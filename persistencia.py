"""
PhishGuard — Camada de Persistência (PostgreSQL / Azure) com Retenção Zero.

Responsabilidades:

* Ser o ÚNICO ponto do sistema com acesso de escrita ao banco. Isso torna a
  garantia de retenção zero verificável: basta auditar este arquivo para provar
  que nenhum conteúdo de e-mail ou mensagem chega ao disco.
* Manter um pool de conexões (o código anterior abria e fechava uma conexão por
  requisição, o que na latência do Azure custava centenas de milissegundos).
* Degradar com elegância: se o banco estiver indisponível, a telemetria falha em
  silêncio e a análise de segurança continua funcionando. Segurança do usuário
  nunca depende do dashboard.

Contrato de dados (tabela `interacoes_hub`):
    PERSISTIDO   — canal, veredito, score, nível, domínio, hashes, contadores.
    NUNCA GRAVADO — corpo, assunto, mensagem do usuário, resposta da IA.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Iterator, List, Optional

try:  # pragma: no cover - dependência opcional em ambientes de teste
    import psycopg2
    from psycopg2 import pool as psycopg2_pool
    from psycopg2.extras import RealDictCursor
except ImportError:  # pragma: no cover
    psycopg2 = None
    psycopg2_pool = None
    RealDictCursor = None

try:  # O .env precisa estar carregado ANTES da primeira leitura de configuração.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

logger = logging.getLogger("phishguard.persistencia")


def _database_url() -> Optional[str]:
    """Leitura tardia: o .env pode ser carregado depois do import deste módulo."""
    return os.getenv("DATABASE_URL")


POOL_MIN = int(os.getenv("PHISHGUARD_DB_POOL_MIN", "1"))
POOL_MAX = int(os.getenv("PHISHGUARD_DB_POOL_MAX", "8"))

_pool: Optional["psycopg2_pool.ThreadedConnectionPool"] = None
_lock = threading.Lock()

#: Colunas legadas que continham conteúdo em texto puro. Mantidas no schema por
#: compatibilidade com bases já provisionadas, mas o PhishGuard nunca mais
#: escreve nelas. Use `scripts/migrar_lgpd_zero_retencao.py` para expurgá-las.
COLUNAS_LEGADAS_COM_CONTEUDO = ("mensagem_usuario", "resposta_bot")


class BancoIndisponivel(RuntimeError):
    """Levantada quando uma leitura precisa do banco e ele não está acessível."""


# ---------------------------------------------------------------------------
# Modelo de evento — o que efetivamente vai para o disco
# ---------------------------------------------------------------------------

@dataclass
class EventoTelemetria:
    """
    Metadado agregado e anonimizado de uma análise.

    Nenhum campo desta classe carrega conteúdo do usuário. Ela é, na prática, o
    contrato de privacidade do produto expresso em código.
    """

    canal: str                      # extensao | whatsapp | webchat
    risco_detectado: str            # Phishing | Seguro
    score_risco: float              # 0.0 – 1.0
    nivel_alerta: str               # SEGURO | ATENCAO | CRITICO
    tipo_conta: str = "B2C"         # B2C | B2B
    tenant_hash: Optional[str] = None
    usuario_hash: Optional[str] = None
    dominio_remetente: Optional[str] = None
    dupla_checagem: bool = False
    pii_mascarado_qtd: int = 0
    pii_tipos: Optional[str] = None  # ex.: "cpf=1, telefone=2"
    latencia_ms: int = 0
    origem_veredito: str = "camada_2"  # camada_1 | camada_2 | fallback
    data_hora: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def como_dicionario(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Pool de conexões
# ---------------------------------------------------------------------------

def banco_configurado() -> bool:
    return bool(_database_url()) and psycopg2 is not None


def inicializar_pool() -> bool:
    """Cria o pool de conexões. Retorna False (sem levantar) se indisponível."""
    global _pool
    if not banco_configurado():
        logger.warning(
            "DATABASE_URL ausente ou psycopg2 não instalado. "
            "A telemetria agregada ficará desativada; a análise continua ativa."
        )
        return False
    with _lock:
        if _pool is not None:
            return True
        try:
            _pool = psycopg2_pool.ThreadedConnectionPool(
                POOL_MIN, POOL_MAX, _database_url(), connect_timeout=10
            )
            return True
        except Exception as erro:
            logger.error("Falha ao criar o pool de conexões: %s", erro)
            _pool = None
            return False


def encerrar_pool() -> None:
    global _pool
    with _lock:
        if _pool is not None:
            try:
                _pool.closeall()
            except Exception:  # pragma: no cover
                pass
            _pool = None


@contextmanager
def conexao() -> Iterator[Any]:
    """Empresta uma conexão do pool e a devolve ao final, mesmo em erro."""
    if _pool is None and not inicializar_pool():
        raise BancoIndisponivel("Banco de dados não configurado ou inacessível.")
    conn = _pool.getconn()
    try:
        yield conn
    except Exception:
        try:
            conn.rollback()
        except Exception:  # pragma: no cover
            pass
        raise
    finally:
        _pool.putconn(conn)


# ---------------------------------------------------------------------------
# Schema (migração idempotente)
# ---------------------------------------------------------------------------

_DDL_TABELA = """
CREATE TABLE IF NOT EXISTS interacoes_hub (
    id SERIAL PRIMARY KEY,
    canal TEXT NOT NULL,
    risco_detectado TEXT,
    data_hora TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
)
"""

# Colunas de metadados adicionadas de forma idempotente. Isso permite evoluir uma
# base já existente (que tinha mensagem_usuario/resposta_bot) sem downtime e sem
# destruir dados históricos — o expurgo é uma decisão explícita do operador.
_COLUNAS_METADADOS = (
    ("score_risco", "NUMERIC(6,4)"),
    ("nivel_alerta", "TEXT"),
    ("tipo_conta", "TEXT DEFAULT 'B2C'"),
    ("tenant_hash", "TEXT"),
    ("usuario_hash", "TEXT"),
    ("dominio_remetente", "TEXT"),
    ("dupla_checagem", "BOOLEAN DEFAULT FALSE"),
    ("pii_mascarado_qtd", "INTEGER DEFAULT 0"),
    ("pii_tipos", "TEXT"),
    ("latencia_ms", "INTEGER DEFAULT 0"),
    ("origem_veredito", "TEXT"),
)

_INDICES = (
    "CREATE INDEX IF NOT EXISTS idx_hub_data_hora ON interacoes_hub (data_hora DESC)",
    "CREATE INDEX IF NOT EXISTS idx_hub_tenant ON interacoes_hub (tenant_hash)",
    "CREATE INDEX IF NOT EXISTS idx_hub_usuario ON interacoes_hub (usuario_hash)",
    "CREATE INDEX IF NOT EXISTS idx_hub_canal ON interacoes_hub (canal)",
)


def inicializar_banco() -> bool:
    """Cria/evolui o schema de metadados. Nunca derruba a API em caso de falha."""
    if not inicializar_pool():
        return False
    try:
        with conexao() as conn:
            with conn.cursor() as cursor:
                cursor.execute(_DDL_TABELA)
                for nome, tipo in _COLUNAS_METADADOS:
                    cursor.execute(
                        f"ALTER TABLE interacoes_hub ADD COLUMN IF NOT EXISTS {nome} {tipo}"
                    )
                # Colunas legadas de conteúdo: garantimos que sejam anuláveis para
                # que a gravação somente-metadados nunca esbarre em NOT NULL.
                for coluna in COLUNAS_LEGADAS_COM_CONTEUDO:
                    if _coluna_existe(cursor, coluna):
                        cursor.execute(
                            f"ALTER TABLE interacoes_hub "
                            f"ALTER COLUMN {coluna} DROP NOT NULL"
                        )
                for indice in _INDICES:
                    cursor.execute(indice)
            conn.commit()
        logger.info("Schema de telemetria (retenção zero) validado com sucesso.")
        return True
    except Exception as erro:
        logger.error("Não foi possível inicializar o schema: %s", erro)
        return False


def _coluna_existe(cursor: Any, coluna: str) -> bool:
    cursor.execute(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = 'interacoes_hub' AND column_name = %s",
        (coluna,),
    )
    return cursor.fetchone() is not None


# ---------------------------------------------------------------------------
# Escrita — exclusivamente metadados
# ---------------------------------------------------------------------------

_SQL_INSERIR = """
INSERT INTO interacoes_hub (
    canal, risco_detectado, score_risco, nivel_alerta, tipo_conta,
    tenant_hash, usuario_hash, dominio_remetente, dupla_checagem,
    pii_mascarado_qtd, pii_tipos, latencia_ms, origem_veredito, data_hora
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


def registrar_evento(evento: EventoTelemetria) -> bool:
    """Grava um evento de telemetria (bloqueante). Retorna False em falha."""
    if not banco_configurado():
        return False
    try:
        with conexao() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    _SQL_INSERIR,
                    (
                        evento.canal,
                        evento.risco_detectado,
                        round(float(evento.score_risco), 4),
                        evento.nivel_alerta,
                        evento.tipo_conta,
                        evento.tenant_hash,
                        evento.usuario_hash,
                        evento.dominio_remetente,
                        evento.dupla_checagem,
                        evento.pii_mascarado_qtd,
                        evento.pii_tipos,
                        evento.latencia_ms,
                        evento.origem_veredito,
                        evento.data_hora,
                    ),
                )
            conn.commit()
        return True
    except Exception as erro:
        # Telemetria jamais interrompe a proteção do usuário.
        logger.warning("Telemetria não registrada (%s): %s", evento.canal, erro)
        return False


async def registrar_evento_async(evento: EventoTelemetria) -> None:
    """
    Agenda a gravação fora do caminho crítico da requisição.

    O usuário recebe o veredito imediatamente; a escrita no Azure acontece em
    uma thread separada e qualquer erro é apenas logado.
    """
    try:
        await asyncio.to_thread(registrar_evento, evento)
    except Exception as erro:  # pragma: no cover
        logger.warning("Falha ao agendar telemetria: %s", erro)


def agendar_registro(evento: EventoTelemetria) -> None:
    """Dispara a telemetria em background sem bloquear a resposta HTTP."""
    try:
        tarefa = asyncio.create_task(registrar_evento_async(evento))
        # Evita "Task exception was never retrieved" e mantém referência forte.
        _tarefas_pendentes.add(tarefa)
        tarefa.add_done_callback(_tarefas_pendentes.discard)
    except RuntimeError:
        # Sem loop de eventos (uso síncrono/CLI): grava direto.
        registrar_evento(evento)


_tarefas_pendentes: set = set()


def tarefas_pendentes() -> list:
    """Tarefas de telemetria ainda em voo — drenadas no shutdown da API."""
    return list(_tarefas_pendentes)


# ---------------------------------------------------------------------------
# Leitura — consultas agregadas para os painéis
# ---------------------------------------------------------------------------

_COLUNAS_PUBLICAS = (
    "id, canal, risco_detectado, score_risco, nivel_alerta, tipo_conta, "
    "tenant_hash, usuario_hash, dominio_remetente, dupla_checagem, "
    "pii_mascarado_qtd, pii_tipos, latencia_ms, origem_veredito, data_hora"
)


def _normalizar(valor: Any) -> Any:
    """
    Converte tipos do driver para JSON amigável ao navegador.

    Em especial: os registros são gravados em UTC, mas a coluna histórica é
    TIMESTAMP (sem fuso). Sem o sufixo 'Z' explícito, o `new Date()` do painel
    interpretaria o horário como local e exibiria a trilha de auditoria com
    horas erradas.
    """
    if isinstance(valor, Decimal):
        return float(valor)
    if isinstance(valor, datetime):
        with_tz = valor if valor.tzinfo else valor.replace(tzinfo=timezone.utc)
        return with_tz.isoformat()
    if isinstance(valor, date):
        return valor.isoformat()
    return valor


def _consultar(sql: str, parametros: tuple = ()) -> List[Dict[str, Any]]:
    with conexao() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(sql, parametros)
            return [
                {chave: _normalizar(valor) for chave, valor in dict(linha).items()}
                for linha in cursor.fetchall()
            ]


def listar_eventos(
    limite: int = 50,
    tenant_hash: Optional[str] = None,
    usuario_hash: Optional[str] = None,
    canal: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Lista eventos anonimizados. Nunca retorna conteúdo — as colunas não existem aqui."""
    filtros: List[str] = []
    parametros: List[Any] = []
    if tenant_hash:
        filtros.append("tenant_hash = %s")
        parametros.append(tenant_hash)
    if usuario_hash:
        filtros.append("usuario_hash = %s")
        parametros.append(usuario_hash)
    if canal:
        filtros.append("canal = %s")
        parametros.append(canal)

    onde = f"WHERE {' AND '.join(filtros)}" if filtros else ""
    limite = max(1, min(int(limite), 500))
    sql = (
        f"SELECT {_COLUNAS_PUBLICAS} FROM interacoes_hub {onde} "
        f"ORDER BY data_hora DESC LIMIT {limite}"
    )
    return _consultar(sql, tuple(parametros))


def resumo_agregado(
    dias: int = 30,
    tenant_hash: Optional[str] = None,
    usuario_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Contadores globais do período — base dos cartões dos dois painéis."""
    filtros = ["data_hora >= NOW() - (%s || ' days')::INTERVAL"]
    parametros: List[Any] = [str(max(1, int(dias)))]
    if tenant_hash:
        filtros.append("tenant_hash = %s")
        parametros.append(tenant_hash)
    if usuario_hash:
        filtros.append("usuario_hash = %s")
        parametros.append(usuario_hash)
    onde = " AND ".join(filtros)

    sql = f"""
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE risco_detectado = 'Phishing') AS ameacas,
            COUNT(*) FILTER (WHERE risco_detectado <> 'Phishing') AS seguros,
            COALESCE(AVG(score_risco), 0) AS score_medio,
            COALESCE(SUM(pii_mascarado_qtd), 0) AS pii_mascarados,
            COALESCE(AVG(latencia_ms), 0) AS latencia_media_ms,
            COUNT(DISTINCT usuario_hash) AS usuarios_ativos,
            COUNT(DISTINCT dominio_remetente) AS dominios_distintos
        FROM interacoes_hub
        WHERE {onde}
    """
    linhas = _consultar(sql, tuple(parametros))
    bruto = linhas[0] if linhas else {}
    return {
        "total": int(bruto.get("total") or 0),
        "ameacas": int(bruto.get("ameacas") or 0),
        "seguros": int(bruto.get("seguros") or 0),
        "score_medio": round(float(bruto.get("score_medio") or 0), 4),
        "pii_mascarados": int(bruto.get("pii_mascarados") or 0),
        "latencia_media_ms": int(float(bruto.get("latencia_media_ms") or 0)),
        "usuarios_ativos": int(bruto.get("usuarios_ativos") or 0),
        "dominios_distintos": int(bruto.get("dominios_distintos") or 0),
    }


def serie_temporal(
    dias: int = 14,
    tenant_hash: Optional[str] = None,
    usuario_hash: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Série diária de ameaças x seguros para os gráficos dos painéis."""
    filtros = ["data_hora >= NOW() - (%s || ' days')::INTERVAL"]
    parametros: List[Any] = [str(max(1, int(dias)))]
    if tenant_hash:
        filtros.append("tenant_hash = %s")
        parametros.append(tenant_hash)
    if usuario_hash:
        filtros.append("usuario_hash = %s")
        parametros.append(usuario_hash)
    onde = " AND ".join(filtros)

    sql = f"""
        SELECT
            DATE(data_hora) AS dia,
            COUNT(*) FILTER (WHERE risco_detectado = 'Phishing') AS ameacas,
            COUNT(*) FILTER (WHERE risco_detectado <> 'Phishing') AS seguros
        FROM interacoes_hub
        WHERE {onde}
        GROUP BY DATE(data_hora)
        ORDER BY dia ASC
    """
    return [
        {
            "dia": linha["dia"],
            "ameacas": int(linha["ameacas"] or 0),
            "seguros": int(linha["seguros"] or 0),
        }
        for linha in _consultar(sql, tuple(parametros))
    ]


def dominios_sob_risco(
    limite: int = 10,
    dias: int = 30,
    tenant_hash: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Ranking de domínios que mais originaram ameaças (visão B2B / CISO)."""
    filtros = [
        "data_hora >= NOW() - (%s || ' days')::INTERVAL",
        "risco_detectado = 'Phishing'",
        "dominio_remetente IS NOT NULL",
        "dominio_remetente <> 'desconhecido'",
    ]
    parametros: List[Any] = [str(max(1, int(dias)))]
    if tenant_hash:
        filtros.append("tenant_hash = %s")
        parametros.append(tenant_hash)
    onde = " AND ".join(filtros)
    limite = max(1, min(int(limite), 50))

    sql = f"""
        SELECT dominio_remetente,
               COUNT(*) AS ocorrencias,
               COALESCE(AVG(score_risco), 0) AS score_medio,
               MAX(data_hora) AS ultima_ocorrencia
        FROM interacoes_hub
        WHERE {onde}
        GROUP BY dominio_remetente
        ORDER BY ocorrencias DESC
        LIMIT {limite}
    """
    return [
        {
            "dominio": linha["dominio_remetente"],
            "ocorrencias": int(linha["ocorrencias"] or 0),
            "score_medio": round(float(linha["score_medio"] or 0), 4),
            "ultima_ocorrencia": linha["ultima_ocorrencia"],
        }
        for linha in _consultar(sql, tuple(parametros))
    ]


def distribuicao_por_canal(
    dias: int = 30,
    tenant_hash: Optional[str] = None,
    usuario_hash: Optional[str] = None,
) -> List[Dict[str, Any]]:
    filtros = ["data_hora >= NOW() - (%s || ' days')::INTERVAL"]
    parametros: List[Any] = [str(max(1, int(dias)))]
    if tenant_hash:
        filtros.append("tenant_hash = %s")
        parametros.append(tenant_hash)
    if usuario_hash:
        filtros.append("usuario_hash = %s")
        parametros.append(usuario_hash)
    onde = " AND ".join(filtros)

    sql = f"""
        SELECT canal,
               COUNT(*) AS total,
               COUNT(*) FILTER (WHERE risco_detectado = 'Phishing') AS ameacas
        FROM interacoes_hub
        WHERE {onde}
        GROUP BY canal
        ORDER BY total DESC
    """
    return [
        {
            "canal": linha["canal"],
            "total": int(linha["total"] or 0),
            "ameacas": int(linha["ameacas"] or 0),
        }
        for linha in _consultar(sql, tuple(parametros))
    ]


def colaboradores_em_risco(
    limite: int = 10,
    dias: int = 30,
    tenant_hash: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Colaboradores mais expostos — identificados APENAS pelo hash pseudonimizado.

    O gestor enxerga a distribuição do risco na equipe sem que o produto revele
    quem é a pessoa: a reidentificação exige o sal do servidor, deliberadamente
    fora do alcance do painel.
    """
    filtros = [
        "data_hora >= NOW() - (%s || ' days')::INTERVAL",
        "usuario_hash IS NOT NULL",
    ]
    parametros: List[Any] = [str(max(1, int(dias)))]
    if tenant_hash:
        filtros.append("tenant_hash = %s")
        parametros.append(tenant_hash)
    onde = " AND ".join(filtros)
    limite = max(1, min(int(limite), 50))

    sql = f"""
        SELECT usuario_hash,
               COUNT(*) AS analises,
               COUNT(*) FILTER (WHERE risco_detectado = 'Phishing') AS ameacas,
               MAX(data_hora) AS ultima_atividade
        FROM interacoes_hub
        WHERE {onde}
        GROUP BY usuario_hash
        HAVING COUNT(*) FILTER (WHERE risco_detectado = 'Phishing') > 0
        ORDER BY ameacas DESC
        LIMIT {limite}
    """
    return [
        {
            "usuario_hash": linha["usuario_hash"],
            "analises": int(linha["analises"] or 0),
            "ameacas": int(linha["ameacas"] or 0),
            "ultima_atividade": linha["ultima_atividade"],
        }
        for linha in _consultar(sql, tuple(parametros))
    ]


# ---------------------------------------------------------------------------
# Direitos do titular (Art. 18 da LGPD)
# ---------------------------------------------------------------------------

def eliminar_dados_do_titular(usuario_hash: str) -> int:
    """
    Elimina todos os metadados de um titular pseudonimizado.

    Como nenhum conteúdo é armazenado, esta operação já esgota o direito à
    eliminação previsto no Art. 18, VI.
    """
    if not usuario_hash:
        return 0
    with conexao() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "DELETE FROM interacoes_hub WHERE usuario_hash = %s", (usuario_hash,)
            )
            removidos = cursor.rowcount
        conn.commit()
    logger.info("Direito de eliminação executado: %s registros removidos.", removidos)
    return removidos


def auditar_retencao() -> Dict[str, Any]:
    """
    Autoauditoria: prova, em tempo de execução, que não há conteúdo residual.

    Usada pelo endpoint `/api/privacidade/auditoria` para que um auditor externo
    confirme a garantia sem precisar de acesso ao banco.
    """
    with conexao() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'interacoes_hub' ORDER BY ordinal_position"
            )
            colunas = [linha["column_name"] for linha in cursor.fetchall()]

            legadas_presentes = [c for c in COLUNAS_LEGADAS_COM_CONTEUDO if c in colunas]
            residuos = 0
            for coluna in legadas_presentes:
                cursor.execute(
                    f"SELECT COUNT(*) AS n FROM interacoes_hub "
                    f"WHERE {coluna} IS NOT NULL AND {coluna} <> ''"
                )
                residuos += int(cursor.fetchone()["n"] or 0)

            cursor.execute("SELECT COUNT(*) AS n FROM interacoes_hub")
            total = int(cursor.fetchone()["n"] or 0)

    return {
        "tabela": "interacoes_hub",
        "colunas_atuais": colunas,
        "colunas_legadas_de_conteudo": legadas_presentes,
        "registros_totais": total,
        "registros_com_conteudo_residual": residuos,
        "conforme": residuos == 0,
        "acao_recomendada": (
            "Nenhuma. Nenhum conteúdo residual encontrado."
            if residuos == 0
            else "Execute `python scripts/migrar_lgpd_zero_retencao.py --executar` "
                 "para expurgar o conteúdo legado."
        ),
    }
