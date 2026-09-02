"""
PhishGuard — Camada de Privacidade e Conformidade (LGPD by Design).

Este módulo concentra TODAS as rotinas de tratamento de dados pessoais do
PhishGuard. Ele existe para que a conformidade com a Lei 13.709/2018 (LGPD) seja
uma propriedade *arquitetural* — verificável por um auditor em um único arquivo —
e não uma prática dispersa pelo código.

Três garantias são implementadas aqui:

1. PII Masking (Art. 6º, III — necessidade / Art. 12 — anonimização):
   `mascarar_pii()` remove identificadores diretos do texto ANTES de qualquer
   envio ao processador externo (Gemini / Camada 2).

2. Pseudonimização (Art. 13, §4º):
   `pseudonimizar()` converte identificadores de conta/tenant em hashes HMAC
   irreversíveis sem a chave-mestra, permitindo métricas por usuário/empresa
   sem armazenar quem é o titular.

3. Manifesto de Transparência (Art. 9º e Art. 6º, VI):
   `MANIFESTO_LGPD` é a fonte única de verdade exibida na extensão, nos painéis
   e no endpoint público `/api/privacidade`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import unicodedata
from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Callable, Dict, Optional, Pattern, Tuple

try:  # O .env precisa estar carregado ANTES da primeira leitura de configuração.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

# Sal usado na pseudonimização. Em produção DEVE vir de um cofre (Azure Key Vault).
# O fallback aleatório por processo é intencional: sem sal configurado os hashes
# não são estáveis entre reinícios, o que degrada métricas mas NUNCA vaza PII.
_SAL_PSEUDONIMIZACAO = os.getenv("PHISHGUARD_SAL_PSEUDONIMO") or os.urandom(32).hex()

SAL_CONFIGURADO = bool(os.getenv("PHISHGUARD_SAL_PSEUDONIMO"))

# Tag usada quando o mascaramento precisa falhar de forma fechada.
TAG_GENERICA = "[DADOS_CONFIDENCIAIS]"

# Rótulo explícito para quando o 'De:' não pôde ser capturado. É deliberadamente
# uma frase (não um e-mail sintético) para que a IA NÃO a interprete como um
# domínio real e não alucine análise de spoofing sobre "desconhecido.com".
REMETENTE_NAO_INFORMADO = "(remetente não informado)"

# Valores herdados/placeholder que devem ser tratados como "ausente".
_REMETENTES_AUSENTES = {
    "",
    "desconhecido",
    "desconhecido@desconhecido.com",
    "unknown",
    "unknown@unknown.com",
    "nao informado",
    "não informado",
}


def _remetente_ausente(remetente: Optional[str]) -> bool:
    if not remetente:
        return True
    return remetente.strip().strip("<>").lower() in _REMETENTES_AUSENTES


# ---------------------------------------------------------------------------
# Validadores auxiliares (reduzem falso-positivo do mascaramento)
# ---------------------------------------------------------------------------

def _somente_digitos(valor: str) -> str:
    return re.sub(r"\D", "", valor)


def validar_luhn(numero: str) -> bool:
    """Algoritmo de Luhn (ISO/IEC 7812) — confirma que a sequência é um cartão."""
    digitos = _somente_digitos(numero)
    if not 13 <= len(digitos) <= 19:
        return False
    soma = 0
    inverter = False
    for caractere in reversed(digitos):
        valor = ord(caractere) - 48
        if inverter:
            valor *= 2
            if valor > 9:
                valor -= 9
        soma += valor
        inverter = not inverter
    return soma % 10 == 0


def validar_cpf(numero: str) -> bool:
    """Valida os dois dígitos verificadores do CPF (Receita Federal)."""
    digitos = _somente_digitos(numero)
    if len(digitos) != 11 or digitos == digitos[0] * 11:
        return False
    for tamanho in (9, 10):
        soma = sum(int(digitos[i]) * (tamanho + 1 - i) for i in range(tamanho))
        verificador = (soma * 10) % 11
        verificador = 0 if verificador >= 10 else verificador
        if verificador != int(digitos[tamanho]):
            return False
    return True


def validar_cnpj(numero: str) -> bool:
    """Valida os dois dígitos verificadores do CNPJ."""
    digitos = _somente_digitos(numero)
    if len(digitos) != 14 or digitos == digitos[0] * 14:
        return False
    pesos_1 = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]
    pesos_2 = [6] + pesos_1
    for pesos, posicao in ((pesos_1, 12), (pesos_2, 13)):
        soma = sum(int(digitos[i]) * pesos[i] for i in range(posicao))
        resto = soma % 11
        verificador = 0 if resto < 2 else 11 - resto
        if verificador != int(digitos[posicao]):
            return False
    return True


# ---------------------------------------------------------------------------
# Catálogo declarativo de regras de mascaramento
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RegraPII:
    """Uma regra declarativa de detecção e mascaramento de dado pessoal."""

    nome: str
    padrao: Pattern[str]
    substituto: str
    # Validador opcional: recebe o trecho casado e decide se é PII de verdade.
    validador: Optional[Callable[[str], bool]] = None
    # Quando definido, substitui apenas o grupo nomeado do padrão.
    grupo_alvo: Optional[str] = None


def _c(padrao: str) -> Pattern[str]:
    return re.compile(padrao, re.IGNORECASE | re.UNICODE)


# A ORDEM É SIGNIFICATIVA: regras mais específicas primeiro, para que um cartão
# de crédito não seja parcialmente consumido pela regra de telefone, etc.
REGRAS_PII: Tuple[RegraPII, ...] = (
    # 1. Segredos declarados explicitamente ("senha: 1234", "token = abc").
    RegraPII(
        nome="credencial",
        padrao=_c(
            r"\b(?:senha|password|passwd|pwd|token|api[\s_-]?key|secret|"
            r"chave[\s_-]?de[\s_-]?acesso|c[oó]digo[\s_-]?(?:de[\s_-]?)?"
            r"(?:verifica[cç][aã]o|seguran[cç]a|confirma[cç][aã]o)|otp|pin)\b"
            r"\s*(?:[:=]|\bé\b|\beh\b)\s*"
            r"(?P<alvo>\S{3,64}?)(?=[\s]|[.,;:!?](?:\s|$)|$)"
        ),
        substituto="[CREDENCIAL_MASCARADA]",
        grupo_alvo="alvo",
    ),
    # 2. Linha digitável de boleto (44+ dígitos) — identifica pagador/contrato.
    RegraPII(
        nome="linha_digitavel",
        padrao=_c(r"\b\d(?:[\s.]?\d){43,47}\b"),
        substituto="[LINHA_DIGITAVEL_MASCARADA]",
    ),
    # 3. Cartão de crédito/débito (confirmado por Luhn).
    RegraPII(
        nome="cartao_credito",
        padrao=_c(r"\b\d(?:[ -]?\d){12,18}\b"),
        substituto="[CARTAO_MASCARADO]",
        validador=validar_luhn,
    ),
    # 4. CNPJ.
    RegraPII(
        nome="cnpj",
        padrao=_c(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b"),
        substituto="[CNPJ_MASCARADO]",
        validador=validar_cnpj,
    ),
    # 5. CPF formatado (mascarado sempre) e CPF cru com DV válido.
    RegraPII(
        nome="cpf",
        padrao=_c(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
        substituto="[CPF_MASCARADO]",
    ),
    RegraPII(
        nome="cpf",
        padrao=_c(r"\b\d{11}\b"),
        substituto="[CPF_MASCARADO]",
        validador=validar_cpf,
    ),
    # 6. Chave Pix aleatória (UUID) e Pix copia-e-cola (BR Code / EMV).
    RegraPII(
        nome="chave_pix",
        padrao=_c(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}"
            r"-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b"
        ),
        substituto="[CHAVE_PIX_MASCARADA]",
    ),
    RegraPII(
        nome="pix_copia_cola",
        padrao=_c(r"\b000201[0-9A-Z.*\-\s]{30,}"),
        substituto="[PIX_COPIA_E_COLA_MASCARADO]",
    ),
    # 7. Dados bancários ("Agência 1234 Conta 56789-0").
    RegraPII(
        nome="conta_bancaria",
        padrao=_c(
            r"\b(?:ag[eê]ncia|ag\.?)\s*:?\s*\d{3,6}[-\s]?\d?\s*[,;/|]?\s*"
            r"(?:conta|c/c|cc)\s*:?\s*\d{3,12}-?\d?\b"
        ),
        substituto="[DADOS_BANCARIOS_MASCARADOS]",
    ),
    # 8. E-mail: preserva o domínio (sinal técnico antispoofing) e anonimiza a
    #    identidade do titular. Ver ADR-002 em docs/ARQUITETURA_LGPD.md.
    RegraPII(
        nome="email_pessoal",
        padrao=_c(r"\b(?P<alvo>[A-Z0-9._%+\-]{1,64})@(?=[A-Z0-9.\-]+\.[A-Z]{2,})"),
        substituto="[USUARIO_MASCARADO]",
        grupo_alvo="alvo",
    ),
    # 9. Telefone brasileiro (fixo ou celular, com ou sem DDI/DDD).
    RegraPII(
        nome="telefone",
        padrao=_c(r"(?:\+?55[\s.-]?)?(?:\(?\d{2}\)?[\s.-]?)?9?\d{4}[\s.-]?\d{4}\b"),
        substituto="[TELEFONE_MASCARADO]",
    ),
    # 10. CEP.
    RegraPII(
        nome="cep",
        padrao=_c(r"\b\d{5}-\d{3}\b"),
        substituto="[CEP_MASCARADO]",
    ),
    # 11. Documentos com marcador explícito.
    RegraPII(
        nome="documento",
        padrao=_c(
            r"\b(?:rg|identidade|cnh|passaporte|t[ií]tulo\s+de\s+eleitor)"
            r"\s*:?\s*(?P<alvo>[\w.\-/]{5,20})\b"
        ),
        substituto="[DOCUMENTO_MASCARADO]",
        grupo_alvo="alvo",
    ),
    # 12. Data de nascimento explícita.
    RegraPII(
        nome="data_nascimento",
        padrao=_c(
            r"\b(?:nascimento|nasc\.?|data\s+de\s+nascimento|dob)"
            r"\s*:?\s*(?P<alvo>\d{2}[/\-.]\d{2}[/\-.]\d{2,4})\b"
        ),
        substituto="[DATA_NASCIMENTO_MASCARADA]",
        grupo_alvo="alvo",
    ),
)


@dataclass
class ResultadoMascaramento:
    """Saída auditável do mascaramento: o texto seguro e o que foi removido."""

    texto: str
    ocorrencias: Dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.ocorrencias.values())

    @property
    def houve_mascaramento(self) -> bool:
        return self.total > 0

    def resumo(self) -> str:
        if not self.houve_mascaramento:
            return "nenhum dado pessoal identificado"
        return ", ".join(f"{tipo}={qtd}" for tipo, qtd in sorted(self.ocorrencias.items()))


# Limite defensivo: textos gigantes são truncados antes do regex para evitar
# custo de CPU desproporcional (proteção contra negação de serviço por volume).
LIMITE_CARACTERES_ANALISE = 20_000


def mascarar_pii(
    texto: Optional[str],
    limite: int = LIMITE_CARACTERES_ANALISE,
) -> ResultadoMascaramento:
    """
    Remove identificadores pessoais diretos de um texto livre.

    É a única porta de saída de conteúdo do usuário rumo a um processador
    externo (Gemini). Nenhuma função deste projeto deve enviar texto bruto para
    fora sem passar por aqui.

    Falha fechada: qualquer erro inesperado em uma regra faz o texto inteiro ser
    substituído pela tag genérica, jamais vazando o original.
    """
    if not texto:
        return ResultadoMascaramento(texto="", ocorrencias={})

    trabalho = unicodedata.normalize("NFC", texto)[:limite]
    ocorrencias: Dict[str, int] = {}

    for regra in REGRAS_PII:
        try:
            trabalho, quantidade = _aplicar_regra(trabalho, regra)
        except Exception:  # pragma: no cover - salvaguarda de último recurso
            return ResultadoMascaramento(
                texto=TAG_GENERICA, ocorrencias={"falha_segura": 1}
            )
        if quantidade:
            ocorrencias[regra.nome] = ocorrencias.get(regra.nome, 0) + quantidade

    return ResultadoMascaramento(texto=trabalho, ocorrencias=ocorrencias)


def _aplicar_regra(texto: str, regra: RegraPII) -> Tuple[str, int]:
    contador = 0

    def _substituir(match: "re.Match[str]") -> str:
        nonlocal contador
        trecho = match.group(regra.grupo_alvo) if regra.grupo_alvo else match.group(0)
        if regra.validador is not None and not regra.validador(trecho):
            return match.group(0)
        contador += 1
        if regra.grupo_alvo:
            inicio, fim = match.span(regra.grupo_alvo)
            deslocamento = match.start()
            original = match.group(0)
            return (
                original[: inicio - deslocamento]
                + regra.substituto
                + original[fim - deslocamento :]
            )
        return regra.substituto

    return regra.padrao.sub(_substituir, texto), contador


def mascarar_remetente(remetente: Optional[str]) -> str:
    """
    Trata o campo 'De:' do e-mail.

    O endereço técnico do remetente é o principal sinal antifraude (spoofing,
    domínios sósias) e por isso é preservado sob a base legal de *legítimo
    interesse* com o princípio da necessidade (Art. 10). O que é removido é o
    excedente: o nome de exibição, que identifica uma pessoa natural sem
    contribuir para a detecção.
    """
    if _remetente_ausente(remetente):
        return REMETENTE_NAO_INFORMADO
    # 1. Formato "Nome <email@dominio>": preserva o endereço técnico.
    match = re.search(r"<([^>]+)>", remetente)
    if match:
        endereco = match.group(1).strip()
        return endereco or REMETENTE_NAO_INFORMADO
    # 2. Texto solto: extrai o primeiro e-mail válido, se houver.
    achado = re.search(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", remetente, re.IGNORECASE)
    if achado:
        return achado.group(0)
    # 3. Sem e-mail reconhecível: nunca devolve o placeholder herdado.
    return remetente.strip() or REMETENTE_NAO_INFORMADO


def extrair_dominio(remetente: Optional[str]) -> str:
    """Domínio do remetente — metadado técnico, não identifica pessoa natural."""
    if _remetente_ausente(remetente):
        return "desconhecido"
    _, endereco = parseaddr(remetente)
    alvo = endereco or remetente
    if "@" in alvo:
        return alvo.split("@")[-1].replace(">", "").strip().lower() or "desconhecido"
    return "desconhecido"


# ---------------------------------------------------------------------------
# Pseudonimização
# ---------------------------------------------------------------------------

def pseudonimizar(
    valor: Optional[str],
    escopo: str = "geral",
    tamanho: int = 16,
) -> Optional[str]:
    """
    HMAC-SHA256 com sal do servidor: identificador estável e irreversível.

    Sem a posse do sal (guardado no cofre da infraestrutura) não é possível
    reverter nem enumerar o valor original — atendendo ao Art. 13, §4º.
    """
    if not valor:
        return None
    normalizado = unicodedata.normalize("NFC", str(valor)).strip().lower()
    if not normalizado:
        return None
    digest = hmac.new(
        _SAL_PSEUDONIMIZACAO.encode("utf-8"),
        f"{escopo}:{normalizado}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:tamanho]


# ---------------------------------------------------------------------------
# Manifesto público de transparência
# ---------------------------------------------------------------------------

VERSAO_POLITICA = "2026.09"

MANIFESTO_LGPD: Dict[str, object] = {
    "versao_politica": VERSAO_POLITICA,
    "titulo": "Processamento em memória, retenção zero",
    "resumo": (
        "O conteúdo das suas mensagens e e-mails é analisado exclusivamente na "
        "memória volátil do servidor e descartado ao fim da requisição. Nenhum "
        "texto, assunto ou destinatário é gravado em banco de dados."
    ),
    "garantias": [
        {
            "chave": "zero_retencao",
            "titulo": "Retenção zero de conteúdo",
            "descricao": (
                "O corpo do e-mail e as mensagens do hub conversacional nunca são "
                "persistidos. A análise é stateless: o payload existe apenas "
                "durante a requisição HTTP."
            ),
        },
        {
            "chave": "pii_masking",
            "titulo": "Anonimização preventiva antes da IA",
            "descricao": (
                "CPF, CNPJ, cartões, chaves Pix, dados bancários, telefones, CEP, "
                "documentos e credenciais são mascarados por expressões regulares "
                "ANTES de qualquer envio ao modelo de linguagem."
            ),
        },
        {
            "chave": "metadados_agregados",
            "titulo": "Apenas metadados agregados",
            "descricao": (
                "Persistimos somente canal, data/hora, veredito, score de risco e "
                "identificadores pseudonimizados — suficientes para governança, "
                "insuficientes para reconstruir a mensagem."
            ),
        },
        {
            "chave": "sem_treinamento",
            "titulo": "Seus dados não treinam modelos",
            "descricao": (
                "Nenhum conteúdo analisado é usado para treinar ou ajustar modelos "
                "de IA, próprios ou de terceiros."
            ),
        },
        {
            "chave": "direitos_titular",
            "titulo": "Direitos do titular",
            "descricao": (
                "Art. 18 da LGPD: confirmação, acesso, correção, anonimização e "
                "eliminação. Como não guardamos conteúdo, o direito à eliminação é "
                "atendido por construção."
            ),
        },
    ],
    "bases_legais": [
        "Art. 7º, IX — legítimo interesse para segurança da informação",
        "Art. 7º, I — consentimento na instalação da extensão",
        "Art. 10 — tratamento limitado ao mínimo necessário",
    ],
    "dados_persistidos": [
        "canal (extensao | whatsapp | webchat)",
        "data/hora do evento",
        "veredito (Phishing | Seguro)",
        "score de risco (0.0000–1.0000)",
        "nível de alerta",
        "domínio do remetente (metadado técnico)",
        "identificadores de conta e organização pseudonimizados (HMAC-SHA256)",
        "quantidade de dados sensíveis mascarados (contador)",
    ],
    "dados_nunca_persistidos": [
        "corpo do e-mail ou da mensagem",
        "assunto do e-mail",
        "endereço completo do remetente ou destinatário",
        "resposta textual gerada pela IA",
        "anexos, imagens ou links completos",
    ],
    "subprocessadores": [
        {
            "nome": "Google Gemini",
            "papel": "Análise contextual (Camada 2)",
            "dado_enviado": "Texto já anonimizado pelo mecanismo de PII Masking",
        },
        {
            "nome": "Azure Database for PostgreSQL",
            "papel": "Armazenamento de metadados agregados",
            "dado_enviado": "Somente metadados; nenhum conteúdo",
        },
    ],
    "contato_encarregado": os.getenv("PHISHGUARD_DPO_CONTATO", "dpo@phishguard.com.br"),
}


def selo_transparencia() -> Dict[str, object]:
    """Bloco compacto anexado a cada resposta de análise (selo em tempo real)."""
    return {
        "versao_politica": VERSAO_POLITICA,
        "retencao_conteudo": "nenhuma",
        "processamento": "memoria_volatil",
        "anonimizacao_antes_da_ia": True,
        "sal_pseudonimizacao_configurado": SAL_CONFIGURADO,
    }
