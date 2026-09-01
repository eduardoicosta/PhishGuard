"""
Migração LGPD — expurgo do conteúdo legado da tabela `interacoes_hub`.

Contexto
--------
Antes da versão 2.0 o PhishGuard gravava, em texto puro, a mensagem do usuário
(`mensagem_usuario`) e a resposta da IA (`resposta_bot`). A arquitetura atual
não escreve mais nessas colunas, mas os registros históricos permanecem no
banco — e enquanto permanecerem, a empresa continua sendo *controladora* desses
dados perante a LGPD.

Este script executa o expurgo. Ele é deliberadamente MANUAL e não roda no
startup da API: apagar dados de produção é uma decisão do operador, não um
efeito colateral de um deploy.

Modos
-----
    python scripts/migrar_lgpd_zero_retencao.py
        Diagnóstico. Não altera nada. Mostra quantos registros têm conteúdo.

    python scripts/migrar_lgpd_zero_retencao.py --executar
        Anonimiza: sobrescreve o conteúdo das colunas legadas com NULL.
        Os metadados (canal, veredito, data) são preservados para o histórico.

    python scripts/migrar_lgpd_zero_retencao.py --executar --remover-colunas
        Além de anonimizar, faz DROP das colunas legadas. Torna a garantia
        estrutural: nem um bug futuro consegue gravar conteúdo ali.
        IRREVERSÍVEL — exige confirmação digitada.
"""

from __future__ import annotations

import argparse
import os
import sys

# Permite executar o script diretamente de dentro de scripts/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import persistencia  # noqa: E402


def diagnosticar() -> dict:
    relatorio = persistencia.auditar_retencao()
    print("\n=== Diagnóstico de retenção — tabela interacoes_hub ===")
    print(f"Registros totais...................: {relatorio['registros_totais']}")
    print(f"Colunas legadas de conteúdo........: {relatorio['colunas_legadas_de_conteudo'] or 'nenhuma'}")
    print(f"Valores de conteúdo residuais......: {relatorio['registros_com_conteudo_residual']}")
    print(f"Conforme com retenção zero.........: {'SIM' if relatorio['conforme'] else 'NÃO'}")
    print(f"Ação recomendada...................: {relatorio['acao_recomendada']}\n")
    return relatorio


def anonimizar_historico() -> int:
    """Sobrescreve com NULL o conteúdo das colunas legadas, preservando metadados."""
    colunas = _colunas_legadas_presentes()
    if not colunas:
        print("Nenhuma coluna legada de conteúdo existe. Nada a fazer.")
        return 0

    atribuicoes = ", ".join(f"{coluna} = NULL" for coluna in colunas)
    condicao = " OR ".join(f"{coluna} IS NOT NULL" for coluna in colunas)

    with persistencia.conexao() as conn:
        with conn.cursor() as cursor:
            cursor.execute(f"UPDATE interacoes_hub SET {atribuicoes} WHERE {condicao}")
            afetados = cursor.rowcount
        conn.commit()

    print(f"Anonimização concluída: {afetados} registro(s) tiveram o conteúdo removido.")
    return afetados


def remover_colunas() -> None:
    """DROP das colunas legadas — garantia estrutural de retenção zero."""
    colunas = _colunas_legadas_presentes()
    if not colunas:
        print("As colunas legadas já não existem. Nada a fazer.")
        return

    print("\n!!! OPERAÇÃO IRREVERSÍVEL !!!")
    print(f"As colunas {colunas} serão REMOVIDAS permanentemente de interacoes_hub.")
    confirmacao = input("Digite exatamente REMOVER para confirmar: ").strip()
    if confirmacao != "REMOVER":
        print("Operação cancelada. Nenhuma alteração foi feita.")
        return

    with persistencia.conexao() as conn:
        with conn.cursor() as cursor:
            for coluna in colunas:
                cursor.execute(f"ALTER TABLE interacoes_hub DROP COLUMN IF EXISTS {coluna}")
                print(f"  coluna '{coluna}' removida.")
        conn.commit()
    print("Retenção zero agora é garantida pelo próprio schema.")


def _colunas_legadas_presentes() -> list:
    with persistencia.conexao() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'interacoes_hub'"
            )
            existentes = {linha[0] for linha in cursor.fetchall()}
    return [c for c in persistencia.COLUNAS_LEGADAS_COM_CONTEUDO if c in existentes]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Expurgo do conteúdo legado (conformidade LGPD — retenção zero)."
    )
    parser.add_argument(
        "--executar",
        action="store_true",
        help="Aplica o expurgo. Sem esta flag o script apenas diagnostica.",
    )
    parser.add_argument(
        "--remover-colunas",
        action="store_true",
        help="Após anonimizar, faz DROP das colunas legadas (irreversível).",
    )
    argumentos = parser.parse_args()

    if not persistencia.inicializar_pool():
        print("ERRO: banco indisponível. Verifique DATABASE_URL no arquivo .env.")
        return 1

    try:
        persistencia.inicializar_banco()
        diagnosticar()

        if not argumentos.executar:
            print("Modo diagnóstico. Use --executar para aplicar o expurgo.\n")
            return 0

        anonimizar_historico()
        if argumentos.remover_colunas:
            remover_colunas()

        print("\n--- Situação após a migração ---")
        diagnosticar()
        return 0
    finally:
        persistencia.encerrar_pool()


if __name__ == "__main__":
    raise SystemExit(main())
