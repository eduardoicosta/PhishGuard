"""
Testes de conformidade — a garantia de privacidade como código executável.

Estes testes não verificam "se o código roda"; eles verificam as PROMESSAS que
o PhishGuard faz aos titulares de dados. Se um deles quebrar, o produto deixou
de ser aderente à sua própria política — e isso deve travar o pipeline.

Executar:
    python -m pytest tests -v
    python tests/test_conformidade_lgpd.py   (fallback sem pytest)
"""

from __future__ import annotations

import os
import sys
from dataclasses import fields

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import privacidade  # noqa: E402
from persistencia import EventoTelemetria  # noqa: E402


# ---------------------------------------------------------------------------
# 1. PII Masking — nenhum identificador direto sobrevive
# ---------------------------------------------------------------------------

def test_cpf_formatado_e_mascarado():
    resultado = privacidade.mascarar_pii("Meu CPF é 111.444.777-35 para o cadastro.")
    assert "111.444.777-35" not in resultado.texto
    assert "[CPF_MASCARADO]" in resultado.texto
    assert resultado.ocorrencias["cpf"] == 1


def test_cpf_sem_formatacao_valido_e_mascarado():
    resultado = privacidade.mascarar_pii("Documento 11144477735 confirmado.")
    assert "11144477735" not in resultado.texto


def test_numero_de_11_digitos_invalido_nao_e_mascarado_como_cpf():
    # Evita destruir sinais úteis (números de pedido, protocolos) por falso-positivo.
    resultado = privacidade.mascarar_pii("Protocolo 12345678901 registrado.")
    assert "cpf" not in resultado.ocorrencias


def test_cartao_de_credito_valido_por_luhn_e_mascarado():
    resultado = privacidade.mascarar_pii("Cartão 4111 1111 1111 1111 aprovado.")
    assert "4111" not in resultado.texto
    assert "[CARTAO_MASCARADO]" in resultado.texto


def test_sequencia_numerica_que_falha_no_luhn_nao_e_tratada_como_cartao():
    resultado = privacidade.mascarar_pii("Referência 1234567812345678.")
    assert "cartao_credito" not in resultado.ocorrencias


def test_chave_pix_aleatoria_e_mascarada():
    resultado = privacidade.mascarar_pii(
        "Pix: a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
    )
    assert "a1b2c3d4" not in resultado.texto
    assert "[CHAVE_PIX_MASCARADA]" in resultado.texto


def test_senha_acidental_e_mascarada():
    resultado = privacidade.mascarar_pii("Minha senha: SuperSecreta2026!")
    assert "SuperSecreta2026" not in resultado.texto
    assert "[CREDENCIAL_MASCARADA]" in resultado.texto


def test_token_e_api_key_sao_mascarados():
    resultado = privacidade.mascarar_pii("api_key = sk-ABCDEF123456 e token: xyz987654")
    assert "sk-ABCDEF123456" not in resultado.texto
    assert "xyz987654" not in resultado.texto


def test_telefone_brasileiro_e_mascarado():
    resultado = privacidade.mascarar_pii("Ligue para (11) 98765-4321 hoje.")
    assert "98765-4321" not in resultado.texto


def test_cnpj_valido_e_mascarado():
    resultado = privacidade.mascarar_pii("CNPJ 11.222.333/0001-81 da empresa.")
    assert "11.222.333/0001-81" not in resultado.texto


def test_dados_bancarios_sao_mascarados():
    resultado = privacidade.mascarar_pii("Agência 1234 Conta 56789-0")
    assert "56789-0" not in resultado.texto


def test_email_preserva_dominio_e_anonimiza_o_titular():
    # O domínio é o sinal antispoofing central: perdê-lo cegaria a detecção.
    resultado = privacidade.mascarar_pii("Escreva para joao.silva@bradesco.com.br")
    assert "joao.silva" not in resultado.texto
    assert "bradesco.com.br" in resultado.texto


def test_url_suspeita_sobrevive_ao_mascaramento():
    # Sem a URL, a Camada 2 não consegue julgar o phishing.
    texto = "Acesse http://bradesco-seguranca.xyz/atualizar agora"
    resultado = privacidade.mascarar_pii(texto)
    assert "bradesco-seguranca.xyz" in resultado.texto


def test_texto_sem_pii_permanece_intacto():
    texto = "Reunião de alinhamento do projeto na próxima terça-feira às 14h."
    resultado = privacidade.mascarar_pii(texto)
    assert resultado.texto == texto
    assert not resultado.houve_mascaramento


def test_acentuacao_e_preservada():
    texto = "Atenção: sua manutenção não foi concluída em função da inscrição."
    assert privacidade.mascarar_pii(texto).texto == texto


def test_entrada_vazia_ou_nula_nao_quebra():
    assert privacidade.mascarar_pii("").texto == ""
    assert privacidade.mascarar_pii(None).texto == ""


def test_texto_gigante_e_truncado_para_proteger_a_cpu():
    resultado = privacidade.mascarar_pii("a" * 50_000)
    assert len(resultado.texto) <= privacidade.LIMITE_CARACTERES_ANALISE


def test_email_de_phishing_completo_perde_toda_a_pii():
    texto = (
        "Prezado cliente, detectamos uma pendência. Confirme o CPF 111.444.777-35, "
        "o cartão 4111 1111 1111 1111, a senha: MinhaSenha123 e o telefone "
        "(11) 98765-4321. Responda para golpista@fraude-banco.xyz ou acesse "
        "http://fraude-banco.xyz/login. CEP 01310-100."
    )
    resultado = privacidade.mascarar_pii(texto)
    for segredo in (
        "111.444.777-35",
        "4111 1111 1111 1111",
        "MinhaSenha123",
        "98765-4321",
        "golpista",
        "01310-100",
    ):
        assert segredo not in resultado.texto, f"PII vazou: {segredo}"
    # O sinal técnico de fraude precisa sobreviver.
    assert "fraude-banco.xyz" in resultado.texto


# ---------------------------------------------------------------------------
# 2. Pseudonimização — estável, irreversível, com escopo
# ---------------------------------------------------------------------------

def test_pseudonimo_e_estavel_para_o_mesmo_valor():
    assert privacidade.pseudonimizar("ana@empresa.com") == privacidade.pseudonimizar(
        "ANA@empresa.com "
    )


def test_pseudonimo_difere_entre_titulares():
    assert privacidade.pseudonimizar("ana@empresa.com") != privacidade.pseudonimizar(
        "bruno@empresa.com"
    )


def test_pseudonimo_difere_entre_escopos():
    # Impede correlacionar "usuário X" com "tenant X" a partir dos hashes.
    assert privacidade.pseudonimizar("acme", escopo="conta") != privacidade.pseudonimizar(
        "acme", escopo="tenant"
    )


def test_pseudonimo_nao_contem_o_valor_original():
    hash_gerado = privacidade.pseudonimizar("ana@empresa.com")
    assert "ana" not in hash_gerado and "empresa" not in hash_gerado


def test_pseudonimo_de_valor_vazio_e_nulo():
    assert privacidade.pseudonimizar(None) is None
    assert privacidade.pseudonimizar("   ") is None


# ---------------------------------------------------------------------------
# 3. Retenção zero — o contrato de persistência não admite conteúdo
# ---------------------------------------------------------------------------

CAMPOS_PROIBIDOS = {
    "mensagem",
    "mensagem_usuario",
    "corpo",
    "corpo_texto",
    "assunto",
    "resposta",
    "resposta_bot",
    "texto",
    "conteudo",
    "explicacao",
    "remetente",
}


def test_evento_de_telemetria_nao_possui_campo_de_conteudo():
    nomes = {campo.name for campo in fields(EventoTelemetria)}
    vazamentos = nomes & CAMPOS_PROIBIDOS
    assert not vazamentos, f"Campo de conteúdo no contrato de persistência: {vazamentos}"


def test_insert_de_telemetria_nao_referencia_colunas_de_conteudo():
    import persistencia

    sql = persistencia._SQL_INSERIR.lower()
    for coluna in persistencia.COLUNAS_LEGADAS_COM_CONTEUDO:
        assert coluna not in sql, f"O INSERT ainda grava a coluna de conteúdo '{coluna}'."


def test_consulta_publica_nao_seleciona_colunas_de_conteudo():
    import persistencia

    colunas = persistencia._COLUNAS_PUBLICAS.lower()
    for coluna in persistencia.COLUNAS_LEGADAS_COM_CONTEUDO:
        assert coluna not in colunas, f"A leitura pública expõe a coluna '{coluna}'."


def test_manifesto_declara_o_que_nunca_e_persistido():
    manifesto = privacidade.MANIFESTO_LGPD
    assert manifesto["dados_nunca_persistidos"]
    assert any(
        "corpo" in item for item in manifesto["dados_nunca_persistidos"]
    ), "O manifesto deve declarar explicitamente que o corpo não é persistido."


def test_selo_de_transparencia_declara_retencao_nenhuma():
    selo = privacidade.selo_transparencia()
    assert selo["retencao_conteudo"] == "nenhuma"
    assert selo["anonimizacao_antes_da_ia"] is True


# ---------------------------------------------------------------------------
# 4. Higiene do remetente
# ---------------------------------------------------------------------------

def test_remetente_perde_o_nome_de_exibicao_e_mantem_o_endereco():
    assert privacidade.mascarar_remetente("João Silva <joao@banco.com>") == "joao@banco.com"


def test_dominio_e_extraido_em_minusculas():
    assert privacidade.extrair_dominio("Fake <a@Fraude-Banco.XYZ>") == "fraude-banco.xyz"


def test_remetente_ausente_nao_quebra():
    assert privacidade.extrair_dominio("") == "desconhecido"
    assert privacidade.extrair_dominio(None) == "desconhecido"


# ---------------------------------------------------------------------------
# Execução direta (sem pytest)
# ---------------------------------------------------------------------------

def _executar_sem_pytest() -> int:
    testes = [
        (nome, funcao)
        for nome, funcao in sorted(globals().items())
        if nome.startswith("test_") and callable(funcao)
    ]
    falhas = 0
    for nome, funcao in testes:
        try:
            funcao()
            print(f"  [OK]    {nome}")
        except AssertionError as erro:
            falhas += 1
            print(f"  [FALHA] {nome}: {erro}")
        except Exception as erro:  # pragma: no cover
            falhas += 1
            print(f"  [ERRO]  {nome}: {type(erro).__name__}: {erro}")
    print(f"\n{len(testes) - falhas}/{len(testes)} testes de conformidade aprovados.")
    return 1 if falhas else 0


if __name__ == "__main__":
    raise SystemExit(_executar_sem_pytest())
