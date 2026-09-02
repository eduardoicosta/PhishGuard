"""
PhishGuard API — Barramento de Detecção de Phishing (SECaaS).

Arquitetura em camadas
----------------------
Camada 0 — Reputação: whitelist de domínios corporativos verificados.
Camada 1 — Estatística: ensemble Random Forest + XGBoost sobre TF-IDF (local,
           determinístico, sem dependência de rede).
Camada 2 — Contextual: Google Gemini, acionado SOMENTE com o texto já
           anonimizado pelo módulo `privacidade`.

Garantias de privacidade (LGPD by Design)
-----------------------------------------
* O corpo do e-mail e as mensagens do hub existem apenas em memória volátil,
  pelo tempo da requisição. Nenhum endpoint deste arquivo grava conteúdo.
* Toda saída de texto rumo a um processador externo passa obrigatoriamente por
  `privacidade.mascarar_pii()`.
* A persistência é feita exclusivamente por `persistencia.EventoTelemetria`,
  cujo contrato de campos não admite conteúdo.

Segmentação de negócio
----------------------
O mesmo motor atende dois públicos, separados pelo campo `perfil` do payload:
* B2C (PhishGuard Personal) — métricas individuais em `/api/metricas/pessoal`.
* B2B (PhishGuard Enterprise) — governança de equipe em `/api/metricas/corporativo`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sys
from asyncio import CancelledError
from contextlib import asynccontextmanager
from typing import Dict, List, Literal, Optional

import joblib
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

import persistencia
import privacidade
from persistencia import EventoTelemetria
from resiliencia import (
    CircuitBreaker,
    CircuitoAberto,
    MedidorLatencia,
    executar_com_resiliencia,
)

load_dotenv()

# ---------------------------------------------------------------------------
# Observabilidade
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=os.getenv("PHISHGUARD_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("phishguard.api")

# Regra de ouro do log: NADA de conteúdo do usuário. Apenas metadados.
logging.getLogger("phishguard").setLevel(
    os.getenv("PHISHGUARD_LOG_LEVEL", "INFO").upper()
)

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

VERSAO_API = "2.0.0"

LIMIAR_CAMADA_1 = float(os.getenv("PHISHGUARD_LIMIAR_CAMADA_1", "0.35"))
GEMINI_MODEL = os.getenv("PHISHGUARD_GEMINI_MODEL", "gemini-3.5-flash")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_TIMEOUT_S = float(os.getenv("PHISHGUARD_GEMINI_TIMEOUT", "12"))
GEMINI_TENTATIVAS = int(os.getenv("PHISHGUARD_GEMINI_TENTATIVAS", "2"))

# Token de administração dos endpoints de governança. Quando ausente a API opera
# em modo de desenvolvimento (aberto) e o avisa explicitamente em /health.
ADMIN_TOKEN = os.getenv("PHISHGUARD_ADMIN_TOKEN")

DOMINIOS_WHITELIST = {
    "fiap.com.br", "gmail.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "aws.amazon.com", "github.com", "gitlab.com", "linkedin.com",
    "slack.com", "zoom.us", "atlassian.com", "gov.br", "sp.gov.br",
    "ccee.org.br", "itau.com.br", "nubank.com.br", "bb.com.br",
    "caixa.gov.br", "bradesco.com.br", "picpay.com", "mercadolivre.com.br",
    "ifood.com.br", "uber.com", "netflix.com",
}

# Estado global carregado no lifespan.
vetorizador = None
modelo_rf = None
modelo_xgb = None
cliente_gemini: Optional[genai.Client] = None
banco_ativo = False

# Um circuito por rota de uso do Gemini: um incidente no canal de e-mail não
# derruba o hub conversacional e vice-versa.
breaker_email = CircuitBreaker(nome="gemini_email", limite_falhas=5, segundos_recuperacao=30)
breaker_hub = CircuitBreaker(nome="gemini_hub", limite_falhas=5, segundos_recuperacao=30)


# ---------------------------------------------------------------------------
# Ciclo de vida
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global vetorizador, modelo_rf, modelo_xgb, cliente_gemini, banco_ativo

    caminhos = {
        "vetorizador": os.path.join(MODEL_DIR, "vetorizador.pkl"),
        "random_forest": os.path.join(MODEL_DIR, "random_forest.pkl"),
        "xgboost": os.path.join(MODEL_DIR, "xgboost.pkl"),
    }
    faltando = [nome for nome, caminho in caminhos.items() if not os.path.exists(caminho)]
    if faltando:
        raise RuntimeError(
            f"Modelos não encontrados em '{MODEL_DIR}': {', '.join(faltando)}. "
            "Execute 'python src/ml_engine.py' para treinar e exportar os arquivos .pkl."
        )

    vetorizador = joblib.load(caminhos["vetorizador"])
    modelo_rf = joblib.load(caminhos["random_forest"])
    modelo_xgb = joblib.load(caminhos["xgboost"])
    logger.info("Camada 1 carregada (Random Forest + XGBoost).")

    # O banco é telemetria, não é caminho crítico: falha nele não impede subir.
    banco_ativo = persistencia.inicializar_banco()

    if GEMINI_API_KEY:
        cliente_gemini = genai.Client(api_key=GEMINI_API_KEY)
        logger.info("Camada 2 habilitada (modelo %s).", GEMINI_MODEL)
    else:
        logger.warning("GEMINI_API_KEY ausente: a dupla checagem ficará indisponível.")

    if not privacidade.SAL_CONFIGURADO:
        logger.warning(
            "PHISHGUARD_SAL_PSEUDONIMO não definido. Um sal efêmero foi gerado: "
            "os hashes de conta não serão estáveis entre reinícios."
        )
    if ADMIN_TOKEN is None:
        logger.warning(
            "PHISHGUARD_ADMIN_TOKEN não definido: endpoints de governança abertos "
            "(aceitável apenas em desenvolvimento)."
        )

    yield

    # Drena a telemetria pendente antes de fechar o pool: sem isso, os últimos
    # eventos agendados em background seriam perdidos no desligamento.
    pendentes = persistencia.tarefas_pendentes()
    if pendentes:
        logger.info("Drenando %s evento(s) de telemetria pendentes.", len(pendentes))
        await asyncio.gather(*pendentes, return_exceptions=True)

    persistencia.encerrar_pool()
    logger.info("PhishGuard API encerrada com segurança.")


class UTF8JSONResponse(JSONResponse):
    """Resposta JSON que preserva acentuação (ensure_ascii=False) e declara charset=utf-8."""

    media_type = "application/json; charset=utf-8"

    def render(self, content) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=True,
            indent=None,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")


app = FastAPI(
    title="PhishGuard API",
    version=VERSAO_API,
    description=(
        "Detecção de phishing multicanal com dupla checagem "
        "(ensemble estatístico + Gemini) e arquitetura LGPD by Design: "
        "retenção zero de conteúdo e anonimização preventiva de PII."
    ),
    lifespan=lifespan,
    default_response_class=UTF8JSONResponse,
)

# CORS: consumidores reais são a extensão (chrome-extension://<id> variável),
# os webmails suportados e os painéis servidos localmente ou abertos via file://
# (que enviam Origin "null"). Sem cookies, allow_credentials permanece desligado.
ORIGENS_PADRAO = [
    "https://outlook.live.com",
    "https://outlook.office.com",
    "https://outlook.office365.com",
    "https://mail.google.com",
    "null",
]
_origens_extra = os.getenv("PHISHGUARD_CORS_ORIGENS", "")
ORIGENS_PERMITIDAS = ORIGENS_PADRAO + [
    origem.strip() for origem in _origens_extra.split(",") if origem.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ORIGENS_PERMITIDAS,
    # Extensões de navegador e qualquer porta de localhost (painéis em dev).
    allow_origin_regex=(
        r"^(chrome-extension|moz-extension)://.*$"
        r"|^https?://(localhost|127\.0\.0\.1)(:\d+)?$"
    ),
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)


@app.middleware("http")
async def cabecalhos_de_seguranca(request: Request, call_next):
    """
    Duas responsabilidades:

    1) Private Network Access: o Chrome bloqueia requisições de uma origem
       pública (https://outlook.live.com) para o espaço de loopback
       (http://localhost:8000). O preflight traz
       'Access-Control-Request-Private-Network: true' e exige
       'Access-Control-Allow-Private-Network: true' na resposta — algo que o
       CORSMiddleware padrão não emite.
    2) Cabeçalhos de endurecimento (nosniff, no-store) — a resposta pode conter
       o veredito de segurança do usuário e não deve ser cacheada por proxies.
    """
    if (
        request.method == "OPTIONS"
        and "access-control-request-private-network" in request.headers
    ):
        origem = request.headers.get("origin", "*")
        acr_headers = request.headers.get("access-control-request-headers", "*")
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": origem,
                "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": acr_headers,
                "Access-Control-Allow-Private-Network": "true",
                "Access-Control-Max-Age": "3600",
                "Vary": "Origin",
            },
        )

    response = await call_next(request)
    response.headers.setdefault("Access-Control-Allow-Private-Network", "true")
    if "origin" in request.headers:
        response.headers.setdefault(
            "Access-Control-Allow-Origin", request.headers["origin"]
        )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    # Selo de conformidade legível por máquina, em toda resposta.
    response.headers.setdefault("X-PhishGuard-Data-Retention", "none")
    return response


# ---------------------------------------------------------------------------
# Autorização dos endpoints de governança
# ---------------------------------------------------------------------------

async def exigir_token_admin(
    x_phishguard_token: Optional[str] = Header(default=None),
) -> None:
    """Protege os endpoints B2B/auditoria quando PHISHGUARD_ADMIN_TOKEN está definido."""
    if ADMIN_TOKEN is None:
        return  # modo desenvolvimento, sinalizado em /health
    if not x_phishguard_token or x_phishguard_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Credencial de governança inválida.")


# ---------------------------------------------------------------------------
# Contratos de entrada e saída
# ---------------------------------------------------------------------------

PerfilConta = Literal["B2C", "B2B"]


class ContextoConta(BaseModel):
    """
    Identificação da conta — pseudonimizada no servidor, nunca armazenada em claro.

    `id_conta` pode ser o e-mail do usuário ou um UUID gerado localmente pela
    extensão; em ambos os casos apenas o HMAC derivado chega ao banco.
    """

    perfil: PerfilConta = Field(default="B2C", description="B2C (Personal) ou B2B (Enterprise)")
    id_conta: Optional[str] = Field(default=None, max_length=256)
    organizacao: Optional[str] = Field(default=None, max_length=256)


class EmailAnaliseRequest(ContextoConta):
    assunto: str = Field(default="", max_length=1000)
    corpo_texto: str = Field(default="", max_length=200_000)
    remetente: str = Field(default="", max_length=500)


class BlocoPrivacidade(BaseModel):
    """Selo de transparência devolvido em cada análise."""

    versao_politica: str
    retencao_conteudo: str
    processamento: str
    anonimizacao_antes_da_ia: bool
    dados_sensiveis_mascarados: int = 0
    tipos_mascarados: List[str] = Field(default_factory=list)


class EmailAnaliseResponse(BaseModel):
    score_risco: float
    is_phishing: bool
    nivel_alerta: str
    explicacao: str
    veredito_gemini: Optional[bool] = Field(
        default=None, description="Veredito do Gemini. Null quando a Camada 2 não foi acionada."
    )
    dupla_checagem: bool = Field(
        default=False, description="Indica se o e-mail passou pela análise contextual do Gemini."
    )
    origem_veredito: str = Field(default="camada_2")
    latencia_ms: int = 0
    privacidade: BlocoPrivacidade


class MensagemHubRequest(ContextoConta):
    mensagem: str = Field(default="", max_length=20_000)


class MensagemHubResponse(BaseModel):
    resposta: str
    privacidade: BlocoPrivacidade


class VereditoGemini(BaseModel):
    is_phishing_real: bool
    explicacao: str


# ---------------------------------------------------------------------------
# Camada 1 — motor estatístico
# ---------------------------------------------------------------------------

def modelos_prontos() -> bool:
    return not (vetorizador is None or modelo_rf is None or modelo_xgb is None)


def garantir_modelos() -> None:
    if not modelos_prontos():
        raise HTTPException(status_code=503, detail="Modelos de IA ainda não foram carregados.")


def calcular_score_risco(assunto: str, corpo_texto: str, remetente: str) -> float:
    """Probabilidade média do ensemble. Domínio na whitelist zera o score base."""
    dominio = privacidade.extrair_dominio(remetente)
    if dominio in DOMINIOS_WHITELIST:
        return 0.0

    texto_completo = f"{assunto} {corpo_texto}".strip()
    if not texto_completo:
        return 0.0

    vetor_texto = vetorizador.transform([texto_completo])
    prob_rf = float(modelo_rf.predict_proba(vetor_texto)[0][1])
    prob_xgb = float(modelo_xgb.predict_proba(vetor_texto)[0][1])
    return (prob_rf + prob_xgb) / 2


# ---------------------------------------------------------------------------
# Camada 2 — Gemini (recebe SOMENTE texto anonimizado)
# ---------------------------------------------------------------------------

def _extrair_json_resposta(texto: str) -> dict:
    texto = (texto or "").strip()
    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{.*\}", texto, re.DOTALL)
    if match:
        return json.loads(match.group())
    raise ValueError("Resposta do Gemini não contém JSON válido.")


INSTRUCAO_EMAIL = (
    "Você é um analista sênior de cibersegurança e especialista em detecção de phishing. "
    "Sua tarefa é analisar o e-mail fornecido com extrema precisão técnica, baseando-se "
    "EXATAMENTE nos dados reais extraídos do cabeçalho e do corpo do e-mail.\n\n"
    "REGRAS CRÍTICAS DE ANÁLISE:\n"
    "1. NUNCA invente, suponha ou alucine informações sobre o remetente. O campo 'De:' "
    "analisado deve ser estritamente o que consta no e-mail original. Se o remetente vier "
    "como '(remetente não informado)', significa apenas que a extensão não conseguiu ler o "
    "cabeçalho 'De:' nesta tela — NÃO trate isso como indício de fraude, NÃO invente um "
    "domínio e baseie a análise no assunto e no corpo. Nunca analise spoofing de um domínio "
    "chamado 'desconhecido'.\n"
    "2. VERIFICAÇÃO DE DOMÍNIO LEGÍTIMO: antes de classificar como phishing, verifique se o "
    "domínio do remetente pertence oficialmente à marca citada. Não rotule domínios "
    "corporativos legítimos como 'genéricos' ou 'falsos'.\n"
    "3. CRITÉRIO DE PHISHING REAL: só classifique como phishing se houver indícios claros de "
    "engenharia social maliciosa, links para domínios desalinhados com a marca ou spoofing "
    "comprovado. E-mails transacionais legítimos NÃO são phishing.\n"
    "4. FORMATO DE SAÍDA: seja objetivo e técnico. Se o e-mail for legítimo, explique de forma "
    "detalhada por que ele é seguro, em vez de devolver apenas um rótulo.\n"
    "5. PRIVACIDADE: trechos como [CPF_MASCARADO], [CARTAO_MASCARADO], [TELEFONE_MASCARADO], "
    "[CREDENCIAL_MASCARADA] ou [USUARIO_MASCARADO] são anonimizações aplicadas pelo PhishGuard "
    "para proteger o titular dos dados. Interprete-os como o tipo de dado indicado, NUNCA peça "
    "o valor original e NUNCA cite essas tags na sua explicação ao usuário final.\n"
    "6. IDIOMA E ACENTUAÇÃO: a explicação final DEVE ser escrita em Português do Brasil "
    "impecável, preservando toda a acentuação gráfica nativa e a pontuação adequada."
)

INSTRUCAO_WHATSAPP = (
    "Você é o assistente virtual do PhishGuard no WhatsApp. Sua função é analisar textos e links "
    "encaminhados por usuários em chats de mensagens. "
    "NUNCA mencione e-mail, remetentes de e-mail, assuntos ou cabeçalhos. "
    "Analise estritamente a mensagem em busca de engenharia social, urgência artificial, golpes "
    "conhecidos (falsas taxas dos Correios/Receita Federal, clonagem de cartão, falso suporte "
    "bancário) e links maliciosos. "
    "Trechos como [CPF_MASCARADO] ou [CHAVE_PIX_MASCARADA] são anonimizações de privacidade "
    "aplicadas pelo PhishGuard: interprete-os como o tipo de dado indicado e nunca os cite na "
    "resposta ao usuário. "
    "A sua explicação final DEVE ser escrita em Português do Brasil impecável, preservando toda a "
    "acentuação gráfica nativa e pontuação adequada."
)

INSTRUCAO_WEBCHAT = (
    "Você é a IA de atendimento híbrido do PhishGuard, uma solução de SECaaS "
    "(Security as a Service) de proteção contra phishing com ofertas para empresas (Enterprise) "
    "e para pessoas físicas (Personal).\n"
    "Sua atuação deve se adaptar dinamicamente ao objetivo do usuário:\n\n"
    "PAPEL 1: VENDAS E SUPORTE (saudações, dúvidas sobre o produto, preços, planos):\n"
    "- Seja um assistente comercial profissional, persuasivo e simpático.\n"
    "- Identifique se o interlocutor é pessoa física (B2C) ou empresa (B2B) e apresente a linha "
    "correspondente:\n"
    "  • PhishGuard Personal (B2C) — R$ 9,90/mês por pessoa: extensão para Gmail e Outlook, "
    "análise ilimitada de e-mails, hub no WhatsApp e painel pessoal de proteção.\n"
    "  • PhishGuard Enterprise (B2B) — Plano Starter R$ 15/colaborador/mês (extensão + motor "
    "estatístico) e Plano Enterprise R$ 25/colaborador/mês (extensão + IA Gemini + Hub "
    "WhatsApp + Painel SOC de governança).\n"
    "- Destaque dois diferenciais: o hub conversacional unificado e a arquitetura de privacidade "
    "com retenção zero (nenhum conteúdo de e-mail é armazenado).\n\n"
    "PAPEL 2: ANÁLISE DE RISCO (o usuário envia link, mensagem ou texto suspeito):\n"
    "- Ignore o papel comercial e atue estritamente como Analista de Segurança.\n"
    "- Use o [Contexto de Riscos Sincronizados] do prompt para apoiar o veredito.\n"
    "- Se for golpe, use emojis de alerta (🚨, ⚠️) e oriente a não clicar.\n"
    "- Se for seguro, tranquilize com argumentos técnicos.\n"
    "- NUNCA cite termos de e-mail (cabeçalhos, remetentes, campos 'De/Assunto') a menos que o "
    "usuário tenha enviado explicitamente um cabeçalho de e-mail.\n\n"
    "Trechos como [CPF_MASCARADO] são anonimizações de privacidade do PhishGuard: nunca os cite "
    "na resposta. "
    "Responda sempre em português brasileiro com formatação amigável para chat (negrito com "
    "asteriscos e emojis), preservando acentuação impecável."
)


def _gerar_veredito(prompt: str, instrucao_sistema: str) -> VereditoGemini:
    if cliente_gemini is None:
        raise RuntimeError("Cliente Gemini não configurado. Defina GEMINI_API_KEY no ambiente.")

    resposta = cliente_gemini.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.2,
            thinking_config=types.ThinkingConfig(thinking_budget=0),
            system_instruction=instrucao_sistema,
            response_mime_type="application/json",
            response_json_schema=VereditoGemini.model_json_schema(),
        ),
    )
    return VereditoGemini.model_validate(_extrair_json_resposta(resposta.text or ""))


def consultar_gemini_email(
    remetente: str, assunto: str, corpo_anonimizado: str, score_risco: float
) -> VereditoGemini:
    prompt = (
        f"Analise o seguinte e-mail. O modelo estatístico anterior classificou este e-mail "
        f"com score de risco de {score_risco * 100:.1f}%.\n\n"
        f"Remetente: {remetente}\n"
        f"Assunto: {assunto}\n"
        f"Texto do e-mail (com dados pessoais já anonimizados):\n{corpo_anonimizado}\n"
    )
    return _gerar_veredito(prompt, INSTRUCAO_EMAIL)


def consultar_gemini_whatsapp(mensagem_anonimizada: str, score_risco: float) -> VereditoGemini:
    prompt = (
        f"Analise o seguinte texto enviado via WhatsApp. O modelo estatístico preliminar "
        f"classificou esta mensagem com score de risco de {score_risco * 100:.1f}%.\n\n"
        f"Texto (com dados pessoais já anonimizados):\n{mensagem_anonimizada}\n"
    )
    return _gerar_veredito(prompt, INSTRUCAO_WHATSAPP)


def consultar_gemini_webchat(mensagem_anonimizada: str, score_risco: float) -> str:
    if cliente_gemini is None:
        raise RuntimeError("Cliente Gemini não configurado.")

    score_phishing = max(score_risco, 0.85) * 100
    score_seguro = min(score_risco, 0.15) * 100
    prompt = (
        f"Mensagem do usuário (com dados pessoais já anonimizados):\n{mensagem_anonimizada}\n\n"
        f"[Contexto de Riscos Sincronizados]\n"
        f"- Se classificar como PHISHING/GOLPE, use obrigatoriamente o score de risco de "
        f"exatamente {score_phishing:.1f}%.\n"
        f"- Se classificar como SEGURA, ou se for dúvida comercial, use obrigatoriamente o score "
        f"de risco de exatamente {score_seguro:.1f}% caso precise citar alguma porcentagem."
    )
    resposta = cliente_gemini.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.3,
            thinking_config=types.ThinkingConfig(thinking_budget=0),
            system_instruction=INSTRUCAO_WEBCHAT,
        ),
    )
    return resposta.text or ""


# ---------------------------------------------------------------------------
# Utilidades compartilhadas
# ---------------------------------------------------------------------------

def montar_bloco_privacidade(*resultados: privacidade.ResultadoMascaramento) -> BlocoPrivacidade:
    tipos: Dict[str, int] = {}
    for resultado in resultados:
        for nome, quantidade in resultado.ocorrencias.items():
            tipos[nome] = tipos.get(nome, 0) + quantidade
    selo = privacidade.selo_transparencia()
    return BlocoPrivacidade(
        versao_politica=str(selo["versao_politica"]),
        retencao_conteudo=str(selo["retencao_conteudo"]),
        processamento=str(selo["processamento"]),
        anonimizacao_antes_da_ia=bool(selo["anonimizacao_antes_da_ia"]),
        dados_sensiveis_mascarados=sum(tipos.values()),
        tipos_mascarados=sorted(tipos),
    )


def _resumo_tipos(*resultados: privacidade.ResultadoMascaramento) -> Optional[str]:
    tipos: Dict[str, int] = {}
    for resultado in resultados:
        for nome, quantidade in resultado.ocorrencias.items():
            tipos[nome] = tipos.get(nome, 0) + quantidade
    if not tipos:
        return None
    return ", ".join(f"{nome}={qtd}" for nome, qtd in sorted(tipos.items()))


def registrar_telemetria(
    contexto: ContextoConta,
    canal: str,
    is_phishing: bool,
    score: float,
    nivel: str,
    dupla_checagem: bool,
    origem: str,
    latencia_ms: int,
    dominio: Optional[str],
    *resultados: privacidade.ResultadoMascaramento,
) -> None:
    """Enfileira APENAS metadados. Nenhum argumento desta função carrega conteúdo."""
    if not banco_ativo:
        return
    total_pii = sum(resultado.total for resultado in resultados)
    persistencia.agendar_registro(
        EventoTelemetria(
            canal=canal,
            risco_detectado="Phishing" if is_phishing else "Seguro",
            score_risco=round(score, 4),
            nivel_alerta=nivel,
            tipo_conta=contexto.perfil,
            tenant_hash=privacidade.pseudonimizar(contexto.organizacao, escopo="tenant"),
            usuario_hash=privacidade.pseudonimizar(contexto.id_conta, escopo="conta"),
            dominio_remetente=dominio,
            dupla_checagem=dupla_checagem,
            pii_mascarado_qtd=total_pii,
            pii_tipos=_resumo_tipos(*resultados),
            latencia_ms=latencia_ms,
            origem_veredito=origem,
        )
    )


# ---------------------------------------------------------------------------
# Endpoints — análise de e-mail (extensão)
# ---------------------------------------------------------------------------

@app.post("/analisar-email", response_model=EmailAnaliseResponse)
async def analisar_email(payload: EmailAnaliseRequest):
    """
    Análise stateless do e-mail.

    O `payload.corpo_texto` vive apenas no escopo desta função. Ele é anonimizado
    antes de sair para a Camada 2 e é descartado com o retorno — nenhuma linha
    abaixo o grava, loga ou serializa em resposta.
    """
    garantir_modelos()
    medidor = MedidorLatencia()

    try:
        # 1. Anonimização preventiva (LGPD Art. 12) — antes de qualquer uso externo.
        corpo = privacidade.mascarar_pii(payload.corpo_texto)
        assunto = privacidade.mascarar_pii(payload.assunto)
        remetente_tecnico = privacidade.mascarar_remetente(payload.remetente)
        dominio = privacidade.extrair_dominio(payload.remetente)

        # 2. Camada 1 — estatística local sobre o texto original em memória.
        score_risco = await asyncio.to_thread(
            calcular_score_risco, payload.assunto, payload.corpo_texto, payload.remetente
        )

        # 3. Camada 2 — contextual, com resiliência (timeout + retry + breaker).
        try:
            veredito = await executar_com_resiliencia(
                consultar_gemini_email,
                remetente_tecnico,
                assunto.texto,
                corpo.texto,
                score_risco,
                timeout_s=GEMINI_TIMEOUT_S,
                tentativas=GEMINI_TENTATIVAS,
                breaker=breaker_email,
                rotulo="gemini_email",
            )
            is_phishing = veredito.is_phishing_real
            nivel_alerta = "CRITICO" if is_phishing else "SEGURO"
            explicacao = veredito.explicacao
            dupla_checagem = True
            origem = "camada_2"
        except CancelledError:
            raise
        except (CircuitoAberto, Exception) as erro:
            # Degradação graciosa: em vez de alarmar todo e-mail, caímos para o
            # veredito determinístico da Camada 1 e sinalizamos a incerteza.
            logger.warning(
                "Camada 2 indisponível para o canal de e-mail (%s). "
                "Aplicando veredito da Camada 1.",
                type(erro).__name__,
            )
            is_phishing = score_risco >= LIMIAR_CAMADA_1
            nivel_alerta = "ATENÇÃO"
            dupla_checagem = False
            origem = "camada_1_fallback"
            explicacao = (
                "A análise contextual por IA está temporariamente indisponível. "
                + (
                    "O motor estatístico local identificou padrões compatíveis com "
                    "phishing neste e-mail: não clique em links nem informe dados."
                    if is_phishing
                    else "O motor estatístico local não encontrou padrões de fraude, "
                    "mas mantenha cautela com links e solicitações de dados."
                )
            )

        latencia = medidor.ms
        bloco = montar_bloco_privacidade(corpo, assunto)

        registrar_telemetria(
            payload, "extensao", is_phishing, score_risco, nivel_alerta,
            dupla_checagem, origem, latencia, dominio, corpo, assunto,
        )

        logger.info(
            "analise canal=extensao perfil=%s veredito=%s score=%.3f dominio=%s "
            "pii_mascarados=%s latencia=%sms origem=%s",
            payload.perfil,
            "Phishing" if is_phishing else "Seguro",
            score_risco,
            dominio,
            bloco.dados_sensiveis_mascarados,
            latencia,
            origem,
        )

        return EmailAnaliseResponse(
            score_risco=round(score_risco, 4),
            is_phishing=is_phishing,
            nivel_alerta=nivel_alerta,
            explicacao=explicacao,
            veredito_gemini=is_phishing if dupla_checagem else None,
            dupla_checagem=dupla_checagem,
            origem_veredito=origem,
            latencia_ms=latencia,
            privacidade=bloco,
        )

    except CancelledError:
        # Navegação rápida do usuário: encerra sem traceback nem 500 no terminal.
        logger.debug("Análise de e-mail cancelada pelo cliente.")
        raise


# ---------------------------------------------------------------------------
# Endpoints — hub conversacional
# ---------------------------------------------------------------------------

@app.post("/webhook/whatsapp", response_model=MensagemHubResponse)
async def webhook_whatsapp(payload: MensagemHubRequest):
    garantir_modelos()
    medidor = MedidorLatencia()

    mensagem = (payload.mensagem or "").strip()
    if not mensagem:
        return MensagemHubResponse(
            resposta="⚠️ Por favor, envie uma mensagem válida para análise.",
            privacidade=montar_bloco_privacidade(),
        )

    try:
        anonimizada = privacidade.mascarar_pii(mensagem)
        score_risco = await asyncio.to_thread(calcular_score_risco, "", mensagem, "")

        try:
            veredito = await executar_com_resiliencia(
                consultar_gemini_whatsapp,
                anonimizada.texto,
                score_risco,
                timeout_s=GEMINI_TIMEOUT_S,
                tentativas=GEMINI_TENTATIVAS,
                breaker=breaker_hub,
                rotulo="gemini_whatsapp",
            )
            is_phishing = veredito.is_phishing_real
            explicacao = veredito.explicacao
            dupla_checagem = True
            origem = "camada_2"
        except CancelledError:
            raise
        except (CircuitoAberto, Exception):
            is_phishing = score_risco >= LIMIAR_CAMADA_1
            explicacao = (
                "Análise preventiva realizada pelo motor estatístico local. "
                "A checagem contextual por IA está temporariamente indisponível."
            )
            dupla_checagem = False
            origem = "camada_1_fallback"

        if is_phishing:
            score_exibicao = max(score_risco, 0.85)
            resposta_texto = (
                f"🚨 *Alerta PhishGuard!*\n\n"
                f"Analisei sua mensagem e ela tem *{score_exibicao * 100:.1f}%* de chance de ser "
                f"um golpe/phishing.\n\n"
                f"🔎 *Análise do bot:*\n{explicacao}\n\n"
                f"✅ *Recomendação:* não clique em nenhum link, não compartilhe códigos ou dados "
                f"pessoais e evite interagir com esse remetente!"
            )
        else:
            score_exibicao = min(score_risco, 0.15)
            resposta_texto = (
                f"🛡️ *PhishGuard Seguro!*\n\n"
                f"Analisei sua mensagem e o risco de golpe é muito baixo "
                f"(*{score_exibicao * 100:.1f}%*).\n\n"
                f"🔎 *Explicação:*\n{explicacao}\n\n"
                f"💡 *Dica:* mesmo que pareça seguro, fique sempre atento a links desconhecidos e "
                f"nunca forneça senhas ou dados confidenciais."
            )

        latencia = medidor.ms
        registrar_telemetria(
            payload, "whatsapp", is_phishing, score_risco,
            "CRITICO" if is_phishing else "SEGURO",
            dupla_checagem, origem, latencia, None, anonimizada,
        )
        logger.info(
            "analise canal=whatsapp perfil=%s veredito=%s score=%.3f pii_mascarados=%s "
            "latencia=%sms origem=%s",
            payload.perfil,
            "Phishing" if is_phishing else "Seguro",
            score_risco,
            anonimizada.total,
            latencia,
            origem,
        )

        return MensagemHubResponse(
            resposta=resposta_texto,
            privacidade=montar_bloco_privacidade(anonimizada),
        )

    except CancelledError:
        logger.debug("Análise de WhatsApp cancelada pelo cliente.")
        raise


@app.post("/webhook/webchat", response_model=MensagemHubResponse)
async def webhook_webchat(payload: MensagemHubRequest):
    garantir_modelos()
    medidor = MedidorLatencia()

    mensagem = (payload.mensagem or "").strip()
    if not mensagem:
        return MensagemHubResponse(
            resposta="Olá! Como posso ajudar você hoje?",
            privacidade=montar_bloco_privacidade(),
        )

    try:
        anonimizada = privacidade.mascarar_pii(mensagem)
        score_risco = await asyncio.to_thread(calcular_score_risco, "", mensagem, "")
        classificado_como_ameaca = score_risco >= LIMIAR_CAMADA_1

        try:
            resposta_texto = await executar_com_resiliencia(
                consultar_gemini_webchat,
                anonimizada.texto,
                score_risco,
                timeout_s=GEMINI_TIMEOUT_S,
                tentativas=GEMINI_TENTATIVAS,
                breaker=breaker_hub,
                rotulo="gemini_webchat",
            )
            # O webchat é dual (vendas + análise), então a resposta é texto livre:
            # o veredito vem do marcador de alerta emitido pelo próprio modelo.
            # Exigimos, porém, que a mensagem contenha um artefato analisável — um
            # link ou um score relevante da Camada 1. Sem isso, alguém apenas
            # PERGUNTANDO sobre golpes ("recebi um link dizendo X, é golpe?")
            # entraria nas métricas de governança como ameaça bloqueada,
            # inflando artificialmente o painel do CISO.
            classificado_como_ameaca = _contem_marcador_de_alerta(resposta_texto) and (
                _contem_artefato_analisavel(mensagem) or score_risco >= LIMIAR_CAMADA_1
            )
            dupla_checagem = True
            origem = "camada_2"
        except CancelledError:
            raise
        except (CircuitoAberto, Exception):
            dupla_checagem = False
            origem = "camada_1_fallback"
            resposta_texto = _resposta_webchat_local(mensagem, score_risco)
            classificado_como_ameaca = _contem_marcador_de_alerta(resposta_texto)

        latencia = medidor.ms
        registrar_telemetria(
            payload, "webchat", classificado_como_ameaca, score_risco,
            "CRITICO" if classificado_como_ameaca else "SEGURO",
            dupla_checagem, origem, latencia, None, anonimizada,
        )
        logger.info(
            "analise canal=webchat perfil=%s veredito=%s score=%.3f pii_mascarados=%s "
            "latencia=%sms origem=%s",
            payload.perfil,
            "Phishing" if classificado_como_ameaca else "Seguro",
            score_risco,
            anonimizada.total,
            latencia,
            origem,
        )

        return MensagemHubResponse(
            resposta=resposta_texto,
            privacidade=montar_bloco_privacidade(anonimizada),
        )

    except CancelledError:
        logger.debug("Análise de Webchat cancelada pelo cliente.")
        raise


MARCADOR_ALERTA = "\U0001F6A8"  # 🚨 — emitido pelo modelo ao classificar um golpe.
PADRAO_ARTEFATO = re.compile(r"https?://|www\.|\b[a-z0-9-]+\.(?:com|br|net|xyz|top|click|link|info|site|online)\b", re.IGNORECASE)


def _contem_marcador_de_alerta(resposta: str) -> bool:
    return MARCADOR_ALERTA in (resposta or "")


def _contem_artefato_analisavel(mensagem: str) -> bool:
    """Há de fato algo a analisar (um link/domínio) ou é só uma pergunta?"""
    return bool(PADRAO_ARTEFATO.search(mensagem or ""))


PALAVRAS_COMERCIAIS = (
    "preço", "preco", "plano", "valor", "mensal", "custo", "contratar", "comprar",
    "assinar", "starter", "enterprise", "personal", "phishguard", "funciona",
    "b2b", "b2c", "venda", "empresa", "comercial", "assinatura",
)


def _resposta_webchat_local(mensagem: str, score_risco: float) -> str:
    """Fallback determinístico do webchat quando a Camada 2 está fora do ar."""
    mensagem_lc = mensagem.lower()
    if any(palavra in mensagem_lc for palavra in PALAVRAS_COMERCIAIS):
        return (
            "Olá! O *PhishGuard* protege contra phishing e engenharia social em múltiplos "
            "canais (e-mail, WhatsApp e webchat), com uma arquitetura de *retenção zero*: "
            "nenhum conteúdo das suas mensagens é armazenado.\n\n"
            "👤 *PhishGuard Personal (para você e sua família) — R$ 9,90/mês:*\n"
            "- Extensão para Gmail e Outlook com análise ilimitada.\n"
            "- Hub de checagem no WhatsApp.\n"
            "- Painel pessoal com seu histórico de proteção.\n\n"
            "🏢 *PhishGuard Enterprise (para empresas):*\n"
            "- *Starter — R$ 15/colaborador/mês:* extensão desktop + motor estatístico de "
            "Machine Learning (Camada 1).\n"
            "- *Enterprise — R$ 25/colaborador/mês:* tudo do Starter + dupla checagem com IA "
            "Gemini (Camada 2), Hub WhatsApp e Painel SOC de governança.\n\n"
            "Quer agendar uma demonstração ou falar com um especialista?"
        )

    if score_risco >= LIMIAR_CAMADA_1:
        return (
            f"🚨 *Alerta de Phishing Detectado!*\n\n"
            f"Nossa análise estatística identificou um risco de "
            f"*{max(score_risco, 0.85) * 100:.1f}%* nesta mensagem.\n\n"
            f"*Análise:* o texto apresenta gatilhos associados a engenharia social, urgência "
            f"artificial ou links maliciosos.\n\n"
            f"*Recomendação:* não clique em links e não forneça informações confidenciais."
        )

    return (
        f"🛡️ *PhishGuard Seguro!*\n\n"
        f"Nossa análise estatística indica que esta mensagem parece segura "
        f"(risco estimado em *{min(score_risco, 0.15) * 100:.1f}%*).\n\n"
        f"*Dica:* mesmo assim, sempre desconfie de solicitações incomuns."
    )


# ---------------------------------------------------------------------------
# Endpoints — transparência e direitos do titular (LGPD)
# ---------------------------------------------------------------------------

@app.get("/api/privacidade")
async def politica_privacidade():
    """Manifesto público de transparência, consumido pela extensão e pelos painéis."""
    return UTF8JSONResponse(content=privacidade.MANIFESTO_LGPD)


@app.get("/api/privacidade/auditoria", dependencies=[Depends(exigir_token_admin)])
async def auditoria_privacidade():
    """Prova, em tempo de execução, que não há conteúdo persistido (auditoria externa)."""
    if not banco_ativo:
        return {
            "conforme": True,
            "observacao": "Banco de telemetria desativado: nada é persistido.",
        }
    try:
        return await asyncio.to_thread(persistencia.auditar_retencao)
    except Exception as erro:
        raise HTTPException(status_code=503, detail=f"Auditoria indisponível: {erro}")


@app.delete("/api/privacidade/meus-dados")
async def eliminar_meus_dados(
    id_conta: str = Query(..., min_length=1, max_length=256, description="Identificador da conta"),
):
    """
    Art. 18, VI — eliminação dos dados do titular.

    O identificador é pseudonimizado no servidor antes da exclusão; o valor em
    claro não é gravado em log nem em banco em nenhum momento.
    """
    if not banco_ativo:
        return {"removidos": 0, "observacao": "Nenhum dado a eliminar: telemetria desativada."}
    usuario_hash = privacidade.pseudonimizar(id_conta, escopo="conta")
    try:
        removidos = await asyncio.to_thread(persistencia.eliminar_dados_do_titular, usuario_hash)
    except Exception as erro:
        raise HTTPException(status_code=503, detail=f"Falha ao eliminar dados: {erro}")
    return {
        "removidos": removidos,
        "mensagem": (
            "Metadados eliminados. Lembre-se: o conteúdo das suas mensagens nunca foi "
            "armazenado, portanto não havia texto a excluir."
        ),
    }


# ---------------------------------------------------------------------------
# Endpoints — B2C (PhishGuard Personal)
# ---------------------------------------------------------------------------

@app.get("/api/metricas/pessoal")
async def metricas_pessoais(
    id_conta: str = Query(..., min_length=1, max_length=256),
    dias: int = Query(default=30, ge=1, le=365),
):
    """
    Visão do usuário final: o que a proteção fez por ELE.

    Deliberadamente não expõe nada de outros titulares — a consulta é filtrada
    pelo hash da própria conta.
    """
    if not banco_ativo:
        raise HTTPException(status_code=503, detail="Telemetria indisponível no momento.")

    usuario_hash = privacidade.pseudonimizar(id_conta, escopo="conta")
    try:
        resumo, serie, canais, eventos = await asyncio.gather(
            asyncio.to_thread(persistencia.resumo_agregado, dias, None, usuario_hash),
            asyncio.to_thread(persistencia.serie_temporal, min(dias, 30), None, usuario_hash),
            asyncio.to_thread(persistencia.distribuicao_por_canal, dias, None, usuario_hash),
            asyncio.to_thread(persistencia.listar_eventos, 25, None, usuario_hash, None),
        )
    except Exception as erro:
        raise HTTPException(status_code=503, detail=f"Erro ao consultar métricas: {erro}")

    total = resumo["total"]
    return {
        "perfil": "B2C",
        "produto": "PhishGuard Personal",
        "periodo_dias": dias,
        "identificador_pseudonimizado": usuario_hash,
        "resumo": {
            **resumo,
            "taxa_protecao_percentual": (
                round((resumo["seguros"] / total) * 100, 1) if total else 100.0
            ),
        },
        "serie_diaria": serie,
        "por_canal": canais,
        "historico": eventos,
        "assinatura": {
            "plano": "PhishGuard Personal",
            "status": "ativa",
            "canais_incluidos": ["Extensão Gmail/Outlook", "WhatsApp", "Webchat"],
        },
        "privacidade": privacidade.selo_transparencia(),
    }


# ---------------------------------------------------------------------------
# Endpoints — B2B (PhishGuard Enterprise / Painel SOC)
# ---------------------------------------------------------------------------

@app.get("/api/metricas/corporativo", dependencies=[Depends(exigir_token_admin)])
async def metricas_corporativas(
    organizacao: Optional[str] = Query(default=None, max_length=256),
    dias: int = Query(default=30, ge=1, le=365),
):
    """Visão do gestor de TI / CISO: postura de segurança da organização."""
    if not banco_ativo:
        raise HTTPException(status_code=503, detail="Telemetria indisponível no momento.")

    tenant_hash = privacidade.pseudonimizar(organizacao, escopo="tenant") if organizacao else None
    try:
        resumo, serie, canais, dominios, colaboradores, eventos = await asyncio.gather(
            asyncio.to_thread(persistencia.resumo_agregado, dias, tenant_hash, None),
            asyncio.to_thread(persistencia.serie_temporal, min(dias, 30), tenant_hash, None),
            asyncio.to_thread(persistencia.distribuicao_por_canal, dias, tenant_hash, None),
            asyncio.to_thread(persistencia.dominios_sob_risco, 10, dias, tenant_hash),
            asyncio.to_thread(persistencia.colaboradores_em_risco, 10, dias, tenant_hash),
            asyncio.to_thread(persistencia.listar_eventos, 50, tenant_hash, None, None),
        )
    except Exception as erro:
        raise HTTPException(status_code=503, detail=f"Erro ao consultar métricas: {erro}")

    total = resumo["total"]
    return {
        "perfil": "B2B",
        "produto": "PhishGuard Enterprise",
        "periodo_dias": dias,
        "organizacao_pseudonimizada": tenant_hash,
        "resumo": {
            **resumo,
            "taxa_ameaca_percentual": (
                round((resumo["ameacas"] / total) * 100, 1) if total else 0.0
            ),
        },
        "serie_diaria": serie,
        "por_canal": canais,
        "dominios_sob_risco": dominios,
        "colaboradores_em_risco": colaboradores,
        "eventos": eventos,
        "conformidade": {
            "retencao_conteudo": "nenhuma",
            "anonimizacao_antes_da_ia": True,
            "pii_mascarados_no_periodo": resumo["pii_mascarados"],
            "identificacao_de_colaboradores": "pseudonimizada (HMAC-SHA256)",
        },
        "privacidade": privacidade.selo_transparencia(),
    }


@app.get("/api/logs-soc", dependencies=[Depends(exigir_token_admin)])
async def logs_soc(limite: int = Query(default=50, ge=1, le=500)):
    """
    Trilha de auditoria anonimizada (compatível com o painel SOC existente).

    Diferença crítica em relação à versão anterior: as colunas de conteúdo não
    são mais lidas nem retornadas — o auditor vê o evento, nunca a mensagem.
    """
    if not banco_ativo:
        return UTF8JSONResponse(content=[])
    try:
        eventos = await asyncio.to_thread(persistencia.listar_eventos, limite, None, None, None)
    except Exception as erro:
        raise HTTPException(status_code=503, detail=f"Erro ao consultar banco de dados: {erro}")
    return UTF8JSONResponse(content=eventos)


# ---------------------------------------------------------------------------
# Operação
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Prontidão para load balancer e diagnóstico rápido da extensão."""
    return {
        "status": "ok" if modelos_prontos() else "degradado",
        "versao": VERSAO_API,
        "camada_1_carregada": modelos_prontos(),
        "camada_2_disponivel": cliente_gemini is not None,
        "telemetria_ativa": banco_ativo,
        "circuitos": [breaker_email.diagnostico(), breaker_hub.diagnostico()],
        "governanca_autenticada": ADMIN_TOKEN is not None,
        "sal_pseudonimizacao_configurado": privacidade.SAL_CONFIGURADO,
        "privacidade": privacidade.selo_transparencia(),
    }


@app.get("/")
async def raiz():
    return {
        "produto": "PhishGuard",
        "versao": VERSAO_API,
        "descricao": "Detecção de phishing multicanal com arquitetura LGPD by Design.",
        "linhas": {
            "B2C": "PhishGuard Personal — /api/metricas/pessoal",
            "B2B": "PhishGuard Enterprise — /api/metricas/corporativo",
        },
        "privacidade": "/api/privacidade",
        "documentacao": "/docs",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
