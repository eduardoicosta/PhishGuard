import asyncio
import json
import os
import re
from asyncio import CancelledError
from contextlib import asynccontextmanager
from email.utils import parseaddr
from typing import Optional

import joblib
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

LIMIAR_CAMADA_1 = 0.35
GEMINI_MODEL = "gemini-3.5-flash"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

DOMINIOS_WHITELIST = {
    "fiap.com.br",
    "gmail.com",
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "aws.amazon.com",
    "github.com",
    "gitlab.com",
    "linkedin.com",
    "slack.com",
    "zoom.us",
    "atlassian.com",
    "gov.br",
    "sp.gov.br",
    "ccee.org.br",
    "itau.com.br",
    "nubank.com.br",
    "bb.com.br",
    "caixa.gov.br",
    "bradesco.com.br",
    "picpay.com",
    "mercadolivre.com.br",
    "ifood.com.br",
    "uber.com",
    "netflix.com",
}

vetorizador = None
modelo_rf = None
modelo_xgb = None
cliente_gemini: Optional[genai.Client] = None


class VereditoGemini(BaseModel):
    is_phishing_real: bool
    explicacao: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    global vetorizador, modelo_rf, modelo_xgb, cliente_gemini

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

    if GEMINI_API_KEY:
        cliente_gemini = genai.Client(api_key=GEMINI_API_KEY)
    else:
        print("Aviso: GEMINI_API_KEY não configurada. A dupla checagem ficará indisponível.")

    yield


app = FastAPI(
    title="PhishGuard API",
    description=(
        "API de detecção de phishing com dupla checagem: "
        "modelo estatístico (Camada 1) + Gemini (Camada 2 / Conversational Security)."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class EmailAnaliseRequest(BaseModel):
    assunto: str
    corpo_texto: str
    remetente: str


class EmailAnaliseResponse(BaseModel):
    score_risco: float
    is_phishing: bool
    nivel_alerta: str
    explicacao: str
    veredito_gemini: Optional[bool] = Field(
        default=None,
        description="Veredito do Gemini. Null quando a Camada 2 não foi acionada.",
    )
    dupla_checagem: bool = Field(
        default=False,
        description="Indica se o e-mail passou pela análise contextual do Gemini.",
    )


def extrair_dominio(remetente: str) -> str:
    _, endereco = parseaddr(remetente)
    if "@" in endereco:
        return endereco.split("@")[-1].lower().strip()
    if "@" in remetente:
        return remetente.split("@")[-1].replace(">", "").strip().lower()
    return "desconhecido"


def calcular_score_risco(assunto: str, corpo_texto: str, remetente: str) -> float:
    dominio = extrair_dominio(remetente)
    if dominio in DOMINIOS_WHITELIST:
        return 0.0

    texto_completo = f"{assunto} {corpo_texto}".strip()
    vetor_texto = vetorizador.transform([texto_completo])

    prob_rf = float(modelo_rf.predict_proba(vetor_texto)[0][1])
    prob_xgb = float(modelo_xgb.predict_proba(vetor_texto)[0][1])

    return (prob_rf + prob_xgb) / 2


def montar_prompt_gemini(remetente: str, assunto: str, corpo_texto: str, score_risco: float) -> str:
    return (
        f"Analise o seguinte e-mail. O modelo estatístico anterior classificou este e-mail com score de risco de {score_risco * 100:.1f}%.\n\n"
        f"Remetente: {remetente}\n"
        f"Assunto: {assunto}\n"
        f"Texto do e-mail:\n{corpo_texto}\n"
    )


def extrair_json_resposta(texto: str) -> dict:
    texto = texto.strip()

    try:
        return json.loads(texto)
    except json.JSONDecodeError:
        pass

    match = re.search(r"\{.*\}", texto, re.DOTALL)
    if match:
        return json.loads(match.group())

    raise ValueError("Resposta do Gemini não contém JSON válido.")


def consultar_gemini(remetente: str, assunto: str, corpo_texto: str, score_risco: float) -> VereditoGemini:
    if cliente_gemini is None:
        raise RuntimeError("Cliente Gemini não configurado. Defina GEMINI_API_KEY no ambiente.")

    prompt = montar_prompt_gemini(remetente, assunto, corpo_texto, score_risco)

    instrucao_sistema = (
        "Você é um analista sênior de cibersegurança e especialista em detecção de phishing. Sua tarefa é analisar o e-mail fornecido com extrema precisão técnica, baseando-se EXATAMENTE nos dados reais extraídos do cabeçalho e do corpo do e-mail.\n\n"
        "REGRAS CRÍTICAS DE ANÁLISE:\n"
        "1. NUNCA invente, suponha ou alucine informações sobre o remetente. O campo 'De:' (Remetente) analisado deve ser estritamente o que consta no e-mail original (ex: se o e-mail veio de payments-noreply@google.com, você deve reportar exatamente esse domínio oficial).\n"
        "2. VERIFICAÇÃO DE DOMÍNIO LEGÍTIMO: Antes de classificar como phishing, verifique se o domínio do remetente pertence oficialmente à marca citada (ex: domínios terminados em .google.com, vindi.com.br, etc., são corporativos e oficiais). Não os rotule como 'genéricos' ou 'falsos' se forem legítimos.\n"
        "3. CRITÉRIO DE PHISHING REAL: Só classifique como phishing se houver indícios claros de engenharia social maliciosa, links externos suspeitos para domínios desconhecidos/desalinhados com a marca, ou erros gritantes de spoofing comprovados. E-mails transacionais legítimos de cobrança ou boas-vindas NÃO são phishing.\n"
        "4. FORMATO DE SAÍDA E FEEDBACK: Seja objetivo e técnico. CASO O E-MAIL SEJA SEGURO/LEGÍTIMO, não retorne apenas um rótulo seco. Forneça uma explicação detalhada e descritiva justificando por que o e-mail é legítimo (ex: confirmando a autenticidade do remetente oficial, a ausência de malícia e a conformidade com comunicados reais da marca), garantindo uma experiência clara e informativa para o usuário."
    )

    response = cliente_gemini.models.generate_content(
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

    dados = extrair_json_resposta(response.text or "")
    veredito = VereditoGemini.model_validate(dados)
    return veredito


def resposta_segura_camada_1(score_risco: float, explicacao: str) -> EmailAnaliseResponse:
    return EmailAnaliseResponse(
        score_risco=round(score_risco, 4),
        is_phishing=False,
        nivel_alerta="SEGURO",
        explicacao=explicacao,
        veredito_gemini=None,
        dupla_checagem=False,
    )


@app.post("/analisar-email", response_model=EmailAnaliseResponse)
async def analisar_email(payload: EmailAnaliseRequest):
    if vetorizador is None or modelo_rf is None or modelo_xgb is None:
        raise HTTPException(status_code=503, detail="Modelos de IA ainda não foram carregados.")

    score_risco = calcular_score_risco(payload.assunto, payload.corpo_texto, payload.remetente)

    try:
        try:
            if cliente_gemini is None:
                raise RuntimeError("Cliente Gemini não configurado.")

            veredito = await asyncio.to_thread(
                consultar_gemini,
                payload.remetente,
                payload.assunto,
                payload.corpo_texto,
                score_risco,
            )
            is_phishing = veredito.is_phishing_real
            nivel_alerta = "CRITICO" if is_phishing else "SEGURO"
            explicacao = veredito.explicacao
            dupla_checagem = True
        except Exception as exc:
            # Fallback ultra-seguro se o Gemini falhar
            is_phishing = True
            nivel_alerta = "ATENÇÃO"
            explicacao = "Aviso de segurança: A análise detalhada por IA falhou temporariamente, mas o e-mail apresenta características que exigem cautela. Não clique em links."
            dupla_checagem = False

        return EmailAnaliseResponse(
            score_risco=round(score_risco, 4),
            is_phishing=is_phishing,
            nivel_alerta=nivel_alerta,
            explicacao=explicacao,
            veredito_gemini=is_phishing if dupla_checagem else None,
            dupla_checagem=dupla_checagem,
        )
    except CancelledError:
        # Trata cancelamento de requisição silenciosamente sem gerar traceback ou erro 500 no terminal
        print("Análise cancelada pelo cliente (navegação rápida).")
        raise


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
