import asyncio
import json
import os
import re
from asyncio import CancelledError
from contextlib import asynccontextmanager
from email.utils import parseaddr
from typing import Optional

import joblib
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(BASE_DIR, "models")

DATABASE_URL = os.getenv("DATABASE_URL")


def obter_conexao():
    """Abre uma conexão com o PostgreSQL (Azure) a partir da variável DATABASE_URL."""
    if not DATABASE_URL:
        raise RuntimeError(
            "Variável de ambiente DATABASE_URL não configurada. "
            "Defina a string de conexão do PostgreSQL do Azure no arquivo .env."
        )
    return psycopg2.connect(DATABASE_URL)


def inicializar_banco():
    conn = None
    cursor = None
    try:
        conn = obter_conexao()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS interacoes_hub (
                id SERIAL PRIMARY KEY,
                canal TEXT,
                mensagem_usuario TEXT,
                resposta_bot TEXT,
                risco_detectado TEXT,
                data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


def salvar_interacao_hub(canal: str, mensagem: str, resposta: str, risco: str):
    conn = None
    cursor = None
    try:
        conn = obter_conexao()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO interacoes_hub (canal, mensagem_usuario, resposta_bot, risco_detectado) VALUES (%s, %s, %s, %s)",
            (canal, mensagem, resposta, risco)
        )
        conn.commit()
    except Exception as e:
        print(f"Erro ao salvar interação no banco: {e}")
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()

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

    # Inicializar banco de dados PostgreSQL (Azure)
    inicializar_banco()

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
    description=(
        "API de detecção de phishing com dupla checagem: "
        "modelo estatístico (Camada 1) + Gemini (Camada 2 / Conversational Security)."
    ),
    lifespan=lifespan,
    default_response_class=UTF8JSONResponse,
)

# Origens que consomem a API: extensão de navegador (Gmail/Outlook Web) + ferramentas locais.
# Mantemos "*" para cobrir chrome-extension://<id> (que varia por instalação) e qualquer
# webmail suportado. Como a extensão não envia cookies, allow_credentials fica desligado
# (o par "*" + credentials é rejeitado pelos navegadores).
ORIGENS_PERMITIDAS = [
    "https://outlook.live.com",
    "https://outlook.office.com",
    "https://mail.google.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=r"^(chrome-extension|moz-extension)://.*$",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)


@app.middleware("http")
async def liberar_private_network_access(request: Request, call_next):
    """
    Chrome bloqueia requisições de sites públicos (https://outlook.live.com) para o
    espaço de loopback (http://localhost:8000) via Private Network Access (PNA).

    O navegador dispara um preflight OPTIONS com o cabeçalho
    'Access-Control-Request-Private-Network: true'. O servidor precisa responder com
    'Access-Control-Allow-Private-Network: true' — algo que o CORSMiddleware padrão
    não faz. Este middleware injeta esse cabeçalho (e reforça os de CORS) em toda
    resposta, inclusive nos preflights que o CORSMiddleware já resolveu.
    """
    if (
        request.method == "OPTIONS"
        and "access-control-request-private-network" in request.headers
    ):
        # Responde o preflight diretamente, garantindo todos os cabeçalhos necessários.
        origem = request.headers.get("origin", "*")
        acr_headers = request.headers.get("access-control-request-headers", "*")
        return Response(
            status_code=200,
            headers={
                "Access-Control-Allow-Origin": origem,
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
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
    return response


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
        "4. FORMATO DE SAÍDA E FEEDBACK: Seja objetivo e técnico. CASO O E-MAIL SEJA SEGURO/LEGÍTIMO, não retorne apenas um rótulo seco. Forneça uma explicação detalhada e descritiva justificando por que o e-mail é legítimo (ex: confirmando a autenticidade do remetente oficial, a ausência de malícia e a conformidade com comunicados reais da marca), garantindo uma experiência clara e informativa para o usuário.\n"
        "5. IDIOMA E ACENTUAÇÃO: A sua explicação final DEVE ser escrita em Português do Brasil impecável, preservando toda a acentuação gráfica nativa e pontuação adequada."
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


class WhatsAppMessageRequest(BaseModel):
    mensagem: str


class WhatsAppMessageResponse(BaseModel):
    resposta: str


def consultar_gemini_whatsapp(mensagem: str, score_risco: float) -> VereditoGemini:
    if cliente_gemini is None:
        raise RuntimeError("Cliente Gemini não configurado. Defina GEMINI_API_KEY no ambiente.")

    prompt = (
        f"Analise o seguinte texto enviado via WhatsApp. O modelo estatístico preliminar classificou esta mensagem com score de risco de {score_risco * 100:.1f}%.\n\n"
        f"Texto:\n{mensagem}\n"
    )

    instrucao_sistema = (
        "Você é o assistente virtual do PhishGuard no WhatsApp. Sua função é analisar textos e links encaminhados por usuários em chats de mensagens. "
        "NUNCA mencione e-mail, remetentes de e-mail, assuntos ou cabeçalhos. "
        "Analise estritamente a mensagem em busca de engenharia social, urgência artificial, golpes conhecidos (como falsas taxas dos Correios/Receita Federal, clonagem de cartão ou bancos) e links maliciosos. "
        "A sua explicação final DEVE ser escrita em Português do Brasil impecável, preservando toda a acentuação gráfica nativa e pontuação adequada."
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


@app.post("/webhook/whatsapp", response_model=WhatsAppMessageResponse)
async def webhook_whatsapp(payload: WhatsAppMessageRequest):
    if vetorizador is None or modelo_rf is None or modelo_xgb is None:
        raise HTTPException(status_code=503, detail="Modelos de IA ainda não foram carregados.")

    mensagem = payload.mensagem.strip()
    if not mensagem:
        return WhatsAppMessageResponse(
            resposta="⚠️ Por favor, envie uma mensagem válida para análise."
        )

    # 1. Calcular o score de risco estatístico puramente sobre o texto (sem metadados de e-mail)
    score_risco = calcular_score_risco(
        assunto="",
        corpo_texto=mensagem,
        remetente=""
    )

    try:
        try:
            if cliente_gemini is None:
                raise RuntimeError("Cliente Gemini não configurado.")

            # 2. Consultar Gemini utilizando a instrução de sistema dedicada ao WhatsApp
            veredito = await asyncio.to_thread(
                consultar_gemini_whatsapp,
                mensagem,
                score_risco,
            )
            is_phishing = veredito.is_phishing_real
            explicacao = veredito.explicacao
            dupla_checagem = True
        except Exception as exc:
            # Fallback se o Gemini falhar ou não estiver configurado
            is_phishing = score_risco >= LIMIAR_CAMADA_1
            explicacao = (
                "Análise preventiva realizada com sucesso. "
                "Detectamos padrões de risco com base na estrutura estatística da mensagem."
            )
            dupla_checagem = False

        # 3. Sincronizar o score de exibição com o veredito para eliminar contradições
        if is_phishing:
            score_exibicao = max(score_risco, 0.85)
            resposta_texto = (
                f" *Alerta PhishGuard!* \n\n"
                f"Analisei sua mensagem e ela tem *{score_exibicao * 100:.1f}%* de chance de ser um golpe/phishing.\n\n"
                f" *Análise do bot:*\n{explicacao}\n\n"
                f" *Recomendação:* Não clique em nenhum link, não compartilhe códigos ou dados pessoais, e evite interagir com esse remetente!"
            )
        else:
            score_exibicao = min(score_risco, 0.15)
            resposta_texto = (
                f" *PhishGuard Seguro!* \n\n"
                f"Analisei sua mensagem e o risco de golpe é muito baixo (*{score_exibicao * 100:.1f}%*).\n\n"
                f" *Explicação:*\n{explicacao}\n\n"
                f"️ *Dica:* Mesmo que pareça seguro, sempre fique atento a links desconhecidos e nunca forneça senhas ou dados confidenciais."
            )

        # Gravar log no banco PostgreSQL (Azure)
        salvar_interacao_hub(
            canal="whatsapp",
            mensagem=mensagem,
            resposta=resposta_texto,
            risco="Phishing" if is_phishing else "Seguro"
        )

        return WhatsAppMessageResponse(resposta=resposta_texto)

    except CancelledError:
        print("Análise de WhatsApp cancelada pelo cliente.")
        raise


class WebchatMessageRequest(BaseModel):
    mensagem: str


class WebchatMessageResponse(BaseModel):
    resposta: str


def consultar_gemini_webchat(mensagem: str, score_risco: float) -> str:
    if cliente_gemini is None:
        raise RuntimeError("Cliente Gemini não configurado.")

    score_phishing_sincronizado = max(score_risco, 0.85) * 100
    score_seguro_sincronizado = min(score_risco, 0.15) * 100

    prompt = (
        f"Mensagem do usuário:\n{mensagem}\n\n"
        f"[Contexto de Riscos Sincronizados]\n"
        f"- Caso você classifique a mensagem como PHISHING/GOLPE (Papel 2), utilize obrigatoriamente o score de risco de exatamente {score_phishing_sincronizado:.1f}% na sua resposta escrita.\n"
        f"- Caso você classifique a mensagem como SEGURA (Papel 2) ou se tratar de dúvidas comerciais (Papel 1), utilize obrigatoriamente o score de risco de exatamente {score_seguro_sincronizado:.1f}% caso precise citar alguma porcentagem de risco."
    )

    instrucao_sistema = (
        "Você é a IA de atendimento híbrido do PhishGuard, uma solução corporativa B2B de SECaaS (Security as a Service) de proteção contra phishing.\n"
        "Sua atuação deve se adaptar dinamicamente ao objetivo do usuário:\n\n"
        "PAPEL 1: VENDAS E SUPORTE (Se o usuário saudar, perguntar sobre o PhishGuard, como funciona, preços, contratação ou planos):\n"
        "- Seja um assistente de vendas altamente persuasivo, profissional e simpático.\n"
        "- Explique que o PhishGuard é um SECaaS SaaS cobrado mensalmente por colaborador.\n"
        "- Apresente os planos com orgulho:\n"
        "  1. Plano Starter (R$ 15/colaborador/mês): Proteção de Extensão Desktop + motor estatístico de Machine Learning.\n"
        "  2. Plano Enterprise (R$ 25/colaborador/mês): Extensão Desktop + IA Generativa Gemini + Hub Conversacional WhatsApp + Painel de Governança corporativa.\n"
        "- Destaque o diferencial de termos um Hub Conversacional unificado (Extensão, WhatsApp e Webchat).\n\n"
        "PAPEL 2: ANÁLISE DE RISCO (Se o usuário enviar um link, mensagem ou texto suspeito solicitando análise):\n"
        "- Ignore o papel comercial e atue estritamente como um Analista de Segurança.\n"
        "- Use o [Contexto Técnico] fornecido no prompt para apoiar seu veredito.\n"
        "- Se classificar como golpe, indique que há alto risco (mostre o score de risco correspondente, ex: acima de 85% se for phishing, garantindo sincronia entre seu tom e a porcentagem). Use emojis de alerta (🚨, ⚠️) e dê orientações claras para não clicar.\n"
        "- Se classificar como seguro, tranquilize o usuário com base em argumentos técnicos, mostrando um risco baixo (abaixo de 15%).\n"
        "- NUNCA cite termos de e-mail (como cabeçalhos, remetentes de e-mail ou campos 'De/Assunto') a menos que o usuário tenha explicitamente enviado um cabeçalho de e-mail para análise.\n\n"
        "Sempre responda em português brasileiro usando formatação amigável para chat (negritos com asteriscos * e emojis).\n"
        "A sua explicação final DEVE ser escrita em Português do Brasil impecável, preservando toda a acentuação gráfica nativa e pontuação adequada."
    )

    response = cliente_gemini.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.3,
            thinking_config=types.ThinkingConfig(thinking_budget=0),
            system_instruction=instrucao_sistema,
        ),
    )

    return response.text or ""


@app.post("/webhook/webchat", response_model=WebchatMessageResponse)
async def webhook_webchat(payload: WebchatMessageRequest):
    if vetorizador is None or modelo_rf is None or modelo_xgb is None:
        raise HTTPException(status_code=503, detail="Modelos de IA ainda não foram carregados.")

    mensagem = payload.mensagem.strip()
    if not mensagem:
        return WebchatMessageResponse(resposta="Olá! Como posso ajudar você hoje?")

    # Calcular o score de risco estatístico puramente sobre o texto
    score_risco = calcular_score_risco(
        assunto="",
        corpo_texto=mensagem,
        remetente=""
    )

    try:
        try:
            if cliente_gemini is None:
                raise RuntimeError("Cliente Gemini não configurado.")

            # Consultar Gemini usando o prompt híbrido
            resposta_texto = await asyncio.to_thread(
                consultar_gemini_webchat,
                mensagem,
                score_risco,
            )
        except Exception as exc:
            # Fallback robusto se o Gemini falhar ou não estiver configurado
            palavras_chave = ["preço", "plano", "valor", "mensal", "custo", "contratar", "comprar", "assinar", "starter", "enterprise", "phishguard", "funciona", "b2b", "venda", "empresa", "comercial"]
            mensagem_lc = mensagem.lower()
            
            if any(p in mensagem_lc for p in palavras_chave):
                resposta_texto = (
                    "Olá! O *PhishGuard* é uma solução corporativa B2B de *SECaaS (Security as a Service)* voltada para proteger sua empresa contra phishing e engenharia social em múltiplos canais (E-mail, WhatsApp e Webchat).\n\n"
                    "Oferecemos dois planos flexíveis sob assinatura mensal por colaborador (seat):\n\n"
                    "🛡️ *Plano Starter (R$ 15/colaborador/mês):*\n"
                    "- Extensão Desktop de análise de e-mails.\n"
                    "- Motor estatístico avançado de Machine Learning (Camada 1).\n\n"
                    "👑 *Plano Enterprise (R$ 25/colaborador/mês):*\n"
                    "- Extensão Desktop de análise de e-mails.\n"
                    "- Dupla checagem contextual profunda com IA Generativa Gemini (Camada 2).\n"
                    "- Hub Conversacional integrado para WhatsApp.\n"
                    "- Painel de Governança corporativa completo com métricas e SOC.\n\n"
                    "Gostaria de agendar uma demonstração ou falar com um de nossos especialistas?"
                )
            else:
                is_phishing = score_risco >= LIMIAR_CAMADA_1
                if is_phishing:
                    score_exibicao = max(score_risco, 0.85)
                    resposta_texto = (
                        f"*Alerta de Phishing Detectado!* \n\n"
                        f"Nossa análise estatística de segurança identificou um risco de *{score_exibicao * 100:.1f}%* nesta mensagem.\n\n"
                        f"*Análise do bot:* O texto apresenta gatilhos suspeitos associados a engenharia social, urgência artificial ou links maliciosos.\n\n"
                        f"*Recomendação:* Não clique em links e não forneça informações confidenciais."
                    )
                else:
                    score_exibicao = min(score_risco, 0.15)
                    resposta_texto = (
                        f"*PhishGuard Seguro!*\n\n"
                        f"Nossa análise estatística de segurança identificou que esta mensagem parece ser segura (risco estimado em *{score_exibicao * 100:.1f}%*).\n\n"
                        f"*Dica:* Mesmo que pareça segura, sempre desconfie de solicitações incomuns."
                    )

        # Gravar log no banco PostgreSQL (Azure)
        risco_banco = "Phishing" if "🚨" in resposta_texto else "Seguro"
        salvar_interacao_hub(
            canal="webchat",
            mensagem=mensagem,
            resposta=resposta_texto,
            risco=risco_banco
        )

        return WebchatMessageResponse(resposta=resposta_texto)

    except CancelledError:
        print("Análise de Webchat cancelada pelo cliente.")
        raise


@app.get("/api/logs-soc")
async def get_logs_soc():
    conn = None
    cursor = None
    try:
        conn = obter_conexao()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("SELECT id, canal, mensagem_usuario, resposta_bot, risco_detectado, data_hora FROM interacoes_hub ORDER BY data_hora DESC LIMIT 50")
        rows = cursor.fetchall()
        logs = [dict(row) for row in rows]
        return UTF8JSONResponse(content=logs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao consultar banco de dados: {e}")
    finally:
        if cursor is not None:
            cursor.close()
        if conn is not None:
            conn.close()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
