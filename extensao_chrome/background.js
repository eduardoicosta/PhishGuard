// PhishGuard — Service Worker (MV3)
//
// Por que o fetch mora aqui e não no content script:
// O Chrome bloqueia requisições feitas do CONTEXTO DA PÁGINA (https://outlook.live.com,
// uma origem "pública") para o espaço de loopback (http://localhost:8000) via
// Private Network Access — mesmo com CORS liberado no servidor o navegador nega
// ("Permission was denied for this request to access the loopback address space").
// O service worker roda na origem chrome-extension:// e usa as host_permissions do
// manifest, portanto não passa por CORS nem pela restrição de rede privada.
//
// Responsabilidades adicionais desta versão:
//  * Configuração persistida (perfil B2C/B2B, identidade da conta, endpoint).
//  * Resiliência de rede: timeout, retry com backoff e mensagens de erro legíveis.
//  * Contadores locais de proteção — a base do painel pessoal (B2C) dentro do popup.
//    Os contadores são AGREGADOS: guardamos números, nunca o conteúdo dos e-mails.

"use strict";

const PADROES = {
  apiBase: "http://localhost:8000",
  perfil: "B2C",
  idConta: "",
  organizacao: "",
  protecaoAtiva: true,
};

const TIMEOUT_MS = 20000;
const TENTATIVAS = 2;
const BACKOFF_BASE_MS = 500;

// ---------------------------------------------------------------------------
// Configuração
// ---------------------------------------------------------------------------

async function obterConfig() {
  try {
    const salvo = await chrome.storage.local.get(Object.keys(PADROES));
    const config = { ...PADROES, ...salvo };
    // Identidade local anônima: gerada no dispositivo, nunca solicitada ao usuário.
    // O servidor só recebe o valor para derivar um HMAC — e não o armazena em claro.
    if (!config.idConta) {
      config.idConta = `anon-${crypto.randomUUID()}`;
      await chrome.storage.local.set({ idConta: config.idConta });
    }
    return config;
  } catch (erro) {
    console.warn("[PhishGuard] Falha ao ler configuração, usando padrões.", erro);
    return { ...PADROES, idConta: "anon-local" };
  }
}

async function salvarConfig(parcial) {
  const permitidas = Object.keys(PADROES);
  const limpa = {};
  for (const chave of permitidas) {
    if (parcial && Object.prototype.hasOwnProperty.call(parcial, chave)) {
      limpa[chave] = parcial[chave];
    }
  }
  await chrome.storage.local.set(limpa);
  return obterConfig();
}

// ---------------------------------------------------------------------------
// Estatísticas locais (visão B2C offline-first)
// ---------------------------------------------------------------------------

const ESTATISTICAS_PADRAO = {
  totalAnalisados: 0,
  ameacasBloqueadas: 0,
  emailsSeguros: 0,
  analisesIndisponiveis: 0,
  dadosSensiveisMascarados: 0,
  ultimaAnalise: null,
  // Série dos últimos dias no formato { "2026-09-01": { seguros, ameacas } }.
  porDia: {},
};

const DIAS_HISTORICO_LOCAL = 30;

async function obterEstatisticas() {
  const { estatisticas } = await chrome.storage.local.get("estatisticas");
  return { ...ESTATISTICAS_PADRAO, ...(estatisticas || {}) };
}

async function registrarEstatistica(resultado) {
  try {
    const atuais = await obterEstatisticas();
    const hoje = new Date().toISOString().slice(0, 10);
    const dia = atuais.porDia[hoje] || { seguros: 0, ameacas: 0 };

    atuais.totalAnalisados += 1;
    if (resultado && resultado.indisponivel) {
      atuais.analisesIndisponiveis += 1;
    } else if (resultado && resultado.is_phishing) {
      atuais.ameacasBloqueadas += 1;
      dia.ameacas += 1;
    } else {
      atuais.emailsSeguros += 1;
      dia.seguros += 1;
    }

    const mascarados =
      (resultado && resultado.privacidade && resultado.privacidade.dados_sensiveis_mascarados) || 0;
    atuais.dadosSensiveisMascarados += mascarados;
    atuais.ultimaAnalise = new Date().toISOString();
    atuais.porDia[hoje] = dia;

    // Janela deslizante: o histórico local não cresce indefinidamente.
    const limite = new Date(Date.now() - DIAS_HISTORICO_LOCAL * 86400000)
      .toISOString()
      .slice(0, 10);
    for (const chave of Object.keys(atuais.porDia)) {
      if (chave < limite) delete atuais.porDia[chave];
    }

    await chrome.storage.local.set({ estatisticas: atuais });
  } catch (erro) {
    console.warn("[PhishGuard] Não foi possível atualizar as estatísticas locais.", erro);
  }
}

async function limparEstatisticas() {
  await chrome.storage.local.set({ estatisticas: { ...ESTATISTICAS_PADRAO, porDia: {} } });
  return obterEstatisticas();
}

// ---------------------------------------------------------------------------
// Rede resiliente
// ---------------------------------------------------------------------------

function esperar(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function mensagemDeErroLegivel(erro) {
  const texto = String((erro && erro.message) || erro || "");
  if (texto.includes("AbortError") || texto.includes("abortada")) {
    return "A análise demorou mais que o esperado. Tente abrir o e-mail novamente.";
  }
  if (texto.includes("Failed to fetch") || texto.includes("NetworkError")) {
    return "Não foi possível falar com o servidor do PhishGuard. Verifique se a API está no ar.";
  }
  return texto || "Falha desconhecida na análise.";
}

async function requisitar(url, opcoes = {}, tentativas = TENTATIVAS) {
  let ultimoErro = null;

  for (let tentativa = 1; tentativa <= tentativas; tentativa += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opcoes.timeoutMs || TIMEOUT_MS);
    try {
      const resposta = await fetch(url, { ...opcoes, signal: controller.signal });
      if (!resposta.ok) {
        // 4xx é erro do cliente: repetir não vai mudar o resultado.
        if (resposta.status >= 400 && resposta.status < 500) {
          throw new Error(`A API recusou a requisição (HTTP ${resposta.status}).`);
        }
        throw new Error(`A API respondeu HTTP ${resposta.status}.`);
      }
      return await resposta.json();
    } catch (erro) {
      ultimoErro = erro;
      const semRetentativa = String(erro && erro.message).includes("recusou a requisição");
      if (semRetentativa || tentativa === tentativas) break;
      await esperar(BACKOFF_BASE_MS * Math.pow(2, tentativa - 1));
    } finally {
      clearTimeout(timer);
    }
  }

  throw new Error(mensagemDeErroLegivel(ultimoErro));
}

// ---------------------------------------------------------------------------
// Operações
// ---------------------------------------------------------------------------

async function analisarEmail(payload) {
  const config = await obterConfig();
  if (!config.protecaoAtiva) {
    return { pausado: true };
  }

  const corpo = {
    assunto: payload.assunto || "",
    corpo_texto: payload.corpo_texto || "",
    remetente: payload.remetente || "",
    perfil: config.perfil === "B2B" ? "B2B" : "B2C",
    id_conta: config.idConta,
    organizacao: config.perfil === "B2B" ? config.organizacao || null : null,
  };

  const resultado = await requisitar(`${config.apiBase}/analisar-email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Accept: "application/json; charset=utf-8",
    },
    body: JSON.stringify(corpo),
  });

  await registrarEstatistica(resultado);
  return resultado;
}

async function verificarSaude() {
  const config = await obterConfig();
  try {
    const saude = await requisitar(
      `${config.apiBase}/health`,
      { method: "GET", timeoutMs: 5000 },
      1
    );
    return { online: true, ...saude };
  } catch (erro) {
    return { online: false, erro: mensagemDeErroLegivel(erro) };
  }
}

async function obterPrivacidade() {
  const config = await obterConfig();
  return requisitar(`${config.apiBase}/api/privacidade`, { method: "GET", timeoutMs: 8000 }, 1);
}

async function eliminarMeusDados() {
  const config = await obterConfig();
  const url = `${config.apiBase}/api/privacidade/meus-dados?id_conta=${encodeURIComponent(
    config.idConta
  )}`;
  return requisitar(url, { method: "DELETE", timeoutMs: 10000 }, 1);
}

// ---------------------------------------------------------------------------
// Barramento de mensagens
// ---------------------------------------------------------------------------

const ROTAS = {
  ANALISAR_EMAIL: (mensagem) => analisarEmail(mensagem.payload || {}),
  OBTER_CONFIG: () => obterConfig(),
  SALVAR_CONFIG: (mensagem) => salvarConfig(mensagem.payload || {}),
  OBTER_ESTATISTICAS: () => obterEstatisticas(),
  LIMPAR_ESTATISTICAS: () => limparEstatisticas(),
  VERIFICAR_SAUDE: () => verificarSaude(),
  OBTER_PRIVACIDADE: () => obterPrivacidade(),
  ELIMINAR_MEUS_DADOS: () => eliminarMeusDados(),
};

chrome.runtime.onMessage.addListener((mensagem, _sender, sendResponse) => {
  const rota = mensagem && ROTAS[mensagem.type];
  if (!rota) return false;

  Promise.resolve()
    .then(() => rota(mensagem))
    .then((data) => sendResponse({ ok: true, data }))
    .catch((erro) => sendResponse({ ok: false, error: mensagemDeErroLegivel(erro) }));

  // Mantém o canal aberto para a resposta assíncrona.
  return true;
});

chrome.runtime.onInstalled.addListener(() => {
  // Garante que a identidade local exista já na instalação.
  obterConfig().catch(() => {});
});
