// PhishGuard — Popup da extensão (vertente B2C + selo de transparência LGPD).
//
// A aba "Proteção" é o PhishGuard Personal em miniatura: métricas do próprio
// usuário, calculadas a partir de contadores locais mantidos pelo service
// worker. Isso é deliberado — o painel pessoal funciona mesmo com a API fora do
// ar e sem depender de nenhum dado do servidor.

"use strict";

const $ = (id) => document.getElementById(id);

function enviar(type, payload) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage({ type, payload }, (resp) => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else if (!resp || !resp.ok) reject(new Error((resp && resp.error) || "Falha na operação."));
      else resolve(resp.data);
    });
  });
}

function mostrarAviso(elemento, mensagem, tipo) {
  elemento.textContent = mensagem;
  elemento.className = `aviso ${tipo}`;
  clearTimeout(elemento._timer);
  elemento._timer = setTimeout(() => {
    elemento.className = "aviso";
  }, 5000);
}

// ---------------------------------------------------------------------------
// Navegação por abas
// ---------------------------------------------------------------------------

document.querySelectorAll("nav button").forEach((botao) => {
  botao.addEventListener("click", () => {
    document.querySelectorAll("nav button").forEach((b) => b.classList.remove("ativo"));
    document.querySelectorAll(".aba").forEach((s) => s.classList.remove("ativa"));
    botao.classList.add("ativo");
    $(`aba-${botao.dataset.aba}`).classList.add("ativa");
  });
});

// ---------------------------------------------------------------------------
// Aba Proteção
// ---------------------------------------------------------------------------

function formatarDataHora(iso) {
  if (!iso) return "Nenhuma análise registrada ainda.";
  try {
    return `Última análise: ${new Date(iso).toLocaleString("pt-BR")}`;
  } catch (erro) {
    return "Nenhuma análise registrada ainda.";
  }
}

function renderizarEstatisticas(estatisticas) {
  const total = estatisticas.totalAnalisados || 0;
  const ameacas = estatisticas.ameacasBloqueadas || 0;
  const seguros = estatisticas.emailsSeguros || 0;
  const base = seguros + ameacas;

  $("mTotal").textContent = total;
  $("mAmeacas").textContent = ameacas;
  $("mSeguros").textContent = seguros;
  $("mMascarados").textContent = estatisticas.dadosSensiveisMascarados || 0;

  const pctSeguro = base ? Math.round((seguros / base) * 100) : 100;
  $("fatiaSegura").style.width = `${pctSeguro}%`;
  $("fatiaAmeaca").style.width = `${100 - pctSeguro}%`;
  $("pctSeguro").textContent = `${pctSeguro}%`;
  $("pctAmeaca").textContent = `${100 - pctSeguro}%`;
  $("ultimaAnalise").textContent = formatarDataHora(estatisticas.ultimaAnalise);
}

async function carregarEstatisticas() {
  try {
    renderizarEstatisticas(await enviar("OBTER_ESTATISTICAS"));
  } catch (erro) {
    mostrarAviso($("avisoProtecao"), erro.message, "erro");
  }
}

$("btnAtualizar").addEventListener("click", carregarEstatisticas);

$("btnLimpar").addEventListener("click", async () => {
  try {
    renderizarEstatisticas(await enviar("LIMPAR_ESTATISTICAS"));
    mostrarAviso($("avisoProtecao"), "Histórico local zerado neste dispositivo.", "sucesso");
  } catch (erro) {
    mostrarAviso($("avisoProtecao"), erro.message, "erro");
  }
});

// ---------------------------------------------------------------------------
// Aba Privacidade
// ---------------------------------------------------------------------------

const GARANTIAS_PADRAO = [
  {
    titulo: "Retenção zero de conteúdo",
    descricao:
      "O corpo dos e-mails e as mensagens do hub nunca são gravados. A análise é stateless.",
  },
  {
    titulo: "Anonimização antes da IA",
    descricao:
      "CPF, cartões, chaves Pix, telefones, dados bancários e senhas são mascarados antes de qualquer envio ao modelo de linguagem.",
  },
  {
    titulo: "Apenas metadados agregados",
    descricao:
      "Guardamos canal, data/hora, veredito e score — insuficientes para reconstruir a mensagem.",
  },
  {
    titulo: "Seus dados não treinam modelos",
    descricao: "Nenhum conteúdo analisado é usado para treinar ou ajustar modelos de IA.",
  },
];

function renderizarGarantias(garantias) {
  const lista = $("listaGarantias");
  lista.textContent = "";
  garantias.forEach((garantia) => {
    const item = document.createElement("li");
    const check = document.createElement("span");
    check.className = "check";
    check.textContent = "✓";
    const corpo = document.createElement("div");
    const titulo = document.createElement("strong");
    titulo.textContent = garantia.titulo;
    const descricao = document.createElement("span");
    descricao.textContent = garantia.descricao;
    corpo.appendChild(titulo);
    corpo.appendChild(descricao);
    item.appendChild(check);
    item.appendChild(corpo);
    lista.appendChild(item);
  });
}

async function carregarPolitica() {
  renderizarGarantias(GARANTIAS_PADRAO);
  try {
    const manifesto = await enviar("OBTER_PRIVACIDADE");
    if (manifesto && Array.isArray(manifesto.garantias) && manifesto.garantias.length) {
      renderizarGarantias(manifesto.garantias);
    }
    if (manifesto && manifesto.resumo) $("resumoPrivacidade").textContent = manifesto.resumo;
    $("rodapePolitica").textContent =
      `Política versão ${manifesto.versao_politica || "2026.09"} · DPO: ` +
      `${manifesto.contato_encarregado || "dpo@phishguard.com.br"}`;
  } catch (erro) {
    // Offline: o texto padrão embutido continua sendo a política vigente.
    $("rodapePolitica").textContent =
      "Política versão 2026.09 (exibida localmente — API indisponível).";
  }
}

$("btnPolitica").addEventListener("click", carregarPolitica);

$("btnEliminar").addEventListener("click", async () => {
  try {
    const resultado = await enviar("ELIMINAR_MEUS_DADOS");
    mostrarAviso(
      $("avisoPrivacidade"),
      `${resultado.removidos || 0} registro(s) de metadados eliminado(s). ` +
        "O conteúdo das suas mensagens nunca foi armazenado.",
      "sucesso"
    );
  } catch (erro) {
    mostrarAviso($("avisoPrivacidade"), erro.message, "erro");
  }
});

// ---------------------------------------------------------------------------
// Aba Conta
// ---------------------------------------------------------------------------

function alternarBlocoOrganizacao() {
  $("blocoOrganizacao").style.display = $("perfil").value === "B2B" ? "block" : "none";
  $("linhaProduto").textContent =
    $("perfil").value === "B2B" ? "PhishGuard Enterprise" : "PhishGuard Personal";
}

$("perfil").addEventListener("change", alternarBlocoOrganizacao);

async function carregarConfig() {
  try {
    const config = await enviar("OBTER_CONFIG");
    $("perfil").value = config.perfil === "B2B" ? "B2B" : "B2C";
    $("organizacao").value = config.organizacao || "";
    $("apiBase").value = config.apiBase || "http://localhost:8000";
    $("idConta").value = config.idConta || "";
    $("protecaoAtiva").checked = config.protecaoAtiva !== false;
    alternarBlocoOrganizacao();
  } catch (erro) {
    mostrarAviso($("avisoConta"), erro.message, "erro");
  }
}

$("btnSalvar").addEventListener("click", async () => {
  const apiBase = $("apiBase").value.trim().replace(/\/+$/, "");
  if (!/^https?:\/\/.+/i.test(apiBase)) {
    mostrarAviso($("avisoConta"), "Informe um endpoint válido começando com http:// ou https://.", "erro");
    return;
  }
  try {
    await enviar("SALVAR_CONFIG", {
      perfil: $("perfil").value,
      organizacao: $("organizacao").value.trim(),
      apiBase,
      protecaoAtiva: $("protecaoAtiva").checked,
    });
    mostrarAviso($("avisoConta"), "Configurações salvas.", "sucesso");
    verificarSaude();
  } catch (erro) {
    mostrarAviso($("avisoConta"), erro.message, "erro");
  }
});

// ---------------------------------------------------------------------------
// Estado do serviço
// ---------------------------------------------------------------------------

async function verificarSaude() {
  const pill = $("statusApi");
  try {
    const saude = await enviar("VERIFICAR_SAUDE");
    if (saude.online) {
      pill.textContent = saude.camada_2_disponivel ? "proteção total" : "camada 1 apenas";
      pill.className = "status-pill online";
      pill.title = `API v${saude.versao || "?"} · telemetria ${
        saude.telemetria_ativa ? "ativa" : "desativada"
      }`;
    } else {
      pill.textContent = "API offline";
      pill.className = "status-pill offline";
      pill.title = saude.erro || "";
    }
  } catch (erro) {
    pill.textContent = "API offline";
    pill.className = "status-pill offline";
    pill.title = erro.message;
  }
}

carregarEstatisticas();
carregarConfig();
carregarPolitica();
verificarSaude();
