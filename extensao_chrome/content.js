(function () {
  "use strict";

  const BANNER_ID = "phishguard-banner";
  const MODAL_ID = "phishguard-modal-lgpd";
  const LOG_PREFIX = "[PhishGuard]";

  // Identidade visual corporativa — fonte única de verdade das cores.
  const TEMA = {
    fundo: "#1e293b",
    texto: "#f8fafc",
    textoSecundario: "#cbd5e1",
    textoTerciario: "#94a3b8",
    seguro: "#10b981",
    critico: "#dc2626",
    atencao: "#f59e0b",
    neutro: "#64748b",
    fonte: "'Segoe UI', 'Google Sans', Roboto, Arial, sans-serif",
  };

  let ultimoEmailAnalisado = null;
  let bannerNodeAtual = null; // Nó mantido em RAM para evitar recálculo de tela.
  let debounceTimer = null;
  let analiseEmAndamento = false;
  let provedorAtual = null;
  let guardiaoOutlookTimer = null;
  let manifestoLGPD = null; // Cache do manifesto para o modal de transparência.

  function logAviso(mensagem, erro) {
    if (erro) console.warn(LOG_PREFIX, mensagem, erro);
    else console.warn(LOG_PREFIX, mensagem);
  }

  /**
   * Toda comunicação com o service worker passa por aqui.
   * Trata o caso clássico de "Extension context invalidated" (a extensão foi
   * recarregada enquanto a aba do webmail continuava aberta): sem este guarda, o
   * content script antigo lança exceções não capturadas a cada mutação do DOM.
   */
  function enviarAoBackground(type, payload) {
    return new Promise((resolve, reject) => {
      if (!chrome.runtime || !chrome.runtime.id) {
        reject(new Error("Extensão recarregada. Atualize a página do webmail."));
        return;
      }
      try {
        chrome.runtime.sendMessage({ type, payload }, (resp) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else if (!resp || !resp.ok) {
            reject(new Error((resp && resp.error) || "Sem resposta do serviço."));
          } else {
            resolve(resp.data);
          }
        });
      } catch (erro) {
        reject(erro);
      }
    });
  }

  function consultarElemento(seletor) {
    try {
      return document.querySelector(seletor);
    } catch (erro) {
      return null;
    }
  }

  function consultarTexto(candidatos, extrator) {
    for (const candidato of candidatos) {
      const elemento = consultarElemento(candidato);
      if (!elemento) continue;
      try {
        const valor = extrator(elemento);
        if (valor && String(valor).trim()) return String(valor).trim();
      } catch (erro) {
        /* seletor incompatível com este layout — segue para o próximo */
      }
    }
    return "";
  }

  function detectarProvedor() {
    const hostname = window.location.hostname;
    if (hostname === "mail.google.com") return "gmail";
    if (
      hostname === "outlook.office.com" ||
      hostname === "outlook.office365.com" ||
      hostname === "outlook.live.com"
    ) {
      return "outlook";
    }
    return null;
  }

  // --- MOTOR DE EXTRAÇÃO DE DADOS -----------------------------------------
  const PROVEDORES = {
    gmail: {
      extrairAssunto: () =>
        consultarTexto(["h2.hP", "[data-thread-perm-id] h2", ".ha h2"], (el) => el.textContent),
      extrairRemetente() {
        const container = document.querySelector(".adn, .gE");
        if (!container) return "desconhecido@desconhecido.com";
        const remetenteEl =
          container.querySelector("span[email]") ||
          container.querySelector("[email]") ||
          container.querySelector(".gD");
        if (!remetenteEl) return "desconhecido@desconhecido.com";
        const email =
          remetenteEl.getAttribute("email") || remetenteEl.getAttribute("data-sender-email");
        const nome = remetenteEl.textContent.trim();
        return email && nome ? `${nome} <${email}>` : email || nome || "desconhecido@desconhecido.com";
      },
      extrairCorpoTexto: () =>
        consultarTexto([".ii.gt", ".a3s.aiL", ".a3s"], (el) => el.innerText || el.textContent),
    },
    outlook: {
      extrairAssunto() {
        const assunto = consultarTexto(
          ['[aria-label="Subject"]', '[role="textbox"][aria-label*="Subject"]'],
          (el) => el.textContent || el.value
        );
        if (assunto) return assunto;
        const headings = document.querySelectorAll(
          '[role="main"] [role="heading"], [role="main"] h1, [role="main"] h2'
        );
        for (const heading of headings) {
          const texto = heading.textContent.trim();
          if (texto && !texto.startsWith("From:") && !texto.startsWith("To:")) return texto;
        }
        return "";
      },
      extrairRemetente() {
        const container = document.querySelector('[role="main"]') || document;
        const corpoEl = container.querySelector('[role="document"], [aria-label*="Message body"]');
        const contemEmail = (texto) => /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(texto);
        const limpa = (t) => (t ? t.trim().replace(/^(From|De|Remetente):\s*/i, "").trim() : null);
        const seletores = [
          'span[title*="@"]',
          'div[title*="@"]',
          'button[title*="@"]',
          'a[href^="mailto:"]',
          '[aria-label^="From"]',
          '[aria-label*="From:"]',
          '[aria-label^="De:"]',
          '[data-test-id="sender-address"]',
          "span[email]",
        ];
        for (const seletor of seletores) {
          for (const el of container.querySelectorAll(seletor)) {
            if (corpoEl && corpoEl.contains(el)) continue;
            const title = el.getAttribute("title");
            if (title && contemEmail(title)) return limpa(title);
            const aria = el.getAttribute("aria-label");
            if (aria && (contemEmail(aria) || aria.toLowerCase().startsWith("from"))) {
              return limpa(aria);
            }
            const text = el.textContent.trim();
            if (contemEmail(text) || text.startsWith("From:")) return limpa(text);
          }
        }
        return "desconhecido@desconhecido.com";
      },
      extrairCorpoTexto: () =>
        consultarTexto(
          ['[role="document"]', '[aria-label="Message body"]', '[aria-label*="Message body"]'],
          (el) => el.innerText
        ),
    },
  };

  function extrairDadosEmail() {
    if (!provedorAtual) provedorAtual = detectarProvedor();
    if (!provedorAtual) return null;
    const prov = PROVEDORES[provedorAtual];
    const assunto = prov.extrairAssunto();
    const corpoTexto = prov.extrairCorpoTexto();
    const remetente = prov.extrairRemetente();
    if (!assunto || !corpoTexto) return null;
    return { assunto, corpoTexto, remetente };
  }

  // --- MOTOR DE UI / BANNER -----------------------------------------------
  const SVG_ESCUDO =
    '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2.5l7 2.6v5.6c0 4.7-3 8.4-7 10.3-4-1.9-7-5.6-7-10.3V5.1l7-2.6z" fill="currentColor" fill-opacity="0.16" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/><path d="M8.6 12.2l2.3 2.3 4.5-4.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  const SVG_CADEADO =
    '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="4.5" y="10.5" width="15" height="10" rx="2.2" stroke="currentColor" stroke-width="1.9"/><path d="M8 10.5V7.6a4 4 0 0 1 8 0v2.9" stroke="currentColor" stroke-width="1.9" stroke-linecap="round"/></svg>';

  /**
   * Estado visual do banner. A borda lateral e o ícone compartilham a mesma cor,
   * de modo que o veredito seja legível perifericamente, sem leitura do texto.
   */
  const ESTADOS = {
    analisando: { cor: TEMA.neutro, titulo: "PHISHGUARD IA: ANALISANDO E-MAIL..." },
    seguro: { cor: TEMA.seguro, titulo: "PHISHGUARD IA: E-MAIL SEGURO" },
    critico: { cor: TEMA.critico, titulo: "PHISHGUARD IA: AMEAÇA DETECTADA" },
    atencao: { cor: TEMA.atencao, titulo: "PHISHGUARD IA: ATENÇÃO — ANÁLISE PARCIAL" },
    erro: { cor: TEMA.atencao, titulo: "PHISHGUARD IA: ANÁLISE INDISPONÍVEL" },
  };

  function estiloDoBanner(corStatus) {
    return [
      "box-sizing: border-box",
      "position: relative",
      "width: 100%",
      "margin: 16px 0",
      "z-index: 10",
      "padding: 16px 20px",
      "display: flex",
      "align-items: flex-start",
      "gap: 14px",
      `font-family: ${TEMA.fonte}`,
      `background: ${TEMA.fundo}`,
      `color: ${TEMA.texto}`,
      "border-radius: 12px",
      `border-left: 7px solid ${corStatus}`,
      "box-shadow: 0 8px 24px rgba(15, 23, 42, 0.25)",
      "text-align: left",
      "transition: opacity 0.2s ease-in",
    ].join(";");
  }

  function criarElementoBanner(estado, textoExplicacao, meta) {
    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.setAttribute("role", "alert");
    banner.setAttribute("lang", "pt-BR");
    banner.style.cssText = estiloDoBanner(estado.cor);

    const conteudo = document.createElement("div");
    conteudo.style.cssText = "display: flex; flex-direction: column; gap: 5px; flex: 1; min-width: 0;";

    const titulo = document.createElement("div");
    titulo.style.cssText =
      `display: flex; align-items: center; gap: 10px; font-size: 15px; font-weight: 700; color: ${TEMA.texto}; letter-spacing: 0.3px;`;

    const icone = document.createElement("div");
    icone.style.cssText = `display: flex; align-items: center; justify-content: center; flex-shrink: 0; line-height: 0; color: ${estado.cor};`;
    icone.innerHTML = SVG_ESCUDO;

    const textoTituloEl = document.createElement("span");
    textoTituloEl.textContent = estado.titulo;

    titulo.appendChild(icone);
    titulo.appendChild(textoTituloEl);
    conteudo.appendChild(titulo);

    if (textoExplicacao) {
      const descricao = document.createElement("div");
      descricao.style.cssText = `font-size: 13px; font-weight: 400; color: ${TEMA.textoSecundario}; line-height: 1.6; overflow-wrap: anywhere;`;
      descricao.textContent = textoExplicacao;
      conteudo.appendChild(descricao);
    }

    // Rodapé de transparência: discreto, presente em toda análise concluída.
    if (meta) {
      conteudo.appendChild(criarRodapeTransparencia(meta));
    }

    banner.appendChild(conteudo);
    return banner;
  }

  function criarRodapeTransparencia(meta) {
    const rodape = document.createElement("div");
    rodape.style.cssText =
      "display: flex; align-items: center; flex-wrap: wrap; gap: 10px; margin-top: 6px; padding-top: 9px; border-top: 1px solid rgba(148, 163, 184, 0.18);";

    const selo = document.createElement("button");
    selo.type = "button";
    selo.setAttribute(
      "aria-label",
      "Ver como o PhishGuard protege seus dados pessoais (LGPD)"
    );
    selo.style.cssText = [
      "display: inline-flex",
      "align-items: center",
      "gap: 6px",
      "padding: 4px 10px",
      "border-radius: 999px",
      "border: 1px solid rgba(16, 185, 129, 0.35)",
      "background: rgba(16, 185, 129, 0.12)",
      `color: ${TEMA.seguro}`,
      "font-size: 11px",
      "font-weight: 600",
      "letter-spacing: 0.2px",
      `font-family: ${TEMA.fonte}`,
      "cursor: pointer",
      "line-height: 1",
    ].join(";");

    const cadeado = document.createElement("span");
    cadeado.style.cssText = "display: flex; line-height: 0;";
    cadeado.innerHTML = SVG_CADEADO;
    const rotulo = document.createElement("span");
    rotulo.textContent = "LGPD · Retenção zero";
    selo.appendChild(cadeado);
    selo.appendChild(rotulo);
    selo.addEventListener("click", (evento) => {
      evento.preventDefault();
      evento.stopPropagation();
      abrirModalTransparencia(meta);
    });

    rodape.appendChild(selo);

    const detalhes = [];
    if (meta.mascarados > 0) {
      detalhes.push(
        `${meta.mascarados} dado(s) sensível(is) anonimizado(s) antes da IA`
      );
    }
    if (meta.latencia) detalhes.push(`${meta.latencia} ms`);
    if (meta.duplaChecagem === false) detalhes.push("análise local (Camada 1)");

    if (detalhes.length) {
      const nota = document.createElement("span");
      nota.style.cssText = `font-size: 11px; color: ${TEMA.textoTerciario}; line-height: 1.5;`;
      nota.textContent = detalhes.join(" · ");
      rodape.appendChild(nota);
    }

    return rodape;
  }

  // --- MODAL DE TRANSPARÊNCIA LGPD ----------------------------------------

  function fecharModalTransparencia() {
    const existente = document.getElementById(MODAL_ID);
    if (existente) existente.remove();
    document.removeEventListener("keydown", aoPressionarEsc, true);
  }

  function aoPressionarEsc(evento) {
    if (evento.key === "Escape") fecharModalTransparencia();
  }

  function criarLinha(titulo, descricao) {
    const item = document.createElement("div");
    item.style.cssText = "display: flex; gap: 10px; align-items: flex-start;";

    const marcador = document.createElement("span");
    marcador.textContent = "✓";
    marcador.style.cssText = `color: ${TEMA.seguro}; font-weight: 700; line-height: 1.6; flex-shrink: 0;`;

    const texto = document.createElement("div");
    const forte = document.createElement("div");
    forte.textContent = titulo;
    forte.style.cssText = `color: ${TEMA.texto}; font-weight: 600; font-size: 13px;`;
    const detalhe = document.createElement("div");
    detalhe.textContent = descricao;
    detalhe.style.cssText = `color: ${TEMA.textoSecundario}; font-size: 12.5px; line-height: 1.6;`;
    texto.appendChild(forte);
    texto.appendChild(detalhe);

    item.appendChild(marcador);
    item.appendChild(texto);
    return item;
  }

  const GARANTIAS_LOCAIS = [
    [
      "Processamento em memória volátil",
      "O texto do e-mail é analisado durante a requisição e descartado em seguida. Nada é gravado em disco ou banco de dados.",
    ],
    [
      "Anonimização antes da IA",
      "CPF, cartões, chaves Pix, telefones, dados bancários e senhas são mascarados antes de qualquer envio ao modelo de linguagem.",
    ],
    [
      "Apenas metadados agregados",
      "Guardamos somente canal, data/hora, veredito e score de risco — insuficientes para reconstruir a sua mensagem.",
    ],
    [
      "Identidade pseudonimizada",
      "Sua conta é identificada por um hash irreversível (HMAC-SHA256), nunca pelo seu e-mail em texto claro.",
    ],
    [
      "Seus dados não treinam modelos",
      "Nenhum conteúdo analisado é reutilizado para treinar ou ajustar modelos de IA.",
    ],
  ];

  function abrirModalTransparencia(meta) {
    fecharModalTransparencia();

    const overlay = document.createElement("div");
    overlay.id = MODAL_ID;
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", "Transparência de dados — PhishGuard");
    overlay.style.cssText = [
      "position: fixed",
      "inset: 0",
      "z-index: 2147483647",
      "background: rgba(2, 6, 23, 0.72)",
      "display: flex",
      "align-items: center",
      "justify-content: center",
      "padding: 24px",
      `font-family: ${TEMA.fonte}`,
    ].join(";");
    overlay.addEventListener("click", (evento) => {
      if (evento.target === overlay) fecharModalTransparencia();
    });

    const caixa = document.createElement("div");
    caixa.style.cssText = [
      "width: 100%",
      "max-width: 560px",
      "max-height: 82vh",
      "overflow-y: auto",
      `background: ${TEMA.fundo}`,
      `color: ${TEMA.texto}`,
      "border-radius: 14px",
      `border-left: 7px solid ${TEMA.seguro}`,
      "box-shadow: 0 24px 60px rgba(2, 6, 23, 0.55)",
      "padding: 26px 28px",
      "text-align: left",
    ].join(";");

    const cabecalho = document.createElement("div");
    cabecalho.style.cssText =
      "display: flex; align-items: center; gap: 12px; margin-bottom: 6px;";
    const iconeCab = document.createElement("span");
    iconeCab.style.cssText = `color: ${TEMA.seguro}; display: flex; line-height: 0;`;
    iconeCab.innerHTML = SVG_ESCUDO;
    const tituloCab = document.createElement("h2");
    tituloCab.textContent = "Como o PhishGuard trata os seus dados";
    tituloCab.style.cssText = `margin: 0; font-size: 17px; font-weight: 700; color: ${TEMA.texto}; flex: 1;`;
    const fechar = document.createElement("button");
    fechar.type = "button";
    fechar.textContent = "✕";
    fechar.setAttribute("aria-label", "Fechar");
    fechar.style.cssText = `background: none; border: none; color: ${TEMA.textoTerciario}; font-size: 17px; cursor: pointer; padding: 4px 6px; line-height: 1;`;
    fechar.addEventListener("click", fecharModalTransparencia);
    cabecalho.appendChild(iconeCab);
    cabecalho.appendChild(tituloCab);
    cabecalho.appendChild(fechar);

    const subtitulo = document.createElement("p");
    subtitulo.textContent =
      "Arquitetura de retenção zero, em conformidade com a Lei Geral de Proteção de Dados (Lei 13.709/2018).";
    subtitulo.style.cssText = `margin: 0 0 18px; font-size: 12.5px; color: ${TEMA.textoTerciario}; line-height: 1.6;`;

    const lista = document.createElement("div");
    lista.style.cssText = "display: flex; flex-direction: column; gap: 13px;";

    const garantias =
      manifestoLGPD && Array.isArray(manifestoLGPD.garantias) && manifestoLGPD.garantias.length
        ? manifestoLGPD.garantias.map((g) => [g.titulo, g.descricao])
        : GARANTIAS_LOCAIS;
    garantias.forEach(([titulo, descricao]) => lista.appendChild(criarLinha(titulo, descricao)));

    caixa.appendChild(cabecalho);
    caixa.appendChild(subtitulo);
    caixa.appendChild(lista);

    if (meta && meta.mascarados > 0) {
      const destaque = document.createElement("div");
      destaque.style.cssText = [
        "margin-top: 18px",
        "padding: 12px 14px",
        "border-radius: 10px",
        "background: rgba(16, 185, 129, 0.10)",
        "border: 1px solid rgba(16, 185, 129, 0.28)",
        `color: ${TEMA.textoSecundario}`,
        "font-size: 12.5px",
        "line-height: 1.6",
      ].join(";");
      const tipos = (meta.tipos || []).join(", ");
      destaque.textContent =
        `Nesta análise, ${meta.mascarados} dado(s) sensível(is) foram anonimizados antes de sair do servidor` +
        (tipos ? ` (${tipos}).` : ".");
      caixa.appendChild(destaque);
    }

    const rodapeModal = document.createElement("p");
    rodapeModal.style.cssText = `margin: 18px 0 0; font-size: 11.5px; color: ${TEMA.textoTerciario}; line-height: 1.6;`;
    const versao =
      (manifestoLGPD && manifestoLGPD.versao_politica) || (meta && meta.versaoPolitica) || "2026.09";
    const contato = (manifestoLGPD && manifestoLGPD.contato_encarregado) || "dpo@phishguard.com.br";
    rodapeModal.textContent = `Política versão ${versao} · Encarregado de dados (DPO): ${contato}`;
    caixa.appendChild(rodapeModal);

    overlay.appendChild(caixa);
    document.body.appendChild(overlay);
    document.addEventListener("keydown", aoPressionarEsc, true);
    fechar.focus();

    // Enriquecimento assíncrono: se a API responder, o modal passa a exibir o
    // manifesto oficial. Se falhar, o texto local já entregue permanece válido.
    if (!manifestoLGPD) {
      enviarAoBackground("OBTER_PRIVACIDADE")
        .then((dados) => {
          manifestoLGPD = dados;
          if (document.getElementById(MODAL_ID)) {
            fecharModalTransparencia();
            abrirModalTransparencia(meta);
          }
        })
        .catch(() => {
          /* offline: mantém o conteúdo local */
        });
    }
  }

  // --- INJEÇÃO ------------------------------------------------------------

  function removerBannersAntigos() {
    document.querySelectorAll(`#${BANNER_ID}`).forEach((b) => b.remove());
  }

  function injetarNaTela(bannerNode) {
    if (!bannerNode) return;
    try {
      if (provedorAtual === "gmail") {
        // GMAIL: injeta imediatamente acima da div do corpo do e-mail.
        const corpoGmail =
          document.querySelector(".a3s.aiL") || document.querySelector(".ii.gt");
        if (corpoGmail && corpoGmail.parentElement) {
          corpoGmail.parentElement.insertBefore(bannerNode, corpoGmail);
        }
      } else if (provedorAtual === "outlook") {
        // OUTLOOK: o React da Microsoft reconcilia o container do corpo e destrói
        // qualquer nó "irmão" estranho que injetamos ali (efeito pisca-pisca).
        // Solução: injetar DENTRO do corpo do e-mail, como primeiro filho. Essa
        // região é preenchida uma única vez via innerHTML (o HTML do e-mail) e
        // NÃO passa por reconciliação de filhos pelo React — é uma "zona cega".
        const corpoOutlook =
          document.querySelector('[aria-label="Message body"]') ||
          document.querySelector('[aria-label*="Message body"]') ||
          document.querySelector('[role="document"]');
        if (corpoOutlook) {
          corpoOutlook.insertBefore(bannerNode, corpoOutlook.firstChild);
        } else {
          // Fallback: acima do painel de leitura, se o corpo ainda não montou.
          const painel = document.querySelector('[role="main"]');
          if (painel) painel.insertBefore(bannerNode, painel.firstChild);
        }
      }
    } catch (erro) {
      logAviso("Falha na injeção estrutural.", erro);
    }
  }

  function renderizar(estado, explicacao, meta) {
    removerBannersAntigos();
    bannerNodeAtual = criarElementoBanner(estado, explicacao, meta);
    injetarNaTela(bannerNodeAtual);
  }

  function estadoDoResultado(resultado) {
    const nivel = String(resultado.nivel_alerta || "")
      .normalize("NFD")
      .replace(/[\u0300-\u036f]/g, "")
      .toUpperCase();
    if (resultado.is_phishing) return nivel === "ATENCAO" ? ESTADOS.atencao : ESTADOS.critico;
    if (nivel === "ATENCAO") return ESTADOS.atencao;
    return ESTADOS.seguro;
  }

  async function analisarEmailAtual() {
    if (analiseEmAndamento) return;
    const dados = extrairDadosEmail();
    if (!dados) return;

    const idUnicoEmail = dados.assunto + dados.remetente;
    if (idUnicoEmail === ultimoEmailAnalisado) return;

    analiseEmAndamento = true;
    ultimoEmailAnalisado = idUnicoEmail;

    renderizar(ESTADOS.analisando, null, null);

    try {
      // O fetch NÃO pode sair da página (https://outlook.live.com → http://localhost
      // é bloqueado pelo Private Network Access do Chrome). Delegamos ao service
      // worker, que fala com o localhost sem CORS nem restrição de rede privada.
      const resultado = await enviarAoBackground("ANALISAR_EMAIL", {
        assunto: dados.assunto,
        corpo_texto: dados.corpoTexto,
        remetente: dados.remetente,
      });

      if (resultado && resultado.pausado) {
        removerBannersAntigos();
        bannerNodeAtual = null;
        return;
      }

      const privacidadeResp = resultado.privacidade || {};
      const meta = {
        mascarados: privacidadeResp.dados_sensiveis_mascarados || 0,
        tipos: privacidadeResp.tipos_mascarados || [],
        versaoPolitica: privacidadeResp.versao_politica,
        latencia: resultado.latencia_ms || 0,
        duplaChecagem: Boolean(resultado.dupla_checagem),
      };

      const explicacao = String(
        resultado.explicacao ||
          (resultado.is_phishing
            ? "Padrões suspeitos identificados."
            : "E-mail considerado legítimo.")
      ).trim();

      renderizar(estadoDoResultado(resultado), explicacao, meta);
    } catch (erro) {
      // Falha de rede/serviço não pode deixar o usuário com um banner eterno de
      // "analisando": informamos o estado real e mantemos a identidade visual.
      logAviso("Falha ao analisar.", erro);
      renderizar(
        ESTADOS.erro,
        `${erro.message} Enquanto isso, avalie o remetente e os links manualmente.`,
        null
      );
    } finally {
      analiseEmAndamento = false;
    }
  }

  function iniciarObservador() {
    provedorAtual = detectarProvedor();
    if (!provedorAtual) return;

    let ultimoAssuntoProcessado = "";

    const verificarMudancaEmail = () => {
      const dados = extrairDadosEmail();
      if (dados && dados.assunto !== ultimoAssuntoProcessado) {
        ultimoAssuntoProcessado = dados.assunto;
        analisarEmailAtual();
      } else if (!dados) {
        removerBannersAntigos();
        ultimoAssuntoProcessado = "";
        ultimoEmailAnalisado = null;
        bannerNodeAtual = null;
      }
    };

    const observer = new MutationObserver(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(verificarMudancaEmail, 400);
    });
    observer.observe(document.body, { childList: true, subtree: true });

    // GUARDIÃO OUTLOOK (rede de segurança):
    // Com a injeção na "zona cega" o React quase nunca destrói o banner. Ainda
    // assim, um MutationObserver recoloca o nó da RAM no MESMO frame (antes do
    // paint) caso algo o remova, e um intervalo lento cobre o caso raro do corpo
    // inteiro do e-mail ser trocado.
    if (provedorAtual === "outlook") {
      let checagemAgendada = false;
      const reinjetarSeSumiu = () => {
        checagemAgendada = false;
        if (bannerNodeAtual && !document.contains(bannerNodeAtual)) {
          injetarNaTela(bannerNodeAtual);
        }
      };
      const agendarChecagem = () => {
        if (checagemAgendada) return;
        checagemAgendada = true;
        requestAnimationFrame(reinjetarSeSumiu);
      };

      const moGuardiao = new MutationObserver(agendarChecagem);
      moGuardiao.observe(document.body, { childList: true, subtree: true });

      clearInterval(guardiaoOutlookTimer);
      guardiaoOutlookTimer = setInterval(reinjetarSeSumiu, 1000);
    }

    window.addEventListener("hashchange", () => {
      ultimoAssuntoProcessado = "";
      setTimeout(verificarMudancaEmail, 300);
    });

    // A aba pode ficar horas em segundo plano; ao voltar, revalida o e-mail aberto.
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) setTimeout(verificarMudancaEmail, 300);
    });

    verificarMudancaEmail();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", iniciarObservador);
  } else {
    iniciarObservador();
  }
})();
