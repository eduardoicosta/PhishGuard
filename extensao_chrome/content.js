(function () {
  "use strict";

  const API_URL = "http://localhost:8000/analisar-email";
  const BANNER_ID = "phishguard-banner";
  const DEBOUNCE_MS = 800;
  const LOG_PREFIX = "[PhishGuard]";

  let ultimoEmailAnalisado = null;
  let bannerNodeAtual = null; // Armazena o nó na RAM para evitar recálculo de tela (pisca-pisca)
  let debounceTimer = null;
  let analiseEmAndamento = false;
  let provedorAtual = null;
  let guardiaoOutlookTimer = null;

  function logAviso(mensagem, erro) {
    if (erro) console.warn(LOG_PREFIX, mensagem, erro);
    else console.warn(LOG_PREFIX, mensagem);
  }

  function consultarElemento(seletor) {
    try { return document.querySelector(seletor); } 
    catch (erro) { return null; }
  }

  function consultarTexto(candidatos, extrator) {
    for (const candidato of candidatos) {
      const elemento = consultarElemento(candidato);
      if (!elemento) continue;
      try {
        const valor = extrator(elemento);
        if (valor && String(valor).trim()) return String(valor).trim();
      } catch (erro) {}
    }
    return "";
  }

  function detectarProvedor() {
    const hostname = window.location.hostname;
    if (hostname === "mail.google.com") return "gmail";
    if (hostname === "outlook.office.com" || hostname === "outlook.live.com") return "outlook";
    return null;
  }

  // --- MOTOR DE EXTRAÇÃO DE DADOS ---
  const PROVEDORES = {
    gmail: {
      extrairAssunto: () => consultarTexto(["h2.hP", "[data-thread-perm-id] h2", ".ha h2"], (el) => el.textContent),
      extrairRemetente() {
        const container = document.querySelector(".adn, .gE");
        if (!container) return "desconhecido@desconhecido.com";
        let remetenteEl = container.querySelector("span[email]") || container.querySelector("[email]") || container.querySelector(".gD");
        if (!remetenteEl) return "desconhecido@desconhecido.com";
        const email = remetenteEl.getAttribute("email") || remetenteEl.getAttribute("data-sender-email");
        const nome = remetenteEl.textContent.trim();
        return (email && nome) ? `${nome} <${email}>` : email || nome || "desconhecido@desconhecido.com";
      },
      extrairCorpoTexto: () => consultarTexto([".ii.gt", ".a3s.aiL", ".a3s"], (el) => el.innerText || el.textContent)
    },
    outlook: {
      extrairAssunto() {
        const assunto = consultarTexto(['[aria-label="Subject"]', '[role="textbox"][aria-label*="Subject"]'], (el) => el.textContent || el.value);
        if (assunto) return assunto;
        const headings = document.querySelectorAll('[role="main"] [role="heading"], [role="main"] h1, [role="main"] h2');
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
        const limpa = (t) => t ? t.trim().replace(/^(From|De|Remetente):\s*/i, "").trim() : null;
        const seletores = ['span[title*="@"]', 'div[title*="@"]', 'button[title*="@"]', 'a[href^="mailto:"]', '[aria-label^="From"]', '[aria-label*="From:"]', '[aria-label^="De:"]', '[data-test-id="sender-address"]', 'span[email]'];
        for (const seletor of seletores) {
          for (const el of container.querySelectorAll(seletor)) {
            if (corpoEl && corpoEl.contains(el)) continue;
            const title = el.getAttribute("title");
            if (title && contemEmail(title)) return limpa(title);
            const aria = el.getAttribute("aria-label");
            if (aria && (contemEmail(aria) || aria.toLowerCase().startsWith("from"))) return limpa(aria);
            const text = el.textContent.trim();
            if (contemEmail(text) || text.startsWith("From:")) return limpa(text);
          }
        }
        return "desconhecido@desconhecido.com";
      },
      extrairCorpoTexto: () => consultarTexto(['[role="document"]', '[aria-label="Message body"]', '[aria-label*="Message body"]'], (el) => el.innerText)
    }
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

  // --- MOTOR DE UI / BANNER ---
  const SVG_ESCUDO = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2.5l7 2.6v5.6c0 4.7-3 8.4-7 10.3-4-1.9-7-5.6-7-10.3V5.1l7-2.6z" fill="currentColor" fill-opacity="0.16" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/><path d="M8.6 12.2l2.3 2.3 4.5-4.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function criarElementoBanner(corStatus, textoTitulo, textoExplicacao) {
    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.setAttribute("role", "alert");
    
    // Animação e estilos aplicados diretamente no elemento
    banner.style.cssText = [
      "box-sizing: border-box", "position: relative", "width: 100%", "margin: 16px 0", "z-index: 10",
      "padding: 16px 20px", "display: flex", "align-items: flex-start", "gap: 14px",
      "font-family: 'Segoe UI', 'Google Sans', Roboto, Arial, sans-serif",
      "background: #1e293b", "color: #f8fafc", "border-radius: 12px",
      `border-left: 7px solid ${corStatus}`, "box-shadow: 0 8px 24px rgba(15, 23, 42, 0.25)",
      "text-align: left", "transition: opacity 0.2s ease-in"
    ].join(";");

    const conteudo = document.createElement("div");
    conteudo.style.cssText = "display: flex; flex-direction: column; gap: 5px; flex: 1;";

    const titulo = document.createElement("div");
    titulo.style.cssText = "display: flex; align-items: center; gap: 10px; font-size: 15px; font-weight: 700; color: #f8fafc; letter-spacing: 0.3px;";
    
    const icone = document.createElement("div");
    icone.style.cssText = `display: flex; align-items: center; justify-content: center; flex-shrink: 0; line-height: 0; color: ${corStatus};`;
    icone.innerHTML = SVG_ESCUDO;

    const textoTituloEl = document.createElement("span");
    textoTituloEl.textContent = textoTitulo;

    titulo.appendChild(icone);
    titulo.appendChild(textoTituloEl);
    conteudo.appendChild(titulo);

    if (textoExplicacao) {
      const descricao = document.createElement("div");
      descricao.style.cssText = "font-size: 13px; font-weight: 400; color: #cbd5e1; line-height: 1.6;";
      descricao.textContent = textoExplicacao;
      conteudo.appendChild(descricao);
    }

    banner.appendChild(conteudo);
    return banner;
  }

  function removerBannersAntigos() {
    document.querySelectorAll(`#${BANNER_ID}`).forEach(b => b.remove());
  }

  function injetarNaTela(bannerNode) {
    if (!bannerNode) return;
    try {
      if (provedorAtual === "gmail") {
        // GMAIL: Procura a div exata do texto do e-mail e injeta o banner LOGO ACIMA dela (abaixo do remetente).
        const corpoGmail = document.querySelector('.a3s.aiL') || document.querySelector('.ii.gt');
        if (corpoGmail && corpoGmail.parentElement) {
          corpoGmail.parentElement.insertBefore(bannerNode, corpoGmail);
        }
      } else if (provedorAtual === "outlook") {
        // OUTLOOK: o React da Microsoft reconcilia o container do corpo e destrói
        // qualquer nó "irmão" estranho que injetamos ali (efeito pisca-pisca).
        // Solução: injetar DENTRO do corpo do e-mail, como primeiro filho. Essa região
        // é preenchida uma única vez via innerHTML (HTML do e-mail) e NÃO passa por
        // reconciliação de filhos pelo React — é uma "zona cega" estável.
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

  async function analisarEmailAtual() {
    if (analiseEmAndamento) return;
    const dados = extrairDadosEmail();
    if (!dados) return;

    const idUnicoEmail = dados.assunto + dados.remetente;
    if (idUnicoEmail === ultimoEmailAnalisado) return;

    analiseEmAndamento = true;
    ultimoEmailAnalisado = idUnicoEmail; 
    
    // Cria o banner de carregamento e guarda na RAM
    removerBannersAntigos();
    bannerNodeAtual = criarElementoBanner("#64748b", "PHISHGUARD IA: ANALISANDO E-MAIL...", null);
    injetarNaTela(bannerNodeAtual);

    try {
        // O fetch NÃO pode sair da página (https://outlook.live.com → http://localhost
        // é bloqueado pelo Private Network Access do Chrome). Delegamos ao service worker
        // da extensão, que fala com o localhost sem CORS nem restrição de rede privada.
        const resultado = await new Promise((resolve, reject) => {
            chrome.runtime.sendMessage(
                {
                    type: "ANALISAR_EMAIL",
                    payload: { assunto: dados.assunto, corpo_texto: dados.corpoTexto, remetente: dados.remetente },
                },
                (resp) => {
                    if (chrome.runtime.lastError) {
                        reject(new Error(chrome.runtime.lastError.message));
                    } else if (!resp || !resp.ok) {
                        reject(new Error((resp && resp.error) || "Sem resposta do background."));
                    } else {
                        resolve(resp.data);
                    }
                }
            );
        });

        const isPhishing = Boolean(resultado.is_phishing);
        const corStatus = isPhishing ? "#dc2626" : "#10b981";
        const textoTitulo = isPhishing ? "PHISHGUARD IA: AMEAÇA DETECTADA" : "PHISHGUARD IA: E-MAIL SEGURO";
        const textoExplicacao = (resultado.explicacao || (isPhishing ? "Padrões suspeitos identificados." : "E-mail considerado legítimo.")).trim();

        // Atualiza o banner oficial e substitui o de carregamento
        removerBannersAntigos();
        bannerNodeAtual = criarElementoBanner(corStatus, textoTitulo, textoExplicacao);
        injetarNaTela(bannerNodeAtual);

    } catch (erro) {
        logAviso("Falha ao analisar.", erro);
        removerBannersAntigos();
        bannerNodeAtual = null;
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
        bannerNodeAtual = null;
      }
    };

    const observer = new MutationObserver(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(verificarMudancaEmail, 400); 
    });

    observer.observe(document.body, { childList: true, subtree: true });

    // GUARDIÃO OUTLOOK (rede de segurança):
    // Com a injeção na "zona cega" (dentro do corpo do e-mail) o React não destrói mais
    // o banner, então isto quase nunca dispara. Um MutationObserver recoloca o nó da RAM
    // no MESMO tick (antes do paint) caso algo o remova, e um intervalo lento cobre o
    // caso raro do corpo do e-mail inteiro ser trocado pelo React.
    if (provedorAtual === "outlook") {
      let checagemAgendada = false;
      const reinjetarSeSumiu = () => {
        checagemAgendada = false;
        if (bannerNodeAtual && !document.contains(bannerNodeAtual)) {
          injetarNaTela(bannerNodeAtual);
        }
      };
      // Coalesce as muitas mutações do OWA numa única checagem por frame.
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

    verificarMudancaEmail();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", iniciarObservador);
  } else {
    iniciarObservador();
  }
})();