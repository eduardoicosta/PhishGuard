(function () {
  "use strict";

  const API_URL = "http://localhost:8000/analisar-email";
  const BANNER_ID = "phishguard-banner";
  const DEBOUNCE_MS = 800;
  const LOG_PREFIX = "[PhishGuard]";

  let ultimoEmailAnalisado = null;
  let debounceTimer = null;
  let analiseEmAndamento = false;
  let provedorAtual = null;

  function logDebug(mensagem, detalhe) {
    if (detalhe !== undefined) {
      console.debug(LOG_PREFIX, mensagem, detalhe);
    } else {
      console.debug(LOG_PREFIX, mensagem);
    }
  }

  function logAviso(mensagem, erro) {
    if (erro) {
      console.warn(LOG_PREFIX, mensagem, erro);
    } else {
      console.warn(LOG_PREFIX, mensagem);
    }
  }

  function consultarElemento(seletorOuFn) {
    try {
      if (typeof seletorOuFn === "function") {
        return seletorOuFn() || null;
      }
      return document.querySelector(seletorOuFn);
    } catch (erro) {
      logDebug("Seletor ignorado por erro de DOM.", erro);
      return null;
    }
  }

  function consultarTexto(candidatos, extrator) {
    for (const candidato of candidatos) {
      const elemento = consultarElemento(candidato);
      if (!elemento) {
        continue;
      }

      try {
        const valor = extrator(elemento);
        if (valor && String(valor).trim()) {
          return String(valor).trim();
        }
      } catch (erro) {
        logDebug("Falha ao extrair texto do elemento.", erro);
      }
    }

    return "";
  }

  function detectarProvedor() {
    const hostname = window.location.hostname;

    if (hostname === "mail.google.com") {
      return "gmail";
    }

    if (hostname === "outlook.office.com" || hostname === "outlook.live.com") {
      return "outlook";
    }

    return null;
  }

  const PROVEDORES = {
    gmail: {
      extrairAssunto() {
        return consultarTexto(
          ["h2.hP", "[data-thread-perm-id] h2", ".ha h2"],
          (el) => el.textContent
        );
      },

      extrairRemetente() {
        // Buscar o container da mensagem aberta no Gmail (classes .adn ou .gE)
        // para garantir que a busca seja estrita à mensagem e nunca pegue o e-mail do cabeçalho global.
        const container = document.querySelector(".adn, .gE");

        if (!container) {
          logDebug("Container da mensagem aberta do Gmail (.adn ou .gE) não encontrado.");
          return "desconhecido@desconhecido.com";
        }

        let remetenteEl = null;
        try {
          remetenteEl = 
            container.querySelector("span[email]") ||
            container.querySelector("[email]") ||
            container.querySelector(".gD") ||
            container.querySelector(".go");
        } catch (erro) {
          logDebug("Falha ao selecionar elemento do remetente dentro do container Gmail.", erro);
        }

        if (!remetenteEl) {
          return "desconhecido@desconhecido.com";
        }

        try {
          const email = remetenteEl.getAttribute("email") || remetenteEl.getAttribute("data-sender-email");
          const nome = remetenteEl.textContent.trim();

          if (email && nome) {
            return `${nome} <${email}>`;
          }

          return email || nome || "desconhecido@desconhecido.com";
        } catch (erro) {
          logDebug("Falha ao extrair remetente do Gmail.", erro);
          return "desconhecido@desconhecido.com";
        }
      },

      extrairCorpoTexto() {
        return consultarTexto(
          [
            ".ii.gt",                     // Seletor extremamente resiliente do Gmail (corpo completo)
            ".a3s.aiL",                   // Corpo do e-mail clássico do Gmail
            ".a3s",                       // Corpo alternativo
            "[role='listitem'] .ii.gt"    // Corpo estruturado em lista de conversas
          ],
          (el) => el.innerText || el.textContent
        );
      },

      obterContainerEmail() {
        return (
          consultarElemento(".nH.if") ||
          consultarElemento(".nH") ||
          consultarElemento("[role='main']")
        );
      },
    },

    outlook: {
      extrairAssunto() {
        const assuntoDireto = consultarTexto(
          ['[aria-label="Subject"]', '[role="textbox"][aria-label*="Subject"]'],
          (el) => el.textContent || el.value || el.innerText
        );

        if (assuntoDireto) {
          return assuntoDireto;
        }

        try {
          const headings = document.querySelectorAll(
            '[role="main"] [role="heading"], [role="main"] h1, [role="main"] h2, [role="main"] h3'
          );

          for (const heading of headings) {
            const texto = heading.textContent.trim();
            if (!texto) {
              continue;
            }

            const pareceMetadado =
              texto.startsWith("From:") ||
              texto.startsWith("To:") ||
              texto.startsWith("Cc:") ||
              texto.startsWith("Bcc:") ||
              /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b/.test(texto) ||
              /^\d{1,2}\/\d{1,2}\/\d{4}/.test(texto);

            if (!pareceMetadado) {
              return texto;
            }
          }
        } catch (erro) {
          logDebug("Falha ao extrair assunto do Outlook.", erro);
        }

        return "";
      },

      extrairRemetente() {
        // 1. Tentar encontrar o container principal do e-mail no Outlook
        const container = PROVEDORES.outlook.obterContainerEmail() || document;
        
        // 2. Procurar especificamente na área de cabeçalho (evitando o corpo do texto)
        // O corpo do texto normalmente fica em [role="document"] ou dentro de um elemento com aria-label "Message body"
        const corpoEl = container.querySelector('[role="document"], [aria-label*="Message body"]');
        
        // Função auxiliar para validar se uma string contém um e-mail válido
        const contemEmail = (texto) => {
          return /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(texto);
        };

        // Função para limpar e formatar o remetente
        const formatarRemetente = (rawText) => {
          if (!rawText) return null;
          let texto = rawText.trim();
          // Remove prefixos comuns do Outlook como "From:", "De:", "Remetente:"
          texto = texto.replace(/^(From|De|Remetente):\s*/i, "");
          return texto.trim();
        };

        // Seletores específicos de remetente / cabeçalho do Outlook
        const seletoresCandidatos = [
          // Elementos com atributo title contendo e-mail (comum no Outlook)
          'span[title*="@"]',
          'div[title*="@"]',
          'button[title*="@"]',
          'a[href^="mailto:"]',
          // Elementos com aria-label de remetente
          '[aria-label^="From"]',
          '[aria-label*="From:"]',
          '[aria-label^="De:"]',
          '[aria-label*="De:"]',
          '[aria-label^="Remetente"]',
          '[aria-label*="Remetente:"]',
          // Outros seletores conhecidos de OWA
          '[data-test-id="sender-address"]',
          '[data-test-id="sender"]',
          'span[email]',
          '.PersonaHeader',
          '.ms-Persona'
        ];

        for (const seletor of seletoresCandidatos) {
          try {
            const elementos = container.querySelectorAll(seletor);
            for (const el of elementos) {
              // Garante que o elemento está FORA do corpo do e-mail para evitar falsos positivos
              if (corpoEl && corpoEl.contains(el)) {
                continue;
              }

              // Verifica se tem title contendo e-mail
              const titleValue = el.getAttribute("title");
              if (titleValue && contemEmail(titleValue)) {
                return formatarRemetente(titleValue);
              }

              // Verifica se é link de mailto
              const hrefValue = el.getAttribute("href");
              if (hrefValue && hrefValue.startsWith("mailto:")) {
                const emailDoMailto = hrefValue.replace(/^mailto:/i, "").trim();
                if (contemEmail(emailDoMailto)) {
                  // Pode ser que o texto do elemento seja o nome
                  const nome = el.textContent.trim();
                  return nome && nome !== emailDoMailto ? `${nome} <${emailDoMailto}>` : emailDoMailto;
                }
              }

              // Verifica se o aria-label contém e-mail ou dados úteis
              const ariaValue = el.getAttribute("aria-label");
              if (ariaValue && (contemEmail(ariaValue) || ariaValue.toLowerCase().startsWith("from") || ariaValue.toLowerCase().startsWith("de"))) {
                return formatarRemetente(ariaValue);
              }

              // Verifica o textContent do próprio elemento
              const textValue = el.textContent.trim();
              if (contemEmail(textValue) || textValue.startsWith("From:") || textValue.startsWith("De:")) {
                return formatarRemetente(textValue);
              }
            }
          } catch (e) {
            logDebug("Erro ao analisar seletor no Outlook: " + seletor, e);
          }
        }

        // 3. Fallback genérico: varrer elementos de cabeçalho (headings/spans/divs) fora do corpo do e-mail que contenham "From:" ou "De:"
        try {
          const elementosCabecalho = container.querySelectorAll('h1, h2, h3, [role="heading"], span, div');
          for (const el of elementosCabecalho) {
            if (corpoEl && corpoEl.contains(el)) {
              continue;
            }
            const texto = el.textContent.trim();
            if ((texto.startsWith("From:") || texto.startsWith("De:") || texto.startsWith("Remetente:")) && contemEmail(texto)) {
              return formatarRemetente(texto);
            }
          }
        } catch (erro) {
          logDebug("Falha no fallback de extração de remetente do Outlook.", erro);
        }

        // 4. Último recurso: varrer qualquer elemento fora do corpo que se pareça com um e-mail
        try {
          const todosElementos = container.querySelectorAll('span, div, a');
          for (const el of todosElementos) {
            if (corpoEl && corpoEl.contains(el)) {
              continue;
            }
            const texto = el.textContent.trim();
            // Evita strings muito longas para não capturar textos incorretos
            if (texto.length < 150 && contemEmail(texto)) {
              // Verifica se tem formato de email ou nome + email
              const match = texto.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
              if (match) {
                return formatarRemetente(texto);
              }
            }
          }
        } catch (erro) {
          logDebug("Falha no último recurso de remetente do Outlook.", erro);
        }

        return "desconhecido@desconhecido.com";
      },

      extrairCorpoTexto() {
        return consultarTexto(
          [
            '[role="document"]',
            '[aria-label="Message body"]',
            '[aria-label*="Message body"]',
            '[data-app-section="ReadingPane"] [role="document"]',
          ],
          (el) => el.innerText
        );
      },

      obterContainerEmail() {
        return (
          consultarElemento('[role="main"]') ||
          consultarElemento('[data-app-section="ReadingPane"]') ||
          consultarElemento("#ReadingPaneContainerId") ||
          consultarElemento(".ReadingPaneContainer")
        );
      },
    },
  };

  function obterProvedor() {
    if (!provedorAtual) {
      provedorAtual = detectarProvedor();
    }
    return provedorAtual ? PROVEDORES[provedorAtual] : null;
  }

  function extrairDadosEmail() {
    const provedor = obterProvedor();
    if (!provedor) {
      return null;
    }

    try {
      const assunto = provedor.extrairAssunto();
      const corpoTexto = provedor.extrairCorpoTexto();
      const remetente = provedor.extrairRemetente();

      if (!assunto || !corpoTexto) {
        return null;
      }

      return { assunto, corpoTexto, remetente };
    } catch (erro) {
      logAviso("Não foi possível extrair dados do e-mail aberto.", erro);
      return null;
    }
  }

  function limparBannersPhishGuard() {
    try {
      const bannerExistente = document.getElementById(BANNER_ID);
      if (bannerExistente) {
        bannerExistente.remove();
        logDebug("Banner do PhishGuard removido.");
      }
      const todosBanners = document.querySelectorAll(`#${BANNER_ID}`);
      todosBanners.forEach((banner) => {
        banner.remove();
        logDebug("Banner órfão do PhishGuard removido.");
      });
    } catch (erro) {
      logDebug("Falha ao limpar banners anteriores.", erro);
    }
  }

  function mostrarBannerCarregando() {
    limparBannersPhishGuard();

    const provedor = obterProvedor();
    if (!provedor) {
      return;
    }

    const container = provedor.obterContainerEmail();
    if (!container) {
      logAviso("Container do e-mail não encontrado. Banner não exibido.");
      return;
    }

    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.setAttribute("role", "alert");
    banner.textContent = "🛡️ PhishGuard: Analisando e-mail...";

    aplicarEstilosBase(banner, false);
    banner.style.background = "linear-gradient(135deg, #4b5563 0%, #6b7280 100%)";
    banner.style.color = "#ffffff";

    try {
      container.insertBefore(banner, container.firstChild);
    } catch (erro) {
      logAviso("Falha ao injetar banner no DOM.", erro);
    }
  }

  function aplicarEstilosBase(banner, compacto) {
    const estilosComuns = [
      "box-sizing: border-box",
      "width: 100%",
      "font-family: 'Segoe UI', 'Google Sans', Roboto, Arial, sans-serif",
      "letter-spacing: 0.2px",
      "border-radius: 8px",
      "position: relative",
      "z-index: 9999",
      "display: flex",
      "align-items: center",
      "justify-content: center",
      "gap: 8px",
      "text-align: center",
      "line-height: 1.45",
      "margin: 0 0 12px 0",
    ];

    if (compacto) {
      banner.style.cssText = estilosComuns.concat([
        "background: linear-gradient(135deg, #15803d 0%, #22c55e 100%)",
        "color: #ffffff",
        "font-size: 12px",
        "font-weight: 600",
        "padding: 8px 14px",
        "box-shadow: 0 2px 8px rgba(21, 128, 61, 0.25)",
        "border: 1px solid rgba(255, 255, 255, 0.25)",
      ]).join(";");
      return;
    }

    banner.style.cssText = estilosComuns.concat([
      "font-size: 14px",
      "font-weight: 700",
      "padding: 14px 18px",
      "box-shadow: 0 4px 14px rgba(0, 0, 0, 0.18)",
      "border: 1px solid rgba(255, 255, 255, 0.22)",
    ]).join(";");
  }

  function criarBanner(resultado) {
    limparBannersPhishGuard();

    const provedor = obterProvedor();
    if (!provedor) {
      return;
    }

    const container = provedor.obterContainerEmail();
    if (!container) {
      logAviso("Container do e-mail não encontrado. Banner não exibido.");
      return;
    }

    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.setAttribute("role", "alert");

    const isPhishing = Boolean(resultado.is_phishing);
    const explicacao = (resultado.explicacao || "").trim();

    if (isPhishing) {
      banner.textContent = `🚨 ALERTA PHISHGUARD — Risco Crítico | Motivo: ${explicacao || "Padrões suspeitos identificados pela IA."}`;
      aplicarEstilosBase(banner, false);
      banner.style.background = "linear-gradient(135deg, #991b1b 0%, #dc2626 100%)";
      banner.style.color = "#ffffff";
    } else {
      banner.textContent = `✅ VERIFICADO POR IA | ${explicacao || "E-mail analisado e considerado legítimo."}`;
      aplicarEstilosBase(banner, false);
      banner.style.background = "linear-gradient(135deg, #166534 0%, #22c55e 100%)";
      banner.style.color = "#ffffff";
    }

    try {
      container.insertBefore(banner, container.firstChild);
    } catch (erro) {
      logAviso("Falha ao injetar banner no DOM.", erro);
    }
  }

  function emailEstaAberto() {
    return Boolean(extrairDadosEmail());
  }

async function analisarEmailAtual() {
    if (analiseEmAndamento) return;

    const dados = extrairDadosEmail();
    if (!dados) return;

    // Verificação simples: se o assunto for igual ao do último e-mail, não analise de novo
    const idUnicoEmail = dados.assunto + dados.remetente;
    if (idUnicoEmail === ultimoEmailAnalisado) return;

    analiseEmAndamento = true;
    ultimoEmailAnalisado = idUnicoEmail; // Atualiza o ID
    
    mostrarBannerCarregando();

    try {
        // ENVIAR JSON DIRETO (SEM BTOA/BASE64)
        const resposta = await fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                assunto: dados.assunto, 
                corpo_texto: dados.corpoTexto, 
                remetente: dados.remetente 
            }),
        });

        if (!resposta.ok) throw new Error("Falha na API");

        const resultado = await resposta.json();
        
        criarBanner(resultado);
    } catch (erro) {
        logAviso("Falha ao analisar.", erro);
        limparBannersPhishGuard();
    } finally {
        analiseEmAndamento = false;
    }
}

  function agendarAnalise() {
    clearTimeout(debounceTimer);

    debounceTimer = setTimeout(() => {
      try {
        if (!obterProvedor()) {
          return;
        }

        if (!emailEstaAberto()) {
          limparBannersPhishGuard();
          ultimoEmailAnalisado = null;
          return;
        }

        analisarEmailAtual();
      } catch (erro) {
        logAviso("Erro durante o ciclo de análise.", erro);
      }
    }, DEBOUNCE_MS);
  }

function iniciarObservador() {
    provedorAtual = detectarProvedor();

    if (!provedorAtual) {
      logDebug("Provedor de e-mail não suportado nesta página.");
      return;
    }

    logDebug(`PhishGuard ativo para: ${provedorAtual}`);

    // Variável para armazenar o último ID/assunto analisado e evitar reanálises desnecessárias
    let ultimoAssuntoProcessado = "";

    const verificarMudancaEmail = () => {
      const dados = extrairDadosEmail();
      if (dados && dados.assunto !== ultimoAssuntoProcessado) {
        ultimoAssuntoProcessado = dados.assunto;
        analisarEmailAtual();
      } else if (!dados) {
        limparBannersPhishGuard();
        ultimoAssuntoProcessado = "";
      }
    };

    // Observador leve focado apenas nas mudanças do container principal (sem subtree global pesada)
    const observer = new MutationObserver(() => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(verificarMudancaEmail, 400); // Debounce reduzido para 400ms para maior agilidade
    });

    const containerAlvo = document.body; 
    observer.observe(containerAlvo, {
      childList: true,
      // Removido o 'subtree: true' excessivo para evitar travamento de performance
    });

    // Eventos de navegação SPA (mudança de e-mail ao clicar na lista)
    window.addEventListener("hashchange", () => {
      logDebug("Mudança de URL detectada (hashchange).");
      limparBannersPhishGuard();
      ultimoAssuntoProcessado = "";
      setTimeout(verificarMudancaEmail, 300);
    });

    window.addEventListener("popstate", () => {
      logDebug("Mudança de URL detectada (popstate).");
      limparBannersPhishGuard();
      ultimoAssuntoProcessado = "";
      setTimeout(verificarMudancaEmail, 300);
    });

    // Executa na inicialização caso já haja um e-mail aberto
    verificarMudancaEmail();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", iniciarObservador);
  } else {
    iniciarObservador();
  }
})();
