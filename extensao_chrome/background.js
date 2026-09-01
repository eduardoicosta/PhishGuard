// PhishGuard — Service Worker (MV3)
//
// Motivo de existir:
// O Chrome bloqueia requisições feitas do CONTEXTO DA PÁGINA (https://outlook.live.com,
// uma origem "pública") para o espaço de loopback (http://localhost:8000) via
// Private Network Access / Local Network Access — mesmo com CORS liberado no servidor
// o navegador nega ("Permission was denied for this request to access the loopback
// address space").
//
// A solução definitiva é fazer o fetch AQUI, no service worker da extensão: ele roda
// na origem chrome-extension:// e usa as host_permissions do manifest, portanto NÃO
// passa por CORS nem pela restrição de rede privada. O content script apenas manda uma
// mensagem e recebe o JSON pronto.

const API_URL = "http://localhost:8000/analisar-email";
const TIMEOUT_MS = 30000;

async function analisarEmail(payload) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const resposta = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json; charset=utf-8",
      },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    if (!resposta.ok) {
      throw new Error(`API respondeu ${resposta.status}`);
    }

    return await resposta.json();
  } finally {
    clearTimeout(timer);
  }
}

chrome.runtime.onMessage.addListener((mensagem, _sender, sendResponse) => {
  if (!mensagem || mensagem.type !== "ANALISAR_EMAIL") {
    return false;
  }

  analisarEmail(mensagem.payload)
    .then((data) => sendResponse({ ok: true, data }))
    .catch((erro) =>
      sendResponse({ ok: false, error: String((erro && erro.message) || erro) })
    );

  // Mantém o canal aberto para a resposta assíncrona.
  return true;
});
