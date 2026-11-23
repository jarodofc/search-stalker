const state = {
  online: false,
  mode: 'checking',
  region: '-',
  latencyMs: null,
  virustotalServerKey: false,
  error: null
};

export function getProxyState() {
  return { ...state };
}

/**
 * Non-blocking boot handshake against /api/proxy?ping=1 (max 3.2s timeout).
 */
export async function initRemoteProxy() {
  const t0 = performance.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 3200);

  try {
    const res = await fetch('/api/proxy?ping=1', {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: ctrl.signal
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (!data || !data.ok) throw new Error('Handshake invalido');

    state.online = true;
    state.mode = data.mode || 'vercel-serverless';
    state.region = data.region || 'edge';
    state.latencyMs = Math.round(performance.now() - t0);
    state.virustotalServerKey = Boolean(data.capabilities && data.capabilities.virustotalServerKey);
    state.error = null;
  } catch (err) {
    state.online = false;
    state.mode = 'offline-local-only';
    state.region = 'browser';
    state.latencyMs = null;
    state.error = err ? err.message : 'API serverless indisponivel localmente';
  } finally {
    clearTimeout(timer);
  }
  return getProxyState();
}

export async function callApi(path, params = {}, extraHeaders = {}, timeoutMs = 14000) {
  const url = new URL(path, window.location.origin);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && String(v).trim() !== '') {
      url.searchParams.set(k, String(v).trim());
    }
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);

  try {
    const res = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        ...extraHeaders
      },
      signal: ctrl.signal
    });

    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      throw new Error(
        'A rota serverless /api nao respondeu em JSON. Certifique-se de que o projeto esta rodando via Vercel (deploy ou `vercel dev`).'
      );
    }

    const data = await res.json();
    if (!res.ok || data.ok === false) {
      const err = new Error(data.error || `Erro HTTP ${res.status}`);
      err.status = res.status;
      err.payload = data;
      throw err;
    }
    return data;
  } catch (err) {
    if (err && err.name === 'AbortError') {
      throw new Error('Tempo limite da requisicao excedido. Tente novamente.');
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
