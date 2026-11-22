// Proxy Remoto Serverless (Vercel) — Assinatura: KIIK HACKING
const BLOCKED_HOSTS = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|\[::1\])/i;

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Proxy-Headers');
  res.setHeader('X-Proxy-Signature', 'KIIK HACKING');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Método não permitido.' });

  // Handshake de inicialização do Proxy Remoto
  if (req.query.ping === '1') {
    return res.status(200).json({
      ok: true,
      mode: 'vercel-remote-proxy',
      region: process.env.VERCEL_REGION || 'remote-edge',
      signature: 'KIIK HACKING'
    });
  }

  const target = req.query.url;
  if (!target || typeof target !== 'string') {
    return res.status(400).json({ error: 'Parâmetro ?url= obrigatório.' });
  }

  let parsed;
  try {
    parsed = new URL(target);
  } catch {
    return res.status(400).json({ error: 'URL de destino inválida.' });
  }

  if (!['http:', 'https:'].includes(parsed.protocol) || BLOCKED_HOSTS.test(parsed.hostname)) {
    return res.status(403).json({ error: 'Destino não permitido pelo proxy remoto.' });
  }

  const forwardHeaders = {
    'User-Agent': 'Mozilla/5.0 (compatible; GlassOSINT-RemoteProxy/7.1; +KIIK-HACKING)'
  };

  if (req.headers['x-proxy-headers']) {
    try {
      const custom = JSON.parse(req.headers['x-proxy-headers']);
      for (const [k, v] of Object.entries(custom)) {
        if (k.toLowerCase() === 'accept' && typeof v === 'string') {
          forwardHeaders[k] = v;
        }
      }
    } catch {}
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 11000);

  try {
    const upstream = await fetch(parsed.href, {
      method: 'GET',
      headers: forwardHeaders,
      redirect: 'follow',
      signal: ctrl.signal
    });

    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    const buffer = Buffer.from(await upstream.arrayBuffer());

    res.setHeader('Content-Type', contentType);
    res.setHeader('X-Proxy-Upstream-Status', String(upstream.status));
    return res.status(upstream.status).send(buffer);
  } catch (err) {
    return res.status(502).json({
      error: 'Falha ao conectar via proxy remoto.',
      detail: err?.message || 'Timeout ou erro de rede'
    });
  } finally {
    clearTimeout(timer);
  }
};
