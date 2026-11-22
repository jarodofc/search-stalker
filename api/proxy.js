// Proxy Remoto Serverless + Rota VirusTotal v3 (Vercel) — Assinatura: KIIK HACKING
const BLOCKED_HOSTS = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|\[::1\])/i;

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Proxy-Headers, X-VT-Key');
  res.setHeader('X-Proxy-Signature', 'KIIK HACKING');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Método não permitido.' });

  // 1. Handshake de inicialização do Proxy Remoto
  if (req.query.ping === '1') {
    return res.status(200).json({
      ok: true,
      mode: 'vercel-remote-proxy',
      region: process.env.VERCEL_REGION || 'remote-edge',
      vtConfigured: Boolean(process.env.VT_API_KEY),
      signature: 'KIIK HACKING'
    });
  }

  // 2. Rota Dedicada: VirusTotal API v3 (?vt=1&type=file|domain|ip|url&target=...)
  if (req.query.vt === '1') {
    const vtKey = String(process.env.VT_API_KEY || req.headers['x-vt-key'] || '').trim();
    const type = String(req.query.type || '').toLowerCase();
    const target = String(req.query.target || '').trim();

    if (!vtKey) {
      return res.status(503).json({
        error: 'Chave VirusTotal não configurada. Adicione VT_API_KEY nas Environment Variables da Vercel ou informe sua chave gratuita no painel.'
      });
    }
    if (!target) return res.status(400).json({ error: 'Alvo obrigatório para consulta no VirusTotal.' });

    let vtUrl = '';
    if (type === 'file') {
      vtUrl = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(target)}`; } else if (type === 'domain') { vtUrl = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(target)}`;
    } else if (type === 'ip') {
      vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(target)}`; } else if (type === 'url') { const urlId = Buffer.from(target, 'utf8').toString('base64url'); vtUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    } else {
      return res.status(400).json({ error: 'Tipo VirusTotal inválido (use file, domain, ip ou url).' });
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 12000);
    try {
      const upstream = await fetch(vtUrl, {
        method: 'GET',
        headers: { 'x-apikey': vtKey, 'Accept': 'application/json' },
        signal: ctrl.signal
      });
      const text = await upstream.text();
      res.setHeader('Content-Type', 'application/json');
      return res.status(upstream.status).send(text);
    } catch (err) {
      return res.status(502).json({ error: 'Falha ao consultar VirusTotal v3.', detail: err?.message || 'Timeout' });
    } finally {
      clearTimeout(timer);
    }
  }

  // 3. Rota Geral: Proxy Remoto Transparente (?url=...)
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
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/html, */*;q=0.8',
    'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8'
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
