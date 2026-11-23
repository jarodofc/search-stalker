'use strict';

const { applyCors, safeFetch, readLimitedBuffer, isValidIPv4 } = require('./_lib/net');

module.exports = async (req, res) => {
  applyCors(req, res, 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Método não permitido.' });

  // 1. Handshake de inicialização do Proxy Remoto
  if (req.query.ping === '1') {
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).json({
      ok: true,
      mode: 'vercel-remote-proxy',
      version: '2.0.0',
      region: process.env.VERCEL_REGION || 'remote-edge',
      vtConfigured: Boolean(process.env.VT_API_KEY),
      endpoints: { recon: '/api/recon', scrape: '/api/scrape' },
      signature: 'KIIK HACKING'
    });
  }

  // 2. Rota VirusTotal API v3 (?vt=1&type=file|domain|ip|url&target=...)
  if (req.query.vt === '1') {
    const vtKey = String(process.env.VT_API_KEY || req.headers['x-vt-key'] || '').trim();
    const type = String(req.query.type || '').toLowerCase();
    const target = String(req.query.target || '').trim();

    if (!vtKey) {
      return res.status(503).json({
        error: 'Chave VirusTotal não configurada. Adicione VT_API_KEY nas Environment Variables da Vercel ou informe sua chave no painel.'
      });
    }
    if (!target) {
      return res.status(400).json({ error: 'Alvo obrigatório para consulta no VirusTotal.' });
    }

    let vtUrl = '';
    if (type === 'file') {
      if (!/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(target)) {
        return res.status(400).json({ error: 'Hash inválido (use MD5, SHA-1 ou SHA-256).' });
      }
      vtUrl = `[https://www.virustotal.com/api/v3/files/$](https://www.virustotal.com/api/v3/files/$){encodeURIComponent(target.toLowerCase())}`;
    } else if (type === 'domain') {
      vtUrl = `[https://www.virustotal.com/api/v3/domains/$](https://www.virustotal.com/api/v3/domains/$){encodeURIComponent(target.toLowerCase())}`;
    } else if (type === 'ip') {
      if (!isValidIPv4(target)) {
        return res.status(400).json({ error: 'Endereço IPv4 inválido.' });
      }
      vtUrl = `[https://www.virustotal.com/api/v3/ip_addresses/$](https://www.virustotal.com/api/v3/ip_addresses/$){encodeURIComponent(target)}`;
    } else if (type === 'url') {
      const urlId = Buffer.from(target, 'utf8').toString('base64url');
      vtUrl = `[https://www.virustotal.com/api/v3/urls/$](https://www.virustotal.com/api/v3/urls/$){urlId}`;
    } else {
      return res.status(400).json({ error: 'Tipo VirusTotal inválido (use file, domain, ip ou url).' });
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 12000);
    try {
      const upstream = await fetch(vtUrl, {
        method: 'GET',
        headers: { 'x-apikey': vtKey, Accept: 'application/json' },
        signal: ctrl.signal
      });
      const text = await upstream.text();
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.setHeader('Cache-Control', 'private, max-age=120');
      return res.status(upstream.status).send(text);
    } catch (err) {
      return res.status(502).json({
        error: 'Falha ao consultar VirusTotal v3.',
        detail: err?.name === 'AbortError' ? 'Timeout na API do VirusTotal' : err?.message
      });
    } finally {
      clearTimeout(timer);
    }
  }

  // 3. Proxy Remoto Transparente Blindado (?url=...)
  const target = req.query.url;
  if (!target || typeof target !== 'string') {
    return res.status(400).json({ error: 'Parâmetro ?url= obrigatório.' });
  }

  const forwardHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    Accept: 'application/json, text/html, text/plain, */*;q=0.8',
    'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8'
  };

  if (req.headers['x-proxy-headers']) {
    try {
      const custom = JSON.parse(req.headers['x-proxy-headers']);
      if (custom && typeof custom === 'object') {
        for (const [k, v] of Object.entries(custom)) {
          if (k.toLowerCase() === 'accept' && typeof v === 'string' && v.length <= 200) {
            forwardHeaders.Accept = v;
          }
        }
      }
    } catch {}
  }

  try {
    const { upstream } = await safeFetch(target, { method: 'GET', headers: forwardHeaders }, 11000);
    const contentType = upstream.headers.get('content-type') || 'application/octet-stream';
    const buffer = await readLimitedBuffer(upstream);

    res.setHeader('Content-Type', contentType);
    res.setHeader('X-Proxy-Upstream-Status', String(upstream.status));
    if (upstream.ok) {
      res.setHeader('Cache-Control', 'public, s-maxage=60, stale-while-revalidate=300');
    }
    return res.status(upstream.status).send(buffer);
  } catch (err) {
    const code = err?.statusCode || 502;
    return res.status(code).json({
      error: err?.statusCode ? err.message : 'Falha ao conectar via proxy remoto.',
      detail: err?.name === 'AbortError' ? 'Timeout na origem' : err?.message
    });
  }
};
