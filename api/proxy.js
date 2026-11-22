// Proxy Remoto + Adaptador de Módulos (Vercel Serverless) — Assinatura: KIIK HACKING
const BLOCKED_HOSTS = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|\[::1\])/i;

// Mapeamento dos 18 módulos adaptados (substituível por variáveis de ambiente na Vercel)
const MODULE_ENDPOINTS = {
  cpf_full: process.env.EP_CPF_FULL || 'cpf_full.php',
  bigdata: process.env.EP_BIGDATA || 'bigdata.php',
  cadsus: process.env.EP_CADSUS || 'cadsus.php',
  credlink: process.env.EP_CREDLINK || 'credlink.php',
  financeiro_credito: process.env.EP_FINANCEIRO || 'financeiro_credito.php',
  telefone: process.env.EP_TELEFONE || 'telefone.php',
  cnh_sp: process.env.EP_CNH_SP || 'cnh_sp.php',
  processos: process.env.EP_PROCESSOS || 'processos.php',
  placas: process.env.EP_PLACAS || 'placas.php',
  veicular_multas_mg: process.env.EP_MULTAS_MG || 'veicular_multas_mg.php',
  veicular_vistoria: process.env.EP_VISTORIA || 'veicular_vistoria.php',
  veicular_ear: process.env.EP_EAR || 'veicular_ear.php',
  foto_ce: process.env.EP_FOTO_CE || 'foto_ce.php',
  foto_es: process.env.EP_FOTO_ES || 'foto_es.php',
  foto_ma: process.env.EP_FOTO_MA || 'foto_ma.php',
  foto_pe: process.env.EP_FOTO_PE || 'foto_pe.php',
  foto_pr: process.env.EP_FOTO_PR || 'foto_pr.php',
  foto_rj: process.env.EP_FOTO_RJ || 'foto_rj.php'
};

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Proxy-Headers');
  res.setHeader('X-Proxy-Signature', 'KIIK HACKING');

  if (req.method === 'OPTIONS') return res.status(204).end();

  // 1. Handshake de inicialização do site
  if (req.method === 'GET' && req.query.ping === '1') {
    return res.status(200).json({
      ok: true,
      mode: 'vercel-remote-proxy',
      region: process.env.VERCEL_REGION || 'remote-edge',
      privateApiConfigured: Boolean(process.env.API_BASE_URL),
      signature: 'KIIK HACKING'
    });
  }

  // 2. Rota POST: Consultas dos módulos privados adaptados (configurados via Env Vars na Vercel)
  if (req.method === 'POST') {
    const body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {});
    const mod = String(body.module || '').trim();
    const params = body.params && typeof body.params === 'object' ? body.params : {};

    if (!mod || !MODULE_ENDPOINTS[mod]) {
      return res.status(400).json({ success: false, error: 'Módulo de consulta inválido.' });
    }

    const baseUrl = (process.env.API_BASE_URL || '').replace(/\/+$/, '');
    const apiToken = process.env.API_TOKEN || '';

    if (!baseUrl) {
      return res.status(503).json({
        success: false,
        error: 'API externa ainda não vinculada. Configure API_BASE_URL e API_TOKEN nas Environment Variables da Vercel.'
      });
    }

    const ep = MODULE_ENDPOINTS[mod];
    const targetUrl = /^https?:\/\//i.test(ep) ? new URL(ep) : new URL(`${baseUrl}/${ep.replace(/^\/+/, '')}`);

    if (apiToken) targetUrl.searchParams.set('token', apiToken);
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && String(v).trim() !== '') {
        targetUrl.searchParams.set(k, String(v).trim());
      }
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);

    try {
      const upstream = await fetch(targetUrl.href, {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'GlassOSINT-RemoteProxy/6.0 (+KIIK-HACKING)',
          ...(apiToken ? { 'X-API-Key': apiToken } : {})
        },
        signal: ctrl.signal
      });

      const rawText = await upstream.text();
      let parsed;
      try { parsed = JSON.parse(rawText); } catch { parsed = { raw: rawText }; }

      return res.status(upstream.ok ? 200 : upstream.status).json({
        success: upstream.ok,
        module: mod,
        data: parsed
      });
    } catch (err) {
      return res.status(502).json({
        success: false,
        error: 'Erro ao consultar a API externa pelo proxy remoto.',
        detail: err?.message || 'Timeout'
      });
    } finally {
      clearTimeout(timer);
    }
  }

  // 3. Rota GET: Proxy Remoto Transparente (?url=...) para APIs públicas, RDAP, OSINT e Scraper
  const target = req.query.url;
  if (!target || typeof target !== 'string') {
    return res.status(400).json({ error: 'Parâmetro ?url= obrigatório.' });
  }

  let parsed;
  try { parsed = new URL(target); } catch {
    return res.status(400).json({ error: 'URL de destino inválida.' });
  }

  if (!['http:', 'https:'].includes(parsed.protocol) || BLOCKED_HOSTS.test(parsed.hostname)) {
    return res.status(403).json({ error: 'Destino não permitido pelo proxy remoto.' });
  }

  const forwardHeaders = {
    'User-Agent': 'Mozilla/5.0 (compatible; GlassOSINT-RemoteProxy/6.0; +KIIK-HACKING)'
  };

  if (req.headers['x-proxy-headers']) {
    try {
      const custom = JSON.parse(req.headers['x-proxy-headers']);
      for (const [k, v] of Object.entries(custom)) {
        if (['accept', 'x-api-key', 'authorization'].includes(k.toLowerCase()) && typeof v === 'string') {
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
    return res.status(502).json({ error: 'Falha ao conectar via proxy remoto.', detail: err?.message || 'Timeout' });
  } finally {
    clearTimeout(timer);
  }
};
