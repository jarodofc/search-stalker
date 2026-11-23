'use strict';

const {
  validatePublicUrl,
  fetchWithTimeout,
  setCommonHeaders,
  sendJson,
  MAX_RESPONSE_BYTES
} = require('./_utils');

const ALLOWED_PROXY_DOMAINS = [
  'brasilapi.com.br',
  'publica.cnpj.ws',
  'minhareceita.org',
  'rdap.registro.br',
  'rdap.org',
  'rdap.verisign.com',
  'crt.sh',
  'ipwho.is',
  'ipapi.co',
  'api.ipapi.is',
  'proxycheck.io',
  'api.xposedornot.com',
  'otx.alienvault.com',
  'api.hackertarget.com',
  'ip-api.com',
  'www.vpngate.net',
  'api.proxyscrape.com',
  'proxylist.geonode.com',
  'raw.githubusercontent.com',
  'nominatim.openstreetmap.org',
  'api.bigdatacloud.net',
  'dns.google',
  'cloudflare-dns.com',
  'api.github.com',
  'gitlab.com',
  'dev.to',
  'www.reddit.com',
  'hacker-news.firebaseio.com',
  'api.chess.com',
  'lichess.org',
  'registry.npmjs.org'
];

function isAllowedHost(hostname) {
  const h = hostname.toLowerCase();
  return ALLOWED_PROXY_DOMAINS.some((domain) => h === domain || h.endsWith(`.${domain}`));
}

module.exports = async (req, res) => {
  setCommonHeaders(req, res);

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') {
    return sendJson(res, 405, { ok: false, error: 'Metodo nao permitido. Use GET.' });
  }

  if (req.query.ping === '1') {
    return sendJson(res, 200, {
      ok: true,
      service: 'SHERLOCK 221B Prism Proxy',
      version: '4.1.0',
      mode: 'vercel-serverless',
      region: process.env.VERCEL_REGION || 'local-node',
      node: process.version,
      capabilities: {
        ssrfGuard: true,
        virustotalServerKey: Boolean(process.env.VT_API_KEY)
      },
      timestamp: new Date().toISOString()
    });
  }

  const target = req.query.url;
  if (!target || typeof target !== 'string') {
    return sendJson(res, 400, { ok: false, error: 'Parametro ?url= obrigatorio.' });
  }

  let parsed;
  try {
    parsed = await validatePublicUrl(target);
  } catch (err) {
    return sendJson(res, err.statusCode || 403, { ok: false, error: err.message });
  }

  if (!isAllowedHost(parsed.hostname)) {
    return sendJson(res, 403, {
      ok: false,
      error: 'Dominio fora da allowlist do proxy generico. Utilize /api/scrape ou /api/intel.'
    });
  }

  try {
    const upstream = await fetchWithTimeout(parsed.href, {
      method: 'GET',
      redirect: 'manual',
      headers: { Accept: 'application/json, text/plain, */*' }
    }, 10000);

    if (upstream.status >= 300 && upstream.status < 400) {
      return sendJson(res, 403, { ok: false, error: 'Redirecionamento bloqueado pelo proxy seguro.' });
    }

    const arrayBuf = await upstream.arrayBuffer();
    if (arrayBuf.byteLength > MAX_RESPONSE_BYTES) {
      return sendJson(res, 413, { ok: false, error: 'Payload excede o limite de 5 MB.' });
    }

    res.setHeader('Content-Type', upstream.headers.get('content-type') || 'application/octet-stream');
    res.setHeader('Cache-Control', 'public, s-maxage=60, stale-while-revalidate=120');
    return res.status(upstream.status).send(Buffer.from(arrayBuf));
  } catch (err) {
    const isAbort = err && err.name === 'AbortError';
    return sendJson(res, isAbort ? 504 : 502, {
      ok: false,
      error: isAbort ? 'Timeout ao conectar ao destino via proxy remoto.' : 'Falha na conexao via proxy remoto.'
    });
  }
};
