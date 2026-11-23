'use strict';

const dns = require('node:dns').promises;
const net = require('node:net');

const USER_AGENT = 'Mozilla/5.0 (compatible; zFORENSE/2.0; +https://vercel.com)';
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB cap

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts;
  if (a === 0) return true;                          // 0.0.0.0/8
  if (a === 10) return true;                         // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
  if (a === 127) return true;                        // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true;           // 169.254.0.0/16 link-local / AWS metadata
  if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
  if (a === 192 && b === 0 && parts[2] === 0) return true;
  if (a === 192 && b === 0 && parts[2] === 2) return true;
  if (a === 192 && b === 168) return true;           // 192.168.0.0/16
  if (a === 198 && (b === 18 || b === 19)) return true; // Benchmark
  if (a >= 224) return true;                         // Multicast / Reserved
  return false;
}

function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase().split('%')[0];
  if (normalized === '::' || normalized === '::1') return true;
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true; // ULA fc00::/7
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') ||
      normalized.startsWith('fea') || normalized.startsWith('feb')) return true; // Link-local fe80::/10
  if (normalized.startsWith('ff')) return true; // Multicast
  // IPv4-mapped IPv6 ::ffff:127.0.0.1
  if (normalized.startsWith('::ffff:')) {
    const mapped = normalized.slice(7);
    if (net.isIPv4(mapped)) return isPrivateIPv4(mapped);
    // Hex-encoded mapped IPv4 e.g. ::ffff:7f00:1
    const hexParts = mapped.split(':');
    if (hexParts.length === 2) {
      const hi = parseInt(hexParts[0], 16);
      const lo = parseInt(hexParts[1], 16);
      if (!Number.isNaN(hi) && !Number.isNaN(lo)) {
        const ipv4 = `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
        return isPrivateIPv4(ipv4);
      }
    }
    return true;
  }
  return false;
}

function isPrivateIp(ip) {
  const ver = net.isIP(ip);
  if (ver === 4) return isPrivateIPv4(ip);
  if (ver === 6) return isPrivateIPv6(ip);
  return true;
}

/**
 * Validates URL protocol, hostname, and resolves DNS to prevent SSRF / DNS rebinding.
 */
async function validatePublicUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw Object.assign(new Error('URL invalida.'), { statusCode: 400 });
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw Object.assign(new Error('Apenas protocolos HTTP e HTTPS sao permitidos.'), { statusCode: 403 });
  }

  if (parsed.username || parsed.password) {
    throw Object.assign(new Error('Credenciais embutidas na URL nao sao permitidas.'), { statusCode: 403 });
  }

  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    throw Object.assign(new Error('Host interno ou reservado bloqueado (SSRF Guard).'), { statusCode: 403 });
  }

  if (net.isIP(host)) {
    if (isPrivateIp(host)) {
      throw Object.assign(new Error('IP privado ou reservado bloqueado (SSRF Guard).'), { statusCode: 403 });
    }
    return parsed;
  }

  // Resolve DNS records to ensure host does not point to private infrastructure
  let records;
  try {
    records = await dns.lookup(host, { all: true, verbatim: true });
  } catch {
    throw Object.assign(new Error('Nao foi possivel resolver o dominio informado.'), { statusCode: 502 });
  }

  if (!records || records.length === 0) {
    throw Object.assign(new Error('Dominio sem registros de endereco validos.'), { statusCode: 502 });
  }

  for (const rec of records) {
    if (isPrivateIp(rec.address)) {
      throw Object.assign(new Error('Dominio resolve para faixa de IP privada (SSRF Guard).'), { statusCode: 403 });
    }
  }

  return parsed;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': USER_AGENT,
        ...(options.headers || {})
      }
    });
    return response;
  } finally {
    clearTimeout(timer);
  }
}

async function readLimitedText(response, maxBytes = MAX_RESPONSE_BYTES) {
  const contentLength = Number(response.headers.get('content-length') || 0);
  if (contentLength > maxBytes) {
    throw Object.assign(new Error('Resposta excede o limite maximo de 5 MB.'), { statusCode: 413 });
  }
  const reader = response.body ? response.body.getReader() : null;
  if (!reader) {
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      throw Object.assign(new Error('Resposta excede o limite maximo de 5 MB.'), { statusCode: 413 });
    }
    return text;
  }

  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      try { await reader.cancel(); } catch {}
      throw Object.assign(new Error('Resposta excede o limite maximo de 5 MB.'), { statusCode: 413 });
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString('utf8');
}

function setCommonHeaders(req, res) {
  const origin = req.headers.origin;
  const allowed = String(process.env.ALLOWED_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
  if (origin && allowed.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Accept');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

function sendJson(res, status, payload, cacheSeconds = 0) {
  if (cacheSeconds > 0 && status >= 200 && status < 300) {
    res.setHeader('Cache-Control', `public, s-maxage=${cacheSeconds}, stale-while-revalidate=${cacheSeconds * 2}`);
  } else {
    res.setHeader('Cache-Control', 'no-store');
  }
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  return res.status(status).json(payload);
}

async function readLimitedBuffer(response, limit = MAX_RESPONSE_BYTES) {
  const length = Number(response.headers.get('content-length') || 0);
  if (length > limit) throw Object.assign(new Error('Limite de resposta excedido.'), {statusCode:413});
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader(), chunks = [];
  let total = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel().catch(()=>{});
        throw Object.assign(new Error('Limite de resposta excedido.'), {statusCode:413});
      }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  return Buffer.concat(chunks,total);
}

function sanitizeDomain(input) {
  const cleaned = String(input || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .replace(/\.$/, '');
  if (!cleaned || cleaned.length > 253 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(cleaned)) {
    return null;
  }
  return cleaned;
}

module.exports = {
  USER_AGENT,
  MAX_RESPONSE_BYTES,
  isPrivateIp,
  validatePublicUrl,
  fetchWithTimeout,
  readLimitedText,
  readLimitedBuffer,
  setCommonHeaders,
  sendJson,
  sanitizeDomain
};
