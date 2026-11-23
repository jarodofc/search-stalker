'use strict';

const dns = require('node:dns').promises;
const net = require('node:net');

const MAX_REDIRECTS = 3;
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MB

function isPrivateIPv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // Link-local / Cloud Metadata
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // Multicast / Reservado
  return false;
}

function isPrivateIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // ULA fc00::/7
  if (/^fe[89ab]/.test(lower)) return true; // Link-local fe80::/10
  if (lower.startsWith('ff')) return true; // Multicast
  // IPv4-mapped IPv6 (ex: ::ffff:127.0.0.1)
  const v4Mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (v4Mapped) return isPrivateIPv4(v4Mapped[1]);
  return false;
}

function isPrivateIp(ip) {
  const kind = net.isIP(ip);
  if (kind === 4) return isPrivateIPv4(ip);
  if (kind === 6) return isPrivateIPv6(ip);
  return true;
}

async function assertSafeUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    const err = new Error('URL de destino inválida.');
    err.statusCode = 400;
    throw err;
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    const err = new Error('Apenas protocolos HTTP e HTTPS são permitidos.');
    err.statusCode = 403;
    throw err;
  }

  const host = parsed.hostname.replace(/^\[|\]$/g, '');
  if (!host || /^(localhost|.*\.localhost|.*\.local|.*\.internal)$/i.test(host)) {
    const err = new Error('Destino interno bloqueado pela política anti-SSRF.');
    err.statusCode = 403;
    throw err;
  }

  if (net.isIP(host)) {
    if (isPrivateIp(host)) {
      const err = new Error('Endereço IP privado ou reservado bloqueado.');
      err.statusCode = 403;
      throw err;
    }
    return parsed;
  }

  let resolved;
  try {
    resolved = await dns.lookup(host, { all: true, verbatim: true });
  } catch {
    const err = new Error('Não foi possível resolver o domínio informado.');
    err.statusCode = 502;
    throw err;
  }

  if (!resolved.length || resolved.some(entry => isPrivateIp(entry.address))) {
    const err = new Error('O domínio resolve para um endereço IP privado bloqueado.');
    err.statusCode = 403;
    throw err;
  }

  return parsed;
}

async function readLimitedBuffer(response, maxBytes = MAX_RESPONSE_BYTES) {
  const contentLength = Number(response.headers.get('content-length') || 0);
  if (contentLength > maxBytes) {
    const err = new Error(`Resposta excede o limite de ${(maxBytes / 1048576).toFixed(0)} MB.`);
    err.statusCode = 413;
    throw err;
  }

  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      const err = new Error(`Resposta excede o limite de ${(maxBytes / 1048576).toFixed(0)} MB.`);
      err.statusCode = 413;
      throw err;
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total);
}

async function safeFetch(targetUrl, options = {}, timeoutMs = 11000) {
  let currentUrl = targetUrl;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const parsed = await assertSafeUrl(currentUrl);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);

    try {
      const upstream = await fetch(parsed.href, {
        ...options,
        redirect: 'manual',
        signal: ctrl.signal
      });

      if ([301, 302, 303, 307, 308].includes(upstream.status)) {
        const loc = upstream.headers.get('location');
        if (!loc) return { upstream, finalUrl: parsed.href };
        currentUrl = new URL(loc, parsed).href;
        continue;
      }

      return { upstream, finalUrl: parsed.href };
    } finally {
      clearTimeout(timer);
    }
  }

  const err = new Error('Limite máximo de redirecionamentos excedido.');
  err.statusCode = 508;
  throw err;
}

function applyCors(req, res, methods = 'GET, OPTIONS') {
  const allowed = process.env.ALLOWED_ORIGIN || '*';
  res.setHeader('Access-Control-Allow-Origin', allowed);
  res.setHeader('Access-Control-Allow-Methods', methods);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Proxy-Headers, X-VT-Key');
  res.setHeader('X-Proxy-Signature', 'KIIK HACKING');
  res.setHeader('X-Content-Type-Options', 'nosniff');
}

function isValidIPv4(ip) {
  return net.isIPv4(String(ip || '').trim());
}

module.exports = {
  assertSafeUrl,
  readLimitedBuffer,
  safeFetch,
  applyCors,
  isValidIPv4,
  MAX_RESPONSE_BYTES
};
