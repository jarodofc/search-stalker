'use strict';

const {
  validatePublicUrl,
  fetchWithTimeout,
  readLimitedText,
  setCommonHeaders,
  sendJson
} = require('./_utils');

function decodeEntities(str) {
  if (!str) return '';
  return str
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&nbsp;/gi, ' ')
    .replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(Number(dec)))
    .replace(/\s+/g, ' ')
    .trim();
}

function extractMeta(html, attrName, attrValue) {
  const rx = new RegExp(
    `<meta[^>]*${attrName}\\s*=\\s*["']${attrValue}["'][^>]*content\\s*=\\s*["']([^"']*)["'][^>]*>|` +
    `<meta[^>]*content\\s*=\\s*["']([^"']*)["'][^>]*${attrName}\\s*=\\s*["']${attrValue}["'][^>]*>`,
    'i'
  );
  const m = html.match(rx);
  return decodeEntities((m && (m[1] || m[2])) || '');
}

function analyzeSecurityHeaders(headers) {
  const checks = [
    { name: 'Strict-Transport-Security', key: 'strict-transport-security', weight: 20 },
    { name: 'Content-Security-Policy', key: 'content-security-policy', weight: 25 },
    { name: 'X-Frame-Options', key: 'x-frame-options', weight: 15 },
    { name: 'X-Content-Type-Options', key: 'x-content-type-options', weight: 15 },
    { name: 'Referrer-Policy', key: 'referrer-policy', weight: 15 },
    { name: 'Permissions-Policy', key: 'permissions-policy', weight: 10 }
  ];

  let score = 0;
  const details = checks.map((c) => {
    const val = headers.get(c.key);
    const present = Boolean(val);
    if (present) score += c.weight;
    return {
      header: c.name,
      present,
      value: val ? String(val).slice(0, 180) : null
    };
  });

  const grade = score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : score >= 30 ? 'D' : 'F';
  return {
    score,
    grade,
    server: headers.get('server') || null,
    poweredBy: headers.get('x-powered-by') || null,
    details
  };
}

module.exports = async (req, res) => {
  setCommonHeaders(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') {
    return sendJson(res, 405, { ok: false, error: 'Metodo nao permitido.' });
  }

  let rawTarget = String(req.query.url || '').trim();
  if (!rawTarget) {
    return sendJson(res, 400, { ok: false, error: 'Parametro ?url= obrigatorio.' });
  }
  if (!/^https?:\/\//i.test(rawTarget)) {
    rawTarget = `https://${rawTarget}`;
  }

  let parsed;
  try {
    parsed = await validatePublicUrl(rawTarget);
  } catch (err) {
    return sendJson(res, err.statusCode || 403, { ok: false, error: err.message });
  }

  const startedAt = Date.now();
  try {
    // Segue manualmente ate 3 redirecionamentos validando SSRF em cada salto
    let currentUrl = parsed.href;
    let upstream = null;
    for (let hop = 0; hop < 4; hop++) {
      upstream = await fetchWithTimeout(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8'
        }
      }, 10000);

      if (upstream.status >= 300 && upstream.status < 400) {
        const loc = upstream.headers.get('location');
        if (!loc) break;
        const nextUrl = new URL(loc, currentUrl).href;
        const checked = await validatePublicUrl(nextUrl);
        currentUrl = checked.href;
        continue;
      }
      break;
    }

    const elapsedMs = Date.now() - startedAt;
    const contentType = upstream.headers.get('content-type') || '';
    const html = await readLimitedText(upstream);
    const security = analyzeSecurityHeaders(upstream.headers);

    const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
    const title = decodeEntities(titleMatch ? titleMatch[1] : '');
    const description = extractMeta(html, 'name', 'description') || extractMeta(html, 'property', 'og:description');
    const ogTitle = extractMeta(html, 'property', 'og:title');
    const ogSite = extractMeta(html, 'property', 'og:site_name');
    const generator = extractMeta(html, 'name', 'generator');
    const langMatch = html.match(/<html[^>]*\blang\s*=\s*["']([^"']+)["']/i);
    const lang = langMatch ? langMatch[1] : '';

    // Remove script/style para extrair texto limpo
    const plainText = html
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ');

    // E-mails
    const rawEmails = html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
    const emails = [...new Set(
      rawEmails
        .map((e) => e.toLowerCase())
        .filter((e) => !/\.(png|jpe?g|gif|svg|webp|ico|css|js|woff2?|ttf|map)$/i.test(e))
    )].slice(0, 40);

    // Telefones (BR + internacional basico)
    const rawPhones = plainText.match(/(?:\+55\s?)?(?:\(?\d{2}\)?\s?)(?:9\d{4}|\d{4})[-\s]?\d{4}/g) || [];
    const phones = [...new Set(rawPhones.map((p) => p.replace(/\s+/g, ' ').trim()))].slice(0, 25);

    // Links
    const hrefMatches = [...html.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"'#]+)["']/gi)];
    const finalOrigin = new URL(currentUrl);
    const internalLinks = new Set();
    const externalLinks = new Set();
    const socialLinks = new Set();
    const socialRx = /(instagram\.com|facebook\.com|linkedin\.com|x\.com|twitter\.com|youtube\.com|tiktok\.com|wa\.me|whatsapp\.com|t\.me|github\.com|discord\.gg)/i;

    for (const m of hrefMatches) {
      const rawHref = m[1].trim();
      if (!rawHref || /^(javascript|mailto|tel|data):/i.test(rawHref)) continue;
      try {
        const resolved = new URL(rawHref, finalOrigin.href);
        if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') continue;
        if (socialRx.test(resolved.hostname)) {
          socialLinks.add(resolved.href);
        } else if (resolved.hostname === finalOrigin.hostname) {
          internalLinks.add(resolved.href);
        } else {
          externalLinks.add(resolved.href);
        }
      } catch {}
    }

    // Scripts externos
    const scriptMatches = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)];
    const scripts = [...new Set(scriptMatches.map((m) => {
      try { return new URL(m[1], finalOrigin.href).href; } catch { return m[1]; }
    }))].slice(0, 40);

    const imgCount = (html.match(/<img\b/gi) || []).length;
    const formCount = (html.match(/<form\b/gi) || []).length;

    return sendJson(res, 200, {
      ok: true,
      url: currentUrl,
      status: upstream.status,
      contentType,
      elapsedMs,
      bytes: Buffer.byteLength(html, 'utf8'),
      metadata: {
        title: title || ogTitle || '-',
        description: description || '-',
        siteName: ogSite || '-',
        generator: generator || '-',
        language: lang || '-',
        images: imgCount,
        forms: formCount,
        internalLinksCount: internalLinks.size,
        externalLinksCount: externalLinks.size
      },
      security,
      contacts: {
        emails,
        phones,
        social: [...socialLinks].slice(0, 30)
      },
      links: {
        internal: [...internalLinks].slice(0, 35),
        external: [...externalLinks].slice(0, 35)
      },
      scripts
    }, 60);
  } catch (err) {
    const isAbort = err && err.name === 'AbortError';
    return sendJson(res, err.statusCode || (isAbort ? 504 : 502), {
      ok: false,
      error: isAbort ? 'Tempo limite excedido ao raspar a pagina.' : (err.message || 'Falha ao coletar a pagina.')
    });
  }
};
