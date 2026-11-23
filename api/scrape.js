'use strict';

const { applyCors, safeFetch, readLimitedBuffer } = require('./_lib/net');

function decodeEntities(str) {
  return String(str || '')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .trim();
}

module.exports = async (req, res) => {
  applyCors(req, res, 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Método não permitido.' });

  let target = String(req.query.url || '').trim();
  if (!target) return res.status(400).json({ error: 'Parâmetro ?url= obrigatório.' });
  if (!/^https?:\/\//i.test(target)) target = `https://${target}`;

  try {
    const { upstream, finalUrl } = await safeFetch(
      target,
      {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
          Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
          'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8'
        }
      },
      11000
    );

    const buf = await readLimitedBuffer(upstream, 3 * 1024 * 1024);
    const html = buf.toString('utf8');
    const parsedFinal = new URL(finalUrl);

    const title = decodeEntities((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || '-');
    const descMatch = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']*)["'][^>]+name=["']description["']/i);
    const genMatch = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']*)["']/i);

    const plainText = html
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ');

    const emails = [...new Set(
      (html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])
        .filter(e => !/\.(png|jpg|jpeg|gif|svg|webp|css|js|woff2?)$/i.test(e))
    )].slice(0, 30);

    const telefones = [...new Set(
      (plainText.match(/(?:\+55\s?)?(?:\(?\d{2}\)?\s?)(?:9\d{4}|\d{4})-?\d{4}/g) || []).map(t => t.trim())
    )].slice(0, 20);

    const hrefs = [];
    const linkRx = /href=["'](https?:\/\/[^"'#\s]+)["']/gi;
    let m;
    while ((m = linkRx.exec(html)) !== null) hrefs.push(m[1]);
    const uniqueLinks = [...new Set(hrefs)];

    const socialRx = /(instagram\.com|facebook\.com|linkedin\.com|x\.com|twitter\.com|youtube\.com|tiktok\.com|wa\.me|whatsapp\.com|t\.me|github\.com)/i;
    const imgCount = (html.match(/<img\b/gi) || []).length;

    const secHeaders = [
      `HTTP Status: ${upstream.status}`,
      `Server: ${upstream.headers.get('server') || 'Oculto'}`,
      `HSTS: ${upstream.headers.get('strict-transport-security') ? 'Ativo' : 'Ausente'}`,
      `CSP: ${upstream.headers.get('content-security-policy') ? 'Ativo' : 'Ausente'}`,
      `X-Frame-Options: ${upstream.headers.get('x-frame-options') || 'Ausente'}`,
      `X-Content-Type-Options: ${upstream.headers.get('x-content-type-options') || 'Ausente'}`
    ];

    res.setHeader('Cache-Control', 'public, s-maxage=120, stale-while-revalidate=300');
    return res.status(200).json({
      provider: 'Scraper Server-Side (Vercel Node.js)',
      resumo: {
        url: finalUrl,
        status_http: String(upstream.status),
        titulo: title || '-',
        descricao: decodeEntities(descMatch?.[1] || '-'),
        tecnologia: decodeEntities(genMatch?.[1] || upstream.headers.get('x-powered-by') || '-'),
        total_links: uniqueLinks.length,
        total_imagens: imgCount,
        emails_encontrados: emails.length
      },
      listas: [
        { titulo: 'Cabeçalhos HTTP & Segurança', itens: secHeaders },
        { titulo: 'E-mails Públicos', itens: emails },
        { titulo: 'Telefones', itens: telefones },
        { titulo: 'Redes Sociais', itens: uniqueLinks.filter(l => socialRx.test(l)).slice(0, 20) },
        { titulo: 'Links Externos', itens: uniqueLinks.filter(l => !l.includes(parsedFinal.hostname) && !socialRx.test(l)).slice(0, 20) }
      ].filter(l => l.itens.length > 0),
      raw: { url: finalUrl, status: upstream.status, secHeaders, emails, telefones }
    });
  } catch (err) {
    const code = err?.statusCode || 502;
    return res.status(code).json({
      error: err?.message || 'Falha ao raspar a URL informada.'
    });
  }
};
