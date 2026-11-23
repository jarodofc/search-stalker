'use strict';

const dns = require('node:dns').promises;
const net = require('node:net');
const { isPrivateIp, fetchWithTimeout, setCommonHeaders, sendJson, sanitizeDomain } = require('./_utils');

function isValidCnpj(cnpj) {
  const c = String(cnpj || '').replace(/\D/g, '');
  if (c.length !== 14 || /^(\d)\1{13}$/.test(c)) return false;
  const calc = (base, w) => {
    let s = 0;
    for (let i = 0; i < w.length; i++) s += Number(base[i]) * w[i];
    const r = s % 11;
    return r < 2 ? 0 : 11 - r;
  };
  return calc(c.slice(0, 12), [5,4,3,2,9,8,7,6,5,4,3,2]) === Number(c[12]) &&
         calc(c.slice(0, 13), [6,5,4,3,2,9,8,7,6,5,4,3,2]) === Number(c[13]);
}

async function handleDns(req, res) {
  const domain = sanitizeDomain(req.query.domain);
  if (!domain) return sendJson(res, 400, { ok: false, error: 'Dominio invalido.' });
  const safe = (fn) => fn().catch(() => []);
  const [A, AAAA, MX, NS, TXT, CNAME, SOA, DMARC] = await Promise.all([
    safe(() => dns.resolve4(domain)),
    safe(() => dns.resolve6(domain)),
    safe(() => dns.resolveMx(domain)),
    safe(() => dns.resolveNs(domain)),
    safe(() => dns.resolveTxt(domain)),
    safe(() => dns.resolveCname(domain)),
    dns.resolveSoa(domain).catch(() => null),
    safe(() => dns.resolveTxt(`_dmarc.${domain}`))
  ]);
  const flatTxt = TXT.map((x) => x.join(''));
  const flatDmarc = DMARC.map((x) => x.join(''));
  const spf = flatTxt.find((t) => t.toLowerCase().startsWith('v=spf1')) || null;
  const dmarc = flatDmarc.find((t) => t.toLowerCase().startsWith('v=dmarc1')) || null;
  return sendJson(res, 200, {
    ok: true, domain,
    records: { A, AAAA, MX: MX.sort((a, b) => a.priority - b.priority), NS, CNAME, TXT: flatTxt, SOA },
    emailSecurity: { hasSpf: Boolean(spf), spf, hasDmarc: Boolean(dmarc), dmarc }
  }, 120);
}

function getVcard(ent, field) {
  const arr = ent && ent.vcardArray && ent.vcardArray[1];
  const row = Array.isArray(arr) ? arr.find((r) => Array.isArray(r) && r[0] === field) : null;
  if (!row) return null;
  return Array.isArray(row[3]) ? row[3].filter(Boolean).join(' ') : String(row[3] || '');
}

async function handleRdap(req, res) {
  const domain = sanitizeDomain(req.query.domain);
  if (!domain) return sendJson(res, 400, { ok: false, error: 'Dominio invalido.' });
  const eps = [];
  if (domain.endsWith('.br')) eps.push(['Registro.br RDAP', `https://rdap.registro.br/domain/${encodeURIComponent(domain)}`]);
  else if (domain.endsWith('.com') || domain.endsWith('.net')) {
    eps.push(['Verisign RDAP', `https://rdap.verisign.com/${domain.endsWith('.com') ? 'com' : 'net'}/v1/domain/${encodeURIComponent(domain)}`]);
  }
  eps.push(['RDAP.org', `https://rdap.org/domain/${encodeURIComponent(domain)}`]);

  let data = null, provider = null, lastErr = 'RDAP indisponivel';
  for (const [name, url] of eps) {
    try {
      const r = await fetchWithTimeout(url, { headers: { Accept: 'application/rdap+json, application/json' } }, 8000);
      if (r.ok) { data = await r.json(); provider = name; break; }
      lastErr = `HTTP ${r.status} em ${name}`;
    } catch (e) { lastErr = e.message; }
  }
  if (!data) return sendJson(res, 502, { ok: false, error: `Falha RDAP (${lastErr}).` });

  const ents = Array.isArray(data.entities) ? data.entities : [];
  const regt = ents.find((e) => (e.roles || []).includes('registrant')) || ents.find((e) => (e.roles || []).includes('administrative'));
  const regr = ents.find((e) => (e.roles || []).includes('registrar'));
  const events = {};
  (data.events || []).forEach((ev) => { if (ev.eventAction) events[ev.eventAction] = ev.eventDate; });

  return sendJson(res, 200, {
    ok: true, provider, domain: data.ldhName || domain,
    owner: {
      name: (regt && (getVcard(regt, 'fn') || getVcard(regt, 'org'))) || 'Privado / Redigido (LGPD/GDPR)',
      document: (regt && ((regt.publicIds && regt.publicIds[0] && regt.publicIds[0].identifier) || regt.handle)) || '-',
      email: (regt && getVcard(regt, 'email')) || '-'
    },
    registrar: (regr && (getVcard(regr, 'fn') || regr.handle)) || '-',
    status: data.status || [],
    events: { registration: events.registration || null, lastChanged: events['last changed'] || null, expiration: events.expiration || null },
    nameservers: (data.nameservers || []).map((n) => n.ldhName).filter(Boolean),
    dnssec: Boolean(data.secureDNS && data.secureDNS.delegationSigned)
  }, 300);
}

async function handleSubdomains(req, res) {
  const domain = sanitizeDomain(req.query.domain);
  if (!domain) return sendJson(res, 400, { ok: false, error: 'Dominio invalido.' });
  try {
    const r = await fetchWithTimeout(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { headers: { Accept: 'application/json' } }, 11000);
    if (!r.ok) return sendJson(res, 502, { ok: false, error: `crt.sh retornou HTTP ${r.status}.` });
    const rows = await r.json();
    const map = new Map();
    for (const row of (Array.isArray(rows) ? rows : [])) {
      for (const raw of String(row.name_value || '').split(/\r?\n/)) {
        const sub = raw.trim().toLowerCase().replace(/^\*\./, '');
        if (!sub || (!sub.endsWith(`.${domain}`) && sub !== domain)) continue;
        if (!map.has(sub)) map.set(sub, { host: sub, notBefore: row.not_before || null, notAfter: row.not_after || null });
      }
    }
    const subdomains = [...map.values()].sort((a, b) => a.host.localeCompare(b.host));
    return sendJson(res, 200, { ok: true, domain, total: subdomains.length, subdomains: subdomains.slice(0, 500) }, 300);
  } catch (e) {
    return sendJson(res, e.name === 'AbortError' ? 504 : 502, { ok: false, error: 'Timeout ou falha ao consultar crt.sh.' });
  }
}

async function handleIp(req, res) {
  let ip = String(req.query.target || '').trim();
  if (!ip) {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    ip = net.isIP(xff) && !isPrivateIp(xff) ? xff : '';
  } else if (!net.isIP(ip)) {
    const dom = sanitizeDomain(ip);
    if (!dom) return sendJson(res, 400, { ok: false, error: 'IP ou dominio invalido.' });
    try { ip = (await dns.lookup(dom, { family: 4 })).address; } catch {
      return sendJson(res, 404, { ok: false, error: 'Dominio nao resolveu para IPv4.' });
    }
  }
  if (ip && isPrivateIp(ip)) return sendJson(res, 400, { ok: false, error: 'IP privado nao possui geolocalizacao publica.' });

  const providers = [
    ['ipwho.is', async () => {
      const r = await fetchWithTimeout(`https://ipwho.is/${encodeURIComponent(ip)}`, {}, 7000);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      if (d.success === false) throw new Error(d.message || 'Erro ipwho.is');
      return {
        ip: d.ip, type: d.type, country: d.country, countryCode: d.country_code,
        region: d.region, city: d.city, postal: d.postal || '-',
        latitude: d.latitude, longitude: d.longitude,
        timezone: d.timezone ? d.timezone.id : '-',
        asn: d.connection ? `AS${d.connection.asn}` : '-',
        org: d.connection ? (d.connection.org || d.connection.isp) : '-'
      };
    }],
    ['ipapi.co', async () => {
      const r = await fetchWithTimeout(ip ? `https://ipapi.co/${encodeURIComponent(ip)}/json/` : 'https://ipapi.co/json/', {}, 7000);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      if (d.error) throw new Error(d.reason || 'Erro ipapi.co');
      return {
        ip: d.ip, type: d.version || '-', country: d.country_name || '-', countryCode: d.country_code || '-',
        region: d.region || '-', city: d.city || '-', postal: d.postal || '-',
        latitude: d.latitude, longitude: d.longitude,
        timezone: d.timezone || '-', asn: d.asn || '-', org: d.org || '-'
      };
    }]
  ];
  let lastErr = 'Falha ao consultar IP.';
  for (const [provider, run] of providers) {
    try { return sendJson(res, 200, { ok: true, provider, geo: await run() }, 300); } catch (e) { lastErr = e.message; }
  }
  return sendJson(res, 502, { ok: false, error: lastErr });
}

async function handleCnpj(req, res) {
  const clean = String(req.query.cnpj || '').replace(/\D/g, '');
  if (!isValidCnpj(clean)) return sendJson(res, 400, { ok: false, error: 'CNPJ invalido.' });

  const normBr = (d) => ({
    cnpj: d.cnpj || clean, razaoSocial: d.razao_social || '-', nomeFantasia: d.nome_fantasia || '-',
    situacao: d.descricao_situacao_cadastral || '-', dataAbertura: d.data_inicio_atividade || '-',
    porte: d.porte || '-', naturezaJuridica: d.natureza_juridica || '-',
    cnaePrincipal: d.cnae_fiscal_descricao || '-', capitalSocial: d.capital_social != null ? Number(d.capital_social) : null,
    telefone: d.ddd_telefone_1 || '-', email: d.email || '-',
    endereco: `${d.logradouro || ''}, ${d.numero || 'S/N'} - ${d.bairro || ''}`.replace(/\s+/g, ' ').trim(),
    cidadeUf: `${d.municipio || '-'} / ${d.uf || '-'}`, cep: d.cep || '-',
    socios: (d.qsa || []).map((s) => ({ nome: s.nome_socio || '-', qualificacao: s.qualificacao_socio || '-', entrada: s.data_entrada_sociedade || '-' }))
  });

  const providers = [
    ['BrasilAPI', async () => {
      const r = await fetchWithTimeout(`https://brasilapi.com.br/api/cnpj/v1/${clean}`, {}, 8000);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return normBr(await r.json());
    }],
    ['CNPJ.ws', async () => {
      const r = await fetchWithTimeout(`https://publica.cnpj.ws/cnpj/${clean}`, {}, 8000);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json(), est = d.estabelecimento || {};
      return {
        cnpj: clean, razaoSocial: d.razao_social || '-', nomeFantasia: est.nome_fantasia || '-',
        situacao: est.situacao_cadastral || '-', dataAbertura: est.data_inicio_atividade || '-',
        porte: d.porte ? d.porte.descricao : '-', naturezaJuridica: d.natureza_juridica ? d.natureza_juridica.descricao : '-',
        cnaePrincipal: est.atividade_principal ? est.atividade_principal.descricao : '-',
        capitalSocial: d.capital_social != null ? Number(d.capital_social) : null,
        telefone: est.telefone1 ? `(${est.ddd1 || ''}) ${est.telefone1}` : '-', email: est.email || '-',
        endereco: `${est.tipo_logradouro || ''} ${est.logradouro || ''}, ${est.numero || 'S/N'} - ${est.bairro || ''}`.trim(),
        cidadeUf: `${est.cidade ? est.cidade.nome : '-'} / ${est.estado ? est.estado.sigla : '-'}`, cep: est.cep || '-',
        socios: (d.socios || []).map((s) => ({ nome: s.nome || '-', qualificacao: s.qualificacao_socio ? s.qualificacao_socio.descricao : '-', entrada: s.data_entrada || '-' }))
      };
    }],
    ['MinhaReceita', async () => {
      const r = await fetchWithTimeout(`https://minhareceita.org/${clean}`, {}, 8000);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return normBr(await r.json());
    }]
  ];
  let lastErr = 'Bases CNPJ indisponiveis.';
  for (const [provider, run] of providers) {
    try { return sendJson(res, 200, { ok: true, provider, company: await run() }, 600); } catch (e) { lastErr = `${provider}: ${e.message}`; }
  }
  return sendJson(res, 502, { ok: false, error: lastErr });
}

async function handleSherlock(req, res) {
  const username = String(req.query.username || '').trim().replace(/^@/, '');
  if (!/^[a-zA-Z0-9._-]{2,40}$/.test(username)) {
    return sendJson(res, 400, { ok: false, error: 'Username invalido (2-40 caracteres).' });
  }
  const enc = encodeURIComponent(username);
  const targets = [
    ['GitHub', `https://github.com/${enc}`, async () => {
      const r = await fetchWithTimeout(`https://api.github.com/users/${enc}`, { headers: { Accept: 'application/vnd.github+json' } }, 5000);
      if (r.status === 404) return { status: 'not_found' };
      if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
      const d = await r.json();
      return { status: 'found', info: `${d.public_repos ?? 0} repos • ${d.followers ?? 0} seguidores` };
    }],
    ['GitLab', `https://gitlab.com/${enc}`, async () => {
      const r = await fetchWithTimeout(`https://gitlab.com/api/v4/users?username=${enc}`, {}, 5000);
      if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
      const a = await r.json();
      return a.length ? { status: 'found', info: a[0].name || 'Ativo' } : { status: 'not_found' };
    }],
    ['Reddit', `https://www.reddit.com/user/${enc}`, async () => {
      const r = await fetchWithTimeout(`https://www.reddit.com/user/${enc}/about.json`, {}, 5000);
      if (r.status === 404) return { status: 'not_found' };
      if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
      const d = await r.json();
      return d && d.data && d.data.name ? { status: 'found', info: `Karma: ${d.data.total_karma ?? 0}` } : { status: 'not_found' };
    }],
    ['Dev.to', `https://dev.to/${enc}`, async () => {
      const r = await fetchWithTimeout(`https://dev.to/api/users/by_username?url=${enc}`, {}, 5000);
      if (r.status === 404) return { status: 'not_found' };
      if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
      const d = await r.json();
      return { status: 'found', info: d.name || 'Perfil ativo' };
    }],
    ['Hacker News', `https://news.ycombinator.com/user?id=${enc}`, async () => {
      const r = await fetchWithTimeout(`https://hacker-news.firebaseio.com/v0/user/${enc}.json`, {}, 5000);
      if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
      const d = await r.json();
      return d ? { status: 'found', info: `Karma: ${d.karma ?? 0}` } : { status: 'not_found' };
    }],
    ['npm', `https://www.npmjs.com/~${enc}`, async () => {
      const r = await fetchWithTimeout(`https://registry.npmjs.org/-/v1/search?text=maintainer:${enc}&size=1`, {}, 5000);
      if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
      const d = await r.json();
      return d && d.total > 0 ? { status: 'found', info: `${d.total} pacote(s)` } : { status: 'not_found' };
    }],
    ['Chess.com', `https://www.chess.com/member/${enc}`, async () => {
      const r = await fetchWithTimeout(`https://api.chess.com/pub/player/${enc.toLowerCase()}`, {}, 5000);
      return r.status === 404 ? { status: 'not_found' } : r.ok ? { status: 'found', info: 'Jogador localizado' } : { status: 'error', info: `HTTP ${r.status}` };
    }],
    ['Lichess', `https://lichess.org/@/${enc}`, async () => {
      const r = await fetchWithTimeout(`https://lichess.org/api/user/${enc}`, {}, 5000);
      return r.status === 404 ? { status: 'not_found' } : r.ok ? { status: 'found', info: 'Jogador localizado' } : { status: 'error', info: `HTTP ${r.status}` };
    }],
    ['Codeforces', `https://codeforces.com/profile/${enc}`, async () => {
      const r = await fetchWithTimeout(`https://codeforces.com/api/user.info?handles=${enc}`, {}, 5000);
      if (r.status === 400) return { status: 'not_found' };
      if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
      const u = ((await r.json()).result || [])[0];
      return u ? { status: 'found', info: `Rating: ${u.rating ?? 'N/A'}` } : { status: 'not_found' };
    }],
    ['Scratch', `https://scratch.mit.edu/users/${enc}/`, async () => {
      const r = await fetchWithTimeout(`https://api.scratch.mit.edu/users/${enc}`, {}, 5000);
      return r.status === 404 ? { status: 'not_found' } : r.ok ? { status: 'found', info: 'Perfil ativo' } : { status: 'error', info: `HTTP ${r.status}` };
    }],
    ['Wikipedia (PT)', `https://pt.wikipedia.org/wiki/Usu%C3%A1rio:${enc}`, async () => {
      const r = await fetchWithTimeout(`https://pt.wikipedia.org/w/api.php?action=query&list=users&ususers=${enc}&usprop=editcount&format=json`, {}, 5000);
      if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
      const u = ((await r.json()).query?.users || [])[0];
      return u && !('missing' in u) ? { status: 'found', info: `${u.editcount ?? 0} edicoes` } : { status: 'not_found' };
    }]
  ];

  const settled = await Promise.allSettled(targets.map(async ([platform, url, fn]) => {
    const t0 = Date.now();
    try { return { platform, url, latencyMs: Date.now() - t0, ...(await fn()) }; } catch (e) {
      return { platform, url, latencyMs: Date.now() - t0, status: 'error', info: e.name === 'AbortError' ? 'Timeout' : 'Indisponivel' };
    }
  }));
  const results = settled.map((s) => s.status === 'fulfilled' ? s.value : { status: 'error', info: 'Falha' });
  return sendJson(res, 200, {
    ok: true, username, results,
    summary: {
      total: results.length,
      found: results.filter((r) => r.status === 'found').length,
      notFound: results.filter((r) => r.status === 'not_found').length,
      errors: results.filter((r) => r.status === 'error').length
    }
  }, 120);
}

async function handleBreach(req, res) {
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return sendJson(res, 400, { ok: false, error: 'E-mail invalido.' });
  const domain = email.split('@')[1];
  const [mx, txt, dmarc, xon] = await Promise.all([
    dns.resolveMx(domain).catch(() => []),
    dns.resolveTxt(domain).catch(() => []),
    dns.resolveTxt(`_dmarc.${domain}`).catch(() => []),
    (async () => {
      try {
        const r = await fetchWithTimeout(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`, {}, 8000);
        if (r.status === 404) return { ok: true, exposed: false, breaches: [] };
        if (!r.ok) return { ok: false, error: `HTTP ${r.status}` };
        const d = await r.json();
        const list = Array.isArray(d.breaches?.[0]) ? d.breaches[0] : (Array.isArray(d.breaches) ? d.breaches : []);
        return { ok: true, exposed: list.length > 0, breaches: list };
      } catch (e) { return { ok: false, error: e.message }; }
    })()
  ]);
  return sendJson(res, 200, {
    ok: true, email, domain, breachCheck: xon,
    mailHealth: {
      mxValid: mx.length > 0,
      mxServers: mx.sort((a, b) => a.priority - b.priority).map((m) => `${m.exchange} (prio ${m.priority})`),
      hasSpf: txt.map((c) => c.join('')).some((t) => t.toLowerCase().startsWith('v=spf1')),
      hasDmarc: dmarc.map((c) => c.join('')).some((t) => t.toLowerCase().startsWith('v=dmarc1'))
    }
  }, 120);
}

async function handleVirusTotal(req, res) {
  const vtKey = String(process.env.VT_API_KEY || req.headers['x-vt-key'] || '').trim();
  const type = String(req.query.type || '').toLowerCase();
  const target = String(req.query.target || '').trim();
  if (!vtKey) return sendJson(res, 503, { ok: false, error: 'Configure VT_API_KEY na Vercel ou informe sua chave no campo opcional.' });
  if (!target) return sendJson(res, 400, { ok: false, error: 'Informe um alvo.' });

  let ep = '';
  if (type === 'hash') {
    if (!/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(target)) return sendJson(res, 400, { ok: false, error: 'Hash MD5/SHA1/SHA256 invalido.' });
    ep = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(target)}`;
  } else if (type === 'domain') {
    const d = sanitizeDomain(target);
    if (!d) return sendJson(res, 400, { ok: false, error: 'Dominio invalido.' });
    ep = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(d)}`;
  } else if (type === 'ip') {
    if (!net.isIP(target) || isPrivateIp(target)) return sendJson(res, 400, { ok: false, error: 'IP publico invalido.' });
    ep = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(target)}`;
  } else if (type === 'url') {
    const norm = /^https?:\/\//i.test(target) ? target : `https://${target}`;
    ep = `https://www.virustotal.com/api/v3/urls/${Buffer.from(norm, 'utf8').toString('base64url')}`;
  } else {
    return sendJson(res, 400, { ok: false, error: 'Tipo invalido (hash, domain, ip, url).' });
  }

  try {
    const up = await fetchWithTimeout(ep, { headers: { 'x-apikey': vtKey, Accept: 'application/json' } }, 10000);
    if (up.status === 404) return sendJson(res, 200, { ok: true, found: false, message: 'Indicador nao encontrado na base VirusTotal.' }, 60);
    const body = await up.json();
    if (!up.ok) return sendJson(res, up.status, { ok: false, error: body?.error?.message || `VirusTotal HTTP ${up.status}` });
    const a = body?.data?.attributes || {};
    const st = a.last_analysis_stats || {};
    const detections = Object.entries(a.last_analysis_results || {})
      .filter(([, v]) => v && (v.category === 'malicious' || v.category === 'suspicious'))
      .map(([engine, v]) => ({ engine, category: v.category, result: v.result || 'Flagged' }))
      .slice(0, 30);
    return sendJson(res, 200, {
      ok: true, found: true, type, target,
      reputation: a.reputation ?? 0,
      stats: { malicious: st.malicious || 0, suspicious: st.suspicious || 0, harmless: st.harmless || 0, undetected: st.undetected || 0 },
      lastAnalysisDate: a.last_analysis_date ? new Date(a.last_analysis_date * 1000).toISOString() : null,
      meaningfulName: a.meaningful_name || a.title || a.as_owner || null,
      tags: a.tags || [],
      detections
    }, 180);
  } catch (e) {
    return sendJson(res, e.name === 'AbortError' ? 504 : 502, { ok: false, error: 'Erro ou timeout no VirusTotal.' });
  }
}

module.exports = async (req, res) => {
  setCommonHeaders(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return sendJson(res, 405, { ok: false, error: 'Use GET.' });
  const handlers = {
    dns: handleDns, rdap: handleRdap, subdomains: handleSubdomains, ip: handleIp,
    cnpj: handleCnpj, sherlock: handleSherlock, breach: handleBreach, virustotal: handleVirusTotal
  };
  const fn = handlers[String(req.query.action || '').toLowerCase()];
  if (!fn) return sendJson(res, 400, { ok: false, error: 'Acao invalida.' });
  return fn(req, res);
};
