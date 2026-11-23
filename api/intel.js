'use strict';

const dns = require('node:dns').promises;
const net = require('node:net');
const {
  isPrivateIp,
  fetchWithTimeout,
  setCommonHeaders,
  sendJson,
  sanitizeDomain
} = require('./_utils');

function isValidCnpj(cnpj) {
  const clean = String(cnpj || '').replace(/\D/g, '');
  if (clean.length !== 14 || /^(\d)\1{13}$/.test(clean)) return false;
  const calc = (base, weights) => {
    let sum = 0;
    for (let i = 0; i < weights.length; i++) sum += Number(base[i]) * weights[i];
    const rem = sum % 11;
    return rem < 2 ? 0 : 11 - rem;
  };
  const d1 = calc(clean.slice(0, 12), [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  const d2 = calc(clean.slice(0, 13), [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  return d1 === Number(clean[12]) && d2 === Number(clean[13]);
}

async function handleDns(req, res) {
  const domain = sanitizeDomain(req.query.domain);
  if (!domain) return sendJson(res, 400, { ok: false, error: 'Dominio invalido.' });

  const safeResolve = async (fn) => {
    try { return await fn(); } catch { return []; }
  };

  const [A, AAAA, MX, NS, TXT, CNAME, SOA, DMARC] = await Promise.all([
    safeResolve(() => dns.resolve4(domain)),
    safeResolve(() => dns.resolve6(domain)),
    safeResolve(() => dns.resolveMx(domain)),
    safeResolve(() => dns.resolveNs(domain)),
    safeResolve(() => dns.resolveTxt(domain)),
    safeResolve(() => dns.resolveCname(domain)),
    safeResolve(() => dns.resolveSoa(domain).then((r) => r || null)),
    safeResolve(() => dns.resolveTxt(`_dmarc.${domain}`))
  ]);

  const flatTxt = TXT.map((chunks) => chunks.join(''));
  const flatDmarc = DMARC.map((chunks) => chunks.join(''));
  const spfRecord = flatTxt.find((t) => t.toLowerCase().startsWith('v=spf1')) || null;
  const dmarcRecord = flatDmarc.find((t) => t.toLowerCase().startsWith('v=dmarc1')) || null;

  return sendJson(res, 200, {
    ok: true,
    domain,
    records: {
      A,
      AAAA,
      MX: MX.sort((a, b) => a.priority - b.priority),
      NS,
      CNAME,
      TXT: flatTxt,
      SOA: Array.isArray(SOA) ? null : SOA
    },
    emailSecurity: {
      hasSpf: Boolean(spfRecord),
      spf: spfRecord,
      hasDmarc: Boolean(dmarcRecord),
      dmarc: dmarcRecord
    }
  }, 120);
}

function extractVcard(entity, field) {
  const arr = entity && entity.vcardArray && entity.vcardArray[1];
  if (!Array.isArray(arr)) return null;
  const row = arr.find((r) => Array.isArray(r) && r[0] === field);
  if (!row) return null;
  return Array.isArray(row[3]) ? row[3].filter(Boolean).join(' ') : String(row[3] || '');
}

async function handleRdap(req, res) {
  const domain = sanitizeDomain(req.query.domain);
  if (!domain) return sendJson(res, 400, { ok: false, error: 'Dominio invalido.' });

  const endpoints = [];
  if (domain.endsWith('.br')) {
    endpoints.push({ name: 'Registro.br RDAP', url: `https://rdap.registro.br/domain/${encodeURIComponent(domain)}` });
  } else if (domain.endsWith('.com') || domain.endsWith('.net')) {
    endpoints.push({ name: 'Verisign RDAP', url: `https://rdap.verisign.com/${domain.endsWith('.com') ? 'com' : 'net'}/v1/domain/${encodeURIComponent(domain)}` });
  }
  endpoints.push({ name: 'RDAP.org Bootstrap', url: `https://rdap.org/domain/${encodeURIComponent(domain)}` });

  let data = null;
  let provider = null;
  let lastErr = 'RDAP indisponivel';

  for (const ep of endpoints) {
    try {
      const r = await fetchWithTimeout(ep.url, { headers: { Accept: 'application/rdap+json, application/json' } }, 8000);
      if (r.ok) {
        data = await r.json();
        provider = ep.name;
        break;
      }
      lastErr = `HTTP ${r.status} em ${ep.name}`;
    } catch (err) {
      lastErr = err.message;
    }
  }

  if (!data) {
    return sendJson(res, 502, { ok: false, error: `Falha na consulta RDAP (${lastErr}).` });
  }

  const entities = Array.isArray(data.entities) ? data.entities : [];
  const registrant = entities.find((e) => Array.isArray(e.roles) && e.roles.includes('registrant'))
    || entities.find((e) => Array.isArray(e.roles) && e.roles.includes('administrative'));
  const registrar = entities.find((e) => Array.isArray(e.roles) && e.roles.includes('registrar'));

  const events = {};
  for (const ev of (data.events || [])) {
    if (ev.eventAction && ev.eventDate) events[ev.eventAction] = ev.eventDate;
  }

  const ownerName = (registrant && (extractVcard(registrant, 'fn') || extractVcard(registrant, 'org'))) || 'Privado / Redigido (LGPD/GDPR)';
  const ownerDoc = (registrant && ((registrant.publicIds && registrant.publicIds[0] && registrant.publicIds[0].identifier) || registrant.handle)) || '-';
  const ownerEmail = (registrant && extractVcard(registrant, 'email')) || '-';
  const registrarName = (registrar && (extractVcard(registrar, 'fn') || registrar.handle)) || '-';
  const nameservers = (data.nameservers || []).map((n) => n.ldhName).filter(Boolean);

  return sendJson(res, 200, {
    ok: true,
    provider,
    domain: data.ldhName || domain,
    owner: {
      name: ownerName,
      document: ownerDoc,
      email: ownerEmail
    },
    registrar: registrarName,
    status: data.status || [],
    events: {
      registration: events.registration || null,
      lastChanged: events['last changed'] || null,
      expiration: events.expiration || null
    },
    nameservers,
    dnssec: Boolean(data.secureDNS && data.secureDNS.delegationSigned)
  }, 300);
}

async function handleSubdomains(req, res) {
  const domain = sanitizeDomain(req.query.domain);
  if (!domain) return sendJson(res, 400, { ok: false, error: 'Dominio invalido.' });

  // Provider 1: crt.sh
  try {
    const r = await fetchWithTimeout(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { headers: { Accept: 'application/json' } },
      9500
    );
    if (r.ok) {
      const rows = await r.json();
      const set = new Map();
      for (const row of (Array.isArray(rows) ? rows : [])) {
        const names = String(row.name_value || '').split(/?
/);
        for (const raw of names) {
          const sub = raw.trim().toLowerCase().replace(/^\*\./, '');
          if (!sub || (!sub.endsWith(`.${domain}`) && sub !== domain)) continue;
          if (!set.has(sub)) {
            set.set(sub, {
              host: sub,
              issuer: row.issuer_name ? String(row.issuer_name).slice(0, 90) : '-',
              notBefore: row.not_before || null,
              notAfter: row.not_after || null
            });
          }
        }
      }
      if (set.size > 0) {
        const subdomains = [...set.values()].sort((a, b) => a.host.localeCompare(b.host));
        return sendJson(res, 200, {
          ok: true,
          provider: 'crt.sh (CT Logs)',
          domain,
          total: subdomains.length,
          subdomains: subdomains.slice(0, 500)
        }, 300);
      }
    }
  } catch {}

  // Provider 2: HackerTarget fallback
  try {
    const r = await fetchWithTimeout(
      `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`,
      {},
      8500
    );
    if (r.ok) {
      const txt = await r.text();
      if (txt && !/error|API count exceeded/i.test(txt)) {
        const set = new Map();
        for (const line of txt.split(/?
/)) {
          const parts = line.trim().split(',');
          const host = (parts[0] || '').trim().toLowerCase();
          const ip = (parts[1] || '').trim();
          if (host && (host.endsWith(`.${domain}`) || host === domain) && !set.has(host)) {
            set.set(host, { host, issuer: ip ? `IP: ${ip}` : 'HackerTarget', notBefore: null, notAfter: null });
          }
        }
        const subdomains = [...set.values()].sort((a, b) => a.host.localeCompare(b.host));
        return sendJson(res, 200, {
          ok: true,
          provider: 'HackerTarget (Fallback)',
          domain,
          total: subdomains.length,
          subdomains: subdomains.slice(0, 500)
        }, 300);
      }
    }
  } catch {}

  return sendJson(res, 502, {
    ok: false,
    error: 'crt.sh e HackerTarget nao responderam no momento. Tente novamente em alguns segundos.'
  });
}

async function handleIp(req, res) {
  const raw = String(req.query.target || '').trim();
  let ip = raw;

  if (!ip) {
    // Retorna IP do servidor/proxy ou do visitante conforme x-forwarded-for
    const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    ip = net.isIP(xff) && !isPrivateIp(xff) ? xff : '';
  } else if (!net.isIP(ip)) {
    // Permite informar um dominio e resolve para IP automaticamente
    const dom = sanitizeDomain(ip);
    if (!dom) return sendJson(res, 400, { ok: false, error: 'Informe um IP ou dominio valido.' });
    try {
      const resolved = await dns.lookup(dom, { family: 4 });
      ip = resolved.address;
    } catch {
      return sendJson(res, 404, { ok: false, error: 'Nao foi possivel resolver o dominio para um IP.' });
    }
  }

  if (ip && isPrivateIp(ip)) {
    return sendJson(res, 400, { ok: false, error: 'IP privado/local nao possui geolocalizacao publica.' });
  }

  const providers = [
    {
      name: 'ipwho.is',
      run: async () => {
        const r = await fetchWithTimeout(`https://ipwho.is/${encodeURIComponent(ip)}`, {}, 7000);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        if (d.success === false) throw new Error(d.message || 'Falha ipwho.is');
        return {
          ip: d.ip,
          type: d.type,
          continent: d.continent,
          country: d.country,
          countryCode: d.country_code,
          region: d.region,
          city: d.city,
          postal: d.postal || '-',
          latitude: d.latitude,
          longitude: d.longitude,
          timezone: d.timezone ? d.timezone.id : '-',
          asn: d.connection ? `AS${d.connection.asn}` : '-',
          org: d.connection ? (d.connection.org || d.connection.isp) : '-',
          isp: d.connection ? d.connection.isp : '-',
          domain: d.connection ? (d.connection.domain || '-') : '-'
        };
      }
    },
    {
      name: 'ipapi.co',
      run: async () => {
        const url = ip ? `https://ipapi.co/${encodeURIComponent(ip)}/json/` : 'https://ipapi.co/json/';
        const r = await fetchWithTimeout(url, {}, 7000);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        if (d.error) throw new Error(d.reason || 'Falha ipapi.co');
        return {
          ip: d.ip,
          type: d.version || '-',
          continent: d.continent_code || '-',
          country: d.country_name || '-',
          countryCode: d.country_code || '-',
          region: d.region || '-',
          city: d.city || '-',
          postal: d.postal || '-',
          latitude: d.latitude,
          longitude: d.longitude,
          timezone: d.timezone || '-',
          asn: d.asn || '-',
          org: d.org || '-',
          isp: d.org || '-',
          domain: '-'
        };
      }
    }
  ];

  let lastErr = 'Erro ao consultar geolocalizacao.';
  for (const p of providers) {
    try {
      const geo = await p.run();
      return sendJson(res, 200, { ok: true, provider: p.name, geo }, 300);
    } catch (err) {
      lastErr = err.message;
    }
  }
  return sendJson(res, 502, { ok: false, error: lastErr });
}

async function handleCnpj(req, res) {
  const clean = String(req.query.cnpj || '').replace(/\D/g, '');
  if (!isValidCnpj(clean)) {
    return sendJson(res, 400, { ok: false, error: 'CNPJ invalido (digitos verificadores incorretos ou formato invalido).' });
  }

  const providers = [
    {
      name: 'BrasilAPI',
      run: async () => {
        const r = await fetchWithTimeout(`https://brasilapi.com.br/api/cnpj/v1/${clean}`, {}, 8000);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        return {
          cnpj: d.cnpj || clean,
          razaoSocial: d.razao_social || '-',
          nomeFantasia: d.nome_fantasia || '-',
          situacao: d.descricao_situacao_cadastral || '-',
          dataAbertura: d.data_inicio_atividade || '-',
          porte: d.porte || '-',
          naturezaJuridica: d.natureza_juridica || '-',
          cnaePrincipal: d.cnae_fiscal_descricao || '-',
          capitalSocial: d.capital_social != null ? Number(d.capital_social) : null,
          telefone: d.ddd_telefone_1 || '-',
          email: d.email || '-',
          endereco: `${d.logradouro || ''}, ${d.numero || 'S/N'} ${d.complemento || ''} - ${d.bairro || ''}`.replace(/\s+/g, ' ').trim(),
          cidadeUf: `${d.municipio || '-'} / ${d.uf || '-'}`,
          cep: d.cep || '-',
          socios: (d.qsa || []).map((s) => ({
            nome: s.nome_socio || '-',
            qualificacao: s.qualificacao_socio || '-',
            entrada: s.data_entrada_sociedade || '-'
          }))
        };
      }
    },
    {
      name: 'CNPJ.ws',
      run: async () => {
        const r = await fetchWithTimeout(`https://publica.cnpj.ws/cnpj/${clean}`, {}, 8000);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        const est = d.estabelecimento || {};
        return {
          cnpj: clean,
          razaoSocial: d.razao_social || '-',
          nomeFantasia: est.nome_fantasia || '-',
          situacao: est.situacao_cadastral || '-',
          dataAbertura: est.data_inicio_atividade || '-',
          porte: d.porte ? d.porte.descricao : '-',
          naturezaJuridica: d.natureza_juridica ? d.natureza_juridica.descricao : '-',
          cnaePrincipal: est.atividade_principal ? est.atividade_principal.descricao : '-',
          capitalSocial: d.capital_social != null ? Number(d.capital_social) : null,
          telefone: est.telefone1 ? `(${est.ddd1 || ''}) ${est.telefone1}` : '-',
          email: est.email || '-',
          endereco: `${est.tipo_logradouro || ''} ${est.logradouro || ''}, ${est.numero || 'S/N'} - ${est.bairro || ''}`.replace(/\s+/g, ' ').trim(),
          cidadeUf: `${est.cidade ? est.cidade.nome : '-'} / ${est.estado ? est.estado.sigla : '-'}`,
          cep: est.cep || '-',
          socios: (d.socios || []).map((s) => ({
            nome: s.nome || '-',
            qualificacao: s.qualificacao_socio ? s.qualificacao_socio.descricao : '-',
            entrada: s.data_entrada || '-'
          }))
        };
      }
    },
    {
      name: 'MinhaReceita',
      run: async () => {
        const r = await fetchWithTimeout(`https://minhareceita.org/${clean}`, {}, 8000);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        return {
          cnpj: d.cnpj || clean,
          razaoSocial: d.razao_social || '-',
          nomeFantasia: d.nome_fantasia || '-',
          situacao: d.descricao_situacao_cadastral || '-',
          dataAbertura: d.data_inicio_atividade || '-',
          porte: d.porte || '-',
          naturezaJuridica: d.natureza_juridica || '-',
          cnaePrincipal: d.cnae_fiscal_descricao || '-',
          capitalSocial: d.capital_social != null ? Number(d.capital_social) : null,
          telefone: d.ddd_telefone_1 || '-',
          email: d.email || '-',
          endereco: `${d.logradouro || ''}, ${d.numero || 'S/N'} - ${d.bairro || ''}`.replace(/\s+/g, ' ').trim(),
          cidadeUf: `${d.municipio || '-'} / ${d.uf || '-'}`,
          cep: d.cep || '-',
          socios: (d.qsa || []).map((s) => ({
            nome: s.nome_socio || '-',
            qualificacao: s.qualificacao_socio || '-',
            entrada: s.data_entrada_sociedade || '-'
          }))
        };
      }
    }
  ];

  let lastErr = 'Todas as bases de CNPJ falharam.';
  for (const p of providers) {
    try {
      const company = await p.run();
      return sendJson(res, 200, { ok: true, provider: p.name, company }, 600);
    } catch (err) {
      lastErr = `${p.name}: ${err.message}`;
    }
  }
  return sendJson(res, 502, { ok: false, error: lastErr });
}

async function handleSherlock(req, res) {
  const username = String(req.query.username || '').trim().replace(/^@/, '');
  if (!username || !/^[a-zA-Z0-9._-]{2,40}$/.test(username)) {
    return sendJson(res, 400, { ok: false, error: 'Username invalido (use 2-40 caracteres: letras, numeros, ., _, -).' });
  }

  const enc = encodeURIComponent(username);
  const platforms = [
    {
      name: 'GitHub',
      url: `https://github.com/${enc}`,
      check: async () => {
        const r = await fetchWithTimeout(`https://api.github.com/users/${enc}`, { headers: { Accept: 'application/vnd.github+json' } }, 5000);
        if (r.status === 404) return { status: 'not_found' };
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        const d = await r.json();
        return { status: 'found', info: `${d.public_repos ?? 0} repos • ${d.followers ?? 0} seguidores` };
      }
    },
    {
      name: 'GitLab',
      url: `https://gitlab.com/${enc}`,
      check: async () => {
        const r = await fetchWithTimeout(`https://gitlab.com/api/v4/users?username=${enc}`, {}, 5000);
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        const arr = await r.json();
        return Array.isArray(arr) && arr.length > 0
          ? { status: 'found', info: arr[0].name || 'Conta ativa' }
          : { status: 'not_found' };
      }
    },
    {
      name: 'Reddit',
      url: `https://www.reddit.com/user/${enc}`,
      check: async () => {
        const r = await fetchWithTimeout(`https://www.reddit.com/user/${enc}/about.json`, {}, 5000);
        if (r.status === 404) return { status: 'not_found' };
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        const d = await r.json();
        return d && d.data && d.data.name
          ? { status: 'found', info: `Karma: ${d.data.total_karma ?? 0}` }
          : { status: 'not_found' };
      }
    },
    {
      name: 'Dev.to',
      url: `https://dev.to/${enc}`,
      check: async () => {
        const r = await fetchWithTimeout(`https://dev.to/api/users/by_username?url=${enc}`, {}, 5000);
        if (r.status === 404) return { status: 'not_found' };
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        const d = await r.json();
        return { status: 'found', info: d.name || 'Perfil ativo' };
      }
    },
    {
      name: 'Hacker News',
      url: `https://news.ycombinator.com/user?id=${enc}`,
      check: async () => {
        const r = await fetchWithTimeout(`https://hacker-news.firebaseio.com/v0/user/${enc}.json`, {}, 5000);
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        const d = await r.json();
        return d ? { status: 'found', info: `Karma: ${d.karma ?? 0}` } : { status: 'not_found' };
      }
    },
    {
      name: 'npm',
      url: `https://www.npmjs.com/~${enc}`,
      check: async () => {
        const r = await fetchWithTimeout(`https://registry.npmjs.org/-/v1/search?text=maintainer:${enc}&size=1`, {}, 5000);
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        const d = await r.json();
        return d && d.total > 0 ? { status: 'found', info: `${d.total} pacote(s)` } : { status: 'not_found' };
      }
    },
    {
      name: 'PyPI',
      url: `https://pypi.org/user/${enc}/`,
      check: async () => {
        const r = await fetchWithTimeout(`https://pypi.org/user/${enc}/`, {}, 5000);
        if (r.status === 404) return { status: 'not_found' };
        if (r.ok) return { status: 'found', info: 'Perfil encontrado' };
        return { status: 'error', info: `HTTP ${r.status}` };
      }
    },
    {
      name: 'Chess.com',
      url: `https://www.chess.com/member/${enc}`,
      check: async () => {
        const r = await fetchWithTimeout(`https://api.chess.com/pub/player/${enc.toLowerCase()}`, {}, 5000);
        if (r.status === 404) return { status: 'not_found' };
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        const d = await r.json();
        return { status: 'found', info: d.status || 'Jogador localizado' };
      }
    },
    {
      name: 'Lichess',
      url: `https://lichess.org/@/${enc}`,
      check: async () => {
        const r = await fetchWithTimeout(`https://lichess.org/api/user/${enc}`, {}, 5000);
        if (r.status === 404) return { status: 'not_found' };
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        return { status: 'found', info: 'Jogador localizado' };
      }
    },
    {
      name: 'Codeforces',
      url: `https://codeforces.com/profile/${enc}`,
      check: async () => {
        const r = await fetchWithTimeout(`https://codeforces.com/api/user.info?handles=${enc}`, {}, 5000);
        if (r.status === 400) return { status: 'not_found' };
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        const d = await r.json();
        const u = d && d.result && d.result[0];
        return u ? { status: 'found', info: `Rating: ${u.rating ?? 'N/A'}` } : { status: 'not_found' };
      }
    },
    {
      name: 'Scratch',
      url: `https://scratch.mit.edu/users/${enc}/`,
      check: async () => {
        const r = await fetchWithTimeout(`https://api.scratch.mit.edu/users/${enc}`, {}, 5000);
        if (r.status === 404) return { status: 'not_found' };
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        return { status: 'found', info: 'Perfil localizado' };
      }
    },
    {
      name: 'Wikipedia (PT)',
      url: `https://pt.wikipedia.org/wiki/Usu%C3%A1rio:${enc}`,
      check: async () => {
        const r = await fetchWithTimeout(`https://pt.wikipedia.org/w/api.php?action=query&list=users&ususers=${enc}&usprop=editcount&format=json`, {}, 5000);
        if (!r.ok) return { status: 'error', info: `HTTP ${r.status}` };
        const d = await r.json();
        const u = d && d.query && d.query.users && d.query.users[0];
        return u && !('missing' in u)
          ? { status: 'found', info: `${u.editcount ?? 0} edicoes` }
          : { status: 'not_found' };
      }
    }
  ];

  const settled = await Promise.allSettled(
    platforms.map(async (p) => {
      const t0 = Date.now();
      try {
        const out = await p.check();
        return { platform: p.name, url: p.url, latencyMs: Date.now() - t0, ...out };
      } catch (err) {
        return {
          platform: p.name,
          url: p.url,
          latencyMs: Date.now() - t0,
          status: 'error',
          info: err && err.name === 'AbortError' ? 'Timeout' : 'Indisponivel'
        };
      }
    })
  );

  const results = settled.map((s) => s.status === 'fulfilled' ? s.value : { status: 'error', info: 'Erro interno' });
  const summary = {
    total: results.length,
    found: results.filter((r) => r.status === 'found').length,
    notFound: results.filter((r) => r.status === 'not_found').length,
    errors: results.filter((r) => r.status === 'error').length
  };

  return sendJson(res, 200, { ok: true, username, summary, results }, 120);
}

async function handleBreach(req, res) {
  const email = String(req.query.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return sendJson(res, 400, { ok: false, error: 'Informe um e-mail valido.' });
  }
  const domain = email.split('@')[1];

  const [mxRecords, txtRecords, dmarcRecords, xonResult] = await Promise.all([
    dns.resolveMx(domain).catch(() => []),
    dns.resolveTxt(domain).catch(() => []),
    dns.resolveTxt(`_dmarc.${domain}`).catch(() => []),
    (async () => {
      try {
        const r = await fetchWithTimeout(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`, {}, 8000);
        if (r.status === 404) return { ok: true, exposed: false, breaches: [], source: 'XposedOrNot' };
        if (!r.ok) return { ok: false, error: `HTTP ${r.status}`, source: 'XposedOrNot' };
        const d = await r.json();
        const rawList = Array.isArray(d.breaches && d.breaches[0]) ? d.breaches[0] : (Array.isArray(d.breaches) ? d.breaches : []);
        return { ok: true, exposed: rawList.length > 0, breaches: rawList, source: 'XposedOrNot' };
      } catch (err) {
        return { ok: false, error: err.message, source: 'XposedOrNot' };
      }
    })()
  ]);

  const flatTxt = txtRecords.map((c) => c.join(''));
  const flatDmarc = dmarcRecords.map((c) => c.join(''));

  return sendJson(res, 200, {
    ok: true,
    email,
    domain,
    breachCheck: xonResult,
    mailHealth: {
      mxValid: mxRecords.length > 0,
      mxServers: mxRecords.sort((a, b) => a.priority - b.priority).map((m) => `${m.exchange} (prio ${m.priority})`),
      hasSpf: flatTxt.some((t) => t.toLowerCase().startsWith('v=spf1')),
      hasDmarc: flatDmarc.some((t) => t.toLowerCase().startsWith('v=dmarc1'))
    }
  }, 120);
}

async function handleVirusTotal(req, res) {
  const vtKey = String(process.env.VT_API_KEY || '').trim();
  const type = String(req.query.type || '').toLowerCase();
  const target = String(req.query.target || '').trim();

  if (!target) {
    return sendJson(res, 400, { ok: false, error: 'Informe um alvo (Hash, Dominio, IP ou URL).' });
  }

  let vtEndpoint = '';
  let otxEndpoint = '';
  let guiUrl = '';
  let cleanTarget = target;

  if (type === 'hash' || type === 'file') {
    if (!/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(target)) {
      return sendJson(res, 400, { ok: false, error: 'Hash invalido. Use MD5 (32), SHA-1 (40) ou SHA-256 (64).' });
    }
    cleanTarget = target.toLowerCase();
    vtEndpoint = `https://www.virustotal.com/api/v3/files/${encodeURIComponent(cleanTarget)}`;
    otxEndpoint = `https://otx.alienvault.com/api/v1/indicators/file/${encodeURIComponent(cleanTarget)}/general`;
    guiUrl = `https://www.virustotal.com/gui/file/${encodeURIComponent(cleanTarget)}`;
  } else if (type === 'domain') {
    const dom = sanitizeDomain(target);
    if (!dom) return sendJson(res, 400, { ok: false, error: 'Dominio invalido.' });
    cleanTarget = dom;
    vtEndpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(dom)}`;
    otxEndpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(dom)}/general`;
    guiUrl = `https://www.virustotal.com/gui/domain/${encodeURIComponent(dom)}`;
  } else if (type === 'ip') {
    if (!net.isIP(target) || isPrivateIp(target)) {
      return sendJson(res, 400, { ok: false, error: 'Informe um IP publico valido.' });
    }
    vtEndpoint = `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(target)}`;
    otxEndpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(target)}/general`;
    guiUrl = `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(target)}`;
  } else if (type === 'url') {
    const normalized = /^https?:\/\//i.test(target) ? target : `https://${target}`;
    cleanTarget = normalized;
    const urlId = Buffer.from(normalized, 'utf8').toString('base64url');
    vtEndpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;
    otxEndpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(normalized)}/general`;
    guiUrl = `https://www.virustotal.com/gui/url/${urlId}`;
  } else {
    return sendJson(res, 400, { ok: false, error: 'Tipo invalido. Use hash, domain, ip ou url.' });
  }

  let vtNotice = null;
  if (vtKey) {
    try {
      const upstream = await fetchWithTimeout(vtEndpoint, {
        headers: { 'x-apikey': vtKey, Accept: 'application/json' }
      }, 9500);

      if (upstream.status === 404) {
        return sendJson(res, 200, {
          ok: true,
          provider: 'VirusTotal API v3',
          found: false,
          type,
          target: cleanTarget,
          guiUrl,
          message: 'Nenhum registro encontrado na base do VirusTotal para este indicador.'
        }, 60);
      }

      const body = await upstream.json().catch(() => ({}));
      if (upstream.ok) {
        const attrs = (body && body.data && body.data.attributes) || {};
        const stats = attrs.last_analysis_stats || {};
        const resultsMap = attrs.last_analysis_results || {};
        const detections = Object.entries(resultsMap)
          .filter(([, v]) => v && (v.category === 'malicious' || v.category === 'suspicious'))
          .map(([engine, v]) => ({ engine, category: v.category, result: v.result || 'Flagged' }))
          .slice(0, 30);

        return sendJson(res, 200, {
          ok: true,
          provider: 'VirusTotal API v3',
          found: true,
          type,
          target: cleanTarget,
          guiUrl,
          reputation: attrs.reputation ?? 0,
          stats: {
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0
          },
          lastAnalysisDate: attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
          tags: attrs.tags || [],
          meaningfulName: attrs.meaningful_name || attrs.title || attrs.as_owner || null,
          detections
        }, 180);
      }
      vtNotice = (body && body.error && body.error.message) || `VirusTotal HTTP ${upstream.status}`;
    } catch (err) {
      vtNotice = err && err.name === 'AbortError' ? 'Timeout no VirusTotal' : 'Falha de rede no VirusTotal';
    }
  } else {
    vtNotice = 'VT_API_KEY nao configurada na Vercel (usando fallback publico AlienVault OTX).';
  }

  // Fallback publico: AlienVault OTX (nao exige API Key)
  try {
    const r = await fetchWithTimeout(otxEndpoint, { headers: { Accept: 'application/json' } }, 8500);
    if (!r.ok) throw new Error(`OTX HTTP ${r.status}`);
    const otx = await r.json();
    const pulseCount = (otx && otx.pulse_info && otx.pulse_info.count) || 0;
    const pulses = ((otx && otx.pulse_info && otx.pulse_info.pulses) || []).slice(0, 20).map((p) => p.name);
    return sendJson(res, 200, {
      ok: true,
      provider: 'AlienVault OTX (Fallback)',
      fallback: true,
      vtNotice,
      found: true,
      type,
      target: cleanTarget,
      guiUrl,
      pulseCount,
      pulses,
      country: otx.country_name || '-',
      asn: otx.asn || '-'
    }, 180);
  } catch (err) {
    return sendJson(res, 502, {
      ok: false,
      error: `${vtNotice || 'Falha no VirusTotal'} | Fallback OTX indisponivel (${err.message}).`
    });
  }
}

async function handleVpnDetect(req, res) {
  let ip = String(req.query.target || '').trim();
  if (!ip) {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    ip = net.isIP(xff) && !isPrivateIp(xff) ? xff : '';
  } else if (!net.isIP(ip)) {
    const dom = sanitizeDomain(ip);
    if (!dom) return sendJson(res, 400, { ok: false, error: 'Informe um IP ou dominio valido.' });
    try { ip = (await dns.lookup(dom, { family: 4 })).address; } catch {
      return sendJson(res, 404, { ok: false, error: 'Dominio nao resolveu para IPv4.' });
    }
  }
  if (ip && isPrivateIp(ip)) {
    return sendJson(res, 400, { ok: false, error: 'IP privado nao pode ser auditado em bases publicas.' });
  }

  const providers = [
    {
      name: 'ipapi.is',
      run: async () => {
        const url = ip ? `https://api.ipapi.is?q=${encodeURIComponent(ip)}` : 'https://api.ipapi.is';
        const r = await fetchWithTimeout(url, {}, 8500);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        if (d.error) throw new Error(d.error);
        const flags = {
          vpn: Boolean(d.is_vpn),
          proxy: Boolean(d.is_proxy),
          tor: Boolean(d.is_tor),
          datacenter: Boolean(d.is_datacenter),
          abuser: Boolean(d.is_abuser)
        };
        const score = Math.min(100, (flags.tor ? 45 : 0) + (flags.vpn ? 35 : 0) + (flags.proxy ? 35 : 0) + (flags.datacenter ? 20 : 0) + (flags.abuser ? 25 : 0));
        return {
          ip: d.ip || ip,
          flags,
          score,
          vpnService: (d.vpn && d.vpn.service) || (d.datacenter && d.datacenter.datacenter) || '-',
          org: (d.company && d.company.name) || (d.asn && d.asn.org) || '-',
          asn: d.asn && d.asn.asn ? `AS${d.asn.asn}` : '-',
          country: (d.location && d.location.country) || '-',
          city: (d.location && d.location.city) || '-',
          latitude: d.location ? d.location.latitude : null,
          longitude: d.location ? d.location.longitude : null
        };
      }
    },
    {
      name: 'ProxyCheck.io v2',
      run: async () => {
        if (!ip) throw new Error('Informe um IP para consultar ProxyCheck.');
        const r = await fetchWithTimeout(`https://proxycheck.io/v2/${encodeURIComponent(ip)}?vpn=1&asn=1`, {}, 8500);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        const info = d && d[ip];
        if (!info) throw new Error('Sem dados no ProxyCheck.');
        const isP = info.proxy === 'yes';
        const typ = String(info.type || '').toUpperCase();
        const flags = {
          vpn: isP && typ.includes('VPN'),
          proxy: isP && !typ.includes('VPN') && !typ.includes('TOR'),
          tor: typ.includes('TOR'),
          datacenter: typ.includes('HOSTING') || typ.includes('DCH'),
          abuser: false
        };
        const score = Math.min(100, (flags.tor ? 85 : 0) + (flags.vpn ? 70 : 0) + (flags.proxy ? 65 : 0) + (flags.datacenter ? 35 : 0));
        return {
          ip,
          flags,
          score,
          vpnService: (info.operator && info.operator.name) || info.type || '-',
          org: info.provider || '-',
          asn: info.asn || '-',
          country: info.country || '-',
          city: info.city || '-',
          latitude: info.latitude != null ? Number(info.latitude) : null,
          longitude: info.longitude != null ? Number(info.longitude) : null
        };
      }
    },
    {
      name: 'ip-api.com',
      run: async () => {
        const r = await fetchWithTimeout(
          `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,proxy,hosting,query`,
          {},
          7500
        );
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        if (d.status !== 'success') throw new Error(d.message || 'Falha ip-api');
        const flags = { vpn: false, proxy: Boolean(d.proxy), tor: false, datacenter: Boolean(d.hosting), abuser: false };
        return {
          ip: d.query || ip,
          flags,
          score: (flags.proxy ? 65 : 0) + (flags.datacenter ? 25 : 0),
          vpnService: flags.proxy ? 'Proxy / VPN detectado' : '-',
          org: d.isp || d.org || '-',
          asn: d.as || '-',
          country: d.country || '-',
          city: d.city || '-',
          latitude: d.lat ?? null,
          longitude: d.lon ?? null
        };
      }
    }
  ];

  let lastErr = 'Falha ao auditar IP.';
  for (const p of providers) {
    try {
      const report = await p.run();
      return sendJson(res, 200, { ok: true, provider: p.name, report }, 180);
    } catch (err) {
      lastErr = `${p.name}: ${err.message}`;
    }
  }
  return sendJson(res, 502, { ok: false, error: lastErr });
}

async function handleVpnGate(req, res) {
  const country = String(req.query.country || 'ALL').trim().toUpperCase().slice(0, 4);
  const endpoints = [
    { name: 'VPN Gate (HTTPS)', url: 'https://www.vpngate.net/api/iphone/' },
    { name: 'VPN Gate (HTTP Fallback)', url: 'http://www.vpngate.net/api/iphone/' }
  ];

  let csvText = null;
  let provider = null;
  let lastErr = 'VPN Gate indisponivel.';
  for (const ep of endpoints) {
    try {
      const r = await fetchWithTimeout(ep.url, {}, 11000);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      csvText = await r.text();
      provider = ep.name;
      break;
    } catch (err) {
      lastErr = err.message;
    }
  }
  if (!csvText) return sendJson(res, 502, { ok: false, error: lastErr });

  const lines = csvText.split(/\r?\n/).filter((l) => l && !l.startsWith('*') && !l.startsWith('#') && l.includes(','));
  const servers = [];
  for (const line of lines) {
    const cols = line.split(',');
    if (cols.length < 15) continue;
    const ovpnB64 = cols[cols.length - 1].trim();
    const ip = (cols[1] || '').trim();
    const countryShort = (cols[6] || '').trim().toUpperCase();
    if (!ip || !ovpnB64 || ovpnB64.length < 40) continue;
    if (country !== 'ALL' && countryShort !== country) continue;
    servers.push({
      host: (cols[0] || '-').trim(),
      ip,
      ping: cols[3] && cols[3] !== '-' ? `${cols[3]} ms` : '-',
      speedMbps: ((Number(cols[4]) || 0) / 1e6).toFixed(1),
      countryLong: (cols[5] || countryShort).trim(),
      countryShort,
      sessions: (cols[7] || '0').trim(),
      ovpnB64
    });
  }

  if (!servers.length) {
    return sendJson(res, 404, { ok: false, error: 'Nenhum servidor VPN ativo retornado para este filtro.' });
  }
  servers.sort((a, b) => Number(b.speedMbps) - Number(a.speedMbps));
  return sendJson(res, 200, { ok: true, provider, total: servers.length, servers: servers.slice(0, 40) }, 180);
}

async function handlePublicProxies(req, res) {
  const rawProto = String(req.query.protocol || 'http').toLowerCase();
  const proto = ['http', 'socks4', 'socks5'].includes(rawProto) ? rawProto : 'http';
  const rawCountry = String(req.query.country || 'all').trim();
  const ctry = rawCountry.toLowerCase() === 'all' ? 'all' : rawCountry.toUpperCase().slice(0, 2);

  const providers = [
    {
      name: 'ProxyScrape v4',
      run: async () => {
        const r = await fetchWithTimeout(
          `https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=${proto}&proxy_format=ipport&format=text&timeout=10000&country=${ctry}&limit=60`,
          {},
          9500
        );
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const text = await r.text();
        const unique = [...new Set(text.split(/\r?\n/).map((s) => (s.match(/(\d{1,3}(?:\.\d{1,3}){3}:\d{2,5})/) || [])[1]).filter(Boolean))].slice(0, 60);
        if (!unique.length) throw new Error('Sem proxies ativos para este filtro.');
        return unique.map((addr) => ({ addr, protocol: proto.toUpperCase(), country: ctry === 'all' ? 'Global' : ctry, latency: '-' }));
      }
    },
    {
      name: 'GeoNode API',
      run: async () => {
        const cParam = ctry !== 'all' ? `&country=${ctry}` : '';
        const r = await fetchWithTimeout(
          `https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc&protocols=${proto}${cParam}`,
          {},
          9500
        );
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const d = await r.json();
        const rows = (d && d.data) || [];
        if (!rows.length) throw new Error('GeoNode vazio.');
        return rows.map((row) => ({
          addr: `${row.ip}:${row.port}`,
          protocol: ((row.protocols && row.protocols[0]) || proto).toUpperCase(),
          country: row.country || '-',
          latency: row.latency ? `${Math.round(row.latency)} ms` : '-'
        }));
      }
    },
    {
      name: 'SpeedX GitHub Mirror',
      run: async () => {
        const r = await fetchWithTimeout(`https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/${proto}.txt`, {}, 9500);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const text = await r.text();
        const list = text.split(/\r?\n/).map((s) => s.trim()).filter((s) => /^\d{1,3}(\.\d{1,3}){3}:\d{2,5}$/.test(s)).slice(0, 60);
        if (!list.length) throw new Error('Lista vazia.');
        return list.map((addr) => ({ addr, protocol: proto.toUpperCase(), country: 'Global', latency: '-' }));
      }
    }
  ];

  let lastErr = 'Nenhuma lista de proxies respondeu.';
  for (const p of providers) {
    try {
      const proxies = await p.run();
      return sendJson(res, 200, { ok: true, provider: p.name, total: proxies.length, proxies }, 120);
    } catch (err) {
      lastErr = `${p.name}: ${err.message}`;
    }
  }
  return sendJson(res, 502, { ok: false, error: lastErr });
}

async function handleReverseGeo(req, res) {
  const lat = Number(req.query.lat);
  const lon = Number(req.query.lon);
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) {
    return sendJson(res, 400, { ok: false, error: 'Coordenadas invalidas.' });
  }
  try {
    const r = await fetchWithTimeout(
      `https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=${lat}&longitude=${lon}&localityLanguage=pt`,
      {},
      7000
    );
    if (r.ok) {
      const d = await r.json();
      const address = [d.locality, d.city, d.principalSubdivision, d.countryName].filter(Boolean).join(', ');
      if (address) return sendJson(res, 200, { ok: true, provider: 'BigDataCloud', address }, 600);
    }
  } catch {}
  return sendJson(res, 200, { ok: true, provider: 'Fallback', address: `${lat.toFixed(5)}, ${lon.toFixed(5)}` }, 60);
}

module.exports = async (req, res) => {
  setCommonHeaders(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') {
    return sendJson(res, 405, { ok: false, error: 'Metodo nao permitido.' });
  }

  const action = String(req.query.action || '').toLowerCase();
  switch (action) {
    case 'dns': return handleDns(req, res);
    case 'rdap': return handleRdap(req, res);
    case 'subdomains': return handleSubdomains(req, res);
    case 'ip': return handleIp(req, res);
    case 'cnpj': return handleCnpj(req, res);
    case 'sherlock': return handleSherlock(req, res);
    case 'breach': return handleBreach(req, res);
    case 'virustotal': return handleVirusTotal(req, res);
    case 'vpn_detect': return handleVpnDetect(req, res);
    case 'vpngate': return handleVpnGate(req, res);
    case 'proxies': return handlePublicProxies(req, res);
    case 'reverse_geo': return handleReverseGeo(req, res);
    default:
      return sendJson(res, 400, {
        ok: false,
        error: 'Acao invalida. Use: dns, rdap, subdomains, ip, cnpj, sherlock, breach ou virustotal.'
      });
  }
};
