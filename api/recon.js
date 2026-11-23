'use strict';

const dns = require('node:dns').promises;
const { applyCors, safeFetch, readLimitedBuffer } = require('./_lib/net');

function extractRdapOwner(rdap) {
  const out = {
    proprietario: 'Protegido por privacidade / Não divulgado',
    registro_titular: '-',
    email_contato: '-',
    registrador: '-'
  };
  if (!rdap || !Array.isArray(rdap.entities)) return out;

  const getVc = (ent, field) => {
    const row = ent?.vcardArray?.[1]?.find(i => i[0] === field);
    return row ? (Array.isArray(row[3]) ? row[3].filter(Boolean).join(' ') : String(row[3] || '')) : null;
  };

  const owner = rdap.entities.find(e => (e.roles || []).includes('registrant'))
    || rdap.entities.find(e => (e.roles || []).includes('administrative'));
  const reg = rdap.entities.find(e => (e.roles || []).includes('registrar'));

  if (owner) {
    out.proprietario = getVc(owner, 'fn') || getVc(owner, 'org') || out.proprietario;
    out.registro_titular = owner.publicIds?.[0]?.identifier || owner.handle || '-';
    out.email_contato = getVc(owner, 'email') || '-';
  }
  if (reg) out.registrador = getVc(reg, 'fn') || reg.handle || '-';
  return out;
}

module.exports = async (req, res) => {
  applyCors(req, res, 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Método não permitido.' });

  const domain = String(req.query.domain || '')
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0];

  if (!domain || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)) {
    return res.status(400).json({ error: 'Informe um domínio válido.' });
  }

  const rdapCandidates = domain.endsWith('.br')
    ? [`[https://rdap.registro.br/domain/$](https://rdap.registro.br/domain/$){encodeURIComponent(domain)}`, `[https://rdap.org/domain/$](https://rdap.org/domain/$){encodeURIComponent(domain)}`]
    : [`[https://rdap.org/domain/$](https://rdap.org/domain/$){encodeURIComponent(domain)}`, `[https://rdap.verisign.com/com/v1/domain/$](https://rdap.verisign.com/com/v1/domain/$){encodeURIComponent(domain)}`];

  const fetchRdap = async () => {
    for (const url of rdapCandidates) {
      try {
        const { upstream } = await safeFetch(url, { method: 'GET', headers: { Accept: 'application/rdap+json, application/json' } }, 9000);
        if (upstream.ok) {
          const buf = await readLimitedBuffer(upstream, 1024 * 1024);
          return { data: JSON.parse(buf.toString('utf8')), provider: new URL(url).hostname };
        }
      } catch {}
    }
    return { data: null, provider: 'DNS Only' };
  };

  const [rdapRes, aRec, aaaaRec, mxRec, nsRec, txtRec] = await Promise.all([
    fetchRdap(),
    dns.resolve4(domain).catch(() => []),
    dns.resolve6(domain).catch(() => []),
    dns.resolveMx(domain).then(arr => arr.sort((a, b) => a.priority - b.priority).map(m => `${m.priority} ${m.exchange}`)).catch(() => []),
    dns.resolveNs(domain).catch(() => []),
    dns.resolveTxt(domain).then(arr => arr.map(parts => parts.join(''))).catch(() => [])
  ]);

  const rdap = rdapRes.data;
  const owner = extractRdapOwner(rdap);
  const events = (rdap?.events || []).reduce((acc, ev) => {
    if (ev.eventAction && ev.eventDate) acc[ev.eventAction] = ev.eventDate.split('T')[0];
    return acc;
  }, {});

  res.setHeader('Cache-Control', 'public, s-maxage=300, stale-while-revalidate=900');
  return res.status(200).json({
    provider: `${rdapRes.provider} + Node DNS`,
    resumo: {
      dominio: domain,
      proprietario: owner.proprietario,
      registro_titular: owner.registro_titular,
      email_contato: owner.email_contato,
      registrador: owner.registrador,
      status_rdap: (rdap?.status || []).join(', ') || 'Não retornado',
      registro: events.registration || '-',
      expiracao: events.expiration || '-'
    },
    listas: [
      { titulo: 'IPs IPv4 (A)', itens: aRec },
      { titulo: 'IPs IPv6 (AAAA)', itens: aaaaRec },
      { titulo: 'E-mail (MX)', itens: mxRec },
      { titulo: 'Nameservers (NS)', itens: nsRec },
      { titulo: 'Registros TXT / SPF / DMARC', itens: txtRec }
    ].filter(l => l.itens.length > 0),
    raw: { domain, owner, rdap, dns: { aRec, aaaaRec, mxRec, nsRec, txtRec } }
  });
};
