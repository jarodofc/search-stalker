import {
  saveDossier, loadDossier, clearDossier, signExport,
  parseImageMetadata, runEla, decodeJwt, transformText
} from './local-engines.js';

const MODULES = [
  { id: 'custody', g: 'Pericia Local (Web Worker)', t: 'Custodia, Hashes & Hex', d: 'MD5, SHA-1/256/512, Magic Bytes, Entropia de Shannon, Hex Dump e IOCs 100% locais.' },
  { id: 'ela', g: 'Pericia Local (Web Worker)', t: 'Analise ELA (Imagem)', d: 'Error Level Analysis em Canvas local para deteccao de manipulacao.' },
  { id: 'exif', g: 'Pericia Local (Web Worker)', t: 'Metadados EXIF & GPS', d: 'Extracao binaria de camera, software e coordenadas GPS com mapa.' },
  { id: 'decoders', g: 'Pericia Local (Web Worker)', t: 'Decodificador & JWT', d: 'Inspecao de JWT, Base64, Hex, URL, ROT13, Unix Timestamp e CIDR.' },

  { id: 'virustotal', g: 'Threat Intel & OSINT (Serverless)', t: 'VirusTotal API v3', d: 'Analise de Hash, Dominio, IP ou URL via chave protegida na Vercel.' },
  { id: 'sherlock', g: 'Threat Intel & OSINT (Serverless)', t: 'Sherlock OSINT (11 APIs)', d: 'Varredura concorrente de username via Promise.allSettled no servidor.' },
  { id: 'dorks', g: 'Threat Intel & OSINT (Serverless)', t: 'Central de Dorks', d: 'Gerador de buscas Google Hacking para documentos expostos e redes sociais.' },
  { id: 'breach', g: 'Threat Intel & OSINT (Serverless)', t: 'Vazamentos & E-mail', d: 'XposedOrNot + auditoria nativa de MX, SPF e DMARC.' },
  { id: 'cnpj', g: 'Threat Intel & OSINT (Serverless)', t: 'Consulta CNPJ (QSA)', d: 'Fallback automatico: BrasilAPI -> CNPJ.ws -> MinhaReceita.' },
  { id: 'ip', g: 'Threat Intel & OSINT (Serverless)', t: 'IP, ASN & Mapa', d: 'Geolocalizacao, ASN e mapa OpenStreetMap (ipwho.is -> ipapi.co).' },
  { id: 'subdomains', g: 'Threat Intel & OSINT (Serverless)', t: 'Subdominios SSL (crt.sh)', d: 'Descoberta passiva via Certificate Transparency.' },
  { id: 'dns', g: 'Threat Intel & OSINT (Serverless)', t: 'DNS & Seguranca', d: 'Resolucao nativa no servidor (A/AAAA/MX/NS/TXT/SOA) + SPF/DMARC.' },
  { id: 'rdap', g: 'Threat Intel & OSINT (Serverless)', t: 'Dono de Site (RDAP)', d: 'Consulta oficial Registro.br / Verisign / RDAP.org.' },
  { id: 'scraper', g: 'Threat Intel & OSINT (Serverless)', t: 'Web Scraper & Headers', d: 'Metadados, contatos, links e nota A-F de Security Headers.' },

  { id: 'dossier', g: 'Cadeia de Custodia', t: 'Dossie da Sessao', d: 'Evidencias salvas em AES-256-GCM e exportadas com assinatura HMAC-SHA256.' }
];

const st = { active: 'custody', proxy: { online: false, region: '-', latencyMs: null, vtKey: false }, last: {}, dossier: [], worker: null, hexOff: 0, hexTot: 0 };

const esc = (v) => String(v ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
const fmtB = (n) => { n = Number(n || 0); if (n < 1024) return `${n} B`; const u = ['KB', 'MB', 'GB']; let i = 0; n /= 1024; while (n >= 1024 && i < 2) { n /= 1024; i++; } return `${n.toFixed(2)} ${u[i]}`; };
const alertBox = (m, t = 'info') => `<div class="alert alert-${esc(t)}">${esc(m)}</div>`;
const loaderBox = (m) => `<div class="loader-box"><span class="spinner"></span><span>${esc(m)}</span></div>`;
const actionsBar = (id) => `<div class="result-toolbar no-print">
  <button type="button" class="btn btn-sm btn-secondary" data-act="save" data-mod="${esc(id)}">Arquivar no Dossie</button>
  <button type="button" class="btn btn-sm btn-secondary" data-act="json" data-mod="${esc(id)}">JSON Assinado</button>
  <button type="button" class="btn btn-sm btn-secondary" data-act="print">Imprimir / PDF</button></div>`;
const kvGrid = (rows) => `<div class="kv-grid">${rows.map(([k, v, cp]) => `
  <div class="kv-item"><span class="kv-label">${esc(k)}</span><div class="kv-val-row">
    <span class="kv-val">${esc(v ?? '-')}</span>
    ${cp && v && v !== '-' ? `<button type="button" class="btn-copy" data-copy="${esc(v)}">Copiar</button>` : ''}
  </div></div>`).join('')}</div>`;

function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  document.getElementById('toast-host').appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

async function pingProxy() {
  const t0 = performance.now(), ctrl = new AbortController(), tm = setTimeout(() => ctrl.abort(), 3200);
  try {
    const r = await fetch('/api/proxy?ping=1', { signal: ctrl.signal });
    const d = await r.json();
    if (!r.ok || !d.ok) throw new Error();
    st.proxy = { online: true, region: d.region || 'edge', latencyMs: Math.round(performance.now() - t0), vtKey: Boolean(d.capabilities?.virustotalServerKey) };
  } catch {
    st.proxy = { online: false, region: 'local', latencyMs: null, vtKey: false };
  } finally { clearTimeout(tm); }
  const el = document.getElementById('proxy-status');
  if (el) {
    el.className = `proxy-pill ${st.proxy.online ? 'proxy-online' : 'proxy-offline'}`;
    el.textContent = st.proxy.online ? `Proxy Remoto: Online (${st.proxy.region} • ${st.proxy.latencyMs}ms)` : 'Modo Local (Deploy na Vercel para /api)';
  }
}

async function api(path, params = {}, headers = {}) {
  const u = new URL(path, location.origin);
  Object.entries(params).forEach(([k, v]) => { if (v !== undefined && String(v).trim() !== '') u.searchParams.set(k, String(v).trim()); });
  const ctrl = new AbortController(), tm = setTimeout(() => ctrl.abort(), 14000);
  try {
    const r = await fetch(u, { headers: { Accept: 'application/json', ...headers }, signal: ctrl.signal });
    if (!(r.headers.get('content-type') || '').includes('application/json')) throw new Error('Rota /api nao respondeu JSON. Publique na Vercel ou rode vercel dev.');
    const d = await r.json();
    if (!r.ok || d.ok === false) throw new Error(d.error || `HTTP ${r.status}`);
    return d;
  } catch (e) { throw new Error(e.name === 'AbortError' ? 'Timeout na requisicao.' : e.message); } finally { clearTimeout(tm); }
}

function renderNav() {
  const nav = document.getElementById('sidebar-nav');
  const groups = [...new Set(MODULES.map((m) => m.g))];
  nav.innerHTML = groups.map((g) => `<div class="nav-group"><div class="nav-group-label">${esc(g)}</div>${
    MODULES.filter((m) => m.g === g).map((m) => `<button type="button" class="nav-item${m.id === st.active ? ' active' : ''}" data-nav="${esc(m.id)}">
      <span>${esc(m.t)}</span>${m.id === 'dossier' ? `<span class="nav-badge" id="dos-cnt">${st.dossier.length}</span>` : ''}</button>`).join('')
  }</div>`).join('');
}

function renderView() {
  const m = MODULES.find((x) => x.id === st.active);
  document.getElementById('workspace-title').textContent = m.t;
  document.getElementById('workspace-desc').textContent = m.d;
  const el = document.getElementById('workspace-body');

  if (m.id === 'custody') {
    el.innerHTML = `<div class="card"><div class="dropzone" id="c-drop"><input type="file" id="c-file" class="hidden" />
      <p><strong>Arraste qualquer arquivo aqui ou selecione abaixo</strong></p>
      <p class="muted">Processamento 100% local em Web Worker dedicado.</p>
      <button type="button" class="btn btn-primary" id="c-pick">Selecionar Evidencia</button></div></div><div id="c-res"></div>`;
    const inp = document.getElementById('c-file'), drop = document.getElementById('c-drop'), res = document.getElementById('c-res');
    const run = async (f) => {
      if (!f) return;
      res.innerHTML = loaderBox(`Analisando ${f.name} (${fmtB(f.size)})...`);
      const buf = await f.arrayBuffer();
      if (!st.worker) st.worker = new Worker('/assets/js/worker-forensics.js');
      st.worker.onmessage = ({ data: msg }) => {
        if (!msg.ok) { res.innerHTML = alertBox(msg.error, 'error'); return; }
        if (msg.cmd === 'analyze') {
          const d = msg.data; st.last.custody = d; st.hexOff = 0; st.hexTot = d.size;
          res.innerHTML = `${actionsBar('custody')}${d.magic.mismatch ? alertBox(`SPOOFING: extensao ".${d.magic.extension}" diverge da assinatura real (${d.magic.type}).`, 'warning') : ''}
            <div class="card"><h3 class="card-title">Identificacao &amp; Entropia</h3>${kvGrid([
              ['Arquivo', d.filename, true], ['Tamanho', `${fmtB(d.size)} (${d.size} bytes)`],
              ['Magic Bytes', d.magic.type, true], ['Cabecalho (Hex)', d.magic.headHex, true],
              ['Entropia', `${d.entropy.bits} bits/byte — ${d.entropy.assessment}`], ['Modificacao', d.lastModified || '-']
            ])}</div>
            <div class="card"><h3 class="card-title">Hashes</h3>${kvGrid([['SHA-256', d.hashes.sha256, true], ['SHA-512', d.hashes.sha512, true], ['SHA-1', d.hashes.sha1, true], ['MD5', d.hashes.md5, true]])}</div>
            <div class="card"><div class="card-head-row"><h3 class="card-title">Hex Dump</h3><div>
              <button type="button" class="btn btn-sm btn-secondary" id="hx-p">-2 KB</button>
              <button type="button" class="btn btn-sm btn-secondary" id="hx-n">+2 KB</button></div></div>
              <pre class="code-pre" id="hx-box">${esc(d.hexDump.text)}</pre></div>
            <div class="card"><h3 class="card-title">IOCs &amp; Strings (${d.extracted.strings.length})</h3>${kvGrid([
              ['URLs', d.extracted.iocs.urls.join(', ') || '-', d.extracted.iocs.urls.length],
              ['E-mails', d.extracted.iocs.emails.join(', ') || '-', d.extracted.iocs.emails.length],
              ['IPs', d.extracted.iocs.ips.join(', ') || '-', d.extracted.iocs.ips.length]
            ])}</div>`;
          document.getElementById('hx-p').addEventListener('click', () => { st.hexOff = Math.max(0, st.hexOff - 2048); st.worker.postMessage({ cmd: 'hexPage', offset: st.hexOff }); });
          document.getElementById('hx-n').addEventListener('click', () => { if (st.hexOff + 2048 < st.hexTot) { st.hexOff += 2048; st.worker.postMessage({ cmd: 'hexPage', offset: st.hexOff }); } });
        } else if (msg.cmd === 'hexPage') {
          const b = document.getElementById('hx-box'); if (b) b.textContent = msg.data.text;
        }
      };
      st.worker.postMessage({ cmd: 'analyze', buffer: buf, filename: f.name, lastModified: f.lastModified }, [buf]);
    };
    document.getElementById('c-pick').addEventListener('click', () => inp.click());
    inp.addEventListener('change', () => run(inp.files[0]));
    drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('drag-over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('drag-over'));
    drop.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('drag-over'); run(e.dataTransfer.files[0]); });
    return;
  }

  if (m.id === 'ela') {
    el.innerHTML = `<div class="card"><div class="form-grid">
      <div><label class="field-label">Imagem</label><input type="file" id="e-f" accept="image/*" class="input" /></div>
      <div><label class="field-label">Qualidade: <strong id="e-qv">90%</strong></label><input type="range" id="e-q" min="60" max="98" value="90" class="range-input" /></div>
      <div><label class="field-label">Ganho: <strong id="e-sv">15x</strong></label><input type="range" id="e-s" min="1" max="35" value="15" class="range-input" /></div>
    </div><button type="button" class="btn btn-primary mt-12" id="e-go">Executar ELA</button></div><div id="e-res"></div>`;
    const q = document.getElementById('e-q'), s = document.getElementById('e-s');
    q.addEventListener('input', () => { document.getElementById('e-qv').textContent = `${q.value}%`; });
    s.addEventListener('input', () => { document.getElementById('e-sv').textContent = `${s.value}x`; });
    document.getElementById('e-go').addEventListener('click', async () => {
      const f = document.getElementById('e-f').files[0], res = document.getElementById('e-res');
      if (!f) return toast('Selecione uma imagem.', 'error');
      res.innerHTML = loaderBox('Calculando ELA no Canvas...');
      try {
        const o = await runEla(f, Number(q.value), Number(s.value));
        st.last.ela = { filename: f.name, width: o.width, height: o.height, stats: o.stats };
        res.innerHTML = `${actionsBar('ela')}<div class="card">${kvGrid([['Dimensoes', `${o.width}x${o.height}`], ['Erro Medio', o.stats.meanError], ['Erro Max', o.stats.maxError], ['Alta Variancia', `${o.stats.highPct}%`]])}</div>
          <div class="ela-grid"><div class="card"><h4 class="card-title">Original</h4><img src="${o.originalUrl}" class="preview-img" alt="Original" /></div>
          <div class="card"><div class="card-head-row"><h4 class="card-title">Mapa ELA</h4><a href="${o.elaUrl}" download="ela.png" class="btn btn-sm btn-secondary">Baixar PNG</a></div><img src="${o.elaUrl}" class="preview-img" alt="ELA" /></div></div>`;
      } catch (e) { res.innerHTML = alertBox(e.message, 'error'); }
    });
    return;
  }

  if (m.id === 'exif') {
    el.innerHTML = `<div class="card"><label class="field-label">Imagem JPEG/PNG (100% local)</label><input type="file" id="x-f" accept="image/*" class="input" /></div><div id="x-res"></div>`;
    document.getElementById('x-f').addEventListener('change', async (ev) => {
      const f = ev.target.files[0], res = document.getElementById('x-res'); if (!f) return;
      try {
        const d = await parseImageMetadata(f); st.last.exif = d;
        const gps = d.gps ? `<div class="card"><h3 class="card-title">GPS</h3>${kvGrid([['Latitude', d.gps.latitude, true], ['Longitude', d.gps.longitude, true], ['Altitude', d.gps.altitude || '-']])}
          <iframe class="map-frame mt-12" loading="lazy" src="https://www.openstreetmap.org/export/embed.html?bbox=${d.gps.longitude - 0.01},${d.gps.latitude - 0.01},${d.gps.longitude + 0.01},${d.gps.latitude + 0.01}&layer=mapnik&marker=${d.gps.latitude},${d.gps.longitude}"></iframe></div>` : '';
        res.innerHTML = `${actionsBar('exif')}${d.alerts.map((a) => alertBox(a, 'warning')).join('')}
          <div class="card">${kvGrid([['Arquivo', d.filename, true], ['Formato', d.format], ['Tamanho', fmtB(d.size)], ['Dimensoes', d.dimensions ? `${d.dimensions.width}x${d.dimensions.height}` : '-']])}</div>
          ${gps}<div class="card"><h3 class="card-title">Tags EXIF</h3>${Object.keys(d.tags).length ? kvGrid(Object.entries(d.tags).map(([k, v]) => [k, v, true])) : '<p class="muted">Sem metadados EXIF.</p>'}</div>`;
      } catch (e) { res.innerHTML = alertBox(e.message, 'error'); }
    });
    return;
  }

  if (m.id === 'decoders') {
    el.innerHTML = `<div class="card"><div class="form-row"><select id="d-m" class="input select-auto">
      <option value="jwt">JWT Inspector</option><option value="b64_decode">Base64 -> Texto</option><option value="b64_encode">Texto -> Base64</option>
      <option value="hex_decode">Hex -> Texto</option><option value="hex_encode">Texto -> Hex</option><option value="url_decode">URL Decode</option>
      <option value="url_encode">URL Encode</option><option value="rot13">ROT13</option><option value="timestamp">Unix Timestamp</option><option value="cidr">Calculadora CIDR</option>
    </select><button type="button" class="btn btn-primary" id="d-go">Processar</button></div>
    <textarea id="d-in" rows="5" class="input textarea mt-12" placeholder="Cole JWT, Base64, Hex, Epoch ou CIDR..."></textarea></div><div id="d-res"></div>`;
    document.getElementById('d-go').addEventListener('click', () => {
      const mode = document.getElementById('d-m').value, raw = document.getElementById('d-in').value, res = document.getElementById('d-res');
      try {
        if (mode === 'jwt') {
          const j = decodeJwt(raw); st.last.decoders = j;
          res.innerHTML = `${actionsBar('decoders')}${j.warnings.map((w) => alertBox(w, w.startsWith('CRITICO') ? 'error' : 'info')).join('')}
            <div class="ela-grid"><div class="card"><h3 class="card-title">Header</h3><pre class="code-pre">${esc(JSON.stringify(j.header, null, 2))}</pre></div>
            <div class="card"><h3 class="card-title">Payload</h3><pre class="code-pre">${esc(JSON.stringify(j.payload, null, 2))}</pre></div></div>`;
        } else {
          const out = transformText(mode, raw); st.last.decoders = { mode, out };
          res.innerHTML = `${actionsBar('decoders')}<div class="card"><div class="card-head-row"><h3 class="card-title">Saida</h3>
            <button type="button" class="btn btn-sm btn-secondary" data-copy="${esc(out)}">Copiar</button></div><pre class="code-pre">${esc(out)}</pre></div>`;
        }
      } catch (e) { res.innerHTML = alertBox(e.message, 'error'); }
    });
    return;
  }

  if (m.id === 'dorks') {
    el.innerHTML = `<div class="card"><form id="dk-f" class="form-row"><input id="dk-q" class="input" placeholder="Alvo (dominio, nome, e-mail ou username)" required />
      <button class="btn btn-primary">Gerar Dorks</button></form></div><div id="dk-res"></div>`;
    document.getElementById('dk-f').addEventListener('submit', (e) => {
      e.preventDefault();
      const q = document.getElementById('dk-q').value.trim(), g = (s) => `https://www.google.com/search?q=${encodeURIComponent(s)}`;
      const cats = [
        ['Documentos & Arquivos Expostos', [
          ['PDFs', g(`"${q}" filetype:pdf`)], ['Planilhas XLS/CSV', g(`"${q}" (filetype:xls OR filetype:xlsx OR filetype:csv)`)],
          ['Diretorios Abertos (Index of)', g(`intitle:"index of" "${q}"`)], ['Pastebin / GitHub Gist', g(`"${q}" (site:pastebin.com OR site:gist.github.com)`)]
        ]],
        ['Redes Sociais', [
          ['Instagram', g(`site:instagram.com "${q}"`)], ['LinkedIn', g(`site:linkedin.com "${q}"`)],
          ['X (Twitter)', g(`site:x.com "${q}"`)], ['Facebook', g(`site:facebook.com "${q}"`)], ['TikTok', g(`site:tiktok.com "${q}"`)]
        ]]
      ];
      st.last.dorks = { alvo: q, cats };
      document.getElementById('dk-res').innerHTML = `${actionsBar('dorks')}${cats.map(([t, items]) => `<div class="card"><h3 class="card-title">${esc(t)}</h3>
        <div class="tag-cloud">${items.map(([n, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-secondary">${esc(n)} ↗</a>`).join('')}</div></div>`).join('')}`;
    });
    return;
  }

  if (m.id === 'virustotal') {
    el.innerHTML = `<div class="card">${st.proxy.vtKey ? alertBox('VT_API_KEY ativa no servidor Vercel.', 'success') : alertBox('Configure VT_API_KEY na Vercel ou informe sua chave abaixo.', 'info')}
      <form id="vt-f"><div class="form-row"><select id="vt-t" class="input select-auto"><option value="domain">Dominio</option><option value="ip">IP</option><option value="hash">Hash</option><option value="url">URL</option></select>
      <input id="vt-q" class="input" placeholder="Alvo..." required /><button class="btn btn-primary">Consultar</button></div>
      ${st.proxy.vtKey ? '' : '<input id="vt-k" type="password" class="input mt-8" placeholder="(Opcional) Chave API VirusTotal" />'}</form></div><div id="vt-res"></div>`;
    document.getElementById('vt-f').addEventListener('submit', async (e) => {
      e.preventDefault();
      const res = document.getElementById('vt-res'); res.innerHTML = loaderBox('Consultando VirusTotal...');
      try {
        const k = document.getElementById('vt-k')?.value.trim();
        const d = await api('/api/intel', { action: 'virustotal', type: document.getElementById('vt-t').value, target: document.getElementById('vt-q').value }, k ? { 'X-VT-Key': k } : {});
        st.last.virustotal = d;
        if (!d.found) { res.innerHTML = alertBox(d.message, 'info'); return; }
        res.innerHTML = `${actionsBar('virustotal')}<div class="card"><div class="stat-grid">
          <div class="stat-box stat-danger"><span class="stat-num">${d.stats.malicious}</span><span class="stat-lbl">Malicioso</span></div>
          <div class="stat-box stat-warn"><span class="stat-num">${d.stats.suspicious}</span><span class="stat-lbl">Suspeito</span></div>
          <div class="stat-box stat-ok"><span class="stat-num">${d.stats.harmless}</span><span class="stat-lbl">Seguro</span></div>
          <div class="stat-box"><span class="stat-num">${d.stats.undetected}</span><span class="stat-lbl">Nao detectado</span></div></div></div>`;
      } catch (err) { res.innerHTML = alertBox(err.message, 'error'); }
    });
    return;
  }

  if (m.id === 'dossier') {
    el.innerHTML = `<div class="result-toolbar no-print">
      <button type="button" class="btn btn-primary" id="dos-exp">Exportar Dossie Assinado</button>
      <button type="button" class="btn btn-secondary" id="dos-prt">Imprimir / PDF</button>
      <button type="button" class="btn btn-danger" id="dos-clr">Limpar</button></div>
      ${st.dossier.length ? st.dossier.map((it) => `<div class="card"><div class="card-head-row"><div><h3 class="card-title">${esc(it.t)}</h3><span class="muted">${esc(it.at)}</span></div>
        <button type="button" class="btn btn-sm btn-danger" data-del="${esc(it.id)}">Remover</button></div>
        <details><summary class="ext-link">Ver JSON</summary><pre class="code-pre mt-8">${esc(JSON.stringify(it.data, null, 2))}</pre></details></div>`).join('') : '<div class="card"><p class="muted">Nenhuma evidencia arquivada.</p></div>'}`;
    document.getElementById('dos-exp').addEventListener('click', () => st.dossier.length ? exportSigned('dossier', st.dossier) : toast('Dossie vazio.', 'error'));
    document.getElementById('dos-prt').addEventListener('click', () => window.print());
    document.getElementById('dos-clr').addEventListener('click', () => { st.dossier = []; clearDossier(); renderNav(); renderView(); });
    return;
  }

  // Modulos de consulta unica (/api/intel e /api/scrape)
  const cfg = {
    sherlock: ['Username (ex: torvalds)', 'Rastrear', async (v) => {
      const d = await api('/api/intel', { action: 'sherlock', username: v });
      st.last.sherlock = d;
      return `${actionsBar('sherlock')}<div class="card"><div class="table-wrap"><table class="data-table"><thead><tr><th>Plataforma</th><th>Status</th><th>Info</th><th>Link</th></tr></thead><tbody>${
        d.results.map((r) => `<tr><td><strong>${esc(r.platform)}</strong></td><td><span class="pill ${r.status === 'found' ? 'pill-ok' : r.status === 'error' ? 'pill-warn' : ''}">${esc(r.status)}</span></td><td>${esc(r.info || '-')}</td><td>${r.status === 'found' ? `<a class="ext-link" href="${esc(r.url)}" target="_blank" rel="noopener noreferrer">Abrir</a>` : '-'}</td></tr>`).join('')
      }</tbody></table></div></div>`;
    }],
    breach: ['E-mail (ex: teste@dominio.com)', 'Verificar', async (v) => {
      const d = await api('/api/intel', { action: 'breach', email: v });
      st.last.breach = d;
      const b = d.breachCheck;
      return `${actionsBar('breach')}${b.ok ? alertBox(b.exposed ? `Exposto em ${b.breaches.length} vazamento(s)!` : 'Nenhum vazamento encontrado.', b.exposed ? 'error' : 'success') : alertBox(`XposedOrNot indisponivel (${b.error}).`, 'warning')}
        <div class="card">${kvGrid([['MX Valido', d.mailHealth.mxValid ? 'Sim' : 'Nao'], ['SPF', d.mailHealth.hasSpf ? 'Ativo' : 'Ausente'], ['DMARC', d.mailHealth.hasDmarc ? 'Ativo' : 'Ausente'], ['Vazamentos', (b.breaches || []).join(', ') || '-']])}</div>`;
    }],
    cnpj: ['CNPJ (ex: 00.000.000/0001-91)', 'Consultar', async (v) => {
      const d = await api('/api/intel', { action: 'cnpj', cnpj: v }); st.last.cnpj = d; const c = d.company;
      return `${actionsBar('cnpj')}<div class="card"><div class="card-head-row"><h3 class="card-title">${esc(c.razaoSocial)}</h3><span class="pill pill-ok">${esc(d.provider)}</span></div>${kvGrid([
        ['CNPJ', c.cnpj, true], ['Fantasia', c.nomeFantasia], ['Situacao', c.situacao], ['Abertura', c.dataAbertura],
        ['CNAE', c.cnaePrincipal], ['Capital', c.capitalSocial != null ? c.capitalSocial.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' }) : '-'],
        ['Telefone', c.telefone, true], ['E-mail', c.email, true], ['Endereco', `${c.endereco} (${c.cidadeUf})`, true]
      ])}</div>${c.socios.length ? `<div class="card"><h3 class="card-title">Socios (${c.socios.length})</h3><div class="table-wrap"><table class="data-table"><thead><tr><th>Nome</th><th>Qualificacao</th><th>Entrada</th></tr></thead><tbody>${c.socios.map((s) => `<tr><td>${esc(s.nome)}</td><td>${esc(s.qualificacao)}</td><td>${esc(s.entrada)}</td></tr>`).join('')}</tbody></table></div></div>` : ''}`;
    }],
    ip: ['IP ou dominio (vazio = seu IP)', 'Localizar', async (v) => {
      const d = await api('/api/intel', { action: 'ip', target: v }); st.last.ip = d; const g = d.geo;
      const map = typeof g.latitude === 'number' ? `<div class="card"><iframe class="map-frame" loading="lazy" src="https://www.openstreetmap.org/export/embed.html?bbox=${g.longitude - 0.08},${g.latitude - 0.08},${g.longitude + 0.08},${g.latitude + 0.08}&layer=mapnik&marker=${g.latitude},${g.longitude}"></iframe></div>` : '';
      return `${actionsBar('ip')}<div class="card">${kvGrid([['IP', g.ip, true], ['Local', `${g.city}, ${g.region} - ${g.country}`], ['ASN', g.asn, true], ['ISP/Org', g.org, true], ['Coords', `${g.latitude}, ${g.longitude}`, true], ['Fuso', g.timezone]])}</div>${map}`;
    }, true],
    subdomains: ['Dominio raiz (ex: exemplo.com.br)', 'Buscar', async (v) => {
      const d = await api('/api/intel', { action: 'subdomains', domain: v }); st.last.subdomains = d;
      const list = d.subdomains.map((s) => s.host).join('\n');
      return `${actionsBar('subdomains')}<div class="card"><div class="card-head-row"><h3 class="card-title">${d.total} subdominio(s)</h3><button type="button" class="btn btn-sm btn-secondary" data-copy="${esc(list)}">Copiar Lista</button></div><pre class="code-pre">${esc(list || '(nenhum)')}</pre></div>`;
    }],
    dns: ['Dominio (ex: gov.br)', 'Resolver', async (v) => {
      const d = await api('/api/intel', { action: 'dns', domain: v }); st.last.dns = d; const r = d.records;
      return `${actionsBar('dns')}<div class="card">${kvGrid([['SPF', d.emailSecurity.spf || 'Ausente'], ['DMARC', d.emailSecurity.dmarc || 'Ausente'], ['A', r.A.join(', ') || '-', true], ['AAAA', r.AAAA.join(', ') || '-'], ['NS', r.NS.join(', ') || '-'], ['MX', r.MX.map((x) => `${x.exchange} (${x.priority})`).join(' | ') || '-']])}</div>`;
    }],
    rdap: ['Dominio (ex: uol.com.br)', 'Consultar RDAP', async (v) => {
      const d = await api('/api/intel', { action: 'rdap', domain: v }); st.last.rdap = d;
      return `${actionsBar('rdap')}<div class="card"><div class="card-head-row"><h3 class="card-title">${esc(d.domain)}</h3><span class="pill">${esc(d.provider)}</span></div>${kvGrid([
        ['Titular', d.owner.name, true], ['Documento', d.owner.document, true], ['E-mail', d.owner.email, true],
        ['Registrador', d.registrar], ['Criacao', d.events.registration || '-'], ['Expiracao', d.events.expiration || '-'],
        ['DNSSEC', d.dnssec ? 'Assinado' : 'Nao'], ['Nameservers', d.nameservers.join(', ') || '-']
      ])}</div>`;
    }],
    scraper: ['URL (ex: https://exemplo.com.br)', 'Analisar', async (v) => {
      const d = await api('/api/scrape', { url: v }); st.last.scraper = d;
      return `${actionsBar('scraper')}<div class="card"><div class="card-head-row"><h3 class="card-title">Nota Security Headers: ${esc(d.security.grade)} (${d.security.score}/100)</h3><span class="pill">HTTP ${d.status} • ${d.elapsedMs}ms</span></div>${kvGrid([
        ['URL Final', d.url, true], ['Titulo', d.metadata.title], ['Descricao', d.metadata.description],
        ['E-mails', d.contacts.emails.join(', ') || '-', d.contacts.emails.length],
        ['Telefones', d.contacts.phones.join(', ') || '-', d.contacts.phones.length],
        ['Redes Sociais', d.contacts.social.join('\n') || '-']
      ])}</div><div class="card"><div class="table-wrap"><table class="data-table"><thead><tr><th>Header</th><th>Status</th><th>Valor</th></tr></thead><tbody>${
        d.security.details.map((h) => `<tr><td><code>${esc(h.header)}</code></td><td><span class="pill ${h.present ? 'pill-ok' : 'pill-danger'}">${h.present ? 'Presente' : 'Ausente'}</span></td><td>${esc(h.value || '-')}</td></tr>`).join('')
      }</tbody></table></div></div>`;
    }]
  };

  const [ph, btnTxt, handler, optional] = cfg[m.id];
  el.innerHTML = `<div class="card"><form id="q-f" class="form-row"><input id="q-in" class="input" placeholder="${esc(ph)}" ${optional ? '' : 'required'} />
    <button class="btn btn-primary">${esc(btnTxt)}</button></form></div><div id="q-res"></div>`;
  document.getElementById('q-f').addEventListener('submit', async (e) => {
    e.preventDefault();
    const res = document.getElementById('q-res');
    res.innerHTML = loaderBox('Consultando via servidor Vercel...');
    try { res.innerHTML = await handler(document.getElementById('q-in').value.trim()); } catch (err) { res.innerHTML = alertBox(err.message, 'error'); }
  });
}

async function exportSigned(mod, data) {
  const signed = await signExport(mod, data, st.proxy);
  const blob = new Blob([JSON.stringify(signed, null, 2)], { type: 'application/json' });
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: `zforense-${mod}-${Date.now()}.json` });
  a.click(); URL.revokeObjectURL(a.href);
  toast('JSON assinado (HMAC-SHA256) baixado.', 'success');
}

document.addEventListener('click', async (e) => {
  const nav = e.target.closest('[data-nav]');
  if (nav) { st.active = nav.dataset.nav; document.body.classList.remove('sidebar-open'); renderNav(); renderView(); return; }
  const cp = e.target.closest('[data-copy]');
  if (cp) { navigator.clipboard?.writeText(cp.dataset.copy).catch(() => {}); toast('Copiado.', 'success'); return; }
  const act = e.target.closest('[data-act]');
  if (act) {
    const mod = act.dataset.mod;
    if (act.dataset.act === 'print') window.print();
    else if (act.dataset.act === 'json' && st.last[mod]) exportSigned(mod, st.last[mod]);
    else if (act.dataset.act === 'save' && st.last[mod]) {
      st.dossier.unshift({ id: `ev-${Date.now()}`, t: MODULES.find((x) => x.id === mod)?.t || mod, at: new Date().toISOString(), data: st.last[mod] });
      await saveDossier(st.dossier); renderNav(); toast('Arquivado no Dossie.', 'success');
    }
    return;
  }
  const del = e.target.closest('[data-del]');
  if (del) { st.dossier = st.dossier.filter((x) => x.id !== del.dataset.del); await saveDossier(st.dossier); renderNav(); renderView(); }
});

document.getElementById('theme-toggle').addEventListener('click', () => {
  const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('zforense_theme', next);
});
document.getElementById('menu-toggle').addEventListener('click', () => document.body.classList.toggle('sidebar-open'));
document.getElementById('sidebar-backdrop').addEventListener('click', () => document.body.classList.remove('sidebar-open'));
document.getElementById('proxy-status').addEventListener('click', () => pingProxy().then(() => toast('Proxy atualizado.')));

(async () => {
  const th = localStorage.getItem('zforense_theme');
  if (th === 'light' || th === 'dark') document.documentElement.setAttribute('data-theme', th);
  renderNav(); renderView();
  const [dos] = await Promise.all([loadDossier(), pingProxy()]);
  st.dossier = dos; renderNav();
})();
