import { initRemoteProxy, getProxyState, callApi } from './network.js';
import { saveEncryptedDossier, loadEncryptedDossier, clearEncryptedDossier } from './crypto-custody.js';
import { parseImageMetadata } from './exif-parser.js';
import { runErrorLevelAnalysis } from './ela.js';
import { decodeJwt, transformText } from './decoders.js';
import {
  escapeHtml, formatBytes, formatCurrencyBRL, showToast, copyText,
  downloadSignedJson, renderKvList, renderBanner, renderLoading, renderMapBlock, renderResHeader
} from './ui.js';

const CASE_ID = `ZF-LMN-${new Date().toISOString().slice(2, 10).replace(/-/g, '')}`;
const THEMES = [
  { id: 'prism', label: 'Crimson Frost' },
  { id: 'ivory', label: 'Claro' },
  { id: 'noir', label: 'Alto contraste' }
];

const SECTORS = [
  { id: 'forense', title: 'Laboratorio Forense', icon: 'biotech', accent: '#2DD4BF' },
  { id: 'rede', title: 'Proxy, VPN & Anonimato', icon: 'vpn_lock', accent: '#38BDF8' },
  { id: 'sherlock', title: 'Rastreamento Sherlock', icon: 'policy', accent: '#E2B354' },
  { id: 'web', title: 'Web, SSL & Empresas', icon: 'language', accent: '#30D158' }
];

const MODULES = [
  { id: 'virustotal', sector: 'forense', name: 'VirusTotal', summary: 'Analisa arquivos (SHA-256 local), hashes, URLs, dominios e IPs via API v3 segura na Vercel.', io: 'Hash / URL / Arquivo -> Laudo AV', badge: 'VT v3 + OTX', badgeClass: 't-err', icon: 'bug_report', gradient: 'linear-gradient(135deg,#0A84FF,#1D4ED8)', keywords: 'virustotal virus malware hash sha256 md5 url dominio ip' },
  { id: 'metadata', sector: 'forense', name: 'Metadados EXIF', summary: 'Extrai aparelho, camera, data original, GPS e plota mapa interativo 100% local.', io: 'Foto Original -> EXIF + Mapa', badge: 'GPS + Mapa', badgeClass: 't-accent', icon: 'photo_camera', gradient: 'linear-gradient(135deg,#E2B354,#9E6E1F)', keywords: 'metadados exif foto gps mapa aparelho camera' },
  { id: 'ela', sector: 'forense', name: 'Analise ELA', summary: 'Detecta recortes, montagens e edicoes via variacao de compressao JPEG no Canvas.', io: 'Imagem -> Mapa ELA (PNG)', badge: 'Adulteracao', badgeClass: 't-accent', icon: 'compare', gradient: 'linear-gradient(135deg,#FF453A,#9B1C26)', keywords: 'ela adulteracao fraude montagem photoshop' },
  { id: 'custody', sector: 'forense', name: 'Custodia & Hex', summary: 'Hashes MD5/SHA-1/256/512, entropia de Shannon, spoofing de extensao e Hex Dump em Web Worker.', io: 'Arquivo -> Hashes + Magic Bytes', badge: 'Web Worker', badgeClass: 't-accent', icon: 'fingerprint', gradient: 'linear-gradient(135deg,#2DD4BF,#0F766E)', keywords: 'custodia hash sha256 entropia magic bytes spoofing hex' },
  { id: 'decoder', sector: 'forense', name: 'Decodificador', summary: 'Inspeciona JWT, Unix Timestamp, Base64, Hexadecimal, ROT13, URL Encoding e CIDR.', io: 'Artefato Texto -> Legivel', badge: '9 Motores', badgeClass: 't-accent', icon: 'terminal', gradient: 'linear-gradient(135deg,#BF5AF2,#6B21A8)', keywords: 'jwt base64 hex url timestamp cidr decoder' },

  { id: 'proxyvpn', sector: 'rede', name: 'Proxy & VPN Lab', summary: 'Detector VPN/Proxy/Tor (ipapi.is + ProxyCheck), OpenVPN (.ovpn) e proxies live no servidor.', io: 'IP / Pais / Proto -> VPN & Proxies', badge: 'Serverless', badgeClass: 't-blue', icon: 'vpn_lock', gradient: 'linear-gradient(135deg,#0EA5E9,#0369A1)', keywords: 'proxy vpn tor socks5 http openvpn ovpn vpngate proxyscrape anonimato detector' },

  { id: 'osint', sector: 'sherlock', name: 'Sherlock OSINT', summary: 'Varredura concorrente de username em 12 plataformas com timeout individual via Promise.allSettled.', io: 'Username -> 12 Plataformas', badge: '12 APIs', badgeClass: 't-blue', icon: 'travel_explore', gradient: 'linear-gradient(135deg,#6366F1,#312E81)', keywords: 'osint sherlock username github reddit perfis', placeholder: 'Username (ex: torvalds)' },
  { id: 'dork', sector: 'sherlock', name: 'Dorks Forenses', summary: 'Google Hacking para PDFs, planilhas, diretorios abertos, pastes e redes sociais.', io: 'Termo / Alvo -> Dorks Google', badge: '4 Categorias', badgeClass: 't-warn', icon: 'manage_search', gradient: 'linear-gradient(135deg,#F59E0B,#B45309)', keywords: 'dork google pdf pastes redes sociais', placeholder: 'Nome, dominio, @user ou termo' },
  { id: 'breach', sector: 'sherlock', name: 'Vazamentos', summary: 'Checa exposicao de e-mail na base XposedOrNot + auditoria nativa de MX, SPF e DMARC.', io: 'E-mail -> Bases + MX/SPF/DMARC', badge: '2 Motores', badgeClass: 't-err', icon: 'security', gradient: 'linear-gradient(135deg,#EF4444,#991B1B)', keywords: 'vazamento email breach senha spf dmarc', placeholder: 'Ex: nome@dominio.com' },

  { id: 'ssl_crt', sector: 'web', name: 'Subdominios SSL', summary: 'Enumera subdominios e certificados via logs de Certificate Transparency (crt.sh).', io: 'Dominio -> Subdominios + Datas', badge: 'crt.sh + Alt', badgeClass: 't-ok', icon: 'workspace_premium', gradient: 'linear-gradient(135deg,#14B8A6,#0F766E)', keywords: 'ssl crt.sh subdominios certificados recon', placeholder: 'Ex: exemplo.com.br' },
  { id: 'dns', sector: 'web', name: 'DNS & Seguranca', summary: 'Resolucao nativa no servidor (A, AAAA, MX, NS, TXT, CNAME, SOA) + auditoria SPF/DMARC.', io: 'Dominio -> Registros + Anti-Spoofing', badge: 'Node DNS', badgeClass: 't-ok', icon: 'dns', gradient: 'linear-gradient(135deg,#10B981,#047857)', keywords: 'dns mx spf dmarc txt ns registros', placeholder: 'Ex: gov.br' },
  { id: 'domain', sector: 'web', name: 'Dono de Site', summary: 'Consulta titular, registrador, vigencia e DNSSEC via RDAP oficial (Registro.br e global).', io: 'Dominio -> RDAP Oficial', badge: 'RDAP', badgeClass: 't-blue', icon: 'language', gradient: 'linear-gradient(135deg,#38BDF8,#0284C7)', keywords: 'site dominio dono proprietario whois rdap', placeholder: 'Ex: uol.com.br ou openai.com' },
  { id: 'scraping', sector: 'web', name: 'Web Scraper', summary: 'Extrai metadados HTML, e-mails, telefones, links e nota A-F de Security Headers no servidor.', io: 'URL -> Contatos + Headers A-F', badge: 'SSRF Guard', badgeClass: 't-blue', icon: 'code', gradient: 'linear-gradient(135deg,#06B6D4,#0369A1)', keywords: 'scraper html links telefones emails headers seguranca', placeholder: 'Ex: https://exemplo.com.br' },
  { id: 'ip', sector: 'web', name: 'IP & Mapa', summary: 'Geolocalizacao, ISP, ASN e mapa OpenStreetMap (vazio consulta seu IP publico).', io: 'IP / Dominio -> ISP + ASN + Mapa', badge: 'Geo + Mapa', badgeClass: 't-blue', icon: 'router', gradient: 'linear-gradient(135deg,#8B5CF6,#5B21B6)', keywords: 'ip geo localizacao mapa operadora asn', placeholder: 'IP ou dominio (vazio = seu IP)', optional: true },
  { id: 'cnpj', sector: 'web', name: 'Consulta CNPJ', summary: 'Validacao Modulo 11 + dados cadastrais e Quadro Societario com fallback triplo.', io: 'CNPJ 14d -> Empresa + QSA', badge: '3 APIs BR', badgeClass: 't-ok', icon: 'domain', gradient: 'linear-gradient(135deg,#22C55E,#15803D)', keywords: 'cnpj empresa razao social socios qsa receita cnae', placeholder: 'CNPJ (14 digitos)', digits: true }
];

const state = {
  theme: localStorage.getItem('sherlock_prism_theme') || 'prism',
  solid: localStorage.getItem('sherlock_prism_solid') === '1',
  activeHomeSector: 'all',
  pendingQuery: null,
  lastModuleId: 'custody',
  lastResultData: null,
  dossier: [],
  history: [],
  worker: null,
  hexOffset: 0,
  hexTotalBytes: 0,
  elaFile: null
};

try { state.history = JSON.parse(localStorage.getItem('sherlock_prism_history') || '[]'); } catch { state.history = []; }

async function safeSha256Hex(buffer) {
  if (!window.crypto || !window.crypto.subtle) return 'Indisponivel (requer HTTPS)';
  const dig = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(dig), (b) => b.toString(16).padStart(2, '0')).join('');
}

function getWorker() {
  if (!state.worker) state.worker = new Worker('/assets/js/worker-forensics.js?v=4.1.0');
  return state.worker;
}

function isValidCnpj(cnpj) {
  const s = String(cnpj || '').replace(/\D/g, '');
  if (s.length !== 14 || /^(\d)\1{13}$/.test(s)) return false;
  const calc = (base, w) => { let sum = 0; for (let i = 0; i < w.length; i++) sum += Number(base[i]) * w[i]; const m = sum % 11; return m < 2 ? 0 : 11 - m; };
  return calc(s, [5,4,3,2,9,8,7,6,5,4,3,2]) === Number(s[12]) && calc(s, [6,5,4,3,2,9,8,7,6,5,4,3,2]) === Number(s[13]);
}

function applyTheme(id) {
  state.theme = THEMES.some((t) => t.id === id) ? id : 'prism';
  document.documentElement.setAttribute('data-theme', state.theme);
  localStorage.setItem('sherlock_prism_theme', state.theme);
  const meta = THEMES.find((t) => t.id === state.theme);
  const lbl = document.getElementById('themeNameLbl');
  if (lbl && meta) lbl.textContent = meta.label;
}

function cycleTheme() {
  const idx = THEMES.findIndex((t) => t.id === state.theme);
  applyTheme(THEMES[(idx + 1) % THEMES.length].id);
}

function applySolid(enabled) {
  state.solid = Boolean(enabled);
  document.documentElement.setAttribute('data-solid-panels', state.solid ? 'true' : 'false');
  localStorage.setItem('sherlock_prism_solid', state.solid ? '1' : '0');
  const btn = document.getElementById('railSolidBtn');
  if (btn) btn.classList.toggle('active', state.solid);
}

function saveHistory(moduleId, query) {
  if (!query) return;
  state.history = state.history.filter((x) => !(x.moduleId === moduleId && x.query === query));
  state.history.unshift({ moduleId, query, ts: Date.now() });
  state.history = state.history.slice(0, 24);
  try { localStorage.setItem('sherlock_prism_history', JSON.stringify(state.history)); } catch {}
}

function getHistory(moduleId) {
  return state.history.filter((x) => x.moduleId === moduleId).slice(0, 5);
}

async function recordEvidence(moduleId, target, payload) {
  state.lastModuleId = moduleId;
  state.lastResultData = payload;
  const mod = MODULES.find((m) => m.id === moduleId);
  state.dossier.unshift({
    id: `EV-${String(state.dossier.length + 1).padStart(3, '0')}`,
    moduleId,
    moduleName: mod ? mod.name : moduleId,
    target: String(target || '-').slice(0, 64),
    ts: new Date().toLocaleTimeString('pt-BR'),
    savedAt: new Date().toISOString(),
    payload
  });
  state.dossier = state.dossier.slice(0, 40);
  try { await saveEncryptedDossier(state.dossier); }
  catch (error) { showToast(error.message, 'error'); }
  updateEvidenceUI();
}

function updateEvidenceUI() {
  const badge = document.getElementById('evidenceCountBadge');
  if (badge) badge.textContent = String(state.dossier.length);
  const cid = document.getElementById('drawerCaseId');
  if (cid) cid.textContent = CASE_ID;
  const body = document.getElementById('drawerBody');
  if (!body) return;
  if (!state.dossier.length) {
    body.innerHTML = '<div class="result-empty" style="min-height:220px;"><span class="material-symbols-rounded">inventory_2</span><p class="text-xs-muted">Nenhuma evidencia registrada nesta sessao.</p></div>';
    return;
  }
  body.innerHTML = state.dossier.map((ev) => `
    <div class="dossier-item">
      <div class="dossier-item-top">
        <span class="font-mono-code text-accent" style="font-size:11px;font-weight:700;">${escapeHtml(ev.id)} • ${escapeHtml(ev.moduleName)}</span>
        <span class="font-mono-code text-xs-muted">${escapeHtml(ev.ts)}</span>
      </div>
      <p class="font-mono-code" style="font-size:12px;margin:0;word-break:break-all;">${escapeHtml(ev.target)}</p>
    </div>`).join('');
}

function renderProxyStatus() {
  const dot = document.getElementById('proxyDot');
  const lbl = document.getElementById('proxyLabel');
  const p = getProxyState();
  if (!dot || !lbl) return;
  if (p.online) {
    dot.style.background = 'var(--green)';
    dot.style.boxShadow = '0 0 8px var(--green)';
    lbl.textContent = `Proxy (${p.region} • ${p.latencyMs}ms)`;
  } else {
    dot.style.background = 'var(--orange)';
    dot.style.boxShadow = '0 0 8px var(--orange)';
    lbl.textContent = 'API indisponível (módulos locais ativos)';
  }
}

/* ==================== BOOT ANIMATION ==================== */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function runBootSequence() {
  const bootEl = document.getElementById('proxyBoot');
  if (!bootEl) return;
  const finish = () => {
    if (!bootEl.classList.contains('boot-done')) {
      bootEl.classList.add('boot-done');
      setTimeout(() => bootEl.remove(), 400);
    }
  };
  const failsafe = setTimeout(finish, 3000);

  try {
    const bar = document.getElementById('bootBar');
    const sub = document.getElementById('bootSubtitle');
    const s1 = document.getElementById('stepP2P');
    const s2 = document.getElementById('stepProxy');
    const s3 = document.getElementById('stepSig');
    const markDone = (el, txt) => {
      el.classList.remove('active');
      el.classList.add('done');
      const ic = el.querySelector('[data-step-icon]');
      if (ic) { ic.className = 'boot-step-txt text-green'; ic.textContent = txt; }
    };
    const markAct = (el) => {
      el.classList.add('active');
      const ic = el.querySelector('[data-step-icon]');
      if (ic) { ic.className = 'material-symbols-rounded spinner boot-step-ic'; ic.textContent = 'refresh'; }
    };

    bar.style.width = '34%';
    const [loaded] = await Promise.all([loadEncryptedDossier(), sleep(220)]);
    state.dossier = loaded;
    updateEvidenceUI();
    markDone(s1, 'Pronto');

    markAct(s2);
    bar.style.width = '72%';
    sub.textContent = 'Validando tunel serverless (/api/proxy)...';
    const [proxyState] = await Promise.all([initRemoteProxy(), sleep(320)]);
    renderProxyStatus();
    markDone(s2, proxyState.online ? `Vercel (${proxyState.region})` : 'Modo Local');

    markAct(s3);
    bar.style.width = '96%';
    sub.textContent = 'Preparando a sessão e verificações de rede...';
    await sleep(180);
    markDone(s3, 'Pronto');

    bar.style.width = '100%';
    await sleep(180);
  } catch {} finally {
    clearTimeout(failsafe);
    finish();
  }
}

/* ==================== NAVIGATION & BENTO OVERVIEW ==================== */
function navigate(id) {
  closeMobileDrawer();
  closeCmdPalette();
  window.location.hash = id ? `#${id}` : '';
}

function renderRailAndMobile(activeHash) {
  const rail = document.getElementById('railNav');
  if (rail) {
    rail.innerHTML = `
      <button type="button" class="rail-btn${activeHash === '' ? ' active' : ''}" data-nav="" title="Central de Inteligencia">
        <span class="material-symbols-rounded">dashboard</span>
      </button>
      <div class="rail-divider"></div>
      ${MODULES.map((m) => `
        <button type="button" class="rail-btn${activeHash === m.id ? ' active' : ''}" data-nav="${m.id}" title="${escapeHtml(m.name)} (${escapeHtml(m.io)})">
          <span class="material-symbols-rounded">${m.icon}</span>
        </button>`).join('')}`;
  }
  const mob = document.getElementById('mobileNavBody');
  if (mob) {
    mob.innerHTML = `
      <button type="button" class="btn-soft${activeHash === '' ? ' text-accent' : ''}" data-nav="">
        <span class="material-symbols-rounded">dashboard</span> Central de Inteligencia
      </button>
      ${SECTORS.map((sec) => `
        <div class="section-sub" style="margin:10px 4px 4px;">${escapeHtml(sec.title)}</div>
        ${MODULES.filter((m) => m.sector === sec.id).map((m) => `
          <button type="button" class="btn-soft${activeHash === m.id ? ' text-accent' : ''}" data-nav="${m.id}">
            <span class="material-symbols-rounded">${m.icon}</span> ${escapeHtml(m.name)}
          </button>`).join('')}`).join('')}`;
  }
}

function routeSmartTarget(rawInput) {
  const val = rawInput.trim();
  if (!val) return;
  const digits = val.replace(/\D/g, '');
  if (digits.length === 14 && isValidCnpj(digits)) { state.pendingQuery = { moduleId: 'cnpj', value: digits }; return navigate('cnpj'); }
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(val)) { state.pendingQuery = { moduleId: 'virustotal', value: val }; return navigate('virustotal'); }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(val)) { state.pendingQuery = { moduleId: 'proxyvpn', value: val }; return navigate('proxyvpn'); }
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) { state.pendingQuery = { moduleId: 'breach', value: val }; return navigate('breach'); }
  if (/^https?:\/\//i.test(val)) { state.pendingQuery = { moduleId: 'scraping', value: val }; return navigate('scraping'); }
  if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val)) { state.pendingQuery = { moduleId: 'domain', value: val }; return navigate('domain'); }
  state.pendingQuery = { moduleId: 'osint', value: val };
  return navigate('osint');
}

function renderBentoGrid() {
  const grid = document.getElementById('bentoGrid');
  if (!grid) return;
  const visible = state.activeHomeSector === 'all' ? SECTORS : SECTORS.filter((s) => s.id === state.activeHomeSector);
  grid.innerHTML = visible.map((sec) => {
    const items = MODULES.filter((m) => m.sector === sec.id);
    return `
      <section class="sector-section">
        <div class="sector-head">
          <div class="sector-head-left">
            <span class="material-symbols-rounded" style="color:${sec.accent};font-size:20px;">${sec.icon}</span>
            <h2 class="sector-title">${escapeHtml(sec.title)}</h2>
          </div>
          <span class="tag t-accent">${items.length}</span>
        </div>
        <div class="bento-grid">
          ${items.map((m) => `
            <div class="glass-panel prism-edge bento-card" data-nav="${m.id}">
              <div>
                <div class="bento-top">
                  <div class="squircle-ic" style="background:${m.gradient};"><span class="material-symbols-rounded">${m.icon}</span></div>
                  <span class="tag ${m.badgeClass}">${escapeHtml(m.badge)}</span>
                </div>
                <h3 class="bento-title"><span>${escapeHtml(m.name)}</span><span class="material-symbols-rounded" style="font-size:16px;opacity:0.4;">arrow_forward</span></h3>
                <p class="bento-desc">${escapeHtml(m.summary)}</p>
              </div>
              <div class="bento-io font-mono-code">${escapeHtml(m.io)}</div>
            </div>`).join('')}
        </div>
      </section>`;
  }).join('');
}

function renderOverview(ws) {
  document.getElementById('topTitle').textContent = 'Central de Inteligencia';
  ws.innerHTML = `
    <div class="fade-in container-deck">
      <div class="glass-panel prism-edge hero-card">
        <div class="hero-top">
          <div>
            <span class="hero-overline font-mono-code">${CASE_ID} • AUTO-ROTEAMENTO DE ALVO</span>
            <h2 class="font-crest hero-title">Painel LÚMEN</h2>
            <p class="hero-sub">Cole um IP, Hash SHA-256, CNPJ, Dominio, URL, E-mail ou Username para direcionamento automatico.</p>
          </div>
          <div class="hero-quick">
            <button type="button" class="btn-soft" data-nav="proxyvpn"><span class="material-symbols-rounded text-blue">vpn_lock</span> Proxy &amp; VPN</button>
            <button type="button" class="btn-soft" data-nav="virustotal"><span class="material-symbols-rounded text-red">bug_report</span> VirusTotal</button>
            <button type="button" class="btn-soft" data-nav="custody"><span class="material-symbols-rounded text-accent">fingerprint</span> Custodia</button>
          </div>
        </div>
        <form id="smartOmniForm" class="omnibox">
          <span class="material-symbols-rounded text-accent">travel_explore</span>
          <input type="text" id="smartOmniInput" placeholder="Cole IP (VPN/Proxy), SHA-256 (VirusTotal), CNPJ, dominio, URL, e-mail ou username..." autocomplete="off" />
          <button type="submit" class="btn-accent btn-accent-auto">Rastrear</button>
        </form>
        <div class="mobile-sector-row">
          ${[['all', 'Todos (15)'], ['forense', 'Forense'], ['rede', 'Proxy & VPN'], ['sherlock', 'Sherlock'], ['web', 'Web & CNPJ']].map(([id, lbl]) => `
            <button type="button" class="btn-soft${state.activeHomeSector === id ? ' text-accent' : ''}" data-home-sector="${id}">${lbl}</button>`).join('')}
        </div>
      </div>
      <div id="bentoGrid"></div>
    </div>`;

  renderBentoGrid();
  document.getElementById('smartOmniForm').addEventListener('submit', (e) => {
    e.preventDefault();
    routeSmartTarget(document.getElementById('smartOmniInput').value);
  });
}

/* ==================== WORKBENCH HELPER ==================== */
function renderWorkbenchShell(ws, m, controlsHtml, emptyTitle, emptyDesc) {
  ws.innerHTML = `
    <div class="fade-in container-deck workbench-grid">
      <div class="glass-panel prism-edge control-panel">
        <div class="mod-head">
          <div class="squircle-ic" style="background:${m.gradient};"><span class="material-symbols-rounded">${m.icon}</span></div>
          <div>
            <h2>${escapeHtml(m.name)}</h2>
            <span class="tag ${m.badgeClass}" style="margin-top:4px;">${escapeHtml(m.badge)}</span>
          </div>
        </div>
        <p class="mod-summary">${escapeHtml(m.summary)}</p>
        <p class="mod-io font-mono-code">${escapeHtml(m.io)}</p>
        ${controlsHtml}
      </div>
      <div id="modResult" class="glass-panel result-panel">
        <div class="result-empty">
          <span class="material-symbols-rounded">${m.icon}</span>
          <p style="font-weight:700;margin:0;">${escapeHtml(emptyTitle)}</p>
          <p class="text-muted" style="font-size:12.5px;max-width:340px;margin:6px 0 0;">${escapeHtml(emptyDesc)}</p>
        </div>
      </div>
    </div>`;
  return document.getElementById('modResult');
}

/* ==================== 1. PROXY & VPN LAB ==================== */
function renderProxyVpn(ws, m) {
  const controls = `
    <div class="ios-segment">
      <button type="button" id="pvTabDetect" class="seg-btn active">Detector</button>
      <button type="button" id="pvTabVpn" class="seg-btn">VPN .ovpn</button>
      <button type="button" id="pvTabProxies" class="seg-btn">Proxies</button>
    </div>
    <form id="pvDetectForm">
      <div class="field-group">
        <label for="pvIpInput" class="field-lbl">IP ou Dominio (vazio = seu IP)</label>
        <input type="text" id="pvIpInput" class="m3-input font-mono-code" placeholder="Ex: 185.220.101.34 ou 1.1.1.1" autocomplete="off" />
      </div>
      <button type="submit" class="btn-accent"><span class="material-symbols-rounded">radar</span> Auditar IP</button>
    </form>
    <form id="pvVpnForm" class="hidden">
      <div class="field-group">
        <label for="pvVpnCountry" class="field-lbl">Filtrar Pais (VPN Gate)</label>
        <select id="pvVpnCountry" class="m3-select">
          <option value="ALL">Todos os Paises (Mais Rapidos)</option>
          <option value="US">Estados Unidos (US)</option>
          <option value="JP">Japao (JP)</option>
          <option value="KR">Coreia do Sul (KR)</option>
          <option value="GB">Reino Unido (GB)</option>
          <option value="DE">Alemanha (DE)</option>
          <option value="BR">Brasil (BR)</option>
        </select>
      </div>
      <button type="submit" class="btn-accent"><span class="material-symbols-rounded">vpn_key</span> Listar Servidores VPN</button>
    </form>
    <form id="pvProxyForm" class="hidden">
      <div class="field-group">
        <label for="pvProto" class="field-lbl">Protocolo</label>
        <select id="pvProto" class="m3-select">
          <option value="http">HTTP / HTTPS</option>
          <option value="socks4">SOCKS4</option>
          <option value="socks5">SOCKS5</option>
        </select>
      </div>
      <div class="field-group">
        <label for="pvCountry" class="field-lbl">Pais</label>
        <select id="pvCountry" class="m3-select">
          <option value="all">Global (Todos)</option>
          <option value="BR">Brasil (BR)</option>
          <option value="US">Estados Unidos (US)</option>
          <option value="DE">Alemanha (DE)</option>
          <option value="GB">Reino Unido (GB)</option>
        </select>
      </div>
      <button type="submit" class="btn-accent"><span class="material-symbols-rounded">dns</span> Buscar Proxies Live</button>
    </form>`;

  const resEl = renderWorkbenchShell(ws, m, controls, 'Laboratorio Proxy & VPN', 'Audite anonimato de IPs (VPN/Proxy/Tor), baixe perfis .ovpn do VPN Gate ou extraia proxies HTTP/SOCKS via servidor Vercel.');

  const tabs = [
    [document.getElementById('pvTabDetect'), document.getElementById('pvDetectForm')],
    [document.getElementById('pvTabVpn'), document.getElementById('pvVpnForm')],
    [document.getElementById('pvTabProxies'), document.getElementById('pvProxyForm')]
  ];
  tabs.forEach(([btn], idx) => btn.addEventListener('click', () => {
    tabs.forEach(([b, f], i) => { b.classList.toggle('active', i === idx); f.classList.toggle('hidden', i !== idx); });
  }));

  document.getElementById('pvDetectForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = document.getElementById('pvIpInput').value.trim();
    resEl.innerHTML = renderLoading('Auditando VPN / Proxy / Tor no servidor...');
    try {
      const d = await callApi('/api/intel', { action: 'vpn_detect', target });
      const r = d.report, f = r.flags;
      const verdict = f.tor ? 'NO DE SAIDA TOR DETECTADO' : (f.vpn ? `VPN DETECTADA (${r.vpnService})` : (f.proxy ? 'PROXY DETECTADO' : (f.datacenter ? 'DATACENTER / HOSTING' : 'IP RESIDENCIAL / LIMPO')));
      const bType = (f.tor || f.vpn || f.proxy) ? 'err' : (f.datacenter ? 'warn' : 'ok');
      await recordEvidence('proxyvpn', `Detector: ${r.ip}`, d);
      const card = (lbl, on) => `<div class="stat-card${on ? ' stat-card-danger' : ''}"><span class="stat-val ${on ? 'text-red' : 'text-green'}">${on ? 'SIM' : 'NAO'}</span><span class="stat-lbl">${lbl}</span></div>`;
      resEl.innerHTML = `
        ${renderResHeader(`Auditoria de Anonimato (${r.ip})`, d.provider)}
        ${renderBanner(verdict, bType)}
        <div class="stat-grid">${card('VPN', f.vpn)}${card('Proxy', f.proxy)}${card('Tor', f.tor)}${card('Datacenter', f.datacenter)}${card('Abuso', f.abuser)}</div>
        ${renderKvList([
          ['IP', r.ip, true, true],
          ['Indice Anonimato', `${r.score} / 100`, false, true],
          ['Servico VPN/Proxy', r.vpnService, true],
          ['Organizacao / ISP', r.org, true],
          ['ASN', r.asn, true, true],
          ['Localizacao', `${r.city} / ${r.country}`]
        ])}
        ${r.latitude != null && r.longitude != null ? renderMapBlock(r.latitude, r.longitude, `Localizacao de ${r.ip}`) : ''}`;
    } catch (err) { resEl.innerHTML = renderBanner(err.message, 'err'); }
  });

  document.getElementById('pvVpnForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const country = document.getElementById('pvVpnCountry').value;
    resEl.innerHTML = renderLoading('Coletando servidores OpenVPN ativos do VPN Gate...');
    try {
      const d = await callApi('/api/intel', { action: 'vpngate', country });
      await recordEvidence('proxyvpn', `VPN Gate (${country})`, { total: d.total, servers: d.servers.map(({ ovpnB64, ...rest }) => rest) });
      resEl.innerHTML = `
        ${renderResHeader(`${d.servers.length} Servidores OpenVPN Ativos`, d.provider)}
        <div class="kv-list scroll-list">
          ${d.servers.map((s, idx) => `
            <div class="kv-item">
              <div class="kv-left">
                <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;">
                  <span class="font-mono-code" style="font-size:12.5px;font-weight:700;">${escapeHtml(s.ip)}</span>
                  <span class="tag t-accent">${escapeHtml(s.countryShort)}</span>
                  <span class="tag t-ok">${escapeHtml(s.speedMbps)} Mbps</span>
                </div>
                <span class="text-xs-muted">${escapeHtml(s.countryLong)} • Ping: ${escapeHtml(s.ping)} • Sessoes: ${escapeHtml(s.sessions)}</span>
              </div>
              <div class="res-actions">
                <button type="button" class="btn-soft btn-xs" data-copy-val="${escapeHtml(s.ip)}"><span class="material-symbols-rounded">content_copy</span></button>
                <button type="button" class="btn-soft btn-xs text-accent" data-ovpn-idx="${idx}"><span class="material-symbols-rounded">download</span> .ovpn</button>
              </div>
            </div>`).join('')}
        </div>`;
      resEl.querySelectorAll('[data-ovpn-idx]').forEach((btn) => btn.addEventListener('click', () => {
        const s = d.servers[Number(btn.getAttribute('data-ovpn-idx'))];
        if (!s) return;
        const url = URL.createObjectURL(new Blob([atob(s.ovpnB64)], { type: 'application/x-openvpn-profile' }));
        const a = document.createElement('a'); a.href = url; a.download = `vpngate-${s.countryShort.toLowerCase()}-${s.ip}.ovpn`; a.click(); URL.revokeObjectURL(url);
      }));
    } catch (err) { resEl.innerHTML = renderBanner(err.message, 'err'); }
  });

  document.getElementById('pvProxyForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const protocol = document.getElementById('pvProto').value;
    const country = document.getElementById('pvCountry').value;
    resEl.innerHTML = renderLoading('Coletando lista ao vivo de proxies publicos...');
    try {
      const d = await callApi('/api/intel', { action: 'proxies', protocol, country });
      const plain = d.proxies.map((p) => p.addr).join('\n');
      await recordEvidence('proxyvpn', `Proxies ${protocol.toUpperCase()} (${country})`, d);
      resEl.innerHTML = `
        ${renderResHeader(`${d.proxies.length} Proxies (${protocol.toUpperCase()})`, d.provider, `<button type="button" class="btn-soft" data-copy-val="${escapeHtml(plain)}">Copiar Lista</button>`)}
        <div class="kv-list scroll-list">
          ${d.proxies.map((p) => `
            <div class="kv-item">
              <div class="kv-left">
                <span class="font-mono-code" style="font-size:12.5px;font-weight:700;display:block;">${escapeHtml(p.addr)}</span>
                <span class="text-xs-muted">${escapeHtml(p.protocol)} • ${escapeHtml(p.country)}${p.latency !== '-' ? ` • ${escapeHtml(p.latency)}` : ''}</span>
              </div>
              <button type="button" class="btn-soft btn-xs" data-copy-val="${escapeHtml(p.addr)}"><span class="material-symbols-rounded">content_copy</span></button>
            </div>`).join('')}
        </div>`;
    } catch (err) { resEl.innerHTML = renderBanner(err.message, 'err'); }
  });

  if (state.pendingQuery?.moduleId === 'proxyvpn') {
    document.getElementById('pvIpInput').value = state.pendingQuery.value;
    state.pendingQuery = null;
    setTimeout(() => document.getElementById('pvDetectForm').requestSubmit(), 80);
  }
}

/* ==================== 2. VIRUSTOTAL ==================== */
function detectVtType(val) {
  const v = val.trim();
  if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(v)) return 'hash';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ip';
  if (/^https?:\/\//i.test(v)) return 'url';
  return 'domain';
}

function renderVirusTotal(ws, m) {
  const p = getProxyState();
  const controls = `
    <input type="file" id="vtFile" class="hidden" />
    <div id="vtDrop" class="dropzone">
      <span class="material-symbols-rounded">shield</span>
      <p style="font-size:12.5px;font-weight:600;margin:0;">Soltar arquivo (SHA-256 local)</p>
    </div>
    <form id="vtForm">
      <div class="field-group">
        <label for="vtTarget" class="field-lbl">Hash, URL, Dominio ou IP</label>
        <input type="text" id="vtTarget" class="m3-input font-mono-code" placeholder="SHA-256, IPv4, dominio ou URL" required autocomplete="off" />
      </div>
      ${p.virustotalServerKey
        ? renderBanner('VT_API_KEY ativa no servidor Vercel.', 'ok')
        : `<div class="field-group"><label for="vtKey" class="field-lbl">Chave VT Pessoal (Opcional)</label><input type="password" id="vtKey" class="m3-input font-mono-code" placeholder="Caso VT_API_KEY nao esteja na Vercel" autocomplete="off" /></div>`}
      <button type="submit" class="btn-accent"><span class="material-symbols-rounded">radar</span> Escanear Ameaca</button>
    </form>`;

  const resEl = renderWorkbenchShell(ws, m, controls, 'Painel Threat Intel', 'Consulta Hash, Dominio, IP ou URL diretamente na API v3 do VirusTotal via servidor Vercel.');
  const fi = document.getElementById('vtFile'), dz = document.getElementById('vtDrop'), ti = document.getElementById('vtTarget'), form = document.getElementById('vtForm');

  const hashFile = async (f) => {
    ti.value = 'Calculando SHA-256...';
    const buf = await f.arrayBuffer();
    ti.value = await safeSha256Hex(buf);
    form.requestSubmit();
  };
  dz.addEventListener('click', () => fi.click());
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('drag-over'); if (e.dataTransfer.files[0]) hashFile(e.dataTransfer.files[0]); });
  fi.addEventListener('change', () => { if (fi.files[0]) hashFile(fi.files[0]); });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = ti.value.trim();
    const type = detectVtType(target);
    const keyEl = document.getElementById('vtKey');
    const hdr = keyEl && keyEl.value.trim() ? { 'X-VT-Key': keyEl.value.trim() } : {};
    resEl.innerHTML = renderLoading(`Consultando VirusTotal (${type.toUpperCase()})...`);
    try {
      const d = await callApi('/api/intel', { action: 'virustotal', type, target }, hdr);
      await recordEvidence('virustotal', target, d);
      const guiBtn = d.guiUrl ? `<a href="${escapeHtml(d.guiUrl)}" target="_blank" rel="noopener noreferrer" class="btn-soft">Abrir VT</a>` : '';
      if (!d.found) {
        resEl.innerHTML = `${renderResHeader('Sem registro no VirusTotal', d.provider || 'VirusTotal API v3', guiBtn)}${renderBanner(d.message, 'info')}`;
        return;
      }
      if (d.fallback) {
        const pulses = (d.pulses || []).map((p) => `<span class="tag t-warn font-mono-code">${escapeHtml(p)}</span>`).join('');
        resEl.innerHTML = `
          ${renderResHeader('Threat Intel (AlienVault OTX)', d.provider, guiBtn)}
          ${d.vtNotice ? renderBanner(d.vtNotice, 'warn') : ''}
          ${renderBanner(d.pulseCount > 0 ? `ALERTA: ${d.pulseCount} pulso(s) de ameaca registrados no OTX.` : 'Nenhum pulso malicioso encontrado no AlienVault OTX.', d.pulseCount > 0 ? 'err' : 'ok')}
          ${renderKvList([
            ['Alvo', d.target, true, true],
            ['Tipo', d.type.toUpperCase()],
            ['Pulsos OTX', String(d.pulseCount), false, true],
            ['Pais', d.country || '-'],
            ['ASN', d.asn || '-', true, true]
          ])}
          ${pulses ? `<div class="section-sub text-orange">Relatorios OTX (${d.pulses.length})</div><div class="chip-wrap">${pulses}</div>` : ''}`;
        return;
      }
      const det = (d.detections || []).map((x) => `<span class="tag t-err font-mono-code">${escapeHtml(x.engine)}: ${escapeHtml(x.result)}</span>`).join('');
      resEl.innerHTML = `
        ${renderResHeader('Laudo VirusTotal v3', d.provider || 'VirusTotal API v3', guiBtn)}
        <div class="stat-grid">
          <div class="stat-card"><span class="stat-val text-red font-mono-code">${d.stats.malicious}</span><span class="stat-lbl">Maliciosos</span></div>
          <div class="stat-card"><span class="stat-val text-orange font-mono-code">${d.stats.suspicious}</span><span class="stat-lbl">Suspeitos</span></div>
          <div class="stat-card"><span class="stat-val text-green font-mono-code">${d.stats.harmless}</span><span class="stat-lbl">Inofensivos</span></div>
          <div class="stat-card"><span class="stat-val font-mono-code">${d.stats.undetected}</span><span class="stat-lbl">Indetectados</span></div>
        </div>
        ${renderKvList([
          ['Alvo', d.target, true, true],
          ['Tipo', d.type.toUpperCase()],
          ['Reputacao', String(d.reputation)],
          ['Nome / AS Owner', d.meaningfulName || '-'],
          ['Ultima Analise', d.lastAnalysisDate || '-']
        ])}
        ${det ? `<div class="section-sub text-red">Deteccoes (${d.detections.length})</div><div class="chip-wrap">${det}</div>` : ''}`;
    } catch (err) { resEl.innerHTML = renderBanner(err.message, 'err'); }
  });

  if (state.pendingQuery?.moduleId === 'virustotal') {
    ti.value = state.pendingQuery.value;
    state.pendingQuery = null;
    setTimeout(() => form.requestSubmit(), 80);
  }
}

/* ==================== 3. CUSTODIA & HEX (WEB WORKER) ==================== */
function renderCustody(ws, m) {
  const controls = `
    <input type="file" id="custFile" class="hidden" />
    <div id="custDrop" class="dropzone">
      <span class="material-symbols-rounded">upload_file</span>
      <p style="font-size:12.5px;font-weight:600;margin:0;">Arrastar ou selecionar evidencia</p>
      <p class="text-xs-muted" style="margin:4px 0 0;">100% local em Web Worker dedicado</p>
    </div>
    <div class="field-group">
      <label for="custExpected" class="field-lbl">SHA-256 Esperado (Opcional)</label>
      <input type="text" id="custExpected" class="m3-input font-mono-code" placeholder="Validar integridade" autocomplete="off" />
    </div>`;

  const resEl = renderWorkbenchShell(ws, m, controls, 'Certificado de Custodia', 'Calcula MD5, SHA-1, SHA-256, SHA-512, Magic Bytes, Entropia de Shannon, Hex Dump paginado e IOCs sem travar o navegador.');
  const fi = document.getElementById('custFile'), dz = document.getElementById('custDrop');

  const process = async (file) => {
    if (!file) return;
    const expected = document.getElementById('custExpected').value.trim().toLowerCase();
    resEl.innerHTML = renderLoading(`Processando ${file.name} (${formatBytes(file.size)}) no Web Worker...`);
    const buf = await file.arrayBuffer();
    const w = getWorker();
    w.onmessage = async (ev) => {
      const msg = ev.data || {};
      if (!msg.ok) { resEl.innerHTML = renderBanner(msg.error || 'Erro no Worker.', 'err'); return; }
      if (msg.cmd === 'analyze') {
        const d = msg.data;
        state.hexOffset = 0; state.hexTotalBytes = d.size;
        await recordEvidence('custody', d.filename, { ...d, hexDump: { totalBytes: d.size } });
        let banners = d.magic.mismatch
          ? renderBanner(`ALERTA DE SPOOFING: extensao ".${d.magic.extension}" diverge da assinatura real (${d.magic.type}).`, 'err')
          : renderBanner(`Assinatura verificada: ${d.magic.type}`, 'ok');
        if (expected) {
          banners += expected === d.hashes.sha256.toLowerCase()
            ? renderBanner('INTEGRIDADE CONFIRMADA: SHA-256 identico ao esperado.', 'ok')
            : renderBanner('DIVERGENCIA: SHA-256 nao corresponde ao valor esperado.', 'err');
        }
        resEl.innerHTML = `
          ${renderResHeader('Certificado de Custodia', 'Web Worker Local', `<button type="button" class="btn-soft" data-vt-hash="${escapeHtml(d.hashes.sha256)}">VirusTotal</button>`)}
          ${banners}
          ${renderKvList([
            ['Arquivo', d.filename, true],
            ['Tamanho', `${formatBytes(d.size)} (${d.size.toLocaleString('pt-BR')} bytes)`],
            ['Magic Bytes', d.magic.type, true],
            ['Cabecalho (Hex)', d.magic.headHex, true, true],
            ['Entropia de Shannon', `${d.entropy.bits} bits/byte (${d.entropy.assessment})`, false, true],
            ['SHA-256', d.hashes.sha256, true, true],
            ['SHA-512', d.hashes.sha512, true, true],
            ['SHA-1', d.hashes.sha1, true, true],
            ['MD5', d.hashes.md5, true, true]
          ])}
          <div class="res-header" style="border:0;padding:0;margin:14px 0 8px;">
            <span class="section-sub" style="margin:0;">Visualizador Hexadecimal</span>
            <div class="res-actions">
              <button type="button" id="hxPrev" class="btn-soft btn-xs">-2 KB</button>
              <span id="hxRange" class="font-mono-code text-xs-muted">0 a ${Math.min(2048, d.size)} / ${d.size}</span>
              <button type="button" id="hxNext" class="btn-soft btn-xs">+2 KB</button>
            </div>
          </div>
          <pre id="hxBox" class="code-viewer">${escapeHtml(d.hexDump.text)}</pre>
          <div class="section-sub">IOCs &amp; Strings (${d.extracted.strings.length})</div>
          ${renderKvList([
            ['URLs', d.extracted.iocs.urls.join(', ') || '-', d.extracted.iocs.urls.length > 0, true],
            ['E-mails', d.extracted.iocs.emails.join(', ') || '-', d.extracted.iocs.emails.length > 0, true],
            ['IPs', d.extracted.iocs.ips.join(', ') || '-', d.extracted.iocs.ips.length > 0, true]
          ])}`;
        document.getElementById('hxPrev').addEventListener('click', () => { state.hexOffset = Math.max(0, state.hexOffset - 2048); w.postMessage({ cmd: 'hexPage', offset: state.hexOffset, length: 2048 }); });
        document.getElementById('hxNext').addEventListener('click', () => { if (state.hexOffset + 2048 < state.hexTotalBytes) { state.hexOffset += 2048; w.postMessage({ cmd: 'hexPage', offset: state.hexOffset, length: 2048 }); } });
      } else if (msg.cmd === 'hexPage') {
        const b = document.getElementById('hxBox'), r = document.getElementById('hxRange');
        if (b) b.textContent = msg.data.text;
        if (r) r.textContent = `${msg.data.offset} a ${msg.data.offset + msg.data.shownBytes} / ${msg.data.totalBytes}`;
      }
    };
    w.postMessage({ cmd: 'analyze', buffer: buf, filename: file.name, mimeType: file.type, lastModified: file.lastModified }, [buf]);
  };

  dz.addEventListener('click', () => fi.click());
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('drag-over'); if (e.dataTransfer.files[0]) process(e.dataTransfer.files[0]); });
  fi.addEventListener('change', () => { if (fi.files[0]) process(fi.files[0]); });
}

/* ==================== 4. METADADOS EXIF ==================== */
function renderMetadata(ws, m) {
  const controls = `
    <input type="file" id="metaFile" accept="image/*" class="hidden" />
    <div id="metaDrop" class="dropzone">
      <span class="material-symbols-rounded">add_photo_alternate</span>
      <p style="font-size:12.5px;font-weight:600;margin:0;">Selecionar fotografia original</p>
      <p class="text-xs-muted" style="margin:4px 0 0;">JPEG, PNG, WebP (leitura local)</p>
    </div>
    <div id="metaPrevBox" class="hidden" style="margin-top:12px;">
      <img id="metaPrevImg" src="" alt="Previa" style="width:100%;max-height:200px;object-fit:contain;border-radius:12px;border:1px solid var(--border);" />
    </div>`;

  const resEl = renderWorkbenchShell(ws, m, controls, 'Laudo Forense EXIF / GPS', 'Extrai modelo de camera, datas, software, SHA-256 e plota coordenadas GPS no mapa.');
  const fi = document.getElementById('metaFile'), dz = document.getElementById('metaDrop');

  const analyze = async (file) => {
    const objUrl = URL.createObjectURL(file);
    document.getElementById('metaPrevBox').classList.remove('hidden');
    document.getElementById('metaPrevImg').src = objUrl;
    resEl.innerHTML = renderLoading('Lendo cabecalhos binarios EXIF e SHA-256...');
    try {
      const [data, buf] = await Promise.all([parseImageMetadata(file), file.arrayBuffer()]);
      const sha256 = await safeSha256Hex(buf);
      let address = null;
      if (data.gps) {
        try {
          const rg = await callApi('/api/intel', { action: 'reverse_geo', lat: data.gps.latitude, lon: data.gps.longitude });
          address = rg.address;
        } catch {}
      }
      await recordEvidence('metadata', file.name, { ...data, sha256, address });
      const tags = Object.entries(data.tags);
      resEl.innerHTML = `
        ${renderResHeader(`Laudo EXIF (${data.format})`, 'Parser Binario Local', `<button type="button" class="btn-soft" data-vt-hash="${escapeHtml(sha256)}">VirusTotal</button>`)}
        ${data.alerts.map((a) => renderBanner(a, 'warn')).join('')}
        ${data.gps ? renderBanner(`GPS Localizado: ${address || `${data.gps.latitude}, ${data.gps.longitude}`}`, 'ok') : renderBanner('Sem coordenadas GPS embutidas nesta imagem.', 'info')}
        ${renderKvList([
          ['Arquivo', data.filename, true],
          ['Formato', data.format],
          ['Tamanho', formatBytes(data.size)],
          ['Dimensoes', data.dimensions ? `${data.dimensions.width} x ${data.dimensions.height} px` : '-'],
          ['SHA-256', sha256, true, true]
        ])}
        ${data.gps ? renderMapBlock(data.gps.latitude, data.gps.longitude, 'Local da Captura') : ''}
        <div class="section-sub">Tags Extraidas (${tags.length})</div>
        ${tags.length ? renderKvList(tags.map(([k, v]) => [k, Array.isArray(v) ? v.join(', ') : String(v), true])) : '<p class="text-xs-muted">Nenhum metadado EXIF/PNG presente.</p>'}`;
    } catch (err) { resEl.innerHTML = renderBanner(err.message, 'err'); }
  };

  dz.addEventListener('click', () => fi.click());
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('drag-over'); if (e.dataTransfer.files[0]) analyze(e.dataTransfer.files[0]); });
  fi.addEventListener('change', () => { if (fi.files[0]) analyze(fi.files[0]); });
}

/* ==================== 5. ANALISE ELA ==================== */
function renderEla(ws, m) {
  const controls = `
    <input type="file" id="elaFile" accept="image/*" class="hidden" />
    <div id="elaDrop" class="dropzone">
      <span class="material-symbols-rounded text-red">image_search</span>
      <p style="font-size:12.5px;font-weight:600;margin:0;">Enviar imagem para ELA</p>
    </div>
    <div class="field-group">
      <div class="range-row"><span class="text-muted">Ganho (Amplificacao)</span><span id="elaSv" class="font-mono-code text-accent">15x</span></div>
      <input type="range" id="elaS" class="prism-range" min="1" max="35" value="15" />
    </div>
    <div class="field-group">
      <div class="range-row"><span class="text-muted">Qualidade JPEG</span><span id="elaQv" class="font-mono-code text-accent">90%</span></div>
      <input type="range" id="elaQ" class="prism-range" min="60" max="98" value="90" />
    </div>`;

  const resEl = renderWorkbenchShell(ws, m, controls, 'Laboratorio ELA', 'Carregue uma foto para gerar o mapa de diferenca de compressao em tempo real.');
  const fi = document.getElementById('elaFile'), dz = document.getElementById('elaDrop'), sEl = document.getElementById('elaS'), qEl = document.getElementById('elaQ');

  const exec = async () => {
    if (!state.elaFile) return;
    resEl.innerHTML = renderLoading('Calculando mapa ELA no Canvas...');
    try {
      const out = await runErrorLevelAnalysis(state.elaFile, { quality: Number(qEl.value), scale: Number(sEl.value) });
      await recordEvidence('ela', state.elaFile.name, { filename: state.elaFile.name, width: out.width, height: out.height, stats: out.stats });
      resEl.innerHTML = `
        ${renderResHeader('Mapa Forense ELA', 'Canvas Local', `<button type="button" id="elaTog" class="btn-soft">Ver Original</button><a href="${out.elaDataUrl}" download="sherlock-ela.png" class="btn-soft">PNG</a>`)}
        <div class="ela-box">
          <img id="elaImgMap" src="${out.elaDataUrl}" alt="Mapa ELA" />
          <img id="elaImgOrig" src="${out.originalDataUrl}" alt="Original" class="hidden" />
        </div>
        ${renderBanner(out.stats.interpretation, out.stats.highVariancePct > 12 ? 'warn' : 'info')}
        ${renderKvList([
          ['Arquivo', state.elaFile.name],
          ['Dimensoes', `${out.width} x ${out.height} px`],
          ['Erro Medio (RGB)', String(out.stats.meanError), false, true],
          ['Erro Maximo', String(out.stats.maxError), false, true],
          ['Alta Variancia', `${out.stats.highVariancePct}%`, false, true]
        ])}`;
      let showOrig = false;
      document.getElementById('elaTog').addEventListener('click', (ev) => {
        showOrig = !showOrig;
        document.getElementById('elaImgMap').classList.toggle('hidden', showOrig);
        document.getElementById('elaImgOrig').classList.toggle('hidden', !showOrig);
        ev.currentTarget.textContent = showOrig ? 'Ver Mapa ELA' : 'Ver Original';
      });
    } catch (err) { resEl.innerHTML = renderBanner(err.message, 'err'); }
  };

  dz.addEventListener('click', () => fi.click());
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('drag-over'); if (e.dataTransfer.files[0]) { state.elaFile = e.dataTransfer.files[0]; exec(); } });
  fi.addEventListener('change', () => { if (fi.files[0]) { state.elaFile = fi.files[0]; exec(); } });
  sEl.addEventListener('input', () => { document.getElementById('elaSv').textContent = `${sEl.value}x`; });
  qEl.addEventListener('input', () => { document.getElementById('elaQv').textContent = `${qEl.value}%`; });
  sEl.addEventListener('change', exec);
  qEl.addEventListener('change', exec);
}

/* ==================== 6. DECODIFICADOR ==================== */
function renderDecoder(ws, m) {
  const controls = `
    <form id="decForm">
      <div class="field-group">
        <label for="decMode" class="field-lbl">Motor de Decodificacao</label>
        <select id="decMode" class="m3-select">
          <option value="jwt">Inspecionar JWT (Header + Payload)</option>
          <option value="b64_decode">Base64 / Base64URL -> Texto</option>
          <option value="b64_encode">Texto -> Base64</option>
          <option value="hex_decode">Hexadecimal -> Texto</option>
          <option value="hex_encode">Texto -> Hexadecimal</option>
          <option value="url_decode">URL Decode</option>
          <option value="url_encode">URL Encode</option>
          <option value="rot13">ROT13</option>
          <option value="timestamp">Unix Epoch <-> Data ISO</option>
          <option value="cidr">Calculadora IPv4 / CIDR</option>
        </select>
      </div>
      <div class="field-group">
        <label for="decIn" class="field-lbl">Artefato de Entrada</label>
        <textarea id="decIn" class="m3-textarea font-mono-code" placeholder="Cole JWT, Base64, Hex, Epoch ou CIDR..." required></textarea>
      </div>
      <button type="submit" class="btn-accent"><span class="material-symbols-rounded">auto_fix_high</span> Processar</button>
    </form>`;

  const resEl = renderWorkbenchShell(ws, m, controls, 'Decodificador Forense', 'Inspecione tokens JWT, converta Base64/Hex/Epoch ou calcule faixas CIDR localmente.');
  document.getElementById('decForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const mode = document.getElementById('decMode').value;
    const raw = document.getElementById('decIn').value;
    try {
      if (mode === 'jwt') {
        const jwt = decodeJwt(raw);
        await recordEvidence('decoder', 'JWT', jwt);
        resEl.innerHTML = `
          ${renderResHeader('Inspecao JWT', 'Decodificador Local')}
          ${jwt.warnings.map((w) => renderBanner(w, w.startsWith('CRITICO') ? 'err' : 'info')).join('')}
          <div class="section-sub">Header</div>
          <pre class="code-viewer">${escapeHtml(JSON.stringify(jwt.header, null, 2))}</pre>
          <div class="section-sub">Payload</div>
          <pre class="code-viewer">${escapeHtml(JSON.stringify(jwt.payload, null, 2))}</pre>`;
      } else {
        const out = transformText(mode, raw);
        await recordEvidence('decoder', mode, { mode, output: out });
        resEl.innerHTML = `
          ${renderResHeader('Saida Decodificada', mode, `<button type="button" class="btn-soft" data-copy-val="${escapeHtml(out)}">Copiar</button>`)}
          <pre class="code-viewer">${escapeHtml(out)}</pre>`;
      }
    } catch (err) { resEl.innerHTML = renderBanner(err.message, 'err'); }
  });
}

/* ==================== 7. MODULOS DE CONSULTA UNICA ==================== */
function renderQueryModule(ws, m) {
  const hist = getHistory(m.id);
  const controls = `
    <form id="qForm">
      <div class="field-group">
        <label for="qInput" class="field-lbl">${escapeHtml(m.placeholder || 'Alvo')}</label>
        <input type="text" id="qInput" class="m3-input" placeholder="${escapeHtml(m.placeholder || '')}" ${m.optional ? '' : 'required'} autocomplete="off" />
      </div>
      <button type="submit" class="btn-accent"><span class="material-symbols-rounded">search</span> ${m.id === 'dork' ? 'Gerar Dorks' : 'Investigar'}</button>
    </form>
    ${hist.length ? `<div class="history-box"><span class="field-lbl">Recentes</span><div class="chip-wrap">${hist.map((h) => `<button type="button" class="btn-soft btn-xs font-mono-code" data-fill="${escapeHtml(h.query)}">${escapeHtml(h.query)}</button>`).join('')}</div></div>` : ''}`;

  const resEl = renderWorkbenchShell(ws, m, controls, 'Painel de Evidencias', 'Informe o alvo ao lado para executar com seguranca via servidor Vercel.');
  const inp = document.getElementById('qInput');
  if (m.digits) inp.addEventListener('input', () => { inp.value = inp.value.replace(/\D/g, ''); });

  document.getElementById('qForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const val = inp.value.trim();
    if (val) saveHistory(m.id, val);

    if (m.id === 'dork') {
      const g = (s) => `https://www.google.com/search?q=${encodeURIComponent(s)}`;
      const groups = [
        ['Documentos & Pastes', g(`"${val}" (filetype:pdf OR filetype:xlsx OR filetype:docx OR site:pastebin.com OR site:docs.google.com)`), [
          ['PDFs Indexados', g(`"${val}" filetype:pdf`)],
          ['Planilhas XLS/CSV', g(`"${val}" (filetype:xlsx OR filetype:xls OR filetype:csv)`)],
          ['Word / TXT', g(`"${val}" (filetype:docx OR filetype:doc OR filetype:txt)`)],
          ['Diretorios Abertos', g(`intitle:"index of" "${val}"`)],
          ['Pastebin / Gist', g(`"${val}" (site:pastebin.com OR site:gist.github.com)`)],
          ['Google Docs / Drive', g(`"${val}" (site:docs.google.com OR site:drive.google.com)`)]
        ]],
        ['Redes Sociais', g(`"${val}" (site:instagram.com OR site:tiktok.com OR site:x.com OR site:facebook.com OR site:linkedin.com OR site:youtube.com)`), [
          ['Instagram', g(`site:instagram.com "${val}"`)],
          ['TikTok', g(`site:tiktok.com "${val}"`)],
          ['X (Twitter)', g(`site:x.com "${val}"`)],
          ['Facebook', g(`site:facebook.com "${val}"`)],
          ['LinkedIn', g(`site:linkedin.com "${val}"`)],
          ['YouTube', g(`site:youtube.com "${val}"`)]
        ]],
        ['Sites Adultos', g(`"${val}" (site:onlyfans.com OR site:privacy.com.br OR site:fansly.com OR site:pornhub.com OR site:xvideos.com)`), [
          ['OnlyFans', g(`site:onlyfans.com "${val}"`)],
          ['Privacy', g(`site:privacy.com.br "${val}"`)],
          ['Fansly', g(`site:fansly.com "${val}"`)],
          ['Pornhub', g(`site:pornhub.com "${val}"`)],
          ['XVideos', g(`site:xvideos.com "${val}"`)]
        ]],
        ['Namoro & Apostas', g(`"${val}" (site:tinder.com OR site:badoo.com OR site:betano.com OR site:bet365.com OR site:blaze.com OR site:stake.com)`), [
          ['Tinder', g(`site:tinder.com "${val}"`)],
          ['Badoo', g(`site:badoo.com "${val}"`)],
          ['Betano', g(`site:betano.com "${val}"`)],
          ['Bet365', g(`site:bet365.com "${val}"`)],
          ['Blaze', g(`site:blaze.com "${val}"`)],
          ['Stake', g(`site:stake.com "${val}"`)]
        ]]
      ];
      await recordEvidence('dork', val, { alvo: val, groups });
      resEl.innerHTML = `${renderResHeader(`Dorks: ${val}`, '4 Categorias Forenses')}${groups.map(([t, geral, items]) => `
        <div class="res-header" style="border:0;padding:0;margin:14px 0 6px;">
          <span class="section-sub" style="margin:0;">${escapeHtml(t)}</span>
          <a href="${escapeHtml(geral)}" target="_blank" rel="noopener noreferrer" class="btn-soft btn-xs">Dork Geral</a>
        </div>
        <div class="kv-list">${items.map(([n, u]) => `<a href="${escapeHtml(u)}" target="_blank" rel="noopener noreferrer" class="kv-item"><span>${escapeHtml(n)}</span><span class="tag t-accent">Abrir</span></a>`).join('')}</div>`).join('')}`;
      return;
    }

    resEl.innerHTML = renderLoading('Consultando via servidor Vercel...');
    try {
      if (m.id === 'osint') {
        const d = await callApi('/api/intel', { action: 'sherlock', username: val });
        await recordEvidence('osint', val, d);
        resEl.innerHTML = `
          ${renderResHeader(`Sherlock OSINT: @${d.username}`, '12 Plataformas (Serverless)')}
          <div class="stat-grid">
            <div class="stat-card"><span class="stat-val text-green font-mono-code">${d.summary.found}</span><span class="stat-lbl">Encontrados</span></div>
            <div class="stat-card"><span class="stat-val font-mono-code">${d.summary.notFound}</span><span class="stat-lbl">Ausentes</span></div>
            <div class="stat-card"><span class="stat-val text-orange font-mono-code">${d.summary.errors}</span><span class="stat-lbl">Timeout</span></div>
            <div class="stat-card"><span class="stat-val font-mono-code">${d.summary.total}</span><span class="stat-lbl">Total</span></div>
          </div>
          <div class="kv-list">${d.results.map((r) => `
            <a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer" class="kv-item">
              <div class="kv-left"><span style="font-weight:600;display:block;">${escapeHtml(r.platform)}</span><span class="text-xs-muted">${escapeHtml(r.info || '-')} • ${r.latencyMs ?? 0}ms</span></div>
              <span class="tag ${r.status === 'found' ? 't-ok' : r.status === 'not_found' ? 't-err' : 't-warn'}">${r.status === 'found' ? 'Encontrado' : r.status === 'not_found' ? 'Ausente' : 'Fora'}</span>
            </a>`).join('')}</div>`;
      } else if (m.id === 'breach') {
        const d = await callApi('/api/intel', { action: 'breach', email: val });
        await recordEvidence('breach', val, d);
        const b = d.breachCheck;
        resEl.innerHTML = `
          ${renderResHeader(`Auditoria: ${d.email}`, 'XposedOrNot + Node DNS')}
          ${!b.ok ? renderBanner(`Base XposedOrNot indisponivel (${b.error}).`, 'warn') : b.exposed ? renderBanner(`ALERTA: E-mail localizado em ${b.breaches.length} incidente(s).`, 'err') : renderBanner('Nenhum vazamento encontrado na base XposedOrNot.', 'ok')}
          ${renderKvList([
            ['Dominio', d.domain],
            ['MX Ativo', d.mailHealth.mxValid ? 'Sim' : 'Nao'],
            ['SPF', d.mailHealth.hasSpf ? 'Configurado' : 'Ausente'],
            ['DMARC', d.mailHealth.hasDmarc ? 'Configurado' : 'Ausente'],
            ['Servidores MX', d.mailHealth.mxServers.join(' | ') || '-', false, true]
          ])}
          ${b.exposed ? `<div class="section-sub text-red">Bases Expostas</div><div class="chip-wrap">${b.breaches.map((x) => `<span class="tag t-err">${escapeHtml(x)}</span>`).join('')}</div>` : ''}`;
      } else if (m.id === 'ssl_crt') {
        const d = await callApi('/api/intel', { action: 'subdomains', domain: val });
        await recordEvidence('ssl_crt', val, d);
        const listTxt = d.subdomains.map((s) => s.host).join('\n');
        resEl.innerHTML = `
          ${renderResHeader(`${d.total} Subdominio(s) em ${d.domain}`, d.provider || 'crt.sh', `<button type="button" class="btn-soft" data-copy-val="${escapeHtml(listTxt)}">Copiar Lista</button>`)}
          <div class="field-group"><input type="text" id="subFilter" class="m3-input" placeholder="Filtrar subdominios..." /></div>
          <div class="data-table-wrap scroll-list"><table class="data-table" id="subTbl"><thead><tr><th>Subdominio</th><th>Emissao</th><th>Expiracao</th></tr></thead><tbody>${d.subdomains.map((s) => `<tr><td class="font-mono-code">${escapeHtml(s.host)}</td><td>${escapeHtml(s.notBefore ? s.notBefore.slice(0, 10) : '-')}</td><td>${escapeHtml(s.notAfter ? s.notAfter.slice(0, 10) : '-')}</td></tr>`).join('') || '<tr><td colspan="3">Nenhum subdominio.</td></tr>'}</tbody></table></div>`;
        document.getElementById('subFilter').addEventListener('input', (ev) => {
          const q = ev.target.value.trim().toLowerCase();
          document.querySelectorAll('#subTbl tbody tr').forEach((tr) => { tr.style.display = tr.textContent.toLowerCase().includes(q) ? '' : 'none'; });
        });
      } else if (m.id === 'dns') {
        const d = await callApi('/api/intel', { action: 'dns', domain: val });
        await recordEvidence('dns', val, d);
        const r = d.records, es = d.emailSecurity;
        resEl.innerHTML = `
          ${renderResHeader(`DNS: ${d.domain}`, 'Node.js DNS')}
          ${renderKvList([
            ['SPF', es.hasSpf ? es.spf : 'Ausente', es.hasSpf, true],
            ['DMARC', es.hasDmarc ? es.dmarc : 'Ausente', es.hasDmarc, true],
            ['A (IPv4)', r.A.join(', ') || '-', r.A.length > 0, true],
            ['AAAA (IPv6)', r.AAAA.join(', ') || '-', r.AAAA.length > 0, true],
            ['NS', r.NS.join(', ') || '-', r.NS.length > 0, true],
            ['MX', r.MX.map((x) => `${x.exchange} (${x.priority})`).join(' | ') || '-', false, true],
            ['SOA', r.SOA ? `${r.SOA.nsname} (serial ${r.SOA.serial})` : '-', false, true]
          ])}
          ${r.TXT.length ? `<div class="section-sub">Registros TXT (${r.TXT.length})</div><pre class="code-viewer">${escapeHtml(r.TXT.join('\n'))}</pre>` : ''}`;
      } else if (m.id === 'domain') {
        const d = await callApi('/api/intel', { action: 'rdap', domain: val });
        await recordEvidence('domain', val, d);
        resEl.innerHTML = `
          ${renderResHeader(`RDAP: ${d.domain}`, d.provider)}
          ${renderKvList([
            ['Titular', d.owner.name, true],
            ['Documento / Handle', d.owner.document, true, true],
            ['E-mail Contato', d.owner.email, true],
            ['Registrador', d.registrar],
            ['Criacao', d.events.registration || '-'],
            ['Ultima Alteracao', d.events.lastChanged || '-'],
            ['Expiracao', d.events.expiration || '-'],
            ['DNSSEC', d.dnssec ? 'Assinado' : 'Nao assinado'],
            ['Status EPP', (d.status || []).join(', ') || '-'],
            ['Nameservers', (d.nameservers || []).join(', ') || '-', false, true]
          ])}`;
      } else if (m.id === 'scraping') {
        const d = await callApi('/api/scrape', { url: val });
        await recordEvidence('scraping', val, d);
        resEl.innerHTML = `
          ${renderResHeader(`Auditoria Web (Nota ${d.security.grade} • ${d.security.score}/100)`, `HTTP ${d.status} • ${d.elapsedMs}ms`)}
          ${renderKvList([
            ['URL Final', d.url, true, true],
            ['Titulo', d.metadata.title, true],
            ['Descricao', d.metadata.description],
            ['Servidor / Stack', `${d.security.server || '-'} / ${d.security.poweredBy || d.metadata.generator}`],
            ['E-mails', d.contacts.emails.join(', ') || '-', d.contacts.emails.length > 0, true],
            ['Telefones', d.contacts.phones.join(', ') || '-', d.contacts.phones.length > 0, true],
            ['Redes Sociais', d.contacts.social.join('\n') || '-', d.contacts.social.length > 0, true]
          ])}
          <div class="section-sub">Cabecalhos de Seguranca</div>
          <div class="data-table-wrap"><table class="data-table"><thead><tr><th>Header</th><th>Status</th><th>Valor</th></tr></thead><tbody>${d.security.details.map((h) => `<tr><td class="font-mono-code">${escapeHtml(h.header)}</td><td><span class="tag ${h.present ? 't-ok' : 't-err'}">${h.present ? 'Presente' : 'Ausente'}</span></td><td style="word-break:break-word;">${escapeHtml(h.value || '-')}</td></tr>`).join('')}</tbody></table></div>`;
      } else if (m.id === 'ip') {
        const d = await callApi('/api/intel', { action: 'ip', target: val });
        await recordEvidence('ip', val || 'IP Publico', d);
        const g = d.geo;
        resEl.innerHTML = `
          ${renderResHeader(`IP: ${g.ip}`, d.provider)}
          ${renderKvList([
            ['IP', g.ip, true, true],
            ['Tipo', g.type],
            ['Localizacao', `${g.city}, ${g.region} (${g.country})`],
            ['Coordenadas', g.latitude != null ? `${g.latitude}, ${g.longitude}` : '-', g.latitude != null, true],
            ['ASN', g.asn, true, true],
            ['Organizacao / ISP', g.org || g.isp, true],
            ['Fuso Horario', g.timezone]
          ])}
          ${g.latitude != null && g.longitude != null ? renderMapBlock(g.latitude, g.longitude, `Localizacao de ${g.ip}`) : ''}`;
      } else if (m.id === 'cnpj') {
        const d = await callApi('/api/intel', { action: 'cnpj', cnpj: val });
        await recordEvidence('cnpj', val, d);
        const c = d.company;
        resEl.innerHTML = `
          ${renderResHeader(c.razaoSocial, d.provider)}
          ${renderKvList([
            ['CNPJ', c.cnpj, true, true],
            ['Nome Fantasia', c.nomeFantasia, true],
            ['Situacao', c.situacao],
            ['Abertura', c.dataAbertura],
            ['Porte', c.porte],
            ['Capital Social', formatCurrencyBRL(c.capitalSocial)],
            ['Natureza Juridica', c.naturezaJuridica],
            ['CNAE Principal', c.cnaePrincipal],
            ['Telefone', c.telefone, true],
            ['E-mail', c.email, true],
            ['Endereco', `${c.endereco} (${c.cidadeUf} • CEP ${c.cep})`, true]
          ])}
          ${c.socios.length ? `<div class="section-sub">Quadro Societario (${c.socios.length})</div><div class="data-table-wrap"><table class="data-table"><thead><tr><th>Socio</th><th>Qualificacao</th><th>Entrada</th></tr></thead><tbody>${c.socios.map((s) => `<tr><td>${escapeHtml(s.nome)}</td><td>${escapeHtml(s.qualificacao)}</td><td>${escapeHtml(s.entrada)}</td></tr>`).join('')}</tbody></table></div>` : ''}`;
      }
    } catch (err) { resEl.innerHTML = renderBanner(err.message, 'err'); }
  });

  if (state.pendingQuery?.moduleId === m.id) {
    inp.value = state.pendingQuery.value;
    state.pendingQuery = null;
    setTimeout(() => document.getElementById('qForm').requestSubmit(), 80);
  }
}

/* ==================== ROUTER ==================== */
function render() {
  const ws = document.getElementById('workspace');
  const hash = window.location.hash.replace('#', '');
  renderRailAndMobile(hash);
  if (!hash) { renderOverview(ws); return; }

  const m = MODULES.find((x) => x.id === hash);
  if (!m) return navigate('');
  document.getElementById('topTitle').textContent = m.name;

  if (m.id === 'proxyvpn') return renderProxyVpn(ws, m);
  if (m.id === 'virustotal') return renderVirusTotal(ws, m);
  if (m.id === 'custody') return renderCustody(ws, m);
  if (m.id === 'metadata') return renderMetadata(ws, m);
  if (m.id === 'ela') return renderEla(ws, m);
  if (m.id === 'decoder') return renderDecoder(ws, m);
  return renderQueryModule(ws, m);
}

/* ==================== DRAWERS, COMMAND PALETTE & EVENTS ==================== */
function openMobileDrawer() { document.getElementById('mobileDrawer').classList.add('open'); document.getElementById('backdrop').classList.add('open'); }
function closeMobileDrawer() { document.getElementById('mobileDrawer').classList.remove('open'); if (!document.getElementById('caseDrawer').classList.contains('open')) document.getElementById('backdrop').classList.remove('open'); }
function openCaseDrawer() { updateEvidenceUI(); document.getElementById('caseDrawer').classList.add('open'); document.getElementById('backdrop').classList.add('open'); }
function closeCaseDrawer() { document.getElementById('caseDrawer').classList.remove('open'); if (!document.getElementById('mobileDrawer').classList.contains('open')) document.getElementById('backdrop').classList.remove('open'); }

function renderCmdList(q = '') {
  const t = q.trim().toLowerCase();
  const list = MODULES.filter((m) => !t || `${m.name} ${m.summary} ${m.io} ${m.keywords}`.toLowerCase().includes(t));
  document.getElementById('cmdList').innerHTML = list.length
    ? list.map((m) => `
      <button type="button" class="btn-soft cmd-item" data-nav="${m.id}">
        <span class="cmd-item-left">
          <span class="squircle-ic squircle-sm" style="background:${m.gradient};"><span class="material-symbols-rounded">${m.icon}</span></span>
          <span><strong style="display:block;font-size:12.5px;">${escapeHtml(m.name)}</strong><span class="font-mono-code text-xs-muted">${escapeHtml(m.io)}</span></span>
        </span>
        <span class="tag ${m.badgeClass}">${escapeHtml(m.badge)}</span>
      </button>`).join('')
    : '<div class="text-xs-muted" style="text-align:center;padding:24px;">Nenhum modulo encontrado.</div>';
}

function openCmdPalette() {
  document.getElementById('cmdModal').classList.add('open');
  const i = document.getElementById('cmdInput');
  i.value = '';
  renderCmdList('');
  setTimeout(() => i.focus(), 40);
}
function closeCmdPalette() { document.getElementById('cmdModal').classList.remove('open'); }

document.getElementById('railThemeBtn').addEventListener('click', cycleTheme);
document.getElementById('topThemeBtn').addEventListener('click', cycleTheme);
document.getElementById('railSolidBtn').addEventListener('click', () => {
  applySolid(!state.solid);
  showToast(state.solid ? 'Paineis Solidos ativados.' : 'Transparência Lúmen ativada.', 'info');
});
document.getElementById('openMobileBtn').addEventListener('click', openMobileDrawer);
document.getElementById('closeMobileBtn').addEventListener('click', closeMobileDrawer);
document.getElementById('openDrawerBtn').addEventListener('click', openCaseDrawer);
document.getElementById('closeDrawerBtn').addEventListener('click', closeCaseDrawer);
document.getElementById('backdrop').addEventListener('click', () => { closeMobileDrawer(); closeCaseDrawer(); });
document.getElementById('openCmdBtn').addEventListener('click', openCmdPalette);
document.getElementById('cmdClose').addEventListener('click', closeCmdPalette);
document.getElementById('cmdModal').addEventListener('click', (e) => { if (e.target.id === 'cmdModal') closeCmdPalette(); });
document.getElementById('cmdInput').addEventListener('input', (e) => renderCmdList(e.target.value));
document.getElementById('proxyRetryBtn').addEventListener('click', async () => {
  document.getElementById('proxyLabel').textContent = 'Reconectando...';
  await initRemoteProxy();
  renderProxyStatus();
  showToast(getProxyState().online ? 'Conexão com a API validada.' : 'API indisponível. Ferramentas locais seguem ativas.', getProxyState().online ? 'success' : 'error');
});

document.getElementById('exportFullCaseBtn').addEventListener('click', () => {
  if (!state.dossier.length) return showToast('Dossie vazio.', 'error');
  downloadSignedJson('dossie-completo', { case_id: CASE_ID, total: state.dossier.length, timeline: state.dossier }, CASE_ID.toLowerCase());
});
document.getElementById('printCaseBtn').addEventListener('click', () => window.print());
document.getElementById('clearCaseBtn').addEventListener('click', () => {
  state.dossier = [];
  clearEncryptedDossier();
  updateEvidenceUI();
  showToast('Dossie limpo.', 'info');
});

document.addEventListener('keydown', (e) => {
  const k = (e.key || '').toUpperCase();
  if ((e.ctrlKey || e.metaKey) && k === 'K') { e.preventDefault(); openCmdPalette(); }
  else if (k === 'ESCAPE') { closeCmdPalette(); closeCaseDrawer(); closeMobileDrawer(); }
});

document.addEventListener('click', (e) => {
  const nav = e.target.closest('[data-nav]');
  if (nav) { navigate(nav.getAttribute('data-nav')); return; }

  const hs = e.target.closest('[data-home-sector]');
  if (hs) {
    state.activeHomeSector = hs.getAttribute('data-home-sector');
    document.querySelectorAll('[data-home-sector]').forEach((b) => b.classList.toggle('active', b.getAttribute('data-home-sector') === state.activeHomeSector));
    if (window.location.hash) navigate('');
    else renderBentoGrid();
    return;
  }

  const vth = e.target.closest('[data-vt-hash]');
  if (vth) { state.pendingQuery = { moduleId: 'virustotal', value: vth.getAttribute('data-vt-hash') }; navigate('virustotal'); return; }

  if (e.target.closest('[data-print]')) { window.print(); return; }

  const fl = e.target.closest('[data-fill]');
  if (fl) {
    const inp = document.getElementById('qInput');
    if (inp) { inp.value = fl.getAttribute('data-fill'); document.getElementById('qForm')?.requestSubmit(); }
    return;
  }

  const cp = e.target.closest('[data-copy-val]');
  if (cp) { copyText(cp.getAttribute('data-copy-val')); return; }

  const ex = e.target.closest('[data-export]');
  if (ex && state.lastResultData) {
    downloadSignedJson(state.lastModuleId, state.lastResultData, `lumen-${state.lastModuleId}`);
  }
});

window.addEventListener('hashchange', render);

applyTheme(state.theme);
applySolid(state.solid);
render();
runBootSequence();
