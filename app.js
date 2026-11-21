// ==========================================
// 1. CONFIGURAÇÃO E DEFINIÇÃO DAS APIS
// ==========================================
const CONFIG = { keys: { feriadosapi: '' } };

const MODULES = [
  { id: 'cnpj_brasilapi', t: 'CNPJ (BrasilAPI)', d: 'Empresa por CNPJ via BrasilAPI', i: 'domain', c: 'Empresas', e: ['https://brasilapi.com.br/api/cnpj/v1/{cnpj}'], in: [{ k: 'cnpj', l: 'CNPJ', p: '00000000000000', m: 14, n: 1, v: v => v.length === 14 || 'Inválido' }] },
  { id: 'cep', t: 'Consulta CEP', d: 'BrasilAPI → ViaCEP', i: 'location_on', c: 'Localização', e: ['https://brasilapi.com.br/api/cep/v2/{cep}', 'https://viacep.com.br/ws/{cep}/json/'], in: [{ k: 'cep', l: 'CEP', p: '01310100', m: 8, n: 1, v: v => v.length === 8 || 'Inválido' }] },
  { id: 'ddd', t: 'Consulta DDD', d: 'Cidades por DDD', i: 'phone_in_talk', c: 'Localização', e: ['https://brasilapi.com.br/api/ddd/v1/{ddd}'], in: [{ k: 'ddd', l: 'DDD', p: '11', m: 2, n: 1, v: v => v.length === 2 || 'Inválido' }] },
  { id: 'feriados', t: 'Feriados', d: 'Feriados Nacionais', i: 'event', c: 'Feriados', e: ['https://brasilapi.com.br/api/feriados/v1/{ano}'], in: [{ k: 'ano', l: 'Ano', p: '2025', m: 4, n: 1, v: v => /^\d{4}$/.test(v) || 'Inválido' }] },
  { id: 'fipe_marcas', t: 'FIPE Marcas', d: 'Marcas de veículos', i: 'directions_car', c: 'Veículos', e: ['https://brasilapi.com.br/api/fipe/marcas/v1/{tipo}'], in: [{ k: 'tipo', l: 'Tipo', ty: 'select', o: [{ v: 'carros', l: 'Carros' }, { v: 'motos', l: 'Motos' }] }] },
  { id: 'cotacao', t: 'Cotação', d: 'Dólar, Euro, Bitcoin', i: 'currency_exchange', c: 'Economia', e: ['https://economia.awesomeapi.com.br/json/last/{par}'], in: [{ k: 'par', l: 'Par', p: 'USD-BRL', v: v => v.includes('-') || 'Formato: USD-BRL' }] },
  { id: 'bancos', t: 'Bancos', d: 'Lista de bancos', i: 'account_balance', c: 'Utilidades', e: ['https://brasilapi.com.br/api/banks/v1'], in: [] },
  { id: 'pix', t: 'PIX', d: 'Participantes PIX', i: 'pix', c: 'Utilidades', e: ['https://brasilapi.com.br/api/pix/v1/participants'], in: [] },
  { id: 'cpf', t: 'Consulta CPF', d: 'Via Vercel Serverless', i: 'person', c: 'Pessoas', e: ['/api/cpf?cpf={cpf}'], in: [{ k: 'cpf', l: 'CPF', p: '00000000000', m: 11, n: 1, v: v => v.length === 11 || 'Inválido' }] }
];

const CATEGORIES = [...new Set(MODULES.map(m => m.c))];

// ==========================================
// 2. LÓGICA DE API E FETCH
// ==========================================
async function fetchAPI(endpoints, query) {
  const errors = [];
  for (const ep of endpoints) {
    const url = ep.replace(/\{(\w+)\}/g, (_, k) => encodeURIComponent(query[k] || ''));
    let host = 'api local';
    try { host = url.startsWith('http') ? new URL(url).host : window.location.host; } catch (e) {}

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(timeout);

      if (!res.ok) { errors.push(`${host} → HTTP ${res.status}`); continue; }
      
      let data = await res.json();
      if (data.erro === true) { errors.push(`${host} → Não encontrado`); continue; }
      // Desempacota a resposta da Serverless Function do Vercel
      if (data && data.success === true && data.data) data = data.data;

      return { success: true, data, source: host };
    } catch (e) {
      errors.push(`${host} → ${e.name === 'AbortError' ? 'Timeout' : 'Falha/CORS'}`);
    }
  }
  return { success: false, error: errors.join('\n') };
}

// ==========================================
// 3. RENDERIZAÇÃO DA INTERFACE (DOM)
// ==========================================
function esc(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function prog(a) { const b = document.getElementById('progressBar'); if(a){b.classList.add('active');b.style.width='70%'}else{b.style.width='100%';setTimeout(()=>{b.classList.remove('active');b.style.width='0'},350)} }
function getRoute() { let h = location.hash.replace(/^#/,''); return !h || h==='/' ? '/' : (h.startsWith('/')?h:'/'+h); }

function renderSidebar() {
  const nav = document.getElementById('sidebar-nav'), cur = getRoute();
  let html = `<a href="#/" class="nav-item ${cur==='/'?'active':''}"><span class="material-symbols-outlined icon-sm">dashboard</span>Dashboard</a>`;
  
  CATEGORIES.forEach(c => {
    const mods = MODULES.filter(m => m.c === c);
    html += `<div class="mt-3"><div class="flex items-center gap-2 px-2 py-1 mb-1"><span class="material-symbols-outlined icon-sm" style="color:#22c55e">folder</span><span class="font-medium text-xs text-1 flex-1">${c}</span><span class="text-xs text-3">${mods.length}</span></div><div class="space-y-0.5 ml-3">`;
    mods.forEach(m => { html += `<a href="#/${m.id}" class="nav-item ${cur==='/'+m.id?'active':''}"><span class="nav-bullet"></span><span class="truncate flex-1">${m.t}</span></a>`; });
    html += `</div></div>`;
  });
  nav.innerHTML = html;
}

function renderDash() {
  const v = document.getElementById('view');
  let sections = '';
  
  CATEGORIES.forEach(c => {
    const mods = MODULES.filter(m => m.c === c);
    const cards = mods.map(m => `
      <a href="#/${m.id}" class="card hover p-5 group block" data-s="${m.t.toLowerCase()} ${m.d.toLowerCase()}">
        <div class="flex items-start justify-between mb-3"><div class="p-2.5 rounded-xl" style="background:rgba(34,197,94,.14);color:#22c55e"><span class="material-symbols-outlined icon-lg">${m.i}</span></div></div>
        <h3 class="text-1 font-semibold mb-1">${m.t}</h3><p class="text-2 text-sm mb-4">${m.d}</p>
        <div class="flex items-center justify-between pt-3 border-t" style="border-color:var(--border)"><span class="text-3 text-xs">Rápida</span><span class="material-symbols-outlined icon-sm" style="color:#22c55e">arrow_forward</span></div>
      </a>`).join('');
    sections += `<section class="mb-8"><div class="flex items-center mb-2 gap-3"><div class="p-2 rounded-xl" style="background:rgba(34,197,94,.14);color:#22c55e"><span class="material-symbols-outlined icon-lg">folder</span></div><h2 class="text-xl font-bold text-1">${c}</h2><span class="ml-auto text-3 text-sm">${mods.length}</span></div><div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">${cards}</div></section>`;
  });

  v.innerHTML = `<div class="view-enter"><div class="mb-6"><h1 class="text-2xl font-bold text-1">APIs Públicas</h1><p class="text-2 text-sm">${MODULES.length} módulos disponíveis</p></div><div class="search-w mb-6"><span class="material-symbols-outlined">search</span><input type="text" id="search" class="search-i" placeholder="Buscar..."></div><div id="mods">${sections}</div></div>`;
  
  document.getElementById('search').addEventListener('input', e => {
    const q = e.target.value.toLowerCase();
    document.querySelectorAll('section').forEach(sec => {
      let vis = false;
      sec.querySelectorAll('[data-s]').forEach(c => { const match = !q || c.dataset.s.includes(q); c.style.display = match ? '' : 'none'; if(match) vis = true; });
      sec.style.display = vis ? '' : 'none';
    });
  });
  checkConn();
}

function renderMod(m) {
  const v = document.getElementById('view');
  const inputsHtml = m.in && m.in.length ? m.in.map(i => {
    if (i.ty === 'select') return `<div class="md-field"><select id="i_${i.k}"><option value="" disabled selected>Selecione</option>${i.o.map(o=>`<option value="${o.v}">${o.l}</option>`).join('')}</select><span class="material-symbols-outlined chev">expand_more</span><label>${i.l}</label></div>`;
    return `<div class="md-field"><input type="text" id="i_${i.k}" placeholder=" " ${i.m?`maxlength="${i.m}"`:''}><label>${i.l}</label></div>`;
  }).join('') : '<p class="text-sm text-3">Sem parâmetros</p>';

  v.innerHTML = `<div class="view-enter"><nav class="text-sm mb-4 text-3"><a href="#/">Dashboard</a> > ${m.c} > <span class="text-1">${m.t}</span></nav><div class="card p-5 mb-4"><div class="flex items-center gap-3"><div class="p-3 rounded-xl" style="background:rgba(34,197,94,.14);color:#22c55e"><span class="material-symbols-outlined icon-xl">${m.i}</span></div><div><h1 class="text-2xl font-bold text-1">${m.t}</h1><p class="text-2 text-sm">${m.d}</p></div></div></div><div class="grid grid-cols-1 lg:grid-cols-3 gap-6"><div><div class="card p-5 sticky top-24"><h2 class="font-semibold text-1 mb-4">Nova consulta</h2><form id="form">${inputsHtml}<button type="submit" class="btn-p w-full mt-4">Consultar</button></form></div></div><div class="lg:col-span-2"><div id="res"><div class="card text-center p-8"><span class="material-symbols-outlined icon-xl text-3">search</span><p class="text-3 text-sm mt-2">Aguardando</p></div></div></div></div></div>`;

  document.getElementById('form').addEventListener('submit', async e => {
    e.preventDefault();
    const r = document.getElementById('res'), q = {};
    let valid = true;

    m.in.forEach(i => {
      const el = document.getElementById('i_'+i.k);
      if(el) {
        if(!el.value.trim()){ alert('Preencha '+i.l); valid=false; el.focus(); return; }
        if(i.v) { const err = i.v(el.value.trim()); if(err !== true){ alert(err); valid=false; el.focus(); return; } }
        q[i.k] = el.value.trim();
      }
    });
    if(!valid) return;

    prog(true);
    r.innerHTML = '<div class="card p-5"><div class="sk mb-2" style="height:40px;width:50%"></div><div class="sk mb-2" style="height:14px;width:80%"></div><div class="sk" style="height:14px;width:60%"></div></div>';

    const rs = await fetchAPI(m.e, q);
    prog(false);

    if(!rs.success) {
      r.innerHTML = `<div class="card p-5" style="border-color:#ef4444"><p class="text-red-400">Erro: ${esc(rs.error)}</p></div>`;
      return;
    }

    const preview = typeof rs.data === 'object' && !Array.isArray(rs.data) 
      ? Object.keys(rs.data).slice(0,10).map(k => `<div class="kv-row"><span class="kv-key">${k}</span><span class="kv-val">${esc(rs.data[k])}</span></div>`).join('')
      : `<pre class="text-xs text-2">${esc(JSON.stringify(rs.data, null, 2))}</pre>`;

    r.innerHTML = `<div class="card p-5"><h3 class="font-semibold text-1 mb-3">Resultado</h3><div class="space-y-1">${preview}</div><button id="op" class="btn-g mt-4">Ver JSON completo</button></div>`;
    
    document.getElementById('op').onclick = () => {
      document.getElementById('modalBody').innerHTML = `<pre class="text-xs text-2">${esc(JSON.stringify(rs.data, null, 2))}</pre>`;
      document.getElementById('analiticModal').classList.add('open');
    };
  });
}

function checkConn() {
  const dot = document.getElementById('netStatus'), txt = document.getElementById('netText');
  if(!dot) return; dot.className = 's-dot check'; txt.textContent = 'Verificando...';
  fetch('https://brasilapi.com.br/api/feriados/v1/2024')
    .then(r => { if(r.ok) { dot.className = 's-dot on'; txt.textContent = 'BrasilAPI online'; } else throw 0; })
    .catch(() => { dot.className = 's-dot off'; txt.textContent = 'Offline'; });
}

// ==========================================
// 4. ROTEAMENTO E INICIALIZAÇÃO
// ==========================================
function render() {
  const r = getRoute();
  prog(true);
  if(r === '/') renderDash();
  else {
    const m = MODULES.find(x => x.id === r.slice(1));
    if(!m) { location.hash = '#/'; return; }
    renderMod(m);
  }
  renderSidebar();
  window.scrollTo(0,0);
  setTimeout(() => prog(false), 200);
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('sidebar-toggle').onclick = () => { const s = document.getElementById('sidebar'), o = document.getElementById('sidebar-overlay'); s.classList.toggle('-translate-x-full'); o.classList.toggle('visible'); };
  document.getElementById('sidebar-close').onclick = () => { document.getElementById('sidebar').classList.add('-translate-x-full'); document.getElementById('sidebar-overlay').classList.remove('visible'); };
  document.getElementById('sidebar-overlay').onclick = () => { document.getElementById('sidebar').classList.add('-translate-x-full'); document.getElementById('sidebar-overlay').classList.remove('visible'); };
  
  document.getElementById('theme-toggle').onclick = () => {
    const isDark = document.body.classList.contains('theme-dark');
    document.body.className = isDark ? 'theme-light min-h-screen' : 'theme-dark min-h-screen';
    localStorage.setItem('theme', isDark ? 'light' : 'dark');
    document.getElementById('themeIcon').textContent = isDark ? 'dark_mode' : 'light_mode';
  };
  
  document.getElementById('btnCloseModal').onclick = () => document.getElementById('analiticModal').classList.remove('open');
  
  document.getElementById('apiCount').textContent = MODULES.length;
  if(localStorage.getItem('theme') === 'light') document.getElementById('themeIcon').textContent = 'dark_mode';

  render();
  window.addEventListener('hashchange', render);
});
