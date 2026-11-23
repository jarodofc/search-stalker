import { buildSignedExport } from './crypto-custody.js';
import { getProxyState } from './network.js';

export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function formatBytes(bytes) {
  const n = Number(bytes || 0);
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(2)} ${u[i]}`;
}

export function formatCurrencyBRL(val) {
  if (val === null || val === undefined || Number.isNaN(Number(val))) return '-';
  return Number(val).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
}

export function showToast(message, type = 'info') {
  const host = document.getElementById('toastHost');
  if (!host) return;
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = message;
  host.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(String(text ?? ''));
    showToast('Copiado para a area de transferencia.', 'success');
  } catch {
    showToast('Nao foi possivel copiar automaticamente.', 'error');
  }
}

export async function downloadSignedJson(moduleName, payload, filenamePrefix = 'sherlock221b') {
  const signed = await buildSignedExport(moduleName, payload, getProxyState());
  const blob = new Blob([JSON.stringify(signed, null, 2)], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${filenamePrefix}-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  showToast('Dossie JSON assinado (HMAC-SHA256) baixado.', 'success');
}

export function renderKvList(rows) {
  const valid = rows.filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (!valid.length) return '<p class="text-xs-muted">Nenhum dado retornado.</p>';
  return `<div class="kv-list">${valid.map(([k, v, copyable, mono]) => `
    <div class="kv-item">
      <div class="kv-left">
        <span class="kv-key">${escapeHtml(k)}</span>
        <span class="kv-val${mono ? ' kv-val-mono' : ''}">${escapeHtml(v)}</span>
      </div>
      ${copyable && v !== '-' ? `<button type="button" class="btn-soft btn-xs" data-copy-val="${escapeHtml(v)}" title="Copiar"><span class="material-symbols-rounded">content_copy</span></button>` : ''}
    </div>`).join('')}</div>`;
}

export function renderBanner(msg, type = 'info') {
  return `<div class="banner banner-${escapeHtml(type)}">${escapeHtml(msg)}</div>`;
}

export function renderLoading(msg = 'Consultando via Proxy Serverless...') {
  return `<div class="result-empty"><span class="material-symbols-rounded spinner text-accent">refresh</span><p style="font-weight:600;margin:8px 0 0;">${escapeHtml(msg)}</p></div>`;
}

export function renderMapBlock(lat, lon, label = 'Geolocalizacao no Mapa') {
  const la = Number(lat), lo = Number(lon);
  if (!Number.isFinite(la) || !Number.isFinite(lo)) return '';
  const d = 0.008;
  const bbox = `${(lo - d).toFixed(6)},${(la - d).toFixed(6)},${(lo + d).toFixed(6)},${(la + d).toFixed(6)}`;
  const osm = `https://www.openstreetmap.org/export/embed.html?bbox=${encodeURIComponent(bbox)}&layer=mapnik&marker=${la.toFixed(6)},${lo.toFixed(6)}`;
  return `
    <div style="margin-top:14px;">
      <div class="res-header" style="border:0;margin-bottom:4px;padding:0;">
        <span class="section-sub" style="margin:0;">${escapeHtml(label)}</span>
        <span class="font-mono-code text-accent" style="font-size:11px;">${la.toFixed(6)}, ${lo.toFixed(6)}</span>
      </div>
      <div class="map-wrap"><iframe loading="lazy" referrerpolicy="no-referrer" src="${osm}" title="${escapeHtml(label)}"></iframe></div>
      <div class="res-actions" style="margin-top:8px;">
        <a href="https://www.google.com/maps?q=${la.toFixed(6)},${lo.toFixed(6)}" target="_blank" rel="noopener noreferrer" class="btn-soft">Google Maps</a>
        <a href="https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${la.toFixed(6)},${lo.toFixed(6)}" target="_blank" rel="noopener noreferrer" class="btn-soft">Street View</a>
        <a href="https://maps.apple.com/?ll=${la.toFixed(6)},${lo.toFixed(6)}" target="_blank" rel="noopener noreferrer" class="btn-soft">Apple Maps</a>
      </div>
    </div>`;
}

export function renderResHeader(title, source = '', extraHtml = '') {
  return `
    <div class="res-header">
      <div>
        <h3>${escapeHtml(title)}</h3>
        ${source ? `<span class="res-source">Fonte: ${escapeHtml(source)}</span>` : ''}
      </div>
      <div class="res-actions">
        ${extraHtml}
        <button type="button" class="btn-soft" data-print="1">PDF</button>
        <button type="button" class="btn-soft" data-export="download">JSON</button>
      </div>
    </div>`;
}
