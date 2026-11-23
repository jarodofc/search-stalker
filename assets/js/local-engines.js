const STORAGE_KEY = 'zforense_dossier_v2';
const SEED_KEY = 'zforense_seed_v2';

const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const toB64 = (b) => { let s = ''; b.forEach((x) => { s += String.fromCharCode(x); }); return btoa(s); };
const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function getSeed() {
  let seed = sessionStorage.getItem(SEED_KEY);
  if (!seed) {
    const r = new Uint8Array(32);
    crypto.getRandomValues(r);
    seed = toHex(r);
    sessionStorage.setItem(SEED_KEY, seed);
  }
  return seed;
}

async function getAesKey() {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(getSeed()), { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('zFORENSE-v2-salt'), iterations: 50000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

export async function saveDossier(items) {
  try {
    if (!window.crypto?.subtle) { localStorage.setItem(STORAGE_KEY, JSON.stringify({ plain: true, items })); return; }
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await getAesKey(), new TextEncoder().encode(JSON.stringify(items)));
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ alg: 'AES-256-GCM', iv: toB64(iv), ct: toB64(new Uint8Array(ct)) }));
  } catch {}
}

export async function loadDossier() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const env = JSON.parse(raw);
    if (env.plain) return Array.isArray(env.items) ? env.items : [];
    if (!env.iv || !env.ct || !window.crypto?.subtle) return [];
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(env.iv) }, await getAesKey(), fromB64(env.ct));
    const parsed = JSON.parse(new TextDecoder().decode(pt));
    return Array.isArray(parsed) ? parsed : [];
  } catch { return []; }
}

export function clearDossier() { try { localStorage.removeItem(STORAGE_KEY); } catch {} }

export async function signExport(moduleName, data, proxyMeta = {}) {
  const body = { platform: 'zFORENSE', version: '2.0.0', module: moduleName, exportedAt: new Date().toISOString(), transport: proxyMeta, data };
  const enc = new TextEncoder().encode(JSON.stringify(body));
  let contentSha256 = 'n/a', sessionHmacSha256 = 'n/a';
  if (window.crypto?.subtle) {
    contentSha256 = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', enc)));
    const hk = await crypto.subtle.importKey('raw', new TextEncoder().encode(`zFORENSE::${getSeed()}`), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    sessionHmacSha256 = toHex(new Uint8Array(await crypto.subtle.sign('HMAC', hk, enc)));
  }
  return { ...body, custody: { algorithm: 'SHA-256 + HMAC-SHA256', contentSha256, sessionHmacSha256 } };
}

/* ---------- EXIF / PNG Local Parser ---------- */
const IFD0 = { 0x010f: 'Fabricante', 0x0110: 'Modelo', 0x0131: 'Software', 0x0132: 'DataModificacao', 0x013b: 'Artista', 0x8769: '_E', 0x8825: '_G' };
const EXIF = { 0x829a: 'Exposicao', 0x829d: 'Abertura', 0x8827: 'ISO', 0x9003: 'DataOriginal', 0x920a: 'Focal', 0xa431: 'SerialCamera', 0xa434: 'Lente' };
const GPS = { 0x0001: 'LatRef', 0x0002: 'Lat', 0x0003: 'LonRef', 0x0004: 'Lon', 0x0006: 'Alt', 0x001d: 'DataGPS' };

function readAscii(v, off, len) {
  let s = '';
  for (let i = off; i < Math.min(v.byteLength, off + len); i++) { const c = v.getUint8(i); if (!c) break; s += String.fromCharCode(c); }
  return s.trim();
}

function parseIfd(v, tiff, ifdOff, le, dict) {
  const out = {}, base = tiff + ifdOff;
  if (base < 0 || base + 2 > v.byteLength) return out;
  const n = v.getUint16(base, le);
  const sizes = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 9: 4, 10: 8 };
  for (let i = 0; i < n; i++) {
    const e = base + 2 + i * 12;
    if (e + 12 > v.byteLength) break;
    const name = dict[v.getUint16(e, le)];
    if (!name) continue;
    const type = v.getUint16(e + 2, le), cnt = v.getUint32(e + 4, le);
    const bytes = (sizes[type] || 1) * cnt;
    const pos = bytes <= 4 ? e + 8 : tiff + v.getUint32(e + 8, le);
    if (pos < 0 || pos + bytes > v.byteLength) continue;
    if (type === 2) out[name] = readAscii(v, pos, cnt);
    else if (type === 3) out[name] = v.getUint16(pos, le);
    else if (type === 4) out[name] = v.getUint32(pos, le);
    else if (type === 5 || type === 10) {
      const r1 = (p) => { const a = type === 5 ? v.getUint32(p, le) : v.getInt32(p, le), b = type === 5 ? v.getUint32(p + 4, le) : v.getInt32(p + 4, le); return b ? a / b : 0; };
      out[name] = cnt === 1 ? r1(pos) : Array.from({ length: cnt }, (_, k) => r1(pos + k * 8));
    }
  }
  return out;
}

export async function parseImageMetadata(file) {
  const v = new DataView(await file.arrayBuffer());
  const out = { filename: file.name, size: file.size, format: 'Outro', tags: {}, gps: null, dimensions: null, alerts: [] };
  if (v.byteLength >= 4 && v.getUint16(0, false) === 0xffd8) {
    out.format = 'JPEG';
    let off = 2;
    while (off + 4 < v.byteLength && v.getUint8(off) === 0xff) {
      const mk = v.getUint8(off + 1);
      if (mk === 0xda || mk === 0xd9) break;
      const len = v.getUint16(off + 2, false);
      if (len < 2 || off + 2 + len > v.byteLength) break;
      if ((mk === 0xc0 || mk === 0xc2) && off + 9 < v.byteLength) out.dimensions = { height: v.getUint16(off + 5, false), width: v.getUint16(off + 7, false) };
      if (mk === 0xe1 && len > 10 && readAscii(v, off + 4, 4) === 'Exif') {
        const tiff = off + 10, le = readAscii(v, tiff, 2) === 'II';
        const ifd0 = parseIfd(v, tiff, v.getUint32(tiff + 4, le), le, IFD0);
        const ePtr = ifd0._E, gPtr = ifd0._G; delete ifd0._E; delete ifd0._G;
        Object.assign(out.tags, ifd0);
        if (typeof ePtr === 'number') Object.assign(out.tags, parseIfd(v, tiff, ePtr, le, EXIF));
        if (typeof gPtr === 'number') {
          const g = parseIfd(v, tiff, gPtr, le, GPS);
          const toDec = (d, ref) => Array.isArray(d) && d.length >= 3 ? Number(((ref === 'S' || ref === 'W' ? -1 : 1) * (d[0] + d[1] / 60 + d[2] / 3600)).toFixed(6)) : null;
          const lat = toDec(g.Lat, g.LatRef), lon = toDec(g.Lon, g.LonRef);
          if (lat !== null && lon !== null) out.gps = { latitude: lat, longitude: lon, altitude: typeof g.Alt === 'number' ? `${g.Alt.toFixed(1)} m` : null, date: g.DataGPS || null };
        }
      }
      off += 2 + len;
    }
  } else if (v.byteLength >= 24 && v.getUint32(0, false) === 0x89504e47) {
    out.format = 'PNG';
    out.dimensions = { width: v.getUint32(16, false), height: v.getUint32(20, false) };
  }
  if (out.gps) out.alerts.push('Coordenadas GPS exatas expostas nos metadados.');
  if (out.tags.Software) out.alerts.push(`Software detectado: ${out.tags.Software}`);
  return out;
}

/* ---------- Canvas ELA Engine ---------- */
const loadImg = (blob) => new Promise((res, rej) => {
  const url = URL.createObjectURL(blob), img = new Image();
  img.addEventListener('load', () => { URL.revokeObjectURL(url); res(img); });
  img.addEventListener('error', () => { URL.revokeObjectURL(url); rej(new Error('Imagem invalida.')); });
  img.src = url;
});

export async function runEla(file, qualityPct = 90, scale = 15) {
  const img = await loadImg(file);
  const ratio = Math.min(1, 1500 / Math.max(img.naturalWidth || 1, img.naturalHeight || 1));
  const w = Math.max(1, Math.round(img.naturalWidth * ratio)), h = Math.max(1, Math.round(img.naturalHeight * ratio));
  const c1 = Object.assign(document.createElement('canvas'), { width: w, height: h });
  const ctx1 = c1.getContext('2d', { willReadFrequently: true });
  ctx1.drawImage(img, 0, 0, w, h);
  const d1 = ctx1.getImageData(0, 0, w, h).data;
  const jpgBlob = await new Promise((r) => c1.toBlob(r, 'image/jpeg', qualityPct / 100));
  const img2 = await loadImg(jpgBlob);
  const c2 = Object.assign(document.createElement('canvas'), { width: w, height: h });
  const ctx2 = c2.getContext('2d', { willReadFrequently: true });
  ctx2.drawImage(img2, 0, 0, w, h);
  const d2 = ctx2.getImageData(0, 0, w, h).data;
  const outImg = ctx2.createImageData(w, h), out = outImg.data;
  let sum = 0, max = 0, hi = 0;
  for (let i = 0; i < d1.length; i += 4) {
    const dr = Math.abs(d1[i] - d2[i]), dg = Math.abs(d1[i + 1] - d2[i + 1]), db = Math.abs(d1[i + 2] - d2[i + 2]);
    const avg = (dr + dg + db) / 3;
    sum += avg; if (avg > max) max = avg; if (avg >= 18) hi++;
    out[i] = Math.min(255, dr * scale); out[i + 1] = Math.min(255, dg * scale); out[i + 2] = Math.min(255, db * scale); out[i + 3] = 255;
  }
  ctx2.putImageData(outImg, 0, 0);
  return {
    width: w, height: h, qualityPct, scale,
    originalUrl: c1.toDataURL('image/png'), elaUrl: c2.toDataURL('image/png'),
    stats: { meanError: Number((sum / (w * h)).toFixed(2)), maxError: Number(max.toFixed(2)), highPct: Number(((hi / (w * h)) * 100).toFixed(2)) }
  };
}

/* ---------- Forensic Decoders ---------- */
const b64UrlUtf8 = (s) => {
  let b = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  return new TextDecoder().decode(fromB64(b));
};

export function decodeJwt(token) {
  const p = String(token || '').trim().split('.');
  if (p.length < 2 || p.length > 3) throw new Error('JWT invalido.');
  const header = JSON.parse(b64UrlUtf8(p[0])), payload = JSON.parse(b64UrlUtf8(p[1])), warnings = [];
  if (!header.alg || String(header.alg).toLowerCase() === 'none') warnings.push('CRITICO: Algoritmo "none" (sem assinatura).');
  if (typeof payload.exp === 'number') warnings.push(payload.exp < Date.now() / 1000 ? `Expirado em ${new Date(payload.exp * 1000).toISOString()}` : `Valido ate ${new Date(payload.exp * 1000).toISOString()}`);
  return { header, payload, warnings };
}

export function transformText(mode, input) {
  const t = String(input || '');
  if (mode === 'b64_encode') return toB64(new TextEncoder().encode(t));
  if (mode === 'b64_decode') return b64UrlUtf8(t.trim());
  if (mode === 'hex_encode') return Array.from(new TextEncoder().encode(t), (b) => b.toString(16).padStart(2, '0')).join(' ');
  if (mode === 'hex_decode') {
    const c = t.replace(/[^a-fA-F0-9]/g, '');
    if (!c || c.length % 2) throw new Error('Hexadecimal invalido.');
    return new TextDecoder().decode(Uint8Array.from({ length: c.length / 2 }, (_, i) => parseInt(c.slice(i * 2, i * 2 + 2), 16)));
  }
  if (mode === 'url_encode') return encodeURIComponent(t);
  if (mode === 'url_decode') return decodeURIComponent(t);
  if (mode === 'rot13') return t.replace(/[a-zA-Z]/g, (c) => String.fromCharCode(((c.charCodeAt(0) - (c <= 'Z' ? 65 : 97) + 13) % 26) + (c <= 'Z' ? 65 : 97)));
  if (mode === 'timestamp') {
    const s = t.trim();
    if (/^\d{10,13}$/.test(s)) {
      const d = new Date(s.length === 10 ? Number(s) * 1000 : Number(s));
      return `UTC: ${d.toISOString()}\nLocal: ${d.toLocaleString('pt-BR')}`;
    }
    const ms = Date.parse(s);
    if (Number.isNaN(ms)) throw new Error('Informe Epoch (10-13 digitos) ou data ISO.');
    return `Epoch (s): ${Math.floor(ms / 1000)}\nUTC: ${new Date(ms).toISOString()}`;
  }
  if (mode === 'cidr') {
    const m = t.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
    if (!m) throw new Error('Formato esperado: 192.168.1.0/24');
    const o = [1, 2, 3, 4].map((i) => Number(m[i])), pfx = Number(m[5]);
    if (o.some((x) => x > 255) || pfx > 32) throw new Error('IP/CIDR fora do intervalo.');
    const ip = ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
    const mask = pfx === 0 ? 0 : (0xffffffff << (32 - pfx)) >>> 0;
    const net = (ip & mask) >>> 0, bc = (net | (~mask >>> 0)) >>> 0;
    const fmt = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
    const tot = Math.pow(2, 32 - pfx);
    return `Rede: ${fmt(net)}/${pfx}\nMascara: ${fmt(mask)}\nBroadcast: ${fmt(bc)}\nTotal IPs: ${tot.toLocaleString('pt-BR')}`;
  }
  throw new Error('Modo invalido.');
}
