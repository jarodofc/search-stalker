'use strict';

function md5Bytes(bytes) {
  const len = bytes.length;
  const pad = ((56 - ((len + 1) % 64)) + 64) % 64;
  const total = len + 1 + pad + 8;
  const buf = new Uint8Array(total);
  buf.set(bytes);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(total - 8, (len << 3) >>> 0, true);
  dv.setUint32(total - 4, (len >>> 29) >>> 0, true);

  const S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
  const K = Uint32Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const M = new Uint32Array(16);

  for (let off = 0; off < total; off += 64) {
    for (let j = 0; j < 16; j++) M[j] = dv.getUint32(off + j * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      const sum = (F + A + K[i] + M[g]) >>> 0;
      A = D; D = C; C = B;
      B = (B + ((sum << S[i]) | (sum >>> (32 - S[i])))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16), odv = new DataView(out.buffer);
  odv.setUint32(0, a0, true); odv.setUint32(4, b0, true); odv.setUint32(8, c0, true); odv.setUint32(12, d0, true);
  return Array.from(out, (b) => b.toString(16).padStart(2, '0')).join('');
}

const SIGS = [
  [[0x25,0x50,0x44,0x46], 'PDF Document', ['pdf']],
  [[0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a], 'PNG Image', ['png']],
  [[0xff,0xd8,0xff], 'JPEG Image', ['jpg','jpeg','jfif']],
  [[0x47,0x49,0x46,0x38], 'GIF Image', ['gif']],
  [[0x50,0x4b,0x03,0x04], 'ZIP / Office / APK', ['zip','docx','xlsx','pptx','apk','jar']],
  [[0x52,0x61,0x72,0x21,0x1a,0x07], 'RAR Archive', ['rar']],
  [[0x37,0x7a,0xbc,0xaf,0x27,0x1c], '7-Zip Archive', ['7z']],
  [[0x1f,0x8b], 'GZIP Compressed', ['gz','tgz']],
  [[0x4d,0x5a], 'Windows PE Executable (MZ)', ['exe','dll','sys','msi']],
  [[0x7f,0x45,0x4c,0x46], 'Linux ELF Binary', ['elf','so','bin']],
  [[0x53,0x51,0x4c,0x69,0x74,0x65,0x20,0x66], 'SQLite 3 Database', ['db','sqlite','sqlite3']],
  [[0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1], 'MS Office Legacy (OLE2)', ['doc','xls','ppt','msg']]
];

function detectMagic(bytes, filename) {
  let det = null;
  if (bytes.length >= 12 && bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46) {
    const cc = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
    if (cc === 'WEBP') det = ['WebP Image', ['webp']];
    else if (cc === 'WAVE') det = ['WAV Audio', ['wav']];
  }
  if (!det && bytes.length >= 8 && bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
    det = ['MP4 / ISO Base Media', ['mp4','m4a','mov','heic']];
  }
  if (!det) {
    for (const [hex, type, exts] of SIGS) {
      if (bytes.length >= hex.length && hex.every((b, i) => bytes[i] === b)) { det = [type, exts]; break; }
    }
  }
  const headHex = Array.from(bytes.slice(0, 16), (b) => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
  const ext = (String(filename || '').toLowerCase().match(/\.([a-z0-9]+)$/) || [])[1] || '';
  if (!det) return { type: 'Texto ou binario generico', headHex, extension: ext || '(sem)', mismatch: false };
  return { type: det[0], headHex, extension: ext || '(sem)', mismatch: Boolean(ext && !det[1].includes(ext)) };
}

function calcEntropy(bytes) {
  if (!bytes.length) return { bits: 0, assessment: 'Vazio' };
  const freq = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
  let e = 0;
  for (let i = 0; i < 256; i++) if (freq[i]) { const p = freq[i] / bytes.length; e -= p * Math.log2(p); }
  const assessment = e >= 7.5 ? 'Muito Alta (criptografado/compactado)' : e >= 6.5 ? 'Alta (midia/empacotado)' : e >= 4.5 ? 'Media (codigo/estruturado)' : 'Baixa (texto simples)';
  return { bits: Number(e.toFixed(4)), assessment };
}

function buildHex(bytes, offset = 0, length = 2048) {
  const start = Math.max(0, Math.min(offset, bytes.length));
  const end = Math.min(bytes.length, start + length);
  const lines = [];
  for (let i = start; i < end; i += 16) {
    let h1 = '', h2 = '', asc = '';
    for (let j = 0; j < 16; j++) {
      if (i + j < end) {
        const b = bytes[i + j], hx = b.toString(16).padStart(2, '0').toUpperCase();
        if (j < 8) h1 += hx + ' '; else h2 += hx + ' ';
        asc += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      } else { if (j < 8) h1 += '   '; else h2 += '   '; asc += ' '; }
    }
    lines.push(`${i.toString(16).padStart(8, '0').toUpperCase()}  ${h1} ${h2} |${asc}|`);
  }
  return { offset: start, shownBytes: end - start, totalBytes: bytes.length, text: lines.join('\n') };
}

function extractStrings(bytes) {
  const strings = [], urls = new Set(), emails = new Set(), ips = new Set();
  const lim = Math.min(bytes.length, 4 * 1024 * 1024);
  let cur = '';
  const flush = () => {
    if (cur.length >= 5) {
      if (strings.length < 350) strings.push(cur);
      (cur.match(/https?:\/\/[^\s"'<>]+/gi) || []).forEach((u) => urls.add(u.slice(0, 140)));
      (cur.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []).forEach((e) => emails.add(e));
      (cur.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []).forEach((ip) => ips.add(ip));
    }
    cur = '';
  };
  for (let i = 0; i < lim; i++) {
    const b = bytes[i];
    if (b >= 32 && b <= 126) cur += String.fromCharCode(b); else flush();
  }
  flush();
  return { strings, iocs: { urls: [...urls].slice(0, 30), emails: [...emails].slice(0, 30), ips: [...ips].slice(0, 30) } };
}

const digest = async (alg, buf) => Array.from(new Uint8Array(await crypto.subtle.digest(alg, buf)), (b) => b.toString(16).padStart(2, '0')).join('');
let cached = null;

self.onmessage = async (ev) => {
  const m = ev.data || {};
  try {
    if (m.cmd === 'analyze') {
      const bytes = new Uint8Array(m.buffer);
      cached = bytes;
      const [sha256, sha512, sha1] = await Promise.all([digest('SHA-256', m.buffer), digest('SHA-512', m.buffer), digest('SHA-1', m.buffer)]);
      self.postMessage({
        ok: true, cmd: 'analyze',
        data: {
          filename: m.filename, size: bytes.byteLength,
          lastModified: m.lastModified ? new Date(m.lastModified).toISOString() : null,
          hashes: { md5: md5Bytes(bytes), sha1, sha256, sha512 },
          magic: detectMagic(bytes, m.filename),
          entropy: calcEntropy(bytes),
          hexDump: buildHex(bytes, 0, 2048),
          extracted: extractStrings(bytes)
        }
      });
    } else if (m.cmd === 'hexPage' && cached) {
      self.postMessage({ ok: true, cmd: 'hexPage', data: buildHex(cached, m.offset || 0, m.length || 2048) });
    }
  } catch (err) {
    self.postMessage({ ok: false, cmd: m.cmd, error: err?.message || 'Erro no Worker.' });
  }
};
