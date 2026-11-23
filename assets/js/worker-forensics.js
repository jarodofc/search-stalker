'use strict';

// Pure-JS RFC 1321 MD5 implementation (Web Crypto API intentionally omits MD5)
function md5Bytes(bytes) {
  const len = bytes.length;
  const bitLenLo = (len << 3) >>> 0;
  const bitLenHi = (len >>> 29) >>> 0;
  const padLen = ((56 - ((len + 1) % 64)) + 64) % 64;
  const totalLen = len + 1 + padLen + 8;
  const buf = new Uint8Array(totalLen);
  buf.set(bytes);
  buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(totalLen - 8, bitLenLo, true);
  dv.setUint32(totalLen - 4, bitLenHi, true);

  const S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ];
  const K = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) >>> 0;
  }

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const M = new Uint32Array(16);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let j = 0; j < 16; j++) {
      M[j] = dv.getUint32(offset + j * 4, true);
    }
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) {
        F = (B & C) | (~B & D);
        g = i;
      } else if (i < 32) {
        F = (D & B) | (~D & C);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        F = B ^ C ^ D;
        g = (3 * i + 5) % 16;
      } else {
        F = C ^ (B | ~D);
        g = (7 * i) % 16;
      }
      const sum = (F + A + K[i] + M[g]) >>> 0;
      A = D;
      D = C;
      C = B;
      const s = S[i];
      B = (B + ((sum << s) | (sum >>> (32 - s)))) >>> 0;
    }
    a0 = (a0 + A) >>> 0;
    b0 = (b0 + B) >>> 0;
    c0 = (c0 + C) >>> 0;
    d0 = (d0 + D) >>> 0;
  }

  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer);
  odv.setUint32(0, a0, true);
  odv.setUint32(4, b0, true);
  odv.setUint32(8, c0, true);
  odv.setUint32(12, d0, true);
  return Array.from(out, (b) => b.toString(16).padStart(2, '0')).join('');
}

const SIGNATURES = [
  { hex: [0x25, 0x50, 0x44, 0x46], type: 'PDF Document', exts: ['pdf'] },
  { hex: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], type: 'PNG Image', exts: ['png'] },
  { hex: [0xff, 0xd8, 0xff], type: 'JPEG Image', exts: ['jpg', 'jpeg', 'jfif'] },
  { hex: [0x47, 0x49, 0x46, 0x38], type: 'GIF Image', exts: ['gif'] },
  { hex: [0x50, 0x4b, 0x03, 0x04], type: 'ZIP / Office / APK Archive', exts: ['zip', 'docx', 'xlsx', 'pptx', 'apk', 'jar', 'odt'] },
  { hex: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], type: 'RAR Archive', exts: ['rar'] },
  { hex: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], type: '7-Zip Archive', exts: ['7z'] },
  { hex: [0x1f, 0x8b], type: 'GZIP Compressed', exts: ['gz', 'tgz'] },
  { hex: [0x4d, 0x5a], type: 'Windows PE / Executable (MZ)', exts: ['exe', 'dll', 'sys', 'scr', 'msi'] },
  { hex: [0x7f, 0x45, 0x4c, 0x46], type: 'Linux ELF Binary', exts: ['elf', 'so', 'bin', 'out'] },
  { hex: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66], type: 'SQLite 3 Database', exts: ['db', 'sqlite', 'sqlite3'] },
  { hex: [0x49, 0x44, 0x33], type: 'MP3 Audio (ID3)', exts: ['mp3'] },
  { hex: [0x4f, 0x67, 0x67, 0x53], type: 'OGG Media', exts: ['ogg', 'oga', 'ogv'] },
  { hex: [0x42, 0x4d], type: 'BMP Image', exts: ['bmp'] },
  { hex: [0x49, 0x49, 0x2a, 0x00], type: 'TIFF Image (LE)', exts: ['tif', 'tiff'] },
  { hex: [0x4d, 0x4d, 0x00, 0x2a], type: 'TIFF Image (BE)', exts: ['tif', 'tiff'] },
  { hex: [0x00, 0x00, 0x01, 0x00], type: 'ICO Icon', exts: ['ico'] },
  { hex: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], type: 'MS Office Legacy (OLE2)', exts: ['doc', 'xls', 'ppt', 'msg'] }
];

function detectMagic(bytes, filename) {
  let detected = null;
  if (bytes.length >= 12 &&
      bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46) {
    const fourcc = String.fromCharCode(bytes[8], bytes[9], bytes[10], bytes[11]);
    if (fourcc === 'WEBP') detected = { type: 'WebP Image', exts: ['webp'] };
    else if (fourcc === 'WAVE') detected = { type: 'WAV Audio', exts: ['wav'] };
    else if (fourcc === 'AVI ') detected = { type: 'AVI Video', exts: ['avi'] };
  }
  if (!detected && bytes.length >= 8 &&
      bytes[4] === 0x66 && bytes[5] === 0x74 && bytes[6] === 0x79 && bytes[7] === 0x70) {
    detected = { type: 'MP4 / ISO Base Media', exts: ['mp4', 'm4a', 'm4v', 'mov', 'heic'] };
  }
  if (!detected) {
    for (const sig of SIGNATURES) {
      if (bytes.length >= sig.hex.length && sig.hex.every((b, idx) => bytes[idx] === b)) {
        detected = sig;
        break;
      }
    }
  }

  const headHex = Array.from(bytes.slice(0, 16), (b) => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
  const extMatch = String(filename || '').toLowerCase().match(/\.([a-z0-9]+)$/);
  const ext = extMatch ? extMatch[1] : '';

  if (!detected) {
    // Heuristica para texto ASCII/UTF-8
    let printable = 0;
    const sampleLen = Math.min(bytes.length, 1024);
    for (let i = 0; i < sampleLen; i++) {
      const b = bytes[i];
      if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13 || b >= 128) printable++;
    }
    const isText = sampleLen > 0 && (printable / sampleLen) > 0.92;
    return {
      type: isText ? 'Texto / Codigo-fonte (UTF-8/ASCII)' : 'Binario desconhecido',
      headHex,
      extension: ext || '(sem extensao)',
      mismatch: false
    };
  }

  const mismatch = Boolean(ext && !detected.exts.includes(ext));
  return {
    type: detected.type,
    headHex,
    extension: ext || '(sem extensao)',
    expectedExts: detected.exts,
    mismatch
  };
}

function calcEntropy(bytes) {
  if (!bytes.length) return { bits: 0, assessment: 'Arquivo vazio' };
  const freq = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
  let ent = 0;
  const n = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / n;
      ent -= p * Math.log2(p);
    }
  }
  let assessment = 'Baixa (texto simples / estrutura esparsa)';
  if (ent >= 7.5) assessment = 'Muito Alta (criptografado, compactado ou ofuscado)';
  else if (ent >= 6.5) assessment = 'Alta (midia compactada ou binario empacotado)';
  else if (ent >= 4.5) assessment = 'Media (codigo compilado ou texto estruturado)';
  return { bits: Number(ent.toFixed(4)), assessment };
}

function buildHexDump(bytes, offset = 0, length = 2048) {
  const start = Math.max(0, Math.min(offset, bytes.length));
  const end = Math.min(bytes.length, start + length);
  const lines = [];
  for (let i = start; i < end; i += 16) {
    const addr = i.toString(16).padStart(8, '0').toUpperCase();
    let hexLeft = '';
    let hexRight = '';
    let ascii = '';
    for (let j = 0; j < 16; j++) {
      if (i + j < end) {
        const b = bytes[i + j];
        const h = b.toString(16).padStart(2, '0').toUpperCase();
        if (j < 8) hexLeft += h + ' ';
        else hexRight += h + ' ';
        ascii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
      } else {
        if (j < 8) hexLeft += '   ';
        else hexRight += '   ';
        ascii += ' ';
      }
    }
    lines.push(`${addr}  ${hexLeft} ${hexRight} |${ascii}|`);
  }
  return {
    offset: start,
    shownBytes: end - start,
    totalBytes: bytes.length,
    text: lines.join('\n')
  };
}

function extractStrings(bytes, minLen = 5, maxItems = 400) {
  const results = [];
  const iocs = { urls: new Set(), emails: new Set(), ips: new Set() };
  let current = '';
  const limit = Math.min(bytes.length, 4 * 1024 * 1024); // analisa ate 4 MB para manter resposta instantanea

  const flush = () => {
    if (current.length >= minLen) {
      if (results.length < maxItems) results.push(current);
      const urls = current.match(/https?:\/\/[^\s"'<>]+/gi);
      if (urls) urls.forEach((u) => iocs.urls.add(u.slice(0, 140)));
      const emails = current.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
      if (emails) emails.forEach((e) => iocs.emails.add(e));
      const ips = current.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
      if (ips) ips.forEach((ip) => iocs.ips.add(ip));
    }
    current = '';
  };

  for (let i = 0; i < limit; i++) {
    const b = bytes[i];
    if (b >= 32 && b <= 126) {
      current += String.fromCharCode(b);
    } else {
      flush();
    }
  }
  flush();

  return {
    strings: results,
    truncated: bytes.length > limit || results.length >= maxItems,
    iocs: {
      urls: [...iocs.urls].slice(0, 40),
      emails: [...iocs.emails].slice(0, 40),
      ips: [...iocs.ips].slice(0, 40)
    }
  };
}

async function digestHex(algo, buffer) {
  const hashBuf = await crypto.subtle.digest(algo, buffer);
  return Array.from(new Uint8Array(hashBuf), (b) => b.toString(16).padStart(2, '0')).join('');
}

let cachedBytes = null;

self.onmessage = async (event) => {
  const msg = event.data || {};
  try {
    if (msg.cmd === 'analyze') {
      const bytes = new Uint8Array(msg.buffer);
      cachedBytes = bytes;
      const [sha256, sha512, sha1] = await Promise.all([
        digestHex('SHA-256', msg.buffer),
        digestHex('SHA-512', msg.buffer),
        digestHex('SHA-1', msg.buffer)
      ]);
      const md5 = md5Bytes(bytes);
      const magic = detectMagic(bytes, msg.filename);
      const entropy = calcEntropy(bytes);
      const hexDump = buildHexDump(bytes, 0, 2048);
      const extracted = extractStrings(bytes, msg.minStringLen || 5);

      self.postMessage({
        ok: true,
        cmd: 'analyze',
        data: {
          filename: msg.filename,
          size: bytes.byteLength,
          mimeType: msg.mimeType || 'application/octet-stream',
          lastModified: msg.lastModified ? new Date(msg.lastModified).toISOString() : null,
          hashes: { md5, sha1, sha256, sha512 },
          magic,
          entropy,
          hexDump,
          extracted
        }
      });
    } else if (msg.cmd === 'hexPage') {
      if (!cachedBytes) {
        self.postMessage({ ok: false, error: 'Nenhum arquivo carregado na memoria do Worker.' });
        return;
      }
      const hexDump = buildHexDump(cachedBytes, msg.offset || 0, msg.length || 2048);
      self.postMessage({ ok: true, cmd: 'hexPage', data: hexDump });
    }
  } catch (err) {
    self.postMessage({ ok: false, cmd: msg.cmd, error: err ? err.message : 'Erro no Web Worker forense.' });
  }
};
