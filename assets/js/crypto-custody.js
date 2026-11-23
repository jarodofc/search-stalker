const STORAGE_KEY = 'zforense_dossier_v2';
const SESSION_SECRET_KEY = 'zforense_session_seed_v2';

function bytesToHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function getOrCreateSeed() {
  let seed = sessionStorage.getItem(SESSION_SECRET_KEY);
  if (!seed) {
    const rand = new Uint8Array(32);
    crypto.getRandomValues(rand);
    seed = bytesToHex(rand);
    sessionStorage.setItem(SESSION_SECRET_KEY, seed);
  }
  return seed;
}

async function deriveAesKey() {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(getOrCreateSeed()),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode('zFORENSE-v2-custody-salt'),
      iterations: 50000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function saveEncryptedDossier(items) {
  try {
    if (!window.crypto || !window.crypto.subtle) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ plain: true, items }));
      return;
    }
    const key = await deriveAesKey();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(items));
    const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
    const envelope = {
      alg: 'AES-256-GCM',
      iv: bytesToB64(iv),
      ct: bytesToB64(new Uint8Array(cipherBuf)),
      updatedAt: new Date().toISOString()
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
  } catch {
    // Fallback silencioso se storage estiver indisponivel
  }
}

export async function loadEncryptedDossier() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const env = JSON.parse(raw);
    if (env.plain && Array.isArray(env.items)) return env.items;
    if (!env.iv || !env.ct || !window.crypto || !window.crypto.subtle) return [];
    const key = await deriveAesKey();
    const plainBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(env.iv) },
      key,
      b64ToBytes(env.ct)
    );
    const parsed = JSON.parse(new TextDecoder().decode(plainBuf));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function clearEncryptedDossier() {
  try { localStorage.removeItem(STORAGE_KEY); } catch {}
}

/**
 * Generates an integrity-sealed JSON export with SHA-256 content hash and HMAC-SHA256 signature.
 */
export async function buildSignedExport(moduleName, payload, proxyMeta = {}) {
  const exportedAt = new Date().toISOString();
  const body = {
    platform: 'zFORENSE',
    version: '2.0.0',
    module: moduleName,
    exportedAt,
    transport: {
      mode: proxyMeta.mode || 'local-client',
      region: proxyMeta.region || 'browser'
    },
    data: payload
  };

  const canonical = JSON.stringify(body);
  const enc = new TextEncoder().encode(canonical);

  let sha256 = 'unavailable-insecure-context';
  let hmacSha256 = 'unavailable-insecure-context';

  if (window.crypto && window.crypto.subtle) {
    const hashBuf = await crypto.subtle.digest('SHA-256', enc);
    sha256 = bytesToHex(new Uint8Array(hashBuf));

    const hmacKey = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(`zFORENSE::${getOrCreateSeed()}`),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const sigBuf = await crypto.subtle.sign('HMAC', hmacKey, enc);
    hmacSha256 = bytesToHex(new Uint8Array(sigBuf));
  }

  return {
    ...body,
    custody: {
      algorithm: 'SHA-256 + HMAC-SHA256',
      contentSha256: sha256,
      sessionHmacSha256: hmacSha256
    }
  };
}
