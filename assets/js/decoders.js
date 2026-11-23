function base64UrlToUtf8(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

export function decodeJwt(token) {
  const parts = String(token || '').trim().split('.');
  if (parts.length < 2 || parts.length > 3) {
    throw new Error('Formato JWT invalido. Esperado: header.payload.signature');
  }
  const header = JSON.parse(base64UrlToUtf8(parts[0]));
  const payload = JSON.parse(base64UrlToUtf8(parts[1]));
  const nowSec = Math.floor(Date.now() / 1000);
  const warnings = [];

  if (!header.alg || String(header.alg).toLowerCase() === 'none') {
    warnings.push('CRITICO: Algoritmo "none" detectado (token sem assinatura criptografica).');
  }
  if (!parts[2]) {
    warnings.push('Assinatura ausente no terceiro segmento do token.');
  }
  if (typeof payload.exp === 'number') {
    if (payload.exp < nowSec) warnings.push(`Token EXPIRADO em ${new Date(payload.exp * 1000).toISOString()}.`);
    else warnings.push(`Token valido ate ${new Date(payload.exp * 1000).toISOString()}.`);
  }
  if (typeof payload.iat === 'number') {
    warnings.push(`Emitido em (iat): ${new Date(payload.iat * 1000).toISOString()}.`);
  }

  return { header, payload, signature: parts[2] || '(vazia)', warnings };
}

export function transformText(mode, input) {
  const text = String(input || '');
  switch (mode) {
    case 'b64_encode': {
      const bytes = new TextEncoder().encode(text);
      let bin = '';
      bytes.forEach((b) => { bin += String.fromCharCode(b); });
      return btoa(bin);
    }
    case 'b64_decode':
      return base64UrlToUtf8(text.trim());
    case 'hex_encode': {
      const bytes = new TextEncoder().encode(text);
      return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join(' ');
    }
    case 'hex_decode': {
      const clean = text.replace(/[^a-fA-F0-9]/g, '');
      if (!clean || clean.length % 2 !== 0) throw new Error('Hexadecimal invalido (comprimento impar).');
      const bytes = new Uint8Array(clean.length / 2);
      for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
      return new TextDecoder().decode(bytes);
    }
    case 'url_encode':
      return encodeURIComponent(text);
    case 'url_decode':
      return decodeURIComponent(text);
    case 'rot13':
      return text.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      });
    case 'timestamp': {
      const trimmed = text.trim();
      if (/^\d{10,13}$/.test(trimmed)) {
        const ms = trimmed.length === 10 ? Number(trimmed) * 1000 : Number(trimmed);
        const d = new Date(ms);
        return `UTC: ${d.toISOString()}\nLocal: ${d.toLocaleString('pt-BR')}\nEpoch (s): ${Math.floor(ms / 1000)}`;
      }
      const parsed = Date.parse(trimmed);
      if (Number.isNaN(parsed)) throw new Error('Informe um Unix Epoch (10 ou 13 digitos) ou data ISO valida.');
      return `Epoch (s): ${Math.floor(parsed / 1000)}\nEpoch (ms): ${parsed}\nUTC: ${new Date(parsed).toISOString()}`;
    }
    case 'cidr': {
      const m = text.trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
      if (!m) throw new Error('Use o formato IPv4/CIDR (ex: 192.168.1.0/24).');
      const octs = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
      const prefix = Number(m[5]);
      if (octs.some((o) => o > 255) || prefix > 32) throw new Error('IP ou mascara fora do intervalo valido.');
      const ipInt = ((octs[0] << 24) | (octs[1] << 16) | (octs[2] << 8) | octs[3]) >>> 0;
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      const net = (ipInt & mask) >>> 0;
      const bcast = (net | (~mask >>> 0)) >>> 0;
      const toIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
      const total = Math.pow(2, 32 - prefix);
      const usable = prefix >= 31 ? total : Math.max(0, total - 2);
      return [
        `Rede:       ${toIp(net)}/${prefix}`,
        `Mascara:    ${toIp(mask)}`,
        `Broadcast:  ${toIp(bcast)}`,
        `Primeiro:   ${prefix >= 31 ? toIp(net) : toIp(net + 1)}`,
        `Ultimo:     ${prefix >= 31 ? toIp(bcast) : toIp(bcast - 1)}`,
        `Total IPs:  ${total.toLocaleString('pt-BR')} (${usable.toLocaleString('pt-BR')} utilizaveis)`
      ].join('\n');
    }
    default:
      throw new Error('Modo de transformacao desconhecido.');
  }
}
