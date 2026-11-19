/*
 * CofreKey — códigos de verificação em duas etapas (2FA)
 *
 * Implementa o TOTP (RFC 6238), que usa o HOTP (RFC 4226): o mesmo padrão do
 * Google Authenticator. O código depende só da chave secreta e do relógio, por
 * isso funciona sem internet.
 *
 * Também lê os QR codes de cadastro (otpauth://totp/...) e os de exportação do
 * Google Authenticator (otpauth-migration://offline?data=...).
 *
 * Funciona no navegador (window.CK.totp) e no Node.js (require) para os testes.
 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else (root.CK = root.CK || {}).totp = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const ALGOS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };
  const subtle = globalThis.crypto.subtle;

  /* ---------- Base32 (RFC 4648), formato usado nas chaves secretas ---------- */

  function cleanSecret(text) {
    return String(text || '').toUpperCase().replace(/[\s=-]/g, '');
  }

  function isValidSecret(text) {
    const s = cleanSecret(text);
    return s.length >= 16 && /^[A-Z2-7]+$/.test(s);
  }

  function base32Decode(text) {
    const s = cleanSecret(text);
    let bits = 0, value = 0;
    const out = [];
    for (const ch of s) {
      const idx = ALPHABET.indexOf(ch);
      if (idx < 0) throw new Error('INVALID_SECRET');
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 255);
        bits -= 8;
      }
    }
    return new Uint8Array(out);
  }

  function base32Encode(bytes) {
    let bits = 0, value = 0, out = '';
    for (const b of bytes) {
      value = (value << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out += ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
    return out;
  }

  function randomSecret(byteLength = 20) {
    return base32Encode(globalThis.crypto.getRandomValues(new Uint8Array(byteLength)));
  }

  function groupSecret(secret) {
    return cleanSecret(secret).replace(/(.{4})/g, '$1 ').trim();
  }

  /* ---------- HOTP / TOTP ---------- */

  // Guarda a chave HMAC já importada para não refazer o trabalho a cada segundo.
  const keyCache = new Map();

  async function hmacKey(secret, algo) {
    const id = algo + ':' + cleanSecret(secret);
    let key = keyCache.get(id);
    if (!key) {
      key = await subtle.importKey('raw', base32Decode(secret), { name: 'HMAC', hash: algo }, false, ['sign']);
      keyCache.set(id, key);
    }
    return key;
  }

  async function hotp(secret, counter, { digits = 6, algo = 'SHA-1' } = {}) {
    const msg = new ArrayBuffer(8);
    const view = new DataView(msg);
    view.setUint32(0, Math.floor(counter / 2 ** 32));
    view.setUint32(4, counter >>> 0);
    const mac = new Uint8Array(await subtle.sign('HMAC', await hmacKey(secret, algo), msg));
    const offset = mac[mac.length - 1] & 15; // "dynamic truncation" da RFC 4226
    const bin = ((mac[offset] & 127) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
    return String(bin % 10 ** digits).padStart(digits, '0');
  }

  function counterAt(account, timeMs = Date.now()) {
    return Math.floor(timeMs / 1000 / (account.period || 30));
  }

  function generate(account, timeMs = Date.now()) {
    return hotp(account.secret, counterAt(account, timeMs), {
      digits: account.digits || 6,
      algo: account.algo || 'SHA-1',
    });
  }

  /** Segundos que faltam para o código mudar. */
  function secondsLeft(account, timeMs = Date.now()) {
    const period = account.period || 30;
    return period - ((timeMs / 1000) % period);
  }

  function clearCache() {
    keyCache.clear();
  }

  /* ---------- QR code de cadastro: otpauth://totp/Emissor:conta?secret=... ---------- */

  function parseUri(text) {
    let url;
    try {
      url = new URL(String(text).trim());
    } catch (e) {
      throw new Error('INVALID_URI');
    }
    if (url.protocol === 'otpauth-migration:') throw new Error('MIGRATION');
    if (url.protocol !== 'otpauth:') throw new Error('INVALID_URI');
    const type = (url.host || url.pathname.replace(/^\/+/, '').split('/')[0]).toLowerCase();
    if (type === 'hotp') throw new Error('UNSUPPORTED_HOTP');
    if (type !== 'totp') throw new Error('INVALID_URI');

    const label = decodeURIComponent(url.pathname.replace(/^\/+/, '').replace(/^totp\//i, ''));
    const sep = label.indexOf(':');
    const labelIssuer = sep >= 0 ? label.slice(0, sep).trim() : '';
    const account = (sep >= 0 ? label.slice(sep + 1) : label).trim();
    const p = url.searchParams;
    const algo = ALGOS[(p.get('algorithm') || 'SHA1').toUpperCase()];
    const digits = parseInt(p.get('digits') || '6', 10);
    const period = parseInt(p.get('period') || '30', 10);
    const secret = cleanSecret(p.get('secret'));

    if (!algo || ![6, 7, 8].includes(digits) || !(period >= 10 && period <= 120)) throw new Error('UNSUPPORTED_PARAMS');
    if (!isValidSecret(secret)) throw new Error('INVALID_SECRET');
    return { issuer: (p.get('issuer') || labelIssuer).trim(), account, secret, digits, period, algo };
  }

  function buildUri(account) {
    const issuer = account.issuer || 'CofreKey';
    const label = encodeURIComponent(issuer) + ':' + encodeURIComponent(account.account || issuer);
    const params = new URLSearchParams({
      secret: cleanSecret(account.secret),
      issuer,
      algorithm: (account.algo || 'SHA-1').replace('-', ''),
      digits: String(account.digits || 6),
      period: String(account.period || 30),
    });
    return `otpauth://totp/${label}?${params.toString()}`;
  }

  /* ---------- Exportação do Google Authenticator (protobuf) ----------
   * message MigrationPayload { repeated OtpParameters otp_parameters = 1; ... }
   * message OtpParameters {
   *   bytes secret = 1; string name = 2; string issuer = 3;
   *   Algorithm algorithm = 4;  // 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
   *   DigitCount digits = 5;    // 1 seis, 2 oito
   *   OtpType type = 6;         // 1 HOTP, 2 TOTP
   * }
   */
  function readFields(bytes) {
    const fields = [];
    let i = 0;
    const varint = () => {
      let result = 0, shift = 0, b;
      do {
        if (i >= bytes.length) throw new Error('INVALID_MIGRATION');
        b = bytes[i++];
        result += (b & 127) * 2 ** shift;
        shift += 7;
      } while (b & 128);
      return result;
    };
    while (i < bytes.length) {
      const tag = varint();
      const field = Math.floor(tag / 8), wire = tag & 7;
      if (wire === 0) fields.push({ field, value: varint() });
      else if (wire === 2) {
        const len = varint();
        if (i + len > bytes.length) throw new Error('INVALID_MIGRATION');
        fields.push({ field, bytes: bytes.subarray(i, i + len) });
        i += len;
      } else if (wire === 1) i += 8;
      else if (wire === 5) i += 4;
      else throw new Error('INVALID_MIGRATION');
    }
    return fields;
  }

  function parseMigration(text) {
    let url;
    try {
      url = new URL(String(text).trim());
    } catch (e) {
      throw new Error('INVALID_MIGRATION');
    }
    if (url.protocol !== 'otpauth-migration:') throw new Error('INVALID_MIGRATION');
    const data = url.searchParams.get('data');
    if (!data) throw new Error('INVALID_MIGRATION');
    let raw;
    try {
      raw = Uint8Array.from(atob(data.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '+')), (c) => c.charCodeAt(0));
    } catch (e) {
      throw new Error('INVALID_MIGRATION');
    }
    const textDec = new TextDecoder();
    const accounts = [];
    let skipped = 0;
    for (const top of readFields(raw)) {
      if (top.field !== 1 || !top.bytes) continue;
      const o = { algo: 1, digits: 1, type: 2 };
      for (const f of readFields(top.bytes)) {
        if (f.field === 1) o.secret = f.bytes;
        else if (f.field === 2) o.name = textDec.decode(f.bytes);
        else if (f.field === 3) o.issuer = textDec.decode(f.bytes);
        else if (f.field === 4) o.algo = f.value;
        else if (f.field === 5) o.digits = f.value;
        else if (f.field === 6) o.type = f.value;
      }
      const algo = { 0: 'SHA-1', 1: 'SHA-1', 2: 'SHA-256', 3: 'SHA-512' }[o.algo];
      if (o.type !== 2 || !algo || !o.secret || o.secret.length < 10) {
        skipped++;
        continue;
      }
      let name = (o.name || '').trim(), issuer = (o.issuer || '').trim();
      const sep = name.indexOf(':');
      if (sep >= 0) {
        if (!issuer) issuer = name.slice(0, sep).trim();
        name = name.slice(sep + 1).trim();
      }
      accounts.push({
        issuer: issuer || name || 'Conta',
        account: issuer ? name : '',
        secret: base32Encode(o.secret),
        digits: o.digits === 2 ? 8 : 6,
        period: 30,
        algo,
      });
    }
    return { accounts, skipped };
  }

  return {
    cleanSecret, isValidSecret, base32Decode, base32Encode, randomSecret, groupSecret,
    hotp, generate, secondsLeft, counterAt, clearCache, parseUri, buildUri, parseMigration,
  };
});
