/*
 * CofreKey — o cofre criptografado
 *
 * Como funciona (conhecimento zero):
 *   1. Ao criar o cofre, sorteamos uma "chave de dados" aleatória (AES-256).
 *      É ela que criptografa as senhas e os códigos (AES-GCM).
 *   2. A chave de dados é guardada duas vezes, sempre criptografada:
 *        - com uma chave derivada da SENHA MESTRA (PBKDF2-SHA256);
 *        - com uma chave derivada do CÓDIGO DE RECUPERAÇÃO.
 *   3. Nem a senha mestra nem o código de recuperação são salvos.
 *
 * Vantagens desse desenho:
 *   - trocar a senha mestra não precisa recriptografar os dados;
 *   - o código de recuperação abre o cofre se a senha mestra for esquecida;
 *   - dá para diferenciar "senha errada" (a chave não abre) de
 *     "arquivo danificado" (a chave abre, mas os dados não).
 *
 * Funciona no navegador (window.CK.vault) e no Node.js (require) para os testes.
 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else (root.CK = root.CK || {}).vault = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const FORMAT = 2;
  const ITERATIONS = 600000; // PBKDF2-HMAC-SHA256, recomendação atual da OWASP
  const AAD = { key: 'cofrekey/v2/key', recovery: 'cofrekey/v2/recovery', data: 'cofrekey/v2/data' };
  const subtle = globalThis.crypto.subtle;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  class VaultError extends Error {
    constructor(code) {
      super(code);
      this.name = 'VaultError';
      this.code = code; // WRONG_PASSWORD | WRONG_CODE | CORRUPTED | INVALID_FORMAT
    }
  }

  /* ---------- utilitários ---------- */

  const random = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

  function toB64(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s);
  }

  function fromB64(text) {
    return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
  }

  async function deriveKek(secret, salt, iterations) {
    const base = await subtle.importKey('raw', enc.encode(String(secret).normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function seal(key, bytes, aad) {
    const iv = random(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, bytes));
    return { iv: toB64(iv), ct: toB64(ct) };
  }

  async function open(key, box, aad) {
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(box.iv), additionalData: enc.encode(aad) },
      key,
      fromB64(box.ct)
    );
    return new Uint8Array(pt);
  }

  const importDataKey = (raw) => subtle.importKey('raw', raw, 'AES-GCM', true, ['encrypt', 'decrypt']);

  /* ---------- código de recuperação ---------- */

  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  /** 128 bits aleatórios, em 26 letras/números agrupados de 4 em 4. */
  function newRecoveryCode() {
    const bytes = random(16);
    let bits = 0, value = 0, out = '';
    for (const b of bytes) {
      value = (value << 8) | b;
      bits += 8;
      while (bits >= 5) {
        out += B32[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    return out.replace(/(.{4})(?=.)/g, '$1-');
  }

  /** Aceita o código com ou sem traços, em minúsculas, e troca 0→O, 1→I, 8→B. */
  function normalizeRecoveryCode(text) {
    return String(text || '')
      .toUpperCase()
      .replace(/0/g, 'O').replace(/1/g, 'I').replace(/8/g, 'B')
      .replace(/[^A-Z2-7]/g, '');
  }

  /* ---------- formato do arquivo ---------- */

  const isBox = (b) => b && typeof b.iv === 'string' && typeof b.ct === 'string';

  function parse(text) {
    let r;
    try {
      r = typeof text === 'string' ? JSON.parse(text) : text;
    } catch (e) {
      throw new VaultError('INVALID_FORMAT');
    }
    const ok = r && r.app === 'CofreKey' && r.format === FORMAT &&
      r.kdf && typeof r.kdf.salt === 'string' && Number.isInteger(r.kdf.iterations) && r.kdf.iterations >= 100000 &&
      isBox(r.wrappedKey) && isBox(r.data) && Number.isInteger(r.rev) &&
      (!r.recovery || (isBox(r.recovery) && typeof r.recovery.salt === 'string'));
    if (!ok) throw new VaultError('INVALID_FORMAT');
    return r;
  }

  function serialize(record, pretty = false) {
    return JSON.stringify(record, null, pretty ? 2 : 0);
  }

  /* ---------- operações ---------- */

  async function wrapWithSecret(rawKey, secret, aad, iterations) {
    const salt = random(16);
    const kek = await deriveKek(secret, salt, iterations);
    return { salt: toB64(salt), ...(await seal(kek, rawKey, aad)) };
  }

  /** Cria um cofre novo. Devolve o registro para salvar, a sessão aberta e o código de recuperação. */
  async function create(password, data, { iterations = ITERATIONS } = {}) {
    const raw = random(32);
    const recoveryCode = newRecoveryCode();
    const main = await wrapWithSecret(raw, password, AAD.key, iterations);
    const recovery = await wrapWithSecret(raw, normalizeRecoveryCode(recoveryCode), AAD.recovery, iterations);
    const session = { key: await importDataKey(raw) };
    raw.fill(0);
    const base = {
      app: 'CofreKey',
      format: FORMAT,
      kdf: { name: 'PBKDF2', hash: 'SHA-256', iterations, salt: main.salt },
      wrappedKey: { iv: main.iv, ct: main.ct },
      recovery: { iterations, salt: recovery.salt, iv: recovery.iv, ct: recovery.ct },
      rev: 0,
      data: null,
    };
    const record = await save(session, base, data);
    return { record, session, recoveryCode };
  }

  /** Criptografa os dados de novo e devolve o registro atualizado (rev + 1). */
  async function save(session, record, data) {
    const box = await seal(session.key, enc.encode(JSON.stringify(data)), AAD.data);
    return { ...record, rev: (record.rev || 0) + 1, data: box, updatedAt: new Date().toISOString() };
  }

  async function openData(session, record) {
    try {
      return JSON.parse(dec.decode(await open(session.key, record.data, AAD.data)));
    } catch (e) {
      throw new VaultError('CORRUPTED');
    }
  }

  async function unlock(record, password) {
    parse(record);
    let raw;
    try {
      const kek = await deriveKek(password, fromB64(record.kdf.salt), record.kdf.iterations);
      raw = await open(kek, record.wrappedKey, AAD.key);
    } catch (e) {
      throw new VaultError('WRONG_PASSWORD');
    }
    const session = { key: await importDataKey(raw) };
    raw.fill(0);
    return { session, data: await openData(session, record) };
  }

  async function unlockWithRecovery(record, code) {
    parse(record);
    if (!record.recovery) throw new VaultError('WRONG_CODE');
    let raw;
    try {
      const kek = await deriveKek(normalizeRecoveryCode(code), fromB64(record.recovery.salt), record.recovery.iterations);
      raw = await open(kek, record.recovery, AAD.recovery);
    } catch (e) {
      throw new VaultError('WRONG_CODE');
    }
    const session = { key: await importDataKey(raw) };
    raw.fill(0);
    return { session, data: await openData(session, record) };
  }

  /** Troca a senha mestra: só a chave de dados é recriptografada. */
  async function changePassword(session, record, newPassword) {
    const raw = new Uint8Array(await subtle.exportKey('raw', session.key));
    const iterations = record.kdf.iterations;
    const main = await wrapWithSecret(raw, newPassword, AAD.key, iterations);
    raw.fill(0);
    return {
      ...record,
      kdf: { ...record.kdf, salt: main.salt },
      wrappedKey: { iv: main.iv, ct: main.ct },
      rev: record.rev + 1,
      updatedAt: new Date().toISOString(),
    };
  }

  /** Gera um novo código de recuperação; o anterior deixa de funcionar. */
  async function newRecovery(session, record) {
    const raw = new Uint8Array(await subtle.exportKey('raw', session.key));
    const recoveryCode = newRecoveryCode();
    const iterations = record.kdf.iterations;
    const rec = await wrapWithSecret(raw, normalizeRecoveryCode(recoveryCode), AAD.recovery, iterations);
    raw.fill(0);
    return {
      recoveryCode,
      record: {
        ...record,
        recovery: { iterations, salt: rec.salt, iv: rec.iv, ct: rec.ct },
        rev: record.rev + 1,
        updatedAt: new Date().toISOString(),
      },
    };
  }

  return {
    VaultError, ITERATIONS, create, save, unlock, unlockWithRecovery, changePassword, newRecovery,
    parse, serialize, newRecoveryCode, normalizeRecoveryCode,
  };
});
