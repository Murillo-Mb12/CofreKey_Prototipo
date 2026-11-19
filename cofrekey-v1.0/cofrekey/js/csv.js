/*
 * CofreKey — importação de senhas por CSV
 *
 * Lê os arquivos exportados pelo Chrome, Edge, Firefox, Safari e Bitwarden.
 * Cada linha vira uma senha; se o arquivo trouxer o código de verificação
 * (coluna login_totp/otpauth), ele vira também um código no autenticador.
 *
 * Funciona no navegador (window.CK.csv) e no Node.js (require) para os testes.
 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else (root.CK = root.CK || {}).csv = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /** CSV no padrão RFC 4180: aspas, aspas duplas escapadas e quebras de linha dentro de campos. */
  function parse(text) {
    const s = String(text || '').replace(/^﻿/, '');
    const delimiter = detectDelimiter(s);
    const rows = [];
    let row = [], field = '', quoted = false;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (quoted) {
        if (c === '"') {
          if (s[i + 1] === '"') { field += '"'; i++; } else quoted = false;
        } else field += c;
      } else if (c === '"') quoted = true;
      else if (c === delimiter) { row.push(field); field = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && s[i + 1] === '\n') i++;
        row.push(field); field = '';
        if (row.some((v) => v !== '')) rows.push(row);
        row = [];
      } else field += c;
    }
    row.push(field);
    if (row.some((v) => v !== '')) rows.push(row);
    return rows;
  }

  function detectDelimiter(s) {
    const firstLine = s.split(/\r?\n/, 1)[0] || '';
    return (firstLine.match(/;/g) || []).length > (firstLine.match(/,/g) || []).length ? ';' : ',';
  }

  const COLUMNS = {
    site: ['name', 'title', 'nome', 'site', 'website'],
    url: ['url', 'login_uri', 'uri', 'endereco', 'endereço', 'website'],
    user: ['username', 'login_username', 'user', 'usuario', 'usuário', 'email', 'login'],
    pass: ['password', 'login_password', 'senha'],
    note: ['note', 'notes', 'extra', 'observacoes', 'observações', 'comments'],
    totp: ['login_totp', 'totp', 'otpauth', 'otp'],
  };

  function hostOf(url) {
    try {
      return new URL(/^[a-z]+:\/\//i.test(url) ? url : 'https://' + url).hostname.replace(/^www\./, '');
    } catch (e) {
      return '';
    }
  }

  /**
   * Converte as linhas em itens do cofre.
   * Devolve { logins: [...], codes: [...], skipped } — codes são textos otpauth:// ou chaves.
   */
  function toItems(rows) {
    if (!rows.length) return { logins: [], codes: [], skipped: 0 };
    const header = rows[0].map((h) => h.trim().toLowerCase());
    const col = {};
    for (const [key, names] of Object.entries(COLUMNS)) {
      col[key] = header.findIndex((h) => names.includes(h));
    }
    if (col.pass < 0) throw new Error('NO_PASSWORD_COLUMN');

    const logins = [], codes = [];
    let skipped = 0;
    for (const r of rows.slice(1)) {
      const get = (k) => (col[k] >= 0 ? (r[col[k]] || '').trim() : '');
      const pass = col.pass >= 0 ? r[col.pass] || '' : '';
      const url = get('url');
      const site = (col.site >= 0 && col.site !== col.url ? get('site') : '') || hostOf(url) || url;
      if (!pass || !site) { skipped++; continue; }
      logins.push({ site, user: get('user'), pass, url, note: get('note') });
      const totp = get('totp');
      if (totp) codes.push({ site, user: get('user'), value: totp });
    }
    return { logins, codes, skipped };
  }

  return { parse, toItems, hostOf };
});
