/*
 * CofreKey — gerador de senhas e medidor de força
 *
 * O gerador usa crypto.getRandomValues (aleatório criptograficamente seguro),
 * nunca Math.random. O medidor estima a força pelo tamanho e pela variedade de
 * caracteres e penaliza padrões comuns (sequências, repetições, senhas famosas).
 *
 * Funciona no navegador (window.CK.passwords) e no Node.js (require) para os testes.
 */
(function (root, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else (root.CK = root.CK || {}).passwords = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Sem caracteres que se confundem (0/O, 1/l/I) para facilitar quando a senha é digitada.
  const SETS = {
    upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
    lower: 'abcdefghijkmnopqrstuvwxyz',
    digits: '23456789',
    symbols: '!@#$%&*?-_=+.',
  };

  const COMMON = [
    '123456', '1234567', '12345678', '123456789', '1234567890', '111111', '000000', '123123', '654321',
    'senha', 'senha123', 'password', 'qwerty', 'abc123', 'admin', 'iloveyou', 'brasil', 'flamengo',
    'corinthians', 'palmeiras', 'saopaulo', 'gremio', 'teamo', 'mudar123', 'master', 'welcome',
  ];

  /** Inteiro aleatório em [0, max) sem viés de módulo. */
  function randomInt(max) {
    const limit = Math.floor(0x100000000 / max) * max;
    const buf = new Uint32Array(1);
    do globalThis.crypto.getRandomValues(buf); while (buf[0] >= limit);
    return buf[0] % max;
  }

  /**
   * Gera uma senha com pelo menos um caractere de cada tipo escolhido.
   * options: { length: 8..64, upper, lower, digits, symbols }
   */
  function generate(options = {}) {
    const length = Math.min(64, Math.max(8, options.length || 16));
    const pools = Object.keys(SETS).filter((k) => options[k] !== false).map((k) => SETS[k]);
    if (!pools.length) throw new Error('NO_CHARSET');
    const all = pools.join('');
    const chars = pools.map((p) => p[randomInt(p.length)]);
    while (chars.length < length) chars.push(all[randomInt(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join('');
  }

  /** Quantos caracteres fazem parte de sequências (abc, 321), repetições (aaa), anos (2026) ou senhas famosas. */
  function patternChars(pw) {
    const s = pw.toLowerCase();
    const marked = new Array(s.length).fill(false);
    let start = 0;
    for (let i = 1; i <= s.length; i++) {
      const d = i < s.length ? s.charCodeAt(i) - s.charCodeAt(i - 1) : NaN;
      const prev = i >= 2 ? s.charCodeAt(i - 1) - s.charCodeAt(i - 2) : NaN;
      const continues = i < s.length && (d === 0 || d === 1 || d === -1) && (i - start < 2 || d === prev);
      if (!continues) {
        if (i - start >= 3) for (let k = start; k < i; k++) marked[k] = true;
        start = i - (i < s.length && (d === 0 || d === 1 || d === -1) ? 1 : 0);
      }
    }
    // Anos (1990, 2026) e senhas famosas (123456, senha, flamengo) também são fáceis de adivinhar.
    for (const m of s.matchAll(/(?:19|20)\d{2}/g)) for (let k = m.index; k < m.index + 4; k++) marked[k] = true;
    for (const word of COMMON) {
      for (let at = s.indexOf(word); at >= 0; at = s.indexOf(word, at + 1)) {
        for (let k = at; k < at + word.length; k++) marked[k] = true;
      }
    }
    return marked.filter(Boolean).length;
  }

  /**
   * Força da senha: nível 0 (vazia) a 4.
   * 1 = Fraca, 2 = Média, 3 = Boa, 4 = Forte.
   */
  function strength(pw) {
    if (!pw) return { level: 0, label: '', bits: 0 };
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/\d/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
    // Caracteres dentro de sequências e repetições valem pouco: são fáceis de adivinhar.
    const weak = patternChars(pw);
    const bits = Math.round((pw.length - weak) * Math.log2(Math.max(pool, 2)) + weak * 1.5);
    const level = bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    return { level, label: ['', 'Fraca', 'Média', 'Boa', 'Forte'][level], bits };
  }

  return { SETS, generate, strength, randomInt };
});
