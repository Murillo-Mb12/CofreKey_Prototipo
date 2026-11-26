/*
 * CofreKey — armazenamento local
 *
 * Tudo fica no próprio navegador (localStorage). O cofre só é gravado já
 * criptografado. Se o navegador bloquear o armazenamento (modo anônimo,
 * configuração de privacidade), o app continua funcionando na memória e
 * AVISA o usuário de que nada será salvo (RF-33).
 */
(function (root) {
  'use strict';

  const KEYS = {
    vault: 'cofrekey.vault',
    attempts: 'cofrekey.attempts',
    settings: 'cofrekey.settings',
  };

  const DEFAULT_SETTINGS = {
    idleMinutes: 2,        // bloqueio automático por inatividade
    hideLock: 'now',       // ao sair do app: 'now' | '1min' | 'never'
    clipboardSeconds: 30,  // limpa a área de transferência depois de copiar
    theme: 'auto',         // 'auto' | 'light' | 'dark'
    lastBackupAt: null,
  };

  const memory = new Map();
  let available = false;

  try {
    const probe = '__cofrekey_probe__';
    localStorage.setItem(probe, '1');
    available = localStorage.getItem(probe) === '1';
    localStorage.removeItem(probe);
  } catch (e) {
    available = false;
  }

  function get(key) {
    if (available) {
      try { return localStorage.getItem(key); } catch (e) { /* cai para a memória */ }
    }
    return memory.has(key) ? memory.get(key) : null;
  }

  /** Grava e devolve true se ficou salvo no navegador, false se só na memória. */
  function set(key, value) {
    memory.set(key, value);
    if (!available) return false;
    try {
      localStorage.setItem(key, value);
      return true;
    } catch (e) {
      return false; // cota cheia ou bloqueio
    }
  }

  function remove(key) {
    memory.delete(key);
    if (available) {
      try { localStorage.removeItem(key); } catch (e) { /* ignore */ }
    }
  }

  function readJSON(key, fallback) {
    try {
      const v = get(key);
      return v ? JSON.parse(v) : fallback;
    } catch (e) {
      return fallback;
    }
  }

  const store = {
    KEYS,
    isAvailable: () => available,

    getVault: () => get(KEYS.vault),
    setVault: (text) => set(KEYS.vault, text),
    removeVault: () => remove(KEYS.vault),

    /** Tentativas erradas ficam salvas: recarregar a página não zera o bloqueio (RF-31). */
    getAttempts: () => readJSON(KEYS.attempts, { fails: 0, until: 0 }),
    setAttempts: (a) => set(KEYS.attempts, JSON.stringify(a)),
    clearAttempts: () => remove(KEYS.attempts),

    getSettings: () => ({ ...DEFAULT_SETTINGS, ...readJSON(KEYS.settings, {}) }),
    saveSettings(partial) {
      const next = { ...store.getSettings(), ...partial };
      set(KEYS.settings, JSON.stringify(next));
      return next;
    },

    /** Pede ao navegador para não apagar os dados quando faltar espaço. */
    async requestPersistence() {
      try {
        if (navigator.storage && navigator.storage.persist) return await navigator.storage.persist();
      } catch (e) { /* ignore */ }
      return false;
    },
    async isPersisted() {
      try {
        if (navigator.storage && navigator.storage.persisted) return await navigator.storage.persisted();
      } catch (e) { /* ignore */ }
      return false;
    },
  };

  (root.CK = root.CK || {}).store = store;
})(self);
