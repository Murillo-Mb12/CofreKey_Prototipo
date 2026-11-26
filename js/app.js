/*
 * CofreKey — interface
 *
 * Telas, listas, janelas e eventos. A criptografia fica em vault.js, os códigos
 * em totp.js, o gerador em passwords.js e o armazenamento em storage.js.
 */
(function () {
  'use strict';

  const VERSION = '1.0.0';
  const { totp, vault, passwords, csv, store, qr } = window.CK;
  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  /* ================= estado ================= */

  const S = {
    screen: null,
    record: null,   // cofre salvo (sempre criptografado)
    session: null,  // chave de dados aberta: só existe com o cofre desbloqueado
    data: null,     // { logins: [], codes: [] } abertos na memória
    settings: store.getSettings(),
    recovery: null, // sessão aberta pelo código de recuperação (antes de criar a nova senha)
    pendingCode: null,
    afterCode: null,
  };
  const ui = {
    tab: 'senhas',
    openLogins: new Set(),
    openCodes: new Set(),
    revealed: new Set(),
    armedDelete: null,
    editingLogin: null,
    editingCode: null,
    codeTouched: false,
    scanParams: null,
    stopCamera: null,
  };

  const ICON = {
    chev: '<svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>',
  };

  const LOCK_REASONS = {
    idle: 'O cofre foi bloqueado por falta de uso. Digite a senha mestra para continuar.',
    hidden: 'O cofre foi bloqueado porque você saiu do app. Digite a senha mestra para continuar.',
    external: 'O cofre foi alterado em outra aba ou janela. Digite a senha mestra para ver a versão mais recente.',
    restored: 'Backup restaurado. Digite a senha mestra que você usava quando fez esse backup.',
  };

  /* ================= utilitários ================= */

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const uid = () => Array.from(crypto.getRandomValues(new Uint8Array(9)), (b) => b.toString(16).padStart(2, '0')).join('');
  const norm = (s) => String(s || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const colorClass = (s) => 'c' + (Array.from(String(s)).reduce((a, c) => a + c.codePointAt(0), 0) % 7);
  const firstChar = (s) => (Array.from(String(s).trim())[0] || '?').toUpperCase();
  const fmtDate = (iso) => new Date(iso).toLocaleDateString('pt-BR');
  const today = () => new Date().toISOString().slice(0, 10);
  const count = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const groupCode = (c) => (c.length === 6 ? c.slice(0, 3) + ' ' + c.slice(3) : c.length === 8 ? c.slice(0, 4) + ' ' + c.slice(4) : c);
  const listNames = (arr) => arr.slice(0, 3).join(', ') + (arr.length > 3 ? '…' : '');

  let toastTimer;
  function toast(text, action) {
    const t = $('toast');
    t.textContent = '';
    const span = document.createElement('span');
    span.textContent = text;
    t.append(span);
    if (action) {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = action.label;
      b.addEventListener('click', () => { t.classList.remove('show'); action.run(); });
      t.append(b);
    }
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), action ? 8000 : 2800);
  }
  const hideToast = () => $('toast').classList.remove('show');

  let clipTimer;
  async function copy(text, what) {
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.append(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
      ta.remove();
    }
    if (!ok) return toast('Não foi possível copiar neste navegador.');
    const secs = S.settings.clipboardSeconds;
    toast(`${what} copiado. Será apagado da área de transferência em ${secs} s.`);
    clearTimeout(clipTimer);
    clipTimer = setTimeout(() => {
      if (navigator.clipboard) navigator.clipboard.writeText('').catch(() => {});
    }, secs * 1000);
  }

  function download(name, text, type) {
    suppressHideLock(15000);
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  }

  function paintMeter(bar, label, pw, emptyText = '') {
    const s = passwords.strength(pw);
    bar.className = s.level ? 'lv' + s.level : '';
    bar.style.width = s.level * 25 + '%';
    if (label) label.textContent = pw ? `Força: ${s.label}` : emptyText;
    return s;
  }

  function fail(msgEl, field, text) {
    if (field) {
      field.setAttribute('aria-invalid', 'true');
      field.focus();
    }
    msgEl.textContent = text;
    return false;
  }
  document.addEventListener('input', (e) => {
    if (e.target.removeAttribute) e.target.removeAttribute('aria-invalid');
  });

  async function busy(btn, label, fn) {
    const old = btn.textContent;
    btn.disabled = true;
    btn.textContent = label;
    try {
      return await fn();
    } finally {
      btn.disabled = false;
      btn.textContent = old;
    }
  }

  /** Mostrar/ocultar senha nos campos de senha mestra. */
  $$('[data-eye]').forEach((b) => {
    b.setAttribute('aria-controls', b.dataset.eye);
    b.setAttribute('aria-pressed', 'false');
    b.addEventListener('click', () => {
      const input = $(b.dataset.eye);
      const reveal = input.type === 'password';
      input.type = reveal ? 'text' : 'password';
      b.textContent = reveal ? 'Ocultar' : 'Mostrar';
      b.setAttribute('aria-pressed', String(reveal));
      input.focus();
    });
  });
  function resetEyes() {
    $$('[data-eye]').forEach((b) => {
      $(b.dataset.eye).type = 'password';
      b.textContent = 'Mostrar';
      b.setAttribute('aria-pressed', 'false');
    });
  }

  function checkNewMaster(a, b, fields) {
    if (a.length < 10) return { field: fields[0], text: `A senha mestra tem ${a.length} caracteres. Use pelo menos 10.` };
    if (passwords.strength(a).level < 3) return { field: fields[0], text: 'Senha mestra fraca. Use uma frase longa ou misture letras, números e símbolos.' };
    if (a !== b) return { field: fields[1], text: 'As duas senhas não são iguais. Toque em Mostrar para conferir.' };
    return null;
  }

  /* ================= telas ================= */

  const SCREENS = ['setup', 'code', 'lock', 'recover', 'main'];
  function show(name, focusId) {
    SCREENS.forEach((s) => $('scr-' + s).classList.toggle('hidden', s !== name));
    S.screen = name;
    if (focusId) setTimeout(() => { const el = $(focusId); if (el) el.focus(); }, 30);
  }

  function applyTheme() {
    const t = S.settings.theme;
    if (t === 'auto') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = t;
  }

  function storageWarning(on) {
    $('bnStorage').classList.toggle('hidden', !on);
  }

  /** Lê o cofre salvo: registro válido, 'damaged' (arquivo estragado) ou null (não existe). */
  function loadRecord() {
    const text = store.getVault();
    if (!text) return null;
    try {
      return vault.parse(text);
    } catch (e) {
      return 'damaged';
    }
  }

  function writeRecord(rec) {
    S.record = rec;
    const saved = store.setVault(vault.serialize(rec));
    storageWarning(!saved);
    return saved;
  }

  /* ---------- janelas ---------- */

  const sheetStack = [];
  function openSheet(id, focusId) {
    const el = $(id);
    el.classList.add('show');
    sheetStack.push({ id, back: document.activeElement });
    setTimeout(() => {
      const target = focusId ? $(focusId) : el.querySelector('input:not([type=hidden]), select, button');
      if (target && !target.closest('.hidden')) target.focus();
    }, 40);
  }
  let confirmResolve = null;
  function closeSheet(id) {
    const el = $(id);
    if (!el.classList.contains('show')) return;
    el.classList.remove('show');
    if (id === 'codeSheet') stopCamera();
    if (id === 'confirmSheet' && confirmResolve) {
      const r = confirmResolve;
      confirmResolve = null;
      r(false);
    }
    const i = sheetStack.map((s) => s.id).lastIndexOf(id);
    if (i >= 0) {
      const [entry] = sheetStack.splice(i, 1);
      if (entry.back && document.contains(entry.back)) entry.back.focus();
    }
  }
  function closeAllSheets() {
    [...sheetStack].reverse().forEach((s) => closeSheet(s.id));
    $$('.scrim.show').forEach((s) => s.classList.remove('show'));
    sheetStack.length = 0;
  }
  $$('.scrim').forEach((s) => s.addEventListener('click', (e) => {
    if (e.target === s || e.target.closest('[data-close]')) closeSheet(s.id);
  }));

  function confirmDialog({ title, text, ok = 'Confirmar', danger = false }) {
    $('cfTitle').textContent = title;
    $('cfText').textContent = text;
    $('cfOk').textContent = ok;
    $('cfOk').className = danger ? 'btn danger-fill' : 'btn';
    openSheet('confirmSheet', 'cfCancel');
    return new Promise((resolve) => { confirmResolve = resolve; });
  }
  $('cfOk').addEventListener('click', () => {
    const r = confirmResolve;
    confirmResolve = null;
    closeSheet('confirmSheet');
    if (r) r(true);
  });
  $('cfCancel').addEventListener('click', () => closeSheet('confirmSheet'));

  function openHelp(section) {
    $$('#helpSheet details').forEach((d) => { d.open = !!section && d.id === section; });
    openSheet('helpSheet');
    if (section && $(section)) setTimeout(() => $(section).scrollIntoView({ block: 'nearest' }), 60);
  }
  document.addEventListener('click', (e) => {
    const h = e.target.closest('[data-help]');
    if (h) openHelp(h.dataset.help);
  });

  /* ================= tentativas erradas (RF-31) ================= */

  let throttleTimer;
  const waitSeconds = () => Math.max(0, Math.ceil((store.getAttempts().until - Date.now()) / 1000));

  function registerFail() {
    const a = store.getAttempts();
    a.fails = (a.fails || 0) + 1;
    if (a.fails >= 5) a.until = Date.now() + Math.min(30 * 2 ** (a.fails - 5), 900) * 1000;
    store.setAttempts(a);
    return a;
  }

  function refreshThrottle() {
    clearInterval(throttleTimer);
    let wasBlocked = false;
    const tick = () => {
      const w = waitSeconds();
      $('unlockBtn').disabled = w > 0;
      $('recVerify').disabled = w > 0;
      const msg = S.screen === 'recover' ? $('recMsg1') : $('lockMsg');
      if (w > 0) {
        wasBlocked = true;
        msg.textContent = `Muitas tentativas erradas. Tente de novo em ${w} s.`;
      } else {
        clearInterval(throttleTimer);
        if (wasBlocked) msg.textContent = 'Você já pode tentar de novo.';
      }
    };
    tick();
    if (waitSeconds() > 0) throttleTimer = setInterval(tick, 1000);
  }

  /* ================= criar cofre ================= */

  $('m1').addEventListener('input', () => paintMeter($('m1Meter'), $('m1Label'), $('m1').value, 'Use uma frase longa ou misture letras, números e símbolos.'));

  $('createBtn').addEventListener('click', async () => {
    const a = $('m1').value, b = $('m2').value, msg = $('setupMsg');
    const err = checkNewMaster(a, b, ['m1', 'm2']);
    if (err) return fail(msg, $(err.field), err.text);
    msg.textContent = '';
    await busy($('createBtn'), 'Criando cofre…', async () => {
      const empty = { logins: [], codes: [] };
      const { record, session, recoveryCode } = await vault.create(a, empty);
      writeRecord(record);
      store.clearAttempts();
      $('m1').value = '';
      $('m2').value = '';
      paintMeter($('m1Meter'), $('m1Label'), '', 'Use uma frase longa ou misture letras, números e símbolos.');
      resetEyes();
      S.session = session;
      S.data = empty;
      store.requestPersistence();
      showRecoveryCode(recoveryCode, () => enter(S.record, S.session, S.data));
    });
  });

  /* ---------- tela do código de recuperação ---------- */

  function showRecoveryCode(code, after) {
    S.pendingCode = code;
    S.afterCode = after;
    $('rcCode').textContent = code;
    $('rcCheck').checked = false;
    $('rcContinue').disabled = true;
    show('code', 'rcCopy');
  }
  $('rcCheck').addEventListener('change', () => { $('rcContinue').disabled = !$('rcCheck').checked; });
  $('rcCopy').addEventListener('click', () => copy(S.pendingCode, 'Código de recuperação'));
  $('rcDownload').addEventListener('click', () => {
    download('cofrekey-codigo-de-recuperacao.txt',
      'CofreKey: código de recuperação\r\n\r\n' + S.pendingCode + '\r\n\r\n' +
      'Criado em ' + new Date().toLocaleString('pt-BR') + '.\r\n' +
      'Este código abre o cofre se você esquecer a senha mestra.\r\n' +
      'Guarde fora do celular (ou imprima) e não mostre a ninguém.\r\n', 'text/plain');
  });
  $('rcContinue').addEventListener('click', () => {
    const after = S.afterCode;
    S.pendingCode = null;
    S.afterCode = null;
    $('rcCode').textContent = '';
    if (after) after();
  });

  /* ================= bloquear / desbloquear ================= */

  function goLock(reason, damaged = false) {
    const r = loadRecord();
    if (!r) return show('setup', 'm1');
    const isDamaged = damaged || r === 'damaged';
    S.record = r === 'damaged' ? null : r;
    $('lockDamaged').classList.toggle('hidden', !isDamaged);
    $('lockField').classList.toggle('hidden', isDamaged);
    $('unlockBtn').classList.toggle('hidden', isDamaged);
    $('forgotBtn').classList.toggle('hidden', isDamaged);
    $('lockLead').textContent = LOCK_REASONS[reason] || 'Digite sua senha mestra para ver suas senhas e códigos.';
    $('lockMsg').textContent = '';
    show('lock', isDamaged ? 'damagedRestore' : 'unlockPw');
    refreshThrottle();
  }

  async function tryUnlock() {
    const input = $('unlockPw'), msg = $('lockMsg');
    if (waitSeconds() > 0) return refreshThrottle();
    if (!input.value) return fail(msg, input, 'Digite a senha mestra.');
    msg.textContent = '';
    await busy($('unlockBtn'), 'Abrindo…', async () => {
      const rec = loadRecord();
      if (!rec || rec === 'damaged') return goLock(null, true);
      try {
        const { session, data } = await vault.unlock(rec, input.value);
        store.clearAttempts();
        input.value = '';
        resetEyes();
        enter(rec, session, data);
      } catch (e) {
        if (e.code === 'CORRUPTED') {
          store.clearAttempts();
          input.value = '';
          return goLock(null, true);
        }
        const a = registerFail();
        input.setAttribute('aria-invalid', 'true');
        if (a.until > Date.now()) refreshThrottle();
        else msg.textContent = `Senha mestra incorreta. Toque em Mostrar para conferir o que digitou (maiúsculas contam). Tentativa ${a.fails} de 5.`;
      }
    });
    if (waitSeconds() > 0) refreshThrottle();
  }
  $('unlockBtn').addEventListener('click', tryUnlock);
  $('unlockPw').addEventListener('keydown', (e) => { if (e.key === 'Enter') tryUnlock(); });

  function normalizeData(d) {
    const o = d && typeof d === 'object' ? d : {};
    return { logins: Array.isArray(o.logins) ? o.logins : [], codes: Array.isArray(o.codes) ? o.codes : [] };
  }

  function enter(record, session, data) {
    S.record = record;
    S.session = session;
    S.data = normalizeData(data);
    ui.openLogins.clear();
    ui.openCodes.clear();
    ui.revealed.clear();
    ui.armedDelete = null;
    $('search').value = '';
    show('main');
    selectTab('senhas');
    renderAll();
    bumpIdle();
  }

  function wipeSession() {
    stopCamera();
    closeAllSheets();
    hideToast();
    clearIdle();
    ['fSite', 'fUser', 'fPass', 'fUrl', 'fNote', 'cIssuer', 'cAccount', 'cSecret', 'p0', 'p1', 'p2', 'r1', 'r2', 'recCode', 'unlockPw', 'search'].forEach((id) => { $(id).value = ''; });
    resetEyes();
    S.session = null;
    S.data = null;
    S.recovery = null;
    totp.clearCache();
    codeCache.clear();
    $('loginList').textContent = '';
    $('codeList').textContent = '';
    $('genOut').textContent = '';
  }

  function lock(reason = 'manual') {
    wipeSession();
    goLock(reason);
    if (reason === 'manual') toast('Cofre bloqueado.');
  }
  $('lockBtn').addEventListener('click', () => lock('manual'));

  /* ---------- bloqueio por falta de uso, com aviso antes ---------- */

  let idleWarnTimer, idleLockTimer, idleCountdown;
  function clearIdle() {
    clearTimeout(idleWarnTimer);
    clearTimeout(idleLockTimer);
    clearInterval(idleCountdown);
    $('bnIdle').classList.add('hidden');
  }
  function bumpIdle() {
    if (!S.session || S.screen !== 'main') return;
    clearIdle();
    const ms = S.settings.idleMinutes * 60000;
    idleWarnTimer = setTimeout(showIdleWarning, Math.max(0, ms - 15000));
    idleLockTimer = setTimeout(() => lock('idle'), ms);
  }
  function showIdleWarning() {
    const end = Date.now() + 15000;
    $('bnIdle').classList.remove('hidden');
    const tick = () => {
      const s = Math.max(0, Math.ceil((end - Date.now()) / 1000));
      $('bnIdleText').textContent = `O cofre será bloqueado em ${s} s por falta de uso.`;
    };
    tick();
    idleCountdown = setInterval(tick, 1000);
  }
  ['pointerdown', 'keydown', 'wheel', 'touchstart', 'input'].forEach((ev) =>
    document.addEventListener(ev, bumpIdle, { passive: true, capture: true }));
  $('bnIdleStay').addEventListener('click', () => { bumpIdle(); toast('Tudo certo, o cofre continua aberto.'); });

  /* ---------- bloqueio ao sair do app (RF-32) ---------- */

  let hiddenAt = 0, hideTimer, suppressHideUntil = 0;
  function suppressHideLock(ms) { suppressHideUntil = Date.now() + ms; }
  document.addEventListener('visibilitychange', () => {
    if (!S.session || S.screen !== 'main') return;
    const mode = S.settings.hideLock;
    if (document.visibilityState === 'hidden') {
      if (mode === 'never' || Date.now() < suppressHideUntil) return;
      if (mode === 'now') return lock('hidden');
      hiddenAt = Date.now();
      clearTimeout(hideTimer);
      hideTimer = setTimeout(() => lock('hidden'), 60000);
    } else {
      clearTimeout(hideTimer);
      if (mode === '1min' && hiddenAt && Date.now() - hiddenAt >= 60000) lock('hidden');
      hiddenAt = 0;
    }
  });

  /** Abre o seletor de arquivo sem que o cofre bloqueie enquanto ele está aberto. */
  function pickFile(input) {
    suppressHideLock(5 * 60000);
    input.value = '';
    input.click();
  }
  window.addEventListener('focus', () => setTimeout(() => { suppressHideUntil = Math.min(suppressHideUntil, Date.now() + 3000); }, 500));

  /* ---------- salvar com proteção entre abas (RF-34) ---------- */

  let saveChain = Promise.resolve(true);
  function persistWith(makeRecord) {
    const run = async () => {
      if (!S.session) return false;
      try {
        const stored = loadRecord();
        if (stored && stored !== 'damaged' && S.record && stored.rev !== S.record.rev) {
          lock('external');
          return false;
        }
        writeRecord(await makeRecord());
        return true;
      } catch (e) {
        console.error(e);
        toast('Não foi possível salvar. Tente de novo.');
        return false;
      }
    };
    saveChain = saveChain.then(run, run);
    return saveChain;
  }
  const save = () => persistWith(() => vault.save(S.session, S.record, S.data));

  window.addEventListener('storage', (e) => {
    if (e.key === store.KEYS.settings) {
      S.settings = store.getSettings();
      applyTheme();
      if (S.session) renderSettings();
      return;
    }
    if (e.key !== store.KEYS.vault && e.key !== null) return;
    if (S.session && S.screen === 'main') {
      let r = null;
      try { r = e.newValue ? vault.parse(e.newValue) : null; } catch (_) { r = null; }
      if (!r || !S.record || r.rev !== S.record.rev) lock('external');
    } else if (S.screen === 'lock' || S.screen === 'setup') {
      if (store.getVault()) goLock();
      else show('setup', 'm1');
    }
  });

  /* ================= recuperar acesso ================= */

  $('forgotBtn').addEventListener('click', () => {
    S.recovery = null;
    $('recStep1').classList.remove('hidden');
    $('recStep2').classList.add('hidden');
    $('recCode').value = '';
    $('recMsg1').textContent = '';
    $('recMsg2').textContent = '';
    show('recover', 'recCode');
    refreshThrottle();
  });
  $('recBack').addEventListener('click', () => {
    S.recovery = null;
    ['recCode', 'r1', 'r2'].forEach((id) => { $(id).value = ''; });
    goLock();
  });

  async function verifyRecovery() {
    const input = $('recCode'), msg = $('recMsg1');
    if (waitSeconds() > 0) return refreshThrottle();
    if (vault.normalizeRecoveryCode(input.value).length < 26) {
      return fail(msg, input, 'O código tem 26 letras e números. Confira se digitou todos.');
    }
    const rec = loadRecord();
    if (!rec || rec === 'damaged') return goLock(null, true);
    msg.textContent = '';
    await busy($('recVerify'), 'Verificando…', async () => {
      try {
        const { session, data } = await vault.unlockWithRecovery(rec, input.value);
        store.clearAttempts();
        S.recovery = { session, data, record: rec };
        input.value = '';
        $('recStep1').classList.add('hidden');
        $('recStep2').classList.remove('hidden');
        paintMeter($('r1Meter'), $('r1Label'), '');
        setTimeout(() => $('r1').focus(), 30);
      } catch (e) {
        if (e.code === 'CORRUPTED') return goLock(null, true);
        const a = registerFail();
        input.setAttribute('aria-invalid', 'true');
        if (a.until > Date.now()) refreshThrottle();
        else msg.textContent = `Código de recuperação incorreto. Tentativa ${a.fails} de 5.`;
      }
    });
    if (waitSeconds() > 0) refreshThrottle();
  }
  $('recVerify').addEventListener('click', verifyRecovery);
  $('recCode').addEventListener('keydown', (e) => { if (e.key === 'Enter') verifyRecovery(); });
  $('r1').addEventListener('input', () => paintMeter($('r1Meter'), $('r1Label'), $('r1').value));

  $('recSave').addEventListener('click', async () => {
    const a = $('r1').value, b = $('r2').value, msg = $('recMsg2');
    const err = checkNewMaster(a, b, ['r1', 'r2']);
    if (err) return fail(msg, $(err.field), err.text);
    const R = S.recovery;
    if (!R) return goLock();
    await busy($('recSave'), 'Salvando…', async () => {
      let rec = await vault.changePassword(R.session, R.record, a);
      const fresh = await vault.newRecovery(R.session, rec); // o código usado deixa de valer
      rec = fresh.record;
      writeRecord(rec);
      $('r1').value = '';
      $('r2').value = '';
      resetEyes();
      S.recovery = null;
      S.session = R.session;
      S.data = normalizeData(R.data);
      showRecoveryCode(fresh.recoveryCode, () => {
        enter(S.record, S.session, S.data);
        toast('Nova senha mestra salva.');
      });
    });
  });

  async function eraseVault() {
    const ok = await confirmDialog({
      title: 'Apagar o cofre?',
      text: 'Todas as senhas e códigos deste aparelho serão apagados. Sem um backup, não há como recuperar.',
      ok: 'Apagar tudo',
      danger: true,
    });
    if (!ok) return;
    wipeSession();
    store.removeVault();
    store.clearAttempts();
    S.record = null;
    show('setup', 'm1');
    toast('Cofre apagado deste aparelho.');
  }
  $('recErase').addEventListener('click', eraseVault);
  $('damagedErase').addEventListener('click', eraseVault);
  $('setErase').addEventListener('click', eraseVault);

  /* ================= abas ================= */

  const TABS = ['senhas', 'codigos', 'gerador', 'ajustes'];
  function selectTab(name) {
    TABS.forEach((t) => {
      const tab = $('tab-' + t);
      tab.setAttribute('aria-selected', String(t === name));
      tab.tabIndex = t === name ? 0 : -1;
      $('v-' + t).classList.toggle('hidden', t !== name);
    });
    ui.tab = name;
    $('views').scrollTop = 0;
    if (name === 'gerador' && !$('genOut').textContent) newPassword();
    if (name === 'ajustes') renderSettings();
  }
  $$('nav.tabs [role=tab]').forEach((b) => b.addEventListener('click', () => selectTab(b.dataset.tab)));
  document.querySelector('nav.tabs').addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const i = (TABS.indexOf(ui.tab) + (e.key === 'ArrowRight' ? 1 : -1) + TABS.length) % TABS.length;
    selectTab(TABS[i]);
    $('tab-' + TABS[i]).focus();
  });

  function renderAll() {
    if (!S.data) return;
    renderLogins();
    renderCodes();
    renderBackupBanner();
    if (ui.tab === 'ajustes') renderSettings();
  }

  function toggle(set, id) {
    if (set.has(id)) set.delete(id);
    else set.add(id);
  }
  function refocus(listId, id, act) {
    const el = document.querySelector(`#${listId} [data-id="${id}"] [data-act="${act}"]`);
    if (el) el.focus();
  }
  const deleteButton = (id) =>
    `<button class="btn danger sm" type="button" data-act="del">${ui.armedDelete === id ? 'Confirmar exclusão' : 'Excluir'}</button>`;
  const ringHTML = (id) =>
    `<div class="ring" data-ring="${id}" aria-hidden="true"><svg viewBox="0 0 40 40"><circle class="track" cx="20" cy="20" r="16"/><circle class="arc" cx="20" cy="20" r="16"/></svg><span></span></div>`;

  /* ================= senhas ================= */

  const findCode = (id) => (id ? S.data.codes.find((c) => c.id === id) : null);

  function reuseMap() {
    const m = new Map();
    for (const l of S.data.logins) {
      if (!l.pass) continue;
      if (!m.has(l.pass)) m.set(l.pass, []);
      m.get(l.pass).push(l);
    }
    return m;
  }

  function loginHTML(l, reuse) {
    const s = passwords.strength(l.pass);
    const open = ui.openLogins.has(l.id);
    const rev = ui.revealed.has(l.id);
    const others = (reuse.get(l.pass) || []).filter((x) => x.id !== l.id).map((x) => x.site);
    const code = findCode(l.codeId);
    const safeUrl = /^https?:\/\//i.test(l.url || '') ? l.url : '';
    return `<div class="item${open ? ' open' : ''}" data-id="${l.id}">
      <button class="item-head" type="button" data-act="toggle" aria-expanded="${open}">
        <span class="avatar ${colorClass(l.site)}" aria-hidden="true">${esc(firstChar(l.site))}</span>
        <span class="grow"><span class="item-title">${esc(l.site)}${l.fav ? '<span class="star" aria-label="favorito">★</span>' : ''}</span><span class="item-sub">${esc(l.user || 'sem usuário')}</span></span>
        <span class="dot lv${s.level}" title="Senha ${s.label.toLowerCase()}"></span>
        ${ICON.chev}
      </button>
      <div class="item-body">
        <output class="secret">${rev ? esc(l.pass) : '•'.repeat(Math.min(l.pass.length, 16))}</output>
        <div class="chips"><span class="chip lv${s.level}">Senha ${s.label.toLowerCase()}</span>${others.length ? `<span class="chip reuse">Repetida em ${esc(listNames(others))}</span>` : ''}</div>
        ${code ? `<div class="inline-code">${ringHTML(code.id)}<div class="grow"><div class="label">Código de verificação (${esc(code.issuer)})</div><button class="code-btn small" type="button" data-act="copyCode" data-code-id="${code.id}" data-live="${code.id}">··· ···</button></div></div>` : ''}
        ${safeUrl ? `<div class="kv">Endereço: <a href="${esc(safeUrl)}" target="_blank" rel="noopener noreferrer">${esc(safeUrl)}</a></div>` : l.url ? `<div class="kv">Endereço: <b>${esc(l.url)}</b></div>` : ''}
        ${l.note ? `<div class="kv">Observações: <b>${esc(l.note)}</b></div>` : ''}
        <div class="actions">
          <button class="btn quiet sm" type="button" data-act="reveal" aria-pressed="${rev}">${rev ? 'Ocultar' : 'Mostrar'}</button>
          <button class="btn sm" type="button" data-act="copyPass">Copiar senha</button>
          ${l.user ? '<button class="btn quiet sm" type="button" data-act="copyUser">Copiar usuário</button>' : ''}
          <button class="btn quiet sm" type="button" data-act="fav">${l.fav ? 'Tirar dos favoritos' : 'Favoritar'}</button>
          <button class="btn quiet sm" type="button" data-act="edit">Editar</button>
          ${deleteButton(l.id)}
        </div>
      </div>
    </div>`;
  }

  function renderLogins() {
    const list = $('loginList');
    const all = S.data.logins;
    const q = norm($('search').value);
    if (!all.length) {
      list.innerHTML = `<div class="empty"><strong>Nenhuma senha guardada</strong>Adicione a primeira conta ou traga as senhas do navegador em Ajustes.<br><button class="btn sm" type="button" data-act="new">Adicionar senha</button></div>`;
      return;
    }
    const items = all
      .filter((l) => !q || norm(l.site).includes(q) || norm(l.user).includes(q))
      .sort((a, b) => (b.fav ? 1 : 0) - (a.fav ? 1 : 0) || a.site.localeCompare(b.site, 'pt-BR', { sensitivity: 'base' }));
    if (!items.length) {
      list.innerHTML = `<div class="empty"><strong>Nada encontrado</strong>Nenhuma conta tem “${esc($('search').value.trim())}” no nome ou no usuário.</div>`;
      return;
    }
    const reuse = reuseMap();
    list.innerHTML = items.map((l) => loginHTML(l, reuse)).join('');
    tickCodes();
  }
  $('search').addEventListener('input', renderLogins);
  $('search').addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && $('search').value) { $('search').value = ''; renderLogins(); }
  });

  $('loginList').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;
    if (act === 'new') return openLoginSheet();
    if (act === 'copyCode') return copyCode(btn.dataset.codeId);
    const id = btn.closest('.item').dataset.id;
    const l = S.data.logins.find((x) => x.id === id);
    if (!l) return;
    switch (act) {
      case 'toggle': toggle(ui.openLogins, id); ui.revealed.delete(id); ui.armedDelete = null; break;
      case 'reveal': toggle(ui.revealed, id); break;
      case 'copyPass': return copy(l.pass, 'Senha');
      case 'copyUser': return copy(l.user, 'Usuário');
      case 'fav':
        l.fav = !l.fav;
        if (!(await save())) return;
        toast(l.fav ? `“${l.site}” está nos favoritos.` : `“${l.site}” saiu dos favoritos.`);
        break;
      case 'edit': return openLoginSheet(l);
      case 'del':
        if (ui.armedDelete !== id) { ui.armedDelete = id; break; }
        return deleteItem('logins', l);
      default: return;
    }
    renderLogins();
    refocus('loginList', id, act);
  });

  /** Exclusão igual nas duas listas: confirmar com um segundo toque e poder desfazer. */
  async function deleteItem(kind, obj) {
    const arr = S.data[kind];
    const idx = arr.indexOf(obj);
    if (idx < 0) return;
    arr.splice(idx, 1);
    ui.armedDelete = null;
    const unlinked = kind === 'codes' ? S.data.logins.filter((l) => l.codeId === obj.id) : [];
    unlinked.forEach((l) => { l.codeId = null; });
    if (!(await save())) return;
    renderAll();
    const what = kind === 'logins' ? `Senha de “${obj.site}” excluída.` : `Código de “${obj.issuer}” excluído.`;
    const back = kind === 'logins' ? `Senha de “${obj.site}” restaurada.` : `Código de “${obj.issuer}” restaurado.`;
    toast(what, {
      label: 'Desfazer',
      run: async () => {
        if (!S.session) return;
        S.data[kind].splice(Math.min(idx, S.data[kind].length), 0, obj);
        unlinked.forEach((l) => { l.codeId = obj.id; });
        if (await save()) { renderAll(); toast(back); }
      },
    });
  }

  /* ---------- janela de senha ---------- */

  function fillCodeSelect(selected) {
    const sel = $('fCode');
    sel.textContent = '';
    sel.append(new Option('Nenhum', ''));
    [...S.data.codes]
      .sort((a, b) => a.issuer.localeCompare(b.issuer, 'pt-BR', { sensitivity: 'base' }))
      .forEach((c) => sel.append(new Option(c.account ? `${c.issuer} (${c.account})` : c.issuer, c.id)));
    sel.value = selected && findCode(selected) ? selected : '';
  }

  function openLoginSheet(l = null, prefill = '') {
    ui.editingLogin = l ? l.id : null;
    ui.codeTouched = !!l;
    $('loginTitle').textContent = l ? 'Editar senha' : 'Adicionar senha';
    $('saveLogin').textContent = l ? 'Salvar alterações' : 'Salvar senha';
    $('fSite').value = l ? l.site : '';
    $('fUser').value = l ? l.user || '' : '';
    $('fPass').value = l ? l.pass : prefill;
    $('fUrl').value = l ? l.url || '' : '';
    $('fNote').value = l ? l.note || '' : '';
    fillCodeSelect(l && l.codeId);
    $('loginMsg').textContent = '';
    updateLoginWarning();
    openSheet('loginSheet', 'fSite');
  }

  /** Avisa ANTES de salvar quando a senha é fraca ou já é usada em outra conta. */
  function updateLoginWarning() {
    const pw = $('fPass').value;
    const s = paintMeter($('fMeter'), $('fLabel'), pw);
    const others = pw ? S.data.logins.filter((x) => x.pass === pw && x.id !== ui.editingLogin).map((x) => x.site) : [];
    let text = '';
    if (others.length) text = `Você já usa essa senha em ${listNames(others)}. Se um desses sites vazar, as duas contas ficam expostas.`;
    else if (pw && s.level <= 2) text = 'Essa senha é fácil de adivinhar.';
    $('fWarnText').textContent = text;
    $('fWarn').classList.toggle('hidden', !text);
  }
  function generateIntoForm() {
    $('fPass').value = passwords.generate({ length: 16 });
    updateLoginWarning();
    $('fPass').focus();
  }
  $('fPass').addEventListener('input', updateLoginWarning);
  $('fGen').addEventListener('click', generateIntoForm);
  $('fWarnGen').addEventListener('click', generateIntoForm);
  $('fCode').addEventListener('change', () => { ui.codeTouched = true; });
  $('fSite').addEventListener('input', () => {
    if (ui.codeTouched) return;
    const n = norm($('fSite').value);
    const match = n && S.data.codes.find((c) => norm(c.issuer) === n);
    $('fCode').value = match ? match.id : '';
  });
  $('addLogin').addEventListener('click', () => openLoginSheet());

  $('saveLogin').addEventListener('click', async () => {
    const msg = $('loginMsg');
    const site = $('fSite').value.trim(), pass = $('fPass').value;
    if (!site) return fail(msg, $('fSite'), 'Informe o nome do site ou aplicativo.');
    if (!pass) return fail(msg, $('fPass'), 'Digite a senha ou toque em Gerar.');
    const fields = {
      site, pass,
      user: $('fUser').value.trim(),
      url: $('fUrl').value.trim(),
      note: $('fNote').value.trim(),
      codeId: $('fCode').value || null,
      updated: Date.now(),
    };
    const editing = ui.editingLogin;
    if (editing) Object.assign(S.data.logins.find((x) => x.id === editing), fields);
    else {
      const item = { id: uid(), fav: false, created: Date.now(), ...fields };
      S.data.logins.push(item);
      ui.openLogins.add(item.id);
    }
    if (!(await busy($('saveLogin'), 'Salvando…', save))) return;
    closeSheet('loginSheet');
    $('search').value = '';
    selectTab('senhas');
    renderAll();
    toast(editing ? 'Alterações salvas.' : 'Senha salva.');
  });

  /* ================= códigos ================= */

  const codeCache = new Map(); // id → { counter, code }
  async function currentCode(c, now) {
    const counter = totp.counterAt(c, now);
    const hit = codeCache.get(c.id);
    if (hit && hit.counter === counter) return hit.code;
    const code = await totp.generate(c, now);
    codeCache.set(c.id, { counter, code });
    return code;
  }
  async function copyCode(id) {
    const c = findCode(id);
    if (!c) return;
    copy(await currentCode(c, Date.now()), 'Código');
  }

  let ticking = false;
  async function tickCodes() {
    if (!S.session || ticking) return;
    ticking = true;
    try {
      const now = Date.now();
      const ids = new Set($$('[data-live], [data-ring]').map((el) => el.dataset.live || el.dataset.ring));
      for (const id of ids) {
        const c = findCode(id);
        if (!c) continue;
        const left = totp.secondsLeft(c, now);
        const ending = left <= 5;
        let code = null;
        try { code = await currentCode(c, now); } catch (e) { code = null; }
        $$(`[data-live="${id}"]`).forEach((el) => {
          el.textContent = code ? groupCode(code) : 'Erro';
          el.classList.toggle('ending', ending);
        });
        $$(`[data-ring="${id}"]`).forEach((el) => {
          el.classList.toggle('ending', ending);
          el.querySelector('.arc').style.strokeDashoffset = (100.53 * (1 - left / (c.period || 30))).toFixed(2);
          el.querySelector('span').textContent = Math.ceil(left);
        });
      }
    } finally {
      ticking = false;
    }
  }
  setInterval(tickCodes, 500);

  function codeHTML(c) {
    const open = ui.openCodes.has(c.id);
    const linked = S.data.logins.filter((l) => l.codeId === c.id).map((l) => l.site);
    return `<div class="item${open ? ' open' : ''}" data-id="${c.id}">
      <div class="item-head code-head">
        ${ringHTML(c.id)}
        <div class="grow">
          <span class="item-title">${esc(c.issuer)}</span>
          <button class="code-btn" type="button" data-act="copy" data-live="${c.id}" aria-label="Copiar código de ${esc(c.issuer)}">··· ···</button>
          <span class="item-sub">${esc(c.account || '')}</span>
        </div>
        <button class="icon-btn" type="button" data-act="toggle" aria-expanded="${open}" aria-label="Opções de ${esc(c.issuer)}">${ICON.chev}</button>
      </div>
      <div class="item-body">
        ${linked.length ? `<div class="kv gap-top">Ligado à senha de <b>${esc(listNames(linked))}</b>.</div>` : ''}
        <div class="actions gap-top">
          <button class="btn sm" type="button" data-act="copy">Copiar código</button>
          <button class="btn quiet sm" type="button" data-act="qr">Levar para outro app</button>
          <button class="btn quiet sm" type="button" data-act="edit">Editar</button>
          ${deleteButton(c.id)}
        </div>
      </div>
    </div>`;
  }

  function renderCodes() {
    const list = $('codeList');
    const all = S.data.codes;
    if (!all.length) {
      list.innerHTML = `<div class="empty"><strong>Nenhum código ainda</strong>Ative a verificação em duas etapas em um site e escaneie o QR code que ele mostrar.<br><button class="btn sm" type="button" data-act="new">Adicionar código</button></div>`;
      return;
    }
    list.innerHTML = [...all]
      .sort((a, b) => a.issuer.localeCompare(b.issuer, 'pt-BR', { sensitivity: 'base' }))
      .map(codeHTML)
      .join('');
    tickCodes();
  }

  $('codeList').addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    const act = btn.dataset.act;
    if (act === 'new') return openCodeSheet();
    const id = btn.closest('.item').dataset.id;
    const c = findCode(id);
    if (!c) return;
    switch (act) {
      case 'copy': return copyCode(id);
      case 'toggle': toggle(ui.openCodes, id); ui.armedDelete = null; break;
      case 'qr': return showQr(c);
      case 'edit': return openCodeSheet(c);
      case 'del':
        if (ui.armedDelete !== id) { ui.armedDelete = id; break; }
        return deleteItem('codes', c);
      default: return;
    }
    renderCodes();
    refocus('codeList', id, act);
  });

  function showQr(c) {
    $('qrHint').textContent = `Escaneie no outro aplicativo (por exemplo, o Google Authenticator). Os dois vão mostrar o mesmo código de “${c.issuer}”. Não mostre este QR code a ninguém.`;
    qr.render($('qrBox'), totp.buildUri(c));
    $('qrSecret').textContent = totp.groupSecret(c.secret);
    openSheet('qrSheet');
  }

  /* ---------- janela de código ---------- */

  function openCodeSheet(c = null) {
    ui.editingCode = c ? c.id : null;
    ui.scanParams = null;
    $('codeTitle').textContent = c ? 'Editar código' : 'Adicionar código';
    $('saveCode').textContent = c ? 'Salvar alterações' : 'Salvar código';
    $('scanArea').classList.toggle('hidden', !!c);
    $('cSecretField').classList.toggle('hidden', !!c);
    $('demoCode').classList.toggle('hidden', !!c);
    $('cIssuer').value = c ? c.issuer : '';
    $('cAccount').value = c ? c.account || '' : '';
    $('cSecret').value = '';
    $('codeMsg').textContent = '';
    $('camBox').classList.add('hidden');
    openSheet('codeSheet', c ? 'cIssuer' : 'scanCam');
  }
  $('addCode').addEventListener('click', () => openCodeSheet());

  const SCAN_ERRORS = {
    UNSUPPORTED_HOTP: 'Esse QR code usa um código por contador (HOTP), que o CofreKey ainda não aceita.',
    UNSUPPORTED_PARAMS: 'Esse QR code usa uma configuração de código que o CofreKey não aceita.',
    INVALID_SECRET: 'A chave secreta desse QR code é inválida.',
  };

  function handleScan(text) {
    stopCamera();
    const msg = $('codeMsg');
    msg.textContent = '';
    if (/^otpauth-migration:/i.test(text)) return importMigration(text);
    try {
      const acc = totp.parseUri(text);
      $('cIssuer').value = acc.issuer;
      $('cAccount').value = acc.account;
      $('cSecret').value = totp.groupSecret(acc.secret);
      ui.scanParams = { digits: acc.digits, period: acc.period, algo: acc.algo, secret: acc.secret };
      toast('QR code lido. Confira o nome e toque em Salvar código.');
      $('saveCode').focus();
    } catch (e) {
      msg.textContent = SCAN_ERRORS[e.message] || 'Esse QR code não é de verificação em duas etapas.';
    }
  }

  async function importMigration(text) {
    const msg = $('codeMsg');
    let res;
    try {
      res = totp.parseMigration(text);
    } catch (e) {
      msg.textContent = 'Não foi possível ler esse QR code de exportação.';
      return;
    }
    const fresh = res.accounts.filter((a) => !S.data.codes.some((c) => c.secret === a.secret));
    if (!fresh.length) {
      msg.textContent = res.accounts.length ? 'Esses códigos já estão no cofre.' : 'Esse QR code não tem códigos que o CofreKey aceite.';
      return;
    }
    const ok = await confirmDialog({
      title: 'Importar do Google Authenticator',
      text: `Encontramos ${count(fresh.length, 'código', 'códigos')}${res.skipped ? ` (${res.skipped} de outro tipo ficaram de fora)` : ''}. Importar para o cofre?`,
      ok: 'Importar',
    });
    if (!ok) return;
    fresh.forEach((a) => S.data.codes.push({ id: uid(), ...a, created: Date.now() }));
    if (!(await save())) return;
    closeSheet('codeSheet');
    selectTab('codigos');
    renderAll();
    toast(`${count(fresh.length, 'código importado', 'códigos importados')}.`);
  }

  function stopCamera() {
    if (ui.stopCamera) {
      ui.stopCamera();
      ui.stopCamera = null;
    }
    $('camBox').classList.add('hidden');
  }
  $('scanCam').addEventListener('click', async () => {
    const msg = $('codeMsg');
    msg.textContent = '';
    stopCamera();
    $('camBox').classList.remove('hidden');
    try {
      ui.stopCamera = await qr.startCamera($('camVideo'), handleScan);
    } catch (e) {
      $('camBox').classList.add('hidden');
      msg.textContent = e.message === 'CAMERA_DENIED'
        ? 'O navegador não deu permissão para usar a câmera. Libere nas configurações do site ou use “Ler QR de uma imagem”.'
        : 'Não encontramos uma câmera. Use “Ler QR de uma imagem” ou digite a chave secreta.';
    }
  });
  $('camStop').addEventListener('click', stopCamera);
  $('scanImg').addEventListener('click', () => pickFile($('fileQr')));
  $('fileQr').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const text = await qr.decodeFile(file);
      if (!text) {
        $('codeMsg').textContent = 'Não achamos um QR code nessa imagem. Tente um print mais nítido, só com o QR code.';
        return;
      }
      handleScan(text);
    } catch (err) {
      $('codeMsg').textContent = 'Não foi possível abrir essa imagem.';
    }
  });
  $('cSecret').addEventListener('input', () => {
    if (ui.scanParams && totp.cleanSecret($('cSecret').value) !== ui.scanParams.secret) ui.scanParams = null;
  });
  $('demoCode').addEventListener('click', () => {
    $('cIssuer').value = 'CofreKey Teste';
    $('cAccount').value = 'grupo@fatec.sp.gov.br';
    $('cSecret').value = totp.groupSecret(totp.randomSecret());
    ui.scanParams = null;
    $('codeMsg').textContent = '';
  });

  $('saveCode').addEventListener('click', async () => {
    const msg = $('codeMsg');
    const issuer = $('cIssuer').value.trim(), account = $('cAccount').value.trim();
    if (ui.editingCode) {
      if (!issuer) return fail(msg, $('cIssuer'), 'Informe o nome do serviço.');
      Object.assign(findCode(ui.editingCode), { issuer, account, updated: Date.now() });
      if (!(await save())) return;
      closeSheet('codeSheet');
      renderAll();
      return toast('Alterações salvas.');
    }
    const raw = $('cSecret').value.trim();
    if (/^otpauth/i.test(raw)) return handleScan(raw); // colou o link do QR code
    if (!issuer) return fail(msg, $('cIssuer'), 'Informe o nome do serviço, por exemplo GitHub.');
    if (!raw) return fail(msg, $('cSecret'), 'Digite a chave secreta mostrada pelo site ou escaneie o QR code.');
    const secret = totp.cleanSecret(raw);
    if (!/^[A-Z2-7]+$/.test(secret)) return fail(msg, $('cSecret'), 'A chave tem caracteres que não existem nela. Ela usa só letras de A a Z e números de 2 a 7.');
    if (secret.length < 16) return fail(msg, $('cSecret'), `A chave tem ${secret.length} caracteres; o normal é ter 16 ou mais. Confira se copiou tudo.`);
    if (S.data.codes.some((c) => c.secret === secret)) return fail(msg, $('cSecret'), 'Esse código já está no cofre.');
    const p = ui.scanParams && ui.scanParams.secret === secret ? ui.scanParams : { digits: 6, period: 30, algo: 'SHA-1' };
    const c = { id: uid(), issuer, account, secret, digits: p.digits, period: p.period, algo: p.algo, created: Date.now() };
    S.data.codes.push(c);
    const n = norm(issuer);
    const login = S.data.logins.find((l) => !l.codeId && norm(l.site) === n);
    if (login) login.codeId = c.id; // liga o código à senha do mesmo site (RF-18)
    if (!(await busy($('saveCode'), 'Salvando…', save))) return;
    closeSheet('codeSheet');
    selectTab('codigos');
    renderAll();
    toast(login ? `Código salvo e ligado à senha de “${login.site}”.` : 'Código salvo.');
  });

  /* ================= gerador ================= */

  function newPassword() {
    const o = {
      length: +$('genLen').value,
      upper: $('gUpper').checked, lower: $('gLower').checked,
      digits: $('gDigits').checked, symbols: $('gSymbols').checked,
    };
    if (!o.upper && !o.lower && !o.digits && !o.symbols) {
      $('gLower').checked = true;
      o.lower = true;
      toast('Escolha pelo menos um tipo de caractere.');
    }
    const pw = passwords.generate(o);
    $('genOut').textContent = pw;
    paintMeter($('genMeter'), $('genLabel'), pw);
  }
  $('genLen').addEventListener('input', () => { $('genLenVal').textContent = $('genLen').value; newPassword(); });
  ['gUpper', 'gLower', 'gDigits', 'gSymbols'].forEach((id) => $(id).addEventListener('change', newPassword));
  $('genNew').addEventListener('click', newPassword);
  $('genCopy').addEventListener('click', () => copy($('genOut').textContent, 'Senha'));
  $('genSave').addEventListener('click', () => openLoginSheet(null, $('genOut').textContent));

  /* ================= ajustes ================= */

  function updateSettings(partial) {
    S.settings = store.saveSettings(partial);
  }

  function renderSettings() {
    const st = S.settings;
    $('setIdle').value = String(st.idleMinutes);
    $('setHide').value = st.hideLock;
    $('setClip').value = String(st.clipboardSeconds);
    $('setTheme').value = st.theme;
    $('backupStatus').textContent = st.lastBackupAt
      ? `Último backup: ${fmtDate(st.lastBackupAt)}. O arquivo continua criptografado.`
      : 'Você ainda não fez nenhum backup.';
    renderStorageStatus();
  }

  async function renderStorageStatus() {
    const el = $('storageStatus');
    if (!store.isAvailable()) {
      el.className = 'note bad';
      el.textContent = 'Este navegador não está salvando os dados. Faça um backup antes de fechar a página.';
      return;
    }
    const persisted = await store.isPersisted();
    el.className = 'note';
    el.textContent = 'As senhas ficam só neste navegador, criptografadas. ' + (persisted
      ? 'O navegador garantiu que não vai apagar esses dados sozinho.'
      : 'Se faltar espaço no aparelho, o navegador pode apagar dados de sites: mantenha o backup em dia.');
  }

  function renderBackupBanner() {
    const items = S.data.logins.length + S.data.codes.length;
    const last = S.settings.lastBackupAt ? new Date(S.settings.lastBackupAt).getTime() : 0;
    const old = Date.now() - last > 30 * 86400000;
    $('bnBackup').classList.toggle('hidden', !(items > 0 && old));
    $('bnBackupText').textContent = last
      ? 'Seu último backup tem mais de 30 dias. Faça um novo para não perder o que mudou.'
      : 'Você ainda não fez um backup. Sem ele, perder este aparelho é perder as senhas.';
  }

  $('setIdle').addEventListener('change', () => {
    updateSettings({ idleMinutes: +$('setIdle').value });
    bumpIdle();
    toast('Tempo de bloqueio atualizado.');
  });
  $('setHide').addEventListener('change', () => { updateSettings({ hideLock: $('setHide').value }); toast('Preferência salva.'); });
  $('setClip').addEventListener('change', () => { updateSettings({ clipboardSeconds: +$('setClip').value }); toast('Preferência salva.'); });
  $('setTheme').addEventListener('change', () => { updateSettings({ theme: $('setTheme').value }); applyTheme(); });

  /* ---------- senha mestra e código de recuperação ---------- */

  $('setChangePw').addEventListener('click', () => {
    ['p0', 'p1', 'p2'].forEach((id) => { $(id).value = ''; });
    paintMeter($('p1Meter'), $('p1Label'), '');
    $('pwMsg').textContent = '';
    openSheet('pwSheet', 'p0');
  });
  $('p1').addEventListener('input', () => paintMeter($('p1Meter'), $('p1Label'), $('p1').value));
  $('pwSave').addEventListener('click', async () => {
    const msg = $('pwMsg');
    const current = $('p0').value, a = $('p1').value, b = $('p2').value;
    if (!current) return fail(msg, $('p0'), 'Digite a senha mestra atual.');
    const err = checkNewMaster(a, b, ['p1', 'p2']);
    if (err) return fail(msg, $(err.field), err.text);
    if (a === current) return fail(msg, $('p1'), 'A nova senha é igual à atual.');
    await busy($('pwSave'), 'Salvando…', async () => {
      try {
        await vault.unlock(S.record, current);
      } catch (e) {
        return fail(msg, $('p0'), 'A senha mestra atual está incorreta.');
      }
      if (!(await persistWith(() => vault.changePassword(S.session, S.record, a)))) return;
      closeSheet('pwSheet');
      ['p0', 'p1', 'p2'].forEach((id) => { $(id).value = ''; });
      resetEyes();
      toast('Senha mestra alterada. Use a nova senha da próxima vez.');
    });
  });

  $('setNewCode').addEventListener('click', async () => {
    const ok = await confirmDialog({
      title: 'Gerar novo código de recuperação?',
      text: 'O código antigo deixa de funcionar. O novo aparece uma única vez: tenha papel à mão para anotar.',
      ok: 'Gerar novo código',
    });
    if (!ok) return;
    let code = null;
    const saved = await persistWith(async () => {
      const r = await vault.newRecovery(S.session, S.record);
      code = r.recoveryCode;
      return r.record;
    });
    if (!saved) return;
    clearIdle();
    showRecoveryCode(code, () => {
      show('main');
      selectTab('ajustes');
      bumpIdle();
      toast('Novo código de recuperação ativado.');
    });
  });

  /* ---------- backup (RF-27) ---------- */

  function exportBackup() {
    if (!S.record) return;
    download(`cofrekey-backup-${today()}.json`, vault.serialize(S.record, true), 'application/json');
    updateSettings({ lastBackupAt: new Date().toISOString() });
    renderSettings();
    renderBackupBanner();
    toast('Backup baixado. Ele só abre com a senha mestra ou o código de recuperação.');
  }
  $('setBackup').addEventListener('click', exportBackup);
  $('bnBackupBtn').addEventListener('click', exportBackup);

  ['setupRestore', 'damagedRestore', 'setRestore'].forEach((id) => $(id).addEventListener('click', () => pickFile($('fileRestore'))));
  $('fileRestore').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    let rec;
    try {
      rec = vault.parse(await file.text());
    } catch (err) {
      return toast('Esse arquivo não é um backup do CofreKey.');
    }
    if (store.getVault()) {
      const ok = await confirmDialog({
        title: 'Restaurar este backup?',
        text: 'O cofre deste aparelho será trocado pelo do backup. O que foi salvo depois desse backup será perdido.',
        ok: 'Restaurar',
        danger: true,
      });
      if (!ok) return;
    }
    wipeSession();
    const saved = store.setVault(vault.serialize(rec));
    storageWarning(!saved);
    store.clearAttempts();
    updateSettings({ lastBackupAt: rec.updatedAt || new Date().toISOString() });
    goLock('restored');
  });

  /* ---------- importar CSV (RF-37) ---------- */

  $('setImport').addEventListener('click', () => pickFile($('fileCsv')));
  $('fileCsv').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    let parsed;
    try {
      parsed = csv.toItems(csv.parse(await file.text()));
    } catch (err) {
      return toast(err.message === 'NO_PASSWORD_COLUMN'
        ? 'Esse arquivo não tem uma coluna de senhas. Exporte de novo pelo navegador.'
        : 'Não foi possível ler esse arquivo.');
    }
    const key = (l) => [norm(l.site), l.user || '', l.pass].join('\u0000');
    const seen = new Set(S.data.logins.map(key));
    const fresh = parsed.logins.filter((l) => {
      const k = key(l);
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    const codes = [];
    for (const c of parsed.codes) {
      let acc = null;
      try {
        if (/^otpauth:/i.test(c.value)) acc = totp.parseUri(c.value);
        else if (totp.isValidSecret(c.value)) acc = { issuer: c.site, account: c.user, secret: totp.cleanSecret(c.value), digits: 6, period: 30, algo: 'SHA-1' };
      } catch (err) { acc = null; }
      if (acc && !S.data.codes.some((x) => x.secret === acc.secret) && !codes.some((x) => x.secret === acc.secret)) {
        codes.push({ ...acc, issuer: acc.issuer || c.site, account: acc.account || c.user || '', from: c.site + '\u0000' + (c.user || '') });
      }
    }
    if (!fresh.length && !codes.length) {
      return toast(parsed.logins.length ? 'Todas as senhas desse arquivo já estão no cofre.' : 'Nenhuma senha encontrada nesse arquivo.');
    }
    const ok = await confirmDialog({
      title: 'Importar senhas',
      text: `Encontramos ${count(fresh.length, 'senha nova', 'senhas novas')}${codes.length ? ` e ${count(codes.length, 'código', 'códigos')}` : ''}. As repetidas foram ignoradas. Importar?`,
      ok: 'Importar',
    });
    if (!ok) return;
    const now = Date.now();
    const codeItems = codes.map((c) => ({ id: uid(), issuer: c.issuer, account: c.account, secret: c.secret, digits: c.digits, period: c.period, algo: c.algo, created: now, from: c.from }));
    fresh.forEach((l) => {
      const match = codeItems.find((c) => c.from === l.site + '\u0000' + (l.user || ''));
      S.data.logins.push({ id: uid(), fav: false, created: now, updated: now, codeId: match ? match.id : null, ...l });
    });
    codeItems.forEach((c) => { delete c.from; S.data.codes.push(c); });
    if (!(await save())) return;
    renderAll();
    selectTab('senhas');
    toast(`${count(fresh.length, 'senha importada', 'senhas importadas')}. Agora apague o arquivo CSV: ele não é protegido.`);
  });

  /* ---------- instalar como aplicativo (RF-36) ---------- */

  let installEvent = null;
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    installEvent = e;
    $('installRow').classList.remove('hidden');
  });
  $('setInstall').addEventListener('click', async () => {
    if (!installEvent) return;
    installEvent.prompt();
    const choice = await installEvent.userChoice.catch(() => null);
    installEvent = null;
    $('installRow').classList.add('hidden');
    if (choice && choice.outcome === 'accepted') toast('CofreKey instalado.');
  });
  window.addEventListener('appinstalled', () => $('installRow').classList.add('hidden'));

  if ('serviceWorker' in navigator && (location.protocol === 'https:' || ['localhost', '127.0.0.1'].includes(location.hostname))) {
    window.addEventListener('load', () => navigator.serviceWorker.register('sw.js').catch(() => {}));
  }

  /* ================= teclado (heurística 7) ================= */

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const top = sheetStack[sheetStack.length - 1];
      if (top) { e.preventDefault(); closeSheet(top.id); }
      return;
    }
    if (S.screen !== 'main' || sheetStack.length || e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.target.closest && e.target.closest('input, textarea, select, [contenteditable="true"]')) return;
    const k = e.key;
    if (k === '/') { e.preventDefault(); selectTab('senhas'); $('search').focus(); }
    else if (k === 'n' || k === 'N') { e.preventDefault(); if (ui.tab === 'codigos') openCodeSheet(); else openLoginSheet(); }
    else if (['1', '2', '3', '4'].includes(k)) { const t = TABS[+k - 1]; selectTab(t); $('tab-' + t).focus(); }
    else if (k === 'b' || k === 'B') lock('manual');
    else if (k === '?') openHelp('h-atalhos');
  });

  /* ================= início ================= */

  $('appVersion').textContent = VERSION;
  applyTheme();
  storageWarning(!store.isAvailable());
  if (!loadRecord()) show('setup', 'm1');
  else goLock();
})();
