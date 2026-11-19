// Testes do cofre: criptografia, senha errada, arquivo danificado, recuperação.
const test = require('node:test');
const assert = require('node:assert/strict');
const vault = require('../js/vault.js');

const FAST = { iterations: 100000 }; // menos iterações só para o teste rodar rápido
const DATA = { logins: [{ id: '1', site: 'Instagram', user: 'felipe', pass: 'k#8Rz!p2Lq@v' }], codes: [] };

test('cria, salva e abre o cofre com a senha mestra', async () => {
  const { record, recoveryCode } = await vault.create('Fatec#Sorocaba2026', DATA, FAST);
  const text = vault.serialize(record);
  assert.ok(!text.includes('Instagram') && !text.includes('k#8Rz!p2Lq@v'), 'nada fica em texto puro');
  assert.ok(!text.includes('Fatec#Sorocaba2026'), 'a senha mestra não é salva');
  assert.ok(!text.includes(recoveryCode.replace(/-/g, '')), 'o código de recuperação não é salvo');
  const { data } = await vault.unlock(vault.parse(text), 'Fatec#Sorocaba2026');
  assert.deepEqual(data, DATA);
});

test('senha errada dá WRONG_PASSWORD', async () => {
  const { record } = await vault.create('Fatec#Sorocaba2026', DATA, FAST);
  await assert.rejects(vault.unlock(record, 'fatec#sorocaba2026'), { code: 'WRONG_PASSWORD' });
});

test('dados alterados dão CORRUPTED (e não "senha errada")', async () => {
  const { record } = await vault.create('Fatec#Sorocaba2026', DATA, FAST);
  const ct = Buffer.from(record.data.ct, 'base64');
  ct[5] ^= 1; // troca um bit
  const damaged = { ...record, data: { ...record.data, ct: ct.toString('base64') } };
  await assert.rejects(vault.unlock(damaged, 'Fatec#Sorocaba2026'), { code: 'CORRUPTED' });
});

test('arquivo que não é do CofreKey dá INVALID_FORMAT', () => {
  assert.throws(() => vault.parse('{"oi":1}'), { code: 'INVALID_FORMAT' });
  assert.throws(() => vault.parse('isso não é JSON'), { code: 'INVALID_FORMAT' });
});

test('salvar aumenta a revisão (usada para detectar outra aba)', async () => {
  const { record, session } = await vault.create('Fatec#Sorocaba2026', DATA, FAST);
  const next = await vault.save(session, record, { ...DATA, codes: [{ id: 'x' }] });
  assert.equal(next.rev, record.rev + 1);
  const { data } = await vault.unlock(next, 'Fatec#Sorocaba2026');
  assert.equal(data.codes.length, 1);
});

test('código de recuperação abre o cofre, com ou sem traços e em minúsculas', async () => {
  const { record, recoveryCode } = await vault.create('Fatec#Sorocaba2026', DATA, FAST);
  assert.match(recoveryCode, /^([A-Z2-7]{4}-){6}[A-Z2-7]{2}$/);
  const typed = recoveryCode.toLowerCase().replace(/-/g, ' ');
  const { data } = await vault.unlockWithRecovery(record, typed);
  assert.deepEqual(data, DATA);
  await assert.rejects(vault.unlockWithRecovery(record, 'AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AA'), { code: 'WRONG_CODE' });
});

test('trocar a senha mestra: a antiga para de funcionar e os dados continuam', async () => {
  const { record, session } = await vault.create('Fatec#Sorocaba2026', DATA, FAST);
  const changed = await vault.changePassword(session, record, 'Nova senha bem longa 2026!');
  await assert.rejects(vault.unlock(changed, 'Fatec#Sorocaba2026'), { code: 'WRONG_PASSWORD' });
  const { data } = await vault.unlock(changed, 'Nova senha bem longa 2026!');
  assert.deepEqual(data, DATA);
});

test('novo código de recuperação invalida o anterior', async () => {
  const { record, session, recoveryCode } = await vault.create('Fatec#Sorocaba2026', DATA, FAST);
  const { record: next, recoveryCode: fresh } = await vault.newRecovery(session, record);
  await assert.rejects(vault.unlockWithRecovery(next, recoveryCode), { code: 'WRONG_CODE' });
  assert.deepEqual((await vault.unlockWithRecovery(next, fresh)).data, DATA);
});
