const test = require('node:test');
const assert = require('node:assert/strict');
const pw = require('../js/passwords.js');

test('gerador respeita tamanho e tipos escolhidos', () => {
  for (let i = 0; i < 200; i++) {
    const p = pw.generate({ length: 20, symbols: false });
    assert.equal(p.length, 20);
    assert.match(p, /[A-Z]/);
    assert.match(p, /[a-z]/);
    assert.match(p, /[2-9]/);
    assert.doesNotMatch(p, /[^A-Za-z0-9]/);
  }
  assert.equal(pw.generate({ length: 3 }).length, 8);   // mínimo 8
  assert.equal(pw.generate({ length: 99 }).length, 64); // máximo 64
  assert.throws(() => pw.generate({ upper: false, lower: false, digits: false, symbols: false }), /NO_CHARSET/);
});

test('medidor de força', () => {
  assert.equal(pw.strength('').level, 0);
  assert.equal(pw.strength('123456').label, 'Fraca');
  assert.equal(pw.strength('senha123').label, 'Fraca');
  assert.equal(pw.strength('abcd1234efgh').label, 'Fraca');   // sequência + pouco variada
  assert.ok(pw.strength('Fatec#Sorocaba2026').level >= 3);
  assert.equal(pw.strength('Felipe2026').label, 'Média');       // nome + ano
  assert.equal(pw.strength('Flamengo2026!').label, 'Fraca');    // time + ano
  assert.ok(pw.strength('Nova senha do cofre 2026!').level >= 3); // frase longa com a palavra senha
  for (let i = 0; i < 200; i++) assert.ok(pw.strength(pw.generate({ length: 16 })).level >= 3);
});

test('sorteio sem viés: todos os valores aparecem', () => {
  const seen = new Set();
  for (let i = 0; i < 2000; i++) seen.add(pw.randomInt(7));
  assert.equal(seen.size, 7);
});
