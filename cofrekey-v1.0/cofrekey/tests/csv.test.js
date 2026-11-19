const test = require('node:test');
const assert = require('node:assert/strict');
const csv = require('../js/csv.js');

test('lê o CSV exportado pelo Chrome', () => {
  const text = '﻿name,url,username,password,note\r\n' +
    'Instagram,https://www.instagram.com/,felipe,"senha,com""aspas",\r\n' +
    ',https://github.com/login,murillo,abc123XYZ!,"linha 1\nlinha 2"\r\n';
  const { logins, skipped } = csv.toItems(csv.parse(text));
  assert.equal(skipped, 0);
  assert.deepEqual(logins[0], { site: 'Instagram', user: 'felipe', pass: 'senha,com"aspas', url: 'https://www.instagram.com/', note: '' });
  assert.equal(logins[1].site, 'github.com');
  assert.equal(logins[1].note, 'linha 1\nlinha 2');
});

test('lê o CSV do Firefox (sem coluna de nome) e do Bitwarden (com código)', () => {
  const ff = csv.toItems(csv.parse('"url","username","password","httpRealm"\n"https://www.netflix.com","murillo@email.com","123456",""\n'));
  assert.equal(ff.logins[0].site, 'netflix.com');
  const bw = csv.toItems(csv.parse('folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,GitHub,,,0,https://github.com,murillo,Xy7!aa,JBSWY3DPEHPK3PXP\n'));
  assert.equal(bw.logins[0].site, 'GitHub');
  assert.deepEqual(bw.codes, [{ site: 'GitHub', user: 'murillo', value: 'JBSWY3DPEHPK3PXP' }]);
});

test('separador ponto e vírgula (Excel em português) e linhas sem senha', () => {
  const { logins, skipped } = csv.toItems(csv.parse('nome;usuario;senha\nBanco;miguel;Qw!9xx\nVazio;fulano;\n'));
  assert.equal(logins.length, 1);
  assert.equal(skipped, 1);
});

test('arquivo sem coluna de senha', () => {
  assert.throws(() => csv.toItems(csv.parse('a,b\n1,2\n')), /NO_PASSWORD_COLUMN/);
});
