// Testes do autenticador com os vetores oficiais da RFC 6238 (apêndice B).
const test = require('node:test');
const assert = require('node:assert/strict');
const totp = require('../js/totp.js');

const ascii = (s) => totp.base32Encode(new TextEncoder().encode(s));
const SECRETS = {
  'SHA-1': ascii('12345678901234567890'),
  'SHA-256': ascii('12345678901234567890123456789012'),
  'SHA-512': ascii('1234567890123456789012345678901234567890123456789012345678901234'),
};
const VECTORS = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826'],
];

test('gera os códigos da RFC 6238 (SHA-1, SHA-256 e SHA-512)', async () => {
  for (const [t, sha1, sha256, sha512] of VECTORS) {
    for (const [algo, expected] of [['SHA-1', sha1], ['SHA-256', sha256], ['SHA-512', sha512]]) {
      const code = await totp.generate({ secret: SECRETS[algo], digits: 8, period: 30, algo }, t * 1000);
      assert.equal(code, expected, `${algo} em T=${t}`);
    }
  }
});

test('código de 6 dígitos é o final do código de 8 (como no Google Authenticator)', async () => {
  const code = await totp.generate({ secret: SECRETS['SHA-1'] }, 59000);
  assert.equal(code, '287082');
});

test('Base32: ida e volta, espaços e minúsculas', () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 251, 255, 128, 7, 9, 33]);
  assert.deepEqual(totp.base32Decode(totp.base32Encode(bytes)), bytes);
  assert.equal(totp.cleanSecret('jbsw y3dp-ehpk 3pxp'), 'JBSWY3DPEHPK3PXP');
  assert.ok(totp.isValidSecret('JBSW Y3DP EHPK 3PXP'));
  assert.ok(!totp.isValidSecret('JBSWY3DP'));          // curta demais
  assert.ok(!totp.isValidSecret('JBSWY3DPEHPK3PX0'));  // 0 não existe em Base32
  assert.throws(() => totp.base32Decode('ABC1'), /INVALID_SECRET/);
});

test('lê o QR code de cadastro (otpauth://totp)', () => {
  const acc = totp.parseUri('otpauth://totp/GitHub:murillo%40email.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30&algorithm=SHA1');
  assert.deepEqual(acc, { issuer: 'GitHub', account: 'murillo@email.com', secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algo: 'SHA-1' });
  const noIssuer = totp.parseUri('otpauth://totp/Google:grupo?secret=jbswy3dpehpk3pxp');
  assert.equal(noIssuer.issuer, 'Google');
  assert.equal(noIssuer.account, 'grupo');
});

test('recusa QR codes que não são TOTP válidos', () => {
  assert.throws(() => totp.parseUri('https://exemplo.com'), /INVALID_URI/);
  assert.throws(() => totp.parseUri('otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP&counter=1'), /UNSUPPORTED_HOTP/);
  assert.throws(() => totp.parseUri('otpauth://totp/X?secret=ABC'), /INVALID_SECRET/);
  assert.throws(() => totp.parseUri('otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=MD5'), /UNSUPPORTED_PARAMS/);
  assert.throws(() => totp.parseUri('otpauth-migration://offline?data=AA'), /MIGRATION/);
});

test('o QR code gerado para outro app volta igual', () => {
  const acc = { issuer: 'Banco do Brasil', account: 'miguel', secret: 'JBSWY3DPEHPK3PXP', digits: 8, period: 60, algo: 'SHA-256' };
  assert.deepEqual(totp.parseUri(totp.buildUri(acc)), acc);
});

// Monta um QR code de exportação do Google Authenticator (protobuf) para o teste.
function migrationUri(entries) {
  const varint = (n) => { const out = []; while (n > 127) { out.push((n & 127) | 128); n >>>= 7; } out.push(n); return out; };
  const bytesField = (f, bytes) => [...varint((f << 3) | 2), ...varint(bytes.length), ...bytes];
  const intField = (f, n) => [...varint(f << 3), ...varint(n)];
  const enc = new TextEncoder();
  let payload = [];
  for (const e of entries) {
    const p = [
      ...bytesField(1, [...totp.base32Decode(e.secret)]),
      ...bytesField(2, [...enc.encode(e.name)]),
      ...bytesField(3, [...enc.encode(e.issuer)]),
      ...intField(4, e.algo), ...intField(5, e.digits), ...intField(6, e.type),
    ];
    payload = payload.concat(bytesField(1, p));
  }
  payload = payload.concat(intField(2, 1));
  const b64 = Buffer.from(payload).toString('base64');
  return 'otpauth-migration://offline?data=' + encodeURIComponent(b64);
}

test('importa a exportação do Google Authenticator e ignora HOTP', () => {
  const uri = migrationUri([
    { secret: 'JBSWY3DPEHPK3PXP', name: 'GitHub:murillo', issuer: 'GitHub', algo: 1, digits: 1, type: 2 },
    { secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', name: 'felipe@gmail.com', issuer: 'Google', algo: 2, digits: 2, type: 2 },
    { secret: 'KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TF', name: 'contador', issuer: 'Antigo', algo: 1, digits: 1, type: 1 },
  ]);
  const { accounts, skipped } = totp.parseMigration(uri);
  assert.equal(skipped, 1);
  assert.deepEqual(accounts, [
    { issuer: 'GitHub', account: 'murillo', secret: 'JBSWY3DPEHPK3PXP', digits: 6, period: 30, algo: 'SHA-1' },
    { issuer: 'Google', account: 'felipe@gmail.com', secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', digits: 8, period: 30, algo: 'SHA-256' },
  ]);
});
