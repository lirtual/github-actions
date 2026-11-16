import assert from 'node:assert/strict';
import { createCipheriv, createPublicKey, generateKeyPairSync, publicEncrypt, randomBytes, constants, webcrypto } from 'node:crypto';
import { test } from 'node:test';
import { dropAAD, openDropEnvelope, DropEnvelopeError } from '../.github/scripts/drop_envelope.mjs';

const attemptId = 'e47ec2a1-6c11-4ce7-90ea-f34c01984413';
const otherAttempt = 'c264e9c1-ad28-4f8d-8b29-c379bedab8d7';
const contractDigest = 'a'.repeat(64);
const issuedAt = Date.UTC(2026, 10, 15, 12, 0, 0);
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const baseFile = {
  file_id: 'test-fixture-1',
  file_name: 'site.zip',
  download_url: 'https://files.oaiusercontent.com/file?sig=' + 'x'.repeat(4054),
};
assert.ok(baseFile.download_url.length <= 4096);

function seal({
  file = baseFile, attempt = attemptId, contract = contractDigest,
  expiresAt = issuedAt + 5 * 60_000,
  actualAad = dropAAD(attempt, contract),
} = {}) {
  const key = randomBytes(32), nonce = randomBytes(12);
  const payload = JSON.stringify({
    attemptId: attempt, contractDigest: contract,
    issuedAt, expiresAt, file,
  });
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(actualAad);
  const sealed = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  const wrapped = publicEncrypt({
    key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256',
  }, key);
  const envelope = {
    v: 1,
    contract_digest: contract,
    wrapped_key: wrapped.toString('base64url'),
    nonce: nonce.toString('base64url'),
    ciphertext: sealed.toString('base64url'),
  };
  const outer = Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64url');
  assert.ok(outer.length <= 10500, 'Must fit three bounded GitHub inputs');
  return [outer.slice(0, 3500), outer.slice(3500, 7000), outer.slice(7000)];
}
const open = (parts, now = issuedAt + 1000, overrides = {}) =>
  openDropEnvelope(parts, { privateKey, attemptId, contractDigest, now, ...overrides });
const reject = (action, code = 'drop_envelope_invalid') => {
  assert.throws(action, error => {
    assert.ok(error instanceof DropEnvelopeError);
    assert.equal(error.message, code);
    assert.ok(!error.message.includes('files.oaiusercontent.com'));
    assert.ok(!error.message.includes('sig='));
    return true;
  });
};

test('maximum selected-file URL fits 3 GitHub inputs and round trips', () => {
  const segments = seal();
  assert.equal(segments.length, 3);
  assert.ok(segments.every(s => s.length <= 3500));
  assert.deepEqual(open(segments), baseFile);
});

test('Runner derives and authenticates the reviewed digest without an extra input', () => {
  assert.deepEqual(openDropEnvelope(seal(), {
    privateKey, attemptId, now: issuedAt + 1000,
  }), baseFile);
});

test('OpenAI-selected file may omit file_name and mime_type', () => {
  const { file_name, ...withoutName } = baseFile;
  assert.deepEqual(open(seal({ file: withoutName })), withoutName);
});

test('tampered plaintext contract digest fails AES-GCM verification', () => {
  const sealed = seal();
  const outer = JSON.parse(Buffer.from(sealed.join(''), 'base64url').toString());
  outer.contract_digest = 'b'.repeat(64);
  const encoded = Buffer.from(JSON.stringify(outer)).toString('base64url');
  reject(() => open([encoded.slice(0, 3500), encoded.slice(3500, 7000), encoded.slice(7000)]));
});

test('an altered encrypted segment fails closed', () => {
  const parts = seal();
  const changed = [...parts];
  changed[0] = (changed[0][0] === 'A' ? 'B' : 'A') + changed[0].slice(1);
  reject(() => open(changed));
});

test('other Attempt cannot decrypt an otherwise correct envelope', () => {
  const parts = seal();
  reject(() => open(parts, issuedAt + 1000, { attemptId: otherAttempt }));
});

test('other reviewed Action contract cannot decrypt', () => {
  reject(() => open(seal(), issuedAt + 1000, { contractDigest: 'b'.repeat(64) }));
});

test('expired attachment is rejected even with valid authenticated ciphertext', () => {
  reject(() => open(seal({ expiresAt: issuedAt + 500 }), issuedAt + 1000), 'drop_envelope_expired');
});

test('wrong repository private key cannot decrypt', () => {
  const wrong = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  }).privateKey;
  reject(() => open(seal(), issuedAt + 1000, { privateKey: wrong }));
});

test('bad or unsupported envelope parts are rejected', () => {
  reject(() => open(['', '', '']));
  reject(() => open(['A'.repeat(3501), '', '']));
  reject(() => open(['A', '', 'A']));
  reject(() => open([123, '', '']));
  reject(() => open(['garbage', '', '']));
});

test('invalid file name and overlong signed URL are rejected after decryption', () => {
  reject(() => open(seal({ file: { ...baseFile, file_name: 'launch.sh' } })));
  reject(() => open(seal({ file: { ...baseFile, download_url: 'x'.repeat(4097) } })));
});

test('future time or overly long claim of attachment lifetime is rejected', () => {
  reject(() => open(seal(), issuedAt - 61000));
  reject(() => open(seal({ expiresAt: issuedAt + 3600001 })));
});

test('file descriptor plaintext is not present in the sealed dispatch arguments', () => {
  const parts = seal();
  assert.ok(!parts.join('').includes('files.oaiusercontent.com'));
  assert.ok(!parts.join('').includes('sig='));
  assert.ok(!parts.join('').includes('site.zip'));
});

test('Worker-style WebCrypto RSA-OAEP and AES-GCM bytes open in Runner Node', async () => {
  const subtle = webcrypto.subtle;
  const publicDer = createPublicKey(publicKey).export({ format: 'der', type: 'spki' });
  const workerKey = await subtle.importKey(
    'spki', publicDer, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
  const contentKey = randomBytes(32);
  const aes = await subtle.importKey('raw', contentKey, 'AES-GCM', false, ['encrypt']);
  const iv = randomBytes(12);
  const clear = Buffer.from(JSON.stringify({
    attemptId, contractDigest, issuedAt, expiresAt: issuedAt + 60000, file: baseFile,
  }));
  const ciphertext = Buffer.from(await subtle.encrypt({
    name: 'AES-GCM', iv, additionalData: dropAAD(attemptId, contractDigest),
    tagLength: 128,
  }, aes, clear));
  const wrappedKey = Buffer.from(await subtle.encrypt({ name: 'RSA-OAEP' }, workerKey, contentKey));
  const encoded = Buffer.from(JSON.stringify({
    v: 1,
    contract_digest: contractDigest,
    nonce: iv.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
    wrapped_key: wrappedKey.toString('base64url'),
  })).toString('base64url');
  const parts = [encoded.slice(0, 3500), encoded.slice(3500, 7000), encoded.slice(7000)];
  assert.deepEqual(open(parts), baseFile);
});
