import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCipheriv, generateKeyPairSync, publicEncrypt, randomBytes, constants } from 'node:crypto';
import { prepareDropStage, captureTemporaryDeployment } from '../.github/scripts/drop_runner.mjs';
import { dropAAD } from '../.github/scripts/drop_envelope.mjs';

const attemptId = 'e47ec2a1-6c11-4ce7-90ea-f34c01984413';
const contractDigest = 'a'.repeat(64);
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const file = { file_id: 'fixture', file_name: 'index.html',
  download_url: 'https://files.oaiusercontent.com/fixture.html' };

function fixture() {
  const issuedAt = Date.now();
  const key = randomBytes(32), nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(dropAAD(attemptId, contractDigest));
  const value = JSON.stringify({ attemptId, contractDigest, issuedAt,
    expiresAt: issuedAt + 60000, file });
  const ciphertext = Buffer.concat([
    cipher.update(value, 'utf8'), cipher.final(), cipher.getAuthTag(),
  ]);
  const wrapped = publicEncrypt({ key: publicKey,
    padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key);
  const data = Buffer.from(JSON.stringify({
    v: 1, contract_digest: contractDigest,
    wrapped_key: wrapped.toString('base64url'),
    nonce: nonce.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
  })).toString('base64url');
  return { PATH: '/usr/bin:/bin', ATTEMPT_ID: attemptId,
    DROP_PRIVATE_KEY_PEM: privateKey,
    DROP_PART_0: data.slice(0, 3500), DROP_PART_1: data.slice(3500, 7000),
    DROP_PART_2: data.slice(7000) };
}

test('offline preflight can verify signed envelope without file read', () => {
  const previous = [...process.argv];
  process.argv.push('--offline-preflight');
  try {
    assert.deepEqual(prepareDropStage(fixture(), {
      stage: () => { throw Error('stage must not run'); },
    }), { status: 'drop_envelope_verified' });
  } finally { process.argv = previous; }
});

test('real Runner path cleans staged files, does not deploy, and hides locator', () => {
  const before = new Set(readdirSync(tmpdir()).filter(p => p.startsWith('drop-stage-')));
  let executions = 0;
  const stage = (_bin, argv, opts) => {
    executions++;
    assert.equal(argv.length, 2);
    assert.equal(JSON.parse(opts.input).download_url, file.download_url);
    assert.ok(!JSON.stringify(argv).includes(file.download_url));
    assert.ok(!JSON.stringify(opts.env).includes(file.download_url));
    return { status: 0 };
  };
  assert.throws(() => prepareDropStage(fixture(), { stage }),
    error => error.message === 'drop_owner_receipt_not_ready');
  assert.equal(executions, 1);
  const after = new Set(readdirSync(tmpdir()).filter(p => p.startsWith('drop-stage-')));
  assert.deepEqual(after, before);
});

test('missing key and wrong Attempt stop before staging', () => {
  const valid = fixture();
  const stage = () => { throw Error('staging must not run'); };
  assert.throws(() => prepareDropStage({ ...valid, DROP_PRIVATE_KEY_PEM: '' }, { stage }),
    /drop_private_key_unavailable/);
  assert.throws(() => prepareDropStage({ ...valid, ATTEMPT_ID:
    'c264e9c1-ad28-4f8d-8b29-c379bedab8d7' }, { stage }),
    /drop_envelope_invalid/);
});

test('workflow performs OIDC Claim before accessing encrypted input and private key', () => {
  const yaml = readFileSync(join(import.meta.dirname, '..', '.github/workflows/drop.yml'), 'utf8');
  assert.ok(yaml.includes('WORKFLOW_ACTION_TYPE: task'));
  assert.ok(yaml.includes('WORKFLOW_ACTION_OUTPUT_KIND: none'));
  assert.ok(yaml.indexOf('session_action.py claim') < yaml.indexOf('DROP_PRIVATE_KEY_PEM:'));
  assert.ok(!yaml.includes('environment: drop'));
  assert.ok(!yaml.includes('wrangler deploy'));
  assert.ok(!yaml.includes('autoactions'));
});

function wranglerFixture() {
  return [
    'Continuing means you accept Cloudflare Terms and Privacy Policy.',
    'Temporary account ready:',
    '  Account: example-name (created)',
    '  Claim within:   60 minutes',
    '  Claim URL:      https://dash.cloudflare.com/claim-preview?claimToken=' + 'a'.repeat(48),
    'Uploaded drop-preview',
    'Deployed drop-preview triggers',
    '  https://drop-preview.example-name.workers.dev',
  ].join('\n');
}

test('G4 captures documented Wrangler result and seals the bearer before callback', () => {
  const startedAt = Date.now();
  const raw = wranglerFixture();
  let callbacks = 0;
  const receipt = captureTemporaryDeployment(raw, {
    ATTEMPT_ID: attemptId, DROP_RECEIPT_PUBLIC_KEY_PEM: publicKey,
  }, {
    startedAt, finishedAt: startedAt + 1000,
    post: (_bin, args, options) => {
      callbacks++;
      assert.equal(args.length, 1);
      assert.ok(!JSON.stringify(args).includes('claimToken'));
      assert.ok(!JSON.stringify(options.env).includes('claimToken'));
      assert.ok(!JSON.stringify(options).includes('claim-preview'));
      const sealed = JSON.parse(options.input);
      assert.equal(sealed.preview_url, 'https://drop-preview.example-name.workers.dev');
      assert.equal(sealed.expires_at, startedAt + 55 * 60000);
      assert.ok(!JSON.stringify(sealed).includes('claimToken'));
      return { status: 0 };
    },
  });
  assert.deepEqual(receipt, { status: 'drop_receipt_acknowledged' });
  assert.equal(callbacks, 1);
});

test('G4 refuses ambiguous, reused, unverified or expired Wrangler output', () => {
  const startedAt = Date.now();
  const raw = wranglerFixture();
  const failures = [
    raw.replace('(created)', '(reused)'),
    raw.replace('60 minutes', '59 minutes'),
    raw.replace('Claim URL:', 'Claim URL: invalid\n  Claim URL:'),
    raw.replace('https://drop-preview.example-name.workers.dev', 'http://evil.invalid'),
    raw + '\n  https://second-account.workers.dev',
    raw.slice(0, 16),
    'X'.repeat(65537),
  ];
  for (const output of failures) {
    assert.throws(() => captureTemporaryDeployment(output, {
      ATTEMPT_ID: attemptId, DROP_RECEIPT_PUBLIC_KEY_PEM: publicKey,
    }, {
      startedAt, finishedAt: startedAt + 1000,
      post: () => { throw Error('no callback on failed parse'); },
    }), /drop_deploy_result_unknown/);
  }
  assert.throws(() => captureTemporaryDeployment(raw, {
    ATTEMPT_ID: attemptId, DROP_RECEIPT_PUBLIC_KEY_PEM: publicKey,
  }, {
    startedAt: startedAt - 60 * 60000, finishedAt: startedAt,
    post: () => { throw Error('no callback on expired receipt'); },
  }), /drop_deploy_result_unknown/);
});
