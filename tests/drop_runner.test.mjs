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

function fixture(selectedFile = file) {
  const issuedAt = Date.now();
  const key = randomBytes(32), nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(dropAAD(attemptId, contractDigest));
  const value = JSON.stringify({ attemptId, contractDigest, issuedAt,
    expiresAt: issuedAt + 60000, file: selectedFile });
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

test('an exact sealed Attempt stages without a repository-wide opt-in flag', () => {
  const before = new Set(readdirSync(tmpdir()).filter(p => p.startsWith('drop-stage-')));
  let executions = 0, deploys = 0;
  const stage = (_bin, argv, opts) => {
    executions++;
    assert.equal(argv.length, 2);
    assert.equal(JSON.parse(opts.input).download_url, file.download_url);
    assert.ok(!JSON.stringify(argv).includes(file.download_url));
    assert.ok(!JSON.stringify(opts.env).includes(file.download_url));
    return { status: 0 };
  };
  assert.throws(() => prepareDropStage(fixture(), { stage,
    deploy: () => { deploys++; return { status: 1, stdout: '', stderr: '' }; },
  }), /drop_deploy_unknown/);
  assert.equal(executions, 1);
  assert.equal(deploys, 1);
  const after = new Set(readdirSync(tmpdir()).filter(p => p.startsWith('drop-stage-')));
  assert.deepEqual(after, before);
});

test('missing optional ChatGPT metadata still reaches the bounded stage', () => {
  const required = { file_id: file.file_id, download_url: file.download_url };
  let staged = 0;
  assert.throws(() => prepareDropStage(fixture(required), {
    stage: (_bin, _argv, opts) => {
      staged++;
      assert.deepEqual(JSON.parse(opts.input), required);
      return { status: 0 };
    },
    deploy: () => ({ status: 1, stdout: '', stderr: '' }),
  }), /drop_deploy_unknown/);
  assert.equal(staged, 1);
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
  assert.ok(yaml.includes('wrangler@4.162.0'));
  assert.ok(yaml.includes('--ignore-scripts'));
  assert.ok(yaml.includes('$RUNNER_TEMP/drop-cli'));
  assert.ok(!yaml.includes('DROP_TEMPORARY_DEPLOYMENT_AUTHORIZED'));
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

test('G4 rejected output has a bounded, non-sensitive diagnostic reason', () => {
  const startedAt = Date.now();
  const canary = 'claimToken=' + 'z'.repeat(48);
  assert.throws(() => captureTemporaryDeployment('unexpected output ' + canary, {
    ATTEMPT_ID: attemptId, DROP_RECEIPT_PUBLIC_KEY_PEM: publicKey,
  }, {
    startedAt, finishedAt: startedAt + 1000,
    post: () => { throw Error('callback must not occur'); },
  }), error => {
    assert.equal(error.message, 'drop_deploy_result_unknown:output_shape');
    assert.ok(!error.message.includes(canary));
    return true;
  });
});

test('G4 captures documented Wrangler result and seals the bearer before callback', () => {
  const startedAt = Date.now();
  const raw = wranglerFixture();
  let callbacks = 0;
  const receipt = captureTemporaryDeployment(raw, {
    ATTEMPT_ID: attemptId, DROP_RECEIPT_PUBLIC_KEY_PEM: publicKey,
  }, {
    startedAt, finishedAt: startedAt + 1000,
    probe: () => ({ status: 0, stdout: '200' }),
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

test('G4 verifies public HTTP 200 after transient 404 without exposing claim', () => {
  const at = Date.now();
  const seen = [], waits = [];
  let callbacks = 0;
  const result = captureTemporaryDeployment(wranglerFixture(), {
    ATTEMPT_ID: attemptId, DROP_RECEIPT_PUBLIC_KEY_PEM: publicKey,
  }, {
    startedAt: at, finishedAt: at + 1000,
    probe: (command, args, options) => {
      assert.equal(command, 'curl');
      assert.equal(args[0], '-q');
      assert.ok(args.includes('--max-redirs'));
      assert.equal(args.at(-1), 'https://drop-preview.example-name.workers.dev');
      assert.deepEqual(Object.keys(options.env), ['PATH']);
      assert.ok(!JSON.stringify({args, options}).includes('claimToken'));
      const response = ['404', '503', '200'][seen.length];
      seen.push(response);
      return { status: 0, stdout: response };
    },
    wait: (command, args) => {
      assert.equal(command, 'sleep');
      assert.deepEqual(args, ['8']);
      waits.push(1);
      return { status: 0 };
    },
    post: () => { callbacks++; return { status: 0 }; },
  });
  assert.deepEqual(result, { status: 'drop_receipt_acknowledged' });
  assert.deepEqual(seen, ['404', '503', '200']);
  assert.equal(waits.length, 2);
  assert.equal(callbacks, 1);
});

test('G4 inaccessible preview becomes Unknown without callback or redeploy', () => {
  const at = Date.now();
  let probes = 0, waits = 0, callbacks = 0;
  assert.throws(() => captureTemporaryDeployment(wranglerFixture(), {
    ATTEMPT_ID: attemptId, DROP_RECEIPT_PUBLIC_KEY_PEM: publicKey,
  }, {
    startedAt: at, finishedAt: at + 1000,
    probe: () => { probes++; return { status: 0, stdout: '404' }; },
    wait: () => { waits++; return { status: 0 }; },
    post: () => { callbacks++; return { status: 0 }; },
  }), /drop_deploy_result_unknown:preview_unreachable/);
  assert.equal(probes, 12);
  assert.equal(waits, 11);
  assert.equal(callbacks, 0);
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

test('G4 reports bounded label, field and timing diagnostic stages', () => {
  const at = Date.now();
  const raw = wranglerFixture();
  for (const [output, startedAt, finishedAt, stage] of [
    [raw.replace('Claim URL:', 'Claim URL: invalid\n  Claim URL:'), at, at + 1000, 'output_labels'],
    [raw.replace('(created)', '(reused)'), at, at + 1000, 'output_fields'],
    [raw, at, at + 16 * 60000, 'time_bounds'],
  ]) {
    assert.throws(() => captureTemporaryDeployment(output, {
      ATTEMPT_ID: attemptId, DROP_RECEIPT_PUBLIC_KEY_PEM: publicKey,
    }, {
      startedAt, finishedAt,
      post: () => { throw Error('no callback on unknown result'); },
    }), error => {
      assert.equal(error.message, 'drop_deploy_result_unknown:' + stage);
      return true;
    });
  }
});

test('G4 full staged→mock Wrangler→sealed callback chain does not expose credentials', () => {
  const before = new Set(readdirSync(tmpdir()).filter(p => p.startsWith('drop-stage-')));
  const env = { ...fixture(), DROP_RECEIPT_PUBLIC_KEY_PEM: publicKey,
    DISPATCH_ID: attemptId, CAPABILITY_ID: 'github.action',
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'opaque-fixture',
  };
  let staged = 0, deployed = 0, posted = 0;
  const result = prepareDropStage(env, {
    stage: (_command, _argv, options) => {
      staged++;
      assert.equal(JSON.parse(options.input).download_url, file.download_url);
      assert.ok(!JSON.stringify(options.env).includes(file.download_url));
      return { status: 0 };
    },
    deploy: (command, argv, options) => {
      deployed++;
      assert.equal(command, 'wrangler');
      assert.equal(argv[0], 'deploy');
      assert.equal(argv[1], '--temporary');
      assert.equal(argv[2], '--assets');
      assert.ok(argv[3].endsWith('/site'));
      assert.deepEqual(argv.slice(4), ['--name', 'drop-preview',
        '--compatibility-date', '2026-11-13']);
      assert.ok(!JSON.stringify({ argv, options }).includes(privateKey));
      assert.ok(!JSON.stringify({ argv, options }).includes(file.download_url));
      assert.ok(!JSON.stringify({ argv, options }).includes('opaque-fixture'));
      assert.ok(options.env.HOME.startsWith(options.cwd + '/'));
      assert.ok(options.env.XDG_CONFIG_HOME.startsWith(options.cwd + '/'));
      assert.deepEqual(Object.keys(options.env).sort(), [
        'CI', 'FORCE_COLOR', 'HOME', 'NO_COLOR', 'PATH', 'XDG_CONFIG_HOME',
      ]);
      assert.equal(options.encoding, 'utf8');
      return { status: 0, stdout: wranglerFixture(), stderr: '' };
    },
    probe: () => ({ status: 0, stdout: '200' }),
    post: (_command, _argv, options) => {
      posted++;
      assert.ok(!JSON.stringify(options).includes('claimToken'));
      assert.ok(!JSON.stringify(options).includes('claim-preview'));
      assert.equal(JSON.parse(options.input).drop_claim_v, 1);
      return { status: 0 };
    },
  });
  assert.deepEqual(result, { status: 'drop_receipt_acknowledged' });
  assert.equal(staged, 1);
  assert.equal(deployed, 1);
  assert.equal(posted, 1);
  const after = new Set(readdirSync(tmpdir()).filter(p => p.startsWith('drop-stage-')));
  assert.deepEqual(after, before);
});

test('failed static staging blocks even an explicitly mocked deployer', () => {
  let deployed = 0;
  assert.throws(() => prepareDropStage(fixture(), {
    stage: () => ({ status: 1 }),
    deploy: () => { deployed++; throw Error('must not create account'); },
  }), /drop_stage_failed/);
  assert.equal(deployed, 0);
});

test('G4 uncertain CLI exits never retry or emit a callback', () => {
  for (const outcome of [
    { status: 1, stdout: wranglerFixture(), stderr: 'opaque failure' },
    { status: null, error: new Error('timeout'), stdout: '', stderr: '' },
    { status: 0, stdout: 'incomplete output', stderr: '' },
  ]) {
    let deployed = 0;
    assert.throws(() => prepareDropStage({
      ...fixture(), DROP_RECEIPT_PUBLIC_KEY_PEM: publicKey,
    }, {
      stage: () => ({ status: 0 }),
      deploy: () => { deployed++; return outcome; },
      post: () => { throw Error('must not callback an uncertain result'); },
    }), /drop_deploy_unknown|drop_deploy_result_unknown/);
    assert.equal(deployed, 1);
  }
});
