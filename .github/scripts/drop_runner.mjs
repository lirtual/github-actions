/** Spec #87: Claim-gated file stage and synthetic deploy→sealed-result integration.
 * Production CLI defaults to deployment-disabled. The reviewed repository
 * variable opt-in is separate from each request's Cloudflare Terms consent.
 */
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { openDropEnvelope, DropEnvelopeError } from './drop_envelope.mjs';
import {sealDropClaim,DropReceiptError} from './drop_receipt.mjs';

class DropRunnerError extends Error {
  constructor(code) {
    super(code);
    this.name = 'DropRunnerError';
  }
}

/** The future Wrangler capture must call only this narrow encrypted channel. */
export function deliverDropClaim(claim,env,{post=spawnSync}={}){
  try{
    const sealed=sealDropClaim(claim,env.DROP_RECEIPT_PUBLIC_KEY_PEM);
    return submitSealedDropResult(sealed,env,{post});
  }catch(error){
    if(error instanceof DropReceiptError)throw new DropRunnerError('drop_receipt_invalid');
    throw error;
  }
}

/** G4 callback seam for the future G5 deployment; never invoked by G3.
 * The signed result body is delivered only via private Python stdin.
 */
export function submitSealedDropResult(sealed, env, { post = spawnSync } = {}) {
  if (!sealed || typeof sealed !== 'object' || Array.isArray(sealed) ||
      Object.keys(sealed).sort().join(',') !== 'drop_claim_v,expires_at,preview_url,sealed_claim' ||
      sealed.drop_claim_v !== 1 || typeof sealed.sealed_claim !== 'string' ||
      !/^[A-Za-z0-9_-]{250,3600}$/.test(sealed.sealed_claim))
    throw new DropRunnerError('drop_receipt_invalid');
  const command = fileURLToPath(new URL('./drop_result.py', import.meta.url));
  const result = post('python3', [command], {
    input: JSON.stringify(sealed),
    encoding: 'utf8',
    timeout: 30000,
    maxBuffer: 256,
    env: {
      PATH: env.PATH || '/usr/bin:/bin',
      PYTHONDONTWRITEBYTECODE: '1',
      ATTEMPT_ID: env.ATTEMPT_ID || '',
      DISPATCH_ID: env.DISPATCH_ID || '',
      CAPABILITY_ID: env.CAPABILITY_ID || '',
      WORKFLOW_ACTION_CLAIM_URL: env.WORKFLOW_ACTION_CLAIM_URL || '',
      ACTIONS_ID_TOKEN_REQUEST_URL: env.ACTIONS_ID_TOKEN_REQUEST_URL || '',
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: env.ACTIONS_ID_TOKEN_REQUEST_TOKEN || '',
    },
  });
  if (result.error || result.status !== 0)
    throw new DropRunnerError('drop_receipt_callback_unknown');
  return { status: 'drop_receipt_acknowledged' };
}

/** Cloudflare may return 404 immediately after Wrangler completes. Check the
 * actual public URL with up to 12 credential-free GETs.
 * Never follow redirects or redeploy an Unknown result.
 */
function verifyTemporaryPreview(url, { probe = spawnSync, wait = spawnSync } = {}) {
  for (let attempt = 0; attempt < 12; attempt++) {
    const checked = probe('curl', [
      '-q', '--silent', '--max-time', '8', '--max-redirs', '0',
      '--output', '/dev/null', '--write-out', '%{http_code}', url,
    ], {
      env: { PATH: '/usr/bin:/bin' }, encoding: 'utf8',
      timeout: 10000, maxBuffer: 256,
    });
    if (!checked.error && checked.status === 0 && checked.stdout === '200') return;
    if (attempt < 11) {
      const slept = wait('sleep', ['8'], {
        env: { PATH: '/usr/bin:/bin' }, timeout: 9000,
      });
      if (slept.error || slept.status !== 0) break;
    }
  }
  throw new DropRunnerError('drop_deploy_result_unknown');
}

/** G4-only Wrangler output capture. The caller must check the CLI exit status;
 * this function never invokes Wrangler or creates a temporary account.
 * Treat parsing/transport failures as Unknown (never redeploy or retry).
 */
export function captureTemporaryDeployment(output, env, {
  startedAt, finishedAt = Date.now(), post = spawnSync,
  probe = spawnSync, wait = spawnSync,
} = {}) {
  const unknown = () => { throw new DropRunnerError('drop_deploy_result_unknown'); };
  if (typeof output !== 'string' || output.length > 65536 ||
      !Number.isSafeInteger(startedAt) || !Number.isSafeInteger(finishedAt) ||
      finishedAt < startedAt || finishedAt - startedAt > 15 * 60000 ||
      !/^[ \t]*Temporary account ready:[ \t]*$/m.test(output)) unknown();

  // Reject extra labelled lines even when the extra value is malformed.
  for (const label of ['Account:', 'Claim within:', 'Claim URL:']) {
    const prefix = new RegExp('^[ \\t]*' + label, 'gm');
    if ([...output.matchAll(prefix)].length !== 1) unknown();
  }
  const exactlyOne = pattern => {
    const matches = [...output.matchAll(pattern)];
    if (matches.length !== 1) unknown();
    return matches[0][1];
  };
  // Source: Cloudflare's documented unauthenticated Wrangler --temporary output.
  // Fail closed on reused accounts, changed output formats, or ambiguous URLs.
  exactlyOne(/^[ \t]*Account:[ \t]*[a-zA-Z0-9_-]{1,100}[ \t]+\((created)\)[ \t]*$/gm);
  exactlyOne(/^[ \t]*Claim within:[ \t]*(60)[ \t]+minutes[ \t]*$/gm);
  const claimUrl = exactlyOne(/^[ \t]*Claim URL:[ \t]*(https:\/\/dash\.cloudflare\.com\/claim-preview\?claimToken=[A-Za-z0-9_-]{16,1024})[ \t]*$/gm);
  const previewUrl = exactlyOne(/^[ \t]*(https:\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+workers\.dev\/?)[ \t]*$/gm);
  // CLI success does not establish public accessibility (actual 404 observed).
  // Read-only probes cannot create a second account or expose Claim bearer.
  verifyTemporaryPreview(previewUrl, { probe, wait });
  // Wrangler gives a relative 60-minute window, not an absolute expiry.
  // Bound the delivered receipt from *before* account creation with a margin.
  const expiresAt = startedAt + 55 * 60000;
  if (expiresAt - finishedAt < 120000) unknown();
  return deliverDropClaim({
    attemptId: env.ATTEMPT_ID, previewUrl, claimUrl, expiresAt,
  }, env, { post });
}

export function prepareDropStage(env, {
  stage = spawnSync, deploy = spawnSync, post = spawnSync,
  probe = spawnSync, wait = spawnSync,
  deploymentAuthorized = env.DROP_TEMPORARY_DEPLOYMENT_AUTHORIZED === 'true',
  temporaryDirectory = tmpdir,
} = {}) {
  const { ATTEMPT_ID: attemptId, DROP_PRIVATE_KEY_PEM: privateKey } = env;
  if (!privateKey || typeof privateKey !== 'string')
    throw new DropRunnerError('drop_private_key_unavailable');
  // The public contract digest is authenticated inside the envelope's
  // AES-GCM AAD; it is not independently supplied by a caller or step input.
  const file = openDropEnvelope(
    [env.DROP_PART_0 || '', env.DROP_PART_1 || '', env.DROP_PART_2 || ''],
    { privateKey, attemptId },
  );
  if (process.argv.includes('--offline-preflight')) {
    // No file read and no external network call in CI/offline preflight.
    return { status: 'drop_envelope_verified' };
  }
  // No source download, staging or new Cloudflare account without opt-in.
  if (!deploymentAuthorized)
    throw new DropRunnerError('drop_deploy_not_authorized');
  const root = mkdtempSync(join(temporaryDirectory(), 'drop-stage-'));
  try {
    const destination = join(root, 'site');
    mkdirSync(destination, { mode: 0o700 });
    const python = fileURLToPath(new URL('./drop_static.py', import.meta.url));
    const result = stage('python3', [python, destination], {
      input: JSON.stringify(file),
      encoding: 'utf8',
      timeout: 120000,
      maxBuffer: 4096,
      // No inherited credentials, file URL or sensitive environment.
      env: { PATH: env.PATH || '/usr/bin:/bin', PYTHONDONTWRITEBYTECODE: '1' },
    });
    if (result.error || result.status !== 0)
      throw new DropRunnerError('drop_stage_failed');
    // Isolate Wrangler's temporary credentials from every other Job and user.
    const isolatedHome = join(root, 'wrangler-home');
    const isolatedConfig = join(root, 'wrangler-config');
    mkdirSync(isolatedHome, { mode: 0o700 });
    mkdirSync(isolatedConfig, { mode: 0o700 });
    const startedAt = Date.now();
    // No shell, no inherited Cloudflare/GitHub tokens, and no terminal output.
    const deployed = deploy('wrangler', [
      'deploy', '--temporary', '--assets', destination,
      '--name', 'drop-preview', '--compatibility-date', '2026-11-13',
    ], {
      cwd: root,
      env: {
        PATH: env.PATH || '/usr/bin:/bin',
        HOME: isolatedHome,
        XDG_CONFIG_HOME: isolatedConfig,
        CI: 'true',
        NO_COLOR: '1',
        FORCE_COLOR: '0',
      },
      encoding: 'utf8',
      timeout: 10 * 60000,
      maxBuffer: 65536,
    });
    const finishedAt = Date.now();
    // Nonzero/timeout can still mean that an account was created: Unknown,
    // never retry the same Attempt, and never forward raw stdout/stderr.
    if (deployed.error || deployed.status !== 0 ||
        typeof deployed.stdout !== 'string' || typeof deployed.stderr !== 'string')
      throw new DropRunnerError('drop_deploy_unknown');
    return captureTemporaryDeployment(
      deployed.stdout + '\n' + deployed.stderr, env,
      { startedAt, finishedAt, post, probe, wait },
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  try {
    const result = prepareDropStage(process.env);
    process.stdout.write(result.status + '\n');
  } catch (error) {
    const code = error instanceof DropRunnerError || error instanceof DropEnvelopeError
      ? error.message : 'drop_runner_failed';
    process.stderr.write(code + '\n');
    process.exitCode = 1;
  }
}
