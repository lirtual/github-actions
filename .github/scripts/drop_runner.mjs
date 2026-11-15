/** G3 only: after successful signed Claim, stage one selected file and stop.
 * G4 Owner-only encrypted claim receipt and G5 temporary deployment are NOT
 * connected. No real Cloudflare account creation, Terms acceptance, or upload.
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

export function prepareDropStage(env, { stage = spawnSync, temporaryDirectory = tmpdir } = {}) {
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
    // Deliberately fail closed here. Adding real temporary deployment before
    // the G4 encrypted claim receipt would expose a bearer claim link.
    throw new DropRunnerError('drop_owner_receipt_not_ready');
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
