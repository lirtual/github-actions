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

class DropRunnerError extends Error {
  constructor(code) {
    super(code);
    this.name = 'DropRunnerError';
  }
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
