/**
 * Spec #87 — offline-verifiable Drop handoff contract.
 *
 * Only the reviewed GitHub Task, after a successful OIDC Claim, may call this
 * with its private repository Secret. The plaintext file locator must stay in
 * memory and must never be returned as a GitHub Step output or logged.
 */
import { constants, createDecipheriv, privateDecrypt } from 'node:crypto';

const MAX_PART_BYTES = 3500;
const MAX_ENVELOPE_BYTES = MAX_PART_BYTES * 3;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const DIGEST = /^[a-f0-9]{64}$/i;
const B64URL = /^[A-Za-z0-9_-]+$/;

export class DropEnvelopeError extends Error {
  constructor(code = 'drop_envelope_invalid') {
    super(code);
    this.name = 'DropEnvelopeError';
  }
}

const keysAre = (object, names) =>
  object !== null && typeof object === 'object' && !Array.isArray(object) &&
  Object.keys(object).sort().join(',') === names.slice().sort().join(',');

function b64url(input, min, max) {
  if (typeof input !== 'string' || input.length < min || input.length > max ||
      !B64URL.test(input)) throw new DropEnvelopeError();
  const bytes = Buffer.from(input, 'base64url');
  if (bytes.toString('base64url') !== input) throw new DropEnvelopeError();
  return bytes;
}

/** AAD binds the encrypted file to the exact authenticated physical Attempt. */
export function dropAAD(attemptId, contractDigest) {
  if (typeof attemptId !== 'string' || !UUID.test(attemptId) ||
      typeof contractDigest !== 'string' || !DIGEST.test(contractDigest))
    throw new DropEnvelopeError();
  return Buffer.from(`drop-v1\n${attemptId.toLowerCase()}\n${contractDigest.toLowerCase()}`, 'utf8');
}

/** Never includes the original URL in returned errors, even on crypto failures. */
export function openDropEnvelope(parts, { privateKey, attemptId, contractDigest, now = Date.now() }) {
  try {
    if (!Array.isArray(parts) || parts.length !== 3 ||
        parts.some(part => typeof part !== 'string' || part.length > MAX_PART_BYTES) ||
        !Number.isSafeInteger(now)) throw new DropEnvelopeError();
    // Three fixed dispatch inputs. Only trailing empty parts are permitted.
    const present = parts.filter(part => part.length > 0);
    if (present.length === 0 || parts.slice(0, present.length).some(part => !part) ||
        parts.join('').length > MAX_ENVELOPE_BYTES)
      throw new DropEnvelopeError();
    const encoded = parts.join('');
    const envelope = JSON.parse(b64url(encoded, 32, MAX_ENVELOPE_BYTES).toString('utf8'));
    if (!keysAre(envelope, ['v', 'contract_digest', 'wrapped_key', 'nonce', 'ciphertext']) ||
        envelope.v !== 1 || !DIGEST.test(envelope.contract_digest) ||
        (contractDigest !== undefined && contractDigest.toLowerCase() !== envelope.contract_digest))
      throw new DropEnvelopeError();
    const aad = dropAAD(attemptId, envelope.contract_digest);
    const nonce = b64url(envelope.nonce, 16, 16);
    const cipher = b64url(envelope.ciphertext, 24, 10000);
    const wrapped = b64url(envelope.wrapped_key, 340, 800);
    if (nonce.length !== 12 || cipher.length < 17) throw new DropEnvelopeError();
    const key = privateDecrypt({
      key: privateKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    }, wrapped);
    if (key.length !== 32) throw new DropEnvelopeError();
    const decrypted = createDecipheriv('aes-256-gcm', key, nonce);
    decrypted.setAAD(aad);
    decrypted.setAuthTag(cipher.subarray(cipher.length - 16));
    const plaintext = Buffer.concat([
      decrypted.update(cipher.subarray(0, cipher.length - 16)),
      decrypted.final(),
    ]);
    const payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
    if (!keysAre(payload, ['attemptId', 'contractDigest', 'issuedAt', 'expiresAt', 'file']) ||
        payload.attemptId !== attemptId.toLowerCase() ||
        payload.contractDigest !== envelope.contract_digest ||
        !Number.isSafeInteger(payload.issuedAt) ||
        !Number.isSafeInteger(payload.expiresAt) ||
        payload.issuedAt > now + 60000 ||
        payload.expiresAt <= payload.issuedAt ||
        payload.expiresAt - payload.issuedAt > 3600000)
      throw new DropEnvelopeError();
    const file = payload.file;
    if (!file || typeof file !== 'object' || Array.isArray(file) ||
        Object.keys(file).some(k => !['file_id', 'download_url', 'file_name', 'mime_type'].includes(k)) ||
        typeof file.file_id !== 'string' || file.file_id.length < 1 || file.file_id.length > 512 ||
        typeof file.download_url !== 'string' || file.download_url.length < 1 ||
        file.download_url.length > 4096 ||
        typeof file.file_name !== 'string' || file.file_name.length < 1 ||
        file.file_name.length > 255 ||
        !/\.(html|zip)$/i.test(file.file_name) ||
        (file.mime_type !== undefined && typeof file.mime_type !== 'string'))
      throw new DropEnvelopeError();
    if (now >= payload.expiresAt) throw new DropEnvelopeError('drop_envelope_expired');
    // drop_static.py performs the final host, SAS, no-redirect and size checks.
    return file;
  } catch (error) {
    if (error instanceof DropEnvelopeError) throw error;
    throw new DropEnvelopeError();
  }
}
