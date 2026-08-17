/**
 * Field-level encryption and pseudonymisation.
 *
 * Message bodies are encrypted with AES-256-GCM before they are written to
 * SQLite, so the database file on disk is not readable by anything that gets
 * hold of it without also holding the key. GCM is authenticated, so tampering
 * with the ciphertext is detected on read rather than silently returning
 * garbage.
 *
 * The tradeoff this buys and costs: an encrypted body cannot be indexed for
 * full-text search. Search is therefore a bounded decrypt-and-scan (see
 * src/db/index.ts). At personal-archive scale that is fine, and it keeps a
 * plaintext search index from existing on disk, which would have undone the
 * encryption anyway.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12; // 96-bit nonce, the size GCM is specified for
const TAG_BYTES = 16;
const VERSION = 'v1';

/** Generates a fresh 32-byte key, hex-encoded for use in the environment. */
export function generateKeyHex(): string {
  return randomBytes(32).toString('hex');
}

/**
 * Encrypts a UTF-8 string.
 *
 * A fresh random IV per call is what makes it safe to encrypt the same message
 * text twice; GCM catastrophically leaks plaintext if an IV is ever reused
 * under the same key, so this must never be made deterministic.
 */
export function encryptField(plaintext: string, key: Buffer): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, b64(iv), b64(tag), b64(ciphertext)].join('.');
}

/** Reverses {@link encryptField}. Throws if the payload was altered. */
export function decryptField(payload: string, key: Buffer): string {
  const parts = payload.split('.');
  if (parts.length !== 4) {
    throw new Error('Malformed ciphertext: expected 4 dot-separated segments');
  }
  const [version, ivB64, tagB64, ctB64] = parts as [string, string, string, string];
  if (version !== VERSION) {
    throw new Error(`Unsupported ciphertext version ${JSON.stringify(version)}`);
  }

  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
    throw new Error('Malformed ciphertext: bad IV or tag length');
  }

  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([
    decipher.update(Buffer.from(ctB64, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

/**
 * Maps a real LINE id to a stable pseudonym such as `user_3f9a2c1b`.
 *
 * Used whenever `mcp.exposeSenderIds` is false, so the model can tell two
 * participants apart across a conversation without ever receiving an
 * identifier that could be used to contact or correlate them elsewhere.
 *
 * Keyed with the install's own encryption key, so the mapping is not
 * reproducible by anyone who merely knows a userId, and differs per install.
 */
export function pseudonymise(lineId: string, key: Buffer): string {
  const digest = createHmac('sha256', key).update(`pseudonym:${lineId}`).digest('hex');
  return `user_${digest.slice(0, 12)}`;
}

/**
 * Constant-time string comparison, for anything an attacker can retry against.
 *
 * Node's timingSafeEqual throws on length mismatch, which would itself leak
 * length, so lengths are compared through the same fixed-width path.
 */
export function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    // Still burn a comparison so the timing profile does not depend on length.
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}

function b64(buf: Buffer): string {
  return buf.toString('base64');
}
