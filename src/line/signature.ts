/**
 * Webhook authenticity.
 *
 * The webhook endpoint has to be reachable from the public internet for LINE
 * to call it, which means anyone else can call it too. This signature check is
 * the only thing standing between the store and forged messages, so it runs
 * before the body is parsed and before anything is written.
 */

import { createHmac } from 'node:crypto';

import { safeEqual } from '../privacy/crypto.js';

/**
 * Verifies the `x-line-signature` header.
 *
 * The HMAC must be computed over the exact bytes LINE sent. Parsing the JSON
 * and re-serialising it before hashing is the classic way to break this: key
 * order, whitespace and unicode escaping all change the bytes and the
 * signature stops matching — or worse, a lenient implementation starts
 * accepting bodies that differ from what was signed.
 */
export function verifySignature(
  rawBody: Buffer,
  signatureHeader: string | string[] | undefined,
  channelSecret: string,
): boolean {
  if (typeof signatureHeader !== 'string' || signatureHeader.length === 0) return false;
  if (channelSecret.length === 0) return false;

  const expected = createHmac('sha256', channelSecret).update(rawBody).digest('base64');
  return safeEqual(expected, signatureHeader);
}

/** Produces a valid signature. Used by the tests and the local replay tool. */
export function signBody(rawBody: Buffer, channelSecret: string): string {
  return createHmac('sha256', channelSecret).update(rawBody).digest('base64');
}
