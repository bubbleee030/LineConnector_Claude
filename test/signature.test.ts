import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { signBody, verifySignature } from '../src/line/signature.js';

const SECRET = 'test-channel-secret';
const body = Buffer.from(JSON.stringify({ destination: 'U1', events: [] }), 'utf8');

describe('verifySignature', () => {
  it('accepts a correctly signed body', () => {
    assert.equal(verifySignature(body, signBody(body, SECRET), SECRET), true);
  });

  it('rejects a body that was altered after signing', () => {
    const signature = signBody(body, SECRET);
    const tampered = Buffer.from(JSON.stringify({ destination: 'U1', events: [{ type: 'message' }] }));
    assert.equal(verifySignature(tampered, signature, SECRET), false);
  });

  it('rejects a signature made with a different secret', () => {
    assert.equal(verifySignature(body, signBody(body, 'other-secret'), SECRET), false);
  });

  it('rejects a missing or malformed header', () => {
    assert.equal(verifySignature(body, undefined, SECRET), false);
    assert.equal(verifySignature(body, '', SECRET), false);
    assert.equal(verifySignature(body, 'not-base64!!', SECRET), false);
    // Node gives array-valued headers when one is sent twice.
    assert.equal(verifySignature(body, ['a', 'b'], SECRET), false);
  });

  it('rejects everything when no channel secret is configured', () => {
    // Guards against an empty env var turning the endpoint into an open door.
    assert.equal(verifySignature(body, signBody(body, ''), ''), false);
  });

  it('is sensitive to byte-level differences, not just parsed equality', () => {
    // The same JSON re-serialised with different key order must not verify.
    // This is the failure mode that appears when an implementation hashes a
    // re-encoded body rather than the bytes that arrived.
    const reordered = Buffer.from(JSON.stringify({ events: [], destination: 'U1' }), 'utf8');
    assert.equal(verifySignature(reordered, signBody(body, SECRET), SECRET), false);
  });
});
