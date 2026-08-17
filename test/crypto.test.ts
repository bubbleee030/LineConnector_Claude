import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { describe, it } from 'node:test';

import {
  decryptField,
  encryptField,
  generateKeyHex,
  pseudonymise,
  safeEqual,
} from '../src/privacy/crypto.js';

const key = randomBytes(32);

describe('field encryption', () => {
  it('round-trips text, including unicode', () => {
    for (const text of ['hello', '今晚七點可以嗎', '🙂 emoji', '']) {
      assert.equal(decryptField(encryptField(text, key), key), text);
    }
  });

  it('produces different ciphertext for the same plaintext', () => {
    // A fresh IV per call. If this ever fails, GCM's security guarantee is
    // broken and identical messages become linkable in the database.
    const a = encryptField('same message', key);
    const b = encryptField('same message', key);
    assert.notEqual(a, b);
  });

  it('detects tampering with the ciphertext', () => {
    const payload = encryptField('transfer approved', key);
    const parts = payload.split('.');
    const ciphertext = Buffer.from(parts[3] as string, 'base64');
    ciphertext.writeUInt8(ciphertext.readUInt8(0) ^ 0xff, 0);
    parts[3] = ciphertext.toString('base64');

    assert.throws(() => decryptField(parts.join('.'), key));
  });

  it('refuses a ciphertext encrypted under a different key', () => {
    const payload = encryptField('secret', key);
    assert.throws(() => decryptField(payload, randomBytes(32)));
  });

  it('rejects malformed payloads instead of returning garbage', () => {
    assert.throws(() => decryptField('nonsense', key), /Malformed/);
    assert.throws(() => decryptField('v9.a.b.c', key), /Unsupported ciphertext version/);
  });
});

describe('pseudonymise', () => {
  it('is stable for the same id and key', () => {
    const id = 'U1234567890abcdef1234567890abcdef';
    assert.equal(pseudonymise(id, key), pseudonymise(id, key));
  });

  it('differs between ids', () => {
    assert.notEqual(
      pseudonymise('U1111111111111111111111111111111a', key),
      pseudonymise('U2222222222222222222222222222222b', key),
    );
  });

  it('differs between installs, so pseudonyms cannot be correlated across them', () => {
    const id = 'U1234567890abcdef1234567890abcdef';
    assert.notEqual(pseudonymise(id, key), pseudonymise(id, randomBytes(32)));
  });

  it('does not leak the underlying id', () => {
    const id = 'U1234567890abcdef1234567890abcdef';
    assert.equal(pseudonymise(id, key).includes(id.slice(1, 10)), false);
  });
});

describe('generateKeyHex', () => {
  it('produces a 32-byte key in hex', () => {
    const hex = generateKeyHex();
    assert.match(hex, /^[0-9a-f]{64}$/);
    assert.notEqual(hex, generateKeyHex());
  });
});

describe('safeEqual', () => {
  it('compares equal and unequal strings correctly', () => {
    assert.equal(safeEqual('abc', 'abc'), true);
    assert.equal(safeEqual('abc', 'abd'), false);
    assert.equal(safeEqual('abc', 'abcd'), false);
    assert.equal(safeEqual('', ''), true);
  });
});
