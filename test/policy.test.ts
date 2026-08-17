import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { defaultPrivacyConfig } from '../src/config.js';
import {
  clampLimit,
  effectiveRetentionDays,
  evaluateCapture,
  isReadable,
} from '../src/privacy/policy.js';

const ALICE = 'U1111111111111111111111111111111a';
const BOB = 'U2222222222222222222222222222222b';

describe('evaluateCapture', () => {
  it('stores nothing by default', () => {
    // The single most important assertion in this file: a fresh install with
    // a live webhook records nobody until someone opts a conversation in.
    const decision = evaluateCapture(ALICE, defaultPrivacyConfig());
    assert.equal(decision.store, false);
    assert.match(decision.reason, /not on the allow list/);
  });

  it('stores an allow-listed conversation', () => {
    const config = defaultPrivacyConfig();
    config.capture.allow.push(ALICE);
    assert.equal(evaluateCapture(ALICE, config).store, true);
    assert.equal(evaluateCapture(BOB, config).store, false);
  });

  it('lets deny beat allow when both list the same conversation', () => {
    const config = defaultPrivacyConfig();
    config.capture.allow.push(ALICE);
    config.capture.deny.push(ALICE);
    const decision = evaluateCapture(ALICE, config);
    assert.equal(decision.store, false);
    assert.match(decision.reason, /deny list/);
  });

  it('stores everything undenied in allowByDefault mode', () => {
    const config = defaultPrivacyConfig();
    config.capture.mode = 'allowByDefault';
    config.capture.deny.push(BOB);
    assert.equal(evaluateCapture(ALICE, config).store, true);
    assert.equal(evaluateCapture(BOB, config).store, false);
  });

  it('stops everything when the kill switch is off, including allow-listed threads', () => {
    const config = defaultPrivacyConfig();
    config.capture.mode = 'allowByDefault';
    config.capture.allow.push(ALICE);
    config.capture.enabled = false;
    const decision = evaluateCapture(ALICE, config);
    assert.equal(decision.store, false);
    assert.match(decision.reason, /kill switch/);
  });

  it('passes the configured text mode through to the caller', () => {
    const config = defaultPrivacyConfig();
    config.capture.allow.push(ALICE);
    assert.equal(evaluateCapture(ALICE, config).storeText, 'redacted');
    config.capture.storeText = 'none';
    assert.equal(evaluateCapture(ALICE, config).storeText, 'none');
  });
});

describe('isReadable', () => {
  it('exposes every captured conversation when readable is null', () => {
    assert.equal(isReadable(ALICE, defaultPrivacyConfig()), true);
  });

  it('narrows the model to an explicit list without affecting capture', () => {
    const config = defaultPrivacyConfig();
    config.mcp.readable = [ALICE];
    assert.equal(isReadable(ALICE, config), true);
    assert.equal(isReadable(BOB, config), false);
  });

  it('hides everything when readable is an empty list', () => {
    const config = defaultPrivacyConfig();
    config.mcp.readable = [];
    assert.equal(isReadable(ALICE, config), false);
  });
});

describe('clampLimit', () => {
  it('caps a request above the ceiling', () => {
    const config = defaultPrivacyConfig();
    config.mcp.maxMessagesPerCall = 100;
    assert.equal(clampLimit(5000, config), 100);
  });

  it('honours a smaller request', () => {
    assert.equal(clampLimit(10, defaultPrivacyConfig()), 10);
  });

  it('falls back to a modest default when unspecified', () => {
    assert.equal(clampLimit(undefined, defaultPrivacyConfig()), 50);
  });

  it('rejects zero, negatives and non-finite values', () => {
    const config = defaultPrivacyConfig();
    assert.equal(clampLimit(0, config), 1);
    assert.equal(clampLimit(-5, config), 1);
    assert.equal(clampLimit(Number.NaN, config), 50);
  });
});

describe('effectiveRetentionDays', () => {
  it('uses the global setting by default', () => {
    const config = defaultPrivacyConfig();
    assert.equal(effectiveRetentionDays(ALICE, config), 30);
  });

  it('lets a per-conversation override win, including a stricter zero-day case', () => {
    const config = defaultPrivacyConfig();
    config.retention.perConversationDays[ALICE] = 7;
    assert.equal(effectiveRetentionDays(ALICE, config), 7);
    assert.equal(effectiveRetentionDays(BOB, config), 30);
  });
});
