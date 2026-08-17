/**
 * Consent and access decisions.
 *
 * Two separate gates, deliberately not merged:
 *
 *   1. Capture  - may this conversation be written to disk at all?
 *   2. Read     - may the model see a conversation that was captured?
 *
 * Keeping them apart means you can stop exposing a thread to Claude without
 * losing the record, and you can keep a record for yourself that the model is
 * never shown. Collapsing them into one list would force those two very
 * different intentions to share a switch.
 */

import type { PrivacyConfig } from '../config.js';

export interface CaptureDecision {
  store: boolean;
  /** How much of the message body may be persisted. */
  storeText: 'full' | 'redacted' | 'none';
  /** Human-readable explanation, surfaced in logs and in `privacy_status`. */
  reason: string;
}

/**
 * Decides whether an inbound conversation may be recorded.
 *
 * A LINE Official Account webhook receives every message anyone sends it,
 * including from people who found it by accident. Defaulting to deny means
 * that traffic passes through and is dropped rather than accumulating.
 */
export function evaluateCapture(conversationId: string, config: PrivacyConfig): CaptureDecision {
  const { capture } = config;

  if (!capture.enabled) {
    return { store: false, storeText: 'none', reason: 'capture disabled (kill switch)' };
  }

  // Deny always wins over allow, so an entry in `deny` cannot be defeated by
  // also appearing in `allow`, whichever order they were added in.
  if (capture.deny.includes(conversationId)) {
    return { store: false, storeText: 'none', reason: 'conversation is on the deny list' };
  }

  if (capture.mode === 'denyByDefault' && !capture.allow.includes(conversationId)) {
    return {
      store: false,
      storeText: 'none',
      reason: 'conversation is not on the allow list (mode: denyByDefault)',
    };
  }

  return {
    store: true,
    storeText: capture.storeText,
    reason:
      capture.mode === 'denyByDefault'
        ? 'conversation is on the allow list'
        : 'capture mode is allowByDefault and conversation is not denied',
  };
}

/**
 * Decides whether the model may read a captured conversation.
 *
 * `mcp.readable === null` means "anything that was captured". Setting it to an
 * explicit array narrows the model's view without changing what is recorded.
 */
export function isReadable(conversationId: string, config: PrivacyConfig): boolean {
  const { readable } = config.mcp;
  if (readable === null) return true;
  return readable.includes(conversationId);
}

/** Filters a list of conversation ids down to the ones the model may read. */
export function filterReadable(ids: readonly string[], config: PrivacyConfig): string[] {
  return ids.filter((id) => isReadable(id, config));
}

/**
 * Retention for a specific conversation, falling back to the global setting.
 * Returns 0 when messages should be kept indefinitely.
 */
export function effectiveRetentionDays(conversationId: string, config: PrivacyConfig): number {
  const override = config.retention.perConversationDays[conversationId];
  return override ?? config.retention.days;
}

/**
 * Clamps a caller-supplied result limit to the configured ceiling.
 * The model can ask for less than the cap but never for more, which is what
 * stops a single tool call from draining the whole archive.
 */
export function clampLimit(requested: number | undefined, config: PrivacyConfig): number {
  const max = config.mcp.maxMessagesPerCall;
  if (requested === undefined || !Number.isFinite(requested)) return Math.min(50, max);
  return Math.max(1, Math.min(Math.floor(requested), max));
}
