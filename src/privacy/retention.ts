/**
 * Retention sweeping.
 *
 * Data you no longer hold cannot leak, be subpoenaed, or be read by a future
 * bug. Retention is therefore the single most effective control in this
 * project, and it runs on a timer rather than on demand so that forgetting is
 * the default behaviour and not something anyone has to remember to do.
 */

import type { PrivacyConfig } from '../config.js';
import type { Store } from '../db/index.js';

const DAY_MS = 86_400_000;

export interface SweepResult {
  messagesDeleted: number;
  conversationsRemoved: number;
  auditEntriesDeleted: number;
  sweptAt: number;
}

/**
 * Deletes everything past its retention window.
 *
 * A per-conversation setting of 0 means "keep indefinitely", which is why the
 * check is `days <= 0` rather than falsy — it has to be a deliberate choice,
 * not the result of an unset field.
 */
export function sweepRetention(store: Store, config: PrivacyConfig, now = Date.now()): SweepResult {
  // Config is keyed by real LINE id; the store is keyed by HMAC. Translate the
  // overrides once rather than per conversation.
  const overrides = new Map<string, number>();
  for (const [lineId, days] of Object.entries(config.retention.perConversationDays)) {
    overrides.set(store.keyFor(lineId), days);
  }

  let messagesDeleted = 0;
  for (const conversationKey of store.listConversationKeys()) {
    const days = overrides.get(conversationKey) ?? config.retention.days;
    if (days <= 0) continue;
    messagesDeleted += store.purgeConversationBefore(conversationKey, now - days * DAY_MS);
  }

  const conversationsRemoved = store.pruneEmptyConversations();
  const auditEntriesDeleted = store.purgeAuditBefore(now - config.audit.retentionDays * DAY_MS);

  // Deleted rows leave their contents in free pages until the file is
  // rewritten, so without this the text would still be recoverable from disk.
  if (messagesDeleted > 0 || auditEntriesDeleted > 0) {
    store.vacuum();
  }

  return { messagesDeleted, conversationsRemoved, auditEntriesDeleted, sweptAt: now };
}

/**
 * Runs {@link sweepRetention} immediately and then on the configured interval.
 * Returns a function that stops the timer.
 */
export function startRetentionSweeper(
  store: Store,
  config: PrivacyConfig,
  onSweep?: (result: SweepResult) => void,
): () => void {
  const run = (): void => {
    try {
      const result = sweepRetention(store, config);
      onSweep?.(result);
    } catch (err) {
      // A failed sweep must not take the ingest server down with it; the next
      // tick will try again.
      console.error('[retention] sweep failed:', (err as Error).message);
    }
  };

  run();
  const timer = setInterval(run, config.retention.sweepIntervalMinutes * 60_000);
  timer.unref();
  return () => clearInterval(timer);
}
