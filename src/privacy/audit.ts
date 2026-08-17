/**
 * Audit logging for model-initiated access.
 *
 * The privacy guarantee this project offers is not "Claude cannot see your
 * messages" — it is "Claude sees exactly what you allowed, and you can check
 * afterwards what it actually looked at". The second half only holds if every
 * read is recorded, so auditing lives in the tool dispatch path rather than
 * being something individual tools opt into.
 *
 * What is recorded is deliberately thin: which tool ran, which conversation it
 * touched, how many rows came back. Recording the query text would put the
 * user's search terms — themselves revealing — into a second store with a
 * different retention policy.
 */

import type { PrivacyConfig } from '../config.js';
import type { Store } from '../db/index.js';

export type Actor = 'mcp' | 'cli' | 'ingest';

export interface AuditInput {
  actor: Actor;
  action: string;
  conversationKey?: string | null;
  /** Short, non-sensitive summary. Never message content or search terms. */
  detail?: string;
  resultCount?: number | null;
}

export function audit(store: Store, config: PrivacyConfig, entry: AuditInput): void {
  if (!config.audit.enabled) return;
  try {
    store.recordAudit({
      actor: entry.actor,
      action: entry.action,
      conversationId: entry.conversationKey ?? null,
      detail: entry.detail ?? '',
      resultCount: entry.resultCount ?? null,
    });
  } catch (err) {
    // Losing an audit row must not fail the operation the user asked for, but
    // it should be visible rather than swallowed.
    console.error('[audit] failed to record entry:', (err as Error).message);
  }
}

/**
 * Builds a detail string that is safe to persist.
 *
 * Values are described by shape rather than content, so an audit trail can
 * never become a second copy of the data it is auditing.
 */
export function describeParams(params: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (typeof value === 'number' || typeof value === 'boolean') {
      parts.push(`${key}=${value}`);
    } else if (typeof value === 'string') {
      parts.push(`${key}=<${value.length} chars>`);
    } else if (Array.isArray(value)) {
      parts.push(`${key}=<${value.length} items>`);
    } else {
      parts.push(`${key}=<object>`);
    }
  }
  return parts.join(' ');
}
