/**
 * Imports a parsed LINE chat export into the encrypted store.
 *
 * Imported messages go through the same privacy pipeline as webhook traffic —
 * redaction, then encryption, then storage — so a personal chat is protected
 * exactly as an Official Account's inbox is.
 *
 * One deliberate difference: importing bypasses the capture allow list. That
 * list exists to stop a webhook silently recording strangers who message an
 * account. An import is the opposite situation: a person pointing at one file
 * and asking for it specifically. Requiring a second opt-in for data they just
 * chose by hand would be friction without a safety benefit.
 *
 * Sender names are never stored in the clear. They are hashed for lookups and
 * encrypted for recovery, the same treatment LINE user ids get, so the export's
 * plaintext names do not survive into the database.
 */

import type { PrivacyConfig } from '../config.js';
import type { Store } from '../db/index.js';
import { redact } from '../privacy/redact.js';
import type { SourceType } from '../types.js';
import {
  importedConversationId,
  importedMessageId,
  type ParsedExport,
  type ParsedMessage,
} from './lineExport.js';

/** Labels LINE uses for the exporting user across its supported languages. */
const DEFAULT_SELF_LABELS = ['me', 'you', '自分', '私', '我', '자신', '나'];

export interface ImportOptions {
  /** Extra names to treat as the exporting user. Case-insensitive. */
  selfLabels?: readonly string[];
  /** Overrides the title from the file, for exports with no readable header. */
  title?: string;
}

export interface ImportResult {
  conversationId: string;
  title: string;
  sourceType: SourceType;
  imported: number;
  duplicates: number;
  /** Lines the parser could not interpret. */
  skipped: number;
  /** How many stored messages had something removed. */
  redacted: number;
  /** Distinct sender names seen, so the caller can report them. */
  senders: string[];
  earliest: number | null;
  latest: number | null;
}

export function importExport(
  store: Store,
  config: PrivacyConfig,
  parsed: ParsedExport,
  options: ImportOptions = {},
): ImportResult {
  const title = options.title ?? parsed.title ?? 'Imported chat';
  const conversationId = importedConversationId(title);

  const selfLabels = new Set(
    [...DEFAULT_SELF_LABELS, ...(options.selfLabels ?? [])].map((s) => s.toLowerCase()),
  );

  const senders = [
    ...new Set(parsed.messages.map((m) => m.sender).filter((s): s is string => s !== null)),
  ];

  // More than two participants means it cannot be a 1:1 chat. Two or fewer is
  // ambiguous but overwhelmingly a direct conversation.
  const sourceType: SourceType = senders.length > 2 ? 'group' : 'user';

  const now = Date.now();
  store.upsertConversation(conversationId, sourceType, now);

  let imported = 0;
  let duplicates = 0;
  let redactedCount = 0;
  let earliest: number | null = null;
  let latest: number | null = null;

  for (const message of parsed.messages) {
    const { text, redactions } = applyTextPolicy(message, config);
    if (redactions.length > 0 && text !== null) redactedCount++;

    const isSelf = message.sender !== null && selfLabels.has(message.sender.toLowerCase());

    const inserted = store.insertMessage({
      message: {
        id: importedMessageId(conversationId, message),
        conversationId,
        sourceType,
        // The display name stands in for a LINE id here: it is hashed for
        // lookups and encrypted at rest, never written in the clear.
        senderId: message.sender,
        direction: isSelf ? 'outbound' : 'inbound',
        type: message.type,
        text,
        timestamp: message.timestamp,
        isRedelivery: false,
        meta: { source: 'export' },
      },
      text,
      redactions,
      originalTextLength: message.text.length,
    });

    if (inserted) {
      imported++;
      if (earliest === null || message.timestamp < earliest) earliest = message.timestamp;
      if (latest === null || message.timestamp > latest) latest = message.timestamp;
    } else {
      duplicates++;
    }
  }

  return {
    conversationId,
    title,
    sourceType,
    imported,
    duplicates,
    skipped: parsed.skipped,
    redacted: redactedCount,
    senders,
    earliest,
    latest,
  };
}

/**
 * Applies `capture.storeText` to an imported message.
 *
 * Non-text messages carry only a placeholder such as `[Photo]`, which is
 * LINE's own wording rather than anything the sender wrote, so it is dropped
 * and re-derived at read time like every other non-text message.
 */
function applyTextPolicy(
  message: ParsedMessage,
  config: PrivacyConfig,
): { text: string | null; redactions: string[] } {
  if (message.type !== 'text') return { text: null, redactions: [] };

  switch (config.capture.storeText) {
    case 'none':
      return { text: null, redactions: ['storeText:none'] };
    case 'full':
      return { text: message.text, redactions: [] };
    case 'redacted': {
      const result = redact(message.text, config);
      return { text: result.text, redactions: result.applied };
    }
  }
}
