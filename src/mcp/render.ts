/**
 * Rendering stored rows into text for the model.
 *
 * This is the last place data passes through before it leaves the process, so
 * it is also the last place a privacy control can be applied. Two things
 * happen here that are not merely cosmetic: identifiers are replaced with
 * pseudonyms unless the policy says otherwise, and output is truncated to the
 * configured character budget so a single call cannot drain the archive.
 */

import type { PrivacyConfig } from '../config.js';
import type { ConversationRow, MessageRow } from '../db/index.js';
import { describeNonTextMessage } from '../line/normalize.js';

/** ISO 8601 in UTC — unambiguous, unlike a locale-formatted local time. */
export function formatTimestamp(ms: number): string {
  // Second precision: milliseconds add noise to a transcript without telling
  // the reader anything they can use.
  return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z');
}

export function renderConversationList(
  conversations: readonly ConversationRow[],
  config: PrivacyConfig,
): string {
  if (conversations.length === 0) {
    return 'No conversations are available.\n\nEither nothing has been captured yet, or no conversation is allow-listed. Captured conversations appear here only after someone messages the Official Account while the ingest server is running.';
  }

  const lines = conversations.map((c) => {
    const handle = config.mcp.exposeSenderIds ? c.lineId : c.pseudonym;
    const name = c.displayName !== null ? ` "${c.displayName}"` : '';
    const last = c.lastMessageAt === null ? 'never' : formatTimestamp(c.lastMessageAt);
    return `- ${handle}${name} (${c.sourceType}) — ${c.messageCount} message(s), last activity ${last}`;
  });

  return `${conversations.length} conversation(s):\n${lines.join('\n')}`;
}

export interface TranscriptOptions {
  conversation?: ConversationRow | null;
  /** Prefixes each line with its conversation, for cross-thread results. */
  showConversation?: boolean;
}

/**
 * Renders messages as a chronological transcript.
 *
 * Input is expected newest-first (the order the store returns); output is
 * oldest-first, because a conversation only reads correctly forwards.
 */
export function renderTranscript(
  messages: readonly MessageRow[],
  config: PrivacyConfig,
  options: TranscriptOptions = {},
): string {
  if (messages.length === 0) return 'No messages matched.';

  const chronological = [...messages].reverse();
  const budget = config.mcp.maxCharsPerCall;

  const lines: string[] = [];
  let used = 0;
  let truncatedAt = -1;

  for (let i = 0; i < chronological.length; i++) {
    const line = renderMessage(chronological[i] as MessageRow, config, options);
    if (used + line.length > budget) {
      truncatedAt = i;
      break;
    }
    lines.push(line);
    used += line.length + 1;
  }

  const parts = [lines.join('\n')];

  if (truncatedAt >= 0) {
    parts.push(
      `\n[output truncated at the ${budget} character limit: ${
        chronological.length - truncatedAt
      } more message(s) matched but were not included. Narrow the time range or lower the limit to see them.]`,
    );
  }

  const redacted = messages.filter((m) => m.redactions.length > 0).length;
  if (redacted > 0) {
    const kinds = [...new Set(messages.flatMap((m) => m.redactions))].sort().join(', ');
    parts.push(`\n[${redacted} message(s) had content removed before storage. Rules: ${kinds}]`);
  }

  return parts.join('\n');
}

function renderMessage(
  message: MessageRow,
  config: PrivacyConfig,
  options: TranscriptOptions,
): string {
  const when = formatTimestamp(message.timestamp);
  const who = senderLabel(message, config, options.conversation ?? null);
  const prefix = options.showConversation === true ? `{${message.conversationPseudonym}} ` : '';
  return `[${when}] ${prefix}${who}: ${bodyOf(message)}`;
}

function senderLabel(
  message: MessageRow,
  config: PrivacyConfig,
  conversation: ConversationRow | null,
): string {
  if (message.direction === 'outbound') return 'you (Official Account)';

  if (config.mcp.exposeSenderIds && message.senderLineId !== null) return message.senderLineId;

  // In a 1:1 chat the conversation's display name is the sender's name, so use
  // it when it was captured. In groups it would be wrong, since many people
  // share one conversation.
  if (conversation?.sourceType === 'user' && conversation.displayName !== null) {
    return conversation.displayName;
  }

  return message.senderPseudonym ?? 'unknown sender';
}

/**
 * Produces the body text.
 *
 * Non-text messages carry no stored body by design; their placeholder is
 * derived from metadata here rather than being written to the database, so
 * there is one source of truth for how an image or sticker is described.
 */
function bodyOf(message: MessageRow): string {
  if (message.type !== 'text') {
    return describeNonTextMessage(message.type, message.meta);
  }
  if (message.text === null) {
    return '[text not stored: capture.storeText is set to "none"]';
  }
  return message.text;
}

/** A compact summary of the policy currently in force. */
export function renderPrivacyStatus(
  config: PrivacyConfig,
  stats: {
    conversations: number;
    messages: number;
    oldestMessage: number | null;
    sendEnabled: boolean;
    readableCount: number;
  },
): string {
  const { capture, retention, mcp, audit } = config;

  const captureScope =
    capture.mode === 'denyByDefault'
      ? `allow list only (${capture.allow.length} conversation(s))`
      : `everything except the deny list (${capture.deny.length} denied)`;

  return [
    '# LINE connector privacy status',
    '',
    '## What is being recorded',
    `- Capture: ${capture.enabled ? 'enabled' : 'DISABLED (kill switch is on)'}`,
    `- Scope: ${captureScope}`,
    `- Message text: ${describeStoreText(capture.storeText)}`,
    `- Media files: ${capture.storeMedia ? 'downloaded and encrypted at rest' : 'not downloaded'}`,
    `- Shared locations: ${describeLocation(capture.storeLocation)}`,
    `- File names: ${capture.storeFileNames ? 'stored' : 'dropped, extension kept'}`,
    `- Display names: ${capture.resolveDisplayNames ? 'looked up and stored' : 'not looked up'}`,
    '',
    '## What I can see',
    `- Readable conversations: ${stats.readableCount} of ${stats.conversations} captured`,
    `- Sender identifiers: ${mcp.exposeSenderIds ? 'real LINE user ids' : 'pseudonyms only'}`,
    `- Per-call ceiling: ${mcp.maxMessagesPerCall} messages, ${mcp.maxCharsPerCall} characters`,
    `- Sending messages: ${stats.sendEnabled ? 'ENABLED' : 'disabled'}`,
    '',
    '## How long it is kept',
    `- Retention: ${retention.days === 0 ? 'indefinite' : `${retention.days} days`}`,
    `- Sweeper interval: every ${retention.sweepIntervalMinutes} minute(s)`,
    `- Per-conversation overrides: ${Object.keys(retention.perConversationDays).length}`,
    '',
    '## Current contents',
    `- Stored messages: ${stats.messages}`,
    `- Oldest message: ${stats.oldestMessage === null ? 'none' : formatTimestamp(stats.oldestMessage)}`,
    `- Access auditing: ${audit.enabled ? `on, kept ${audit.retentionDays} days` : 'OFF'}`,
    '',
    'Everything above is set in the privacy config file and can only be changed by the operator, not from this session.',
  ].join('\n');
}

function describeStoreText(mode: 'full' | 'redacted' | 'none'): string {
  switch (mode) {
    case 'full':
      return 'stored verbatim, NO redaction';
    case 'redacted':
      return 'redacted before storage (cards, ids, emails, phones, secrets removed)';
    case 'none':
      return 'not stored at all, metadata only';
  }
}

function describeLocation(mode: 'none' | 'coarse' | 'precise'): string {
  switch (mode) {
    case 'none':
      return 'not stored, only that a location was shared';
    case 'coarse':
      return 'rounded to ~1km';
    case 'precise':
      return 'stored exactly as sent';
  }
}
