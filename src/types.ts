/**
 * Shared domain types.
 *
 * Naming follows the LINE Messaging API where it maps cleanly, so that anyone
 * cross-referencing the LINE docs can follow along.
 */

/** Where a message came from. LINE calls these "source types". */
export type SourceType = 'user' | 'group' | 'room';

/** LINE message types we know how to normalize. */
export type MessageType =
  | 'text'
  | 'image'
  | 'video'
  | 'audio'
  | 'file'
  | 'location'
  | 'sticker'
  | 'unknown';

/** Direction relative to the Official Account that owns this connector. */
export type Direction = 'inbound' | 'outbound';

/**
 * A conversation is a stable addressable thread: a 1:1 chat with a user, a
 * group, or a multi-person room. `id` is the LINE-issued userId/groupId/roomId.
 */
export interface Conversation {
  id: string;
  sourceType: SourceType;
  /** Display name, only populated when profile lookup is enabled. */
  displayName: string | null;
  firstSeenAt: number;
  lastMessageAt: number | null;
  messageCount: number;
}

/**
 * A normalized message, before the privacy pipeline has run on it.
 * `text` is still raw at this point and must never be persisted as-is unless
 * the policy explicitly allows `storeText: "full"`.
 */
export interface NormalizedMessage {
  /** LINE message id. Unique per message; used for idempotent ingest. */
  id: string;
  conversationId: string;
  sourceType: SourceType;
  /** LINE userId of the sender. Null for events with no attributable sender. */
  senderId: string | null;
  direction: Direction;
  type: MessageType;
  /** Raw text content, if the message carries any. */
  text: string | null;
  /** Timestamp in epoch milliseconds, as supplied by LINE. */
  timestamp: number;
  /** True when LINE re-delivered an event we may already have stored. */
  isRedelivery: boolean;
  /**
   * Type-specific metadata that is safe to keep even when text is dropped:
   * sticker ids, file names, media durations, coarse location labels.
   */
  meta: Record<string, unknown>;
}

/** A message as it exists on disk and as returned to callers. */
export interface StoredMessage {
  id: string;
  conversationId: string;
  senderId: string | null;
  direction: Direction;
  type: MessageType;
  /** Decrypted, already-redacted text. Null when policy stored no text. */
  text: string | null;
  timestamp: number;
  meta: Record<string, unknown>;
  /** Which redaction rules fired on this message, for transparency. */
  redactions: string[];
}

/** Result of running the redaction engine over a string. */
export interface RedactionResult {
  text: string;
  /** Names of the rules that matched, deduplicated and stable-sorted. */
  applied: string[];
}
