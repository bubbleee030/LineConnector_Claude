/**
 * The local store.
 *
 * Built on node:sqlite (Node 22.5+) rather than a native SQLite binding, so
 * the project ships with two runtime dependencies and no compiled add-ons.
 * For something that holds other people's private messages, a small and
 * auditable dependency tree is a feature, not an aesthetic preference.
 *
 * Identifier handling is the notable part of the schema. No plaintext LINE id
 * is ever written to disk. Each id is stored twice:
 *
 *   - as a keyed HMAC, used as the primary key and for all lookups, so rows
 *     can be found without the database knowing who they belong to;
 *   - as an AES-GCM ciphertext, so the real id can be recovered when it is
 *     genuinely needed (sending a reply, or an operator listing their own
 *     conversations).
 *
 * Someone who steals the database file without the key learns how many people
 * wrote and when, and nothing else.
 */

import { chmodSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createHmac } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

import { decryptField, encryptField, pseudonymise } from '../privacy/crypto.js';
import type { Direction, MessageType, NormalizedMessage, SourceType } from '../types.js';

const SCHEMA_VERSION = 1;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS conversations (
  id              TEXT PRIMARY KEY,       -- HMAC of the LINE id
  line_id_enc     TEXT NOT NULL,          -- encrypted real LINE id
  pseudonym       TEXT NOT NULL,          -- stable handle shown to the model
  source_type     TEXT NOT NULL,
  display_name_enc TEXT,                  -- encrypted, only if policy allows
  first_seen_at   INTEGER NOT NULL,
  last_message_at INTEGER
);

CREATE TABLE IF NOT EXISTS messages (
  id              TEXT PRIMARY KEY,       -- HMAC of the LINE message id
  conversation_id TEXT NOT NULL,
  sender_key      TEXT,                   -- HMAC of the sender's LINE id
  sender_id_enc   TEXT,                   -- encrypted sender LINE id
  sender_pseudonym TEXT,
  direction       TEXT NOT NULL,
  type            TEXT NOT NULL,
  text_enc        TEXT,                   -- encrypted, already-redacted body
  text_len        INTEGER NOT NULL DEFAULT 0,
  timestamp       INTEGER NOT NULL,
  meta_json       TEXT NOT NULL DEFAULT '{}',
  redactions      TEXT NOT NULL DEFAULT '',
  created_at      INTEGER NOT NULL,
  FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_conv_ts ON messages(conversation_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_messages_ts      ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_sender  ON messages(sender_key);

CREATE TABLE IF NOT EXISTS audit_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  ts              INTEGER NOT NULL,
  actor           TEXT NOT NULL,
  action          TEXT NOT NULL,
  conversation_id TEXT,
  detail          TEXT NOT NULL DEFAULT '',
  result_count    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
`;

export interface ConversationRow {
  id: string;
  lineId: string;
  pseudonym: string;
  sourceType: SourceType;
  displayName: string | null;
  firstSeenAt: number;
  lastMessageAt: number | null;
  messageCount: number;
}

export interface MessageRow {
  id: string;
  conversationId: string;
  conversationPseudonym: string;
  senderPseudonym: string | null;
  senderLineId: string | null;
  direction: Direction;
  type: MessageType;
  text: string | null;
  timestamp: number;
  meta: Record<string, unknown>;
  redactions: string[];
}

export interface InsertMessageInput {
  message: NormalizedMessage;
  /** Already redacted per policy; null when the policy stores no body. */
  text: string | null;
  redactions: string[];
  /** Original body length, kept even when the body itself is not stored. */
  originalTextLength: number;
}

export interface MessageQuery {
  conversationId?: string;
  since?: number;
  until?: number;
  limit: number;
  /** Restricts results to these internal conversation keys. */
  restrictTo?: readonly string[];
}

export class Store {
  private readonly db: DatabaseSync;
  private readonly key: Buffer;

  constructor(path: string, key: Buffer) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(path);
    this.key = key;

    // WAL lets the MCP server read while the ingest server writes.
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA foreign_keys = ON');
    this.db.exec('PRAGMA synchronous = NORMAL');
    this.db.exec(SCHEMA);
    this.migrate();

    // The file holds private messages; keep it owner-only. Best effort, since
    // some filesystems (and Windows) will not honour this.
    try {
      chmodSync(path, 0o600);
    } catch {
      /* not fatal */
    }
  }

  private migrate(): void {
    const row = this.db.prepare('SELECT value FROM meta WHERE key = ?').get('schema_version') as
      | { value: string }
      | undefined;

    if (row === undefined) {
      this.db
        .prepare('INSERT INTO meta (key, value) VALUES (?, ?)')
        .run('schema_version', String(SCHEMA_VERSION));
      return;
    }

    const found = Number.parseInt(row.value, 10);
    if (found > SCHEMA_VERSION) {
      throw new Error(
        `Database was written by a newer version of line-connector (schema ${found}, this build understands ${SCHEMA_VERSION}). Upgrade rather than downgrade.`,
      );
    }
    // Future migrations for found < SCHEMA_VERSION would run here.
  }

  close(): void {
    this.db.close();
  }

  /** Derives the internal lookup key for a LINE id. */
  keyFor(lineId: string): string {
    return createHmac('sha256', this.key).update(`id:${lineId}`).digest('hex');
  }

  // -- writes ---------------------------------------------------------------

  /**
   * Creates the conversation row if it is new, and refreshes the display name
   * when one is supplied. Returns the internal key.
   */
  upsertConversation(
    lineId: string,
    sourceType: SourceType,
    now: number,
    displayName?: string | null,
  ): string {
    const id = this.keyFor(lineId);
    const existing = this.db.prepare('SELECT id FROM conversations WHERE id = ?').get(id);

    if (existing === undefined) {
      this.db
        .prepare(
          `INSERT INTO conversations
             (id, line_id_enc, pseudonym, source_type, display_name_enc, first_seen_at, last_message_at)
           VALUES (?, ?, ?, ?, ?, ?, NULL)`,
        )
        .run(
          id,
          encryptField(lineId, this.key),
          pseudonymise(lineId, this.key),
          sourceType,
          displayName ? encryptField(displayName, this.key) : null,
          now,
        );
    } else if (displayName) {
      this.db
        .prepare('UPDATE conversations SET display_name_enc = ? WHERE id = ?')
        .run(encryptField(displayName, this.key), id);
    }

    return id;
  }

  /**
   * Stores a message.
   *
   * Keyed on the HMAC of the LINE message id, so LINE's at-least-once webhook
   * redelivery cannot produce duplicate rows. Returns false when the message
   * was already present.
   */
  insertMessage(input: InsertMessageInput): boolean {
    const { message, text, redactions, originalTextLength } = input;
    const now = Date.now();
    const conversationId = this.keyFor(message.conversationId);
    const messageId = this.keyFor(message.id);

    const alreadyStored = this.db.prepare('SELECT id FROM messages WHERE id = ?').get(messageId);
    if (alreadyStored !== undefined) return false;

    this.db
      .prepare(
        `INSERT INTO messages
           (id, conversation_id, sender_key, sender_id_enc, sender_pseudonym, direction,
            type, text_enc, text_len, timestamp, meta_json, redactions, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        messageId,
        conversationId,
        message.senderId ? this.keyFor(message.senderId) : null,
        message.senderId ? encryptField(message.senderId, this.key) : null,
        message.senderId ? pseudonymise(message.senderId, this.key) : null,
        message.direction,
        message.type,
        text === null ? null : encryptField(text, this.key),
        originalTextLength,
        message.timestamp,
        JSON.stringify(message.meta),
        redactions.join(','),
        now,
      );

    this.db
      .prepare(
        `UPDATE conversations
            SET last_message_at = MAX(COALESCE(last_message_at, 0), ?)
          WHERE id = ?`,
      )
      .run(message.timestamp, conversationId);

    return true;
  }

  // -- reads ----------------------------------------------------------------

  listConversations(restrictTo?: readonly string[]): ConversationRow[] {
    const rows = this.db
      .prepare(
        `SELECT c.id, c.line_id_enc, c.pseudonym, c.source_type, c.display_name_enc,
                c.first_seen_at, c.last_message_at,
                (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS message_count
           FROM conversations c
          ORDER BY COALESCE(c.last_message_at, c.first_seen_at) DESC`,
      )
      .all() as unknown as RawConversation[];

    const allowed = restrictTo === undefined ? null : new Set(restrictTo);
    const out: ConversationRow[] = [];
    for (const row of rows) {
      if (allowed !== null && !allowed.has(row.id)) continue;
      out.push(this.hydrateConversation(row));
    }
    return out;
  }

  getConversationByLineId(lineId: string): ConversationRow | null {
    const row = this.db
      .prepare(
        `SELECT c.id, c.line_id_enc, c.pseudonym, c.source_type, c.display_name_enc,
                c.first_seen_at, c.last_message_at,
                (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS message_count
           FROM conversations c WHERE c.id = ?`,
      )
      .get(this.keyFor(lineId)) as RawConversation | undefined;
    return row === undefined ? null : this.hydrateConversation(row);
  }

  /**
   * Resolves the handle a caller supplied to a conversation.
   *
   * Accepts the pseudonym the model is given, or a real LINE id for an
   * operator working from the LINE console. Returns null when neither matches,
   * which callers must treat as "not found" rather than "not permitted" — the
   * two are kept distinct so the model cannot probe for the existence of
   * conversations it is not allowed to read.
   */
  findConversation(handle: string): ConversationRow | null {
    const row = this.db
      .prepare(
        `SELECT c.id, c.line_id_enc, c.pseudonym, c.source_type, c.display_name_enc,
                c.first_seen_at, c.last_message_at,
                (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS message_count
           FROM conversations c WHERE c.pseudonym = ?`,
      )
      .get(handle) as RawConversation | undefined;

    if (row !== undefined) return this.hydrateConversation(row);
    return this.getConversationByLineId(handle);
  }

  /**
   * Reads messages newest-first.
   *
   * `restrictTo` is applied in SQL rather than after the fact, so a
   * conversation the caller may not read is never even decrypted.
   */
  queryMessages(query: MessageQuery): MessageRow[] {
    const clauses: string[] = [];
    const params: (string | number)[] = [];

    if (query.conversationId !== undefined) {
      clauses.push('m.conversation_id = ?');
      params.push(query.conversationId);
    }
    if (query.restrictTo !== undefined) {
      if (query.restrictTo.length === 0) return [];
      clauses.push(`m.conversation_id IN (${query.restrictTo.map(() => '?').join(',')})`);
      params.push(...query.restrictTo);
    }
    if (query.since !== undefined) {
      clauses.push('m.timestamp >= ?');
      params.push(query.since);
    }
    if (query.until !== undefined) {
      clauses.push('m.timestamp <= ?');
      params.push(query.until);
    }

    const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    params.push(query.limit);

    const rows = this.db
      .prepare(
        `SELECT m.*, c.pseudonym AS conversation_pseudonym
           FROM messages m
           JOIN conversations c ON c.id = m.conversation_id
           ${where}
          ORDER BY m.timestamp DESC
          LIMIT ?`,
      )
      .all(...params) as unknown as RawMessage[];

    return rows.map((row) => this.hydrateMessage(row));
  }

  /** Total message count, used by status reporting. */
  countMessages(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM messages').get() as { n: number };
    return row.n;
  }

  oldestMessageTimestamp(): number | null {
    const row = this.db.prepare('SELECT MIN(timestamp) AS t FROM messages').get() as {
      t: number | null;
    };
    return row.t;
  }

  // -- deletion -------------------------------------------------------------

  /** Deletes messages older than `cutoff` within one conversation. */
  purgeConversationBefore(conversationId: string, cutoff: number): number {
    const result = this.db
      .prepare('DELETE FROM messages WHERE conversation_id = ? AND timestamp < ?')
      .run(conversationId, cutoff);
    return Number(result.changes);
  }

  /**
   * Deletes a single message by its LINE message id.
   *
   * Used to honour `unsend`: when someone retracts a message in LINE, the copy
   * here goes too. A connector that kept retracted messages would quietly
   * defeat a privacy control the sender actively chose to use.
   */
  deleteMessageByLineId(lineMessageId: string): boolean {
    const result = this.db.prepare('DELETE FROM messages WHERE id = ?').run(this.keyFor(lineMessageId));
    return Number(result.changes) > 0;
  }

  /** Erases everything attributable to one LINE id, as sender or as thread. */
  forget(lineId: string): { messages: number; conversations: number } {
    const key = this.keyFor(lineId);
    const bySender = this.db.prepare('DELETE FROM messages WHERE sender_key = ?').run(key);
    const byConversation = this.db
      .prepare('DELETE FROM messages WHERE conversation_id = ?')
      .run(key);
    const conversations = this.db.prepare('DELETE FROM conversations WHERE id = ?').run(key);
    return {
      messages: Number(bySender.changes) + Number(byConversation.changes),
      conversations: Number(conversations.changes),
    };
  }

  /** Drops conversations that retention has emptied. */
  pruneEmptyConversations(): number {
    const result = this.db
      .prepare(
        `DELETE FROM conversations
          WHERE id NOT IN (SELECT DISTINCT conversation_id FROM messages)`,
      )
      .run();
    return Number(result.changes);
  }

  listConversationKeys(): string[] {
    const rows = this.db.prepare('SELECT id FROM conversations').all() as { id: string }[];
    return rows.map((r) => r.id);
  }

  /**
   * Reclaims the space freed by deletes.
   *
   * Without this, purged message text stays in free pages inside the file and
   * is recoverable with a hex editor, which would make "deleted" a lie.
   */
  vacuum(): void {
    this.db.exec('VACUUM');
  }

  // -- audit ----------------------------------------------------------------

  recordAudit(entry: {
    actor: string;
    action: string;
    conversationId?: string | null;
    detail?: string;
    resultCount?: number | null;
  }): void {
    this.db
      .prepare(
        `INSERT INTO audit_log (ts, actor, action, conversation_id, detail, result_count)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(
        Date.now(),
        entry.actor,
        entry.action,
        entry.conversationId ?? null,
        entry.detail ?? '',
        entry.resultCount ?? null,
      );
  }

  readAudit(limit: number): AuditEntry[] {
    return this.db
      .prepare('SELECT * FROM audit_log ORDER BY ts DESC LIMIT ?')
      .all(limit) as unknown as AuditEntry[];
  }

  purgeAuditBefore(cutoff: number): number {
    const result = this.db.prepare('DELETE FROM audit_log WHERE ts < ?').run(cutoff);
    return Number(result.changes);
  }

  // -- internals ------------------------------------------------------------

  private hydrateConversation(row: RawConversation): ConversationRow {
    return {
      id: row.id,
      lineId: decryptField(row.line_id_enc, this.key),
      pseudonym: row.pseudonym,
      sourceType: row.source_type as SourceType,
      displayName:
        row.display_name_enc === null ? null : decryptField(row.display_name_enc, this.key),
      firstSeenAt: row.first_seen_at,
      lastMessageAt: row.last_message_at,
      messageCount: row.message_count,
    };
  }

  private hydrateMessage(row: RawMessage): MessageRow {
    return {
      id: row.id,
      conversationId: row.conversation_id,
      conversationPseudonym: row.conversation_pseudonym,
      senderPseudonym: row.sender_pseudonym,
      senderLineId: row.sender_id_enc === null ? null : decryptField(row.sender_id_enc, this.key),
      direction: row.direction as Direction,
      type: row.type as MessageType,
      text: row.text_enc === null ? null : decryptField(row.text_enc, this.key),
      timestamp: row.timestamp,
      meta: safeParseJson(row.meta_json),
      redactions: row.redactions === '' ? [] : row.redactions.split(','),
    };
  }
}

export interface AuditEntry {
  id: number;
  ts: number;
  actor: string;
  action: string;
  conversation_id: string | null;
  detail: string;
  result_count: number | null;
}

interface RawConversation {
  id: string;
  line_id_enc: string;
  pseudonym: string;
  source_type: string;
  display_name_enc: string | null;
  first_seen_at: number;
  last_message_at: number | null;
  message_count: number;
}

interface RawMessage {
  id: string;
  conversation_id: string;
  conversation_pseudonym: string;
  sender_key: string | null;
  sender_id_enc: string | null;
  sender_pseudonym: string | null;
  direction: string;
  type: string;
  text_enc: string | null;
  text_len: number;
  timestamp: number;
  meta_json: string;
  redactions: string;
  created_at: number;
}

function safeParseJson(raw: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(raw);
    return parsed !== null && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}
