import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  LINE_PACKAGE,
  normalizeNotification,
  notificationConversationId,
} from '../src/ingest/notify.js';
import { importedConversationId } from '../src/import/lineExport.js';

const NOW = 1_755_400_000_000;

function notify(overrides: Record<string, unknown> = {}): unknown {
  return { app: LINE_PACKAGE, chat: 'Alice', text: 'see you at seven', ...overrides };
}

describe('normalizeNotification', () => {
  it('accepts a LINE notification', () => {
    const result = normalizeNotification(notify(), NOW);
    assert.equal(result.ok, true);
    if (!result.ok) return;

    assert.equal(result.message.text, 'see you at seven');
    assert.equal(result.message.senderId, 'Alice');
    assert.equal(result.message.direction, 'inbound');
    assert.equal(result.message.timestamp, NOW);
  });

  it('marks the text as a preview, since notifications truncate', () => {
    // A transcript must not imply it holds the full message when it holds a
    // notification preview.
    const result = normalizeNotification(notify(), NOW);
    assert.equal(result.ok && result.message.meta.fidelity, 'preview');
    assert.equal(result.ok && result.message.meta.source, 'notification');
  });

  it('ignores notifications from other apps', () => {
    const result = normalizeNotification(notify({ app: 'com.whatsapp' }), NOW);
    assert.equal(result.ok, false);
    if (result.ok) return;
    assert.match(result.reason, /ignoring notification from com\.whatsapp/);
  });

  it('accepts a payload with no app field, for relays that omit it', () => {
    const result = normalizeNotification({ chat: 'Alice', text: 'hi' }, NOW);
    assert.equal(result.ok, true);
  });

  it('splits "Sender: message" so group chats attribute correctly', () => {
    const result = normalizeNotification(
      notify({ chat: 'Team Chat', text: 'Bob: standup in five' }),
      NOW,
    );
    assert.equal(result.ok, true);
    if (!result.ok) return;

    assert.equal(result.message.senderId, 'Bob');
    assert.equal(result.message.text, 'standup in five');
  });

  it('prefers an explicit sender over the heuristic', () => {
    const result = normalizeNotification(
      notify({ chat: 'Team', sender: 'Carol', text: 'Bob: quoted text' }),
      NOW,
    );
    assert.equal(result.ok && result.message.senderId, 'Carol');
    assert.equal(result.ok && result.message.text, 'Bob: quoted text');
  });

  it('does not mistake a long prefix for a sender name', () => {
    const long = 'a'.repeat(60);
    const result = normalizeNotification(notify({ text: `${long}: rest` }), NOW);
    assert.equal(result.ok, true);
    if (!result.ok) return;
    // Bounded prefix length keeps ordinary text containing a colon intact.
    assert.equal(result.message.text, `${long}: rest`);
    assert.equal(result.message.senderId, 'Alice');
  });

  it('drops summary notifications in each supported language', () => {
    for (const text of ['3 new messages', '3 則新訊息', '3件の新着メッセージ']) {
      const result = normalizeNotification(notify({ text }), NOW);
      assert.equal(result.ok, false, `expected "${text}" to be dropped`);
    }
  });

  it('rejects malformed payloads', () => {
    const cases: unknown[] = [
      null,
      'string',
      [],
      {},
      { chat: 'Alice' },
      { text: 'orphan' },
      { chat: '', text: 'hi' },
      { chat: 'Alice', text: '   ' },
      { chat: 'Alice', text: 'x'.repeat(5001) },
    ];
    for (const payload of cases) {
      assert.equal(normalizeNotification(payload, NOW).ok, false);
    }
  });

  it('falls back to arrival time when postedAt is missing or invalid', () => {
    assert.equal(normalizeNotification(notify(), NOW).ok && true, true);
    for (const postedAt of [undefined, 'nope', Number.NaN, Infinity]) {
      const result = normalizeNotification(notify({ postedAt }), NOW);
      assert.equal(result.ok && result.message.timestamp, NOW);
    }
  });

  it('collapses the same notification reposted within a minute', () => {
    // Android updates a notification in place, delivering it repeatedly.
    const a = normalizeNotification(notify({ postedAt: NOW }), NOW);
    const b = normalizeNotification(notify({ postedAt: NOW + 5_000 }), NOW);
    assert.equal(a.ok && b.ok && a.message.id === b.message.id, true);
  });

  it('keeps identical messages a minute apart distinct', () => {
    const a = normalizeNotification(notify({ postedAt: NOW }), NOW);
    const b = normalizeNotification(notify({ postedAt: NOW + 90_000 }), NOW);
    assert.equal(a.ok && b.ok && a.message.id !== b.message.id, true);
  });
});

describe('conversation identity across intakes', () => {
  it('routes a notification and an import of the same chat to one conversation', () => {
    // A chat captured live by notification and later backfilled from an export
    // must merge, not appear twice.
    assert.equal(notificationConversationId('Alice'), importedConversationId('Alice'));
  });

  it('separates different chats', () => {
    assert.notEqual(notificationConversationId('Alice'), notificationConversationId('Bob'));
  });

  it('produces an id the config schema accepts', () => {
    assert.match(notificationConversationId('Alice'), /^X[0-9a-f]{32}$/);
  });
});
