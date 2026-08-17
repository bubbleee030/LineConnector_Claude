import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';

import { defaultPrivacyConfig, type PrivacyConfig } from '../src/config.js';
import { Store } from '../src/db/index.js';
import { normalizeEvent } from '../src/line/normalize.js';
import { processAction } from '../src/ingest/pipeline.js';
import { sweepRetention } from '../src/privacy/retention.js';

const USER = 'U1111111111111111111111111111111a';
const OTHER = 'U2222222222222222222222222222222b';
const DAY_MS = 86_400_000;

const tempDirs: string[] = [];

after(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

function newStore(): { store: Store; dir: string; key: Buffer } {
  const dir = mkdtempSync(join(tmpdir(), 'line-connector-test-'));
  tempDirs.push(dir);
  const key = randomBytes(32);
  return { store: new Store(join(dir, 'line.db'), key), dir, key };
}

function allowing(overrides: (c: PrivacyConfig) => void = () => {}): PrivacyConfig {
  const config = defaultPrivacyConfig();
  config.capture.allow.push(USER);
  overrides(config);
  return config;
}

function messageEvent(
  text: string,
  opts: { id?: string; from?: string; at?: number } = {},
): Record<string, unknown> {
  return {
    type: 'message',
    timestamp: opts.at ?? Date.now(),
    source: { type: 'user', userId: opts.from ?? USER },
    deliveryContext: { isRedelivery: false },
    message: { id: opts.id ?? `m-${Math.random().toString(16).slice(2)}`, type: 'text', text },
  };
}

async function ingest(
  store: Store,
  config: PrivacyConfig,
  key: Buffer,
  event: Record<string, unknown>,
): Promise<string> {
  const action = normalizeEvent(event, config);
  const result = await processAction(action, { store, config, encryptionKey: key, client: null });
  return result.outcome;
}

describe('capture pipeline', () => {
  it('stores nothing on a default config, even with a live webhook', async () => {
    const { store, key } = newStore();
    const config = defaultPrivacyConfig();

    assert.equal(await ingest(store, config, key, messageEvent('hello')), 'dropped-by-policy');
    assert.equal(store.countMessages(), 0);
    store.close();
  });

  it('stores an allow-listed conversation and skips everyone else', async () => {
    const { store, key } = newStore();
    const config = allowing();

    assert.equal(await ingest(store, config, key, messageEvent('hello')), 'stored');
    assert.equal(
      await ingest(store, config, key, messageEvent('hi', { from: OTHER })),
      'dropped-by-policy',
    );
    assert.equal(store.countMessages(), 1);
    store.close();
  });

  it('redacts before writing, so the raw value never reaches the row', async () => {
    const { store, key } = newStore();
    const config = allowing();

    await ingest(store, config, key, messageEvent('my card is 4111111111111111 ok'));
    const [message] = store.queryMessages({ limit: 10 });

    assert.equal(message?.text, 'my card is [redacted:card] ok');
    assert.deepEqual(message?.redactions, ['creditCard']);
    store.close();
  });

  it('leaves no plaintext in the database file', async () => {
    // The load-bearing claim of the whole design: someone who copies the .db
    // without the key gets nothing readable.
    const { store, key, dir } = newStore();
    const config = allowing();

    await ingest(store, config, key, messageEvent('meet me at the usual place tomorrow'));
    store.close(); // checkpoints the WAL into the main file

    const onDisk = readdirSync(dir)
      .map((f) => readFileSync(join(dir, f)).toString('latin1'))
      .join('');

    assert.equal(onDisk.includes('meet me at the usual place'), false, 'message text found on disk');
    assert.equal(onDisk.includes(USER), false, 'raw LINE id found on disk');
  });

  it('stores metadata but no body when storeText is "none"', async () => {
    const { store, key } = newStore();
    const config = allowing((c) => {
      c.capture.storeText = 'none';
    });

    await ingest(store, config, key, messageEvent('something private'));
    const [message] = store.queryMessages({ limit: 10 });

    assert.equal(message?.text, null);
    assert.equal(message?.type, 'text');
    assert.deepEqual(message?.redactions, ['storeText:none']);
    store.close();
  });

  it('stores text verbatim only when explicitly set to "full"', async () => {
    const { store, key } = newStore();
    const config = allowing((c) => {
      c.capture.storeText = 'full';
    });

    await ingest(store, config, key, messageEvent('card 4111111111111111'));
    assert.equal(store.queryMessages({ limit: 1 })[0]?.text, 'card 4111111111111111');
    store.close();
  });

  it('is idempotent when LINE redelivers the same message', async () => {
    const { store, key } = newStore();
    const config = allowing();
    const event = messageEvent('only once', { id: 'fixed-id' });

    assert.equal(await ingest(store, config, key, event), 'stored');
    assert.equal(await ingest(store, config, key, event), 'duplicate');
    assert.equal(store.countMessages(), 1);
    store.close();
  });

  it('deletes the local copy when the sender unsends a message', async () => {
    const { store, key } = newStore();
    const config = allowing();

    await ingest(store, config, key, messageEvent('oops wrong chat', { id: 'unsend-me' }));
    assert.equal(store.countMessages(), 1);

    const outcome = await ingest(store, config, key, {
      type: 'unsend',
      timestamp: Date.now(),
      source: { type: 'user', userId: USER },
      unsend: { messageId: 'unsend-me' },
    });

    assert.equal(outcome, 'unsent');
    assert.equal(store.countMessages(), 0);
    store.close();
  });

  it('honours an unsend even for a conversation that is no longer allow-listed', async () => {
    // Deleting must never be gated on consent; refusing to forget because a
    // thread was removed from the allow list would be exactly backwards.
    const { store, key } = newStore();
    const config = allowing();
    await ingest(store, config, key, messageEvent('delete me', { id: 'x1' }));

    const revoked = defaultPrivacyConfig(); // USER no longer allowed
    const outcome = await ingest(store, revoked, key, {
      type: 'unsend',
      timestamp: Date.now(),
      source: { type: 'user', userId: USER },
      unsend: { messageId: 'x1' },
    });

    assert.equal(outcome, 'unsent');
    assert.equal(store.countMessages(), 0);
    store.close();
  });
});

describe('store', () => {
  it('hands the model a pseudonym, not the LINE id', async () => {
    const { store, key } = newStore();
    await ingest(store, allowing(), key, messageEvent('hi'));

    const [conversation] = store.listConversations();
    assert.match(conversation?.pseudonym ?? '', /^user_[0-9a-f]{12}$/);
    assert.equal(conversation?.lineId, USER);
    store.close();
  });

  it('finds a conversation by pseudonym or by LINE id', async () => {
    const { store, key } = newStore();
    await ingest(store, allowing(), key, messageEvent('hi'));
    const [conversation] = store.listConversations();

    assert.equal(store.findConversation(conversation?.pseudonym as string)?.lineId, USER);
    assert.equal(store.findConversation(USER)?.lineId, USER);
    assert.equal(store.findConversation('user_deadbeefcafe'), null);
    store.close();
  });

  it('restricts queries in SQL so unreadable threads are never decrypted', async () => {
    const { store, key } = newStore();
    const config = allowing((c) => c.capture.allow.push(OTHER));

    await ingest(store, config, key, messageEvent('from alice'));
    await ingest(store, config, key, messageEvent('from bob', { from: OTHER }));

    const onlyAlice = store.queryMessages({ limit: 10, restrictTo: [store.keyFor(USER)] });
    assert.equal(onlyAlice.length, 1);
    assert.equal(onlyAlice[0]?.text, 'from alice');

    assert.deepEqual(store.queryMessages({ limit: 10, restrictTo: [] }), []);
    store.close();
  });

  it('erases everything for one person on forget', async () => {
    const { store, key } = newStore();
    const config = allowing((c) => c.capture.allow.push(OTHER));

    await ingest(store, config, key, messageEvent('alice one'));
    await ingest(store, config, key, messageEvent('alice two'));
    await ingest(store, config, key, messageEvent('bob one', { from: OTHER }));

    const result = store.forget(USER);
    assert.equal(result.messages, 2);
    assert.equal(result.conversations, 1);
    assert.equal(store.countMessages(), 1);
    assert.equal(store.findConversation(USER), null);
    store.close();
  });
});

describe('retention', () => {
  it('deletes messages past the window and keeps the rest', async () => {
    const { store, key } = newStore();
    const config = allowing((c) => {
      c.retention.days = 7;
    });

    await ingest(store, config, key, messageEvent('old', { at: Date.now() - 30 * DAY_MS }));
    await ingest(store, config, key, messageEvent('recent', { at: Date.now() - 1 * DAY_MS }));
    assert.equal(store.countMessages(), 2);

    const result = sweepRetention(store, config);
    assert.equal(result.messagesDeleted, 1);
    assert.equal(store.queryMessages({ limit: 10 })[0]?.text, 'recent');
    store.close();
  });

  it('applies a stricter per-conversation override', async () => {
    const { store, key } = newStore();
    const config = allowing((c) => {
      c.retention.days = 90;
      c.retention.perConversationDays[USER] = 1;
    });

    await ingest(store, config, key, messageEvent('two days old', { at: Date.now() - 2 * DAY_MS }));
    assert.equal(sweepRetention(store, config).messagesDeleted, 1);
    store.close();
  });

  it('keeps everything when retention is zero', async () => {
    const { store, key } = newStore();
    const config = allowing((c) => {
      c.retention.days = 0;
    });

    await ingest(store, config, key, messageEvent('ancient', { at: Date.now() - 3650 * DAY_MS }));
    assert.equal(sweepRetention(store, config).messagesDeleted, 0);
    assert.equal(store.countMessages(), 1);
    store.close();
  });

  it('removes conversations left empty by the sweep', async () => {
    const { store, key } = newStore();
    const config = allowing((c) => {
      c.retention.days = 7;
    });

    await ingest(store, config, key, messageEvent('old', { at: Date.now() - 30 * DAY_MS }));
    const result = sweepRetention(store, config);

    assert.equal(result.conversationsRemoved, 1);
    assert.equal(store.listConversations().length, 0);
    store.close();
  });

  it('leaves no trace of purged text in the file afterwards', async () => {
    const { store, key, dir } = newStore();
    const config = allowing((c) => {
      c.retention.days = 1;
    });

    await ingest(store, config, key, messageEvent('purge this line', { at: Date.now() - 5 * DAY_MS }));
    sweepRetention(store, config);
    store.close();

    const onDisk = readdirSync(dir)
      .map((f) => readFileSync(join(dir, f)).toString('latin1'))
      .join('');
    assert.equal(onDisk.includes('purge this line'), false);
  });
});
