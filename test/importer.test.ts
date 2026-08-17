import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';

import { defaultPrivacyConfig } from '../src/config.js';
import { Store } from '../src/db/index.js';
import { importExport } from '../src/import/importer.js';
import { parseLineExport } from '../src/import/lineExport.js';

const tempDirs: string[] = [];
after(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

function newStore(): { store: Store; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), 'line-import-test-'));
  tempDirs.push(dir);
  return { store: new Store(join(dir, 'line.db'), randomBytes(32)), dir };
}

function line(...parts: string[]): string {
  return parts.join('\t');
}

const EXPORT = [
  '[LINE] Chat history with Alice',
  '',
  '2026/08/15(Fri)',
  line('14:32', 'Alice', 'my card is 4111111111111111'),
  line('14:33', 'Me', 'got it, thanks'),
  line('14:35', 'Alice', '[Photo]'),
].join('\n');

describe('importExport', () => {
  it('imports a personal chat into the store', () => {
    const { store } = newStore();
    const result = importExport(store, defaultPrivacyConfig(), parseLineExport(EXPORT));

    assert.equal(result.imported, 3);
    assert.equal(result.sourceType, 'user');
    assert.equal(store.countMessages(), 3);
    store.close();
  });

  it('bypasses the capture allow list, unlike webhook traffic', () => {
    // Importing is an explicit act on a file the person chose by hand, so the
    // allow list — which exists to stop a webhook recording strangers — does
    // not apply. A default config would drop every webhook message.
    const { store } = newStore();
    const config = defaultPrivacyConfig();
    assert.deepEqual(config.capture.allow, []);

    const result = importExport(store, config, parseLineExport(EXPORT));
    assert.equal(result.imported, 3);
    store.close();
  });

  it('redacts imported messages the same as webhook messages', () => {
    const { store } = newStore();
    importExport(store, defaultPrivacyConfig(), parseLineExport(EXPORT));

    const messages = store.queryMessages({ limit: 10 });
    const withCard = messages.find((m) => m.text?.includes('card'));
    assert.equal(withCard?.text, 'my card is [redacted:card]');
    store.close();
  });

  it('marks your own messages as outbound when --me is given', () => {
    const { store } = newStore();
    importExport(store, defaultPrivacyConfig(), parseLineExport(EXPORT), {
      selfLabels: ['Me'],
    });

    const messages = store.queryMessages({ limit: 10 });
    const mine = messages.filter((m) => m.direction === 'outbound');
    assert.equal(mine.length, 1);
    assert.equal(mine[0]?.text, 'got it, thanks');
    store.close();
  });

  it('recognises the default self labels without configuration', () => {
    const { store } = newStore();
    // "Me" is in the built-in list, so this works with no --me flag.
    importExport(store, defaultPrivacyConfig(), parseLineExport(EXPORT));
    const outbound = store.queryMessages({ limit: 10 }).filter((m) => m.direction === 'outbound');
    assert.equal(outbound.length, 1);
    store.close();
  });

  it('deduplicates when the same export is imported twice', () => {
    // Re-exporting a chat later produces a file that repeats everything; the
    // second import must add only what is new.
    const { store } = newStore();
    const config = defaultPrivacyConfig();

    const first = importExport(store, config, parseLineExport(EXPORT));
    const second = importExport(store, config, parseLineExport(EXPORT));

    assert.equal(first.imported, 3);
    assert.equal(second.imported, 0);
    assert.equal(second.duplicates, 3);
    assert.equal(store.countMessages(), 3);
    store.close();
  });

  it('adds only the new messages from a longer re-export', () => {
    const { store } = newStore();
    const config = defaultPrivacyConfig();
    importExport(store, config, parseLineExport(EXPORT));

    const longer = `${EXPORT}\n${line('16:00', 'Alice', 'one more thing')}`;
    const result = importExport(store, config, parseLineExport(longer));

    assert.equal(result.imported, 1);
    assert.equal(result.duplicates, 3);
    assert.equal(store.countMessages(), 4);
    store.close();
  });

  it('lands a re-import in the same conversation, not a second one', () => {
    const { store } = newStore();
    const config = defaultPrivacyConfig();
    importExport(store, config, parseLineExport(EXPORT));
    importExport(store, config, parseLineExport(EXPORT));

    assert.equal(store.listConversations().length, 1);
    store.close();
  });

  it('treats a chat with several participants as a group', () => {
    const { store } = newStore();
    const groupExport = [
      '[LINE] Chat history with Team',
      '',
      '2026/08/15(Fri)',
      line('14:32', 'Alice', 'hi'),
      line('14:33', 'Bob', 'hello'),
      line('14:34', 'Carol', 'hey'),
    ].join('\n');

    const result = importExport(store, defaultPrivacyConfig(), parseLineExport(groupExport));
    assert.equal(result.sourceType, 'group');
    assert.deepEqual(result.senders, ['Alice', 'Bob', 'Carol']);
    store.close();
  });

  it('leaves no sender name or message text in the database file', () => {
    // The export is plaintext on disk; the imported copy must not be.
    const { store, dir } = newStore();
    importExport(store, defaultPrivacyConfig(), parseLineExport(EXPORT));
    store.close();

    const onDisk = readdirSync(dir)
      .map((f) => readFileSync(join(dir, f)).toString('latin1'))
      .join('');

    assert.equal(onDisk.includes('Alice'), false, 'sender name found on disk');
    assert.equal(onDisk.includes('got it, thanks'), false, 'message text found on disk');
    assert.equal(onDisk.includes('4111111111111111'), false, 'card number found on disk');
  });

  it('gives imported participants stable pseudonyms', () => {
    const { store } = newStore();
    importExport(store, defaultPrivacyConfig(), parseLineExport(EXPORT));

    const fromAlice = store
      .queryMessages({ limit: 10 })
      .filter((m) => m.direction === 'inbound' && m.senderPseudonym !== null);

    const distinct = new Set(fromAlice.map((m) => m.senderPseudonym));
    assert.equal(distinct.size, 1);
    assert.match([...distinct][0] as string, /^user_[0-9a-f]{12}$/);
    store.close();
  });

  it('stores no body for non-text messages, leaving the placeholder to read time', () => {
    const { store } = newStore();
    importExport(store, defaultPrivacyConfig(), parseLineExport(EXPORT));

    const photo = store.queryMessages({ limit: 10 }).find((m) => m.type === 'image');
    assert.equal(photo?.text, null);
    store.close();
  });

  it('honours storeText: none', () => {
    const { store } = newStore();
    const config = defaultPrivacyConfig();
    config.capture.storeText = 'none';

    importExport(store, config, parseLineExport(EXPORT));
    for (const message of store.queryMessages({ limit: 10 })) {
      assert.equal(message.text, null);
    }
    store.close();
  });
});
