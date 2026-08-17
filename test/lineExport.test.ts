import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  importedConversationId,
  importedMessageId,
  parseLineExport,
} from '../src/import/lineExport.js';

/** Tab-separated, the way LINE writes the file. */
function line(...parts: string[]): string {
  return parts.join('\t');
}

const ENGLISH_EXPORT = [
  '[LINE] Chat history with Alice',
  'Saved on: 2026/08/17 14:30',
  '',
  '2026/08/15(Fri)',
  line('14:32', 'Alice', 'Hello there'),
  line('14:33', 'Me', 'Hi! How are you?'),
  line('14:35', 'Alice', '[Photo]'),
  '',
  '2026/08/16(Sat)',
  line('09:01', 'Alice', 'Good morning'),
].join('\n');

describe('parseLineExport', () => {
  it('parses an English export', () => {
    const result = parseLineExport(ENGLISH_EXPORT);

    assert.equal(result.title, 'Chat history with Alice');
    assert.equal(result.messages.length, 4);
    assert.equal(result.skipped, 1); // the "Saved on:" line

    const first = result.messages[0];
    assert.equal(first?.sender, 'Alice');
    assert.equal(first?.text, 'Hello there');
    assert.equal(first?.type, 'text');

    const date = new Date(first?.timestamp as number);
    assert.equal(date.getFullYear(), 2026);
    assert.equal(date.getMonth(), 7); // August, zero-indexed
    assert.equal(date.getDate(), 15);
    assert.equal(date.getHours(), 14);
    assert.equal(date.getMinutes(), 32);
  });

  it('carries the date forward across a day boundary', () => {
    const result = parseLineExport(ENGLISH_EXPORT);
    const last = result.messages[3];
    assert.equal(new Date(last?.timestamp as number).getDate(), 16);
    assert.equal(last?.text, 'Good morning');
  });

  it('classifies bracketed placeholders as their media type', () => {
    const result = parseLineExport(ENGLISH_EXPORT);
    assert.equal(result.messages[2]?.type, 'image');
  });

  it('parses a Traditional Chinese export', () => {
    const content = [
      '[LINE] 與Alice的聊天記錄',
      '儲存日期：2026/08/17 14:30',
      '',
      '2026/08/15(週五)',
      line('14:32', '小明', '你好'),
      line('14:35', '小明', '[照片]'),
      line('14:36', '小明', '[貼圖]'),
    ].join('\n');

    const result = parseLineExport(content);
    assert.equal(result.messages.length, 3);
    assert.equal(result.messages[0]?.sender, '小明');
    assert.equal(result.messages[0]?.text, '你好');
    assert.equal(result.messages[1]?.type, 'image');
    assert.equal(result.messages[2]?.type, 'sticker');
  });

  it('parses a Japanese export', () => {
    const content = [
      '[LINE] Aliceとのトーク履歴',
      '保存日時：2026/08/17 14:30',
      '',
      '2026/08/15(土)',
      line('14:32', '田中', 'こんにちは'),
      line('14:33', '田中', '[スタンプ]'),
    ].join('\n');

    const result = parseLineExport(content);
    assert.equal(result.messages.length, 2);
    assert.equal(result.messages[0]?.text, 'こんにちは');
    assert.equal(result.messages[1]?.type, 'sticker');
  });

  it('handles a 12-hour clock with AM/PM', () => {
    const content = ['2026/08/15(Fri)', line('2:32 PM', 'Alice', 'afternoon'), line('9:05 AM', 'Alice', 'morning')].join('\n');
    const result = parseLineExport(content);

    assert.equal(new Date(result.messages[0]?.timestamp as number).getHours(), 14);
    assert.equal(new Date(result.messages[1]?.timestamp as number).getHours(), 9);
  });

  it('maps 12 AM to midnight and 12 PM to noon', () => {
    const content = ['2026/08/15(Fri)', line('12:00 AM', 'A', 'midnight'), line('12:00 PM', 'A', 'noon')].join('\n');
    const result = parseLineExport(content);

    assert.equal(new Date(result.messages[0]?.timestamp as number).getHours(), 0);
    assert.equal(new Date(result.messages[1]?.timestamp as number).getHours(), 12);
  });

  it('joins a multi-line message back together', () => {
    // LINE writes continuation lines bare; treating them as unparseable would
    // silently truncate every paragraph in the export.
    const content = [
      '2026/08/15(Fri)',
      line('14:32', 'Alice', 'First line'),
      'second line',
      'third line',
      line('14:33', 'Alice', 'Separate message'),
    ].join('\n');

    const result = parseLineExport(content);
    assert.equal(result.messages.length, 2);
    assert.equal(result.messages[0]?.text, 'First line\nsecond line\nthird line');
    assert.equal(result.messages[1]?.text, 'Separate message');
    assert.equal(result.skipped, 0);
  });

  it('reads a system line that has no sender', () => {
    const content = ['2026/08/15(Fri)', line('14:32', 'Alice unsent a message')].join('\n');
    const result = parseLineExport(content);

    assert.equal(result.messages[0]?.sender, null);
    assert.equal(result.messages[0]?.text, 'Alice unsent a message');
  });

  it('accepts dot- and dash-separated dates', () => {
    for (const header of ['2026.08.15', '2026-08-15 Saturday', '2026/8/5(Wed)']) {
      const result = parseLineExport([header, line('10:00', 'A', 'hi')].join('\n'));
      assert.equal(result.messages.length, 1, `failed on ${header}`);
    }
  });

  it('tolerates a BOM and CRLF line endings', () => {
    const content = '﻿2026/08/15(Fri)\r\n' + line('14:32', 'Alice', 'hello') + '\r\n';
    const result = parseLineExport(content);

    assert.equal(result.messages.length, 1);
    assert.equal(result.messages[0]?.text, 'hello');
  });

  it('counts a timestamped line before any date header rather than misdating it', () => {
    const result = parseLineExport(line('14:32', 'Alice', 'orphan'));
    assert.equal(result.messages.length, 0);
    assert.equal(result.skipped, 1);
  });

  it('returns nothing for a file that is not an export', () => {
    const result = parseLineExport('just some random text\nwith no structure');
    assert.equal(result.messages.length, 0);
  });
});

describe('imported ids', () => {
  it('derives a stable conversation id from the title', () => {
    const a = importedConversationId('Chat history with Alice');
    assert.equal(a, importedConversationId('Chat history with Alice'));
    assert.notEqual(a, importedConversationId('Chat history with Bob'));
    // Must satisfy the conversation-id schema so it can be allow-listed.
    assert.match(a, /^X[0-9a-f]{32}$/);
  });

  it('derives a stable message id, so re-importing deduplicates', () => {
    const message = { timestamp: 1_755_000_000_000, sender: 'Alice', text: 'hi', type: 'text' as const };
    const id = importedMessageId('Xabc', message);

    assert.equal(id, importedMessageId('Xabc', message));
    assert.notEqual(id, importedMessageId('Xabc', { ...message, text: 'different' }));
    assert.notEqual(id, importedMessageId('Xabc', { ...message, timestamp: 1 }));
  });
});
