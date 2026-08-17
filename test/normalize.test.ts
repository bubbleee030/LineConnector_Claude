import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { defaultPrivacyConfig } from '../src/config.js';
import { describeNonTextMessage, extractEvents, normalizeEvent } from '../src/line/normalize.js';

const USER = 'U1111111111111111111111111111111a';
const GROUP = 'C3333333333333333333333333333333c';
const config = defaultPrivacyConfig();

function textEvent(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 'message',
    timestamp: 1_700_000_000_000,
    source: { type: 'user', userId: USER },
    deliveryContext: { isRedelivery: false },
    replyToken: 'reply-token',
    message: { id: '500000000001', type: 'text', text: 'hello there' },
    ...overrides,
  };
}

describe('extractEvents', () => {
  it('reads the events array', () => {
    assert.equal(extractEvents({ destination: USER, events: [textEvent()] }).length, 1);
  });

  it('treats a verification ping with no events as an empty batch', () => {
    assert.deepEqual(extractEvents({ destination: USER, events: [] }), []);
  });

  it('tolerates junk bodies rather than throwing', () => {
    for (const body of [null, undefined, 'string', 42, {}, { events: 'nope' }]) {
      assert.deepEqual(extractEvents(body), []);
    }
  });
});

describe('normalizeEvent', () => {
  it('normalizes a 1:1 text message', () => {
    const action = normalizeEvent(textEvent(), config);
    assert.equal(action.kind, 'message');
    if (action.kind !== 'message') return;

    assert.equal(action.message.conversationId, USER);
    assert.equal(action.message.senderId, USER);
    assert.equal(action.message.sourceType, 'user');
    assert.equal(action.message.type, 'text');
    assert.equal(action.message.text, 'hello there');
    assert.equal(action.message.direction, 'inbound');
    assert.equal(action.message.timestamp, 1_700_000_000_000);
  });

  it('groups a group message under the group, not the sender', () => {
    // Keying on the sender would scatter one thread across as many
    // conversations as it has participants.
    const action = normalizeEvent(
      textEvent({ source: { type: 'group', groupId: GROUP, userId: USER } }),
      config,
    );
    assert.equal(action.kind, 'message');
    if (action.kind !== 'message') return;
    assert.equal(action.message.conversationId, GROUP);
    assert.equal(action.message.senderId, USER);
    assert.equal(action.message.sourceType, 'group');
  });

  it('flags redelivered events', () => {
    const action = normalizeEvent(
      textEvent({ deliveryContext: { isRedelivery: true } }),
      config,
    );
    assert.equal(action.kind === 'message' && action.message.isRedelivery, true);
  });

  it('turns an unsend event into a deletion', () => {
    const action = normalizeEvent(
      {
        type: 'unsend',
        timestamp: 1_700_000_000_000,
        source: { type: 'user', userId: USER },
        unsend: { messageId: '500000000001' },
      },
      config,
    );
    assert.equal(action.kind, 'unsend');
    if (action.kind !== 'unsend') return;
    assert.equal(action.messageLineId, '500000000001');
    assert.equal(action.conversationLineId, USER);
  });

  it('ignores lifecycle events that carry no conversation content', () => {
    for (const type of ['follow', 'unfollow', 'join', 'leave', 'postback', 'memberJoined']) {
      const action = normalizeEvent({ type, source: { type: 'user', userId: USER } }, config);
      assert.equal(action.kind, 'ignored', `expected ${type} to be ignored`);
    }
  });

  it('ignores malformed events instead of throwing', () => {
    const cases: unknown[] = [
      null,
      'string',
      {},
      { type: 'message' },
      { type: 'message', source: { type: 'user' } },
      { type: 'message', source: { type: 'alien', userId: USER } },
      { type: 'message', source: { type: 'user', userId: USER }, message: { type: 'text' } },
      { type: 'unsend', source: { type: 'user', userId: USER } },
    ];
    for (const event of cases) {
      assert.equal(normalizeEvent(event, config).kind, 'ignored');
    }
  });

  it('maps unrecognised message types to "unknown" rather than dropping them', () => {
    const action = normalizeEvent(
      textEvent({ message: { id: '1', type: 'newFutureType' } }),
      config,
    );
    assert.equal(action.kind === 'message' && action.message.type, 'unknown');
  });
});

describe('metadata policy', () => {
  function locationEvent(): Record<string, unknown> {
    return textEvent({
      message: {
        id: '1',
        type: 'location',
        title: 'Home',
        address: '1 Some Street, Taipei',
        latitude: 25.033964,
        longitude: 121.564468,
      },
    });
  }

  it('drops coordinates entirely by default', () => {
    const action = normalizeEvent(locationEvent(), config);
    assert.equal(action.kind, 'message');
    if (action.kind !== 'message') return;
    assert.equal(action.message.meta.latitude, undefined);
    assert.equal(action.message.meta.longitude, undefined);
    assert.equal(action.message.meta.address, undefined);
    assert.equal(action.message.meta.locationPrecision, 'none');
  });

  it('rounds coordinates in coarse mode and never keeps the street address', () => {
    const coarse = defaultPrivacyConfig();
    coarse.capture.storeLocation = 'coarse';
    const action = normalizeEvent(locationEvent(), coarse);
    if (action.kind !== 'message') return assert.fail('expected a message');

    assert.equal(action.message.meta.latitude, 25.03);
    assert.equal(action.message.meta.longitude, 121.56);
    assert.equal(action.message.meta.address, undefined);
  });

  it('keeps everything only when explicitly set to precise', () => {
    const precise = defaultPrivacyConfig();
    precise.capture.storeLocation = 'precise';
    const action = normalizeEvent(locationEvent(), precise);
    if (action.kind !== 'message') return assert.fail('expected a message');

    assert.equal(action.message.meta.latitude, 25.033964);
    assert.equal(action.message.meta.address, '1 Some Street, Taipei');
  });

  it('drops file names but keeps the extension by default', () => {
    const action = normalizeEvent(
      textEvent({
        message: { id: '1', type: 'file', fileName: 'contract-wang-2026.pdf', fileSize: 1024 },
      }),
      config,
    );
    if (action.kind !== 'message') return assert.fail('expected a message');

    assert.equal(action.message.meta.fileName, undefined);
    assert.equal(action.message.meta.fileExtension, 'pdf');
    assert.equal(action.message.meta.fileSize, 1024);
  });

  it('keeps file names when the operator opts in', () => {
    const withNames = defaultPrivacyConfig();
    withNames.capture.storeFileNames = true;
    const action = normalizeEvent(
      textEvent({ message: { id: '1', type: 'file', fileName: 'invoice.pdf', fileSize: 10 } }),
      withNames,
    );
    assert.equal(action.kind === 'message' && action.message.meta.fileName, 'invoice.pdf');
  });

  it('records that mentions happened without recording who was mentioned', () => {
    const action = normalizeEvent(
      textEvent({
        message: {
          id: '1',
          type: 'text',
          text: '@alice @bob look',
          mention: { mentionees: [{ index: 0, length: 6, userId: USER }, { index: 7, length: 4 }] },
        },
      }),
      config,
    );
    if (action.kind !== 'message') return assert.fail('expected a message');
    assert.equal(action.message.meta.mentionCount, 2);
    assert.equal(JSON.stringify(action.message.meta).includes(USER), false);
  });

  it('keeps sticker keywords, which describe sentiment and identify nobody', () => {
    const action = normalizeEvent(
      textEvent({
        message: { id: '1', type: 'sticker', packageId: '446', stickerId: '1988', keywords: ['happy', 'thanks'] },
      }),
      config,
    );
    if (action.kind !== 'message') return assert.fail('expected a message');
    assert.deepEqual(action.message.meta.keywords, ['happy', 'thanks']);
  });
});

describe('describeNonTextMessage', () => {
  it('renders readable placeholders', () => {
    assert.equal(describeNonTextMessage('image', {}), '[image]');
    assert.equal(describeNonTextMessage('audio', { durationMs: 12_000 }), '[voice message, 12s]');
    assert.equal(describeNonTextMessage('file', { fileExtension: 'pdf' }), '[file: .pdf]');
    assert.equal(describeNonTextMessage('location', {}), '[location shared]');
    assert.equal(describeNonTextMessage('sticker', { keywords: ['happy'] }), '[sticker: happy]');
  });
});
