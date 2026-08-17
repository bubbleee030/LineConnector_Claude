/**
 * Turns raw LINE webhook events into the shapes the rest of the app uses.
 *
 * This layer is where "how much of a message is even worth keeping" gets
 * decided. LINE sends more than text: precise GPS coordinates, file names,
 * sticker ids. Those ride along in the same event and would be stored by
 * default in a naive implementation, which is how a connector that promises to
 * redact phone numbers ends up quietly recording where someone lives.
 *
 * Nothing here is trusted. The webhook body is attacker-controlled until the
 * signature check passes, and even afterwards LINE may add fields, so every
 * access is defensive.
 */

import type { PrivacyConfig } from '../config.js';
import type { MessageType, NormalizedMessage, SourceType } from '../types.js';

/** What the ingest pipeline should do with a single webhook event. */
export type IngestAction =
  | { kind: 'message'; message: NormalizedMessage }
  /** The sender deleted a message; we delete our copy to match. */
  | { kind: 'unsend'; conversationLineId: string; messageLineId: string }
  | { kind: 'ignored'; reason: string };

export interface WebhookBody {
  destination?: unknown;
  events?: unknown;
}

/**
 * Extracts the events array from a parsed webhook body.
 * LINE sends an empty `events` array for endpoint verification, which is a
 * successful call rather than an error.
 */
export function extractEvents(body: unknown): unknown[] {
  if (!isRecord(body)) return [];
  const events = (body as WebhookBody).events;
  return Array.isArray(events) ? events : [];
}

export function normalizeEvent(event: unknown, config: PrivacyConfig): IngestAction {
  if (!isRecord(event)) return { kind: 'ignored', reason: 'event is not an object' };

  const source = isRecord(event.source) ? event.source : null;
  if (source === null) return { kind: 'ignored', reason: 'event has no source' };

  const sourceType = readSourceType(source.type);
  if (sourceType === null) {
    return { kind: 'ignored', reason: `unknown source type ${String(source.type)}` };
  }

  // The conversation is the group or room when there is one, otherwise the
  // 1:1 chat with the user. Grouping group messages under their sender would
  // scatter one thread across many conversations.
  const conversationLineId = readString(
    sourceType === 'group' ? source.groupId : sourceType === 'room' ? source.roomId : source.userId,
  );
  if (conversationLineId === null) {
    return { kind: 'ignored', reason: 'event source has no usable id' };
  }

  const eventType = readString(event.type);

  if (eventType === 'unsend') {
    const unsend = isRecord(event.unsend) ? event.unsend : null;
    const messageLineId = unsend === null ? null : readString(unsend.messageId);
    if (messageLineId === null) {
      return { kind: 'ignored', reason: 'unsend event has no messageId' };
    }
    return { kind: 'unsend', conversationLineId, messageLineId };
  }

  if (eventType !== 'message') {
    // follow, unfollow, join, leave, postback, memberJoined, ... These are
    // account lifecycle, not conversation content, and are not stored.
    return { kind: 'ignored', reason: `event type ${String(eventType)} is not message content` };
  }

  const message = isRecord(event.message) ? event.message : null;
  if (message === null) return { kind: 'ignored', reason: 'message event has no message' };

  const messageLineId = readString(message.id);
  if (messageLineId === null) return { kind: 'ignored', reason: 'message has no id' };

  const messageType = readMessageType(message.type);
  const timestamp = readNumber(event.timestamp) ?? Date.now();
  const deliveryContext = isRecord(event.deliveryContext) ? event.deliveryContext : null;

  return {
    kind: 'message',
    message: {
      id: messageLineId,
      conversationId: conversationLineId,
      sourceType,
      senderId: readString(source.userId),
      direction: 'inbound',
      type: messageType,
      text: messageType === 'text' ? readString(message.text) : null,
      timestamp,
      isRedelivery: deliveryContext?.isRedelivery === true,
      meta: buildMeta(messageType, message, config),
    },
  };
}

/**
 * Builds the per-type metadata that survives even when the body is dropped.
 *
 * The rule applied throughout: keep what makes a transcript readable ("they
 * sent a 12-second voice note"), discard what identifies or locates someone.
 */
function buildMeta(
  type: MessageType,
  message: Record<string, unknown>,
  config: PrivacyConfig,
): Record<string, unknown> {
  const meta: Record<string, unknown> = {};

  switch (type) {
    case 'text': {
      // Mentions carry userIds. Record only that mentions happened.
      const mention = isRecord(message.mention) ? message.mention : null;
      const mentionees = mention !== null && Array.isArray(mention.mentionees)
        ? mention.mentionees.length
        : 0;
      if (mentionees > 0) meta.mentionCount = mentionees;
      break;
    }

    case 'image':
    case 'video':
    case 'audio': {
      const duration = readNumber(message.duration);
      if (duration !== null) meta.durationMs = duration;
      const provider = isRecord(message.contentProvider) ? message.contentProvider : null;
      if (provider !== null) meta.contentProvider = readString(provider.type) ?? 'unknown';
      // Whether the bytes are retrievable at all, given storeMedia.
      meta.mediaStored = config.capture.storeMedia;
      break;
    }

    case 'file': {
      const size = readNumber(message.fileSize);
      if (size !== null) meta.fileSize = size;
      const name = readString(message.fileName);
      if (name !== null) {
        if (config.capture.storeFileNames) {
          meta.fileName = name;
        } else {
          // The extension is useful context and carries no identity.
          const dot = name.lastIndexOf('.');
          meta.fileExtension = dot > 0 && dot < name.length - 1 ? name.slice(dot + 1).toLowerCase() : null;
        }
      }
      break;
    }

    case 'location': {
      const mode = config.capture.storeLocation;
      meta.locationPrecision = mode;
      if (mode === 'precise' || mode === 'coarse') {
        const lat = readNumber(message.latitude);
        const lon = readNumber(message.longitude);
        if (lat !== null && lon !== null) {
          // 2 decimal places is roughly a 1km square: enough to say "they were
          // in this part of town", not enough to say which building.
          meta.latitude = mode === 'coarse' ? Math.round(lat * 100) / 100 : lat;
          meta.longitude = mode === 'coarse' ? Math.round(lon * 100) / 100 : lon;
        }
        if (mode === 'precise') {
          const address = readString(message.address);
          if (address !== null) meta.address = address;
        }
      }
      break;
    }

    case 'sticker': {
      const packageId = readString(message.packageId);
      const stickerId = readString(message.stickerId);
      if (packageId !== null) meta.packageId = packageId;
      if (stickerId !== null) meta.stickerId = stickerId;
      // Sticker keywords describe the sentiment, which is genuinely useful
      // context and reveals nothing about the sender.
      if (Array.isArray(message.keywords)) {
        meta.keywords = message.keywords.filter((k): k is string => typeof k === 'string').slice(0, 5);
      }
      break;
    }

    case 'unknown':
      break;
  }

  return meta;
}

/**
 * Renders a non-text message as a short readable placeholder, so a transcript
 * reads as a conversation rather than a run of blanks.
 */
export function describeNonTextMessage(type: MessageType, meta: Record<string, unknown>): string {
  switch (type) {
    case 'image':
      return '[image]';
    case 'video':
      return typeof meta.durationMs === 'number'
        ? `[video, ${Math.round(meta.durationMs / 1000)}s]`
        : '[video]';
    case 'audio':
      return typeof meta.durationMs === 'number'
        ? `[voice message, ${Math.round(meta.durationMs / 1000)}s]`
        : '[voice message]';
    case 'file':
      return typeof meta.fileName === 'string'
        ? `[file: ${meta.fileName}]`
        : typeof meta.fileExtension === 'string'
          ? `[file: .${meta.fileExtension}]`
          : '[file]';
    case 'location':
      return meta.latitude !== undefined
        ? `[location: ~${String(meta.latitude)}, ${String(meta.longitude)}]`
        : '[location shared]';
    case 'sticker':
      return Array.isArray(meta.keywords) && meta.keywords.length > 0
        ? `[sticker: ${(meta.keywords as string[]).join(', ')}]`
        : '[sticker]';
    default:
      return '[unsupported message type]';
  }
}

// -- narrow readers -----------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readString(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

function readNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function readSourceType(value: unknown): SourceType | null {
  return value === 'user' || value === 'group' || value === 'room' ? value : null;
}

function readMessageType(value: unknown): MessageType {
  switch (value) {
    case 'text':
    case 'image':
    case 'video':
    case 'audio':
    case 'file':
    case 'location':
    case 'sticker':
      return value;
    default:
      return 'unknown';
  }
}
