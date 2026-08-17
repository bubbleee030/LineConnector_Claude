/**
 * Notification relay ingest.
 *
 * This exists because of a specific gap: reading a personal LINE chat any
 * other way sends a read receipt. Opening the chat marks it read, and the
 * export feature can only be reached by opening the chat, so "export it" is
 * not an answer when the point is to read without the sender seeing 已讀.
 *
 * Android notifications have neither problem. A NotificationListenerService
 * sees the message as the OS posts it, and reading a notification never marks
 * anything read in LINE — no request reaches LINE's servers at all. The phone
 * forwards the notification here, and it lands in the same encrypted store as
 * everything else.
 *
 * What this costs, and it is not small: a notification is a *preview*, not the
 * message. Long messages arrive truncated, attachments arrive as placeholders,
 * a muted chat may post nothing, and if the chat is already open on the phone
 * there is no notification to capture. This is a lossy channel, and the store
 * records that fact per message so a transcript never implies more fidelity
 * than it has.
 */

import { createHash } from 'node:crypto';

import type { NormalizedMessage } from '../types.js';

/** Package name of the official LINE Android client. */
export const LINE_PACKAGE = 'jp.naver.line.android';

export interface NotifyPayload {
  /** Notification title: the chat name, or the group name for a group. */
  chat: string;
  /** Sender within a group. Absent for a 1:1 chat, where it equals `chat`. */
  sender?: string;
  /** Notification body: the message preview. */
  text: string;
  /** Epoch milliseconds. Defaults to arrival time when the relay omits it. */
  postedAt?: number;
  /** Source package, so non-LINE notifications can be rejected. */
  app?: string;
}

export type NotifyResult =
  | { ok: true; message: NormalizedMessage }
  | { ok: false; reason: string };

/**
 * Group notifications arrive with the group as the title and the body written
 * as `Sender: message`. Splitting that is a heuristic — a 1:1 message that
 * happens to start with `word:` would be misread — so it only runs when the
 * relay did not supply an explicit sender, and the prefix is bounded to a
 * plausible display-name length.
 */
const GROUP_BODY = /^([^\n:]{1,40}):\s(.+)$/s;

/** Notification texts LINE posts that are not message content. */
const NON_MESSAGE = [
  /^\d+ new messages?$/i,
  /^\d+ 則新訊息$/,
  /^\d+件の新着メッセージ$/,
];

/**
 * Validates and normalizes a relayed notification.
 *
 * Everything here is untrusted: the relay is an app on a phone posting over
 * the network, so this validates shape and length rather than assuming a
 * well-behaved client.
 */
export function normalizeNotification(body: unknown, now = Date.now()): NotifyResult {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return { ok: false, reason: 'payload is not an object' };
  }

  const payload = body as Record<string, unknown>;

  if (payload.app !== undefined && payload.app !== LINE_PACKAGE) {
    // The relay may be forwarding every notification on the device. Anything
    // that is not LINE is silently none of this project's business.
    return { ok: false, reason: `ignoring notification from ${String(payload.app)}` };
  }

  const chat = readString(payload.chat, 200);
  if (chat === null) return { ok: false, reason: 'missing or invalid "chat"' };

  const text = readString(payload.text, 5000);
  if (text === null) return { ok: false, reason: 'missing or invalid "text"' };

  if (NON_MESSAGE.some((pattern) => pattern.test(text.trim()))) {
    // "3 new messages" is a summary notification, not a message.
    return { ok: false, reason: 'summary notification, not message content' };
  }

  let sender = readString(payload.sender, 200);
  let messageText = text;

  if (sender === null) {
    const grouped = GROUP_BODY.exec(text);
    if (grouped !== null) {
      sender = grouped[1] as string;
      messageText = grouped[2] as string;
    } else {
      sender = chat;
    }
  }

  const postedAt =
    typeof payload.postedAt === 'number' && Number.isFinite(payload.postedAt)
      ? payload.postedAt
      : now;

  const conversationId = notificationConversationId(chat);

  return {
    ok: true,
    message: {
      id: notificationMessageId(conversationId, sender, messageText, postedAt),
      conversationId,
      // A notification cannot tell a group from a 1:1 chat. Treating it as a
      // direct chat is the safer default: it never invents a group that is
      // not there, and the sender is recorded either way.
      sourceType: 'user',
      senderId: sender,
      direction: 'inbound',
      type: 'text',
      text: messageText,
      timestamp: postedAt,
      isRedelivery: false,
      meta: {
        source: 'notification',
        // Recorded so a reader knows the text may be a truncated preview
        // rather than the whole message.
        fidelity: 'preview',
      },
    },
  };
}

/**
 * Stable conversation id derived from the chat name.
 *
 * `X` marks it as not LINE-issued, the same prefix imported chats use, so a
 * chat captured both ways lands in one conversation instead of two.
 */
export function notificationConversationId(chat: string): string {
  const digest = createHash('sha256').update(`line-export:${chat}`).digest('hex');
  return `X${digest.slice(0, 32)}`;
}

/**
 * Message id derived from content and the minute it arrived.
 *
 * Android reposts a notification when it is updated, so the same message can
 * arrive several times. Rounding to the minute means those collapse into one
 * row, while two genuinely identical messages a minute apart stay distinct.
 */
function notificationMessageId(
  conversationId: string,
  sender: string,
  text: string,
  postedAt: number,
): string {
  const minute = Math.floor(postedAt / 60_000);
  const digest = createHash('sha256')
    .update(`${conversationId} ${minute} ${sender} ${text}`)
    .digest('hex');
  return `n-${digest.slice(0, 24)}`;
}

function readString(value: unknown, maxLength: number): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > maxLength) return null;
  return trimmed;
}
