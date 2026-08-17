/**
 * The capture pipeline: one webhook event in, one storage decision out.
 *
 * Kept separate from the HTTP server so the privacy-relevant logic can be
 * tested directly, without sockets. Everything that decides what survives
 * contact with the disk happens here, in this order:
 *
 *   consent check -> text selection -> redaction -> encrypt -> store
 *
 * The order is the point. Redaction happens before encryption and storage, so
 * the sensitive substring is discarded in memory and never written anywhere,
 * not even in a form that could be decrypted later.
 */

import type { PrivacyConfig } from '../config.js';
import type { Store } from '../db/index.js';
import type { LineClient } from '../line/client.js';
import type { IngestAction } from '../line/normalize.js';
import { evaluateCapture, evaluateSelfCapture } from '../privacy/policy.js';
import { redact } from '../privacy/redact.js';
import type { NormalizedMessage } from '../types.js';
import { isMediaMessage, storeMedia } from './media.js';

export type Outcome =
  | 'stored'
  | 'duplicate'
  | 'dropped-by-policy'
  | 'unsent'
  | 'unsend-miss'
  | 'ignored';

export interface PipelineContext {
  store: Store;
  config: PrivacyConfig;
  encryptionKey: Buffer;
  /** Only needed for display-name resolution and media download. */
  client?: LineClient | null;
}

export interface PipelineOutcome {
  outcome: Outcome;
  reason?: string;
}

export async function processAction(
  action: IngestAction,
  ctx: PipelineContext,
): Promise<PipelineOutcome> {
  if (action.kind === 'ignored') {
    return { outcome: 'ignored', reason: action.reason };
  }

  if (action.kind === 'unsend') {
    // No consent check here on purpose: deleting is always allowed, and
    // refusing to delete because a conversation is not on the allow list
    // would be backwards.
    const removed = ctx.store.deleteMessageByLineId(action.messageLineId);
    return { outcome: removed ? 'unsent' : 'unsend-miss' };
  }

  const { message } = action;
  const decision = evaluateCapture(message.conversationId, ctx.config);
  if (!decision.store) {
    return { outcome: 'dropped-by-policy', reason: decision.reason };
  }

  if (message.direction === 'outbound' && !ctx.config.capture.storeOutbound) {
    return { outcome: 'dropped-by-policy', reason: 'outbound messages are not stored' };
  }

  // -- text selection and redaction ------------------------------------------
  // Only user-authored text is ever encrypted into text_enc. Placeholders for
  // images, stickers and the like are rendered at read time from metadata, so
  // there is exactly one source of truth for each.
  const originalText = message.text;
  let storedText: string | null = null;
  let redactions: string[] = [];

  if (originalText !== null) {
    switch (decision.storeText) {
      case 'none':
        storedText = null;
        redactions = ['storeText:none'];
        break;
      case 'full':
        storedText = originalText;
        break;
      case 'redacted': {
        const result = redact(originalText, ctx.config);
        storedText = result.text;
        redactions = result.applied;
        break;
      }
    }
  }

  // -- optional enrichment ---------------------------------------------------
  let displayName: string | null = null;
  if (ctx.config.capture.resolveDisplayNames && ctx.client && message.senderId) {
    displayName = await resolveDisplayName(ctx, message.senderId, message.conversationId, message.sourceType);
  }

  const meta = { ...message.meta };
  if (ctx.config.capture.storeMedia && ctx.client && isMediaMessage(message.type)) {
    const stored = await storeMedia(
      ctx.client,
      message.id,
      ctx.store.keyFor(message.id),
      ctx.encryptionKey,
    );
    if (stored !== null) {
      meta.mediaFile = stored.file;
      meta.mediaBytes = stored.bytes;
    }
  }

  // -- write -----------------------------------------------------------------
  const now = Date.now();
  ctx.store.upsertConversation(message.conversationId, message.sourceType, now, displayName);

  const inserted = ctx.store.insertMessage({
    message: { ...message, meta },
    text: storedText,
    redactions,
    originalTextLength: originalText?.length ?? 0,
  });

  return { outcome: inserted ? 'stored' : 'duplicate' };
}

/**
 * Stores a message relayed from a phone notification.
 *
 * Separate from {@link processAction} because the consent model differs: this
 * is the operator's own device forwarding their own notifications, so the
 * allow list does not apply (see `evaluateSelfCapture`). Redaction, encryption
 * and retention are identical.
 */
export function processNotification(
  message: NormalizedMessage,
  ctx: PipelineContext,
): PipelineOutcome {
  const decision = evaluateSelfCapture(message.conversationId, ctx.config);
  if (!decision.store) {
    return { outcome: 'dropped-by-policy', reason: decision.reason };
  }

  let storedText: string | null = null;
  let redactions: string[] = [];

  switch (decision.storeText) {
    case 'none':
      redactions = ['storeText:none'];
      break;
    case 'full':
      storedText = message.text;
      break;
    case 'redacted': {
      const result = redact(message.text ?? '', ctx.config);
      storedText = result.text;
      redactions = result.applied;
      break;
    }
  }

  ctx.store.upsertConversation(message.conversationId, message.sourceType, Date.now());

  const inserted = ctx.store.insertMessage({
    message,
    text: storedText,
    redactions,
    originalTextLength: message.text?.length ?? 0,
  });

  return { outcome: inserted ? 'stored' : 'duplicate' };
}

/**
 * Fetches a sender's display name, tolerating the common failure cases.
 *
 * Users who have not added the Official Account as a friend, and members who
 * have left a group, both return 404. That is normal, not an error worth
 * failing the message over.
 */
async function resolveDisplayName(
  ctx: PipelineContext,
  senderId: string,
  conversationId: string,
  sourceType: 'user' | 'group' | 'room',
): Promise<string | null> {
  try {
    const scope =
      sourceType === 'group'
        ? ({ type: 'group', id: conversationId } as const)
        : sourceType === 'room'
          ? ({ type: 'room', id: conversationId } as const)
          : undefined;
    const profile = await ctx.client!.getProfile(senderId, scope);
    return profile?.displayName ?? null;
  } catch {
    return null;
  }
}
