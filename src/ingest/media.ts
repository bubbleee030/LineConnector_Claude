/**
 * Optional media storage.
 *
 * Off unless `capture.storeMedia` is enabled, because downloading media means
 * keeping other people's photographs, voice notes and documents on disk — a
 * materially larger exposure than keeping their text.
 *
 * When it is enabled, files are encrypted at rest with the same key as message
 * bodies, and the bytes are never handed to the model. Tools report only that
 * a file exists and how large it is; retrieving the content is an operator
 * action through the CLI. This keeps a conversation summary from turning into
 * an image exfiltration path.
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { encryptField } from '../privacy/crypto.js';
import type { LineClient } from '../line/client.js';
import type { MessageType } from '../types.js';

const MEDIA_TYPES: ReadonlySet<MessageType> = new Set<MessageType>([
  'image',
  'video',
  'audio',
  'file',
]);

/** 20 MB. Beyond this the download is skipped rather than buffered. */
const MAX_MEDIA_BYTES = 20 * 1024 * 1024;

export function mediaDirectory(): string {
  return resolve(process.env.LINE_CONNECTOR_MEDIA_DIR ?? 'media');
}

export function isMediaMessage(type: MessageType): boolean {
  return MEDIA_TYPES.has(type);
}

export interface StoredMedia {
  /** File name inside the media directory. Never the original file name. */
  file: string;
  bytes: number;
}

/**
 * Downloads and stores one message's media.
 *
 * Returns null on any failure. Media retrieval is best-effort by nature —
 * LINE only keeps content for a limited window — and a missing photo is never
 * a reason to lose the message record it belonged to.
 */
export async function storeMedia(
  client: LineClient,
  messageLineId: string,
  storageKey: string,
  key: Buffer,
): Promise<StoredMedia | null> {
  try {
    const content = await client.getMessageContent(messageLineId);
    if (content.byteLength > MAX_MEDIA_BYTES) return null;

    const dir = mediaDirectory();
    mkdirSync(dir, { recursive: true, mode: 0o700 });

    // The file is named after the message's HMAC, so the media directory
    // listing does not reveal LINE message ids.
    const file = `${storageKey}.enc`;
    const ciphertext = encryptField(content.toString('base64'), key);
    writeFileSync(join(dir, file), ciphertext, { mode: 0o600 });

    return { file, bytes: content.byteLength };
  } catch {
    return null;
  }
}
