#!/usr/bin/env node
/**
 * The webhook receiver.
 *
 * LINE has no endpoint for reading chat history — the Messaging API only
 * pushes each message once, as it happens. This process is therefore the only
 * thing that ever sees a message, and anything it does not record is gone for
 * good. It has to be running before a conversation happens to have any record
 * of it.
 *
 * Built on node:http rather than a framework. The whole server is one request
 * handler, and a body parser that hands back raw bytes is a requirement here
 * rather than an inconvenience: the signature is computed over exactly what
 * arrived on the wire.
 */

import '../quiet.js';

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';

import {
  databasePath,
  ingestPort,
  loadPrivacyConfig,
  loadSecrets,
  type PrivacyConfig,
} from '../config.js';
import { Store } from '../db/index.js';
import { LineClient } from '../line/client.js';
import { extractEvents, normalizeEvent } from '../line/normalize.js';
import { verifySignature } from '../line/signature.js';
import { safeEqual } from '../privacy/crypto.js';
import { startRetentionSweeper } from '../privacy/retention.js';
import { normalizeNotification } from './notify.js';
import {
  processAction,
  processNotification,
  type Outcome,
  type PipelineContext,
} from './pipeline.js';

/** LINE webhook bodies are small; anything larger is not from LINE. */
const MAX_BODY_BYTES = 1024 * 1024;

const WEBHOOK_PATH = process.env.LINE_CONNECTOR_WEBHOOK_PATH ?? '/webhook';
const NOTIFY_PATH = process.env.LINE_CONNECTOR_NOTIFY_PATH ?? '/notify';

function main(): void {
  const config = loadPrivacyConfig();
  const secrets = loadSecrets();

  // Either intake may be used on its own: an Official Account webhook, a
  // phone notification relay, or both. Requiring the LINE channel secret
  // unconditionally would block the notification-only setup, which is the
  // one that works for personal chats.
  const notifySecret = process.env.LINE_CONNECTOR_NOTIFY_SECRET?.trim() ?? null;
  if (secrets.channelSecret === null && notifySecret === null) {
    fail(
      'Neither intake is configured. Set LINE_CHANNEL_SECRET to receive Official Account webhooks, or LINE_CONNECTOR_NOTIFY_SECRET to receive relayed phone notifications, or both.',
    );
  }
  if (secrets.encryptionKey === null) {
    fail(
      'LINE_CONNECTOR_KEY is not set. Run `npm run cli -- init` to generate one, then export it before starting the ingest server.',
    );
  }

  const store = new Store(databasePath(), secrets.encryptionKey);
  const needsClient = config.capture.resolveDisplayNames || config.capture.storeMedia;

  if (needsClient && secrets.channelAccessToken === null) {
    fail(
      'capture.resolveDisplayNames or capture.storeMedia is enabled, which requires LINE_CHANNEL_ACCESS_TOKEN.',
    );
  }

  const ctx: PipelineContext = {
    store,
    config,
    encryptionKey: secrets.encryptionKey,
    client:
      needsClient && secrets.channelAccessToken !== null
        ? new LineClient(secrets.channelAccessToken)
        : null,
  };

  startRetentionSweeper(store, config, (result) => {
    if (result.messagesDeleted > 0 || result.conversationsRemoved > 0) {
      console.log(
        `[retention] purged ${result.messagesDeleted} message(s), ${result.conversationsRemoved} conversation(s)`,
      );
    }
  });

  const server = createServer((req, res) => {
    handleRequest(req, res, ctx, secrets.channelSecret).catch((err: unknown) => {
      console.error('[ingest] unhandled error:', (err as Error).message);
      if (!res.headersSent) respond(res, 500, 'internal error');
    });
  });

  const port = ingestPort();
  server.listen(port, () => {
    const intakes: string[] = [];
    if (secrets.channelSecret !== null) intakes.push(`${WEBHOOK_PATH} (Official Account webhook)`);
    if (notifySecret !== null) intakes.push(`${NOTIFY_PATH} (phone notification relay)`);
    console.log(`[ingest] listening on http://127.0.0.1:${port}`);
    console.log(`[ingest] intakes: ${intakes.join(', ')}`);
    printPolicySummary(config, { notifyEnabled: notifySecret !== null });
  });

  const shutdown = (): void => {
    console.log('\n[ingest] shutting down');
    server.close(() => {
      store.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  ctx: PipelineContext,
  channelSecret: string | null,
): Promise<void> {
  const url = req.url ?? '/';

  if (req.method === 'GET' && url.startsWith('/healthz')) {
    // Deliberately says nothing about who has messaged or how much is stored;
    // this endpoint may be exposed to whatever is in front of the server.
    respond(res, 200, JSON.stringify({ status: 'ok' }), 'application/json');
    return;
  }

  if (req.method === 'POST' && url.startsWith(NOTIFY_PATH)) {
    await handleNotification(req, res, ctx);
    return;
  }

  if (req.method !== 'POST' || !url.startsWith(WEBHOOK_PATH)) {
    respond(res, 404, 'not found');
    return;
  }

  if (channelSecret === null) {
    respond(res, 503, 'webhook intake is not configured');
    return;
  }

  let rawBody: Buffer;
  try {
    rawBody = await readBody(req);
  } catch (err) {
    respond(res, 413, (err as Error).message);
    return;
  }

  if (!verifySignature(rawBody, req.headers['x-line-signature'], channelSecret)) {
    // No detail in the response: an attacker probing this endpoint learns only
    // that it rejected them.
    console.warn('[ingest] rejected a request with an invalid signature');
    respond(res, 401, 'invalid signature');
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    respond(res, 400, 'invalid json');
    return;
  }

  // Acknowledge before processing. LINE times out quickly and retries on
  // failure; since storage is idempotent on message id, a retry costs nothing
  // while a timeout would make LINE mark the endpoint unhealthy.
  respond(res, 200, 'ok');

  const events = extractEvents(parsed);
  const tally: Partial<Record<Outcome, number>> = {};

  for (const event of events) {
    try {
      const action = normalizeEvent(event, ctx.config);
      const { outcome } = await processAction(action, ctx);
      tally[outcome] = (tally[outcome] ?? 0) + 1;
    } catch (err) {
      console.error('[ingest] failed to process an event:', (err as Error).message);
    }
  }

  if (events.length > 0) {
    // Counts only. Logging ids or content here would create a plaintext copy
    // of exactly the data the store goes to some trouble to encrypt.
    console.log(
      `[ingest] ${events.length} event(s): ` +
        Object.entries(tally)
          .map(([k, v]) => `${k}=${v}`)
          .join(' '),
    );
  }
}

/**
 * Accepts a notification relayed from a phone.
 *
 * This is the path that reads a personal chat without sending a read receipt:
 * the message is captured from the Android notification as the OS posts it,
 * so nothing ever reaches LINE's servers to mark it read.
 *
 * Authenticated with a bearer token rather than an HMAC signature, because
 * the clients are phone automation apps whose HTTP actions can set a header
 * but cannot compute a signature. That makes TLS non-optional: without it the
 * token is on the wire in the clear.
 */
async function handleNotification(
  req: IncomingMessage,
  res: ServerResponse,
  ctx: PipelineContext,
): Promise<void> {
  const secret = process.env.LINE_CONNECTOR_NOTIFY_SECRET?.trim();
  if (!secret) {
    respond(res, 503, 'notification relay is not configured');
    return;
  }

  const header = req.headers.authorization;
  const presented = typeof header === 'string' ? header.replace(/^Bearer\s+/i, '') : '';
  if (!safeEqual(presented, secret)) {
    console.warn('[notify] rejected a request with a bad token');
    respond(res, 401, 'unauthorized');
    return;
  }

  let rawBody: Buffer;
  try {
    rawBody = await readBody(req);
  } catch (err) {
    respond(res, 413, (err as Error).message);
    return;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    respond(res, 400, 'invalid json');
    return;
  }

  const result = normalizeNotification(parsed);
  if (!result.ok) {
    // A 200 with a reason: the relay forwards every notification on the
    // device, and a non-LINE one being ignored is normal, not a failure the
    // phone should retry or alert on.
    respond(res, 200, JSON.stringify({ stored: false, reason: result.reason }), 'application/json');
    return;
  }

  const { outcome } = processNotification(result.message, ctx);
  console.log(`[notify] ${outcome}`);
  respond(res, 200, JSON.stringify({ stored: outcome === 'stored' }), 'application/json');
}

/** Reads the request body, refusing anything oversized. */
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;

    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function respond(res: ServerResponse, status: number, body: string, contentType = 'text/plain'): void {
  res.writeHead(status, {
    'Content-Type': contentType,
    // This endpoint has no browser-facing surface; make that explicit.
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function printPolicySummary(config: PrivacyConfig, opts: { notifyEnabled: boolean }): void {
  const { capture, retention } = config;
  const scope =
    capture.mode === 'denyByDefault'
      ? `${capture.allow.length} allow-listed conversation(s)`
      : 'every conversation except the deny list';

  console.log(
    [
      `[policy] capture: ${capture.enabled ? 'on' : 'OFF (kill switch)'}, webhook scope: ${scope}`,
      `[policy] message text: ${capture.storeText}, media: ${capture.storeMedia ? 'stored' : 'not stored'}, location: ${capture.storeLocation}`,
      `[policy] retention: ${retention.days === 0 ? 'indefinite' : `${retention.days} days`}, sweep every ${retention.sweepIntervalMinutes} min`,
    ].join('\n'),
  );

  // The allow list gates webhook traffic only. Relayed notifications are the
  // operator's own device and bypass it, so the "nothing allow-listed" warning
  // is only true when the webhook is the sole intake.
  if (capture.mode === 'denyByDefault' && capture.allow.length === 0 && !opts.notifyEnabled) {
    console.warn(
      '[policy] nothing is allow-listed, so no webhook messages will be stored. Add conversation ids with `npm run cli -- allow <id>`.',
    );
  }
  if (opts.notifyEnabled) {
    console.log(
      '[policy] notification relay bypasses the allow list (it is your own device); the deny list and kill switch still apply.',
    );
  }
}

function fail(message: string): never {
  console.error(`[ingest] ${message}`);
  process.exit(1);
}

main();
