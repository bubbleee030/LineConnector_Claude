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
import { startRetentionSweeper } from '../privacy/retention.js';
import { processAction, type Outcome, type PipelineContext } from './pipeline.js';

/** LINE webhook bodies are small; anything larger is not from LINE. */
const MAX_BODY_BYTES = 1024 * 1024;

const WEBHOOK_PATH = process.env.LINE_CONNECTOR_WEBHOOK_PATH ?? '/webhook';

function main(): void {
  const config = loadPrivacyConfig();
  const secrets = loadSecrets();

  if (secrets.channelSecret === null) {
    fail(
      'LINE_CHANNEL_SECRET is not set. Without it, webhook signatures cannot be verified and anyone could post fake messages to this endpoint.',
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
    handleRequest(req, res, ctx, secrets.channelSecret as string).catch((err: unknown) => {
      console.error('[ingest] unhandled error:', (err as Error).message);
      if (!res.headersSent) respond(res, 500, 'internal error');
    });
  });

  const port = ingestPort();
  server.listen(port, () => {
    console.log(`[ingest] listening on http://127.0.0.1:${port}${WEBHOOK_PATH}`);
    printPolicySummary(config);
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
  channelSecret: string,
): Promise<void> {
  const url = req.url ?? '/';

  if (req.method === 'GET' && url.startsWith('/healthz')) {
    // Deliberately says nothing about who has messaged or how much is stored;
    // this endpoint may be exposed to whatever is in front of the server.
    respond(res, 200, JSON.stringify({ status: 'ok' }), 'application/json');
    return;
  }

  if (req.method !== 'POST' || !url.startsWith(WEBHOOK_PATH)) {
    respond(res, 404, 'not found');
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

function printPolicySummary(config: PrivacyConfig): void {
  const { capture, retention } = config;
  const scope =
    capture.mode === 'denyByDefault'
      ? `${capture.allow.length} allow-listed conversation(s)`
      : 'every conversation except the deny list';

  console.log(
    [
      `[policy] capture: ${capture.enabled ? 'on' : 'OFF (kill switch)'}, scope: ${scope}`,
      `[policy] message text: ${capture.storeText}, media: ${capture.storeMedia ? 'stored' : 'not stored'}, location: ${capture.storeLocation}`,
      `[policy] retention: ${retention.days === 0 ? 'indefinite' : `${retention.days} days`}, sweep every ${retention.sweepIntervalMinutes} min`,
    ].join('\n'),
  );

  if (capture.mode === 'denyByDefault' && capture.allow.length === 0) {
    console.warn(
      '[policy] nothing is allow-listed, so no messages will be stored. Add conversation ids with `npm run cli -- allow <id>`.',
    );
  }
}

function fail(message: string): never {
  console.error(`[ingest] ${message}`);
  process.exit(1);
}

main();
