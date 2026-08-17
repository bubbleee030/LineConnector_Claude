/**
 * Configuration loading and validation.
 *
 * Two separate sources, deliberately:
 *
 *   - Secrets come from the environment (channel secret, access token,
 *     encryption key). They are never written to the config file.
 *   - Privacy policy comes from a JSON file that is meant to be read, edited
 *     and reviewed by a human. Everything that decides what gets stored and
 *     what Claude can see lives there, in one auditable place.
 *
 * Every default here is the conservative one. A config file that is missing,
 * empty, or partial yields the most private behaviour, not the most useful.
 */

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'zod';

/**
 * A conversation identifier.
 *
 * U/R/C are LINE's own prefixes for users, rooms and chats. X is this
 * project's prefix for a conversation imported from a LINE chat export, which
 * carries no LINE-issued id — the rest is derived deterministically from the
 * chat name so re-importing the same chat lands in the same conversation.
 */
const lineIdSchema = z
  .string()
  .regex(/^[URCX][0-9a-f]{32}$/, 'must be a conversation id: U/R/C/X followed by 32 hex chars');

const captureSchema = z
  .object({
    /** Master kill switch. When false, the webhook still 200s but stores nothing. */
    enabled: z.boolean().default(true),
    /**
     * denyByDefault: only conversations in `allow` are captured. This is the
     * default because a webhook receives everything sent to the Official
     * Account, including from people who never intended to talk to a bot.
     */
    mode: z.enum(['denyByDefault', 'allowByDefault']).default('denyByDefault'),
    allow: z.array(lineIdSchema).default([]),
    deny: z.array(lineIdSchema).default([]),
    /**
     * full     - store message text verbatim (no redaction). Opt-in only.
     * redacted - run the redaction engine, store the result. Default.
     * none     - store metadata only; no message body ever touches disk.
     */
    storeText: z.enum(['full', 'redacted', 'none']).default('redacted'),
    /** Downloading media means storing other people's photos. Off by default. */
    storeMedia: z.boolean().default(false),
    /**
     * Shared locations are among the most sensitive things LINE carries.
     * none    - record only that a location was shared. Default.
     * coarse  - round coordinates to 2 decimals, roughly a 1km square.
     * precise - store exactly what was sent.
     */
    storeLocation: z.enum(['none', 'coarse', 'precise']).default('none'),
    /** File names routinely contain names, case numbers and dates. */
    storeFileNames: z.boolean().default(false),
    /** Calling the profile API to turn userIds into real names. Off by default. */
    resolveDisplayNames: z.boolean().default(false),
    /** Whether the Official Account's own replies are recorded too. */
    storeOutbound: z.boolean().default(true),
  })
  .strict()
  .default({});

const redactionSchema = z
  .object({
    /**
     * Built-in rule names map to booleans. Unlisted rules keep their default.
     * See src/privacy/redact.ts for the rule catalogue.
     */
    rules: z.record(z.string(), z.boolean()).default({}),
    custom: z
      .array(
        z
          .object({
            name: z.string().min(1),
            pattern: z.string().min(1),
            flags: z.string().regex(/^[gimsuy]*$/).default('g'),
            replacement: z.string().default('[redacted:custom]'),
          })
          .strict(),
      )
      .default([]),
  })
  .strict()
  .default({});

const retentionSchema = z
  .object({
    /** Messages older than this are hard-deleted. 0 disables time-based purge. */
    days: z.number().int().min(0).max(3650).default(30),
    sweepIntervalMinutes: z.number().int().min(1).max(1440).default(60),
    /** Tighter retention for specific conversations, keyed by LINE id. */
    perConversationDays: z.record(lineIdSchema, z.number().int().min(0).max(3650)).default({}),
  })
  .strict()
  .default({});

const mcpSchema = z
  .object({
    /**
     * Narrows what the model can read, independent of what is captured.
     * null means "everything that was captured". An array means only these.
     */
    readable: z.array(lineIdSchema).nullable().default(null),
    /** Hard cap on rows returned by a single tool call. */
    maxMessagesPerCall: z.number().int().min(1).max(1000).default(100),
    /** Hard cap on total characters returned by a single tool call. */
    maxCharsPerCall: z.number().int().min(500).max(200_000).default(20_000),
    defaultLookbackDays: z.number().int().min(1).max(3650).default(30),
    /** Sending is a side effect on someone else's phone. Off by default. */
    allowSend: z.boolean().default(false),
    /**
     * When false, real LINE userIds are replaced with stable per-install
     * pseudonyms before anything reaches the model.
     */
    exposeSenderIds: z.boolean().default(false),
  })
  .strict()
  .default({});

const auditSchema = z
  .object({
    enabled: z.boolean().default(true),
    retentionDays: z.number().int().min(1).max(3650).default(90),
  })
  .strict()
  .default({});

export const privacyConfigSchema = z
  .object({
    capture: captureSchema,
    redaction: redactionSchema,
    retention: retentionSchema,
    mcp: mcpSchema,
    audit: auditSchema,
  })
  .strict();

export type PrivacyConfig = z.infer<typeof privacyConfigSchema>;

/** The all-defaults policy, used when no config file is present. */
export function defaultPrivacyConfig(): PrivacyConfig {
  return privacyConfigSchema.parse({});
}

/**
 * Reads and validates the privacy policy.
 *
 * A malformed config is fatal rather than ignored: silently falling back to
 * defaults when someone wrote a policy they believed was in effect is exactly
 * the failure mode this whole project exists to avoid.
 */
export function loadPrivacyConfig(path?: string): PrivacyConfig {
  const configPath = resolve(path ?? process.env.LINE_CONNECTOR_CONFIG ?? 'config/privacy.json');

  let raw: string;
  try {
    raw = readFileSync(configPath, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return defaultPrivacyConfig();
    }
    throw err;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Privacy config at ${configPath} is not valid JSON: ${(err as Error).message}`);
  }

  const result = privacyConfigSchema.safeParse(parsed);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
      .join('\n');
    throw new Error(`Privacy config at ${configPath} is invalid:\n${issues}`);
  }
  return result.data;
}

export interface Secrets {
  channelSecret: string | null;
  channelAccessToken: string | null;
  encryptionKey: Buffer | null;
}

/**
 * Loads secrets from the environment.
 *
 * Nothing here throws on absence. Different processes need different subsets:
 * the MCP server needs only the encryption key, while the ingest server needs
 * the channel secret too. Each caller asserts what it actually requires.
 */
export function loadSecrets(): Secrets {
  const keyHex = process.env.LINE_CONNECTOR_KEY?.trim();
  const keyFile = process.env.LINE_CONNECTOR_KEY_FILE?.trim();

  let encryptionKey: Buffer | null = null;
  if (keyHex) {
    encryptionKey = decodeKey(keyHex, 'LINE_CONNECTOR_KEY');
  } else if (keyFile) {
    encryptionKey = decodeKey(readFileSync(resolve(keyFile), 'utf8').trim(), keyFile);
  }

  return {
    channelSecret: process.env.LINE_CHANNEL_SECRET?.trim() || null,
    channelAccessToken: process.env.LINE_CHANNEL_ACCESS_TOKEN?.trim() || null,
    encryptionKey,
  };
}

function decodeKey(hex: string, source: string): Buffer {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error(`${source} must be exactly 64 hex characters (a 32-byte AES-256 key)`);
  }
  return Buffer.from(hex, 'hex');
}

export function databasePath(): string {
  return resolve(process.env.LINE_CONNECTOR_DB ?? 'data/line.db');
}

export function ingestPort(): number {
  const raw = process.env.LINE_CONNECTOR_PORT ?? '8787';
  const port = Number.parseInt(raw, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`LINE_CONNECTOR_PORT must be a valid port number, got ${JSON.stringify(raw)}`);
  }
  return port;
}

/**
 * Sending requires agreement from both the policy file and the environment.
 * Two independent switches means neither a stray config edit nor a stray env
 * var alone can give the model the ability to message a real person.
 */
export function sendingEnabled(config: PrivacyConfig): boolean {
  return config.mcp.allowSend && process.env.LINE_CONNECTOR_ALLOW_SEND === 'true';
}
