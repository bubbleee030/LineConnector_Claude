#!/usr/bin/env node
/**
 * Operator CLI.
 *
 * Everything destructive or consent-changing lives here and nowhere else. The
 * MCP server can read messages; it cannot grant itself access to a new
 * conversation, cannot turn off redaction, and cannot delete anyone's data.
 * Those are decisions a person makes at a terminal, which is the whole reason
 * this file exists rather than being three more MCP tools.
 *
 * This is also the only place that prints real LINE ids, since the operator
 * needs them to match a conversation against what they see in the LINE
 * console.
 */

import '../quiet.js';

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import {
  databasePath,
  defaultPrivacyConfig,
  loadPrivacyConfig,
  loadSecrets,
  privacyConfigSchema,
  sendingEnabled,
  type PrivacyConfig,
} from '../config.js';
import { Store } from '../db/index.js';
import { generateKeyHex } from '../privacy/crypto.js';
import { defaultEnabledRules, RULE_NAMES } from '../privacy/redact.js';
import { sweepRetention } from '../privacy/retention.js';
import { formatTimestamp, renderTranscript } from '../mcp/render.js';

const LINE_ID = /^[URC][0-9a-f]{32}$/;

function configPath(): string {
  return resolve(process.env.LINE_CONNECTOR_CONFIG ?? 'config/privacy.json');
}

function main(): void {
  const [command, ...args] = process.argv.slice(2);

  switch (command) {
    case 'init':
      return cmdInit();
    case 'keygen':
      return cmdKeygen();
    case 'status':
      return cmdStatus();
    case 'conversations':
      return cmdConversations();
    case 'allow':
      return cmdConsent('allow', args[0]);
    case 'deny':
      return cmdConsent('deny', args[0]);
    case 'forget':
      return cmdForget(args[0]);
    case 'purge':
      return cmdPurge();
    case 'audit':
      return cmdAudit(args[0]);
    case 'export':
      return cmdExport(args[0]);
    case 'help':
    case '--help':
    case undefined:
      return usage();
    default:
      console.error(`Unknown command: ${command}\n`);
      usage();
      process.exit(1);
  }
}

function usage(): void {
  console.log(
    `line-connector — operator commands

Setup
  init                 Generate an encryption key and a starter privacy config
  keygen               Print a fresh encryption key and exit

Consent
  conversations        List captured conversations with their real LINE ids
  allow <lineId>       Add a conversation to the capture allow list
  deny <lineId>        Add a conversation to the deny list (deny always wins)

Data
  status               Show the policy in force and what is currently stored
  export <handle>      Print one conversation as a transcript
  purge                Run the retention sweep now
  forget <lineId>      Erase everything for one user or group, permanently
  audit [n]            Show the last n access-log entries (default 20)

Conversation ids look like U or C followed by 32 hex characters. Find them with
\`conversations\`, or in the LINE Developers console.`,
  );
}

// -- setup --------------------------------------------------------------------

function cmdKeygen(): void {
  console.log(generateKeyHex());
}

function cmdInit(): void {
  const key = generateKeyHex();
  const path = configPath();

  if (existsSync(path)) {
    console.log(`Privacy config already exists at ${path} — leaving it alone.\n`);
  } else {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, `${JSON.stringify(starterConfig(), null, 2)}\n`, { mode: 0o600 });
    console.log(`Wrote a starter privacy config to ${path}\n`);
  }

  console.log(
    `Add this to your environment (it decrypts the message store — treat it like a password):

  export LINE_CONNECTOR_KEY=${key}

If you lose this key the stored messages are unrecoverable. If someone else
gets it and a copy of the database, they can read everything in it.

Next steps:
  1. Set LINE_CHANNEL_SECRET from the LINE Developers console.
  2. Start the webhook receiver:  npm run ingest
  3. Point your Official Account's webhook URL at it (HTTPS, publicly reachable).
  4. Allow-list the conversations you want captured:  npm run cli -- allow <lineId>

Nothing is recorded until step 4 — the default policy denies every conversation.`,
  );
}

function starterConfig(): PrivacyConfig {
  const config = defaultPrivacyConfig();
  // Write the redaction rules out explicitly rather than leaving them implicit,
  // so the file shows what is actually running instead of an empty object.
  for (const rule of RULE_NAMES) {
    config.redaction.rules[rule] = defaultEnabledRules().includes(rule);
  }
  return config;
}

// -- consent ------------------------------------------------------------------

function cmdConsent(list: 'allow' | 'deny', lineId: string | undefined): void {
  if (lineId === undefined || !LINE_ID.test(lineId)) {
    console.error(
      `Expected a LINE id: U or C followed by 32 hex characters. Run \`conversations\` to see the ids that have messaged this account.`,
    );
    process.exit(1);
  }

  const path = configPath();
  const config = loadPrivacyConfig();
  const target = config.capture[list];

  if (target.includes(lineId)) {
    console.log(`${lineId} is already on the ${list} list.`);
    return;
  }

  target.push(lineId);
  // Remove it from the opposing list, so the two never disagree. Deny still
  // wins when both are set, but leaving a stale entry behind is confusing.
  const other = list === 'allow' ? 'deny' : 'allow';
  const stale = config.capture[other].indexOf(lineId);
  if (stale !== -1) {
    config.capture[other].splice(stale, 1);
    console.log(`Removed ${lineId} from the ${other} list.`);
  }

  writeConfig(path, config);
  console.log(
    `Added ${lineId} to the ${list} list.\n\nRestart the ingest server for this to take effect.`,
  );
  if (list === 'allow') {
    console.log(
      'Only messages sent from now on will be captured — LINE provides no access to past chat history.',
    );
  }
}

function writeConfig(path: string, config: PrivacyConfig): void {
  // Re-validate before writing: a hand-edited file that we then append to
  // should not be silently rewritten into something invalid.
  const validated = privacyConfigSchema.parse(config);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(validated, null, 2)}\n`, { mode: 0o600 });
}

// -- inspection ---------------------------------------------------------------

function cmdStatus(): void {
  const config = loadPrivacyConfig();
  const store = openStore();

  const conversations = store.listConversations();
  const oldest = store.oldestMessageTimestamp();

  console.log(`Privacy config: ${configPath()}`);
  console.log(`Message store:  ${databasePath()}\n`);

  console.log('Capture');
  console.log(`  enabled:        ${config.capture.enabled ? 'yes' : 'NO (kill switch on)'}`);
  console.log(`  mode:           ${config.capture.mode}`);
  console.log(`  allow list:     ${config.capture.allow.length} conversation(s)`);
  console.log(`  deny list:      ${config.capture.deny.length} conversation(s)`);
  console.log(`  message text:   ${config.capture.storeText}`);
  console.log(`  media:          ${config.capture.storeMedia ? 'stored' : 'not stored'}`);
  console.log(`  location:       ${config.capture.storeLocation}`);
  console.log(`  display names:  ${config.capture.resolveDisplayNames ? 'resolved' : 'not resolved'}`);

  console.log('\nRedaction');
  const active = RULE_NAMES.filter(
    (r) => config.redaction.rules[r] ?? defaultEnabledRules().includes(r),
  );
  console.log(`  active rules:   ${active.join(', ') || 'none'}`);
  console.log(`  custom rules:   ${config.redaction.custom.length}`);

  console.log('\nRetention');
  console.log(`  messages:       ${config.retention.days === 0 ? 'kept indefinitely' : `${config.retention.days} days`}`);
  console.log(`  sweep every:    ${config.retention.sweepIntervalMinutes} minute(s)`);
  console.log(`  audit log:      ${config.audit.enabled ? `${config.audit.retentionDays} days` : 'disabled'}`);

  console.log('\nModel access');
  console.log(
    `  readable:       ${config.mcp.readable === null ? 'all captured conversations' : `${config.mcp.readable.length} conversation(s)`}`,
  );
  console.log(`  sender ids:     ${config.mcp.exposeSenderIds ? 'REAL LINE IDS' : 'pseudonyms'}`);
  console.log(`  per-call cap:   ${config.mcp.maxMessagesPerCall} messages / ${config.mcp.maxCharsPerCall} chars`);
  console.log(`  sending:        ${sendingEnabled(config) ? 'ENABLED' : 'disabled'}`);

  console.log('\nStored now');
  console.log(`  conversations:  ${conversations.length}`);
  console.log(`  messages:       ${store.countMessages()}`);
  console.log(`  oldest:         ${oldest === null ? 'none' : formatTimestamp(oldest)}`);

  if (config.capture.mode === 'denyByDefault' && config.capture.allow.length === 0) {
    console.log('\nNothing is allow-listed, so nothing is being captured.');
  }

  store.close();
}

function cmdConversations(): void {
  const store = openStore();
  const conversations = store.listConversations();

  if (conversations.length === 0) {
    console.log(
      'No conversations captured yet.\n\nThe ingest server must be running and the conversation allow-listed before anything is recorded.',
    );
    store.close();
    return;
  }

  console.log(`${conversations.length} conversation(s):\n`);
  for (const c of conversations) {
    const name = c.displayName !== null ? ` "${c.displayName}"` : '';
    console.log(`  ${c.lineId}${name}`);
    console.log(`    handle:   ${c.pseudonym}   (this is what Claude sees)`);
    console.log(`    type:     ${c.sourceType}`);
    console.log(`    messages: ${c.messageCount}`);
    console.log(
      `    last:     ${c.lastMessageAt === null ? 'never' : formatTimestamp(c.lastMessageAt)}\n`,
    );
  }

  store.close();
}

function cmdExport(handle: string | undefined): void {
  if (handle === undefined) {
    console.error('Usage: export <handle|lineId>');
    process.exit(1);
  }

  const config = loadPrivacyConfig();
  const store = openStore();
  const conversation = store.findConversation(handle);

  if (conversation === null) {
    console.error(`No conversation matches ${JSON.stringify(handle)}.`);
    store.close();
    process.exit(1);
  }

  const messages = store.queryMessages({
    conversationId: conversation.id,
    limit: config.mcp.maxMessagesPerCall,
  });

  console.log(`Conversation ${conversation.lineId} (${conversation.sourceType})`);
  console.log(`${messages.length} message(s)\n`);
  // The operator gets the unclamped character budget; the cap exists to bound
  // what leaves the machine toward the model, not what the owner can read.
  console.log(
    renderTranscript(messages, { ...config, mcp: { ...config.mcp, maxCharsPerCall: 200_000 } }, {
      conversation,
    }),
  );

  store.close();
}

function cmdAudit(countArg: string | undefined): void {
  const limit = Number.parseInt(countArg ?? '20', 10);
  const store = openStore();
  const entries = store.readAudit(Number.isFinite(limit) && limit > 0 ? limit : 20);

  if (entries.length === 0) {
    console.log('Audit log is empty.');
    store.close();
    return;
  }

  console.log(`Last ${entries.length} access-log entries (most recent first):\n`);
  for (const e of entries) {
    const count = e.result_count === null ? '' : ` → ${e.result_count} row(s)`;
    const detail = e.detail === '' ? '' : `  ${e.detail}`;
    console.log(`  ${formatTimestamp(e.ts)}  ${e.actor.padEnd(6)} ${e.action}${count}${detail}`);
  }

  store.close();
}

// -- deletion -----------------------------------------------------------------

function cmdPurge(): void {
  const config = loadPrivacyConfig();
  const store = openStore();
  const result = sweepRetention(store, config);

  console.log(
    `Purged ${result.messagesDeleted} message(s), removed ${result.conversationsRemoved} empty conversation(s), dropped ${result.auditEntriesDeleted} audit entr(ies).`,
  );
  if (result.messagesDeleted > 0) {
    console.log('Database was rewritten, so the deleted content is no longer recoverable.');
  }

  store.close();
}

function cmdForget(lineId: string | undefined): void {
  if (lineId === undefined || !LINE_ID.test(lineId)) {
    console.error('Usage: forget <lineId>   (U or C followed by 32 hex characters)');
    process.exit(1);
  }

  const store = openStore();
  const result = store.forget(lineId);
  // Without this the deleted text stays readable in the file's free pages,
  // which would make "forget" a claim rather than a fact.
  store.vacuum();

  console.log(
    `Erased ${result.messages} message(s) and ${result.conversations} conversation record(s) for ${lineId}.`,
  );
  console.log('The database was rewritten, so the content is not recoverable from the file.');
  console.log(
    '\nNote: this does not stop future capture. Run `deny ' +
      lineId +
      '` as well if that is what you want.',
  );

  store.close();
}

// -- shared -------------------------------------------------------------------

function openStore(): Store {
  const secrets = loadSecrets();
  if (secrets.encryptionKey === null) {
    console.error(
      'LINE_CONNECTOR_KEY is not set. The message store is encrypted and cannot be opened without it.\n\nIf this is a first run, generate one with:  npm run cli -- init',
    );
    process.exit(1);
  }
  if (!existsSync(databasePath())) {
    console.error(
      `No message store at ${databasePath()} yet. It is created when the ingest server first records a message.`,
    );
    process.exit(1);
  }
  return new Store(databasePath(), secrets.encryptionKey);
}

// Reading the config early surfaces a malformed file with a clear message
// rather than a stack trace from somewhere deeper in a command.
try {
  if (existsSync(configPath())) {
    readFileSync(configPath(), 'utf8');
  }
  main();
} catch (err) {
  console.error((err as Error).message);
  process.exit(1);
}
