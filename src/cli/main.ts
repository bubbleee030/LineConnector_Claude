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
import { importExport } from '../import/importer.js';
import { parseLineExport } from '../import/lineExport.js';
import { formatTimestamp, renderTranscript } from '../mcp/render.js';

const LINE_ID = /^[URCX][0-9a-f]{32}$/;

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
    case 'import':
      return cmdImport(args);
    case 'forget':
      return cmdForget(args[0]);
    case 'purge':
      return cmdPurge();
    case 'audit':
      return cmdAudit(args[0]);
    case 'export':
      return cmdExport(args[0]);
    case 'setup-relay':
      return cmdSetupRelay(args);
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
  setup-relay          Set up the notification relay for personal chats

Consent
  conversations        List captured conversations with their real LINE ids
  allow <lineId>       Add a conversation to the capture allow list
  deny <lineId>        Add a conversation to the deny list (deny always wins)

Data
  status               Show the policy in force and what is currently stored
  import <file>        Import a LINE chat-export .txt (see options below)
  export <handle>      Print one conversation as a transcript
  purge                Run the retention sweep now
  forget <lineId>      Erase everything for one user or group, permanently
  audit [n]            Show the last n access-log entries (default 20)

Import options
  --me <name>          Your display name in the export, so your own messages
                       are marked as sent rather than received
  --title <name>       Override the chat name (needed if the header is missing)
  --retain-days <n>    Retention for this chat. Defaults to 0 (keep forever),
                       because imported history is usually older than the
                       global retention window and would be purged at once.

Relay options
  --url <host>         Server URL (e.g. https://myhost.example.com)
  --all                Show instructions for all platforms

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

Nothing is recorded until step 4 — the default policy denies every conversation.

For personal chats (not just the Official Account), run:
  npm run cli -- setup-relay

It sets up a notification relay so Claude can read your messages without
sending read receipts — works on Android, macOS, Windows, and iOS via Mac.`,
  );
}

function cmdSetupRelay(args: string[]): void {
  const existing = process.env.LINE_CONNECTOR_NOTIFY_SECRET?.trim();
  const secret = existing || generateKeyHex();
  const urlFlag = args.indexOf('--url');
  const serverUrl = urlFlag !== -1 && args[urlFlag + 1]
    ? args[urlFlag + 1] as string
    : '<your-server>';

  const notifyUrl = serverUrl.startsWith('http')
    ? `${serverUrl.replace(/\/+$/, '')}/notify`
    : `https://${serverUrl}/notify`;

  if (existing) {
    console.log('Using existing LINE_CONNECTOR_NOTIFY_SECRET from environment.\n');
  } else {
    console.log('Generated a new relay secret:\n');
    console.log(`  ${secret}\n`);
    console.log('Add this to the ingest server\'s environment and restart it:\n');
    console.log(`  export LINE_CONNECTOR_NOTIFY_SECRET=${secret}\n`);
  }

  const platform = process.platform;
  const allPlatforms = args.includes('--all');
  const show = (p: string) => allPlatforms || platform === p;

  if (!allPlatforms && platform === 'linux') {
    console.log(
      'This machine is Linux — the ingest server runs here, but the relay\n' +
      'runs on the device where you receive LINE notifications.\n' +
      'Showing instructions for all platforms:\n',
    );
  }

  const showAll = allPlatforms || platform === 'linux';

  // ---- Android ----
  if (showAll || platform === 'android') {
    console.log(
      '── Android (recommended — easiest, most reliable) ──\n\n' +
      '  Install MacroDroid (free on Play Store), then create a macro:\n\n' +
      '  Trigger:  Notification Received → application LINE\n' +
      '  Action:   HTTP Request (POST)\n' +
      `    URL:    ${notifyUrl}\n` +
      '    Headers:\n' +
      `      Authorization: Bearer ${secret}\n` +
      '      Content-Type: application/json\n' +
      '    Body:\n' +
      '      {"app":"jp.naver.line.android","chat":"{notification_title}",\n' +
      '       "text":"{notification_text}","postedAt":{trigger_time}}\n\n' +
      '  Grant MacroDroid notification access when prompted.\n' +
      '  Tasker and Automate (LlamaLab) work the same way.\n',
    );
  }

  // ---- macOS ----
  if (showAll || platform === 'darwin') {
    console.log(
      '── macOS ──\n\n' +
      '  Requirement: Full Disk Access for Terminal\n' +
      '  (System Settings → Privacy & Security → Full Disk Access)\n\n' +
      `  export LINE_CONNECTOR_NOTIFY_SECRET=${secret}\n` +
      `  export LINE_CONNECTOR_NOTIFY_URL=${notifyUrl}\n` +
      '  python3 scripts/relay/macos-relay.py\n\n' +
      '  Run with --once --verbose first to verify it reads notifications.\n\n' +
      '  The relay also captures iPhone notifications if you have an iPhone\n' +
      '  on the same Apple ID with notification mirroring enabled.\n',
    );
  }

  // ---- Windows ----
  if (showAll || platform === 'win32') {
    console.log(
      '── Windows ──\n\n' +
      '  Requirement: Windows 10 1709+, LINE desktop app running\n\n' +
      `  $env:LINE_CONNECTOR_NOTIFY_SECRET = "${secret}"\n` +
      `  $env:LINE_CONNECTOR_NOTIFY_URL = "${notifyUrl}"\n` +
      '  .\\scripts\\relay\\windows-relay.ps1\n\n' +
      '  Run with -Once -Verbose first to verify it reads notifications.\n' +
      '  First run prompts for notification access — grant it in\n' +
      '  Settings → Privacy → Notifications.\n',
    );
  }

  // ---- iOS ----
  if (showAll) {
    console.log(
      '── iOS ──\n\n' +
      '  iOS cannot read other apps\' notifications directly (Apple sandbox).\n' +
      '  Mirror your iPhone to a Mac, then use the macOS relay above.\n' +
      '  (Same Apple ID, Settings → Notifications → iPhone notification mirroring.)\n\n' +
      '  For specific threads without a Mac, use LINE\'s export:\n' +
      '    npm run cli -- import ~/Downloads/chat.txt --me "Your Name"\n',
    );
  }

  console.log(
    '── How it works ──\n\n' +
    '  The relay reads notifications your OS already delivered — it never\n' +
    '  contacts LINE, never opens the chat, never sends a read receipt.\n' +
    '  Messages arrive as previews (long texts truncate, media shows as\n' +
    '  [Photo]). For the full text of a specific thread, use the import\n' +
    '  command after an export from LINE.\n\n' +
    '  The ingest server must be reachable over HTTPS from your device.\n' +
    '  For local development, put a tunnel in front of it:\n' +
    '    npm run ingest\n' +
    '    cloudflared tunnel --url http://localhost:8787\n',
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

/**
 * Imports a LINE chat-export file.
 *
 * This is the only route to a personal conversation: the Messaging API cannot
 * see personal chats, so an export produced by the LINE app is the data
 * source. Everything imported goes through the same redaction and encryption
 * as webhook traffic.
 */
function cmdImport(args: string[]): void {
  const flags = parseFlags(args);
  const file = flags.positional[0];

  if (file === undefined) {
    console.error('Usage: import <file.txt> [--me <name>] [--title <name>] [--retain-days <n>]');
    process.exit(1);
  }

  let content: string;
  try {
    content = readFileSync(resolve(file), 'utf8');
  } catch (err) {
    console.error(`Could not read ${file}: ${(err as Error).message}`);
    process.exit(1);
  }

  const config = loadPrivacyConfig();
  const store = openStore({ create: true });

  const parsed = parseLineExport(content);
  if (parsed.messages.length === 0) {
    console.error(
      `No messages found in ${file}.\n\nExpected a LINE chat export: open a chat in LINE, then Settings → Export chat history. If this is such a file, it may use a layout this parser does not recognise — the first few lines would help.`,
    );
    store.close();
    process.exit(1);
  }

  const selfLabels = flags.me === undefined ? [] : [flags.me];
  const result = importExport(store, config, parsed, {
    selfLabels,
    ...(flags.title !== undefined ? { title: flags.title } : {}),
  });

  console.log(`Imported "${result.title}" (${result.sourceType})`);
  console.log(`  conversation id: ${result.conversationId}`);
  console.log(`  messages added:  ${result.imported}`);
  if (result.duplicates > 0) {
    console.log(`  already present: ${result.duplicates} (re-import is safe, nothing duplicated)`);
  }
  if (result.redacted > 0) {
    console.log(`  redacted:        ${result.redacted} message(s) had content removed`);
  }
  if (result.skipped > 0) {
    console.log(`  unparsed lines:  ${result.skipped}`);
  }
  if (result.earliest !== null && result.latest !== null) {
    console.log(`  covering:        ${formatTimestamp(result.earliest)} → ${formatTimestamp(result.latest)}`);
  }

  console.log(`\n  participants: ${result.senders.join(', ') || '(none detected)'}`);
  if (flags.me === undefined) {
    console.log(
      '  All messages were recorded as received. Re-run with --me "<your name>"\n  to mark your own messages as sent.',
    );
  }

  // Imported history is usually older than the global retention window, so
  // without an override the next sweep would delete everything just imported.
  const retainDays = flags.retainDays ?? 0;
  const path = configPath();
  config.retention.perConversationDays[result.conversationId] = retainDays;
  writeConfig(path, config);

  console.log(
    `\n  retention: ${
      retainDays === 0 ? 'kept indefinitely' : `${retainDays} days`
    } (written to ${path})`,
  );
  if (retainDays === 0 && config.retention.days > 0) {
    console.log(
      `  The global retention of ${config.retention.days} days would otherwise have purged this\n  history on the next sweep. Change it with --retain-days if that is not what you want.`,
    );
  }

  store.close();
}

interface Flags {
  positional: string[];
  me?: string;
  title?: string;
  retainDays?: number;
}

function parseFlags(args: string[]): Flags {
  const flags: Flags = { positional: [] };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    switch (arg) {
      case '--me':
        flags.me = args[++i];
        break;
      case '--title':
        flags.title = args[++i];
        break;
      case '--retain-days': {
        const value = Number.parseInt(args[++i] ?? '', 10);
        if (!Number.isInteger(value) || value < 0) {
          console.error('--retain-days expects a whole number of days (0 means keep forever)');
          process.exit(1);
        }
        flags.retainDays = value;
        break;
      }
      default:
        flags.positional.push(arg);
    }
  }

  return flags;
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

function openStore(options: { create?: boolean } = {}): Store {
  const secrets = loadSecrets();
  if (secrets.encryptionKey === null) {
    console.error(
      'LINE_CONNECTOR_KEY is not set. The message store is encrypted and cannot be opened without it.\n\nIf this is a first run, generate one with:  npm run cli -- init',
    );
    process.exit(1);
  }
  // Import can be the first thing anyone runs, so it creates the store rather
  // than insisting the webhook server has recorded something first.
  if (options.create === true) {
    return new Store(databasePath(), secrets.encryptionKey);
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
