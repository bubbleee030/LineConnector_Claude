#!/usr/bin/env node
/**
 * The MCP server Claude talks to.
 *
 * This process is read-only by default and, in that mode, never contacts LINE
 * at all — it only reads the local encrypted store. It does not need the
 * channel access token unless sending is switched on, which means the
 * credential that can message real people is simply absent from the process
 * the model drives.
 *
 * Three limits apply to every call, enforced here rather than left to the
 * caller's good behaviour:
 *
 *   - conversations outside the readable set are filtered in SQL, so they are
 *     never decrypted, let alone returned;
 *   - row counts are clamped to the configured ceiling;
 *   - output is truncated to a character budget.
 *
 * Together they mean no single tool call can pull down the whole archive.
 */

import '../quiet.js';

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import {
  databasePath,
  loadPrivacyConfig,
  loadSecrets,
  sendingEnabled,
  type PrivacyConfig,
} from '../config.js';
import { Store, type ConversationRow } from '../db/index.js';
import { LineClient } from '../line/client.js';
import { audit, describeParams } from '../privacy/audit.js';
import { clampLimit, isReadable } from '../privacy/policy.js';
import { redact } from '../privacy/redact.js';
import {
  renderConversationList,
  renderPrivacyStatus,
  renderTranscript,
} from './render.js';

const DAY_MS = 86_400_000;

/**
 * Ceiling on how many stored rows a search may decrypt.
 *
 * Encrypted bodies cannot be indexed, so search is a linear scan. The cap
 * bounds both the work done and how much of the archive one query can touch.
 */
const SEARCH_SCAN_CAP = 5000;

function textResult(text: string): { content: { type: 'text'; text: string }[] } {
  return { content: [{ type: 'text', text }] };
}

function errorResult(text: string): {
  content: { type: 'text'; text: string }[];
  isError: true;
} {
  return { content: [{ type: 'text', text }], isError: true };
}

function main(): void {
  const config = loadPrivacyConfig();
  const secrets = loadSecrets();

  if (secrets.encryptionKey === null) {
    console.error(
      '[mcp] LINE_CONNECTOR_KEY is not set. The store is encrypted and cannot be opened without it. Run `npm run cli -- init` to generate a key.',
    );
    process.exit(1);
  }

  const store = new Store(databasePath(), secrets.encryptionKey);
  const canSend = sendingEnabled(config);
  const client =
    canSend && secrets.channelAccessToken !== null ? new LineClient(secrets.channelAccessToken) : null;

  if (canSend && client === null) {
    console.error(
      '[mcp] sending is enabled in the policy but LINE_CHANNEL_ACCESS_TOKEN is not set; the send tool will not be registered.',
    );
  }

  const server = new McpServer(
    { name: 'line-connector', version: '0.1.0' },
    {
      instructions: [
        'Reads messages sent to a LINE Official Account from a local, encrypted store.',
        '',
        'What you see has already been filtered by the operator: conversations must be',
        'allow-listed to be captured at all, personal data is redacted before storage,',
        'and old messages are deleted on a retention schedule. Sender identifiers are',
        'pseudonyms such as `user_3f9a2c1b` unless the operator chose otherwise; use',
        'those pseudonyms when referring to a conversation in other tool calls.',
        '',
        'Call `line_privacy_status` when you need to explain why something is missing.',
        'Gaps are usually policy, not error.',
      ].join('\n'),
    },
  );

  registerTools(server, store, config, client);

  const transport = new StdioServerTransport();
  server
    .connect(transport)
    .then(() => {
      console.error(
        `[mcp] line-connector ready (read-only${canSend && client !== null ? ' + send enabled' : ''})`,
      );
    })
    .catch((err: unknown) => {
      console.error('[mcp] failed to start:', (err as Error).message);
      process.exit(1);
    });

  const shutdown = (): void => {
    store.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

function registerTools(
  server: McpServer,
  store: Store,
  config: PrivacyConfig,
  client: LineClient | null,
): void {
  /**
   * Translates the policy's readable list into internal keys.
   * `undefined` means unrestricted; an array restricts the SQL query.
   */
  const readableKeys = (): string[] | undefined =>
    config.mcp.readable === null
      ? undefined
      : config.mcp.readable.map((lineId) => store.keyFor(lineId));

  /**
   * Resolves a caller-supplied handle, refusing anything not readable.
   *
   * "Not found" and "not permitted" deliberately return the same message, so
   * the tool cannot be used to test whether a given conversation exists.
   */
  const resolve = (handle: string): ConversationRow | { error: string } => {
    const conversation = store.findConversation(handle);
    if (conversation === null || !isReadable(conversation.lineId, config)) {
      return {
        error: `No readable conversation matches ${JSON.stringify(handle)}. Use line_list_conversations to see what is available.`,
      };
    }
    return conversation;
  };

  // -- list -----------------------------------------------------------------
  server.registerTool(
    'line_list_conversations',
    {
      title: 'List LINE conversations',
      description:
        'Lists the LINE conversations available to read, with message counts and last activity. Returns pseudonymous handles to use with the other tools.',
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => {
      const conversations = store.listConversations(readableKeys());
      audit(store, config, {
        actor: 'mcp',
        action: 'list_conversations',
        resultCount: conversations.length,
      });
      return textResult(renderConversationList(conversations, config));
    },
  );

  // -- read -----------------------------------------------------------------
  server.registerTool(
    'line_read_messages',
    {
      title: 'Read a LINE conversation',
      description:
        'Reads messages from one conversation, newest last. Returns a chronological transcript. Subject to the operator-configured per-call limits.',
      inputSchema: {
        conversation: z
          .string()
          .describe('Conversation handle from line_list_conversations, e.g. "user_3f9a2c1b".'),
        limit: z
          .number()
          .int()
          .positive()
          .optional()
          .describe('Maximum messages to return. Clamped to the configured ceiling.'),
        since_days: z
          .number()
          .int()
          .positive()
          .optional()
          .describe('Only include messages from the last N days.'),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ conversation: handle, limit, since_days: sinceDays }) => {
      const resolved = resolve(handle);
      if ('error' in resolved) {
        audit(store, config, { actor: 'mcp', action: 'read_messages:denied', resultCount: 0 });
        return errorResult(resolved.error);
      }

      const lookback = sinceDays ?? config.mcp.defaultLookbackDays;
      const messages = store.queryMessages({
        conversationId: resolved.id,
        since: Date.now() - lookback * DAY_MS,
        limit: clampLimit(limit, config),
      });

      audit(store, config, {
        actor: 'mcp',
        action: 'read_messages',
        conversationKey: resolved.id,
        detail: describeParams({ limit, since_days: lookback }),
        resultCount: messages.length,
      });

      const header = `Conversation ${resolved.pseudonym} (${resolved.sourceType}), ${messages.length} message(s) in the last ${lookback} day(s):\n`;
      return textResult(header + renderTranscript(messages, config, { conversation: resolved }));
    },
  );

  // -- search ---------------------------------------------------------------
  server.registerTool(
    'line_search_messages',
    {
      title: 'Search LINE messages',
      description:
        'Case-insensitive substring search across readable conversations. Searches only text that was actually stored, so redacted content will not match.',
      inputSchema: {
        query: z.string().min(2).describe('Text to search for. At least two characters.'),
        conversation: z
          .string()
          .optional()
          .describe('Restrict the search to one conversation handle.'),
        limit: z.number().int().positive().optional().describe('Maximum matches to return.'),
        since_days: z
          .number()
          .int()
          .positive()
          .optional()
          .describe('Only search messages from the last N days.'),
      },
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async ({ query, conversation: handle, limit, since_days: sinceDays }) => {
      let conversationId: string | undefined;
      let conversation: ConversationRow | null = null;

      if (handle !== undefined) {
        const resolved = resolve(handle);
        if ('error' in resolved) {
          audit(store, config, { actor: 'mcp', action: 'search_messages:denied', resultCount: 0 });
          return errorResult(resolved.error);
        }
        conversation = resolved;
        conversationId = resolved.id;
      }

      const lookback = sinceDays ?? config.mcp.defaultLookbackDays;
      const wanted = clampLimit(limit, config);

      // Encrypted bodies cannot be indexed, so this decrypts a bounded window
      // of recent messages and scans them in memory.
      const candidates = store.queryMessages({
        conversationId,
        restrictTo: conversationId === undefined ? readableKeys() : undefined,
        since: Date.now() - lookback * DAY_MS,
        limit: SEARCH_SCAN_CAP,
      });

      const needle = query.toLowerCase();
      const matches = candidates
        .filter((m) => m.text !== null && m.text.toLowerCase().includes(needle))
        .slice(0, wanted);

      audit(store, config, {
        actor: 'mcp',
        action: 'search_messages',
        conversationKey: conversationId ?? null,
        // The query itself is not recorded: search terms are as revealing as
        // the messages they find, and the audit log has its own retention.
        detail: describeParams({ query, since_days: lookback, scanned: candidates.length }),
        resultCount: matches.length,
      });

      if (matches.length === 0) {
        const scanNote =
          candidates.length >= SEARCH_SCAN_CAP
            ? ` Only the ${SEARCH_SCAN_CAP} most recent messages in that window were scanned; narrow since_days to search further back.`
            : '';
        return textResult(`No stored messages matched that search.${scanNote}`);
      }

      const header = `${matches.length} match(es) for that search in the last ${lookback} day(s):\n`;
      return textResult(
        header +
          renderTranscript(matches, config, {
            conversation,
            showConversation: conversationId === undefined,
          }),
      );
    },
  );

  // -- status ---------------------------------------------------------------
  server.registerTool(
    'line_privacy_status',
    {
      title: 'LINE connector privacy status',
      description:
        'Reports what this connector is currently recording, what it will let you read, and how long data is kept. Use this to explain gaps in the data.',
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () => {
      const all = store.listConversations();
      const readable = all.filter((c) => isReadable(c.lineId, config));
      audit(store, config, { actor: 'mcp', action: 'privacy_status', resultCount: null });

      return textResult(
        renderPrivacyStatus(config, {
          conversations: all.length,
          messages: store.countMessages(),
          oldestMessage: store.oldestMessageTimestamp(),
          sendEnabled: client !== null,
          readableCount: readable.length,
        }),
      );
    },
  );

  // -- send (gated) ---------------------------------------------------------
  // Registered only when the policy file and the environment both allow it, so
  // the tool is not merely refused but absent from the model's tool list.
  if (client === null) return;

  server.registerTool(
    'line_send_message',
    {
      title: 'Send a LINE message',
      description:
        'Sends a text message to a LINE conversation. This delivers to a real person immediately and cannot be undone. Confirm the recipient and wording with the user before calling.',
      inputSchema: {
        conversation: z.string().describe('Conversation handle to send to.'),
        text: z.string().min(1).max(5000).describe('Message body, at most 5000 characters.'),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: false,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    async ({ conversation: handle, text }) => {
      const resolved = resolve(handle);
      if ('error' in resolved) {
        audit(store, config, { actor: 'mcp', action: 'send_message:denied', resultCount: 0 });
        return errorResult(resolved.error);
      }

      try {
        const { messageId } = await client.pushText(resolved.lineId, text);

        // Record what was sent, so the transcript stays complete. LINE does
        // not webhook the account's own outgoing messages, so if this is not
        // written here it is not recorded anywhere.
        const outboundText =
          config.capture.storeText === 'none' ? null : redact(text, config).text;

        store.insertMessage({
          message: {
            id: messageId ?? `local-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`,
            conversationId: resolved.lineId,
            sourceType: resolved.sourceType,
            senderId: null,
            direction: 'outbound',
            type: 'text',
            text: outboundText,
            timestamp: Date.now(),
            isRedelivery: false,
            meta: { sentVia: 'mcp' },
          },
          text: outboundText,
          redactions: [],
          originalTextLength: text.length,
        });

        audit(store, config, {
          actor: 'mcp',
          action: 'send_message',
          conversationKey: resolved.id,
          detail: describeParams({ text }),
          resultCount: 1,
        });

        return textResult(`Sent to ${resolved.pseudonym}.`);
      } catch (err) {
        audit(store, config, {
          actor: 'mcp',
          action: 'send_message:failed',
          conversationKey: resolved.id,
          resultCount: 0,
        });
        return errorResult(`Failed to send: ${(err as Error).message}`);
      }
    },
  );
}

main();
