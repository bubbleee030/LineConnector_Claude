# line-connector

A privacy-first LINE connector for Claude. It captures messages sent to a LINE
Official Account into a local encrypted store, and exposes them to Claude
through MCP as read-only tools with per-call limits and an audit log.

---

## Read this before you start

**This cannot read your personal LINE chats.** There is no API for that, from
LINE or anyone else. The Messaging API only works for a LINE **Official
Account** — a business/bot account — and only sees messages that people send
*to that account*. Your own conversations with friends are not reachable
programmatically, and the LINE Notify service that used to offer a sliver of
this was shut down in 2025.

**There is also no chat history.** LINE pushes each message once, by webhook,
as it happens. There is no "fetch the last 200 messages" endpoint. The ingest
server has to be running *before* a conversation happens for there to be any
record of it. Nothing that arrived before you set this up can be recovered.

So what this is actually good for: you have (or create) a LINE Official
Account, people message it, and you want Claude to help you read, search and
reason over that inbox — without handing a third party a copy of everyone's
messages.

If that is not what you wanted, stop here rather than working around it.

---

## How it works

```
   people on LINE
        │
        │  message the Official Account
        ▼
   LINE Platform
        │
        │  webhook POST (signed with your channel secret)
        ▼
┌───────────────────────────────────────────────┐
│  ingest server            src/ingest/         │
│                                               │
│   verify signature over raw bytes             │
│      ↓                                        │
│   consent check    is this thread allowed?    │
│      ↓                                        │
│   redact           strip PII from the text    │
│      ↓                                        │
│   encrypt          AES-256-GCM per field      │
│      ↓                                        │
│   store                                       │
└───────────────────┬───────────────────────────┘
                    ▼
          ┌──────────────────────┐
          │  SQLite, encrypted   │◄── retention sweeper deletes on a timer
          │  no plaintext ids    │
          └──────────┬───────────┘
                     │  read-only
                     ▼
          ┌──────────────────────┐        ┌──────────┐
          │  MCP server          │◄──────►│  Claude  │
          │  src/mcp/            │  stdio └──────────┘
          │  caps + audit log    │
          └──────────────────────┘
```

Two processes, deliberately separate. The ingest server holds the LINE
credentials and writes. The MCP server only reads, and in its default
configuration never contacts LINE at all — it does not even need the channel
access token, so the credential that can message real people is simply absent
from the process Claude drives.

---

## Setup

### 1. Install and generate a key

```bash
npm install
npm run build
npm run cli -- init
```

`init` writes `config/privacy.json` and prints an encryption key. Export it:

```bash
export LINE_CONNECTOR_KEY=<the key it printed>
```

Keep it somewhere durable. Lose it and the store is unreadable; leak it
alongside a copy of the database and everything in it is readable.

### 2. Set up the LINE side

In the [LINE Developers Console](https://developers.line.biz/):

1. Create a provider, then a **Messaging API** channel (this creates or links a
   LINE Official Account).
2. **Basic settings** → copy the **Channel secret**.
3. **Messaging API** tab → issue a **Channel access token** (only needed if you
   want sending, display names, or media).
4. **Messaging API** tab → set the **Webhook URL** and turn **Use webhook** on.
5. In [LINE Official Account Manager](https://manager.line.biz/), turn off
   **Auto-reply messages** and **Greeting messages** unless you want them.

```bash
export LINE_CHANNEL_SECRET=<the channel secret>
```

The webhook URL must be public HTTPS with a valid certificate. For local
development, put a tunnel in front of the ingest server:

```bash
npm run ingest                      # listens on 127.0.0.1:8787
cloudflared tunnel --url http://localhost:8787   # or: ngrok http 8787
```

Then set the webhook URL to `https://<tunnel-host>/webhook`.

### 3. Choose what gets captured

Nothing is recorded until you say so — the default policy denies every
conversation. Have someone message the account, then:

```bash
npm run cli -- conversations              # shows ids that have written in
npm run cli -- allow U1234...             # opt that conversation in
```

Restart the ingest server for the change to take effect. Only messages sent
from that point on are captured.

### 4. Connect it to Claude

**Claude Code:**

```bash
claude mcp add line -- node /absolute/path/to/dist/src/mcp/server.js
```

**Claude Desktop** — in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "line": {
      "command": "node",
      "args": ["/absolute/path/to/dist/src/mcp/server.js"],
      "env": {
        "LINE_CONNECTOR_KEY": "your-key-here",
        "LINE_CONNECTOR_DB": "/absolute/path/to/data/line.db",
        "LINE_CONNECTOR_CONFIG": "/absolute/path/to/config/privacy.json"
      }
    }
  }
}
```

Absolute paths matter: the MCP server is launched from an unpredictable working
directory.

---

## What Claude gets

| Tool | What it does |
|---|---|
| `line_list_conversations` | Lists readable conversations as pseudonymous handles |
| `line_read_messages` | Chronological transcript of one conversation |
| `line_search_messages` | Substring search across readable conversations |
| `line_privacy_status` | Reports what is captured, visible, and how long it is kept |
| `line_send_message` | Sends a message — **not registered unless you enable it** |

Claude sees handles like `user_3f9a2c1b`, not LINE user ids. It cannot change
the policy, grant itself access to a new conversation, turn off redaction, or
delete anyone's data — those are CLI-only, on purpose.

`line_privacy_status` exists so that when Claude notices a gap, it can explain
it. Missing data here is usually policy working, not a bug.

---

## Operator commands

```
npm run cli -- <command>

  init                 Generate a key and a starter privacy config
  keygen               Print a fresh encryption key

  conversations        List captured conversations with their real LINE ids
  allow <lineId>       Add a conversation to the capture allow list
  deny <lineId>        Add a conversation to the deny list (deny always wins)

  status               Show the policy in force and what is stored
  export <handle>      Print one conversation as a transcript
  purge                Run the retention sweep now
  forget <lineId>      Erase everything for one user or group, permanently
  audit [n]            Show the last n things Claude looked at
```

---

## Privacy design

The short version; the reasoning and the threat model are in
[PRIVACY.md](./PRIVACY.md).

- **Local only.** Messages go to a SQLite file you control. No third-party
  service, no telemetry, no outbound calls except to LINE itself.
- **Deny by default.** A webhook receives everything sent to the account,
  including from people who found it by accident. Conversations must be
  allow-listed individually before anything is written.
- **Redaction before storage.** Card numbers, national IDs, emails, phone
  numbers, IBANs, API keys and tokens are stripped *before* the row is
  written, so the sensitive substring never reaches disk in any form.
- **Encrypted at rest.** Message bodies, sender ids and display names are
  AES-256-GCM encrypted. Identifiers are stored as keyed HMACs, so the
  database has no plaintext LINE ids in it at all.
- **Pseudonyms to the model.** Claude gets stable per-install handles, not
  identifiers that could be used to contact or correlate anyone elsewhere.
- **Retention by default.** 30 days, swept hourly, with `VACUUM` so deleted
  text is not recoverable from free pages.
- **Deletions propagate.** When someone unsends a message in LINE, the local
  copy is deleted too.
- **Bounded reads.** Per-call ceilings on rows and characters, so no single
  tool call can drain the archive.
- **Audited.** Every read is logged — which tool, which thread, how many rows.
  Search terms are recorded by length only, never content.

Three runtime dependencies in total (`@modelcontextprotocol/sdk`, `zod`, and
Node's built-in `node:sqlite`), with no native addons — a small supply chain is
part of the privacy story, not separate from it.

### One thing the code cannot do for you

The people messaging your Official Account cannot see this config. In most
places you have some obligation to tell them what you record and why — Taiwan's
PDPA, Japan's APPI, and the GDPR all point the same direction, and an AI
assistant reading the inbox is the kind of thing people expect to be told
about. Put it in the account's greeting message or description. This is not
legal advice.

---

## Development

```bash
npm run build       # compile
npm test            # build, then run the suite (84 tests)
npm run typecheck   # types only
```

Tests cover signature verification, the redaction rules and their checksum
validators, encryption round-trips and tamper detection, the consent matrix,
webhook normalization, and end-to-end capture — including an assertion that
message text and LINE ids do not appear anywhere in the database file.

## Limitations

- LINE Official Accounts only. Personal chats are not accessible. **Not fixable.**
- No history. Only what arrives while the ingest server is running.
- Search decrypts and scans up to 5000 recent messages per query rather than
  using an index — an encrypted store cannot have a plaintext search index
  without giving up the encryption. Fine at personal scale.
- The ingest server must be internet-reachable over HTTPS to receive webhooks.
- Sending uses the push endpoint, which counts against your account's message
  quota. Reply tokens expire too quickly to be useful to a model.
