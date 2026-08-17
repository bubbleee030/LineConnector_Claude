# Privacy design

This document says what the connector protects, what it does not, and why each
control is built the way it is. The goal is that you can decide whether to
trust it, rather than take a claim on faith.

---

## The situation this is designed for

You run a LINE Official Account. Other people — customers, members, whoever —
send it messages. Those people did not choose to have their messages read by an
AI assistant; you did, on their behalf. That asymmetry is the reason this
project is shaped the way it is.

Two design commitments follow from it:

1. **The default is to record nothing.** Consent is something you grant per
   conversation, deliberately. A fresh install with a live webhook stores
   nobody.
2. **The model is a reader, not an administrator.** Claude can read what you
   allowed. It cannot widen its own access, disable redaction, or delete
   anyone's data. Those are terminal commands a person runs.

---

## Threat model

### Protected against

| Threat | Control |
|---|---|
| Someone steals the database file | AES-256-GCM on message bodies, sender ids, display names. Identifiers are keyed HMACs. Without the key, a thief learns how many people wrote and when, and nothing more. |
| A forged webhook injects fake messages | HMAC-SHA256 signature verified over the raw request bytes, constant-time compare, before parsing and before any write. |
| Sensitive data accumulating in the store | Redaction runs *before* storage, so card numbers and national IDs never land on disk. Retention deletes on a timer, with `VACUUM` so freed pages are actually overwritten. |
| The model pulling down the whole archive | Per-call ceilings on rows and characters; unreadable conversations are filtered in SQL and never decrypted. |
| Silent scope creep in what Claude reads | Every tool call is audit-logged with the thread and row count. `npm run cli -- audit` shows exactly what was looked at. |
| Identifiers leaking into model context | Claude receives per-install HMAC pseudonyms. They cannot be used to contact anyone, and do not correlate across installs. |
| A sender changing their mind | LINE `unsend` events delete the local copy. Deletion is never gated on the consent list. |
| Supply chain | Two runtime dependencies, no native addons. Storage is Node's built-in `node:sqlite`. |

### Not protected against

Being straight about this matters more than the table above.

- **Anyone with the key and the database file reads everything.** That is the
  whole security boundary. Key management is yours.
- **A compromised host.** If an attacker is running as your user while the
  ingest server is live, they can read messages in memory and take the key from
  the environment.
- **LINE itself.** LINE has all of these messages regardless of what this does.
  This reduces *your* copy's exposure, not theirs.
- **What Claude does with what it reads.** Once a message is in the model's
  context, this project's controls no longer apply. Restricting `mcp.readable`
  is how you limit that, not anything downstream.
- **Redaction being perfect.** It is pattern matching. It will miss a
  creatively formatted ID number, and it will occasionally redact something
  harmless. `storeText: "none"` is the setting that does not depend on a regex
  being clever enough.
- **Traffic analysis of the database.** Row counts and timestamps are not
  encrypted. Someone with the file learns the shape of your message volume.

---

## What is actually stored

Per message:

| Field | Form on disk |
|---|---|
| Message id | HMAC-SHA256, keyed |
| Conversation id | HMAC-SHA256, keyed |
| Sender id | HMAC (for lookups) **and** AES-GCM ciphertext (for replying) |
| Sender pseudonym | `user_` + 12 hex chars |
| Message text | AES-GCM ciphertext of the **already-redacted** text, or `NULL` |
| Original text length | Integer, in the clear |
| Timestamp, type, direction | In the clear |
| Metadata | JSON in the clear — sticker ids, durations, file extensions |
| Which redaction rules fired | In the clear |

Timestamps and counts are deliberately unencrypted: they are what make the
retention sweeper and the transcript ordering work, and encrypting them would
mean decrypting the entire table to answer "what happened last Tuesday".

### What is dropped before it ever reaches a row

- Precise GPS coordinates from shared locations (default `storeLocation: none`)
- Street addresses attached to locations
- File names (the extension is kept)
- The user ids of people mentioned in a message — only the count survives
- Media bytes, unless `storeMedia` is explicitly turned on

---

## The pipeline, in order

Order is the design. Each step is upstream of the next for a reason.

```
1. verify signature   ← before parsing, so unsigned input never becomes data
2. consent check      ← before redaction, so denied threads cost nothing
3. select text        ← full / redacted / none, per policy
4. redact             ← before encryption, so the raw value is discarded in memory
5. encrypt            ← before the write
6. store              ← keyed by HMAC, idempotent on message id
```

Redacting on *read* instead of on *write* would be the natural shortcut, and it
is the wrong one: it leaves the real card number sitting in the database, one
config mistake or one copied file away from disclosure. Redaction here is
irreversible, and that is the intended direction to fail in.

---

## The controls you set

All of these live in `config/privacy.json`. `npm run cli -- status` prints what
is actually in force.

**`capture.mode`** — `denyByDefault` (the default) records only allow-listed
conversations. `allowByDefault` records everything not denied; only reasonable
for an account whose entire purpose is to be read.

**`capture.storeText`** — `redacted` (default), `full` (no redaction, opt-in
only), or `none` (metadata only — you still see who wrote and when, and that
is all).

**`capture.storeLocation`** — `none` (default), `coarse` (~1km), `precise`.
Shared locations are among the most sensitive things LINE carries.

**`retention.days`** — 30 by default. Data you no longer hold cannot leak, be
subpoenaed, or be read by a future bug, which makes this the single most
effective control here. `perConversationDays` sets tighter windows per thread.

**`mcp.readable`** — narrows what Claude sees *independently* of what is
recorded. `null` means everything captured. This is kept separate from the
capture list so you can stop showing a thread to the model without losing your
own record of it.

**`mcp.exposeSenderIds`** — off by default. Turning it on hands real LINE user
ids to the model.

**`mcp.allowSend`** — off by default, and requires `LINE_CONNECTOR_ALLOW_SEND=true`
in the environment as well. Two independent switches, so neither a stray config
edit nor a stray env var alone gives the model the ability to message a real
person. When it is off, the tool is not merely refused — it is never registered,
so it does not appear in Claude's tool list at all.

---

## Key management

One 32-byte AES-256 key, from `LINE_CONNECTOR_KEY` or `LINE_CONNECTOR_KEY_FILE`.

- Generate with `npm run cli -- keygen`. It uses `crypto.randomBytes`.
- Lose it and the store is unrecoverable. There is no recovery path by design.
- Prefer `LINE_CONNECTOR_KEY_FILE` on a shared machine: it keeps the key out of
  `ps` output and shell history. Mode `0600`.
- The same key derives the HMAC pseudonyms, which is why they differ between
  installs and cannot be correlated across them.
- Rotation is not implemented. Rotating would mean re-encrypting every row;
  given a 30-day default retention, letting the old data age out is usually the
  better answer.

The database is created mode `0600`, and `data/`, `media/`, `*.db`, `*.key` and
`config/privacy.json` are all gitignored.

---

## Telling the people who message you

The code cannot do this part. In most jurisdictions you have some obligation to
tell people what you record and why, and "an AI assistant reads this inbox" is
the kind of thing people expect to be told about even where the law is vague.
Taiwan's PDPA, Japan's APPI and the GDPR all point in the same direction.

The practical version: put it in the Official Account's greeting message or
description. Something like *"Messages to this account are stored and may be
reviewed with AI assistance. Personal data is automatically removed and
messages are deleted after 30 days."*

Adjust it to match your actual config, and keep it true if you change the
config. This is not legal advice.

---

## Verifying the claims

The privacy-relevant behaviour is tested rather than asserted. `npm test` runs
84 tests, including:

- `stores nothing on a default config, even with a live webhook`
- `leaves no plaintext in the database file` — writes a message, closes the
  store, and greps every file in the directory for the text and the LINE id
- `redacts before writing, so the raw value never reaches the row`
- `leaves no trace of purged text in the file afterwards`
- `honours an unsend even for a conversation that is no longer allow-listed`
- `is sensitive to byte-level differences, not just parsed equality` — the
  signature check, against the re-serialisation mistake

You can also check by hand at any time:

```bash
grep -a "some text you sent" data/line.db     # expect no match
npm run cli -- audit 50                       # what Claude has read
```
