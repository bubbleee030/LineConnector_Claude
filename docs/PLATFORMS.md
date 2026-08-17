# Reading personal LINE chats: what each platform allows

Your goal is to read messages "like the API" — including your personal chats,
without opening them and sending a read receipt. This page is the honest map of
what is achievable per platform, why, and how.

The short version: **the read-receipt-free path is notification capture**, and
how well it works depends entirely on the OS, because you are asking the
operating system — not LINE — to hand you a copy of the notification. That is
also why it is legitimate: it never touches LINE's servers.

---

## Why not just talk to LINE directly

There is no LINE API for personal accounts. To pull your chats "like the API"
in the literal sense, a program would have to log in *as you* over LINE's
private client protocol — an unofficial client. That route is a dead end, and
not because it is hard:

- It **violates LINE's Terms of Service**, and LINE bans accounts that do it.
  The ban lands on your real account, with your real contacts.
- It needs your actual login credentials and long-lived auth tokens, which
  becomes the single most dangerous secret in the whole system.
- LINE end-to-end encrypts chats (their "Letter Sealing"), rotates the
  protocol, and runs active anti-abuse. Unofficial clients break every few
  weeks and have a long history of being shut down.

So a credential-based unofficial client is not built here. It trades your
account's safety for a capability the notification path already gives you
without the risk. If your true requirement is specifically "read the messages
without a read receipt," notification capture *is* the API-like answer —
messages arrive as events, in near-real-time, structured — and it reads the
notification the OS already delivered rather than impersonating you to LINE.

Where "reverse engineering" is genuinely useful, it is aimed at the **operating
system's own notification store**, not at LINE — decoding the local
notification database on macOS, for instance. That is your data on your device,
and it is covered per-platform below.

---

## The matrix

| Platform | Read without read-receipt? | Mechanism | Effort |
|---|---|---|---|
| **Android** | ✅ Yes, cleanly | `NotificationListenerService` — a first-class OS API for reading notifications | Low |
| **Windows** | ✅ Yes | `UserNotificationListener` (WinRT) reads Action Center notifications with consent | Medium |
| **macOS** | ⚠️ Yes, with caveats | Read the Notification Center SQLite database (needs Full Disk Access) | Medium |
| **iOS** | ❌ Not on its own | Sandboxing forbids reading another app's notifications | — |
| **iOS via a Mac** | ⚠️ Indirect | iPhone notifications mirrored to a Mac, captured there | Medium |

Every "yes" feeds the **same** `/notify` endpoint this connector exposes, so
the storage, redaction, encryption and Claude-facing tools are identical
regardless of platform. The only per-platform part is the small relay that
reads a notification and POSTs it. That contract is documented in
[RELAY.md](./RELAY.md).

A universal caveat, true on every platform: **a notification is a preview, not
the message.** Long messages are truncated, media shows as `[Photo]`, a muted
chat may post nothing, and a chat already open on the device generates no
notification. The store marks every notification-sourced row as
`fidelity: preview` so a transcript never overstates what it holds. Notification
capture is a very good running log, not a perfect archive. Pair it with an
occasional export import (see the main README) when you want the full text of a
specific thread.

---

## Android — the recommended path

Android has a real, documented OS API for exactly this:
`NotificationListenerService`. You grant one app "Notification access" in
Settings, and it receives every notification as it is posted. Reading it sends
nothing to LINE.

You do not need to write an app. Any of the mainstream automation apps can do
it:

**MacroDroid** (easiest):
1. Install MacroDroid.
2. New macro → Trigger: **Notification Received** → application **LINE**.
3. Action: **HTTP Request (POST)** to `https://your-host/notify`
   - Header `Authorization: Bearer <your LINE_CONNECTOR_NOTIFY_SECRET>`
   - Header `Content-Type: application/json`
   - Body:
     ```json
     {"app":"jp.naver.line.android","chat":"{notification_title}","text":"{notification_text}","postedAt":{trigger_time}}
     ```
4. Grant MacroDroid notification access when prompted.

**Tasker** works the same way (Event → UI → Notification, then an HTTP Request
action). **Automate** (LlamaLab) has a "Notification posted" block feeding an
"HTTP request" block.

For a group chat, LINE puts the sender inside the body as `Name: message`; the
receiver splits that automatically, or you can send an explicit `sender` field
if your automation exposes it.

This is the path to prefer. It is the closest thing to an official capability,
it is stable, and it needs no reverse engineering at all.

---

## Windows

Windows exposes `Windows.UI.Notifications.Management.UserNotificationListener`
— the OS-sanctioned equivalent of Android's listener. An app calls
`RequestAccessAsync()`, the user consents once, and it can then enumerate and
subscribe to Action Center notifications, including LINE's (LINE ships a Windows
app via the Microsoft Store).

There is no no-code automation app for this the way there is on Android, so it
needs a small helper. A minimal PowerShell approach that polls the listener is
sketched in [RELAY.md](./RELAY.md); a more robust version is a ~100-line C#/.NET
tray app. Both just read notifications and POST them to `/notify`.

Caveat: the listener sees notifications posted while it is running. If the LINE
Windows app is closed, no notifications are posted, so run it alongside LINE.

---

## macOS

macOS keeps delivered notifications in a local SQLite database:

```
~/Library/Group Containers/group.com.apple.usernoted/db2/db
```

A script with **Full Disk Access** (System Settings → Privacy & Security → Full
Disk Access) can read new rows and POST them. This is where a little reverse
engineering earns its place: the notification payload is stored as a binary
plist (`NSKeyedArchiver`) inside a blob column, so the relay decodes that to
pull out the title and body. It is your own notification data in a local file —
no LINE server involved, no read receipt.

A starter relay using only the Python standard library (which ships with macOS)
is in [`scripts/relay/macos-relay.py`](../scripts/relay/macos-relay.py). Treat
it as a working starting point rather than a turnkey binary: Apple changes this
database between OS versions, so run it `--once --verbose` first and check what
it reads on your actual macOS release. It is commented so you can see exactly
what it does.

Two ways notifications get there:
- **The LINE Mac app** posts them directly. Reading the notification does not
  mark the chat read; only opening the chat in LINE does.
- **A mirrored iPhone** (below) posts them via Continuity.

---

## iOS

Standalone iOS is the one platform where this cannot be done cleanly. Apple's
sandbox specifically prevents an app from reading other apps' notifications —
there is no public `NotificationListenerService` equivalent, and Shortcuts has
no automation trigger that hands you another app's notification content. This is
a deliberate privacy boundary in iOS, and working around it means a jailbreak,
which is not something to build a daily workflow on.

The supported way to capture an iPhone's LINE notifications is to **let a Mac
mirror them**. With the iPhone and Mac on the same Apple ID and
iPhone-notification mirroring enabled, LINE notifications appear in the Mac's
Notification Center, where the macOS relay above captures them. So iOS messages
are reachable — through a Mac, not on the phone itself.

If you have no Mac, your realistic options on iOS are the export import (manual,
per-chat, and it does mark the chat read when you open it to export) or running
an Official Account instead of a personal one.

---

## Which should you use?

- **You have an Android phone** → MacroDroid recipe above. Done in ten minutes,
  no reverse engineering, stable.
- **You live on a Mac** (with the LINE Mac app, or an iPhone mirrored to it) →
  the macOS relay.
- **You're on Windows** → the `UserNotificationListener` helper.
- **iPhone, no Mac** → notification capture isn't available; use export import
  for specific threads, and consider whether an Official Account fits your use.

Whichever you pick, it POSTs to the same `/notify` endpoint, and from there
everything Claude sees is identical.
