# The `/notify` relay contract

Every platform relay does the same tiny job: read a LINE notification the OS
delivered, and POST it here. This is the whole interface. Anything that can make
an authenticated HTTP request can be a relay — a phone automation app, a shell
script, a tray app.

## Endpoint

```
POST https://your-host/notify
Authorization: Bearer <LINE_CONNECTOR_NOTIFY_SECRET>
Content-Type: application/json
```

The bearer token is whatever you set as `LINE_CONNECTOR_NOTIFY_SECRET` in the
ingest server's environment. **Use HTTPS.** Unlike the webhook, which is
verified with an HMAC over the raw body, the relay authenticates with a bearer
token, so on plain HTTP that token would travel in the clear. Put the ingest
server behind TLS (a tunnel like Cloudflare or Tailscale, or a reverse proxy).

## Body

```json
{
  "app": "jp.naver.line.android",
  "chat": "Alice",
  "sender": "Alice",
  "text": "see you at seven",
  "postedAt": 1755400000000
}
```

| Field | Required | Meaning |
|---|---|---|
| `chat` | yes | Notification title — the chat name, or the group name |
| `text` | yes | Notification body — the message preview |
| `sender` | no | Who sent it, within a group. Omit for a 1:1 chat |
| `app` | no | Source package. If present it must be LINE, else the event is ignored — lets you forward *all* notifications and let the server filter |
| `postedAt` | no | Epoch milliseconds. Defaults to arrival time |

## Behaviour worth knowing

- **Group attribution.** If you omit `sender` and the body looks like
  `Name: message`, the server splits it. If your automation can supply `sender`
  explicitly, that is more reliable — the split is skipped when `sender` is set.
- **Summary notifications are dropped.** "3 new messages" and its Japanese and
  Chinese equivalents are recognised and ignored.
- **De-duplication.** The message id is derived from the chat, sender, text and
  the minute it arrived, so a notification Android reposts (on update) collapses
  into one row. Two genuinely identical messages a minute apart stay separate.
- **Same conversation as imports.** A chat captured by notification and later
  backfilled from an export land in the *same* conversation, because both derive
  the id from the chat name.

## Responses

| Status | Meaning |
|---|---|
| `200 {"stored":true}` | Captured |
| `200 {"stored":false,"reason":"..."}` | Valid request, nothing stored (non-LINE app, summary notification, duplicate). Not an error — do not retry |
| `401` | Bad or missing bearer token |
| `503` | The relay is not configured (`LINE_CONNECTOR_NOTIFY_SECRET` unset) |

A `200` with `stored:false` is deliberate: a relay that forwards every
notification on the device will send plenty this server does not want, and those
should not look like failures the phone needs to retry.

## Testing it by hand

```bash
curl -X POST https://your-host/notify \
  -H "Authorization: Bearer $LINE_CONNECTOR_NOTIFY_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"app":"jp.naver.line.android","chat":"Test","text":"hello from curl"}'
```

Then read it back:

```bash
npm run cli -- conversations
npm run cli -- export "<the handle it shows>"
```

## Windows relay sketch (PowerShell)

A minimal poller using the WinRT `UserNotificationListener`. Run it alongside
the LINE Windows app. This is a starting point, not a packaged tool.

```powershell
# Requires Windows 10+ and one-time consent via RequestAccessAsync.
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$secret = $env:LINE_CONNECTOR_NOTIFY_SECRET
$listener = [Windows.UI.Notifications.Management.UserNotificationListener,Windows.UI.Notifications.Management,ContentType=WindowsRuntime]::Current
# ... RequestAccessAsync(), then poll GetNotificationsAsync(Toast),
#     read each notification's title/body, and POST to /notify.
```

The full version is about 100 lines; the load-bearing parts are the one-time
access request and reading each notification's `Text` elements. A C#/.NET tray
app is the more robust form of the same thing.
