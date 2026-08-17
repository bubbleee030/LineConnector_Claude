#!/usr/bin/env python3
"""
macOS notification relay for line-connector.

Reads LINE notifications from macOS Notification Center's local database and
POSTs them to the connector's /notify endpoint. This captures a personal LINE
chat *without opening it*, so no read receipt is sent — nothing here ever talks
to LINE's servers. It reads a local file that macOS already wrote.

Uses only the Python standard library, which ships with macOS, so there is
nothing to install.

    Requirements
      - Full Disk Access for whatever runs this (Terminal, or the launchd job).
        System Settings -> Privacy & Security -> Full Disk Access.
      - The ingest server reachable over HTTPS, with LINE_CONNECTOR_NOTIFY_SECRET
        set to the same value you pass here.

    Usage
      export LINE_CONNECTOR_NOTIFY_SECRET=...           # same as the server
      export LINE_CONNECTOR_NOTIFY_URL=https://host/notify
      python3 macos-relay.py            # poll forever
      python3 macos-relay.py --once     # one pass, for testing or cron

Honest caveats. Apple changes this database between macOS releases, and the
notification payload is a nested binary plist whose exact keys have shifted over
time. This script tries the shapes seen across recent macOS versions and prints
what it could not decode instead of guessing. If your LINE app's bundle id or
the payload layout differs on your release, the two constants below and
`extract_fields` are the places to adjust. Run with --once --verbose first and
look at what it prints.
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# LINE's macOS app bundle id. Verify with:  osascript -e 'id of app "LINE"'
LINE_BUNDLE_IDS = {"jp.naver.line.mac", "jp.naver.line.osx"}

# macOS records notifications here. Path has been stable for several releases,
# but confirm it exists on yours.
DB_PATH = (
    Path.home()
    / "Library/Group Containers/group.com.apple.usernoted/db2/db"
)

# Where we remember the last row we forwarded, so a restart does not re-send
# the whole history.
STATE_PATH = Path.home() / ".line-connector-macos-relay.state"

POLL_SECONDS = 5


def load_last_rec_id() -> int:
    try:
        return int(STATE_PATH.read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0


def save_last_rec_id(rec_id: int) -> None:
    STATE_PATH.write_text(str(rec_id))


def open_db() -> sqlite3.Connection:
    if not DB_PATH.exists():
        sys.exit(
            f"Notification database not found at:\n  {DB_PATH}\n"
            "This path changes between macOS versions; check where yours lives."
        )
    # Read-only, and immutable so we never take a write lock on Apple's file.
    uri = f"file:{DB_PATH}?mode=ro&immutable=1"
    try:
        return sqlite3.connect(uri, uri=True)
    except sqlite3.OperationalError as exc:
        sys.exit(
            f"Could not open the notification database: {exc}\n"
            "This almost always means the running process lacks Full Disk Access."
        )


def decode_record(blob: bytes) -> dict | None:
    """
    Decode the notification payload blob into a plain dict.

    macOS stores it as a binary plist. Depending on the release it is either a
    straightforward dict or an NSKeyedArchiver graph; plistlib reads the bytes
    either way, and we normalise the couple of shapes we have seen.
    """
    try:
        payload = plistlib.loads(blob)
    except Exception:
        return None

    if not isinstance(payload, dict):
        return None

    # Common shape: the interesting fields live under a "req" dict.
    if "req" in payload and isinstance(payload["req"], dict):
        return payload["req"]
    return payload


def extract_fields(req: dict) -> tuple[str | None, str | None, str | None]:
    """
    Pull (bundle_id, title, body) out of a decoded record.

    Key names have varied across macOS versions, so each field is looked up
    through a small list of the names seen in the wild rather than one fixed key.
    """
    def first(d: dict, keys: list[str]) -> str | None:
        for key in keys:
            value = d.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    bundle = first(req, ["app", "bundleid", "appBundleID"])
    title = first(req, ["titl", "title", "AppNotificationTitle"])
    subtitle = first(req, ["subt", "subtitle"])
    body = first(req, ["body", "AppNotificationBody", "mesg"])

    # In group chats the title is the group and the subtitle is the sender.
    # Fold the subtitle into the title so the server's "Sender: message" split
    # still has something to work with when the body lacks a prefix.
    if subtitle and title and subtitle != title:
        title = f"{title} • {subtitle}"

    return bundle, title, body


def post_notification(url: str, secret: str, chat: str, text: str, posted_ms: int, verbose: bool) -> None:
    payload = json.dumps(
        {"app": "jp.naver.line.android", "chat": chat, "text": text, "postedAt": posted_ms}
    ).encode("utf-8")
    # The server keys on the Android package name for its LINE check; sending
    # that keeps one code path on the receiver regardless of source OS.

    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {secret}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if verbose:
                print(f"  -> {response.status} {response.read().decode('utf-8', 'replace')}")
    except urllib.error.HTTPError as exc:
        print(f"  -> HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')}", file=sys.stderr)
    except urllib.error.URLError as exc:
        print(f"  -> could not reach {url}: {exc.reason}", file=sys.stderr)


def cocoa_time_to_ms(value: object) -> int:
    """Notification timestamps are seconds since 2001-01-01 (Cocoa epoch)."""
    COCOA_EPOCH_OFFSET = 978_307_200  # seconds between 1970 and 2001
    if isinstance(value, (int, float)) and value > 0:
        return int((value + COCOA_EPOCH_OFFSET) * 1000)
    return int(time.time() * 1000)


def process(conn: sqlite3.Connection, url: str, secret: str, verbose: bool) -> int:
    last = load_last_rec_id()
    # The `record` table holds delivered notifications; `data` is the blob,
    # `delivered_date` the Cocoa timestamp. Column names are stable recently.
    try:
        rows = conn.execute(
            "SELECT rec_id, data, delivered_date FROM record WHERE rec_id > ? ORDER BY rec_id",
            (last,),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        sys.exit(f"Unexpected notification schema on this macOS version: {exc}")

    highest = last
    forwarded = 0

    for rec_id, blob, delivered in rows:
        highest = max(highest, rec_id)
        if not blob:
            continue

        req = decode_record(blob)
        if req is None:
            if verbose:
                print(f"rec {rec_id}: could not decode payload, skipping")
            continue

        bundle, title, body = extract_fields(req)
        if bundle not in LINE_BUNDLE_IDS:
            continue
        if not title or not body:
            if verbose:
                print(f"rec {rec_id}: LINE notification with no title/body, skipping")
            continue

        if verbose:
            print(f"rec {rec_id}: {title}: {body[:60]}")
        post_notification(url, secret, title, body, cocoa_time_to_ms(delivered), verbose)
        forwarded += 1

    if highest > last:
        save_last_rec_id(highest)
    return forwarded


def main() -> None:
    parser = argparse.ArgumentParser(description="Relay macOS LINE notifications to line-connector.")
    parser.add_argument("--once", action="store_true", help="one pass, then exit")
    parser.add_argument("--verbose", action="store_true", help="print what is read and sent")
    args = parser.parse_args()

    secret = os.environ.get("LINE_CONNECTOR_NOTIFY_SECRET", "").strip()
    url = os.environ.get("LINE_CONNECTOR_NOTIFY_URL", "").strip()
    if not secret or not url:
        sys.exit("Set LINE_CONNECTOR_NOTIFY_SECRET and LINE_CONNECTOR_NOTIFY_URL first.")

    conn = open_db()
    try:
        if args.once:
            count = process(conn, url, secret, args.verbose)
            print(f"Forwarded {count} LINE notification(s).")
            return

        print("Relaying LINE notifications. Ctrl-C to stop.")
        while True:
            process(conn, url, secret, args.verbose)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
