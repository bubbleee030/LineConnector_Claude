/**
 * A minimal LINE Messaging API client.
 *
 * Only the three calls this project actually needs are implemented. A thin
 * client is easier to audit than a full SDK, and it keeps the set of things
 * that can be done with the channel access token small and legible.
 *
 * Note on sending: this uses the push endpoint rather than reply. Reply tokens
 * are single-use and expire shortly after the incoming message arrives, which
 * makes them a poor fit for a model that composes a response some time later.
 * Push works at any time, at the cost of counting against the account's
 * message quota.
 */

const API_BASE = 'https://api.line.me';
const DATA_API_BASE = 'https://api-data.line.me';
const TIMEOUT_MS = 10_000;

export class LineApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: string,
  ) {
    super(message);
    this.name = 'LineApiError';
  }
}

export interface LineProfile {
  userId: string;
  displayName: string;
  pictureUrl?: string;
  statusMessage?: string;
}

export class LineClient {
  constructor(private readonly channelAccessToken: string) {
    if (channelAccessToken.length === 0) {
      throw new Error('LINE channel access token is required');
    }
  }

  /**
   * Looks up a user's display name.
   *
   * For group and room conversations the member-scoped endpoint must be used;
   * the plain profile endpoint only works for users who have added the Official
   * Account as a friend and returns 404 otherwise.
   */
  async getProfile(
    userId: string,
    scope?: { type: 'group' | 'room'; id: string },
  ): Promise<LineProfile | null> {
    const path =
      scope === undefined
        ? `/v2/bot/profile/${encodeURIComponent(userId)}`
        : scope.type === 'group'
          ? `/v2/bot/group/${encodeURIComponent(scope.id)}/member/${encodeURIComponent(userId)}`
          : `/v2/bot/room/${encodeURIComponent(scope.id)}/member/${encodeURIComponent(userId)}`;

    const response = await this.request('GET', `${API_BASE}${path}`);
    if (response.status === 404) return null; // not a friend, or left the group
    await assertOk(response, 'profile lookup');
    return (await response.json()) as LineProfile;
  }

  /**
   * Sends a text message to a user, group or room.
   * Returns the id LINE assigned, so the sent message can be recorded in the
   * local transcript alongside the messages that arrived by webhook.
   */
  async pushText(to: string, text: string): Promise<{ messageId: string | null }> {
    if (text.length === 0) throw new Error('Message text must not be empty');
    // LINE rejects text messages over 5000 characters outright.
    if (text.length > 5000) throw new Error('Message text exceeds the 5000 character limit');

    const response = await this.request('POST', `${API_BASE}/v2/bot/message/push`, {
      to,
      messages: [{ type: 'text', text }],
    });
    await assertOk(response, 'push message');

    const payload = (await response.json().catch(() => null)) as
      | { sentMessages?: { id?: string }[] }
      | null;
    return { messageId: payload?.sentMessages?.[0]?.id ?? null };
  }

  /**
   * Downloads the bytes of a media message.
   *
   * Only called when `capture.storeMedia` is enabled. LINE keeps content for a
   * limited window after delivery, so this fails for older messages.
   */
  async getMessageContent(messageId: string): Promise<Buffer> {
    const response = await this.request(
      'GET',
      `${DATA_API_BASE}/v2/bot/message/${encodeURIComponent(messageId)}/content`,
    );
    await assertOk(response, 'message content');
    return Buffer.from(await response.arrayBuffer());
  }

  private async request(method: string, url: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = {
      Authorization: `Bearer ${this.channelAccessToken}`,
    };
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    return fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  }
}

async function assertOk(response: Response, what: string): Promise<void> {
  if (response.ok) return;
  // Read the body for diagnostics, but cap it: LINE error payloads are small,
  // and an unbounded read here would be a memory hazard on a malformed reply.
  const body = (await response.text().catch(() => '')).slice(0, 500);
  throw new LineApiError(
    `LINE ${what} failed with HTTP ${response.status}`,
    response.status,
    body,
  );
}
