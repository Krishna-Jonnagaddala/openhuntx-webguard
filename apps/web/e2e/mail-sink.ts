import { existsSync, readFileSync } from "node:fs";

/**
 * Slice 17: reads the JSON Lines mail-sink file `global-setup.ts`
 * publishes as `WEBGUARD_E2E_MAIL_SINK_PATH` -- `FakePostmarkTransport`
 * (`tests/integration/webguard_production_harness.py`) mirrors every
 * message the real `ProductionMailProvider` code path "sends" to this
 * file, so a spec running in this separate Node process can read the
 * exact verification/reset/invitation link a browser action just
 * caused the server to send, with no real mail transport involved.
 */

interface SinkMessage {
  to: string;
  subject: string;
  body: string;
  category: string;
  sent_at: string;
}

export async function waitForMail(
  to: string,
  category: string,
  { timeoutMs = 15_000, pollMs = 150 }: { timeoutMs?: number; pollMs?: number } = {},
): Promise<SinkMessage> {
  const sinkPath = process.env.WEBGUARD_E2E_MAIL_SINK_PATH;
  if (!sinkPath) throw new Error("WEBGUARD_E2E_MAIL_SINK_PATH was not published by global-setup.ts");

  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(sinkPath)) {
      const lines = readFileSync(sinkPath, "utf-8").split("\n").filter((line) => line.trim().length > 0);
      const messages: SinkMessage[] = lines.map((line) => JSON.parse(line));
      const matches = messages.filter((message) => message.to === to && message.category === category);
      if (matches.length > 0) return matches[matches.length - 1];
    }
    await new Promise((resolve) => setTimeout(resolve, pollMs));
  }
  throw new Error(`Timed out waiting for a "${category}" email to ${to} in the mail sink at ${sinkPath}.`);
}

/** Extracts the `?token=...` query value from a mailed link's body. */
export function extractToken(body: string): string {
  const match = body.match(/token=([^\s&]+)/);
  if (!match) throw new Error(`No token= query parameter found in mail body: ${body}`);
  return match[1];
}
