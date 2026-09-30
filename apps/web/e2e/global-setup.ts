import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Slice 15 requirement 28: starts the REAL production-mode WebGuard
 * API (real PostgreSQL, real KMS-shaped Ed25519/ECDSA signing, real
 * worker) plus a controlled HTTPS fixture asset, via
 * `tests/integration/webguard_e2e_server.py`. Its readiness line
 * (base URL, bootstrapped owner email/password for a real browser
 * login, an owner API token, fixture target URL, and -- Slice 17 --
 * a mail-sink JSON Lines file path) is published into `process.env`
 * for the spec files to read -- the spec itself never constructs its
 * own backend state. The mail sink lets a spec read the exact
 * verification/reset/invitation link the real (fake-Postmark-backed)
 * `ProductionMailProvider` code path just "sent", with no real mail
 * transport and no new production-reachable endpoint.
 */

const REPO_ROOT = path.resolve(__dirname, "..", "..", "..");
const DEFAULT_DSN = "postgresql://webguard:webguard_dev_only_not_for_production@127.0.0.1:5433/webguard";

let child: ChildProcessWithoutNullStreams | undefined;

export default async function globalSetup(): Promise<() => Promise<void>> {
  const pythonBin = process.env.WEBGUARD_E2E_PYTHON ?? path.join(REPO_ROOT, ".venv", "bin", "python3");
  const scriptPath = path.join(REPO_ROOT, "tests", "integration", "webguard_e2e_server.py");

  child = spawn(pythonBin, ["-u", scriptPath], {
    cwd: REPO_ROOT,
    env: {
      ...process.env,
      WEBGUARD_POSTGRES_TEST_DSN: process.env.WEBGUARD_POSTGRES_TEST_DSN ?? DEFAULT_DSN,
      WEBGUARD_E2E_API_PORT: process.env.WEBGUARD_E2E_API_PORT ?? "8765",
    },
  });

  const stderrChunks: string[] = [];
  child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk.toString()));

  const ready = await new Promise<{
    base_url: string;
    token: string;
    owner_email: string;
    owner_password: string;
    target_url: string;
    organization_id: string;
    mail_sink_path: string;
  }>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error(`Timed out waiting for the E2E API server. Stderr so far:\n${stderrChunks.join("")}`));
    }, 30_000);

    const rl = createInterface({ input: child!.stdout });
    rl.on("line", (line) => {
      const trimmed = line.trim();
      if (!trimmed.startsWith("{")) return;
      try {
        const payload = JSON.parse(trimmed);
        clearTimeout(timeout);
        rl.close();
        resolve(payload);
      } catch {
        // not the readiness line; keep waiting
      }
    });

    child!.on("exit", (code) => {
      clearTimeout(timeout);
      reject(new Error(`E2E API server exited early (code ${code}). Stderr:\n${stderrChunks.join("")}`));
    });
  });

  process.env.WEBGUARD_E2E_BASE_URL = ready.base_url;
  process.env.WEBGUARD_E2E_TOKEN = ready.token;
  process.env.WEBGUARD_E2E_OWNER_EMAIL = ready.owner_email;
  process.env.WEBGUARD_E2E_OWNER_PASSWORD = ready.owner_password;
  process.env.WEBGUARD_E2E_TARGET_URL = ready.target_url;
  process.env.WEBGUARD_E2E_MAIL_SINK_PATH = ready.mail_sink_path;
  process.env.VITE_API_BASE_URL = ready.base_url;

  return async () => {
    if (!child) return;
    child.kill("SIGTERM");
    await new Promise<void>((resolve) => {
      child!.once("exit", () => resolve());
      setTimeout(resolve, 5_000);
    });
  };
}
