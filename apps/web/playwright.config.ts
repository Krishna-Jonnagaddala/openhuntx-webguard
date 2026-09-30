import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig, devices } from '@playwright/test'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

/**
 * Slice 15 requirement 28: real browser E2E against the disposable
 * production-mode API/PostgreSQL stack. `WEBGUARD_E2E_BASE_URL` points
 * at that real, running API (see docs/audit/customer-platform-phase1.md
 * for how it's started); the frontend's own dev server is started
 * separately by `webServer` below so the E2E drives the actual built
 * UI, not a mock.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [['list']],
  globalSetup: path.join(__dirname, 'e2e', 'global-setup.ts'),
  timeout: 60_000,
  use: {
    baseURL: process.env.WEBGUARD_WEB_BASE_URL ?? 'http://127.0.0.1:5173',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // Explicit --host: on this machine Vite's default bind resolves
    // only to the IPv6 loopback (::1), which 127.0.0.1 below cannot
    // reach, causing Playwright's readiness probe to time out.
    command: 'npm run dev -- --host 127.0.0.1 --port 5173 --strictPort',
    url: 'http://127.0.0.1:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
})
