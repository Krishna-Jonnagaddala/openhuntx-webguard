import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, UNAUTHORIZED_EVENT } from "./api";
import { clearSession, saveSession } from "./auth-storage";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("api request layer (contract)", () => {
  beforeEach(() => {
    clearSession();
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("attaches no Authorization header when signed out", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    await api.get("/v1/dashboard/summary");
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect((init?.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("attaches a Bearer Authorization header from the stored session", async () => {
    saveSession({
      token: "wgt_test-token",
      organizationId: "org-1",
      organizationName: "Org",
      principalId: "p-1",
      principalName: "Person",
      role: "owner",
    });
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    await api.get("/v1/dashboard/summary");
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect((init?.headers as Record<string, string>).Authorization).toBe("Bearer wgt_test-token");
  });

  it("builds a query string from provided params, skipping undefined and empty values", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    await api.get("/v1/findings", { severity: "high", status: undefined, cwe_id: "" });
    const [url] = vi.mocked(fetch).mock.calls[0];
    expect(url).toBe("http://127.0.0.1:8765/v1/findings?severity=high");
  });

  it("throws an ApiError with the server's code, message, and request id on failure", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse(403, { error: { code: "forbidden", message: "Not allowed.", request_id: "req-1" } }),
    );
    await expect(api.get("/v1/team")).rejects.toMatchObject({
      status: 403,
      code: "forbidden",
      message: "Not allowed.",
      requestId: "req-1",
    });
  });

  it("falls back to a generic ApiError when the failure body has no error object", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(new Response("", { status: 500 }));
    await expect(api.get("/v1/team")).rejects.toBeInstanceOf(ApiError);
  });

  it("dispatches the unauthorized event exactly on a 401 response", async () => {
    const handler = vi.fn();
    window.addEventListener(UNAUTHORIZED_EVENT, handler);
    vi.mocked(fetch).mockResolvedValueOnce(
      jsonResponse(401, { error: { code: "unauthenticated", message: "Sign in again." } }),
    );
    await expect(api.get("/v1/team")).rejects.toBeInstanceOf(ApiError);
    expect(handler).toHaveBeenCalledTimes(1);
    window.removeEventListener(UNAUTHORIZED_EVENT, handler);
  });

  it("does not dispatch the unauthorized event on a successful response", async () => {
    const handler = vi.fn();
    window.addEventListener(UNAUTHORIZED_EVENT, handler);
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    await api.get("/v1/dashboard/summary");
    expect(handler).not.toHaveBeenCalled();
    window.removeEventListener(UNAUTHORIZED_EVENT, handler);
  });

  it("sends a JSON content-type header only when a body is present", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    await api.post("/v1/assets", { url: "https://example.com/" });
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(init?.body).toBe(JSON.stringify({ url: "https://example.com/" }));
  });
});
