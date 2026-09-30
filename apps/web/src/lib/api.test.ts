import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, UNAUTHORIZED_EVENT } from "./api";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function clearCookies() {
  for (const cookie of document.cookie.split(";")) {
    const name = cookie.split("=")[0]?.trim();
    if (name) document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
  }
}

describe("api request layer (contract)", () => {
  beforeEach(() => {
    clearCookies();
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    clearCookies();
  });

  it("always sends credentials so the HttpOnly session cookie is included", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    await api.get("/v1/dashboard/summary");
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect(init?.credentials).toBe("include");
  });

  it("never attaches an Authorization header -- there is no token in JS-reachable storage", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    await api.get("/v1/dashboard/summary");
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect((init?.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("attaches the CSRF header on a state-changing request when the CSRF cookie is present", async () => {
    document.cookie = "wg_csrf=csrf-token-value";
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(201, { ok: true }));
    await api.post("/v1/assets", { url: "https://example.com/" });
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect((init?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-token-value");
  });

  it("does not attach a CSRF header on a GET request even when the CSRF cookie is present", async () => {
    document.cookie = "wg_csrf=csrf-token-value";
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    await api.get("/v1/dashboard/summary");
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect((init?.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
  });

  it("omits the CSRF header on a state-changing request when signed out (no CSRF cookie yet)", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    await api.post("/v1/auth/login", { email: "a@example.com", password: "whatever password" });
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect((init?.headers as Record<string, string>)["X-CSRF-Token"]).toBeUndefined();
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
    document.cookie = "wg_csrf=csrf-token-value";
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse(200, { ok: true }));
    await api.post("/v1/assets", { url: "https://example.com/" });
    const [, init] = vi.mocked(fetch).mock.calls[0];
    expect((init?.headers as Record<string, string>)["Content-Type"]).toBe("application/json");
    expect(init?.body).toBe(JSON.stringify({ url: "https://example.com/" }));
  });
});
