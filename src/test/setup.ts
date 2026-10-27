import { vi, afterEach, beforeEach } from "vitest";
import { cleanup } from "@testing-library/react";

// Tauri dialog plugin is not available under jsdom; tests that need folder
// selection drive state directly or mock it per-test.
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(async () => null),
}));

// The opener and app plugins are not wired to a Tauri backend under jsdom.
// Stub them so component imports resolve and calls are inert.
vi.mock("@tauri-apps/plugin-opener", () => ({
  openUrl: vi.fn(async () => undefined),
  openPath: vi.fn(async () => undefined),
}));
vi.mock("@tauri-apps/api/app", () => ({
  getVersion: vi.fn(async () => "1.0.0"),
}));

// Suppress the one-time first-run welcome modal in tests by pre-marking it
// seen, so existing interaction tests render straight into the app shell.
beforeEach(() => {
  try { localStorage.setItem("strazh.welcome.seen.v1", "1"); } catch { /* ignore */ }
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
