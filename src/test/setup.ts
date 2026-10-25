import { vi, afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// Tauri dialog plugin is not available under jsdom; tests that need folder
// selection drive state directly or mock it per-test.
vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(async () => null),
}));

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});
