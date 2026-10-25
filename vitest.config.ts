import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Dev-only test config. Does not affect the production build (vite.config.ts)
// or the Tauri bundle.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
