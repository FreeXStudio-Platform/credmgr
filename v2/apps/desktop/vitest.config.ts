import { defineConfig, mergeConfig } from "vitest/config";

import viteConfig from "./vite.config.ts";

// Unit tests only.  The Playwright specs under tests/e2e/ have the same *.spec.ts shape vitest would pick up by default,
// and they need a built app and a browser: they run through `npm run test:e2e`, never through `npm test`.
// Merged over vite.config.ts so the unit tests compile templates (`*.template.html?dc`) with the same plugin the build uses.
export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      include: ["tests/unit/**/*.test.ts"],
    },
  }),
);
