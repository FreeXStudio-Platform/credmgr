import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import dc from "./scripts/dc/vite-plugin-dc.mjs";

/**
 * The commit this build was made from (short sha), shown in About so every build can be traced.  Read once from the local git
 * checkout at build time (no network); `unknown` when there is no git or no repository (a source tarball).  `-dirty` is NOT
 * appended: About says which commit, the release notes say whether a build is a release.
 */
function buildCommit(): string {
  try {
    const sha = execFileSync("git", ["rev-parse", "--short", "HEAD"], { cwd: fileURLToPath(new URL(".", import.meta.url)), encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return /^[0-9a-f]{7,12}$/.test(sha) ? sha : "unknown";
  } catch {
    return "unknown";
  }
}

// `tauri dev` sets TAURI_DEV_HOST when it targets a device on the network.
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig({
  // The design is precompiled: the .dc.html template becomes an ES module of React.createElement calls at build
  // time (scripts/dc/), so nothing is parsed or evaluated at runtime and the production CSP needs no
  // 'unsafe-eval' and no 'unsafe-inline'.  No framework plugin: the generated code and the glue use createElement.
  // A build-time constant: the commit's short sha, inlined as a string literal (src/env.d.ts declares it).
  define: { __CREDMGR_BUILD_COMMIT__: JSON.stringify(buildCommit()) },
  plugins: [dc({ template: "src/design/app.template.html", runtime: "/src/dc/runtime.ts" })],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },

  build: {
    outDir: "build", // = tauri.conf.json build.frontendDist ("../build")
    emptyOutDir: true,
    target: "safari16", // WKWebView on macOS 13+
    sourcemap: false,
    modulePreload: { polyfill: false },
    // No data: URIs for fonts or images: CSP allows data: for img-src only, and fonts must be real files.
    assetsInlineLimit: 0,
    reportCompressedSize: false,
  },
});
