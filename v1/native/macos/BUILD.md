# credmgr macOS Native App — v3

Thin WKWebView wrapper around the credmgr dashboard (http://127.0.0.1:9876).

v3 adds Touch ID / device-password unlock via `LocalAuthentication`,
forces `?native=1` on the dashboard URL so the service worker is bypassed
inside the native shell (no more stale-cache bugs), and adds a "Lock Vault"
menu-bar action (⌘L when the menu is open).

## Quick build (update the existing .app)

```bash
# Compile directly into the .app bundle on Desktop
swiftc main.swift \
  -o ./build/credmgr.app/Contents/MacOS/credmgr \
  -framework Cocoa -framework WebKit -framework LocalAuthentication
```

## Dev / test binary

```bash
swiftc main.swift -o /tmp/credmgr-native \
  -framework Cocoa -framework WebKit -framework LocalAuthentication
/tmp/credmgr-native
```

## What's in v2

### Bug fix — binary discovery
The old code relied on a hard-coded PATH string that omitted `~/bin`.
v2 uses `findCredmgr()` which searches absolute locations in order:

```
~/bin/credmgr              ← symlink added during credmgr install
/usr/local/bin/credmgr     ← Homebrew Intel
/opt/homebrew/bin/credmgr  ← Homebrew Apple Silicon
/usr/bin/credmgr
```

GUI apps on macOS launch with a minimal environment — `~/.zshrc`, `~/bin`,
and nvm shims are all absent. Absolute-path search is the correct fix.

### Menu bar status item
A lock icon appears in the macOS menu bar as long as the app is running.
Menu items:

| Item | Action |
|------|--------|
| Show / Hide credmgr | Toggle main window visibility |
| Restart Server | Stop the server process and relaunch with new loading screen |
| Quit credmgr | Terminate app + server |

Closing the window (⌘W / red button) **hides** it rather than quitting —
the app stays alive in the menu bar. Click the lock icon → Show credmgr
to bring it back.

To switch to menu-bar-only (no Dock icon), set `LSUIElement` to `true` in
`credmgr.app/Contents/Info.plist`.

### Animated loading screen
Replaces the plain grey text placeholder with a full-window `LoadingView`:

- Dark background with subtle radial gradient (`#111418` → `#212535`)
- SF Symbol `lock.fill` centred in the window, pulsing with scale + opacity
  + shadow-glow animations (CoreAnimation, `repeatCount = .infinity`)
- `NSProgressIndicator` (indeterminate spinner) below the icon
- "credmgr" title + status text that updates as the server starts
- **Error state**: icon shakes red + message + Retry button
- Fades out (0.45 s ease-out) when the dashboard page finishes loading

## Architecture

1. `findCredmgr()` — absolute-path binary search
2. `ServerManager` — spawn/health-check/stop lifecycle
3. `LoadingView` — animated splash (`NSView` + `CABasicAnimation`)
4. `AppDelegate` — window + webview + menu bar + startup orchestration

## Requirements

- macOS 11.0+ (SF Symbols, WKWebpagePreferences)
- `credmgr` CLI installed at any of the paths listed above
- Node.js on the same machine (used by credmgr dashboard)
