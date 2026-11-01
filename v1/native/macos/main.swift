// credmgr — native macOS wrapper v2
//
// Changes from v1:
//   • Finds credmgr binary by absolute path (fixes PATH discovery bug)
//   • Menu bar status item (lock icon) — persists when window is closed
//   • Animated loading screen: pulsing lock icon + spinner + error+retry state
//   • Window close → hide (not quit); app lives in menu bar

import Cocoa
import WebKit
import LocalAuthentication

// ────────────────────────────────────────────────────────────────────────────
// Binary discovery
// Searches common absolute locations so we don't depend on the launch
// environment's PATH (macOS GUI apps start with a minimal environment that
// doesn't include ~/.zshrc, ~/bin, or nvm shims).
// ────────────────────────────────────────────────────────────────────────────

func findCredmgr() -> String? {
    let home = NSHomeDirectory()
    let candidates = [
        "\(home)/bin/credmgr",           // most common dev install (symlink)
        "/usr/local/bin/credmgr",        // Homebrew Intel
        "/opt/homebrew/bin/credmgr",     // Homebrew Apple Silicon
        "/opt/homebrew/sbin/credmgr",
        "/usr/bin/credmgr",
    ]
    return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
}

// Node.js binary discovery — GUI apps don't inherit the user's PATH, so
// /opt/homebrew/bin (where Homebrew installs node) is not present.
// Priority: bundled node (self-contained .app) → Homebrew AS → Homebrew Intel → nvm → Volta
func findNode() -> String? {
    // 1. Bundled Node.js inside the .app bundle (self-contained distribution).
    //    Place a node binary at Contents/Resources/node to use this path.
    if let bundleNode = Bundle.main.path(forResource: "node", ofType: nil),
       FileManager.default.isExecutableFile(atPath: bundleNode) {
        return bundleNode
    }

    let home = NSHomeDirectory()
    let candidates = [
        "/opt/homebrew/bin/node",                     // Homebrew Apple Silicon
        "/usr/local/bin/node",                        // Homebrew Intel
        "\(home)/.nvm/versions/node/current/bin/node", // nvm (symlink)
        "\(home)/.volta/bin/node",                    // Volta version manager
        "/usr/bin/node",
    ]
    return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
}

// ────────────────────────────────────────────────────────────────────────────
// ServerManager
// Spawns `credmgr dashboard` and polls /api/health until it responds 200.
// ────────────────────────────────────────────────────────────────────────────

class ServerManager {
    var process: Process?
    let port = 9876

    func ensureRunning(onStatus: @escaping (String) -> Void,
                       completion: @escaping (Bool) -> Void) {
        checkHealth { [weak self] alive in
            guard let self = self else { return }
            if alive { completion(true); return }
            self.startServer(onStatus: onStatus)
            var attempts = 0
            Timer.scheduledTimer(withTimeInterval: 0.4, repeats: true) { timer in
                attempts += 1
                self.checkHealth { up in
                    if up {
                        timer.invalidate()
                        completion(true)
                    } else if attempts >= 25 {   // ~10 s total
                        timer.invalidate()
                        completion(false)
                    }
                }
            }
        }
    }

    func checkHealth(completion: @escaping (Bool) -> Void) {
        guard let url = URL(string: "http://127.0.0.1:\(port)/api/health") else {
            completion(false); return
        }
        var req = URLRequest(url: url)
        req.timeoutInterval = 1.0
        URLSession.shared.dataTask(with: req) { _, resp, _ in
            DispatchQueue.main.async {
                completion((resp as? HTTPURLResponse)?.statusCode == 200)
            }
        }.resume()
    }

    func startServer(onStatus: @escaping (String) -> Void) {
        guard let path = findCredmgr() else {
            NSLog("credmgr: binary not found — searched ~/bin, /usr/local/bin, /opt/homebrew/bin")
            onStatus("credmgr binary not found")
            return
        }
        NSLog("credmgr: launching \(path) dashboard --port \(port) --no-open")
        onStatus("Launching server at \(path)…")

        let p = Process()
        if let nodePath = findNode() {
            // Preferred path: invoke node directly — completely avoids PATH lookup.
            // The credmgr script works as a plain Node.js program regardless of shebang.
            NSLog("credmgr: using node at \(nodePath)")
            p.executableURL = URL(fileURLWithPath: nodePath)
            p.arguments     = [path, "dashboard", "--port", "\(port)", "--no-open"]
        } else {
            // Fallback: login shell — sources ~/.zprofile which sets up Homebrew PATH
            NSLog("credmgr: node not found at known paths, falling back to zsh -l")
            p.executableURL = URL(fileURLWithPath: "/bin/zsh")
            p.arguments     = ["-l", "-c", "\(path) dashboard --port \(port) --no-open"]
        }
        p.standardOutput = Pipe()
        p.standardError  = Pipe()
        do {
            try p.run()
            process = p
        } catch {
            NSLog("credmgr: failed to launch — \(error)")
        }
    }

    func stopServer() {
        process?.terminate()
        process = nil
    }
}

// ────────────────────────────────────────────────────────────────────────────
// LoadingView
// Full-window animated splash that sits on top of the WKWebView during startup.
// Three states:
//   loading — pulsing lock icon + indeterminate spinner + status text
//   error   — red icon + shake animation + error message + retry button
//   done    — fade out and remove from hierarchy
// ────────────────────────────────────────────────────────────────────────────

class LoadingView: NSView {

    // ── Sub-views ────────────────────────────────────────────────────────────
    private let logoView    = NSImageView()
    private let titleLabel  = NSTextField(labelWithString: "credmgr")
    private let spinner     = NSProgressIndicator()
    private let statusLabel = NSTextField(labelWithString: "Starting server…")
    private let retryButton = NSButton(title: "Retry", target: nil, action: nil)

    /// Called when the user taps Retry; wired by AppDelegate.
    var onRetry: (() -> Void)?

    // ── State ────────────────────────────────────────────────────────────────
    private var pulseStarted = false
    private var isErrorState = false

    // Brand colours
    private static let bgColor     = NSColor(srgbRed: 0.07, green: 0.08, blue: 0.10, alpha: 1)
    private static let accentColor = NSColor(srgbRed: 0.38, green: 0.68, blue: 1.00, alpha: 1)
    private static let errorColor  = NSColor(srgbRed: 1.00, green: 0.42, blue: 0.42, alpha: 1)

    // ── Init ─────────────────────────────────────────────────────────────────

    required init?(coder: NSCoder) { fatalError() }

    override init(frame: NSRect) {
        super.init(frame: frame)
        setup()
    }

    private func setup() {
        // Force dark appearance so NSProgressIndicator / labels look right
        // on the dark background regardless of system setting.
        appearance = NSAppearance(named: .darkAqua)

        wantsLayer = true
        layer?.backgroundColor = LoadingView.bgColor.cgColor

        // Subtle radial-ish gradient for depth: slightly lighter in the center
        let grad = CAGradientLayer()
        grad.type    = .radial
        grad.colors  = [
            NSColor(srgbRed: 0.13, green: 0.15, blue: 0.21, alpha: 1).cgColor,
            LoadingView.bgColor.cgColor,
        ]
        grad.locations   = [0, 1]
        grad.startPoint  = CGPoint(x: 0.5, y: 0.5)
        grad.endPoint    = CGPoint(x: 1.0, y: 1.0)
        grad.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
        layer?.addSublayer(grad)

        // ── Lock icon ────────────────────────────────────────────────────────
        if #available(macOS 11.0, *) {
            let sym = NSImage(systemSymbolName: "lock.fill",
                              accessibilityDescription: "credmgr")
            let cfg = NSImage.SymbolConfiguration(pointSize: 54, weight: .medium)
            logoView.image = sym?.withSymbolConfiguration(cfg)
            logoView.contentTintColor = LoadingView.accentColor
        }
        logoView.imageScaling = .scaleProportionallyUpOrDown
        logoView.wantsLayer   = true
        addSubview(logoView)

        // ── App title ────────────────────────────────────────────────────────
        titleLabel.font      = NSFont.systemFont(ofSize: 22, weight: .semibold)
        titleLabel.textColor = .white
        titleLabel.alignment = .center
        addSubview(titleLabel)

        // ── Spinner ──────────────────────────────────────────────────────────
        spinner.style           = .spinning
        spinner.controlSize     = .regular
        spinner.isIndeterminate = true
        spinner.startAnimation(nil)
        addSubview(spinner)

        // ── Status line ──────────────────────────────────────────────────────
        statusLabel.font             = NSFont.systemFont(ofSize: 12.5)
        statusLabel.textColor        = .secondaryLabelColor
        statusLabel.alignment        = .center
        statusLabel.maximumNumberOfLines = 4
        addSubview(statusLabel)

        // ── Retry button (hidden until error state) ──────────────────────────
        retryButton.bezelStyle = .rounded
        retryButton.isHidden   = true
        retryButton.target     = self
        retryButton.action     = #selector(retryTapped)
        addSubview(retryButton)
    }

    // ── Pulse animation starts only once the view is in the window ───────────
    // CoreAnimation layers are attached to the render tree on viewDidMoveToWindow;
    // trying to add animations before this point has no visible effect.

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        guard window != nil, !pulseStarted, !isErrorState else { return }
        pulseStarted = true
        startPulse()
    }

    // ── Animation helpers ────────────────────────────────────────────────────

    private func startPulse() {
        guard let layer = logoView.layer else { return }

        // Scale: 0.88 ↔ 1.12 at 1.5 s per cycle
        let pulse = CABasicAnimation(keyPath: "transform.scale")
        pulse.fromValue      = 0.88
        pulse.toValue        = 1.12
        pulse.duration       = 1.5
        pulse.autoreverses   = true
        pulse.repeatCount    = .infinity
        pulse.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        layer.add(pulse, forKey: "pulse")

        // Opacity: 0.60 ↔ 1.0 in sync with the scale (breathe effect)
        let breathe = CABasicAnimation(keyPath: "opacity")
        breathe.fromValue      = 0.60
        breathe.toValue        = 1.0
        breathe.duration       = 1.5
        breathe.autoreverses   = true
        breathe.repeatCount    = .infinity
        breathe.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        layer.add(breathe, forKey: "breathe")

        // Subtle glow via shadow animation
        layer.shadowColor   = LoadingView.accentColor.cgColor
        layer.shadowRadius  = 16
        layer.shadowOffset  = .zero
        let glow = CABasicAnimation(keyPath: "shadowOpacity")
        glow.fromValue    = 0.0
        glow.toValue      = 0.55
        glow.duration     = 1.5
        glow.autoreverses = true
        glow.repeatCount  = .infinity
        glow.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        layer.add(glow, forKey: "glow")
    }

    private func stopPulse() {
        logoView.layer?.removeAllAnimations()
        logoView.layer?.shadowOpacity = 0
    }

    // ── Public API (called by AppDelegate) ───────────────────────────────────

    func updateStatus(_ text: String) {
        statusLabel.stringValue = text
    }

    func showError(_ message: String) {
        guard !isErrorState else { return }
        isErrorState = true
        stopPulse()

        // Red tint
        if #available(macOS 11.0, *) {
            logoView.contentTintColor = LoadingView.errorColor
        }

        // Horizontal shake
        if let layer = logoView.layer {
            let shake = CAKeyframeAnimation(keyPath: "transform.translation.x")
            shake.values   = [0, -14, 14, -10, 10, -6, 6, -3, 3, 0]
            shake.duration = 0.65
            shake.timingFunction = CAMediaTimingFunction(name: .easeOut)
            layer.add(shake, forKey: "shake")
        }

        spinner.stopAnimation(nil)
        spinner.isHidden = true

        statusLabel.stringValue  = message
        statusLabel.textColor    = LoadingView.errorColor

        retryButton.isHidden = false
        needsLayout          = true
    }

    func resetToLoading(_ status: String = "Restarting server…") {
        isErrorState = false
        pulseStarted = false

        if #available(macOS 11.0, *) {
            logoView.contentTintColor = LoadingView.accentColor
        }

        statusLabel.textColor   = .secondaryLabelColor
        statusLabel.stringValue = status
        retryButton.isHidden    = true
        spinner.isHidden        = false
        spinner.startAnimation(nil)
        needsLayout = true

        // Layer is already in tree; re-start pulse directly
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.pulseStarted = true
            self.startPulse()
        }
    }

    /// Fade out and remove once the webview has finished loading.
    func dismiss() {
        stopPulse()
        NSAnimationContext.runAnimationGroup({ ctx in
            ctx.duration       = 0.45
            ctx.timingFunction = CAMediaTimingFunction(name: .easeOut)
            animator().alphaValue = 0
        }, completionHandler: { self.removeFromSuperview() })
    }

    // ── Layout ───────────────────────────────────────────────────────────────
    // Everything is positioned relative to the view's geometric centre so it
    // stays centred when the window is resized.

    override func layout() {
        super.layout()
        let cx = bounds.midX
        let cy = bounds.midY

        // Logo — 76 × 76, centred at (cx, cy + 62)
        let logoSize: CGFloat = 76
        logoView.frame = NSRect(x: cx - logoSize / 2, y: cy + 24,
                                width: logoSize, height: logoSize)

        // Title — below logo with a 10 pt gap
        titleLabel.frame = NSRect(x: cx - 120, y: cy - 16, width: 240, height: 28)

        // Spinner
        spinner.frame = NSRect(x: cx - 11, y: cy - 54, width: 22, height: 22)

        if isErrorState {
            statusLabel.frame = NSRect(x: cx - 220, y: cy - 118, width: 440, height: 56)
            retryButton.frame = NSRect(x: cx - 44,  y: cy - 156, width: 88,  height: 28)
        } else {
            statusLabel.frame = NSRect(x: cx - 200, y: cy - 82,  width: 400, height: 20)
            retryButton.frame = .zero
        }
    }

    // ── Mouse handling ───────────────────────────────────────────────────────
    // Three complementary mechanisms so the window is always movable while the
    // loading/error screen is visible:
    //   1. acceptsFirstMouse  — activates app on the very first click
    //   2. mouseDownCanMoveWindow — tells NSWindow this view participates in drag
    //   3. hitTest override — makes LoadingView the hit target (not its subviews),
    //      so mouseDown always reaches this override rather than subviews that
    //      would swallow the event (NSImageView handles image drags, etc.)
    //   4. mouseDown override — direct performDrag call as belt-and-suspenders

    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { return true }

    /// Participates in window background dragging so the window moves
    /// when the user drags anywhere on this view (except the Retry button).
    override var mouseDownCanMoveWindow: Bool { return true }

    /// Route all hit tests to self, bypassing subviews — this ensures
    /// mouseDown is always delivered to LoadingView and not consumed by
    /// the NSImageView / NSProgressIndicator / NSTextField subviews.
    /// Exception: the Retry button still needs to be clickable.
    override func hitTest(_ point: NSPoint) -> NSView? {
        guard bounds.contains(point) else { return nil }
        if !retryButton.isHidden && retryButton.frame.contains(point) {
            return retryButton
        }
        return self
    }

    /// Belt-and-suspenders: explicitly start a window drag.
    override func mouseDown(with event: NSEvent) {
        window?.performDrag(with: event)
    }

    // ── Actions ──────────────────────────────────────────────────────────────

    @objc private func retryTapped() {
        onRetry?()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// AppDelegate
// ────────────────────────────────────────────────────────────────────────────

class AppDelegate: NSObject, NSApplicationDelegate,
                   WKNavigationDelegate, WKUIDelegate,
                   NSMenuDelegate, NSWindowDelegate,
                   WKScriptMessageHandler {

    var window: NSWindow!
    var webView: WKWebView!
    var loadingView: LoadingView!
    var statusItem: NSStatusItem!
    let server = ServerManager()

    private var toggleMenuItem: NSMenuItem!     // updated title on menu-open
    private var isUnlocked = false              // gated by Touch ID / device password

    // NSPasteboard.general is the single OS-wide clipboard shared by every
    // app on the system — there is no "credmgr-only" pasteboard. We record
    // the changeCount right after writing a secret so the delayed/blur clear
    // can verify nothing else has been copied since, instead of blindly
    // nuking whatever the user has copied in the meantime (which previously
    // broke ordinary system-wide copy/paste for up to 30 s after any
    // credmgr secret copy).
    private var pendingSecretChangeCount: Int? = nil

    /// URL the dashboard is loaded from. The `?native=1` flag tells app.js
    /// to skip the service-worker registration so cache never gets stale
    /// inside the native shell.
    private func dashboardURL() -> URL? {
        return URL(string: "http://127.0.0.1:\(server.port)/?native=1")
    }

    // Application-level event monitor for window dragging.
    // Watches for a left-mouse drag gesture starting in the header zone (top 56 pt)
    // and calls window.performDrag — non-destructively, without stealing clicks
    // from WKWebView's interactive elements.
    private var dragMonitor: Any?
    private var dragOrigin: NSPoint?
    private var dragOriginEvent: NSEvent?

    // ── Native inactivity lock ──────────────────────────────────────────────
    // The Touch ID / password gate (requireUnlock/isUnlocked) was previously
    // once-per-launch only — there was no re-lock for "walked away from an
    // unlocked window" or "switched away and came back much later" at the
    // native layer. A local event monitor timestamps the last activity THIS
    // app received; a periodic timer compares that against the same
    // lockTimeoutMinutes the dashboard's own PIN session already uses (read
    // from .credmgr/config.json), so one timeout setting governs both layers
    // instead of a second, confusing native-only control. Using a LOCAL (not
    // global) event monitor is deliberate: it needs no Accessibility
    // permission, and correctly reads as "idle" both while credmgr sits
    // frontmost untouched AND while the user is away in another app —
    // either way, no events are delivered to credmgr's own windows.
    private var idleMonitor: Any?
    private var idleCheckTimer: Timer?
    private var lastLocalActivityAt = Date()

    private func setupIdleMonitor() {
        idleMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.mouseMoved, .leftMouseDown, .rightMouseDown, .keyDown, .scrollWheel]
        ) { [weak self] event in
            self?.lastLocalActivityAt = Date()
            return event
        }
        idleCheckTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            self?.checkIdleTimeout()
        }
    }

    private func checkIdleTimeout() {
        guard isUnlocked else { return }
        if Date().timeIntervalSince(lastLocalActivityAt) >= AppDelegate.inactivityTimeoutSeconds() {
            lockApp()
        }
    }

    /// Resolves alongside the discovered credmgr binary: `<repoRoot>/bin/credmgr`
    /// → strip two path components → `<repoRoot>/.credmgr/config.json`. Mirrors
    /// lib/crypto.js's own CREDMGR_DIR resolution so both layers agree on the
    /// same file without either hardcoding the other's install location.
    private static let credmgrConfigPath: String? = {
        guard let bin = findCredmgr() else { return nil }
        let resolved = (bin as NSString).resolvingSymlinksInPath
        let binDir = (resolved as NSString).deletingLastPathComponent
        let repoRoot = (binDir as NSString).deletingLastPathComponent
        return repoRoot + "/.credmgr/config.json"
    }()

    /// Same lockTimeoutMinutes the dashboard's PIN session TTL uses (see
    /// lib/lock.js DEFAULT_TTL_MINUTES) — read fresh each check so changing it
    /// in Settings takes effect here without an app restart.
    private static func inactivityTimeoutSeconds() -> TimeInterval {
        let fallbackMinutes: Double = 15
        guard let path = credmgrConfigPath,
              let data = FileManager.default.contents(atPath: path),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let minutes = obj["lockTimeoutMinutes"] as? Double, minutes > 0
        else { return fallbackMinutes * 60 }
        return minutes * 60
    }

    // ── Lifecycle ────────────────────────────────────────────────────────────

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMainMenu()
        buildWindow()
        setupMenuBar()
        beginStartupSequence()
    }

    // ── Main menu (required for Cmd+C/V/X/A/Z to work inside WKWebView) ────
    // WKWebView forwards standard editing shortcuts to first-responder
    // selectors (copy:, paste:, cut:, selectAll:, undo:, redo:). Those
    // selectors are only wired up when the application has a main menu with
    // matching key equivalents — NSApplication doesn't synthesize them.
    private func setupMainMenu() {
        let mainMenu = NSMenu()

        // App menu (first menu; title is read from Info.plist at runtime).
        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)
        let appMenu = NSMenu()
        let appName = ProcessInfo.processInfo.processName
        appMenu.addItem(NSMenuItem(title: "About \(appName)",
                                   action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)),
                                   keyEquivalent: ""))
        appMenu.addItem(.separator())
        appMenu.addItem(NSMenuItem(title: "Hide \(appName)",
                                   action: #selector(NSApplication.hide(_:)),
                                   keyEquivalent: "h"))
        let hideOthers = NSMenuItem(title: "Hide Others",
                                    action: #selector(NSApplication.hideOtherApplications(_:)),
                                    keyEquivalent: "h")
        hideOthers.keyEquivalentModifierMask = [.command, .option]
        appMenu.addItem(hideOthers)
        appMenu.addItem(NSMenuItem(title: "Show All",
                                   action: #selector(NSApplication.unhideAllApplications(_:)),
                                   keyEquivalent: ""))
        appMenu.addItem(.separator())
        appMenu.addItem(NSMenuItem(title: "Quit \(appName)",
                                   action: #selector(NSApplication.terminate(_:)),
                                   keyEquivalent: "q"))
        appMenuItem.submenu = appMenu

        // Edit menu — actions target first responder (WKWebView).
        let editMenuItem = NSMenuItem()
        mainMenu.addItem(editMenuItem)
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(NSMenuItem(title: "Undo",
                                    action: Selector(("undo:")),
                                    keyEquivalent: "z"))
        let redo = NSMenuItem(title: "Redo",
                              action: Selector(("redo:")),
                              keyEquivalent: "z")
        redo.keyEquivalentModifierMask = [.command, .shift]
        editMenu.addItem(redo)
        editMenu.addItem(.separator())
        editMenu.addItem(NSMenuItem(title: "Cut",
                                    action: #selector(NSText.cut(_:)),
                                    keyEquivalent: "x"))
        editMenu.addItem(NSMenuItem(title: "Copy",
                                    action: #selector(NSText.copy(_:)),
                                    keyEquivalent: "c"))
        editMenu.addItem(NSMenuItem(title: "Paste",
                                    action: #selector(NSText.paste(_:)),
                                    keyEquivalent: "v"))
        let pasteMatch = NSMenuItem(title: "Paste and Match Style",
                                    action: Selector(("pasteAsPlainText:")),
                                    keyEquivalent: "v")
        pasteMatch.keyEquivalentModifierMask = [.command, .option, .shift]
        editMenu.addItem(pasteMatch)
        editMenu.addItem(NSMenuItem(title: "Delete",
                                    action: #selector(NSText.delete(_:)),
                                    keyEquivalent: ""))
        editMenu.addItem(NSMenuItem(title: "Select All",
                                    action: #selector(NSText.selectAll(_:)),
                                    keyEquivalent: "a"))
        editMenuItem.submenu = editMenu

        // View menu — Reload for the web view.
        let viewMenuItem = NSMenuItem()
        mainMenu.addItem(viewMenuItem)
        let viewMenu = NSMenu(title: "View")
        viewMenu.addItem(NSMenuItem(title: "Reload",
                                    action: #selector(reloadWebView),
                                    keyEquivalent: "r"))
        viewMenuItem.submenu = viewMenu

        // Window menu — standard minimize/zoom/close.
        let windowMenuItem = NSMenuItem()
        mainMenu.addItem(windowMenuItem)
        let windowMenu = NSMenu(title: "Window")
        windowMenu.addItem(NSMenuItem(title: "Minimize",
                                      action: #selector(NSWindow.performMiniaturize(_:)),
                                      keyEquivalent: "m"))
        windowMenu.addItem(NSMenuItem(title: "Zoom",
                                      action: #selector(NSWindow.performZoom(_:)),
                                      keyEquivalent: ""))
        windowMenu.addItem(NSMenuItem(title: "Close",
                                      action: #selector(NSWindow.performClose(_:)),
                                      keyEquivalent: "w"))
        windowMenuItem.submenu = windowMenu
        NSApp.windowsMenu = windowMenu

        NSApp.mainMenu = mainMenu
    }

    @objc private func reloadWebView() {
        webView?.reload()
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let m = dragMonitor { NSEvent.removeMonitor(m); dragMonitor = nil }
        server.stopServer()
    }

    /// Clicking the red close button hides the window; the app stays in the menu bar.
    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    /// Closing the window hides it — the app lives on in the menu bar.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    /// The window is only ever `orderOut`, never actually closed, so AppKit's
    /// default Dock-reopen behavior (which looks for a window it considers
    /// "closed") never kicks in. Without this, clicking the Dock icon after
    /// the red button did nothing — only the menu-bar "Show credmgr" item
    /// worked, because that path calls makeKeyAndOrderFront/activate itself
    /// (see toggleWindow). Reopen now does the same thing.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        return true
    }

    // ── Drag monitor ─────────────────────────────────────────────────────────
    // This is the authoritative drag mechanism for the loaded-dashboard state.
    // It runs at the application level so it works even when WKWebView holds
    // first-responder focus, without blocking any WKWebView click events.

    private func setupDragMonitor() {
        dragMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.leftMouseDown, .leftMouseDragged, .leftMouseUp]
        ) { [weak self] event in
            guard let self = self else { return event }
            switch event.type {
            case .leftMouseDown:
                self.dragOrigin = event.locationInWindow
                self.dragOriginEvent = event
            case .leftMouseDragged:
                guard let origin = self.dragOrigin,
                      let downEvt = self.dragOriginEvent,
                      let cv = self.window?.contentView else { break }
                let dist = hypot(event.locationInWindow.x - origin.x,
                                 event.locationInWindow.y - origin.y)
                // Header zone = top 56 pt of the content view (matches --header-h in CSS).
                // Only trigger when it's a genuine drag (>4 pt) not a click.
                if dist > 4 && origin.y >= cv.bounds.height - 56 {
                    self.dragOrigin = nil
                    self.dragOriginEvent = nil
                    self.window.performDrag(with: downEvt)
                }
            case .leftMouseUp:
                self.dragOrigin = nil
                self.dragOriginEvent = nil
            default: break
            }
            return event
        }
    }

    // ── Server startup sequence ──────────────────────────────────────────────

    private func beginStartupSequence() {
        loadingView.updateStatus("Starting server…")
        server.ensureRunning(onStatus: { [weak self] msg in
            self?.loadingView.updateStatus(msg)
        }) { [weak self] ok in
            guard let self = self else { return }
            if ok {
                self.requireUnlock { [weak self] unlocked in
                    guard let self = self else { return }
                    if unlocked {
                        self.loadingView.updateStatus("Loading dashboard…")
                        if let url = self.dashboardURL() {
                            self.webView.load(URLRequest(url: url))
                        }
                    } else {
                        self.loadingView.showError(
                            "Authentication required.\n\n" +
                            "credmgr won't show your vault until you unlock with Touch ID or your password."
                        )
                    }
                }
            } else {
                let binary = findCredmgr() ?? "not found"
                self.loadingView.showError(
                    "Server not reachable on port \(self.server.port).\n\n" +
                    "Binary: \(binary)\n" +
                    "Check that Node.js is installed and try Retry."
                )
            }
        }
    }

    // ── Authentication gate ──────────────────────────────────────────────────
    // Uses LocalAuthentication so the OS picks the right modality:
    //   • Touch ID on supported MacBooks / Magic Keyboards
    //   • Apple Watch wrist auth
    //   • Account password fallback when biometrics aren't available
    // .deviceOwnerAuthentication = biometric OR password (never blocks the user
    // out of their own machine — required for a credential manager).
    private func requireUnlock(completion: @escaping (Bool) -> Void) {
        if isUnlocked { completion(true); return }

        let ctx = LAContext()
        ctx.localizedReason = "Unlock your credmgr vault"
        ctx.localizedFallbackTitle = "Use Password"

        var error: NSError?
        let policy: LAPolicy = .deviceOwnerAuthentication
        guard ctx.canEvaluatePolicy(policy, error: &error) else {
            // No biometrics + no password configured: skip the gate so the user
            // is never locked out of their own machine. The dashboard is still
            // bound to 127.0.0.1 with bearer-token auth.
            NSLog("credmgr: LAContext unavailable — \(error?.localizedDescription ?? "unknown") — skipping unlock")
            self.isUnlocked = true
            self.lastLocalActivityAt = Date()
            completion(true)
            return
        }

        loadingView.updateStatus("Waiting for Touch ID…")
        ctx.evaluatePolicy(policy,
                           localizedReason: "Unlock your credmgr vault") { [weak self] success, evalErr in
            DispatchQueue.main.async {
                guard let self = self else { return }
                if success {
                    self.isUnlocked = true
                    self.lastLocalActivityAt = Date()
                    completion(true)
                } else {
                    NSLog("credmgr: unlock failed — \(evalErr?.localizedDescription ?? "user cancelled")")
                    completion(false)
                }
            }
        }
    }

    /// Re-locks the app and hides the dashboard. Triggered from the menu bar.
    @objc private func lockApp() {
        isUnlocked = false
        webView.load(URLRequest(url: URL(string: "about:blank")!))

        loadingView.removeFromSuperview()
        loadingView = LoadingView(frame: window.contentView!.bounds)
        loadingView.autoresizingMask = [.width, .height]
        loadingView.onRetry = { [weak self] in self?.beginStartupSequence() }
        window.contentView?.addSubview(loadingView)
        loadingView.updateStatus("Locked — click to unlock")

        requireUnlock { [weak self] unlocked in
            guard let self = self else { return }
            if unlocked, let url = self.dashboardURL() {
                self.loadingView.updateStatus("Loading dashboard…")
                self.webView.load(URLRequest(url: url))
            }
        }
    }

    // ── Menu bar ─────────────────────────────────────────────────────────────

    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

        if let btn = statusItem.button {
            if #available(macOS 11.0, *) {
                let img = NSImage(systemSymbolName: "lock.fill",
                                  accessibilityDescription: "credmgr")
                img?.isTemplate = true   // auto-inverts for dark/light menu bars
                btn.image = img
            } else {
                btn.title = "🔑"
            }
            btn.toolTip = "credmgr"
        }

        let menu = NSMenu()
        menu.delegate = self

        // Item 0 — title is updated dynamically in menuWillOpen
        toggleMenuItem = NSMenuItem(title: "Show credmgr",
                                    action: #selector(toggleWindow),
                                    keyEquivalent: "")
        toggleMenuItem.target = self
        menu.addItem(toggleMenuItem)

        menu.addItem(.separator())

        let lock = NSMenuItem(title: "Lock Vault",
                              action: #selector(lockApp),
                              keyEquivalent: "l")
        lock.target = self
        menu.addItem(lock)

        let restart = NSMenuItem(title: "Restart Server",
                                 action: #selector(restartServer),
                                 keyEquivalent: "r")
        restart.target = self
        menu.addItem(restart)

        menu.addItem(.separator())

        let quit = NSMenuItem(title: "Quit credmgr",
                              action: #selector(quitApp),
                              keyEquivalent: "q")
        quit.target = self
        menu.addItem(quit)

        statusItem.menu = menu
    }

    // Refresh the Show/Hide label each time the menu opens
    func menuWillOpen(_ menu: NSMenu) {
        toggleMenuItem.title = window.isVisible ? "Hide credmgr" : "Show credmgr"
    }

    @objc private func toggleWindow() {
        if window.isVisible {
            window.orderOut(nil)
        } else {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }
    }

    @objc private func restartServer() {
        // Bring window to front so the user can see the restart progress
        if !window.isVisible {
            window.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
        }

        server.stopServer()

        // Rebuild the loading view (the old one may have been dismissed/faded out)
        loadingView.removeFromSuperview()
        loadingView = LoadingView(frame: window.contentView!.bounds)
        loadingView.autoresizingMask = [.width, .height]
        loadingView.onRetry = { [weak self] in self?.restartServer() }
        window.contentView?.addSubview(loadingView)

        loadingView.updateStatus("Restarting server…")

        server.ensureRunning(onStatus: { [weak self] msg in
            self?.loadingView.updateStatus(msg)
        }) { [weak self] ok in
            guard let self = self else { return }
            if ok {
                self.loadingView.updateStatus("Loading dashboard…")
                if let url = self.dashboardURL() {
                    self.webView.load(URLRequest(url: url))
                }
            } else {
                self.loadingView.showError("Server failed to start again.\n\nCheck credmgr installation and Node.js runtime.")
            }
        }
    }

    @objc private func quitApp() {
        NSApp.terminate(nil)
    }

    // ── Window + WebView construction ────────────────────────────────────────

    private func buildWindow() {
        let screen = NSScreen.main?.visibleFrame
                     ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        let size   = NSSize(width:  min(1200, screen.width  - 120),
                            height: min(820,  screen.height - 120))
        let origin = NSPoint(x: screen.minX + (screen.width  - size.width)  / 2,
                             y: screen.minY + (screen.height - size.height) / 2)

        let style: NSWindow.StyleMask = [
            .titled, .closable, .miniaturizable, .resizable, .fullSizeContentView
        ]
        window = NSWindow(contentRect: NSRect(origin: origin, size: size),
                          styleMask: style, backing: .buffered, defer: false)

        window.title                       = ""
        window.titlebarAppearsTransparent  = true
        window.titleVisibility             = .hidden
        window.isMovable                   = true
        window.isMovableByWindowBackground = true
        window.isRestorable                = false
        window.setFrameAutosaveName("")
        window.minSize = NSSize(width: 720, height: 480)
        // Match loading screen background to avoid flash of white on startup
        window.backgroundColor = NSColor(srgbRed: 0.07, green: 0.08, blue: 0.10, alpha: 1)

        // WKWebView
        let cfg = WKWebViewConfiguration()
        cfg.preferences.setValue(true, forKey: "developerExtrasEnabled")
        cfg.websiteDataStore = WKWebsiteDataStore.default()
        // JS → native bridge: concealed clipboard writes. navigator.clipboard
        // can't tag a write as transient/concealed, so clipboard managers
        // would archive every copied secret. The dashboard posts secrets here
        // instead when running inside this shell.
        cfg.userContentController.add(self, name: "copySecret")
        cfg.userContentController.add(self, name: "clearClipboard")
        if #available(macOS 11.0, *) {
            let prefs = WKWebpagePreferences()
            prefs.allowsContentJavaScript = true
            cfg.defaultWebpagePreferences = prefs
        }
        webView = WKWebView(frame: window.contentView!.bounds, configuration: cfg)
        webView.autoresizingMask  = [.width, .height]
        webView.navigationDelegate = self
        webView.uiDelegate         = self
        webView.setValue(false, forKey: "drawsBackground")
        // Append a marker so app.js can detect the native shell even if the
        // URL flag is stripped (defence-in-depth against stale caches that
        // already have the SW registered).
        webView.customUserAgent = "credmgr-native/1.0 (macOS) WKWebView"
        window.contentView?.addSubview(webView)

        // LoadingView sits on top of the webview
        loadingView = LoadingView(frame: window.contentView!.bounds)
        loadingView.autoresizingMask = [.width, .height]
        loadingView.onRetry = { [weak self] in self?.restartServer() }
        window.contentView?.addSubview(loadingView)

        // Wire the window delegate so close-button hides rather than destroys.
        window.delegate = self

        // Install the application-level drag monitor so any drag gesture
        // starting in the header zone (top 56 pt) moves the window without
        // blocking WKWebView's own click handling.
        setupDragMonitor()
        setupIdleMonitor()

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // ── WKNavigationDelegate ─────────────────────────────────────────────────

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        loadingView.dismiss()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!,
                 withError error: Error) {
        NSLog("credmgr: nav failed — \(error.localizedDescription)")
    }

    // Show error in loading view if provisional nav fails (server crashed after health-check)
    func webView(_ webView: WKWebView,
                 didFailProvisionalNavigation navigation: WKNavigation!,
                 withError error: Error) {
        NSLog("credmgr: provisional nav failed — \(error.localizedDescription)")
        if loadingView.superview != nil {
            loadingView.showError(
                "Could not load dashboard.\n\n" +
                "The server may have stopped — use 'Restart Server' from the menu bar."
            )
        }
    }

    // Allow file upload (drag-and-drop .env import in dashboard)
    func webView(_ webView: WKWebView,
                 runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping ([URL]?) -> Void) {
        let panel = NSOpenPanel()
        panel.canChooseFiles           = true
        panel.canChooseDirectories     = false
        panel.allowsMultipleSelection  = parameters.allowsMultipleSelection
        panel.begin { completionHandler($0 == .OK ? panel.urls : nil) }
    }

    // ── JS dialog panels ─────────────────────────────────────────────────────
    // WKWebView has NO built-in alert()/confirm()/prompt() — without these
    // three delegate methods every call silently no-ops and returns undefined
    // (the trap that ate destructive-action confirmations in v1.6). The
    // dashboard now uses its own appConfirm/appPrompt modals, but these
    // NSAlert bridges guarantee a native dialog can never silently vanish.

    func webView(_ webView: WKWebView,
                 runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping () -> Void) {
        let alert = NSAlert()
        alert.messageText = "CredMgr"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.runModal()
        completionHandler()
    }

    func webView(_ webView: WKWebView,
                 runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping (Bool) -> Void) {
        let alert = NSAlert()
        alert.messageText = "CredMgr"
        alert.informativeText = message
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        completionHandler(alert.runModal() == .alertFirstButtonReturn)
    }

    func webView(_ webView: WKWebView,
                 runJavaScriptTextInputPanelWithPrompt prompt: String,
                 defaultText: String?,
                 initiatedByFrame frame: WKFrameInfo,
                 completionHandler: @escaping (String?) -> Void) {
        let alert = NSAlert()
        alert.messageText = "CredMgr"
        alert.informativeText = prompt
        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 260, height: 24))
        input.stringValue = defaultText ?? ""
        alert.accessoryView = input
        alert.window.initialFirstResponder = input
        alert.addButton(withTitle: "OK")
        alert.addButton(withTitle: "Cancel")
        let response = alert.runModal()
        completionHandler(response == .alertFirstButtonReturn ? input.stringValue : nil)
    }

    // ── WKScriptMessageHandler ───────────────────────────────────────────────
    // Concealed clipboard writes: org.nspasteboard.ConcealedType is the
    // de-facto convention (1Password, Keychain) telling clipboard managers
    // "do not archive this". The web clipboard API has no equivalent.

    func userContentController(_ userContentController: WKUserContentController,
                               didReceive message: WKScriptMessage) {
        switch message.name {
        case "copySecret":
            guard let secret = message.body as? String else { return }
            let pb = NSPasteboard.general
            pb.clearContents()
            pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
            pb.setString(secret, forType: .string)
            pendingSecretChangeCount = pb.changeCount
        case "clearClipboard":
            // Only clear if nothing else has been copied since we wrote the
            // secret. Without this guard, a delayed clear (fired after the
            // user has since copied something unrelated in another app)
            // would silently destroy that unrelated clipboard content —
            // indistinguishable from "system-wide copy/paste stopped working."
            let pb = NSPasteboard.general
            if let expected = pendingSecretChangeCount, pb.changeCount == expected {
                pb.clearContents()
            }
            pendingSecretChangeCount = nil
        default:
            break
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Entry point
// ────────────────────────────────────────────────────────────────────────────

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
