/**
 * The page half of the shim: what replaces the Tauri runtime inside the webview.
 *
 * The app finds the shell by `"__TAURI_INTERNALS__" in window` and then calls `window.__TAURI_INTERNALS__.invoke(cmd, args)` (that is
 * all `@tauri-apps/api/core`'s `invoke` does). This defines exactly that, plus the three plugin commands the app uses
 * (`plugin:app|version`, `plugin:path|resolve_directory`, and `plugin:event|listen`/`unlisten` behind `listen()`), and routes every
 * other command to `window.__realInvoke`, the Playwright-exposed function that runs {@link Shim.invoke} in Node.
 *
 * It is installed with `addInitScript`, which runs outside the page's Content-Security-Policy, so installing it weakens nothing
 * about the policy under test. No network is involved: `__realInvoke` is a Playwright binding, not a request.
 *
 * `__realInvoke` never throws (a Playwright binding can only reject with a message); it answers `{ok: true, value}` or
 * `{ok: false, error}` and this script rejects with the error object exactly as Tauri's IPC does: a BridgeError-shaped object
 * for the bridge's own errors, a bare string for the framework's ("missing required key ...").
 */

/**
 * @param {{ version: string, homeDir: string }} options
 * @returns {string} the script text
 */
export function pageShimSource({ version, homeDir }) {
  return `(${function install(opts) {
    "use strict";
    var callbacks = {};
    var nextCallback = 1;
    var listeners = {};
    var nextListener = 1;
    var eventCalls = [];

    function plugin(cmd, args) {
      eventCalls.push({ cmd: cmd, args: JSON.parse(JSON.stringify(args || {})) });
      switch (cmd) {
        case "plugin:app|version":
          return Promise.resolve(opts.version);
        case "plugin:path|resolve_directory":
          return Promise.resolve(opts.homeDir);
        case "plugin:event|listen": {
          var id = nextListener++;
          listeners[id] = { event: args.event, handler: args.handler };
          return Promise.resolve(id);
        }
        case "plugin:event|unlisten":
          delete listeners[args.eventId];
          return Promise.resolve(null);
        default:
          return Promise.reject("Command " + cmd + " not found");
      }
    }

    function invoke(cmd, args) {
      if (cmd.indexOf("plugin:") === 0) return plugin(cmd, args);
      var plain = JSON.parse(JSON.stringify(args || {})); // the IPC layer serialises to JSON: undefined keys vanish
      return window.__realInvoke(cmd, plain).then(function (r) {
        if (r.ok) return r.value;
        return Promise.reject(r.error);
      });
    }

    window.__TAURI_INTERNALS__ = {
      invoke: invoke,
      transformCallback: function (fn) {
        var id = nextCallback++;
        callbacks[id] = fn;
        return id;
      },
      unregisterCallback: function (id) {
        delete callbacks[id];
      },
      convertFileSrc: function (p) {
        return p;
      },
      metadata: { currentWindow: { label: "main" }, currentWebview: { windowLabel: "main", label: "main" } },
    };
    window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: function () {} };

    // The control surface for specs (what the real shell does with app.emit).
    window.__REAL__ = {
      emit: function (event, payload) {
        var n = 0;
        Object.keys(listeners).forEach(function (id) {
          var l = listeners[id];
          if (l.event === event && callbacks[l.handler]) {
            callbacks[l.handler]({ event: event, id: Number(id), payload: payload });
            n++;
          }
        });
        return n;
      },
      listening: function () {
        return Object.keys(listeners).map(function (k) {
          return listeners[k].event;
        });
      },
      pluginCalls: function () {
        return JSON.parse(JSON.stringify(eventCalls));
      },
    };
  }})(${JSON.stringify({ version, homeDir })});`;
}
