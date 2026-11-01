/*
 * FIXTURE BROKER - install.  Defines the two globals, then builds the first vault from window.__BROKER_OPTIONS__ (set by the
 * spec, ahead of these files).  See core.js.
 *
 *   window.__TAURI_INTERNALS__   what @tauri-apps/api/core's invoke() calls; its presence is also how the app decides it is
 *                                running inside the Tauri shell (src/vault/index.ts hasTauriRuntime)
 *   window.__BROKER__            the control surface for specs: calls(), script(), reset(), state()
 */
(function (B) {
  "use strict";

  var callbacks = {};
  var nextCb = 1;

  window.__TAURI_INTERNALS__ = {
    invoke: function (cmd, args) {
      return B.invoke(cmd, args);
    },
    transformCallback: function (fn) {
      var id = nextCb++;
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

  B.callbacks = callbacks;
  // @tauri-apps/api/event's unlisten reaches for this before it calls the plugin; the fake keeps its own table (session.js).
  window.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: function () {} };

  B.options = window.__BROKER_OPTIONS__ || {};
  B.reset(B.options);

  window.__BROKER__ = {
    /** Calls so far, oldest first, optionally only those of one command.  Arguments are copies. */
    calls: function (cmd) {
      return B.clone(B.calls.filter(function (c) { return !cmd || c.cmd === cmd; }));
    },
    /** Answer the next calls of `cmd` with these, in order: { error: {code, message?, detail?, source?} } | { result } | { delayMs } | {} (run the real handler). */
    script: function (cmd, responses) {
      B.scripts[cmd] = (B.scripts[cmd] || []).concat(responses);
    },
    /** Start over: a fresh vault from these options (default: the ones the spec installed with); clears calls and scripts. */
    reset: function (options) {
      B.reset(options || B.options);
    },
    /** A copy of the broker's state, for assertions about what the fake vault holds. */
    state: function () {
      var S = B.clone(B.S);
      return S;
    },
    /** Deliver a shell event (e.g. "credmgr://locked", "sleep") to every listener the page registered for it. */
    emit: function (event, payload) {
      return B.emit(event, payload);
    },
    /** The events the page is listening to, and the listen/unlisten calls it made (kept out of calls()). */
    listening: function () {
      return Object.keys(B.listeners).map(function (k) { return B.listeners[k].event; });
    },
    eventCalls: function () {
      return B.clone(B.eventCalls);
    },
    /** Change the state the fake vault is in without a call (e.g. make the broker unreachable). */
    set: function (patch) {
      for (var k in patch) B.S[k] = patch[k];
    },
  };
})((window.__brokerFixture = window.__brokerFixture || {}));
