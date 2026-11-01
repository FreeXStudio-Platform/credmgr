/* The global notice, and the error router the logic class hands every bridge rejection to.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Foundations (fe-ifc); work
   packages call these, they do not edit them.

   this.notify(kind, text)       kind: "info" | "success" | "warn" | "error" | "presence"; one notice at a time, auto-dismissed
   this.routeError(e, ctx)       EVERY rejection from the model or the bridge goes here (src/vault/errors.ts is the table)

   The notice text is chosen by code in errors.ts, never taken from an error's message, and never contains a value. */

import { routeError } from "../../vault/index";

const CHIP = { info: "", success: "ok", warn: "warn", error: "danger", presence: "warn" };
const LABEL = { info: "info", success: "done", warn: "note", error: "error", presence: "presence" };
const KINDS = Object.keys(CHIP);

export const noticeMethods = {
  notify(kind, text){
    const k = KINDS.includes(kind) ? kind : "info";
    const id = (this._noticeId = (this._noticeId || 0) + 1);
    clearTimeout(this._noticeT);
    this.setState({ notice: { id, kind: k, text: String(text) } });
    this._noticeT = setTimeout(() => { if (this.state.notice && this.state.notice.id === id) this.setState({ notice: null }); }, k === "error" || k === "presence" ? 10000 : 5000);
  },
  /** What the router calls back into; one method per route (src/vault/errors.ts RouteHost). */
  routeHost(){
    return {
      notify: (k, t) => this.notify(k, t),
      // The login is gone: forget everything and show the Lock screen, saying why.
      lock: (code) => this.endSession(code),
      // Package B renders the per-node locked panel; until then the user is told, not left with a blank inspector.
      nodeLocked: () => this.notify("warn", "That node is locked. Unlock it to read it."),
      // At the login the second factor is the next step.  Anywhere else the broker wants a FRESH second factor, and the only door
      // to one is a login: vault.gate_verify answers only the challenge a passphrase unlock opens (07 section 5), so a code typed
      // into a prompt here would be refused.  Say what works instead of showing a prompt that cannot.
      promptTwoFactor: (ctx) => {
        if (ctx && ctx.op === "vault.unlock") this.setState({ screen: "lock", lockStep: 2, twofa: "", fieldErrors: {} });
        else this.notify("warn", "This needs a fresh second factor. Lock the vault and unlock it again with your code, then repeat this within 5 minutes.");
      },
      // A restarted broker has forgotten every login, so nothing the session held may stay on screen or in memory.
      brokerDown: () => { this.model.clear("broker-down"); this.showBrokerDown(); },
      inline: (field, message, ctx, retry) => {
        this.setState((st) => ({ fieldErrors: { ...(st.fieldErrors || {}), [field || "_"]: message } }));
        if (retry && this.state.screen === "lock") this.holdUnlock(retry.afterSeconds);
      },
      // A refusal about one entry's fields (a stale generation, a field that is gone) also re-reads that entry's fields: the list of the
      // node alone carries no labels, so it could not put the open entry right.
      refresh: (nodes, ctx) => {
        const spec = { graph: true, nodes };
        if (ctx && ctx.node && ctx.entry && typeof ctx.op === "string" && ctx.op.startsWith("field.")) spec.details = [{ node: ctx.node, entry: ctx.entry }];
        this.model.refresh(spec).catch((e) => this.routeError(e, { op: "refresh" }));
      },
      alreadyInitialized: () => this.showLock(""),
    };
  },
  /** @returns the route taken (see src/vault/errors.ts ErrorRoute) so a caller can branch on it, e.g. retry after two-factor */
  routeError(e, ctx){
    return routeError(e, ctx || {}, this.routeHost());
  },
  rvNotice(){
    const n = this.state.notice;
    return {
      noticeShow: !!n,
      noticeKind: n ? n.kind : "",
      noticeLabel: n ? LABEL[n.kind] : "",
      noticeChipState: n ? CHIP[n.kind] : "",
      noticeText: n ? n.text : "",
      noticeRole: n && (n.kind === "error" || n.kind === "presence") ? "alert" : "status",
      dismissNotice: () => { clearTimeout(this._noticeT); this.setState({ notice: null }); },
    };
  },
};
