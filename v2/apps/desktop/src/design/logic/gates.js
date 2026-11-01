/* The second factor after the login (S5c) and a decision made while the vault is locked (S16a).
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Added with the 2026-10-25 design drop.

   S5c: a node with `requireTwoFactor` answers `two_factor_required` to a reveal (to every read, at level `always`) until the owner has proven the
   factor in the last five minutes (ADR-085).  The read path hands such a refusal to askSecondFactor(ctx) together with a closure that repeats
   what was refused; the dialog asks for the authenticator's 6-digit code, sends it as `vault.gate_verify` (the step-up: no new login, an
   elevation of five minutes), and then runs the closure ONCE.  Nothing is revealed before the broker accepts the code, and a wrong code leaves
   the dialog open with the broker's reason.

   S16a: an agent's reveal on a vault that is locked answers `approval_pending` and prints a request id (ADR-088).  The panel on the Lock screen
   takes that id, the passphrase and the authenticator's code and sends `vault.approval_decide`; the factors authorise the decision, the vault
   stays locked, and a recovery code is not accepted.  The passphrase and the code are used for one call and are wiped whatever the answer was.

   ADR-090: while the Lock screen is up the page asks `vault.status` every five seconds how many agent requests are waiting (a bare count) and,
   when there is one, `vault.approval_get` what they are; the panel then lists them by the names the broker gave (the ids when a node's name is
   private) instead of asking for a request id.  The id field returns only when nothing is listed (a request seen elsewhere, say on the command line).

   S5c, as the broker does it: the owner's own login is exempt from `requireTwoFactor` (it passed the gate to exist), so the dialog never opens
   from the owner's own reveal.  What the owner can do is give the factor on purpose: `vault.gate_verify` from this login opens a five-minute
   window, vault-wide and for every caller, in which AGENTS and other tools pass the gate.  The deliberate "Give second factor" action on the
   inspector's chip does that, and says so.

   Nothing typed here is put in a notice, a log or storage. */

import { classifyError, errorCode, session } from "../../vault/index";
import { LOCK_PHRASE } from "./session.js";

/** What the second-factor dialog and the approval panel say for the codes the broker answers with, chosen here by code (never taken from an error's text). */
const APPROVAL_TEXT = {
  not_found: "There is no waiting approval with that request id.",
  two_factor_required: "A second-factor code is needed: enter the 6 digits from your authenticator.",
  node_access_denied: "This request can no longer be decided.",
  capability_not_held: "This request can no longer be decided.",
};

/** How long the window the factor opens is, in words. */
const minutesText = (seconds) => { const m = Math.max(1, Math.round((seconds || 300) / 60)); return m === 1 ? 'one minute' : m + ' minutes'; };
/** How often the Lock screen asks how many agent requests are waiting. */
export const APPROVAL_POLL_MS = 5000;

/**
 * What a new list of waiting requests does to the panel's state.  A request the person picked stays the pick; only when nothing is picked is a
 * lone request picked for them.  When the picked one is gone (it expired, or was decided elsewhere) the pick is dropped AND what was typed for
 * it with it, so a passphrase typed for one request can never be sent for another that took its place.  An empty list keeps what is in the
 * request-id field.
 */
export function nextApprovalState(st, list){
  const still = !!st.aprReq && list.some((w) => w.request === st.aprReq);
  if(!st.aprReq || still) return { aprWaiting: list, aprReq: st.aprReq || (list.length === 1 ? list[0].request : '') };
  if(!list.length) return { aprWaiting: list };
  return { aprWaiting: list, aprReq: '', aprPass: '', aprCode: '', aprErr: 'The request you picked is no longer waiting. Pick one again.' };
}

export const gatesMethods = {
  // ───────────────────────────── S5c: the second factor after the login ─────────────────────────────

  /**
   * Open the dialog.  `ctx.retry` repeats what the broker refused (the reveal, the read); it runs once, after the code is accepted, and never if
   * the dialog is cancelled.  A closure lives on the instance, not in state: it is dropped on every lock (dropLocalSecrets).
   */
  askSecondFactor(ctx){
    this._tfRetry = ctx && typeof ctx.retry === 'function' ? ctx.retry : null;
    // `give`: the owner chose to give the factor (the chip's action), not a refused call asking for it.
    this.setState({ dialog: 'tf', tf: { node: (ctx && ctx.node) || '', code: '', err: '', busy: false, give: !!(ctx && ctx.give) }, ctx: null, fieldMenu: null });
  },
  closeSecondFactor(){
    this._tfRetry = null;
    this.setState({ dialog: null, tf: null });
  },
  /** A half-typed code must not outlive its dialog: any way of closing it (Cancel, Escape, the scrim, a lock) leaves no code and no refused call behind. */
  scheduleTfWipe(){
    if(this._tfWipeQueued || this.state.dialog === 'tf' || !this.state.tf) return;
    this._tfWipeQueued = true;
    queueMicrotask(() => { this._tfWipeQueued = false; if(this._mounted && this.state.dialog !== 'tf' && this.state.tf){ this._tfRetry = null; this.setState({ tf: null }); } });
  },
  /** Counts the window down for the chip: advisory (the broker decides), ended here by a lock or by this window changing a node's policy. */
  tfTick(){
    clearInterval(this._tfI);
    this._tfI = setInterval(() => {
      const u = this.state.tfUntil;
      if(!u || Date.now() >= u){ clearInterval(this._tfI); this.setState({ tfUntil: 0 }); } else this.setState({ tfNow: Date.now() });
    }, 1000);
  },
  async verifySecondFactor(){
    const t = this.state.tf;
    if(!t || t.busy || t.code.length !== 6) return;
    this.setState((st) => ({ tf: st.tf ? { ...st.tf, busy: true, err: '' } : null }));
    let given = null;
    try{
      given = await session.stepUp(this.model, t.code);
    }catch(e){
      const r = classifyError(e, { op: 'vault.gate_verify', field: 'code' });
      if(r.route === 'inline'){
        // Wrong code or a wait: the dialog stays, says why, and the digits are gone (a code is single-use).
        this.setState((st) => ({ tf: st.tf ? { ...st.tf, busy: false, code: '', err: r.message } : null }));
      }else{
        this._tfRetry = null;
        this.setState({ dialog: null, tf: null });
        this.routeError(e, { op: 'vault.gate_verify' });
      }
      return;
    }
    const retry = this._tfRetry;
    this._tfRetry = null;
    const secs = given && Number.isFinite(given.expiresIn) && given.expiresIn > 0 ? given.expiresIn : 0;
    this.setState({ dialog: null, tf: null, tfUntil: secs ? Date.now() + secs * 1000 : 0, tfNow: Date.now() });
    if(secs) this.tfTick();
    if(retry) retry();
    else if(t.give) this.notify('success', 'Second factor accepted. For ' + minutesText(given && given.expiresIn) + ', agents and other tools can reveal from every node that asks for one. Locking the vault ends it.');
  },

  // ───────────────────────────── S16a: a decision while locked ─────────────────────────────
  openApproval(){ this.setState({ aprOpen: true, aprResult: '', aprErr: '' }); },
  closeApproval(){ this.setState({ aprOpen: false, aprReq: '', aprPass: '', aprCode: '', aprErr: '', aprBusy: false }); },
  async decideApproval(approved){
    const s = this.state;
    const req = s.aprReq.trim();
    if(s.aprBusy || !req || !s.aprPass || (s.aprCode && s.aprCode.length !== 6)) return;
    this.setState({ aprBusy: true, aprErr: '', aprResult: '' });
    let done = false;
    try{
      await session.decideApproval(this.model, req, approved, s.aprPass, s.aprCode);
      done = true;
    }catch(e){
      const route = classifyError(e, { op: 'vault.approval_decide', field: 'passphrase' });
      const code = errorCode(e);
      const text = APPROVAL_TEXT[code] || (route.route === 'inline' || route.route === 'notice' ? route.message : '');
      if(route.route === 'broker-down'){ this.setState({ aprBusy: false, aprPass: '', aprCode: '' }); this.routeError(e, { op: 'vault.approval_decide' }); return; }
      // The passphrase and the code are single-use here: gone whatever the answer.  The request id stays so the user can try again.
      this.setState({ aprBusy: false, aprPass: '', aprCode: '', aprErr: text || 'The decision could not be recorded. Nothing was changed.' });
      return;
    }
    if(done){
      this.setState({ aprOpen: false, aprBusy: false, aprReq: '', aprPass: '', aprCode: '', aprErr: '', aprResult: (approved ? 'approved' : 'denied') + ' with the passphrase · the vault is still locked' });
      this.pollApprovals(); // the decided request leaves the list
    }
  },

  /** Start asking, every five seconds, which agent requests are waiting (the Lock screen only; it stops itself when the screen changes). */
  startApprovalPoll(){
    clearInterval(this._aprT);
    if(this.model.kind !== 'bridge') return;
    // The first look uses the count the boot's own status already gave (no extra call when none is waiting); the others ask.
    if(this.model.pendingApprovals > 0) this.pollApprovals(this.model.pendingApprovals);
    this._aprT = setInterval(() => this.pollApprovals(), APPROVAL_POLL_MS);
  },
  async pollApprovals(knownCount){
    if(this.state.screen !== 'lock'){ clearInterval(this._aprT); return; }
    // Not while an unlock or a decision is in flight: a look that overlaps one could read as "locked" just before it commits.
    if(this._aprPolling || this.state.lockBusy || this.state.aprBusy) return;
    this._aprPolling = true;
    let list = [];
    try{
      list = await session.waitingApprovals(this.model, undefined, knownCount);
    }catch(e){
      // A broker that is not running or a login that ended is the unlock attempt's to report; the list is simply empty.
      list = [];
    }finally{
      this._aprPolling = false;
    }
    if(!this._mounted || this.state.screen !== 'lock') return;
    this.setState((st) => nextApprovalState(st, list));
  },

  // ───────────────────────────── what the template reads ─────────────────────────────
  rvGates(c){
    const { s } = c;
    this.scheduleTfWipe();
    const t = s.tf;
    const onLock = s.screen === 'lock';
    return {
      dlgTf: s.dialog === 'tf' && !!t,
      tfNode: t ? t.node : '',
      tfCode: t ? t.code : '',
      onTfCode: (ev) => this.setState((st) => (st.tf ? { tf: { ...st.tf, code: ev.target.value.replace(/\D/g, '').slice(0, 6), err: '' } } : null)),
      tfDisabled: !t || t.busy || t.code.length !== 6,
      tfVerify: () => this.verifySecondFactor(),
      tfErrShow: !!(t && t.err),
      tfErr: t ? t.err : '',
      // Given on purpose by the owner (the chip), or asked for by a refused call: the first says what the factor does and for whom.
      tfTitle: t && t.give ? 'Give second factor' : 'Second factor needed',
      tfSub: t && t.give ? 'opens a 5-minute window for agents and other callers' : 'the node “' + (t ? t.node : '') + '” requires a second factor to reveal',
      tfIntro: t && t.give
        ? 'Enter the 6-digit code from your authenticator. For the next 5 minutes any agent, MCP or CLI caller passes the second factor on every node of this vault (vault.gate_verify). You are not asked when you reveal a value yourself.'
        : 'The broker answered two_factor_required. Enter the 6-digit code from your authenticator. Nothing is revealed before then.',
      tfNote: t && t.give
        ? 'It holds for the whole vault and for every caller, 300 s. It ends early when the vault locks or any node policy changes. Level reveal covers reveals; level always also covers lists, gets and notes.'
        : 'Level reveal covers reveals. Level always also covers lists, gets and notes. Once given, it holds for five minutes.',
      tfVerifyLabel: t && t.give ? 'Give second factor' : 'Verify and reveal',

      aprLinkShow: onLock && !s.aprOpen && s.lockStep === LOCK_PHRASE,
      aprLinkText: (s.aprWaiting || []).length ? (s.aprWaiting.length === 1 ? '1 agent request is waiting for approval' : s.aprWaiting.length + ' agent requests are waiting for approval') : 'an agent is waiting for approval?',
      aprIntro: (s.aprWaiting || []).length
        ? 'An agent asked to reveal a value and is waiting for you. Pick the request, then enter your passphrase and your second-factor code. The vault stays locked.'
        : 'An agent asked to reveal a value and is waiting for you. Enter the request id it was given, your passphrase and your second-factor code. The vault stays locked.',
      aprListShow: (s.aprWaiting || []).length > 0,
      aprCount: (s.aprWaiting || []).length,
      aprIdCaption: (s.aprWaiting || []).length ? 'Not listed? Enter the request id the agent printed.' : 'Enter the request id the agent printed.',
      aprSelShow: !!(s.aprReq || '').trim(),
      aprSelLabel: (() => { const id = (s.aprReq || '').trim(); if(!id) return ''; const w = (s.aprWaiting || []).find((x) => x.request === id); return 'Deciding ' + id + ' · ' + (w ? w.title : 'not in the list'); })(),
      aprWaiting: (s.aprWaiting || []).map((w) => ({
        key: w.request,
        picked: s.aprReq === w.request,
        pick: () => this.setState({ aprReq: w.request, aprErr: '' }),
        title: w.title,
        sub: 'asked to reveal · ' + Math.max(0, Math.round((w.expiresAt - Date.now()) / 1000)) + ' s left',
      })),
      aprOpenPanel: () => this.openApproval(),
      aprShow: onLock && !!s.aprOpen,
      aprReq: s.aprReq,
      onAprReq: (ev) => this.setState({ aprReq: ev.target.value, aprErr: '' }),
      aprPass: s.aprPass,
      onAprPass: (ev) => this.setState({ aprPass: ev.target.value, aprErr: '' }),
      aprCode: s.aprCode,
      onAprCode: (ev) => this.setState({ aprCode: ev.target.value.replace(/\D/g, '').slice(0, 6), aprErr: '' }),
      aprDisabled: s.aprBusy || !s.aprReq.trim() || !s.aprPass || (s.aprCode.length > 0 && s.aprCode.length !== 6),
      aprApprove: () => this.decideApproval(true),
      aprDeny: () => this.decideApproval(false),
      aprClose: () => this.closeApproval(),
      aprErrShow: !!s.aprErr,
      aprErr: s.aprErr,
      aprResultShow: onLock && !!s.aprResult,
      aprResult: s.aprResult,
    };
  },
};
