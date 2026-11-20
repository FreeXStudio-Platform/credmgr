/* "Confirm before showing secrets" (ADR-150): the confirm dialog and the Settings rows that set the policy.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   How a confirmation happens.  The broker refuses a reveal, a copy, a TOTP code (or a loosening of this very setting) with
   `confirmation_required` while the owner's session has no live confirmation.  src/lib/bridge.ts catches that ONE code for every
   command, calls the handler installed here, and when the handler resolves `true` sends the same command again, once.  So no
   screen that reveals anything (inspector, fields, model) knows this feature exists: the dialog appears in front of whatever asked.

   The dialog offers Touch ID (when this Mac has a presence key enrolled for this vault) and the vault passphrase; either works.
   Touch ID is `session.confirm` with no passphrase: the broker answers `presence_required` and the Rust shell shows the prompt and
   attaches the proof (src-tauri/src/commands.rs dispatch_at).  The passphrase is read from the uncontrolled input when Confirm is
   pressed, handed to the broker, and wiped; it never enters React state, a notice or a log.

   What the dialog holds lives under ONE state key, `confirm` ({ask, busy, error, touch}), and the promise's resolver lives on the
   instance (`_confirmResolve`).  Closing the dialog in any way (Cancel, the scrim, Escape, a lock) resolves `false`. */

import { admin, classifyError, errorCode } from "../../vault/index";

const MIN = 60;
/** The trust windows the Settings select offers, in minutes; the broker accepts exactly these (as seconds). */
export const CONFIRM_WINDOW_MINUTES = [1, 5, 15, 60];
const DEFAULT_POLICY = { mode: 'off', windowSeconds: 300, scope: 'all' };

export const confirmMethods = {
  /** Install the dialog as the bridge's confirmation handler, and the hook that resolves it when the dialog goes away.  Once. */
  initConfirm(){
    if(this._confirmInit)return; this._confirmInit=true;
    this._unsubConfirm=admin.onConfirmationNeeded((ask)=>this.askConfirmation(ask));
    // A lock ends every confirmation broker-side: a dialog still open for one has nothing left to confirm.
    this._unsubConfirmModel=this.model.subscribe(()=>{ if(this.model.status!=='unlocked'&&this._confirmResolve)this.endConfirm(false); });
    const base=this.componentDidUpdate;
    this.componentDidUpdate=(prevProps,prevState)=>{ base.call(this,prevProps,prevState); if(this._confirmResolve&&this.state.dialog!=='confirm')this.endConfirm(false); };
  },
  stopConfirm(){ if(this._unsubConfirm)this._unsubConfirm(); if(this._unsubConfirmModel)this._unsubConfirmModel(); },

  /** The bridge's handler: open the dialog, resolve `true` once the broker accepted a confirmation, `false` when it was closed. */
  askConfirmation(ask){
    if(this.model.status!=='unlocked'||this.state.screen!=='app')return Promise.resolve(false);
    // A node's note is read by the inspector on its own, the moment the node is selected (ADR-156 §5 gates notes.read as a high value).  No
    // one asked to see it, so no dialog opens over the node: the note stays unread and the inspector says it is held (inspector.js,
    // readNoteQuietly).  Confirming for anything else (a reveal, a copy) opens the window; selecting the node again then reads the note.
    if(ask&&ask.command==='notes_read')return Promise.resolve(false);
    if(this._confirmPromise)return this._confirmPromise;
    this.wipeConfirmPass();
    this._confirmPromise=new Promise((resolve)=>{ this._confirmResolve=resolve; });
    // Opened over a dialog (rare: a reveal from inside one), that dialog comes back when this one closes.
    this._confirmPrevDialog=this.state.dialog&&this.state.dialog!=='confirm'?this.state.dialog:null;
    this.setState({dialog:'confirm',confirm:{ask:ask||{},busy:false,error:'',touch:null}});
    this.focusLater('[data-screen-label="Confirm it is you"] input[data-confirm-pass]');
    const seq=(this._confirmSeq=(this._confirmSeq||0)+1);
    // Touch ID is offered only when this Mac holds a presence key enrolled for this vault; until that is known, the passphrase.
    admin.touchIdState().then((t)=>{
      if(seq!==this._confirmSeq||!this.state.confirm)return;
      const on=!!(t&&t.probe&&t.probe.secureEnclave&&t.probe.keyOnThisMac&&t.status&&t.status.enrolled&&t.status.enrolled.length);
      const kind=t&&t.probe&&t.probe.biometry==='faceid'?'Face ID':'Touch ID';
      this.setState((st)=>st.confirm?{confirm:{...st.confirm,touch:on?kind:null}}:{});
      if(on)this.focusLater('[data-confirm-touch]');
    }).catch(()=>{});
    return this._confirmPromise;
  },
  /** Close the dialog and settle the promise.  Idempotent. */
  endConfirm(ok){
    const resolve=this._confirmResolve;
    this._confirmResolve=null; this._confirmPromise=null; this._confirmSeq=(this._confirmSeq||0)+1;
    this.wipeConfirmPass();
    const back=this._confirmPrevDialog; this._confirmPrevDialog=null;
    if(this.state.confirm||this.state.dialog==='confirm')this.setState((st)=>({confirm:null,dialog:st.dialog==='confirm'?back:st.dialog}));
    if(resolve)resolve(!!ok);
  },
  setConfirm(patch){ this.setState((st)=>st.confirm?{confirm:{...st.confirm,...patch}}:{}); },
  wipeConfirmPass(){ this._confirmPass=''; try{ document.querySelectorAll('input[data-confirm-pass]').forEach((el)=>{ el.value=''; }); }catch(e){} },

  /** Send one confirmation.  `passphrase` undefined = Touch ID. */
  async sendConfirm(passphrase){
    const c=this.state.confirm;
    if(!c||c.busy)return;
    this.setConfirm({busy:true,error:''});
    try{
      await admin.confirmIdentity(passphrase);
      this.endConfirm(true);
    }catch(e){
      if(!this.state.confirm)return; // closed meanwhile: the promise already settled
      const code=errorCode(e);
      let error;
      if(code==='presence_required'||code==='presence_not_enrolled'||(code==='presence_failed'&&e&&e.detail&&e.detail.reason==='not_enrolled')) error='Touch ID is not set up for this vault on this Mac. Use your passphrase.';
      else if(code==='presence_cancelled') error='Touch ID was cancelled. Try again, or use your passphrase.';
      else if(code==='wrong_passphrase') error='Wrong passphrase.';
      else { const r=classifyError(e,{op:'session.confirm',field:'confirm'}); error=r.message||'Could not confirm. Try again.'; }
      this.setConfirm({busy:false,error,...(code==='presence_required'||code==='presence_not_enrolled'?{touch:null}:{})});
      this.focusLater('[data-screen-label="Confirm it is you"] input[data-confirm-pass]');
    }
  },
  confirmWithPassphrase(){
    const pass=this._confirmPass||'';
    if(!pass){ this.setConfirm({error:'Enter the passphrase.'}); return; }
    this.wipeConfirmPass();
    return this.sendConfirm(pass);
  },

  // ─────────────── the policy, in Settings › Security ───────────────
  /** Read the policy once per opening of the Security tab. */
  loadRevealConfirm(){
    if(this._rcAsked)return; this._rcAsked=true;
    admin.revealConfirmPolicy().then((p)=>this.setState({rc:p?{...DEFAULT_POLICY,...p}:null}))
      .catch(()=>{ this._rcAsked=false; this.setState({rc:null}); });
  },
  /** Change it.  A loosening asks for a confirmation first (the bridge does that); a cancelled one leaves the setting as it was. */
  async changeRevealConfirm(patch){
    const cur={...DEFAULT_POLICY,...(this.state.rc||{})};
    const next={...cur,...patch};
    if(next.mode===cur.mode&&next.windowSeconds===cur.windowSeconds&&next.scope===cur.scope)return;
    const r=await this.runAdmin('node.policy',()=>admin.setRevealConfirm(next));
    if(!r.ok)return;
    this.setState({rc:r.value});
    this.notify('success',r.value.mode==='off'?'Secrets show without asking again.':'Saved. Secrets ask for Touch ID or your passphrase before they show.');
  },

  rvConfirm(c){
    const {s, isPro} = c;
    const cf=s.dialog==='confirm'?s.confirm:null;
    const ask=(cf&&cf.ask)||{};
    const every=ask.mode==='everyTime';
    const forPolicy=ask.operation==='node.policy'||ask.operation==='settings.request_decide'; // ADR-155: approving an agent's loosening is a loosening
    const winMin=Math.max(1,Math.round((ask.windowSeconds||0)/MIN));
    const rc={...DEFAULT_POLICY,...(s.rc||{})}, rcOn=rc.mode!=='off', rcLoaded=!!s.rc;
    const busy=!!(this.adm&&this.adm().busy);
    return {
      // the dialog (src/design/screens/dlg-confirm.html)
      dlgConfirm:!!cf,
      confirmBody:forPolicy?'Loosening this setting needs a quick check first.':'Showing a saved secret needs a quick check first.',
      confirmNote:forPolicy?'Nothing changes until you confirm.':every?'You will be asked again for the next secret.':(ask.windowSeconds?`After this, secrets show without asking for ${winMin} min, until the vault locks.`:'Nothing is shown until you confirm.'),
      confirmTouchShow:!!(cf&&cf.touch),
      confirmTouchLabel:cf&&cf.touch?'Use '+cf.touch:'Use Touch ID',
      confirmWithTouch:()=>this.sendConfirm(undefined),
      confirmBusy:!!(cf&&cf.busy),
      confirmError:cf?cf.error:'',
      onConfirmPass:(ev)=>{ this._confirmPass=ev.target.value; },
      confirmPassKey:(ev)=>{ if(ev.key==='Enter'){ ev.preventDefault(); this.confirmWithPassphrase(); } },
      confirmWithPass:()=>this.confirmWithPassphrase(),
      confirmPassLabel:cf&&cf.busy?'Checking…':'Confirm',
      confirmPassVariant:cf&&cf.touch?'':'primary',
      confirmCancel:()=>{ if(!(cf&&cf.busy))this.endConfirm(false); },
      // Settings › Security
      rcShow:rcLoaded,
      rcOn,
      rcToggleLabel:rcOn?'on':'off',
      rcCaption:rcOn
        ? (rc.mode==='everyTime'?'this app and your logged-in CLI ask for Touch ID or your passphrase before every secret is shown or copied':'this app and your logged-in CLI ask for Touch ID or your passphrase before a secret is shown or copied, then not again for the time below')+(rc.scope==='high'?' · only high and critical secrets':'')+' · agents are not asked: each project\'s security level governs them'
        : 'off · secrets show as soon as the vault is unlocked · turn on to ask for Touch ID or your passphrase first',
      toggleRevealConfirm:()=>this.changeRevealConfirm({mode:rcOn?'off':'window'}),
      rcBusy:busy,
      rcWindowShow:rcOn&&rc.mode==='window',
      rcWindowVal:String(rc.windowSeconds),
      rcWindowOpts:CONFIRM_WINDOW_MINUTES.map((m)=>({value:String(m*MIN),label:m+' min'})),
      onRcWindow:(ev)=>this.changeRevealConfirm({windowSeconds:+ev.target.value}),
      rcEveryNote:rcOn&&rc.mode==='everyTime'&&!isPro,
      rcProShow:isPro&&rcOn,
      rcModeVal:rc.mode==='everyTime'?'everyTime':'window',
      onRcMode:(ev)=>this.changeRevealConfirm({mode:ev.target.value==='everyTime'?'everyTime':'window'}),
      rcScopeVal:rc.scope==='high'?'high':'all',
      onRcScope:(ev)=>this.changeRevealConfirm({scope:ev.target.value==='high'?'high':'all'}),
    };
  },
};
