/* Settings, grants, operations, audit, about and help.  (The cosmetic choices and the supporter extras moved to extras.js with the 2026-10-18 design drop.)
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Settings/admin lane (WP-D).
   Split from the upstream monolith (design-upstream/PROVENANCE.md, ADR-075).

   Everything here reaches the broker through `admin.*` (src/vault/actions/admin.ts), `session.*` (the second-factor enrolment of
   Settings → Security) and the model, and every rejection goes through routeError.  What this file keeps of its own:
     - preferences: applied from `credmgr_prefs` when the app mounts, written back by afterUpdate() when a setting changes
     - the working state of the administration screens, under ONE state key, `admin` (results, the audit rows, the open
       prompt).  It is dropped whenever the vault locks.  A passphrase is NOT in it: the prompt's inputs are uncontrolled and
       their text is read at the moment of the call (this._adminPass), so a passphrase never sits in React state. */

import { admin, AUTO_LOCK_CHOICES, classifyError, errorCode, PREF_KEYS, RETAIN_CHOICES, REVEAL_CHOICES, savePrefs, session as sessionActions, storedPrefs } from "../../vault/index";

/** The five donation addresses.  They are copied from v2/DONATE.md; tests/unit/wp-d.test.ts holds the two in step. */
export const DONATE_CHAINS = [
  {chain:'Ethereum & EVM chains',short:'EVM',address:'0x63AD9e7a8f0451bc2b8D03B3B473935F9482A3C9'},
  {chain:'Bitcoin — native segwit',short:'BTC',address:'bc1qxwkq4jgu4wen62wpqkmx3yx6x9zcv8gvl3vydt'},
  {chain:'Solana',short:'SOL',address:'i6SffLGEcaRgtSTbrktGJUjxxcWqe7hRFfRd88dCDEb'},
  {chain:'Tron — TRC-20',short:'TRX',address:'TVeDpvsf6he6vsMQosbeGT4mRZ2hHomz59'},
  {chain:'TON',short:'TON',address:'UQD7BTjZDmc3snzUlvRom6xQgGfhua_Jkhelydc8zwix4R3D'}
];

/**
 * True only in a development or test build (`vite dev`, vitest, `--mode test`): the only builds that carry the in-memory example vault, whose model
 * says `kind === 'demo'`.  A compile-time constant: in a release build it folds to `false` and every branch below that reads it, with the words
 * it shows, is dropped from the bundle (scripts/dc/verify-build.mjs fails the build if any of it is left).  Same expression as src/vault/index.ts.
 */
const DEMO_BUILD = import.meta.env.DEV || import.meta.env.MODE === 'test';

const ADMIN0 = { busy:null, last:null, verify:null, doctor:null, backup:null, audit:null, auditState:'idle', report:null, prompt:null, recovery:null };

/**
 * The second-factor dialog (Settings → Security) while it is open.  `step`: loading → qr → codes, or error.  The authenticator
 * secret, the QR path and the recovery codes exist only here, only while the dialog is open (afterUpdate drops all of it the moment
 * it closes, and a lock drops it with every other dialog), and are never stored, logged or put in a notice.
 */
const GATE0 = { step:'loading', replacing:false, reason:null, qr:null, secret:'', totp:'', codes:[], codesSaved:false, busy:false };

/** What each passphrase prompt is for: the broker operation it ends in, and the words around the input. */
const PROMPTS = {
  backup:{ op:'maintenance.backup', title:'back up the vault', action:'Back up', label:'backup passphrase', repeat:true,
    body:'The backup is encrypted with this passphrase. It is not stored anywhere: keep it, because the backup cannot be opened without it.' },
  rotate:{ op:'maintenance.rotate_root', title:'rotate the root key', action:'Rotate', label:'vault passphrase', repeat:false,
    body:'Enter the vault passphrase again. It protects the new root key. This replaces the root key and the recovery code, and needs presence (Touch ID), which this beta cannot attest yet: the broker will refuse it today and nothing will change.' },
  rebuild:{ op:'maintenance.doctor', title:'rebuild the registry', action:'Rebuild', label:'passphrase of the latest backup', repeat:false,
    body:'Rebuilds the registry from the most recent backup. Enter the passphrase that backup was made with. It needs presence (Touch ID), which this beta cannot attest yet: the broker will refuse it today and nothing will change.' }
};

const pad = (n) => String(n).padStart(2, '0');
/** `MM-DD HH:MM:SS`, local time. */
const fmtTime = (ts) => { const d = new Date(ts * 1000); return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
const ORIGINS = { HumanUi: 'app', Cli: 'cli', Agent: 'agent', Native: 'native' };
const who = (actor) => { const o = String(actor || '').split(':')[0]; return ORIGINS[o] || o || '—'; };
const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;
/** `YYYY-MM-DD HH:MM`, local time. */
const fmtDateTime = (ts) => { const d = new Date(ts * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`; };
/**
 * What a "recently sealed" row says about its restore window.  The broker's real end of it when its answer carried one; otherwise
 * the RULE (7 days after sealing) and nothing that looks like a clock: a fixed "ends in 7d" read the same on day 1 and on day 6.
 * The deadline, when there is one, is an absolute time, so it cannot go stale on screen.
 */
const sealWindow = (r) => (typeof r.expiresAt === 'number' && isFinite(r.expiresAt) && r.expiresAt > 0 ? `restorable until ${fmtDateTime(r.expiresAt)}` : 'restorable for 7 days after sealing');

export const settingsMethods = {
  // ─────────────── preferences ───────────────
  /** Apply the stored preferences, and install the two things that follow state afterwards (see afterUpdate).  Once. */
  initSettings(){
    if(this._settingsInit)return; this._settingsInit=true;
    const S=storedPrefs(), patch={};
    for(const k of PREF_KEYS) if(k in S) patch[k]=S[k];
    // Contrast follows the operating system until the user picks one (a stored `null` means "never picked").
    if(patch.contrastMode==null){ delete patch.contrastMode; try{ if(window.matchMedia&&window.matchMedia('(prefers-contrast: more)').matches)patch.contrastMode='high'; }catch(e){} }
    if(Object.keys(patch).length)this.setState(patch);
    // Screen-capture protection is ON in the window's own config, so the shell is told only when the user's stored choice is explicitly OFF; a missing or unreadable choice calls nothing and stays protected.
    if(S.captureProtection===false)this.applyCaptureProtection(false);
    // Whatever the vault layer's state is, the screens of this file hold nothing once it is locked.
    // (A dialog of this file that is open at that moment goes with it: a `dialog` left set with nothing to show blocks the bare shortcuts.)
    this._unsubAdmin=this.model.subscribe(()=>{ if(this.model.kind==='bridge'&&this.model.status!=='unlocked'&&(this.state.admin||this._adminPass||this._adminRepeat)){ this.wipeAdminPass(); this.setState((st)=>({admin:null,dialog:(st.dialog==='adminPass'||st.dialog==='recovery')?null:st.dialog})); } });
    const base=this.componentDidUpdate;
    this.componentDidUpdate=(prevProps,prevState)=>{ base.call(this,prevProps,prevState); this.afterUpdate(prevState); };
  },
  /** After every committed update: remember a preference that changed, and let go of anything an admin dialog held once it is closed (Escape closes it without asking us). */
  afterUpdate(prev){
    if(!prev)return;
    const s=this.state, patch={};
    for(const k of PREF_KEYS) if(!Object.is(prev[k],s[k])) patch[k]=k==='greyscale'?!!s[k]:s[k];
    if(Object.keys(patch).length)savePrefs(patch);
    if(s.dialog==='about'&&prev.dialog!=='about')this.loadVersion(); // asked when About opens, not at start: the app makes no call it does not need
    if(s.dialog!=='adminPass'&&(this._adminPass||this._adminRepeat))this.wipeAdminPass();
    const gf=s.gateFlow;
    if(gf){
      // While a code is being confirmed the answer carries the recovery codes, and a window closed first would lose them: the dialog comes back.
      // Once the codes are on screen, acknowledging them is optional (Done and Esc both work; they cannot be shown again).  Closed any other way, the flow lets go of
      // its secret, its QR and its codes at once.  (Only on the unlocked app screen: a lock drops the flow, it never re-opens anything.)
      const owed=gf.step==='qr'&&gf.busy;
      if(s.dialog!=='gateEnrol'){
        if(owed&&s.screen==='app'&&this.model.status==='unlocked'){ this.setState({dialog:'gateEnrol'}); this.focusLater('[data-screen-label="Second factor"] input'); }
        else if(!owed){ this._gateSeq=(this._gateSeq||0)+1; this.setState({gateFlow:null}); }
      }
    }
    const a=s.admin;
    if(a){
      if(s.dialog!=='adminPass'&&a.prompt)this.admSet({prompt:null});
      // The new recovery code is shown ONCE and the old one is already dead, so a stray Escape (core.js closes every dialog on it)
      // must not be the end of the only copy: until it is acknowledged the dialog comes back.  Once the box is ticked, however it
      // closes, the code goes with it.  (Only on the unlocked app screen: a lock drops the code, it never re-opens anything.)
      if(a.recovery&&s.dialog!=='recovery'){
        if(a.recovery.saved)this.admSet({recovery:null});
        else if(s.screen==='app'&&this.model.status==='unlocked'){ this.setState({dialog:'recovery'}); this.focusLater('[data-screen-label="New recovery code"] input'); }
      }
    }
  },
  /**
   * Tell the shell the user's screen-capture choice.  Resolves nothing the caller needs; a failure is said in a notice.  Turning protection OFF failing is
   * harmless (the window stays hidden from capture); turning it ON failing is not, so that one is an error and the words say what is true.
   */
  async applyCaptureProtection(enabled){
    try{
      const r=await admin.setCaptureProtection(enabled);
      if(r&&!r.applied)throw new Error('not applied');
    }catch(e){
      this.notify(enabled?'error':'warn',enabled?'Could not hide the window from screen capture. It may still appear in screenshots and screen shares.':'Could not change screen-capture protection. The window stays hidden from capture.');
    }
  },
  loadVersion(){
    if(this._versionAsked)return; this._versionAsked=true;
    const failed=()=>{ this._versionAsked=false; this.setState({versionFailed:true}); }; // asked again the next time About opens
    admin.appVersion().then((v)=>{ if(v)this.setState({appVersion:v,versionFailed:false}); else failed(); }).catch(failed);
  },

  // ─────────────── the administration working state ───────────────
  adm(){ return {...ADMIN0,...(this.state.admin||{})}; },
  /** Merge into the admin working state; `extra` carries other state keys that must change in the SAME commit (a dialog opening with its data). */
  admSet(patch,extra){ this.setState((st)=>({...(extra||{}),admin:{...ADMIN0,...(st.admin||{}),...patch}})); },
  /**
   * Run one broker operation for a screen of this file: one at a time, a plain notice in the browser preview (which has no
   * broker), and every rejection through routeError.  Resolves {ok:true,value} or {ok:false,route} - never rejects.
   * `ctx.reload` re-reads what the calling screen shows; it runs, and is waited for, BEFORE the router reloads the graph on a
   * "changed underneath you" answer: two reads in flight publish over each other and the later one wins with older data.
   */
  async runAdmin(op,fn,ctx){
    const {reload,...rest}=ctx||{};
    if(DEMO_BUILD&&this.model.kind==='demo'){ this.notify('info','This browser preview has no broker. Open the CredMgr app to use this.'); return {ok:false,route:null}; }
    if(this.adm().busy)return {ok:false,route:null};
    this.admSet({busy:op});
    try{ return {ok:true,value:await fn()}; }
    catch(e){
      if(reload&&classifyError(e,rest).route==='refresh'){ try{ await reload(); }catch(x){ this.routeError(x,{op}); } }
      return {ok:false,route:this.routeError(e,{op,...rest})};
    }
    finally{ if(this.state.admin)this.admSet({busy:null}); } // a lock during the call already dropped the working state: do not bring it back
  },
  /** Forget what the passphrase prompt's inputs hold (the text lives in the inputs, not in state). */
  wipeAdminPass(){ this._adminPass=''; this._adminRepeat=''; try{ document.querySelectorAll('input[data-admin-pass]').forEach((el)=>{ el.value=''; }); }catch(e){} },
  /** Move the keyboard into a dialog that opened over an overlay (core.js only focuses a dialog when nothing was open before it). */
  focusLater(selector){ setTimeout(()=>{ try{ const el=document.querySelector(selector); if(el)el.focus(); }catch(e){} },40); },
  labelOf(id){ const n=this.node(id); return n?n.label:String(id); },
  entryNameOf(node,id){ const e=(this.vault.entries[node]||[]).find((x)=>x.id===id); return e?e.name:String(id); },

  // ─────────────── the second factor (Settings → Security) ───────────────
  /** Merge into the open dialog's flow.  Nothing happens once the dialog has been closed: a late answer must not bring a secret back. */
  setGate(patch){ this.setState((st)=>st.gateFlow?{gateFlow:{...st.gateFlow,...patch}}:{}); },
  /** Open the dialog and stage an enrolment.  Over a second factor already in force the broker wants a FRESH code first (two_factor_required): the dialog says how. */
  openGateEnrol(){
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info','Setting up a second factor needs the CredMgr app: this page has no broker. Nothing was changed.'); return; }
    if(this.model.status!=='unlocked'){ this.notify('info','Unlock the vault first. Nothing was changed.'); return; }
    this.setState((st)=>({dialog:'gateEnrol',gateFlow:{...GATE0,replacing:!!this.model.gateConfirmed},fieldErrors:{...(st.fieldErrors||{}),gateEnrol:''}}));
    this.focusLater('[data-screen-label="Second factor"] button'); // opened over Settings, so the design schedules no focus move of its own
    return this.startGateEnrol();
  },
  async startGateEnrol(){
    const seq=(this._gateSeq=(this._gateSeq||0)+1);
    this.setState((st)=>({fieldErrors:{...(st.fieldErrors||{}),gateEnrol:''}}));
    this.setGate({step:'loading',reason:null,totp:'',busy:false});
    try{
      const g=sessionActions.describeEnrolment(await sessionActions.beginGateEnrolment(this.model));
      if(seq===this._gateSeq){ this.setGate({step:'qr',qr:g.qr,secret:g.secret,totp:''}); this.focusLater('[data-screen-label="Second factor"] input[aria-label="authenticator code"]'); } // an answer for a dialog that was closed (or reopened) meanwhile is dropped
    }catch(e){
      if(seq!==this._gateSeq)return;
      this.setGate({step:'error',reason:errorCode(e)});
      this.routeError(e,{op:'vault.gate_enroll_begin',field:'gateEnrol',inlineRendered:true});
    }
  },
  async confirmGateEnrol(){
    const g=this.state.gateFlow;
    if(!g||g.busy||g.step!=='qr'||!/^\d{6}$/.test(g.totp||''))return;
    const seq=this._gateSeq;
    this.setState((st)=>({fieldErrors:{...(st.fieldErrors||{}),gateEnrol:''}}));
    this.setGate({busy:true});
    try{
      const {recoveryCodes:codes}=await sessionActions.confirmGateEnrolment(this.model,g.totp);
      if(seq!==this._gateSeq||!this.state.gateFlow){
        // The broker accepted the code, and the window it would have shown the recovery codes in is gone (a lock came first).  The codes are dropped
        // unseen, never parked anywhere; say so, and how to get new ones.
        this.notify('warn','The second factor was set up, but this window closed before its recovery codes could be shown. Replace it from Settings → Security to get new ones.');
        return;
      }
      this.setGate({busy:false,step:'codes',codes,codesSaved:false,qr:null,secret:'',totp:''});
      this.focusLater('[data-screen-label="Second factor"] input[type="checkbox"]');
    }catch(e){
      if(seq!==this._gateSeq)return;
      this.setGate({busy:false,totp:''});
      this.routeError(e,{op:'vault.gate_enroll_confirm',field:'gateEnrol',inlineRendered:true});
      if(errorCode(e)==='gate_not_enrolling')this.setGate({step:'error',reason:'gate_not_enrolling'});
    }
  },
  /** Close without finishing (Cancel, or the scrim).  Not while a confirmation is in flight. */
  closeGateEnrol(){
    const g=this.state.gateFlow;
    if(g&&g.busy)return; // not while a confirmation is in flight
    this.setState({dialog:null});
  },
  finishGateEnrol(){
    const g=this.state.gateFlow;
    if(!g||g.step!=='codes')return;
    this.setState({dialog:null});
    this.notify('success',g.replacing?'Second factor replaced.':'Second factor set up. The vault now asks for a code at every unlock.');
  },

  // ─────────────── grants ───────────────
  async doCreateGrant(){
    const g=this.state.grant;
    const scope=['read','reveal','notes'].filter((k)=>g.caps[k]);
    const r=await this.runAdmin('grant.create',()=>admin.createGrant(this.model,g.from,{kind:'node',nodeId:g.to},scope,g.reason.trim()));
    if(!r.ok)return; // a refusal (presence) is already on screen; the dialog stays so nothing the user typed is lost
    this.setState((st)=>({dialog:null,grant:{...st.grant,reason:''}}));
    if(r.value.readbackError)this.savedButNotRefreshed(r.value.readbackError,'Grant created.'); // created; the list on screen is out of date
    else this.notify('success','Grant created.');
  },
  async doRevokeGrant(id){
    const r=await this.runAdmin('grant.revoke',()=>admin.revokeGrant(this.model,id),{reload:()=>this.model.refresh({grants:true})}); // already revoked elsewhere: the list says what the broker says
    if(!r.ok)return;
    if(r.value.readbackError)this.savedButNotRefreshed(r.value.readbackError,'Grant revoked.'); // revoked; the list on screen is out of date
    else this.notify('success','Grant revoked.');
  },

  // ─────────────── audit ───────────────
  async loadAudit(){
    if(DEMO_BUILD&&this.model.kind==='demo'){ this.admSet({auditState:'preview',audit:null}); return; }
    const before=this.adm();
    this.admSet({auditState:'loading'});
    const r=await this.runAdmin('audit.tail',()=>admin.readAudit(this.model,50));
    if(r.ok)this.admSet({auditState:'ready',audit:r.value});
    // A failed read says so and shows NO rows: the last good read is older than the failure, and rows left under "could not be read" would pass for the trail.
    else if(r.route)this.admSet({auditState:'error',audit:null});
    // No route = another operation was running and this one never started: the screen stays as it was.
    else this.admSet({auditState:before.auditState,audit:before.audit});
  },
  /** The full record needs presence: today this is the refusal, shown honestly.  If a broker ever answers, the record is summarised. */
  async openAuditRecord(id){
    const r=await this.runAdmin('audit.get',()=>admin.getAudit(this.model,id));
    if(r.ok){ const a=r.value; this.notify('info',`${a.action} · ${a.node?this.labelOf(a.node):'vault'} · ${a.decision||'recorded'}`); }
  },
  async doAuditReport(){
    const r=await this.runAdmin('audit.tail',()=>admin.readAudit(this.model,500));
    if(!r.ok)return;
    const since=Math.floor(Date.now()/1000)-30*86400;
    const rows=r.value.filter((a)=>a.timestamp>=since&&(a.decision==='deny'||/^grant/i.test(a.action)));
    this.admSet({report:{rows,read:r.value.length},last:'report'});
  },

  // ─────────────── maintenance ───────────────
  async doVerify(){
    const r=await this.runAdmin('maintenance.verify',()=>admin.verifyVault(this.model));
    if(r.ok)this.admSet({verify:{...r.value,at:Date.now()},last:'verify'});
  },
  /**
   * `apply: false` is the dry run (what would be fixed); apply only after the user has read it.  A plain run never touches the seals older than
   * seven days: `purge` (the separate "Doctor with purge" row, ADR-089 and B-7) adds `purgeExpiredSeals`; its dry run lists them, Apply removes the
   * retained originals for good, and Apply keeps the flag of the run that was read.
   */
  async doDoctor(apply,purge){
    const r=await this.runAdmin('maintenance.doctor',()=>admin.runDoctor(this.model,{apply:!!apply,...(purge?{purgeExpiredSeals:true}:{})}));
    if(!r.ok)return;
    const {readbackError,...doctor}=r.value;
    this.admSet({doctor:{...doctor,purge:!!purge},last:'doctor'});
    if(doctor.applied){
      const text=doctor.fixCount?`Applied ${plural(doctor.fixCount,'fix','fixes')}.`:'Nothing needed fixing.';
      if(readbackError)this.savedButNotRefreshed(readbackError,text); // applied; the graph on screen has not caught up
      else this.notify('success',text);
    }
  },
  openAdminPass(kind){
    if(DEMO_BUILD&&this.model.kind==='demo'){ this.notify('info','This browser preview has no broker. Open the CredMgr app to use this.'); return; }
    this.wipeAdminPass();
    this.setState((st)=>({dialog:'adminPass',fieldErrors:{...(st.fieldErrors||{}),adminPass:''},admin:{...ADMIN0,...(st.admin||{}),prompt:{kind}}}));
    this.focusLater('input[data-admin-pass]');
  },
  closeAdminPass(){ this.wipeAdminPass(); this.admSet({prompt:null},{dialog:null}); },
  setAdminPassError(message){ this.setState((st)=>({fieldErrors:{...(st.fieldErrors||{}),adminPass:message}})); },
  /** The passphrase prompt's Submit: read the inputs once, hand the text to the broker, keep none of it. */
  async submitAdminPass(){
    const p=this.adm().prompt, def=p&&PROMPTS[p.kind];
    if(!def||this.adm().busy)return;
    const pass=this._adminPass||'', again=this._adminRepeat||'';
    if(!pass){ this.setAdminPassError('Enter the passphrase.'); return; }
    if(def.repeat&&pass!==again){ this.setAdminPassError('The two passphrases are different.'); return; }
    this.setAdminPassError('');
    this.wipeAdminPass();
    const kind=p.kind, retain=this.state.backupRetain||14;
    const call=()=>kind==='backup'?admin.backupVault(this.model,pass,retain):kind==='rotate'?admin.rotateRootKey(this.model,pass):admin.runDoctor(this.model,{apply:true,rebuildRegistry:true,passphrase:pass});
    const r=await this.runAdmin(def.op,call,{field:'adminPass',inlineRendered:true});
    if(!r.ok){ if(r.route&&r.route.route==='presence')this.closeAdminPass(); return; } // refused for lack of presence: nothing changed, nothing to retry here
    if(kind==='backup'){ this.admSet({backup:r.value,last:'backup',prompt:null},{dialog:null}); this.notify('success','Backup written.'); }
    else if(kind==='rotate'){
      // The new recovery code is shown once.  Nothing reads the model after this call: a rotation whose last step is still pending locks the vault.
      this.admSet({recovery:{code:r.value.recoveryCode,pending:!!r.value.completionPending,nodes:r.value.nodesRewrapped,saved:false},last:'rotate',prompt:null},{dialog:'recovery'});
      this.focusLater('[data-screen-label="New recovery code"] input');
    } else {
      const {readbackError,...doctor}=r.value;
      this.admSet({doctor,last:'doctor',prompt:null},{dialog:null});
      if(readbackError)this.savedButNotRefreshed(readbackError,'Registry rebuilt.'); // rebuilt; the graph on screen has not caught up
      else this.notify('success','Registry rebuilt.');
    }
  },
  dismissRecovery(){ this.admSet({recovery:null},{dialog:null}); },

  /** Copy a donation address (not a secret).  Says "copied" only when the clipboard write actually succeeded: the address is the one thing a clipboard hijacker targets, so a silent failure is worse than a visible one. */
  copyDonateAddress(addr){
    const done=(ok)=>{
      clearTimeout(this._donateT);
      this.setState({donateCopied:ok,donateCopyFailed:!ok});
      this._donateT=setTimeout(()=>this.setState({donateCopied:false,donateCopyFailed:false}),ok?1500:6000);
      if(!ok)this.notify('error','Could not copy the address. Select it and copy it by hand.');
    };
    try{ admin.copyPlainText(addr).then(()=>done(true),()=>done(false)); }
    catch(x){ done(false); }
  },

  // ─────────────── what the screens bind to ───────────────
  /** The result panel of the Operations overlay: what the last operation said, and what can be done about it. */
  opsResult(a){
    const lines=[], actions=[];
    const line=(text,tone)=>lines.push({text,tone:tone||'var(--ash)'});
    let title='';
    if(a.last==='verify'&&a.verify){
      const v=a.verify; title='Verify integrity';
      line(v.ok?`ok · ${plural(v.nodesChecked,'node')} checked`:`${plural(v.errors.length,'problem')} in ${plural(v.nodesChecked,'node')} checked`,v.ok?'var(--bone)':'var(--danger-fg)');
      v.errors.forEach((p)=>line(`${p.node?this.labelOf(p.node):'vault'}: ${p.detail}`,'var(--danger-fg)'));
      v.warnings.forEach((p)=>line(`warning · ${p.node?this.labelOf(p.node):'vault'}: ${p.detail}`,'var(--warn)'));
    } else if(a.last==='doctor'&&a.doctor){
      const d=a.doctor; title=d.applied?'Doctor · applied':d.purge?'Doctor · purge expired seals':'Doctor · checked';
      line(d.applied?`${plural(d.fixCount,'fix','fixes')} applied`:(d.fixCount?`${plural(d.fixCount,'fix','fixes')} would be applied`:'nothing needs fixing'),'var(--bone)');
      d.fixes.forEach((f)=>line(`${f.node?this.labelOf(f.node):'vault'} · ${f.type}${/expired-seal$/.test(f.type)?` · ${f.sealedAt?'sealed '+fmtDateTime(f.sealedAt)+' · ':''}the retained original ${d.applied?'was removed for good':'would be removed for good'}`:''}`));
      d.unfixable.forEach((p)=>line(`cannot fix · ${p.node?this.labelOf(p.node):'vault'}: ${p.detail}`,'var(--danger-fg)'));
      if(!d.applied&&d.fixCount>0)actions.push({label:`Apply ${plural(d.fixCount,'fix','fixes')}`,go:()=>this.doDoctor(true,d.purge)});
      if(d.unfixable.length>0)actions.push({label:'Rebuild registry…',go:()=>this.openAdminPass('rebuild')});
    } else if(a.last==='backup'&&a.backup){
      title='Back up vault';
      line(`written to ${a.backup.path}`,'var(--bone)');
      line(`${plural(a.backup.pruned,'older archive')} removed · keeping ${a.backup.retain}`);
    } else if(a.last==='rotate'){
      title='Rotate root key';
      line('The root key was replaced. The new recovery code was shown once.','var(--bone)');
    } else if(a.last==='report'&&a.report){
      title='Audit report · last 30 days';
      line(`${plural(a.report.rows.length,'denied or grant record')} in the ${plural(a.report.read,'record')} read`,'var(--bone)');
      a.report.rows.forEach((r)=>line(`${fmtTime(r.timestamp)} · ${r.action}${r.decision?' · '+r.decision:''} · ${r.node?this.labelOf(r.node):'vault'} · ${who(r.actor)}`,r.decision==='deny'?'var(--danger-fg)':'var(--ash)'));
    }
    return {show:lines.length>0,title,lines,actions};
  },
  rvSettings(c){
    const {btn, e, isLite, isPro, nodeOpts, s, set, v} = c;
    const a=this.adm(), busy=!!a.busy;
    // settings
    // Lite hides levers, never safety: revoking a grant is reachable in both modes (creating one is Pro's).
    const navL=[['security','Security'],['appearance','Appearance'],['backup','Backup'],['mode','Mode'],['grants','Grants'],['games','Games']];
    const navP=[['security','Security'],['appearance','Appearance'],['backup','Backup'],['mode','Mode'],['games','Games'],['nodes','Nodes'],['grants','Grants'],['maintenance','Maintenance'],['audit','Audit'],['advanced','Advanced'],['ops','Operations ⌘⇧O']];
    const nav=(isPro?navP:navL).map(([id,label])=>({label,current:s.setSection===id?'true':'false',bg:s.setSection===id?'var(--steel-3)':'transparent',go:()=>{ if(id==='ops'){this.setState({overlay:'ops'});} else { this.setState({setSection:id}); if(id==='audit')this.loadAudit(); } }}));
    // Operations that exist in beta.1.  merge, re-key, export, import and purge are not part of this release (design-upstream/PROVENANCE.md).
    const op=(name,desc,label,run)=>({name,desc,label,run,disabled:busy});
    const opsRows=[
      op('Verify integrity','Check every envelope and manifest checksum.','Run',()=>this.doVerify()),
      op('Doctor','Diagnose registry and manifest problems; a dry run shows what it would fix. It never purges anything.','Run',()=>this.doDoctor(false,false)),
      op('Doctor with purge','Also lists the seals older than 7 days; Apply then removes their retained originals. Irreversible; a plain Doctor run never does this.','Preview purge',()=>this.doDoctor(false,true)),
      op('Back up vault','Encrypted archive in the vault’s backups folder.','Back up…',()=>this.openAdminPass('backup')),
      op('Rotate root key','New root key and a new recovery code. Needs presence.','Rotate…',()=>this.openAdminPass('rotate')),
      op('Audit report','Denied requests and grant changes, last 30 days.','Run',()=>this.doAuditReport())
    ];
    const res=this.opsResult(a);
    // audit
    const auditRows=(a.audit||[]).map((r)=>{
      const what=r.node?`${this.labelOf(r.node)}${r.entry?' · '+this.entryNameOf(r.node,r.entry):''}`:'—';
      return {time:fmtTime(r.timestamp),op:r.action,what,who:who(r.actor),whoTitle:r.actor,opColor:r.decision==='deny'?'var(--danger-fg)':/reveal/.test(r.action)?'var(--warn)':'var(--ash)',open:()=>this.openAuditRecord(r.id)};
    });
    const auditNote={idle:'',loading:'reading the audit trail…',ready:auditRows.length?`${plural(auditRows.length,'record')}, newest first`:'',error:'the audit trail could not be read',...(DEMO_BUILD?{preview:'the audit trail needs the CredMgr app (this preview has no broker)'}:{})}[a.auditState]||'';
    const dIdx=Math.min(s.donateChainIdx||0,DONATE_CHAINS.length-1);
    const activeChain=DONATE_CHAINS[dIdx];
    const donateTabs=DONATE_CHAINS.map((c2,i)=>({short:c2.short,bg:i===dIdx?'var(--bone)':'transparent',fg:i===dIdx?'var(--night)':'var(--bone)',go:()=>this.setState({donateChainIdx:i})}));
    const [dB,dF]=btn(e.theme==='dark'),[lB,lF]=btn(e.theme==='light');
    const [coB,coF]=btn(e.colour==='off'),[cnB,cnF]=btn(e.colour==='on'),[caB,caF]=btn(e.colour==='auto');
    const [liB,liF]=btn(isLite),[prB,prF]=btn(isPro);
    // grant dialog
    const g=s.grant;
    const grantScope=['read','reveal','notes'].filter((k)=>g.caps[k]);
    const grantSaveDisabled=isLite||busy||g.reason.trim().length<8||g.from===g.to||!grantScope.length;
    // the second factor: what this session can honestly say
    const gate=this.model.gateConfirmed;
    const gf=s.gateFlow, gfs=gf&&s.dialog==='gateEnrol'?gf.step:'';
    const gateErrorText=gf&&gf.reason==='two_factor_required'
      ? 'Replacing the second factor needs a fresh code from the one you have now. Lock the vault, unlock it again with your current code, then come back here within 5 minutes.'
      : gf&&gf.reason==='gate_not_enrolling' ? 'No enrolment is in progress any more. Try again.'
      : 'The second factor could not be prepared'+(gf&&gf.reason?' ('+gf.reason+')':'')+'. Try again.';
    // the passphrase prompt
    const p=a.prompt, pd=p?PROMPTS[p.kind]:null;
    const rec=a.recovery;
    const verifyChip=a.verify?(a.verify.ok?{state:'ok',label:`ok · ${plural(a.verify.nodesChecked,'node')} checked`}:{state:'danger',label:plural(a.verify.errors.length,'problem')}):{state:'',label:'not checked yet'};
    return {
      dlgHelp:s.dialog==='help',
      helpGoAbout:(ev)=>{ev.preventDefault();this.setState({dialog:'about',aboutTab:'main'});},
      // grant dialog (creating one needs presence, which this beta cannot attest: the broker refuses it and nothing changes)
      dlgGrant:s.dialog==='grant',
      grantLiteNote:isLite,
      grantDisabledAll:isLite,
      grantFrom:g.from,
      grantTo:g.to,
      grantFromLabel:this.labelOf(g.from),
      grantToLabel:this.labelOf(g.to),
      onGrantFrom:(ev)=>{ const nv=ev.target.value; const to=g.to===nv?((nodeOpts.find(o=>o.id!==nv)||{}).id||g.to):g.to; this.setState({grant:{...g,from:nv,to}}); }, // C-2
      onGrantTo:(ev)=>this.setState({grant:{...g,to:ev.target.value}}),
      grantNodeOpts:nodeOpts,
      grantNodeOpts2:nodeOpts.filter(o=>o.id!==g.from),
      grantCaps:[['read','read'],['reveal','reveal values'],['notes','notes']].map(([k,label])=>({label,on:!!g.caps[k],toggle:()=>this.setState({grant:{...g,caps:{...g.caps,[k]:!g.caps[k]}}})})),
      grantReason:g.reason,
      onGrantReason:(ev)=>this.setState({grant:{...g,reason:ev.target.value}}),
      grantSaveDisabled,
      confirmGrant:()=>this.doCreateGrant(),
      // the presence notice dialog: a refusal explained, not a Touch ID prompt
      dlgTouch:s.dialog==='touch',
      touchTitle:s.touch?s.touch.title:'',
      touchBody:s.touch?s.touch.body:'',
      touchOk:()=>this.setState({dialog:null,touch:null}),
      // about
      dlgAbout:s.dialog==='about',
      aboutIsMain:s.aboutTab==='main',
      aboutIsDonate:s.aboutTab==='donate',
      aboutIsPrivacy:s.aboutTab==='privacy',
      aboutIsLicenses:s.aboutTab==='licenses',
      aboutVersion:s.appVersion||(DEMO_BUILD&&this.model.kind==='demo'?'browser preview':(s.versionFailed?'unknown':'…')),
      goDonate:(ev)=>{ev.stopPropagation();this.setState({aboutTab:'donate'});},
      goPrivacy:(ev)=>{ev.stopPropagation();this.setState({aboutTab:'privacy'});},
      goLicenses:(ev)=>{ev.stopPropagation();this.setState({aboutTab:'licenses'});},
      goAboutMain:set({aboutTab:'main'}),
      donateTabs,
      activeChainName:activeChain.chain,
      activeChainAddress:activeChain.address,
      donateCopyLabel:s.donateCopied?'copied ✓':(s.donateCopyFailed?'copy failed':'copy address'),
      donateCopyAddr:()=>this.copyDonateAddress(activeChain.address),
      ovSettings:s.overlay==='settings',
      ovOps:s.overlay==='ops',
      settingsNav:nav,
      modeLabel:isPro?'pro':'lite',
      setSecurity:s.setSection==='security',
      setAppearance:s.setSection==='appearance',
      setBackup:s.setSection==='backup',
      setMode:s.setSection==='mode',
      setGames:s.setSection==='games',
      setNodes:isPro&&s.setSection==='nodes',
      setGrants:s.setSection==='grants',
      setMaint:isPro&&s.setSection==='maintenance',
      setAudit:isPro&&s.setSection==='audit',
      setAdvanced:isPro&&s.setSection==='advanced',
      isLite,
      adminBusy:busy,
      // security
      autoLockVal:String(s.autoLockMins),
      autoLockOpts:AUTO_LOCK_CHOICES.map((m)=>({value:String(m),label:m===0?'never (warned)':m+' min'})),
      onAutoLock:(ev)=>{const m=+ev.target.value; this.setState({autoLockMins:m},()=>this.armAutoLock());},
      gateChipLabel:gate?'enrolled':'not confirmed',
      gateChipState:gate?'ok':'warn',
      gateCaption:gate?'vault-wide TOTP, asked at every unlock · replace it here (it needs a fresh code from the current one), or run credmgr gate enroll in a terminal':'this session did not go through a second factor, so the app cannot tell whether one is enrolled · set one up here (confirming replaces any that exists), or run credmgr gate enroll in a terminal',
      gateActionLabel:gate?'Replace…':'Set up…',
      gateActionDisabled:!!gf,
      openGateEnrol:()=>this.openGateEnrol(),
      // the second-factor dialog (src/design/screens/dlg-gate.html)
      dlgGate:s.dialog==='gateEnrol'&&!!gf,
      gateTitle:gf&&gf.replacing?'replace the second factor':'set up a second factor',
      gateReplaceNote:!!(gf&&gf.replacing&&gfs!=='codes'),
      gateStepLoading:gfs==='loading',
      gateStepError:gfs==='error',
      gateErrorText,
      gateStepQr:gfs==='qr',
      gateStepCodes:gfs==='codes',
      gateQrPath:gf&&gf.qr?gf.qr.d:'',
      gateQrViewBox:gf&&gf.qr?'0 0 '+gf.qr.size+' '+gf.qr.size:'0 0 1 1',
      gateSecret:gf?gf.secret:'',
      gateTotp:gf?gf.totp:'',
      onGateTotp:(ev)=>{
        const val=ev.target.value.replace(/\D/g,'').slice(0,6);
        this.setGate({totp:val});
        if(val.length===6)setTimeout(()=>{ const g=this.state.gateFlow; if(g&&g.totp===val&&g.step==='qr')this.confirmGateEnrol(); },250); // six digits is a code: send it without a click
      },
      onGateTotpKey:(ev)=>{ if(ev.key==='Enter'){ ev.preventDefault(); this.confirmGateEnrol(); } },
      gateConfirm:()=>this.confirmGateEnrol(),
      gateConfirmDisabled:!gf||!!gf.busy||!/^\d{6}$/.test(gf.totp||''),
      gateConfirmLabel:gf&&gf.busy?'Working…':'Confirm code',
      gateCodes:(gf?gf.codes:[]).map((code)=>({code})),
      gateCodesSaved:!!(gf&&gf.codesSaved),
      onGateCodesSaved:(ev)=>this.setGate({codesSaved:!!ev.target.checked}),
      gateDone:()=>this.finishGateEnrol(),
      gateDoneDisabled:false,
      gateErrShow:!!(s.fieldErrors||{}).gateEnrol,
      gateErr:(s.fieldErrors||{}).gateEnrol||'',
      gateCanCancel:gfs!=='codes'&&!(gf&&gf.busy),
      gateCanRetry:gfs==='error'&&!(gf&&gf.reason==='two_factor_required'), // that one needs a lock and an unlock first: a retry here cannot work
      gateCancel:()=>this.closeGateEnrol(),
      gateRetry:()=>this.startGateEnrol(),
      gateScrim:()=>this.closeGateEnrol(),
      revealWindowVal:String(s.revealWindowSecs),
      revealOpts:REVEAL_CHOICES.map((n)=>({value:String(n),label:n+' s'})),
      onRevealWindow:(ev)=>this.setState({revealWindowSecs:+ev.target.value}),
      // appearance
      setDark:()=>this.setState({theme:'dark'}),
      setLight:()=>this.setState({theme:'light'}),
      darkBtnBg:dB,
      darkBtnFg:dF,
      lightBtnBg:lB,
      lightBtnFg:lF,
      colourOff:()=>this.setState({colour:'off'}),
      colourOn:()=>this.setState({colour:'on'}),
      colourAuto:()=>this.setState({colour:'auto'}),
      coffBg:coB,
      coffFg:coF,
      conBg:cnB,
      conFg:cnF,
      cautoBg:caB,
      cautoFg:caF,
      colourIsOn:e.colour==='on',
      hueVal:String(e.hue),
      intVal:String(e.intensity),
      onHue:(ev)=>this.setState({hue:+ev.target.value}),
      onIntensity:(ev)=>this.setState({intensity:+ev.target.value}),
      huePresets:[['Vault',198],['Ink',255],['Moss',150],['Rust',30],['Slate',220]].map(([label,h])=>({label,set:()=>this.setState({hue:h,colour:'on'})})),
      toggleGreyscale:()=>this.setState({greyscale:!e.greyscale}),
      gsLabel:e.greyscale?'greyscale on':'greyscale off',
      contrastVal:s.contrastMode,
      onContrast:(ev)=>this.setState({contrastMode:ev.target.value}),
      motionVal:s.motion,
      onMotion:(ev)=>this.setState({motion:ev.target.value}),
      hwAccelOn:s.hwAccel!==false,
      toggleHwAccel:()=>this.setState(st=>({hwAccel:!st.hwAccel})),
      hwAccelLabel:s.hwAccel!==false?'on':'off',
      // screen capture (threat T10): turning it OFF asks first; turning it ON does not
      captureProtectionOn:s.captureProtection!==false,
      captureProtectionLabel:s.captureProtection!==false?'on':'off',
      captureAllowedShow:s.captureProtection===false,
      toggleCaptureProtection:()=>{
        if(this.state.captureProtection!==false){ this.setState({dialog:'captureOff'}); this.focusLater('[data-capture-cancel]'); }
        else { this.setState({captureProtection:true}); this.applyCaptureProtection(true); }
      },
      dlgCaptureOff:s.dialog==='captureOff',
      cancelCaptureOff:()=>this.setState({dialog:null}),
      confirmCaptureOff:()=>{ this.setState({captureProtection:false,dialog:null}); this.applyCaptureProtection(false); },
      // backup and integrity
      openBackupPrompt:()=>this.openAdminPass('backup'),
      retainVal:String(s.backupRetain||14),
      retainOpts:RETAIN_CHOICES.map((n)=>({value:String(n),label:n+' archives'})),
      onRetain:(ev)=>this.setState({backupRetain:+ev.target.value}),
      backupInfoShow:!!a.backup,
      backupInfoText:a.backup?`last backup this session: ${a.backup.path} · ${plural(a.backup.pruned,'older archive')} removed`:'',
      integrityDesc:'checks every envelope and manifest checksum; run it whenever you like',
      verifyChipLabel:verifyChip.label,
      verifyChipState:verifyChip.state,
      verifyChipStyle:verifyChip.state==='danger'?'color:var(--danger-fg)':'', // the chip's own danger colour is for borders; text needs the readable token
      runVerify:()=>this.doVerify(),
      // mode
      setLite:()=>this.setState({mode:'lite',setSection:'mode'}),
      setPro:()=>this.setState({mode:'pro'}),
      liteBtnBg:liB,
      liteBtnFg:liF,
      proBtnBg:prB,
      proBtnFg:prF,
      // nodes (the seal and restore flows are the writes package's)
      settingsNodeRows:v.nodes.filter(n=>n.id!=='global').map(n=>({label:n.label,meta:`${n.kind} · ${n.counts.entries} entries${n.parentId&&n.parentId!=='global'?' · under '+n.parentId:''}`,seal:()=>this.setState({dialog:'seal',sealTarget:n.id,sealTyped:''})})),
      sealedRows:v.sealed.map((r)=>({label:(r.node&&r.node.label)||r.label||r.id,meta:`sealed ${typeof r.sealedAt==='number'&&isFinite(r.sealedAt)&&r.sealedAt>0?fmtDateTime(r.sealedAt).slice(0,10):(r.date||'this session')}${Array.isArray(r.kids)?' · '+plural(r.kids.length,'sub-node'):''} · ${sealWindow(r)}`,restore:()=>this.restoreSealed(r.id)})),
      sealedEmpty:!v.sealed.length,
      // grants
      grantRows:v.grants.map((gr)=>({fromTo:`${this.labelOf(gr.from)} ⇢ ${this.labelOf(gr.to)}${gr.toEntry?' · '+this.entryNameOf(gr.to,gr.toEntry):''}`,scope:gr.scope,expiry:gr.expires==='never'?'never expires':'expires '+gr.expires,reason:gr.reason,revoke:()=>this.doRevokeGrant(gr.id)})),
      grantsEmpty:!v.grants.length,
      openGrantDlg:set({dialog:'grant'}),
      // maintenance and operations
      openOps:set({overlay:'ops'}),
      opsRows,
      opsResultShow:res.show,
      opsResultTitle:res.title,
      opsResultLines:res.lines,
      opsResultActions:res.actions.map((x)=>({...x,disabled:busy})),
      opsResultHasActions:res.actions.length>0,
      // audit
      auditRows,
      auditNote,
      auditEmpty:a.auditState==='ready'&&!auditRows.length,
      refreshAudit:()=>this.loadAudit(),
      // advanced
      openRotatePrompt:()=>this.openAdminPass('rotate'),
      // the passphrase prompt (backup, rotate root, rebuild registry)
      dlgAdminPass:s.dialog==='adminPass'&&!!pd,
      adminPassTitle:pd?pd.title:'',
      adminPassBody:pd?pd.body:'',
      adminPassLabel:pd?pd.label:'',
      adminPassRepeatShow:!!(pd&&pd.repeat),
      adminPassAction:pd?pd.action:'',
      adminPassError:(s.fieldErrors||{}).adminPass||'',
      onAdminPass:(ev)=>{ this._adminPass=ev.target.value; },
      onAdminRepeat:(ev)=>{ this._adminRepeat=ev.target.value; },
      adminPassKey:(ev)=>{ if(ev.key==='Enter'){ ev.preventDefault(); this.submitAdminPass(); } },
      submitAdminPass:()=>this.submitAdminPass(),
      closeAdminPass:()=>this.closeAdminPass(),
      // the recovery code shown once after a root-key rotation
      dlgRecovery:s.dialog==='recovery'&&!!rec,
      recoveryCode:rec?rec.code:'',
      recoveryNote:rec&&rec.pending?'The rotation committed, but moving the last files into place did not finish. The vault has locked itself; unlocking it again finishes the move. This code is already the live one.':'Your previous recovery code no longer works. Write this one down somewhere safe, away from this computer.',
      recoverySaved:!!(rec&&rec.saved),
      onRecoverySaved:(ev)=>this.admSet({recovery:{...rec,saved:!!ev.target.checked}}),
      dismissRecovery:()=>this.dismissRecovery(),
      recoveryCloseDisabled:!(rec&&rec.saved),
    };
  },
};
