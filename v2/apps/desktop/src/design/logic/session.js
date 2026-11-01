/* The session: boot routing, the Lock screen, first run, locking, and the app header.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Session lane (WP-A).

   The one rule everything here serves: a locked vault is the Lock screen.  There is no "locked but visible" mode (the broker
   treats a process with no login as an agent that may only list), so every road to "locked" ends in showLock(), which also
   forgets what the session held: the model's names and notes, every revealed value, anything half-typed in a dialog.

   Roads to the Lock screen:  the user (Lock chip, vault menu, Cmd/Ctrl-L), the idle timer, the window being hidden, the
   broker's own idle lock (found by the 30 s check), the shell (sleep, screen lock: `credmgr://locked`), and any rejected call
   that says the login is gone (`vault_locked`, `session_expired`: src/vault/errors.ts). */

import { errorCode, session as sessionActions } from "../../vault/index";

/** Lock screen steps.  3 is the passphrase (the default); 1 is the old Touch ID step, which no longer exists and shows the passphrase. */
export const LOCK_CODE = 2;
export const LOCK_PHRASE = 3;
export const LOCK_RECOVER = 4;

const FR_STEPS = 4;
/** The GUI asks for more than the CLI does (which takes any non-empty passphrase): a vault passphrase of one letter is a mistake. Four is the floor; eight or more is recommended, never required. */
export const PASSPHRASE_MIN = 4;
export const PASSPHRASE_RECOMMENDED = 8;
/** There is no push channel from the broker (bridge.ts rule 4): ask this often, and whenever the window comes back. */
const LIVENESS_MS = 30000;

/** The first-run wizard's state.  The secrets in it (the passphrase while typing, the recovery code, the authenticator's secret, the gate's recovery codes) exist only while their step is on screen. */
export const freshFirstRun = () => ({
  step: 1, busy: false, pass: '', passRepeat: '',
  recoveryCode: '', retyped: '', rec: false,
  enrol: 'idle', secret: '', qr: null, totp: '', codes: [], codesSaved: false,
  names: ['', '', ''],
});

/** What a lock must forget: open dialogs and menus, everything half-typed in them, the selection, the search, revealed values. */
export const freshEphemeral = () => ({
  reveals: {}, copied: {}, ctx: null, dialog: null, overlay: null, hover: null, openEntry: null,
  searchQ: '', searchOpen: false, vaultMenu: false, railOpen: false, inspOpen: false,
  touch: null, touchCode: '', vaultLocked: false, notice: null,
  selected: 'global', recentNodes: [], renamingNode: null, renameVal: '',
  addNode: 'global', addName: '', addMode: 'single', singleFields: [{ label: '', value: '' }], bulkText: '', splitSegs: false, typeOverrides: {}, entryTypeOverride: null, preview: null, previewBusy: false,
  fieldMenu: null, fieldForm: null, // the field menu, and the add / edit / remove dialog's form (a half-typed value is a secret)
  undo: null, undoDone: null, tf: null, tfUntil: 0, tfNow: 0, // the Undo offer (an audit id of this login), and the second-factor dialog
  aprOpen: false, aprReq: '', aprPass: '', aprCode: '', aprResult: '', aprErr: '', aprBusy: false, aprWaiting: [], // the locked-approval panel: a typed passphrase and code die with the screen
  sealTarget: null, sealTyped: '', newNodeName: '', newNodeParent: 'global', newNodeFolders: [''],
  gateFlow: null, // the Settings second-factor dialog: its authenticator secret, QR and recovery codes die with the session
  donateToastOpen: false, donateView: 'main', donateCode: '', donateCodeErr: false, donateCodeOk: false, donateNoCrypto: false, donateMs: null, flourishOn: false, // the reminder and the unlock flourish never outlive a session
  gameScreen: 'library', gameId: 'credpong', gameLast: null,
});

export const sessionMethods = {
  // ───────────────────────────── boot ─────────────────────────────

  /** Ask the broker where things stand and show the matching screen.  Called once, when the app mounts, and again by Retry. */
  async bootModel(){
    if(this._booting)return; // a second click on Retry while the first is still asking the broker
    this._booting=true;
    const reloadNote=sessionActions.takeReloadLockNote(); // after a shell lock the shell reloaded the page and left the reason: read once, whatever the broker says now
    try{
      try{ await this.model.boot(); }
      catch(e){
        this.routeError(e,{op:'vault.status'});
        if(this.state.screen==='boot')this.setState({screen:'bootfailed'}); // the broker answered, but not usefully: say so, with a way to try again
        return;
      }
      const st=this.model.status;
      if(st==='unlocked'){ this.unlockApp(); }
      else if(st==='locked'){ this.showLock(reloadNote); }
      else if(st==='uninitialized'){ this.setState({screen:'firstrun',fr:freshFirstRun(),fieldErrors:{}}); }
      else if(st==='broker-down'){ this.showBrokerDown(); }
    }finally{ this._booting=false; }
  },
  retryBoot(){ if(this._booting)return; this.setState({screen:'boot'}); return this.bootModel(); },

  // ───────────────────────────── locking ─────────────────────────────

  armAutoLock(){ clearTimeout(this._autoLockT); const m=this.state.autoLockMins; if(!m)return; this._autoLockT=setTimeout(()=>{ if(this.state.screen==='app'&&this.model.status==='unlocked')this.lockVault('Locked after '+m+(m===1?' minute':' minutes')+' without activity.'); },m*60000); },

  /** What the page itself holds that a lock must drop (the model's own store is wiped by model.clear()). */
  dropLocalSecrets(){
    this._frPass=''; this._tfRetry=null; clearInterval(this._tfI); // (a retry closure of the old login must not run in the next one; the five-minute window ends with the lock)
    this.model.wipeSecrets();
    if(typeof this.clearClipboard==='function')this.clearClipboard(); // until the copy path moves to the shell (which clears on lock itself); this only wipes what this page put there
  },

  /** Show the Lock screen with nothing from the last session left on it.  `note` says why, when the user did not ask for it. */
  showLock(note=''){
    clearTimeout(this._retryT); clearTimeout(this._donateTimer); clearTimeout(this._flT);
    this.cpStopListeners(); this.ghStop();
    this.dropLocalSecrets();
    this.setState(st=>({ ...freshEphemeral(), grant:{...st.grant,from:'global',to:'',reason:'',code:''}, fr:freshFirstRun(),
      screen:'lock', lockStep:LOCK_PHRASE, passInput:'', twofa:'', recoverPass:'', recoverCode:'', fieldErrors:{}, lockNote:note, lockRetryAt:0, lockBusy:false }));
    this.startApprovalPoll(); // agents waiting for approval while locked (ADR-090): the Lock screen lists them
  },

  /** The same wipe, for a broker that went away: a restarted broker has forgotten every login. */
  showBrokerDown(){
    clearTimeout(this._retryT);
    this.dropLocalSecrets();
    this.setState(st=>({ ...freshEphemeral(), grant:{...st.grant,from:'global',to:'',reason:'',code:''}, fr:freshFirstRun(),
      screen:'brokerdown', passInput:'', twofa:'', recoverPass:'', recoverCode:'', fieldErrors:{}, lockNote:'', lockRetryAt:0, lockBusy:false }));
  },

  /**
   * Lock on purpose: the user's own lock, the idle timer, a hidden window.  The model forgets at once and shows the Lock screen (see
   * VaultModel.lock) while the broker is told; `note` says why when the user did not ask for it, their own lock says nothing.  Until
   * the broker has answered, Unlock stays off: a login that overlapped the lock call could be dropped by it.
   */
  async lockVault(note=''){
    if(this._locking||this.model.status!=='unlocked')return;
    this._locking=true;
    this._lockNote=note; // read by onModelChange, which the model's clear() reaches before the broker has answered
    sessionActions.rememberPageLockNote(note); // the shell reloads the page after this lock (ADR-091 amendment): the idle-timer sentence has to survive the reload
    try{
      const asking=this.model.lock();
      this.setState({lockWait:true});
      await asking;
    }
    finally{ this._locking=false; this._lockNote=null; this.setState({lockWait:false}); }
    if(this.state.screen==='app'||this.state.screen==='firstrun')this.showLock(note); // the model's change did not reach the screen (the page is going away)
  },

  /** Forget everything the model holds and show the Lock screen with this reason (the model's status becomes 'locked' too). */
  lockWith(note){
    this._lockNote=note; // read by onModelChange, which model.clear() reaches first
    this.model.clear();
    this._lockNote=null;
    this.showLock(note);
  },
  /** The login is gone (a rejected call said so): forget everything and show the Lock screen with the reason. */
  endSession(code){ this.lockWith(sessionActions.lockNoteFor(code)); },

  /** Ask the broker whether this process is still logged in; the model clears itself if not (onModelChange then shows the Lock screen). */
  async checkLiveness(){
    if(this.model.kind!=='bridge'||this.model.status!=='unlocked'||this._probing)return;
    this._probing=true;
    try{ await this.model.checkSession(); }
    catch(e){ this.routeError(e,{op:'vault.status'}); }
    finally{ this._probing=false; }
  },

  /** The shell locked the vault itself (sleep, screen lock) and told us.  It already dropped the login, so there is nothing to lock again. */
  onShellLocked(reason){
    if(this.model.status!=='unlocked')return;
    this._lockNote=sessionActions.shellLockNote(reason);
    this.model.clear();
  },
  /** The shell's other signal: the window is no longer the one the user is looking at.  Hide what was revealed; the vault stays open. */
  onShellWindowInactive(){
    this.model.wipeSecrets();
    if(Object.keys(this.state.reveals).length)this.setState({reveals:{}});
  },
  async startShellListener(){
    if(this.model.kind!=='bridge')return;
    const stops=[], failed=[];
    const subscribe=async(name,sub)=>{ try{ stops.push(await sub()); }catch(e){ failed.push(name); } };
    await subscribe('locked',()=>sessionActions.onShellLocked((reason)=>this.onShellLocked(reason)));
    await subscribe('inactive',()=>sessionActions.onShellWindowInactive(()=>this.onShellWindowInactive()));
    const stopAll=()=>stops.forEach((stop)=>stop());
    if(this._mounted)this._unlistenShell=stopAll; else stopAll();
    if(failed.includes('locked'))this.notify('warn','Could not subscribe to system lock events. The vault still locks when the Mac sleeps; this window notices within 30 seconds.');
    else if(failed.length)this.notify('warn','Could not subscribe to window focus events. Revealed values still hide when their time is up, when the window is hidden and when the vault locks.');
  },
  startLiveness(){ this._liveT=setInterval(()=>this.checkLiveness(),LIVENESS_MS); },
  stopSessionWatchers(){
    clearInterval(this._liveT); clearTimeout(this._retryT);
    if(this._unlistenShell){ this._unlistenShell(); this._unlistenShell=null; }
  },

  // ───────────────────────────── unlock ─────────────────────────────

  /** `{unlocked:true}` when the person just unlocked (counts the day, arms the milestone ask, plays the flourish); a plain call is the app opening onto a login that already exists. */
  unlockApp(opts){
    clearTimeout(this._retryT);
    this._frPass='';
    const flourishOn=opts&&opts.unlocked?this.onUnlocked():false;
    this.setState({flourishOn,donateToastOpen:false,donateMs:null,donateView:'main',screen:'app',lockStep:LOCK_PHRASE,passInput:'',twofa:'',recoverPass:'',recoverCode:'',fieldErrors:{},lockNote:'',lockRetryAt:0,lockBusy:false,fr:freshFirstRun(),pendingBanner:(this.vault.pending||[]).length>0});
    this.armAutoLock();
  },
  retryActive(){ return (this.state.lockRetryAt||0)>Date.now(); },
  /** After a refusal the field is empty and the user is about to retype: put the caret back in the first field of the Lock screen. */
  refocusLock(){ setTimeout(()=>{ const el=document.querySelector('[data-screen-label="S16 Lock screen"] input'); if(el)el.focus(); },0); },

  /** Passphrase step.  Sends the passphrase to the model once and clears the input first, so it is not left in state. */
  async doUnlock(){
    const pass=this.state.passInput||'';
    if(!pass.trim()||this._unlocking||this._locking||this.retryActive())return;
    this._unlocking=true;
    this.setState({passInput:'',fieldErrors:{},lockNote:'',aprResult:'',lockBusy:true});
    try{ await this.model.unlock(pass); this.unlockApp({unlocked:true}); }
    catch(e){ this.routeError(e,{op:'vault.unlock',field:'passphrase',inlineRendered:true}); this.refocusLock(); }
    finally{ this._unlocking=false; this.setState({lockBusy:false}); }
  },
  /** Second-factor step: the 6-digit code (or one of the gate's recovery codes) after `two_factor_required`. */
  async doGateVerify(code){
    if(!code||this._unlocking||this._locking||this.retryActive())return; // the broker's wait applies to this step too
    this._unlocking=true;
    this.setState({twofa:'',fieldErrors:{},lockBusy:true});
    try{ await this.model.gateVerify(code); this.unlockApp({unlocked:true}); }
    catch(e){ this.routeError(e,{op:'vault.gate_verify',field:'code',inlineRendered:true}); this.refocusLock(); }
    finally{ this._unlocking=false; this.setState({lockBusy:false}); }
  },
  /** "Lost your authenticator?": the passphrase and the root recovery code reset the gate, then the login follows. */
  async doRecover(){
    const pass=this.state.recoverPass||'', code=(this.state.recoverCode||'').trim();
    if(!pass||!code||this._unlocking||this._locking||this.retryActive())return;
    this._unlocking=true;
    this.setState({recoverPass:'',recoverCode:'',fieldErrors:{},lockBusy:true});
    try{
      const r=await sessionActions.recoverAndUnlock(this.model,pass,code);
      if(r.unlockError){ // the gate IS reset; only the login after it failed, so the passphrase step is where to go on
        this.setState({lockStep:LOCK_PHRASE,lockNote:'Second factor reset. Unlock with your passphrase.'});
        this.routeError(r.unlockError,{op:'vault.unlock',field:'passphrase',inlineRendered:true});
      } else {
        this.unlockApp({unlocked:true});
        this.notify('success','Second factor reset. Enrol a new authenticator in Settings, under Security.');
      }
    }
    catch(e){ this.routeError(e,{op:'vault.gate_recover',field:'recovery',inlineRendered:true}); this.refocusLock(); }
    finally{ this._unlocking=false; this.setState({lockBusy:false}); }
  },
  /** A `rate_limited` answer: keep the buttons off until the broker's wait is over, then clear the message. */
  holdUnlock(seconds){
    clearTimeout(this._retryT);
    const ms=Math.max(0,seconds)*1000;
    this.setState({lockRetryAt:Date.now()+ms});
    this._retryT=setTimeout(()=>this.setState({lockRetryAt:0,fieldErrors:{}}),ms+50);
  },

  // ───────────────────────────── first run ─────────────────────────────

  setFr(patch){ this.setState(st=>({fr:{...st.fr,...patch}})); },
  /** The wizard's single primary button: what it does depends on the step. */
  frNext(){
    const fr=this.state.fr;
    if(fr.busy)return;
    const step=Math.min(Math.max(fr.step,1),FR_STEPS);
    if(step===1)return this.frBegin();
    if(step===2)return this.frConfirm();
    if(step===3){ if(fr.enrol==='codes')return this.frAfterCodes(); if(fr.enrol==='qr')return this.frConfirmTotp(); if(fr.enrol==='error')return this.frStartEnrol(); return; }
    return this.frFinish();
  },
  frBack(){ const fr=this.state.fr; if(fr.step===2&&!fr.busy){ this._frPass=''; this.setState({fieldErrors:{}}); this.setFr({step:1,pass:'',passRepeat:'',recoveryCode:'',retyped:'',rec:false}); } },
  /** Step 1: send the passphrase.  Nothing is written until step 2 confirms the recovery code (retyped, or the shown one on "Skip for now", ADR-081). */
  async frBegin(){
    const {pass,passRepeat}=this.state.fr;
    if(pass.length<PASSPHRASE_MIN||pass!==passRepeat)return;
    this.setState({fieldErrors:{}}); this.setFr({busy:true});
    try{
      const {recoveryCode}=await sessionActions.beginVault(this.model,pass);
      this._frPass=pass;
      this.setFr({step:2,busy:false,pass:'',passRepeat:'',recoveryCode,retyped:'',rec:false});
    }catch(e){ this.setFr({busy:false}); this.routeError(e,{op:'vault.init_begin',field:'frPass',inlineRendered:true}); }
  },
  /** Step 2: the retyped recovery code writes the vault; the login that opens it follows, then the second factor is offered. */
  async frConfirm(){
    // Retyping the code is optional: left empty (or "Skip for now"), the code shown on this screen is what is sent, so the vault is created either way.
    const fr=this.state.fr, typed=(fr.retyped||'').trim()||fr.recoveryCode;
    if(fr.busy||!typed)return;
    this.setState({fieldErrors:{}}); this.setFr({busy:true});
    try{
      const r=await sessionActions.confirmFirstRun(this.model,typed,this._frPass);
      this._frPass='';
      if(r.unlockError){ // the vault IS written; only the login after it failed, so the Lock screen is where to go on (not "creating it failed")
        this.lockWith('The vault was created. Unlock it with your passphrase.');
        this.routeError(r.unlockError,{op:'vault.unlock',field:'passphrase',inlineRendered:true});
        return;
      }
      this.setFr({step:3,busy:false,recoveryCode:'',retyped:'',rec:false,enrol:'idle'});
      this.frStartEnrol();
    }catch(e){
      this.setFr({busy:false,retyped:''});
      this.routeError(e,{op:'vault.init_confirm',field:'frRecovery',inlineRendered:true});
      if(errorCode(e)==='vault_init_not_pending'){ this._frPass=''; this.setFr({step:1,pass:'',passRepeat:'',recoveryCode:'',rec:false}); }
    }
  },
  /** Step 3: stage an enrolment and show its QR code (drawn locally) and its secret.  Skippable. */
  async frStartEnrol(){
    this.setState({fieldErrors:{}}); this.setFr({enrol:'loading',totp:''});
    try{
      const g=sessionActions.describeEnrolment(await sessionActions.beginGateEnrolment(this.model));
      this.setFr({enrol:'qr',qr:g.qr,secret:g.secret,totp:''});
    }catch(e){ this.setFr({enrol:'error'}); this.routeError(e,{op:'vault.gate_enroll_begin',field:'frTotp',inlineRendered:true}); }
  },
  async frConfirmTotp(){
    const fr=this.state.fr;
    if(fr.busy||!/^\d{6}$/.test(fr.totp||''))return;
    this.setState({fieldErrors:{}}); this.setFr({busy:true});
    try{
      const {recoveryCodes:codes}=await sessionActions.confirmGateEnrolment(this.model,fr.totp);
      this.setFr({busy:false,enrol:'codes',codes,codesSaved:false,qr:null,secret:'',totp:''});
    }catch(e){
      this.setFr({busy:false,totp:''});
      this.routeError(e,{op:'vault.gate_enroll_confirm',field:'frTotp',inlineRendered:true});
      if(errorCode(e)==='gate_not_enrolling')this.setFr({enrol:'error'});
    }
  },
  frSkipEnrol(){ this.setState({fieldErrors:{}}); this.setFr({step:4,enrol:'idle',qr:null,secret:'',totp:''}); },
  /** Continue / Skip for now after the ten recovery codes: ticking "I have saved these" is optional. */
  frAfterCodes(){ this.setFr({step:4,enrol:'idle',codes:[],codesSaved:false}); },
  /** "Skip for now" on the recovery-code step: create the vault without retyping the code. */
  frSkipConfirm(){ this.setFr({retyped:''}); return this.frConfirm(); },
  /** Step 4: the first projects, if any were named, then the app. */
  async frFinish(){
    const fr=this.state.fr;
    if(fr.busy)return;
    this.setState({fieldErrors:{}}); this.setFr({busy:true});
    const r=await sessionActions.createFirstProjects(this.model,fr.names);
    if(r.error){
      this.setFr({busy:false,names:fr.names.map((n,i)=>r.created.includes(i)?'':n)}); // what was made is not made twice on a retry
      this.routeError(r.error,{op:'node.create',field:'frNames',inlineRendered:true});
      return;
    }
    this.unlockApp({unlocked:true});
  },

  // ───────────────────────────── what the template reads ─────────────────────────────

  rvSession(c){
    const {cosm, e, isPro, now, pendN, s, set} = c;
    const fr=s.fr, fe=s.fieldErrors||{};
    const step=Math.min(Math.max(fr.step,1),FR_STEPS);
    const frTitles=['Protect it','Recovery code','Two-factor','Your first projects'];
    const enrol=fr.enrol;
    const retryOn=(s.lockRetryAt||0)>now;
    const passOk=fr.pass.length>=PASSPHRASE_MIN&&fr.pass===fr.passRepeat;
    const frNextLabel=fr.busy?'Working…':step===1?'Continue':step===2?'Create vault':step===3?(enrol==='codes'?'Continue':enrol==='qr'?'Confirm code':enrol==='error'?'Try again':'Preparing…'):'Open the vault';
    const frNextDisabled=fr.busy||(step===1&&!passOk)||(step===3&&(enrol==='loading'||enrol==='idle'||(enrol==='qr'&&!/^\d{6}$/.test(fr.totp||''))));
    const frErrField=step===1?fe.frPass:step===2?fe.frRecovery:step===3?fe.frTotp:fe.frNames;
    const enter=(fn)=>(ev)=>{ if(ev.key==='Enter'){ ev.preventDefault(); fn(); } };
    const onCodeStep=s.lockStep===LOCK_CODE, onRecoverStep=s.lockStep===LOCK_RECOVER;
    return {
      pendingChipShow:pendN>0&&s.screen==='app',
      pendingChipLabel:pendN+' held',
      pendingAnnounce:s.pendingNote||'',
      cosmRing:cosm.ring,
      markKeep:cosm.mark==='keep',
      markCells:cosm.mark==='cells',
      markNode:cosm.mark==='node',
      markSeal:cosm.mark==='seal',
      gsFilter:e.greyscale?'grayscale(1)':'none',
      // ── boot and the broker-down screen
      isBoot:s.screen==='boot',
      isBrokerDown:s.screen==='brokerdown',
      isBootFailed:s.screen==='bootfailed',
      retryBoot:()=>this.retryBoot(),
      // ── Lock screen
      isLockScreen:s.screen==='lock',
      lockNoteShow:!!s.lockNote,
      lockNote:s.lockNote||'',
      lockStepPass:!onCodeStep&&!onRecoverStep,
      lockStepCode:onCodeStep,
      lockStepRecover:onRecoverStep,
      passInput:s.passInput||'',
      onPassInput:(ev)=>this.setState({passInput:ev.target.value}),
      onPassKey:enter(()=>this.doUnlock()),
      passDisabled:!(s.passInput||'').trim()||!!s.lockBusy||!!s.lockWait||retryOn,
      lockBusyLabel:s.lockBusy?'Unlocking…':s.lockWait?'Locking…':'Unlock',
      submitPass:()=>this.doUnlock(),
      lockErrPass:fe.passphrase||fe._||'',
      twofaInput:s.twofa||'',
      onTwofa:(ev)=>{
        const val=ev.target.value.replace(/[^0-9A-Za-z-]/g,'').slice(0,48);
        this.setState({twofa:val});
        // Six digits is a code from the authenticator: send it without a click.  A longer entry is a recovery code and waits for Verify.
        if(/^\d{6}$/.test(val))setTimeout(()=>{ if(this.state.twofa===val&&this.state.lockStep===LOCK_CODE)this.doGateVerify(val); },250);
      },
      onTwofaKey:enter(()=>this.doGateVerify((this.state.twofa||'').trim())),
      submitTwofa:()=>this.doGateVerify((this.state.twofa||'').trim()),
      twofaDisabled:(s.twofa||'').trim().length<6||!!s.lockBusy||!!s.lockWait||retryOn,
      lockErrCode:fe.code||fe._||'',
      gotoPassphrase:()=>this.setState({lockStep:LOCK_PHRASE,passInput:'',twofa:'',recoverPass:'',recoverCode:'',fieldErrors:{}}),
      gotoRecover:()=>this.setState({lockStep:LOCK_RECOVER,twofa:'',recoverPass:'',recoverCode:'',fieldErrors:{}}),
      recoverPass:s.recoverPass||'',
      onRecoverPass:(ev)=>this.setState({recoverPass:ev.target.value}),
      recoverCode:s.recoverCode||'',
      onRecoverCode:(ev)=>this.setState({recoverCode:ev.target.value}),
      onRecoverKey:enter(()=>this.doRecover()),
      submitRecover:()=>this.doRecover(),
      recoverDisabled:!(s.recoverPass||'')||!(s.recoverCode||'').trim()||!!s.lockBusy||!!s.lockWait||retryOn,
      lockErrRecover:fe.recovery||fe.passphrase||fe._||'',
      // ── First run
      isFirstRun:s.screen==='firstrun',
      isApp:s.screen==='app',
      frDots:[1,2,3,4].map(i=>({bg:i<=step?'var(--bone)':'var(--faint)'})),
      frStepNum:String(step),
      frTitle:frTitles[step-1],
      frIs1:step===1,
      frIs2:step===2,
      frIs3:step===3,
      frIs4:step===4,
      frPass:fr.pass,
      onFrPass:(ev)=>this.setFr({pass:ev.target.value}),
      frPassRepeat:fr.passRepeat,
      onFrPassRepeat:(ev)=>this.setFr({passRepeat:ev.target.value}),
      onFrPassKey:enter(()=>this.frNext()),
      frPassShort:fr.pass.length>0&&fr.pass.length<PASSPHRASE_MIN,
      frPassWeak:fr.pass.length>=PASSPHRASE_MIN&&fr.pass.length<PASSPHRASE_RECOMMENDED,
      frSkipConfirmShow:step===2||(step===3&&enrol==='codes'),
      frSkipConfirm:()=>(step===2?this.frSkipConfirm():this.frAfterCodes()),
      frPassMismatch:!!fr.passRepeat&&fr.pass!==fr.passRepeat,
      frRecoveryCode:fr.recoveryCode,
      frRetyped:fr.retyped,
      onFrRetyped:(ev)=>this.setFr({retyped:ev.target.value}),
      onFrRetypedKey:enter(()=>this.frNext()),
      frRecOk:fr.rec,
      onFrRec:(ev)=>this.setFr({rec:ev.target.checked}),
      frEnrolLoading:enrol==='loading'||enrol==='idle',
      frEnrolError:enrol==='error',
      frEnrolQr:enrol==='qr',
      frEnrolCodes:enrol==='codes',
      frQrPath:fr.qr?fr.qr.d:'',
      frQrViewBox:fr.qr?'0 0 '+fr.qr.size+' '+fr.qr.size:'0 0 1 1',
      frSecret:fr.secret,
      frTotp:fr.totp,
      onFrTotp:(ev)=>{
        const val=ev.target.value.replace(/\D/g,'').slice(0,6);
        this.setFr({totp:val});
        if(val.length===6)setTimeout(()=>{ if(this.state.fr.totp===val&&this.state.fr.enrol==='qr')this.frConfirmTotp(); },250);
      },
      onFrTotpKey:enter(()=>this.frConfirmTotp()),
      frCodes:fr.codes.map((code)=>({code})),
      frCodesSaved:fr.codesSaved,
      onFrCodesSaved:(ev)=>this.setFr({codesSaved:ev.target.checked}),
      frSkipShow:step===3&&(enrol==='qr'||enrol==='error'||enrol==='loading'),
      frSkip:()=>this.frSkipEnrol(),
      frNames:fr.names.map((value,i)=>({value,placeholder:i===0?'e.g. my-website':'another project (optional)',aria:'project name '+(i+1),onChange:(ev)=>{ const v=ev.target.value; this.setState(st=>{ const names=[...st.fr.names]; names[i]=v; return {fr:{...st.fr,names}}; }); }})),
      frErr:frErrField||fe._||'',
      frCanBack:step===2&&!fr.busy,
      frBack:()=>this.frBack(),
      frNext:()=>this.frNext(),
      frNextLabel,
      frNextDisabled,
      // ── Header
      toggleVaultLock:()=>this.lockVault(),
      vaultMenuOpen:s.vaultMenu,
      toggleVaultMenu:()=>this.setState(st=>({vaultMenu:!st.vaultMenu,searchOpen:false})),
      vaultMenuItems:[
        {label:'Lock vault',kbd:'⌘L',go:()=>{ this.setState({vaultMenu:false}); this.lockVault(); }},
        {label:'Orphaned',kbd:'',go:()=>{this.select('__orphan');this.setState({vaultMenu:false});}},
        {label:'Pending writes'+(pendN?' · '+pendN:''),kbd:'',go:()=>this.openPending()}, // re-reads the tray, as the header chip and the banner do
        ...(isPro?[{label:'Operations',kbd:'⌘⇧O',go:()=>this.setState({overlay:'ops',vaultMenu:false})}]:[]),
        {label:'Games — CredPong',kbd:'',go:()=>this.setState({overlay:'games',gameScreen:'menu',vaultMenu:false})},
        {label:'Help',kbd:'',go:()=>this.setState({dialog:'help',vaultMenu:false})},
        {label:'About CredMgr',kbd:'',go:()=>this.setState({dialog:'about',vaultMenu:false})}
      ],
      openSettings:()=>{ this.setState({overlay:'settings',vaultMenu:false}); if(this.state.setSection==='audit')this.loadAudit(); }, // Settings reopens on the last section; the audit list is dropped on lock, so read it again
      openHelp:()=>this.setState({dialog:'help',vaultMenu:false}),
      scrimShow:(s.railOpen||s.inspOpen)?'show':'',
      toggleRailOpen:()=>this.setState(st=>({railOpen:!st.railOpen})),
      closeSheets:set({railOpen:false,inspOpen:false}),
      contrastAttr:s.contrastMode==='high'?'high':'standard',
      reducedMotionAttr:s.motion==='reduced'?'true':'false',
      logoDotStyle:s.motion==='reduced'?'animation:none':('animation:logoPulse 3.4s ease-in-out infinite'+(s.hwAccel!==false?';will-change:opacity':'')),
      lockGlyphStyle:s.motion==='reduced'?'display:inline-block':('display:inline-block;animation:lockPulse 2.4s ease-in-out infinite'+(s.hwAccel!==false?';will-change:opacity':'')),
    };
  },
};
