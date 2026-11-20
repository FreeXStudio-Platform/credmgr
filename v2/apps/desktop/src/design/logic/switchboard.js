/* The switchboard (ADR-155): the app reads the same settings registry an agent uses, so the window and an agent never drift.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   Three jobs, all through `switchboard.*` (src/vault/actions/switchboard.ts), all only with the real broker (`model.kind === 'bridge'`):
     - After an unlock, the broker's `app.*` settings are applied to the page and to the local cache (`credmgr_prefs`): the broker
       wins.  syncSwitchboard() is called by unlockApp() (session.js).
     - A preference the person changes is also sent to the broker (settings.set), a moment later so a dragged slider is one call.
       settings.js afterUpdate() hands every changed preference to queueSwitchboardPush().  Best effort: a refusal is a notice,
       the local change still applies.
     - An agent's change that makes a setting less strict waits for the owner.  pollSettingRequests() asks on the session's liveness
       cadence (checkLiveness, session.js) and when Settings › Agents opens; a new request raises a notice once, and Settings › Agents
       lists them with Approve and Deny.  Approving asks "Confirm it is you" first: the bridge does that (confirm.js), not this file.

   What this file keeps: `sbRequests` (the waiting requests, cleaned) and `sbBusy` (the request being decided), both dropped by a lock
   (freshEphemeral, session.js).  No value of a secret passes through here: settings are not secrets. */

import { errorCode, loadPrefs, savePrefs, switchboard as sb } from "../../vault/index";

/** A dragged slider sends one change, not one per pixel. */
const PUSH_MS = 500;
const SESSION_GONE = ['vault_locked', 'session_expired'];
/** How a notice names a preference. */
const LABELS = {
  theme:'theme', colour:'colour', hue:'hue', intensity:'tint intensity', greyscale:'greyscale', contrastMode:'contrast', motion:'motion',
  hwAccel:'hardware acceleration', captureProtection:'screen-capture protection', mode:'mode', autoLockMins:'auto-lock',
  revealWindowSecs:'reveal window', backupRetain:'backup retention', entriesMode:'entries shown', view:'view',
};
const media = (q) => { try{ return !!(window.matchMedia&&window.matchMedia(q).matches); }catch(e){ return false; } };

export const switchboardMethods = {
  /** True when there is a real broker and an open vault to ask. */
  sbLive(){ return this.model.kind==='bridge'&&this.model.status==='unlocked'; },

  /**
   * Read the broker's app settings and show them, then look for agents' requests.  `fresh`: just unlocked (a request still waiting
   * is announced again).  A broker that cannot answer (an older one, a refusal) leaves the cache as it is, quietly.
   */
  async syncSwitchboard(fresh){
    if(!this.sbLive())return;
    if(fresh)this._sbSeen=new Set();
    const seq=(this._sbSyncSeq=(this._sbSyncSeq||0)+1);
    try{
      const r=await sb.readAppSettings();
      if(r&&seq===this._sbSyncSeq&&this.sbLive())this.applyBrokerPrefs(r.apply);
    }catch(e){ /* the cache stays; the next unlock asks again */ }
    await this.pollSettingRequests();
  },

  /** The page's state for a preference value (the cache stores `null` for "follow the system"; the page holds what the system says). */
  prefToState(k, v){
    if(k==='theme'&&v==null)return media('(prefers-color-scheme: light)')?'light':null;
    if(k==='contrastMode'&&v==null)return media('(prefers-contrast: more)')?'high':'standard';
    return v;
  },

  /** Show the broker's values that differ from the cache, and remember them in it.  Nothing is sent back for them. */
  applyBrokerPrefs(values){
    const cache=loadPrefs();
    const keys=Object.keys(values||{}).filter((k)=>!Object.is(values[k],cache[k]));
    if(!keys.length)return;
    const state={}, store={};
    for(const k of keys){ store[k]=values[k]; state[k]=this.prefToState(k,values[k]); }
    this._sbEcho=state; // afterUpdate sees these as changes: they came from the broker, so they are not sent back to it
    this.setState(state,()=>{
      this._sbEcho=null;
      savePrefs(store); // after afterUpdate's own save, so the cache holds the broker's value (`null`, not what the system said)
      if('autoLockMins' in store)this.armAutoLock();
      if('captureProtection' in store)this.applyCaptureProtection(store.captureProtection!==false);
    });
  },

  /** A preference changed on the page (settings.js afterUpdate): send it to the broker shortly, unless the broker is where it came from. */
  queueSwitchboardPush(patch){
    if(!this.sbLive())return;
    const echo=this._sbEcho||{}, out=this._sbOut||(this._sbOut={});
    let any=false;
    for(const k of Object.keys(patch)){
      if(k in echo&&Object.is(echo[k],patch[k]))continue;
      out[k]=patch[k]; any=true;
    }
    if(!any)return;
    clearTimeout(this._sbT);
    this._sbT=setTimeout(()=>this.flushSwitchboardPush(),PUSH_MS);
  },
  async flushSwitchboardPush(){
    clearTimeout(this._sbT);
    const out=this._sbOut||{}; this._sbOut={};
    if(!this.sbLive())return;
    const failed=[];
    for(const k of Object.keys(out)){
      try{ await sb.pushAppSetting(k,out[k]); }
      catch(e){ if(SESSION_GONE.includes(errorCode(e)))return; failed.push(LABELS[k]||k); }
    }
    if(failed.length)this.notify('warn','Changed on this Mac, but the vault did not record the '+failed.join(', ')+' setting. Agents may still see the earlier value.');
  },

  /** Ask for the requests waiting for the owner.  Quiet when the broker cannot answer; a new request is announced once. */
  async pollSettingRequests(){
    if(!this.sbLive())return;
    const seq=(this._sbPollSeq=(this._sbPollSeq||0)+1);
    let list;
    try{ list=await sb.pendingAgentRequests(); }catch(e){ return; }
    if(!list||seq!==this._sbPollSeq||!this.sbLive())return;
    const at=Date.now();
    const rows=list.map((r)=>({...r,deadline:at+r.expiresIn*1000}));
    const seen=this._sbSeen||(this._sbSeen=new Set());
    const fresh=rows.filter((r)=>!seen.has(r.request));
    rows.forEach((r)=>seen.add(r.request));
    this.setState({sbRequests:rows});
    // Settings › Agents already lists them: no notice there, where it would only cover the list it points to.
    if(this.viewingAgentRequests())return;
    if(fresh.length===1)this.notify('info','An agent asks to change '+fresh[0].id+' from '+fresh[0].from+' to '+fresh[0].to+'. Approve or deny it in Settings, under Agents.');
    else if(fresh.length>1)this.notify('info',fresh.length+' agent requests to change a setting are waiting. Approve or deny them in Settings, under Agents.');
  },

  /** True while Settings is open on Agents, where the requests are listed. */
  viewingAgentRequests(){ return this.state.overlay==='settings'&&this.state.setSection==='agents'; },

  /** The notice announcing requests has done its job once the list is on screen: clear it so it never covers the list. */
  clearRequestNotice(){
    const n=this.state.notice;
    if(n&&n.kind==='info'&&/agent (asks|requests) to change/.test(n.text)){ clearTimeout(this._noticeT); this.setState({notice:null}); }
  },

  /** Approve or deny one request, then read the settings and the requests again, so an approved change shows at once. */
  async decideSettingRequest(request, approve){
    if(this.state.sbBusy||!this.sbLive())return;
    this.setState({sbBusy:request});
    try{
      const r=await sb.decideAgentRequest(request,approve);
      this.notify('success',approve?(r.applied?'Approved. The setting is changed.':'Approved.'):'Denied. Nothing was changed.');
    }catch(e){ this.routeError(e,{op:'settings.request_decide'}); }
    finally{ this.setState({sbBusy:null}); }
    await this.syncSwitchboard(false);
  },

  rvSwitchboard(c){
    const {s, now} = c;
    const busy=s.sbBusy||null;
    const rows=(s.sbRequests||[]).filter((r)=>r.deadline>now);
    return {
      sbReqShow:rows.length>0&&this.model.status==='unlocked',
      sbReqRows:rows.map((r)=>({
        request:r.request, id:r.id, change:'from '+r.from+' to '+r.to,
        hasNode:!!r.node, node:r.node||'',
        reason:r.reason||'no reason given',
        hasCwd:!!r.cwd, cwd:r.cwd||'',
        hasToken:!!r.agentToken, token:r.agentToken||'',
        left:Math.max(0,Math.ceil((r.deadline-now)/1000))+' s left',
        disabled:!!busy,
        approveLabel:busy===r.request?'Working…':'Approve',
        approveAria:'approve the request to change '+r.id,
        denyAria:'deny the request to change '+r.id,
        approve:()=>this.decideSettingRequest(r.request,true),
        deny:()=>this.decideSettingRequest(r.request,false),
      })),
    };
  },
};
