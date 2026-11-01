import React from "react";
import { DCLogic } from "../../dc/runtime";
import { createModel, session as sessionActions } from "../../vault/index";
import { noticeMethods } from "./notice.js";
import { sessionMethods, freshFirstRun, LOCK_PHRASE } from "./session.js";
import { mainMethods } from "./main.js";
import { inspectorMethods } from "./inspector.js";
import { fieldsMethods } from "./fields.js";
import { searchMethods } from "./search.js";
import { writeMethods } from "./write.js";
import { settingsMethods } from "./settings.js";
import { gamesMethods } from "./games.js";
import { graphMethods } from "./graph.js";
import { extrasMethods } from "./extras.js";
import { gatesMethods } from "./gates.js";
import { helpMethods } from "./help.js";

/* The design's logic class, split into mixins (one file per screen area) so the wiring lanes edit disjoint files.
   This file keeps the constructor, the initial state, the lifecycle and renderVals().  See design-upstream/PROVENANCE.md. */
class Component extends DCLogic {
  constructor(props){
    super(props);
    // Callback ref: the boot, lock and first-run screens replace the whole app, so the graph's container is a fresh empty <div> every time the app comes back, and the FIRST time is long after componentDidMount (boot -> unlock). initGraph() creates the canvas if there is none, or re-attaches the existing one (with its listeners) the moment that container mounts.
    this.graphRef=(el)=>{ this.graphRef.current=el; if(el&&this._mounted&&(!this.gcv||!el.contains(this.gcv)))this.initGraph(); };
    this.graphRef.current=null;
    this.cpRef = React.createRef();
    // All vault data comes from the model (src/vault/): `this.vault` is its current view, replaced wholesale whenever the
    // model refreshes, so never keep a reference to it across an await.  Nothing in the logic reads any other data source.
    this.model=createModel((kind,text)=>this.notify(kind,text)); // the one way the model speaks to the user
    Object.defineProperty(this,'vault',{get:()=>this.model.view,enumerable:false});
    this._unsubModel=this.model.subscribe(()=>this.onModelChange());
  }
  state={
    screen:'boot', lockStep:LOCK_PHRASE, twofa:'', view:'graph', selected:'global', openEntry:null, notice:null, fieldErrors:{},
    passInput:'', recoverPass:'', recoverCode:'', lockNote:'', lockRetryAt:0, lockBusy:false, lockWait:false,
    railOpen:false, inspOpen:false, aboutTab:'main',
    mode:null, theme:null, colour:null, hue:198, intensity:32, greyscale:null,
    vaultLocked:false /* never true once wired: a locked vault is the Lock screen. Kept until the screens that still read it drop their locked variants */, searchQ:'', searchOpen:false, vaultMenu:false,
    hover:null, ctx:null, dialog:null, overlay:null, setSection:'security',
    reveals:{}, copied:{}, tick:0,
    addNode:'global', addName:'', addMode:'single', singleFields:[{label:'',value:''}], bulkText:'', splitSegs:false, typeOverrides:{}, entryTypeOverride:null, preview:null,
    fieldMenu:null, fieldForm:null,
    undo:null, undoDone:null, tf:null, tfUntil:0, tfNow:0, aprOpen:false, aprReq:'', aprPass:'', aprCode:'', aprResult:'', aprErr:'', aprBusy:false, aprWaiting:[],
    sealTarget:null, sealTyped:'',
    grant:{from:'global',to:'',caps:{list:true,read:true,reveal:false,notes:false},expiry:'30',reason:'',code:''},
    newNodeName:'', newNodeParent:'global',
    touch:null, touchCode:'',
    renamingNode:null, renameVal:'', recentNodes:[],
    fr:freshFirstRun(), gateFlow:null,
    newNodeFolders:[''],
    grants:null, donateChainIdx:0, donateCopied:false, donateCopyFailed:false,
    entriesMode:'all', gameScreen:'library', gameId:'credpong', gameOpts:{}, gameLast:null, cpMode:'bottom',
    autoLockMins:15, revealWindowSecs:20, contrastMode:'standard', motion:'system', hwAccel:true, captureProtection:true,
    addNodeAdv:{subShare:true, twofa:true, childRead:false, agentAccess:'read-write', pn:false},
    pendingBanner:false, pendingNote:'', cosm:{mark:'keep',glyph:'classic',halo:false,ring:false,shape:'circle',global:'bone',link:'default',dots:'spectrum',backdrop:'plain',badge:'none',icon:'keep',flourish:'off',trail:'standard'},
    pack:null, flourishOn:false, donateToastOpen:false, donateView:'main', donateCode:'', donateCodeErr:false, donateCodeOk:false, donateNoCrypto:false, donateMs:null
  };
  eff(){ const s=this.state,p=this.props; return {
    mode: s.mode ?? p.mode ?? 'pro',
    theme: s.theme ?? p.theme ?? 'dark',
    colour: s.colour ?? (p.colourOn?'on':'off'),
    greyscale: s.greyscale ?? p.greyscale ?? false,
    hue: s.hue ?? p.hue ?? 198, intensity: s.intensity ?? p.intensity ?? 32 };
  }
  node(id){return this.model.node(id);}
  children(id){return this.model.children(id);}
  /** The model published a new view or status: bring everything derived from it back in step. */
  onModelChange(){
    this.pal=null;
    const st=this.state, patch={};
    if(this.vault.nodes.length){
      if(!this._posLoaded){ this._posLoaded=true; this.loadPositions(); } // saved positions can only be matched once the node list is known
      const ok=(id)=>!!this.node(id);
      if(st.selected!=='__orphan'&&!ok(st.selected)) patch.selected=ok('global')?'global':this.vault.nodes[0].id;
      if(!ok(st.addNode)) patch.addNode=ok('global')?'global':this.vault.nodes[0].id;
      const g=st.grant;
      if(!ok(g.from)||!ok(g.to)){ const ids=this.vault.nodes.map(n=>n.id); const from=ok(g.from)?g.from:ids[0]; const to=ok(g.to)&&g.to!==from?g.to:(ids.find(i=>i!==from)||from); patch.grant={...g,from,to}; }
    }
    if(Object.keys(patch).length) this.state={...this.state,...patch};
    if(!this._mounted)return; // the graph, its animation loop and the host exist only once the component is on screen
    // The model announced the end of the login (the 30 s check found the broker locked, the shell locked it, a rejected call said so):
    // forget and show the Lock screen.  The reason, when known, was left in _lockNote; the user's own lock leaves ''.
    const ms=this.model.status, scr=this.state.screen;
    if(ms==='locked'&&(scr==='app'||scr==='firstrun')){ const note=this._lockNote!=null?this._lockNote:sessionActions.lockNoteFor('locked'); this._lockNote=null; this.showLock(note); }
    else if(ms==='broker-down'&&(scr==='app'||scr==='firstrun'||scr==='lock')){ this.showBrokerDown(); }
    if(this.gcv) this.refreshGraph(); else this.buildEntryNodes();
    this.forceUpdate();
  }
  componentDidMount(){
    this._mounted=true;
    if(import.meta.env.MODE==='test')window.__cm=this; // test builds only: the design's audit scripts drive state through it; compiled out of release builds (ADR-075)
    this.loadPositions();
    try{ if(localStorage.getItem('credmgr_keys')==='off')this.state.singleKeys=false; }catch(e){} // WCAG 2.1.4: single-key shortcuts can be turned off in Settings → Appearance
    this.loadCosmetics();
    this.loadExtras();
    if(window.matchMedia&&this.state.theme==null&&this.props.theme==null&&window.matchMedia('(prefers-color-scheme: light)').matches){ this.state.theme='light'; } // C-3: OS preference detected once; an explicit Settings choice always overrides it afterward
    this.applyTheme();
    this.initGraph();
    this.buildEntryNodes(this.state.selected);
    this.startLoop();
    // Hidden window: wipe every revealed value, and lock when auto-lock is on.  (The clipboard is NOT cleared here: clearing on an app
    // switch would make pasting into the app you copied for impossible; the shell clears it after 30 s and on lock.)  Back in view:
    // ask the broker whether the login survived.
    this._visH=()=>{
      if(document.hidden){
        this.model.wipeSecrets(); if(Object.keys(this.state.reveals).length)this.setState({reveals:{}});
        if(this.state.autoLockMins>0&&this.state.screen==='app')this.lockVault('Locked because the window was hidden.');
      } else { this.startLoop(); this.checkLiveness(); this.forceUpdate(); } // (the render also asks again for the open entry's unmasked values the hiding wiped)
    };
    document.addEventListener('visibilitychange',this._visH);
    this._focusH=()=>this.checkLiveness();
    window.addEventListener('focus',this._focusH);
    this.startLiveness();
    this.startShellListener();
    this.armAutoLock();
    let lastArm=0;
    this._activityH=()=>{ const now=Date.now(); if(now-lastArm<1000)return; lastArm=now; this.armAutoLock(); }; // B8-2: throttled — was re-arming on every single mousemove
    ['mousemove','keydown','mousedown','touchstart'].forEach(ev=>window.addEventListener(ev,this._activityH,{passive:true}));
    this._outsideH=(ev)=>{ // B3-3: click outside the vault menu / search dropdown / context menu closes it
      const t=ev.target;
      if(this.state.vaultMenu&&!t.closest('.cm-vaultmenu,.cm-vaultmenu-btn'))this.setState({vaultMenu:false});
      if(this.state.searchOpen&&!t.closest('.cm-searchdrop,.cm-searchinput'))this.setState({searchOpen:false});
      if(this.state.ctx&&!t.closest('.cm-ctxmenu'))this.setState({ctx:null});
      if(this.state.fieldMenu&&!t.closest('.cm-fieldmenu,.cm-fieldmenu-btn'))this.setState({fieldMenu:null});
    };
    document.addEventListener('pointerdown',this._outsideH);
    this._focusYieldH=(e)=>{ // 2.4.11: the reminder toast steps aside when focus lands under it
      const tt=document.querySelector('[data-donate-toast]'),el=e.target; if(!tt||!el||!el.getBoundingClientRect||tt.contains(el))return;
      const hit=(box)=>{const a=el.getBoundingClientRect(),b=box;return a.width&&a.left<b.right&&a.right>b.left&&a.top<b.bottom&&a.bottom>b.top;};
      const w=tt.offsetWidth,h=tt.offsetHeight,H=window.innerHeight,W=window.innerWidth;
      const R={left:W-20-w,right:W-20,top:H-20-h,bottom:H-20},L={left:20,right:20+w,top:H-20-h,bottom:H-20};
      if(hit(R)&&!hit(L)){tt.style.right='auto';tt.style.left='20px';} else {tt.style.left='auto';tt.style.right='20px';}
    };
    document.addEventListener('focusin',this._focusYieldH);
    this._fitH=()=>{ if(this.gSize)this.gSize(); this.renderGraph(); };
    window.addEventListener('load',this._fitH);
    if(document.readyState==='complete')Promise.resolve().then(this._fitH);
    if(document.fonts&&document.fonts.ready)document.fonts.ready.then(this._fitH);
    this.keyH=(e)=>{
      // Cmd/Ctrl-L locks from anywhere: while typing, with a dialog open, in the game.  A lock key that waits for focus to leave a field is no lock key.
      if((e.metaKey||e.ctrlKey)&&!e.shiftKey&&!e.altKey&&(e.key||'').toLowerCase()==='l'){ e.preventDefault(); if(this.model.status==='unlocked'&&(this.state.screen==='app'||this.state.screen==='firstrun'))this.lockVault(); return; }
      const tag=(e.target.tagName||'').toLowerCase(); const typing=tag==='input'||tag==='textarea'||tag==='select';
      if(this.state.overlay==='games'){ // C-5: Escape pauses first, exits on a second press; P also toggles pause
        const run=this.gameRun();
        if(e.key==='Escape'){ if(this.state.gameScreen==='play'&&run){ if(run.paused)this.cpExit(); else run.paused=true; } else this.cpExit(); }
        else if((e.key==='p'||e.key==='P')&&this.state.gameScreen==='play'&&run){ run.paused=!run.paused; }
        return; }
      if(e.key==='Escape'&&this.state.fieldMenu&&!this.state.dialog&&!this.state.overlay){ // a menu closes on its own Escape, and focus returns to the button that opened it
        const btn=document.querySelector('.cm-fieldmenu-btn[aria-expanded="true"]'); this.setState({fieldMenu:null}); if(btn)setTimeout(()=>{ if(btn.isConnected)btn.focus(); },0); return; }
      if(e.key==='Escape'){this.setState({searchOpen:false,vaultMenu:false,ctx:null,fieldMenu:null,dialog:null,overlay:null,hover:null,railOpen:false,inspOpen:false});return;}
      if(this.state.fieldMenu&&!this.state.dialog&&(e.key==='ArrowDown'||e.key==='ArrowUp'||e.key==='Home'||e.key==='End')){ // the field menu is a menu: the arrow keys walk its enabled items, Home / End jump to the first / last
        const items=[...document.querySelectorAll('.cm-fieldmenu button:not([disabled])')];
        if(items.length){ e.preventDefault(); const i=items.indexOf(document.activeElement); items[e.key==='Home'?0:e.key==='End'?items.length-1:e.key==='ArrowDown'?(i+1)%items.length:(i<=0?items.length-1:i-1)].focus(); }
        return; }
      if(e.key==='Tab'&&(this.state.dialog||this.state.overlay)){this.trapTab(e);return;} // B5-2: keep Tab cycling inside the open modal
      if(typing)return;
      if(this.state.dialog||this.state.overlay)return; // B3-1: block bare shortcuts while a dialog/overlay is open — only Escape (above) is live
      const bare=!e.metaKey&&!e.ctrlKey&&!e.altKey&&this.state.singleKeys!==false; // WCAG 2.1.4: single-key shortcuts can be turned off (Settings → Appearance, both modes)
      if(bare&&e.key==='/'){e.preventDefault();const el=document.querySelector('input[placeholder^="search"]');if(el)el.focus();}
      if(bare&&(e.key==='f'||e.key==='F')){this.zoomToFitG();}
      if(bare&&(e.key==='g'||e.key==='G')){this.select('global');}
      if(bare&&(e.key==='t'||e.key==='T')){this.setState(st=>({view:st.view==='graph'?'tree':'graph'}));}
      if(bare&&(e.key==='n'||e.key==='N')){const n=this.node(this.state.selected); this.openAddDlg(n?n.id:'global');}
      if(bare&&(e.key==='e'||e.key==='E')){this.setState(st=>({entriesMode:st.entriesMode==='all'?'selected':'all'}),()=>{this.buildEntryNodes();this.renderGraph();});}
      if((e.metaKey||e.ctrlKey)&&e.shiftKey&&e.key.toLowerCase()==='o'){e.preventDefault();if(this.eff().mode==='pro')this.setState({overlay:'ops'});}
    };
    window.addEventListener('keydown',this.keyH);
    this.timer=setInterval(()=>{ const s=this.state;
      this.model.sweepSecrets(); // expired reveals leave the model's secret store the moment they expire, not when the screen next repaints
      const hasReveal=Object.keys(s.reveals).length>0, hasCopy=Object.keys(s.copied).length>0;
      if(hasReveal||hasCopy){ this.setState(st=>{
        const now=Date.now(); const rv={...st.reveals}, cp={...st.copied};
        for(const k in rv) if(rv[k]<now)delete rv[k];
        for(const k in cp) if(cp[k]<now)delete cp[k];
        return {reveals:rv,copied:cp,tick:st.tick+1};
      }); }
    },250);
    this.bootModel();
  }
  componentWillUnmount(){
    this._mounted=false;
    if(this._unsubModel)this._unsubModel();
    if(this._unsubAdmin)this._unsubAdmin();
    window.removeEventListener('keydown',this.keyH);
    document.removeEventListener('pointerdown',this._outsideH);document.removeEventListener('focusin',this._focusYieldH);
    document.removeEventListener('visibilitychange',this._visH);
    window.removeEventListener('focus',this._focusH);
    this.stopSessionWatchers();
    window.removeEventListener('load',this._fitH);
    ['mousemove','keydown','mousedown','touchstart'].forEach(ev=>window.removeEventListener(ev,this._activityH));
    this.cpStopListeners();this.ghStop();clearInterval(this.timer);clearTimeout(this._donateTimer);clearTimeout(this._optT);clearTimeout(this._okT);clearTimeout(this._flT);clearTimeout(this._cpvT);clearTimeout(this._autoLockT);clearTimeout(this._clipT);clearInterval(this._aprT);clearInterval(this._tfI);clearTimeout(this._pnT);
    if(this._raf)cancelAnimationFrame(this._raf);if(this.ro)this.ro.disconnect();
  }
  componentDidUpdate(prevProps,prevState){
    if(document.querySelector('[data-cosm-preview]')){ this.drawCosmPreview(); clearTimeout(this._cpvT); this._cpvT=setTimeout(()=>this.drawCosmPreview(),80); }
    const e=this.eff();
    const ce=this.cosmEff(); const sig=[e.theme,e.colour,e.hue,e.intensity,ce.dots,ce.shape,ce.global,ce.link,ce.backdrop,ce.trail].join('|');
    if(sig!==this._sig){ this._sig=sig; this.applyTheme(); this.pal=null; if(this.entryNodes)for(const en of this.entryNodes)en.color=this.entryColor(en.id); if(this.gcv)this.renderGraph(); }
    const inGames=this.state.overlay==='games'; if(inGames&&!this._wasGames&&Object.keys(this.state.reveals||{}).length)this.setState({reveals:{}}); this._wasGames=inGames; // threat model T7: no revealed value stays in the DOM while game code runs
    const wasOpen=!!(prevState&&(prevState.dialog||prevState.overlay)), isOpen=!!(this.state.dialog||this.state.overlay); // B5-2: focus in on open, restore on close
    if(!wasOpen&&isOpen){ this._preFocusEl=document.activeElement; setTimeout(()=>this.focusModalFirst(),30); }
    else if(wasOpen&&!isOpen){ const el=this._preFocusEl; this._preFocusEl=null; if(el&&document.contains(el)&&el.focus)el.focus(); }
  }
  focusModalFirst(){ const panel=document.querySelector('.cm-modal-panel'); if(!panel)return; const f=panel.querySelector('input,button,select,textarea,[tabindex]'); if(f)f.focus(); }
  trapTab(e){
    const panel=document.querySelector('.cm-modal-panel'); if(!panel)return;
    const f=[...panel.querySelectorAll('input,button,select,textarea,a[href],[tabindex]')].filter(el=>!el.disabled&&el.offsetParent!==null);
    if(!f.length)return; const first=f[0],last=f[f.length-1];
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
  }
  applyTheme(){
    const e=this.eff(); const de=document.documentElement;
    de.dataset.theme=e.theme;
    /* THEMING.md's lightness anchors. keep.css's light --void now matches them (#FCFCFD, synced
       from the upstream fix 2026-10-01), so no per-theme void override is needed below. */
    const anchors=e.theme==='dark'?{void:0.0,night:0.055,steel:0.115,'steel-2':0.16,'steel-3':0.21,faint:0.27}:{void:0.99,night:0.98,steel:0.95,'steel-2':0.93,'steel-3':0.9,faint:0.85};
    if(e.colour==='on'||e.colour==='auto'){ const H=e.colour==='auto'?211:e.hue, C=(0.012*(e.intensity/100)).toFixed(4);
      for(const k in anchors) de.style.setProperty('--'+k,`oklch(${anchors[k]} ${C} ${H})`);
    } else { for(const k in anchors) de.style.removeProperty('--'+k); }
  }
  /* renderVals(): the flat object the compiled template renders against.  Built in two steps so the areas stay independent:
     rvBase() computes the locals more than one area needs; each rvX(c) then computes its own locals and returns its keys.
     Every key of the template has exactly one home; scripts/dc/compile.mjs --check reports bindings with no key. */
  rvBase(){
    const s=this.state, e=this.eff(), v=this.vault;
    const sel=s.selected==='__orphan'?null:this.node(s.selected);
    const isPro=e.mode==='pro', isLite=!isPro;
    const set=(o)=>()=>this.setState(o);
    const now=Date.now();
    // grant dialog
    const g=s.grant;
    const gErrs=!g.reason.trim()||g.code.length!==6||g.from===g.to;
    const nodeOpts=v.nodes.map(n=>({id:n.id,label:n.label}));
    const btn=(on)=>on?['var(--bone)','var(--night)']:['transparent','var(--bone)'];
    this._cosmFx=this.cosmEff();
    const cosm=this._cosmFx;
    const pend=v.pending||[], pendN=pend.length;
    return {s, e, v, sel, isPro, isLite, set, now, g, gErrs, nodeOpts, btn, cosm, pend, pendN};
  }
  rvCommon(c){
    const {isPro, set} = c;
    return {
      stop:(ev)=>ev.stopPropagation(),
      closeDialog:set({dialog:null,aboutTab:'main'}),
      scrimClose:set({dialog:null,overlay:null,aboutTab:'main'}),
      closeOverlay:set({overlay:null}),
      isPro,
    };
  }
  renderVals(){
    const c=this.rvBase();
    return {
      ...this.rvCommon(c),
      ...this.rvSession(c),
      ...this.rvNotice(c),
      ...this.rvMain(c),
      ...this.rvInspector(c),
      ...this.rvFields(c),
      ...this.rvSearch(c),
      ...this.rvWrite(c),
      ...this.rvSettings(c),
      ...this.rvGames(c),
      ...this.rvExtras(c),
      ...this.rvGates(c),
      ...this.rvHelp(c),
    };
  }
}

Object.assign(Component.prototype, noticeMethods, sessionMethods, mainMethods, inspectorMethods, fieldsMethods, searchMethods, writeMethods, settingsMethods, gamesMethods, graphMethods, extrasMethods, gatesMethods, helpMethods);

export default Component;
