import React from "react";
import { DCLogic } from "../../dc/runtime";

class Component extends DCLogic {
  constructor(props){
    super(props);
    // Callback ref: the lock and first-run screens unmount the whole app, so the graph's container is a fresh empty <div> every time it comes back. This re-attaches the existing canvas (with its listeners) the moment that container mounts.
    this.graphRef=(el)=>{ this.graphRef.current=el; if(el&&this.gcv&&!el.contains(this.gcv))this.initGraph(); };
    this.graphRef.current=null;
    this.cpRef = React.createRef();
    const mk=(n,i)=>({id:n.toLowerCase().replace(/[^a-z0-9]/g,'-')+'-'+i,name:n,type:'api',sensitivity:'medium',totp:false,fields:[{label:'token',value:'example_'+Math.random().toString(36).slice(2,12),type:'api-key',masked:true}],meta:'api · medium'});
    const pool=(names,count,pfx)=>{const out=[];let i=0;while(out.length<count){const base=names[i%names.length];const suf=i>=names.length?(i>=names.length*2?'-old':'-staging'):'';out.push(mk(base+suf,pfx+'-'+i));i++;}return out;};
    const linuxEntries=[
      {id:'lx-1',name:'vps-root',type:'server',sensitivity:'critical',totp:true,meta:'server · critical · rotated 2026-06-30',fields:[
        {label:'host',value:'203.0.113.4',type:'host',masked:false},
        {label:'port',value:'22',type:'port',masked:false},
        {label:'username',value:'root',type:'username',masked:false},
        {label:'password',value:'example-Pa55-vps', type:'password',masked:true},
        {label:'2fa seed',value:'JBSWY3DPEHPK3PXP',type:'totp-seed',masked:true}]},
      {id:'lx-2',name:'deploy-key',type:'ssh',sensitivity:'critical',totp:false,meta:'ssh · critical',fields:[
        {label:'username',value:'deploy',type:'username',masked:false},
        {label:'private key',value:'-----BEGIN EXAMPLE KEY-----\nEXAMPLE-ONLY-this-is-not-a-key-000000000000\n-----END EXAMPLE KEY-----',type:'private-key',masked:true},
        {label:'passphrase',value:'correct horse battery staple',type:'password',masked:true}]},
      {id:'lx-3',name:'grafana-admin',type:'login',sensitivity:'high',totp:true,meta:'login · high',fields:[{label:'url',value:'https://grafana.example.internal:3000',type:'url',masked:false},{label:'username',value:'admin',type:'username',masked:false},{label:'password',value:'example-Pa55-grafana',type:'password',masked:true},{label:'2fa seed',value:'KRSXG5CTMVRXEZLU',type:'totp-seed',masked:true}]},
      {id:'lx-4',name:'backup-b2',type:'api',sensitivity:'high',totp:true,meta:'api · high',fields:[{label:'keyID',value:'EXAMPLE-key-id-0001',type:'api-key',masked:false},{label:'applicationKey',value:'EXAMPLE-application-key',type:'api-key',masked:true},{label:'bucket',value:'vault-backups-eu',type:'text',masked:false}]},
      {id:'lx-5',name:'pg-primary',type:'server',sensitivity:'critical',totp:false,meta:'server · critical',fields:[{label:'host',value:'10.0.0.4',type:'host',masked:false},{label:'port',value:'5432',type:'port',masked:false},{label:'username',value:'svc_app',type:'username',masked:false},{label:'password',value:'example-Pa55-pg',type:'password',masked:true}]},
      {id:'lx-6',name:'registry-token',type:'api',sensitivity:'medium',totp:false,meta:'api · medium',fields:[{label:'token',value:'reg_EXAMPLE0001',type:'api-key',masked:true}]},
      {id:'lx-7',name:'wireguard-peer',type:'other',sensitivity:'high',totp:false,meta:'other · high',fields:[{label:'private key',value:'EXAMPLE…wg-key…=',type:'private-key',masked:true},{label:'endpoint',value:'vpn.internal:51820',type:'text',masked:false}]},
      {id:'lx-8',name:'tailscale-auth',type:'api',sensitivity:'medium',totp:false,meta:'api · medium',fields:[{label:'authkey',value:'EXAMPLE-authkey…',type:'api-key',masked:true}]},
      {id:'lx-9',name:'smtp-relay',type:'login',sensitivity:'medium',totp:false,meta:'login · medium',fields:[{label:'host',value:'smtp.example.net',type:'host',masked:false},{label:'username',value:'postmaster@example.com',type:'username',masked:false},{label:'password',value:'example-Pa55-smtp',type:'password',masked:true}]},
      {id:'lx-10',name:'cf-tunnel',type:'api',sensitivity:'medium',totp:false,meta:'api · medium',fields:[{label:'tunnel token',value:'EXAMPLE-tunnel-token…',type:'api-key',masked:true}]},
      {id:'lx-11',name:'monit-webhook',type:'api',sensitivity:'low',totp:false,meta:'api · low',fields:[{label:'url',value:'https://hooks.example.internal/monit',type:'url',masked:false}]},
      {id:'lx-12',name:'fail2ban-alerts',type:'login',sensitivity:'low',totp:false,meta:'login · low',fields:[{label:'email',value:'alerts@internal',type:'username',masked:false},{label:'password',value:'example-Pa55-f2b',type:'password',masked:true}]}
    ];
    this.vault={
      nodes:[
        {id:'global',label:'global',kind:'global',depth:0,parentId:null,counts:{entries:12,totp:3},gate:{locked:false,twofa:'enrolled'},health:null,notes:'Shared, deliberately small. Anything here is readable by every node — keep it to true globals: the licence server, the shared registry mirror.'},
        {id:'atlas',label:'atlas',kind:'project',depth:1,parentId:'global',counts:{entries:41,totp:6},gate:{locked:false,twofa:'required'},health:null,notes:'Stripe rotates on the 1st. The webhook secret pairs with stripe-live — rotate together.'},
        {id:'beacon',label:'beacon',kind:'project',depth:1,parentId:'global',counts:{entries:38,totp:2},gate:{locked:false,twofa:'none'},health:null,notes:''},
        {id:'cobalt',label:'cobalt',kind:'project',depth:1,parentId:'global',counts:{entries:22,totp:0},gate:{locked:true,twofa:'none'},health:null,notes:'Node locked on its own — vault stays open, this stays shut.'},
        {id:'linux',label:'linux',kind:'project',depth:1,parentId:'global',counts:{entries:12,totp:3},gate:{locked:false,twofa:'required'},health:null,notes:'vps-root rotates quarterly; the rotation script lives in ~/ops/rotate.sh. prod deploys only from the deploy-key, never vps-root.'},
        {id:'dev',label:'dev',kind:'sub',depth:2,parentId:'linux',counts:{entries:4,totp:0},gate:{locked:false,twofa:'none'},health:null,notes:''},
        {id:'staging',label:'staging',kind:'sub',depth:2,parentId:'linux',counts:{entries:3,totp:0},gate:{locked:false,twofa:'none'},health:null,notes:''},
        {id:'prod',label:'prod',kind:'sub',depth:2,parentId:'linux',counts:{entries:5,totp:2},gate:{locked:false,twofa:'required'},health:null,notes:'Siblings share (dev/staging/prod are interconnected). prod additionally gates reveals behind 2FA.'}
      ],
      links:[
        {source:'global',target:'atlas',kind:'structural'},{source:'global',target:'beacon',kind:'structural'},
        {source:'global',target:'cobalt',kind:'structural'},{source:'global',target:'linux',kind:'structural'},
        {source:'linux',target:'dev',kind:'structural'},{source:'linux',target:'staging',kind:'structural'},{source:'linux',target:'prod',kind:'structural'},
        {source:'linux',target:'beacon',kind:'grant'}
      ],
      grants:[{from:'linux',to:'beacon',scope:'list · read',expires:'2026-08-30',lastUsed:'2026-08-06',reason:"linux's deploy job needs beacon's registry token"}],
      entries:{
        linux:linuxEntries,
        global:pool(['licence-server','registry-mirror','gh-pat-readonly','anthropic-api','openai-api','ntfy-topic','dns-porkbun','domain-registrar'],12,'gl'),
        atlas:pool(['stripe-live','stripe-webhook','gh-deploy','sentry-dsn','pg-analytics','redis-cache','s3-artifacts','mailgun-api','twilio-sid','dockerhub','npm-token','cf-api','posthog','algolia','crisp-chat'],41,'ah'),
        beacon:pool(['pg-main','redis-main','s3-media','gh-actions','vercel-token','resend-api','upstash','clerk-secret','plaid-sandbox','sentry','logtail'],38,'fn'),
        cobalt:pool(['shopify-admin','shopify-storefront','klaviyo','gorgias','ship-station','tax-jar','meta-ads','google-ads'],22,'ig'),
        dev:pool(['dev-db','dev-redis','dev-smtp','seed-user'],4,'dv'),
        staging:pool(['stg-db','stg-redis','stg-smtp'],3,'st'),
        prod:pool(['prod-db','prod-redis','prod-deploy','prod-smtp','prod-cdn'],5,'pr')
      },
      orphans:[
        {name:'vps-root-old',from:'debian',date:'2026-08-04'},{name:'deploy-key-2023',from:'debian',date:'2026-08-04'},
        {name:'grafana-legacy',from:'debian',date:'2026-08-04'},{name:'backup-s3-old',from:'debian',date:'2026-08-04'},
        {name:'pg-replica',from:'debian',date:'2026-08-04'},{name:'wg-old-peer',from:'debian',date:'2026-08-04'},
        {name:'smtp-legacy',from:'debian',date:'2026-08-04'}
      ],
      sealed:[],
      pending:[]
    };
  }
  state={
    screen:'app', lockStep:1, twofa:'', view:'graph', selected:'linux', openEntry:null,
    railOpen:false, inspOpen:false, aboutTab:'main',
    mode:null, theme:null, colour:null, hue:198, intensity:32, greyscale:null,
    vaultLocked:false, searchQ:'', searchOpen:false, vaultMenu:false,
    hover:null, ctx:null, dialog:null, overlay:null, setSection:'security', secLevel:'guarded',
    reveals:{}, copied:{}, tick:0,
    addNode:'linux', addName:'', addMode:'single', singleFields:[{label:'',value:''}], bulkText:'', splitSegs:false, typeOverrides:{}, entryTypeOverride:null,
    sealTarget:null, sealTyped:'',
    grant:{from:'linux',to:'beacon',caps:{list:true,read:true,reveal:false,notes:false},expiry:'30',reason:'',code:''},
    newNodeName:'', newNodeParent:'global',
    destroyTyped:'', destroyAt:null,
    touch:null, touchCode:'',
    renamingNode:null, renameVal:'', recentNodes:[],
    fr:{step:1,name:'main',rec:false,pass:'',passRepeat:'',totp:'',folders:[{name:'atlas',dir:'~/projects/atlas',on:true},{name:'beacon',dir:'~/projects/beacon',on:true},{name:'cobalt',dir:'~/projects/cobalt',on:false}]},
    newNodeFolders:[''],
    promptCopied:false, connected:{'Claude Code':false,'Cursor':false,'VS Code (Copilot)':false,'Claude Desktop':true},
    grants:null, contentSearchEnabled:false, donateChainIdx:0, donateToastOpen:false, donateCopied:false,
    donateView:'main', donateCode:'', donateCodeErr:false, donateCodeOk:false,
    fieldMenu:null, fd:null, opsResult:null, backupRetention:'14', backupAt:null, verifiedAt:null,
    entriesMode:'all', gameScreen:'library', gameId:'credpong', gameOpts:{}, gameLast:null, cpMode:'bottom',
    autoLockMins:15, revealWindowSecs:20, contrastMode:'standard', motion:'system', hwAccel:true,
    addNodeAdv:{subShare:true, twofa:true, childRead:false, agentAccess:'read-write'},
    pendingBanner:false, pendingNote:'', cosm:{mark:'keep',glyph:'classic',halo:false,ring:false,shape:'circle',global:'bone',link:'default',dots:'spectrum',backdrop:'plain',badge:'none',icon:'keep',flourish:'off',trail:'standard'}, flourishOn:false, pack:null, donateMs:null
  };
  eff(){ const s=this.state,p=this.props; return {
    mode: s.mode ?? p.mode ?? 'pro',
    theme: s.theme ?? p.theme ?? 'dark',
    colour: s.colour ?? (p.colourOn?'on':'off'),
    greyscale: s.greyscale ?? p.greyscale ?? false,
    hue: s.hue ?? p.hue ?? 198, intensity: s.intensity ?? p.intensity ?? 32 };
  }
  node(id){return this.vault.nodes.find(n=>n.id===id);}
  children(id){return this.vault.nodes.filter(n=>n.parentId===id);}
  clampMain(x,y,w,h){ // A2: keep menus and hover cards inside .cm-main whatever the source (canvas, rail, tree)
    const m=this.graphRef.current&&this.graphRef.current.closest('.cm-main'); const W=m?m.clientWidth:window.innerWidth, H=m?m.clientHeight:window.innerHeight;
    return {x:Math.max(8,Math.min(x,W-w-8)),y:Math.max(8,Math.min(y,H-h-8))};
  }
  ctxPosFor(clientX,clientY){ // B3-2: position the context menu relative to .cm-main, clamped inside it — not raw viewport coords + magic offsets
    const mainEl=this.graphRef.current&&this.graphRef.current.closest('.cm-main');
    const rc=mainEl?mainEl.getBoundingClientRect():{left:0,top:0,width:window.innerWidth,height:window.innerHeight};
    const menuW=190,menuH=230;
    let x=clientX-rc.left, y=clientY-rc.top;
    x=Math.max(8,Math.min(x,rc.width-menuW)); y=Math.max(8,Math.min(y,rc.height-menuH));
    return {x,y};
  }
  armAutoLock(){ clearTimeout(this._autoLockT); const m=this.state.autoLockMins; if(!m)return; this._autoLockT=setTimeout(()=>{ if(this.state.screen==='app'&&!this.state.vaultLocked)this.setState({vaultLocked:true,reveals:{}}); },m*60000); }
  devOn(){ try{ return /[?&]dev=1(&|$)/.test(location.search)||localStorage.getItem('credmgr_dev')==='1'; }catch(e){ return false; } } // dev-only switch for the audit tools; off by default
  componentDidMount(){
    this._dev=this.devOn(); if(this._dev)window.__cm=this;
    if(!document.documentElement.lang)document.documentElement.lang='en'; // WCAG 3.1.1: the generated document has no lang
    if(!document.title)document.title='CredMgr'; // WCAG 2.4.2
    try{ if(localStorage.getItem('credmgr_keys')==='off')this.setState({singleKeys:false}); }catch(e){}
    this.loadPositions();
    this.loadCosmetics();
    if(window.matchMedia&&this.state.theme==null&&this.props.theme==null&&window.matchMedia('(prefers-color-scheme: light)').matches){ this.state.theme='light'; } // C-3: OS preference detected once; an explicit Settings choice always overrides it afterward
    this.applyTheme();
    this.initGraph();
    this.buildEntryNodes(this.state.selected);
    this.startLoop();
    this._visH=()=>{ if(document.hidden)this.clearClipboard(); if(!document.hidden)this.startLoop(); else if(this.state.autoLockMins>0&&this.state.screen==='app'&&!this.state.vaultLocked)this.setState({vaultLocked:true,reveals:{}}); };
    document.addEventListener('visibilitychange',this._visH);
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
    this._focusYieldH=(e)=>{ // 2.4.11: the donate toast steps aside when focus lands under it
      const tt=document.querySelector('[data-donate-toast]'),el=e.target; if(!tt||!el||!el.getBoundingClientRect||tt.contains(el))return;
      const hit=(box)=>{const a=el.getBoundingClientRect(),b=box;return a.width&&a.left<b.right&&a.right>b.left&&a.top<b.bottom&&a.bottom>b.top;};
      const w=tt.offsetWidth,h=tt.offsetHeight,H=window.innerHeight,W=window.innerWidth;
      const R={left:W-20-w,right:W-20,top:H-20-h,bottom:H-20},L={left:20,right:20+w,top:H-20-h,bottom:H-20};
      if(hit(R)&&!hit(L)){tt.style.right='auto';tt.style.left='20px';} else {tt.style.left='auto';tt.style.right='20px';}
    };
    document.addEventListener('focusin',this._focusYieldH);
    this.loadExtras(); if(this.state.screen==='app'&&!this.state.vaultLocked)this.usageTick(); this._donateTimer=setTimeout(()=>this.maybeAsk(),6000);
    this._fitH=()=>{ if(this.gSize)this.gSize(); this.renderGraph(); };
    window.addEventListener('load',this._fitH);
    if(document.readyState==='complete')Promise.resolve().then(this._fitH);
    if(document.fonts&&document.fonts.ready)document.fonts.ready.then(this._fitH);
    this.keyH=(e)=>{
      const tag=(e.target.tagName||'').toLowerCase(); const typing=tag==='input'||tag==='textarea'||tag==='select';
      if(this.state.overlay==='games'){ // C-5: Escape pauses first, exits on a second press; P also toggles pause
        const run=this.gameRun();
        if(e.key==='Escape'){ if(this.state.gameScreen==='play'&&run){ if(run.paused)this.cpExit(); else run.paused=true; } else this.cpExit(); }
        else if((e.key==='p'||e.key==='P')&&this.state.gameScreen==='play'&&run){ run.paused=!run.paused; }
        return; }
      if(e.key==='Escape'){ // A4: close only the topmost layer — menu/search, then dialog, then overlay, then sheets
        const st=this.state;
        if(st.ctx||st.hover||st.fieldMenu)this.setState({ctx:null,hover:null,fieldMenu:null});
        else if(st.searchOpen||st.vaultMenu)this.setState({searchOpen:false,vaultMenu:false});
        else if(st.dialog)this.setState({dialog:null});
        else if(st.overlay)this.setState({overlay:null});
        else this.setState({railOpen:false,inspOpen:false});
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
      if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='l'){e.preventDefault();this.setState({vaultLocked:true,reveals:{}});}
      if((e.metaKey||e.ctrlKey)&&e.shiftKey&&e.key.toLowerCase()==='o'){e.preventDefault();if(this.eff().mode==='pro')this.setState({overlay:'ops'});}
    };
    window.addEventListener('keydown',this.keyH);
    this.timer=setInterval(()=>{ const s=this.state;
      const hasReveal=Object.keys(s.reveals).length>0, hasCopy=Object.keys(s.copied).length>0;
      if(hasReveal||hasCopy||s.destroyAt){ let destroyed=false; this.setState(st=>{
        const now=Date.now(); const rv={...st.reveals}, cp={...st.copied};
        for(const k in rv) if(rv[k]<now)delete rv[k];
        for(const k in cp) if(cp[k]<now)delete cp[k];
        let d=st.destroyAt; if(d&&d<now){ destroyed=true; d=null; return {reveals:rv,copied:cp,destroyAt:null,dialog:null,tick:st.tick+1}; }
        return {reveals:rv,copied:cp,tick:st.tick+1};
      }, ()=>{ if(destroyed)this.vault.orphans=[]; }); }
    },250);
  }
  componentWillUnmount(){
    window.removeEventListener('keydown',this.keyH);
    document.removeEventListener('pointerdown',this._outsideH);document.removeEventListener('focusin',this._focusYieldH);
    document.removeEventListener('visibilitychange',this._visH);
    window.removeEventListener('load',this._fitH);
    ['mousemove','keydown','mousedown','touchstart'].forEach(ev=>window.removeEventListener(ev,this._activityH));
    if(window.__cm===this)delete window.__cm; this.cpStopListeners();this.ghStop();clearInterval(this.timer);clearTimeout(this._donateTimer);clearTimeout(this._autoLockT);clearTimeout(this._clipT);clearTimeout(this._pnT);
    if(this._raf)cancelAnimationFrame(this._raf);if(this.ro)this.ro.disconnect();
  }
  componentDidUpdate(prevProps,prevState){
    if(document.querySelector('[data-cosm-preview]')){ this.drawCosmPreview(); clearTimeout(this._cpvT); this._cpvT=setTimeout(()=>this.drawCosmPreview(),80); }
    const e=this.eff();
    const ce=this.cosmEff(); const sig=[e.theme,e.colour,e.hue,e.intensity,ce.dots,ce.shape,ce.global,ce.link,ce.backdrop,ce.trail].join('|');
    if(sig!==this._sig){ this._sig=sig; this.applyTheme(); this.pal=null; if(this.entryNodes)for(const en of this.entryNodes)en.color=this.entryColor(en.id); if(this.gcv)this.renderGraph(); }
    const isOpen=!!(this.state.dialog||this.state.overlay), wasOpen=!!this._wasOpen; this._wasOpen=isOpen;
    const inGames=this.state.overlay==='games'; if(inGames&&!this._wasGames&&Object.keys(this.state.reveals||{}).length)this.setState({reveals:{}}); this._wasGames=inGames; // threat model T7: no revealed value stays in the DOM while game code runs // B5-2: focus in on open, restore on close. D7: open-state is tracked on the instance — a host that omits prevState made every re-render look like "just opened" and pulled focus out of the field being typed in
    if(!wasOpen&&isOpen){ const op=this._openerEl; this._openerEl=null; this._preFocusEl=(op&&op.isConnected)?op:document.activeElement; setTimeout(()=>this.focusModalFirst(),30); }
    else if(wasOpen&&!isOpen){ let el=this._preFocusEl; this._preFocusEl=null; // a field-menu opener can be re-rendered or removed with its row: fall back to the nearest ⋮ or + Add field
      if(el&&!el.isConnected&&el.classList&&el.classList.contains('cm-fieldmenu-btn'))el=document.querySelector('.cm-fieldmenu-btn')||document.querySelector('.cm-addfield-btn');
      if(el&&document.contains(el)&&el.focus)el.focus(); }
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
  palette(){
    if(this.pal)return this.pal;
    const cs=getComputedStyle(document.documentElement);
    const g=(v)=>cs.getPropertyValue(v).trim();
    const p={bone:g('--bone'),ash:g('--ash'),mute:g('--mute'),faint:g('--faint'),warn:g('--warn'),danger:g('--danger'),sig:g('--sig'),sigHi:g('--sig-hi'),hair:g('--hair'),hairS:g('--hair-strong'),void:g('--void')};
    if(!p.bone){ return {bone:'#E9ECF1',ash:'#98A0AE',mute:'#767E8C',faint:'#2A2E38',warn:'#B0812E',danger:'#B3373A',sig:'#3E9C86',hairS:'rgba(233,236,241,0.13)',void:'#000'}; }
    this.pal=p; return p;
  }
  graphData(){
    const SPREAD=1.7; // the same hand-placed composition, pushed apart so entry rings stop crowding each other (2026-09-07)
    const pos0={global:[0,0],atlas:[-118,-58],beacon:[122,-46],cobalt:[-96,84],linux:[92,92],dev:[42,172],staging:[105,185],prod:[168,152],__orphan:[-196,180]};
    const pos={}; for(const k in pos0)pos[k]=[pos0[k][0]*SPREAD,pos0[k][1]*SPREAD];
    this.gpos=this.gpos||{};
    let free=0;
    const spot=(id)=>this.gpos[id]||pos[id]||[(free=free+1)*110-220, 620];
    const nodes=this.vault.nodes.map(n=>{const [x,y]=spot(n.id);return {...n,x,y};});
    const [ox,oy]=spot('__orphan');
    nodes.push({id:'__orphan',label:'orphaned',kind:'orphan',depth:1,parentId:null,counts:{entries:this.vault.orphans.length,totp:null},gate:{locked:false,twofa:'none'},x:ox,y:oy});
    const byId={}; nodes.forEach(n=>byId[n.id]=n);
    const links=this.vault.links.map(l=>({kind:l.kind,source:byId[l.source.id||l.source],target:byId[l.target.id||l.target]})).filter(l=>l.source&&l.target);
    return {nodes,links};
  }
  initGraph(){
    const el=this.graphRef.current; if(!el)return;
    if(this.gcv&&el.contains(this.gcv))return;
    if(this.gcv){ el.innerHTML=''; el.appendChild(this.gcv); this.gEl=el; if(this.ro){this.ro.disconnect();this.ro.observe(el);} if(this.gSize)this.gSize(); this.renderGraph(); return; }
    el.innerHTML='';
    const cv=document.createElement('canvas');
    cv.style.cssText='position:absolute;inset:0;cursor:default';
    cv.setAttribute('role','img'); cv.setAttribute('aria-label','Vault graph: node relationships and entry counts, drawn on canvas. Press T for the accessible tree view (full parity), F to fit, G for global.'); // B5-5
    el.appendChild(cv); this.gcv=cv; this.gEl=el;
    this.gv={k:1,tx:0,ty:0};
    this.gd=this.graphData(); // hard-floor spacing runs unconditionally every tick, so stale/cramped stored positions self-correct on the first frames
    const sizeIt=()=>{ const rc=(this.gEl||el).getBoundingClientRect(); const dpr=window.devicePixelRatio||1; // gEl: the pane the canvas lives in now (it is re-mounted after games and overlays)
      if(rc.width<=50||rc.height<=50){ if(!this._gRetry){ this._gRetry=true; const again=()=>{ this._gRetry=false; sizeIt(); }; requestAnimationFrame(again); setTimeout(()=>{ if(this._gRetry)again(); },200); } return; } // container not laid out yet — retry next frame; never cache a guessed fallback size
      const w=rc.width, h=rc.height;
      if(this.gw===w&&this.gh===h)return;
      cv.width=Math.round(w*dpr); cv.height=Math.round(h*dpr); cv.style.width=w+'px'; cv.style.height=h+'px';
      this.gw=w; this.gh=h; this.zoomToFitG(); };
    this.gSize=sizeIt;
    sizeIt();
    if(this.ro)this.ro.disconnect();
    this.ro=new ResizeObserver(sizeIt); this.ro.observe(el);
    const s2g=(sx,sy)=>({x:(sx-this.gv.tx)/this.gv.k, y:(sy-this.gv.ty)/this.gv.k});
    const hit=(sx,sy)=>{ const g=s2g(sx,sy); let best=null;
      for(const n of this.gd.nodes){ const d=Math.hypot(n.x-g.x,n.y-g.y); if(d<=this.nodeR(n)+5&&(!best||d<best.d))best={n,d}; }
      return best&&best.n; };
    const hitEntry=(sx,sy)=>{ if(!this.entryNodes||!this.entryNodes.length)return null; const g=s2g(sx,sy); let best=null;
      for(const en of this.entryNodes){ const d=Math.hypot(en.x-g.x,en.y-g.y); if(d<=6&&(!best||d<best.d))best={en,d}; }
      return best&&best.en; };
    let drag=null, pan=null, dragE=null;
    cv.addEventListener('pointerdown',ev=>{ if(ev.button!==0)return; cv.setPointerCapture(ev.pointerId);
      const he=hitEntry(ev.offsetX,ev.offsetY);
      if(he){ dragE={en:he,moved:false}; return; }
      const n=hit(ev.offsetX,ev.offsetY);
      if(n){ drag={n,moved:false}; n.pinned=true;
        this._draggedNodeId=n.id;
        this._dragAnchors={}; const descIds=new Set(this.gdDescendants(n.id).map(o=>o.id)); // downstream = anyone reachable by following outgoing links from the dragged node
        for(const o of this.gd.nodes){ if(o.id===n.id)continue;
          if(descIds.has(o.id)) this._dragAnchors[o.id]={follow:true,ox:o.x-n.x,oy:o.y-n.y}; // rides along at its original offset, smoothly lagging
          else this._dragAnchors[o.id]={follow:false,x:o.x,y:o.y}; // everyone else holds its exact spot — if bumped aside it eases straight back
        }
        this._dragging=true;
      }
      else pan={sx:ev.offsetX,sy:ev.offsetY,tx:this.gv.tx,ty:this.gv.ty,moved:false};
    });
    cv.addEventListener('pointermove',ev=>{
      if(dragE){ const g=s2g(ev.offsetX,ev.offsetY); if(Math.hypot(g.x-dragE.en.x,g.y-dragE.en.y)>2||dragE.moved){ dragE.moved=true; dragE.en.x=g.x; dragE.en.y=g.y; dragE.en.pinned=true; this.gposEntry=this.gposEntry||{}; this.gposEntry[dragE.en.id]=[g.x,g.y]; this.renderGraph(); } return; }
      if(drag){ const g=s2g(ev.offsetX,ev.offsetY); if(Math.hypot(g.x-drag.n.x,g.y-drag.n.y)>2||drag.moved){ drag.moved=true;
          drag.n.x=g.x; drag.n.y=g.y; this.gpos[drag.n.id]=[g.x,g.y];
          this.startLoop(); this.renderGraph(); } return; }
      if(pan){ const dx=ev.offsetX-pan.sx, dy=ev.offsetY-pan.sy; if(Math.abs(dx)+Math.abs(dy)>3)pan.moved=true; this.gv.tx=pan.tx+dx; this.gv.ty=pan.ty+dy; this.renderGraph(); return; }
      const he=hitEntry(ev.offsetX,ev.offsetY);
      if(he){ cv.style.cursor='pointer';
        if(this.hoverEntryId!==he.id){ this.hoverEntryId=he.id; this.hoverId=null; clearTimeout(this.hoverT);
          const hx=ev.offsetX+14,hy=ev.offsetY+14;
          this.hoverT=setTimeout(()=>this.setState({hover:{x:hx,y:hy,mode:'entry',etype:he.type}}),150);
          this.renderGraph();
        }
        return;
      } else if(this.hoverEntryId){ this.hoverEntryId=null; clearTimeout(this.hoverT); this.setState({hover:null}); this.renderGraph(); }
      const n=hit(ev.offsetX,ev.offsetY);
      cv.style.cursor=n?'pointer':'default';
      const hid=n?n.id:null;
      if(hid!==this.hoverId){ this.hoverId=hid; clearTimeout(this.hoverT);
        if(n){ const hx=ev.offsetX+14, hy=ev.offsetY+14;
          this.hoverT=setTimeout(()=>this.setState({hover:{x:hx,y:hy,mode:'node',entries:n.counts.entries,totp:n.counts.totp==null?'—':n.counts.totp}}),180); }
        else if(this.state.hover) this.setState({hover:null});
      }
    });
    cv.addEventListener('pointerup',ev=>{
      if(dragE){ const d=dragE; dragE=null;
        if(!d.moved){ this.setState({openEntry:d.en.id,inspOpen:true}); } else this.persistPositions();
        this.renderGraph(); return; }
      if(drag){ const d=drag; drag=null; d.n.pinned=false; this._dragging=false;
        if(!d.moved){ this.select(d.n.id); this._dragAnchors=null; this._draggedNodeId=null; }
        else { if(d.n.id!=='__orphan'){ const hitN=this.gd.nodes.find(o=>o.id!==d.n.id&&o.id!=='__orphan'&&Math.hypot(o.x-d.n.x,o.y-d.n.y)<this.nodeR(o)+this.nodeR(d.n.id==='global'?d.n:d.n)+8);
          if(hitN){ this.setState(st=>({dialog:'grant',grant:{...st.grant,from:d.n.id,to:hitN.id}})); } } this.persistPositions(); this.startLoop(); }
        this.renderGraph(); return; }
      if(pan){ const p=pan; pan=null; if(!p.moved)this.setState({ctx:null,hover:null,searchOpen:false,vaultMenu:false,selected:this.state.selected}); }
    });
    cv.addEventListener('wheel',ev=>{ ev.preventDefault();
      const f=Math.exp(-ev.deltaY*0.0015); const k2=Math.min(6,Math.max(0.3,this.gv.k*f)); const q=k2/this.gv.k;
      this.gv.tx=ev.offsetX-(ev.offsetX-this.gv.tx)*q; this.gv.ty=ev.offsetY-(ev.offsetY-this.gv.ty)*q; this.gv.k=k2;
      this.renderGraph();
    },{passive:false});
    cv.addEventListener('contextmenu',ev=>{ ev.preventDefault(); const n=hit(ev.offsetX,ev.offsetY);
      if(n&&n.id!=='__orphan')this.setState({ctx:{x:ev.offsetX,y:ev.offsetY,node:n.id}});
      else if(n)this.setState({ctx:{x:ev.offsetX,y:ev.offsetY,node:'__orphan'}});
      else this.setState({ctx:null});
    });
    cv.addEventListener('dblclick',ev=>{ const n=hit(ev.offsetX,ev.offsetY); if(n)this.zoomToNode(n); });
    this.renderGraph();
  }
  zoomToFitG(){
    if(!this.gd||!this.gw)return;
    let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
    for(const n of this.gd.nodes){ const r=this.nodeR(n)+20; x0=Math.min(x0,n.x-r);y0=Math.min(y0,n.y-r);x1=Math.max(x1,n.x+r);y1=Math.max(y1,n.y+r+14); }
    const pad=40; const k=Math.min(2.2,Math.max(0.3,Math.min((this.gw-pad*2)/(x1-x0),(this.gh-pad*2)/(y1-y0))));
    this.gv={k,tx:this.gw/2-k*(x0+x1)/2,ty:this.gh/2-k*(y0+y1)/2};
    this.renderGraph();
  }
  zoomToNode(n){
    const kids=this.gd.nodes.filter(o=>o.parentId===n.id).concat([n]);
    let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
    for(const o of kids){ const r=this.nodeR(o)+40; x0=Math.min(x0,o.x-r);y0=Math.min(y0,o.y-r);x1=Math.max(x1,o.x+r);y1=Math.max(y1,o.y+r); }
    const k=Math.min(6,Math.max(0.3,Math.min(this.gw/(x1-x0),this.gh/(y1-y0))));
    this.gv={k,tx:this.gw/2-k*(x0+x1)/2,ty:this.gh/2-k*(y0+y1)/2};
    this.renderGraph();
  }
  renderGraph(){
    const cv=this.gcv; if(!cv||!this.gd)return;
    const ctx=cv.getContext('2d'); const dpr=window.devicePixelRatio||1;
    ctx.setTransform(dpr,0,0,dpr,0,0);
    ctx.clearRect(0,0,cv.width/dpr,cv.height/dpr);
    this._ce=this.cosmEff(); ctx.translate(this.gv.tx,this.gv.ty); ctx.scale(this.gv.k,this.gv.k); this.paintBackdrop(ctx,cv,dpr);
    for(const l of this.gd.links) this.paintLink(l,ctx);
    if(this.entryNodes)for(const en of this.entryNodes) this.paintEntryLink(en,ctx);
    for(const n of this.gd.nodes) this.paintNode(n,ctx,this.gv.k);
    if(this.entryNodes)for(const en of this.entryNodes) this.paintEntry(en,ctx);
  }
  nodeR(n){ // VAULT_GRAPH_SPEC §3: radius scales with entry count, global/orphan fixed
    if(n.kind==='global')return 22; if(n.kind==='orphan')return 15;
    const t=Math.sqrt(Math.max(0,Math.min(40,(n.counts&&n.counts.entries)||0))/40);
    return n.kind==='sub'?8+6*t:12+8*t; }
  gdNode(id){ return this.gd&&this.gd.nodes.find(o=>o.id===id); }
  hashStr(s){let h=0;for(let i=0;i<s.length;i++)h=(h*31+s.charCodeAt(i))|0;return Math.abs(h);}
  entryColor(id){let h=((this.hashStr(id)*2654435761)>>>0)%360;const pk=this.state.pack,rg=pk&&pk.dots&&pk.dots[this.cosmEff().dots];if(rg===0)return this.palette().ash;if(rg)h=Math.round(rg[0]+h/360*(rg[1]-rg[0]));return this.eff().theme==='dark'?`oklch(0.74 0.125 ${h})`:`oklch(0.5 0.13 ${h})`;}
  nodeGlyphIdx(id){return this.hashStr('g:'+id)%14;}
  drawGlyph(ctx,cx,cy,h,idx,color){
    ctx.save();ctx.strokeStyle=color;ctx.fillStyle=color;
    const gsty=(this._cosmFx&&this._cosmFx.glyph)||'classic'; ctx.lineWidth=gsty==='fine'?0.8:gsty==='heavy'?2:1.2; if(gsty==='heavy'){ctx.lineCap='round';ctx.lineJoin='round';} // supporter extra: stroke weight only
    switch(idx){
      case 0: ctx.beginPath();ctx.moveTo(cx-h,cy);ctx.lineTo(cx+h,cy);ctx.moveTo(cx,cy-h);ctx.lineTo(cx,cy+h);ctx.stroke();break;
      case 1: ctx.beginPath();ctx.moveTo(cx-h*.75,cy-h*.75);ctx.lineTo(cx+h*.75,cy+h*.75);ctx.moveTo(cx-h*.75,cy+h*.75);ctx.lineTo(cx+h*.75,cy-h*.75);ctx.stroke();break;
      case 2: ctx.beginPath();ctx.arc(cx,cy,Math.max(1.3,h*.28),0,7);ctx.fill();break;
      case 3: ctx.beginPath();ctx.arc(cx,cy,h*.72,0,7);ctx.stroke();break;
      case 4: ctx.strokeRect(cx-h*.6,cy-h*.6,h*1.2,h*1.2);break;
      case 5: ctx.fillRect(cx-h*.52,cy-h*.52,h*1.04,h*1.04);break;
      case 6: ctx.beginPath();ctx.moveTo(cx,cy-h*.78);ctx.lineTo(cx+h*.72,cy+h*.56);ctx.lineTo(cx-h*.72,cy+h*.56);ctx.closePath();ctx.stroke();break;
      case 7: ctx.beginPath();ctx.moveTo(cx,cy-h*.8);ctx.lineTo(cx+h*.8,cy);ctx.lineTo(cx,cy+h*.8);ctx.lineTo(cx-h*.8,cy);ctx.closePath();ctx.stroke();break;
      case 8: ctx.beginPath();ctx.moveTo(cx-h,cy);ctx.lineTo(cx+h,cy);ctx.stroke();break;
      case 9: ctx.beginPath();ctx.moveTo(cx,cy-h);ctx.lineTo(cx,cy+h);ctx.stroke();break;
      case 10: ctx.beginPath();ctx.arc(cx-h*.42,cy,1.2,0,7);ctx.arc(cx+h*.42,cy,1.2,0,7);ctx.fill();break;
      case 11: ctx.beginPath();ctx.moveTo(cx-h,cy);ctx.lineTo(cx+h,cy);ctx.moveTo(cx,cy-h);ctx.lineTo(cx,cy+h);ctx.moveTo(cx-h*.7,cy-h*.7);ctx.lineTo(cx+h*.7,cy+h*.7);ctx.moveTo(cx-h*.7,cy+h*.7);ctx.lineTo(cx+h*.7,cy-h*.7);ctx.stroke();break;
      case 12: ctx.beginPath();ctx.arc(cx,cy,h*.7,0.15*Math.PI,0.85*Math.PI);ctx.stroke();break;
      default: ctx.beginPath();ctx.moveTo(cx-h*.32,cy-h*.8);ctx.lineTo(cx-h*.52,cy+h*.8);ctx.moveTo(cx+h*.18,cy-h*.8);ctx.lineTo(cx-h*.02,cy+h*.8);ctx.moveTo(cx-h*.82,cy-h*.2);ctx.lineTo(cx+h*.72,cy-h*.2);ctx.moveTo(cx-h*.92,cy+h*.32);ctx.lineTo(cx+h*.62,cy+h*.32);ctx.stroke();
    }
    ctx.restore();
  }

  paintNode(n,ctx,scale){
    if(this._dev)window.__cmPaint=(window.__cmPaint||0)+1;
    const p=this.palette(); const r=this.nodeR(n); const shp=(this._ce||this.cosmEff()).shape; const sel=this.state.selected===(n.id==='__orphan'?'__orphan':n.id);
    const q=this.state.searchQ.trim().toLowerCase();
    const dim=q&&!n.label.toLowerCase().includes(q);
    ctx.save(); ctx.globalAlpha=dim?0.25:1;
    ctx.lineWidth=(sel?2.5:n.kind==='sub'?1:1.5)/1;
    if(n.kind==='orphan'){
      ctx.setLineDash([3,3]); ctx.strokeStyle=p.faint;
      this.shapePath(ctx,n.x,n.y,r,shp);ctx.stroke();
      ctx.setLineDash([]);
      ctx.save();this.shapePath(ctx,n.x,n.y,r-1,shp);ctx.clip();
      ctx.strokeStyle=p.faint;ctx.globalAlpha=(dim?0.25:1)*0.5;ctx.lineWidth=0.6;
      for(let i=-r*2;i<r*2;i+=4){ctx.beginPath();ctx.moveTo(n.x+i-r,n.y+r);ctx.lineTo(n.x+i+r,n.y-r);ctx.stroke();}
      ctx.restore();
    } else if(n.kind==='global'){
      ctx.fillStyle=this.globalFill(p);this.shapePath(ctx,n.x,n.y,r,shp);ctx.fill();
    } else {
      ctx.strokeStyle=n.health==='danger'?p.danger:(n.kind==='sub'?p.ash:p.bone);
      this.shapePath(ctx,n.x,n.y,r,shp);ctx.stroke();
    }
    if(n.kind==='project'||n.kind==='sub'){ this.drawGlyph(ctx,n.x,n.y,r*0.42,this.nodeGlyphIdx(n.id),n.kind==='sub'?p.ash:p.bone); }
    if(sel){ const pulse=0.5+0.5*Math.sin((this.breathT||0)*0.045);
      ctx.strokeStyle=p.bone;ctx.globalAlpha=(dim?0.25:1)*(0.12+0.11*pulse);ctx.lineWidth=2.5;
      ctx.beginPath();ctx.arc(n.x,n.y,r+3+2.5+pulse*1.6,0,2*Math.PI);ctx.stroke();ctx.globalAlpha=dim?0.25:1;
      if(this._cosmFx&&this._cosmFx.halo){ ctx.globalAlpha=(dim?0.25:1)*(0.06+0.08*(1-pulse)); ctx.lineWidth=1.5; ctx.beginPath();ctx.arc(n.x,n.y,r+3+2.5+8+(1-pulse)*2.4,0,2*Math.PI);ctx.stroke();ctx.globalAlpha=dim?0.25:1; } } // supporter flourish: second, slower halo
    if(n.gate&&n.gate.twofa!=='none'&&n.kind!=='global'){
      ctx.strokeStyle=n.gate.twofa==='enrolled'?p.warn:(n.kind==='sub'?p.ash:p.bone);ctx.lineWidth=2;
      ctx.beginPath();ctx.moveTo(n.x,n.y-r-1);ctx.lineTo(n.x,n.y-r+3);ctx.stroke();
    }
    if(n.gate&&n.gate.locked){ // moved off-centre (was drawn at n.y-1, colliding with the new glyph)
      const kc=n.kind==='global'?p.void:(n.kind==='orphan'?p.mute:p.bone);
      ctx.fillStyle=kc;ctx.fillRect(n.x-1.4/scale,n.y+r+2/scale,2.8/scale,2.8/scale);
    }
    { /* labels: mock shows all; production applies the 1.4x-zoom threshold at scale */
      let lb=n.label; if(lb.length>22)lb=lb.slice(0,21)+'…';
      ctx.font=`500 ${10.5/scale}px "JetBrains Mono", ui-monospace, Menlo, monospace`;
      ctx.textAlign='center';ctx.textBaseline='top';
      ctx.fillStyle=n.kind==='orphan'?p.mute:p.ash;
      ctx.fillText(lb,n.x,n.y+r+6/scale);
    }
    ctx.restore();
  }
  paintLink(l,ctx){
    const p=this.palette(); const s=l.source,t=l.target; if(typeof s!=='object')return;
    const selId=this.state.selected; const touching=s.id===selId||t.id===selId;
    ctx.save(); ctx.globalAlpha=selId&&!touching?0.15:1;
    const rs=this.nodeR(s),rt=this.nodeR(t);
    const dx=t.x-s.x,dy=t.y-s.y,dist=Math.hypot(dx,dy)||1,ux=dx/dist,uy=dy/dist;
    const x1=s.x+ux*rs,y1=s.y+uy*rs,x2=t.x-ux*(rt+2),y2=t.y-uy*(rt+2);
    ctx.lineWidth=1;
    if(l.kind==='grant'){ ctx.strokeStyle=p.ash; ctx.setLineDash([4,3]); }
    else { this.linkStyle(ctx,p); ctx.setLineDash([]); }
    ctx.beginPath();ctx.moveTo(x1,y1);ctx.lineTo(x2,y2);ctx.stroke();
    if(l.kind==='grant'){
      ctx.setLineDash([]); ctx.fillStyle=p.ash;
      ctx.beginPath();ctx.moveTo(x2,y2);ctx.lineTo(x2-ux*8-uy*3.5,y2-uy*8+ux*3.5);ctx.lineTo(x2-ux*8+uy*3.5,y2-uy*8-ux*3.5);ctx.closePath();ctx.fill();
    }
    ctx.restore();
  }
  refreshGraph(){ this.pal=null; this.gd=this.graphData(); this.buildEntryNodes(); this.renderGraph(); }
  clusterKey(en){
    const stop=['api','key','password','pass','pw','login','user','username','token','secret','account','db','database','server','host','port','cert','certificate','totp','2fa','seed','phrase','staging','prod','dev','old','readonly'];
    const words=(en.name||'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim().split(' ').filter(w=>w&&!stop.includes(w));
    return words.length?words[0]:en.type;
  }
  // Connector lengths vary a little by field type, so a node's ring reads as a cloud rather than a
  // perfect circle. Deterministic (hash of the type), so a given entry always sits at the same reach.
  typeReach(type,id){ const t=String(type||''); const byType=t?[0,5,10][this.hashStr(t)%3]:0;
    return byType+(id?this.hashStr(String(id))%5:0); } // + a few px keyed off the entry id, so same-type siblings aren't perfectly uniform either
  formationSlots(n){ // shape grows with entry count: pair→triangle→square→pentagon→hexagon→two-ring cluster→golden-angle spiral
    if(n<=0)return[];
    if(n===1)return[{a:0,r:0,rot:0}];
    if(n===2)return[0,1].map(i=>({a:i*Math.PI,r:1,rot:0.0009}));
    const rotByN={3:0.0016,4:0.0012,5:0.0009,6:0.0007};
    if(rotByN[n]!==undefined){ const rot=rotByN[n]; return Array.from({length:n},(_,i)=>({a:i/n*2*Math.PI-Math.PI/2,r:1,rot})); }
    if(n<=12){ const outer=Math.ceil(n/2),inner=n-outer,rot=0.0005,slots=[];
      for(let i=0;i<outer;i++)slots.push({a:i/outer*2*Math.PI,r:1.15,rot});
      for(let i=0;i<inner;i++)slots.push({a:i/inner*2*Math.PI+Math.PI/inner,r:0.6,rot:-rot*1.3});
      return slots; }
    const golden=Math.PI*(3-Math.sqrt(5));
    return Array.from({length:n},(_,i)=>({a:i*golden,r:0.25+0.9*Math.sqrt((i+0.5)/n),rot:0.00035}));
  }
  // Entry-dots deviate from VAULT_GRAPH_SPEC §3/§7 ("entries never separately drawn") at the user's
  // explicit request (Obsidian-style graph). Entry dots default ON for EVERY node (not just the
  // selected one) — togglable back to "selected only" via state.entriesMode (E key / the graph-view
  // chip). Mitigations kept: colour hashes off the internal id only, hover shows type only — never
  // name or value. Signed off 2026-09-07 — §7 amendment text logged in BACKEND_HANDOFF_NOTES.md.
  buildEntryNodes(idOverride){
    const mode=this.state.entriesMode||'all';
    const sid=idOverride!==undefined?idOverride:this.state.selected;
    const ids=mode==='selected' ? (sid&&sid!=='__orphan'?[sid]:[]) : Object.keys(this.vault.entries).filter(id=>this.gdNode(id));
    const prev={}; (this.entryNodes||[]).forEach(e=>prev[e.id]=e);
    const out=[];
    for(const nid of ids){
      const n=this.gdNode(nid); if(!n)continue;
      const list=this.vault.entries[nid]||[]; if(!list.length)continue;
      const R=this.nodeR(n);
      const ranked=list.map((en,i)=>({en,i,ck:this.clusterKey(en)}));
      const order=[...new Set(ranked.map(r=>r.ck))];
      ranked.sort((a,b)=>order.indexOf(a.ck)-order.indexOf(b.ck)||a.i-b.i);
      const slots=this.formationSlots(ranked.length);
      ranked.forEach((r,idx)=>{
        const old=prev[r.en.id]; if(old&&old.parentId===nid){ old.baseR=R; old.ck=r.ck; old.slot=slots[idx]; out.push(old); return; }
        const pin=this.gposEntry&&this.gposEntry[r.en.id];
        const slot=slots[idx], rad=R+20+this.typeReach(r.en.type,r.en.id)+slot.r*(20+Math.min(28,ranked.length));
        out.push({id:r.en.id,parentId:nid,type:r.en.type,ck:r.ck,slot,vx:0,vy:0,pinned:!!pin,baseR:R,
          x:pin?pin[0]:n.x+Math.cos(slot.a)*rad, y:pin?pin[1]:n.y+Math.sin(slot.a)*rad,
          color:this.entryColor(r.en.id)});
      });
    }
    this.entryNodes=out;
    this.simAlpha=1; this.startLoop();
  }
  // Circular formation, Obsidian-style: each entry holds a fixed angular slot on a ring around its
  // node (from formationSlots) and drifts there at a near-static crawl — no jitter, no clustering
  // force, nothing chaotic. Collision resolution runs GLOBALLY across every entry and every node
  // (not just siblings), so entries from different nodes — or a node's own body — never overlap or
  // pass through one another, however close their nodes get dragged.
  tickEntries(){
    const es=this.entryNodes; if(!es||!es.length)return false;
    this.rotT=(this.rotT||0)+1;
    const groups={}; for(const a of es)(groups[a.parentId]=groups[a.parentId]||[]).push(a);
    for(const pid in groups){
      const n=this.gdNode(pid); if(!n)continue;
      const arr=groups[pid];
      for(const a of arr){
        if(a.pinned){ a.vx=0;a.vy=0; continue; }
        const slot=a.slot||{a:0,r:1,rot:0};
        const ring=a.baseR+20+this.typeReach(a.type,a.id)+slot.r*(20+Math.min(28,arr.length));
        const ang=slot.a+this.rotT*slot.rot; // slow, steady drift — alive but calm
        const tx=n.x+Math.cos(ang)*ring, ty=n.y+Math.sin(ang)*ring;
        const fx=(tx-a.x)*0.045, fy=(ty-a.y)*0.045;
        a.vx=(a.vx+fx)*0.85; a.vy=(a.vy+fy)*0.85;
        a.x+=a.vx; a.y+=a.vy;
      }
    }
    // global hard collision — every entry against every entry, and every entry against every node —
    // so nothing ever sits in front of/behind or inside anything else
    const minD=7.6;
    for(let pass=0;pass<3;pass++){
      for(let i=0;i<es.length;i++)for(let j=i+1;j<es.length;j++){
        const a=es[i],b=es[j];
        const rx=a.x-b.x,ry=a.y-b.y; let rd=Math.hypot(rx,ry);
        if(rd<minD){
          if(rd<0.001)rd=0.001;
          const ux=rx/rd,uy=ry/rd, overlap=minD-rd;
          if(a.pinned&&b.pinned)continue;
          if(a.pinned){ b.x-=ux*overlap; b.y-=uy*overlap; }
          else if(b.pinned){ a.x+=ux*overlap; a.y+=uy*overlap; }
          else { a.x+=ux*overlap*0.5; a.y+=uy*overlap*0.5; b.x-=ux*overlap*0.5; b.y-=uy*overlap*0.5; }
        }
      }
      if(this.gd)for(const a of es){ if(a.pinned)continue;
        for(const nn of this.gd.nodes){
          const nr=this.nodeR(nn)+6;
          const dx=a.x-nn.x,dy=a.y-nn.y; let d=Math.hypot(dx,dy);
          if(d<nr){ if(d<0.001)d=0.001; const ux=dx/d,uy=dy/d; a.x=nn.x+ux*nr; a.y=nn.y+uy*nr; }
        }
      }
    }
    return true;
  }
  loadPositions(){
    const clean=(raw)=>{ const out={}; for(const k in raw){ const v=raw[k]; if(Array.isArray(v)&&Number.isFinite(v[0])&&Number.isFinite(v[1]))out[k]=v; } return out; }; // drop any corrupted (NaN/null) entry, fall back to default for that node only
    const LV='2'; // layout version — bumped when default node spacing grew (2026-09-07); a saved arrangement is migrated, never discarded
    try{
      const ver=localStorage.getItem('credmgr_gposV');
      const gp=localStorage.getItem('credmgr_gpos'); if(gp)this.gpos=clean(JSON.parse(gp));
      const ep=localStorage.getItem('credmgr_gposEntry'); if(ep)this.gposEntry=clean(JSON.parse(ep));
      if(ver!==LV){ const k=1.7, mg={}; for(const id in (this.gpos||{}))mg[id]=[this.gpos[id][0]*k,this.gpos[id][1]*k];
        this.gpos=mg; this.gposEntry={}; // entries re-form on the new, wider ring
        localStorage.setItem('credmgr_gposV',LV); this.persistPositions(); }
    }catch(e){}
  }
  persistPositions(){
    const clean=(raw)=>{ const out={}; for(const k in raw){ const v=raw[k]; if(Array.isArray(v)&&Number.isFinite(v[0])&&Number.isFinite(v[1]))out[k]=v; } return out; };
    try{ localStorage.setItem('credmgr_gpos',JSON.stringify(clean(this.gpos||{})));
      localStorage.setItem('credmgr_gposEntry',JSON.stringify(clean(this.gposEntry||{})));
    }catch(e){}
  }
  // A node's "own space" — its body plus the outer edge its entry cloud can reach.
  nodeFootprint(n){
    const cnt=(this.vault.entries[n.id]||[]).length;
    return this.nodeR(n)+(cnt?16+0.6*(14+Math.min(24,cnt)):8); // sized to fit within the hand-placed layout's natural spacing — a floor, not a fight with it
  }
  // Everyone reachable by following outgoing links from id — the transitive "downstream" set that
  // rides along when id is dragged (structural AND grant edges both count: a grant is a real edge).
  gdDescendants(id){
    const seen=new Set(); const stack=[id]; const out=[];
    while(stack.length){ const cur=stack.pop();
      for(const l of this.gd.links){ if(typeof l.source==='object'&&l.source.id===cur&&!seen.has(l.target.id)){ seen.add(l.target.id); out.push(l.target); stack.push(l.target.id); } }
    }
    return out;
  }
  // Deliberately NOT a spring simulation — a bounded lag-follow, chosen after a spring model kept
  // cascading a single drag into whole-graph movement. Only two things can ever move a node: (1) it's
  // a downstream descendant of the node under the cursor, in which case it eases toward "dragged
  // node's current spot + its own original offset" — same shape, smooth lag, can't overshoot; or
  // (2) it got bumped by the own-space check below, in which case it eases straight back to where it
  // started. Nothing else is ever touched, so a drag structurally cannot ripple into unrelated nodes.
  tickNodes(){
    if(!this.gd)return false;
    const nodes=this.gd.nodes;
    let moving=false;
    if(this._dragAnchors){
      const anchors=this._dragAnchors, dragged=nodes.find(o=>o.id===this._draggedNodeId); // by id, not .pinned — still needed as the follow target after release
      for(const n of nodes){
        if(n.pinned)continue;
        const anc=anchors[n.id]; if(!anc)continue;
        const tx=anc.follow&&dragged?dragged.x+anc.ox:anc.x, ty=anc.follow&&dragged?dragged.y+anc.oy:anc.y;
        const dx=tx-n.x, dy=ty-n.y;
        n.x+=dx*0.09; n.y+=dy*0.09; this.gpos[n.id]=[n.x,n.y];
        if(Math.abs(dx)>0.4||Math.abs(dy)>0.4)moving=true;
      }
    }
    for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){ // own space — unconditional, every tick, forever
      const a=nodes[i],b=nodes[j]; if(a.pinned||b.pinned)continue; // the node under the cursor passes freely; settles on release
      const dx=b.x-a.x,dy=b.y-a.y; let d=Math.hypot(dx,dy)||0.01;
      const minD=this.nodeFootprint(a)+this.nodeFootprint(b)+22;
      if(d<minD){ const ux=dx/d,uy=dy/d,push=(minD-d)/2;
        a.x-=ux*push; a.y-=uy*push; b.x+=ux*push; b.y+=uy*push;
        this.gpos[a.id]=[a.x,a.y]; this.gpos[b.id]=[b.x,b.y]; moving=true;
      }
    }
    if(this._dragAnchors&&!moving&&!this._dragging){ this._dragAnchors=null; this._draggedNodeId=null; }
    return moving||this._dragging;
  }
  startLoop(){
    if(this._raf)return;
    const step=()=>{
      this._raf=null;
      if(document.hidden||this.state.view!=='graph')return;
      const movingE=this.tickEntries(), movingN=this.tickNodes();
      this.breathT=(this.breathT||0)+1;
      this.renderGraph();
      if(movingE||movingN){
        const now=performance.now(); if(!this._lastPersist||now-this._lastPersist>1000){ this._lastPersist=now; this.persistPositions(); }
        this._raf=requestAnimationFrame(step);
      } else this.persistPositions();
    };
    this._raf=requestAnimationFrame(step);
  }
  donateCodeKey(){return 'credmgr_donate_unlocked';}
  donateIsUnlocked(){try{return localStorage.getItem(this.donateCodeKey())==='1';}catch(e){return false;}}
  extrasBlob(){return '{"v":1,"it":200000,"salt":"iMl2YaB4VQ0M7GdBsPCIAw==","iv":"T0QSfvfn6z6LDBaV","d":"dilGmqhqMVnn8DpZ6g7Ig+pUiv/HEsS0yKqSopKzjeh4wv5CDRMbwpq5Fq2TKePPS1HTG4ESKTKP9bh94CC/THxWoa7amCdoMKTCwj9y91sJtIWP8ab0W/fm3rbW3UrIlaVVeQPEbt0NM6e4gEm6V6cF/HoueaqCexV+jtAPNO2ZOlNcHkd6Fyl1eQsSbaa8VzX0IXc/3R2LcdALIjoqWjJw0PObGFlw7UL3j7dGMVpbSANki0PUZyB84TtZQWoU66A7PzYTrfItoGSamrmkywieJYG5DSImRGv4O9wmYxy5hqpN22ILgqLZvek883MmH013tRxMbClTMKiQhpU1XBSstbP/rVHgU2tWkYV3YA4/pMe443foFr311JWuEvWOcgd6bpeXoV63+jCXkaszN4cWwmX07ervSDfVRNgwtpubS0OcleYq1rF4Dn+z7YcYJARm2QpwJR57uRF+7aBUsKgyuknOLaCtk+4NORrrdyibNsOIVCBH5JO4e5yceeKxewUyFJEoPCeeUB+1016sKwQMytWuCnRDldYGbHiQ0PpHJw=="}';} // sealed extras pack: AES-GCM, key from PBKDF2(code). The code is not in this file.
  b64d(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
  b64e(u){let s='';u.forEach(c=>{s+=String.fromCharCode(c);});return btoa(s);}
  async extrasOpenWith(key){ const b=JSON.parse(this.extrasBlob()); const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:this.b64d(b.iv)},key,this.b64d(b.d)); return JSON.parse(new TextDecoder().decode(pt)); }
  async extrasUnlock(code,keep){ try{ const b=JSON.parse(this.extrasBlob()); const km=await crypto.subtle.importKey('raw',new TextEncoder().encode(String(code||'').trim().toUpperCase()),'PBKDF2',false,['deriveKey']);
      const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:this.b64d(b.salt),iterations:b.it,hash:'SHA-256'},km,{name:'AES-GCM',length:256},true,['decrypt']);
      const pack=await this.extrasOpenWith(key); const raw=new Uint8Array(await crypto.subtle.exportKey('raw',key));
      if(keep!==false){ try{localStorage.setItem('credmgr_extras_key',this.b64e(raw));localStorage.setItem(this.donateCodeKey(),'1');}catch(e){} }
      this.setState({pack}); return true; }catch(e){ return false; } } // wrong code: decryption fails, nothing is stored
  async loadExtras(){ try{ const k=localStorage.getItem('credmgr_extras_key'); if(!k)return; const key=await crypto.subtle.importKey('raw',this.b64d(k),'AES-GCM',false,['decrypt']); this.setState({pack:await this.extrasOpenWith(key)}); }catch(e){} }
  today(){ const d=new Date(); return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0'); }
  usageGet(){ const d={v:1,days:0,last:'',asked:[],optout:false,lastAsk:'',marks:{}}; try{ const o=JSON.parse(localStorage.getItem('credmgr_usage')||'{}')||{}; const dt=/^\d{4}-\d{2}-\d{2}$/, mk={}; if(o.marks&&typeof o.marks==='object')for(const k of this.msIds()){ if(typeof o.marks[k]==='string'&&dt.test(o.marks[k]))mk[k]=o.marks[k]; }
      return {v:1,days:Math.max(0,o.days|0),last:typeof o.last==='string'&&dt.test(o.last)?o.last:'',asked:Array.isArray(o.asked)?o.asked.filter(x=>['m1','m2','m3'].includes(x)):[],optout:!!o.optout,lastAsk:typeof o.lastAsk==='string'&&dt.test(o.lastAsk)?o.lastAsk:'',marks:mk}; }catch(e){ return d; } }
  usageSave(u){ try{localStorage.setItem('credmgr_usage',JSON.stringify(u));}catch(e){} }
  usageTick(){ const u=this.usageGet(),t=this.today(); if(u.last!==t){u.days++;u.last=t;this.usageSave(u);} this.marksSync(); } // one count per calendar day with an unlock; no time stored
  usageEntries(){ if(this._entriesOv!=null)return this._entriesOv; let n=0; const e=(this.vault&&this.vault.entries)||{}; for(const k in e)n+=(e[k]||[]).length; return n; }
  usageSet(o){ o=o||{}; const u=this.usageGet(); if(o.reset){u.asked=[];u.optout=false;u.lastAsk='';u.marks={};} if(o.days!=null)u.days=o.days; if(o.last!=null)u.last=o.last; this.usageSave(u); if('entries' in o)this._entriesOv=o.entries; } // dev handle
  usagePending(){ const u=this.usageGet(); if(u.optout||this.donateIsUnlocked()||u.lastAsk===this.today())return null; const n=this.usageEntries(); let hit=null;
    [['m1',50,14],['m2',150,45],['m3',300,90]].forEach(([id,e,d])=>{ if(n>=e&&u.days>=d&&!u.asked.includes(id))hit={id,e}; }); return hit; } // highest pending only
  maybeAsk(){ const s=this.state; if(s.screen!=='app'||s.vaultLocked||s.dialog||s.overlay||s.donateToastOpen)return; const m=this.usagePending(); if(!m)return;
    const u=this.usageGet(),order=['m1','m2','m3']; order.slice(0,order.indexOf(m.id)+1).forEach(x=>{if(!u.asked.includes(x))u.asked.push(x);}); u.lastAsk=this.today(); this.usageSave(u);
    this.setState({donateToastOpen:true,donateView:'main',donateMs:m.e+' entries'}); }
  cosmDef(){ return {mark:'keep',glyph:'classic',halo:false,ring:false,shape:'circle',global:'bone',link:'default',dots:'spectrum',backdrop:'plain',badge:'none',icon:'keep',flourish:'off',trail:'standard'}; }
  cosmOpts(){ return {mark:['keep','cells','node','seal'],glyph:['classic','fine','heavy'],shape:['circle','hexagon','square','octagon','diamond'],global:['bone','sig','ash','tint'],link:['default','ash','bone','sig'],dots:['spectrum','cool','warm','mono'],backdrop:['plain','dots','lines','rings'],badge:['none','ring','stamp'],icon:['keep','keepbone','cells','node','seal','keepsig'],flourish:['off','on'],trail:['standard','comet','dotted']}; }
  cosmClean(o){ o=o||{}; const d=this.cosmDef(),opt=this.cosmOpts(),r={...d}; for(const k in opt)r[k]=opt[k].includes(o[k])?o[k]:d[k]; r.halo=!!o.halo; if(!opt.badge.includes(o.badge))r.badge=o.ring?'ring':'none'; r.ring=r.badge==='ring'; return r; } // allow-list; v1 objects migrate (ring:true -> badge:'ring')
  shapePath(ctx,x,y,r,sh){ const pk=this.state.pack,d=pk&&pk.shapes&&pk.shapes[sh]; ctx.beginPath(); if(!d){ctx.arc(x,y,r,0,2*Math.PI);return;}
    if(d.half){ const q=r*d.half; if(ctx.roundRect)ctx.roundRect(x-q,y-q,2*q,2*q,r*d.corner); else ctx.rect(x-q,y-q,2*q,2*q); return; }
    for(let i=0;i<d.n;i++){ const a=(d.rot+360*i/d.n)*Math.PI/180,px=x+r*Math.cos(a),py=y+r*Math.sin(a); if(i)ctx.lineTo(px,py); else ctx.moveTo(px,py); } ctx.closePath(); }
  globalFill(p){ const c=this._ce||this.cosmEff(),pk=this.state.pack,k=pk&&pk.global&&pk.global[c.global]; if(!k)return p.bone; const e=this.eff(),dark=e.theme==='dark';
    if(k==='sig')return dark?(p.sigHi||p.sig):p.sig; if(k==='ash')return p.ash; const hu=e.colour==='off'?211:e.hue; return dark?'oklch(0.80 0.06 '+hu+')':'oklch(0.45 0.07 '+hu+')'; }
  linkStyle(ctx,p){ const c=this._ce||this.cosmEff(),pk=this.state.pack,k=pk&&pk.link&&pk.link[c.link]; if(!k){ctx.strokeStyle=p.hairS;return;} const a=k.split('@'); ctx.strokeStyle=p[a[0]]||p.hairS; if(a[1])ctx.globalAlpha*=+a[1]; }
  paintBackdrop(ctx,cv,dpr){ const c=this._ce,pk=this.state.pack,bd=pk&&pk.backdrop&&pk.backdrop[c.backdrop]; if(!bd||this.gv.k<0.4)return;
    const {k,tx,ty}=this.gv,W=cv.width/dpr,H=cv.height/dpr,x0=-tx/k,y0=-ty/k,x1=(W-tx)/k,y1=(H-ty)/k,st=bd.step,p=this.palette(); if((x1-x0)/st*((y1-y0)/st)>9000)return;
    ctx.save(); ctx.lineWidth=1/k; const a=Math.floor(x0/st)*st,b=Math.floor(y0/st)*st;
    if(bd.k==='dots'){ ctx.fillStyle=p.hairS; const z=1.6/k; for(let x=a;x<=x1;x+=st)for(let y=b;y<=y1;y+=st)ctx.fillRect(x-z/2,y-z/2,z,z); }
    else if(bd.k==='lines'){ ctx.strokeStyle=p.hair||p.hairS; ctx.beginPath(); for(let x=a;x<=x1;x+=st){ctx.moveTo(x,y0);ctx.lineTo(x,y1);} for(let y=b;y<=y1;y+=st){ctx.moveTo(x0,y);ctx.lineTo(x1,y);} ctx.stroke(); }
    else { const g=this.gd.nodes.find(o=>o.kind==='global'); if(g){ ctx.strokeStyle=p.hair||p.hairS; const R=Math.max(Math.hypot(x0-g.x,y0-g.y),Math.hypot(x1-g.x,y0-g.y),Math.hypot(x0-g.x,y1-g.y),Math.hypot(x1-g.x,y1-g.y)); ctx.beginPath(); for(let r=st,i=0;r<=R&&i<80;r+=st,i++){ctx.moveTo(g.x+r,g.y);ctx.arc(g.x,g.y,r,0,2*Math.PI);} ctx.stroke(); } }
    ctx.restore(); }
  isReduced(){ const m=this.state.motion; return m==='reduced'||(m==='system'&&!!(window.matchMedia&&matchMedia('(prefers-reduced-motion: reduce)').matches)); }
  startFlourish(){ const on=this.cosmEff().flourish==='on'&&!this.isReduced(); clearTimeout(this._flT); if(on)this._flT=setTimeout(()=>this.setState({flourishOn:false}),1100); return on; }
  stampText(){ const n=this.usageEntries(),v=[300,150,50,10].find(x=>n>=x); return v?String(v):''; }
  msIds(){ return ['proj1','e10','e50','e150','e300','p5','grant','d30','d90']; }
  msState(u){ const v=this.vault,n=this.usageEntries(),pr=(v.nodes||[]).filter(x=>x.kind==='project').length; return {proj1:pr>=1,e10:n>=10,e50:n>=50,e150:n>=150,e300:n>=300,p5:pr>=5,grant:(v.grants||[]).length>0,d30:u.days>=30,d90:u.days>=90}; }
  marksSync(){ const u=this.usageGet(),st=this.msState(u),t=this.today(); let ch=false; for(const k of this.msIds())if(st[k]&&!u.marks[k]){u.marks[k]=t;ch=true;} if(ch)this.usageSave(u); }
  msRows(sync){ if(sync)this.marksSync(); const u=this.usageGet(),L={proj1:'first project',e10:'10 entries',e50:'50 entries',e150:'150 entries',e300:'300 entries',p5:'5 projects',grant:'first grant',d30:'30 days in use',d90:'90 days in use'};
    return this.msIds().map(k=>({label:L[k],when:u.marks[k]||'not yet',border:u.marks[k]?'var(--bone)':'var(--mute)',fill:u.marks[k]?'var(--bone)':'transparent'})); }
  packLoad(code){ return this.extrasUnlock(code,false); } // dev handle: opens the pack for this session only, stores nothing
  polyPts(cx,cy,r,d){ return Array.from({length:d.n},(_,i)=>{const a=(d.rot+360*i/d.n)*Math.PI/180;return (cx+r*Math.cos(a)).toFixed(2)+','+(cy+r*Math.sin(a)).toFixed(2);}).join(' '); }
  treeShape(sh,r){ const pk=this.state.pack,d=pk&&pk.shapes&&pk.shapes[sh]; const z={gCircle:false,gPoly:false,gRect:false,gpts:'',gx:0,gw:0,grx:0};
    if(!d)return {...z,gCircle:true}; if(d.half){ const q=r*d.half; return {...z,gRect:true,gx:12-q,gw:2*q,grx:r*d.corner}; } return {...z,gPoly:true,gpts:this.polyPts(12,12,r,d)}; }
  drawCosmPreview(){ const cv=document.querySelector('[data-cosm-preview]'); if(!cv||!this.gd)return; const ctx=cv.getContext('2d'); ctx.setTransform(2,0,0,2,0,0); ctx.clearRect(0,0,240,140);
    const p=this.palette(),ce=this.cosmEff(),pk=this.state.pack,prev=this._ce,pf=this._cosmFx; this._ce=ce; this._cosmFx=ce; const G={x:120,y:70},bd=pk&&pk.backdrop&&pk.backdrop[ce.backdrop];
    ctx.save(); if(bd){ ctx.strokeStyle=p.hair||p.hairS; ctx.fillStyle=p.hairS; ctx.lineWidth=1; if(bd.k==='dots'){ for(let x=8;x<240;x+=16)for(let y=6;y<140;y+=16)ctx.fillRect(x-.75,y-.75,1.5,1.5); } else if(bd.k==='lines'){ ctx.beginPath(); for(let x=8;x<240;x+=16){ctx.moveTo(x,0);ctx.lineTo(x,140);} for(let y=6;y<140;y+=16){ctx.moveTo(0,y);ctx.lineTo(240,y);} ctx.stroke(); } else { ctx.beginPath(); for(let r=28;r<150;r+=28){ctx.moveTo(G.x+r,G.y);ctx.arc(G.x,G.y,r,0,2*Math.PI);} ctx.stroke(); } }
    const A={x:52,y:40},B={x:192,y:102}; ctx.lineWidth=1; for(const T of [A,B]){ ctx.save(); this.linkStyle(ctx,p); ctx.beginPath(); ctx.moveTo(G.x,G.y); ctx.lineTo(T.x,T.y); ctx.stroke(); ctx.restore(); }
    for(const [T,i] of [[A,0],[B,1]]){ for(let k=0;k<4;k++){ const a=k*1.7+i, ex=T.x+Math.cos(a)*26, ey=T.y+Math.sin(a)*26; ctx.fillStyle=this.entryColor('pv'+i+k); ctx.beginPath(); ctx.arc(ex,ey,2.6,0,7); ctx.fill(); } }
    ctx.fillStyle=this.globalFill(p); this.shapePath(ctx,G.x,G.y,18,ce.shape); ctx.fill();
    for(const [T,i] of [[A,3],[B,5]]){ ctx.strokeStyle=p.bone; ctx.lineWidth=1.5; this.shapePath(ctx,T.x,T.y,13,ce.shape); ctx.stroke(); this.drawGlyph(ctx,T.x,T.y,13*0.42,i,p.bone); }
    ctx.restore(); this._ce=prev; this._cosmFx=pf; }
  cosmGroups(on){
    const cur=on?this.state.cosm:this.cosmDef(), poly=(n,rot,r)=>Array.from({length:n},(_,i)=>{const a=(rot+360*i/n)*Math.PI/180;return (r*Math.cos(a)).toFixed(1)+','+(r*Math.sin(a)).toFixed(1);}).join(' ');
    const pts={circle:poly(24,0,7),hexagon:poly(6,-90,7),square:poly(4,45,5.1),octagon:poly(8,-67.5,7),diamond:poly(4,-90,7)};
    const T=(m,bg,fg)=>({m,bg,fg});
    const g=(title,caption,key,items,badge)=>({title,caption,hasBadge:!!badge,badgeTitle:badge||'',opts:items.map(([val,label,sw,pt,tl])=>{const isOn=cur[key]===val;return {label,on:isOn,disabled:!on,set:()=>this.setCosm({[key]:val}),bg:isOn?'var(--bone)':'transparent',fg:isOn?'var(--void)':'var(--ash)',hasPts:!!pt,pts:pt||'',hasSw:!!sw,sw:sw||'none',hasTile:!!tl,tileBg:tl?tl.bg:'none',tileFg:tl?tl.fg:'none',tK:!!tl&&tl.m==='keep',tC:!!tl&&tl.m==='cells',tN:!!tl&&tl.m==='node',tS:!!tl&&tl.m==='seal'};})});
    const sp=(a,b)=>'linear-gradient(90deg,oklch(0.74 0.125 '+a+'),oklch(0.74 0.125 '+b+'))';
    return {
      graph:[
        g('Node shape','project and sub-node bodies in the graph, the worktree and CredPong; high contrast and greyscale proof show the defaults','shape',[['circle','circle',0,pts.circle],['hexagon','hexagon',0,pts.hexagon],['square','rounded square',0,pts.square],['octagon','octagon',0,pts.octagon],['diamond','diamond',0,pts.diamond]]),
        g('Global node colour','the filled node at the centre','global',[['bone','bone','var(--bone)'],['sig','signal','var(--sig-hi)'],['ash','ash','var(--ash)'],['tint','tint','oklch(0.7 0.06 211)']]),
        g('Link colour','structural links; grant links keep their colour and dashes','link',[['default','default','var(--hair-strong)'],['ash','ash','var(--ash)'],['bone','bone','var(--bone)'],['sig','signal','var(--sig)']]),
        g('Entry dot palette','the hue range of the dots around each node','dots',[['spectrum','spectrum',sp(0,300)],['cool','cool',sp(160,260)],['warm','warm',sp(20,80)],['mono','mono','var(--ash)']]),
        g('Graph backdrop','drawn under the graph; hidden when zoomed far out','backdrop',[['plain','plain'],['dots','dot grid'],['lines','line grid'],['rings','rings']])],
      identity:[
        g('Header badge','beside the vault name in the header: a small ring, or the highest entry milestone you have reached','badge',[['none','none'],['ring','ring'],['stamp','milestone stamp']]),
        g('App icon','the dock or taskbar icon, shown here on its own tile','icon',[['keep','keep on void',0,0,T('keep','var(--void)','var(--bone)')],['keepbone','keep on bone',0,0,T('keep','var(--bone)','var(--void)')],['cells','cells',0,0,T('cells','var(--void)','var(--bone)')],['node','node',0,0,T('node','var(--void)','var(--bone)')],['seal','seal',0,0,T('seal','var(--void)','var(--bone)')],['keepsig','keep on signal',0,0,T('keep','var(--sig)','var(--void)')]],'app.icon.set: setting the operating-system icon needs a shell operation that 2.0.0-beta.1 does not have; the choice is kept and previewed here')],
      motion:[g('Unlock flourish','the app mark draws itself when you unlock, then fades; the app is usable at once; off under reduced motion','flourish',[['off','off'],['on','on']])],
      games:[g('CredPong ball trail','the ball’s tail; speed, balance and hit boxes are unchanged','trail',[['standard','standard'],['comet','comet'],['dotted','dotted']])]
    }; }
  // Fields (S5a): add, edit, move, remove — the field.* ops (ADR-078). Reveal keys are index-based, so any change re-masks the entry.
  cleanText(v){ return String(v==null?'':v).normalize('NFC').replace(/[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g,''); } // strips zero-width and bidi controls from names and labels (spoofing)
  foldName(v){ return this.cleanText(v).normalize('NFKC').toLowerCase().trim(); } // NFKC + case fold: used for ids
  dupKey(v){ const m=this.CONFUSABLES; return Array.from(this.foldName(v)).map(ch=>m[ch]||ch).join(''); } // T4: the duplicate guard also maps Cyrillic / Greek look-alikes to their Latin twin (table: FRONTEND_THREAT_MODEL.md T4; the backend applies the same fold)
  scriptMix(v){ const s=this.cleanText(v); return /[A-Za-z]/.test(s)&&/[\u0370-\u03FF\u0400-\u04FF\u0500-\u052F]/.test(s); } // Latin letters next to Greek or Cyrillic ones
  CONFUSABLES={'\u0430':'a','\u0435':'e','\u043E':'o','\u0440':'p','\u0441':'c','\u0443':'y','\u0445':'x','\u0456':'i','\u0458':'j','\u0455':'s','\u0501':'d','\u04BB':'h','\u051B':'q','\u051D':'w','\u04CF':'l','\u0131':'i','\u03BF':'o','\u03B1':'a','\u03BD':'v','\u03C1':'p','\u03B9':'i','\u03BA':'k','\u03C5':'u','\u03C7':'x','\u0261':'g','\u0262':'g'};
  openEntryRef(){ const s=this.state; return (this.vault.entries[s.selected]||[]).find(x=>x.id===s.openEntry)||null; }
  clearEntryReveals(id){ this.setState(st=>{ const rv={},cp={}; for(const k in st.reveals)if(!k.startsWith(id+':'))rv[k]=st.reveals[k]; for(const k in st.copied)if(!k.startsWith(id+':'))cp[k]=st.copied[k]; return {reveals:rv,copied:cp}; }); }
  openFieldDlg(mode,idx){ const e=this.openEntryRef(); if(!e||this.state.vaultLocked)return; const f=idx!=null?e.fields[idx]:null;
    if(idx!=null)this._openerEl=document.querySelector('.cm-fieldmenu-btn[aria-expanded="true"]'); // B5-2: the menu item unmounts as the dialog opens; restore to the row's ⋮
    this.setState({fieldMenu:null,dialog:'field',fd:{mode,idx,label:f?f.label:'',value:'',type:f?f.type:'text',masked:f&&f.masked?'yes':'no',err:''}}); }
  moveField(idx,dir){ const e=this.openEntryRef(); if(!e||this.state.vaultLocked)return; const j=idx+dir; if(j<0||j>=e.fields.length)return; const fs=[...e.fields]; [fs[idx],fs[j]]=[fs[j],fs[idx]]; e.fields=fs; this.clearEntryReveals(e.id); this.setState({fieldMenu:null}); }
  saveFieldDlg(){ const s=this.state, fd=s.fd, e=this.openEntryRef(); if(!fd||!e)return;
    if(s.vaultLocked){ this.setState({fd:{...fd,err:'The vault is locked. Unlock it to change fields.'}}); return; }
    const label=this.cleanText(fd.label||'').trim();
    if(fd.mode==='add'){ if(!fd.value){ this.setState({fd:{...fd,err:'A field needs a value.'}}); return; } const ty=this.inferType(label,fd.value); e.fields=[...e.fields,{label,value:fd.value,type:ty,masked:this.typeMasked(ty)}]; }
    else if(fd.mode==='edit'){ const f=e.fields[fd.idx]; if(!f)return; const nf={...f,label,type:fd.type,masked:fd.masked==='yes'}; if(fd.value)nf.value=fd.value; e.fields=e.fields.map((x,k)=>k===fd.idx?nf:x); }
    else if(fd.mode==='remove'){ if(e.fields.length<=1)return; e.fields=e.fields.filter((x,k)=>k!==fd.idx); }
    this.clearEntryReveals(e.id); this.setState({dialog:null,fd:null}); }
  // Operations (S14): the four built ops run here; the rest are designed and not in 2.0.0-beta.1.
  hhmm(){ const d=new Date(); return String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0'); }
  runOp(id){ const at=this.hhmm(), nE=Object.values(this.vault.entries).reduce((a,l)=>a+l.length,0), nN=this.vault.nodes.length;
    const R={
      verify:{title:'verify · ok',lines:[[nE+' entries checked against their manifest digests · 0 mismatches','ok'],[nN+' manifests · checksums ok','ok']]},
      doctor:{title:'doctor · dry run',lines:[['registry consistent · 0 dangling refs · nothing to repair','ok'],['a registry rebuild needs presence and is refused in 2.0.0-beta.1','mute']]},
      backup:{title:'backup · written',lines:[['encrypted archive written to the vault folder › backups','ok'],['it opens only with the passphrase chosen for it','mute']]},
      rotate:{title:'rotate root key · refused',lines:[['presence_required — the broker needs a Touch ID attestation, which 2.0.0-beta.1 cannot give yet','warn'],['nothing was changed; the current recovery code stays valid','mute']]}
    }[id]; if(!R)return;
    this.setState({overlay:'ops',opsResult:{...R,at},...(id==='verify'?{verifiedAt:at}:{}),...(id==='backup'?{backupAt:at}:{})}); }
  // CredPong — a light, local, isolated arcade game (see BACKEND_HANDOFF_NOTES.md for the
  // marketplace/multiplayer phase this deliberately does NOT build yet). Reuses this.formationSlots /
  // nodeGlyphIdx / entryColor / drawGlyph from the graph for visual continuity. Only ever reads node
  // ids and entry counts — never names or values — same boundary as the graph's entry dots.
  cpBestKey(){return 'credpong_best';}
  cpBest(){try{return parseInt(localStorage.getItem(this.cpBestKey())||'0',10)||0;}catch(e){return 0;}}
  cpSaveBest(score){try{if(score>this.cpBest())localStorage.setItem(this.cpBestKey(),String(score));}catch(e){}}
  cpProgressKey(){return 'credpong_level';}
  cpSavedLevel(){try{return Math.max(1,parseInt(localStorage.getItem(this.cpProgressKey())||'1',10)||1);}catch(e){return 1;}}
  cpSaveLevel(level){try{if(level>this.cpSavedLevel())localStorage.setItem(this.cpProgressKey(),String(level));}catch(e){}}
  cpModeDescFor(m){return m==='side'?'Paddle fixed to one side (random each run), moves along it.':m==='roam'?'Paddle roams the whole edge, follows your cursor. All four sides are open.':'Classic — paddle at the bottom, moves left/right.';}
  cpStart(){ this.setState({overlay:'games',gameId:'credpong',gameScreen:'play'},()=>this.cpInit()); }
  cpInit(){
    const el=this.cpRef&&this.cpRef.current; if(!el)return;
    this.cpStopListeners();
    el.innerHTML=''; const cv=document.createElement('canvas'); cv.width=680; cv.height=440;
    cv.style.cssText='position:absolute;inset:0;width:100%;height:100%'; el.appendChild(cv);
    const mode=this.state.cpMode||'bottom';
    this.cp={ cv, ctx:cv.getContext('2d'), mode, level:1, score:0, lives:3, entriesPopped:0, paused:false,
      keys:{left:false,right:false,up:false,down:false}, mouse:{x:340,y:220}, launch:false,
      side: mode==='side'?(Math.random()<0.5?'left':'right'):null,
      ball:{x:340,y:400,vx:0,vy:0,r:5,resting:true}, trail:[], levelT0:performance.now(), banner:null };
    this.cpBuildLevel(this.cpSavedLevel());
    this._cpKeyDown=(e)=>{ if(['ArrowLeft','ArrowRight','ArrowUp','ArrowDown',' '].includes(e.key))e.preventDefault();
      if(e.key==='ArrowLeft')this.cp.keys.left=true; if(e.key==='ArrowRight')this.cp.keys.right=true;
      if(e.key==='ArrowUp')this.cp.keys.up=true; if(e.key==='ArrowDown')this.cp.keys.down=true;
      if(e.key===' ')this.cp.launch=true; };
    this._cpKeyUp=(e)=>{ if(e.key==='ArrowLeft')this.cp.keys.left=false; if(e.key==='ArrowRight')this.cp.keys.right=false;
      if(e.key==='ArrowUp')this.cp.keys.up=false; if(e.key==='ArrowDown')this.cp.keys.down=false; };
    this._cpMouseMove=(e)=>{ const r=cv.getBoundingClientRect(); this.cp.mouse.x=(e.clientX-r.left)*680/r.width; this.cp.mouse.y=(e.clientY-r.top)*440/r.height; };
    window.addEventListener('keydown',this._cpKeyDown); window.addEventListener('keyup',this._cpKeyUp); cv.addEventListener('mousemove',this._cpMouseMove);
    this._cpRaf=requestAnimationFrame(this.cpLoop=this.cpLoop.bind(this));
  }
  cpPaddleInit(){ const c=this.cp;
    if(c.mode==='bottom')c.paddle={edge:'bottom',pos:340,len:90};
    else if(c.mode==='side')c.paddle={edge:c.side,pos:220,len:90};
    else c.paddle={edge:'bottom',pos:340,len:70,roam:true};
    this.cpRestBall();
  }
  cpRestBall(){ const c=this.cp,p=c.paddle,pt=this.cpEdgePoint(p.edge,p.pos);
    c.ball.x=pt.x; c.ball.y=pt.y; c.ball.vx=0; c.ball.vy=0; c.ball.resting=true; }
  cpEdgePoint(edge,pos){ const W=680,H=440,m=14;
    if(edge==='bottom')return{x:pos,y:H-m}; if(edge==='top')return{x:pos,y:m};
    if(edge==='left')return{x:m,y:pos}; return{x:W-m,y:pos}; }
  cpBuildLevel(level){
    const c=this.cp; c.level=level; c.levelT0=performance.now();
    const W=680,H=440,pad=60,nodes=[];
    let realNodes=[];
    if(level<=3) realNodes=this.vault.nodes.filter(n=>n.kind!=='global'&&n.kind!=='orphan')
      .slice().sort((a,b)=>(a.counts.entries||0)-(b.counts.entries||0)).slice(0,Math.min(level+1,5));
    const count=level<=3?realNodes.length:Math.min(6,2+Math.floor(level/2));
    for(let i=0;i<count;i++){
      let entryCount,glyphIdx,color,id;
      if(level<=3&&realNodes[i]){ const rn=realNodes[i]; id=rn.id; entryCount=(this.vault.entries[rn.id]||[]).length||1;
        glyphIdx=this.nodeGlyphIdx(rn.id); color=this.entryColor(rn.id); }
      else { id='gen-'+level+'-'+i; entryCount=2+Math.floor(Math.random()*Math.min(10,3+level)); glyphIdx=this.hashStr(id)%14; color=this.entryColor(id); }
      const hits=Math.min(entryCount,5), slots=this.formationSlots(hits);
      let bx=W/2,by=H/2,tries=0;
      do{ bx=pad+Math.random()*(W-pad*2); by=pad+20+Math.random()*160; tries++; }
      while(tries<20&&nodes.some(n=>Math.hypot(n.baseX-bx,n.baseY-by)<90));
      const shellR=10+6*Math.sqrt(Math.min(20,hits)/5);
      const entries=slots.map(slot=>({slot,alive:true,ring:shellR+16+slot.r*16}));
      nodes.push({id,baseX:bx,baseY:by,shellR,glyphIdx,color,hits,entries,alive:true,driftPhase:Math.random()*6.28,driftAmp:10+Math.random()*8,pop:0,coreLeft:2,coreFlash:0});
    }
    c.nodes=nodes;
    c.banner={text:'Level '+level,until:performance.now()+900};
    this.cpPaddleInit();
  }
  cpNodePos(n,t){ return {x:n.baseX+Math.sin(t*0.0013+n.driftPhase)*n.driftAmp, y:n.baseY+Math.cos(t*0.0011+n.driftPhase*1.4)*n.driftAmp*0.6}; }
  cpSpeed(c){ const base=3.1*(1+c.level*0.055)*0.58, elapsed=(performance.now()-c.levelT0)/1000; return base*(1+Math.min(0.4,elapsed*0.0025)); }
  cpLoop(){
    if(!this.cp||this.state.overlay!=='games'||this.state.gameScreen!=='play')return;
    this.cpUpdate(); this.cpDraw();
    this._cpRaf=requestAnimationFrame(this.cpLoop);
  }
  cpUpdate(){
    const c=this.cp; if(c.paused)return; // C-5
    const W=680,H=440,p=c.paddle,b=c.ball;
    if(c.mode==='bottom'){ let v=0; if(c.keys.left)v-=4.6; if(c.keys.right)v+=4.6;
      p.vel=(p.vel||0)*0.8+v*0.2; p.pos=Math.min(W-14-p.len/2,Math.max(14+p.len/2,p.pos+p.vel)); }
    else if(c.mode==='side'){ let v=0; if(c.keys.up)v-=4.6; if(c.keys.down)v+=4.6;
      p.vel=(p.vel||0)*0.8+v*0.2; p.pos=Math.min(H-14-p.len/2,Math.max(14+p.len/2,p.pos+p.vel)); }
    else { const mx=c.mouse.x,my=c.mouse.y,dl=mx,dr=W-mx,dt=my,db=H-my,min=Math.min(dl,dr,dt,db);
      let edge,pos; if(min===dt){edge='top';pos=mx;} else if(min===db){edge='bottom';pos=mx;} else if(min===dl){edge='left';pos=my;} else {edge='right';pos=my;}
      p.edge=edge; p.pos=Math.min((edge==='top'||edge==='bottom'?W:H)-14-p.len/2,Math.max(14+p.len/2,pos)); }
    if(b.resting){ const pt=this.cpEdgePoint(p.edge,p.pos); b.x=pt.x; b.y=pt.y;
      if(c.launch){ c.launch=false; b.resting=false; const sp=this.cpSpeed(c);
        const inward={top:[0,1],bottom:[0,-1],left:[1,0],right:[-1,0]}[p.edge];
        const tangent=(p.edge==='top'||p.edge==='bottom')?[1,0]:[0,1], spread=(Math.random()-0.5)*0.9;
        b.vx=inward[0]+tangent[0]*spread; b.vy=inward[1]+tangent[1]*spread;
        const mg=Math.hypot(b.vx,b.vy)||1; b.vx=b.vx/mg*sp; b.vy=b.vy/mg*sp; }
      return; }
    b.x+=b.vx; b.y+=b.vy;
    c.trail.push({x:b.x,y:b.y}); if(c.trail.length>(this.cosmEff().trail==='comet'?24:10))c.trail.shift();
    const now=performance.now();
    for(const n of c.nodes){ if(!n.alive)continue; const np=this.cpNodePos(n,now);
      let hitEntry=false;
      for(const en of n.entries){ if(!en.alive)continue;
        const ang=en.slot.a+now*en.slot.rot, ex=np.x+Math.cos(ang)*en.ring, ey=np.y+Math.sin(ang)*en.ring, d=Math.hypot(b.x-ex,b.y-ey);
        if(d<b.r+4){ en.alive=false; n.hits--; c.score+=10;
          c.entriesPopped=(c.entriesPopped||0)+1; if(c.entriesPopped%2===0&&c.lives<4){ c.lives++; c.banner={text:'+1 life',until:now+700}; }
          const nx=(b.x-ex)/(d||1),ny=(b.y-ey)/(d||1), dot=b.vx*nx+b.vy*ny; b.vx-=2*dot*nx; b.vy-=2*dot*ny;
          b.x=ex+nx*(b.r+4.2); b.y=ey+ny*(b.r+4.2);
          if(n.hits<=0){ n.alive=false; n.pop=now; c.score+=50; }
          hitEntry=true; break; } }
      if(!hitEntry){ const dcx=Math.hypot(b.x-np.x,b.y-np.y), rc=b.r+n.shellR;
        if(dcx<rc){ n.coreLeft--; c.score+=10; n.coreFlash=now;
          const nx=(b.x-np.x)/(dcx||1),ny=(b.y-np.y)/(dcx||1), dot=b.vx*nx+b.vy*ny; b.vx-=2*dot*nx; b.vy-=2*dot*ny;
          b.x=np.x+nx*(rc+0.6); b.y=np.y+ny*(rc+0.6);
          if(n.coreLeft<=0){ n.alive=false; n.pop=now; c.score+=50; for(const en2 of n.entries)en2.alive=false; } } } }
    if(c.nodes.every(n=>!n.alive)){ this.cpNextLevel(); return; }
    const m=14;
    const hitPaddle=(edge)=>{ if(p.edge!==edge)return false; const along=(edge==='top'||edge==='bottom')?b.x:b.y; return Math.abs(along-p.pos)<=p.len/2+b.r; };
    if(c.mode==='roam'){
      let missed=false;
      if(b.x<m){ if(hitPaddle('left')){b.vx=Math.abs(b.vx);b.x=m+b.r;} else missed=true; }
      else if(b.x>W-m){ if(hitPaddle('right')){b.vx=-Math.abs(b.vx);b.x=W-m-b.r;} else missed=true; }
      if(!missed){ if(b.y<m){ if(hitPaddle('top')){b.vy=Math.abs(b.vy);b.y=m+b.r;} else missed=true; }
        else if(b.y>H-m){ if(hitPaddle('bottom')){b.vy=-Math.abs(b.vy);b.y=H-m-b.r;} else missed=true; } }
      if(missed)this.cpLoseLife();
    } else {
      const openEdge=c.mode==='bottom'?'bottom':c.side;
      if(b.x<m){ if(openEdge==='left'){ if(hitPaddle('left')){b.vx=Math.abs(b.vx);b.x=m+b.r;} else this.cpLoseLife(); } else {b.vx=Math.abs(b.vx);b.x=m+b.r;} }
      else if(b.x>W-m){ if(openEdge==='right'){ if(hitPaddle('right')){b.vx=-Math.abs(b.vx);b.x=W-m-b.r;} else this.cpLoseLife(); } else {b.vx=-Math.abs(b.vx);b.x=W-m-b.r;} }
      if(b.y<m){ if(openEdge==='top'){ if(hitPaddle('top')){b.vy=Math.abs(b.vy);b.y=m+b.r;} else this.cpLoseLife(); } else {b.vy=Math.abs(b.vy);b.y=m+b.r;} }
      else if(b.y>H-m){ if(openEdge==='bottom'){ if(hitPaddle('bottom')){b.vy=-Math.abs(b.vy);b.y=H-m-b.r;} else this.cpLoseLife(); } else {b.vy=-Math.abs(b.vy);b.y=H-m-b.r;} }
    }
  }
  cpLoseLife(){ const c=this.cp; if(!c||c.ball.resting)return; c.lives--; c.trail=[];
    c.banner={text:c.lives>0?'−1 life':'',until:performance.now()+700};
    if(c.lives<=0)this.cpGameOver(); else this.cpRestBall(); }
  cpNextLevel(){ const lvl=(this.cp.level||1)+1; this.cpSaveLevel(lvl); this.cpBuildLevel(lvl); }
  cpGameOver(){ this.cpSaveBest(this.cp.score); this.cpStopListeners(); this.setState({gameScreen:'over'}); }
  cpDraw(){
    const c=this.cp,ctx=c.ctx,p=this.palette(),W=680,H=440,now=performance.now(),cs=this.cosmEff();
    ctx.clearRect(0,0,W,H); ctx.fillStyle=p.void||'#0b0d10'; ctx.fillRect(0,0,W,H);
    for(const n of c.nodes){ if(!n.alive&&now-n.pop>260)continue;
      const np=this.cpNodePos(n,now), fade=n.alive?1:Math.max(0,1-(now-n.pop)/260), scale=n.alive?1:1+(1-fade)*0.6;
      ctx.save(); ctx.globalAlpha=fade;
      for(const en of n.entries){ if(!en.alive)continue; const ang=en.slot.a+now*en.slot.rot, ex=np.x+Math.cos(ang)*en.ring, ey=np.y+Math.sin(ang)*en.ring;
        ctx.strokeStyle=n.color; ctx.globalAlpha=fade*0.4; ctx.lineWidth=0.8; ctx.beginPath(); ctx.moveTo(np.x,np.y); ctx.lineTo(ex,ey); ctx.stroke();
        ctx.globalAlpha=fade; ctx.fillStyle=n.color; ctx.beginPath(); ctx.arc(ex,ey,3.4,0,7); ctx.fill(); }
      ctx.strokeStyle=n.color; ctx.lineWidth=n.coreLeft===1?2.4:1.4; this.shapePath(ctx,np.x,np.y,n.shellR*scale,cs.shape); ctx.stroke();
      if(n.alive&&n.coreFlash&&now-n.coreFlash<160){ ctx.globalAlpha=fade*(1-(now-n.coreFlash)/160); ctx.lineWidth=2; ctx.beginPath(); ctx.arc(np.x,np.y,n.shellR*scale+5,0,7); ctx.stroke(); ctx.globalAlpha=fade; }
      this.drawGlyph(ctx,np.x,np.y,n.shellR*0.5*scale,n.glyphIdx,n.color);
      ctx.restore(); }
    for(let i=0;i<c.trail.length;i++){ const t=c.trail[i], f=(i+1)/c.trail.length; ctx.fillStyle=p.bone;
      if(cs.trail==='comet'){ ctx.globalAlpha=f*0.45; ctx.beginPath(); ctx.arc(t.x,t.y,c.ball.r*(0.25+0.65*f),0,7); ctx.fill(); }
      else if(cs.trail==='dotted'){ if(i%2)continue; ctx.globalAlpha=f*0.55; ctx.beginPath(); ctx.arc(t.x,t.y,c.ball.r*0.35,0,7); ctx.fill(); }
      else { ctx.globalAlpha=f*0.35; ctx.beginPath(); ctx.arc(t.x,t.y,c.ball.r*0.8,0,7); ctx.fill(); } }
    ctx.globalAlpha=1; ctx.fillStyle=p.bone; ctx.beginPath(); ctx.arc(c.ball.x,c.ball.y,c.ball.r,0,7); ctx.fill();
    const pd=c.paddle; ctx.fillStyle=p.bone;
    if(pd.edge==='bottom')ctx.fillRect(pd.pos-pd.len/2,H-18,pd.len,7);
    else if(pd.edge==='top')ctx.fillRect(pd.pos-pd.len/2,11,pd.len,7);
    else if(pd.edge==='left')ctx.fillRect(11,pd.pos-pd.len/2,7,pd.len);
    else ctx.fillRect(W-18,pd.pos-pd.len/2,7,pd.len);
    ctx.font='500 12px "JetBrains Mono", ui-monospace, monospace'; ctx.fillStyle=p.ash; ctx.textBaseline='top';
    ctx.textAlign='left'; ctx.fillText('score '+c.score,10,8);
    ctx.textAlign='right'; ctx.fillText('lv '+c.level,W-10,8);
    ctx.textAlign='left'; ctx.fillText('◆'.repeat(Math.max(0,c.lives)),10,24);
    if(c.ball.resting){ ctx.textAlign='center'; ctx.fillText('space to launch',W/2,H/2-8); }
    if(c.banner&&now<c.banner.until){ ctx.save(); ctx.globalAlpha=Math.min(1,(c.banner.until-now)/300);
      ctx.font='600 20px "JetBrains Mono", ui-monospace, monospace'; ctx.textAlign='center'; ctx.fillStyle=p.bone; ctx.fillText(c.banner.text,W/2,H/2-40); ctx.restore(); }
    if(c.paused){ ctx.save(); ctx.fillStyle='rgba(0,0,0,0.5)'; ctx.fillRect(0,0,W,H); // C-5: pause overlay
      ctx.font='600 24px "JetBrains Mono", ui-monospace, monospace'; ctx.textAlign='center'; ctx.fillStyle=p.bone; ctx.fillText('paused',W/2,H/2-8);
      ctx.font='500 12px "JetBrains Mono", ui-monospace, monospace'; ctx.fillText('P or Esc to resume · Esc again to exit',W/2,H/2+18); ctx.restore(); }
  }
  cpStopListeners(){ if(this._cpRaf)cancelAnimationFrame(this._cpRaf); this._cpRaf=null;
    if(this._cpKeyDown)window.removeEventListener('keydown',this._cpKeyDown);
    if(this._cpKeyUp)window.removeEventListener('keyup',this._cpKeyUp);
    if(this.cp&&this.cp.cv&&this._cpMouseMove)this.cp.cv.removeEventListener('mousemove',this._cpMouseMove); }
  cpExit(){ this.cpStopListeners(); this.ghStop(); this.setState({overlay:null,gameScreen:'library'}); }
  cpBackToMenu(){ this.cpStopListeners(); this.setState({gameScreen:'menu'}); }
  // CredGames host (GAMES.md). CredPong is built in and keeps its own engine and keys. Every further game is a plain local
  // script, games/<id>.js, that pushes a definition onto window.CredGames; the host validates it, owns the canvas, the loop,
  // pause and exit, scores and storage, and hands the game a frozen api whose only vault data is counts.
  gamesList(){
    const out=[{id:'credpong',name:'CredPong',blurb:'Battle your vault’s nodes: keep the ball in play and break them, level by level.',reads:'node and entry counts',controls:null,options:[],builtIn:true}];
    const seen=new Set(['credpong']); const ext=Array.isArray(window.CredGames)?window.CredGames:[];
    for(const g of ext){ if(!g||typeof g!=='object'||typeof g.create!=='function')continue; const id=String(g.id||'');
      if(!/^[a-z][a-z0-9-]{1,23}$/.test(id)||seen.has(id)||!g.name)continue; seen.add(id);
      const options=(Array.isArray(g.options)?g.options:[]).slice(0,2).filter(o=>o&&/^[a-z][a-z0-9-]{0,15}$/.test(o.id||'')&&Array.isArray(o.choices)&&o.choices.length>1)
        .map(o=>({id:o.id,label:this.cleanText(o.label||o.id).slice(0,24),choices:o.choices.slice(0,4).map(c=>[String(c[0]),this.cleanText(c[1]||c[0]).slice(0,16)])}));
      out.push({id,name:this.cleanText(g.name).slice(0,32),blurb:this.cleanText(g.blurb||'').slice(0,160),reads:g.reads==='counts'?'node and entry counts':'nothing from the vault',controls:this.cleanText(g.controls||'').slice(0,60),options,def:g}); }
    return out; }
  gameStoreKey(id,k){ return id==='credpong'?('credpong_'+k):('credgames.'+id+'.'+k); }
  gameBest(id){ if(id==='credpong')return this.cpBest(); try{return parseInt(localStorage.getItem(this.gameStoreKey(id,'best'))||'0',10)||0;}catch(e){return 0;} }
  gameCounts(){ return Object.freeze(this.vault.nodes.filter(n=>n.kind!=='global'&&n.kind!=='orphan').map(n=>Object.freeze({glyph:this.nodeGlyphIdx(n.id),entries:+(n.counts&&n.counts.entries)||0}))); }
  gameOpenLibrary(){ this.cpStopListeners(); this.ghStop(); this.setState({overlay:'games',gameScreen:'library',vaultMenu:false}); }
  gameRun(){ return this.state.gameId&&this.state.gameId!=='credpong'?this._game:this.cp; }
  gameOpenMenu(id){ this.cpStopListeners(); this.ghStop(); this.setState({overlay:'games',gameId:id,gameScreen:'menu',vaultMenu:false}); }
  gameOpt(g,o){ const v=((this.state.gameOpts||{})[g.id]||{})[o.id]; return o.choices.some(c=>c[0]===v)?v:o.choices[0][0]; }
  gameStart(){ const id=this.state.gameId||'credpong'; if(id==='credpong')return this.cpStart(); const g=this.gamesList().find(x=>x.id===id); if(!g)return;
    this.ghStop(); this.setState({overlay:'games',gameScreen:'play'},()=>this.ghInit(g)); }
  ghInit(g){
    const el=this.cpRef&&this.cpRef.current; if(!el)return; this.cpStopListeners(); this.ghStop();
    el.innerHTML=''; const W=680,H=440, cv=document.createElement('canvas'); cv.width=W; cv.height=H; cv.setAttribute('aria-label',g.name);
    cv.style.cssText='position:absolute;inset:0;width:100%;height:100%;touch-action:none'; el.appendChild(cv);
    const ctx=cv.getContext('2d'), opts={}; g.options.forEach(o=>{opts[o.id]=this.gameOpt(g,o);});
    const lvKey=this.gameStoreKey(g.id,'level'); let score=0, ended=false; const gh={id:g.id,paused:false,last:performance.now(),inst:null};
    const api=Object.freeze({ width:W, height:H, ctx, palette:Object.freeze({...this.palette()}), counts:this.gameCounts(), options:Object.freeze(opts),
      glyph:(x,y,h,idx,color)=>this.drawGlyph(ctx,x,y,h,Math.abs(idx|0)%14,color),
      setScore:(n)=>{ score=Math.max(0,Math.floor(+n||0)); }, isPaused:()=>gh.paused,
      savedLevel:()=>{ try{return Math.max(1,parseInt(localStorage.getItem(lvKey)||'1',10)||1);}catch(e){return 1;} },
      saveLevel:(n)=>{ try{ n=Math.floor(+n||1); if(n>api.savedLevel())localStorage.setItem(lvKey,String(n)); }catch(e){} },
      end:()=>{ if(ended||this._game!==gh)return; ended=true; this.ghOver(g,score); } });
    try{ gh.inst=g.def.create(api)||{}; }catch(e){ console.warn('[CredGames] '+g.id+' did not start',e); this.setState({gameScreen:'menu'}); return; }
    this._game=gh; const inst=gh.inst;
    this._ghKey=(e)=>{ if(this._game!==gh)return; if(['ArrowLeft','ArrowRight','ArrowUp','ArrowDown',' '].includes(e.key))e.preventDefault(); if(gh.paused||!inst.key)return; try{inst.key(e.key,e.type==='keydown');}catch(x){} };
    this._ghPtr=(e)=>{ if(this._game!==gh||gh.paused||!inst.pointer)return; const r=cv.getBoundingClientRect(); try{inst.pointer((e.clientX-r.left)*W/r.width,(e.clientY-r.top)*H/r.height,e.type.replace('pointer',''));}catch(x){} };
    window.addEventListener('keydown',this._ghKey); window.addEventListener('keyup',this._ghKey);
    ['pointermove','pointerdown','pointerup'].forEach(ty=>cv.addEventListener(ty,this._ghPtr)); gh.cv=cv;
    const loop=(now)=>{ if(this._game!==gh||this.state.overlay!=='games'||this.state.gameScreen!=='play')return;
      const dt=Math.min(0.05,Math.max(0,(now-gh.last)/1000)); gh.last=now;
      try{ if(!gh.paused&&inst.update)inst.update(dt); if(inst.draw)inst.draw(ctx); }catch(x){ console.warn('[CredGames] '+g.id+' stopped',x); this.ghOver(g,score); return; }
      if(gh.paused){ const p=api.palette; ctx.save(); ctx.globalAlpha=0.72; ctx.fillStyle=p.void||'#000'; ctx.fillRect(0,0,W,H); ctx.globalAlpha=1; ctx.fillStyle=p.bone; ctx.font='14px "JetBrains Mono", monospace'; ctx.textAlign='center'; ctx.fillText('paused · p to resume · esc to exit',W/2,H/2); ctx.restore(); }
      this._ghRaf=requestAnimationFrame(loop); };
    this._ghRaf=requestAnimationFrame(loop); }
  ghStop(){ const gh=this._game; if(!gh)return; this._game=null; cancelAnimationFrame(this._ghRaf);
    window.removeEventListener('keydown',this._ghKey); window.removeEventListener('keyup',this._ghKey);
    if(gh.cv)['pointermove','pointerdown','pointerup'].forEach(ty=>gh.cv.removeEventListener(ty,this._ghPtr));
    try{ gh.inst&&gh.inst.destroy&&gh.inst.destroy(); }catch(e){} }
  ghOver(g,score){ const prev=this.gameBest(g.id); try{ if(score>prev)localStorage.setItem(this.gameStoreKey(g.id,'best'),String(score)); }catch(e){}
    this.ghStop(); this.setState({gameScreen:'over',gameLast:{id:g.id,score,best:Math.max(prev,score),isBest:score>0&&score>prev}}); }
  paintEntryLink(en,ctx){
    const n=this.gdNode(en.parentId); if(!n)return;
    const dim=this.state.selected&&en.parentId!==this.state.selected;
    const dx=en.x-n.x,dy=en.y-n.y,d=Math.hypot(dx,dy)||1,ux=dx/d,uy=dy/d;
    const R=this.nodeR(n);
    ctx.save();ctx.globalAlpha=dim?0.15:0.5;ctx.strokeStyle=en.color;ctx.lineWidth=0.8;
    ctx.beginPath();ctx.moveTo(n.x+ux*R,n.y+uy*R);ctx.lineTo(en.x,en.y);ctx.stroke();ctx.restore();
  }
  paintEntry(en,ctx){
    const hoverThis=this.hoverEntryId===en.id;
    const dim=this.state.selected&&en.parentId!==this.state.selected;
    ctx.save();ctx.globalAlpha=dim?0.4:1;ctx.beginPath();ctx.arc(en.x,en.y,hoverThis?4.2:3,0,2*Math.PI);ctx.fillStyle=en.color;ctx.fill();
    if(hoverThis){ ctx.lineWidth=1.1;ctx.strokeStyle=this.palette().bone;ctx.globalAlpha=0.55;ctx.beginPath();ctx.arc(en.x,en.y,6.2,0,2*Math.PI);ctx.stroke(); }
    ctx.restore();
  }
  select(id){
    this.setState(st=>{
      let recentNodes=st.recentNodes||[];
      if(id!=='__orphan'){ recentNodes=[id,...recentNodes.filter(x=>x!==id)].slice(0,5); }
      return {selected:id,openEntry:null,ctx:null,railOpen:false,inspOpen:true,recentNodes};
    });
    this.buildEntryNodes(id); setTimeout(()=>this.renderGraph(),0);
  }
  parseBulk(text){
    const RES=['http','https','ftp','ftps','ssh','sftp','git','file','postgres','postgresql','mysql','redis','mongodb','amqp','otpauth','data','mailto','s3','gs'];
    const lines=text.split(/\r\n|\r|\n/);
    const segs=[];let cur=[];
    for(const ln of lines){ if(/^\s*\/\/\/\s*$/.test(ln)){segs.push(cur);cur=[];} else cur.push(ln); }
    segs.push(cur);
    const labRe=/^([A-Za-z0-9 _.()#\/-]{1,40}): +(.*)$/;
    const labOnly=/^([A-Za-z0-9 _.()#\/-]{1,40}):\s*$/;
    const isLab=(l)=>{const m=l.match(labRe);if(!m)return null;if(RES.includes(m[1].trim().toLowerCase()))return null;return{label:m[1],value:m[2]};};
    const out=[];
    for(const seg of segs){ const ne=seg.filter(l=>l.trim()!=='');
      if(!ne.length)continue;
      if(ne.every(l=>isLab(l))){ for(const l of ne){const f=isLab(l);out.push({label:f.label,value:f.value,seg:segs.indexOf(seg)});} }
      else { const m0=seg[0]&&seg[0].match(labOnly); const lab=(m0&&!RES.includes(m0[1].trim().toLowerCase()))?m0[1]:'';
        const body=(m0?seg.slice(1):seg).join('\n').replace(/\n$/,'');
        out.push({label:lab,value:body,seg:segs.indexOf(seg)}); }
    }
    return out;
  }
  inferType(label,value){
    const l=(label||'').toLowerCase(),v=(value||'').trim();
    if(/-----BEGIN [^-]*PRIVATE KEY-----/.test(value))return'private-key';
    if(/-----BEGIN CERTIFICATE-----/.test(value))return'certificate';
    if(/^otpauth:\/\//.test(v)||(/^[A-Z2-7]{16,64}$/.test(v)&&/2fa|totp|seed/.test(l)))return'totp-seed';
    if(/^(\w+ ){11,23}\w+$/.test(v)&&/seed|phrase|mnemonic/.test(l))return'seed-phrase';
    if(/^https?:\/\//.test(v))return'url';
    if(/^\d{2,5}$/.test(v)&&/port/.test(l))return'port';
    if(/pass|pw$|^pw|secret/.test(l))return'password';
    if(/token|key/.test(l))return'api-key';
    if(/user|login|email/.test(l))return'username';
    if(/host|server|^ip/.test(l)||/^\d{1,3}(\.\d{1,3}){3}$/.test(v))return'host';
    return'text';
  }
  typeMasked(t){return['private-key','seed-phrase','totp-seed','password','api-key'].includes(t);}
  looksSensitive(label,value,t){ return t==='text'&&/(^|\s)(pw|pass|secret|token|key)(\s|:|=)/i.test(value)&&/[A-Za-z0-9!#$%^&*]{8,}/.test(value); }
  fieldSensTier(t){ if(t==='private-key'||t==='seed-phrase')return'critical'; if(t==='certificate'||t==='totp-seed'||t==='api-key'||t==='password')return'high'; if(t==='url'||t==='port'||t==='host'||t==='username')return'medium'; return'low'; }
  fieldSensClass(t){return'sens-'+this.fieldSensTier(t);}
  fieldSensBorder(t){const tier=this.fieldSensTier(t);return tier==='critical'?'3px solid var(--danger)':tier==='high'?'3px solid var(--bone)':tier==='medium'?'2px solid var(--mute)':'1px solid var(--faint)';}
  currentFields(){
    const s=this.state;
    let raw = s.addMode==='single' ? s.singleFields.filter(f=>f.label||f.value).map((f,i)=>({label:f.label,value:f.value,seg:i})) : this.parseBulk(s.bulkText);
    return raw.map((f,i)=>{ const inf=this.inferType(f.label,f.value); const t=s.typeOverrides[i]||inf;
      return {...f,idx:i,type:t,masked:this.typeMasked(t),hint:this.looksSensitive(f.label,f.value,t)}; });
  }
  entryTypeOf(fields){
    if(this.state.entryTypeOverride)return this.state.entryTypeOverride;
    const ts=fields.map(f=>f.type);
    if(fields.length===1&&/^notes?$/i.test((fields[0].label||'').trim()))return'note'; // free-text note entry
    if(ts.includes('totp-seed')&&fields.length<=2)return'totp';
    if((ts.includes('seed-phrase')||ts.includes('private-key'))&&ts.includes('host')===false&&ts.some(t=>t==='text'))return ts.includes('seed-phrase')?'wallet':'ssh';
    if(ts.includes('certificate'))return'certificate';
    if(ts.includes('host')&&ts.includes('username'))return'server';
    if(ts.includes('private-key'))return'ssh';
    if(ts.includes('url')&&ts.includes('password'))return'login';
    if(ts.includes('api-key'))return'api';
    return'other';
  }
  sensOf(fields){ const ts=fields.map(f=>f.type);
    if(ts.includes('seed-phrase')||ts.includes('private-key'))return'critical';
    if(ts.includes('password')||ts.includes('api-key')||ts.includes('totp-seed'))return'high';
    return'low';
  }
  saveNewEntry(again){
    const s=this.state; const fields=this.currentFields();
    const split=s.addMode==='bulk'&&s.splitSegs;
    if(!fields.length||(!split&&!this.cleanText(s.addName).trim()))return;
    const nid=s.addNode, locked=!!s.vaultLocked, stamp=Date.now();
    let groups=[fields];
    if(split){ const m=new Map(); for(const f of fields){ if(!m.has(f.seg))m.set(f.seg,[]); m.get(f.seg).push(f); } groups=[...m.values()]; } // FIELD_MODEL §5: each /// segment becomes its own entry, named from its first label or "untitled n"
    const taken=new Set([...(this.vault.entries[nid]||[]).map(e=>this.dupKey(e.name)),...(this.vault.pending||[]).filter(p=>p.node===nid).map(p=>this.dupKey(p.name))]);
    let untitled=0;
    const recs=groups.map((gf,gi)=>{
      let nm=split?(this.cleanText(gf[0].label||'').trim()||('untitled '+(++untitled))):this.cleanText(s.addName).trim();
      if(split){ const base=nm; let k=2; while(taken.has(this.dupKey(nm)))nm=base+' '+(k++); taken.add(this.dupKey(nm)); }
      return {id:(locked?'pd-':'new-')+stamp+'-'+gi,name:nm,type:this.entryTypeOf(gf),sensitivity:this.sensOf(gf),totp:gf.some(f=>f.type==='totp-seed'),fields:gf.map(f=>({label:this.cleanText(f.label).trim()||'field',value:f.value,type:f.type,masked:f.masked}))};
    });
    const keepNote=again&&s.entryTypeOverride==='note'; const reset={addName:'',singleFields:[{label:keepNote?'note':'',value:''}],bulkText:'',typeOverrides:{},entryTypeOverride:keepNote?'note':null,dialog:again?'addEntry':null};
    if(locked){ // S20: a write made while the vault is locked is held in the pending tray, never the manifest
      const when=new Date().toTimeString().slice(0,5);
      (this.vault.pending=this.vault.pending||[]).push(...recs.map(r=>({...r,node:nid,by:'you',when})));
      clearTimeout(this._pnT); this._pnT=setTimeout(()=>this.setState({pendingNote:''}),3500);
      this.setState({...reset,pendingNote:(recs.length===1?'1 entry':recs.length+' entries')+' held for review'}); return; }
    const list=(this.vault.entries[nid]=this.vault.entries[nid]||[]); const n=this.node(nid);
    for(const r of recs){ list.push({...r,meta:r.type+' · '+r.sensitivity}); if(n){n.counts.entries++; if(r.totp)n.counts.totp++;} }
    this.pal=null; this.gd=this.graphData(); this.buildEntryNodes(nid); this.renderGraph();
    this.setState({...reset,selected:nid});
  }
  doSeal(){
    const id=this.state.sealTarget; const n=this.node(id); if(!n)return;
    const kids=this.children(id); const all=[n,...kids];
    const entriesSnapshot={}; for(const k of all) entriesSnapshot[k.id]=(this.vault.entries[k.id]||[]).slice(); // B4-1: keep the real records so restore is verbatim, not just a count
    for(const k of all){ for(const e of (this.vault.entries[k.id]||[])) this.vault.orphans.push({name:e.name,from:k.id,date:'2026-08-08'}); delete this.vault.entries[k.id]; }
    this.vault.sealed.push({node:n,kids,entries:entriesSnapshot,links:this.vault.links.filter(l=>all.some(a=>l.source===a.id||l.target===a.id)),grants:this.vault.grants.filter(g=>g.from===id||g.to===id),date:'2026-08-08'});
    this.vault.nodes=this.vault.nodes.filter(x=>!all.includes(x));
    this.vault.links=this.vault.links.filter(l=>!all.some(a=>l.source===a.id||l.target===a.id)); // B4-5: links are ids at rest — no second object-shape check needed
    this.vault.grants=this.vault.grants.filter(g=>g.from!==id&&g.to!==id);
    this.refreshGraph();
    this.setState({dialog:null,sealTyped:'',selected:'__orphan'});
  }
  restoreSealed(i){
    const r=this.vault.sealed[i]; if(!r)return;
    this.vault.nodes.push(r.node,...r.kids);
    for(const l of r.links) this.vault.links.push({source:l.source.id||l.source,target:l.target.id||l.target,kind:l.kind});
    this.vault.grants.push(...r.grants);
    const restored=[r.node,...r.kids].map(n=>n.id);
    this.vault.orphans=this.vault.orphans.filter(o=>!restored.includes(o.from));
    for(const nid of restored){ this.vault.entries[nid]=(r.entries&&r.entries[nid])?r.entries[nid].slice():[]; } // B4-1: restore the real entries — "nothing is deleted" was a lie until now
    this.vault.sealed.splice(i,1);
    this.refreshGraph(); this.setState({selected:r.node.id});
  }
  copySecret(val){ // B6-3: best-effort 30 s / app-switch clear — the desktop shell does this natively; this is the browser-preview equivalent
    try{ navigator.clipboard.writeText(val).catch(()=>{}); }catch(x){}
    this._clipVal=val; clearTimeout(this._clipT); this._clipT=setTimeout(()=>this.clearClipboard(),30000);
  }
  clearClipboard(){ clearTimeout(this._clipT); const val=this._clipVal; this._clipVal=null; if(val==null)return;
    try{ navigator.clipboard.readText().then(cur=>{ if(cur===val)return navigator.clipboard.writeText(''); }).catch(()=>{}); }catch(x){} } // only wipes it if it still holds what we put there
  openAddDlg(nid,note){ this.setState({dialog:'addEntry',addNode:nid,addName:'',addMode:'single',bulkText:'',splitSegs:false,typeOverrides:{},singleFields:[{label:note?'note':'',value:''}],entryTypeOverride:note?'note':null,searchOpen:false,ctx:null}); } // one opener, so no stale note state or stale node leaks into the next entry
  sensBorderFor(sv){return sv==='critical'?'3px solid var(--danger)':sv==='high'?'3px solid var(--bone)':sv==='medium'?'2px solid var(--mute)':'1px solid var(--faint)';}
  pendingFlash(msg){ clearTimeout(this._pnT); this._pnT=setTimeout(()=>this.setState({pendingNote:''}),3500); this.setState({pendingNote:msg}); }
  acceptPending(i){ // S20: accepting is what writes a held entry to the manifest, so it needs the vault open
    if(this.state.vaultLocked)return;
    const p=(this.vault.pending||[])[i]; if(!p)return;
    this.vault.pending.splice(i,1);
    const n=this.node(p.node);
    if(!n){ this.vault.orphans.push({name:p.name,from:p.node,date:new Date().toISOString().slice(0,10)}); this.pendingFlash(p.name+' accepted into Orphaned — its node was sealed'); return; }
    (this.vault.entries[p.node]=this.vault.entries[p.node]||[]).push({id:p.id.replace(/^pd-/,'new-'),name:p.name,type:p.type,sensitivity:p.sensitivity,totp:p.totp,meta:p.type+' · '+p.sensitivity,fields:p.fields});
    n.counts.entries++; if(p.totp)n.counts.totp++;
    this.pal=null; this.gd=this.graphData(); this.buildEntryNodes(p.node); this.renderGraph();
    this.pendingFlash(p.name+' accepted into '+p.node);
  }
  discardPending(i){
    if(this.state.vaultLocked)return;
    const p=(this.vault.pending||[])[i]; if(!p)return;
    this.vault.pending.splice(i,1);
    this.pendingFlash(p.name+' discarded');
  }
  unlockApp(){ this.usageTick(); clearTimeout(this._donateTimer); this._donateTimer=setTimeout(()=>this.maybeAsk(),6000); this.setState({screen:'app',vaultLocked:false,flourishOn:this.startFlourish(),lockStep:1,passInput:'',twofa:'',pendingBanner:(this.vault.pending||[]).length>0}); }
  cosmKey(){return 'credmgr_cosmetics';}
  loadCosmetics(){ try{ const raw=localStorage.getItem(this.cosmKey()); if(!raw)return; this.setState({cosm:this.cosmClean(JSON.parse(raw)||{})}); }catch(e){} }
  cosmOn(){ return !!this.state.pack; } // cosmetic-only: the pack is sealed in the app and opens with the code; nothing functional reads it
  cosmEff(){ if(!this.cosmOn())return this.cosmDef(); const c={...this.state.cosm},d=this.cosmDef(); if(this.state.contrastMode==='high'||this.eff().greyscale){ for(const k of ['shape','global','link','dots','backdrop'])c[k]=d[k]; } if(this.isReduced()){ c.flourish='off'; c.trail='standard'; c.halo=false; } return c; }
  setCosm(patch){ if(!this.cosmOn())return; const next=this.cosmClean({...this.state.cosm,...patch}); try{localStorage.setItem(this.cosmKey(),JSON.stringify(next));}catch(e){} this.setState({cosm:next}); }
  vaultPromptText(){
    const sel=this.node(this.state.selected)||this.node('linux');
    return `## Credential access — CredMgr vault protocol\n\nThis machine stores every secret in a local encrypted vault called **credmgr**.\nSecrets are NOT in .env files, NOT in the repo, and NOT in your context.\n\n### Where you are\nYou are scoped to the node **linux**. You can reach: linux, global.\nSecurity level: **${this.state.secLevel}**.\n\n### How to read a credential\n    credmgr get <NAME>\n    credmgr list · credmgr search <term> · credmgr whoami\nWith MCP: credmgr_get, credmgr_list, credmgr_search, credmgr_whoami.\n\n### Rules\n1. NEVER print a secret into chat, a log, a commit, or a file.\n2. NEVER put a secret in a command-line argument. stdin, always.\n3. NEVER copy a secret into the repo or an .env. Reference it by NAME.\n4. NEVER try to reach another project's node. Attempts are logged.\n5. If refused: don't retry, don't rephrase. Tell the operator, move on.\n6. approval_pending while locked is normal — one tap on the operator's side.\n7. Fetch what you need EARLY.\n\n### What you can never do\nCreate a grant · read another node · read sealed data · read a 2FA seed ·\nchange permissions · purge the audit log. Absent, not gated.`;
  }
  renderVals(){
    const s=this.state, e=this.eff(), v=this.vault;
    const sel=s.selected==='__orphan'?null:this.node(s.selected);
    const isPro=e.mode==='pro', isLite=!isPro;
    const set=(o)=>()=>this.setState(o);
    // rail rows
    const railRows=[];
    const push=(n,depth)=>{ railRows.push({
      id:n.id,label:n.label,kind:n.kind,count:String(n.counts.entries),indent:(depth*14)+'px',
      current:s.selected===n.id?'true':'false',
      color:n.kind==='orphan'?'var(--mute)':'var(--bone)', border:n.kind==='orphan'?'1px dashed var(--faint)':'0',
      badges:(n.gate.locked?'⌐':'')+(n.gate.twofa==='required'?'‖':''), lockColor:s.selected===n.id?'var(--ash)':'var(--mute)',
      renaming:s.renamingNode===n.id, notRenaming:s.renamingNode!==n.id, renameVal:s.renameVal,
      onRenameChange:(ev)=>this.setState({renameVal:ev.target.value}),
      commitRename:()=>{ const val=this.cleanText(s.renameVal).trim(); if(val){ n.label=val; this.refreshGraph(); } this.setState({renamingNode:null}); },
      cancelRename:(ev)=>{ if(ev.key==='Escape')this.setState({renamingNode:null}); else if(ev.key==='Enter'){const val=this.cleanText(s.renameVal).trim(); if(val){n.label=val;this.refreshGraph();} this.setState({renamingNode:null});} },
      select:()=>this.select(n.id),
      menu:(ev)=>{ev.preventDefault();const pos=this.ctxPosFor(ev.clientX,ev.clientY);this.setState({ctx:{x:pos.x,y:pos.y,node:n.id}});} // B3-2
    });};
    push(this.node('global'),0);
    for(const p of v.nodes.filter(n=>n.depth===1)){ push(p,0); for(const c of this.children(p.id)) push(c,1); }
    railRows.push({id:'__orphan',label:'orphaned',kind:'orphan',count:String(v.orphans.length),indent:'0px',current:s.selected==='__orphan'?'true':'false',color:s.selected==='__orphan'?'var(--ash)':'var(--mute)',border:'1px dashed var(--faint)',badges:'',lockColor:'var(--mute)',renaming:false,notRenaming:true,renameVal:'',select:()=>this.select('__orphan'),menu:(ev)=>ev.preventDefault()});
    // tree view rows
    const tShape=this.cosmEff().shape; const treeRows=railRows.map(r=>{ const n=r.id==='__orphan'?{kind:'orphan',counts:{entries:v.orphans.length,totp:null},gate:{locked:false,twofa:'none'}}:this.node(r.id);
      return { ...r, indent:(parseInt(r.indent)*2)+'px', guide:parseInt(r.indent)>0?'1px solid var(--hair)':'none',
        bg:s.selected===r.id?'var(--steel-3)':'transparent', subColor:s.selected===r.id?'var(--ash)':'var(--mute)', lockColor:s.selected===r.id?'var(--ash)':r.lockColor,
        glyphColor:n.kind==='orphan'?'var(--faint)':n.kind==='sub'?'var(--ash)':'var(--bone)',
        gr:n.kind==='global'?'8':n.kind==='sub'?'5':'7', ...this.treeShape(tShape,n.kind==='global'?8:n.kind==='sub'?5:7), gfill:n.kind==='global'?'currentColor':'none',
        gsw:n.kind==='sub'?'1':'1.5', gdash:n.kind==='orphan'?'2 2':'none',
        fw:n.kind==='global'?'600':'500',
        counts2:n.counts.totp==null?`${n.counts.entries} entries · —`:`${n.counts.entries} entries · ${n.counts.totp} 2FA`,
        hoverOn:(ev)=>{clearTimeout(this.hoverT);const rect=ev.currentTarget.getBoundingClientRect();const mainEl=this.graphRef.current&&this.graphRef.current.closest('.cm-main');const mrc=mainEl?mainEl.getBoundingClientRect():{left:0,top:0}; // C-1: position from the row's own rect instead of a fixed 60%/20%
          const hx=rect.right-mrc.left+8,hy=rect.top-mrc.top;
          this.hoverT=setTimeout(()=>{this.setState({hover:{x:hx,y:hy,entries:n.counts.entries,totp:n.counts.totp==null?'—':n.counts.totp}});},180);},
        hoverOff:()=>{clearTimeout(this.hoverT);this.setState({hover:null});},
        menuBtn:(ev)=>{ev.stopPropagation();const pos=this.ctxPosFor(ev.clientX,ev.clientY);this.setState({ctx:{x:pos.x,y:pos.y,node:r.id}});}
      };});
    // hover
    const hv=s.hover;
    const hoverIsEntry=!!(hv&&hv.mode==='entry'), hoverIsNode=!!hv&&!hoverIsEntry;
    // context menu
    const ctxNode=s.ctx?this.node(s.ctx.node):null;
    const ctxItemsAll=s.ctx?(s.ctx.node==='__orphan'?[{label:'Open orphaned',color:'var(--bone)',go:()=>this.select('__orphan')}]:[
      {label:'Open',color:'var(--bone)',go:()=>this.select(s.ctx.node)},
      {label:'New entry',color:'var(--bone)',go:()=>this.openAddDlg(s.ctx.node)},
      {label:'New sub-node',color:ctxNode&&ctxNode.depth<2?'var(--bone)':'var(--mute)',go:()=>this.setState({dialog:'addNode',newNodeParent:s.ctx.node,ctx:null})},
      {label:'Grant access…',color:'var(--bone)',go:()=>this.setState(st=>({dialog:'grant',grant:{...st.grant,from:s.ctx.node},ctx:null}))},
      {label:'Rename',color:'var(--bone)',go:()=>this.setState(st=>({ctx:null,renamingNode:s.ctx.node,renameVal:ctxNode?ctxNode.label:''}))},
      {label:ctxNode&&ctxNode.gate.locked?'Unlock node':'Lock now',color:'var(--bone)',go:()=>{if(ctxNode){ctxNode.gate.locked=!ctxNode.gate.locked;this.refreshGraph();}this.setState({ctx:null});}},
      {label:'Remove node…',color:'var(--danger-fg)',go:()=>this.setState({dialog:'seal',sealTarget:s.ctx.node,sealTyped:'',ctx:null})}
    ]):[];
    const ctxItems=(s.ctx&&s.ctx.node==='global')?ctxItemsAll.filter(it=>it.label!=='Remove node…'):ctxItemsAll; // C-8: sealing the root node would empty the whole vault — not a valid action
    // inspector
    const inspEntriesArr=(sel?(v.entries[sel.id]||[]):[]);
    const openE=s.openEntry?inspEntriesArr.find(x=>x.id===s.openEntry):null;
    const now=Date.now();
    const revealMs=(s.revealWindowSecs||20)*1000;
    const entryFields=openE?openE.fields.map((f,i)=>{ const key=openE.id+':'+i; const until=s.reveals[key]; const revealed=until&&until>now;
      const masked=f.masked&&!revealed;
      const secs=revealed?Math.ceil((until-now)/1000):0;
      return { label:f.label, type:f.type, masked:masked?'true':'false', maskable:f.masked, sensClass:this.fieldSensClass(f.type),
        display:masked?'••••••••••••':(f.value), counting:!!revealed, pct:revealed?((until-now)/revealMs*100)+'%':'0%', secs:String(secs),
        revealLabel:revealed?'hide':'reveal', revealTitle:'visible '+(s.revealWindowSecs||20)+' s, then re-masks', reveal:()=>this.setState(st=>{const rv={...st.reveals};if(rv[key])delete rv[key];else rv[key]=Date.now()+revealMs;return{reveals:rv};}),
        copyLabel:(s.copied[key]&&s.copied[key]>now)?'copied':(s.vaultLocked?'locked':'copy'), copyDisabled:s.vaultLocked,
        copy:()=>{ if(s.vaultLocked)return; this.copySecret(f.value); this.setState(st=>({copied:{...st.copied,[key]:Date.now()+1500}}));}, // B6-1: copy was the one hole in the locked model
        menuOpen:s.fieldMenu===key, menuLabel:'field '+(f.label||'(no label)'), toggleMenu:()=>this.setState(st=>({fieldMenu:st.fieldMenu===key?null:key})),
        menuItems:[['Edit…',s.vaultLocked,()=>this.openFieldDlg('edit',i),false],['Move up',s.vaultLocked||i===0,()=>this.moveField(i,-1),false],['Move down',s.vaultLocked||i===openE.fields.length-1,()=>this.moveField(i,1),false],['Remove…',s.vaultLocked||openE.fields.length<=1,()=>this.openFieldDlg('remove',i),true]]
          .map(([label,disabled,go,danger])=>({label,disabled,go,color:disabled?'var(--mute)':danger?'var(--danger-fg)':'var(--bone)'})) };
    }):[];
    // search
    const q=s.searchQ.trim().toLowerCase();
    let searchRows=[];
    if(s.searchOpen){
      if(!q){ searchRows=[{glyph:'+',label:'Add new',meta:'',go:()=>{const n=this.node(s.selected); this.openAddDlg(n?n.id:'global');}}];
        if(isPro){ searchRows.push(...(s.recentNodes||[]).map(nid=>{const n=this.node(nid);return n?{glyph:'○',label:n.label,meta:'recent',go:()=>{this.select(nid);this.setState({searchOpen:false});}}:null;}).filter(Boolean)); }
      } else {
        for(const n of v.nodes) if(n.label.toLowerCase().includes(q)) searchRows.push({glyph:'○',label:n.label,meta:'node',go:()=>{this.select(n.id);this.setState({searchOpen:false});}});
        for(const nid in v.entries) for(const en of v.entries[nid]){
          const nameHit=en.name.toLowerCase().includes(q);
          const labelHit=!s.vaultLocked&&en.fields.some(f=>f.label.toLowerCase().includes(q));
          const valueHit=!s.vaultLocked&&s.contentSearchEnabled&&en.fields.some(f=>f.value.toLowerCase().includes(q));
          if(nameHit||labelHit||valueHit) searchRows.push({glyph:'⌗',label:en.name,meta:(nameHit||labelHit)?nid:nid+' · match in a value',go:()=>{this.select(nid);this.setState({openEntry:en.id,searchOpen:false});}});
        }
        for(const o of v.orphans) if(o.name.toLowerCase().includes(q)) searchRows.push({glyph:'⌗',label:o.name,meta:'orphaned · sealed',go:()=>{this.select('__orphan');this.setState({searchOpen:false});}});
      }
    }
    const searchMoreCount=Math.max(0,searchRows.length-9); searchRows=searchRows.slice(0,9); // B3-4
    // add entry
    const fields=this.currentFields();
    const previewFields=fields.map((f,i)=>({label:f.label||('field '+(i+1)),display:this.typeMasked(f.type)?'••••••••••••':(f.value.split('\n')[0].slice(0,48)+(f.value.includes('\n')?' … '+f.value.split('\n').length+' lines':'')),vcolor:this.typeMasked(f.type)?'var(--mute)':'var(--bone)',vspace:this.typeMasked(f.type)?'.12em':'0',type:f.type,hint:f.hint,sensBorder:this.fieldSensBorder(f.type),cycle:()=>{const order=['text','password','api-key','username','host','port','url','private-key','totp-seed','seed-phrase','certificate'];this.setState(st=>({typeOverrides:{...st.typeOverrides,[i]:order[(order.indexOf(f.type)+1)%order.length]}}));}}));
    const maskedCount=fields.filter(f=>this.typeMasked(f.type)).length;
    // seal dialog
    const sealN=s.sealTarget?this.node(s.sealTarget):null;
    const sealKids=sealN?this.children(sealN.id):[];
    const sealGrants=sealN?v.grants.filter(g=>g.from===sealN.id||g.to===sealN.id):[];
    const sealLines=sealN?[
      {text:`${sealN.counts.entries} entries and ${sealN.counts.totp} stored 2FA items move to ORPHANED`},
      {text:'their names stay visible; their values become unreadable to every agent and every automated path'},
      {text:'only you, at this machine, with Touch ID and a fresh 2FA code, can open them again'},
      ...(sealKids.length?[{text:`${sealKids.length} sub-nodes (${sealKids.map(k=>k.label).join(', ')}) are sealed with it`}]:[]),
      ...(sealGrants.length?[{text:`${sealGrants.length} grant (${sealGrants[0].from} → ${sealGrants[0].to}) is revoked`}]:[]),
      {text:'the node key is destroyed after the 7-day recovery window'}
    ]:[];
    // grant dialog
    const g=s.grant;
    const gErrs=!g.reason.trim()||g.code.length!==6||g.from===g.to;
    const nodeOpts=v.nodes.map(n=>({id:n.id,label:n.label}));
    const newNodeProposedId=this.foldName(s.newNodeName).replace(/\s+/g,'-');
    const newNodeDup=!!newNodeProposedId&&v.nodes.some(n=>n.id===newNodeProposedId||this.dupKey(n.label)===this.dupKey(s.newNodeName)); // B4-3: duplicate node names collided silently before this
    // settings
    const navL=[['security','Security'],['appearance','Appearance'],['backup','Backup'],['mode','Mode'],['games','Games']];
    const navP=[...navL,['nodes','Nodes'],['grants','Grants'],['agents','Agents · LLM'],['maintenance','Maintenance'],['audit','Audit'],['advanced','Advanced'],['ops','Operations ⌘⇧O']];
    const nav=(isPro?navP:navL).map(([id,label])=>({label,current:s.setSection===id?'true':'false',bg:s.setSection===id?'var(--steel-3)':'transparent',go:()=>{ if(id==='ops'){this.setState({overlay:'ops'});} else this.setState({setSection:id}); }}));
    const secDesc={open:'Open — agents reveal without prompts. Your explicit choice, shown as a persistent badge here. Cross-node isolation still absolute.',guarded:'Guarded (default) — high/critical reveals wait for one tap on the ~5% of fetches that matter.',sealed:'Sealed — every reveal, create and update waits for a tap.'};
    const llm=[
      ['●','Claude Code','~/.claude.json',true],['●','Claude Desktop','…/claude_desktop_config.json',true],
      ['●','Cursor','~/.cursor/mcp.json',true],['●','VS Code (Copilot)','…/mcp.json',true],
      ['○','Windsurf','not installed',false],['○','Zed','not installed',false],
      ['▲','ChatGPT Desktop','connector — paste the prompt',false]
    ].map(([dot,name,path,can])=>({dot,name,path,dotColor:dot==='▲'?'var(--warn)':dot==='○'?'var(--mute)':'var(--sig)',btn:can||name==='ChatGPT Desktop',btnLabel:name==='ChatGPT Desktop'?'How…':(s.connected[name]?'Connected ✓':'Connect'),connect:()=>this.setState(st=>({connected:{...st.connected,[name]:true}}))}));
    const levelCards=[['open','Open','No prompts. Reveals return immediately. Isolation between nodes is still absolute.'],['guarded','Guarded — default','High and critical reveals wait for one Touch ID tap. Everything else flows.'],['sealed','Sealed','Every reveal, create and update waits for a tap. For the wallet node.']].map(([id,name,desc])=>({name,desc,border:s.secLevel===id?'var(--bone)':'var(--faint)',bg:s.secLevel===id?'var(--steel-3)':'transparent',descColor:s.secLevel===id?'var(--ash)':'var(--mute)',set:()=>this.setState({secLevel:id})}));
    const fd=s.fd;
    const gmList=this.gamesList(), gmId=s.gameId||'credpong', gmCur=gmList.find(g=>g.id===gmId)||null;
    const opsRows=[
      ['verify','Verify integrity','Check every envelope against its manifest digest.','maintenance.verify','Verify'],
      ['doctor','Doctor','Diagnose registry, refs and manifests. Dry run by default.','maintenance.doctor','Run'],
      ['backup','Back up vault','Encrypted archive in the vault folder, under a passphrase you choose.','maintenance.backup','Back up'],
      ['rotate','Rotate root key','New root key; re-issues the recovery code. Needs presence.','maintenance.rotate_root','Rotate…'],
      ['report','Audit report','Read and deny activity, stale grants, last 30 days.','audit.report',null],
      ['merge','Merge entries','Combine duplicates into one entry. Rarely needed in V2.','merge.apply',null],
      ['rekey','Re-key a node','Generate a new node key, re-encrypt its entries.','node.rekey',null],
      ['export','Export node','Write a .env for one node. Requires 2FA.','node.export',null],
      ['import','Import .env','Read a .env into a chosen node as one batch.','entry.create_batch',null],
      ['purge','Purge access log','Empty the access log. Human-only, 2FA-gated.','audit.purge',null]
    ].map(([id,name,desc,op,label])=>({name,desc,label:label||'',ariaLabel:label==='Run'?'Run doctor':name,live:!!label,later:!label,run:()=>this.runOp(id),
      opTitle:label?op:(op==='entry.create_batch'?'entry.create_batch is built; the .env importer that feeds it is not in 2.0.0-beta.1':op==='node.rekey'?'node.rekey: no broker op is specified yet (open backend question); not in 2.0.0-beta.1':op+' is designed, not built; not in 2.0.0-beta.1')}));
    const auditRows=[
      ['02:11:04','reveal','linux/vps-root · password','you'],['01:58:22','copy','linux/deploy-key · private key','you'],
      ['01:44:19','deny','beacon → atlas/stripe-live (cross-node)','agent · ~/projects/beacon'],['01:12:03','read','linux/pg-primary','agent · ~/projects/linux'],
      ['00:41:57','create','atlas/posthog-staging (pending tray)','agent · locked'],['00:02:10','unlock','vault · Touch ID + TOTP','you']
    ].map(([time,op,what,who])=>({time,op,what,who,opColor:op==='deny'?'var(--danger-fg)':op==='reveal'?'var(--warn)':'var(--ash)'}));
    const fr=s.fr;
    const frTitles=['Create your vault','Protect it','Recovery code','Two-factor','Your first nodes'];
    const destroyLeft=s.destroyAt?Math.max(0,Math.ceil((s.destroyAt-now)/1000)):10;
    const vp=this.vaultPromptText();
    const donateChains=[
      {chain:'Ethereum & EVM chains',short:'EVM',address:'0x63AD9e7a8f0451bc2b8D03B3B473935F9482A3C9'},
      {chain:'Bitcoin — native segwit',short:'BTC',address:'bc1qxwkq4jgu4wen62wpqkmx3yx6x9zcv8gvl3vydt'},
      {chain:'Solana',short:'SOL',address:'i6SffLGEcaRgtSTbrktGJUjxxcWqe7hRFfRd88dCDEb'},
      {chain:'Tron — TRC-20',short:'TRX',address:'TVeDpvsf6he6vsMQosbeGT4mRZ2hHomz59'},
      {chain:'TON',short:'TON',address:'UQD7BTjZDmc3snzUlvRom6xQgGfhua_Jkhelydc8zwix4R3D'}
    ];
    const dIdx=Math.min(s.donateChainIdx||0,donateChains.length-1);
    const activeChain=donateChains[dIdx];
    const donateTabs=donateChains.map((c,i)=>({short:c.short,bg:i===dIdx?'var(--bone)':'transparent',fg:i===dIdx?'var(--night)':'var(--bone)',go:()=>this.setState({donateChainIdx:i})}));
    const btn=(on)=>on?['var(--bone)','var(--night)']:['transparent','var(--bone)'];
    const [gbB,gbF]=btn(s.view==='graph'),[tbB,tbF]=btn(s.view==='tree');
    const [dB,dF]=btn(e.theme==='dark'),[lB,lF]=btn(e.theme==='light');
    const [coB,coF]=btn(e.colour==='off'),[cnB,cnF]=btn(e.colour==='on'),[caB,caF]=btn(e.colour==='auto');
    this._cosmFx=this.cosmEff(); const cosm=this._cosmFx, cosmOn=this.cosmOn();
    const pend=v.pending||[], pendN=pend.length;
    const pendingRows=pend.map((p,i)=>({node:p.node,name:p.name,type:p.type,sens:p.sensitivity,sensBorder:this.sensBorderFor(p.sensitivity),fieldCount:p.fields.length+(p.fields.length===1?' field':' fields'),when:p.when||'',by:p.by||'you',accept:()=>this.acceptPending(i),discard:()=>this.discardPending(i)}));
    const splitOn=s.addMode==='bulk'&&s.splitSegs, segCount=new Set(fields.map(f=>f.seg)).size;
    const addNameDup=!splitOn&&!!s.addName.trim()&&[...(v.entries[s.addNode]||[]).map(en=>en.name),...pend.filter(p=>p.node===s.addNode).map(p=>p.name)].some(nm=>this.dupKey(nm)===this.dupKey(s.addName));
    const cosmMarks=[['keep','keep',true],['cells','cells',false],['node','node + ring',false],['seal','seal',false]].map(([id,label,free])=>({label,isKeep:id==='keep',isCells:id==='cells',isNode:id==='node',isSeal:id==='seal',on:cosm.mark===id,disabled:!free&&!cosmOn,border:cosm.mark===id?'var(--bone)':'var(--faint)',bg:cosm.mark===id?'var(--steel-3)':'transparent',set:()=>this.setCosm({mark:id})}));
    const cosmGlyphs=[['classic',1.2,true],['fine',0.8,false],['heavy',2,false]].map(([id,sw,free])=>({label:id,sw:String(sw),on:cosm.glyph===id,disabled:!free&&!cosmOn,bg:cosm.glyph===id?'var(--bone)':'transparent',fg:cosm.glyph===id?'var(--night)':'var(--bone)',set:()=>this.setCosm({glyph:id})}));
    const cosmGroups=this.cosmGroups(cosmOn);
    const [liB,liF]=btn(isLite),[prB,prF]=btn(isPro);
    return {
      noProjects:v.nodes.every(n=>n.kind==='global'), entryUnlocked:!s.vaultLocked, entryLockedShow:!!s.vaultLocked,
      pendingRows, pendingEmpty:!pendN, dlgPending:s.dialog==='pending', pendingLockedNote:!!s.vaultLocked, pendingActDisabled:!!s.vaultLocked,
      openPending:()=>this.setState({dialog:'pending',vaultMenu:false}),
      pendingChipShow:pendN>0&&s.screen==='app', pendingChipLabel:pendN+' held',
      pendingBannerShow:!!(s.pendingBanner&&pendN&&!s.vaultLocked&&s.screen==='app'&&s.dialog!=='pending'),
      pendingBannerText:pendN+(pendN===1?' entry was':' entries were')+' added while locked — review',
      dismissPendingBanner:()=>this.setState({pendingBanner:false}), pendingAnnounce:s.pendingNote||'',
      saveLabel:s.vaultLocked?'Hold for review':'Save', saveAgainLabel:s.vaultLocked?'Hold and add another':'Save and add another',
      addNameDup, addNameMix:this.scriptMix(s.addName), addNameDupMsg:'an entry called “'+this.cleanText(s.addName).trim()+'” already exists in '+s.addNode+' (names are compared ignoring case, look-alike forms and invisible characters)', addNameSplitNote:splitOn,
      cosmUnlocked:cosmOn, cosmLockedShow:!cosmOn, cosmGraph:cosmGroups.graph, cosmIdentity:cosmGroups.identity, cosmMotion:cosmGroups.motion, cosmGames:cosmGroups.games, msRows:this.msRows(s.setSection==='appearance'&&!s.vaultLocked), cosmStampShow:!!(cosmOn&&cosm.badge==='stamp'&&this.stampText()), cosmStampText:this.stampText(), flourishShow:!!(s.flourishOn&&s.screen==='app'), cosmMarks, cosmGlyphs, cosmHaloLabel:cosm.halo?'on':'off', cosmRingLabel:cosm.ring?'on':'off', cosmRing:cosm.ring, cosmToggleDisabled:!cosmOn,
      toggleCosmHalo:()=>this.setCosm({halo:!cosm.halo}), toggleCosmRing:()=>this.setCosm({ring:!cosm.ring}),
      cosmHowTo:()=>this.setState({overlay:null,dialog:null,donateToastOpen:true,donateView:'code',donateCode:'',donateCodeErr:false}),
      markKeep:cosm.mark==='keep', markCells:cosm.mark==='cells', markNode:cosm.mark==='node', markSeal:cosm.mark==='seal',
      gsFilter:e.greyscale?'grayscale(1)':'none', stop:(ev)=>ev.stopPropagation(),
      isLockScreen:s.screen==='lock', lockStep1:s.lockStep===1, lockStep2:s.lockStep===2, lockStep3:s.lockStep===3,
      unlockTouch:()=>this.setState({lockStep:2}), twofaInput:s.twofa,
      gotoPassphrase:()=>this.setState({lockStep:3,passInput:''}),
      passInput:s.passInput||'', onPassInput:(ev)=>this.setState({passInput:ev.target.value}),
      passDisabled:!(s.passInput||'').trim(),
      submitPass:()=>this.unlockApp(),
      onTwofa:(ev)=>{const val=ev.target.value.replace(/\D/g,'');this.setState({twofa:val});if(val.length===6)setTimeout(()=>this.unlockApp(),250);},
      isFirstRun:s.screen==='firstrun', isApp:s.screen==='app',
      frDots:[1,2,3,4,5].map(i=>({bg:i<=fr.step?'var(--bone)':'var(--faint)'})),
      frStepNum:String(fr.step), frTitle:frTitles[fr.step-1],
      frIs1:fr.step===1,frIs2:fr.step===2,frIs3:fr.step===3,frIs4:fr.step===4,frIs5:fr.step===5,
      frVaultName:fr.name, onFrName:(ev)=>this.setState({fr:{...fr,name:ev.target.value}}),
      frRecOk:fr.rec, onFrRec:(ev)=>this.setState({fr:{...fr,rec:ev.target.checked}}),
      frPass:fr.pass, onFrPass:(ev)=>this.setState({fr:{...fr,pass:ev.target.value}}),
      frPassRepeat:fr.passRepeat, onFrPassRepeat:(ev)=>this.setState({fr:{...fr,passRepeat:ev.target.value}}),
      frPassMismatch:!!fr.passRepeat&&fr.pass!==fr.passRepeat,
      frTotp:fr.totp, onFrTotp:(ev)=>this.setState({fr:{...fr,totp:ev.target.value.replace(/\D/g,'')}}),
      frFolders:fr.folders.map((f,i)=>({...f,toggle:()=>this.setState(st=>{const arr=[...st.fr.folders];arr[i]={...arr[i],on:!arr[i].on};return{fr:{...st.fr,folders:arr}};})})), frCanBack:fr.step>1, frBack:()=>this.setState({fr:{...fr,step:fr.step-1}}),
      frNext:()=>{ if(fr.step===5)this.setState({screen:'app'}); else this.setState({fr:{...fr,step:fr.step+1}}); },
      frNextLabel:fr.step===5?'Open the vault':(fr.step===4?(fr.totp&&fr.totp.length===6?'Enrol':'Skip for now'):(fr.step===3?(fr.rec?'Continue':'Skip for now'):'Continue')),
      frNextDisabled:fr.step===2&&(String(fr.pass||'').length<4||fr.pass!==fr.passRepeat), // beta.1 floor: 4 characters; 8 is only recommended (ADR-081)
      searchQ:s.searchQ, onSearch:(ev)=>this.setState({searchQ:ev.target.value,searchOpen:true},()=>this.renderGraph()),
      onSearchFocus:()=>this.setState({searchOpen:true,vaultMenu:false}),
      searchOpen:s.searchOpen, searchRows, searchNone:s.searchOpen&&q&&!searchRows.length,
      searchMoreShow:searchMoreCount>0, searchMoreCount:String(searchMoreCount),
      lockChipState:s.vaultLocked?'':'ok', lockChipGlyph:s.vaultLocked?'●':'○', lockChipLabel:s.vaultLocked?'locked':'unlocked',
      toggleVaultLock:()=>{ if(s.vaultLocked)this.setState({screen:'lock',lockStep:1}); else this.setState({vaultLocked:true,reveals:{}}); },
      vaultMenuOpen:s.vaultMenu, toggleVaultMenu:()=>this.setState(st=>({vaultMenu:!st.vaultMenu,searchOpen:false})),
      vaultMenuItems:[
        {label:'Lock vault',kbd:'⌘L',go:()=>this.setState({vaultLocked:true,reveals:{},vaultMenu:false})},
        {label:'Lock screen',kbd:'',go:()=>this.setState({screen:'lock',lockStep:1,vaultMenu:false})},
        {label:'Orphaned',kbd:'',go:()=>{this.select('__orphan');this.setState({vaultMenu:false});}},
        {label:'Pending writes'+(pendN?' · '+pendN:''),kbd:'',go:()=>this.setState({dialog:'pending',vaultMenu:false})},
        ...(isPro?[{label:'Operations',kbd:'⌘⇧O',go:()=>this.setState({overlay:'ops',vaultMenu:false})}]:[]),
        {label:'Replay first run',kbd:'',go:()=>this.setState({screen:'firstrun',fr:{...fr,step:1},vaultMenu:false})},
        {label:'Games',kbd:'',go:()=>this.gameOpenLibrary()},
        {label:'Help',kbd:'',go:()=>this.setState({dialog:'help',vaultMenu:false})},
        {label:'About CredMgr',kbd:'',go:()=>this.setState({dialog:'about',vaultMenu:false})}
      ],
      openSettings:()=>this.setState({overlay:'settings',vaultMenu:false}),
      openHelp:()=>this.setState({dialog:'help',vaultMenu:false}), dlgHelp:s.dialog==='help',
      helpGoAbout:(ev)=>{ev.preventDefault();this.setState({dialog:'about',aboutTab:'main'});},
      railRows, treeRows,
      setGraphView:set({view:'graph'}), setTreeView:set({view:'tree'}),
      graphBtnBg:gbB,graphBtnFg:gbF,treeBtnBg:tbB,treeBtnFg:tbF,
      graphDisplay:s.view==='graph'?'block':'none', isTreeView:s.view==='tree', graphRef:this.graphRef,
      entriesModeLabel:s.entriesMode==='selected'?'○ entries: selected':'● entries: all',
      toggleEntriesMode:()=>this.setState(st=>({entriesMode:st.entriesMode==='all'?'selected':'all'}),()=>{this.buildEntryNodes();this.renderGraph();}),
      openGames:()=>{ this.cpStopListeners(); this.ghStop(); this.setState({overlay:'games',gameScreen:'library',vaultMenu:false}); },
      ovGames:s.overlay==='games', cpIsMenu:s.gameScreen==='menu'&&gmId==='credpong', cpIsPlay:s.gameScreen==='play', cpIsOver:s.gameScreen==='over',
      gmIsLibrary:(s.gameScreen||'library')==='library', gmIsPongMenu:s.gameScreen==='menu'&&gmId==='credpong', gmIsGenericMenu:s.gameScreen==='menu'&&gmId!=='credpong'&&!!gmCur, gmIsOver:s.gameScreen==='over',
      gmDialogLabel:(s.gameScreen||'library')==='library'?'CredGames':(gmCur?gmCur.name:'CredGames'), gmName:gmCur?gmCur.name:'CredPong', gmBlurb:gmCur?gmCur.blurb:'',
      gmReadsNote:gmCur&&gmCur.reads==='node and entry counts'?'This game reads only how many nodes your vault has and how many entries each holds. It never uses a name, a field or a value, writes nothing to the vault, and nothing leaves this device.':'This game reads nothing from your vault, and nothing leaves this device.',
      gmOptions:gmCur&&!gmCur.builtIn?gmCur.options.map(o=>{ const cur=this.gameOpt(gmCur,o); return {label:o.label,choices:o.choices.map(([cid,label])=>({label,on:cur===cid,bg:cur===cid?'var(--bone)':'transparent',fg:cur===cid?'var(--night)':'var(--bone)',
        go:()=>this.setState(st=>({gameOpts:{...st.gameOpts,[gmCur.id]:{...((st.gameOpts||{})[gmCur.id]||{}),[o.id]:cid}}}))}))}; }):[],
      gmBestLabel:String(this.gameBest(gmId)||'—'), gmStart:()=>this.gameStart(),
      gmBackToLibrary:()=>{ this.cpStopListeners(); this.ghStop(); this.setState({gameScreen:'library'}); },
      gmBackToMenu:()=>{ if(gmId==='credpong')this.cpBackToMenu(); else { this.ghStop(); this.setState({gameScreen:'menu'}); } },
      gmControlHint:gmId==='credpong'?((s.cpMode==='side')?'↑ ↓ move':(s.cpMode==='roam')?'mouse follows the edge':'← → move')+' · space to launch':((gmCur&&gmCur.controls)||'arrow keys or pointer'),
      gmScoreLabel:gmId==='credpong'?'score '+(this.cp?this.cp.score:0):'score '+(s.gameLast?s.gameLast.score:0),
      gmBestNote:gmId==='credpong'?((this.cp&&this.cp.score>0&&this.cp.score>=this.cpBest())?'new local best':('local best: '+this.cpBest())):(s.gameLast&&s.gameLast.isBest?'new local best':'local best: '+(s.gameLast?s.gameLast.best:0)),
      gamesRows:gmList.map(g=>({name:g.name,blurb:g.blurb,reads:g.reads,best:String(this.gameBest(g.id)||'—'),open:()=>this.gameOpenMenu(g.id),openLabel:'Play '+g.name,settingsLabel:'Open '+g.name})),
      cpModeBottomBg:(s.cpMode||'bottom')==='bottom'?'var(--bone)':'transparent', cpModeBottomFg:(s.cpMode||'bottom')==='bottom'?'var(--night)':'var(--bone)',
      cpModeSideBg:s.cpMode==='side'?'var(--bone)':'transparent', cpModeSideFg:s.cpMode==='side'?'var(--night)':'var(--bone)',
      cpModeRoamBg:s.cpMode==='roam'?'var(--bone)':'transparent', cpModeRoamFg:s.cpMode==='roam'?'var(--night)':'var(--bone)',
      cpSetModeBottom:()=>this.setState({cpMode:'bottom'}), cpSetModeSide:()=>this.setState({cpMode:'side'}), cpSetModeRoam:()=>this.setState({cpMode:'roam'}),
      cpModeDesc:this.cpModeDescFor(s.cpMode||'bottom'),
      cpBestLabel:String(this.cpBest()||'—'), cpRef:this.cpRef, cpHasProgress:this.cpSavedLevel()>1, cpResumeLabel:String(this.cpSavedLevel()),
      cpStart:()=>this.cpStart(), cpClose:()=>this.setState({overlay:null}), cpExit:()=>this.cpExit(), cpBackToMenu:()=>this.cpBackToMenu(),
      cpBackdropClick:()=>{ if(s.gameScreen==='play')this.cpExit(); else this.setState({overlay:null}); },
      cpControlHint:(s.cpMode==='side')?'↑ ↓ move':(s.cpMode==='roam')?'mouse follows the edge':'← → move',
      cpScoreLabel:'score '+(this.cp?this.cp.score:0), cpBestNote:(this.cp&&this.cp.score>0&&this.cp.score>=this.cpBest())?'new local best':('local best: '+this.cpBest()),
      hoverVisible:!!hv, hoverX:hv?this.clampMain(+hv.x||0,+hv.y||0,hv.mode==='entry'?100:124,hv.mode==='entry'?40:66).x+'px':'0px', hoverY:hv?this.clampMain(+hv.x||0,+hv.y||0,hv.mode==='entry'?100:124,hv.mode==='entry'?40:66).y+'px':'0px',
      hoverEntries:hv?String(hv.entries):'', hoverTotp:hv?String(hv.totp):'',
      hoverIsEntry, hoverIsNode, hoverEntryType:hv&&hv.etype?hv.etype:'',
      ctxVisible:!!s.ctx, ctxX:s.ctx?this.clampMain(s.ctx.x,s.ctx.y,192,ctxItems.length*30+12).x+'px':'0px', ctxY:s.ctx?this.clampMain(s.ctx.x,s.ctx.y,192,ctxItems.length*30+12).y+'px':'0px', ctxItems,
      inspNode:!!sel&&!openE, inspOrphan:s.selected==='__orphan', inspEntry:!!openE,
      inspLabel:sel?sel.label:'', inspCounts:sel?`${sel.counts.entries} entries · ${sel.counts.totp} 2FA`:'',
      inspLocked:sel?sel.gate.locked:false, insp2fa:sel?sel.gate.twofa==='required':false,
      inspEntries:inspEntriesArr.map(en=>({name:en.name,type:en.type,totp:en.totp,sens:en.sensitivity==='critical'?'3px solid var(--danger)':en.sensitivity==='high'?'3px solid var(--bone)':en.sensitivity==='medium'?'2px solid var(--mute)':'1px solid var(--faint)',open:()=>this.setState({openEntry:en.id})})),
      inspEmpty:sel&&!inspEntriesArr.length,
      inspNotes:s.vaultLocked?'locked — note text needs the vault open':(sel&&sel.notes?sel.notes:'—'),
      orphanCount:String(v.orphans.length), orphanEmpty:v.orphans.length===0, orphanItems:v.orphans,
      openOrphanItem:()=>this.setState({dialog:'touch',touch:{title:'open a sealed item',body:'Touch ID and a fresh 2FA code, every time. This is deliberate friction.'}}),
      openRestoreOrphan:()=>this.setState({dialog:'touch',touch:{title:'restore to a node',body:'Pick a destination node after presence. Restore is one confirmation, not one prompt per item.'}}),
      openDestroy:set({dialog:'destroy',destroyTyped:'',destroyAt:null}),
      closeEntry:()=>this.setState({openEntry:null}),
      entryName:openE?openE.name:'', entryType:openE?openE.type:'', entryMeta:openE?openE.meta:'', entryFields,
      openAddEntry:()=>this.openAddDlg(sel?sel.id:'global'),
      openAddNote:()=>this.openAddDlg(sel?sel.id:'global',true),
      dlgAddEntry:s.dialog==='addEntry', addLockedNote:s.vaultLocked,
      addNode:s.addNode, onAddNode:(ev)=>this.setState({addNode:ev.target.value}),
      addNodeOpts:nodeOpts, addName:s.addName, onAddName:(ev)=>this.setState({addName:ev.target.value}),
      addSingle:s.addMode==='single', addBulk:s.addMode==='bulk',
      setSingle:set({addMode:'single'}), setBulk:set({addMode:'bulk'}),
      addField:()=>{ if(s.addMode==='single')this.setState(st=>({singleFields:[...st.singleFields,{label:'',value:''}]})); },
      singleFields:s.singleFields.map((f,i)=>({label:f.label,value:f.value,rows:Math.max(1,Math.min(6,f.value.split('\n').length)),onLabel:(ev)=>this.setState(st=>{const a=[...st.singleFields];a[i]={...a[i],label:ev.target.value};return{singleFields:a};}),onValue:(ev)=>this.setState(st=>{const a=[...st.singleFields];a[i]={...a[i],value:ev.target.value};return{singleFields:a};})})),
      bulkText:s.bulkText, onBulk:(ev)=>this.setState({bulkText:ev.target.value,typeOverrides:{}}),
      previewFields, previewEmpty:!fields.length,
      previewSummary:fields.length+' field'+(fields.length===1?'':'s')+' · '+maskedCount+' masked'+(splitOn?' · splits into '+segCount+(segCount===1?' entry':' entries'):''),
      previewEntryType:this.entryTypeOf(fields), previewSens:this.sensOf(fields),
      cycleEntryType:()=>{const order=['server','login','api','ssh','wallet','totp','certificate','note','other'];const cur=this.entryTypeOf(fields);this.setState({entryTypeOverride:order[(order.indexOf(cur)+1)%order.length]});},
      splitSegs:s.splitSegs, onSplit:(ev)=>this.setState({splitSegs:ev.target.checked}),
      saveDisabled:!fields.length||(!splitOn&&!s.addName.trim())||addNameDup,
      saveEntry:()=>this.saveNewEntry(false), saveEntryAgain:()=>this.saveNewEntry(true),
      closeDialog:set({dialog:null,destroyAt:null,aboutTab:'main'}), scrimClose:set({dialog:null,overlay:null,destroyAt:null,aboutTab:'main'}),
      dlgSeal:s.dialog==='seal', sealName:sealN?sealN.label:'', sealLines,
      sealTyped:s.sealTyped, onSealTyped:(ev)=>this.setState({sealTyped:ev.target.value}),
      sealDisabled:!sealN||s.sealTyped!==sealN.label, confirmSeal:()=>this.doSeal(),
      dlgGrant:s.dialog==='grant', grantLiteNote:isLite, grantDisabledAll:isLite,
      grantFrom:g.from, grantTo:g.to, grantFromLabel:g.from, grantToLabel:g.to,
      onGrantFrom:(ev)=>{ const nv=ev.target.value; const to=g.to===nv?((nodeOpts.find(o=>o.id!==nv)||{}).id||g.to):g.to; this.setState({grant:{...g,from:nv,to}}); }, // C-2
      onGrantTo:(ev)=>this.setState({grant:{...g,to:ev.target.value}}),
      grantNodeOpts:nodeOpts, grantNodeOpts2:nodeOpts.filter(o=>o.id!==g.from),
      grantCaps:['list','read','reveal values','notes'].map(c=>{const k=c.split(' ')[0];return{label:c,on:g.caps[k],toggle:()=>this.setState({grant:{...g,caps:{...g.caps,[k]:!g.caps[k]}}})};}),
      grantExpiry:g.expiry, onGrantExpiry:(ev)=>this.setState({grant:{...g,expiry:ev.target.value}}), grantNever:g.expiry==='never',
      grantReason:g.reason, onGrantReason:(ev)=>this.setState({grant:{...g,reason:ev.target.value}}),
      grantCode:g.code, onGrantCode:(ev)=>this.setState({grant:{...g,code:ev.target.value.replace(/\D/g,'')}}),
      grantSaveDisabled:isLite||gErrs,
      confirmGrant:()=>{ v.links.push({source:g.from,target:g.to,kind:'grant'}); v.grants.push({from:g.from,to:g.to,scope:Object.keys(g.caps).filter(k=>g.caps[k]).join(' · '),expires:g.expiry==='never'?'never':'in '+g.expiry+' days',lastUsed:'—',reason:g.reason}); this.refreshGraph(); this.setState({dialog:null,grant:{...g,reason:'',code:''}}); },
      dlgAddNode:s.dialog==='addNode',
      newNodeName:s.newNodeName, onNewNodeName:(ev)=>this.setState({newNodeName:ev.target.value}),
      newNodeParent:s.newNodeParent, onNewNodeParent:(ev)=>this.setState({newNodeParent:ev.target.value}),
      newNodeFolders:s.newNodeFolders.map((v,i)=>({val:v,onChange:(ev)=>this.setState(st=>{const a=[...st.newNodeFolders];a[i]=ev.target.value;return{newNodeFolders:a};})})),
      addNodeFolder:()=>this.setState(st=>({newNodeFolders:[...st.newNodeFolders,'']})),
      parentOpts:[{id:'global',label:'global'},...v.nodes.filter(n=>n.depth===1).map(n=>({id:n.id,label:'under: '+n.label}))],
      newNodeDupShow:newNodeDup, newNodeMix:this.scriptMix(s.newNodeName), newNodeDupMsg:newNodeDup?('a node called "'+newNodeProposedId+'" already exists'):'',
      newNodeDisabled:!s.newNodeName.trim()||newNodeDup,
      confirmAddNode:()=>{ if(newNodeDup)return; const nm=newNodeProposedId; const par=s.newNodeParent; const depth=par==='global'?1:2;
        const adv=isPro?s.addNodeAdv:{subShare:true,twofa:false,childRead:false,agentAccess:'read-write'};
        v.nodes.push({id:nm,label:nm,kind:depth===1?'project':'sub',depth,parentId:par,counts:{entries:0,totp:0},
          gate:{locked:false,twofa:adv.twofa?'required':'none'},health:null,notes:'',
          folders:s.newNodeFolders.filter(f=>f.trim()),subShare:adv.subShare,childRead:adv.childRead,agentAccess:adv.agentAccess}); // B4-2: advanced options now land on the node instead of being discarded
        v.links.push({source:par,target:nm,kind:'structural'}); v.entries[nm]=[]; this.refreshGraph(); this.setState({dialog:null,newNodeName:'',newNodeFolders:[''],selected:nm}); },
      dlgGate:s.dialog==='gate', gateCode:s.gateCode||'', onGateCode:(ev)=>this.setState({gateCode:ev.target.value.replace(/\D/g,'')}), openGateDlg:()=>this.setState({dialog:'gate',gateCode:''}),
      dlgDestroy:s.dialog==='destroy',
      destroyTyped:s.destroyTyped, onDestroyTyped:(ev)=>this.setState({destroyTyped:ev.target.value}),
      destroyDisabled:s.destroyTyped!=='DESTROY'||!!s.destroyAt,
      destroyCounting:!!s.destroyAt, destroySecs:String(destroyLeft), destroyPct:s.destroyAt?((10-destroyLeft)/10*100)+'%':'0%',
      destroyLabel:s.destroyAt?'Destroying…':'Destroy',
      startDestroy:()=>this.setState({destroyAt:Date.now()+10000}),
      dlgTouch:s.dialog==='touch', touchTitle:s.touch?s.touch.title:'', touchBody:s.touch?s.touch.body:'',
      touchCode:s.touchCode, onTouchCode:(ev)=>this.setState({touchCode:ev.target.value.replace(/\D/g,'')}),
      touchOk:()=>this.setState({dialog:null,touchCode:''}),
      dlgAbout:s.dialog==='about',
      railOpenClass:s.railOpen?'is-open':'', inspOpenClass:s.inspOpen?'is-open':'', scrimShow:(s.railOpen||s.inspOpen)?'show':'',
      toggleRailOpen:()=>this.setState(st=>({railOpen:!st.railOpen})), closeRail:set({railOpen:false}), closeInsp:set({inspOpen:false}), closeSheets:set({railOpen:false,inspOpen:false}),
      aboutIsMain:s.aboutTab==='main', aboutIsDonate:s.aboutTab==='donate', aboutIsPrivacy:s.aboutTab==='privacy', aboutIsLicenses:s.aboutTab==='licenses',
      goDonate:(ev)=>{ev.stopPropagation();this.setState({aboutTab:'donate'});}, goPrivacy:(ev)=>{ev.stopPropagation();this.setState({aboutTab:'privacy'});}, goLicenses:(ev)=>{ev.stopPropagation();this.setState({aboutTab:'licenses'});}, goAboutMain:set({aboutTab:'main'}),
      donateTabs, activeChainName:activeChain.chain, activeChainAddress:activeChain.address,
      donateCopyLabel:s.donateCopied?'copied ✓':'copy address',
      donateCopyAddr:()=>{try{navigator.clipboard.writeText(activeChain.address);}catch(x){} this.setState({donateCopied:true});setTimeout(()=>this.setState({donateCopied:false}),1500);},
      donateToastVisible:!!(s.donateToastOpen&&s.screen==='app'&&!s.vaultLocked&&!s.dialog&&!s.overlay&&(!this.donateIsUnlocked()||s.donateView==='code'||s.donateView==='optout')),
      donateMsShow:!!s.donateMs, donateMsLabel:s.donateMs||'', donateViewOptout:s.donateView==='optout',
      optOutAsk:()=>{ const u=this.usageGet(); u.optout=true; this.usageSave(u); this.setState({donateView:'optout'}); setTimeout(()=>this.setState({donateToastOpen:false,donateView:'main',donateMs:null}),2600); },
      dismissDonateToast:()=>this.setState({donateToastOpen:false,donateMs:null,donateView:'main',donateCode:'',donateCodeErr:false,donateCodeOk:false}),
      donateViewMain:(s.donateView||'main')==='main', donateViewGuide:s.donateView==='guide', donateViewCode:s.donateView==='code',
      goDonateGuide:()=>this.setState({donateView:'guide'}), goDonateCode:()=>this.setState({donateView:'code',donateCodeErr:false}),
      backDonateMain:()=>this.setState({donateView:'main',donateCodeErr:false}),
      donateCodeVal:s.donateCode||'', onDonateCode:(ev)=>this.setState({donateCode:ev.target.value,donateCodeErr:false}),
      submitDonateCode:()=>{ if(!(window.crypto&&crypto.subtle)){ this.setState({donateCodeErr:true,donateNoCrypto:true}); return; } this.extrasUnlock(s.donateCode).then(ok=>{ if(ok){ this.setState({donateCodeOk:true,donateCodeErr:false}); setTimeout(()=>this.setState({donateToastOpen:false,donateView:'main',donateCode:'',donateCodeOk:false,donateMs:null}),1400); } else this.setState({donateCodeErr:true}); }); },
      donateCodeErrShow:!!s.donateCodeErr, donateCodeErrText:s.donateNoCrypto?"This window can't open the extras: it has no secure context.":"That code doesn't look right.", donateCodeOkShow:!!s.donateCodeOk,
      contentSearchState:s.contentSearchEnabled?'ok':'', contentSearchLabel:s.contentSearchEnabled?'on':'off',
      toggleContentSearch:()=>this.setState(st=>({contentSearchEnabled:!st.contentSearchEnabled})),
      dlgField:s.dialog==='field'&&!!s.fd, fdTitle:fd?({add:'Add a field',edit:'Edit field',remove:'Remove field'})[fd.mode]:'', fdEntry:openE?openE.name:'',
      fdIsAdd:!!fd&&fd.mode==='add', fdIsEdit:!!fd&&fd.mode==='edit', fdIsRemove:!!fd&&fd.mode==='remove', fdIsForm:!!fd&&fd.mode!=='remove',
      fdRemoveText:fd&&fd.mode==='remove'&&openE&&openE.fields[fd.idx]?'Remove the field “'+(openE.fields[fd.idx].label||'(no label)')+'” from this entry? The other fields stay as they are.':'',
      fdLabel:fd?fd.label:'', onFdLabel:(ev)=>this.setState({fd:{...this.state.fd,label:ev.target.value,err:''}}),
      fdValue:fd?fd.value:'', onFdValue:(ev)=>this.setState({fd:{...this.state.fd,value:ev.target.value,err:''}}),
      fdValueLabel:fd&&fd.mode==='edit'?'new value':'value', fdValueHint:fd&&fd.mode==='edit'?'leave empty to keep the current value':'value (grows, multi-line)',
      fdFormHint:fd&&fd.mode==='edit'?'The current value is never shown here. Only what you change is saved.':'The type and whether it is hidden are inferred from the label and the value. Change them afterwards with Edit.',
      fdType:fd?fd.type:'text', onFdType:(ev)=>this.setState({fd:{...this.state.fd,type:ev.target.value}}),
      fdTypeOpts:['text','username','password','url','host','port','api-key','private-key','certificate','totp-seed','seed-phrase'].map(id=>({id})),
      fdMasked:fd?fd.masked:'no', onFdMasked:(ev)=>this.setState({fd:{...this.state.fd,masked:ev.target.value}}),
      fdErrShow:!!(fd&&fd.err), fdErr:fd?fd.err:'', fdVariant:fd&&fd.mode==='remove'?'danger':'primary',
      fdSaveLabel:fd?({add:'Add field',edit:'Save',remove:'Remove'})[fd.mode]:'', fdSaveDisabled:!!fd&&fd.mode==='add'&&!fd.value,
      saveFieldForm:()=>this.saveFieldDlg(), addFieldOpen:()=>this.openFieldDlg('add',null),
      opsResultShow:!!s.opsResult, opsResultTitle:s.opsResult?s.opsResult.title+' · '+s.opsResult.at:'',
      opsResultLines:s.opsResult?s.opsResult.lines.map(([text,tone])=>({text,tone:tone==='warn'?'var(--warn)':tone==='mute'?'var(--mute)':'var(--bone)'})):[],
      runBackupNow:()=>this.setState({backupAt:this.hhmm()}), backupDoneShow:!!s.backupAt, backupDoneText:s.backupAt?'backup written '+s.backupAt+' · encrypted archive in the vault folder › backups':'',
      retainVal:s.backupRetention||'14', onRetain:(ev)=>this.setState({backupRetention:ev.target.value}),
      verifyChipState:s.verifiedAt?'ok':'', verifyChipLabel:s.verifiedAt?'ok · checked '+s.verifiedAt:'not checked yet', runVerifyNow:()=>this.setState({verifiedAt:this.hhmm()}),
      runRotate:()=>this.runOp('rotate'),
      ovSettings:s.overlay==='settings', ovOps:s.overlay==='ops',
      closeOverlay:set({overlay:null}),
      settingsNav:nav, modeLabel:isPro?'pro':'lite',
      setSecurity:s.setSection==='security', setAppearance:s.setSection==='appearance', setBackup:s.setSection==='backup', setMode:s.setSection==='mode',
      setGames:s.setSection==='games',
      setNodes:isPro&&s.setSection==='nodes', setGrants:isPro&&s.setSection==='grants', setAgents:isPro&&s.setSection==='agents',
      setMaint:isPro&&s.setSection==='maintenance', setAudit:isPro&&s.setSection==='audit', setAdvanced:isPro&&s.setSection==='advanced',
      isPro, isLite,
      secLevels:['open','guarded','sealed'].map(lv=>{const on=s.secLevel===lv;return{label:lv,bg:on?'var(--bone)':'transparent',fg:on?'var(--night)':'var(--bone)',set:()=>this.setState({secLevel:lv})};}),
      secLevelDesc:secDesc[s.secLevel],
      integrityDesc:isLite?'checks every envelope against its manifest digest':'Verify here; Doctor and the rest in Operations (⌘⇧O)',
      setDark:()=>this.setState({theme:'dark'}), setLight:()=>this.setState({theme:'light'}),
      darkBtnBg:dB,darkBtnFg:dF,lightBtnBg:lB,lightBtnFg:lF,
      colourOff:()=>this.setState({colour:'off'}), colourOn:()=>this.setState({colour:'on'}), colourAuto:()=>this.setState({colour:'auto'}),
      coffBg:coB,coffFg:coF,conBg:cnB,conFg:cnF,cautoBg:caB,cautoFg:caF,
      colourIsOn:e.colour==='on', hueVal:String(e.hue), intVal:String(e.intensity),
      onHue:(ev)=>this.setState({hue:+ev.target.value}), onIntensity:(ev)=>this.setState({intensity:+ev.target.value}),
      huePresets:[['Vault',198],['Ink',255],['Moss',150],['Rust',30],['Slate',220]].map(([label,h])=>({label,set:()=>this.setState({hue:h,colour:'on'})})),
      toggleGreyscale:()=>this.setState({greyscale:!e.greyscale}), gsLabel:e.greyscale?'greyscale on':'greyscale off',
      autoLockVal:String(s.autoLockMins), onAutoLock:(ev)=>{const m=+ev.target.value; this.setState({autoLockMins:m},()=>this.armAutoLock());},
      revealWindowVal:String(s.revealWindowSecs), onRevealWindow:(ev)=>this.setState({revealWindowSecs:+ev.target.value}),
      contrastVal:s.contrastMode, onContrast:(ev)=>this.setState({contrastMode:ev.target.value}), contrastAttr:s.contrastMode==='high'?'high':'standard',
      cosmHaloOn:!!cosm.halo, cosmRingOn:!!cosm.ring, contentSearchOn:!!s.contentSearchEnabled, hwAccelOn:s.hwAccel!==false,
      singleKeysOn:s.singleKeys!==false, singleKeysLabel:s.singleKeys!==false?'on':'off',
      toggleSingleKeys:()=>{ const on=!(this.state.singleKeys!==false); try{ if(on)localStorage.removeItem('credmgr_keys'); else localStorage.setItem('credmgr_keys','off'); }catch(e){} this.setState({singleKeys:on}); },
      motionVal:s.motion, onMotion:(ev)=>this.setState({motion:ev.target.value}), reducedMotionAttr:s.motion==='reduced'?'true':'false',
      toggleHwAccel:()=>this.setState(st=>({hwAccel:!st.hwAccel})), hwAccelLabel:s.hwAccel!==false?'on':'off',
      logoDotStyle:s.motion==='reduced'?'animation:none':('animation:logoPulse 3.4s ease-in-out infinite'+(s.hwAccel!==false?';will-change:opacity':'')),
      lockGlyphStyle:s.motion==='reduced'?'display:inline-block':('display:inline-block;animation:lockPulse 2.4s ease-in-out infinite'+(s.hwAccel!==false?';will-change:opacity':'')),
      advSubShare:s.addNodeAdv.subShare, onAdvSubShare:()=>this.setState(st=>({addNodeAdv:{...st.addNodeAdv,subShare:!st.addNodeAdv.subShare}})),
      advTwofa:s.addNodeAdv.twofa, onAdvTwofa:()=>this.setState(st=>({addNodeAdv:{...st.addNodeAdv,twofa:!st.addNodeAdv.twofa}})),
      advChildRead:s.addNodeAdv.childRead, onAdvChildRead:()=>this.setState(st=>({addNodeAdv:{...st.addNodeAdv,childRead:!st.addNodeAdv.childRead}})),
      advAgentAccess:s.addNodeAdv.agentAccess, onAdvAgentAccess:(ev)=>this.setState(st=>({addNodeAdv:{...st.addNodeAdv,agentAccess:ev.target.value}})),
      setLite:()=>this.setState({mode:'lite',setSection:'mode'}), setPro:()=>this.setState({mode:'pro'}),
      liteBtnBg:liB,liteBtnFg:liF,proBtnBg:prB,proBtnFg:prF,
      settingsNodeRows:v.nodes.filter(n=>n.id!=='global').map(n=>({label:n.label,meta:`${n.kind} · ${n.counts.entries} entries${n.parentId&&n.parentId!=='global'?' · under '+n.parentId:''}`,seal:()=>this.setState({dialog:'seal',sealTarget:n.id,sealTyped:''})})),
      openAddNodeDlg:()=>this.setState({dialog:'addNode',newNodeParent:'global',newNodeName:''}),
      sealedRows:v.sealed.map((r,i)=>({label:r.node.label,meta:`sealed ${r.date} · ${r.kids.length} sub-nodes · window ends in 7d`,restore:()=>this.restoreSealed(i)})),
      sealedEmpty:!v.sealed.length,
      grantRows:v.grants.map((gr,i)=>({fromTo:`${gr.from} ⇢ ${gr.to}`,scope:gr.scope,expires:gr.expires,lastUsed:gr.lastUsed,reason:gr.reason,revoke:()=>{v.grants.splice(i,1);v.links=v.links.filter(l=>!(l.kind==='grant'&&(l.source.id||l.source)===gr.from&&(l.target.id||l.target)===gr.to));this.refreshGraph();this.forceUpdate();}})),
      grantsEmpty:!v.grants.length,
      openGrantDlg:set({dialog:'grant'}),
      llmClients:llm,
      connectAll:()=>this.setState({connected:{'Claude Code':true,'Cursor':true,'VS Code (Copilot)':true,'Claude Desktop':true}}),
      copyPrompt:()=>{try{navigator.clipboard.writeText(vp);}catch(x){} this.setState({promptCopied:true});setTimeout(()=>this.setState({promptCopied:false}),1500);},
      copyPromptLabel:s.promptCopied?'Copied ✓':'Copy the vault prompt',
      levelCards, vaultPrompt:vp,
      openOps:set({overlay:'ops'}), opsRows, auditRows
    };
  }
}

export default Component;
