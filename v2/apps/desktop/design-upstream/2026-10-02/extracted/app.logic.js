import React from "react";
import { DCLogic } from "../../dc/runtime";

class Component extends DCLogic {
  constructor(props){
    super(props);
    // Callback ref: the lock and first-run screens unmount the whole app, so the graph's container is a fresh empty <div> every time it comes back. This re-attaches the existing canvas (with its listeners) the moment that container mounts.
    this.graphRef=(el)=>{ this.graphRef.current=el; if(el&&this.gcv&&!el.contains(this.gcv))this.initGraph(); };
    this.graphRef.current=null;
    this.cpRef = React.createRef();
    const mk=(n,i)=>({id:n.toLowerCase().replace(/[^a-z0-9]/g,'-')+'-'+i,name:n,type:'api',sensitivity:'medium',totp:false,fields:[{label:'token',value:'sk_'+Math.random().toString(36).slice(2,18),type:'api-key',masked:true}],meta:'api · medium'});
    const pool=(names,count,pfx)=>{const out=[];let i=0;while(out.length<count){const base=names[i%names.length];const suf=i>=names.length?(i>=names.length*2?'-old':'-staging'):'';out.push(mk(base+suf,pfx+'-'+i));i++;}return out;};
    const linuxEntries=[
      {id:'lx-1',name:'vps-root',type:'server',sensitivity:'critical',totp:true,meta:'server · critical · rotated 2026-06-30',fields:[
        {label:'host',value:'203.0.113.4',type:'host',masked:false},
        {label:'port',value:'22',type:'port',masked:false},
        {label:'username',value:'root',type:'username',masked:false},
        {label:'password',value:'kR9!wq-zN4#tUv82', type:'password',masked:true},
        {label:'2fa seed',value:'JBSWY3DPEHPK3PXP',type:'totp-seed',masked:true}]},
      {id:'lx-2',name:'deploy-key',type:'ssh',sensitivity:'critical',totp:false,meta:'ssh · critical',fields:[
        {label:'username',value:'deploy',type:'username',masked:false},
        {label:'private key',value:'-----BEGIN EXAMPLE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\nQyNTUxOQAAACBv8m2LkR7qwXe4nP0aZsT1cJd6yGh…\n-----END EXAMPLE KEY-----',type:'private-key',masked:true},
        {label:'passphrase',value:'correct horse battery staple',type:'password',masked:true}]},
      {id:'lx-3',name:'grafana-admin',type:'login',sensitivity:'high',totp:true,meta:'login · high',fields:[{label:'url',value:'https://grafana.internal:3000',type:'url',masked:false},{label:'username',value:'admin',type:'username',masked:false},{label:'password',value:'g7#Kq!mm20-xx',type:'password',masked:true},{label:'2fa seed',value:'KRSXG5CTMVRXEZLU',type:'totp-seed',masked:true}]},
      {id:'lx-4',name:'backup-b2',type:'api',sensitivity:'high',totp:true,meta:'api · high',fields:[{label:'keyID',value:'0021ab4cd9ef0000000001',type:'api-key',masked:false},{label:'applicationKey',value:'K002ZxY1mQ8pL0vB3nT6wA9sD2fG4hJ7k',type:'api-key',masked:true},{label:'bucket',value:'vault-backups-eu',type:'text',masked:false}]},
      {id:'lx-5',name:'pg-primary',type:'server',sensitivity:'critical',totp:false,meta:'server · critical',fields:[{label:'host',value:'10.0.0.4',type:'host',masked:false},{label:'port',value:'5432',type:'port',masked:false},{label:'username',value:'svc_app',type:'username',masked:false},{label:'password',value:'Z9!kq2LmPw',type:'password',masked:true}]},
      {id:'lx-6',name:'registry-token',type:'api',sensitivity:'medium',totp:false,meta:'api · medium',fields:[{label:'token',value:'reg_9f3aa10cc271e8',type:'api-key',masked:true}]},
      {id:'lx-7',name:'wireguard-peer',type:'other',sensitivity:'high',totp:false,meta:'other · high',fields:[{label:'private key',value:'cF9x…redacted…mM0=',type:'private-key',masked:true},{label:'endpoint',value:'vpn.internal:51820',type:'text',masked:false}]},
      {id:'lx-8',name:'tailscale-auth',type:'api',sensitivity:'medium',totp:false,meta:'api · medium',fields:[{label:'authkey',value:'tskey-auth-kT4…',type:'api-key',masked:true}]},
      {id:'lx-9',name:'smtp-relay',type:'login',sensitivity:'medium',totp:false,meta:'login · medium',fields:[{label:'host',value:'smtp.eu.mailgun.org',type:'host',masked:false},{label:'username',value:'postmaster@example.com',type:'username',masked:false},{label:'password',value:'m4!Lg-un88',type:'password',masked:true}]},
      {id:'lx-10',name:'cf-tunnel',type:'api',sensitivity:'medium',totp:false,meta:'api · medium',fields:[{label:'tunnel token',value:'eyJhIjoi…',type:'api-key',masked:true}]},
      {id:'lx-11',name:'monit-webhook',type:'api',sensitivity:'low',totp:false,meta:'api · low',fields:[{label:'url',value:'https://hooks.internal/monit/x91',type:'url',masked:false}]},
      {id:'lx-12',name:'fail2ban-alerts',type:'login',sensitivity:'low',totp:false,meta:'login · low',fields:[{label:'email',value:'alerts@internal',type:'username',masked:false},{label:'password',value:'f2b-r0t8d',type:'password',masked:true}]}
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
    entriesMode:'all', gameScreen:'menu', cpMode:'bottom',
    autoLockMins:15, revealWindowSecs:20, contrastMode:'standard', motion:'system', hwAccel:true,
    addNodeAdv:{subShare:true, twofa:true, childRead:false, agentAccess:'read-write'},
    pendingBanner:false, pendingNote:'', cosm:{mark:'keep',glyph:'classic',halo:false,ring:false}, cosmPreview:false
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
  ctxPosFor(clientX,clientY){ // B3-2: position the context menu relative to .cm-main, clamped inside it — not raw viewport coords + magic offsets
    const mainEl=this.graphRef.current&&this.graphRef.current.closest('.cm-main');
    const rc=mainEl?mainEl.getBoundingClientRect():{left:0,top:0,width:window.innerWidth,height:window.innerHeight};
    const menuW=190,menuH=230;
    let x=clientX-rc.left, y=clientY-rc.top;
    x=Math.max(8,Math.min(x,rc.width-menuW)); y=Math.max(8,Math.min(y,rc.height-menuH));
    return {x,y};
  }
  armAutoLock(){ clearTimeout(this._autoLockT); const m=this.state.autoLockMins; if(!m)return; this._autoLockT=setTimeout(()=>{ if(this.state.screen==='app'&&!this.state.vaultLocked)this.setState({vaultLocked:true,reveals:{}}); },m*60000); }
  componentDidMount(){
    window.__cm=this;
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
    };
    document.addEventListener('pointerdown',this._outsideH);
    this._donateTimer=setTimeout(()=>{ if(this.state.screen==='app'&&!this.state.vaultLocked&&!this.donateIsUnlocked())this.setState({donateToastOpen:true}); },6000);
    this._fitH=()=>{ if(this.gSize)this.gSize(); this.renderGraph(); };
    window.addEventListener('load',this._fitH);
    if(document.readyState==='complete')Promise.resolve().then(this._fitH);
    if(document.fonts&&document.fonts.ready)document.fonts.ready.then(this._fitH);
    this.keyH=(e)=>{
      const tag=(e.target.tagName||'').toLowerCase(); const typing=tag==='input'||tag==='textarea'||tag==='select';
      if(this.state.overlay==='games'){ // C-5: Escape pauses first, exits on a second press; P also toggles pause
        if(e.key==='Escape'){ if(this.state.gameScreen==='play'&&this.cp){ if(this.cp.paused)this.cpExit(); else this.cp.paused=true; } else this.cpExit(); }
        else if((e.key==='p'||e.key==='P')&&this.state.gameScreen==='play'&&this.cp){ this.cp.paused=!this.cp.paused; }
        return; }
      if(e.key==='Escape'){this.setState({searchOpen:false,vaultMenu:false,ctx:null,dialog:null,overlay:null,hover:null,railOpen:false,inspOpen:false});return;}
      if(e.key==='Tab'&&(this.state.dialog||this.state.overlay)){this.trapTab(e);return;} // B5-2: keep Tab cycling inside the open modal
      if(typing)return;
      if(this.state.dialog||this.state.overlay)return; // B3-1: block bare shortcuts while a dialog/overlay is open — only Escape (above) is live
      if(e.key==='/'){e.preventDefault();const el=document.querySelector('input[placeholder^="search"]');if(el)el.focus();}
      if(e.key==='f'||e.key==='F'){this.zoomToFitG();}
      if(e.key==='g'||e.key==='G'){this.select('global');}
      if(e.key==='t'||e.key==='T'){this.setState(st=>({view:st.view==='graph'?'tree':'graph'}));}
      if(e.key==='n'||e.key==='N'){const n=this.node(this.state.selected); this.openAddDlg(n?n.id:'global');}
      if(e.key==='e'||e.key==='E'){this.setState(st=>({entriesMode:st.entriesMode==='all'?'selected':'all'}),()=>{this.buildEntryNodes();this.renderGraph();});}
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
    document.removeEventListener('pointerdown',this._outsideH);
    document.removeEventListener('visibilitychange',this._visH);
    window.removeEventListener('load',this._fitH);
    ['mousemove','keydown','mousedown','touchstart'].forEach(ev=>window.removeEventListener(ev,this._activityH));
    this.cpStopListeners();clearInterval(this.timer);clearTimeout(this._donateTimer);clearTimeout(this._autoLockT);clearTimeout(this._clipT);clearTimeout(this._pnT);
    if(this._raf)cancelAnimationFrame(this._raf);if(this.ro)this.ro.disconnect();
  }
  componentDidUpdate(prevProps,prevState){
    const e=this.eff();
    const sig=[e.theme,e.colour,e.hue,e.intensity].join('|');
    if(sig!==this._sig){ this._sig=sig; this.applyTheme(); this.pal=null; if(this.entryNodes)for(const en of this.entryNodes)en.color=this.entryColor(en.id); if(this.gcv)this.renderGraph(); }
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
  palette(){
    if(this.pal)return this.pal;
    const cs=getComputedStyle(document.documentElement);
    const g=(v)=>cs.getPropertyValue(v).trim();
    const p={bone:g('--bone'),ash:g('--ash'),mute:g('--mute'),faint:g('--faint'),warn:g('--warn'),danger:g('--danger'),sig:g('--sig'),hairS:g('--hair-strong'),void:g('--void')};
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
    if(this.gcv){ el.innerHTML=''; el.appendChild(this.gcv); if(this.ro){this.ro.disconnect();this.ro.observe(el);} if(this.gSize)this.gSize(); this.renderGraph(); return; }
    el.innerHTML='';
    const cv=document.createElement('canvas');
    cv.style.cssText='position:absolute;inset:0;cursor:default';
    cv.setAttribute('role','img'); cv.setAttribute('aria-label','Vault graph: node relationships and entry counts, drawn on canvas. Press T for the accessible tree view (full parity), F to fit, G for global.'); // B5-5
    el.appendChild(cv); this.gcv=cv;
    this.gv={k:1,tx:0,ty:0};
    this.gd=this.graphData(); // hard-floor spacing runs unconditionally every tick, so stale/cramped stored positions self-correct on the first frames
    const sizeIt=()=>{ const rc=el.getBoundingClientRect(); const dpr=window.devicePixelRatio||1;
      if(rc.width<=50||rc.height<=50){ requestAnimationFrame(sizeIt); return; } // container not laid out yet — retry next frame; never cache a guessed fallback size
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
    ctx.translate(this.gv.tx,this.gv.ty); ctx.scale(this.gv.k,this.gv.k);
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
  entryColor(id){const h=((this.hashStr(id)*2654435761)>>>0)%360;return this.eff().theme==='dark'?`oklch(0.74 0.125 ${h})`:`oklch(0.5 0.13 ${h})`;}
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
    window.__cmPaint=(window.__cmPaint||0)+1;
    const p=this.palette(); const r=this.nodeR(n); const sel=this.state.selected===(n.id==='__orphan'?'__orphan':n.id);
    const q=this.state.searchQ.trim().toLowerCase();
    const dim=q&&!n.label.toLowerCase().includes(q);
    ctx.save(); ctx.globalAlpha=dim?0.25:1;
    ctx.lineWidth=(sel?2.5:n.kind==='sub'?1:1.5)/1;
    if(n.kind==='orphan'){
      ctx.setLineDash([3,3]); ctx.strokeStyle=p.faint;
      ctx.beginPath();ctx.arc(n.x,n.y,r,0,2*Math.PI);ctx.stroke();
      ctx.setLineDash([]);
      ctx.save();ctx.beginPath();ctx.arc(n.x,n.y,r-1,0,2*Math.PI);ctx.clip();
      ctx.strokeStyle=p.faint;ctx.globalAlpha=(dim?0.25:1)*0.5;ctx.lineWidth=0.6;
      for(let i=-r*2;i<r*2;i+=4){ctx.beginPath();ctx.moveTo(n.x+i-r,n.y+r);ctx.lineTo(n.x+i+r,n.y-r);ctx.stroke();}
      ctx.restore();
    } else if(n.kind==='global'){
      ctx.fillStyle=p.bone;ctx.beginPath();ctx.arc(n.x,n.y,r,0,2*Math.PI);ctx.fill();
    } else {
      ctx.strokeStyle=n.health==='danger'?p.danger:(n.kind==='sub'?p.ash:p.bone);
      ctx.beginPath();ctx.arc(n.x,n.y,r,0,2*Math.PI);ctx.stroke();
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
    else { ctx.strokeStyle=p.hairS; ctx.setLineDash([]); }
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
  donateUnlockCodeVal(){return 'REMOVED';}
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
  cpStart(){ this.setState({overlay:'games',gameScreen:'play'},()=>this.cpInit()); }
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
    c.trail.push({x:b.x,y:b.y}); if(c.trail.length>10)c.trail.shift();
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
    const c=this.cp,ctx=c.ctx,p=this.palette(),W=680,H=440,now=performance.now();
    ctx.clearRect(0,0,W,H); ctx.fillStyle=p.void||'#0b0d10'; ctx.fillRect(0,0,W,H);
    for(const n of c.nodes){ if(!n.alive&&now-n.pop>260)continue;
      const np=this.cpNodePos(n,now), fade=n.alive?1:Math.max(0,1-(now-n.pop)/260), scale=n.alive?1:1+(1-fade)*0.6;
      ctx.save(); ctx.globalAlpha=fade;
      for(const en of n.entries){ if(!en.alive)continue; const ang=en.slot.a+now*en.slot.rot, ex=np.x+Math.cos(ang)*en.ring, ey=np.y+Math.sin(ang)*en.ring;
        ctx.strokeStyle=n.color; ctx.globalAlpha=fade*0.4; ctx.lineWidth=0.8; ctx.beginPath(); ctx.moveTo(np.x,np.y); ctx.lineTo(ex,ey); ctx.stroke();
        ctx.globalAlpha=fade; ctx.fillStyle=n.color; ctx.beginPath(); ctx.arc(ex,ey,3.4,0,7); ctx.fill(); }
      ctx.strokeStyle=n.color; ctx.lineWidth=n.coreLeft===1?2.4:1.4; ctx.beginPath(); ctx.arc(np.x,np.y,n.shellR*scale,0,7); ctx.stroke();
      if(n.alive&&n.coreFlash&&now-n.coreFlash<160){ ctx.globalAlpha=fade*(1-(now-n.coreFlash)/160); ctx.lineWidth=2; ctx.beginPath(); ctx.arc(np.x,np.y,n.shellR*scale+5,0,7); ctx.stroke(); ctx.globalAlpha=fade; }
      this.drawGlyph(ctx,np.x,np.y,n.shellR*0.5*scale,n.glyphIdx,n.color);
      ctx.restore(); }
    for(let i=0;i<c.trail.length;i++){ const t=c.trail[i]; ctx.globalAlpha=(i+1)/c.trail.length*0.35; ctx.fillStyle=p.bone;
      ctx.beginPath(); ctx.arc(t.x,t.y,c.ball.r*0.8,0,7); ctx.fill(); }
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
  cpExit(){ this.cpStopListeners(); this.setState({overlay:null,gameScreen:'menu'}); }
  cpBackToMenu(){ this.cpStopListeners(); this.setState({gameScreen:'menu'}); }
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
    if(!fields.length||(!split&&!s.addName.trim()))return;
    const nid=s.addNode, locked=!!s.vaultLocked, stamp=Date.now();
    let groups=[fields];
    if(split){ const m=new Map(); for(const f of fields){ if(!m.has(f.seg))m.set(f.seg,[]); m.get(f.seg).push(f); } groups=[...m.values()]; } // FIELD_MODEL §5: each /// segment becomes its own entry, named from its first label or "untitled n"
    const taken=new Set([...(this.vault.entries[nid]||[]).map(e=>e.name.toLowerCase()),...(this.vault.pending||[]).filter(p=>p.node===nid).map(p=>p.name.toLowerCase())]);
    let untitled=0;
    const recs=groups.map((gf,gi)=>{
      let nm=split?((gf[0].label||'').trim()||('untitled '+(++untitled))):s.addName.trim();
      if(split){ const base=nm; let k=2; while(taken.has(nm.toLowerCase()))nm=base+' '+(k++); taken.add(nm.toLowerCase()); }
      return {id:(locked?'pd-':'new-')+stamp+'-'+gi,name:nm,type:this.entryTypeOf(gf),sensitivity:this.sensOf(gf),totp:gf.some(f=>f.type==='totp-seed'),fields:gf.map(f=>({label:f.label||'field',value:f.value,type:f.type,masked:f.masked}))};
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
  unlockApp(){ this.setState({screen:'app',vaultLocked:false,lockStep:1,passInput:'',twofa:'',pendingBanner:(this.vault.pending||[]).length>0}); }
  cosmKey(){return 'credmgr_cosmetics';}
  loadCosmetics(){ try{ const raw=localStorage.getItem(this.cosmKey()); if(!raw)return; const o=JSON.parse(raw)||{};
      this.setState({cosm:{mark:['keep','cells','node','seal'].includes(o.mark)?o.mark:'keep',glyph:['classic','fine','heavy'].includes(o.glyph)?o.glyph:'classic',halo:!!o.halo,ring:!!o.ring}}); }catch(e){} }
  cosmOn(){ return this.donateIsUnlocked()||!!this.state.cosmPreview||!!this.props.supporterPreview; } // cosmetic-only gate: honour-system local flag, never gates function
  cosmEff(){ return this.cosmOn()?this.state.cosm:{mark:'keep',glyph:'classic',halo:false,ring:false}; }
  setCosm(patch){ if(!this.cosmOn())return; const next={...this.state.cosm,...patch}; try{localStorage.setItem(this.cosmKey(),JSON.stringify(next));}catch(e){} this.setState({cosm:next}); }
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
      commitRename:()=>{ const val=s.renameVal.trim(); if(val){ n.label=val; this.refreshGraph(); } this.setState({renamingNode:null}); },
      cancelRename:(ev)=>{ if(ev.key==='Escape')this.setState({renamingNode:null}); else if(ev.key==='Enter'){const val=s.renameVal.trim(); if(val){n.label=val;this.refreshGraph();} this.setState({renamingNode:null});} },
      select:()=>this.select(n.id),
      menu:(ev)=>{ev.preventDefault();const pos=this.ctxPosFor(ev.clientX,ev.clientY);this.setState({ctx:{x:pos.x,y:pos.y,node:n.id}});} // B3-2
    });};
    push(this.node('global'),0);
    for(const p of v.nodes.filter(n=>n.depth===1)){ push(p,0); for(const c of this.children(p.id)) push(c,1); }
    railRows.push({id:'__orphan',label:'orphaned',kind:'orphan',count:String(v.orphans.length),indent:'0px',current:s.selected==='__orphan'?'true':'false',color:'var(--mute)',border:'1px dashed var(--faint)',badges:'',lockColor:'var(--mute)',select:()=>this.select('__orphan'),menu:(ev)=>ev.preventDefault()});
    // tree view rows
    const treeRows=railRows.map(r=>{ const n=r.id==='__orphan'?{kind:'orphan',counts:{entries:v.orphans.length,totp:null},gate:{locked:false,twofa:'none'}}:this.node(r.id);
      return { ...r, indent:(parseInt(r.indent)*2)+'px', guide:parseInt(r.indent)>0?'1px solid var(--hair)':'none',
        bg:s.selected===r.id?'var(--steel-3)':'transparent', subColor:s.selected===r.id?'var(--ash)':'var(--mute)', lockColor:s.selected===r.id?'var(--ash)':r.lockColor,
        glyphColor:n.kind==='orphan'?'var(--faint)':n.kind==='sub'?'var(--ash)':'var(--bone)',
        gr:n.kind==='global'?'8':n.kind==='sub'?'5':'7', gfill:n.kind==='global'?'currentColor':'none',
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
        copy:()=>{ if(s.vaultLocked)return; this.copySecret(f.value); this.setState(st=>({copied:{...st.copied,[key]:Date.now()+1500}}));} }; // B6-1: copy was the one hole in the locked model
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
    const newNodeProposedId=s.newNodeName.trim().toLowerCase().replace(/\s+/g,'-');
    const newNodeDup=!!newNodeProposedId&&v.nodes.some(n=>n.id===newNodeProposedId); // B4-3: duplicate node names collided silently before this
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
    const opsRows=[
      ['Verify integrity','Check every envelope and manifest checksum.','maintenance.verify'],['Doctor','Diagnose and repair registry, refs, manifests.','maintenance.doctor'],
      ['Back up vault','Encrypted archive to the configured destination.','maintenance.backup'],['Merge entries','Combine duplicates into one entry. Rarely needed in V2.','entry.merge'],
      ['Re-key a node','Generate a new node key, re-encrypt its entries.','node.rekey'],['Rotate root key','New root key; re-issues the recovery code.','maintenance.rotate_root'],
      ['Export node','Write a .env for one node. Requires 2FA.','node.export'],['Import .env','Read a .env into a chosen node.','node.import'],
      ['Purge access log','Empty the access log.','audit.purge'],['Audit report','Read/deny activity + stale grants, last 30 days.','audit.get']
    ].map(([name,desc,op])=>({name,desc,opTitle:op+' is not built yet'}));
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
    const addNameDup=!splitOn&&!!s.addName.trim()&&[...(v.entries[s.addNode]||[]).map(en=>en.name),...pend.filter(p=>p.node===s.addNode).map(p=>p.name)].some(nm=>nm.toLowerCase()===s.addName.trim().toLowerCase());
    const cosmMarks=[['keep','keep',true],['cells','cells',false],['node','node + ring',false],['seal','seal',false]].map(([id,label,free])=>({label,isKeep:id==='keep',isCells:id==='cells',isNode:id==='node',isSeal:id==='seal',on:cosm.mark===id,disabled:!free&&!cosmOn,border:cosm.mark===id?'var(--bone)':'var(--faint)',bg:cosm.mark===id?'var(--steel-3)':'transparent',set:()=>this.setCosm({mark:id})}));
    const cosmGlyphs=[['classic',1.2,true],['fine',0.8,false],['heavy',2,false]].map(([id,sw,free])=>({label:id,sw:String(sw),on:cosm.glyph===id,disabled:!free&&!cosmOn,bg:cosm.glyph===id?'var(--bone)':'transparent',fg:cosm.glyph===id?'var(--night)':'var(--bone)',set:()=>this.setCosm({glyph:id})}));
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
      addNameDup, addNameDupMsg:'an entry called “'+s.addName.trim()+'” already exists in '+s.addNode, addNameSplitNote:splitOn,
      cosmUnlocked:cosmOn, cosmLockedShow:!cosmOn, cosmMarks, cosmGlyphs, cosmHaloLabel:cosm.halo?'on':'off', cosmRingLabel:cosm.ring?'on':'off', cosmRing:cosm.ring, cosmToggleDisabled:!cosmOn,
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
      frNextLabel:fr.step===5?'Open the vault':(fr.step===4?'Enrol later':'Continue'),
      frNextDisabled:fr.step===3&&!fr.rec,
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
        {label:'Games — CredPong',kbd:'',go:()=>this.setState({overlay:'games',gameScreen:'menu',vaultMenu:false})},
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
      openGames:()=>this.setState({overlay:'games',gameScreen:s.gameScreen==='over'?'menu':(s.gameScreen||'menu'),vaultMenu:false}),
      ovGames:s.overlay==='games', cpIsMenu:(s.gameScreen||'menu')==='menu', cpIsPlay:s.gameScreen==='play', cpIsOver:s.gameScreen==='over',
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
      hoverVisible:!!hv, hoverX:hv?(typeof hv.x==='number'?hv.x+'px':hv.x):'0px', hoverY:hv?(typeof hv.y==='number'?hv.y+'px':hv.y):'0px',
      hoverEntries:hv?String(hv.entries):'', hoverTotp:hv?String(hv.totp):'',
      hoverIsEntry, hoverIsNode, hoverEntryType:hv&&hv.etype?hv.etype:'',
      ctxVisible:!!s.ctx, ctxX:s.ctx?s.ctx.x+'px':'0px', ctxY:s.ctx?s.ctx.y+'px':'0px', ctxItems,
      inspNode:!!sel&&!openE, inspOrphan:s.selected==='__orphan', inspEntry:!!openE,
      inspLabel:sel?sel.label:'', inspCounts:sel?`${sel.counts.entries} entries · ${sel.counts.totp} 2FA`:'',
      inspLocked:sel?sel.gate.locked:false, insp2fa:sel?sel.gate.twofa==='required':false,
      inspEntries:inspEntriesArr.map(en=>({name:en.name,type:en.type,totp:en.totp,sens:en.sensitivity==='critical'?'3px solid var(--danger)':en.sensitivity==='high'?'3px solid var(--bone)':en.sensitivity==='medium'?'2px solid var(--mute)':'1px solid var(--faint)',open:()=>this.setState({openEntry:en.id})})),
      inspEmpty:sel&&!inspEntriesArr.length,
      inspNotes:s.vaultLocked?'locked — note text needs the vault open':(sel&&sel.notes?sel.notes:'—'),
      orphanCount:String(v.orphans.length), orphanItems:v.orphans,
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
      newNodeDupShow:newNodeDup, newNodeDupMsg:newNodeDup?('a node called "'+newNodeProposedId+'" already exists'):'',
      newNodeDisabled:!s.newNodeName.trim()||newNodeDup,
      confirmAddNode:()=>{ if(newNodeDup)return; const nm=newNodeProposedId; const par=s.newNodeParent; const depth=par==='global'?1:2;
        const adv=isPro?s.addNodeAdv:{subShare:true,twofa:false,childRead:false,agentAccess:'read-write'};
        v.nodes.push({id:nm,label:nm,kind:depth===1?'project':'sub',depth,parentId:par,counts:{entries:0,totp:0},
          gate:{locked:false,twofa:adv.twofa?'required':'none'},health:null,notes:'',
          folders:s.newNodeFolders.filter(f=>f.trim()),subShare:adv.subShare,childRead:adv.childRead,agentAccess:adv.agentAccess}); // B4-2: advanced options now land on the node instead of being discarded
        v.links.push({source:par,target:nm,kind:'structural'}); v.entries[nm]=[]; this.refreshGraph(); this.setState({dialog:null,newNodeName:'',newNodeFolders:[''],selected:nm}); },
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
      donateToastVisible:!!(s.donateToastOpen&&s.screen==='app'&&!s.vaultLocked&&!s.dialog&&!s.overlay&&!this.donateIsUnlocked()),
      dismissDonateToast:()=>this.setState({donateToastOpen:false,donateView:'main',donateCode:'',donateCodeErr:false,donateCodeOk:false}),
      donateViewMain:(s.donateView||'main')==='main', donateViewGuide:s.donateView==='guide', donateViewCode:s.donateView==='code',
      goDonateGuide:()=>this.setState({donateView:'guide'}), goDonateCode:()=>this.setState({donateView:'code',donateCodeErr:false}),
      backDonateMain:()=>this.setState({donateView:'main',donateCodeErr:false}),
      donateCodeVal:s.donateCode||'', onDonateCode:(ev)=>this.setState({donateCode:ev.target.value,donateCodeErr:false}),
      submitDonateCode:()=>{ const ok=(s.donateCode||'').trim().toUpperCase()===this.donateUnlockCodeVal();
        if(ok){ try{localStorage.setItem(this.donateCodeKey(),'1');}catch(x){}
          this.setState({donateCodeOk:true,donateCodeErr:false});
          setTimeout(()=>this.setState({donateToastOpen:false,donateView:'main',donateCode:'',donateCodeOk:false}),1400);
        } else this.setState({donateCodeErr:true}); },
      donateCodeErrShow:!!s.donateCodeErr, donateCodeOkShow:!!s.donateCodeOk,
      contentSearchState:s.contentSearchEnabled?'ok':'', contentSearchLabel:s.contentSearchEnabled?'on':'off',
      toggleContentSearch:()=>this.setState(st=>({contentSearchEnabled:!st.contentSearchEnabled})),
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
      integrityDesc:isLite?'automatic — surfaces only on failure':'automatic + manual verify, doctor, repair in Operations',
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
