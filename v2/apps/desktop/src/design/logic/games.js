/* CredGames: the library, CredPong, and the host a further game plugs into.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Self-contained; nothing here reads the vault except node ids and entry counts.
   Split from the upstream monolith (design-upstream/PROVENANCE.md, ADR-075).  The host is the design drop of 2026-10-18 (GAMES.md), with ONE deliberate
   difference: it does not read a global `window.CredGames` list.  The upstream design loaded each further game from a plain script that pushed a
   definition onto that list; here no script can be added to the page (the production policy is script-src 'self' with no inline code), so a global list
   would only be a way for something that already runs in the page to hand code to the games host.  A further game is a module imported into
   BUNDLED_GAMES below, reviewed and built with the app. */

/** Further CredGames titles, bundled with the app: `{id,name,blurb,reads:'counts'|'nothing',controls,options:[{id,label,choices:[[id,label]]}],create(api)}`.  None ships yet. */
const BUNDLED_GAMES = [];

export const gamesMethods = {
  // CredPong — a light, local, isolated arcade game (see BACKEND_HANDOFF_NOTES.md for the
  // marketplace/multiplayer phase this deliberately does NOT build yet). Reuses this.formationSlots /
  // nodeGlyphIdx / entryColor / drawGlyph from the graph for visual continuity. Only ever reads node
  // ids and entry counts — never names or values — same boundary as the graph's entry dots.
  cpBestKey(){return 'credpong_best';},
  cpBest(){try{return parseInt(localStorage.getItem(this.cpBestKey())||'0',10)||0;}catch(e){return 0;}},
  cpSaveBest(score){try{if(score>this.cpBest())localStorage.setItem(this.cpBestKey(),String(score));}catch(e){}},
  cpProgressKey(){return 'credpong_level';},
  cpSavedLevel(){try{return Math.max(1,parseInt(localStorage.getItem(this.cpProgressKey())||'1',10)||1);}catch(e){return 1;}},
  cpSaveLevel(level){try{if(level>this.cpSavedLevel())localStorage.setItem(this.cpProgressKey(),String(level));}catch(e){}},
  cpModeDescFor(m){return m==='side'?'Paddle fixed to one side (random each run), moves along it.':m==='roam'?'Paddle roams the whole edge, follows your cursor. All four sides are open.':'Classic — paddle at the bottom, moves left/right.';},
  cpStart(){ this.setState({overlay:'games',gameId:'credpong',gameScreen:'play'},()=>this.cpInit()); },
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
  },
  cpPaddleInit(){ const c=this.cp;
    if(c.mode==='bottom')c.paddle={edge:'bottom',pos:340,len:90};
    else if(c.mode==='side')c.paddle={edge:c.side,pos:220,len:90};
    else c.paddle={edge:'bottom',pos:340,len:70,roam:true};
    this.cpRestBall();
  },
  cpRestBall(){ const c=this.cp,p=c.paddle,pt=this.cpEdgePoint(p.edge,p.pos);
    c.ball.x=pt.x; c.ball.y=pt.y; c.ball.vx=0; c.ball.vy=0; c.ball.resting=true; },
  cpEdgePoint(edge,pos){ const W=680,H=440,m=14;
    if(edge==='bottom')return{x:pos,y:H-m}; if(edge==='top')return{x:pos,y:m};
    if(edge==='left')return{x:m,y:pos}; return{x:W-m,y:pos}; },
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
  },
  cpNodePos(n,t){ return {x:n.baseX+Math.sin(t*0.0013+n.driftPhase)*n.driftAmp, y:n.baseY+Math.cos(t*0.0011+n.driftPhase*1.4)*n.driftAmp*0.6}; },
  cpSpeed(c){ const base=3.1*(1+c.level*0.055)*0.58, elapsed=(performance.now()-c.levelT0)/1000; return base*(1+Math.min(0.4,elapsed*0.0025)); },
  cpLoop(){
    if(!this.cp||this.state.overlay!=='games'||this.state.gameScreen!=='play')return;
    this.cpUpdate(); this.cpDraw();
    this._cpRaf=requestAnimationFrame(this.cpLoop);
  },
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
  },
  cpLoseLife(){ const c=this.cp; if(!c||c.ball.resting)return; c.lives--; c.trail=[];
    c.banner={text:c.lives>0?'−1 life':'',until:performance.now()+700};
    if(c.lives<=0)this.cpGameOver(); else this.cpRestBall(); },
  cpNextLevel(){ const lvl=(this.cp.level||1)+1; this.cpSaveLevel(lvl); this.cpBuildLevel(lvl); },
  cpGameOver(){ this.cpSaveBest(this.cp.score); this.cpStopListeners(); this.setState({gameScreen:'over'}); },
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
  },
  cpStopListeners(){ if(this._cpRaf)cancelAnimationFrame(this._cpRaf); this._cpRaf=null;
    if(this._cpKeyDown)window.removeEventListener('keydown',this._cpKeyDown);
    if(this._cpKeyUp)window.removeEventListener('keyup',this._cpKeyUp);
    if(this.cp&&this.cp.cv&&this._cpMouseMove)this.cp.cv.removeEventListener('mousemove',this._cpMouseMove); },
  cpExit(){ this.cpStopListeners(); this.ghStop(); this.setState({overlay:null,gameScreen:'library'}); },
  cpBackToMenu(){ this.cpStopListeners(); this.setState({gameScreen:'menu'}); },
  // CredGames host (GAMES.md).  CredPong is built in and keeps its own engine and keys.  Every further game is a bundled definition that the host
  // validates and then owns: the canvas, the loop, pause and exit, scores and storage.  The game gets a frozen api whose only vault data is counts.
  gamesList(){
    const out=[{id:'credpong',name:'CredPong',blurb:'Battle your vault’s nodes: keep the ball in play and break them, level by level.',reads:'node and entry counts',controls:null,options:[],builtIn:true}];
    const seen=new Set(['credpong']);
    for(const g of BUNDLED_GAMES){ if(!g||typeof g!=='object'||typeof g.create!=='function')continue; const id=String(g.id||'');
      if(!/^[a-z][a-z0-9-]{1,23}$/.test(id)||seen.has(id)||!g.name)continue; seen.add(id);
      const options=(Array.isArray(g.options)?g.options:[]).slice(0,2).filter(o=>o&&/^[a-z][a-z0-9-]{0,15}$/.test(o.id||'')&&Array.isArray(o.choices)&&o.choices.length>1)
        .map(o=>({id:o.id,label:this.cleanText(o.label||o.id).slice(0,24),choices:o.choices.slice(0,4).map(ch=>[String(ch[0]),this.cleanText(ch[1]||ch[0]).slice(0,16)])}));
      out.push({id,name:this.cleanText(g.name).slice(0,32),blurb:this.cleanText(g.blurb||'').slice(0,160),reads:g.reads==='counts'?'node and entry counts':'nothing from the vault',controls:this.cleanText(g.controls||'').slice(0,60),options,def:g}); }
    return out; },
  /** Strip zero-width and bidi controls from text a game supplies (names, labels). */
  cleanText(v){ return String(v==null?'':v).normalize('NFC').replace(/[​-‏‪-‮⁦-⁩﻿]/g,''); },
  gameStoreKey(id,k){ return id==='credpong'?('credpong_'+k):('credgames.'+id+'.'+k); },
  gameBest(id){ if(id==='credpong')return this.cpBest(); try{return parseInt(localStorage.getItem(this.gameStoreKey(id,'best'))||'0',10)||0;}catch(e){return 0;} },
  gameCounts(){ return Object.freeze(this.vault.nodes.filter(n=>n.kind!=='global'&&n.kind!=='orphan').map(n=>Object.freeze({glyph:this.nodeGlyphIdx(n.id),entries:+(n.counts&&n.counts.entries)||0}))); },
  gameOpenLibrary(){ this.cpStopListeners(); this.ghStop(); this.setState({overlay:'games',gameScreen:'library',vaultMenu:false}); },
  gameRun(){ return this.state.gameId&&this.state.gameId!=='credpong'?this._game:this.cp; },
  gameOpenMenu(id){ this.cpStopListeners(); this.ghStop(); this.setState({overlay:'games',gameId:id,gameScreen:'menu',vaultMenu:false}); },
  gameOpt(g,o){ const v=((this.state.gameOpts||{})[g.id]||{})[o.id]; return o.choices.some(ch=>ch[0]===v)?v:o.choices[0][0]; },
  gameStart(){ const id=this.state.gameId||'credpong'; if(id==='credpong')return this.cpStart(); const g=this.gamesList().find(x=>x.id===id); if(!g)return;
    this.ghStop(); this.setState({overlay:'games',gameScreen:'play'},()=>this.ghInit(g)); },
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
    try{ gh.inst=g.def.create(api)||{}; }catch(e){ this.notify('warn',g.name+' did not start.'); this.setState({gameScreen:'menu'}); return; }
    this._game=gh; const inst=gh.inst;
    this._ghKey=(e)=>{ if(this._game!==gh)return; if(['ArrowLeft','ArrowRight','ArrowUp','ArrowDown',' '].includes(e.key))e.preventDefault(); if(gh.paused||!inst.key)return; try{inst.key(e.key,e.type==='keydown');}catch(x){} };
    this._ghPtr=(e)=>{ if(this._game!==gh||gh.paused||!inst.pointer)return; const r=cv.getBoundingClientRect(); try{inst.pointer((e.clientX-r.left)*W/r.width,(e.clientY-r.top)*H/r.height,e.type.replace('pointer',''));}catch(x){} };
    window.addEventListener('keydown',this._ghKey); window.addEventListener('keyup',this._ghKey);
    ['pointermove','pointerdown','pointerup'].forEach(ty=>cv.addEventListener(ty,this._ghPtr)); gh.cv=cv;
    const loop=(now)=>{ if(this._game!==gh||this.state.overlay!=='games'||this.state.gameScreen!=='play')return;
      const dt=Math.min(0.05,Math.max(0,(now-gh.last)/1000)); gh.last=now;
      try{ if(!gh.paused&&inst.update)inst.update(dt); if(inst.draw)inst.draw(ctx); }catch(x){ this.notify('warn',g.name+' stopped unexpectedly.'); this.ghOver(g,score); return; }
      if(gh.paused){ const p=api.palette; ctx.save(); ctx.globalAlpha=0.72; ctx.fillStyle=p.void||'#000'; ctx.fillRect(0,0,W,H); ctx.globalAlpha=1; ctx.fillStyle=p.bone; ctx.font='14px "JetBrains Mono", monospace'; ctx.textAlign='center'; ctx.fillText('paused · p to resume · esc to exit',W/2,H/2); ctx.restore(); }
      this._ghRaf=requestAnimationFrame(loop); };
    this._ghRaf=requestAnimationFrame(loop); },
  ghStop(){ const gh=this._game; if(!gh)return; this._game=null; cancelAnimationFrame(this._ghRaf);
    window.removeEventListener('keydown',this._ghKey); window.removeEventListener('keyup',this._ghKey);
    if(gh.cv)['pointermove','pointerdown','pointerup'].forEach(ty=>gh.cv.removeEventListener(ty,this._ghPtr));
    try{ gh.inst&&gh.inst.destroy&&gh.inst.destroy(); }catch(e){} },
  ghOver(g,score){ const prev=this.gameBest(g.id); try{ if(score>prev)localStorage.setItem(this.gameStoreKey(g.id,'best'),String(score)); }catch(e){}
    this.ghStop(); this.setState({gameScreen:'over',gameLast:{id:g.id,score,best:Math.max(prev,score),isBest:score>0&&score>prev}}); },
  rvGames(c){
    const {s} = c;
    const gmList=this.gamesList(), gmId=s.gameId||'credpong', gmCur=gmList.find(g=>g.id===gmId)||null;
    return {
      openGames:()=>this.gameOpenLibrary(),
      ovGames:s.overlay==='games',
      cpIsMenu:s.gameScreen==='menu'&&gmId==='credpong',
      cpIsPlay:s.gameScreen==='play',
      cpIsOver:s.gameScreen==='over',
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
      cpModeBottomBg:(s.cpMode||'bottom')==='bottom'?'var(--bone)':'transparent',
      cpModeBottomFg:(s.cpMode||'bottom')==='bottom'?'var(--night)':'var(--bone)',
      cpModeSideBg:s.cpMode==='side'?'var(--bone)':'transparent',
      cpModeSideFg:s.cpMode==='side'?'var(--night)':'var(--bone)',
      cpModeRoamBg:s.cpMode==='roam'?'var(--bone)':'transparent',
      cpModeRoamFg:s.cpMode==='roam'?'var(--night)':'var(--bone)',
      cpSetModeBottom:()=>this.setState({cpMode:'bottom'}),
      cpSetModeSide:()=>this.setState({cpMode:'side'}),
      cpSetModeRoam:()=>this.setState({cpMode:'roam'}),
      cpModeDesc:this.cpModeDescFor(s.cpMode||'bottom'),
      cpBestLabel:String(this.cpBest()||'—'),
      cpRef:this.cpRef,
      cpHasProgress:this.cpSavedLevel()>1,
      cpResumeLabel:String(this.cpSavedLevel()),
      cpStart:()=>this.cpStart(),
      cpClose:()=>this.setState({overlay:null}),
      cpExit:()=>this.cpExit(),
      cpBackToMenu:()=>this.cpBackToMenu(),
      cpBackdropClick:()=>{ if(s.gameScreen==='play')this.cpExit(); else this.setState({overlay:null}); },
      cpControlHint:(s.cpMode==='side')?'↑ ↓ move':(s.cpMode==='roam')?'mouse follows the edge':'← → move',
      cpScoreLabel:'score '+(this.cp?this.cp.score:0),
      cpBestNote:(this.cp&&this.cp.score>0&&this.cp.score>=this.cpBest())?'new local best':('local best: '+this.cpBest()),
    };
  },
};
