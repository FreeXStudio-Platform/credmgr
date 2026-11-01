/* Graph canvas: layout, painting, entry dots, positions.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Read-wiring lane (WP-B) edits graphData()/loadPositions()/persistPositions(); the physics is not touched.
   Split from the upstream monolith (design-upstream/PROVENANCE.md, ADR-075).  Nodes, links and entry dots all come from the model's view
   (the broker's graph snapshot, grant list and entry lists); where a node sits is computed from the tree, never looked up by name. */

import { hid } from "./pstore.js";

const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

/**
 * Where each node starts, from the tree alone: global at the centre, its children evenly round a ring (in id order, so the
 * same vault always opens the same way), each node's own children on an arc beyond it, facing away from the centre.  The
 * orphaned node sits outside the ring, lower left.  A position the user dragged to (saved by hashed id) wins over this, and
 * the physics pushes apart anything that still overlaps, so this only has to be a sensible first picture.
 * @returns {Record<string,[number,number]>} by node id; the orphaned node is under `__orphan`
 */
export function layoutPositions(nodes, spread = 1.7){
  const out={}, ang={};
  const root=nodes.find(n=>n.kind==='global');
  const known=new Set(nodes.map(n=>n.id));
  if(root)out[root.id]=[0,0];
  // top level: a child of global; a node whose parent is not in the snapshot (it should not happen) is placed there too, not dropped
  const tops=nodes.filter(n=>n!==root&&((root&&n.parentId===root.id)||!known.has(n.parentId))).sort(byId);
  const ring=spread*Math.max(150,36*tops.length), arm=spread*80;
  tops.forEach((n,i)=>{ const a=-Math.PI/2+(2*Math.PI*i)/tops.length; ang[n.id]=a; out[n.id]=[Math.cos(a)*ring,Math.sin(a)*ring]; });
  // breadth first, so a node is always placed after its parent
  const queue=[...tops];
  while(queue.length){
    const p=queue.shift();
    const kids=nodes.filter(n=>n.parentId===p.id&&!out[n.id]).sort(byId);
    const width=kids.length>1?Math.min(Math.PI*1.1,0.55*(kids.length-1)):0;
    kids.forEach((k,j)=>{
      const a=ang[p.id]+(kids.length>1?(j-(kids.length-1)/2)*(width/(kids.length-1)):0);
      ang[k.id]=a; out[k.id]=[out[p.id][0]+Math.cos(a)*arm,out[p.id][1]+Math.sin(a)*arm]; queue.push(k);
    });
  }
  const far=Math.max(ring*1.35,spread*230);
  out.__orphan=[Math.cos(Math.PI*0.75)*far,Math.sin(Math.PI*0.75)*far];
  return out;
}

export const graphMethods = {
  palette(){
    if(this.pal)return this.pal;
    const cs=getComputedStyle(document.documentElement);
    const g=(v)=>cs.getPropertyValue(v).trim();
    const p={bone:g('--bone'),ash:g('--ash'),mute:g('--mute'),faint:g('--faint'),warn:g('--warn'),danger:g('--danger'),sig:g('--sig'),sigHi:g('--sig-hi'),hair:g('--hair'),hairS:g('--hair-strong'),void:g('--void')};
    if(!p.bone){ return {bone:'#E9ECF1',ash:'#98A0AE',mute:'#767E8C',faint:'#2A2E38',warn:'#B0812E',danger:'#B3373A',sig:'#3E9C86',hairS:'rgba(233,236,241,0.13)',void:'#000'}; }
    this.pal=p; return p;
  },
  graphData(){
    const lay=layoutPositions(this.vault.nodes);
    this.gpos=this.gpos||{};
    // A refresh (a rename, a lock, a note read) must not throw every node back to its first position: keep where each one is now.
    // The orphaned node is left out of this because it is first drawn before any node has loaded, when its place is not meaningful yet.
    const here={}; if(this.gd)for(const o of this.gd.nodes)if(o.id!=='__orphan')here[o.id]=[o.x,o.y];
    const spot=(id)=>this.gpos[id]||here[id]||lay[id]||[0,0];
    const nodes=this.vault.nodes.map(n=>{const [x,y]=spot(n.id);return {...n,x,y};});
    const [ox,oy]=spot('__orphan');
    nodes.push({id:'__orphan',label:'orphaned',kind:'orphan',depth:1,parentId:null,counts:{entries:this.vault.orphans.length,totp:null},gate:{locked:false,twofa:'none'},x:ox,y:oy});
    const byId={}; nodes.forEach(n=>byId[n.id]=n);
    const links=this.vault.links.map(l=>({kind:l.kind,source:byId[l.source.id||l.source],target:byId[l.target.id||l.target]})).filter(l=>l.source&&l.target);
    return {nodes,links};
  },
  /**
   * The callback ref for the graph's container (rvMain hands it to the template).  The constructor's own ref only RE-attaches a canvas
   * that already exists, and in the Tauri shell the app starts on the boot screen, so at mount there is no container and no canvas:
   * nothing would ever create the first one.  This one creates it the moment the container mounts, and re-attaches it every time after.
   */
  graphHostRef(){
    if(!this._graphHostRef) this._graphHostRef=(el)=>{ this.graphRef.current=el; if(el&&(!this.gcv||!el.contains(this.gcv)))this.initGraph(); };
    return this._graphHostRef;
  },
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
        if(!d.moved){ if(this.state.selected!==d.en.parentId)this.select(d.en.parentId); this.setState({openEntry:d.en.id,inspOpen:true}); } // a dot belongs to ITS node: open it there, not in whichever node happens to be selected
        else this.persistPositions();
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
  },
  zoomToFitG(){
    if(!this.gd||!this.gw)return;
    let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
    for(const n of this.gd.nodes){ const r=this.nodeR(n)+20; x0=Math.min(x0,n.x-r);y0=Math.min(y0,n.y-r);x1=Math.max(x1,n.x+r);y1=Math.max(y1,n.y+r+14); }
    const pad=40; const k=Math.min(2.2,Math.max(0.3,Math.min((this.gw-pad*2)/(x1-x0),(this.gh-pad*2)/(y1-y0))));
    this.gv={k,tx:this.gw/2-k*(x0+x1)/2,ty:this.gh/2-k*(y0+y1)/2};
    this.renderGraph();
  },
  zoomToNode(n){
    const kids=this.gd.nodes.filter(o=>o.parentId===n.id).concat([n]);
    let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
    for(const o of kids){ const r=this.nodeR(o)+40; x0=Math.min(x0,o.x-r);y0=Math.min(y0,o.y-r);x1=Math.max(x1,o.x+r);y1=Math.max(y1,o.y+r); }
    const k=Math.min(6,Math.max(0.3,Math.min(this.gw/(x1-x0),this.gh/(y1-y0))));
    this.gv={k,tx:this.gw/2-k*(x0+x1)/2,ty:this.gh/2-k*(y0+y1)/2};
    this.renderGraph();
  },
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
  },
  nodeR(n){ // VAULT_GRAPH_SPEC §3: radius scales with entry count, global/orphan fixed
    if(n.kind==='global')return 22; if(n.kind==='orphan')return 15;
    const t=Math.sqrt(Math.max(0,Math.min(40,(n.counts&&n.counts.entries)||0))/40);
    return n.kind==='sub'?8+6*t:12+8*t; },
  gdNode(id){ return this.gd&&this.gd.nodes.find(o=>o.id===id); },
  hashStr(s){let h=0;for(let i=0;i<s.length;i++)h=(h*31+s.charCodeAt(i))|0;return Math.abs(h);},
  entryColor(id){let h=((this.hashStr(id)*2654435761)>>>0)%360;const pk=this.state.pack,rg=pk&&pk.dots&&pk.dots[this.cosmEff().dots];if(rg===0)return this.palette().ash;if(rg)h=Math.round(rg[0]+h/360*(rg[1]-rg[0]));return this.eff().theme==='dark'?`oklch(0.74 0.125 ${h})`:`oklch(0.5 0.13 ${h})`;},
  nodeGlyphIdx(id){return this.hashStr('g:'+id)%14;},
  drawGlyph(ctx,cx,cy,h,idx,color){
    ctx.save();ctx.strokeStyle=color;ctx.fillStyle=color;
    const gsty=(this._cosmFx&&this._cosmFx.glyph)||'classic'; ctx.lineWidth=gsty==='fine'?0.8:gsty==='heavy'?2:1.2; if(gsty==='heavy'){ctx.lineCap='round';ctx.lineJoin='round';} // cosmetic extra (free for everyone): stroke weight only
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
  },
  paintNode(n,ctx,scale){
    if(import.meta.env.MODE==='test')window.__cmPaint=(window.__cmPaint||0)+1;
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
      if(this._cosmFx&&this._cosmFx.halo){ ctx.globalAlpha=(dim?0.25:1)*(0.06+0.08*(1-pulse)); ctx.lineWidth=1.5; ctx.beginPath();ctx.arc(n.x,n.y,r+3+2.5+8+(1-pulse)*2.4,0,2*Math.PI);ctx.stroke();ctx.globalAlpha=dim?0.25:1; } } // cosmetic extra (free for everyone): second, slower halo
    if(n.gate&&n.gate.twofa!=='none'&&n.kind!=='global'){
      ctx.strokeStyle=n.gate.twofa==='enrolled'?p.warn:(n.kind==='sub'?p.ash:p.bone);ctx.lineWidth=2;
      ctx.beginPath();ctx.moveTo(n.x,n.y-r-1);ctx.lineTo(n.x,n.y-r+3);ctx.stroke();
    }
    if(n.gate&&n.gate.locked){ // moved off-centre (was drawn at n.y-1, colliding with the new glyph)
      const kc=n.kind==='global'?p.void:(n.kind==='orphan'?p.mute:p.bone);
      ctx.fillStyle=kc;ctx.fillRect(n.x-1.4/scale,n.y+r+2/scale,2.8/scale,2.8/scale);
    }
    { /* labels: always drawn; the 1.4x-zoom threshold (VAULT_GRAPH_SPEC §3) is not applied at scale yet */
      let lb=n.label; if(lb.length>22)lb=lb.slice(0,21)+'…';
      ctx.font=`500 ${10.5/scale}px "JetBrains Mono", ui-monospace, Menlo, monospace`;
      ctx.textAlign='center';ctx.textBaseline='top';
      ctx.fillStyle=n.kind==='orphan'?p.mute:p.ash;
      ctx.fillText(lb,n.x,n.y+r+6/scale);
    }
    ctx.restore();
  },
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
  },
  refreshGraph(){ this.pal=null; this.gd=this.graphData(); this.buildEntryNodes(); this.renderGraph(); },
  clusterKey(en){
    const stop=['api','key','password','pass','pw','login','user','username','token','secret','account','db','database','server','host','port','cert','certificate','totp','2fa','seed','phrase','staging','prod','dev','old','readonly'];
    const words=(en.name||'').toLowerCase().replace(/[^a-z0-9]+/g,' ').trim().split(' ').filter(w=>w&&!stop.includes(w));
    return words.length?words[0]:en.type;
  },
  // Connector lengths vary a little by field type, so a node's ring reads as a cloud rather than a
  // perfect circle. Deterministic (hash of the type), so a given entry always sits at the same reach.
  typeReach(type,id){ const t=String(type||''); const byType=t?[0,5,10][this.hashStr(t)%3]:0;
    return byType+(id?this.hashStr(String(id))%5:0); }, // + a few px keyed off the entry id, so same-type siblings aren't perfectly uniform either
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
  },
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
        const old=prev[r.en.id]; if(old&&old.parentId===nid){ old.baseR=R; old.ck=r.ck; old.slot=slots[idx]; old.totp=!!r.en.totp; out.push(old); return; }
        const pin=this.entryPin(r.en.id);
        const slot=slots[idx], rad=R+20+this.typeReach(r.en.type,r.en.id)+slot.r*(20+Math.min(28,ranked.length));
        out.push({id:r.en.id,parentId:nid,type:r.en.type,totp:!!r.en.totp,ck:r.ck,slot,vx:0,vy:0,pinned:!!pin,baseR:R,
          x:pin?pin[0]:n.x+Math.cos(slot.a)*rad, y:pin?pin[1]:n.y+Math.sin(slot.a)*rad,
          color:this.entryColor(r.en.id)});
      });
    }
    this.entryNodes=out;
    this.simAlpha=1; this.startLoop();
  },
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
  },
  loadPositions(){
    // D10: positions are stored under hid(kind, id), never under the id itself (see pstore.js).  Call again after the
    // model has loaded the node list, because only nodes known now can be matched to a saved position.
    const clean=(raw)=>{ const out={}; for(const k in raw){ const v=raw[k]; if(Array.isArray(v)&&Number.isFinite(v[0])&&Number.isFinite(v[1]))out[k]=v; } return out; }; // drop any corrupted (NaN/null) entry, fall back to default for that node only
    const LV='3'; // layout format: 3 = positions keyed by hashed ids.  Anything older keyed positions by plain ids and is dropped, not migrated.
    try{
      if(localStorage.getItem('credmgr_gposV')!==LV){
        localStorage.removeItem('credmgr_gpos'); localStorage.removeItem('credmgr_gposEntry'); localStorage.setItem('credmgr_gposV',LV); return; }
      this._gposH=clean(JSON.parse(localStorage.getItem('credmgr_gpos')||'{}'));
      this._gposEntryH=clean(JSON.parse(localStorage.getItem('credmgr_gposEntry')||'{}'));
      this.gpos=this.gpos||{};
      for(const id of [...this.vault.nodes.map(n=>n.id),'__orphan']){ const p=this._gposH[hid('n',id)]; if(p)this.gpos[id]=p; }
    }catch(e){}
  },
  // The saved position of an entry dot (resolved lazily: an entry's id is only known once its node's entries are loaded).
  entryPin(id){
    const live=this.gposEntry&&this.gposEntry[id]; if(live)return live;
    const saved=this._gposEntryH&&this._gposEntryH[hid('e',id)];
    if(saved){ this.gposEntry=this.gposEntry||{}; this.gposEntry[id]=saved; }
    return saved;
  },
  persistPositions(){
    const clean=(raw)=>{ const out={}; for(const k in raw){ const v=raw[k]; if(Array.isArray(v)&&Number.isFinite(v[0])&&Number.isFinite(v[1]))out[k]=v; } return out; };
    try{
      // keep what was saved for objects that are not loaded right now, add what moved
      const nodes={...(this._gposH||{})}, ents={...(this._gposEntryH||{})};
      const gp=clean(this.gpos||{}), ge=clean(this.gposEntry||{});
      for(const id in gp)nodes[hid('n',id)]=gp[id];
      for(const id in ge)ents[hid('e',id)]=ge[id];
      this._gposH=nodes; this._gposEntryH=ents;
      localStorage.setItem('credmgr_gpos',JSON.stringify(nodes));
      localStorage.setItem('credmgr_gposEntry',JSON.stringify(ents));
    }catch(e){}
  },
  // A node's "own space" — its body plus the outer edge its entry cloud can reach.
  nodeFootprint(n){
    const cnt=(this.vault.entries[n.id]||[]).length;
    return this.nodeR(n)+(cnt?16+0.6*(14+Math.min(24,cnt)):8); // sized to fit within the hand-placed layout's natural spacing — a floor, not a fight with it
  },
  // Everyone reachable by following outgoing links from id — the transitive "downstream" set that
  // rides along when id is dragged (structural AND grant edges both count: a grant is a real edge).
  gdDescendants(id){
    const seen=new Set(); const stack=[id]; const out=[];
    while(stack.length){ const cur=stack.pop();
      for(const l of this.gd.links){ if(typeof l.source==='object'&&l.source.id===cur&&!seen.has(l.target.id)){ seen.add(l.target.id); out.push(l.target); stack.push(l.target.id); } }
    }
    return out;
  },
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
  },
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
  },
  paintEntryLink(en,ctx){
    const n=this.gdNode(en.parentId); if(!n)return;
    const dim=this.state.selected&&en.parentId!==this.state.selected;
    const dx=en.x-n.x,dy=en.y-n.y,d=Math.hypot(dx,dy)||1,ux=dx/d,uy=dy/d;
    const R=this.nodeR(n);
    ctx.save();ctx.globalAlpha=dim?0.15:0.5;ctx.strokeStyle=en.color;ctx.lineWidth=0.8;
    ctx.beginPath();ctx.moveTo(n.x+ux*R,n.y+uy*R);ctx.lineTo(en.x,en.y);ctx.stroke();ctx.restore();
  },
  paintEntry(en,ctx){
    const hoverThis=this.hoverEntryId===en.id;
    const dim=this.state.selected&&en.parentId!==this.state.selected;
    ctx.save();ctx.globalAlpha=dim?0.4:1;ctx.beginPath();ctx.arc(en.x,en.y,hoverThis?4.2:3,0,2*Math.PI);ctx.fillStyle=en.color;ctx.fill();
    if(en.totp){ ctx.lineWidth=1;ctx.strokeStyle=en.color;ctx.globalAlpha=dim?0.3:0.85;ctx.beginPath();ctx.arc(en.x,en.y,5.4,0,2*Math.PI);ctx.stroke();ctx.globalAlpha=dim?0.4:1; } // a ring marks an entry with a 2FA field (the broker's hasTotp)
    if(hoverThis){ ctx.lineWidth=1.1;ctx.strokeStyle=this.palette().bone;ctx.globalAlpha=0.55;ctx.beginPath();ctx.arc(en.x,en.y,6.2,0,2*Math.PI);ctx.stroke(); }
    ctx.restore();
  },
};
