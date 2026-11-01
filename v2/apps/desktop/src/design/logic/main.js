/* Rail, tree view, hover card and node context menu.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Read-path lane (WP-B).
   Split from the upstream monolith (design-upstream/PROVENANCE.md, ADR-075).  The rows come from the model's view (the
   broker's graph snapshot); Rename (node.update) and Lock now / Unlock node (vault.node_lock / node_unlock) go to the
   broker and the view is re-read afterwards: nothing here edits the view. */

import { lockNode, renameNode, unlockNode, write } from "../../vault/index";

export const mainMethods = {
  /** Finish a rename: send the new label, or just close the editor if there is nothing to send.  The label on screen is whatever the broker last said. */
  async commitRename(id){
    if(this.state.renamingNode!==id)return; // Enter and the blur that follows it both arrive here; the first one wins
    const cur=this.node(id), val=(this.state.renameVal||'').trim();
    this.setState({renamingNode:null});
    if(!cur||!val||val===cur.label)return;
    if([...val].length>120){ this.notify('error','A node name is 1 to 120 characters.'); return; } // characters, as the broker counts them (a UTF-16 length would refuse a name of 61 emoji that it accepts)
    try{
      const r=await renameNode(this.model,id,val);
      const warned=write.nameWarningText(r); // a name that mixes scripts (ADR-084): accepted, and said so
      const done='Renamed.'+(warned?' '+warned:'');
      if(r.readbackError)this.savedButNotRefreshed(r.readbackError,done); // the broker renamed it; only the re-read failed
      else this.notify(warned?'warn':'success',done);
    }
    catch(e){ this.routeReadError(e,{op:'node.update',node:id}); }
  },
  /** Lock or unlock one node (the login survives it).  Locking drops every value revealed from it. */
  async setNodeLock(id,lock){
    this.setState({ctx:null});
    try{
      const r=lock?await lockNode(this.model,id):await unlockNode(this.model,id);
      if(lock)this.setState({reveals:{}});
      const text=lock?'Node locked.':'Node unlocked.';
      if(r.readbackError)this.savedButNotRefreshed(r.readbackError,text); // it happened; the screen has not caught up
      else this.notify('success',text);
    }
    catch(e){ this.routeReadError(e,{op:lock?'vault.node_lock':'vault.node_unlock',node:id}); }
  },
  clampMain(x,y,w,h){ // A2: keep menus and hover cards inside .cm-main whatever the source (canvas, rail, tree)
    const mn=this.graphRef.current&&this.graphRef.current.closest('.cm-main'); const W=mn?mn.clientWidth:window.innerWidth, H=mn?mn.clientHeight:window.innerHeight;
    return {x:Math.max(8,Math.min(x,W-w-8)),y:Math.max(8,Math.min(y,H-h-8))};
  },
  ctxPosFor(clientX,clientY){ // B3-2: position the context menu relative to .cm-main, clamped inside it — not raw viewport coords + magic offsets
    const mainEl=this.graphRef.current&&this.graphRef.current.closest('.cm-main');
    const rc=mainEl?mainEl.getBoundingClientRect():{left:0,top:0,width:window.innerWidth,height:window.innerHeight};
    const menuW=190,menuH=230;
    let x=clientX-rc.left, y=clientY-rc.top;
    x=Math.max(8,Math.min(x,rc.width-menuW)); y=Math.max(8,Math.min(y,rc.height-menuH));
    return {x,y};
  },
  rvMain(c){
    const {btn, s, set, v} = c;
    // rail rows
    const railRows=[];
    const push=(n,depth)=>{ railRows.push({
      id:n.id,label:n.label,kind:n.kind,count:String(n.counts.entries),indent:(depth*14)+'px',
      current:s.selected===n.id?'true':'false',
      color:n.kind==='orphan'?'var(--mute)':'var(--bone)', border:n.kind==='orphan'?'1px dashed var(--faint)':'0',
      badges:(n.gate.locked?'⌐':'')+(n.gate.twofa==='required'?'‖':''), lockColor:s.selected===n.id?'var(--ash)':'var(--mute)',
      renaming:s.renamingNode===n.id, notRenaming:s.renamingNode!==n.id, renameVal:s.renameVal,
      onRenameChange:(ev)=>this.setState({renameVal:ev.target.value}),
      commitRename:()=>this.commitRename(n.id),
      cancelRename:(ev)=>{ if(ev.key==='Escape')this.setState({renamingNode:null}); else if(ev.key==='Enter')this.commitRename(n.id); },
      select:()=>this.select(n.id),
      menu:(ev)=>{ev.preventDefault();const pos=this.ctxPosFor(ev.clientX,ev.clientY);this.setState({ctx:{x:pos.x,y:pos.y,node:n.id}});} // B3-2
    });};
    const globalNode=this.node('global'); if(globalNode)push(globalNode,0); // the view is empty until the model has loaded
    for(const p of v.nodes.filter(n=>n.depth===1)){ push(p,0); for(const c of this.children(p.id)) push(c,1); }
    railRows.push({id:'__orphan',label:'orphaned',kind:'orphan',count:String(v.orphans.length),indent:'0px',current:s.selected==='__orphan'?'true':'false',color:s.selected==='__orphan'?'var(--ash)':'var(--mute)',border:'1px dashed var(--faint)',badges:'',lockColor:'var(--mute)',renaming:false,notRenaming:true,select:()=>this.select('__orphan'),menu:(ev)=>ev.preventDefault()}); // the orphaned node is never renamed: without notRenaming the row drew no label at all
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
    const ctxIsGlobal=!!ctxNode&&ctxNode.kind==='global';
    // New sub-node only under a project (depth 1; the tree stops at depth 2).  Under global the same dialog makes a project.
    // Rename is not offered for global: the broker refuses it (node.update: the global node is singular and unrenamable).
    const ctxItemsAll=s.ctx?(s.ctx.node==='__orphan'?[{label:'Open orphaned',color:'var(--bone)',go:()=>this.select('__orphan')}]:[
      {label:'Open',color:'var(--bone)',go:()=>this.select(s.ctx.node)},
      {label:'New entry',color:'var(--bone)',go:()=>this.openAddDlg(s.ctx.node)},
      ...(ctxNode&&ctxNode.depth<2?[{label:ctxIsGlobal?'New project':'New sub-node',color:'var(--bone)',go:()=>this.setState({dialog:'addNode',newNodeParent:s.ctx.node,ctx:null})}]:[]),
      {label:'Grant access…',color:'var(--bone)',go:()=>this.setState(st=>({dialog:'grant',grant:{...st.grant,from:s.ctx.node},ctx:null}))},
      ...(ctxIsGlobal?[]:[{label:'Rename',color:'var(--bone)',go:()=>this.setState(st=>({ctx:null,renamingNode:s.ctx.node,renameVal:ctxNode?ctxNode.label:''}))}]),
      {label:ctxNode&&ctxNode.gate.locked?'Unlock node':'Lock now',color:'var(--bone)',go:()=>this.setNodeLock(s.ctx.node,!(ctxNode&&ctxNode.gate.locked))},
      {label:'Remove node…',color:'var(--danger-fg)',go:()=>this.setState({dialog:'seal',sealTarget:s.ctx.node,sealTyped:'',ctx:null})}
    ]):[];
    const ctxItems=(s.ctx&&s.ctx.node==='global')?ctxItemsAll.filter(it=>it.label!=='Remove node…'):ctxItemsAll; // C-8: sealing the root node would empty the whole vault — not a valid action
    const [gbB,gbF]=btn(s.view==='graph'),[tbB,tbF]=btn(s.view==='tree');
    return {
      noProjects:v.nodes.length>0&&v.nodes.every(n=>n.kind==='global'), // an empty view is "not loaded yet", not "no projects"
      railRows,
      treeRows,
      setGraphView:set({view:'graph'}),
      setTreeView:set({view:'tree'}),
      graphBtnBg:gbB,
      graphBtnFg:gbF,
      treeBtnBg:tbB,
      treeBtnFg:tbF,
      graphDisplay:s.view==='graph'?'block':'none',
      isTreeView:s.view==='tree',
      graphRef:this.graphHostRef(), // creates the canvas when the container first mounts (the constructor's ref only re-attaches one)
      entriesModeLabel:s.entriesMode==='selected'?'○ entries: selected':'● entries: all',
      toggleEntriesMode:()=>this.setState(st=>({entriesMode:st.entriesMode==='all'?'selected':'all'}),()=>{this.buildEntryNodes();this.renderGraph();}),
      hoverVisible:!!hv,
      hoverX:hv?(typeof hv.x==='number'&&typeof hv.y==='number'?this.clampMain(hv.x,hv.y,hv.mode==='entry'?100:124,hv.mode==='entry'?40:66).x+'px':hv.x):'0px',
      hoverY:hv?(typeof hv.x==='number'&&typeof hv.y==='number'?this.clampMain(hv.x,hv.y,hv.mode==='entry'?100:124,hv.mode==='entry'?40:66).y+'px':hv.y):'0px',
      hoverEntries:hv?String(hv.entries):'',
      hoverTotp:hv?String(hv.totp):'',
      hoverIsEntry,
      hoverIsNode,
      hoverEntryType:hv&&hv.etype?hv.etype:'',
      ctxVisible:!!s.ctx,
      ctxX:s.ctx?this.clampMain(s.ctx.x,s.ctx.y,192,ctxItems.length*30+12).x+'px':'0px',
      ctxY:s.ctx?this.clampMain(s.ctx.x,s.ctx.y,192,ctxItems.length*30+12).y+'px':'0px',
      ctxItems,
      railOpenClass:s.railOpen?'is-open':'',
      closeRail:set({railOpen:false}),
      openAddNodeDlg:()=>this.setState({dialog:'addNode',newNodeParent:'global',newNodeName:''}),
    };
  },
};
