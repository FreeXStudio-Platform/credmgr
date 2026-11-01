/* Add entry (single, note, bulk), the held-entry tray and its banner, add node, seal and restore.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Write lane (WP-C).

   Every change goes: one bridge call through src/vault/actions/write.ts, then model.refresh of what it touched, then a notice.
   Nothing is written to the view (it is the broker's last word, replaced wholesale); a rejection goes to this.routeError and
   is never swallowed.  What the user typed (a value, a bulk paste) lives in this component's state only while its dialog is
   open: it is cleared on save, on any way of closing the dialog, and on lock (see scheduleEntryFormWipe).  No value is ever
   put in a notice, a log or storage. */

import { errorCode, isSessionEnded, write } from "../../vault/index";
import { fieldName } from "./inspector.js";
import { FIELD_TYPES } from "./fields.js";

/** True only in a development or test build, which may run on the in-memory example vault with no broker (see settings.js DEMO_BUILD). Folds to `false` in a release build. */
const DEMO_BUILD = import.meta.env.DEV || import.meta.env.MODE === 'test';
const NEEDS_APP = 'Writing needs the CredMgr app: this page has no broker to write to. Nothing was changed.';
const RESERVED_IDS = ['global', 'orphan', 'orphaned'];
const DEFAULT_ADV = { subShare: true, twofa: true, childRead: false, agentAccess: 'read-write', pn: false };
const BATCH_MAX = 500;
const PREVIEW_ROWS = 100;
const pad = (n) => String(n).padStart(2, '0');
/** Unix seconds as a local `YYYY-MM-DD HH:MM`. */
const stamp = (secs) => {
  if (typeof secs !== 'number' || !isFinite(secs) || secs <= 0) return '—';
  const d = new Date(secs * 1000);
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
};
/** A node id from the name the user typed: lower case letters, digits and single dashes only (the id becomes a folder name). */
export const slugify = (name) =>
  String(name).normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+/, '').slice(0, 48).replace(/-+$/, '');
const hasControl = (t) => /[\u0000-\u001f\u007f]/.test(t);
const omitErrors = (fe, prefix) => { const out = {}; for (const k in (fe || {})) if (!k.startsWith(prefix)) out[k] = fe[k]; return out; };
const TIER_ORDER = ['low', 'medium', 'high', 'critical'];
/** The broker's entry types, for the one pin a user may put on an entry ("auto" leaves it to inference). */
const ENTRY_TYPES = ['server', 'database', 'api', 'wallet', 'login', 'ssh', 'certificate', 'token', 'totp', 'env-bundle', 'note', 'other'];
const MASK = '••••••••••••';

export const writeMethods = {
  // ───────────────────────────── how a field is drawn ─────────────────────────────
  // The page keeps NO parser and NO type inference of its own: a paste is parsed and typed by the same Rust code the broker's world uses
  // (`fields_preview`, locally, in the shell), and what the preview shows is what is stored.  Only the colours of a tier live here.
  fieldSensTier(t){ if(t==='private-key'||t==='seed-phrase')return'critical'; if(t==='certificate'||t==='totp-seed'||t==='api-key'||t==='password')return'high'; if(t==='url'||t==='port'||t==='host'||t==='username')return'medium'; return'low'; },
  fieldSensClass(t){return'sens-'+this.fieldSensTier(t);},
  fieldSensBorder(t){const tier=this.fieldSensTier(t);return tier==='critical'?'3px solid var(--danger)':tier==='high'?'3px solid var(--bone)':tier==='medium'?'2px solid var(--mute)':'1px solid var(--faint)';},
  sensBorderFor(sv){return sv==='critical'?'3px solid var(--danger)':sv==='high'?'3px solid var(--bone)':sv==='medium'?'2px solid var(--mute)':'1px solid var(--faint)';},

  // ───────────────────────────── add entry / note ─────────────────────────────
  /**
   * One opener, so no stale note state, stale node or stale secret leaks into the next entry.  A note is an entry of type `note`
   * whose one field is free text: "+ New note" opens the form with that field labelled `note` and the entry type pinned to `note`.
   */
  openAddDlg(nid,note){
    this.setState(st=>({dialog:'addEntry',addNode:nid,addName:'',addMode:'single',bulkText:'',splitSegs:false,typeOverrides:{},singleFields:[{label:note?'note':'',value:''}],entryTypeOverride:note?'note':null,preview:null,previewBusy:false,addBusy:false,fieldErrors:omitErrors(st.fieldErrors,'entry.'),searchOpen:false,ctx:null}));
  },
  /**
   * Change the form, then preview what it holds again.  Save stays off until the preview that matches the form has arrived, so a
   * save can never send an earlier keystroke's preview.
   */
  editEntryForm(patch){
    this.setState(st=>({...(typeof patch==='function'?patch(st):patch),previewBusy:true,fieldErrors:omitErrors(st.fieldErrors,'entry.')}),()=>this.schedulePreview());
  },
  schedulePreview(){
    clearTimeout(this._pvT);
    const seq=(this._pvSeq=(this._pvSeq||0)+1);
    this._pvPending=true;
    this._pvT=setTimeout(()=>this.runPreview(seq),120);
  },
  /**
   * The preview of the form, from the shell's own parser and inference (src/vault/actions/write.ts previewPaste / previewRows): no broker
   * call, no login, no audit record.  A pin the user put on a field's type is carried in the rows sent to it; for a paste, a segment with a pin is
   * previewed again from its own fields, so the type, masking, entry type and sensitivity shown are always the shell's answer.  An answer that
   * was overtaken by a later keystroke, or that arrives after the dialog closed, is dropped: it would put what was typed back into the state.
   */
  async runPreview(seq){
    this._pvPending=false;
    if(!this._mounted||this.state.dialog!=='addEntry')return;
    const s=this.state, pins=s.typeOverrides||{};
    const pin=(si,fi)=>pins[si+'.'+fi];
    try{
      let segs=[], hint=false;
      if(s.addMode==='single'){
        const rows=[];
        for(const f of (s.singleFields||[]))if(f.value!=='')rows.push({label:f.label,value:f.value});
        rows.forEach((r,fi)=>{ const t=pin(0,fi); if(t)r.type=t; });
        if(rows.length)segs=(await write.previewRows(this.model,rows)).segments;
      } else if((s.bulkText||'').trim()!==''){
        const p=await write.previewPaste(this.model,s.bulkText,!!s.splitSegs);
        segs=p.segments; hint=p.singleBlobHint;
        for(let si=0;si<segs.length;si++){
          if(!segs[si].fields.some((_,fi)=>pin(si,fi)))continue;
          const rows=write.previewFieldInputs(segs[si]).map((r,fi)=>pin(si,fi)?{...r,type:pin(si,fi)}:r);
          segs[si]=(await write.previewRows(this.model,rows)).segments[0];
        }
      }
      if(seq!==this._pvSeq||this.state.dialog!=='addEntry')return;
      this.setState({preview:{segs,hint,failed:null},previewBusy:false});
    }catch(e){
      if(seq!==this._pvSeq||this.state.dialog!=='addEntry')return;
      this.setState({preview:{segs:[],hint:false,failed:errorCode(e)||'unavailable'},previewBusy:false});
    }
  },
  /** The user pinned (or un-pinned, with "auto") the type of one previewed field.  Pins last until the content next changes. */
  pinFieldType(si,fi,type){
    this.editEntryForm(st=>{ const o={...(st.typeOverrides||{})}; const k=si+'.'+fi; if(type==='auto')delete o[k]; else o[k]=type; return {typeOverrides:o}; });
  },
  /** What Save would send, with the checks the screen needs.  Pure: reads state and the view, writes nothing. */
  entryPlan(){
    const s=this.state, v=this.vault, nid=s.addNode, bulk=s.addMode==='bulk', split=bulk&&!!s.splitSegs;
    const taken=new Set([...(v.entries[nid]||[]).map(e=>e.name.toLowerCase()),...(v.pending||[]).filter(p=>p.node===nid).map(p=>p.name.toLowerCase())]);
    const segs=(s.preview&&s.preview.segs)||[];
    const used=new Set();
    const items=segs.map(seg=>{
      let name;
      if(!split)name=(s.addName||'').trim();
      else{ // each /// segment is ONE entry, named by its first label (else "untitled n"); a repeated name inside the paste gets " 2", " 3"
        const base=Array.from((seg.suggestedName||'untitled').trim()).slice(0,190).join(''); name=base; let k=2; // the broker refuses a name over 200 characters (ADR-093); 190 leaves room for the " 2" suffix
        while(used.has(name.toLowerCase()))name=base+' '+(k++);
        used.add(name.toLowerCase());
      }
      return {name,seg,fields:write.previewFieldInputs(seg),clash:!!name&&taken.has(name.toLowerCase())};
    });
    const tooMany=items.length>BATCH_MAX;
    let disabled=!!s.addBusy||!!s.previewBusy||!items.length||tooMany||items.some(i=>i.clash)||(!split&&!items[0].name);
    // A page with no shell (a development or test build on its demo data) cannot preview, and cannot write: Save then stays available once
    // something is typed, so that pressing it can say why nothing is saved (see saveNewEntry).
    if(DEMO_BUILD&&this.model.kind!=='bridge'&&!items.length)disabled=!!s.addBusy||!((s.addName||'').trim()||split)||!((s.bulkText||'').trim()||(s.singleFields||[]).some(f=>f.value));
    return {items,tooMany,bulk,split,disabled,nodeLocked:!!(this.node(nid)&&this.node(nid).gate.locked)};
  },
  async saveNewEntry(again){
    if(this._savingEntry)return;
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info',NEEDS_APP); return; }
    const plan=this.entryPlan(); if(plan.disabled)return;
    const s=this.state, nid=s.addNode, bulk=plan.bulk;
    const keepNote=again&&s.entryTypeOverride==='note';
    const pin=s.entryTypeOverride||undefined; // a pin only if the user chose one: the inferred type is never sent back
    const total=plan.items.length;
    this._savingEntry=true;
    this.setState(st=>({addBusy:true,fieldErrors:omitErrors(st.fieldErrors,'entry.')}));
    try{
      let created=0, held=0, partial=null, readback=null, warned='';
      const inputs=plan.items.map(it=>({name:it.name,fields:it.fields,entryType:pin}));
      if(total===1){
        const r=await write.createEntry(this.model,nid,inputs[0]);
        if(r.pending)held=1; else created=1;
        readback=r.readbackError||null;
        warned=write.nameWarningText(r);
      } else {
        const r=await write.createEntries(this.model,nid,inputs);
        created=r.created.filter(c=>!c.pending).length; held=r.created.filter(c=>c.pending).length;
        if(!r.complete&&r.failed)partial={name:r.failed.name};
        readback=r.readbackError||null;
        warned=write.nameWarningText(r,true);
      }
      const done=again&&!partial;
      this._pvSeq=(this._pvSeq||0)+1; clearTimeout(this._pvT);
      this.setState({addName:'',singleFields:[{label:keepNote?'note':'',value:''}],bulkText:'',entryTypeOverride:keepNote?'note':null,typeOverrides:{},preview:null,previewBusy:false,dialog:done?'addEntry':null,addBusy:false});
      if(nid!==this.state.selected)this.select(nid); else { this.buildEntryNodes(nid); this.renderGraph(); }
      if(done)setTimeout(()=>{ const el=document.querySelector('.cm-modal-panel input[aria-label="entry name"]'); if(el)el.focus(); },30); // "add another": back to the name field
      const many=(n)=>n+(n===1?' entry':' entries');
      let note;
      if(partial)note={kind:'warn',text:`Saved ${many(created+held)} of ${total} in ${nid}; stopped at “${partial.name}”. The rest were not written.`};
      else if(held&&!created)note={kind:'info',flash:true,text:held===1?`Held for review: ${nid} is locked, so the entry waits in the tray. Unlock the node, then accept it.`:`Held for review: ${nid} is locked, so ${many(held)} wait in the tray. Unlock the node, then accept them.`};
      else if(held)note={kind:'success',flash:true,text:`Saved ${many(created)} to ${nid}; ${many(held)} held for review.`};
      else note={kind:'success',text:`Saved ${many(created)} to ${nid}.`};
      // A name the broker accepted but wants noticed (ADR-084): said in the same notice, never blocking.
      if(warned)note={...note,kind:note.kind==='error'?'error':'warn',text:note.text+' '+warned};
      if(note.flash)this.pendingFlash(note.text);
      // The broker wrote it; only the re-read failed. The form is already gone (a retry would meet entry_exists), and the notice says so.
      if(readback)this.savedButNotRefreshed(readback,note.text);
      else this.notify(note.kind,note.text);
    }catch(e){
      // A refused call changed nothing (a batch checks every name before it writes). entry_exists on a single entry belongs next to the name.
      const field=errorCode(e)==='entry_exists'&&!bulk?'entry.name':'entry.save';
      this.routeError(e,{op:total===1?'entry.create':'entry.create_batch',node:nid,field,inlineRendered:true});
    }finally{
      this._savingEntry=false;
      this.setState({addBusy:false});
    }
  },
  entryFormDirty(){ const s=this.state; return !!(s.addName||s.bulkText||s.preview||(s.singleFields||[]).some(f=>f.value||f.label&&f.label!=='note')); },
  wipeEntryForm(){
    this._pvSeq=(this._pvSeq||0)+1; this._pvPending=false; clearTimeout(this._pvT); // an answer still on its way must not put what was typed back
    this.setState(st=>({addName:'',singleFields:[{label:'',value:''}],bulkText:'',splitSegs:false,entryTypeOverride:null,typeOverrides:{},preview:null,previewBusy:false,addBusy:false,fieldErrors:omitErrors(st.fieldErrors,'entry.')}));
  },
  /** What was typed is a secret. It must not outlive its dialog: any close (Cancel, Escape, the scrim, a lock) leaves the form empty. */
  scheduleEntryFormWipe(){
    if(this._wipeQueued||this.state.dialog==='addEntry'||!this.entryFormDirty())return;
    this._wipeQueued=true;
    queueMicrotask(()=>{ this._wipeQueued=false; if(this._mounted&&this.state.dialog!=='addEntry'&&this.entryFormDirty())this.wipeEntryForm(); });
  },

  nodeFormDirty(){ const s=this.state, a=s.addNodeAdv||DEFAULT_ADV; return !!(s.newNodeName||(s.newNodeFolders||['']).some(f=>f)||s.addNodeBusy||a.subShare!==DEFAULT_ADV.subShare||a.twofa!==DEFAULT_ADV.twofa||a.childRead!==DEFAULT_ADV.childRead||a.agentAccess!==DEFAULT_ADV.agentAccess||!!a.pn!==DEFAULT_ADV.pn); },
  /** The advanced choices are security settings: a "2FA on reveal: off" left from one node must never ride into the next. Closing the dialog any way resets the form. */
  scheduleNodeFormReset(){
    if(this._nodeResetQueued||this.state.dialog==='addNode'||!this.nodeFormDirty())return;
    this._nodeResetQueued=true;
    queueMicrotask(()=>{ this._nodeResetQueued=false; if(this._mounted&&this.state.dialog!=='addNode'&&this.nodeFormDirty())this.setState(st=>({newNodeName:'',newNodeFolders:[''],addNodeAdv:{...DEFAULT_ADV},addNodeBusy:false,fieldErrors:omitErrors(st.fieldErrors,'node.')})); });
  },

  /**
   * The broker DID what was asked and only the re-read afterwards failed (`readbackError` on a write action's answer).  This is
   * never "nothing was changed": the notice says what was saved and that the screen is out of date, and the read's own error still
   * goes where the router sends it (the Lock screen for a lost login, the broker-down screen for an unreachable broker).
   */
  savedButNotRefreshed(error,saved){ return this.routeError(error,{op:'refresh',changed:saved}); },

  // ───────────────────────────── held entries: the tray and its banner ─────────────────────────────
  pendingFlash(msg){ clearTimeout(this._pnT); this._pnT=setTimeout(()=>this.setState({pendingNote:''}),3500); this.setState({pendingNote:msg}); },
  /** Open the tray and re-read it: entries can be held by another process (an agent, the CLI) while this window is open. */
  openPending(){ this.setState({dialog:'pending',vaultMenu:false}); return this.refreshTray(); },
  async refreshTray(){
    if(DEMO_BUILD&&this.model.kind!=='bridge')return;
    try{ await write.listPending(this.model); }
    catch(e){ this.routeError(e,{op:'vault.pending_list'}); }
  },
  async actPending(kind,node,entry,name){
    const key=node+'/'+entry;
    if((this.state.pendingBusy||{})[key])return;
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info',NEEDS_APP); return; }
    this.setState(st=>({pendingBusy:{...(st.pendingBusy||{}),[key]:true}}));
    try{
      const r=kind==='accept'?await write.acceptPending(this.model,node,entry):await write.discardPending(this.model,node,entry);
      const msg=kind==='accept'?`“${name}” accepted into ${node}`:`“${name}” discarded`;
      this.pendingFlash(msg);
      if(r.readbackError)this.savedButNotRefreshed(r.readbackError,msg+'.'); // it happened; the tray on screen is out of date
      else this.notify('success',msg+'.');
    }catch(e){
      this.routeError(e,{op:kind==='accept'?'vault.pending_accept':'vault.pending_discard',node,entry});
      if(errorCode(e)==='not_found')this.refreshTray(); // it was already accepted or discarded elsewhere: show the tray as it is now
    }finally{
      this.setState(st=>{ const b={...(st.pendingBusy||{})}; delete b[key]; return {pendingBusy:b}; });
    }
  },
  acceptPending(node,entry,name){ return this.actPending('accept',node,entry,name); },
  discardPending(node,entry,name){ return this.actPending('discard',node,entry,name); },

  // ───────────────────────────── add node ─────────────────────────────
  /** The new node's id, label and folders as the dialog stands, with the reason it cannot be created yet (if any). */
  addNodeInfo(){
    const s=this.state, v=this.vault;
    const label=(s.newNodeName||'').trim();
    const adv=this.eff().mode==='pro'?(s.addNodeAdv||DEFAULT_ADV):DEFAULT_ADV;
    // "Hide this node's name" (privateNames): the id must not be made from the name, because every reader who may list the node sees the id.
    // It is chosen once, at creation (an id never changes), so here there is none yet and the name's slug is not checked.
    const priv=!!adv.pn;
    const id=priv?'':slugify(label);
    let problem='';
    if(label){
      if(priv){ if(label.length>120||hasControl(label))problem='the name must be 1 to 120 characters, with no control characters'; }
      else if(!id)problem='the name needs at least one letter or digit';
      else if(RESERVED_IDS.includes(id))problem='“'+id+'” is reserved';
      else if(v.nodes.some(n=>n.id===id))problem='a node called "'+id+'" already exists';
      else if(label.length>120||hasControl(label))problem='the name must be 1 to 120 characters, with no control characters';
    }
    const folders=(s.newNodeFolders||[]).map(f=>f.trim()).filter(Boolean);
    const badFolder=folders.find(f=>!(f==='~'||f.startsWith('~/')||f.startsWith('/')));
    return {id,priv,label,folders,problem,badFolder,disabled:!!s.addNodeBusy||!label||!!problem||!!badFolder};
  },
  async confirmAddNode(){
    if(this._creatingNode)return;
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info',NEEDS_APP); return; }
    const info=this.addNodeInfo(); if(info.disabled)return;
    const s=this.state, adv=this.eff().mode==='pro'?(s.addNodeAdv||DEFAULT_ADV):DEFAULT_ADV;
    this._creatingNode=true;
    this.setState(st=>({addNodeBusy:true,fieldErrors:omitErrors(st.fieldErrors,'node.')}));
    try{
      const choices={siblingShare:!!adv.subShare,twofaOnReveal:!!adv.twofa,childRead:!!adv.childRead,agentAccess:adv.agentAccess,privateNames:!!adv.pn};
      const id=info.priv?write.opaqueNodeId(new Set(this.vault.nodes.map(n=>n.id))):info.id;
      const out=await write.createNodeWithPolicy(this.model,{id,label:info.label,parentId:s.newNodeParent,workdirs:info.folders},choices);
      if(this.state.tfUntil&&(choices.siblingShare||choices.twofaOnReveal||choices.childRead||choices.agentAccess||choices.privateNames)){ clearInterval(this._tfI); this.setState({tfUntil:0}); } // node.policy ends every elevation at the broker
      this.setState({dialog:null,newNodeName:'',newNodeFolders:[''],addNodeBusy:false});
      this.select(id);
      // The node EXISTS from here on, whatever else went wrong.  If the broker refused part of its settings, ONE notice says which
      // part, why, and what state the node is in (a second refusal must not replace the first, and a node left wider than the
      // user chose must be said to be).  A login that ended meanwhile puts that same text on the Lock screen.
      const report=write.policyReport(info.label,id,choices,out);
      const ended=!!report&&(report.sessionEnded||(!!out.readbackError&&isSessionEnded(out.readbackError)));
      const warned=write.nameWarningText(out); // a name that mixes scripts (ADR-084): accepted, and said so in the same notice
      if(ended)this.lockWith(report.text);
      else{
        const created=`Node “${info.label}” created.`+(warned?' '+warned:'');
        if(out.readbackError)this.savedButNotRefreshed(out.readbackError,created); // only the re-read failed: the node was created
        if(report)this.notify(report.kind,report.text+(warned?' '+warned:''));
        else if(!out.readbackError)this.notify(warned?'warn':'success',created);
      }
    }catch(e){
      // Nothing was created. A rejected name, parent or folder is a malformed_request: say what to check, next to the field.
      if(errorCode(e)==='malformed_request')this.setState(st=>({fieldErrors:{...(st.fieldErrors||{}),'node.save':'The broker did not accept this node. Check the name, the parent, and that every work folder is an existing directory.'}}));
      this.routeError(e,{op:'node.create',node:info.priv?undefined:info.id,field:'node.save'});
    }finally{
      this._creatingNode=false;
      this.setState({addNodeBusy:false});
    }
  },

  // ───────────────────────────── seal and restore ─────────────────────────────
  /** The dialog's facts. The broker seals exactly one node: a node that still has sub-nodes is not offered (it would strand them). */
  sealInfo(){
    const s=this.state, v=this.vault;
    const n=s.sealTarget?this.node(s.sealTarget):null;
    const kids=n?this.children(n.id):[];
    const grants=n?v.grants.filter(g=>g.from===n.id||g.to===n.id):[];
    const blocked=!n?'':n.id==='global'?'The global node cannot be sealed.':kids.length?`Seal its sub-nodes first (${kids.map(k=>k.label).join(', ')}): the broker seals one node at a time.`:n.gate.locked?'This node is locked. Unlock it first: sealing needs its key.':'';
    return {n,kids,grants,blocked,disabled:!n||!!blocked||s.sealTyped!==n.label||!!s.sealBusy};
  },
  async doSeal(){
    if(this._sealing)return;
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info',NEEDS_APP); return; }
    const info=this.sealInfo(); if(info.disabled)return;
    const id=info.n.id, label=info.n.label;
    this._sealing=true; this.setState({sealBusy:true});
    try{
      const r=await write.sealNode(this.model,id);
      this.setState({dialog:null,sealTyped:'',sealTarget:null,sealBusy:false});
      this.select('__orphan');
      const text=`Node “${label}” sealed. Restore it from Settings → Nodes within 7 days.`;
      if(r.readbackError)this.savedButNotRefreshed(r.readbackError,text); // sealed for real; the graph on screen has not caught up
      else this.notify('success',text);
    }catch(e){
      this.routeError(e,{op:'node.seal',node:id});
    }finally{
      this._sealing=false;
      this.setState({sealBusy:false});
    }
  },
  async restoreSealed(id){
    const r=this.vault.sealed.find((x)=>x.id===id); if(!r||this._restoring)return; // by id: the list may have changed between the render and the click
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info',NEEDS_APP); return; }
    this._restoring=true;
    try{
      const done=await write.restoreNode(this.model,r.id);
      const text=`Node “${r.label}” restored.`;
      if(done.readbackError)this.savedButNotRefreshed(done.readbackError,text); // restored for real; the node is not in the stale graph, so it is not selected
      else { this.select(r.id); this.notify('success',text); }
    }catch(e){
      this.routeError(e,{op:'node.restore',node:(errorCode(e)==='archive_expired'||errorCode(e)==='not_found')?undefined:r.id}); // an expired archive has no node left to re-read
    }finally{
      this._restoring=false;
    }
  },

  // ───────────────────────────── what the templates read ─────────────────────────────
  rvWrite(c){
    const {isPro, nodeOpts, pend, pendN, s, v} = c;
    this.scheduleEntryFormWipe();
    this.scheduleNodeFormReset();
    // The preview is derived from the form: a form that holds something and has no preview yet (the dialog was put in a state from outside,
    // or the first answer is still on its way) gets one.  Once asked it is not asked again until the form changes.
    if(s.dialog==='addEntry'&&!s.preview&&!this._pvPending&&((s.bulkText||'').trim()!==''||(s.singleFields||[]).some(f=>f.value!=='')))this.schedulePreview();
    const fe=s.fieldErrors||{};

    // add entry
    const plan=this.entryPlan();
    const bulk=plan.bulk, split=plan.split;
    const pv=s.preview||{segs:[],hint:false,failed:null};
    const typeOptsFor=(f)=>[{id:'auto',label:'auto: '+f.inferredType},...FIELD_TYPES.map(t=>({id:t,label:t}))];
    let rowBudget=PREVIEW_ROWS, fieldTotal=0, maskedTotal=0, shownFields=0;
    const previewSegs=plan.items.map((it,si)=>{
      const rows=[];
      it.seg.fields.forEach((f,fi)=>{
        fieldTotal++; if(f.masked)maskedTotal++;
        if(rowBudget<=0)return;
        rowBudget--; shownFields++;
        const lines=f.value.split('\n'), nm=fieldName(f,fi);
        rows.push({name:nm,labelNote:f.label?('label: '+f.label):'',display:f.masked?MASK:(lines[0].slice(0,48)+(lines.length>1?' … '+lines.length+' lines':'')),
          vcolor:f.masked?'var(--mute)':'var(--bone)',vspace:f.masked?'.12em':'0',sensBorder:this.fieldSensBorder(f.type),
          typeAria:'type of '+nm,typeVal:f.typeOverridden?f.type:'auto',typeOpts:typeOptsFor(f),onType:(ev)=>this.pinFieldType(si,fi,ev.target.value)});
      });
      return {showHead:split,name:it.name||'(name)',clash:it.clash,entryType:s.entryTypeOverride||it.seg.entryType,rows};
    });
    const topTier=plan.items.reduce((a,it)=>TIER_ORDER.indexOf(it.seg.sensitivity)>TIER_ORDER.indexOf(a)?it.seg.sensitivity:a,'low');
    const clashNames=plan.items.filter(i=>i.clash).map(i=>i.name);
    const single=plan.items[0];
    const nameDup=!split&&!!single&&single.clash;
    const nameErr=fe['entry.name']||(nameDup?'an entry called “'+single.name+'” already exists in '+s.addNode:'');
    const splitErr=split&&clashNames.length?(clashNames.length===1?'“'+clashNames[0]+'” already exists in '+s.addNode+': rename or remove that segment.':clashNames.length+' names already exist in '+s.addNode+' (marked below): rename or remove those segments.'):(plan.tooMany?'A paste holds at most '+BATCH_MAX+' entries.':'');
    const saveErr=fe['entry.save']?(fe['entry.save']+(plan.items.length>1?' Nothing was written.':'')):splitErr;
    const lockedNode=plan.nodeLocked;
    const autoType=plan.items.length?plan.items[0].seg.entryType:'other';
    const previewEmptyText=pv.failed?(pv.failed==='invalid_fields'?'That text could not be previewed: a label is at most 200 characters.':'The preview is not available here. Nothing can be saved.'):'nothing to save yet';

    // held entries
    const pendingRows=pend.map(p=>{
      const pn=this.node(p.node), locked=!!(pn&&pn.gate.locked), busy=!!(s.pendingBusy||{})[p.node+'/'+p.id];
      return {node:p.node,name:p.name,type:p.type,sens:p.sensitivity,sensBorder:this.sensBorderFor(p.sensitivity),
        fieldCount:p.fieldCount+(p.fieldCount===1?' field':' fields'),when:stamp(p.created),nodeLocked:locked,disabled:locked||busy,
        accept:()=>this.acceptPending(p.node,p.id,p.name),discard:()=>this.discardPending(p.node,p.id,p.name)};
    });

    // seal
    const si=this.sealInfo(), sealN=si.n;
    const sealLines=sealN?[
      {text:`${sealN.counts.entries} entries (${sealN.counts.totp} 2FA) move to ORPHANED`},
      {text:'their names stay visible; their values become unreadable to every agent and every automated path'},
      {text:'while sealed they can only be opened with presence (Touch ID), which this beta cannot attest yet; restoring the node is the way back'},
      ...(si.grants.length?[{text:`${si.grants.length} grant${si.grants.length===1?'':'s'} touching this node ${si.grants.length===1?'is':'are'} revoked`}]:[]),
      {text:'you can restore the node for 7 days (Settings → Nodes, until you lock the vault); after that its key is destroyed'}
    ]:[];

    // add node
    const ni=this.addNodeInfo();
    const adv=s.addNodeAdv||DEFAULT_ADV;
    const folderErr=ni.badFolder?'Work folders must be absolute paths (or start with ~).':'';

    return {
      // add entry
      dlgAddEntry:s.dialog==='addEntry',
      addTitle:s.entryTypeOverride==='note'?'New note':'New entry',
      addNodeLockedNote:lockedNode,
      addNodeLockedText:`${s.addNode} is locked: the entry will be held in the review tray until you unlock the node and accept it. Nothing is written to the node yet.`,
      addNode:s.addNode,
      onAddNode:(ev)=>this.setState({addNode:ev.target.value}),
      addNodeOpts:nodeOpts,
      addName:s.addName,
      onAddName:(ev)=>this.setState(st=>({addName:ev.target.value,fieldErrors:omitErrors(st.fieldErrors,'entry.')})),
      addNameOff:split,
      addNameErrShow:!!nameErr,
      addNameErr:nameErr,
      addNameBulkNote:split,
      addSingle:s.addMode==='single',
      addBulk:bulk,
      setSingle:()=>this.editEntryForm({addMode:'single',typeOverrides:{}}),
      setBulk:()=>this.editEntryForm({addMode:'bulk',typeOverrides:{}}),
      singleFields:(s.singleFields||[{label:'',value:''}]).map((f,i,all)=>({label:f.label,value:f.value,rows:Math.max(1,Math.min(6,f.value.split('\n').length)),
        labelAria:i===0?'label (optional)':'label of field '+(i+1), valueAria:i===0?'value':'value of field '+(i+1), removeAria:'remove field '+(i+1), canRemove:all.length>1,
        onLabel:(ev)=>this.editEntryForm(st=>{const a=[...st.singleFields];a[i]={...a[i],label:ev.target.value};return{singleFields:a,typeOverrides:{}};}),
        onValue:(ev)=>this.editEntryForm(st=>{const a=[...st.singleFields];a[i]={...a[i],value:ev.target.value};return{singleFields:a,typeOverrides:{}};}),
        remove:()=>this.editEntryForm(st=>({singleFields:st.singleFields.filter((_,j)=>j!==i),typeOverrides:{}}))})),
      addFormField:()=>this.setState(st=>({singleFields:[...(st.singleFields||[]),{label:'',value:''}],typeOverrides:{}})),
      bulkText:s.bulkText,
      onBulk:(ev)=>this.editEntryForm({bulkText:ev.target.value,typeOverrides:{}}),
      splitSegs:!!s.splitSegs,
      onSplit:(ev)=>this.editEntryForm({splitSegs:!!ev.target.checked,typeOverrides:{}}),
      blobHintShow:bulk&&!split&&!!pv.hint,
      splitByLine:()=>this.editEntryForm(st=>({bulkText:(st.bulkText||'').split(/\r\n|\r|\n/).filter(l=>l.trim()!=='').join('\n///\n'),typeOverrides:{}})),
      previewSegs,
      previewEmpty:!plan.items.length,
      previewEmptyText,
      previewMoreShow:fieldTotal>shownFields,
      previewMore:'+'+(fieldTotal-shownFields)+' more',
      previewSummary:fieldTotal+(fieldTotal===1?' field':' fields')+' · '+maskedTotal+' masked'+(split?' · '+plan.items.length+(plan.items.length===1?' entry':' entries'):''),
      previewSens:plan.items.length?topTier:'—',
      entryTypeVal:s.entryTypeOverride||'auto',
      entryTypeOpts:[{id:'auto',label:'auto: '+autoType},...ENTRY_TYPES.map(t=>({id:t,label:t}))],
      onEntryType:(ev)=>this.setState({entryTypeOverride:ev.target.value==='auto'?null:ev.target.value}),
      saveLabel:lockedNode?'Hold for review':(plan.items.length>1?'Save '+plan.items.length+' entries':'Save'),
      saveAgainLabel:lockedNode?'Hold and add another':'Save and add another',
      saveDisabled:plan.disabled,
      saveEntry:()=>this.saveNewEntry(false),
      saveEntryAgain:()=>this.saveNewEntry(true),
      addSaveErrShow:!!saveErr,
      addSaveErr:saveErr,

      // the tray and its banner
      dlgPending:s.dialog==='pending',
      pendingRows,
      pendingEmpty:!pendN,
      openPending:()=>this.openPending(),
      refreshPendingTray:()=>this.refreshTray(),
      pendingBannerShow:!!(s.pendingBanner&&pendN&&s.screen==='app'&&s.dialog!=='pending'),
      pendingBannerText:pendN+(pendN===1?' entry is':' entries are')+' waiting for your review',
      dismissPendingBanner:()=>this.setState({pendingBanner:false}),

      // seal
      dlgSeal:s.dialog==='seal',
      sealName:sealN?sealN.label:'',
      sealLines,
      sealNoteShow:!!si.blocked,
      sealNote:si.blocked,
      sealTyped:s.sealTyped,
      onSealTyped:(ev)=>this.setState({sealTyped:ev.target.value}),
      sealDisabled:si.disabled,
      confirmSeal:()=>this.doSeal(),

      // add node
      dlgAddNode:s.dialog==='addNode',
      newNodeName:s.newNodeName,
      onNewNodeName:(ev)=>this.setState(st=>({newNodeName:ev.target.value,fieldErrors:omitErrors(st.fieldErrors,'node.')})),
      newNodeParent:s.newNodeParent,
      onNewNodeParent:(ev)=>this.setState({newNodeParent:ev.target.value}),
      newNodeFolders:(s.newNodeFolders||['']).map((val,i)=>({val,onChange:(ev)=>this.setState(st=>{const a=[...st.newNodeFolders];a[i]=ev.target.value;return{newNodeFolders:a,fieldErrors:omitErrors(st.fieldErrors,'node.')};})})),
      addNodeFolder:()=>this.setState(st=>({newNodeFolders:[...st.newNodeFolders,'']})),
      parentOpts:[{id:'global',label:'global'},...v.nodes.filter(n=>n.depth===1).map(n=>({id:n.id,label:'under: '+n.label}))],
      newNodeDupShow:!!ni.problem,
      newNodeDupMsg:ni.problem,
      newNodeIdShow:ni.priv?(!!ni.label&&!ni.problem):(!!ni.id&&!ni.problem&&ni.id!==ni.label),
      newNodeIdNote:ni.priv?'node id: chosen at random when it is created (the name is not part of it)':'node id: '+ni.id,
      newNodeFolderErrShow:!!folderErr,
      newNodeFolderErr:folderErr,
      addNodeErrShow:!!fe['node.save'],
      addNodeErr:fe['node.save']||'',
      newNodeDisabled:ni.disabled,
      confirmAddNode:()=>this.confirmAddNode(),
      advSubShare:!!adv.subShare,
      onAdvSubShare:()=>this.setState(st=>({addNodeAdv:{...(st.addNodeAdv||DEFAULT_ADV),subShare:!(st.addNodeAdv||DEFAULT_ADV).subShare}})),
      advTwofa:!!adv.twofa,
      onAdvTwofa:()=>this.setState(st=>({addNodeAdv:{...(st.addNodeAdv||DEFAULT_ADV),twofa:!(st.addNodeAdv||DEFAULT_ADV).twofa}})),
      advChildRead:!!adv.childRead,
      onAdvChildRead:()=>this.setState(st=>({addNodeAdv:{...(st.addNodeAdv||DEFAULT_ADV),childRead:!(st.addNodeAdv||DEFAULT_ADV).childRead}})),
      advPn:!!adv.pn,
      onAdvPn:()=>this.setState(st=>({addNodeAdv:{...(st.addNodeAdv||DEFAULT_ADV),pn:!(st.addNodeAdv||DEFAULT_ADV).pn}})),
      advAgentAccess:adv.agentAccess,
      onAdvAgentAccess:(ev)=>this.setState(st=>({addNodeAdv:{...(st.addNodeAdv||DEFAULT_ADV),agentAccess:ev.target.value}})),
    };
  },
};
