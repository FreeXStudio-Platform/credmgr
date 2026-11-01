/* Inspector, orphaned panel and entry detail.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Read-path lane (WP-B).
   Split from the upstream monolith (design-upstream/PROVENANCE.md, ADR-075); wired to the broker through the model.

   What this file does with the broker, and nothing else:
     notes.read          a node's note, as plain text (never rendered as markup)
     entry.get           an opened entry's fields: id, label, type, masking (never a value).  The detail screen draws from this and
                         from nothing else; a bridge entry's list row carries no labels, so no field is invented for it
     entry.reveal        ONE field's value (fieldIds: [id]), held in the model's private store for the reveal window; and, in one
                         read, the fields that are not masked, so they show without a click (ADR-078: a reveal, audited)
     totp.code           a TOTP-seed field's current code instead of a reveal; totp.seed is asked for and refused (presence)
     entry.reveal (Rust) the Copy button: the shell reveals the ONE field and writes the concealed clipboard; the value never reaches here
   What changes the fields (the menu, the dialogs, add / edit / remove / reorder) is in fields.js.
   A locked NODE is read from the snapshot (gate.locked): its entries keep their names, and the detail shows the per-node
   locked panel instead of reveal and copy.  A locked VAULT never reaches this file: it is the Lock screen. */

import { copyEntry, errorCode, fieldKeyOf, loadEntryDetail, loadNotes, readTotp, readTotpSeed, revealUnmasked } from "../../vault/index";

const MASK = "••••••••••••";
const TOTP_STEP_MS = 30000;
/** Fields that are not masked are shown without a click.  They stay until the entry is closed, the node changes, the window is hidden or the vault locks, so the window is longer than any auto-lock. */
const UNMASKED_WINDOW_MS = 8 * 60 * 60 * 1000;
/** The text of a field with no label: the broker allows an empty one, and the screen numbers it. */
export const fieldName = (f, i) => (f.label && f.label.trim() ? f.label : 'field ' + (i + 1));
/** `123456` is read as `123 456`. */
const groupCode = (c) => (/^\d{6}$/.test(c) ? c.slice(0, 3) + " " + c.slice(3) : c);
/**
 * What the inspector says about a node whose entries this login could not list (the model's `view.unreadable`, by the broker's own code).
 * Chosen here by code.  The point of every line is the last clause: "none shown" is not "none".
 */
const UNREADABLE_TEXT = {
  node_locked: "This node is locked, so its entries could not be listed. Unlock it to see them.",
  node_access_denied: "This login is not allowed to read this node, so its entries are not listed. That is not the same as having none.",
  capability_not_held: "This login does not hold the permission to list this node’s entries, so none are shown. That is not the same as having none.",
  two_factor_required: "This node asks for a second factor before it lists its entries (level always). Give it to read them. That is not the same as having none.",
};
const unreadableText = (code) => (code ? UNREADABLE_TEXT[code] || "This node’s entries could not be listed by this login. That is not the same as having none." : "");

/** An item of the orphaned node, shaped like an entry so the entry detail can show it (values are sealed: always masked). */
const orphanEntry = (o) => ({ id: o.id, name: o.name, type: "sealed", sensitivity: null, totp: false, meta: "orphaned · sealed · human-only", fieldCount: 1, fields: [{ label: "", type: "sealed", masked: true }] });

export const inspectorMethods = {
  select(id){
    this.setState(st=>{
      let recentNodes=st.recentNodes||[];
      if(id!=='__orphan'){ recentNodes=[id,...recentNodes.filter(x=>x!==id)].slice(0,5); }
      return {selected:id,openEntry:null,ctx:null,fieldMenu:null,railOpen:false,inspOpen:true,recentNodes,reveals:{}};
    });
    this._unmaskedFor=null;
    this.model.wipeSecrets(); // a revealed value does not follow the user to another node
    if(id!=='__orphan') this.rereadNote(id);
    this.buildEntryNodes(id); setTimeout(()=>this.renderGraph(),0);
  },
  /** Read a node's note again (selecting a node is the explicit "show me this node"; the note may have changed since). */
  rereadNote(id){
    const n=this.node(id);
    if(!n||n.gate.locked||this.model.status!=='unlocked')return;
    (this._notesAsked||(this._notesAsked=new Set())).add(id);
    loadNotes(this.model,id).catch(e=>this.routeReadError(e,{op:'notes.read',node:id,retry:()=>this.rereadNote(id)}));
  },
  /** The first time a node's inspector is drawn and its note has never been read: read it (once per unlocked session). */
  wantNotes(n){
    if(this.model.status!=='unlocked'){ this._notesAsked=null; return; }
    if(n.gate.locked||n.notes!==null)return;
    const asked=this._notesAsked||(this._notesAsked=new Set());
    if(asked.has(n.id))return;
    asked.add(n.id);
    setTimeout(()=>{ loadNotes(this.model,n.id).catch(e=>this.routeReadError(e,{op:'notes.read',node:n.id,retry:()=>this.rereadNote(n.id)})); },0); // never start a request from inside a render
  },
  /** Every rejection of a read-path call goes here.  A locked node is the locked panel (derived from the node's gate), not a notice. */
  routeReadError(e,ctx){
    ctx=ctx||{};
    const code=errorCode(e), n=ctx.node?this.node(ctx.node):null, nodeIsLocked=!!(n&&n.gate.locked);
    // Only a READ of a locked node is the locked panel; a refused lock, unlock or rename must still say what was refused.
    const reading=ctx.op==='entry.reveal'||ctx.op==='entry.get'||ctx.op==='totp.code'||ctx.op==='notes.read';
    // A node that requires a second factor (ADR-085) refuses a reveal, and at level `always` every read, until the owner has proven it in the last
    // five minutes.  The dialog asks for the code; on success the caller's `retry` repeats what was refused.  Without a `retry` there is nothing to repeat.
    if(code==='two_factor_required'&&reading&&typeof ctx.retry==='function'){ this.askSecondFactor(ctx); return {route:'two-factor'}; }
    // node_locked is the broker's own word.  An owner's reveal on a locked node answers approval_pending (ADR-042: approval on demand is how a
    // locked node is reached at all), and a TOTP code answers node_access_denied (R1), which only means "locked" if the snapshot agrees.
    if(reading&&(code==='node_locked'||code==='approval_pending'||(nodeIsLocked&&code==='node_access_denied'))){
      if(!nodeIsLocked){ // our snapshot may be stale: re-read it, and the panel follows from the node's gate; if the node is not locked after all, say what happened
        this.model.refresh({graph:true}).then(()=>{ const m=ctx.node&&this.node(ctx.node); if(!m||!m.gate.locked)this.routeError(e,ctx); },(e2)=>this.routeError(e2,{op:'refresh'}));
      }
      return {route:'node-locked',node:ctx.node||null};
    }
    if(ctx.op==='totp.code'&&code==='malformed_request'){ this.notify('warn','This entry does not hold a usable TOTP seed (codes need a base32 seed of at least 80 bits, 16 characters).'); return {route:'notice'}; }
    if(code==='clipboard_failed'||code==='text_too_large'){ this.notify('error','The clipboard could not be written. Nothing was copied.'); return {route:'notice'}; }
    return this.routeError(e,ctx);
  },
  /** Open an entry from the list.  Its fields are read afresh (another process may have changed them since the last time it was open). */
  openEntryDetail(node,en){
    const key=node+'\u0000'+en.id;
    if(this._detailAsked)this._detailAsked.delete(key);
    if(this._detailErr)delete this._detailErr[key];
    this.model.dropDetail(node,en.id);
    this.setState({openEntry:en.id,fieldMenu:null});
  },
  /**
   * The entry's fields (ids, labels, types, masking) have not been read: read them, once per opening.  A failure is kept by code so the
   * detail can say so and offer a retry; it is not retried by itself (a render would loop on it).  Never start a request from inside a render.
   */
  wantDetail(node,en){
    if(this.model.status!=='unlocked'){ this._detailAsked=null; this._detailErr=null; return; }
    const key=node+'\u0000'+en.id;
    const asked=this._detailAsked||(this._detailAsked=new Set());
    if(asked.has(key))return;
    asked.add(key);
    setTimeout(()=>{
      loadEntryDetail(this.model,node,en.id).catch((e)=>{
        (this._detailErr||(this._detailErr={}))[key]=errorCode(e)||'unknown';
        this.routeReadError(e,{op:'entry.get',node,entry:en.id,retry:()=>this.retryDetail(node,en)});
        if(this._mounted)this.forceUpdate();
      });
    },0);
  },
  /** "Try again" on a detail whose fields could not be read. */
  retryDetail(node,en){
    const key=node+'\u0000'+en.id;
    if(this._detailAsked)this._detailAsked.delete(key);
    if(this._detailErr)delete this._detailErr[key];
    this.forceUpdate();
  },
  /**
   * The fields that are not masked are shown without a click (ADR-078): ONE read of exactly those fields, audited like any reveal.  It is
   * asked for again whenever the held values were wiped (the window was hidden, a field was changed), and not otherwise, so a refusal
   * does not loop.  Values of another entry that were still held are dropped first: only the open entry shows anything.
   */
  wantUnmasked(node,en,ids){
    const key=node+'\u0000'+en.id, list=ids.join(',');
    const asked=this._unmaskedAsked||(this._unmaskedAsked={});
    if(this.model.status!=='unlocked'){ this._unmaskedAsked=null; return; }
    if(typeof document!=='undefined'&&document.hidden)return; // a hidden window holds no value: the wipe that hid it is not undone until it is back in view
    // asked again only when the held values were wiped, or when the fields still to read are not the ones last asked for (a field was added)
    if(asked[key]===this.model.wipeCount+'|'+list)return;
    asked[key]=this.model.wipeCount+'|'+list;
    (this._unmaskedPending||(this._unmaskedPending={}))[key]=true;
    setTimeout(async ()=>{
      if(this._unmaskedFor&&this._unmaskedFor!==key)this.model.wipeSecrets();
      this._unmaskedFor=key;
      asked[key]=this.model.wipeCount+'|'+list; // (the wipe above is not a reason to ask again)
      let held;
      try{ held=await revealUnmasked(this.model,node,en.id,ids,UNMASKED_WINDOW_MS); }
      catch(e){ held=false; this.routeReadError(e,{op:'entry.reveal',node,entry:en.id,retry:()=>{ this._unmaskedAsked=null; if(this._mounted)this.forceUpdate(); }}); }
      if(this._unmaskedPending)delete this._unmaskedPending[key];
      if(held&&(this.model.status!=='unlocked'||this.state.openEntry!==en.id))this.model.dropEntrySecrets(node,en.id); // the user moved on meanwhile
      if(this._mounted)this.forceUpdate();
    },0);
  },
  /** Show or hide one field.  The value is fetched into the model's secret store for the reveal window and nowhere else. */
  async toggleReveal(node,en,f,i){
    const fk=fieldKeyOf(f,i), key=en.id+':'+fk, totp=f.type==='totp-seed';
    if(this.state.reveals[key]){ this.model.hide(node,en.id,fk); this.setState(st=>{const rv={...st.reveals};delete rv[key];return{reveals:rv};}); return; }
    this._busy=this._busy||{};
    if(this._busy[key])return; // a second click while the first is in flight must not ask the broker twice
    this._busy[key]=true;
    const ms=(this.state.revealWindowSecs||20)*1000;
    let until, held;
    try{
      if(totp){ const t=await readTotp(this.model,node,en.id,ms,f.id); held=t.held; until=t.expiresAt; } // the code, valid to the end of its 30 s step
      else{ held=await this.model.reveal(node,en.id,fk,ms); until=Date.now()+ms; }
    }
    catch(e){ this.routeReadError(e,{op:totp?'totp.code':'entry.reveal',node,entry:en.id,retry:()=>this.toggleReveal(node,en,f,i)}); return; }
    finally{ this._busy[key]=false; }
    // `held` is the model's own word: false means the user hid the field, moved to another node, hid the window or locked while the
    // broker was answering, and the value was dropped on arrival.  Nothing is shown for it.
    if(!held)return;
    // (defence in depth) locked, or the user moved on, in the instant between the model keeping the value and this line
    if(this.model.status!=='unlocked'||this.state.openEntry!==en.id){ this.model.hide(node,en.id,fk); return; }
    this.setState(st=>({reveals:{...st.reveals,[key]:until}}));
  },
  /**
   * Copy one field.  The shell reveals ONLY that field Rust-side and writes the concealed clipboard (cleared after 30 s, on lock and
   * on quit); the value never enters this page.  If this build has no such command nothing is copied and the user is told.
   * A secret is never written with navigator.clipboard.
   */
  async copyField(node,en,f,i){
    if(f.type==='totp-seed')return; // a code is shown, never copied; the seed is not available
    const key=en.id+':'+fieldKeyOf(f,i);
    let r;
    try{ r=await copyEntry(this.model,node,en.id,f.id); }
    catch(e){ this.routeReadError(e,{op:'entry.reveal',node,entry:en.id,retry:()=>this.copyField(node,en,f,i)}); return; }
    if(!r.copied){ this.notify('info','Copy is not available in this build.'); return; }
    this.setState(st=>({copied:{...st.copied,[key]:Date.now()+1500}}));
  },
  /** "show seed": asked for, and refused (presence).  If the broker ever answered, the answer is dropped unread. */
  async showTotpSeed(node,en,f){
    try{ await readTotpSeed(this.model,node,en.id,f?f.id:undefined); this.notify('info','The seed is not shown in this build.'); }
    catch(e){ this.routeReadError(e,{op:'totp.seed',node,entry:en.id}); }
  },
  /** "open" on a sealed item: ask the broker.  It refuses without presence (R0); if it ever answered, the item opens like an entry. */
  async openOrphanItem(o){
    const node=this.model.orphanNodeId; if(!node)return;
    const ms=(this.state.revealWindowSecs||20)*1000;
    let held;
    this._openingOrphan=o.id;
    try{ held=await this.model.reveal(node,o.id,0,ms); }
    catch(e){
      // R0: the orphaned node is native + presence only, and presence cannot be attested in this build, so the broker's denial IS the
      // presence refusal.  It goes through the router like every other error, as the standard presence notice.
      const r0=errorCode(e)==='node_access_denied'&&e.detail&&e.detail.rule==='R0';
      this.routeReadError(r0?{...e,code:'presence_required'}:e,{op:'entry.reveal',node,entry:o.id}); return;
    }
    finally{ this._openingOrphan=null; }
    if(!held)return; // dropped on arrival: the user moved on, hid the window or locked while the broker was answering
    if(this.model.status!=='unlocked'||this.state.selected!=='__orphan'){ this.model.hide(node,o.id,0); return; }
    this.setState(st=>({openEntry:o.id,reveals:{...st.reveals,[o.id+':0']:Date.now()+ms}}));
  },
  /** Kept because other areas call it (lock, window hidden).  The webview never writes a secret to the clipboard now, and the shell empties its own copy. */
  clearClipboard(){},
  /**
   * What the detail asked of the broker, and what it was refused, is remembered so a render does not ask twice.  All of it belongs to ONE login:
   * when the model has cleared (a lock, a lost login) the next one starts from nothing, or an entry opened again by a path that does not call
   * openEntryDetail (a click on the graph) would wait forever for fields it believes it already asked for.
   */
  syncFieldGuards(){
    if(this._guardEpoch===this.model.epoch)return;
    this._guardEpoch=this.model.epoch;
    this._detailAsked=null; this._detailErr=null; this._unmaskedAsked=null; this._unmaskedFor=null; this._unmaskedPending=null;
  },
  rvInspector(c){
    this.syncFieldGuards();
    const {now, s, sel, set, v} = c;
    const isOrphan=s.selected==='__orphan';
    const tfL=Math.max(0,Math.ceil(((s.tfUntil||0)-Date.now())/1000)), tfOn=tfL>0, tfLab=Math.floor(tfL/60)+':'+String(tfL%60).padStart(2,'0'); // the five-minute window (advisory countdown)
    const nodeId=isOrphan?this.model.orphanNodeId:(sel?sel.id:null);
    // inspector
    const inspEntriesArr=isOrphan?v.orphans.map(orphanEntry):(sel?(v.entries[sel.id]||[]):[]);
    const openE=s.openEntry?inspEntriesArr.find(x=>x.id===s.openEntry):null;
    // The one place that knows which entry is open: whatever route opened it (graph dot, list, search, keyboard), the previous entry's values go.
    if(!this._openingOrphan)this.model.retainSecretsFor(openE&&nodeId?nodeId:null,openE?openE.id:null); // (not while an orphaned item is being opened: its reveal is in flight before openEntry is set)
    const nodeLocked=!!(sel&&sel.gate.locked); // the per-node locked panel: known from the snapshot, no refusal needed to show it
    const unreadable=(!isOrphan&&sel&&v.unreadable?v.unreadable[sel.id]:null)||null; // the broker refused to list this node's entries: shown as that, never as "no entries"
    const orphanUnreadable=(isOrphan&&nodeId&&v.unreadable?v.unreadable[nodeId]:null)||null;
    const revealMs=(s.revealWindowSecs||20)*1000;
    if(sel&&!openE)this.wantNotes(sel);
    // The open entry's fields.  A bridge entry's list row carries no labels (they are encrypted with the values), so they come from
    // `entry.get` (the model's detail) and from nothing else: until it answers the detail says it is reading, and if it fails it says so.
    const inEntry=!!openE&&!nodeLocked;
    const detailKey=inEntry&&!isOrphan?nodeId+'\u0000'+openE.id:null;
    const detail=detailKey?this.model.detail(nodeId,openE.id):undefined;
    if(detailKey&&!detail)this.wantDetail(nodeId,openE);
    const detailErr=detailKey&&this._detailErr?this._detailErr[detailKey]||null:null;
    const fieldsSrc=!inEntry?[]:isOrphan?openE.fields:(detail?detail.fields:[]);
    // The fields that are not masked show without a click: one read of the ones not held yet.
    const unmaskedMissing=detail?detail.fields.filter(f=>!f.masked&&f.type!=='totp-seed'&&this.model.plain(nodeId,openE.id,f.id)===undefined).map(f=>f.id):[];
    if(unmaskedMissing.length)this.wantUnmasked(nodeId,openE,unmaskedMissing);
    const unmaskedBusy=!!(detailKey&&this._unmaskedPending&&this._unmaskedPending[detailKey]);
    const entryFields=fieldsSrc.map((f,i)=>{ const fk=fieldKeyOf(f,i), key=openE.id+':'+fk; const until=s.reveals[key]; const revealed=!!(until&&until>now);
      const totp=f.type==='totp-seed'; // a seed is never shown or copied: its code is
      const keepMasked=f.masked||totp;
      const masked=keepMasked&&!revealed;
      const text=masked?undefined:this.model.plain(nodeId,openE.id,fk); // from the model's private store (revealed, or fetched as unmasked); never from the view
      const secs=revealed?Math.ceil((until-now)/1000):0;
      const span=totp?Math.min(revealMs,TOTP_STEP_MS):revealMs;
      const shown=text===undefined?(masked?MASK:(unmaskedBusy?'…':'—')):(totp?groupCode(text):(text===''?'(empty)':text));
      const menuOpen=!isOrphan&&s.fieldMenu===key;
      const last=fieldsSrc.length===1;
      return { id:f.id||String(i), label:fieldName(f,i), type:f.type, masked:masked?'true':'false', maskable:keepMasked, groupLabel:fieldName(f,i)+' ('+f.type+')',
        sensClass:'sens-'+(isOrphan?(openE.sensitivity||this.fieldSensTier(f.type)):this.fieldSensTier(f.type)),
        display:shown, counting:revealed, pct:revealed?Math.min(100,(until-now)/span*100)+'%':'0%', secs:String(secs),
        revealLabel:revealed?'hide':(totp?'show code':'reveal'),
        revealTitle:totp?'the current code, valid until the next 30 s step':'visible '+(s.revealWindowSecs||20)+' s, then re-masks',
        reveal:()=>this.toggleReveal(nodeId,openE,f,i),
        canCopy:!totp&&!isOrphan, copyLabel:(s.copied[key]&&s.copied[key]>now)?'copied':'copy', copy:()=>this.copyField(nodeId,openE,f,i),
        isTotp:totp, showSeed:()=>this.showTotpSeed(nodeId,openE,f),
        canMenu:!isOrphan, menuOpen, menuLabel:'actions for '+fieldName(f,i), toggleMenu:()=>this.toggleFieldMenu(key),
        menuItems:isOrphan?[]:[
          {label:'Edit…',title:'',color:'var(--bone)',disabled:false,go:()=>this.openFieldDlg('edit',nodeId,openE,f,i)},
          {label:'Move up',title:i===0?'already the first field':'',color:'var(--bone)',disabled:i===0,go:()=>this.moveField(nodeId,openE,fieldsSrc,i,-1)},
          {label:'Move down',title:i===fieldsSrc.length-1?'already the last field':'',color:'var(--bone)',disabled:i===fieldsSrc.length-1,go:()=>this.moveField(nodeId,openE,fieldsSrc,i,1)},
          {label:'Remove…',title:last?'an entry keeps at least one field':'',color:'var(--danger-fg)',disabled:last,go:()=>this.openFieldDlg('remove',nodeId,openE,f,i)},
        ] };
    });
    const noteText=!sel?'':sel.gate.locked?'locked — unlock the node to read its note':sel.notes===null?'—':(sel.notes===''?'No note.':sel.notes);
    return {
      entryUnlocked:!nodeLocked,
      entryLockedShow:nodeLocked,
      lockedUnlock:()=>{ if(sel)this.setNodeLock(sel.id,false); },
      inspNode:!!sel&&!openE,
      inspOrphan:isOrphan&&!openE,
      inspEntry:!!openE,
      inspLabel:isOrphan?'orphaned':(sel?sel.label:''),
      inspCounts:sel?`${sel.counts.entries} entries · ${sel.counts.totp} 2FA`:'',
      inspLocked:sel?sel.gate.locked:false,
      insp2fa:sel?sel.gate.twofa==='required':false, // the snapshot says a second factor is required here, not at which level
      inspTfBtn:!!sel&&sel.gate.twofa==='required'&&!tfOn&&!sel.gate.locked, // the action: a deliberate step-up (the owner's own login is exempt; the window it opens is for agents)
      inspTfGive:()=>{ if(sel)this.askSecondFactor({node:sel.id,give:true}); },
      inspTf:tfOn, inspTfLabel:tfOn?'second factor given · '+tfLab:'', // the window is vault-wide, so the countdown shows on every node that asks
      inspNameHidden:!!(sel&&sel.nameHidden), // ADR-083: this login is the owner and still sees the name; everyone else gets an opaque row
      inspEntries:isOrphan?[]:inspEntriesArr.map(en=>({name:en.name,type:en.type,totp:en.totp,sens:en.sensitivity==='critical'?'3px solid var(--danger)':en.sensitivity==='high'?'3px solid var(--bone)':en.sensitivity==='medium'?'2px solid var(--mute)':'1px solid var(--faint)',open:()=>this.openEntryDetail(nodeId,en)})),
      inspEmpty:!!sel&&!inspEntriesArr.length&&!unreadable,
      inspUnreadable:!!unreadable,
      inspUnreadableCode:unreadable||'',
      inspUnreadableText:unreadableText(unreadable),
      inspUnreadableUnlock:unreadable==='node_locked',
      inspUnreadableFactor:unreadable==='two_factor_required',
      unreadableUnlock:()=>{ if(sel)this.setNodeLock(sel.id,false); },
      unreadableFactor:()=>{ if(sel)this.askSecondFactor({node:sel.id,retry:()=>{ this.model.refresh({graph:true,nodes:[sel.id]}).catch(e=>this.routeError(e,{op:'refresh'})); }}); },
      inspNotes:noteText,
      orphanCount:orphanUnreadable?'—':String(v.orphans.length), // "0 items" would claim an answer the broker never gave
      orphanItems:v.orphans.map(o=>({name:o.name,open:()=>this.openOrphanItem(o)})),
      orphanEmpty:!v.orphans.length&&!orphanUnreadable,
      orphanUnreadable:!!orphanUnreadable,
      orphanUnreadableCode:orphanUnreadable||'',
      orphanUnreadableText:unreadableText(orphanUnreadable),
      closeEntry:()=>{ this.model.wipeSecrets(); this._unmaskedFor=null; this.setState({openEntry:null,reveals:{},fieldMenu:null}); }, // leaving the detail hides what it showed
      entryName:openE?openE.name:'',
      entryType:openE?(detail?detail.type:openE.type):'',
      entryMeta:openE?(isOrphan?openE.meta:openE.meta+' · '+(detail?detail.fieldCount:openE.fieldCount)+((detail?detail.fieldCount:openE.fieldCount)===1?' field':' fields')):'',
      entryFields,
      fieldsLoading:inEntry&&!isOrphan&&!detail&&!detailErr,
      fieldsFailed:inEntry&&!isOrphan&&!detail&&!!detailErr,
      fieldsFailedText:detailErr==='not_found'?'This entry no longer exists.':detailErr==='two_factor_required'?'This node asks for a second factor before it shows an entry (level always).':'The fields of this entry could not be read.',
      retryFields:()=>{ if(openE)this.retryDetail(nodeId,openE); },
      fieldsShow:inEntry&&(isOrphan||!!detail),
      fieldsEditable:!isOrphan&&!!detail,
      addFieldOpen:()=>{ if(openE&&detail)this.openFieldDlg('add',nodeId,openE,null,fieldsSrc.length); },
      openAddEntry:()=>this.openAddDlg(sel?sel.id:'global'),
      openAddNote:()=>this.openAddDlg(sel?sel.id:'global',true),
      inspOpenClass:s.inspOpen?'is-open':'',
      closeInsp:set({inspOpen:false}),
    };
  },
};
