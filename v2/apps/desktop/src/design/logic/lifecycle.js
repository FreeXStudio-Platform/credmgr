/* An entry's Rotate…, Remove… and Undo-remove (rc.2 §1 item 1).
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   What this file does with the broker, and nothing else:
     entry.rotate    {node, entry, generation, field, value}   the Rotate dialog: one field gets a new value, the old one is kept as history
     entry.remove    {node, entry, generation}                 the Remove dialog's button: the entry leaves every list at once, kept seven days
     entry.restore   {node, entry, generation, mode?}          Undo after a removal, and Restore in the audit view's "removed in the last
                                                               seven days"; `mode: "keep-both"` only when the person chose it after an
                                                               `entry_exists` (an entry took the name since)
   Rotate's new value is typed or made by the broker (util.generate, the same Generate the Add field dialog has).  It lives in this
   component's state only while the dialog is open (scheduleRotateWipe), is shown masked when generated, and is never put in a notice.
   After a rotation the entry offers Undo through the existing entry.undo link (fields.js offerUndo): a rotation is undoable with no limit.
   After a removal the node's list shows a bar with Undo for as long as this login lasts and nothing else is opened. */

import { errorCode, write } from "../../vault/index";
import { fieldName } from "./inspector.js";

/** True only in a development or test build, which may run on the in-memory example vault with no broker. Folds to `false` in a release build. */
const DEMO_BUILD = import.meta.env.DEV || import.meta.env.MODE === 'test';
const NEEDS_APP = 'This needs the CredMgr app: this page has no broker to write to. Nothing was changed.';
/** How long a removed entry is kept (crates/store/src/entry_archive.rs RECOVERY_WINDOW_SECONDS). */
export const REMOVE_WINDOW_DAYS = 7;
const DAY = 86400;
const dropErrors = (fe, prefix) => { const out = {}; for (const k in (fe || {})) if (!k.startsWith(prefix)) out[k] = fe[k]; return out; };
const blankRotate = { node: null, entry: null, entryName: '', field: '', fields: [], value: '', gen: false, genBits: 0, gl: '24', gs: true, gp: false, busy: false };

/** What the Remove dialog says before the press: what happens at once, and for how long it can be undone. */
export function removeText(name, nodeLabel){
  return `“${name}” leaves ${nodeLabel} at once: it is no longer listed, searched or readable, by you or by any agent. It is kept, sealed, for ${REMOVE_WINDOW_DAYS} days; Undo brings it back until then. After ${REMOVE_WINDOW_DAYS} days it is deleted for good.`;
}

/** The fields a rotation can change: every field of the entry, the hidden ones first (the value most often rotated), each named as the inspector names it. */
export function rotateFields(detail){
  const fs = (detail && Array.isArray(detail.fields) ? detail.fields : []).map((f, i) => ({ id: f.id, label: fieldName(f, i), masked: !!f.masked }));
  return fs.filter((f) => f.masked).concat(fs.filter((f) => !f.masked)).filter((f) => !!f.id);
}

/**
 * The entries the audit rows say were removed in the last seven days and not brought back since: `rows` is `audit.tail`, newest first.
 * A removal that a newer `entry.restore` / `entry.undo` / `entry.create` of the same entry follows is left out.  Pure.
 */
export function recentlyRemoved(rows, nowSecs){
  const seen = new Set(), out = [];
  for(const r of (rows || [])){
    if(!r || !r.node || !r.entry) continue;
    const key = `${r.node}\u0000${r.entry}`;
    if(seen.has(key)) continue;
    if(r.decision && r.decision !== 'allow') continue;
    if(r.action === 'entry.restore' || r.action === 'entry.undo' || r.action === 'entry.create'){ seen.add(key); continue; }
    if(r.action !== 'entry.remove') continue;
    seen.add(key);
    const left = r.timestamp + REMOVE_WINDOW_DAYS * DAY - nowSecs;
    if(left > 0) out.push({ node: r.node, entry: r.entry, removedAt: r.timestamp, daysLeft: Math.max(1, Math.ceil(left / DAY)) });
  }
  return out;
}

export const lifecycleMethods = {
  // ───────────────────────────── Rotate… ─────────────────────────────
  openRotateDlg(node, en){
    const fields = rotateFields(this.model.detail(node, en.id));
    if(!fields.length) return;
    this.setState((st) => ({ dialog: 'rotate', fieldMenu: null, ctx: null, fieldErrors: dropErrors(st.fieldErrors, 'rotate.'),
      rotateForm: { ...blankRotate, node, entry: en.id, entryName: en.name, fields, field: fields[0].id } }));
  },
  closeRotateDlg(){ this.setState((st) => ({ dialog: null, rotateForm: null, fieldErrors: dropErrors(st.fieldErrors, 'rotate.') })); },
  setRotateForm(patch, keepErrors){
    this.setState((st) => (st.rotateForm ? { rotateForm: { ...st.rotateForm, ...patch }, ...(keepErrors ? {} : { fieldErrors: dropErrors(st.fieldErrors, 'rotate.') }) } : null));
  },
  /** A typed value may be a secret: any way of closing the dialog (Cancel, Escape, the scrim, a lock) leaves no form behind. */
  scheduleRotateWipe(){
    if(this._rotateWipeQueued || this.state.dialog === 'rotate' || !this.state.rotateForm) return;
    this._rotateWipeQueued = true;
    queueMicrotask(() => { this._rotateWipeQueued = false; if(this._mounted && this.state.dialog !== 'rotate' && this.state.rotateForm) this.setState({ rotateForm: null }); });
  },
  async generateRotate(){
    const f = this.state.rotateForm;
    if(!f || f.busy || this._rotGenerating) return;
    if(DEMO_BUILD && this.model.kind !== 'bridge'){ this.notify('info', NEEDS_APP); return; }
    this._rotGenerating = true;
    try{
      const g = await write.generatePassword(this.model, Number(f.gl), f.gs && !f.gp, f.gp);
      this.setRotateForm({ value: g.value, gen: true, genBits: g.entropyBits, gl: String(g.length) });
    }catch(e){
      this.routeError(e, { op: 'util.generate' });
    }finally{
      this._rotGenerating = false;
    }
  },
  /** One broker call; only it is inside the try, so nothing after a rotation the broker made can read as "Nothing was changed". */
  async saveRotate(){
    const f = this.state.rotateForm;
    if(!f || f.busy || !f.value || !f.field || this._rotating) return;
    if(DEMO_BUILD && this.model.kind !== 'bridge'){ this.notify('info', NEEDS_APP); return; }
    this._rotating = true;
    this.setRotateForm({ busy: true }, true);
    let r;
    try{
      r = await write.rotateEntry(this.model, f.node, f.entry, f.field, f.value);
    }catch(e){
      const route = this.routeError(e, { op: 'entry.rotate', node: f.node, entry: f.entry, field: 'rotate.save', inlineRendered: true });
      if(route && route.route === 'refresh' && errorCode(e) === 'not_found') this.closeRotateDlg();
      else this.setRotateForm({ busy: false }, true);
      return;
    }finally{
      this._rotating = false;
    }
    // The broker did it: the form (and the value in it) is done with, whatever the re-read does.
    this.setState((st) => { const rv = { ...st.reveals }; for(const k of Object.keys(rv)) if(k.startsWith(f.entry + ':')) delete rv[k]; return { dialog: null, rotateForm: null, fieldErrors: dropErrors(st.fieldErrors, 'rotate.'), reveals: rv, historyView: null }; });
    const text = `“${f.entryName}” rotated. The previous value is kept as history; Undo puts it back.`;
    if(r.readbackError) this.savedButNotRefreshed(r.readbackError, text);
    else this.notify('success', text);
    this.offerUndo(f.node, f.entry, write.auditOf(r), 'rotate');
  },

  // ───────────────────────────── Remove… and Undo ─────────────────────────────
  openRemoveDlg(node, en){
    this.setState((st) => ({ dialog: 'removeEntry', fieldMenu: null, ctx: null, fieldErrors: dropErrors(st.fieldErrors, 'remove.'),
      removeForm: { node, entry: en.id, entryName: en.name, busy: false } }));
  },
  closeRemoveDlg(){ this.setState((st) => ({ dialog: null, removeForm: null, fieldErrors: dropErrors(st.fieldErrors, 'remove.') })); },
  async saveRemove(){
    const f = this.state.removeForm;
    if(!f || f.busy || this._removing) return;
    if(DEMO_BUILD && this.model.kind !== 'bridge'){ this.notify('info', NEEDS_APP); return; }
    this._removing = true;
    this.setState((st) => (st.removeForm ? { removeForm: { ...st.removeForm, busy: true } } : null));
    let r;
    try{
      r = await write.removeEntry(this.model, f.node, f.entry);
    }catch(e){
      const route = this.routeError(e, { op: 'entry.remove', node: f.node, entry: f.entry, field: 'remove.save', inlineRendered: true });
      if(route && route.route === 'refresh' && errorCode(e) === 'not_found') this.closeRemoveDlg();
      else this.setState((st) => (st.removeForm ? { removeForm: { ...st.removeForm, busy: false } } : null));
      return;
    }finally{
      this._removing = false;
    }
    this.setState((st) => ({ dialog: null, removeForm: null, fieldErrors: dropErrors(st.fieldErrors, 'remove.'), openEntry: st.openEntry === f.entry ? null : st.openEntry, entryTab: null, historyView: null, undo: null, undoDone: null,
      removedUndo: { node: f.node, entry: f.entry, name: f.entryName, epoch: this.model.epoch, busy: false, clash: false } }));
    const text = `“${f.entryName}” removed. It is kept for ${REMOVE_WINDOW_DAYS} days; Undo in the list brings it back.`;
    if(r.readbackError) this.savedButNotRefreshed(r.readbackError, text);
    else this.notify('success', text);
  },
  /**
   * Bring a removed entry back (entry.restore).  `keepBoth` only after the broker said the name is taken now (`entry_exists`) and the person
   * chose to keep both.  `from`: 'bar' (the list's Undo bar) or 'audit' (the audit view's list, read again after).
   */
  async restoreRemoved(node, entry, name, keepBoth, from){
    const key = `${node}\u0000${entry}`;
    if(this._restoring) return;
    if(DEMO_BUILD && this.model.kind !== 'bridge'){ this.notify('info', NEEDS_APP); return; }
    this._restoring = key;
    if(from === 'bar') this.setState((st) => (st.removedUndo ? { removedUndo: { ...st.removedUndo, busy: true } } : null));
    let r;
    try{
      r = await write.restoreEntry(this.model, node, entry, !!keepBoth);
    }catch(e){
      const code = errorCode(e);
      if(code === 'entry_exists'){
        // Nothing was restored: an entry has the name now.  Offer the broker's keep-both, which restores it as “<name> old”.
        if(from === 'bar') this.setState((st) => (st.removedUndo ? { removedUndo: { ...st.removedUndo, busy: false, clash: true } } : null));
        else this.setState({ restoreClash: key });
        this.notify('warn', `Another entry is called “${name}” now. Choose Restore as a copy to keep both; nothing was restored.`);
      }else{
        this.routeError(e, { op: 'entry.restore', node, entry });
        if(from === 'bar') this.setState({ removedUndo: null });
        if(from === 'audit') this.loadAudit();
      }
      return;
    }finally{
      this._restoring = null;
    }
    const shown = r.restoredName || name;
    const text = keepBoth ? `Restored as “${shown}”.` : `“${shown}” is back.`;
    if(from === 'bar') this.setState({ removedUndo: null });
    else this.setState({ restoreClash: null });
    if(r.readbackError) this.savedButNotRefreshed(r.readbackError, text);
    else this.notify('success', text);
    if(from === 'audit'){ this.loadAudit(); return; }
    if(this.state.selected === node) this.setState({ openEntry: r.entry || entry });
  },

  rvLifecycle(c){
    const { s, sel, v } = c;
    this.scheduleRotateWipe();
    const nodeId = s.selected && s.selected !== '__orphan' && sel ? sel.id : null;
    const entryId = nodeId && s.openEntry ? s.openEntry : null;
    const detail = entryId ? this.model.detail(nodeId, entryId) : undefined;
    const en = entryId ? (((v.entries || {})[nodeId] || []).find((x) => x.id === entryId) || null) : null;
    const usable = !!(detail && en && !sel.gate.locked);

    // Rotate dialog
    const rf = s.rotateForm, rOpen = s.dialog === 'rotate' && !!rf;
    const f = rOpen ? rf : blankRotate;
    const rErr = rOpen ? ((s.fieldErrors || {})['rotate.save'] || '') : '';
    // Remove dialog
    const mf = s.removeForm, mOpen = s.dialog === 'removeEntry' && !!mf;
    const mErr = mOpen ? ((s.fieldErrors || {})['remove.save'] || '') : '';
    // The list's Undo bar: this login only, on its node, while no entry is open
    const ru = s.removedUndo;
    const barShow = !!(ru && (ru.epoch === undefined || ru.epoch === this.model.epoch) && ru.node === nodeId && !entryId && this.model.status === 'unlocked');
    // The audit view's "removed in the last seven days", from the rows it already read (audit.tail, newest first)
    const a = this.adm();
    const removed = a.auditState === 'ready' ? recentlyRemoved(a.audit, Math.floor(Date.now() / 1000)) : [];
    const auditRemoved = removed.map((x) => {
      const key = `${x.node}\u0000${x.entry}`;
      const name = this.entryNameOf(x.node, x.entry);
      return {
        what: `${this.labelOf(x.node)} · ${name}`,
        left: `${x.daysLeft} day${x.daysLeft === 1 ? '' : 's'} left`,
        restore: () => this.restoreRemoved(x.node, x.entry, name, false, 'audit'),
        copyShow: s.restoreClash === key,
        copy: () => this.restoreRemoved(x.node, x.entry, name, true, 'audit'),
      };
    });
    return {
      auditRemovedShow: auditRemoved.length > 0,
      auditRemoved,
      rotateBtnShow: usable && rotateFields(detail).length > 0,
      rotateOpen: () => { if(usable) this.openRotateDlg(nodeId, en); },
      removeBtnShow: usable,
      removeOpen: () => { if(usable) this.openRemoveDlg(nodeId, en); },

      dlgRotate: rOpen,
      rtEntry: f.entryName,
      rtField: f.field,
      rtFieldOpts: f.fields,
      rtFieldPick: f.fields.length > 1,
      rtFieldOneShow: f.fields.length === 1,
      rtFieldOne: f.fields.length === 1 ? f.fields[0].label : '',
      onRtField: (ev) => this.setRotateForm({ field: ev.target.value }),
      rtValue: f.gen ? '•'.repeat(Math.min(f.value.length, 32)) : f.value, // a generated value is shown masked
      onRtValue: (ev) => this.setRotateForm({ value: ev.target.value, gen: false, genBits: 0 }),
      rtGenOn: !!f.gen,
      rtGenNote: f.gen ? `${f.value.length} characters · about ${f.genBits} bits of entropy · shown masked, never copied` : '',
      rtGl: f.gl,
      onRtGl: (ev) => this.setRotateForm({ gl: ev.target.value }),
      rtGs: !!(f.gs && !f.gp),
      onRtGs: () => this.setRotateForm({ gs: !f.gs }),
      rtGp: !!f.gp,
      onRtGp: () => this.setRotateForm({ gp: !f.gp }),
      rtGenerate: () => this.generateRotate(),
      rtGenClear: () => this.setRotateForm({ value: '', gen: false, genBits: 0 }),
      rtErrShow: !!rErr,
      rtErr: rErr,
      rtSaveDisabled: !rOpen || !!f.busy || !f.value || !f.field,
      rtSaveLabel: rOpen && f.busy ? 'Rotating…' : 'Rotate',
      saveRotateForm: () => this.saveRotate(),
      cancelRotateDlg: () => this.closeRotateDlg(),

      dlgRemoveEntry: mOpen,
      rmEntry: mOpen ? mf.entryName : '',
      rmText: mOpen ? removeText(mf.entryName, this.labelOf(mf.node)) : '',
      rmErrShow: !!mErr,
      rmErr: mErr,
      rmSaveDisabled: !mOpen || !!mf.busy,
      rmSaveLabel: mOpen && mf.busy ? 'Removing…' : 'Remove entry',
      saveRemoveForm: () => this.saveRemove(),
      cancelRemoveDlg: () => this.closeRemoveDlg(),

      removedBarShow: barShow,
      removedBarText: barShow ? `“${ru.name}” was removed. It is kept for ${REMOVE_WINDOW_DAYS} days.` : '',
      removedUndoLabel: barShow && ru.busy ? 'Restoring…' : 'Undo',
      removedUndoDisabled: !barShow || !!ru.busy,
      removedUndo: () => { if(barShow) this.restoreRemoved(ru.node, ru.entry, ru.name, false, 'bar'); },
      removedCopyShow: barShow && !!ru.clash,
      removedCopy: () => { if(barShow) this.restoreRemoved(ru.node, ru.entry, ru.name, true, 'bar'); },
      removedDismiss: () => this.setState({ removedUndo: null }),
    };
  },
};
