/* The entry inspector's "Move to project…" and its dialog (ADR-158: `entry.move`).
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   What this file does with the broker, and nothing else:
     entry.move   {node, entry, to, generation}   the dialog's Move button; the value is re-sealed inside the broker and never reaches the page
   The tidy-up overlay (tidy.js, ADR-161) opens the same dialog for a "Move to <project>" proposal, with that project chosen.
   The broker asks for the second factor and Touch ID itself (the shell answers Touch ID; a missing code is the app's 2FA prompt), so the
   dialog asks for neither.  What the move does not carry (grants on the entry, its Undo history) is said in the dialog before the press
   and counted in the message after it, from the broker's own answer. */

import { errorCode, write } from "../../vault/index";

/** True only in a development or test build, which may run on the in-memory example vault with no broker. Folds to `false` in a release build. */
const DEMO_BUILD = import.meta.env.DEV || import.meta.env.MODE === 'test';
const NEEDS_APP = 'This needs the CredMgr app: this page has no broker to write to. Nothing was changed.';
const dropErrors = (fe, prefix) => { const out = {}; for (const k in (fe || {})) if (!k.startsWith(prefix)) out[k] = fe[k]; return out; };
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

/**
 * The nodes an entry of `from` can move to: every other node of the vault that is not locked.  A locked node is refused by the broker
 * (`node_locked`), so it is not offered.  Pure: `nodes` is the model's node list.
 */
export function moveTargets(nodes, from){
  return (nodes || []).filter((n) => n && n.id !== from && !(n.gate && n.gate.locked)).map((n) => ({ id: n.id, label: n.label }));
}

/** The message after a move, from the broker's answer: where it went, and what did not go with it. */
export function movedText(name, toLabel, r){
  const parts = [`“${name}” moved to ${toLabel}.`];
  const revoked = Array.isArray(r && r.grantsRevoked) ? r.grantsRevoked.length : 0;
  if(revoked) parts.push(`${plural(revoked, 'grant on it was', 'grants on it were')} revoked.`);
  const dropped = r && typeof r.historyDropped === 'number' ? r.historyDropped : 0;
  if(dropped) parts.push(`${plural(dropped, 'earlier value', 'earlier values')} kept for Undo ${dropped === 1 ? 'was' : 'were'} dropped.`);
  return parts.join(' ');
}

export const moveMethods = {
  /** `opts` (ADR-161): the tidy-up overlay opens this dialog with its proposal's destination chosen (`to`) and `origin: 'tidy'`. */
  openMoveDlg(node, en, opts){
    const targets = moveTargets(this.vault.nodes, node);
    const want = opts && opts.to && targets.some((t) => t.id === opts.to) ? opts.to : null;
    this.setState((st) => ({ dialog: 'move', fieldMenu: null, ctx: null, fieldErrors: dropErrors(st.fieldErrors, 'move.'),
      moveForm: { node, entry: en.id, entryName: en.name, to: want || (targets.length ? targets[0].id : ''), busy: false, origin: (opts && opts.origin) || null } }));
  },
  closeMoveDlg(){ this.setState((st) => ({ dialog: null, moveForm: null, fieldErrors: dropErrors(st.fieldErrors, 'move.') })); },
  setMoveForm(patch, keepErrors){
    this.setState((st) => (st.moveForm ? { moveForm: { ...st.moveForm, ...patch }, ...(keepErrors ? {} : { fieldErrors: dropErrors(st.fieldErrors, 'move.') }) } : null));
  },
  /**
   * One broker call.  Only that call is inside the try: once the broker has moved the entry, nothing after it may read as "Nothing was
   * changed".  Then the inspector follows the entry to its new node, so the person sees where it went.
   */
  async saveMove(){
    const f = this.state.moveForm;
    if(!f || f.busy || !f.to || this._moving) return;
    if(!moveTargets(this.vault.nodes, f.node).some((t) => t.id === f.to)) return;
    if(DEMO_BUILD && this.model.kind !== 'bridge'){ this.notify('info', NEEDS_APP); return; }
    this._moving = true;
    this.setMoveForm({ busy: true });
    const toLabel = this.labelOf(f.to);
    let r;
    try{
      r = await write.moveEntry(this.model, f.node, f.entry, f.to);
    }catch(e){
      // A refused call moved nothing.  `entry_exists` is the destination's name clash, said in the dialog; a stale generation
      // re-reads the node (routeError) and keeps the dialog for a retry; a missing entry closes it.
      const code = errorCode(e);
      const route = this.routeError(e, { op: 'entry.move', node: f.node, entry: f.entry, field: 'move.save', inlineRendered: true });
      if(code === 'entry_exists') this.setState((st) => ({ fieldErrors: { ...(st.fieldErrors || {}), 'move.save': `${toLabel} already has an entry called “${f.entryName}” or one of its other names. Rename one of them first. Nothing was moved.` } }));
      if(route && route.route === 'refresh' && code === 'not_found') this.closeMoveDlg();
      else this.setMoveForm({ busy: false }, true);
      return;
    }finally{
      this._moving = false;
    }
    this.setState((st) => ({ dialog: null, moveForm: null, fieldErrors: dropErrors(st.fieldErrors, 'move.'), historyView: null, entryTab: null }));
    const text = movedText(f.entryName, toLabel, r);
    if(r.readbackError) this.savedButNotRefreshed(r.readbackError, text);
    else this.notify('success', text);
    // ADR-161: from the tidy-up overlay, the person stays on its list, which is read again.
    if(f.origin === 'tidy'){ this.runTidy(); return; }
    this.select(f.to);
    this.setState({ openEntry: r.entry || f.entry });
  },

  rvMove(c){
    const { s, sel, v } = c;
    const nodeId = s.selected && s.selected !== '__orphan' && sel ? sel.id : null;
    const entryId = nodeId && s.openEntry ? s.openEntry : null;
    const detail = entryId ? this.model.detail(nodeId, entryId) : undefined;
    const en = entryId ? (((v.entries || {})[nodeId] || []).find((x) => x.id === entryId) || null) : null;
    const usable = !!(detail && en && !sel.gate.locked);
    const targets = usable ? moveTargets(this.vault.nodes, nodeId) : [];

    const f = s.moveForm, open = s.dialog === 'move' && !!f;
    const opts = open ? moveTargets(this.vault.nodes, f.node) : [];
    const err = open ? ((s.fieldErrors || {})['move.save'] || '') : '';
    return {
      moveBtnShow: usable && targets.length > 0,
      moveOpen: () => { if(usable && targets.length) this.openMoveDlg(nodeId, en); },

      dlgMove: open,
      mvEntry: open ? f.entryName : '',
      mvFrom: open ? this.labelOf(f.node) : '',
      mvTo: open ? f.to : '',
      mvOpts: opts,
      onMvTo: (ev) => this.setMoveForm({ to: ev.target.value }),
      mvErrShow: !!err,
      mvErr: err,
      mvSaveDisabled: !open || !!f.busy || !opts.some((o) => o.id === f.to),
      mvSaveLabel: open && f.busy ? 'Moving…' : 'Move entry',
      saveMoveForm: () => this.saveMove(),
      cancelMoveDlg: () => this.closeMoveDlg(),
    };
  },
};
