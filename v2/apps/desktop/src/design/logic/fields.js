/* The fields of an entry (ADR-078): the per-field menu, adding a field, editing one, removing one and moving one.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Field-UI lane.

   Every change is ONE bridge call through src/vault/actions/write.ts, then a re-read of the node, the graph and the entry's fields,
   then a notice.  Nothing is written to the view; a rejection goes to this.routeError and is never swallowed.  What the commands are:
     + Add field      field.add      {fields:[{label,value}]}                    appended; the broker mints the id
     Edit…            field.update   {field, patch:{label?,value?,type?,masked?}} only the keys the user changed
     Move up / down   field.reorder  {order:[every field id, in the new order]}
     Remove…          field.remove   {field}                                      the last field cannot go
   Each carries the node's generation as the list last said it; a stale one is `conflict`, and the screen reloads and says so.
   After an add, an edit or a remove the entry offers Undo (entry.undo, ADR-086): the broker restores the fields and says what it restored.
   Add field also offers Generate (util.generate, ADR-087): the broker makes the value, the dialog shows it masked with its entropy, and it
   goes into the entry only through field.add like a typed one.

   What the user typed (a new value, a label) lives in this component's state only while its dialog is open: it is cleared on save,
   on any way of closing the dialog and on lock (scheduleFieldFormWipe).  No value is ever put in a notice, a log or storage, and a
   notice never names a field's label (a label is the user's own text; the entry's name is already on screen). */

import { errorCode, isSessionEnded, write } from "../../vault/index";
import { fieldName } from "./inspector.js";

/** True only in a development or test build, which may run on the in-memory example vault with no broker (see settings.js DEMO_BUILD). Folds to `false` in a release build. */
const DEMO_BUILD = import.meta.env.DEV || import.meta.env.MODE === 'test';
const NEEDS_APP = 'Changing a field needs the CredMgr app: this page has no broker to write to. Nothing was changed.';

/** The field types a user may pin (the broker's `FieldType`).  `auto` clears the pin and lets inference decide again. */
export const FIELD_TYPES = ['password','api-key','private-key','seed-phrase','totp-seed','username','host','port','url','certificate','text'];
const MASK_CHOICES = [['auto','follows the type'],['hidden','always hidden'],['shown','always shown']];
/** A label is at most 200 characters (counted as characters, not UTF-16 units), on one line. */
const LABEL_MAX = 200;
const chars = (t) => Array.from(t).length;
const dropErrors = (fe, prefix) => { const out = {}; for (const k in (fe || {})) if (!k.startsWith(prefix)) out[k] = fe[k]; return out; };
const maskChoice = (f) => (f.maskedOverridden ? (f.masked ? 'hidden' : 'shown') : 'auto');
const blankForm = { mode: null, node: null, entry: null, entryName: '', field: null, label: '', origLabel: '', value: '', type: 'auto', origType: 'auto', masked: 'auto', origMasked: 'auto', index: 0, busy: false,
  gl: '24', gs: true, gp: false, gen: false, genBits: 0 }; // Generate: length, symbols, pronounceable, whether `value` was made by the broker, and the broker's entropy estimate

export const fieldsMethods = {
  // ───────────────────────────── the per-field menu ─────────────────────────────
  toggleFieldMenu(key){
    const opening = this.state.fieldMenu !== key;
    this.setState({ fieldMenu: opening ? key : null });
    if(opening) setTimeout(() => { const el = document.querySelector('.cm-fieldmenu button:not([disabled])'); if(el) el.focus(); }, 30);
  },

  /** A field moves one place.  The ids stay, so nothing held is dropped: only the order changes. */
  async moveField(node, en, fields, index, dir){
    const to = index + dir;
    if(to < 0 || to >= fields.length || this._reordering) return;
    this.setState({ fieldMenu: null });
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info', NEEDS_APP); return; }
    const order = fields.map((f) => f.id);
    [order[index], order[to]] = [order[to], order[index]];
    this._reordering = true;
    try{
      const r = await write.reorderFields(this.model, node, en.id, order);
      if(r.readbackError) this.savedButNotRefreshed(r.readbackError, `The fields of “${en.name}” were reordered.`);
    }catch(e){
      this.routeError(e, { op: 'field.reorder', node, entry: en.id });
    }finally{
      this._reordering = false;
    }
  },

  // ───────────────────────────── the add / edit / remove dialog ─────────────────────────────
  /** `f` is the field (edit, remove) or null (add).  The form starts from what the broker said about the field, never from its value. */
  openFieldDlg(mode, node, en, f, index){
    const form = mode === 'add'
      ? { ...blankForm, mode, node, entry: en.id, entryName: en.name }
      : { ...blankForm, mode, node, entry: en.id, entryName: en.name, field: f.id, index, label: f.label, origLabel: f.label,
          type: f.typeOverridden ? f.type : 'auto', origType: f.typeOverridden ? f.type : 'auto', masked: maskChoice(f), origMasked: maskChoice(f) };
    this.setState((st) => ({ dialog: 'field', fieldMenu: null, fieldForm: form, fieldErrors: dropErrors(st.fieldErrors, 'field.'), ctx: null }));
  },
  closeFieldDlg(){
    this.setState((st) => ({ dialog: null, fieldForm: null, fieldErrors: dropErrors(st.fieldErrors, 'field.') }));
  },
  fieldFormDirty(){ const ff = this.state.fieldForm; return !!(ff && (ff.value || ff.label !== ff.origLabel)); },
  /** What was typed may be a secret. It must not outlive its dialog: any close (Cancel, Escape, the scrim, a lock) leaves no form behind. */
  scheduleFieldFormWipe(){
    if(this._fieldWipeQueued || this.state.dialog === 'field' || !this.state.fieldForm) return;
    this._fieldWipeQueued = true;
    queueMicrotask(() => { this._fieldWipeQueued = false; if(this._mounted && this.state.dialog !== 'field' && this.state.fieldForm) this.setState({ fieldForm: null }); });
  },
  /** Change the form. Typing clears the error that was shown for the previous attempt; `keepErrors` is for the busy flag, which must not erase the answer it is waiting on. */
  setFieldForm(patch, keepErrors){
    this.setState((st) => (st.fieldForm ? { fieldForm: { ...st.fieldForm, ...patch }, ...(keepErrors ? {} : { fieldErrors: dropErrors(st.fieldErrors, 'field.') }) } : null));
  },
  /** What Save would send, and whether it can be sent.  Pure: reads state, writes nothing. */
  fieldPlan(){
    const ff = this.state.fieldForm;
    if(!ff) return { disabled: true, patch: {}, problem: '' };
    if(ff.busy) return { disabled: true, patch: {}, problem: '' };
    if(ff.mode === 'remove') return { disabled: false, patch: {}, problem: '' };
    if(chars(ff.label) > LABEL_MAX) return { disabled: true, patch: {}, problem: `A label is at most ${LABEL_MAX} characters.` };
    if(ff.mode === 'add') return { disabled: ff.value === '', patch: {}, problem: '' };
    const patch = {};
    if(ff.label !== ff.origLabel) patch.label = ff.label;
    if(ff.value !== '') patch.value = ff.value; // empty means "keep the value": nothing was typed
    if(ff.type !== ff.origType) patch.type = ff.type; // 'auto' clears the pin
    if(ff.masked !== ff.origMasked) patch.masked = ff.masked === 'auto' ? 'auto' : ff.masked === 'hidden';
    return { disabled: Object.keys(patch).length === 0, patch, problem: '' };
  },
  async saveFieldForm(){
    const ff = this.state.fieldForm;
    if(!ff || this._savingField) return;
    const plan = this.fieldPlan();
    if(plan.disabled) return;
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info', NEEDS_APP); return; }
    const op = ff.mode === 'add' ? 'field.add' : ff.mode === 'edit' ? 'field.update' : 'field.remove';
    this._savingField = true;
    this.setFieldForm({ busy: true });
    try{
      let r, text;
      if(ff.mode === 'add'){ r = await write.addFields(this.model, ff.node, ff.entry, [{ label: ff.label, value: ff.value }]); text = `Field added to “${ff.entryName}”.`; }
      else if(ff.mode === 'edit'){ r = await write.updateField(this.model, ff.node, ff.entry, ff.field, plan.patch); text = `Field updated in “${ff.entryName}”.`; }
      else{ r = await write.removeField(this.model, ff.node, ff.entry, ff.field); text = `Field removed from “${ff.entryName}”.`; }
      // The broker did it. Whatever the re-read does, the form is done with (a retry of an add would add a second field).
      this.setState((st) => { const rv = { ...st.reveals }; for(const k of Object.keys(rv)) if(k.startsWith(ff.entry + ':')) delete rv[k]; return { dialog: null, fieldForm: null, fieldErrors: dropErrors(st.fieldErrors, 'field.'), reveals: rv }; });
      if(r.readbackError) this.savedButNotRefreshed(r.readbackError, text);
      else this.notify('success', text);
      this.offerUndo(ff.node, ff.entry, write.auditOf(r), ({ add: 'add field', edit: 'edit', remove: 'remove field' })[ff.mode]);
    }catch(e){
      // A refused call changed nothing. A rejected field is shown next to the form; a stale generation reloads the entry and keeps the form for a retry;
      // an entry or field that is gone closes it, because there is nothing left to apply it to.
      const route = this.routeError(e, { op, node: ff.node, entry: ff.entry, field: 'field.save', inlineRendered: true });
      if(route && route.route === 'refresh' && errorCode(e) === 'not_found') this.closeFieldDlg();
      else this.setFieldForm({ busy: false }, true);
    }finally{
      this._savingField = false;
    }
  },

  // ───────────────────────────── Undo (entry.undo) ─────────────────────────────
  /**
   * Offer Undo for the change just made.  The audit id is the `audit` member of the change's own answer (ADR-091; the shell passes the
   * broker's envelope id through); if the answer has none, no Undo is offered.  Holds ids and a word, never a value or a label.
   */
  offerUndo(node, entry, audit, text){
    this.setState({ undo: null, undoDone: null });
    if(DEMO_BUILD&&this.model.kind!=='bridge') return;
    if(audit && this._mounted && this.model.status === 'unlocked') this.setState({ undo: { node, entry, audit, text, epoch: this.model.epoch } });
  },
  /** The Undo link: ask the broker to undo, say what it restored (its words, not a copy this page kept), and read the entry afresh. */
  async undoField(){
    const u = this.state.undo;
    if(!u || this._undoing) return;
    this._undoing = true;
    try{
      const r = await write.undoFieldChange(this.model, u);
      const n = r.restored && typeof r.restored.fieldCount === 'number' ? r.restored.fieldCount : null;
      const did = ({ 'field.add': 'add field', 'field.update': 'edit', 'field.remove': 'remove field', 'field.reorder': 'reorder' })[r.restored && r.restored.action] || u.text;
      const msg = n === null ? `Undone: ${did}` : `Restored: ${n} field${n === 1 ? '' : 's'} (undone ${did})`;
      this.setState((st) => { const rv = { ...st.reveals }; for(const k of Object.keys(rv)) if(k.startsWith(u.entry + ':')) delete rv[k]; return { undo: null, undoDone: { entry: u.entry, text: msg }, reveals: rv }; });
      if(r.readbackError) this.savedButNotRefreshed(r.readbackError, 'The change was undone.');
    }catch(e){
      this.setState({ undo: null }); // a refused undo is not offered again
      this.routeError(e, { op: 'entry.undo', node: u.node, entry: u.entry });
    }finally{
      this._undoing = false;
    }
  },

  // ───────────────────────────── Generate (util.generate) ─────────────────────────────
  async generateField(){
    const ff = this.state.fieldForm;
    if(!ff || ff.mode !== 'add' || ff.busy || this._generating) return;
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info', NEEDS_APP); return; }
    this._generating = true;
    try{
      const g = await write.generatePassword(this.model, Number(ff.gl), ff.gs && !ff.gp, ff.gp);
      this.setFieldForm({ value: g.value, gen: true, genBits: g.entropyBits, gl: String(g.length) });
    }catch(e){
      this.routeError(e, { op: 'util.generate' });
    }finally{
      this._generating = false;
    }
  },

  // ───────────────────────────── what the template reads ─────────────────────────────
  rvFields(c){
    const { s } = c;
    this.scheduleFieldFormWipe();
    const ff = s.fieldForm;
    const open = s.dialog === 'field' && !!ff;
    const mode = open ? ff.mode : null;
    const plan = this.fieldPlan();
    const err = (s.fieldErrors || {})['field.save'] || plan.problem || '';
    const typeOpts = [{ id: 'auto', label: 'auto: inferred from the label and the value' }, ...FIELD_TYPES.map((t) => ({ id: t, label: t }))];
    const maskOpts = MASK_CHOICES.map(([id, label]) => ({ id, label }));
    const f = open ? ff : blankForm;
    return {
      dlgField: open,
      fdIsAdd: mode === 'add',
      fdIsEdit: mode === 'edit',
      fdIsRemove: mode === 'remove',
      fdTitle: mode === 'add' ? 'Add a field' : mode === 'edit' ? 'Edit a field' : 'Remove a field',
      fdEntry: f.entryName,
      fdLabel: f.label,
      onFdLabel: (ev) => this.setFieldForm({ label: ev.target.value.replace(/[\r\n\0]/g, ' ') }),
      fdValue: f.gen ? '•'.repeat(Math.min(f.value.length, 32)) : f.value, // a generated value is shown masked, here and everywhere in the dialog
      fdValueRows: f.gen ? 2 : Math.max(2, Math.min(8, f.value.split('\n').length)),
      onFdValue: (ev) => this.setFieldForm({ value: ev.target.value }),
      fdType: f.type,
      fdTypeOpts: typeOpts,
      onFdType: (ev) => this.setFieldForm({ type: ev.target.value }),
      fdMasked: f.masked,
      fdMaskOpts: maskOpts,
      onFdMasked: (ev) => this.setFieldForm({ masked: ev.target.value }),
      fdErrShow: !!err,
      fdErr: err,
      fdRemoveText: mode === 'remove' ? `Remove the field “${fieldName({ label: f.origLabel }, f.index)}” from “${f.entryName}”? The entry keeps its other fields.` : '',
      fdSaveLabel: mode === 'add' ? 'Add field' : mode === 'edit' ? 'Save' : 'Remove field',
      fdVariant: mode === 'remove' ? 'danger' : 'primary',
      fdSaveDisabled: plan.disabled,
      fdGl: f.gl,
      onFdGl: (ev) => this.setFieldForm({ gl: ev.target.value }),
      fdGs: !!(f.gs && !f.gp),
      onFdGs: () => this.setFieldForm({ gs: !f.gs }),
      fdGp: !!f.gp,
      onFdGp: () => this.setFieldForm({ gp: !f.gp }),
      fdGenOn: !!f.gen,
      fdGenNote: f.gen ? `${f.value.length} characters · about ${f.genBits} bits of entropy · shown masked, never copied` : '',
      fdGenerate: () => this.generateField(),
      fdGenClear: () => this.setFieldForm({ value: '', gen: false, genBits: 0 }),
      undoShow: !!(s.undo && (s.undo.epoch === undefined || s.undo.epoch === this.model.epoch) && s.undo.entry === s.openEntry && s.undo.node === s.selected && this.model.status === 'unlocked'),
      undoText: s.undo ? s.undo.text : '',
      undoField: () => this.undoField(),
      undoMsgShow: !!(s.undoDone && s.undoDone.entry === s.openEntry),
      undoMsg: s.undoDone ? s.undoDone.text : '',
      saveFieldForm: () => this.saveFieldForm(),
      cancelFieldDlg: () => this.closeFieldDlg(),
    };
  },
};
