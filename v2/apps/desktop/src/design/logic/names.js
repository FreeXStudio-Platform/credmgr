/* Aliases, near-duplicate names and the .env import (ADR-121, ADR-122).  Mixin of the design's logic class: Object.assign'd onto
   Component.prototype in core.js.

   Every change is ONE bridge call through src/vault/actions/write.ts, then a re-read of what it touched, then a notice.  Nothing is written
   to the view; a rejection goes to this.routeError and is never swallowed.  What the commands are:
     Aliases…           entry.alias       {entry, generation, aliases:[…]}   the whole list (at most 8); a name or alias another entry has is refused
     the name hint      entry.similar     {name}                             while typing a new entry's name: which names look like it (a hint, never a block)
     Import .env…       env_preview       {text}                             the shell reads the text with the command line's own parser (local)
                        entry.import_env  {entries:[{name,value}], dryRun}   the preview: every name, what it would become, what it resembles
                        entry.import_env  {entries, onConflict}              the write: each pair its own entry with its own audit record

   What the user typed or pasted (a .env text, its values) lives in this component's state only while its dialog is open: it is cleared on
   import, on any way of closing the dialog and on lock (scheduleImportWipe).  No value is ever put in a notice, a log or storage.  The
   broker's answers to the preview and the import carry names, statuses and counts, never a value. */

import { write } from "../../vault/index";

/** True only in a development or test build, which may run on the in-memory example vault with no broker (see settings.js DEMO_BUILD). Folds to `false` in a release build. */
const DEMO_BUILD = import.meta.env.DEV || import.meta.env.MODE === 'test';
const NEEDS_APP = 'This needs the CredMgr app: this page has no broker to write to. Nothing was changed.';

const ALIASES_MAX = 8;
const NAME_MAX = 200;
const FILE_MAX = 4 * 1024 * 1024;
const chars = (t) => Array.from(t).length;
const dropErrors = (fe, prefix) => { const out = {}; for (const k in (fe || {})) if (!k.startsWith(prefix)) out[k] = fe[k]; return out; };
const many = (n, one, other) => n + ' ' + (n === 1 ? one : other);

const STATUS_TEXT = {
  new: 'new', exists: 'already there', duplicate: 'repeated in the file', empty: 'empty value, skipped', invalid: 'not a usable name',
};
const STATUS_COLOR = {
  new: 'var(--sig)', exists: 'var(--warn)', duplicate: 'var(--warn)', empty: 'var(--mute)', invalid: 'var(--danger-fg)',
};
const nearText = (n) => (n.alias ? `${n.name} (alias “${n.alias}”)` : n.name);

export const namesMethods = {
  // ───────────────────────────── aliases ─────────────────────────────
  /** `en` is the open entry; `detail` is what `entry.get` said about it (its aliases are there). The form starts from what the broker said. */
  openAliasDlg(node, en, detail){
    const current = (detail && detail.aliases) || [];
    this.setState((st) => ({ dialog: 'alias', fieldMenu: null, ctx: null, fieldErrors: dropErrors(st.fieldErrors, 'alias.'),
      aliasForm: { node, entry: en.id, entryName: en.name, text: current.join('\n'), orig: current, busy: false } }));
  },
  closeAliasDlg(){
    this.setState((st) => ({ dialog: null, aliasForm: null, fieldErrors: dropErrors(st.fieldErrors, 'alias.') }));
  },
  setAliasForm(patch, keepErrors){
    this.setState((st) => (st.aliasForm ? { aliasForm: { ...st.aliasForm, ...patch }, ...(keepErrors ? {} : { fieldErrors: dropErrors(st.fieldErrors, 'alias.') }) } : null));
  },
  /** What Save would send, and whether it can be sent.  Pure: reads state, writes nothing. */
  aliasPlan(){
    const af = this.state.aliasForm;
    if(!af) return { disabled: true, list: [], problem: '' };
    const list = af.text.split(/\r\n|\r|\n/).map((l) => l.trim()).filter((l) => l !== '');
    if(list.length > ALIASES_MAX) return { disabled: true, list, problem: `An entry has at most ${ALIASES_MAX} aliases.` };
    if(list.some((l) => chars(l) > NAME_MAX)) return { disabled: true, list, problem: `An alias is at most ${NAME_MAX} characters.` };
    const seen = new Set();
    for(const l of list){ const k = l.toLowerCase(); if(seen.has(k)) return { disabled: true, list, problem: 'Two of these are the same name.' }; seen.add(k); }
    if(list.some((l) => l.toLowerCase() === af.entryName.toLowerCase())) return { disabled: true, list, problem: 'An alias cannot be the entry’s own name.' };
    const same = list.length === af.orig.length && list.every((l, i) => l === af.orig[i]);
    return { disabled: !!af.busy || same, list, problem: '' };
  },
  async saveAliasForm(){
    const af = this.state.aliasForm;
    if(!af || this._savingAlias) return;
    const plan = this.aliasPlan();
    if(plan.disabled) return;
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info', NEEDS_APP); return; }
    this._savingAlias = true;
    this.setAliasForm({ busy: true });
    try{
      const r = await write.setAliases(this.model, af.node, af.entry, plan.list);
      // The broker did it. Whatever the re-read does, the form is done with.
      this.setState((st) => ({ dialog: null, aliasForm: null, fieldErrors: dropErrors(st.fieldErrors, 'alias.') }));
      let text = plan.list.length ? `Aliases of “${af.entryName}” saved.` : `Aliases of “${af.entryName}” cleared.`;
      const near = Array.isArray(r.similar) ? r.similar : [];
      let kind = 'success';
      if(near.length){ text += ` Looks like ${near.slice(0, 3).map(nearText).join(', ')}${near.length > 3 ? ' and more' : ''}: check they are different entries.`; kind = 'warn'; }
      const warned = write.nameWarningText(r);
      if(warned){ text += ' ' + warned; kind = 'warn'; }
      if(r.readbackError) this.savedButNotRefreshed(r.readbackError, text);
      else this.notify(kind, text);
    }catch(e){
      // A refused call changed nothing: a taken name is shown next to the form; a stale generation reloads the entry and keeps the form for a retry.
      const route = this.routeError(e, { op: 'entry.alias', node: af.node, entry: af.entry, field: 'alias.save', inlineRendered: true });
      if(route && route.route === 'refresh' && e && e.code === 'not_found') this.closeAliasDlg();
      else this.setAliasForm({ busy: false }, true);
    }finally{
      this._savingAlias = false;
    }
  },

  // ───────────────────────────── the name hint in Add entry ─────────────────────────────
  /** A hint, never a block: while a new entry's name is typed, ask which names on the node look like it.  Debounced; an answer for a name no longer typed is dropped. */
  scheduleSimilar(){
    clearTimeout(this._simT);
    const s = this.state;
    const name = (s.addName || '').trim();
    const node = s.addNode;
    if(s.dialog !== 'addEntry' || !name || (s.addMode === 'bulk' && s.splitSegs) || this.model.kind !== 'bridge'){ if(s.addSimilar) this.setState({ addSimilar: null }); return; }
    this._simT = setTimeout(async () => {
      try{
        const r = await write.similarNames(this.model, node, name);
        const now = this.state;
        if(now.dialog !== 'addEntry' || now.addNode !== node || (now.addName || '').trim() !== name) return;
        this.setState({ addSimilar: !r.nameHidden && r.similar.length ? { name, node, text: r.similar.slice(0, 3).map(nearText).join(', ') + (r.similar.length > 3 ? ' and more' : '') } : null });
      }catch(e){
        if(this.state.addSimilar) this.setState({ addSimilar: null }); // a hint: when it cannot be had, nothing is said
      }
    }, 300);
  },

  // ───────────────────────────── the .env import ─────────────────────────────
  openImportDlg(node){
    this.setState((st) => ({ dialog: 'importEnv', ctx: null, fieldErrors: dropErrors(st.fieldErrors, 'import.'),
      importForm: { node, text: '', fileName: '', stage: 'input', pairs: [], skippedEmpty: [], plan: null, onConflict: 'refuse', busy: false } }));
  },
  closeImportDlg(){
    this.setState((st) => ({ dialog: null, importForm: null, fieldErrors: dropErrors(st.fieldErrors, 'import.') }));
  },
  /** What was pasted holds secrets. It must not outlive its dialog: any close (Cancel, Escape, the scrim, a lock) leaves no form behind. */
  scheduleImportWipe(){
    if(this._importWipeQueued || this.state.dialog === 'importEnv' || !this.state.importForm) return;
    this._importWipeQueued = true;
    queueMicrotask(() => { this._importWipeQueued = false; if(this._mounted && this.state.dialog !== 'importEnv' && this.state.importForm) this.setState({ importForm: null }); });
  },
  scheduleAliasWipe(){
    if(this._aliasWipeQueued || this.state.dialog === 'alias' || !this.state.aliasForm) return;
    this._aliasWipeQueued = true;
    queueMicrotask(() => { this._aliasWipeQueued = false; if(this._mounted && this.state.dialog !== 'alias' && this.state.aliasForm) this.setState({ aliasForm: null }); });
  },
  setImportForm(patch, keepErrors){
    this.setState((st) => (st.importForm ? { importForm: { ...st.importForm, ...patch }, ...(keepErrors ? {} : { fieldErrors: dropErrors(st.fieldErrors, 'import.') }) } : null));
  },
  /** A chosen file is read here (File API, no network) into the same text box a paste goes to. */
  async importLoadFile(ev){
    const input = ev && ev.target, file = input && input.files && input.files[0];
    if(!file) return;
    if(file.size > FILE_MAX){ this.setState((st) => ({ fieldErrors: { ...st.fieldErrors, 'import.read': 'That file is larger than 4 MiB.' } })); if(input) input.value = ''; return; }
    try{
      const text = await file.text();
      this.setImportForm({ text, fileName: file.name });
    }catch(e){
      this.setState((st) => ({ fieldErrors: { ...st.fieldErrors, 'import.read': 'That file could not be read.' } }));
    }
    if(input) input.value = '';
  },
  /** Step 1 to 2: the shell reads the text, then the broker previews every name against the node. Nothing is written. */
  async importPreview(){
    const f = this.state.importForm;
    if(!f || f.busy || this._importing) return;
    if(f.text.trim() === ''){ this.setState((st) => ({ fieldErrors: { ...st.fieldErrors, 'import.read': 'Paste the text of a .env file, or choose one.' } })); return; }
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info', NEEDS_APP); return; }
    this._importing = true;
    this.setImportForm({ busy: true });
    try{
      const read = await write.readEnv(this.model, f.text);
      if(!read.entries.length){
        const empties = read.skippedEmpty.length;
        this.setState((st) => ({ fieldErrors: { ...st.fieldErrors, 'import.read': 'Nothing to import: no NAME=value line with a value' + (empties ? ` (${many(empties, 'name has', 'names have')} an empty value).` : '.') } }));
        this.setImportForm({ busy: false }, true);
        return;
      }
      const plan = await write.planImport(this.model, f.node, read.entries);
      this.setImportForm({ stage: 'preview', text: '', pairs: read.entries, skippedEmpty: read.skippedEmpty, plan: { items: plan.items || [], counts: plan.counts }, busy: false });
    }catch(e){
      this.routeError(e, { op: 'env.preview', node: f.node, field: 'import.read', inlineRendered: true });
      this.setImportForm({ busy: false }, true);
    }finally{
      this._importing = false;
    }
  },
  /** Step 2 to 1: back to the text, which is gone (the values are in the pairs); the pairs are dropped too, the file is chosen again. */
  importBack(){
    this.setImportForm({ stage: 'input', pairs: [], skippedEmpty: [], plan: null, text: '', fileName: '' });
  },
  async importRun(){
    const f = this.state.importForm;
    if(!f || f.stage !== 'preview' || f.busy || this._importing) return;
    const c = f.plan.counts;
    if(!c.new || (c.exists + c.duplicate > 0 && f.onConflict === 'refuse') || c.invalid) return;
    if(DEMO_BUILD&&this.model.kind!=='bridge'){ this.notify('info', NEEDS_APP); return; }
    this._importing = true;
    this.setImportForm({ busy: true });
    try{
      const r = await write.runImport(this.model, f.node, f.pairs, f.onConflict);
      const created = (r.created || []);
      const held = created.filter((x) => x.pending).length, saved = created.length - held;
      const node = this.node(f.node), where = node ? node.label : f.node;
      this.setState((st) => ({ dialog: null, importForm: null, fieldErrors: dropErrors(st.fieldErrors, 'import.') }));
      let text, kind = 'success';
      if(r.complete === false){
        const at = r.failed && typeof r.failed.name === 'string' ? ` Stopped at “${r.failed.name}”.` : '';
        text = `Imported ${created.length} of ${r.total} into ${where}.${at} The rest were not written.`; kind = 'warn';
      }else if(held && !saved){
        text = `Held for review: ${where} is locked, so ${many(held, 'entry waits', 'entries wait')} in the tray. Unlock the node, then accept ${held === 1 ? 'it' : 'them'}.`; kind = 'info';
      }else{
        text = `Imported ${many(created.length, 'entry', 'entries')} into ${where}.` + (held ? ` ${held} held for review.` : '');
      }
      const skipped = (r.skipped || []).filter((x) => x.status !== 'empty').length;
      if(skipped) text += ` ${many(skipped, 'name was', 'names were')} skipped.`;
      const warned = write.nameWarningText(r, true);
      if(warned) text += ' ' + warned;
      if(r.readbackError) this.savedButNotRefreshed(r.readbackError, text);
      else this.notify(kind, text);
      if(f.node !== this.state.selected) this.select(f.node); else { this.buildEntryNodes(f.node); this.renderGraph(); }
    }catch(e){
      // A refused call changed nothing (the broker checks every name before it writes): a conflict is said as a notice, the preview stays for another choice.
      this.routeError(e, { op: 'entry.import_env', node: f.node });
      this.setImportForm({ busy: false }, true);
    }finally{
      this._importing = false;
    }
  },

  // ───────────────────────────── what the template reads ─────────────────────────────
  rvNames(c){
    const { s } = c;
    this.scheduleImportWipe();
    this.scheduleAliasWipe();
    const fe = s.fieldErrors || {};

    const af = s.aliasForm, aOpen = s.dialog === 'alias' && !!af;
    const aPlan = this.aliasPlan();
    const aErr = fe['alias.save'] || aPlan.problem || '';
    const aCount = aOpen ? `${aPlan.list.length} of ${ALIASES_MAX}` : '';

    const f = s.importForm, iOpen = s.dialog === 'importEnv' && !!f;
    const stage = iOpen ? f.stage : 'input';
    const plan = iOpen && f.plan ? f.plan : { items: [], counts: { new: 0, exists: 0, duplicate: 0, empty: 0, invalid: 0 } };
    const cnt = plan.counts;
    const conflicts = cnt.exists + cnt.duplicate;
    const blocked = conflicts > 0 && !!f && f.onConflict === 'refuse';
    const imNode = iOpen ? this.node(f.node) : null;
    const rows = plan.items.slice(0, 200).map((it) => ({
      name: it.name, status: it.status, label: STATUS_TEXT[it.status] || it.status, color: STATUS_COLOR[it.status] || 'var(--ash)',
      note: Array.isArray(it.similar) && it.similar.length ? 'looks like ' + it.similar.slice(0, 3).map(nearText).join(', ') : '',
    }));
    const empties = iOpen ? f.skippedEmpty.map((n) => ({ name: n, status: 'empty', label: STATUS_TEXT.empty, color: STATUS_COLOR.empty, note: '' })) : [];
    const sim = s.addSimilar;
    const simShow = !!sim && s.dialog === 'addEntry' && sim.node === s.addNode && sim.name === (s.addName || '').trim();

    return {
      // aliases
      dlgAlias: aOpen,
      anEntry: aOpen ? af.entryName : '',
      anText: aOpen ? af.text : '',
      onAnText: (ev) => this.setAliasForm({ text: ev.target.value }),
      anCount: aCount,
      anErrShow: !!aErr,
      anErr: aErr,
      anSaveDisabled: aPlan.disabled,
      saveAliasForm: () => this.saveAliasForm(),
      cancelAliasDlg: () => this.closeAliasDlg(),

      // the name hint in Add entry
      addSimilarShow: simShow,
      addSimilarText: simShow ? `Looks like ${sim.text}. You can still save it under this name.` : '',

      // the import
      dlgImport: iOpen,
      imIsInput: stage === 'input',
      imIsPreview: stage === 'preview',
      imNode: imNode ? imNode.label : (iOpen ? f.node : ''),
      imText: iOpen ? f.text : '',
      onImText: (ev) => this.setImportForm({ text: ev.target.value }),
      imFile: iOpen ? f.fileName : '',
      imFileShow: iOpen && !!f.fileName,
      onImFile: (ev) => this.importLoadFile(ev),
      imErrShow: !!fe['import.read'],
      imErr: fe['import.read'] || '',
      imPreviewDisabled: !iOpen || f.busy || f.text.trim() === '',
      imPreview: () => this.importPreview(),
      imRows: rows.concat(empties),
      imMore: plan.items.length > 200 ? `+ ${plan.items.length - 200} more` : '',
      imMoreShow: plan.items.length > 200,
      imSummary: `${cnt.new} new${cnt.exists ? `, ${cnt.exists} already there` : ''}${cnt.duplicate ? `, ${cnt.duplicate} repeated in the file` : ''}${empties.length ? `, ${empties.length} empty (skipped)` : ''}${cnt.invalid ? `, ${cnt.invalid} not usable` : ''}`,
      imConflict: conflicts > 0,
      imStopOn: !!f && f.onConflict === 'refuse',
      imSkipOn: !!f && f.onConflict === 'skip',
      onImStop: () => this.setImportForm({ onConflict: 'refuse' }),
      onImSkip: () => this.setImportForm({ onConflict: 'skip' }),
      imBlockedText: blocked ? `${many(conflicts, 'name is', 'names are')} already taken. Choose “skip them” to import the rest, or go back.` : '',
      imBlocked: blocked,
      imRunLabel: cnt.new ? `Import ${many(cnt.new, 'entry', 'entries')}` : 'Nothing to import',
      imRunDisabled: !iOpen || f.busy || !cnt.new || blocked || cnt.invalid > 0,
      imRun: () => this.importRun(),
      imBack: () => this.importBack(),
      cancelImportDlg: () => this.closeImportDlg(),
    };
  },
};
