/* Restore from a backup (ADR-166): Settings › Backup › Restore…, and the same dialog on the broker-unreachable screen.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   What this file sends, and nothing else:
     backup_restore   {archive, passphrase, target?}   the shell's own command: it runs the bundled `credmgr restore --json`, so the app and
                                                       the terminal share one restore and one set of refusals.  No broker op, no audit record.
   A restore refuses while a broker answers on the vault's socket (`broker_running`), and a broker is always running while this window is
   unlocked: the dialog says so before the press, and the refusal says what to do (quit CredMgr, then `credmgr restore` in a terminal).
   On the broker-unreachable screen no broker is running, so the restore can go through there.

   The backup passphrase lives in this component's state only while the dialog is open (scheduleRestoreWipe); it is never put in a notice. */

import { admin } from "../../vault/index";

const dropErrors = (fe, prefix) => { const out = {}; for (const k in (fe || {})) if (!k.startsWith(prefix)) out[k] = fe[k]; return out; };
const blank = { archive: '', target: '', passphrase: '', busy: false, done: null };

/** The lines a finished restore shows: what was written, the counter, and what to do next.  Pure. */
export function restoredLines(r){
  const lines = [`${r.files} file${r.files === 1 ? '' : 's'} restored into ${r.target}.`];
  if(r.counter === 'restored') lines.push(`The generation counter was restored into ${r.stateDir}.`);
  else if(r.counter === 'keptExisting') lines.push(`${r.stateDir} already had a generation counter and it was kept. If it is ahead of this backup, the vault will refuse to open as rolled back.`);
  // ADR-148 amendment: a backup carries a restore ticket, not the counter; the restore left a one-time marker.
  else if(r.counter === 'acceptMarker') lines.push(`${r.stateDir} had no generation counter: a one-time restore marker there lets the first unlock of this restored vault set one.`);
  else lines.push('The backup carries neither a generation counter nor a restore ticket: the broker opens it only when started once with CREDMGR_ACCEPT_MISSING_ROLLBACK_COUNTER=1.');
  if(!r.complete) lines.push('This backup predates the complete format: notes, sealed nodes, removed entries and earlier values are not in it.');
  lines.push('Start the broker on that folder, unlock with your vault passphrase, then run Verify.');
  return lines;
}

export const restoreMethods = {
  openRestoreDlg(){
    this.setState((st) => ({ dialog: 'restoreBackup', restoreForm: { ...blank }, fieldErrors: dropErrors(st.fieldErrors, 'restore.') }));
  },
  closeRestoreDlg(){ this.setState((st) => ({ dialog: null, restoreForm: null, fieldErrors: dropErrors(st.fieldErrors, 'restore.') })); },
  setRestoreForm(patch, keepErrors){
    this.setState((st) => (st.restoreForm ? { restoreForm: { ...st.restoreForm, ...patch }, ...(keepErrors ? {} : { fieldErrors: dropErrors(st.fieldErrors, 'restore.') }) } : null));
  },
  /** The passphrase must not outlive its dialog: any way of closing it (Cancel, Escape, the scrim, a lock) leaves no form behind. */
  scheduleRestoreWipe(){
    if(this._restoreWipeQueued || this.state.dialog === 'restoreBackup' || !this.state.restoreForm) return;
    this._restoreWipeQueued = true;
    queueMicrotask(() => { this._restoreWipeQueued = false; if(this._mounted && this.state.dialog !== 'restoreBackup' && this.state.restoreForm) this.setState({ restoreForm: null }); });
  },
  async saveRestore(){
    const f = this.state.restoreForm;
    if(!f || f.busy || !f.archive.trim() || !f.passphrase || this._restoringBackup) return;
    this._restoringBackup = true;
    this.setRestoreForm({ busy: true }, true);
    try{
      const r = await admin.restoreBackup(f.archive.trim(), f.passphrase, f.target.trim() || undefined);
      // Done: the passphrase goes; what was written stays on screen until the dialog is closed.
      this.setRestoreForm({ busy: false, passphrase: '', done: r }, true);
      this.notify('success', `Backup restored: ${r.files} file${r.files === 1 ? '' : 's'} written.`);
    }catch(e){
      this.routeError(e, { op: 'backup.restore', field: 'restore.save', inlineRendered: true });
      this.setRestoreForm({ busy: false }, true);
    }finally{
      this._restoringBackup = false;
    }
  },

  rvRestore(c){
    const { s } = c;
    this.scheduleRestoreWipe();
    const f = s.restoreForm, open = s.dialog === 'restoreBackup' && !!f;
    const g = open ? f : blank;
    const err = open ? ((s.fieldErrors || {})['restore.save'] || '') : '';
    const live = this.model.status === 'unlocked' || this.model.status === 'locked';
    return {
      openRestore: () => this.openRestoreDlg(),
      dlgRestore: open,
      rsArchive: g.archive,
      onRsArchive: (ev) => this.setRestoreForm({ archive: ev.target.value }),
      rsTarget: g.target,
      onRsTarget: (ev) => this.setRestoreForm({ target: ev.target.value }),
      rsPass: g.passphrase,
      onRsPass: (ev) => this.setRestoreForm({ passphrase: ev.target.value }),
      rsLiveShow: open && live && !g.done,
      rsErrShow: !!err,
      rsErr: err,
      rsFormShow: open && !g.done,
      rsDoneShow: open && !!g.done,
      rsDoneLines: g.done ? restoredLines(g.done).map((text) => ({ text })) : [],
      rsSaveDisabled: !open || !!g.busy || !g.archive.trim() || !g.passphrase,
      rsSaveLabel: open && g.busy ? 'Restoring…' : 'Restore',
      saveRestoreForm: () => this.saveRestore(),
      cancelRestoreDlg: () => this.closeRestoreDlg(),
      rsCloseLabel: open && g.done ? 'Close' : 'Cancel',
    };
  },
};
