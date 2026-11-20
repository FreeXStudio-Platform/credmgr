/* The "Tidy up" overlay: the doctor's tidy-up scan, phase 1 (ADR-161: `vault.doctor_scan`).
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   What this file does with the broker, and nothing else:
     vault.doctor_scan   {}   the overlay's Scan button; a read — names, ids and reasons come back, never a value
     vault.doctor_apply  {moves}   ADR-169: "Apply all moves", after a confirm that lists every move; `moves` is the report's own move
                         proposals, sent exactly as the scan carried them (entry, from, to, generation), so what the person confirmed is
                         what the broker checks and what the one Touch ID proof signs
   A finding whose proposal is a move ("Move to <project>") opens the entry inspector's own Move dialog (move.js, ADR-158) with that
   project chosen; the dialog's Move button is the only thing that changes the vault, one entry at a time, with its own second factor
   and Touch ID.  After a move from here the scan runs again, so the list shows what is left.  Nothing of a report is kept: it lives
   in the `tidy` state key and goes when the vault locks.

   ADR-168: a finding about copies (or near-identical names) inside ONE node also offers
     merge.apply     {node, keep, drop, generation}   "Merge": keeps the oldest entry (lowest reference, the broker's own rule), the others'
                                                       names become its aliases; a fresh second factor is asked for by the broker
     merge.dismiss   {node, key}                      "Dismiss": the node remembers the group, and merge suggestions leave it out
   and the scan runs again after either. */

import { admin, errorCode, write } from "../../vault/index";

/** True only in a development or test build, which may run on the in-memory example vault with no broker. Folds to `false` in a release build. */
const DEMO_BUILD = import.meta.env.DEV || import.meta.env.MODE === 'test';
const NEEDS_APP = 'The tidy-up scan needs the CredMgr app: this page has no broker to ask.';
const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;
const pad = (n) => String(n).padStart(2, '0');
const fmtDate = (ts) => { const d = new Date(ts * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`; };

/** The groups, in the broker's order, with the words the overlay uses for each. */
export const TIDY_KINDS = [
  { kind: 'duplicate_value', title: 'Shared values', hint: 'These entries hold the same value.' },
  { kind: 'misfiled', title: 'Misfiled', hint: 'In Global, which every project and agent reads, but named for one project.' },
  { kind: 'similar_names', title: 'Near-identical names', hint: 'One letter or separator apart.' },
  { kind: 'weak', title: 'Weak passwords', hint: 'Short, few kinds of character, or a common pattern.' },
  { kind: 'mistyped', title: 'Mistyped values', hint: 'Stored as something they are not.' },
  { kind: 'expired', title: 'Expired', hint: 'Past their expiry date.' },
  { kind: 'expiring', title: 'Expiring soon', hint: 'Expire within the window.' },
  { kind: 'stale', title: 'Not rotated for a long time', hint: 'Older than the window.' },
];

const REASONS = {
  short: 'short', few_character_kinds: 'few kinds of character', common_pattern: 'a common pattern',
  otpauth_uri: 'a whole otpauth:// link stored as a password; store it as a 2FA code instead',
  live_key_in_test: 'a live key in a test project', test_key_in_live: 'a test key in a live project',
};
const SKIPS = { locked: 'locked', second_factor: 'needs its second factor', not_listed: 'not listed for you' };

/** What one finding says, in words, from the broker's own fields.  Pure. */
export function tidyLine(f){
  const who = (e) => `${e.nodeLabel || e.node} · ${e.name}`;
  const es = (f.entries || []).map(who);
  switch(f.kind){
    case 'duplicate_value': return `${es.join(', ')}${f.match === 'probable' ? ' (equal once spaces and the address’s case are ignored)' : ''}`;
    case 'similar_names': return es.join(' and ');
    case 'weak': return `${es[0]} · ${f.fieldLabel || 'field'}: ${(f.reasons || []).map((r) => REASONS[r] || r).join(', ')}`;
    case 'mistyped': return `${es[0]} · ${f.fieldLabel || 'field'}: ${REASONS[f.reason] || f.reason}`;
    case 'expired': return `${es[0]} · expired ${fmtDate(f.expiresAt)}${f.source === 'jwt' ? ' (the token’s own date)' : ''}`;
    case 'expiring': return `${es[0]} · expires ${fmtDate(f.expiresAt)}${f.source === 'jwt' ? ' (the token’s own date)' : ''}`;
    case 'stale': return `${es[0]} · last ${f.basis === 'rotated' ? 'rotated' : 'changed'} ${fmtDate(f.lastChanged)}`;
    default: return es.join(', ');
  }
}

/**
 * The merge a finding allows (ADR-168), or `null`: a `merge` / `rename_or_merge` proposal whose entries all sit in one node.  `keep` is the
 * oldest entry (the lowest reference), `key` the group's entry ids sorted and joined with `+`, exactly as `merge.suggestions` keys it.  Pure.
 */
export function tidyMergePlan(f){
  const p = (f && f.proposal) || {};
  if(p.action !== 'merge' && p.action !== 'rename_or_merge') return null;
  const es = (f.entries || []).filter((e) => e && typeof e.entry === 'string');
  if(es.length < 2 || es.some((e) => e.node !== es[0].node)) return null;
  const keep = es.slice().sort((a, b) => (a.ref - b.ref) || (a.entry < b.entry ? -1 : 1))[0];
  return {
    node: keep.node,
    keep: keep.entry,
    keepName: keep.name,
    drop: es.filter((e) => e.entry !== keep.entry).map((e) => e.entry),
    key: es.map((e) => e.entry).sort().join('+'),
  };
}

/** What a finding proposes, in words, when it is not a move the app applies.  Pure. */
export function tidyAdvice(f){
  const p = f.proposal || {};
  switch(p.action){
    case 'merge': return 'Keep one entry; give it the other names as aliases.';
    case 'remove_copies': return `The copy in ${p.keep ? p.keep.node : 'the parent'} already reaches the others: remove the rest.`;
    case 'share': return 'In different projects: keep it in one and grant the others, or use a shared project.';
    case 'rename_or_merge': return 'Rename one, or merge them.';
    case 'move_to_parent': return 'Move one copy up, where both projects read it; then remove the other.';
    case 'move_to_project': return 'Move it to the project its name is for.';
    default: return '';
  }
}

/**
 * ADR-169: the plan "Apply all moves" sends — every move proposal of the report, in the report's order, each with the moved entry's
 * name and the two projects' labels for the confirm list.  `move` is the proposal's own `{node, entry, to, generation}`, untouched.  Pure.
 */
export function tidyPlan(report){
  const out = [];
  for(const f of (report && report.findings) || []){
    const p = f.proposal || {};
    if(p.op !== 'entry.move' || !p.move) continue;
    const en = (f.entries || []).find((e) => e.entry === p.move.entry && e.node === p.move.node);
    out.push({ move: { node: p.move.node, entry: p.move.entry, to: p.move.to, generation: p.move.generation },
      name: en ? en.name : p.move.entry, fromLabel: en && en.nodeLabel ? en.nodeLabel : p.move.node, toLabel: p.toLabel || p.move.to });
  }
  return out;
}

/** The message after a plan was applied, from the broker's answer.  Pure. */
export function tidyAppliedText(plan, r){
  const n = Array.isArray(r && r.applied) ? r.applied.length : 0;
  if(r && r.complete) return `Moved ${plural(n, 'entry', 'entries')} as planned.`;
  const at = r && r.stopped ? r.stopped.index : n;
  const name = plan[at] ? `“${plan[at].name}”` : 'the next entry';
  const left = r && typeof r.notApplied === 'number' ? r.notApplied : plan.length - n;
  return `Moved ${plural(n, 'entry', 'entries')}, then stopped at ${name}${r && r.stopped && r.stopped.code ? ` (${r.stopped.code})` : ''}: ${left} ${left === 1 ? 'move was' : 'moves were'} not made. The moves made stand; the list is read again.`;
}

export const tidyMethods = {
  openTidy(){
    this.setState({ overlay: 'tidy' });
    if(!this.state.tidy || this.state.tidy.state !== 'ready') this.runTidy();
  },
  /** One broker read.  A refusal is routed like any other (the owner's login only; an agent never reaches this screen). */
  async runTidy(){
    if(this._tidyBusy) return;
    if(DEMO_BUILD && this.model.kind !== 'bridge'){ this.setState({ tidy: { state: 'error', report: null, error: NEEDS_APP } }); return; }
    this._tidyBusy = true;
    this.setState((st) => ({ tidy: { ...(st.tidy || {}), state: 'loading', error: '' } }));
    try{
      const report = await admin.doctorScan();
      this.setState({ tidy: { state: 'ready', report, error: '' } });
    }catch(e){
      const code = errorCode(e);
      this.routeError(e, { op: 'vault.doctor_scan', inlineRendered: true });
      const error = code === 'rate_limited' ? 'A scan is already running. Try again in a few seconds.' : 'The scan could not run' + (code ? ` (${code})` : '') + '. Nothing was changed.';
      this.setState({ tidy: { state: 'error', report: null, error } });
    }finally{
      this._tidyBusy = false;
    }
  },
  /** "Merge" (ADR-168): one `merge.apply`; a refusal (a missing second factor among them) is routed like any write; the scan runs again. */
  async tidyMerge(f){
    const plan = tidyMergePlan(f);
    if(!plan || this._tidyActBusy) return;
    this._tidyActBusy = true;
    this.setState({ tidyActErr: '' });
    try{
      await write.mergeApply(this.model, plan.node, plan.keep, plan.drop);
      this._tidyActBusy = false;
      this.runTidy();
    }catch(e){
      const code = errorCode(e);
      this.routeError(e, { op: 'merge.apply', node: plan.node, inlineRendered: true });
      const text = code === 'two_factor_required' ? 'Merging needs your second factor: give a code, then press Merge again. Nothing was changed.'
        : code === 'conflict' ? 'The project changed since the scan; scan again. Nothing was changed.'
        : 'The merge could not run' + (code ? ` (${code})` : '') + '. Nothing was changed.';
      this.setState({ tidyActErr: text });
    }finally{
      this._tidyActBusy = false;
    }
  },
  /** "Dismiss" (ADR-168): one `merge.dismiss`, so merge suggestions leave this group out; the scan runs again. */
  async tidyDismiss(f){
    const plan = tidyMergePlan(f);
    if(!plan || this._tidyActBusy) return;
    this._tidyActBusy = true;
    this.setState({ tidyActErr: '' });
    try{
      await write.mergeDismiss(this.model, plan.node, plan.key);
      this._tidyActBusy = false;
      this.runTidy();
    }catch(e){
      const code = errorCode(e);
      this.routeError(e, { op: 'merge.dismiss', node: plan.node, inlineRendered: true });
      this.setState({ tidyActErr: 'The suggestion could not be dismissed' + (code ? ` (${code})` : '') + '.' });
    }finally{
      this._tidyActBusy = false;
    }
  },
  /** "Move to <project>": the inspector's Move dialog, the proposal's destination chosen; the scan runs again after the move. */
  tidyMove(f){
    const m = f && f.proposal && f.proposal.op === 'entry.move' ? f.proposal.move : null;
    if(!m) return;
    const en = (f.entries || []).find((e) => e.entry === m.entry && e.node === m.node);
    if(!en) return;
    this.openMoveDlg(m.node, { id: m.entry, name: en.name }, { to: m.to, origin: 'tidy' });
  },

  /** ADR-169: "Apply all moves" opens the confirm list; nothing is sent until its Apply button. */
  openTidyApply(){
    const t = this.state.tidy;
    if(!t || t.state !== 'ready' || !tidyPlan(t.report).length) return;
    this.setState((st) => ({ tidy: { ...st.tidy, apply: { open: true, busy: false, error: '' } } }));
  },
  cancelTidyApply(){
    this.setState((st) => (st.tidy ? { tidy: { ...st.tidy, apply: null } } : null));
  },
  /**
   * One broker call with the plan the confirm list showed.  Only that call is inside the try: once the broker has moved anything, nothing
   * after it may read as "Nothing was moved".  A refusal before any move is said in the confirm list; after the call the scan runs again.
   */
  async applyTidyPlan(){
    const t = this.state.tidy;
    if(!t || t.state !== 'ready' || !t.apply || t.apply.busy || this._tidyApplying) return;
    const plan = tidyPlan(t.report);
    if(!plan.length) return;
    if(DEMO_BUILD && this.model.kind !== 'bridge'){ this.notify('info', NEEDS_APP); return; }
    this._tidyApplying = true;
    this.setState((st) => ({ tidy: { ...st.tidy, apply: { ...st.tidy.apply, busy: true, error: '' } } }));
    let r;
    try{
      r = await write.applyDoctorPlan(this.model, plan.map((p) => p.move));
    }catch(e){
      const code = errorCode(e);
      this.routeError(e, { op: 'vault.doctor_apply', inlineRendered: true });
      const error = code === 'conflict' || code === 'not_found'
        ? 'The vault changed since this scan. Scan again, then apply. Nothing was moved.'
        : code === 'entry_exists'
          ? 'One of these moves would give a project two entries with the same name. Rename one first. Nothing was moved.'
          : 'The moves could not be applied' + (code ? ` (${code})` : '') + '. Nothing was moved.';
      this.setState((st) => (st.tidy ? { tidy: { ...st.tidy, apply: { open: true, busy: false, error } } } : null));
      return;
    }finally{
      this._tidyApplying = false;
    }
    this.setState((st) => (st.tidy ? { tidy: { ...st.tidy, apply: null } } : null));
    const text = tidyAppliedText(plan, r);
    if(r.readbackError) this.savedButNotRefreshed(r.readbackError, text);
    else this.notify(r.complete ? 'success' : 'warn', text);
    this.runTidy();
  },

  rvTidy(c){
    const { s } = c;
    const t = s.tidy || null;
    const open = s.overlay === 'tidy';
    const r = t && t.state === 'ready' ? t.report : null;
    const groups = !open || !r ? [] : TIDY_KINDS.map((k) => {
      const rows = (r.findings || []).filter((f) => f.kind === k.kind).map((f, i) => {
        const p = f.proposal || {};
        const canMove = p.op === 'entry.move' && !!p.move;
        const merge = tidyMergePlan(f);
        return {
          key: `${k.kind}-${i}`,
          text: tidyLine(f),
          advice: canMove ? '' : tidyAdvice(f),
          adviceShow: !canMove && !!tidyAdvice(f),
          moveShow: canMove,
          moveLabel: canMove ? `Move to ${p.toLabel || p.to}` : '',
          move: () => this.tidyMove(f),
          mergeShow: !!merge,
          mergeLabel: merge ? `Merge into ${merge.keepName}` : '',
          merge: () => this.tidyMerge(f),
          dismiss: () => this.tidyDismiss(f),
        };
      });
      return { kind: k.kind, title: `${k.title} · ${rows.length}`, hint: k.hint, rows, show: rows.length > 0 };
    }).filter((g) => g.show);
    const skipped = r ? (r.skipped || []).map((x) => ({ text: `${x.nodeLabel || x.node}: ${x.what === 'values' ? 'values not compared' : 'not read'} (${SKIPS[x.reason] || x.reason})` })) : [];
    const plan = r ? tidyPlan(r) : [];
    const apply = t && t.apply ? t.apply : null;
    const summary = r
      ? `${plural(r.entriesScanned, 'entry', 'entries')} in ${plural(r.nodesScanned, 'project')}, ${plural(r.valuesChecked, 'value')} compared · ${plural((r.findings || []).length, 'finding')}`
      : '';
    return {
      ovTidy: open,
      openTidy: () => this.openTidy(),
      tidyRescan: () => this.runTidy(),
      tidyBusy: !!(t && t.state === 'loading'),
      tidyScanLabel: t && t.state === 'loading' ? 'Scanning…' : (r ? 'Scan again' : 'Scan'),
      tidySummary: summary,
      tidySummaryShow: !!r,
      tidyEmpty: !!r && groups.length === 0,
      tidyGroups: groups,
      tidySkipped: skipped,
      tidySkippedShow: skipped.length > 0,
      tidyTruncated: !!(r && r.truncated),
      tidyActErrShow: !!s.tidyActErr,
      tidyActErr: s.tidyActErr || '',
      tidyErrShow: !!(t && t.state === 'error'),
      tidyErr: t && t.state === 'error' ? t.error : '',
      // ADR-169: apply every move of the plan, after a confirm that lists each one.
      tidyApplyShow: open && plan.length > 0,
      tidyApplyLabel: `Apply all moves (${plan.length})`,
      openTidyApply: () => this.openTidyApply(),
      tidyApplyOpen: open && !!(apply && apply.open) && plan.length > 0,
      tidyApplyRows: plan.map((p, i) => ({ key: `${p.move.node}-${p.move.entry}`, text: `${i + 1}. ${p.name}: ${p.fromLabel} → ${p.toLabel}` })),
      tidyApplyTitle: `Apply ${plural(plan.length, 'move')}?`,
      tidyApplyBusy: !!(apply && apply.busy),
      tidyApplyGo: () => this.applyTidyPlan(),
      tidyApplyGoLabel: apply && apply.busy ? 'Moving…' : `Apply ${plural(plan.length, 'move')}`,
      tidyApplyCancel: () => this.cancelTidyApply(),
      tidyApplyErrShow: !!(apply && apply.error),
      tidyApplyErr: apply && apply.error ? apply.error : '',
    };
  },
};
