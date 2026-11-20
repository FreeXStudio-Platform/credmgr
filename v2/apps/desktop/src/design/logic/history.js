/* An entry's expiry chip and dialog, and its History tab (ADR-157: the desktop half of ADR-156's quick wins 3 and 4).
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   What this file does with the broker, and nothing else:
     entry.set_expiry   {node, entry, generation, expiresAt | clear}   the dialog's Save / Remove expiry; manifest metadata only, no value
     entry.history      {node, entry, limit}                            the History tab: audit actions and times, never a value
   The chip itself reads the entry's own detail (`entry.get` already answers `expiresAt`), so it costs no call of its own.

   A date is a calendar day, read and shown in UTC, exactly as the command line reads `credmgr expire --at YYYY-MM-DD` (the start of that
   day in UTC; crates/cli/src/quick_cmds.rs parse_at), so the app and the CLI agree on what a date means. */

import { errorCode, read, write } from "../../vault/index";

/** True only in a development or test build, which may run on the in-memory example vault with no broker. Folds to `false` in a release build. */
const DEMO_BUILD = import.meta.env.DEV || import.meta.env.MODE === 'test';
const NEEDS_APP = 'This needs the CredMgr app: this page has no broker to write to. Nothing was changed.';
const DAY = 86400;
/** The chip turns amber this many days before the date (the broker's own `entry.expiring` window, 30 days). */
export const SOON_DAYS = 30;
/** How many records the History tab asks for (the broker keeps the newest `limit`, and says when it cut). */
export const HISTORY_LIMIT = 200;
/** The broker's own bound on `expiresAt` (quick_ops.rs EXPIRY_MAX: the last second of 9999). */
const EXPIRY_MAX = 253402300799;

const pad = (n) => String(n).padStart(2, '0');
/** Unix seconds as `YYYY-MM-DD` in UTC (what the CLI prints). */
export const utcDay = (secs) => { const d = new Date(secs * 1000); return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`; };
/** Unix seconds as `YYYY-MM-DD HH:MM` in local time (the audit view's format). */
const localTime = (secs) => { const d = new Date(secs * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`; };
/** `YYYY-MM-DD` as unix seconds at the start of that day in UTC, or `null` when it is not a real calendar date. */
export const parseDay = (text) => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(text || '').trim());
  if(!m) return null;
  const y = +m[1], mo = +m[2], d = +m[3];
  const ms = Date.UTC(y, mo - 1, d);
  const back = new Date(ms);
  if(back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d) return null;
  const secs = Math.floor(ms / 1000);
  return secs >= 0 && secs <= EXPIRY_MAX ? secs : null;
};
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

/**
 * What the chip says about `expiresAt` at `nowSecs`: `null` when the entry has no expiry.  `tone` is `expired`, `soon` (within
 * {@link SOON_DAYS}) or `later`.  Whole days, counted between UTC calendar days, so the chip and `credmgr expiring` agree.
 */
export function expiryChip(expiresAt, nowSecs){
  if(typeof expiresAt !== 'number' || !isFinite(expiresAt)) return null;
  const days = Math.floor(expiresAt / DAY) - Math.floor(nowSecs / DAY);
  const day = utcDay(expiresAt);
  if(expiresAt <= nowSecs){
    const ago = -days;
    return { tone: 'expired', text: ago <= 0 ? `expired today · ${day}` : `expired ${day} · ${plural(ago, 'day', 'days')} ago` };
  }
  if(days <= SOON_DAYS) return { tone: 'soon', text: days <= 0 ? `expires today · ${day}` : `expires ${day} · in ${plural(days, 'day', 'days')}` };
  return { tone: 'later', text: `expires ${day}` };
}

/** The audit actions an entry's trail carries, in plain words.  Anything else is shown as the broker named it. */
const ACTION_TEXT = {
  'entry.create': 'created', 'entry.create_batch': 'created', 'entry.import_env': 'imported from .env', 'entry.update': 'value changed',
  'entry.rotate': 'rotated', 'entry.remove': 'removed', 'entry.restore': 'restored', 'entry.undo': 'change undone', 'entry.rename': 'renamed',
  'entry.reveal': 'revealed', 'entry.copy': 'copied', 'entry.get': 'opened', 'entry.alias': 'aliases changed', 'entry.set_expiry': 'expiry changed',
  'entry.move': 'moved', 'field.add': 'field added', 'field.update': 'field changed', 'field.remove': 'field removed', 'field.reorder': 'fields reordered',
  'totp.code': 'code shown', 'totp.seed': 'seed shown', 'vault.approval_decide': 'agent request decided', 'vault.pending_accept': 'accepted from the tray',
};
export const actionText = (a) => ACTION_TEXT[a] || a;
/** The broker's actor: `human` is the owner's own login; anything else (an agent's public session id) is shown as it came. */
const actorText = (a) => (a === 'human' ? 'you' : a === 'redacted' || !a ? 'someone (not recorded)' : a);
const decisionText = (d) => (d === 'allow' || !d ? '' : d === 'deny' ? 'refused' : d);

/** Failures that are the app's to show (the Lock screen, a locked node, the broker-down screen, the 2FA prompt), not the History tab's. */
const APP_LEVEL = new Set(['vault_locked', 'session_expired', 'node_locked', 'two_factor_required', 'broker_unreachable']);
const keyOf = (node, entry) => node + '\u0000' + entry;
const dropErrors = (fe, prefix) => { const out = {}; for (const k in (fe || {})) if (!k.startsWith(prefix)) out[k] = fe[k]; return out; };

export const historyMethods = {
  // ───────────────────────── tabs ─────────────────────────
  /** Switch the open entry's detail between its fields and its history.  The tab belongs to that entry: another entry opens on Fields. */
  setEntryTab(node, entry, tab){
    this.setState({ entryTab: { key: keyOf(node, entry), tab }, fieldMenu: null });
    if(tab === 'history') this.loadHistory(node, entry, false);
  },
  /**
   * Read the trail of one entry.  Never twice at once for the same entry; `force` reads again even when an answer is held (the Refresh
   * button, and after a change made from this detail).  A failure is kept by code so the tab can say so and offer a retry.
   */
  async loadHistory(node, entry, force){
    const key = keyOf(node, entry);
    const cur = this.state.historyView;
    if(cur && cur.key === key && (cur.loading || (!force && (cur.data || cur.err)))) return;
    this.setState({ historyView: { key, loading: true, data: null, err: null } });
    try{
      const data = await read.entryHistory(this.model, node, entry, HISTORY_LIMIT);
      this.setState((st) => (st.historyView && st.historyView.key === key ? { historyView: { key, loading: false, data, err: null } } : null));
    }catch(e){
      const code = errorCode(e) || 'internal';
      this.setState((st) => (st.historyView && st.historyView.key === key ? { historyView: { key, loading: false, data: null, err: code } } : null));
      // A lost login or a stopped broker is the app's business (the Lock screen, the broker-down screen), not the tab's.
      if(APP_LEVEL.has(code)) this.routeError(e, { op: 'entry.history', node, entry });
    }
  },

  // ───────────────────────── the expiry dialog ─────────────────────────
  openExpiryDlg(node, en, detail){
    const orig = detail && typeof detail.expiresAt === 'number' ? detail.expiresAt : null;
    this.setState((st) => ({ dialog: 'expiry', fieldMenu: null, ctx: null, fieldErrors: dropErrors(st.fieldErrors, 'expiry.'),
      expiryForm: { node, entry: en.id, entryName: en.name, date: orig === null ? '' : utcDay(orig), orig, busy: false } }));
  },
  closeExpiryDlg(){ this.setState((st) => ({ dialog: null, expiryForm: null, fieldErrors: dropErrors(st.fieldErrors, 'expiry.') })); },
  setExpiryForm(patch, keepErrors){
    this.setState((st) => (st.expiryForm ? { expiryForm: { ...st.expiryForm, ...patch }, ...(keepErrors ? {} : { fieldErrors: dropErrors(st.fieldErrors, 'expiry.') }) } : null));
  },
  /** A preset: today plus `days`, as a calendar day. */
  expiryIn(days){ this.setExpiryForm({ date: utcDay(Math.floor(Date.now() / 1000) + days * DAY) }); },
  /** What Save would send, and whether it can be sent.  Pure: reads state, writes nothing. */
  expiryPlan(){
    const f = this.state.expiryForm;
    if(!f) return { disabled: true, at: null, problem: '', past: false };
    const text = (f.date || '').trim();
    if(!text) return { disabled: true, at: null, problem: '', past: false };
    const at = parseDay(text);
    if(at === null) return { disabled: true, at: null, problem: 'Give a date as YYYY-MM-DD, between 1970 and 9999.', past: false };
    return { disabled: !!f.busy || at === f.orig, at, problem: '', past: at <= Math.floor(Date.now() / 1000) };
  },
  /** Save (`at` a date) or Remove expiry (`at` null).  One broker call; the chip then shows what the broker stored. */
  async saveExpiry(clear){
    const f = this.state.expiryForm;
    if(!f || this._savingExpiry) return;
    const plan = this.expiryPlan();
    if(!clear && plan.disabled) return;
    if(clear && f.orig === null) return;
    if(DEMO_BUILD && this.model.kind !== 'bridge'){ this.notify('info', NEEDS_APP); return; }
    this._savingExpiry = true;
    this.setExpiryForm({ busy: true });
    try{
      const at = clear ? null : plan.at;
      const r = await write.setExpiry(this.model, f.node, f.entry, at);
      this.setState((st) => ({ dialog: null, expiryForm: null, fieldErrors: dropErrors(st.fieldErrors, 'expiry.') }));
      const text = at === null ? `“${f.entryName}” no longer expires.` : `“${f.entryName}” expires on ${utcDay(at)} (UTC).`;
      if(r.readbackError) this.savedButNotRefreshed(r.readbackError, text);
      else this.notify('success', text);
      // The trail now has one more record: an open History tab of this entry reads it again.
      const hv = this.state.historyView;
      if(hv && hv.key === keyOf(f.node, f.entry)) this.loadHistory(f.node, f.entry, true);
    }catch(e){
      // A refused call changed nothing.  A stale generation re-reads the entry (routeError) and keeps the form for a retry.
      const route = this.routeError(e, { op: 'entry.set_expiry', node: f.node, entry: f.entry, field: 'expiry.save', inlineRendered: true });
      if(route && route.route === 'refresh' && errorCode(e) === 'not_found') this.closeExpiryDlg();
      else this.setExpiryForm({ busy: false }, true);
    }finally{
      this._savingExpiry = false;
    }
  },

  rvHistory(c){
    const { s, sel, v } = c;
    const nodeId = s.selected && s.selected !== '__orphan' && sel ? sel.id : null;
    const entryId = nodeId && s.openEntry ? s.openEntry : null;
    const key = entryId ? keyOf(nodeId, entryId) : null;
    const detail = key ? this.model.detail(nodeId, entryId) : undefined;
    const en = entryId ? (((v.entries || {})[nodeId] || []).find((x) => x.id === entryId) || null) : null;
    const usable = !!(detail && en && !sel.gate.locked);
    const nowSecs = Math.floor(Date.now() / 1000);

    // the chip
    const chip = usable ? expiryChip(detail.expiresAt, nowSecs) : null;
    const tone = chip ? chip.tone : 'none';

    // the tabs
    const onHistory = !!key && !!s.entryTab && s.entryTab.key === key && s.entryTab.tab === 'history';
    const hv = s.historyView && s.historyView.key === key ? s.historyView : null;
    if(onHistory && !hv && usable) setTimeout(() => this.loadHistory(nodeId, entryId, false), 0); // never start a request from inside a render
    const data = hv && hv.data ? hv.data : null;
    const records = data && Array.isArray(data.records) ? data.records.slice().reverse() : [];
    const histRows = records.map((r) => ({
      id: r.id, when: localTime(r.timestamp), what: actionText(r.action), raw: r.action, who: actorText(r.actor),
      outcome: decisionText(r.decision), outcomeShow: decisionText(r.decision) !== '',
    }));
    const times = data && data.exists ? [
      `last changed ${typeof data.modified === 'number' && data.modified > 0 ? localTime(data.modified) : '—'}`,
      `rotated ${typeof data.rotatedAt === 'number' ? localTime(data.rotatedAt) : 'never'}`,
      `expires ${typeof data.expiresAt === 'number' ? utcDay(data.expiresAt) + ' (UTC)' : 'never'}`,
    ].join(' · ') : '';
    const errText = !hv || !hv.err ? '' : hv.err === 'not_found' ? 'This entry no longer exists.'
      : hv.err === 'capability_not_held' || hv.err === 'node_access_denied' ? 'This login may not read this entry’s history.'
      : 'The history of this entry could not be read.';

    // the dialog
    const f = s.expiryForm, open = s.dialog === 'expiry' && !!f;
    const plan = this.expiryPlan();
    const err = open ? ((s.fieldErrors || {})['expiry.save'] || plan.problem) : '';

    return {
      expiryChipShow: !!chip,
      expiryChipText: chip ? chip.text : '',
      expiryChipTone: tone,
      expiryChipColor: tone === 'expired' ? 'var(--danger-fg)' : tone === 'soon' ? 'var(--warn-fg, var(--bone))' : 'var(--ash)',
      expiryChipBorder: tone === 'expired' ? 'var(--danger)' : tone === 'soon' ? 'var(--bone)' : 'var(--hair-strong)',
      expiryBtnShow: usable,
      expiryBtnLabel: chip ? 'Change expiry…' : 'Set expiry…',
      expiryOpen: () => { if(usable) this.openExpiryDlg(nodeId, en, detail); },

      entryTabsShow: usable,
      entryTabFields: !onHistory,
      entryTabHistory: onHistory,
      entryTabFieldsSel: onHistory ? 'false' : 'true',
      entryTabHistorySel: onHistory ? 'true' : 'false',
      entryTabFieldsLine: onHistory ? 'transparent' : 'var(--bone)',
      entryTabHistoryLine: onHistory ? 'var(--bone)' : 'transparent',
      entryTabToFields: () => { if(key) this.setEntryTab(nodeId, entryId, 'fields'); },
      entryTabToHistory: () => { if(key) this.setEntryTab(nodeId, entryId, 'history'); },

      histLoading: onHistory && (!hv || hv.loading),
      histFailed: onHistory && !!hv && !hv.loading && !!hv.err,
      histFailedText: errText,
      histRetry: () => { if(key) this.loadHistory(nodeId, entryId, true); },
      histShow: onHistory && !!data,
      histRows,
      histEmpty: onHistory && !!data && !histRows.length,
      histTimes: times,
      histTimesShow: !!times,
      histNote: data ? (data.truncated ? `Newest ${records.length} records shown, newest first. Older ones are in the full audit view.` : `${records.length === 1 ? '1 record' : records.length + ' records'}, newest first.`) : '',
      histGoneShow: !!data && data.exists === false,
      histRefresh: () => { if(key) this.loadHistory(nodeId, entryId, true); },

      dlgExpiry: open,
      exEntry: open ? f.entryName : '',
      exDate: open ? f.date : '',
      onExDate: (ev) => this.setExpiryForm({ date: ev.target.value }),
      exIn30: () => this.expiryIn(30),
      exIn90: () => this.expiryIn(90),
      exIn365: () => this.expiryIn(365),
      exCurrent: open ? (f.orig === null ? 'No expiry is set.' : `Now: ${utcDay(f.orig)} (UTC).`) : '',
      exPastShow: open && plan.past && !plan.problem,
      exErrShow: !!err,
      exErr: err,
      exSaveDisabled: plan.disabled,
      exClearShow: open && f.orig !== null,
      exClearDisabled: !open || !!f.busy,
      saveExpiryForm: () => this.saveExpiry(false),
      clearExpiryForm: () => this.saveExpiry(true),
      cancelExpiryDlg: () => this.closeExpiryDlg(),
    };
  },
};
