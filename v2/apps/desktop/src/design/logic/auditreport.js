/* Settings › Audit report (rc.2 §1 item 3): a summary of the audit log for a time range and, optionally, one node.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   What this file does with the broker, and nothing else:
     audit.report   {from, to, node?}   counts by action, by actor (public session ids, never a token) and by node, the denials with their
                                        reasons, presence uses and whether the hash chain verified.  No value and no entry name is in it.
   The owner's login only; the broker allows at most 366 days.  A range is either the last N days or two calendar dates read in UTC (the
   start of `from`'s day to the end of `to`'s), as `credmgr audit report --from/--to` reads them. */

import { read } from "../../vault/index";
import { parseDay, utcDay } from "./history.js";

const DAY = 86400;
/** The ranges offered, in days. */
export const REPORT_RANGES = [1, 7, 30, 90, 366];
const pad = (n) => String(n).padStart(2, '0');
const localTime = (secs) => { const d = new Date(secs * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`; };

/**
 * `[from, to)` in unix seconds for the form, or `{error}` in words.  `range` is a number of days back from `nowSecs`, or `'dates'` for the two
 * calendar days `fromDay` and `toDay` (both inclusive, UTC).  Pure.
 */
export function reportWindow(form, nowSecs){
  if(form.range !== 'dates'){
    const days = Number(form.range);
    if(!REPORT_RANGES.includes(days)) return { error: 'Choose a range.' };
    return { from: nowSecs - days * DAY, to: nowSecs + 1 };
  }
  const from = parseDay(form.fromDay), last = parseDay(form.toDay);
  if(from === null || last === null) return { error: 'Type both dates as YYYY-MM-DD.' };
  if(last < from) return { error: 'The end date is before the start date.' };
  const to = last + DAY;
  if(to - from > 366 * DAY) return { error: 'A report covers at most 366 days.' };
  return { from, to };
}

const blank = (nowSecs) => ({ range: '30', fromDay: utcDay(nowSecs - 30 * DAY), toDay: utcDay(nowSecs), node: '', busy: false, report: null, err: '' });

export const auditReportMethods = {
  auditReportForm(){ return this.state.auditReport || blank(Math.floor(Date.now() / 1000)); },
  setAuditReport(patch){ this.setState((st) => ({ auditReport: { ...(st.auditReport || blank(Math.floor(Date.now() / 1000))), ...patch } })); },
  async runAuditReport(){
    const f = this.auditReportForm();
    if(f.busy || this._reporting) return;
    const w = reportWindow(f, Math.floor(Date.now() / 1000));
    if(w.error){ this.setAuditReport({ err: w.error }); return; }
    this._reporting = true;
    this.setAuditReport({ busy: true, err: '' });
    try{
      const report = await read.auditReport(this.model, w.from, w.to, f.node || undefined);
      this.setAuditReport({ busy: false, report });
    }catch(e){
      this.setAuditReport({ busy: false, report: null, err: 'The report could not be made.' });
      this.routeError(e, { op: 'audit.report' });
    }finally{
      this._reporting = false;
    }
  },

  rvAuditReport(c){
    const { s, v } = c;
    const f = this.auditReportForm();
    const r = f.report;
    const nodeName = (id) => (id ? this.labelOf(id) : 'vault');
    const rangeOpts = REPORT_RANGES.map((d) => ({ value: String(d), label: d === 1 ? 'the last 24 hours' : `the last ${d} days` })).concat([{ value: 'dates', label: 'between two dates (UTC)' }]);
    const nodeOpts = [{ id: '', label: 'every node' }].concat((v.nodes || []).map((n) => ({ id: n.id, label: n.label })));
    const row = (x, key) => ({ name: key, count: String(x.count), allow: String(x.allow), deny: String(x.deny), denyColor: x.deny ? 'var(--danger-fg)' : 'var(--mute)' });
    return {
      setReport: !!c.isPro && s.setSection === 'report',
      arRange: f.range,
      arRangeOpts: rangeOpts,
      onArRange: (ev) => this.setAuditReport({ range: ev.target.value, err: '' }),
      arDatesShow: f.range === 'dates',
      arFrom: f.fromDay,
      onArFrom: (ev) => this.setAuditReport({ fromDay: ev.target.value, err: '' }),
      arTo: f.toDay,
      onArTo: (ev) => this.setAuditReport({ toDay: ev.target.value, err: '' }),
      arNode: f.node,
      arNodeOpts: nodeOpts,
      onArNode: (ev) => this.setAuditReport({ node: ev.target.value, err: '' }),
      arRun: () => this.runAuditReport(),
      arRunDisabled: !!f.busy,
      arRunLabel: f.busy ? 'Reading…' : 'Make report',
      arErrShow: !!f.err,
      arErr: f.err,
      arShow: !!r,
      arSummary: r ? `${r.records} record${r.records === 1 ? '' : 's'} from ${localTime(r.from)} to ${localTime(r.to)}${r.node ? ` · ${nodeName(r.node)} only` : ''} · ${r.decisions.allow} allowed, ${r.decisions.deny} refused${r.decisions.other ? `, ${r.decisions.other} other` : ''}` : '',
      arChain: r ? (r.chain.verified ? `The audit log's hash chain verified${r.chain.months.length ? ` (${r.chain.months.join(', ')})` : ''}.` : 'The audit log’s hash chain did not verify when this report was read (a record written at that moment can do this). Make the report again; if it still does not verify, run Verify and keep a copy of the vault folder as it is.') : '',
      arChainColor: r && !r.chain.verified ? 'var(--danger-fg)' : 'var(--ash)',
      arPresence: r ? `Touch ID: used ${r.presence.uses} time${r.presence.uses === 1 ? '' : 's'}${r.presence.refused ? `, refused ${r.presence.refused}` : ''}${r.presence.byOp.length ? ` (${r.presence.byOp.map((x) => `${x.op} ${x.count}`).join(', ')})` : ''}.` : '',
      arByAction: r ? r.byAction.map((x) => row(x, x.action)) : [],
      arByActor: r ? r.byActor.map((x) => row(x, x.actor)) : [],
      arByNode: r ? r.byNode.map((x) => row(x, nodeName(x.node))) : [],
      arDenialsShow: !!(r && r.denials.total),
      arDenials: r ? r.denials.recent.map((d) => ({ time: localTime(d.timestamp), actor: d.actor, action: d.action, node: d.node ? nodeName(d.node) : '—', reason: d.reason })) : [],
      arReasons: r ? r.denials.reasons.map((x) => ({ text: `${x.action} · ${x.reason} · ${x.count}` })) : [],
      arEmpty: !!(r && r.records === 0),
    };
  },
};
