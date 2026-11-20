/* Finding things (rc.2 §1 item 3): the rail's node filter, and "Find in this node" in the node inspector.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   What this file does with the broker, and nothing else:
     entry.search   {node, term}   "Find in this node": names and aliases on the selected node that contain the term, case-insensitive;
                                   never values.  It runs 200 ms after the last keystroke, and an answer for an older term or another node
                                   is dropped.
   The node filter asks the broker nothing: there is no node search operation, and the graph snapshot the model already holds lists every
   node this login may see, so the filter narrows that list in the page (main.js reads `nodeFilterIds`).
   (Lookup by reference lives in the header search, search.js; the audit report in auditreport.js.) */

import { isSessionEnded, read } from "../../vault/index";

const DEBOUNCE_MS = 200;

/**
 * The node ids the rail shows for a filter: every node whose label or id contains `term` (case-insensitive), plus the parent of a
 * matching sub-node, so it is never shown without its project.  `null` for an empty filter: everything shows.  Pure.
 */
export function nodeFilterIds(nodes, term){
  const t = String(term || '').trim().toLowerCase();
  if(!t) return null;
  const list = nodes || [];
  const byId = new Map(list.map((n) => [n.id, n]));
  const out = new Set();
  for(const n of list){
    if(String(n.label || '').toLowerCase().includes(t) || String(n.id).toLowerCase().includes(t)){
      out.add(n.id);
      if(n.parentId && byId.has(n.parentId) && byId.get(n.parentId).kind !== 'global') out.add(n.parentId);
    }
  }
  return out;
}

export const finderMethods = {
  // ───────────────────────────── the rail's node filter ─────────────────────────────
  onNodeFilter(val){ this.setState({ nodeFilter: String(val).slice(0, 120) }); },

  // ───────────────────────────── Find in this node (entry.search) ─────────────────────────────
  onNodeFind(node, val){
    const q = String(val);
    this.setState({ nodeFind: { node, q, rows: null, err: null } });
    clearTimeout(this._nodeFindT);
    if(!q.trim()) return;
    this._nodeFindT = setTimeout(() => this.runNodeFind(node, q), DEBOUNCE_MS);
  },
  async runNodeFind(node, q){
    let rows;
    try{ rows = await read.searchInNode(this.model, node, q); }
    catch(e){
      const f = this.state.nodeFind;
      if((f && f.node === node && f.q === q) || isSessionEnded(e)){
        this.setState((st) => (st.nodeFind && st.nodeFind.node === node && st.nodeFind.q === q ? { nodeFind: { ...st.nodeFind, err: 'This node could not be searched.' } } : null));
        this.routeReadError(e, { op: 'entry.search', node });
      }
      return;
    }
    const f = this.state.nodeFind;
    if(!f || f.node !== node || f.q !== q) return; // a later keystroke, or another node, owns the box now
    this.setState({ nodeFind: { ...f, rows } });
  },

  rvFinder(c){
    const { s, sel, v } = c;
    const ids = nodeFilterIds(v.nodes, s.nodeFilter);
    const nodeId = s.selected && s.selected !== '__orphan' && sel ? sel.id : null;
    const showFind = !!(nodeId && !s.openEntry && !sel.gate.locked && ((v.entries || {})[nodeId] || []).length > 0);
    const f = s.nodeFind && s.nodeFind.node === nodeId ? s.nodeFind : null;
    const q = f ? f.q : '';
    const rows = f && f.rows ? f.rows : [];
    const entries = nodeId ? ((v.entries || {})[nodeId] || []) : [];
    return {
      nodeFilter: s.nodeFilter || '',
      onNodeFilter: (ev) => this.onNodeFilter(ev.target.value),
      clearNodeFilter: () => this.setState({ nodeFilter: '' }),
      nodeFilterOn: !!ids,
      nodeFilterNone: !!ids && ids.size === 0,

      nodeFindShow: showFind,
      nodeFindQ: q,
      onNodeFind: (ev) => { if(nodeId) this.onNodeFind(nodeId, ev.target.value); },
      nodeFindRowsShow: !!(f && f.rows && q.trim()),
      nodeFindRows: rows.map((r) => ({
        name: r.name,
        why: r.alias ? `also called ${r.alias}` : '',
        whyShow: !!r.alias,
        open: () => { const en = entries.find((x) => x.id === r.id); if(en){ this.setState({ nodeFind: null }); this.openEntryDetail(nodeId, en); } },
      })),
      nodeFindNone: !!(f && f.rows && q.trim() && rows.length === 0),
      nodeFindErrShow: !!(f && f.err),
      nodeFindErr: f && f.err ? f.err : '',
    };
  },
};
