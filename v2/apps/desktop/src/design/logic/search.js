/* Header search.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Read-path lane (WP-B).
   Split from the upstream monolith (design-upstream/PROVENANCE.md, ADR-075).

   Node names are matched here, against the model's view.  Entry NAMES come from the broker's `search` op, which applies the
   caller's own list permissions; it runs 150 ms after the last keystroke and an answer for an older term is dropped.  Field
   labels and values are not searched: labels are not exposed and values are never searchable. */

import { isSessionEnded, searchEntries } from "../../vault/index";

const DEBOUNCE_MS = 150;

export const searchMethods = {
  /** The search box changed: show what is known now and ask the broker for entry names once typing pauses. */
  onSearchInput(val){
    this.setState({searchQ:val,searchOpen:true},()=>this.renderGraph());
    clearTimeout(this._searchT);
    const term=val.trim();
    if(!term)return;
    this._searchT=setTimeout(()=>this.runSearch(term),DEBOUNCE_MS);
  },
  async runSearch(term){
    if(!this._mounted)return;
    let rows;
    try{ rows=await searchEntries(this.model,term); }
    // An answer for an older term is dropped, EXCEPT one that says the login is gone: that is true whatever was typed since.
    catch(e){ if(this.state.searchQ.trim()===term||isSessionEnded(e))this.routeReadError(e,{op:'search'}); return; }
    if(!this._mounted||this.state.searchQ.trim()!==term)return; // a later keystroke owns the box now
    this.setState({searchHits:{q:term,rows}});
  },
  rvSearch(c){
    const {isPro, s, v} = c;
    // search
    const q=s.searchQ.trim().toLowerCase();
    const label=(id)=>{ const n=this.node(id); return n?n.label:id; };
    const orphanId=this.model.orphanNodeId;
    const hits=(q&&s.searchHits&&s.searchHits.q.toLowerCase()===q)?s.searchHits.rows:null; // the broker's answer for exactly this term, if it has come
    let searchRows=[];
    if(s.searchOpen){
      if(!q){ searchRows=[{glyph:'+',label:'Add new',meta:'',go:()=>{const n=this.node(s.selected); this.openAddDlg(n?n.id:'global');}}];
        if(isPro){ searchRows.push(...(s.recentNodes||[]).map(nid=>{const n=this.node(nid);return n?{glyph:'○',label:n.label,meta:'recent',go:()=>{this.select(nid);this.setState({searchOpen:false});}}:null;}).filter(Boolean)); }
      } else {
        for(const n of v.nodes) if(n.label.toLowerCase().includes(q)) searchRows.push({glyph:'○',label:n.label,meta:'node',go:()=>{this.select(n.id);this.setState({searchOpen:false});}});
        if(hits) for(const r of hits){
          if(r.node===orphanId)continue; // sealed items are listed from the orphaned node's own list, below
          searchRows.push({glyph:'⌗',label:r.name,meta:label(r.node),go:()=>{this.select(r.node);this.setState({openEntry:r.id,searchOpen:false});}});
        }
        for(const o of v.orphans) if(o.name.toLowerCase().includes(q)) searchRows.push({glyph:'⌗',label:o.name,meta:'orphaned · sealed',go:()=>{this.select('__orphan');this.setState({searchOpen:false});}});
      }
    }
    const searchMoreCount=Math.max(0,searchRows.length-9);
    searchRows=searchRows.slice(0,9); // B3-4
    return {
      searchQ:s.searchQ,
      onSearch:(ev)=>this.onSearchInput(ev.target.value),
      onSearchFocus:()=>this.setState({searchOpen:true,vaultMenu:false}),
      searchOpen:s.searchOpen,
      searchRows,
      searchNone:s.searchOpen&&!!q&&hits!==null&&!searchRows.length, // not "Nothing matches" while the broker has not answered yet
      searchMoreShow:searchMoreCount>0,
      searchMoreCount:String(searchMoreCount),
    };
  },
};
