/* An entry's tags in the inspector (ADR-167): chips under the name, each with ✕, and a small box that adds one on Enter.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   What this file does with the broker, and nothing else:
     entry.tag_set   {node, entry, generation, tags}   one call per change (the whole set); metadata only, no value
   The chips read the entry's own detail (`entry.get` already answers `tags`), so showing them costs no call.  After a change the entry
   is read again (no optimistic write), exactly as the expiry chip does (ADR-157); a stale generation re-reads it and says so. */

import { errorCode, write } from "../../vault/index";

/** True only in a development or test build, which may run on the in-memory example vault with no broker. */
const DEMO_BUILD = import.meta.env.DEV || import.meta.env.MODE === 'test';
const NEEDS_APP = 'This needs the CredMgr app: this page has no broker to write to. Nothing was changed.';
/** The broker's own bounds (credmgr_core::tags). */
export const TAGS_MAX = 16;
export const TAG_MAX_CHARS = 32;

/** The broker's normaliser, mirrored for the box: trimmed, lower-cased, inner spaces to one `-`; `null` when the broker would refuse it. */
export function normaliseTag(raw){
  const t = String(raw || '').trim().toLowerCase().replace(/\s+/g, '-');
  if(!t || [...t].length > TAG_MAX_CHARS) return null;
  return /^[\p{L}\p{N}\-_.:/]+$/u.test(t) ? t : null;
}

const keyOf = (node, entry) => `${node}\u0000${entry}`;

export const tagsMethods = {
  /** Send the whole new set.  One broker call; the chips then show what the broker stored. */
  async saveTags(node, entry, next){
    if(this._tagsBusy) return;
    if(DEMO_BUILD && this.model.kind !== 'bridge'){ this.setState({ tagErr: { key: keyOf(node, entry), text: NEEDS_APP } }); return; }
    this._tagsBusy = true;
    this.setState({ tagErr: null });
    try{
      await write.setTags(this.model, node, entry, next);
      this.setState({ tagDraft: null });
    }catch(e){
      const code = errorCode(e);
      this.routeError(e, { op: 'entry.tag_set', node, entry, field: 'tags', inlineRendered: true });
      const text = code === 'conflict' ? 'This entry changed elsewhere; it was read again. Try once more.'
        : code === 'malformed_request' ? 'A tag holds letters, digits, spaces and - _ . : / only (at most 32 characters, 16 tags).'
        : 'The tags could not be saved' + (code ? ` (${code})` : '') + '. Nothing was changed.';
      this.setState({ tagErr: { key: keyOf(node, entry), text } });
    }finally{
      this._tagsBusy = false;
    }
  },
  addTag(node, entry, current){
    const draft = this.state.tagDraft && this.state.tagDraft.key === keyOf(node, entry) ? this.state.tagDraft.text : '';
    const tag = normaliseTag(draft);
    if(!tag){ this.setState({ tagErr: { key: keyOf(node, entry), text: 'A tag holds letters, digits, spaces and - _ . : / only (at most 32 characters).' } }); return; }
    if(current.includes(tag)){ this.setState({ tagDraft: null }); return; }
    if(current.length >= TAGS_MAX){ this.setState({ tagErr: { key: keyOf(node, entry), text: `At most ${TAGS_MAX} tags.` } }); return; }
    this.saveTags(node, entry, [...current, tag]);
  },
  removeTag(node, entry, current, tag){
    this.saveTags(node, entry, current.filter((t) => t !== tag));
  },

  rvTags(c){
    const { s, sel, v } = c;
    const nodeId = s.selected && s.selected !== '__orphan' && sel ? sel.id : null;
    const entryId = nodeId && s.openEntry ? s.openEntry : null;
    const detail = entryId ? this.model.detail(nodeId, entryId) : undefined;
    const en = entryId ? (((v.entries || {})[nodeId] || []).find((x) => x.id === entryId) || null) : null;
    const usable = !!(detail && en && !sel.gate.locked);
    const key = usable ? keyOf(nodeId, entryId) : null;
    const current = usable && Array.isArray(detail.tags) ? detail.tags : [];
    const draft = key && s.tagDraft && s.tagDraft.key === key ? s.tagDraft.text : '';
    const err = key && s.tagErr && s.tagErr.key === key ? s.tagErr.text : '';
    return {
      tagsShow: usable,
      tagChips: current.map((t) => ({ tag: t, label: `remove the tag ${t}`, remove: () => this.removeTag(nodeId, entryId, current, t) })),
      tagDraft: draft,
      onTagDraft: (ev) => { if(key) this.setState({ tagDraft: { key, text: ev.target.value }, tagErr: null }); },
      onTagKey: (ev) => { if(key && ev && ev.key === 'Enter'){ if(ev.preventDefault) ev.preventDefault(); this.addTag(nodeId, entryId, current); } },
      tagErrShow: !!err,
      tagErr: err,
    };
  },
};
