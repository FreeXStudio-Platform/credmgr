/* Help: the searchable list of everything the app and its command line can do, and where to find each thing.
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.

   The data is help-data.js, generated from v2/docs/help/features.json by tools/gen_help.py, so it ships with the app and nothing is
   fetched.  Search is local: every word typed must appear somewhere in a topic's title, section, summary, place, command, steps or
   search terms (case-insensitive, any order); topics whose title or search terms match rank first.  The query is page state only -
   it is not stored anywhere and no vault data is involved. */

import { HELP_AREAS, HELP_FEATURES } from "./help-data.js";

const AREA_TITLE = Object.fromEntries(HELP_AREAS.map((a) => [a.id, a.title]));
const STATUS_LABEL = { built: "", partial: "partly working", planned: "planned" };

let INDEX = null;
/** The lower-cased text each topic is searched in, built once. */
function index() {
  if (!INDEX) {
    INDEX = HELP_FEATURES.map((f, order) => ({
      f,
      order,
      title: f.title.toLowerCase(),
      terms: f.keywords.join(" ").toLowerCase(),
      place: f.where.toLowerCase(),
      all: [f.title, AREA_TITLE[f.area] || f.area, f.summary, f.where, f.cli || "", f.keywords.join(" "), f.steps.join(" ")].join(" ").toLowerCase(),
    }));
  }
  return INDEX;
}

/** The topics matching `query`, best first; every topic, in order, for an empty query. */
export function helpSearch(query) {
  const words = String(query || "").toLowerCase().split(/\s+/).filter(Boolean);
  const rows = index();
  if (!words.length) return rows.map((r) => r.f);
  const hits = [];
  for (const r of rows) {
    if (!words.every((w) => r.all.includes(w))) continue;
    let score = 0;
    for (const w of words) score += (r.title.includes(w) ? 3 : 0) + (r.terms.includes(w) ? 2 : 0) + (r.place.includes(w) ? 1 : 0);
    hits.push({ f: r.f, score, order: r.order });
  }
  hits.sort((a, b) => b.score - a.score || a.order - b.order);
  return hits.map((h) => h.f);
}

export const helpTotal = () => HELP_FEATURES.length;

export const helpMethods = {
  rvHelp(c) {
    const { s } = c;
    const open = s.dialog === "help";
    const raw = typeof s.helpQ === "string" ? s.helpQ : "";
    const q = raw.trim();
    const hits = open ? helpSearch(q) : [];
    const rows = [];
    let lastArea = null;
    for (const f of hits) {
      if (!q && f.area !== lastArea) {
        lastArea = f.area;
        rows.push({ key: "area-" + f.area, isHead: true, isTopic: false, head: AREA_TITLE[f.area] || f.area });
      }
      rows.push({
        key: f.id,
        isHead: false,
        isTopic: true,
        title: f.title,
        where: f.where,
        summary: f.summary,
        howText: f.steps.join("  ›  "),
        hasCli: !!f.cli,
        cli: f.cli || "",
        areaLabel: AREA_TITLE[f.area] || f.area,
        badge: STATUS_LABEL[f.status],
        hasBadge: f.status !== "built",
        badgeState: "warn", // the text says which; the danger tint on a steel ground is under the contrast floor
      });
    }
    const total = helpTotal();
    let countText = "";
    if (open) countText = q ? (hits.length ? `${hits.length} of ${total} topics match “${q}”` : `No topic matches “${q}”`) : `${total} topics`;
    return {
      helpQ: raw,
      onHelpQ: (ev) => this.setState({ helpQ: ev.target.value }),
      helpClear: () => this.setState({ helpQ: "" }),
      helpHasQuery: !!q,
      helpNoQuery: !q,
      helpRows: rows,
      helpCountText: countText,
      helpNone: open && !!q && hits.length === 0,
    };
  },
};
