/* Supporter extras, the milestone ask and the cosmetic settings (ADR-082).
   Mixin of the design's logic class: Object.assign'd onto Component.prototype in core.js.  Merged in from the design drop of 2026-10-18
   (design-upstream/PROVENANCE.md, "Drop 2026-10-18"); the broker is not involved: nothing here reads or writes the vault.

   What lives here
     - the sealed pack: cosmetic DATA (shape geometry, colour and backdrop tables) as AES-GCM ciphertext inside the app.  A supporter
       code, e-mailed after a donation, derives the key (PBKDF2-SHA-256, 200 000 rounds) and opens it once; the key is then kept
       (credmgr_extras_key) so later launches need no code.  A wrong code decrypts nothing and stores nothing.  The pack is parsed
       as JSON and cleaned (packClean); it is never evaluated, and it holds no code.
     - the milestone ask: a dismissible toast, at most three times in the life of an install (50 entries / 14 days, 150 / 45, 300 / 90),
       after an unlock, never over a dialog or a game, never twice in a day; "don't remind me" ends it.  credmgr_usage keeps calendar
       days and flags only.
     - the cosmetic choices (credmgr_cosmetics, allow-listed), the free Milestones list, the unlock flourish, the header stamp.
   Storage keys written here: credmgr_cosmetics, credmgr_donate_unlocked, credmgr_extras_key, credmgr_usage, credmgr_keys (see pstore.js).
   Nothing here makes a network request; the donor mails the proof from their own mail client. */

import { admin } from "../../vault/index";

const TEST = import.meta.env.MODE === "test";

// credmgr-allow: ciphertext only (AES-GCM under a key derived from a code that is not in this repository), no key material. This is the pack the design project sealed.
const REAL_BLOB = '{"v":1,"it":200000,"salt":"tW7kZQzV1rdSUDbT6QSbEQ==","iv":"RYMUT5BctVQq7zuz","d":"MlSerniBYhj0zCjzJpirasAtKVv2TNxasu+lBPLNV9+af78YVhE55eHITqXNSpFS1fHWlrFBfz3FQiTdEmDKMMNxy1VxEhbZuyDi4i3RH4DR9fEYGn6WJ+/2jOwbrGxhK+rekTOGxgnlGPk3QxRh8AHcDvfOIX+faT4uXoNkRZ2ITfn3sMt7+B4Ao0Dyn9bq1U9ijy/1qKhuwpSts819jpHTuwkNnagscRBLJk+YBHk4Sxyu3sBPqnVkj2MrtZaF/XV73wfjMd524eljxVA2xiownyq33OQBm5ky/krUx84E+jYLB+ZlAHOQdXiHjgoDHgMsW+sWdQ1rWTDQKc49eM6VltARQzqHXo2SqiwHEDg5ahwdVGhVjgI0kWE7d7EjIgHSAhhrVA8R04Gh97qYLBiUuKYA/od7CMQrm/KsQ67wgdkjglMtaJFp3yLMS5f2fGyiIY9H3yGw02PfjQ0PDbOkCRgtPXQUvtsFXUJwEMjnGWSVxgG7GHC1CDpXpbtO36rDx0R70/+RHGHbnuFIaLqUaKCtPVX8XQcSx66jmj1a2w=="}';
// credmgr-allow: test builds only (vite --mode test); the same data tables sealed under a code that exists only for tests (tests/fixtures/extras/seal-test-pack.mjs). Compiled out of a release build.
const TEST_BLOB = TEST ? '{"v":1,"it":200000,"salt":"Q94x3UQWG4XZc0w3XfM1Mg==","iv":"ESoC5DMvKr+k+Ny+","d":"35a6XwIs1dCsvEUEReM33iyIDcsUgVFwew0BlIrF2ZGdDzKc1G/7npTempL9P1nXJZpQWxxyAYguhDY5BDPteXsi6bGkqyytK1Powg1AvjoF710oX2E3aezj1Swp5vb5SxXkTvxSzj9u5oYDOgy92BOmanCWXRw5GnCYCJNQws+YWdJ0FANVd6ycB6vFwUji4a4A1PUwh99ON4ac1I7qs3AR20MkJ6i6XWx602GCydYh1jM+WpzR49txynQDLcOy2J3jVmSOEU0KIneVd/2OaFMW1AO5GPGf/HnrdJi+yvvFohtEUR16I6UYQzwJ4V9+8XsYWvXoORtnRvCkjHQkMFzs26gkmsiSJl6EYqAuuBvLBkzozqdoGEhoTh++Ss1xWC6+I1kiyk3kEMpzKkgtwGXX1yKL/IxG6TTraD5aHMmdLDXDqZKkBCaUPniKOl9xNe5obx5CxUsPQ1eUcduWYKTeJAi9GBm/6v76ZLp3BGlpJOB+wn3NxSv9G/2rtXjEO4fJH4ovs+o0NUhl2/U7VE2HKE1Nwx7LzjkKQPi7SWRVPA=="}' : '';

const SHAPES = ['circle', 'hexagon', 'square', 'octagon', 'diamond'];
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const num = (x, lo, hi, d) => { x = +x; return Number.isFinite(x) ? Math.min(hi, Math.max(lo, x)) : d; };

/** Clean a decrypted pack down to the data the painters read.  The pack is authenticated ciphertext, so this is depth, not the first line: it keeps a wrong number from ever becoming a loop bound. */
export function packClean(p) {
  const out = { v: 1, shapes: {}, global: {}, link: {}, dots: {}, backdrop: {} };
  if (!p || typeof p !== 'object') return out;
  for (const k of SHAPES.slice(1)) {
    const d = p.shapes && p.shapes[k]; if (!d || typeof d !== 'object') continue;
    if (d.half != null) out.shapes[k] = { half: num(d.half, 0.3, 1, 0.72), corner: num(d.corner, 0, 0.5, 0.22) };
    else out.shapes[k] = { n: Math.round(num(d.n, 3, 16, 6)), rot: num(d.rot, -360, 360, -90) };
  }
  for (const k of ['sig', 'ash', 'tint']) { const v = p.global && p.global[k]; if (v === 'sig' || v === 'ash' || v === 'tint') out.global[k] = v; }
  for (const k of ['ash', 'bone', 'sig']) { const v = p.link && p.link[k]; if (typeof v === 'string' && /^(ash|bone|sig|sigHi)(@(0|1|0?\.\d{1,3}))?$/.test(v)) out.link[k] = v; }
  for (const k of ['cool', 'warm', 'mono']) { const v = p.dots && p.dots[k]; if (v === 0) out.dots[k] = 0; else if (Array.isArray(v) && v.length === 2) out.dots[k] = [num(v[0], 0, 360, 0), num(v[1], 0, 360, 360)]; }
  for (const k of ['dots', 'lines', 'rings']) { const d = p.backdrop && p.backdrop[k]; if (d && typeof d === 'object' && ['dots', 'lines', 'rings'].includes(d.k)) out.backdrop[k] = { k: d.k, step: num(d.step, 16, 200, 40) }; }
  return out;
}

/** The test-only hooks.  A `const` object built under `import.meta.env.MODE === 'test'`, so a release build has neither the methods nor their names. */
const devMethods = TEST ? {
  /** Drive the ask in a test: `{days, entries, last, reset}`.  `entries` overrides the live count until the page reloads. */
  usageSet(o) {
    o = o || {}; const u = this.usageGet();
    if (o.reset) { u.asked = []; u.optout = false; u.lastAsk = ''; u.marks = {}; }
    if (o.days != null) u.days = o.days;
    if (o.last != null) u.last = o.last;
    if (o.lastAsk != null) u.lastAsk = o.lastAsk;
    this.usageSave(u);
    if ('entries' in o) this._entriesOv = o.entries;
  },
  /** Open the pack for this session only: no key and no flag are stored. */
  packLoad(code) { return this.extrasUnlock(code, false); },
} : {};

export const extrasMethods = {
  ...devMethods,

  // ─────────────── the sealed pack ───────────────
  donateCodeKey() { return 'credmgr_donate_unlocked'; },
  donateIsUnlocked() { try { return localStorage.getItem(this.donateCodeKey()) === '1'; } catch (e) { return false; } },
  extrasBlob() { return TEST ? TEST_BLOB : REAL_BLOB; },
  b64d(s) { return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); },
  b64e(u) { let s = ''; u.forEach((c) => { s += String.fromCharCode(c); }); return btoa(s); },
  async extrasOpenWith(key) {
    const b = JSON.parse(this.extrasBlob());
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: this.b64d(b.iv) }, key, this.b64d(b.d));
    return packClean(JSON.parse(new TextDecoder().decode(pt)));
  },
  /** Try a code.  True and the pack is open; false and NOTHING has been stored.  `keep:false` opens it for this session only. */
  async extrasUnlock(code, keep) {
    try {
      if (!(globalThis.crypto && globalThis.crypto.subtle)) return false;
      const b = JSON.parse(this.extrasBlob());
      const norm = String(code || '').replace(/\s+/g, '').toUpperCase();
      if (!norm || norm.length > 128) return false; // an empty or absurd paste is a wrong code, and must not feed 200 000 rounds of PBKDF2 a megabyte
      const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(norm), 'PBKDF2', false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt: this.b64d(b.salt), iterations: b.it, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
      const pack = await this.extrasOpenWith(key);
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
      if (keep !== false) { try { localStorage.setItem('credmgr_extras_key', this.b64e(raw)); localStorage.setItem(this.donateCodeKey(), '1'); } catch (e) { /* storage refused: the pack is open for this session */ } }
      this.setState({ pack });
      return true;
    } catch (e) { return false; }
  },
  async loadExtras() {
    try {
      const k = localStorage.getItem('credmgr_extras_key'); if (!k) return;
      const key = await crypto.subtle.importKey('raw', this.b64d(k), 'AES-GCM', false, ['decrypt']);
      this.setState({ pack: await this.extrasOpenWith(key) });
    } catch (e) { /* a stale or foreign key opens nothing: the extras stay sealed */ }
  },

  // ─────────────── usage: calendar days and asks only ───────────────
  today() { const d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); },
  usageGet() {
    const d = { v: 1, days: 0, last: '', asked: [], optout: false, lastAsk: '', marks: {} };
    try {
      const o = JSON.parse(localStorage.getItem('credmgr_usage') || '{}') || {}; const mk = {};
      if (o.marks && typeof o.marks === 'object') for (const k of this.msIds()) { if (typeof o.marks[k] === 'string' && DAY_RE.test(o.marks[k])) mk[k] = o.marks[k]; }
      return { v: 1, days: Math.max(0, o.days | 0), last: typeof o.last === 'string' && DAY_RE.test(o.last) ? o.last : '', asked: Array.isArray(o.asked) ? o.asked.filter((x) => ['m1', 'm2', 'm3'].includes(x)) : [], optout: !!o.optout, lastAsk: typeof o.lastAsk === 'string' && DAY_RE.test(o.lastAsk) ? o.lastAsk : '', marks: mk };
    } catch (e) { return d; }
  },
  usageSave(u) { try { localStorage.setItem('credmgr_usage', JSON.stringify(u)); } catch (e) { /* storage refused: the ask simply cannot be remembered */ } },
  /** One count per calendar day with a successful unlock.  No time of day is stored. */
  usageTick() { const u = this.usageGet(), t = this.today(); if (u.last !== t) { u.days++; u.last = t; this.usageSave(u); } this.marksSync(); },
  /** The live entries over all nodes, from the counts the graph already reads (no sealed, pending or trashed entries, no new op). */
  usageEntries() {
    if (this._entriesOv != null) return this._entriesOv;
    let n = 0; for (const nd of (this.vault.nodes || [])) n += Math.max(0, +(nd.counts && nd.counts.entries) || 0); return n;
  },
  /** The highest milestone that is due, or null.  A jump past two at once yields only the highest. */
  usagePending() {
    const u = this.usageGet(); if (u.optout || this.donateIsUnlocked() || u.lastAsk === this.today()) return null;
    const n = this.usageEntries(); let hit = null;
    [['m1', 50, 14], ['m2', 150, 45], ['m3', 300, 90]].forEach(([id, e, d]) => { if (n >= e && u.days >= d && !u.asked.includes(id)) hit = { id, e }; });
    return hit;
  },
  /** Called 6 s after an unlock.  Shows the toast when a milestone is due and nothing is in the way; marks the lower milestones passed. */
  maybeAsk() {
    const s = this.state;
    if (s.screen !== 'app' || this.model.status !== 'unlocked' || s.dialog || s.overlay || s.donateToastOpen) return;
    const m = this.usagePending(); if (!m) return;
    const u = this.usageGet(), order = ['m1', 'm2', 'm3'];
    order.slice(0, order.indexOf(m.id) + 1).forEach((x) => { if (!u.asked.includes(x)) u.asked.push(x); });
    u.lastAsk = this.today(); this.usageSave(u);
    this.setState({ donateToastOpen: true, donateView: 'main', donateMs: m.e + ' entries' });
  },
  /** An unlock the person made: count the day, arm the ask, start the flourish.  Not called for a window coming back into view. */
  onUnlocked() {
    this.applyAppIcon(); this.usageTick(); clearTimeout(this._donateTimer); this._donateTimer = setTimeout(() => this.maybeAsk(), 6000);
    return this.startFlourish();
  },

  // ─────────────── the cosmetic choices ───────────────
  cosmKey() { return 'credmgr_cosmetics'; },
  cosmDef() { return { mark: 'keep', glyph: 'classic', halo: false, ring: false, shape: 'circle', global: 'bone', link: 'default', dots: 'spectrum', backdrop: 'plain', badge: 'none', icon: 'keep', flourish: 'off', trail: 'standard' }; },
  cosmOpts() { return { mark: ['keep', 'cells', 'node', 'seal'], glyph: ['classic', 'fine', 'heavy'], shape: SHAPES, global: ['bone', 'sig', 'ash', 'tint'], link: ['default', 'ash', 'bone', 'sig'], dots: ['spectrum', 'cool', 'warm', 'mono'], backdrop: ['plain', 'dots', 'lines', 'rings'], badge: ['none', 'ring', 'stamp'], icon: ['keep', 'keepbone', 'cells', 'node', 'seal', 'keepsig'], flourish: ['off', 'on'], trail: ['standard', 'comet', 'dotted'] }; },
  /** Allow-list every field; anything else falls back to the default.  A v1 object migrates (ring:true becomes badge:'ring'). */
  cosmClean(o) {
    o = o || {}; const d = this.cosmDef(), opt = this.cosmOpts(), r = { ...d };
    for (const k in opt) r[k] = opt[k].includes(o[k]) ? o[k] : d[k];
    r.halo = !!o.halo; if (!opt.badge.includes(o.badge)) r.badge = o.ring ? 'ring' : 'none'; r.ring = r.badge === 'ring';
    return r;
  },
  /** Called once, when the app mounts: the stored cosmetics, then everything else that has to be in place first. */
  loadCosmetics() {
    try { const raw = localStorage.getItem(this.cosmKey()); if (raw) this.setState({ cosm: this.cosmClean(JSON.parse(raw) || {}) }); } catch (e) { /* unreadable: the defaults stay */ }
    this.initSettings();
  },
  cosmOn() { return !!this.state.pack; }, // cosmetic only: the pack is sealed in the app and opens with the code; nothing functional reads it
  /** What is drawn: the defaults while the pack is sealed, while high contrast or greyscale proof is on (graph choices) and under reduced motion (motion choices). */
  cosmEff() {
    if (!this.cosmOn()) return this.cosmDef();
    const c = { ...this.state.cosm }, d = this.cosmDef();
    if (this.state.contrastMode === 'high' || this.eff().greyscale) { for (const k of ['shape', 'global', 'link', 'dots', 'backdrop']) c[k] = d[k]; }
    if (this.isReduced()) { c.flourish = 'off'; c.trail = 'standard'; c.halo = false; }
    return c;
  },
  setCosm(patch) {
    if (!this.cosmOn()) return;
    const next = this.cosmClean({ ...this.state.cosm, ...patch });
    try { localStorage.setItem(this.cosmKey(), JSON.stringify(next)); } catch (e) { /* storage refused: the choice lasts until the window closes */ }
    this.setState({ cosm: next });
    this.applyAppIcon();
  },
  /** Tell the shell which app icon to show (X9, `app_icon_set`).  The defaults while the pack is sealed.  The OS icon resets when the app quits,
      so this runs again after every unlock; it is skipped when the shell already has this one.  Cosmetic: a refusal is ignored. */
  applyAppIcon() {
    const id = this.cosmOn() ? this.state.cosm.icon : 'keep';
    if (id === this._iconSent) return;
    this._iconSent = id;
    admin.setAppIcon(id).then((ok) => { if (!ok) this._iconSent = null; });
  },
  isReduced() { const m = this.state.motion; return m === 'reduced' || (m === 'system' && typeof matchMedia === 'function' && !!matchMedia('(prefers-reduced-motion: reduce)').matches); },

  // ─────────────── painting ───────────────
  /** A node outline path.  Every shape sits INSIDE the circle of radius r, so nothing that reads r (collision, hit test, spacing) changes. */
  shapePath(ctx, x, y, r, sh) {
    const pk = this.state.pack, d = pk && pk.shapes && pk.shapes[sh]; ctx.beginPath();
    if (!d) { ctx.arc(x, y, r, 0, 2 * Math.PI); return; }
    if (d.half) { const q = r * d.half; if (ctx.roundRect) ctx.roundRect(x - q, y - q, 2 * q, 2 * q, r * d.corner); else ctx.rect(x - q, y - q, 2 * q, 2 * q); return; }
    for (let i = 0; i < d.n; i++) { const a = (d.rot + 360 * i / d.n) * Math.PI / 180, px = x + r * Math.cos(a), py = y + r * Math.sin(a); if (i) ctx.lineTo(px, py); else ctx.moveTo(px, py); }
    ctx.closePath();
  },
  globalFill(p) {
    const c = this._ce || this.cosmEff(), pk = this.state.pack, k = pk && pk.global && pk.global[c.global]; if (!k) return p.bone;
    const e = this.eff(), dark = e.theme === 'dark';
    if (k === 'sig') return dark ? (p.sigHi || p.sig) : p.sig;
    if (k === 'ash') return p.ash;
    const hu = e.colour === 'off' ? 211 : e.hue; return dark ? 'oklch(0.80 0.06 ' + hu + ')' : 'oklch(0.45 0.07 ' + hu + ')';
  },
  /** Structural links only: a grant link keeps its own colour and dashes (the dash is the meaning). */
  linkStyle(ctx, p) {
    const c = this._ce || this.cosmEff(), pk = this.state.pack, k = pk && pk.link && pk.link[c.link];
    if (!k) { ctx.strokeStyle = p.hairS; return; }
    const a = k.split('@'); ctx.strokeStyle = p[a[0]] || p.hairS; if (a[1]) ctx.globalAlpha *= +a[1];
  },
  paintBackdrop(ctx, cv, dpr) {
    const c = this._ce, pk = this.state.pack, bd = pk && pk.backdrop && pk.backdrop[c.backdrop]; if (!bd || this.gv.k < 0.4) return;
    const { k, tx, ty } = this.gv, W = cv.width / dpr, H = cv.height / dpr, x0 = -tx / k, y0 = -ty / k, x1 = (W - tx) / k, y1 = (H - ty) / k, st = bd.step, p = this.palette();
    if ((x1 - x0) / st * ((y1 - y0) / st) > 9000) return;
    ctx.save(); ctx.lineWidth = 1 / k; const a = Math.floor(x0 / st) * st, b = Math.floor(y0 / st) * st;
    if (bd.k === 'dots') { ctx.fillStyle = p.hairS; const z = 1.6 / k; for (let x = a; x <= x1; x += st) for (let y = b; y <= y1; y += st) ctx.fillRect(x - z / 2, y - z / 2, z, z); }
    else if (bd.k === 'lines') { ctx.strokeStyle = p.hair || p.hairS; ctx.beginPath(); for (let x = a; x <= x1; x += st) { ctx.moveTo(x, y0); ctx.lineTo(x, y1); } for (let y = b; y <= y1; y += st) { ctx.moveTo(x0, y); ctx.lineTo(x1, y); } ctx.stroke(); }
    else { const g = this.gd.nodes.find((o) => o.kind === 'global'); if (g) { ctx.strokeStyle = p.hair || p.hairS; const R = Math.max(Math.hypot(x0 - g.x, y0 - g.y), Math.hypot(x1 - g.x, y0 - g.y), Math.hypot(x0 - g.x, y1 - g.y), Math.hypot(x1 - g.x, y1 - g.y)); ctx.beginPath(); for (let r = st, i = 0; r <= R && i < 80; r += st, i++) { ctx.moveTo(g.x + r, g.y); ctx.arc(g.x, g.y, r, 0, 2 * Math.PI); } ctx.stroke(); } }
    ctx.restore();
  },
  polyPts(cx, cy, r, d) { return Array.from({ length: d.n }, (_, i) => { const a = (d.rot + 360 * i / d.n) * Math.PI / 180; return (cx + r * Math.cos(a)).toFixed(2) + ',' + (cy + r * Math.sin(a)).toFixed(2); }).join(' '); },
  /** The worktree bullet's shape, as the three template branches read it (circle, polygon, rounded square). */
  treeShape(sh, r) {
    const pk = this.state.pack, d = pk && pk.shapes && pk.shapes[sh]; const z = { gCircle: false, gPoly: false, gRect: false, gpts: '', gx: 0, gw: 0, grx: 0 };
    if (!d) return { ...z, gCircle: true };
    if (d.half) { const q = r * d.half; return { ...z, gRect: true, gx: 12 - q, gw: 2 * q, grx: r * d.corner }; }
    return { ...z, gPoly: true, gpts: this.polyPts(12, 12, r, d) };
  },
  /** The small live preview in Settings → Appearance: three nodes, a link, the global node. */
  drawCosmPreview() {
    const cv = document.querySelector('[data-cosm-preview]'); if (!cv || !this.gd) return;
    const ctx = cv.getContext('2d'); ctx.setTransform(2, 0, 0, 2, 0, 0); ctx.clearRect(0, 0, 240, 140);
    const p = this.palette(), ce = this.cosmEff(), pk = this.state.pack, prev = this._ce, pf = this._cosmFx; this._ce = ce; this._cosmFx = ce;
    const G = { x: 120, y: 70 }, bd = pk && pk.backdrop && pk.backdrop[ce.backdrop];
    ctx.save();
    if (bd) {
      ctx.strokeStyle = p.hair || p.hairS; ctx.fillStyle = p.hairS; ctx.lineWidth = 1;
      if (bd.k === 'dots') { for (let x = 8; x < 240; x += 16) for (let y = 6; y < 140; y += 16) ctx.fillRect(x - .75, y - .75, 1.5, 1.5); }
      else if (bd.k === 'lines') { ctx.beginPath(); for (let x = 8; x < 240; x += 16) { ctx.moveTo(x, 0); ctx.lineTo(x, 140); } for (let y = 6; y < 140; y += 16) { ctx.moveTo(0, y); ctx.lineTo(240, y); } ctx.stroke(); }
      else { ctx.beginPath(); for (let r = 28; r < 150; r += 28) { ctx.moveTo(G.x + r, G.y); ctx.arc(G.x, G.y, r, 0, 2 * Math.PI); } ctx.stroke(); }
    }
    const A = { x: 52, y: 40 }, B = { x: 192, y: 102 }; ctx.lineWidth = 1;
    for (const T of [A, B]) { ctx.save(); this.linkStyle(ctx, p); ctx.beginPath(); ctx.moveTo(G.x, G.y); ctx.lineTo(T.x, T.y); ctx.stroke(); ctx.restore(); }
    for (const [T, i] of [[A, 0], [B, 1]]) { for (let k = 0; k < 4; k++) { const a = k * 1.7 + i, ex = T.x + Math.cos(a) * 26, ey = T.y + Math.sin(a) * 26; ctx.fillStyle = this.entryColor('pv' + i + k); ctx.beginPath(); ctx.arc(ex, ey, 2.6, 0, 7); ctx.fill(); } }
    ctx.fillStyle = this.globalFill(p); this.shapePath(ctx, G.x, G.y, 18, ce.shape); ctx.fill();
    for (const [T, i] of [[A, 3], [B, 5]]) { ctx.strokeStyle = p.bone; ctx.lineWidth = 1.5; this.shapePath(ctx, T.x, T.y, 13, ce.shape); ctx.stroke(); this.drawGlyph(ctx, T.x, T.y, 13 * 0.42, i, p.bone); }
    ctx.restore(); this._ce = prev; this._cosmFx = pf;
  },

  // ─────────────── flourish, stamp, milestones ───────────────
  startFlourish() { const on = this.cosmEff().flourish === 'on' && !this.isReduced(); clearTimeout(this._flT); if (on) this._flT = setTimeout(() => this.setState({ flourishOn: false }), 1100); return on; },
  stampText() { const n = this.usageEntries(), v = [300, 150, 50, 10].find((x) => n >= x); return v ? String(v) : ''; },
  msIds() { return ['proj1', 'e10', 'e50', 'e150', 'e300', 'p5', 'grant', 'd30', 'd90']; },
  msState(u) {
    const v = this.vault, n = this.usageEntries(), pr = (v.nodes || []).filter((x) => x.kind === 'project').length;
    return { proj1: pr >= 1, e10: n >= 10, e50: n >= 50, e150: n >= 150, e300: n >= 300, p5: pr >= 5, grant: (v.grants || []).length > 0, d30: u.days >= 30, d90: u.days >= 90 };
  },
  /** Record the day each free milestone was first reached.  Day only. */
  marksSync() { const u = this.usageGet(), st = this.msState(u), t = this.today(); let ch = false; for (const k of this.msIds()) if (st[k] && !u.marks[k]) { u.marks[k] = t; ch = true; } if (ch) this.usageSave(u); },
  msRows(sync) {
    if (sync) this.marksSync();
    const u = this.usageGet(), L = { proj1: 'first project', e10: '10 entries', e50: '50 entries', e150: '150 entries', e300: '300 entries', p5: '5 projects', grant: 'first grant', d30: '30 days in use', d90: '90 days in use' };
    return this.msIds().map((k) => ({ label: L[k], when: u.marks[k] || 'not yet', border: u.marks[k] ? 'var(--bone)' : 'var(--mute)', fill: u.marks[k] ? 'var(--bone)' : 'transparent' }));
  },

  /** The option groups of Settings → Appearance, grouped Graph · Identity · Motion · Games. */
  cosmGroups(on) {
    const cur = on ? this.state.cosm : this.cosmDef(), poly = (n, rot, r) => Array.from({ length: n }, (_, i) => { const a = (rot + 360 * i / n) * Math.PI / 180; return (r * Math.cos(a)).toFixed(1) + ',' + (r * Math.sin(a)).toFixed(1); }).join(' ');
    const pts = { circle: poly(24, 0, 7), hexagon: poly(6, -90, 7), square: poly(4, 45, 5.1), octagon: poly(8, -67.5, 7), diamond: poly(4, -90, 7) };
    const T = (m, bg, fg) => ({ m, bg, fg });
    const g = (title, caption, key, items, badge) => ({ title, caption, hasBadge: !!badge, badgeTitle: badge || '', opts: items.map(([val, label, sw, pt, tl]) => { const isOn = cur[key] === val; return { label, on: isOn, disabled: !on, set: () => this.setCosm({ [key]: val }), bg: isOn ? 'var(--bone)' : 'transparent', fg: isOn ? 'var(--void)' : 'var(--ash)', hasPts: !!pt, pts: pt || '', hasSw: !!sw, sw: sw || 'none', hasTile: !!tl, tileBg: tl ? tl.bg : 'none', tileFg: tl ? tl.fg : 'none', tK: !!tl && tl.m === 'keep', tC: !!tl && tl.m === 'cells', tN: !!tl && tl.m === 'node', tS: !!tl && tl.m === 'seal' }; }) });
    const sp = (a, b) => 'linear-gradient(90deg,oklch(0.74 0.125 ' + a + '),oklch(0.74 0.125 ' + b + '))';
    return {
      graph: [
        g('Node shape', 'project and sub-node bodies in the graph, the worktree and CredPong; high contrast and greyscale proof show the defaults', 'shape', [['circle', 'circle', 0, pts.circle], ['hexagon', 'hexagon', 0, pts.hexagon], ['square', 'rounded square', 0, pts.square], ['octagon', 'octagon', 0, pts.octagon], ['diamond', 'diamond', 0, pts.diamond]]),
        g('Global node colour', 'the filled node at the centre', 'global', [['bone', 'bone', 'var(--bone)'], ['sig', 'signal', 'var(--sig-hi)'], ['ash', 'ash', 'var(--ash)'], ['tint', 'tint', 'oklch(0.7 0.06 211)']]),
        g('Link colour', 'structural links; grant links keep their colour and dashes', 'link', [['default', 'default', 'var(--hair-strong)'], ['ash', 'ash', 'var(--ash)'], ['bone', 'bone', 'var(--bone)'], ['sig', 'signal', 'var(--sig)']]),
        g('Entry dot palette', 'the hue range of the dots around each node', 'dots', [['spectrum', 'spectrum', sp(0, 300)], ['cool', 'cool', sp(160, 260)], ['warm', 'warm', sp(20, 80)], ['mono', 'mono', 'var(--ash)']]),
        g('Graph backdrop', 'drawn under the graph; hidden when zoomed far out', 'backdrop', [['plain', 'plain'], ['dots', 'dot grid'], ['lines', 'line grid'], ['rings', 'rings']])],
      identity: [
        g('Header badge', 'beside the vault name in the header: a small ring, or the highest entry milestone you have reached', 'badge', [['none', 'none'], ['ring', 'ring'], ['stamp', 'milestone stamp']]),
        g('App icon', 'the dock or taskbar icon, shown here on its own tile; the app sets it on every choice and after every unlock (shell command app_icon_set)', 'icon', [['keep', 'keep on void', 0, 0, T('keep', 'var(--void)', 'var(--bone)')], ['keepbone', 'keep on bone', 0, 0, T('keep', 'var(--bone)', 'var(--void)')], ['cells', 'cells', 0, 0, T('cells', 'var(--void)', 'var(--bone)')], ['node', 'node', 0, 0, T('node', 'var(--void)', 'var(--bone)')], ['seal', 'seal', 0, 0, T('seal', 'var(--void)', 'var(--bone)')], ['keepsig', 'keep on signal', 0, 0, T('keep', 'var(--sig)', 'var(--void)')]], '')],
      motion: [g('Unlock flourish', 'the app mark draws itself when you unlock, then fades; the app is usable at once; off under reduced motion', 'flourish', [['off', 'off'], ['on', 'on']])],
      games: [g('CredPong ball trail', 'the ball’s tail; speed, balance and hit boxes are unchanged', 'trail', [['standard', 'standard'], ['comet', 'comet'], ['dotted', 'dotted']])],
    };
  },

  /** Latin letters next to Greek or Cyrillic ones: some of those are indistinguishable from Latin, so the name could imitate another (threat T4; the refusal itself is the broker's, ADR-084). A warning, never a block. */

  // ─────────────── what the screens bind to ───────────────
  rvExtras(c) {
    const { s, cosm } = c; const cosmOn = this.cosmOn(), grp = this.cosmGroups(cosmOn);
    const marks = [['keep', 'keep', true], ['cells', 'cells', false], ['node', 'node + ring', false], ['seal', 'seal', false]].map(([id, label, free]) => ({ label, isKeep: id === 'keep', isCells: id === 'cells', isNode: id === 'node', isSeal: id === 'seal', on: cosm.mark === id, disabled: !free && !cosmOn, border: cosm.mark === id ? 'var(--bone)' : 'var(--faint)', bg: cosm.mark === id ? 'var(--steel-3)' : 'transparent', set: () => this.setCosm({ mark: id }) }));
    const glyphs = [['classic', 1.2, true], ['fine', 0.8, false], ['heavy', 2, false]].map(([id, sw, free]) => ({ label: id, sw: String(sw), on: cosm.glyph === id, disabled: !free && !cosmOn, bg: cosm.glyph === id ? 'var(--bone)' : 'transparent', fg: cosm.glyph === id ? 'var(--night)' : 'var(--bone)', set: () => this.setCosm({ glyph: id }) }));
    return {
      // Settings → Appearance
      cosmUnlocked: cosmOn, cosmLockedShow: !cosmOn, cosmMarks: marks, cosmGlyphs: glyphs,
      cosmGraph: grp.graph, cosmIdentity: grp.identity, cosmMotion: grp.motion, cosmGames: grp.games,
      cosmHaloOn: !!cosm.halo, cosmHaloLabel: cosm.halo ? 'on' : 'off', cosmToggleDisabled: !cosmOn,
      cosmRingOn: !!cosm.ring, cosmRingLabel: cosm.ring ? 'on' : 'off', cosmRing: cosm.ring,
      toggleCosmHalo: () => this.setCosm({ halo: !cosm.halo }), toggleCosmRing: () => this.setCosm({ ring: !cosm.ring }),
      cosmHowTo: () => this.setState({ overlay: null, dialog: null, donateToastOpen: true, donateView: 'code', donateCode: '', donateCodeErr: false, donateNoCrypto: false }),
      msRows: this.msRows(s.setSection === 'appearance' && this.model.status === 'unlocked'),
      cosmStampShow: !!(cosmOn && cosm.badge === 'stamp' && this.stampText()), cosmStampText: this.stampText(),
      flourishShow: !!(s.flourishOn && s.screen === 'app'),
      // single-key shortcuts (WCAG 2.1.4): off keeps the modifier shortcuts only
      singleKeysOn: s.singleKeys !== false, singleKeysLabel: s.singleKeys !== false ? 'on' : 'off',
      toggleSingleKeys: () => { const on = !(this.state.singleKeys !== false); try { if (on) localStorage.removeItem('credmgr_keys'); else localStorage.setItem('credmgr_keys', 'off'); } catch (e) { /* storage refused: the choice lasts until the window closes */ } this.setState({ singleKeys: on }); },
      // the reminder toast
      donateToastVisible: !!(s.donateToastOpen && s.screen === 'app' && this.model.status === 'unlocked' && !s.dialog && !s.overlay && (!this.donateIsUnlocked() || s.donateView === 'code' || s.donateView === 'optout')),
      donateMsShow: !!s.donateMs, donateMsLabel: s.donateMs || '', donateViewOptout: s.donateView === 'optout',
      optOutAsk: () => { const u = this.usageGet(); u.optout = true; this.usageSave(u); this.setState({ donateView: 'optout' }); clearTimeout(this._optT); this._optT = setTimeout(() => this.setState({ donateToastOpen: false, donateView: 'main', donateMs: null }), 2600); },
      dismissDonateToast: () => this.setState({ donateToastOpen: false, donateMs: null, donateView: 'main', donateCode: '', donateCodeErr: false, donateCodeOk: false }),
      donateViewMain: (s.donateView || 'main') === 'main', donateViewGuide: s.donateView === 'guide', donateViewCode: s.donateView === 'code',
      goDonateGuide: () => this.setState({ donateView: 'guide' }), goDonateCode: () => this.setState({ donateView: 'code', donateCodeErr: false }),
      backDonateMain: () => this.setState({ donateView: 'main', donateCodeErr: false }),
      donateCodeVal: s.donateCode || '', onDonateCode: (ev) => this.setState({ donateCode: ev.target.value, donateCodeErr: false }),
      submitDonateCode: () => {
        if (!(globalThis.crypto && globalThis.crypto.subtle)) { this.setState({ donateCodeErr: true, donateNoCrypto: true }); return; }
        this.extrasUnlock(s.donateCode).then((ok) => {
          if (ok) { this.setState({ donateCodeOk: true, donateCodeErr: false, donateNoCrypto: false }); clearTimeout(this._okT); this._okT = setTimeout(() => this.setState({ donateToastOpen: false, donateView: 'main', donateCode: '', donateCodeOk: false, donateMs: null }), 1400); }
          else this.setState({ donateCodeErr: true, donateNoCrypto: false });
        });
      },
      donateCodeErrShow: !!s.donateCodeErr, donateCodeErrText: s.donateNoCrypto ? "This window can't open the extras: it has no secure context." : "That code doesn't look right.", donateCodeOkShow: !!s.donateCodeOk,
    };
  },
};
