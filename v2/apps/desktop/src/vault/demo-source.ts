/**
 * `DemoSource`: an in-memory example vault behind the same `ModelSource` seam as the real thing.
 *
 * DEVELOPMENT AND TEST BUILDS ONLY.  It exists so a screen can be worked on in a plain browser (`vite dev`) and so unit tests
 * can build a model with no shell.  `createModel()` (index.ts) reaches it only when the build is a development or test
 * build; a release build drops this module, and `scripts/dc/verify-build.mjs` fails the build if {@link DEMO_MARKER}, or any
 * other trace of it, is in the bundle.
 *
 * EVERYTHING HERE IS INVENTED, and invented so that no scanner (and no reader) can take it for the real thing: hosts are the
 * documentation names (`example.test`) and documentation address range (`198.51.100.0/24`, `203.0.113.0/24`); every secret-looking
 * value is produced by {@link fake}, which only ever yields `demo-<kind>-<base36>` - no credential prefix, no key header, no
 * real-looking token.  The values of fields live in a private map, not in the entries, exactly as the real model keeps them.
 */
/** Present in a bundle iff this module is. */
export const DEMO_MARKER = "credmgr-demo-vault-marker";

import type { AuthLite, EntriesPart, GraphPart, ModelSource } from "./source";
import type { DEntry, DEntryDetail, DField, DGrant, DLink, DNode, DOrphan, DPending } from "./types";

interface RawField extends DField {
  value: string;
}
interface RawEntry extends Omit<DEntry, "fields" | "fieldCount"> {
  fields: RawField[];
}

/** Deterministic, obviously fake text for a secret-looking value: `demo-<kind>-<n in base36>`.  Never a real credential's shape. */
const fake = (kind: string, n: number): string => `demo-${kind}-${((n + 1) * 2654435761 >>> 0).toString(36)}`;

const PASSPHRASE_REQUIRED = { source: "broker", code: "wrong_passphrase", message: "passphrase required" } as const;
const CODE_REJECTED = { source: "broker", code: "gate_verification_failed", message: "code rejected" } as const;

function mk(name: string, i: string): RawEntry {
  const seq = Array.from(name + i).reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7);
  return {
    id: name.toLowerCase().replace(/[^a-z0-9]/g, "-") + "-" + i,
    name,
    type: "api",
    sensitivity: "medium",
    totp: false,
    meta: "api · medium",
    fields: [{ label: "token", value: fake("token", seq), type: "api-key", masked: true }],
  };
}

function pool(names: string[], count: number, pfx: string): RawEntry[] {
  const out: RawEntry[] = [];
  let i = 0;
  while (out.length < count) {
    const base = names[i % names.length];
    const suf = i >= names.length ? (i >= names.length * 2 ? "-old" : "-staging") : "";
    out.push(mk(base + suf, pfx + "-" + i));
    i++;
  }
  return out;
}

const F = (label: string, value: string, type: string, masked: boolean): RawField => ({ label, value, type, masked });
const E = (id: string, name: string, type: string, sensitivity: DEntry["sensitivity"], totp: boolean, meta: string, fields: RawField[]): RawEntry => ({ id, name, type, sensitivity, totp, meta, fields });

function demoEntries(): Record<string, RawEntry[]> {
  const linux: RawEntry[] = [
    E("lx-1", "vps-root", "server", "critical", true, "server · critical · rotated 2026-06-30", [F("host", "203.0.113.4", "host", false), F("port", "22", "port", false), F("username", "root", "username", false), F("password", fake("password", 1), "password", true), F("2fa seed", fake("totp", 1), "totp-seed", true)]),
    E("lx-2", "deploy-key", "ssh", "critical", false, "ssh · critical", [F("username", "deploy", "username", false), F("private key", "-----BEGIN DEMO KEY-----\n(a placeholder, not a key)\n-----END DEMO KEY-----", "private-key", true), F("passphrase", fake("passphrase", 2), "password", true)]),
    E("lx-3", "grafana-admin", "login", "high", true, "login · high", [F("url", "https://grafana.example.test:3000", "url", false), F("username", "admin", "username", false), F("password", fake("password", 3), "password", true), F("2fa seed", fake("totp", 3), "totp-seed", true)]),
    E("lx-4", "backup-b2", "api", "high", true, "api · high", [F("keyID", fake("key-id", 4), "api-key", false), F("applicationKey", fake("app-key", 4), "api-key", true), F("bucket", "vault-backups-eu", "text", false)]),
    E("lx-5", "pg-primary", "server", "critical", false, "server · critical", [F("host", "198.51.100.4", "host", false), F("port", "5432", "port", false), F("username", "svc_app", "username", false), F("password", fake("password", 5), "password", true)]),
    E("lx-6", "registry-token", "api", "medium", false, "api · medium", [F("token", fake("token", 6), "api-key", true)]),
    E("lx-7", "wireguard-peer", "other", "high", false, "other · high", [F("private key", fake("wg-key", 7), "private-key", true), F("endpoint", "vpn.example.test:51820", "text", false)]),
    E("lx-8", "tailscale-auth", "api", "medium", false, "api · medium", [F("authkey", fake("auth-key", 8), "api-key", true)]),
    E("lx-9", "smtp-relay", "login", "medium", false, "login · medium", [F("host", "smtp.example.test", "host", false), F("username", "postmaster@example.com", "username", false), F("password", fake("password", 9), "password", true)]),
    E("lx-10", "cf-tunnel", "api", "medium", false, "api · medium", [F("tunnel token", fake("tunnel", 10), "api-key", true)]),
    E("lx-11", "monit-webhook", "api", "low", false, "api · low", [F("url", "https://hooks.example.test/monit/demo", "url", false)]),
    E("lx-12", "fail2ban-alerts", "login", "low", false, "login · low", [F("email", "alerts@example.test", "username", false), F("password", fake("password", 12), "password", true)]),
  ];
  return {
    linux,
    global: pool(["licence-server", "registry-mirror", "gh-pat-readonly", "anthropic-api", "openai-api", "ntfy-topic", "dns-porkbun", "domain-registrar"], 12, "gl"),
    atlas: pool(["stripe-live", "stripe-webhook", "gh-deploy", "sentry-dsn", "pg-analytics", "redis-cache", "s3-artifacts", "mailgun-api", "twilio-sid", "dockerhub", "npm-token", "cf-api", "posthog", "algolia", "crisp-chat"], 41, "ah"),
    beacon: pool(["pg-main", "redis-main", "s3-media", "gh-actions", "vercel-token", "resend-api", "upstash", "clerk-secret", "plaid-sandbox", "sentry", "logtail"], 38, "fn"),
    cobalt: pool(["shopify-admin", "shopify-storefront", "klaviyo", "gorgias", "ship-station", "tax-jar", "meta-ads", "google-ads"], 22, "ig"),
    dev: pool(["dev-db", "dev-redis", "dev-smtp", "seed-user"], 4, "dv"),
    staging: pool(["stg-db", "stg-redis", "stg-smtp"], 3, "st"),
    prod: pool(["prod-db", "prod-redis", "prod-deploy", "prod-smtp", "prod-cdn"], 5, "pr"),
  };
}

function demoNodes(): DNode[] {
  const n = (id: string, kind: DNode["kind"], depth: number, parentId: string | null, entries: number, totp: number, locked: boolean, twofa: DNode["gate"]["twofa"], notes: string): DNode => ({
    id,
    label: id,
    kind,
    depth,
    parentId,
    counts: { entries, totp },
    gate: { locked, twofa },
    health: null,
    notes,
  });
  return [
    n("global", "global", 0, null, 12, 3, false, "enrolled", "Shared, deliberately small. Anything here is readable by every node — keep it to true globals: the licence server, the shared registry mirror."),
    n("atlas", "project", 1, "global", 41, 6, false, "required", "Stripe rotates on the 1st. The webhook secret pairs with stripe-live — rotate together."),
    n("beacon", "project", 1, "global", 38, 2, false, "none", ""),
    n("cobalt", "project", 1, "global", 22, 0, true, "none", "Node locked on its own — vault stays open, this stays shut."),
    n("linux", "project", 1, "global", 12, 3, false, "required", "vps-root rotates quarterly; the rotation script lives in the ops repo. prod deploys only from the deploy-key, never vps-root."),
    n("dev", "sub", 2, "linux", 4, 0, false, "none", ""),
    n("staging", "sub", 2, "linux", 3, 0, false, "none", ""),
    n("prod", "sub", 2, "linux", 5, 2, false, "required", "Siblings share (dev/staging/prod are interconnected). prod additionally gates reveals behind 2FA."),
  ];
}

export class DemoSource implements ModelSource {
  readonly kind = "demo" as const;
  readonly marker = DEMO_MARKER;
  private locked = false;
  private readonly nodes = demoNodes();
  private readonly raw = demoEntries();
  /** The entries as the view sees them: no values.  Shared with the view on purpose (see model options). */
  private readonly entryViews: Record<string, DEntry[]> = {};
  private readonly values = new Map<string, string>();
  private readonly demoGrants: DGrant[] = [{ id: "g-1", from: "linux", to: "beacon", toEntry: null, scope: "list · read", expires: "2026-08-30", lastUsed: "2026-08-06", reason: "linux's deploy job needs beacon's registry token" }];
  private readonly orphanItems: DOrphan[] = ["vps-root-old", "deploy-key-2023", "grafana-legacy", "backup-s3-old", "pg-replica", "wg-old-peer", "smtp-legacy"].map((name, i) => ({ id: "orph-" + i, name, from: "debian", date: "2026-08-04" }));

  constructor() {
    for (const [node, list] of Object.entries(this.raw)) {
      this.entryViews[node] = list.map((e) => {
        e.fields.forEach((f, i) => {
          this.values.set(`${node}/${e.id}/${i}`, f.value);
          this.values.set(`${node}/${e.id}/${demoFieldId(i)}`, f.value);
        });
        return { id: e.id, name: e.name, type: e.type, sensitivity: e.sensitivity, totp: e.totp, meta: e.meta, fieldCount: e.fields.length, fields: e.fields.map(({ label, type, masked }, i) => ({ id: demoFieldId(i), label, type, masked })) };
      });
    }
  }

  private auth(): AuthLite {
    return { locked: this.locked, authenticated: !this.locked, initialized: true };
  }

  async status(): Promise<AuthLite> {
    return this.auth();
  }

  async unlock(passphrase: string): Promise<AuthLite> {
    if (!passphrase.trim()) throw PASSPHRASE_REQUIRED;
    this.locked = false;
    return this.auth();
  }

  async gateVerify(code: string): Promise<AuthLite> {
    if (!/^\d{6}$/.test(code)) throw CODE_REJECTED;
    this.locked = false;
    return this.auth();
  }

  async lock(): Promise<void> {
    this.locked = true;
  }

  async graph(): Promise<GraphPart> {
    const structural: DLink[] = this.nodes.filter((n) => n.parentId).map((n) => ({ source: n.parentId as string, target: n.id, kind: "structural" as const }));
    return { nodes: this.nodes, links: structural, orphanNodeId: null };
  }

  async grants(): Promise<DGrant[]> {
    return this.demoGrants;
  }

  async entries(node: string): Promise<EntriesPart> {
    return { entries: (this.entryViews[node] ??= []), generation: 1 };
  }

  async orphans(): Promise<DOrphan[]> {
    return this.orphanItems;
  }

  async pending(): Promise<DPending[]> {
    return [];
  }

  async notes(node: string): Promise<string | null> {
    return this.nodes.find((n) => n.id === node)?.notes ?? null;
  }

  /** What the broker's `entry.get` would say about an example entry: the same fields, with ids. */
  async entryMeta(node: string, entry: string): Promise<DEntryDetail> {
    const e = (this.entryViews[node] ?? []).find((x) => x.id === entry);
    if (!e) throw { source: "broker", code: "not_found", message: "no such entry" } as const;
    return {
      node, entry, name: e.name, type: e.type, sensitivity: e.sensitivity, fieldCount: e.fields.length, hasTotp: e.totp, generation: 1,
      typeOverridden: false, sensitivityOverridden: false, modified: 0, rotatedAt: null, expiresAt: null,
      fields: e.fields.map((f, i) => ({ ...f, id: f.id ?? demoFieldId(i) })),
    };
  }

  async reveal(node: string, entry: string, field: number | string): Promise<string> {
    return this.values.get(`${node}/${entry}/${field}`) ?? "";
  }

  async revealFields(node: string, entry: string, fields: string[]): Promise<Array<{ id: string; value: string }>> {
    return fields.map((id) => ({ id, value: this.values.get(`${node}/${entry}/${id}`) ?? "" }));
  }
}

/** The id an example entry's field has: the broker's shape (`f_` and 8 hex digits). */
const demoFieldId = (i: number): string => `f_d${i.toString(16).padStart(7, "0")}`;
