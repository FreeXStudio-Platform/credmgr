//! The switchboard's settings registry (ADR-155): every setting an LLM or a person can read and change without the app
//! window, in one table — what it is for, where it is stored, what values it takes, and which way is the weaker one.
//!
//! This table is the single source of truth for three surfaces that must never drift apart: the broker's `settings.*`
//! operations (and so the MCP tools and the CLI that call them), the app's Settings page (which reads the same values
//! through the broker), and the LLM knowledge base (`docs/LLM_KB.md`), which [`kb_markdown`] generates from it and a test
//! holds byte-for-byte to the committed file.
//!
//! **Safety tiers (ADR-155).** [`classify`] says whether a change is cosmetic, makes the vault stricter, or weakens it.
//! A cosmetic or strengthening change from an agent applies at once; a weakening change from an agent becomes a request
//! the owner approves on their own device after a fresh confirmation (Touch ID or passphrase). A person's own change
//! follows the rules the app already had. Every applied change is recorded with its previous value and can be reverted.
//!
//! Pure compute, like the rest of `credmgr-core`: no storage, no clock, no I/O.

use serde_json::Value;

/// Where a setting applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// One value for the whole vault.
    Vault,
    /// One value per node (project); `node` names it.
    Node,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Vault => "vault",
            Scope::Node => "node",
        }
    }
}

/// Where the value is stored. Every store is inside the signed node registry, so a value read back is the value the
/// broker signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Store {
    /// `global.policy.appPrefs[key]`: the app's preferences, shared by the window and every client.
    AppPref(&'static str),
    /// `global.policy.revealConfirm.<field>` (ADR-150).
    RevealConfirm(&'static str),
    /// `<node>.policy.<field>` (`03_DATA_MODEL.md §1`).
    NodePolicy(&'static str),
}

impl Store {
    /// The path a person can read, e.g. `global.policy.appPrefs.autoLockMins`.
    pub fn path(self) -> String {
        match self {
            Store::AppPref(k) => format!("global.policy.appPrefs.{k}"),
            Store::RevealConfirm(k) => format!("global.policy.revealConfirm.{k}"),
            Store::NodePolicy(k) => format!("<node>.policy.{k}"),
        }
    }
}

/// The values a setting takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bool,
    /// One of these strings.
    Choice(&'static [&'static str]),
    /// One of these strings, or `null` ("follow the operating system").
    NullableChoice(&'static [&'static str]),
    /// One of these integers.
    IntChoice(&'static [i64]),
    /// An integer in `[min, max]`.
    IntRange(i64, i64),
    /// An integer in `[min, max]`, or `null` ("never").
    NullableIntRange(i64, i64),
}

/// Which way is weaker. Drives [`classify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Appearance and convenience: no direction is weaker.
    Cosmetic,
    /// Strictest first: moving right weakens.
    Ordered(&'static [&'static str]),
    /// This boolean value is the safe one.
    SafeBool(bool),
    /// A larger number is weaker; `zero_is_never` makes 0 the weakest of all (an idle lock of 0 is "never").
    HigherWeaker { zero_is_never: bool },
    /// A larger number is weaker and `null` ("never") is the weakest.
    NullableHigherWeaker,
}

/// One setting.
#[derive(Debug, Clone, Copy)]
pub struct SettingDef {
    /// Stable id, e.g. `app.autoLockMins`. Never renamed: an LLM and a script may hold it.
    pub id: &'static str,
    pub scope: Scope,
    pub kind: Kind,
    /// The default, as JSON text.
    pub default: &'static str,
    pub store: Store,
    /// The heading it sits under in the app and in the KB.
    pub group: &'static str,
    pub title: &'static str,
    /// What it is for, in a sentence a person and a model both understand.
    pub purpose: &'static str,
    /// Where a person finds it in the app.
    pub ui: &'static str,
    pub risk: Risk,
}

impl SettingDef {
    pub fn default_value(&self) -> Value {
        serde_json::from_str(self.default).expect("setting defaults are valid JSON")
    }

    /// True when some change of this setting can weaken the vault.
    pub fn security_relevant(&self) -> bool {
        self.risk != Risk::Cosmetic
    }

    /// A short description of the accepted values.
    pub fn values_text(&self) -> String {
        match self.kind {
            Kind::Bool => "true | false".to_string(),
            Kind::Choice(c) => c.join(" | "),
            Kind::NullableChoice(c) => format!("{} | null", c.join(" | ")),
            Kind::IntChoice(c) => c.iter().map(i64::to_string).collect::<Vec<_>>().join(" | "),
            Kind::IntRange(a, b) => format!("{a}..{b}"),
            Kind::NullableIntRange(a, b) => format!("{a}..{b} | null"),
        }
    }
}

const SECURITY_LEVELS: &[&str] = &["sealed", "guarded", "open"];
const AGENT_ACCESS: &[&str] = &["none", "read-only", "read-write"];
const TWO_FACTOR: &[&str] = &["always", "reveal", "never"];
const SIBLINGS: &[&str] = &["isolated", "shared"];
const CONFIRM_MODES: &[&str] = &["everyTime", "window", "off"];
const CONFIRM_SCOPES: &[&str] = &["all", "high"];

/// Every setting the switchboard knows. Order is the order of the KB and of `settings.list`.
pub static SETTINGS: &[SettingDef] = &[
    // ── Locking and revealing ────────────────────────────────────────────────────────────────────────────────
    SettingDef {
        id: "app.autoLockMins",
        scope: Scope::Vault,
        kind: Kind::IntChoice(&[5, 15, 60, 0]),
        default: "15",
        store: Store::AppPref("autoLockMins"),
        group: "Locking and revealing",
        title: "Idle auto-lock (minutes)",
        purpose: "Locks the vault after this many minutes without activity in the app; 0 turns the idle timer off (the vault still locks on sleep, screen lock and when the window is put away).",
        ui: "Settings › Security › Auto-lock",
        risk: Risk::HigherWeaker { zero_is_never: true },
    },
    SettingDef {
        id: "app.revealWindowSecs",
        scope: Scope::Vault,
        kind: Kind::IntChoice(&[10, 20, 60]),
        default: "20",
        store: Store::AppPref("revealWindowSecs"),
        group: "Locking and revealing",
        title: "Reveal window (seconds)",
        purpose: "How long a revealed value stays on screen in the app before it is masked again.",
        ui: "Settings › Security › Reveal window",
        risk: Risk::HigherWeaker { zero_is_never: false },
    },
    SettingDef {
        id: "app.captureProtection",
        scope: Scope::Vault,
        kind: Kind::Bool,
        default: "true",
        store: Store::AppPref("captureProtection"),
        group: "Locking and revealing",
        title: "Hide the window from screen capture",
        purpose: "Screenshots, recordings and screen sharing show the app's window blank, on every display.",
        ui: "Settings › Security › Screen capture",
        risk: Risk::SafeBool(true),
    },
    SettingDef {
        id: "vault.confirmBeforeReveal.mode",
        scope: Scope::Vault,
        kind: Kind::Choice(&["off", "window", "everyTime"]),
        default: "\"off\"",
        store: Store::RevealConfirm("mode"),
        group: "Locking and revealing",
        title: "Confirm before showing secrets",
        purpose: "Makes the owner's own login prove a person is at the keyboard (Touch ID or passphrase) before a value is shown: once per window, or every time (ADR-150).",
        ui: "Settings › Security › Confirm before showing secrets",
        risk: Risk::Ordered(CONFIRM_MODES),
    },
    SettingDef {
        id: "vault.confirmBeforeReveal.windowSeconds",
        scope: Scope::Vault,
        kind: Kind::IntChoice(&[60, 300, 900, 3600]),
        default: "300",
        store: Store::RevealConfirm("windowSeconds"),
        group: "Locking and revealing",
        title: "Confirmation window (seconds)",
        purpose: "How long one confirmation covers further reveals when the mode is `window`.",
        ui: "Settings › Security › Confirm before showing secrets › Window",
        risk: Risk::HigherWeaker { zero_is_never: false },
    },
    SettingDef {
        id: "vault.confirmBeforeReveal.scope",
        scope: Scope::Vault,
        kind: Kind::Choice(CONFIRM_SCOPES),
        default: "\"all\"",
        store: Store::RevealConfirm("scope"),
        group: "Locking and revealing",
        title: "Which values need confirming",
        purpose: "`all` values, or only entries whose sensitivity is high or critical.",
        ui: "Settings › Security › Confirm before showing secrets › Covers",
        risk: Risk::Ordered(CONFIRM_SCOPES),
    },
    // ── Projects (nodes) ─────────────────────────────────────────────────────────────────────────────────────
    SettingDef {
        id: "node.securityLevel",
        scope: Scope::Node,
        kind: Kind::Choice(&["open", "guarded", "sealed"]),
        default: "\"guarded\"",
        store: Store::NodePolicy("securityLevel"),
        group: "Projects (nodes)",
        title: "Agent security level",
        purpose: "How much an agent may do on this project without the owner: `open` (no approvals), `guarded` (high and critical reveals wait for approval), `sealed`, shown as Strict (every reveal waits; agent creates go to the held tray).",
        ui: "Node inspector › agents here",
        risk: Risk::Ordered(SECURITY_LEVELS),
    },
    SettingDef {
        id: "node.agentAccess",
        scope: Scope::Node,
        kind: Kind::Choice(&["none", "read-only", "read-write"]),
        default: "\"read-write\"",
        store: Store::NodePolicy("agentAccess"),
        group: "Projects (nodes)",
        title: "Agent access",
        purpose: "Whether agents scoped to this project may read and write, only read, or nothing.",
        ui: "Node inspector › Policy",
        risk: Risk::Ordered(AGENT_ACCESS),
    },
    SettingDef {
        id: "node.privateNames",
        scope: Scope::Node,
        kind: Kind::Bool,
        default: "false",
        store: Store::NodePolicy("privateNames"),
        group: "Projects (nodes)",
        title: "Private names",
        purpose: "Hides this project's label and entry names from everyone but the owner's login (ADR-083).",
        ui: "Node inspector › Policy",
        risk: Risk::SafeBool(true),
    },
    SettingDef {
        id: "node.requireTwoFactor",
        scope: Scope::Node,
        kind: Kind::Choice(&["never", "reveal", "always"]),
        default: "\"reveal\"",
        store: Store::NodePolicy("requireTwoFactor"),
        group: "Projects (nodes)",
        title: "Second factor",
        purpose: "When this project's two-factor gate is asked for, if one is enrolled: on every read, on reveals only, or never.",
        ui: "Node inspector › Policy",
        risk: Risk::Ordered(TWO_FACTOR),
    },
    SettingDef {
        id: "node.lockAfterSeconds",
        scope: Scope::Node,
        kind: Kind::NullableIntRange(30, 604_800),
        default: "null",
        store: Store::NodePolicy("lockAfterSeconds"),
        group: "Projects (nodes)",
        title: "Project lock after (seconds)",
        purpose: "Locks just this project again after this many seconds unlocked; null keeps it open while the vault is.",
        ui: "Node inspector › Policy",
        risk: Risk::NullableHigherWeaker,
    },
    SettingDef {
        id: "node.descendantRead",
        scope: Scope::Node,
        kind: Kind::Bool,
        default: "false",
        store: Store::NodePolicy("descendantRead"),
        group: "Projects (nodes)",
        title: "Parent reads its sub-nodes",
        purpose: "Lets this project read its own sub-nodes' entries (parents do not read children unless this is on).",
        ui: "Node inspector › Policy",
        risk: Risk::SafeBool(false),
    },
    SettingDef {
        id: "node.siblingVisibility",
        scope: Scope::Node,
        kind: Kind::Choice(SIBLINGS),
        default: "\"shared\"",
        store: Store::NodePolicy("siblingVisibility"),
        group: "Projects (nodes)",
        title: "Sub-nodes see each other",
        purpose: "Whether sub-nodes under one parent read each other's entries (`shared`) or not (`isolated`).",
        ui: "Node inspector › Policy",
        risk: Risk::Ordered(SIBLINGS),
    },
    // ── Appearance and behaviour ─────────────────────────────────────────────────────────────────────────────
    SettingDef {
        id: "app.theme",
        scope: Scope::Vault,
        kind: Kind::NullableChoice(&["dark", "light"]),
        default: "null",
        store: Store::AppPref("theme"),
        group: "Appearance and behaviour",
        title: "Theme",
        purpose: "Dark or light; null follows the operating system.",
        ui: "Settings › Appearance",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.colour",
        scope: Scope::Vault,
        kind: Kind::Choice(&["off", "on", "auto"]),
        default: "\"off\"",
        store: Store::AppPref("colour"),
        group: "Appearance and behaviour",
        title: "Accent colour",
        purpose: "Tints the interface with the accent hue.",
        ui: "Settings › Appearance",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.hue",
        scope: Scope::Vault,
        kind: Kind::IntRange(0, 360),
        default: "198",
        store: Store::AppPref("hue"),
        group: "Appearance and behaviour",
        title: "Accent hue",
        purpose: "The accent colour's hue, in degrees.",
        ui: "Settings › Appearance",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.intensity",
        scope: Scope::Vault,
        kind: Kind::IntRange(0, 100),
        default: "32",
        store: Store::AppPref("intensity"),
        group: "Appearance and behaviour",
        title: "Accent intensity",
        purpose: "How strong the accent tint is, 0 to 100.",
        ui: "Settings › Appearance",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.greyscale",
        scope: Scope::Vault,
        kind: Kind::Bool,
        default: "false",
        store: Store::AppPref("greyscale"),
        group: "Appearance and behaviour",
        title: "Greyscale",
        purpose: "Shows the interface without colour.",
        ui: "Settings › Appearance",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.contrastMode",
        scope: Scope::Vault,
        kind: Kind::NullableChoice(&["standard", "high"]),
        default: "null",
        store: Store::AppPref("contrastMode"),
        group: "Appearance and behaviour",
        title: "Contrast",
        purpose: "Standard or high contrast; null follows the operating system.",
        ui: "Settings › Appearance",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.motion",
        scope: Scope::Vault,
        kind: Kind::Choice(&["system", "reduced"]),
        default: "\"system\"",
        store: Store::AppPref("motion"),
        group: "Appearance and behaviour",
        title: "Motion",
        purpose: "Follow the system's reduced-motion setting, or always reduce motion.",
        ui: "Settings › Appearance",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.hwAccel",
        scope: Scope::Vault,
        kind: Kind::Bool,
        default: "true",
        store: Store::AppPref("hwAccel"),
        group: "Appearance and behaviour",
        title: "Hardware acceleration",
        purpose: "Draws the graph with the GPU.",
        ui: "Settings › Appearance",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.mode",
        scope: Scope::Vault,
        kind: Kind::Choice(&["lite", "pro"]),
        default: "\"pro\"",
        store: Store::AppPref("mode"),
        group: "Appearance and behaviour",
        title: "Interface mode",
        purpose: "Lite shows the essentials; Pro shows every control.",
        ui: "Settings › Mode",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.backupRetain",
        scope: Scope::Vault,
        kind: Kind::IntChoice(&[14, 30]),
        default: "14",
        store: Store::AppPref("backupRetain"),
        group: "Appearance and behaviour",
        title: "Backups kept",
        purpose: "How many encrypted backups `maintenance.backup` keeps before the oldest is removed.",
        ui: "Settings › Backup",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.entriesMode",
        scope: Scope::Vault,
        kind: Kind::Choice(&["all", "selected"]),
        default: "\"all\"",
        store: Store::AppPref("entriesMode"),
        group: "Appearance and behaviour",
        title: "Entries shown",
        purpose: "List every reachable entry, or only the selected project's.",
        ui: "Main view",
        risk: Risk::Cosmetic,
    },
    SettingDef {
        id: "app.view",
        scope: Scope::Vault,
        kind: Kind::Choice(&["graph", "tree"]),
        default: "\"graph\"",
        store: Store::AppPref("view"),
        group: "Appearance and behaviour",
        title: "Main view",
        purpose: "Graph or tree.",
        ui: "Main view › graph / tree",
        risk: Risk::Cosmetic,
    },
];

/// The setting called `id`.
pub fn find(id: &str) -> Option<&'static SettingDef> {
    SETTINGS.iter().find(|d| d.id == id)
}

/// The setting stored as app preference `key`.
pub fn find_app_pref(key: &str) -> Option<&'static SettingDef> {
    SETTINGS
        .iter()
        .find(|d| matches!(d.store, Store::AppPref(k) if k == key))
}

/// Check `value` against the setting's kind.
pub fn validate(def: &SettingDef, value: &Value) -> Result<(), String> {
    let ok = match (def.kind, value) {
        (Kind::Bool, Value::Bool(_)) => true,
        (Kind::Choice(c), Value::String(s)) => c.contains(&s.as_str()),
        (Kind::NullableChoice(_), Value::Null) => true,
        (Kind::NullableChoice(c), Value::String(s)) => c.contains(&s.as_str()),
        (Kind::IntChoice(c), v) => v.as_i64().is_some_and(|n| c.contains(&n)),
        (Kind::IntRange(a, b), v) => v.as_i64().is_some_and(|n| n >= a && n <= b),
        (Kind::NullableIntRange(_, _), Value::Null) => true,
        (Kind::NullableIntRange(a, b), v) => v.as_i64().is_some_and(|n| n >= a && n <= b),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("{} takes {}", def.id, def.values_text()))
    }
}

/// What a change does to the vault's protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// The value does not change.
    Same,
    /// Appearance or convenience only.
    Cosmetic,
    /// The vault becomes stricter.
    Strengthens,
    /// The vault becomes less protected: from an agent this waits for the owner's approval.
    Weakens,
}

impl Change {
    pub fn as_str(self) -> &'static str {
        match self {
            Change::Same => "same",
            Change::Cosmetic => "cosmetic",
            Change::Strengthens => "strengthens",
            Change::Weakens => "weakens",
        }
    }
}

/// Classify a change from `old` to `new`. Both are assumed valid ([`validate`]); an unknown value is read as the weakest,
/// so a value the table does not know can never be classified as safe.
pub fn classify(def: &SettingDef, old: &Value, new: &Value) -> Change {
    if old == new {
        return Change::Same;
    }
    let weaker = match def.risk {
        Risk::Cosmetic => return Change::Cosmetic,
        Risk::Ordered(order) => {
            let rank = |v: &Value| {
                v.as_str()
                    .and_then(|s| order.iter().position(|o| *o == s))
                    .unwrap_or(order.len())
            };
            rank(new) > rank(old)
        }
        Risk::SafeBool(safe) => new.as_bool() != Some(safe),
        Risk::HigherWeaker { zero_is_never } => {
            let rank = |v: &Value| match v.as_i64() {
                Some(0) if zero_is_never => i64::MAX,
                Some(n) => n,
                None => i64::MAX,
            };
            rank(new) > rank(old)
        }
        Risk::NullableHigherWeaker => {
            let rank = |v: &Value| v.as_i64().unwrap_or(i64::MAX);
            rank(new) > rank(old)
        }
    };
    if weaker {
        Change::Weakens
    } else {
        Change::Strengthens
    }
}

/// How many applied changes the registry keeps for `settings.revert`.
pub const HISTORY_LIMIT: usize = 100;

/// One applied setting change, as the registry records it (`global.policy.settingsHistory`). Carries no secret: every
/// setting value is a policy or a preference.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingChange {
    /// `sc-` and 16 hex digits.
    pub id: String,
    pub setting: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    pub from: Value,
    pub to: Value,
    /// `owner`, or `agent:<public id>` for an agent's direct change; an approved request is `owner` with `request` set.
    pub by: String,
    /// Unix seconds.
    pub at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,
    pub reason: String,
    /// The change this one reverted, if it was a revert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverts: Option<String>,
}

/// A feature an LLM should know about: what it is, and the switch or command that drives it.
#[derive(Debug, Clone, Copy)]
pub struct FeatureDef {
    pub id: &'static str,
    pub title: &'static str,
    pub purpose: &'static str,
    /// How an LLM or a person uses it without the app window.
    pub how: &'static str,
}

/// The features, for the KB. Settings are in [`SETTINGS`]; these are the things the vault does.
pub static FEATURES: &[FeatureDef] = &[
    FeatureDef { id: "projects", title: "Projects (nodes) as boundaries", purpose: "Every project is a node with its own key. Everything reads Global; projects never read each other; sub-nodes read their parents.", how: "MCP `credmgr_whoami` shows your node; CLI `credmgr node list`, `credmgr node create` (owner)." },
    FeatureDef { id: "entries", title: "Entries and fields", purpose: "A credential is an entry with one or more labelled fields; every write keeps history and can be undone.", how: "MCP `credmgr_list`, `credmgr_create`, `credmgr_update`, `credmgr_rotate`, `credmgr_undo`; CLI `credmgr set`, `credmgr get`, `credmgr list`." },
    FeatureDef { id: "agents", title: "Agent scoping by working folder", purpose: "An agent started in a folder bound to a project reaches that project, its ancestors and Global, nothing else.", how: "CLI `credmgr node create <id> --workdir <dir>` (owner); MCP `credmgr_whoami`." },
    FeatureDef { id: "securityLevels", title: "Security levels", purpose: "Per project: open, guarded or Strict (stored as sealed) — how much an agent's request waits for the owner.", how: "Setting `node.securityLevel` through the switchboard." },
    FeatureDef { id: "approvals", title: "Approvals", purpose: "A request the vault holds back (a guarded reveal, a weakening setting change) waits for the owner's decision on their device.", how: "Owner: the app, or CLI `credmgr settings requests` / `credmgr settings approve <id>`; agent: MCP `credmgr_settings_request` to poll." },
    FeatureDef { id: "touchId", title: "Touch ID", purpose: "A Secure Enclave key proves a person is present for the gated operations, and can unlock the vault. Agents can never use it.", how: "Owner only: Settings › Security › Touch ID; CLI `credmgr unlock --touch-id`." },
    FeatureDef { id: "secondFactor", title: "Second factor (TOTP gates)", purpose: "A vault or project can require a TOTP code before reading or revealing.", how: "Owner only: CLI `credmgr gate enroll`; setting `node.requireTwoFactor`." },
    FeatureDef { id: "totp", title: "TOTP codes", purpose: "An entry can hold a 2FA seed; the vault answers the current code, never the seed, to agents.", how: "MCP `credmgr_totp_code`; CLI `credmgr totp <name>`." },
    FeatureDef { id: "backup", title: "Encrypted backup and restore", purpose: "A backup is the encrypted vault as it is on disk; restore is offline and makes no network call.", how: "Owner: CLI `credmgr backup`, `credmgr restore`; setting `app.backupRetain`." },
    FeatureDef { id: "export", title: "Encrypted export", purpose: "One project exported as an age file under a passphrase you choose.", how: "Owner: CLI `credmgr node export <id> --age <file>`." },
    FeatureDef { id: "seal", title: "Seal and restore", purpose: "Sealing a project moves it to Orphaned: names stay, values become owner-only until restored.", how: "Owner: app node menu, CLI `credmgr node seal` / `credmgr node restore`." },
    FeatureDef { id: "audit", title: "Audit log", purpose: "Every operation is recorded in a hash-chained log with no value in it.", how: "Owner: CLI `credmgr audit`; MCP `credmgr_recent_changes` for your own scope." },
    FeatureDef { id: "passphrase", title: "Changing the passphrase", purpose: "The owner can change the vault passphrase; it replaces the root key and issues a new recovery code. Agents cannot.", how: "Owner only: Settings › Security › Passphrase; CLI `credmgr passphrase` (both values on stdin)." },
    FeatureDef { id: "expiry", title: "Expiry, history and references", purpose: "An entry can carry an expiry date; the owner can list what expires soon and read one entry's trail. No value is ever in either. Every entry also has a vault-wide reference number.", how: "Owner: CLI `credmgr expire`, `credmgr expiring`, `credmgr history`, `credmgr ref <number>`. No MCP tool." },
    FeatureDef { id: "anomalyAlarm", title: "Anomaly alarm", purpose: "Five refusals across node boundaries in ten minutes raise an alarm the owner sees; an agent that keeps probing other projects is noticed.", how: "Owner: the app's notice bar; CLI `credmgr status` shows unseen alarms, `credmgr status --ack` marks them seen." },
    FeatureDef { id: "switchboard", title: "Switchboard", purpose: "Every setting in this file can be read and changed without the app window, with the safety tiers below.", how: "MCP `credmgr_settings_*`; CLI `credmgr settings ...`." },
];

/// The MCP tools the KB lists. `crates/mcp`'s tests hold this list to the tools the server registers, so the KB can
/// never name a tool that does not exist or miss one that does.
pub static MCP_TOOL_NAMES: &[&str] = &[
    "credmgr_whoami",
    "credmgr_list",
    "credmgr_search",
    "credmgr_get",
    "credmgr_get_metadata",
    "credmgr_create",
    "credmgr_update",
    "credmgr_rotate",
    "credmgr_field_add",
    "credmgr_field_update",
    "credmgr_field_remove",
    "credmgr_remove",
    "credmgr_undo",
    "credmgr_totp_code",
    "credmgr_recent_changes",
    "credmgr_settings_list",
    "credmgr_settings_get",
    "credmgr_settings_set",
    "credmgr_settings_revert",
    "credmgr_settings_request",
    "credmgr_kb",
];

fn md_escape(s: &str) -> String {
    s.replace('|', "\\|")
}

/// The LLM knowledge base, generated from this module. `docs/LLM_KB.md` is this output, byte for byte.
pub fn kb_markdown() -> String {
    let mut o = String::new();
    o.push_str("<!-- artifact-hardened: NEEDS RE-HARDENING — generated, not hand-written: the source of truth is crates/core/src/settings.rs (ADR-155), and a test holds this file to it byte for byte -->\n");
    o.push_str("<!-- GENERATED by credmgr_core::settings::kb_markdown — do not edit by hand. Regenerate with `CREDMGR_WRITE_KB=1 cargo test -p credmgr-core the_committed_kb`; a test fails when this file and the generator differ. -->\n");
    o.push_str("# CredMgr — knowledge base for language models\n\n");
    o.push_str("CredMgr is a local credential vault. One broker process (`credmgrd`) holds the keys and decides every request; the app, the CLI (`credmgr`) and the MCP server (`credmgr mcp`) are clients of it. The broker has no network code: nothing in the vault is sent anywhere.\n\n");
    o.push_str("This file tells a model everything it needs to drive CredMgr without the app window: the features, every setting with what it is for and where it lives, how to connect, where data is kept, and how to read and change settings through the **switchboard**.\n\n");

    o.push_str("## 1. Connect\n\n");
    o.push_str("- **Local agents (Claude Code, Cursor, Codex, Gemini CLI, Claude Desktop):** the MCP server runs over stdio. Print the config to paste with `credmgr mcp --print-config`, or let CredMgr add itself with `credmgr agent connect <client>`.\n");
    o.push_str("- **Your scope:** an agent is scoped by its working folder. Start it inside a folder bound to a project; `credmgr_whoami` tells you the node you reach.\n");
    o.push_str("- **The vault must be unlocked by the owner** (the app, Touch ID, or `credmgr unlock`). An agent never unlocks it.\n");
    o.push_str("- **Cloud assistants (claude.ai, ChatGPT):** not connected in this version. The planned design keeps values on the Mac and lets a remote assistant use credentials without receiving them (`docs/26` Phase 5).\n\n");

    o.push_str("## 2. Where data lives\n\n");
    o.push_str("| What | macOS | Linux | Windows |\n|---|---|---|---|\n");
    o.push_str("| Vault (encrypted entries, signed registry, audit log) | `~/Library/Application Support/credmgr` | `$XDG_DATA_HOME/credmgr` (`~/.local/share/credmgr`) | `%APPDATA%\\credmgr` |\n");
    o.push_str("| State (broker socket, counters) | `~/Library/Application Support/credmgr-state` | `$XDG_STATE_HOME/credmgr` | `%LOCALAPPDATA%\\credmgr\\state` |\n");
    o.push_str("| Settings | inside the signed registry: `global.policy.appPrefs`, `global.policy.revealConfirm`, `<node>.policy` | same | same |\n\n");
    o.push_str("`CREDMGR_VAULT_DIR` and `CREDMGR_STATE_DIR` override both. Values are encrypted per project; names and settings are signed so a changed file is refused.\n\n");

    o.push_str("## 3. Retention and backup\n\n");
    o.push_str("- Every write keeps the previous value; `credmgr_undo` reverses the last change to an entry. A removed entry can be restored for 7 days.\n");
    o.push_str("- `credmgr backup` (owner) writes an encrypted copy of the vault; `app.backupRetain` sets how many are kept. `credmgr restore` is offline.\n");
    o.push_str("- Every setting change made through the switchboard is recorded with its previous value and can be reverted (`credmgr_settings_revert`).\n");
    o.push_str("- The audit log keeps every operation, never a value.\n\n");

    o.push_str("## 4. The switchboard\n\n");
    o.push_str("| MCP tool | CLI | What it does |\n|---|---|---|\n");
    o.push_str("| `credmgr_settings_list` | `credmgr settings list [--node <id>]` | Every setting with its current value, default, scope, risk and whether **you** may change it directly or need approval. |\n");
    o.push_str("| `credmgr_settings_get` | `credmgr settings get <id> [--node <id>]` | One setting, described in full. |\n");
    o.push_str("| `credmgr_settings_set` | `credmgr settings set <id> <json> [--node <id>] --reason <why>` | Change a setting (`toggle` is `set` with the other boolean). |\n");
    o.push_str("| `credmgr_settings_revert` | `credmgr settings revert <change>` | Put back the value a recorded change replaced. |\n");
    o.push_str("| `credmgr_settings_request` | `credmgr settings requests` / `approve <id>` / `deny <id>` | An agent polls its waiting request; the owner lists and decides them. |\n");
    o.push_str("| `credmgr_kb` | `credmgr kb` | This file. |\n\n");
    o.push_str("### Safety tiers\n\n");
    o.push_str("- **Cosmetic** changes (appearance, layout) apply at once, for an agent too.\n");
    o.push_str("- **Strengthening** changes (a stricter level, a shorter lock, protection on) apply at once, for an agent too.\n");
    o.push_str("- **Weakening** changes (a longer or no auto-lock, a looser reveal policy, a lower security level, more agent access, protection off) from an agent become a **request**: `credmgr_settings_set` answers `state: \"pending\"` with a `request` id. The owner approves it on their own device after a fresh Touch ID or passphrase confirmation; the change then applies and is recorded. Poll with `credmgr_settings_request`. A request expires after 10 minutes.\n");
    o.push_str(
        "- An agent sees and changes project settings only for projects in its own scope.\n",
    );
    o.push_str("- Not on the switchboard (owner-only operations, unchanged): unlocking, Touch ID enrolment, second-factor enrolment, grants, creating or sealing projects, rotating the root key, deleting orphans, backups and exports.\n\n");
    o.push_str("### Examples\n\n");
    o.push_str("```json\n{\"tool\": \"credmgr_settings_set\", \"arguments\": {\"id\": \"app.theme\", \"value\": \"dark\", \"reason\": \"user asked for dark mode\"}}\n```\n");
    o.push_str("→ `{\"applied\": true, \"change\": \"cosmetic\", \"changeId\": \"sc-…\"}`\n\n");
    o.push_str("```json\n{\"tool\": \"credmgr_settings_set\", \"arguments\": {\"id\": \"node.securityLevel\", \"node\": \"acme\", \"value\": \"open\", \"reason\": \"user wants no approvals on acme\"}}\n```\n");
    o.push_str("→ `{\"applied\": false, \"state\": \"pending\", \"request\": \"sr-…\", \"change\": \"weakens\"}` — tell the user to approve it in CredMgr.\n\n");
    o.push_str("```sh\ncredmgr settings set app.autoLockMins 5 --reason \"lock sooner\"\ncredmgr settings list --node acme\n```\n\n");

    o.push_str("## 5. Every setting\n\n");
    let mut group = "";
    for d in SETTINGS {
        if d.group != group {
            group = d.group;
            o.push_str(&format!("### {group}\n\n| id | scope | values | default | risk | what it is for | where |\n|---|---|---|---|---|---|---|\n"));
        }
        let risk = match d.risk {
            Risk::Cosmetic => "cosmetic".to_string(),
            Risk::Ordered(order) => format!("weaker toward `{}`", order[order.len() - 1]),
            Risk::SafeBool(safe) => format!("`{}` is weaker", !safe),
            Risk::HigherWeaker {
                zero_is_never: true,
            } => "higher or 0 is weaker".to_string(),
            Risk::HigherWeaker { .. } => "higher is weaker".to_string(),
            Risk::NullableHigherWeaker => "higher or null is weaker".to_string(),
        };
        o.push_str(&format!(
            "| `{}` | {} | {} | `{}` | {} | {} | {}; stored `{}` |\n",
            d.id,
            d.scope.as_str(),
            md_escape(&d.values_text()),
            d.default,
            risk,
            md_escape(d.purpose),
            d.ui,
            d.store.path()
        ));
        if SETTINGS
            .iter()
            .skip_while(|x| x.id != d.id)
            .nth(1)
            .map_or(true, |n| n.group != group)
        {
            o.push('\n');
        }
    }

    o.push_str("## 6. Features\n\n| Feature | What it is for | How to use it without the app |\n|---|---|---|\n");
    for f in FEATURES {
        o.push_str(&format!(
            "| **{}** | {} | {} |\n",
            f.title,
            md_escape(f.purpose),
            md_escape(f.how)
        ));
    }
    o.push('\n');

    o.push_str("## 7. Every MCP tool\n\n");
    o.push_str(
        &MCP_TOOL_NAMES
            .iter()
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(" · "),
    );
    o.push_str("\n\nCall `credmgr_whoami` first. A tool never widens your scope; if you need something outside it, ask the user.\n\n");

    o.push_str("## 8. Rules for a model\n\n");
    o.push_str("- Prefer reading names and metadata over revealing values. A value you reveal enters your context and cannot be taken back.\n");
    o.push_str(
        "- Give a `reason` for every change; it is shown to the owner and kept in the record.\n",
    );
    o.push_str("- When a change answers `pending`, tell the user what you asked for and that it waits for their approval in CredMgr. Do not retry in a loop.\n");
    o.push_str("- Never ask the user for their passphrase, recovery code or a TOTP seed.\n");
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;

    #[test]
    fn ids_are_unique_and_defaults_validate() {
        let mut seen = HashSet::new();
        for d in SETTINGS {
            assert!(seen.insert(d.id), "duplicate id {}", d.id);
            validate(d, &d.default_value()).unwrap_or_else(|e| panic!("{}: {e}", d.id));
            let prefix = match d.store {
                Store::AppPref(_) => "app.",
                Store::RevealConfirm(_) => "vault.confirmBeforeReveal.",
                Store::NodePolicy(_) => "node.",
            };
            assert!(d.id.starts_with(prefix), "{} stored as {:?}", d.id, d.store);
            assert_eq!(
                d.scope == Scope::Node,
                matches!(d.store, Store::NodePolicy(_)),
                "{}",
                d.id
            );
        }
    }

    #[test]
    fn the_app_prefs_are_exactly_the_window_prefs() {
        // apps/desktop/src/vault/prefs.ts PREF_KEYS; tests/unit holds the page to this list too.
        let keys: Vec<&str> = SETTINGS
            .iter()
            .filter_map(|d| match d.store {
                Store::AppPref(k) => Some(k),
                _ => None,
            })
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        let mut expected = vec![
            "theme",
            "colour",
            "hue",
            "intensity",
            "greyscale",
            "contrastMode",
            "motion",
            "hwAccel",
            "captureProtection",
            "mode",
            "autoLockMins",
            "revealWindowSecs",
            "backupRetain",
            "entriesMode",
            "view",
        ];
        expected.sort_unstable();
        assert_eq!(sorted, expected);
        assert!(find_app_pref("autoLockMins").is_some() && find_app_pref("nope").is_none());
    }

    #[test]
    fn validation_refuses_what_the_kind_does_not_take() {
        let lock = find("app.autoLockMins").unwrap();
        assert!(validate(lock, &json!(7)).is_err());
        assert!(validate(lock, &json!("15")).is_err());
        let theme = find("app.theme").unwrap();
        assert!(validate(theme, &Value::Null).is_ok());
        assert!(validate(theme, &json!("purple")).is_err());
        let after = find("node.lockAfterSeconds").unwrap();
        assert!(validate(after, &Value::Null).is_ok());
        assert!(validate(after, &json!(10)).is_err());
    }

    #[test]
    fn classification_knows_which_way_is_weaker() {
        let c = |id: &str, a: Value, b: Value| classify(find(id).unwrap(), &a, &b);
        assert_eq!(
            c("app.autoLockMins", json!(15), json!(5)),
            Change::Strengthens
        );
        assert_eq!(c("app.autoLockMins", json!(15), json!(60)), Change::Weakens);
        assert_eq!(c("app.autoLockMins", json!(60), json!(0)), Change::Weakens);
        assert_eq!(
            c("app.autoLockMins", json!(0), json!(60)),
            Change::Strengthens
        );
        assert_eq!(
            c("app.captureProtection", json!(true), json!(false)),
            Change::Weakens
        );
        assert_eq!(
            c("app.captureProtection", json!(false), json!(true)),
            Change::Strengthens
        );
        assert_eq!(
            c("node.securityLevel", json!("guarded"), json!("open")),
            Change::Weakens
        );
        assert_eq!(
            c("node.securityLevel", json!("guarded"), json!("sealed")),
            Change::Strengthens
        );
        assert_eq!(
            c("node.agentAccess", json!("read-only"), json!("read-write")),
            Change::Weakens
        );
        assert_eq!(
            c("node.lockAfterSeconds", json!(300), Value::Null),
            Change::Weakens
        );
        assert_eq!(
            c("node.lockAfterSeconds", Value::Null, json!(300)),
            Change::Strengthens
        );
        assert_eq!(
            c("node.descendantRead", json!(false), json!(true)),
            Change::Weakens
        );
        assert_eq!(
            c(
                "vault.confirmBeforeReveal.mode",
                json!("window"),
                json!("off")
            ),
            Change::Weakens
        );
        assert_eq!(
            c(
                "vault.confirmBeforeReveal.scope",
                json!("all"),
                json!("high")
            ),
            Change::Weakens
        );
        assert_eq!(
            c("app.theme", json!("dark"), json!("light")),
            Change::Cosmetic
        );
        assert_eq!(c("app.theme", json!("dark"), json!("dark")), Change::Same);
        // A value outside the table is read as the weakest: never classified safe.
        assert_eq!(
            c("node.securityLevel", json!("guarded"), json!("bogus")),
            Change::Weakens
        );
    }

    #[test]
    fn the_kb_names_every_setting_and_feature() {
        let kb = kb_markdown();
        for d in SETTINGS {
            assert!(kb.contains(&format!("`{}`", d.id)), "{}", d.id);
        }
        for f in FEATURES {
            assert!(kb.contains(f.title), "{}", f.id);
        }
        for t in MCP_TOOL_NAMES {
            assert!(kb.contains(t), "{t}");
        }
    }

    #[test]
    fn the_committed_kb_is_the_generated_one() {
        let committed = include_str!("../../../docs/LLM_KB.md");
        if std::env::var_os("CREDMGR_WRITE_KB").is_some() {
            let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/LLM_KB.md");
            std::fs::write(path, kb_markdown()).expect("write docs/LLM_KB.md");
            return;
        }
        assert!(
            committed == kb_markdown(),
            "docs/LLM_KB.md is out of date: regenerate it with `CREDMGR_WRITE_KB=1 cargo test -p credmgr-core the_committed_kb` (or `credmgr kb > docs/LLM_KB.md`)"
        );
    }
}
