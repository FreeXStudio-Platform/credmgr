//! Wiring an agent client to CredMgr - pure text in, text out (ADR-141, ADR-142).
//!
//! `17_AIRLOCK_AND_LLM.md §4` and `§5`. This module knows how each coding-agent client names its
//! MCP configuration file, what the `credmgr` entry looks like in that client's format, how to add
//! or remove exactly that one entry without disturbing a byte of anything else in the file, and how
//! to word the Vault Protocol prompt and the `CREDMGR.md` file. It performs **no I/O**: the CLI and
//! the desktop shell read and write the files; this crate stays pure (`crates/core` has no file,
//! socket, clock or environment access), so every rule below is testable without a disk.
//!
//! What it never does: hold a secret, ask for one, or write one. Everything it renders is a node
//! name, a path to the `credmgr` binary, or fixed text.

use serde_json::Value;

pub use crate::registry::SecurityLevel;

/// The key under which every client's config carries the entry.
pub const SERVER_NAME: &str = "credmgr";

/// A coding-agent client with a local, stdio-capable MCP configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Client {
    ClaudeCode,
    ClaudeDesktop,
    Cursor,
    /// VS Code (GitHub Copilot's agent mode reads the same file).
    VsCode,
    Windsurf,
}

pub const CLIENTS: [Client; 5] = [
    Client::ClaudeCode,
    Client::ClaudeDesktop,
    Client::Cursor,
    Client::VsCode,
    Client::Windsurf,
];

impl Client {
    /// The stable id the CLI flag and the desktop bridge use.
    pub fn id(self) -> &'static str {
        match self {
            Client::ClaudeCode => "claude-code",
            Client::ClaudeDesktop => "claude-desktop",
            Client::Cursor => "cursor",
            Client::VsCode => "vscode",
            Client::Windsurf => "windsurf",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Client::ClaudeCode => "Claude Code",
            Client::ClaudeDesktop => "Claude Desktop",
            Client::Cursor => "Cursor",
            Client::VsCode => "VS Code (Copilot)",
            Client::Windsurf => "Windsurf",
        }
    }

    /// Accepts the ids above plus the names people type (`copilot`, `claude`, `vs-code`).
    pub fn parse(s: &str) -> Option<Client> {
        match s.trim().to_ascii_lowercase().as_str() {
            "claude-code" | "claudecode" | "claude" => Some(Client::ClaudeCode),
            "claude-desktop" | "claudedesktop" => Some(Client::ClaudeDesktop),
            "cursor" => Some(Client::Cursor),
            "vscode" | "vs-code" | "code" | "copilot" | "github-copilot" => Some(Client::VsCode),
            "windsurf" | "codeium" => Some(Client::Windsurf),
            _ => None,
        }
    }

    /// The user-level config file, relative to the home directory (macOS - the only platform in
    /// scope for 2.0.0; ADR-141).
    pub fn config_rel_path(self) -> &'static str {
        match self {
            Client::ClaudeCode => ".claude.json",
            Client::ClaudeDesktop => {
                "Library/Application Support/Claude/claude_desktop_config.json"
            }
            Client::Cursor => ".cursor/mcp.json",
            Client::VsCode => "Library/Application Support/Code/User/mcp.json",
            Client::Windsurf => ".codeium/windsurf/mcp_config.json",
        }
    }

    /// The top-level object that holds the servers: VS Code names it `servers`, the rest
    /// `mcpServers`.
    pub fn container_key(self) -> &'static str {
        match self {
            Client::VsCode => "servers",
            _ => "mcpServers",
        }
    }

    /// May CredMgr offer to write this client's file? `~/.claude.json` is the live state of a
    /// running Claude Code (history, projects, caches) that the client rewrites itself; editing it
    /// from outside races with the client, so for Claude Code CredMgr shows the `claude mcp add`
    /// command and the JSON and never writes the file (ADR-142).
    pub fn writable(self) -> bool {
        self != Client::ClaudeCode
    }

    /// The `command` + `args` entry as this client reads it, written with a stable key order.
    fn entry_lines(self, binary: &str) -> Vec<String> {
        let mut lines = Vec::new();
        if self == Client::VsCode {
            lines.push("\"type\": \"stdio\"".to_string());
        }
        lines.push(format!("\"command\": {}", json_str(binary)));
        lines.push("\"args\": [\"mcp\"]".to_string());
        lines
    }

    /// The entry as a JSON value (for comparison only; order is irrelevant here).
    fn entry_value(self, binary: &str) -> Value {
        let mut o = serde_json::Map::new();
        if self == Client::VsCode {
            o.insert("type".into(), Value::String("stdio".into()));
        }
        o.insert("command".into(), Value::String(binary.to_string()));
        o.insert(
            "args".into(),
            Value::Array(vec![Value::String("mcp".into())]),
        );
        Value::Object(o)
    }
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).expect("a string always serialises")
}

/// The whole-file snippet a person can paste, in the client's own shape, 2-space indented. For a
/// generic client (`None`) it is the common `mcpServers` shape.
pub fn snippet(client: Option<Client>, binary: &str) -> String {
    let key = client.map_or("mcpServers", Client::container_key);
    let lines = match client {
        Some(c) => c.entry_lines(binary),
        None => vec![
            format!("\"command\": {}", json_str(binary)),
            "\"args\": [\"mcp\"]".to_string(),
        ],
    };
    let mut out = format!("{{\n  \"{key}\": {{\n    \"{SERVER_NAME}\": {{\n");
    for (i, l) in lines.iter().enumerate() {
        out.push_str("      ");
        out.push_str(l);
        if i + 1 < lines.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("    }\n  }\n}\n");
    out
}

/// The one-line command that adds the server to Claude Code without touching its state file.
pub fn claude_code_command(binary: &str) -> String {
    format!(
        "claude mcp add --scope user {SERVER_NAME} -- {} mcp",
        shell_quote(binary)
    )
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'/' | b'.' | b'_' | b'-' | b'+' | b':' | b'@' | b'%')
        })
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

// ---- the edit -----------------------------------------------------------------------------------

/// Why an edit was refused. Every one of these leaves the file untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// The file is not valid JSON (a comment, a trailing comma, a half-saved edit). It is shown to
    /// the person, never overwritten (`17 §4.1` step 3).
    NotJson(String),
    /// The top level is not an object.
    RootNotObject,
    /// The servers key exists but is not an object.
    ContainerNotObject,
    /// A different `credmgr` entry is already there. CredMgr does not replace what it did not write.
    DifferentEntryPresent,
    /// The edit was made and then did not re-parse to exactly the expected document. Nothing is
    /// offered for writing.
    VerifyFailed,
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlanError::NotJson(why) => write!(f, "the file is not valid JSON ({why}); it was left alone"),
            PlanError::RootNotObject => write!(f, "the file's top level is not a JSON object; it was left alone"),
            PlanError::ContainerNotObject => write!(f, "the servers entry in the file is not an object; it was left alone"),
            PlanError::DifferentEntryPresent => write!(
                f,
                "the file already has a different \"credmgr\" entry; CredMgr will not replace what it did not write"
            ),
            PlanError::VerifyFailed => write!(f, "the edit did not check out against the original; nothing was written"),
        }
    }
}

/// What a connect or disconnect would do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The complete new file text. Equal to the old text when `unchanged`.
    pub new_text: String,
    /// Nothing to do: the entry is already there (connect) or not there (disconnect).
    pub unchanged: bool,
}

/// Add the `credmgr` entry to `existing` (the file's text, or `None` when the file does not exist).
/// Every other byte of an existing file is preserved; the new entry is spliced in. The result is
/// re-parsed and compared with the original document plus exactly that one entry before it is
/// returned.
pub fn plan_connect(
    existing: Option<&str>,
    client: Client,
    binary: &str,
) -> Result<Plan, PlanError> {
    let entry_value = client.entry_value(binary);
    let Some(text) = existing.filter(|t| !t.trim().is_empty()) else {
        // No file (or an empty one): write a fresh document.
        return Ok(Plan {
            new_text: snippet(Some(client), binary),
            unchanged: false,
        });
    };
    let original: Value =
        serde_json::from_str(text).map_err(|e| PlanError::NotJson(e.to_string()))?;
    let Some(root) = original.as_object() else {
        return Err(PlanError::RootNotObject);
    };
    let key = client.container_key();
    // Already there?
    if let Some(container) = root.get(key) {
        let Some(container) = container.as_object() else {
            return Err(PlanError::ContainerNotObject);
        };
        if let Some(found) = container.get(SERVER_NAME) {
            return if *found == entry_value {
                Ok(Plan {
                    new_text: text.to_string(),
                    unchanged: true,
                })
            } else {
                Err(PlanError::DifferentEntryPresent)
            };
        }
    }

    let root_open = skip_ws(text, 0);
    let new_text = match member_span(text, root_open, key) {
        None => {
            // No servers object at all: add one to the root.
            let member = {
                let lines = client.entry_lines(binary);
                render_member(key, &render_object_of(SERVER_NAME, &lines, 2), 2)
            };
            insert_member(text, root_open, &member, 0)
        }
        Some(span) => {
            let container_open = span.value_start;
            let member_indent = line_indent(text, span.key_start);
            // Sit level with the servers already there; two in from the key when there are none.
            let (siblings, _) = object_members(text, container_open);
            let inner_len = siblings.last().map_or(member_indent.len() + 2, |m| {
                line_indent(text, m.key_start).len()
            });
            let lines = client.entry_lines(binary);
            let member = render_member(
                SERVER_NAME,
                &render_entry_object(&lines, inner_len),
                inner_len,
            );
            insert_member(text, container_open, &member, member_indent.len())
        }
    };

    // Verify: the new text must parse to the original with exactly one entry added.
    let mut expected = original.clone();
    {
        let root_mut = expected.as_object_mut().expect("checked above");
        let container = root_mut
            .entry(key.to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        container
            .as_object_mut()
            .expect("checked above")
            .insert(SERVER_NAME.to_string(), entry_value);
    }
    match serde_json::from_str::<Value>(&new_text) {
        Ok(v) if v == expected => Ok(Plan {
            new_text,
            unchanged: false,
        }),
        _ => Err(PlanError::VerifyFailed),
    }
}

/// Remove the `credmgr` entry from `existing`, leaving everything else as it was.
pub fn plan_disconnect(existing: &str, client: Client) -> Result<Plan, PlanError> {
    let original: Value =
        serde_json::from_str(existing).map_err(|e| PlanError::NotJson(e.to_string()))?;
    let Some(root) = original.as_object() else {
        return Err(PlanError::RootNotObject);
    };
    let key = client.container_key();
    let Some(container) = root.get(key) else {
        return Ok(Plan {
            new_text: existing.to_string(),
            unchanged: true,
        });
    };
    let Some(container) = container.as_object() else {
        return Err(PlanError::ContainerNotObject);
    };
    if !container.contains_key(SERVER_NAME) {
        return Ok(Plan {
            new_text: existing.to_string(),
            unchanged: true,
        });
    }
    let root_open = skip_ws(existing, 0);
    let span = member_span(existing, root_open, key).ok_or(PlanError::VerifyFailed)?;
    let (members, _close) = object_members(existing, span.value_start);
    let idx = members
        .iter()
        .position(|m| m.key == SERVER_NAME)
        .ok_or(PlanError::VerifyFailed)?;
    let mut new_text = String::with_capacity(existing.len());
    if members.len() == 1 {
        // The only server: leave an empty object in place.
        new_text.push_str(&existing[..span.value_start]);
        new_text.push_str("{}");
        new_text.push_str(&existing[span.value_end..]);
    } else if idx + 1 < members.len() {
        // Not last: from this member's key to the next member's key.
        new_text.push_str(&existing[..members[idx].key_start]);
        new_text.push_str(&existing[members[idx + 1].key_start..]);
    } else {
        // Last: from the previous member's end (taking the comma with it) to this member's end.
        new_text.push_str(&existing[..members[idx - 1].value_end]);
        new_text.push_str(&existing[members[idx].value_end..]);
    }
    let mut expected = original.clone();
    expected
        .as_object_mut()
        .and_then(|r| r.get_mut(key))
        .and_then(Value::as_object_mut)
        .map(|c| c.remove(SERVER_NAME));
    match serde_json::from_str::<Value>(&new_text) {
        Ok(v) if v == expected => Ok(Plan {
            new_text,
            unchanged: false,
        }),
        _ => Err(PlanError::VerifyFailed),
    }
}

/// What a client looks like on this machine (`17 §4.2`: "file existence plus a parse check, never
/// process scanning"; a client that is present but unconfigured is shown as such).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detected {
    /// Neither the config file nor the client's config folder exists.
    NotFound,
    /// The client's folder (or an empty/absent file in it) exists; CredMgr is not wired in.
    Ready,
    /// The file has a matching `credmgr` entry.
    Connected,
    /// The file has a `credmgr` entry that is not the one CredMgr would write.
    OtherEntry,
    /// The file exists and is not a JSON object CredMgr can edit; the reason is for the person.
    Unreadable(String),
}

impl Detected {
    pub fn id(&self) -> &'static str {
        match self {
            Detected::NotFound => "not_found",
            Detected::Ready => "ready",
            Detected::Connected => "connected",
            Detected::OtherEntry => "other_entry",
            Detected::Unreadable(_) => "unreadable",
        }
    }
}

/// `file_text`: the config file's text when it exists; `dir_exists`: the client's config folder.
pub fn detect(file_text: Option<&str>, dir_exists: bool, client: Client, binary: &str) -> Detected {
    match file_text {
        None => {
            if dir_exists {
                Detected::Ready
            } else {
                Detected::NotFound
            }
        }
        Some(t) if t.trim().is_empty() => Detected::Ready,
        Some(t) => match plan_connect(Some(t), client, binary) {
            Ok(p) if p.unchanged => Detected::Connected,
            Ok(_) => Detected::Ready,
            Err(PlanError::DifferentEntryPresent) => Detected::OtherEntry,
            Err(e) => Detected::Unreadable(e.to_string()),
        },
    }
}

/// Is a `credmgr` entry present in `text`? (`false` for unparsable text.)
pub fn has_entry(text: &str, client: Client) -> bool {
    serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| {
            v.get(client.container_key())
                .and_then(|c| c.get(SERVER_NAME))
                .cloned()
        })
        .is_some()
}

// ---- a minimal JSON scanner (the text was already validated by serde_json) ----------------------

#[derive(Debug, Clone)]
struct Member {
    key: String,
    key_start: usize,
    value_start: usize,
    value_end: usize,
}

fn skip_ws(text: &str, mut i: usize) -> usize {
    let b = text.as_bytes();
    while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// End (exclusive) of the JSON string starting at `i` (which is the opening quote).
fn string_end(text: &str, i: usize) -> usize {
    let b = text.as_bytes();
    let mut j = i + 1;
    while j < b.len() {
        match b[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    b.len()
}

/// End (exclusive) of the JSON value starting at `i`.
fn value_end(text: &str, i: usize) -> usize {
    let b = text.as_bytes();
    match b[i] {
        b'"' => string_end(text, i),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut j = i;
            while j < b.len() {
                match b[j] {
                    b'"' => {
                        j = string_end(text, j);
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return j + 1;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            b.len()
        }
        _ => {
            let mut j = i;
            while j < b.len() && !matches!(b[j], b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r')
            {
                j += 1;
            }
            j
        }
    }
}

/// The members of the object whose `{` is at `open`, and the index of its closing `}`.
fn object_members(text: &str, open: usize) -> (Vec<Member>, usize) {
    let b = text.as_bytes();
    let mut members = Vec::new();
    let mut i = skip_ws(text, open + 1);
    loop {
        if i >= b.len() {
            return (members, b.len());
        }
        if b[i] == b'}' {
            return (members, i);
        }
        if b[i] == b',' {
            i = skip_ws(text, i + 1);
            continue;
        }
        let key_start = i;
        let key_end = string_end(text, i);
        let key: String = serde_json::from_str(&text[key_start..key_end]).unwrap_or_default();
        i = skip_ws(text, key_end);
        i = skip_ws(text, i + 1); // the colon
        let value_start = i;
        let ve = value_end(text, i);
        members.push(Member {
            key,
            key_start,
            value_start,
            value_end: ve,
        });
        i = skip_ws(text, ve);
    }
}

fn member_span(text: &str, open: usize, key: &str) -> Option<Member> {
    if text.as_bytes().get(open) != Some(&b'{') {
        return None;
    }
    object_members(text, open)
        .0
        .into_iter()
        .find(|m| m.key == key)
}

/// The leading whitespace of the line that contains byte `at`.
fn line_indent(text: &str, at: usize) -> String {
    let line_start = text[..at].rfind('\n').map_or(0, |p| p + 1);
    text[line_start..at]
        .chars()
        .take_while(|c| *c == ' ' || *c == '\t')
        .collect()
}

/// `"key": {` + the entry lines + `}`, every line indented by `indent` spaces except the first.
fn render_entry_object(lines: &[String], indent: usize) -> String {
    let pad = " ".repeat(indent);
    let mut out = String::from("{\n");
    for (i, l) in lines.iter().enumerate() {
        out.push_str(&pad);
        out.push_str("  ");
        out.push_str(l);
        if i + 1 < lines.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str(&pad);
    out.push('}');
    out
}

/// An object holding the single member `name`, whose value is the entry; the object is itself the
/// value of a member written at `member_indent`, so its members sit two further in and its closing
/// brace at `member_indent`.
fn render_object_of(name: &str, entry_lines: &[String], member_indent: usize) -> String {
    let inner = render_member(
        name,
        &render_entry_object(entry_lines, member_indent + 2),
        member_indent + 2,
    );
    format!("{{\n{inner}\n{}}}", " ".repeat(member_indent))
}

/// `"key": value`, indented by `indent` spaces.
fn render_member(key: &str, value: &str, indent: usize) -> String {
    format!("{}{}: {}", " ".repeat(indent), json_str(key), value)
}

/// Splice `member` (already indented) as the last member of the object whose `{` is at `open`.
/// `closing_indent` is the indentation of the object's own closing brace.
fn insert_member(text: &str, open: usize, member: &str, closing_indent: usize) -> String {
    let (members, close) = object_members(text, open);
    let mut out = String::with_capacity(text.len() + member.len() + 8);
    match members.last() {
        Some(last) => {
            out.push_str(&text[..last.value_end]);
            out.push_str(",\n");
            out.push_str(member);
            out.push_str(&text[last.value_end..]);
        }
        None => {
            out.push_str(&text[..open + 1]);
            out.push('\n');
            out.push_str(member);
            out.push('\n');
            out.push_str(&" ".repeat(closing_indent));
            out.push_str(&text[close..]);
        }
    }
    out
}

// ---- the diff the person sees --------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    /// `' '` context, `'+'` added, `'-'` removed.
    pub kind: char,
    pub text: String,
}

/// A line diff of `old` against `new` with up to `context` unchanged lines either side. A connect
/// or disconnect changes one contiguous region, so the common prefix and suffix are trimmed and
/// what is left is the change; this is not a general diff and is not meant to be.
pub fn line_diff(old: &str, new: &str, context: usize) -> Vec<DiffLine> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let mut pre = 0;
    while pre < a.len() && pre < b.len() && a[pre] == b[pre] {
        pre += 1;
    }
    let mut suf = 0;
    while suf < a.len() - pre && suf < b.len() - pre && a[a.len() - 1 - suf] == b[b.len() - 1 - suf]
    {
        suf += 1;
    }
    let mut out = Vec::new();
    for l in &a[pre.saturating_sub(context)..pre] {
        out.push(DiffLine {
            kind: ' ',
            text: (*l).to_string(),
        });
    }
    for l in &a[pre..a.len() - suf] {
        out.push(DiffLine {
            kind: '-',
            text: (*l).to_string(),
        });
    }
    for l in &b[pre..b.len() - suf] {
        out.push(DiffLine {
            kind: '+',
            text: (*l).to_string(),
        });
    }
    let tail_end = (a.len() - suf + context).min(a.len());
    for l in &a[a.len() - suf..tail_end] {
        out.push(DiffLine {
            kind: ' ',
            text: (*l).to_string(),
        });
    }
    out
}

/// `<file>.credmgr-backup-<ISO8601>` - the copy taken before any write. `stamp` is a basic-format
/// UTC time such as `20261106T101500Z`, supplied by the caller (this crate has no clock).
pub fn backup_name(file_name: &str, stamp: &str) -> String {
    format!("{file_name}.credmgr-backup-{stamp}")
}

// ---- the Vault Protocol prompt and CREDMGR.md ---------------------------------------------------

/// What the prompt knows about the vault: **names and structure only**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultView {
    /// The node the reader works in.
    pub node: String,
    /// Every node id the reader can reach (its own, its ancestors, any grant).
    pub reachable: Vec<String>,
    pub level: SecurityLevel,
}

const PROMPT_TEMPLATE: &str = r#"## Credential access - CredMgr vault protocol

This machine stores every secret in a local encrypted vault called **credmgr**.
Secrets are NOT in .env files, NOT in the repo, and NOT in your context. Get them
from the vault at the moment you need them.

### Where you are
You are scoped to the node **{{node}}**. You can reach: {{reachable}}.
Security level: **{{level}}**. {{level_line}}

### How to read a credential
    credmgr get <NAME>              # value on stdout, nothing logged
    credmgr get <NAME> --json       # value + metadata
    credmgr list                    # everything you can see (names only)
    credmgr search <term>
    credmgr whoami                  # your node, scope, and limits
With MCP available, prefer the tools: credmgr_get, credmgr_list, credmgr_search,
credmgr_whoami.

### How to write one
    credmgr set <NAME> --node <NODE>   # value from stdin - NEVER as an argument
    echo "$VALUE" | credmgr set <NAME> --node <NODE>
    credmgr rotate <NAME>              # replaces a value, keeps history

### Rules you must follow
1. NEVER print a secret value into chat, a log, a commit message, a comment, or a
   file. Pipe it. If you must show it, show `****` and the last 4 characters.
2. NEVER put a secret in a command-line argument - it lands in shell history and
   in `ps` output. stdin, always.
3. NEVER copy a secret into the repository, an .env file, or a config you commit.
   Reference it by NAME. If code needs it at runtime, read it from the vault or
   from an environment variable the operator sets.
4. NEVER try to reach another project's node. You cannot, and attempts are logged.
5. If you are refused, the refusal tells you why and what would fix it. Do not
   retry, do not rephrase, do not look for another route. Tell the operator what
   you need and why, in one sentence, and continue with everything else.
6. You may get `approval_pending`. That is normal: the operator gets a one-tap
   prompt. Wait, or carry on with other work.
7. Fetch what you need EARLY, not in the middle of a long run.

### What you will never be able to do
Create a grant - read another node - read sealed/orphaned data - read a 2FA seed
(you can get a current 6-digit code, except on a Sealed node) - change your own
permissions - purge the audit log. These are absent, not merely gated. Asking
differently will not help.

### If a secret does not exist yet
Do not invent one and do not put a placeholder in the code. Say exactly which
credential is missing and what it is for, and let the operator add it.
"#;

const CREDMGR_MD_TEMPLATE: &str = r#"# CREDMGR.md

<!-- Written by `credmgr agent init`. It contains no secret and no value: only node names, the
     path to the credmgr binary and the rules below. Safe to commit; delete it to undo. -->

This project's credentials live in a local CredMgr vault, not in this repository.

{{prompt}}
### MCP
If your client supports MCP, the server is `{{binary}} mcp` (stdio). Print the exact configuration
for your client with `{{binary}} mcp --print-config <claude-code|claude-desktop|cursor|vscode|windsurf>`.
Without MCP the CLI commands above work the same way.
"#;

/// `17 §5.2` - the Vault Protocol prompt, filled from the live vault.
pub fn vault_protocol_prompt(view: &VaultView) -> String {
    let reachable = if view.reachable.is_empty() {
        "its own node only".to_string()
    } else {
        view.reachable
            .iter()
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let level_line = match view.level {
        SecurityLevel::Open => {
            "Open - you can read and write the values of this node as your access allows, without asking."
        }
        SecurityLevel::Guarded => {
            "Guarded - low and medium values come straight back; a high or critical value waits for the operator's one-tap approval."
        }
        SecurityLevel::Sealed => {
            "Strict - every value waits for the operator's one-tap approval, anything you add waits in a tray for the operator to accept, and you cannot change or remove what exists."
        }
    };
    PROMPT_TEMPLATE
        .replace("{{node}}", &view.node)
        .replace("{{reachable}}", &reachable)
        .replace("{{level_line}}", level_line)
        .replace(
            "{{level}}",
            match view.level {
                SecurityLevel::Sealed => "Strict (stored as sealed)",
                other => other.as_str(),
            },
        )
}

/// `17 §4.3` - the file dropped into a node's work folder. It carries the prompt, how to wire MCP,
/// and the statement that the file itself holds no secret.
pub fn credmgr_md(view: &VaultView, binary: &str) -> String {
    CREDMGR_MD_TEMPLATE
        .replace("{{prompt}}", &vault_protocol_prompt(view))
        .replace("{{binary}}", binary)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BIN: &str = "/opt/homebrew/bin/credmgr";

    fn connect(existing: Option<&str>, c: Client) -> Plan {
        plan_connect(existing, c, BIN).expect("plan")
    }

    #[test]
    fn a_missing_file_gets_a_fresh_document() {
        let p = connect(None, Client::Cursor);
        assert!(!p.unchanged);
        let v: Value = serde_json::from_str(&p.new_text).unwrap();
        assert_eq!(v["mcpServers"]["credmgr"]["command"], BIN);
        assert_eq!(v["mcpServers"]["credmgr"]["args"][0], "mcp");
        assert!(p.new_text.ends_with('\n'));
    }

    #[test]
    fn vscode_uses_servers_and_a_type() {
        let p = connect(None, Client::VsCode);
        let v: Value = serde_json::from_str(&p.new_text).unwrap();
        assert_eq!(v["servers"]["credmgr"]["type"], "stdio");
        assert!(v.get("mcpServers").is_none());
    }

    #[test]
    fn other_servers_and_formatting_survive_byte_for_byte() {
        let old = "{\n    \"theme\":   \"dark\",\n    \"mcpServers\": {\n        \"other\": { \"command\": \"x\",   \"args\": [] }\n    },\n    \"last\": [1, 2,   3]\n}\n";
        let p = connect(Some(old), Client::Cursor);
        assert!(!p.unchanged);
        // Everything before and after the insertion is untouched.
        let at = old.find("\n    },\n    \"last\"").unwrap();
        assert!(p.new_text.starts_with(&old[..at]));
        assert!(p.new_text.ends_with(&old[at..]));
        let v: Value = serde_json::from_str(&p.new_text).unwrap();
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert_eq!(v["mcpServers"]["credmgr"]["command"], BIN);
        // The new member uses the file's own indentation (8 spaces for a server).
        assert!(p.new_text.contains("\n        \"credmgr\": {\n"));
    }

    #[test]
    fn a_file_without_the_servers_key_gets_one() {
        let old = "{\n  \"a\": 1\n}\n";
        let p = connect(Some(old), Client::Windsurf);
        let v: Value = serde_json::from_str(&p.new_text).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["mcpServers"]["credmgr"]["args"][0], "mcp");
        assert!(p
            .new_text
            .starts_with("{\n  \"a\": 1,\n  \"mcpServers\": {"));
    }

    #[test]
    fn an_empty_object_and_an_empty_servers_object_work() {
        for old in [
            "{}",
            "{ }\n",
            "{\n  \"mcpServers\": {}\n}\n",
            "{\"mcpServers\":{}}",
        ] {
            let p = connect(Some(old), Client::ClaudeDesktop);
            let v: Value = serde_json::from_str(&p.new_text).unwrap();
            assert_eq!(v["mcpServers"]["credmgr"]["command"], BIN, "{old:?}");
        }
    }

    #[test]
    fn connecting_twice_changes_nothing() {
        let first = connect(None, Client::Cursor);
        let second = connect(Some(&first.new_text), Client::Cursor);
        assert!(second.unchanged);
        assert_eq!(second.new_text, first.new_text);
    }

    #[test]
    fn a_different_credmgr_entry_is_never_replaced() {
        let old = "{\"mcpServers\":{\"credmgr\":{\"command\":\"/elsewhere/credmgr\",\"args\":[\"mcp\"]}}}";
        assert_eq!(
            plan_connect(Some(old), Client::Cursor, BIN),
            Err(PlanError::DifferentEntryPresent)
        );
    }

    #[test]
    fn a_file_that_is_not_json_is_refused_and_not_touched() {
        let old = "{\n  // a comment\n  \"mcpServers\": {}\n}\n";
        assert!(matches!(
            plan_connect(Some(old), Client::VsCode, BIN),
            Err(PlanError::NotJson(_))
        ));
        assert_eq!(
            plan_connect(Some("[1]"), Client::Cursor, BIN),
            Err(PlanError::RootNotObject)
        );
        assert_eq!(
            plan_connect(Some("{\"mcpServers\": 3}"), Client::Cursor, BIN),
            Err(PlanError::ContainerNotObject)
        );
    }

    #[test]
    fn strings_that_look_like_json_do_not_confuse_the_scanner() {
        let old = "{\"note\": \"}{ \\\"mcpServers\\\": [ , ] \", \"mcpServers\": {\"a\": {\"command\": \"}\"}}}";
        let p = connect(Some(old), Client::Cursor);
        let v: Value = serde_json::from_str(&p.new_text).unwrap();
        assert_eq!(v["mcpServers"]["a"]["command"], "}");
        assert_eq!(v["mcpServers"]["credmgr"]["command"], BIN);
    }

    #[test]
    fn a_binary_path_with_quotes_and_spaces_is_escaped() {
        let p = plan_connect(None, Client::Cursor, "/opt/a b/\"x\"/credmgr").unwrap();
        let v: Value = serde_json::from_str(&p.new_text).unwrap();
        assert_eq!(
            v["mcpServers"]["credmgr"]["command"],
            "/opt/a b/\"x\"/credmgr"
        );
    }

    #[test]
    fn disconnect_removes_only_our_entry() {
        let with = connect(
            Some("{\n  \"mcpServers\": {\n    \"other\": {\"command\": \"x\"}\n  }\n}\n"),
            Client::Cursor,
        );
        let gone = plan_disconnect(&with.new_text, Client::Cursor).unwrap();
        let v: Value = serde_json::from_str(&gone.new_text).unwrap();
        assert!(v["mcpServers"].get("credmgr").is_none());
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        // Order variants: ours first, ours in the middle, ours alone.
        for old in [
            "{\"mcpServers\":{\"credmgr\":{\"command\":\"c\"},\"b\":{}}}",
            "{\"mcpServers\":{\"a\":{},\"credmgr\":{\"command\":\"c\"},\"b\":{}}}",
            "{\"mcpServers\":{\"credmgr\":{\"command\":\"c\"}}}",
            "{\n  \"mcpServers\": {\n    \"credmgr\": {\n      \"command\": \"c\"\n    }\n  }\n}\n",
        ] {
            let p = plan_disconnect(old, Client::Cursor).unwrap();
            let v: Value = serde_json::from_str(&p.new_text).unwrap();
            assert!(v["mcpServers"].get("credmgr").is_none(), "{old}");
        }
        let nothing = plan_disconnect("{\"a\":1}", Client::Cursor).unwrap();
        assert!(nothing.unchanged);
    }

    #[test]
    fn connect_then_disconnect_restores_the_document() {
        let old = "{\n  \"mcpServers\": {\n    \"other\": { \"command\": \"x\" }\n  },\n  \"z\": true\n}\n";
        let c = connect(Some(old), Client::Cursor);
        let d = plan_disconnect(&c.new_text, Client::Cursor).unwrap();
        let a: Value = serde_json::from_str(old).unwrap();
        let b: Value = serde_json::from_str(&d.new_text).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn the_diff_shows_only_the_added_lines() {
        let old = "{\n  \"mcpServers\": {\n    \"a\": {}\n  }\n}\n";
        let c = connect(Some(old), Client::Cursor);
        let d = line_diff(old, &c.new_text, 2);
        assert!(d
            .iter()
            .any(|l| l.kind == '+' && l.text.contains("\"credmgr\"")));
        assert!(d
            .iter()
            .all(|l| l.kind != '-' || l.text.trim() == "\"a\": {}"));
    }

    #[test]
    fn claude_code_is_shown_never_written() {
        assert!(!Client::ClaudeCode.writable());
        assert!(Client::Cursor.writable());
        let c = claude_code_command("/opt/homebrew/bin/credmgr");
        assert_eq!(
            c,
            "claude mcp add --scope user credmgr -- /opt/homebrew/bin/credmgr mcp"
        );
        assert!(claude_code_command("/opt/a b/credmgr").contains("'/opt/a b/credmgr'"));
    }

    #[test]
    fn client_names_parse_and_roundtrip() {
        for c in CLIENTS {
            assert_eq!(Client::parse(c.id()), Some(c));
        }
        assert_eq!(Client::parse("Copilot"), Some(Client::VsCode));
        assert_eq!(Client::parse("nope"), None);
    }

    #[test]
    fn the_prompt_carries_names_and_the_level_and_no_value() {
        let view = VaultView {
            node: "acme".into(),
            reachable: vec!["acme".into(), "global".into()],
            level: SecurityLevel::Sealed,
        };
        let p = vault_protocol_prompt(&view);
        assert!(p.contains("**acme**"));
        assert!(p.contains("`acme`, `global`"));
        assert!(p.contains("**Strict (stored as sealed)**"));
        assert!(p.contains("Strict - every value waits"));
        assert!(!p.contains("Sealed -"));
        assert!(p.contains("NEVER print a secret value"));
        let md = credmgr_md(&view, BIN);
        assert!(md.contains("contains no secret"));
        assert!(md.contains("mcp --print-config"));
    }
}
