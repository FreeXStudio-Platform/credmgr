<!-- artifact-hardened: NEEDS RE-HARDENING — generated 2026-10-31 -->

# CredMgr help

What CredMgr 2.0.0-beta.1 can do, and where to find each thing: which screen, button, menu, shortcut or command.

This file is generated from `docs/help/features.json` by `tools/gen_help.py`; edit that file, never this one. The desktop app's Help (the **?** button in the header) holds the same list with a search box. An AI agent should read `docs/llm/credmgr-capabilities.json` instead.

Topics marked **Partly working** work in some places and not others; **Planned** ones are listed so you know they are missing, and nothing here describes them as working.

## Contents

| Section | Topics |
|---|---|
| [First run and recovery](#first-run-and-recovery) | 5 |
| [Unlocking, locking and the menu-bar icon](#unlocking-locking-and-the-menu-bar-icon) | 8 |
| [Graph, tree and search](#graph-tree-and-search) | 8 |
| [Projects and nodes](#projects-and-nodes) | 12 |
| [Entries and notes](#entries-and-notes) | 12 |
| [Fields, reveal and copy](#fields-reveal-and-copy) | 9 |
| [Authenticator codes you store](#authenticator-codes-you-store) | 3 |
| [The vault's second factor](#the-vaults-second-factor) | 5 |
| [Agent requests while locked](#agent-requests-while-locked) | 2 |
| [Writes made while locked](#writes-made-while-locked) | 3 |
| [Grants](#grants) | 4 |
| [Sealing and restoring](#sealing-and-restoring) | 3 |
| [Audit](#audit) | 3 |
| [Backup, checks and maintenance](#backup-checks-and-maintenance) | 6 |
| [Importing](#importing) | 1 |
| [Settings](#settings) | 7 |
| [Cosmetics, games and donations](#cosmetics-games-and-donations) | 4 |
| [AI agents and the MCP server](#ai-agents-and-the-mcp-server) | 10 |
| [Command line and broker](#command-line-and-broker) | 6 |
| [Keyboard shortcuts](#keyboard-shortcuts) | 10 |
| [About, privacy and licence](#about-privacy-and-licence) | 4 |
| [Planned, not in this build](#planned-not-in-this-build) | 17 |

142 topics in 22 sections.

## First run and recovery

### Create the vault: choose a passphrase

The first time the app starts with no vault, it asks you to choose a passphrase (step 1 of 4). The passphrase opens the vault on this machine; nothing is created anywhere else. Nothing in this version can recover a lost passphrase.

- **Where:** App: first run, step 1 of 4. CLI: credmgr init
- **How:**
  1. Type a passphrase of at least 4 characters (8 or more is recommended).
  2. Type it again to confirm.
  3. Choose Next.
- **Command line:** `credmgr init`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** new vault, create vault, setup, install, first launch, onboarding, init, password, master password, passphrase

### Recovery code, shown once

Step 2 shows a 256-bit root recovery code once. Together with your passphrase it resets the second factor if you lose your authenticator. Write it on paper and keep it away from the passphrase. Retyping it is optional in the app; the CLI requires the retype before it writes anything.

- **Where:** App: first run, step 2 of 4. CLI: credmgr init (retype when asked)
- **How:**
  1. Copy the code onto paper.
  2. Optionally retype it to prove you have it, or skip.
  3. Choose Next.
- **Command line:** `credmgr init`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** recovery code, root recovery, backup code, lost authenticator, write down, paper, init confirm

### Optional second factor at first run

Step 3 offers to set up a second factor (an authenticator app). The QR code is drawn inside the window and nothing is sent anywhere. After you confirm one code, ten one-time recovery codes are shown once. You may skip it and enrol later in Settings; until you do, the vault rests on the passphrase alone.

- **Where:** App: first run, step 3 of 4 (Enrol later to skip)
- **How:**
  1. Scan the QR code, or type the key by hand.
  2. Enter one 6-digit code to confirm.
  3. Save the ten recovery codes, then continue.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** 2fa, authenticator, totp, qr code, two factor, mfa, google authenticator, enrol, enroll

### Name your first projects

Step 4 creates up to three starting projects. Global is created automatically, and so is the Orphaned node that sealing needs. Each project is its own boundary: what is stored in one is invisible to the others. A new vault starts empty; nothing is imported.

- **Where:** App: first run, step 4 of 4
- **How:**
  1. Type up to three project names, or leave them blank.
  2. Finish. You land on the graph.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** first project, initial nodes, starter projects, global, empty vault

### The broker is not running

If the app shows 'credmgr cannot reach its broker', the credmgrd process is not running or its socket is not where the app looks. Start credmgrd in a terminal or let launchd keep it running, then choose Retry. Nothing from the last session is shown.

- **Where:** App: startup screen. Terminal: credmgrd
- **How:**
  1. Run credmgrd, or install the launchd unit from the release package.
  2. Choose Retry.
- **Also searched as:** cannot reach broker, credmgrd not running, socket, starting credmgr, could not start, launchd, daemon

## Unlocking, locking and the menu-bar icon

### Unlock with your passphrase

The Lock screen asks for the passphrase. Wrong tries count toward a back-off that grows with each failure; while backed off, the broker answers rate_limited with the seconds to wait.

- **Where:** App: Lock screen > passphrase. CLI: credmgr unlock
- **How:**
  1. Type the passphrase.
  2. Press Enter or choose Unlock.
  3. If two-factor is on, the screen asks for a code next.
- **Command line:** `credmgr unlock`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** login, sign in, open vault, locked screen, password, back-off, rate limited, too many attempts

### Unlock with a second-factor code

When the vault has a second factor, unlocking asks for the 6 digits from your authenticator, or one of your ten recovery codes (each works once). On the command line, credmgr unlock answers two_factor_required and credmgr gate verify completes it.

- **Where:** App: Lock screen > 2FA code. CLI: credmgr gate verify <code>
- **How:**
  1. Enter the 6-digit code or a recovery code.
  2. Choose Verify.
- **Command line:** `credmgr gate verify <code>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** 2fa code, authenticator code, recovery code, verify, two_factor_required, otp

### Lock the vault now

Locking ends every login, clears a copied secret from the clipboard and returns the app to the Lock screen. It works from anywhere, including while typing or with a dialog open.

- **Where:** App: header lock chip, vault menu > Lock vault, or the shortcut Cmd+L. CLI: credmgr lock
- **How:** Press Cmd+L, or choose the 'unlocked' chip in the header.
- **Command line:** `credmgr lock`
- **Also searched as:** lock, log out, sign out, cmd l, lock vault, end session

### Auto-lock after idle time

The app locks itself after a period with no activity: 5, 15 or 60 minutes, or never (the setting warns). Even when set to never, the broker still locks on its own idle timer (15 minutes by default). Hiding the window also locks when auto-lock is on.

- **Where:** App: Settings > Security > Auto-lock
- **How:**
  1. Open Settings (the gear in the header).
  2. Choose Security.
  3. Pick a time in Auto-lock.
- **Also searched as:** idle, timeout, inactivity, auto lock, lock after, minutes

### Lock on sleep, screen lock and window close

The desktop app locks the vault when the Mac sleeps, when the screen locks, when another user session takes over, and when you close the window. The Lock screen says why it locked. A daemon running without the app does not do this.

- **Where:** App: automatic. Menu-bar icon > Lock vault locks on demand
- **How:**
  1. Nothing to do; it happens by itself.
  2. The Lock screen shows a note such as 'Locked because this Mac went to sleep.'
- **Also searched as:** sleep, screen lock, lid, fast user switching, close window, locked because

### Lock a single node

A node can be locked on its own while the vault stays unlocked. Names and types stay visible but values need the node unlocked. A node's policy can lock it after a number of idle seconds.

- **Where:** App: node right-click or the three-dot menu > Lock now / Unlock node; inspector > Unlock node. CLI: node policy --lock-after-seconds
- **How:**
  1. Right-click the node, choose Lock now.
  2. To reopen it, choose Unlock node.
- **Command line:** `credmgr node policy <id> --reason "..." --lock-after-seconds <n>|none`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** node lock, lock project, lock wallet node, unlock node, lock now, lock after seconds

### Unlock a single node

Reopens a node that was locked on its own (by hand or by its idle timer) without touching the rest of the vault. Names and types are visible while it is locked; values and field labels need it unlocked. If a node says it is locked, this is the fix. There is no CLI command for it yet; use the app.

- **Where:** App: node menu > Unlock node; inspector > Unlock node
- **How:** Right-click the node, choose Unlock node.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** unlock node, node locked, node_locked, reopen node

### Menu-bar icon

The app stays reachable after its window is closed. Left-click the icon to show the window. Right-click (or Ctrl-click) for Open CredMgr, Lock vault and Quit CredMgr. Closing the window hides it and locks the vault; Quit locks it too. Clicking the Dock icon also shows the window.

- **Where:** App: macOS menu bar
- **How:** Right-click the icon for the menu.
- **Also searched as:** tray, menu bar, status bar, quit, dock, close window

## Graph, tree and search

### The graph

The main view draws your nodes as a graph. A filled circle is global, a ringed circle a project, a thinner ring a sub-node, a dashed ring the Orphaned node. Small dots around a node are its entries; their colour is a hash of the entry id, never a name or value. You can drag nodes to arrange them; positions are remembered on this device under hashed ids.

- **Where:** App: main area, graph mode (the 'graph' button in the left rail)
- **How:**
  1. Click a node to select it and open the inspector.
  2. Drag a node to move it.
  3. Press F to fit the graph to the window.
- **Also searched as:** graph, map, nodes, circles, legend, dots, orbit, canvas, layout

### Hover cards

Hovering a node shows how many entries it holds and how many of them are authenticator seeds. Hovering an entry dot shows its entry type. Nothing about names or values.

- **Where:** App: hover over a node or an entry dot on the graph
- **How:** Point at a node.
- **Also searched as:** tooltip, counts, entries count, 2fa count, hover

### The tree view

The tree is a full keyboard- and screen-reader-accessible peer to the graph, with the same information and the same node menu. It is not a fallback.

- **Where:** App: 'tree' button in the left rail, or press T
- **How:**
  1. Press T to switch between graph and tree.
  2. Use the three-dot button on a row for the node menu.
- **Also searched as:** tree, list view, accessible, screen reader, keyboard, outline

### The left rail

The rail lists every node with its badges and entry count, plus the Orphaned node. On a narrow window it is hidden behind the menu button (three lines) in the header. Right-click a row for the node menu.

- **Where:** App: left rail (the menu button opens it on a narrow window)
- **How:**
  1. Click a row to select the node.
  2. Right-click a row for Open, New entry, Rename, Lock and more.
- **Also searched as:** worktree, sidebar, nodes list, hamburger, menu button

### The node menu

Right-clicking a node (or the three-dot button in the tree) offers Open, New entry, New project or New sub-node, Grant access, Rename, Lock now or Unlock node, and Remove node. Global has no Rename or Remove. The Orphaned node only offers Open.

- **Where:** App: right-click a node in the graph or rail; three-dot button in the tree
- **How:**
  1. Right-click the node.
  2. Choose an item.
- **Also searched as:** context menu, right click, node actions, three dots, kebab

### Search

The header search box finds node names in the page and entry names through the broker's search. It matches names only: field labels and values are never searched. It shows up to nine rows and says how many more there are. With an empty box it offers 'Add new' and, in Pro mode, recent nodes.

- **Where:** App: header search box, or press / to focus it. CLI: credmgr search <term>
- **How:**
  1. Press / (or click the box) and type.
  2. Choose a row to select the node or open the entry.
- **Command line:** `credmgr search <term> [--json]`
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** find, lookup, search bar, filter, entry name

### Entries: all nodes or selected only

The graph can show every node's entry dots at once or only the selected node's. The choice is remembered.

- **Where:** App: button at the top of the graph, or press E
- **How:** Press E to toggle.
- **Also searched as:** entry dots, show entries, all nodes, selected node

### The Orphaned node

*Partly working.*

Orphaned holds sealed items. Names stay visible; the values are human-only and this build cannot open them, because that needs a presence check (Touch ID) it cannot make yet. The open button asks the broker and is refused.

- **Where:** App: left rail > orphaned, or vault menu > Orphaned
- **How:**
  1. Select orphaned in the rail.
  2. Read the list of names.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** orphan, sealed items, orphaned node, cold key

## Projects and nodes

### Create a project

A project is a boundary: it has its own key, notes and agent scope, and projects never read each other. The dialog takes a name, a parent and optional work folders. In Pro mode an advanced block sets agent access, second-factor requirement, hidden name and sibling sharing at creation.

- **Where:** App: right-click global > New project; Settings > Nodes > + New project (Pro); the empty-graph button. CLI: credmgr node create
- **How:**
  1. Open the dialog from one of the places above.
  2. Type a name (1 to 120 characters).
  3. Pick the parent: global makes a project.
  4. Choose Create node.
- **Command line:** `credmgr node create <id> --parent <id> [--label <l>] [--workdir <dir>]...`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** new project, new node, add project, boundary, create node, workspace

### Create a sub-node

A sub-node lives under a project. The tree stops at two levels, so a sub-node cannot have children.

- **Where:** App: right-click a project > New sub-node
- **How:**
  1. Right-click the project.
  2. Choose New sub-node.
  3. Name it and choose Create node.
- **Command line:** `credmgr node create <id> --parent <project> --label <l>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** sub node, child node, environment, dev staging prod, depth 2

### Work folders: scope an agent to a node

Binding folders to a node means any process started inside one of them, such as an AI coding agent, is scoped to that node automatically: it can read the node and its ancestors, never another project. The longest matching folder wins. An agent started outside every bound folder sees only that the vault exists.

- **Where:** App: New node dialog > work folders. CLI: credmgr node workdir <id> <dir>...
- **How:**
  1. Add a folder when creating the node, or run credmgr node workdir <id> <dir>.
  2. Run credmgr node workdir <id> with no folder to clear the list.
- **Command line:** `credmgr node workdir <id> [<dir>...]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** workdir, working directory, cwd, bind folder, scope agent, project folder, agent scope

### Rename a node

Renaming changes the display name only; the node id never changes. Global cannot be renamed.

- **Where:** App: right-click a node > Rename, then Enter or click away. CLI: credmgr node rename
- **How:** Choose Rename, type the new name, press Enter. Esc cancels.
- **Command line:** `credmgr node rename <id> <label>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** rename project, change label, display name

### Node policy: agent access

*Partly working.*

Sets what an agent scoped to this node may do: read-write (list, read metadata, reveal, create, update), read-only (list, read metadata, reveal) or none. In the app it is chosen when the node is created (Pro mode); change it later with the CLI.

- **Where:** App: New node dialog > advanced (Pro). CLI: credmgr node policy
- **How:** Run credmgr node policy <id> --reason "why" --agent-access read-only.
- **Command line:** `credmgr node policy <id> --reason "..." --agent-access read-write|read-only|none`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** agent access, read-only agent, read-write, policy, agentAccess, permissions

### Node policy: require a second factor

*Partly working.*

With a vault second factor set up, a node can ask callers other than you for a fresh code: 'reveal' asks before a value leaves the vault, 'always' asks before any read of the node. Your own login is not asked. The factor and the five-minute window belong to the whole vault, not to one node.

- **Where:** App: New node dialog > advanced (Pro); the node shows a chip when it is set. CLI: credmgr node policy --require-two-factor
- **How:** Run credmgr node policy <id> --reason "why" --require-two-factor reveal.
- **Command line:** `credmgr node policy <id> --reason "..." --require-two-factor never|reveal|always`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** requireTwoFactor, 2fa on reveal, wallet node, always, reveal level

### Node policy: hide the node's name

*Partly working.*

A node with hidden names shows other callers an opaque row instead of its label, entry names and notes. The node id is opaque and fixed when the node is created.

- **Where:** App: New node dialog > 'Hide this node's name' (Pro). CLI: credmgr node policy --private-names
- **How:** Tick the option when creating the node, or run credmgr node policy <id> --reason "why" --private-names.
- **Command line:** `credmgr node policy <id> --reason "..." --private-names|--no-private-names`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** privateNames, hidden name, opaque, nameHidden, secret project

### Node policy: sibling and descendant reading

*Partly working.*

Two options widen who can read: sub-nodes seeing each other (siblings shared) and a node reading its children. Turning either off is immediate. Turning either on needs a presence check this build cannot make, so the broker refuses and applies nothing.

- **Where:** CLI: credmgr node policy --sibling-visibility, --descendant-read
- **How:** Run credmgr node policy with --sibling-visibility isolated or --no-descendant-read to narrow.
- **Command line:** `credmgr node policy <id> --reason "..." --sibling-visibility shared|isolated --descendant-read|--no-descendant-read`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** siblingVisibility, descendantRead, share between sub-nodes, widen

### Node policy: lock a node after idle seconds

*Partly working.*

A node can carry its own idle timer. When it runs out the node locks while the vault stays open.

- **Where:** CLI: credmgr node policy --lock-after-seconds <n>|none
- **How:** Run credmgr node policy <id> --reason "why" --lock-after-seconds 600.
- **Command line:** `credmgr node policy <id> --reason "..." --lock-after-seconds <n>|none`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** lockAfterSeconds, idle node, wallet, auto lock node

### Node notes

Each node can hold one markdown note, sealed under the node's key. The inspector shows it. Writing a note is a CLI action; an empty input is refused so a failed pipe cannot erase a note, and 'notes clear' is the only deletion. Agents never hold the notes capability.

- **Where:** App: inspector > notes (read). CLI: credmgr notes show | set | clear
- **How:**
  1. Run credmgr notes set <id> --file ./notes.md.
  2. Run credmgr notes show <id>.
- **Command line:** `credmgr notes show <id> | set <id> [--file <path>] | clear <id>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** note, markdown, node note, context, readme

### Write or clear a node note

*Partly working.*

Notes are written on the command line: credmgr notes set takes the text from a file or stdin and refuses empty input, and credmgr notes clear is the only way to delete one. The desktop app shows a note but has no editor for it.

- **Where:** CLI: credmgr notes set <id> [--file <path>], credmgr notes clear <id>
- **How:** Run credmgr notes set acme --file ./notes.md.
- **Command line:** `credmgr notes set <id> [--file <path>] | clear <id>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** write note, edit note, clear note, notes set

### Move a node under a different parent

*Planned.*

Re-parenting changes which nodes can read a node, which is a grant by another name, so it needs presence. The operation exists and refuses everyone in this build.

- **Where:** No control in the app or CLI
- **How:** Not available.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** reparent, move node, change parent

## Entries and notes

### Add an entry

An entry is one named secret that can hold any number of fields, each with a label you choose. The dialog asks where (which node), a name (up to 200 characters), and either a single set of fields or a bulk paste. A preview shows exactly what will be stored; nothing is written until you save. If the node or vault is locked the entry is held for review instead (see Writes made while locked).

- **Where:** App: inspector > + New entry, press N, node menu > New entry, or search > Add new. CLI: credmgr set <name> --node <id>
- **How:**
  1. Press N.
  2. Pick the node and type a name.
  3. Enter label and value, or switch to Bulk.
  4. Check the preview, then choose Save (or Save and add another).
- **Command line:** `credmgr set <name> --node <id> [--label <l>]`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** new entry, add secret, add credential, store password, create secret, save api key, add item

### Bulk paste: one entry from many lines

Bulk mode takes a paste of 'label: value' lines (a colon followed by a space) and turns it into one entry with one field per line. A line of three slashes separates blocks, so a value can span lines, such as a private key. A box can split each slash-separated block into its own entry. The preview shows the result before you save.

- **Where:** App: Add entry dialog > Bulk. CLI: credmgr set <name> --node <id> --bulk
- **How:**
  1. Choose Bulk.
  2. Paste the text.
  3. Check the preview, optionally tick 'split each /// segment into its own entry', then save.
- **Command line:** `credmgr set <name> --node <id> --bulk`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** paste, env file, multiple fields, label value, split, slashes, private key block, server credentials

### Entry type and sensitivity

Every entry has a type (server, database, api, wallet, login, ssh, certificate, token, totp, env-bundle, note or other) and a sensitivity (low, medium, high, critical). Both are inferred from the fields and can be pinned; 'auto' returns to inferring. A seed phrase or private key raises sensitivity to critical.

- **Where:** App: Add entry dialog > entry type; preview shows the inferred sensitivity
- **How:** Leave 'auto', or pick a type in the entry type list.
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** entry type, sensitivity, critical, classification, category, infer

### Add a note (free-text entry)

A note is an entry whose single value is free text, for anything that is not a credential. It is audited like any entry. It is different from the node note, which is one markdown page per node.

- **Where:** App: inspector > + New note
- **How:**
  1. Select a node.
  2. Choose + New note.
  3. Type the text and save.
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** note, free text, memo, secure note

### List the entries of a node

The inspector lists a node's entries with their type and a 2FA badge. A node you cannot read, or one that is locked, says so instead of showing an empty list.

- **Where:** App: select a node; inspector on the right. CLI: credmgr list [--node <id>]
- **How:**
  1. Click the node.
  2. Read the list.
- **Command line:** `credmgr list [--node <id>] [--json]`
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** list entries, inventory, names, show secrets, browse

### Open an entry and see its fields

Opening an entry shows its fields: label, type, and a masked value. The broker answers with field ids, labels, types and masking and never a value; values appear only when you reveal or copy one. Labels are encrypted with the values, so a locked node shows only names and types.

- **Where:** App: click an entry in the inspector. CLI: credmgr field ls <name>
- **How:**
  1. Click the entry name.
  2. Use the back arrow to return to the node.
- **Command line:** `credmgr field ls <name> [--node <id>] [--json]`
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** entry detail, metadata, labels, field list, entry.get, inspect

### Replace a value

Replaces one field's value, or the whole field list, in place. It keeps no history. Use rotate when the old value should be kept.

- **Where:** CLI: credmgr set <name> --node <id> --field <label>. App: field menu > Edit
- **How:** Pipe the new value on stdin: credmgr set vps --node acme --field password.
- **Command line:** `credmgr set <name> --node <id> (--field <label> | --field-id <id>) [--label <new>]`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** change password, overwrite, edit value, update secret

### Rotate a secret and keep history

Rotation replaces the value and keeps the previous one as history, so it can be undone with no time limit. A legitimate rotation implies you could have read what you replace, so it needs the vault unlocked.

- **Where:** CLI: credmgr rotate <name>
- **How:** Pipe the new value on stdin: credmgr rotate API_KEY --node acme.
- **Command line:** `credmgr rotate <name> [--node <id>] [--field <label> | --field-id <id>]`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** rotate, renew, new key, history, previous value, key rotation

### Remove an entry (soft delete)

*Partly working.*

Removing hides the entry from lists and search at once and keeps it for seven days, when undo can bring it back. The desktop app has no control for this yet; use the CLI.

- **Where:** CLI: credmgr rm <name>. App: no control
- **How:**
  1. Run credmgr rm <name> --node <id>.
  2. To bring it back inside seven days, run credmgr undo <audit id> --node <id>.
- **Command line:** `credmgr rm <name> [--node <id>]`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** delete, trash, remove secret, 7 day, recover deleted

### Undo a change

Undo reverses a rotation, a field change or a removal, addressed by the audit record id. A removal can be undone for seven days and a field change for seven days; a rotation has no limit. In the app the inspector shows 'Undo' for the most recent change on the node while nothing else has changed it. Undo is itself an audited action.

- **Where:** App: inspector > Undo button under the fields. CLI: credmgr undo <audit id> --node <id>
- **How:**
  1. Find the id with credmgr audit, then run credmgr undo <id> --node <node>.
  2. If the name was reused, add --mode keep-both.
- **Command line:** `credmgr undo <id> --node <id> [--mode replace|keep-both]`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** undo, revert, restore entry, oops, mistake, audit id, keep-both

### Generate a password

The broker can generate a random password of 8 to 128 characters, with symbols on or off, or a pronounceable form, and tells you its strength. The value appears in the answer only; it is not stored or audited until you save it in a field.

- **Where:** App: Add field dialog > Generate. CLI: credmgr generate
- **How:**
  1. Open + Add field.
  2. Set the length and options.
  3. Choose Generate, then save the field.
- **Command line:** `credmgr generate [--length <n>] [--no-symbols] [--pronounceable] [--json]`
- **Also searched as:** generate, random password, password generator, entropy, pronounceable, strong password

### Entry and node name rules

Names are compared in one canonical form, so a look-alike of an existing name (different case, width, invisible characters or look-alike letters) is refused as already existing, for agents too. A name that mixes Latin with Greek or Cyrillic letters is accepted with a warning. Entry names are at most 200 characters; node labels 1 to 120.

- **Where:** Applies wherever a name is typed
- **How:** Choose a different name if you see 'already exists'.
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** duplicate, look-alike, homoglyph, mixed script, entry exists, unicode, name length

## Fields, reveal and copy

### Add a field

Adds one or more fields to an entry, appended or inserted at a position. The label is free text and may be empty; there are no fixed field names. The type and whether it is hidden are inferred from the label and value.

- **Where:** App: open an entry > + Add field. CLI: credmgr field add
- **How:**
  1. Open the entry.
  2. Choose + Add field.
  3. Type a label and a value (or Generate), then save.
- **Command line:** `credmgr field add <name> (--label <l> | --bulk) [--at <n>]`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** add field, new field, extra field, label, append

### Edit a field

Changes a field's label, value, type or hidden state. The current value is never shown in the dialog; leave the new value empty to keep it. Only what you change is sent. The previous state is kept as history.

- **Where:** App: field three-dot menu > Edit. CLI: credmgr field set
- **How:**
  1. Open the field menu and choose Edit.
  2. Change what you need and save.
- **Command line:** `credmgr field set <name> (--field <l> | --field-id <id>) [--label <new>] [--type <t>|auto] [--mask on|off|auto]`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** edit field, rename label, change type, mask, hidden, pin type

### Remove a field

Removes one field from an entry. An entry keeps at least one field; remove the entry instead. Undoable.

- **Where:** App: field three-dot menu > Remove. CLI: credmgr field rm
- **How:** Open the field menu, choose Remove, confirm.
- **Command line:** `credmgr field rm <name> (--field <l> | --field-id <id>)`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** delete field, remove field

### Reorder fields

Moves a field up or down. Order is presentation only.

- **Where:** App: field three-dot menu > Move up / Move down. CLI: credmgr field mv
- **How:** Open the field menu and choose Move up or Move down.
- **Command line:** `credmgr field mv <name> (--field <l> | --field-id <id>) --to <n>`
- **Also searched as:** move field, order, sort, position

### Field types and hidden values

A field has one of eleven types: password, api-key, private-key, seed-phrase, totp-seed, username, host, port, url, certificate, text. The type is inferred from label and value and can be pinned. Password, api-key, private-key, seed-phrase and totp-seed fields are hidden by default; any field can be pinned shown or hidden.

- **Where:** App: Add entry preview and Edit field dialog
- **How:** Pick a type in the preview list, or choose auto.
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** type, masked, mask, hidden, show, password field, seed phrase, api key

### Reveal a value

Reveal fetches one field's value and shows it for the reveal window (10, 20 or 60 seconds; 20 by default), then hides it again with a countdown. Each reveal is audited. An agent asking the broker for a value goes through the same gate: if the vault is locked the request waits for you; if the node asks for a second factor it needs a fresh code.

- **Where:** App: open an entry > Reveal on a field. CLI: credmgr get <name> --field <label>
- **How:**
  1. Open the entry.
  2. Choose Reveal on the field.
  3. The value hides again when the countdown ends or you lock.
- **Command line:** `credmgr get <name> [--node <id>] [--field <label> | --field-id <id> | --all] [--json]`
- **AI agents:** An AI agent can ask for this through MCP; a locked vault or a node that asks for a second factor makes it wait for you.
- **Also searched as:** show password, reveal, view secret, unmask, see value, get secret

### Copy a value without revealing it

Copy places the value on the clipboard through the app's native shell and never passes it through the window. The clipboard is cleared after 30 seconds and when the vault locks. Every copy is audited.

- **Where:** App: field row > Copy
- **How:**
  1. Choose Copy on the field.
  2. Paste within 30 seconds.
- **Also searched as:** clipboard, copy password, paste, concealed, 30 seconds

### Read a value on the command line

credmgr get prints one value on stdout. An entry with several fields needs a selector (--field, --field-id) or --all; without one it exits 2 and lists the labels. --json prints the fields.

- **Where:** CLI: credmgr get
- **How:**
  1. credmgr get API_KEY --node acme
  2. credmgr get vps --node acme --field password
- **Command line:** `credmgr get <name> [--node <id>] [--field <label> | --field-id <id> | --all] [--json]`
- **AI agents:** An AI agent can ask for this through MCP; a locked vault or a node that asks for a second factor makes it wait for you.
- **Also searched as:** cli read, stdout, pipe, env var, script

### Conflict protection on writes

Every change to an existing entry carries the entry's current generation. If something else changed it first, the broker answers conflict with both generations and nothing is applied. Re-read, re-apply, retry once.

- **Where:** Automatic
- **How:** On a conflict, read the entry again and repeat the change.
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** generation, conflict, concurrent edit, stale

## Authenticator codes you store

### Store an authenticator seed

A field holding an otpauth URI, a base32 secret of a standard length (16, 20, 24, 26, 32, 40, 52, 56 or 64 characters, upper case or in groups of four), or a field typed totp-seed is a stored authenticator seed. The entry gets a 2FA badge and counts toward the node's 2FA number. This is separate from the vault's own second factor.

- **Where:** App: Add entry with a seed field. CLI: credmgr set <name> --node <id>
- **How:**
  1. Add a field whose value is the seed.
  2. The entry shows a 2FA badge.
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** totp, authenticator, 2fa seed, otpauth, base32, mfa secret

### Show the current 6-digit code

Revealing a seed field shows the current 6-digit code with a bar that runs to the end of its 30-second step. The seed itself is never shown or returned: a reveal of a seed field answers with the value removed. Codes use SHA-1, 6 digits, 30 seconds.

- **Where:** App: seed field > Reveal. CLI: none. MCP: credmgr_totp_code
- **How:**
  1. Open the entry.
  2. Choose Reveal on the seed field.
- **AI agents:** An AI agent can ask for this through MCP; a locked vault or a node that asks for a second factor makes it wait for you.
- **Also searched as:** code, 6 digit, one time password, otp, countdown, 2fa code

### Show the seed itself

*Planned.*

Not available. A code is worth thirty seconds, a seed is worth forever, so reading it needs a presence check this build cannot make. The 'show seed' button asks the broker and is refused.

- **Where:** App: seed field > show seed (refused)
- **How:** Not available.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** seed, secret key, export 2fa, show seed

## The vault's second factor

### Set up or replace the second factor

Enrolling gives the vault a second factor: the broker will not unlock without a fresh code from your authenticator. The QR code is drawn locally. After you confirm one code, ten recovery codes are shown once. Replacing a confirmed factor needs a fresh code from the current one first (unlock again, then do it within five minutes).

- **Where:** App: Settings > Security > Two-factor gate. CLI: credmgr gate enroll
- **How:**
  1. Choose Enrol (or Replace).
  2. Scan the QR code and enter one code.
  3. Save the ten recovery codes.
- **Command line:** `credmgr gate enroll`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** enable 2fa, two factor, authenticator app, setup mfa, replace authenticator, new phone

### Lost your authenticator

The passphrase, plus the root recovery code printed when the vault was created, resets the second factor. It does not unlock: unlock afterwards, then enrol a new authenticator. Without both, nothing recovers it.

- **Where:** App: Lock screen > 'lost your authenticator?'. CLI: credmgr gate recover
- **How:**
  1. Choose 'lost your authenticator?'.
  2. Enter the passphrase and the root recovery code.
  3. Choose Reset and unlock, then enrol again.
- **Command line:** `credmgr gate recover`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** lost phone, reset 2fa, recovery, gate recover, locked out

### The ten recovery codes

Enrolment issues ten one-time codes, each good once in place of an authenticator code at unlock. They are shown once and cannot be shown again. They are not the root recovery code.

- **Where:** App: after confirming a code; the Lock screen accepts one in the 2FA field
- **How:** Store them apart from the passphrase.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** backup codes, one-time codes, 10 codes

### Give the second factor to agents

For nodes whose policy asks for a second factor, an agent or tool gets two_factor_required until a person proves the factor. One code opens a vault-wide window of five minutes in which agents and other tools pass the gate on every node that asks. A lock or any node policy change ends it. Your own login is never asked.

- **Where:** App: 'Give second factor' on the node chip or in the inspector. CLI: credmgr gate verify <code> in a shell that holds your login
- **How:**
  1. Choose Give second factor on the node.
  2. Enter the current authenticator code.
- **Command line:** `credmgr gate verify <code>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** step up, elevation, five minute window, two_factor_required, give code, agent 2fa

### What the second factor does and does not protect

The check is made by credmgrd, not by the encryption. Anyone who has your passphrase or your recovery code and a copy of the vault folder can decrypt it without the second factor. Treat each of the passphrase and the recovery code as a complete key.

- **Where:** Applies to the whole vault
- **How:** Keep the passphrase and recovery code offline and apart.
- **Also searched as:** door not safe, limitation, security model, offline attack, argon2

## Agent requests while locked

### Decide an agent's waiting request

If an agent asks for a value while the whole vault is locked, the broker records the request and answers approval_pending. You decide it while the vault stays locked: you give the passphrase (and the authenticator code if two-factor is on). Approving decrypts that one entry and hands it to the agent's retry once; the vault stays locked. A request expires and is denied after 120 seconds.

- **Where:** App: Lock screen > 'N agent requests are waiting for approval'. CLI: credmgr approvals, credmgr approve <request>
- **How:**
  1. Open the Lock screen's request list and pick a request.
  2. Enter the passphrase (and code).
  3. Choose Approve or Deny.
- **Command line:** `credmgr approve <request> [--deny] [--code <n>]`
- **AI agents:** An AI agent can ask for this through MCP; a locked vault or a node that asks for a second factor makes it wait for you.
- **Also searched as:** approve, deny, approval pending, agent waiting, permission, request, approval on demand

### See what a request asks for

Before deciding, you can see what each waiting request is: the node, the entry (by name unless the node hides names), the command and the seconds left. The list works while locked and decrypts nothing. The Lock screen checks the waiting count every five seconds.

- **Where:** App: Lock screen request list. CLI: credmgr approvals [<request>]
- **How:** Run credmgr approvals, or open the request list on the Lock screen.
- **Command line:** `credmgr approvals [<request>] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** approvals, pending approvals, what is requested, pendingApprovals

## Writes made while locked

### Writes made while locked are held for review

An entry added while the vault or its node is locked does not enter the manifest. It waits in the pending tray, across restarts, showing node, name, field count, type, sensitivity and when it was held, and never its values. Accept writes it to its node; Discard removes it. Accepting needs the node unlocked.

- **Where:** App: header 'N held' chip, the banner after unlock (Review), or vault menu > Pending writes. CLI: credmgr pending
- **How:**
  1. Open Held for review.
  2. Choose Accept or Discard on each row.
- **Command line:** `credmgr pending [--node <id>] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** held, pending writes, review tray, locked write, accept, discard, agent created entry

### Accept or discard a held entry

Each held entry is accepted or discarded on its own. A name already used on the node is refused rather than overwritten.

- **Where:** App: Held for review > Accept / Discard. CLI: credmgr pending accept|discard <entry> --node <id>
- **How:** credmgr pending accept <entry> --node acme.
- **Command line:** `credmgr pending accept|discard <entry> --node <id>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** accept pending, discard pending

### The review banner

After you unlock, a banner reports how many held entries are waiting, with Review and dismiss buttons. The header chip stays until the tray is empty.

- **Where:** App: banner under the header after unlock
- **How:** Choose Review.
- **Also searched as:** banner, chip, held count

## Grants

### See and revoke grants

A grant lets one node see into another. The list shows from and to, the scope (read, reveal, notes), a reason and when it ends. Revoking closes it at once in both Lite and Pro mode, because revoking is safety.

- **Where:** App: Settings > Grants > Revoke. CLI: credmgr grant ls, credmgr grant revoke <id>
- **How:**
  1. Open Settings > Grants.
  2. Choose Revoke on the row.
- **Command line:** `credmgr grant ls [--json] | revoke <id>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** revoke grant, remove access, cross node, dashed line, share between projects

### List grants

Shows every grant: from and to, scope, reason and when it ends. Grants made elsewhere appear here even though this build cannot create one.

- **Where:** App: Settings > Grants. CLI: credmgr grant ls
- **How:** Open Settings > Grants, or run credmgr grant ls.
- **Command line:** `credmgr grant ls [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** grants list, who can see what, cross node access

### Create a grant

*Partly working.*

The dialog takes a from-node, a to-node, what to allow (read, reveal values, notes) and a reason of at least eight characters. In this build the broker refuses the request with presence_required, because creating a grant widens a boundary and needs a presence check nothing can make yet; nothing changes. Grants made elsewhere are listed and can be revoked. A grant never expires by itself.

- **Where:** App: node menu > Grant access; Settings > Grants > + New grant (Pro); drag one node onto another. CLI: credmgr grant <from> --to <node> --scope read --reason "..."
- **How:** The dialog validates your input, sends it, and shows the presence notice.
- **Command line:** `credmgr grant <from> --to <node> --scope read --reason "..."`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** new grant, share access, cross-project, allow node, drag node

### How isolation and grants work

Projects never read each other. A node reads itself, Global and its ancestors. It reads its children only if its own policy allows it, and a sibling only for sub-nodes whose parent shares them. Anything else is a grant: human-only, with a reason, revocable, drawn as a dashed arrow on the graph from the trusted node to the node it can see into. An agent can never create one.

- **Where:** Concept; see the graph legend in Help
- **How:** Read the dashed arrows on the graph.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** isolation, access rules, R2 R3 R4, ancestors, global readable, boundary

## Sealing and restoring

### Remove (seal) a node

Removing a node never deletes it. Its entries are re-encrypted to the Orphaned node's key, names stay visible and values become human-only. You type the node name to confirm. A node that still has sub-nodes cannot be sealed until they are sealed; Global cannot be sealed.

- **Where:** App: node menu > Remove node; Settings > Nodes > Remove (Pro). CLI: credmgr node seal <name>
- **How:**
  1. Choose Remove node.
  2. Type the node name.
  3. Choose Seal node.
- **Command line:** `credmgr node seal <name>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** remove project, delete node, archive, retire project, orphan

### Restore a sealed node

A sealed node can be restored byte for byte for seven days, across restarts. After that restore is refused (archive_expired). Work folders another node has claimed since are not restored.

- **Where:** App: Settings > Nodes > Sealed nodes > Restore node (Pro). CLI: credmgr node restore <name>
- **How:**
  1. Open Settings > Nodes.
  2. Choose Restore node on the sealed row.
- **Command line:** `credmgr node restore <name>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** undo seal, bring back, restore project, seven days, archive expired

### Destroy expired seals

After seven days a sealed node's retained originals can be destroyed for good. Nothing does this by itself: only credmgr doctor --purge-expired-seals, or the Operations panel's 'Doctor with purge' followed by Apply. A plain Doctor never purges. The Orphaned copies stay encrypted.

- **Where:** App: Operations (Cmd+Shift+O) > Doctor with purge. CLI: credmgr doctor --purge-expired-seals
- **How:** Preview first with --dry-run, then apply.
- **Command line:** `credmgr doctor [--dry-run] [--purge-expired-seals]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** purge, destroy, irreversible, expired seal

## Audit

### The audit trail

Every request the broker decides, allowed or denied, is recorded in a hash-chained log. The Audit screen lists newest first: time, action, what it touched and who. An agent sees a redacted feed of id, action, time and actor, never values. Audit is a Pro-mode screen.

- **Where:** App: Settings > Audit (Pro). CLI: credmgr audit [--limit N]
- **How:**
  1. Open Settings > Audit.
  2. Choose Refresh.
- **Command line:** `credmgr audit [--limit N] [--json]`
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** log, history, who accessed, activity, recent changes, audit trail, denied

### Open the full audit record

*Planned.*

Clicking a row asks for the full, unredacted record. That needs a presence check this build cannot make, so the broker refuses and the app says so.

- **Where:** App: Settings > Audit > click a row (refused)
- **How:** Not available.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** audit.get, full record, details

### Audit report

A 30-day report of denied requests and grant changes.

- **Where:** App: Operations (Cmd+Shift+O) > Audit report
- **How:** Choose Run on the Audit report row.
- **Also searched as:** report, denied requests, 30 days, security review

## Backup, checks and maintenance

### Back up the vault

*Partly working.*

Writes an encrypted archive into the vault's backups folder under a passphrase you choose. It holds entries and keys; it omits notes, sealed-node archives and the rollback counter. Nothing in this beta restores an archive, so treat it as a copy to keep, not a restore path.

- **Where:** App: Settings > Backup > Back up now, or Operations > Back up vault. CLI: credmgr backup [--retain N]
- **How:**
  1. Choose Back up now.
  2. Choose and repeat an archive passphrase.
- **Command line:** `credmgr backup [--retain N]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** backup, export, archive, snapshot, copy vault, age, tar

### Backup retention

Keeps the 14 or 30 most recent archives. Shown in Pro mode.

- **Where:** App: Settings > Backup > Retention (Pro)
- **How:** Pick 14 or 30 archives.
- **Also searched as:** retain, keep archives, rotate backups

### Verify integrity

Checks every envelope against its manifest digest and the registry. Run it after copying or restoring files, or when something looks wrong. The result is ok or a count of problems.

- **Where:** App: Settings > Backup > Verify now, or Operations > Verify integrity. CLI: credmgr verify
- **How:** Choose Verify now.
- **Command line:** `credmgr verify [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** verify, check, integrity, tamper, checksum, health

### Doctor

Diagnoses registry and manifest problems; a dry run shows what it would fix. It never purges anything on its own. Rebuilding the registry needs presence and is refused.

- **Where:** App: Operations (Cmd+Shift+O) > Doctor. CLI: credmgr doctor [--dry-run]
- **How:** Run with --dry-run first.
- **Command line:** `credmgr doctor [--dry-run]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** repair, fix, diagnose, drift, rebuild registry

### Rotate the root key

*Planned.*

Would replace the root key every other key is wrapped under and issue a new recovery code. It needs a presence check, so the broker refuses it in this build.

- **Where:** App: Settings > Advanced > Rotate (Pro), or Operations. Refused
- **How:** Not available.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** root key, rekey, new recovery code, rotate

### The Operations panel

A Pro-mode panel with Verify integrity, Doctor, Doctor with purge, Back up vault, Rotate root key and Audit report. It shows each result in place.

- **Where:** App: vault menu > Operations, or Cmd+Shift+O
- **How:** Press Cmd+Shift+O.
- **Also searched as:** operations, maintenance, admin tools, pro

## Importing

### Import a .env file

*Partly working.*

Turns a .env-style file (NAME=value lines, # comments, export, quotes) into entries in one all-or-nothing call. A missing closing quote, a repeated name or a name that already exists refuses the whole file and names the line, never its content. Values are never printed. Your .env file is not touched. There is no import control in the desktop app.

- **Where:** CLI: credmgr import <file|-> --node <id>
- **How:**
  1. credmgr import ./service.env --node acme
  2. Delete the .env yourself once you have checked the result.
- **Command line:** `credmgr import <file|-> --node <id> [--json]`
- **Also searched as:** import, env, dotenv, bulk load, migrate secrets, environment file

## Settings

### Open Settings

Settings is a panel with sections. Lite mode shows Security, Appearance, Backup, Mode, Grants and Games. Pro mode (the default) adds Nodes, Maintenance, Audit, Advanced and Operations.

- **Where:** App: the gear in the header
- **How:**
  1. Choose the gear.
  2. Pick a section on the left.
- **Also searched as:** preferences, options, configuration, gear

### Lite and Pro mode

Lite hides levers, never safety: backup, integrity checking and revoking a grant are available in both. Pro adds Nodes, creating grants, Maintenance, Audit, Advanced and the Operations panel. Switching is instant and never hides data.

- **Where:** App: Settings > Mode
- **How:** Choose Lite or Pro.
- **Also searched as:** lite, pro, simple mode, advanced mode

### Reveal window

How long a revealed value stays visible before it hides again: 10, 20 (default) or 60 seconds.

- **Where:** App: Settings > Security > Reveal window
- **How:** Pick a time.
- **Also searched as:** reveal timeout, auto hide, re-mask

### Concealed clipboard

Always on and not a choice: a copied secret is cleared after 30 seconds and when the vault locks, and never enters the window.

- **Where:** App: Settings > Security > Concealed clipboard (shows 'on')
- **How:** Nothing to set.
- **Also searched as:** clipboard clear, copy protection

### Theme, colour, contrast and motion

Dark or light theme; colour off, on or auto with hue and intensity sliders (grounds are tinted, never coloured); standard or high contrast; system or reduced motion; hardware acceleration on or off; a greyscale proof mode for design review.

- **Where:** App: Settings > Appearance
- **How:** Choose the options.
- **Also searched as:** dark mode, light mode, colour, hue, accessibility, reduced motion, high contrast, greyscale, theme

### Turn single-key shortcuts off

The shortcuts / F G T N E work without a modifier. Turn them off if they get in the way of speech input or a screen reader. Cmd+L and Cmd+Shift+O always work.

- **Where:** App: Settings > Appearance > Single-key shortcuts
- **How:** Choose the button to toggle.
- **Also searched as:** keyboard shortcuts off, wcag, accessibility, speech input

### Hide the window from screen capture and screen sharing

The window is hidden from screenshots, screen recordings and screen sharing by default. Turn the switch off to allow capture; the app asks you to confirm first and shows a 'capture allowed' chip while it is off. The choice is remembered.

- **Where:** App: gear > Security > Hide the window from screen capture and screen sharing
- **How:**
  1. Choose the gear, then Security.
  2. Switch 'Hide the window from screen capture and screen sharing' on or off.
  3. Turning it off asks for confirmation; turning it on does not.
- **Also searched as:** screenshot, screen recording, screen share, capture, privacy, hide window, content protection, zoom, meeting

## Cosmetics, games and donations

### Milestones

A private record of your use, kept on this device as dates only, free for everyone.

- **Where:** App: Settings > Appearance > Milestones
- **How:** Read the list.
- **Also searched as:** usage, streak, badge, stamp

### Supporter extras (cosmetic)

Optional cosmetic choices: node shape and colours, backdrop, flourish, ball trail, app mark, the Dock icon, glyph weight, double halo and header badge. They open with a supporter code e-mailed after a donation, once, on this device. Nothing functional is ever locked behind a donation. Some options are badged 'not in beta.1'.

- **Where:** App: Settings > Appearance > Supporter extras > Enter code
- **How:** Choose Enter code and type the code.
- **Also searched as:** cosmetics, supporter code, themes, node shape, app mark, donate code

### Donations and the reminder

A donation is a voluntary gift: not refundable, buys no features and gives no influence. About > Donate lists the addresses with a checklist (verify the first and last six characters after pasting; send a small test first). A dismissible reminder appears about six seconds after unlock and can be turned off with 'don't remind me' or a supporter code.

- **Where:** App: About > Donate; reminder box after unlock
- **How:**
  1. Open About, choose Donate.
  2. Copy an address and verify it.
- **Also searched as:** donate, support, crypto, wallet address, tip, reminder

### CredGames

Small local games for Graph mode, starting with CredPong. A game may read how many nodes the vault has and how many entries each holds, never a name, a field or a value. It writes nothing to the vault and has no network. Scores stay on this device.

- **Where:** App: vault menu > Games, the rail's games button, or Settings > Games
- **How:** Open Games and choose Play.
- **Also searched as:** credpong, pong, arcade, game, play

## AI agents and the MCP server

### The MCP server for AI agents

credmgr mcp is a stdio MCP server that exposes 15 tools to an AI client. It forwards each call to the broker unchanged; the broker decides. You register it once, globally, in your AI client's MCP settings with the full path to the credmgr binary and the argument mcp. One entry serves every project because the folder the client starts in decides the node. Automatic setup of client config files does not exist yet.

- **Where:** AI client MCP settings (you edit them). CLI: credmgr mcp
- **How:**
  1. Add a server named credmgr: command = the full path to credmgr, args = ["mcp"].
  2. Start the client inside a project folder bound to a node.
- **Command line:** `credmgr mcp`
- **Also searched as:** mcp, model context protocol, claude code, cursor, claude desktop, agent setup, register, tools

### An agent learns its own boundary

credmgr_whoami returns the agent's node, its capabilities and the nodes it can reach, and names nothing else. An agent should call it first and reason about its own boundary instead of discovering it by being denied.

- **Where:** MCP: credmgr_whoami. CLI: credmgr whoami
- **How:** Call credmgr_whoami before anything else.
- **Command line:** `credmgr whoami [--json]`
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** whoami, scope, boundary, reachable nodes, capabilities

### How an agent is scoped

An agent is scoped to one node, resolved from the folder it was started in (the node's work folders), or from an explicit token. It reads that node, its ancestors and Global, plus anything granted. No tool argument changes that. An agent started in an unbound folder gets only a bare list on Global.

- **Where:** Set with work folders on a node
- **How:** Bind the project folder to the node (see Work folders).
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** cwd, folder, project scope, which node, agent boundary, isolation

### What each agent access level allows

*Partly working.*

The node's agent access decides the agent's capabilities. read-write: list, read metadata, reveal, create, update. read-only: list, read metadata, reveal. none: nothing. The notes and admin capabilities are never part of an agent's scope, whatever the policy says.

- **Where:** CLI: credmgr node policy <id> --reason "..." --agent-access ...
- **How:** Choose the narrowest level that does the job.
- **Command line:** `credmgr node policy <id> --reason "..." --agent-access read-write|read-only|none`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** permissions, capabilities, read only agent, agent policy

### What an agent sees when the vault is locked

Reading a value on a locked vault answers approval_pending and waits for you (see Decide an agent's waiting request); asking for an authenticator code on a locked vault is simply refused. Creating an entry works and lands in the pending tray for your review. Updating, rotating, removing and field changes are refused with vault_locked, because overwriting a credential you cannot read would be substitution.

- **Where:** Behaviour of the broker
- **How:** Agent: wait or carry on with other work; do not retry in a loop.
- **Also searched as:** approval_pending, vault_locked, agent blocked, locked

### What an agent does when refused

A refusal is explicit and names the human action that would fix it in its remedy field. The right response is to say what is needed and why in one sentence, ask the operator, and carry on with other work. Do not retry, rephrase or look for another route.

- **Where:** Every MCP tool result that is an error
- **How:**
  1. Read error and remedy.
  2. Tell the operator what you need.
- **Also searched as:** node_access_denied, remedy, refused, capability_not_held, denied

### What an agent can never do

These are absent, not merely gated: create or change a grant; read the Orphaned node; read a stored authenticator seed (it can get the current 6-digit code); change a node's policy, agent access, name, parent or work folders; touch the second factor or recovery; run backup, verify, doctor or root-key rotation; purge or shorten the audit log or the recovery window; read another node under any argument; read notes. A test fails if a tool for any of these is added.

- **Where:** Enforced in the broker; restated in the MCP registry
- **How:** Ask the operator instead.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** forbidden, never, limits, restricted, cannot, guardrails

### Private names and agents

*Partly working.*

On a node with hidden names, an agent sees an opaque row (nameHidden) instead of its label, entry names and notes, and search skips the node.

- **Where:** Node policy: private names
- **How:** Set private names on a sensitive node.
- **Also searched as:** nameHidden, privateNames, recon

### Machine-readable manifest for AI agents

v2/docs/llm/credmgr-capabilities.json describes every feature, the 15 MCP tools with their input schemas, the error codes with what to do on each, the broker operations (which ones an agent can reach), the CLI commands and the safety rules. It is generated from the same data as this help and is checked against the code, so it cannot silently drift.

- **Where:** File: v2/docs/llm/credmgr-capabilities.json. Regenerate: python3 tools/gen_help.py
- **How:** Give the file to an agent as context.
- **Also searched as:** llm, manifest, json, schema, agent instructions, capabilities file, machine readable

### Keep your login out of an agent's shell

credmgr unlock exports a login token that reaches every project until the vault locks or the token idles out for 15 minutes. Never export it into a shell an AI agent runs in: the agent would inherit your reach. Agents should use the MCP server, scoped by folder.

- **Where:** CLI: credmgr unlock; known risk K-6
- **How:** Unlock in a shell the agent cannot read, and lock when done.
- **Command line:** `credmgr unlock`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** CREDMGR_TOKEN, token, K-6, export, session, shell

## Command line and broker

### The credmgr command line

One binary, credmgr, is the command line and the MCP server. A secret never travels as an argument: values come from stdin, so they stay out of shell history and process lists. --json gives machine output where offered. credmgr help lists every command and flag.

- **Where:** Terminal: credmgr help
- **How:**
  1. Run credmgr help.
  2. Pipe values: credmgr set API_KEY --node acme <<< 'value'.
- **Command line:** `credmgr help`
- **Also searched as:** command line, terminal, cli, shell, stdin, json, help, commands

### Vault status

Prints whether the vault is locked and, when there are any, how many agent requests are waiting.

- **Where:** CLI: credmgr status
- **How:** Run credmgr status.
- **Command line:** `credmgr status`
- **Also searched as:** status, is it locked, pending approvals count

### Log in from a shell

credmgr unlock reads the passphrase from stdin and prints an export line for CREDMGR_TOKEN; use eval to apply it. With two-factor on it answers two_factor_required and credmgr gate verify <code> completes it. credmgr lock ends every login.

- **Where:** CLI: credmgr unlock, credmgr lock
- **How:** eval "$(credmgr unlock <<< 'your passphrase')"
- **Command line:** `credmgr unlock`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** login, unlock cli, token, eval, export

### The broker: credmgrd

credmgrd holds every key and makes every access decision. The app, the CLI and the MCP server are clients of its local socket and none holds a key. It speaks newline-delimited JSON over a Unix socket (mode 0600 in a 0700 folder), accepts only the vault owner's user id, and has no network listener and makes no outbound connection. Run it in a terminal or with the launchd unit in the release package.

- **Where:** Terminal: credmgrd; launchd unit packaging/com.credmgr.brokerd.plist
- **How:**
  1. Run credmgrd.
  2. Or copy the plist to ~/Library/LaunchAgents and bootstrap it.
- **Also searched as:** credmgrd, daemon, socket, launchd, broker, no network, offline, unix socket

### Where the vault lives

The vault folder is ~/Library/Application Support/credmgr (override with CREDMGR_VAULT_DIR) and must not be inside a git working tree. A rollback counter lives in ~/Library/Application Support/credmgr-state; moving a vault without it makes the first unlock refuse.

- **Where:** Filesystem
- **How:** Set CREDMGR_VAULT_DIR to use another location.
- **Also searched as:** location, path, folder, move vault, rollback counter, CREDMGR_VAULT_DIR

### Which version is this

credmgr --version prints the version, commit, dirty flag and platform. The app shows the same version in About.

- **Where:** CLI: credmgr --version. App: About
- **How:** Run credmgr --version.
- **Command line:** `credmgr --version`
- **Also searched as:** version, build, commit, beta

## Keyboard shortcuts

### Shortcut: / focus search

Moves the cursor to the header search box.

- **Where:** App: anywhere outside a text field or dialog
- **How:** Press /.
- **Also searched as:** slash, find

### Shortcut: F fit graph

Fits the whole graph in the window.

- **Where:** App: graph
- **How:** Press F.
- **Also searched as:** zoom to fit, reset view

### Shortcut: G jump to global

Selects the global node.

- **Where:** App: anywhere outside a text field or dialog
- **How:** Press G.
- **Also searched as:** go to global, root

### Shortcut: T toggle graph and tree

Switches between the graph and the tree view.

- **Where:** App: anywhere outside a text field or dialog
- **How:** Press T.
- **Also searched as:** toggle view

### Shortcut: E entries all or selected

Switches the graph between showing every node's entries and only the selected node's.

- **Where:** App: graph
- **How:** Press E.
- **Also searched as:** entry dots

### Shortcut: N new entry

Opens the Add entry dialog for the selected node.

- **Where:** App: anywhere outside a text field or dialog
- **How:** Press N.
- **Also searched as:** add, create

### Shortcut: Cmd+L lock

Locks the vault from anywhere, even while typing or with a dialog open.

- **Where:** App: anywhere
- **How:** Press Cmd+L.
- **Also searched as:** lock key, cmd l, ctrl l

### Shortcut: Cmd+Shift+O Operations

Opens the Operations panel (Pro mode).

- **Where:** App: anywhere in Pro mode
- **How:** Press Cmd+Shift+O.
- **Also searched as:** operations, maintenance

### Shortcut: Esc close

Closes whatever is open: a dialog, menu, search results or the inspector. In games Esc pauses first.

- **Where:** App: anywhere
- **How:** Press Esc.
- **Also searched as:** escape, cancel, close dialog

### Shortcut: Tab inside a dialog

Tab and Shift+Tab cycle through the controls of an open dialog and stay inside it.

- **Where:** App: any dialog
- **How:** Press Tab.
- **Also searched as:** focus, keyboard navigation, accessibility

## About, privacy and licence

### This help

The Help dialog explains the graph, sealing, grants, notes, writing while locked and the keyboard, and lists every feature with where to find it. Type in the search box to filter. The same list is in v2/HELP.md.

- **Where:** App: the question mark in the header, vault menu > Help, or Settings > Help
- **How:**
  1. Choose the ? button.
  2. Type a word such as 'backup' or 'agent'.
- **Also searched as:** help, manual, documentation, how do i, faq, ?

### About CredMgr

Shows the name, version (read from the app), the publisher, and links to Donate, Privacy and Licences. The app is offline: no telemetry, no HTTP client.

- **Where:** App: vault menu > About CredMgr
- **How:** Open the vault menu (the arrow in the header).
- **Also searched as:** about, version, publisher, freexstudio

### Privacy: what the app keeps

CredMgr has no server, no account, no telemetry, no crash reporting and no cloud sync. The window makes no network request. It stores only small settings in the window's local storage (theme, cosmetic choices, positions under hashed ids, game scores); none holds a secret or a name. A revealed value lives in memory for the reveal window only.

- **Where:** App: About > Privacy
- **How:** Open About, choose Privacy.
- **Also searched as:** telemetry, tracking, data collection, local storage, offline, analytics

### Licence

CredMgr is source-available, not open source. You may run the current stable release, read and audit the source, build the unmodified current version to compare it with the official release, and report problems or send patches. You may not fork, modify or redistribute it. It is free to use today; future versions may be paid. Names and brand assets are covered separately.

- **Where:** App: About > Licences. File: LICENSE
- **How:** Read LICENSE for the complete terms.
- **Also searched as:** license, source available, open source, terms, redistribute

## Planned, not in this build

### Touch ID and presence checks

*Planned.*

Operations that need a live presence check (creating grants, re-parenting, the full audit record, seed display, root-key rotation, registry rebuild, widening a node's reach, opening Orphaned items) are built up to the check and then refused with presence_required. No transport can attest presence yet.

- **Where:** Not available in this build
- **How:** Not available.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** touch id, biometric, presence_required, fingerprint

### Secure Enclave keystore tier

*Planned.*

Only the software tier exists: your passphrase is the key, and a copy of the vault folder can be attacked offline on any computer. Hardware-backed protection is planned.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** secure enclave, hardware key, keychain, software tier

### Signed and notarised app

*Planned.*

The binaries and the app are not code-signed or notarised. SHA256SUMS is the only provenance and macOS Gatekeeper refuses them until you clear the quarantine flag yourself (see RELEASE.md).

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** gatekeeper, notarize, unsigned, developer id, quarantine

### Windows and Linux builds

*Planned.*

Only macOS on Apple Silicon is built and tested. The broker does not compile on Windows yet (Unix socket only).

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** windows, linux, intel mac, platform

### Restoring from a backup archive

*Planned.*

credmgr backup writes an encrypted archive, but nothing in this release reads one back.

- **Where:** Not available in this build
- **How:** Not available.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** restore backup, import backup, recover vault

### Migration from V1

*Planned.*

There is no migration from the V1 vault. Start a new vault and add what you need; credmgr import reads .env files.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** v1, migrate, upgrade from v1

### Remove an entry in the app

*Planned.*

The app has no control to remove an entry. Use credmgr rm; credmgr undo brings it back for seven days.

- **Where:** Not available in this build
- **How:** Not available.
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** delete entry app, trash button

### LLM integration (llm.*)

*Planned.*

Designed, not yet available: there are no llm operations, no settings screen for agents and no built-in model calls. The vault has no outbound network connection by design.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** llm, ai assistant, chat, openai, built-in ai

### One-click MCP setup, vault prompt and CREDMGR.md

*Planned.*

No screen or command writes an AI client's configuration, generates a vault protocol prompt, or drops a CREDMGR.md file into a project. Register credmgr mcp by hand.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** connect claude, auto configure, credmgr prompt, CREDMGR.md, print-config

### Open, Guarded and Sealed agent modes

*Planned.*

A per-node or global setting that changes which agent actions need approval is designed but does not exist. Node policy fields are what you have today.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** security level, guarded, open sealed

### Native notification for agent requests

*Planned.*

A desktop notification that appears while the vault is locked, with a presence check on Approve, is planned. Today you decide from the Lock screen or credmgr approve.

- **Where:** Not available in this build
- **How:** Not available.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** notification, push, alert, approve popup

### MCP tools for notes

*Planned.*

credmgr_notes_read and credmgr_notes_write are specified but not registered: node notes are human-only for now.

- **Where:** Not available in this build
- **How:** Not available.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** agent notes, notes tool

### Machine lock and duress code

*Planned.*

Binding a vault to one machine and a duress passphrase are designed and do not exist.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** machine lock, duress, coercion, panic code

### Security-key second factor

*Planned.*

A hardware key (WebAuthn) as an additional factor beside the authenticator is deferred.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** fido, yubikey, webauthn, hardware token

### Organisation vault and sync

*Planned.*

A shared organisation vault, vault-to-vault sync and licence checks are designed and have no code.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** team, shared vault, sync, multi user, cloud

### A separate second-factor secret per node

*Planned.*

The second factor and its five-minute window belong to the whole vault. A per-node secret is planned.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** per node 2fa, wallet node gate

### Alerts for suspicious activity

*Planned.*

Only a token-folder mismatch is recorded as an anomaly today. A banner or notification on repeated cross-node denials is planned.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** anomaly, alert, intrusion
