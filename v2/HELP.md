<!-- artifact-hardened: NEEDS RE-HARDENING — generated 2026-10-31 -->

# CredMgr help

What CredMgr 2.0.0-rc.2 can do, and where to find each thing: which screen, button, menu, shortcut or command.

This file is generated from `docs/help/features.json` by `tools/gen_help.py`; edit that file, never this one. The desktop app's Help (the **?** button in the header) holds the same list with a search box. An AI agent should read `docs/llm/credmgr-capabilities.json` instead.

Topics marked **Partly working** work in some places and not others; **Planned** ones are listed so you know they are missing, and nothing here describes them as working.

## Contents

| Section | Topics |
|---|---|
| [First run and recovery](#first-run-and-recovery) | 5 |
| [Unlocking, locking and the menu-bar icon](#unlocking-locking-and-the-menu-bar-icon) | 10 |
| [Graph, tree and search](#graph-tree-and-search) | 8 |
| [Projects and nodes](#projects-and-nodes) | 13 |
| [Entries and notes](#entries-and-notes) | 33 |
| [Fields, reveal and copy](#fields-reveal-and-copy) | 9 |
| [Authenticator codes you store](#authenticator-codes-you-store) | 4 |
| [The vault's second factor](#the-vaults-second-factor) | 9 |
| [Agent requests while locked](#agent-requests-while-locked) | 2 |
| [Writes made while locked](#writes-made-while-locked) | 3 |
| [Grants](#grants) | 4 |
| [Sealing and restoring](#sealing-and-restoring) | 6 |
| [Audit](#audit) | 5 |
| [Backup, checks and maintenance](#backup-checks-and-maintenance) | 10 |
| [Importing](#importing) | 2 |
| [Settings](#settings) | 19 |
| [Cosmetics, games and donations](#cosmetics-games-and-donations) | 4 |
| [AI agents and the MCP server](#ai-agents-and-the-mcp-server) | 25 |
| [Command line and broker](#command-line-and-broker) | 7 |
| [Keyboard shortcuts](#keyboard-shortcuts) | 10 |
| [About, privacy and licence](#about-privacy-and-licence) | 4 |
| [Planned, not in this build](#planned-not-in-this-build) | 7 |

199 topics in 22 sections.

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

When the vault has a second factor, unlocking asks for the 6 digits from your authenticator, or one of your ten recovery codes (each works once). On the command line, credmgr unlock answers two_factor_required and credmgr gate verify completes it; it asks for the code at a prompt or reads it from stdin, so it never appears in the process list.

- **Where:** App: Lock screen > 2FA code. CLI: credmgr gate verify
- **How:**
  1. Enter the 6-digit code or a recovery code.
  2. Choose Verify.
- **Command line:** `credmgr gate verify [--code-on-argv <n>]`
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

### Unlock with Touch ID

The Lock screen shows a fingerprint icon beside the passphrase field. Once Touch ID is set up, pressing it unlocks the vault; until then it is dimmed and a press says how to set it up. The vault key is sealed in this Mac's Secure Enclave and opens only on this Mac, with your fingerprint or the Mac password. Your passphrase and recovery code keep working, and a second factor, if on, is still asked. The Touch ID dialog says which program asked and from which folder (for example "Unlock CredMgr for credmgr (pid 4021) <- zsh <- Terminal, in ~/projects/app"): cancel any request you did not start. CredMgr refuses this unlock to an AI agent it can recognise (one holding an agent token, or asking from inside a registered project folder), but an agent running anywhere else reaches it exactly as your own terminal does, and the program and folder in the dialog are a hint, not proof: a program can rename itself, change folder or detach from the app that started it. Five dismissed or timed-out prompts in a row pause unlocking for a while, as wrong passphrases do.

- **Where:** App: Lock screen > the fingerprint icon beside the passphrase field. CLI: credmgr unlock --touch-id
- **How:**
  1. Set up Touch ID in Settings > Security.
  2. Lock the vault.
  3. Press the fingerprint icon beside the passphrase field on the Lock screen.
- **Command line:** `credmgr unlock --touch-id`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** touch id, fingerprint, secure enclave, unlock, biometric

### Alert for agent requests that wait

When an AI assistant asks for a secret while the vault is locked, the request waits for you (two minutes, then it is denied). The app now tells you without opening the window: a count beside the menu-bar icon and in its tooltip for as long as a request waits, one macOS notification per request (several at once are one notification) that says which project it is for and nothing else, and a Dock bounce. It never shows a value, an entry name or a request id; a project that hides its names is called "a private project". The broker does not say which assistant asked, so the text says "an agent". Clicking the notification or the menu-bar icon brings the window back; a locked vault shows the Lock screen with the request listed, and you decide there with your passphrase (and code) or with credmgr approve. Nothing is sent anywhere. The first notification asks macOS for permission; if you refuse, the count and the bounce still work. The notification needs the installed app (a development build run from a terminal has none). On a vault that is open, approving an agent's request from a login needs your fingerprint once a Touch ID key is set up (denying never does).

- **Where:** App: the menu-bar icon and macOS notifications (no setting). Decide on the Lock screen or with credmgr approve.
- **How:**
  1. Let an assistant ask for a secret while the vault is locked.
  2. Look at the menu-bar icon: a number shows how many requests wait. A notification appears if the app is not in front.
  3. Click the notification or the icon, then decide on the Lock screen.
- **Command line:** `credmgr approve`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** notification, alert, approve popup, agent request, waiting, menu bar, badge, presence, touch id, approval_pending

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

The header search box finds node names in the page and entry names through the broker's search. It matches names only: field labels and values are never searched. It shows up to nine rows and says how many more there are. With an empty box it offers 'Add new' and, in Pro mode, recent nodes. A number (1042 or #1042) is also looked up as an entry's reference. The rail has its own filter that narrows the node list by name without asking the broker.

- **Where:** App: header search box, or press / to focus it. CLI: credmgr search <term>
- **How:**
  1. Press / (or click the box) and type.
  2. Choose a row to select the node or open the entry.
  3. To narrow the node list instead, type in filter nodes at the top of the rail.
- **Command line:** `credmgr search <term> [--json]`
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** find, lookup, search bar, filter, entry name

### Entries: all nodes or selected only

The graph can show every node's entry dots at once or only the selected node's. The choice is remembered.

- **Where:** App: button at the top of the graph, or press E
- **How:** Press E to toggle.
- **Also searched as:** entry dots, show entries, all nodes, selected node

### The Orphaned node

Orphaned holds sealed items. Names stay visible. A value opens only in the app, one item at a time, after Touch ID and a fresh second factor (when one is on); no agent, command or MCP tool can open it. Without Touch ID set up, the open is refused and the app says how to set it up.

- **Where:** App: left rail > orphaned, or vault menu > Orphaned
- **How:**
  1. Select orphaned in the rail.
  2. Read the list of names.
  3. Choose Open on an item and approve Touch ID.
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

Two options widen who can read: sub-nodes seeing each other (siblings shared) and a node reading its children. Turning either off is immediate. Turning either on needs a Touch ID proof (a person present): the command asks for it itself, and with no Touch ID set up the broker refuses and applies nothing.

- **Where:** CLI: credmgr node policy --sibling-visibility, --descendant-read
- **How:**
  1. Run credmgr node policy with --sibling-visibility isolated or --no-descendant-read to narrow.
  2. Run it with --sibling-visibility shared or --descendant-read to widen, and approve Touch ID.
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

Re-parenting changes which nodes can read a node, which is a grant by another name, so it needs Admin, a reason and a Touch ID proof (the command asks for it itself). A cycle, Global and Orphaned are refused. With no Touch ID set up the broker refuses. The app has no control for it.

- **Where:** CLI: credmgr node reparent <id> --to <parent> --reason "...". No control in the app
- **How:**
  1. Run credmgr node reparent <id> --to <parent> --reason "...".
  2. Approve Touch ID.
- **Command line:** `credmgr node reparent <id> --to <parent> --reason "..."`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** reparent, move node, change parent

### Replace a node's key

Gives one project a new encryption key and re-seals everything that was sealed to the old one: entries, the note, kept history and removed entries. A crash at any point leaves the node either exactly as it was or completely re-keyed. It costs a fresh second factor and a Touch ID check every time.

- **Where:** CLI: credmgr node rekey <id> (no screen yet)
- **How:**
  1. Unlock as the owner.
  2. Run credmgr node rekey <id>.
  3. Give your authenticator code and touch the sensor.
- **Command line:** `credmgr node rekey <id>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** rekey, re-key, new key, rotate node key, compromised key

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

### Set an expiry date

Gives an entry an expiry date, or removes it. The date is a calendar day in UTC and is metadata: the sealed value is not touched, and nothing is locked or deleted when the day passes. The entry detail shows a chip with the date, amber within 30 days and red once it has passed.

- **Where:** App: entry detail > Set expiry… (or Change expiry…). CLI: credmgr expire <name> --node <id> (--at <date> | --in <days> | --clear)
- **How:**
  1. In the app, open the entry and choose Set expiry…, type a date as YYYY-MM-DD or pick in 30 days, in 90 days or in a year, and choose Save expiry.
  2. To remove it, choose Change expiry… and then Remove expiry.
  3. On the command line, run credmgr expire stripe --node acme --in 90 to expire it in 90 days, or --clear to remove the date.
- **Command line:** `credmgr expire <name> [--node <id>] (--at <YYYY-MM-DD|unix seconds> | --in <days> | --clear)`
- **Also searched as:** expiry, expire, expiration date, rotate reminder, due date

### Edit an entry's details in your editor

Opens an entry's details (aliases, expiry, sensitivity, type, tags when offered, and each field's label, type and masking) as a small text file in your editor, then applies only the lines you changed. No secret value is in the file and none can be changed there; renaming is not supported. Nothing is applied if a line is malformed.

- **Where:** CLI: credmgr edit <name> --node <id> [--dry-run]
- **How:**
  1. Run credmgr edit stripe --node acme. Your editor opens (VISUAL, then EDITOR, then vi) on a private temporary file.
  2. Change the lines you want and save. Lines you leave alone change nothing.
  3. Add --dry-run to see what would be applied without applying it. If the entry changed meanwhile, your edited file is kept and its path is printed so you can retry.
- **Command line:** `credmgr edit <name> --node <id> [--dry-run]`
- **Also searched as:** edit, editor, metadata, aliases, labels, tags

### Entries about to expire

Lists the entries whose expiry falls within the next N days (30 unless you say), soonest first, including any already expired. Names and dates only, never a value. Human sessions only.

- **Where:** CLI: credmgr expiring [--days N] [--node <id>]
- **How:** Run credmgr expiring to see the next 30 days, or add --days 90.
- **Command line:** `credmgr expiring [--days N] [--node <id>] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** expiring, expired, expiry report, what needs rotating

### Move an entry to another project

Moves one entry to another project (node). The value is sealed again with that project's key inside the broker, in one step that survives a crash: the entry is never readable in both projects and never lost. Its name, other names, expiry and reference number go with it. Grants on the entry are revoked and earlier values kept for Undo are dropped. A name the other project already uses is refused. Your login only, with a fresh second-factor code when one is set up and Touch ID every time; no agent can move an entry.

- **Where:** App: entry detail > Move to project…. CLI: credmgr move <name> --node <id> --to <id>
- **How:**
  1. In the app, open the entry, choose Move to project…, pick the project and choose Move entry. Touch ID is asked for.
  2. On the command line, run credmgr move stripe --node acme --to billing.
  3. If the other project already has an entry with that name or one of its other names, rename one of them first.
- **Command line:** `credmgr move <name> [--node <id>] --to <id> [--reason <text>] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** move, move entry, reassign, wrong project, misfiled, transfer

### An entry's history

Shows one entry's trail: every audit record that names it (created, changed, rotated, revealed, denied), oldest first, and when it was last rotated and edited. Values are never in the audit log, so none is shown. Human sessions only. The app shows the newest 200 records, newest first, on the entry's History tab.

- **Where:** App: entry detail > History. CLI: credmgr history <name> [--node <id>] [--limit N]
- **How:**
  1. In the app, open the entry and choose the History tab; Refresh reads it again.
  2. On the command line, run credmgr history stripe --node acme.
- **Command line:** `credmgr history <name> [--node <id>] [--limit N] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** history, trail, who changed, when rotated, changelog

### Find an entry by its number

Every entry has a short reference number that is unique across the vault. This finds the entry it belongs to, among the entries you could already list; a number in a node you cannot reach answers not found, the same as no such number.

- **Where:** App: type the number (1042 or #1042) in the header search box. CLI: credmgr ref <number>
- **How:**
  1. In the app, type the number in the search box; the entry it names comes first. Choose it to open the entry.
  2. On the command line, run credmgr ref 1042.
- **Command line:** `credmgr ref <number> [--json]`
- **Also searched as:** ref, reference number, short id, lookup by number

### Search one node

Finds names and aliases containing a word on one node, case-insensitive. Names only, never values. The header search box and credmgr search search the whole vault instead.

- **Where:** App: select a node; Find in this node, above its entries. Broker operation entry.search (no command of its own)
- **How:**
  1. Select the node in the rail.
  2. Type in Find in this node; a match on another name says which.
  3. Choose a result to open the entry.
- **Also searched as:** search node, find in project, name search

### Rotate a secret and keep history

Rotation replaces a value and keeps the previous one as history, so it can be undone with no time limit, and the entry records when it was rotated. A legitimate rotation implies you could have read what you replace, so it needs the vault unlocked.

- **Where:** App: entry detail > Rotate…. CLI: credmgr rotate <name>
- **How:**
  1. In the app, open the entry and choose Rotate…, pick the field (the hidden one is chosen first), type the new value or choose Generate, and choose Rotate. Undo under the fields puts the old value back.
  2. On the command line, pipe the new value on stdin: credmgr rotate API_KEY --node acme.
- **Command line:** `credmgr rotate <name> [--node <id>] [--field <label> | --field-id <id>]`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** rotate, renew, new key, history, previous value, key rotation

### Remove an entry (soft delete)

Removing hides the entry from lists and search at once and keeps it, sealed, for seven days, when Undo can bring it back. After seven days it is deleted for good.

- **Where:** App: entry detail > Remove…, then Undo in the node's list or Restore in Settings > Audit. CLI: credmgr rm <name>
- **How:**
  1. In the app, open the entry, choose Remove… and confirm with Remove entry.
  2. To bring it back, choose Undo on the bar in the node's list, or Restore under removed in the last 7 days in Settings > Audit. If another entry has taken the name, choose Restore as a copy.
  3. On the command line, run credmgr rm <name> --node <id>, and credmgr undo <audit id> --node <id> to bring it back inside seven days.
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

The broker can generate a random password of 8 to 128 characters, with symbols on or off, a pronounceable form, or lower-case hex only (--hex), and tells you its strength. On the command line, --copy puts the value on the macOS clipboard instead of stdout and clears it after 30 seconds if it is unchanged. The value appears in the answer only; it is not stored or audited until you save it in a field.

- **Where:** App: Add field dialog > Generate. CLI: credmgr generate
- **How:**
  1. Open + Add field.
  2. Set the length and options.
  3. Choose Generate, then save the field.
- **Command line:** `credmgr generate [--length <n>] [--no-symbols] [--pronounceable | --hex] [--copy | --json]`
- **Also searched as:** generate, random password, password generator, entropy, pronounceable, strong password

### Entry and node name rules

Names are compared in one canonical form, so a look-alike of an existing name (different case, width, invisible characters or look-alike letters) is refused as already existing, for agents too. A name that mixes Latin with Greek or Cyrillic letters is accepted with a warning. Entry names are at most 200 characters; node labels 1 to 120.

- **Where:** Applies wherever a name is typed
- **How:** Choose a different name if you see 'already exists'.
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** duplicate, look-alike, homoglyph, mixed script, entry exists, unicode, name length

### Tidy up (the doctor's scan of your entries)

Scans the vault for entries that share a value, near-identical names, entries in Global named for one project, weak passwords, values stored as the wrong kind (a whole otpauth:// link as a password, a live key in a test project), and entries that are expired, about to expire or not rotated for a year. It never shows a value: shared values are found inside the broker with a key made for that one scan and thrown away after it. It changes nothing. Where moving an entry fixes a finding, Move to <project> opens the entry's Move dialog with that project chosen, and the move asks for Touch ID as always. Nodes it could not read (locked, or waiting for their own second factor) are listed. Your login only; no agent can run it.

- **Where:** App: Settings > Maintenance > Tidy up…, or Operations (Cmd+Shift+O) > Tidy up. CLI: credmgr doctor --scan
- **How:**
  1. In the app, open Tidy up and read the findings by kind; each says what to do.
  2. Choose Move to <project> on a finding to move that entry; after the move the scan runs again.
  3. On the command line, run credmgr doctor --scan; add --stale-days 180 or --expiring-days 14 to change the windows, or --json for the report.
- **Command line:** `credmgr doctor --scan [--stale-days N] [--expiring-days N] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** tidy, tidy up, duplicates, shared value, reused password, weak password, stale, expired, misfiled, clean up, doctor scan

### Apply all the moves Tidy up proposes

Moves every entry Tidy up proposes to move, in one step: the entries in Global named for one project, and one copy of a value two sub-projects of a project share. Before anything moves you see the whole list, each entry with where it comes from and where it goes, and confirm it; exactly that list is sent. One authenticator code (when a second factor is on) and one Touch ID check cover the whole list. Each entry is moved the way Move moves one: re-encrypted to its new project's key, keeping its name, reference and expiry; grants on it are revoked and its Undo history stays behind. If the vault changed since the scan, nothing moves. If a move fails part-way, the moves before it stay made and you are told which ones; move one back with Move. Your login only; no agent can do it.

- **Where:** App: Tidy up > Apply all moves. CLI: credmgr doctor --scan --apply
- **How:**
  1. In the app, open Tidy up, press Apply all moves (N), read the list and press Apply.
  2. On the command line, run credmgr doctor --scan --apply, read the plan it prints and answer y; --yes applies the plan shown without asking.
  3. To undo one move, open the entry and Move it back.
- **Command line:** `credmgr doctor --scan --apply [--yes] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** tidy, apply all, apply plan, move all, misfiled, clean up, doctor apply

### Search inside values

Finds entries by what their field values contain. The answer is the node and the entry name only, never a value or a snippet. It needs the reveal capability, is limited to twelve searches a minute, never searches a private node for an agent and never matches a stored 2FA seed. An agent's search never matches a value it would need your approval to read: nothing on a Sealed node and no high or critical entry on a Guarded one.

- **Where:** CLI: credmgr search <term> --deep
- **How:** Run credmgr search <term> --deep (add --node <id> to narrow it).
- **Command line:** `credmgr search <term> --deep [--node <id>] [--json]`
- **AI agents:** An AI agent can ask for this through MCP; a locked vault or a node that asks for a second factor makes it wait for you.
- **Also searched as:** search values, find by value, grep, which entry holds

### Aliases: other names for an entry

An entry can answer to up to 8 other names. An alias lives in the node's one name space: it cannot be the name or alias of another entry (compared the way names are, ADR-084). Search and credmgr get find an entry by an alias. Aliases are names, not secrets.

- **Where:** App: entry > Aliases... CLI: credmgr alias <name> [--add <alias>] [--remove <alias>] [--clear]
- **How:**
  1. Open the entry.
  2. Choose Aliases... and type one alias per line.
  3. Choose Save aliases.
- **Command line:** `credmgr alias <name> [--node <id>] [--add <alias>]... [--remove <alias>]... [--clear] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** alias, other name, nickname, also called, rename

### Near-duplicate names

Beyond the exact-name rule, the app tells you when a name looks like one that exists: the same letters with other separators or case (stripe-key, Stripe_Key), or one letter apart (stirpe-key). Numbered series (wallet1, wallet2) are not flagged. It is a hint, never a block.

- **Where:** App: Add entry (under the name), Aliases, Import .env... CLI: credmgr similar <name> --node <id>
- **How:**
  1. Type a name in Add entry; a line under it names any look-alike.
  2. Or run credmgr similar <name> --node <id>.
- **Command line:** `credmgr similar <name> --node <id> [--json]`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** duplicate, similar, look alike, typo, near duplicate

### Tags on an entry

An entry can carry up to 16 tags: short labels such as prod or team:payments. A tag is lower-cased and its spaces become '-'. Tags are read like names: you can list one project by a tag, but a tag never finds entries across projects. Only you set them; no agent can.

- **Where:** App: entry detail > the tag box under the name. CLI: credmgr tag <name> --add <tag>, credmgr list --node <id> --tag <tag>
- **How:**
  1. In the app, open the entry, type a tag in the box under its name and press Enter; the x on a tag removes it.
  2. On the command line, run credmgr tag stripe --node acme --add prod, then credmgr list --node acme --tag prod.
- **Command line:** `credmgr tag <name> [--node <id>] [--add <tag>]... [--remove <tag>]... [--clear] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** tag, tags, label, category, group, filter by tag

### Merge suggestions

Lists entries inside one project that look like one thing: identical values, a value in common, or names one letter apart. Values are compared inside the broker and never shown. Each suggestion names the entry it would keep (the oldest).

- **Where:** App: Tidy up > Merge / Dismiss. CLI: credmgr merge suggest --node <id>
- **How:**
  1. On the command line, run credmgr merge suggest --node acme.
  2. In the app, open Tidy up: copies inside one project offer Merge and Dismiss.
- **Command line:** `credmgr merge suggest --node <id> [--include-dismissed] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** merge, duplicates, dedupe, same value, suggestions

### Merge duplicate entries

Keeps one entry and folds the others into it: their names become its other names (aliases), their tags join its tags, and they are removed. Each removed entry can be brought back for 7 days with undo, under its own name. Needs a fresh second-factor code when one is set up.

- **Where:** App: Tidy up > Merge / Dismiss. CLI: credmgr merge apply --node <id> --keep <name> --drop <name>
- **How:**
  1. Run credmgr merge apply --node acme --keep STRIPE_KEY --drop stripe-key.
  2. To take it back, run the credmgr undo line it prints.
- **Command line:** `credmgr merge apply --node <id> --keep <name> --drop <name>... [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** merge, combine, duplicates, keep one

### Merge one identical group

Merges one suggestion by its key, but only when every entry in it holds exactly the same values, so nothing is lost; it keeps the oldest entry.

- **Where:** App: Tidy up > Merge / Dismiss. CLI: credmgr merge auto --node <id> --group <key>
- **How:**
  1. Run credmgr merge suggest --node acme and copy the key of an identical group.
  2. Run credmgr merge auto --node acme --group <key>.
- **Command line:** `credmgr merge auto --node <id> --group <key> [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** merge, auto merge, identical

### Merge every identical group

Plans every identical group in a project and changes nothing; with --apply it merges them all. Groups with a grant on an entry to be removed are skipped.

- **Where:** App: Tidy up > Merge / Dismiss. CLI: credmgr merge auto-all --node <id> [--apply]
- **How:**
  1. Run credmgr merge auto-all --node acme to see the plan.
  2. Run it again with --apply to merge.
- **Command line:** `credmgr merge auto-all --node <id> [--apply] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** merge all, auto merge, dry run, bulk

### Dismiss a merge suggestion

Tells CredMgr that a suggested group is not a duplicate. The project remembers it (sealed with the project's key) and it is not suggested again.

- **Where:** App: Tidy up > Dismiss. CLI: credmgr merge dismiss --node <id> --group <key>
- **How:**
  1. In Tidy up, choose Dismiss on the finding.
  2. Or run credmgr merge dismiss --node acme --group <key>.
- **Command line:** `credmgr merge dismiss --node <id> --group <key> [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** dismiss, ignore, not a duplicate, decision memory

### Undo a dismissal

Forgets one dismissed merge suggestion, so it is suggested again.

- **Where:** CLI: credmgr merge undismiss --node <id> --group <key>
- **How:**
  1. Run credmgr merge dismissed --node acme to find the key.
  2. Run credmgr merge undismiss --node acme --group <key>.
- **Command line:** `credmgr merge undismiss --node <id> --group <key> [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** undismiss, suggest again

### Dismissed merge suggestions

Lists the groups a project remembers as not duplicates, newest first, with their entries' names.

- **Where:** CLI: credmgr merge dismissed --node <id>
- **How:** Run credmgr merge dismissed --node acme.
- **Command line:** `credmgr merge dismissed --node <id> [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** dismissed, ignored suggestions

### Forget every dismissal

Forgets every dismissed merge suggestion in a project, so they can be suggested again.

- **Where:** CLI: credmgr merge restore-all --node <id>
- **How:** Run credmgr merge restore-all --node acme.
- **Command line:** `credmgr merge restore-all --node <id> [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** restore all, reset dismissals

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
- **Command line:** `credmgr get <name> [--node <id>] [--field <label> | --field-id <id> | --all] [--json | --copy]`
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

credmgr get prints one value on stdout. An entry with several fields needs a selector (--field, --field-id) or --all; without one it exits 2 and lists the labels. --json prints the fields. --copy puts one value on the macOS clipboard instead of stdout (cleared after 30 seconds if unchanged).

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

### Import an authenticator seed from a QR image

In Add entry, drop a PNG or JPEG of an authenticator QR code on the 2FA QR box, or choose one. The image is read on this computer, never uploaded or saved, and the otpauth URI in it goes into a field as if you had pasted it; the preview types it a 2FA seed. A QR code that is not an authenticator code is refused. Nothing is stored until you save.

- **Where:** App: Add entry > 2FA QR
- **How:**
  1. Open Add entry in a project.
  2. Drop the QR image on the 2FA QR box, or choose the file.
  3. Name the entry and save.
- **Also searched as:** qr, qr code, scan, screenshot, authenticator, otpauth, import 2fa

### Show the current 6-digit code

Revealing a seed field shows the current 6-digit code with a bar that runs to the end of its 30-second step. A reveal of a seed field never returns the seed, only the code; the seed has its own Touch ID-gated 'show seed'. Codes use SHA-1, 6 digits, 30 seconds.

- **Where:** App: seed field > Reveal. CLI: credmgr totp <name>. MCP: credmgr_totp_code
- **How:**
  1. Open the entry.
  2. Choose Reveal on the seed field.
- **Command line:** `credmgr totp <name> [--node <id>] [--field <label> | --field-id <id>] [--copy | --json]`
- **AI agents:** An AI agent can ask for this through MCP; a locked vault or a node that asks for a second factor makes it wait for you.
- **Also searched as:** code, 6 digit, one time password, otp, countdown, 2fa code

### Show the seed itself

A code is worth thirty seconds, a seed is worth forever. The broker releases a seed only to the owner's login with a Touch ID proof and never to an agent. In the app, 'show seed' asks for your fingerprint and then shows the seed in that field's row for the reveal window, like a revealed value: it re-masks by itself, is wiped when the vault locks or the window is hidden, and can never be copied. Without Touch ID set up, or if you cancel the prompt, nothing is shown and the notice says how to set Touch ID up. There is no CLI command for it.

- **Where:** App: seed field > show seed (asks for Touch ID, then shows the seed for the reveal window)
- **How:**
  1. Set up Touch ID in Settings > Security if you have not.
  2. Open the entry and choose show seed on the seed field.
  3. Confirm with your fingerprint; the seed shows until it re-masks.
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

- **Where:** App: 'Give second factor' on the node chip or in the inspector. CLI: credmgr gate verify in a shell that holds your login
- **How:**
  1. Choose Give second factor on the node.
  2. Enter the current authenticator code.
- **Command line:** `credmgr gate verify [--code-on-argv <n>]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** step up, elevation, five minute window, two_factor_required, give code, agent 2fa

### What the second factor does and does not protect

The check is made by credmgrd, not by the encryption. Anyone who has your passphrase or your recovery code and a copy of the vault folder can decrypt it without the second factor. Treat each of the passphrase and the recovery code as a complete key.

- **Where:** Applies to the whole vault
- **How:** Keep the passphrase and recovery code offline and apart.
- **Also searched as:** door not safe, limitation, security model, offline attack, argon2

### A second factor for one project

A project can have an authenticator of its own, with its own recovery codes. Its code is asked even of you, opens that project only for five minutes, and the vault's code never opens it. A project with one is not sealed, and a locked-vault approval is not opened for it. Lost authenticator: the passphrase plus the root recovery code remove it.

- **Where:** CLI: credmgr gate enroll|verify|remove --node <id> (no screen yet)
- **How:**
  1. Run credmgr gate enroll --node <id> and scan the key.
  2. Later give a code with credmgr gate verify --node <id> (it asks for the code, or reads it from stdin).
- **Command line:** `credmgr gate enroll | verify | remove [--last-door] --node <id>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** per node 2fa, project second factor, node gate, wallet node gate

### Confirm a project's own second factor

One valid code from the new authenticator turns the project's own second factor on and shows its ten recovery codes once.

- **Where:** CLI: credmgr gate enroll --node <id> (no screen yet)
- **How:**
  1. Type the 6-digit code when credmgr gate enroll --node <id> asks.
  2. Save the ten recovery codes.
- **Command line:** `credmgr gate enroll --node <id>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** node gate confirm, recovery codes project

### Give a project's own code

Proves the project's own second factor: that project opens for five minutes, for you and for agents, and no other project does.

- **Where:** CLI: credmgr gate verify --node <id> (no screen yet)
- **How:** Run credmgr gate verify --node <id> and type the code (or pipe it on stdin).
- **Command line:** `credmgr gate verify --node <id> [--code-on-argv <n>]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** node step up, project code

### Remove a project's own second factor

Needs the project's fresh code and a Touch ID check, or, when the authenticator is lost, the vault passphrase and the root recovery code together. The vault's own second factor is untouched.

- **Where:** CLI: credmgr gate remove [--last-door] --node <id> (no screen yet)
- **How:** Run credmgr gate remove --node <id>, or add --last-door and give the passphrase and the root recovery code on stdin.
- **Command line:** `credmgr gate remove [--last-door] --node <id>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** remove node gate, lost node authenticator

## Agent requests while locked

### Decide an agent's waiting request

If an agent asks for a value while the whole vault is locked, the broker records the request and answers approval_pending. You decide it while the vault stays locked: you give the passphrase (and the authenticator code if two-factor is on). On the command line the passphrase is the first stdin line and the code the second, or it is asked for at a terminal. Approving decrypts that one entry and hands it to the agent's retry once; the vault stays locked. A request expires and is denied after 120 seconds.

- **Where:** App: Lock screen > 'N agent requests are waiting for approval'. CLI: credmgr approvals, credmgr approve <request>
- **How:**
  1. Open the Lock screen's request list and pick a request.
  2. Enter the passphrase (and code).
  3. Choose Approve or Deny.
- **Command line:** `credmgr approve <request> [--deny] [--code-on-argv <n>]`
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

The dialog takes a from-node, a to-node, what to allow (read, reveal values, notes) and a reason of at least eight characters. Creating a grant widens a boundary, so it asks for Touch ID and then writes the grant; with no Touch ID set up the broker refuses with presence_required and nothing changes. Grants made elsewhere are listed and can be revoked. A grant never expires by itself.

- **Where:** App: node menu > Grant access; Settings > Grants > + New grant (Pro); drag one node onto another. CLI: credmgr grant <from> --to <node> --scope read --reason "..."
- **How:** The dialog validates your input, asks for Touch ID and shows the result.
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

### See the Orphaned entries

Lists the entries of sealed nodes by name. The values stay locked.

- **Where:** App: the Orphaned node in the worktree
- **How:** Lists the entries of sealed nodes by name.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** orphaned, sealed, list

### Open a sealed entry

Opens one entry of a sealed node. It costs a fresh second factor (when one is on) and a Touch ID check every time, and exists only in the app.

- **Where:** App: Orphaned > an entry > Open (Touch ID)
- **How:** Opens one entry of a sealed node.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** orphaned, sealed, reveal, touch id

### Destroy sealed entries for good

Permanently deletes sealed entries and the archives kept behind them. You must name how many entries you were shown and type the confirmation word. It cannot be undone; an earlier backup still holds what it held.

- **Where:** CLI: credmgr orphan ls, then credmgr orphan destroy (no screen yet)
- **How:**
  1. List them with credmgr orphan ls.
  2. Run credmgr orphan destroy with --all or ids, --count and --confirm destroy-sealed-entries.
  3. Give your authenticator code and touch the sensor.
- **Command line:** `credmgr orphan ls | destroy`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** destroy, delete sealed, purge orphaned, permanently

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

Clicking a row asks for the full, unredacted record, after Touch ID. The app shows a one-line summary of it. With no Touch ID set up the broker refuses and the app says so.

- **Where:** App: Settings > Audit > click a row (asks for Touch ID)
- **How:**
  1. Open Settings > Audit.
  2. Click a row.
  3. Approve Touch ID.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** audit.get, full record, details

### Audit report

A 30-day report of denied requests and grant changes.

- **Where:** App: Operations (Cmd+Shift+O) > Audit report
- **How:** Choose Run on the Audit report row.
- **Also searched as:** report, denied requests, 30 days, security review

### Audit summary for a period

Counts what happened in a period by action, actor and node, lists the denials by reason, counts the presence checks and says whether the log's hash chain still verifies. It never contains a value, an entry name or free text a person wrote.

- **Where:** App: Settings > Audit report (Pro). CLI: credmgr audit report
- **How:**
  1. In the app, open Settings > Audit report, choose the last 24 hours, 7, 30, 90 or 366 days, or two dates, and optionally one node, then Make report.
  2. On the command line, run credmgr audit report --days 30, or --from and --to dates.
- **Command line:** `credmgr audit report (--days <n> | --from <date> --to <date>) [--node <id>]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** audit report, summary, denials, presence uses, chain

### Alarm for repeated cross-node denials

When a caller is refused across node boundaries five times in ten minutes, the broker raises an alarm. The app shows a notice bar until you dismiss it, and credmgr status says how many are unseen. Dismissing marks them seen; the denials stay in the audit log.

- **Where:** App: notice bar at the top (Open audit, or ✕ to dismiss). CLI: credmgr status --ack
- **How:**
  1. Read the notice bar.
  2. Choose Open audit to see the denials, or ✕ to dismiss it.
- **Command line:** `credmgr status [--ack]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** anomaly, alert, intrusion, suspicious, denials, alarm

## Backup, checks and maintenance

### Back up the vault

Writes a complete encrypted archive into the vault's backups folder (while the machine lock is on, into CredMgr's state folder on this Mac instead, outside the vault folder) under a passphrase you choose: entries, notes, sealed-node and removed-entry archives, rotation history, the audit log and the keys, and a restore ticket in place of the rollback counter (which stays on this Mac; the first unlock of the restored vault sets a new one). Restore it from Settings > Restore from backup or with credmgr restore, into an empty directory, while the broker is not running. Take the backup while the vault is idle.

- **Where:** App: Settings > Backup > Back up now, or Operations > Back up vault. CLI: credmgr backup [--retain N]
- **How:**
  1. Choose Back up now.
  2. Choose and repeat an archive passphrase.
- **Command line:** `credmgr backup [--retain N]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** backup, export, archive, snapshot, copy vault, age, tar

### Restore a backup

Rebuilds a vault from a backup archive into an empty folder: the backup passphrase is never on a command line, nothing is merged into or written over an existing vault, and the archive is checked whole before a single file is written. A restore never runs beside a running broker: it is refused while credmgrd answers on the vault's socket, in the app and in the terminal alike (the app runs the same credmgr restore). Afterwards unlock with your vault passphrase and run verify. An existing generation counter on this machine is kept, so an archive older than it is refused as rolled back.

- **Where:** App: Settings > Backup > Restore…, or Restore from a backup… on the screen the app shows when no broker answers. CLI: credmgr restore <archive> [--to <empty dir>] [--state-dir <dir>] [--json]
- **How:**
  1. Quit CredMgr, and stop credmgrd if Start at login keeps it running: a restore is refused while a broker runs.
  2. In the app, on the screen it shows when no broker answers, choose Restore from a backup…, give the archive's path, an empty folder and the backup passphrase, and choose Restore.
  3. Or run credmgr restore with the archive file and an empty --to directory; give the backup passphrase on stdin.
  4. Start the broker on that folder, unlock with your vault passphrase, and run credmgr verify.
- **Command line:** `credmgr restore <archive> [--to <empty dir>] [--state-dir <dir>] [--json]`
- **Also searched as:** restore, recover, disaster recovery, rebuild vault, backup archive, new machine

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

Diagnoses registry and manifest problems; a dry run shows what it would fix. It never purges anything on its own. Rebuilding the registry needs a Touch ID proof (and the passphrase of the backup it uses); with no Touch ID set up the broker refuses.

- **Where:** App: Operations (Cmd+Shift+O) > Doctor. CLI: credmgr doctor [--dry-run]
- **How:** Run with --dry-run first.
- **Command line:** `credmgr doctor [--dry-run]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** repair, fix, diagnose, drift, rebuild registry

### Rotate the root key

Replaces the root key every other key is wrapped under and issues a new recovery code. It asks for the vault passphrase again, a fresh second factor (when one is on) and Touch ID; with no Touch ID set up the broker refuses and nothing changes. If Touch ID unlock is on it is re-sealed to the same Mac key. The command line has no command for it. A Touch ID unlock set up in 2.0.0-beta.1 (before version 2.0.0-rc.2) must be turned off and on again first: the rotation refuses to seal the new key to an unlock file it cannot authenticate.

- **Where:** App: Settings > Advanced > Rotate (Pro), or Operations
- **How:**
  1. Open Settings > Advanced.
  2. Choose Rotate and enter the vault passphrase.
  3. Approve Touch ID (and the second factor).
  4. Save the new recovery code.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** root key, rekey, new recovery code, rotate

### Change the vault passphrase

Changes the passphrase that opens the vault. It asks for the current passphrase and the new one twice, then replaces the root key under the new passphrase, so it also issues a new recovery code (shown once; the old code stops working). It asks for a fresh second factor when one is on, and Touch ID when a Touch ID key is set up; without Touch ID the current passphrase is the proof it is you. The same passphrase twice is refused.

- **Where:** App: Settings > Security > Passphrase > Change. CLI: credmgr passphrase
- **How:**
  1. Open Settings > Security and choose Change on the Passphrase row.
  2. Enter the current passphrase, then the new one twice.
  3. Approve Touch ID and the second factor if asked.
  4. Save the new recovery code.
- **Command line:** `credmgr passphrase`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** change password, new passphrase, master password, reset passphrase, pin

### Forgot the passphrase? Open the vault with the recovery code

Opens a locked vault with the recovery code you saved when you created it, when the passphrase is forgotten. In the same step you choose a new passphrase and get a new recovery code (shown once); the code you used and the old passphrase stop working. If a second factor is on it still asks for it (an authenticator code or one of its printed backup codes); Touch ID is not needed. Wrong codes are slowed down like wrong passphrases, and every attempt is in the audit log. An older vault, made before recovery wraps existed, gets the option after its next passphrase change.

- **Where:** App: Lock screen > Forgot passphrase? Use recovery code. CLI: credmgr recover
- **How:**
  1. On the Lock screen choose Forgot passphrase? Use recovery code.
  2. Type the recovery code, then a new passphrase twice.
  3. Give the second-factor code if asked.
  4. Save the new recovery code: the old one no longer works.
- **Command line:** `credmgr recover`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** forgot passphrase, forgot password, lost passphrase, recovery code, locked out, reset passphrase

### The Operations panel

A Pro-mode panel with Verify integrity, Doctor, Doctor with purge, Back up vault, Rotate root key and Audit report. It shows each result in place.

- **Where:** App: vault menu > Operations, or Cmd+Shift+O
- **How:** Press Cmd+Shift+O.
- **Also searched as:** operations, maintenance, admin tools, pro

### Export a node as an encrypted file

Writes an age-encrypted archive of one node to a file you name, never to the screen. Give a passphrase on stdin or one or more age public keys. Stored 2FA seeds are left out and counted. It costs a fresh second factor and a Touch ID check.

- **Where:** CLI: credmgr export --node <id> --out <file> --age
- **How:**
  1. Run credmgr export --node <id> --out <file> --age.
  2. Type the passphrase twice, or pass --age-recipient age1....
  3. Give your authenticator code and touch the sensor.
- **Command line:** `credmgr export --node <id> --out <file> --age [--age-recipient <age1...>]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** export, age, encrypted archive, rage, backup a node

## Importing

### Import a .env file

Turns a .env-style file (NAME=value lines, # comments, export, quotes) into entries. Two ways: credmgr import (one all-or-nothing call; also reads a .json file, or --format json, as an array of name+value or name+fields entries) and credmgr import-env / the window's Import .env... (previews every name first). A missing closing quote names the line, never its content. Values are never printed. Your .env file is not touched.

- **Where:** CLI: credmgr import <file|-> --node <id>, credmgr import-env <file|-> --node <id>. App: inspector > Import .env...
- **How:**
  1. credmgr import ./service.env --node acme
  2. Delete the .env yourself once you have checked the result.
- **Command line:** `credmgr import <file|-> --node <id> [--format json|env] [--json]`
- **Also searched as:** import, env, dotenv, bulk load, migrate secrets, environment file

### Import a .env file after a preview

Reads the file, then shows every name and what it would become: new, already there, repeated in the file, empty (skipped), or resembling another name. A conflict writes nothing unless you choose to skip those names. Each new pair becomes its own entry with its own audit record. Values are never shown.

- **Where:** App: inspector > Import .env... CLI: credmgr import-env <file|-> --node <id> [--dry-run] [--on-conflict refuse|skip]
- **How:**
  1. Select a node.
  2. Choose Import .env... and paste the text or choose the file.
  3. Choose Preview and read the names.
  4. Choose Import (or, if names conflict, choose skip them first).
- **Command line:** `credmgr import-env <file|-> --node <id> [--dry-run] [--on-conflict refuse|skip] [--json]`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** import, env, dotenv, preview, conflict, dry run, bulk load

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

### Confirm before showing secrets

Off by default. When it is on, the vault asks you to confirm it is you, with Touch ID or the vault passphrase, before it shows a saved secret: revealing a value, copying one, or showing a one-time code. After you confirm, it does not ask again for the trust window you chose (1, 5, 15 or 60 minutes; 5 by default). Locking the vault ends the trust window. It guards this app and your logged-in command line (credmgr with your login), on a Mac that is left unlocked. It does not ask agents, including a credmgr command run from inside a registered project folder without your login: what they may read is decided by each project's security level. Approving a waiting request asks too, because approving releases a value. The setting is kept in the vault's signed registry. Turning it off, or making it ask less, needs a fresh confirmation; turning it on does not.

- **Where:** App: Settings > Security > Confirm before showing secrets. CLI: credmgr confirm
- **How:**
  1. Open Settings > Security.
  2. Turn on Confirm before showing secrets.
  3. Choose how long a confirmation lasts (the trust window).
  4. The next time you show a secret, confirm with Touch ID or your passphrase.
- **Command line:** `credmgr confirm`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** confirm, confirmation_required, fingerprint every time, ask for passphrase, shoulder surfing, unlocked mac, trust window, re-authenticate, reveal protection, touch id

### Confirm every time, or only for high and critical secrets

In Pro mode, Settings > Security has two more choices for Confirm before showing secrets. When to ask: once per trust window, or every time (each secret needs its own confirmation, so Touch ID asks once per reveal). Which secrets: all of them, or only entries whose sensitivity is high or critical (low and medium values show without asking). Under the second choice, lowering an entry's sensitivity out of high or critical also asks you to confirm. Making the rule ask less needs a fresh confirmation.

- **Where:** App: Settings > Security (Pro mode) > When to ask, Which secrets
- **How:**
  1. Switch to Pro in Settings > Mode.
  2. Open Settings > Security.
  3. Under Confirm before showing secrets choose When to ask and Which secrets.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** every time, each reveal, high sensitivity, critical, pro, confirm, sensitivity

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

### Touch ID

Touch ID confirms the sensitive things: creating a grant, moving a project, the full audit record, showing a 2FA seed, widening a node's reach, rotating the root key, rebuilding the registry, and opening a sealed (Orphaned) entry, and approving an AI assistant's waiting request from an open vault (denying never asks). Each asks the Secure Enclave to sign a one-time challenge, so a fingerprint (or the Mac password) is needed every time; nothing is remembered. Adding a key proves it: the new key signs a one-time challenge too, so a second fingerprint is asked for when you set it up. The list of keys is kept inside the vault's signed registry, so deleting or replacing a file in the vault folder does not remove a key or bring an old one back. On a Mac without a Secure Enclave the row is shown greyed out, with the reason, instead of being hidden.

- **Where:** App: Settings > Security > Touch ID. CLI: credmgr presence enrol, credmgr touch-id enable
- **How:**
  1. Open Settings > Security.
  2. Choose Set up on the Touch ID row (a fresh second factor is asked for if one is on).
  3. From then on the sensitive actions ask for your fingerprint.
- **Command line:** `credmgr presence enrol`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** touch id, biometric, presence, presence_required, fingerprint, secure enclave, confirm

### Machine lock: lock the vault to this Mac

Seals the vault's passphrase file with a device key kept on this Mac, outside the vault folder (a file only your user account can read), and replaces the root key and every project key at the same time. A copy of the vault folder made from then on - a synced folder, a copied directory, a USB disk - does not open on another computer with the passphrase alone. A copy made before still opens with the passphrase and still shows what it held then; nothing written after the lock is readable in it. Turning it on asks for the passphrase and your current recovery code, then shows you a NEW recovery code and asks you to type it back before anything changes; only then is the lock turned on, and the old code stops working. Closing the dialog before that changes nothing. On a new Mac, on another Mac that shares the folder, or if the key file is lost, open the vault with the recovery code; that also locks it to that Mac. It does not protect a stolen or unlocked Mac, Time Machine, a whole-disk image or Migration Assistant (they carry the device key with the folder), or CredMgr backups (they hold the passphrase file unsealed inside their own encryption and open with their backup passphrase and the vault passphrase; while the lock is on they are written outside the vault folder, in CredMgr's state folder on this Mac, and turning it on moves the ones already in the vault folder there, so a copy of the vault folder does not carry them). The key is a file, not sealed in the Secure Enclave. Rotating the root key and changing the passphrase keep the lock on, and say so if they could not.

- **Where:** App: Settings > Security > Machine lock > Bind. CLI: credmgr keystore bind
- **How:**
  1. Have your passphrase and your current recovery code ready, and unlock every project.
  2. Open Settings > Security and choose Bind on the Machine lock row.
  3. Read what it covers and what it does not, type the passphrase and the recovery code, then choose Next. Nothing has changed yet.
  4. Write down the new recovery code it shows, type it back, then choose Turn the lock on; the old code no longer works.
- **Command line:** `credmgr keystore bind`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** machine lock, bind to this mac, lock to this mac, device key, copied vault folder, keystore, new mac, time machine, recovery code, backup

### Machine lock status

Shows whether the passphrase file is sealed to a device key, whether this Mac holds that key, and the honest tier: a key file on this Mac, never the Secure Enclave. Says when turning the lock on did not finish (projects still on a key from before it) or when an older, unlocked passphrase file was put back, and what to do. Also says what the lock protects (a copy of the vault folder made after it) and what it does not (a stolen or unlocked Mac, Time Machine and disk images, copies made before it, CredMgr backups, or whoever holds the recovery code). Needs the owner's login; an agent is refused.

- **Where:** App: Settings > Security > Machine lock. CLI: credmgr keystore status
- **How:** Open Settings > Security and read the Machine lock row, or run credmgr keystore status.
- **Command line:** `credmgr keystore status`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** machine lock status, is the vault bound, device key, keystore status, secure enclave

### Turn off the machine lock

Puts the passphrase file back in its plain form, so a copy of the vault folder opens on any computer with the passphrase again. The device key stays on this Mac, so turning the lock on again reuses it. Asks first, and needs a fresh second factor and Touch ID when they are set up, or the vault passphrase when neither is.

- **Where:** App: Settings > Security > Machine lock > Unbind. CLI: credmgr keystore unbind
- **How:**
  1. Open Settings > Security and choose Unbind on the Machine lock row.
  2. Choose Turn off, and give Touch ID or the second factor if asked; type the passphrase if neither is set up.
- **Command line:** `credmgr keystore unbind`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** unbind, turn off machine lock, keystore unbind, unlock on another mac

### Start the broker at login

On a Mac, turns on a per-user login agent so credmgrd starts when you log in and the vault is ready before you open the app. It looks for credmgrd beside the app, then in /usr/local/bin and /opt/homebrew/bin, and says so if it finds none. Turning it off asks once more, because it also stops the broker the agent started. It changes nothing inside the vault.

- **Where:** App: Settings > Security > Start at login (macOS only)
- **How:**
  1. Open Settings > Security.
  2. Turn on Start at login.
  3. To stop it, turn it off and confirm.
- **Also searched as:** launch agent, login item, start automatically, autostart, launchd, background

### Touch ID status

Shows what this Mac can do for Touch ID and whether it is set up.

- **Where:** App: Settings > Security > Touch ID. CLI: credmgr presence status
- **How:** Shows what this Mac can do for Touch ID and whether it is set up..
- **Command line:** `credmgr presence status`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** touch id, status, secure enclave

### Remove a presence key

Removes an enrolled presence key; Touch ID then no longer confirms sensitive actions until one is enrolled again.

- **Where:** App: Settings > Security > Touch ID > Turn off. CLI: credmgr presence unenrol <id>
- **How:** Removes an enrolled presence key; Touch ID then no longer confirms sensitive actions until one is enrolled again..
- **Command line:** `credmgr presence unenrol`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** touch id, remove, presence key

### The Touch ID challenge

Before a sensitive action the app asks the broker for a one-time challenge, has the Secure Enclave sign it with your fingerprint, and repeats the action with the proof. It is automatic.

- **Where:** Automatic (the app and the CLI do it)
- **How:** Before a sensitive action the app asks the broker for a one-time challenge, has the Secure Enclave sign it with your fingerprint, and repeats the action with the proof.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** touch id, challenge, nonce

### Turn Touch ID unlock off

Removes the Touch ID unlock; the passphrase and recovery code are unchanged.

- **Where:** App: Settings > Security > Touch ID > Turn off. CLI: credmgr touch-id disable
- **How:** Removes the Touch ID unlock; the passphrase and recovery code are unchanged..
- **Command line:** `credmgr touch-id disable`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** touch id, turn off, disable

### Turn Touch ID unlock on

Seals the vault key in this Mac's Secure Enclave so the Lock screen can offer Unlock with Touch ID.

- **Where:** App: Settings > Security > Touch ID > Set up. CLI: credmgr touch-id enable
- **How:** Seals the vault key in this Mac's Secure Enclave so the Lock screen can offer Unlock with Touch ID..
- **Command line:** `credmgr touch-id enable`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** touch id, set up, enable

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

credmgr mcp is a stdio MCP server that exposes 21 tools to an AI client. It forwards each call to the broker unchanged; the broker decides. You register it once, globally, in your AI client's MCP settings with the full path to the credmgr binary and the argument mcp. One entry serves every project because the folder the client starts in decides the node. Settings, Agents shows the exact configuration for each client and writes it only when you press Write on the change it shows; credmgr mcp --print-config prints it for a terminal.

- **Where:** Settings, Agents (the app). CLI: credmgr mcp --print-config <client>; credmgr agent connect <client>
- **How:**
  1. Open Settings, Agents, and press Connect on your assistant (or copy the configuration).
  2. Read the change, then press Write this change. Restart the assistant.
  3. Start the assistant inside a project folder bound to a node.
- **Command line:** `credmgr mcp`
- **Also searched as:** mcp, model context protocol, claude code, cursor, claude desktop, agent setup, register, tools

### An agent learns its own boundary

credmgr_whoami returns the agent's node, its capabilities, the nodes it can reach and the node's security level, and names nothing else. An agent should call it first and reason about its own boundary instead of discovering it by being denied.

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

The node's agent access decides the agent's capabilities. read-write: list, read metadata, reveal, create, update. read-only: list, read metadata, reveal. none: nothing. The notes and admin capabilities are never part of an agent's scope, whatever the policy says. The security level (Open, Guarded, Strict) is separate: it decides which of those actions wait for you.

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

v2/docs/llm/credmgr-capabilities.json describes every feature, the 21 MCP tools with their input schemas, the error codes with what to do on each, the broker operations (which ones an agent can reach), the CLI commands and the safety rules. It is generated from the same data as this help and is checked against the code, so it cannot silently drift.

- **Where:** File: v2/docs/llm/credmgr-capabilities.json. Regenerate: python3 tools/gen_help.py
- **How:** Give the file to an agent as context.
- **Also searched as:** llm, manifest, json, schema, agent instructions, capabilities file, machine readable

### Keep your login out of an agent's shell

credmgr unlock exports a login token that reaches every project until the vault locks or the token idles out for 15 minutes. Never export it into a shell an AI agent runs in: the agent would inherit your reach. Agents should use the MCP server, scoped by folder, or an agent token for one node. The MCP server never reads CREDMGR_TOKEN and refuses to start if CREDMGR_AGENT_TOKEN holds a login.

- **Where:** CLI: credmgr unlock; known risk K-6
- **How:** Unlock in a shell the agent cannot read, and lock when done.
- **Command line:** `credmgr unlock`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** CREDMGR_TOKEN, token, K-6, export, session, shell

### Give an agent a token for one node

An agent token lets an agent reach exactly one project node (not Global), with the capabilities you pick (list, read, reveal, create, update) and never more than that node allows agents. It always expires: one day unless you choose otherwise, seven days at most. Issuing needs your login, your second factor if you set one up, and Touch ID; an agent can never issue, widen or renew one. You get the token once: the app puts it on the clipboard (concealed, cleared after 30 seconds) without showing it, and the CLI prints it alone. Paste it into the agent's settings as CREDMGR_AGENT_TOKEN. Restarting the broker, or sealing the node, ends its agent tokens. When an agent asks for a reveal approval or a setting change with a token, the request says which token asked.

- **Where:** App: Settings > Agents > Agent tokens > Issue token. CLI: credmgr agent token issue <node> --label "..." --cap list,read [--expires 8h]
- **How:**
  1. Open Settings > Agents and choose Issue token under Agent tokens.
  2. Pick the node, name the agent, tick what it may do and choose how long the token lasts.
  3. Confirm with Touch ID. The token is now on the clipboard: paste it into the agent's settings within 30 seconds. It is not shown or copied again.
- **Command line:** `credmgr agent token issue <node> --label "..." --cap list,read [--expires 8h]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** agent token, node token, scoped token, CREDMGR_AGENT_TOKEN, issue token, mcp token, expiry

### See your agent tokens

Lists the live agent tokens: the label, the node, what each may do now, when it expires and when it was last used. The list never shows a token itself; the broker keeps only a hash. If you narrow a node's agent access, its tokens narrow at once.

- **Where:** App: Settings > Agents > Agent tokens. CLI: credmgr agent token ls [--node <id>]
- **How:** Open Settings > Agents, or run credmgr agent token ls.
- **Command line:** `credmgr agent token ls [--node <id>] [--json]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** agent tokens, list tokens, token expiry, last used

### Replace an agent token

Gives an existing agent token a new secret and a new expiry; the old secret stops working on its next request. The node and capabilities stay the same. Needs your login, your second factor if set up, and Touch ID. The new token is shown once.

- **Where:** CLI: credmgr agent token rotate <id> [--expires 8h]
- **How:** Run credmgr agent token rotate with the token's id, then give the agent the new token.
- **Command line:** `credmgr agent token rotate <id> [--expires 8h]`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** rotate token, renew token, new secret, extend token

### Revoke an agent token

Ends an agent token at once: the next request that presents it is refused and recorded in the audit log under the token's id. Revoking only takes access away, so it does not ask for Touch ID. If the vault locks before a new token reaches the clipboard, the app revokes that token as soon as you unlock.

- **Where:** App: Settings > Agents > Agent tokens > Revoke. CLI: credmgr agent token revoke <id>
- **How:** Choose Revoke on the token's row, or run credmgr agent token revoke <id>.
- **Command line:** `credmgr agent token revoke <id>`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** revoke token, remove agent access, stop agent, kill token

### Open, Guarded and Strict: how much an agent may do on a node

Each node has a security level. Guarded (the default): an agent reads low and medium values at once and a high or critical value waits for your one-tap approval. Strict: every value waits for you, what an agent adds waits in the tray for you to accept, and it cannot change or remove anything or get a one-time code. Open: nothing waits. The level never changes cross-node isolation, orphan sealing or grants, and never holds you. Lowering a level needs Touch ID. On a Guarded or Strict node an agent cannot lower an entry's sensitivity (by setting it, by an edit that would make it read lower, or by undoing your change), and only you accept or discard what waits in the tray. Strict is stored as sealed, and credmgr accepts either word; it is not the same as sealing a node into Orphaned.

- **Where:** The node panel, agents here. CLI: credmgr node policy <id> --reason "..." --security-level open|guarded|strict
- **How:**
  1. Select the node.
  2. Under agents here choose Open, Guarded or Strict. The words under it say what that means.
  3. Lowering the level asks for Touch ID.
- **Command line:** `credmgr node policy <id> --reason "..." --security-level open|guarded|strict`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** security level, guarded, strict, sealed, open, approval, agent waits, wallet node

### Connect a coding assistant

Settings, Agents lists the coding assistants it can find (Claude Code, Claude Desktop, Cursor, VS Code with Copilot, Windsurf), shows whether CredMgr is wired in, and copies the exact configuration. Connect shows the change as a diff and writes only the credmgr entry after you press Write, after copying the file to a backup. Claude Code's own state file is never edited: the app copies the one-line command instead. Nothing is written without that click.

- **Where:** Settings, Agents. CLI: credmgr agent detect|connect|disconnect
- **How:**
  1. Open Settings, Agents.
  2. Press Copy configuration, or Connect and read the change.
  3. Press Write this change. A copy of the original stays beside the file.
- **Command line:** `credmgr agent connect <client> [--yes]`
- **Also searched as:** connect, claude code, cursor, windsurf, vs code, copilot, mcp config, backup, diff

### The vault prompt and CREDMGR.md

The Vault Protocol prompt tells an assistant that has no MCP how to use the vault and what to do when it is refused. It is built from your node names and the node's security level, never a value. credmgr prompt prints it; credmgr agent init writes it into a project folder as CREDMGR.md (it holds no secret; an existing file is shown as a diff first); Settings, Agents copies either.

- **Where:** Settings, Agents. CLI: credmgr prompt; credmgr agent init
- **How:**
  1. Select the node, then Settings, Agents, Copy prompt (or Copy CREDMGR.md).
  2. Or in a terminal: credmgr agent init --node <id> --dir <folder>.
- **Command line:** `credmgr prompt [--node <id>] [--json]`
- **Also searched as:** prompt, credmgr.md, agent instructions, chatgpt, no mcp, vault protocol

### The switchboard: every setting, also for AI assistants

Every CredMgr setting can be read and changed without the window: by you from the command line, and by an AI assistant through MCP, so you can just ask it. The app reads the same settings, so the two never disagree. A change that makes the vault less protected, asked by an assistant, waits for your approval.

- **Where:** CLI: credmgr settings list [--node <id>]. MCP: credmgr_settings_list.
- **How:**
  1. Run credmgr settings list, or ask your assistant to list CredMgr's settings.
  2. Add --node <project> to see a project's settings.
- **Command line:** `credmgr settings list`
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** switchboard, settings, assistant, llm, change settings, configure

### See one setting in full

What a setting is for, the values it takes, where it is stored, its current value, and its recent changes with the value each replaced.

- **Where:** CLI: credmgr settings get <id>. MCP: credmgr_settings_get.
- **How:** Run credmgr settings get app.autoLockMins.
- **Command line:** `credmgr settings get`
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** setting, describe, history

### Change a setting from the command line or an assistant

Change any setting with a reason. Appearance changes and changes that make the vault stricter apply at once. A change that weakens it (a longer or no auto-lock, a looser reveal rule, a lower security level, more agent access) applies at once when you make it; when an assistant asks, it waits for your approval.

- **Where:** CLI: credmgr settings set <id> <value> --reason <why>; credmgr settings toggle <id> --reason <why>. MCP: credmgr_settings_set.
- **How:**
  1. Run credmgr settings set app.theme '"dark"' --reason "prefer dark".
  2. Or ask your assistant: make CredMgr lock after 5 minutes.
- **Command line:** `credmgr settings set`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** set setting, toggle, change, auto-lock, theme

### Undo a setting change

Every setting change is recorded with the value it replaced. Reverting puts that value back, under the same rules as a change.

- **Where:** CLI: credmgr settings revert <change>. MCP: credmgr_settings_revert.
- **How:**
  1. Find the change id with credmgr settings get <id>.
  2. Run credmgr settings revert <change>.
- **Command line:** `credmgr settings revert`
- **AI agents:** An AI agent can do this through MCP, only inside the node it is scoped to.
- **Also searched as:** revert, undo setting, history

### An assistant's request waiting for you

When an assistant asks for a change that weakens the vault, it gets a request id and waits. It can check the request's state; only you approve or deny it.

- **Where:** CLI: credmgr settings request <id>. MCP: credmgr_settings_request.
- **How:** The assistant tells you it asked; approve or deny it (below).
- **Command line:** `credmgr settings request`
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** request, pending, waiting, approval

### See assistants' requests

Every request an assistant made, waiting or decided, with the folder it was asked from. Only you see this list.

- **Where:** Settings, Agents (the app). CLI: credmgr settings requests.
- **How:** Open Settings, Agents, or run credmgr settings requests.
- **Command line:** `credmgr settings requests`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** requests, agents asked, pending changes

### Approve or deny an assistant's request

Approving a change that weakens the vault asks you to confirm it is you first (Touch ID or your passphrase). Denying changes nothing.

- **Where:** Settings, Agents (the app). CLI: credmgr settings approve <id> | credmgr settings deny <id>.
- **How:**
  1. Read the request: what changes, from what to what, and why.
  2. Approve (confirm with Touch ID or your passphrase) or deny.
- **Command line:** `credmgr settings approve`
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** approve, deny, agent request, step-up

### The knowledge base for AI assistants

docs/LLM_KB.md tells an assistant everything it needs: how to connect, where data lives, retention and backup, every feature and setting and how to change it, and the rules. It is generated from the settings table and checked against it, so it cannot drift.

- **Where:** File: v2/docs/LLM_KB.md. CLI: credmgr kb. MCP: credmgr_kb.
- **How:** Ask your assistant to read CredMgr's knowledge base (credmgr_kb), or run credmgr kb.
- **Command line:** `credmgr kb`
- **AI agents:** An AI agent can use this through MCP to read names, ids and labels, never a value.
- **Also searched as:** knowledge base, kb, llm, instructions, documentation for agents

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

Prints whether the vault is locked, how many agent requests are waiting when there are any, and where the diagnostic log is.

- **Where:** CLI: credmgr status
- **How:** Run credmgr status.
- **Command line:** `credmgr status`
- **Also searched as:** status, is it locked, pending approvals count

### Diagnostic log for bug reports

A local log of what the broker and the app did: times, operation names, error codes, durations, start and stop, versions. It never holds entry or project names, values, notes, paths or tokens, so it can be attached to a bug report. Off unless CREDMGR_DIAG_LOG=1 is set for the broker; at most three files of 1 MiB; nothing is sent anywhere.

- **Where:** CLI: credmgr status --log
- **How:**
  1. On a Mac, run launchctl setenv CREDMGR_DIAG_LOG 1, then restart the broker (and the app).
  2. Reproduce the problem.
  3. Run credmgr status --log to see where credmgrd.log and desktop.log are.
- **Command line:** `credmgr status --log`
- **Also searched as:** log, logs, diagnostics, bug report, crash, troubleshoot

### Log in from a shell

credmgr unlock reads the passphrase from stdin and prints an export line for CREDMGR_TOKEN; use eval to apply it. With two-factor on it answers two_factor_required and credmgr gate verify completes it (the code is typed at a prompt or piped in). credmgr lock ends every login.

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

### Migration from V1 inside the app

*Planned.*

Neither the app nor the credmgr CLI reads a V1 vault; an in-app V1 copy is planned for 2.1. Today the one-way, read-only copy is the script tools/v1-to-v2/migrate.js (see tools/v1-to-v2/README.md): V1 is never modified, it plans first (dry run) and copies with --apply into an unlocked V2 vault. credmgr import reads .env files only.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** v1, migrate, upgrade from v1, migrate.js, v1-to-v2

### MCP tools for notes

*Planned.*

credmgr_notes_read and credmgr_notes_write are specified but not registered: node notes are human-only for now.

- **Where:** Not available in this build
- **How:** Not available.
- **AI agents:** Only you can do this. An AI agent cannot.
- **Also searched as:** agent notes, notes tool

### Duress code

*Planned.*

A duress or panic code that opens a decoy vault under coercion is dropped (ADR-145) and will not be built. The machine lock (Settings > Security) is built: it stops a copied vault folder from opening elsewhere with the passphrase alone.

- **Where:** Not available in this build
- **How:** Not available.
- **Also searched as:** duress, coercion, panic code, decoy vault

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
