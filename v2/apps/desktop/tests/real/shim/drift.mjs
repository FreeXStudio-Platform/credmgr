/**
 * The comparison the drift guard makes: the shim's command table against what the Tauri shell really exposes.
 *
 * Pure: it takes both sides as data and returns a list of findings (empty = in agreement), so the guard test can also feed it
 * deliberately broken inputs and require it to object (a guard that has never failed proves nothing).
 */

const paramKey = (p) => `${p.key}:${p.kind}:${p.required ? "required" : "optional"}`;

/**
 * @param {object} shim  { broker, shell, vaultStateOps, sessionEndedCodes, copyTextMaxBytes, clipboardTtlSeconds, localCodesUsed }
 * @param {object} rust  readShellSurface()
 * @param {string[]} brokerOps  every op ops.rs dispatches
 * @param {string[]} bridgeInvokes  every invoke("...") name src/lib/bridge.ts makes
 * @returns {string[]} findings
 */
export function compareSurfaces(shim, rust, brokerOps, bridgeInvokes) {
  const out = [];
  const dupes = (list, what) => {
    const seen = new Set();
    for (const x of list) {
      if (seen.has(x)) out.push(`${what} lists ${x} twice`);
      seen.add(x);
    }
  };

  // 1. broker-bridged commands, both directions
  dupes(shim.broker.map((r) => r.command), "the shim table");
  dupes(rust.broker.map((r) => r.command), "commands.rs");
  const shimBy = new Map(shim.broker.map((r) => [r.command, r]));
  const rustBy = new Map(rust.broker.map((r) => [r.command, r]));
  for (const name of rustBy.keys()) if (!shimBy.has(name)) out.push(`commands.rs exposes ${name} but the shim table has no such command`);
  for (const name of shimBy.keys()) if (!rustBy.has(name)) out.push(`the shim table has ${name} but commands.rs exposes no such command`);
  for (const [name, r] of rustBy) {
    const s = shimBy.get(name);
    if (!s) continue;
    if (s.op !== r.op) out.push(`${name}: the shim sends op ${s.op}, commands.rs sends ${r.op}`);
    const sp = s.params.map(paramKey).join(", ");
    const rp = r.params.map(paramKey).join(", ");
    if (sp !== rp) out.push(`${name}: the shim's arguments are [${sp}], commands.rs's are [${rp}]`);
  }

  // 2. the shell's own commands
  const shimShell = new Map(shim.shell.map((r) => [r.command, r]));
  const rustShell = new Map(rust.shell.map((r) => [r.command, r]));
  for (const name of rustShell.keys()) if (!shimShell.has(name)) out.push(`commands.rs has the shell command ${name} but the shim does not`);
  for (const name of shimShell.keys()) if (!rustShell.has(name)) out.push(`the shim has the shell command ${name} but commands.rs does not`);
  for (const [name, r] of rustShell) {
    const s = shimShell.get(name);
    if (!s) continue;
    if ((s.wrapsOp ?? null) !== (r.wrapsOp ?? null)) out.push(`${name}: the shim wraps op ${s.wrapsOp}, commands.rs wraps ${r.wrapsOp}`);
    const sp = s.params.map((p) => `${p.key}:${p.kind}`).join(", ");
    const rp = r.args.map((a, i) => `${a}:${r.kinds[i]}`).join(", ");
    if (sp !== rp) out.push(`${name}: the shim's arguments are [${sp}], commands.rs's are [${rp}]`);
    // The frame it sends to the op it wraps (`entry_copy`: its `field` goes out as `fieldIds`): the shim builds that frame by hand.
    const so = (s.opParams ?? []).join(", ");
    const ro = (r.opParams ?? []).join(", ");
    if (so !== ro) out.push(`${name}: the shim sends [${so}] to the op it wraps, commands.rs sends [${ro}]`);
  }
  // a name must not be in both tables
  for (const name of shimShell.keys()) if (shimBy.has(name)) out.push(`${name} is in both the shim's broker table and its shell table`);

  // 3. the broker: every op ops.rs dispatches is bridged, and every bridged op is dispatched
  const bridgedOps = new Set([...shim.broker.map((r) => r.op), ...shim.shell.map((r) => r.wrapsOp).filter(Boolean)]);
  const dispatched = new Set(brokerOps);
  for (const op of dispatched) if (!bridgedOps.has(op)) out.push(`ops.rs dispatches ${op} but no shim command carries it`);
  for (const op of bridgedOps) if (!dispatched.has(op)) out.push(`the shim carries op ${op} but ops.rs does not dispatch it`);

  // 4. the typed client: it must invoke exactly the commands the shim serves, each once
  dupes(bridgeInvokes, "src/lib/bridge.ts");
  const served = new Set([...shim.broker.map((r) => r.command), ...shim.shell.map((r) => r.command)]);
  for (const name of bridgeInvokes) if (!served.has(name)) out.push(`src/lib/bridge.ts invokes ${name} but the shim does not serve it`);
  for (const name of served) if (!bridgeInvokes.includes(name)) out.push(`the shim serves ${name} but src/lib/bridge.ts never invokes it`);

  // 5. the constants the session and clipboard logic is built on
  const same = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  if (!same(shim.vaultStateOps, rust.vaultStateOps)) out.push(`VAULT_STATE_OPS: shim [${shim.vaultStateOps}] vs session.rs [${rust.vaultStateOps}]`);
  if (!same(shim.sessionEndedCodes, rust.sessionEndedCodes)) out.push(`SESSION_ENDED_CODES: shim [${shim.sessionEndedCodes}] vs error.rs [${rust.sessionEndedCodes}]`);
  if (shim.copyTextMaxBytes !== rust.copyTextMaxBytes) out.push(`COPY_TEXT_MAX_BYTES: shim ${shim.copyTextMaxBytes} vs commands.rs ${rust.copyTextMaxBytes}`);
  if (shim.clipboardTtlSeconds !== rust.clipboardTtlSeconds) out.push(`CLEAR_AFTER: shim ${shim.clipboardTtlSeconds} s vs clipboard.rs ${rust.clipboardTtlSeconds} s`);
  for (const code of shim.localCodesUsed) if (!rust.bridgeLocalCodes.includes(code)) out.push(`the shim raises the bridge-local code ${code}, which error.rs does not define`);
  for (const code of rust.sessionEndedCodes) if (!rust.brokerErrorCodes.includes(code)) out.push(`error.rs: session-ending code ${code} is not a broker error code`);

  return out;
}
