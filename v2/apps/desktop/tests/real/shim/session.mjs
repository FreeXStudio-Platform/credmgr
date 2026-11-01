/**
 * Token custody, as `src-tauri/src/session.rs` does it: the login token lives here, in the shim (the Node side of the test),
 * and never in the page. The page learns only {@link AuthState}; the unlock answer's `token` is stripped before it is returned.
 */
import { endsSession } from "./bridge-error.mjs";
import { VAULT_STATE_OPS } from "./table.mjs";

export class Session {
  #token = null;

  token() {
    return this.#token;
  }

  isAuthenticated() {
    return this.#token !== null;
  }

  set(token) {
    this.#token = token;
  }

  clear() {
    this.#token = null;
  }

  /** Take `token` out of an unlock-like answer, whatever its type; keep it only if it is a string. */
  captureToken(value) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    const token = value.token;
    delete value.token;
    if (typeof token === "string") {
      this.#token = token;
      return true;
    }
    return false;
  }

  /**
   * An answer that says the vault is locked ends the login (the idle auto-lock revokes the token broker-side with no event).
   * `locked` on a vault-state op names the vault; on any other op it may name a NODE (`vault.node_lock` answers
   * `{node, locked: true}`), which must not end the login. `meta.vaultLocked` names the vault on any op.
   */
  reconcileOk(op, value) {
    const flat = VAULT_STATE_OPS.includes(op) && typeof value?.locked === "boolean" ? value.locked : null;
    const nested = typeof value?.meta?.vaultLocked === "boolean" ? value.meta.vaultLocked : null;
    const locked = flat ?? nested ?? false;
    if (locked) this.clear();
  }

  reconcileErr(error) {
    if (endsSession(error)) this.clear();
  }
}
