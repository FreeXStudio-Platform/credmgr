/**
 * The bridge's error type, in the shape `invoke()` rejects with (`src-tauri/src/error.rs`): `{ source, code, message, detail? }`.
 *
 * `source` is one of transport | protocol | broker | bridge; only a `broker` error with a session-ending code ends the login.
 * A transport failure ("could not connect") says nothing about whether the token is still good, so it never does.
 */
import { SESSION_ENDED_CODES } from "./table.mjs";

/** Bridge-local codes this shim can raise (all must be in error.rs `BRIDGE_LOCAL_CODES`; the drift guard checks). */
export const LOCAL_CODES_USED = ["broker_unreachable", "malformed_response", "text_too_large", "clipboard_failed", "field_required", "invalid_fields"];

export function transportError(message) {
  return { source: "transport", code: "broker_unreachable", message };
}

export function protocolError(message) {
  return { source: "protocol", code: "malformed_response", message };
}

export function bridgeError(code, message) {
  return { source: "bridge", code, message };
}

function defaultMessage(code) {
  switch (code) {
    case "wrong_passphrase":
      return "that passphrase did not unlock the vault";
    case "two_factor_required":
      return "the passphrase was accepted; a second factor is still required";
    case "conflict":
      return "someone else changed this node since you loaded it; reload and retry";
    case "capability_not_held":
      return "this session does not hold that capability";
    default:
      return code;
  }
}

/** `BridgeError::from_wire`: the broker's own words, with the envelope's `id` and `ok` removed from `detail`. */
export function fromWire(body) {
  const code = typeof body.error === "string" ? body.error : "unknown";
  const message = typeof body.message === "string" ? body.message : defaultMessage(code);
  const detail = { ...body };
  delete detail.id;
  delete detail.ok;
  return { source: "broker", code, message, detail };
}

export function endsSession(error) {
  return error.source === "broker" && SESSION_ENDED_CODES.includes(error.code);
}
