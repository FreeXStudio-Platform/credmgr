/**
 * One request, one response, over the broker's Unix domain socket: connect, write one newline-terminated JSON object, read exactly
 * one line back, close. A port of `src-tauri/src/transport.rs`, which is itself a port of the CLI's reference transport
 * (`10_API_AND_MCP.md §1`).
 *
 * Unix-domain only. Nothing in the real-broker suite opens or connects to a TCP port.
 */
import net from "node:net";

import { fromWire, protocolError, transportError } from "./bridge-error.mjs";

/** The shell allows 30 s: `vault.unlock` does a memory-hard key derivation before it answers. */
export const READ_TIMEOUT_MS = 30_000;

let nextRequestId = 1;

/**
 * Parse and adjudicate one response line. Returns the `value`, or throws the typed bridge error. The server answers an
 * unparseable frame with `id: "?"`: a real answer to a real failure, so it is adjudicated like any other denial.
 */
export function interpret(requestId, line) {
  return interpretAudited(requestId, line).value;
}

/** {@link interpret}, keeping the envelope's `audit` id (a string, or null): `{ value, audit }`. */
export function interpretAudited(requestId, line) {
  const trimmed = line.trim();
  if (trimmed === "") throw transportError("credmgrd closed the connection without answering");
  let body;
  try {
    body = JSON.parse(trimmed);
  } catch (e) {
    throw protocolError(`response was not JSON: ${e.message}`);
  }
  const echoed = typeof body?.id === "string" ? body.id : "";
  if (echoed !== requestId && echoed !== "?") {
    throw protocolError(`response id ${JSON.stringify(echoed)} does not match request id ${JSON.stringify(requestId)}`);
  }
  if (body.ok === true) return { value: body.value === undefined ? null : body.value, audit: typeof body.audit === "string" ? body.audit : null };
  if (body.ok === false) throw fromWire(body);
  throw protocolError("response carried no boolean 'ok' field");
}

/**
 * Send one op and resolve with its `value`, or reject with the typed denial.
 * @param {string} socketPath
 * @param {string} op
 * @param {string|null} token  attached here, on the shim side; nothing above this function hands a token to the page
 * @param {object} params
 * @param {{timeoutMs?: number}} [options]
 */
export function call(socketPath, op, token, params, options = {}) {
  return callAudited(socketPath, op, token, params, options).then((r) => r.value);
}

/** {@link call}, resolving with `{ value, audit }` (src-tauri/src/transport.rs `call_audited`). */
export function callAudited(socketPath, op, token, params, options = {}) {
  const timeoutMs = options.timeoutMs ?? READ_TIMEOUT_MS;
  const id = String(nextRequestId++);
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ path: socketPath });
    let buffer = "";
    let settled = false;
    const settle = (fn, arg) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      fn(arg);
    };
    socket.setTimeout(timeoutMs, () => settle(reject, transportError(`no response from credmgrd within ${timeoutMs} ms`)));
    socket.once("connect", () => {
      socket.write(`${JSON.stringify({ id, op, token, params })}\n`, (err) => {
        if (err) settle(reject, transportError(`could not send the request: ${err.message}`));
      });
    });
    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      const nl = buffer.indexOf("\n");
      if (nl < 0) return;
      const line = buffer.slice(0, nl);
      try {
        settle(resolve, interpretAudited(id, line));
      } catch (e) {
        settle(reject, e);
      }
    });
    socket.on("end", () => {
      if (settled) return;
      try {
        settle(resolve, interpretAudited(id, buffer));
      } catch (e) {
        settle(reject, e);
      }
    });
    socket.on("error", (err) => settle(reject, transportError(`could not connect to credmgrd at ${socketPath}: ${err.message} (is it running?)`)));
  });
}
