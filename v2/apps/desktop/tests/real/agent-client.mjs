/**
 * A one-shot, tokenless broker client, run as its own process (`node agent-client.mjs <socket> <op> <paramsJson>`).
 *
 * The broker decides what a tokenless caller may do from the caller's PROCESS (its working directory against the folders bound
 * to nodes), so an agent has to be a separate process with the right cwd; claiming a node in the request changes nothing.
 * Prints `{ok: true, value}` or `{ok: false, error}` as one JSON line. Never prints a token.
 */
import { call } from "./shim/transport.mjs";

const [socketPath, op, paramsJson] = process.argv.slice(2);
try {
  const value = await call(socketPath, op, null, JSON.parse(paramsJson ?? "{}"));
  process.stdout.write(`${JSON.stringify({ ok: true, value })}\n`);
} catch (error) {
  process.stdout.write(`${JSON.stringify({ ok: false, error })}\n`);
}
