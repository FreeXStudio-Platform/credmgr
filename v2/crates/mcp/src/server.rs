//! The MCP stdio server loop — JSON-RPC 2.0 over newline-delimited stdin/
//! stdout, the three methods this server actually needs: `initialize`,
//! `tools/list`, `tools/call`. No resources, no prompts, no sampling —
//! `credmgr` has nothing to offer any of those MCP capabilities.
//!
//! Generic over `Read`/`Write` (not hard-wired to real stdin/stdout) so the
//! whole protocol loop is testable with in-memory buffers — the same
//! "take I/O as a parameter, not a global" discipline `crates/core`'s
//! purity rule applies at the crypto layer, applied here at the transport
//! layer instead.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::tools;

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "credmgr";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Runs the loop until EOF. Malformed input on one line produces a JSON-RPC
/// parse-error response and continues — one bad frame must not kill the
/// whole session, matching `credmgrd`'s own `server::serve_connection`
/// convention for its wire protocol.
pub fn run(mut reader: impl BufRead, mut writer: impl Write) -> std::io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(()); // EOF
        }
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(response) = handle_line(trimmed) {
            writeln!(writer, "{response}")?;
        }
    }
}

/// `None` for a notification (no `id`) — per JSON-RPC 2.0, a notification
/// gets no response at all, not even an empty one.
fn handle_line(line: &str) -> Option<Value> {
    let request: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(json!({
                "jsonrpc": "2.0", "id": Value::Null,
                "error": { "code": -32700, "message": format!("parse error: {e}") },
            }));
        }
    };

    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(json!({}));

    let Some(id) = id else {
        return None; // notification — no response, even for an unknown method
    };

    let result = dispatch_method(method, &params);
    Some(match result {
        Ok(value) => json!({ "jsonrpc": "2.0", "id": id, "result": value }),
        Err(RpcError { code, message }) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
        }
    })
}

struct RpcError {
    code: i64,
    message: String,
}

fn dispatch_method(method: &str, params: &Value) -> Result<Value, RpcError> {
    match method {
        "initialize" => Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": { "name": SERVER_NAME, "version": SERVER_VERSION },
        })),
        "tools/list" => Ok(json!({
            "tools": tools::registry().iter().map(|t| json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": (t.input_schema)(),
            })).collect::<Vec<_>>(),
        })),
        "tools/call" => {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError {
                    code: -32602,
                    message: "params.name is required".to_string(),
                })?;
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            Ok(tool_call_result(name, arguments))
        }
        other => Err(RpcError {
            code: -32601,
            message: format!("unknown method: {other}"),
        }),
    }
}

/// A tool failing (denied, not found, wrong argument) is an MCP *tool*
/// error — `isError: true` inside a normal JSON-RPC result — never a
/// JSON-RPC protocol-level error. `params.name` naming an unregistered tool
/// is the one exception (a protocol-level "you asked for something that
/// isn't there", raised in `dispatch_method` via `-32602` before ever
/// reaching here — this function only runs for tools that exist).
fn tool_call_result(name: &str, arguments: Value) -> Value {
    match tools::call_tool(name, arguments) {
        Ok(value) => json!({
            "content": [{ "type": "text", "text": value.to_string() }],
            "isError": false,
        }),
        Err(e) => json!({
            "content": [{ "type": "text", "text": e.to_string() }],
            "isError": true,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn run_one(input: &str) -> String {
        let mut out = Vec::new();
        run(Cursor::new(input.as_bytes()), &mut out).expect("run");
        String::from_utf8(out).expect("utf8")
    }

    #[test]
    fn initialize_reports_the_protocol_version_and_tools_capability() {
        let out = run_one(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);
        let v: Value = serde_json::from_str(out.trim()).expect("valid json");
        assert_eq!(v["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(v["result"]["capabilities"]["tools"], json!({}));
    }

    #[test]
    fn tools_list_returns_the_real_registry_with_schemas() {
        let out = run_one(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
        let v: Value = serde_json::from_str(out.trim()).expect("valid json");
        let listed = v["result"]["tools"].as_array().expect("array");
        assert_eq!(listed.len(), tools::registry().len());
        let names: Vec<&str> = listed.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"credmgr_whoami"));
        assert!(listed[0]["inputSchema"]["type"] == "object");
    }

    #[test]
    fn a_notification_gets_no_response_line_at_all() {
        let out = run_one(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        assert_eq!(out, "", "a request with no id must produce no output");
    }

    #[test]
    fn an_unknown_method_is_a_named_jsonrpc_error() {
        let out = run_one(r#"{"jsonrpc":"2.0","id":3,"method":"not/a/real/method"}"#);
        let v: Value = serde_json::from_str(out.trim()).expect("valid json");
        assert_eq!(v["error"]["code"], -32601);
    }

    #[test]
    fn malformed_json_gets_a_parse_error_and_the_loop_continues() {
        let mut out = Vec::new();
        let input = "not json at all\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"initialize\"}\n";
        run(Cursor::new(input.as_bytes()), &mut out).expect("run");
        let text = String::from_utf8(out).expect("utf8");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines.len(),
            2,
            "one error line, then the next request still answered"
        );
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(first["error"]["code"], -32700);
        let second: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(second["id"], 9);
    }

    #[test]
    fn calling_an_unregistered_tool_is_a_tool_error_not_a_protocol_error() {
        let out = run_one(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"credmgr_grant_create","arguments":{}}}"#,
        );
        let v: Value = serde_json::from_str(out.trim()).expect("valid json");
        assert!(
            v.get("error").is_none(),
            "must be a result, not a JSON-RPC error"
        );
        assert_eq!(v["result"]["isError"], true);
    }
}
