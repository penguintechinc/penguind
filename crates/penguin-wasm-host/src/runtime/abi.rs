//! The `penguin.call_tool` host import: guest-memory marshalling and error codes.

use penguin_sdk::tools::ToolError;
use serde_json::{Value, json};
use wasmtime::Caller;

use super::{HostState, memory_of};
use crate::tools::MAX_ARGS_BYTES;

/// Unknown tool id.
pub const E_UNKNOWN_TOOL: i32 = -1;
/// Arguments malformed or failed schema validation.
pub const E_INVALID_ARGS: i32 = -2;
/// The executor failed or returned a bad result.
pub const E_FAILED: i32 = -3;
/// Tool declared but not implemented on this host.
pub const E_NOT_IMPLEMENTED: i32 = -4;
/// Tool not in this module's allowlist.
pub const E_FORBIDDEN: i32 = -5;
/// The executor timed out.
pub const E_TIMEOUT: i32 = -6;
/// The guest's output buffer was too small for the result.
pub const E_BUFFER_TOO_SMALL: i32 = -7;
/// A pointer/length pair fell outside guest memory.
pub const E_BAD_POINTER: i32 = -8;
/// The per-run tool call budget is spent.
pub const E_TOO_MANY_CALLS: i32 = -9;

const MAX_NAME_BYTES: usize = 128;
/// Largest result body the host will write into guest memory.
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;
/// Longest error message written to the guest (bytes; cut on a char boundary).
pub const MAX_ERROR_MESSAGE_BYTES: usize = 512;

/// Truncates `text` to at most `max` bytes without splitting a character.
pub fn truncate_utf8(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Maps a [`ToolError`] to its ABI code.
pub fn code_for(err: &ToolError) -> i32 {
    match err {
        ToolError::UnknownTool(_) => E_UNKNOWN_TOOL,
        ToolError::InvalidArgs { .. } => E_INVALID_ARGS,
        ToolError::Failed { .. } | ToolError::BadResult { .. } | ToolError::Unavailable => E_FAILED,
        ToolError::NotImplemented(_) => E_NOT_IMPLEMENTED,
        ToolError::Forbidden(_) => E_FORBIDDEN,
        ToolError::Timeout(_) => E_TIMEOUT,
    }
}

fn read(
    caller: &Caller<'_, HostState>,
    mem: &wasmtime::Memory,
    ptr: i32,
    len: i32,
) -> Option<Vec<u8>> {
    let start = usize::try_from(ptr).ok()?;
    let len = usize::try_from(len).ok()?;
    let end = start.checked_add(len)?;
    mem.data(caller).get(start..end).map(<[u8]>::to_vec)
}

/// Writes `body` to the guest's out buffer; returns false if it doesn't fit/bounds.
fn write(
    caller: &mut Caller<'_, HostState>,
    mem: &wasmtime::Memory,
    ptr: i32,
    cap: i32,
    body: &[u8],
) -> bool {
    let (Ok(start), Ok(cap)) = (usize::try_from(ptr), usize::try_from(cap)) else {
        return false;
    };
    body.len() <= cap && mem.write(caller, start, body).is_ok()
}

/// The host import body: decode name/args, dispatch through the registry,
/// encode the result or a typed error body, and record the call.
pub(crate) async fn call_tool(
    mut caller: Caller<'_, HostState>,
    (np, nl, ap, al, op, oc): (i32, i32, i32, i32, i32, i32),
) -> i32 {
    if !caller.data_mut().begin_call() {
        return E_TOO_MANY_CALLS;
    }
    let Some(mem) = memory_of(&mut caller) else {
        return E_BAD_POINTER;
    };
    let name_bytes = if usize::try_from(nl).is_ok_and(|n| n <= MAX_NAME_BYTES) {
        read(&caller, &mem, np, nl)
    } else {
        None
    };
    let Some(name) = name_bytes.and_then(|b| String::from_utf8(b).ok()) else {
        caller
            .data_mut()
            .record("<invalid-name>".into(), E_BAD_POINTER);
        return E_BAD_POINTER;
    };
    let finish = |caller: &mut Caller<'_, HostState>, code: i32| {
        caller.data_mut().record(name.clone(), code);
        code
    };

    let args_raw = if usize::try_from(al).is_ok_and(|n| n <= MAX_ARGS_BYTES) {
        read(&caller, &mem, ap, al)
    } else {
        None
    };
    let Some(args_raw) = args_raw else {
        return finish(&mut caller, E_BAD_POINTER);
    };

    let registry = caller.data().registry();
    let allowed = caller.data().allowed();
    let allowed_dns = caller.data().allowed_dns();
    let outcome = match serde_json::from_slice::<Value>(&args_raw) {
        // DNS names are a per-module grant, checked before any request.
        Ok(args)
            if name == "doh_query"
                && allowed.contains(&name)
                && !allowed_dns.permits(args["name"].as_str().unwrap_or("")) =>
        {
            Err(ToolError::Forbidden(
                "doh_query: name not in module DNS allowlist".into(),
            ))
        }
        Ok(args) => {
            registry
                .call_scoped(&name, args, Some(allowed.as_ref()))
                .await
        }
        Err(e) => Err(ToolError::InvalidArgs {
            tool: name.clone(),
            reason: e.to_string(),
        }),
    };

    match outcome {
        Ok(value) => {
            let body = serde_json::to_vec(&value).unwrap_or_default();
            if body.len() <= MAX_OUTPUT_BYTES && write(&mut caller, &mem, op, oc, &body) {
                let len = i32::try_from(body.len()).unwrap_or(i32::MAX);
                finish(&mut caller, len)
            } else {
                finish(&mut caller, E_BUFFER_TOO_SMALL)
            }
        }
        Err(err) => {
            let code = code_for(&err);
            let message = err.to_string();
            let message = truncate_utf8(&message, MAX_ERROR_MESSAGE_BYTES);
            let body = json!({ "error": { "code": code, "message": message } });
            let bytes = serde_json::to_vec(&body).unwrap_or_default();
            let _ = write(&mut caller, &mem, op, oc, &bytes);
            finish(&mut caller, code)
        }
    }
}
