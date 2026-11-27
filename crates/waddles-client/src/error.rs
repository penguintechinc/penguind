//! Everything a [`crate::WaddlesClient`] request can fail with, plus the
//! hub API's error-body decoder.
//!
//! The hub is inconsistent about the shape of an error body across
//! controllers: the global error handler (`middleware/errorHandler.js`)
//! emits `{"error": {"code": ..., "message": ...}}`, but several
//! controllers answer directly with `res.status(...).json({"error": "..."})`
//! or `{"success": false, "error": "..."}` instead of going through it —
//! `tokenController.js`, `musicController.js`, and the inline 403 in
//! `middleware/auth.js`'s `requireScope` are three confirmed examples.
//! [`ErrorBody`]/[`parse_error_body`] accept all three without the caller
//! needing to know which controller answered.

use serde_json::Value;

/// One decoded hub API error body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorBody {
    /// `{"error": {"code": "...", "message": "..."}}` — the global error
    /// handler's shape. `success` may or may not also be present; it's
    /// ignored either way.
    Structured { code: String, message: String },
    /// `{"error": "..."}` or `{"success": false, "error": "..."}` — the
    /// inline shape several controllers use directly instead of going
    /// through the shared error factory.
    Plain(String),
    /// The body wasn't JSON at all, or was JSON that didn't match either
    /// known shape (e.g. no `error` key). Kept verbatim rather than
    /// discarded, so callers can still see what the hub actually sent.
    Unparsed(String),
}

impl std::fmt::Display for ErrorBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorBody::Structured { code, message } => write!(f, "{code}: {message}"),
            ErrorBody::Plain(message) => write!(f, "{message}"),
            ErrorBody::Unparsed(raw) => write!(f, "{raw}"),
        }
    }
}

/// Parses a non-2xx response body into an [`ErrorBody`], trying each known
/// shape before giving up and keeping the raw bytes.
pub(crate) fn parse_error_body(bytes: &[u8]) -> ErrorBody {
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return ErrorBody::Unparsed(String::from_utf8_lossy(bytes).into_owned());
    };

    let Some(error_value) = value.get("error") else {
        return ErrorBody::Unparsed(String::from_utf8_lossy(bytes).into_owned());
    };

    if let Some(message) = error_value.as_str() {
        return ErrorBody::Plain(message.to_string());
    }

    if let Some(object) = error_value.as_object() {
        let code = object
            .get("code")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let message = object
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        return ErrorBody::Structured {
            code: code.to_string(),
            message: message.to_string(),
        };
    }

    ErrorBody::Unparsed(String::from_utf8_lossy(bytes).into_owned())
}

/// Every way a [`crate::WaddlesClient`] call can fail.
#[derive(Debug, thiserror::Error)]
pub enum WaddlesError {
    /// Building the client's HTTP/TLS stack failed — before any request is
    /// sent.
    #[error("failed to set up HTTP client: {0}")]
    Setup(String),
    /// The request never got a usable response: DNS failure, connection
    /// refused, timeout, TLS handshake failure, or the response body
    /// couldn't be read off the wire.
    #[error("transport error: {0}")]
    Transport(String),
    /// The hub rejected the request's credentials — HTTP 401 or 403. Kept
    /// distinct from [`WaddlesError::Status`] because it's the one
    /// outcome callers almost always want to handle differently.
    ///
    /// As of `waddlebot#155`, this is currently the *only* outcome a valid
    /// `wdl_c_...` CAT ever produces: `requireAuth` in
    /// `middleware/auth.js` defines `resolveCAT`/`resolvePAT` but never
    /// calls them, so every CAT-authenticated request falls through to the
    /// session-JWT path, finds no session, and 401s — regardless of
    /// whether the CAT itself is valid, scoped correctly, or even exists.
    /// This crate is built to the endpoint's intended contract regardless
    /// of that gap; there is no client-side workaround for a server-side
    /// auth bug.
    #[error("authentication rejected (HTTP {status}): {body}")]
    Auth { status: u16, body: ErrorBody },
    /// Any other non-2xx response.
    #[error("HTTP {status}: {body}")]
    Status { status: u16, body: ErrorBody },
    /// The response was 2xx but its body wasn't the JSON shape expected.
    #[error("failed to decode response: {0}")]
    Decode(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_error_body_reads_the_structured_global_handler_shape() {
        let body = parse_error_body(
            br#"{"success":false,"error":{"code":"NOT_FOUND","message":"missing"}}"#,
        );
        assert_eq!(
            body,
            ErrorBody::Structured {
                code: "NOT_FOUND".to_string(),
                message: "missing".to_string(),
            }
        );
    }

    #[test]
    fn parse_error_body_reads_the_bare_string_shape() {
        let body = parse_error_body(br#"{"error":"Token name is required"}"#);
        assert_eq!(body, ErrorBody::Plain("Token name is required".to_string()));
    }

    #[test]
    fn parse_error_body_reads_the_success_false_string_shape() {
        let body = parse_error_body(br#"{"success":false,"error":"Failed to get music settings"}"#);
        assert_eq!(
            body,
            ErrorBody::Plain("Failed to get music settings".to_string())
        );
    }

    #[test]
    fn parse_error_body_keeps_unparseable_bytes_verbatim() {
        let body = parse_error_body(b"<html>502 Bad Gateway</html>");
        assert_eq!(
            body,
            ErrorBody::Unparsed("<html>502 Bad Gateway</html>".to_string())
        );
    }

    #[test]
    fn parse_error_body_keeps_json_with_no_error_key_verbatim() {
        let body = parse_error_body(br#"{"message":"no error field here"}"#);
        assert!(matches!(body, ErrorBody::Unparsed(_)));
    }
}
