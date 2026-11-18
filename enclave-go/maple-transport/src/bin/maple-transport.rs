//! One-shot adapter protocol: a bounded JSON request on stdin, a status line
//! then canonical SSE on stdout. A failure before the status line writes one
//! `{"error":"<reason>"}` line instead, from this file's fixed vocabulary.
//! No credentials in arguments or diagnostics.
//! Runs inside the measured serving image, never on an untrusted parent host.
use bytes::Bytes;
use futures::StreamExt;
use http::Request;
use maple_sdk::{
    client::{InferenceSendBudget, TransportV2CacheNamespaceRoot},
    OpenSecretClient,
};
use serde_json::Value;
use std::io::{Read, Write};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{timeout, Duration};
use trustedrouter_maple_pilot::{relay::Relay, serving_policy, BACKEND, MODEL};
use zeroize::Zeroizing;

const REQUEST_LIMIT: usize = 16 * 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

/// Set once a status line is on stdout. After that the parent reads a status
/// and a stream, so a failure must not add a reason line to it.
static STATUS_WRITTEN: AtomicBool = AtomicBool::new(false);

fn write_status(out: &mut impl Write, status: u16) -> Result<()> {
    // Set first: once any status byte may be out, no reason line may follow.
    STATUS_WRITTEN.store(true, Ordering::SeqCst);
    writeln!(out, "{{\"status\":{status}}}")
        .and_then(|_| out.flush())
        .map_err(|_| "consumer_closed")
}

/// The line the parent reads when the helper fails before any status. REASON
/// is always one of this file's fixed strings, never SDK or provider text.
fn failure_line(reason: &str) -> String {
    format!("{{\"error\":\"{reason}\"}}")
}

/// What a failed helper adds to stdout: its reason line, unless a status line
/// has started, after which the parent is reading a status and a stream.
fn failure_output(reason: &str, status_written: bool) -> Option<String> {
    (!status_written).then(|| failure_line(reason))
}

/// The fixed reason a request failed before Maple answered. A refused
/// attestation (an invalid Nitro document, or a PCR0 neither pinned nor in
/// Maple's signed history) is told apart: it is the one an operator acts on.
fn send_failure(error: maple_sdk::Error) -> &'static str {
    match error {
        maple_sdk::Error::AttestationVerificationFailed(_) => "attestation_rejected",
        _ => "encrypted_request_failed",
    }
}

struct Input {
    key: Zeroizing<String>,
    root: TransportV2CacheNamespaceRoot,
    body: Bytes,
}

fn decode(bytes: &[u8]) -> Result<Input> {
    let mut input: Value = serde_json::from_slice(bytes).map_err(|_| "invalid_request")?;
    let object = input.as_object_mut().ok_or("invalid_request")?;
    if object.len() != 3 {
        return Err("invalid_request_fields");
    }
    let key = match object.remove("api_key") {
        Some(Value::String(key)) if !key.trim().is_empty() && key.len() <= 8192 => {
            Zeroizing::new(key)
        }
        _ => return Err("invalid_credential"),
    };
    let root = match object.remove("cache_root") {
        Some(Value::String(root)) => {
            let root = Zeroizing::new(root);
            TransportV2CacheNamespaceRoot::from_base64(&root).map_err(|_| "invalid_cache_root")?
        }
        _ => return Err("invalid_cache_root"),
    };
    let mut body = object.remove("body").ok_or("missing_body")?;
    let body_object = body.as_object_mut().ok_or("invalid_body")?;
    if body_object.get("model").and_then(Value::as_str) != Some(MODEL)
        || body_object.get("stream").and_then(Value::as_bool) != Some(true)
        || body_object.get("n").is_some_and(|n| n.as_u64() != Some(1))
    {
        return Err("unsupported_request");
    }
    // The authorized workspace root is the sole cache authority. Never let a
    // caller-provided wire field bridge unrelated tenants' KV caches.
    for field in [
        "cache_salt",
        "cache_namespace_root",
        "prompt_cache_key",
        "prompt_cache_options",
        "prompt_cache_retention",
        "user",
    ] {
        body_object.remove(field);
    }
    body_object.insert(
        "stream_options".into(),
        serde_json::json!({"include_usage":true}),
    );
    let body = serde_json::to_vec(&body).map_err(|_| "encode_failed")?;
    Ok(Input {
        key,
        root,
        body: Bytes::from(body),
    })
}

async fn run(input: Input, out: &mut impl Write) -> Result<()> {
    let client = OpenSecretClient::new_with_api_key_and_pcr0_trust_policy(
        BACKEND,
        input.key.to_string(),
        // Maple's signed history, as its SDK clients trust it (see serving_policy).
        serving_policy().map_err(|_| "invalid_policy")?,
    )
    .map_err(|_| "client_initialization_failed")?
    .with_cache_namespace_root(input.root);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .body(input.body)
        .map_err(|_| "request_construction_failed")?;
    let budget = InferenceSendBudget::new(1).map_err(|_| "invalid_send_budget")?;
    let response = timeout(
        Duration::from_secs(120),
        client.send_inference_request_with_budget(request, budget),
    )
    .await
    .map_err(|_| "response_start_timeout")?
    .map_err(send_failure)?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    if status != 200 {
        // Do not expose provider error bodies or trust a partial error response.
        let mut count = 0usize;
        while let Some(chunk) = timeout(Duration::from_secs(30), body.next())
            .await
            .map_err(|_| "error_body_timeout")?
        {
            count = count
                .checked_add(chunk.map_err(|_| "encrypted_body_failed")?.len())
                .ok_or("error_body_too_large")?;
            if count > 64 * 1024 {
                return Err("error_body_too_large");
            }
        }
        write_status(out, status)?;
        return Ok(());
    }
    write_status(out, 200)?;
    let mut relay = Relay::default();
    while let Some(chunk) = timeout(Duration::from_secs(90), body.next())
        .await
        .map_err(|_| "response_idle_timeout")?
    {
        relay.push(&chunk.map_err(|_| "encrypted_body_failed")?, out)?;
    }
    relay.finish(out)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // No tracing subscriber: SDK/provider diagnostics must not log plaintext.
    std::panic::set_hook(Box::new(|_| eprintln!("maple.adapter_failed")));
    let mut bytes = Zeroizing::new(Vec::new());
    let result = std::io::stdin()
        .take((REQUEST_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "request_read_failed")
        .and_then(|_| {
            if bytes.len() > REQUEST_LIMIT {
                Err("request_too_large")
            } else {
                decode(&bytes)
            }
        });
    let result = match result {
        Ok(input) => {
            drop(bytes);
            timeout(
                Duration::from_secs(600),
                run(input, &mut std::io::stdout().lock()),
            )
            .await
            .map_err(|_| "request_timeout")
            .and_then(|result| result)
        }
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            eprintln!("maple.{reason}");
            if let Some(line) = failure_output(reason, STATUS_WRITTEN.load(Ordering::SeqCst)) {
                let mut out = std::io::stdout().lock();
                let _ = writeln!(out, "{line}").and_then(|_| out.flush());
            }
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request() -> Value {
        json!({"api_key":"test", "cache_root":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "body":{"model":MODEL,"stream":true,"messages":[{"role":"user","content":"PONG"}]}})
    }

    #[test]
    fn restricts_model_and_transport() {
        for (key, value) in [
            ("model", json!("deepseek-v4-1-flash")),
            ("stream", json!(false)),
            ("n", json!(2)),
        ] {
            let mut request = request();
            request["body"][key] = value;
            assert!(decode(&serde_json::to_vec(&request).unwrap()).is_err());
        }
        let mut request = request();
        request["backend"] = json!("https://attacker.example");
        assert!(decode(&serde_json::to_vec(&request).unwrap()).is_err());
    }

    #[test]
    fn strips_caller_cache_fields_and_requires_usage() {
        let mut request = request();
        for field in [
            "cache_salt",
            "cache_namespace_root",
            "prompt_cache_key",
            "prompt_cache_options",
            "prompt_cache_retention",
            "user",
        ] {
            request["body"][field] = json!("caller-controlled");
        }
        request["body"]["stream_options"] = json!({"include_usage":false});
        let input = decode(&serde_json::to_vec(&request).unwrap()).unwrap();
        let body: Value = serde_json::from_slice(&input.body).unwrap();
        assert_eq!(body["stream_options"]["include_usage"], true);
        assert!(!input.body.windows(17).any(|w| w == b"caller-controlled"));
    }

    #[test]
    fn invalid_roots_cannot_silently_share_cache() {
        for root in [Value::Null, json!(""), json!("abc")] {
            let mut request = request();
            request["cache_root"] = root;
            assert!(decode(&serde_json::to_vec(&request).unwrap()).is_err());
        }
    }

    /// Every reason the helper can fail with before a status line, except
    /// consumer_closed: the parent has gone and reads nothing. The parent's
    /// adapterFailures (internal/maple/client.go) must have exactly these keys;
    /// a Go test reads this list from this file.
    const PRE_STATUS_REASONS: &[&str] = &[
        "attestation_rejected",
        "encrypted_request_failed",
        "response_start_timeout",
        "request_timeout",
        "client_initialization_failed",
        "invalid_policy",
        "request_construction_failed",
        "invalid_send_budget",
        "request_read_failed",
        "request_too_large",
        "invalid_request",
        "invalid_request_fields",
        "invalid_credential",
        "invalid_cache_root",
        "missing_body",
        "invalid_body",
        "unsupported_request",
        "encode_failed",
        "error_body_timeout",
        "encrypted_body_failed",
        "error_body_too_large",
    ];

    #[test]
    fn attestation_rejection_is_told_apart_from_other_send_failures() {
        assert_eq!(
            send_failure(maple_sdk::Error::AttestationVerificationFailed(
                "PCR0 is not approved by the configured trust policy".into()
            )),
            "attestation_rejected"
        );
        for other in [
            maple_sdk::Error::Session("x".into()),
            maple_sdk::Error::InvalidResponse("x".into()),
            maple_sdk::Error::KeyExchange("x".into()),
            maple_sdk::Error::Configuration("x".into()),
        ] {
            assert_eq!(send_failure(other), "encrypted_request_failed");
        }
    }

    #[test]
    fn failure_line_is_one_short_fixed_json_object() {
        for reason in PRE_STATUS_REASONS {
            let line = failure_line(reason);
            // The parent reads at most 64 bytes, newline included.
            assert!(line.len() < 64, "{reason}");
            let parsed: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(parsed, json!({ "error": reason }));
        }
    }

    #[test]
    fn a_written_status_suppresses_the_failure_line() {
        assert_eq!(
            failure_output("attestation_rejected", false).as_deref(),
            Some("{\"error\":\"attestation_rejected\"}")
        );
        assert_eq!(failure_output("attestation_rejected", true), None);
        let mut out = Vec::new();
        write_status(&mut out, 401).unwrap();
        assert_eq!(out, b"{\"status\":401}\n");
        assert!(STATUS_WRITTEN.load(Ordering::SeqCst));
    }

    #[test]
    fn a_failed_status_write_still_suppresses_the_failure_line() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(write_status(&mut Closed, 200), Err("consumer_closed"));
        assert!(STATUS_WRITTEN.load(Ordering::SeqCst));
    }
}
