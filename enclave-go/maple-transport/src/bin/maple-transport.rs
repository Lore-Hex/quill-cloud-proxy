//! One-shot adapter protocol: a bounded JSON request on stdin, a status line
//! then canonical SSE on stdout. No credentials in arguments or diagnostics.
//! Runs inside the measured serving image, never on an untrusted parent host.
use bytes::Bytes;
use futures::StreamExt;
use http::Request;
use maple_sdk::{
    client::{InferenceSendBudget, TransportV2CacheNamespaceRoot},
    OpenSecretClient, Pcr0TrustPolicy,
};
use serde_json::Value;
use std::io::{Read, Write};
use std::process::ExitCode;
use tokio::time::{timeout, Duration};
use trustedrouter_maple_pilot::{relay::Relay, BACKEND, MODEL, PCR0};
use zeroize::Zeroizing;

const REQUEST_LIMIT: usize = 16 * 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

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
        Pcr0TrustPolicy::from_static_allowlist([PCR0]).map_err(|_| "invalid_policy")?,
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
    .map_err(|_| "encrypted_request_failed")?;
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
        writeln!(out, "{{\"status\":{status}}}")
            .and_then(|_| out.flush())
            .map_err(|_| "consumer_closed")?;
        return Ok(());
    }
    writeln!(out, "{{\"status\":200}}")
        .and_then(|_| out.flush())
        .map_err(|_| "consumer_closed")?;
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
}
