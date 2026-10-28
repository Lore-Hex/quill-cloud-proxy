//! Qualification only. Not linked into the serving image or a privacy claim.
use bytes::Bytes;
use eventsource_stream::Eventsource;
use futures::StreamExt;
use http::{Request, StatusCode};
use maple_sdk::{client::InferenceSendBudget, OpenSecretClient, Pcr0TrustPolicy};
use serde_json::{json, Value};
use std::{env, process::ExitCode, time::Instant};
use tokio::time::{timeout, Duration};

const BACKEND: &str = "https://enclave.trymaple.ai";
const MODEL: &str = "deepseek-v4-1-flash-1017-uncensored";
// Latest entry in the production history at the pinned source revision.
// Candidate only: acceptance is not proof of source/image reproducibility.
const PCR0: &str = "ada74c7aa10cbde75f83d7ec674cc4fc4a4cf9cc555e367189fbec332dffa985c6082ae4647fd50242a590bf9cd1d3f0";
const BAD_PCR0: &str = "bda74c7aa10cbde75f83d7ec674cc4fc4a4cf9cc555e367189fbec332dffa985c6082ae4647fd50242a590bf9cd1d3f0";
const LIMIT: usize = 4 * 1024 * 1024;
type Check<T> = Result<T, &'static str>;

#[derive(Debug, PartialEq)]
struct Usage {
    input: u64,
    output: u64,
    cached: u64,
}

fn usage(value: &Value) -> Check<Usage> {
    let input = value["prompt_tokens"]
        .as_u64()
        .ok_or("invalid_prompt_tokens")?;
    let output = value["completion_tokens"]
        .as_u64()
        .ok_or("invalid_completion_tokens")?;
    let total = value["total_tokens"]
        .as_u64()
        .ok_or("invalid_total_tokens")?;
    if input.checked_add(output) != Some(total) || input == 0 || output == 0 {
        return Err("invalid_usage_totals");
    }
    let cached = match value.get("prompt_tokens_details") {
        None | Some(Value::Null) => 0,
        Some(Value::Object(details)) => match details.get("cached_tokens") {
            None => 0,
            Some(value) => value.as_u64().ok_or("invalid_cached_tokens")?,
        },
        _ => return Err("invalid_prompt_token_details"),
    };
    if cached > input {
        return Err("cached_tokens_exceed_input");
    }
    Ok(Usage {
        input,
        output,
        cached,
    })
}

fn output_summary(kind: &str, usage: &Usage, elapsed: u128, first_delta: Option<u128>) {
    println!(
        "{}",
        json!({
            "check": kind, "ok": true, "model": MODEL,
            "input_tokens": usage.input, "output_tokens": usage.output,
            "cached_input_tokens": usage.cached, "elapsed_ms": elapsed,
            "first_delta_ms": first_delta,
            "billing_reconciled": false
        })
    );
}

async fn send(
    client: &OpenSecretClient,
    method: &str,
    path: &str,
    body: Bytes,
) -> Check<maple_sdk::client::InferenceResponse> {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .body(body)
        .map_err(|_| "request_construction_failed")?;
    // An unauthenticated transport retry hint is not evidence of non-execution.
    let budget = InferenceSendBudget::new(1).map_err(|_| "invalid_send_budget")?;
    timeout(
        Duration::from_secs(120),
        client.send_inference_request_with_budget(request, budget),
    )
    .await
    .map_err(|_| "response_start_timeout")?
    .map_err(|_| "encrypted_request_failed")
}

async fn collect(response: maple_sdk::client::InferenceResponse) -> Check<Value> {
    if response.status() != StatusCode::OK {
        println!(
            "{}",
            json!({"check":"logical_http_status", "status":response.status().as_u16()})
        );
        return Err("logical_http_failure");
    }
    let mut body = response.into_body();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|_| "encrypted_body_failed")?;
        if bytes.len() + chunk.len() > LIMIT {
            return Err("response_too_large");
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| "invalid_json_response")
}

fn validate_catalog(value: &Value) -> Check<usize> {
    let rows = value["data"].as_array().ok_or("invalid_catalog")?;
    let mut ids = std::collections::HashSet::new();
    for row in rows {
        let id = row["id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or("invalid_model_id")?;
        if !ids.insert(id) {
            return Err("duplicate_model_id");
        }
    }
    if !ids.contains(MODEL) {
        return Err("uncensored_model_not_advertised");
    }
    Ok(ids.len())
}

fn validate_completion(value: &Value) -> Check<Usage> {
    if value.get("error").is_some() {
        return Err("inference_error");
    }
    if value["model"].as_str() != Some(MODEL) {
        return Err("model_identity_mismatch");
    }
    let choice = &value["choices"][0];
    if choice["message"]["content"]
        .as_str()
        .is_none_or(|s| !pong(s))
    {
        return Err("pong_mismatch");
    }
    if choice["finish_reason"].as_str() != Some("stop") {
        return Err("incomplete_answer");
    }
    usage(&value["usage"])
}

fn pong(value: &str) -> bool {
    value
        .trim()
        .trim_matches(['\"', '\'', '.', '!'])
        .eq_ignore_ascii_case("PONG")
}

#[derive(Default)]
struct StreamChecks {
    seen_model: bool,
    content: bool,
    finish: bool,
    done: bool,
    usage: Option<Usage>,
    answer: String,
}

impl StreamChecks {
    fn accept(&mut self, data: &str) -> Check<bool> {
        if self.done {
            return Err("data_after_done");
        }
        if data.trim() == "[DONE]" {
            self.done = true;
            return Ok(false);
        }
        let value: Value = serde_json::from_str(data).map_err(|_| "invalid_sse_json")?;
        if value.get("error").is_some() {
            return Err("stream_error_event");
        }
        if let Some(model) = value.get("model") {
            if model.as_str() != Some(MODEL) {
                return Err("stream_model_identity_mismatch");
            }
            self.seen_model = true;
        }
        let mut got_delta = false;
        let choices = value["choices"]
            .as_array()
            .ok_or("invalid_stream_choices")?;
        for choice in choices {
            if let Some(reason) = choice["finish_reason"].as_str() {
                if reason != "stop" {
                    return Err("incomplete_stream");
                }
                self.finish = true;
            }
            if let Some(text) = choice["delta"]["content"].as_str() {
                if !text.is_empty() {
                    self.content = true;
                    if self.answer.len() + text.len() > 1024 {
                        return Err("unexpected_answer_length");
                    }
                    self.answer.push_str(text);
                    got_delta = true;
                }
            }
            for field in ["reasoning", "reasoning_content"] {
                got_delta |= choice["delta"][field]
                    .as_str()
                    .is_some_and(|s| !s.is_empty());
            }
        }
        if let Some(value) = value.get("usage").filter(|value| !value.is_null()) {
            if self.usage.is_some() {
                return Err("duplicate_stream_usage");
            }
            self.usage = Some(usage(value)?);
        }
        Ok(got_delta)
    }

    fn finish(self) -> Check<Usage> {
        if !self.done || !self.finish || !self.content || !self.seen_model || !pong(&self.answer) {
            return Err("incomplete_stream");
        }
        self.usage.ok_or("missing_stream_usage")
    }
}

async fn probe(client: &OpenSecretClient) -> Check<()> {
    let catalog = collect(send(client, "GET", "/v1/models", Bytes::new()).await?).await?;
    let count = validate_catalog(&catalog)?;
    println!(
        "{}",
        json!({"check":"catalog", "ok":true, "count":count, "model":MODEL})
    );
    for stream in [false, true] {
        let started = Instant::now();
        let mut payload = json!({"model":MODEL, "messages":[{"role":"user",
            "content":"Reply with exactly PONG and nothing else."}], "max_tokens":1024, "stream":stream});
        if stream {
            payload["stream_options"] = json!({"include_usage":true});
        }
        let response = send(
            client,
            "POST",
            "/v1/chat/completions",
            Bytes::from(payload.to_string()),
        )
        .await?;
        if !stream {
            let result = validate_completion(&collect(response).await?)?;
            output_summary("nonstream", &result, started.elapsed().as_millis(), None);
            continue;
        }
        let (result, first_delta) = read_stream(response, started).await?;
        output_summary(
            "stream",
            &result,
            started.elapsed().as_millis(),
            first_delta,
        );
    }
    Ok(())
}

async fn read_stream(
    response: maple_sdk::client::InferenceResponse,
    started: Instant,
) -> Check<(Usage, Option<u128>)> {
    if response.status() != StatusCode::OK {
        return Err("stream_http_failure");
    }
    if response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .is_none_or(|s| s.split(';').next().unwrap_or("").trim() != "text/event-stream")
    {
        return Err("invalid_stream_content_type");
    }
    let mut total = 0;
    let bounded = response.into_body().map(move |chunk| {
        let chunk = chunk.map_err(|_| std::io::Error::other("encrypted_stream_failed"))?;
        total += chunk.len();
        if total > LIMIT {
            return Err(std::io::Error::other("stream_too_large"));
        }
        Ok(chunk)
    });
    let mut events = bounded.eventsource();
    let mut checks = StreamChecks::default();
    let mut first_delta = None;
    // Drain through EOF even after [DONE] to authenticate Transport V2 finality.
    while let Some(event) = timeout(Duration::from_secs(120), events.next())
        .await
        .map_err(|_| "stream_idle_timeout")?
    {
        let event = event.map_err(|_| "invalid_encrypted_sse")?;
        if checks.accept(&event.data)? && first_delta.is_none() {
            first_delta = Some(started.elapsed().as_millis());
        }
    }
    Ok((checks.finish()?, first_delta))
}

async fn run(mode: &str) -> Check<()> {
    if mode == "reject-pin" {
        // A failing network or broken deployment must not pass a negative test.
        let control = OpenSecretClient::new_with_pcr0_trust_policy(
            BACKEND,
            Pcr0TrustPolicy::from_static_allowlist([PCR0]).map_err(|_| "invalid_static_policy")?,
        )
        .map_err(|_| "client_configuration_failed")?;
        timeout(
            Duration::from_secs(60),
            control.perform_attestation_handshake(),
        )
        .await
        .map_err(|_| "control_attestation_timeout")?
        .map_err(|_| "control_attestation_failed")?;
    }
    let pin = if mode == "reject-pin" { BAD_PCR0 } else { PCR0 };
    let policy =
        Pcr0TrustPolicy::from_static_allowlist([pin]).map_err(|_| "invalid_static_policy")?;
    let client = OpenSecretClient::new_with_pcr0_trust_policy(BACKEND, policy)
        .map_err(|_| "client_configuration_failed")?;
    let start = Instant::now();
    let result = timeout(
        Duration::from_secs(60),
        client.perform_attestation_handshake(),
    )
    .await
    .map_err(|_| "attestation_timeout")?;
    if mode == "reject-pin" {
        return match result {
            Err(maple_sdk::Error::AttestationVerificationFailed(reason))
                if reason == "Transport V2 attestation or PCR policy was rejected" =>
            {
                println!("{}", json!({"check":"changed_pin_rejected", "ok":true}));
                Ok(())
            }
            _ => Err("changed_pin_rejection_not_proven"),
        };
    }
    result.map_err(|_| "attestation_verification_failed")?;
    println!(
        "{}",
        json!({"check":"front_enclave_attestation", "ok":true,
        "pcr0":PCR0, "elapsed_ms":start.elapsed().as_millis(),
        "source_reproduction_verified":false, "end_to_end_qualified":false})
    );
    if mode == "attest" {
        return Ok(());
    }
    if mode == "reject-key" {
        client
            .set_api_key("tr-maple-deliberately-invalid-qualification-key".into())
            .map_err(|_| "invalid_test_credential")?;
        let response = send(&client, "GET", "/v1/models", Bytes::new()).await?;
        if response.status() != StatusCode::UNAUTHORIZED
            && response.status() != StatusCode::FORBIDDEN
        {
            return Err("invalid_key_not_rejected");
        }
        println!(
            "{}",
            json!({"check":"invalid_key_rejected", "ok":true,
            "status":response.status().as_u16()})
        );
        return Ok(());
    }
    let key = env::var("MAPLE_API_KEY")
        .ok()
        .filter(|key| !key.trim().is_empty())
        .ok_or("maple_api_key_missing")?;
    client.set_api_key(key).map_err(|_| "invalid_api_key")?;
    timeout(Duration::from_secs(600), probe(&client))
        .await
        .map_err(|_| "probe_timeout")?
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<_> = env::args().skip(1).collect();
    if args.len() != 1
        || !matches!(
            args[0].as_str(),
            "attest" | "reject-pin" | "reject-key" | "probe"
        )
    {
        eprintln!("usage: trustedrouter-maple-pilot attest|reject-pin|reject-key|probe");
        return ExitCode::FAILURE;
    }
    match run(&args[0]).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            // Only our fixed vocabulary is emitted, never SDK/provider bodies.
            eprintln!("{}", json!({"ok":false,"reason":reason}));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_usage() -> Value {
        json!({"prompt_tokens":10,"completion_tokens":2,"total_tokens":12,
            "prompt_tokens_details":{"cached_tokens":4}})
    }

    #[test]
    fn integer_usage_and_cache_are_required() {
        assert_eq!(
            usage(&sample_usage()).unwrap(),
            Usage {
                input: 10,
                output: 2,
                cached: 4
            }
        );
        for field in ["prompt_tokens", "completion_tokens", "total_tokens"] {
            for invalid in [json!(-1), json!(1.5), json!("10"), json!(true), Value::Null] {
                let mut value = sample_usage();
                value[field] = invalid;
                assert!(usage(&value).is_err());
            }
        }
        let mut value = sample_usage();
        value["prompt_tokens_details"]["cached_tokens"] = json!(11);
        assert!(usage(&value).is_err());
        value["prompt_tokens_details"] = json!("malformed");
        assert!(usage(&value).is_err());
        value = sample_usage();
        value["total_tokens"] = json!(13);
        assert!(usage(&value).is_err());
    }

    #[test]
    fn stock_model_never_satisfies_discovery() {
        assert!(validate_catalog(&json!({"data":[{"id":"deepseek-v4-1-flash"}]})).is_err());
        assert_eq!(
            validate_catalog(&json!({"data":[{"id":MODEL}]})).unwrap(),
            1
        );
        assert!(validate_catalog(&json!({"data":[{"id":MODEL},{"id":MODEL}]})).is_err());
    }

    #[test]
    fn nonstream_requires_exact_identity_answer_finish_and_usage() {
        let value = json!({"model":MODEL,"choices":[{"message":{"content":"PONG"},
            "finish_reason":"stop"}],"usage":sample_usage()});
        assert!(validate_completion(&value).is_ok());
        for changed in [
            json!({"model":"deepseek-v4-1-flash"}),
            json!({"choices":[{"message":{"reasoning":"PONG"},"finish_reason":"stop"}]}),
            json!({"choices":[{"message":{"content":"PONG"},"finish_reason":"length"}]}),
            json!({"error": {"message":"unsafe upstream content"}}),
        ] {
            let mut value = value.clone();
            value
                .as_object_mut()
                .unwrap()
                .extend(changed.as_object().unwrap().clone());
            assert!(validate_completion(&value).is_err());
        }
    }

    fn finished_stream() -> StreamChecks {
        let mut stream = StreamChecks::default();
        stream
            .accept(
                &json!({"model":MODEL,"choices":[{"delta":{"content":"PONG"},
            "finish_reason":"stop"}]})
                .to_string(),
            )
            .unwrap();
        stream
            .accept(&json!({"model":MODEL,"choices":[],"usage":sample_usage()}).to_string())
            .unwrap();
        stream
    }

    #[test]
    fn stream_requires_usage_finish_and_done_and_rejects_error_events() {
        assert!(finished_stream().finish().is_err());
        let mut stream = finished_stream();
        stream.accept("[DONE]").unwrap();
        assert!(stream.finish().is_ok());
        let mut stream = finished_stream();
        stream.accept("[DONE]").unwrap();
        assert!(stream.accept("[DONE]").is_err());
        assert!(finished_stream()
            .accept(r#"{"error":{"message":"failure"}}"#)
            .is_err());
        assert!(StreamChecks::default()
            .accept(r#"{"model":"stock","choices":[]}"#)
            .is_err());
        assert!(StreamChecks::default().finish().is_err());
    }

    #[test]
    fn policy_pins_are_distinct_and_nonzero() {
        assert_ne!(PCR0, BAD_PCR0);
        assert!(Pcr0TrustPolicy::from_static_allowlist([PCR0]).is_ok());
        assert!(Pcr0TrustPolicy::from_static_allowlist(["0".repeat(96)]).is_err());
    }

    fn sse_response(chunks: Vec<maple_sdk::Result<Bytes>>) -> maple_sdk::client::InferenceResponse {
        let body: maple_sdk::client::OpenSecretResponseBody =
            Box::pin(futures::stream::iter(chunks));
        http::Response::builder()
            .header("content-type", "text/event-stream; charset=utf-8")
            .body(body)
            .unwrap()
    }

    fn sse_bytes() -> Vec<u8> {
        format!(
            "data: {}\r\n\r\ndata: {}\r\n\r\ndata: [DONE]\r\n\r\n",
            json!({"model":MODEL,"choices":[{"delta":{"content":"PONG"},"finish_reason":"stop"}]}),
            json!({"model":MODEL,"choices":[],"usage":sample_usage()})
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn fragmented_or_coalesced_sse_is_validated_through_eof() {
        for size in [1, 3, 17, 4096] {
            let chunks = sse_bytes()
                .chunks(size)
                .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
                .collect();
            let (actual, first) = read_stream(sse_response(chunks), Instant::now())
                .await
                .unwrap();
            assert_eq!(actual, usage(&sample_usage()).unwrap());
            assert!(first.is_some());
        }
    }

    #[tokio::test]
    async fn sdk_finality_failure_after_done_is_not_success() {
        let chunks = vec![
            Ok(Bytes::from(sse_bytes())),
            Err(maple_sdk::Error::InvalidResponse(
                "synthetic missing finality".into(),
            )),
        ];
        assert_eq!(
            read_stream(sse_response(chunks), Instant::now())
                .await
                .unwrap_err(),
            "invalid_encrypted_sse"
        );
        let chunks = vec![
            Ok(Bytes::from(sse_bytes())),
            Ok(Bytes::from_static(b"data: [DONE]\n\n")),
        ];
        assert_eq!(
            read_stream(sse_response(chunks), Instant::now())
                .await
                .unwrap_err(),
            "data_after_done"
        );
    }

    #[tokio::test]
    async fn response_limits_fail_closed() {
        let response = sse_response(vec![Ok(Bytes::from(vec![b'x'; LIMIT + 1]))]);
        assert_eq!(
            read_stream(response, Instant::now()).await.unwrap_err(),
            "invalid_encrypted_sse"
        );
        let response = sse_response(vec![Ok(Bytes::from(vec![b'x'; LIMIT + 1]))]);
        assert_eq!(collect(response).await.unwrap_err(), "response_too_large");
    }
}
