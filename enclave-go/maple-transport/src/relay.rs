//! Bounded SSE relay. Only authenticated encrypted EOF releases [DONE].
use serde_json::Value;
use std::io::Write;

const MAX_LINE: usize = 1024 * 1024;
const MAX_RESPONSE: usize = 64 * 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Default)]
pub struct Relay {
    line: Vec<u8>,
    data: Vec<u8>,
    bytes: usize,
    done: bool,
    model: bool,
    finish: bool,
    usage: Option<(u64, u64, u64)>,
}

impl Relay {
    pub fn push(&mut self, bytes: &[u8], out: &mut impl Write) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or("response_too_large")?;
        if self.bytes > MAX_RESPONSE {
            return Err("response_too_large");
        }
        for &byte in bytes {
            if byte == b'\n' {
                if self.line.last() == Some(&b'\r') {
                    self.line.pop();
                }
                self.accept_line(out)?;
                self.line.clear();
            } else {
                if self.line.len() >= MAX_LINE {
                    return Err("line_too_large");
                }
                self.line.push(byte);
            }
        }
        Ok(())
    }

    fn accept_line(&mut self, out: &mut impl Write) -> Result<()> {
        if self.line.is_empty() {
            if !self.data.is_empty() {
                self.accept_event(out)?;
                self.data.clear();
            }
        } else if let Some(data) = self.line.strip_prefix(b"data:") {
            let data = data.strip_prefix(b" ").unwrap_or(data);
            if self.data.len() + data.len() + 1 > MAX_LINE {
                return Err("event_too_large");
            }
            if !self.data.is_empty() {
                self.data.push(b'\n');
            }
            self.data.extend_from_slice(data);
        } else if self.line.starts_with(b"event:") {
            let event = std::str::from_utf8(&self.line[6..])
                .map_err(|_| "invalid_event")?
                .trim();
            if event != "message" && !event.is_empty() {
                return Err("unexpected_event");
            }
        }
        Ok(())
    }

    fn accept_event(&mut self, out: &mut impl Write) -> Result<()> {
        if self.done {
            return Err("data_after_done");
        }
        if self.data == b"[DONE]" {
            self.done = true;
            return Ok(());
        }
        let value: Value = serde_json::from_slice(&self.data).map_err(|_| "invalid_stream_json")?;
        if value.get("error").is_some() {
            return Err("upstream_stream_error");
        }
        if let Some(model) = value.get("model") {
            if model.as_str() != Some(crate::MODEL) {
                return Err("model_identity_mismatch");
            }
            self.model = true;
        }
        let choices = value["choices"].as_array().ok_or("invalid_choices")?;
        if choices.len() > 1 {
            return Err("multiple_choices_unsupported");
        }
        for choice in choices {
            if choice.get("error").is_some() || choice["delta"].get("error").is_some() {
                return Err("upstream_stream_error");
            }
            if let Some(reason) = choice.get("finish_reason").filter(|value| !value.is_null()) {
                if !matches!(
                    reason.as_str(),
                    Some("stop" | "length" | "tool_calls" | "content_filter")
                ) {
                    return Err("invalid_finish_reason");
                }
                self.finish = true;
            }
        }
        if let Some(usage) = value.get("usage").filter(|value| !value.is_null()) {
            let next = usage_counts(usage)?;
            if self
                .usage
                .is_some_and(|prior| next.0 < prior.0 || next.1 < prior.1 || next.2 < prior.2)
            {
                return Err("nonmonotonic_usage");
            }
            self.usage = Some(next);
        }
        // Re-encode parsed JSON: multiline SSE and arbitrary whitespace cannot
        // confuse the gateway's one-line translator or inject an extra event.
        let encoded = serde_json::to_vec(&value).map_err(|_| "encode_failed")?;
        out.write_all(b"data: ")
            .and_then(|_| out.write_all(&encoded))
            .and_then(|_| out.write_all(b"\n\n"))
            .and_then(|_| out.flush())
            .map_err(|_| "consumer_closed")
    }

    // Call only after the SDK stream returns clean EOF, not after logical DONE.
    pub fn finish(self, out: &mut impl Write) -> Result<()> {
        if !self.line.is_empty() || !self.data.is_empty() {
            return Err("truncated_sse");
        }
        if !self.done || !self.model || !self.finish || self.usage.is_none_or(|usage| usage.0 == 0)
        {
            return Err("incomplete_stream");
        }
        out.write_all(b"data: [DONE]\n\n")
            .and_then(|_| out.flush())
            .map_err(|_| "consumer_closed")
    }
}

fn usage_counts(value: &Value) -> Result<(u64, u64, u64)> {
    let input = value["prompt_tokens"]
        .as_u64()
        .ok_or("invalid_input_usage")?;
    let output = value["completion_tokens"]
        .as_u64()
        .ok_or("invalid_output_usage")?;
    if input > i64::MAX as u64 || output > i64::MAX as u64 {
        return Err("usage_out_of_range");
    }
    if input.checked_add(output) != value["total_tokens"].as_u64() {
        return Err("invalid_total_usage");
    }
    let cached = match value.get("prompt_tokens_details") {
        None | Some(Value::Null) => 0,
        Some(Value::Object(details)) => match details.get("cached_tokens") {
            None => 0,
            Some(value) => value.as_u64().ok_or("invalid_cached_usage")?,
        },
        _ => return Err("invalid_usage_details"),
    };
    if cached > input {
        return Err("invalid_cached_usage");
    }
    Ok((input, output, cached))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event() -> Vec<u8> {
        format!("data: {}\n\n", json!({"model":crate::MODEL,"choices":[{"delta":{"content":"PONG"},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"completion_tokens":2,"total_tokens":22,"prompt_tokens_details":{"cached_tokens":10}}})).into_bytes()
    }

    #[test]
    fn incremental_with_authenticated_finality() {
        let mut relay = Relay::default();
        let mut out = Vec::new();
        for byte in event() {
            relay.push(&[byte], &mut out).unwrap();
        }
        assert!(String::from_utf8_lossy(&out).contains("PONG"));
        relay.push(b"data: [DONE]\n\n", &mut out).unwrap();
        assert!(!String::from_utf8_lossy(&out).contains("[DONE]"));
        relay.finish(&mut out).unwrap();
        assert!(out.ends_with(b"data: [DONE]\n\n"));
    }

    #[test]
    fn incomplete_or_extra_data_never_succeeds() {
        for suffix in [
            b"".as_slice(),
            b"data: [DONE]",
            b"data: [DONE]\n",
            b"data: [DONE]\n\ndata: {}\n\n",
        ] {
            let mut relay = Relay::default();
            let mut out = Vec::new();
            relay.push(&event(), &mut out).unwrap();
            let result = relay
                .push(suffix, &mut out)
                .and_then(|_| relay.finish(&mut out));
            assert!(result.is_err());
            assert!(!String::from_utf8_lossy(&out).contains("[DONE]"));
        }
    }

    #[test]
    fn rejects_identity_and_usage_corruption() {
        let good: Value = serde_json::from_slice(&event()[6..event().len() - 2]).unwrap();
        for (pointer, bad) in [
            ("/model", json!("deepseek-v4-1-flash")),
            ("/usage/prompt_tokens", json!(-1)),
            ("/usage/completion_tokens", json!(2.5)),
            ("/usage/total_tokens", json!(23)),
            ("/usage/prompt_tokens_details/cached_tokens", json!(21)),
        ] {
            let mut value = good.clone();
            *value.pointer_mut(pointer).unwrap() = bad;
            let mut relay = Relay::default();
            let mut out = Vec::new();
            assert!(relay
                .push(format!("data: {value}\n\n").as_bytes(), &mut out)
                .is_err());
            assert!(out.is_empty());
        }
    }

    #[test]
    fn cumulative_usage_is_not_summed_and_cannot_decrease() {
        let mut relay = Relay::default();
        let mut out = Vec::new();
        relay.push(&event(), &mut out).unwrap();
        relay.push(&event(), &mut out).unwrap();
        assert_eq!(relay.usage, Some((20, 2, 10)));
        assert!(relay.push(b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n", &mut out).is_err());
    }

    #[test]
    fn rejects_oversized_frames_and_redacts_errors() {
        let mut relay = Relay::default();
        assert_eq!(
            relay.push(&vec![b'a'; MAX_LINE + 1], &mut Vec::new()),
            Err("line_too_large")
        );
        let mut relay = Relay::default();
        let mut out = Vec::new();
        assert_eq!(
            relay.push(b"data: {\"error\":{\"message\":\"SECRET\"}}\n\n", &mut out),
            Err("upstream_stream_error")
        );
        assert!(out.is_empty());
    }

    #[test]
    fn multiline_events_and_crlf_are_normalized() {
        let mut relay = Relay::default();
        let mut out = Vec::new();
        relay.push(b"data: {\"choices\":[],\r\ndata: \"model\":\"deepseek-v4-1-flash-1017-uncensored\"}\r\n\r\n", &mut out).unwrap();
        assert_eq!(out.iter().filter(|&&c| c == b'\n').count(), 2);
        assert!(serde_json::from_slice::<Value>(&out[6..out.len() - 2]).is_ok());
    }
}
