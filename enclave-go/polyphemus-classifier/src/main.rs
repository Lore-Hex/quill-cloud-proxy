//! Line protocol on stdin/stdout, one request at a time:
//!   startup  -> {"ready":true}
//!   {"text":"..."} -> {"task":"Code Generation","task_probability":0.77,"domain_knowledge":0.98,"tokens":14}
//!   anything else  -> {"error":"invalid_request"} or {"error":"classification_failed"}
//! Errors never echo input. The process exits when stdin closes.
//!
//! `--weights DIR` serves from another directory (local testing).
//! `--self-test DIR` classifies the model card's example and checks the
//! card's published outputs, so the image build fails on a wrong model.

use anyhow::{bail, Result};
use polyphemus_classifier::Classifier;
use serde::Deserialize;
use std::io::{BufRead, Read, Write};
use std::path::Path;

const WEIGHTS_DIR: &str = "/polyphemus-classifier-model";
/// The gateway sends at most 16 KiB of text; JSON escaping can at most
/// sextuple it. Anything longer is refused without being parsed.
const MAX_LINE_BYTES: usize = 6 * 16 * 1024 + 64;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    text: String,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.as_slice() {
        [_] => serve(Path::new(WEIGHTS_DIR)),
        [_, flag, dir] if flag == "--self-test" => self_test(Path::new(dir)),
        [_, flag, dir] if flag == "--weights" => serve(Path::new(dir)),
        _ => bail!("usage: polyphemus-classifier [--self-test DIR | --weights DIR]"),
    }
}

fn serve(dir: &Path) -> Result<()> {
    let classifier = Classifier::load(dir)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    writeln!(out, r#"{{"ready":true}}"#)?;
    out.flush()?;
    let mut input = std::io::stdin().lock();
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = input
            .by_ref()
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(());
        }
        let reply = if line.len() > MAX_LINE_BYTES || line.last() != Some(&b'\n') {
            // Drain the rest of an oversized line so the next request starts clean.
            if line.last() != Some(&b'\n') {
                let mut rest = Vec::new();
                input.read_until(b'\n', &mut rest)?;
            }
            r#"{"error":"invalid_request"}"#.to_string()
        } else {
            match serde_json::from_slice::<Request>(&line) {
                Ok(request) if !request.text.trim().is_empty() => {
                    match classifier.classify(&request.text) {
                        Ok(result) => serde_json::to_string(&result)?,
                        Err(_) => r#"{"error":"classification_failed"}"#.to_string(),
                    }
                }
                _ => r#"{"error":"invalid_request"}"#.to_string(),
            }
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
}

fn self_test(dir: &Path) -> Result<()> {
    let classifier = Classifier::load(dir)?;
    // The model card's example and its printed result: Code Generation at
    // 0.767, domain_knowledge 0.9803.
    let result = classifier.classify("Prompt: Write a Python script that uses a for loop.")?;
    if result.task != "Code Generation"
        || (result.task_probability - 0.767).abs() > 0.001
        || (result.domain_knowledge - 0.9803).abs() > 0.0005
    {
        bail!("self-test mismatch: {result:?}");
    }
    let trivia = classifier.classify("What is the capital of France?")?;
    if trivia.task != "Open QA" || trivia.domain_knowledge > 0.5 {
        bail!("self-test mismatch: {trivia:?}");
    }
    println!("self-test ok: {result:?} {trivia:?}");
    Ok(())
}
