//! NVIDIA's prompt task-and-complexity classifier, run on the CPU with no
//! network access. Only the two outputs Polyphemus routes on are returned:
//! the most likely task type and the domain-knowledge score.
//!
//! Model: https://huggingface.co/nvidia/prompt-task-and-complexity-classifier
//! (revision fea1121511eafabaf7dd6fc66863dcb04f74defb, NVIDIA Open Model
//! License). The post-processing mirrors the model card's `CustomModel`.

use anyhow::{anyhow, Result};
use candle_core::{DType, Device, Tensor};
use candle_nn::{Linear, Module, VarBuilder};
use candle_transformers::models::debertav2::{Config, DebertaV2Model};
use serde::Serialize;
use std::path::Path;

/// microsoft/deberta-v3-base's config.json, the backbone the card loads.
const BACKBONE_CONFIG: &str = r#"{
  "model_type": "deberta-v2", "attention_probs_dropout_prob": 0.1,
  "hidden_act": "gelu", "hidden_dropout_prob": 0.1, "hidden_size": 768,
  "initializer_range": 0.02, "intermediate_size": 3072,
  "max_position_embeddings": 512, "relative_attention": true,
  "position_buckets": 256, "norm_rel_ebd": "layer_norm", "share_att_key": true,
  "pos_att_type": "p2c|c2p", "layer_norm_eps": 1e-7,
  "max_relative_positions": -1, "position_biased_input": false,
  "num_attention_heads": 12, "num_hidden_layers": 12, "type_vocab_size": 0,
  "vocab_size": 128100
}"#;

/// The card's `max_length`: longer prompts are truncated, keeping the start.
pub const MAX_TOKENS: usize = 512;

/// task_type_map from the model's config.json, in logit order.
pub const TASK_TYPES: [&str; 12] = [
    "Brainstorming",
    "Chatbot",
    "Classification",
    "Closed QA",
    "Code Generation",
    "Extraction",
    "Open QA",
    "Other",
    "Rewrite",
    "Summarization",
    "Text Generation",
    "Unknown",
];

/// Head sizes in safetensors order: task_type, creativity_scope, reasoning,
/// contextual_knowledge, number_of_few_shots, domain_knowledge,
/// no_label_reason, constraint_ct. All are loaded so a wrong file fails here.
const HEAD_SIZES: [usize; 8] = [12, 3, 2, 2, 6, 4, 1, 2];
const TASK_HEAD: usize = 0;
const DOMAIN_HEAD: usize = 5;
/// weights_map["domain_knowledge"] and divisor_map["domain_knowledge"].
const DOMAIN_WEIGHTS: [f32; 4] = [3.0, 1.0, 2.0, 0.0];
const DOMAIN_DIVISOR: f32 = 3.0;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Classification {
    pub task: &'static str,
    pub task_probability: f32,
    /// 0 (none) to 1 (expert): how much specialist knowledge the prompt needs.
    pub domain_knowledge: f32,
    pub tokens: usize,
}

pub fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|v| (v - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    exps.iter().map(|v| v / sum).collect()
}

/// Top task type and its probability. Ties go to the earlier index, as in torch.topk.
pub fn task_from_logits(logits: &[f32]) -> Result<(&'static str, f32)> {
    if logits.len() != TASK_TYPES.len() {
        return Err(anyhow!("task head has {} outputs", logits.len()));
    }
    let probs = softmax(logits);
    let mut best = 0;
    for (i, p) in probs.iter().enumerate() {
        if *p > probs[best] {
            best = i;
        }
    }
    Ok((TASK_TYPES[best], probs[best]))
}

pub fn domain_from_logits(logits: &[f32]) -> Result<f32> {
    if logits.len() != DOMAIN_WEIGHTS.len() {
        return Err(anyhow!("domain head has {} outputs", logits.len()));
    }
    let probs = softmax(logits);
    Ok(probs
        .iter()
        .zip(DOMAIN_WEIGHTS)
        .map(|(p, w)| p * w)
        .sum::<f32>()
        / DOMAIN_DIVISOR)
}

pub struct Classifier {
    model: DebertaV2Model,
    heads: Vec<Linear>,
    tokenizer: tokenizers::Tokenizer,
    device: Device,
}

impl Classifier {
    /// Loads `model.safetensors` and `tokenizer.json` from `dir`.
    pub fn load(dir: &Path) -> Result<Self> {
        let device = Device::Cpu;
        let config: Config = serde_json::from_str(BACKBONE_CONFIG)?;
        // SAFETY: the weights are an immutable file in the measured image.
        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(
                &[dir.join("model.safetensors")],
                DType::F32,
                &device,
            )?
        };
        let model = DebertaV2Model::load(vb.pp("backbone"), &config)?;
        let heads = HEAD_SIZES
            .iter()
            .enumerate()
            .map(|(i, &n)| candle_nn::linear(config.hidden_size, n, vb.pp(format!("head_{i}.fc"))))
            .collect::<candle_core::Result<Vec<_>>>()?;
        let mut tokenizer = tokenizers::Tokenizer::from_file(dir.join("tokenizer.json"))
            .map_err(|e| anyhow!("tokenizer: {e}"))?;
        tokenizer
            .with_truncation(Some(tokenizers::TruncationParams {
                max_length: MAX_TOKENS,
                ..Default::default()
            }))
            .map_err(|e| anyhow!("tokenizer: {e}"))?;
        tokenizer.with_padding(None);
        Ok(Self {
            model,
            heads,
            tokenizer,
            device,
        })
    }

    pub fn classify(&self, text: &str) -> Result<Classification> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|e| anyhow!("tokenize: {e}"))?;
        let ids = encoding.get_ids();
        if ids.is_empty() || ids.len() > MAX_TOKENS {
            return Err(anyhow!("token count {}", ids.len()));
        }
        let input = Tensor::new(ids, &self.device)?.unsqueeze(0)?;
        let hidden = self.model.forward(&input, None, None)?;
        // One unpadded sequence: the card's masked mean pooling is a plain mean.
        let pooled = hidden.mean(1)?;
        let logits = |head: usize| -> Result<Vec<f32>> {
            Ok(self.heads[head]
                .forward(&pooled)?
                .squeeze(0)?
                .to_vec1::<f32>()?)
        };
        let (task, task_probability) = task_from_logits(&logits(TASK_HEAD)?)?;
        let domain_knowledge = domain_from_logits(&logits(DOMAIN_HEAD)?)?;
        Ok(Classification {
            task,
            task_probability,
            domain_knowledge,
            tokens: ids.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softmax_sums_to_one_and_is_stable() {
        let p = softmax(&[1000.0, 1000.0, 999.0]);
        assert!((p.iter().sum::<f32>() - 1.0).abs() < 1e-6);
        assert!((p[0] - p[1]).abs() < 1e-7 && p[2] < p[0]);
    }

    #[test]
    fn task_picks_highest_and_breaks_ties_low() {
        let mut logits = [0.0f32; 12];
        logits[4] = 5.0;
        assert_eq!(task_from_logits(&logits).unwrap().0, "Code Generation");
        let tie = [1.0f32; 12];
        let (task, p) = task_from_logits(&tie).unwrap();
        assert_eq!(task, "Brainstorming");
        assert!((p - 1.0 / 12.0).abs() < 1e-6);
        assert!(task_from_logits(&[0.0; 11]).is_err());
    }

    #[test]
    fn domain_matches_card_weights() {
        // Class order is High, Low, Medium, No (domain_knowledge_map).
        let high = domain_from_logits(&[50.0, 0.0, 0.0, 0.0]).unwrap();
        let none = domain_from_logits(&[0.0, 0.0, 0.0, 50.0]).unwrap();
        let medium = domain_from_logits(&[0.0, 0.0, 50.0, 0.0]).unwrap();
        let low = domain_from_logits(&[0.0, 50.0, 0.0, 0.0]).unwrap();
        assert!((high - 1.0).abs() < 1e-6 && none.abs() < 1e-6);
        assert!((medium - 2.0 / 3.0).abs() < 1e-6 && (low - 1.0 / 3.0).abs() < 1e-6);
        let uniform = domain_from_logits(&[0.0; 4]).unwrap();
        assert!((uniform - 0.5).abs() < 1e-6);
        assert!(domain_from_logits(&[0.0; 3]).is_err());
    }
}
