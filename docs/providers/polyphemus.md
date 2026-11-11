# Polyphemus model selection

`trustedrouter/polyphemus-1.0` picks a model for each request inside the
attested gateway. No prompt text leaves the gateway to choose a model.

## How it chooses

1. The gateway takes the latest user message's text, at most 16 KiB.
2. `/polyphemus-classifier` classifies it. This is a static Rust binary in
   the measured image, run as a child process under its own user ID, with no
   network code. It runs NVIDIA's open prompt task-and-complexity classifier
   (DeBERTa-v3-base, 184M parameters) on the CPU and returns the task type
   and a domain-knowledge score from 0 to 1.
3. The rule in `cmd/enclave/polyphemus.go`:
   - Strong model if the request carries tools, the task is Code Generation,
     or domain knowledge is at least 0.8.
   - Cheap model otherwise.

| | Strong | Cheap |
|---|---|---|
| Default | `anthropic/claude-opus-5.5` | `deepseek/deepseek-v4.1-flash-1017` |
| Confidential | `moonshotai/kimi-k3.1-pro` | `deepseek/deepseek-v4.1-flash-1017` |

A request is confidential when `provider.min_privacy` is `confidential`,
`trusted`, `e2e`, `e2ee`, `max` or `maximum`, or when it arrives on the
confidential-only hostname. The caller's privacy settings still apply to the
generation, so the control plane only admits endpoints that meet them.

A conversation that already used tools stays on the model that started it
(the model rides in the tool call ids). If the classifier is unavailable,
the request goes to `trustedrouter/auto` and the selector hold is refunded.

`polyphemus.x_perf` and `polyphemus.model_zoo` are still accepted, so old
clients keep working, but they no longer change the choice.

## Billing

The selector costs $0.05 per million tokens of the classified text, estimated
as UTF-8 bytes / 4, rounded down, minimum one token and $0.000001. The chosen
model is billed at its normal rates.

## The model

- Weights: [nvidia/prompt-task-and-complexity-classifier](https://huggingface.co/nvidia/prompt-task-and-complexity-classifier)
  at revision `fea1121511eafabaf7dd6fc66863dcb04f74defb`, NVIDIA Open Model
  License. `model.safetensors` SHA-256
  `d9abb6b67d266a712a7f5baea5117bcb8f4be4bec325cf4c7856d35df0fcb953`,
  `tokenizer.json` SHA-256
  `5124ef2ead1a10a717703bc436de7f353da76d6340e4587719b42b1693707964`.
- The Docker build fetches both files by digest
  (`Dockerfile.enclave.gcp.multi`, stage `polyphemus-classifier`). Then
  `polyphemus-classifier --self-test` must reproduce the model card's
  published example (Code Generation, probability 0.767, domain knowledge
  0.9803) or the build fails.
- Checked against NVIDIA's PyTorch reference on 32 prompts, including a
  full 512-token prompt: identical token ids, logits within 1e-5.
- About 80 ms per typical prompt on an M-series Mac, about 520 ms at the
  512-token limit. Longer text is truncated, keeping the start.

Run it locally:

```bash
cd enclave-go/polyphemus-classifier
cargo test --locked
cargo run --locked --release -- --self-test /path/to/weights
```

## Not yet

- Only the GCP image ships the classifier. On AWS and Azure the helper is
  absent, so Polyphemus falls back to `trustedrouter/auto` there.
- The former selector's key, secret and egress plumbing is still configured
  but unused, and will be removed separately.
