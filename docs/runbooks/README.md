# Runbooks

Operational playbooks for TrustedRouter + Quill Cloud Proxy. Each
runbook is short, action-oriented, and assumes you already know the
architecture (see top-level README for that).

If you're paged or notice red on https://status.trustedrouter.com/,
start with [incident-response.md](./incident-response.md).

## Catalog

| Runbook | When to use |
|---|---|
| [incident-response.md](./incident-response.md) | Status page goes red. First response. |
| [enclave-deploy-debugging.md](./enclave-deploy-debugging.md) | A GHA enclave deploy failed or rolled back. |
| [provider-onboarding.md](./provider-onboarding.md) | Adding a new upstream LLM provider (Together, Fireworks, …). |

## Tooling

`tools/dx/` holds quick-look scripts the runbooks lean on:

- **`enclave-logs.sh`** — fetch attested workload logs by time window.
  The Confidential Space launcher writes to a non-obvious log name;
  this wrapper applies the right filter.
  ```
  tools/dx/enclave-logs.sh --since 30m
  tools/dx/enclave-logs.sh --since 2026-05-06T03:00:00Z --until 2026-05-06T04:00:00Z --top
  tools/dx/enclave-logs.sh --since 1h --grep "error|panic|denied"
  ```

## When updating

A runbook earns its place by being followable under stress. If you
ever read one during an incident and find yourself filling in gaps,
update it the same week — when the steps are still fresh. Stale
runbooks are worse than no runbooks because they encode false
confidence.
