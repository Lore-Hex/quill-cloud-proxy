# Per-user usage and OpenAI safety identifiers

On `POST /v1/chat/completions` and `POST /v1/responses`, set the optional top-level `safety_identifier` to a stable, opaque ID from your application. Generate or look it up on your server after signing the user in. Don't send an email address, real name, credential, or device fingerprint. The identifier is an attribution hint, not proof of identity.

```json
{
  "model": "openai/gpt-4o-mini",
  "messages": [{"role": "user", "content": "Hello"}],
  "safety_identifier": "acct_7f29"
}
```

Use the same field with `input` instead of `messages` on Responses. Streaming does not change its meaning.

- Supply a nonblank string of at most 64 UTF-8 bytes, without control characters. Omitting it or sending `null` keeps the existing direct OpenAI key-owner/workspace attribution and does not add a caller usage tag.
- For opted-in requests, TrustedRouter adds a workspace-scoped hash to the activity tag `safety_identifier`. A direct OpenAI route receives a **different** workspace-scoped hash in its `safety_identifier` field. Other providers do not get this field. Neither hash contains the original ID, and rotating keys in the same workspace preserves both hashes.
- Don't also set `tags.safety_identifier` in the same request. The generated tag counts toward normal tag limits. Setting a tag alone does not select the identifier sent to OpenAI. Existing `user` and other tags keep their usual meaning.

To see attributed request counts, tokens and spend, use your workspace management credentials with `GET /v1/activity?group_by=tag:safety_identifier`. Groups are labeled with the activity hash, not the original ID or the value sent to OpenAI. This is a bounded date-window report: check `meta.truncated` and `meta.groups_truncated`. The top 100 groups are reported individually; the rest are combined under `__other__`. To look up one user, filter by `tag_key=safety_identifier&tag_value=<activity hash>`. Pricing and the billing account do not change.

To match your app's ID to an activity group, let `H` be SHA-256 encoded as lowercase hexadecimal. Compute `inner = H("trustedrouter/caller-safety/input/v1" + NUL + id)`, then `group = H("trustedrouter/caller-safety/activity/v1" + NUL + workspace_id + NUL + inner)`. Use UTF-8, a single zero byte for each NUL, and the exact identifier as sent. Keep the association in your own application.
