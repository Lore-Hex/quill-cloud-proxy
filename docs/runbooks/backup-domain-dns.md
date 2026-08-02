# Backup domain DNS

`allyrouter.com` and `uptimerouter.com` are independent operational aliases for
TrustedRouter. Their control-plane records live in Route53, and their API names
are direct A records to the attested enclave fleet. Neither backup domain uses a
CNAME to `trustedrouter.com` or `quillrouter.com`.

## Health authority

`tools/reconcile-enclave-dns.py` attests every gateway and publishes the healthy
set to `api.trustedrouter.com`. `tools/sync-route53-api-aliases.py` copies that
already-gated set into these Route53 records:

| Record | Hosted zone |
| --- | --- |
| `api.allyrouter.com` | `Z09662142UE0IQL51B13V` |
| `api.uptimerouter.com` | `Z00893363GIOMU7Z8647K` |

The copy runs after every deploy-time drain/re-add and every five-minute health
reconcile. It requires at least two public IPv4 addresses. On any discovery or
validation failure it leaves Route53 unchanged, preserving the last-good set.

Each GCP enclave has both API aliases in `QUILL_API_HOST`, so ACME certificates
are issued and private keys remain inside Confidential Space.

## OAuth isolation

Each backup domain has separate Google and GitHub OAuth clients with same-origin
callbacks. Login state and sessions use host-only cookies. A callback for one
domain cannot complete on another domain, and no backup-domain login redirects
through a canonical TrustedRouter or QuillRouter hostname.
