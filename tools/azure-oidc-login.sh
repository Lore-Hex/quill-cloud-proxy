#!/usr/bin/env bash
# Log the Azure CLI in with this job's GitHub OIDC token (audience
# api://AzureADTokenExchange), then pre-fetch ARM, Key Vault and container
# registry access tokens.
#
# GitHub's ID token lives only minutes and az exchanges it lazily, per
# resource: quill-router lost a deploy to exactly that (a first Key Vault call
# after a long wait failed and looked like "secret not found"). Call this
# before every step that talks to Azure; the access tokens it pre-fetches last
# about an hour, longer than any single step here.
#
# ARM is listed by the audience az's own commands ask for
# (https://management.core.windows.net/), so its expiry line describes the
# token they will use. The registry is its own resource. `az acr repository show` and `az acr login`
# ask for a token for https://containerregistry.azure.net, not for ARM, and
# they first run after the registry build, a quarter of an hour after login.
# Without that token in the cache az reports AADSTS700024 (the assertion is
# past its valid time), falls back to the registry's admin credentials, and
# stops on registries/listCredentials/action, which the rollout identity does
# not and should not hold.
#
# Every call starts from an empty token cache. `az login` and the token
# requests at the end of this file both read the cache first, so a second call in
# the same job would otherwise hand the next step the first call's tokens,
# already minutes old: the deploy step, the longest one, would inherit the
# drain step's expiry and could run out late in its verify phase.
#
# Needs AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID and the job's
# id-token: write permission. Never run with xtrace.
set -euo pipefail
set +x
fail() { echo "::error::azure-oidc-login: $*"; exit 1; }
guid='^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
for name in AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_SUBSCRIPTION_ID; do
  [[ "${!name:-}" =~ $guid ]] || fail "$name is not set to a GUID"
done
[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] \
  || fail "no GitHub OIDC token is available; the job needs permissions id-token: write"
# The request token reaches curl on stdin (-H @-), never argv.
id_token="$(printf 'Authorization: bearer %s\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  | curl -fsS --retry 3 --retry-all-errors -H @- \
      "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api%3A%2F%2FAzureADTokenExchange" \
  | python3 -c 'import json, sys; sys.stdout.write(json.load(sys.stdin)["value"])')" \
  || fail "could not fetch a GitHub OIDC token"
[ -n "$id_token" ] || fail "the GitHub OIDC token endpoint returned no token"
echo "::add-mask::${id_token}"
az cloud set --name AzureCloud --output none
az account clear --only-show-errors || fail "could not clear the previous login's cached tokens"
az login --service-principal --username "$AZURE_CLIENT_ID" --tenant "$AZURE_TENANT_ID" \
  --federated-token "$id_token" --output none --only-show-errors \
  || fail "az login with the federated token failed"
unset id_token
az account set --subscription "$AZURE_SUBSCRIPTION_ID" || fail "cannot select the subscription"
for resource in https://management.core.windows.net/ https://vault.azure.net https://containerregistry.azure.net; do
  expires="$(az account get-access-token --resource "$resource" --query expiresOn --output tsv --only-show-errors)" \
    || fail "could not obtain an access token for $resource"
  echo "access token for $resource cached until $expires"
done
echo "Azure CLI logged in as the gateway rollout identity"
