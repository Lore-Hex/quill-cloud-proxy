# Azure enclave region scaffolding

Declarative ownership of the parts of an Azure enclave region that do not
change per deploy: the resource group, the managed identity, the attestation
provider, and the identity's role assignments.

Adding a region is a map entry in `variables.tf`, not a remembered sequence of
`az` commands.

## What this does not own, and why

The container group is not here. Its CCE policy hash is a function of the
entire container definition -- image digest, every env var name and value, the
sidecar, resources -- so it changes on essentially every deploy, and the Key
Vault release policy has to be **widened** to `{old,new}` before the group is
created and **narrowed** to `{new}` only after a live attestation has been
checked against what the key actually expects.

Plan/apply cannot express "widen, create, verify against ground truth, narrow".
A single apply that swapped the pin in one step is exactly the failure
`tools/deploy-azure-aci.sh` warns about in its header: a confidential group
must be deleted before it can be recreated, so a create that fails for an
ordinary reason (ACR pull, capacity, quota) leaves no group *and* no way back.

The SKR key `tr-bootstrap-wrap` is likewise not managed here. It gates every
provider secret on Azure; a resource that can replace it is a resource that can
destroy the platform.

    terraform            ->  resource group, identity, attestation provider,
                             role assignments
    deploy-azure-aci.sh  ->  build, template, policy, bind, deploy, verify,
                             narrow

## State

Local, matching `tools/dns`. This is a deliberate limitation: a remote backend
has to live in some cloud, and putting Azure's bring-up state in AWS or GCP
would make one cloud a prerequisite for provisioning another -- the hub
dependency the multi-cloud split exists to avoid. Until there is an
Azure-local state container, treat `terraform plan` here as a drift detector
run by one operator.

## Usage

Adopt what already exists (idempotent, safe to re-run):

```bash
bash tools/azure-enclave/import.sh
```

It imports every resource that exists in Azure and reports the ones that do
not. On a fresh checkout that is everything except role assignments that have
never been granted.

Then review and apply:

```bash
cd tools/azure-enclave
terraform plan
terraform apply
```

`apply` is where privilege changes happen. Creating role assignments is
deliberately *not* something the deploy script does -- a deploy pipeline that
can grant itself roles is a deploy pipeline that is quietly an admin -- so it
is a human running `terraform apply` against a reviewed plan.

## Handing off to the deploy

```bash
terraform output -json deploy_env \
  | jq -r '.australiaeast | to_entries[] | "\(.key)=\(.value)"'
```

Export those and run the measured deploy from the repo root:

```bash
RESOURCE_GROUP=tr-tee-sydney LOCATION=australiaeast \
MAA_ENDPOINT=trquillsyd.eau.attest.azure.net \
API_HOST=api-azure-syd.trustedrouter.com \
bash tools/deploy-azure-aci.sh all --apply
```

## Checking the release policy against reality

Every region here must have a matching `anyOf` entry in the SKR key, and every
entry there should correspond to a region here:

```bash
terraform output -json attestation_authorities | jq -r '.[]' | sort > /tmp/tf-regions
az keyvault key show --vault-name trquillkv -n tr-bootstrap-wrap -o json \
  | jq -r '.releasePolicy.encodedPolicy | fromjson | .anyOf[].authority' | sort -u > /tmp/kv-regions
diff /tmp/tf-regions /tmp/kv-regions
```

A region in terraform but not in the key cannot boot: it attests fine and then
gets a 403 from Key Vault that points at nothing. A region in the key but not
in terraform is a retired region whose pin was never cleaned up -- an authority
that is still trusted to release every provider secret.

Note `releasePolicy.encodedPolicy` only materialises under `-o json`; asking
for it with `--query ... -o tsv` returns empty, which looks exactly like a key
with no release policy at all.

## Crypto Officer

`grant_crypto_officer` records reality, not intent. UAE North's identity holds
**Key Vault Crypto Officer**, which lets a workload rewrite the release policy
that constrains it -- a self-authorizing TEE. If the enclave is compromised it
can authorize any future workload, including a non-confidential one.

New regions leave it `false`. Rebinding is an operator action: `bind` and
`narrow` run under the operator's own credential, so the identity never needs
it. Australia East was brought up without it.
