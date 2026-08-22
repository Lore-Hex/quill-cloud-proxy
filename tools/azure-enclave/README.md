# Moved: quill-cloud-infra `envs/azure-tee/`

This Terraform root migrated to Lore-Hex/quill-cloud-infra on 2026-08-22
(commit 32119fa there), where every cloud's infrastructure Terraform lives.
Its state moved from this directory's local terraform.tfstate into the
azurerm backend (tr-tfstate/trquilltfstate, key envs/azure-tee/terraform.tfstate)
via `terraform init -migrate-state`, verified to plan "No changes" before the
local copy was deleted.

Do not recreate config here: a root module applied against a resurrected
local state is two owners for the same identities and role assignments --
whichever applies second silently reverts the other.

The measured enclave DEPLOY is unaffected and stays here:
tools/deploy-azure-aci.sh.
