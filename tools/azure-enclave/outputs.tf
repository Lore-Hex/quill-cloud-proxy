// The handoff to tools/deploy-azure-aci.sh. Everything the measured deploy
// needs to know about a region is derived here rather than retyped, so a new
// region cannot be deployed against a stale MAA endpoint or the wrong identity.

output "deploy_env" {
  description = <<-EOT
    Per-region environment for tools/deploy-azure-aci.sh. Render one region's
    block and export it, e.g.:

      terraform output -json deploy_env \
        | jq -r '.australiaeast | to_entries[] | "\(.key)=\(.value)"'
  EOT
  // Keyed off the attestation providers actually in state, not off var.regions,
  // so a partially imported or partially applied configuration still renders.
  // Iterating the variable instead would index a resource that does not exist
  // yet and fail EVERY terraform command mid-import, including `import` itself.
  value = {
    for name, provider in azurerm_attestation_provider.maa : name => {
      RESOURCE_GROUP = var.regions[name].resource_group
      LOCATION       = name
      MAA_ENDPOINT   = replace(provider.attestation_uri, "https://", "")
      API_HOST       = var.regions[name].api_host
      IDENTITY_NAME  = var.identity_name
      VAULT          = var.shared_vault_name
      ACR            = var.shared_acr_name
    }
  }
}

output "identity_principal_ids" {
  description = <<-EOT
    Per-region managed identity principal ids. These are what the role
    assignments bind to, and what an SKR 403 investigation starts from.
  EOT
  value = {
    for name, identity in azurerm_user_assigned_identity.skr : name => identity.principal_id
  }
}

output "identity_client_ids" {
  description = <<-EOT
    Per-region managed identity client ids. This is QUILL_AZURE_MI_CLIENT_ID in
    the container definition, so it is part of the measured surface: changing it
    changes the CCE policy hash and requires a rebind.
  EOT
  value = {
    for name, identity in azurerm_user_assigned_identity.skr : name => identity.client_id
  }
}

output "attestation_authorities" {
  description = <<-EOT
    Per-region MAA authority URLs, in the exact form the SKR key's release
    policy names them (`authority`). Compare against the live policy with:

      az keyvault key show --vault-name trquillkv -n tr-bootstrap-wrap -o json \
        | jq -r '.releasePolicy.encodedPolicy | fromjson | .anyOf[].authority'

    A region present here but absent there cannot boot; a region present there
    but absent here is a retired region whose pin was never cleaned up.
  EOT
  value = {
    for name, provider in azurerm_attestation_provider.maa : name => provider.attestation_uri
  }
}
