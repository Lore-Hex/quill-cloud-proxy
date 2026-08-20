variable "subscription_id" {
  description = "Azure subscription holding the enclave regions."
  type        = string
  default     = "2fc83893-ca6c-48e4-b090-8860fba33d33"
}

variable "identity_name" {
  description = <<-EOT
    User-assigned identity name, identical in every region. deploy-azure-aci.sh
    defaults IDENTITY_NAME to this and looks it up inside the region's own
    resource group, so the name is shared while the principal is per-region.
  EOT
  type        = string
  default     = "tr-skr-identity"
}

variable "shared_resource_group" {
  description = <<-EOT
    Resource group holding the resources every region shares: the SKR vault, the
    enclave registry and the ACME cert cache. It is TR-TEE-DUBAI because Dubai
    was the first region, not because it is Dubai's -- which is exactly why this
    configuration never manages that group.
  EOT
  type        = string
  default     = "TR-TEE-DUBAI"
}

variable "shared_vault_name" {
  description = "Key Vault Premium holding tr-bootstrap-wrap (SKR key) and tr-bootstrap-bundle."
  type        = string
  default     = "trquillkv"
}

variable "shared_acr_name" {
  description = "Registry holding quill-enclave-azure."
  type        = string
  default     = "trquillacr"
}

variable "shared_acme_storage_account" {
  description = "StorageV2 account backing the shared ACME cert cache."
  type        = string
  default     = "trquillacmecache"
}

variable "regions" {
  description = <<-EOT
    Enclave regions, keyed by Azure location.

    manage_resource_group is false for uaenorth ONLY because TR-TEE-DUBAI also
    holds the shared vault, registry and storage account; a per-region destroy
    there would take the whole platform's secrets with it. Any region whose
    group holds nothing but that region's own scaffolding sets it true.

    grant_crypto_officer records reality rather than intent. Dubai's identity
    holds "Key Vault Crypto Officer", which lets a workload rewrite the release
    policy that constrains it -- a self-authorizing TEE. New regions must leave
    this false; rebinding is an operator action, not an enclave capability.
  EOT
  type = map(object({
    resource_group        = string
    attestation_provider  = string
    api_host              = string
    manage_resource_group = bool
    grant_crypto_officer  = bool
  }))

  default = {
    uaenorth = {
      resource_group        = "TR-TEE-DUBAI"
      attestation_provider  = "trquilluaen"
      api_host              = "api-azure.trustedrouter.com"
      manage_resource_group = false
      grant_crypto_officer  = true
    }
    australiaeast = {
      resource_group        = "tr-tee-sydney"
      attestation_provider  = "trquillsyd"
      api_host              = "api-azure-syd.trustedrouter.com"
      manage_resource_group = true
      grant_crypto_officer  = false
    }
  }
}
