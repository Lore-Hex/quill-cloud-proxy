variable "provision_signer" {
  description = "Enable only after approval of the specific Phase 0 IAM/KMS plan."
  type        = bool
  default     = false
}

locals {
  operator_arn = "arn:aws:iam::330422590279:user/jperla"
  admin_arn    = "arn:aws:iam::330422590279:role/quill-enclave-key-admin"
  ci_arn       = "arn:aws:iam::330422590279:role/trustedrouter-github-trust-publisher"
  crypto_actions = [
    "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*",
    "kms:GenerateRandom", "kms:Sign", "kms:Verify", "kms:GenerateMac",
    "kms:VerifyMac", "kms:DeriveSharedSecret",
  ]
  signer_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "NamedAdministratorsOnly"
        Effect    = "Allow"
        Principal = { AWS = [local.admin_arn, local.operator_arn] }
        NotAction = local.crypto_actions
        Resource  = "*"
      },
      {
        Sid       = "SealOperatorSigns"
        Effect    = "Allow"
        Principal = { AWS = local.operator_arn }
        Action    = "kms:Sign"
        Resource  = "*"
      },
      {
        Sid       = "CIReadsPublicKey"
        Effect    = "Allow"
        Principal = { AWS = local.ci_arn }
        Action    = ["kms:GetPublicKey", "kms:DescribeKey"]
        Resource  = "*"
      },
      {
        Sid       = "NoOtherSignerEvenViaGrant"
        Effect    = "Deny"
        Principal = "*"
        Action    = "kms:Sign"
        Resource  = "*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = local.operator_arn } }
      },
      {
        Sid       = "NoUntrustedKeyMutation"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncryptTo",
          "kms:CreateGrant", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion",
          "kms:DisableKey",
        ]
        Resource  = "*"
        Condition = { ArnNotEquals = { "aws:PrincipalArn" = [local.operator_arn, local.admin_arn] } }
      },
    ]
  }
}

resource "aws_iam_role" "key_admin" {
  count       = var.provision_signer ? 1 : 0
  name        = "quill-enclave-key-admin"
  description = "Named enclave KMS administrator; Joseph with MFA only. No workload trust."
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.operator_arn }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
  lifecycle { prevent_destroy = true }
}

resource "aws_kms_key" "bundle_signer" {
  count                              = var.provision_signer ? 1 : 0
  description                        = "AWS Nitro bootstrap bundle signer; Phase 0, not yet consumed by production"
  key_usage                          = "SIGN_VERIFY"
  customer_master_key_spec           = "ECC_NIST_P384"
  deletion_window_in_days            = 30
  bypass_policy_lockout_safety_check = false
  policy                             = jsonencode(local.signer_policy)
  # Terraform must wait until the named role exists before KMS validates it.
  depends_on = [aws_iam_role.key_admin]
  lifecycle { prevent_destroy = true }
}

resource "aws_kms_alias" "bundle_signer" {
  count         = var.provision_signer ? 1 : 0
  name          = "alias/quill-enclave-bundle-signer"
  target_key_id = aws_kms_key.bundle_signer[0].key_id
  lifecycle { prevent_destroy = true }
}

output "bundle_signer_arn" {
  value = var.provision_signer ? aws_kms_key.bundle_signer[0].arn : null
}
