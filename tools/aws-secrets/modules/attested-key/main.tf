terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "accepted_pcr0" { type = list(string) }
variable "operator_arn" { type = string }
variable "administrator_arns" { type = list(string) }
variable "parent_arn" { type = string }
variable "crypto_actions" { type = list(string) }
variable "policy_reader_arns" { type = list(string) }

locals {
  policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "NoUnattestedDecryptEvenViaIAMOrGrant"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["kms:Decrypt", "kms:ReEncrypt*"]
        Resource  = "*"
        Condition = {
          StringNotEqualsIgnoreCase = {
            "kms:RecipientAttestation:ImageSha384" = var.accepted_pcr0
          }
        }
      },
      {
        Sid       = "NamedAdministratorsOnly"
        Effect    = "Allow"
        Principal = { AWS = var.administrator_arns }
        NotAction = var.crypto_actions
        Resource  = "*"
      },
      {
        Sid       = "ParentAttestedRecipientOnly"
        Effect    = "Allow"
        Principal = { AWS = var.parent_arn }
        Action    = "kms:Decrypt"
        Resource  = "*"
      },
      {
        Sid       = "OperatorSealsBootstrapOnly"
        Effect    = "Allow"
        Principal = { AWS = var.operator_arn }
        Action    = "kms:GenerateDataKey"
        Resource  = "*"
        Condition = {
          StringEquals = {
            "kms:EncryptionContext:purpose" = "trustedrouter.aws-bootstrap.v2"
          }
        }
      },
      {
        Sid       = "NoUntrustedKeyMutation"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncryptTo",
          "kms:CreateGrant", "kms:PutKeyPolicy", "kms:ScheduleKeyDeletion", "kms:DisableKey",
        ]
        Resource = "*"
        Condition = {
          ArnNotEquals = { "aws:PrincipalArn" = distinct(concat(var.administrator_arns, [var.operator_arn])) }
        }
      },
      {
        # rollout-aws-gateway.yml compares this policy with the published
        # admission set before and after the key administrator's apply. Two
        # metadata reads and nothing else: this key hands nothing to IAM, so
        # the reader's own IAM policy has no effect without this statement.
        Sid       = "RolloutReadsPolicy"
        Effect    = "Allow"
        Principal = { AWS = var.policy_reader_arns }
        Action    = ["kms:DescribeKey", "kms:GetKeyPolicy"]
        Resource  = "*"
      },
    ]
  }
}

resource "aws_kms_key" "attested" {
  description                        = "Nitro recipient-only bootstrap data keys; published PCR0 required"
  key_usage                          = "ENCRYPT_DECRYPT"
  customer_master_key_spec           = "SYMMETRIC_DEFAULT"
  enable_key_rotation                = true
  deletion_window_in_days            = 30
  bypass_policy_lockout_safety_check = false
  policy                             = jsonencode(local.policy)
  lifecycle {
    prevent_destroy = true
    precondition {
      condition = length(var.accepted_pcr0) >= 1 && length(var.accepted_pcr0) <= 16 && alltrue([
        for value in var.accepted_pcr0 : can(regex("^[0-9a-f]{96}$", value)) && !can(regex("^0+$", value))
      ])
      error_message = "Never create an attested key with empty, malformed or debug measurements."
    }
  }
}

resource "aws_kms_alias" "attested" {
  name          = "alias/quill-enclave-attested-cmk"
  target_key_id = aws_kms_key.attested.key_id
  lifecycle { prevent_destroy = true }
}

# Metadata only. The off-host seal operator writes versions; Terraform must
# never receive the plaintext bundle or put secret values into its state.
resource "aws_secretsmanager_secret" "bundle" {
  name                    = "quill/attested-bootstrap-v2"
  description             = "Operator-signed ciphertext-only Nitro bootstrap bundle"
  recovery_window_in_days = 30
  lifecycle { prevent_destroy = true }
}

output "key_arn" { value = aws_kms_key.attested.arn }
output "secret_arn" { value = aws_secretsmanager_secret.bundle.arn }
output "policy" { value = aws_kms_key.attested.policy }
