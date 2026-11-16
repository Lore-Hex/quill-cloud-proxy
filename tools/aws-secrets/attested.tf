variable "provision_attested_keys" {
  description = "Phase 4 only: requires separate approval and a verified Phase 3 release."
  type        = bool
  default     = false
}

variable "accepted_pcr0" {
  description = "CI-authenticated non-debug measurements, widened before boot and narrowed after verification."
  type        = list(string)
  default     = []
  validation {
    condition = length(var.accepted_pcr0) <= 16 && length(distinct(var.accepted_pcr0)) == length(var.accepted_pcr0) && alltrue([
      for value in var.accepted_pcr0 : can(regex("^[0-9a-f]{96}$", value)) && !can(regex("^0+$", value))
    ])
    error_message = "Use at most 16 unique, lowercase, nonzero SHA-384 measurements."
  }
}

module "attested_dublin" {
  count              = var.provision_attested_keys ? 1 : 0
  source             = "./modules/attested-key"
  accepted_pcr0      = var.accepted_pcr0
  operator_arn       = local.operator_arn
  administrator_arns = [local.admin_arn, local.operator_arn]
  parent_arn         = "arn:aws:iam::330422590279:role/quill-enclave-role"
  crypto_actions     = local.crypto_actions
  depends_on         = [aws_iam_role.key_admin]
}

module "attested_paris" {
  count              = var.provision_attested_keys ? 1 : 0
  source             = "./modules/attested-key"
  providers          = { aws = aws.paris }
  accepted_pcr0      = var.accepted_pcr0
  operator_arn       = local.operator_arn
  administrator_arns = [local.admin_arn, local.operator_arn]
  parent_arn         = "arn:aws:iam::330422590279:role/quill-enclave-role"
  crypto_actions     = local.crypto_actions
  depends_on         = [aws_iam_role.key_admin]
}

resource "aws_iam_role_policy" "parent_attested_reader" {
  count = var.provision_attested_keys ? 1 : 0
  name  = "quill-enclave-attested-bootstrap-reader"
  role  = aws_iam_role.parent.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = [module.attested_dublin[0].key_arn, module.attested_paris[0].key_arn]
      },
      {
        Effect   = "Allow"
        Action   = "secretsmanager:GetSecretValue"
        Resource = [module.attested_dublin[0].secret_arn, module.attested_paris[0].secret_arn]
      },
    ]
  })
  lifecycle {
    precondition {
      condition     = var.provision_signer
      error_message = "The approved signer/admin stage must remain enabled."
    }
  }
}

output "attested_bootstrap" {
  value = var.provision_attested_keys ? {
    eu-west-1 = { key_arn = module.attested_dublin[0].key_arn, secret_arn = module.attested_dublin[0].secret_arn }
    eu-west-3 = { key_arn = module.attested_paris[0].key_arn, secret_arn = module.attested_paris[0].secret_arn }
  } : {}
}
