mock_provider "aws" {}

run "empty_admission_is_refused" {
  command = plan
  module { source = "./modules/attested-key" }
  variables {
    accepted_pcr0      = []
    operator_arn       = "arn:aws:iam::330422590279:user/jperla"
    administrator_arns = ["arn:aws:iam::330422590279:user/jperla", "arn:aws:iam::330422590279:role/quill-enclave-key-admin"]
    parent_arn         = "arn:aws:iam::330422590279:role/quill-enclave-role"
    crypto_actions     = ["kms:Decrypt", "kms:Encrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*"]
    policy_reader_arns = ["arn:aws:iam::330422590279:role/trustedrouter-github-gateway-rollout"]
  }
  expect_failures = [aws_kms_key.attested]
}
