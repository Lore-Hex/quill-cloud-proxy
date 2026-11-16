mock_provider "aws" {}
mock_provider "aws" { alias = "paris" }

override_resource {
  target = aws_iam_role.parent
  values = { name = "quill-enclave-role" }
}
override_resource {
  target = aws_iam_role_policy.parent
}
override_resource {
  target = aws_kms_key.legacy_dublin
}
override_resource {
  target = aws_kms_key.legacy_paris
}

run "import_only_default" {
  command = plan
  assert {
    condition     = length(aws_kms_key.bundle_signer) == 0 && length(aws_iam_role.key_admin) == 0 && length(aws_kms_alias.bundle_signer) == 0
    error_message = "Default adoption must not create a role, key or alias."
  }
}

run "explicit_signer_bootstrap" {
  command = plan
  variables { provision_signer = true }
  assert {
    condition     = aws_kms_key.bundle_signer[0].customer_master_key_spec == "ECC_NIST_P384" && aws_kms_key.bundle_signer[0].key_usage == "SIGN_VERIFY"
    error_message = "The bundle signer must use ECDSA P-384."
  }
  assert {
    condition     = !strcontains(aws_kms_key.bundle_signer[0].policy, ":root")
    error_message = "The signer must not delegate key permissions to account root."
  }
  assert {
    condition     = jsondecode(aws_kms_key.bundle_signer[0].policy).Statement[3].Effect == "Deny" && jsondecode(aws_kms_key.bundle_signer[0].policy).Statement[3].Action == "kms:Sign" && jsondecode(aws_kms_key.bundle_signer[0].policy).Statement[3].Condition.ArnNotEquals["aws:PrincipalArn"] == "arn:aws:iam::330422590279:user/jperla"
    error_message = "No IAM grant may let the parent or CI sign bundles."
  }
  assert {
    condition     = jsondecode(aws_iam_role.key_admin[0].assume_role_policy).Statement[0].Condition.Bool["aws:MultiFactorAuthPresent"] == "true" && jsondecode(aws_iam_role.key_admin[0].assume_role_policy).Statement[0].Principal.AWS == "arn:aws:iam::330422590279:user/jperla"
    error_message = "Only Joseph's MFA-authenticated session may assume the key-admin role."
  }
  assert {
    condition     = contains(jsondecode(aws_kms_key.bundle_signer[0].policy).Statement[0].NotAction, "kms:Sign") && contains(jsondecode(aws_kms_key.bundle_signer[0].policy).Statement[0].NotAction, "kms:Decrypt")
    error_message = "The administration statement must not grant cryptographic operations."
  }
  assert {
    condition     = jsondecode(aws_kms_key.bundle_signer[0].policy).Statement[2].Principal.AWS == "arn:aws:iam::330422590279:role/trustedrouter-github-trust-publisher" && toset(jsondecode(aws_kms_key.bundle_signer[0].policy).Statement[2].Action) == toset(["kms:GetPublicKey", "kms:DescribeKey"])
    error_message = "CI may read public signing material, never sign or decrypt."
  }
  assert {
    condition     = !aws_kms_key.bundle_signer[0].bypass_policy_lockout_safety_check
    error_message = "KMS's policy-lockout safety check must remain enabled."
  }
}
