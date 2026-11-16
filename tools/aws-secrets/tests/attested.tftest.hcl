mock_provider "aws" {}
mock_provider "aws" { alias = "paris" }

override_resource {
  target = aws_iam_role.parent
  values = { name = "quill-enclave-role" }
}
override_resource { target = aws_iam_role_policy.parent }
override_resource { target = aws_kms_key.legacy_dublin }
override_resource { target = aws_kms_key.legacy_paris }

run "disabled_by_default" {
  command = plan
  assert {
    condition     = length(module.attested_dublin) == 0 && length(module.attested_paris) == 0 && length(aws_iam_role_policy.parent_attested_reader) == 0
    error_message = "Attested keys and access must require separate Phase 4 approval."
  }
}

run "attested_keys_have_explicit_deny_boundary" {
  command = plan
  variables {
    provision_signer        = true
    provision_attested_keys = true
    accepted_pcr0           = [join("", [for i in range(96) : "a"]), join("", [for i in range(96) : "b"])]
  }
  assert {
    condition = alltrue([
      for record in [jsondecode(module.attested_dublin[0].policy), jsondecode(module.attested_paris[0].policy)] :
      record.Statement[0].Effect == "Deny" &&
      record.Statement[0].Principal == "*" &&
      toset(record.Statement[0].Action) == toset(["kms:Decrypt", "kms:ReEncrypt*"]) &&
      toset(record.Statement[0].Condition.StringNotEqualsIgnoreCase["kms:RecipientAttestation:ImageSha384"]) == toset(var.accepted_pcr0)
    ])
    error_message = "Absent, zero or unapproved attestation must be explicitly denied despite IAM/grants."
  }
  assert {
    condition = alltrue([
      for policy in [module.attested_dublin[0].policy, module.attested_paris[0].policy] :
      !strcontains(policy, ":root") &&
      contains(jsondecode(policy).Statement[1].NotAction, "kms:Decrypt") &&
      jsondecode(policy).Statement[3].Principal.AWS == "arn:aws:iam::330422590279:user/jperla" &&
      jsondecode(policy).Statement[3].Action == "kms:GenerateDataKey" &&
      jsondecode(policy).Statement[4].Effect == "Deny" &&
      contains(jsondecode(policy).Statement[4].Action, "kms:CreateGrant")
    ])
    error_message = "Only named admins manage keys; only the operator seals; host/CI cannot create grants."
  }
}

run "debug_measurement_is_refused" {
  command = plan
  variables { accepted_pcr0 = [format("%096d", 0)] }
  expect_failures = [var.accepted_pcr0]
}
