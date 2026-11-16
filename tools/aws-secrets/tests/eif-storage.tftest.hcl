mock_provider "aws" {}
mock_provider "aws" { alias = "paris" }

override_resource {
  target = aws_iam_role.parent
  values = { name = "quill-enclave-role" }
}
override_resource { target = aws_iam_role_policy.parent }
override_resource { target = aws_kms_key.legacy_dublin }
override_resource { target = aws_kms_key.legacy_paris }

run "no_storage_without_opt_in" {
  command = plan
  assert {
    condition     = length(module.eif_dublin) == 0 && length(module.eif_paris) == 0 && length(aws_ecr_repository.eif_builder) == 0
    error_message = "Phase 1 must be an explicit opt-in."
  }
}

run "private_create_only_artifacts" {
  command = plan
  variables { provision_eif_storage = true }
  override_resource {
    target          = module.eif_dublin[0].aws_s3_bucket.artifacts
    override_during = plan
    values          = { arn = "arn:aws:s3:::quill-enclave-eif-eu-west-1-330422590279", id = "quill-enclave-eif-eu-west-1-330422590279" }
  }
  override_resource {
    target          = module.eif_paris[0].aws_s3_bucket.artifacts
    override_during = plan
    values          = { arn = "arn:aws:s3:::quill-enclave-eif-eu-west-3-330422590279", id = "quill-enclave-eif-eu-west-3-330422590279" }
  }
  override_resource {
    target          = aws_ecr_repository.eif_builder[0]
    override_during = plan
    values          = { arn = "arn:aws:ecr:eu-west-1:330422590279:repository/quill-enclave-eif-builder" }
  }
  assert {
    condition     = aws_ecr_repository.eif_builder[0].image_tag_mutability == "IMMUTABLE" && aws_ecr_repository.eif_builder[0].image_scanning_configuration[0].scan_on_push
    error_message = "Builder tags must be immutable and scanned."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.parent_eif_reader[0].policy).Statement[0].Action == "s3:GetObject" && length(jsondecode(aws_iam_role_policy.parent_eif_reader[0].policy).Statement) == 1
    error_message = "Hosts may read artifacts, never publish or delete them."
  }
  assert {
    condition     = !strcontains(aws_iam_role_policy.ci_eif_publisher[0].policy, "Delete") && !strcontains(aws_iam_role_policy.ci_eif_publisher[0].policy, "kms:") && !strcontains(aws_iam_role_policy.ci_eif_publisher[0].policy, "secretsmanager:") && !strcontains(aws_iam_role_policy.ci_eif_publisher[0].policy, "ecr:Put")
    error_message = "The publisher may not delete, replace the builder, or access secrets."
  }
}
