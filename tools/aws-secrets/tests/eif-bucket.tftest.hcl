mock_provider "aws" {}

run "private_immutable_release_bucket" {
  command = plan
  module { source = "./modules/eif-bucket" }
  variables { name = "quill-enclave-eif-test" }
  override_resource {
    target          = aws_s3_bucket.artifacts
    override_during = plan
    values          = { arn = "arn:aws:s3:::quill-enclave-eif-test", id = "quill-enclave-eif-test" }
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.artifacts.block_public_acls && aws_s3_bucket_public_access_block.artifacts.block_public_policy && aws_s3_bucket_public_access_block.artifacts.ignore_public_acls && aws_s3_bucket_public_access_block.artifacts.restrict_public_buckets
    error_message = "All public access must remain blocked."
  }
  assert {
    condition     = aws_s3_bucket_versioning.artifacts.versioning_configuration[0].status == "Enabled"
    error_message = "Versioning must remain enabled."
  }
  assert {
    condition     = jsondecode(aws_s3_bucket_policy.artifacts.policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false" && jsondecode(aws_s3_bucket_policy.artifacts.policy).Statement[0].Effect == "Deny"
    error_message = "Unencrypted transport must be denied."
  }
  assert {
    condition     = jsondecode(aws_s3_bucket_policy.artifacts.policy).Statement[1].Condition.StringNotEquals["s3:if-none-match"] == "*" && jsondecode(aws_s3_bucket_policy.artifacts.policy).Statement[1].Effect == "Deny"
    error_message = "Release writes must require If-None-Match: *."
  }
  assert {
    condition     = toset(jsondecode(aws_s3_bucket_policy.artifacts.policy).Statement[2].Action) == toset(["s3:DeleteObject", "s3:DeleteObjectVersion"]) && jsondecode(aws_s3_bucket_policy.artifacts.policy).Statement[2].Effect == "Deny"
    error_message = "Release deletion must be explicitly denied."
  }
}
