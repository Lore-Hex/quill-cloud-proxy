# Phase 0 imports only. Freeze the existing objects so adoption cannot alter
# serving access, key policy, or rotation. Later reviewed phases own cutover.
resource "aws_iam_role" "parent" {
  name = "quill-enclave-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = { StringEqualsIfExists = { "aws:SourceAccount" = "330422590279" } }
    }]
  })
  lifecycle {
    prevent_destroy = true
    ignore_changes  = all
  }
}

resource "aws_iam_role_policy" "parent" {
  name   = "quill-enclave-policy"
  role   = aws_iam_role.parent.name
  policy = file("${path.module}/legacy-parent-policy.json")
  lifecycle {
    prevent_destroy = true
    ignore_changes  = all
  }
}

resource "aws_kms_key" "legacy_dublin" {
  description = "Quill enclave envelope-wrap CMK (wraps GCP SA key + BYOK envelopes for the AWS-side Nitro enclave)"
  lifecycle {
    prevent_destroy = true
    ignore_changes  = all
  }
}

resource "aws_kms_key" "legacy_paris" {
  provider    = aws.paris
  description = "Quill enclave envelope-wrap CMK (wraps GCP SA key + BYOK envelopes for the AWS-side Nitro enclave)"
  lifecycle {
    prevent_destroy = true
    ignore_changes  = all
  }
}

import {
  to = aws_iam_role.parent
  id = "quill-enclave-role"
}
import {
  to = aws_iam_role_policy.parent
  id = "quill-enclave-role:quill-enclave-policy"
}
import {
  to = aws_kms_key.legacy_dublin
  id = "d2535b04-c182-4262-adaa-c9489ce0d196"
}
import {
  to = aws_kms_key.legacy_paris
  id = "0646cbd6-2687-4561-a7d9-f55aed89d16c"
}
