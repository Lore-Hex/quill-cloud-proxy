mock_provider "aws" {}
mock_provider "aws" { alias = "paris" }

override_resource { target = aws_iam_role.parent }
override_resource { target = aws_iam_role_policy.parent }
override_resource { target = aws_kms_key.legacy_dublin }
override_resource { target = aws_kms_key.legacy_paris }

run "legacy_permissions_cannot_return_with_default_variables" {
  command = plan
  assert {
    condition     = aws_iam_role_policy.parent.policy == file("${path.module}/ciphertext-only-parent-policy.json")
    error_message = "Default variables must never restore legacy secret permissions."
  }
  assert {
    condition     = toset([for statement in jsondecode(aws_iam_role_policy.parent.policy).Statement : statement.Sid if statement.Effect == "Allow"]) == toset(["PullECR", "Logs"])
    error_message = "The old policy may retain only its existing ECR and logging grants."
  }
  assert {
    condition = [for statement in jsondecode(aws_iam_role_policy.parent.policy).Statement : statement if statement.Effect == "Allow"] == [
      for statement in jsondecode(file("${path.module}/legacy-parent-policy.json")).Statement : statement if contains(["PullECR", "Logs"], statement.Sid)
    ]
    error_message = "Retirement must preserve existing image-download and logging permissions exactly."
  }
  assert {
    condition = jsondecode(aws_iam_role_policy.parent.policy).Statement[0].Effect == "Deny" && jsondecode(aws_iam_role_policy.parent.policy).Statement[0].Action == "secretsmanager:GetSecretValue" && toset(jsondecode(aws_iam_role_policy.parent.policy).Statement[0].NotResource) == toset([
      "arn:aws:secretsmanager:eu-west-1:330422590279:secret:quill/attested-bootstrap-v2-??????",
      "arn:aws:secretsmanager:eu-west-3:330422590279:secret:quill/attested-bootstrap-v2-??????",
      "arn:aws:secretsmanager:eu-west-1:330422590279:secret:quill/tls-cache-recipient-v1-ZE1qiN",
      "arn:aws:secretsmanager:eu-west-3:330422590279:secret:quill/tls-cache-recipient-v1-OohLtW",
    ])
    error_message = "Only the regional ciphertext bundles and the two exact wrapped TLS descriptors may escape the explicit read deny. Recreated descriptors must fail closed."
  }
  assert {
    condition = jsondecode(aws_iam_role_policy.parent.policy).Statement[1].Effect == "Deny" && toset(jsondecode(aws_iam_role_policy.parent.policy).Statement[1].Action) == toset(["kms:Decrypt", "kms:ReEncrypt*"]) && toset(jsondecode(aws_iam_role_policy.parent.policy).Statement[1].Resource) == toset([
      "arn:aws:kms:eu-west-1:330422590279:key/d2535b04-c182-4262-adaa-c9489ce0d196",
      "arn:aws:kms:eu-west-3:330422590279:key/0646cbd6-2687-4561-a7d9-f55aed89d16c",
    ])
    error_message = "Both legacy wrapping keys must remain explicitly denied to the parent."
  }
}
