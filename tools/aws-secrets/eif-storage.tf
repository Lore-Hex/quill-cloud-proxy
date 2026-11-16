variable "provision_eif_storage" {
  description = "Enable only after approval of the Phase 1 storage and additive IAM plan."
  type        = bool
  default     = false
}

module "eif_dublin" {
  count  = var.provision_eif_storage ? 1 : 0
  source = "./modules/eif-bucket"
  name   = "quill-enclave-eif-eu-west-1-330422590279"
}

module "eif_paris" {
  count     = var.provision_eif_storage ? 1 : 0
  source    = "./modules/eif-bucket"
  providers = { aws = aws.paris }
  name      = "quill-enclave-eif-eu-west-3-330422590279"
}

resource "aws_ecr_repository" "eif_builder" {
  count                = var.provision_eif_storage ? 1 : 0
  name                 = "quill-enclave-eif-builder"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "AES256" }
  lifecycle { prevent_destroy = true }
}

locals {
  eif_bucket_arns = var.provision_eif_storage ? [module.eif_dublin[0].arn, module.eif_paris[0].arn] : []
  eif_objects     = [for arn in local.eif_bucket_arns : "${arn}/releases/*"]
}

resource "aws_iam_role_policy" "parent_eif_reader" {
  count = var.provision_eif_storage ? 1 : 0
  name  = "quill-enclave-eif-reader"
  role  = aws_iam_role.parent.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = local.eif_objects
    }]
  })
}

resource "aws_iam_role_policy" "ci_eif_publisher" {
  count = var.provision_eif_storage ? 1 : 0
  name  = "quill-enclave-eif-publisher"
  role  = "trustedrouter-github-trust-publisher"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = local.eif_objects
      },
      {
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = local.eif_bucket_arns
        Condition = { StringLike = { "s3:prefix" = ["releases/*"] } }
      },
      {
        Effect   = "Allow"
        Action   = "s3:GetBucketLocation"
        Resource = local.eif_bucket_arns
      },
      {
        Effect   = "Allow"
        Action   = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = aws_ecr_repository.eif_builder[0].arn
      },
      {
        Effect   = "Allow"
        Action   = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
    ]
  })
}

output "eif_buckets" {
  value = var.provision_eif_storage ? {
    eu-west-1 = module.eif_dublin[0].name
    eu-west-3 = module.eif_paris[0].name
  } : {}
}

output "eif_builder_repository" {
  value = var.provision_eif_storage ? aws_ecr_repository.eif_builder[0].repository_url : null
}
