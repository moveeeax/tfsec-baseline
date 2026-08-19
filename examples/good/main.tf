# A well-formed module: it should pass the tfsec-baseline cleanly.
# Encryption on by default, public access locked down, mandatory tags present.

locals {
  common_tags = {
    Owner       = "platform-team"
    Environment = "prod"
  }
}

resource "aws_kms_key" "this" {
  description             = "CMK for the app bucket and volumes"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  tags                    = local.common_tags
}

resource "aws_s3_bucket" "app" {
  bucket = "acme-app-prod-artifacts"
  tags   = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "app" {
  bucket                  = aws_s3_bucket.app.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "app" {
  bucket = aws_s3_bucket.app.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "app" {
  bucket = aws_s3_bucket.app.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.this.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-central-1a"
  size              = 20
  encrypted         = true
  kms_key_id        = aws_kms_key.this.arn
  tags              = local.common_tags
}
