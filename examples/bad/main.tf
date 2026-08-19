# A deliberately insecure module: the tfsec-baseline should light this up.
# No encryption, wide-open access, and no mandatory tags anywhere.

resource "aws_s3_bucket" "leaky" {
  bucket = "acme-open-bucket"
  # no tags -> trips the custom Owner/Environment rule
}

resource "aws_s3_bucket_public_access_block" "leaky" {
  bucket                  = aws_s3_bucket.leaky.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_ebs_volume" "data" {
  availability_zone = "eu-central-1a"
  size              = 20
  encrypted         = false # trips the custom encryption-default rule
  # no tags either
}
