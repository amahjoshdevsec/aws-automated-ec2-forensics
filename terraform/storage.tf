# ---------------------------------------------------------------- evidence bucket
resource "aws_s3_bucket" "evidence" {
  bucket              = local.evidence_bucket_name
  force_destroy       = var.force_destroy_evidence_bucket
  object_lock_enabled = var.enable_object_lock
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.forensics.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  count  = var.enable_object_lock ? 1 : 0
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_days
    }
  }
  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    id     = "archive-case-evidence"
    status = "Enabled"
    filter {
      prefix = "cases/"
    }
    transition {
      days          = var.evidence_retention_days
      storage_class = "DEEP_ARCHIVE"
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "expire-old-tool-versions"
    status = "Enabled"
    filter {
      prefix = "tools/"
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

data "aws_iam_policy_document" "evidence_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Objects without an explicit SSE header (for example SSM command output) are
  # still encrypted by the bucket's default SSE-KMS configuration. This denies
  # anyone explicitly requesting a weaker algorithm.
  statement {
    sid       = "DenyNonKmsEncryption"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }
  }

  statement {
    sid       = "DenyEvidenceDeletionExceptAdmins"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.evidence.arn}/cases/*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.orchestrator.arn, aws_iam_role.workstation.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket     = aws_s3_bucket.evidence.id
  policy     = data.aws_iam_policy_document.evidence_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.evidence]
}

# Scan tooling is versioned in the bucket and pulled by the workstation at scan time.
resource "aws_s3_object" "scan_script" {
  bucket                 = aws_s3_bucket.evidence.id
  key                    = "tools/forensic-scan.sh"
  source                 = "${path.module}/../src/workstation/forensic-scan.sh"
  source_hash            = filemd5("${path.module}/../src/workstation/forensic-scan.sh")
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.forensics.arn
}

resource "aws_s3_object" "yara_rules" {
  for_each               = fileset("${path.module}/../src/workstation/rules", "*.yar")
  bucket                 = aws_s3_bucket.evidence.id
  key                    = "tools/rules/${each.value}"
  source                 = "${path.module}/../src/workstation/rules/${each.value}"
  source_hash            = filemd5("${path.module}/../src/workstation/rules/${each.value}")
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.forensics.arn
}

# ---------------------------------------------------------------- case records
resource "aws_dynamodb_table" "cases" {
  name         = "${local.name}-cases"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "case_id"

  attribute {
    name = "case_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.forensics.arn
  }

  deletion_protection_enabled = !var.force_destroy_evidence_bucket
}

resource "aws_dynamodb_table" "approvals" {
  name         = "${local.name}-approvals"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "approval_id"

  attribute {
    name = "approval_id"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.forensics.arn
  }
}

# ---------------------------------------------------------------- notifications
resource "aws_sns_topic" "approvals" {
  name              = "${local.name}-approvals"
  kms_master_key_id = aws_kms_key.forensics.arn
}

resource "aws_sns_topic" "notifications" {
  name              = "${local.name}-notifications"
  kms_master_key_id = aws_kms_key.forensics.arn
}

resource "aws_sns_topic_subscription" "approver" {
  topic_arn = aws_sns_topic.approvals.arn
  protocol  = "email"
  endpoint  = var.approver_email
}

resource "aws_sns_topic_subscription" "notify" {
  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = local.notify_mail
}
