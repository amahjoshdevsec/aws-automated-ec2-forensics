# Customer managed key that protects all evidence: EBS snapshots, analysis
# volumes, the S3 evidence bucket, DynamoDB tables, SNS topics and logs.
# Snapshots encrypted with this key can be shared cross-account (the default
# aws/ebs key cannot), which is what makes multi-account collection possible.

data "aws_iam_policy_document" "kms" {
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid     = "CloudWatchLogs"
    actions = [
      "kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:*"]
    }
  }

  statement {
    sid       = "CloudWatchAlarmsToEncryptedTopic"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
  }

  dynamic "statement" {
    for_each = local.cross_account ? [1] : []
    content {
      sid     = "MemberAccountResponderUse"
      actions = [
        "kms:Encrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey", "kms:Decrypt",
      ]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = local.member_role_arns
      }
    }
  }

  dynamic "statement" {
    for_each = local.cross_account ? [1] : []
    content {
      sid       = "MemberAccountResponderGrants"
      actions   = ["kms:CreateGrant"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = local.member_role_arns
      }
      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = ["true"]
      }
    }
  }
}

resource "aws_kms_key" "forensics" {
  description             = "${local.name} evidence encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_deletion_window_days
  policy                  = data.aws_iam_policy_document.kms.json
}

resource "aws_kms_alias" "forensics" {
  name          = "alias/${local.name}-evidence"
  target_key_id = aws_kms_key.forensics.key_id
}
