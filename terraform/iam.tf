data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------- orchestrator role
resource "aws_iam_role" "orchestrator" {
  name               = "${local.name}-orchestrator"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "orchestrator" {
  statement {
    sid     = "Logs"
    actions = [
      "logs:CreateLogStream", "logs:PutLogEvents",
    ]
    resources = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.name}-*:*"]
  }

  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }

  statement {
    sid     = "DescribeEc2"
    actions = [
      "ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeSnapshots",
      "ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "PreserveEvidence"
    actions   = ["ec2:CreateSnapshot", "ec2:CopySnapshot"]
    resources = ["arn:${local.partition}:ec2:${local.region}:*:volume/*", "arn:${local.partition}:ec2:${local.region}::snapshot/*"]
  }

  statement {
    sid       = "TagForensicResources"
    actions   = ["ec2:CreateTags"]
    resources = ["arn:${local.partition}:ec2:${local.region}:*:*"]
  }

  statement {
    sid       = "ShareTransferSnapshots"
    actions   = ["ec2:ModifySnapshotAttribute"]
    resources = ["arn:${local.partition}:ec2:${local.region}::snapshot/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/ForensicsStage"
      values   = ["transfer"]
    }
  }

  # Evidence snapshots can never be deleted by the automation.
  statement {
    sid       = "DeleteIntermediateSnapshotsOnly"
    actions   = ["ec2:DeleteSnapshot"]
    resources = ["arn:${local.partition}:ec2:${local.region}::snapshot/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/ForensicsStage"
      values   = ["original", "transfer"]
    }
  }

  statement {
    sid       = "CreateAnalysisVolumes"
    actions   = ["ec2:CreateVolume"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:volume/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/ForensicsStage"
      values   = ["analysis"]
    }
  }

  statement {
    sid       = "CreateVolumeFromEvidence"
    actions   = ["ec2:CreateVolume"]
    resources = ["arn:${local.partition}:ec2:${local.region}::snapshot/*"]
  }

  statement {
    sid       = "AttachToWorkstation"
    actions   = ["ec2:AttachVolume", "ec2:DetachVolume", "ec2:StartInstances"]
    resources = [aws_instance.workstation.arn]
  }

  statement {
    sid       = "ManageAnalysisVolumes"
    actions   = ["ec2:AttachVolume", "ec2:DetachVolume", "ec2:DeleteVolume"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:volume/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/ForensicsStage"
      values   = ["analysis"]
    }
  }

  statement {
    sid     = "PreserveAndIsolateInstance"
    actions = [
      "ec2:ModifyInstanceAttribute", "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:CreateSecurityGroup", "ec2:RevokeSecurityGroupEgress",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "RunScan"
    actions   = ["ssm:SendCommand"]
    resources = [
      aws_instance.workstation.arn,
      "arn:${local.partition}:ssm:${local.region}::document/AWS-RunShellScript",
    ]
  }

  statement {
    sid       = "TrackScan"
    actions   = ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations", "ssm:DescribeInstanceInformation"]
    resources = ["*"]
  }

  statement {
    sid       = "EvidenceBucket"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.evidence.arn}/cases/*"]
  }

  statement {
    sid       = "EvidenceBucketList"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.evidence.arn]
  }

  statement {
    sid     = "EvidenceKey"
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey",
    ]
    resources = [aws_kms_key.forensics.arn]
  }

  statement {
    sid       = "EvidenceKeyGrantsForEbs"
    actions   = ["kms:CreateGrant"]
    resources = [aws_kms_key.forensics.arn]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }

  # Source volumes encrypted with the account's default aws/ebs key or another
  # CMK: EBS needs to decrypt them to copy the snapshot. Scoped to use via EC2.
  statement {
    sid       = "SourceVolumeKeysViaEc2"
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant", "kms:ReEncrypt*", "kms:GenerateDataKey*"]
    resources = ["arn:${local.partition}:kms:${local.region}:${local.account_id}:key/*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ec2.${local.region}.amazonaws.com"]
    }
  }

  statement {
    sid       = "CaseRecords"
    actions   = ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:GetItem"]
    resources = [aws_dynamodb_table.cases.arn, aws_dynamodb_table.approvals.arn]
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.approvals.arn, aws_sns_topic.notifications.arn]
  }

  dynamic "statement" {
    for_each = local.cross_account ? [1] : []
    content {
      sid       = "AssumeMemberResponderRoles"
      actions   = ["sts:AssumeRole"]
      resources = local.member_role_arns
    }
  }
}

resource "aws_iam_role_policy" "orchestrator" {
  name   = "forensics-orchestrator"
  role   = aws_iam_role.orchestrator.id
  policy = data.aws_iam_policy_document.orchestrator.json
}

# ---------------------------------------------------------------- approval callback role
resource "aws_iam_role" "approval_callback" {
  name               = "${local.name}-approval-callback"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "approval_callback" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:/aws/lambda/${local.name}-approval-callback:*"]
  }
  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
  statement {
    sid       = "Approvals"
    actions   = ["dynamodb:GetItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.approvals.arn]
  }
  statement {
    sid       = "DecryptApprovals"
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
    resources = [aws_kms_key.forensics.arn]
  }
  # Task-token APIs are authorised by the unguessable token itself; the token is
  # only ever stored server side (DynamoDB), never sent in the email link.
  statement {
    sid       = "ResumeWorkflow"
    actions   = ["states:SendTaskSuccess", "states:SendTaskFailure"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "approval_callback" {
  name   = "forensics-approval-callback"
  role   = aws_iam_role.approval_callback.id
  policy = data.aws_iam_policy_document.approval_callback.json
}
