# Deploy this module into every workload (member) account that the forensics
# account should be able to investigate, e.g. with a provider alias per account,
# AWS Control Tower Account Factory for Terraform (AFT) customizations, or
# CloudFormation StackSets (see README for the equivalent approach).

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.60.0, < 7.0.0"
    }
  }
}

variable "forensics_account_id" {
  description = "Account id of the central forensics (security tooling) account."
  type        = string
}

variable "orchestrator_role_name" {
  description = "Name of the orchestrator Lambda role in the forensics account (<project_name>-orchestrator)."
  type        = string
  default     = "ec2-forensics-orchestrator"
}

variable "forensics_kms_key_arn" {
  description = "ARN of the forensics evidence KMS key (terraform output kms_key_arn)."
  type        = string
}

variable "role_name" {
  description = "Name of the responder role (must match member_role_name in the forensics stack)."
  type        = string
  default     = "ForensicsResponderRole"
}

data "aws_partition" "current" {}

data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.forensics_account_id}:role/${var.orchestrator_role_name}"]
    }
  }
}

resource "aws_iam_role" "responder" {
  name                 = var.role_name
  description          = "Assumed by the central EC2 forensics workflow to preserve evidence and contain instances"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "responder" {
  statement {
    sid     = "Describe"
    actions = [
      "ec2:DescribeInstances", "ec2:DescribeVolumes", "ec2:DescribeSnapshots",
      "ec2:DescribeSecurityGroups", "ec2:DescribeNetworkInterfaces",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "Snapshot"
    actions   = ["ec2:CreateSnapshot", "ec2:CopySnapshot", "ec2:CreateTags"]
    resources = ["*"]
  }
  statement {
    sid       = "ShareTransferSnapshotWithForensicsAccount"
    actions   = ["ec2:ModifySnapshotAttribute"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/ForensicsStage"
      values   = ["transfer"]
    }
  }
  statement {
    sid       = "DeleteIntermediateSnapshots"
    actions   = ["ec2:DeleteSnapshot"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/ForensicsStage"
      values   = ["original", "transfer"]
    }
  }
  statement {
    sid     = "PreserveAndContain"
    actions = [
      "ec2:ModifyInstanceAttribute", "ec2:ModifyNetworkInterfaceAttribute",
      "ec2:CreateSecurityGroup", "ec2:RevokeSecurityGroupEgress",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "ForensicsKey"
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey", "kms:CreateGrant"]
    resources = [var.forensics_kms_key_arn]
  }
  statement {
    sid       = "LocalVolumeKeysViaEc2"
    actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant", "kms:ReEncrypt*", "kms:GenerateDataKey*"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:ViaService"
      values   = ["ec2.*.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "responder" {
  name   = "forensics-responder"
  role   = aws_iam_role.responder.id
  policy = data.aws_iam_policy_document.responder.json
}

output "role_arn" {
  value = aws_iam_role.responder.arn
}
