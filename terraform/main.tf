data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  name        = var.project_name
  account_id  = data.aws_caller_identity.current.account_id
  partition   = data.aws_partition.current.partition
  region      = var.region
  az          = data.aws_availability_zones.available.names[0]
  notify_mail = coalesce(var.notification_email, var.approver_email)

  evidence_bucket_name = "${local.name}-evidence-${local.account_id}-${local.region}"
  cross_account        = length(var.member_account_ids) > 0
  member_role_arns     = [for a in var.member_account_ids : "arn:${local.partition}:iam::${a}:role/${var.member_role_name}"]
}
