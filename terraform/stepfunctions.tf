data "aws_iam_policy_document" "sfn_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${local.name}-state-machine"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
}

data "aws_iam_policy_document" "sfn" {
  statement {
    sid     = "InvokeWorkflowSteps"
    actions = ["lambda:InvokeFunction"]
    resources = concat(
      [for f in aws_lambda_function.orchestrator : f.arn],
      [for f in aws_lambda_function.orchestrator : "${f.arn}:*"],
    )
  }
  statement {
    sid = "ExecutionLogging"
    actions = [
      "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery",
      "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
  statement {
    sid       = "Tracing"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "sfn" {
  name   = "forensics-state-machine"
  role   = aws_iam_role.sfn.id
  policy = data.aws_iam_policy_document.sfn.json
}

resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/vendedlogs/states/${local.name}-workflow"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.forensics.arn
}

resource "aws_sfn_state_machine" "forensics" {
  name     = "${local.name}-workflow"
  role_arn = aws_iam_role.sfn.arn
  type     = "STANDARD"

  definition = templatefile("${path.module}/templates/state_machine.asl.json", {
    partition         = local.partition
    execution_timeout = var.approval_timeout_seconds + var.scan_timeout_seconds + 14400
    approval_timeout  = var.approval_timeout_seconds
    validate          = aws_lambda_function.orchestrator["validate"].arn
    request_approval  = aws_lambda_function.orchestrator["request-approval"].arn
    notify_rejected   = aws_lambda_function.orchestrator["notify-rejected"].arn
    create_snapshots  = aws_lambda_function.orchestrator["create-snapshots"].arn
    check_snapshots   = aws_lambda_function.orchestrator["check-snapshots"].arn
    copy_snapshots    = aws_lambda_function.orchestrator["copy-snapshots"].arn
    share_snapshots   = aws_lambda_function.orchestrator["share-snapshots"].arn
    attach_volumes    = aws_lambda_function.orchestrator["attach-volumes"].arn
    start_scan        = aws_lambda_function.orchestrator["start-scan"].arn
    check_scan        = aws_lambda_function.orchestrator["check-scan"].arn
    cleanup           = aws_lambda_function.orchestrator["cleanup"].arn
    finalize          = aws_lambda_function.orchestrator["finalize"].arn
    isolate           = aws_lambda_function.orchestrator["isolate"].arn
    notify_failure    = aws_lambda_function.orchestrator["notify-failure"].arn
  })

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = false
    level                  = "ERROR"
  }

  tracing_configuration {
    enabled = true
  }

  depends_on = [aws_iam_role_policy.sfn]
}
