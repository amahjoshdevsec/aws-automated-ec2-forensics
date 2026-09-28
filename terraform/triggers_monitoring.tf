# ---------------------------------------------------------------- GuardDuty trigger (optional)
# High severity GuardDuty EC2 findings start an investigation automatically.
# The human approval gate still applies before any evidence is collected.

resource "aws_cloudwatch_event_rule" "guardduty" {
  count         = var.enable_guardduty_trigger ? 1 : 0
  name          = "${local.name}-guardduty-ec2"
  description   = "Start an EC2 forensic investigation for high severity GuardDuty findings"
  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail        = {
      resource = { resourceType = ["Instance"] }
      severity = [{ numeric = [">=", var.guardduty_min_severity] }]
    }
  })
}

data "aws_iam_policy_document" "events_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "events" {
  count              = var.enable_guardduty_trigger ? 1 : 0
  name               = "${local.name}-events"
  assume_role_policy = data.aws_iam_policy_document.events_assume.json
}

resource "aws_iam_role_policy" "events" {
  count  = var.enable_guardduty_trigger ? 1 : 0
  name   = "start-forensics"
  role   = aws_iam_role.events[0].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "states:StartExecution"
      Resource = aws_sfn_state_machine.forensics.arn
    }]
  })
}

resource "aws_cloudwatch_event_target" "guardduty" {
  count    = var.enable_guardduty_trigger ? 1 : 0
  rule     = aws_cloudwatch_event_rule.guardduty[0].name
  arn      = aws_sfn_state_machine.forensics.arn
  role_arn = aws_iam_role.events[0].arn

  input_transformer {
    input_paths = {
      instance = "$.detail.resource.instanceDetails.instanceId"
      account  = "$.detail.accountId"
      region   = "$.region"
      type     = "$.detail.type"
      finding  = "$.detail.id"
    }
    input_template = <<-EOT
      {
        "instance_id": <instance>,
        "account_id": <account>,
        "region": <region>,
        "requested_by": "guardduty",
        "reason": "GuardDuty finding <finding>: <type>",
        "isolate": false
      }
    EOT
  }
}

# ---------------------------------------------------------------- alarms
resource "aws_cloudwatch_metric_alarm" "workflow_failures" {
  alarm_name          = "${local.name}-workflow-failures"
  alarm_description   = "A forensic investigation failed or timed out"
  namespace           = "AWS/States"
  metric_name         = "ExecutionsFailed"
  dimensions          = { StateMachineArn = aws_sfn_state_machine.forensics.arn }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.notifications.arn]
}

resource "aws_cloudwatch_metric_alarm" "workflow_timeouts" {
  alarm_name          = "${local.name}-workflow-timeouts"
  alarm_description   = "A forensic investigation timed out"
  namespace           = "AWS/States"
  metric_name         = "ExecutionsTimedOut"
  dimensions          = { StateMachineArn = aws_sfn_state_machine.forensics.arn }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.notifications.arn]
}

# CloudWatch alarms publishing to a KMS-encrypted topic need key access.
data "aws_iam_policy_document" "notifications_topic" {
  statement {
    sid       = "AllowCloudWatchAlarms"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.notifications.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
  statement {
    sid       = "AccountOwner"
    actions   = ["sns:Publish", "sns:Subscribe", "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:ListSubscriptionsByTopic"]
    resources = [aws_sns_topic.notifications.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_sns_topic_policy" "notifications" {
  arn    = aws_sns_topic.notifications.arn
  policy = data.aws_iam_policy_document.notifications_topic.json
}
