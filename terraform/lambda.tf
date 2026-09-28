data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../src/lambda"
  output_path = "${path.module}/.build/forensics-lambda.zip"
  excludes    = ["__pycache__", "**/__pycache__/*"]
}

locals {
  # name => { handler, timeout }
  orchestrator_functions = {
    validate         = { handler = "validate.handler", timeout = 60 }
    request-approval = { handler = "approval.request_handler", timeout = 30 }
    create-snapshots = { handler = "snapshots.create_handler", timeout = 120 }
    check-snapshots  = { handler = "snapshots.check_handler", timeout = 60 }
    copy-snapshots   = { handler = "snapshots.copy_handler", timeout = 120 }
    share-snapshots  = { handler = "snapshots.share_and_copy_handler", timeout = 120 }
    attach-volumes   = { handler = "volumes.attach_handler", timeout = 900 }
    start-scan       = { handler = "scan.start_handler", timeout = 60 }
    check-scan       = { handler = "scan.check_handler", timeout = 60 }
    cleanup          = { handler = "cleanup.handler", timeout = 900 }
    finalize         = { handler = "finalize.handler", timeout = 120 }
    isolate          = { handler = "isolate.handler", timeout = 120 }
    notify-rejected  = { handler = "notify.rejected_handler", timeout = 30 }
    notify-failure   = { handler = "notify.failure_handler", timeout = 30 }
  }

  lambda_env = {
    LOG_LEVEL                     = "INFO"
    FORENSICS_PARTITION           = local.partition
    CASES_TABLE                   = aws_dynamodb_table.cases.name
    APPROVALS_TABLE               = aws_dynamodb_table.approvals.name
    APPROVAL_TOPIC_ARN            = aws_sns_topic.approvals.arn
    NOTIFY_TOPIC_ARN              = aws_sns_topic.notifications.arn
    APPROVAL_API_URL              = aws_apigatewayv2_stage.approval.invoke_url
    APPROVAL_TIMEOUT_SECONDS      = tostring(var.approval_timeout_seconds)
    EVIDENCE_BUCKET               = aws_s3_bucket.evidence.id
    FORENSICS_KMS_KEY_ARN         = aws_kms_key.forensics.arn
    WORKSTATION_INSTANCE_ID       = aws_instance.workstation.id
    SCAN_TIMEOUT_SECONDS          = tostring(var.scan_timeout_seconds)
    SCAN_LOG_GROUP                = aws_cloudwatch_log_group.scan.name
    MAX_VOLUMES                   = tostring(var.max_volumes_per_instance)
    ALLOWED_ACCOUNT_IDS           = join(",", var.member_account_ids)
    MEMBER_ROLE_NAME              = var.member_role_name
    DELETE_INTERMEDIATE_SNAPSHOTS = tostring(var.delete_intermediate_snapshots)
  }
}

resource "aws_cloudwatch_log_group" "lambda" {
  for_each          = toset(concat(keys(local.orchestrator_functions), ["approval-callback"]))
  name              = "/aws/lambda/${local.name}-${each.value}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.forensics.arn
}

resource "aws_lambda_function" "orchestrator" {
  for_each = local.orchestrator_functions

  function_name    = "${local.name}-${each.key}"
  description      = "EC2 forensics workflow step: ${each.key}"
  role             = aws_iam_role.orchestrator.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = each.value.handler
  timeout          = each.value.timeout
  memory_size      = 256
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  kms_key_arn      = aws_kms_key.forensics.arn

  environment {
    variables = local.lambda_env
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}

resource "aws_lambda_function" "approval_callback" {
  function_name    = "${local.name}-approval-callback"
  description      = "Receives approve/reject decisions and resumes the Step Functions workflow"
  role             = aws_iam_role.approval_callback.arn
  runtime          = "python3.12"
  architectures    = ["arm64"]
  handler          = "approval.callback_handler"
  timeout          = 15
  memory_size      = 128
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  kms_key_arn      = aws_kms_key.forensics.arn

  environment {
    variables = {
      LOG_LEVEL       = "INFO"
      APPROVALS_TABLE = aws_dynamodb_table.approvals.name
    }
  }

  tracing_config {
    mode = "Active"
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}
