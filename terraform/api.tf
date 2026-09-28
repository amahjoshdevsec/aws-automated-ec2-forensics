# Public HTTPS endpoint that receives approve / reject decisions from the
# approval email. GET shows a confirmation page; POST records the decision.
# Approval ids are 256-bit random, single use and expire with the request.
# Production: put this behind Amazon Cognito / IAM Identity Center or replace
# the email link with a ChatOps (Slack/Teams) or ITSM (ServiceNow) approval.

resource "aws_apigatewayv2_api" "approval" {
  name          = "${local.name}-approval"
  protocol_type = "HTTP"
  description   = "Approve or reject forensic investigations"
}

resource "aws_apigatewayv2_integration" "approval" {
  api_id                 = aws_apigatewayv2_api.approval.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.approval_callback.invoke_arn
  payload_format_version = "2.0"
}

resource "aws_apigatewayv2_route" "decision_get" {
  api_id    = aws_apigatewayv2_api.approval.id
  route_key = "GET /decision"
  target    = "integrations/${aws_apigatewayv2_integration.approval.id}"
}

resource "aws_apigatewayv2_route" "decision_post" {
  api_id    = aws_apigatewayv2_api.approval.id
  route_key = "POST /decision"
  target    = "integrations/${aws_apigatewayv2_integration.approval.id}"
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/${local.name}/approval-api"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.forensics.arn
}

resource "aws_apigatewayv2_stage" "approval" {
  api_id      = aws_apigatewayv2_api.approval.id
  name        = "$default"
  auto_deploy = true

  default_route_settings {
    throttling_burst_limit = 10
    throttling_rate_limit  = 5
  }

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api.arn
    format          = jsonencode({
      requestId = "$context.requestId"
      ip        = "$context.identity.sourceIp"
      userAgent = "$context.identity.userAgent"
      time      = "$context.requestTime"
      method    = "$context.httpMethod"
      path      = "$context.path"
      status    = "$context.status"
    })
  }
}

resource "aws_lambda_permission" "approval_api" {
  statement_id  = "AllowApiGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approval_callback.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.approval.execution_arn}/*/*/decision"
}
