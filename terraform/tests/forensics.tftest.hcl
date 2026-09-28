# Offline tests: `terraform test` runs these against a mocked AWS provider, so
# no AWS account or credentials are needed (used by CI on every push).

mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111111111111", arn = "arn:aws:iam::111111111111:user/test", user_id = "AIDTEST" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws", dns_suffix = "amazonaws.com" }
  }
  mock_data "aws_availability_zones" {
    defaults = { names = ["us-east-1a", "us-east-1b"] }
  }
  mock_data "aws_ssm_parameter" {
    defaults = { value = "ami-0123456789abcdef0", insecure_value = "ami-0123456789abcdef0" }
  }
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}]}" }
  }

  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000", key_id = "00000000-0000-0000-0000-000000000000" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111111111111:role/mock-role" }
  }
  mock_resource "aws_iam_instance_profile" {
    defaults = { arn = "arn:aws:iam::111111111111:instance-profile/mock-profile" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::mock-evidence-bucket", id = "mock-evidence-bucket" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-1:111111111111:mock-topic" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:us-east-1:111111111111:table/mock-table" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:111111111111:log-group:/mock" }
  }
  mock_resource "aws_instance" {
    defaults = { arn = "arn:aws:ec2:us-east-1:111111111111:instance/i-0123456789abcdef0", id = "i-0123456789abcdef0" }
  }
  mock_resource "aws_lambda_function" {
    defaults = {
      arn        = "arn:aws:lambda:us-east-1:111111111111:function:mock-fn"
      invoke_arn = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:111111111111:function:mock-fn/invocations"
    }
  }
  mock_resource "aws_sfn_state_machine" {
    defaults = { arn = "arn:aws:states:us-east-1:111111111111:stateMachine:mock-workflow" }
  }
  mock_resource "aws_apigatewayv2_api" {
    defaults = { execution_arn = "arn:aws:execute-api:us-east-1:111111111111:abcdef1234", id = "abcdef1234" }
  }
  mock_resource "aws_apigatewayv2_stage" {
    defaults = { invoke_url = "https://abcdef1234.execute-api.us-east-1.amazonaws.com/" }
  }
}

variables {
  approver_email = "soc@example.com"
}

run "single_account_lab_defaults" {
  command = apply

  assert {
    condition     = aws_s3_bucket_public_access_block.evidence.block_public_acls && aws_s3_bucket_public_access_block.evidence.restrict_public_buckets
    error_message = "Evidence bucket must block all public access."
  }

  assert {
    condition     = aws_kms_key.forensics.enable_key_rotation
    error_message = "Evidence KMS key must rotate."
  }

  assert {
    condition     = aws_instance.workstation.metadata_options[0].http_tokens == "required"
    error_message = "Workstation must enforce IMDSv2."
  }

  assert {
    condition     = aws_instance.workstation.root_block_device[0].encrypted
    error_message = "Workstation root volume must be encrypted."
  }

  assert {
    condition     = length(aws_instance.test_target) == 1
    error_message = "Demo target should be deployed by default."
  }

  assert {
    condition     = jsondecode(aws_sfn_state_machine.forensics.definition).StartAt == "ValidateRequest"
    error_message = "Workflow must start by validating the request."
  }

  assert {
    condition     = jsondecode(aws_sfn_state_machine.forensics.definition).States.RequestApproval.Resource == "arn:aws:states:::lambda:invoke.waitForTaskToken"
    error_message = "Approval step must use the callback (waitForTaskToken) pattern."
  }

  assert {
    condition     = length(aws_cloudwatch_event_rule.guardduty) == 0
    error_message = "GuardDuty trigger must be opt-in."
  }
}

run "production_like_settings" {
  command = apply

  variables {
    deploy_test_target            = false
    enable_object_lock            = true
    force_destroy_evidence_bucket = false
    enable_guardduty_trigger      = true
    member_account_ids            = ["222222222222", "333333333333"]
  }

  assert {
    condition     = length(aws_instance.test_target) == 0
    error_message = "No demo target in production."
  }

  assert {
    condition     = length(aws_s3_bucket_object_lock_configuration.evidence) == 1
    error_message = "Object Lock should be configured."
  }

  assert {
    condition     = aws_dynamodb_table.cases.deletion_protection_enabled
    error_message = "Case table must be deletion protected in production."
  }

  assert {
    condition     = length(aws_cloudwatch_event_target.guardduty) == 1
    error_message = "GuardDuty trigger should be wired to the workflow."
  }

  assert {
    condition     = strcontains(aws_lambda_function.orchestrator["validate"].environment[0].variables["ALLOWED_ACCOUNT_IDS"], "222222222222")
    error_message = "Member accounts must be passed to the workflow allow-list."
  }
}

run "rejects_invalid_email" {
  command = plan

  variables {
    approver_email = "not-an-email"
  }

  expect_failures = [var.approver_email]
}
