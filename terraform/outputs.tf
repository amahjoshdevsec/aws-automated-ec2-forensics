output "state_machine_arn" {
  description = "ARN of the forensics Step Functions workflow."
  value       = aws_sfn_state_machine.forensics.arn
}

output "state_machine_console_url" {
  description = "Open the workflow in the Step Functions console."
  value       = "https://${local.region}.console.aws.amazon.com/states/home?region=${local.region}#/statemachines/view/${aws_sfn_state_machine.forensics.arn}"
}

output "evidence_bucket" {
  description = "S3 bucket holding reports, artifacts and chain-of-custody manifests."
  value       = aws_s3_bucket.evidence.id
}

output "kms_key_arn" {
  description = "Forensics evidence KMS key."
  value       = aws_kms_key.forensics.arn
}

output "workstation_instance_id" {
  description = "Forensic workstation (connect with: aws ssm start-session --target <id>)."
  value       = aws_instance.workstation.id
}

output "approval_api_url" {
  description = "Base URL of the approval endpoint."
  value       = aws_apigatewayv2_stage.approval.invoke_url
}

output "cases_table" {
  description = "DynamoDB table with one audit record per investigation."
  value       = aws_dynamodb_table.cases.name
}

output "test_target_instance_id" {
  description = "Demo compromised instance to investigate (when deploy_test_target = true)."
  value       = var.deploy_test_target ? aws_instance.test_target[0].id : null
}

output "start_investigation_command" {
  description = "Copy/paste command to start an investigation of the demo target."
  value = var.deploy_test_target ? join(" ", [
    "aws stepfunctions start-execution --region ${local.region}",
    "--state-machine-arn ${aws_sfn_state_machine.forensics.arn}",
    "--input '{\"instance_id\":\"${aws_instance.test_target[0].id}\",\"requested_by\":\"soc-analyst\",\"reason\":\"demo investigation\",\"isolate\":false}'",
  ]) : null
}

output "approvals_table" {
  description = "DynamoDB table holding pending approval tokens (used by the automated smoke test)."
  value       = aws_dynamodb_table.approvals.name
}
