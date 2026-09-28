#!/usr/bin/env bash
# End-to-end smoke test against a deployed stack (used by the Deploy workflow
# and runnable from a laptop). It starts an investigation of the demo target,
# approves it programmatically (standing in for the human approver), waits for
# the workflow to finish and asserts that the planted indicators were found.
set -euo pipefail
cd "$(dirname "$0")/../terraform"

SM_ARN=$(terraform output -raw state_machine_arn)
REGION=$(echo "$SM_ARN" | cut -d: -f4)
TARGET=$(terraform output -raw test_target_instance_id)
APPROVALS=$(terraform output -raw approvals_table)
BUCKET=$(terraform output -raw evidence_bucket)
CASE_ID="SMOKE-$(date -u +%Y%m%d-%H%M%S)"
TIMEOUT_MIN="${SMOKE_TIMEOUT_MIN:-75}"
export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"

[[ -n "$TARGET" && "$TARGET" != "null" ]] || { echo "deploy_test_target must be true for the smoke test" >&2; exit 1; }

# Give first-boot scripts time to plant indicators on a freshly created target.
LAUNCH=$(aws ec2 describe-instances --instance-ids "$TARGET" --query 'Reservations[0].Instances[0].LaunchTime' --output text)
AGE=$(( $(date +%s) - $(date -d "$LAUNCH" +%s) ))
if (( AGE < 300 )); then echo "Target is ${AGE}s old; waiting for user data to finish"; sleep $(( 300 - AGE )); fi

echo "Starting case $CASE_ID for $TARGET"
EXEC_ARN=$(aws stepfunctions start-execution --state-machine-arn "$SM_ARN" --name "$CASE_ID" \
  --input "{\"instance_id\":\"$TARGET\",\"case_id\":\"$CASE_ID\",\"requested_by\":\"smoke-test\",\"reason\":\"automated smoke test\",\"isolate\":false}" \
  --query executionArn --output text)

echo "Waiting for the approval request"
TOKEN="" APPROVAL_ID=""
for _ in $(seq 1 30); do
  read -r APPROVAL_ID TOKEN < <(aws dynamodb scan --table-name "$APPROVALS" \
    --filter-expression "case_id = :c" --expression-attribute-values "{\":c\":{\"S\":\"$CASE_ID\"}}" \
    --query 'Items[0].[approval_id.S, task_token.S]' --output text) || true
  [[ -n "$TOKEN" && "$TOKEN" != "None" ]] && break
  sleep 5
done
[[ -n "$TOKEN" && "$TOKEN" != "None" ]] || { echo "approval request never appeared" >&2; exit 1; }

aws dynamodb delete-item --table-name "$APPROVALS" --key "{\"approval_id\":{\"S\":\"$APPROVAL_ID\"}}"
aws stepfunctions send-task-success --task-token "$TOKEN" \
  --task-output '{"approved":true,"decision":"approve","decided_by":"smoke-test"}'
echo "Approved. Waiting for the workflow (up to ${TIMEOUT_MIN} min)"

STATUS=RUNNING
for _ in $(seq 1 $(( TIMEOUT_MIN * 2 ))); do
  STATUS=$(aws stepfunctions describe-execution --execution-arn "$EXEC_ARN" --query status --output text)
  [[ "$STATUS" != "RUNNING" ]] && break
  sleep 30
done
echo "Execution finished with status $STATUS"
[[ "$STATUS" == "SUCCEEDED" ]] || {
  aws stepfunctions get-execution-history --execution-arn "$EXEC_ARN" --reverse-order --max-items 5 --output json | head -80
  exit 1
}

aws s3 cp "s3://${BUCKET}/cases/${CASE_ID}/analysis/summary.json" /tmp/summary.json --only-show-errors
aws s3 cp "s3://${BUCKET}/cases/${CASE_ID}/analysis/report.md" /tmp/report.md --only-show-errors
echo "----- report.md (head) -----"; head -40 /tmp/report.md
YARA=$(jq '.totals.yara_matches' /tmp/summary.json)
CLAM=$(jq '.totals.clamav_detections' /tmp/summary.json)
echo "YARA matches: $YARA, ClamAV detections: $CLAM"
(( YARA > 0 )) || { echo "expected YARA matches on the demo target" >&2; exit 1; }
aws s3api head-object --bucket "$BUCKET" --key "cases/${CASE_ID}/chain-of-custody.json" >/dev/null
echo "SMOKE TEST PASSED: case $CASE_ID"
