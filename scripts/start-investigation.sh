#!/usr/bin/env bash
# Start a forensic investigation.
#
#   ./scripts/start-investigation.sh                       # investigate the demo target
#   ./scripts/start-investigation.sh i-0abc123... "reason" [--isolate] [--account 222222222222]
#
# Requires: AWS CLI v2, terraform (reads outputs from ./terraform), jq.
set -euo pipefail
cd "$(dirname "$0")/../terraform"

SM_ARN=$(terraform output -raw state_machine_arn)
REGION=$(echo "$SM_ARN" | cut -d: -f4)
INSTANCE_ID="${1:-$(terraform output -raw test_target_instance_id 2>/dev/null || true)}"
REASON="${2:-Manual investigation}"
shift $(( $# > 2 ? 2 : $# )) || true
ISOLATE=false ACCOUNT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --isolate) ISOLATE=true; shift ;;
    --account) ACCOUNT="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[[ -n "$INSTANCE_ID" && "$INSTANCE_ID" != "null" ]] || { echo "usage: $0 <instance-id> [reason] [--isolate] [--account id]" >&2; exit 2; }

REQUESTER=$(aws sts get-caller-identity --query Arn --output text)
INPUT=$(jq -n --arg i "$INSTANCE_ID" --arg r "$REASON" --arg u "$REQUESTER" --arg a "$ACCOUNT" --argjson iso "$ISOLATE" \
  '{instance_id:$i, reason:$r, requested_by:$u, isolate:$iso} + (if $a != "" then {account_id:$a} else {} end)')

EXEC_ARN=$(aws stepfunctions start-execution --region "$REGION" --state-machine-arn "$SM_ARN" \
  --input "$INPUT" --query executionArn --output text)

echo "Investigation started."
echo "  Execution: $EXEC_ARN"
echo "  Console:   https://${REGION}.console.aws.amazon.com/states/home?region=${REGION}#/v2/executions/details/${EXEC_ARN}"
echo "Check your inbox for the approval email, then watch the workflow in the console."
