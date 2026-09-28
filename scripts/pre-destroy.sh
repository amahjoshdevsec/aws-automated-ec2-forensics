#!/usr/bin/env bash
# Run BEFORE `terraform destroy`. The workflow deliberately creates things that
# Terraform does not own (so evidence survives a redeploy). This script:
#   1. turns termination protection back off on the demo target
#   2. moves the demo target out of the quarantine security group and deletes that group
#   3. optionally deletes evidence snapshots created by the workflow (--delete-evidence)
set -euo pipefail
cd "$(dirname "$0")/../terraform"
DELETE_EVIDENCE=false
[[ "${1:-}" == "--delete-evidence" ]] && DELETE_EVIDENCE=true

SM_ARN=$(terraform output -raw state_machine_arn)
REGION=$(echo "$SM_ARN" | cut -d: -f4)
export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
TARGET=$(terraform output -raw test_target_instance_id 2>/dev/null || echo "")

if [[ -n "$TARGET" && "$TARGET" != "null" ]]; then
  echo "Disabling termination protection on $TARGET"
  aws ec2 modify-instance-attribute --instance-id "$TARGET" --no-disable-api-termination || true
  VPC=$(aws ec2 describe-instances --instance-ids "$TARGET" --query 'Reservations[0].Instances[0].VpcId' --output text)
  QSG=$(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$VPC" Name=group-name,Values=forensics-quarantine \
        --query 'SecurityGroups[0].GroupId' --output text)
  if [[ "$QSG" != "None" && -n "$QSG" ]]; then
    ORIG=$(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$VPC" Name=tag:Name,Values='*-demo-target' \
          --query 'SecurityGroups[0].GroupId' --output text)
    for ENI in $(aws ec2 describe-network-interfaces --filters Name=group-id,Values="$QSG" --query 'NetworkInterfaces[].NetworkInterfaceId' --output text); do
      echo "Restoring $ENI to $ORIG"
      aws ec2 modify-network-interface-attribute --network-interface-id "$ENI" --groups "$ORIG"
    done
    echo "Deleting quarantine security group $QSG"
    aws ec2 delete-security-group --group-id "$QSG"
  fi
fi

# Analysis volumes are normally deleted by the workflow; remove any left behind by a failed run.
for VOL in $(aws ec2 describe-volumes --filters Name=tag:ManagedBy,Values=aws-automated-ec2-forensics Name=tag:ForensicsStage,Values=analysis \
            --query 'Volumes[].VolumeId' --output text); do
  echo "Deleting leftover analysis volume $VOL"
  aws ec2 detach-volume --volume-id "$VOL" --force >/dev/null 2>&1 || true
  aws ec2 wait volume-available --volume-ids "$VOL" || true
  aws ec2 delete-volume --volume-id "$VOL" || true
done

SNAPS=$(aws ec2 describe-snapshots --owner-ids self --filters Name=tag:ManagedBy,Values=aws-automated-ec2-forensics \
        --query 'Snapshots[].SnapshotId' --output text)
if [[ -n "$SNAPS" ]]; then
  if $DELETE_EVIDENCE; then
    for S in $SNAPS; do echo "Deleting evidence snapshot $S"; aws ec2 delete-snapshot --snapshot-id "$S"; done
  else
    echo "Evidence snapshots kept (re-run with --delete-evidence to remove them): $SNAPS"
  fi
fi
echo "Ready for: terraform destroy"
