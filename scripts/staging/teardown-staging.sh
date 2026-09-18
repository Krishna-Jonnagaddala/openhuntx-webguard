#!/usr/bin/env bash
# Tears down everything provision-staging-bastion.sh and the
# postgres.tf/networking.tf staging apply created, in the order that
# avoids dependency errors: verify the destroy plan first, delete the
# callback_receiver secret this session created, terminate the bastion
# (so the security group it used is no longer referenced), then apply
# the verified destroy plan (RDS, then the NAT/networking resources, in
# Terraform's own dependency order).
#
# Run this whether validation passed or failed, once its outcome is
# recorded in docs/production/STAGING_ENVIRONMENT_PROVISIONING.md
# section 10. There is no reason to leave a disposable staging
# environment running after its purpose is served.
#
# Usage:
#   BASTION_INSTANCE_ID=i-xxx BASTION_SECURITY_GROUP_ID=sg-xxx \
#   BASTION_IAM_ROLE_NAME=... BASTION_INSTANCE_PROFILE_NAME=... \
#   CALLBACK_RECEIVER_SECRET_NAME=... \
#   AWS_REGION=eu-west-2 ./teardown-staging.sh
#
# CALLBACK_RECEIVER_SECRET_NAME must match the value
# run-staging-bootstrap-and-validation.sh was given, and
# TF_VAR_FILE must point at the same var file (or equivalent -var
# flags, including create_staging_bastion_networking=true) the
# provisioning apply used, so the destroy plan matches what was
# actually created, not a default-valued guess at it.

set -euo pipefail

: "${BASTION_INSTANCE_ID:?}"
: "${BASTION_SECURITY_GROUP_ID:?}"
: "${BASTION_IAM_ROLE_NAME:?}"
: "${BASTION_INSTANCE_PROFILE_NAME:?}"
: "${CALLBACK_RECEIVER_SECRET_NAME:?}"
: "${AWS_REGION:?}"
TF_VAR_FILE="${TF_VAR_FILE:-scripts/staging/staging.tfvars}"

TERRAFORM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../infra/terraform" && pwd)"
PLAN_FILE="$(mktemp -t staging-destroy-plan.XXXXXX)"

echo "== 0. Verifying the destroy plan before deleting anything ==" >&2
(
  cd "$TERRAFORM_DIR"
  terraform plan -destroy \
    -var-file="$TF_VAR_FILE" \
    -var create_staging_bastion_networking=true \
    -out="$PLAN_FILE"
  echo "" >&2
  echo "-- Resources this plan will destroy --" >&2
  terraform show -json "$PLAN_FILE" \
    | python3 -c "
import json, sys
plan = json.load(sys.stdin)
for change in plan.get('resource_changes', []):
    if 'delete' in change.get('change', {}).get('actions', []):
        print(f\"  {change['address']}\")
"
)
echo "" >&2
read -r -p "Confirm the list above is exactly this staging environment's own resources (Environment=staging tag), and nothing from another environment. Type 'destroy' to proceed: " CONFIRMATION
if [ "$CONFIRMATION" != "destroy" ]; then
  echo "Aborted: no resources were deleted, and the reviewed plan was discarded." >&2
  rm -f "$PLAN_FILE"
  exit 1
fi

echo "== 1. Deleting the callback_receiver secret ==" >&2
# Default 30-day recovery window: this secret is retained (accruing
# its own $0.40/month) for up to that long unless
# --force-delete-without-recovery is passed explicitly, a real
# irreversible-recovery-vs-cost tradeoff this script does not decide
# on the operator's behalf. The RDS master credential's own secret is
# NOT deleted here: manage_master_user_password=true means RDS itself
# owns that secret's lifecycle and removes it as part of instance
# deletion in step 3 below.
aws secretsmanager delete-secret \
  --region "$AWS_REGION" \
  --secret-id "$CALLBACK_RECEIVER_SECRET_NAME" >/dev/null
echo "  scheduled for deletion (default recovery window)." >&2

echo "== 2. Terminating bastion instance $BASTION_INSTANCE_ID ==" >&2
aws ec2 terminate-instances --region "$AWS_REGION" --instance-ids "$BASTION_INSTANCE_ID" >/dev/null
aws ec2 wait instance-terminated --region "$AWS_REGION" --instance-ids "$BASTION_INSTANCE_ID"
echo "  terminated." >&2

echo "== 3. Removing bastion IAM role/instance profile ==" >&2
aws iam remove-role-from-instance-profile \
  --instance-profile-name "$BASTION_INSTANCE_PROFILE_NAME" \
  --role-name "$BASTION_IAM_ROLE_NAME" || true
aws iam delete-instance-profile --instance-profile-name "$BASTION_INSTANCE_PROFILE_NAME" || true

# Detach every attached policy before deleting the role. IAM refuses
# to delete a role with policies still attached.
for policy_arn in $(aws iam list-attached-role-policies \
  --role-name "$BASTION_IAM_ROLE_NAME" \
  --query 'AttachedPolicies[].PolicyArn' --output text)
do
  aws iam detach-role-policy --role-name "$BASTION_IAM_ROLE_NAME" --policy-arn "$policy_arn"
done
aws iam delete-role --role-name "$BASTION_IAM_ROLE_NAME" || true
echo "  removed." >&2

echo "== 4. Deleting bastion security group $BASTION_SECURITY_GROUP_ID ==" >&2
# May need a short retry loop: AWS can take a few seconds after instance
# termination before the ENI holding this security group is fully
# released.
for attempt in $(seq 1 12); do
  if aws ec2 delete-security-group --region "$AWS_REGION" --group-id "$BASTION_SECURITY_GROUP_ID" 2>/dev/null; then
    echo "  deleted." >&2
    break
  fi
  echo "  still in use, retrying in 10s (attempt $attempt/12)..." >&2
  sleep 10
done

echo "== 5. Applying the verified destroy plan (RDS, then NAT/networking) ==" >&2
(cd "$TERRAFORM_DIR" && terraform apply "$PLAN_FILE")
rm -f "$PLAN_FILE"

echo "" >&2
echo "Destroy plan applied. What was RETAINED rather than destroyed (expected, not a bug):" >&2
echo "  - A final RDS snapshot (postgres.tf's skip_final_snapshot stays false)." >&2
echo "    Not a Terraform-managed resource, so 'terraform destroy' does not remove it." >&2
echo "    ~\$0.10/GB-month (eu-west-2) until deleted manually:" >&2
echo "      aws rds describe-db-snapshots --region $AWS_REGION --db-instance-identifier webguard" >&2
echo "      aws rds delete-db-snapshot --region $AWS_REGION --db-snapshot-identifier <identifier-from-above>" >&2
echo "  - Two KMS keys (RDS storage encryption, VPC flow-log encryption), each now" >&2
echo "    PendingDeletion for AWS's mandatory 7-30 day window. No action needed; this is" >&2
echo "    expected, and each key keeps accruing its ~\$1/month charge, prorated, until the" >&2
echo "    window elapses and AWS deletes it automatically." >&2
echo "  - The callback_receiver secret (step 1 above), similarly pending its own recovery window." >&2
echo "" >&2
echo "Confirm deletion of the rest with:" >&2
echo "  aws rds describe-db-instances --region $AWS_REGION --query 'DBInstances[?DBInstanceIdentifier==\`webguard\`]'" >&2
echo "  aws ec2 describe-vpcs --region $AWS_REGION --filters Name=tag:Environment,Values=staging" >&2
echo "which should both return empty lists." >&2
