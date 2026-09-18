#!/usr/bin/env bash
# Tears down everything provision-staging-bastion.sh and the
# postgres.tf/networking.tf staging apply created, in the order that
# avoids dependency errors: bastion first (so the security group it
# used is no longer referenced), then RDS (which references that
# security group's VPC), then the remaining networking resources.
#
# Run this whether validation passed or failed, once its outcome is
# recorded in docs/production/STAGING_ENVIRONMENT_PROVISIONING.md
# section 8. There is no reason to leave a disposable staging database
# running after its purpose is served.
#
# Usage:
#   BASTION_INSTANCE_ID=i-xxx BASTION_SECURITY_GROUP_ID=sg-xxx \
#   BASTION_IAM_ROLE_NAME=... BASTION_INSTANCE_PROFILE_NAME=... \
#   AWS_REGION=eu-west-2 ./teardown-staging.sh
#
# Then, separately, from infra/terraform:
#   terraform destroy -var-file=scripts/staging/staging.tfvars

set -euo pipefail

: "${BASTION_INSTANCE_ID:?}"
: "${BASTION_SECURITY_GROUP_ID:?}"
: "${BASTION_IAM_ROLE_NAME:?}"
: "${BASTION_INSTANCE_PROFILE_NAME:?}"
: "${AWS_REGION:?}"

echo "== Terminating bastion instance $BASTION_INSTANCE_ID ==" >&2
aws ec2 terminate-instances --region "$AWS_REGION" --instance-ids "$BASTION_INSTANCE_ID" >/dev/null
aws ec2 wait instance-terminated --region "$AWS_REGION" --instance-ids "$BASTION_INSTANCE_ID"
echo "  terminated." >&2

echo "== Removing bastion IAM role/instance profile ==" >&2
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

echo "== Deleting bastion security group $BASTION_SECURITY_GROUP_ID ==" >&2
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

echo "" >&2
echo "Bastion teardown complete." >&2
echo "Next, from infra/terraform:" >&2
echo "  terraform destroy -var-file=../../scripts/staging/staging.tfvars" >&2
echo "" >&2
echo "This deletes aws_db_instance.webguard (a final snapshot is taken" >&2
echo "automatically unless postgres.tf is changed to skip it. Leave" >&2
echo "that default in place for a validation run), plus the VPC/subnet/" >&2
echo "security-group networking resources, and their KMS key (subject to" >&2
echo "AWS's mandatory 7-30 day deletion window)." >&2
echo "Confirm deletion afterward with:" >&2
echo "  aws rds describe-db-instances --region \$AWS_REGION --query 'DBInstances[?DBInstanceIdentifier==\`webguard\`]'" >&2
echo "which should return an empty list." >&2
