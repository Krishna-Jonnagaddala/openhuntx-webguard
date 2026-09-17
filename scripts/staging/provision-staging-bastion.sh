#!/usr/bin/env bash
# Creates one minimal, temporary EC2 instance to act as a network bastion
# for reaching a private-subnet RDS instance during P1-2 staging
# validation. See docs/production/STAGING_ENVIRONMENT_PROVISIONING.md
# section 2 for why this exists and why it is not part of
# infra/terraform/ (that tree is the reviewed, production-shaped
# configuration; this is a throwaway test-runner, created and destroyed
# in the same validation session).
#
# Reached over AWS Systems Manager Session Manager, not SSH: no key
# pair to generate or leak, no inbound security-group rule needed beyond
# what SSM's own VPC endpoint traffic requires. Requires the AWS CLI,
# valid credentials, and that the VPC/subnet/security-group networking
# resources from infra/terraform (networking.tf) already exist.
#
# Usage:
#   VPC_ID=vpc-xxx SUBNET_ID=subnet-xxx ./provision-staging-bastion.sh
#
# Prints the created security group ID on success -- pass that as
# application_security_group_id when applying postgres.tf.

set -euo pipefail

: "${VPC_ID:?Set VPC_ID to the VPC created by infra/terraform networking.tf}"
: "${SUBNET_ID:?Set SUBNET_ID to one of the two private subnets created by networking.tf}"
: "${AWS_REGION:?Set AWS_REGION to the region networking.tf was applied in}"

TAG_NAME="${TAG_NAME:-p1-2-staging-bastion}"

echo "Creating bastion security group..." >&2
SG_ID=$(aws ec2 create-security-group \
  --region "$AWS_REGION" \
  --group-name "${TAG_NAME}-sg" \
  --description "Temporary P1-2 staging validation bastion. No inbound rules: reached via SSM only." \
  --vpc-id "$VPC_ID" \
  --query 'GroupId' --output text)

# Explicitly no ingress rules are added. SSM Session Manager needs only
# outbound HTTPS to the SSM service endpoints (the default egress rule
# every new security group has already permits this), never an inbound
# rule of any kind.
echo "Security group created: $SG_ID (no inbound rules)" >&2

AMI_ID=$(aws ec2 describe-images \
  --region "$AWS_REGION" \
  --owners amazon \
  --filters "Name=name,Values=al2023-ami-*-x86_64" "Name=state,Values=available" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' --output text)

INSTANCE_PROFILE_NAME="${TAG_NAME}-profile"
ROLE_NAME="${TAG_NAME}-role"

echo "Creating IAM role for SSM + Secrets Manager read access..." >&2
aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
  }' >/dev/null

aws iam attach-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

# Secrets Manager read access is scoped narrowly by the caller after
# the RDS instance exists (its secret ARN is only known post-apply);
# this script only creates the role shell. See
# docs/production/STAGING_ENVIRONMENT_PROVISIONING.md section 3 --
# attach a resource-scoped GetSecretValue policy for exactly the RDS
# master credential's own secret ARN before running the validation
# script, never a wildcard "secretsmanager:*" grant.

aws iam create-instance-profile --instance-profile-name "$INSTANCE_PROFILE_NAME" >/dev/null
aws iam add-role-to-instance-profile \
  --instance-profile-name "$INSTANCE_PROFILE_NAME" \
  --role-name "$ROLE_NAME"

echo "Waiting for instance profile propagation..." >&2
sleep 10

echo "Launching bastion instance..." >&2
INSTANCE_ID=$(aws ec2 run-instances \
  --region "$AWS_REGION" \
  --image-id "$AMI_ID" \
  --instance-type t3.micro \
  --subnet-id "$SUBNET_ID" \
  --security-group-ids "$SG_ID" \
  --iam-instance-profile "Name=$INSTANCE_PROFILE_NAME" \
  --no-associate-public-ip-address \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TAG_NAME},{Key=purpose,Value=p1-2-staging-validation},{Key=temporary,Value=true}]" \
  --metadata-options "HttpTokens=required,HttpEndpoint=enabled" \
  --query 'Instances[0].InstanceId' --output text)

echo "Bastion instance launched: $INSTANCE_ID" >&2
echo "Waiting for instance to reach running state..." >&2
aws ec2 wait instance-running --region "$AWS_REGION" --instance-ids "$INSTANCE_ID"

echo "" >&2
echo "Done. Record these for teardown-staging.sh:" >&2
echo "  BASTION_INSTANCE_ID=$INSTANCE_ID" >&2
echo "  BASTION_SECURITY_GROUP_ID=$SG_ID" >&2
echo "  BASTION_IAM_ROLE_NAME=$ROLE_NAME" >&2
echo "  BASTION_INSTANCE_PROFILE_NAME=$INSTANCE_PROFILE_NAME" >&2
echo "" >&2
echo "application_security_group_id for staging.tfvars:" >&2
echo "$SG_ID"
