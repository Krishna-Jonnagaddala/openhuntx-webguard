# TrustScan permit/receipt signing key custody -- CloudHSM v2 (Slice 18
# requirement 1). This is the AWS-side resource behind
# `build_cloudhsm_signing_provider_from_env()`
# (apps/api/src/webguard_api/signing_service.py) and the recommended
# production direction from docs/production/TRUSTSCAN_PRODUCTION_SIGNING.md:
# a CloudHSM-backed Ed25519 key, reached only through the dedicated
# TrustScan Signing Service (signing_service.py's narrow HTTP interface
# -- sign/get_active_key_id/get_public_key, nothing else), never
# directly by the API or worker processes (requirement 2).
#
# Provisioning this resource is not the same decision as running the
# signing service against it -- exactly like signing.tf's KMS key,
# this is a prerequisite an operator provisions before making that
# separate, explicit choice (WEBGUARD_SIGNING_PROVIDER=cloudhsm_signing_service
# on the signing service; see docs/production/TRUSTSCAN_SIGNING_SERVICE.md).

resource "aws_cloudhsm_v2_cluster" "trustscan_signing" {
  hsm_type   = var.cloudhsm_hsm_type
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name        = "webguard-${var.environment_name}-trustscan-signing"
    Environment = var.environment_name
    ManagedBy   = "terraform"
    Purpose     = "trustscan-permit-signing"
  }
}

# A single HSM is a single point of failure for signing availability
# (not for key material -- CloudHSM clusters keep encrypted key backups
# independent of any one HSM), which is an acceptable v1 trade-off
# given TrustScan permits/receipts are already an internal control, not
# a customer-facing synchronous path with sub-second SLA requirements.
# Add a second `aws_cloudhsm_v2_hsm` in the second private subnet if
# signing availability ever needs to survive a single-AZ HSM failure --
# this is a scaling decision for a future slice, not a v1 requirement.
resource "aws_cloudhsm_v2_hsm" "trustscan_signing" {
  cluster_id = aws_cloudhsm_v2_cluster.trustscan_signing.cluster_id
  subnet_id  = aws_subnet.private[0].id
}

# AWS creates the cluster's security group automatically
# (`security_group_id` is a computed attribute, not an input) --
# this configuration only adds an ingress rule to it, the same pattern
# postgres_ingress_from_application already uses in networking.tf: only
# the signing service's own compute security group may reach the HSM's
# ENI, on the ports the CloudHSM client SDK/PKCS#11 library actually
# uses. Nothing else in this VPC, and nothing on the public Internet,
# is ever permitted to reach it -- this is the network-level half of
# requirement 2's "do not give every API/worker process direct
# unrestricted HSM access": the API and worker security groups are
# never added here at all.
resource "aws_security_group_rule" "cloudhsm_ingress_from_signing_service" {
  type                     = "ingress"
  from_port                = 2223
  to_port                  = 2225
  protocol                 = "tcp"
  security_group_id        = aws_cloudhsm_v2_cluster.trustscan_signing.security_group_id
  source_security_group_id = var.signing_service_security_group_id
  description              = "CloudHSM client/PKCS#11 traffic from the TrustScan Signing Service only -- never from the API or worker security groups."
}

# --- The activation ceremony Terraform cannot express ---
#
# A freshly-created CloudHSM v2 cluster starts in UNINITIALIZED state
# and stays unusable until an operator completes an out-of-band
# ceremony that has no Terraform resource because it inherently
# requires a manual trust decision outside AWS's API:
#
#   1. Read the cluster's CSR from
#      aws_cloudhsm_v2_cluster.trustscan_signing.cluster_certificates[0].cluster_csr
#      (a computed attribute -- already available after apply).
#   2. Sign that CSR with an operator-controlled CA (a self-signed root
#      is the normal choice for a single-cluster deployment like this
#      one) -- this is the actual trust root for everything the cluster
#      will ever sign, so it is a decision Terraform correctly refuses
#      to make on an operator's behalf.
#   3. Call `aws cloudhsmv2 initialize-cluster` (AWS CLI/SDK, not
#      Terraform) with the signed cluster certificate and the signing
#      CA certificate.
#   4. Connect to the now-ACTIVE cluster with `cloudhsm-cli` (or the
#      legacy `cloudhsm_mgmt_util`/`key_mgmt_util`) as the default
#      Crypto Officer, set a real CO password, and create the Crypto
#      User (CU) account the signing service actually authenticates as
#      -- then generate (or import) the Ed25519 key pair under that CU
#      and label it to match WEBGUARD_SIGNING_SERVICE_PKCS11_PRIVATE_KEY_LABEL
#      / _PUBLIC_KEY_LABEL (see signing_service.py).
#
# None of steps 2-4 have an aws_cloudhsm_v2_* Terraform resource --
# this is a genuine, well-documented AWS CloudHSM limitation, not a gap
# in this configuration. This is also exactly why requirement 4's
# signing E2E proof in this slice uses a controlled fake-HSM test
# harness (tests/unit/test_cloudhsm_signing.py,
# tests/integration/test_signing_service_e2e.py) rather than claiming
# real CloudHSM validation: no cluster has been created, and even a
# created cluster could not be exercised by an unattended test run
# without a human completing this ceremony first.
