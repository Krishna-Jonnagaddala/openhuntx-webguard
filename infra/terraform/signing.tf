# TrustScan permit signing key (Slice 12 requirement 2). AWS KMS has no
# Ed25519 KeySpec -- see signing.py's module docstring and this
# directory's README for the full explanation. This key is
# ECC_NIST_P256 / SIGN_VERIFY, the AWS-side resource a
# `KmsSigningProvider` would call with SigningAlgorithm=ECDSA_SHA_256.
# Provisioning it is not the same decision as switching TrustScan's
# active signer to it -- that remains a separate, explicit,
# not-yet-made decision.

resource "aws_kms_key" "trustscan_permit_signing" {
  description              = "TrustScan permit/safety-receipt signing key (ECDSA_SHA_256 -- AWS KMS has no Ed25519 KeySpec)."
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30

  # No automatic rotation for asymmetric signing keys -- AWS KMS does
  # not support it for SIGN_VERIFY keys. Key rotation for this key
  # means provisioning a *new* aws_kms_key and following the
  # active/retired-key lifecycle already built in
  # webguard_api.signing.SigningKeyRegistry, not an in-place rotation
  # of this resource.
  enable_key_rotation = false

  tags = {
    Name        = "webguard-${var.environment_name}-trustscan-signing"
    Environment = var.environment_name
    ManagedBy   = "terraform"
    Purpose     = "trustscan-permit-signing"
  }
}

resource "aws_kms_alias" "trustscan_permit_signing" {
  name          = "alias/webguard-${var.environment_name}-trustscan-signing"
  target_key_id = aws_kms_key.trustscan_permit_signing.key_id
}
