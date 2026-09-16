# Production Provider Evaluation

## Status

A comparative evaluation of realistic infrastructure providers against the requirements in `docs/production/INFRASTRUCTURE_REQUIREMENTS.md`. **No account has been created and nothing has been provisioned.** This is a recommendation for a human decision, not an action taken. Evaluation criteria throughout: security posture, UK/EU region availability, price at small-to-mid scale, scalability headroom, operational burden, lock-in risk, backup/restore maturity, and compliance path (SOC 2 / ISO 27001 / GDPR data-processing terms).

## PostgreSQL

| Provider | Security | UK/EU regions | Price (small) | Scalability | Ops burden | Lock-in | Backup/restore | Compliance |
|---|---|---|---|---|---|---|---|---|
| **AWS RDS/Aurora PostgreSQL** | Strong (VPC isolation, KMS-encrypted at rest, IAM auth option) | Yes (eu-west-1 Dublin, eu-west-2 London) | Moderate-high; Aurora scales cost with usage | Excellent (Aurora read replicas, auto-scaling storage) | Low (fully managed) | Moderate (Aurora-specific extensions if used; standard PG otherwise) | Excellent (PITR, automated snapshots) | SOC 2, ISO 27001, GDPR DPA available |
| **Supabase (managed Postgres)** | Good (managed, but younger platform, smaller security track record) | Yes (EU region option) | Low at small scale, generous free tier | Good, but scaling ceiling lower than hyperscalers | Very low (includes auth/storage/realtime bundled, mostly unused here) | Higher (bundled platform features encourage coupling) | Good (daily backups on paid tiers) | SOC 2 in progress historically; verify current status before committing |
| **Self-hosted on a VPS (e.g. Hetzner) with pgBackRest** | Depends entirely on operator diligence | Yes (Hetzner has German/Finnish DCs) | Lowest raw cost | Manual scaling | High (operator owns patching, failover, backups) | Lowest (plain Postgres, fully portable) | Depends on operator setup quality | No inherited compliance certifications; operator must build the whole program |

**Recommendation**: AWS RDS PostgreSQL (or Aurora if read-scaling becomes a real need) in `eu-west-2` (London) or `eu-west-1` (Dublin), given UK/EU data residency and the maturity of its backup/PITR story matter more than raw price at this project's likely scale.

## Redis / job queue

| Provider | Security | UK/EU regions | Price | Scalability | Ops burden | Lock-in | Backup/restore | Compliance |
|---|---|---|---|---|---|---|---|---|
| **AWS ElastiCache for Redis** | Strong (VPC, encryption in transit/at rest, IAM) | Yes | Moderate | Excellent (cluster mode) | Low | Moderate (AWS-managed failover semantics) | Good (snapshot to S3) | Same umbrella as RDS |
| **Upstash (serverless Redis)** | Good | Yes (EU regions) | Very low at low volume (pay-per-request) | Good, scales to zero | Very low | Low (Redis-protocol compatible) | Adequate | SOC 2 |
| **Self-hosted Redis** | Depends on operator | Yes | Lowest | Manual | High | Lowest | Depends on operator | None inherited |

**Recommendation**: AWS ElastiCache if already committed to AWS for RDS (simpler network topology, one VPC); Upstash is a reasonable lower-ops alternative if avoiding always-on Redis cost is a priority given this project's traffic is currently zero/pre-launch.

## Object storage

| Provider | Security | UK/EU regions | Price | Scalability | Ops burden | Lock-in | Backup/restore | Compliance |
|---|---|---|---|---|---|---|---|---|
| **AWS S3** | Strong (bucket policies, KMS, Object Lock for immutability) | Yes | Low, pay-per-use | Effectively unlimited | Very low | Moderate (S3 API is a de facto standard, but lifecycle/IAM policies are AWS-specific) | Excellent (versioning, cross-region replication) | SOC 2, ISO 27001, GDPR DPA |
| **Cloudflare R2** | Good | Yes (EU jurisdiction option) | Lower than S3, **zero egress fees** | Good | Very low | Lower (S3-API-compatible) | Adequate (versioning available) | SOC 2 |

**Recommendation**: S3 if staying inside AWS for RDS/ElastiCache anyway (single-vendor networking simplicity); R2 is genuinely attractive if artifact/report download volume grows, since egress cost is the one place S3 gets expensive for a security-report-download-heavy product.

## Containers / workers

| Provider | Security | UK/EU regions | Price | Scalability | Ops burden | Lock-in | Backup/restore | Compliance |
|---|---|---|---|---|---|---|---|---|
| **AWS ECS Fargate** | Strong (IAM task roles, no host access needed) | Yes | Pay-per-task, no idle-node waste | Excellent | Low (no cluster/node management) | Moderate | N/A (stateless workers) | SOC 2/ISO umbrella |
| **Fly.io** | Good | Yes (London, Amsterdam, Frankfurt regions) | Competitive, simple pricing | Good, easy multi-region | Very low (deploy-focused DX) | Low-moderate | N/A | Smaller compliance footprint; verify before enterprise sales |
| **Kubernetes (self-managed or EKS)** | Strong if configured correctly | Yes | Higher baseline cost, more control | Excellent | High (real ongoing K8s expertise required) | Low (portable), but high *effort* lock-in | N/A | Depends on hosting choice |

**Recommendation**: ECS Fargate for the worker fleet: the worker's own architecture (stateless, lease-based, crash-recoverable by design) maps cleanly onto ephemeral task scheduling with no need for Kubernetes's operational complexity at this project's current scale.

## Frontend / API hosting

| Provider | Security | UK/EU regions | Price | Scalability | Ops burden | Lock-in | Backup/restore | Compliance |
|---|---|---|---|---|---|---|---|---|
| **AWS (ALB + ECS/Fargate)** | Strong | Yes | Pay-per-use | Excellent | Low-moderate | Moderate | N/A | SOC 2/ISO umbrella |
| **Vercel (frontend only)** | Good | Yes (EU edge regions) | Low for typical usage | Excellent for static/SSR frontend | Very low | Low for frontend code, but tied to their build pipeline | N/A | SOC 2 |

**Recommendation**: keep the API on the same AWS account as the data layer (network simplicity, IAM-scoped access to RDS/S3 without public exposure); a separate frontend host (Vercel or similar) is fine and common, since the frontend has no direct database access requirement.

## DNS / CDN / WAF

| Provider | Security | UK/EU regions | Price | Scalability | Ops burden | Lock-in | Backup/restore | Compliance |
|---|---|---|---|---|---|---|---|---|
| **Cloudflare** | Strong (WAF, DDoS protection included even on lower tiers, Bot Management available) | Global anycast, EU jurisdiction option (Data Localization Suite) | Free/low tier is genuinely usable; WAF/enterprise features cost more | Excellent | Very low | Low (DNS/CDN are portable) | SOC 2, ISO 27001 |
| **AWS Route53 + CloudFront + WAF** | Strong | Yes | Higher than Cloudflare for equivalent WAF coverage | Excellent | Moderate (more configuration surface) | Higher (tightly AWS-specific WAF rule syntax) | N/A | SOC 2/ISO umbrella |

**Recommendation**: Cloudflare: this is also the natural home for the **SSRF callback hostname** (`callback.openhuntx.com`): Cloudflare's proxy can front the callback receiver with rate limiting and abuse controls without WebGuard needing to build that layer itself, while still forwarding the raw request path (containing the correlation token) through untouched.

## KMS / secrets

| Provider | Security | UK/EU regions | Price | Scalability | Ops burden | Lock-in | Backup/restore | Compliance |
|---|---|---|---|---|---|---|---|---|
| **AWS KMS + Secrets Manager** | Strong (HSM-backed, IAM-scoped, automatic rotation support) | Yes | Low per-key/per-secret cost | Excellent | Low | Moderate-high (KMS key policies are AWS-specific; migrating signing keys off KMS later is nontrivial) | Key material itself is never exportable by design (this is a feature, not a gap) | SOC 2, ISO 27001, FIPS 140-2 validated HSMs available |
| **HashiCorp Vault (self-hosted or HCP Vault)** | Strong, but only as strong as the deployment | Yes (HCP Vault has EU regions) | Higher (Vault itself needs hosting/ops even as HCP) | Excellent | Moderate-high | Lower (portable secrets engine) | Good, operator-configured | Depends on hosting |

**Recommendation**: AWS KMS for the TrustScan permit signing key specifically (this is exactly the "KMS/HSM-backed key custody, versions, rotation, revocation" requirement `docs/THREAT_MODEL.md` already states). This is the single highest-priority infrastructure item given the current local-file signing key is the weakest link in the permit-integrity chain today.

**Slice 12 correction**: this recommendation needs one caveat this table did not previously carry: **AWS KMS has no Ed25519 `KeySpec`** (only RSA and NIST/SECG elliptic curves), so "AWS KMS for the TrustScan permit signing key" necessarily means an algorithm change (Ed25519 → ECDSA_SHA_256), not a like-for-like custody upgrade of the existing Ed25519 key. `apps/api/src/webguard_api/signing.py`'s `KmsSigningProvider` is built against this reality honestly (targets `ECDSA_SHA_256`, never claims Ed25519 compatibility) but is not wired in as the active signer: an actual algorithm migration is a separate, explicit decision this evaluation does not make. If genuine HSM-backed Ed25519 custody (not just KMS custody of *some* algorithm) is the actual requirement, **AWS CloudHSM** is the correct recommendation instead of KMS: it is a general-purpose HSM reachable via PKCS#11 and does support Ed25519, at the cost of materially higher operational complexity (CloudHSM requires cluster management KMS does not) than the KMS recommendation above assumed.

**Correction, 2026-09-15: the "AWS KMS has no Ed25519 KeySpec" premise above is now out of date.** AWS added `ECC_NIST_EDWARDS25519` as a KMS asymmetric signing key spec, generally available since 2025-11-07 (before this document's own Slice 12 note was written). KMS can now sign Ed25519 directly (`ED25519_SHA_512`, `MessageType:RAW`), so a like-for-like custody upgrade of the existing Ed25519 key is possible without the CloudHSM path this correction previously pointed to. Nothing in this codebase uses that key spec yet: `KmsSigningProvider` still targets `ECDSA_SHA_256` only, and no live KMS signing of any kind has been tested by this project. See `docs/production/TRUSTSCAN_PRODUCTION_SIGNING.md`'s own 2026-09 correction for the full reassessment of what this means for the CloudHSM recommendation there; this table's job is to flag the premise change, not to re-pick a provider.

## Observability

| Provider | Security | UK/EU regions | Price | Scalability | Ops burden | Lock-in | Backup/restore | Compliance |
|---|---|---|---|---|---|---|---|---|
| **AWS CloudWatch** | Adequate, IAM-scoped | Yes | Included baseline, scales with volume | Good | Low (native integration) | High (CloudWatch query language is AWS-specific) | N/A | SOC 2/ISO umbrella |
| **Grafana Cloud (metrics/logs/traces)** | Good | Yes (EU stack option) | Free tier usable for small scale, then per-metric | Excellent | Low | Low (Prometheus/OpenTelemetry-based, portable) | N/A | SOC 2 |

**Recommendation**: Grafana Cloud with OpenTelemetry instrumentation from day one: this avoids the CloudWatch lock-in and gives a portable path if infrastructure ever moves off AWS partially or fully; the runtime-safety engine's existing before/after-request hooks are a natural, already-built instrumentation point.

## Email

| Provider | Security | UK/EU regions | Price | Scalability | Ops burden | Lock-in | Compliance |
|---|---|---|---|---|---|---|---|
| **AWS SES** | Good | Yes | Very low | Excellent | Low | Moderate | SOC 2/ISO umbrella |
| **Postmark** | Good, transactional-email-focused (better deliverability reputation management) | Yes (EU sending option) | Slightly higher than SES but simpler | Good | Very low | Low | SOC 2 |

**Recommendation**: Postmark for transactional email (account verification, job-completion, security notifications): deliverability reputation matters disproportionately for a security-tool vendor whose emails must not land in spam, and Postmark's focus on transactional-only sending (no marketing-blast reputation risk) is a better fit than SES's general-purpose posture.

## Recommended stack (single coherent recommendation)

**AWS** (`eu-west-2` London primary, `eu-west-1` Dublin as DR) as the core: RDS PostgreSQL, ElastiCache Redis, S3, ECS Fargate for workers and the API, KMS for the permit signing key. **Cloudflare** in front for DNS/CDN/WAF and as the callback-hostname proxy. **Grafana Cloud** for observability (avoiding CloudWatch lock-in). **Postmark** for transactional email.

Rationale for a single-cloud-plus-two-specialists shape rather than either "everything on one hyperscaler" or "best-of-breed everywhere": the data layer (RDS/ElastiCache/S3/KMS/ECS) genuinely benefits from being in one VPC with IAM-scoped access between services: splitting the database and compute across providers would add real operational and security-boundary complexity for no benefit at this project's scale. Cloudflare and Grafana are added specifically where they solve a problem AWS's native offering solves less well or more expensively (WAF/DDoS at the edge, portable observability) without touching the data layer's network boundary at all. This is not licensing indecision: each vendor was chosen where it is the better fit only.

**Why not GCP or Azure**: no material differentiator was found for this project's specific requirements (UK/EU regions, managed Postgres/Redis, KMS-backed signing) that would justify evaluating a second full hyperscaler stack from scratch; AWS's `eu-west-2` (London) region specifically gives strong UK data-residency positioning that matters if UK enterprise customers are a target market, which GCP's/Azure's UK regions also offer but without a clear advantage over AWS here.

**What this recommendation does not do**: create any account, provision any resource, or commit to any pricing tier. It is a starting point for a human decision, to be revisited once real usage/traffic patterns exist to validate the cost assumptions above.
