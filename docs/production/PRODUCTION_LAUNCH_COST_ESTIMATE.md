# Production launch cost estimate (distinct from the staging validation sandbox)

## Status

**An estimate only. No AWS resource has been created for this document.** Every figure below comes from AWS's own official Price List API offer files for `eu-west-2`, downloaded fresh this session (2026-09-24), not a generic or remembered rate.

## This is not the same thing as PR #71's cost estimate

PR #71 (`docs/production/STAGING_ENVIRONMENT_PROVISIONING.md`) prices a **temporary, single-purpose validation sandbox**: one RDS instance and one throwaway EC2 bastion, provisioned for a few hours to run the existing Postgres integration test suite and the RLS `ENABLE`/`FORCE` activation procedure against a real, non-disposable database, then torn down. Its own numbers (~$2.30 for a one-day window; ~$67-75/month only if teardown is forgotten, dominated by its own NAT Gateway) are correct as written and are not revised here: independently re-checked this session against the same official `eu-west-2` NAT Gateway rate ($0.05/hour) PR #71 itself already uses, and the two match.

This document prices something PR #71 explicitly does not: **the actual application running in production**, continuously, for real customers. Conflating the two would understate the real launch cost by roughly 50x (PR #71's sandbox costs $2.30 for a day of use; the numbers below are a recurring monthly bill).

## What actually needs to run, and what this estimate covers

Cross-referenced against `docs/production/PROVIDER_EVALUATION.md`'s own recommended stack and this session's own architecture docs, so nothing already designed is silently left out of the number:

| Component | Covered here? | Notes |
|---|---|---|
| Application compute (API + worker) | Yes | ECS Fargate, 2 tasks |
| Callback receiver (separate process, `docs/production/CALLBACK_SERVICE_DEPLOYMENT.md`) | Yes, as an add-on | A third Fargate task; not in the headline number below since not every deployment shape needs it running continuously at launch, but real if it does |
| Reverse proxy / TLS termination | Partially | An Application Load Balancer is costed (the actual internet-facing hop); the `infra/nginx/api-sidecar.conf` sidecar validated this session runs *inside* the same Fargate task, at no separate infrastructure cost, per `docs/production/PUBLIC_EDGE_SECURITY.md`'s own topology (`Cloudflare -> Load Balancer -> [sidecar] -> API process`) |
| Artifact storage (S3) | Yes | Small at launch scale, correctly a rounding error |
| Signing key (KMS) | Yes | One asymmetric key, low request volume |
| Database backups | Yes, included | RDS automated backups are included in the RDS line, not a separate charge, up to the provisioned storage size |
| Transactional email | Yes, separately | Postmark, not an AWS charge |
| Edge/WAF (Cloudflare) | Yes, separately | Not an AWS charge; see below, this is the single biggest surprise in this estimate |
| Monitoring/alerting | **No** | Deliberately not costed: `docs/production/DEPLOYMENT_ROLLBACK.md`'s 2026-09-24 monitoring-status section found nothing currently configured to monitor, so there is nothing yet to price. Grafana Cloud is named in `PROVIDER_EVALUATION.md` as the intended tool but was never priced against a real usage estimate; that is a real, separate omission from this number, not an oversight in this document specifically |

## AWS-native monthly cost, small scale (eu-west-2, on-demand, under 10,000 requests/day)

| # | Item | Monthly |
|---|---|---|
| 1 | RDS PostgreSQL `db.t4g.micro`, single-AZ, 20GB gp3, 7-day backups | $15.80 |
| 2 | ECS Fargate, 2 tasks (API+sidecar, worker), 0.25 vCPU / 0.5GB each | $20.72 |
| 3 | Application Load Balancer (base + LCU + 2 public IPv4) | $26.75 |
| 4 | S3 (5GB artifacts, light request volume) | $0.17 |
| 5 | KMS (1 asymmetric signing key, ~500 requests/month) | $1.01 |
| 6 | NAT Gateway (1 AZ, hourly + Elastic IP + light data processing) | $41.15 |
| 7 | Secrets Manager, ECR, CloudWatch Logs baseline | ~$2.70 |
| | **AWS subtotal** | **~$108/month** |

Adding the callback receiver as a third continuously-running Fargate task: **+$10.36/month** (+$14.01 if it also needs its own public IP rather than routing through the same NAT).

**The NAT Gateway is not avoidable via VPC endpoints here**, and this is worth stating plainly since it is the single largest line item: endpoints only reach AWS's own services, and the WebGuard worker's entire job is reaching *customer-owned sites on the public internet*, which no VPC endpoint can route to. Pricing the endpoint-only alternative for comparison (five interface endpoints across two AZs) comes to roughly $80/month, more than the NAT itself, while still leaving the actual scanning traffic with nowhere to go. The only real NAT-free option is running the Fargate tasks in public subnets with individually-assigned public IPs, which trades the NAT's fixed egress IP (customers can allowlist one stable scanning source address) for a worker whose outbound IP changes on every task restart, a real capability loss for a security-scanning product, not a free cost saving.

## Outside the AWS bill

- **Postmark** (transactional email): $15/month (the free tier's 100 emails/month is not enough for production signups/password resets).
- **Cloudflare**: this is the estimate's biggest source of range. `infra/terraform/cloudflare.tf` (not yet applied) configures the Cloudflare Managed and OWASP Core managed WAF rulesets plus 3 rate-limiting rules; the Managed/OWASP rulesets need at least the Pro plan, and Pro's rate-limiting-rule allowance is 2, one short of what's already configured. As configured today, that needs **Business ($200-250/month)**; consolidating to 2 rate-limiting rules would fit **Pro ($20-25/month)**. This is a real, ten-to-one cost swing driven entirely by a Terraform file already in this repository, and is worth an explicit decision before launch, not a default.

## Total

- **AWS + Postmark + Cloudflare Pro (rules consolidated to fit): ~$148/month.**
- **AWS + Postmark + Cloudflare Business (current `cloudflare.tf` as written): ~$373/month.**

Neither figure includes monitoring/alerting tooling cost (Grafana Cloud or equivalent), since none has been sized against real usage yet, and neither includes the callback-receiver add-on above.

## Retained resources and teardown

If this stack is ever torn down: the KMS key(s) enter a mandatory 7-30 day `PendingDeletion` window regardless of the `terraform destroy` timing (same mechanic `docs/production/TRUSTSCAN_KMS_REAL_AWS_VERIFICATION_PLAN.md` documents for the separate verification key); the RDS instance's final snapshot persists until manually deleted (`skip_final_snapshot = false` in `postgres.tf`); any Elastic IP allocated for the NAT Gateway or the ALB stops being billed only once explicitly released, not merely once the resource using it is deleted, if Terraform's own dependency graph leaves it allocated.

## Proposed spending ceiling

Not this document's decision to make unilaterally, but a concrete number to react to rather than an open-ended one: **$200/month**, covering the AWS subtotal, Postmark, and Cloudflare Pro with rules consolidated, with headroom for the callback-receiver task. Exceeding it (most likely by keeping Cloudflare on Business) should be an explicit, separate approval, not something that happens by leaving `cloudflare.tf` unreviewed before its first apply.

## What this document does not cover

Real production request volume beyond the small-scale assumption stated at the top (10,000 requests/day); Grafana Cloud or any other monitoring tool's own cost, since none is sized yet; multi-region or DR costs (`eu-west-1` is named as a DR region in `PROVIDER_EVALUATION.md` but never costed anywhere); RDS storage growth over time (20GB is a launch-scale assumption, not a ceiling).
