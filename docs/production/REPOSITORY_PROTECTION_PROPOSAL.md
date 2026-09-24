# Repository protection proposal (M19)

## Status

**A proposal only. Nothing in this document has been applied.** `gh api repos/Krishna-Jonnagaddala/openhuntx-webguard/branches/main/protection` returns 404 (`Branch not protected`) and `.../rulesets` returns `[]`, confirmed again on 2026-09-24, immediately before writing this. Repository settings are outside this session's standing authorization; every command below is exact and ready to run, but running any of it needs the owner's explicit say-so.

## What was verified before writing this

- **GitHub's current REST API fields**, fetched directly rather than assumed from training-data-era documentation: classic branch protection's `required_status_checks`/`required_pull_request_reviews`/`enforce_admins`/`restrictions` shape, and the newer repository-ruleset API's `bypass_actors` field, which classic branch protection has no equivalent for.
- **The exact 10 required check names**, read from this session's own live CI runs on PR #75 and #76 (`gh pr checks`), not a guessed or combined shorthand for the Python version matrix: `Frontend build, lint, and unit tests`, `Terraform validation and IaC security scan`, `Security gates`, `Unit tests: Python 3.11.15`, `Unit tests: Python 3.12.13`, `Unit tests: Python 3.13.14`, `Unit tests: Python 3.14.6`, `PostgreSQL repository integration`, `Authorised Juice Shop integration`, `Frontend browser E2E (Playwright)`. All four Python versions are named individually below: a single collapsed "Unit tests" entry would not match any real check name and the requirement would never actually gate anything.
- **Workflow token permissions**, checked directly rather than assumed clean because SHA-pinning was already fixed: `.github/workflows/ci.yml` sets `permissions: contents: read` once, at the workflow level, with no job overriding it to anything broader (verified: zero `permissions:` blocks anywhere else in the file). The repository's own default (`GET /actions/permissions/workflow`) is `default_workflow_permissions: read`, `can_approve_pull_request_reviews: false`. The workflow's own triggers are `push` (to `main` only), `pull_request`, and `workflow_dispatch`: no `pull_request_target`, no `workflow_run`, neither of which this repository's single workflow file has ever used. **This is already correct and needs no change**; it is reported here because "check workflow token permissions" was asked for explicitly, not because there is a gap to close.

## Three separate decisions, not one bundled setting

The three items below are independent. Approving one does not require approving the others, and this repository's own single-maintainer shape makes that independence load-bearing, not a formality:

### 1. Required status checks + force-push/deletion protection (recommended, low risk)

A repository **ruleset** (not classic branch protection) targeting `refs/heads/main`, with a `bypass_actors` entry for the owner set to `bypass_mode: "always"`. This is the reason a ruleset is proposed instead of classic branch protection: classic protection's `enforce_admins: true` would block the owner from ever bypassing a required check even in a genuine emergency, with no override; a ruleset's bypass actor keeps every rule enforced for anyone else (there is no one else today, but this also does not change if that stops being true) while leaving the owner a documented, audit-logged escape hatch rather than an implicit one.

```bash
gh api --method POST repos/Krishna-Jonnagaddala/openhuntx-webguard/rulesets --input - <<'EOF'
{
  "name": "main-required-checks",
  "target": "branch",
  "enforcement": "active",
  "conditions": {
    "ref_name": { "include": ["refs/heads/main"], "exclude": [] }
  },
  "bypass_actors": [
    { "actor_id": 139624944, "actor_type": "User", "bypass_mode": "always" }
  ],
  "rules": [
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": true,
        "required_status_checks": [
          { "context": "Frontend build, lint, and unit tests" },
          { "context": "Terraform validation and IaC security scan" },
          { "context": "Security gates" },
          { "context": "Unit tests: Python 3.11.15" },
          { "context": "Unit tests: Python 3.12.13" },
          { "context": "Unit tests: Python 3.13.14" },
          { "context": "Unit tests: Python 3.14.6" },
          { "context": "PostgreSQL repository integration" },
          { "context": "Authorised Juice Shop integration" },
          { "context": "Frontend browser E2E (Playwright)" }
        ]
      }
    },
    { "type": "non_fast_forward" },
    { "type": "deletion" }
  ]
}
EOF
```

`actor_id: 139624944` is the owner's own numeric GitHub user ID (`gh api user -q .id`, confirmed this session), not a placeholder. `non_fast_forward` blocks a force-push to `main`; `deletion` blocks deleting the branch. Neither requires a PR or a review from anyone; both apply to the owner too, except through the bypass actor above.

**Risk if applied as written**: essentially none. It only requires that the already-passing 10 checks keep passing before a merge to `main`, which is already true of every recent PR in this session, and gives the owner an explicit, logged bypass rather than removing enforcement from admins entirely.

### 2. Required pull-request review (separate decision, real cost on a solo-maintainer repo)

Classic branch protection's `required_pull_request_reviews.required_approving_review_count` (or the ruleset equivalent, `pull_request` rule type with `required_approving_review_count`) would require a second person's approval before any PR can merge. **On a single-collaborator repository, this blocks the owner's own merges entirely**, unless a bypass actor is also added for this specific rule (which then makes the requirement close to symbolic for the one collaborator it would apply to) or a second maintainer is added first. This is not proposed as part of item 1 above because it is a materially different trade-off: item 1 costs nothing an owner would notice in normal use; this one does, immediately, on the very next PR. If a second maintainer is added later, this becomes straightforward to add without touching item 1's rule at all (rulesets are additive; a second ruleset or an added rule handles it).

### 3. Actions policy: SHA pinning (recommended, zero risk given current state)

```bash
gh api --method PUT repos/Krishna-Jonnagaddala/openhuntx-webguard/actions/permissions \
  -f enabled=true -f allowed_actions=all -F sha_pinning_required=true
```

Every third-party action this repository's one workflow file uses (`actions/checkout`, `actions/setup-node`, `actions/setup-python`, `actions/upload-artifact`, `hashicorp/setup-terraform`) is already pinned to a full commit SHA (verified by grep against `.github/workflows/ci.yml`, not assumed from the earlier M17 audit). Turning this flag on enforces that going forward with zero effect on any workflow run that exists today. `allowed_actions=all` is left unchanged deliberately: narrowing it to `selected` would require enumerating and allow-listing all five actions above by name, a real additional restriction with its own maintenance cost (a new action added later needs an explicit allow-list edit before its workflow run will even start), proposed here as available but not recommended alongside the free win of SHA pinning.

## What this document does not do

It does not add required PR review by default (item 2 is presented, not recommended, for the stated reason). It does not narrow `allowed_actions` to `selected` (also presented, not recommended, in item 3). It does not apply anything: every command above needs to be run by, or with the explicit go-ahead of, the repository owner.
