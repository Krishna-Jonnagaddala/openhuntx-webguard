# Lab Validation: OWASP Juice Shop

## Status

Complete. This validates that WebGuard's passive detection engine produces correct, evidence-backed, CWE-mapped findings against a known-vulnerable application, before those same checks are trusted against a real owned site.

## Setup

- Target: `bkimminich/juice-shop:v20.1.1` (pinned by digest, `infra/compose/compose.lab.yml`), bound to `127.0.0.1:3000` only, hardened container (`cap_drop: ALL`, `no-new-privileges`, resource limits).
- Started via `docker compose -f infra/compose/compose.lab.yml up -d`; healthcheck reported `healthy`.

## Part 1: Integration suite (service/API plumbing)

```
WEBGUARD_RUN_INTEGRATION=1 WEBGUARD_LAB_TARGET=http://127.0.0.1:3000/ \
python -m unittest discover -s tests/integration -p "test_*.py" -v
```

**14/14 tests passed**, exercising the full stack against the live container: crawling, checkpoint resume, TLS-analyzer HTTPS-skip logic, HTML analyzer, professional report rendering, authenticated job submission/scheduling/pagination through the API layer, and, notably, both directions of scope enforcement: `test_commercial_policy_blocks_local_target` (confirms the scanner refuses `127.0.0.1` under normal commercial policy) and `test_lab_policy_allows_and_reaches_local_target` (confirms `--lab` mode correctly reaches it only with an explicit allowlist), plus `test_issue_bind_revoke_and_fail_closed` for TrustScan permits.

This was previously documented as passing in the Phase 4/5 checkpoint docs; re-run here independently rather than trusted from documentation, per this session's own audit discipline.

## Part 2: Standalone CLI scan (actual findings)

```
webguard scan http://127.0.0.1:3000/ --lab --allow-host 127.0.0.1 \
  --crawl --crawl-max-pages 10 --crawl-max-depth 1
```

**Result:** completed, 1 page, 3 findings, coverage 80% (8 of 40 checks correctly skipped, not silently dropped; see below).

| Finding | Severity | CWE | Evidence |
|---|---|---|---|
| Content-Security-Policy header missing | Medium | CWE-693 | No `Content-Security-Policy` header observed |
| CORS permits requests from any origin | Low | CWE-942 | `Access-Control-Allow-Origin: *` |
| Referrer-Policy header missing | Low | CWE-200 | No `Referrer-Policy` header observed |

All three match Juice Shop's documented, intentional misconfigurations (it is well known for a wildcard CORS policy and no CSP). CWE mappings are correct: CWE-693 (Protection Mechanism Failure) for the missing CSP, CWE-942 (Overly Permissive Cross-domain Whitelist) for the CORS wildcard, CWE-200 (Exposure of Sensitive Information) for missing Referrer-Policy.

**Skipped checks were explicit, not silent.** The target is HTTP, not HTTPS, so 8 HTTPS-only checks (HSTS, TLS/certificate analysis ×7) were skipped with a stated reason (`"HSTS applies only to HTTPS responses..."` etc.) rather than either failing or silently reporting 100% coverage. This is a positive finding about the coverage-accounting design, not a gap.

**Single page reached**, same known limitation as the InternStack scan: Juice Shop is an Angular SPA and WebGuard does not execute JavaScript, so client-side-rendered routes were not discovered from the root page.

## Conclusion

Both the plumbing (permits, scheduling, pagination, checkpoints) and the actual passive-detection output (real findings, correct CWE mapping, honest coverage accounting) are verified working against a live, known-vulnerable target, independent of and prior to any scan of a real owned site. This satisfies the "prove the scanner actually detects and correctly maps vulnerabilities" requirement before trusting the same engine's output against `internstack.in` (see `docs/audit/internstack-first-production-scan.md`).

No active-detection findings (injection, XSS, SSRF, auth bypass, IDOR: the classes Juice Shop is actually designed to exercise) are present here because that engine does not exist yet (`docs/CWE_COVERAGE.md`, "Planned"). This lab only validates the passive engine that is currently implemented.
