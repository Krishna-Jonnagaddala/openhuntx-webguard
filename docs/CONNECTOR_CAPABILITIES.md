# Connector Capabilities

Tracks every SOC/Compliance connector's API versions, required permissions, licensing dependencies, live-validation state, and known limitations. Per `docs/audit/OPENHUNTX_THREE_MODULE_PLATFORM_HANDOFF_2026-09.md` section 5: "If a connector lacks credentials, complete its contract, fixtures, permission manifest, failure tests and UI, mark live validation blocked, and continue independent work. Never convert a fixture-backed adapter into a 'production verified' claim."

Live-validation states used below: `not_started`, `contract_designed`, `fixture_tested`, `blocked_on_credentials`, `live_validated`. Only `live_validated` may ever be described as production-proven anywhere in this repository's docs, UI copy, or marketing material.

## SOC connectors

Federated entry point per the handoff section 9.1: begin with Microsoft Sentinel, Defender XDR, and Entra (plus selected Intune/Azure evidence early scenarios need), inventory their APIs separately even where the commercial UI groups them, then expand to Splunk and other SIEMs through tested adapters. The existing SIEM remains authoritative for its own native incidents and query execution until an explicit ownership/migration design says otherwise.

| Connector | API / version | Required permissions | Licensing dependency | State | Limitations |
|---|---|---|---|---|---|
| Microsoft Sentinel | Not yet selected (Log Analytics / Azure Resource Manager REST) | Not yet designed | Requires an Azure Sentinel workspace | `not_started` | No design work started this session |
| Microsoft Defender XDR | Not yet selected (Microsoft Graph Security API) | Not yet designed | Requires Defender XDR licensing | `not_started` | No design work started this session |
| Microsoft Entra | Microsoft Graph API | Not yet designed (expect directory read, sign-in log read, Conditional Access policy read at minimum) | Requires an Entra tenant | `not_started` | No design work started this session |
| Splunk | Not yet selected | Not yet designed | Requires a Splunk deployment | `not_started` | Explicitly sequenced after the Microsoft subset per the handoff |

Every row above needs, before it can move past `contract_designed`: connector manifest (tenant/account binding, delegated vs. application permissions, licence dependencies, regional availability, stable vs. preview endpoints, pagination, incremental cursors, token refresh/revocation, retry policy, `Retry-After` handling, rate limits, backfill limits, deletion semantics, API-version support), a permission manifest, failure-mode tests (source silence, connector outage, parse rejection, clock skew, collection lag, missing fields, query failure), and a UI surface that shows those failure states honestly. None of that exists yet for any connector; this table will grow rows and columns as each one is actually designed, not before.

## Compliance data sources

Compliance's initial assertion families (privileged-role inventory, MFA enforcement, Conditional Access policy mode, emergency accounts, stale privileged accounts, app/service-principal ownership, credential expiry/exposure metadata, endpoint inventory/sensor freshness, log-source health, detection enablement/execution errors, evidence retention settings, vulnerability/remediation aging) read from the same underlying APIs as the SOC connectors above where authoritative APIs support them (handoff section 10.3). No separate connector table is tracked here yet; Compliance assertions will reference the SOC connector table above once both exist, rather than duplicating connector state.

## Review discipline

A generic REST connector wrapper is not evidence of "hundreds of implemented integrations." A workflow-only connection (e.g. a ticketing webhook) cannot substantiate "evidence-capable" coverage of an unrelated security control. Any future addition to this file must name the exact API surface exercised and the exact permission scope requested, not a vendor's marketing name for a product suite.
