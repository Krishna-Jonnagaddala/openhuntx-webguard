# OpenHuntX WebGuard Product Charter

## Product

OpenHuntX WebGuard is a continuous web vulnerability discovery and security-assurance platform for organisations that own or are explicitly authorised to test the assessed systems.

## Mission

Help organisations identify, prioritise, remediate and continuously monitor known and detectable security weaknesses across websites, web applications, APIs and associated software components.

## Core principles

1. Authorization before testing.
2. Safety before scan coverage.
3. Evidence before severity.
4. Reproducibility before automation.
5. Human validation for high-impact findings.
6. Clear limitations rather than absolute security claims.
7. Privacy and data minimisation by design.
8. Complete auditability of customer and scanner actions.
9. Continuous vulnerability intelligence.
10. Actionable remediation rather than vulnerability volume.
11. Cryptographically permissioned execution: no valid TrustScan permit, no scanner network execution.

## Initial customer

The initial customer profile is a small or medium-sized organisation operating a public website, web application or API without a dedicated application-security team.

## Initial product scope

The initial release will provide:

* Domain ownership verification
* Public asset registration
* TLS analysis
* HTTP security-header analysis
* Cookie-security analysis
* Public exposure checks
* Passive web scanning
* Technology inventory
* Known-vulnerability correlation
* Finding prioritisation
* Remediation guidance
* Web and PDF reporting
* Retesting
* Audit records
* Cryptographically signed TrustScan execution permits
* Permit revocation and execution-time revalidation

## Excluded from the initial release

The initial release will not provide:

* Denial-of-service testing
* Password attacks
* Social engineering
* Malware testing
* Persistence
* Data destruction
* Unverified third-party testing
* Autonomous vulnerability exploitation
* Claims that a system is completely secure
* Formal penetration-testing certification

## Product statement

A successful assessment means that no confirmed vulnerabilities were identified within the authorised scope, test coverage, assessment configuration and intelligence available at the recorded assessment time.

It does not mean that the assessed system is free from every possible vulnerability.

## Authorization requirement

No scan may begin until the customer has:

* Registered the target;
* Verified control of the target;
* Accepted the applicable testing terms;
* Selected the permitted assessment level; and
* Confirmed that any necessary third-party permission has been obtained; and
* Received a valid TrustScan permit that narrows the approved execution policy.

## Success criteria

The product will be considered commercially ready only when it can:

* Reliably enforce scan scope;
* Prevent access to prohibited network ranges;
* Isolate scanner workers;
* Produce repeatable findings;
* Demonstrate finding evidence;
* Minimise duplicate findings;
* Record complete scan audit trails;
* Protect customer credentials and scan data;
* Cancel running scans safely;
* Pass an independent security assessment; and
* Clearly communicate assessment limitations.
