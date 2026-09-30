"""Authenticated crawling for authorization resource discovery (Slice 9).

Orchestrates an authenticated same-origin crawl (Slice 5's
`crawl_same_origin`, reused unchanged, with the Slice-7 authentication
mechanism now threaded through it) whose purpose is to legitimately
observe authorization-sensitive resources belonging to one controlled
test identity -- never to guess, enumerate, or brute-force them.

This function performs no detector-specific authentication handling of
its own: authentication is applied exactly once, through
`crawler.crawl_same_origin`'s `authentication_material` parameter,
which threads it through the single shared
`authentication.apply_authentication` mechanism already used by every
other authenticated request path in this codebase. Credential isolation
is structural, not merely tested: each call to this function accepts
exactly one identity's `AuthenticationMaterial` as a plain parameter,
so two calls for two identities can never share, merge, or leak into
each other's requests.

All existing crawler controls (authorization/permit-derived policy,
scope validation, same-origin restriction, DNS/IP validation, page/
depth/request budgets, rate limiting, cancellation, checkpointing,
response limits) are preserved unchanged -- this module adds a resource-
discovery sink and an authentication-health check on top of the
existing `run_passive_crawl_scan` orchestration, it does not bypass or
duplicate any of that orchestration's own safety logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import FrozenSet, Tuple

from webguard_contracts import CrawlCheckpoint

from .authentication import AuthenticationMaterial
from .authorization_resource import AuthorizationResource
from .authorization_resource_discovery import (
    DEFAULT_IDENTIFIER_FIELD_PATTERNS,
    AuthenticatedCrawlStatus,
    AuthenticationHealthCriterion,
    ResourceDiscoveryBudget,
    ResourceDiscoverySink,
)
from .crawl_scan import CheckpointCallback, run_passive_crawl_scan
from .crawler import CrawlCancellationToken, CrawlPolicy
from .passive_scan import DEFAULT_PASSIVE_ANALYZERS
from .retry_policy import RetryPolicy
from .runtime_hooks import AfterRequestHook, BeforeRequestHook
from .safe_http import FetchPolicy
from .scope_validator import ValidatedTarget


@dataclass(frozen=True, slots=True)
class AuthenticatedResourceDiscoveryResult:
    """The outcome of one authenticated resource-discovery crawl for
    exactly one test identity. `resources` never includes anything
    observed on a page classified as authentication-failed/expired."""

    owning_identity: str
    status: AuthenticatedCrawlStatus
    resources: Tuple[AuthorizationResource, ...]
    pages_visited: int
    pages_with_authentication_failure: Tuple[str, ...]


def run_authenticated_resource_discovery_crawl(
    root_target: ValidatedTarget,
    *,
    authentication_material: AuthenticationMaterial,
    owning_identity: str,
    crawl_policy: CrawlPolicy = CrawlPolicy(),
    fetch_policy: FetchPolicy = FetchPolicy(),
    retry_policy: RetryPolicy = RetryPolicy(),
    discovery_budget: ResourceDiscoveryBudget = ResourceDiscoveryBudget(),
    identifier_field_patterns: FrozenSet[str] = DEFAULT_IDENTIFIER_FIELD_PATTERNS,
    endpoint_templates: "dict[str, str] | None" = None,
    authentication_health_criterion: AuthenticationHealthCriterion | None = None,
    scan_id: str | None = None,
    started_at: datetime | None = None,
    cancellation_token: CrawlCancellationToken | None = None,
    resume_checkpoint: CrawlCheckpoint | None = None,
    checkpoint_callback: CheckpointCallback | None = None,
    before_request: BeforeRequestHook | None = None,
    after_request: AfterRequestHook | None = None,
) -> AuthenticatedResourceDiscoveryResult:
    """Run one authenticated crawl dedicated to authorization resource
    discovery for `owning_identity`.

    If `authentication_health_criterion` detects an expired/failed
    session on some page, the crawl is cancelled (via the same
    `cancellation_token` this function threads through
    `run_passive_crawl_scan`, reusing existing cooperative-cancellation
    infrastructure rather than inventing new control flow) as soon as
    the crawler next checks for it -- no resource is ever recorded from
    a page classified unhealthy, and no resource is recorded from any
    page visited after the failure.
    """

    token = cancellation_token or CrawlCancellationToken()
    sink = ResourceDiscoverySink(
        owning_identity=owning_identity,
        budget=discovery_budget,
        field_patterns=identifier_field_patterns,
        endpoint_templates=endpoint_templates or {},
        authentication_health_criterion=authentication_health_criterion,
        cancellation_token=token,
    )

    crawl_result = run_passive_crawl_scan(
        root_target,
        crawl_policy=crawl_policy,
        fetch_policy=fetch_policy,
        retry_policy=retry_policy,
        analyzers=DEFAULT_PASSIVE_ANALYZERS,
        scan_id=scan_id,
        started_at=started_at,
        cancellation_token=token,
        resume_checkpoint=resume_checkpoint,
        checkpoint_callback=checkpoint_callback,
        before_request=before_request,
        after_request=after_request,
        authentication_material=authentication_material,
        resource_discovery=sink,
    )

    return AuthenticatedResourceDiscoveryResult(
        owning_identity=owning_identity,
        status=sink.status,
        resources=sink.resources,
        pages_visited=len(crawl_result.pages),
        pages_with_authentication_failure=sink.pages_with_authentication_failure,
    )


__all__ = [
    "AuthenticatedResourceDiscoveryResult",
    "run_authenticated_resource_discovery_crawl",
]
