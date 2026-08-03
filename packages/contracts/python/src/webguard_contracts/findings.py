"""Versioned, scanner-independent finding contract."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Tuple
from urllib.parse import urlsplit


_RULE_ID = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")
_HTTP_METHOD = re.compile(r"^[A-Z]+$")


class Severity(str, Enum):
    """Technical severity of a security finding."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    """Confidence that a reported issue is genuine."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


class ContractValidationError(ValueError):
    """Controlled failure raised for an invalid contract value."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _text(
    value: str,
    name: str,
    maximum: int,
) -> str:
    """Validate and trim a required text value."""

    if not isinstance(value, str):
        raise ContractValidationError(
            f"{name}_invalid",
            f"{name} must be text.",
        )

    cleaned = value.strip()

    if (
        not cleaned
        or len(cleaned) > maximum
        or "\x00" in cleaned
    ):
        raise ContractValidationError(
            f"{name}_invalid",
            f"{name} is empty, too long, or contains a null byte.",
        )

    return cleaned


def _optional_text(
    value: str | None,
    name: str,
    maximum: int,
) -> str | None:
    """Validate optional text."""

    if value is None:
        return None

    return _text(value, name, maximum)


@dataclass(frozen=True, slots=True, order=True)
class ExternalIdentifier:
    """Identifier supplied by an external standard or database."""

    namespace: str
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "namespace",
            _text(
                self.namespace,
                "identifier_namespace",
                32,
            ).upper(),
        )

        object.__setattr__(
            self,
            "value",
            _text(
                self.value,
                "identifier_value",
                256,
            ),
        )


@dataclass(frozen=True, slots=True)
class Evidence:
    """Non-secret evidence supporting a finding.

    Raw HTTP responses, credentials and sensitive material must be stored
    separately in protected artifact storage.
    """

    summary: str
    artifact_reference: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "summary",
            _text(
                self.summary,
                "evidence_summary",
                4096,
            ),
        )

        object.__setattr__(
            self,
            "artifact_reference",
            _optional_text(
                self.artifact_reference,
                "artifact_reference",
                256,
            ),
        )


@dataclass(frozen=True, slots=True)
class FindingIdentity:
    """Fields identifying the same issue across repeated scans."""

    rule_id: str
    asset: str
    path: str = "/"
    method: str = "GET"
    parameter: str | None = None

    def __post_init__(self) -> None:
        rule_id = _text(
            self.rule_id,
            "rule_id",
            128,
        ).lower()

        if not _RULE_ID.fullmatch(rule_id):
            raise ContractValidationError(
                "rule_id_invalid",
                "rule_id must use lowercase letters, digits, dots, "
                "underscores, or hyphens.",
            )

        asset = _text(
            self.asset,
            "asset",
            2048,
        )

        parsed_asset = urlsplit(asset)

        if (
            parsed_asset.scheme.lower() not in {"http", "https"}
            or not parsed_asset.hostname
            or parsed_asset.username is not None
            or parsed_asset.password is not None
            or parsed_asset.path not in {"", "/"}
            or parsed_asset.query
            or parsed_asset.fragment
        ):
            raise ContractValidationError(
                "asset_invalid",
                "asset must be an HTTP(S) origin without credentials, "
                "path, query, or fragment.",
            )

        try:
            configured_port = parsed_asset.port
        except ValueError as exc:
            raise ContractValidationError(
                "asset_invalid",
                "asset contains an invalid port.",
            ) from exc

        scheme = parsed_asset.scheme.lower()
        hostname = parsed_asset.hostname.lower().rstrip(".")
        default_port = 443 if scheme == "https" else 80
        port = configured_port or default_port

        formatted_hostname = (
            f"[{hostname}]"
            if ":" in hostname
            else hostname
        )

        canonical_asset = (
            f"{scheme}://{formatted_hostname}"
            if port == default_port
            else f"{scheme}://{formatted_hostname}:{port}"
        )

        path = _text(
            self.path,
            "path",
            4096,
        )

        if not path.startswith("/"):
            raise ContractValidationError(
                "path_invalid",
                "path must begin with '/'.",
            )

        parsed_path = urlsplit(path)

        if (
            parsed_path.scheme
            or parsed_path.netloc
            or parsed_path.query
            or parsed_path.fragment
        ):
            raise ContractValidationError(
                "path_invalid",
                "path cannot contain a scheme, authority, "
                "query, or fragment.",
            )

        method = _text(
            self.method,
            "method",
            32,
        ).upper()

        if not _HTTP_METHOD.fullmatch(method):
            raise ContractValidationError(
                "method_invalid",
                "method must contain only ASCII letters.",
            )

        object.__setattr__(
            self,
            "rule_id",
            rule_id,
        )
        object.__setattr__(
            self,
            "asset",
            canonical_asset,
        )
        object.__setattr__(
            self,
            "path",
            path,
        )
        object.__setattr__(
            self,
            "method",
            method,
        )
        object.__setattr__(
            self,
            "parameter",
            _optional_text(
                self.parameter,
                "parameter",
                512,
            ),
        )

    @property
    def fingerprint(self) -> str:
        """Return a deterministic SHA-256 identity fingerprint."""

        payload = json.dumps(
            {
                "fingerprint_version": "1",
                "rule_id": self.rule_id,
                "asset": self.asset,
                "path": self.path,
                "method": self.method,
                "parameter": self.parameter or "",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class NormalizedFinding:
    """Scanner-independent representation of one security finding."""

    identity: FindingIdentity
    source: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    remediation: str

    detected_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    source_rule_id: str | None = None
    identifiers: Tuple[ExternalIdentifier, ...] = ()
    evidence: Tuple[Evidence, ...] = ()
    references: Tuple[str, ...] = ()
    tags: Tuple[str, ...] = ()

    schema_version: str = field(
        default="1.0",
        init=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(
            self.identity,
            FindingIdentity,
        ):
            raise ContractValidationError(
                "identity_invalid",
                "identity must be a FindingIdentity.",
            )

        if not isinstance(
            self.severity,
            Severity,
        ):
            raise ContractValidationError(
                "severity_invalid",
                "severity must be a Severity value.",
            )

        if not isinstance(
            self.confidence,
            Confidence,
        ):
            raise ContractValidationError(
                "confidence_invalid",
                "confidence must be a Confidence value.",
            )

        if (
            not isinstance(self.detected_at, datetime)
            or self.detected_at.tzinfo is None
            or self.detected_at.utcoffset() is None
        ):
            raise ContractValidationError(
                "detected_at_invalid",
                "detected_at must be timezone-aware.",
            )

        if any(
            not isinstance(item, ExternalIdentifier)
            for item in self.identifiers
        ):
            raise ContractValidationError(
                "identifiers_invalid",
                "identifiers contains an invalid value.",
            )

        if any(
            not isinstance(item, Evidence)
            for item in self.evidence
        ):
            raise ContractValidationError(
                "evidence_invalid",
                "evidence contains an invalid value.",
            )

        identifiers = tuple(
            sorted(set(self.identifiers))
        )
        evidence = tuple(self.evidence)

        references = tuple(
            sorted(
                {
                    _text(
                        item,
                        "reference",
                        2048,
                    )
                    for item in self.references
                }
            )
        )

        tags = tuple(
            sorted(
                {
                    _text(
                        item,
                        "tag",
                        64,
                    ).lower()
                    for item in self.tags
                }
            )
        )

        if (
            len(identifiers) > 64
            or len(evidence) > 32
            or len(references) > 64
            or len(tags) > 64
        ):
            raise ContractValidationError(
                "collection_too_large",
                "The finding contains too many identifiers, evidence "
                "items, references, or tags.",
            )

        for reference in references:
            parsed_reference = urlsplit(reference)

            if (
                parsed_reference.scheme != "https"
                or not parsed_reference.hostname
                or parsed_reference.username is not None
                or parsed_reference.password is not None
            ):
                raise ContractValidationError(
                    "reference_invalid",
                    "references must be absolute HTTPS URLs "
                    "without embedded credentials.",
                )

        object.__setattr__(
            self,
            "source",
            _text(
                self.source,
                "source",
                128,
            ).lower(),
        )

        object.__setattr__(
            self,
            "source_rule_id",
            _optional_text(
                self.source_rule_id,
                "source_rule_id",
                256,
            ),
        )

        object.__setattr__(
            self,
            "title",
            _text(
                self.title,
                "title",
                256,
            ),
        )

        object.__setattr__(
            self,
            "description",
            _text(
                self.description,
                "description",
                16_384,
            ),
        )

        object.__setattr__(
            self,
            "remediation",
            _text(
                self.remediation,
                "remediation",
                16_384,
            ),
        )

        object.__setattr__(
            self,
            "detected_at",
            self.detected_at.astimezone(timezone.utc),
        )

        object.__setattr__(
            self,
            "identifiers",
            identifiers,
        )
        object.__setattr__(
            self,
            "evidence",
            evidence,
        )
        object.__setattr__(
            self,
            "references",
            references,
        )
        object.__setattr__(
            self,
            "tags",
            tags,
        )

    @property
    def fingerprint(self) -> str:
        """Return the stable identity fingerprint."""

        return self.identity.fingerprint

    def to_dict(self) -> dict[str, Any]:
        """Convert the finding to a JSON-compatible dictionary."""

        return {
            "schema_version": self.schema_version,
            "fingerprint": self.fingerprint,
            "identity": {
                "rule_id": self.identity.rule_id,
                "asset": self.identity.asset,
                "path": self.identity.path,
                "method": self.identity.method,
                "parameter": self.identity.parameter,
            },
            "source": self.source,
            "source_rule_id": self.source_rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "remediation": self.remediation,
            "detected_at": (
                self.detected_at
                .isoformat()
                .replace("+00:00", "Z")
            ),
            "identifiers": [
                {
                    "namespace": item.namespace,
                    "value": item.value,
                }
                for item in self.identifiers
            ],
            "evidence": [
                {
                    "summary": item.summary,
                    "artifact_reference": item.artifact_reference,
                }
                for item in self.evidence
            ],
            "references": list(self.references),
            "tags": list(self.tags),
        }

    def to_json(self) -> str:
        """Serialise deterministically for storage and message queues."""

        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
