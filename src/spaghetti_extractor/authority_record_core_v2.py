"""Stable record primitives shared by v2 authority certificate families.

This module deliberately excludes every concrete authority record.  Analysis
phases may depend on these immutable primitives without inheriting schema
changes from unrelated acceptance certificates.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
from typing import Any, ClassVar, Mapping, Sequence

from .authority_bindings_v2 import (
    AuthorityDataError,
    CanonicalJson,
    _array,
    _json_value,
    _object,
    _sha256,
    _text,
    _token,
    _uint,
    canonical_json,
    canonical_json_bytes,
)


HYBRID_AUTHORITY_SCHEMA_VERSION = 2
MAX_FINITE_ALTERNATIVES = 256

_CONTENT_ID_RE = re.compile(
    r"hybrid-authority-v2:([a-z][a-z0-9_]{0,63}):([0-9a-f]{64})"
)


class AuthorityStatus(str, Enum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    VIOLATED = "violated"


class EvidenceIssueKind(str, Enum):
    MISSING = "missing"
    CONTRADICTORY = "contradictory"
    CORRUPT = "corrupt"


def _content_id(kind: str, core: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json_bytes(core)).hexdigest()
    return f"hybrid-authority-v2:{kind}:{digest}"


def _checked_content_id(value: Any, context: str) -> str:
    if not isinstance(value, str) or _CONTENT_ID_RE.fullmatch(value) is None:
        raise AuthorityDataError(f"{context} must be a v2 authority content ID")
    return value


def _content_id_kind(value: str) -> str:
    match = _CONTENT_ID_RE.fullmatch(value)
    if match is None:
        raise AuthorityDataError("value is not a v2 authority content ID")
    return match.group(1)


@dataclass(frozen=True, order=True)
class EvidenceIssue:
    kind: EvidenceIssueKind
    code: str
    detail: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, EvidenceIssueKind):
            raise AuthorityDataError("evidence issue kind must be typed")
        _token(self.code, "evidence issue code")
        _text(self.detail, "evidence issue detail")

    def to_payload(self) -> dict[str, str]:
        return {"kind": self.kind.value, "code": self.code, "detail": self.detail}

    @classmethod
    def parse(cls, value: Any) -> "EvidenceIssue":
        row = _object(value, {"kind", "code", "detail"}, "evidence issue")
        try:
            kind = EvidenceIssueKind(row["kind"])
        except (TypeError, ValueError) as exc:
            raise AuthorityDataError("evidence issue has an invalid kind") from exc
        return cls(
            kind=kind,
            code=_token(row["code"], "evidence issue code"),
            detail=_text(row["detail"], "evidence issue detail"),
        )


@dataclass(frozen=True, order=True)
class AuthorityDependency:
    role: str
    content_id: str

    def __post_init__(self) -> None:
        _token(self.role, "dependency role")
        _checked_content_id(self.content_id, "dependency content ID")

    def to_payload(self) -> dict[str, str]:
        return {"role": self.role, "content_id": self.content_id}

    @classmethod
    def parse(cls, value: Any) -> "AuthorityDependency":
        row = _object(value, {"role", "content_id"}, "authority dependency")
        return cls(
            role=_token(row["role"], "dependency role"),
            content_id=_checked_content_id(
                row["content_id"], "dependency content ID"
            ),
        )


@dataclass(frozen=True)
class FiniteAlternatives:
    """A sorted, unique, explicitly bounded nonempty set of JSON alternatives."""

    maximum: int
    values: tuple[CanonicalJson, ...]

    def __post_init__(self) -> None:
        _uint(
            self.maximum,
            "finite alternative maximum",
            maximum=MAX_FINITE_ALTERNATIVES,
        )
        if self.maximum == 0:
            raise AuthorityDataError("finite alternative maximum must be positive")
        if not isinstance(self.values, tuple) or not self.values:
            raise AuthorityDataError("finite alternatives must be a nonempty tuple")
        if len(self.values) > self.maximum:
            raise AuthorityDataError("finite alternatives exceed their declared bound")
        if any(not isinstance(value, CanonicalJson) for value in self.values):
            raise AuthorityDataError("finite alternatives must contain CanonicalJson")
        if self.values != tuple(sorted(set(self.values))):
            raise AuthorityDataError("finite alternatives must be sorted and unique")

    @classmethod
    def of(
        cls, values: Sequence[Any], *, maximum: int = MAX_FINITE_ALTERNATIVES
    ) -> "FiniteAlternatives":
        normalized = tuple(
            sorted(
                {
                    value if isinstance(value, CanonicalJson) else CanonicalJson.of(value)
                    for value in values
                }
            )
        )
        return cls(maximum=maximum, values=normalized)

    def to_payload(self) -> dict[str, Any]:
        return {
            "maximum": self.maximum,
            "values": [value.to_value() for value in self.values],
        }

    @classmethod
    def parse(cls, value: Any) -> "FiniteAlternatives":
        row = _object(value, {"maximum", "values"}, "finite alternatives")
        values = tuple(
            CanonicalJson.of(item)
            for item in _array(row["values"], "finite alternative values")
        )
        return cls(
            maximum=_uint(
                row["maximum"],
                "finite alternative maximum",
                maximum=MAX_FINITE_ALTERNATIVES,
            ),
            values=values,
        )


@dataclass(frozen=True, order=True)
class ProfileBinding:
    profile_id: str
    profile_sha256: str
    entry_id: str

    def __post_init__(self) -> None:
        _text(self.profile_id, "profile ID", maximum=256)
        _sha256(self.profile_sha256, "profile SHA-256")
        _text(self.entry_id, "profile entry ID", maximum=256)

    def to_payload(self) -> dict[str, str]:
        return {
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "entry_id": self.entry_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "ProfileBinding":
        row = _object(
            value,
            {"profile_id", "profile_sha256", "entry_id"},
            "profile binding",
        )
        return cls(
            profile_id=_text(row["profile_id"], "profile ID", maximum=256),
            profile_sha256=_sha256(row["profile_sha256"], "profile SHA-256"),
            entry_id=_text(row["entry_id"], "profile entry ID", maximum=256),
        )


def _check_dependencies(value: tuple[AuthorityDependency, ...]) -> None:
    if not isinstance(value, tuple) or any(
        not isinstance(item, AuthorityDependency) for item in value
    ):
        raise AuthorityDataError("dependencies must be an immutable typed tuple")
    if value != tuple(sorted(set(value))):
        raise AuthorityDataError("dependencies must be sorted and unique")


def _check_issues(value: tuple[EvidenceIssue, ...]) -> None:
    if not isinstance(value, tuple) or any(
        not isinstance(item, EvidenceIssue) for item in value
    ):
        raise AuthorityDataError("issues must be an immutable typed tuple")
    key = lambda item: (item.kind.value, item.code, item.detail)
    if value != tuple(sorted(set(value), key=key)):
        raise AuthorityDataError("evidence issues must be sorted and unique")


def _derive_status(
    *,
    missing: bool,
    violated: bool,
    issues: tuple[EvidenceIssue, ...],
) -> AuthorityStatus:
    if violated or any(
        issue.kind in {EvidenceIssueKind.CONTRADICTORY, EvidenceIssueKind.CORRUPT}
        for issue in issues
    ):
        return AuthorityStatus.VIOLATED
    if missing or any(issue.kind is EvidenceIssueKind.MISSING for issue in issues):
        return AuthorityStatus.INCOMPLETE
    return AuthorityStatus.COMPLETE


def _alternative_references(value: Any) -> set[str]:
    if isinstance(value, str) and _CONTENT_ID_RE.fullmatch(value) is not None:
        return {value}
    if isinstance(value, Mapping):
        result: set[str] = set()
        for item in value.values():
            result.update(_alternative_references(item))
        return result
    if isinstance(value, list):
        result = set()
        for item in value:
            result.update(_alternative_references(item))
        return result
    return set()


def _has_undeclared_references(
    alternatives: FiniteAlternatives | None,
    dependencies: tuple[AuthorityDependency, ...],
) -> bool:
    if alternatives is None:
        return False
    referenced: set[str] = set()
    for alternative in alternatives.values:
        referenced.update(_alternative_references(alternative.to_value()))
    declared = {dependency.content_id for dependency in dependencies}
    return not referenced <= declared


def _record_core(
    *,
    format_name: str,
    status: AuthorityStatus,
    binding: Mapping[str, Any],
    dependencies: tuple[AuthorityDependency, ...],
    alternatives: FiniteAlternatives | None,
    issues: tuple[EvidenceIssue, ...],
    fields: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "format": format_name,
        "schema_version": HYBRID_AUTHORITY_SCHEMA_VERSION,
        "status": status.value,
        "binding": dict(binding),
        "dependencies": [item.to_payload() for item in dependencies],
        "alternatives": None if alternatives is None else alternatives.to_payload(),
        "issues": [item.to_payload() for item in issues],
        **dict(fields),
    }


@dataclass(frozen=True)
class _ParsedRecordParts:
    binding: Any
    dependencies: tuple[AuthorityDependency, ...]
    alternatives: FiniteAlternatives | None
    issues: tuple[EvidenceIssue, ...]


def _parse_record_parts(
    value: Mapping[str, Any],
    *,
    format_name: str,
    fields: set[str],
) -> _ParsedRecordParts:
    expected = {
        "format",
        "schema_version",
        "content_id",
        "status",
        "binding",
        "dependencies",
        "alternatives",
        "issues",
        *fields,
    }
    row = _object(value, expected, format_name)
    if row["format"] != format_name or row["schema_version"] != 2:
        raise AuthorityDataError("v1 and unknown authority formats are not authorizing")
    dependencies = tuple(
        AuthorityDependency.parse(item)
        for item in _array(row["dependencies"], "authority dependencies")
    )
    issues = tuple(
        EvidenceIssue.parse(item)
        for item in _array(row["issues"], "authority issues")
    )
    alternatives = (
        None
        if row["alternatives"] is None
        else FiniteAlternatives.parse(row["alternatives"])
    )
    return _ParsedRecordParts(
        binding=row["binding"],
        dependencies=dependencies,
        alternatives=alternatives,
        issues=issues,
    )


def _finish_record_parse(record: Any, value: Mapping[str, Any]) -> None:
    observed = _json_value(value, context="authority record")
    if record.to_payload() != observed:
        raise AuthorityDataError(
            "authority record status, content ID, or canonical ordering is stale"
        )


class AuthorityRecordMixin:
    KIND: ClassVar[str]
    FORMAT: ClassVar[str]

    dependencies: tuple[AuthorityDependency, ...]
    alternatives: FiniteAlternatives | None
    issues: tuple[EvidenceIssue, ...]

    @property
    def status(self) -> AuthorityStatus:
        raise NotImplementedError

    @cached_property
    def content_id(self) -> str:
        core = self._core_payload()
        return _content_id(self.KIND, core)

    def _core_payload(self) -> dict[str, Any]:
        raise NotImplementedError

    def to_payload(self) -> dict[str, Any]:
        core = self._core_payload()
        return {**core, "content_id": self.content_id}

    def to_json(self) -> str:
        return canonical_json(self.to_payload())


__all__ = [
    "HYBRID_AUTHORITY_SCHEMA_VERSION",
    "MAX_FINITE_ALTERNATIVES",
    "AuthorityDependency",
    "AuthorityRecordMixin",
    "AuthorityStatus",
    "EvidenceIssue",
    "EvidenceIssueKind",
    "FiniteAlternatives",
    "ProfileBinding",
]
