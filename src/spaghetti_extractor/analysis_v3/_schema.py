"""Strict schema and identity helpers for recordized v3 analyses."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, NoReturn

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactV3Error,
    CanonicalValueV3,
    JsonValue,
    RecordDependencyV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
)


_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


class AnalysisV3Error(ArtifactV3Error):
    """A typed authority-family record failed closed."""


def fail(code: str, message: str, remediation: str) -> NoReturn:
    raise AnalysisV3Error(code, message, remediation=remediation)


def strict_object(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        fail(
            "record_schema_mismatch",
            f"{context} must contain exactly {sorted(fields)!r}",
            "regenerate the record with the matching analysis_v3 codec",
        )
    return value


def mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        fail(
            "record_schema_mismatch",
            f"{context} must be an object",
            "emit the canonical object required by the v3 record schema",
        )
    return value


def sequence(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        fail(
            "record_schema_mismatch",
            f"{context} must be an array",
            "emit a canonical JSON array",
        )
    return value


def text(value: Any, context: str, *, maximum: int = 1024) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        fail(
            "record_schema_mismatch",
            f"{context} must be bounded nonempty text",
            "emit a stable printable identifier",
        )
    return value


def optional_text(value: Any, context: str, *, maximum: int = 1024) -> str | None:
    return None if value is None else text(value, context, maximum=maximum)


def digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        fail(
            "record_schema_mismatch",
            f"{context} must be a lowercase SHA-256 digest",
            "bind the exact canonical producer content",
        )
    return value


def uint(value: Any, context: str, *, maximum: int = 0xFFFFFFFF) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > maximum
    ):
        fail(
            "record_schema_mismatch",
            f"{context} must be an unsigned integer no greater than {maximum}",
            "emit the exact bounded integer",
        )
    return value


def optional_uint(value: Any, context: str) -> int | None:
    return None if value is None else uint(value, context)


def boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        fail(
            "record_schema_mismatch",
            f"{context} must be Boolean",
            "emit true or false",
        )
    return value


def canonical_strings(value: Any, context: str) -> tuple[str, ...]:
    result = tuple(text(item, context) for item in sequence(value, context))
    if result != tuple(sorted(set(result))):
        fail(
            "noncanonical_record_order",
            f"{context} must be sorted and unique",
            "sort and deduplicate the identifiers before encoding",
        )
    return result


def canonical_values(value: Any, context: str) -> tuple[CanonicalValueV3, ...]:
    result = tuple(CanonicalValueV3.of(item) for item in sequence(value, context))
    if result != tuple(sorted(set(result), key=lambda item: item.data)):
        fail(
            "noncanonical_record_order",
            f"{context} must be canonically sorted and unique",
            "sort and deduplicate values by canonical JSON bytes",
        )
    return result


def stable_id(prefix: str, payload: Any) -> str:
    text(prefix, "stable ID prefix", maximum=128)
    return f"{prefix}:{canonical_sha256_v3(payload)}"


def require_stable_id(value: str, prefix: str, payload: Any, context: str) -> None:
    expected = stable_id(prefix, payload)
    if value != expected:
        fail(
            "stale_record_id",
            f"{context} ID {value!r} does not bind its identity payload",
            f"recreate it as {expected!r}",
        )


def canonical_payload(value: CanonicalValueV3, context: str) -> Mapping[str, Any]:
    return mapping(value.to_value(), context)


def sorted_records(records: Iterable[ArtifactRecordV3]) -> tuple[ArtifactRecordV3, ...]:
    result = tuple(sorted(records, key=lambda row: row.record_id))
    if len({row.record_id for row in result}) != len(result):
        fail(
            "duplicate_record_id",
            "input records contain duplicate stable IDs",
            "repair the upstream artifact set",
        )
    return result


def dependencies_for(
    input_name: str, records: Iterable[ArtifactRecordV3]
) -> tuple[RecordDependencyV3, ...]:
    return tuple(
        sorted(
            RecordDependencyV3(input_name, record.record_id) for record in records
        )
    )


def exact_dependency_closure(
    inputs: Mapping[str, Sequence[ArtifactRecordV3]],
) -> tuple[RecordDependencyV3, ...]:
    return tuple(
        sorted(
            dependency
            for name, records in inputs.items()
            for dependency in dependencies_for(name, records)
        )
    )


def require_record_ids(
    records: Sequence[ArtifactRecordV3], expected: Iterable[str], context: str
) -> None:
    actual = tuple(sorted(record.record_id for record in records))
    canonical_expected = tuple(sorted(set(expected)))
    if actual != canonical_expected:
        fail(
            "incomplete_record_set",
            f"{context} IDs differ: expected={canonical_expected!r}, actual={actual!r}",
            "rerun the phase over the complete exact input artifact",
        )


def canonical_json_rows(values: Iterable[CanonicalValueV3]) -> list[JsonValue]:
    return [value.to_value() for value in values]


def canonical_sort(values: Iterable[Any]) -> tuple[CanonicalValueV3, ...]:
    by_bytes = {
        canonical_json_bytes_v3(value): CanonicalValueV3.of(value) for value in values
    }
    return tuple(by_bytes[key] for key in sorted(by_bytes))


__all__ = ["AnalysisV3Error"]
