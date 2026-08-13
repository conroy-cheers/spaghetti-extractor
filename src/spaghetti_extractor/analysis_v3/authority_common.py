"""Shared fail-closed decision records for v3 authority families."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

from ..artifact_set_v3 import RecordDependencyV3
from ..phase_framework_v3 import PhaseContextV3
from ._schema import fail, strict_object, text


AuthorityStatusV3: TypeAlias = Literal["complete", "incomplete", "violated"]


@dataclass(frozen=True, order=True)
class PrimaryBlockerV3:
    """The deterministic first reason a record cannot grant authority."""

    status: Literal["incomplete", "violated"]
    code: str
    input_name: str | None = None
    record_id: str | None = None

    def __post_init__(self) -> None:
        if self.status not in {"incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"primary blocker has invalid status {self.status!r}",
                "use incomplete or violated for a blocking condition",
            )
        text(self.code, "primary blocker code", maximum=128)
        if (self.input_name is None) != (self.record_id is None):
            fail(
                "record_schema_mismatch",
                "primary blocker has a partial dependency reference",
                "provide both input_name and record_id, or neither",
            )
        if self.input_name is not None:
            RecordDependencyV3(self.input_name, str(self.record_id))

    @property
    def dependency(self) -> RecordDependencyV3 | None:
        if self.input_name is None or self.record_id is None:
            return None
        return RecordDependencyV3(self.input_name, self.record_id)

    def to_payload(self) -> dict[str, str | None]:
        return {
            "status": self.status,
            "code": self.code,
            "input": self.input_name,
            "record_id": self.record_id,
        }

    @classmethod
    def parse(cls, value: Any) -> "PrimaryBlockerV3":
        row = strict_object(
            value,
            {"status", "code", "input", "record_id"},
            "primary blocker",
        )
        status = text(row["status"], "primary blocker status")
        if status not in {"incomplete", "violated"}:
            fail(
                "record_schema_mismatch",
                f"primary blocker has invalid status {status!r}",
                "use incomplete or violated",
            )
        input_name = row["input"]
        record_id = row["record_id"]
        if input_name is not None:
            input_name = text(input_name, "primary blocker input")
        if record_id is not None:
            record_id = text(record_id, "primary blocker record ID")
        return cls(status, text(row["code"], "primary blocker code"), input_name, record_id)  # type: ignore[arg-type]


def canonical_dependencies_v3(
    values: Iterable[RecordDependencyV3],
) -> tuple[RecordDependencyV3, ...]:
    return tuple(sorted(set(values)))


def encode_dependencies_v3(
    values: Iterable[RecordDependencyV3],
) -> list[dict[str, str]]:
    return [row.to_payload() for row in canonical_dependencies_v3(values)]


def decode_dependencies_v3(value: Any) -> tuple[RecordDependencyV3, ...]:
    if not isinstance(value, list):
        fail(
            "record_schema_mismatch",
            "authority dependencies must be an array",
            "emit sorted unique record dependency objects",
        )
    result = tuple(RecordDependencyV3.parse(row) for row in value)
    canonical = canonical_dependencies_v3(result)
    if result != canonical:
        fail(
            "noncanonical_record_order",
            "authority dependencies are duplicated or unsorted",
            "sort and deduplicate dependency records",
        )
    return result


def aggregate_blockers_v3(
    blockers: Iterable[PrimaryBlockerV3],
) -> PrimaryBlockerV3 | None:
    rows = tuple(blockers)
    if not rows:
        return None
    rank = {"violated": 0, "incomplete": 1}
    return min(
        rows,
        key=lambda row: (
            rank[row.status],
            row.code,
            row.input_name or "",
            row.record_id or "",
        ),
    )


def manifest_blocker_v3(
    context: PhaseContextV3,
    input_name: str,
    code: str,
    dependency: RecordDependencyV3 | None = None,
) -> PrimaryBlockerV3 | None:
    status = context.manifest(input_name).status
    if status == "complete":
        return None
    return PrimaryBlockerV3(
        "violated" if status == "violated" else "incomplete",
        code,
        None if dependency is None else dependency.input_name,
        None if dependency is None else dependency.record_id,
    )


def validate_authority_decision_v3(
    *,
    status: str,
    authorizing: bool,
    primary_blocker: PrimaryBlockerV3 | None,
    dependencies: tuple[RecordDependencyV3, ...],
    context: str,
) -> None:
    if status not in {"complete", "incomplete", "violated"}:
        fail(
            "record_schema_mismatch",
            f"{context} has invalid status {status!r}",
            "use complete, incomplete, or violated",
        )
    if dependencies != canonical_dependencies_v3(dependencies):
        fail(
            "noncanonical_record_order",
            f"{context} dependencies are duplicated or unsorted",
            "sort and deduplicate exact dependency records",
        )
    if status == "complete":
        if not authorizing or primary_blocker is not None:
            fail(
                "fail_open_authority_status",
                f"complete {context} has inconsistent authority fields",
                "set authorizing true and clear the primary blocker",
            )
    elif authorizing or primary_blocker is None or primary_blocker.status != status:
        fail(
            "fail_open_authority_status",
            f"non-complete {context} retains authority or lacks its blocker",
            "clear authority and bind the matching primary blocker",
        )
    if primary_blocker is not None and primary_blocker.dependency is not None:
        if primary_blocker.dependency not in dependencies:
            fail(
                "incomplete_record_dependencies",
                f"{context} primary blocker is absent from explicit dependencies",
                "include the blocked input record in the dependency inventory",
            )


def blocker_payload_v3(
    value: PrimaryBlockerV3 | None,
) -> Mapping[str, Any] | None:
    return None if value is None else value.to_payload()


__all__ = [
    "AuthorityStatusV3",
    "PrimaryBlockerV3",
    "aggregate_blockers_v3",
    "blocker_payload_v3",
    "canonical_dependencies_v3",
    "decode_dependencies_v3",
    "encode_dependencies_v3",
    "manifest_blocker_v3",
    "validate_authority_decision_v3",
]
