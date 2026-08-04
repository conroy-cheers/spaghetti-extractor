"""Typed bounded value provenance shared by Stage A analyses.

The values in this module are untrusted abstract-analysis proposals. They are
deliberately small and serializable so checked analyses can replay each origin
derivation against exact machine semantics before candidate qualification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


PROVENANCE_KINDS = frozenset({
    "exact",
    "static_code",
    "static_data",
    "stack_location",
    "import",
    "resource",
    "resource_view",
    "guarded_resource_view",
    "call_result",
    "register_location",
    "operation_table",
    "operation_slot",
    "operation_target",
    "guarded_operation_target",
    "callback",
    # Compatibility spellings used while the interface-specific analysis is
    # migrated onto the operation vocabulary.
    "interface_object",
    "interface_vtable",
    "interface_slot",
    "interface_method",
})


@dataclass(frozen=True, order=True)
class ValueOrigin:
    """One checked-origin proposal for a concrete 32-bit machine value."""

    kind: str
    key: tuple[Any, ...]

    def __post_init__(self) -> None:
        if self.kind not in PROVENANCE_KINDS:
            raise ValueError(f"unsupported value-origin kind {self.kind!r}")

    def as_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "key": list(self.key)}


FiniteValue = frozenset[ValueOrigin] | None


def finite_value(origins: Iterable[ValueOrigin], budget: int) -> FiniteValue:
    values = frozenset(origins)
    return values if values and len(values) <= budget else None


def join_finite_values(
    left: FiniteValue,
    right: FiniteValue,
    budget: int,
    *,
    missing_is_identity: bool = False,
) -> FiniteValue:
    if missing_is_identity:
        if left is None:
            return right
        if right is None:
            return left
    if left is None or right is None:
        return None
    result = left | right
    return result if len(result) <= budget else None


def origins_json(value: FiniteValue) -> list[dict[str, Any]] | None:
    return None if value is None else [origin.as_json() for origin in sorted(value)]


__all__ = [
    "FiniteValue",
    "PROVENANCE_KINDS",
    "ValueOrigin",
    "finite_value",
    "join_finite_values",
    "origins_json",
]
