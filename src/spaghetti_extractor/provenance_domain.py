"""Typed bounded value provenance shared by Stage A analyses.

The values in this module are untrusted abstract-analysis proposals. They are
deliberately small and serializable so checked analyses can replay each origin
derivation against exact machine semantics before candidate qualification.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence


PROVENANCE_KINDS = frozenset({
    "exact",
    "static_code",
    "static_data",
    "stack_location",
    "dynamic_range",
    "dynamic_location",
    # Event-address witness for every byte start in one checked inclusive
    # offset interval of a bounded dynamic allocation. It is emitted only by
    # the natural-loop footprint replay and is not a runtime value type.
    "dynamic_span",
    # Event-address witness for every byte start in one checked inclusive
    # absolute-address interval. Consumers must independently establish that
    # the whole interval belongs to an allowed mapped range. Like
    # ``dynamic_span``, this is a footprint witness rather than a runtime value.
    "absolute_span",
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
    "callback_token",
    "loaded_module",
    "resolved_export",
    # Internal analysis witness for an arbitrary 32-bit value expressed as a
    # canonical affine form over entry-state symbols.  It may establish value
    # and address equality inside a checked replay, but is never itself a
    # callable-target or persistent-global fact.
    "symbolic_affine",
    # Compatibility spellings used while the interface-specific analysis is
    # migrated onto the operation vocabulary.
    "interface_object",
    "interface_vtable",
    "interface_slot",
    "interface_method",
})

PERSISTENT_ORIGIN_KINDS = frozenset({
    "exact",
    "import",
    "static_code",
    "static_data",
    "dynamic_range",
    "dynamic_location",
    "resource",
    "resource_view",
    "operation_table",
    "operation_slot",
    "operation_target",
    "callback",
    "callback_token",
    "loaded_module",
    "resolved_export",
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
    dependencies: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.kind not in PROVENANCE_KINDS:
            raise ValueError(f"unsupported value-origin kind {self.kind!r}")
        if (
            tuple(sorted(set(self.dependencies))) != self.dependencies
            or any(not value for value in self.dependencies)
        ):
            raise ValueError("value-origin dependencies must be sorted unique IDs")

    def as_json(self) -> dict[str, Any]:
        result = {"kind": self.kind, "key": list(self.key)}
        if self.dependencies:
            result["authority_dependencies"] = list(self.dependencies)
        return result


FiniteValue = frozenset[ValueOrigin] | None


def is_persistent_origin(origin: ValueOrigin) -> bool:
    """Whether one origin may be retained as a checked memory fact."""

    return origin.kind in PERSISTENT_ORIGIN_KINDS


def origin_concrete_value(origin: ValueOrigin) -> int | None:
    """Return the exact machine value carried by a concrete origin."""

    if origin.kind == "exact" and len(origin.key) == 1:
        return int(origin.key[0]) & 0xFFFFFFFF
    if origin.kind in {"static_code", "static_data"} and len(origin.key) == 2:
        return int(origin.key[0]) & 0xFFFFFFFF
    return None


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


def parse_value_origin(raw: Any, *, context: str) -> ValueOrigin:
    if not isinstance(raw, Mapping):
        raise ValueError(f"{context} must be an object")
    if not {"kind", "key"} <= set(raw) <= {
        "kind", "key", "authority_dependencies"
    }:
        raise ValueError(f"{context} has invalid fields")
    kind = raw.get("kind")
    key = raw.get("key")
    dependencies = raw.get("authority_dependencies", [])
    if (
        not isinstance(kind, str)
        or not isinstance(key, Sequence)
        or isinstance(key, (str, bytes))
        or not isinstance(dependencies, Sequence)
        or isinstance(dependencies, (str, bytes))
        or any(
            not isinstance(value, str) or not value
            for value in dependencies
        )
        or tuple(sorted(set(dependencies))) != tuple(dependencies)
    ):
        raise ValueError(f"{context} is malformed")
    return ValueOrigin(
        kind,
        tuple(_freeze_origin_key(value, context=context) for value in key),
        tuple(str(value) for value in dependencies),
    )


def parse_finite_value(
    raw: Any, *, finite_value_budget: int, context: str
) -> frozenset[ValueOrigin]:
    if finite_value_budget <= 0:
        raise ValueError("finite-value budget must be positive")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise ValueError(f"{context} must be an array")
    if not 1 <= len(raw) <= finite_value_budget:
        raise ValueError(
            f"{context} must contain 1..{finite_value_budget} alternatives"
        )
    result = frozenset(
        parse_value_origin(value, context=f"{context} origin") for value in raw
    )
    if len(result) != len(raw):
        raise ValueError(f"{context} contains duplicate origins")
    return result


def _freeze_origin_key(value: Any, *, context: str) -> Any:
    if value is None or isinstance(value, (str, bool)) or (
        isinstance(value, int) and not isinstance(value, bool)
    ):
        return value
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(_freeze_origin_key(item, context=context) for item in value)
    raise ValueError(f"{context} key is not canonical JSON data")


def with_origin_dependencies(
    origin: ValueOrigin, dependencies: Iterable[str]
) -> ValueOrigin:
    combined = tuple(sorted(set(origin.dependencies) | set(dependencies)))
    return (
        origin
        if combined == origin.dependencies
        else ValueOrigin(origin.kind, origin.key, combined)
    )


def with_value_dependencies(
    value: FiniteValue, dependencies: Iterable[str]
) -> FiniteValue:
    required = tuple(sorted(set(dependencies)))
    if value is None or not required:
        return value
    return frozenset(with_origin_dependencies(origin, required) for origin in value)


def value_dependencies(value: FiniteValue) -> tuple[str, ...]:
    if value is None:
        return ()
    return tuple(sorted({item for origin in value for item in origin.dependencies}))


__all__ = [
    "FiniteValue",
    "PERSISTENT_ORIGIN_KINDS",
    "PROVENANCE_KINDS",
    "ValueOrigin",
    "finite_value",
    "join_finite_values",
    "is_persistent_origin",
    "origin_concrete_value",
    "origins_json",
    "parse_finite_value",
    "parse_value_origin",
    "value_dependencies",
    "with_origin_dependencies",
    "with_value_dependencies",
]
