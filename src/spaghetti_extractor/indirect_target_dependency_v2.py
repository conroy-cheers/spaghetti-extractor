"""Checked dependency semantics for finite indirect-target inventories.

An indirect target expression may read mutable data without requiring the
mutable value itself to be invariant.  The important distinction is whether
that value can change the *set* of possible targets.  A statically checked jump
table with an exhaustive selector bound is the first supported instance: the
selector chooses one member of an already complete immutable inventory.

These certificates are structural evidence attached to an exact static
recovery.  They do not recover targets and do not make an incomplete recovery
authoritative.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .authority_bindings_v2 import canonical_json_bytes


FINITE_TARGET_DEPENDENCY_V2_FORMAT = (
    "spaghetti-extractor-finite-target-dependency-v2"
)
_ID_PREFIX = "finite-target-dependency-v2:"
_DIGEST = re.compile(r"[0-9a-f]{64}")


class IndirectTargetDependencyV2Error(ValueError):
    """A finite-target dependency certificate is malformed or inconsistent."""


def build_bounded_selector_dependency_v2(
    recovery: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a complete static jump-table recovery to bounded-selector semantics."""

    core = _bounded_selector_core(recovery)
    return {
        **core,
        "content_id": _ID_PREFIX + _sha256(core),
    }


def validate_bounded_selector_dependency_v2(
    recovery: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the canonical certificate or raise on any mismatch."""

    observed = recovery.get("target_set_dependency")
    if not isinstance(observed, Mapping):
        raise IndirectTargetDependencyV2Error(
            "finite target recovery has no target-set dependency certificate"
        )
    expected = build_bounded_selector_dependency_v2(recovery)
    if canonical_json_bytes(observed) != canonical_json_bytes(expected):
        raise IndirectTargetDependencyV2Error(
            "finite target dependency certificate does not match its recovery"
        )
    return expected


def has_value_independent_target_set_v2(recovery: Mapping[str, Any]) -> bool:
    """Whether mutable selector values cannot alter the certified target set."""

    try:
        certificate = validate_bounded_selector_dependency_v2(recovery)
    except (IndirectTargetDependencyV2Error, TypeError, ValueError):
        return False
    return (
        certificate["dependency_kind"] == "bounded_selector"
        and certificate["requires_selector_value_provenance"] is False
    )


def _bounded_selector_core(recovery: Mapping[str, Any]) -> dict[str, Any]:
    if (
        recovery.get("status") != "recovered"
        or recovery.get("closure") != "checked_finite_target_inventory"
        or recovery.get("recovery_kind") != "pe32_indexed_absolute_jump_table"
        or recovery.get("failure") is not None
    ):
        raise IndirectTargetDependencyV2Error(
            "bounded-selector certificate requires a complete static jump table"
        )

    index = _mapping(recovery.get("index"), "jump-table index")
    table = _mapping(recovery.get("table"), "jump-table metadata")
    entries = _mapping_array(recovery.get("entries"), "jump-table entries")
    values = _u32_array(index.get("values"), "jump-table selector values")
    if not values or values != sorted(set(values)):
        raise IndirectTargetDependencyV2Error(
            "jump-table selector values must be nonempty sorted unique uint32 values"
        )
    if index.get("value_count") != len(values):
        raise IndirectTargetDependencyV2Error(
            "jump-table selector value count is inconsistent"
        )
    if len(entries) != len(values):
        raise IndirectTargetDependencyV2Error(
            "jump-table entries do not exhaust the selector domain"
        )

    entry_indices = [_u32(row.get("index"), "jump-table entry index") for row in entries]
    if entry_indices != values:
        raise IndirectTargetDependencyV2Error(
            "jump-table entries are not in exact selector order"
        )
    entry_targets = [
        _u32(row.get("target_rva"), "jump-table target RVA") for row in entries
    ]
    target_rvas = _u32_array(recovery.get("target_rvas"), "target RVAs")
    if target_rvas != sorted(set(entry_targets)):
        raise IndirectTargetDependencyV2Error(
            "jump-table target inventory disagrees with its entries"
        )

    target_unit_ids = _string_array(
        recovery.get("target_unit_ids"), "target unit IDs"
    )
    unit_binding = _mapping(recovery.get("unit_binding"), "target unit binding")
    if (
        unit_binding.get("status") != "complete"
        or _u32_array(
            unit_binding.get("resolved_target_rvas"), "resolved target RVAs"
        )
        != target_rvas
        or unit_binding.get("unmaterialized_target_rvas") != []
        or not target_unit_ids
        or len(target_unit_ids) != len(target_rvas)
    ):
        raise IndirectTargetDependencyV2Error(
            "jump-table targets are not completely bound to canonical units"
        )

    if (
        table.get("entry_width") != 4
        or table.get("entry_count") != len(values)
        or _u32_array(table.get("index_values"), "table index values") != values
        or not isinstance(table.get("contiguous"), bool)
    ):
        raise IndirectTargetDependencyV2Error(
            "jump-table metadata is inconsistent with its selector inventory"
        )
    table_bytes_sha256 = _digest(
        table.get("bytes_sha256"), "jump-table bytes SHA-256"
    )
    table_inventory_sha256 = _digest(
        table.get("inventory_sha256"), "jump-table inventory SHA-256"
    )
    _validate_selector_bound(index, values)

    expression = _mapping(index.get("expression"), "selector expression")
    selector_expression_sha256 = _sha256(expression)
    selector_values_sha256 = _sha256(values)
    target_inventory = [
        {
            "index": index_value,
            "entry_rva": _u32(row.get("entry_rva"), "jump-table entry RVA"),
            "target_rva": target_rva,
        }
        for index_value, row, target_rva in zip(values, entries, entry_targets)
    ]
    return {
        "format": FINITE_TARGET_DEPENDENCY_V2_FORMAT,
        "dependency_kind": "bounded_selector",
        "selector_expression_sha256": selector_expression_sha256,
        "selector_values_sha256": selector_values_sha256,
        "selector_value_count": len(values),
        "table_bytes_sha256": table_bytes_sha256,
        "table_inventory_sha256": table_inventory_sha256,
        "target_inventory_sha256": _sha256(target_inventory),
        "target_count": len(target_rvas),
        "requires_selector_value_provenance": False,
    }


def _validate_selector_bound(index: Mapping[str, Any], values: list[int]) -> None:
    dataflow = index.get("dataflow_evidence")
    if isinstance(dataflow, Mapping) and dataflow.get("status") == "complete":
        if _u32_array(dataflow.get("values"), "finite selector-domain values") != values:
            raise IndirectTargetDependencyV2Error(
                "finite selector-domain evidence disagrees with the table inventory"
            )
        return

    remap = index.get("remap")
    evidence = _mapping_array(index.get("bound_evidence"), "selector bound evidence")
    if not evidence:
        raise IndirectTargetDependencyV2Error(
            "bounded selector has no predecessor or dataflow evidence"
        )
    if isinstance(remap, Mapping):
        possible = _u32_array(remap.get("possible_values"), "remap values")
        source_upper = _u32(remap.get("source_upper_exclusive"), "remap source bound")
        if possible != values or any(
            row.get("upper_exclusive") != source_upper for row in evidence
        ):
            raise IndirectTargetDependencyV2Error(
                "immutable remap evidence does not exhaust the selector domain"
            )
        _digest(remap.get("bytes_sha256"), "selector remap bytes SHA-256")
        return

    contiguous = values == list(range(len(values)))
    if (
        not contiguous
        or index.get("lower_inclusive") != 0
        or index.get("upper_exclusive") != len(values)
        or any(row.get("upper_exclusive") != len(values) for row in evidence)
    ):
        raise IndirectTargetDependencyV2Error(
            "predecessor bounds do not exhaust a contiguous selector domain"
        )


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IndirectTargetDependencyV2Error(f"{context} must be an object")
    return value


def _mapping_array(value: Any, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise IndirectTargetDependencyV2Error(f"{context} must be an array")
    result = list(value)
    if any(not isinstance(row, Mapping) for row in result):
        raise IndirectTargetDependencyV2Error(f"{context} contains a non-object")
    return result  # type: ignore[return-value]


def _u32(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
        raise IndirectTargetDependencyV2Error(f"{context} must be a uint32")
    return value


def _u32_array(value: Any, context: str) -> list[int]:
    if not isinstance(value, list):
        raise IndirectTargetDependencyV2Error(f"{context} must be an array")
    return [_u32(item, f"{context} item") for item in value]


def _string_array(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise IndirectTargetDependencyV2Error(
            f"{context} must be an array of nonempty strings"
        )
    if len(set(value)) != len(value):
        raise IndirectTargetDependencyV2Error(f"{context} contains duplicates")
    return list(value)


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise IndirectTargetDependencyV2Error(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "FINITE_TARGET_DEPENDENCY_V2_FORMAT",
    "IndirectTargetDependencyV2Error",
    "build_bounded_selector_dependency_v2",
    "has_value_independent_target_set_v2",
    "validate_bounded_selector_dependency_v2",
]
