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
PROFILE_DISPATCH_DEPENDENCY_V2_FORMAT = (
    "spaghetti-extractor-profile-dispatch-dependency-v2"
)
_ID_PREFIX = "finite-target-dependency-v2:"
_PROFILE_DISPATCH_ID_PREFIX = "profile-dispatch-dependency-v2:"
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


def build_profile_dispatch_dependency_v2(
    recovery: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind a finite profile dispatch to instance-bearing receiver evidence."""

    core = _profile_dispatch_core(recovery)
    return {
        **core,
        "content_id": _PROFILE_DISPATCH_ID_PREFIX + _sha256(core),
    }


def validate_profile_dispatch_dependency_v2(
    recovery: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the canonical profile-dispatch certificate or fail closed."""

    observed = recovery.get("target_set_dependency")
    if not isinstance(observed, Mapping):
        raise IndirectTargetDependencyV2Error(
            "profile dispatch has no target-set dependency certificate"
        )
    expected = build_profile_dispatch_dependency_v2(recovery)
    if canonical_json_bytes(observed) != canonical_json_bytes(expected):
        raise IndirectTargetDependencyV2Error(
            "profile-dispatch dependency certificate does not match its recovery"
        )
    return expected


def has_profile_dispatch_dependency_v2(recovery: Mapping[str, Any]) -> bool:
    """Whether recovery has checked profile dispatch and receiver instances."""

    try:
        certificate = validate_profile_dispatch_dependency_v2(recovery)
    except (IndirectTargetDependencyV2Error, TypeError, ValueError):
        return False
    return (
        certificate["dependency_kind"] == "profile_dispatch"
        and certificate["requires_live_receiver"] is True
        and certificate["requires_receiver_pointer_equality"] is False
    )


def _profile_dispatch_core(recovery: Mapping[str, Any]) -> dict[str, Any]:
    closure = recovery.get("closure")
    if (
        recovery.get("status") != "recovered"
        or closure not in {
            "checked_profile_interface_method_inventory",
            "checked_external_operation_inventory",
        }
        or recovery.get("failure") is not None
        or recovery.get("kind") != "indirect_call"
        or recovery.get("target_rvas") != []
        or recovery.get("target_unit_ids") != []
    ):
        raise IndirectTargetDependencyV2Error(
            "profile-dispatch certificate requires a complete external call recovery"
        )
    expression = _mapping(
        recovery.get("target_expression"), "profile-dispatch target expression"
    )
    targets = _mapping_array(
        recovery.get("external_targets"), "profile-dispatch external targets"
    )
    witnesses = _mapping_array(
        recovery.get("target_origin_witnesses"),
        "profile-dispatch origin witnesses",
    )
    if not targets or not witnesses or recovery.get("origin_count") != len(witnesses):
        raise IndirectTargetDependencyV2Error(
            "profile dispatch has no exact finite target/origin inventory"
        )
    dependencies = _string_array_allow_empty(
        recovery.get("analysis_dependencies"), "profile-dispatch dependencies"
    )
    receiver_instances: list[dict[str, Any]] = []
    expected_targets: set[tuple[str, str, str, int | None]] = set()
    for witness in witnesses:
        kind = witness.get("kind")
        key = witness.get("key")
        raw_dependencies = witness.get("authority_dependencies", [])
        witness_dependencies = _string_array_allow_empty(
            raw_dependencies, "profile-dispatch witness dependencies"
        )
        if not isinstance(key, list):
            raise IndirectTargetDependencyV2Error(
                "profile-dispatch witness key must be an array"
            )
        if kind == "interface_method" and len(key) == 4:
            profile_sha256 = _digest(key[0], "interface profile SHA-256")
            view_id = _nonempty_string(key[1], "interface view ID")
            slot = _u32(key[2], "interface dispatch slot")
            producer_id = _nonempty_string(key[3], "interface producer ID")
            expected_targets.add(("pe32-interface-method", profile_sha256, view_id, slot))
            receiver_instances.append({
                "origin_kind": kind,
                "profile_sha256": profile_sha256,
                "view_id": view_id,
                "dispatch_slot": slot,
                "producer_id": producer_id,
                "authority_dependencies": witness_dependencies,
            })
            continue
        if kind == "operation_target" and len(key) == 3:
            profile_sha256 = _digest(key[0], "operation profile SHA-256")
            operation_id = _nonempty_string(key[1], "operation ID")
            producer_id = _nonempty_string(key[2], "operation producer ID")
            expected_targets.add(("pe32-operation", profile_sha256, operation_id, None))
            receiver_instances.append({
                "origin_kind": kind,
                "profile_sha256": profile_sha256,
                "operation_id": operation_id,
                "producer_id": producer_id,
                "authority_dependencies": witness_dependencies,
            })
            continue
        raise IndirectTargetDependencyV2Error(
            "profile dispatch requires instance-bearing method or operation origins"
        )
    observed_targets: set[tuple[str, str, str, int | None]] = set()
    for target in targets:
        protocol = _mapping(
            target.get("external_protocol"), "profile-dispatch external protocol"
        )
        kind = protocol.get("kind")
        profile_sha256 = _digest(
            protocol.get("profile_sha256"), "external profile SHA-256"
        )
        if kind == "pe32-interface-method":
            observed_targets.add((
                kind,
                profile_sha256,
                _nonempty_string(protocol.get("interface_id"), "interface ID"),
                _u32(protocol.get("slot"), "interface method slot"),
            ))
        elif kind == "pe32-operation":
            observed_targets.add((
                kind,
                profile_sha256,
                _nonempty_string(protocol.get("operation_id"), "operation ID"),
                None,
            ))
        else:
            raise IndirectTargetDependencyV2Error(
                "profile dispatch contains a non-profile external target"
            )
    if observed_targets != expected_targets:
        raise IndirectTargetDependencyV2Error(
            "profile-dispatch targets disagree with receiver origin witnesses"
        )
    canonical_instances = sorted(
        receiver_instances,
        key=lambda row: canonical_json_bytes(row),
    )
    if len({canonical_json_bytes(row) for row in canonical_instances}) != len(
        canonical_instances
    ):
        raise IndirectTargetDependencyV2Error(
            "profile dispatch contains duplicate receiver origins"
        )
    return {
        "format": PROFILE_DISPATCH_DEPENDENCY_V2_FORMAT,
        "dependency_kind": "profile_dispatch",
        "source": {
            "exit_id": _nonempty_string(recovery.get("id"), "indirect exit ID"),
            "unit_id": _nonempty_string(
                recovery.get("source_unit_id"), "indirect source unit ID"
            ),
            "event_index": (
                None
                if recovery.get("source_event_index") is None
                else _u32(
                    recovery.get("source_event_index"),
                    "indirect source event index",
                )
            ),
        },
        "target_expression_sha256": _sha256(expression),
        "receiver_instances": canonical_instances,
        "receiver_inventory_sha256": _sha256(canonical_instances),
        "external_target_inventory_sha256": _sha256(targets),
        "analysis_dependencies": dependencies,
        "requires_live_receiver": True,
        "requires_receiver_pointer_equality": False,
        "target_set_value_independent_given_live_receiver": True,
    }


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


def _string_array_allow_empty(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise IndirectTargetDependencyV2Error(
            f"{context} must be an array of nonempty strings"
        )
    if value != sorted(set(value)):
        raise IndirectTargetDependencyV2Error(
            f"{context} must be sorted and contain no duplicates"
        )
    return list(value)


def _nonempty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise IndirectTargetDependencyV2Error(
            f"{context} must be a nonempty string"
        )
    return value


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
    "PROFILE_DISPATCH_DEPENDENCY_V2_FORMAT",
    "IndirectTargetDependencyV2Error",
    "build_bounded_selector_dependency_v2",
    "build_profile_dispatch_dependency_v2",
    "has_profile_dispatch_dependency_v2",
    "has_value_independent_target_set_v2",
    "validate_bounded_selector_dependency_v2",
    "validate_profile_dispatch_dependency_v2",
]
