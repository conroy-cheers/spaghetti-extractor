"""Promote cold-replayed mutable-slot evidence into typed v2 authority."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from .entry_fact_derivation_v2 import promote_complete_global_slot_evidence_v2
from .authority_bindings_v2 import BinaryBinding, canonical_json_bytes
from .checked_memory_access_v2 import (
    CheckedMemoryAccessV2Error,
    validate_checked_memory_access_facts_v2,
)
from .global_slot_proposal_v2 import propose_global_slot_invariant
from .global_slot_image_v2 import (
    GlobalSlotImageV2Error,
    build_image_span_binding_v2,
    loader_initial_bytes_v2,
)
from .machine_ir_authority_v2 import recompute_unit_binding
from .memory_range_invariants_v2 import validate_memory_range_invariants_v2
from .stage_binary import StageABinary
from .stack_range_analysis_v2 import validate_stack_range_analysis_v2


GLOBAL_SLOT_AUTHORITY_V2_FORMAT = "spaghetti-extractor-global-slot-authority-v2"
GLOBAL_SLOT_ANALYSIS_V2_FORMAT = "stage-a-global-slot-analysis-v2"


def build_global_slot_authority_v2(
    *,
    provenance: Mapping[str, Any],
    global_slot_analysis: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    pe_sha256: str,
    machine_ir_sha256: str,
    image_base: int,
    size_of_image: int,
    original_binary: StageABinary | None = None,
    stack_range_analysis: Mapping[str, Any] | None = None,
    stack_graph: Mapping[str, Any] | None = None,
    stack_launch_assumptions: Mapping[str, Any] | None = None,
    stack_call_summaries: Mapping[str, Any] | None = None,
    stack_indirect_recoveries: Sequence[Mapping[str, Any]] = (),
    stack_finite_offset_budget: int = 256,
) -> dict[str, Any]:
    """Build only facts that complete cold replay can authorize."""

    issues = _analysis_issues(global_slot_analysis)
    binary = BinaryBinding(pe_sha256, machine_ir_sha256)
    if original_binary is not None and (
        original_binary.sha256 != pe_sha256
        or original_binary.image_base != image_base
        or original_binary.size_of_image != size_of_image
    ):
        issues.append(_issue("violated", "global_slot_pe_binding_mismatch"))
    unit_bindings = {
        binding.unit_id: binding
        for row in units
        for binding in (recompute_unit_binding(row, binary=binary),)
    }
    raw_access_facts = global_slot_analysis.get("checked_memory_access_facts")
    analysis_bindings = global_slot_analysis.get("bindings")
    interprocedural_sha256 = (
        analysis_bindings.get("interprocedural_authority_sha256")
        if isinstance(analysis_bindings, Mapping)
        else None
    )
    if not isinstance(raw_access_facts, list) or any(
        not isinstance(row, Mapping) for row in raw_access_facts
    ):
        issues.append(_issue(
            "violated",
            "checked_memory_access_inventory_corrupt",
        ))
    elif raw_access_facts:
        try:
            validate_checked_memory_access_facts_v2(
                raw_access_facts,
                units=units,
                binary=binary,
                interprocedural_authority_sha256=interprocedural_sha256,
            )
        except (CheckedMemoryAccessV2Error, TypeError, ValueError) as exc:
            issues.append(_issue(
                "violated",
                "checked_memory_access_binding_invalid",
                detail=str(exc),
            ))
    raw_spatial_facts = global_slot_analysis.get(
        "checked_memory_spatial_facts"
    )
    if not isinstance(raw_spatial_facts, list) or any(
        not isinstance(row, Mapping) for row in raw_spatial_facts
    ):
        issues.append(_issue(
            "violated",
            "checked_memory_spatial_inventory_corrupt",
        ))
    elif raw_spatial_facts:
        if (
            not isinstance(stack_range_analysis, Mapping)
            or not isinstance(stack_graph, Mapping)
            or not isinstance(stack_launch_assumptions, Mapping)
        ):
            issues.append(_issue(
                "violated",
                "checked_memory_spatial_replay_inputs_missing",
            ))
        else:
            try:
                replayed = validate_stack_range_analysis_v2(
                    stack_range_analysis,
                    units=units,
                    graph=stack_graph,
                    launch_assumptions=stack_launch_assumptions,
                    pe_sha256=pe_sha256,
                    machine_ir_sha256=machine_ir_sha256,
                    image_base=image_base,
                    size_of_image=size_of_image,
                    call_summaries=stack_call_summaries,
                    indirect_recoveries=stack_indirect_recoveries,
                    finite_offset_budget=stack_finite_offset_budget,
                )
                expected_spatial = [
                    dict(row) for row in replayed.values()
                ]
                if raw_spatial_facts != expected_spatial:
                    raise ValueError(
                        "global-slot spatial inventory differs from stack replay"
                    )
            except (TypeError, ValueError) as exc:
                issues.append(_issue(
                    "violated",
                    "checked_memory_spatial_binding_invalid",
                    detail=str(exc),
                ))
    raw_memory_ranges = global_slot_analysis.get(
        "memory_range_invariant_analysis"
    )
    if raw_memory_ranges is not None:
        if not isinstance(raw_memory_ranges, Mapping):
            issues.append(_issue(
                "violated", "memory_range_invariant_inventory_corrupt"
            ))
        else:
            try:
                validate_memory_range_invariants_v2(
                    raw_memory_ranges,
                    units=units,
                    binary_sha256=pe_sha256,
                    machine_ir_sha256=machine_ir_sha256,
                )
            except (TypeError, ValueError) as exc:
                issues.append(_issue(
                    "violated",
                    "memory_range_invariant_binding_invalid",
                    detail=str(exc),
                ))
    raw_evidence = global_slot_analysis.get("global_slot_evidence")
    evidence_rows = raw_evidence if isinstance(raw_evidence, list) else []
    if not isinstance(raw_evidence, list):
        issues.append(_issue("violated", "global_slot_evidence_inventory_corrupt"))
    evidence_by_address = {
        int(row["address"]): row
        for row in evidence_rows
        if isinstance(row, Mapping)
        and isinstance(row.get("address"), int)
        and not isinstance(row.get("address"), bool)
    }
    promoted = promote_complete_global_slot_evidence_v2(provenance, evidence_rows)
    promoted_addresses = {
        int(row["address"])
        for row in promoted.get("static_interface_slots", ())
        if isinstance(row, Mapping)
        and isinstance(row.get("address"), int)
        and not isinstance(row.get("address"), bool)
    }
    promoted_evidence = [
        dict(row)
        for row in evidence_rows
        if isinstance(row, Mapping) and row.get("address") in promoted_addresses
    ]
    checks: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    image_span_bindings = {}
    for address, evidence in sorted(evidence_by_address.items()):
        launch = evidence.get("launch_initializer")
        if launch is None:
            continue
        if original_binary is None:
            issues.append(_issue(
                "incomplete",
                "global_slot_exact_pe_launch_evidence_missing",
                address=address,
            ))
            continue
        try:
            rva = address - image_base
            data, _initialization_kind = loader_initial_bytes_v2(
                original_binary,
                rva_start=rva,
                width_bytes=4,
            )
            expected_origin = {
                "kind": "exact_bits",
                "value": int.from_bytes(data, "little"),
                "width_bits": 32,
            }
            if (
                not isinstance(launch, Mapping)
                or launch.get("kind") != "launch_image"
                or launch.get("address") != address
                or launch.get("value_origin") != expected_origin
            ):
                issues.append(_issue(
                    "violated",
                    "global_slot_launch_value_contradiction",
                    address=address,
                ))
                continue
            image_span_bindings[address] = build_image_span_binding_v2(
                original_binary,
                machine_ir_sha256=machine_ir_sha256,
                rva_start=rva,
                width_bytes=4,
            )
        except GlobalSlotImageV2Error as exc:
            issues.append(_issue(
                "incomplete",
                "global_slot_launch_span_unsupported",
                address=address,
                detail=str(exc),
            ))
    for slot in promoted.get("static_interface_slots", ()):
        address = slot.get("address") if isinstance(slot, Mapping) else None
        evidence = evidence_by_address.get(address) if isinstance(address, int) else None
        if evidence is None:
            issues.append(_issue("violated", "promoted_global_slot_evidence_missing"))
            continue
        check = propose_global_slot_invariant(
            evidence,
            interface_slot=slot,
            unit_bindings=unit_bindings,
            image_span_bindings=image_span_bindings,
            image_base=image_base,
            size_of_image=size_of_image,
        )
        checks.append(check)
        if check.get("status") != "complete" or not isinstance(
            check.get("proposal"), Mapping
        ):
            issues.append(_issue(
                (
                    "violated"
                    if check.get("status") == "violated"
                    else "incomplete"
                ),
                (
                    "promoted_global_slot_replay_contradiction"
                    if check.get("status") == "violated"
                    else "promoted_global_slot_replay_incomplete"
                ),
                address=address,
            ))
            continue
        records.append(dict(check["proposal"]))
    records.sort(key=lambda row: str(row.get("content_id")))
    checks.sort(key=lambda row: int(row.get("address", -1)))
    status = _status(issues)
    body = {
        "format": GLOBAL_SLOT_AUTHORITY_V2_FORMAT,
        "status": status,
        "source_analysis": {
            "status": global_slot_analysis.get("status"),
            "analysis_sha256": global_slot_analysis.get("analysis_sha256"),
        },
        "authoritative_provenance": promoted,
        "global_slot_evidence": promoted_evidence,
        "global_slot_invariants": records,
        "checks": checks,
        "issues": sorted(issues, key=lambda row: (row["status"], row["code"])),
        "constraints": {
            "cold_replay_required": True,
            "checked_spatial_facts_require_full_stack_replay": True,
            "inductive_facts_require_final_complete_rooted_graph": True,
            "tainted_slots_exported": False,
            "incomplete_evidence_exported": False,
        },
    }
    return {**body, "authority_sha256": _sha256(body)}


def apply_global_slot_authority_v2(
    provenance: Mapping[str, Any], authority: Mapping[str, Any]
) -> dict[str, Any]:
    """Attach only checked slot facts to fresh interprocedural metadata."""

    if (
        authority.get("format") != GLOBAL_SLOT_AUTHORITY_V2_FORMAT
        or authority.get("status") != "complete"
    ):
        promoted_slots: list[Any] = []
    else:
        checked = authority.get("authoritative_provenance")
        raw_slots = checked.get("static_interface_slots") if isinstance(checked, Mapping) else None
        promoted_slots = raw_slots if isinstance(raw_slots, list) else []
    result = json.loads(canonical_json_bytes(provenance))
    result["static_interface_slots"] = json.loads(canonical_json_bytes(promoted_slots))
    result["rejected_tainted_slots"] = []
    return result


def _analysis_issues(analysis: Mapping[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if analysis.get("format") != GLOBAL_SLOT_ANALYSIS_V2_FORMAT:
        issues.append(_issue("violated", "global_slot_analysis_format_mismatch"))
        return issues
    body = dict(analysis)
    observed = body.pop("analysis_sha256", None)
    if observed != _sha256(body):
        issues.append(_issue("violated", "global_slot_analysis_hash_mismatch"))
    cold = analysis.get("cold_replay")
    if (
        not isinstance(cold, Mapping)
        or cold.get("status") != "complete"
        or cold.get("unseeded") is not True
        or cold.get("first_sha256") != cold.get("replay_sha256")
    ):
        issues.append(_issue("violated", "global_slot_cold_replay_missing"))
    if analysis.get("status") == "violated":
        issues.append(_issue("violated", "global_slot_analysis_violated"))
    return issues


def _issue(status: str, code: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "code": code, **details}


def _status(issues: Sequence[Mapping[str, Any]]) -> str:
    if any(row.get("status") == "violated" for row in issues):
        return "violated"
    if any(row.get("status") == "incomplete" for row in issues):
        return "incomplete"
    return "complete"


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "GLOBAL_SLOT_AUTHORITY_V2_FORMAT",
    "apply_global_slot_authority_v2",
    "build_global_slot_authority_v2",
]
