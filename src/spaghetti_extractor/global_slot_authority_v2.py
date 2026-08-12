"""Promote cold-replayed mutable-slot evidence into typed v2 authority."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Mapping, Sequence

from .entry_fact_derivation_v2 import promote_complete_global_slot_evidence_v2
from .authority_bindings_v2 import (
    BinaryBinding,
    EventBinding,
    UnitBinding,
    canonical_json_bytes,
)
from .checked_memory_access_v2 import (
    CheckedMemoryAccessV2Error,
    validate_checked_memory_access_facts_v2,
)
from .checked_memory_address_domain_v2 import (
    CheckedMemoryAddressDomainV2Error,
    validate_checked_memory_address_domains_v2,
)
from .global_slot_proposal_v2 import propose_global_slot_invariant
from .global_slot_image_v2 import (
    GlobalSlotImageV2Error,
    build_image_span_binding_v2,
    loader_initial_bytes_v2,
)
from .machine_ir_authority_v2 import (
    MachineIRAuthorityV2Error,
    recompute_event_binding,
    recompute_unit_binding,
)
from .memory_range_invariants_v2 import validate_memory_range_invariants_v2
from .launch_memory_ranges_v2 import (
    CHECKED_LAUNCH_SPATIAL_FACT_V2_FORMAT,
    validate_launch_memory_range_analysis_v2,
)
from .stage_binary import StageABinary
from .stack_range_analysis_v2 import validate_stack_range_analysis_v2


GLOBAL_SLOT_AUTHORITY_V2_FORMAT = "spaghetti-extractor-global-slot-authority-v2"
GLOBAL_SLOT_PROMOTION_V2_FORMAT = "spaghetti-extractor-global-slot-promotion-v2"
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
    stack_call_site_effects: Sequence[Mapping[str, Any]] = (),
    stack_finite_offset_budget: int = 256,
    launch_memory_range_analysis: Mapping[str, Any] | None = None,
    launch_memory_assumptions: Mapping[str, Any] | None = None,
    promotion_only: bool = False,
) -> dict[str, Any]:
    """Build checked slot facts or a non-authorizing fixed-point promotion.

    ``promotion_only`` is used immediately after stack-range derivation inside
    the joint fixed point. It verifies that the slot analysis copied the exact
    just-produced spatial inventory, but defers independent stack replay to
    ``replay_global_slot_authority_v2``. The resulting artifact has a distinct
    format and cannot authorize candidate generation.
    """

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
    event_bindings = _memory_event_bindings(
        units,
        unit_bindings=unit_bindings,
        issues=issues,
    )
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
    raw_address_domains = global_slot_analysis.get(
        "checked_memory_address_domains"
    )
    if not isinstance(raw_address_domains, list) or any(
        not isinstance(row, Mapping) for row in raw_address_domains
    ):
        issues.append(_issue(
            "violated",
            "checked_memory_address_domain_inventory_corrupt",
        ))
    elif raw_address_domains:
        try:
            validate_checked_memory_address_domains_v2(
                raw_address_domains,
                units=units,
                binary=binary,
                interprocedural_authority_sha256=interprocedural_sha256,
            )
        except (
            CheckedMemoryAddressDomainV2Error,
            TypeError,
            ValueError,
        ) as exc:
            issues.append(_issue(
                "violated",
                "checked_memory_address_domain_binding_invalid",
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
        stack_spatial = [
            row
            for row in raw_spatial_facts
            if row.get("format") != CHECKED_LAUNCH_SPATIAL_FACT_V2_FORMAT
        ]
        launch_spatial = [
            row
            for row in raw_spatial_facts
            if row.get("format") == CHECKED_LAUNCH_SPATIAL_FACT_V2_FORMAT
        ]
        expected_spatial: list[dict[str, Any]] = []
        if stack_spatial:
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
                    if promotion_only:
                        produced_spatial = stack_range_analysis.get(
                            "checked_spatial_facts"
                        )
                        if not isinstance(produced_spatial, list) or any(
                            not isinstance(row, Mapping)
                            for row in produced_spatial
                        ):
                            raise ValueError(
                                "stack-range spatial inventory is malformed"
                            )
                        expected_spatial.extend(
                            copy.deepcopy(dict(row))
                            for row in produced_spatial
                        )
                    else:
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
                            call_site_effects=stack_call_site_effects,
                            checked_memory_access_facts=raw_access_facts,
                            interprocedural_authority_sha256=(
                                interprocedural_sha256
                            ),
                            finite_offset_budget=stack_finite_offset_budget,
                        )
                        expected_spatial.extend(
                            dict(row) for row in replayed.values()
                        )
                except (TypeError, ValueError) as exc:
                    issues.append(_issue(
                        "violated",
                        "checked_memory_spatial_binding_invalid",
                        detail=str(exc),
                    ))
        if launch_spatial:
            if (
                not isinstance(launch_memory_range_analysis, Mapping)
                or not isinstance(launch_memory_assumptions, Mapping)
            ):
                issues.append(_issue(
                    "violated",
                    "launch_memory_spatial_replay_inputs_missing",
                ))
            else:
                try:
                    replayed_launch = validate_launch_memory_range_analysis_v2(
                        launch_memory_range_analysis,
                        units=units,
                        launch_assumptions=launch_memory_assumptions,
                        pe_sha256=pe_sha256,
                        machine_ir_sha256=machine_ir_sha256,
                        image_base=image_base,
                        size_of_image=size_of_image,
                    )
                    expected_spatial.extend(
                        dict(row) for row in replayed_launch.values()
                    )
                except (TypeError, ValueError) as exc:
                    issues.append(_issue(
                        "violated",
                        "launch_memory_spatial_binding_invalid",
                        detail=str(exc),
                    ))
        if not any(
            row.get("code") in {
                "checked_memory_spatial_replay_inputs_missing",
                "checked_memory_spatial_binding_invalid",
                "launch_memory_spatial_replay_inputs_missing",
                "launch_memory_spatial_binding_invalid",
            }
            for row in issues
        ):
            try:
                expected_spatial.sort(
                    key=lambda row: (
                        str(row.get("unit_id")),
                        int(row.get("event_index", -1)),
                        str(row.get("id")),
                    )
                )
                if raw_spatial_facts != expected_spatial:
                    raise ValueError(
                        "global-slot spatial inventory differs from exact replay"
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
    checks: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    record_addresses: set[int] = set()
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
    promoted_by_address = {
        int(slot["address"]): slot
        for slot in promoted.get("static_interface_slots", ())
        if isinstance(slot, Mapping)
        and isinstance(slot.get("address"), int)
        and not isinstance(slot.get("address"), bool)
    }
    for address, evidence in sorted(evidence_by_address.items()):
        slot = promoted_by_address.get(address)
        check = propose_global_slot_invariant(
            evidence,
            interface_slot=slot,
            unit_bindings=unit_bindings,
            event_bindings=event_bindings,
            image_span_bindings=image_span_bindings,
            image_base=image_base,
            size_of_image=size_of_image,
        )
        checks.append(check)
        if slot is not None and (
            check.get("status") != "complete"
            or not isinstance(check.get("proposal"), Mapping)
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
        elif slot is not None:
            records.append(dict(check["proposal"]))
            record_addresses.add(address)

        read_checks = check.get("read_checks")
        if not isinstance(read_checks, list):
            issues.append(_issue(
                "violated",
                "global_slot_per_read_checks_corrupt",
                address=address,
            ))
            continue
        for read_check in read_checks:
            if not isinstance(read_check, Mapping):
                issues.append(_issue(
                    "violated",
                    "global_slot_per_read_check_corrupt",
                    address=address,
                ))
                continue
            proposal = read_check.get("proposal")
            if read_check.get("status") == "complete" and isinstance(
                proposal, Mapping
            ):
                records.append(dict(proposal))
                record_addresses.add(address)
            elif read_check.get("status") == "violated":
                issues.append(_issue(
                    "violated",
                    "global_slot_per_read_replay_contradiction",
                    address=address,
                    read_index=read_check.get("read_index"),
                ))
    missing_promoted = sorted(promoted_addresses - set(evidence_by_address))
    if missing_promoted:
        issues.append(_issue(
            "violated",
            "promoted_global_slot_evidence_missing",
            addresses=missing_promoted,
        ))
    by_content_id: dict[str, dict[str, Any]] = {}
    for record in records:
        content_id = record.get("content_id")
        if not isinstance(content_id, str) or content_id in by_content_id:
            issues.append(_issue(
                "violated",
                "global_slot_invariant_record_duplicated",
                content_id=content_id,
            ))
            continue
        by_content_id[content_id] = record
    records = list(by_content_id.values())
    records.sort(key=lambda row: str(row.get("content_id")))
    checks.sort(key=lambda row: int(row.get("address", -1)))
    promoted_evidence = [
        dict(row)
        for row in evidence_rows
        if isinstance(row, Mapping)
        and row.get("address") in promoted_addresses | record_addresses
    ]
    status = _status(issues)
    if status != "complete":
        records = []
    body = {
        "format": (
            GLOBAL_SLOT_PROMOTION_V2_FORMAT
            if promotion_only
            else GLOBAL_SLOT_AUTHORITY_V2_FORMAT
        ),
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
            "checked_spatial_facts_require_exact_source_replay": (
                not promotion_only
            ),
            "inductive_facts_require_final_complete_rooted_graph": True,
            "tainted_slots_exported": False,
            "incomplete_evidence_exported": False,
            "event_facts_seeded_globally": False,
            **(
                {
                    "candidate_acceptance_authority": False,
                    "independent_source_replay_deferred": True,
                }
                if promotion_only
                else {}
            ),
        },
    }
    return {
        **body,
        (
            "promotion_sha256" if promotion_only else "authority_sha256"
        ): _sha256(body),
    }


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


def _with_replay_violation(
    authority: Mapping[str, Any],
    *,
    code: str,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        key: json.loads(canonical_json_bytes(value))
        for key, value in authority.items()
        if key != "authority_sha256"
    }
    body["status"] = "violated"
    body["global_slot_invariants"] = []
    body["issues"] = sorted(
        [
            *body.get("issues", []),
            _issue("violated", code, **dict(details or {})),
        ],
        key=lambda row: (str(row.get("status")), str(row.get("code"))),
    )
    return {**body, "authority_sha256": _sha256(body)}


def _violated_replay_authority(
    code: str, **details: Any
) -> dict[str, Any]:
    body = {
        "format": GLOBAL_SLOT_AUTHORITY_V2_FORMAT,
        "status": "violated",
        "source_analysis": {"status": None, "analysis_sha256": None},
        "authoritative_provenance": {
            "static_interface_slots": [],
            "rejected_tainted_slots": [],
        },
        "global_slot_evidence": [],
        "global_slot_invariants": [],
        "checks": [],
        "issues": [_issue("violated", code, **details)],
        "constraints": {
            "cold_replay_required": True,
            "checked_spatial_facts_require_exact_source_replay": True,
            "inductive_facts_require_final_complete_rooted_graph": True,
            "tainted_slots_exported": False,
            "incomplete_evidence_exported": False,
            "event_facts_seeded_globally": False,
        },
    }
    return {**body, "authority_sha256": _sha256(body)}


def _issue(status: str, code: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "code": code, **details}


def _memory_event_bindings(
    units: Sequence[Mapping[str, Any]],
    *,
    unit_bindings: Mapping[str, UnitBinding],
    issues: list[dict[str, Any]],
) -> dict[tuple[str, int], EventBinding]:
    result: dict[tuple[str, int], EventBinding] = {}
    for unit_index, row in enumerate(units):
        unit_id = row.get("id") if isinstance(row, Mapping) else None
        binding = unit_bindings.get(unit_id) if isinstance(unit_id, str) else None
        semantics = row.get("semantics") if isinstance(row, Mapping) else None
        events = (
            semantics.get("memory_events")
            if isinstance(semantics, Mapping)
            else None
        )
        if binding is None or not isinstance(events, list):
            issues.append(_issue(
                "violated",
                "global_slot_memory_event_inventory_corrupt",
                unit_index=unit_index,
                unit_id=unit_id,
            ))
            continue
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping):
                issues.append(_issue(
                    "violated",
                    "global_slot_memory_event_corrupt",
                    unit_id=unit_id,
                    event_index=event_index,
                ))
                continue
            try:
                result[(unit_id, event_index)] = recompute_event_binding(
                    binding,
                    event,
                    event_index=event_index,
                )
            except (MachineIRAuthorityV2Error, TypeError, ValueError) as exc:
                issues.append(_issue(
                    "violated",
                    "global_slot_memory_event_binding_invalid",
                    unit_id=unit_id,
                    event_index=event_index,
                    detail=str(exc),
                ))
    return dict(sorted(result.items()))


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
    "GLOBAL_SLOT_PROMOTION_V2_FORMAT",
    "apply_global_slot_authority_v2",
    "build_global_slot_authority_v2",
]
