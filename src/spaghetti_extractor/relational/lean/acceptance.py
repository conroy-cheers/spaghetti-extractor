from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from ...stage_binary import StageABinary, StageAInputError
from ...util import write_json
from ..analyses.external import (
    _machine_import_call_contract_identity,
    _register_offset_witness,
    _semantic_external_target_identity,
)
from ..artifacts import write_text_if_changed as _write_text_if_changed
from ..schema import (
    FLAG_BITS,
    RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
    choose_relational_acceptance_theorem,
)
from .expressions import (
    _lean_acceptance_outcome,
    _lean_external_target,
    _lean_paired_exact_expr_witness,
    _lean_register_offset_witness,
    _lean_register_output_claim,
    _lean_return_slot_offset_pair,
    _lean_semantic_bool_expr,
    _lean_semantic_expr,
    _lean_stack_window,
    _lean_stack_window_transfer_claim,
    _lean_state_invariant,
)
from .affine_linked_control import (
    write_relational_affine_linked_call_binding_modules,
    write_relational_affine_linked_control_binding_modules,
    write_relational_affine_linked_external_call_binding_modules,
    write_relational_affine_linked_memory_binding_modules,
    write_relational_affine_linked_control_module,
)
from .definitions import (
    _has_compositional_normalized_support,
    _lean_region_input_invariant,
    _normalized_behavior_fast_path,
)
from .common import _lean_register_relation_pair
from .callbacks import _lean_acceptance_callback_return_node
from .lockstep_environment import relational_exact_lockstep_acceptance_source
from .opaque_lockstep_environment import (
    OPAQUE_LOCKSTEP_ENVIRONMENT_FORMAT,
    parse_opaque_lockstep_environment_artifact,
    relational_opaque_lockstep_acceptance_source,
    relational_opaque_lockstep_environment_source,
)
from .acceptance_plan import (
    _checked_infeasible_branch_edge,
    _compact_acceptance_blockers,
    _frame_exact_expr_witness,
    _frame_exact_stack_word_writes_claim,
    _frame_relations_requiring_internal_preservation,
    _paired_frame_expression_witness,
    _retain_checked_linked_control_links,
    _whole_program_acceptance_plan,
    _witnessed_linked_call_target_control_state,
)
from .acceptance_running import (
    _lean_acceptance_running_node,
    _lean_acceptance_running_target,
    _lean_external_jump_return_slot_inventory_transfer_claim,
    _lean_external_jump_return_slot_transfer_claim,
    _lean_external_return_slot_inventory_transfer_claim,
    _lean_external_return_slot_transfer_claim,
    _lean_return_slot_exact_word_transfer_claim,
    _lean_return_slot_frame_inventory_transfer_claim,
    _lean_return_slot_frame_transfer_claim,
    _lean_return_slot_offset_inventory,
    _lean_runtime_call_import_transfer_claim,
    _lean_runtime_call_import_transfer_claims,
    _runtime_frame_protected_bytes,
)

_LEAN_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "lean" / "StageA"


def _lean_frame_exact_guard_claim(claim: dict[str, Any]) -> str:
    if claim.get("profile") != "paired_exact_guard_v1":
        raise StageAInputError(
            f"unsupported active-frame guard claim: {claim.get('profile')!r}"
        )
    return (
        "{ originalGuard := "
        + _lean_semantic_bool_expr(claim["original_guard"])
        + ", candidateGuard := "
        + _lean_semantic_bool_expr(claim["candidate_guard"])
        + ", witness := "
        + _lean_paired_exact_expr_witness(claim["witness"])
        + " }"
    )


def _lean_preserved_input_flags_proof(
    *,
    claim: dict[str, Any],
    source_region_index: int,
    original_behavior: str,
    candidate_behavior: str,
) -> str:
    """Replay a checked preserved-input-flags claim for a linked step."""
    if claim.get("profile") != "preserved_input_flags_v1":
        raise StageAInputError(
            f"unsupported linked flag-transfer claim: {claim.get('profile')!r}"
        )
    bits = [int(bit) for bit in claim.get("bits", [])]
    if not bits:
        return "rfl"
    flag_theorems = {
        0: "evalNormalizedFlags_extract_cf_input_of_checked",
        2: "evalNormalizedFlags_extract_pf_input_of_checked",
        4: "evalNormalizedFlags_extract_af_input_of_checked",
        6: "evalNormalizedFlags_extract_zf_input_of_checked",
        7: "evalNormalizedFlags_extract_sf_input_of_checked",
        11: "evalNormalizedFlags_extract_of_input_of_checked",
    }

    def prove_from(index: int, indent: str) -> list[str]:
        bit = bits[index]
        lines = [f"{indent}apply flagsRelated_cons_of_eq"]
        lines.append(
            f"{indent}· simp only [NormalizedSymbolicBehavior.eval_eflags]"
        )
        proof_indent = indent + "  "
        if bit == 10:
            lines.append(
                f"{proof_indent}rw [evalNormalizedFlags_extract_df, "
                "evalNormalizedFlags_extract_df]"
            )
        else:
            theorem = flag_theorems.get(bit)
            if theorem is None:
                raise StageAInputError(
                    f"unsupported preserved linked flag bit: {bit}"
                )
            lines.append(
                f"{proof_indent}rw [{theorem} originalState "
                f"{original_behavior}.flags (by decide), {theorem} "
                f"candidateState {candidate_behavior}.flags (by decide)]"
            )
        lines.append(
            f"{proof_indent}exact flagsRelated_of_contains "
            f"region{source_region_index}.flagInputs originalState.eflags "
            "candidateState.eflags inputFlags (by decide)"
        )
        if index + 1 == len(bits):
            lines.append(f"{indent}· rfl")
        else:
            nested = prove_from(index + 1, indent + "  ")
            lines.append(f"{indent}· " + nested[0].lstrip())
            lines.extend(nested[1:])
        return lines

    return "\n".join(prove_from(0, ""))














def _opaque_argument_source(expression: Any) -> dict[str, Any] | None:
    if not isinstance(expression, Mapping):
        return None
    operation = expression.get("op")
    if operation == "constant":
        value = expression.get("value")
        if type(value) is int and 0 <= value < 2**32:
            return {"kind": "constant", "value": int(value)}
        return None
    if operation == "input_reg":
        register = expression.get("reg")
        if register in {
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        }:
            return {"kind": "register", "register": str(register)}
        return None
    if operation != "read32":
        return None
    witness = _register_offset_witness(expression.get("address"), "esp")
    if witness is None:
        return None
    return {"kind": "stack_word", "offset": int(witness[1])}


def _opaque_region_input_invariant(region: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "register_relations": list(region.get("input_relations", [])),
        "import_register_relations": list(region.get("input_import_relations", [])),
        "dynamic_register_range_relations": list(
            region.get("input_dynamic_range_relations", [])
        ),
        "dynamic_stack_range_relations": list(
            region.get("input_dynamic_stack_range_relations", [])
        ),
        "flag_bits": list(region.get("flag_inputs", FLAG_BITS)),
        "bounds": list(region.get("bounds", [])),
        "address_separations": list(region.get("address_separations", [])),
        "stack_windows": list(region.get("stack_windows", [])),
        "predicates": list(region.get("state_predicates", [])),
    }


def _opaque_import_iat_rvas(
    binary: StageABinary,
    identity: tuple[str, str, str | int],
) -> list[int]:
    matches: list[int] = []
    for imported in binary.imports:
        candidate = (
            imported.dll.lower(),
            "symbol" if imported.symbol is not None else "ordinal",
            imported.symbol if imported.symbol is not None else imported.ordinal,
        )
        if candidate == identity and imported.thunk_rva is not None:
            matches.append(int(imported.thunk_rva))
    return sorted(matches)


def _opaque_lockstep_inventory_plan(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: Mapping[str, Any],
    behaviors: list[dict[str, Any]],
    plan: Mapping[str, Any],
    external_site_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Propose a complete reachable opaque inventory without proof authority."""
    transitions: list[dict[str, Any]] = []
    protocol_count = 0
    for parent in plan.get("node_steps", []):
        kind = parent.get("kind")
        if kind == "external_protocol":
            protocol_count += 1
            continue
        if kind not in {"external_call", "external_jump", "external_terminate"}:
            continue
        cases = parent.get("cases")
        if isinstance(cases, list):
            for case_index, case in enumerate(cases):
                transitions.append({
                    "kind": kind,
                    "node_id": int(parent["node_id"]),
                    "case_index": case_index,
                    "step": {**parent, **case},
                })
        else:
            transitions.append({
                "kind": kind,
                "node_id": int(parent["node_id"]),
                "case_index": None,
                "step": parent,
            })

    callback_states = list(plan.get("protocol_callback_states") or [])
    tls_root_ids = list(
        (plan.get("launch") or {}).get("tls_callback_node_ids", [])
    )
    # Protocol-only and callback-only graphs remain the responsibility of the
    # existing prototype-dependent exact-lockstep profile.  Once an opaque
    # transition is selected, however, every mixed protocol/callback frontier
    # must be represented by the same opaque event and nested-frame model.
    if not transitions:
        return {
            "status": "not_applicable",
            "required_site_ids": [],
            "site_bindings": [],
            "counts": {
                "returning_or_tail_or_terminal": 0,
                "covered": 0,
                "protocol": protocol_count,
                "callback_states": len(callback_states),
                "tls_roots": len(tls_root_ids),
            },
            "gaps": [],
        }

    gaps: list[dict[str, Any]] = []

    def gap(
        code: str,
        message: str,
        *,
        node_id: int | None = None,
        edge_id: int | None = None,
        count: int | None = None,
    ) -> None:
        item: dict[str, Any] = {
            "code": code,
            "message": message,
            "next_action": (
                "supply one statically extractable normalized event identity, "
                "paired machine argument sources, and bounded memory observations"
            ),
        }
        if node_id is not None:
            item["node_id"] = node_id
        if edge_id is not None:
            item["edge_id"] = edge_id
        if count is not None:
            item["count"] = count
        gaps.append(item)

    if protocol_count:
        gap(
            "opaque_lockstep_protocol_callback_frame_unsupported",
            f"{protocol_count} reachable protocol external nodes require an exact "
            "opaque callback/action and nested-frame refinement",
            count=protocol_count,
        )
    if callback_states:
        gap(
            "opaque_lockstep_callback_entry_frame_unsupported",
            f"{len(callback_states)} reachable callback control states are not bound "
            "to opaque event identities and nested continuation frames",
            count=len(callback_states),
        )
    if tls_root_ids:
        gap(
            "opaque_lockstep_tls_entry_frame_unsupported",
            f"{len(tls_root_ids)} reachable TLS callback roots are not bound to "
            "opaque nested entry and continuation frames",
            count=len(tls_root_ids),
        )

    candidates_by_edge: dict[int, list[dict[str, Any]]] = {}
    candidates_by_id: dict[int, list[dict[str, Any]]] = {}
    for candidate in external_site_candidates:
        candidate_id = candidate.get("id")
        if type(candidate_id) is int:
            candidates_by_id.setdefault(int(candidate_id), []).append(candidate)
        edge_index = candidate.get("edge_index")
        if type(edge_index) is int:
            candidates_by_edge.setdefault(int(edge_index), []).append(candidate)
    contracts_by_id = {
        int(item["id"]): item
        for item in contract.get("machine_import_call_contracts", [])
        if isinstance(item, Mapping) and type(item.get("id")) is int
    }

    sites_by_id: dict[int, dict[str, Any]] = {}
    site_bindings: list[dict[str, Any]] = []
    covered_transitions = 0
    for transition in transitions:
        kind = str(transition["kind"])
        node_id = int(transition["node_id"])
        step = transition["step"]
        planned_site = step.get("external_site")
        if not isinstance(planned_site, Mapping):
            gap(
                "opaque_lockstep_site_evidence_missing",
                f"external node {node_id} has no checked call-site evidence",
                node_id=node_id,
            )
            continue

        edge_id: int | None = None
        if kind == "external_call":
            edges = step.get("edges", [])
            if not isinstance(edges, list) or len(edges) != 1:
                gap(
                    "opaque_lockstep_external_edge_ambiguous",
                    f"external node {node_id} does not have one returning edge",
                    node_id=node_id,
                )
                continue
            edge_id = int(edges[0]["edge_id"])
            matches = candidates_by_edge.get(edge_id, [])
        else:
            site_id_value = planned_site.get("id")
            matches = (
                candidates_by_id.get(int(site_id_value), [])
                if type(site_id_value) is int else []
            )
        if len(matches) != 1 or matches[0] != planned_site:
            location = f"edge {edge_id}" if edge_id is not None else f"node {node_id}"
            gap(
                "opaque_lockstep_site_evidence_ambiguous",
                f"external {location} has {len(matches)} matching call-site candidates",
                node_id=node_id,
                edge_id=edge_id,
            )
            continue
        site = matches[0]
        dispatch_profile = site.get("dispatch_profile")
        if dispatch_profile not in {
            "decoded_external_call",
            "checked_import_register",
            "checked_direct_import_thunk",
        }:
            gap(
                "opaque_lockstep_indirect_identity_unsupported",
                f"external node {node_id} has unresolved dispatch profile "
                f"{dispatch_profile!r}",
                node_id=node_id,
                edge_id=edge_id,
            )
            continue

        source_index = int(site["source_region_index"])
        target_index = int(site["target_region_index"])
        original_outcome = behaviors[source_index].get("original_ir", {}).get(
            "outcome", {}
        )
        candidate_outcome = behaviors[source_index].get("candidate_ir", {}).get(
            "outcome", {}
        )
        machine_contract = contracts_by_id.get(int(site["machine_contract_id"]))
        identity = (
            _machine_import_call_contract_identity(machine_contract)
            if machine_contract is not None else None
        )
        expected_disposition = "terminates" if kind == "external_terminate" else "returns"
        decoded_identity = _semantic_external_target_identity(
            step.get("decoded_import") or original_outcome.get("import")
        )
        paired_decoded_identity = _semantic_external_target_identity(
            candidate_outcome.get("import")
        )
        decoded_operation_ok = (
            original_outcome.get("op") == candidate_outcome.get("op")
            and (
                original_outcome.get("op") == "external_call"
                if dispatch_profile == "decoded_external_call"
                else original_outcome.get("op") == "indirect_call"
                if dispatch_profile == "checked_import_register"
                else original_outcome.get("op") == "external_jump"
            )
        )
        if (
            machine_contract is None
            or identity is None
            or decoded_identity != identity
            or (
                paired_decoded_identity is not None
                and paired_decoded_identity != identity
            )
            or machine_contract.get("disposition") != expected_disposition
            or not decoded_operation_ok
        ):
            gap(
                "opaque_lockstep_import_identity_unextractable",
                f"external node {node_id} lacks one normalized {expected_disposition} "
                "import identity and disposition",
                node_id=node_id,
                edge_id=edge_id,
            )
            continue

        original_iats = _opaque_import_iat_rvas(original_bin, identity)
        candidate_iats = _opaque_import_iat_rvas(candidate_bin, identity)
        if len(original_iats) != 1 or len(candidate_iats) != 1:
            gap(
                "opaque_lockstep_iat_identity_ambiguous",
                f"external node {node_id} resolves to {len(original_iats)} original "
                f"and {len(candidate_iats)} candidate IAT slots",
                node_id=node_id,
                edge_id=edge_id,
            )
            continue

        if dispatch_profile == "checked_import_register":
            original_arguments = site.get("argument_expressions")
            candidate_arguments = site.get("argument_expressions")
        else:
            original_arguments = original_outcome.get("arguments")
            candidate_arguments = candidate_outcome.get("arguments")
        if (
            not isinstance(original_arguments, list)
            or not isinstance(candidate_arguments, list)
            or len(original_arguments) != len(candidate_arguments)
            or len(site.get("argument_relation_claims") or [])
                != len(original_arguments)
        ):
            gap(
                "opaque_lockstep_argument_inventory_unextractable",
                f"external node {node_id} has no unique paired argument inventory",
                node_id=node_id,
                edge_id=edge_id,
            )
            continue
        argument_sources: list[dict[str, Any]] = []
        argument_failed = False
        for argument_index, (original_argument, candidate_argument) in enumerate(
            zip(original_arguments, candidate_arguments, strict=True)
        ):
            original_source = _opaque_argument_source(original_argument)
            candidate_source = _opaque_argument_source(candidate_argument)
            if original_source is None or candidate_source is None:
                gap(
                    "opaque_lockstep_argument_source_unextractable",
                    f"external node {node_id} argument {argument_index} is not one "
                    "register, stack word, or constant per side",
                    node_id=node_id,
                    edge_id=edge_id,
                )
                argument_failed = True
                break
            argument_sources.append({
                "original": original_source,
                "candidate": candidate_source,
            })
        if argument_failed:
            continue

        memory_observations: list[dict[str, Any]] = []
        memory_failed = False
        footprints = machine_contract.get("memory_footprints")
        memory_effect = machine_contract.get("memory_effect")
        if not isinstance(footprints, list) or memory_effect == "relationalState":
            footprints = []
            memory_failed = True
        if memory_effect in {"readOnly", "argumentRanges"} and not footprints:
            memory_failed = True
        for footprint in footprints:
            size = footprint.get("size") if isinstance(footprint, Mapping) else None
            offset = footprint.get("offset") if isinstance(footprint, Mapping) else None
            base_argument = (
                footprint.get("base_argument")
                if isinstance(footprint, Mapping) else None
            )
            if (
                not isinstance(size, Mapping)
                or size.get("kind") != "fixed"
                or type(size.get("bytes")) is not int
                or int(size["bytes"]) <= 0
                or type(offset) is not int
                or int(offset) < 0
                or type(base_argument) is not int
                or not 0 <= int(base_argument) < len(argument_sources)
            ):
                memory_failed = True
                break
            memory_observations.append({
                "argument_index": int(base_argument),
                "original_offset": int(offset),
                "candidate_offset": int(offset),
                "bytes": int(size["bytes"]),
                "relation": "exact_bytes",
            })
        if len({json.dumps(item, sort_keys=True) for item in memory_observations}) != len(
            memory_observations
        ):
            memory_failed = True
        if memory_failed:
            gap(
                "opaque_lockstep_memory_observation_unextractable",
                f"external node {node_id} lacks one bounded memory observation inventory",
                node_id=node_id,
                edge_id=edge_id,
            )
            continue

        imported: dict[str, Any] = {"dll": identity[0]}
        imported[identity[1]] = identity[2]
        target_invariant = _opaque_region_input_invariant(
            contract["regions"][target_index]
        )
        if site.get("site_kind") == "direct_import_thunk":
            target_invariant["import_register_relations"] = []
        site_payload = {
            "id": int(site["id"]),
            "source_target_id": int(site["source_target_id"]),
            "continuation_target_id": int(site["continuation_target_id"]),
            "disposition": expected_disposition,
            "import": imported,
            "original_iat_rva": original_iats[0],
            "candidate_iat_rva": candidate_iats[0],
            "argument_sources": argument_sources,
            "memory_observations": memory_observations,
            "boundary_invariant": site["boundary_invariant"],
            "target_invariant": target_invariant,
        }
        prior = sites_by_id.setdefault(int(site["id"]), site_payload)
        if prior != site_payload:
            gap(
                "opaque_lockstep_site_identity_ambiguous",
                f"opaque site {site['id']} has inconsistent reachable definitions",
                node_id=node_id,
                edge_id=edge_id,
            )
            continue
        binding = {
            "node_id": node_id,
            "kind": kind,
            "case_index": transition["case_index"],
            "site_id": int(site["id"]),
        }
        if edge_id is not None:
            binding["edge_id"] = edge_id
        site_bindings.append(binding)
        covered_transitions += 1

    sites = sorted(sites_by_id.values(), key=lambda item: int(item["id"]))
    required_site_ids = [int(site["id"]) for site in sites]
    if covered_transitions != len(transitions):
        gap(
            "opaque_lockstep_reachable_coverage_incomplete",
            f"covered {covered_transitions} of {len(transitions)} reachable returning, "
            "tail, or terminating external transitions",
            count=len(transitions) - covered_transitions,
        )
    summary = {
        "required_site_ids": required_site_ids,
        "site_bindings": site_bindings,
        "counts": {
            "returning_or_tail_or_terminal": len(transitions),
            "covered": covered_transitions,
            "protocol": protocol_count,
            "callback_states": len(callback_states),
            "tls_roots": len(tls_root_ids),
        },
    }
    if gaps:
        return {"status": "incomplete", **summary, "gaps": gaps}

    artifact = {
        "format": OPAQUE_LOCKSTEP_ENVIRONMENT_FORMAT,
        "call_sites": sites,
    }
    parse_opaque_lockstep_environment_artifact(artifact)
    return {
        "status": "ready",
        **summary,
        "artifact": artifact,
        "gaps": [],
    }



def _lean_all_listed_proof(theorems: list[str]) -> str:
    return (
        "".join(f"⟨{theorem}, " for theorem in theorems)
        + "True.intro"
        + "⟩" * len(theorems)
    )


def _lean_return_slot_transfer_rule(rule: dict[str, Any]) -> str:
    return (
        "{ originalSourceRegister := ."
        + str(rule["original_source_register"])
        + ", candidateSourceRegister := ."
        + str(rule["candidate_source_register"])
        + ", originalTargetRegister := ."
        + str(rule["original_target_register"])
        + ", candidateTargetRegister := ."
        + str(rule["candidate_target_register"])
        + ", originalOutput := "
        + _lean_register_offset_witness(rule["original_output_witness"])
        + ", candidateOutput := "
        + _lean_register_offset_witness(rule["candidate_output_witness"])
        + ", originalDelta := BitVec.ofNat 32 "
        + str(int(rule["original_delta"]))
        + ", candidateDelta := BitVec.ofNat 32 "
        + str(int(rule["candidate_delta"]))
        + " }"
    )

def _lean_appended_list(names: list[str]) -> str:
    if not names:
        return "[]"
    result = names[-1]
    for name in reversed(names[:-1]):
        result = f"{name} ++ ({result})"
    return result

def _lean_appended_proof(
    chunks: list[dict[str, str]], theorem: str, arguments: str, proof_key: str
) -> str:
    if not chunks:
        return "True.intro"
    proof = chunks[-1][proof_key]
    ids = chunks[-1]["ids"]
    for chunk in reversed(chunks[:-1]):
        proof = (
            f"{theorem} {arguments} {chunk['ids']} ({ids}) "
            f"({chunk[proof_key]}) ({proof})"
        )
        ids = f"{chunk['ids']} ++ ({ids})"
    return proof


def _launch_check_ranges(total: int, chunk_size: int) -> list[tuple[int, int]]:
    """Return an exact, contiguous half-open partition of a launch span."""
    if total < 0:
        raise StageAInputError("launch-check span cannot be negative")
    if chunk_size <= 0:
        raise StageAInputError("launch-check chunk size must be positive")
    return [
        (start, min(chunk_size, total - start))
        for start in range(0, total, chunk_size)
    ]


def _launch_structural_image_ranges(
    *,
    image_base: int,
    span_start: int,
    span_size: int,
    excluded_ranges: list[tuple[int, int]],
    structurally_immutable: bool,
) -> list[tuple[int, int, bool]]:
    """Partition one mapped image span into checked structural/fallback ranges."""
    if span_start < 0 or span_size < 0 or image_base < 0:
        raise StageAInputError("launch image spans cannot be negative")
    span_end = span_start + span_size
    if not structurally_immutable:
        return [(span_start, span_size, False)] if span_size else []

    clipped: list[tuple[int, int]] = []
    for lower, upper in sorted(excluded_ranges):
        if lower < 0 or upper < lower:
            raise StageAInputError("launch image exclusion range is invalid")
        lower = max(span_start, lower)
        upper = min(span_end, upper)
        if lower >= upper:
            continue
        if clipped and lower <= clipped[-1][1]:
            clipped[-1] = (clipped[-1][0], max(clipped[-1][1], upper))
        else:
            clipped.append((lower, upper))

    ranges: list[tuple[int, int, bool]] = []

    def append_range(start: int, stop: int, structural: bool) -> None:
        if start >= stop:
            return
        if (
            ranges
            and ranges[-1][2] == structural
            and ranges[-1][0] + ranges[-1][1] == start
        ):
            previous_start, previous_size, _ = ranges[-1]
            ranges[-1] = (
                previous_start,
                previous_size + stop - start,
                structural,
            )
        else:
            ranges.append((start, stop - start, structural))

    def append_immutable_interval(start: int, stop: int) -> None:
        aligned_start = min(
            start + (-(image_base + start) % 4),
            stop,
        )
        aligned_stop = aligned_start + ((stop - aligned_start) // 4) * 4
        append_range(start, aligned_start, False)
        append_range(aligned_start, aligned_stop, True)
        append_range(aligned_stop, stop, False)

    cursor = span_start
    for lower, upper in clipped:
        append_immutable_interval(cursor, lower)
        append_range(lower, upper, False)
        cursor = upper
    append_immutable_interval(cursor, span_end)
    return ranges


def _lean_acceptance_empty_stack(node_id: int) -> str:
    return (
        "  have stackHoldsNext : RelationalRuntimeCallStackHolds staticProofContext\n"
        f"      ((acceptanceOriginalNormalizedBehavior{node_id}.eval originalState).nextMachineState\n"
        "        originalState)\n"
        f"      ((acceptanceCandidateNormalizedBehavior{node_id}.eval candidateState).nextMachineState\n"
        "        candidateState) [] [] [] := by\n"
        "    simp [RelationalRuntimeCallStackHolds]"
    )















def _lean_frame_exact_word_register_output_claim(
    claim: dict[str, Any],
) -> str:
    if claim.get("profile") != "active_frame_exact_word_register_output_v1":
        raise StageAInputError(
            "unsupported active-frame exact-word register output profile"
        )
    word = claim["word"]
    return (
        "{ sourceLocation := "
        + _lean_return_slot_offset_pair(claim["source_location"])
        + ", word := { originalOffset := " + str(int(word["original"]))
        + ", candidateOffset := " + str(int(word["candidate"]))
        + " }, output := "
        + _lean_register_relation_pair(claim["output"])
        + ", originalAddress := "
        + _lean_register_offset_witness(claim["original_address_witness"])
        + ", candidateAddress := "
        + _lean_register_offset_witness(claim["candidate_address_witness"])
        + ", originalAssembledRead := "
        + str(bool(claim.get("original_assembled_read"))).lower()
        + ", candidateAssembledRead := "
        + str(bool(claim.get("candidate_assembled_read"))).lower()
        + ", originalInputAssembledRead := "
        + str(bool(claim.get("original_input_assembled_read"))).lower()
        + ", candidateInputAssembledRead := "
        + str(bool(claim.get("candidate_input_assembled_read"))).lower()
        + ", originalWriteWitnesses := ["
        + ", ".join(
            _lean_register_offset_witness(witness)
            for witness in claim.get("original_write_witnesses", [])
        )
        + "], candidateWriteWitnesses := ["
        + ", ".join(
            _lean_register_offset_witness(witness)
            for witness in claim.get("candidate_write_witnesses", [])
        )
        + "] }"
    )

def _lean_frame_paired_expression_register_output_claim(
    claim: dict[str, Any],
) -> str:
    if claim.get("profile") != (
        "active_frame_paired_expression_register_output_v1"
    ):
        raise StageAInputError(
            "unsupported active-frame paired-expression register output profile"
        )
    return (
        "{ output := "
        + _lean_register_relation_pair(claim["output"])
        + ", witness := "
        + _lean_paired_exact_expr_witness(claim["witness"])
        + " }"
    )




def _lean_relational_runtime_call_frame_link(link: dict[str, Any]) -> str:
    return (
        "{ callSourceTargetId := " + str(int(link["call_source_target_id"]))
        + ", resumeNodeId := " + str(int(link["resume_node_id"]))
        + ", resumeTargetId := " + str(int(link["resume_target_id"]))
        + ", resumeContinuation := " + str(int(link["resume_continuation"]))
        + ", innerInventory := "
        + _lean_return_slot_offset_inventory(link["inner_inventory"])
        + ", suspendedInventory := "
        + _lean_return_slot_offset_inventory(link["suspended_inventory"])
        + ", resumeInventory := "
        + _lean_return_slot_offset_inventory(link["resume_inventory"])
        + ", originalGap := " + str(int(link["original_gap"]))
        + ", candidateGap := " + str(int(link["candidate_gap"])) + " }"
    )


def _lean_linked_product_control_state(state: dict[str, Any]) -> str:
    continuation = (
        "none" if state["continuation_target_id"] is None
        else f"some {int(state['continuation_target_id'])}"
    )
    active = (
        "none" if state["active_frame"] is None
        else "some " + _lean_return_slot_offset_inventory(state["active_frame"])
    )
    return (
        "{ nodeId := " + str(int(state["node_id"]))
        + f", continuation := {continuation}, active := {active}"
        + f", minimumDepth := {int(state['minimum_depth'])} }}"
    )



def _lean_acceptance_linked_running_target(
    *, node_id: int, edge: dict[str, Any], frames: str = "[]",
    calls: str = "[]", active: str = "none", links: str = "[]",
    stack_targets_proof: str = "(by simp [RelationalRuntimeCallTargetsMapped])",
    target_control_proof: str = "(by decide)",
    links_allowed_proof: str = "linksAllowedNext",
    frame_facts_proof: str = "frameFactsNext",
    observation_proof: str = "True.intro",
    world_equal_proof: str = "rfl",
) -> str:
    target_node_id = int(edge["target_node_id"])
    target_region_index = int(edge["target_region_index"])
    target_target_id = int(edge["target_target_id"])
    return (
        f"  have targetInvariant : productInvariantTable.nodeInvariants[{target_node_id}]? =\n"
        f"      some region{target_region_index}.inputInvariant := by decide\n"
        f"  have targetNodeTarget : relationalProductGraph.nodes[{target_node_id}].targetId =\n"
        f"      {target_target_id} := by decide\n"
        f"  refine ⟨{observation_proof}, ?_⟩\n"
        f"  refine ⟨rfl, rfl, rfl, {world_equal_proof}, {target_node_id},\n"
        f"    relationalProductGraph.nodes[{target_node_id}],\n"
        f"    region{target_region_index}.inputInvariant, {frames}, {active}, {links},\n"
        f"    (by decide), targetNodeTarget, ?_, targetInvariant, {target_control_proof},\n"
        f"    stackHoldsNext, {links_allowed_proof}, {frame_facts_proof},\n"
        f"    {stack_targets_proof}, nextStatesRelated⟩\n"
        "  decide"
    )


def _linked_empty_jump_supported(step: dict[str, Any]) -> bool:
    if step.get("kind") != "jump" or step.get("cases") is not None:
        return False
    if step.get("certificate_profile") == "composable_x87_state_only_singleton_v1":
        return False
    control = step.get("control_state")
    if not isinstance(control, dict):
        return False
    if control.get("calls") != [] or control.get("frame_offsets") != []:
        return False
    return step.get("return_slot_frame_transfer_claims") == []


def _linked_shallow_profiles_supported(
    control_states: list[dict[str, Any]], linked_control: dict[str, Any]
) -> bool:
    """Check whether the finite old and linked profiles are the same at depth <= 1.

    This is only a generation preflight.  The emitted Lean theorem rechecks the
    complete finite profiles before an old local proof may be lifted.
    """

    if linked_control.get("links") != []:
        return False
    projected: list[dict[str, Any]] = []
    for state in control_states:
        calls = state.get("calls")
        frame_offsets = state.get("frame_offsets")
        if not isinstance(calls, list) or not isinstance(frame_offsets, list):
            return False
        if len(calls) != len(frame_offsets) or len(calls) > 1:
            return False
        projected.append({
            "node_id": int(state["node_id"]),
            "continuation_target_id": int(calls[0]) if calls else None,
            "active_frame": frame_offsets[0] if frame_offsets else None,
        })
    linked_states = [
        {
            "node_id": int(state["node_id"]),
            "continuation_target_id": state.get("continuation_target_id"),
            "active_frame": state.get("active_frame"),
        }
        for state in linked_control.get("states", [])
    ]
    return sorted(projected, key=lambda item: json.dumps(item, sort_keys=True)) == sorted(
        linked_states, key=lambda item: json.dumps(item, sort_keys=True)
    )


def _lean_acceptance_linked_shallow_node(
    step: dict[str, Any], *, parameterized_environment: bool = False,
    parameterized_protocol_environment: bool = False,
) -> str:
    """Lift an existing depth-zero/one node proof through a Lean-checked bridge."""

    node_id = int(step["node_id"])
    acceptance_environment = (
        step.get("kind") == "external_call"
        or bool(step.get("opaque_lockstep_profile"))
        or "opaque_lockstep_site_id" in step
    )
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        + (
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            if parameterized_protocol_environment else ""
        )
        + (
            "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment) :\n"
            if acceptance_environment else
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
        )
        if parameterized_environment else "    :\n"
    )
    original_program = (
        "(originalWorldProgram originalEnvironment"
        + (
            " originalProtocolEnvironment"
            if parameterized_protocol_environment else ""
        )
        + ")"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment"
        + (
            " candidateProtocolEnvironment"
            if parameterized_protocol_environment else ""
        )
        + ")"
        if parameterized_environment else "candidateWorldProgram"
    )
    old_refined = (
        f"acceptanceRunningNode{node_id}Refined originalEnvironment "
        "candidateEnvironment "
        + (
            "originalProtocolEnvironment candidateProtocolEnvironment "
            if parameterized_protocol_environment else ""
        )
        + "environmentRefines"
        if parameterized_environment else
        f"acceptanceRunningNode{node_id}Refined"
    )
    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined\n"
        + environment_binders
        + "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      {original_program} {candidate_program} {node_id} := by\n"
        "  exact acceptanceLinkedRunningNodeRefinedOfShallow\n"
        + (
            "    originalEnvironment candidateEnvironment "
            + (
                "originalProtocolEnvironment candidateProtocolEnvironment "
                if parameterized_protocol_environment else ""
            )
            if parameterized_environment else "    "
        )
        + f"{node_id}\n"
        f"    ({old_refined})"
    )


def _lean_acceptance_linked_shallow_lift(
    *, parameterized_environment: bool = False,
    parameterized_protocol_environment: bool = False,
) -> str:
    """Prove the old-to-linked profile bridge once for every generated node."""

    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        + (
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            if parameterized_protocol_environment else ""
        )
        if parameterized_environment else ""
    )
    original_program = (
        "(originalWorldProgram originalEnvironment"
        + (
            " originalProtocolEnvironment"
            if parameterized_protocol_environment else ""
        )
        + ")"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment"
        + (
            " candidateProtocolEnvironment"
            if parameterized_protocol_environment else ""
        )
        + ")"
        if parameterized_environment else "candidateWorldProgram"
    )
    return (
        "theorem acceptanceLinkedRunningNodeRefinedOfShallow\n"
        + environment_binders
        + "    (nodeId : Nat)\n"
        "    (oldRefined : RunningProductNodeStepRefined staticProofContext\n"
        "      relationalProductGraph productInvariantTable\n"
        "      relationalProductReachabilityEvidence productControlProfile\n"
        f"      protocolCallbackTargets {original_program} {candidate_program}\n"
        "      nodeId) :\n"
        "    LinkedRunningProductNodeStepRefined staticProofContext\n"
        "      relationalProductGraph productInvariantTable\n"
        "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
        f"      protocolCallbackTargets {original_program} {candidate_program}\n"
        "      nodeId := by\n"
        "  exact LinkedRunningProductNodeStepRefined.of_shallow\n"
        "    staticProofContext relationalProductGraph productInvariantTable\n"
        "    relationalProductReachabilityEvidence productControlProfile\n"
        f"    linkedProductControlProfile protocolCallbackTargets {original_program}\n"
        f"    {candidate_program} nodeId\n"
        "    productControlProfilesOldToLinkedShallow\n"
        "    productControlProfilesLinkedToOldShallow\n"
        "    linkedProductControlProfileLinksEmpty oldRefined\n\n"
    )


def _lean_acceptance_running_node_with_protocol_x87_bridge(
    step: dict[str, Any],
    regions: list[dict[str, Any]],
    behaviors: list[dict[str, Any]],
    *,
    parameterized_environment: bool,
    parameterized_protocol_environment: bool,
) -> str:
    source = _lean_acceptance_running_node(
        step,
        regions,
        behaviors,
        parameterized_environment=parameterized_environment,
        parameterized_protocol_environment=parameterized_protocol_environment,
    )
    if step.get("kind") != "external_protocol":
        return source

    legacy_clause = (
        "    · simpa [originalEvent, candidateEvent] using outputX87\n"
    )
    if source.count(legacy_clause) != 1:
        raise StageAInputError(
            "unsupported external-protocol x87 boundary proof profile"
        )
    return source.replace(
        legacy_clause,
        "    · simpa [originalEvent, candidateEvent] using outputX87.1\n",
    )


def _linked_active_jump_case(
    step: dict[str, Any], linked_states: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if (
        step.get("kind") != "jump"
        or step.get("certificate_profile") != "composable_local_no_write_v1"
        or len(linked_states) != 1
    ):
        return None
    linked_state = linked_states[0]
    active = linked_state.get("active_frame")
    continuation = linked_state.get("continuation_target_id")
    if active is None or continuation is None:
        return None
    candidates = step.get("cases")
    if candidates is None:
        candidates = [step]
    matches: list[dict[str, Any]] = []
    for candidate in candidates:
        control = candidate.get("control_state") or {}
        calls = control.get("calls") or []
        offsets = control.get("frame_offsets") or []
        claims = candidate.get("return_slot_frame_transfer_claims") or []
        edges = candidate.get("edges") or []
        if (
            calls
            and offsets
            and int(calls[0]) == int(continuation)
            and offsets[0] == active
            and claims
            and len(edges) == 1
            and claims[0].get("source") == active
        ):
            matches.append({
                "continuation_target_id": int(continuation),
                "source_active": active,
                "target_active": claims[0]["target"],
                "frame_claim": claims[0],
                "edge": edges[0],
            })
    unique = {
        json.dumps(match, sort_keys=True, separators=(",", ":")): match
        for match in matches
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _linked_active_branch_case(
    step: dict[str, Any], linked_states: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if step.get("kind") != "branch" or len(linked_states) != 1:
        return None
    linked_state = linked_states[0]
    active = linked_state.get("active_frame")
    continuation = linked_state.get("continuation_target_id")
    if active is None or continuation is None:
        return None
    candidates = step.get("cases") or [step]
    matches: list[dict[str, Any]] = []
    for candidate in candidates:
        control = candidate.get("control_state") or {}
        calls = control.get("calls") or []
        offsets = control.get("frame_offsets") or []
        edges = candidate.get("edges") or []
        if (
            not calls
            or not offsets
            or int(calls[0]) != int(continuation)
            or offsets[0] != active
            or len(edges) != 2
            or any(
                edge.get("certificate_profile")
                    != "composable_local_no_write_deferred_guard_v1"
                or not isinstance(edge.get("frame_guard_claim"), dict)
                or len(edge.get("return_slot_frame_transfer_claims") or []) != 1
                or edge["return_slot_frame_transfer_claims"][0].get("source")
                    != active
                for edge in edges
            )
        ):
            continue
        matches.append({
            "continuation_target_id": int(continuation),
            "source_active": active,
            "edges": edges,
        })
    unique = {
        json.dumps(match, sort_keys=True, separators=(",", ":")): match
        for match in matches
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _step_uses_deferred_guard(step: dict[str, Any]) -> bool:
    """Whether a node needs linked-frame authority for at least one edge."""

    candidates = step.get("cases") or [step]
    return any(
        edge.get("certificate_profile")
            == "composable_local_no_write_deferred_guard_v1"
        for candidate in candidates
        for edge in candidate.get("edges", [])
    )


def _linked_direct_call_case(
    step: dict[str, Any], linked_states: list[dict[str, Any]],
    linked_control: dict[str, Any],
) -> dict[str, Any] | None:
    """Select a native linked direct-call proof shape.

    The first profile deliberately covers the ordinary IA-32 call instruction:
    one four-byte return-slot write, ESP-relative active inventories, and no
    dormant exact scalar words.  Richer checked write footprints can extend the
    same kernel interface without changing linked-stack composition.
    """

    if (
        step.get("kind") != "call"
        or step.get("certificate_profile") != "composable_direct_call_v1"
        or step.get("cases") is not None
        or len(step.get("edges") or []) != 1
        or len(linked_states) != 1
        or int(step.get("stack_amount", -1)) != 4
    ):
        return None
    state = linked_states[0]
    active = state.get("active_frame")
    continuation = state.get("continuation_target_id")
    control = step.get("control_state") or {}
    calls = control.get("calls") or []
    offsets = control.get("frame_offsets") or []
    seeded = step.get("seeded_frame_inventory")
    if not isinstance(seeded, dict) or seeded.get("exact_words", []) != []:
        return None
    if active is None:
        if continuation is not None or calls != [] or offsets != []:
            return None
        edge = step["edges"][0]
        targets = [
            candidate for candidate in linked_control.get("states", [])
            if int(candidate["node_id"]) == int(edge["target_node_id"])
            and candidate.get("continuation_target_id")
                == int(step["continuation_target_id"])
            and candidate.get("active_frame") == seeded
            and int(candidate.get("minimum_depth", -1)) <= 1
        ]
        if len(targets) != 1:
            return None
        return {
            "kind": "first", "source_state": state,
            "target_state": targets[0],
        }
    if (
        continuation is None
        or not calls
        or not offsets
        or int(calls[0]) != int(continuation)
        or offsets[0] != active
    ):
        return None
    claims = step.get("return_slot_frame_transfer_claims") or []
    if len(claims) != 1 or claims[0].get("source") != active:
        return None
    edge = step["edges"][0]
    matching = []
    for link in linked_control.get("links", []):
        if (
            int(link.get("source_state_id", -1)) == int(state["id"])
            and int(link.get("target_state_id", -1)) >= 0
            and int(link.get("call_source_target_id", -1)) == int(step["target_id"])
            and int(link.get("resume_target_id", -1))
                == int(step["continuation_target_id"])
            and int(link.get("resume_continuation", -1)) == int(continuation)
            and int(link.get("original_gap", -1)) == 4
            and int(link.get("candidate_gap", -1)) == 4
            and link.get("inner_inventory") == seeded
            and link.get("suspended_inventory") == claims[0].get("target")
            and link.get("inner_inventory", {}).get("exact_words", []) == []
            and link.get("suspended_inventory", {}).get("exact_words", []) == []
            and link.get("resume_inventory", {}).get("exact_words", []) == []
            and int(edge["target_node_id"])
                == int(linked_control["states"][int(link["target_state_id"])]["node_id"])
        ):
            matching.append(link)
    if len(matching) != 1:
        return None
    target_state = next((
        candidate for candidate in linked_control.get("states", [])
        if int(candidate["id"]) == int(matching[0]["target_state_id"])
    ), None)
    if target_state is None:
        return None
    return {
        "kind": "nested",
        "source_state": state,
        "target_state": target_state,
        "link": matching[0],
        "outer_claim": claims[0],
    }


def _linked_return_case(
    step: dict[str, Any], linked_states: list[dict[str, Any]],
    linked_control: dict[str, Any],
) -> dict[str, Any] | None:
    """Select an unambiguous native linked-return proof shape.

    Return dispatch is keyed by the concrete runtime-frame continuation.  The
    Lean profile rechecks that exactly one submitted link has that continuation;
    an ambiguous resume contract is never resolved by Python ordering.
    """

    if (
        step.get("kind") != "return"
        or step.get("cases") is not None
        or len(linked_states) != 1
        or step.get("active_frame_imports", []) != []
        or step.get("active_frame_relations", []) != []
        or step.get("import_transfer_claims", []) != []
    ):
        return None
    state = linked_states[0]
    active = state.get("active_frame")
    continuation = state.get("continuation_target_id")
    if (
        active is None
        or continuation is None
        or active != step.get("return_frame_inventory")
        or int(continuation) != int(step.get("target_target_id", -1))
    ):
        return None
    target_calls = (step.get("target_control_state") or {}).get("calls") or []
    target_continuation = int(target_calls[0]) if target_calls else None
    target_state = next((
        candidate for candidate in linked_control.get("states", [])
        if int(candidate["node_id"]) == int(step.get("target_node_id", -1))
        and candidate.get("continuation_target_id") == target_continuation
    ), None)
    if target_state is None:
        return None

    compatible_links = [
        link for link in linked_control.get("links", [])
        if int(link.get("resume_target_id", -1)) == int(continuation)
    ]
    claims = step.get("return_slot_frame_transfer_claims") or []
    nested = [
        link for link in compatible_links
        if int(link.get("target_state_id", -1)) == int(state["id"])
        and int(link.get("resume_state_id", -1)) == int(target_state["id"])
        and link.get("inner_inventory") == active
        and len(claims) == 1
        and claims[0].get("source") == link.get("suspended_inventory")
        and claims[0].get("target") == link.get("resume_inventory")
    ]
    if len(compatible_links) == 1 and len(nested) == 1:
        return {
            "kind": "nested",
            "source_state": state,
            "target_state": target_state,
            "link": nested[0],
            "outer_claim": claims[0],
        }
    if not compatible_links and not claims:
        target_control = step.get("target_control_state") or {}
        if (
            target_control.get("calls") == []
            and target_state.get("active_frame") is None
            and target_state.get("continuation_target_id") is None
        ):
            return {
                "kind": "last",
                "source_state": state,
                "target_state": target_state,
            }
    return None


def _lean_acceptance_linked_direct_call_node(
    step: dict[str, Any], call_case: dict[str, Any],
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    edge = step["edges"][0]
    edge_id = int(edge["edge_id"])
    target_region_index = int(edge["target_region_index"])
    target_node_id = int(edge["target_node_id"])
    continuation = int(step["continuation_target_id"])
    continuation_node_id = int(step["continuation_node_id"])
    claim = step["call_push_claim"]
    original_return = int(claim["original_return_address"])
    candidate_return = int(claim["candidate_return_address"])
    stack_amount = int(step["stack_amount"])
    stack_amount_twos_complement = 2**32 - stack_amount
    source_window = _lean_stack_window(step["source_stack_window"])
    active_inventory = _lean_return_slot_offset_inventory(
        step["seeded_frame_inventory"]
    )
    protected_bytes = _runtime_frame_protected_bytes(
        step["seeded_frame_inventory"]
    )
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    target_control_state = _lean_linked_product_control_state(
        call_case["target_state"]
    )

    common = (
        f"let activeFrameInventory : ReturnSlotOffsetInventory :=\n"
        f"  {active_inventory}\n"
        f"let sourceWindow : StackWindowPair := {source_window}\n"
        f"have stackAddressRewrite (value : Word) :\n"
        f"    value + BitVec.ofNat 32 {stack_amount_twos_complement} =\n"
        f"      value - BitVec.ofNat 32 {stack_amount} := by\n"
        f"  exact word_add_ia32_twos_complement value {stack_amount} (by decide)\n"
        f"have originalBehaviorSegment : {original_behavior} =\n"
        f"    segmentRefinementEdge{edge_id}OriginalNormalizedBehavior := by decide\n"
        f"have candidateBehaviorSegment : {candidate_behavior} =\n"
        f"    segmentRefinementEdge{edge_id}CandidateNormalizedBehavior := by decide\n"
        "let runtimeFrame : RelationalRuntimeCallFrame := {\n"
        f"  continuationTargetId := {continuation}\n"
        f"  originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
        f"  candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
        "  originalStackAddress := originalState.registers.get\n"
        f"    sourceWindow.originalRegister - BitVec.ofNat 32 {stack_amount}\n"
        "  candidateStackAddress := candidateState.registers.get\n"
        f"    sourceWindow.candidateRegister - BitVec.ofNat 32 {stack_amount}\n"
        f"  protectedBytes := {protected_bytes}\n"
        "}\n"
        f"have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
        "  originalState candidateState statesRelated\n"
        f"have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
        "    originalState = true := by\n"
        f"  simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
        "have transitioned := transition.2 guardTrue\n"
        "have nextStatesRelated : StateRel staticProofContext world\n"
        f"    region{target_region_index}.inputInvariant\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState) := by\n"
        "  rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
        "  exact transitioned.2.2.2\n"
        "have frameMemory : runtimeFrame.memoryHolds\n"
        f"    (({original_behavior}.eval originalState).nextMachineState\n"
        "      originalState).memory\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState\n"
        "      candidateState).memory := by\n"
        "  unfold RelationalRuntimeCallFrame.memoryHolds runtimeFrame\n"
        "  exact pairedStackWordWriteReadsBack_amount staticProofContext world\n"
        f"    region{region_index}.inputInvariant sourceWindow {stack_amount}\n"
        f"    (BitVec.ofNat 32 {original_return}) (BitVec.ofNat 32 {candidate_return})\n"
        "    originalState candidateState\n"
        f"    ({original_behavior}.eval originalState)\n"
        f"    ({candidate_behavior}.eval candidateState)\n"
        "    (by simp) (by simp) statesRelated\n"
        "    (by decide) (by decide) (by decide) (by decide)\n"
        "    (by simp [sourceWindow,\n"
        f"      acceptanceOriginalNormalizedWrites{node_id},\n"
        f"      originalBehavior{region_index}, evalNormalizedWrites, Expr.eval,\n"
        "      stackAddressRewrite])\n"
        "    (by simp [sourceWindow,\n"
        f"      acceptanceCandidateNormalizedWrites{node_id},\n"
        f"      candidateBehavior{region_index}, evalNormalizedWrites, Expr.eval,\n"
        "      stackAddressRewrite])\n"
        "have frameOffsetsHold : ReturnSlotOffsetPair.zero.holds runtimeFrame\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers := by\n"
        "  simp [ReturnSlotOffsetPair.zero, ReturnSlotOffsetPair.holds, runtimeFrame,\n"
        "    sourceWindow,\n"
        f"    acceptanceOriginalNormalizedRegisters{node_id},\n"
        f"    acceptanceCandidateNormalizedRegisters{node_id},\n"
        f"    originalBehavior{region_index}, candidateBehavior{region_index},\n"
        "    evalNormalizedRegisters, evalNormalizedRegisters_get,\n"
        "    StageA.Formal.Registers.get, Expr.eval, stackAddressRewrite]\n"
        "have sourceWindows := StateRel.stackWindowsHold staticProofContext world\n"
        f"  region{region_index}.inputInvariant originalState candidateState statesRelated\n"
        "simp only [stackWindowsRelated, List.all_eq_true] at sourceWindows\n"
        "have sourceWindowHolds : sourceWindow.holds world originalState.registers\n"
        "    candidateState.registers = true := by\n"
        "  exact sourceWindows sourceWindow (by decide)\n"
        "have frameProtected : runtimeFrame.protectedSpanValid\n"
        "    staticProofContext = true := by\n"
        "  exact RelationalRuntimeCallFrame.protectedSpanValid_of_window_call\n"
        "    staticProofContext world sourceWindow originalState.registers\n"
        "    candidateState.registers runtimeFrame " + str(stack_amount) + "\n"
        "    (StateRel.stackRangesValid staticProofContext world\n"
        f"      region{region_index}.inputInvariant originalState candidateState\n"
        "      statesRelated) sourceWindowHolds (by decide) (by decide)\n"
        "    (by simp [runtimeFrame]) (by simp [runtimeFrame, sourceWindow])\n"
        "    (by simp [runtimeFrame])\n"
        "    (by simp [runtimeFrame])\n"
        "have frameValid : runtimeFrame.valid staticProofContext = true := by\n"
        "  unfold RelationalRuntimeCallFrame.valid\n"
        "  simp only [Bool.and_eq_true]\n"
        "  constructor\n"
        "  · change RelationalCallFrame.valid staticProofContext {\n"
        f"    continuationTargetId := {continuation}\n"
        f"    originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
        f"    candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
        "    } = true\n"
        "    decide\n"
        "  · exact frameProtected\n"
        "have frameResolves : runtimeFrame.toRelationalCallFrame.resolves\n"
        "    staticProofContext = true := by\n"
        "  change RelationalCallFrame.resolves staticProofContext {\n"
        f"    continuationTargetId := {continuation}\n"
        f"    originalReturnAddress := BitVec.ofNat 32 {original_return}\n"
        f"    candidateReturnAddress := BitVec.ofNat 32 {candidate_return}\n"
        "  } = true\n"
        "  decide\n"
        "have activeFrameInventoryHolds : activeFrameInventory.holds runtimeFrame\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers := by\n"
        "  refine And.intro (by decide) ?_\n"
        "  intro location locationMember\n"
        "  have locationExact : location = ReturnSlotOffsetPair.zero := by\n"
        "    simpa [activeFrameInventory] using locationMember\n"
        "  subst location\n"
        "  exact frameOffsetsHold\n"
        "have activeFrameExactWords : activeFrameInventory.boundedExactWordsHold runtimeFrame\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState).memory\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState).memory := by\n"
        "  simp [activeFrameInventory, ReturnSlotOffsetInventory.boundedExactWordsHold,\n"
        "    ReturnSlotOffsetInventory.exactWordsFit,\n"
        "    ReturnSlotOffsetInventory.exactWordsHold, runtimeFrame]\n"
        "have activeFrameImportSeedChecked :\n"
        "    activeFrameInventory.seedsPreservedImportsFrom\n"
        f"      region{region_index}.inputInvariant {original_behavior}\n"
        f"      {candidate_behavior} = true := by decide\n"
        "have activeFrameImportsNext : activeFrameInventory.preservedImportsHold\n"
        "    world\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        "  exact ReturnSlotOffsetInventory."
        "preservedImportsHold_after_stateRel_of_checked\n"
        "    staticProofContext activeFrameInventory world\n"
        f"    region{region_index}.inputInvariant {original_behavior}\n"
        f"    {candidate_behavior} originalState candidateState\n"
        "    activeFrameImportSeedChecked statesRelated\n"
        "let activeFrameRegisterClaims : List InvariantWP.RegisterOutputClaim := ["
        + ", ".join(
            _lean_register_output_claim(output_claim)
            for output_claim in step.get("seeded_register_output_claims", [])
        )
        + "]\n"
        "have activeFrameRelationSeedChecked :\n"
        "    activeFrameInventory.seedsPreservedRelationsFromOutputClaims\n"
        f"      staticProofContext region{region_index} {original_behavior}\n"
        f"      {candidate_behavior} activeFrameRegisterClaims = true := by decide\n"
        "have activeFrameRelationsNext :\n"
        "    activeFrameInventory.preservedRelationsHold staticProofContext world\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        "  exact ReturnSlotOffsetInventory."
        "preservedRelationsHold_after_stateRel_of_outputClaims\n"
        "    staticProofContext activeFrameInventory world\n"
        f"    region{region_index} {original_behavior} {candidate_behavior}\n"
        "    activeFrameRegisterClaims originalState candidateState\n"
        "    activeFrameRelationSeedChecked statesRelated\n"
        "have frameFactsNext : RelationalLinkedRuntimeCallFactsHold\n"
        "    staticProofContext world (some activeFrameInventory)\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers := by\n"
        "  exact ⟨activeFrameImportsNext, activeFrameRelationsNext⟩\n"
    )

    if call_case["kind"] == "first":
        control_setup = (
            "  have controlHead : none = calls.head? ∧ none = active := by\n"
            "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
            "using controlMember.2\n"
            "  have controlShape : calls = [] ∧ active = none := by\n"
            "    constructor\n"
            "    · exact continuations_eq_nil_of_head?_eq_none calls controlHead.1\n"
            "    · exact controlHead.2.symm\n"
            "  rcases controlShape with ⟨rfl, rfl⟩\n"
            "  have stackShape : frames = [] ∧ links = [] := by\n"
            "    exact RelationalLinkedRuntimeCallStackHolds.empty_shape\n"
            "      staticProofContext originalState candidateState frames links stackHolds\n"
            "  rcases stackShape with ⟨rfl, rfl⟩\n"
        )
        stack_proof = (
            "have stackHoldsNext : RelationalLinkedRuntimeCallStackHolds\n"
            "    staticProofContext\n"
            f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            f"    [runtimeFrame] [{continuation}] (some activeFrameInventory) [] := by\n"
            "  exact RelationalLinkedRuntimeCallStackHolds.pushFirst staticProofContext\n"
            f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "    runtimeFrame " + str(continuation) + " activeFrameInventory (by decide)\n"
            "    activeFrameInventoryHolds activeFrameExactWords rfl frameValid\n"
            "    frameResolves frameMemory\n"
            "have linksAllowedNext : linkedProductControlProfile.LinksAllowed [] := by\n"
            "  exact LinkedProductControlProfile.LinksAllowed.nil\n"
            "    linkedProductControlProfile linkedProductControlProfileChecked\n"
            f"let targetControlState : LinkedProductControlState := "
            f"{target_control_state}\n"
            "have controlAllowedNext : linkedProductControlProfile.Allows\n"
            f"    {target_node_id} [{continuation}] (some activeFrameInventory) = true := by\n"
            "  exact LinkedProductControlProfile.allowsOfListedState\n"
            "    linkedProductControlProfile targetControlState _ _ _\n"
            "    linkedProductControlProfileChecked\n"
            "    (by simp [targetControlState, linkedProductControlProfile])\n"
            "    (by simp [targetControlState, LinkedProductControlState.matches, "
            "      activeFrameInventory])\n"
            "    (by simp [targetControlState])\n"
        )
        target = _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=edge,
            frames="[runtimeFrame]",
            calls=f"[{continuation}]",
            active="some activeFrameInventory",
            links="[]",
            target_control_proof="controlAllowedNext",
            links_allowed_proof="linksAllowedNext",
            frame_facts_proof="frameFactsNext",
            stack_targets_proof=(
                "(by simp only [RelationalRuntimeCallTargetsMapped]; "
                f"exact ⟨⟨{continuation_node_id}, relationalProductGraph.nodes["
                f"{continuation_node_id}], by decide, by decide⟩, True.intro⟩)"
            ),
        )
        body = (
            control_setup
            + "\n".join("  " + line for line in (common + stack_proof).splitlines())
            + "\n"
            + target
        )
    else:
        link = call_case["link"]
        outer_claim = call_case["outer_claim"]
        source_active = _lean_return_slot_offset_inventory(
            call_case["source_state"]["active_frame"]
        )
        source_minimum_depth = int(call_case["source_state"]["minimum_depth"])
        link_literal = _lean_relational_runtime_call_frame_link(link)
        outer_claim_literal = _lean_return_slot_frame_inventory_transfer_claim(
            outer_claim
        )
        source_continuation = int(call_case["source_state"]["continuation_target_id"])
        control_setup = (
            f"  have controlShape : (some {source_continuation} = calls.head? ∧\n"
            f"      some {source_active} = active) ∧\n"
            f"      {source_minimum_depth} <= calls.length := by\n"
            "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
            "using controlMember.2\n"
            "  cases calls with\n"
            "  | nil => simp at controlShape\n"
            "  | cons selected continuations =>\n"
            "    simp only [List.head?_cons, Option.some.injEq] at controlShape\n"
            "    rcases controlShape with ⟨⟨rfl, rfl⟩, _depthEnough⟩\n"
            "    cases frames with\n"
            "    | nil => simp [RelationalLinkedRuntimeCallStackHolds] at stackHolds\n"
            "    | cons outer frames =>\n"
        )
        nested = (
            f"let outerClaim : ReturnSlotFrameInventoryTransferClaim :=\n"
            f"  {outer_claim_literal}\n"
            f"let newLink : RelationalRuntimeCallFrameLink := {link_literal}\n"
            + common
            + "have stackShape := stackHolds\n"
            "simp only [RelationalLinkedRuntimeCallStackHolds] at stackShape\n"
            "have outerOffsetsHold : ReturnSlotOffsetPair.zero.holds outer\n"
            "    originalState.registers candidateState.registers := by\n"
            "  have sourceHolds : outerClaim.source.holds outer\n"
            "      originalState.registers candidateState.registers := by\n"
            "    simpa [outerClaim] using stackShape.2.1\n"
            "  exact sourceHolds.2 ReturnSlotOffsetPair.zero (by decide)\n"
            "have linkHolds : newLink.holds runtimeFrame outer := by\n"
            "  exact RelationalRuntimeCallFrameLink.holds_of_esp_call\n"
            "    staticProofContext world sourceWindow originalState.registers\n"
            "    candidateState.registers\n"
            f"    ({original_behavior}.eval originalState).registers\n"
            f"    ({candidate_behavior}.eval candidateState).registers\n"
            f"    runtimeFrame outer newLink {stack_amount}\n"
            "    (StateRel.stackRangesValid staticProofContext world\n"
            f"      region{region_index}.inputInvariant originalState candidateState\n"
            "      statesRelated) sourceWindowHolds (by decide) (by decide)\n"
            "    (by decide) (by decide) (by decide)\n"
            "    (by simp [sourceWindow,\n"
            f"      acceptanceOriginalNormalizedRegisters{node_id},\n"
            f"      originalBehavior{region_index}, evalNormalizedRegisters,\n"
            "      evalNormalizedRegisters_get, StageA.Formal.Registers.get,\n"
            "      Expr.eval, stackAddressRewrite])\n"
            "    (by simp [sourceWindow,\n"
            f"      acceptanceCandidateNormalizedRegisters{node_id},\n"
            f"      candidateBehavior{region_index}, evalNormalizedRegisters,\n"
            "      evalNormalizedRegisters_get, StageA.Formal.Registers.get,\n"
            "      Expr.eval, stackAddressRewrite])\n"
            "    outerOffsetsHold frameOffsetsHold (by decide) (by decide)\n"
            "    (by decide) rfl (by simpa [newLink] using stackShape.2.2.2.1.1)\n"
            "    (by decide) (by decide)\n"
            "have originalMemory :\n"
            f"    (({original_behavior}.eval originalState).nextMachineState originalState).memory =\n"
            "      originalState.memory.write32 runtimeFrame.originalStackAddress\n"
            "        runtimeFrame.originalReturnAddress := by\n"
            "  simp [RelationalBehavior.nextMachineState, runtimeFrame, sourceWindow,\n"
            f"    acceptanceOriginalNormalizedWrites{node_id}, originalBehavior{region_index},\n"
            "    evalNormalizedWrites, applyConcreteWrites, Expr.eval, stackAddressRewrite]\n"
            "have candidateMemory :\n"
            f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState).memory =\n"
            "      candidateState.memory.write32 runtimeFrame.candidateStackAddress\n"
            "        runtimeFrame.candidateReturnAddress := by\n"
            "  simp [RelationalBehavior.nextMachineState, runtimeFrame, sourceWindow,\n"
            f"    acceptanceCandidateNormalizedWrites{node_id}, candidateBehavior{region_index},\n"
            "    evalNormalizedWrites, applyConcreteWrites, Expr.eval, stackAddressRewrite]\n"
            "have stackHoldsNext : RelationalLinkedRuntimeCallStackHolds\n"
            "    staticProofContext\n"
            f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            f"    (runtimeFrame :: outer :: frames) ({continuation} :: "
            f"{source_continuation} :: continuations)\n"
            "    (some activeFrameInventory) (newLink :: links) := by\n"
            "  exact RelationalLinkedRuntimeCallStackHolds."
            "pushNestedAfterSingletonWrite\n"
            f"    staticProofContext world region{region_index}.inputInvariant\n"
            f"    {original_behavior} {candidate_behavior} outerClaim originalState\n"
            "    candidateState runtimeFrame outer frames continuations newLink links\n"
            "    (by simpa [outerClaim, newLink] using stackHolds) (by decide)\n"
            "    statesRelated linkHolds (by decide) activeFrameInventoryHolds\n"
            "    activeFrameExactWords frameValid frameResolves frameMemory\n"
            "    originalMemory candidateMemory\n"
            "have linksAllowedNext : linkedProductControlProfile.LinksAllowed\n"
            "    (newLink :: links) := by\n"
            "  exact LinkedProductControlProfile.LinksAllowed.cons\n"
            "    linkedProductControlProfile newLink links (by decide) linksAllowed\n"
            f"let targetControlState : LinkedProductControlState := "
            f"{target_control_state}\n"
            "have controlAllowedNext : linkedProductControlProfile.Allows\n"
            f"    {target_node_id} ({continuation} :: {source_continuation} :: continuations)\n"
            "    (some activeFrameInventory) = true := by\n"
            "  exact LinkedProductControlProfile.allowsOfListedState\n"
            "    linkedProductControlProfile targetControlState _ _ _\n"
            "    linkedProductControlProfileChecked\n"
            "    (by simp [targetControlState, linkedProductControlProfile])\n"
            "    (by simp [targetControlState, LinkedProductControlState.matches, "
            "      activeFrameInventory])\n"
            "    (by simp [targetControlState])\n"
        )
        target = _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=edge,
            frames="runtimeFrame :: outer :: frames",
            calls=f"{continuation} :: {source_continuation} :: continuations",
            active="some activeFrameInventory",
            links="newLink :: links",
            target_control_proof="controlAllowedNext",
            links_allowed_proof="linksAllowedNext",
            frame_facts_proof="frameFactsNext",
            stack_targets_proof=(
                "(by simp only [RelationalRuntimeCallTargetsMapped]; "
                f"exact ⟨⟨{continuation_node_id}, "
                f"relationalProductGraph.nodes[{continuation_node_id}], "
                "by decide, by decide⟩, stackTargetsReachable⟩)"
            ),
        )
        body = (
            control_setup
            + "\n".join("    " + line for line in nested.splitlines())
            + "\n"
            + "\n".join("  " + line for line in target.splitlines())
        )

    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined :\n"
        "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      originalWorldProgram candidateWorldProgram {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
        "  unfold DecodedWorldProgram.transitionSystem\n"
        "  simp only [stepWorldExecution]\n"
        f"  rw [originalWorldBehaviorNode{node_id}, candidateWorldBehaviorNode{node_id}]\n"
        "  simp only [transitionFromWorldBehavior, transitionFromWorldOutcome,\n"
        "    NormalizedSymbolicBehavior.eval_outcome,\n"
        f"    acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"    acceptanceCandidateNormalizedOutcome{node_id}, NormalizedOutcomeExpr.eval]\n"
        + body
    )


def _lean_acceptance_linked_return_node(
    step: dict[str, Any], return_case: dict[str, Any],
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_node_id = int(step["target_node_id"])
    target_region_index = int(step["target_region_index"])
    continuation = int(step["target_target_id"])
    source_state = return_case["source_state"]
    minimum_depth = int(source_state["minimum_depth"])
    target_control_state = _lean_linked_product_control_state(
        return_case["target_state"]
    )
    active_inventory = _lean_return_slot_offset_inventory(
        step["return_frame_inventory"]
    )
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    return_claim = step["return_pop_claim"]
    frame_claim = step["return_frame_claim"]
    return_claim_literal = (
        "{ originalStackAddress := "
        + _lean_semantic_expr(return_claim["original_stack_address"])
        + ", candidateStackAddress := "
        + _lean_semantic_expr(return_claim["candidate_stack_address"])
        + f", popBytes := {int(return_claim['pop_bytes'])} }}"
    )
    frame_claim_literal = (
        "{ offsets := "
        + _lean_return_slot_offset_pair(frame_claim["offsets"])
        + ", originalSlot := "
        + _lean_register_offset_witness(frame_claim["original_slot_witness"])
        + ", candidateSlot := "
        + _lean_register_offset_witness(frame_claim["candidate_slot_witness"])
        + " }"
    )
    selected_offsets = _lean_return_slot_offset_pair(frame_claim["offsets"])
    output_claims = ", ".join(
        _lean_register_output_claim(claim) for claim in step["output_claims"]
    )
    stack_transfers = ", ".join(
        _lean_stack_window_transfer_claim(claim)
        for claim in step["stack_window_transfers"]
    )
    flag_transfer_claim = step.get("flag_transfer_claim")
    if flag_transfer_claim is None:
        output_flags_proof = (
            f"  simp [RegionRelation.inputInvariant, region{target_region_index}, "
            "flagsRelated]"
        )
    else:
        output_flags_proof = "\n".join(
            "  " + line
            for line in _lean_preserved_input_flags_proof(
                claim=flag_transfer_claim,
                source_region_index=region_index,
                original_behavior=original_behavior,
                candidate_behavior=candidate_behavior,
            ).splitlines()
        )

    state_relation = (
        "have relatedForTransfer := statesRelated\n"
        "rcases statesRelated with\n"
        "  ⟨_worldValid, stackRangesValid, _stackMemory, _importsStatic,\n"
        "    _importsComplete, _importsMemory, _originalImmutable,\n"
        "    _candidateImmutable, relatedCore, _inputImportRegisters⟩\n"
        "rcases relatedCore with\n"
        "  ⟨_inputRegisters, _inputBounds, _inputSeparations, inputStackWindows,\n"
        "    _inputMemory, _inputDynamicMemory, _inputUndefined, inputX87,\n"
        "    inputFlags, _inputFsBase⟩\n"
        f"let outputClaims : List InvariantWP.RegisterOutputClaim := [{output_claims}]\n"
        "have outputRegisters : registerRelationsHold\n"
        "    staticProofContext.originalPe.imageBase\n"
        "    staticProofContext.candidatePe.imageBase\n"
        "    staticProofContext.codeMap.entries.toList\n"
        "    (staticProofContext.relationalValueTargets world)\n"
        f"    region{target_region_index}.inputInvariant.registerRelations\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        "  have inventory : outputClaims.map InvariantWP.RegisterOutputClaim.output =\n"
        f"      region{target_region_index}.inputInvariant.registerRelations := by decide\n"
        "  rw [← inventory]\n"
        "  exact InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
        f"    staticProofContext world region{region_index} {original_behavior}\n"
        f"    {candidate_behavior} outputClaims (by decide) originalState\n"
        "    candidateState relatedForTransfer\n"
        "have outputBounds : boundsRelated\n"
        f"    region{target_region_index}.inputInvariant.bounds\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index}, boundsRelated]\n"
        "have outputSeparations : addressSeparationsRelated\n"
        f"    region{target_region_index}.inputInvariant.addressSeparations\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "    addressSeparationsRelated]\n"
        f"let stackTransfers : List StackWindowAffineTransferClaim := [{stack_transfers}]\n"
        "have outputStackWindows := stackWindowsRelated_after_affine_of_checked\n"
        f"  staticProofContext world region{region_index}.inputInvariant\n"
        f"  region{target_region_index}.inputInvariant {original_behavior}\n"
        f"  {candidate_behavior} stackTransfers originalState candidateState\n"
        "  stackRangesValid inputStackWindows (by decide)\n"
        f"have originalX87Field : {original_behavior}.x87 =\n"
        f"    originalBehavior{region_index}.x87 := by decide\n"
        f"have candidateX87Field : {candidate_behavior}.x87 =\n"
        f"    candidateBehavior{region_index}.x87 := by decide\n"
        "have outputX87 :\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState).x87 =\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState).x87 := by\n"
        "  have inputLegacyX87 := inputX87.1\n"
        "  simp [originalX87Field, candidateX87Field,\n"
        f"    originalBehavior{region_index}, candidateBehavior{region_index},\n"
        "    RelationalBehavior.nextMachineState, evalNormalizedX87,\n"
        "    X87Expr.eval, Expr.eval, inputLegacyX87]\n"
        "have outputFlags : flagsRelated\n"
        f"    region{target_region_index}.inputInvariant.flagBits\n"
        f"    ({original_behavior}.eval originalState).eflags\n"
        f"    ({candidate_behavior}.eval candidateState).eflags = true := by\n"
        + output_flags_proof + "\n"
        f"have originalWritesField : {original_behavior}.writes = [] := by decide\n"
        f"have candidateWritesField : {candidate_behavior}.writes = [] := by decide\n"
        f"have originalWrites : ({original_behavior}.eval originalState).writes = [] := by\n"
        "  simp [originalWritesField, evalNormalizedWrites]\n"
        f"have candidateWrites : ({candidate_behavior}.eval candidateState).writes = [] := by\n"
        "  simp [candidateWritesField, evalNormalizedWrites]\n"
        "have originalMemory :\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState).memory =\n"
        "      originalState.memory := by\n"
        "  change applyConcreteWrites originalState.memory\n"
        f"      (({original_behavior}.eval originalState).writes) = originalState.memory\n"
        "  rw [originalWrites]\n"
        "  rfl\n"
        "have candidateMemory :\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState).memory =\n"
        "      candidateState.memory := by\n"
        "  change applyConcreteWrites candidateState.memory\n"
        f"      (({candidate_behavior}.eval candidateState).writes) = candidateState.memory\n"
        "  rw [candidateWrites]\n"
        "  rfl\n"
        "have outputImports : importRegisterRelationsHold world\n"
        f"    region{target_region_index}.inputInvariant.importRegisterRelations\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "    importRegisterRelationsHold]\n"
        "have outputOrigins : registerValueOriginRelationsHold staticProofContext world\n"
        f"    region{target_region_index}.inputInvariant.registerValueOriginRelations\n"
        f"    ({original_behavior}.eval originalState).registers\n"
        f"    ({candidate_behavior}.eval candidateState).registers = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "    registerValueOriginRelationsHold]\n"
        "have outputMemoryOrigins : memoryValueOriginRelationsHold staticProofContext world\n"
        f"    region{target_region_index}.inputInvariant.memoryValueOriginRelations\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState) = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "    memoryValueOriginRelationsHold]\n"
        "have outputDynamic : activeDynamicRegisterRangeRelationsHold staticProofContext world\n"
        f"    region{target_region_index}.inputInvariant.dynamicRegisterRangeRelations\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState) = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "    activeDynamicRegisterRangeRelationsHold]\n"
        "have outputDynamicStack : activeDynamicStackRangeRelationsHold staticProofContext world\n"
        f"    region{target_region_index}.inputInvariant.dynamicStackRangeRelations\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState) = true := by\n"
        f"  simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "    activeDynamicStackRangeRelationsHold]\n"
        "have nextStatesRelated : StateRel staticProofContext world\n"
        f"    region{target_region_index}.inputInvariant\n"
        f"    (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"    (({candidate_behavior}.eval candidateState).nextMachineState candidateState) :=\n"
        "  StateRel.afterNoWriteEvaluation staticProofContext world\n"
        f"    region{region_index}.inputInvariant region{target_region_index}.inputInvariant\n"
        f"    originalState candidateState ({original_behavior}.eval originalState)\n"
        f"    ({candidate_behavior}.eval candidateState) relatedForTransfer\n"
        "    originalWrites candidateWrites (by simp) (by simp)\n"
        "    outputRegisters outputBounds outputSeparations outputStackWindows\n"
        "    outputX87 outputFlags outputImports outputOrigins outputMemoryOrigins\n"
        "    outputDynamic outputDynamicStack\n"
        f"    (by simp [RegionRelation.inputInvariant, region{target_region_index},\n"
        "      pairedStatePredicatesHold])\n"
    )

    control = (
        "  have controlShape : (some " + str(continuation) + " = calls.head? ∧\n"
        f"      some {active_inventory} = active) ∧ {minimum_depth} <= calls.length := by\n"
        "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
        "using controlMember.2\n"
        "  cases calls with\n"
        "  | nil => simp at controlShape\n"
        "  | cons selected continuations =>\n"
        "    simp only [List.head?_cons, Option.some.injEq, List.length_cons] at controlShape\n"
        "    rcases controlShape with ⟨⟨rfl, rfl⟩, depthEnough⟩\n"
        "    cases frames with\n"
        "    | nil => simp [RelationalLinkedRuntimeCallStackHolds] at stackHolds\n"
        "    | cons frame frames =>\n"
    )
    common = (
        "have stackShape := stackHolds\n"
        "simp only [RelationalLinkedRuntimeCallStackHolds] at stackShape\n"
        "have frameContinuation := stackShape.2.2.2.1.1\n"
        "have frameResolves := stackShape.2.2.2.1.2.2.1\n"
        "have frameMemory := stackShape.2.2.2.1.2.2.2.1\n"
        f"have selectedFrameOffsetsHold : ({selected_offsets} : ReturnSlotOffsetPair).holds\n"
        "    frame originalState.registers candidateState.registers := by\n"
        f"  exact stackShape.2.1.2 ({selected_offsets} : ReturnSlotOffsetPair) (by decide)\n"
        f"let returnClaim : ReturnPopClaim := {return_claim_literal}\n"
        f"let frameClaim : ReturnPopFrameClaim := {frame_claim_literal}\n"
        "have returnTargets := returnPopTargetsRuntimeFrame_of_checked\n"
        f"  {original_behavior} {candidate_behavior} returnClaim frameClaim frame\n"
        "  originalState candidateState (by decide) (by decide)\n"
        "  selectedFrameOffsetsHold frameMemory\n"
        f"simp only [acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"  acceptanceCandidateNormalizedOutcome{node_id},\n"
        "  NormalizedOutcomeExpr.eval, PureOutcome.returned.injEq] at returnTargets\n"
        + state_relation
    )

    target_edge = {
        "target_node_id": target_node_id,
        "target_region_index": target_region_index,
        "target_target_id": continuation,
    }
    if return_case["kind"] == "nested":
        link = return_case["link"]
        link_literal = _lean_relational_runtime_call_frame_link(link)
        claim_literal = _lean_return_slot_frame_inventory_transfer_claim(
            return_case["outer_claim"]
        )
        target = _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=target_edge,
            frames="outer :: tailFrames",
            calls="outerContinuation :: tailContinuations",
            active="some expectedLink.resumeInventory",
            links="tailLinks",
            target_control_proof="controlAllowedNext",
            links_allowed_proof="linksAllowedNext",
            frame_facts_proof="frameFactsNext",
            stack_targets_proof=(
                "(by simpa only [RelationalRuntimeCallTargetsMapped] using "
                "stackTargetsReachable.2)"
            ),
        )
        body = (
            "cases continuations with\n"
            "| nil => simp at depthEnough\n"
            "| cons outerContinuation tailContinuations =>\n"
            "  cases frames with\n"
            "  | nil =>\n"
            "    have frameLengths :=\n"
            "      RelationalLinkedRuntimeCallStackHolds.length_eq\n"
            "        staticProofContext originalState candidateState _ _ _ _ stackHolds\n"
            "    simp at frameLengths\n"
            "  | cons outer tailFrames =>\n"
            "    cases links with\n"
            "    | nil =>\n"
            "      have impossible := stackHolds\n"
            "      simp [RelationalLinkedRuntimeCallStackHolds,\n"
            "        RelationalRuntimeCallFrameLinksHold] at impossible\n"
            "    | cons selectedLink tailLinks =>\n"
            f"      let expectedLink : RelationalRuntimeCallFrameLink := {link_literal}\n"
            f"      let outerClaim : ReturnSlotFrameInventoryTransferClaim := {claim_literal}\n"
            + "\n".join("      " + line for line in common.splitlines()) + "\n"
            "      have selectedLinkHolds := stackShape.2.2.2.2.1\n"
            "      have selectedLinkExact : selectedLink = expectedLink :=\n"
            "        LinkedProductControlProfile.selectedHeadLink_eq\n"
            "          linkedProductControlProfile " + str(continuation) + " expectedLink\n"
            "          selectedLink frame outer tailLinks (by decide) linksAllowed\n"
            "          frameContinuation selectedLinkHolds\n"
            "      subst selectedLink\n"
            "      have stackHoldsNext : RelationalLinkedRuntimeCallStackHolds\n"
            "          staticProofContext\n"
            f"          (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "          (outer :: tailFrames) (outerContinuation :: tailContinuations)\n"
            "          (some expectedLink.resumeInventory) tailLinks := by\n"
            "        exact RelationalLinkedRuntimeCallStackHolds."
            "popNestedAfterNoWriteTransfer\n"
            f"          staticProofContext world region{region_index}.inputInvariant\n"
            f"          {original_behavior} {candidate_behavior} outerClaim\n"
            "          originalState candidateState frame outer tailFrames\n"
            f"          {continuation} outerContinuation tailContinuations\n"
            f"          {active_inventory} expectedLink tailLinks stackHolds\n"
            "          (by decide) relatedForTransfer (by decide) (by decide)\n"
            "          (by decide) originalMemory candidateMemory\n"
            "      have linksAllowedNext := LinkedProductControlProfile.LinksAllowed.tail\n"
            "        linkedProductControlProfile expectedLink tailLinks linksAllowed\n"
            "      have controlAllowedRaw := LinkedProductControlProfile.allowsResumeOfLink\n"
            "        linkedProductControlProfile expectedLink frame outer tailContinuations\n"
            "        (by decide) selectedLinkHolds\n"
            "      have outerContinuationExact : outer.continuationTargetId =\n"
            "          outerContinuation := stackShape.2.2.2.1.2.2.2.2.1\n"
            "      have controlAllowedNext : linkedProductControlProfile.Allows\n"
            f"          {target_node_id} (outerContinuation :: tailContinuations)\n"
            "          (some expectedLink.resumeInventory) = true := by\n"
            "        simpa [expectedLink, outerContinuationExact] using controlAllowedRaw\n"
            "      have frameFactsNext := RelationalLinkedRuntimeCallFactsHold.of_stateRel\n"
            f"        staticProofContext world region{target_region_index}.inputInvariant\n"
            "        expectedLink.resumeInventory\n"
            f"        (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"        (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            "        (by decide) nextStatesRelated\n"
            "      simp only [RelationalCallFrame.resolves, Bool.and_eq_true, beq_iff_eq]\n"
            "        at frameResolves\n"
            "      rw [frameContinuation] at frameResolves\n"
            "      simp [originalWorldProgram, candidateWorldProgram]\n"
            "      rw [returnTargets.1, returnTargets.2, frameResolves.1, frameResolves.2]\n"
            "      simp\n"
            + "\n".join("    " + line for line in target.splitlines())
        )
    else:
        target = _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=target_edge,
            frames="[]", calls="[]", active="none", links="[]",
            target_control_proof="controlAllowedNext",
            links_allowed_proof="linksAllowedNext",
            frame_facts_proof=(
                "(by simp [RelationalLinkedRuntimeCallFactsHold])"
            ),
            stack_targets_proof=(
                "(by simp [RelationalRuntimeCallTargetsMapped])"
            ),
        )
        body = (
            "have shallowCalls :=\n"
            "  RelationalLinkedRuntimeCallStackHolds."
            "shallow_calls_of_excluded_resume_target\n"
            "    staticProofContext linkedProductControlProfile originalState\n"
            "    candidateState (frame :: frames) (" + str(continuation) + " :: continuations)\n"
            f"    (some {active_inventory}) links {continuation} (by simp)\n"
            "    (by decide) stackHolds linksAllowed\n"
            "have continuationsEmpty : continuations = [] := by\n"
            "  rcases shallowCalls with impossible | ⟨selected, singleton⟩\n"
            "  · simp at impossible\n"
            "  · exact (List.cons.inj singleton).2\n"
            "subst continuations\n"
            "cases frames with\n"
            "| nil =>\n"
            + "\n".join("  " + line for line in common.splitlines()) + "\n"
            + "  have linksEmpty : links = [] := by\n"
            "    cases links with\n"
            "    | nil => rfl\n"
            "    | cons link tail =>\n"
            "      have impossible := stackHolds\n"
            "      simp [RelationalLinkedRuntimeCallStackHolds,\n"
            "        RelationalRuntimeCallFrameLinksHold] at impossible\n"
            "  subst links\n"
            "  have stackHoldsNext :=\n"
            "    RelationalLinkedRuntimeCallStackHolds.popLastAfter\n"
            "      staticProofContext originalState candidateState\n"
            f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
            f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
            f"      frame {continuation} {active_inventory} (by\n"
            "        simpa using stackHolds)\n"
            "  have linksAllowedNext := LinkedProductControlProfile.LinksAllowed.nil\n"
            "    linkedProductControlProfile linkedProductControlProfileChecked\n"
            f"  let targetControlState : LinkedProductControlState := {target_control_state}\n"
            "  have controlAllowedNext : linkedProductControlProfile.Allows\n"
            f"      {target_node_id} [] none = true := by\n"
            "    exact LinkedProductControlProfile.allowsOfListedState\n"
            "      linkedProductControlProfile targetControlState _ _ _\n"
            "      linkedProductControlProfileChecked\n"
            "      (by simp [targetControlState, linkedProductControlProfile])\n"
            "      (by simp [targetControlState, LinkedProductControlState.matches])\n"
            "      (by simp [targetControlState])\n"
            "  simp only [RelationalCallFrame.resolves, Bool.and_eq_true, beq_iff_eq]\n"
            "    at frameResolves\n"
            "  rw [frameContinuation] at frameResolves\n"
            "  simp [originalWorldProgram, candidateWorldProgram]\n"
            "  rw [returnTargets.1, returnTargets.2, frameResolves.1, frameResolves.2]\n"
            "  simp\n"
            + "\n".join("" + line for line in target.splitlines())
            + "\n| cons unexpected tailFrames =>\n"
            "  have impossible := stackHolds\n"
            "  simp [RelationalLinkedRuntimeCallStackHolds,\n"
            "    RelationalRuntimeCallFramesHold] at impossible\n"
        )

    indented_body = "\n".join("      " + line for line in body.splitlines())
    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined :\n"
        "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      originalWorldProgram candidateWorldProgram {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {int(step['target_id'])} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
        "  unfold DecodedWorldProgram.transitionSystem\n"
        "  simp only [stepWorldExecution]\n"
        f"  rw [originalWorldBehaviorNode{node_id}, candidateWorldBehaviorNode{node_id}]\n"
        "  simp only [transitionFromWorldBehavior, transitionFromWorldOutcome,\n"
        "    NormalizedSymbolicBehavior.eval_outcome,\n"
        f"    acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"    acceptanceCandidateNormalizedOutcome{node_id}, NormalizedOutcomeExpr.eval]\n"
        + control
        + indented_body
    )


def _linked_empty_terminate_supported(
    step: dict[str, Any], linked_states: list[dict[str, Any]],
) -> bool:
    return bool(
        step.get("kind") == "terminate"
        and step.get("cases") is None
        and len(linked_states) == 1
        and linked_states[0].get("continuation_target_id") is None
        and linked_states[0].get("active_frame") is None
        and int(linked_states[0].get("minimum_depth", -1)) == 0
        and (step.get("control_state") or {}).get("calls") == []
    )


def _lean_acceptance_linked_empty_terminate_node(step: dict[str, Any]) -> str:
    """Reuse the existing semantic termination proof from an empty linked stack."""

    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined :\n"
        "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      originalWorldProgram candidateWorldProgram {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {int(step['target_id'])} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
        "  have controlHead : none = calls.head? ∧ none = active := by\n"
        "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
        "using controlMember.2\n"
        "  have controlShape : calls = [] ∧ active = none := by\n"
        "    constructor\n"
        "    · exact continuations_eq_nil_of_head?_eq_none calls controlHead.1\n"
        "    · exact controlHead.2.symm\n"
        "  rcases controlShape with ⟨rfl, rfl⟩\n"
        "  have stackShape : frames = [] ∧ links = [] := by\n"
        "    exact RelationalLinkedRuntimeCallStackHolds.empty_shape\n"
        "      staticProofContext originalState candidateState frames links stackHolds\n"
        "  rcases stackShape with ⟨rfl, rfl⟩\n"
        f"  have oldResult := acceptanceRunningNode{node_id}Refined [] [] []\n"
        "    eventIndex world originalState candidateState (by decide)\n"
        "    (by simp [RelationalRuntimeCallStackHolds])\n"
        "    (RelationalRuntimeCallFactsHold.empty staticProofContext world _ _)\n"
        "    (by simp [RelationalRuntimeCallTargetsMapped]) statesRelated\n"
        "  refine ⟨oldResult.1, ?_⟩\n"
        "  simpa [WorldExecutionsRelated, LinkedWorldExecutionsRelated] using oldResult.2"
    )


def _lean_acceptance_linked_active_jump_node(
    step: dict[str, Any], linked_case: dict[str, Any]
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    edge = linked_case["edge"]
    edge_id = int(edge["edge_id"])
    target_region_index = int(edge["target_region_index"])
    continuation = int(linked_case["continuation_target_id"])
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    frame_claim = _lean_return_slot_frame_inventory_transfer_claim(
        linked_case["frame_claim"]
    )
    frame_word_claims = linked_case["frame_claim"].get(
        "frame_exact_word_register_outputs", []
    )
    frame_expression_claims = linked_case["frame_claim"].get(
        "frame_paired_expression_register_outputs", []
    )
    fact_claim = _lean_runtime_call_import_transfer_claim(
        linked_case["source_active"], linked_case["target_active"],
        linked_case["frame_claim"].get("carried_relations"),
    )
    frame_word_claims_literal = "[" + ", ".join(
        _lean_frame_exact_word_register_output_claim(claim)
        for claim in frame_word_claims
    ) + "]"
    frame_expression_claims_literal = "[" + ", ".join(
        _lean_frame_paired_expression_register_output_claim(claim)
        for claim in frame_expression_claims
    ) + "]"
    if frame_word_claims or frame_expression_claims:
        frame_facts_transfer = (
            "      let activeFrameWordClaims : List "
            "FrameExactWordRegisterOutputClaim :=\n"
            f"        {frame_word_claims_literal}\n"
            "      let activeFrameExpressionClaims : List "
            "FramePairedExpressionRegisterOutputClaim :=\n"
            f"        {frame_expression_claims_literal}\n"
            "      have stackShape := stackHolds\n"
            "      simp only [RelationalLinkedRuntimeCallStackHolds] at stackShape\n"
            "      have frameFactsNext :=\n"
            "        RelationalLinkedRuntimeCallFactsHold."
            "afterInternalWithFrameEvidence\n"
            f"          staticProofContext world {original_behavior} "
            f"{candidate_behavior}\n"
            "          activeFactClaim activeFrameWordClaims "
            "activeFrameExpressionClaims frame originalState\n"
            "          candidateState (by decide)\n"
            "          (by simpa [activeFactClaim] using frameFactsHold)\n"
            "          (by simpa [activeFactClaim] using stackShape.2.1)\n"
            "          (by simpa [activeFactClaim] using stackShape.2.2.1)\n"
        )
    else:
        frame_facts_transfer = (
            "      have frameFactsNext :=\n"
            "        RelationalLinkedRuntimeCallFactsHold.afterInternal\n"
            f"          staticProofContext world {original_behavior} "
            f"{candidate_behavior}\n"
            "          activeFactClaim originalState candidateState (by decide)\n"
            "          (by simpa [activeFactClaim] using frameFactsHold)\n"
        )
    target_active = _lean_return_slot_offset_inventory(
        linked_case["target_active"]
    )
    target = _lean_acceptance_linked_running_target(
        node_id=node_id,
        edge=edge,
        frames="frame :: frames",
        calls=f"{continuation} :: continuations",
        active=f"some {target_active}",
        links="links",
        target_control_proof="controlAllowedNext",
        links_allowed_proof="linksAllowed",
        frame_facts_proof="frameFactsNext",
        stack_targets_proof="stackTargetsReachable",
    )
    indented_target = "\n".join("    " + line for line in target.splitlines())
    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined :\n"
        "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      originalWorldProgram candidateWorldProgram {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
        "  have controlShape : some " + str(continuation) + " = calls.head? ∧\n"
        "      some "
        + _lean_return_slot_offset_inventory(linked_case["source_active"])
        + " = active := by\n"
        "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
        "using controlMember.2\n"
        "  cases calls with\n"
        "  | nil => simp at controlShape\n"
        "  | cons continuation continuations =>\n"
        "    simp only [List.head?_cons, Option.some.injEq] at controlShape\n"
        "    rcases controlShape with ⟨rfl, rfl⟩\n"
        "    cases frames with\n"
        "    | nil => simp [RelationalLinkedRuntimeCallStackHolds] at stackHolds\n"
        "    | cons frame frames =>\n"
        f"      let activeFrameClaim : ReturnSlotFrameInventoryTransferClaim :=\n"
        f"        {frame_claim}\n"
        "      let activeFactClaim : RelationalRuntimeCallImportTransferClaim :=\n"
        f"        {fact_claim}\n"
        "      unfold DecodedWorldProgram.transitionSystem\n"
        "      simp only [stepWorldExecution]\n"
        f"      rw [originalWorldBehaviorNode{node_id}, candidateWorldBehaviorNode{node_id}]\n"
        "      simp only [transitionFromWorldBehavior, transitionFromWorldOutcome,\n"
        "        NormalizedSymbolicBehavior.eval_outcome,\n"
        "        NormalizedSymbolicBehavior.eval_x87Fault,\n"
        f"        acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"        acceptanceCandidateNormalizedOutcome{node_id}, NormalizedOutcomeExpr.eval]\n"
        f"      have originalBehaviorSegment : {original_behavior} =\n"
        f"          segmentRefinementEdge{edge_id}OriginalNormalizedBehavior := by decide\n"
        f"      have candidateBehaviorSegment : {candidate_behavior} =\n"
        f"          segmentRefinementEdge{edge_id}CandidateNormalizedBehavior := by decide\n"
        f"      have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
        "        originalState candidateState statesRelated\n"
        f"      have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
        "          originalState = true := by\n"
        f"        simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
        "      have transitioned := transition.2 guardTrue\n"
        "      have nextStatesRelated : StateRel staticProofContext world\n"
        f"          region{target_region_index}.inputInvariant\n"
        f"          (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"          (({candidate_behavior}.eval candidateState).nextMachineState candidateState) := by\n"
        "        rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
        "        exact transitioned.2.2.2\n"
        "      have originalMemory :\n"
        f"          (({original_behavior}.eval originalState).nextMachineState\n"
        "            originalState).memory = originalState.memory := by\n"
        f"        simp [RelationalBehavior.nextMachineState,\n"
        f"          acceptanceOriginalNormalizedWrites{node_id},\n"
        f"          originalBehavior{region_index}, evalNormalizedWrites,\n"
        "          applyConcreteWrites]\n"
        "      have candidateMemory :\n"
        f"          (({candidate_behavior}.eval candidateState).nextMachineState\n"
        "            candidateState).memory = candidateState.memory := by\n"
        f"        simp [RelationalBehavior.nextMachineState,\n"
        f"          acceptanceCandidateNormalizedWrites{node_id},\n"
        f"          candidateBehavior{region_index}, evalNormalizedWrites,\n"
        "          applyConcreteWrites]\n"
        "      have stackHoldsNext :=\n"
        "        RelationalLinkedRuntimeCallStackHolds.afterActiveTransfer\n"
        f"          staticProofContext world region{region_index}.inputInvariant\n"
        f"          {original_behavior} {candidate_behavior} activeFrameClaim\n"
        f"          originalState candidateState frame frames {continuation} continuations links\n"
        "          (by decide) (by simpa [activeFrameClaim] using stackHolds)\n"
        "          statesRelated originalMemory candidateMemory\n"
        + frame_facts_transfer
        +
        "      have controlAllowedNext : linkedProductControlProfile.Allows\n"
        f"          {int(edge['target_node_id'])} ({continuation} :: continuations)\n"
        f"          (some {target_active}) = true := by\n"
        "        simp only [LinkedProductControlProfile.Allows, Bool.and_eq_true]\n"
        "        exact ⟨linkedProductControlProfileChecked, by\n"
        "          simp [linkedProductControlProfile, "
        "linkedRuntimeCallFrameLinkCandidates]⟩\n"
        + indented_target
    )


def _lean_acceptance_linked_active_branch_node(
    step: dict[str, Any], linked_case: dict[str, Any],
    regions: list[dict[str, Any]], behaviors: list[dict[str, Any]],
    *, parameterized_environment: bool = False,
    parameterized_protocol_environment: bool = False,
) -> str:
    if parameterized_protocol_environment:
        raise StageAInputError(
            "linked active-frame branches do not yet support protocol environments"
        )
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    continuation = int(linked_case["continuation_target_id"])
    source_active_payload = linked_case["source_active"]
    source_active = _lean_return_slot_offset_inventory(source_active_payload)
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    edges = linked_case["edges"]
    taken = next(edge for edge in edges if bool(edge["branch_value"]))
    fallthrough = next(edge for edge in edges if not bool(edge["branch_value"]))
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        "    (_environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
        "      externalCallSites originalEnvironment candidateEnvironment) :\n"
        if parameterized_environment else "    :\n"
    )
    original_program = (
        "(originalWorldProgram originalEnvironment)"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment)"
        if parameterized_environment else "candidateWorldProgram"
    )
    original_behavior_arguments = (
        " originalEnvironment" if parameterized_environment else ""
    )
    candidate_behavior_arguments = (
        " candidateEnvironment" if parameterized_environment else ""
    )

    def branch_case(edge: dict[str, Any], condition: bool) -> str:
        edge_id = int(edge["edge_id"])
        target_node_id = int(edge["target_node_id"])
        target_region_index = int(edge["target_region_index"])
        candidate_condition = bool(
            edge.get("candidate_branch_value", condition)
        )
        candidate_condition_literal = (
            "true" if candidate_condition else "false"
        )
        claims = edge["return_slot_frame_transfer_claims"]
        frame_claim_payload = claims[0]
        target_active_payload = frame_claim_payload["target"]
        target_active = _lean_return_slot_offset_inventory(target_active_payload)
        frame_claim = _lean_return_slot_frame_inventory_transfer_claim(
            frame_claim_payload
        )
        frame_word_claims = frame_claim_payload.get(
            "frame_exact_word_register_outputs", []
        )
        frame_expression_claims = frame_claim_payload.get(
            "frame_paired_expression_register_outputs", []
        )
        fact_claim = _lean_runtime_call_import_transfer_claim(
            source_active_payload, target_active_payload,
            frame_claim_payload.get("carried_relations"),
        )
        frame_word_claims_literal = "[" + ", ".join(
            _lean_frame_exact_word_register_output_claim(claim)
            for claim in frame_word_claims
        ) + "]"
        frame_expression_claims_literal = "[" + ", ".join(
            _lean_frame_paired_expression_register_output_claim(claim)
            for claim in frame_expression_claims
        ) + "]"
        if frame_word_claims or frame_expression_claims:
            frame_facts_transfer = (
                "      let activeFrameWordClaims : List "
                "FrameExactWordRegisterOutputClaim :=\n"
                f"        {frame_word_claims_literal}\n"
                "      let activeFrameExpressionClaims : List "
                "FramePairedExpressionRegisterOutputClaim :=\n"
                f"        {frame_expression_claims_literal}\n"
                "      have stackShape := stackHolds\n"
                "      simp only [RelationalLinkedRuntimeCallStackHolds] at stackShape\n"
                "      have frameFactsNext :=\n"
                "        RelationalLinkedRuntimeCallFactsHold."
                "afterInternalWithFrameEvidence\n"
                f"          staticProofContext world {original_behavior} "
                f"{candidate_behavior}\n"
                "          activeFactClaim activeFrameWordClaims "
                "activeFrameExpressionClaims frame originalState\n"
                "          candidateState (by decide)\n"
                "          (by simpa [activeFactClaim] using frameFactsHold)\n"
                "          (by simpa [activeFactClaim] using stackShape.2.1)\n"
                "          (by simpa [activeFactClaim] using stackShape.2.2.1)\n"
            )
        else:
            frame_facts_transfer = (
                "      have frameFactsNext :=\n"
                "        RelationalLinkedRuntimeCallFactsHold.afterInternal\n"
                f"          staticProofContext world {original_behavior} "
                f"{candidate_behavior}\n"
                "          activeFactClaim originalState candidateState (by decide)\n"
                "          (by simpa [activeFactClaim] using frameFactsHold)\n"
            )
        guard_claim = _lean_frame_exact_guard_claim(edge["frame_guard_claim"])
        if _normalized_behavior_fast_path(
            regions[region_index], behaviors[region_index]
        ):
            segment_original_behavior = f"region{region_index}NormalizedBehavior"
            segment_candidate_behavior = f"region{region_index}NormalizedBehavior"
        else:
            segment_original_behavior = (
                f"segmentRefinementEdge{edge_id}OriginalNormalizedBehavior"
            )
            segment_candidate_behavior = (
                f"segmentRefinementEdge{edge_id}CandidateNormalizedBehavior"
            )
        original_guard = (
            f"        change region{region_index}OutcomeCondition.eval "
            "originalState = true\n"
            "        exact originalCondition\n"
            if condition else
            f"        change (!region{region_index}OutcomeCondition.eval "
            "originalState) = true\n"
            "        simp [originalCondition]\n"
        )
        target = _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=edge,
            frames="frame :: frames",
            calls=f"{continuation} :: continuations",
            active=f"some {target_active}",
            links="links",
            target_control_proof="controlAllowedNext",
            links_allowed_proof="linksAllowed",
            frame_facts_proof="frameFactsNext",
            stack_targets_proof="stackTargetsReachable",
        )
        indented_target = "\n".join(
            "      " + line for line in target.splitlines()
        )
        return (
            "      let activeFrameClaim : "
            "ReturnSlotFrameInventoryTransferClaim :=\n"
            f"        {frame_claim}\n"
            "      let activeFactClaim : "
            "RelationalRuntimeCallImportTransferClaim :=\n"
            f"        {fact_claim}\n"
            "      let activeGuardClaim : FrameExactGuardClaim :=\n"
            f"        {guard_claim}\n"
            f"      have originalBehaviorSegment : {original_behavior} =\n"
            f"          {segment_original_behavior} := by decide\n"
            f"      have candidateBehaviorSegment : {candidate_behavior} =\n"
            f"          {segment_candidate_behavior} := by decide\n"
            "      have guardAgreement :\n"
            f"          segmentRefinementEdge{edge_id}Spec.originalGuard.eval "
            "originalState =\n"
            f"            segmentRefinementEdge{edge_id}Spec.candidateGuard.eval "
            "candidateState := by\n"
            "        exact RelationalLinkedRuntimeCallFactsHold."
            "guardEvalEqual_of_frameExact\n"
            f"          staticProofContext world {source_active}\n"
            f"          segmentRefinementEdge{edge_id}Spec.originalGuard\n"
            f"          segmentRefinementEdge{edge_id}Spec.candidateGuard "
            "activeGuardClaim\n"
            "          originalState candidateState (by decide)\n"
            "          (by simpa [activeGuardClaim] using frameFactsHold)\n"
            f"      have originalGuard : segmentRefinementEdge{edge_id}Spec."
            "originalGuard.eval\n"
            "          originalState = true := by\n"
            + original_guard
            + f"      have transitioned := segmentRefinementEdge{edge_id}"
            "TransitionChecked world\n"
            "        originalState candidateState statesRelated guardAgreement "
            "originalGuard\n"
            "      have nextStatesRelated : StateRel staticProofContext world\n"
            f"          region{target_region_index}.inputInvariant\n"
            f"          (({original_behavior}.eval originalState).nextMachineState "
            "originalState)\n"
            f"          (({candidate_behavior}.eval candidateState).nextMachineState "
            "candidateState) := by\n"
            "        rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
            "        exact transitioned.2.2.2\n"
            "      have originalMemory :\n"
            f"          (({original_behavior}.eval originalState).nextMachineState\n"
            "            originalState).memory = originalState.memory := by\n"
            "        simp [RelationalBehavior.nextMachineState,\n"
            f"          acceptanceOriginalNormalizedWrites{node_id},\n"
            f"          originalBehavior{region_index}, evalNormalizedWrites,\n"
            "          applyConcreteWrites]\n"
            "      have candidateMemory :\n"
            f"          (({candidate_behavior}.eval candidateState).nextMachineState\n"
            "            candidateState).memory = candidateState.memory := by\n"
            "        simp [RelationalBehavior.nextMachineState,\n"
            f"          acceptanceCandidateNormalizedWrites{node_id},\n"
            f"          candidateBehavior{region_index}, evalNormalizedWrites,\n"
            "          applyConcreteWrites]\n"
            "      have stackHoldsNext :=\n"
            "        RelationalLinkedRuntimeCallStackHolds.afterActiveTransfer\n"
            f"          staticProofContext world region{region_index}.inputInvariant\n"
            f"          {original_behavior} {candidate_behavior} activeFrameClaim\n"
            f"          originalState candidateState frame frames {continuation} "
            "continuations links\n"
            "          (by decide) (by simpa [activeFrameClaim] using stackHolds)\n"
            "          statesRelated originalMemory candidateMemory\n"
            + frame_facts_transfer
            +
            "      have controlAllowedNext : linkedProductControlProfile.Allows\n"
            f"          {target_node_id} ({continuation} :: continuations)\n"
            f"          (some {target_active}) = true := by\n"
            "        simp only [LinkedProductControlProfile.Allows, "
            "Bool.and_eq_true]\n"
            "        exact ⟨linkedProductControlProfileChecked, by\n"
            "          simp [linkedProductControlProfile, "
            "linkedRuntimeCallFrameLinkCandidates]⟩\n"
            f"      have candidateGuard : segmentRefinementEdge{edge_id}Spec."
            "candidateGuard.eval\n"
            "          candidateState = true := by\n"
            "        rw [← guardAgreement]\n"
            "        exact originalGuard\n"
            f"      have candidateCondition : segmentRefinementEdge{edge_id}"
            "CandidateOutcomeCondition.eval\n"
            f"          candidateState = {candidate_condition_literal} := by\n"
            "        exact normalizedBranchCondition_eval_of_guard_true\n"
            f"          segmentRefinementEdge{edge_id}CandidateOutcomeCondition\n"
            f"          segmentRefinementEdge{edge_id}Spec.candidateGuard\n"
            f"          {candidate_condition_literal} candidateState (by decide) "
            "candidateGuard\n"
            f"      simp only [region{region_index}OutcomeCondition,\n"
            f"        segmentRefinementEdge{edge_id}CandidateOutcomeCondition] at\n"
            "        originalCondition candidateCondition\n"
            "      simp [originalCondition, candidateCondition]\n"
            + indented_target
        )

    source_prefix = (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined\n"
        + environment_binders
        +
        "    LinkedRunningProductNodeStepRefined staticProofContext "
        "relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      {original_program} {candidate_program} {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState "
        "candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at "
        "controlMember\n"
        f"  have controlShape : some {continuation} = calls.head? ∧\n"
        f"      some {source_active} = active := by\n"
        "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
        "using controlMember.2\n"
        "  cases calls with\n"
        "  | nil => simp at controlShape\n"
        "  | cons continuation continuations =>\n"
        "    simp only [List.head?_cons, Option.some.injEq] at controlShape\n"
        "    rcases controlShape with ⟨rfl, rfl⟩\n"
        "    cases frames with\n"
        "    | nil => simp [RelationalLinkedRuntimeCallStackHolds] at stackHolds\n"
        "    | cons frame frames =>\n"
        "      unfold DecodedWorldProgram.transitionSystem\n"
        "      simp only [stepWorldExecution]\n"
        f"      rw [originalWorldBehaviorNode{node_id}{original_behavior_arguments}, "
        f"candidateWorldBehaviorNode{node_id}{candidate_behavior_arguments}]\n"
        "      simp only [transitionFromWorldBehavior, transitionFromWorldOutcome,\n"
        "        NormalizedSymbolicBehavior.eval_outcome,\n"
        "        NormalizedSymbolicBehavior.eval_x87Fault,\n"
        f"        acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"        acceptanceCandidateNormalizedOutcome{node_id}, "
        "NormalizedOutcomeExpr.eval]\n"
        f"      cases originalCondition : region{region_index}OutcomeCondition.eval "
        "originalState with\n"
    )
    return (
        source_prefix
        + "      | false =>\n"
        + branch_case(fallthrough, False)
        + "\n      | true =>\n"
        + branch_case(taken, True)
    )


def _lean_acceptance_linked_empty_jump_node(
    step: dict[str, Any], *, parameterized_environment: bool = False,
    parameterized_protocol_environment: bool = False,
) -> str:
    """Emit a native linked-stack node proof for an empty-stack internal jump."""

    if not _linked_empty_jump_supported(step):
        raise StageAInputError(
            f"acceptance node {step.get('node_id')} is not an empty-stack jump"
        )
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    edge = step["edges"][0]
    edge_id = int(edge["edge_id"])
    target_region_index = int(edge["target_region_index"])
    original_behavior = f"acceptanceOriginalNormalizedBehavior{node_id}"
    candidate_behavior = f"acceptanceCandidateNormalizedBehavior{node_id}"
    original_program = (
        "(originalWorldProgram originalEnvironment"
        + (" originalProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "originalWorldProgram"
    )
    candidate_program = (
        "(candidateWorldProgram candidateEnvironment"
        + (" candidateProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "candidateWorldProgram"
    )
    environment_binders = (
        "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
        + (
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            if parameterized_protocol_environment else ""
        )
        + "    (_environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
        "      externalCallSites originalEnvironment candidateEnvironment) :\n"
        if parameterized_environment else ""
    )
    behavior_arguments = (
        " originalEnvironment"
        + (" originalProtocolEnvironment" if parameterized_protocol_environment else "")
        if parameterized_environment else ""
    )
    candidate_behavior_arguments = (
        " candidateEnvironment"
        + (" candidateProtocolEnvironment" if parameterized_protocol_environment else "")
        if parameterized_environment else ""
    )
    return (
        f"theorem acceptanceLinkedRunningNode{node_id}Refined\n"
        + environment_binders
        + ("    " if parameterized_environment else "    :\n")
        + "    LinkedRunningProductNodeStepRefined staticProofContext relationalProductGraph\n"
        "      productInvariantTable relationalProductReachabilityEvidence\n"
        "      linkedProductControlProfile protocolCallbackTargets\n"
        f"      {original_program} {candidate_program} {node_id} := by\n"
        "  unfold LinkedRunningProductNodeStepRefined\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
        f"    some relationalProductGraph.nodes[{node_id}] by decide), sourceInvariant]\n"
        "  simp only\n"
        f"  have sourceTarget : relationalProductGraph.nodes[{node_id}].targetId =\n"
        f"      {target_id} := by decide\n"
        "  rw [sourceTarget]\n"
        "  intro frames calls active links eventIndex world originalState candidateState\n"
        "    controlAllowed stackHolds linksAllowed frameFactsHold\n"
        "    stackTargetsReachable statesRelated\n"
        "  have controlMember := controlAllowed\n"
        "  simp only [LinkedProductControlProfile.authority, "
        "LinkedProductControlProfile.Allows, Bool.and_eq_true] at controlMember\n"
        "  have controlHead : none = calls.head? ∧ none = active := by\n"
        "    simpa [linkedProductControlProfile, LinkedProductControlState.matches] "
        "using controlMember.2\n"
        "  have controlShape : calls = [] ∧ active = none := by\n"
        "    constructor\n"
        "    · exact continuations_eq_nil_of_head?_eq_none calls controlHead.1\n"
        "    · exact controlHead.2.symm\n"
        "  rcases controlShape with ⟨rfl, rfl⟩\n"
        "  have stackShape : frames = [] ∧ links = [] := by\n"
        "    exact RelationalLinkedRuntimeCallStackHolds.empty_shape\n"
        "      staticProofContext originalState candidateState frames links stackHolds\n"
        "  rcases stackShape with ⟨rfl, rfl⟩\n"
        "  unfold DecodedWorldProgram.transitionSystem\n"
        "  simp only [stepWorldExecution]\n"
        f"  rw [originalWorldBehaviorNode{node_id}{behavior_arguments},\n"
        f"    candidateWorldBehaviorNode{node_id}{candidate_behavior_arguments}]\n"
        "  simp only [transitionFromWorldBehavior, transitionFromWorldOutcome,\n"
        "    NormalizedSymbolicBehavior.eval_outcome,\n"
        f"    acceptanceOriginalNormalizedOutcome{node_id},\n"
        f"    acceptanceCandidateNormalizedOutcome{node_id}, NormalizedOutcomeExpr.eval]\n"
        f"  have originalBehaviorSegment : {original_behavior} =\n"
        f"      segmentRefinementEdge{edge_id}OriginalNormalizedBehavior := by decide\n"
        f"  have candidateBehaviorSegment : {candidate_behavior} =\n"
        f"      segmentRefinementEdge{edge_id}CandidateNormalizedBehavior := by decide\n"
        f"  have transition := segmentRefinementEdge{edge_id}TransitionChecked world\n"
        "    originalState candidateState statesRelated\n"
        f"  have guardTrue : segmentRefinementEdge{edge_id}Spec.originalGuard.eval\n"
        "      originalState = true := by\n"
        f"    simp [segmentRefinementEdge{edge_id}Spec, BoolExpr.eval, Expr.eval]\n"
        "  have transitioned := transition.2 guardTrue\n"
        "  have nextStatesRelated : StateRel staticProofContext world\n"
        f"      region{target_region_index}.inputInvariant\n"
        f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState) := by\n"
        "    rw [originalBehaviorSegment, candidateBehaviorSegment]\n"
        "    exact transitioned.2.2.2\n"
        "  have stackHoldsNext : RelationalLinkedRuntimeCallStackHolds\n"
        "      staticProofContext\n"
        f"      (({original_behavior}.eval originalState).nextMachineState originalState)\n"
        f"      (({candidate_behavior}.eval candidateState).nextMachineState candidateState)\n"
        "      [] [] none [] := by\n"
        "    simp [RelationalLinkedRuntimeCallStackHolds]\n"
        "  have linksAllowedNext : linkedProductControlProfile.LinksAllowed [] := by\n"
        "    exact LinkedProductControlProfile.LinksAllowed.nil\n"
        "      linkedProductControlProfile linkedProductControlProfileChecked\n"
        "  have frameFactsNext : RelationalLinkedRuntimeCallFactsHold staticProofContext\n"
        "      world none\n"
        f"      ({original_behavior}.eval originalState).registers\n"
        f"      ({candidate_behavior}.eval candidateState).registers := by\n"
        "    simp [RelationalLinkedRuntimeCallFactsHold]\n"
        + _lean_acceptance_linked_running_target(
            node_id=node_id,
            edge=edge,
            stack_targets_proof="stackTargetsReachable",
        )
    )


def _lean_acceptance_execution_edge(
    *, step: dict[str, Any], edge: dict[str, Any]
) -> str:
    node_id = int(step["node_id"])
    region_index = int(step["region_index"])
    target_id = int(step["target_id"])
    edge_id = int(edge["edge_id"])
    target_node_id = int(edge["target_node_id"])
    target_region_index = int(edge["target_region_index"])
    target_target_id = int(edge["target_target_id"])
    node_resolution_theorems = [
        f"(show relationalProductGraph.getNode? {node_id} = "
        f"some relationalProductGraph.nodes[{node_id}] by decide)"
    ]
    if target_node_id != node_id:
        node_resolution_theorems.append(
            f"(show relationalProductGraph.getNode? {target_node_id} = "
            f"some relationalProductGraph.nodes[{target_node_id}] by decide)"
        )
    invariant_rewrites = ["sourceInvariant"]
    if target_node_id != node_id:
        invariant_rewrites.append("targetInvariant")
    if step["kind"] in {"external_call", "external_protocol"}:
        return (
            f"theorem acceptanceExecutionEdge{edge_id}Refined :\n"
            "    RelationalProductExecutionEdgeRefined staticProofContext\n"
            "      relationalProductGraph allRegions productInvariantTable "
            f"{edge_id} := by\n"
            "  apply Or.inr\n"
            "  unfold RelationalExternalExecutionEdgeRefined\n"
            f"  rw [externalCallEdge{edge_id}ProductResolved]\n"
            "  simp only\n"
            f"  have edgeSourceNode : relationalProductGraph.edges[{edge_id}].sourceNodeId =\n"
            f"      {node_id} := by decide\n"
            f"  have edgeTargetNode : relationalProductGraph.edges[{edge_id}].targetNodeId =\n"
            f"      {target_node_id} := by decide\n"
            f"  have edgeSourceTarget : relationalProductGraph.edges[{edge_id}].sourceTargetId =\n"
            f"      {target_id} := by decide\n"
            f"  have edgeTargetTarget : relationalProductGraph.edges[{edge_id}].targetTargetId =\n"
            f"      {target_target_id} := by decide\n"
            "  rw [edgeSourceNode, edgeTargetNode, edgeSourceTarget, edgeTargetTarget,\n"
            f"    {', '.join(node_resolution_theorems)}]\n"
            f"  have regionFound : regionById allRegions {target_id} = "
            f"some region{region_index} := by decide\n"
            f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
            f"      some region{region_index}.inputInvariant := by decide\n"
            f"  have targetInvariant : productInvariantTable.nodeInvariants[{target_node_id}]? =\n"
            f"      some region{target_region_index}.inputInvariant := by decide\n"
            f"  rw [regionFound, {', '.join(invariant_rewrites)}]\n"
            f"  refine ⟨externalCallSite{edge_id}, externalCallEdge{edge_id}Spec,\n"
            f"    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,\n"
            f"    externalCallEdge{edge_id}ProductRefinementChecked⟩\n"
            "  all_goals decide"
        )
    return (
        f"theorem acceptanceExecutionEdge{edge_id}Refined :\n"
        "    RelationalProductExecutionEdgeRefined staticProofContext\n"
        "      relationalProductGraph allRegions productInvariantTable "
        f"{edge_id} := by\n"
        "  apply Or.inl\n"
        "  unfold RelationalInternalExecutionEdgeRefined\n"
        f"  rw [productEdge{edge_id}Resolved]\n"
        "  simp only\n"
        f"  have edgeSourceNode : relationalProductGraph.edges[{edge_id}].sourceNodeId =\n"
        f"      {node_id} := by decide\n"
        f"  have edgeTargetNode : relationalProductGraph.edges[{edge_id}].targetNodeId =\n"
        f"      {target_node_id} := by decide\n"
        f"  have edgeSourceTarget : relationalProductGraph.edges[{edge_id}].sourceTargetId =\n"
        f"      {target_id} := by decide\n"
        f"  have edgeTargetTarget : relationalProductGraph.edges[{edge_id}].targetTargetId =\n"
        f"      {target_target_id} := by decide\n"
        "  rw [edgeSourceNode, edgeTargetNode, edgeSourceTarget, edgeTargetTarget,\n"
        f"    {', '.join(node_resolution_theorems)}]\n"
        f"  have regionFound : regionById allRegions {target_id} = "
        f"some region{region_index} := by decide\n"
        f"  have sourceInvariant : productInvariantTable.nodeInvariants[{node_id}]? =\n"
        f"      some region{region_index}.inputInvariant := by decide\n"
        f"  have targetInvariant : productInvariantTable.nodeInvariants[{target_node_id}]? =\n"
        f"      some region{target_region_index}.inputInvariant := by decide\n"
        f"  rw [regionFound, {', '.join(invariant_rewrites)}]\n"
        f"  refine ⟨segmentRefinementEdge{edge_id}Spec, ?_, ?_, ?_, ?_, ?_, ?_,\n"
        f"    productEdge{edge_id}Refined⟩\n"
        "  all_goals decide"
    )

def _paired_launch_import_bindings(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    *,
    reserved_ranges: list[tuple[int, int]],
) -> tuple[list[dict[str, Any]], str | None]:
    def identity(imported: Any) -> tuple[str, str, str | int] | None:
        if imported.thunk_rva is None:
            return None
        dll = str(imported.dll).lower()
        if imported.symbol is not None:
            return (dll, "symbol", str(imported.symbol))
        if imported.ordinal is not None:
            return (dll, "ordinal", int(imported.ordinal))
        return None

    original_groups: dict[
        tuple[str, str, str | int], list[Any]
    ] = {}
    candidate_groups: dict[
        tuple[str, str, str | int], list[Any]
    ] = {}
    for imported in original_bin.imports:
        key = identity(imported)
        if key is None:
            return [], "the original import table has an unresolved IAT entry"
        original_groups.setdefault(key, []).append(imported)
    for imported in candidate_bin.imports:
        key = identity(imported)
        if key is None:
            return [], "the candidate import table has an unresolved IAT entry"
        candidate_groups.setdefault(key, []).append(imported)
    if set(original_groups) != set(candidate_groups):
        return [], "the images do not have the same normalized import identities"
    for key in original_groups:
        if len(original_groups[key]) != len(candidate_groups[key]):
            return [], f"the import occurrence count differs for {key!r}"

    def allocate(start: int, used: set[int]) -> int | None:
        address = start
        while address + 4 <= 2**32:
            if address not in used and all(
                address + 4 <= lower or upper <= address
                for lower, upper in reserved_ranges
            ):
                used.add(address)
                return address
            address += 0x1000
        return None

    used: set[int] = set()
    addresses: dict[tuple[str, str, str | int], tuple[int, int]] = {}
    for index, key in enumerate(sorted(original_groups, key=repr)):
        original_address = allocate(0x60000000 + index * 0x1000, used)
        candidate_address = allocate(0x68000000 + index * 0x1000, used)
        if original_address is None or candidate_address is None:
            return [], "no disjoint synthetic import-address range is available"
        addresses[key] = (original_address, candidate_address)

    bindings: list[dict[str, Any]] = []
    for key in sorted(original_groups, key=repr):
        original_address, candidate_address = addresses[key]
        for original_import, candidate_import in zip(
            original_groups[key], candidate_groups[key], strict=True
        ):
            imported: dict[str, Any] = {"dll": key[0]}
            imported[key[1]] = key[2]
            bindings.append({
                "id": len(bindings),
                "import": imported,
                "original_iat_rva": int(original_import.thunk_rva),
                "candidate_iat_rva": int(candidate_import.thunk_rva),
                "original_address": original_address,
                "candidate_address": candidate_address,
            })
    return bindings, None


def _semantic_bool_is_structural_tautology(expression: object) -> bool:
    """Recognize a small proof-by-reduction fragment used at launch roots.

    This is only a generation gate. The emitted `StateRel` launch theorem still
    evaluates the predicate in Lean, so a mistaken proposal cannot authorize
    acceptance.
    """
    if not isinstance(expression, dict):
        return False
    operation = expression.get("op")
    if operation == "bool_constant":
        return expression.get("value") is True
    if operation == "equal":
        return expression.get("left") == expression.get("right")
    if operation == "and":
        return (
            _semantic_bool_is_structural_tautology(expression.get("left"))
            and _semantic_bool_is_structural_tautology(expression.get("right"))
        )
    if operation != "or":
        return False
    left = expression.get("left")
    right = expression.get("right")
    if (
        isinstance(left, dict)
        and left.get("op") == "not"
        and left.get("value") == right
    ) or (
        isinstance(right, dict)
        and right.get("op") == "not"
        and right.get("value") == left
    ):
        return True
    return (
        _semantic_bool_is_structural_tautology(left)
        or _semantic_bool_is_structural_tautology(right)
    )


def _launch_state_predicates_structurally_true(predicates: object) -> bool:
    if not isinstance(predicates, list):
        return False
    return all(
        isinstance(predicate, dict)
        and predicate.get("exact_memory_reads", []) == []
        and _semantic_bool_is_structural_tautology(predicate.get("original"))
        and _semantic_bool_is_structural_tautology(predicate.get("candidate"))
        for predicate in predicates
    )


def _segment_module_ownership(
    segment_refinement_modules: list[dict[str, Any]] | None,
) -> dict[int, str]:
    ownership: dict[int, str] = {}
    for segment_module in segment_refinement_modules or []:
        module = str(segment_module["module"])
        for raw_edge_id in segment_module.get("edge_ids", []):
            edge_id = int(raw_edge_id)
            previous = ownership.setdefault(edge_id, module)
            if previous != module:
                raise StageAInputError(
                    f"segment edge {edge_id} is owned by both {previous} and {module}"
                )
    return ownership


def _acceptance_segment_imports(
    selected_steps: list[dict[str, Any]], segment_module_by_edge: Mapping[int, str]
) -> str:
    edge_ids = {
        int(edge["edge_id"])
        for step in selected_steps
        if step.get("kind") not in {
            "external_call", "external_protocol", "control_unrepresented",
        }
        for edge in step.get("edges", [])
    }
    missing = sorted(edge_ids - segment_module_by_edge.keys())
    if missing:
        raise StageAInputError(
            "acceptance steps reference segment edges without generated Lean "
            f"owners: {missing}"
        )
    modules = sorted({segment_module_by_edge[edge_id] for edge_id in edge_ids})
    return "".join(f"import StageA.{module}\n" for module in modules)


def _write_relational_acceptance_modules(
    lean_dir: Path,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    product_graph: dict[str, Any],
    register_relations: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    decode_chunk_regions: list[list[int]],
    external_site_candidates: list[dict[str, Any]],
    *,
    runtime_frame_affine: Mapping[str, Any] | None = None,
    deferred_guard_segment_candidates: list[dict[str, Any]] | None = None,
    segment_refinement_modules: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    stage_a = lean_dir / "StageA"
    for path in [
        *stage_a.glob("RelationalAcceptance*.lean"),
        *stage_a.glob("RelationalAcceptance*.olean"),
        *stage_a.glob("RelationalLaunch*.lean"),
        *stage_a.glob("RelationalLaunch*.olean"),
        *stage_a.glob("RelationalLinkedControl*.lean"),
        *stage_a.glob("RelationalLinkedControl*.olean"),
        *stage_a.glob("RelationalAffineLinkedControl*.lean"),
        *stage_a.glob("RelationalAffineLinkedControl*.olean"),
    ]:
        path.unlink()
    _write_text_if_changed(
        stage_a / "RelationalAcceptanceExactLockstep.lean",
        relational_exact_lockstep_acceptance_source(),
    )
    _write_text_if_changed(
        stage_a / "RelationalAcceptanceOpaqueLockstep.lean",
        relational_opaque_lockstep_acceptance_source(),
    )
    all_segment_candidates = (
        segment_candidates + list(deferred_guard_segment_candidates or [])
    )
    segment_module_by_edge = _segment_module_ownership(
        segment_refinement_modules
    )
    x87_region_indices = {
        int(candidate["source_region_index"])
        for candidate in all_segment_candidates
        if str(candidate.get("certificate_profile", "")).startswith(
            "composable_x87_"
        )
    }
    physical_state_only_region_indices = {
        index
        for index in x87_region_indices
        if original_bin.pe.get_data(
            int(contract["regions"][index]["original"]["rva_start"]),
            int(contract["regions"][index]["original"]["size"]),
        ) == b"\x9b"
        or candidate_bin.pe.get_data(
            int(contract["regions"][index]["candidate"]["rva_start"]),
            int(contract["regions"][index]["candidate"]["size"]),
        ) == b"\x9b"
    }
    plan = _whole_program_acceptance_plan(
        contract, behaviors, product_graph, register_relations,
        all_segment_candidates,
        external_site_candidates,
        runtime_frame_affine=runtime_frame_affine,
        physical_state_only_region_indices=physical_state_only_region_indices,
        launch_profile={
            "original_is_dll": original_bin.is_dll,
            "candidate_is_dll": candidate_bin.is_dll,
            "original_exports": (
                [
                    {
                        "ordinal": exported.ordinal,
                        "name": exported.name,
                        "rva": exported.rva,
                        "kind": exported.kind,
                        "forwarder": exported.forwarder,
                    }
                    for exported in original_bin.exports
                ]
                if original_bin.exports is not None else None
            ),
            "candidate_exports": (
                [
                    {
                        "ordinal": exported.ordinal,
                        "name": exported.name,
                        "rva": exported.rva,
                        "kind": exported.kind,
                        "forwarder": exported.forwarder,
                    }
                    for exported in candidate_bin.exports
                ]
                if candidate_bin.exports is not None else None
            ),
            "original_export_parse_error": original_bin.export_parse_error,
            "candidate_export_parse_error": candidate_bin.export_parse_error,
            "original_loader_diagnostics": (
                original_bin.loader_diagnostics.as_payload()
            ),
            "candidate_loader_diagnostics": (
                candidate_bin.loader_diagnostics.as_payload()
            ),
            "original_tls_directory": {
                "rva": original_bin.tls_directory_rva,
                "size": original_bin.tls_directory_size,
            },
            "candidate_tls_directory": {
                "rva": candidate_bin.tls_directory_rva,
                "size": candidate_bin.tls_directory_size,
            },
            "original_tls_callback_rvas": original_bin.tls_callback_rvas,
            "candidate_tls_callback_rvas": candidate_bin.tls_callback_rvas,
            "original_tls_callback_array_immutable": (
                original_bin.tls_callback_array_immutable
            ),
            "candidate_tls_callback_array_immutable": (
                candidate_bin.tls_callback_array_immutable
            ),
            "original_tls_callback_parse_error": (
                original_bin.tls_callback_parse_error
            ),
            "candidate_tls_callback_parse_error": (
                candidate_bin.tls_callback_parse_error
            ),
        },
    )
    opaque_inventory = _opaque_lockstep_inventory_plan(
        original_bin,
        candidate_bin,
        contract,
        behaviors,
        plan,
        external_site_candidates,
    )
    plan["opaque_lockstep_environment"] = {
        key: value
        for key, value in opaque_inventory.items()
        if key != "artifact"
    }
    opaque_profile = opaque_inventory["status"] == "ready"
    if opaque_profile:
        opaque_artifact = opaque_inventory["artifact"]
        write_json(lean_dir.parent / "opaque-lockstep-environment.json", opaque_artifact)
        _write_text_if_changed(
            stage_a / "RelationalAcceptanceOpaqueLockstepData.lean",
            relational_opaque_lockstep_environment_source(opaque_artifact),
        )
        bindings_by_node_case = {
            (int(item["node_id"]), item.get("case_index")): int(item["site_id"])
            for item in opaque_inventory["site_bindings"]
        }
        for step in plan.get("node_steps", []):
            node_id = int(step["node_id"])
            cases = step.get("cases")
            if isinstance(cases, list):
                annotated = False
                for case_index, case in enumerate(cases):
                    site_id = bindings_by_node_case.get((node_id, case_index))
                    if site_id is not None:
                        case["opaque_lockstep_site_id"] = site_id
                        annotated = True
                if annotated:
                    step["opaque_lockstep_profile"] = True
            else:
                site_id = bindings_by_node_case.get((node_id, None))
                if site_id is not None:
                    step["opaque_lockstep_site_id"] = site_id
                    step["opaque_lockstep_profile"] = True
    elif opaque_inventory["status"] == "incomplete":
        plan = {
            **plan,
            "status": "incomplete",
            "theorem": None,
            "blockers": _compact_acceptance_blockers([
                *plan.get("blockers", []),
                *opaque_inventory["gaps"],
            ]),
        }
    launch_plan = plan.get("launch") or {}
    launch_root_node_id = plan.get("root_node_id", launch_plan.get("root_node_id"))
    if launch_root_node_id is not None:
        root_node_id = int(launch_root_node_id)
        root_region = contract["regions"][root_node_id]
        input_relations = root_region.get("input_relations", [])
        self_related_inputs = all(
            relation.get("original") == relation.get("candidate")
            and relation.get("relation") in {"exact", "related_word"}
            for relation in input_relations
        )
        launch_reasons: list[str] = []
        if original_bin.image_base != candidate_bin.image_base:
            launch_reasons.append("the preferred image bases differ")
        if original_bin.size_of_image != candidate_bin.size_of_image:
            launch_reasons.append("the preferred image spans differ")
        value_targets = list(contract.get("value_targets", []))
        if any(
            int(target.get("mapped_size", 0)) != 0
            and int(target.get("original_value", -1))
                != int(target.get("candidate_value", -2))
            for target in value_targets
        ):
            launch_reasons.append("the static data map is not identity-addressed")
        if contract.get("static_dynamic_pointer_slots"):
            launch_reasons.append("the launch has static dynamic-pointer slots")
        if not self_related_inputs:
            launch_reasons.append(
                "root register relations are not concrete self relations"
            )
        for key in (
            "input_import_relations",
            "input_dynamic_range_relations",
            "input_dynamic_stack_range_relations",
            "bounds",
            "address_separations",
            "state_predicates",
        ):
            if (
                key == "state_predicates"
                and root_region.get(key)
                and _launch_state_predicates_structurally_true(
                    root_region.get(key)
                )
            ):
                continue
            if root_region.get(key):
                launch_reasons.append(f"the root invariant has {key}")
        stack_size = 4096
        stack_base = 0x70000000
        stack_pointer = stack_base + stack_size // 2
        code_target_by_id = {
            int(target["id"]): target for target in contract.get("code_targets", [])
        }
        launch_frames: list[dict[str, int]] = []
        occupied_frame_bytes: set[tuple[str, int]] = set()
        continuation_target_ids = [
            int(target_id)
            for target_id in launch_plan.get("continuation_target_ids", [])
        ]
        frame_offsets = list(launch_plan.get("frame_offsets", []))
        if len(continuation_target_ids) != len(frame_offsets):
            launch_reasons.append(
                "the TLS continuation and return-slot inventories differ in length"
            )
        for frame_index, (continuation_target_id, inventory) in enumerate(
            zip(continuation_target_ids, frame_offsets, strict=False)
        ):
            locations = list(inventory.get("locations", []))
            esp_locations = [
                location for location in locations
                if location.get("original_register") == "esp"
                and location.get("candidate_register") == "esp"
            ]
            target = code_target_by_id.get(continuation_target_id)
            if target is None:
                launch_reasons.append(
                    f"TLS frame {frame_index} has no canonical continuation target"
                )
                continue
            if not esp_locations:
                launch_reasons.append(
                    f"TLS frame {frame_index} has no paired ESP-relative slot"
                )
                continue
            location = esp_locations[0]
            original_offset = int(location.get("original", 2**32))
            candidate_offset = int(location.get("candidate", 2**32))
            original_stack_address = stack_pointer + original_offset
            candidate_stack_address = stack_pointer + candidate_offset
            if (
                original_offset >= 2**31
                or candidate_offset >= 2**31
                or original_stack_address < stack_base
                or candidate_stack_address < stack_base
                or original_stack_address + 16 > stack_base + stack_size
                or candidate_stack_address + 16 > stack_base + stack_size
            ):
                launch_reasons.append(
                    f"TLS frame {frame_index} is outside the bounded launch stack"
                )
                continue
            frame_byte_keys = {
                *(('original', original_stack_address + byte) for byte in range(16)),
                *(('candidate', candidate_stack_address + byte) for byte in range(16)),
            }
            if occupied_frame_bytes.intersection(frame_byte_keys):
                launch_reasons.append(
                    f"TLS frame {frame_index} overlaps another launch frame"
                )
                continue
            occupied_frame_bytes.update(frame_byte_keys)
            launch_frames.append({
                "continuation_target_id": continuation_target_id,
                "original_return_address": (
                    original_bin.image_base + int(target["original_rva"])
                ),
                "candidate_return_address": (
                    candidate_bin.image_base + int(target["candidate_rva"])
                ),
                "original_stack_address": original_stack_address,
                "candidate_stack_address": candidate_stack_address,
            })
        stack_windows = root_region.get("stack_windows", [])
        if any(
            int(window.get("range_id", -1)) != 0
            or window.get("original_register") != "esp"
            or window.get("candidate_register") != "esp"
            or int(window.get("bytes_below", -1)) < 0
            or int(window.get("bytes_above", -1)) < 0
            or stack_pointer - int(window.get("bytes_below", 0)) < stack_base
            or stack_pointer + int(window.get("bytes_above", 0))
                > stack_base + stack_size
            for window in stack_windows
        ):
            launch_reasons.append(
                "the root stack windows are outside the bounded ESP launch profile"
            )
        for image in (original_bin, candidate_bin):
            image_end = image.image_base + image.size_of_image
            if not (
                stack_base + stack_size <= image.image_base
                or image_end <= stack_base
            ):
                launch_reasons.append("the canonical launch stack overlaps an image")
                break
        import_bindings, import_pair_error = _paired_launch_import_bindings(
            original_bin,
            candidate_bin,
            reserved_ranges=[
                (
                    original_bin.image_base,
                    original_bin.image_base + original_bin.size_of_image,
                ),
                (
                    candidate_bin.image_base,
                    candidate_bin.image_base + candidate_bin.size_of_image,
                ),
                (stack_base, stack_base + stack_size),
            ],
        )
        if import_pair_error is not None:
            launch_reasons.append(import_pair_error)
        if launch_reasons:
            launch_blocker = {
                "code": "launch_realizability_certificate_unsupported",
                "message": (
                    "no checked concrete launch-state certificate is available: "
                    + "; ".join(launch_reasons)
                ),
                "next_action": (
                    "extend the generic launch-memory/state witness checker for this "
                    "constraint family"
                ),
            }
            plan = {
                **plan,
                "status": "incomplete",
                "theorem": None,
                "blockers": [*plan.get("blockers", []), launch_blocker],
            }
        else:
            plan["launch_realizability"] = {
                "profile": (
                    "paired-preferred-base-import-stack-tls-static-v2"
                    if (
                        launch_frames
                        or value_targets
                        or contract.get("static_word_relation_slots")
                    )
                    else "paired-preferred-base-import-stack-v1"
                ),
                "stack_base": stack_base,
                "stack_size": stack_size,
                "stack_pointer": stack_pointer,
                "import_bindings": import_bindings,
                "frames": launch_frames,
            }
    write_json(lean_dir.parent / "whole-program-acceptance.json", plan)
    affine_linked_control = plan.get("affine_linked_control")
    if (
        isinstance(affine_linked_control, Mapping)
        and affine_linked_control.get("shape_projection_status") == "complete"
        and affine_linked_control.get("gaps") == []
    ):
        write_relational_affine_linked_control_module(
            lean_dir, affine_linked_control
        )
        write_relational_affine_linked_control_binding_modules(
            lean_dir, affine_linked_control
        )
        write_relational_affine_linked_call_binding_modules(
            lean_dir, affine_linked_control
        )
        write_relational_affine_linked_external_call_binding_modules(
            lean_dir, affine_linked_control
        )
        write_relational_affine_linked_memory_binding_modules(
            lean_dir, affine_linked_control
        )
    linked_control = plan["linked_control"]
    linked_rows = []
    for state in linked_control["states"]:
        continuation = (
            "none" if state["continuation_target_id"] is None
            else f"some {int(state['continuation_target_id'])}"
        )
        active = (
            "none" if state["active_frame"] is None
            else "some " + _lean_return_slot_offset_inventory(state["active_frame"])
        )
        linked_rows.append(
            "{ nodeId := " + str(int(state["node_id"]))
            + f", continuation := {continuation}, active := {active}"
            + f", minimumDepth := {int(state['minimum_depth'])} }}"
        )
    linked_link_rows = [
        "{ callSourceTargetId := " + str(int(link["call_source_target_id"]))
        + ", resumeNodeId := " + str(int(link["resume_node_id"]))
        + ", resumeTargetId := " + str(int(link["resume_target_id"]))
        + ", resumeContinuation := " + str(int(link["resume_continuation"]))
        + ", innerInventory := "
        + _lean_return_slot_offset_inventory(link["inner_inventory"])
        + ", suspendedInventory := "
        + _lean_return_slot_offset_inventory(link["suspended_inventory"])
        + ", resumeInventory := "
        + _lean_return_slot_offset_inventory(link["resume_inventory"])
        + ", originalGap := " + str(int(link["original_gap"]))
        + ", candidateGap := " + str(int(link["candidate_gap"])) + " }"
        for link in linked_control["links"]
    ]
    linked_control_source = (
        "import StageA.RelationalLinkedFrames\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "def linkedRuntimeCallFrameLinkCandidates :\n"
        "    List RelationalRuntimeCallFrameLink := ["
        + ", ".join(linked_link_rows) + "]\n\n"
        "def linkedProductControlProfile : LinkedProductControlProfile := {\n"
        "  states := [" + ", ".join(linked_rows) + "]\n"
        "  links := linkedRuntimeCallFrameLinkCandidates\n"
        "}\n\n"
        "theorem linkedProductControlProfileChecked :\n"
        "    linkedProductControlProfile.checked = true := by decide\n\n"
        "theorem linkedRuntimeCallFrameLinkCandidatesChecked :\n"
        "    linkedRuntimeCallFrameLinkCandidates.all\n"
        "      RelationalRuntimeCallFrameLink.checked = true := by native_decide\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLinkedControlProfile.lean", linked_control_source
    )
    acceptance_ready = plan["status"] == "ready"
    if "launch_realizability" not in plan:
        return plan

    nodes = product_graph["nodes"]
    root_node_id = int(plan["root_node_id"])
    launch_plan = plan["launch"]
    entry_root_node_id = int(launch_plan["entry_root_node_id"])
    entry_target_id = int(launch_plan["entry_target_id"])
    tls_callback_node_ids = [
        int(node_id) for node_id in launch_plan["tls_callback_node_ids"]
    ]
    tls_callback_target_ids = [
        int(target_id) for target_id in launch_plan["tls_callback_target_ids"]
    ]
    launch_continuation_target_ids = [
        *tls_callback_target_ids[1:], entry_target_id
    ] if tls_callback_target_ids else []
    node_id_by_target = {
        int(node["target_id"]): node_id for node_id, node in enumerate(nodes)
    }
    launch_continuation_node_ids = [
        node_id_by_target[target_id]
        for target_id in launch_continuation_target_ids
    ]
    launch_frame_offsets = [
        _lean_return_slot_offset_inventory(inventory)
        for inventory in launch_plan["frame_offsets"]
    ]
    parameterized_environment = any(
        step["kind"] in {
            "external_call", "external_protocol", "external_jump", "external_terminate"
        }
        for step in plan["node_steps"]
    )
    parameterized_protocol_environment = any(
        step["kind"] == "external_protocol" for step in plan["node_steps"]
    )
    linked_states_by_node: dict[int, list[dict[str, Any]]] = {}
    for linked_state in linked_control["states"]:
        linked_states_by_node.setdefault(int(linked_state["node_id"]), []).append(
            linked_state
        )
    linked_acceptance_steps = list(plan.get("node_steps", []))
    linked_native_cases_by_node: dict[int, tuple[str, dict[str, Any] | None]] = {}
    for step in linked_acceptance_steps:
        node_id = int(step["node_id"])
        states = linked_states_by_node.get(node_id, [])
        direct_call = _linked_direct_call_case(step, states, linked_control)
        linked_return = _linked_return_case(step, states, linked_control)
        active_jump = _linked_active_jump_case(step, states)
        active_branch = _linked_active_branch_case(step, states)
        if direct_call is not None:
            linked_native_cases_by_node[node_id] = ("direct_call", direct_call)
        elif linked_return is not None:
            linked_native_cases_by_node[node_id] = ("return", linked_return)
        elif active_jump is not None:
            linked_native_cases_by_node[node_id] = ("active_jump", active_jump)
        elif active_branch is not None:
            linked_native_cases_by_node[node_id] = (
                "active_branch", active_branch
            )
        elif _linked_empty_jump_supported(step):
            linked_native_cases_by_node[node_id] = ("empty_jump", None)
        elif _linked_empty_terminate_supported(step, states):
            linked_native_cases_by_node[node_id] = ("empty_terminate", None)
    linked_native_ready = bool(
        acceptance_ready
        and not parameterized_environment
        and not launch_frame_offsets
        and not plan.get("protocol_callback_states")
        and linked_acceptance_steps
        and len(linked_native_cases_by_node) == len(linked_acceptance_steps)
    )
    linked_empty_jump_ready = bool(
        acceptance_ready
        and not parameterized_environment
        and not launch_frame_offsets
        and not plan.get("protocol_callback_states")
        and linked_acceptance_steps
        and all(_linked_empty_jump_supported(step) for step in linked_acceptance_steps)
        and all(
            len(linked_states_by_node.get(int(step["node_id"]), [])) == 1
            and linked_states_by_node[int(step["node_id"])][0].get(
                "continuation_target_id"
            ) is None
            and linked_states_by_node[int(step["node_id"])][0].get("active_frame")
                is None
            for step in linked_acceptance_steps
        )
    )
    linked_shallow_compatibility_ready = bool(
        acceptance_ready
        and not launch_frame_offsets
        and linked_acceptance_steps
        and _linked_shallow_profiles_supported(
            list(plan.get("control_states", [])), linked_control
        )
    )
    deferred_guard_node_ids = {
        int(step["node_id"])
        for step in linked_acceptance_steps
        if _step_uses_deferred_guard(step)
    }
    linked_mixed_frame_guard_ready = bool(
        linked_shallow_compatibility_ready
        and not parameterized_protocol_environment
        and deferred_guard_node_ids
        and all(
            (
                linked_native_cases_by_node.get(node_id, (None, None))[0]
                == "active_branch"
            )
            for node_id in deferred_guard_node_ids
        )
    )
    ordinary_profile_eligible = bool(
        acceptance_ready and not deferred_guard_node_ids
    )
    linked_acceptance_mode = (
        "native-linked-call-return-v1"
        if linked_native_ready else
        "lean-checked-shallow-with-native-frame-guards-v1"
        if linked_mixed_frame_guard_ready else
        "native-empty-stack-internal-jump-v1"
        if linked_empty_jump_ready else
        "lean-checked-shallow-profile-compatibility-v1"
        if linked_shallow_compatibility_ready and ordinary_profile_eligible else None
    )
    linked_acceptance_ready = linked_acceptance_mode is not None
    # Shallow linked acceptance is a checked wrapper around the ordinary node
    # proofs, while native linked modes close their nodes directly.
    ordinary_acceptance_ready = bool(
        ordinary_profile_eligible
        and (
            not linked_acceptance_ready
            or linked_acceptance_mode
                == "lean-checked-shallow-profile-compatibility-v1"
        )
    )
    plan["linked_acceptance"] = {
        "status": "ready" if linked_acceptance_ready else "incomplete",
        "profile": linked_acceptance_mode,
        "theorem": (
            RELATIONAL_LINKED_ACCEPTANCE_THEOREM
            if linked_acceptance_ready else None
        ),
        "blockers": [] if linked_acceptance_ready else [
            {
                "code": "linked_acceptance_node_family_pending",
                "message": (
                    "the linked acceptance generator does not yet cover every "
                    "reachable node, recursive call-frame, and launch-frame family"
                ),
                "next_action": (
                    "add native linked call, return, branch, termination, and "
                    "external-cutpoint node proofs"
                ),
            }
        ],
    }
    if plan["status"] == "ready":
        selected_theorem = choose_relational_acceptance_theorem(
            ordinary_ready=ordinary_acceptance_ready,
            linked_ready=linked_acceptance_ready,
        )
        if selected_theorem is None:
            plan = {
                **plan,
                "status": "incomplete",
                "theorem": None,
                "blockers": [
                    *plan.get("blockers", []),
                    {
                        "code": "whole_program_acceptance_theorem_pending",
                        "message": (
                            "no supported generated whole-program theorem closes "
                            "the selected control model"
                        ),
                        "next_action": (
                            "complete linked whole-program acceptance for every "
                            "reachable node"
                        ),
                    },
                ],
            }
        else:
            plan["required_theorem"] = selected_theorem
            plan["theorem"] = selected_theorem
    write_json(lean_dir.parent / "whole-program-acceptance.json", plan)
    acceptance_ready = plan["status"] == "ready"
    root_invariant = _lean_region_input_invariant(root_region)
    terminal_region_index = int(plan["terminal_region_index"])
    terminal_invariant = _lean_state_invariant(plan["terminal_invariant"])
    invariant_rows = ", ".join(
        f"region{node_id}.inputInvariant" for node_id in range(len(nodes))
    )
    control_rows = ", ".join(
        "{ nodeId := " + str(int(state["node_id"]))
        + ", calls := [" + ", ".join(str(int(item)) for item in state["calls"])
        + "], frameOffsets := ["
        + ", ".join(
            _lean_return_slot_offset_inventory(offsets)
            for offsets in state["frame_offsets"]
        )
        + "] }"
        for state in plan["control_states"]
    )
    callback_target_rows = ", ".join(
        "{ nodeId := " + str(int(state["node_id"]))
        + ", activeFrameOffset := "
        + _lean_return_slot_offset_pair(state["active_frame_offset"])
        + ", returnInvariant := terminalInvariant"
        + ", outerFrameTransferRules := ["
        + ", ".join(
            _lean_return_slot_transfer_rule(rule)
            for rule in state["outer_frame_transfer_rules"]
        )
        + "] }"
        for state in plan["protocol_callback_states"]
    )
    inert_protocol_source = (
        "def inertWorldProtocolEnvironment : WorldExternalProtocolEnvironment := {\n"
        "  action := fun request => .returned { state := request.state, world := request.world }\n"
        "}\n\n"
    )
    if parameterized_environment:
        protocol_parameter = (
            " (protocolEnvironment : WorldExternalProtocolEnvironment)"
            if parameterized_protocol_environment else ""
        )
        protocol_assignment = (
            "protocolEnvironment" if parameterized_protocol_environment
            else "inertWorldProtocolEnvironment"
        )
        world_program_source = (
            inert_protocol_source
            + "def originalWorldProgram (environment : WorldExternalEnvironment)"
            + protocol_parameter + " : DecodedWorldProgram := {\n"
            "  candidate := false\n  context := staticProofContext\n"
            "  regions := allRegions\n  externalCallSites\n"
            f"  environment\n  protocolEnvironment := {protocol_assignment}\n}}\n\n"
            + "def candidateWorldProgram (environment : WorldExternalEnvironment)"
            + protocol_parameter + " : DecodedWorldProgram := {\n"
            "  candidate := true\n  context := staticProofContext\n"
            "  regions := allRegions\n  externalCallSites\n"
            f"  environment\n  protocolEnvironment := {protocol_assignment}\n}}\n\n"
        )
    else:
        world_program_source = (
            inert_protocol_source
            + "def inertWorldEnvironment : WorldExternalEnvironment := {\n"
            "  result := fun _ event => { state := event.state, world := event.world }\n"
            "}\n\n"
            "def originalWorldProgram : DecodedWorldProgram := {\n"
            "  candidate := false\n  context := staticProofContext\n"
            "  regions := allRegions\n  externalCallSites\n"
            "  environment := inertWorldEnvironment\n"
            "  protocolEnvironment := inertWorldProtocolEnvironment\n}\n\n"
            "def candidateWorldProgram : DecodedWorldProgram := {\n"
            "  candidate := true\n  context := staticProofContext\n"
            "  regions := allRegions\n  externalCallSites\n"
            "  environment := inertWorldEnvironment\n"
            "  protocolEnvironment := inertWorldProtocolEnvironment\n}\n\n"
        )
    launch_definition_source = (
        "import StageA.RelationalCertificates\n"
        "import StageA.RelationalStaticContextBase\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "def consoleLaunch : PE32ConsoleLaunchV2 := {\n"
        f"  rootNodeId := {root_node_id}\n"
        f"  rootTargetId := {int(nodes[root_node_id]['target_id'])}\n"
        f"  entryNodeId := {entry_root_node_id}\n"
        f"  entryTargetId := {entry_target_id}\n"
        "  tlsCallbackNodeIds := ["
        + ", ".join(str(node_id) for node_id in tls_callback_node_ids)
        + "]\n"
        "  tlsCallbackTargetIds := ["
        + ", ".join(str(target_id) for target_id in tls_callback_target_ids)
        + "]\n"
        f"  rootInvariant := {root_invariant}\n"
        "  frameOffsets := [" + ", ".join(launch_frame_offsets) + "]\n"
        "}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchDefinition.lean", launch_definition_source
    )
    linked_shallow_compatibility_source = ""
    if linked_acceptance_mode in {
        "lean-checked-shallow-profile-compatibility-v1",
        "lean-checked-shallow-with-native-frame-guards-v1",
    }:
        linked_shallow_compatibility_source = (
            "theorem productControlProfilesShallowEquivalentChecked :\n"
            "    ProductControlProfilesShallowEquivalent productControlProfile\n"
            "      linkedProductControlProfile = true := by decide\n\n"
            "theorem productControlProfilesOldToLinkedShallow :\n"
            "    ProductControlProfilesOldToLinkedShallow productControlProfile\n"
            "      linkedProductControlProfile :=\n"
            "  ProductControlProfilesShallowEquivalent.oldToLinked\n"
            "    productControlProfile linkedProductControlProfile\n"
            "    productControlProfilesShallowEquivalentChecked\n\n"
            "theorem productControlProfilesLinkedToOldShallow :\n"
            "    ProductControlProfilesLinkedToOldShallow productControlProfile\n"
            "      linkedProductControlProfile :=\n"
            "  ProductControlProfilesShallowEquivalent.linkedToOld\n"
            "    productControlProfile linkedProductControlProfile\n"
            "    productControlProfilesShallowEquivalentChecked\n\n"
            "theorem linkedProductControlProfileLinksEmpty :\n"
            "    linkedProductControlProfile.links = [] :=\n"
            "  ProductControlProfilesShallowEquivalent.links_eq_nil\n"
            "    productControlProfile linkedProductControlProfile\n"
            "    productControlProfilesShallowEquivalentChecked\n\n"
        )
    opaque_acceptance_import = (
        "import StageA.RelationalAcceptanceOpaqueLockstepData\n"
        if opaque_profile else ""
    )
    acceptance_environment_alias = (
        "abbrev AcceptanceExternalEnvironmentsRefine\n"
        "    (original candidate : WorldExternalEnvironment) : Prop :=\n"
        "  OpaqueLockstepExternalEnvironmentsRefine staticProofContext\n"
        "    externalCallSites opaqueLockstepCallSites\n"
        "    (opaqueLockstepCallSites.map fun site => site.id) original candidate\n\n"
        if opaque_profile else
        "abbrev AcceptanceExternalEnvironmentsRefine\n"
        "    (original candidate : WorldExternalEnvironment) : Prop :=\n"
        "  ExactLockstepExternalEnvironmentsRefine staticProofContext\n"
        "    externalCallSites original candidate\n\n"
    )
    context_source = (
        "import StageA.RelationalCertificates\n"
        "import StageA.RelationalLinkedExecution\n"
        "import StageA.RelationalLaunchDefinition\n"
        "import StageA.RelationalLinkedControlProfile\n"
        "import StageA.RelationalProofClosureBase\n"
        "import StageA.RelationalProofStaticUsageCertificate\n"
        "import StageA.RelationalProductGraphCertificate\n"
        "import StageA.RelationalProductNodeCoverageCertificate\n"
        "import StageA.RelationalProductReachabilityCertificate\n"
        "import StageA.RelationalProductDecodedControlCertificate\n"
        "import StageA.RelationalReachableProductLocalCertificate\n"
        "import StageA.RelationalExternalCallSites\n"
        "import StageA.RelationalImportRegisterSeedCertificate\n"
        "import StageA.RelationalDynamicRangeIndirectCallCertificate\n"
        "import StageA.RelationalExternalCallRefinementCertificate\n"
        "import StageA.RelationalExternalJumpRefinementCertificate\n"
        "import StageA.RelationalAcceptanceExactLockstep\n"
        "import StageA.RelationalAcceptanceOpaqueLockstep\n"
        + opaque_acceptance_import
        + "\n"
        +
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + acceptance_environment_alias
        +
        f"def terminalInvariant : StateInvariant := {terminal_invariant}\n\n"
        "def productInvariantTable : ProductInvariantTable := {\n"
        f"  nodeInvariants := #[{invariant_rows}]\n"
        "  terminalInvariant\n"
        "}\n\n"
        "def productControlProfile : ProductControlProfile := {\n"
        f"  states := [{control_rows}]\n"
        "}\n\n"
        + linked_shallow_compatibility_source
        + "def protocolCallbackTargets : ProtocolCallbackTargetProfile := {\n"
        f"  states := [{callback_target_rows}]\n"
        "}\n\n"
        + world_program_source
        + (
            _lean_acceptance_linked_shallow_lift(
                parameterized_environment=parameterized_environment,
                parameterized_protocol_environment=
                    parameterized_protocol_environment,
            )
            if linked_acceptance_mode in {
                "lean-checked-shallow-profile-compatibility-v1",
                "lean-checked-shallow-with-native-frame-guards-v1",
            }
            else ""
        )
        + "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalAcceptanceContext.lean", context_source
    )

    launch_witness = plan["launch_realizability"]
    stack_base = int(launch_witness["stack_base"])
    stack_size = int(launch_witness["stack_size"])
    stack_pointer = int(launch_witness["stack_pointer"])
    import_binding_rows = ", ".join(
        "{ id := " + str(int(binding["id"]))
        + ", imported := " + _lean_external_target(binding["import"])
        + ", originalIatRva := " + str(int(binding["original_iat_rva"]))
        + ", candidateIatRva := " + str(int(binding["candidate_iat_rva"]))
        + ", originalAddress := BitVec.ofNat 32 "
        + str(int(binding["original_address"]))
        + ", candidateAddress := BitVec.ofNat 32 "
        + str(int(binding["candidate_address"])) + " }"
        for binding in launch_witness["import_bindings"]
    )
    launch_frame_rows = ", ".join(
        "{ continuationTargetId := "
        + str(int(frame["continuation_target_id"]))
        + ", originalReturnAddress := BitVec.ofNat 32 "
        + str(int(frame["original_return_address"]))
        + ", candidateReturnAddress := BitVec.ofNat 32 "
        + str(int(frame["candidate_return_address"]))
        + ", originalStackAddress := BitVec.ofNat 32 "
        + str(int(frame["original_stack_address"]))
        + ", candidateStackAddress := BitVec.ofNat 32 "
        + str(int(frame["candidate_stack_address"]))
        + ", protectedBytes := 16"
        + " }"
        for frame in launch_witness["frames"]
    )
    original_launch_writes: list[tuple[int, int]] = []
    candidate_launch_writes: list[tuple[int, int]] = []
    for frame in launch_witness["frames"]:
        original_stack_address = int(frame["original_stack_address"])
        candidate_stack_address = int(frame["candidate_stack_address"])
        original_launch_writes.extend([
            (original_stack_address, int(frame["original_return_address"])),
            (original_stack_address + 4, original_bin.image_base),
            (original_stack_address + 8, 1),
            (original_stack_address + 12, 0),
        ])
        candidate_launch_writes.extend([
            (candidate_stack_address, int(frame["candidate_return_address"])),
            (candidate_stack_address + 4, candidate_bin.image_base),
            (candidate_stack_address + 8, 1),
            (candidate_stack_address + 12, 0),
        ])

    def stack_offset_writes(
        writes: list[tuple[int, int]], *, side: str
    ) -> list[tuple[int, int]]:
        result: list[tuple[int, int]] = []
        for address, value in writes:
            offset = address - stack_base
            if offset < 0 or offset + 4 > stack_size:
                raise StageAInputError(
                    f"{side} launch write at {address:#x} is outside the "
                    "checked launch stack range"
                )
            result.append((offset, value))
        return result

    original_stack_writes = stack_offset_writes(
        original_launch_writes, side="original"
    )
    candidate_stack_writes = stack_offset_writes(
        candidate_launch_writes, side="candidate"
    )

    def lean_stack_writes(writes: list[tuple[int, int]]) -> str:
        return ", ".join(
            "(" + str(offset) + ", BitVec.ofNat 32 " + str(value) + ")"
            for offset, value in writes
        )

    launch_context_source = (
        "import StageA.RelationalLaunchDefinition\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        "def consoleLaunchStackRange : DynamicAddressRangePair := {\n"
        "  id := 0\n"
        f"  originalBase := BitVec.ofNat 32 {stack_base}\n"
        f"  candidateBase := BitVec.ofNat 32 {stack_base}\n"
        f"  size := {stack_size}\n"
        "}\n\n"
        f"def consoleLaunchImportAddresses : List ImportAddressPair := [{import_binding_rows}]\n\n"
        f"def consoleLaunchFrames : List RelationalRuntimeCallFrame := [{launch_frame_rows}]\n\n"
        "def consoleLaunchOriginalStackWrites : List (Nat × Word) := ["
        + lean_stack_writes(original_stack_writes) + "]\n\n"
        "def consoleLaunchCandidateStackWrites : List (Nat × Word) := ["
        + lean_stack_writes(candidate_stack_writes) + "]\n\n"
        "def consoleLaunchOriginalWrites : List (Word × Word) :=\n"
        "  stackRangeConcreteWrites consoleLaunchStackRange.originalBase\n"
        "    consoleLaunchOriginalStackWrites\n\n"
        "def consoleLaunchCandidateWrites : List (Word × Word) :=\n"
        "  stackRangeConcreteWrites consoleLaunchStackRange.candidateBase\n"
        "    consoleLaunchCandidateStackWrites\n\n"
        "def consoleLaunchWorld : RelationalWorld := {\n"
        "  stackRanges := [consoleLaunchStackRange]\n"
        "  importAddresses := consoleLaunchImportAddresses\n"
        "}\n\n"
        "def consoleLaunchRegisters : Registers Word := {\n"
        "  eax := BitVec.ofNat 32 0\n"
        "  ebx := BitVec.ofNat 32 0\n"
        "  ecx := BitVec.ofNat 32 0\n"
        "  edx := BitVec.ofNat 32 0\n"
        "  esi := BitVec.ofNat 32 0\n"
        "  edi := BitVec.ofNat 32 0\n"
        "  ebp := BitVec.ofNat 32 0\n"
        f"  esp := BitVec.ofNat 32 {stack_pointer}\n"
        "}\n\n"
        "def consoleLaunchOriginalMemory : Memory :=\n"
        "  applyConcreteWrites\n"
        "    (loaderPopulatedPreferredBaseMemory false staticProofContext consoleLaunchWorld)\n"
        "    consoleLaunchOriginalWrites\n\n"
        "def consoleLaunchCandidateExcludedMemory : Memory :=\n"
        "  applyConcreteWrites\n"
        "    (loaderPopulatedPreferredBaseMemory true staticProofContext consoleLaunchWorld)\n"
        "    consoleLaunchCandidateWrites\n\n"
        "def consoleLaunchCandidateMemory : Memory :=\n"
        "  ordinaryMemoryCandidateProjection staticProofContext consoleLaunchWorld\n"
        "    (staticProofContext.relationalValueTargets consoleLaunchWorld)\n"
        "    consoleLaunchOriginalMemory consoleLaunchCandidateExcludedMemory\n\n"
        "def consoleLaunchOriginalState : MachineState := {\n"
        "  registers := consoleLaunchRegisters\n"
        "  memory := consoleLaunchOriginalMemory\n"
        "}\n\n"
        "def consoleLaunchCandidateState : MachineState := {\n"
        "  registers := consoleLaunchRegisters\n"
        "  memory := consoleLaunchCandidateMemory\n"
        "}\n\n"
        "def consoleLaunchOriginalImageMappedAt : Nat -> Bool :=\n"
        "  preferredBaseImageMemoryAt staticProofContext.originalPe\n"
        "    staticProofContext.originalImports consoleLaunchOriginalState.memory\n\n"
        "def consoleLaunchCandidateImageCompatibilityAt : Nat -> Bool :=\n"
        "  candidateProjectionImageCompatibleAt staticProofContext consoleLaunchWorld\n"
        "\n"
        "def consoleLaunchOriginalImmutableImageAt : Nat -> Bool :=\n"
        "  immutableImageWordMemoryAtWithImports staticProofContext.originalPe\n"
        "    staticProofContext.originalImports consoleLaunchOriginalState.memory\n\n"
        "def consoleLaunchCandidateImmutableImageAt : Nat -> Bool :=\n"
        "  immutableImageWordMemoryAtWithImports staticProofContext.candidatePe\n"
        "    staticProofContext.candidateImports consoleLaunchCandidateState.memory\n\n"
        "def consoleLaunchStackMemoryAt : Nat -> Bool :=\n"
        "  stackRangeMemoryHoldAt staticProofContext consoleLaunchWorld\n"
        "    consoleLaunchOriginalState.memory consoleLaunchCandidateState.memory\n"
        "    consoleLaunchStackRange\n\n"
        "def consoleLaunchStaticWordSlotAt : Nat -> Bool :=\n"
        "  staticWordRelationSlotMemoryHoldAt staticProofContext consoleLaunchWorld\n"
        "    consoleLaunchOriginalState.memory consoleLaunchCandidateState.memory\n\n"
        "theorem consoleLaunchWorldValid :\n"
        "    PE32ConsoleLaunchWorldV1.Valid staticProofContext consoleLaunchWorld := by\n"
        "  unfold PE32ConsoleLaunchWorldV1.Valid\n"
        "  refine ⟨by decide, by decide, rfl, rfl, rfl, rfl, by decide,\n"
        "    by decide⟩\n\n"
        "theorem consoleLaunchCandidateLoaderImageChecked :\n"
        "    preferredBaseLoaderImageValid staticProofContext.candidatePe = true := by\n"
        "  decide\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchContext.lean", launch_context_source
    )

    launch_chunk_size = max(
        1,
        int(os.environ.get(
            "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_CHECK_CHUNK",
            "1024",
        )),
    )
    launch_stack_chunk_size = max(
        1,
        int(os.environ.get(
            "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_STACK_CHECK_CHUNK",
            "64",
        )),
    )
    launch_aggregation_fanout = max(
        2,
        int(os.environ.get(
            "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_LAUNCH_AGGREGATION_FANOUT",
            "8",
        )),
    )
    launch_leaf_module_by_theorem: dict[str, str] = {}
    launch_aggregation_source = (
        "import StageA.RelationalLaunchContext\n"
        "import StageA.RelationalStaticTree\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "theorem launchAllIndexedBoolRangesHold_append (predicate : Nat -> Bool) :\n"
        "    ∀ left right,\n"
        "      AllIndexedBoolRangesHold predicate left ->\n"
        "      AllIndexedBoolRangesHold predicate right ->\n"
        "      AllIndexedBoolRangesHold predicate (left ++ right) := by\n"
        "  intro left\n"
        "  induction left with\n"
        "  | nil =>\n"
        "      intro right _ rightHolds\n"
        "      simpa [AllIndexedBoolRangesHold] using rightHolds\n"
        "  | cons span spans ih =>\n"
        "      intro right leftHolds rightHolds\n"
        "      change IndexedBoolRangeHolds predicate span ∧\n"
        "        AllIndexedBoolRangesHold predicate spans at leftHolds\n"
        "      change IndexedBoolRangeHolds predicate span ∧\n"
        "        AllIndexedBoolRangesHold predicate (spans ++ right)\n"
        "      exact And.intro leftHolds.1\n"
        "        (ih right leftHolds.2 rightHolds)\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchProofAggregation.lean",
        launch_aggregation_source,
    )

    def write_launch_span_leaves(
        *,
        module_prefix: str,
        theorem_prefix: str,
        spans: list[tuple[int, int]],
        predicate: str,
        chunk_size: int = launch_chunk_size,
    ) -> list[tuple[int, int, list[tuple[str, int, int]]]]:
        checked_spans: list[tuple[int, int, list[tuple[str, int, int]]]] = []
        leaf_index = 0
        for span_start, span_size in spans:
            checked_ranges: list[tuple[str, int, int]] = []
            for relative_start, count in _launch_check_ranges(
                span_size, chunk_size
            ):
                start = span_start + relative_start
                module = f"{module_prefix}{leaf_index}"
                theorem_name = f"{theorem_prefix}{leaf_index}"
                source_rows = [
                    "import StageA.RelationalLaunchContext\n\n",
                    "import StageA.RelationalStaticTree\n\n",
                    "namespace StageA.GeneratedRelational\n\n",
                    "open StageA.Formal StageA.Relational\n\n",
                    "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n",
                ]
                source_rows.extend([
                    f"theorem {theorem_name} :\n",
                    f"    IndexedBoolRangeHolds {predicate} "
                    f"{{ start := {start}, size := {count} }} := by\n",
                    "  apply indexedBoolRangeHolds_of_checked\n",
                    "  decide\n\n",
                ])
                source_rows.append("end StageA.GeneratedRelational\n")
                source = "".join(source_rows)
                _write_text_if_changed(stage_a / f"{module}.lean", source)
                launch_leaf_module_by_theorem[theorem_name] = module
                checked_ranges.append((theorem_name, start, count))
                leaf_index += 1
            checked_spans.append((span_start, span_size, checked_ranges))
        return checked_spans

    def write_launch_leaves(
        *,
        module_prefix: str,
        theorem_prefix: str,
        total: int,
        predicate: str,
        chunk_size: int = launch_chunk_size,
    ) -> list[tuple[str, int, int]]:
        return write_launch_span_leaves(
            module_prefix=module_prefix,
            theorem_prefix=theorem_prefix,
            spans=[(0, total)],
            predicate=predicate,
            chunk_size=chunk_size,
        )[0][2]

    def partition_candidate_image_span(
        span_start: int,
        span_size: int,
        *,
        structurally_immutable: bool,
    ) -> list[tuple[int, int, bool]]:
        iat_ranges = [
            (int(imported.thunk_rva), int(imported.thunk_rva) + 4)
            for imported in candidate_bin.imports
            if imported.thunk_rva is not None
        ]
        return _launch_structural_image_ranges(
            image_base=candidate_bin.image_base,
            span_start=span_start,
            span_size=span_size,
            excluded_ranges=iat_ranges,
            structurally_immutable=structurally_immutable,
        )

    def write_candidate_image_span_leaves(
    ) -> list[tuple[int, int, list[tuple[str, int, int]]]]:
        checked_spans: list[tuple[int, int, list[tuple[str, int, int]]]] = []
        leaf_index = 0
        mapped_spans = [(0, candidate_bin.size_of_headers, True)] + [
            (
                section.rva_start,
                section.rva_end - section.rva_start,
                not section.writable,
            )
            for section in candidate_bin.sections
        ]
        predicate = "consoleLaunchCandidateImageCompatibilityAt"
        for span_start, span_size, structurally_immutable in mapped_spans:
            checked_ranges: list[tuple[str, int, int]] = []
            for range_start, range_size, structural in partition_candidate_image_span(
                span_start,
                span_size,
                structurally_immutable=structurally_immutable,
            ):
                chunk_size = range_size if structural else launch_chunk_size
                for relative_start, count in _launch_check_ranges(
                    range_size, chunk_size
                ):
                    start = range_start + relative_start
                    module = (
                        f"RelationalLaunchCandidateImageMappedLeaf{leaf_index}"
                    )
                    theorem_name = (
                        f"consoleLaunchCandidateImageMappedRange{leaf_index}"
                    )
                    source_rows = [
                        "import StageA.RelationalLaunchContext\n",
                        "import StageA.RelationalStaticTree\n\n",
                        "namespace StageA.GeneratedRelational\n\n",
                        "open StageA.Formal StageA.Relational\n\n",
                        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n",
                    ]
                    if structural:
                        source_rows.extend([
                            f"theorem {theorem_name} :\n",
                            f"    IndexedBoolRangeHolds {predicate} "
                            f"{{ start := {start}, size := {count} }} := by\n",
                            "  apply "
                            "candidateProjectionImageCompatibleAt_of_immutable_span\n",
                            "    staticProofContext consoleLaunchWorld\n",
                            f"    {{ start := {start}, size := {count} }}\n",
                            "    consoleLaunchCandidateLoaderImageChecked\n",
                            "  decide\n\n",
                        ])
                    elif count > 1:
                        level: list[tuple[str, int, int]] = []
                        for offset in range(count):
                            row_name = f"{theorem_name}Byte{offset}"
                            row_start = start + offset
                            source_rows.extend([
                                f"theorem {row_name} :\n",
                                f"    IndexedBoolRangeHolds {predicate} "
                                f"{{ start := {row_start}, size := 1 }} := by\n",
                                "  apply indexedBoolRangeHolds_of_checked\n",
                                "  decide\n\n",
                            ])
                            level.append((row_name, row_start, 1))
                        merge_level = 0
                        while len(level) > 1:
                            next_level: list[tuple[str, int, int]] = []
                            for pair_index in range(0, len(level), 2):
                                left = level[pair_index]
                                if pair_index + 1 >= len(level):
                                    next_level.append(left)
                                    continue
                                right = level[pair_index + 1]
                                merge_name = (
                                    f"{theorem_name}Merge{merge_level}_"
                                    f"{pair_index // 2}"
                                )
                                source_rows.extend([
                                    f"theorem {merge_name} :\n",
                                    f"    IndexedBoolRangeHolds {predicate} "
                                    f"{{ start := {left[1]}, "
                                    f"size := {left[2] + right[2]} }} :=\n",
                                    f"  indexedBoolRangeHolds_append {predicate}\n",
                                    f"    {{ start := {left[1]}, size := {left[2]} }}\n",
                                    f"    {{ start := {right[1]}, size := {right[2]} }}\n",
                                    f"    (by decide) {left[0]} {right[0]}\n\n",
                                ])
                                next_level.append((
                                    merge_name,
                                    left[1],
                                    left[2] + right[2],
                                ))
                            level = next_level
                            merge_level += 1
                        source_rows.extend([
                            f"theorem {theorem_name} :\n",
                            f"    IndexedBoolRangeHolds {predicate} "
                            f"{{ start := {start}, size := {count} }} :=\n",
                            f"  {level[0][0]}\n\n",
                        ])
                    else:
                        source_rows.extend([
                            f"theorem {theorem_name} :\n",
                            f"    IndexedBoolRangeHolds {predicate} "
                            f"{{ start := {start}, size := 1 }} := by\n",
                            "  apply indexedBoolRangeHolds_of_checked\n",
                            "  decide\n\n",
                        ])
                    source_rows.append("end StageA.GeneratedRelational\n")
                    _write_text_if_changed(
                        stage_a / f"{module}.lean", "".join(source_rows)
                    )
                    launch_leaf_module_by_theorem[theorem_name] = module
                    checked_ranges.append((theorem_name, start, count))
                    leaf_index += 1
            checked_spans.append((span_start, span_size, checked_ranges))
        return checked_spans

    candidate_image_spans = write_candidate_image_span_leaves()
    stack_ranges = write_launch_leaves(
        module_prefix="RelationalLaunchStackMemoryLeaf",
        theorem_prefix="consoleLaunchStackMemoryRange",
        total=stack_size,
        predicate="consoleLaunchStackMemoryAt",
        chunk_size=launch_stack_chunk_size,
    )
    static_word_slot_ranges = write_launch_leaves(
        module_prefix="RelationalLaunchStaticWordSlotLeaf",
        theorem_prefix="consoleLaunchStaticWordSlotRange",
        total=len(contract.get("static_word_relation_slots", [])),
        predicate="consoleLaunchStaticWordSlotAt",
    )

    def launch_certificate(name: str, ranges: list[tuple[str, int, int]]) -> str:
        span_rows = ", ".join(
            f"{{ start := {start}, size := {count} }}"
            for _theorem, start, count in ranges
        )
        return (
            f"def {name} : IndexedBoolCertificate := "
            f"{{ ranges := [{span_rows}] }}\n\n"
        )

    def lean_span_list(
        spans: list[tuple[int, int, list[tuple[str, int, int]]]],
    ) -> str:
        return "[" + ", ".join(
            f"{{ start := {start}, size := {size} }}"
            for start, size, _chunks in spans
        ) + "]"

    def launch_range_leaf(
        theorem: str, start: int, size: int
    ) -> dict[str, Any]:
        module = launch_leaf_module_by_theorem.get(theorem)
        if module is None:
            raise StageAInputError(
                f"launch proof leaf {theorem} has no generated module"
            )
        return {
            "module": module,
            "theorem": theorem,
            "start": start,
            "size": size,
        }

    def write_contiguous_launch_aggregation(
        *,
        module_prefix: str,
        theorem_prefix: str,
        predicate: str,
        chunks: list[tuple[str, int, int]],
        expected_start: int,
        expected_size: int,
    ) -> dict[str, Any]:
        if not chunks:
            raise StageAInputError("mapped launch span cannot be empty")
        nodes = [
            launch_range_leaf(theorem, start, size)
            for theorem, start, size in chunks
        ]
        cursor = expected_start
        for node in nodes:
            if int(node["start"]) != cursor or int(node["size"]) <= 0:
                raise StageAInputError(
                    "mapped launch proof chunks are not an exact contiguous span"
                )
            cursor += int(node["size"])
        if cursor != expected_start + expected_size:
            raise StageAInputError(
                "mapped launch proof chunks do not cover the expected span"
            )

        level = 0
        while len(nodes) > 1:
            next_nodes: list[dict[str, Any]] = []
            for group_offset in range(0, len(nodes), launch_aggregation_fanout):
                group = nodes[
                    group_offset : group_offset + launch_aggregation_fanout
                ]
                if len(group) == 1:
                    next_nodes.append(group[0])
                    continue
                node_index = group_offset // launch_aggregation_fanout
                module = f"{module_prefix}Level{level}Node{node_index}"
                imports = "\n".join(
                    f"import StageA.{name}"
                    for name in dict.fromkeys([
                        "RelationalLaunchProofAggregation",
                        *(str(child["module"]) for child in group),
                    ])
                )
                definitions: list[str] = []
                current = group[0]
                for merge_index, right in enumerate(group[1:], 1):
                    start = int(current["start"])
                    size = int(current["size"])
                    right_start = int(right["start"])
                    right_size = int(right["size"])
                    if right_start != start + size or right_size <= 0:
                        raise StageAInputError(
                            "mapped launch proof chunks are not adjacent"
                        )
                    theorem = (
                        f"{theorem_prefix}Level{level}Node{node_index}"
                        f"Step{merge_index}Checked"
                    )
                    definitions.append(
                        f"theorem {theorem} :\n"
                        f"    IndexedBoolRangeHolds {predicate} "
                        f"{{ start := {start}, size := {size + right_size} }} :=\n"
                        f"  indexedBoolRangeHolds_append {predicate}\n"
                        f"    {{ start := {start}, size := {size} }}\n"
                        f"    {{ start := {right_start}, size := {right_size} }}\n"
                        f"    (by decide) {current['theorem']} {right['theorem']}"
                    )
                    current = {
                        "module": module,
                        "theorem": theorem,
                        "start": start,
                        "size": size + right_size,
                    }
                source = (
                    imports
                    + "\n\nnamespace StageA.GeneratedRelational\n\n"
                    "open StageA.Formal StageA.Relational\n\n"
                    "set_option maxRecDepth 1000000\n"
                    "set_option maxHeartbeats 0\n\n"
                    + "\n\n".join(definitions)
                    + "\n\nend StageA.GeneratedRelational\n"
                )
                _write_text_if_changed(stage_a / f"{module}.lean", source)
                next_nodes.append(current)
            nodes = next_nodes
            level += 1
        return nodes[0]

    def write_launch_range_list_aggregation(
        *,
        module_prefix: str,
        theorem_prefix: str,
        predicate: str,
        nodes: list[dict[str, Any]],
    ) -> dict[str, str]:
        if not nodes:
            return {
                "module": "RelationalLaunchProofAggregation",
                "ranges": "[]",
                "proof": "True.intro",
            }
        level = 0
        while len(nodes) > 1:
            next_nodes: list[dict[str, Any]] = []
            for group_offset in range(0, len(nodes), launch_aggregation_fanout):
                group = nodes[
                    group_offset : group_offset + launch_aggregation_fanout
                ]
                if len(group) == 1:
                    next_nodes.append(group[0])
                    continue
                node_index = group_offset // launch_aggregation_fanout
                module = f"{module_prefix}Level{level}Node{node_index}"
                imports = "\n".join(
                    f"import StageA.{name}"
                    for name in dict.fromkeys([
                        "RelationalLaunchProofAggregation",
                        *(str(child["module"]) for child in group),
                    ])
                )
                definitions: list[str] = []
                current = group[0]
                for merge_index, right in enumerate(group[1:], 1):
                    name = (
                        f"{theorem_prefix}Level{level}Node{node_index}"
                        f"Step{merge_index}"
                    )
                    ranges = f"{name}Ranges"
                    proof = f"{name}Checked"
                    definitions.extend([
                        f"def {ranges} : List Span :=\n"
                        f"  {current['ranges']} ++ {right['ranges']}",
                        f"theorem {proof} :\n"
                        f"    AllIndexedBoolRangesHold {predicate} {ranges} := by\n"
                        f"  exact launchAllIndexedBoolRangesHold_append {predicate}\n"
                        f"    {current['ranges']} {right['ranges']}\n"
                        f"    ({current['proof']}) ({right['proof']})",
                    ])
                    current = {
                        "module": module,
                        "ranges": ranges,
                        "proof": proof,
                    }
                source = (
                    imports
                    + "\n\nnamespace StageA.GeneratedRelational\n\n"
                    "open StageA.Formal StageA.Relational\n\n"
                    "set_option maxRecDepth 1000000\n"
                    "set_option maxHeartbeats 0\n\n"
                    + "\n\n".join(definitions)
                    + "\n\nend StageA.GeneratedRelational\n"
                )
                _write_text_if_changed(stage_a / f"{module}.lean", source)
                next_nodes.append(current)
            nodes = next_nodes
            level += 1
        root = nodes[0]
        return {
            "module": str(root["module"]),
            "ranges": str(root["ranges"]),
            "proof": str(root["proof"]),
        }

    candidate_span_nodes: list[dict[str, Any]] = []
    for span_index, (span_start, span_size, chunks) in enumerate(
        candidate_image_spans
    ):
        span_root = write_contiguous_launch_aggregation(
            module_prefix=(
                f"RelationalLaunchCandidateImageSpan{span_index}Aggregate"
            ),
            theorem_prefix=(
                f"consoleLaunchCandidateImageSpan{span_index}Aggregate"
            ),
            predicate="consoleLaunchCandidateImageCompatibilityAt",
            chunks=chunks,
            expected_start=span_start,
            expected_size=span_size,
        )
        candidate_span_nodes.append({
            "module": span_root["module"],
            "ranges": f"[{{ start := {span_start}, size := {span_size} }}]",
            "proof": f"⟨{span_root['theorem']}, True.intro⟩",
        })
    candidate_image_range_root = write_launch_range_list_aggregation(
        module_prefix="RelationalLaunchCandidateImageAggregate",
        theorem_prefix="consoleLaunchCandidateImageAggregate",
        predicate="consoleLaunchCandidateImageCompatibilityAt",
        nodes=candidate_span_nodes,
    )
    stack_range_root = write_launch_range_list_aggregation(
        module_prefix="RelationalLaunchStackMemoryAggregate",
        theorem_prefix="consoleLaunchStackMemoryAggregate",
        predicate="consoleLaunchStackMemoryAt",
        nodes=[{
            "module": launch_range_leaf(theorem, start, size)["module"],
            "ranges": f"[{{ start := {start}, size := {size} }}]",
            "proof": f"⟨{theorem}, True.intro⟩",
        } for theorem, start, size in stack_ranges],
    )
    static_word_slot_range_root = write_launch_range_list_aggregation(
        module_prefix="RelationalLaunchStaticWordSlotAggregate",
        theorem_prefix="consoleLaunchStaticWordSlotAggregate",
        predicate="consoleLaunchStaticWordSlotAt",
        nodes=[{
            "module": launch_range_leaf(theorem, start, size)["module"],
            "ranges": f"[{{ start := {start}, size := {size} }}]",
            "proof": f"⟨{theorem}, True.intro⟩",
        } for theorem, start, size in static_word_slot_ranges],
    )
    launch_check_imports = "\n".join(
        f"import StageA.{module}"
        for module in dict.fromkeys([
            str(candidate_image_range_root["module"]),
            str(stack_range_root["module"]),
            str(static_word_slot_range_root["module"]),
        ])
    )

    launch_checks_source = (
        launch_check_imports
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + launch_certificate("consoleLaunchStackCertificate", stack_ranges)
        + launch_certificate(
            "consoleLaunchStaticWordSlotCertificate", static_word_slot_ranges
        )
        + "theorem consoleLaunchOriginalImageMapped :\n"
        "    PreferredBaseImageMemory staticProofContext.originalPe\n"
        "      staticProofContext.originalImports consoleLaunchOriginalState.memory := by\n"
        "  have loaderMapped := loaderPopulatedPreferredBaseMemory_maps_image\n"
        "    false staticProofContext consoleLaunchWorld (by decide)\n"
        "    (by decide) (by decide)\n"
        "  have stackMapped := preferredBaseImageMemory_after_stack_range_writes\n"
        "    staticProofContext.originalPe staticProofContext.originalImports\n"
        "    (loaderPopulatedPreferredBaseMemory false staticProofContext\n"
        "      consoleLaunchWorld) consoleLaunchStackRange.originalBase\n"
        "    consoleLaunchStackRange.size consoleLaunchOriginalStackWrites\n"
        "    (by decide) (by decide) (by decide) (by decide) loaderMapped\n"
        "  simpa [consoleLaunchOriginalState, consoleLaunchOriginalMemory,\n"
        "    consoleLaunchOriginalWrites] using stackMapped\n\n"
        "theorem consoleLaunchCandidateExcludedImageMapped :\n"
        "    PreferredBaseImageMemory staticProofContext.candidatePe\n"
        "      staticProofContext.candidateImports\n"
        "      consoleLaunchCandidateExcludedMemory := by\n"
        "  have loaderMapped := loaderPopulatedPreferredBaseMemory_maps_image\n"
        "    true staticProofContext consoleLaunchWorld (by decide)\n"
        "    (by decide) (by decide)\n"
        "  have stackMapped := preferredBaseImageMemory_after_stack_range_writes\n"
        "    staticProofContext.candidatePe staticProofContext.candidateImports\n"
        "    (loaderPopulatedPreferredBaseMemory true staticProofContext\n"
        "      consoleLaunchWorld) consoleLaunchStackRange.candidateBase\n"
        "    consoleLaunchStackRange.size consoleLaunchCandidateStackWrites\n"
        "    (by decide) (by decide) (by decide) (by decide) loaderMapped\n"
        "  simpa [consoleLaunchCandidateExcludedMemory, consoleLaunchCandidateWrites]\n"
        "    using stackMapped\n\n"
        "theorem consoleLaunchCandidateImageMapped :\n"
        "    PreferredBaseImageMemory staticProofContext.candidatePe\n"
        "      staticProofContext.candidateImports consoleLaunchCandidateState.memory := by\n"
        "  change PreferredBaseImageMemory staticProofContext.candidatePe\n"
        "    staticProofContext.candidateImports\n"
        "    (ordinaryMemoryCandidateProjection staticProofContext consoleLaunchWorld\n"
        "      (staticProofContext.relationalValueTargets consoleLaunchWorld)\n"
        "      consoleLaunchOriginalMemory consoleLaunchCandidateExcludedMemory)\n"
        "  apply preferredBaseImageMemory_projection_of_compatible_ranges\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · decide\n"
        "  · exact consoleLaunchOriginalImageMapped\n"
        "  · exact consoleLaunchCandidateExcludedImageMapped\n"
        "  have rangesHold : AllIndexedBoolRangesHold\n"
        "      consoleLaunchCandidateImageCompatibilityAt\n"
        "      (mappedImageSpans staticProofContext.candidatePe) := by\n"
        "    change AllIndexedBoolRangesHold "
        "consoleLaunchCandidateImageCompatibilityAt "
        + lean_span_list(candidate_image_spans) + "\n"
        f"    exact {candidate_image_range_root['proof']}\n"
        "  simpa [consoleLaunchCandidateImageCompatibilityAt] using rangesHold\n\n"
        "theorem consoleLaunchOriginalImmutableImage :\n"
        "    ImmutableImageWordMemory staticProofContext.originalPe\n"
        "      consoleLaunchOriginalState.memory := by\n"
        "  exact preferredBaseImageMemory_implies_immutable\n"
        "    staticProofContext.originalPe staticProofContext.originalImports\n"
        "    consoleLaunchOriginalState.memory (by decide)\n"
        "    consoleLaunchOriginalImageMapped (by decide)\n\n"
        "theorem consoleLaunchCandidateImmutableImage :\n"
        "    ImmutableImageWordMemory staticProofContext.candidatePe\n"
        "      consoleLaunchCandidateState.memory := by\n"
        "  exact preferredBaseImageMemory_implies_immutable\n"
        "    staticProofContext.candidatePe staticProofContext.candidateImports\n"
        "    consoleLaunchCandidateState.memory (by decide)\n"
        "    consoleLaunchCandidateImageMapped (by decide)\n\n"
        "theorem consoleLaunchStackMemoryRelated :\n"
        "    StackRangesMemoryHold staticProofContext consoleLaunchWorld\n"
        "      consoleLaunchOriginalState.memory consoleLaunchCandidateState.memory := by\n"
        "  apply stackRangesMemoryHold_of_single_range_indexed_holds staticProofContext\n"
        "    consoleLaunchWorld consoleLaunchOriginalState.memory\n"
        "    consoleLaunchCandidateState.memory consoleLaunchStackRange\n"
        "  · rfl\n"
        "  · have rangesHold : AllIndexedBoolRangesHold consoleLaunchStackMemoryAt\n"
        "        consoleLaunchStackCertificate.ranges := by\n"
        f"      exact {stack_range_root['proof']}\n"
        "    have checked := IndexedBoolCertificate.holds_of_ranges\n"
        "      consoleLaunchStackMemoryAt consoleLaunchStackRange.size\n"
        "      consoleLaunchStackCertificate (by decide) rangesHold\n"
        "    simpa [consoleLaunchStackMemoryAt] using checked\n\n"
        "theorem consoleLaunchStaticWordSlotsRelated :\n"
        "    StaticWordRelationSlotsMemoryHold staticProofContext consoleLaunchWorld\n"
        "      consoleLaunchOriginalState.memory consoleLaunchCandidateState.memory := by\n"
        "  apply staticWordRelationSlotsMemoryHold_of_indexed_holds\n"
        "    staticProofContext consoleLaunchWorld consoleLaunchOriginalState.memory\n"
        "    consoleLaunchCandidateState.memory consoleLaunchStaticWordSlotCertificate\n"
        "  have rangesHold : AllIndexedBoolRangesHold consoleLaunchStaticWordSlotAt\n"
        "      consoleLaunchStaticWordSlotCertificate.ranges := by\n"
        f"    exact {static_word_slot_range_root['proof']}\n"
        "  have checked := IndexedBoolCertificate.holds_of_ranges\n"
        "    consoleLaunchStaticWordSlotAt staticProofContext.staticWordRelationSlots.length\n"
        "    consoleLaunchStaticWordSlotCertificate (by decide) rangesHold\n"
        "  simpa [consoleLaunchStaticWordSlotAt] using checked\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchCheckCertificate.lean", launch_checks_source
    )

    linked_launch_realizability_source = ""
    if linked_acceptance_ready:
        linked_launch_realizability_source = (
            "theorem consoleLaunchLinkedRealizable :\n"
            "    consoleLaunch.LinkedRealizable staticProofContext relationalProductGraph\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile := by\n"
            "  refine ⟨consoleLaunchWorld, consoleLaunchOriginalState,\n"
            "    consoleLaunchCandidateState, consoleLaunchFrames, [],\n"
            "    consoleLaunchWorldValid, consoleLaunchOriginalImageMapped,\n"
            "    consoleLaunchCandidateImageMapped, ?_, ?_, ?_, ?_, ?_,\n"
            "    consoleLaunchStateRelated⟩\n"
            "  · simp [consoleLaunch, consoleLaunchFrames,\n"
            "    consoleLaunchOriginalState, consoleLaunchCandidateState,\n"
            "    consoleLaunchOriginalMemory, consoleLaunchCandidateMemory,\n"
            "    consoleLaunchCandidateExcludedMemory, consoleLaunchOriginalWrites,\n"
            "    consoleLaunchCandidateWrites, RelationalLinkedRuntimeCallStackHolds,\n"
            "    PE32ConsoleLaunchV2.continuationTargetIds] <;> decide\n"
            "  · exact LinkedProductControlProfile.LinksAllowed.nil\n"
            "      linkedProductControlProfile linkedProductControlProfileChecked\n"
            "  · simp [consoleLaunch, RelationalLinkedRuntimeCallFactsHold]\n"
            "  · exact RelationalRuntimeCallTargetsMapped.of_checked\n"
            "      relationalProductGraph relationalProductReachabilityEvidence\n"
            "      [] consoleLaunch.continuationTargetIds (by decide)\n"
            "  · simp [consoleLaunch, consoleLaunchFrames,\n"
            "    consoleLaunchOriginalState, consoleLaunchCandidateState,\n"
            "    consoleLaunchOriginalMemory, consoleLaunchCandidateMemory,\n"
            "    consoleLaunchCandidateExcludedMemory, consoleLaunchOriginalWrites,\n"
            "    consoleLaunchCandidateWrites, PE32TlsProcessAttachArgumentsHold] <;> decide\n\n"
        )
    launch_realizability_source = (
        "import StageA.RelationalLaunchCheckCertificate\n"
        "import StageA.RelationalProductGraphContext\n"
        "import StageA.RelationalLinkedExecution\n"
        "import StageA.RelationalLinkedControlProfile\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        "theorem consoleLaunchStateRelated :\n"
        "    StateRel staticProofContext consoleLaunchWorld consoleLaunch.rootInvariant\n"
        "      consoleLaunchOriginalState consoleLaunchCandidateState := by\n"
        "  refine ⟨consoleLaunchWorldValid.1, by decide, ?_, by decide, by decide,\n"
        "    ?_, ?_, ?_, ?_, ?_⟩\n"
        "  · exact consoleLaunchStackMemoryRelated\n"
        "  · apply importAddressesMemoryHold_of_checked\n"
        "    decide\n"
        "  · exact consoleLaunchOriginalImmutableImage\n"
        "  · exact consoleLaunchCandidateImmutableImage\n"
        "  · refine ⟨by decide, by decide, by decide, by decide, ?_, ?_, rfl, ?_,\n"
        "      by decide, rfl⟩\n"
        "    · exact ordinaryMemoryRelated_projection_of_mapped_identity\n"
        "        staticProofContext consoleLaunchWorld\n"
        "        staticProofContext.codeMap.entries.toList\n"
        "        (staticProofContext.relationalValueTargets consoleLaunchWorld)\n"
        "        consoleLaunchOriginalMemory consoleLaunchCandidateExcludedMemory\n"
        "        (by decide)\n"
        "    · refine { staticPointerSlots := ?_, staticWordSlots := ?_, active := ?_ }\n"
        "      · intro slot member\n"
        "        simp [staticProofContext] at member\n"
        "      · exact consoleLaunchStaticWordSlotsRelated\n"
        "      · exact { registerRanges := by decide, stackRanges := by decide }\n"
        "    · simp [MachineX87Related, consoleLaunchOriginalState,\n"
        "        consoleLaunchCandidateState, StageA.Relational.X87.StateRelated,\n"
        "        StageA.Relational.X87.MetadataRelated, StageA.X87.PhysicalState.core,\n"
        "        StageA.X87.PhysicalState.metadata, x87AddressRelation]\n"
        "  · decide\n\n"
        "theorem consoleLaunchRealizable :\n"
        "    consoleLaunch.Realizable staticProofContext relationalProductGraph\n"
        "      relationalProductReachabilityEvidence := by\n"
        "  refine ⟨consoleLaunchWorld, consoleLaunchOriginalState,\n"
        "    consoleLaunchCandidateState, consoleLaunchFrames,\n"
        "    consoleLaunchWorldValid, consoleLaunchOriginalImageMapped,\n"
        "    consoleLaunchCandidateImageMapped, ?_, ?_, ?_, ?_,\n"
        "    consoleLaunchStateRelated⟩\n"
        "  · simp [consoleLaunch, consoleLaunchFrames,\n"
        "    consoleLaunchOriginalState, consoleLaunchCandidateState,\n"
        "    consoleLaunchOriginalMemory, consoleLaunchCandidateMemory,\n"
        "    consoleLaunchCandidateExcludedMemory, consoleLaunchOriginalWrites,\n"
        "    consoleLaunchCandidateWrites, RelationalRuntimeCallStackHolds,\n"
        "    RelationalRuntimeCallFrame.memoryHolds,\n"
        "    ReturnSlotOffsetInventory.holds,\n"
        "    ReturnSlotOffsetInventory.boundedExactWordsHold,\n"
        "    ReturnSlotOffsetInventory.exactWordsHold,\n"
        "    ReturnSlotExactWordPair.holds, ReturnSlotOffsetPair.holds,\n"
        "    PE32ConsoleLaunchV2.continuationTargetIds] <;> decide\n"
        "  · simp [consoleLaunch, consoleLaunchOriginalState,\n"
        "    consoleLaunchCandidateState,\n"
        "    RelationalRuntimeCallFactsHold, RelationalRuntimeCallImportsHold,\n"
        "    RelationalRuntimeCallRelationsHold] <;> decide\n"
        "  · exact RelationalRuntimeCallTargetsMapped.of_checked\n"
        "      relationalProductGraph relationalProductReachabilityEvidence\n"
        "      ["
        + ", ".join(str(node_id) for node_id in launch_continuation_node_ids)
        + "] consoleLaunch.continuationTargetIds (by decide)\n"
        "  · simp [consoleLaunch, consoleLaunchFrames,\n"
        "    consoleLaunchOriginalState, consoleLaunchCandidateState,\n"
        "    consoleLaunchOriginalMemory, consoleLaunchCandidateMemory,\n"
        "    consoleLaunchCandidateExcludedMemory, consoleLaunchOriginalWrites,\n"
        "    consoleLaunchCandidateWrites,\n"
        "    PE32TlsProcessAttachArgumentsHold] <;> decide\n\n"
        + linked_launch_realizability_source
        + "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        stage_a / "RelationalLaunchRealizabilityCertificate.lean",
        launch_realizability_source,
    )

    if not acceptance_ready:
        return plan

    chunk_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_ACCEPTANCE_CHUNK", "1"))
    )
    region_chunks: list[dict[str, str]] = []
    for chunk_index, offset in enumerate(range(0, len(nodes), chunk_size)):
        selected_node_ids = list(range(offset, min(offset + chunk_size, len(nodes))))
        module = f"RelationalAcceptanceRegionChunk{chunk_index}"
        ids_name = f"acceptanceRegionNodeChunk{chunk_index}Ids"
        definitions: list[str] = []
        region_theorems: list[str] = []
        for node_id in selected_node_ids:
            node = nodes[node_id]
            target_id = int(node["target_id"])
            region_index = int(contract["regions"][node_id]["numeric_id"])
            region_match = f"acceptanceRegionNode{node_id}Matches"
            region_theorems.append(region_match)
            definitions.append(
                f"theorem {region_match} :\n"
                "    RegionMatchesProductNode staticProofContext relationalProductGraph "
                f"allRegions {node_id} := by\n"
                "  unfold RegionMatchesProductNode\n"
                f"  rw [(show relationalProductGraph.getNode? {node_id} =\n"
                f"    some relationalProductGraph.nodes[{node_id}] by decide)]\n"
                "  simp only\n"
                f"  have nodeTarget : relationalProductGraph.nodes[{node_id}].targetId = "
                f"{target_id} := by decide\n"
                "  have codeFound : staticProofContext.codeMap.get? "
                f"{target_id} = some staticProofContext.codeMap.entries[{target_id}] := by decide\n"
                f"  have regionFound : regionById allRegions {target_id} = "
                f"some region{region_index} := by decide\n"
                "  rw [nodeTarget, codeFound, regionFound]\n"
                "  exact ⟨by decide, by decide, by decide, by decide⟩"
            )
        definitions.extend([
            f"def {ids_name} : List Nat := "
            f"[{', '.join(map(str, selected_node_ids))}]",
            (
                f"theorem acceptanceRegionChunk{chunk_index}Checked :\n"
                "    AllListedRegionsMatchProductGraph staticProofContext\n"
                f"      relationalProductGraph allRegions {ids_name} := by\n"
                f"  exact {_lean_all_listed_proof(region_theorems)}"
            ),
        ])
        source = (
            "import StageA.RelationalAcceptanceContext\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(stage_a / f"{module}.lean", source)
        region_chunks.append({
            "module": module,
            "ids": ids_name,
            "regions": f"acceptanceRegionChunk{chunk_index}Checked",
        })

    chunks: list[dict[str, str]] = []
    steps = plan["node_steps"]
    for chunk_index, offset in enumerate(range(0, len(steps), chunk_size)):
        selected = steps[offset : offset + chunk_size]
        module = f"RelationalAcceptanceChunk{chunk_index}"
        ids_name = f"acceptanceNodeChunk{chunk_index}Ids"
        edge_ids_name = f"acceptanceEdgeChunk{chunk_index}Ids"
        definitions: list[str] = []
        running_theorems: list[str] = []
        linked_running_theorems: list[str] = []
        edge_theorems: list[str] = []
        for step in selected:
            node_id = int(step["node_id"])
            region_index = int(step["region_index"])
            target_id = int(step["target_id"])
            uses_deferred_guard = _step_uses_deferred_guard(step)
            running = f"acceptanceRunningNode{node_id}Refined"
            if not uses_deferred_guard:
                running_environment = (
                    "environmentRefines"
                    if (
                        step.get("kind") == "external_call"
                        or bool(step.get("opaque_lockstep_profile"))
                    )
                    else "environmentRefines.externalRefines"
                )
                running_theorems.append(
                    f"{running} originalEnvironment candidateEnvironment "
                    + (
                        "originalProtocolEnvironment candidateProtocolEnvironment "
                        if parameterized_protocol_environment else ""
                    )
                    + running_environment
                    if parameterized_environment else running
                )
            for side in ("original", "candidate"):
                side_title = side.capitalize()
                side_bool = "false" if side == "original" else "true"
                normalized_name = (
                    f"acceptance{side_title}NormalizedBehavior{node_id}"
                )
                normalized_outcome = (
                    f"acceptance{side_title}NormalizedOutcome{node_id}"
                )
                normalized_writes = (
                    f"acceptance{side_title}NormalizedWrites{node_id}"
                )
                normalized_registers = (
                    f"acceptance{side_title}NormalizedRegisters{node_id}"
                )
                normalized_checked = (
                    f"acceptance{side_title}Normalization{node_id}Checked"
                )
                environment_name = f"{side}Environment"
                protocol_environment_name = f"{side}ProtocolEnvironment"
                world_program = (
                    f"({side}WorldProgram {environment_name}"
                    + (
                        f" {protocol_environment_name}"
                        if parameterized_protocol_environment else ""
                    )
                    + ")"
                    if parameterized_environment else f"{side}WorldProgram"
                )
                world_behavior_binder = (
                    f" ({environment_name} : WorldExternalEnvironment)"
                    + (
                        f" ({protocol_environment_name} : "
                        "WorldExternalProtocolEnvironment)"
                        if parameterized_protocol_environment else ""
                    )
                    if parameterized_environment else ""
                )
                if step.get("certificate_profile") == (
                    "composable_x87_state_only_singleton_v1"
                ):
                    definitions.append(
                        f"theorem {side}WorldBehaviorNode{node_id}"
                        f"{world_behavior_binder} (state : MachineState) "
                        "(calls : List Nat) :\n"
                        f"    decodedWorldRegionBehaviorWithCalls {world_program} "
                        f"{target_id} state calls =\n"
                        "      StageA.Relational.X87.executeSingletonCommand "
                        f"{side_bool} staticProofContext.{side}Pe "
                        f"segmentRefinementEdge{int(step['edges'][0]['edge_id'])}Spec.{side}Span "
                        f"region{region_index}.targets state := by\n"
                        f"  have regionFound : regionById allRegions {target_id} = "
                        f"some region{region_index} := by decide\n"
                        "  unfold decodedWorldRegionBehaviorWithCalls "
                        f"{side}WorldProgram\n"
                        "  rw [regionFound]\n"
                        "  simp only [Bool.false_eq_true, if_false, if_true]\n"
                        "  rfl"
                    )
                    continue
                if _has_compositional_normalized_support(
                    contract["regions"][region_index], behaviors[region_index]
                ):
                    definitions.append(
                        f"abbrev {normalized_name} : NormalizedSymbolicBehavior :=\n"
                        f"  region{region_index}NormalizedBehavior\n\n"
                        f"theorem {normalized_checked} : normalizeSymbolicBehavior {side_bool}\n"
                        f"    region{region_index}.targets {side}Behavior{region_index} =\n"
                        f"      some {normalized_name} := by\n"
                        f"  simpa only [{normalized_name}] using "
                        f"region{region_index}{side_title}Normalized\n\n"
                        f"theorem {normalized_writes} : {normalized_name}.writes =\n"
                        f"    {side}Behavior{region_index}.writes := by\n"
                        f"  simpa only [{normalized_name}] using "
                        f"region{region_index}{side_title}NormalizedWrites\n\n"
                        f"theorem {normalized_registers} : {normalized_name}.registers =\n"
                        f"    {side}Behavior{region_index}.registers := by\n"
                        f"  simpa only [{normalized_name}] using "
                        f"region{region_index}{side_title}NormalizedRegisters\n\n"
                        f"theorem {normalized_outcome} : {normalized_name}.outcome =\n"
                        f"    {_lean_acceptance_outcome(behaviors[region_index][side + '_ir']['outcome'])} "
                        ":= by\n"
                        f"  simpa only [{normalized_name}] using "
                        f"region{region_index}NormalizedOutcome"
                    )
                else:
                    definitions.append(
                        f"def {normalized_name} : NormalizedSymbolicBehavior :=\n"
                        f"  (normalizeSymbolicBehavior {side_bool} region{region_index}.targets "
                        f"{side}Behavior{region_index}).get (by decide)\n\n"
                        f"theorem {normalized_checked} : normalizeSymbolicBehavior {side_bool}\n"
                        f"    region{region_index}.targets {side}Behavior{region_index} =\n"
                        f"      some {normalized_name} := by decide\n\n"
                        f"theorem {normalized_writes} : {normalized_name}.writes =\n"
                        f"    {side}Behavior{region_index}.writes := by decide\n\n"
                        f"theorem {normalized_registers} : {normalized_name}.registers =\n"
                        f"    {side}Behavior{region_index}.registers := by decide\n\n"
                        f"theorem {normalized_outcome} : {normalized_name}.outcome =\n"
                        f"    {_lean_acceptance_outcome(behaviors[region_index][side + '_ir']['outcome'])} "
                        ":= by decide"
                    )
                definitions.append(
                    f"theorem {side}WorldBehaviorNode{node_id}{world_behavior_binder} "
                    "(state : MachineState) (calls : List Nat) :\n"
                    f"    decodedWorldRegionBehaviorWithCalls {world_program} "
                    f"{target_id} state calls =\n"
                    f"      some ({normalized_name}.eval state) := by\n"
                    f"  have regionFound : regionById allRegions {target_id} = "
                    f"some region{region_index} := by decide\n"
                    "  unfold decodedWorldRegionBehaviorWithCalls "
                    f"{side}WorldProgram\n"
                    "  rw [regionFound]\n"
                    f"  change (regionBehaviorWithMachineCallContracts {side}Pe "
                    f"{side}Imports machineImportCallContracts region{region_index}.{side}).bind\n"
                    f"      (evalBehavior {side_bool} region{region_index}.targets state) = _\n"
                    f"  have decoded : regionBehaviorWithMachineCallContracts {side}Pe "
                    f"{side}Imports machineImportCallContracts region{region_index}.{side} =\n"
                    f"      some {side}Behavior{region_index} := by\n"
                    f"    exact {side}Behavior{region_index}CheckedDecoded\n"
                    "  rw [decoded]\n"
                    f"  change evalBehavior {side_bool} region{region_index}.targets state "
                    f"{side}Behavior{region_index} = some ({normalized_name}.eval state)\n"
                    f"  exact evalBehavior_of_normalized {side_bool} "
                    f"region{region_index}.targets state {side}Behavior{region_index} "
                    f"{normalized_name} {normalized_checked}"
                )
            native_case = linked_native_cases_by_node.get(node_id)
            linked_termination_reuses_ordinary_node = bool(
                linked_acceptance_ready
                and linked_acceptance_mode == "native-linked-call-return-v1"
                and native_case is not None
                and native_case[0] == "empty_terminate"
            )
            if (
                ordinary_acceptance_ready or linked_termination_reuses_ordinary_node
            ) and not uses_deferred_guard:
                definitions.append(
                    _lean_acceptance_running_node_with_protocol_x87_bridge(
                    step, contract["regions"], behaviors,
                    parameterized_environment=parameterized_environment,
                    parameterized_protocol_environment=
                        parameterized_protocol_environment,
                    )
                )
            if linked_acceptance_ready:
                linked_running = f"acceptanceLinkedRunningNode{node_id}Refined"
                linked_environment = (
                    "environmentRefines"
                    if (
                        linked_acceptance_mode in {
                            "lean-checked-shallow-profile-compatibility-v1",
                            "lean-checked-shallow-with-native-frame-guards-v1",
                        }
                        and (
                            step.get("kind") == "external_call"
                            or bool(step.get("opaque_lockstep_profile"))
                        )
                    )
                    else "environmentRefines.externalRefines"
                )
                linked_running_theorems.append(
                    f"{linked_running} originalEnvironment candidateEnvironment "
                    + (
                        "originalProtocolEnvironment candidateProtocolEnvironment "
                        if parameterized_protocol_environment else ""
                    )
                    + linked_environment
                    if parameterized_environment else linked_running
                )
                if linked_acceptance_mode == "native-linked-call-return-v1":
                    if native_case is None:
                        raise StageAInputError(
                            f"linked native node {node_id} lost its proof family"
                        )
                    family, payload = native_case
                    if family == "direct_call":
                        assert payload is not None
                        definitions.append(_lean_acceptance_linked_direct_call_node(
                            step, payload
                        ))
                    elif family == "return":
                        assert payload is not None
                        definitions.append(_lean_acceptance_linked_return_node(
                            step, payload
                        ))
                    elif family == "active_jump":
                        assert payload is not None
                        definitions.append(_lean_acceptance_linked_active_jump_node(
                            step, payload
                        ))
                    elif family == "active_branch":
                        assert payload is not None
                        definitions.append(
                            _lean_acceptance_linked_active_branch_node(
                                step, payload, contract["regions"], behaviors
                            )
                        )
                    elif family == "empty_jump":
                        definitions.append(_lean_acceptance_linked_empty_jump_node(
                            step,
                            parameterized_environment=parameterized_environment,
                            parameterized_protocol_environment=
                                parameterized_protocol_environment,
                        ))
                    elif family == "empty_terminate":
                        definitions.append(
                            _lean_acceptance_linked_empty_terminate_node(step)
                        )
                    else:
                        raise StageAInputError(
                            f"unknown linked native node family {family!r}"
                        )
                elif linked_acceptance_mode == (
                    "lean-checked-shallow-profile-compatibility-v1"
                ):
                    definitions.append(_lean_acceptance_linked_shallow_node(
                        step,
                        parameterized_environment=parameterized_environment,
                        parameterized_protocol_environment=
                            parameterized_protocol_environment,
                    ))
                elif linked_acceptance_mode == (
                    "lean-checked-shallow-with-native-frame-guards-v1"
                ):
                    if native_case is not None and native_case[0] == "active_branch":
                        assert native_case[1] is not None
                        definitions.append(_lean_acceptance_linked_active_branch_node(
                            step, native_case[1], contract["regions"], behaviors,
                            parameterized_environment=parameterized_environment,
                            parameterized_protocol_environment=
                                parameterized_protocol_environment,
                        ))
                    else:
                        definitions.append(_lean_acceptance_linked_shallow_node(
                            step,
                            parameterized_environment=parameterized_environment,
                            parameterized_protocol_environment=
                                parameterized_protocol_environment,
                        ))
                elif native_case is not None and native_case[0] == "active_jump":
                    assert native_case[1] is not None
                    definitions.append(_lean_acceptance_linked_active_jump_node(
                        step, native_case[1]
                    ))
                elif native_case is not None and native_case[0] == "active_branch":
                    assert native_case[1] is not None
                    definitions.append(_lean_acceptance_linked_active_branch_node(
                        step, native_case[1], contract["regions"], behaviors,
                        parameterized_environment=parameterized_environment,
                        parameterized_protocol_environment=
                            parameterized_protocol_environment,
                    ))
                elif _linked_empty_jump_supported(step):
                    definitions.append(_lean_acceptance_linked_empty_jump_node(
                        step,
                        parameterized_environment=parameterized_environment,
                        parameterized_protocol_environment=
                            parameterized_protocol_environment,
                    ))
                else:
                    definitions.append(_lean_acceptance_linked_shallow_node(
                        step,
                        parameterized_environment=parameterized_environment,
                        parameterized_protocol_environment=
                            parameterized_protocol_environment,
                    ))
            if "callback_profile_index" in step:
                definitions.append(_lean_acceptance_callback_return_node(
                    step,
                    parameterized_environment=parameterized_environment,
                    parameterized_protocol_environment=parameterized_protocol_environment,
                ))
            if ordinary_acceptance_ready and not uses_deferred_guard:
                definitions.extend(
                    _lean_acceptance_execution_edge(step=step, edge=edge)
                    for edge in step["edges"]
                    if edge.get("infeasible") is not True
                )
        node_ids = [int(step["node_id"]) for step in selected]
        edge_ids = [
            int(edge["edge_id"])
            for step in selected
            for edge in step["edges"]
            if edge.get("infeasible") is not True
        ]
        edge_ids.sort()
        ordinary_edge_ids = [
            int(edge["edge_id"])
            for step in selected
            if not _step_uses_deferred_guard(step)
            for edge in step["edges"]
            if edge.get("infeasible") is not True
        ]
        ordinary_edge_ids.sort()
        edge_theorems = [
            f"acceptanceExecutionEdge{edge_id}Refined"
            for edge_id in ordinary_edge_ids
        ]
        definitions.extend([
            f"def {ids_name} : List Nat := [{', '.join(map(str, node_ids))}]",
            f"def {edge_ids_name} : List Nat := [{', '.join(map(str, edge_ids))}]",
        ])
        if ordinary_acceptance_ready:
            definitions.extend([
                (
                f"theorem acceptanceRunningChunk{chunk_index}Checked"
                + (
                    " (originalEnvironment candidateEnvironment : "
                    "WorldExternalEnvironment)\n"
                    + (
                        "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                        "WorldExternalProtocolEnvironment)\n"
                        if parameterized_protocol_environment else ""
                    )
                    + "    (environmentRefines : "
                    "AcceptanceExternalEnvironmentsRefine\n"
                    "      originalEnvironment candidateEnvironment)"
                    if parameterized_environment else ""
                )
                + " :\n"
                "    AllListedRunningProductNodesRefined staticProofContext\n"
                "      relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence productControlProfile\n"
                "      protocolCallbackTargets\n"
                + (
                    "      (originalWorldProgram originalEnvironment"
                    + (
                        " originalProtocolEnvironment"
                        if parameterized_protocol_environment else ""
                    )
                    + ")\n"
                    + "      (candidateWorldProgram candidateEnvironment"
                    + (
                        " candidateProtocolEnvironment"
                        if parameterized_protocol_environment else ""
                    )
                    + ") "
                    if parameterized_environment else
                    "      originalWorldProgram\n"
                    "      candidateWorldProgram "
                )
                + f"{ids_name} := by\n"
                f"  exact {_lean_all_listed_proof(running_theorems)}"
                ),
                (
                f"theorem acceptanceExecutionEdgeChunk{chunk_index}Checked :\n"
                "    AllListedProductExecutionEdgesRefined staticProofContext\n"
                "      relationalProductGraph allRegions productInvariantTable\n"
                f"      {edge_ids_name} := by\n"
                f"  exact {_lean_all_listed_proof(edge_theorems)}"
                ),
            ])
        if linked_acceptance_ready:
            definitions.append(
                f"theorem acceptanceLinkedRunningChunk{chunk_index}Checked"
                + (
                    " (originalEnvironment candidateEnvironment : "
                    "WorldExternalEnvironment)\n"
                    + (
                        "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                        "WorldExternalProtocolEnvironment)\n"
                        if parameterized_protocol_environment else ""
                    )
                    + "    (environmentRefines : "
                    "AcceptanceExternalEnvironmentsRefine\n"
                    "      originalEnvironment candidateEnvironment)"
                    if parameterized_environment else ""
                )
                + " :\n"
                "    AllListedLinkedRunningProductNodesRefined staticProofContext\n"
                "      relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
                "      protocolCallbackTargets\n"
                + (
                    "      (originalWorldProgram originalEnvironment"
                    + (
                        " originalProtocolEnvironment"
                        if parameterized_protocol_environment else ""
                    )
                    + ")\n"
                    + "      (candidateWorldProgram candidateEnvironment"
                    + (
                        " candidateProtocolEnvironment"
                        if parameterized_protocol_environment else ""
                    )
                    + ") "
                    if parameterized_environment else
                    "      originalWorldProgram\n"
                    "      candidateWorldProgram "
                )
                + f"{ids_name} := by\n"
                f"  exact {_lean_all_listed_proof(linked_running_theorems)}"
            )
        source = (
            "import StageA.RelationalAcceptanceContext\n"
            + _acceptance_segment_imports(selected, segment_module_by_edge)
            + "\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n"
            "set_option linter.constructorNameAsVariable false\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(stage_a / f"{module}.lean", source)
        chunks.append({
            "module": module,
            "ids": ids_name,
            "edge_ids": edge_ids_name,
            "running": (
                f"acceptanceRunningChunk{chunk_index}Checked originalEnvironment "
                "candidateEnvironment "
                + (
                    "originalProtocolEnvironment candidateProtocolEnvironment "
                    if parameterized_protocol_environment else ""
                )
                + "environmentRefines"
                if parameterized_environment else
                f"acceptanceRunningChunk{chunk_index}Checked"
            ),
            "linked_running": (
                f"acceptanceLinkedRunningChunk{chunk_index}Checked "
                "originalEnvironment candidateEnvironment "
                + (
                    "originalProtocolEnvironment candidateProtocolEnvironment "
                    if parameterized_protocol_environment else ""
                )
                + "environmentRefines"
                if linked_acceptance_ready and parameterized_environment else
                f"acceptanceLinkedRunningChunk{chunk_index}Checked"
                if linked_acceptance_ready else ""
            ),
            "edges": f"acceptanceExecutionEdgeChunk{chunk_index}Checked",
        })

    node_ids_expr = _lean_appended_list([chunk["ids"] for chunk in chunks])
    edge_ids_expr = _lean_appended_list([chunk["edge_ids"] for chunk in chunks])
    region_node_ids_expr = _lean_appended_list(
        [chunk["ids"] for chunk in region_chunks]
    )
    region_proof = _lean_appended_proof(
        region_chunks, "allListedRegionsMatchProductGraph_append",
        "staticProofContext relationalProductGraph allRegions", "regions",
    )
    acceptance_original_program = (
        "(originalWorldProgram originalEnvironment"
        + (" originalProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "originalWorldProgram"
    )
    acceptance_candidate_program = (
        "(candidateWorldProgram candidateEnvironment"
        + (" candidateProtocolEnvironment" if parameterized_protocol_environment else "")
        + ")"
        if parameterized_environment else "candidateWorldProgram"
    )
    running_proof = ""
    if ordinary_acceptance_ready:
        running_proof = _lean_appended_proof(
            chunks, "allListedRunningProductNodesRefined_append",
            "staticProofContext relationalProductGraph productInvariantTable "
            "relationalProductReachabilityEvidence productControlProfile "
            "protocolCallbackTargets "
            f"{acceptance_original_program} {acceptance_candidate_program}",
            "running",
        )
    linked_running_proof = ""
    if linked_acceptance_ready:
        linked_running_proof = _lean_appended_proof(
            chunks, "allListedLinkedRunningProductNodesRefined_append",
            "staticProofContext relationalProductGraph productInvariantTable "
            "relationalProductReachabilityEvidence linkedProductControlProfile "
            "protocolCallbackTargets "
            f"{acceptance_original_program} {acceptance_candidate_program}",
            "linked_running",
        )
    edge_proof = ""
    if ordinary_acceptance_ready:
        edge_proof = _lean_appended_proof(
            [dict(chunk, ids=chunk["edge_ids"]) for chunk in chunks],
            "allListedProductExecutionEdgesRefined_append",
            "staticProofContext relationalProductGraph allRegions productInvariantTable",
            "edges",
        )
    root_target_id = int(nodes[root_node_id]["target_id"])
    callback_node_ids = [
        int(state["node_id"]) for state in plan["protocol_callback_states"]
    ]
    callback_node_ids_literal = "[" + ", ".join(map(str, callback_node_ids)) + "]"
    callback_theorems = [
        f"acceptanceCallbackRunningNode{node_id}Refined"
        + (
            " originalEnvironment candidateEnvironment"
            + (
                " originalProtocolEnvironment candidateProtocolEnvironment"
                if parameterized_protocol_environment else ""
            )
            + " environmentRefines"
            if parameterized_environment else ""
        )
        for node_id in callback_node_ids
    ]
    callback_closure_source = ""
    if parameterized_protocol_environment:
        callback_closure_source = (
            f"def allAcceptanceCallbackNodeIds : List Nat := {callback_node_ids_literal}\n\n"
            "theorem allAcceptanceCallbackRunningNodesListed\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    AllListedCallbackRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            "      (originalWorldProgram originalEnvironment originalProtocolEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment candidateProtocolEnvironment)\n"
            "      allAcceptanceCallbackNodeIds := by\n"
            f"  exact {_lean_all_listed_proof(callback_theorems)}\n\n"
            "theorem allAcceptanceCallbackRunningNodesRefined\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            "    (environmentRefines : ExternalEnvironmentRefines staticProofContext\n"
            "      externalCallSites originalEnvironment candidateEnvironment) :\n"
            "    ReachableCallbackRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            "      (originalWorldProgram originalEnvironment originalProtocolEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment candidateProtocolEnvironment) := by\n"
            "  apply reachableCallbackRunningProductNodesRefined_of_listed_profile\n"
            "  have ids : allAcceptanceCallbackNodeIds =\n"
            "      (protocolCallbackTargets.states.map fun state => state.nodeId) := by decide\n"
            "  rw [\u2190 ids]\n"
            "  exact allAcceptanceCallbackRunningNodesListed originalEnvironment\n"
            "    candidateEnvironment originalProtocolEnvironment\n"
            "    candidateProtocolEnvironment environmentRefines\n\n"
        )
    linked_running_closure_source = ""
    if linked_acceptance_ready and parameterized_environment:
        linked_running_closure_source = (
            "theorem allAcceptanceLinkedRunningNodesListed\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            + (
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                if parameterized_protocol_environment else ""
            )
            + "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment) :\n"
            "    AllListedLinkedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets\n"
            f"      {acceptance_original_program}\n"
            f"      {acceptance_candidate_program} allAcceptanceNodeIds := by\n"
            f"  simpa [allAcceptanceNodeIds] using ({linked_running_proof})\n\n"
            "theorem allAcceptanceLinkedRunningNodesRefined\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            + (
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                if parameterized_protocol_environment else ""
            )
            + "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment) :\n"
            "    ReachableLinkedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets\n"
            f"      {acceptance_original_program}\n"
            f"      {acceptance_candidate_program} := by\n"
            "  apply reachableLinkedRunningProductNodesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph productInvariantTable\n"
            "    relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "    protocolCallbackTargets\n"
            f"    {acceptance_original_program}\n"
            f"    {acceptance_candidate_program} relationalProductLocalEvidence\n"
            "    relationalProductLocalEvidenceCompleteChecked\n"
            "  have ids : allAcceptanceNodeIds =\n"
            "      relationalProductLocalEvidence.decodedNodeIds := by decide\n"
            "  rw [← ids]\n"
            "  exact allAcceptanceLinkedRunningNodesListed originalEnvironment\n"
            "    candidateEnvironment "
            + (
                "originalProtocolEnvironment candidateProtocolEnvironment "
                if parameterized_protocol_environment else ""
            )
            + "environmentRefines\n\n"
        )
    elif linked_acceptance_ready:
        linked_running_closure_source = (
            "theorem allAcceptanceLinkedRunningNodesListed :\n"
            "    AllListedLinkedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets originalWorldProgram candidateWorldProgram\n"
            "      allAcceptanceNodeIds := by\n"
            f"  simpa [allAcceptanceNodeIds] using ({linked_running_proof})\n\n"
            "theorem allAcceptanceLinkedRunningNodesRefined :\n"
            "    ReachableLinkedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets originalWorldProgram candidateWorldProgram := by\n"
            "  apply reachableLinkedRunningProductNodesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph productInvariantTable\n"
            "    relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "    protocolCallbackTargets originalWorldProgram candidateWorldProgram\n"
            "    relationalProductLocalEvidence relationalProductLocalEvidenceCompleteChecked\n"
            "  have ids : allAcceptanceNodeIds =\n"
            "      relationalProductLocalEvidence.decodedNodeIds := by decide\n"
            "  rw [← ids]\n"
            "  exact allAcceptanceLinkedRunningNodesListed\n\n"
        )
    if parameterized_environment:
        running_closure_source = (
            "theorem allAcceptanceRunningNodesListed\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            + (
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                if parameterized_protocol_environment else ""
            )
            +
            "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment) :\n"
            "    AllListedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            f"      {acceptance_original_program}\n"
            f"      {acceptance_candidate_program} allAcceptanceNodeIds := by\n"
            f"  simpa [allAcceptanceNodeIds] using ({running_proof})\n\n"
            "theorem allAcceptanceRunningNodesRefined\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            + (
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                if parameterized_protocol_environment else ""
            )
            +
            "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment) :\n"
            "    ReachableRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            f"      {acceptance_original_program}\n"
            f"      {acceptance_candidate_program} := by\n"
            "  apply reachableRunningProductNodesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph productInvariantTable\n"
            "    relationalProductReachabilityEvidence productControlProfile\n"
            "    protocolCallbackTargets\n"
            f"    {acceptance_original_program}\n"
            f"    {acceptance_candidate_program}\n"
            "    relationalProductLocalEvidence\n"
            "    relationalProductLocalEvidenceCompleteChecked\n"
            "  have ids : allAcceptanceNodeIds =\n"
            "      relationalProductLocalEvidence.decodedNodeIds := by decide\n"
            "  rw [← ids]\n"
            "  exact allAcceptanceRunningNodesListed originalEnvironment\n"
            "    candidateEnvironment "
            + (
                "originalProtocolEnvironment candidateProtocolEnvironment "
                if parameterized_protocol_environment else ""
            )
            + "environmentRefines\n\n"
        )
        if parameterized_protocol_environment:
            acceptance_certificate_source = (
                "def wholeProgramCertificate\n"
                "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
                "      originalEnvironment candidateEnvironment)\n"
                "    (protocolRefines : WorldExternalProtocolEnvironmentsRefine\n"
                "      staticProofContext relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence productControlProfile\n"
                "      protocolCallbackTargets externalCallSites\n"
                "      originalProtocolEnvironment candidateProtocolEnvironment) :\n"
                "    WholeProgramCertificate staticProofContext relationalProductGraph\n"
                "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
                "      productControlProfile protocolCallbackTargets externalCallSites consoleLaunch\n"
                "      originalEnvironment candidateEnvironment\n"
                "      originalProtocolEnvironment candidateProtocolEnvironment := {\n"
                "  imageBundle := proofBundle\n"
                "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
                "  originalCodeAliasesSemanticallyValid := "
                "staticOriginalCodeAliasesSemanticallyChecked\n"
                "  candidateCodeAliasesSemanticallyValid := "
                "staticCandidateCodeAliasesSemanticallyChecked\n"
                "  originalCodeAliasesInstructionSemanticallyValid := "
                "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
                "  candidateCodeAliasesInstructionSemanticallyValid := "
                "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
                "  staticContextValid := staticProofContextChecked\n"
                "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
                "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
                "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
                "  invariantTableValid := productInvariantTableValid\n"
                "  callbackTargetsValid := by decide\n"
                "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
                "  decodedControlComplete := reachableProductLocalCertificate.reachableControlComplete\n"
                "  reachableEdgesRefined := reachableProductLocalCertificate.reachableEdgesRefined\n"
                "  reachableExecutionEdgesRefined := allAcceptanceExecutionEdgesRefined\n"
                "  environmentsRefined := environmentRefines.externalRefines\n"
                "  protocolEnvironmentsRefined := protocolRefines\n"
                "  launchValid := consoleLaunchValid\n"
                "  launchRealizable := consoleLaunchRealizable\n"
                "  launchControlAllowed := by decide\n"
                "  runningProductNodesRefined := allAcceptanceRunningNodesRefined\n"
                "    originalEnvironment candidateEnvironment originalProtocolEnvironment\n"
                "    candidateProtocolEnvironment environmentRefines\n"
                "  callbackRunningProductNodesRefined :=\n"
                "    allAcceptanceCallbackRunningNodesRefined originalEnvironment\n"
                "      candidateEnvironment originalProtocolEnvironment\n"
                "      candidateProtocolEnvironment environmentRefines.externalRefines\n"
                "  originalInstructionSemanticsAdequate := by\n"
                "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
                "    simpa [originalWorldProgram, allRegions] using\n"
                "      allOriginalRegionsInstructionAdequate\n"
                "  candidateInstructionSemanticsAdequate := by\n"
                "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
                "    simpa [candidateWorldProgram, allRegions] using\n"
                "      allCandidateRegionsInstructionAdequate\n"
                "}\n\n"
                "theorem candidatePE32ProgramsEquivalent\n"
                "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
                "    (originalProtocolEnvironment candidateProtocolEnvironment : "
                "WorldExternalProtocolEnvironment)\n"
                "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
                "      originalEnvironment candidateEnvironment)\n"
                "    (protocolRefines : WorldExternalProtocolEnvironmentsRefine\n"
                "      staticProofContext relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence productControlProfile\n"
                "      protocolCallbackTargets externalCallSites\n"
                "      originalProtocolEnvironment candidateProtocolEnvironment) :\n"
                "    PE32RawProgramsObservationallyEquivalent staticProofContext\n"
                "      relationalProductGraph productInvariantTable\n"
                "      relationalProductReachabilityEvidence productControlProfile consoleLaunch\n"
                "      (originalWorldProgram originalEnvironment originalProtocolEnvironment)\n"
                "      (candidateWorldProgram candidateEnvironment candidateProtocolEnvironment) := by\n"
                "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
                "    pe32ProgramsEquivalent_raw staticProofContext relationalProductGraph allRegions\n"
                "      productInvariantTable relationalProductReachabilityEvidence productControlProfile\n"
                "      protocolCallbackTargets externalCallSites consoleLaunch\n"
                "      originalEnvironment candidateEnvironment originalProtocolEnvironment\n"
                "      candidateProtocolEnvironment\n"
                "      (wholeProgramCertificate originalEnvironment candidateEnvironment\n"
                "        originalProtocolEnvironment candidateProtocolEnvironment\n"
                "        environmentRefines protocolRefines)\n\n"
            )
        else:
            acceptance_certificate_source = (
            "theorem noProtocolExternalCallSitesChecked :\n"
            "    externalCallSitesExcludeProtocol staticProofContext externalCallSites = true :=\n"
            "  by decide\n\n"
            "def wholeProgramCertificate\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment) :\n"
            "    WholeProgramCertificate staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      productControlProfile protocolCallbackTargets externalCallSites consoleLaunch\n"
            "      originalEnvironment candidateEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment := {\n"
            "  imageBundle := proofBundle\n"
            "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
            "  originalCodeAliasesSemanticallyValid := "
            "staticOriginalCodeAliasesSemanticallyChecked\n"
            "  candidateCodeAliasesSemanticallyValid := "
            "staticCandidateCodeAliasesSemanticallyChecked\n"
            "  originalCodeAliasesInstructionSemanticallyValid := "
            "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
            "  candidateCodeAliasesInstructionSemanticallyValid := "
            "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  callbackTargetsValid := by decide\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := reachableProductLocalCertificate.reachableControlComplete\n"
            "  reachableEdgesRefined := reachableProductLocalCertificate.reachableEdgesRefined\n"
            "  reachableExecutionEdgesRefined := allAcceptanceExecutionEdgesRefined\n"
            "  environmentsRefined := environmentRefines.externalRefines\n"
            "  protocolEnvironmentsRefined :=\n"
            "    WorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets externalCallSites inertWorldProtocolEnvironment\n"
            "      inertWorldProtocolEnvironment noProtocolExternalCallSitesChecked\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchRealizable := consoleLaunchRealizable\n"
            "  launchControlAllowed := by decide\n"
            "  runningProductNodesRefined := allAcceptanceRunningNodesRefined\n"
            "    originalEnvironment candidateEnvironment environmentRefines\n"
            "  callbackRunningProductNodesRefined :=\n"
            "    reachableCallbackRunningProductNodesRefined_of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment)\n"
            "      productInvariantTableValid noProtocolExternalCallSitesChecked\n"
            "  originalInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [originalWorldProgram, allRegions] using\n"
            "      allOriginalRegionsInstructionAdequate\n"
            "  candidateInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [candidateWorldProgram, allRegions] using\n"
            "      allCandidateRegionsInstructionAdequate\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalent\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment) :\n"
            "    PE32RawProgramsObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile consoleLaunch\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment) := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalent_raw staticProofContext relationalProductGraph allRegions\n"
            "      productInvariantTable relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets externalCallSites consoleLaunch\n"
            "      originalEnvironment candidateEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment\n"
            "      (wholeProgramCertificate originalEnvironment candidateEnvironment\n"
            "        environmentRefines)\n\n"
        )
    else:
        running_closure_source = (
            "theorem allAcceptanceRunningNodesListed :\n"
            "    AllListedRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            "      originalWorldProgram\n"
            "      candidateWorldProgram allAcceptanceNodeIds := by\n"
            f"  simpa [allAcceptanceNodeIds] using ({running_proof})\n\n"
            "theorem allAcceptanceRunningNodesRefined :\n"
            "    ReachableRunningProductNodesRefined staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets\n"
            "      originalWorldProgram\n"
            "      candidateWorldProgram := by\n"
            "  apply reachableRunningProductNodesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph productInvariantTable\n"
            "    relationalProductReachabilityEvidence productControlProfile\n"
            "    protocolCallbackTargets\n"
            "    originalWorldProgram\n"
            "    candidateWorldProgram relationalProductLocalEvidence\n"
            "    relationalProductLocalEvidenceCompleteChecked\n"
            "  have ids : allAcceptanceNodeIds =\n"
            "      relationalProductLocalEvidence.decodedNodeIds := by decide\n"
            "  rw [← ids]\n"
            "  exact allAcceptanceRunningNodesListed\n\n"
        )
        acceptance_certificate_source = (
            "theorem inertEnvironmentRefines :\n"
            "    ExternalEnvironmentRefines staticProofContext externalCallSites\n"
            "      inertWorldEnvironment inertWorldEnvironment := by\n"
            "  unfold ExternalEnvironmentRefines\n"
            "  refine ⟨by decide, by decide, ?_⟩\n"
            "  intro site member\n  simp [externalCallSites] at member\n\n"
            "theorem noProtocolExternalCallSitesChecked :\n"
            "    externalCallSitesExcludeProtocol staticProofContext externalCallSites = true :=\n"
            "  by decide\n\n"
            "def wholeProgramCertificate : WholeProgramCertificate staticProofContext\n"
            "    relationalProductGraph allRegions productInvariantTable\n"
            "    relationalProductReachabilityEvidence productControlProfile\n"
            "    protocolCallbackTargets externalCallSites consoleLaunch\n"
            "    inertWorldEnvironment inertWorldEnvironment\n"
            "    inertWorldProtocolEnvironment inertWorldProtocolEnvironment := {\n"
            "  imageBundle := proofBundle\n"
            "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
            "  originalCodeAliasesSemanticallyValid := "
            "staticOriginalCodeAliasesSemanticallyChecked\n"
            "  candidateCodeAliasesSemanticallyValid := "
            "staticCandidateCodeAliasesSemanticallyChecked\n"
            "  originalCodeAliasesInstructionSemanticallyValid := "
            "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
            "  candidateCodeAliasesInstructionSemanticallyValid := "
            "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  callbackTargetsValid := by decide\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := reachableProductLocalCertificate.reachableControlComplete\n"
            "  reachableEdgesRefined := reachableProductLocalCertificate.reachableEdgesRefined\n"
            "  reachableExecutionEdgesRefined := allAcceptanceExecutionEdgesRefined\n"
            "  environmentsRefined := inertEnvironmentRefines\n"
            "  protocolEnvironmentsRefined :=\n"
            "    WorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets externalCallSites inertWorldProtocolEnvironment\n"
            "      inertWorldProtocolEnvironment noProtocolExternalCallSitesChecked\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchRealizable := consoleLaunchRealizable\n"
            "  launchControlAllowed := by decide\n"
            "  runningProductNodesRefined := by\n"
            "    simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "      allAcceptanceRunningNodesRefined\n"
            "  callbackRunningProductNodesRefined :=\n"
            "    reachableCallbackRunningProductNodesRefined_of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets originalWorldProgram candidateWorldProgram\n"
            "      productInvariantTableValid\n"
            "      noProtocolExternalCallSitesChecked\n"
            "  originalInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [originalWorldProgram, allRegions] using\n"
            "      allOriginalRegionsInstructionAdequate\n"
            "  candidateInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [candidateWorldProgram, allRegions] using\n"
            "      allCandidateRegionsInstructionAdequate\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalent :\n"
            "    PE32RawProgramsObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile consoleLaunch\n"
            "      originalWorldProgram candidateWorldProgram := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalent_raw staticProofContext relationalProductGraph allRegions\n"
            "      productInvariantTable relationalProductReachabilityEvidence productControlProfile\n"
            "      protocolCallbackTargets externalCallSites\n"
            "      consoleLaunch inertWorldEnvironment inertWorldEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment\n"
            "      wholeProgramCertificate\n\n"
        )
    linked_environment_support_source = ""
    if linked_acceptance_ready and not ordinary_acceptance_ready:
        if not parameterized_protocol_environment:
            linked_environment_support_source = (
                (
                    "theorem inertEnvironmentRefines :\n"
                    "    ExternalEnvironmentRefines staticProofContext externalCallSites\n"
                    "      inertWorldEnvironment inertWorldEnvironment := by\n"
                    "  unfold ExternalEnvironmentRefines\n"
                    "  refine ⟨by decide, by decide, ?_⟩\n"
                    "  intro site member\n  simp [externalCallSites] at member\n\n"
                    if not parameterized_environment else ""
                )
                + "theorem noProtocolExternalCallSitesChecked :\n"
                "    externalCallSitesExcludeProtocol staticProofContext externalCallSites = true :=\n"
                "  by decide\n\n"
            )
        running_closure_source = ""
        callback_closure_source = ""
        acceptance_certificate_source = ""

    linked_acceptance_certificate_source = ""
    if (
        linked_acceptance_ready
        and parameterized_environment
        and parameterized_protocol_environment
    ):
        linked_acceptance_certificate_source = (
            "def linkedWholeProgramCertificate\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment)\n"
            "    (protocolRefines : LinkedWorldExternalProtocolEnvironmentsRefine\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets externalCallSites\n"
            "      originalProtocolEnvironment candidateProtocolEnvironment) :\n"
            "    LinkedWholeProgramCertificate staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      linkedProductControlProfile protocolCallbackTargets externalCallSites consoleLaunch\n"
            "      originalEnvironment candidateEnvironment\n"
            "      originalProtocolEnvironment candidateProtocolEnvironment := {\n"
            "  imageBundle := proofBundle\n"
            "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
            "  originalCodeAliasesSemanticallyValid := "
            "staticOriginalCodeAliasesSemanticallyChecked\n"
            "  candidateCodeAliasesSemanticallyValid := "
            "staticCandidateCodeAliasesSemanticallyChecked\n"
            "  originalCodeAliasesInstructionSemanticallyValid := "
            "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
            "  candidateCodeAliasesInstructionSemanticallyValid := "
            "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  callbackTargetsValid := by decide\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := "
            "reachableProductLocalCertificate.reachableControlComplete\n"
            "  environmentsRefined := environmentRefines.externalRefines\n"
            "  protocolEnvironmentsRefined := protocolRefines\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchRealizable := consoleLaunchLinkedRealizable\n"
            "  launchControlAllowed := by\n"
            "    change linkedProductControlProfile.Allows\n"
            "      consoleLaunch.rootNodeId consoleLaunch.continuationTargetIds\n"
            "      consoleLaunch.frameOffsets.head? = true\n"
            "    decide\n"
            "  runningProductNodesRefined := allAcceptanceLinkedRunningNodesRefined\n"
            "    originalEnvironment candidateEnvironment originalProtocolEnvironment\n"
            "    candidateProtocolEnvironment environmentRefines\n"
            "  callbackRunningProductNodesRefined :=\n"
            "    ReachableLinkedCallbackRunningProductNodesRefined.of_shallow\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence productControlProfile\n"
            "      linkedProductControlProfile protocolCallbackTargets\n"
            "      (originalWorldProgram originalEnvironment originalProtocolEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment candidateProtocolEnvironment)\n"
            "      productControlProfilesOldToLinkedShallow\n"
            "      productControlProfilesLinkedToOldShallow\n"
            "      linkedProductControlProfileLinksEmpty\n"
            "      (allAcceptanceCallbackRunningNodesRefined originalEnvironment\n"
            "        candidateEnvironment originalProtocolEnvironment\n"
            "        candidateProtocolEnvironment environmentRefines.externalRefines)\n"
            "  originalInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [originalWorldProgram, allRegions] using\n"
            "      allOriginalRegionsInstructionAdequate\n"
            "  candidateInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [candidateWorldProgram, allRegions] using\n"
            "      allCandidateRegionsInstructionAdequate\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalentLinked\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (originalProtocolEnvironment candidateProtocolEnvironment : "
            "WorldExternalProtocolEnvironment)\n"
            "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment)\n"
            "    (protocolRefines : LinkedWorldExternalProtocolEnvironmentsRefine\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets externalCallSites\n"
            "      originalProtocolEnvironment candidateProtocolEnvironment) :\n"
            "    PE32RawProgramsLinkedObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile consoleLaunch\n"
            "      (originalWorldProgram originalEnvironment originalProtocolEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment candidateProtocolEnvironment) := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalentLinked_raw staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      linkedProductControlProfile protocolCallbackTargets externalCallSites\n"
            "      consoleLaunch originalEnvironment candidateEnvironment\n"
            "      originalProtocolEnvironment candidateProtocolEnvironment\n"
            "      (linkedWholeProgramCertificate originalEnvironment candidateEnvironment\n"
            "        originalProtocolEnvironment candidateProtocolEnvironment\n"
            "        environmentRefines protocolRefines)\n\n"
        )
    elif linked_acceptance_ready and parameterized_environment:
        linked_acceptance_certificate_source = (
            "def linkedWholeProgramCertificate\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment) :\n"
            "    LinkedWholeProgramCertificate staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      linkedProductControlProfile protocolCallbackTargets externalCallSites consoleLaunch\n"
            "      originalEnvironment candidateEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment := {\n"
            "  imageBundle := proofBundle\n"
            "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
            "  originalCodeAliasesSemanticallyValid := "
            "staticOriginalCodeAliasesSemanticallyChecked\n"
            "  candidateCodeAliasesSemanticallyValid := "
            "staticCandidateCodeAliasesSemanticallyChecked\n"
            "  originalCodeAliasesInstructionSemanticallyValid := "
            "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
            "  candidateCodeAliasesInstructionSemanticallyValid := "
            "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  callbackTargetsValid := by decide\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := "
            "reachableProductLocalCertificate.reachableControlComplete\n"
            "  environmentsRefined := environmentRefines.externalRefines\n"
            "  protocolEnvironmentsRefined :=\n"
            "    LinkedWorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets externalCallSites inertWorldProtocolEnvironment\n"
            "      inertWorldProtocolEnvironment noProtocolExternalCallSitesChecked\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchRealizable := consoleLaunchLinkedRealizable\n"
            "  launchControlAllowed := by\n"
            "    change linkedProductControlProfile.Allows\n"
            "      consoleLaunch.rootNodeId consoleLaunch.continuationTargetIds\n"
            "      consoleLaunch.frameOffsets.head? = true\n"
            "    decide\n"
            "  runningProductNodesRefined := allAcceptanceLinkedRunningNodesRefined\n"
            "    originalEnvironment candidateEnvironment environmentRefines\n"
            "  callbackRunningProductNodesRefined :=\n"
            "    reachableLinkedCallbackRunningProductNodesRefined_of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment)\n"
            "      productInvariantTableValid noProtocolExternalCallSitesChecked\n"
            "  originalInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [originalWorldProgram, allRegions] using\n"
            "      allOriginalRegionsInstructionAdequate\n"
            "  candidateInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [candidateWorldProgram, allRegions] using\n"
            "      allCandidateRegionsInstructionAdequate\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalentLinked\n"
            "    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)\n"
            "    (environmentRefines : AcceptanceExternalEnvironmentsRefine\n"
            "      originalEnvironment candidateEnvironment) :\n"
            "    PE32RawProgramsLinkedObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile consoleLaunch\n"
            "      (originalWorldProgram originalEnvironment)\n"
            "      (candidateWorldProgram candidateEnvironment) := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalentLinked_raw staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      linkedProductControlProfile protocolCallbackTargets externalCallSites\n"
            "      consoleLaunch originalEnvironment candidateEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment\n"
            "      (linkedWholeProgramCertificate originalEnvironment candidateEnvironment\n"
            "        environmentRefines)\n\n"
        )
    elif linked_acceptance_ready:
        linked_acceptance_certificate_source = (
            "def linkedWholeProgramCertificate : LinkedWholeProgramCertificate\n"
            "    staticProofContext relationalProductGraph allRegions productInvariantTable\n"
            "    relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "    protocolCallbackTargets externalCallSites consoleLaunch\n"
            "    inertWorldEnvironment inertWorldEnvironment\n"
            "    inertWorldProtocolEnvironment inertWorldProtocolEnvironment := {\n"
            "  imageBundle := proofBundle\n"
            "  executableImagesCovered := ⟨rfl, rfl, rfl, structuralChecked⟩\n"
            "  originalCodeAliasesSemanticallyValid := "
            "staticOriginalCodeAliasesSemanticallyChecked\n"
            "  candidateCodeAliasesSemanticallyValid := "
            "staticCandidateCodeAliasesSemanticallyChecked\n"
            "  originalCodeAliasesInstructionSemanticallyValid := "
            "staticOriginalCodeAliasesInstructionSemanticallyChecked\n"
            "  candidateCodeAliasesInstructionSemanticallyValid := "
            "staticCandidateCodeAliasesInstructionSemanticallyChecked\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  productGraphValid := relationalProductGraphIndexedValidChecked\n"
            "  regionsUseCanonicalContext := allRegionsUseStaticContextChecked\n"
            "  regionsMatchProductGraph := allRegionsMatchProductGraph\n"
            "  invariantTableValid := productInvariantTableValid\n"
            "  callbackTargetsValid := by decide\n"
            "  reachabilityClosed := generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  decodedControlComplete := "
            "reachableProductLocalCertificate.reachableControlComplete\n"
            "  environmentsRefined := inertEnvironmentRefines\n"
            "  protocolEnvironmentsRefined :=\n"
            "    LinkedWorldExternalProtocolEnvironmentsRefine.of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets externalCallSites inertWorldProtocolEnvironment\n"
            "      inertWorldProtocolEnvironment noProtocolExternalCallSitesChecked\n"
            "  launchValid := consoleLaunchValid\n"
            "  launchRealizable := consoleLaunchLinkedRealizable\n"
            "  launchControlAllowed := by\n"
            "    change linkedProductControlProfile.Allows\n"
            "      consoleLaunch.rootNodeId consoleLaunch.continuationTargetIds\n"
            "      consoleLaunch.frameOffsets.head? = true\n"
            "    decide\n"
            "  runningProductNodesRefined := by\n"
            "    simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "      allAcceptanceLinkedRunningNodesRefined\n"
            "  callbackRunningProductNodesRefined :=\n"
            "    reachableLinkedCallbackRunningProductNodesRefined_of_no_protocol_sites\n"
            "      staticProofContext relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      protocolCallbackTargets originalWorldProgram candidateWorldProgram\n"
            "      productInvariantTableValid noProtocolExternalCallSitesChecked\n"
            "  originalInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [originalWorldProgram, allRegions] using\n"
            "      allOriginalRegionsInstructionAdequate\n"
            "  candidateInstructionSemanticsAdequate := by\n"
            "    apply DecodedWorldProgram.instructionSemanticsAdequate_of_regions\n"
            "    simpa [candidateWorldProgram, allRegions] using\n"
            "      allCandidateRegionsInstructionAdequate\n"
            "}\n\n"
            "theorem candidatePE32ProgramsEquivalentLinked :\n"
            "    PE32RawProgramsLinkedObservationallyEquivalent staticProofContext\n"
            "      relationalProductGraph productInvariantTable\n"
            "      relationalProductReachabilityEvidence linkedProductControlProfile\n"
            "      consoleLaunch originalWorldProgram candidateWorldProgram := by\n"
            "  simpa [originalWorldProgram, candidateWorldProgram] using\n"
            "    pe32ProgramsEquivalentLinked_raw staticProofContext relationalProductGraph\n"
            "      allRegions productInvariantTable relationalProductReachabilityEvidence\n"
            "      linkedProductControlProfile protocolCallbackTargets externalCallSites\n"
            "      consoleLaunch inertWorldEnvironment inertWorldEnvironment\n"
            "      inertWorldProtocolEnvironment inertWorldProtocolEnvironment\n"
            "      linkedWholeProgramCertificate\n\n"
        )
    ordinary_execution_closure_source = ""
    if ordinary_acceptance_ready:
        ordinary_execution_closure_source = (
            "theorem allAcceptanceExecutionEdgesListed :\n"
            "    AllListedProductExecutionEdgesRefined staticProofContext\n"
            "      relationalProductGraph allRegions productInvariantTable\n"
            "      allAcceptanceEdgeIds := by\n"
            f"  simpa [allAcceptanceEdgeIds] using ({edge_proof})\n\n"
            "theorem allAcceptanceExecutionEdgesRefined :\n"
            "    ReachableProductExecutionEdgesRefined staticProofContext\n"
            "      relationalProductGraph allRegions productInvariantTable\n"
            "      relationalProductReachabilityEvidence := by\n"
            "  apply reachableProductExecutionEdgesRefined_of_complete_evidence\n"
            "    staticProofContext relationalProductGraph allRegions productInvariantTable\n"
            "    relationalProductReachabilityEvidence relationalProductLocalEvidence\n"
            "    relationalProductLocalEvidenceCompleteChecked\n"
            "  have inventoriesMatch :\n"
            "      allAcceptanceEdgeIds.all\n"
            "          relationalProductLocalEvidence.refinedEdgeIds.contains &&\n"
            "        relationalProductLocalEvidence.refinedEdgeIds.all\n"
            "          allAcceptanceEdgeIds.contains = true := by decide\n"
            "  simp only [Bool.and_eq_true] at inventoriesMatch\n"
            "  exact allListedProductExecutionEdgesRefined_of_contains\n"
            "    staticProofContext relationalProductGraph allRegions\n"
            "    productInvariantTable allAcceptanceEdgeIds\n"
            "    relationalProductLocalEvidence.refinedEdgeIds\n"
            "    allAcceptanceExecutionEdgesListed inventoriesMatch.2\n\n"
        )

    final_source = (
        "import StageA.RelationalInstructionAdequacyCertificate\n"
        "import StageA.RelationalISARequirementReplayCertificate\n"
        "import StageA.RelationalPEWorldExecution\n"
        "import StageA.RelationalLaunchRealizabilityCertificate\n"
        + "".join(
            f"import StageA.{chunk['module']}\n" for chunk in region_chunks
        )
        + "".join(f"import StageA.{chunk['module']}\n" for chunk in chunks)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        f"def allAcceptanceNodeIds : List Nat := {node_ids_expr}\n\n"
        f"def allAcceptanceRegionNodeIds : List Nat := {region_node_ids_expr}\n\n"
        f"def allAcceptanceEdgeIds : List Nat := {edge_ids_expr}\n\n"
        "theorem allAcceptanceRegionsListed :\n"
        "    AllListedRegionsMatchProductGraph staticProofContext relationalProductGraph\n"
        "      allRegions allAcceptanceRegionNodeIds := by\n"
        f"  simpa [allAcceptanceRegionNodeIds] using ({region_proof})\n\n"
        "theorem allAcceptanceRegionNodeIdsComplete :\n"
        "    allAcceptanceRegionNodeIds = List.range relationalProductGraph.nodes.size := by\n"
        "  decide\n\n"
        "theorem allRegionsMatchProductGraph :\n"
        "    RegionsMatchProductGraph staticProofContext relationalProductGraph allRegions := by\n"
        "  apply regionsMatchProductGraph_of_listed_range\n"
        "  rw [← allAcceptanceRegionNodeIdsComplete]\n"
        "  exact allAcceptanceRegionsListed\n\n"
        + running_closure_source
        + linked_running_closure_source
        + callback_closure_source
        + ordinary_execution_closure_source
        +
        "theorem productInvariantTableValid :\n"
        "    productInvariantTable.Valid relationalProductGraph := by\n"
        "  unfold ProductInvariantTable.Valid\n  decide\n\n"
        "theorem consoleLaunchValid :\n"
        "    consoleLaunch.Valid staticProofContext relationalProductGraph\n"
        "      productInvariantTable := by\n"
        "  refine ⟨by decide, by decide, by decide, by decide, by decide,\n"
        "    by decide, by decide, ?_, ?_, ⟨by decide, by decide⟩⟩\n"
        f"  · exact ⟨relationalProductGraph.nodes[{entry_root_node_id}], by decide,\n"
        "      by decide, by decide, by decide, by decide⟩\n"
        f"  · exact ⟨relationalProductGraph.nodes[{root_node_id}], by decide,\n"
        "      by decide, by decide, by decide, by decide⟩\n\n"
        + linked_environment_support_source
        + acceptance_certificate_source
        + linked_acceptance_certificate_source
        + "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(stage_a / "RelationalAcceptance.lean", final_source)
    return plan
