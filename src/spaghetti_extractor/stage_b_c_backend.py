from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .artifact_formats import SEMANTIC_IR_FORMAT
from .stage_b_state_machine import (
    STAGE_B_STATE_MACHINE_FORMAT,
    normalize_stage_a_semantic_transfer,
    normalize_stage_a_semantic_transfers,
)
from .stage_b_api_catalog import MachineCallCatalog, MachineCallSignature, load_machine_call_catalog
from .util import sha256_bytes, sha256_file, write_json


STAGE_B_C_BACKEND_FORMAT = "stage-b-semantic-c-backend-v1"

_REGISTER_NAMES = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAG_NAMES = ("cf", "zf", "sf", "of", "pf", "df")
_REP_SCAS_OWNED_REGISTERS = ("edi", "ecx")
_REP_SCAS_OWNED_FLAGS = ("cf", "pf", "af", "zf", "sf", "of")
_LEAF_OPS = {
    "const",
    "reg",
    "flag",
    "true",
    "false",
    "undefined_bv",
    "undefined_flag",
    "call_response",
    "call_flag",
}
_SUPPORTED_OPS = _LEAF_OPS | {
    "load",
    "add32",
    "sub32",
    "mul32",
    "xor32",
    "and32",
    "or32",
    "not32",
    "neg32",
    "shl32",
    "lshr32",
    "sar",
    "sign_extend",
    "ite",
    "ult32",
    "eq",
    "msb",
    "not",
    "and_bool",
    "or_bool",
    "xor_bool",
    "eq_bool",
    "add_overflow",
    "sub_overflow",
    "parity",
    "bool_to_bit",
    "imul_low32",
    "imul_high32",
    "imul_overflow",
    "mul_low32",
    "mul_high32",
    "mul_carry",
    "udiv_quot32",
    "udiv_rem32",
    "udiv_valid32",
    "bsr_index",
    "tzcnt",
    "shift_cf",
    "shift_of",
    "sbb_borrow",
    "sbb_overflow",
    "fpu_add",
    "fpu_bits_hi32",
    "fpu_bits_lo32",
    "fpu_cmp_cf",
    "fpu_cmp_pf",
    "fpu_cmp_zf",
    "fpu_const",
    "fpu_control",
    "fpu_control_init",
    "fpu_control_load",
    "fpu_control_word",
    "fpu_div",
    "fpu_divr",
    "fpu_empty",
    "fpu_fxam",
    "fpu_int",
    "fpu_int32",
    "fpu_instruction_pointer",
    "fpu_code_selector",
    "fpu_data_pointer",
    "fpu_data_selector",
    "fpu_last_opcode",
    "fpu_mem",
    "fpu_mem64",
    "fpu_mul",
    "fpu_neg",
    "fpu_reg",
    "fpu_status",
    "fpu_status_init",
    "fpu_status_word",
    "fpu_pending_exception",
    "fpu_tag",
    "fpu_sub",
    "fpu_subr",
}
_X87_VALUE_OPS = {
    "fpu_add",
    "fpu_const",
    "fpu_div",
    "fpu_divr",
    "fpu_empty",
    "fpu_int",
    "fpu_mem",
    "fpu_mem64",
    "fpu_mul",
    "fpu_neg",
    "fpu_reg",
    "fpu_sub",
    "fpu_subr",
}
_X87_WORD_OPS = {
    "fpu_bits_hi32",
    "fpu_bits_lo32",
    "fpu_cmp_cf",
    "fpu_cmp_pf",
    "fpu_cmp_zf",
    "fpu_control",
    "fpu_control_init",
    "fpu_control_load",
    "fpu_control_word",
    "fpu_fxam",
    "fpu_int32",
    "fpu_instruction_pointer",
    "fpu_code_selector",
    "fpu_data_pointer",
    "fpu_data_selector",
    "fpu_last_opcode",
    "fpu_pending_exception",
    "fpu_status",
    "fpu_status_init",
    "fpu_status_word",
    "fpu_tag",
}
_SUPPORTED_OUTCOMES = {"fallthrough", "jump", "branch", "return", "indirect_jump", "external_jump"}
_CALL_EVENT_KINDS = {"external_call", "internal_call", "indirect_call"}
_SUPPORTED_EVENT_KINDS = _CALL_EVENT_KINDS | {
    "rep_movsd",
    "rep_movs",
    "rep_scas",
    "rep_stos",
}


def write_stage_b_semantic_c_backend(
    out_dir: Path,
    rows: Iterable[dict[str, Any]],
    *,
    state_machine_binding: dict[str, str] | None = None,
    machine_call_catalog: MachineCallCatalog | None = None,
) -> dict[str, Any]:
    """Emit conservative C transition functions directly from Stage A transfer IR."""

    out_dir.mkdir(parents=True, exist_ok=True)
    header = out_dir / "state-machine-runtime.h"
    transfers_header = out_dir / "state-machine-transfers.h"
    source = out_dir / "state-machine-transfers.c"
    repairs = out_dir / "state-machine-repairs.c"
    dispatch_header = out_dir / "state-machine-dispatch.h"
    dispatch_source = out_dir / "state-machine-dispatch.c"
    engine_header = out_dir / "state-machine-engine.h"
    engine_source = out_dir / "state-machine-engine.c"
    api_adapters_header = out_dir / "state-machine-api-adapters.h"
    api_adapters_source = out_dir / "state-machine-api-adapters.c"
    api_adapters_report_path = out_dir / "state-machine-api-adapters.json"
    source_map_path = out_dir / "state-machine-source-map.json"
    implementation_manifest_path = out_dir / "state-machine-implementation.json"
    runtime_obligations_path = out_dir / "state-machine-runtime-obligations.json"
    report_path = out_dir / "state-machine-c-report.json"
    rows = list(rows)
    inventory_complete = bool(rows)
    api_adapter_plan = _api_adapter_plan(rows, machine_call_catalog)
    runtime_call_boundaries = _runtime_call_obligations(
        rows,
        api_bindings=api_adapter_plan["bindings"],
    )
    runtime_obligations = [item for item in runtime_call_boundaries if item.get("status") != "bound"]
    runtime_obligation_counts = Counter(str(item.get("kind") or "unknown") for item in runtime_obligations)
    runtime_binding_counts = Counter(str(item.get("status") or "unknown") for item in runtime_call_boundaries)
    write_json(
        runtime_obligations_path,
        {
            "format": "stage-b-runtime-call-obligations-v1",
            "status": "complete" if inventory_complete else "incomplete",
            "authority": "stage-a-semantic-transfer-contracts",
            "state_machine": state_machine_binding,
            "machine_call_catalog": machine_call_catalog.binding if machine_call_catalog is not None else None,
            "counts": {
                "call_boundaries": len(runtime_call_boundaries),
                "unbound_obligations": len(runtime_obligations),
                "by_status": dict(sorted(runtime_binding_counts.items())),
                "unbound_by_kind": dict(sorted(runtime_obligation_counts.items())),
            },
            "call_boundaries": runtime_call_boundaries,
            "acceptance": "every obligation must be bound by candidate runtime source and the compiled PE must pass Stage A",
        },
    )
    api_adapters_header.write_text(_api_adapters_header(), encoding="utf-8")
    api_adapters_source.write_text(
        _api_adapters_source(api_adapter_plan["signatures"]),
        encoding="utf-8",
    )
    write_json(
        api_adapters_report_path,
        {
            "format": "stage-b-generated-api-adapters-v1",
            "status": "complete" if not api_adapter_plan["unmatched"] else "incomplete",
            "authority": "machine-call catalog plus Stage A semantic call boundaries",
            "catalog": machine_call_catalog.binding if machine_call_catalog is not None else None,
            "counts": {
                "external_calls": api_adapter_plan["external_call_count"],
                "bound_calls": len(api_adapter_plan["bindings"]),
                "unmatched_calls": len(api_adapter_plan["unmatched"]),
                "generated_import_adapters": len(api_adapter_plan["signatures"]),
            },
            "generated_adapters": [signature.as_json() for signature in api_adapter_plan["signatures"]],
            "unmatched": api_adapter_plan["unmatched"],
        },
    )
    supported: list[tuple[dict[str, Any], str, str]] = []
    repair_rows: list[tuple[dict[str, Any], str, list[str]]] = []
    all_rows: list[tuple[dict[str, Any], str, bool, list[str]]] = []
    unsupported: list[dict[str, Any]] = []
    reason_counts: Counter[str] = Counter()
    used_symbols: set[str] = set()

    for row in rows:
        symbol = _unique_transfer_symbol(row, used_symbols)
        reasons = _row_blockers(row)
        if reasons:
            reason_counts.update(reasons)
            reference = _row_reference(row, reasons)
            reference["symbol"] = symbol
            unsupported.append(reference)
            repair_rows.append((row, symbol, reasons))
            all_rows.append((row, symbol, False, reasons))
            continue
        try:
            rendered = _render_transfer(row, symbol)
        except ValueError as exc:
            reason = f"c_renderer:{exc}"
            reason_counts[reason] += 1
            reference = _row_reference(row, [reason])
            reference["symbol"] = symbol
            unsupported.append(reference)
            repair_rows.append((row, symbol, [reason]))
            all_rows.append((row, symbol, False, [reason]))
            continue
        supported.append((row, symbol, rendered))
        all_rows.append((row, symbol, True, []))

    header.write_text(_runtime_header(), encoding="utf-8")
    transfers_header.write_text(_transfers_header(all_rows), encoding="utf-8")
    generated_source, generated_spans = _render_source(supported)
    repair_source, repair_spans = _render_repairs_source(repair_rows)
    source.write_text(generated_source, encoding="utf-8")
    repairs.write_text(repair_source, encoding="utf-8")
    dispatch_header.write_text(_dispatch_header(), encoding="utf-8")
    dispatch_source.write_text(_dispatch_source(all_rows), encoding="utf-8")
    engine_header.write_text(_engine_header(), encoding="utf-8")
    engine_source.write_text(_engine_source(), encoding="utf-8")
    duplicate_rvas = _duplicate_dispatch_rvas(all_rows)
    strict_candidate_blockers = _strict_candidate_blockers(
        inventory_complete=inventory_complete,
        repair_stub_count=len(repair_rows),
        runtime_obligations=runtime_obligations,
        duplicate_rvas=duplicate_rvas,
    )
    source_map = _semantic_c_source_map(
        all_rows,
        generated_spans=generated_spans,
        repair_spans=repair_spans,
    )
    write_json(source_map_path, source_map)
    implementation_artifacts = {
        "runtime_header": {"path": header.name, "sha256": sha256_file(header)},
        "transfers_header": {"path": transfers_header.name, "sha256": sha256_file(transfers_header)},
        "generated_source": {"path": source.name, "sha256": sha256_file(source)},
        "repair_source": {"path": repairs.name, "sha256": sha256_file(repairs)},
        "dispatch_header": {"path": dispatch_header.name, "sha256": sha256_file(dispatch_header)},
        "dispatch_source": {"path": dispatch_source.name, "sha256": sha256_file(dispatch_source)},
        "engine_header": {"path": engine_header.name, "sha256": sha256_file(engine_header)},
        "engine_source": {"path": engine_source.name, "sha256": sha256_file(engine_source)},
        "api_adapters_header": {
            "path": api_adapters_header.name,
            "sha256": sha256_file(api_adapters_header),
        },
        "api_adapters_source": {
            "path": api_adapters_source.name,
            "sha256": sha256_file(api_adapters_source),
        },
        "api_adapters_report": {
            "path": api_adapters_report_path.name,
            "sha256": sha256_file(api_adapters_report_path),
        },
        "source_map": {"path": source_map_path.name, "sha256": sha256_file(source_map_path)},
        "runtime_obligations": {
            "path": runtime_obligations_path.name,
            "sha256": sha256_file(runtime_obligations_path),
        },
    }
    write_json(
        implementation_manifest_path,
        {
            "format": "stage-b-semantic-c-implementation-v1",
            "authority": "stage-a-semantic-transfer-contracts",
            "status": (
                "complete"
                if inventory_complete and not unsupported and not duplicate_rvas and not runtime_obligations
                else "incomplete"
            ),
            "state_machine": state_machine_binding,
            "machine_call_catalog": machine_call_catalog.binding if machine_call_catalog is not None else None,
            "transfer_inventory": [
                {
                    "id": row.get("id"),
                    "contract_sha256": _row_contract_sha256(row),
                    "rva_start": _row_rva(row),
                    "symbol": symbol,
                    "implementation": _generated_implementation_kind(row) if generated else "repair_stub",
                }
                for row, symbol, generated, _reasons in all_rows
            ],
            "artifacts": implementation_artifacts,
            "strict_candidate": {
                "status": "ready" if not strict_candidate_blockers else "incomplete",
                "blockers": strict_candidate_blockers,
                "policy": "no repair stubs, unbound runtime call adapters, missing transfers, or ambiguous dispatch entries",
            },
            "acceptance": "compile this implementation, then prove the resulting PE with Stage A",
        },
    )
    report = {
        "format": STAGE_B_C_BACKEND_FORMAT,
        "status": "complete" if inventory_complete and not unsupported and not runtime_obligations else "incomplete",
        "source_generation_status": "complete" if inventory_complete and not unsupported else "incomplete",
        "authority": "stage-a-semantic-transfer-contracts",
        "state_machine": state_machine_binding,
        "machine_call_catalog": machine_call_catalog.binding if machine_call_catalog is not None else None,
        "role": "compiler-consumable repair substrate; Stage A whole-program proof remains authoritative",
        "counts": {
            "transfers": len(rows),
            "generated": len(supported),
            "unsupported": len(unsupported),
        },
        "repair_stub_count": len(repair_rows),
        "runtime_obligation_count": len(runtime_obligations),
        "generated_runtime_binding_count": runtime_binding_counts.get("bound", 0),
        "runtime_obligation_counts": dict(sorted(runtime_obligation_counts.items())),
        "runtime_obligations_sample": runtime_obligations[:50],
        "api_adapters": {
            "status": "complete" if not api_adapter_plan["unmatched"] else "incomplete",
            "external_calls": api_adapter_plan["external_call_count"],
            "bound_calls": len(api_adapter_plan["bindings"]),
            "unmatched_calls": len(api_adapter_plan["unmatched"]),
            "generated_import_adapters": len(api_adapter_plan["signatures"]),
        },
        "strict_candidate": {
            "status": "ready" if not strict_candidate_blockers else "incomplete",
            "blockers": strict_candidate_blockers,
        },
        "reason_counts": dict(sorted(reason_counts.items())),
        "generated_transfers": [
            {
                "id": row.get("id"),
                "function": row.get("function"),
                "symbol": symbol,
                "contract_sha256": _row_contract_sha256(row),
                "rva_start": _row_rva(row),
            }
            for row, symbol, _rendered in supported
        ],
        "unsupported": unsupported[:200],
        "dispatch": {
            "status": "complete" if inventory_complete and not duplicate_rvas else "incomplete",
            "entries": len(all_rows),
            "duplicate_rvas": duplicate_rvas,
            "lookup_policy": "fail_closed_on_missing_or_ambiguous_rva",
        },
        "artifacts": {
            "header": implementation_artifacts["runtime_header"],
            "transfers_header": implementation_artifacts["transfers_header"],
            "source": implementation_artifacts["generated_source"],
            "repairs": implementation_artifacts["repair_source"],
            "dispatch_header": implementation_artifacts["dispatch_header"],
            "dispatch_source": implementation_artifacts["dispatch_source"],
            "engine_header": implementation_artifacts["engine_header"],
            "engine_source": implementation_artifacts["engine_source"],
            "api_adapters_header": implementation_artifacts["api_adapters_header"],
            "api_adapters_source": implementation_artifacts["api_adapters_source"],
            "api_adapters_report": implementation_artifacts["api_adapters_report"],
            "source_map": implementation_artifacts["source_map"],
            "runtime_obligations": implementation_artifacts["runtime_obligations"],
            "implementation_manifest": {
                "path": implementation_manifest_path.name,
                "sha256": sha256_file(implementation_manifest_path),
            },
        },
        "constraints": {
            "original_instruction_bytes_embedded": False,
            "original_runtime_execution_required": False,
            "generation_authority": "stage-a-semantic-transfer-contracts",
            "manual_repairs_must_preserve_transfer_bindings": True,
            "external_events_supported": "through_explicit_runtime_protocol_contract",
            "x87_supported": False,
            "x87_semantics": "checked_replay_interpreter_required",
            "x87_exactness": "no host floating-point lowering is generated",
            "x87_missing_metadata_policy": "fail_closed_per_transfer",
            "native_call_boundary_state": (
                "full_machine_state_including_x87_physical_state; handler output "
                "becomes the post-call state"
            ),
            "terminal_control_api": "stage_b_run_function_result",
            "mixed_memory_read_write_supported": "requires_complete_ordered_events",
        },
    }
    if not inventory_complete:
        report["reason_counts"]["missing_transfer_inventory"] = 1
    if duplicate_rvas:
        report["status"] = "incomplete"
    write_json(report_path, report)
    report["report"] = {"path": report_path.name, "sha256": sha256_file(report_path)}
    return report


def stage_b_generate_semantic_c_from_state_machine(
    *,
    state_machine: Path,
    out_dir: Path,
    machine_call_catalog: Path | None = None,
) -> dict[str, Any]:
    """Regenerate the semantic-C work package from a canonical Stage B state machine."""

    state_machine = Path(state_machine)
    source_rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for line_number, line in enumerate(state_machine.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid state-machine JSON on line {line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"state-machine line {line_number} must be a JSON object")
        if row.get("stage_b_format") != STAGE_B_STATE_MACHINE_FORMAT:
            raise ValueError(
                f"state-machine line {line_number} must have stage_b_format {STAGE_B_STATE_MACHINE_FORMAT}"
            )
        normalized = normalize_stage_a_semantic_transfer(row)
        if row.get("contract_sha256") != normalized["contract_sha256"]:
            raise ValueError(f"state-machine line {line_number} contract_sha256 does not match its transfer payload")
        identity = str(normalized.get("id") or "")
        if not identity:
            raise ValueError(f"state-machine line {line_number} is missing a transfer id")
        if identity in seen_ids:
            raise ValueError(f"state-machine contains duplicate transfer id {identity!r}")
        seen_ids.add(identity)
        source_rows.append(normalized)

    rows = normalize_stage_a_semantic_transfers(source_rows)
    binding = {"path": state_machine.name, "sha256": sha256_file(state_machine)}
    catalog = load_machine_call_catalog(machine_call_catalog) if machine_call_catalog is not None else None
    return write_stage_b_semantic_c_backend(
        Path(out_dir),
        rows,
        state_machine_binding=binding,
        machine_call_catalog=catalog,
    )


def _row_blockers(row: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if row.get("status") != "reimplementable":
        blockers.append("incomplete_transfer")
    if row.get("expression_model") != SEMANTIC_IR_FORMAT:
        blockers.append("unsupported_expression_model")
    fpu_state = row.get("fpu_state")
    if fpu_state is not None:
        blockers.extend(("x87_state", "x87_checked_replay_required"))
    memory_events = row.get("memory_events") if isinstance(row.get("memory_events"), list) else []
    reads = any(isinstance(event, dict) and event.get("kind") == "read" for event in memory_events)
    writes = any(isinstance(event, dict) and event.get("kind") == "write" for event in memory_events)
    ordered_events = row.get("ordered_events") if isinstance(row.get("ordered_events"), list) else []
    ordered_memory = [event for event in ordered_events if isinstance(event, dict) and event.get("family") == "memory"]
    ordered_faults = [event for event in ordered_events if isinstance(event, dict) and event.get("family") == "fault"]
    ordered_external = [event for event in ordered_events if isinstance(event, dict) and event.get("family") == "external"]
    faults = row.get("faults") if isinstance(row.get("faults"), list) else []
    external_events = row.get("external_events") if isinstance(row.get("external_events"), list) else []
    if fpu_state is not None and any(
        isinstance(event, dict) and event.get("kind") in _CALL_EVENT_KINDS
        for event in external_events
    ):
        blockers.append("call_event_x87_post_state_order_missing")
    complete_order = (
        len(ordered_memory) == len(memory_events)
        and len(ordered_faults) == len(faults)
        and len(ordered_external) == len(external_events)
    )
    if (reads and writes or faults and memory_events) and not complete_order:
        blockers.append("mixed_memory_event_order")
    if external_events and not complete_order:
        blockers.append("external_event_order")
    if complete_order and not _ordered_event_projection_matches(
        ordered_memory=ordered_memory,
        memory_events=memory_events,
        ordered_faults=ordered_faults,
        faults=faults,
        ordered_external=ordered_external,
        external_events=external_events,
    ):
        blockers.append("ordered_event_projection_mismatch")
    for event_index, event in enumerate(external_events):
        if not isinstance(event, dict) or event.get("kind") not in _SUPPORTED_EVENT_KINDS:
            blockers.append(f"unsupported_external_event:{event.get('kind') if isinstance(event, dict) else 'invalid'}")
            continue
        if event.get("kind") == "rep_scas" and not _valid_rep_scas_event(
            event,
            event_index,
            require_instruction_rva=False,
        ):
            blockers.append("malformed_rep_scas_event")
        if event.get("kind") in _CALL_EVENT_KINDS:
            register_inputs = event.get("register_inputs")
            flag_inputs = event.get("flag_inputs")
            if not isinstance(register_inputs, dict) or not all(name in register_inputs for name in _REGISTER_NAMES):
                blockers.append("external_event_register_inputs")
            if not isinstance(flag_inputs, dict) or not all(name in flag_inputs for name in _FLAG_NAMES):
                blockers.append("external_event_flag_inputs")
            if not isinstance(event.get("return_rva"), int):
                blockers.append("external_event_return_rva")
            stack_inputs = event.get("stack_inputs")
            if not isinstance(stack_inputs, list) or any(
                not isinstance(item, dict)
                or not isinstance(item.get("offset"), int)
                or not isinstance(item.get("width"), int)
                or "value" not in item
                for item in stack_inputs if isinstance(stack_inputs, list)
            ):
                blockers.append("external_event_stack_inputs")
            if event.get("kind") == "external_call" and _external_event_identity(event) is None:
                blockers.append("external_event_import_identity")
            if event.get("kind") == "internal_call" and not isinstance(event.get("target_rva"), int):
                blockers.append("internal_call_target_rva")
            if event.get("kind") == "indirect_call" and not isinstance(event.get("target"), dict):
                blockers.append("indirect_call_target_expression")
    for event_index, event in enumerate(ordered_external):
        if event.get("kind") == "rep_scas" and not _valid_rep_scas_event(
            event,
            event_index,
            require_instruction_rva=True,
        ):
            blockers.append("malformed_rep_scas_event")
    outcome = row.get("outcome") if isinstance(row.get("outcome"), dict) else {}
    if outcome.get("kind") not in _SUPPORTED_OUTCOMES:
        blockers.append("unsupported_outcome")
    elif outcome.get("kind") == "external_jump":
        blockers.append("external_jump_target_materialization_missing")
    expression_ops = _row_expression_ops(row)
    unsupported_ops = sorted(expression_ops - _SUPPORTED_OPS)
    blockers.extend(f"unsupported_expression:{op}" for op in unsupported_ops)
    return sorted(set(blockers))


def _valid_rep_scas_event(
    event: dict[str, Any],
    event_index: int,
    *,
    require_instruction_rva: bool,
) -> bool:
    def is_u32(value: Any) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value < 2**32
        )

    return (
        event.get("index") == event_index
        and not isinstance(event.get("index"), bool)
        and event.get("element_width") == 1
        and not isinstance(event.get("element_width"), bool)
        and event.get("address_size") == 32
        and not isinstance(event.get("address_size"), bool)
        and event.get("repeat_condition") == "while_not_equal_v1"
        and event.get("comparison_model") == "subtraction_flags_v1"
        and event.get("segment_model") == "flat_es_zero_v1"
        and event.get("effect_model") == "symbolic_string_scan_v1"
        and event.get("restart_semantics") == "element_committed_v1"
        and event.get("fault_model") == "read_before_commit_v1"
        and event.get("owned_register_outputs") == list(_REP_SCAS_OWNED_REGISTERS)
        and event.get("owned_flag_outputs") == list(_REP_SCAS_OWNED_FLAGS)
        and all(
            isinstance(event.get(field), dict)
            for field in ("destination", "accumulator", "count", "direction_flag")
        )
        and "source" not in event
        and "value" not in event
        and (
            not require_instruction_rva
            or is_u32(event.get("instruction_rva"))
        )
    )


def _ordered_event_projection_matches(
    *,
    ordered_memory: list[dict[str, Any]],
    memory_events: list[dict[str, Any]],
    ordered_faults: list[dict[str, Any]],
    faults: list[dict[str, Any]],
    ordered_external: list[dict[str, Any]],
    external_events: list[dict[str, Any]],
) -> bool:
    def project(event: dict[str, Any], *, keep_instruction_rva: bool) -> dict[str, Any]:
        result = dict(event)
        result.pop("family", None)
        if not keep_instruction_rva:
            result.pop("instruction_rva", None)
        return result

    return (
        [project(event, keep_instruction_rva=False) for event in ordered_memory] == memory_events
        and [project(event, keep_instruction_rva=True) for event in ordered_faults] == faults
        and [project(event, keep_instruction_rva=False) for event in ordered_external] == external_events
    )


def _row_expression_ops(row: dict[str, Any]) -> set[str]:
    result: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            op = value.get("op")
            if isinstance(op, str):
                result.add(op)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    for key in (
        "register_writes",
        "flag_writes",
        "memory_events",
        "faults",
        "ordered_events",
        "fpu_state",
        "outcome",
    ):
        visit(row.get(key))
    return result


def _row_reference(row: dict[str, Any], reasons: list[str]) -> dict[str, Any]:
    original = row.get("original") if isinstance(row.get("original"), dict) else {}
    return {
        "id": row.get("id"),
        "function": row.get("function"),
        "block_id": row.get("block_id"),
        "rva_start": original.get("rva_start"),
        "reasons": reasons,
    }


def _api_adapter_plan(
    rows: list[dict[str, Any]],
    catalog: MachineCallCatalog | None,
) -> dict[str, Any]:
    signatures = catalog.by_identity() if catalog is not None else {}
    bindings: dict[tuple[str, int], MachineCallSignature] = {}
    selected: dict[tuple[str, str, str | int], MachineCallSignature] = {}
    unmatched: list[dict[str, Any]] = []
    external_call_count = 0
    for row in rows:
        row_id = str(row.get("id") or "")
        events = row.get("external_events") if isinstance(row.get("external_events"), list) else []
        for event_index, event in enumerate(events):
            if not isinstance(event, dict) or event.get("kind") != "external_call":
                continue
            external_call_count += 1
            identity = _external_event_identity(event)
            signature = signatures.get(identity) if identity is not None else None
            reasons = _api_adapter_blockers(event, signature, catalog_present=catalog is not None)
            if reasons:
                unmatched.append(
                    {
                        "transfer_id": row.get("id"),
                        "contract_sha256": _row_contract_sha256(row),
                        "rva_start": _row_rva(row),
                        "event_index": event_index,
                        "identity": {
                            "dll": event.get("dll"),
                            "symbol": event.get("symbol"),
                            "ordinal": event.get("ordinal"),
                        },
                        "reasons": reasons,
                        "next_action": _api_adapter_next_action(reasons),
                    }
                )
                continue
            assert signature is not None
            bindings[(row_id, event_index)] = signature
            selected[signature.identity] = signature
    return {
        "bindings": bindings,
        "signatures": [selected[key] for key in sorted(selected)],
        "unmatched": unmatched,
        "external_call_count": external_call_count,
    }


def _external_event_identity(event: dict[str, Any]) -> tuple[str, str, str | int] | None:
    dll = event.get("dll")
    symbol = event.get("symbol")
    ordinal = event.get("ordinal")
    if not isinstance(dll, str) or not dll:
        return None
    if isinstance(symbol, str) and symbol and ordinal is None:
        return (dll.lower(), "symbol", symbol)
    if isinstance(ordinal, int) and not isinstance(ordinal, bool) and symbol is None:
        return (dll.lower(), "ordinal", ordinal)
    return None


def _api_adapter_blockers(
    event: dict[str, Any],
    signature: MachineCallSignature | None,
    *,
    catalog_present: bool,
) -> list[str]:
    if not catalog_present:
        return ["missing_machine_call_catalog"]
    if signature is None:
        return ["missing_machine_call_signature"]
    blockers: list[str] = []
    if signature.symbol is None:
        blockers.append("ordinal_import_adapter_not_implemented")
    if signature.calling_convention is None:
        blockers.append("ambiguous_calling_convention")
    expected_offsets = tuple(range(0, len(signature.stack_argument_offsets) * 4, 4))
    if signature.stack_argument_offsets != expected_offsets:
        blockers.append("noncontiguous_stack_arguments")
    if len(signature.stack_argument_offsets) > 32:
        blockers.append("excessive_argument_count")
    if signature.world_effect == "callbackRegistration":
        blockers.append("callback_target_adapter_required")
    if not isinstance(event.get("return_rva"), int):
        blockers.append("missing_call_return_rva")
    return sorted(blockers)


def _api_adapter_next_action(reasons: list[str]) -> str:
    if "missing_machine_call_catalog" in reasons:
        return "provide the checked Stage A relation contract or a reviewed machine-call catalog"
    if "missing_machine_call_signature" in reasons:
        return "add a reviewed machine-level signature for this exact DLL and symbol or ordinal"
    if "ambiguous_calling_convention" in reasons:
        return "declare cdecl or stdcall explicitly for this zero-argument or otherwise ambiguous import"
    if "callback_target_adapter_required" in reasons:
        return "generate a checked callback thunk and nested external/internal frame binding"
    return "repair the machine-call signature or call boundary until direct adapter generation is unambiguous"


def _runtime_call_obligations(
    rows: list[dict[str, Any]],
    *,
    api_bindings: dict[tuple[str, int], MachineCallSignature] | None = None,
) -> list[dict[str, Any]]:
    obligations: list[dict[str, Any]] = []
    api_bindings = api_bindings or {}
    dispatch_counts = Counter(_row_rva(row) for row in rows)
    for row in rows:
        external_events = row.get("external_events") if isinstance(row.get("external_events"), list) else []
        ordered_external = [
            event
            for event in (row.get("ordered_events") if isinstance(row.get("ordered_events"), list) else [])
            if isinstance(event, dict) and event.get("family") == "external"
        ]
        for event_index, event in enumerate(external_events):
            if not isinstance(event, dict) or event.get("kind") not in _CALL_EVENT_KINDS:
                continue
            ordered = ordered_external[event_index] if event_index < len(ordered_external) else {}
            kind = str(event.get("kind"))
            reference: dict[str, Any] = {
                "id": f"runtime-call:{row.get('id')}:{event_index}",
                "status": "unbound",
                "transfer_id": row.get("id"),
                "contract_sha256": _row_contract_sha256(row),
                "rva_start": _row_rva(row),
                "instruction_rva": ordered.get("instruction_rva"),
                "event_index": event_index,
                "kind": kind,
            }
            if kind == "external_call":
                reference["identity"] = {
                    "dll": event.get("dll"),
                    "symbol": event.get("symbol"),
                    "ordinal": event.get("ordinal"),
                }
                signature = api_bindings.get((str(row.get("id") or ""), event_index))
                if signature is not None:
                    reference["status"] = "bound"
                    reference["binding"] = "generated_machine_call_adapter_v1"
                    reference["machine_call_signature"] = signature.as_json()
                    reference["next_action"] = "compile and validate the generated exact import adapter"
                else:
                    reference["next_action"] = (
                        "bind an exact machine-level import adapter for this canonical external event"
                    )
            elif kind == "internal_call":
                target_rva = event.get("target_rva")
                reference["target_rva"] = target_rva
                if isinstance(target_rva, int) and dispatch_counts[target_rva] == 1:
                    reference["status"] = "bound"
                    reference["binding"] = "generated_nested_frame_engine_v1"
                    reference["next_action"] = "compile and validate the generated nested-frame dispatcher"
                else:
                    reference["next_action"] = (
                        "provide an unambiguous generated transfer entry for the direct internal target"
                    )
            else:
                reference["target"] = event.get("target")
                reference["next_action"] = (
                    "bind checked indirect-target resolution and nested-frame dispatch"
                )
            obligations.append(reference)
    return obligations


def _generated_implementation_kind(row: dict[str, Any]) -> str:
    events = row.get("external_events") if isinstance(row.get("external_events"), list) else []
    if any(isinstance(event, dict) and event.get("kind") in _CALL_EVENT_KINDS for event in events):
        return "generated_semantic_c_runtime_contract"
    return "generated_semantic_c"


def _strict_candidate_blockers(
    *,
    inventory_complete: bool,
    repair_stub_count: int,
    runtime_obligations: list[dict[str, Any]],
    duplicate_rvas: list[dict[str, Any]],
) -> list[str]:
    blockers: list[str] = []
    if not inventory_complete:
        blockers.append("missing_transfer_inventory")
    if repair_stub_count:
        blockers.append("repair_stubs_remaining")
    if runtime_obligations:
        blockers.append("runtime_call_adapters_unbound")
    if duplicate_rvas:
        blockers.append("ambiguous_dispatch_rvas")
    return blockers


def _unique_transfer_symbol(row: dict[str, Any], used: set[str]) -> str:
    identity = str(row.get("id") or row.get("block_id") or "transfer")
    stem = re.sub(r"[^A-Za-z0-9_]", "_", identity).strip("_") or "transfer"
    stem = f"stage_b_transfer_{stem}"
    symbol = stem
    suffix = 2
    while symbol in used:
        symbol = f"{stem}_{suffix}"
        suffix += 1
    used.add(symbol)
    return symbol


def _runtime_header() -> str:
    return """#ifndef STAGE_B_STATE_MACHINE_RUNTIME_H
#define STAGE_B_STATE_MACHINE_RUNTIME_H

#define STAGE_B_MACHINE_STATE_HAS_EFLAGS 1

#include <stdint.h>

typedef struct stage_b_x87_value {
  uint8_t value_bytes[10];
  uint32_t empty;
  uint8_t tag;
} stage_b_x87_value;

typedef struct stage_b_machine_state {
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
  uint32_t cf, zf, sf, of, pf, df;
  stage_b_x87_value x87_stack[8];
  uint16_t x87_control;
  uint16_t x87_status;
  uint8_t x87_pending_exception;
  uint16_t x87_last_opcode;
  uint32_t x87_instruction_pointer;
  uint16_t x87_code_selector;
  uint32_t x87_data_pointer;
  uint16_t x87_data_selector;
  uint32_t eflags;
  uint32_t fs_base;
  uint32_t original_rva;
} stage_b_machine_state;

_Static_assert(sizeof(((stage_b_x87_value *)0)->value_bytes) == 10U,
    "x87 payload must be exactly 80 bits");
_Static_assert(sizeof(((stage_b_x87_value *)0)->empty) == 4U,
    "x87 occupancy must match EngineField.x87Empty");
_Static_assert(sizeof(((stage_b_x87_value *)0)->tag) == 1U,
    "x87 tag must match EngineField.x87Tag");

typedef struct stage_b_stack_input {
  uint32_t offset;
  uint32_t width;
  uint32_t value;
} stage_b_stack_input;

typedef enum stage_b_call_event_kind {
  STAGE_B_CALL_EXTERNAL_IMPORT = 0,
  STAGE_B_CALL_INTERNAL_DIRECT = 1,
  STAGE_B_CALL_INDIRECT = 2
} stage_b_call_event_kind;

typedef struct stage_b_call_event {
  stage_b_call_event_kind kind;
  uint32_t instruction_rva;
  uint32_t call_index;
  uint32_t target_rva;
  uint32_t return_rva;
  const char *dll;
  const char *symbol;
  uint32_t ordinal;
  uint32_t has_ordinal;
  const uint32_t *arguments;
  uint32_t argument_count;
  const stage_b_stack_input *stack_inputs;
  uint32_t stack_input_count;
} stage_b_call_event;

typedef struct stage_b_runtime stage_b_runtime;

typedef enum stage_b_call_status {
  STAGE_B_CALL_OK = 0,
  STAGE_B_CALL_UNIMPLEMENTED = 1,
  STAGE_B_CALL_DIVIDE_ERROR = 2,
  STAGE_B_CALL_MEMORY_FAULT = 3,
  STAGE_B_CALL_EXTERNAL_FAULT = 4
} stage_b_call_status;

typedef stage_b_call_status (*stage_b_external_call_handler)(
    stage_b_runtime *runtime,
    const stage_b_call_event *event,
    const stage_b_machine_state *input,
    stage_b_machine_state *output);

typedef void (*stage_b_atomic_compare_exchange_handler)(
    void *context,
    uint32_t address,
    uint32_t width,
    uint32_t expected,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *exchanged,
    uint32_t *fault);

typedef void (*stage_b_atomic_exchange_handler)(
    void *context,
    uint32_t address,
    uint32_t width,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *fault);

typedef uint32_t (*stage_b_code_target_resolver)(
    stage_b_runtime *runtime,
    uint32_t target_word,
    uint32_t *target_rva);

typedef stage_b_call_status (*stage_b_callable_external_jump_handler)(
    stage_b_runtime *runtime,
    uint32_t source_rva,
    uint32_t target_word,
    const stage_b_machine_state *input,
    stage_b_machine_state *output);

struct stage_b_runtime {
  void *context;
  uint32_t (*read)(void *context, uint32_t address, uint32_t width, uint32_t *fault);
  void (*write)(void *context, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault);
  stage_b_atomic_compare_exchange_handler atomic_compare_exchange;
  stage_b_atomic_exchange_handler atomic_exchange;
  uint32_t (*undefined_value)(
      void *context, uint32_t slot, const stage_b_machine_state *input,
      uint32_t defined_value);
  stage_b_external_call_handler external_call_fallback;
  stage_b_code_target_resolver resolve_code_target;
  stage_b_callable_external_jump_handler invoke_callable_external_jump;
};

void stage_b_runtime_atomic_compare_exchange(
    stage_b_runtime *runtime,
    uint32_t address,
    uint32_t width,
    uint32_t expected,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *exchanged,
    uint32_t *fault);

void stage_b_runtime_atomic_exchange(
    stage_b_runtime *runtime,
    uint32_t address,
    uint32_t width,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *fault);

stage_b_call_status stage_b_invoke_call(
    stage_b_runtime *runtime,
    const stage_b_call_event *event,
    const stage_b_machine_state *input,
    stage_b_machine_state *output);

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime,
    const stage_b_call_event *event,
    const stage_b_machine_state *input,
    stage_b_machine_state *output);

typedef enum stage_b_control_kind {
  STAGE_B_FALLTHROUGH = 0,
  STAGE_B_JUMP = 1,
  STAGE_B_BRANCH = 2,
  STAGE_B_RETURN = 3,
  STAGE_B_INDIRECT_JUMP = 4,
  STAGE_B_DIVIDE_ERROR = 5,
  STAGE_B_MEMORY_FAULT = 6,
  STAGE_B_UNIMPLEMENTED = 7,
  STAGE_B_EXTERNAL_FAULT = 8,
  STAGE_B_EXTERNAL_JUMP = 9
} stage_b_control_kind;

typedef struct stage_b_step_result {
  stage_b_control_kind kind;
  uint32_t target_rva;
  uint32_t value;
} stage_b_step_result;

#endif
"""


def _transfers_header(rows: list[tuple[dict[str, Any], str, bool, list[str]]]) -> str:
    declarations = [
        f"stage_b_step_result {symbol}(stage_b_runtime *rt, stage_b_machine_state *state);"
        for _row, symbol, _generated, _reasons in rows
    ]
    return "\n".join([
        "#ifndef STAGE_B_STATE_MACHINE_TRANSFERS_H",
        "#define STAGE_B_STATE_MACHINE_TRANSFERS_H",
        "",
        '#include "state-machine-runtime.h"',
        "",
        *declarations,
        "",
        "#endif",
        "",
    ])


def _render_source(rows: list[tuple[dict[str, Any], str, str]]) -> tuple[str, dict[str, tuple[int, int]]]:
    lines = [
        '#include "state-machine-transfers.h"',
        "",
        *_runtime_helpers().splitlines(),
    ]
    spans: dict[str, tuple[int, int]] = {}
    for _row, symbol, rendered in rows:
        lines.append("")
        start = len(lines) + 1
        lines.extend(rendered.splitlines())
        spans[symbol] = (start, len(lines))
    return "\n".join(lines).rstrip() + "\n", spans


def _render_repairs_source(
    rows: list[tuple[dict[str, Any], str, list[str]]],
) -> tuple[str, dict[str, tuple[int, int]]]:
    lines = [
        '#include "state-machine-transfers.h"',
        "",
        "/* Replace only the marked transition bodies, preserving their symbols and contract bindings. */",
    ]
    spans: dict[str, tuple[int, int]] = {}
    for row, symbol, reasons in rows:
        lines.append("")
        start = len(lines) + 1
        identity = _c_comment(str(row.get("id") or row.get("block_id") or symbol))
        reason_text = _c_comment(", ".join(reasons))
        lines.extend(
            [
                f"/* Stage B repair required: {identity}; blockers: {reason_text}. */",
                f"stage_b_step_result {symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
                "  (void)rt;",
                "  (void)state;",
                "  return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, 0U, 0U };",
                "}",
            ]
        )
        spans[symbol] = (start, len(lines))
    return "\n".join(lines).rstrip() + "\n", spans


def _dispatch_header() -> str:
    return """#ifndef STAGE_B_STATE_MACHINE_DISPATCH_H
#define STAGE_B_STATE_MACHINE_DISPATCH_H

#include <stdint.h>
#include "state-machine-transfers.h"

typedef stage_b_step_result (*stage_b_transfer_function)(stage_b_runtime *, stage_b_machine_state *);

typedef struct stage_b_transfer_descriptor {
  uint32_t source_rva;
  const char *contract_id;
  const char *contract_sha256;
  stage_b_transfer_function step;
  uint32_t generated_from_semantics;
} stage_b_transfer_descriptor;

extern const stage_b_transfer_descriptor stage_b_transfer_table[];
extern const uint32_t stage_b_transfer_count;

const stage_b_transfer_descriptor *stage_b_lookup_transfer(uint32_t source_rva);
stage_b_step_result stage_b_step_by_rva(
    stage_b_runtime *rt,
    stage_b_machine_state *state,
    uint32_t source_rva);

#endif
"""


def _dispatch_source(rows: list[tuple[dict[str, Any], str, bool, list[str]]]) -> str:
    entries = [
        "  { "
        f"{_row_rva(row)}U, {_c_string(str(row.get('id') or ''))}, "
        f"{_c_string(_row_contract_sha256(row))}, {symbol}, {1 if generated else 0}U "
        "},"
        for row, symbol, generated, _reasons in rows
    ]
    if not entries:
        entries = ['  { 0U, "", "", 0, 0U },']
    return "\n".join(
        [
            '#include "state-machine-dispatch.h"',
            "",
            "const stage_b_transfer_descriptor stage_b_transfer_table[] = {",
            *entries,
            "};",
            f"const uint32_t stage_b_transfer_count = {len(rows)}U;",
            "",
            "const stage_b_transfer_descriptor *stage_b_lookup_transfer(uint32_t source_rva) {",
            "  const stage_b_transfer_descriptor *match = 0;",
            "  uint32_t index;",
            "  for (index = 0U; index < stage_b_transfer_count; ++index) {",
            "    if (stage_b_transfer_table[index].source_rva != source_rva) continue;",
            "    if (match != 0) return 0;",
            "    match = &stage_b_transfer_table[index];",
            "  }",
            "  return match;",
            "}",
            "",
            "stage_b_step_result stage_b_step_by_rva(",
            "    stage_b_runtime *rt,",
            "    stage_b_machine_state *state,",
            "    uint32_t source_rva) {",
            "  const stage_b_transfer_descriptor *entry = stage_b_lookup_transfer(source_rva);",
            "  if (entry == 0 || entry->step == 0)",
            "    return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, source_rva, 0U };",
            "  state->original_rva = source_rva;",
            "  return entry->step(rt, state);",
            "}",
            "",
        ]
    )


def _engine_header() -> str:
    return """#ifndef STAGE_B_STATE_MACHINE_ENGINE_H
#define STAGE_B_STATE_MACHINE_ENGINE_H

#include "state-machine-dispatch.h"

typedef struct stage_b_engine_result {
  stage_b_call_status status;
  stage_b_step_result control;
} stage_b_engine_result;

stage_b_engine_result stage_b_run_function_result(
    stage_b_runtime *runtime,
    uint32_t entry_rva,
    const stage_b_machine_state *input,
    stage_b_machine_state *output);

stage_b_call_status stage_b_run_function(
    stage_b_runtime *runtime,
    uint32_t entry_rva,
    const stage_b_machine_state *input,
    stage_b_machine_state *output);

#endif
"""


def _engine_source() -> str:
    return """#include "state-machine-engine.h"

static stage_b_call_status stage_b_resolve_code_target(
    stage_b_runtime *runtime,
    uint32_t target_word,
    uint32_t *target_rva) {
  if (runtime == 0 || runtime->resolve_code_target == 0)
    return STAGE_B_CALL_UNIMPLEMENTED;
  if (runtime->resolve_code_target(runtime, target_word, target_rva) != 0U)
    return STAGE_B_CALL_UNIMPLEMENTED;
  return STAGE_B_CALL_OK;
}

static stage_b_engine_result stage_b_engine_result_make(
    stage_b_call_status status,
    stage_b_step_result control) {
  stage_b_engine_result result;
  result.status = status;
  result.control = control;
  return result;
}

stage_b_engine_result stage_b_run_function_result(
    stage_b_runtime *runtime,
    uint32_t entry_rva,
    const stage_b_machine_state *input,
    stage_b_machine_state *output) {
  stage_b_machine_state state;
  uint32_t current_rva;
  if (input == 0 || output == 0)
    return stage_b_engine_result_make(
        STAGE_B_CALL_UNIMPLEMENTED,
        (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, entry_rva, 0U });
  state = *input;
  current_rva = entry_rva;
  for (;;) {
    stage_b_step_result result = stage_b_step_by_rva(runtime, &state, current_rva);
    switch (result.kind) {
      case STAGE_B_FALLTHROUGH:
      case STAGE_B_JUMP:
      case STAGE_B_BRANCH:
        current_rva = result.target_rva;
        break;
      case STAGE_B_INDIRECT_JUMP: {
        stage_b_call_status status = stage_b_resolve_code_target(runtime, result.value, &current_rva);
        if (status != STAGE_B_CALL_OK && runtime != 0 &&
            runtime->invoke_callable_external_jump != 0) {
          stage_b_machine_state external_output = state;
          status = runtime->invoke_callable_external_jump(
              runtime, current_rva, result.value, &state, &external_output);
          if (status == STAGE_B_CALL_OK) {
            *output = external_output;
            return stage_b_engine_result_make(
                STAGE_B_CALL_OK,
                (stage_b_step_result){ STAGE_B_EXTERNAL_JUMP, current_rva,
                                       result.value });
          }
        }
        if (status != STAGE_B_CALL_OK)
          return stage_b_engine_result_make(status, result);
        break;
      }
      case STAGE_B_RETURN:
      case STAGE_B_EXTERNAL_JUMP:
        *output = state;
        return stage_b_engine_result_make(STAGE_B_CALL_OK, result);
      case STAGE_B_DIVIDE_ERROR:
        return stage_b_engine_result_make(STAGE_B_CALL_DIVIDE_ERROR, result);
      case STAGE_B_MEMORY_FAULT:
        return stage_b_engine_result_make(STAGE_B_CALL_MEMORY_FAULT, result);
      case STAGE_B_EXTERNAL_FAULT:
        return stage_b_engine_result_make(STAGE_B_CALL_EXTERNAL_FAULT, result);
      case STAGE_B_UNIMPLEMENTED:
      default:
        return stage_b_engine_result_make(STAGE_B_CALL_UNIMPLEMENTED, result);
    }
  }
}

stage_b_call_status stage_b_run_function(
    stage_b_runtime *runtime,
    uint32_t entry_rva,
    const stage_b_machine_state *input,
    stage_b_machine_state *output) {
  return stage_b_run_function_result(
      runtime, entry_rva, input, output).status;
}

stage_b_call_status stage_b_invoke_call(
    stage_b_runtime *runtime,
    const stage_b_call_event *event,
    const stage_b_machine_state *input,
    stage_b_machine_state *output) {
  uint32_t target_rva;
  if (event == 0) return STAGE_B_CALL_UNIMPLEMENTED;
  switch (event->kind) {
    case STAGE_B_CALL_INTERNAL_DIRECT:
      return stage_b_run_function(runtime, event->target_rva, input, output);
    case STAGE_B_CALL_INDIRECT: {
      stage_b_call_status status = stage_b_resolve_code_target(
          runtime, event->target_rva, &target_rva);
      if (status == STAGE_B_CALL_OK)
        return stage_b_run_function(runtime, target_rva, input, output);
      return stage_b_dispatch_external_call(runtime, event, input, output);
    }
    case STAGE_B_CALL_EXTERNAL_IMPORT:
      return stage_b_dispatch_external_call(runtime, event, input, output);
    default:
      return STAGE_B_CALL_UNIMPLEMENTED;
  }
}
"""


def _api_adapters_header() -> str:
    return """#ifndef STAGE_B_STATE_MACHINE_API_ADAPTERS_H
#define STAGE_B_STATE_MACHINE_API_ADAPTERS_H

#include "state-machine-runtime.h"

stage_b_call_status stage_b_dispatch_external_call(
    stage_b_runtime *runtime,
    const stage_b_call_event *event,
    const stage_b_machine_state *input,
    stage_b_machine_state *output);

#endif
"""


def _api_adapters_source(signatures: list[MachineCallSignature]) -> str:
    lines = [
        '#include "state-machine-api-adapters.h"',
        "",
        "static uint32_t stage_b_api_undefined(stage_b_runtime *runtime, uint32_t slot, const stage_b_machine_state *input, uint32_t defined_value) {",
        "  return runtime != 0 && runtime->undefined_value != 0",
        "      ? runtime->undefined_value(runtime->context, slot, input, defined_value) : slot;",
        "}",
        "",
        "static uint32_t stage_b_api_read_word(",
        "    stage_b_runtime *runtime, uint32_t address, uint32_t *value) {",
        "  uint32_t fault = 0U;",
        "  if (runtime == 0 || runtime->read == 0 || value == 0) return 1U;",
        "  *value = runtime->read(runtime->context, address, 4U, &fault);",
        "  return fault;",
        "}",
        "",
        "static uint32_t stage_b_api_ascii_lower(uint32_t value) {",
        "  return value >= (uint32_t)'A' && value <= (uint32_t)'Z' ? value + 32U : value;",
        "}",
        "",
        "static uint32_t stage_b_api_string_equal(const char *left, const char *right, uint32_t fold_case) {",
        "  if (left == 0 || right == 0) return left == right;",
        "  while (*left != '\\0' && *right != '\\0') {",
        "    uint32_t l = (uint32_t)(unsigned char)*left++;",
        "    uint32_t r = (uint32_t)(unsigned char)*right++;",
        "    if (fold_case) { l = stage_b_api_ascii_lower(l); r = stage_b_api_ascii_lower(r); }",
        "    if (l != r) return 0U;",
        "  }",
        "  return *left == *right;",
        "}",
    ]
    for index, signature in enumerate(signatures):
        assert signature.symbol is not None
        arguments = ", ".join("uint32_t" for _ in signature.stack_argument_offsets) or "void"
        lines.extend(
            [
                "",
                f"extern uint32_t __attribute__(({signature.calling_convention}, dllimport))",
                f"    stage_b_import_{index}({arguments}) __asm__({_c_string(signature.symbol)});",
            ]
        )
    for index, signature in enumerate(signatures):
        lines.extend(["", *_render_api_adapter(index, signature)])
    lines.extend(
        [
            "",
            "stage_b_call_status stage_b_dispatch_external_call(",
            "    stage_b_runtime *runtime,",
            "    const stage_b_call_event *event,",
            "    const stage_b_machine_state *input,",
            "    stage_b_machine_state *output) {",
            "  if (event == 0) return STAGE_B_CALL_UNIMPLEMENTED;",
        ]
    )
    for index, signature in enumerate(signatures):
        assert signature.symbol is not None
        lines.extend(
            [
                "  if (stage_b_api_string_equal(event->dll, "
                f"{_c_string(signature.dll)}, 1U) &&",
                "      stage_b_api_string_equal(event->symbol, "
                f"{_c_string(signature.symbol)}, 0U) && !event->has_ordinal)",
                f"    return stage_b_api_adapter_{index}(runtime, input, output);",
            ]
        )
    lines.extend(
        [
            "  if (runtime != 0 && runtime->external_call_fallback != 0)",
            "    return runtime->external_call_fallback(runtime, event, input, output);",
            "  return STAGE_B_CALL_UNIMPLEMENTED;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _render_api_adapter(index: int, signature: MachineCallSignature) -> list[str]:
    lines = [
        f"static stage_b_call_status stage_b_api_adapter_{index}(",
        "    stage_b_runtime *runtime,",
        "    const stage_b_machine_state *input,",
        "    stage_b_machine_state *output) {",
        "  if (input == 0 || output == 0) return STAGE_B_CALL_UNIMPLEMENTED;",
    ]
    for argument_index, offset in enumerate(signature.stack_argument_offsets):
        lines.extend(
            [
                f"  uint32_t argument_{argument_index};",
                f"  if (stage_b_api_read_word(runtime, input->esp + {offset}U, &argument_{argument_index}))",
                "    return STAGE_B_CALL_MEMORY_FAULT;",
            ]
        )
    call_arguments = ", ".join(
        f"argument_{argument_index}" for argument_index in range(len(signature.stack_argument_offsets))
    )
    lines.extend(
        [
            "  *output = *input;",
            f"  output->eax = stage_b_import_{index}({call_arguments});",
        ]
    )
    for register in signature.clobbered_registers:
        if register == "eax":
            continue
        if register in _REGISTER_NAMES:
            slot = _stable_slot(f"api:{signature.dll}:{signature.symbol}:{register}")
            lines.append(
                f"  output->{register} = stage_b_api_undefined(runtime, {slot}U, input, 0U);"
            )
    for flag in _FLAG_NAMES:
        slot = _stable_slot(f"api:{signature.dll}:{signature.symbol}:{flag}")
        lines.append(
            f"  output->{flag} = stage_b_api_undefined(runtime, {slot}U, input, 0U) & 1U;"
        )
    lines.extend(
        [
            f"  output->esp = input->esp + {signature.stack_result_delta}U;",
            "  return STAGE_B_CALL_OK;",
            "}",
        ]
    )
    return lines


def _semantic_c_source_map(
    rows: list[tuple[dict[str, Any], str, bool, list[str]]],
    *,
    generated_spans: dict[str, tuple[int, int]],
    repair_spans: dict[str, tuple[int, int]],
) -> dict[str, Any]:
    transfers = []
    for row, symbol, generated, reasons in rows:
        spans = generated_spans if generated else repair_spans
        start, end = spans[symbol]
        transfers.append(
            {
                "id": row.get("id"),
                "function": row.get("function"),
                "block_id": row.get("block_id"),
                "contract_sha256": _row_contract_sha256(row),
                "rva_start": _row_rva(row),
                "symbol": symbol,
                "implementation": _generated_implementation_kind(row) if generated else "repair_stub",
                "source": {
                    "path": "state-machine-transfers.c" if generated else "state-machine-repairs.c",
                    "line_start": start,
                    "line_end": end,
                },
                "blockers": reasons,
            }
        )
    return {
        "format": "stage-b-semantic-c-source-map-v1",
        "authority": "stage-a-semantic-transfer-contracts",
        "transfers": transfers,
    }


def _duplicate_dispatch_rvas(rows: list[tuple[dict[str, Any], str, bool, list[str]]]) -> list[dict[str, Any]]:
    by_rva: dict[int, list[str]] = {}
    for row, _symbol, _generated, _reasons in rows:
        by_rva.setdefault(_row_rva(row), []).append(str(row.get("id") or ""))
    return [
        {"rva_start": rva, "transfer_ids": identities}
        for rva, identities in sorted(by_rva.items())
        if len(identities) > 1
    ]


def _row_rva(row: dict[str, Any]) -> int:
    original = row.get("original") if isinstance(row.get("original"), dict) else {}
    value = original.get("rva_start")
    return int(value) if isinstance(value, int) else 0


def _row_contract_sha256(row: dict[str, Any]) -> str:
    digest = row.get("contract_sha256")
    if isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest):
        return digest
    payload = json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(payload)


def _c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _runtime_helpers() -> str:
    helpers = """static uint32_t stage_b_mask(uint32_t width) {
  return width >= 32U ? 0xffffffffU : ((1U << width) - 1U);
}

static uint32_t stage_b_read(stage_b_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {
  if (rt == 0 || rt->read == 0) { *fault = 1U; return 0U; }
  return rt->read(rt->context, address, width, fault);
}

static void stage_b_write(stage_b_runtime *rt, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault) {
  if (rt == 0 || rt->write == 0) { *fault = 1U; return; }
  rt->write(rt->context, address, width, value, fault);
}

static uint32_t stage_b_undefined(stage_b_runtime *rt, uint32_t slot,
    const stage_b_machine_state *input, uint32_t defined_value) {
  return rt != 0 && rt->undefined_value != 0
      ? rt->undefined_value(rt->context, slot, input, defined_value) : slot;
}

static void stage_b_sync_eflags(stage_b_machine_state *state) {
  const uint32_t represented =
      (1U << 0) | (1U << 2) | (1U << 6) | (1U << 7) |
      (1U << 10) | (1U << 11);
  state->eflags = (state->eflags & ~represented) |
      ((state->cf & 1U) << 0) |
      ((state->pf & 1U) << 2) |
      ((state->zf & 1U) << 6) |
      ((state->sf & 1U) << 7) |
      ((state->df & 1U) << 10) |
      ((state->of & 1U) << 11);
}

static uint32_t stage_b_sign_extend(uint32_t width, uint32_t value) {
  uint32_t mask = stage_b_mask(width);
  uint32_t sign = 1U << (width - 1U);
  value &= mask;
  return (value ^ sign) - sign;
}

static uint32_t stage_b_sar(uint32_t width, uint32_t value, uint32_t amount) {
  amount &= 31U;
  return (uint32_t)(((int32_t)stage_b_sign_extend(width, value)) >> amount) & stage_b_mask(width);
}

static uint32_t stage_b_msb(uint32_t width, uint32_t value) {
  return (value >> (width - 1U)) & 1U;
}

static uint32_t stage_b_parity(uint32_t value) {
  value ^= value >> 4U;
  value &= 0xfU;
  return (0x9669U >> value) & 1U;
}

static uint32_t stage_b_add_overflow(uint32_t width, uint32_t left, uint32_t right, uint32_t result) {
  return ((~(left ^ right) & (left ^ result)) >> (width - 1U)) & 1U;
}

static uint32_t stage_b_sub_overflow(uint32_t width, uint32_t left, uint32_t right, uint32_t result) {
  return (((left ^ right) & (left ^ result)) >> (width - 1U)) & 1U;
}

static uint32_t stage_b_imul_high(uint32_t left, uint32_t right) {
  return (uint32_t)(((int64_t)(int32_t)left * (int64_t)(int32_t)right) >> 32U);
}

static uint32_t stage_b_mul_high(uint32_t left, uint32_t right) {
  return (uint32_t)(((uint64_t)left * (uint64_t)right) >> 32U);
}

static uint32_t stage_b_udiv_pair(
    uint32_t high, uint32_t low, uint32_t divisor, uint32_t *remainder) {
  uint64_t rest = high;
  uint32_t quotient = 0U;
  uint32_t index;
  if (divisor == 0U || high >= divisor) {
    if (remainder != 0) *remainder = 0U;
    return 0U;
  }
  for (index = 0U; index < 32U; ++index) {
    rest = (rest << 1U) | ((low >> 31U) & 1U);
    low <<= 1U;
    quotient <<= 1U;
    if (rest >= divisor) {
      rest -= divisor;
      quotient |= 1U;
    }
  }
  if (remainder != 0) *remainder = (uint32_t)rest;
  return quotient;
}

static uint32_t stage_b_udiv_quot(uint32_t high, uint32_t low, uint32_t divisor) {
  return stage_b_udiv_pair(high, low, divisor, 0);
}

static uint32_t stage_b_udiv_rem(uint32_t high, uint32_t low, uint32_t divisor) {
  uint32_t remainder = 0U;
  (void)stage_b_udiv_pair(high, low, divisor, &remainder);
  return remainder;
}

static uint32_t stage_b_udiv_valid(uint32_t high, uint32_t low, uint32_t divisor) {
  (void)low;
  return divisor != 0U && high < divisor;
}

static uint32_t stage_b_bsr(uint32_t value) {
  uint32_t index = 0U;
  while (value >>= 1U) { ++index; }
  return index;
}

static uint32_t stage_b_tzcnt(uint32_t value) {
  uint32_t count = 0U;
  if (value == 0U) return 32U;
  while ((value & 1U) == 0U) { value >>= 1U; ++count; }
  return count;
}

static uint32_t stage_b_shift_cf(uint32_t kind, uint32_t width, uint32_t value, uint32_t count) {
  count &= 31U;
  value &= stage_b_mask(width);
  if (count == 0U || count > width) return 0U;
  if (kind == 0U) return (value >> (width - count)) & 1U;
  return (value >> (count - 1U)) & 1U;
}

static uint32_t stage_b_shift_of(
    uint32_t kind, uint32_t width, uint32_t value, uint32_t count, uint32_t result) {
  count &= 31U;
  if (count != 1U) return 0U;
  if (kind == 0U) return stage_b_msb(width, result) ^ stage_b_shift_cf(kind, width, value, count);
  if (kind == 1U) return stage_b_msb(width, value);
  return 0U;
}

static uint32_t stage_b_sbb_borrow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry, uint32_t result) {
  uint32_t mask = stage_b_mask(width);
  uint64_t subtrahend = (uint64_t)(right & mask) + (uint64_t)(carry & 1U);
  (void)result;
  return (uint64_t)(left & mask) < subtrahend;
}

static uint32_t stage_b_sbb_overflow(
    uint32_t width, uint32_t left, uint32_t right, uint32_t carry, uint32_t result) {
  uint32_t mask = stage_b_mask(width);
  (void)carry;
  return ((((left & mask) ^ (right & mask)) & ((left & mask) ^ (result & mask)))
      >> (width - 1U)) & 1U;
}"""
    prefix = """#if defined(__GNUC__) || defined(__clang__)
#define STAGE_B_INTERNAL_HELPER static __attribute__((unused))
#else
#define STAGE_B_INTERNAL_HELPER static
#endif

"""
    return prefix + helpers.replace("static ", "STAGE_B_INTERNAL_HELPER ") + (
        "\n#undef STAGE_B_INTERNAL_HELPER\n"
    )


@dataclass
class _ExpressionRenderer:
    lines: list[str] = field(default_factory=list)
    memo: dict[str, str] = field(default_factory=dict)
    x87_memo: dict[str, str] = field(default_factory=dict)
    call_outputs: set[int] = field(default_factory=set)
    counter: int = 0
    x87_counter: int = 0

    def render(self, expr: Any) -> str:
        if not isinstance(expr, dict):
            if isinstance(expr, bool):
                return "1U" if expr else "0U"
            if isinstance(expr, int):
                return f"{expr & 0xFFFFFFFF}U"
            raise ValueError(f"unsupported semantic expression leaf {expr!r}")
        key = json.dumps(expr, sort_keys=True, separators=(",", ":"))
        if key in self.memo:
            return self.memo[key]
        op = str(expr.get("op") or "")
        if op == "const":
            return f"{int(expr.get('value') or 0) & 0xFFFFFFFF}U"
        if op == "reg":
            name = str(expr.get("name") or "")
            if name not in _REGISTER_NAMES:
                raise ValueError(f"unsupported register {name!r}")
            return f"input.{name}"
        if op == "flag":
            name = str(expr.get("name") or "")
            if name == "af":
                return "((input.eflags >> 4) & 1U)"
            if name not in _FLAG_NAMES:
                raise ValueError(f"unsupported flag {name!r}")
            return f"input.{name}"
        if op == "true":
            return "1U"
        if op == "false":
            return "0U"
        if op in {"undefined_bv", "undefined_flag"}:
            slot = _stable_slot(str(expr.get("id") or expr.get("reason") or "undefined"))
            defined_value = expr.get("defined_value")
            rendered = "0U" if defined_value is None else self.render(defined_value)
            return f"stage_b_undefined(rt, {slot}U, &input, {rendered})"
        if op == "call_response":
            call_index = _required_nonnegative_int(expr.get("call_index"), "call_response call_index")
            register = str(expr.get("register") or "")
            if register not in _REGISTER_NAMES:
                raise ValueError(f"unsupported call-response register {register!r}")
            if call_index not in self.call_outputs:
                raise ValueError(f"call_response references unavailable call index {call_index}")
            return f"call_output_{call_index}.{register}"
        if op == "call_flag":
            call_index = _required_nonnegative_int(expr.get("call_index"), "call_flag call_index")
            flag = str(expr.get("flag") or "")
            if flag not in _FLAG_NAMES and flag != "af":
                raise ValueError(f"unsupported call-response flag {flag!r}")
            if call_index not in self.call_outputs:
                raise ValueError(f"call_flag references unavailable call index {call_index}")
            if flag == "af":
                return f"((call_output_{call_index}.eflags >> 4) & 1U)"
            return f"call_output_{call_index}.{flag}"
        if op in _X87_WORD_OPS:
            raise ValueError("x87 expressions require the checked replay interpreter")
        if op in _X87_VALUE_OPS:
            raise ValueError(f"x87 value operation {op!r} used as a 32-bit expression")
        if op in {"shift_cf", "shift_of"}:
            raw_args = expr.get("args") if isinstance(expr.get("args"), list) else []
            expected = 4 if op == "shift_cf" else 5
            if len(raw_args) != expected or raw_args[0] not in {"shl", "sal", "shr", "sar", "shld", "shrd"}:
                raise ValueError(f"unsupported {op} expression shape")
            width = raw_args[1]
            if not isinstance(width, int) or isinstance(width, bool) or width not in {8, 16, 32}:
                raise ValueError(f"unsupported {op} operand width")
            kind = {
                "shl": 0,
                "sal": 0,
                "shld": 0,
                "shr": 1,
                "shrd": 1,
                "sar": 2,
            }[str(raw_args[0])]
            left = self.render(raw_args[2])
            count = self.render(raw_args[3])
            if op == "shift_cf":
                value = f"stage_b_shift_cf({kind}U, {width}U, {left}, {count})"
            else:
                result = self.render(raw_args[4])
                value = f"stage_b_shift_of({kind}U, {width}U, {left}, {count}, {result})"
            return self._bind(key, value)
        args = expr.get("args") if isinstance(expr.get("args"), list) else []
        rendered = [self.render(arg) for arg in args]
        value = self._operation(op, expr, rendered)
        return self._bind(key, value)

    def render_x87(self, expr: Any) -> str:
        if not isinstance(expr, dict):
            raise ValueError(f"unsupported x87 expression leaf {expr!r}")
        key = json.dumps(expr, sort_keys=True, separators=(",", ":"))
        if key in self.x87_memo:
            return self.x87_memo[key]
        op = str(expr.get("op") or "")
        args = self._x87_args(expr, op)
        if op == "fpu_reg":
            self._require_x87_arg_count(op, args, 1)
            index = args[0]
            if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 8:
                raise ValueError("fpu_reg index must be an integer from 0 through 7")
            return f"input.x87_stack[{index}]"
        if op == "fpu_empty":
            self._require_x87_arg_count(op, args, 1)
            slot = args[0]
            if not isinstance(slot, int) or isinstance(slot, bool) or not 0 <= slot < 8:
                raise ValueError("fpu_empty slot must be an integer from 0 through 7")
            return self._bind_x87(key, f"stage_b_x87_empty({slot}U)")
        if op == "fpu_const":
            self._require_x87_arg_count(op, args, 1)
            if args[0] not in {"0", "1"}:
                raise ValueError(f"unsupported fpu_const value {args[0]!r}")
            return self._bind_x87(key, f"stage_b_x87_number({args[0]}.0L)")
        if op in {"fpu_mem", "fpu_int"}:
            self._require_x87_arg_count(op, args, 2)
            width = args[0]
            if not isinstance(width, int) or isinstance(width, bool):
                raise ValueError(f"{op} width must be an integer")
            raw = self.render(args[1])
            if op == "fpu_mem":
                if width != 32:
                    raise ValueError(f"unsupported fpu_mem width {width}")
                value = f"stage_b_x87_mem32({raw})"
            else:
                if width not in {8, 16, 32}:
                    raise ValueError(f"unsupported fpu_int width {width}")
                value = f"stage_b_x87_int({width}U, {raw}, &x87_fault)"
            return self._bind_x87(key, value)
        if op == "fpu_mem64":
            self._require_x87_arg_count(op, args, 2)
            low = self.render(args[0])
            high = self.render(args[1])
            return self._bind_x87(key, f"stage_b_x87_mem64({low}, {high})")
        if op == "fpu_neg":
            self._require_x87_arg_count(op, args, 1)
            value = self.render_x87(args[0])
            return self._bind_x87(key, f"stage_b_x87_neg({value}, &x87_fault)")
        if op in {"fpu_add", "fpu_sub", "fpu_subr", "fpu_mul", "fpu_div", "fpu_divr"}:
            self._require_x87_arg_count(op, args, 2)
            operation = {
                "fpu_add": 0,
                "fpu_sub": 1,
                "fpu_subr": 1,
                "fpu_mul": 2,
                "fpu_div": 3,
                "fpu_divr": 3,
            }[op]
            left = self.render_x87(args[0])
            right = self.render_x87(args[1])
            return self._bind_x87(
                key,
                f"stage_b_x87_binary({operation}U, {left}, {right}, &x87_fault)",
            )
        raise ValueError(f"unsupported x87 value operation {op!r}")

    def _render_x87_word(self, key: str, op: str, expr: dict[str, Any]) -> str:
        args = self._x87_args(expr, op)
        if op in {"fpu_control", "fpu_control_init", "fpu_status", "fpu_status_init"}:
            self._require_x87_arg_count(op, args, 0)
            return {
                "fpu_control": "input.x87_control",
                "fpu_control_init": "0x037fU",
                "fpu_status": "input.x87_status",
                "fpu_status_init": "0U",
            }[op]
        if op == "fpu_tag":
            self._require_x87_arg_count(op, args, 1)
            index = args[0]
            if not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < 8:
                raise ValueError("fpu_tag index must be an integer from 0 through 7")
            return f"input.x87_stack[{index}].tag"
        metadata_inputs = {
            "fpu_pending_exception": "input.x87_pending_exception",
            "fpu_last_opcode": "input.x87_last_opcode",
            "fpu_instruction_pointer": "input.x87_instruction_pointer",
            "fpu_code_selector": "input.x87_code_selector",
            "fpu_data_pointer": "input.x87_data_pointer",
            "fpu_data_selector": "input.x87_data_selector",
        }
        if op in metadata_inputs:
            self._require_x87_arg_count(op, args, 0)
            return metadata_inputs[op]
        if op in {"fpu_control_load", "fpu_control_word", "fpu_status_word"}:
            self._require_x87_arg_count(op, args, 1)
            return self._bind(key, f"({self.render(args[0])}) & 0xffffU")
        if op in {"fpu_bits_lo32", "fpu_bits_hi32"}:
            self._require_x87_arg_count(op, args, 1)
            value = self.render_x87(args[0])
            high = 1 if op == "fpu_bits_hi32" else 0
            return self._bind(key, f"stage_b_x87_bits({value}, {high}U, &x87_fault)")
        if op in {"fpu_cmp_cf", "fpu_cmp_pf", "fpu_cmp_zf"}:
            self._require_x87_arg_count(op, args, 2)
            bit = {"fpu_cmp_cf": 0, "fpu_cmp_pf": 1, "fpu_cmp_zf": 2}[op]
            left = self.render_x87(args[0])
            right = self.render_x87(args[1])
            return self._bind(
                key,
                f"stage_b_x87_compare({bit}U, {left}, {right}, &x87_fault)",
            )
        if op == "fpu_fxam":
            self._require_x87_arg_count(op, args, 1)
            value = self.render_x87(args[0])
            return self._bind(key, f"stage_b_x87_fxam({value}, input.x87_status)")
        if op == "fpu_int32":
            self._require_x87_arg_count(op, args, 2)
            value = self.render_x87(args[0])
            control = self.render(args[1])
            return self._bind(
                key,
                f"stage_b_x87_int32({value}, {control}, &x87_fault)",
            )
        raise ValueError(f"unsupported x87 word operation {op!r}")

    @staticmethod
    def _x87_args(expr: dict[str, Any], op: str) -> list[Any]:
        args = expr.get("args")
        if not isinstance(args, list):
            raise ValueError(f"{op} args must be a list")
        return args

    @staticmethod
    def _require_x87_arg_count(op: str, args: list[Any], expected: int) -> None:
        if len(args) != expected:
            raise ValueError(f"{op} requires {expected} arguments, got {len(args)}")

    def _bind(self, key: str, value: str) -> str:
        name = f"v{self.counter}"
        self.counter += 1
        self.lines.append(f"  uint32_t {name} = {value};")
        self.memo[key] = name
        return name

    def _bind_x87(self, key: str, value: str) -> str:
        name = f"x87_v{self.x87_counter}"
        self.x87_counter += 1
        self.lines.append(f"  stage_b_x87_value {name} = {value};")
        self.x87_memo[key] = name
        return name

    def _operation(self, op: str, expr: dict[str, Any], args: list[str]) -> str:
        if op == "load":
            return f"stage_b_read(rt, {self.render(expr.get('address'))}, {int(expr.get('width') or 4)}U, &memory_fault)"
        infix = {"sub32": "-", "ult32": "<", "eq": "==", "xor_bool": "!=", "eq_bool": "=="}
        if op in infix and len(args) == 2:
            return f"(({args[0]}) {infix[op]} ({args[1]}))"
        associative = {"add32": "+", "mul32": "*", "xor32": "^", "and32": "&", "or32": "|"}
        if op in associative and len(args) >= 2:
            operator = associative[op]
            return "(" + f") {operator} (".join(args) + ")"
        if op in {"not32", "neg32"} and len(args) == 1:
            return f"({'~' if op == 'not32' else '-'}({args[0]}))"
        if op in {"shl32", "lshr32"} and len(args) == 2:
            operator = "<<" if op == "shl32" else ">>"
            return f"(({args[0]}) {operator} (({args[1]}) & 31U))"
        if op == "sar" and len(args) == 3:
            return f"stage_b_sar({args[0]}, {args[1]}, {args[2]})"
        if op == "sign_extend" and len(args) == 2:
            return f"stage_b_sign_extend({args[0]}, {args[1]})"
        if op == "ite" and len(args) == 3:
            return f"(({args[0]}) ? ({args[1]}) : ({args[2]}))"
        if op == "msb":
            width, value = (args[0], args[1]) if len(args) == 2 else ("32U", args[0])
            return f"stage_b_msb({width}, {value})"
        if op == "not" and len(args) == 1:
            return f"(!({args[0]}))"
        if op in {"and_bool", "or_bool"} and args:
            operator = "&&" if op == "and_bool" else "||"
            return "(" + f") {operator} (".join(args) + ")"
        if op == "parity" and len(args) == 2:
            return f"stage_b_parity({args[1]})"
        if op == "bool_to_bit" and len(args) == 1:
            return f"(({args[0]}) ? 1U : 0U)"
        if op in {"add_overflow", "sub_overflow"} and len(args) == 4:
            helper = "stage_b_add_overflow" if op == "add_overflow" else "stage_b_sub_overflow"
            return f"{helper}({', '.join(args)})"
        if op in {"imul_low32", "mul_low32"} and len(args) == 2:
            return f"((uint32_t)((uint64_t)({args[0]}) * (uint64_t)({args[1]})))"
        if op == "imul_high32" and len(args) == 2:
            return f"stage_b_imul_high({args[0]}, {args[1]})"
        if op == "mul_high32" and len(args) == 2:
            return f"stage_b_mul_high({args[0]}, {args[1]})"
        if op == "imul_overflow" and len(args) == 5:
            return f"(({args[4]}) != ((int32_t)({args[3]}) < 0 ? 0xffffffffU : 0U))"
        if op == "mul_carry" and len(args) == 4:
            return f"(({args[3]}) != 0U)"
        if op in {"udiv_quot32", "udiv_rem32", "udiv_valid32"} and len(args) == 3:
            helper = {"udiv_quot32": "stage_b_udiv_quot", "udiv_rem32": "stage_b_udiv_rem", "udiv_valid32": "stage_b_udiv_valid"}[op]
            return f"{helper}({', '.join(args)})"
        if op == "bsr_index" and len(args) >= 1:
            return f"stage_b_bsr({args[-1]})"
        if op == "tzcnt" and len(args) >= 1:
            return f"stage_b_tzcnt({args[-1]})"
        if op == "sbb_borrow" and len(args) == 5:
            return f"stage_b_sbb_borrow({', '.join(args)})"
        if op == "sbb_overflow" and len(args) == 5:
            return f"stage_b_sbb_overflow({', '.join(args)})"
        raise ValueError(f"unsupported semantic operation {op!r} with {len(args)} arguments")


def _render_transfer(row: dict[str, Any], symbol: str) -> str:
    renderer = _ExpressionRenderer()
    updates: list[str] = []
    external_index = 0
    ordered_events = row.get("ordered_events") if isinstance(row.get("ordered_events"), list) else []
    owned_register_outputs = {
        output
        for event in ordered_events
        if isinstance(event, dict) and event.get("kind") == "rep_scas"
        for output in event.get("owned_register_outputs", [])
    }
    owned_flag_outputs = {
        output
        for event in ordered_events
        if isinstance(event, dict) and event.get("kind") == "rep_scas"
        for output in event.get("owned_flag_outputs", [])
    }
    if ordered_events:
        for event in ordered_events:
            if not isinstance(event, dict):
                continue
            family = event.get("family")
            if family == "memory":
                _render_ordered_memory_event(renderer, event)
            elif family == "fault":
                _render_ordered_fault_event(renderer, event)
            elif family == "external":
                _render_ordered_external_event(renderer, event, external_index)
                external_index += 1
    else:
        for event in row.get("memory_events", []):
            if isinstance(event, dict):
                _render_ordered_memory_event(renderer, event)
        for fault in row.get("faults", []):
            if isinstance(fault, dict):
                _render_ordered_fault_event(renderer, fault)

    for write in row.get("register_writes", []):
        if not isinstance(write, dict):
            continue
        register = str(write.get("register") or "")
        if register in _REGISTER_NAMES and register not in owned_register_outputs:
            updates.append(f"  state->{register} = {renderer.render(write.get('value'))};")
    for write in row.get("flag_writes", []):
        if not isinstance(write, dict):
            continue
        flag = str(write.get("flag") or "")
        if flag in _FLAG_NAMES and flag not in owned_flag_outputs:
            updates.append(f"  state->{flag} = ({renderer.render(write.get('value'))}) & 1U;")

    fpu_state = row.get("fpu_state")
    if fpu_state is not None:
        raise ValueError("x87_checked_replay_required")

    outcome = row.get("outcome") if isinstance(row.get("outcome"), dict) else {}
    result = _render_outcome(renderer, outcome)
    identity = _c_comment(str(row.get("id") or row.get("block_id") or symbol))
    body = [
        f"/* {identity} */",
        f"stage_b_step_result {symbol}(stage_b_runtime *rt, stage_b_machine_state *state) {{",
        "  stage_b_machine_state input = *state;",
        "  (void)rt;",
        "  (void)input;",
        "  uint32_t memory_fault = 0U;",
        *renderer.lines,
        "  if (memory_fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
    ]
    body.extend(updates)
    body.append("  stage_b_sync_eflags(state);")
    body.append(f"  return {result};")
    body.append("}")
    return "\n".join(body)


def _render_ordered_memory_event(renderer: _ExpressionRenderer, event: dict[str, Any]) -> None:
    address = renderer.render(event.get("address"))
    width = int(event.get("width") or 4)
    if event.get("kind") == "read":
        load = {"op": "load", "width": width, "address": event.get("address")}
        renderer.render(load)
    elif event.get("kind") == "write":
        value = renderer.render(event.get("value"))
        renderer.lines.append(f"  stage_b_write(rt, {address}, {width}U, {value}, &memory_fault);")
    renderer.lines.append("  if (memory_fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };")


def _render_ordered_fault_event(renderer: _ExpressionRenderer, event: dict[str, Any]) -> None:
    condition = renderer.render(event.get("condition"))
    if event.get("kind") == "divide_error":
        renderer.lines.append(f"  if ({condition}) return (stage_b_step_result){{ STAGE_B_DIVIDE_ERROR, 0U, 0U }};")


def _render_ordered_external_event(
    renderer: _ExpressionRenderer,
    event: dict[str, Any],
    event_index: int,
) -> None:
    kind = str(event.get("kind") or "")
    if kind == "rep_movsd":
        _render_rep_movsd_event(renderer, event, event_index)
        return
    if kind == "rep_movs":
        _render_rep_movs_event(renderer, event, event_index)
        return
    if kind == "rep_scas":
        _render_rep_scas_event(renderer, event, event_index)
        return
    if kind == "rep_stos":
        _render_rep_stos_event(renderer, event, event_index)
        return
    if kind not in _CALL_EVENT_KINDS:
        raise ValueError(f"unsupported external event {kind!r}")

    register_inputs = event.get("register_inputs")
    flag_inputs = event.get("flag_inputs")
    if not isinstance(register_inputs, dict) or not isinstance(flag_inputs, dict):
        raise ValueError(f"call event {event_index} has incomplete machine-state inputs")

    renderer.lines.append(f"  stage_b_machine_state call_input_{event_index} = *state;")
    for register in _REGISTER_NAMES:
        if register not in register_inputs:
            raise ValueError(f"call event {event_index} is missing register input {register}")
        value = renderer.render(register_inputs[register])
        renderer.lines.append(f"  call_input_{event_index}.{register} = {value};")
    for flag in _FLAG_NAMES:
        if flag not in flag_inputs:
            raise ValueError(f"call event {event_index} is missing flag input {flag}")
        value = renderer.render(flag_inputs[flag])
        renderer.lines.append(f"  call_input_{event_index}.{flag} = ({value}) & 1U;")

    arguments = event.get("arguments") if isinstance(event.get("arguments"), list) else []
    rendered_arguments = [renderer.render(value) for value in arguments]
    if rendered_arguments:
        renderer.lines.append(
            f"  const uint32_t call_arguments_{event_index}[] = {{ {', '.join(rendered_arguments)} }};"
        )

    stack_inputs = event.get("stack_inputs") if isinstance(event.get("stack_inputs"), list) else []
    rendered_stack_inputs: list[str] = []
    for stack_input in stack_inputs:
        if not isinstance(stack_input, dict):
            raise ValueError(f"call event {event_index} has an invalid stack input")
        offset = _required_nonnegative_int(stack_input.get("offset"), "stack input offset")
        width = _required_nonnegative_int(stack_input.get("width"), "stack input width")
        value = renderer.render(stack_input.get("value"))
        rendered_stack_inputs.append(f"{{ {offset}U, {width}U, {value} }}")
    if rendered_stack_inputs:
        renderer.lines.append(
            f"  const stage_b_stack_input call_stack_inputs_{event_index}[] = "
            f"{{ {', '.join(rendered_stack_inputs)} }};"
        )

    event_kind = {
        "external_call": "STAGE_B_CALL_EXTERNAL_IMPORT",
        "internal_call": "STAGE_B_CALL_INTERNAL_DIRECT",
        "indirect_call": "STAGE_B_CALL_INDIRECT",
    }[kind]
    target = (
        renderer.render(event.get("target"))
        if kind == "indirect_call"
        else f"{int(event.get('target_rva') or 0)}U"
    )
    return_rva = int(event.get("return_rva") or 0)
    instruction_rva = int(event.get("instruction_rva") or 0)
    ordinal = event.get("ordinal")
    has_ordinal = isinstance(ordinal, int)
    dll = _c_string(str(event.get("dll"))) if isinstance(event.get("dll"), str) else "0"
    symbol = _c_string(str(event.get("symbol"))) if isinstance(event.get("symbol"), str) else "0"
    argument_pointer = f"call_arguments_{event_index}" if rendered_arguments else "0"
    stack_pointer = f"call_stack_inputs_{event_index}" if rendered_stack_inputs else "0"
    renderer.lines.extend(
        [
            f"  const stage_b_call_event call_event_{event_index} = {{",
            f"    {event_kind}, {instruction_rva}U, {event_index}U, {target}, {return_rva}U,",
            f"    {dll}, {symbol}, {int(ordinal) if has_ordinal else 0}U, {1 if has_ordinal else 0}U,",
            f"    {argument_pointer}, {len(rendered_arguments)}U,",
            f"    {stack_pointer}, {len(rendered_stack_inputs)}U",
            "  };",
            f"  stage_b_machine_state call_output_{event_index} = call_input_{event_index};",
            f"  stage_b_call_status call_status_{event_index} = stage_b_invoke_call(",
            f"      rt, &call_event_{event_index}, &call_input_{event_index}, &call_output_{event_index});",
            f"  if (call_status_{event_index} == STAGE_B_CALL_UNIMPLEMENTED)",
            "    return (stage_b_step_result){ STAGE_B_UNIMPLEMENTED, 0U, 0U };",
            f"  if (call_status_{event_index} == STAGE_B_CALL_DIVIDE_ERROR)",
            "    return (stage_b_step_result){ STAGE_B_DIVIDE_ERROR, 0U, 0U };",
            f"  if (call_status_{event_index} == STAGE_B_CALL_MEMORY_FAULT)",
            "    return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            f"  if (call_status_{event_index} != STAGE_B_CALL_OK)",
            "    return (stage_b_step_result){ STAGE_B_EXTERNAL_FAULT, 0U, 0U };",
            f"  *state = call_output_{event_index};",
        ]
    )
    renderer.call_outputs.add(event_index)


def _render_rep_movsd_event(
    renderer: _ExpressionRenderer,
    event: dict[str, Any],
    event_index: int,
) -> None:
    _render_rep_movs_event(
        renderer,
        {
            **event,
            "kind": "rep_movs",
            "element_width": 4,
            "address_size": 32,
            "effect_model": "symbolic_string_copy_v2",
            "restart_semantics": "element_committed_v1",
        },
        event_index,
    )


def _render_rep_movs_event(
    renderer: _ExpressionRenderer,
    event: dict[str, Any],
    event_index: int,
) -> None:
    if event.get("effect_model") != "symbolic_string_copy_v2":
        raise ValueError("rep_movs requires symbolic_string_copy_v2")
    _validate_restartable_string_event(event, event_index, "rep_movs")
    width = _required_nonnegative_int(
        event.get("element_width"), "string-copy element width"
    )
    if width not in {1, 2, 4}:
        raise ValueError(f"unsupported string-copy element width {width}")
    source = renderer.render(event.get("source"))
    destination = renderer.render(event.get("destination"))
    count = renderer.render(event.get("count"))
    direction = renderer.render(event.get("direction_flag"))
    instruction_rva = int(event["instruction_rva"])
    backward_step = (-width) & 0xFFFFFFFF
    renderer.lines.extend(
        [
            f"  uint32_t copy_source_{event_index} = {source};",
            f"  uint32_t copy_destination_{event_index} = {destination};",
            f"  uint32_t copy_count_{event_index} = {count};",
            f"  uint32_t copy_step_{event_index} = ({direction}) ? 0x{backward_step:08x}U : {width}U;",
            f"  state->esi = copy_source_{event_index};",
            f"  state->edi = copy_destination_{event_index};",
            f"  state->ecx = copy_count_{event_index};",
            f"  while (copy_count_{event_index} != 0U) {{",
            f"    uint32_t copy_value_{event_index} = stage_b_read(rt, copy_source_{event_index}, {width}U, &memory_fault);",
            f"    if (memory_fault) return (stage_b_step_result){{ STAGE_B_MEMORY_FAULT, {instruction_rva}U, 0U }};",
            f"    stage_b_write(rt, copy_destination_{event_index}, {width}U, copy_value_{event_index}, &memory_fault);",
            "    if (memory_fault) return (stage_b_step_result){ STAGE_B_MEMORY_FAULT, 0U, 0U };",
            f"    copy_source_{event_index} += copy_step_{event_index};",
            f"    copy_destination_{event_index} += copy_step_{event_index};",
            f"    --copy_count_{event_index};",
            f"    state->esi = copy_source_{event_index};",
            f"    state->edi = copy_destination_{event_index};",
            f"    state->ecx = copy_count_{event_index};",
            "  }",
        ]
    )


def _render_rep_stos_event(
    renderer: _ExpressionRenderer,
    event: dict[str, Any],
    event_index: int,
) -> None:
    if event.get("effect_model") != "symbolic_string_fill_v2":
        raise ValueError("rep_stos requires symbolic_string_fill_v2")
    _validate_restartable_string_event(event, event_index, "rep_stos")
    width = _required_nonnegative_int(
        event.get("element_width"), "string-fill element width"
    )
    if width not in {1, 2, 4}:
        raise ValueError(f"unsupported string-fill element width {width}")
    destination = renderer.render(event.get("destination"))
    value = renderer.render(event.get("value"))
    count = renderer.render(event.get("count"))
    direction = renderer.render(event.get("direction_flag"))
    instruction_rva = int(event["instruction_rva"])
    backward_step = (-width) & 0xFFFFFFFF
    renderer.lines.extend(
        [
            f"  uint32_t fill_destination_{event_index} = {destination};",
            f"  uint32_t fill_value_{event_index} = {value};",
            f"  uint32_t fill_count_{event_index} = {count};",
            f"  uint32_t fill_step_{event_index} = ({direction}) ? 0x{backward_step:08x}U : {width}U;",
            f"  state->edi = fill_destination_{event_index};",
            f"  state->ecx = fill_count_{event_index};",
            f"  while (fill_count_{event_index} != 0U) {{",
            f"    stage_b_write(rt, fill_destination_{event_index}, {width}U, fill_value_{event_index}, &memory_fault);",
            f"    if (memory_fault) return (stage_b_step_result){{ STAGE_B_MEMORY_FAULT, {instruction_rva}U, 0U }};",
            f"    fill_destination_{event_index} += fill_step_{event_index};",
            f"    --fill_count_{event_index};",
            f"    state->edi = fill_destination_{event_index};",
            f"    state->ecx = fill_count_{event_index};",
            "  }",
        ]
    )


def _render_rep_scas_event(
    renderer: _ExpressionRenderer,
    event: dict[str, Any],
    event_index: int,
) -> None:
    if not _valid_rep_scas_event(
        event,
        event_index,
        require_instruction_rva=True,
    ):
        raise ValueError("malformed rep_scas event")
    destination = renderer.render(event.get("destination"))
    accumulator = renderer.render(event.get("accumulator"))
    count = renderer.render(event.get("count"))
    direction = renderer.render(event.get("direction_flag"))
    instruction_rva = int(event["instruction_rva"])
    renderer.lines.extend(
        [
            f"  uint32_t scan_destination_{event_index} = {destination};",
            f"  uint32_t scan_accumulator_{event_index} = ({accumulator}) & 0xffU;",
            f"  uint32_t scan_count_{event_index} = {count};",
            f"  uint32_t scan_step_{event_index} = ({direction}) ? 0xffffffffU : 1U;",
            f"  state->edi = scan_destination_{event_index};",
            f"  state->ecx = scan_count_{event_index};",
            f"  while (scan_count_{event_index} != 0U) {{",
            f"    uint32_t scan_memory_{event_index} = stage_b_read(rt, scan_destination_{event_index}, 1U, &memory_fault) & 0xffU;",
            f"    if (memory_fault) return (stage_b_step_result){{ STAGE_B_MEMORY_FAULT, {instruction_rva}U, 0U }};",
            f"    uint32_t scan_result_{event_index} = (scan_accumulator_{event_index} - scan_memory_{event_index}) & 0xffU;",
            f"    scan_destination_{event_index} += scan_step_{event_index};",
            f"    --scan_count_{event_index};",
            f"    state->edi = scan_destination_{event_index};",
            f"    state->ecx = scan_count_{event_index};",
            f"    state->cf = scan_accumulator_{event_index} < scan_memory_{event_index};",
            f"    state->zf = scan_result_{event_index} == 0U;",
            f"    state->sf = (scan_result_{event_index} >> 7) & 1U;",
            f"    state->of = (((scan_accumulator_{event_index} ^ scan_memory_{event_index}) & (scan_accumulator_{event_index} ^ scan_result_{event_index}) & 0x80U) != 0U);",
            f"    state->pf = stage_b_parity(scan_result_{event_index});",
            f"    state->eflags = (state->eflags & ~(1U << 4)) | ((((scan_accumulator_{event_index} ^ scan_memory_{event_index} ^ scan_result_{event_index}) >> 4) & 1U) << 4);",
            "    stage_b_sync_eflags(state);",
            "    if (state->zf != 0U) break;",
            "  }",
        ]
    )


def _validate_restartable_string_event(
    event: dict[str, Any], event_index: int, kind: str
) -> None:
    if _required_nonnegative_int(event.get("index"), f"{kind} event index") != event_index:
        raise ValueError(f"{kind} event index does not match ordered position")
    if event.get("address_size") != 32:
        raise ValueError(f"{kind} requires 32-bit address size")
    if event.get("restart_semantics") != "element_committed_v1":
        raise ValueError(f"{kind} requires element_committed_v1 restart semantics")


def _render_outcome(renderer: _ExpressionRenderer, outcome: dict[str, Any]) -> str:
    kind = str(outcome.get("kind") or "")
    if kind == "fallthrough":
        return f"(stage_b_step_result){{ STAGE_B_FALLTHROUGH, {int(outcome.get('target_rva') or 0)}U, 0U }}"
    if kind == "jump":
        return f"(stage_b_step_result){{ STAGE_B_JUMP, {int(outcome.get('target_rva') or 0)}U, 0U }}"
    if kind == "branch":
        condition = renderer.render(outcome.get("condition"))
        true_target = int(outcome.get("true_target_rva") or 0)
        false_target = int(outcome.get("false_target_rva") or 0)
        return f"(stage_b_step_result){{ STAGE_B_BRANCH, ({condition}) ? {true_target}U : {false_target}U, 0U }}"
    if kind == "return":
        value = renderer.render(outcome.get("value"))
        return f"(stage_b_step_result){{ STAGE_B_RETURN, 0U, {value} }}"
    if kind == "indirect_jump":
        target = renderer.render(outcome.get("target"))
        return f"(stage_b_step_result){{ STAGE_B_INDIRECT_JUMP, 0U, {target} }}"
    if kind == "external_jump":
        return "(stage_b_step_result){ STAGE_B_EXTERNAL_JUMP, 0U, 0U }"
    raise ValueError(f"unsupported semantic outcome {kind!r}")


def _stable_slot(value: str) -> int:
    result = 2166136261
    for byte in value.encode("utf-8"):
        result = ((result ^ byte) * 16777619) & 0xFFFFFFFF
    return result


def _required_nonnegative_int(value: Any, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{description} must be a nonnegative integer")
    return value


def _c_comment(value: str) -> str:
    return value.replace("*/", "* /").replace("\n", " ")
