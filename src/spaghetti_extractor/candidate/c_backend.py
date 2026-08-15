from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from ..artifacts.formats import SEMANTIC_IR_FORMAT
from .api_catalog import MachineCallCatalog, MachineCallSignature
from .c_domains import (
    _CALL_EVENT_KINDS,
    _FLAG_NAMES,
    _REGISTER_NAMES,
    c_string as _c_string,
    valid_rep_scas_event as _valid_rep_scas_event,
)
from ..util import sha256_bytes, sha256_file, write_json


SPX_C_BACKEND_FORMAT = "spaghetti-extractor-semantic-c-backend-v1"

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
_SUPPORTED_OUTCOMES = {"fallthrough", "jump", "branch", "return", "indirect_jump", "external_jump"}
_SUPPORTED_EVENT_KINDS = _CALL_EVENT_KINDS | {
    "rep_movsd",
    "rep_movs",
    "rep_scas",
    "rep_stos",
}


def write_spx_semantic_c_backend(
    out_dir: Path,
    rows: Iterable[dict[str, Any]],
    *,
    state_machine_binding: dict[str, str] | None = None,
    machine_call_catalog: MachineCallCatalog | None = None,
) -> dict[str, Any]:
    """Emit conservative C transition functions directly from static analysis transfer IR."""

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
            "format": "spaghetti-extractor-runtime-call-obligations-v1",
            "status": "complete" if inventory_complete else "incomplete",
            "authority": "spaghetti-extractor-semantic-transfer-contracts",
            "state_machine": state_machine_binding,
            "machine_call_catalog": machine_call_catalog.binding if machine_call_catalog is not None else None,
            "counts": {
                "call_boundaries": len(runtime_call_boundaries),
                "unbound_obligations": len(runtime_obligations),
                "by_status": dict(sorted(runtime_binding_counts.items())),
                "unbound_by_kind": dict(sorted(runtime_obligation_counts.items())),
            },
            "call_boundaries": runtime_call_boundaries,
            "acceptance": "every obligation must be bound by candidate runtime source before candidate assurance can qualify",
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
            "format": "spaghetti-extractor-generated-api-adapters-v1",
            "status": "complete" if not api_adapter_plan["unmatched"] else "incomplete",
            "authority": "machine-call catalog plus static analysis semantic call boundaries",
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
            "format": "spaghetti-extractor-semantic-c-implementation-v1",
            "authority": "spaghetti-extractor-semantic-transfer-contracts",
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
            "assurance": "compile this implementation, then run candidate static and behavioral validation",
        },
    )
    report = {
        "format": SPX_C_BACKEND_FORMAT,
        "status": "complete" if inventory_complete and not unsupported and not runtime_obligations else "incomplete",
        "source_generation_status": "complete" if inventory_complete and not unsupported else "incomplete",
        "authority": "spaghetti-extractor-semantic-transfer-contracts",
        "state_machine": state_machine_binding,
        "machine_call_catalog": machine_call_catalog.binding if machine_call_catalog is not None else None,
        "role": "compiler-consumable repair substrate; candidate assurance remains separate",
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
            "generation_authority": "spaghetti-extractor-semantic-transfer-contracts",
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
            "terminal_control_api": "spx_run_function_result",
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
        return "provide the checked static analysis relation contract or a reviewed machine-call catalog"
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
    stem = f"spx_transfer_{stem}"
    symbol = stem
    suffix = 2
    while symbol in used:
        symbol = f"{stem}_{suffix}"
        suffix += 1
    used.add(symbol)
    return symbol


def _runtime_header() -> str:
    return """#ifndef SPX_STATE_MACHINE_RUNTIME_H
#define SPX_STATE_MACHINE_RUNTIME_H

#define SPX_MACHINE_STATE_HAS_EFLAGS 1

#include <stdint.h>

typedef struct spx_x87_value {
  uint8_t value_bytes[10];
  uint32_t empty;
  uint8_t tag;
} spx_x87_value;

typedef struct spx_machine_state {
  uint32_t eax, ebx, ecx, edx, esi, edi, ebp, esp;
  uint32_t cf, zf, sf, of, pf, df;
  spx_x87_value x87_stack[8];
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
} spx_machine_state;

_Static_assert(sizeof(((spx_x87_value *)0)->value_bytes) == 10U,
    "x87 payload must be exactly 80 bits");
_Static_assert(sizeof(((spx_x87_value *)0)->empty) == 4U,
    "x87 occupancy must match EngineField.x87Empty");
_Static_assert(sizeof(((spx_x87_value *)0)->tag) == 1U,
    "x87 tag must match EngineField.x87Tag");

typedef struct spx_stack_input {
  uint32_t offset;
  uint32_t width;
  uint32_t value;
} spx_stack_input;

typedef enum spx_call_event_kind {
  SPX_CALL_EXTERNAL_IMPORT = 0,
  SPX_CALL_INTERNAL_DIRECT = 1,
  SPX_CALL_INDIRECT = 2
} spx_call_event_kind;

typedef struct spx_call_event {
  spx_call_event_kind kind;
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
  const spx_stack_input *stack_inputs;
  uint32_t stack_input_count;
} spx_call_event;

#define SPX_MAX_EXTERNAL_ARGUMENTS 256U
typedef struct spx_external_call_snapshot {
  uint32_t instruction_rva;
  uint32_t target_iat_rva;
  uint32_t argument_base_offset;
  uint32_t argument_count;
  uint32_t arguments[SPX_MAX_EXTERNAL_ARGUMENTS];
} spx_external_call_snapshot;

typedef struct spx_runtime spx_runtime;

typedef enum spx_call_status {
  SPX_CALL_OK = 0,
  SPX_CALL_UNIMPLEMENTED = 1,
  SPX_CALL_DIVIDE_ERROR = 2,
  SPX_CALL_MEMORY_FAULT = 3,
  SPX_CALL_EXTERNAL_FAULT = 4
} spx_call_status;

typedef spx_call_status (*spx_external_call_handler)(
    spx_runtime *runtime,
    const spx_call_event *event,
    const spx_machine_state *input,
    spx_machine_state *output);

typedef void (*spx_atomic_compare_exchange_handler)(
    void *context,
    uint32_t address,
    uint32_t width,
    uint32_t expected,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *exchanged,
    uint32_t *fault);

typedef void (*spx_atomic_exchange_handler)(
    void *context,
    uint32_t address,
    uint32_t width,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *fault);

typedef uint32_t (*spx_code_target_resolver)(
    spx_runtime *runtime,
    uint32_t target_word,
    uint32_t *target_rva);

typedef spx_call_status (*spx_callable_external_jump_handler)(
    spx_runtime *runtime,
    uint32_t source_rva,
    uint32_t target_word,
    const spx_machine_state *input,
    spx_machine_state *output);

struct spx_runtime {
  void *context;
  uint32_t (*read)(void *context, uint32_t address, uint32_t width, uint32_t *fault);
  void (*write)(void *context, uint32_t address, uint32_t width, uint32_t value, uint32_t *fault);
  spx_atomic_compare_exchange_handler atomic_compare_exchange;
  spx_atomic_exchange_handler atomic_exchange;
  uint32_t (*undefined_value)(
      void *context, uint32_t slot, const spx_machine_state *input,
      uint32_t defined_value);
  spx_external_call_handler external_call_fallback;
  spx_code_target_resolver resolve_code_target;
  spx_callable_external_jump_handler invoke_callable_external_jump;
};

void spx_runtime_atomic_compare_exchange(
    spx_runtime *runtime,
    uint32_t address,
    uint32_t width,
    uint32_t expected,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *exchanged,
    uint32_t *fault);

void spx_runtime_atomic_exchange(
    spx_runtime *runtime,
    uint32_t address,
    uint32_t width,
    uint32_t desired,
    uint32_t *observed,
    uint32_t *fault);

spx_call_status spx_invoke_call(
    spx_runtime *runtime,
    const spx_call_event *event,
    const spx_machine_state *input,
    spx_machine_state *output);

spx_call_status spx_dispatch_external_call(
    spx_runtime *runtime,
    const spx_call_event *event,
    const spx_machine_state *input,
    spx_machine_state *output);

typedef enum spx_control_kind {
  SPX_FALLTHROUGH = 0,
  SPX_JUMP = 1,
  SPX_BRANCH = 2,
  SPX_RETURN = 3,
  SPX_INDIRECT_JUMP = 4,
  SPX_DIVIDE_ERROR = 5,
  SPX_MEMORY_FAULT = 6,
  SPX_UNIMPLEMENTED = 7,
  SPX_EXTERNAL_FAULT = 8,
  SPX_EXTERNAL_JUMP = 9
} spx_control_kind;

typedef struct spx_step_result {
  spx_control_kind kind;
  uint32_t target_rva;
  uint32_t value;
} spx_step_result;

#endif
"""


def _transfers_header(rows: list[tuple[dict[str, Any], str, bool, list[str]]]) -> str:
    declarations = [
        f"spx_step_result {symbol}(spx_runtime *rt, spx_machine_state *state);"
        for _row, symbol, _generated, _reasons in rows
    ]
    return "\n".join([
        "#ifndef SPX_STATE_MACHINE_TRANSFERS_H",
        "#define SPX_STATE_MACHINE_TRANSFERS_H",
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
                f"/* candidate reconstruction repair required: {identity}; blockers: {reason_text}. */",
                f"spx_step_result {symbol}(spx_runtime *rt, spx_machine_state *state) {{",
                "  (void)rt;",
                "  (void)state;",
                "  return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
                "}",
            ]
        )
        spans[symbol] = (start, len(lines))
    return "\n".join(lines).rstrip() + "\n", spans


def _dispatch_header() -> str:
    return """#ifndef SPX_STATE_MACHINE_DISPATCH_H
#define SPX_STATE_MACHINE_DISPATCH_H

#include <stdint.h>
#include "state-machine-transfers.h"

typedef spx_step_result (*spx_transfer_function)(spx_runtime *, spx_machine_state *);

typedef struct spx_transfer_descriptor {
  uint32_t source_rva;
  const char *contract_id;
  const char *contract_sha256;
  spx_transfer_function step;
  uint32_t generated_from_semantics;
} spx_transfer_descriptor;

extern const spx_transfer_descriptor spx_transfer_table[];
extern const uint32_t spx_transfer_count;

const spx_transfer_descriptor *spx_lookup_transfer(uint32_t source_rva);
spx_step_result spx_step_by_rva(
    spx_runtime *rt,
    spx_machine_state *state,
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
            "const spx_transfer_descriptor spx_transfer_table[] = {",
            *entries,
            "};",
            f"const uint32_t spx_transfer_count = {len(rows)}U;",
            "",
            "const spx_transfer_descriptor *spx_lookup_transfer(uint32_t source_rva) {",
            "  const spx_transfer_descriptor *match = 0;",
            "  uint32_t index;",
            "  for (index = 0U; index < spx_transfer_count; ++index) {",
            "    if (spx_transfer_table[index].source_rva != source_rva) continue;",
            "    if (match != 0) return 0;",
            "    match = &spx_transfer_table[index];",
            "  }",
            "  return match;",
            "}",
            "",
            "spx_step_result spx_step_by_rva(",
            "    spx_runtime *rt,",
            "    spx_machine_state *state,",
            "    uint32_t source_rva) {",
            "  const spx_transfer_descriptor *entry = spx_lookup_transfer(source_rva);",
            "  if (entry == 0 || entry->step == 0)",
            "    return (spx_step_result){ SPX_UNIMPLEMENTED, source_rva, 0U };",
            "  state->original_rva = source_rva;",
            "  return entry->step(rt, state);",
            "}",
            "",
        ]
    )


def _engine_header() -> str:
    return """#ifndef SPX_STATE_MACHINE_ENGINE_H
#define SPX_STATE_MACHINE_ENGINE_H

#include "state-machine-dispatch.h"

typedef struct spx_engine_result {
  spx_call_status status;
  spx_step_result control;
} spx_engine_result;

spx_engine_result spx_run_function_result(
    spx_runtime *runtime,
    uint32_t entry_rva,
    const spx_machine_state *input,
    spx_machine_state *output);

spx_call_status spx_run_function(
    spx_runtime *runtime,
    uint32_t entry_rva,
    const spx_machine_state *input,
    spx_machine_state *output);

#endif
"""


def _engine_source() -> str:
    return """#include "state-machine-engine.h"

static spx_call_status spx_resolve_code_target(
    spx_runtime *runtime,
    uint32_t target_word,
    uint32_t *target_rva) {
  if (runtime == 0 || runtime->resolve_code_target == 0)
    return SPX_CALL_UNIMPLEMENTED;
  if (runtime->resolve_code_target(runtime, target_word, target_rva) != 0U)
    return SPX_CALL_UNIMPLEMENTED;
  return SPX_CALL_OK;
}

static spx_engine_result spx_engine_result_make(
    spx_call_status status,
    spx_step_result control) {
  spx_engine_result result;
  result.status = status;
  result.control = control;
  return result;
}

spx_engine_result spx_run_function_result(
    spx_runtime *runtime,
    uint32_t entry_rva,
    const spx_machine_state *input,
    spx_machine_state *output) {
  spx_machine_state state;
  uint32_t current_rva;
  if (input == 0 || output == 0)
    return spx_engine_result_make(
        SPX_CALL_UNIMPLEMENTED,
        (spx_step_result){ SPX_UNIMPLEMENTED, entry_rva, 0U });
  state = *input;
  current_rva = entry_rva;
  for (;;) {
    spx_step_result result = spx_step_by_rva(runtime, &state, current_rva);
    switch (result.kind) {
      case SPX_FALLTHROUGH:
      case SPX_JUMP:
      case SPX_BRANCH:
        current_rva = result.target_rva;
        break;
      case SPX_INDIRECT_JUMP: {
        spx_call_status status = spx_resolve_code_target(runtime, result.value, &current_rva);
        if (status != SPX_CALL_OK && runtime != 0 &&
            runtime->invoke_callable_external_jump != 0) {
          spx_machine_state external_output = state;
          status = runtime->invoke_callable_external_jump(
              runtime, current_rva, result.value, &state, &external_output);
          if (status == SPX_CALL_OK) {
            *output = external_output;
            return spx_engine_result_make(
                SPX_CALL_OK,
                (spx_step_result){ SPX_EXTERNAL_JUMP, current_rva,
                                       result.value });
          }
        }
        if (status != SPX_CALL_OK)
          return spx_engine_result_make(status, result);
        break;
      }
      case SPX_RETURN:
      case SPX_EXTERNAL_JUMP:
        *output = state;
        return spx_engine_result_make(SPX_CALL_OK, result);
      case SPX_DIVIDE_ERROR:
        return spx_engine_result_make(SPX_CALL_DIVIDE_ERROR, result);
      case SPX_MEMORY_FAULT:
        return spx_engine_result_make(SPX_CALL_MEMORY_FAULT, result);
      case SPX_EXTERNAL_FAULT:
        return spx_engine_result_make(SPX_CALL_EXTERNAL_FAULT, result);
      case SPX_UNIMPLEMENTED:
      default:
        return spx_engine_result_make(SPX_CALL_UNIMPLEMENTED, result);
    }
  }
}

spx_call_status spx_run_function(
    spx_runtime *runtime,
    uint32_t entry_rva,
    const spx_machine_state *input,
    spx_machine_state *output) {
  return spx_run_function_result(
      runtime, entry_rva, input, output).status;
}

spx_call_status spx_invoke_call(
    spx_runtime *runtime,
    const spx_call_event *event,
    const spx_machine_state *input,
    spx_machine_state *output) {
  uint32_t target_rva;
  if (event == 0) return SPX_CALL_UNIMPLEMENTED;
  switch (event->kind) {
    case SPX_CALL_INTERNAL_DIRECT:
      return spx_run_function(runtime, event->target_rva, input, output);
    case SPX_CALL_INDIRECT: {
      spx_call_status status = spx_resolve_code_target(
          runtime, event->target_rva, &target_rva);
      if (status == SPX_CALL_OK)
        return spx_run_function(runtime, target_rva, input, output);
      return spx_dispatch_external_call(runtime, event, input, output);
    }
    case SPX_CALL_EXTERNAL_IMPORT:
      return spx_dispatch_external_call(runtime, event, input, output);
    default:
      return SPX_CALL_UNIMPLEMENTED;
  }
}
"""


def _api_adapters_header() -> str:
    return """#ifndef SPX_STATE_MACHINE_API_ADAPTERS_H
#define SPX_STATE_MACHINE_API_ADAPTERS_H

#include "state-machine-runtime.h"

spx_call_status spx_dispatch_external_call(
    spx_runtime *runtime,
    const spx_call_event *event,
    const spx_machine_state *input,
    spx_machine_state *output);

#endif
"""


def _api_adapters_source(signatures: list[MachineCallSignature]) -> str:
    lines = [
        '#include "state-machine-api-adapters.h"',
        "",
        "static uint32_t spx_api_undefined(spx_runtime *runtime, uint32_t slot, const spx_machine_state *input, uint32_t defined_value) {",
        "  return runtime != 0 && runtime->undefined_value != 0",
        "      ? runtime->undefined_value(runtime->context, slot, input, defined_value) : slot;",
        "}",
        "",
        "static uint32_t spx_api_read_word(",
        "    spx_runtime *runtime, uint32_t address, uint32_t *value) {",
        "  uint32_t fault = 0U;",
        "  if (runtime == 0 || runtime->read == 0 || value == 0) return 1U;",
        "  *value = runtime->read(runtime->context, address, 4U, &fault);",
        "  return fault;",
        "}",
        "",
        "static uint32_t spx_api_ascii_lower(uint32_t value) {",
        "  return value >= (uint32_t)'A' && value <= (uint32_t)'Z' ? value + 32U : value;",
        "}",
        "",
        "static uint32_t spx_api_string_equal(const char *left, const char *right, uint32_t fold_case) {",
        "  if (left == 0 || right == 0) return left == right;",
        "  while (*left != '\\0' && *right != '\\0') {",
        "    uint32_t l = (uint32_t)(unsigned char)*left++;",
        "    uint32_t r = (uint32_t)(unsigned char)*right++;",
        "    if (fold_case) { l = spx_api_ascii_lower(l); r = spx_api_ascii_lower(r); }",
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
                f"    spx_import_{index}({arguments}) __asm__({_c_string(signature.symbol)});",
            ]
        )
    for index, signature in enumerate(signatures):
        lines.extend(["", *_render_api_adapter(index, signature)])
    lines.extend(
        [
            "",
            "spx_call_status spx_dispatch_external_call(",
            "    spx_runtime *runtime,",
            "    const spx_call_event *event,",
            "    const spx_machine_state *input,",
            "    spx_machine_state *output) {",
            "  if (event == 0) return SPX_CALL_UNIMPLEMENTED;",
        ]
    )
    for index, signature in enumerate(signatures):
        assert signature.symbol is not None
        lines.extend(
            [
                "  if (spx_api_string_equal(event->dll, "
                f"{_c_string(signature.dll)}, 1U) &&",
                "      spx_api_string_equal(event->symbol, "
                f"{_c_string(signature.symbol)}, 0U) && !event->has_ordinal)",
                f"    return spx_api_adapter_{index}(runtime, input, output);",
            ]
        )
    lines.extend(
        [
            "  if (runtime != 0 && runtime->external_call_fallback != 0)",
            "    return runtime->external_call_fallback(runtime, event, input, output);",
            "  return SPX_CALL_UNIMPLEMENTED;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _render_api_adapter(index: int, signature: MachineCallSignature) -> list[str]:
    lines = [
        f"static spx_call_status spx_api_adapter_{index}(",
        "    spx_runtime *runtime,",
        "    const spx_machine_state *input,",
        "    spx_machine_state *output) {",
        "  if (input == 0 || output == 0) return SPX_CALL_UNIMPLEMENTED;",
    ]
    for argument_index, offset in enumerate(signature.stack_argument_offsets):
        lines.extend(
            [
                f"  uint32_t argument_{argument_index};",
                f"  if (spx_api_read_word(runtime, input->esp + {offset}U, &argument_{argument_index}))",
                "    return SPX_CALL_MEMORY_FAULT;",
            ]
        )
    call_arguments = ", ".join(
        f"argument_{argument_index}" for argument_index in range(len(signature.stack_argument_offsets))
    )
    lines.extend(
        [
            "  *output = *input;",
            f"  output->eax = spx_import_{index}({call_arguments});",
        ]
    )
    for register in signature.clobbered_registers:
        if register == "eax":
            continue
        if register in _REGISTER_NAMES:
            slot = _stable_slot(f"api:{signature.dll}:{signature.symbol}:{register}")
            lines.append(
                f"  output->{register} = spx_api_undefined(runtime, {slot}U, input, 0U);"
            )
    for flag in _FLAG_NAMES:
        slot = _stable_slot(f"api:{signature.dll}:{signature.symbol}:{flag}")
        lines.append(
            f"  output->{flag} = spx_api_undefined(runtime, {slot}U, input, 0U) & 1U;"
        )
    lines.extend(
        [
            f"  output->esp = input->esp + {signature.stack_result_delta}U;",
            "  return SPX_CALL_OK;",
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
        "format": "spaghetti-extractor-semantic-c-source-map-v1",
        "authority": "spaghetti-extractor-semantic-transfer-contracts",
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


# Rendering is isolated from validation and package assembly.
from .c_render import (  # noqa: E402
    _c_comment,
    _render_transfer,
    _runtime_helpers,
    _stable_slot,
)
