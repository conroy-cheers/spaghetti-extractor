"""Validation and package assembly for the Stage B interpreter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifacts.formats import (
    STAGE_B_INTERPRETER_PACKAGE_FORMAT,
    STAGE_B_INTERPRETER_PROGRAM_FORMAT,
)
from ..machine_ir.definedness import analyze_definedness_jsonl
from ..util import sha256_bytes, sha256_file, write_json
from .interpreter_compiler import _TransferCompiler
from .interpreter_model import (
    STAGE_B_INTERPRETER_DEFINEDNESS_USE_FIELDS,
    STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT,
    StageBInterpreterError,
    _MACHINE_IR_FORMAT,
    _RAW_INSTRUCTION_FIELDS,
    _Transfer,
    _TypedX87Program,
    _X87_CHECKED_DECODER,
    _X87_CHECKED_EXECUTOR,
    _X87_TYPED_PROGRAM_FORMAT,
)
from .interpreter_render import (
    _INTERPRETER_INTERNAL_HEADER,
    _interpreter_header,
    _interpreter_runtime_header,
    _interpreter_source,
    _program_source,
)
from .interpreter_values import (
    _list,
    _nonnegative,
    _object,
    _read_jsonl,
    _sha256,
    _string,
    _u32,
)
from .machine_ir_scope import partition_candidate_machine_ir_units
from .x87 import TYPED_NATIVE_X87_OPERATION_FORMAT


def compile_stage_b_interpreter_program(state_machine: Path) -> tuple[_Transfer, ...]:
    rows = _read_jsonl(Path(state_machine))
    transfers, _blockers = _compile_interpreter_rows(rows, collect_blockers=False)
    return transfers


def compile_stage_b_interpreter_machine_ir(machine_ir: Path) -> tuple[_Transfer, ...]:
    rows = _adapt_machine_ir_rows(_read_jsonl(Path(machine_ir)))
    transfers, _blockers = _compile_interpreter_rows(rows, collect_blockers=False)
    return transfers


def _adapt_machine_ir_rows(units: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index, unit in enumerate(units):
        if unit.get("format") != _MACHINE_IR_FORMAT or unit.get("record_kind") != "unit":
            raise StageBInterpreterError(
                f"machine-IR record {index} is not a v2 unit",
                code="malformed_machine_ir_input",
            )
        if _contains_raw_instruction_material(unit):
            raise StageBInterpreterError(
                f"machine-IR record {index} contains raw instruction material",
                code="malformed_machine_ir_input",
            )
        identity = _string(unit.get("id"), "machine-IR unit id")
        source = _object(unit.get("source"), f"{identity} source binding")
        original = _object(source.get("original"), f"{identity} source span")
        semantics = _object(unit.get("semantics"), f"{identity} semantics")
        source_digest = _sha256(
            source.get("instruction_bytes_sha256"), f"{identity} source span SHA-256"
        )
        rva_start = _u32(original.get("rva_start"), "machine-IR start RVA")
        rva_end = _u32(original.get("rva_end"), "machine-IR end RVA")
        span_size = _nonnegative(original.get("size"), "machine-IR span size")
        if rva_end <= rva_start or span_size != rva_end - rva_start:
            raise StageBInterpreterError(
                f"{identity}: machine-IR source span is inconsistent",
                code="malformed_machine_ir_input",
            )
        row: dict[str, Any] = {
            "format": "stage-a-semantic-transfer-contract-v1",
            "expression_model": "stage-a-semantic-ir-v1",
            "id": identity,
            "status": "reimplementable" if unit.get("status") == "qualified" else "incomplete",
            "reachable": unit.get("reachable") is True,
            "contract_sha256": _sha256(
                source.get("contract_sha256"), f"{identity} contract SHA-256"
            ),
            "instruction_bytes_sha256": source_digest,
            "original": {
                "rva_start": rva_start,
                "rva_end": rva_end,
                "size": span_size,
            },
            "_machine_ir_x87_micro_ops": _list(
                unit.get("x87_micro_ops"), f"{identity} x87 micro-ops"
            ),
            # Definedness analysis needs the checked instruction identity and
            # typed operand shape for ISA-defined input witnesses such as the
            # zero-source BSR destination.  The machine IR contains no opcode
            # bytes, so retaining this metadata does not reintroduce runtime
            # decoding or original executable material.
            "instructions": _list(
                unit.get("instructions", []), f"{identity} instructions"
            ),
        }
        for field in (
            "pre_state", "register_writes", "flag_writes", "memory_events",
            "external_events", "faults", "ordered_events", "edge_conditions",
            "outcome", "stack_delta", "counts", "fpu_state",
            "instruction_effect_schedule",
        ):
            row[field] = semantics.get(field)
        rows.append(row)
    return rows


def _contains_raw_instruction_material(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            key in _RAW_INSTRUCTION_FIELDS
            or _contains_raw_instruction_material(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_raw_instruction_material(item) for item in value)
    return False


def _compile_interpreter_rows(
    rows: list[dict[str, Any]],
    *,
    collect_blockers: bool,
) -> tuple[tuple[_Transfer, ...], list[dict[str, Any]]]:
    transfers: list[_Transfer] = []
    blockers: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_rvas: set[int] = set()
    for index, row in enumerate(rows):
        if row.get("status") == "incomplete":
            error = StageBInterpreterError(
                f"{row.get('id')}: semantic transfer is not qualified",
                code="machine_ir_semantics_incomplete",
                next_action=(
                    "classify the bytes as non-code or implement and qualify their semantics"
                ),
            )
            if not collect_blockers:
                raise error
            blockers.append(
                _package_blocker(
                    row, index, error, failure_phase="semantic_qualification"
                )
            )
            continue
        try:
            transfer = _TransferCompiler(row).compile()
        except StageBInterpreterError as exc:
            if not collect_blockers:
                raise
            blockers.append(
                _package_blocker(row, index, exc, failure_phase="semantic_lowering")
            )
            continue
        if transfer.identity in seen_ids:
            error = StageBInterpreterError(
                f"duplicate transfer id {transfer.identity}",
                code="duplicate_transfer_id",
                next_action="make every Stage A semantic transfer identity unique",
            )
            if not collect_blockers:
                raise error
            blockers.append(
                _package_blocker(row, index, error, failure_phase="identity_validation")
            )
            continue
        if transfer.rva_start in seen_rvas:
            error = StageBInterpreterError(
                f"duplicate transfer RVA 0x{transfer.rva_start:x}",
                code="duplicate_transfer_rva",
                next_action="split or reconcile transfers that start at the same original RVA",
            )
            if not collect_blockers:
                raise error
            blockers.append(
                _package_blocker(row, index, error, failure_phase="identity_validation")
            )
            continue
        seen_ids.add(transfer.identity)
        seen_rvas.add(transfer.rva_start)
        transfers.append(transfer)
    blockers.sort(key=_package_blocker_sort_key)
    return tuple(sorted(transfers, key=lambda item: item.rva_start)), blockers


def _package_blocker(
    row: Mapping[str, Any],
    index: int,
    error: StageBInterpreterError,
    *,
    failure_phase: str = "semantic_lowering",
) -> dict[str, Any]:
    original = row.get("original")
    rva_start = original.get("rva_start") if isinstance(original, dict) else None
    return {
        "transfer_index": index,
        "transfer_id": row.get("id") if isinstance(row.get("id"), str) else None,
        "rva_start": (
            rva_start
            if isinstance(rva_start, int) and not isinstance(rva_start, bool)
            else None
        ),
        "code": error.code,
        "failure_phase": failure_phase,
        "message": str(error),
        "next_action": error.next_action,
    }


def _package_blocker_sort_key(blocker: Mapping[str, Any]) -> tuple[int, str, str, str, int]:
    rva_start = blocker.get("rva_start")
    return (
        rva_start if isinstance(rva_start, int) else 2**32,
        str(blocker.get("transfer_id") or ""),
        str(blocker.get("code") or ""),
        str(blocker.get("message") or ""),
        int(blocker.get("transfer_index") or 0),
    )


def write_stage_b_interpreter_package(
    *,
    state_machine: Path | None = None,
    machine_ir: Path | None = None,
    out: Path,
    allow_deferred_potential_transfers: bool = False,
) -> dict[str, Any]:
    """Write stable interpreter source, program data, and a strict manifest."""

    if (state_machine is None) == (machine_ir is None):
        raise StageBInterpreterError(
            "provide exactly one of state_machine or machine_ir",
            code="ambiguous_interpreter_input",
        )
    input_path = Path(state_machine if state_machine is not None else machine_ir)
    input_kind = "state_machine" if state_machine is not None else "machine_ir"
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    input_rows = _read_jsonl(input_path)
    deferred_transfers: list[dict[str, Any]] = []
    if state_machine is not None:
        rows = input_rows
    else:
        scoped_units, deferred_transfers = partition_candidate_machine_ir_units(
            input_rows,
            allow_deferred_potential_transfers=allow_deferred_potential_transfers,
        )
        rows = _adapt_machine_ir_rows(scoped_units)
    definedness_input = input_path
    if machine_ir is not None:
        definedness_input = out / "machine-ir-adapted-semantics.jsonl"
        definedness_input.write_text(
            "".join(
                json.dumps(
                    _sanitize_generated_binding_names(row),
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
                + "\n"
                for row in rows
            ),
            encoding="ascii",
        )
    transfers, blockers = _compile_interpreter_rows(rows, collect_blockers=True)
    max_word_nodes = max((len(transfer.nodes) for transfer in transfers), default=0)
    if max_word_nodes > 1024:
        blockers.append({
            "transfer_index": 0,
            "transfer_id": None,
            "rva_start": None,
            "code": "word_node_capacity_exceeded",
            "failure_phase": "package_capacity",
            "message": (
                f"interpreter requires {max_word_nodes} word nodes; "
                "the supported maximum is 1024"
            ),
            "next_action": (
                "split the oversized transfer or raise the checked interpreter "
                "profile limit"
            ),
        })
        blockers.sort(key=_package_blocker_sort_key)
    files = {
        "runtime_header": out / "state-machine-runtime.h",
        "interpreter_header": out / "state-machine-interpreter.h",
        "interpreter_internal_header": out / "state-machine-interpreter-internal.h",
        "interpreter_source": out / "state-machine-interpreter.c",
        "program_source": out / "state-machine-program.c",
        "program_manifest": out / "state-machine-interpreter-program.json",
    }
    files["runtime_header"].write_text(_interpreter_runtime_header(), encoding="ascii")
    files["interpreter_header"].write_text(_interpreter_header(), encoding="ascii")
    files["interpreter_internal_header"].write_text(
        _INTERPRETER_INTERNAL_HEADER, encoding="ascii"
    )
    files["interpreter_source"].write_text(
        _interpreter_source(max_word_nodes=max(1, max_word_nodes)),
        encoding="ascii",
    )
    files["program_source"].write_text(_program_source(transfers), encoding="ascii")
    program_payload = _program_payload(
        transfers,
        semantic_input_sha256=sha256_file(input_path),
        definedness_input=definedness_input,
        input_transfer_count=len(input_rows),
        blockers=blockers,
        deferred_transfers=deferred_transfers,
        sanitized_source_bindings=machine_ir is not None,
    )
    write_json(files["program_manifest"], program_payload)
    package = {
        "format": STAGE_B_INTERPRETER_PACKAGE_FORMAT,
        "status": "ready" if not blockers else "incomplete",
        input_kind: {"path": input_path.name, "sha256": sha256_file(input_path)},
        "input_mode": (
            "strict_exact_state_machine_v1"
            if state_machine is not None
            else "sanitized_machine_ir_v2"
        ),
        "program": {
            "path": files["program_manifest"].name,
            "sha256": sha256_file(files["program_manifest"]),
        },
        "sources": [
            {"role": role, "path": path.name, "sha256": sha256_file(path)}
            for role, path in files.items()
            if role != "program_manifest"
        ],
        "counts": program_payload["counts"],
        "blockers": blockers,
        "semantic_coverage": program_payload["semantic_coverage"],
        "execution_policy": program_payload["execution_policy"],
        "deferred_transfers": deferred_transfers,
        "authority": "candidate generation only; static and behavioral qualification remain required",
    }
    if machine_ir is not None:
        package["adapted_semantics"] = {
            "path": definedness_input.name,
            "sha256": sha256_file(definedness_input),
            "role": "byte_free_definedness_analysis_input",
        }
    write_json(out / "state-machine-interpreter-package.json", package)
    return package


def _sanitize_generated_binding_names(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            ("source_span_sha256" if key == "instruction_bytes_sha256" else str(key)):
            _sanitize_generated_binding_names(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_generated_binding_names(item) for item in value]
    return value


def _program_payload(
    transfers: Iterable[_Transfer],
    *,
    semantic_input_sha256: str,
    definedness_input: Path,
    input_transfer_count: int | None = None,
    blockers: Iterable[Mapping[str, Any]] = (),
    deferred_transfers: Iterable[Mapping[str, Any]] = (),
    sanitized_source_bindings: bool = False,
) -> dict[str, Any]:
    rows = list(transfers)
    blocker_rows = [dict(item) for item in blockers]
    deferred_rows = [dict(item) for item in deferred_transfers]
    input_count = len(rows) if input_transfer_count is None else input_transfer_count
    word_ops = sorted({node.op for row in rows for node in row.nodes})
    x87_ops = sorted({node.op for row in rows for node in row.x87_nodes})
    action_ops = sorted({action.op for row in rows for action in row.actions})
    state_machine_sha256 = semantic_input_sha256
    transfer_payloads = []
    for row in rows:
        source_binding = {
            (
                "source_span_sha256"
                if sanitized_source_bindings
                else "instruction_bytes_sha256"
            ): row.instruction_bytes_sha256
        }
        transfer_payloads.append({
            "id": row.identity,
            "rva_start": row.rva_start,
            "contract_sha256": row.contract_sha256,
            **source_binding,
            "counts": {
                "word_nodes": len(row.nodes),
                "x87_nodes": len(row.x87_nodes),
                "actions": len(row.actions),
                "calls": len(row.calls),
                "x87_operations": len(row.x87_operations),
            },
            "x87_operations": [
                _typed_x87_payload(operation) for operation in row.x87_operations
            ],
        })
    undefined_node_count = sum(
        node.op in {"undefined_bv", "undefined_flag"}
        for row in rows
        for node in row.nodes
    )
    payload = {
        "format": STAGE_B_INTERPRETER_PROGRAM_FORMAT,
        "status": "ready" if not blocker_rows else "incomplete",
        "state_machine_sha256": state_machine_sha256,
        "counts": {
            "input_transfers": input_count,
            "transfers": len(rows),
            "blocked_transfers": len(blocker_rows),
            "deferred_transfers": len(deferred_rows),
            "word_nodes": sum(len(row.nodes) for row in rows),
            "x87_nodes": sum(len(row.x87_nodes) for row in rows),
            "x87_operations": sum(len(row.x87_operations) for row in rows),
            "actions": sum(len(row.actions) for row in rows),
            "calls": sum(len(row.calls) for row in rows),
            "undefined_nodes": undefined_node_count,
            "max_word_nodes_per_transfer": max((len(row.nodes) for row in rows), default=0),
            "max_x87_nodes_per_transfer": max((len(row.x87_nodes) for row in rows), default=0),
        },
        "capability": {
            "word_ops": word_ops,
            "x87_ops": x87_ops,
            "action_ops": action_ops,
            "typed_native_x87": {
                "format": _X87_TYPED_PROGRAM_FORMAT,
                "operation_format": TYPED_NATIVE_X87_OPERATION_FORMAT,
                "mode": "sanitized_typed_native_v1",
                "action": "typed_x87",
                "runtime_handler": "execute_typed_x87_operation",
                "checked_decoder": _X87_CHECKED_DECODER,
                "checked_executor": _X87_CHECKED_EXECUTOR,
            },
        },
        "blockers": blocker_rows,
        "semantic_coverage": {
            "status": "complete" if not deferred_rows else "incomplete",
            "deferred_transfers": len(deferred_rows),
            "acceptance_authority": False,
        },
        "execution_policy": (
            "complete_transfer_inventory_v1"
            if not deferred_rows
            else "fail_closed_on_deferred_potential_transfer_v1"
        ),
        "deferred_transfers": deferred_rows,
        "transfers": transfer_payloads,
        "authority": "untrusted generated program; Stage A checks every binding",
    }
    if undefined_node_count:
        definedness_evidence = analyze_definedness_jsonl(definedness_input)
        payload["definedness_use"] = _definedness_use_payload(
            rows,
            state_machine_sha256=state_machine_sha256,
            transfer_payloads=transfer_payloads,
            definedness_evidence=definedness_evidence,
        )
    return payload


def _definedness_use_payload(
    transfers: Iterable[_Transfer],
    *,
    state_machine_sha256: str,
    transfer_payloads: list[dict[str, Any]],
    definedness_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind every compiled undefined node to the analyzer's exact evidence."""

    uses_by_slot: dict[int, list[dict[str, Any]]] = {}
    for transfer in transfers:
        for node_index, node in enumerate(transfer.nodes):
            if node.op not in {"undefined_bv", "undefined_flag"}:
                continue
            use = {
                "transfer_id": transfer.identity,
                "node_index": node_index,
                "op": node.op,
            }
            if len(node.args) == 1:
                use["defined_value_node"] = node.args[0]
            uses_by_slot.setdefault(node.immediate, []).append(use)
    evidence_slots: dict[int, Mapping[str, Any]] = {}
    raw_evidence_slots = definedness_evidence.get("slots")
    if not isinstance(raw_evidence_slots, list):
        raise StageBInterpreterError(
            "definedness analysis omitted its slot inventory",
            code="definedness_evidence_incomplete",
            next_action="rerun complete fail-closed definedness analysis",
        )
    for raw_slot in raw_evidence_slots:
        if not isinstance(raw_slot, Mapping):
            raise StageBInterpreterError(
                "definedness analysis emitted a non-object slot",
                code="definedness_evidence_invalid",
                next_action="repair the definedness evidence schema",
            )
        slot = raw_slot.get("slot")
        if not isinstance(slot, int) or isinstance(slot, bool) or slot < 0 or slot > 0xFFFFFFFF:
            raise StageBInterpreterError(
                "definedness analysis emitted an invalid slot id",
                code="definedness_evidence_invalid",
                next_action="repair stable undefined-slot assignment",
            )
        if slot in evidence_slots:
            raise StageBInterpreterError(
                "definedness analysis emitted duplicate slot ids",
                code="definedness_evidence_invalid",
                next_action="repair stable undefined-slot assignment",
            )
        evidence_slots[slot] = raw_slot
    missing_slots = set(uses_by_slot) - set(evidence_slots)
    if missing_slots:
        raise StageBInterpreterError(
            "compiled undefined nodes are missing definedness evidence",
            code="definedness_evidence_incomplete",
            next_action="regenerate interpreter and definedness evidence from one state machine",
        )

    slots: list[dict[str, Any]] = []
    for slot in sorted(uses_by_slot):
        evidence = evidence_slots[slot]
        classification = evidence.get("classification")
        witness_policy = evidence.get("witness_policy")
        choice_source = evidence.get("choice_source")
        obligations = evidence.get("proof_obligations")
        undefined_id = evidence.get("undefined_id")
        if classification not in {
            "unconstrained_noninterfering",
            "unconstrained_conditionally_noninterfering",
            "synchronized_behavior_relevant",
            "unknown",
        } or not isinstance(undefined_id, str) or not undefined_id:
            raise StageBInterpreterError(
                "definedness analysis emitted an unsupported slot classification",
                code="definedness_evidence_invalid",
                next_action="repair the definedness evidence classifier",
            )
        if not isinstance(obligations, list):
            obligations = []
        slots.append(
            {
                "slot": slot,
                "undefined_id": undefined_id,
                "classification": classification,
                "witness_policy": witness_policy,
                "choice_source": choice_source,
                "proof_obligations": obligations,
                "uses": uses_by_slot[slot],
            }
        )
    metadata: dict[str, Any] = {
        "format": STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT,
        "status": "complete",
        "proof_authority": False,
        "state_machine_sha256": state_machine_sha256,
        "definedness_evidence_sha256": definedness_evidence.get("evidence_sha256"),
        "transfer_inventory_sha256": sha256_bytes(
            json.dumps(
                transfer_payloads,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ),
        "evidence_slot_count": len(evidence_slots),
        "unused_evidence_slot_count": len(set(evidence_slots) - set(uses_by_slot)),
        "undefined_node_count": sum(len(uses) for uses in uses_by_slot.values()),
        "slots": slots,
    }
    metadata["metadata_sha256"] = sha256_bytes(
        json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    )
    assert set(metadata) == STAGE_B_INTERPRETER_DEFINEDNESS_USE_FIELDS
    return metadata


def _typed_x87_payload(program: _TypedX87Program) -> dict[str, Any]:
    return {
        "format": _X87_TYPED_PROGRAM_FORMAT,
        "contract_sha256": program.contract_sha256,
        "image_base": program.image_base,
        "rva_start": program.rva_start,
        "rva_end": program.rva_end,
        "operation": program.operation.payload(),
        "checked_decoder": program.checked_decoder,
        "checked_executor": program.checked_executor,
    }
