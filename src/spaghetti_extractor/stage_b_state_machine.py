from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .util import sha256_bytes


STAGE_B_STATE_MACHINE_FORMAT = "stage-b-state-machine-transfer-v1"
STAGE_A_SEMANTIC_IR_MODEL = "stage-a-semantic-ir-v1"

_TRANSFER_FIELDS = (
    "format",
    "id",
    "function",
    "block_id",
    "unit_kind",
    "status",
    "reachable",
    "original",
    "instructions",
    "instruction_bytes_sha256",
    "expression_model",
    "pre_state",
    "register_writes",
    "flag_writes",
    "memory_events",
    "external_events",
    "faults",
    "ordered_events",
    "edge_conditions",
    "outcome",
    "stack_delta",
    "fpu_state",
    "counts",
    "acceptance",
    "blocker_category",
    "blocker",
    "next_action",
)


def normalize_stage_a_semantic_transfer(row: dict[str, Any]) -> dict[str, Any]:
    """Preserve the checked Stage A transfer IR used to generate Stage B source."""

    normalized = {
        key: _json_value(row[key])
        for key in _TRANSFER_FIELDS
        if key in row
    }
    source_bytes = _canonical_json(normalized)
    normalized["stage_b_format"] = STAGE_B_STATE_MACHINE_FORMAT
    normalized["contract_sha256"] = sha256_bytes(source_bytes)
    return normalized


def state_machine_rows_from_functions(functions: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    source_rows: list[dict[str, Any]] = []
    for function in functions:
        reference = function.get("reference_contract")
        if not isinstance(reference, dict):
            continue
        bytecode = reference.get("semantic_transfer_bytecode")
        transfers = bytecode.get("transfers") if isinstance(bytecode, dict) else None
        if not isinstance(transfers, list):
            continue
        for transfer in transfers:
            if not isinstance(transfer, dict):
                continue
            source_rows.append(transfer)
    return normalize_stage_a_semantic_transfers(source_rows)


def normalize_stage_a_semantic_transfers(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_rows: dict[str, dict[str, Any]] = {}
    for row in rows:
        normalized = normalize_stage_a_semantic_transfer(row)
        identity = str(
            normalized.get("id")
            or f"{normalized.get('function')}:{normalized.get('block_id')}:{_transfer_start(normalized)}"
        )
        existing = normalized_rows.get(identity)
        if existing is not None and existing != normalized:
            identity = f"{identity}:{normalized['contract_sha256']}"
        normalized_rows[identity] = normalized
    return sorted(
        normalized_rows.values(),
        key=lambda row: (
            _transfer_start(row),
            str(row.get("function") or ""),
            str(row.get("block_id") or ""),
            str(row.get("id") or ""),
        ),
    )


def write_stage_b_state_machine(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def stage_b_state_machine_coverage(
    functions: Iterable[dict[str, Any]],
    rows: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    function_rows = list(functions)
    transfer_rows = list(rows)
    status_counts = Counter(str(row.get("status") or "unspecified") for row in transfer_rows)
    model_counts = Counter(str(row.get("expression_model") or "unspecified") for row in transfer_rows)
    functions_without_transfers = [
        _function_reference(function)
        for function in function_rows
        if not _function_has_transfer(function)
    ]
    incomplete_transfers = [
        _transfer_reference(row)
        for row in transfer_rows
        if row.get("status") != "reimplementable"
    ]
    unsupported_models = [
        _transfer_reference(row)
        for row in transfer_rows
        if row.get("expression_model") not in {STAGE_A_SEMANTIC_IR_MODEL}
    ]
    duplicate_ids = sorted(
        identity
        for identity, count in Counter(str(row.get("id") or "") for row in transfer_rows).items()
        if identity and count > 1
    )
    blockers: list[str] = []
    if not transfer_rows:
        blockers.append("missing_stage_a_semantic_transfer_contracts")
    if functions_without_transfers:
        blockers.append("functions_without_stage_a_semantic_transfers")
    if incomplete_transfers:
        blockers.append("incomplete_stage_a_semantic_transfers")
    if unsupported_models:
        blockers.append("unsupported_stage_a_semantic_ir_model")
    if duplicate_ids:
        blockers.append("duplicate_stage_a_semantic_transfer_ids")
    return {
        "format": "stage-b-state-machine-coverage-v1",
        "status": "complete" if not blockers else "incomplete",
        "authority": "stage-a-semantic-transfer-contracts",
        "expression_model": STAGE_A_SEMANTIC_IR_MODEL,
        "counts": {
            "functions": len(function_rows),
            "functions_with_transfers": len(function_rows) - len(functions_without_transfers),
            "functions_without_transfers": len(functions_without_transfers),
            "transfers": len(transfer_rows),
            "incomplete_transfers": len(incomplete_transfers),
            "unsupported_models": len(unsupported_models),
            "duplicate_ids": len(duplicate_ids),
        },
        "status_counts": dict(sorted(status_counts.items())),
        "expression_model_counts": dict(sorted(model_counts.items())),
        "functions_without_transfers": functions_without_transfers[:100],
        "incomplete_transfers": incomplete_transfers[:100],
        "unsupported_models": unsupported_models[:100],
        "duplicate_ids": duplicate_ids[:100],
        "blockers": blockers,
    }


def function_state_machine_binding(function: dict[str, Any]) -> dict[str, Any] | None:
    reference = function.get("reference_contract")
    bytecode = reference.get("semantic_transfer_bytecode") if isinstance(reference, dict) else None
    transfers = bytecode.get("transfers") if isinstance(bytecode, dict) else None
    if not isinstance(transfers, list):
        return None
    rows = [normalize_stage_a_semantic_transfer(row) for row in transfers if isinstance(row, dict)]
    return state_machine_binding_from_rows(rows)


def state_machine_binding_from_rows(rows: Iterable[dict[str, Any]]) -> dict[str, Any] | None:
    rows = list(rows)
    if not rows:
        return None
    return {
        "format": "stage-b-source-state-machine-binding-v1",
        "authority": "stage-a-semantic-transfer-contracts",
        "expression_model": STAGE_A_SEMANTIC_IR_MODEL,
        "transfer_ids": [str(row.get("id") or "") for row in rows],
        "contract_sha256": [str(row["contract_sha256"]) for row in rows],
        "status_counts": dict(sorted(Counter(str(row.get("status") or "unspecified") for row in rows).items())),
    }


def stage_b_state_machine_source_coverage(
    coverage: dict[str, Any],
    rows: Iterable[dict[str, Any]],
    source_map: dict[str, Any],
) -> dict[str, Any]:
    transfer_rows = list(rows)
    bound_ids: set[str] = set()
    source_functions = source_map.get("functions") if isinstance(source_map.get("functions"), list) else []
    for function in source_functions:
        binding = function.get("state_machine") if isinstance(function, dict) else None
        transfer_ids = binding.get("transfer_ids") if isinstance(binding, dict) else None
        if isinstance(transfer_ids, list):
            bound_ids.update(str(item) for item in transfer_ids if isinstance(item, str) and item)
    source_transfers = source_map.get("transfers") if isinstance(source_map.get("transfers"), list) else []
    for transfer in source_transfers:
        identity = transfer.get("id") if isinstance(transfer, dict) else None
        if isinstance(identity, str) and identity:
            bound_ids.add(identity)
    unbound = [
        _transfer_reference(row)
        for row in transfer_rows
        if str(row.get("id") or "") not in bound_ids
    ]
    updated = dict(coverage)
    blockers = list(updated.get("blockers") or [])
    if unbound and "semantic_transfers_without_generated_source_binding" not in blockers:
        blockers.append("semantic_transfers_without_generated_source_binding")
    counts = dict(updated.get("counts") or {})
    counts["source_bound_transfers"] = len(transfer_rows) - len(unbound)
    counts["source_unbound_transfers"] = len(unbound)
    updated["counts"] = counts
    updated["source_binding"] = {
        "status": "complete" if not unbound else "incomplete",
        "bound_transfers": len(transfer_rows) - len(unbound),
        "unbound_transfers": len(unbound),
        "unbound": unbound[:100],
    }
    updated["blockers"] = blockers
    updated["status"] = "complete" if not blockers else "incomplete"
    return updated


def _function_has_transfer(function: dict[str, Any]) -> bool:
    reference = function.get("reference_contract")
    bytecode = reference.get("semantic_transfer_bytecode") if isinstance(reference, dict) else None
    transfers = bytecode.get("transfers") if isinstance(bytecode, dict) else None
    return isinstance(transfers, list) and any(isinstance(row, dict) for row in transfers)


def _function_reference(function: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(function.get("name") or ""),
        "rva_start": function.get("rva_start"),
        "rva_end": function.get("rva_end"),
    }


def _transfer_reference(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row.get("id"),
        "function": row.get("function"),
        "block_id": row.get("block_id"),
        "rva_start": _transfer_start(row),
        "status": row.get("status"),
        "expression_model": row.get("expression_model"),
        "blocker_category": row.get("blocker_category"),
        "blocker": row.get("blocker"),
        "next_action": row.get("next_action"),
    }


def _transfer_start(row: dict[str, Any]) -> int:
    original = row.get("original")
    value = original.get("rva_start") if isinstance(original, dict) else row.get("rva_start")
    return int(value) if isinstance(value, int) else 0x7FFFFFFF


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _json_value(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))
