from __future__ import annotations

import json
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import pefile

from .stage_binary import StageAInputError
from .util import sha256_bytes, sha256_file


STAGE_B_STATE_MACHINE_FORMAT = "stage-b-state-machine-transfer-v1"
STAGE_A_SEMANTIC_IR_MODEL = "stage-a-semantic-ir-v1"
STAGE_A_REFERENCE_CONTRACT_FORMAT = "stage-a-reference-contract-v1"
STAGE_A_SEMANTIC_TRANSFER_FORMAT = "stage-a-semantic-transfer-contract-v1"
STAGE_A_SEMANTIC_EXPORT_BINDING_FORMAT = "stage-a-semantic-export-binding-v1"

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


@dataclass(frozen=True)
class StageAReferenceContractBinding:
    path: Path
    sha256: str
    original_pe_sha256: str
    semantic_transfer_contracts: Path


@dataclass(frozen=True)
class StageBStateMachineBinding:
    path: Path
    sha256: str
    reference_contract_sha256: str
    semantic_transfer_contracts_sha256: str
    transfer_count: int


def load_stage_a_reference_contract_binding(
    path: Path,
    *,
    original_pe: Path | None = None,
) -> StageAReferenceContractBinding:
    """Validate the public Stage A export fields used by the opaque handoff."""

    path = Path(path).resolve()
    payload = _read_json_object(path, "Stage A reference contract")
    expected_fields = {
        "format", "generator", "generated_at", "model", "status", "tool_versions",
        "inputs", "original", "candidate", "constraints", "families", "coverage",
        "assumptions", "issues", "counts", "sidecars",
    }
    if set(payload) != expected_fields:
        raise StageAInputError(
            "Stage A reference contract schema does not match the public export format"
        )
    if payload.get("format") != STAGE_A_REFERENCE_CONTRACT_FORMAT:
        raise StageAInputError(
            f"Stage A reference contract must have format {STAGE_A_REFERENCE_CONTRACT_FORMAT}"
        )
    if payload.get("generator") != "stage-a-export-reference-contract":
        raise StageAInputError(
            "Stage A reference contract was not produced by the public export interface"
        )
    model = payload.get("model")
    if not isinstance(model, str) or not model.startswith("x86-pe32-"):
        raise StageAInputError("Stage A reference contract is not an x86 PE32 contract")

    original = _object(payload.get("original"), "Stage A reference contract original")
    inputs = _object(payload.get("inputs"), "Stage A reference contract inputs")
    if set(inputs) != {
        "original", "candidate", "mapping", "validation_report", "layout_contract"
    }:
        raise StageAInputError("Stage A reference contract input inventory has schema drift")
    original_input = _object(inputs.get("original"), "Stage A reference contract original input")
    original_digest = _digest(original.get("sha256"), "reference contract original.sha256")
    input_digest = _digest(
        original_input.get("sha256"), "reference contract inputs.original.sha256"
    )
    if original_digest != input_digest or original_input.get("exists") is not True:
        raise StageAInputError("Stage A reference contract has inconsistent original PE bindings")
    if original.get("machine") != "i386" or original.get("bitness") != 32:
        raise StageAInputError("Stage A reference contract original is not i386 PE32")
    if original_pe is not None:
        original_pe = Path(original_pe).resolve()
        if not original_pe.is_file() or original_pe.is_symlink():
            raise StageAInputError("opaque Stage B provenance original must be a regular PE file")
        if sha256_file(original_pe) != original_digest:
            raise StageAInputError("Stage A reference contract is not bound to the supplied original PE")
        try:
            pe = pefile.PE(data=original_pe.read_bytes(), fast_load=True)
        except (OSError, pefile.PEFormatError) as exc:
            raise StageAInputError(f"opaque Stage B provenance original is not a PE: {exc}") from exc
        if int(pe.FILE_HEADER.Machine) != 0x14C or int(pe.OPTIONAL_HEADER.Magic) != 0x10B:
            raise StageAInputError("opaque Stage B provenance original is not i386 PE32")

    sidecars = _object(payload.get("sidecars"), "Stage A reference contract sidecars")
    unit = _object(sidecars.get("unit_contracts"), "Stage A unit-contract sidecars")
    directory_raw = unit.get("directory")
    if not isinstance(directory_raw, str) or not directory_raw:
        raise StageAInputError("Stage A reference contract omits its unit-contract directory")
    semantic_spec = _object(
        unit.get("semantic_transfer_contracts"),
        "Stage A semantic-transfer sidecar",
    )
    semantic_raw = semantic_spec.get("path")
    if not isinstance(semantic_raw, str) or not semantic_raw:
        raise StageAInputError("Stage A reference contract omits semantic-transfer contracts")
    directory = Path(directory_raw)
    if not directory.is_absolute():
        directory = path.parent / directory
    semantic_path = Path(semantic_raw)
    if not semantic_path.is_absolute():
        semantic_path = directory / semantic_path
    semantic_path = semantic_path.resolve()
    return StageAReferenceContractBinding(
        path=path,
        sha256=sha256_file(path),
        original_pe_sha256=original_digest,
        semantic_transfer_contracts=semantic_path,
    )


def normalize_stage_a_semantic_transfer(
    row: dict[str, Any],
    *,
    reference_contract_sha256: str | None = None,
    semantic_transfer_sha256: str | None = None,
) -> dict[str, Any]:
    """Preserve the checked Stage A transfer IR used to generate Stage B source."""

    normalized = {
        key: _json_value(row[key])
        for key in _TRANSFER_FIELDS
        if key in row
    }
    source_bytes = _canonical_json(normalized)
    normalized["stage_b_format"] = STAGE_B_STATE_MACHINE_FORMAT
    normalized["contract_sha256"] = sha256_bytes(source_bytes)
    existing_binding = row.get("stage_a_export")
    if existing_binding is not None:
        binding = _parse_semantic_export_binding(existing_binding)
        if reference_contract_sha256 is not None and (
            binding["reference_contract_sha256"] != reference_contract_sha256
        ):
            raise StageAInputError("state-machine reference-contract binding changed")
        if semantic_transfer_sha256 is not None and (
            binding["semantic_transfer_sha256"] != semantic_transfer_sha256
        ):
            raise StageAInputError("state-machine semantic-transfer binding changed")
        normalized["stage_a_export"] = binding
    elif reference_contract_sha256 is not None or semantic_transfer_sha256 is not None:
        normalized["stage_a_export"] = {
            "format": STAGE_A_SEMANTIC_EXPORT_BINDING_FORMAT,
            "reference_contract_sha256": _digest(
                reference_contract_sha256, "semantic export reference contract"
            ),
            "semantic_transfer_sha256": _digest(
                semantic_transfer_sha256, "semantic export transfer"
            ),
        }
    return normalized


def write_stage_b_state_machine_from_stage_a_export(
    *,
    reference_contract: Path,
    semantic_transfer_contracts: Path,
    out: Path,
    original_pe: Path | None = None,
) -> StageBStateMachineBinding:
    """Derive the canonical Stage B state machine from public Stage A exports."""

    reference = load_stage_a_reference_contract_binding(
        reference_contract, original_pe=original_pe
    )
    semantic_path = Path(semantic_transfer_contracts).resolve()
    if not semantic_path.is_file() or semantic_path.is_symlink():
        raise StageAInputError("Stage A semantic-transfer sidecar must be a regular file")
    declared_semantic = reference.semantic_transfer_contracts
    if (
        semantic_path != declared_semantic
        and declared_semantic.is_file()
        and sha256_file(semantic_path) != sha256_file(declared_semantic)
    ):
        raise StageAInputError(
            "semantic-transfer input is not the sidecar declared by the reference contract"
        )
    raw_rows = _load_stage_a_semantic_transfer_rows(semantic_path, reference)
    rows = [
        normalize_stage_a_semantic_transfer(
            row,
            reference_contract_sha256=reference.sha256,
            semantic_transfer_sha256=sha256_bytes(_canonical_json(row)),
        )
        for row in raw_rows
    ]
    rows = normalize_stage_a_semantic_transfers(rows)
    if not rows:
        raise StageAInputError("Stage A semantic-transfer export is empty")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_stage_b_state_machine(out, rows)
    return StageBStateMachineBinding(
        path=out.resolve(),
        sha256=sha256_file(out),
        reference_contract_sha256=reference.sha256,
        semantic_transfer_contracts_sha256=sha256_file(semantic_path),
        transfer_count=len(rows),
    )


def validate_stage_b_state_machine_export_chain(
    *,
    state_machine: Path,
    reference_contract: Path,
    semantic_transfer_contracts: Path,
    original_pe: Path | None = None,
) -> StageBStateMachineBinding:
    """Check that a state machine is exactly reproducible from its Stage A exports."""

    state_machine = Path(state_machine).resolve()
    with tempfile.TemporaryDirectory(prefix="stage-b-state-machine-check-") as temporary:
        expected_path = Path(temporary) / "expected.jsonl"
        expected = write_stage_b_state_machine_from_stage_a_export(
            reference_contract=reference_contract,
            semantic_transfer_contracts=semantic_transfer_contracts,
            out=expected_path,
            original_pe=original_pe,
        )
        if state_machine.is_symlink() or not state_machine.is_file():
            raise StageAInputError("Stage B state machine must be a regular non-symlink file")
        observed_sha = sha256_file(state_machine)
        if observed_sha != expected.sha256:
            raise StageAInputError(
                "Stage B state machine is not the canonical derivative of the Stage A exports"
            )
        return StageBStateMachineBinding(
            path=state_machine,
            sha256=observed_sha,
            reference_contract_sha256=expected.reference_contract_sha256,
            semantic_transfer_contracts_sha256=expected.semantic_transfer_contracts_sha256,
            transfer_count=expected.transfer_count,
        )


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


def _load_stage_a_semantic_transfer_rows(
    path: Path,
    reference: StageAReferenceContractBinding,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"Stage A semantic-transfer line {line_number} is invalid JSON: {exc}"
            ) from exc
        row = _object(raw, f"Stage A semantic-transfer line {line_number}")
        expected_fields = set(_TRANSFER_FIELDS) | {"reference_contract"}
        missing = sorted(expected_fields - set(row))
        extra = sorted(set(row) - expected_fields)
        if missing or extra:
            raise StageAInputError(
                f"Stage A semantic-transfer line {line_number} has schema drift: "
                f"missing={missing}, extra={extra}"
            )
        if row.get("format") != STAGE_A_SEMANTIC_TRANSFER_FORMAT:
            raise StageAInputError(
                f"Stage A semantic-transfer line {line_number} has an unsupported format"
            )
        identity = row.get("id")
        if not isinstance(identity, str) or not identity:
            raise StageAInputError(
                f"Stage A semantic-transfer line {line_number} omits its identity"
            )
        if identity in seen_ids:
            raise StageAInputError(f"Stage A semantic-transfer identity is duplicated: {identity}")
        seen_ids.add(identity)
        if not isinstance(row.get("reachable"), bool):
            raise StageAInputError(
                f"Stage A semantic-transfer line {line_number} has invalid reachability"
            )
        if row.get("expression_model") != STAGE_A_SEMANTIC_IR_MODEL:
            raise StageAInputError(
                f"Stage A semantic-transfer line {line_number} has an unsupported expression model"
            )
        for field in (
            "instructions", "register_writes", "flag_writes", "memory_events",
            "external_events", "faults", "ordered_events", "edge_conditions",
        ):
            if not isinstance(row.get(field), list):
                raise StageAInputError(
                    f"Stage A semantic-transfer line {line_number}.{field} must be a list"
                )
        instruction_bytes = bytearray()
        for instruction_index, instruction_raw in enumerate(row["instructions"]):
            instruction = _object(
                instruction_raw,
                f"Stage A semantic-transfer line {line_number} instruction {instruction_index}",
            )
            encoded = instruction.get("bytes")
            if not isinstance(encoded, str):
                raise StageAInputError(
                    f"Stage A semantic-transfer line {line_number} has missing instruction bytes"
                )
            try:
                instruction_bytes.extend(bytes.fromhex(encoded))
            except ValueError as exc:
                raise StageAInputError(
                    f"Stage A semantic-transfer line {line_number} has invalid instruction bytes"
                ) from exc
        instruction_digest = _digest(
            row.get("instruction_bytes_sha256"),
            f"Stage A semantic-transfer line {line_number} instruction digest",
        )
        if sha256_bytes(bytes(instruction_bytes)) != instruction_digest:
            raise StageAInputError(
                f"Stage A semantic-transfer line {line_number} instruction digest changed"
            )
        contract = _object(
            row.get("reference_contract"),
            f"Stage A semantic-transfer line {line_number} reference contract",
        )
        if contract.get("format") != STAGE_A_REFERENCE_CONTRACT_FORMAT:
            raise StageAInputError(
                f"Stage A semantic-transfer line {line_number} has an invalid contract format"
            )
        if contract.get("sha256") != reference.sha256:
            raise StageAInputError(
                f"Stage A semantic-transfer line {line_number} is not bound to the reference contract"
            )
        rows.append(dict(row))
    return rows


def _parse_semantic_export_binding(value: Any) -> dict[str, str]:
    binding = _object(value, "state-machine Stage A export binding")
    expected = {
        "format",
        "reference_contract_sha256",
        "semantic_transfer_sha256",
    }
    if set(binding) != expected:
        raise StageAInputError("state-machine Stage A export binding has undeclared fields")
    if binding.get("format") != STAGE_A_SEMANTIC_EXPORT_BINDING_FORMAT:
        raise StageAInputError("state-machine Stage A export binding has an unsupported format")
    return {
        "format": STAGE_A_SEMANTIC_EXPORT_BINDING_FORMAT,
        "reference_contract_sha256": _digest(
            binding.get("reference_contract_sha256"), "state-machine reference contract"
        ),
        "semantic_transfer_sha256": _digest(
            binding.get("semantic_transfer_sha256"), "state-machine semantic transfer"
        ),
    }


def _read_json_object(path: Path, context: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise StageAInputError(f"{context} must be a regular non-symlink file")
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context}: {exc}") from exc


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return dict(value)


def _digest(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise StageAInputError(f"{context} must be a lowercase SHA-256 digest")
    return value


__all__ = [
    "STAGE_A_REFERENCE_CONTRACT_FORMAT",
    "STAGE_A_SEMANTIC_EXPORT_BINDING_FORMAT",
    "STAGE_A_SEMANTIC_IR_MODEL",
    "STAGE_A_SEMANTIC_TRANSFER_FORMAT",
    "STAGE_B_STATE_MACHINE_FORMAT",
    "StageAReferenceContractBinding",
    "StageBStateMachineBinding",
    "function_state_machine_binding",
    "load_stage_a_reference_contract_binding",
    "normalize_stage_a_semantic_transfer",
    "normalize_stage_a_semantic_transfers",
    "stage_b_state_machine_coverage",
    "stage_b_state_machine_source_coverage",
    "state_machine_binding_from_rows",
    "state_machine_rows_from_functions",
    "validate_stage_b_state_machine_export_chain",
    "write_stage_b_state_machine",
    "write_stage_b_state_machine_from_stage_a_export",
]
