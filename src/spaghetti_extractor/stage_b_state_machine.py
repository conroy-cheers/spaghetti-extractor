from __future__ import annotations

import json
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

import capstone
import pefile
from capstone.x86 import X86_OP_MEM, X86_OP_REG

from .artifact_formats import (
    SEMANTIC_IR_FORMAT,
    SEMANTIC_TRANSFER_CONTRACT_FORMAT,
)
from .machine_import_profiles import load_machine_import_profile_set
from .stage_binary import StageAInputError
from .util import sha256_bytes, sha256_file


STAGE_B_STATE_MACHINE_FORMAT = "stage-b-state-machine-transfer-v1"
STAGE_A_SEMANTIC_IR_MODEL = SEMANTIC_IR_FORMAT
STAGE_A_REFERENCE_CONTRACT_FORMAT = "stage-a-reference-contract-v1"
STAGE_A_SEMANTIC_TRANSFER_FORMAT = SEMANTIC_TRANSFER_CONTRACT_FORMAT
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

_OPTIONAL_TRANSFER_FIELDS = (
    "instruction_effect_schedule",
    "semantic_cutpoint",
    "control_disposition",
    "blocking_instruction",
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


@dataclass(frozen=True)
class StageBPaddingBridgeResult:
    path: Path
    sha256: str
    input_transfer_count: int
    padding_bridge_count: int
    output_transfer_count: int
    bridged_rvas: tuple[int, ...]
    terminating_transfer_rvas: tuple[int, ...]


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
        for key in (*_TRANSFER_FIELDS, *_OPTIONAL_TRANSFER_FIELDS)
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


def augment_state_machine_with_padding_bridges(
    *,
    state_machine: Path,
    original_pe: Path,
    block_map: Path,
    external_profile: Path | None = None,
    out: Path,
) -> StageBPaddingBridgeResult:
    """Close direct control targets that enter checked semantic no-op padding.

    The block map and Capstone decode are untrusted proposal inputs.  Generated
    rows retain the exact bytes so the ordinary Lean decode/normalization path
    must independently prove that every bridge preserves the machine state.
    """

    state_machine = Path(state_machine).resolve()
    original_pe = Path(original_pe).resolve()
    block_map = Path(block_map).resolve()
    rows = _read_state_machine_rows(state_machine)
    if not rows:
        raise StageAInputError("padding bridge input state machine is empty")
    starts = {_transfer_start(row) for row in rows}
    if len(starts) != len(rows):
        raise StageAInputError("padding bridge input has duplicate transfer RVAs")
    machine_import_contracts = _machine_import_contracts(external_profile)
    rows = [
        _annotate_machine_import_arguments(row, machine_import_contracts)
        for row in rows
    ]
    terminating_imports = frozenset(
        identity
        for identity, contract in machine_import_contracts.items()
        if contract.get("disposition") == "terminates"
    )
    terminating_rows = {
        _transfer_start(row)
        for row in rows
        if _row_calls_terminating_import(row, terminating_imports)
    }
    direct_targets = {
        target
        for row in rows
        if _transfer_start(row) not in terminating_rows
        for target in _semantic_direct_targets(row)
    }
    missing = sorted(direct_targets - starts)

    try:
        pe_data = original_pe.read_bytes()
        pe = pefile.PE(data=pe_data, fast_load=True)
    except (OSError, pefile.PEFormatError) as exc:
        raise StageAInputError(f"padding bridge original is not a PE: {exc}") from exc
    if int(pe.FILE_HEADER.Machine) != 0x14C or int(pe.OPTIONAL_HEADER.Magic) != 0x10B:
        raise StageAInputError("padding bridge original must be i386 PE32")
    mapping = _read_json_object(block_map, "padding bridge block map")
    raw_waivers = mapping.get("waivers")
    if not isinstance(raw_waivers, list):
        raise StageAInputError("padding bridge block map has no waiver inventory")
    waivers = tuple(
        _padding_waiver_span(value, index)
        for index, value in enumerate(raw_waivers)
        if isinstance(value, dict) and value.get("binary") in {"original", "both"}
    )

    bridges: list[dict[str, Any]] = []
    occupied = [
        (_transfer_start(row), _transfer_end(row))
        for row in rows
    ]
    for target in missing:
        matches = [span for span in waivers if span[0] <= target < span[1]]
        if len(matches) != 1:
            raise StageAInputError(
                f"direct target 0x{target:x} has {len(matches)} matching padding waivers"
            )
        _waiver_start, waiver_end, waiver_id = matches[0]
        if any(start <= target < end for start, end in occupied):
            raise StageAInputError(
                f"direct target 0x{target:x} overlaps an existing semantic transfer"
            )
        encoded = bytes(pe.get_data(target, waiver_end - target))
        if len(encoded) != waiver_end - target or not encoded:
            raise StageAInputError(
                f"padding bridge 0x{target:x}-0x{waiver_end:x} is not fully file-backed"
            )
        instructions = _decode_semantic_padding(
            encoded,
            image_base=int(pe.OPTIONAL_HEADER.ImageBase),
            rva_start=target,
        )
        bridge = normalize_stage_a_semantic_transfer(
            _padding_bridge_transfer(
                rva_start=target,
                rva_end=waiver_end,
                waiver_id=waiver_id,
                encoded=encoded,
                instructions=instructions,
            )
        )
        bridges.append(bridge)
        occupied.append((target, waiver_end))

    annotated_rows = [
        {
            **row,
            "control_disposition": {
                "kind": "terminates_after_external_event",
                "authority": "external_profile_machine_import_contract",
            },
        }
        if _transfer_start(row) in terminating_rows
        else row
        for row in rows
    ]
    augmented = normalize_stage_a_semantic_transfers([*annotated_rows, *bridges])
    augmented_starts = {_transfer_start(row) for row in augmented}
    remaining = sorted(
        target
        for row in augmented
        if _transfer_start(row) not in terminating_rows
        for target in _semantic_direct_targets(row)
        if target not in augmented_starts
    )
    if remaining:
        rendered = ", ".join(f"0x{target:x}" for target in remaining[:16])
        raise StageAInputError(
            "padding bridge augmentation left unresolved direct targets: " + rendered
        )
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_stage_b_state_machine(out, augmented)
    return StageBPaddingBridgeResult(
        path=out.resolve(),
        sha256=sha256_file(out),
        input_transfer_count=len(rows),
        padding_bridge_count=len(bridges),
        output_transfer_count=len(augmented),
        bridged_rvas=tuple(sorted(_transfer_start(row) for row in bridges)),
        terminating_transfer_rvas=tuple(sorted(terminating_rows)),
    )


def _read_state_machine_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        raise StageAInputError("padding bridge state machine must be a regular file")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"invalid state-machine JSON on line {line_number}: {exc}"
            ) from exc
        rows.append(_object(value, f"state-machine line {line_number}"))
    return rows


def _semantic_direct_targets(row: Mapping[str, Any]) -> tuple[int, ...]:
    outcome = _object(row.get("outcome"), "semantic transfer outcome")
    kind = outcome.get("kind")
    if kind in {"fallthrough", "jump"}:
        return (_u32(outcome.get("target_rva"), "semantic direct target"),)
    if kind == "branch":
        return (
            _u32(outcome.get("true_target_rva"), "semantic true target"),
            _u32(outcome.get("false_target_rva"), "semantic false target"),
        )
    return ()


def _terminating_imports(external_profile: Path | None) -> frozenset[tuple[str, str, Any]]:
    return frozenset(
        identity
        for identity, contract in _machine_import_contracts(external_profile).items()
        if contract.get("disposition") == "terminates"
    )


def _machine_import_contracts(
    external_profile: Path | None,
) -> dict[tuple[str, str, Any], dict[str, Any]]:
    if external_profile is None:
        return {}
    profile_set = load_machine_import_profile_set([Path(external_profile).resolve()])
    result: dict[tuple[str, str, Any], dict[str, Any]] = {}
    for selected in profile_set.contracts:
        # A variadic profile describes the minimum call shape, not the exact
        # stack inventory.  It cannot safely synthesize concrete arguments.
        if selected.arity_kind != "fixed":
            continue
        contract = dict(selected.contract)
        contract["profile_binding"] = {
            "profile_id": selected.profile_id,
            "profile_sha256": selected.profile_sha256,
            "entry_key": selected.entry_key,
            "entry_index": selected.entry_index,
        }
        identity = selected.identity.state_machine_key()
        argument_words = selected.argument_words
        if (
            not isinstance(argument_words, int)
            or isinstance(argument_words, bool)
            or argument_words < 0
            or argument_words > 64
        ):
            raise StageAInputError(
                f"external profile contract {contract['id']!r} has invalid argument_words"
            )
        if contract.get("abi_template") not in {
            "pe32-cdecl-v1",
            "pe32-stdcall-v1",
        }:
            raise StageAInputError(
                f"external profile contract {contract['id']!r} has unsupported ABI template"
            )
        world_effect = contract.get("world_effect")
        callback_abi = contract.get("callback_abi")
        if world_effect == "callbackRegistration":
            if not isinstance(callback_abi, dict) or set(callback_abi) != {
                "kind", "argument_words", "stack_cleanup_bytes", "nullable",
            }:
                raise StageAInputError(
                    f"external profile contract {contract['id']!r} has no exact callback ABI"
                )
            callback_argument_words = callback_abi.get("argument_words")
            callback_cleanup = callback_abi.get("stack_cleanup_bytes")
            if (
                callback_abi.get("kind") != "generic_callback"
                or not isinstance(callback_argument_words, int)
                or isinstance(callback_argument_words, bool)
                or not 0 <= callback_argument_words <= 64
                or not isinstance(callback_cleanup, int)
                or isinstance(callback_cleanup, bool)
                or not 0 <= callback_cleanup <= 0xFFFF
                or not isinstance(callback_abi.get("nullable"), bool)
            ):
                raise StageAInputError(
                    f"external profile contract {contract['id']!r} has an invalid callback ABI"
                )
            world_effect_argument = contract.get("world_effect_argument")
            if (
                not isinstance(world_effect_argument, int)
                or isinstance(world_effect_argument, bool)
                or not 0 <= world_effect_argument < argument_words
            ):
                raise StageAInputError(
                    f"external profile contract {contract['id']!r} has an invalid callback argument"
                )
            callback_lifetime = contract.get("callback_lifetime")
            if not isinstance(callback_lifetime, (str, dict)) or not callback_lifetime:
                raise StageAInputError(
                    f"external profile contract {contract['id']!r} has no exact callback lifetime"
                )
        elif callback_abi is not None:
            raise StageAInputError(
                f"external profile contract {contract['id']!r} attaches a callback ABI to a non-callback effect"
            )
        result[identity] = contract
    return result


def _annotate_machine_import_arguments(
    row: dict[str, Any],
    contracts: Mapping[tuple[str, str, Any], dict[str, Any]],
) -> dict[str, Any]:
    if not contracts:
        return row

    outcome = _object(row.get("outcome"), "semantic transfer outcome")
    argument_base_offset = 4 if outcome.get("kind") == "external_jump" else 0

    def annotate(raw: Any, label: str) -> dict[str, Any]:
        event = dict(_object(raw, label))
        if event.get("kind") != "external_call":
            return event
        dll = event.get("dll")
        symbol = event.get("symbol")
        ordinal = event.get("ordinal")
        if not isinstance(dll, str):
            return event
        contract = contracts.get(
            (dll.lower(), str(symbol) if symbol is not None else "", ordinal)
        )
        if contract is None:
            return event
        argument_words = int(contract["argument_words"])
        arguments = event.get("arguments")
        if not isinstance(arguments, list):
            raise StageAInputError(f"{label} arguments must be a list")
        if arguments and len(arguments) != argument_words:
            raise StageAInputError(
                f"{label} argument inventory differs from its machine-call contract"
            )
        if not arguments:
            arguments = [
                _cdecl_stack_word_expression(
                    index, base_offset=argument_base_offset
                )
                for index in range(argument_words)
            ]
            event["arguments"] = arguments
        stack_inputs = event.get("stack_inputs")
        if stack_inputs is not None and not isinstance(stack_inputs, list):
            raise StageAInputError(f"{label} stack_inputs must be a list")
        if not stack_inputs:
            event["stack_inputs"] = [
                {
                    "offset": argument_base_offset + index * 4,
                    "width": 4,
                    "value": value,
                }
                for index, value in enumerate(arguments)
            ]
        abi_contract = {
            "template": contract["abi_template"],
            "argument_words": argument_words,
            "argument_base_offset": argument_base_offset,
            "contract_id": contract.get("id"),
            "disposition": contract.get("disposition", "returns"),
            "result_register_relations": _machine_contract_metadata(
                contract.get("result_register_relations", [])
            ),
            "memory_effect": contract.get("memory_effect", "none"),
            "memory_footprints": _machine_contract_metadata(
                contract.get("memory_footprints", [])
            ),
            "world_effect": contract.get("world_effect", "none"),
        }
        profile_binding = contract.get("profile_binding")
        if isinstance(profile_binding, Mapping):
            abi_contract["profile_binding"] = dict(profile_binding)
        if contract.get("world_effect") == "callbackRegistration":
            abi_contract.update({
                "world_effect_argument": contract["world_effect_argument"],
                "callback_abi": dict(contract["callback_abi"]),
                "callback_behavior": contract.get(
                    "callback_behavior", "registration"
                ),
                "callback_lifetime": _machine_contract_metadata(
                    contract.get("callback_lifetime")
                ),
            })
        event["abi_contract"] = abi_contract
        return event

    result = dict(row)
    external_events = row.get("external_events")
    if not isinstance(external_events, list):
        raise StageAInputError("semantic transfer external_events must be a list")
    ordered_events = row.get("ordered_events")
    if not isinstance(ordered_events, list):
        raise StageAInputError("semantic transfer ordered_events must be a list")
    result["external_events"] = [
        annotate(event, f"semantic external event {index}")
        for index, event in enumerate(external_events)
    ]
    result["ordered_events"] = [
        annotate(event, f"semantic ordered event {index}")
        for index, event in enumerate(ordered_events)
    ]
    schedule = row.get("instruction_effect_schedule")
    if schedule is not None:
        enriched_schedule = _annotate_machine_import_instruction_schedule(
            schedule=schedule,
            aggregate_ordered_events=result["ordered_events"],
            annotate=annotate,
        )
        result["instruction_effect_schedule"] = enriched_schedule

        fpu_state = row.get("fpu_state")
        if isinstance(fpu_state, Mapping):
            replay = fpu_state.get("replay")
            if isinstance(replay, Mapping) and "instruction_effect_schedule" in replay:
                if replay.get("instruction_effect_schedule") != schedule:
                    raise StageAInputError(
                        "FPU replay and transfer instruction effect schedules differ"
                    )
                enriched_fpu = _json_value(fpu_state)
                enriched_replay = _object(
                    enriched_fpu.get("replay"), "FPU replay metadata"
                )
                enriched_replay["instruction_effect_schedule"] = _json_value(
                    enriched_schedule
                )
                enriched_fpu["replay"] = enriched_replay
                result["fpu_state"] = enriched_fpu
    return result


def _machine_contract_metadata(value: Any) -> Any:
    """Project profile metadata without instruction-byte-shaped field names."""

    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = "byte_count" if raw_key == "bytes" else str(raw_key)
            if key in result:
                raise StageAInputError(
                    f"machine import contract metadata collides at {key!r}"
                )
            result[key] = _machine_contract_metadata(item)
        return result
    if isinstance(value, list):
        return [_machine_contract_metadata(item) for item in value]
    return json.loads(json.dumps(value))


def _annotate_machine_import_instruction_schedule(
    *,
    schedule: Any,
    aggregate_ordered_events: list[dict[str, Any]],
    annotate: Any,
) -> dict[str, Any]:
    source = dict(_object(schedule, "instruction effect schedule"))
    _verify_embedded_digest(
        source, "schedule_sha256", "instruction effect schedule"
    )
    records = source.get("records")
    if not isinstance(records, list):
        raise StageAInputError("instruction effect schedule records must be a list")

    expected_calls = Counter(
        _scheduled_external_call_key(event, "aggregate ordered external call")
        for event in aggregate_ordered_events
        if event.get("kind") == "external_call" and "abi_contract" in event
    )
    observed_calls: Counter[tuple[Any, ...]] = Counter()
    enriched_records: list[dict[str, Any]] = []
    for record_index, raw_record in enumerate(records):
        record = dict(_object(raw_record, f"instruction effect record {record_index}"))
        _verify_embedded_digest(
            record,
            "record_sha256",
            f"instruction effect record {record_index}",
        )
        record_rva = _u32(
            record.get("rva_start"),
            f"instruction effect record {record_index} RVA",
        )
        effects = dict(
            _object(
                record.get("effects"),
                f"instruction effect record {record_index} effects",
            )
        )
        raw_ordered = effects.get("ordered_events")
        raw_calls = effects.get("call_effects")
        if not isinstance(raw_ordered, list) or not isinstance(raw_calls, list):
            raise StageAInputError(
                f"instruction effect record {record_index} call inventories must be lists"
            )

        enriched_ordered: list[dict[str, Any]] = []
        ordered_call_signatures: Counter[tuple[Any, ...]] = Counter()
        for event_index, raw_event in enumerate(raw_ordered):
            event = annotate(
                raw_event,
                f"instruction effect record {record_index} ordered event {event_index}",
            )
            if event.get("kind") == "external_call" and "abi_contract" in event:
                if event.get("instruction_rva") != record_rva:
                    raise StageAInputError(
                        f"instruction effect record {record_index} external call has "
                        "a mismatched instruction RVA"
                    )
                observed_calls[
                    _scheduled_external_call_key(
                        event,
                        f"instruction effect record {record_index} external call",
                    )
                ] += 1
                ordered_call_signatures[
                    _external_call_signature(
                        event,
                        f"instruction effect record {record_index} external call",
                    )
                ] += 1
            enriched_ordered.append(event)

        enriched_calls: list[dict[str, Any]] = []
        call_effect_signatures: Counter[tuple[Any, ...]] = Counter()
        for call_index, raw_call in enumerate(raw_calls):
            call = annotate(
                raw_call,
                f"instruction effect record {record_index} call effect {call_index}",
            )
            if call.get("kind") == "external_call" and "abi_contract" in call:
                call_effect_signatures[
                    _external_call_signature(
                        call,
                        f"instruction effect record {record_index} call effect",
                    )
                ] += 1
            enriched_calls.append(call)
        if call_effect_signatures != ordered_call_signatures:
            raise StageAInputError(
                f"instruction effect record {record_index} call_effects and "
                "ordered_events disagree"
            )

        effects["ordered_events"] = enriched_ordered
        effects["call_effects"] = enriched_calls
        record["effects"] = effects
        record["record_sha256"] = _embedded_digest(record, "record_sha256")
        enriched_records.append(record)

    if observed_calls != expected_calls:
        missing = expected_calls - observed_calls
        extra = observed_calls - expected_calls
        raise StageAInputError(
            "instruction effect schedule and aggregate machine-import calls differ: "
            f"missing={list(missing.elements())[:3]}, "
            f"extra={list(extra.elements())[:3]}"
        )
    source["records"] = enriched_records
    source["schedule_sha256"] = _embedded_digest(source, "schedule_sha256")
    return source


def _scheduled_external_call_key(
    event: Mapping[str, Any], label: str
) -> tuple[Any, ...]:
    return (
        _u32(event.get("instruction_rva"), f"{label} instruction RVA"),
        *_external_call_signature(event, label),
    )


def _external_call_signature(
    event: Mapping[str, Any], label: str
) -> tuple[Any, ...]:
    dll = event.get("dll")
    if not isinstance(dll, str) or not dll:
        raise StageAInputError(f"{label} DLL identity must be a nonempty string")
    symbol = event.get("symbol")
    ordinal = event.get("ordinal")
    if symbol is None and ordinal is None:
        raise StageAInputError(f"{label} has no symbol or ordinal identity")
    return (
        event.get("kind"),
        dll.lower(),
        str(symbol) if symbol is not None else "",
        ordinal,
        event.get("return_rva"),
    )


def _verify_embedded_digest(
    value: Mapping[str, Any], digest_field: str, label: str
) -> None:
    expected = _digest(value.get(digest_field), f"{label} digest")
    if _embedded_digest(value, digest_field) != expected:
        raise StageAInputError(f"{label} digest does not match its canonical contents")


def _embedded_digest(value: Mapping[str, Any], digest_field: str) -> str:
    body = {key: item for key, item in value.items() if key != digest_field}
    return sha256_bytes(_canonical_json(body))


def _cdecl_stack_word_expression(
    index: int, *, base_offset: int = 0
) -> dict[str, Any]:
    address: dict[str, Any] = {"op": "reg", "name": "esp", "width": 32}
    offset = base_offset + index * 4
    if offset != 0:
        address = {
            "op": "add32",
            "args": [
                {"op": "const", "value": offset, "width": 32},
                address,
            ],
        }
    return {"op": "load", "width": 4, "address": address}


def _row_calls_terminating_import(
    row: Mapping[str, Any],
    terminating_imports: frozenset[tuple[str, str, Any]],
) -> bool:
    if not terminating_imports:
        return False
    external_events = row.get("external_events")
    if not isinstance(external_events, list):
        raise StageAInputError("semantic transfer external_events must be a list")
    for index, raw in enumerate(external_events):
        event = _object(raw, f"semantic external event {index}")
        if event.get("kind") != "external_call":
            continue
        dll = event.get("dll")
        symbol = event.get("symbol")
        ordinal = event.get("ordinal")
        if isinstance(dll, str) and (
            dll.lower(), str(symbol) if symbol is not None else "", ordinal
        ) in terminating_imports:
            return True
    return False


def _transfer_end(row: Mapping[str, Any]) -> int:
    original = _object(row.get("original"), "semantic transfer original span")
    return _u32(original.get("rva_end"), "semantic transfer rva_end")


def _padding_waiver_span(value: Mapping[str, Any], index: int) -> tuple[int, int, str]:
    start = _u32(value.get("rva"), f"padding waiver {index} rva")
    size = _nonnegative_int(value.get("size"), f"padding waiver {index} size")
    if size == 0 or start + size >= 2**32:
        raise StageAInputError(f"padding waiver {index} has an invalid span")
    waiver_id = value.get("id")
    if not isinstance(waiver_id, str) or not waiver_id:
        raise StageAInputError(f"padding waiver {index} has no stable identity")
    return start, start + size, waiver_id


def _decode_semantic_padding(
    encoded: bytes,
    *,
    image_base: int,
    rva_start: int,
) -> list[dict[str, Any]]:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoded = list(decoder.disasm(encoded, image_base + rva_start))
    if sum(int(instruction.size) for instruction in decoded) != len(encoded):
        raise StageAInputError(
            f"padding bridge at 0x{rva_start:x} does not decode exactly"
        )
    for instruction in decoded:
        if not _semantic_padding_instruction(instruction):
            raise StageAInputError(
                "padding bridge contains a non-no-op instruction at "
                f"0x{int(instruction.address - image_base):x}: "
                f"{instruction.mnemonic} {instruction.op_str}".rstrip()
            )
    return [
        {
            "rva": int(instruction.address - image_base),
            "size": int(instruction.size),
            "bytes": bytes(instruction.bytes).hex(),
            "mnemonic": instruction.mnemonic,
            "op_str": instruction.op_str,
        }
        for instruction in decoded
    ]


def _semantic_padding_instruction(instruction: Any) -> bool:
    if instruction.mnemonic == "nop":
        return True
    if instruction.mnemonic != "lea" or len(instruction.operands) != 2:
        return False
    destination, source = instruction.operands
    if destination.type != X86_OP_REG or source.type != X86_OP_MEM:
        return False
    memory = source.mem
    return (
        destination.reg == memory.base
        and memory.index == 0
        and memory.disp == 0
    )


def _padding_bridge_transfer(
    *,
    rva_start: int,
    rva_end: int,
    waiver_id: str,
    encoded: bytes,
    instructions: list[dict[str, Any]],
) -> dict[str, Any]:
    identity = f"semantic-transfer:padding-bridge-{rva_start:x}-{rva_end:x}"
    return {
        "format": STAGE_A_SEMANTIC_TRANSFER_FORMAT,
        "id": identity,
        "function": f"padding-bridge-{rva_start:x}",
        "block_id": f"padding-{rva_start:x}-{rva_end:x}",
        "unit_kind": "semantic_transfer",
        "status": "reimplementable",
        "reachable": True,
        "original": {
            "rva_start": rva_start,
            "rva_end": rva_end,
            "size": rva_end - rva_start,
        },
        "instructions": instructions,
        "instruction_bytes_sha256": sha256_bytes(encoded),
        "expression_model": STAGE_A_SEMANTIC_IR_MODEL,
        "pre_state": _canonical_pre_state(),
        "register_writes": [],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "edge_conditions": [{"condition": {"op": "true"}, "target_rva": rva_end}],
        "outcome": {"kind": "fallthrough", "target_rva": rva_end},
        "stack_delta": {
            "status": "derived",
            "net_bytes": 0,
            "expression": {"op": "reg", "name": "esp", "width": 32},
        },
        "fpu_state": None,
        "counts": {
            "register_writes": 0,
            "flag_writes": 0,
            "memory_events": 0,
            "external_events": 0,
            "faults": 0,
            "ordered_events": 0,
            "edge_conditions": 1,
        },
        "acceptance": (
            "untrusted exact padding bridge proposal; Lean decode and semantic "
            "normalization are required"
        ),
        "blocker_category": None,
        "blocker": None,
        "next_action": f"Lean-check exact no-op bridge from waiver {waiver_id}",
    }


def _canonical_pre_state() -> dict[str, Any]:
    return {
        "registers": {
            name: {"op": "reg", "name": name, "width": 32}
            for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        },
        "flags": {
            name: {"op": "flag", "name": name}
            for name in ("cf", "zf", "sf", "of", "pf", "df")
        },
        "memory": {
            "op": "memory",
            "name": "mem0",
            "address_width": 32,
            "value_width": 8,
        },
    }


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


def _transfer_start(row: Mapping[str, Any]) -> int:
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
        allowed_fields = expected_fields | set(_OPTIONAL_TRANSFER_FIELDS)
        missing = sorted(expected_fields - set(row))
        extra = sorted(set(row) - allowed_fields)
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
        if "instruction_effect_schedule" in row and not isinstance(
            row["instruction_effect_schedule"], dict
        ):
            raise StageAInputError(
                f"Stage A semantic-transfer line {line_number}."
                "instruction_effect_schedule must be an object"
            )
        if "blocking_instruction" in row and row["blocking_instruction"] is not None:
            _object(
                row["blocking_instruction"],
                f"Stage A semantic-transfer line {line_number}.blocking_instruction",
            )
        if "semantic_cutpoint" in row:
            cutpoint = _object(
                row["semantic_cutpoint"],
                f"Stage A semantic-transfer line {line_number}.semantic_cutpoint",
            )
            if set(cutpoint) != {"index", "parent_block_id", "policy"}:
                raise StageAInputError(
                    f"Stage A semantic-transfer line {line_number} has an invalid "
                    "semantic-cutpoint schema"
                )
            if (
                not isinstance(cutpoint["index"], int)
                or isinstance(cutpoint["index"], bool)
                or cutpoint["index"] < 0
                or not isinstance(cutpoint["parent_block_id"], str)
                or not cutpoint["parent_block_id"]
                or cutpoint["policy"] != "formal_stopping_instruction_v1"
            ):
                raise StageAInputError(
                    f"Stage A semantic-transfer line {line_number} has invalid "
                    "semantic-cutpoint evidence"
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


def _nonnegative_int(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{context} must be a non-negative integer")
    return value


def _u32(value: Any, context: str) -> int:
    result = _nonnegative_int(value, context)
    if result >= 2**32:
        raise StageAInputError(f"{context} must fit in 32 bits")
    return result


__all__ = [
    "STAGE_A_REFERENCE_CONTRACT_FORMAT",
    "STAGE_A_SEMANTIC_EXPORT_BINDING_FORMAT",
    "STAGE_A_SEMANTIC_IR_MODEL",
    "STAGE_A_SEMANTIC_TRANSFER_FORMAT",
    "STAGE_B_STATE_MACHINE_FORMAT",
    "StageAReferenceContractBinding",
    "StageBPaddingBridgeResult",
    "StageBStateMachineBinding",
    "augment_state_machine_with_padding_bridges",
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
