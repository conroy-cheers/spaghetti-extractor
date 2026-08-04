from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ...stage_b_interpreter_backend import (
    StageBInterpreterError,
    _Transfer,
    _TransferCompiler,
)
from ...stage_binary import StageAInputError


RELATIONAL_INTERPRETER_TRANSFER_FORMAT = (
    "stage-a-relational-interpreter-transfer-v1"
)
RELATIONAL_INTERPRETER_TRANSFER_PROFILE = (
    "memory-effect-free-no-x87-no-call-no-fault-single-exit-v1"
)
RELATIONAL_INTERPRETER_TRANSFER_GENERAL_FORMAT = (
    "stage-a-relational-interpreter-transfer-v2"
)
RELATIONAL_INTERPRETER_TRANSFER_GENERAL_PROFILE = (
    "ordered-flat-memory-control-call-fault-rep-undefined-no-x87-v1"
)
RELATIONAL_INTERPRETER_TRANSFER_INVENTORY_FORMAT = (
    "stage-a-relational-interpreter-transfer-inventory-v1"
)

_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_FIELDS = frozenset(
    {
        "format",
        "profile",
        "source_module",
        "certificate_name",
        "pe_bytes",
        "contract_bytes",
        "instruction_bytes",
        "pe",
        "span",
        "imports",
        "machine_contracts",
        "targets",
        "decoded",
        "normalized",
        "record",
        "exported",
        "pe_parsed",
        "instruction_bytes_read",
        "decoded_from_exact_bytes",
        "normalized_from_decoded",
        "target_map_checked",
        "contract_digest_checked",
        "instruction_digest_checked",
        "instruction_profile_supported",
        "raw_record_decoded",
        "transfer_checked",
        "transfer_profile_supported",
        "source_rva_bound",
        "normalized_profile_supported",
        "semantic_agreement",
    }
)
_GENERAL_FIELDS = frozenset(
    {
        "format",
        "profile",
        "source_module",
        "certificate_name",
        "pe_bytes",
        "contract_bytes",
        "instruction_bytes",
        "pe",
        "span",
        "imports",
        "machine_contracts",
        "targets",
        "decoded",
        "normalized",
        "record",
        "exported",
        "original_macro",
        "original_call_boundaries",
        "footprint",
        "alias_witnesses",
        "target_witnesses",
        "undefined_slots",
        "return_frame_target",
        "external_target",
        "pe_parsed",
        "instruction_bytes_read",
        "decoded_from_exact_bytes",
        "normalized_from_decoded",
        "target_map_checked",
        "contract_digest_checked",
        "instruction_digest_checked",
        "instruction_profile_supported",
        "raw_record_decoded",
        "transfer_checked",
        "transfer_profile_supported",
        "footprint_exact",
        "alias_inventory",
        "source_rva_bound",
        "targets_exact",
        "call_boundaries_exact",
        "call_boundaries_decoded",
        "alias_disjointness",
        "undefined_inventory",
        "undefined_noninterference",
        "indirect_targets_complete",
        "original_macro_decoded",
        "semantic_agreement",
    }
)


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _lean_name(value: object, context: str) -> str:
    if not isinstance(value, str) or _LEAN_NAME.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a qualified Lean identifier")
    return value


def _local_name(value: object, context: str) -> str:
    if not isinstance(value, str) or _LOCAL_NAME.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a local Lean identifier")
    return value


def _validated_artifact(payload: object) -> dict[str, str]:
    artifact = _object(payload, "relational interpreter-transfer artifact")
    missing = sorted(_FIELDS - set(artifact))
    unexpected = sorted(set(artifact) - _FIELDS)
    if missing:
        raise StageAInputError(
            "relational interpreter-transfer artifact is missing required fields: "
            + ", ".join(missing)
        )
    if unexpected:
        raise StageAInputError(
            "relational interpreter-transfer artifact has unexpected fields: "
            + ", ".join(unexpected)
        )
    if artifact["format"] != RELATIONAL_INTERPRETER_TRANSFER_FORMAT:
        raise StageAInputError("unsupported relational interpreter-transfer format")
    if artifact["profile"] != RELATIONAL_INTERPRETER_TRANSFER_PROFILE:
        raise StageAInputError(
            "unsupported interpreter-transfer profile; x87, reads, calls, faults, "
            "and multi-exit transfers remain fail-closed"
        )

    result = {
        field: _lean_name(artifact[field], field)
        for field in _FIELDS
        if field not in {"format", "profile", "certificate_name"}
    }
    result["certificate_name"] = _local_name(
        artifact["certificate_name"], "certificate_name"
    )
    return result


def _validated_general_artifact(payload: object) -> dict[str, str]:
    artifact = _object(payload, "general relational interpreter-transfer artifact")
    missing = sorted(_GENERAL_FIELDS - set(artifact))
    unexpected = sorted(set(artifact) - _GENERAL_FIELDS)
    if missing:
        raise StageAInputError(
            "general relational interpreter-transfer artifact is missing required fields: "
            + ", ".join(missing)
        )
    if unexpected:
        raise StageAInputError(
            "general relational interpreter-transfer artifact has unexpected fields: "
            + ", ".join(unexpected)
        )
    if artifact["format"] != RELATIONAL_INTERPRETER_TRANSFER_GENERAL_FORMAT:
        raise StageAInputError("unsupported general interpreter-transfer format")
    if artifact["profile"] != RELATIONAL_INTERPRETER_TRANSFER_GENERAL_PROFILE:
        raise StageAInputError(
            "unsupported general interpreter-transfer profile; x87 remains a "
            "separate fail-closed proof frontier"
        )
    result = {
        field: _lean_name(artifact[field], field)
        for field in _GENERAL_FIELDS
        if field not in {"format", "profile", "certificate_name"}
    }
    result["certificate_name"] = _local_name(
        artifact["certificate_name"], "certificate_name"
    )
    return result


def relational_interpreter_transfer_source(payload: object) -> str:
    """Compose a checked transfer certificate from named Lean proof objects.

    The generator deliberately emits no `by decide` semantic claim and consumes
    no status field. Expensive byte decoding and universal semantic agreement
    can therefore be proved and cached in separate generated modules.
    """

    artifact = _object(payload, "relational interpreter-transfer artifact")
    if artifact.get("format") == RELATIONAL_INTERPRETER_TRANSFER_GENERAL_FORMAT:
        return _relational_interpreter_general_transfer_source(artifact)
    names = _validated_artifact(artifact)
    certificate = names["certificate_name"]
    arguments = "\n      ".join(
        names[field]
        for field in (
            "pe_bytes",
            "contract_bytes",
            "instruction_bytes",
            "pe",
            "span",
            "imports",
            "machine_contracts",
            "targets",
            "decoded",
            "normalized",
            "record",
            "exported",
        )
    )
    return f"""import StageA.RelationalInterpreterTransfer
import {names['source_module']}

namespace StageA.GeneratedRelational

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer

def {certificate} : InterpreterTransferCertificate
      {arguments} := {{
  original := {{
    peParsed := {names['pe_parsed']}
    instructionBytesRead := {names['instruction_bytes_read']}
    decodedFromExactBytes := {names['decoded_from_exact_bytes']}
    normalizedFromDecoded := {names['normalized_from_decoded']}
    canonicalTargets := {names['target_map_checked']}
  }}
  interpreter := {{
    contractDigestChecked := {names['contract_digest_checked']}
    instructionDigestChecked := {names['instruction_digest_checked']}
    exactInstructionProfile := {names['instruction_profile_supported']}
    rawRecordDecoded := {names['raw_record_decoded']}
    transferChecked := {names['transfer_checked']}
    supportedProfile := {names['transfer_profile_supported']}
  }}
  sourceRvaBound := {names['source_rva_bound']}
  normalizedSupported := {names['normalized_profile_supported']}
  semanticAgreement := {names['semantic_agreement']}
}}

theorem {certificate}MacroStepRefinesOriginal :=
  {certificate}.macroStepRefinesOriginal

theorem {certificate}RawMacroStepRefinesOriginal
    (state : MachineState)
    (environment : StageA.Relational.Interpreter.Environment) :=
  {certificate}.rawMacroStepRefinesOriginal state environment

end StageA.GeneratedRelational
"""


def _relational_interpreter_general_transfer_source(payload: object) -> str:
    names = _validated_general_artifact(payload)
    certificate = names["certificate_name"]
    arguments = "\n      ".join(
        names[field]
        for field in (
            "pe_bytes",
            "contract_bytes",
            "instruction_bytes",
            "pe",
            "span",
            "imports",
            "machine_contracts",
            "targets",
            "decoded",
            "normalized",
            "record",
            "exported",
            "original_macro",
            "original_call_boundaries",
            "footprint",
            "alias_witnesses",
            "target_witnesses",
            "undefined_slots",
            "return_frame_target",
            "external_target",
        )
    )
    return f"""import StageA.RelationalInterpreterTransfer
import {names['source_module']}

namespace StageA.GeneratedRelational

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer

def {certificate} : GeneralInterpreterTransferCertificate
      {arguments} := {{
  original := {{
    peParsed := {names['pe_parsed']}
    instructionBytesRead := {names['instruction_bytes_read']}
    decodedFromExactBytes := {names['decoded_from_exact_bytes']}
    normalizedFromDecoded := {names['normalized_from_decoded']}
    canonicalTargets := {names['target_map_checked']}
  }}
  interpreter := {{
    contractDigestChecked := {names['contract_digest_checked']}
    instructionDigestChecked := {names['instruction_digest_checked']}
    exactInstructionProfile := {names['instruction_profile_supported']}
    rawRecordDecoded := {names['raw_record_decoded']}
    transferChecked := {names['transfer_checked']}
    supportedProfile := {names['transfer_profile_supported']}
    exactFootprint := {names['footprint_exact']}
    aliasInventory := {names['alias_inventory']}
  }}
  sourceRvaBound := {names['source_rva_bound']}
  targetsExact := {names['targets_exact']}
  callBoundariesExact := {names['call_boundaries_exact']}
  callBoundariesDecoded := {names['call_boundaries_decoded']}
  aliasDisjointness := {names['alias_disjointness']}
  undefinedInventory := {names['undefined_inventory']}
  undefinedNoninterference := {names['undefined_noninterference']}
  dynamicTargetsComplete := {names['indirect_targets_complete']}
  originalMacroDecoded := {names['original_macro_decoded']}
  semanticAgreement := {names['semantic_agreement']}
}}

theorem {certificate}MacroStepRefinesOriginal :=
  {certificate}.macroStepRefinesOriginal

theorem {certificate}RawMacroStepRefinesOriginal
    (state : MachineState)
    (environment : StageA.Relational.Interpreter.Environment)
    (undefinedValues : EnvironmentMatchesUndefinedValues
      {names['undefined_slots']} state environment) :=
  {certificate}.rawMacroStepRefinesOriginal state environment undefinedValues

theorem {certificate}MacroStepProducesDecodedResult
    (state : MachineState)
    (environment : StageA.Relational.Interpreter.Environment)
    (undefinedValues : EnvironmentMatchesUndefinedValues
      {names['undefined_slots']} state environment) :=
  {certificate}.macroStepProducesDecodedResult state environment undefinedValues

end StageA.GeneratedRelational
"""


def _counter(counter: Counter[str]) -> dict[str, int]:
    return {key: counter[key] for key in sorted(counter)}


def _outcome_name(transfer: _Transfer) -> str:
    return transfer.actions[-1].op.removeprefix("outcome_")


def _compiled_feature_counts(transfer: _Transfer) -> tuple[Counter[str], Counter[str]]:
    features: Counter[str] = Counter()
    operations: Counter[str] = Counter()
    features["transfer"] = 1
    outcome = _outcome_name(transfer)
    features[f"outcome.{outcome}"] = 1
    for node in transfer.nodes:
        operations[f"word.{node.op}"] += 1
        if node.op == "load":
            features["flat_memory.read"] += 1
        elif node.op in {"undefined_bv", "undefined_flag"}:
            features[f"undefined.{node.op}"] += 1
        elif node.op in {"call_response", "call_flag"}:
            features[f"call_result.{node.op}"] += 1
    for action in transfer.actions[:-1]:
        operations[f"action.{action.op}"] += 1
        if action.op == "memory_write":
            features["flat_memory.write"] += 1
        elif action.op == "divide_if":
            features["fault.divide_error"] += 1
        elif action.op == "rep_movsd":
            features["bulk.rep_movsd"] += 1
        elif action.op in {"rep_movs", "rep_stos", "rep_scas"}:
            features[f"bulk.{action.op}.{action.aux}"] += 1
    for call in transfer.calls:
        features[f"call.{call.kind.removesuffix('_call')}"] += 1
        features["call.exact_machine_boundary"] += 1
        operations[f"call.{call.kind}"] += 1
    if outcome == "branch":
        features["control.exhaustive_branch"] += 1
    elif outcome in {"fallthrough", "jump"}:
        features["control.direct_target"] += 1
    elif outcome == "return":
        features["control.return"] += 1
    elif outcome == "indirect":
        features["control.indirect_target"] += 1
    elif outcome == "external":
        features["control.external_jump"] += 1
    return features, operations


def _raw_ordered_effect_signature(row: Mapping[str, Any]) -> list[tuple[object, ...]]:
    signature: list[tuple[object, ...]] = []
    ordered = row.get("ordered_events")
    if not isinstance(ordered, list):
        return signature
    for raw in ordered:
        if not isinstance(raw, Mapping):
            signature.append(("malformed",))
            continue
        family = raw.get("family")
        kind = raw.get("kind")
        if family == "memory":
            signature.append(("memory", kind, raw.get("width")))
        elif family == "fault":
            signature.append(("fault", kind))
        elif family == "external" and kind == "rep_movsd":
            signature.append(("rep_movsd",))
        elif family == "external" and kind in {"rep_movs", "rep_stos"}:
            signature.append(
                (
                    kind,
                    raw.get("element_width"),
                    raw.get("address_size"),
                    raw.get("effect_model"),
                    raw.get("restart_semantics"),
                )
            )
        elif family == "external" and kind == "rep_scas":
            signature.append(
                (
                    kind,
                    raw.get("element_width"),
                    raw.get("address_size"),
                    raw.get("effect_model"),
                    raw.get("restart_semantics"),
                    raw.get("repeat_condition"),
                    raw.get("comparison_model"),
                    raw.get("segment_model"),
                    raw.get("fault_model"),
                )
            )
        elif family == "external":
            signature.append(
                (
                    "call",
                    kind,
                    raw.get("instruction_rva"),
                    raw.get("return_rva"),
                    raw.get("dll"),
                    raw.get("symbol"),
                    raw.get("ordinal"),
                )
            )
        else:
            signature.append(("unsupported", family, kind))
    return signature


def _typed_ordered_effect_signature(transfer: _Transfer) -> list[tuple[object, ...]]:
    signature: list[tuple[object, ...]] = []
    for action in transfer.actions[:-1]:
        if action.op == "eval_word":
            node = transfer.nodes[action.args[0]]
            if node.op == "load":
                signature.append(("memory", "read", node.aux))
        elif action.op == "memory_write":
            signature.append(("memory", "write", action.aux))
        elif action.op == "divide_if":
            signature.append(("fault", "divide_error"))
        elif action.op == "rep_movsd":
            signature.append(("rep_movsd",))
        elif action.op in {"rep_movs", "rep_stos"}:
            signature.append(
                (
                    action.op,
                    action.aux,
                    32,
                    (
                        "symbolic_string_copy_v2"
                        if action.op == "rep_movs"
                        else "symbolic_string_fill_v2"
                    ),
                    "element_committed_v1",
                )
            )
        elif action.op == "rep_scas":
            signature.append(
                (
                    "rep_scas",
                    action.aux,
                    32,
                    "symbolic_string_scan_v1",
                    "element_committed_v1",
                    "while_not_equal_v1",
                    "subtraction_flags_v1",
                    "flat_es_zero_v1",
                    "read_before_commit_v1",
                )
            )
        elif action.op == "call":
            call = transfer.calls[action.args[0]]
            signature.append(
                (
                    "call",
                    call.kind,
                    call.instruction_rva,
                    call.return_rva,
                    call.dll,
                    call.symbol,
                    call.ordinal,
                )
            )
    return signature


def _blocker_family(row: Mapping[str, Any], error: StageBInterpreterError) -> str:
    fpu = row.get("fpu_state")
    if isinstance(fpu, Mapping) and fpu.get("model") in {
        "symbolic_x87_stack_v1",
        "native_exact_x87_command_replay_obligation_v1",
    }:
        return "x87_separate_frontier"
    return error.code


def _walk_ops(value: object, counts: Counter[str]) -> None:
    if isinstance(value, Mapping):
        op = value.get("op")
        if isinstance(op, str):
            counts[op] += 1
        for child in value.values():
            _walk_ops(child, counts)
    elif isinstance(value, list):
        for child in value:
            _walk_ops(child, counts)


def _blocked_features(
    row: Mapping[str, Any], family: str
) -> tuple[set[str], Counter[str]]:
    transfer_features = {f"blocker.{family}"}
    occurrences: Counter[str] = Counter()
    fpu = row.get("fpu_state")
    if not isinstance(fpu, Mapping):
        return transfer_features, occurrences
    model = fpu.get("model")
    if isinstance(model, str):
        transfer_features.add(f"x87.state.{model}")
    for field in (
        "tags",
        "pending_exception",
        "last_opcode",
        "instruction_pointer",
        "code_selector",
        "data_pointer",
        "data_selector",
    ):
        if field not in fpu:
            transfer_features.add(f"x87.state.missing_{field}")
    expression_ops: Counter[str] = Counter()
    _walk_ops(fpu, expression_ops)
    for op, count in expression_ops.items():
        if op.startswith("fpu_"):
            key = f"x87.expression.{op}"
            transfer_features.add(key)
            occurrences[key] += count
    instructions = row.get("instructions")
    if isinstance(instructions, list):
        for raw in instructions:
            if not isinstance(raw, Mapping):
                continue
            mnemonic = raw.get("mnemonic")
            if isinstance(mnemonic, str) and (
                mnemonic.startswith("f") or mnemonic == "wait"
            ):
                key = f"x87.instruction.{mnemonic}"
                transfer_features.add(key)
                occurrences[key] += 1
    return transfer_features, occurrences


def interpreter_transfer_inventory(state_machine: Path) -> dict[str, Any]:
    """Preflight every transfer without treating exporter status as evidence.

    ``structurally_supported`` means that the raw semantic row lowers into the
    checked non-x87 ``ProgramRecord`` vocabulary.  It deliberately does not
    mean proved: every supported row still needs a Lean general-transfer
    certificate tied to its exact PE bytes and decoded Stage A semantics.
    """

    path = Path(state_machine)
    raw_bytes = path.read_bytes()
    rows: list[Mapping[str, Any]] = []
    for line_number, raw_line in enumerate(raw_bytes.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            value = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"{path}:{line_number}: invalid state-machine JSON: {exc}"
            ) from exc
        rows.append(_object(value, f"{path}:{line_number} transfer"))

    feature_counts: Counter[str] = Counter()
    operation_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    blocked_feature_transfer_counts: Counter[str] = Counter()
    blocked_feature_occurrence_counts: Counter[str] = Counter()
    blocked: list[dict[str, Any]] = []
    supported_ids: list[str] = []
    seen_ids: set[str] = set()
    seen_rvas: set[int] = set()
    ignored_status_fields = 0

    for index, row in enumerate(rows):
        if "status" in row:
            ignored_status_fields += 1
        identity = row.get("id") if isinstance(row.get("id"), str) else f"row:{index}"
        schedule_missing: Counter[tuple[object, ...]] = Counter()
        try:
            transfer = _TransferCompiler(row).compile()
            raw_schedule = _raw_ordered_effect_signature(row)
            typed_schedule = _typed_ordered_effect_signature(transfer)
            if raw_schedule != typed_schedule:
                schedule_missing = Counter(raw_schedule) - Counter(typed_schedule)
                raise StageBInterpreterError(
                    f"{transfer.identity}: typed transfer does not preserve the exact "
                    "ordered effect schedule",
                    code="ordered_effect_schedule_mismatch",
                    next_action=(
                        "lower every ordered access/event without memoizing away repeated "
                        "reads, then regenerate the checked ProgramRecord"
                    ),
                )
            if transfer.identity in seen_ids:
                raise StageBInterpreterError(
                    f"duplicate transfer id {transfer.identity}",
                    code="duplicate_transfer_id",
                )
            if transfer.rva_start in seen_rvas:
                raise StageBInterpreterError(
                    f"duplicate transfer RVA 0x{transfer.rva_start:x}",
                    code="duplicate_transfer_rva",
                )
            if transfer.x87_nodes or transfer.x87_replays or any(
                action.op.startswith("set_x87") or action.op == "replay_x87"
                for action in transfer.actions
            ):
                raise StageBInterpreterError(
                    f"{transfer.identity}: x87 uses its separate checked transfer bridge",
                    code="x87_separate_frontier",
                )
        except StageBInterpreterError as exc:
            family = _blocker_family(row, exc)
            blocker_counts[family] += 1
            transfer_features, occurrences = _blocked_features(row, family)
            if family == "ordered_effect_schedule_mismatch":
                transfer_features.add("ordered_effect.exact_schedule_mismatch")
                for token, count in schedule_missing.items():
                    if token == ("memory", "read", 4):
                        key = "ordered_effect.missing_dword_read"
                    else:
                        key = "ordered_effect.missing." + ".".join(map(str, token))
                    transfer_features.add(key)
                    occurrences[key] += count
            blocked_feature_transfer_counts.update(transfer_features)
            blocked_feature_occurrence_counts.update(occurrences)
            original = row.get("original")
            rva = original.get("rva_start") if isinstance(original, Mapping) else None
            blocked.append(
                {
                    "index": index,
                    "id": identity,
                    "original_rva": rva if isinstance(rva, int) else None,
                    "family": family,
                    "code": exc.code,
                    "message": str(exc),
                    "next_action": exc.next_action,
                }
            )
            continue

        seen_ids.add(transfer.identity)
        seen_rvas.add(transfer.rva_start)
        supported_ids.append(transfer.identity)
        row_features, row_operations = _compiled_feature_counts(transfer)
        feature_counts.update(row_features)
        operation_counts.update(row_operations)

    blocked.sort(
        key=lambda item: (
            item["family"],
            item["original_rva"] if item["original_rva"] is not None else 2**32,
            item["id"],
        )
    )
    total = len(rows)
    supported = len(supported_ids)
    return {
        "format": RELATIONAL_INTERPRETER_TRANSFER_INVENTORY_FORMAT,
        "profile": RELATIONAL_INTERPRETER_TRANSFER_GENERAL_PROFILE,
        "input": str(path),
        "input_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "total_transfers": total,
        "structurally_supported": supported,
        "blocked": total - supported,
        "lean_semantic_certificates_required": supported,
        "lean_semantic_certificates_proved": 0,
        "status_fields_ignored": ignored_status_fields,
        "supported_transfer_ids": supported_ids,
        "feature_counts": _counter(feature_counts),
        "operation_counts": _counter(operation_counts),
        "blocker_family_counts": _counter(blocker_counts),
        "blocked_feature_transfer_counts": _counter(
            blocked_feature_transfer_counts
        ),
        "blocked_feature_occurrence_counts": _counter(
            blocked_feature_occurrence_counts
        ),
        "blocked_transfers": blocked,
    }
