from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...errors import StageAInputError
from ...util import sha256_bytes
from .pe_byte_packs import (
    PEBytePackInventory,
    PEBytePackSpan,
    render_pe_byte_pack_span_proof,
)


RELATIONAL_INTERPRETER_X87_SCHEDULE_FORMAT = (
    "stage-a-relational-interpreter-x87-schedule-v1"
)
RELATIONAL_INTERPRETER_X87_MODULE_INVENTORY_FORMAT = (
    "stage-a-relational-interpreter-x87-module-inventory-v1"
)
RELATIONAL_INTERPRETER_X87_CANDIDATE_REPLAY_INVENTORY_FORMAT = (
    "stage-a-relational-interpreter-x87-candidate-replay-inventory-v1"
)
_SCHEDULE_FORMAT = "stage-a-instruction-ordered-effect-schedule-v1"
_STATE_MACHINE_FORMAT = "stage-b-state-machine-transfer-v1"
_X87_CLASS = "x87_singleton_checked_replay"
_ORDINARY_CLASS = "ordinary_symbolic_instruction"
_X87_DECODER = "StageA.Relational.X87.decodeSingletonCommand"
_X87_EXECUTOR = "StageA.Relational.X87.executeSingletonCommand"
_ORDINARY_DECODER = "StageA.Formal.decodeInstructionExact"
_ORDINARY_EXECUTOR = "StageA.Formal.executeInstruction"
_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STAGE_A_MODULE = re.compile(r"StageA\.([A-Za-z_][A-Za-z0-9_']*)\Z")
_STAGE_A_IMPORT = re.compile(
    r"^import StageA\.([A-Za-z_][A-Za-z0-9_']*)$", re.MULTILINE
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SCHEDULE_FIELDS = frozenset(
    {
        "format",
        "status",
        "proof_authority",
        "ordering",
        "rva_start",
        "rva_end",
        "transfer_bytes_sha256",
        "records",
        "blockers",
        "counts",
        "schedule_sha256",
    }
)
_RECORD_FIELDS = frozenset(
    {
        "index",
        "rva_start",
        "rva_end",
        "bytes",
        "bytes_sha256",
        "transfer_bytes_sha256",
        "instruction_class",
        "classification",
        "symbolic_pre_state_sha256",
        "symbolic_post_state_sha256",
        "effects",
        "record_sha256",
    }
)
_CLASSIFICATION_FIELDS = frozenset(
    {
        "status",
        "source",
        "proof_authority",
        "mnemonic_guidance",
        "operand_guidance",
        "checked_decoder",
        "checked_executor",
    }
)
_EFFECT_FIELDS = frozenset(
    {
        "register_writes",
        "defined_flag_writes",
        "undefined_flags",
        "undefined_flag_writes",
        "memory_events",
        "faults",
        "control",
        "call_effects",
        "ordered_events",
        "counts",
    }
)
_X87_REPLAY_FIELDS = frozenset(
    {
        "rva_start",
        "rva_end",
        "bytes",
        "bytes_sha256",
        "checked_decoder",
        "checked_executor",
        "physical_state_effect",
    }
)


@dataclass(frozen=True)
class CandidateReplayProofSpec:
    """Stable names for a generated candidate replay proof graph."""

    original_source_module: str
    original_pe_name: str
    table_shard_size: int
    schedule_module_prefix: str = "GeneratedInterpreterX87Schedule"
    schedule_definition_prefix: str = "checkedInterpreterX87Schedule"
    candidate_data_shard_module_prefix: str = "GeneratedInterpreterKernelDataShard"
    candidate_data_bundle_module: str = "GeneratedInterpreterKernelDataBundle"
    candidate_data_namespace: str = (
        "StageA.GeneratedRelational.InterpreterKernelData"
    )
    candidate_entries_prefix: str = "generatedInterpreterKernelDataEntries"
    candidate_entries_suffix: str = ""
    candidate_shard_prefix: str = "generatedInterpreterKernelDataShard"
    candidate_shard_suffix: str = ""
    candidate_table_certificate: str = "generatedInterpreterKernelDataCertificate"
    module_prefix: str = "GeneratedInterpreterX87CandidateReplayShard"
    bundle_module: str = "GeneratedInterpreterX87CandidateReplayBundle"
    definition_prefix: str = "checkedInterpreterX87CandidateReplay"


@dataclass(frozen=True)
class _CandidateReplayTransfer:
    rva_start: int
    x87_replays: tuple[int, ...]


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing:
        raise StageAInputError(f"{context} is missing fields: {', '.join(missing)}")
    if unexpected:
        raise StageAInputError(
            f"{context} has unexpected fields: {', '.join(unexpected)}"
        )


def _list(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a JSON array")
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{context} must be a natural number")
    return value


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a canonical SHA-256 digest")
    return value


def _hex_bytes(value: object, context: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise StageAInputError(f"{context} must be even-length hexadecimal bytes")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise StageAInputError(f"{context} must be hexadecimal bytes") from error


def _lean_name(value: str, context: str) -> str:
    if _LEAN_NAME.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a qualified Lean identifier")
    return value


def _local_name(value: str, context: str) -> str:
    if _LOCAL_NAME.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a local Lean identifier")
    return value


def _stage_a_module(value: str, context: str) -> tuple[str, str]:
    match = _STAGE_A_MODULE.fullmatch(value)
    if match is None:
        raise StageAInputError(
            f"{context} must be a canonical StageA.<module> identifier"
        )
    return value, match.group(1)


def _bytes_literal(value: bytes) -> str:
    if not value:
        return "[]"
    return "[" + ", ".join(str(byte) for byte in value) + "]"


def _utf8_bytes_literal(value: bytes) -> str:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise StageAInputError("canonical JSON bytes must be valid UTF-8") from error
    return f"utf8Bytes {json.dumps(text)}"


def _contract_body(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in row.items()
        if key not in {"stage_b_format", "contract_sha256", "stage_a_export"}
    }


def _read_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as error:
                raise StageAInputError(
                    f"state-machine line {line_number} is not valid JSON"
                ) from error
            rows.append(dict(_object(raw, f"state-machine line {line_number}")))
    if not rows:
        raise StageAInputError("state machine contains no transfers")
    return rows


def _candidate_replay_transfers(
    rows: list[dict[str, Any]], schedules: list[Mapping[str, Any]]
) -> list[_CandidateReplayTransfer]:
    replay_counts = {schedule["start"]: schedule["x87_count"] for schedule in schedules}
    if len(replay_counts) != len(schedules):
        raise StageAInputError("candidate replay schedules have duplicate source RVAs")
    starts: list[int] = []
    for index, row in enumerate(rows):
        original = _object(row.get("original"), f"state-machine row {index} original")
        starts.append(
            _nat(
                original.get("rva_start"),
                f"state-machine row {index} original rva_start",
            )
        )
    if len(set(starts)) != len(starts):
        raise StageAInputError("candidate replay transfers have duplicate source RVAs")
    unknown = sorted(set(replay_counts) - set(starts))
    if unknown:
        raise StageAInputError(
            f"candidate replay schedules have no transfer rows: {unknown}"
        )
    return [
        _CandidateReplayTransfer(
            rva_start=start,
            x87_replays=tuple(range(replay_counts.get(start, 0))),
        )
        for start in sorted(starts)
    ]


def _validate_record(
    raw: object,
    *,
    transfer_id: str,
    expected_index: int,
    expected_rva: int,
    transfer_digest: str,
) -> tuple[dict[str, Any], bytes, bool]:
    record = dict(_object(raw, f"{transfer_id} schedule record {expected_index}"))
    instruction_class = record.get("instruction_class")
    expected_fields = _RECORD_FIELDS | (
        frozenset({"x87_singleton_replay"})
        if instruction_class == _X87_CLASS
        else frozenset()
    )
    _exact_fields(
        record, expected_fields, f"{transfer_id} schedule record {expected_index}"
    )
    record_digest = _digest(
        record.get("record_sha256"),
        f"{transfer_id} schedule record {expected_index} digest",
    )
    body = dict(record)
    del body["record_sha256"]
    if sha256_bytes(_canonical_json(body)) != record_digest:
        raise StageAInputError(
            f"{transfer_id} schedule record {expected_index} canonical hash differs"
        )
    index = _nat(record.get("index"), "schedule record index")
    start = _nat(record.get("rva_start"), "schedule record rva_start")
    stop = _nat(record.get("rva_end"), "schedule record rva_end")
    encoded = _hex_bytes(record.get("bytes"), "schedule record bytes")
    if index != expected_index or start != expected_rva or stop != start + len(encoded):
        raise StageAInputError(
            f"{transfer_id} schedule record {expected_index} is not contiguous"
        )
    if not encoded:
        raise StageAInputError(
            f"{transfer_id} schedule record {expected_index} is empty"
        )
    if _digest(record.get("bytes_sha256"), "record bytes digest") != sha256_bytes(
        encoded
    ):
        raise StageAInputError(
            f"{transfer_id} schedule record {expected_index} byte hash differs"
        )
    if (
        _digest(record.get("transfer_bytes_sha256"), "record transfer digest")
        != transfer_digest
    ):
        raise StageAInputError(
            f"{transfer_id} schedule record {expected_index} binds another transfer"
        )
    classification = _object(
        record.get("classification"),
        f"{transfer_id} schedule record {expected_index} classification",
    )
    _exact_fields(
        classification,
        _CLASSIFICATION_FIELDS,
        f"{transfer_id} schedule record {expected_index} classification",
    )
    if (
        classification.get("status") != "proposal_requires_lean_exact_byte_replay"
        or classification.get("proof_authority") is not False
    ):
        raise StageAInputError(
            f"{transfer_id} schedule record {expected_index} claims unsupported authority"
        )
    is_x87 = instruction_class == _X87_CLASS
    expected_decoder = _X87_DECODER if is_x87 else _ORDINARY_DECODER
    expected_executor = _X87_EXECUTOR if is_x87 else _ORDINARY_EXECUTOR
    if instruction_class not in {_X87_CLASS, _ORDINARY_CLASS}:
        raise StageAInputError(
            f"{transfer_id} schedule record {expected_index} has an unsupported class"
        )
    if (
        classification.get("checked_decoder") != expected_decoder
        or classification.get("checked_executor") != expected_executor
    ):
        raise StageAInputError(
            f"{transfer_id} schedule record {expected_index} names another checker"
        )
    if is_x87:
        replay = _object(
            record.get("x87_singleton_replay"),
            f"{transfer_id} schedule record {expected_index} replay",
        )
        _exact_fields(
            replay,
            _X87_REPLAY_FIELDS,
            f"{transfer_id} schedule record {expected_index} replay",
        )
        expected = {
            "rva_start": start,
            "rva_end": stop,
            "bytes": encoded.hex(),
            "bytes_sha256": sha256_bytes(encoded),
            "checked_decoder": _X87_DECODER,
            "checked_executor": _X87_EXECUTOR,
            "physical_state_effect": (
                "produced_by_checked_executor_not_inferred_by_exporter"
            ),
        }
        if dict(replay) != expected:
            raise StageAInputError(
                f"{transfer_id} schedule record {expected_index} replay binding differs"
            )
    elif "x87_singleton_replay" in record:
        raise StageAInputError(
            f"{transfer_id} ordinary schedule record {expected_index} carries x87 replay"
        )
    effects = _object(
        record.get("effects"),
        f"{transfer_id} schedule record {expected_index} effects",
    )
    _exact_fields(
        effects,
        _EFFECT_FIELDS,
        f"{transfer_id} schedule record {expected_index} effects",
    )
    _digest(record.get("symbolic_pre_state_sha256"), "symbolic pre-state digest")
    _digest(record.get("symbolic_post_state_sha256"), "symbolic post-state digest")
    return record, encoded, is_x87


def _validated_schedule(row: Mapping[str, Any]) -> dict[str, Any]:
    transfer_id = row.get("id")
    if not isinstance(transfer_id, str) or not transfer_id:
        raise StageAInputError("x87 schedule transfer id must be a non-empty string")
    schedule = dict(
        _object(row.get("instruction_effect_schedule"), f"{transfer_id} schedule")
    )
    _exact_fields(schedule, _SCHEDULE_FIELDS, f"{transfer_id} schedule")
    if (
        schedule.get("format") != _SCHEDULE_FORMAT
        or schedule.get("status") != "complete"
        or schedule.get("proof_authority") is not False
        or schedule.get("ordering") != "strict_contiguous_rva_order"
    ):
        raise StageAInputError(f"{transfer_id} schedule is not a complete proposal")
    if schedule.get("blockers") != []:
        raise StageAInputError(f"{transfer_id} complete schedule contains blockers")
    schedule_digest = _digest(
        schedule.get("schedule_sha256"), f"{transfer_id} schedule digest"
    )
    schedule_body = dict(schedule)
    del schedule_body["schedule_sha256"]
    if sha256_bytes(_canonical_json(schedule_body)) != schedule_digest:
        raise StageAInputError(f"{transfer_id} canonical schedule hash differs")
    transfer_digest = _digest(
        row.get("instruction_bytes_sha256"), f"{transfer_id} transfer digest"
    )
    if schedule.get("transfer_bytes_sha256") != transfer_digest:
        raise StageAInputError(f"{transfer_id} schedule binds another transfer")
    original = _object(row.get("original"), f"{transfer_id} original span")
    start = _nat(original.get("rva_start"), "transfer rva_start")
    stop = _nat(original.get("rva_end"), "transfer rva_end")
    if schedule.get("rva_start") != start or schedule.get("rva_end") != stop:
        raise StageAInputError(f"{transfer_id} schedule span differs from transfer")
    records: list[dict[str, Any]] = []
    encoded_records: list[bytes] = []
    x87_count = 0
    expected_rva = start
    for index, raw in enumerate(_list(schedule.get("records"), "schedule records")):
        record, encoded, is_x87 = _validate_record(
            raw,
            transfer_id=transfer_id,
            expected_index=index,
            expected_rva=expected_rva,
            transfer_digest=transfer_digest,
        )
        records.append(record)
        encoded_records.append(encoded)
        x87_count += int(is_x87)
        expected_rva += len(encoded)
    if not records or expected_rva != stop:
        raise StageAInputError(f"{transfer_id} schedule does not cover its exact span")
    transfer_bytes = b"".join(encoded_records)
    if sha256_bytes(transfer_bytes) != transfer_digest:
        raise StageAInputError(f"{transfer_id} reconstructed transfer hash differs")
    instructions = _list(row.get("instructions"), f"{transfer_id} instructions")
    instruction_bytes = b"".join(
        _hex_bytes(
            _object(raw, f"{transfer_id} instruction {index}").get("bytes"),
            f"{transfer_id} instruction {index} bytes",
        )
        for index, raw in enumerate(instructions)
    )
    if instruction_bytes != transfer_bytes:
        raise StageAInputError(f"{transfer_id} instruction inventory differs from schedule")
    counts = _object(schedule.get("counts"), f"{transfer_id} schedule counts")
    ordinary_count = len(records) - x87_count
    expected_counts = {
        "instructions": len(records),
        "x87_singletons": x87_count,
        "ordinary_instructions": ordinary_count,
        "blockers": 0,
    }
    if dict(counts) != expected_counts:
        raise StageAInputError(f"{transfer_id} schedule counts differ")
    contract_digest = _digest(
        row.get("contract_sha256"), f"{transfer_id} contract digest"
    )
    contract_body = _contract_body(row)
    contract_bytes = _canonical_json(contract_body)
    if sha256_bytes(contract_bytes) != contract_digest:
        raise StageAInputError(f"{transfer_id} canonical contract hash differs")
    if row.get("stage_b_format") != _STATE_MACHINE_FORMAT:
        raise StageAInputError(f"{transfer_id} has an unsupported state-machine format")
    fpu_state = _object(row.get("fpu_state"), f"{transfer_id} fpu_state")
    replay = _object(fpu_state.get("replay"), f"{transfer_id} fpu replay")
    if replay.get("instruction_effect_schedule") != schedule:
        raise StageAInputError(
            f"{transfer_id} outer and FPU instruction schedules differ"
        )
    return {
        "id": transfer_id,
        "start": start,
        "stop": stop,
        "transfer_bytes": transfer_bytes,
        "transfer_digest": transfer_digest,
        "contract_bytes": contract_bytes,
        "contract_digest": contract_digest,
        "schedule_bytes": _canonical_json(schedule_body),
        "schedule_digest": schedule_digest,
        "records": records,
        "x87_count": x87_count,
        "ordinary_count": ordinary_count,
    }


def relational_interpreter_x87_preflight(state_machine: Path) -> dict[str, Any]:
    """Inventory exact x87 schedules without granting proof authority."""

    rows = _read_rows(state_machine)
    checked: list[dict[str, Any]] = []
    blocked: list[dict[str, str]] = []
    for row in rows:
        if row.get("instruction_effect_schedule") is None:
            continue
        transfer_id = str(row.get("id") or "<missing-id>")
        try:
            schedule = _validated_schedule(row)
        except StageAInputError as error:
            blocked.append({"transfer_id": transfer_id, "blocker": str(error)})
            continue
        checked.append(
            {
                "transfer_id": schedule["id"],
                "rva_start": schedule["start"],
                "rva_end": schedule["stop"],
                "x87_singletons": schedule["x87_count"],
                "ordinary_instructions": schedule["ordinary_count"],
                "classification": "ready_for_lean_exact_byte_check",
            }
        )
    return {
        "format": RELATIONAL_INTERPRETER_X87_SCHEDULE_FORMAT,
        "status": "ready" if checked and not blocked else "incomplete",
        "proof_authority": False,
        "state_machine": str(Path(state_machine)),
        "counts": {
            "input_transfers": len(rows),
            "x87_schedules": len(checked) + len(blocked),
            "preflight_checked_schedules": len(checked),
            "blocked_schedules": len(blocked),
            "mixed_schedules": sum(item["ordinary_instructions"] > 0 for item in checked),
            "all_x87_schedules": sum(item["ordinary_instructions"] == 0 for item in checked),
            "x87_singleton_replays": sum(item["x87_singletons"] for item in checked),
            "ordinary_instruction_records": sum(
                item["ordinary_instructions"] for item in checked
            ),
        },
        "checked": checked,
        "blocked": blocked,
        "remaining_formal_requirements": [
            "Lean exact PE byte and singleton decode checks",
            "ordinary instruction refinement certificates for mixed schedules",
            "opcode-25 replay refinement against executeX87Singleton",
            "compiled interpreter-kernel refinement",
            "whole-program acceptance composition",
        ],
    }


def relational_interpreter_x87_source(
    state_machine: Path,
    *,
    transfer_id: str,
    source_module: str,
    pe_name: str,
    definition_prefix: str = "checkedInterpreterX87Schedule",
    pe_byte_pack_inventory: PEBytePackInventory | None = None,
) -> str:
    """Emit one cacheable exact-byte schedule module for a selected transfer."""

    source_module = _lean_name(source_module, "source_module")
    pe_name = _lean_name(pe_name, "pe_name")
    definition_prefix = _local_name(definition_prefix, "definition_prefix")
    matches = [row for row in _read_rows(state_machine) if row.get("id") == transfer_id]
    if len(matches) != 1:
        raise StageAInputError(
            f"x87 transfer {transfer_id!r} must occur exactly once; found {len(matches)}"
        )
    schedule = _validated_schedule(matches[0])
    return _relational_interpreter_x87_schedule_source(
        schedule,
        source_module=source_module,
        pe_name=pe_name,
        definition_prefix=definition_prefix,
        pe_byte_pack_inventory=pe_byte_pack_inventory,
    )


def _relational_interpreter_x87_schedule_source(
    schedule: Mapping[str, Any],
    *,
    source_module: str,
    pe_name: str,
    definition_prefix: str,
    pe_byte_pack_inventory: PEBytePackInventory | None,
) -> str:
    pack_proof = None
    imports = ["StageA.RelationalInterpreterX87"]
    pack_opens = ""
    if pe_byte_pack_inventory is None:
        imports.append(source_module)
    else:
        if pe_name != pe_byte_pack_inventory.qualified_pe_name:
            raise StageAInputError(
                "x87 PE name differs from the byte-pack authoritative PE"
            )
        if pe_byte_pack_inventory.runtime_binding_prefix is None:
            raise StageAInputError(
                "pack-aware x87 schedules require authoritative runtime bindings"
            )
        pack_proof = render_pe_byte_pack_span_proof(
            pe_byte_pack_inventory,
            span=PEBytePackSpan(
                f"{definition_prefix}PEByteSpan",
                schedule["start"],
                len(schedule["transfer_bytes"]),
            ),
        )
        if pack_proof.data != schedule["transfer_bytes"]:
            raise StageAInputError(
                f"x87 schedule {schedule['id']} bytes differ from the authoritative PE"
            )
        imports.extend(f"StageA.{module}" for module in pack_proof.imports)
        pack_opens = (
            "open StageA.Relational.PEBytePacks\n"
            f"open {pe_byte_pack_inventory.namespace}\n"
        )
    records: list[Mapping[str, Any]] = schedule["records"]
    replay_index = 0
    rendered_record_definitions: list[str] = []
    rendered_action_definitions: list[str] = []
    rendered_replay_witnesses: list[str] = []
    record_names: list[str] = []
    action_names: list[str] = []
    for record in records:
        encoded = _hex_bytes(record["bytes"], "record bytes")
        body = dict(record)
        record_digest = body.pop("record_sha256")
        kind = 1 if record["instruction_class"] == _X87_CLASS else 0
        record_name = f"{definition_prefix}Record{record['index']:04d}"
        record_names.append(record_name)
        rendered_record_definitions.append(
            f"def {record_name} : RawInstructionRecord := {{\n"
            f"  index := {record['index']}\n"
            f"  kind := {kind}\n"
            f"  span := {{ start := {record['rva_start']}, size := {len(encoded)} }}\n"
            f"  bytes := {_bytes_literal(encoded)}\n"
            f"  bytesSha256 := {json.dumps(record['bytes_sha256'])}\n"
            f"  canonicalBytes := {_utf8_bytes_literal(_canonical_json(body))}\n"
            f"  recordSha256 := {json.dumps(record_digest)}\n"
            f"  transferBytesSha256 := {json.dumps(schedule['transfer_digest'])}\n"
            "}"
        )
        if kind == 1:
            action_name = f"{definition_prefix}ReplayAction{replay_index:04d}"
            action_names.append(action_name)
            rendered_action_definitions.append(
                f"def {action_name} : RawReplayAction := {{\n"
                "  opcode := 25\n"
                f"  replayIndex := {replay_index}\n"
                f"  span := {{ start := {record['rva_start']}, size := {len(encoded)} }}\n"
                f"  instructionBytes := {_bytes_literal(encoded)}\n"
                f"  instructionBytesSha256 := {json.dumps(record['bytes_sha256'])}\n"
                f"  transferBytesSha256 := {json.dumps(schedule['transfer_digest'])}\n"
                f"  contractSha256 := {json.dumps(schedule['contract_digest'])}\n"
                "}"
            )
            rendered_replay_witnesses.append(
                f"def {action_name}Witness : "
                f"ExactInterpreterX87ReplayActionWitness {pe_name} := {{\n"
                f"  schedule := {definition_prefix}\n"
                f"  certificate := {definition_prefix}ExactCertificate\n"
                f"  record := {record_name}\n"
                f"  action := {action_name}\n"
                "  recordMember := by decide +kernel\n"
                "  actionMember := by decide +kernel\n"
                "  recordClass := by decide +kernel\n"
                "  actionFound := by decide +kernel\n"
                "}"
            )
            replay_index += 1
    definitions = "\n\n".join(
        rendered_record_definitions + rendered_action_definitions
    )
    records_literal = ",\n    ".join(record_names)
    actions_literal = ",\n    ".join(action_names)
    replay_witnesses = "\n\n".join(rendered_replay_witnesses)
    import_source = "\n".join(f"import {module}" for module in dict.fromkeys(imports))
    pack_source = "" if pack_proof is None else f"{pack_proof.source}\n\n"
    if pack_proof is None:
        exact_pe_proof = "by decide +kernel"
        ordinary_local = ""
        ordinary_proof = "by decide +kernel"
    else:
        transfer_literal = _bytes_literal(schedule["transfer_bytes"])
        exact_pe_proof = f"""by
  change (exactScheduleRvaBytes {pe_name} {schedule['start']}
      {len(schedule['transfer_bytes'])} == some {transfer_literal}) = true
  rw [exactScheduleRvaBytes_eq_readExactSectionRvaSpan
    {pe_name} {schedule['start']} {len(schedule['transfer_bytes'])} (by decide)]
  rw [{pack_proof.exact_theorem}]
  decide"""
        runtime_prefix = pe_byte_pack_inventory.runtime_binding_prefix
        imports_name = f"{pe_byte_pack_inventory.namespace}.{runtime_prefix}Imports"
        imports_parsed = (
            f"{pe_byte_pack_inventory.namespace}.{runtime_prefix}ImportsParsed"
        )
        local_theorem = f"{definition_prefix}OrdinaryExecutableWithImports"
        ordinary_local = f"""
theorem {local_theorem} :
    {definition_prefix}.ordinaryExecutableWithImportsChecked {pe_name}
      {imports_name} = true := by decide +kernel
"""
        ordinary_proof = f"""by
  exact RawInstructionSchedule.ordinaryExecutableChecked_of_importsParsed
    {definition_prefix} {pe_name} {imports_name} {imports_parsed}
    {local_theorem}"""
    return f"""{import_source}

namespace StageA.GeneratedRelational

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterX87
{pack_opens}

set_option maxRecDepth 100000
set_option maxHeartbeats 0

{definitions}

def {definition_prefix} : RawInstructionSchedule := {{
  sourceRva := {schedule['start']}
  transferBytes := {_bytes_literal(schedule['transfer_bytes'])}
  transferBytesSha256 := {json.dumps(schedule['transfer_digest'])}
  contractCanonicalBytes := {_utf8_bytes_literal(schedule['contract_bytes'])}
  contractSha256 := {json.dumps(schedule['contract_digest'])}
  scheduleCanonicalBytes := {_utf8_bytes_literal(schedule['schedule_bytes'])}
  scheduleSha256 := {json.dumps(schedule['schedule_digest'])}
  records := [
    {records_literal}
  ]
  replayActions := [
    {actions_literal}
  ]
}}

{pack_source}theorem {definition_prefix}OrderAndReplay :
    {definition_prefix}.orderAndReplayChecked = true := by decide +kernel

theorem {definition_prefix}ExactPEBytes :
    {definition_prefix}.exactPEChecked {pe_name} = true := {exact_pe_proof}

theorem {definition_prefix}SemanticClasses :
    {definition_prefix}.semanticClassesChecked {pe_name} = true := by decide +kernel

{ordinary_local}
theorem {definition_prefix}OrdinaryExecutable :
    {definition_prefix}.ordinaryExecutableChecked {pe_name} = true := {ordinary_proof}

theorem {definition_prefix}ReplayOpcode25 :
    {definition_prefix}.replayOpcode25Checked = true := by decide +kernel

def {definition_prefix}Checked :
    CheckedInstructionSchedule {definition_prefix} {pe_name} := {{
  orderAndReplay := {definition_prefix}OrderAndReplay
  exactPEBytes := {definition_prefix}ExactPEBytes
  semanticClasses := {definition_prefix}SemanticClasses
}}

def {definition_prefix}ExactCertificate :
    ExactInterpreterX87ScheduleCertificate {pe_name} {definition_prefix} := {{
  scheduleChecked := {definition_prefix}Checked
  ordinaryExecutable := {definition_prefix}OrdinaryExecutable
  replayOpcode25 := {definition_prefix}ReplayOpcode25
}}

theorem {definition_prefix}MacroStepRefines (state : MachineState) :
    runExactAuthoritative {pe_name} {definition_prefix} state =
      runExactInterpreter {pe_name} {definition_prefix} state :=
  {definition_prefix}ExactCertificate.macroStepRefines state

def {definition_prefix}Witness :
    ExactInterpreterX87ScheduleWitness {pe_name} := {{
  schedule := {definition_prefix}
  certificate := {definition_prefix}ExactCertificate
}}

{replay_witnesses}

#print axioms {definition_prefix}ExactPEBytes
#print axioms {definition_prefix}OrdinaryExecutable

end StageA.GeneratedRelational
"""


def relational_interpreter_x87_bundle_sources(
    state_machine: Path,
    *,
    source_module: str,
    pe_name: str,
    module_prefix: str = "GeneratedInterpreterX87Schedule",
    definition_prefix: str = "checkedInterpreterX87Schedule",
    pe_byte_pack_inventory: PEBytePackInventory | None = None,
) -> dict[str, str]:
    """Emit one semantic proof shard per exact schedule plus a typed bundle.

    The returned keys are canonical unqualified StageA module names, matching
    the keys accepted by ``stage-a-lean-graph.nix``.  Each shard binds only one
    transfer, so an extraction or semantic change invalidates that shard and the
    small aggregate module rather than every x87 proof.
    """

    source_module, _ = _stage_a_module(source_module, "source_module")
    pe_name = _lean_name(pe_name, "pe_name")
    module_prefix = _local_name(module_prefix, "module_prefix")
    definition_prefix = _local_name(definition_prefix, "definition_prefix")
    rows = _read_rows(state_machine)
    selected = [row for row in rows if row.get("instruction_effect_schedule") is not None]
    if not selected:
        raise StageAInputError("state machine contains no x87 instruction schedules")
    identities = [row.get("id") for row in selected]
    if any(not isinstance(identity, str) or not identity for identity in identities):
        raise StageAInputError("every x87 schedule must have a non-empty transfer id")
    if len(set(identities)) != len(identities):
        raise StageAInputError("x87 schedule transfer ids must be unique")
    schedules = sorted(
        (_validated_schedule(row) for row in selected),
        key=lambda schedule: (schedule["start"], schedule["stop"], schedule["id"]),
    )
    source_rvas = [schedule["start"] for schedule in schedules]
    if len(set(source_rvas)) != len(source_rvas):
        raise StageAInputError("x87 schedule source RVAs must be unique")
    sources: dict[str, str] = {}
    witness_names: list[str] = []
    replay_witness_names: list[str] = []
    for index, schedule in enumerate(schedules):
        suffix = f"{index:04d}"
        module_name = f"{module_prefix}{suffix}"
        local_prefix = f"{definition_prefix}{suffix}"
        sources[module_name] = _relational_interpreter_x87_schedule_source(
            schedule,
            source_module=source_module,
            pe_name=pe_name,
            definition_prefix=local_prefix,
            pe_byte_pack_inventory=pe_byte_pack_inventory,
        )
        witness_names.append(f"{local_prefix}Witness")
        replay_count = sum(
            record["instruction_class"] == _X87_CLASS
            for record in schedule["records"]
        )
        replay_witness_names.extend(
            f"{local_prefix}ReplayAction{replay_index:04d}Witness"
            for replay_index in range(replay_count)
        )

    bundle_module = f"{module_prefix}Bundle"
    imports = "\n".join(f"import StageA.{module}" for module in sources)
    witnesses = ",\n  ".join(witness_names)
    replay_witnesses = ",\n  ".join(replay_witness_names)
    source_rvas_literal = ", ".join(str(source_rva) for source_rva in source_rvas)
    bundle_prefix = f"{definition_prefix}Bundle"
    sources[bundle_module] = f"""{imports}
import StageA.RelationalInterpreterAcceptance

namespace StageA.GeneratedRelational

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterAcceptance

set_option maxRecDepth 100000
set_option maxHeartbeats 0

def {bundle_prefix}Witnesses :
    List (ExactInterpreterX87ScheduleWitness {pe_name}) := [
  {witnesses}
]

def {bundle_prefix}SourceRvas : List Nat :=
  {bundle_prefix}Witnesses.map (fun witness => witness.schedule.sourceRva)

theorem {bundle_prefix}Count :
    {bundle_prefix}Witnesses.length = {len(schedules)} := by decide +kernel

def {bundle_prefix}ReplayActionWitnesses :
    List (ExactInterpreterX87ReplayActionWitness {pe_name}) := [
  {replay_witnesses}
]

theorem {bundle_prefix}ReplayActionCount :
    {bundle_prefix}ReplayActionWitnesses.length = {len(replay_witness_names)} := by decide +kernel

theorem {bundle_prefix}MemberReplayActionRefines
    (witness : ExactInterpreterX87ReplayActionWitness {pe_name})
    (_member : witness ∈ {bundle_prefix}ReplayActionWitnesses)
    (state : MachineState) :
    executeX87Singleton {pe_name} witness.record state =
      executeReplayOpcode25 {pe_name} witness.schedule witness.record state :=
  witness.stepRefines state

theorem {bundle_prefix}ExactSourceInventory :
    {bundle_prefix}SourceRvas = [{source_rvas_literal}] := by decide +kernel

theorem {bundle_prefix}SourceRvasNodup :
    {bundle_prefix}SourceRvas.Nodup := by decide +kernel

/-- The acceptance inventory is constructed from the exact schedule witnesses,
not from generator status or counts.  The equality premise ties this reusable
bundle to the canonical original PE in the final static context. -/
def {bundle_prefix}ExactOriginalInventory
    (context : StaticProofContext)
    (originalPeBound : context.originalPe = {pe_name}) :
    ExactOriginalX87Inventory context := by
  let normalized : StaticProofContext := {{
    context with originalPe := {pe_name}
  }}
  have normalizedEq : normalized = context := by
    cases context
    simp_all [normalized]
  have inventory : ExactOriginalX87Inventory normalized := {{
    requiredSourceRvas := {bundle_prefix}SourceRvas
    witnesses := {bundle_prefix}Witnesses
    requiredUnique := {bundle_prefix}SourceRvasNodup
    witnessSourcesUnique := {bundle_prefix}SourceRvasNodup
    complete := by
      intro sourceRva required
      rcases List.mem_map.mp required with ⟨witness, member, source⟩
      exact ⟨witness, member, source⟩
    exact := by
      intro witness member
      exact List.mem_map.mpr ⟨witness, member, rfl⟩
  }}
  exact normalizedEq ▸ inventory

/-- The candidate side must instantiate this PE-backed replay inventory.  Its
handler field is a universal semantic obligation, not a generated assertion. -/
def {bundle_prefix}CandidateReplayObligation
    (candidatePe : PE32) (imports : List PEImport)
    (relocations : List BaseRelocation) (tableRva countRva : Nat)
    (semanticRecords : List ProgramRecord)
    (table : ProgramTableCertificate candidatePe imports relocations tableRva
      countRva semanticRecords) (handler : CandidateReplayHandler) : Prop :=
  ExactCandidateX87ReplayInventory {pe_name} candidatePe imports relocations
    tableRva countRva semanticRecords {bundle_prefix}Witnesses table handler

theorem {bundle_prefix}MemberMacroStepRefines
    (witness : ExactInterpreterX87ScheduleWitness {pe_name})
    (member : witness \u2208 {bundle_prefix}Witnesses) (state : MachineState) :
    runExactAuthoritative {pe_name} witness.schedule state =
      runExactInterpreter {pe_name} witness.schedule state :=
  witness.certificate.macroStepRefines state

#print axioms {bundle_prefix}MemberReplayActionRefines
#print axioms {bundle_prefix}MemberMacroStepRefines

end StageA.GeneratedRelational
"""
    return sources


def _candidate_replay_membership_cases(
    names: list[str], *, member: str, success: list[str] | None = None
) -> str:
    if not names:
        return f"    simp at {member}"
    simplifier = (
        "List.mem_singleton"
        if len(names) == 1
        else "List.mem_cons, List.mem_singleton"
    )
    alternatives = " | ".join("rfl" for _ in names)
    lines = [
        f"    simp only [{simplifier}] at {member}",
        f"    rcases {member} with {alternatives}",
    ]
    if success is None:
        lines.append("    all_goals rfl")
    else:
        for statement in success:
            lines.append(f"    · {statement}")
    return "\n".join(lines)


def _candidate_replay_shard_source(
    *,
    spec: CandidateReplayProofSpec,
    shard_index: int,
    transfers: list[_CandidateReplayTransfer],
    schedule_by_rva: Mapping[int, tuple[int, Mapping[str, Any]]],
) -> tuple[str, int]:
    data_module = f"{spec.candidate_data_shard_module_prefix}{shard_index:04d}"
    data_entries = (
        f"Data.{spec.candidate_entries_prefix}{shard_index:04d}"
        f"{spec.candidate_entries_suffix}"
    )
    data_shard = (
        f"Data.{spec.candidate_shard_prefix}{shard_index:04d}"
        f"{spec.candidate_shard_suffix}"
    )
    shard_prefix = f"{spec.definition_prefix}Shard{shard_index:04d}"
    schedules = [
        schedule_by_rva[transfer.rva_start]
        for transfer in transfers
        if transfer.x87_replays
    ]
    schedule_imports = "\n".join(
        f"import StageA.{spec.schedule_module_prefix}{schedule_index:04d}"
        for schedule_index, _ in schedules
    )
    definitions: list[str] = []
    selected_entries: list[str] = []
    selected_witnesses: list[str] = []
    bindings: list[str] = []
    complete_results: list[str] = []
    exact_results: list[str] = []

    for local_index, transfer in enumerate(transfers):
        if not transfer.x87_replays:
            continue
        schedule_index, schedule = schedule_by_rva[transfer.rva_start]
        schedule_prefix = f"{spec.schedule_definition_prefix}{schedule_index:04d}"
        entry_prefix = f"{shard_prefix}Entry{local_index:04d}"
        entry_name = entry_prefix
        binding_name = f"{entry_prefix}Binding"
        selected_entries.append(entry_name)
        selected_witnesses.append(f"Original.{schedule_prefix}Witness")
        bindings.append(binding_name)
        replay_names: list[str] = []
        replay_defs: list[str] = []
        for replay_index, _replay in enumerate(transfer.x87_replays):
            replay_name = f"{entry_prefix}Replay{replay_index:04d}"
            replay_names.append(replay_name)
            replay_defs.append(
                f"def {replay_name} : RawX87Replay :=\n"
                "  candidateReplayDescriptorForAction "
                f"{spec.original_pe_name} "
                f"Original.{schedule_prefix}ReplayAction{replay_index:04d}"
            )
        replays_literal = ", ".join(replay_names)
        handler_cases = _candidate_replay_membership_cases(
            replay_names, member="replayMember"
        )
        definitions.append(
            "\n\n".join(replay_defs)
            + "\n\n"
            + f"def {entry_name} : CompiledProgramRecord :=\n"
            + f"  {data_entries}.get ⟨{local_index}, by decide +kernel⟩\n\n"
            + f"theorem {entry_prefix}Member : {entry_name} ∈ {data_entries} := by\n"
            + "  decide +kernel\n\n"
            + f"theorem {entry_prefix}Replays :\n"
            + f"    {entry_name}.x87Replays = [{replays_literal}] := by\n"
            + "  decide +kernel\n\n"
            + f"theorem {entry_prefix}Metadata :\n"
            + "    CandidateReplayRecordChecked "
            + f"{spec.original_pe_name} Original.{schedule_prefix} "
            + f"{entry_name} = true := by\n"
            + "  decide +kernel\n\n"
            + f"def {binding_name} :\n"
            + "    ExactCandidateX87ReplayBinding "
            + f"{spec.original_pe_name} Original.{schedule_prefix} "
            + f"{entry_name} (reviewedExpectedCandidateReplay "
            + f"{spec.original_pe_name}) := {{\n"
            + f"  originalSchedule := Original.{schedule_prefix}ExactCertificate\n"
            + f"  candidateMetadata := {entry_prefix}Metadata\n"
            + "  handlerRefines := by\n"
            + "    intro replay replayMember state\n"
            + f"    rw [{entry_prefix}Replays] at replayMember\n"
            + handler_cases
            + "\n}"
        )
        complete_results.append(
            f"exact ⟨{entry_name}, by simp, {binding_name}⟩"
        )
        exact_results.append(
            f"exact ⟨Original.{schedule_prefix}Witness, by simp, {binding_name}⟩"
        )

    selected_entries_literal = ", ".join(selected_entries)
    selected_witnesses_literal = ", ".join(selected_witnesses)
    definition_block = "\n\n".join(definitions)
    complete_cases = _candidate_replay_membership_cases(
        selected_witnesses, member="witnessMember", success=complete_results
    )
    exact_cases = _candidate_replay_membership_cases(
        selected_entries, member="entryMember", success=exact_results
    )
    source = f"""import StageA.{data_module}
{schedule_imports}

namespace StageA.GeneratedRelational.CandidateX87Replay

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterKernelData

namespace Original := StageA.GeneratedRelational
namespace Data := {spec.candidate_data_namespace}

set_option maxRecDepth 100000
set_option maxHeartbeats 0

{definition_block}

def {shard_prefix}Entries : List CompiledProgramRecord :=
  [{selected_entries_literal}]

def {shard_prefix}Witnesses :
    List (ExactInterpreterX87ScheduleWitness {spec.original_pe_name}) :=
  [{selected_witnesses_literal}]

theorem {shard_prefix}ReplayBearingEntries :
    replayBearingCandidateEntries {data_entries} = {shard_prefix}Entries := by
  decide +kernel

def {shard_prefix} : ExactCandidateX87ReplayShard
    {spec.original_pe_name} Data.generatedInterpreterKernelCandidatePe
    Data.generatedInterpreterKernelImports Data.generatedInterpreterKernelRelocations
    Data.generatedInterpreterKernelTableRva
    (reviewedExpectedCandidateReplay {spec.original_pe_name}) := {{
  tableShard := {data_shard}
  originalWitnesses := {shard_prefix}Witnesses
  candidateEntries := {shard_prefix}Entries
  candidateEntriesSound := by
    intro entry entryMember
    have filtered : entry ∈ replayBearingCandidateEntries {data_entries} := by
      rw [{shard_prefix}ReplayBearingEntries]
      exact entryMember
    exact (List.mem_filter.mp filtered).1
  candidateEntriesComplete := by
    intro entry entryMember replayPresent
    have filtered : entry ∈ replayBearingCandidateEntries {data_entries} := by
      apply List.mem_filter.mpr
      exact ⟨entryMember, by simp [replayPresent]⟩
    rw [{shard_prefix}ReplayBearingEntries] at filtered
    exact filtered
  complete := by
    intro witness witnessMember
{complete_cases}
  exact := by
    intro entry entryMember _replayPresent
{exact_cases}
}}

#print axioms {shard_prefix}

end StageA.GeneratedRelational.CandidateX87Replay
"""
    return source, len(selected_entries)


def relational_interpreter_x87_candidate_replay_sources(
    state_machine: Path,
    *,
    spec: CandidateReplayProofSpec,
) -> dict[str, str]:
    """Emit exact candidate replay bindings aligned to PE-decoded table shards.

    Each local module imports one compiled table shard and only the original
    schedule modules used by replay-bearing entries in that shard.  The bundle
    composes those local certificates into one concrete
    ``ExactCandidateX87ReplayInventory`` value.
    """

    if spec.table_shard_size <= 0:
        raise StageAInputError("candidate replay table_shard_size must be positive")
    original_source_module, _ = _stage_a_module(
        spec.original_source_module, "original_source_module"
    )
    original_pe_name = _lean_name(spec.original_pe_name, "original_pe_name")
    candidate_data_namespace = _lean_name(
        spec.candidate_data_namespace, "candidate_data_namespace"
    )
    for field_name in (
        "schedule_module_prefix",
        "schedule_definition_prefix",
        "candidate_data_shard_module_prefix",
        "candidate_data_bundle_module",
        "candidate_entries_prefix",
        "candidate_shard_prefix",
        "candidate_table_certificate",
        "module_prefix",
        "bundle_module",
        "definition_prefix",
    ):
        _local_name(getattr(spec, field_name), field_name)
    for field_name in ("candidate_entries_suffix", "candidate_shard_suffix"):
        value = getattr(spec, field_name)
        if value:
            _local_name(value, field_name)
    spec = CandidateReplayProofSpec(
        **{
            **spec.__dict__,
            "original_source_module": original_source_module,
            "original_pe_name": original_pe_name,
            "candidate_data_namespace": candidate_data_namespace,
        }
    )

    rows = _read_rows(state_machine)
    schedules = sorted(
        (_validated_schedule(row) for row in rows if row.get("instruction_effect_schedule") is not None),
        key=lambda schedule: (schedule["start"], schedule["stop"], schedule["id"]),
    )
    schedule_by_rva = {
        schedule["start"]: (index, schedule)
        for index, schedule in enumerate(schedules)
    }
    if len(schedule_by_rva) != len(schedules):
        raise StageAInputError("candidate replay schedules have duplicate source RVAs")
    transfers = _candidate_replay_transfers(rows, schedules)
    transfer_rvas = {transfer.rva_start for transfer in transfers}
    if set(schedule_by_rva) != {
        transfer.rva_start for transfer in transfers if transfer.x87_replays
    }:
        missing = sorted(set(schedule_by_rva) - transfer_rvas)
        raise StageAInputError(
            "candidate replay schedules and compiled replay entries differ"
            + (f"; missing compiled RVAs: {missing}" if missing else "")
        )

    sources: dict[str, str] = {}
    shard_names: list[str] = []
    shard_values: list[str] = []
    replay_count = 0
    for shard_index, start in enumerate(
        range(0, len(transfers), spec.table_shard_size)
    ):
        shard_transfers = transfers[start : start + spec.table_shard_size]
        module_name = f"{spec.module_prefix}{shard_index:04d}"
        source, local_count = _candidate_replay_shard_source(
            spec=spec,
            shard_index=shard_index,
            transfers=shard_transfers,
            schedule_by_rva=schedule_by_rva,
        )
        sources[module_name] = source
        shard_names.append(module_name)
        shard_values.append(f"{spec.definition_prefix}Shard{shard_index:04d}")
        replay_count += local_count

    imports = "\n".join(f"import StageA.{name}" for name in shard_names)
    shard_literal = ",\n  ".join(shard_values)
    bundle_prefix = f"{spec.definition_prefix}Bundle"
    bundle = f"""{imports}
import StageA.{spec.candidate_data_bundle_module}
import StageA.{spec.schedule_module_prefix}Bundle

namespace StageA.GeneratedRelational.CandidateX87Replay

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterKernelData

namespace Original := StageA.GeneratedRelational
namespace Data := {spec.candidate_data_namespace}

def {bundle_prefix}Handler : CandidateReplayHandler :=
  reviewedExpectedCandidateReplay {spec.original_pe_name}

def {bundle_prefix}Shards : List (ExactCandidateX87ReplayShard
    {spec.original_pe_name} Data.generatedInterpreterKernelCandidatePe
    Data.generatedInterpreterKernelImports Data.generatedInterpreterKernelRelocations
    Data.generatedInterpreterKernelTableRva {bundle_prefix}Handler) := [
  {shard_literal}
]

theorem {bundle_prefix}OriginalWitnessesExact :
    Original.{spec.schedule_definition_prefix}BundleWitnesses =
      candidateReplayShardOriginalWitnesses {bundle_prefix}Shards := by
  rfl

theorem {bundle_prefix}TableShardsExact :
    candidateReplayTableShards {bundle_prefix}Shards =
      Data.{spec.candidate_table_certificate}.shards := by
  rfl

/-- Concrete candidate replay inventory.  Every candidate descriptor is read
from the exact PE-backed table certificate and bound to the reviewed original
x87 state transformer. -/
def {bundle_prefix}ExactInventory : ExactCandidateX87ReplayInventory
    {spec.original_pe_name} Data.generatedInterpreterKernelCandidatePe
    Data.generatedInterpreterKernelImports Data.generatedInterpreterKernelRelocations
    Data.generatedInterpreterKernelTableRva Data.generatedInterpreterKernelCountRva
    Data.semanticInterpreterProgramRecords
    Original.{spec.schedule_definition_prefix}BundleWitnesses
    Data.{spec.candidate_table_certificate} {bundle_prefix}Handler :=
  ExactCandidateX87ReplayInventory.ofShards {bundle_prefix}Shards
    {bundle_prefix}OriginalWitnessesExact {bundle_prefix}TableShardsExact

/-- Deliberately unresolved here: the compiled bridge execution relation must
come from exact candidate-PE execution, not from selecting the semantic Lean
handler above. -/
def {bundle_prefix}CompiledNativeBridgeRefinementObligation
    (executes : CandidateReplayExecutionRelation) : Prop :=
  CompiledNativeReplayBridgeRefines Data.{spec.candidate_table_certificate}
    executes {bundle_prefix}Handler

#print axioms {bundle_prefix}ExactInventory

end StageA.GeneratedRelational.CandidateX87Replay
"""
    sources[spec.bundle_module] = bundle
    if replay_count != len(schedules):
        raise StageAInputError("candidate replay entry inventory is inconsistent")
    return sources


def relational_interpreter_x87_candidate_replay_inventory(
    state_machine: Path,
    *,
    spec: CandidateReplayProofSpec,
) -> dict[str, Any]:
    sources = relational_interpreter_x87_candidate_replay_sources(
        state_machine, spec=spec
    )
    modules = {
        module: {
            "imports": _STAGE_A_IMPORT.findall(source),
            "source_sha256": sha256_bytes(source.encode("utf-8")),
            "source_bytes": len(source.encode("utf-8")),
        }
        for module, source in sources.items()
    }
    bundle_prefix = f"{spec.definition_prefix}Bundle"
    rows = _read_rows(state_machine)
    schedules = sorted(
        (_validated_schedule(row) for row in rows if row.get("instruction_effect_schedule") is not None),
        key=lambda schedule: (schedule["start"], schedule["stop"], schedule["id"]),
    )
    transfers = _candidate_replay_transfers(rows, schedules)
    replay_entries = len(schedules)
    replay_actions = sum(schedule["x87_count"] for schedule in schedules)
    return {
        "format": RELATIONAL_INTERPRETER_X87_CANDIDATE_REPLAY_INVENTORY_FORMAT,
        "status": "source-ready",
        "proof_authority": False,
        "modules": modules,
        "targets": {
            "bundle_node": spec.bundle_module,
            "semantic_handler": f"{bundle_prefix}Handler",
            "exact_candidate_inventory": f"{bundle_prefix}ExactInventory",
            "compiled_native_bridge_obligation": (
                f"{bundle_prefix}CompiledNativeBridgeRefinementObligation"
            ),
        },
        "counts": {
            "table_shards": len(sources) - 1,
            "replay_entries": replay_entries,
            "replay_actions": replay_actions,
            "generated_modules": len(sources),
        },
        "native_bridge_status": "incomplete",
        "native_bridge_reason": (
            "exact candidate C/assembly replay execution is not yet connected "
            "to the reviewed semantic handler"
        ),
    }


def relational_interpreter_x87_module_inventory(
    state_machine: Path,
    *,
    source_module: str,
    pe_name: str,
    module_prefix: str = "GeneratedInterpreterX87Schedule",
    definition_prefix: str = "checkedInterpreterX87Schedule",
    pe_byte_pack_inventory: PEBytePackInventory | None = None,
) -> dict[str, Any]:
    """Describe generated shards in the canonical Nix module-graph vocabulary.

    This is deliberately an inventory rather than a proof result.  The ordinary
    Stage A graph writer still hashes the materialized sources and assigns Nix
    derivations; this helper makes the required external modules and target node
    explicit without creating a second authoritative graph format.
    """

    source_module, source_module_name = _stage_a_module(
        source_module, "source_module"
    )
    sources = relational_interpreter_x87_bundle_sources(
        state_machine,
        source_module=source_module,
        pe_name=pe_name,
        module_prefix=module_prefix,
        definition_prefix=definition_prefix,
        pe_byte_pack_inventory=pe_byte_pack_inventory,
    )
    bundle_module = f"{module_prefix}Bundle"
    shard_modules = [module for module in sources if module != bundle_module]
    modules: dict[str, dict[str, Any]] = {}
    for module, source in sources.items():
        modules[module] = {
            "imports": _STAGE_A_IMPORT.findall(source),
            "source_sha256": sha256_bytes(source.encode("utf-8")),
            "source_bytes": len(source.encode("utf-8")),
        }
    required_external_modules = sorted(
        {
            dependency
            for metadata in modules.values()
            for dependency in metadata["imports"]
            if dependency not in modules
        }
    )
    if (
        pe_byte_pack_inventory is None
        and source_module_name not in required_external_modules
    ):
        raise StageAInputError(
            "generated x87 modules do not import their declared PE source module"
        )
    preflight = relational_interpreter_x87_preflight(state_machine)
    if preflight["status"] != "ready":
        raise StageAInputError("x87 module inventory requires a ready preflight")
    return {
        "format": RELATIONAL_INTERPRETER_X87_MODULE_INVENTORY_FORMAT,
        "status": "ready",
        "proof_authority": False,
        "source_module": source_module,
        "pe_name": pe_name,
        "module_prefix": module_prefix,
        "pe_byte_packs": (
            None
            if pe_byte_pack_inventory is None
            else {
                "format": pe_byte_pack_inventory.payload()["format"],
                "source_sha256": pe_byte_pack_inventory.source_sha256,
                "authoritative_module": (
                    pe_byte_pack_inventory.authoritative_module
                ),
                "pack_modules": sorted(
                    dependency
                    for dependency in required_external_modules
                    if dependency in {
                        pack.certificate_module
                        for pack in pe_byte_pack_inventory.packs
                    }
                ),
            }
        ),
        "modules": modules,
        "required_external_modules": required_external_modules,
        "targets": {
            "schedule_nodes": shard_modules,
            "bundle_node": bundle_module,
            "exact_original_inventory": (
                f"{definition_prefix}BundleExactOriginalInventory"
            ),
            "exact_replay_action_inventory": (
                f"{definition_prefix}BundleReplayActionWitnesses"
            ),
            "candidate_replay_obligation": (
                f"{definition_prefix}BundleCandidateReplayObligation"
            ),
        },
        "counts": {
            "schedule_modules": len(shard_modules),
            "bundle_modules": 1,
            "generated_modules": len(sources),
            "x87_singleton_replays": preflight["counts"][
                "x87_singleton_replays"
            ],
            "candidate_replay_obligations": preflight["counts"][
                "x87_singleton_replays"
            ],
            "ordinary_instruction_records": preflight["counts"][
                "ordinary_instruction_records"
            ],
        },
    }
