from __future__ import annotations

import json
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import pefile

from ..artifacts.formats import (
    SEMANTIC_IR_FORMAT,
    SEMANTIC_TRANSFER_CONTRACT_FORMAT,
    STATIC_PROGRAM_SEMANTIC_BINDING_FORMAT,
)
from ..external.callbacks import parse_callback_abi, parse_callback_source
from ..external.machine_import_profiles import load_machine_import_profile_set
from ..errors import ToolkitInputError
from ..static_program.codec import load_static_program_contract_binding
from ..static_program.model import StaticProgramContractBinding
from ..util import sha256_bytes, sha256_file


SPX_STATE_MACHINE_FORMAT = "spaghetti-extractor-state-machine-transfer-v1"
SPX_SEMANTIC_IR_MODEL = SEMANTIC_IR_FORMAT
SPX_SEMANTIC_TRANSFER_FORMAT = SEMANTIC_TRANSFER_CONTRACT_FORMAT

_TRANSFER_FIELDS = (
    "format",
    "id",
    "function",
    "block_id",
    "unit_kind",
    "status",
    "span",
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
class StateMachineBinding:
    path: Path
    sha256: str
    static_program_contract_sha256: str
    semantic_transfer_contracts_sha256: str
    transfer_count: int


def normalize_spx_semantic_transfer(
    row: dict[str, Any],
    *,
    static_program_contract_sha256: str | None = None,
    semantic_transfer_sha256: str | None = None,
) -> dict[str, Any]:
    """Preserve the checked static analysis transfer IR used to generate candidate reconstruction source."""

    source_row = dict(row)
    if "span" not in source_row:
        if (
            source_row.get("spx_format") != SPX_STATE_MACHINE_FORMAT
            or not isinstance(source_row.get("original"), Mapping)
        ):
            raise ToolkitInputError("static semantic transfer omits its source span")
        source_row["span"] = source_row["original"]
    normalized = {
        key: _json_value(source_row[key])
        for key in (*_TRANSFER_FIELDS, *_OPTIONAL_TRANSFER_FIELDS)
        if key in source_row
    }
    source_bytes = _canonical_json(normalized)
    normalized["original"] = normalized.pop("span")
    normalized["spx_format"] = SPX_STATE_MACHINE_FORMAT
    normalized["contract_sha256"] = sha256_bytes(source_bytes)
    existing_binding = source_row.get("static_program_export")
    if existing_binding is not None:
        binding = _parse_semantic_export_binding(existing_binding)
        if static_program_contract_sha256 is not None and (
            binding["static_program_contract_sha256"]
            != static_program_contract_sha256
        ):
            raise ToolkitInputError("state-machine static-program binding changed")
        if semantic_transfer_sha256 is not None and (
            binding["semantic_transfer_sha256"] != semantic_transfer_sha256
        ):
            raise ToolkitInputError("state-machine semantic-transfer binding changed")
        normalized["static_program_export"] = binding
    elif static_program_contract_sha256 is not None or semantic_transfer_sha256 is not None:
        normalized["static_program_export"] = {
            "format": STATIC_PROGRAM_SEMANTIC_BINDING_FORMAT,
            "static_program_contract_sha256": _digest(
                static_program_contract_sha256, "semantic export static program"
            ),
            "semantic_transfer_sha256": _digest(
                semantic_transfer_sha256, "semantic export transfer"
            ),
        }
    return normalized


def write_state_machine_from_static_program(
    *,
    static_program_contract: Path,
    semantic_transfer_contracts: Path,
    out: Path,
    original_pe: Path | None = None,
) -> StateMachineBinding:
    """Derive the canonical machine-state IR from an original-only contract."""

    static_program = load_static_program_contract_binding(
        static_program_contract, original_pe=original_pe
    )
    semantic_path = Path(semantic_transfer_contracts).resolve()
    if not semantic_path.is_file() or semantic_path.is_symlink():
        raise ToolkitInputError("static analysis semantic-transfer sidecar must be a regular file")
    declared_semantic = static_program.semantic_transfers
    if semantic_path != declared_semantic:
        raise ToolkitInputError(
            "semantic-transfer input is not the sidecar declared by the static program"
        )
    if sha256_file(semantic_path) != static_program.semantic_transfers_sha256:
        raise ToolkitInputError(
            "semantic-transfer input differs from the static-program hash binding"
        )
    raw_rows = _load_spx_semantic_transfer_rows(semantic_path, static_program)
    rows = [
        normalize_spx_semantic_transfer(
            row,
            static_program_contract_sha256=static_program.sha256,
            semantic_transfer_sha256=sha256_bytes(_canonical_json(row)),
        )
        for row in raw_rows
    ]
    rows = normalize_spx_semantic_transfers(rows)
    if not rows:
        raise ToolkitInputError("static analysis semantic-transfer export is empty")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    write_spx_state_machine(out, rows)
    return StateMachineBinding(
        path=out.resolve(),
        sha256=sha256_file(out),
        static_program_contract_sha256=static_program.sha256,
        semantic_transfer_contracts_sha256=sha256_file(semantic_path),
        transfer_count=len(rows),
    )


def validate_state_machine_static_program_chain(
    *,
    state_machine: Path,
    static_program_contract: Path,
    semantic_transfer_contracts: Path,
    original_pe: Path | None = None,
) -> StateMachineBinding:
    """Check that a state machine is exactly reproducible from static evidence."""

    state_machine = Path(state_machine).resolve()
    with tempfile.TemporaryDirectory(prefix="spaghetti-extractor-state-machine-check-") as temporary:
        expected_path = Path(temporary) / "expected.jsonl"
        expected = write_state_machine_from_static_program(
            static_program_contract=static_program_contract,
            semantic_transfer_contracts=semantic_transfer_contracts,
            out=expected_path,
            original_pe=original_pe,
        )
        if state_machine.is_symlink() or not state_machine.is_file():
            raise ToolkitInputError("candidate reconstruction state machine must be a regular non-symlink file")
        observed_sha = sha256_file(state_machine)
        if observed_sha != expected.sha256:
            raise ToolkitInputError(
                "candidate reconstruction state machine is not the canonical derivative of the static analysis exports"
            )
        return StateMachineBinding(
            path=state_machine,
            sha256=observed_sha,
            static_program_contract_sha256=expected.static_program_contract_sha256,
            semantic_transfer_contracts_sha256=expected.semantic_transfer_contracts_sha256,
            transfer_count=expected.transfer_count,
        )


def normalize_spx_semantic_transfers(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_rows: dict[str, dict[str, Any]] = {}
    for row in rows:
        normalized = normalize_spx_semantic_transfer(row)
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


def write_spx_state_machine(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def annotate_state_machine_import_contracts(
    rows: Iterable[dict[str, Any]],
    *,
    machine_import_profiles: Sequence[Path] = (),
) -> tuple[list[dict[str, Any]], tuple[int, ...]]:
    """Bind reviewed import arguments and no-return dispositions once.

    This annotation is a static proposal. The machine-IR exporter independently
    validates the exact imported call site and the selected profile binding.
    """

    contracts = _machine_import_contracts(machine_import_profiles)
    annotated = [
        _annotate_machine_import_arguments(dict(row), contracts) for row in rows
    ]
    terminating_imports = frozenset(
        identity
        for identity, contract in contracts.items()
        if contract.get("disposition") == "terminates"
    )
    terminating = tuple(sorted(
        _transfer_start(row)
        for row in annotated
        if _row_calls_terminating_import(row, terminating_imports)
    ))
    terminating_set = frozenset(terminating)
    result = [
        {
            **row,
            "control_disposition": {
                "kind": "terminates_after_external_event",
                "authority": "external_profile_machine_import_contract",
            },
        }
        if _transfer_start(row) in terminating_set
        else row
        for row in annotated
    ]
    return normalize_spx_semantic_transfers(result), terminating


def _read_state_machine_rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        raise ToolkitInputError("state machine must be a regular file")
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ToolkitInputError(
                f"invalid state-machine JSON on line {line_number}: {exc}"
            ) from exc
        rows.append(_object(value, f"state-machine line {line_number}"))
    return rows


def semantic_direct_targets(row: Mapping[str, Any]) -> tuple[int, ...]:
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

def _machine_import_contracts(
    machine_import_profiles: Sequence[Path],
) -> dict[tuple[str, str, Any], dict[str, Any]]:
    if not machine_import_profiles:
        return {}
    profile_set = load_machine_import_profile_set(
        [Path(path).resolve() for path in machine_import_profiles]
    )
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
            raise ToolkitInputError(
                f"external profile contract {contract['id']!r} has invalid argument_words"
            )
        if contract.get("abi_template") not in {
            "pe32-cdecl-v1",
            "pe32-stdcall-v1",
        }:
            raise ToolkitInputError(
                f"external profile contract {contract['id']!r} has unsupported ABI template"
            )
        world_effect = contract.get("world_effect")
        callback_abi = contract.get("callback_abi")
        if world_effect == "callbackRegistration":
            context = f"external profile contract {contract['id']!r}"
            source = parse_callback_source(
                contract, argument_words=argument_words, context=context
            )
            callback = parse_callback_abi(contract, context=context)
            contract["callback_source"] = source.as_json()
            contract["callback_abi"] = callback.as_json()
            callback_lifetime = contract.get("callback_lifetime")
            if not isinstance(callback_lifetime, (str, dict)) or not callback_lifetime:
                raise ToolkitInputError(
                    f"external profile contract {contract['id']!r} has no exact callback lifetime"
                )
            callback_result = contract.get("callback_result")
            if callback_result is not None and (
                not isinstance(callback_result, Mapping)
                or set(callback_result) != {"register", "origin", "nullable"}
                or callback_result.get("register")
                not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
                or callback_result.get("origin") != "previous_registered_callback"
                or not isinstance(callback_result.get("nullable"), bool)
            ):
                raise ToolkitInputError(
                    f"external profile contract {contract['id']!r} has an invalid callback result"
                )
        elif callback_abi is not None:
            raise ToolkitInputError(
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
            raise ToolkitInputError(f"{label} arguments must be a list")
        if arguments and len(arguments) != argument_words:
            raise ToolkitInputError(
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
            raise ToolkitInputError(f"{label} stack_inputs must be a list")
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
        }
        for field in (
            "disposition",
            "memory_effect",
            "world_effect",
            "callback_effect",
        ):
            if field in contract:
                abi_contract[field] = contract[field]
        for field in (
            "result_register_relations",
            "memory_footprints",
            "out_pointer_relations",
            "out_interface_relations",
        ):
            if field in contract:
                abi_contract[field] = _machine_contract_metadata(contract[field])
        profile_binding = contract.get("profile_binding")
        if isinstance(profile_binding, Mapping):
            abi_contract["profile_binding"] = dict(profile_binding)
        if contract.get("world_effect") == "callbackRegistration":
            callback_source = parse_callback_source(
                contract,
                argument_words=argument_words,
                context=f"machine call {contract.get('id')!r}",
            )
            callback = parse_callback_abi(
                contract, context=f"machine call {contract.get('id')!r}"
            )
            abi_contract.update({
                "callback_source": callback_source.as_json(),
                "callback_abi": callback.as_json(),
                "callback_behavior": contract.get(
                    "callback_behavior", "registration"
                ),
                "callback_lifetime": _machine_contract_metadata(
                    contract.get("callback_lifetime")
                ),
            })
            if contract.get("callback_result") is not None:
                abi_contract["callback_result"] = dict(contract["callback_result"])
        event["abi_contract"] = abi_contract
        return event

    result = dict(row)
    external_events = row.get("external_events")
    if not isinstance(external_events, list):
        raise ToolkitInputError("semantic transfer external_events must be a list")
    ordered_events = row.get("ordered_events")
    if not isinstance(ordered_events, list):
        raise ToolkitInputError("semantic transfer ordered_events must be a list")
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
                    raise ToolkitInputError(
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
                raise ToolkitInputError(
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
        raise ToolkitInputError("instruction effect schedule records must be a list")

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
            raise ToolkitInputError(
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
                    raise ToolkitInputError(
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
            raise ToolkitInputError(
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
        raise ToolkitInputError(
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
        raise ToolkitInputError(f"{label} DLL identity must be a nonempty string")
    symbol = event.get("symbol")
    ordinal = event.get("ordinal")
    if symbol is None and ordinal is None:
        raise ToolkitInputError(f"{label} has no symbol or ordinal identity")
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
        raise ToolkitInputError(f"{label} digest does not match its canonical contents")


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
        raise ToolkitInputError("semantic transfer external_events must be a list")
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


def _transfer_start(row: Mapping[str, Any]) -> int:
    span = row.get("span")
    if not isinstance(span, dict):
        span = row.get("original")
    value = span.get("rva_start") if isinstance(span, dict) else row.get("rva_start")
    return int(value) if isinstance(value, int) else 0x7FFFFFFF


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _json_value(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _validate_restartable_string_events(
    row: Mapping[str, Any], label: str
) -> None:
    def validate(raw: Any, expected_index: int, event_label: str) -> None:
        event = _object(raw, event_label)
        kind = event.get("kind")
        if kind not in {"rep_movs", "rep_stos", "rep_scas"}:
            return
        if event.get("index") != expected_index:
            raise ToolkitInputError(
                f"{event_label} has a noncanonical external-event index"
            )
        allowed_widths = {1} if kind == "rep_scas" else {1, 2, 4}
        if event.get("element_width") not in allowed_widths:
            raise ToolkitInputError(f"{event_label} has an invalid element width")
        if event.get("address_size") != 32:
            raise ToolkitInputError(f"{event_label} has an unsupported address size")
        expected_model = {
            "rep_movs": "symbolic_string_copy_v2",
            "rep_stos": "symbolic_string_fill_v2",
            "rep_scas": "symbolic_string_scan_v1",
        }[kind]
        if event.get("effect_model") != expected_model:
            raise ToolkitInputError(f"{event_label} has an invalid effect model")
        if event.get("restart_semantics") != "element_committed_v1":
            raise ToolkitInputError(f"{event_label} lacks restart-state semantics")
        operand = {
            "rep_movs": "source",
            "rep_stos": "value",
            "rep_scas": "accumulator",
        }[kind]
        required = {"destination", "count", "direction_flag", operand}
        forbidden = {"source", "value", "accumulator"} - {operand}
        for field in sorted(required):
            if not isinstance(event.get(field), Mapping):
                raise ToolkitInputError(f"{event_label}.{field} must be an expression")
        if any(field in event for field in forbidden):
            raise ToolkitInputError(f"{event_label} mixes string-operation operands")
        if kind == "rep_scas":
            expected_fields = {
                "repeat_condition": "while_not_equal_v1",
                "comparison_model": "subtraction_flags_v1",
                "segment_model": "flat_es_zero_v1",
                "fault_model": "read_before_commit_v1",
                "owned_register_outputs": ["edi", "ecx"],
                "owned_flag_outputs": ["cf", "pf", "af", "zf", "sf", "of"],
            }
            for field, expected in expected_fields.items():
                if event.get(field) != expected:
                    raise ToolkitInputError(
                        f"{event_label} has an invalid {field.replace('_', ' ')}"
                    )

    external_events = row.get("external_events")
    ordered_events = row.get("ordered_events")
    if not isinstance(external_events, list) or not isinstance(ordered_events, list):
        return
    for index, event in enumerate(external_events):
        validate(event, index, f"{label}.external_events[{index}]")
    external_index = 0
    for index, raw in enumerate(ordered_events):
        event = _object(raw, f"{label}.ordered_events[{index}]")
        if event.get("family") != "external":
            continue
        validate(event, external_index, f"{label}.ordered_events[{index}]")
        external_index += 1


def _load_spx_semantic_transfer_rows(
    path: Path,
    static_program: StaticProgramContractBinding,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ToolkitInputError(
                f"static analysis semantic-transfer line {line_number} is invalid JSON: {exc}"
            ) from exc
        row = _object(raw, f"static analysis semantic-transfer line {line_number}")
        expected_fields = set(_TRANSFER_FIELDS)
        allowed_fields = expected_fields | set(_OPTIONAL_TRANSFER_FIELDS)
        missing = sorted(expected_fields - set(row))
        extra = sorted(set(row) - allowed_fields)
        if missing or extra:
            raise ToolkitInputError(
                f"static analysis semantic-transfer line {line_number} has schema drift: "
                f"missing={missing}, extra={extra}"
            )
        if row.get("format") != SPX_SEMANTIC_TRANSFER_FORMAT:
            raise ToolkitInputError(
                f"static analysis semantic-transfer line {line_number} has an unsupported format"
            )
        identity = row.get("id")
        if not isinstance(identity, str) or not identity:
            raise ToolkitInputError(
                f"static analysis semantic-transfer line {line_number} omits its identity"
            )
        if identity in seen_ids:
            raise ToolkitInputError(f"static analysis semantic-transfer identity is duplicated: {identity}")
        seen_ids.add(identity)
        if row.get("expression_model") != SPX_SEMANTIC_IR_MODEL:
            raise ToolkitInputError(
                f"static analysis semantic-transfer line {line_number} has an unsupported expression model"
            )
        for field in (
            "instructions", "register_writes", "flag_writes", "memory_events",
            "external_events", "faults", "ordered_events", "edge_conditions",
        ):
            if not isinstance(row.get(field), list):
                raise ToolkitInputError(
                    f"static analysis semantic-transfer line {line_number}.{field} must be a list"
                )
        _validate_restartable_string_events(
            row,
            f"static analysis semantic-transfer line {line_number}",
        )
        if "instruction_effect_schedule" in row and not isinstance(
            row["instruction_effect_schedule"], dict
        ):
            raise ToolkitInputError(
                f"static analysis semantic-transfer line {line_number}."
                "instruction_effect_schedule must be an object"
            )
        if "blocking_instruction" in row and row["blocking_instruction"] is not None:
            _object(
                row["blocking_instruction"],
                f"static analysis semantic-transfer line {line_number}.blocking_instruction",
            )
        if "semantic_cutpoint" in row:
            cutpoint = _object(
                row["semantic_cutpoint"],
                f"static analysis semantic-transfer line {line_number}.semantic_cutpoint",
            )
            if set(cutpoint) != {"index", "parent_block_id", "policy"}:
                raise ToolkitInputError(
                    f"static analysis semantic-transfer line {line_number} has an invalid "
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
                raise ToolkitInputError(
                    f"static analysis semantic-transfer line {line_number} has invalid "
                    "semantic-cutpoint evidence"
                )
        instruction_bytes = bytearray()
        for instruction_index, instruction_raw in enumerate(row["instructions"]):
            instruction = _object(
                instruction_raw,
                f"static analysis semantic-transfer line {line_number} instruction {instruction_index}",
            )
            encoded = instruction.get("bytes")
            if not isinstance(encoded, str):
                raise ToolkitInputError(
                    f"static analysis semantic-transfer line {line_number} has missing instruction bytes"
                )
            try:
                instruction_bytes.extend(bytes.fromhex(encoded))
            except ValueError as exc:
                raise ToolkitInputError(
                    f"static analysis semantic-transfer line {line_number} has invalid instruction bytes"
                ) from exc
        instruction_digest = _digest(
            row.get("instruction_bytes_sha256"),
            f"static analysis semantic-transfer line {line_number} instruction digest",
        )
        if sha256_bytes(bytes(instruction_bytes)) != instruction_digest:
            raise ToolkitInputError(
                f"static analysis semantic-transfer line {line_number} instruction digest changed"
            )
        rows.append(dict(row))
    return rows


def _parse_semantic_export_binding(value: Any) -> dict[str, str]:
    binding = _object(value, "state-machine static-program export binding")
    expected = {
        "format",
        "static_program_contract_sha256",
        "semantic_transfer_sha256",
    }
    if set(binding) != expected:
        raise ToolkitInputError("state-machine static analysis export binding has undeclared fields")
    if binding.get("format") != STATIC_PROGRAM_SEMANTIC_BINDING_FORMAT:
        raise ToolkitInputError(
            "state-machine static-program export binding has an unsupported format"
        )
    return {
        "format": STATIC_PROGRAM_SEMANTIC_BINDING_FORMAT,
        "static_program_contract_sha256": _digest(
            binding.get("static_program_contract_sha256"),
            "state-machine static-program contract",
        ),
        "semantic_transfer_sha256": _digest(
            binding.get("semantic_transfer_sha256"), "state-machine semantic transfer"
        ),
    }


def _read_json_object(path: Path, context: str) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        raise ToolkitInputError(f"{context} must be a regular non-symlink file")
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolkitInputError(f"cannot read {context}: {exc}") from exc


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an object")
    return dict(value)


def _digest(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ToolkitInputError(f"{context} must be a lowercase SHA-256 digest")
    return value


def _nonnegative_int(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ToolkitInputError(f"{context} must be a non-negative integer")
    return value


def _u32(value: Any, context: str) -> int:
    result = _nonnegative_int(value, context)
    if result >= 2**32:
        raise ToolkitInputError(f"{context} must fit in 32 bits")
    return result


__all__ = [
    "SPX_SEMANTIC_IR_MODEL",
    "SPX_SEMANTIC_TRANSFER_FORMAT",
    "SPX_STATE_MACHINE_FORMAT",
    "StateMachineBinding",
    "annotate_state_machine_import_contracts",
    "normalize_spx_semantic_transfer",
    "normalize_spx_semantic_transfers",
    "semantic_direct_targets",
    "validate_state_machine_static_program_chain",
    "write_spx_state_machine",
    "write_state_machine_from_static_program",
]
