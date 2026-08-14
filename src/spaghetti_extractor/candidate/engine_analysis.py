"""Root-independent machine-IR and import analyses for candidate planning."""

from __future__ import annotations

import copy
import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..callback_contracts import (
    CallbackABI,
    CallbackSource,
    parse_callback_abi,
    parse_callback_source,
)
from ..external.contracts import CheckedExternalSiteContract
from ..stage_binary import StageAInputError
from ..util import sha256_bytes, sha256_file
from .engine_model import (
    NativeTerminationImport,
    _CALL_KINDS,
    _MACHINE_FLAGS,
    _MACHINE_IR_FORMAT,
    _MACHINE_REGISTERS,
    _PE32_CALLEE_PRESERVED_REGISTERS,
    _RAW_INSTRUCTION_FIELDS,
    _canonical_sha256,
)
from .engine_x87 import (
    _required_portable_identity,
    _required_sha256,
    _required_string,
    _required_u32,
)


def _parse_native_termination_import(
    value: Mapping[str, Any] | None,
    import_iat_vas: Mapping[tuple[str, str | int], int],
) -> NativeTerminationImport | None:
    if value is None:
        return None
    dll = _required_string(value.get("dll"), "termination import DLL").lower()
    symbol_value = value.get("symbol")
    ordinal_value = value.get("ordinal")
    if (symbol_value is None) == (ordinal_value is None):
        raise StageAInputError(
            "termination import must provide exactly one symbol or ordinal"
        )
    symbol = (
        _required_string(symbol_value, "termination import symbol")
        if symbol_value is not None
        else None
    )
    ordinal = (
        _required_u32(ordinal_value, "termination import ordinal")
        if ordinal_value is not None
        else None
    )
    if value.get("disposition") != "terminates":
        raise StageAInputError(
            "termination import must be selected from a modeled terminates contract"
        )
    if symbol is not None:
        identity: str | int = symbol
    else:
        assert ordinal is not None
        identity = ordinal
    iat_va = import_iat_vas.get((dll, identity))
    if iat_va is None:
        raise StageAInputError(
            "termination import has no unique IAT cell in the load-image contract"
        )
    return NativeTerminationImport(
        dll=dll,
        symbol=symbol,
        ordinal=ordinal,
        iat_va=_required_u32(iat_va, "termination import IAT VA"),
    )


def _external_runtime_semantics(
    contract: CheckedExternalSiteContract,
) -> dict[str, Any]:
    """Return only the fields that affect the generated runtime bridge."""

    payload = copy.deepcopy(contract.payload())
    for field in ("identity", "contract_id", "profile_binding"):
        payload.pop(field, None)
    return payload


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


def _adapt_native_machine_ir_unit(
    unit: Mapping[str, Any], row_index: int
) -> dict[str, Any]:
    if unit.get("format") != _MACHINE_IR_FORMAT or unit.get("record_kind") != "unit":
        raise StageAInputError(f"machine-IR record {row_index} is not a v2 unit")
    if _contains_raw_instruction_material(unit):
        raise StageAInputError(
            f"machine-IR record {row_index} contains raw instruction material"
        )
    transfer_id = _required_string(
        unit.get("id"), f"machine-IR record {row_index} id"
    )
    if unit.get("status") != "qualified":
        raise StageAInputError(f"{transfer_id} is not a qualified machine-IR unit")
    source = unit.get("source")
    semantics = unit.get("semantics")
    if not isinstance(source, Mapping) or not isinstance(semantics, Mapping):
        raise StageAInputError(f"{transfer_id} source or semantics is malformed")
    original = source.get("original")
    if not isinstance(original, Mapping):
        raise StageAInputError(f"{transfer_id} has no machine-IR source span")
    rva_start = _required_u32(
        original.get("rva_start"), f"{transfer_id} original start RVA"
    )
    rva_end = _required_u32(
        original.get("rva_end"), f"{transfer_id} original end RVA"
    )
    size = original.get("size")
    if (
        rva_end <= rva_start
        or isinstance(size, bool)
        or not isinstance(size, int)
        or size != rva_end - rva_start
    ):
        raise StageAInputError(f"{transfer_id} machine-IR source span is inconsistent")
    instructions = _machine_ir_instruction_inventory(
        transfer_id=transfer_id,
        raw_instructions=unit.get("instructions"),
        rva_start=rva_start,
        rva_end=rva_end,
    )
    ordered_events = semantics.get("ordered_events")
    if not isinstance(ordered_events, list):
        raise StageAInputError(f"{transfer_id} ordered_events must be a list")
    semantic_export = source.get("semantic_export")
    return {
        "id": transfer_id,
        "original": {"rva_start": rva_start, "rva_end": rva_end, "size": size},
        "instructions": instructions,
        "ordered_events": ordered_events,
        "register_writes": semantics.get("register_writes"),
        "outcome": semantics.get("outcome"),
        "fpu_state": semantics.get("fpu_state"),
        "instruction_effect_schedule": semantics.get("instruction_effect_schedule"),
        "contract_sha256": _required_sha256(
            source.get("contract_sha256"), f"{transfer_id} contract SHA-256"
        ),
        "instruction_bytes_sha256": _required_sha256(
            source.get("instruction_bytes_sha256"),
            f"{transfer_id} source-span SHA-256",
        ),
        "stage_a_export": (
            dict(semantic_export) if isinstance(semantic_export, Mapping) else None
        ),
        "_machine_ir": True,
        "_machine_ir_x87_micro_ops": unit.get("x87_micro_ops"),
        "_source_record_sha256": _canonical_sha256(unit),
    }


def _machine_ir_instruction_inventory(
    *,
    transfer_id: str,
    raw_instructions: Any,
    rva_start: int,
    rva_end: int,
) -> list[dict[str, Any]]:
    if not isinstance(raw_instructions, list) or not raw_instructions:
        raise StageAInputError(f"{transfer_id} machine-IR instructions must be nonempty")
    result: list[dict[str, Any]] = []
    cursor = rva_start
    for index, raw in enumerate(raw_instructions):
        if not isinstance(raw, Mapping):
            raise StageAInputError(
                f"{transfer_id} machine-IR instruction {index} must be an object"
            )
        start = _required_u32(
            raw.get("rva_start"), f"{transfer_id} instruction {index} start RVA"
        )
        end = _required_u32(
            raw.get("rva_end"), f"{transfer_id} instruction {index} end RVA"
        )
        size = raw.get("size")
        mnemonic = _required_string(
            raw.get("mnemonic"), f"{transfer_id} instruction {index} mnemonic"
        ).lower()
        operands = raw.get("operands")
        registers_read = raw.get("registers_read")
        registers_written = raw.get("registers_written")
        groups = raw.get("groups")
        if (
            start != cursor
            or end <= start
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size != end - start
            or not isinstance(operands, list)
            or not isinstance(registers_read, list)
            or not isinstance(registers_written, list)
            or not isinstance(groups, list)
            or any(not isinstance(item, str) for item in registers_read)
            or any(not isinstance(item, str) for item in registers_written)
            or any(not isinstance(item, str) for item in groups)
        ):
            raise StageAInputError(
                f"{transfer_id} machine-IR instruction {index} is malformed"
            )
        result.append({
            "rva": start,
            "rva_end": end,
            "size": size,
            "instruction_sha256": _required_sha256(
                raw.get("instruction_sha256"),
                f"{transfer_id} instruction {index} SHA-256",
            ),
            "mnemonic": mnemonic,
            "operands": operands,
            "registers_read": registers_read,
            "registers_written": registers_written,
            "groups": groups,
        })
        cursor = end
    if cursor != rva_end:
        raise StageAInputError(
            f"{transfer_id} machine-IR instructions do not cover the unit span"
        )
    return result


def _machine_ir_event_evidence(
    event: Mapping[str, Any], *, transfer_id: str, event_index: int
) -> tuple[str, str, Any]:
    kind = event.get("kind")
    registers = event.get("register_inputs")
    flags = event.get("flag_inputs")
    arguments = event.get("arguments", [])
    stack_inputs = event.get("stack_inputs")
    if (
        not isinstance(registers, Mapping)
        or set(registers) != set(_MACHINE_REGISTERS)
        or not isinstance(flags, Mapping)
        or set(flags) != set(_MACHINE_FLAGS)
        or not isinstance(arguments, list)
        or not isinstance(stack_inputs, list)
    ):
        raise StageAInputError(
            f"{transfer_id} external event {event_index} lacks complete machine ABI metadata"
        )
    for field, values in (("register", registers), ("flag", flags)):
        if any(not isinstance(value, Mapping) for value in values.values()):
            raise StageAInputError(
                f"{transfer_id} external event {event_index} has malformed {field} inputs"
            )
    if any(not isinstance(value, Mapping) for value in arguments):
        raise StageAInputError(
            f"{transfer_id} external event {event_index} has malformed arguments"
        )
    normalized_stack: list[dict[str, Any]] = []
    for stack_index, value in enumerate(stack_inputs):
        if not isinstance(value, Mapping):
            raise StageAInputError(
                f"{transfer_id} external event {event_index} stack input {stack_index} "
                "is malformed"
            )
        offset = _required_u32(
            value.get("offset"),
            f"{transfer_id} external event {event_index} stack offset",
        )
        width = value.get("width")
        if width not in {1, 2, 4} or not isinstance(value.get("value"), Mapping):
            raise StageAInputError(
                f"{transfer_id} external event {event_index} stack input {stack_index} "
                "has an unsupported width or value"
            )
        normalized_stack.append({
            "offset": offset, "width": width, "value": value.get("value")
        })
    target_expression = event.get("target") if kind == "indirect_call" else None
    if kind == "indirect_call" and not isinstance(target_expression, Mapping):
        raise StageAInputError(
            f"{transfer_id} indirect event {event_index} has no target expression"
        )
    identity = {
        "kind": kind,
        "dll": str(event.get("dll") or "").lower() or None,
        "symbol": event.get("symbol"),
        "ordinal": event.get("ordinal"),
    }
    abi = {
        "register_inputs": dict(registers),
        "flag_inputs": dict(flags),
        "arguments": arguments,
        "stack_inputs": normalized_stack,
        "abi_contract": (
            dict(event["abi_contract"])
            if isinstance(event.get("abi_contract"), Mapping)
            else None
        ),
    }
    return _canonical_sha256(identity), _canonical_sha256(abi), target_expression


def _machine_ir_callback_registration(
    event: Mapping[str, Any], *, transfer_id: str, event_index: int
) -> tuple[CallbackSource, int, CallbackABI] | None:
    raw_contract = event.get("abi_contract")
    if raw_contract is None:
        return None
    if not isinstance(raw_contract, Mapping):
        raise StageAInputError(
            f"{transfer_id} external event {event_index} has malformed ABI contract"
        )
    if raw_contract.get("world_effect") != "callbackRegistration":
        return None
    argument_words = _required_u32(
        raw_contract.get("argument_words"),
        f"{transfer_id} callback-registration argument count",
    )
    argument_base_offset = _required_u32(
        raw_contract.get("argument_base_offset"),
        f"{transfer_id} callback-registration argument base offset",
    )
    if (
        argument_words > 64
        or argument_base_offset % 4 != 0
        or argument_base_offset > 0x10000
    ):
        raise StageAInputError(
            f"{transfer_id} callback-registration argument inventory is invalid"
        )
    context = f"{transfer_id} external event {event_index}"
    source = parse_callback_source(
        raw_contract,
        argument_words=argument_words,
        context=context,
    )
    callback_abi = parse_callback_abi(raw_contract, context=context)
    return (
        source,
        source.stack_argument_offset(argument_base_offset),
        callback_abi,
    )


def _exact_u32_expression(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    width = value.get("width", 32)
    raw = value.get("value")
    if (
        width != 32
        or isinstance(raw, bool)
        or not isinstance(raw, int)
        or not 0 <= raw <= 0xFFFFFFFF
    ):
        return None
    return raw


def _static_iat_import_identity(
    target: Any,
    *,
    import_iat_vas: Mapping[tuple[str, str | int], int],
) -> tuple[str, str | None, int | None, int] | None:
    """Resolve an indirect target that is exactly one checked IAT-cell load."""

    if (
        not isinstance(target, Mapping)
        or target.get("op") != "load"
        or target.get("width") != 4
    ):
        return None
    iat_va = _exact_u32_expression(target.get("address"))
    if iat_va is None:
        return None
    matches = [
        (dll.lower(), identity)
        for (dll, identity), value in import_iat_vas.items()
        if _required_u32(value, "import IAT VA") == iat_va
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise StageAInputError(
            f"indirect target IAT cell {iat_va:#x} has ambiguous import identities"
        )
    dll, identity = matches[0]
    if isinstance(identity, str) and identity:
        return dll, identity, None, iat_va
    if isinstance(identity, int) and not isinstance(identity, bool) and identity >= 0:
        return dll, None, identity, iat_va
    raise StageAInputError("import IAT identity must be one symbol or ordinal")


def _stack_expression_at_offset(event: Mapping[str, Any], offset: int) -> Any:
    raw_inputs = event.get("stack_inputs")
    if not isinstance(raw_inputs, list):
        return None
    matches = [
        item.get("value")
        for item in raw_inputs
        if isinstance(item, Mapping)
        and item.get("offset") == offset
        and item.get("width") == 4
    ]
    return matches[0] if len(matches) == 1 else None


def _forward_expression_from_prior_writes(
    expression: Any,
    *,
    row: Mapping[str, Any],
    before_instruction_rva: int,
    budget: int = 8,
) -> Any:
    """Forward exact same-address writes within one ordered semantic transfer."""

    if budget <= 0 or not isinstance(expression, Mapping):
        return expression
    if expression.get("op") != "load" or expression.get("width") != 4:
        return expression
    address = expression.get("address")
    events = row.get("ordered_events")
    if not isinstance(events, list):
        return expression
    candidates = [
        event
        for event in events
        if isinstance(event, Mapping)
        and event.get("family") == "memory"
        and event.get("kind") == "write"
        and event.get("width") == 4
        and event.get("address") == address
        and isinstance(event.get("instruction_rva"), int)
        and event.get("instruction_rva") < before_instruction_rva
    ]
    if not candidates:
        return expression
    latest_rva = max(int(event["instruction_rva"]) for event in candidates)
    latest = [event for event in candidates if event.get("instruction_rva") == latest_rva]
    if len(latest) != 1:
        return expression
    return _forward_expression_from_prior_writes(
        latest[0].get("value"),
        row=row,
        before_instruction_rva=latest_rva,
        budget=budget - 1,
    )


def _direct_outcome_targets(row: Mapping[str, Any]) -> tuple[int, ...]:
    outcome = row.get("outcome")
    if not isinstance(outcome, Mapping):
        return ()
    kind = outcome.get("kind")
    if kind in {"fallthrough", "jump"}:
        target = outcome.get("target_rva")
        return (target,) if isinstance(target, int) and not isinstance(target, bool) else ()
    if kind == "branch":
        targets = (outcome.get("true_target_rva"), outcome.get("false_target_rva"))
        return tuple(
            target
            for target in targets
            if isinstance(target, int) and not isinstance(target, bool)
        )
    return ()


_IMPORT_ORIGIN_BOTTOM = object()
_IMPORT_ORIGIN_UNKNOWN = object()


@dataclass(frozen=True, order=True)
class _DiagnosticCallPreservation:
    transfer_rva: int
    instruction_rva: int
    target_rva: int
    register: str

    def payload(self) -> dict[str, Any]:
        return {
            "kind": "pe32-internal-call-abi-hypothesis-v1",
            "proof_authority": False,
            "transfer_rva": self.transfer_rva,
            "instruction_rva": self.instruction_rva,
            "target_rva": self.target_rva,
            "register": self.register,
            "assumption": "pe32-callee-preserved-register",
        }


@dataclass(frozen=True)
class _RegisterImportOrigin:
    dll: str
    symbol: str | None
    ordinal: int | None
    iat_va: int
    diagnostic_dependencies: frozenset[_DiagnosticCallPreservation] = frozenset()

    @property
    def identity(self) -> tuple[str, str | None, int | None, int]:
        return self.dll, self.symbol, self.ordinal, self.iat_va

    def with_dependency(
        self, dependency: _DiagnosticCallPreservation
    ) -> "_RegisterImportOrigin":
        return _RegisterImportOrigin(
            self.dll,
            self.symbol,
            self.ordinal,
            self.iat_va,
            self.diagnostic_dependencies | frozenset({dependency}),
        )


@dataclass(frozen=True)
class _RegisterImportSiteAnalysis:
    sites: Mapping[
        tuple[int, int], tuple[str, str | None, int | None, int]
    ]
    diagnostic_dependencies: Mapping[
        tuple[int, int], tuple[_DiagnosticCallPreservation, ...]
    ]


def _machine_ir_register_import_sites(
    rows: Iterable[Mapping[str, Any]],
    *,
    import_iat_vas: Mapping[tuple[str, str | int], int],
    internal_call_preserved_registers: Mapping[int, frozenset[str]],
    allow_diagnostic_abi_hypotheses: bool,
) -> _RegisterImportSiteAnalysis:
    """Propagate exact IAT origins through registers and checked direct CFG edges.

    The analysis is deliberately finite and conservative.  A join retains an
    origin only when every known incoming path agrees, and imported calls carry
    origins only in PE32 nonvolatile registers. Diagnostic mode may retain an
    origin across an unproved internal-call frame, but records that hypothesis
    and generates an exact live-target-versus-IAT guard. Strict mode never
    consumes such hypotheses.
    """

    row_by_rva: dict[int, Mapping[str, Any]] = {}
    predecessors: dict[int, set[int]] = {}
    successors: dict[int, set[int]] = {}
    for row_index, row in enumerate(rows):
        original = row.get("original")
        if not isinstance(original, Mapping):
            raise StageAInputError(f"machine-IR row {row_index} has no source span")
        source = _required_u32(
            original.get("rva_start"), f"machine-IR row {row_index} source RVA"
        )
        if source in row_by_rva:
            raise StageAInputError(f"duplicate machine-IR source RVA {source:#x}")
        row_by_rva[source] = row
        for target in _direct_outcome_targets(row):
            predecessors.setdefault(target, set()).add(source)
            successors.setdefault(source, set()).add(target)

    def join(values: Iterable[Any]) -> Any:
        concrete: list[Any] = []
        for value in values:
            if value is _IMPORT_ORIGIN_UNKNOWN:
                return _IMPORT_ORIGIN_UNKNOWN
            if value is not _IMPORT_ORIGIN_BOTTOM:
                concrete.append(value)
        if not concrete:
            return _IMPORT_ORIGIN_BOTTOM
        first = concrete[0]
        if not isinstance(first, _RegisterImportOrigin) or any(
            not isinstance(value, _RegisterImportOrigin)
            or value.identity != first.identity
            for value in concrete[1:]
        ):
            return _IMPORT_ORIGIN_UNKNOWN
        return _RegisterImportOrigin(
            *first.identity,
            frozenset(
                dependency
                for value in concrete
                for dependency in value.diagnostic_dependencies
            ),
        )

    def expression_origin(expression: Any, inputs: Mapping[str, Any]) -> Any:
        direct = _static_iat_import_identity(
            expression, import_iat_vas=import_iat_vas
        )
        if direct is not None:
            return _RegisterImportOrigin(*direct)
        if (
            isinstance(expression, Mapping)
            and expression.get("op") == "reg"
            and expression.get("width", 32) == 32
            and isinstance(expression.get("name"), str)
        ):
            return inputs.get(str(expression["name"]).lower(), _IMPORT_ORIGIN_UNKNOWN)
        return _IMPORT_ORIGIN_UNKNOWN

    def direct_event_origin(event: Mapping[str, Any]) -> Any:
        dll = event.get("dll")
        symbol = event.get("symbol")
        ordinal = event.get("ordinal")
        if not isinstance(dll, str) or not dll:
            return _IMPORT_ORIGIN_UNKNOWN
        if isinstance(symbol, str) and symbol and ordinal is None:
            identity: str | int = symbol
        elif (
            isinstance(ordinal, int)
            and not isinstance(ordinal, bool)
            and ordinal >= 0
            and symbol is None
        ):
            identity = ordinal
        else:
            return _IMPORT_ORIGIN_UNKNOWN
        iat_va = import_iat_vas.get((dll.lower(), identity))
        if iat_va is None:
            return _IMPORT_ORIGIN_UNKNOWN
        checked_iat = _required_u32(iat_va, "import IAT VA")
        return _RegisterImportOrigin(
            dll.lower(),
            identity if isinstance(identity, str) else None,
            identity if isinstance(identity, int) else None,
            checked_iat,
        )

    def transfer(
        row: Mapping[str, Any], inputs: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[int, Any]]:
        events = row.get("ordered_events")
        if not isinstance(events, list):
            return ({name: _IMPORT_ORIGIN_UNKNOWN for name in _MACHINE_REGISTERS}, {})
        call_origins: dict[int, Any] = {}
        call_preserved: dict[int, frozenset[str]] = {}
        call_diagnostic_preservation: dict[
            tuple[int, str], _DiagnosticCallPreservation
        ] = {}
        site_origins: dict[int, Any] = {}
        call_index = 0
        for raw_event in events:
            if not isinstance(raw_event, Mapping) or raw_event.get("family") != "external":
                continue
            kind = raw_event.get("kind")
            if kind == "internal_call":
                target_rva = raw_event.get("target_rva")
                instruction_rva = raw_event.get("instruction_rva")
                call_origins[call_index] = _IMPORT_ORIGIN_UNKNOWN
                call_preserved[call_index] = (
                    internal_call_preserved_registers.get(target_rva, frozenset())
                    if isinstance(target_rva, int) and not isinstance(target_rva, bool)
                    else frozenset()
                )
                if (
                    allow_diagnostic_abi_hypotheses
                    and isinstance(target_rva, int)
                    and not isinstance(target_rva, bool)
                    and isinstance(instruction_rva, int)
                    and not isinstance(instruction_rva, bool)
                ):
                    original = row.get("original")
                    if not isinstance(original, Mapping):
                        raise StageAInputError(
                            "machine-IR internal call has no source span"
                        )
                    source = _required_u32(
                        original.get("rva_start"),
                        "machine-IR internal-call source RVA",
                    )
                    for register in _PE32_CALLEE_PRESERVED_REGISTERS:
                        if register not in call_preserved[call_index]:
                            call_diagnostic_preservation[(call_index, register)] = (
                                _DiagnosticCallPreservation(
                                    source,
                                    instruction_rva,
                                    target_rva,
                                    register,
                                )
                            )
                call_index += 1
                continue
            if kind not in _CALL_KINDS:
                continue
            if kind == "external_call":
                origin = direct_event_origin(raw_event)
            else:
                origin = expression_origin(raw_event.get("target"), inputs)
            call_origins[call_index] = origin
            call_preserved[call_index] = (
                _PE32_CALLEE_PRESERVED_REGISTERS
                if origin not in {_IMPORT_ORIGIN_BOTTOM, _IMPORT_ORIGIN_UNKNOWN}
                else frozenset()
            )
            instruction_rva = raw_event.get("instruction_rva")
            if isinstance(instruction_rva, int) and not isinstance(instruction_rva, bool):
                site_origins[instruction_rva] = origin
            call_index += 1

        outputs = dict(inputs)
        raw_writes = row.get("register_writes")
        if not isinstance(raw_writes, list):
            return ({name: _IMPORT_ORIGIN_UNKNOWN for name in _MACHINE_REGISTERS}, site_origins)
        for raw_write in raw_writes:
            if not isinstance(raw_write, Mapping):
                continue
            register = raw_write.get("register")
            value = raw_write.get("value")
            if not isinstance(register, str) or register.lower() not in _MACHINE_REGISTERS:
                continue
            register = register.lower()
            if (
                isinstance(value, Mapping)
                and value.get("op") == "call_response"
                and value.get("register") == register
                and isinstance(value.get("call_index"), int)
                and register in call_preserved.get(value["call_index"], frozenset())
            ):
                outputs[register] = inputs.get(register, _IMPORT_ORIGIN_UNKNOWN)
            elif (
                isinstance(value, Mapping)
                and value.get("op") == "call_response"
                and value.get("register") == register
                and isinstance(value.get("call_index"), int)
                and (
                    dependency := call_diagnostic_preservation.get(
                        (value["call_index"], register)
                    )
                )
                is not None
                and isinstance(
                    prior := inputs.get(register), _RegisterImportOrigin
                )
            ):
                outputs[register] = prior.with_dependency(dependency)
            else:
                outputs[register] = expression_origin(value, inputs)
        return outputs, site_origins

    outputs = {
        rva: {name: _IMPORT_ORIGIN_BOTTOM for name in _MACHINE_REGISTERS}
        for rva in row_by_rva
    }
    worklist = deque(sorted(row_by_rva))
    queued = set(row_by_rva)
    steps = 0
    maximum_steps = max(
        1,
        (len(row_by_rva) + sum(len(value) for value in successors.values()))
        * (len(_MACHINE_REGISTERS) + 2),
    )
    while worklist:
        rva = worklist.popleft()
        queued.remove(rva)
        incoming = predecessors.get(rva, set())
        if not incoming:
            inputs = {name: _IMPORT_ORIGIN_UNKNOWN for name in _MACHINE_REGISTERS}
        else:
            inputs = {
                name: join(
                    outputs[source][name]
                    for source in incoming
                    if source in outputs
                )
                for name in _MACHINE_REGISTERS
            }
        updated, _ = transfer(row_by_rva[rva], inputs)
        steps += 1
        if steps > maximum_steps:
            raise StageAInputError("register import-origin analysis did not converge")
        if updated == outputs[rva]:
            continue
        outputs[rva] = updated
        for target in sorted(successors.get(rva, set())):
            if target in row_by_rva and target not in queued:
                queued.add(target)
                worklist.append(target)

    result: dict[tuple[int, int], tuple[str, str | None, int | None, int]] = {}
    diagnostic_dependencies: dict[
        tuple[int, int], tuple[_DiagnosticCallPreservation, ...]
    ] = {}
    for rva, row in row_by_rva.items():
        incoming = predecessors.get(rva, set())
        if not incoming:
            inputs = {name: _IMPORT_ORIGIN_UNKNOWN for name in _MACHINE_REGISTERS}
        else:
            inputs = {
                name: join(
                    outputs[source][name]
                    for source in incoming
                    if source in outputs
                )
                for name in _MACHINE_REGISTERS
            }
        _, sites = transfer(row, inputs)
        for instruction_rva, origin in sites.items():
            if isinstance(origin, _RegisterImportOrigin):
                key = (rva, instruction_rva)
                result[key] = origin.identity
                if origin.diagnostic_dependencies:
                    diagnostic_dependencies[key] = tuple(
                        sorted(origin.diagnostic_dependencies)
                    )
    return _RegisterImportSiteAnalysis(result, diagnostic_dependencies)


def _machine_ir_manifest_payload(
    *, machine_ir: Path, manifest: Path | None
) -> Mapping[str, Any] | None:
    if manifest is None:
        return None
    try:
        payload = json.loads(Path(manifest).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read machine-IR manifest: {exc}") from exc
    if not isinstance(payload, Mapping) or payload.get("format") != _MACHINE_IR_FORMAT:
        raise StageAInputError("machine-IR manifest has an unsupported format")
    artifact = payload.get("artifacts")
    artifact = artifact.get("machine_ir") if isinstance(artifact, Mapping) else None
    if (
        not isinstance(artifact, Mapping)
        or artifact.get("format") != _MACHINE_IR_FORMAT
        or artifact.get("sha256") != sha256_file(machine_ir)
    ):
        raise StageAInputError(
            "machine-IR manifest does not bind the exact machine-ir.jsonl artifact"
        )
    return payload


def _checked_contract_callback_registration(
    contract: CheckedExternalSiteContract,
    *,
    context: str,
) -> tuple[CallbackSource, int, CallbackABI] | None:
    adapter = contract.callback_adapter
    if contract.callback_effect != "explicit":
        return None
    if adapter is None:
        raise StageAInputError(f"{context} has no checked callback adapter")
    source = parse_callback_source(
        {"callback_source": adapter.source},
        argument_words=contract.argument_words,
        context=context,
    )
    abi = parse_callback_abi(
        {"callback_abi": adapter.abi},
        context=context,
    )
    return (
        source,
        source.stack_argument_offset(contract.argument_base_offset),
        abi,
    )


def _portable_component_selections(
    values: Iterable[Mapping[str, Any]],
    *,
    transfer_by_id: Mapping[str, tuple[int, str]],
) -> dict[str, dict[str, Any]]:
    """Normalize explicit portable dispatch selections.

    The linked runtime independently checks these identifiers against the
    strong region-override lookup. A portable component may not fall back to
    machine IR, because that would give the unit two selected implementation
    classes at execution time.
    """

    expected_fields = {
        "unit_id",
        "rva",
        "replacement_id",
        "cluster_id",
        "component_manifest_sha256",
        "fallback_on_unimplemented",
    }
    expected_fields_v2 = expected_fields | {"dispatch_role", "entry_rva"}
    result: dict[str, dict[str, Any]] = {}
    seen_rvas: set[int] = set()
    for index, raw in enumerate(values):
        v2 = isinstance(raw, Mapping) and set(raw) == expected_fields_v2
        if not isinstance(raw, Mapping) or (not v2 and set(raw) != expected_fields):
            raise StageAInputError(
                f"portable component selection {index} fields are not canonical"
            )
        unit_id = _required_string(
            raw.get("unit_id"), f"portable component selection {index} unit id"
        )
        rva = _required_u32(
            raw.get("rva"), f"portable component selection {index} RVA"
        )
        binding = transfer_by_id.get(unit_id)
        if binding is None or binding[0] != rva:
            raise StageAInputError(
                "portable component selection does not bind one exact machine-IR unit"
            )
        if unit_id in result or rva in seen_rvas:
            raise StageAInputError("duplicate portable component dispatch selection")
        if raw.get("fallback_on_unimplemented") is not False:
            raise StageAInputError(
                "selected portable components must disable machine-IR fallback"
            )
        result[unit_id] = {
            "rva": rva,
            "replacement_id": _required_portable_identity(
                raw.get("replacement_id"),
                f"portable component selection {index} replacement id",
            ),
            "cluster_id": _required_portable_identity(
                raw.get("cluster_id"),
                f"portable component selection {index} cluster id",
            ),
            "component_manifest_sha256": _required_sha256(
                raw.get("component_manifest_sha256"),
                f"portable component selection {index} manifest SHA-256",
            ),
            "dispatch_role": (
                _required_string(
                    raw.get("dispatch_role"),
                    f"portable component selection {index} dispatch role",
                )
                if v2
                else "entry"
            ),
            "entry_rva": (
                _required_u32(
                    raw.get("entry_rva"),
                    f"portable component selection {index} entry RVA",
                )
                if v2
                else rva
            ),
        }
        if result[unit_id]["dispatch_role"] not in {"entry", "subsumed_member"}:
            raise StageAInputError("portable component dispatch role is unsupported")
        if result[unit_id]["dispatch_role"] == "entry" and result[unit_id]["entry_rva"] != rva:
            raise StageAInputError("portable component entry must dispatch at its own RVA")
        seen_rvas.add(rva)
    entry_keys = {
        (value["entry_rva"], value["cluster_id"], value["component_manifest_sha256"])
        for value in result.values()
        if value["dispatch_role"] == "entry"
    }
    if any(
        value["dispatch_role"] == "subsumed_member"
        and (value["entry_rva"], value["cluster_id"], value["component_manifest_sha256"])
        not in entry_keys
        for value in result.values()
    ):
        raise StageAInputError("portable component member has no selected boundary entry")
    return result
