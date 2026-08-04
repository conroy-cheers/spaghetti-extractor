"""Generate a stable semantic-IR interpreter and immutable program data.

The generated C is candidate source, not proof evidence.  Stage A must bind the
program records to exact decoded original transfers and prove the compiled
interpreter kernel before a candidate can contribute to final acceptance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from .artifact_formats import INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT
from .relational.definedness import analyze_definedness_jsonl
from .stage_b_c_backend import _runtime_header, _runtime_helpers
from .stage_b_typed_x87 import (
    TYPED_NATIVE_X87_OPERATION_FORMAT,
    TYPED_NATIVE_X87_PROGRAM_FORMAT,
    TypedX87Operation,
    X87_CHECKED_DECODER,
    X87_CHECKED_EXECUTOR,
    extract_typed_x87_operation,
    typed_x87_operation_from_micro_op,
)
from .stage_binary import StageAInputError
from .util import sha256_bytes, sha256_file, write_json


STAGE_B_INTERPRETER_PROGRAM_FORMAT = "stage-b-semantic-interpreter-program-v1"
STAGE_B_INTERPRETER_PACKAGE_FORMAT = "stage-b-semantic-interpreter-package-v1"
STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT = (
    "stage-b-interpreter-definedness-use-v2"
)
_MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"

_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_REGISTER_INDEX = {name: index for index, name in enumerate(_REGISTERS)}
_FLAG_INDEX = {name: index for index, name in enumerate(_FLAGS)}
_AF_FLAG_INDEX = len(_FLAGS)
_REP_SCAS_OWNED_REGISTERS = ("edi", "ecx")
_REP_SCAS_OWNED_FLAGS = ("cf", "pf", "af", "zf", "sf", "of")
_X87_REPLAY_MODEL = "native_exact_x87_command_replay_obligation_v1"
_X87_REPLAY_FORMAT = "stage-a-native-exact-x87-command-replay-obligation-v1"
_X87_REPLAY_PROGRAM_FORMAT = "stage-b-native-exact-x87-command-replay-program-v1"
_X87_TYPED_PROGRAM_FORMAT = TYPED_NATIVE_X87_PROGRAM_FORMAT
_X87_CHECKED_DECODER = X87_CHECKED_DECODER
_X87_CHECKED_EXECUTOR = X87_CHECKED_EXECUTOR
_INSTRUCTION_EFFECT_SCHEDULE_FORMAT = (
    INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT
)
_ORDINARY_CHECKED_DECODER = "StageA.Formal.decodeInstructionExact"
_ORDINARY_CHECKED_EXECUTOR = "StageA.Formal.executeInstruction"
_X87_PHYSICAL_FIELDS = (
    "stack", "tags", "control", "status", "pending_exception", "last_opcode",
    "instruction_pointer", "code_selector", "data_pointer", "data_selector",
)
_RAW_INSTRUCTION_FIELDS = frozenset({
    "bytes",
    "instruction_bytes",
    "opcode_bytes",
    "raw_bytes",
    "encoded_instruction",
})


class StageBInterpreterError(StageAInputError):
    """The semantic program cannot be lowered into the qualified interpreter."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "unsupported_transfer",
        next_action: str = (
            "repair the Stage A transfer or add generic checked interpreter lowering"
        ),
    ) -> None:
        super().__init__(message)
        self.code = code
        self.next_action = next_action


@dataclass(frozen=True)
class _Node:
    op: str
    args: tuple[int, ...] = ()
    aux: int = 0
    immediate: int = 0


@dataclass(frozen=True)
class _Action:
    op: str
    args: tuple[int, ...] = ()
    aux: int = 0


@dataclass(frozen=True)
class _Call:
    kind: str
    instruction_rva: int
    call_index: int
    target_node: int | None
    target_rva: int
    return_rva: int
    dll: str | None
    symbol: str | None
    ordinal: int | None
    register_nodes: tuple[int, ...]
    flag_nodes: tuple[int, ...]
    argument_nodes: tuple[int, ...]
    stack_inputs: tuple[tuple[int, int, int], ...]


@dataclass(frozen=True)
class _TypedX87Program:
    contract_sha256: str
    image_base: int
    rva_start: int
    rva_end: int
    operation: TypedX87Operation
    checked_decoder: str
    checked_executor: str


@dataclass(frozen=True)
class _Transfer:
    identity: str
    contract_sha256: str
    instruction_bytes_sha256: str
    rva_start: int
    nodes: tuple[_Node, ...]
    x87_nodes: tuple[_Node, ...]
    actions: tuple[_Action, ...]
    calls: tuple[_Call, ...]
    x87_operations: tuple[_TypedX87Program, ...]

    @property
    def x87_replays(self) -> tuple[_TypedX87Program, ...]:
        """Compatibility alias for proof consumers migrating to typed operations."""

        return self.x87_operations


@dataclass
class _TransferCompiler:
    row: Mapping[str, Any]
    nodes: list[_Node] = field(default_factory=list)
    x87_nodes: list[_Node] = field(default_factory=list)
    actions: list[_Action] = field(default_factory=list)
    calls: list[_Call] = field(default_factory=list)
    x87_operations: list[_TypedX87Program] = field(default_factory=list)
    memo: dict[str, int] = field(default_factory=dict)
    memo_memory_dependencies: dict[str, frozenset[str]] = field(default_factory=dict)
    x87_memo: dict[str, int] = field(default_factory=dict)
    x87_memo_memory_dependencies: dict[str, frozenset[str]] = field(
        default_factory=dict
    )
    available_calls: set[int] = field(default_factory=set)
    instruction_local: bool = False
    scheduled_outcome: _Action | None = None

    def compile(self) -> _Transfer:
        machine_ir_x87 = self.row.get("_machine_ir_x87_micro_ops")
        fpu_state = self.row.get("fpu_state")
        fpu = (
            _object(fpu_state, f"{self.identity} fpu_state")
            if fpu_state is not None
            else None
        )
        native_x87_replay = fpu is not None and fpu.get("model") == _X87_REPLAY_MODEL
        scheduled_x87_replay = False
        if machine_ir_x87 is not None:
            typed_micro_ops = _list(
                machine_ir_x87, f"{self.identity} x87 micro-ops"
            )
            self._compile_machine_ir_transfer(typed_micro_ops)
            scheduled_x87_replay = self.scheduled_outcome is not None
            native_x87_replay = bool(typed_micro_ops)
        elif native_x87_replay:
            scheduled_x87_replay = self._compile_x87_replay(fpu)
        elif fpu is not None:
            raise StageBInterpreterError(
                f"{self.identity}: x87 transitions require an exact checked replay schedule",
                code="x87_checked_replay_required",
                next_action=(
                    "regenerate the transfer with exact singleton x87 replay bindings "
                    "and an instruction-ordered effect schedule"
                ),
            )
        else:
            self._compile_symbolic_transfer()

        outcome = _object(self.row.get("outcome"), f"{self.identity} outcome")
        if native_x87_replay and not scheduled_x87_replay:
            self._check_x87_replay_outcome(outcome)
        outcome_action = self.scheduled_outcome or self._outcome(outcome)
        self.actions.append(outcome_action)
        return _Transfer(
            identity=self.identity,
            contract_sha256=_sha256(self.row.get("contract_sha256"), "contract_sha256"),
            instruction_bytes_sha256=_sha256(
                self.row.get("instruction_bytes_sha256"), "instruction_bytes_sha256"
            ),
            rva_start=_u32(
                _object(self.row.get("original"), "original span").get("rva_start"),
                "original.rva_start",
            ),
            nodes=tuple(self.nodes),
            x87_nodes=tuple(self.x87_nodes),
            actions=tuple(self.actions),
            calls=tuple(self.calls),
            x87_operations=tuple(self.x87_operations),
        )

    def _compile_machine_ir_transfer(self, micro_ops: list[Any]) -> None:
        schedule = self.row.get("instruction_effect_schedule")
        original = _object(self.row.get("original"), f"{self.identity} source span")
        original_start = _u32(original.get("rva_start"), "machine-IR start RVA")
        original_end = _u32(original.get("rva_end"), "machine-IR end RVA")
        if schedule is None:
            if not micro_ops:
                self._compile_symbolic_transfer()
                return
            cursor = original_start
            for raw in micro_ops:
                micro = _object(raw, f"{self.identity} x87 micro-op")
                start = _u32(micro.get("rva_start"), "typed x87 start RVA")
                end = _u32(micro.get("rva_end"), "typed x87 end RVA")
                if start != cursor or end <= start:
                    raise StageBInterpreterError(
                        f"{self.identity}: typed x87 micro-ops do not cover the unit",
                        code="malformed_machine_ir_x87_schedule",
                    )
                self._append_machine_ir_x87_operation(micro)
                cursor = end
            if cursor != original_end:
                raise StageBInterpreterError(
                    f"{self.identity}: typed x87 micro-ops do not cover the unit",
                    code="malformed_machine_ir_x87_schedule",
                )
            return
        schedule_object = _object(
            schedule, f"{self.identity} machine-IR instruction schedule"
        )
        if (
            schedule_object.get("format") != _INSTRUCTION_EFFECT_SCHEDULE_FORMAT
            or schedule_object.get("status") != "complete"
            or schedule_object.get("proof_authority") is not False
            or schedule_object.get("blockers") != []
            or schedule_object.get("ordering") != "strict_contiguous_rva_order"
            or schedule_object.get("rva_start", original_start) != original_start
            or schedule_object.get("rva_end", original_end) != original_end
        ):
            raise StageBInterpreterError(
                f"{self.identity}: machine-IR instruction schedule is incomplete",
                code="malformed_machine_ir_x87_schedule",
            )
        records = _list(
            schedule_object.get("records"),
            f"{self.identity} machine-IR schedule records",
        )
        counts = _object(
            schedule_object.get("counts"),
            f"{self.identity} machine-IR schedule counts",
        )
        if counts.get("instructions") != len(records) or counts.get("blockers") != 0:
            raise StageBInterpreterError(
                f"{self.identity}: machine-IR schedule counts are inconsistent",
                code="malformed_machine_ir_x87_schedule",
            )
        micro_by_rva: dict[int, Mapping[str, Any]] = {}
        for raw in micro_ops:
            micro = _object(raw, f"{self.identity} x87 micro-op")
            rva = _u32(micro.get("rva_start"), "x87 micro-op RVA")
            if rva in micro_by_rva:
                raise StageBInterpreterError(
                    f"{self.identity}: duplicate x87 micro-op RVA 0x{rva:x}",
                    code="malformed_machine_ir_x87_schedule",
                )
            micro_by_rva[rva] = micro
        used: set[int] = set()
        cursor = original_start
        x87_count = 0
        ordinary_count = 0
        for index, raw_record in enumerate(records):
            record = _object(raw_record, f"{self.identity} schedule record {index}")
            rva = _u32(record.get("rva_start"), "machine-IR schedule RVA")
            rva_end = _u32(record.get("rva_end"), "machine-IR schedule end RVA")
            if rva != cursor or rva_end <= rva:
                raise StageBInterpreterError(
                    f"{self.identity}: machine-IR schedule is not contiguous",
                    code="malformed_machine_ir_x87_schedule",
                )
            cursor = rva_end
            instruction_class = record.get("instruction_class")
            classification = _object(
                record.get("classification"),
                f"{self.identity} schedule classification {index}",
            )
            if (
                classification.get("status")
                != "proposal_requires_lean_exact_byte_replay"
                or classification.get("proof_authority") is not False
            ):
                raise StageBInterpreterError(
                    f"{self.identity}: machine-IR schedule classification is invalid",
                    code="malformed_machine_ir_x87_schedule",
                )
            effects = _object(
                record.get("effects") or {}, f"machine-IR schedule effects {index}"
            )
            control = effects.get("control")
            if control is None:
                control = (
                    {"kind": "fallthrough", "target_rva": records[index + 1].get("rva_start")}
                    if index + 1 < len(records) and isinstance(records[index + 1], Mapping)
                    else self.row.get("outcome")
                )
            control_object = _object(control, f"machine-IR schedule control {index}")
            if index + 1 < len(records):
                next_record = _object(records[index + 1], "next machine-IR schedule record")
                if (
                    control_object.get("kind") != "fallthrough"
                    or control_object.get("target_rva") != next_record.get("rva_start")
                ):
                    raise StageBInterpreterError(
                        f"{self.identity}: machine-IR schedule is not contiguous",
                        code="malformed_machine_ir_x87_schedule",
                    )
            else:
                self._validate_scheduled_outcome(control_object)
            if instruction_class == "x87_singleton_checked_replay":
                micro = micro_by_rva.get(rva)
                if micro is None:
                    raise StageBInterpreterError(
                        f"{self.identity}: x87 schedule record has no typed micro-op",
                        code="malformed_machine_ir_x87_schedule",
                    )
                if (
                    micro.get("rva_end") != rva_end
                    or classification.get("checked_decoder") != _X87_CHECKED_DECODER
                    or classification.get("checked_executor") != _X87_CHECKED_EXECUTOR
                ):
                    raise StageBInterpreterError(
                        f"{self.identity}: typed x87 schedule binding is invalid",
                        code="malformed_machine_ir_x87_schedule",
                    )
                self._append_machine_ir_x87_operation(micro)
                used.add(rva)
                x87_count += 1
            elif instruction_class == "ordinary_symbolic_instruction":
                if (
                    classification.get("checked_decoder")
                    != _ORDINARY_CHECKED_DECODER
                    or classification.get("checked_executor")
                    != _ORDINARY_CHECKED_EXECUTOR
                ):
                    raise StageBInterpreterError(
                        f"{self.identity}: ordinary schedule binding is invalid",
                        code="malformed_machine_ir_x87_schedule",
                    )
                self._reset_instruction_expression_cache()
                self.instruction_local = True
                try:
                    self._compile_instruction_effects(effects)
                    if index + 1 == len(records):
                        self.scheduled_outcome = self._outcome(control_object)
                finally:
                    self.instruction_local = False
                ordinary_count += 1
            else:
                raise StageBInterpreterError(
                    f"{self.identity}: unsupported machine-IR instruction class",
                    code="malformed_machine_ir_x87_schedule",
                )
            if index + 1 == len(records) and self.scheduled_outcome is None:
                # Checked x87 replay updates the current machine state. A
                # terminal control expression following it must therefore use
                # the same instruction-local state view as an ordinary final
                # instruction.
                self.instruction_local = True
                try:
                    self.scheduled_outcome = self._outcome(control_object)
                finally:
                    self.instruction_local = False
        if used != set(micro_by_rva):
            raise StageBInterpreterError(
                f"{self.identity}: machine-IR x87 micro-op coverage differs from schedule",
                code="malformed_machine_ir_x87_schedule",
            )
        if (
            cursor != original_end
            or counts.get("x87_singletons") != x87_count
            or counts.get("ordinary_instructions") != ordinary_count
        ):
            raise StageBInterpreterError(
                f"{self.identity}: machine-IR schedule coverage is inconsistent",
                code="malformed_machine_ir_x87_schedule",
            )

    def _append_machine_ir_x87_operation(self, micro: Mapping[str, Any]) -> None:
        fpu = _object(self.row.get("fpu_state"), f"{self.identity} fpu_state")
        typed_replay = _object(
            fpu.get("typed_replay"), f"{self.identity} typed x87 metadata"
        )
        if (
            micro.get("unit_id") != self.identity
            or micro.get("transfer_instruction_sha256")
            != self.row.get("instruction_bytes_sha256")
            or micro.get("checked_decoder") != _X87_CHECKED_DECODER
            or micro.get("checked_executor") != _X87_CHECKED_EXECUTOR
            or micro.get("physical_state_effect")
            != "defined_by_checked_typed_x87_executor"
        ):
            raise StageBInterpreterError(
                f"{self.identity}: typed x87 micro-op is not bound to its unit or checker",
                code="malformed_typed_x87_operation",
            )
        _sha256(micro.get("instruction_sha256"), "typed x87 instruction SHA-256")
        image_base = _u32(typed_replay.get("image_base"), "typed x87 image base")
        try:
            operation = typed_x87_operation_from_micro_op(micro, image_base=image_base)
        except StageAInputError as exc:
            raise StageBInterpreterError(
                f"{self.identity}: malformed typed x87 micro-op: {exc}",
                code="unsupported_typed_x87_operation",
            ) from exc
        start = _u32(micro.get("rva_start"), "typed x87 start RVA")
        end = _u32(micro.get("rva_end"), "typed x87 end RVA")
        original = _object(self.row.get("original"), f"{self.identity} source span")
        original_start = _u32(original.get("rva_start"), "machine-IR start RVA")
        original_end = _u32(original.get("rva_end"), "machine-IR end RVA")
        if (
            end <= start
            or operation.source_size != end - start
            or start < original_start
            or end > original_end
        ):
            raise StageBInterpreterError(
                f"{self.identity}: typed x87 micro-op span is invalid for its unit",
                code="malformed_typed_x87_operation",
            )
        index = len(self.x87_operations)
        self.x87_operations.append(
            _TypedX87Program(
                contract_sha256=_sha256(
                    self.row.get("contract_sha256"), "contract_sha256"
                ),
                image_base=image_base,
                rva_start=start,
                rva_end=end,
                operation=operation,
                checked_decoder=_string(
                    micro.get("checked_decoder"), "typed x87 checked decoder"
                ),
                checked_executor=_string(
                    micro.get("checked_executor"), "typed x87 checked executor"
                ),
            )
        )
        self.actions.append(_Action("typed_x87", (index,)))
        self._reset_instruction_expression_cache()

    def _compile_symbolic_transfer(self) -> None:
        ordered = self.row.get("ordered_events")
        if not isinstance(ordered, list):
            raise StageBInterpreterError(f"{self.identity}: ordered_events must be a list")
        owned_register_outputs, owned_flag_outputs = self._rep_scas_owned_outputs(
            ordered
        )
        external_index = 0
        for raw in ordered:
            event = _object(raw, f"{self.identity} ordered event")
            family = event.get("family")
            if family == "memory":
                self._memory_event(event)
            elif family == "fault":
                self._fault_event(event)
            elif family == "external":
                self._external_event(
                    self._instruction_call_boundary(event, external_index),
                    external_index,
                )
                external_index += 1
            else:
                raise StageBInterpreterError(
                    f"{self.identity}: unsupported ordered-event family {family!r}"
                )

        updates: list[_Action] = []
        for raw in _list(self.row.get("register_writes"), "register_writes"):
            write = _object(raw, f"{self.identity} register write")
            name = _string(write.get("register"), "register write name")
            if name in owned_register_outputs:
                continue
            if name not in _REGISTER_INDEX:
                raise StageBInterpreterError(f"{self.identity}: unsupported register {name!r}")
            updates.append(
                _Action("set_reg", (self.word(write.get("value")),), _REGISTER_INDEX[name])
            )
        for raw in _list(self.row.get("flag_writes"), "flag_writes"):
            write = _object(raw, f"{self.identity} flag write")
            name = _string(write.get("flag"), "flag write name")
            if name in owned_flag_outputs:
                continue
            if name not in _FLAG_INDEX:
                raise StageBInterpreterError(f"{self.identity}: unsupported flag {name!r}")
            updates.append(
                _Action("set_flag", (self.word(write.get("value")),), _FLAG_INDEX[name])
            )

        self.actions.extend(updates)
        self.actions.append(_Action("sync_eflags"))

    def _instruction_call_boundary(
        self, event: Mapping[str, Any], event_index: int
    ) -> Mapping[str, Any]:
        """Bind an exact call instruction to its transfer-level ABI inventory."""

        if event.get("kind") not in {
            "external_call",
            "internal_call",
            "indirect_call",
        }:
            return event
        aggregate_events = _optional_list(self.row.get("external_events"))
        if event_index >= len(aggregate_events):
            return event
        aggregate = _object(
            aggregate_events[event_index],
            f"{self.identity} aggregate external event {event_index}",
        )
        identity_fields = (
            "kind",
            "dll",
            "symbol",
            "ordinal",
            "target_rva",
            "return_rva",
        )
        if any(
            event.get(field) != aggregate.get(field)
            for field in identity_fields
        ):
            raise StageBInterpreterError(
                f"{self.identity}: instruction and aggregate call identities differ",
                code="instruction_call_boundary_mismatch",
            )
        merged = dict(event)
        for field in ("arguments", "stack_inputs"):
            local = _optional_list(event.get(field))
            boundary = _optional_list(aggregate.get(field))
            # Instruction-local inventories already describe the exact call
            # state.  The aggregate inventory is a required fallback for
            # values prepared by preceding instructions in the same unit.
            selected = local or boundary
            if field == "stack_inputs" and not local:
                selected = [
                    self._instruction_local_stack_input(raw)
                    for raw in selected
                ]
            merged[field] = selected
        return merged

    def _instruction_local_stack_input(self, raw: Any) -> Mapping[str, Any]:
        """Sample an aggregate ABI slot from current ESP at the call."""

        item = _object(raw, f"{self.identity} aggregate stack input")
        offset = _nonnegative(item.get("offset"), "stack input offset")
        width = _width(item.get("width"))
        return {
            "offset": offset,
            "width": width,
            "value": {
                "op": "load",
                "width": width,
                "address": {
                    "op": "add32",
                    "args": [
                        {"op": "reg", "name": "esp", "width": 32},
                        {"op": "const", "value": offset, "width": 32},
                    ],
                },
            },
        }

    @property
    def identity(self) -> str:
        return _string(self.row.get("id"), "transfer id")

    def _compile_x87_replay(self, fpu: Mapping[str, Any]) -> bool:
        malformed_action = (
            "regenerate the exact x87 replay obligation from contract_tools"
        )

        def reject(message: str, *, code: str = "malformed_x87_replay") -> None:
            raise StageBInterpreterError(
                f"{self.identity}: {message}",
                code=code,
                next_action=malformed_action,
            )

        if fpu.get("status") != "required":
            reject("x87 replay obligation status must be 'required'")
        if fpu.get("authoritative_state_type") != "StageA.X87.PhysicalState":
            reject("x87 replay obligation has an unsupported authoritative state type")
        if fpu.get("required_fields") != list(_X87_PHYSICAL_FIELDS):
            reject("x87 replay obligation required_fields changed")
        missing = fpu.get("missing_or_invalid_fields")
        if (
            not isinstance(missing, list)
            or not missing
            or len(set(item for item in missing if isinstance(item, str))) != len(missing)
            or any(item not in _X87_PHYSICAL_FIELDS for item in missing)
        ):
            reject("x87 replay obligation missing_or_invalid_fields is malformed")
        present_physical = sorted(
            field for field in _X87_PHYSICAL_FIELDS
            if field != "status" and field in fpu
        )
        if present_physical:
            reject(
                "x87 replay obligation carries unqualified physical fields: "
                + ", ".join(present_physical)
            )

        replay = _object(fpu.get("replay"), f"{self.identity} x87 replay")
        declarations = (
            ("format", _X87_REPLAY_FORMAT),
            ("checked_decoder", _X87_CHECKED_DECODER),
            ("checked_executor", _X87_CHECKED_EXECUTOR),
            ("architecture", "x86"),
        )
        for field_name, expected in declarations:
            if replay.get(field_name) != expected:
                reject(f"x87 replay {field_name} must be {expected!r}")
        if replay.get("bitness") != 32:
            reject("x87 replay only supports checked PE32 singleton commands")

        original = _object(self.row.get("original"), "original span")
        rva_start = _u32(original.get("rva_start"), "original.rva_start")
        rva_end = _u32(original.get("rva_end"), "original.rva_end")
        if rva_end <= rva_start:
            reject("x87 replay original span must be non-empty")
        if original.get("size") is not None and original.get("size") != rva_end - rva_start:
            reject("x87 replay original span size does not match its RVAs")
        if replay.get("rva_start") != rva_start or replay.get("rva_end") != rva_end:
            reject("x87 replay RVAs do not match the original transfer span")

        encoded = _hex_bytes(replay.get("bytes"), "x87 replay bytes")
        if len(encoded) != rva_end - rva_start:
            reject("x87 replay bytes do not cover the exact transfer span")
        replay_digest = _sha256(replay.get("bytes_sha256"), "x87 replay bytes_sha256")
        if sha256_bytes(encoded) != replay_digest:
            reject("x87 replay bytes_sha256 does not match its exact bytes")
        transfer_digest = _sha256(
            self.row.get("instruction_bytes_sha256"), "instruction_bytes_sha256"
        )
        if replay_digest != transfer_digest:
            reject("x87 replay digest does not match the transfer instruction digest")

        replay_instructions = replay.get("instructions")
        outer_instructions = self.row.get("instructions")
        if not isinstance(replay_instructions, list) or not replay_instructions:
            reject("x87 replay instructions must be a non-empty list")
        if (
            not isinstance(outer_instructions, list)
            or len(outer_instructions) != len(replay_instructions)
        ):
            reject("outer and replay instruction inventories do not match")

        instruction_records: list[tuple[int, int, bytes, Mapping[str, Any]]] = []
        expected_rva = rva_start
        reconstructed = bytearray()
        for index, (replay_raw, outer_raw) in enumerate(
            zip(replay_instructions, outer_instructions, strict=True)
        ):
            replay_instruction = _object(
                replay_raw, f"{self.identity} x87 replay instruction {index}"
            )
            outer_instruction = _object(
                outer_raw, f"{self.identity} outer instruction {index}"
            )
            instruction_rva = _u32(
                replay_instruction.get("rva"), f"x87 replay instruction {index} rva"
            )
            instruction_size = _nonnegative(
                replay_instruction.get("size"), f"x87 replay instruction {index} size"
            )
            instruction_bytes = _hex_bytes(
                replay_instruction.get("bytes"), f"x87 replay instruction {index} bytes"
            )
            if instruction_size == 0 or instruction_size != len(instruction_bytes):
                reject(f"x87 replay instruction {index} has an invalid exact size")
            if instruction_rva != expected_rva:
                reject("x87 replay instruction sequence is not contiguous and ordered")
            expected_instruction = {
                "rva": instruction_rva,
                "size": instruction_size,
                "bytes": instruction_bytes.hex(),
            }
            if any(
                outer_instruction.get(key) != value
                for key, value in expected_instruction.items()
            ):
                reject(f"outer instruction {index} does not match its replay binding")
            instruction_records.append(
                (
                    instruction_rva,
                    instruction_rva + instruction_size,
                    instruction_bytes,
                    outer_instruction,
                )
            )
            reconstructed.extend(instruction_bytes)
            expected_rva += instruction_size
        if expected_rva != rva_end or bytes(reconstructed) != encoded:
            reject("x87 replay instructions do not reconstruct the exact transfer span")

        schedule = replay.get("instruction_effect_schedule")
        if schedule is not None:
            self._compile_instruction_effect_schedule(
                replay=replay,
                schedule=_object(schedule, f"{self.identity} instruction effect schedule"),
                instruction_records=instruction_records,
                transfer_digest=transfer_digest,
            )
            return True

        replayable = [
            _x87_singleton_candidate(instruction_bytes, outer_instruction)
            for _start, _end, instruction_bytes, outer_instruction in instruction_records
        ]
        if not all(replayable):
            x87_rvas = [
                start
                for (start, _end, _bytes, _outer), is_x87 in zip(
                    instruction_records, replayable, strict=True
                )
                if is_x87
            ]
            ordinary_rvas = [
                start
                for (start, _end, _bytes, _outer), is_x87 in zip(
                    instruction_records, replayable, strict=True
                )
                if not is_x87
            ]
            raise StageBInterpreterError(
                f"{self.identity}: mixed x87/ordinary transfer lacks instruction-local "
                f"effect interleaving (x87 RVAs={_rva_list(x87_rvas)}, "
                f"ordinary RVAs={_rva_list(ordinary_rvas)})",
                code="x87_replay_interleaving_unavailable",
                next_action=(
                    "export an instruction-ordered effect schedule that classifies each "
                    "instruction and attaches register, flag, memory, fault, and call "
                    "effects to its RVA, plus one exact singleton x87 replay binding "
                    "with RVA, bytes, SHA-256, checked decoder, and checked executor"
                ),
            )

        contract_digest = _sha256(self.row.get("contract_sha256"), "contract_sha256")
        image_base = _u32(replay.get("image_base"), "x87 replay image_base")
        for instruction_rva, instruction_end, instruction_bytes, _outer in instruction_records:
            replay_index = len(self.x87_operations)
            self.x87_operations.append(
                _typed_x87_program(
                    contract_sha256=contract_digest,
                    image_base=image_base,
                    rva_start=instruction_rva,
                    rva_end=instruction_end,
                    instruction_bytes=instruction_bytes,
                    instruction=_outer,
                    checked_decoder=_X87_CHECKED_DECODER,
                    checked_executor=_X87_CHECKED_EXECUTOR,
                )
            )
            self.actions.append(_Action("typed_x87", (replay_index,)))
        return False

    def _compile_instruction_effect_schedule(
        self,
        *,
        replay: Mapping[str, Any],
        schedule: Mapping[str, Any],
        instruction_records: list[tuple[int, int, bytes, Mapping[str, Any]]],
        transfer_digest: str,
    ) -> None:
        if schedule.get("format") != _INSTRUCTION_EFFECT_SCHEDULE_FORMAT:
            raise StageBInterpreterError(
                f"{self.identity}: unsupported instruction effect schedule format",
                code="malformed_x87_instruction_effect_schedule",
            )
        if schedule.get("status") != "complete" or schedule.get("proof_authority") is not False:
            raise StageBInterpreterError(
                f"{self.identity}: instruction effect schedule is not a complete proposal",
                code="malformed_x87_instruction_effect_schedule",
            )
        original = _object(self.row.get("original"), "original span")
        if (
            schedule.get("ordering") != "strict_contiguous_rva_order"
            or schedule.get("rva_start", original.get("rva_start"))
            != original.get("rva_start")
            or schedule.get("rva_end", original.get("rva_end"))
            != original.get("rva_end")
        ):
            raise StageBInterpreterError(
                f"{self.identity}: instruction effect schedule span or ordering changed",
                code="malformed_x87_instruction_effect_schedule",
            )
        if schedule.get("transfer_bytes_sha256") != transfer_digest:
            raise StageBInterpreterError(
                f"{self.identity}: instruction effect schedule binds different transfer bytes",
                code="malformed_x87_instruction_effect_schedule",
            )
        outer_schedule = self.row.get("instruction_effect_schedule")
        if outer_schedule != schedule:
            raise StageBInterpreterError(
                f"{self.identity}: outer and replay instruction effect schedules differ",
                code="malformed_x87_instruction_effect_schedule",
            )
        schedule_digest = _sha256(
            schedule.get("schedule_sha256"), "instruction effect schedule SHA-256"
        )
        schedule_body = dict(schedule)
        del schedule_body["schedule_sha256"]
        if _json_sha256(schedule_body) != schedule_digest:
            raise StageBInterpreterError(
                f"{self.identity}: instruction effect schedule SHA-256 mismatch",
                code="malformed_x87_instruction_effect_schedule",
            )
        if schedule.get("blockers") != []:
            raise StageBInterpreterError(
                f"{self.identity}: complete instruction effect schedule contains blockers",
                code="malformed_x87_instruction_effect_schedule",
            )
        records = _list(schedule.get("records"), "instruction effect schedule records")
        if len(records) != len(instruction_records):
            raise StageBInterpreterError(
                f"{self.identity}: instruction effect schedule does not cover the transfer",
                code="malformed_x87_instruction_effect_schedule",
            )
        counts = _object(schedule.get("counts"), "instruction effect schedule counts")
        if counts.get("instructions") != len(records) or counts.get("blockers") != 0:
            raise StageBInterpreterError(
                f"{self.identity}: instruction effect schedule counts are inconsistent",
                code="malformed_x87_instruction_effect_schedule",
            )

        contract_digest = _sha256(self.row.get("contract_sha256"), "contract_sha256")
        image_base = _u32(replay.get("image_base"), "x87 replay image_base")
        x87_count = 0
        ordinary_count = 0
        final_control: Mapping[str, Any] | None = None
        for index, (raw_record, instruction) in enumerate(
            zip(records, instruction_records, strict=True)
        ):
            record = _object(raw_record, f"{self.identity} schedule record {index}")
            record_digest = _sha256(
                record.get("record_sha256"), f"schedule record {index} SHA-256"
            )
            record_body = dict(record)
            del record_body["record_sha256"]
            if _json_sha256(record_body) != record_digest:
                raise StageBInterpreterError(
                    f"{self.identity}: schedule record {index} SHA-256 mismatch",
                    code="malformed_x87_instruction_effect_schedule",
                )
            instruction_rva, instruction_end, instruction_bytes, _outer = instruction
            if (
                record.get("index") != index
                or record.get("rva_start") != instruction_rva
                or record.get("rva_end") != instruction_end
                or _hex_bytes(record.get("bytes"), "schedule record bytes")
                != instruction_bytes
                or record.get("bytes_sha256") != sha256_bytes(instruction_bytes)
                or record.get("transfer_bytes_sha256") != transfer_digest
            ):
                raise StageBInterpreterError(
                    f"{self.identity}: schedule record {index} does not bind its exact instruction",
                    code="malformed_x87_instruction_effect_schedule",
                )
            classification = _object(
                record.get("classification"), f"schedule record {index} classification"
            )
            if (
                classification.get("status")
                != "proposal_requires_lean_exact_byte_replay"
                or classification.get("proof_authority") is not False
            ):
                raise StageBInterpreterError(
                    f"{self.identity}: schedule record {index} classification is unqualified",
                    code="malformed_x87_instruction_effect_schedule",
                )
            instruction_class = record.get("instruction_class")
            raw_effects = record.get("effects")
            if raw_effects is None and instruction_class == "x87_singleton_checked_replay":
                effects: Mapping[str, Any] = {}
            else:
                effects = _object(raw_effects, f"schedule record {index} effects")
            raw_control = effects.get("control")
            if raw_control is None:
                control: Mapping[str, Any] = (
                    {"kind": "fallthrough", "target_rva": instruction_records[index + 1][0]}
                    if index + 1 < len(records)
                    else _object(self.row.get("outcome"), f"{self.identity} outcome")
                )
            else:
                control = _object(raw_control, f"schedule record {index} control")
            if index + 1 < len(records):
                next_rva = instruction_records[index + 1][0]
                if (
                    control.get("kind") != "fallthrough"
                    or control.get("target_rva") != next_rva
                ):
                    raise StageBInterpreterError(
                        f"{self.identity}: schedule record {index} does not fall through "
                        "to the next exact instruction",
                        code="malformed_x87_instruction_effect_schedule",
                    )
            else:
                self._validate_scheduled_outcome(control)
                final_control = control
            if instruction_class == "x87_singleton_checked_replay":
                if (
                    classification.get("checked_decoder") != _X87_CHECKED_DECODER
                    or classification.get("checked_executor") != _X87_CHECKED_EXECUTOR
                ):
                    raise StageBInterpreterError(
                        f"{self.identity}: x87 schedule record {index} names an unsupported checker",
                        code="malformed_x87_instruction_effect_schedule",
                    )
                singleton = _object(
                    record.get("x87_singleton_replay"),
                    f"schedule record {index} x87 singleton",
                )
                if (
                    singleton.get("rva_start") != instruction_rva
                    or singleton.get("rva_end") != instruction_end
                    or singleton.get("bytes") != instruction_bytes.hex()
                    or singleton.get("bytes_sha256") != sha256_bytes(instruction_bytes)
                    or singleton.get("checked_decoder") != _X87_CHECKED_DECODER
                    or singleton.get("checked_executor") != _X87_CHECKED_EXECUTOR
                    or singleton.get("physical_state_effect")
                    != "produced_by_checked_executor_not_inferred_by_exporter"
                ):
                    raise StageBInterpreterError(
                        f"{self.identity}: x87 schedule record {index} singleton binding is malformed",
                        code="malformed_x87_instruction_effect_schedule",
                    )
                replay_index = len(self.x87_operations)
                self.x87_operations.append(_typed_x87_program(
                    contract_sha256=contract_digest,
                    image_base=image_base,
                    rva_start=instruction_rva,
                    rva_end=instruction_end,
                    instruction_bytes=instruction_bytes,
                    instruction=_outer,
                    checked_decoder=_X87_CHECKED_DECODER,
                    checked_executor=_X87_CHECKED_EXECUTOR,
                ))
                self.actions.append(_Action("typed_x87", (replay_index,)))
                self._reset_instruction_expression_cache()
                if index + 1 == len(records):
                    if control.get("kind") not in {"fallthrough", "jump"}:
                        raise StageBInterpreterError(
                            f"{self.identity}: terminal checked x87 instruction has "
                            "non-static control",
                            code="x87_checked_export_unavailable",
                            next_action=(
                                "split terminal control into a checked ordinary instruction "
                                "after the x87 replay"
                            ),
                        )
                    self.scheduled_outcome = self._outcome(control)
                x87_count += 1
            elif instruction_class == "ordinary_symbolic_instruction":
                if (
                    classification.get("checked_decoder") != _ORDINARY_CHECKED_DECODER
                    or classification.get("checked_executor") != _ORDINARY_CHECKED_EXECUTOR
                    or "x87_singleton_replay" in record
                ):
                    raise StageBInterpreterError(
                        f"{self.identity}: ordinary schedule record {index} is malformed",
                        code="malformed_x87_instruction_effect_schedule",
                    )
                self._reset_instruction_expression_cache()
                self.instruction_local = True
                try:
                    self._compile_instruction_effects(effects)
                    if index + 1 == len(records):
                        self.scheduled_outcome = self._outcome(control)
                finally:
                    self.instruction_local = False
                ordinary_count += 1
            else:
                raise StageBInterpreterError(
                    f"{self.identity}: schedule record {index} has an unsupported class",
                    code="malformed_x87_instruction_effect_schedule",
                )
        if (
            counts.get("x87_singletons") != x87_count
            or counts.get("ordinary_instructions") != ordinary_count
        ):
            raise StageBInterpreterError(
                f"{self.identity}: instruction effect schedule class counts differ",
                code="malformed_x87_instruction_effect_schedule",
            )
        if final_control is None or self.scheduled_outcome is None:
            raise StageBInterpreterError(
                f"{self.identity}: instruction effect schedule has no composable outcome",
                code="malformed_x87_instruction_effect_schedule",
            )

    def _validate_scheduled_outcome(self, control: Mapping[str, Any]) -> None:
        aggregate = _object(self.row.get("outcome"), f"{self.identity} outcome")
        kind = control.get("kind")
        if kind != aggregate.get("kind"):
            raise StageBInterpreterError(
                f"{self.identity}: final schedule control differs from aggregate outcome",
                code="malformed_x87_instruction_effect_schedule",
            )
        fields = {
            "fallthrough": ("target_rva",),
            "jump": ("target_rva",),
            "branch": ("true_target_rva", "false_target_rva"),
        }.get(str(kind), ())
        if any(control.get(field) != aggregate.get(field) for field in fields):
            raise StageBInterpreterError(
                f"{self.identity}: final schedule targets differ from aggregate outcome",
                code="malformed_x87_instruction_effect_schedule",
            )

    def _reset_instruction_expression_cache(self) -> None:
        self.memo.clear()
        self.memo_memory_dependencies.clear()
        self.x87_memo.clear()
        self.x87_memo_memory_dependencies.clear()

    def _compile_instruction_effects(self, effects: Mapping[str, Any]) -> None:
        ordered = _optional_list(effects.get("ordered_events"))
        owned_register_outputs, owned_flag_outputs = self._rep_scas_owned_outputs(
            ordered
        )
        call_event = any(
            isinstance(raw, Mapping)
            and raw.get("family") == "external"
            and raw.get("kind") in {"external_call", "internal_call", "indirect_call"}
            for raw in ordered
        )

        updates: list[_Action] = []
        writes = [
            *_optional_list(effects.get("register_writes")),
        ]
        flag_writes = [
            *_optional_list(effects.get("defined_flag_writes")),
            *_optional_list(effects.get("undefined_flag_writes")),
        ]

        def compile_updates() -> None:
            for raw in writes:
                write = _object(raw, f"{self.identity} instruction register write")
                name = _string(write.get("register"), "register write name")
                if name in owned_register_outputs:
                    continue
                if name not in _REGISTER_INDEX:
                    raise StageBInterpreterError(
                        f"{self.identity}: unsupported instruction register {name!r}"
                    )
                updates.append(_Action(
                    "set_reg", (self.word(write.get("value")),), _REGISTER_INDEX[name]
                ))
            for raw in flag_writes:
                write = _object(raw, f"{self.identity} instruction flag write")
                name = _string(write.get("flag"), "flag write name")
                if name in owned_flag_outputs:
                    continue
                if name not in _FLAG_INDEX:
                    raise StageBInterpreterError(
                        f"{self.identity}: unsupported instruction flag {name!r}"
                    )
                updates.append(_Action(
                    "set_flag", (self.word(write.get("value")),), _FLAG_INDEX[name]
                ))

        if not call_event:
            compile_updates()
        external_index = len(self.available_calls)
        for raw in ordered:
            event = _object(raw, f"{self.identity} instruction ordered event")
            family = event.get("family")
            if family == "memory":
                self._memory_event(event)
            elif family == "fault":
                self._fault_event(event)
            elif family == "external":
                self._external_event(
                    self._instruction_call_boundary(event, external_index),
                    external_index,
                )
                external_index += 1
            else:
                raise StageBInterpreterError(
                    f"{self.identity}: unsupported instruction event family {family!r}"
                )
        if call_event:
            compile_updates()
        self.actions.extend(updates)
        self.actions.append(_Action("sync_eflags"))

    def _rep_scas_owned_outputs(
        self, ordered_events: list[Any]
    ) -> tuple[set[str], set[str]]:
        registers: set[str] = set()
        flags: set[str] = set()
        for raw in ordered_events:
            if not isinstance(raw, Mapping) or raw.get("kind") != "rep_scas":
                continue
            if (
                raw.get("owned_register_outputs")
                != list(_REP_SCAS_OWNED_REGISTERS)
                or raw.get("owned_flag_outputs") != list(_REP_SCAS_OWNED_FLAGS)
            ):
                raise StageBInterpreterError(
                    f"{self.identity}: rep_scas has an invalid owned-output inventory",
                    code="malformed_rep_scas_event",
                )
            registers.update(_REP_SCAS_OWNED_REGISTERS)
            flags.update(_REP_SCAS_OWNED_FLAGS)
        return registers, flags

    def _check_x87_replay_outcome(self, outcome: Mapping[str, Any]) -> None:
        continuation = self.x87_operations[-1].rva_end
        if outcome.get("kind") != "fallthrough" or outcome.get("target_rva") != continuation:
            raise StageBInterpreterError(
                f"{self.identity}: checked x87 replay sequence must fall through to its span end",
                code="unsupported_x87_replay_outcome",
                next_action=(
                    "split control transfer from the ordered checked x87 singleton commands"
                ),
            )

    def word(self, raw: Any) -> int:
        if isinstance(raw, bool):
            raw = {"op": "true" if raw else "false"}
        elif isinstance(raw, int):
            raw = {"op": "const", "value": raw, "width": 32}
        expr = _object(raw, f"{self.identity} word expression")
        key = _canonical(expr)
        if key in self.memo:
            return self.memo[key]
        op = _string(expr.get("op"), "expression op")
        node = self._word_node(op, expr)
        index = len(self.nodes)
        self.nodes.append(node)
        self.memo[key] = index
        self.memo_memory_dependencies[key] = _memory_dependency_keys(expr)
        self.actions.append(_Action("eval_word", (index,)))
        return index

    def x87(self, raw: Any) -> int:
        _object(raw, f"{self.identity} x87 expression")
        raise StageBInterpreterError(
            f"{self.identity}: x87-derived value is not materialized by checked replay",
            code="x87_checked_export_unavailable",
            next_action=(
                "export the value through checked machine-state or memory effects from "
                "the exact singleton x87 replay"
            ),
        )

    def _ordered_memory_read(self, raw_address: Any, width: int) -> int:
        """Emit one evaluator read for one architectural read event."""

        address = self.word(raw_address)
        expression = {"op": "load", "width": width, "address": raw_address}
        key = _canonical(expression)
        self._invalidate_memory_observation(key)
        index = len(self.nodes)
        self.nodes.append(_Node("load", (address,), aux=width))
        self.memo[key] = index
        self.memo_memory_dependencies[key] = frozenset((key,))
        self.actions.append(_Action("eval_word", (index,)))
        return index

    def _invalidate_memory_observation(self, load_key: str) -> None:
        stale_word_keys = tuple(
            key
            for key, dependencies in self.memo_memory_dependencies.items()
            if load_key in dependencies
        )
        for key in stale_word_keys:
            self.memo.pop(key, None)
            self.memo_memory_dependencies.pop(key, None)

        stale_x87_keys = tuple(
            key
            for key, dependencies in self.x87_memo_memory_dependencies.items()
            if load_key in dependencies
        )
        for key in stale_x87_keys:
            self.x87_memo.pop(key, None)
            self.x87_memo_memory_dependencies.pop(key, None)

    def _word_node(self, op: str, expr: Mapping[str, Any]) -> _Node:
        if op == "const":
            return _Node(op, immediate=_u32_wrapping(expr.get("value"), "constant"))
        if op == "reg":
            name = _string(expr.get("name"), "register expression name")
            if name not in _REGISTER_INDEX:
                raise StageBInterpreterError(f"{self.identity}: unsupported register {name!r}")
            return _Node(
                op,
                aux=_REGISTER_INDEX[name],
                immediate=int(self.instruction_local),
            )
        if op == "flag":
            name = _string(expr.get("name"), "flag expression name")
            if name not in _FLAG_INDEX and name != "af":
                raise StageBInterpreterError(f"{self.identity}: unsupported flag {name!r}")
            return _Node(
                op,
                aux=_AF_FLAG_INDEX if name == "af" else _FLAG_INDEX[name],
                immediate=int(self.instruction_local),
            )
        if op == "fs_base":
            return _Node(op, immediate=int(self.instruction_local))
        if op in {"true", "false"}:
            return _Node(op)
        if op in {"undefined_bv", "undefined_flag"}:
            label = str(expr.get("id") or expr.get("reason") or "undefined")
            defined_value = expr.get("defined_value")
            arguments = () if defined_value is None else (self.word(defined_value),)
            return _Node(op, arguments, immediate=_stable_slot(label))
        if op in {"call_response", "call_flag"}:
            call_index = _nonnegative(expr.get("call_index"), f"{op} call_index")
            if call_index not in self.available_calls:
                raise StageBInterpreterError(
                    f"{self.identity}: {op} references unavailable call {call_index}"
                )
            field = _string(
                expr.get("register" if op == "call_response" else "flag"),
                f"{op} field",
            )
            index_map = _REGISTER_INDEX if op == "call_response" else _FLAG_INDEX
            if field not in index_map and not (op == "call_flag" and field == "af"):
                raise StageBInterpreterError(f"{self.identity}: unsupported {op} field {field!r}")
            index = _AF_FLAG_INDEX if field == "af" else index_map[field]
            return _Node(op, aux=index, immediate=call_index)
        if op == "load":
            width = _width(expr.get("width"))
            return _Node(op, (self.word(expr.get("address")),), aux=width)
        if op.startswith("fpu_"):
            return self._x87_word_node(op, expr)
        if op in {"shift_cf", "shift_of"}:
            args = _list(expr.get("args"), f"{op} args")
            expected = 4 if op == "shift_cf" else 5
            if len(args) != expected or args[0] not in {
                "shl", "sal", "shr", "sar", "shld", "shrd"
            }:
                raise StageBInterpreterError(f"{self.identity}: unsupported {op} shape")
            width = _width_bits(args[1])
            kind = {"shl": 0, "sal": 0, "shld": 0, "shr": 1, "shrd": 1, "sar": 2}[str(args[0])]
            refs = tuple(self.word(arg) for arg in args[2:])
            return _Node(op, refs, aux=(kind << 8) | width)
        expected = {
            "sub32": 2, "ult32": 2, "eq": 2, "xor_bool": 2, "eq_bool": 2,
            "add32": (2, 4), "mul32": (2, 4), "xor32": (2, 4),
            "and32": (2, 4), "or32": (2, 4), "not32": 1, "neg32": 1,
            "shl32": 2, "lshr32": 2, "sar": 3, "sign_extend": 2,
            "ite": 3, "msb": (1, 2), "not": 1, "and_bool": (1, 5),
            "or_bool": (1, 5), "parity": 2, "bool_to_bit": 1,
            "add_overflow": 4, "sub_overflow": 4, "imul_low32": 2,
            "mul_low32": 2, "imul_high32": 2, "mul_high32": 2,
            "imul_overflow": 5, "mul_carry": 4, "udiv_quot32": 3,
            "udiv_rem32": 3, "udiv_valid32": 3, "bsr_index": 2,
            "tzcnt": 2, "sbb_borrow": 5, "sbb_overflow": 5,
            "adc_carry": 5, "adc_overflow": 5,
        }.get(op)
        if expected is None:
            raise StageBInterpreterError(
                f"{self.identity}: unsupported semantic op {op!r}"
            )
        args = _list(expr.get("args"), f"{op} args")
        refs = tuple(self.word(arg) for arg in args)
        if not _arity_ok(len(refs), expected):
            raise StageBInterpreterError(
                f"{self.identity}: unsupported semantic op {op!r} with {len(refs)} args"
            )
        return _Node(op, refs)

    def _x87_word_node(self, op: str, expr: Mapping[str, Any]) -> _Node:
        args = _list(expr.get("args"), f"{op} args")
        zero_inputs = {
            "fpu_control", "fpu_control_init", "fpu_status", "fpu_status_init",
            "fpu_pending_exception", "fpu_last_opcode", "fpu_instruction_pointer",
            "fpu_code_selector", "fpu_data_pointer", "fpu_data_selector",
        }
        if op in zero_inputs and not args:
            return _Node(op, immediate=int(self.instruction_local))
        if op == "fpu_tag" and len(args) == 1:
            return _Node(
                op,
                aux=_x87_slot(args[0]),
                immediate=int(self.instruction_local),
            )
        if op in {"fpu_control_load", "fpu_control_word", "fpu_status_word"} and len(args) == 1:
            return _Node(op, (self.word(args[0]),))
        if op in {"fpu_bits_lo32", "fpu_bits_hi32", "fpu_fxam"} and len(args) == 1:
            return _Node(op, (self.x87(args[0]),))
        if op in {"fpu_cmp_cf", "fpu_cmp_pf", "fpu_cmp_zf"} and len(args) == 2:
            return _Node(op, (self.x87(args[0]), self.x87(args[1])))
        if op == "fpu_int32" and len(args) == 2:
            return _Node(op, (self.x87(args[0]), self.word(args[1])))
        raise StageBInterpreterError(f"{self.identity}: unsupported x87 word op {op!r}")

    def _x87_node(self, op: str, expr: Mapping[str, Any]) -> _Node:
        args = _list(expr.get("args"), f"{op} args")
        if op == "fpu_reg" and len(args) == 1:
            return _Node(op, aux=_x87_slot(args[0]))
        if op == "fpu_empty" and len(args) == 1:
            return _Node(op, aux=_x87_slot(args[0]))
        if op == "fpu_const" and len(args) == 1 and args[0] in {"0", "1"}:
            return _Node(op, aux=int(args[0]))
        if op in {"fpu_mem", "fpu_int"} and len(args) == 2:
            width = _width_bits(args[0])
            if op == "fpu_mem" and width != 32:
                raise StageBInterpreterError(f"{self.identity}: fpu_mem supports 32 bits")
            return _Node(op, (self.word(args[1]),), aux=width)
        if op == "fpu_mem64" and len(args) == 2:
            return _Node(op, (self.word(args[0]), self.word(args[1])))
        if op == "fpu_neg" and len(args) == 1:
            return _Node(op, (self.x87(args[0]),))
        if op in {"fpu_add", "fpu_sub", "fpu_subr", "fpu_mul", "fpu_div", "fpu_divr"} and len(args) == 2:
            return _Node(op, (self.x87(args[0]), self.x87(args[1])))
        raise StageBInterpreterError(f"{self.identity}: unsupported x87 value op {op!r}")

    def _memory_event(self, event: Mapping[str, Any]) -> None:
        kind = event.get("kind")
        width = _width(event.get("width"))
        if kind == "read":
            self._ordered_memory_read(event.get("address"), width)
        elif kind == "write":
            address = self.word(event.get("address"))
            value = self.word(event.get("value"))
            self.actions.append(_Action("memory_write", (address, value), width))
        else:
            raise StageBInterpreterError(f"{self.identity}: unsupported memory event {kind!r}")

    def _fault_event(self, event: Mapping[str, Any]) -> None:
        if event.get("kind") != "divide_error":
            raise StageBInterpreterError(f"{self.identity}: unsupported fault event")
        self.actions.append(_Action("divide_if", (self.word(event.get("condition")),)))

    def _external_event(self, event: Mapping[str, Any], event_index: int) -> None:
        kind = _string(event.get("kind"), "external event kind")
        if kind == "rep_movsd":
            self.actions.append(_Action("rep_movsd", (
                self.word(event.get("source")), self.word(event.get("destination")),
                self.word(event.get("count")), self.word(event.get("direction_flag")),
            )))
            return
        if kind == "rep_movs":
            width = self._checked_string_event(
                event,
                event_index,
                kind="rep_movs",
                effect_model="symbolic_string_copy_v2",
            )
            if "value" in event:
                raise StageBInterpreterError(
                    f"{self.identity}: rep_movs must not carry a fill value",
                    code="malformed_rep_movs_event",
                )
            self.actions.append(_Action("rep_movs", (
                self.word(event.get("source")), self.word(event.get("destination")),
                self.word(event.get("count")), self.word(event.get("direction_flag")),
            ), width))
            return
        if kind == "rep_scas":
            self._checked_rep_scas_event(event, event_index)
            arguments = (
                self.word(event.get("accumulator")),
                self.word(event.get("destination")),
                self.word(event.get("count")),
                self.word(event.get("direction_flag")),
            )
            self.actions.append(_Action("rep_scas", arguments, 1))
            return
        if kind == "rep_stosd":
            _u32(event.get("instruction_rva"), "rep_stosd instruction_rva")
            if event.get("effect_model") != "symbolic_string_fill_v1":
                raise StageBInterpreterError(
                    f"{self.identity}: rep_stosd requires symbolic_string_fill_v1",
                    code="malformed_rep_stosd_event",
                    next_action=(
                        "regenerate the ordered REP STOSD event from exact symbolic "
                        "instruction semantics"
                    ),
                )
            if _nonnegative(event.get("index"), "rep_stosd event index") != event_index:
                raise StageBInterpreterError(
                    f"{self.identity}: rep_stosd event index does not match its "
                    "ordered external-event position",
                    code="malformed_rep_stosd_event",
                    next_action=(
                        "regenerate one canonical ordered external-event inventory"
                    ),
                )
            if "source" in event:
                raise StageBInterpreterError(
                    f"{self.identity}: rep_stosd must not carry a source address",
                    code="malformed_rep_stosd_event",
                    next_action=(
                        "use the repeated EAX value field for REP STOSD"
                    ),
                )
            self.actions.append(_Action("rep_stosd", (
                self.word(event.get("destination")),
                self.word(event.get("value")),
                self.word(event.get("count")),
                self.word(event.get("direction_flag")),
            )))
            return
        if kind == "rep_stos":
            width = self._checked_string_event(
                event,
                event_index,
                kind="rep_stos",
                effect_model="symbolic_string_fill_v2",
            )
            if "source" in event:
                raise StageBInterpreterError(
                    f"{self.identity}: rep_stos must not carry a source address",
                    code="malformed_rep_stos_event",
                )
            self.actions.append(_Action("rep_stos", (
                self.word(event.get("destination")),
                self.word(event.get("value")),
                self.word(event.get("count")),
                self.word(event.get("direction_flag")),
            ), width))
            return
        if kind not in {"external_call", "internal_call", "indirect_call"}:
            raise StageBInterpreterError(f"{self.identity}: unsupported external event {kind!r}")
        registers = _object(event.get("register_inputs"), "call register_inputs")
        flags = _object(event.get("flag_inputs"), "call flag_inputs")
        register_nodes = tuple(self.word(registers.get(name)) for name in _REGISTERS)
        flag_nodes = tuple(self.word(flags.get(name)) for name in _FLAGS)
        argument_nodes = tuple(
            self.word(item) for item in _optional_list(event.get("arguments"))
        )
        stack_inputs = tuple(
            (
                _nonnegative(item.get("offset"), "stack input offset"),
                _width(item.get("width")),
                self.word(item.get("value")),
            )
            for item in (
                _object(raw, "stack input")
                for raw in _optional_list(event.get("stack_inputs"))
            )
        )
        target_node = self.word(event.get("target")) if kind == "indirect_call" else None
        ordinal = event.get("ordinal")
        if ordinal is not None:
            ordinal = _nonnegative(ordinal, "import ordinal")
        call = _Call(
            kind=kind,
            instruction_rva=_u32(event.get("instruction_rva"), "instruction_rva"),
            call_index=event_index,
            target_node=target_node,
            target_rva=_u32_wrapping(event.get("target_rva") or 0, "target_rva"),
            return_rva=_u32(event.get("return_rva"), "return_rva"),
            dll=event.get("dll") if isinstance(event.get("dll"), str) else None,
            symbol=event.get("symbol") if isinstance(event.get("symbol"), str) else None,
            ordinal=ordinal,
            register_nodes=register_nodes,
            flag_nodes=flag_nodes,
            argument_nodes=argument_nodes,
            stack_inputs=stack_inputs,
        )
        call_index = len(self.calls)
        self.calls.append(call)
        self.actions.append(_Action("call", (call_index,)))
        self.available_calls.add(event_index)

    def _checked_string_event(
        self,
        event: Mapping[str, Any],
        event_index: int,
        *,
        kind: str,
        effect_model: str,
    ) -> int:
        code = f"malformed_{kind}_event"
        _u32(event.get("instruction_rva"), f"{kind} instruction_rva")
        if event.get("effect_model") != effect_model:
            raise StageBInterpreterError(
                f"{self.identity}: {kind} requires {effect_model}",
                code=code,
            )
        if event.get("address_size") != 32:
            raise StageBInterpreterError(
                f"{self.identity}: {kind} requires 32-bit address size",
                code=code,
            )
        if event.get("restart_semantics") != "element_committed_v1":
            raise StageBInterpreterError(
                f"{self.identity}: {kind} requires element_committed_v1 restart semantics",
                code=code,
            )
        if _nonnegative(event.get("index"), f"{kind} event index") != event_index:
            raise StageBInterpreterError(
                f"{self.identity}: {kind} event index does not match its "
                "ordered external-event position",
                code=code,
            )
        try:
            return _width(event.get("element_width"))
        except StageBInterpreterError as error:
            raise StageBInterpreterError(
                f"{self.identity}: {kind} has invalid element width",
                code=code,
            ) from error

    def _checked_rep_scas_event(
        self,
        event: Mapping[str, Any],
        event_index: int,
    ) -> None:
        code = "malformed_rep_scas_event"
        try:
            width = self._checked_string_event(
                event,
                event_index,
                kind="rep_scas",
                effect_model="symbolic_string_scan_v1",
            )
        except StageBInterpreterError as error:
            raise StageBInterpreterError(
                f"{self.identity}: malformed rep_scas event: {error}",
                code=code,
            ) from error
        if width != 1:
            raise StageBInterpreterError(
                f"{self.identity}: rep_scas requires byte element width",
                code=code,
            )
        required_models = {
            "repeat_condition": "while_not_equal_v1",
            "comparison_model": "subtraction_flags_v1",
            "segment_model": "flat_es_zero_v1",
            "fault_model": "read_before_commit_v1",
        }
        for field, expected in required_models.items():
            if event.get(field) != expected:
                raise StageBInterpreterError(
                    f"{self.identity}: rep_scas requires {expected}",
                    code=code,
                )
        if (
            event.get("owned_register_outputs")
            != list(_REP_SCAS_OWNED_REGISTERS)
            or event.get("owned_flag_outputs") != list(_REP_SCAS_OWNED_FLAGS)
        ):
            raise StageBInterpreterError(
                f"{self.identity}: rep_scas has an invalid owned-output inventory",
                code=code,
            )
        if "source" in event or "value" in event:
            raise StageBInterpreterError(
                f"{self.identity}: rep_scas must not carry copy/fill operands",
                code=code,
            )

    def _outcome(self, outcome: Mapping[str, Any]) -> _Action:
        kind = _string(outcome.get("kind"), "outcome kind")
        if kind in {"fallthrough", "jump"}:
            return _Action("outcome_" + kind, (_u32(outcome.get("target_rva"), "target_rva"),))
        if kind == "branch":
            return _Action("outcome_branch", (
                self.word(outcome.get("condition")),
                _u32(outcome.get("true_target_rva"), "true_target_rva"),
                _u32(outcome.get("false_target_rva"), "false_target_rva"),
            ))
        if kind == "return":
            return _Action("outcome_return", (self.word(outcome.get("value")),))
        if kind == "indirect_jump":
            return _Action("outcome_indirect", (self.word(outcome.get("target")),))
        if kind == "external_jump":
            return _Action("outcome_external")
        raise StageBInterpreterError(f"{self.identity}: unsupported outcome {kind!r}")


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
        try:
            transfer = _TransferCompiler(row).compile()
        except StageBInterpreterError as exc:
            if not collect_blockers:
                raise
            blockers.append(_package_blocker(row, index, exc))
            continue
        if transfer.identity in seen_ids:
            error = StageBInterpreterError(
                f"duplicate transfer id {transfer.identity}",
                code="duplicate_transfer_id",
                next_action="make every Stage A semantic transfer identity unique",
            )
            if not collect_blockers:
                raise error
            blockers.append(_package_blocker(row, index, error))
            continue
        if transfer.rva_start in seen_rvas:
            error = StageBInterpreterError(
                f"duplicate transfer RVA 0x{transfer.rva_start:x}",
                code="duplicate_transfer_rva",
                next_action="split or reconcile transfers that start at the same original RVA",
            )
            if not collect_blockers:
                raise error
            blockers.append(_package_blocker(row, index, error))
            continue
        seen_ids.add(transfer.identity)
        seen_rvas.add(transfer.rva_start)
        transfers.append(transfer)
    blockers.sort(key=_package_blocker_sort_key)
    return tuple(sorted(transfers, key=lambda item: item.rva_start)), blockers


def _package_blocker(
    row: Mapping[str, Any], index: int, error: StageBInterpreterError
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
    rows = (
        input_rows
        if state_machine is not None
        else _adapt_machine_ir_rows(input_rows)
    )
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
        "authority": "candidate generation only; final acceptance requires Lean replay",
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
    sanitized_source_bindings: bool = False,
) -> dict[str, Any]:
    rows = list(transfers)
    blocker_rows = [dict(item) for item in blockers]
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
    if set(evidence_slots) != set(uses_by_slot):
        raise StageBInterpreterError(
            "compiled undefined nodes and definedness evidence have different slots",
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
    return metadata


def _typed_x87_program(
    *,
    contract_sha256: str,
    image_base: int,
    rva_start: int,
    rva_end: int,
    instruction_bytes: bytes,
    instruction: Mapping[str, Any],
    checked_decoder: str,
    checked_executor: str,
) -> _TypedX87Program:
    try:
        operation = extract_typed_x87_operation(
            encoded=instruction_bytes,
            instruction=instruction,
            image_base=image_base,
        )
    except StageAInputError as exc:
        raise StageBInterpreterError(
            f"typed x87 extraction failed: {exc}",
            code="unsupported_typed_x87_operation",
            next_action=(
                "add the mnemonic and operand form to the reviewed typed x87 table "
                "and qualify it against the ISA oracles"
            ),
        ) from exc
    if operation.source_size != rva_end - rva_start:
        raise StageBInterpreterError(
            "typed x87 source size differs from its checked span",
            code="malformed_typed_x87_operation",
        )
    return _TypedX87Program(
        contract_sha256=contract_sha256,
        image_base=image_base,
        rva_start=rva_start,
        rva_end=rva_end,
        operation=operation,
        checked_decoder=checked_decoder,
        checked_executor=checked_executor,
    )


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


def _interpreter_runtime_header() -> str:
    header = _runtime_header()
    replay_record = """#define STAGE_B_MACHINE_STATE_HAS_X87 1

typedef struct stage_b_typed_x87_operation {
  uint32_t image_base, rva_start, rva_end, source_size;
  const char *operation_identity;
  const char *contract_sha256;
  const char *checked_decoder;
  const char *checked_executor;
  const char *mnemonic;
  uint32_t operand_kind, operand_width;
  uint32_t stack_register_count, stack_register_0, stack_register_1;
  uint32_t base_register, index_register, scale;
  int32_t displacement;
  uint32_t image_rva, has_image_rva;
} stage_b_typed_x87_operation;

"""
    replay_handler = """typedef stage_b_call_status (*stage_b_typed_x87_handler)(
    stage_b_runtime *runtime,
    const stage_b_typed_x87_operation *program,
    const stage_b_machine_state *input,
    stage_b_machine_state *output);

"""
    replacements = (
        (
            "typedef struct stage_b_runtime stage_b_runtime;\n",
            replay_record + "typedef struct stage_b_runtime stage_b_runtime;\n",
        ),
        (
            "typedef uint32_t (*stage_b_code_target_resolver)(\n",
            replay_handler + "typedef uint32_t (*stage_b_code_target_resolver)(\n",
        ),
        (
            "  stage_b_external_call_handler external_call_fallback;\n"
            "  stage_b_code_target_resolver resolve_code_target;\n",
            "  stage_b_external_call_handler external_call_fallback;\n"
            "  stage_b_code_target_resolver resolve_code_target;\n"
            "  stage_b_typed_x87_handler execute_typed_x87_operation;\n",
        ),
    )
    for old, new in replacements:
        if old not in header:
            raise StageBInterpreterError(
                "shared runtime header changed before x87 replay ABI injection",
                code="interpreter_runtime_abi_drift",
                next_action="reconcile the interpreter replay ABI with stage_b_c_backend",
            )
        header = header.replace(old, new, 1)
    return header


def _interpreter_header() -> str:
    return """#ifndef STAGE_B_SEMANTIC_INTERPRETER_H
#define STAGE_B_SEMANTIC_INTERPRETER_H

#include "state-machine-runtime.h"

typedef struct stage_b_program_transfer stage_b_program_transfer;
typedef stage_b_step_result (*stage_b_region_override_fn)(
    stage_b_runtime *, stage_b_machine_state *);
typedef struct stage_b_region_override {
  uint32_t entry_rva;
  stage_b_region_override_fn function;
  uint32_t fallback_on_unimplemented;
  const char *replacement_id;
  const char *cluster_id;
} stage_b_region_override;

const stage_b_program_transfer *stage_b_program_lookup(uint32_t source_rva);
const stage_b_region_override *stage_b_region_override_lookup(uint32_t entry_rva);
stage_b_step_result stage_b_interpreter_step(
    stage_b_runtime *runtime, stage_b_machine_state *state, uint32_t source_rva);
stage_b_call_status stage_b_run_function(
    stage_b_runtime *runtime, uint32_t entry_rva,
    const stage_b_machine_state *input, stage_b_machine_state *output);

#endif
"""


# The opcode/action enums and evaluator are emitted from the same fixed table as
# the data source.  Keeping this kernel invariant is the main cache boundary.
_WORD_OPS = (
    "const", "reg", "flag", "true", "false", "undefined_bv", "undefined_flag",
    "call_response", "call_flag", "load", "sub32", "ult32", "eq", "xor_bool",
    "eq_bool", "add32", "mul32", "xor32", "and32", "or32", "not32", "neg32",
    "shl32", "lshr32", "sar", "sign_extend", "ite", "msb", "not", "and_bool",
    "or_bool", "parity", "bool_to_bit", "add_overflow", "sub_overflow",
    "imul_low32", "mul_low32", "imul_high32", "mul_high32", "imul_overflow",
    "mul_carry", "udiv_quot32", "udiv_rem32", "udiv_valid32", "bsr_index",
    "tzcnt", "sbb_borrow", "sbb_overflow", "shift_cf", "shift_of",
    "fpu_control", "fpu_control_init", "fpu_status", "fpu_status_init", "fpu_tag",
    "fpu_pending_exception", "fpu_last_opcode", "fpu_instruction_pointer",
    "fpu_code_selector", "fpu_data_pointer", "fpu_data_selector", "fpu_control_load",
    "fpu_control_word", "fpu_status_word", "fpu_bits_lo32", "fpu_bits_hi32",
    "fpu_cmp_cf", "fpu_cmp_pf", "fpu_cmp_zf", "fpu_fxam", "fpu_int32",
    "adc_carry", "adc_overflow",
    "fs_base",
)
_X87_OPS = (
    "fpu_reg", "fpu_empty", "fpu_const", "fpu_mem", "fpu_int", "fpu_mem64",
    "fpu_neg", "fpu_add", "fpu_sub", "fpu_subr", "fpu_mul", "fpu_div", "fpu_divr",
)
_ACTIONS = (
    "eval_word", "eval_x87", "memory_write", "divide_if", "call", "rep_movsd",
    "set_reg", "set_flag", "set_x87", "set_x87_tag", "set_x87_control",
    "set_x87_status", "set_x87_pending", "set_x87_opcode", "set_x87_ip",
    "set_x87_cs", "set_x87_dp", "set_x87_ds", "sync_eflags", "outcome_fallthrough",
    "outcome_jump", "outcome_branch", "outcome_return", "outcome_indirect",
    # Opcode 25 retains its historical ABI label. Its payload is now a typed,
    # byte-free operation and all newly generated capability metadata says so.
    "outcome_external", "replay_x87", "rep_stosd", "rep_movs", "rep_stos",
    "rep_scas",
)


def _program_source(transfers: tuple[_Transfer, ...]) -> str:
    # Flatten while rewriting local node and call references remains unnecessary:
    # each transfer points at slices and all references are transfer-local.
    lines = [
        '#include "state-machine-interpreter-internal.h"',
        "",
    ]
    for index, row in enumerate(transfers):
        prefix = f"stage_b_t{index:04d}"
        lines.extend(_render_transfer_data(prefix, row))
    lines.extend([
        "",
        "const stage_b_program_transfer stage_b_program_transfers[] = {",
    ])
    for index, row in enumerate(transfers):
        prefix = f"stage_b_t{index:04d}"
        lines.append(
            f"  {{ 0x{row.rva_start:08x}U, {len(row.nodes)}U, {len(row.x87_nodes)}U, "
            f"{len(row.actions)}U, {len(row.x87_operations)}U, {prefix}_nodes, "
            f"{prefix}_x87_nodes, {prefix}_actions, {prefix}_calls, {prefix}_x87_operations }},"
        )
    if not transfers:
        lines.append("  { 0U,0U,0U,0U,0U,0,0,0,0,0 },")
    lines.extend([
        "};",
        f"const uint32_t stage_b_program_transfer_count = {len(transfers)}U;",
        "",
    ])
    return "\n".join(lines)


def _render_transfer_data(prefix: str, row: _Transfer) -> list[str]:
    lines = [f"/* {row.identity.replace('*/', '* /')} */"]
    lines.append(f"static const stage_b_word_node {prefix}_nodes[] = {{")
    lines.extend("  " + _c_node(node, _WORD_OPS) + "," for node in row.nodes)
    if not row.nodes:
        lines.append("  { 0U, 0U, 0U, 0U, {0U,0U,0U,0U,0U} },")
    lines.append("};")
    lines.append(f"static const stage_b_x87_node {prefix}_x87_nodes[] = {{")
    lines.extend("  " + _c_node(node, _X87_OPS) + "," for node in row.x87_nodes)
    if not row.x87_nodes:
        lines.append("  { 0U, 0U, 0U, 0U, {0U,0U,0U,0U,0U} },")
    lines.append("};")
    for index, call in enumerate(row.calls):
        name = f"{prefix}_call_{index}"
        lines.append(f"static const uint32_t {name}_regs[] = {{ {', '.join(str(x)+'U' for x in call.register_nodes)} }};")
        lines.append(f"static const uint32_t {name}_flags[] = {{ {', '.join(str(x)+'U' for x in call.flag_nodes)} }};")
        arg_values = ", ".join(str(x) + "U" for x in call.argument_nodes) or "0U"
        lines.append(f"static const uint32_t {name}_args[] = {{ {arg_values} }};")
        stack_values = ", ".join(
            f"{{ {offset}U, {width}U, {node}U }}" for offset, width, node in call.stack_inputs
        ) or "{ 0U, 0U, 0U }"
        lines.append(f"static const stage_b_program_stack_input {name}_stack[] = {{ {stack_values} }};")
    lines.append(f"static const stage_b_program_call {prefix}_calls[] = {{")
    for index, call in enumerate(row.calls):
        name = f"{prefix}_call_{index}"
        kind = {"external_call": 0, "internal_call": 1, "indirect_call": 2}[call.kind]
        target = call.target_node if call.target_node is not None else 0
        lines.append(
            "  { "
            f"{kind}U, 0x{call.instruction_rva:08x}U, {call.call_index}U, {target}U, "
            f"0x{call.target_rva:08x}U, 0x{call.return_rva:08x}U, "
            f"{_c_string(call.dll)}, {_c_string(call.symbol)}, {call.ordinal or 0}U, "
            f"{1 if call.ordinal is not None else 0}U, {name}_regs, {name}_flags, "
            f"{name}_args, {len(call.argument_nodes)}U, {name}_stack, {len(call.stack_inputs)}U "
            "},"
        )
    if not row.calls:
        lines.append("  { 0U,0U,0U,0U,0U,0U,0,0,0U,0U,0,0,0,0U,0,0U },")
    lines.append("};")
    lines.append(
        f"static const stage_b_typed_x87_operation {prefix}_x87_operations[] = {{"
    )
    for operation in row.x87_operations:
        operand = operation.operation.operand
        register_codes = {
            None: 0,
            "eax": 1,
            "ebx": 2,
            "ecx": 3,
            "edx": 4,
            "esi": 5,
            "edi": 6,
            "ebp": 7,
            "esp": 8,
        }
        operand_kinds = {"none": 0, "ax": 1, "stack": 2, "memory": 3}
        stack_registers = (*operand.registers, 0, 0)
        lines.append(
            "  { "
            f"0x{operation.image_base:08x}U, 0x{operation.rva_start:08x}U, "
            f"0x{operation.rva_end:08x}U, {operation.operation.source_size}U, "
            f"{_c_string(operation.operation.identity)}, "
            f"{_c_string(operation.contract_sha256)}, "
            f"{_c_string(operation.checked_decoder)}, "
            f"{_c_string(operation.checked_executor)}, "
            f"{_c_string(operation.operation.mnemonic)}, "
            f"{operand_kinds[operand.kind]}U, {operand.width}U, "
            f"{len(operand.registers)}U, {stack_registers[0]}U, "
            f"{stack_registers[1]}U, {register_codes[operand.base]}U, "
            f"{register_codes[operand.index]}U, {operand.scale}U, "
            f"{operand.displacement}, {operand.image_rva or 0}U, "
            f"{1 if operand.image_rva is not None else 0}U "
            "},"
        )
    if not row.x87_operations:
        lines.append("  { 0 },")
    lines.append("};")
    lines.append(f"static const stage_b_program_action {prefix}_actions[] = {{")
    lines.extend("  " + _c_action(action) + "," for action in row.actions)
    lines.append("};")
    lines.append("")
    return lines


def _c_node(node: _Node, inventory: tuple[str, ...]) -> str:
    if node.op not in inventory:
        raise StageBInterpreterError(f"interpreter opcode inventory lacks {node.op}")
    args = list(node.args) + [0] * (5 - len(node.args))
    return (
        f"{{ {inventory.index(node.op)}U, {len(node.args)}U, {node.aux}U, "
        f"0x{node.immediate & 0xffffffff:08x}U, "
        "{" + ",".join(f"{value}U" for value in args) + "} }"
    )


def _c_action(action: _Action) -> str:
    opcode_name = "replay_x87" if action.op == "typed_x87" else action.op
    if opcode_name not in _ACTIONS:
        raise StageBInterpreterError(f"interpreter action inventory lacks {action.op}")
    args = list(action.args) + [0] * (5 - len(action.args))
    return (
        f"{{ {_ACTIONS.index(opcode_name)}U, {len(action.args)}U, {action.aux}U, "
        "{" + ",".join(f"{value}U" for value in args) + "} }"
    )


def _interpreter_source(*, max_word_nodes: int) -> str:
    if not 1 <= max_word_nodes <= 1024:
        raise StageBInterpreterError(
            f"interpreter word-node capacity {max_word_nodes} is outside 1..1024",
            code="word_node_capacity_exceeded",
            next_action=(
                "split the oversized transfer or raise the checked interpreter "
                "profile limit"
            ),
        )
    return (
        '#include "state-machine-interpreter-internal.h"\n\n'
        + f"#define STAGE_B_MAX_WORD_NODES {max_word_nodes}U\n"
        + _interpreter_runtime_helpers()
        + "\n"
        + _INTERPRETER_KERNEL
    )


def _interpreter_runtime_helpers() -> str:
    """Reuse the integer helper kernel without compiling host x87 arithmetic."""
    helpers = _runtime_helpers()
    if "long double" in helpers or "stage_b_x87_" in helpers:
        raise StageBInterpreterError(
            "host x87 arithmetic leaked into the interpreter helper kernel",
            code="interpreter_runtime_helper_drift",
        )
    return helpers


_INTERPRETER_INTERNAL_HEADER = r'''#ifndef STAGE_B_SEMANTIC_INTERPRETER_INTERNAL_H
#define STAGE_B_SEMANTIC_INTERPRETER_INTERNAL_H

#include "state-machine-interpreter.h"

typedef struct stage_b_word_node {
  uint32_t op, arity, aux, immediate, args[5];
} stage_b_word_node;
typedef stage_b_word_node stage_b_x87_node;
typedef struct stage_b_program_action {
  uint32_t op, arity, aux, args[5];
} stage_b_program_action;
typedef struct stage_b_program_stack_input {
  uint32_t offset, width, value_node;
} stage_b_program_stack_input;
typedef struct stage_b_program_call {
  uint32_t kind, instruction_rva, call_index, target_node, target_rva, return_rva;
  const char *dll, *symbol;
  uint32_t ordinal, has_ordinal;
  const uint32_t *register_nodes, *flag_nodes, *argument_nodes;
  uint32_t argument_count;
  const stage_b_program_stack_input *stack_inputs;
  uint32_t stack_input_count;
} stage_b_program_call;
struct stage_b_program_transfer {
  uint32_t source_rva, word_count, x87_count, action_count, x87_operation_count;
  const stage_b_word_node *nodes;
  const stage_b_x87_node *x87_nodes;
  const stage_b_program_action *actions;
  const stage_b_program_call *calls;
  const stage_b_typed_x87_operation *x87_operations;
};
extern const stage_b_program_transfer stage_b_program_transfers[];
extern const uint32_t stage_b_program_transfer_count;

#endif
'''


# The kernel deliberately has no host floating-point implementation. Every x87
# transition crosses the exact checked replay boundary; legacy x87-node opcodes
# remain reserved in the stable data ABI and fail closed if encountered.
_INTERPRETER_KERNEL = r'''
#define STAGE_B_MAX_CALL_ARGUMENTS 64U
#define W(i) words[node->args[(i)]]

static uint32_t stage_b_state_reg(const stage_b_machine_state *state, uint32_t index) {
  const uint32_t *registers = &state->eax;
  return registers[index];
}
static void stage_b_set_reg(stage_b_machine_state *state, uint32_t index, uint32_t value) {
  uint32_t *registers = &state->eax;
  registers[index] = value;
}
static uint32_t stage_b_state_flag(const stage_b_machine_state *state, uint32_t index) {
  static const uint32_t offsets[6] = { 0U,1U,2U,3U,4U,5U };
  const uint32_t *flags = &state->cf;
  if (index == 6U) return (state->eflags >> 4) & 1U;
  if (index >= 6U) return 0U;
  return flags[offsets[index]] & 1U;
}
static void stage_b_set_flag(stage_b_machine_state *state, uint32_t index, uint32_t value) {
  uint32_t *flags = &state->cf;
  if (index == 6U) {
    state->eflags = (state->eflags & ~(1U << 4)) | ((value & 1U) << 4);
    return;
  }
  if (index >= 6U) return;
  flags[index] = value & 1U;
}
static uint32_t stage_b_eval_word(
    stage_b_runtime *rt, const stage_b_machine_state *input,
    const stage_b_machine_state *current,
    const stage_b_machine_state *call_output, uint32_t *words,
    const stage_b_word_node *node, uint32_t *memory_fault,
    uint32_t *semantic_fault) {
  uint32_t op = node->op;
  if (op == 0U) return node->immediate;
  if (op == 1U) return stage_b_state_reg(node->immediate?current:input, node->aux);
  if (op == 2U) return stage_b_state_flag(node->immediate?current:input, node->aux);
  if (op == 3U) return 1U;
  if (op == 4U) return 0U;
  if (op == 5U || op == 6U)
    return stage_b_undefined(
        rt, node->immediate, input, node->arity == 1U ? W(0) : 0U);
  if (op == 7U) return stage_b_state_reg(call_output, node->aux);
  if (op == 8U) return stage_b_state_flag(call_output, node->aux);
  if (op == 9U) return stage_b_read(rt, W(0), node->aux, memory_fault);
  if (op == 10U) return W(0) - W(1);
  if (op == 11U) return W(0) < W(1);
  if (op == 12U || op == 14U) return W(0) == W(1);
  if (op == 13U) return W(0) != W(1);
  if (op == 15U) { uint32_t i, v=0U; for(i=0;i<node->arity;++i)v+=W(i); return v; }
  if (op == 16U) { uint32_t i, v=1U; for(i=0;i<node->arity;++i)v*=W(i); return v; }
  if (op == 17U) { uint32_t i, v=0U; for(i=0;i<node->arity;++i)v^=W(i); return v; }
  if (op == 18U) { uint32_t i, v=0xffffffffU; for(i=0;i<node->arity;++i)v&=W(i); return v; }
  if (op == 19U) { uint32_t i, v=0U; for(i=0;i<node->arity;++i)v|=W(i); return v; }
  if (op == 20U) return ~W(0);
  if (op == 21U) return 0U-W(0);
  if (op == 22U) return W(0) << (W(1)&31U);
  if (op == 23U) return W(0) >> (W(1)&31U);
  if (op == 24U) return stage_b_sar(W(0),W(1),W(2));
  if (op == 25U) return stage_b_sign_extend(W(0),W(1));
  if (op == 26U) return W(0)?W(1):W(2);
  if (op == 27U) return stage_b_msb(node->arity==2U?W(0):32U,node->arity==2U?W(1):W(0));
  if (op == 28U) return !W(0);
  if (op == 29U) { uint32_t i; for(i=0;i<node->arity;++i)if(!W(i))return 0U;return 1U; }
  if (op == 30U) { uint32_t i; for(i=0;i<node->arity;++i)if(W(i))return 1U;return 0U; }
  if (op == 31U) return stage_b_parity(W(1));
  if (op == 32U) return W(0)?1U:0U;
  if (op == 33U) return stage_b_add_overflow(W(0),W(1),W(2),W(3));
  if (op == 34U) return stage_b_sub_overflow(W(0),W(1),W(2),W(3));
  if (op == 35U || op == 36U) return (uint32_t)((uint64_t)W(0)*(uint64_t)W(1));
  if (op == 37U) return stage_b_imul_high(W(0),W(1));
  if (op == 38U) return stage_b_mul_high(W(0),W(1));
  if (op == 39U) return W(4)!=((int32_t)W(3)<0?0xffffffffU:0U);
  if (op == 40U) return W(3)!=0U;
  if (op == 41U) return stage_b_udiv_quot(W(0),W(1),W(2));
  if (op == 42U) return stage_b_udiv_rem(W(0),W(1),W(2));
  if (op == 43U) return stage_b_udiv_valid(W(0),W(1),W(2));
  if (op == 44U) return stage_b_bsr(W(node->arity-1U));
  if (op == 45U) return stage_b_tzcnt(W(node->arity-1U));
  if (op == 46U) return stage_b_sbb_borrow(W(0),W(1),W(2),W(3),W(4));
  if (op == 47U) return stage_b_sbb_overflow(W(0),W(1),W(2),W(3),W(4));
  if (op == 48U) return stage_b_shift_cf(node->aux>>8,node->aux&255U,W(0),W(1));
  if (op == 49U) return stage_b_shift_of(node->aux>>8,node->aux&255U,W(0),W(1),W(2));
  if (op == 50U) return (node->immediate?current:input)->x87_control;
  if (op == 51U) return 0x037fU;
  if (op == 52U) return (node->immediate?current:input)->x87_status;
  if (op == 53U) return 0U;
  if (op == 54U) return (node->immediate?current:input)->x87_stack[node->aux].tag;
  if (op == 55U) return (node->immediate?current:input)->x87_pending_exception;
  if (op == 56U) return (node->immediate?current:input)->x87_last_opcode;
  if (op == 57U) return (node->immediate?current:input)->x87_instruction_pointer;
  if (op == 58U) return (node->immediate?current:input)->x87_code_selector;
  if (op == 59U) return (node->immediate?current:input)->x87_data_pointer;
  if (op == 60U) return (node->immediate?current:input)->x87_data_selector;
  if (op >= 61U && op <= 63U) return W(0)&0xffffU;
  if (op == 71U) {
    uint32_t width = W(0);
    uint64_t mask, sum;
    if (width == 0U || width > 32U || W(3) > 1U) {
      *semantic_fault = 1U;
      return 0U;
    }
    mask = width == 32U ? 0xffffffffULL : ((1ULL << width) - 1ULL);
    sum = ((uint64_t)W(1) & mask) + ((uint64_t)W(2) & mask) + (uint64_t)W(3);
    if (((uint32_t)sum & (uint32_t)mask) != (W(4) & (uint32_t)mask)) {
      *semantic_fault = 1U;
      return 0U;
    }
    return (uint32_t)((sum >> width) & 1ULL);
  }
  if (op == 72U) {
    uint32_t width = W(0), mask, left, right, result, sign;
    uint64_t sum;
    if (width == 0U || width > 32U || W(3) > 1U) {
      *semantic_fault = 1U;
      return 0U;
    }
    mask = width == 32U ? 0xffffffffU : ((1U << width) - 1U);
    left = W(1) & mask;
    right = W(2) & mask;
    result = W(4) & mask;
    sum = (uint64_t)left + (uint64_t)right + (uint64_t)W(3);
    if (((uint32_t)sum & mask) != result) {
      *semantic_fault = 1U;
      return 0U;
    }
    sign = 1U << (width - 1U);
    return ((~(left ^ right) & (left ^ result) & sign) != 0U) ? 1U : 0U;
  }
  if (op == 73U) return (node->immediate?current:input)->fs_base;
  *semantic_fault = 1U;
  return 0U;
}
#undef W

__attribute__((weak)) const stage_b_region_override *
stage_b_region_override_lookup(uint32_t entry_rva) {
  (void)entry_rva;
  return (const stage_b_region_override *)0;
}

static uint32_t stage_b_region_override_result_valid(stage_b_step_result result) {
  if (result.kind > STAGE_B_EXTERNAL_JUMP) return 0U;
  if (result.kind <= STAGE_B_BRANCH)
    return result.target_rva != 0U && result.value == 0U;
  if (result.kind == STAGE_B_RETURN)
    return result.target_rva == 0U;
  if (result.kind == STAGE_B_INDIRECT_JUMP)
    return result.target_rva == 0U && result.value != 0U;
  if (result.kind == STAGE_B_UNIMPLEMENTED)
    return result.value == 0U;
  return result.target_rva == 0U && result.value == 0U;
}

const stage_b_program_transfer *stage_b_program_lookup(uint32_t source_rva) {
  uint32_t low=0U,high=stage_b_program_transfer_count;
  while(low<high){uint32_t mid=low+(high-low)/2U;uint32_t r=stage_b_program_transfers[mid].source_rva;
    if(r<source_rva)low=mid+1U;else high=mid;}
  return low<stage_b_program_transfer_count&&stage_b_program_transfers[low].source_rva==source_rva
      ? &stage_b_program_transfers[low] : 0;
}

stage_b_step_result stage_b_interpreter_step(
    stage_b_runtime *rt, stage_b_machine_state *state, uint32_t source_rva) {
  const stage_b_region_override *override;
  const stage_b_program_transfer *t;
  stage_b_machine_state input,call_output;
  uint32_t words[STAGE_B_MAX_WORD_NODES],memory_fault=0U,semantic_fault=0U,i;
  if(!state)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
  override=stage_b_region_override_lookup(source_rva);
  if(override){
    stage_b_machine_state overridden=*state;
    stage_b_step_result result;
    if(override->entry_rva!=source_rva||!override->function)
      return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    result=override->function(rt,&overridden);
    if(!stage_b_region_override_result_valid(result))
      return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    if(result.kind==STAGE_B_UNIMPLEMENTED&&override->fallback_on_unimplemented){
      if(result.target_rva!=source_rva||result.value!=0U)
        return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    }else{
      *state=overridden;
      return result;
    }
  }
  t=stage_b_program_lookup(source_rva);
  if(!t||t->word_count>STAGE_B_MAX_WORD_NODES||t->x87_count!=0U)
    return (stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
  input=*state;call_output=input;state->original_rva=source_rva;
  for(i=0U;i<t->action_count;++i){
    const stage_b_program_action *a=&t->actions[i];
    if(a->op==0U){const stage_b_word_node*n=&t->nodes[a->args[0]];words[a->args[0]]=stage_b_eval_word(rt,&input,state,&call_output,words,n,&memory_fault,&semantic_fault);}
    else if(a->op==1U)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    else if(a->op==2U)stage_b_write(rt,words[a->args[0]],a->aux,words[a->args[1]],&memory_fault);
    else if(a->op==3U&&words[a->args[0]])return(stage_b_step_result){STAGE_B_DIVIDE_ERROR,0U,0U};
    else if(a->op==4U){
      const stage_b_program_call*c=&t->calls[a->args[0]];stage_b_machine_state ci=*state;stage_b_call_event e;stage_b_stack_input si[64];uint32_t av[64],j;
      if(c->argument_count>64U||c->stack_input_count>64U)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,0U,0U};
      for(j=0U;j<8U;++j)stage_b_set_reg(&ci,j,words[c->register_nodes[j]]);
      for(j=0U;j<6U;++j)stage_b_set_flag(&ci,j,words[c->flag_nodes[j]]);
      for(j=0U;j<c->argument_count;++j)av[j]=words[c->argument_nodes[j]];
      for(j=0U;j<c->stack_input_count;++j){si[j].offset=c->stack_inputs[j].offset;si[j].width=c->stack_inputs[j].width;si[j].value=words[c->stack_inputs[j].value_node];}
      e.kind=(stage_b_call_event_kind)c->kind;e.instruction_rva=c->instruction_rva;e.call_index=c->call_index;
      e.target_rva=c->kind==2U?words[c->target_node]:c->target_rva;e.return_rva=c->return_rva;e.dll=c->dll;e.symbol=c->symbol;
      e.ordinal=c->ordinal;e.has_ordinal=c->has_ordinal;e.arguments=av;e.argument_count=c->argument_count;e.stack_inputs=si;e.stack_input_count=c->stack_input_count;
      call_output=ci;{stage_b_call_status s=stage_b_invoke_call(rt,&e,&ci,&call_output);if(s!=STAGE_B_CALL_OK){*state=call_output;return(stage_b_step_result){s==STAGE_B_CALL_DIVIDE_ERROR?STAGE_B_DIVIDE_ERROR:s==STAGE_B_CALL_MEMORY_FAULT?STAGE_B_MEMORY_FAULT:s==STAGE_B_CALL_EXTERNAL_FAULT?STAGE_B_EXTERNAL_FAULT:STAGE_B_UNIMPLEMENTED,call_output.original_rva,0U};}}*state=call_output;
    } else if(a->op==5U){
      uint32_t s=words[a->args[0]],d=words[a->args[1]],n=words[a->args[2]],step=words[a->args[3]]?0xfffffffcU:4U;
      stage_b_set_reg(state,4U,s);stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      while(n!=0U){uint32_t v=stage_b_read(rt,s,4U,&memory_fault);if(memory_fault)break;stage_b_write(rt,d,4U,v,&memory_fault);if(memory_fault)break;s+=step;d+=step;--n;stage_b_set_reg(state,4U,s);stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);}}
    else if(a->op==6U)stage_b_set_reg(state,a->aux,words[a->args[0]]);
    else if(a->op==7U)stage_b_set_flag(state,a->aux,words[a->args[0]]);
    else if(a->op>=8U&&a->op<=17U)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    else if(a->op==18U)stage_b_sync_eflags(state);
    else if(a->op==19U)return(stage_b_step_result){STAGE_B_FALLTHROUGH,a->args[0],0U};
    else if(a->op==20U)return(stage_b_step_result){STAGE_B_JUMP,a->args[0],0U};
    else if(a->op==21U)return(stage_b_step_result){STAGE_B_BRANCH,words[a->args[0]]?a->args[1]:a->args[2],0U};
    else if(a->op==22U)return(stage_b_step_result){STAGE_B_RETURN,0U,words[a->args[0]]};
    else if(a->op==23U)return(stage_b_step_result){STAGE_B_INDIRECT_JUMP,0U,words[a->args[0]]};
    else if(a->op==24U)return(stage_b_step_result){STAGE_B_EXTERNAL_JUMP,0U,0U};
    else if(a->op==25U){
      const stage_b_typed_x87_operation*p;stage_b_machine_state operation_output;stage_b_call_status s;
      if(a->arity!=1U||a->args[0]>=t->x87_operation_count||!rt||!rt->execute_typed_x87_operation)
        return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
      p=&t->x87_operations[a->args[0]];
      if(p->rva_end<=p->rva_start||p->source_size!=p->rva_end-p->rva_start||
          !p->operation_identity||!p->contract_sha256||
          !p->checked_decoder||!p->checked_executor)
        return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
      operation_output=*state;s=rt->execute_typed_x87_operation(rt,p,state,&operation_output);
      if(s!=STAGE_B_CALL_OK)return(stage_b_step_result){s==STAGE_B_CALL_DIVIDE_ERROR?STAGE_B_DIVIDE_ERROR:s==STAGE_B_CALL_MEMORY_FAULT?STAGE_B_MEMORY_FAULT:s==STAGE_B_CALL_EXTERNAL_FAULT?STAGE_B_EXTERNAL_FAULT:STAGE_B_UNIMPLEMENTED,source_rva,0U};
      *state=operation_output;
    } else if(a->op==26U){
      uint32_t d=words[a->args[0]],v=words[a->args[1]];
      uint32_t n=words[a->args[2]],step=words[a->args[3]]?0xfffffffcU:4U;
      stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      while(n!=0U){
        stage_b_write(rt,d,4U,v,&memory_fault);
        if(memory_fault)break;
        d+=step;
        --n;
        stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      }
    } else if(a->op==27U){
      uint32_t s=words[a->args[0]],d=words[a->args[1]],n=words[a->args[2]],w=a->aux;
      uint32_t step=words[a->args[3]]?0U-w:w;
      if(w!=1U&&w!=2U&&w!=4U)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
      stage_b_set_reg(state,4U,s);stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      while(n!=0U){
        uint32_t v=stage_b_read(rt,s,w,&memory_fault);
        if(memory_fault)break;
        stage_b_write(rt,d,w,v,&memory_fault);
        if(memory_fault)break;
        s+=step;d+=step;--n;
        stage_b_set_reg(state,4U,s);stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      }
    } else if(a->op==28U){
      uint32_t d=words[a->args[0]],v=words[a->args[1]],n=words[a->args[2]],w=a->aux;
      uint32_t step=words[a->args[3]]?0U-w:w;
      if(w!=1U&&w!=2U&&w!=4U)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
      stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      while(n!=0U){
        stage_b_write(rt,d,w,v,&memory_fault);
        if(memory_fault)break;
        d+=step;--n;
        stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      }
    } else if(a->op==29U){
      uint32_t d,al,n,step;
      if(a->arity!=4U||a->aux!=1U)
        return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
      al=words[a->args[0]]&0xffU;d=words[a->args[1]];
      n=words[a->args[2]];step=words[a->args[3]]?0xffffffffU:1U;
      stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
      while(n!=0U){
        uint32_t m=stage_b_read(rt,d,1U,&memory_fault)&0xffU,result;
        if(memory_fault)break;
        result=(al-m)&0xffU;d+=step;--n;
        stage_b_set_reg(state,5U,d);stage_b_set_reg(state,2U,n);
        stage_b_set_flag(state,0U,al<m);
        stage_b_set_flag(state,1U,result==0U);
        stage_b_set_flag(state,2U,(result>>7)&1U);
        stage_b_set_flag(state,3U,((al^m)&(al^result)&0x80U)!=0U);
        stage_b_set_flag(state,4U,stage_b_parity(result));
        stage_b_set_flag(state,6U,((al^m^result)>>4)&1U);
        stage_b_sync_eflags(state);
        if(result==0U)break;
      }
    } else return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
    if(memory_fault)return(stage_b_step_result){STAGE_B_MEMORY_FAULT,source_rva,0U};
    if(semantic_fault)return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
  }
  return(stage_b_step_result){STAGE_B_UNIMPLEMENTED,source_rva,0U};
}

static stage_b_call_status stage_b_run_function_checked(
    stage_b_runtime *rt, uint32_t rva, const stage_b_machine_state *in,
    stage_b_machine_state *out, uint32_t expected_return_rva,
    uint32_t check_return_rva) {
  stage_b_machine_state s;
  if (!in || !out) return STAGE_B_CALL_UNIMPLEMENTED;
  s = *in;
  for (;;) {
    stage_b_step_result r = stage_b_interpreter_step(rt, &s, rva);
    if (r.kind <= STAGE_B_BRANCH) {
      rva = r.target_rva;
      continue;
    }
    if (r.kind == STAGE_B_INDIRECT_JUMP) {
      uint32_t next_rva;
      if (!rt || !rt->resolve_code_target ||
          rt->resolve_code_target(rt, r.value, &next_rva)) {
        stage_b_call_status external_status = STAGE_B_CALL_UNIMPLEMENTED;
        stage_b_machine_state external_output = s;
        if (rt && rt->invoke_callable_external_jump) {
          external_status = rt->invoke_callable_external_jump(
              rt, rva, r.value, &s, &external_output);
          if (external_status == STAGE_B_CALL_OK) {
            *out = external_output;
            return STAGE_B_CALL_OK;
          }
        }
        *out = s;
        out->original_rva = rva;
        return external_status;
      }
      rva = next_rva;
      continue;
    }
    *out = s;
    out->original_rva = r.target_rva != 0U ? r.target_rva : rva;
    if (r.kind == STAGE_B_RETURN) {
      if (check_return_rva && r.value != expected_return_rva) {
        /* Failure-only payload consumed by the candidate diagnostic trap. */
        out->esi = expected_return_rva;
        out->edi = r.value;
        return STAGE_B_CALL_UNIMPLEMENTED;
      }
      return STAGE_B_CALL_OK;
    }
    if (r.kind == STAGE_B_EXTERNAL_JUMP) return STAGE_B_CALL_OK;
    if (r.kind == STAGE_B_DIVIDE_ERROR) return STAGE_B_CALL_DIVIDE_ERROR;
    if (r.kind == STAGE_B_MEMORY_FAULT) return STAGE_B_CALL_MEMORY_FAULT;
    if (r.kind == STAGE_B_EXTERNAL_FAULT) return STAGE_B_CALL_EXTERNAL_FAULT;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }
}

stage_b_call_status stage_b_run_function(
    stage_b_runtime *rt, uint32_t rva, const stage_b_machine_state *in,
    stage_b_machine_state *out) {
  return stage_b_run_function_checked(rt, rva, in, out, 0U, 0U);
}

static stage_b_call_status stage_b_invoke_internal_call(
    stage_b_runtime *rt, const stage_b_call_event *event, uint32_t target_rva,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  stage_b_machine_state call_input;
  stage_b_call_status status;
  uint32_t memory_fault = 0U;
  if (!rt || !event || !input || !output || input->esp < 4U)
    return STAGE_B_CALL_UNIMPLEMENTED;
  call_input = *input;
  call_input.esp -= 4U;
  stage_b_write(
      rt, call_input.esp, 4U, event->return_rva, &memory_fault);
  if (memory_fault) {
    *output = call_input;
    output->original_rva = event->instruction_rva;
    return STAGE_B_CALL_MEMORY_FAULT;
  }
  status = stage_b_run_function_checked(
      rt, target_rva, &call_input, output, event->return_rva, 1U);
#ifdef STAGE_B_NATIVE_DIAGNOSTIC_FAILURE_TRAP
  if (status == STAGE_B_CALL_OK && output->esp < input->esp) {
    output->esi = input->esp;
    output->edi = output->esp;
    return STAGE_B_CALL_UNIMPLEMENTED;
  }
#endif
  return status;
}

stage_b_call_status stage_b_invoke_call(
    stage_b_runtime *rt, const stage_b_call_event *event,
    const stage_b_machine_state *input, stage_b_machine_state *output) {
  uint32_t target_rva;
  if (!event) return STAGE_B_CALL_UNIMPLEMENTED;
  if (event->kind == STAGE_B_CALL_INTERNAL_DIRECT)
    return stage_b_invoke_internal_call(
        rt, event, event->target_rva, input, output);
  if (event->kind == STAGE_B_CALL_INDIRECT && rt && rt->resolve_code_target &&
      !rt->resolve_code_target(rt, event->target_rva, &target_rva))
    return stage_b_invoke_internal_call(
        rt, event, target_rva, input, output);
  return stage_b_dispatch_external_call(rt, event, input, output);
}
'''


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise StageBInterpreterError(f"cannot read state machine {path}") from exc
    result: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            result.append(_object(json.loads(line), f"state machine line {number}"))
        except json.JSONDecodeError as exc:
            raise StageBInterpreterError(f"invalid state machine line {number}: {exc}") from exc
    if not result:
        raise StageBInterpreterError("state machine is empty")
    return result


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StageBInterpreterError(f"{field} must be an object")
    return value


def _list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageBInterpreterError(f"{field} must be a list")
    return value


def _optional_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageBInterpreterError(f"{field} must be a non-empty string")
    return value


def _sha256(value: Any, field: str) -> str:
    text = _string(value, field)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise StageBInterpreterError(f"{field} must be a lowercase SHA-256")
    return text


def _hex_bytes(value: Any, field: str) -> bytes:
    text = _string(value, field)
    if len(text) % 2 or text != text.lower() or any(
        char not in "0123456789abcdef" for char in text
    ):
        raise StageBInterpreterError(f"{field} must be lowercase even-length hex")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise StageBInterpreterError(f"{field} must be lowercase even-length hex") from exc


def _x87_singleton_candidate(
    instruction_bytes: bytes, instruction: Mapping[str, Any]
) -> bool:
    """Classify only; the configured checked singleton decoder remains authoritative."""

    mnemonic = instruction.get("mnemonic")
    if not isinstance(mnemonic, str):
        return False
    mnemonic = mnemonic.lower()
    if mnemonic == "wait":
        return instruction_bytes == b"\x9b"
    if not mnemonic.startswith("f"):
        return False
    return any(0xD8 <= byte <= 0xDF for byte in instruction_bytes[:4])


def _rva_list(values: Iterable[int]) -> str:
    return "[" + ", ".join(f"0x{value:x}" for value in values) + "]"


def _u32(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise StageBInterpreterError(f"{field} must be a uint32")
    return value


def _u32_wrapping(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StageBInterpreterError(f"{field} must be an integer")
    return value & 0xFFFFFFFF


def _nonnegative(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StageBInterpreterError(f"{field} must be nonnegative")
    return value


def _width(value: Any) -> int:
    result = _nonnegative(value, "memory width")
    if result not in {1, 2, 4}:
        raise StageBInterpreterError(f"unsupported memory width {result}")
    return result


def _width_bits(value: Any) -> int:
    result = _nonnegative(value, "bit width")
    if result not in {8, 16, 32}:
        raise StageBInterpreterError(f"unsupported bit width {result}")
    return result


def _x87_slot(value: Any) -> int:
    result = _nonnegative(value, "x87 slot")
    if result >= 8:
        raise StageBInterpreterError("x87 slot must be below 8")
    return result


def _arity_ok(actual: int, expected: int | tuple[int, int]) -> bool:
    return actual == expected if isinstance(expected, int) else expected[0] <= actual <= expected[1]


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _memory_dependency_keys(value: Any) -> frozenset[str]:
    """Return the canonical load observations needed by an expression."""

    if isinstance(value, Mapping):
        if value.get("op") == "load":
            # A completed outer load remains its own observation even when an
            # address-producing load is observed again later.
            return frozenset((_canonical(value),))
        dependencies: set[str] = set()
        for child in value.values():
            dependencies.update(_memory_dependency_keys(child))
        return frozenset(dependencies)
    if isinstance(value, list):
        dependencies = set()
        for child in value:
            dependencies.update(_memory_dependency_keys(child))
        return frozenset(dependencies)
    return frozenset()


def _json_sha256(value: Mapping[str, Any]) -> str:
    return sha256_bytes(_canonical(value).encode("ascii"))


def _stable_slot(value: str) -> int:
    result = 2166136261
    for byte in value.encode("utf-8"):
        result = ((result ^ byte) * 16777619) & 0xFFFFFFFF
    return result


def _c_string(value: str | None) -> str:
    if value is None:
        return "0"
    return json.dumps(value, ensure_ascii=True)


__all__ = [
    "STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT",
    "STAGE_B_INTERPRETER_PACKAGE_FORMAT",
    "STAGE_B_INTERPRETER_PROGRAM_FORMAT",
    "StageBInterpreterError",
    "compile_stage_b_interpreter_program",
    "write_stage_b_interpreter_package",
]
