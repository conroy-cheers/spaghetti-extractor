"""Semantic transfer compiler for the Stage B interpreter."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ..stage_binary import StageAInputError
from ..util import sha256_bytes
from .interpreter_model import (
    StageBInterpreterError,
    _AF_FLAG_INDEX,
    _Action,
    _Call,
    _FLAGS,
    _FLAG_INDEX,
    _INSTRUCTION_EFFECT_SCHEDULE_FORMAT,
    _Node,
    _ORDINARY_CHECKED_DECODER,
    _ORDINARY_CHECKED_EXECUTOR,
    _REGISTERS,
    _REGISTER_INDEX,
    _REP_SCAS_OWNED_FLAGS,
    _REP_SCAS_OWNED_REGISTERS,
    _Transfer,
    _TypedX87Program,
    _X87_CHECKED_DECODER,
    _X87_CHECKED_EXECUTOR,
    _X87_PHYSICAL_FIELDS,
    _X87_REPLAY_FORMAT,
    _X87_REPLAY_MODEL,
)
from .interpreter_values import (
    _arity_ok,
    _canonical,
    _hex_bytes,
    _json_sha256,
    _list,
    _memory_dependency_keys,
    _nonnegative,
    _object,
    _optional_list,
    _rva_list,
    _sha256,
    _stable_slot,
    _string,
    _typed_x87_program,
    _u32,
    _u32_wrapping,
    _width,
    _width_bits,
    _x87_singleton_candidate,
    _x87_slot,
)
from .x87 import typed_x87_operation_from_micro_op


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
    scheduled_word_evaluations: set[int] = field(default_factory=set)
    word_compile_depth: int = 0
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
                        code="malformed_machine_ir_instruction_schedule",
                    )
                self._append_machine_ir_x87_operation(micro)
                cursor = end
            if cursor != original_end:
                raise StageBInterpreterError(
                    f"{self.identity}: typed x87 micro-ops do not cover the unit",
                    code="malformed_machine_ir_instruction_schedule",
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
                code="malformed_machine_ir_instruction_schedule",
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
                code="malformed_machine_ir_instruction_schedule",
            )
        micro_by_rva: dict[int, Mapping[str, Any]] = {}
        for raw in micro_ops:
            micro = _object(raw, f"{self.identity} x87 micro-op")
            rva = _u32(micro.get("rva_start"), "x87 micro-op RVA")
            if rva in micro_by_rva:
                raise StageBInterpreterError(
                    f"{self.identity}: duplicate x87 micro-op RVA 0x{rva:x}",
                    code="malformed_machine_ir_instruction_schedule",
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
                    code="malformed_machine_ir_instruction_schedule",
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
                    code="malformed_machine_ir_instruction_schedule",
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
                        code="malformed_machine_ir_instruction_schedule",
                    )
            else:
                self._validate_scheduled_outcome(control_object)
            if instruction_class == "x87_singleton_checked_replay":
                micro = micro_by_rva.get(rva)
                if micro is None:
                    raise StageBInterpreterError(
                        f"{self.identity}: x87 schedule record has no typed micro-op",
                        code="malformed_machine_ir_instruction_schedule",
                    )
                if (
                    micro.get("rva_end") != rva_end
                    or classification.get("checked_decoder") != _X87_CHECKED_DECODER
                    or classification.get("checked_executor") != _X87_CHECKED_EXECUTOR
                ):
                    raise StageBInterpreterError(
                        f"{self.identity}: typed x87 schedule binding is invalid",
                        code="malformed_machine_ir_instruction_schedule",
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
                        code="malformed_machine_ir_instruction_schedule",
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
                    code="malformed_machine_ir_instruction_schedule",
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
                code="malformed_machine_ir_instruction_schedule",
            )
        if (
            cursor != original_end
            or counts.get("x87_singletons") != x87_count
            or counts.get("ordinary_instructions") != ordinary_count
        ):
            raise StageBInterpreterError(
                f"{self.identity}: machine-IR schedule coverage is inconsistent",
                code="malformed_machine_ir_instruction_schedule",
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
        top_level = self.word_compile_depth == 0
        self.word_compile_depth += 1
        try:
            index = self.memo.get(key)
            if index is None:
                op = _string(expr.get("op"), "expression op")
                node = self._word_node(op, expr)
                index = len(self.nodes)
                self.nodes.append(node)
                self.memo[key] = index
                self.memo_memory_dependencies[key] = _memory_dependency_keys(expr)
        finally:
            self.word_compile_depth -= 1
        if top_level and index not in self.scheduled_word_evaluations:
            self.actions.append(_Action("eval_word", (index,)))
            self.scheduled_word_evaluations.add(index)
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
        self.scheduled_word_evaluations.add(index)
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
