"""Typed x87 rendering, qualification, and exact helper utilities."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT
from ..pe32.stage_binary import StageAInputError
from ..util import sha256_bytes
from .engine_model import (
    PE32_BASE_RELOCATION_EVIDENCE_FORMAT,
    NativeX87Operation,
    _HEX_BYTES,
    _PEBaseRelocation,
    _PEBaseRelocationEvidence,
    _SHA256,
    _STATE_OFFSETS,
    _X87ReplayASLRUnsafe,
    _X87_CHECKED_DECODER,
    _X87_CHECKED_EXECUTOR,
    _X87_PHYSICAL_FIELDS,
    _X87_REPLAY_FORMAT,
    _X87_REPLAY_MODEL,
    _X87_VALUE_EMPTY_OFFSET,
    _X87_VALUE_SIZE,
    _X87_VALUE_TAG_OFFSET,
)
from .x87 import (
    X87_MEMORY_NO_SIZE_MNEMONICS as _X87_MEMORY_NO_SIZE_MNEMONICS,
    X87_MEMORY_SIZE_KEYWORDS as _X87_MEMORY_SIZE_KEYWORDS,
    extract_typed_x87_operation,
    typed_x87_operation_from_micro_op,
)


def _render_typed_x87_instruction(operation: NativeX87Operation) -> str:
    typed = operation.operation
    operand = typed.operand
    if operand.kind == "none":
        return typed.mnemonic
    if operand.kind == "ax":
        return f"{typed.mnemonic} ax"
    if operand.kind == "stack":
        registers = operand.registers
        # GNU as Intel syntax encodes ST(0) implicitly for FXCH.  Capstone's
        # typed operand inventory can still spell out both architectural
        # operands, so normalize that complete form before rendering.
        if typed.mnemonic == "fxch" and len(registers) == 2:
            if registers[0] != 0:
                raise StageAInputError("typed fxch first operand must be st(0)")
            registers = registers[1:]
        rendered = ", ".join(f"st({index})" for index in registers)
        return f"{typed.mnemonic} {rendered}"
    if operand.kind != "memory":
        raise StageAInputError(f"unsupported typed x87 operand kind {operand.kind!r}")
    terms: list[str] = []
    if operand.image_rva is not None:
        if (
            operation.target_rva != operand.image_rva
            or not (
                (
                    operation.relocation_type == 3
                    and operation.relocation_width == 4
                )
                or operation.fixed_image_base == operation.image_base
            )
        ):
            raise StageAInputError(
                "absolute typed x87 operand lacks a checked image-address binding"
            )
        terms.append(f"___ImageBase + 0x{operand.image_rva:08x}")
    if operand.base is not None:
        terms.append(operand.base)
    if operand.index is not None:
        terms.append(
            operand.index
            if operand.scale == 1
            else f"{operand.index} * {operand.scale}"
        )
    if not terms:
        raise StageAInputError("typed x87 memory operand has no address source")
    address = " + ".join(terms)
    if operand.displacement > 0:
        address += f" + 0x{operand.displacement:x}"
    elif operand.displacement < 0:
        address += f" - 0x{-operand.displacement:x}"
    size = (
        ""
        if typed.mnemonic in _X87_MEMORY_NO_SIZE_MNEMONICS
        else _X87_MEMORY_SIZE_KEYWORDS.get(operand.width)
    )
    if size is None:
        raise StageAInputError(
            f"typed x87 memory width {operand.width} has no reviewed rendering"
        )
    prefix = f"{size} " if size else ""
    return f"{typed.mnemonic} {prefix}[{address}]"


def _restore_pushes(state_register: str) -> list[str]:
    """Build a PUSHAD/POPAD-compatible restore record below logical ESP."""

    return [
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['eflags']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['eax']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['ecx']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['edx']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['ebx']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['esp']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['ebp']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['esi']}]",
        f"    push DWORD PTR [{state_register} + {_STATE_OFFSETS['edi']}]",
    ]


def _capture_pushad_registers(output_register: str) -> list[str]:
    """Capture the PUSHFD/PUSHAD record without losing its logical ESP."""

    return _capture_pushad_registers_from("esp", output_register)


def _capture_pushad_registers_from(
    stack_register: str, output_register: str
) -> list[str]:
    """Capture a PUSHFD/PUSHAD record addressed by ``stack_register``."""

    stack_offsets = {
        "edi": 0,
        "esi": 4,
        "ebp": 8,
        "ebx": 16,
        "edx": 20,
        "ecx": 24,
        "eax": 28,
    }
    lines: list[str] = []
    for field, stack_offset in stack_offsets.items():
        lines.extend([
            f"    mov ecx, DWORD PTR [{stack_register} + {stack_offset}]",
            f"    mov DWORD PTR [{output_register} + {_STATE_OFFSETS[field]}], ecx",
        ])
    lines.append(f"    lea ecx, [{stack_register} + 36]")
    return lines


def _absolute_iat_va(raw: bytes, mnemonic: str) -> int | None:
    """Return the absolute IAT cell encoded by ``call/jmp [imm32]``."""

    expected = b"\xff\x15" if mnemonic == "call" else b"\xff\x25"
    if mnemonic not in {"call", "jmp"} or len(raw) != 6 or raw[:2] != expected:
        return None
    return int.from_bytes(raw[2:], "little")


def _indirect_call_encoding(raw: bytes) -> bool:
    """Accept exact unprefixed 32-bit FF /2 indirect CALL encodings."""

    if len(raw) < 2 or raw[0] != 0xFF or ((raw[1] >> 3) & 7) != 2:
        return False
    mod = raw[1] >> 6
    rm = raw[1] & 7
    if mod == 3:
        return len(raw) == 2
    if rm == 4:
        if len(raw) < 3:
            return False
    absolute_sib = rm == 4 and mod == 0 and (raw[2] & 7) == 5
    displacement_size = (
        4 if (mod == 0 and rm == 5) or absolute_sib or mod == 2
        else 1 if mod == 1
        else 0
    )
    expected_size = 2 + (1 if rm == 4 else 0) + displacement_size
    return len(raw) == expected_size


def _uses_x87_state(row: Mapping[str, Any]) -> bool:
    if row.get("fpu_state") is not None:
        return True

    def walk(value: Any) -> bool:
        if isinstance(value, Mapping):
            operation = value.get("op")
            if isinstance(operation, str) and operation.startswith(("fpu_", "x87_")):
                return True
            return any(walk(item) for item in value.values())
        if isinstance(value, list):
            return any(walk(item) for item in value)
        return False

    return walk(row)


def _qualified_machine_ir_x87_operations(
    *,
    row: Mapping[str, Any],
    transfer_id: str,
    first_id: int,
    relocation_evidence: _PEBaseRelocationEvidence | None,
    fixed_image_base: int | None,
) -> tuple[NativeX87Operation, ...]:
    fpu = row.get("fpu_state")
    micro_ops = row.get("_machine_ir_x87_micro_ops")
    if not isinstance(fpu, Mapping) or not isinstance(micro_ops, list) or not micro_ops:
        raise StageAInputError("machine-IR x87 state lacks typed micro-operations")
    replay = fpu.get("typed_replay")
    original = row.get("original")
    instructions = row.get("instructions")
    if (
        not isinstance(replay, Mapping)
        or not isinstance(original, Mapping)
        or not isinstance(instructions, list)
    ):
        raise StageAInputError("machine-IR x87 typed replay binding is malformed")
    rva_start = _required_u32(original.get("rva_start"), "machine-IR x87 start RVA")
    rva_end = _required_u32(original.get("rva_end"), "machine-IR x87 end RVA")
    image_base = _required_u32(replay.get("image_base"), "machine-IR x87 image base")
    transfer_digest = _required_sha256(
        row.get("instruction_bytes_sha256"), "machine-IR x87 transfer SHA-256"
    )
    if (
        replay.get("source_format") != _X87_REPLAY_FORMAT
        or replay.get("architecture") != "x86"
        or replay.get("bitness") != 32
        or replay.get("rva_start") != rva_start
        or replay.get("rva_end") != rva_end
        or replay.get("instruction_bytes_sha256") != transfer_digest
        or replay.get("checked_decoder") != _X87_CHECKED_DECODER
        or replay.get("checked_executor") != _X87_CHECKED_EXECUTOR
    ):
        raise StageAInputError("machine-IR x87 typed replay metadata is unqualified")
    micro_ids = replay.get("micro_op_ids")
    if (
        not isinstance(micro_ids, list)
        or len(micro_ids) != len(micro_ops)
        or len(set(str(item) for item in micro_ids)) != len(micro_ids)
    ):
        raise StageAInputError("machine-IR x87 micro-op inventory is malformed")
    instruction_by_rva = _instruction_inventory(transfer_id, instructions)
    contract_digest = _required_sha256(
        row.get("contract_sha256"), "machine-IR x87 contract SHA-256"
    )
    result: list[NativeX87Operation] = []
    seen_spans: set[tuple[int, int]] = set()
    for index, raw in enumerate(micro_ops):
        if not isinstance(raw, Mapping):
            raise StageAInputError(f"machine-IR x87 micro-op {index} is malformed")
        micro_id = _required_string(raw.get("id"), f"machine-IR x87 micro-op {index} id")
        start = _required_u32(
            raw.get("rva_start"), f"machine-IR x87 micro-op {index} start RVA"
        )
        end = _required_u32(
            raw.get("rva_end"), f"machine-IR x87 micro-op {index} end RVA"
        )
        size = raw.get("size")
        instruction = instruction_by_rva.get(start)
        if (
            micro_ids[index] != micro_id
            or raw.get("unit_id") != transfer_id
            or end <= start
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size != end - start
            or (start, end) in seen_spans
            or instruction is None
            or instruction.get("rva_end") != end
            or raw.get("instruction_sha256")
            != instruction.get("instruction_sha256")
            or raw.get("transfer_instruction_sha256") != transfer_digest
            or raw.get("mnemonic") != instruction.get("mnemonic")
            or raw.get("operands") != instruction.get("operands")
            or raw.get("implicit_registers_read")
            != instruction.get("registers_read")
            or raw.get("implicit_registers_written")
            != instruction.get("registers_written")
            or raw.get("checked_decoder") != _X87_CHECKED_DECODER
            or raw.get("checked_executor") != _X87_CHECKED_EXECUTOR
            or raw.get("physical_state_effect")
            != "defined_by_checked_typed_x87_executor"
        ):
            raise StageAInputError(
                f"machine-IR x87 micro-op {index} does not bind its typed instruction"
            )
        seen_spans.add((start, end))
        typed = typed_x87_operation_from_micro_op(raw, image_base=image_base)
        relocation: _PEBaseRelocation | None = None
        fixed_binding: int | None = None
        if typed.operand.image_rva is not None:
            preferred_value = image_base + typed.operand.image_rva
            matches = (
                [
                    item
                    for item in relocation_evidence.relocations
                    if start <= item.source_rva
                    and item.source_rva + item.width <= end
                    and item.preferred_value == preferred_value
                ]
                if relocation_evidence is not None
                else []
            )
            if len(matches) == 0 and fixed_image_base == image_base:
                fixed_binding = image_base
            elif len(matches) != 1:
                raise _X87ReplayASLRUnsafe(
                    "absolute typed x87 operand lacks one span-bound PE relocation"
                )
            else:
                relocation = matches[0]
                if (
                    relocation_evidence is None
                    or relocation_evidence.image_base != image_base
                    or relocation.type != 3
                    or relocation.width != 4
                ):
                    raise _X87ReplayASLRUnsafe(
                        "typed x87 absolute operand is not bound by PE32 HIGHLOW evidence"
                    )
        elif relocation_evidence is not None and any(
            item.source_rva < end and item.source_rva + item.width > start
            for item in relocation_evidence.relocations
        ):
            raise _X87ReplayASLRUnsafe(
                "position-independent typed x87 form overlaps relocation evidence"
            )
        result.append(NativeX87Operation(
            id=first_id + len(result),
            transfer_id=transfer_id,
            contract_sha256=contract_digest,
            image_base=image_base,
            rva_start=start,
            rva_end=end,
            operation=typed,
            relocation_source_rva=(
                relocation.source_rva if relocation is not None else None
            ),
            preferred_value=(
                relocation.preferred_value if relocation is not None else None
            ),
            target_rva=(
                relocation.preferred_value - image_base
                if relocation is not None else None
            ) if fixed_binding is None else typed.operand.image_rva,
            relocation_type=relocation.type if relocation is not None else None,
            relocation_width=relocation.width if relocation is not None else None,
            relocation_pe_sha256=(
                relocation_evidence.pe_sha256
                if relocation is not None and relocation_evidence is not None else None
            ),
            relocation_static_program_contract_sha256=(
                relocation_evidence.static_program_contract_sha256
                if relocation is not None and relocation_evidence is not None else None
            ),
            fixed_image_base=fixed_binding,
        ))
    return tuple(result)


def _qualified_x87_operations(
    *,
    row: Mapping[str, Any],
    transfer_id: str,
    first_id: int,
    relocation_evidence: _PEBaseRelocationEvidence | None,
    fixed_image_base: int | None,
) -> tuple[NativeX87Operation, ...]:
    fpu = row.get("fpu_state")
    if not isinstance(fpu, Mapping) or fpu.get("model") != _X87_REPLAY_MODEL:
        raise StageAInputError("x87 state is not an exact native replay obligation")
    if fpu.get("status") != "required":
        raise StageAInputError("x87 replay obligation status must be required")
    if fpu.get("authoritative_state_type") != "StageA.X87.PhysicalState":
        raise StageAInputError("x87 replay does not bind StageA.X87.PhysicalState")
    if fpu.get("required_fields") != list(_X87_PHYSICAL_FIELDS):
        raise StageAInputError("x87 replay physical-field inventory changed")
    missing = fpu.get("missing_or_invalid_fields")
    if (
        not isinstance(missing, list)
        or not missing
        or any(item not in _X87_PHYSICAL_FIELDS for item in missing)
        or len(set(item for item in missing if isinstance(item, str))) != len(missing)
    ):
        raise StageAInputError("x87 replay missing-field inventory is malformed")
    unexpected = [
        field for field in _X87_PHYSICAL_FIELDS
        if field != "status" and field in fpu
    ]
    if unexpected:
        raise StageAInputError(
            "x87 replay contains unqualified physical fields: " + ", ".join(unexpected)
        )
    replay = fpu.get("replay")
    if not isinstance(replay, Mapping):
        raise StageAInputError("x87 replay binding must be an object")
    expected_literals = {
        "format": _X87_REPLAY_FORMAT,
        "checked_decoder": _X87_CHECKED_DECODER,
        "checked_executor": _X87_CHECKED_EXECUTOR,
        "architecture": "x86",
        "bitness": 32,
    }
    for field, expected in expected_literals.items():
        if replay.get(field) != expected:
            raise StageAInputError(f"x87 replay {field} must be {expected!r}")
    original = row.get("original")
    if not isinstance(original, Mapping):
        raise StageAInputError("x87 replay has no original span")
    rva_start = _required_u32(original.get("rva_start"), "x87 original start")
    rva_end = _required_u32(original.get("rva_end"), "x87 original end")
    if rva_end <= rva_start:
        raise StageAInputError("x87 replay span must be nonempty")
    if replay.get("rva_start") != rva_start or replay.get("rva_end") != rva_end:
        raise StageAInputError("x87 replay span differs from its transfer")
    raw_hex = replay.get("bytes")
    if not isinstance(raw_hex, str) or not _HEX_BYTES.fullmatch(raw_hex):
        raise StageAInputError("x87 replay bytes must be canonical hexadecimal")
    raw = bytes.fromhex(raw_hex)
    if len(raw) != rva_end - rva_start:
        raise StageAInputError("x87 replay bytes do not cover the transfer")
    transfer_digest = _required_sha256(
        row.get("instruction_bytes_sha256"), "x87 transfer instruction digest"
    )
    replay_digest = _required_sha256(
        replay.get("bytes_sha256"), "x87 replay instruction digest"
    )
    if sha256_bytes(raw) != replay_digest or replay_digest != transfer_digest:
        raise StageAInputError("x87 replay digest does not bind the transfer bytes")
    contract_digest = _required_sha256(
        row.get("contract_sha256"), "x87 transfer contract digest"
    )
    image_base = _required_u32(replay.get("image_base"), "x87 replay image base")
    outer_instructions = row.get("instructions")
    replay_instructions = replay.get("instructions")
    schedule = replay.get("instruction_effect_schedule")
    if (
        not isinstance(outer_instructions, list)
        or not isinstance(replay_instructions, list)
        or not replay_instructions
        or len(outer_instructions) != len(replay_instructions)
    ):
        raise StageAInputError("x87 replay instruction inventories differ")
    cursor = rva_start
    reconstructed = bytearray()
    result: list[NativeX87Operation] = []
    schedule_records: list[Any] | None = None
    if schedule is not None:
        if not isinstance(schedule, Mapping):
            raise StageAInputError("x87 instruction effect schedule must be an object")
        if (
            schedule.get("format")
            != INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT
            or schedule.get("status") != "complete"
            or schedule.get("proof_authority") is not False
            or schedule.get("transfer_bytes_sha256") != transfer_digest
            or schedule.get("blockers") != []
            or row.get("instruction_effect_schedule") != schedule
        ):
            raise StageAInputError("x87 instruction effect schedule is not qualified")
        _verify_embedded_sha256(schedule, "schedule_sha256", "x87 effect schedule")
        raw_records = schedule.get("records")
        if not isinstance(raw_records, list) or len(raw_records) != len(replay_instructions):
            raise StageAInputError("x87 instruction effect schedule coverage differs")
        schedule_records = raw_records
    for index, (outer, bound) in enumerate(
        zip(outer_instructions, replay_instructions, strict=True)
    ):
        if not isinstance(outer, Mapping) or not isinstance(bound, Mapping):
            raise StageAInputError(f"x87 replay instruction {index} is malformed")
        instruction_rva = _required_u32(bound.get("rva"), "x87 instruction RVA")
        size = bound.get("size")
        encoded_hex = bound.get("bytes")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or not isinstance(encoded_hex, str)
            or not _HEX_BYTES.fullmatch(encoded_hex)
        ):
            raise StageAInputError(f"x87 replay instruction {index} is malformed")
        encoded = bytes.fromhex(encoded_hex)
        if len(encoded) != size or instruction_rva != cursor:
            raise StageAInputError("x87 replay instructions are not exact and contiguous")
        if any(
            outer.get(field) != value
            for field, value in {
                "rva": instruction_rva,
                "size": size,
                "bytes": encoded_hex,
            }.items()
        ):
            raise StageAInputError("x87 replay outer instruction binding differs")
        is_x87 = _x87_singleton_candidate(encoded, outer)
        if schedule_records is None:
            if not is_x87:
                raise StageAInputError(
                    "mixed ordinary/x87 replay requires instruction-ordered lowering"
                )
        else:
            record = schedule_records[index]
            if not isinstance(record, Mapping):
                raise StageAInputError(f"x87 schedule record {index} is malformed")
            _verify_embedded_sha256(
                record, "record_sha256", f"x87 schedule record {index}"
            )
            if (
                record.get("index") != index
                or record.get("rva_start") != instruction_rva
                or record.get("rva_end") != instruction_rva + size
                or record.get("bytes") != encoded_hex
                or record.get("bytes_sha256") != sha256_bytes(encoded)
                or record.get("transfer_bytes_sha256") != transfer_digest
            ):
                raise StageAInputError(
                    f"x87 schedule record {index} differs from exact instruction bytes"
                )
            expected_class = (
                "x87_singleton_checked_replay"
                if is_x87 else "ordinary_symbolic_instruction"
            )
            if record.get("instruction_class") != expected_class:
                raise StageAInputError(
                    f"x87 schedule record {index} classification differs"
                )
            classification = record.get("classification")
            if (
                not isinstance(classification, Mapping)
                or classification.get("status")
                != "proposal_requires_lean_exact_byte_replay"
                or classification.get("proof_authority") is not False
            ):
                raise StageAInputError(
                    f"x87 schedule record {index} lacks checked classification"
                )
        if is_x87:
            typed = extract_typed_x87_operation(
                encoded=encoded,
                instruction=outer,
                image_base=image_base,
            )
            operand_offset = _x87_absolute_operand_offset(encoded)
            relocation: _PEBaseRelocation | None = None
            fixed_binding: int | None = None
            if operand_offset is not None:
                source_rva = instruction_rva + operand_offset
                matches = (
                    [
                        item
                        for item in relocation_evidence.relocations
                        if item.source_rva == source_rva
                    ]
                    if relocation_evidence is not None
                    else []
                )
                if len(matches) == 0 and fixed_image_base == image_base:
                    fixed_binding = image_base
                elif len(matches) != 1:
                    raise _X87ReplayASLRUnsafe(
                        "absolute x87 disp32 does not have exactly one bound PE relocation"
                    )
                raw_preferred = int.from_bytes(
                    encoded[operand_offset : operand_offset + 4], "little"
                )
                if raw_preferred < image_base:
                    raise _X87ReplayASLRUnsafe(
                        "x87 absolute preferred value is below the preferred image base"
                    )
                if fixed_binding is None:
                    relocation = matches[0]
                    if relocation_evidence is None or relocation_evidence.image_base != image_base:
                        raise _X87ReplayASLRUnsafe(
                            "x87 relocation evidence preferred image base differs from replay"
                        )
                    if relocation.type != 3 or relocation.width != 4:
                        raise _X87ReplayASLRUnsafe(
                            "x87 absolute operand relocation is not PE32 HIGHLOW width 4"
                        )
                    if source_rva < instruction_rva or source_rva + 4 > instruction_rva + size:
                        raise _X87ReplayASLRUnsafe(
                            "x87 relocation target span is outside its exact instruction"
                        )
                    if relocation.preferred_value != raw_preferred:
                        raise _X87ReplayASLRUnsafe(
                            "x87 relocation preferred value differs from exact operand bytes"
                        )
            elif not _x87_replay_relocation_safe(encoded):
                raise _X87ReplayASLRUnsafe(
                    "x87 singleton uses an absolute or unqualified addressing form "
                    "whose typed address has no PE HIGHLOW relocation"
                )
            elif relocation_evidence is not None and any(
                item.source_rva < instruction_rva + size
                and item.source_rva + item.width > instruction_rva
                for item in relocation_evidence.relocations
            ):
                raise _X87ReplayASLRUnsafe(
                    "position-independent x87 instruction overlaps unexpected relocation evidence"
                )
            if (
                typed.operand.image_rva is None
            ) != (relocation is None and fixed_binding is None):
                raise _X87ReplayASLRUnsafe(
                    "typed x87 absolute-address classification differs from relocation evidence"
                )
            result.append(NativeX87Operation(
                id=first_id + len(result),
                transfer_id=transfer_id,
                contract_sha256=contract_digest,
                image_base=image_base,
                rva_start=instruction_rva,
                rva_end=instruction_rva + size,
                operation=typed,
                relocation_source_rva=(
                    relocation.source_rva if relocation is not None else None
                ),
                preferred_value=(
                    relocation.preferred_value if relocation is not None else None
                ),
                target_rva=(
                    relocation.preferred_value - image_base
                    if relocation is not None
                    else None
                ) if fixed_binding is None else typed.operand.image_rva,
                relocation_type=relocation.type if relocation is not None else None,
                relocation_width=relocation.width if relocation is not None else None,
                relocation_pe_sha256=(
                    relocation_evidence.pe_sha256
                    if relocation is not None and relocation_evidence is not None
                    else None
                ),
                relocation_static_program_contract_sha256=(
                    relocation_evidence.static_program_contract_sha256
                    if relocation is not None and relocation_evidence is not None
                    else None
                ),
                fixed_image_base=fixed_binding,
            ))
        reconstructed.extend(encoded)
        cursor += size
    if cursor != rva_end or bytes(reconstructed) != raw:
        raise StageAInputError("x87 replay instructions do not reconstruct the span")
    if schedule_records is None:
        outcome = row.get("outcome")
        if (
            not isinstance(outcome, Mapping)
            or outcome.get("kind") != "fallthrough"
            or outcome.get("target_rva") != rva_end
        ):
            raise StageAInputError("x87 replay transfer is not an exact fallthrough")
    return tuple(result)


def _verify_embedded_sha256(
    payload: Mapping[str, Any], field: str, context: str
) -> None:
    expected = _required_sha256(payload.get(field), f"{context} SHA-256")
    body = dict(payload)
    del body[field]
    actual = sha256_bytes(
        json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )
    if actual != expected:
        raise StageAInputError(f"{context} SHA-256 mismatch")


def _x87_singleton_candidate(
    instruction_bytes: bytes, instruction: Mapping[str, Any]
) -> bool:
    mnemonic = instruction.get("mnemonic")
    if not isinstance(mnemonic, str):
        return False
    mnemonic = mnemonic.lower()
    if mnemonic == "wait":
        return instruction_bytes == b"\x9b"
    return mnemonic.startswith("f") and any(
        0xD8 <= byte <= 0xDF for byte in instruction_bytes[:4]
    )


def _x87_replay_relocation_safe(encoded: bytes) -> bool:
    """Accept only exact unprefixed x87 forms with no absolute disp32 operand."""

    if encoded == b"\x9b":
        return True
    if len(encoded) < 2 or not 0xD8 <= encoded[0] <= 0xDF:
        return False
    modrm = encoded[1]
    mod = modrm >> 6
    rm = modrm & 7
    if mod == 3:
        return len(encoded) == 2
    cursor = 2
    absolute = mod == 0 and rm == 5
    if rm == 4:
        if len(encoded) <= cursor:
            return False
        sib = encoded[cursor]
        cursor += 1
        absolute = absolute or (mod == 0 and (sib & 7) == 5)
    displacement_size = 1 if mod == 1 else 4 if mod == 2 or absolute else 0
    return not absolute and len(encoded) == cursor + displacement_size


def _x87_absolute_operand_offset(encoded: bytes) -> int | None:
    """Locate the sole unprefixed x87 absolute disp32 operand, if present."""

    if len(encoded) < 6 or not 0xD8 <= encoded[0] <= 0xDF:
        return None
    modrm = encoded[1]
    if modrm >> 6 != 0:
        return None
    rm = modrm & 7
    if rm == 5 and len(encoded) == 6:
        return 2
    if rm == 4 and len(encoded) == 7 and (encoded[2] & 7) == 5:
        return 3
    return None


def _parse_pe_base_relocation_evidence(
    value: Mapping[str, Any] | None,
) -> _PEBaseRelocationEvidence | None:
    if value is None:
        return None
    expected_fields = {
        "format", "complete", "pe_sha256", "static_program_contract_sha256",
        "image_base", "relocations"
    }
    if set(value) != expected_fields:
        raise StageAInputError(
            "PE base-relocation evidence fields do not match the v1 schema"
        )
    if value.get("format") != PE32_BASE_RELOCATION_EVIDENCE_FORMAT:
        raise StageAInputError("unsupported PE base-relocation evidence format")
    if value.get("complete") is not True:
        raise StageAInputError("PE base-relocation evidence must be complete")
    pe_sha256 = _required_sha256(
        value.get("pe_sha256"), "PE base-relocation evidence PE SHA-256"
    )
    static_program_contract_sha256 = _required_sha256(
        value.get("static_program_contract_sha256"),
        "PE base-relocation evidence static-program SHA-256",
    )
    image_base = _required_u32(
        value.get("image_base"), "PE base-relocation evidence image base"
    )
    raw_rows = value.get("relocations")
    if not isinstance(raw_rows, list):
        raise StageAInputError("PE base-relocation evidence relocations must be a list")
    rows: list[_PEBaseRelocation] = []
    seen_sources: set[int] = set()
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, Mapping) or set(raw) != {
            "source_rva", "type", "kind", "width", "preferred_value"
        }:
            raise StageAInputError(
                f"PE base relocation {index} fields do not match the v1 schema"
            )
        source_rva = _required_u32(
            raw.get("source_rva"), f"PE base relocation {index} source RVA"
        )
        relocation_type = _required_u32(
            raw.get("type"), f"PE base relocation {index} type"
        )
        width = _required_u32(
            raw.get("width"), f"PE base relocation {index} width"
        )
        if width == 0:
            raise StageAInputError(
                f"PE base relocation {index} width must be nonzero"
            )
        preferred_value = _required_u32(
            raw.get("preferred_value"),
            f"PE base relocation {index} preferred value",
        )
        kind = raw.get("kind")
        if (relocation_type == 3) != (kind == "highlow"):
            raise StageAInputError(
                f"PE base relocation {index} type/kind disagree"
            )
        if source_rva in seen_sources:
            raise StageAInputError("PE base-relocation evidence has duplicate sources")
        seen_sources.add(source_rva)
        rows.append(_PEBaseRelocation(
            source_rva=source_rva,
            type=relocation_type,
            width=width,
            preferred_value=preferred_value,
        ))
    rows.sort(key=lambda item: item.source_rva)
    for previous, current in zip(rows, rows[1:]):
        if current.source_rva < previous.source_rva + previous.width:
            raise StageAInputError("PE base-relocation evidence ranges overlap")
    return _PEBaseRelocationEvidence(
        pe_sha256=pe_sha256,
        static_program_contract_sha256=static_program_contract_sha256,
        image_base=image_base,
        relocations=tuple(rows),
    )


def _callback_spec(
    value: int | Mapping[str, Any], index: int
) -> tuple[int, str, int]:
    if not isinstance(value, Mapping):
        raise StageAInputError(
            f"callback {index} is only an RVA and has no checked ABI kind"
        )
    expected_fields = {"rva", "kind", "stack_cleanup_bytes"}
    if set(value) != expected_fields:
        raise StageAInputError(
            f"callback {index} must contain exactly {sorted(expected_fields)}"
        )
    rva = _required_u32(value.get("rva"), f"callback {index} RVA")
    kind = _required_string(value.get("kind"), f"callback {index} kind")
    cleanup = value.get("stack_cleanup_bytes")
    if (
        isinstance(cleanup, bool)
        or not isinstance(cleanup, int)
        or not 0 <= cleanup <= 0xFFFF
    ):
        raise StageAInputError(f"callback {index} cleanup must be a uint16")
    if kind == "tls_callback":
        if cleanup != 12:
            raise StageAInputError("PE32 TLS callbacks require stdcall cleanup of 12 bytes")
    elif kind != "generic_callback":
        raise StageAInputError(
            "callback kind must be tls_callback or generic_callback"
        )
    return rva, kind, cleanup


def _capture_split_flags(output_register: str) -> list[str]:
    return _capture_split_flags_from("esp", output_register, "ecx")


def _capture_x87_result_flags(output_register: str) -> list[str]:
    return _capture_split_flags_from(
        "esp",
        output_register,
        "ecx",
        fields=("cf", "pf", "zf"),
        flags_offset=4,
    )


def _capture_split_flags_from(
    stack_register: str,
    output_register: str,
    scratch_register: str,
    *,
    fields: tuple[str, ...] = ("cf", "pf", "zf", "sf", "df", "of"),
    flags_offset: int = 32,
) -> list[str]:
    bits = {"cf": 0, "pf": 2, "zf": 6, "sf": 7, "df": 10, "of": 11}
    lines: list[str] = []
    for field in fields:
        bit = bits[field]
        lines.extend([
            f"    mov {scratch_register}, DWORD PTR "
            f"[{stack_register} + {flags_offset}]",
            f"    shr {scratch_register}, {bit}",
            f"    and {scratch_register}, 1",
            f"    mov DWORD PTR [{output_register} + {_STATE_OFFSETS[field]}], "
            f"{scratch_register}",
        ])
    return lines


def _capture_fnsave_state(
    image_register: str,
    state_register: str,
    scratch_register: str,
    index_register: str,
) -> list[str]:
    """Unroll the reviewed FNSAVE-to-engine-state representation conversion."""

    register_parts = {
        "eax": ("ax", "al"),
        "ebx": ("bx", "bl"),
        "ecx": ("cx", "cl"),
        "edx": ("dx", "dl"),
    }
    try:
        scratch_word, scratch_byte = register_parts[scratch_register]
    except KeyError as exc:
        raise ValueError(
            f"unsupported FNSAVE conversion scratch register {scratch_register}"
        ) from exc
    if len({
        image_register, state_register, scratch_register, index_register
    }) != 4:
        raise ValueError("FNSAVE conversion registers must be distinct")
    if index_register != "ecx":
        raise ValueError("FNSAVE conversion index register must be ecx")

    lines = [
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 0]",
        f"    mov WORD PTR [{state_register} + {_STATE_OFFSETS['x87_control']}], "
        f"{scratch_word}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 4]",
        f"    mov WORD PTR [{state_register} + {_STATE_OFFSETS['x87_status']}], "
        f"{scratch_word}",
        f"    shr {scratch_register}, 7",
        f"    and {scratch_register}, 1",
        f"    mov BYTE PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_pending_exception']}], {scratch_byte}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 16]",
        f"    shr {scratch_register}, 16",
        f"    and {scratch_register}, 0x7ff",
        f"    mov WORD PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_last_opcode']}], {scratch_word}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 12]",
        f"    mov DWORD PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_instruction_pointer']}], {scratch_register}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 16]",
        f"    mov WORD PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_code_selector']}], {scratch_word}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 20]",
        f"    mov DWORD PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_data_pointer']}], {scratch_register}",
        f"    mov {scratch_register}, DWORD PTR [{image_register} + 24]",
        f"    mov WORD PTR [{state_register} + "
        f"{_STATE_OFFSETS['x87_data_selector']}], {scratch_word}",
    ]
    for index in range(8):
        state_value = _STATE_OFFSETS["x87_stack"] + _X87_VALUE_SIZE * index
        lines.extend([
            f"    mov {index_register}, DWORD PTR [{image_register} + 4]",
            f"    shr {index_register}, 11",
            f"    and {index_register}, 7",
            f"    add {index_register}, {index}",
            f"    and {index_register}, 7",
            f"    imul {index_register}, {index_register}, 10",
            f"    mov {scratch_register}, DWORD PTR "
            f"[{image_register} + {index_register} + 28]",
            f"    mov DWORD PTR [{state_register} + {state_value}], "
            f"{scratch_register}",
            f"    mov {scratch_register}, DWORD PTR "
            f"[{image_register} + {index_register} + 32]",
            f"    mov DWORD PTR [{state_register} + {state_value + 4}], "
            f"{scratch_register}",
            f"    movzx {scratch_register}, WORD PTR "
            f"[{image_register} + {index_register} + 36]",
            f"    mov WORD PTR [{state_register} + {state_value + 8}], "
            f"{scratch_word}",
            f"    mov {index_register}, DWORD PTR [{image_register} + 4]",
            f"    shr {index_register}, 11",
            f"    and {index_register}, 7",
            f"    add {index_register}, {index}",
            f"    and {index_register}, 7",
            f"    shl {index_register}, 1",
            f"    mov {scratch_register}, DWORD PTR [{image_register} + 8]",
            f"    shr {scratch_register}, cl",
            f"    and {scratch_register}, 3",
            f"    mov BYTE PTR [{state_register} + "
            f"{state_value + _X87_VALUE_TAG_OFFSET}], {scratch_byte}",
            f"    cmp {scratch_register}, 3",
            f"    sete {scratch_byte}",
            f"    movzx {scratch_register}, {scratch_byte}",
            f"    mov DWORD PTR [{state_register} + "
            f"{state_value + _X87_VALUE_EMPTY_OFFSET}], {scratch_register}",
        ])
    return lines


def _instruction_inventory(
    transfer_id: str, instructions: list[Any]
) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for index, instruction in enumerate(instructions):
        if not isinstance(instruction, dict):
            raise StageAInputError(f"{transfer_id} instruction {index} must be an object")
        rva = _required_u32(instruction.get("rva"), f"{transfer_id} instruction RVA")
        if rva in result:
            raise StageAInputError(f"{transfer_id} has duplicate instruction RVA {rva:#x}")
        result[rva] = instruction
    return result


def _read_jsonl_objects(path: Path, label: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise StageAInputError(f"cannot read {label}: {path}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(f"invalid {label} line {line_number}: {exc}") from exc
        if not isinstance(row, dict):
            raise StageAInputError(f"{label} line {line_number} must be an object")
        result.append(row)
    if not result:
        raise StageAInputError(f"{label} is empty")
    return result


def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{field} must be a non-empty string")
    return value


def _required_portable_identity(value: Any, field: str) -> str:
    text = _required_string(value, field)
    try:
        encoded = text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise StageAInputError(f"{field} must be printable ASCII") from exc
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise StageAInputError(f"{field} must be printable ASCII")
    return text


def _required_sha256(value: Any, field: str) -> str:
    text = _required_string(value, field)
    if _SHA256.fullmatch(text) is None:
        raise StageAInputError(f"{field} must be a lowercase SHA-256")
    return text


def _required_u32(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise StageAInputError(f"{field} must be a 32-bit unsigned integer")
    return value


def _blocker(category: str, **fields: Any) -> dict[str, Any]:
    return {"category": category, "severity": "hard", **fields}


def _frontier(category: str, **fields: Any) -> dict[str, Any]:
    return {"category": category, "severity": "diagnostic", **fields}
