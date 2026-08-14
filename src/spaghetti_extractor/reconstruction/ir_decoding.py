"""Instruction decoding and semantic-control reconciliation for machine IR."""

from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from ..util import sha256_bytes
from .ir_model import (
    DECODED_CONTROL_RECONCILIATION_FORMAT,
    X87_MICRO_OP_FORMAT,
    MachineIRExportError,
    RvaSpan,
    _Instruction,
    _RAW_INSTRUCTION_FIELDS,
    _canonical_json,
    _digest,
    _hex_bytes,
    _json_scalar,
    _u32,
)


_CONTROL_FLOW_GROUPS = frozenset({
    "branch_relative",
    "call",
    "int",
    "iret",
    "jump",
    "ret",
})
_NON_FALLTHROUGH_MNEMONICS = frozenset({
    "hlt",
    "int",
    "int1",
    "int3",
    "into",
    "iret",
    "iretd",
    "iretq",
    "syscall",
    "sysenter",
    "sysexit",
    "sysret",
    "ud0",
    "ud1",
    "ud2",
})


def _decoded_control_reconciliation(
    *,
    binary: StageABinary,
    instructions: Sequence[_Instruction],
    span: RvaSpan,
    outcome: Any,
    direct_targets: Sequence[int],
    external_events: Any,
    ordered_events: Any,
    control_disposition: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Reconcile semantic control against an independent exact x86 decode."""

    checks: list[dict[str, Any]] = []

    def record(
        code: str,
        status: str,
        message: str,
        *,
        expected: Any = None,
        actual: Any = None,
    ) -> None:
        item: dict[str, Any] = {
            "code": code,
            "status": status,
            "message": message,
        }
        if expected is not None:
            item["expected"] = copy.deepcopy(expected)
        if actual is not None:
            item["actual"] = copy.deepcopy(actual)
        checks.append(item)

    terminal = instructions[-1]
    terminal_effect = _decoded_control_effect(binary, terminal)
    decoded_call_sites = [
        effect
        for instruction in instructions
        for effect in [_decoded_control_effect(binary, instruction)]
        if effect["class"]
        in {"direct_call", "indirect_call", "external_call", "external_jump"}
    ]
    semantic_outcome_kind = (
        str(outcome.get("kind")) if isinstance(outcome, Mapping) else None
    )
    expected_outcome_kinds = _decoded_expected_outcome_kinds(terminal_effect)

    if expected_outcome_kinds is None:
        record(
            "terminal_outcome_class_unresolved",
            "incomplete",
            "the decoded terminal control class has no exact aggregate semantic representation",
            actual=semantic_outcome_kind,
        )
    elif semantic_outcome_kind == "unknown":
        record(
            "terminal_outcome_unknown",
            "incomplete",
            "the aggregate semantic outcome is unknown",
            expected=sorted(expected_outcome_kinds),
            actual=semantic_outcome_kind,
        )
    elif semantic_outcome_kind == "fault" and terminal_effect["class"] == "fallthrough":
        record(
            "terminal_fault_not_decodable_as_control",
            "incomplete",
            "exact decoding alone cannot establish the declared terminal fault",
            expected="independently checked fault behavior",
            actual=semantic_outcome_kind,
        )
    elif semantic_outcome_kind not in expected_outcome_kinds:
        record(
            "terminal_outcome_class_mismatch",
            "violated",
            "the decoded terminal instruction disagrees with the aggregate semantic outcome",
            expected=sorted(expected_outcome_kinds),
            actual=semantic_outcome_kind,
        )
    else:
        record(
            "terminal_outcome_class",
            "complete",
            "the decoded terminal instruction agrees with the aggregate semantic outcome",
            expected=sorted(expected_outcome_kinds),
            actual=semantic_outcome_kind,
        )

    expected_targets = _decoded_expected_direct_targets(
        terminal_effect,
        span=span,
        terminating=control_disposition is not None,
    )
    if semantic_outcome_kind == "fault" and terminal_effect["class"] == "fallthrough":
        expected_targets = []
    actual_targets = [int(target) for target in direct_targets]
    if expected_targets is None:
        record(
            "direct_targets_unresolved",
            "incomplete",
            "the decoded terminal target cannot be reduced to exact PE RVAs",
            actual=actual_targets,
        )
    elif actual_targets != expected_targets:
        record(
            "direct_targets_mismatch",
            "violated",
            "decoded control targets disagree with the aggregate direct-target inventory",
            expected=expected_targets,
            actual=actual_targets,
        )
    else:
        record(
            "direct_targets",
            "complete",
            "decoded control targets agree with the aggregate direct-target inventory",
            expected=expected_targets,
            actual=actual_targets,
        )

    decoded_return_class = terminal_effect.get("return_class")
    if decoded_return_class == "interrupt_return":
        record(
            "return_class_unrepresented",
            "incomplete",
            "the aggregate semantic schema does not represent interrupt-return state restoration",
            expected=decoded_return_class,
            actual=semantic_outcome_kind,
        )
    elif decoded_return_class == "far_return":
        record(
            "return_class_unrepresented",
            "incomplete",
            "the aggregate semantic schema does not distinguish far returns",
            expected=decoded_return_class,
            actual=semantic_outcome_kind,
        )
    elif decoded_return_class == "near_return" and semantic_outcome_kind != "return":
        record(
            "return_class_mismatch",
            "violated",
            "a decoded near return is not declared as an aggregate return",
            expected="return",
            actual=semantic_outcome_kind,
        )
    elif decoded_return_class is None and semantic_outcome_kind == "return":
        record(
            "return_class_mismatch",
            "violated",
            "an aggregate return is not backed by a decoded return instruction",
            expected="decoded return",
            actual=terminal_effect["class"],
        )
    else:
        record(
            "return_class",
            "complete",
            "the decoded return class agrees with the aggregate semantic outcome",
            expected=decoded_return_class or "not_return",
            actual="return" if semantic_outcome_kind == "return" else "not_return",
        )

    if control_disposition is not None:
        terminal_call_site = decoded_call_sites[-1] if decoded_call_sites else None
        if (
            terminal_effect["class"] not in {"external_call", "external_jump"}
            or terminal_call_site is None
            or terminal_call_site["instruction_rva"] != terminal.rva
        ):
            record(
                "terminating_disposition_site_mismatch",
                "violated",
                "the terminating external disposition is not backed by the decoded terminal transfer",
                expected="terminal PE import call or jump",
                actual=terminal_effect["class"],
            )
        else:
            record(
                "terminating_disposition_site",
                "complete",
                "the terminating external disposition is bound to the decoded terminal transfer",
                expected=terminal.rva,
                actual=terminal_call_site["instruction_rva"],
            )

    _reconcile_decoded_call_events(
        decoded_call_sites,
        binary=binary,
        external_events=external_events,
        ordered_events=ordered_events,
        record=record,
    )

    status = (
        "violated"
        if any(check["status"] == "violated" for check in checks)
        else (
            "incomplete"
            if any(check["status"] == "incomplete" for check in checks)
            else "complete"
        )
    )
    return {
        "format": DECODED_CONTROL_RECONCILIATION_FORMAT,
        "status": status,
        "authority": "independent_static_x86_pe32_decode",
        "proof_authority": False,
        "decoder": "capstone",
        "terminal_instruction": {
            "rva": terminal.rva,
            "rva_end": terminal.end,
            "instruction_sha256": terminal.digest,
            "mnemonic": terminal.mnemonic,
            "decoded_class": terminal_effect["class"],
            "return_class": decoded_return_class,
        },
        "decoded_call_sites": decoded_call_sites,
        "semantic": {
            "outcome_kind": semantic_outcome_kind,
            "direct_targets": actual_targets,
            "call_event_count": len(
                _semantic_call_events(external_events)
            ),
            "terminating_external_disposition": control_disposition is not None,
        },
        "checks": checks,
    }


def _decoded_control_effect(
    binary: StageABinary, instruction: _Instruction
) -> dict[str, Any]:
    groups = frozenset(instruction.groups)
    mnemonic = instruction.mnemonic.lower()
    operand = instruction.operands[0] if instruction.operands else None
    direct_target = _decoded_immediate_target_rva(binary, operand)
    imported = _decoded_import_identity(binary, instruction, direct_target)
    result: dict[str, Any] = {
        "instruction_rva": instruction.rva,
        "return_rva": instruction.end,
        "mnemonic": mnemonic,
        "class": "fallthrough",
    }

    if "call" in groups:
        if imported is not None:
            result["class"] = "external_call"
            result["import"] = imported
        elif operand is not None and operand.get("kind") == "immediate":
            result["class"] = "direct_call"
            result["target_rva"] = direct_target
        else:
            result["class"] = "indirect_call"
            result["target"] = copy.deepcopy(operand)
        return result
    if "iret" in groups:
        result["class"] = "interrupt_return"
        result["return_class"] = "interrupt_return"
        return result
    if "ret" in groups:
        result["class"] = "return"
        result["return_class"] = (
            "far_return" if mnemonic in {"retf", "lret"} else "near_return"
        )
        return result
    if "jump" in groups or "branch_relative" in groups:
        if imported is not None and mnemonic in {"jmp", "ljmp"}:
            result["class"] = "external_jump"
            result["import"] = imported
        elif mnemonic in {"jmp", "ljmp"}:
            result["class"] = (
                "direct_jump" if direct_target is not None else "indirect_jump"
            )
        else:
            result["class"] = (
                "direct_branch" if direct_target is not None else "indirect_branch"
            )
        if direct_target is not None:
            result["target_rva"] = direct_target
        elif operand is not None:
            result["target"] = copy.deepcopy(operand)
        return result
    if "int" in groups or mnemonic in _NON_FALLTHROUGH_MNEMONICS:
        result["class"] = "terminal_system"
    return result


def _decoded_immediate_target_rva(
    binary: StageABinary, operand: Mapping[str, Any] | None
) -> int | None:
    if operand is None or operand.get("kind") != "immediate":
        return None
    value = operand.get("value")
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return (value - binary.image_base) & 0xFFFFFFFF


def _decoded_import_identity(
    binary: StageABinary,
    instruction: _Instruction,
    direct_target_rva: int | None,
) -> dict[str, Any] | None:
    if not instruction.operands:
        return None
    operand = instruction.operands[0]
    thunk_rva = _decoded_absolute_memory_rva(binary, operand)
    if thunk_rva is None and direct_target_rva is not None:
        thunk_rva = _decoded_direct_import_thunk_rva(binary, direct_target_rva)
    if thunk_rva is None:
        return None
    imported = next(
        (item for item in binary.imports if item.thunk_rva == thunk_rva),
        None,
    )
    if imported is None:
        return None
    return {
        "dll": imported.dll,
        "symbol": imported.symbol,
        "ordinal": imported.ordinal,
        "thunk_rva": imported.thunk_rva,
    }


def _decoded_absolute_memory_rva(
    binary: StageABinary, operand: Mapping[str, Any]
) -> int | None:
    if (
        operand.get("kind") != "memory"
        or operand.get("base") is not None
        or operand.get("index") is not None
    ):
        return None
    displacement = operand.get("displacement")
    if not isinstance(displacement, int) or isinstance(displacement, bool):
        return None
    address = displacement & 0xFFFFFFFF
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    if 0 <= address < binary.size_of_image:
        return address
    return None


def _decoded_direct_import_thunk_rva(
    binary: StageABinary, target_rva: int
) -> int | None:
    if not any(
        section.executable and section.rva_start <= target_rva < section.rva_end
        for section in binary.sections
    ):
        return None
    encoded = bytes(binary.pe.get_data(target_rva, 15))
    if not encoded:
        return None
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoded = next(
        iter(decoder.disasm(encoded, binary.image_base + target_rva, count=1)),
        None,
    )
    if decoded is None or not decoded.group(capstone.CS_GRP_JUMP):
        return None
    projection = _instruction_projection(
        decoded, target_rva, bytes(decoded.bytes)
    )
    if not projection.operands:
        return None
    return _decoded_absolute_memory_rva(binary, projection.operands[0])


def _decoded_expected_outcome_kinds(
    terminal_effect: Mapping[str, Any],
) -> frozenset[str] | None:
    effect_class = terminal_effect.get("class")
    if effect_class in {"fallthrough", "direct_call", "indirect_call", "external_call"}:
        return frozenset({"fallthrough"})
    if effect_class == "direct_jump":
        return frozenset({"jump"})
    if effect_class == "direct_branch":
        return frozenset({"branch"})
    if effect_class in {"indirect_jump", "indirect_branch"}:
        return frozenset({"indirect_jump", "indirect_jump_table"})
    if effect_class == "external_jump":
        return frozenset({"external_jump"})
    if effect_class == "return":
        return frozenset({"return"})
    return None


def _decoded_expected_direct_targets(
    terminal_effect: Mapping[str, Any],
    *,
    span: RvaSpan,
    terminating: bool,
) -> list[int] | None:
    effect_class = terminal_effect.get("class")
    if terminating:
        return []
    if effect_class in {"fallthrough", "direct_call", "indirect_call", "external_call"}:
        return [span.end]
    if effect_class == "direct_jump":
        target = terminal_effect.get("target_rva")
        return [int(target)] if isinstance(target, int) else None
    if effect_class == "direct_branch":
        target = terminal_effect.get("target_rva")
        return [int(target), span.end] if isinstance(target, int) else None
    if effect_class in {
        "indirect_jump",
        "indirect_branch",
        "external_jump",
        "return",
        "interrupt_return",
        "terminal_system",
    }:
        return []
    return None


def _semantic_call_events(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        event
        for event in value
        if isinstance(event, Mapping)
        and event.get("kind") in {"external_call", "internal_call", "indirect_call"}
    ]


def _decoded_immutable_internal_target(
    binary: StageABinary, decoded: Mapping[str, Any]
) -> dict[str, Any] | None:
    """Resolve one absolute, initialized, non-writable PE pointer slot.

    The instruction remains an indirect call at the ISA layer.  This witness
    only refines its target when the exact image supplies a four-byte pointer
    in a mapped read-only section and that pointer names executable image code.
    Loader relocation preserves the resulting RVA.
    """

    target = decoded.get("target")
    if not isinstance(target, Mapping):
        return None
    slot_rva = _decoded_absolute_memory_rva(binary, target)
    if slot_rva is None:
        return None
    section = next(
        (
            row
            for row in binary.sections
            if row.rva_start <= slot_rva
            and slot_rva + 4 <= row.rva_end
            and row.readable
            and not row.writable
            and slot_rva - row.rva_start + 4 <= row.raw_size
        ),
        None,
    )
    if section is None:
        return None
    encoded = bytes(binary.pe.get_data(slot_rva, 4))
    if len(encoded) != 4:
        return None
    raw_target = int.from_bytes(encoded, "little")
    if binary.image_base <= raw_target < binary.image_base + binary.size_of_image:
        target_rva = raw_target - binary.image_base
    elif 0 <= raw_target < binary.size_of_image:
        target_rva = raw_target
    else:
        return None
    if not any(
        candidate.executable
        and candidate.rva_start <= target_rva < candidate.rva_end
        for candidate in binary.sections
    ):
        return None
    return {
        "slot_rva": slot_rva,
        "slot_section": section.name,
        "raw_target": raw_target,
        "target_rva": target_rva,
        "slot_bytes_sha256": sha256_bytes(encoded),
        "authority": "exact_initialized_nonwritable_pe_slot_v1",
    }


def _reconcile_decoded_call_events(
    decoded_sites: Sequence[Mapping[str, Any]],
    *,
    binary: StageABinary,
    external_events: Any,
    ordered_events: Any,
    record: Any,
) -> None:
    semantic_events = _semantic_call_events(external_events)
    ordered = [
        event
        for event in _semantic_call_events(ordered_events)
        if event.get("family") in {None, "external"}
    ]
    if len(decoded_sites) != len(semantic_events):
        record(
            "call_event_count_mismatch",
            "violated",
            "decoded call transfers disagree with the aggregate external-event inventory",
            expected=len(decoded_sites),
            actual=len(semantic_events),
        )
    else:
        record(
            "call_event_count",
            "complete",
            "decoded call transfers agree with the aggregate external-event count",
            expected=len(decoded_sites),
            actual=len(semantic_events),
        )
    if ordered and len(ordered) != len(semantic_events):
        record(
            "ordered_call_event_count_mismatch",
            "violated",
            "ordered call events disagree with the aggregate external-event inventory",
            expected=len(semantic_events),
            actual=len(ordered),
        )

    for index, (decoded, event) in enumerate(
        zip(decoded_sites, semantic_events, strict=False)
    ):
        ordered_event = ordered[index] if index < len(ordered) else None
        instruction_rva = event.get("instruction_rva")
        if instruction_rva is None and ordered_event is not None:
            instruction_rva = ordered_event.get("instruction_rva")
        if instruction_rva is None:
            record(
                f"call_event_{index}_site_missing",
                "incomplete",
                "the semantic call event is not bound to an instruction RVA",
                expected=decoded["instruction_rva"],
            )
        elif instruction_rva != decoded["instruction_rva"]:
            record(
                f"call_event_{index}_site_mismatch",
                "violated",
                "the semantic call event is bound to a different decoded instruction",
                expected=decoded["instruction_rva"],
                actual=instruction_rva,
            )
        if (
            ordered_event is not None
            and ordered_event.get("instruction_rva") != decoded["instruction_rva"]
        ):
            record(
                f"call_event_{index}_ordered_site_mismatch",
                "violated",
                "the ordered call event is bound to a different decoded instruction",
                expected=decoded["instruction_rva"],
                actual=ordered_event.get("instruction_rva"),
            )

        expected_kind = {
            "direct_call": "internal_call",
            "indirect_call": "indirect_call",
            "external_call": "external_call",
            "external_jump": "external_call",
        }[str(decoded["class"])]
        immutable_target = None
        if decoded["class"] == "indirect_call":
            immutable_target = _decoded_immutable_internal_target(binary, decoded)
            if immutable_target is not None:
                decoded["immutable_internal_target"] = immutable_target
                if event.get("kind") == "internal_call":
                    expected_kind = "internal_call"
        if event.get("kind") != expected_kind:
            record(
                f"call_event_{index}_kind_mismatch",
                "violated",
                "the semantic call event class disagrees with the decoded transfer",
                expected=expected_kind,
                actual=event.get("kind"),
            )
        elif immutable_target is not None and expected_kind == "internal_call":
            semantic_target = event.get("target_rva")
            if semantic_target != immutable_target["target_rva"]:
                record(
                    f"call_event_{index}_immutable_target_mismatch",
                    "violated",
                    "the semantic internal-call target disagrees with the exact immutable pointer slot",
                    expected=immutable_target["target_rva"],
                    actual=semantic_target,
                )
            else:
                record(
                    f"call_event_{index}_immutable_target",
                    "complete",
                    "the semantic internal call is refined by an exact non-writable PE pointer slot",
                    expected=immutable_target["target_rva"],
                    actual=semantic_target,
                )

        return_rva = event.get("return_rva")
        if return_rva is None:
            record(
                f"call_event_{index}_return_missing",
                "incomplete",
                "the semantic call event omits its decoded return RVA",
                expected=decoded["return_rva"],
            )
        elif return_rva != decoded["return_rva"]:
            record(
                f"call_event_{index}_return_mismatch",
                "violated",
                "the semantic call event return RVA disagrees with the decoded call",
                expected=decoded["return_rva"],
                actual=return_rva,
            )

        target_rva = decoded.get("target_rva")
        if decoded["class"] == "direct_call" and event.get("target_rva") != target_rva:
            record(
                f"call_event_{index}_target_mismatch",
                "violated",
                "the semantic internal-call target disagrees with the decoded target",
                expected=target_rva,
                actual=event.get("target_rva"),
            )
        imported = decoded.get("import")
        if isinstance(imported, Mapping):
            actual_import = {
                "dll": event.get("dll"),
                "symbol": event.get("symbol"),
                "ordinal": event.get("ordinal"),
            }
            expected_import = {
                "dll": imported.get("dll"),
                "symbol": imported.get("symbol"),
                "ordinal": imported.get("ordinal"),
            }
            if (
                not isinstance(actual_import["dll"], str)
                or str(actual_import["dll"]).lower()
                != str(expected_import["dll"]).lower()
                or actual_import["symbol"] != expected_import["symbol"]
                or actual_import["ordinal"] != expected_import["ordinal"]
            ):
                record(
                    f"call_event_{index}_import_mismatch",
                    "violated",
                    "the semantic external call identity disagrees with the PE import transfer",
                    expected=expected_import,
                    actual=actual_import,
                )

        if ordered_event is not None:
            compared_fields = (
                "kind",
                "dll",
                "symbol",
                "ordinal",
                "target_rva",
                "return_rva",
            )
            aggregate_projection = {
                field: event.get(field) for field in compared_fields
            }
            ordered_projection = {
                field: ordered_event.get(field) for field in compared_fields
            }
            if aggregate_projection != ordered_projection:
                record(
                    f"call_event_{index}_ordered_mismatch",
                    "violated",
                    "the ordered call event disagrees with the aggregate event",
                    expected=aggregate_projection,
                    actual=ordered_projection,
                )


def _recover_unknown_fallthrough(
    outcome: Any,
    instructions: Sequence[_Instruction],
    span: RvaSpan,
) -> dict[str, Any] | None:
    if (
        not isinstance(outcome, Mapping)
        or outcome.get("kind") != "unknown"
        or not instructions
    ):
        return None
    last = instructions[-1]
    if (
        last.end != span.end
        or _CONTROL_FLOW_GROUPS.intersection(last.groups)
        or last.mnemonic.lower() in _NON_FALLTHROUGH_MNEMONICS
    ):
        return None
    return {
        "kind": "exact_decode_non_control_fallthrough",
        "proof_authority": False,
        "required_replay": "Lean must decode the exact terminal instruction as non-control",
        "terminal_instruction": {
            "rva": last.rva,
            "sha256": last.digest,
            "mnemonic_guidance": last.mnemonic,
        },
        "outcome": {"kind": "fallthrough", "target_rva": span.end},
    }


def _semantic_unit_qualified(
    row: Mapping[str, Any], x87_micro_ops: Sequence[Mapping[str, Any]]
) -> bool:
    if row.get("status") == "reimplementable":
        return True
    return bool(x87_micro_ops) and row.get("blocker_category") in {
        "x87_physical_state_requires_native_exact_command_replay",
        "x87_typed_lowering_required",
    }


def _instructions(
    row: Mapping[str, Any],
    identity: str,
    binary: StageABinary,
    span: RvaSpan,
) -> tuple[tuple[_Instruction, ...], bytes]:
    raw_instructions = row.get("instructions")
    if not isinstance(raw_instructions, list) or not raw_instructions:
        raise MachineIRExportError(
            f"{identity}: instructions must be a non-empty list",
            code="missing_instruction_inventory",
            unit_id=identity,
            rva=span.start,
        )
    result: list[_Instruction] = []
    reconstructed = bytearray()
    expected_rva = span.start
    for index, raw in enumerate(raw_instructions):
        if not isinstance(raw, Mapping):
            raise MachineIRExportError(
                f"{identity}: instruction {index} is not an object",
                unit_id=identity,
                rva=expected_rva,
            )
        rva = _u32(raw.get("rva"), f"{identity} instruction {index} RVA")
        encoded = _hex_bytes(raw.get("bytes"), f"{identity} instruction {index} bytes")
        size = raw.get("size", len(encoded))
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise MachineIRExportError(
                f"{identity}: instruction {index} has an invalid size",
                unit_id=identity,
                rva=rva,
            )
        if rva != expected_rva or len(encoded) != size:
            raise MachineIRExportError(
                f"{identity}: instruction {index} is not an exact contiguous span",
                code="noncontiguous_instruction_inventory",
                unit_id=identity,
                rva=rva,
            )
        decoded = _decode_one(encoded, binary.image_base + rva, identity, rva)
        mnemonic = decoded.mnemonic.lower()
        declared_mnemonic = raw.get("mnemonic")
        if isinstance(declared_mnemonic, str) and declared_mnemonic.lower() != mnemonic:
            raise MachineIRExportError(
                f"{identity}: instruction at 0x{rva:x} has mnemonic drift",
                code="instruction_mnemonic_mismatch",
                unit_id=identity,
                rva=rva,
            )
        result.append(_instruction_projection(decoded, rva, encoded))
        reconstructed.extend(encoded)
        expected_rva += size
    if expected_rva != span.end:
        raise MachineIRExportError(
            f"{identity}: instruction inventory does not cover its exact unit span",
            code="incomplete_instruction_inventory",
            unit_id=identity,
            rva=expected_rva,
        )
    return tuple(result), bytes(reconstructed)


def _decode_one(encoded: bytes, address: int, identity: str, rva: int) -> Any:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoded = list(decoder.disasm(encoded, address))
    if len(decoded) != 1 or int(decoded[0].size) != len(encoded):
        raise MachineIRExportError(
            f"{identity}: bytes at 0x{rva:x} do not decode as one exact IA-32 instruction",
            code="instruction_decode_mismatch",
            unit_id=identity,
            rva=rva,
        )
    return decoded[0]


def _instruction_projection(decoded: Any, rva: int, encoded: bytes) -> _Instruction:
    operands = tuple(_operand_projection(decoded, operand) for operand in decoded.operands)
    try:
        reads, writes = decoded.regs_access()
    except capstone.CsError:
        reads, writes = (), ()
    return _Instruction(
        rva=rva,
        size=len(encoded),
        digest=sha256_bytes(encoded),
        mnemonic=str(decoded.mnemonic).lower(),
        operands=operands,
        registers_read=tuple(decoded.reg_name(value) for value in reads),
        registers_written=tuple(decoded.reg_name(value) for value in writes),
        groups=tuple(decoded.group_name(value) for value in decoded.groups),
    )


def _operand_projection(decoded: Any, operand: Any) -> dict[str, Any]:
    common = {
        "width_bits": int(operand.size) * 8,
        "access": _operand_access(int(getattr(operand, "access", 0))),
    }
    if operand.type == X86_OP_REG:
        return {"kind": "register", "name": decoded.reg_name(operand.reg), **common}
    if operand.type == X86_OP_IMM:
        return {"kind": "immediate", "value": int(operand.imm), **common}
    if operand.type == X86_OP_MEM:
        memory = operand.mem
        return {
            "kind": "memory",
            "segment": decoded.reg_name(memory.segment) or None,
            "base": decoded.reg_name(memory.base) or None,
            "index": decoded.reg_name(memory.index) or None,
            "scale": int(memory.scale),
            "displacement": int(memory.disp),
            **common,
        }
    raise MachineIRExportError(
        f"unsupported Capstone operand type {operand.type}",
        code="unsupported_typed_operand",
    )


def _operand_access(access: int) -> str:
    read = bool(access & capstone.CS_AC_READ)
    write = bool(access & capstone.CS_AC_WRITE)
    if read and write:
        return "read_write"
    if read:
        return "read"
    if write:
        return "write"
    return "implicit_or_unspecified"


def _x87_projection(
    row: Mapping[str, Any],
    *,
    identity: str,
    span: RvaSpan,
    instructions: Sequence[_Instruction],
    transfer_digest: str,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], Any]:
    fpu = row.get("fpu_state")
    schedule_raw = row.get("instruction_effect_schedule")
    schedule = _sanitize_schedule(schedule_raw, identity) if schedule_raw is not None else None
    if fpu is None:
        return schedule, [], None
    if not isinstance(fpu, Mapping):
        raise MachineIRExportError(
            f"{identity}: fpu_state must be an object or null",
            unit_id=identity,
            rva=span.start,
        )
    if fpu.get("model") != "native_exact_x87_command_replay_obligation_v1":
        return schedule, [], _semantic_copy(fpu, "fpu_state", identity)

    replay = fpu.get("replay")
    if not isinstance(replay, Mapping):
        raise MachineIRExportError(
            f"{identity}: x87 replay metadata is missing",
            code="malformed_x87_replay",
            unit_id=identity,
            rva=span.start,
        )
    replay_bytes = _hex_bytes(replay.get("bytes"), f"{identity} x87 replay bytes")
    replay_digest = _digest(replay.get("bytes_sha256"), f"{identity} x87 replay digest")
    if (
        sha256_bytes(replay_bytes) != replay_digest
        or replay_digest != transfer_digest
        or replay.get("rva_start") != span.start
        or replay.get("rva_end") != span.end
    ):
        raise MachineIRExportError(
            f"{identity}: x87 replay does not bind the exact transfer",
            code="malformed_x87_replay",
            unit_id=identity,
            rva=span.start,
        )
    replay_instructions = replay.get("instructions")
    if not isinstance(replay_instructions, list) or len(replay_instructions) != len(instructions):
        raise MachineIRExportError(
            f"{identity}: x87 replay instruction inventory differs from the transfer",
            code="malformed_x87_replay",
            unit_id=identity,
            rva=span.start,
        )
    for index, (raw, instruction) in enumerate(zip(replay_instructions, instructions, strict=True)):
        if not isinstance(raw, Mapping):
            raise MachineIRExportError(f"{identity}: malformed x87 replay instruction {index}")
        encoded = _hex_bytes(raw.get("bytes"), f"{identity} x87 replay instruction {index}")
        if (
            raw.get("rva") != instruction.rva
            or raw.get("size") != instruction.size
            or sha256_bytes(encoded) != instruction.digest
        ):
            raise MachineIRExportError(
                f"{identity}: x87 replay instruction {index} has drifted",
                code="malformed_x87_replay",
                unit_id=identity,
                rva=instruction.rva,
            )

    selected = _x87_instruction_indices(schedule_raw, instructions, identity)
    micro_ops = []
    for index in selected:
        instruction = instructions[index]
        micro_ops.append(
            {
                "format": X87_MICRO_OP_FORMAT,
                "id": f"{identity}:x87:{instruction.rva:08x}",
                "unit_id": identity,
                "rva_start": instruction.rva,
                "rva_end": instruction.end,
                "size": instruction.size,
                "instruction_sha256": instruction.digest,
                "transfer_instruction_sha256": transfer_digest,
                "mnemonic": instruction.mnemonic,
                "operands": [copy.deepcopy(item) for item in instruction.operands],
                "implicit_registers_read": list(instruction.registers_read),
                "implicit_registers_written": list(instruction.registers_written),
                "checked_decoder": replay.get("checked_decoder"),
                "checked_executor": replay.get("checked_executor"),
                "physical_state_effect": "defined_by_checked_typed_x87_executor",
            }
        )
    metadata = {
        key: _semantic_copy(value, f"fpu_state.{key}", identity)
        for key, value in fpu.items()
        if key != "replay"
    }
    metadata["typed_replay"] = {
        "source_format": replay.get("format"),
        "architecture": replay.get("architecture"),
        "bitness": replay.get("bitness"),
        "image_base": replay.get("image_base"),
        "rva_start": replay.get("rva_start"),
        "rva_end": replay.get("rva_end"),
        "instruction_bytes_sha256": replay_digest,
        "checked_decoder": replay.get("checked_decoder"),
        "checked_executor": replay.get("checked_executor"),
        "micro_op_ids": [item["id"] for item in micro_ops],
    }
    return schedule, micro_ops, metadata


def _x87_instruction_indices(
    schedule: Any, instructions: Sequence[_Instruction], identity: str
) -> tuple[int, ...]:
    if schedule is None:
        return tuple(range(len(instructions)))
    if not isinstance(schedule, Mapping) or not isinstance(schedule.get("records"), list):
        raise MachineIRExportError(
            f"{identity}: x87 instruction effect schedule is malformed",
            code="malformed_x87_instruction_effect_schedule",
        )
    records = schedule["records"]
    if len(records) != len(instructions):
        raise MachineIRExportError(
            f"{identity}: x87 effect schedule does not cover every instruction",
            code="malformed_x87_instruction_effect_schedule",
        )
    selected: list[int] = []
    for index, raw in enumerate(records):
        if not isinstance(raw, Mapping):
            raise MachineIRExportError(f"{identity}: x87 schedule record {index} is malformed")
        if raw.get("instruction_class") == "x87_singleton_checked_replay":
            selected.append(index)
    if not selected:
        raise MachineIRExportError(
            f"{identity}: replay-backed FPU state has no typed x87 schedule records",
            code="malformed_x87_instruction_effect_schedule",
        )
    return tuple(selected)


def _sanitize_schedule(value: Any, identity: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MachineIRExportError(f"{identity}: instruction effect schedule must be an object")
    source_schedule_digest = _verified_embedded_digest(
        value,
        "schedule_sha256",
        f"{identity}: source instruction effect schedule",
    )
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key in _RAW_INSTRUCTION_FIELDS or key == "schedule_sha256":
            continue
        if key == "records":
            if not isinstance(item, list):
                raise MachineIRExportError(f"{identity}: schedule records must be a list")
            result[key] = [
                _sanitize_schedule_record(record, identity, index)
                for index, record in enumerate(item)
            ]
        elif key == "blockers":
            if not isinstance(item, list):
                raise MachineIRExportError(f"{identity}: schedule blockers must be a list")
            result[key] = [_sanitize_metadata(record, identity) for record in item]
        else:
            result[key] = _sanitize_metadata(item, identity)
    existing_source_digest = result.get("source_schedule_sha256")
    if existing_source_digest is not None and existing_source_digest != source_schedule_digest:
        raise MachineIRExportError(
            f"{identity}: source instruction effect schedule digest is ambiguous"
        )
    result["source_schedule_sha256"] = source_schedule_digest
    result["schedule_sha256"] = sha256_bytes(_canonical_json(result))
    return result


def _sanitize_schedule_record(
    value: Any, identity: str, index: int
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MachineIRExportError(f"{identity}: schedule record {index} must be an object")
    source_record_digest = _verified_embedded_digest(
        value,
        "record_sha256",
        f"{identity}: source schedule record {index}",
    )
    sanitized = _sanitize_metadata(value, identity)
    if not isinstance(sanitized, dict):
        raise AssertionError("mapping metadata sanitization did not produce an object")
    sanitized.pop("record_sha256", None)
    existing_source_digest = sanitized.get("source_record_sha256")
    if existing_source_digest is not None and existing_source_digest != source_record_digest:
        raise MachineIRExportError(
            f"{identity}: source schedule record {index} digest is ambiguous"
        )
    sanitized["source_record_sha256"] = source_record_digest
    sanitized["record_sha256"] = sha256_bytes(_canonical_json(sanitized))
    return sanitized


def _verified_embedded_digest(
    value: Mapping[str, Any], field: str, label: str
) -> str:
    expected = _digest(value.get(field), f"{label} digest")
    body = dict(value)
    del body[field]
    if sha256_bytes(_canonical_json(body)) != expected:
        raise MachineIRExportError(f"{label} digest does not match its contents")
    return expected


def _sanitize_metadata(value: Any, identity: str) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _sanitize_metadata(item, identity)
            for key, item in value.items()
            if key not in _RAW_INSTRUCTION_FIELDS
        }
    if isinstance(value, list):
        return [_sanitize_metadata(item, identity) for item in value]
    return _json_scalar(value, f"{identity} metadata")


def _semantic_copy(value: Any, field: str, identity: str) -> Any:
    copied = copy.deepcopy(value)
    _assert_semantics_have_no_instruction_bytes(copied, field, identity)
    return copied


def _assert_semantics_have_no_instruction_bytes(value: Any, field: str, identity: str) -> None:
    if isinstance(value, Mapping):
        forbidden = sorted(str(key) for key in value if key in _RAW_INSTRUCTION_FIELDS)
        if forbidden:
            raise MachineIRExportError(
                f"{identity}: semantic field {field} contains raw instruction material: "
                + ", ".join(forbidden),
                code="raw_instruction_bytes_in_semantics",
                unit_id=identity,
            )
        for key, item in value.items():
            _assert_semantics_have_no_instruction_bytes(item, f"{field}.{key}", identity)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_semantics_have_no_instruction_bytes(item, f"{field}[{index}]", identity)
