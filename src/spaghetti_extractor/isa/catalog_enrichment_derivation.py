"""Shared effect constructors and dispatch for Lean-decoded ISA metadata."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .catalog_enrichment import (
    _ARITHMETIC_FLAGS,
    _CARRY_FLAG,
    _GPRS,
    _LOGICAL_FLAGS,
    _MULTIPLY_FLAGS,
    _OTHER_UNRESOLVED_PREFIXES,
    _PREFIXES,
    _TEST_EIP,
    _ZERO_FLAG,
    _exact_fields,
    _string,
    _uint,
)
from ..errors import ToolkitInputError

def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value if value < 0x80000000 else value - 0x100000000


def _register(value: Any, context: str) -> str:
    register = _string(value, context)
    if register not in _GPRS:
        raise ToolkitInputError(f"{context} is not an IA-32 general-purpose register")
    return register


def _defined_outputs(
    eflags: int,
    *,
    gpr_masks: Mapping[str, int] | None = None,
    x87: bool = False,
) -> dict[str, Any]:
    masks = {register: 0xFFFFFFFF for register in _GPRS}
    if gpr_masks is not None:
        masks.update(gpr_masks)
    return {
        "gprs": masks,
        "eip": 0xFFFFFFFF,
        "eflags": eflags,
        "fs": {"selector": 0, "base": 0},
        "x87": {
            "control_word": 0xFFFF if x87 else 0,
            "status_word": 0xFFFF if x87 else 0,
            "tag_word": 0xFFFF if x87 else 0,
            "last_opcode": 0x7FF if x87 else 0,
            "instruction_pointer": 0xFFFFFFFF if x87 else 0,
            "data_pointer": 0xFFFFFFFF if x87 else 0,
            "registers": [
                [0xFF if x87 else 0] * 10 for _ in range(8)
            ],
        },
        "memory": [],
    }


def _register_effect(
    *,
    reads: Sequence[str | Mapping[str, Any]],
    writes: Sequence[str | Mapping[str, Any]],
    width_bits: int = 32,
) -> dict[str, Any] | None:
    def location(value: str | Mapping[str, Any]) -> dict[str, Any] | str:
        if isinstance(value, str):
            if width_bits == 8:
                return {"register": value, "lsb": 0}
            return value
        return {
            "register": _register(value.get("register"), "register location"),
            "lsb": _uint(value.get("lsb"), 5, "register location lsb"),
        }

    def canonical(
        values: Sequence[str | Mapping[str, Any]],
    ) -> list[dict[str, Any] | str]:
        locations = [location(value) for value in values]
        return sorted(
            {
                (
                    value
                    if isinstance(value, str)
                    else (str(value["register"]), int(value["lsb"]))
                )
                for value in locations
            },
            key=lambda value: (
                value if isinstance(value, tuple) else (value, 0)
            ),
        )

    def payload(
        values: Sequence[str | Mapping[str, Any]],
    ) -> list[dict[str, Any] | str]:
        return [
            (
                {"register": value[0], "lsb": value[1]}
                if isinstance(value, tuple)
                else value
            )
            for value in canonical(values)
        ]

    canonical_reads = payload(reads)
    canonical_writes = payload(writes)
    if not canonical_reads and not canonical_writes:
        return None
    return {
        "class": "register",
        "id": f"register-{width_bits:02d}-gpr",
        "width_bits": width_bits,
        "reads": canonical_reads,
        "writes": canonical_writes,
    }


def _register_effect_around_memory(
    *,
    reads: Sequence[str | Mapping[str, Any]],
    writes: Sequence[str | Mapping[str, Any]],
    effects: Sequence[Mapping[str, Any]],
    width_bits: int = 32,
) -> dict[str, Any] | None:
    def parent_register(value: str | Mapping[str, Any]) -> str:
        return (
            value
            if isinstance(value, str)
            else _register(value.get("register"), "register location")
        )

    address_registers = {
        register
        for effect in effects
        if effect.get("class") == "memory"
        for register in (
            effect["address"].get("base"),
            effect["address"].get("index"),
        )
        if register is not None
    }
    return _register_effect(
        reads=[
            register
            for register in reads
            if parent_register(register) not in address_registers
        ],
        writes=writes,
        width_bits=width_bits,
    )


def _address(value: Any, context: str) -> dict[str, Any]:
    payload = _exact_fields(
        value,
        {"base", "index", "scale_shift", "displacement"},
        context,
    )
    raw_base = payload.get("base")
    raw_index = payload.get("index")
    base = None if raw_base is None else _register(raw_base, f"{context}.base")
    index = None if raw_index is None else _register(raw_index, f"{context}.index")
    scale_shift = _uint(payload.get("scale_shift"), 3, f"{context}.scale_shift")
    if scale_shift > 3:
        raise ToolkitInputError(f"{context}.scale_shift exceeds IA-32 SIB width")
    if index is None and scale_shift != 0:
        raise ToolkitInputError(f"{context} has a scale without an index")
    return {
        "base": base,
        "index": index,
        "scale": 1 << scale_shift,
        "displacement": _signed32(
            _uint(payload.get("displacement"), 32, f"{context}.displacement")
        ),
        "segment": "flat",
    }


def _memory_effect(
    *,
    address: Mapping[str, Any],
    access: str,
    width_bits: int,
    role: str,
    condition: Mapping[str, Any] | None = None,
    replay_control: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    effect = {
        "class": "memory",
        "id": f"memory-{role}-{access}-{width_bits:02d}",
        "width_bits": width_bits,
        "access": access,
        "address": dict(address),
        "condition": None if condition is None else dict(condition),
    }
    if replay_control is not None:
        effect["replay_control"] = dict(replay_control)
    return effect


def _x87_effect(*, stack_inputs: int, stack_outputs: int) -> dict[str, Any]:
    return {
        "class": "x87",
        "id": "x87-stack",
        "stack_inputs": stack_inputs,
        "stack_outputs": stack_outputs,
    }


def _x87_format_width(value: Any, context: str) -> int:
    format_name = _condition_name(value, context)
    widths = {
        "float32": 32,
        "int32": 32,
        "int64": 64,
        "float64": 64,
        "float80": 80,
    }
    try:
        return widths[format_name]
    except KeyError as exc:
        raise ToolkitInputError(
            f"{context} is not a reviewed x87 memory format"
        ) from exc


def _x87_index(value: Any, context: str) -> int:
    index = _uint(value, 8, context)
    if index >= 8:
        raise ToolkitInputError(f"{context} exceeds the x87 register stack")
    return index


def _operand32(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an object")
    kind = value.get("kind")
    if kind == "register":
        payload = _exact_fields(value, {"kind", "register"}, context)
        return {
            "kind": "register",
            "register": _register(payload.get("register"), f"{context}.register"),
        }
    if kind == "memory":
        payload = _exact_fields(value, {"kind", "address"}, context)
        return {
            "kind": "memory",
            "address": _address(payload.get("address"), f"{context}.address"),
        }
    if kind == "immediate":
        payload = _exact_fields(value, {"kind", "value"}, context)
        return {
            "kind": "immediate",
            "value": _uint(payload.get("value"), 32, f"{context}.value"),
        }
    raise ToolkitInputError(f"{context}.kind is unsupported")


def _width_bits(value: Any, context: str) -> int:
    width_bits = _uint(value, 8, context)
    if width_bits not in {8, 16, 32}:
        raise ToolkitInputError(f"{context} must be 8, 16, or 32")
    return width_bits


def _byte_register(value: Any, context: str) -> dict[str, Any]:
    payload = _exact_fields(value, {"parent", "high"}, context)
    high = payload.get("high")
    if not isinstance(high, bool):
        raise ToolkitInputError(f"{context}.high must be a boolean")
    return {
        "register": _register(payload.get("parent"), f"{context}.parent"),
        "high": high,
    }


def _operand8(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an object")
    kind = value.get("kind")
    if kind == "register":
        payload = _exact_fields(value, {"kind", "register"}, context)
        return {
            "kind": "register",
            **_byte_register(payload.get("register"), f"{context}.register"),
        }
    if kind == "memory":
        payload = _exact_fields(value, {"kind", "address"}, context)
        return {
            "kind": "memory",
            "address": _address(payload.get("address"), f"{context}.address"),
        }
    if kind == "immediate":
        payload = _exact_fields(value, {"kind", "value"}, context)
        return {
            "kind": "immediate",
            "value": _uint(payload.get("value"), 8, f"{context}.value"),
        }
    raise ToolkitInputError(f"{context}.kind is unsupported")


def _shift_count(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ToolkitInputError(f"{context} must be an object")
    kind = value.get("kind")
    if kind == "cl":
        _exact_fields(value, {"kind"}, context)
        return {"kind": "cl"}
    if kind == "immediate":
        payload = _exact_fields(value, {"kind", "value"}, context)
        return {
            "kind": "immediate",
            "value": _uint(payload.get("value"), 8, f"{context}.value"),
        }
    raise ToolkitInputError(f"{context}.kind is unsupported")


def _has_high_byte_register(*values: Mapping[str, Any]) -> bool:
    return any(
        value.get("kind") == "register" and value.get("high") is True
        for value in values
    )


def _operand_access(
    operand: Mapping[str, Any],
    *,
    read: bool,
    write: bool,
    width_bits: int,
    role: str,
) -> tuple[list[str | dict[str, Any]], list[str | dict[str, Any]], list[dict[str, Any]]]:
    reads: list[str | dict[str, Any]] = []
    writes: list[str | dict[str, Any]] = []
    memory: list[dict[str, Any]] = []
    if operand["kind"] == "register":
        register = str(operand["register"])
        location: str | dict[str, Any] = register
        if width_bits == 8:
            location = {
                "register": register,
                "lsb": 8 if operand.get("high") is True else 0,
            }
        if read:
            reads.append(location)
        if write:
            writes.append(location)
    elif operand["kind"] == "memory":
        access = "read_write" if read and write else "read" if read else "write"
        memory.append(
            _memory_effect(
                address=operand["address"],
                access=access,
                width_bits=width_bits,
                role=role,
            )
        )
    elif operand["kind"] != "immediate":
        raise ToolkitInputError("decoded operand kind is invalid")
    return reads, writes, memory


def _relative_target(instruction_size: int, displacement: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    signed = displacement if displacement < sign_bit else displacement - (1 << bits)
    return (_TEST_EIP + instruction_size + signed) & 0xFFFFFFFF


def _branch_effect(
    *,
    control: str,
    target_eip: int | None,
    target: Mapping[str, Any] | None = None,
    outcomes: Sequence[tuple[str, int, int]] = (("taken", 0, 0),),
) -> dict[str, Any]:
    rows = []
    for scenario, mask, value in sorted(outcomes):
        rows.append(
            {
                "scenario": scenario,
                "eflags_mask": mask,
                "eflags_value": value,
                "control": "fallthrough" if scenario == "not_taken" else control,
                "target": (
                    None
                    if scenario == "not_taken"
                    else (
                        dict(target)
                        if target is not None
                        else (
                            None
                            if target_eip is None
                            else {"kind": "fixed", "target_eip": target_eip}
                        )
                    )
                ),
            }
        )
    return {"class": "branch", "id": "branch-control", "outcomes": rows}


def _condition_name(value: Any, context: str) -> str:
    raw = _string(value, context)
    return raw.rsplit(".", 1)[-1]


def _binary_operation(value: Any, context: str) -> tuple[str, int]:
    operation = _condition_name(value, context)
    if operation not in {"add", "sub", "xor", "and", "or", "compare", "test"}:
        raise ToolkitInputError(
            f"{context} is not a reviewed binary operation"
        )
    flags = (
        _LOGICAL_FLAGS
        if operation in {"xor", "and", "or", "test"}
        else _ARITHMETIC_FLAGS
    )
    return operation, flags


def _shift_operation(value: Any, context: str) -> str:
    operation = _condition_name(value, context)
    if operation not in {"left", "right", "arithmeticRight"}:
        raise ToolkitInputError(f"{context} is not a reviewed shift operation")
    return operation


def _shift_eflags(width_bits: int, count: Mapping[str, Any]) -> int | None:
    if count["kind"] == "cl":
        return 0xC5 if width_bits == 32 else 0xC4
    amount = int(count["value"]) % 32
    if amount == 0:
        return None
    mask = 0xC4
    if amount <= width_bits:
        mask |= _CARRY_FLAG
    if amount == 1:
        mask |= 0x800
    return mask


def _condition_inputs(condition: str) -> tuple[tuple[int, int], tuple[int, int]]:
    cf, pf, zf, sf, of = 0x1, 0x4, 0x40, 0x80, 0x800
    table = {
        "overflow": ((of, of), (of, 0)),
        "notOverflow": ((of, 0), (of, of)),
        "equal": ((zf, zf), (zf, 0)),
        "notEqual": ((zf, 0), (zf, zf)),
        "below": ((cf, cf), (cf, 0)),
        "aboveOrEqual": ((cf, 0), (cf, cf)),
        "belowOrEqual": ((cf | zf, zf), (cf | zf, 0)),
        "above": ((cf | zf, 0), (zf, zf)),
        "sign": ((sf, sf), (sf, 0)),
        "notSign": ((sf, 0), (sf, sf)),
        "parity": ((pf, pf), (pf, 0)),
        "notParity": ((pf, 0), (pf, pf)),
        "less": ((sf | of, sf), (sf | of, 0)),
        "greaterOrEqual": ((sf | of, 0), (sf | of, sf)),
        "greater": ((zf | sf | of, 0), (zf, zf)),
        "lessOrEqual": ((zf, zf), (zf | sf | of, 0)),
    }
    try:
        return table[condition]
    except KeyError as exc:
        raise ToolkitInputError(
            f"decoded branch condition {condition!r} is unsupported"
        ) from exc


def _eflags_predicate(condition: str, *, taken: bool = True) -> dict[str, Any]:
    selected = _condition_inputs(condition)[0 if taken else 1]
    return {
        "kind": "eflags",
        "mask": selected[0],
        "value": selected[1],
    }


def _prefix_unresolved_reason(instruction: bytes) -> str | None:
    index = 0
    while index < len(instruction) and instruction[index] in _PREFIXES:
        prefix = instruction[index]
        if prefix in _OTHER_UNRESOLVED_PREFIXES:
            return _OTHER_UNRESOLVED_PREFIXES[prefix]
        index += 1
    return None


def _metadata_has_aliased_address_registers(value: Any) -> bool:
    if isinstance(value, Mapping):
        if set(value) == {
            "base",
            "index",
            "scale_shift",
            "displacement",
        }:
            base = value.get("base")
            return base is not None and base == value.get("index")
        return any(
            _metadata_has_aliased_address_registers(child)
            for child in value.values()
        )
    if isinstance(value, list):
        return any(_metadata_has_aliased_address_registers(child) for child in value)
    return False


def _resolved(
    *,
    effects: Sequence[dict[str, Any]],
    eflags: int,
    gpr_masks: Mapping[str, int] | None = None,
    x87: bool = False,
) -> dict[str, Any]:
    ordered = sorted(effects, key=lambda row: row["id"])
    if not ordered:
        ordered = [{"class": "noop", "id": "noop-core"}]
    return {
        "status": "resolved",
        "required_features": [],
        "effects": ordered,
        "defined_outputs": _defined_outputs(
            eflags,
            gpr_masks=gpr_masks,
            x87=x87,
        ),
    }


def _resolved_x87(
    *,
    effects: Sequence[dict[str, Any]] = (),
    stack_inputs: int,
    stack_outputs: int,
    eflags: int = _ARITHMETIC_FLAGS,
    gpr_masks: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    return _resolved(
        effects=[
            *effects,
            _x87_effect(
                stack_inputs=stack_inputs,
                stack_outputs=stack_outputs,
            ),
        ],
        eflags=eflags,
        gpr_masks=gpr_masks,
        x87=True,
    )


def _resolved_operand_accesses(
    *,
    accesses: Sequence[
        tuple[Mapping[str, Any], bool, bool, int, str]
    ],
    register_reads: Sequence[tuple[str, int]] = (),
    register_writes: Sequence[tuple[str, int]] = (),
    eflags: int,
    gpr_masks: Mapping[str, int] | None = None,
    memory_condition: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    reads_by_width: dict[int, list[str]] = {}
    writes_by_width: dict[int, list[str]] = {}
    for register, width_bits in register_reads:
        reads_by_width.setdefault(width_bits, []).append(register)
    for register, width_bits in register_writes:
        writes_by_width.setdefault(width_bits, []).append(register)
    effects: list[dict[str, Any]] = []
    for operand, read, write, width_bits, role in accesses:
        more_reads, more_writes, more_effects = _operand_access(
            operand,
            read=read,
            write=write,
            width_bits=width_bits,
            role=role,
        )
        if memory_condition is not None:
            for effect in more_effects:
                effect["condition"] = dict(memory_condition)
        reads_by_width.setdefault(width_bits, []).extend(more_reads)
        writes_by_width.setdefault(width_bits, []).extend(more_writes)
        effects.extend(more_effects)
    for width_bits in sorted(set(reads_by_width) | set(writes_by_width)):
        register = _register_effect_around_memory(
            reads=reads_by_width.get(width_bits, ()),
            writes=writes_by_width.get(width_bits, ()),
            effects=effects,
            width_bits=width_bits,
        )
        if register is not None:
            effects.append(register)
    return _resolved(effects=effects, eflags=eflags, gpr_masks=gpr_masks)

from .catalog_enrichment_integer import _derive_integer_enrichment
from .catalog_enrichment_system import _derive_system_enrichment
from .catalog_enrichment_x87 import _derive_x87_enrichment

def _derive_enrichment(
    encoding: Mapping[str, Any],
    decoded: Mapping[str, Any],
) -> dict[str, Any]:
    instruction_bytes = bytes(encoding["instruction_bytes"])
    semantic_form = str(encoding["semantic_form"])
    if decoded.get("status") != "decoded":
        raise ToolkitInputError(
            f"Lean failed to decode proposal encoding {encoding['encoding_id']}"
        )
    decoded = _exact_fields(
        decoded,
        {
            "encoding_id",
            "status",
            "semantic_form",
            "decoded_size",
            "instruction",
        },
        f"Lean metadata for {encoding['encoding_id']}",
    )
    if decoded.get("encoding_id") != encoding["encoding_id"]:
        raise ToolkitInputError("Lean metadata names the wrong encoding")
    if decoded.get("semantic_form") != semantic_form:
        raise ToolkitInputError(
            f"Lean semantic form changed for encoding {encoding['encoding_id']}"
        )
    if decoded.get("decoded_size") != len(instruction_bytes):
        raise ToolkitInputError(
            f"Lean decoded size changed for encoding {encoding['encoding_id']}"
        )
    prefix_reason = _prefix_unresolved_reason(instruction_bytes)
    if prefix_reason is not None:
        return {"status": "unresolved", "reason": prefix_reason}

    instruction = decoded.get("instruction")
    if not isinstance(instruction, Mapping):
        raise ToolkitInputError("Lean decoded instruction metadata must be an object")
    constructor = _string(
        instruction.get("constructor"),
        f"Lean metadata for {encoding['encoding_id']} constructor",
    )
    context = f"Lean metadata for {encoding['encoding_id']} instruction"
    for derive in (
        _derive_integer_enrichment,
        _derive_x87_enrichment,
        _derive_system_enrichment,
    ):
        result = derive(
            instruction_bytes=instruction_bytes,
            semantic_form=semantic_form,
            instruction=instruction,
            constructor=constructor,
            context=context,
        )
        if result is not None:
            return result
    raise ToolkitInputError(
        f"{context}.constructor was not emitted by the reviewed Lean exporter"
    )
