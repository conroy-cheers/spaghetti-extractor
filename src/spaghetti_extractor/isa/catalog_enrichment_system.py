"""String, system-state, import, and aggregate effect derivation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .catalog_enrichment_derivation import (
    _ARITHMETIC_FLAGS,
    _GPRS,
    _address,
    _branch_effect,
    _exact_fields,
    _memory_effect,
    _operand32,
    _register,
    _register_effect,
    _register_effect_around_memory,
    _resolved,
    _signed32,
    _uint,
    ToolkitInputError,
)

def _derive_system_enrichment(
    *,
    instruction_bytes: bytes,
    semantic_form: str,
    instruction: Mapping[str, Any],
    constructor: str,
    context: str,
) -> dict[str, Any] | None:
    string_widths = {
        "moveBytes": 8,
        "storeBytes": 8,
        "moveWords": 16,
        "storeWords": 16,
        "moveDwords": 32,
        "storeDwords": 32,
    }
    if constructor in string_widths:
        row = _exact_fields(
            instruction, {"constructor", "repeated"}, context
        )
        repeated = row.get("repeated")
        if not isinstance(repeated, bool):
            raise ToolkitInputError(f"{context}.repeated must be a boolean")
        condition = (
            {
                "kind": "register",
                "location": {"register": "ecx", "lsb": 0},
                "width_bits": 32,
                "mask": 0xFFFFFFFF,
                "value": 1,
            }
            if repeated
            else None
        )
        effects: list[dict[str, Any]] = [
            _memory_effect(
                address={
                    "base": "edi",
                    "index": None,
                    "scale": 1,
                    "displacement": 0,
                    "segment": "flat",
                },
                access="write",
                width_bits=string_widths[constructor],
                role="destination",
                condition=condition,
            ),
            {
                "class": "state",
                "id": "state-eflags",
                "state": "eflags",
                "access": "read",
            },
        ]
        is_store = constructor.startswith("store")
        reads = ["edi", "eax"] if is_store else ["esi", "edi"]
        writes = ["edi"]
        if not is_store:
            effects.append(
                _memory_effect(
                    address={
                        "base": "esi",
                        "index": None,
                        "scale": 1,
                        "displacement": 0,
                        "segment": "flat",
                    },
                    access="read",
                    width_bits=string_widths[constructor],
                    role="source",
                    condition=condition,
                )
            )
            writes.append("esi")
        if repeated:
            reads.append("ecx")
            writes.append("ecx")
        register = _register_effect_around_memory(
            reads=reads,
            writes=writes,
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=0)
    if constructor == "movFs32":
        row = _exact_fields(
            instruction, {"constructor", "destination", "source"}, context
        )
        destination = _register(
            row.get("destination"), f"{context}.destination"
        )
        source = _address(row.get("source"), f"{context}.source")
        source["segment"] = "fs"
        effects = [
            _memory_effect(
                address=source,
                access="read",
                width_bits=32,
                role="source",
            ),
            {
                "class": "state",
                "id": "state-fs",
                "state": "fs",
                "access": "read",
            },
        ]
        register = _register_effect_around_memory(
            reads=[],
            writes=[destination],
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor == "movToFs32":
        row = _exact_fields(
            instruction, {"constructor", "destination", "source"}, context
        )
        destination = _address(
            row.get("destination"), f"{context}.destination"
        )
        destination["segment"] = "fs"
        source = _register(row.get("source"), f"{context}.source")
        effects = [
            _memory_effect(
                address=destination,
                access="write",
                width_bits=32,
                role="destination",
            ),
            {
                "class": "state",
                "id": "state-fs",
                "state": "fs",
                "access": "read",
            },
        ]
        register = _register_effect_around_memory(
            reads=[source],
            writes=[],
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor == "atomicCompareExchange":
        row = _exact_fields(
            instruction, {"constructor", "destination", "source"}, context
        )
        destination = _address(
            row.get("destination"), f"{context}.destination"
        )
        source = _register(row.get("source"), f"{context}.source")
        effects = [
            _memory_effect(
                address=destination,
                access="read_write",
                width_bits=32,
                role="destination",
            )
        ]
        register = _register_effect_around_memory(
            reads=["eax", source],
            writes=["eax"],
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"callImport", "jumpImport"}:
        row = _exact_fields(
            instruction,
            {"constructor", "absolute_address"},
            context,
        )
        absolute_address = _uint(
            row.get("absolute_address"),
            32,
            f"{context}.absolute_address",
        )
        effects: list[dict[str, Any]] = [
            _branch_effect(
                control=(
                    "indirect_call"
                    if constructor == "callImport"
                    else "indirect_branch"
                ),
                target_eip=None,
                target={
                    "kind": "memory",
                    "address": {
                        "base": None,
                        "index": None,
                        "scale": 1,
                        "displacement": _signed32(absolute_address),
                        "segment": "flat",
                    },
                },
            )
        ]
        if constructor == "callImport":
            effects.append(
                _memory_effect(
                    address={
                        "base": "esp",
                        "index": None,
                        "scale": 1,
                        "displacement": -4,
                        "segment": "flat",
                    },
                    access="write",
                    width_bits=32,
                    role="stack",
                )
            )
            register = _register_effect(reads=[], writes=["esp"])
            if register is not None:
                effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"divideUnsigned", "divideSigned"}:
        row = _exact_fields(instruction, {"constructor", "source"}, context)
        source = _operand32(row.get("source"), f"{context}.source")
        divisor_register = (
            str(source["register"])
            if source["kind"] == "register"
            else None
        )
        if divisor_register in {"eax", "edx"}:
            return {
                "status": "unresolved",
                "reason": "divide_operand_aliases_implicit_dividend",
            }
        divisor: dict[str, Any]
        if source["kind"] == "register":
            divisor = {
                "kind": "register",
                "location": {"register": divisor_register, "lsb": 0},
            }
        elif source["kind"] == "memory":
            divisor = {
                "kind": "memory",
                "address": source["address"],
            }
        else:
            raise ToolkitInputError(f"{context}.source cannot be immediate")
        return _resolved(
            effects=[
                {
                    "class": "divide",
                    "id": "divide-core",
                    "width_bits": 32,
                    "signed": constructor == "divideSigned",
                    "dividend_high": {"register": "edx", "lsb": 0},
                    "dividend_low": {"register": "eax", "lsb": 0},
                    "divisor": divisor,
                }
            ],
            eflags=0,
        )
    if constructor in {"callIndirect", "jumpIndirect"}:
        row = _exact_fields(
            instruction, {"constructor", "target"}, context
        )
        target_operand = _operand32(row.get("target"), f"{context}.target")
        if target_operand["kind"] == "register":
            target = {
                "kind": "register",
                "location": {
                    "register": target_operand["register"],
                    "lsb": 0,
                },
            }
        elif target_operand["kind"] == "memory":
            target = {
                "kind": "memory",
                "address": target_operand["address"],
            }
        else:
            raise ToolkitInputError(f"{context}.target cannot be immediate")
        effects = [
            _branch_effect(
                control=(
                    "indirect_call"
                    if constructor == "callIndirect"
                    else "indirect_branch"
                ),
                target_eip=None,
                target=target,
            )
        ]
        if constructor == "callIndirect":
            effects.append(
                _memory_effect(
                    address={
                        "base": "esp",
                        "index": None,
                        "scale": 1,
                        "displacement": -4,
                        "segment": "flat",
                    },
                    access="write",
                    width_bits=32,
                    role="stack",
                )
            )
            register = _register_effect(reads=[], writes=["esp"])
            if register is not None:
                effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {
        "pushFlags",
        "popFlags",
        "clearDirection",
        "setDirection",
        "clearCarry",
    }:
        _exact_fields(instruction, {"constructor"}, context)
        effects: list[dict[str, Any]] = [
            {
                "class": "state",
                "id": "state-eflags",
                "state": "eflags",
                "access": (
                    "read"
                    if constructor == "pushFlags"
                    else "write"
                ),
            }
        ]
        if constructor in {"pushFlags", "popFlags"}:
            effects.append(
                _memory_effect(
                    address={
                        "base": "esp",
                        "index": None,
                        "scale": 1,
                        "displacement": (
                            -4 if constructor == "pushFlags" else 0
                        ),
                        "segment": "flat",
                    },
                    access=(
                        "write" if constructor == "pushFlags" else "read"
                    ),
                    width_bits=32,
                    role="stack",
                )
            )
            register = _register_effect(reads=[], writes=["esp"])
            if register is not None:
                effects.append(register)
        return _resolved(
            effects=effects,
            eflags={
                "pushFlags": 0,
                "popFlags": 0x003F7FD7,
                "clearDirection": 0x400,
                "setDirection": 0x400,
                "clearCarry": 0x1,
            }[constructor],
        )
    if constructor == "scanByteNotEqual":
        _exact_fields(instruction, {"constructor"}, context)
        effects = [
            _memory_effect(
                address={
                    "base": "edi",
                    "index": None,
                    "scale": 1,
                    "displacement": 0,
                    "segment": "flat",
                },
                access="read",
                width_bits=8,
                role="source",
                replay_control={
                    "count_location": {"register": "ecx", "lsb": 0},
                    "count_width_bits": 32,
                    "stop_value": {
                        "kind": "register",
                        "location": {"register": "eax", "lsb": 0},
                        "width_bits": 8,
                    },
                },
            )
        ]
        register = _register_effect_around_memory(
            reads=["eax", "ecx", "edi"],
            writes=["ecx", "edi"],
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"pushAll", "popAll"}:
        _exact_fields(instruction, {"constructor"}, context)
        effects = [
            _memory_effect(
                address={
                    "base": "esp",
                    "index": None,
                    "scale": 1,
                    "displacement": -32 if constructor == "pushAll" else 0,
                    "segment": "flat",
                },
                access="write" if constructor == "pushAll" else "read",
                width_bits=256,
                role="stack",
            )
        ]
        register = _register_effect_around_memory(
            reads=list(_GPRS) if constructor == "pushAll" else [],
            writes=(
                ["esp"]
                if constructor == "pushAll"
                else list(_GPRS)
            ),
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    return None
