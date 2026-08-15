"""x87 effect derivation for Lean-decoded ISA metadata."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .catalog_enrichment_derivation import (
    _ARITHMETIC_FLAGS,
    _CARRY_FLAG,
    _address,
    _condition_name,
    _exact_fields,
    _memory_effect,
    _register,
    _register_effect,
    _resolved,
    _resolved_x87,
    _uint,
    _x87_format_width,
    _x87_index,
    ToolkitInputError,
)

def _derive_x87_enrichment(
    *,
    instruction_bytes: bytes,
    semantic_form: str,
    instruction: Mapping[str, Any],
    constructor: str,
    context: str,
) -> dict[str, Any] | None:
    if constructor == "x87LoadStack":
        row = _exact_fields(instruction, {"constructor", "index"}, context)
        index = _x87_index(row.get("index"), f"{context}.index")
        inputs = index + 1
        return _resolved_x87(
            stack_inputs=inputs,
            stack_outputs=min(inputs + 1, 8),
        )
    if constructor == "x87LoadConstant":
        row = _exact_fields(instruction, {"constructor", "value"}, context)
        _uint(row.get("value"), 80, f"{context}.value")
        return _resolved_x87(stack_inputs=0, stack_outputs=1)
    if constructor == "x87Exchange":
        row = _exact_fields(instruction, {"constructor", "index"}, context)
        inputs = _x87_index(row.get("index"), f"{context}.index") + 1
        return _resolved_x87(
            stack_inputs=inputs,
            stack_outputs=inputs,
        )
    if constructor == "x87StoreStack":
        row = _exact_fields(
            instruction,
            {"constructor", "index", "pop"},
            context,
        )
        inputs = _x87_index(row.get("index"), f"{context}.index") + 1
        pop = row.get("pop")
        if not isinstance(pop, bool):
            raise ToolkitInputError(f"{context}.pop must be a boolean")
        return _resolved_x87(
            stack_inputs=inputs,
            stack_outputs=max(0, inputs - int(pop)),
        )
    if constructor == "x87Unary":
        row = _exact_fields(
            instruction,
            {"constructor", "operation"},
            context,
        )
        operation = _condition_name(
            row.get("operation"), f"{context}.operation"
        )
        if operation not in {"negate", "sine", "cosine"}:
            raise ToolkitInputError(
                f"{context}.operation is not a reviewed x87 unary operation"
            )
        return _resolved_x87(stack_inputs=1, stack_outputs=1)
    if constructor == "x87BinaryStack":
        row = _exact_fields(
            instruction,
            {"constructor", "operation", "destination", "source", "pop"},
            context,
        )
        operation = _condition_name(
            row.get("operation"), f"{context}.operation"
        )
        if operation not in {
            "add",
            "multiply",
            "subtract",
            "reverseSubtract",
            "divide",
            "reverseDivide",
        }:
            raise ToolkitInputError(
                f"{context}.operation is not a reviewed x87 binary operation"
            )
        destination = _x87_index(
            row.get("destination"), f"{context}.destination"
        )
        source = _x87_index(row.get("source"), f"{context}.source")
        pop = row.get("pop")
        if not isinstance(pop, bool):
            raise ToolkitInputError(f"{context}.pop must be a boolean")
        inputs = max(destination, source) + 1
        return _resolved_x87(
            stack_inputs=inputs,
            stack_outputs=max(0, inputs - int(pop)),
        )
    if constructor == "x87CompareStack":
        row = _exact_fields(
            instruction,
            {"constructor", "mode", "destination", "index", "pop"},
            context,
        )
        mode = _condition_name(row.get("mode"), f"{context}.mode")
        destination = _condition_name(
            row.get("destination"), f"{context}.destination"
        )
        if mode not in {"ordered", "unordered"}:
            raise ToolkitInputError(
                f"{context}.mode is not a reviewed x87 compare mode"
            )
        if destination not in {"status", "eflags"}:
            raise ToolkitInputError(
                f"{context}.destination is not a reviewed x87 compare destination"
            )
        inputs = _x87_index(row.get("index"), f"{context}.index") + 1
        pop = row.get("pop")
        if not isinstance(pop, bool):
            raise ToolkitInputError(f"{context}.pop must be a boolean")
        return _resolved_x87(
            stack_inputs=inputs,
            stack_outputs=max(0, inputs - int(pop)),
            eflags=0x8C5 if destination == "eflags" else _ARITHMETIC_FLAGS,
        )
    if constructor in {
        "x87LoadMemory",
        "x87StoreMemory",
        "x87BinaryMemory",
        "x87CompareMemory",
    }:
        if constructor == "x87StoreMemory":
            row = _exact_fields(
                instruction,
                {"constructor", "format", "destination", "pop"},
                context,
            )
            address = _address(
                row.get("destination"), f"{context}.destination"
            )
            access = "write"
            role = "destination"
            pop = row.get("pop")
            if not isinstance(pop, bool):
                raise ToolkitInputError(f"{context}.pop must be a boolean")
            stack_inputs = 1
            stack_outputs = 0 if pop else 1
        else:
            row = _exact_fields(
                instruction,
                {"constructor", "format", "source"}
                | (
                    {"operation"}
                    if constructor == "x87BinaryMemory"
                    else {"mode", "pop"}
                    if constructor == "x87CompareMemory"
                    else set()
                ),
                context,
            )
            address = _address(row.get("source"), f"{context}.source")
            access = "read"
            role = "source"
            if constructor == "x87BinaryMemory":
                operation = _condition_name(
                    row.get("operation"), f"{context}.operation"
                )
                if operation not in {
                    "add",
                    "multiply",
                    "subtract",
                    "reverseSubtract",
                    "divide",
                    "reverseDivide",
                }:
                    raise ToolkitInputError(
                        f"{context}.operation is not a reviewed x87 binary operation"
                    )
                stack_inputs = stack_outputs = 1
            elif constructor == "x87CompareMemory":
                mode = _condition_name(row.get("mode"), f"{context}.mode")
                if mode not in {"ordered", "unordered"}:
                    raise ToolkitInputError(
                        f"{context}.mode is not a reviewed x87 compare mode"
                    )
                address = _address(row.get("source"), f"{context}.source")
                pop = row.get("pop")
                if not isinstance(pop, bool):
                    raise ToolkitInputError(f"{context}.pop must be a boolean")
                stack_inputs = 1
                stack_outputs = 0 if pop else 1
            else:
                stack_inputs, stack_outputs = 0, 1
        width_bits = _x87_format_width(
            row.get("format"), f"{context}.format"
        )
        return _resolved_x87(
            effects=[
                _memory_effect(
                    address=address,
                    access=access,
                    width_bits=width_bits,
                    role=role,
                )
            ],
            stack_inputs=stack_inputs,
            stack_outputs=stack_outputs,
        )
    if constructor in {"x87LoadControl", "x87StoreControl"}:
        field = "source" if constructor == "x87LoadControl" else "destination"
        row = _exact_fields(instruction, {"constructor", field}, context)
        return _resolved_x87(
            effects=[
                _memory_effect(
                    address=_address(row.get(field), f"{context}.{field}"),
                    access=(
                        "read"
                        if constructor == "x87LoadControl"
                        else "write"
                    ),
                    width_bits=16,
                    role=field,
                )
            ],
            stack_inputs=0,
            stack_outputs=0,
        )
    if constructor in {"x87SaveState", "x87RestoreState"}:
        field = "destination" if constructor == "x87SaveState" else "source"
        row = _exact_fields(instruction, {"constructor", field}, context)
        operand_size_16 = 0x66 in instruction_bytes[:-1]
        return _resolved_x87(
            effects=[
                _memory_effect(
                    address=_address(row.get(field), f"{context}.{field}"),
                    access=(
                        "write"
                        if constructor == "x87SaveState"
                        else "read"
                    ),
                    width_bits=752 if operand_size_16 else 864,
                    role=field,
                )
            ],
            stack_inputs=8 if constructor == "x87SaveState" else 0,
            stack_outputs=0 if constructor == "x87SaveState" else 8,
        )
    if constructor in {"x87Wait", "x87Initialize"}:
        _exact_fields(instruction, {"constructor"}, context)
        return _resolved_x87(
            stack_inputs=0,
            stack_outputs=0,
        )
    if constructor == "x87StoreStatusAx":
        _exact_fields(instruction, {"constructor"}, context)
        register = _register_effect(
            reads=[],
            writes=["eax"],
            width_bits=16,
        )
        return _resolved_x87(
            effects=[register] if register is not None else [],
            stack_inputs=0,
            stack_outputs=0,
        )
    if constructor == "x87Examine":
        _exact_fields(instruction, {"constructor"}, context)
        return _resolved_x87(stack_inputs=1, stack_outputs=1)
    return None
