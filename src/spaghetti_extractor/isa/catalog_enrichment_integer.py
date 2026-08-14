"""Integer, control-flow, and operand effect derivation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .catalog_enrichment_derivation import (
    _ARITHMETIC_FLAGS,
    _CARRY_FLAG,
    _LOGICAL_FLAGS,
    _MULTIPLY_FLAGS,
    _ZERO_FLAG,
    _address,
    _binary_operation,
    _branch_effect,
    _byte_register,
    _condition_inputs,
    _condition_name,
    _eflags_predicate,
    _exact_fields,
    _memory_effect,
    _operand32,
    _operand8,
    _operand_access,
    _register,
    _register_effect,
    _register_effect_around_memory,
    _relative_target,
    _resolved,
    _resolved_operand_accesses,
    _shift_count,
    _shift_eflags,
    _shift_operation,
    _signed32,
    _string,
    _uint,
    _width_bits,
    StageAInputError,
)

def _derive_integer_enrichment(
    *,
    instruction_bytes: bytes,
    semantic_form: str,
    instruction: Mapping[str, Any],
    constructor: str,
    context: str,
) -> dict[str, Any] | None:
    if constructor == "nop":
        _exact_fields(instruction, {"constructor"}, context)
        return _resolved(effects=[], eflags=_ARITHMETIC_FLAGS)
    if constructor == "movRegImm":
        row = _exact_fields(
            instruction, {"constructor", "destination", "value"}, context
        )
        destination = _register(row.get("destination"), f"{context}.destination")
        _uint(row.get("value"), 32, f"{context}.value")
        effect = _register_effect(reads=[], writes=[destination])
        return _resolved(effects=[effect] if effect else [], eflags=_ARITHMETIC_FLAGS)
    if constructor == "movRegReg":
        row = _exact_fields(
            instruction, {"constructor", "destination", "source"}, context
        )
        destination = _register(row.get("destination"), f"{context}.destination")
        source = _register(row.get("source"), f"{context}.source")
        effect = _register_effect(reads=[source], writes=[destination])
        return _resolved(effects=[effect] if effect else [], eflags=_ARITHMETIC_FLAGS)
    if constructor in {"addZero", "subZero", "cmpImm", "zeroReg"}:
        expected = (
            {"constructor", "source", "value"}
            if constructor == "cmpImm"
            else {"constructor", "destination"}
        )
        row = _exact_fields(instruction, expected, context)
        if constructor == "cmpImm":
            register = _register(row.get("source"), f"{context}.source")
            _uint(row.get("value"), 32, f"{context}.value")
            reads, writes, flags = [register], [], _ARITHMETIC_FLAGS
        elif constructor == "zeroReg":
            register = _register(row.get("destination"), f"{context}.destination")
            reads, writes, flags = [], [register], _LOGICAL_FLAGS
        else:
            register = _register(row.get("destination"), f"{context}.destination")
            reads, writes, flags = [register], [], _ARITHMETIC_FLAGS
        effect = _register_effect(reads=reads, writes=writes)
        return _resolved(effects=[effect] if effect else [], eflags=flags)
    if constructor in {"jumpRel8", "jumpRel32"}:
        row = _exact_fields(
            instruction, {"constructor", "displacement"}, context
        )
        bits = 8 if constructor == "jumpRel8" else 32
        displacement = _uint(
            row.get("displacement"), bits, f"{context}.displacement"
        )
        target = _relative_target(len(instruction_bytes), displacement, bits)
        return _resolved(
            effects=[
                _branch_effect(control="direct_branch", target_eip=target)
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor in {"branchEqual", "branchCondition"}:
        if constructor == "branchEqual":
            row = _exact_fields(
                instruction,
                {"constructor", "inverted", "displacement"},
                context,
            )
            inverted = row.get("inverted")
            if not isinstance(inverted, bool):
                raise StageAInputError(f"{context}.inverted must be a boolean")
            condition = "notEqual" if inverted else "equal"
            bits = 8
        else:
            row = _exact_fields(
                instruction,
                {"constructor", "condition", "displacement", "size"},
                context,
            )
            condition = _condition_name(row.get("condition"), f"{context}.condition")
            size = _uint(row.get("size"), 8, f"{context}.size")
            if size not in {2, 6}:
                raise StageAInputError(f"{context}.size is not a reviewed branch size")
            bits = 8 if size == 2 else 32
        displacement = _uint(
            row.get("displacement"), bits, f"{context}.displacement"
        )
        target = _relative_target(len(instruction_bytes), displacement, bits)
        taken, not_taken = _condition_inputs(condition)
        return _resolved(
            effects=[
                _branch_effect(
                    control="direct_branch",
                    target_eip=target,
                    outcomes=(
                        ("not_taken", not_taken[0], not_taken[1]),
                        ("taken", taken[0], taken[1]),
                    ),
                )
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "callRel32":
        row = _exact_fields(
            instruction, {"constructor", "displacement"}, context
        )
        displacement = _uint(
            row.get("displacement"), 32, f"{context}.displacement"
        )
        target = _relative_target(len(instruction_bytes), displacement, 32)
        stack = {
            "base": "esp",
            "index": None,
            "scale": 1,
            "displacement": -4,
            "segment": "flat",
        }
        register = _register_effect(reads=[], writes=["esp"])
        effects = [
            _branch_effect(control="direct_call", target_eip=target),
            _memory_effect(
                address=stack,
                access="write",
                width_bits=32,
                role="stack",
            ),
        ]
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"ret", "retPop"}:
        expected = (
            {"constructor", "pop_bytes"}
            if constructor == "retPop"
            else {"constructor"}
        )
        row = _exact_fields(instruction, expected, context)
        if constructor == "retPop":
            _uint(row.get("pop_bytes"), 16, f"{context}.pop_bytes")
        stack = {
            "base": "esp",
            "index": None,
            "scale": 1,
            "displacement": 0,
            "segment": "flat",
        }
        register = _register_effect(reads=[], writes=["esp"])
        effects = [
            _branch_effect(control="return", target_eip=None),
            _memory_effect(
                address=stack,
                access="read",
                width_bits=32,
                role="stack",
            ),
        ]
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"pushReg", "popReg", "pushOperand"}:
        if constructor == "pushReg":
            row = _exact_fields(instruction, {"constructor", "source"}, context)
            source = {
                "kind": "register",
                "register": _register(row.get("source"), f"{context}.source"),
            }
            destination = None
            access = "write"
            displacement = -4
        elif constructor == "popReg":
            row = _exact_fields(
                instruction, {"constructor", "destination"}, context
            )
            source = None
            destination = _register(
                row.get("destination"), f"{context}.destination"
            )
            access = "read"
            displacement = 0
        else:
            row = _exact_fields(instruction, {"constructor", "source"}, context)
            source = _operand32(row.get("source"), f"{context}.source")
            destination = None
            access = "write"
            displacement = -4
        reads = (
            [str(source["register"])]
            if source is not None and source.get("kind") == "register"
            else []
        )
        writes = ["esp"] + ([destination] if destination is not None else [])
        if "esp" in reads:
            reads.remove("esp")
        effects: list[dict[str, Any]] = [
            _memory_effect(
                address={
                    "base": "esp",
                    "index": None,
                    "scale": 1,
                    "displacement": displacement,
                    "segment": "flat",
                },
                access=access,
                width_bits=32,
                role="stack",
            )
        ]
        if source is not None and source.get("kind") == "memory":
            effects.append(
                _memory_effect(
                    address=source["address"],
                    access="read",
                    width_bits=32,
                    role="source",
                )
            )
        register = _register_effect(reads=reads, writes=writes)
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor == "leave":
        _exact_fields(instruction, {"constructor"}, context)
        effects = [
            _memory_effect(
                address={
                    "base": "ebp",
                    "index": None,
                    "scale": 1,
                    "displacement": 0,
                    "segment": "flat",
                },
                access="read",
                width_bits=32,
                role="stack",
            )
        ]
        register = _register_effect_around_memory(
            reads=["ebp"],
            writes=["ebp", "esp"],
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"lea", "load32", "store32"}:
        if constructor == "store32":
            row = _exact_fields(
                instruction, {"constructor", "base", "offset", "source"}, context
            )
            base = _register(row.get("base"), f"{context}.base")
            source = _register(row.get("source"), f"{context}.source")
            offset = _uint(row.get("offset"), 32, f"{context}.offset")
            effects = [
                _memory_effect(
                    address={
                        "base": base,
                        "index": None,
                        "scale": 1,
                        "displacement": _signed32(offset),
                        "segment": "flat",
                    },
                    access="write",
                    width_bits=32,
                    role="destination",
                )
            ]
            register = _register_effect_around_memory(
                reads=[source],
                writes=[],
                effects=effects,
            )
        else:
            row = _exact_fields(
                instruction,
                {"constructor", "destination", "base", "offset"},
                context,
            )
            destination = _register(
                row.get("destination"), f"{context}.destination"
            )
            base = _register(row.get("base"), f"{context}.base")
            offset = _uint(row.get("offset"), 32, f"{context}.offset")
            register = _register_effect(
                reads=[base] if constructor == "lea" else [],
                writes=[destination],
            )
            effects = []
            if constructor == "load32":
                effects.append(
                    _memory_effect(
                        address={
                            "base": base,
                            "index": None,
                            "scale": 1,
                            "displacement": _signed32(offset),
                            "segment": "flat",
                        },
                        access="read",
                        width_bits=32,
                        role="source",
                    )
                )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor == "leaAddress":
        row = _exact_fields(
            instruction, {"constructor", "destination", "source"}, context
        )
        destination = _register(row.get("destination"), f"{context}.destination")
        address = _address(row.get("source"), f"{context}.source")
        reads = [
            register
            for register in (address["base"], address["index"])
            if register is not None
        ]
        register = _register_effect(reads=reads, writes=[destination])
        return _resolved(
            effects=[register] if register is not None else [],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor in {"movFromOperand", "movToOperand", "movImmediate"}:
        if constructor == "movFromOperand":
            row = _exact_fields(
                instruction, {"constructor", "destination", "source"}, context
            )
            destination = {
                "kind": "register",
                "register": _register(
                    row.get("destination"), f"{context}.destination"
                ),
            }
            source = _operand32(row.get("source"), f"{context}.source")
        elif constructor == "movToOperand":
            row = _exact_fields(
                instruction, {"constructor", "destination", "source"}, context
            )
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            source = {
                "kind": "register",
                "register": _register(row.get("source"), f"{context}.source"),
            }
        else:
            row = _exact_fields(
                instruction, {"constructor", "destination", "value"}, context
            )
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            source = {
                "kind": "immediate",
                "value": _uint(row.get("value"), 32, f"{context}.value"),
            }
        reads, writes, effects = _operand_access(
            source,
            read=True,
            write=False,
            width_bits=32,
            role="source",
        )
        more_reads, more_writes, destination_effects = _operand_access(
            destination,
            read=False,
            write=True,
            width_bits=32,
            role="destination",
        )
        reads.extend(more_reads)
        writes.extend(more_writes)
        effects.extend(destination_effects)
        register = _register_effect_around_memory(
            reads=reads,
            writes=writes,
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=_ARITHMETIC_FLAGS)
    if constructor in {"binary", "unary"}:
        if constructor == "binary":
            row = _exact_fields(
                instruction,
                {"constructor", "operation", "destination", "source"},
                context,
            )
            operation, flags = _binary_operation(
                row.get("operation"), f"{context}.operation"
            )
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            source = _operand32(row.get("source"), f"{context}.source")
            writes_destination = operation not in {"compare", "test"}
            reads, writes, effects = _operand_access(
                destination,
                read=True,
                write=writes_destination,
                width_bits=32,
                role="destination",
            )
            more_reads, more_writes, source_effects = _operand_access(
                source,
                read=True,
                write=False,
                width_bits=32,
                role="source",
            )
            reads.extend(more_reads)
            writes.extend(more_writes)
            effects.extend(source_effects)
        else:
            row = _exact_fields(
                instruction,
                {"constructor", "operation", "destination"},
                context,
            )
            operation = _condition_name(
                row.get("operation"), f"{context}.operation"
            )
            if operation not in {
                "bitNot",
                "negate",
                "increment",
                "decrement",
            }:
                raise StageAInputError(
                    f"{context}.operation is not a reviewed unary operation"
                )
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            reads, writes, effects = _operand_access(
                destination,
                read=True,
                write=True,
                width_bits=32,
                role="destination",
            )
            flags = _ARITHMETIC_FLAGS
        register = _register_effect_around_memory(
            reads=reads,
            writes=writes,
            effects=effects,
        )
        if register is not None:
            effects.append(register)
        return _resolved(effects=effects, eflags=flags)
    if constructor in {"shift", "shiftWidth", "shift8"}:
        expected = {"constructor", "operation", "destination", "count"}
        if constructor == "shiftWidth":
            expected.add("width_bits")
        row = _exact_fields(instruction, expected, context)
        _shift_operation(row.get("operation"), f"{context}.operation")
        count = _shift_count(row.get("count"), f"{context}.count")
        if constructor == "shift":
            width_bits = 32
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
        elif constructor == "shiftWidth":
            width_bits = _width_bits(
                row.get("width_bits"), f"{context}.width_bits"
            )
            if width_bits not in {8, 16}:
                raise StageAInputError(
                    f"{context}.width_bits is not a partial operand width"
                )
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
        else:
            width_bits = 8
            destination = _operand8(
                row.get("destination"), f"{context}.destination"
            )
        if destination["kind"] == "immediate":
            raise StageAInputError(f"{context}.destination cannot be immediate")
        eflags = _shift_eflags(width_bits, count)
        if eflags is None:
            return _resolved(effects=[], eflags=0)
        return _resolved_operand_accesses(
            accesses=[
                (
                    destination,
                    True,
                    True,
                    width_bits,
                    "destination",
                )
            ],
            register_reads=(
                [("ecx", 8)] if count["kind"] == "cl" else []
            ),
            eflags=eflags,
            memory_condition=(
                {
                    "kind": "register",
                    "location": {"register": "ecx", "lsb": 0},
                    "width_bits": 8,
                    "mask": 0x1F,
                    "value": 1,
                }
                if destination["kind"] == "memory"
                and count["kind"] == "cl"
                else None
            ),
        )
    if constructor in {
        "movZeroExtend",
        "movSignExtend",
        "movSignExtend8",
        "movSignExtend8ToWord",
    }:
        expected = {"constructor", "destination", "source"}
        if constructor in {"movZeroExtend", "movSignExtend"}:
            expected.add("width_bits")
        row = _exact_fields(instruction, expected, context)
        destination_register = _register(
            row.get("destination"), f"{context}.destination"
        )
        if constructor in {"movZeroExtend", "movSignExtend"}:
            width_bits = _width_bits(
                row.get("width_bits"), f"{context}.width_bits"
            )
            if width_bits not in {8, 16}:
                raise StageAInputError(
                    f"{context}.width_bits is not an extension source width"
                )
            source = _operand32(row.get("source"), f"{context}.source")
        else:
            width_bits = 8
            source = _operand8(row.get("source"), f"{context}.source")
        destination_width = (
            16 if constructor == "movSignExtend8ToWord" else 32
        )
        destination = {
            "kind": "register",
            "register": destination_register,
        }
        return _resolved_operand_accesses(
            accesses=[
                (source, True, False, width_bits, "source"),
                (
                    destination,
                    destination_width < 32,
                    True,
                    destination_width,
                    "destination",
                ),
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor in {
        "movFromOperandWidth",
        "movToOperandWidth",
        "movImmediateWidth",
    }:
        expected = {"constructor", "width_bits", "destination"}
        if constructor == "movFromOperandWidth":
            expected.add("source")
        elif constructor == "movToOperandWidth":
            expected.add("source")
        else:
            expected.add("value")
        row = _exact_fields(instruction, expected, context)
        width_bits = _width_bits(
            row.get("width_bits"), f"{context}.width_bits"
        )
        if width_bits not in {8, 16}:
            raise StageAInputError(
                f"{context}.width_bits is not a partial operand width"
            )
        if constructor == "movFromOperandWidth":
            destination = {
                "kind": "register",
                "register": _register(
                    row.get("destination"), f"{context}.destination"
                ),
            }
            source = _operand32(row.get("source"), f"{context}.source")
        elif constructor == "movToOperandWidth":
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            source = {
                "kind": "register",
                "register": _register(
                    row.get("source"), f"{context}.source"
                ),
            }
        else:
            destination = _operand32(
                row.get("destination"), f"{context}.destination"
            )
            source = {
                "kind": "immediate",
                "value": _uint(
                    row.get("value"), width_bits, f"{context}.value"
                ),
            }
        return _resolved_operand_accesses(
            accesses=[
                (source, True, False, width_bits, "source"),
                (
                    destination,
                    destination["kind"] == "register",
                    True,
                    width_bits,
                    "destination",
                ),
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "binaryWidth":
        row = _exact_fields(
            instruction,
            {
                "constructor",
                "width_bits",
                "operation",
                "destination",
                "source",
            },
            context,
        )
        width_bits = _width_bits(
            row.get("width_bits"), f"{context}.width_bits"
        )
        if width_bits not in {8, 16}:
            raise StageAInputError(
                f"{context}.width_bits is not a partial operand width"
            )
        operation, flags = _binary_operation(
            row.get("operation"), f"{context}.operation"
        )
        destination = _operand32(
            row.get("destination"), f"{context}.destination"
        )
        source = _operand32(row.get("source"), f"{context}.source")
        return _resolved_operand_accesses(
            accesses=[
                (
                    destination,
                    True,
                    operation not in {"compare", "test"},
                    width_bits,
                    "destination",
                ),
                (source, True, False, width_bits, "source"),
            ],
            eflags=flags,
        )
    if constructor in {
        "movFromOperand8",
        "movToOperand8",
        "movImmediate8",
        "binary8",
    }:
        if constructor == "movFromOperand8":
            row = _exact_fields(
                instruction,
                {"constructor", "destination", "source"},
                context,
            )
            destination_register = _byte_register(
                row.get("destination"), f"{context}.destination"
            )
            destination = {
                "kind": "register",
                "register": destination_register["register"],
                "high": destination_register["high"],
            }
            source = _operand8(row.get("source"), f"{context}.source")
            operation = None
            flags = _ARITHMETIC_FLAGS
        elif constructor == "movToOperand8":
            row = _exact_fields(
                instruction,
                {"constructor", "destination", "source"},
                context,
            )
            destination = _operand8(
                row.get("destination"), f"{context}.destination"
            )
            source_register = _byte_register(
                row.get("source"), f"{context}.source"
            )
            source = {
                "kind": "register",
                "register": source_register["register"],
                "high": source_register["high"],
            }
            operation = None
            flags = _ARITHMETIC_FLAGS
        elif constructor == "movImmediate8":
            row = _exact_fields(
                instruction,
                {"constructor", "destination", "value"},
                context,
            )
            destination = _operand8(
                row.get("destination"), f"{context}.destination"
            )
            source = {
                "kind": "immediate",
                "value": _uint(row.get("value"), 8, f"{context}.value"),
            }
            operation = None
            flags = _ARITHMETIC_FLAGS
        else:
            row = _exact_fields(
                instruction,
                {"constructor", "operation", "destination", "source"},
                context,
            )
            operation, flags = _binary_operation(
                row.get("operation"), f"{context}.operation"
            )
            destination = _operand8(
                row.get("destination"), f"{context}.destination"
            )
            source = _operand8(row.get("source"), f"{context}.source")
        writes_destination = (
            operation not in {"compare", "test"}
            if operation is not None
            else True
        )
        reads_destination = (
            operation is not None or destination["kind"] == "register"
        )
        return _resolved_operand_accesses(
            accesses=[
                (
                    destination,
                    reads_destination,
                    writes_destination,
                    8,
                    "destination",
                ),
                (source, True, False, 8, "source"),
            ],
            eflags=flags,
        )
    if constructor == "conditionalMove":
        row = _exact_fields(
            instruction,
            {"constructor", "condition", "destination", "source"},
            context,
        )
        condition = _condition_name(
            row.get("condition"), f"{context}.condition"
        )
        _condition_inputs(condition)
        destination = {
            "kind": "register",
            "register": _register(
                row.get("destination"), f"{context}.destination"
            ),
        }
        source = _operand32(row.get("source"), f"{context}.source")
        return _resolved_operand_accesses(
            accesses=[
                (destination, True, True, 32, "destination"),
                (source, True, False, 32, "source"),
            ],
            eflags=_ARITHMETIC_FLAGS,
            memory_condition=(
                _eflags_predicate(condition)
                if source["kind"] == "memory"
                else None
            ),
        )
    if constructor == "setCondition":
        row = _exact_fields(
            instruction,
            {"constructor", "condition", "destination"},
            context,
        )
        condition = _condition_name(
            row.get("condition"), f"{context}.condition"
        )
        _condition_inputs(condition)
        destination = _operand8(
            row.get("destination"), f"{context}.destination"
        )
        return _resolved_operand_accesses(
            accesses=[
                (
                    destination,
                    destination["kind"] == "register",
                    True,
                    8,
                    "destination",
                ),
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "exchange":
        row = _exact_fields(
            instruction,
            {"constructor", "destination", "source"},
            context,
        )
        destination = _operand32(
            row.get("destination"), f"{context}.destination"
        )
        source = {
            "kind": "register",
            "register": _register(row.get("source"), f"{context}.source"),
        }
        return _resolved_operand_accesses(
            accesses=[
                (destination, True, True, 32, "destination"),
                (source, True, True, 32, "source"),
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "convertWordToDword":
        _exact_fields(instruction, {"constructor"}, context)
        return _resolved(
            effects=[
                {
                    "class": "register",
                    "id": "register-16-gpr",
                    "width_bits": 16,
                    "reads": ["eax"],
                    "writes": [],
                },
                {
                    "class": "register",
                    "id": "register-32-gpr",
                    "width_bits": 32,
                    "reads": [],
                    "writes": ["eax"],
                },
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "convertDwordToQuad":
        _exact_fields(instruction, {"constructor"}, context)
        return _resolved(
            effects=[
                {
                    "class": "register",
                    "id": "register-32-gpr",
                    "width_bits": 32,
                    "reads": ["eax"],
                    "writes": ["edx"],
                }
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor == "binaryCarry":
        row = _exact_fields(
            instruction,
            {"constructor", "subtract", "destination", "source"},
            context,
        )
        if not isinstance(row.get("subtract"), bool):
            raise StageAInputError(f"{context}.subtract must be a boolean")
        destination = _operand32(
            row.get("destination"), f"{context}.destination"
        )
        source = _operand32(row.get("source"), f"{context}.source")
        return _resolved_operand_accesses(
            accesses=[
                (destination, True, True, 32, "destination"),
                (source, True, False, 32, "source"),
            ],
            eflags=_ARITHMETIC_FLAGS,
        )
    if constructor in {"multiplyFull", "multiplyLow"}:
        if constructor == "multiplyFull":
            row = _exact_fields(
                instruction,
                {"constructor", "signed", "source"},
                context,
            )
            signed = row.get("signed")
            if not isinstance(signed, bool):
                raise StageAInputError(f"{context}.signed must be a boolean")
            source = _operand32(row.get("source"), f"{context}.source")
            return _resolved_operand_accesses(
                accesses=[(source, True, False, 32, "source")],
                register_reads=[("eax", 32)],
                register_writes=[("eax", 32), ("edx", 32)],
                eflags=_MULTIPLY_FLAGS,
            )
        row = _exact_fields(
            instruction,
            {"constructor", "destination", "source", "immediate"},
            context,
        )
        destination_register = _register(
            row.get("destination"), f"{context}.destination"
        )
        source = _operand32(row.get("source"), f"{context}.source")
        immediate = row.get("immediate")
        if immediate is not None:
            _uint(immediate, 32, f"{context}.immediate")
        destination = {
            "kind": "register",
            "register": destination_register,
        }
        accesses = [(source, True, False, 32, "source")]
        if immediate is None:
            accesses.append((destination, True, False, 32, "destination"))
        accesses.append((destination, False, True, 32, "destination-output"))
        return _resolved_operand_accesses(
            accesses=accesses,
            eflags=_MULTIPLY_FLAGS,
        )
    if constructor == "doubleShift":
        row = _exact_fields(
            instruction,
            {"constructor", "left", "destination", "source", "count"},
            context,
        )
        if not isinstance(row.get("left"), bool):
            raise StageAInputError(f"{context}.left must be a boolean")
        destination = _operand32(
            row.get("destination"), f"{context}.destination"
        )
        if destination["kind"] == "immediate":
            raise StageAInputError(f"{context}.destination cannot be immediate")
        source = _register(row.get("source"), f"{context}.source")
        count = _shift_count(row.get("count"), f"{context}.count")
        eflags = _shift_eflags(32, count)
        if eflags is None:
            return _resolved(effects=[], eflags=0)
        register_reads = [(source, 32)]
        if count["kind"] == "cl":
            register_reads.append(("ecx", 8))
        return _resolved_operand_accesses(
            accesses=[(destination, True, True, 32, "destination")],
            register_reads=register_reads,
            eflags=eflags,
            memory_condition=(
                {
                    "kind": "register",
                    "location": {"register": "ecx", "lsb": 0},
                    "width_bits": 8,
                    "mask": 0x1F,
                    "value": 1,
                }
                if destination["kind"] == "memory"
                and count["kind"] == "cl"
                else None
            ),
        )
    if constructor == "bitScan":
        row = _exact_fields(
            instruction,
            {"constructor", "operation", "destination", "source"},
            context,
        )
        operation = _string(
            row.get("operation"), f"{context}.operation"
        )
        if not (
            operation.endswith(".forward")
            or operation.endswith(".reverse")
            or ".trailingZeroCount" in operation
        ):
            raise StageAInputError(
                f"{context}.operation is not a reviewed bit-scan operation"
            )
        if ".trailingZeroCount" in operation:
            return {
                "status": "unresolved",
                "reason": "profile_feature_not_representable",
            }
        destination = _register(
            row.get("destination"), f"{context}.destination"
        )
        source = _operand32(row.get("source"), f"{context}.source")
        return _resolved_operand_accesses(
            accesses=[(source, True, False, 32, "source")],
            register_writes=[(destination, 32)],
            eflags=_ZERO_FLAG,
            gpr_masks={destination: 0},
        )
    if constructor == "bitTestRegister":
        row = _exact_fields(
            instruction,
            {"constructor", "base", "index"},
            context,
        )
        base = _register(row.get("base"), f"{context}.base")
        index = _register(row.get("index"), f"{context}.index")
        effect = _register_effect(reads=[base, index], writes=[])
        return _resolved(
            effects=[effect] if effect is not None else [],
            eflags=_CARRY_FLAG,
        )
    return None
