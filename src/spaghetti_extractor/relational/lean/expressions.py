from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ...stage_binary import StageAInputError
from ..analyses.external import _semantic_external_target_identity
from ..model import _semantic_hash


from .common import (
    _lean_bool,
    _lean_code_aliases,
    _lean_register_pair,
    _lean_register_relation_pair,
)


def _lean_semantic_expr(expression: dict[str, Any]) -> str:
    operation = expression["op"]
    unary = {
        "bit_not": "bitNot",
        "lowest_set_bit": "lowestSetBit",
        "highest_set_bit": "highestSetBit",
    }
    binary = {
        "add": "add",
        "sub": "sub",
        "bit_and": "bitAnd",
        "bit_xor": "bitXor",
        "shift_left_by": "shiftLeftBy",
        "shift_right_by": "shiftRightBy",
        "shift_arithmetic_right_by": "shiftArithmeticRightBy",
        "bit_or": "bitOr",
        "unsigned_less_value": "unsignedLessValue",
        "multiply": "multiply",
        "multiply_high_unsigned": "multiplyHighUnsigned",
        "multiply_high_signed": "multiplyHighSigned",
    }
    if operation == "input_reg":
        return f"StageA.Formal.Expr.inputReg (StageA.Formal.Reg.{expression['reg']})"
    if operation == "input_flag_value":
        return f"StageA.Formal.Expr.inputFlagValue {int(expression['bit'])}"
    if operation == "input_fs_base":
        return "StageA.Formal.Expr.inputFsBase"
    if operation == "input_x87_control":
        return "StageA.Formal.Expr.inputX87Control"
    if operation == "input_x87_status":
        return "StageA.Formal.Expr.inputX87Status"
    if operation == "constant":
        return f"StageA.Formal.Expr.constant {int(expression['value'])}"
    if operation == "undefined":
        return f"StageA.Formal.Expr.undefined {int(expression['slot'])}"
    if operation in unary:
        return f"StageA.Formal.Expr.{unary[operation]} ({_lean_semantic_expr(expression['value'])})"
    if operation in binary:
        return (
            f"StageA.Formal.Expr.{binary[operation]} "
            f"({_lean_semantic_expr(expression['left'])}) "
            f"({_lean_semantic_expr(expression['right'])})"
        )
    if operation in {"shift_left", "shift_right"}:
        constructor = "shiftLeft" if operation == "shift_left" else "shiftRight"
        return (
            f"StageA.Formal.Expr.{constructor} "
            f"({_lean_semantic_expr(expression['value'])}) {int(expression['amount'])}"
        )
    if operation in {"extract_byte", "bit_value"}:
        constructor = "extractByte" if operation == "extract_byte" else "bitValue"
        return (
            f"StageA.Formal.Expr.{constructor} "
            f"({_lean_semantic_expr(expression['value'])}) {int(expression['index'])}"
        )
    if operation in {"read8", "read32"}:
        return (
            f"StageA.Formal.Expr.{operation} "
            f"({_lean_semantic_expr(expression['address'])})"
        )
    if operation == "read8_after_write":
        return (
            "StageA.Formal.Expr.read8AfterWrite "
            f"({_lean_semantic_expr(expression['address'])}) "
            f"({_lean_semantic_expr(expression['write_address'])}) "
            f"({_lean_semantic_expr(expression['write_value'])}) "
            f"({_lean_semantic_expr(expression['prior'])})"
        )
    if operation == "if_equal":
        return (
            "StageA.Formal.Expr.ifEqual "
            f"({_lean_semantic_expr(expression['left'])}) "
            f"({_lean_semantic_expr(expression['right'])}) "
            f"({_lean_semantic_expr(expression['then'])}) "
            f"({_lean_semantic_expr(expression['else'])})"
        )
    if operation in {"divide_quotient", "divide_remainder", "division_valid_value"}:
        constructor = {
            "divide_quotient": "divideQuotient",
            "divide_remainder": "divideRemainder",
            "division_valid_value": "divisionValidValue",
        }[operation]
        return (
            f"StageA.Formal.Expr.{constructor} "
            f"({_lean_semantic_expr(expression['high'])}) "
            f"({_lean_semantic_expr(expression['low'])}) "
            f"({_lean_semantic_expr(expression['divisor'])})"
        )
    if operation == "x87_part":
        return (
            "StageA.Formal.Expr.x87Part "
            f"({_lean_semantic_x87_expr(expression['value'])}) {int(expression['part'])}"
        )
    if operation == "x87_compare_bit":
        return (
            "StageA.Formal.Expr.x87CompareBit "
            f"({_lean_semantic_x87_expr(expression['left'])}) "
            f"({_lean_semantic_x87_expr(expression['right'])}) "
            f"({_lean_semantic_expr(expression['control'])}) {int(expression['bit'])}"
        )
    if operation == "x87_examine_status":
        return (
            "StageA.Formal.Expr.x87ExamineStatus "
            f"({_lean_semantic_x87_expr(expression['value'])}) "
            f"({_lean_semantic_expr(expression['status'])})"
        )
    raise StageAInputError(f"unsupported semantic expression operation {operation!r}")

def _lean_register_offset_witness(witness: dict[str, Any]) -> str:
    kind = str(witness["kind"])
    if kind == "input":
        return "RegisterOffsetWitness.input"
    constructor = {
        "add_right": "addRight",
        "add_left": "addLeft",
        "sub_right": "subRight",
    }.get(kind)
    if constructor is None:
        raise StageAInputError(f"unsupported register-offset witness: {kind}")
    prior = _lean_register_offset_witness(witness["prior"])
    value = int(witness["value"])
    if kind == "add_left":
        return f"RegisterOffsetWitness.{constructor} {value} ({prior})"
    return f"RegisterOffsetWitness.{constructor} ({prior}) {value}"

def _lean_return_slot_offset_pair(offsets: dict[str, Any]) -> str:
    return (
        "{ originalRegister := ."
        f"{str(offsets.get('original_register', 'esp'))}, originalOffset := BitVec.ofNat 32 "
        f"{int(offsets['original'])}, candidateOffset := BitVec.ofNat 32 "
        f"{int(offsets['candidate'])}, candidateRegister := ."
        f"{str(offsets.get('candidate_register', 'esp'))} }}"
    )

def _lean_register_offset_write(write: dict[str, Any]) -> str:
    return (
        "{ register := ." + str(write["register"])
        + ", offset := " + str(int(write["offset"]))
        + ", value := " + _lean_semantic_expr(write["value"])
        + " }"
    )

def _lean_immutable_indirect_jump_claim(candidate: dict[str, Any]) -> str:
    original_writes = ", ".join(
        _lean_register_offset_write(write)
        for write in candidate.get("original_writes", [])
    )
    candidate_writes = ", ".join(
        _lean_register_offset_write(write)
        for write in candidate.get("candidate_writes", [])
    )
    return (
        "{\n"
        f"  targetId := {int(candidate['target_id'])}\n"
        f"  originalAddress := {int(candidate['original_address'])}\n"
        f"  candidateAddress := {int(candidate['candidate_address'])}\n"
        f"  originalAssembledRead := "
        f"{_lean_bool(bool(candidate['original_assembled_read']))}\n"
        f"  candidateAssembledRead := "
        f"{_lean_bool(bool(candidate['candidate_assembled_read']))}\n"
        f"  originalWrites := [{original_writes}]\n"
        f"  candidateWrites := [{candidate_writes}]\n"
        "}"
    )

def _lean_import_register_seed_claim(candidate: dict[str, Any]) -> str:
    original_writes = ", ".join(
        _lean_register_offset_write(write)
        for write in candidate.get("original_writes", [])
    )
    candidate_writes = ", ".join(
        _lean_register_offset_write(write)
        for write in candidate.get("candidate_writes", [])
    )
    return (
        "{\n"
        f"  imported := {_lean_external_target(candidate['import'])}\n"
        f"  originalRegister := .{candidate['original_register']}\n"
        f"  candidateRegister := .{candidate['candidate_register']}\n"
        f"  originalIatRva := {int(candidate['original_iat_rva'])}\n"
        f"  candidateIatRva := {int(candidate['candidate_iat_rva'])}\n"
        f"  assembledRead := {_lean_bool(bool(candidate.get('assembled_read')))}\n"
        f"  originalWrites := [{original_writes}]\n"
        f"  candidateWrites := [{candidate_writes}]\n"
        "}"
    )

def _lean_external_target(imported: dict[str, Any]) -> str:
    def bytes_literal(value: str) -> str:
        return "[" + ", ".join(str(byte) for byte in value.encode("utf-8")) + "]"

    if "symbol" in imported:
        name = f"(.symbol {bytes_literal(str(imported['symbol']))})"
    elif "ordinal" in imported:
        name = f"(.ordinal {int(imported['ordinal'])})"
    else:
        raise StageAInputError("import target has neither symbol nor ordinal")
    return f"{{ dll := {bytes_literal(str(imported['dll']))}, name := {name} }}"

def _lean_machine_call_memory_size(size: dict[str, Any]) -> str:
    if size["kind"] == "fixed":
        return f".fixed {int(size['bytes'])}"
    if size["kind"] == "argument":
        return f".argument {int(size['argument'])} {int(size['scale'])}"
    if size["kind"] == "product":
        return (
            f".product {int(size['left_argument'])} "
            f"{int(size['right_argument'])}"
        )
    sentinel = ", ".join(str(int(byte)) for byte in size.get("sentinel", []))
    if size["kind"] == "bounded_terminated":
        return (
            f".boundedTerminated {int(size['source_argument'])} "
            f"{int(size['source_offset'])} {int(size['unit_bytes'])} "
            f"[{sentinel}] {int(size['max_units'])}"
        )
    if size["kind"] == "argument_or_bounded_terminated":
        return (
            f".argumentOrBoundedTerminated {int(size['length_argument'])} "
            f"{int(size['terminated_value'])} {int(size['source_argument'])} "
            f"{int(size['source_offset'])} {int(size['unit_bytes'])} "
            f"[{sentinel}] {int(size['max_units'])}"
        )
    raise StageAInputError(f"unsupported machine-call memory size {size!r}")

def _lean_machine_call_memory_footprint(footprint: dict[str, Any]) -> str:
    return (
        "{ "
        f"access := .{footprint['access']}, "
        f"baseArgument := {int(footprint['base_argument'])}, "
        f"offset := {int(footprint['offset'])}, "
        f"size := {_lean_machine_call_memory_size(footprint['size'])}, "
        f"nullable := {str(bool(footprint.get('nullable', False))).lower()} "
        "}"
    )

def _lean_machine_import_call_contract(contract: dict[str, Any]) -> str:
    offsets = ", ".join(
        str(int(offset)) for offset in contract["stack_argument_offsets"]
    )
    preserved = ", ".join(
        f".{register}" for register in contract["preserved_registers"]
    )
    clobbered = ", ".join(
        f".{register}" for register in contract["clobbered_registers"]
    )
    def result_relation_kind(relation: dict[str, Any]) -> str:
        if relation["relation"] == "related_word":
            return ".relatedWord"
        if relation["relation"] == "dynamic_range_base":
            relation_kinds = {
                "related_word": "relatedWord",
                "code_pointer": "codePointer",
                "data_pointer": "dataPointer",
                "nullable_dynamic_pointer": "nullableDynamicPointer",
            }
            required_words = ", ".join(
                "{ offset := " + str(int(word["offset"]))
                + ", kind := ." + relation_kinds[word["relation"]] + " }"
                for word in relation["required_words"]
            )
            return (
                ".dynamicRangeBase "
                f"({_lean_machine_call_memory_size(relation['size'])}) "
                f"{int(relation['minimum_size'])} [{required_words}] "
                f"{str(bool(relation['nullable'])).lower()}"
            )
        return f".{relation['relation']}"

    result_relations = ", ".join(
        "{ register := ." + relation["register"]
        + ", relation := " + result_relation_kind(relation) + " }"
        for relation in contract.get("result_register_relations", [])
    )
    footprints = ", ".join(
        _lean_machine_call_memory_footprint(footprint)
        for footprint in contract.get("memory_footprints", [])
    )
    world_effect = f".{contract['world_effect']}"
    if contract["world_effect"] in {
        "dynamicRangeRelease", "callbackRegistration",
    }:
        world_effect += f" {int(contract['world_effect_argument'])}"
    return (
        "{ "
        f"id := {int(contract['id'])}, "
        f"imported := {_lean_external_target(contract['import'])}, "
        f"stackArgumentOffsets := [{offsets}], "
        f"stackResultDelta := {int(contract['stack_result_delta'])}, "
        f"preservedRegisters := [{preserved}], "
        f"clobberedRegisters := [{clobbered}], "
        f"resultRegisterRelations := [{result_relations}], "
        f"disposition := .{contract['disposition']}, "
        f"memoryEffect := .{contract['memory_effect']}, "
        f"memoryFootprints := [{footprints}], "
        f"worldEffect := {world_effect} "
        "}"
    )

def _lean_semantic_x87_expr(expression: dict[str, Any]) -> str:
    operation = expression["op"]
    if operation == "input_stack":
        return f"StageA.Formal.X87Expr.inputStack {int(expression['index'])}"
    if operation == "constant":
        return f"StageA.Formal.X87Expr.constant {int(expression['value'])}"
    if operation == "load":
        return (
            f"StageA.Formal.X87Expr.load .{expression['format']} "
            f"({_lean_semantic_expr(expression['address'])}) "
            f"({_lean_semantic_expr(expression['control'])})"
        )
    if operation == "image_load":
        return (
            f"StageA.Formal.X87Expr.imageLoad .{expression['format']} "
            f"{int(expression['raw'])} ({_lean_semantic_expr(expression['control'])})"
        )
    if operation == "unary":
        return (
            f"StageA.Formal.X87Expr.unary .{expression['operation']} "
            f"({_lean_semantic_x87_expr(expression['value'])}) "
            f"({_lean_semantic_expr(expression['control'])})"
        )
    if operation == "binary":
        operation_name = {
            "add": "add", "multiply": "multiply", "subtract": "subtract",
            "reverse_subtract": "reverseSubtract", "divide": "divide",
            "reverse_divide": "reverseDivide",
        }[expression["operation"]]
        return (
            f"StageA.Formal.X87Expr.binary .{operation_name} "
            f"({_lean_semantic_x87_expr(expression['left'])}) "
            f"({_lean_semantic_x87_expr(expression['right'])}) "
            f"({_lean_semantic_expr(expression['control'])})"
        )
    if operation == "store":
        return (
            f"StageA.Formal.X87Expr.store .{expression['format']} "
            f"({_lean_semantic_x87_expr(expression['value'])}) "
            f"({_lean_semantic_expr(expression['control'])})"
        )
    raise StageAInputError(f"unsupported x87 invariant expression operation {operation!r}")

def _lean_symbolic_x87_state(state: dict[str, Any]) -> str:
    stack = ", ".join(
        _lean_semantic_x87_expr(expression)
        for expression in state.get("stack", [])
    )
    return (
        "{ stack := [" + stack + "], control := "
        + _lean_semantic_expr(state["control"])
        + ", status := " + _lean_semantic_expr(state["status"])
        + " }"
    )

def _semantic_masked_successor_shape(
    predicate: dict[str, Any],
) -> dict[str, Any] | None:
    if predicate.get("op") != "or" or predicate.get("left", {}).get("op") != "and":
        return None
    conjunction = predicate["left"]
    right = predicate.get("right", {})
    if right.get("op") != "unsigned_less":
        return None
    first = conjunction.get("left", {})
    second = conjunction.get("right", {})
    if first.get("op") != "not" or second.get("op") != "not":
        return None
    lower_test = first.get("value", {})
    nonzero_test = second.get("value", {})
    if lower_test.get("op") != "unsigned_less" or nonzero_test.get("op") != "equal":
        return None
    upper_constant = right.get("right", {})
    if upper_constant.get("op") != "constant":
        return None
    masked_value = right.get("left", {})
    if masked_value.get("op") != "bit_and":
        return None
    mask_constant = masked_value.get("right", {})
    if mask_constant.get("op") != "constant":
        return None
    mask = int(mask_constant["value"])
    limit = mask + 1
    if limit <= 1 or limit & (limit - 1) or limit > 2 ** 32:
        return None
    bits = limit.bit_length() - 1

    def masked_constant(value: dict[str, Any]) -> int | None:
        if value.get("op") == "constant":
            return int(value["value"])
        if value.get("op") != "bit_and":
            return None
        left = value.get("left", {})
        right_value = value.get("right", {})
        if left.get("op") != "constant" or right_value.get("op") != "constant":
            return None
        if int(right_value["value"]) != mask:
            return None
        return int(left["value"]) & mask

    threshold = masked_constant(lower_test.get("right", {}))
    if threshold is None or int(upper_constant["value"]) != threshold + 1:
        return None

    def collapse_repeated_mask(value: dict[str, Any]) -> dict[str, Any]:
        current = value
        while (
            current.get("op") == "bit_and"
            and current.get("right", {}).get("op") == "constant"
            and int(current["right"]["value"]) == mask
            and current.get("left", {}).get("op") == "bit_and"
            and current["left"].get("right", {}).get("op") == "constant"
            and int(current["left"]["right"]["value"]) == mask
        ):
            current = current["left"]
        return current

    if _semantic_hash(collapse_repeated_mask(lower_test["left"])) != _semantic_hash(masked_value):
        return None
    zero_side = None
    for value, zero in (
        (nonzero_test.get("left", {}), nonzero_test.get("right", {})),
        (nonzero_test.get("right", {}), nonzero_test.get("left", {})),
    ):
        if zero.get("op") == "constant" and int(zero["value"]) == 0:
            zero_side = value
            break
    if zero_side is None:
        return None
    masked_difference = collapse_repeated_mask(zero_side)
    if (
        masked_difference.get("op") != "bit_and"
        or masked_difference.get("right", {}).get("op") != "constant"
        or int(masked_difference["right"]["value"]) != mask
    ):
        return None
    difference = masked_difference.get("left", {})
    if (
        difference.get("op") != "sub"
        or _semantic_hash(difference.get("left", {})) != _semantic_hash(masked_value)
        or masked_constant(difference.get("right", {})) != threshold
    ):
        return None
    return {
        "masked_value": masked_value,
        "lower_expression": lower_test["left"],
        "difference_expression": zero_side,
        "upper_expression": right["left"],
        "mask": mask,
        "limit": limit,
        "bits": bits,
        "threshold": threshold,
    }

def _lean_masked_successor_tautology_proof(
    precondition_name: str, predicate: dict[str, Any],
) -> list[str] | None:
    shape = _semantic_masked_successor_shape(predicate)
    if shape is None:
        return None
    bits = shape["bits"]
    threshold = shape["threshold"]
    base = _lean_semantic_expr(shape["masked_value"]["left"])
    return [
        f"    have shape : {precondition_name} =",
        f"        InvariantWP.maskedSuccessorPredicate ({base}) {bits} "
        f"{threshold} := by decide",
        "    rw [shape]",
        f"    exact InvariantWP.maskedSuccessorPredicate_eval ({base}) {bits} "
        f"{threshold} state (by decide) (by decide)",
    ]

def _semantic_successor_shape(predicate: dict[str, Any]) -> dict[str, Any] | None:
    if predicate.get("op") != "or" or predicate.get("left", {}).get("op") != "and":
        return None
    conjunction = predicate["left"]
    upper_test = predicate.get("right", {})
    first = conjunction.get("left", {})
    second = conjunction.get("right", {})
    if (
        upper_test.get("op") != "unsigned_less"
        or first.get("op") != "not"
        or second.get("op") != "not"
    ):
        return None
    lower_test = first.get("value", {})
    nonzero_test = second.get("value", {})
    if lower_test.get("op") != "unsigned_less" or nonzero_test.get("op") != "equal":
        return None
    lower = lower_test.get("right", {})
    upper = upper_test.get("right", {})
    if lower.get("op") != "constant" or upper.get("op") != "constant":
        return None
    threshold = int(lower["value"])
    if int(upper["value"]) != threshold + 1:
        return None
    base = upper_test.get("left", {})
    if _semantic_hash(lower_test.get("left", {})) != _semantic_hash(base):
        return None
    difference = None
    for value, zero in (
        (nonzero_test.get("left", {}), nonzero_test.get("right", {})),
        (nonzero_test.get("right", {}), nonzero_test.get("left", {})),
    ):
        if zero.get("op") == "constant" and int(zero["value"]) == 0:
            difference = value
            break
    if (
        difference is None
        or difference.get("op") != "sub"
        or _semantic_hash(difference.get("left", {})) != _semantic_hash(base)
        or difference.get("right", {}).get("op") != "constant"
        or int(difference["right"]["value"]) != threshold
    ):
        return None
    return {"base": base, "threshold": threshold}

def _lean_successor_tautology_proof(
    precondition_name: str, predicate: dict[str, Any],
) -> list[str] | None:
    shape = _semantic_successor_shape(predicate)
    if shape is None:
        return None
    base = _lean_semantic_expr(shape["base"])
    threshold = shape["threshold"]
    return [
        f"    have shape : {precondition_name} =",
        f"        InvariantWP.successorRangePredicate ({base}) {threshold} := by decide",
        "    rw [shape]",
        f"    exact InvariantWP.successorRangePredicate_eval ({base}) {threshold} "
        "state (by decide)",
    ]

def _lean_semantic_bool_expr(expression: dict[str, Any]) -> str:
    operation = expression["op"]
    if operation == "bool_constant":
        constant = "0" if expression["value"] else "1"
        return (
            "StageA.Formal.BoolExpr.equal "
            "(StageA.Formal.Expr.constant 0) "
            f"(StageA.Formal.Expr.constant {constant})"
        )
    if operation == "input_flag":
        return f"StageA.Formal.BoolExpr.inputFlag {int(expression['index'])}"
    if operation == "not":
        return (
            "StageA.Formal.BoolExpr.not "
            f"({_lean_semantic_bool_expr(expression['value'])})"
        )
    if operation in {"and", "or", "xor"}:
        return (
            f"StageA.Formal.BoolExpr.{operation} "
            f"({_lean_semantic_bool_expr(expression['left'])}) "
            f"({_lean_semantic_bool_expr(expression['right'])})"
        )
    if operation in {"equal", "unsigned_less"}:
        constructor = "equal" if operation == "equal" else "unsignedLess"
        return (
            f"StageA.Formal.BoolExpr.{constructor} "
            f"({_lean_semantic_expr(expression['left'])}) "
            f"({_lean_semantic_expr(expression['right'])})"
        )
    if operation in {"msb", "bit"}:
        suffix = "" if operation == "msb" else f" {int(expression['index'])}"
        return (
            f"StageA.Formal.BoolExpr.{operation} "
            f"({_lean_semantic_expr(expression['value'])}){suffix}"
        )
    if operation == "division_valid":
        return (
            "StageA.Formal.BoolExpr.divisionValid "
            f"({_lean_semantic_expr(expression['high'])}) "
            f"({_lean_semantic_expr(expression['low'])}) "
            f"({_lean_semantic_expr(expression['divisor'])})"
        )
    raise StageAInputError(f"unsupported invariant predicate operation {operation!r}")


def _lean_paired_static_expr_witness(witness: dict[str, Any]) -> str:
    kind = str(witness["kind"])
    if kind == "constant":
        return (
            "PairedStaticExprWitness.constant "
            f"{int(witness['original'])} {int(witness['candidate'])}"
        )
    if kind == "read32":
        return (
            "PairedStaticExprWitness.read32 "
            f"{int(witness['original_address'])} "
            f"{int(witness['candidate_address'])}"
        )
    if kind == "binary":
        operation = {
            "add": "add",
            "sub": "sub",
            "bit_and": "bitAnd",
            "bit_xor": "bitXor",
            "shift_left_by": "shiftLeftBy",
            "shift_right_by": "shiftRightBy",
            "shift_arithmetic_right_by": "shiftArithmeticRightBy",
            "bit_or": "bitOr",
            "unsigned_less_value": "unsignedLessValue",
            "multiply": "multiply",
            "multiply_high_unsigned": "multiplyHighUnsigned",
            "multiply_high_signed": "multiplyHighSigned",
        }.get(str(witness["operation"]))
        if operation is None:
            raise StageAInputError(
                f"unsupported paired static binary witness {witness!r}"
            )
        return (
            f"PairedStaticExprWitness.binary .{operation} "
            f"({_lean_paired_static_expr_witness(witness['left'])}) "
            f"({_lean_paired_static_expr_witness(witness['right'])})"
        )
    raise StageAInputError(f"unsupported paired static expression witness {witness!r}")


def _lean_paired_exact_expr_witness(witness: dict[str, Any]) -> str:
    kind = str(witness["kind"])
    if kind == "input_reg":
        return (
            "PairedExactExprWitness.inputReg ."
            f"{witness['original']} .{witness['candidate']}"
        )
    if kind == "input_flag_value":
        return f"PairedExactExprWitness.inputFlagValue {int(witness['bit'])}"
    nullary = {
        "input_fs_base": "inputFsBase",
        "input_x87_control": "inputX87Control",
        "input_x87_status": "inputX87Status",
    }
    if kind in nullary:
        return f"PairedExactExprWitness.{nullary[kind]}"
    if kind == "constant":
        return f"PairedExactExprWitness.constant {int(witness['value'])}"
    if kind == "undefined":
        return f"PairedExactExprWitness.undefined {int(witness['slot'])}"
    if kind in {"read8", "read32"}:
        return (
            f"PairedExactExprWitness.{kind} "
            f"{int(witness['original_address'])} "
            f"{int(witness['candidate_address'])}"
        )
    if kind in {"read8_at", "read32_at"}:
        constructor = "read8At" if kind == "read8_at" else "read32At"
        return (
            f"PairedExactExprWitness.{constructor} "
            f"({_lean_paired_static_expr_witness(witness['address'])})"
        )
    if kind == "binary":
        operation = {
            "add": "add",
            "sub": "sub",
            "bit_and": "bitAnd",
            "bit_xor": "bitXor",
            "shift_left_by": "shiftLeftBy",
            "shift_right_by": "shiftRightBy",
            "shift_arithmetic_right_by": "shiftArithmeticRightBy",
            "bit_or": "bitOr",
            "unsigned_less_value": "unsignedLessValue",
            "multiply": "multiply",
            "multiply_high_unsigned": "multiplyHighUnsigned",
            "multiply_high_signed": "multiplyHighSigned",
        }.get(str(witness["operation"]))
        if operation is None:
            raise StageAInputError(
                f"unsupported paired exact binary witness {witness!r}"
            )
        return (
            f"PairedExactExprWitness.binary .{operation} "
            f"({_lean_paired_exact_expr_witness(witness['left'])}) "
            f"({_lean_paired_exact_expr_witness(witness['right'])})"
        )
    if kind == "unary":
        operation = {
            "bit_not": "bitNot",
            "lowest_set_bit": "lowestSetBit",
            "highest_set_bit": "highestSetBit",
        }.get(str(witness["operation"]))
        if operation is None:
            raise StageAInputError(
                f"unsupported paired exact unary witness {witness!r}"
            )
        return (
            f"PairedExactExprWitness.unary .{operation} "
            f"({_lean_paired_exact_expr_witness(witness['value'])})"
        )
    if kind == "indexed":
        operation = {
            "extract_byte": "extractByte",
            "shift_left": "shiftLeft",
            "shift_right": "shiftRight",
            "bit_value": "bitValue",
        }.get(str(witness["operation"]))
        if operation is None:
            raise StageAInputError(
                f"unsupported paired exact indexed witness {witness!r}"
            )
        return (
            f"PairedExactExprWitness.indexed .{operation} "
            f"{int(witness['index'])} "
            f"({_lean_paired_exact_expr_witness(witness['value'])})"
        )
    if kind == "if_equal":
        return (
            "PairedExactExprWitness.ifEqual "
            f"({_lean_paired_exact_expr_witness(witness['left'])}) "
            f"({_lean_paired_exact_expr_witness(witness['right'])}) "
            f"({_lean_paired_exact_expr_witness(witness['then'])}) "
            f"({_lean_paired_exact_expr_witness(witness['else'])})"
        )
    if kind == "ternary":
        operation = {
            "divide_quotient": "divideQuotient",
            "divide_remainder": "divideRemainder",
            "division_valid_value": "divisionValidValue",
        }.get(str(witness["operation"]))
        if operation is None:
            raise StageAInputError(
                f"unsupported paired exact ternary witness {witness!r}"
            )
        return (
            f"PairedExactExprWitness.ternary .{operation} "
            f"({_lean_paired_exact_expr_witness(witness['high'])}) "
            f"({_lean_paired_exact_expr_witness(witness['low'])}) "
            f"({_lean_paired_exact_expr_witness(witness['divisor'])})"
        )
    raise StageAInputError(f"unsupported paired exact expression witness {witness!r}")


def _lean_stack_window(window: dict[str, Any]) -> str:
    return (
        "{ rangeId := " + str(int(window["range_id"]))
        + ", originalRegister := ." + str(window["original_register"])
        + ", candidateRegister := ." + str(window["candidate_register"])
        + ", bytesBelow := " + str(int(window["bytes_below"]))
        + ", bytesAbove := " + str(int(window["bytes_above"]))
        + " }"
    )

def _lean_paired_stack_word_value_claim(claim: dict[str, Any]) -> str:
    profile = claim.get("profile")
    if profile == "exact_inputs_v1":
        witness = ".exactInputs"
    elif profile == "register_argument_v1":
        witness = (
            ".registerArgument "
            + _lean_register_argument_claim(claim["claim"])
        )
    elif profile == "mapped_code_target_v1":
        witness = ".mappedCodeTarget " + str(int(claim["target_id"]))
    elif profile == "mapped_data_target_v1":
        witness = ".mappedDataTarget " + str(int(claim["target_id"]))
    elif profile == "dynamic_range_v1":
        witness = ".dynamicRange " + _lean_dynamic_range_relation(
            claim["relation"]
        )
    else:
        raise StageAInputError(
            f"unsupported paired stack-word value profile {profile!r}"
        )
    return (
        "{ original := " + _lean_semantic_expr(claim["original"])
        + ", candidate := " + _lean_semantic_expr(claim["candidate"])
        + ", witness := " + witness + " }"
    )

def _lean_paired_stack_word_write_claim(claim: dict[str, Any]) -> str:
    return (
        "{ window := " + _lean_stack_window(claim["window"])
        + ", amount := " + str(int(claim["amount"]))
        + ", value := " + _lean_paired_stack_word_value_claim(claim["value"])
        + " }"
    )

def _lean_paired_stack_word_writes_claim(claim: dict[str, Any]) -> str:
    writes = ", ".join(
        "{ amount := " + str(int(write["amount"]))
        + ", value := " + _lean_paired_stack_word_value_claim(write["value"])
        + " }"
        for write in claim["writes"]
    )
    return (
        "{ window := " + _lean_stack_window(claim["window"])
        + ", writes := [" + writes + "] }"
    )

def _lean_direct_call_stack_writes_claim(claim: dict[str, Any]) -> str:
    return (
        "{ stackWrites := "
        + _lean_paired_stack_word_writes_claim(claim["stack_writes"])
        + ", stackAmount := " + str(int(claim["stack_amount"]))
        + ", calleeTargetId := " + str(int(claim["callee_target_id"]))
        + ", continuationTargetId := "
        + str(int(claim["continuation_target_id"]))
        + ", originalReturnAddress := "
        + str(int(claim["original_return_address"]))
        + ", candidateReturnAddress := "
        + str(int(claim["candidate_return_address"]))
        + ", indirect := " + ("true" if bool(claim.get("indirect")) else "false")
        + " }"
    )


def _lean_paired_prepared_word_write_item(write: dict[str, Any]) -> str:
    if write["kind"] == "stack":
        return (
            ".stack " + _lean_stack_window(write["window"])
            + " " + str(int(write["amount"]))
            + " " + _lean_paired_stack_word_value_claim(write["value"])
        )
    if write["kind"] == "static_word":
        return (
            ".staticWord " + str(int(write["slot_id"]))
            + " " + str(int(write["original_address"]))
            + " " + str(int(write["candidate_address"]))
            + " " + _lean_paired_stack_word_value_claim(write["value"])
        )
    if write["kind"] == "dynamic_word":
        relation = write["relation"]
        return (
            ".dynamicWord " + _lean_dynamic_range_relation(
                write["source_relation"]
            )
            + " { offset := " + str(int(relation["offset"]))
            + ", kind := ." + str(relation["kind"]) + " }"
            + " " + str(int(write["original_amount"]))
            + " " + str(int(write["candidate_amount"]))
            + " " + _lean_paired_stack_word_value_claim(write["value"])
        )
    if write["kind"] == "static_dynamic_pointer":
        return (
            ".staticDynamicPointer " + str(int(write["slot_id"]))
            + " " + str(int(write["original_address"]))
            + " " + str(int(write["candidate_address"]))
            + " " + _lean_dynamic_range_relation(write["source_relation"])
            + " " + _lean_paired_stack_word_value_claim(write["value"])
        )
    raise StageAInputError(
        f"unsupported paired prepared-word location {write['kind']!r}"
    )


def _lean_paired_prepared_word_writes_claim(claim: dict[str, Any]) -> str:
    writes = [
        _lean_paired_prepared_word_write_item(write) for write in claim["writes"]
    ]
    return "{ writes := [" + ", ".join(writes) + "] }"


def _lean_prepared_dynamic_stack_spill_claim(claim: dict[str, Any]) -> str:
    suffix = ", ".join(
        _lean_paired_prepared_word_write_item(write)
        for write in claim.get("suffix", [])
    )
    return (
        "{ sourceRelation := "
        + _lean_dynamic_range_relation(claim["source_relation"])
        + ", targetRelation := "
        + _lean_dynamic_stack_range_relation(claim["target_relation"])
        + ", window := " + _lean_stack_window(claim["window"])
        + ", amount := " + str(int(claim["amount"]))
        + ", suffix := [" + suffix + "] }"
    )


def _lean_direct_call_prepared_writes_claim(claim: dict[str, Any]) -> str:
    return (
        "{ preparedWrites := "
        + _lean_paired_prepared_word_writes_claim(claim["prepared_writes"])
        + ", returnWindow := " + _lean_stack_window(claim["return_window"])
        + ", stackAmount := " + str(int(claim["stack_amount"]))
        + ", calleeTargetId := " + str(int(claim["callee_target_id"]))
        + ", continuationTargetId := "
        + str(int(claim["continuation_target_id"]))
        + ", originalReturnAddress := "
        + str(int(claim["original_return_address"]))
        + ", candidateReturnAddress := "
        + str(int(claim["candidate_return_address"]))
        + ", indirect := " + ("true" if bool(claim.get("indirect")) else "false")
        + " }"
    )

def _lean_state_invariant(invariant: dict[str, Any]) -> str:
    register_relations = ", ".join(
        _lean_register_relation_pair(pair)
        for pair in invariant.get("register_relations", [])
    )
    import_relations = ", ".join(
        "{ original := ." + str(pair["original"])
        + ", candidate := ." + str(pair["candidate"])
        + ", imported := " + _lean_external_target(pair["import"]) + " }"
        for pair in invariant.get("import_register_relations", [])
    )
    dynamic_relations = ", ".join(
        _lean_dynamic_range_relation(relation)
        for relation in invariant.get("dynamic_register_range_relations", [])
    )
    dynamic_stack_relations = ", ".join(
        _lean_dynamic_stack_range_relation(relation)
        for relation in invariant.get("dynamic_stack_range_relations", [])
    )
    bounds = ", ".join(
        f"{{ original := .{bound['original']}, candidate := .{bound['candidate']}, "
        + (
            "originalExpression := some ("
            + _lean_semantic_expr(bound["original_expression"])
            + "), candidateExpression := some ("
            + _lean_semantic_expr(bound["candidate_expression"])
            + "), "
            if "original_expression" in bound and "candidate_expression" in bound
            else ""
        )
        + f"upperExclusive := {bound['unsigned_lt']} }}"
        for bound in invariant.get("bounds", [])
    )
    flags = ", ".join(str(bit) for bit in invariant.get("flag_bits", []))
    separations = ", ".join(
        _lean_address_separation(separation)
        for separation in invariant.get("address_separations", [])
    )
    windows = ", ".join(
        _lean_stack_window(window)
        for window in invariant.get("stack_windows", [])
    )
    return (
        "{ registerRelations := [" + register_relations
        + "], importRegisterRelations := [" + import_relations
        + "], dynamicRegisterRangeRelations := [" + dynamic_relations
        + "], dynamicStackRangeRelations := [" + dynamic_stack_relations
        + "], bounds := [" + bounds
        + "], flagBits := [" + flags
        + "], addressSeparations := [" + separations
        + "], stackWindows := [" + windows + "] }"
    )

def _lean_dynamic_range_relation(relation: dict[str, Any]) -> str:
    words = ", ".join(
        "{ offset := " + str(int(word["offset"]))
        + ", kind := ." + str(word["kind"]) + " }"
        for word in relation.get("required_words", [])
    )
    active_words = ", ".join(
        "{ offset := " + str(int(word["offset"]))
        + ", kind := ." + str(word["kind"]) + " }"
        for word in relation.get("active_words", relation.get("required_words", []))
    )
    return (
        "{ original := ." + str(relation["original"])
        + ", candidate := ." + str(relation["candidate"])
        + ", originalOffset := " + str(int(relation.get("original_offset", 0)))
        + ", candidateOffset := " + str(int(relation.get("candidate_offset", 0)))
        + ", requiredWords := [" + words
        + "], activeWords := [" + active_words + "] }"
    )


def _lean_dynamic_stack_range_relation(relation: dict[str, Any]) -> str:
    words = ", ".join(
        "{ offset := " + str(int(word["offset"]))
        + ", kind := ." + str(word["kind"]) + " }"
        for word in relation.get("required_words", [])
    )
    active_words = ", ".join(
        "{ offset := " + str(int(word["offset"]))
        + ", kind := ." + str(word["kind"]) + " }"
        for word in relation.get("active_words", relation.get("required_words", []))
    )
    return (
        "{ window := " + _lean_stack_window(relation["window"])
        + ", stackOffset := " + str(int(relation["stack_offset"]))
        + ", originalOffset := " + str(int(relation.get("original_offset", 0)))
        + ", candidateOffset := " + str(int(relation.get("candidate_offset", 0)))
        + ", requiredWords := [" + words
        + "], activeWords := [" + active_words + "] }"
    )

def _lean_static_dynamic_pointer_slot(slot: dict[str, Any]) -> str:
    words = ", ".join(
        "{ offset := " + str(int(word["offset"]))
        + ", kind := ." + str(word["kind"]) + " }"
        for word in slot.get("required_words", [])
    )
    return (
        "{ id := " + str(int(slot["id"]))
        + ", originalAddress := BitVec.ofNat 32 "
        + str(int(slot["original_address"]))
        + ", candidateAddress := BitVec.ofNat 32 "
        + str(int(slot["candidate_address"]))
        + ", requiredWords := [" + words + "] }"
    )

def _lean_static_word_relation_slot(slot: dict[str, Any]) -> str:
    relation = {
        "exact": "exact",
        "related_word": "relatedWord",
        "relatedWord": "relatedWord",
        "code_pointer": "codePointer",
        "codePointer": "codePointer",
        "data_pointer": "dataPointer",
        "dataPointer": "dataPointer",
    }.get(str(slot["relation"]))
    if relation is None:
        if str(slot["relation"]) in {"fixed_code_pointer", "fixedCodePointer"}:
            target_id = int(slot["target_id"])
            relation = f"fixedCodePointer {target_id}"
        else:
            raise StageAInputError(
                f"unsupported static word relation {slot['relation']!r}"
            )
    return (
        "{ id := " + str(int(slot["id"]))
        + ", originalAddress := BitVec.ofNat 32 "
        + str(int(slot["original_address"]))
        + ", candidateAddress := BitVec.ofNat 32 "
        + str(int(slot["candidate_address"]))
        + ", relation := ." + relation + " }"
    )

def _lean_stack_adjustment(adjustment: dict[str, Any]) -> str:
    kind = str(adjustment["kind"])
    if kind == "identity":
        return ".identity"
    if kind not in {"add", "subtract"}:
        raise StageAInputError(f"unsupported stack adjustment {kind!r}")
    return f".{kind} {int(adjustment['amount'])}"


def _lean_stack_window_transfer_claim(claim: dict[str, Any]) -> str:
    adjustment_row = _lean_stack_adjustment(claim["adjustment"])
    return (
        "{ source := " + _lean_stack_window(claim["source"])
        + ", target := " + _lean_stack_window(claim["target"])
        + ", adjustment := " + adjustment_row
        + " }"
    )

def _lean_dynamic_range_argument_claim(claim: dict[str, Any]) -> str:
    word = claim["word_relation"]
    return (
        "{ rangeRelation := "
        + _lean_dynamic_range_relation(claim["range_relation"])
        + ", wordRelation := { offset := " + str(int(word["offset"]))
        + ", kind := ." + str(word["kind"])
        + " }, originalReadOffset := " + str(int(claim["original_read_offset"]))
        + ", candidateReadOffset := " + str(int(claim["candidate_read_offset"]))
        + " }"
    )

def _lean_stack_window_argument_claim(claim: dict[str, Any]) -> str:
    return (
        "{ window := " + _lean_stack_window(claim["window"])
        + ", offset := " + str(int(claim["offset"]))
        + ", originalAssembledRead := "
        + _lean_bool(bool(claim["original_assembled_read"]))
        + ", candidateAssembledRead := "
        + _lean_bool(bool(claim["candidate_assembled_read"]))
        + " }"
    )

def _lean_register_argument_claim(claim: dict[str, Any]) -> str:
    return (
        "{ relation := " + _lean_register_relation_pair(claim["relation"])
        + ", offset := " + str(int(claim["offset"])) + " }"
    )

def _lean_register_output_claim(claim: dict[str, Any]) -> str:
    kind = claim["kind"]
    if kind == "exact_expression":
        return (
            "InvariantWP.RegisterOutputClaim.exactExpression { output := "
            + _lean_register_relation_pair(claim["output"])
            + ", expression := " + _lean_semantic_expr(claim["expression"])
            + " }"
        )
    if kind == "exact_memory":
        return (
            "InvariantWP.RegisterOutputClaim.exactMemory { output := "
            + _lean_register_relation_pair(claim["output"])
            + ", expression := " + _lean_semantic_expr(claim["expression"])
            + " }"
        )
    if kind == "identity":
        return (
            "InvariantWP.RegisterOutputClaim.identity { input := "
            + _lean_register_relation_pair(claim["input"])
            + ", output := " + _lean_register_relation_pair(claim["output"])
            + " }"
        )
    if kind == "constant":
        return (
            "InvariantWP.RegisterOutputClaim.constant { output := "
            + _lean_register_relation_pair(claim["output"])
            + ", originalValue := " + str(claim["original_value"])
            + ", candidateValue := " + str(claim["candidate_value"])
            + " }"
        )
    if kind == "immutable_image_word":
        return (
            "InvariantWP.RegisterOutputClaim.immutableImageWord { output := "
            + _lean_register_relation_pair(claim["output"])
            + ", originalAddress := " + str(claim["original_address"])
            + ", candidateAddress := " + str(claim["candidate_address"])
            + ", originalValue := " + str(claim["original_value"])
            + ", candidateValue := " + str(claim["candidate_value"])
            + " }"
        )
    if kind == "static_word_slot":
        return (
            "InvariantWP.RegisterOutputClaim.staticWordSlot { output := "
            + _lean_register_relation_pair(claim["output"])
            + ", slot := " + _lean_static_word_relation_slot(claim["slot"])
            + ", originalAddress := " + str(claim["original_address"])
            + ", candidateAddress := " + str(claim["candidate_address"])
            + " }"
        )
    if kind == "stack_read32_sub":
        return (
            "InvariantWP.RegisterOutputClaim.stackRead32Sub { output := "
            + _lean_register_relation_pair(claim["output"])
            + ", window := " + _lean_stack_window(claim["window"])
            + ", offset := " + str(claim["offset"])
            + ", subtract := " + str(claim["subtract"])
            + ", originalDirectRead := "
            + _lean_bool(bool(claim.get("original_direct_read")))
            + ", candidateDirectRead := "
            + _lean_bool(bool(claim.get("candidate_direct_read")))
            + ", originalDirectAddress := "
            + _lean_bool(bool(claim.get("original_direct_address")))
            + ", candidateDirectAddress := "
            + _lean_bool(bool(claim.get("candidate_direct_address")))
            + " }"
        )
    if kind == "stack_read32_relative":
        return (
            "InvariantWP.RegisterOutputClaim.stackRead32Relative { output := "
            + _lean_register_relation_pair(claim["output"])
            + ", window := " + _lean_stack_window(claim["window"])
            + ", adjustment := " + _lean_stack_adjustment(claim["adjustment"])
            + " }"
        )
    if kind == "stack_window_identity":
        return (
            "InvariantWP.RegisterOutputClaim.stackWindowIdentity { output := "
            + _lean_register_relation_pair(claim["output"])
            + ", window := " + _lean_stack_window(claim["window"])
            + " }"
        )
    raise StageAInputError(f"unsupported register output claim {kind!r}")

def _lean_address_separation(separation: dict[str, Any]) -> str:
    return (
        "{ originalRegister := ." + str(separation["original_register"])
        + ", candidateRegister := ." + str(separation["candidate_register"])
        + ", originalOffset := " + str(int(separation["original_offset"]))
        + ", candidateOffset := " + str(int(separation["candidate_offset"]))
        + ", originalAddress := " + str(int(separation["original_address"]))
        + ", candidateAddress := " + str(int(separation["candidate_address"]))
        + " }"
    )

def _lean_stack_address_separation_claim(claim: dict[str, Any]) -> str:
    return (
        "{ window := " + _lean_stack_window(claim["window"])
        + ", separation := " + _lean_address_separation(claim["separation"])
        + " }"
    )

def _lean_region_definition(index: int, region: dict[str, Any]) -> str:
    input_rows = ", ".join(_lean_register_pair(pair) for pair in region["inputs"])
    output_rows = ", ".join(_lean_register_pair(pair) for pair in region["outputs"])
    input_relation_rows = ", ".join(
        _lean_register_relation_pair(pair) for pair in region.get("input_relations", [])
    )
    output_relation_rows = ", ".join(
        _lean_register_relation_pair(pair) for pair in region.get("output_relations", [])
    )
    input_import_relation_rows = ", ".join(
        "{ original := ." + str(pair["original"])
        + ", candidate := ." + str(pair["candidate"])
        + ", imported := " + _lean_external_target(pair["import"]) + " }"
        for pair in region.get("input_import_relations", [])
    )
    output_import_relation_rows = ", ".join(
        "{ original := ." + str(pair["original"])
        + ", candidate := ." + str(pair["candidate"])
        + ", imported := " + _lean_external_target(pair["import"]) + " }"
        for pair in region.get("output_import_relations", [])
    )
    input_dynamic_relation_rows = ", ".join(
        _lean_dynamic_range_relation(relation)
        for relation in region.get("input_dynamic_range_relations", [])
    )
    output_dynamic_relation_rows = ", ".join(
        _lean_dynamic_range_relation(relation)
        for relation in region.get("output_dynamic_range_relations", [])
    )
    input_dynamic_stack_relation_rows = ", ".join(
        _lean_dynamic_stack_range_relation(relation)
        for relation in region.get("input_dynamic_stack_range_relations", [])
    )
    output_dynamic_stack_relation_rows = ", ".join(
        _lean_dynamic_stack_range_relation(relation)
        for relation in region.get("output_dynamic_stack_range_relations", [])
    )
    bound_rows = ", ".join(
        f"{{ original := .{bound['original']}, candidate := .{bound['candidate']}, "
        + (
            "originalExpression := some ("
            + _lean_semantic_expr(bound["original_expression"])
            + "), candidateExpression := some ("
            + _lean_semantic_expr(bound["candidate_expression"])
            + "), "
            if "original_expression" in bound and "candidate_expression" in bound
            else ""
        )
        + f"upperExclusive := {bound['unsigned_lt']} }}"
        for bound in region.get("bounds", [])
    )
    target_rows = ", ".join(
        f"{{ id := {target['id']}, regionIndex := {target['region_index']}, originalRva := {target['original_rva']}, candidateRva := {target['candidate_rva']}, "
        f"originalAliases := {_lean_code_aliases(target, 'original')}, candidateAliases := {_lean_code_aliases(target, 'candidate')} }}"
        for target in region.get("code_targets", [])
    )
    value_rows = _lean_region_value_targets(region)
    flag_inputs = ", ".join(str(bit) for bit in region.get("flag_inputs", []))
    flag_outputs = ", ".join(str(bit) for bit in region.get("flag_outputs", []))
    separation_rows = ", ".join(
        "{ originalRegister := ." + separation["original_register"]
        + ", candidateRegister := ." + separation["candidate_register"]
        + ", originalOffset := " + str(separation["original_offset"])
        + ", candidateOffset := " + str(separation["candidate_offset"])
        + ", originalAddress := " + str(separation["original_address"])
        + ", candidateAddress := " + str(separation["candidate_address"])
        + " }"
        for separation in region.get("address_separations", [])
    )
    stack_window_rows = ", ".join(
        "{ rangeId := " + str(int(window["range_id"]))
        + ", originalRegister := ." + str(window["original_register"])
        + ", candidateRegister := ." + str(window["candidate_register"])
        + ", bytesBelow := " + str(int(window["bytes_below"]))
        + ", bytesAbove := " + str(int(window["bytes_above"]))
        + " }"
        for window in region.get("stack_windows", [])
    )
    return (
        f"def region{index} : RegionRelation := {{ id := {region['numeric_id']}, root := {_lean_bool(region['root'])}, "
        f"original := {{ start := {region['original']['rva_start']}, size := {region['original']['size']} }}, "
        f"candidate := {{ start := {region['candidate']['rva_start']}, size := {region['candidate']['size']} }}, "
        f"inputs := [{input_rows}], outputs := [{output_rows}], "
        f"inputRelations := [{input_relation_rows}], outputRelations := [{output_relation_rows}], "
        f"inputImportRelations := [{input_import_relation_rows}], "
        f"outputImportRelations := [{output_import_relation_rows}], "
        f"inputDynamicRangeRelations := [{input_dynamic_relation_rows}], "
        f"outputDynamicRangeRelations := [{output_dynamic_relation_rows}], "
        f"inputDynamicStackRangeRelations := [{input_dynamic_stack_relation_rows}], "
        f"outputDynamicStackRangeRelations := [{output_dynamic_stack_relation_rows}], "
        f"bounds := [{bound_rows}], "
        f"flagInputs := [{flag_inputs}], flagOutputs := [{flag_outputs}], "
        f"addressSeparations := [{separation_rows}], "
        f"stackWindows := [{stack_window_rows}], "
        f"targets := [{target_rows}], values := [{value_rows}] }}"
    )

def _lean_value_target(target: dict[str, Any]) -> str:
    return (
        "{ id := " + str(target["id"])
        + ", originalValue := " + str(target["original_value"])
        + ", candidateValue := " + str(target["candidate_value"])
        + ", originalRelocationRva := " + str(target["original_relocation_rva"])
        + ", candidateRelocationRva := " + str(target["candidate_relocation_rva"])
        + ", mappedSize := " + str(target["mapped_size"])
        + ", relocationOffsets := ["
        + ", ".join(str(offset) for offset in target.get("relocation_offsets", []))
        + "] }"
    )

def _lean_region_value_targets(region: dict[str, Any]) -> str:
    return ", ".join(
        _lean_value_target(target)
        for target in region.get("values", [])
    )

def _lean_region_memory_lemmas(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str:
    name = f"region{index}"
    mapped = [target for target in region.get("values", []) if target["mapped_size"] > 0]
    if not mapped:
        return ""
    rows: list[str] = []
    lemma_index = 0
    for target, offset in _lean_region_static_memory_lemma_specs(region, behaviors):
        rows.append(
            f"theorem {name}MappedAddress{lemma_index} : "
            f"normalizeDataAddress {name}.values "
            f"(BitVec.ofNat 32 {target['candidate_value'] + offset}) = "
            f"BitVec.ofNat 32 {target['original_value'] + offset} := by decide"
        )
        lemma_index += 1
    for indexed_index, (target, upper, shift, offset) in enumerate(
        _lean_region_indexed_memory_lemma_specs(region)
    ):
        scaled = (
            "index"
            if shift == 0
            else f"(index <<< {shift})"
        )
        proof_scaled = (
            "index"
            if shift == 0
            else f"(BitVec.extractLsb' 0 {32 - shift} index ++ BitVec.ofNat {shift} 0)"
        )
        shift_rewrite = (
            "  · rw [BitVec.shiftLeft_eq_concat_of_lt (by decide)]\n    "
            if shift > 0 else "  · "
        )
        candidate_address = target["candidate_value"] + offset
        original_address = target["original_value"] + offset
        zero_prefix_rewrites = "".join(
            "  simp only [normalizeDataAddress_cons_zero (target := "
            + _lean_value_target(zero_target)
            + ") (zero := rfl)]\n"
            for zero_target in region.get("values", [])[:-1]
        )
        rows.append(
            f"theorem {name}MappedIndexedAddress{indexed_index} (index : Word) "
            f"(bounded : index < BitVec.ofNat 32 {upper}) :\n"
            f"    normalizeDataAddress {name}.values "
            f"({scaled} + BitVec.ofNat 32 {candidate_address}) =\n"
            f"      {scaled} + BitVec.ofNat 32 {original_address} := by\n"
            + f"  unfold {name}\n"
            + zero_prefix_rewrites
            + f"  rw [normalizeDataAddress_singleton_of_contains]\n"
            + shift_rewrite
            + f"change BitVec.ofNat 32 {target['original_value']} + "
            f"({proof_scaled} + BitVec.ofNat 32 {candidate_address} - "
            f"BitVec.ofNat 32 {target['candidate_value']}) = "
            f"{proof_scaled} + BitVec.ofNat 32 {original_address}\n"
            f"    bv_normalize\n"
            f"  · simp [valueTargetContainsCandidate]\n"
            f"    bv_omega"
        )
    for relocation_index, (target, offset, _) in enumerate(
        _lean_region_static_relocation_word_specs(region, behaviors)
    ):
        rows.append(
            f"theorem {name}RelocationWordStartStatic{relocation_index} : "
            f"relocationWordStartCandidate {name}.values "
            f"(BitVec.ofNat 32 {target['candidate_value'] + offset}) = true := by decide"
        )
    for relocation_index, (target, upper, shift, offset, _) in enumerate(
        _lean_region_indexed_relocation_word_specs(region)
    ):
        scaled = "index" if shift == 0 else f"(index <<< {shift})"
        rows.append(
            f"theorem {name}RelocationWordStartIndexed{relocation_index} "
            f"(index : Word) (bounded : index < BitVec.ofNat 32 {upper}) :\n"
            f"    relocationWordStartCandidate {name}.values "
            f"({scaled} + BitVec.ofNat 32 {target['candidate_value'] + offset}) = true := by\n"
            f"  simp [relocationWordStartCandidate, valueRelocationWordStartCandidate, {name}]\n"
            f"  bv_omega"
        )
    return "\n\n".join(rows)

def _lean_region_static_memory_lemma_specs(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> list[tuple[dict[str, Any], int]]:
    candidate_constants = {
        int(value)
        for value in re.findall(
            r"StageA\.Formal\.Expr\.constant (\d+)",
            behaviors["candidate"],
        )
    }
    return [
        (target, constant - target["candidate_value"])
        for target in region.get("values", [])
        if target["mapped_size"] > 0
        for constant in sorted(candidate_constants)
        if target["candidate_value"] <= constant < target["candidate_value"] + target["mapped_size"]
    ]

def _lean_region_indexed_memory_lemma_specs(
    region: dict[str, Any],
) -> list[tuple[dict[str, Any], int, int, int]]:
    values = region.get("values", [])
    mapped_indices = [
        value_index for value_index, target in enumerate(values)
        if target["mapped_size"] > 0
    ]
    if len(mapped_indices) != 1 or mapped_indices[0] != len(values) - 1:
        return []
    if any(target["mapped_size"] != 0 for target in values[:-1]):
        return []
    target = values[-1]
    specs: list[tuple[dict[str, Any], int, int, int]] = []
    for upper in sorted({bound["unsigned_lt"] for bound in region.get("bounds", [])}):
        if upper <= 0 or target["mapped_size"] % upper != 0:
            continue
        element_size = target["mapped_size"] // upper
        if element_size not in {1, 2, 4, 8}:
            continue
        shift = element_size.bit_length() - 1
        specs.extend((target, upper, shift, offset) for offset in range(element_size))
    return specs

def _lean_region_static_relocation_word_specs(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> list[tuple[dict[str, Any], int, int]]:
    return [
        (target, offset, address_index)
        for address_index, (target, offset) in enumerate(
            _lean_region_static_memory_lemma_specs(region, behaviors)
        )
        if offset in target.get("relocation_offsets", [])
    ]

def _lean_region_indexed_relocation_word_specs(
    region: dict[str, Any],
) -> list[tuple[dict[str, Any], int, int, int, int]]:
    address_specs = _lean_region_indexed_memory_lemma_specs(region)
    result: list[tuple[dict[str, Any], int, int, int, int]] = []
    seen: set[tuple[int, int, int, int]] = set()
    for target, upper, shift, _ in address_specs:
        element_size = 1 << shift
        for word_offset in range(0, element_size - 3, 4):
            key = (target["id"], upper, shift, word_offset)
            required = {
                index * element_size + word_offset for index in range(upper)
            }
            if key in seen or not required.issubset(set(target.get("relocation_offsets", []))):
                continue
            seen.add(key)
            address_index = next(
                index for index, spec in enumerate(address_specs)
                if spec == (target, upper, shift, word_offset)
            )
            result.append((target, upper, shift, word_offset, address_index))
    return result

def _lean_region_memory_lemma_names(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> list[str]:
    static = [
        f"region{index}MappedAddress{offset}"
        for offset in range(len(_lean_region_static_memory_lemma_specs(region, behaviors)))
    ]
    indexed = [
        f"region{index}MappedIndexedAddressFact{offset}"
        for offset in range(len(_lean_region_indexed_memory_lemma_specs(region)))
    ]
    static_relocations = [
        name
        for offset in range(len(_lean_region_static_relocation_word_specs(region, behaviors)))
        for name in (
            f"region{index}RelocationWordRelatedStatic{offset}",
            f"region{index}RelocationWordZeroStatic{offset}",
            f"region{index}RelocationOriginalRead32Static{offset}",
            f"region{index}RelocationCandidateRead32Static{offset}",
        )
    ]
    indexed_relocations = [
        name
        for offset in range(len(_lean_region_indexed_relocation_word_specs(region)))
        for name in (
            f"region{index}RelocationWordRelatedIndexed{offset}",
            f"region{index}RelocationWordZeroIndexed{offset}",
        )
    ]
    return static + indexed + static_relocations + indexed_relocations

def _lean_region_indexed_memory_fact_names(index: int, region: dict[str, Any]) -> list[str]:
    return [
        f"region{index}MappedIndexedAddressFact{offset}"
        for offset in range(len(_lean_region_indexed_memory_lemma_specs(region)))
    ]

def _lean_region_bound_setup(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str:
    bounds = region.get("bounds", [])
    specs = _lean_region_indexed_memory_lemma_specs(region)
    if not specs:
        return ""
    rows: list[str] = []
    if len(bounds) > 1:
        hypotheses = ", ".join(f"boundSatisfied{bound_index}" for bound_index in range(len(bounds)))
        rows.append(f"  rcases boundsSatisfied with ⟨{hypotheses}⟩")
    for spec_index, (_, upper, _, _) in enumerate(specs):
        bound_index = next(
            bound_index for bound_index, bound in enumerate(bounds)
            if bound["unsigned_lt"] == upper
        )
        hypothesis = "boundsSatisfied" if len(bounds) == 1 else f"boundSatisfied{bound_index}"
        bound = bounds[bound_index]
        index_value = _lean_bound_index_value(bound, "original", "o")
        rows.append(
            f"  have region{index}MappedIndexedAddressFact{spec_index} := "
            f"region{index}MappedIndexedAddress{spec_index} {index_value} "
            f"(by simpa [boundValue, evalExprPure, StageA.Formal.Registers.get] using {hypothesis})"
        )
        rows.append(
            f"  simp [evalExprPure, StageA.Formal.Registers.get] at "
            f"region{index}MappedIndexedAddressFact{spec_index}"
        )
    for mask_index, (register, mask, upper) in enumerate(
        _lean_region_index_masks(region, behaviors)
    ):
        bound_index = next(
            bound_index for bound_index, bound in enumerate(bounds)
            if bound["original"] == register and bound["unsigned_lt"] == upper
        )
        hypothesis = "boundsSatisfied" if len(bounds) == 1 else f"boundSatisfied{bound_index}"
        mask_width = (mask + 1).bit_length() - 1
        rows.append(
            f"  have region{index}IndexMaskFact{mask_index} : "
            f"o{register} &&& BitVec.ofNat 32 {mask} = o{register} := by\n"
            f"    apply BitVec.eq_of_toNat_eq\n"
            f"    simp only [BitVec.toNat_and, BitVec.toNat_ofNat]\n"
            f"    change o{register}.toNat &&& 2 ^ {mask_width} - 1 = o{register}.toNat\n"
            f"    apply Nat.and_two_pow_sub_one_of_lt_two_pow (n := {mask_width})\n"
            f"    have boundedNat : o{register}.toNat < {upper} := by\n"
            f"      simpa [BitVec.lt_def] using {hypothesis}\n"
            f"    omega"
        )
    return "\n".join(rows) + "\n"

def _lean_bound_index_value(bound: dict[str, Any], side: str, prefix: str) -> str:
    expression = bound.get(f"{side}_expression")
    if expression is None:
        return f"{prefix}{bound[side]}"
    registers = ", ".join(
        f"{register} := {prefix}{register}"
        for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    )
    return (
        "((evalExprPure "
        f"({{ {registers} }} : PureState) "
        f"({_lean_semantic_expr(expression)})).get (by simp [evalExprPure]))"
    )

def _lean_region_index_masks(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> list[tuple[str, int, int]]:
    masks: set[tuple[str, int, int]] = set()
    for bound in region.get("bounds", []):
        if "original_expression" in bound or "candidate_expression" in bound:
            continue
        register = bound["original"]
        upper = bound["unsigned_lt"]
        pattern = re.compile(
            rf"StageA\.Formal\.Expr\.bitAnd \(StageA\.Formal\.Expr\.inputReg "
            rf"\(StageA\.Formal\.Reg\.{re.escape(register)}\)\) "
            r"\(StageA\.Formal\.Expr\.constant (\d+)\)"
        )
        for side in ("original", "candidate"):
            for value in pattern.findall(behaviors[side]):
                mask = int(value)
                if mask > 0 and mask & (mask + 1) == 0 and upper <= mask + 1:
                    masks.add((register, mask, upper))
    return sorted(masks)

def _lean_region_separation_setup(index: int, region: dict[str, Any]) -> tuple[str, str]:
    count = len(region.get("address_separations", []))
    if count == 0:
        return (
            f"  simp [addressSeparationsRelated, StageA.Formal.Registers.get, region{index}] "
            "at separationsSatisfied\n",
            "",
        )
    hypotheses = [
        hypothesis
        for separation_index in range(count)
        for hypothesis in (
            f"originalSeparation{separation_index}",
            f"candidateSeparation{separation_index}",
            f"originalSeparationReverse{separation_index}",
            f"candidateSeparationReverse{separation_index}",
        )
    ]
    setup = (
        "".join(
            f"  have originalSeparation{separation_index} := "
            "(addressSeparationsRelated_member "
            f"{_lean_address_separation(separation)} (by decide) "
            "separationsSatisfied).1\n"
            f"  have candidateSeparation{separation_index} := "
            "(addressSeparationsRelated_member "
            f"{_lean_address_separation(separation)} (by decide) "
            "separationsSatisfied).2\n"
            f"  simp [StageA.Formal.Registers.get, region{index}] at "
            f"originalSeparation{separation_index} "
            f"candidateSeparation{separation_index}\n"
            f"  have originalSeparationReverse{separation_index} := "
            f"Ne.symm originalSeparation{separation_index}\n"
            f"  have candidateSeparationReverse{separation_index} := "
            f"Ne.symm candidateSeparation{separation_index}\n"
            for separation_index, separation in enumerate(
                region.get("address_separations", [])
            )
        )
    )
    return setup, ", ".join(hypotheses)

def _lean_region_flag_setup(index: int, region: dict[str, Any]) -> tuple[str, str]:
    bits = region.get("flag_inputs", [])
    setup = (
        f"  simp [StageA.Relational.flagsRelated, region{index}] at flagsRelated\n"
    )
    if not bits:
        return setup, ""
    if len(bits) == 1:
        hypothesis = f"flagInputRelated{bits[0]}"
        return setup + f"  have {hypothesis} := flagsRelated\n", hypothesis
    hypotheses = [f"flagInputRelated{bit}" for bit in bits]
    setup += "  rcases flagsRelated with \u27e8" + ", ".join(hypotheses) + "\u27e9\n"
    return setup, ", ".join(hypotheses)

def _lean_region_memory_setup(
    index: int,
    region: dict[str, Any],
    original_image_base: str,
    candidate_image_base: str,
) -> str:
    name = f"region{index}"
    has_relocations = any(
        target.get("relocation_offsets") for target in region.get("values", [])
    )
    if has_relocations:
        return (
            "  have relocatedMemory := memoryRelated_with_relocations "
            f"{original_image_base} {candidate_image_base} {name}.targets {name}.values "
            "originalMemory candidateMemory (by decide) memoryRelated\n"
            "  rcases relocatedMemory with "
            "\u27e8ordinaryMemoryRelated, relocationWordsRelated\u27e9\n"
        )
    return (
        "  have exactMemory := memoryRelated_without_relocations "
        f"{original_image_base} {candidate_image_base} {name}.targets {name}.values "
        "originalMemory candidateMemory (by decide) memoryRelated\n"
        f"  change candidateMemory = fun address => originalMemory "
        f"(normalizeDataAddress {name}.values address) at exactMemory\n"
        "  subst candidateMemory\n"
    )

def _lean_region_relocation_memory_setup(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str:
    name = f"region{index}"
    rows: list[str] = []
    for relocation_index, (target, offset, address_index) in enumerate(
        _lean_region_static_relocation_word_specs(region, behaviors)
    ):
        fact = f"{name}RelocationWordRelatedStatic{relocation_index}"
        original_read = f"{name}RelocationOriginalRead32Static{relocation_index}"
        candidate_read = f"{name}RelocationCandidateRead32Static{relocation_index}"
        zero_fact = f"{name}RelocationWordZeroStatic{relocation_index}"
        rows.extend((
            f"  have {original_read} := assembledMemoryRead32OfNat_eq "
            f"originalMemory {target['original_value'] + offset}",
            f"  have {candidate_read} := assembledMemoryRead32OfNat_eq "
            f"candidateMemory {target['candidate_value'] + offset}",
            f"  have {fact} := relocationWordsRelated "
            f"(BitVec.ofNat 32 {target['candidate_value'] + offset}) "
            f"{name}RelocationWordStartStatic{relocation_index}",
            f"  rw [{name}MappedAddress{address_index}] at {fact}",
            f"  simp only [{name}] at {fact}",
            f"  have {zero_fact} := wordRelated_zero_equal {fact}",
        ))
    bounds = region.get("bounds", [])
    for relocation_index, (target, upper, shift, offset, address_index) in enumerate(
        _lean_region_indexed_relocation_word_specs(region)
    ):
        bound_index = next(
            bound_index for bound_index, bound in enumerate(bounds)
            if bound["unsigned_lt"] == upper
        )
        bound = bounds[bound_index]
        hypothesis = "boundsSatisfied" if len(bounds) == 1 else f"boundSatisfied{bound_index}"
        register = _lean_bound_index_value(bound, "original", "o")
        scaled = register if shift == 0 else f"({register} <<< {shift})"
        fact = f"{name}RelocationWordRelatedIndexed{relocation_index}"
        zero_fact = f"{name}RelocationWordZeroIndexed{relocation_index}"
        rows.extend((
            f"  have {fact} := relocationWordsRelated "
            f"({scaled} + BitVec.ofNat 32 {target['candidate_value'] + offset}) "
            f"({name}RelocationWordStartIndexed{relocation_index} {register} "
            f"(by simpa [boundValue, evalExprPure, StageA.Formal.Registers.get] using {hypothesis}))",
            f"  simp [evalExprPure, StageA.Formal.Registers.get] at {fact}",
            f"  rw [{name}MappedIndexedAddressFact{address_index}] at {fact}",
            f"  simp only [{name}] at {fact}",
        ))
        if shift > 0:
            rows.append(
                f"  rw [BitVec.shiftLeft_eq_concat_of_lt (by decide)] at {fact}"
            )
        rows.append(f"  have {zero_fact} := wordRelated_zero_equal {fact}")
    return "\n".join(rows) + ("\n" if rows else "")

def _lean_acceptance_outcome(outcome: dict[str, Any]) -> str:
    operation = outcome.get("op")
    if operation == "jump":
        return f"StageA.Relational.NormalizedOutcomeExpr.jump {int(outcome['target'])}"
    if operation == "branch":
        return (
            "StageA.Relational.NormalizedOutcomeExpr.branch "
            f"({_lean_semantic_bool_expr(outcome['condition'])}) "
            f"{int(outcome['taken'])} {int(outcome['fallthrough'])}"
        )
    if operation == "call":
        return (
            "StageA.Relational.NormalizedOutcomeExpr.call "
            f"{int(outcome['target'])} {int(outcome['continuation'])}"
        )
    if operation == "external_call":
        arguments = ", ".join(
            _lean_semantic_expr(argument)
            for argument in outcome.get("arguments", [])
        )
        identity = _semantic_external_target_identity(outcome.get("import"))
        if identity is None:
            raise ValueError("external acceptance outcome has no import identity")
        imported: dict[str, Any] = {"dll": identity[0], identity[1]: identity[2]}
        return (
            "StageA.Relational.NormalizedOutcomeExpr.externalCall "
            f"({_lean_external_target(imported)}) [{arguments}] "
            f"{int(outcome['continuation'])}"
        )
    if operation == "external_jump":
        arguments = ", ".join(
            _lean_semantic_expr(argument)
            for argument in outcome.get("arguments", [])
        )
        identity = _semantic_external_target_identity(outcome.get("import"))
        if identity is None:
            raise ValueError("external acceptance outcome has no import identity")
        imported: dict[str, Any] = {"dll": identity[0], identity[1]: identity[2]}
        return (
            "StageA.Relational.NormalizedOutcomeExpr.externalJump "
            f"({_lean_external_target(imported)}) [{arguments}]"
        )
    if operation == "bulk_copy":
        return (
            "StageA.Relational.NormalizedOutcomeExpr.bulkCopy "
            f"({_lean_semantic_expr(outcome['destination'])}) "
            f"({_lean_semantic_expr(outcome['source'])}) "
            f"({_lean_semantic_expr(outcome['count'])}) "
            f"({_lean_semantic_bool_expr(outcome['direction'])}) "
            f"{int(outcome['continuation'])}"
        )
    if operation == "indirect_call":
        return (
            "StageA.Relational.NormalizedOutcomeExpr.indirectCall "
            f"({_lean_semantic_expr(outcome['target'])}) "
            f"{int(outcome['continuation'])}"
        )
    if operation == "indirect_jump":
        return (
            "StageA.Relational.NormalizedOutcomeExpr.indirectJump "
            f"({_lean_semantic_expr(outcome['target'])})"
        )
    if operation == "checked_continue":
        return (
            "StageA.Relational.NormalizedOutcomeExpr.checkedContinue "
            f"({_lean_semantic_bool_expr(outcome['valid'])}) "
            f"{int(outcome['continuation'])}"
        )
    if operation == "atomic_compare_exchange":
        return (
            "StageA.Relational.NormalizedOutcomeExpr.atomicCompareExchange "
            f"({_lean_semantic_expr(outcome['address'])}) "
            f"({_lean_semantic_expr(outcome['expected'])}) "
            f"({_lean_semantic_expr(outcome['replacement'])}) "
            f"{int(outcome['continuation'])}"
        )
    if operation == "returned":
        return (
            "StageA.Relational.NormalizedOutcomeExpr.returned "
            f"({_lean_semantic_expr(outcome['target'])})"
        )
    raise ValueError(f"unsupported acceptance outcome {operation!r}")
