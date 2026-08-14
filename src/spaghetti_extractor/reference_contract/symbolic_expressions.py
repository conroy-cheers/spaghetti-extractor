"""Symbolic x86 block execution used to propose semantic contracts."""

from __future__ import annotations

import copy
import json
import os
import platform
import re
import shutil
import sys
from bisect import bisect_left
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Iterable

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
import pefile

from ..pe32.stage_binary import (
    BlockSide,
    StageABinary,
    StageAImport,
    StageAInputError,
    StageASection,
    _artifact_name,
    _coff_symbol_aliases_by_rva,
    _executable_section_for_rva,
    _parse_linker_map_functions,
    _parse_linker_map_symbol_line,
    _parse_stage_a_pe,
    _section_for_rva,
)
from ..extraction.cutpoints import semantic_cutpoint_spans_for_side
from ..util import sha256_bytes, sha256_file, utc_now, write_json

from .common import (
    BlockMapping,
    _is_conditional_jump,
    _parse_int,
)

from .map_analysis import (
    _capstone_mode,
)
from .map_analysis import (
    _external_import_call,
    _resolved_branch_target,
)
from .map_verification import (
    _external_import_jump,
)

from .abi_control_flow import (
    _abi_indexed_jump_table_contract,
)
from .abi_instruction import (
    _abi_mem_operand_report,
)

def _expr_add(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    return _canonical_add_parts((left, right))

def _canonical_add_parts(parts: tuple[Any, ...]) -> tuple[Any, ...]:
    """Canonicalize an associative sum without recursively refolding it."""

    constant = 0
    terms: list[tuple[Any, ...]] = []
    for part in parts:
        canonical = _canonical_expr(part)
        flattened = _flatten_expr("add", canonical)
        for term in flattened:
            if term[0] == "const":
                constant = (constant + int(term[1])) & 0xFFFFFFFF
            else:
                terms.append(term)
    if constant:
        terms.append(("const", constant))
    if not terms:
        return ("const", 0)
    ordered = sorted(terms, key=repr)
    if len(ordered) == 1:
        return ordered[0]
    return ("add", *ordered)

def _expr_sub(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) - int(right[1])) & 0xFFFFFFFF)
    return ("sub", left, right)

def _expr_mul(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0) or right == ("const", 0):
        return ("const", 0)
    if left == ("const", 1):
        return right
    if right == ("const", 1):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) * int(right[1])) & 0xFFFFFFFF)
    return ("mul", left, right)

def _expr_mask(value: tuple[Any, ...] | None, width_bits: int) -> tuple[Any, ...]:
    if value is None:
        return ("const", 0)
    if isinstance(value, tuple) and len(value) >= 3 and value[0] == "sext" and int(value[1]) == width_bits:
        return _expr_mask(value[2], width_bits)
    value = _canonical_expr(value)
    if width_bits >= 32:
        return value
    mask = (1 << width_bits) - 1
    if value[0] == "const":
        return ("const", int(value[1]) & mask)
    if value[0] == "and" and ("const", mask) in value[1:]:
        return value
    return _expr_and(value, ("const", mask))

def _expr_sign_extend(value: tuple[Any, ...], width_bits: int) -> tuple[Any, ...]:
    value = _expr_mask(value, width_bits)
    if width_bits >= 32:
        return value
    if value[0] == "const":
        raw = int(value[1]) & ((1 << width_bits) - 1)
        sign_bit = 1 << (width_bits - 1)
        if raw & sign_bit:
            raw |= (~((1 << width_bits) - 1)) & 0xFFFFFFFF
        return ("const", raw & 0xFFFFFFFF)
    return ("sext", width_bits, value)

def _expr_shl(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) << (int(right[1]) & 31)) & 0xFFFFFFFF)
    return ("shl", left, right)

def _expr_lshr(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) & 0xFFFFFFFF) >> (int(right[1]) & 31))
    return ("lshr", left, right)

def _expr_ashr(left: tuple[Any, ...], right: tuple[Any, ...], width_bits: int = 32) -> tuple[Any, ...]:
    left = _expr_mask(left, width_bits)
    right = _canonical_expr(right)
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        shift = int(right[1]) & 31
        raw = int(left[1]) & ((1 << width_bits) - 1)
        if raw & (1 << (width_bits - 1)):
            signed = raw - (1 << width_bits)
        else:
            signed = raw
        return ("const", (signed >> shift) & ((1 << width_bits) - 1))
    return ("ashr", width_bits, left, right)

def _expr_not(value: tuple[Any, ...]) -> tuple[Any, ...]:
    value = _canonical_expr(value)
    if value[0] == "const":
        return ("const", (~int(value[1])) & 0xFFFFFFFF)
    return ("bvnot", value)

def _expr_neg(value: tuple[Any, ...]) -> tuple[Any, ...]:
    value = _canonical_expr(value)
    if value[0] == "const":
        return ("const", (-int(value[1])) & 0xFFFFFFFF)
    return ("neg", value)

def _expr_ite(condition: tuple[Any, ...], when_true: tuple[Any, ...], when_false: tuple[Any, ...]) -> tuple[Any, ...]:
    condition = _canonical_expr(condition)
    when_true = _canonical_expr(when_true)
    when_false = _canonical_expr(when_false)
    if condition == ("true",):
        return when_true
    if condition == ("false",):
        return when_false
    if when_true == when_false:
        return when_true
    return ("ite", condition, when_true, when_false)

def _expr_bool_bit(condition: tuple[Any, ...]) -> tuple[Any, ...]:
    condition = _canonical_expr(condition)
    if condition == ("true",):
        return ("const", 1)
    if condition == ("false",):
        return ("const", 0)
    return ("bool_bit", condition)

def _expr_imul_low(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) * int(right[1])) & 0xFFFFFFFF)
    return ("imul_low", left, right)

def _expr_imul_high(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        signed_left = _signed32(int(left[1]))
        signed_right = _signed32(int(right[1]))
        return ("const", ((signed_left * signed_right) >> 32) & 0xFFFFFFFF)
    return ("imul_high", left, right)

def _expr_mul_low(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        return ("const", (int(left[1]) * int(right[1])) & 0xFFFFFFFF)
    return ("mul_low", left, right)

def _expr_mul_high(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left[0] == "const" and right[0] == "const":
        return ("const", (((int(left[1]) & 0xFFFFFFFF) * (int(right[1]) & 0xFFFFFFFF)) >> 32) & 0xFFFFFFFF)
    return ("mul_high", left, right)

def _signed32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value

def _expr_shift_pair(mnemonic: str, left: tuple[Any, ...], right: tuple[Any, ...], count: tuple[Any, ...], width_bits: int) -> tuple[Any, ...]:
    left = _expr_mask(left, width_bits)
    right = _expr_mask(right, width_bits)
    count = _expr_and(count, ("const", 0x1F))
    inverse = _expr_sub(("const", width_bits), count)
    if mnemonic == "shrd":
        return _expr_mask(_expr_or(_expr_lshr(left, count), _expr_shl(right, inverse)), width_bits)
    return _expr_mask(_expr_or(_expr_shl(left, count), _expr_lshr(right, inverse)), width_bits)

def _expr_xor(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == right:
        return ("const", 0)
    if left == ("const", 0):
        return right
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", int(left[1]) ^ int(right[1]))
    terms = sorted(_flatten_expr("xor", left) + _flatten_expr("xor", right), key=repr)
    return ("xor", *terms)

def _expr_and(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0) or right == ("const", 0):
        return ("const", 0)
    if left == ("const", 0xFFFFFFFF):
        return right
    if right == ("const", 0xFFFFFFFF):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", int(left[1]) & int(right[1]))
    if repr(right) < repr(left):
        left, right = right, left
    return ("and", left, right)

def _expr_or(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == ("const", 0):
        return right
    if right == ("const", 0):
        return left
    if left[0] == "const" and right[0] == "const":
        return ("const", int(left[1]) | int(right[1]))
    if repr(right) < repr(left):
        left, right = right, left
    return ("or", left, right)

def _bool_not(value: tuple[Any, ...]) -> tuple[Any, ...]:
    value = _canonical_expr(value)
    if value == ("true",):
        return ("false",)
    if value == ("false",):
        return ("true",)
    if isinstance(value, tuple) and value and value[0] == "not":
        return value[1]
    return ("not", value)

def _bool_and(*values: tuple[Any, ...]) -> tuple[Any, ...]:
    terms: list[tuple[Any, ...]] = []
    for value in values:
        value = _canonical_expr(value)
        if value == ("false",):
            return ("false",)
        if value == ("true",):
            continue
        terms.extend(_flatten_expr("bool_and", value))
    if not terms:
        return ("true",)
    if len(terms) == 1:
        return terms[0]
    return ("bool_and", *sorted(terms, key=repr))

def _bool_or(*values: tuple[Any, ...]) -> tuple[Any, ...]:
    terms: list[tuple[Any, ...]] = []
    for value in values:
        value = _canonical_expr(value)
        if value == ("true",):
            return ("true",)
        if value == ("false",):
            continue
        terms.extend(_flatten_expr("bool_or", value))
    if not terms:
        return ("false",)
    if len(terms) == 1:
        return terms[0]
    return ("bool_or", *sorted(terms, key=repr))

def _bool_xor(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == right:
        return ("false",)
    if left == ("false",):
        return right
    if right == ("false",):
        return left
    if left == ("true",):
        return _bool_not(right)
    if right == ("true",):
        return _bool_not(left)
    if repr(right) < repr(left):
        left, right = right, left
    return ("bool_xor", left, right)

def _bool_eq(left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    left = _canonical_expr(left)
    right = _canonical_expr(right)
    if left == right:
        return ("true",)
    if left == ("true",):
        return right
    if right == ("true",):
        return left
    if left == ("false",):
        return _bool_not(right)
    if right == ("false",):
        return _bool_not(left)
    if repr(right) < repr(left):
        left, right = right, left
    return ("bool_eq", left, right)

def _flatten_expr(operator: str, expr: tuple[Any, ...]) -> list[tuple[Any, ...]]:
    if expr and expr[0] == operator:
        return list(expr[1:])
    return [expr]

def _canonical_expr(expr: Any) -> Any:
    if not isinstance(expr, tuple) or not expr:
        return expr
    op = expr[0]
    if op == "const":
        return ("const", int(expr[1]) & 0xFFFFFFFF)
    if op in {"reg", "flag", "true", "false", "env_response", "call_response", "call_flag", "undefined_bv", "undefined_flag"}:
        return expr
    if op == "add":
        return _canonical_add_parts(expr[1:])
    if op == "sub":
        return _expr_sub(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "mul":
        return _expr_mul(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "xor":
        result: tuple[Any, ...] = ("const", 0)
        for part in expr[1:]:
            result = _expr_xor(result, _canonical_expr(part))
        return result
    if op == "and":
        return _expr_and(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "or":
        return _expr_or(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "bvnot":
        return _expr_not(_canonical_expr(expr[1]))
    if op == "neg":
        return _expr_neg(_canonical_expr(expr[1]))
    if op == "shl":
        return _expr_shl(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "lshr":
        return _expr_lshr(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "ashr":
        return _expr_ashr(_canonical_expr(expr[2]), _canonical_expr(expr[3]), int(expr[1]))
    if op == "sext":
        return _expr_sign_extend(_canonical_expr(expr[2]), int(expr[1]))
    if op == "write_bits":
        base = _canonical_expr(expr[1])
        offset = int(expr[2])
        width = int(expr[3])
        value = _expr_mask(_canonical_expr(expr[4]), width)
        if (
            isinstance(base, tuple)
            and len(base) == 5
            and base[0] == "write_bits"
            and int(base[2]) == offset
            and int(base[3]) == width
        ):
            base = base[1]
        return ("write_bits", base, offset, width, value)
    if op == "ite":
        return _expr_ite(_canonical_expr(expr[1]), _canonical_expr(expr[2]), _canonical_expr(expr[3]))
    if op == "not":
        return _bool_not(_canonical_expr(expr[1]))
    if op == "bool_and":
        return _bool_and(*[_canonical_expr(part) for part in expr[1:]])
    if op == "bool_or":
        return _bool_or(*[_canonical_expr(part) for part in expr[1:]])
    if op == "bool_xor":
        return _bool_xor(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op == "bool_eq":
        return _bool_eq(_canonical_expr(expr[1]), _canonical_expr(expr[2]))
    if op in {
        "eq",
        "ult",
        "msb",
        "msb_w",
        "add_overflow",
        "sub_overflow",
        "add_overflow_w",
        "sub_overflow_w",
        "shift_cf",
        "shift_of",
        "adc_carry",
        "adc_overflow",
        "sbb_borrow",
        "sbb_overflow",
        "imul_overflow",
        "mul_carry",
        "parity",
        "fpu_cmp_cf",
        "fpu_cmp_zf",
        "fpu_cmp_pf",
        "bool_bit",
        "mem32",
        "mem",
        "call_mem",
        "imul_low",
        "imul_high",
        "mul_low",
        "mul_high",
        "udiv_quot",
        "udiv_rem",
        "udiv_valid",
        "bsr_index",
        "tzcnt",
        "fpu_bits_lo",
        "fpu_bits_hi",
        "fpu_int32",
        "fpu_status_word",
        "fpu_control_word",
    }:
        return tuple(_canonical_expr(part) for part in expr)
    return tuple(_canonical_expr(part) for part in expr)

def _expr_json(value: Any) -> Any:
    if isinstance(value, tuple):
        return [_expr_json(item) for item in value]
    if isinstance(value, list):
        return [_expr_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _expr_json(item) for key, item in value.items()}
    return value

__all__ = [
    '_bool_and',
    '_bool_eq',
    '_bool_not',
    '_bool_or',
    '_bool_xor',
    '_canonical_expr',
    '_expr_add',
    '_expr_and',
    '_expr_ashr',
    '_expr_bool_bit',
    '_expr_imul_high',
    '_expr_imul_low',
    '_expr_ite',
    '_expr_json',
    '_expr_lshr',
    '_expr_mask',
    '_expr_mul',
    '_expr_mul_high',
    '_expr_mul_low',
    '_expr_neg',
    '_expr_not',
    '_expr_or',
    '_expr_shift_pair',
    '_expr_shl',
    '_expr_sign_extend',
    '_expr_sub',
    '_expr_xor',
    '_flatten_expr',
    '_signed32',
]
