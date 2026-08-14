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

from .symbolic_expressions import (
    _bool_and,
    _bool_eq,
    _bool_not,
    _bool_or,
    _bool_xor,
    _expr_and,
    _expr_bool_bit,
    _expr_ite,
    _expr_mask,
    _expr_or,
    _expr_xor,
)

def _branch_condition(mnemonic: str, flags: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    cf = flags["cf"]
    zf = flags["zf"]
    sf = flags["sf"]
    of = flags["of"]
    pf = flags.get("pf", ("flag", "pf"))
    conditions = {
        "ja": _bool_and(_bool_not(cf), _bool_not(zf)),
        "jnbe": _bool_and(_bool_not(cf), _bool_not(zf)),
        "jae": _bool_not(cf),
        "jnb": _bool_not(cf),
        "jnc": _bool_not(cf),
        "jb": cf,
        "jc": cf,
        "jnae": cf,
        "jbe": _bool_or(cf, zf),
        "jna": _bool_or(cf, zf),
        "je": zf,
        "jz": zf,
        "jne": _bool_not(zf),
        "jnz": _bool_not(zf),
        "jg": _bool_and(_bool_not(zf), _bool_eq(sf, of)),
        "jnle": _bool_and(_bool_not(zf), _bool_eq(sf, of)),
        "jge": _bool_eq(sf, of),
        "jnl": _bool_eq(sf, of),
        "jl": _bool_xor(sf, of),
        "jnge": _bool_xor(sf, of),
        "jle": _bool_or(zf, _bool_xor(sf, of)),
        "jng": _bool_or(zf, _bool_xor(sf, of)),
        "jno": _bool_not(of),
        "jo": of,
        "jp": pf,
        "jpe": pf,
        "jnp": _bool_not(pf),
        "jpo": _bool_not(pf),
        "jns": _bool_not(sf),
        "js": sf,
    }
    return conditions.get(mnemonic)

def _arithmetic_flags(
    operator: str,
    left: tuple[Any, ...],
    right: tuple[Any, ...],
    result: tuple[Any, ...],
    *,
    width_bits: int = 32,
) -> dict[str, tuple[Any, ...]]:
    left = _expr_mask(left, width_bits)
    right = _expr_mask(right, width_bits)
    result = _expr_mask(result, width_bits)
    if operator == "add":
        cf = ("ult", result, left)
        of = ("add_overflow_w", width_bits, left, right, result)
    else:
        cf = ("ult", left, right)
        of = ("sub_overflow_w", width_bits, left, right, result)
    return {
        "cf": cf,
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb_w", width_bits, result),
        "of": of,
        "pf": ("parity", width_bits, result),
    }

def _logical_flags(result: tuple[Any, ...], *, width_bits: int = 32) -> dict[str, tuple[Any, ...]]:
    result = _expr_mask(result, width_bits)
    return {
        "cf": ("false",),
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb_w", width_bits, result),
        "of": ("false",),
        "pf": ("parity", width_bits, result),
    }

def _logical_result(operator: str, left: tuple[Any, ...], right: tuple[Any, ...]) -> tuple[Any, ...]:
    if operator == "xor":
        return _expr_xor(left, right)
    if operator == "and":
        return _expr_and(left, right)
    if operator == "or":
        return _expr_or(left, right)
    raise StageAInputError(f"unsupported logical operator {operator!r}")

def _carry_arithmetic_flags(
    operator: str,
    left: tuple[Any, ...],
    right: tuple[Any, ...],
    carry: tuple[Any, ...],
    result: tuple[Any, ...],
    *,
    width_bits: int,
) -> dict[str, tuple[Any, ...]]:
    left = _expr_mask(left, width_bits)
    right = _expr_mask(right, width_bits)
    carry_bit = _expr_mask(_expr_bool_bit(carry), width_bits)
    result = _expr_mask(result, width_bits)
    if operator == "adc":
        return {
            "cf": ("adc_carry", width_bits, left, right, carry_bit, result),
            "zf": ("eq", result, ("const", 0)),
            "sf": ("msb_w", width_bits, result),
            "of": ("adc_overflow", width_bits, left, right, carry_bit, result),
            "pf": ("parity", width_bits, result),
        }
    return {
        "cf": ("sbb_borrow", width_bits, left, right, carry_bit, result),
        "zf": ("eq", result, ("const", 0)),
        "sf": ("msb_w", width_bits, result),
        "of": ("sbb_overflow", width_bits, left, right, carry_bit, result),
        "pf": ("parity", width_bits, result),
    }

def _shift_flags(
    mnemonic: str,
    left: tuple[Any, ...],
    count: tuple[Any, ...],
    result: tuple[Any, ...],
    prior_flags: dict[str, tuple[Any, ...]],
    *,
    rva: int,
    width_bits: int,
) -> dict[str, tuple[Any, ...]]:
    effective_count = _expr_and(count, ("const", 0x1F))
    count_is_zero = _bool_eq(effective_count, ("const", 0))
    count_is_one = _bool_eq(effective_count, ("const", 1))
    count_within_width = ("ult", effective_count, ("const", width_bits + 1))
    result = _expr_mask(result, width_bits)
    shifted_cf = ("shift_cf", mnemonic, width_bits, _expr_mask(left, width_bits), effective_count)
    active_cf = _expr_ite(
        count_within_width,
        shifted_cf,
        _undefined_flag("shift_count_exceeds_width", rva, "cf"),
    )
    shifted_of = ("shift_of", mnemonic, width_bits, _expr_mask(left, width_bits), effective_count, result)
    return {
        "cf": _expr_ite(count_is_zero, prior_flags["cf"], active_cf),
        "zf": _expr_ite(count_is_zero, prior_flags["zf"], ("eq", result, ("const", 0))),
        "sf": _expr_ite(count_is_zero, prior_flags["sf"], ("msb_w", width_bits, result)),
        "of": _expr_ite(
            count_is_zero,
            prior_flags["of"],
            _expr_ite(
                count_is_one,
                shifted_of,
                _undefined_flag("shift_overflow_undefined", rva, "of"),
            ),
        ),
        "pf": _expr_ite(count_is_zero, prior_flags["pf"], ("parity", width_bits, result)),
    }

def _undefined_flag(reason: str, rva: int, name: str) -> tuple[Any, ...]:
    return ("undefined_flag", reason, f"{rva:x}:{name}")

def _undefined_bv(
    reason: str,
    rva: int,
    name: str,
    defined_value: tuple[Any, ...] | None = None,
) -> tuple[Any, ...]:
    base = ("undefined_bv", reason, f"{rva:x}:{name}")
    return base if defined_value is None else (*base, defined_value)

def _undefined_arithmetic_flags(reason: str, rva: int, *, keep: dict[str, tuple[Any, ...]] | None = None) -> dict[str, tuple[Any, ...]]:
    keep = keep or {}
    return {name: keep.get(name, _undefined_flag(reason, rva, name)) for name in ("cf", "zf", "sf", "of", "pf")}

def _setcc_condition(mnemonic: str, flags: dict[str, tuple[Any, ...]]) -> tuple[Any, ...] | None:
    suffix = mnemonic[3:] if mnemonic.startswith("set") else mnemonic
    aliases = {
        "e": "z",
        "ne": "nz",
        "nae": "b",
        "c": "b",
        "nb": "ae",
        "nc": "ae",
        "be": "be",
        "na": "be",
        "nbe": "a",
        "nge": "l",
        "nl": "ge",
        "ng": "le",
        "nle": "g",
        "pe": "p",
        "po": "np",
    }
    key = aliases.get(suffix, suffix)
    zf = flags["zf"]
    cf = flags["cf"]
    sf = flags["sf"]
    of = flags["of"]
    pf = flags.get("pf", ("flag", "pf"))
    conditions = {
        "z": zf,
        "nz": _bool_not(zf),
        "a": _bool_and(_bool_not(cf), _bool_not(zf)),
        "ae": _bool_not(cf),
        "b": cf,
        "be": _bool_or(cf, zf),
        "g": _bool_and(_bool_not(zf), _bool_eq(sf, of)),
        "ge": _bool_eq(sf, of),
        "l": _bool_xor(sf, of),
        "le": _bool_or(zf, _bool_xor(sf, of)),
        "o": of,
        "no": _bool_not(of),
        "s": sf,
        "ns": _bool_not(sf),
        "p": pf,
        "np": _bool_not(pf),
    }
    return conditions.get(key)

__all__ = [
    '_arithmetic_flags',
    '_branch_condition',
    '_carry_arithmetic_flags',
    '_logical_flags',
    '_logical_result',
    '_setcc_condition',
    '_shift_flags',
    '_undefined_arithmetic_flags',
    '_undefined_bv',
    '_undefined_flag',
]
