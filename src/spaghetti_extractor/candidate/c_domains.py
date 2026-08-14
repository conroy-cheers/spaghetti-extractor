"""Shared closed semantic domains for C validation and rendering."""

from __future__ import annotations

import json
from typing import Any


_REGISTER_NAMES = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAG_NAMES = ("cf", "zf", "sf", "of", "pf", "df")
_REP_SCAS_OWNED_REGISTERS = ("edi", "ecx")
_REP_SCAS_OWNED_FLAGS = ("cf", "pf", "af", "zf", "sf", "of")
_CALL_EVENT_KINDS = frozenset({"external_call", "internal_call", "indirect_call"})
_X87_VALUE_OPS = frozenset(
    {
        "fpu_add",
        "fpu_const",
        "fpu_div",
        "fpu_divr",
        "fpu_empty",
        "fpu_int",
        "fpu_mem",
        "fpu_mem64",
        "fpu_mul",
        "fpu_neg",
        "fpu_reg",
        "fpu_sub",
        "fpu_subr",
    }
)
_X87_WORD_OPS = frozenset(
    {
        "fpu_bits_hi32",
        "fpu_bits_lo32",
        "fpu_cmp_cf",
        "fpu_cmp_pf",
        "fpu_cmp_zf",
        "fpu_control",
        "fpu_control_init",
        "fpu_control_load",
        "fpu_control_word",
        "fpu_fxam",
        "fpu_int32",
        "fpu_instruction_pointer",
        "fpu_code_selector",
        "fpu_data_pointer",
        "fpu_data_selector",
        "fpu_last_opcode",
        "fpu_pending_exception",
        "fpu_status",
        "fpu_status_init",
        "fpu_status_word",
        "fpu_tag",
    }
)


def valid_rep_scas_event(
    event: dict[str, Any],
    event_index: int,
    *,
    require_instruction_rva: bool,
) -> bool:
    def is_u32(value: Any) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value < 2**32
        )

    return (
        event.get("index") == event_index
        and not isinstance(event.get("index"), bool)
        and event.get("element_width") == 1
        and not isinstance(event.get("element_width"), bool)
        and event.get("address_size") == 32
        and not isinstance(event.get("address_size"), bool)
        and event.get("repeat_condition") == "while_not_equal_v1"
        and event.get("comparison_model") == "subtraction_flags_v1"
        and event.get("segment_model") == "flat_es_zero_v1"
        and event.get("effect_model") == "symbolic_string_scan_v1"
        and event.get("restart_semantics") == "element_committed_v1"
        and event.get("fault_model") == "read_before_commit_v1"
        and event.get("owned_register_outputs") == list(_REP_SCAS_OWNED_REGISTERS)
        and event.get("owned_flag_outputs") == list(_REP_SCAS_OWNED_FLAGS)
        and all(
            isinstance(event.get(field), dict)
            for field in ("destination", "accumulator", "count", "direction_flag")
        )
        and "source" not in event
        and "value" not in event
        and (not require_instruction_rva or is_u32(event.get("instruction_rva")))
    )


def c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


__all__ = ["c_string", "valid_rep_scas_event"]
