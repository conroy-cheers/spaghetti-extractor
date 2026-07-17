from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ...stage_binary import StageAInputError
from ..schema import REGISTERS


_SCANNER_FIELDS = frozenset({
    "table",
    "original_scanner_register",
    "candidate_scanner_register",
    "original_count_register",
    "candidate_count_register",
    "original_loaded_register",
    "candidate_loaded_register",
    "test_target_id",
    "scanner_target_id",
    "bridge_target_id",
    "zero_flag_bit",
})
_TABLE_FIELDS = frozenset({
    "value_target_id",
    "table_offset",
    "original_base",
    "candidate_base",
    "layout",
    "upper_exclusive",
    "original_index_register",
    "candidate_index_register",
    "continuation_target_id",
    "rows",
})
_ROW_FIELDS = frozenset({"original_index", "target_id"})
_REGISTER_FIELDS = (
    "original_scanner_register",
    "candidate_scanner_register",
    "original_count_register",
    "candidate_count_register",
    "original_loaded_register",
    "candidate_loaded_register",
)
_TABLE_REGISTER_FIELDS = (
    "original_index_register",
    "candidate_index_register",
)
_TABLE_NAT_FIELDS = (
    "value_target_id",
    "table_offset",
    "original_base",
    "candidate_base",
    "upper_exclusive",
    "continuation_target_id",
)


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _require_exact_fields(
    value: Mapping[str, Any],
    expected: frozenset[str],
    context: str,
) -> None:
    fields = set(value)
    missing = sorted(expected - fields)
    unexpected = sorted(fields - expected)
    if missing:
        raise StageAInputError(
            f"{context} is missing required fields: {', '.join(missing)}"
        )
    if unexpected:
        raise StageAInputError(
            f"{context} has unexpected fields: {', '.join(unexpected)}"
        )


def _natural(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{context} must be a nonnegative integer")
    return value


def _register(value: Any, context: str) -> str:
    if not isinstance(value, str) or value not in REGISTERS:
        raise StageAInputError(f"{context} must name an x86 PE32 register")
    return value


def _validated_table(value: Any) -> dict[str, Any]:
    table = _object(value, "reverse sentinel scanner table claim")
    _require_exact_fields(
        table,
        _TABLE_FIELDS,
        "reverse sentinel scanner table claim",
    )

    layout = table["layout"]
    if layout != "sentinelTerminatedReverseCount":
        raise StageAInputError(
            "reverse sentinel scanner table claim layout must be "
            "sentinelTerminatedReverseCount"
        )

    validated: dict[str, Any] = {
        field: _natural(
            table[field],
            f"reverse sentinel scanner table claim {field}",
        )
        for field in _TABLE_NAT_FIELDS
    }
    validated["layout"] = layout
    for field in _TABLE_REGISTER_FIELDS:
        validated[field] = _register(
            table[field],
            f"reverse sentinel scanner table claim {field}",
        )

    rows = table["rows"]
    if not isinstance(rows, list):
        raise StageAInputError(
            "reverse sentinel scanner table claim rows must be a JSON array"
        )
    validated_rows: list[dict[str, int]] = []
    for index, raw_row in enumerate(rows):
        context = f"reverse sentinel scanner table claim row {index}"
        row = _object(raw_row, context)
        _require_exact_fields(row, _ROW_FIELDS, context)
        validated_rows.append({
            "original_index": _natural(
                row["original_index"], f"{context} original_index"
            ),
            "target_id": _natural(row["target_id"], f"{context} target_id"),
        })
    validated["rows"] = validated_rows
    return validated


def _lean_reverse_sentinel_scanner_claim(claim: Mapping[str, Any]) -> str:
    scanner = _object(claim, "reverse sentinel scanner claim")
    _require_exact_fields(scanner, _SCANNER_FIELDS, "reverse sentinel scanner claim")

    table = _validated_table(scanner["table"])
    registers = {
        field: _register(scanner[field], f"reverse sentinel scanner claim {field}")
        for field in _REGISTER_FIELDS
    }
    test_target_id = _natural(
        scanner["test_target_id"],
        "reverse sentinel scanner claim test_target_id",
    )
    scanner_target_id = _natural(
        scanner["scanner_target_id"],
        "reverse sentinel scanner claim scanner_target_id",
    )
    bridge_target_id = _natural(
        scanner["bridge_target_id"],
        "reverse sentinel scanner claim bridge_target_id",
    )
    zero_flag_bit = _natural(
        scanner["zero_flag_bit"],
        "reverse sentinel scanner claim zero_flag_bit",
    )
    if zero_flag_bit != 6:
        raise StageAInputError(
            "reverse sentinel scanner claim zero_flag_bit must select ZF bit 6"
        )

    # Keep this import lazy so composition.py can import this boundary later.
    from .composition import _lean_bounded_immutable_code_pointer_table_call_claim

    table_literal = _lean_bounded_immutable_code_pointer_table_call_claim(table)
    return (
        "{ table := " + table_literal
        + ", originalScannerRegister := ." + registers["original_scanner_register"]
        + ", candidateScannerRegister := ." + registers["candidate_scanner_register"]
        + ", originalCountRegister := ." + registers["original_count_register"]
        + ", candidateCountRegister := ." + registers["candidate_count_register"]
        + ", originalLoadedRegister := ." + registers["original_loaded_register"]
        + ", candidateLoadedRegister := ." + registers["candidate_loaded_register"]
        + ", testTargetId := " + str(test_target_id)
        + ", scannerTargetId := " + str(scanner_target_id)
        + ", bridgeTargetId := " + str(bridge_target_id)
        + ", zeroFlagBit := " + str(zero_flag_bit)
        + " }"
    )
