from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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
_U32_LIMIT = 1 << 32


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


def _u32(value: Any, context: str) -> int:
    natural = _natural(value, context)
    if natural >= _U32_LIMIT:
        raise StageAInputError(f"{context} must fit in an unsigned PE32 word")
    return natural


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


@dataclass(frozen=True)
class OriginalDecodedScannerRegionProposal:
    target_id: int
    rva: int
    size: int

    def validate(self, context: str) -> None:
        _natural(self.target_id, f"{context} target id")
        rva = _u32(self.rva, f"{context} RVA")
        size = _u32(self.size, f"{context} size")
        if size == 0:
            raise StageAInputError(f"{context} size must be nonzero")
        if rva + size > _U32_LIMIT:
            raise StageAInputError(f"{context} span exceeds the PE32 address space")

    def lean(self, context: str) -> str:
        self.validate(context)
        return (
            "{ targetId := "
            f"{self.target_id}, span := {{ start := {self.rva}, "
            f"size := {self.size} }} }}"
        )


@dataclass(frozen=True)
class OriginalScannerExecutionProposal:
    table_base: int
    scanner_register: str
    count_register: str
    loaded_register: str
    selector_region: OriginalDecodedScannerRegionProposal
    zero_region: OriginalDecodedScannerRegionProposal
    scanner_region: OriginalDecodedScannerRegionProposal
    bridge_region: OriginalDecodedScannerRegionProposal
    gate_region: OriginalDecodedScannerRegionProposal
    dispatch_source_target_id: int
    dispatch_bypass_target_id: int

    def validate(self) -> None:
        _u32(self.table_base, "original scanner table base")
        for field, value in (
            ("scanner register", self.scanner_register),
            ("count register", self.count_register),
            ("loaded register", self.loaded_register),
        ):
            _register(value, f"original scanner {field}")
        for field, region in (
            ("selector region", self.selector_region),
            ("zero region", self.zero_region),
            ("scanner region", self.scanner_region),
            ("bridge region", self.bridge_region),
            ("gate region", self.gate_region),
        ):
            if not isinstance(region, OriginalDecodedScannerRegionProposal):
                raise StageAInputError(
                    f"original scanner {field} has the wrong proposal type"
                )
            region.validate(f"original scanner {field}")
        _natural(
            self.dispatch_source_target_id,
            "original scanner dispatch source target id",
        )
        _natural(
            self.dispatch_bypass_target_id,
            "original scanner dispatch bypass target id",
        )

    def lean(self) -> str:
        self.validate()
        return f"""{{
  tableBase := {self.table_base}
  scannerRegister := .{self.scanner_register}
  countRegister := .{self.count_register}
  loadedRegister := .{self.loaded_register}
  selectorRegion := {self.selector_region.lean("original scanner selector region")}
  zeroRegion := {self.zero_region.lean("original scanner zero region")}
  scannerRegion := {self.scanner_region.lean("original scanner scanner region")}
  bridgeRegion := {self.bridge_region.lean("original scanner bridge region")}
  gateRegion := {self.gate_region.lean("original scanner gate region")}
  dispatchSourceTargetId := {self.dispatch_source_target_id}
  dispatchBypassTargetId := {self.dispatch_bypass_target_id}
}}"""
