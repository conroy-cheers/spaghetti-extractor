"""Checked indexed-PE-table target evidence for analysis v3.

This adapter is intentionally narrower than the structural recovery pass.  It
re-reads the exact PE, binds the exact machine-IR and native-v3 projections,
and accepts only a 32-bit immutable table load whose selector is bounded by
every direct predecessor.  Structural proposals and older evidence are veto
inputs only: they can expose a contradiction, but can never supply a target.

The existing target-evaluation evidence schema has no indexed-table method.
Until the target-certificate checker grows that method, the checked table
certificate identity is carried by the required memory/fact identifiers and
the complete proof is retained in the adjacent report.  Consequently these
records remain fail-closed when consumed by the current certificate checker.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pefile

from ..authority._schema import mapping
from ..authority.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    IndirectExitOccurrenceV3,
    SemanticIndexRecordV3,
)
from ..authority.structural_targets import (
    STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
    STRUCTURAL_TARGET_UNIT_CODEC_V3,
    StructuralTargetProposalV3,
)
from ..authority.target_certificate_records import (
    TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3,
    TARGET_EVALUATION_EVIDENCE_CODEC_V3,
    TargetEvaluationEvidenceV3,
)
from ..authority.transition_records import (
    TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)
from ..artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactInputReaderV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
    open_artifact_reader_v3,
)


INDEXED_TARGET_EVIDENCE_REPORT_V3 = (
    "spaghetti-extractor-indexed-target-evidence-report-v3"
)
TARGET_HINTS_ARTIFACT_KIND_V3 = "target-hints-v3"
MACHINE_IR_FORMAT_V2 = "stage-a-machine-ir-v2"
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_READ = 0x40000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_MAX_TABLE_ENTRIES = 4096
_MAX_GUARD_BACKTRACK_DEPTH = 32
_MAX_GUARD_BACKTRACK_PATHS = 128


class IndexedTargetEvidenceV3Error(ValueError):
    """The provider itself was invoked with an unusable input boundary."""


@dataclass(frozen=True)
class _Issue:
    status: str
    code: str
    detail: str

    def to_payload(self) -> dict[str, str]:
        return {"status": self.status, "code": self.code, "detail": self.detail}


@dataclass(frozen=True)
class _TableShape:
    table_va: int
    selector: Any
    expression_form: str


@dataclass(frozen=True)
class _BoundProof:
    upper_exclusive: int
    support_unit_ids: tuple[str, ...]
    support_summary_ids: tuple[str, ...]


@dataclass(frozen=True)
class _Section:
    name: str
    rva_start: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def rva_end(self) -> int:
        return self.rva_start + max(self.virtual_size, self.raw_size)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_READ)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_WRITE)

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & _IMAGE_SCN_MEM_EXECUTE)

    def contains_raw(self, rva: int, size: int) -> bool:
        offset = rva - self.rva_start
        return 0 <= offset and 0 <= size and offset + size <= self.raw_size


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _binary_binding(reader: ArtifactInputReaderV3, label: str) -> ArtifactBindingV3:
    rows = tuple(
        row
        for row in reader.manifest.bindings
        if row.name == "binary" and row.kind == "pe32"
    )
    if len(rows) != 1:
        raise IndexedTargetEvidenceV3Error(
            f"{label} must have exactly one binary/pe32 binding"
        )
    return rows[0]


def _dependency(name: str, reader: ArtifactInputReaderV3) -> ArtifactDependencyV3:
    return ArtifactDependencyV3(
        name=name,
        artifact_kind=reader.manifest.artifact_kind,
        artifact_id=reader.manifest.artifact_id,
        manifest_sha256=reader.manifest_sha256,
    )


def _read_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IndexedTargetEvidenceV3Error(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise IndexedTargetEvidenceV3Error(f"{label} must be a JSON object")
    return value


def _manifest_machine_ir_sha256(manifest: Mapping[str, Any]) -> str | None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping):
        return None
    machine_ir = artifacts.get("machine_ir")
    if not isinstance(machine_ir, Mapping):
        return None
    value = machine_ir.get("sha256")
    return value if isinstance(value, str) else None


def _read_machine_ir(path: Path) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise IndexedTargetEvidenceV3Error(
            f"cannot read machine IR {path}: {exc}"
        ) from exc
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise IndexedTargetEvidenceV3Error(
                f"machine IR line {line_number} is invalid JSON: {exc}"
            ) from exc
        if not isinstance(value, Mapping) or value.get("record_kind") != "unit":
            continue
        unit_id = value.get("id")
        if not isinstance(unit_id, str) or not unit_id:
            raise IndexedTargetEvidenceV3Error(
                f"machine IR line {line_number} has no exact unit ID"
            )
        if unit_id in result:
            raise IndexedTargetEvidenceV3Error(
                f"machine IR repeats exact unit ID {unit_id!r}"
            )
        result[unit_id] = value
    if not result:
        raise IndexedTargetEvidenceV3Error("machine IR contains no unit records")
    return result


def _binary_operands(value: Any, operators: set[str]) -> tuple[Any, Any] | None:
    if not isinstance(value, Mapping) or str(value.get("op", "")).lower() not in operators:
        return None
    args = value.get("args")
    if isinstance(args, list) and len(args) == 2:
        return args[0], args[1]
    if "left" in value and "right" in value:
        return value["left"], value["right"]
    return None


def _constant(value: Any) -> int | None:
    if not isinstance(value, Mapping):
        return None
    if str(value.get("op", "")).lower() not in {"const", "constant"}:
        return None
    raw = value.get("value")
    if not isinstance(raw, int) or isinstance(raw, bool) or not 0 <= raw < 1 << 32:
        return None
    return raw


def _normalize_expression(value: Any) -> Any | None:
    """Normalize only the bounded expression fragment checked by this provider."""

    if not isinstance(value, Mapping):
        return None
    op = str(value.get("op", "")).lower()
    constant = _constant(value)
    if constant is not None:
        return {"op": "const", "value": constant, "width": 32}
    if op in {"reg", "register", "input_reg"}:
        name = value.get("name", value.get("reg"))
        if not isinstance(name, str):
            return None
        name = name.lower()
        low_bytes = {"al": "eax", "bl": "ebx", "cl": "ecx", "dl": "edx"}
        if name in low_bytes:
            return {
                "op": "and32",
                "args": [
                    {"op": "reg", "name": low_bytes[name], "width": 32},
                    {"op": "const", "value": 0xFF, "width": 32},
                ],
            }
        return {"op": "reg", "name": name, "width": 32}
    if op in {"and", "and32", "bit_and"}:
        operands = _binary_operands(value, {"and", "and32", "bit_and"})
        if operands is None:
            return None
        left = _normalize_expression(operands[0])
        right = _normalize_expression(operands[1])
        if left is None or right is None:
            return None
        ordered = sorted((left, right), key=canonical_sha256_v3)
        return {"op": "and32", "args": ordered}
    if op in {"add", "add32", "mul", "mul32", "multiply", "sub", "sub32"}:
        operands = _binary_operands(
            value,
            {"add", "add32", "mul", "mul32", "multiply", "sub", "sub32"},
        )
        if operands is None:
            return None
        left = _normalize_expression(operands[0])
        right = _normalize_expression(operands[1])
        if left is None or right is None:
            return None
        normalized_op = {
            "add": "add32",
            "add32": "add32",
            "mul": "mul32",
            "mul32": "mul32",
            "multiply": "mul32",
            "sub": "sub32",
            "sub32": "sub32",
        }[op]
        args = (
            sorted((left, right), key=canonical_sha256_v3)
            if normalized_op in {"add32", "mul32"}
            else [left, right]
        )
        return {"op": normalized_op, "args": args}
    if op in {"load", "read8", "read32"}:
        address = _normalize_expression(value.get("address"))
        width = value.get("width")
        if width is None:
            width = 1 if op == "read8" else 4 if op == "read32" else None
        if address is None or width not in {1, 2, 4}:
            return None
        return {"op": "load", "width": width, "address": address}
    if op in {"zero_extend", "zext", "truncate", "trunc"}:
        inner = value.get("value", value.get("source"))
        normalized = _normalize_expression(inner)
        width = value.get("from_width", value.get("width_bits", value.get("width")))
        if normalized is None or width not in {8, 32, None}:
            return None
        if width == 8 and normalized.get("op") == "reg":
            return {
                "op": "and32",
                "args": [
                    normalized,
                    {"op": "const", "value": 0xFF, "width": 32},
                ],
            }
        return normalized
    return None


def _substitute_summary_outputs(
    expression: Any, summary: TransitionSummaryRecordV3
) -> Any:
    outputs = {
        (row.category, row.destination.lower()): row.value.to_value()
        for row in summary.outputs
        if row.category in {"register", "flag"}
    }

    def substitute(value: Any) -> Any:
        if not isinstance(value, Mapping):
            return value
        op = str(value.get("op", "")).lower()
        if op in {"reg", "register", "input_reg"}:
            name = value.get("name", value.get("reg"))
            key = ("register", name.lower()) if isinstance(name, str) else None
            if key is not None and key in outputs:
                return outputs[key]
            return dict(value)
        if op in {"flag", "input_flag"}:
            name = value.get("name", value.get("flag"))
            key = ("flag", name.lower()) if isinstance(name, str) else None
            if key is not None and key in outputs:
                return outputs[key]
            return dict(value)
        return {
            key: (
                [substitute(row) for row in item]
                if isinstance(item, list)
                else substitute(item)
                if isinstance(item, Mapping)
                else item
            )
            for key, item in value.items()
        }

    substituted = substitute(expression)
    return _normalize_expression(substituted) or substituted


def _table_shape(expression: Any) -> _TableShape | None:
    if not isinstance(expression, Mapping) or str(expression.get("op", "")).lower() not in {
        "load",
        "read32",
    }:
        return None
    if expression.get("op") == "load":
        if expression.get("width") not in {4, None}:
            return None
        if expression.get("width") is None and expression.get("width_bits") != 32:
            return None
    address = expression.get("address")
    add = _binary_operands(address, {"add", "add32"})
    if add is None:
        return None
    for base_value, scaled_value in (add, (add[1], add[0])):
        base = _constant(base_value)
        if base is None:
            continue
        multiply = _binary_operands(scaled_value, {"mul", "mul32", "multiply"})
        if multiply is not None:
            for selector_value, scale_value in (multiply, (multiply[1], multiply[0])):
                if _constant(scale_value) == 4:
                    selector = _normalize_expression(selector_value)
                    if selector is not None:
                        return _TableShape(base, selector, "multiply_4")
        if isinstance(scaled_value, Mapping) and str(scaled_value.get("op", "")).lower() in {
            "shl",
            "shl32",
            "shift_left",
        }:
            amount = scaled_value.get("amount", scaled_value.get("right"))
            amount_value = amount if isinstance(amount, int) else _constant(amount)
            selector_value = scaled_value.get("value", scaled_value.get("left"))
            selector = _normalize_expression(selector_value)
            if amount_value == 2 and selector is not None:
                return _TableShape(base, selector, "shift_left_2")
    return None


def _condition_bound(condition: Any, selector: Any) -> int | None:
    if not isinstance(condition, Mapping):
        return None
    op = str(condition.get("op", "")).lower()
    operands = _binary_operands(
        condition,
        {
            "ult",
            "ult32",
            "unsigned_less",
            "unsigned_lt",
            "ule",
            "ule32",
            "unsigned_less_equal",
            "unsigned_le",
        },
    )
    if operands is not None and _normalize_expression(operands[0]) == selector:
        bound = _constant(operands[1])
        if bound is not None:
            if op in {"ule", "ule32", "unsigned_less_equal", "unsigned_le"}:
                if bound == 0xFFFFFFFF:
                    return None
                bound += 1
            return bound if 0 < bound <= _MAX_TABLE_ENTRIES else None
    above_bound = _complemented_unsigned_above_bound(condition, selector)
    if above_bound is not None:
        return above_bound
    return _enumerated_condition_bound(condition, selector)


def _not_operand(value: Any) -> Any | None:
    if not isinstance(value, Mapping) or str(value.get("op", "")).lower() != "not":
        return None
    args = value.get("args")
    return args[0] if isinstance(args, list) and len(args) == 1 else None


def _zero_comparison_bound(value: Any, selector: Any) -> int | None:
    operands = _binary_operands(value, {"eq"})
    if operands is None:
        return None
    expression = None
    for candidate, zero in (operands, (operands[1], operands[0])):
        if _constant(zero) == 0:
            expression = candidate
            break
    if expression is None:
        return None
    normalized = _normalize_expression(expression)
    if isinstance(normalized, Mapping) and normalized.get("op") == "and32":
        args = normalized.get("args")
        if isinstance(args, list) and len(args) == 2:
            nonconstants = [row for row in args if _constant(row) is None]
            if len(nonconstants) == 1:
                normalized = nonconstants[0]
    if not isinstance(normalized, Mapping) or normalized.get("op") != "sub32":
        return None
    args = normalized.get("args")
    if (
        not isinstance(args, list)
        or len(args) != 2
        or args[0] != selector
    ):
        return None
    return _constant(args[1])


def _unsigned_less_bound(value: Any, selector: Any) -> int | None:
    operands = _binary_operands(
        value, {"ult", "ult32", "unsigned_less", "unsigned_lt"}
    )
    if operands is None or _normalize_expression(operands[0]) != selector:
        return None
    return _constant(operands[1])


def _complemented_unsigned_above_bound(
    condition: Any, selector: Any
) -> int | None:
    """Recognize the normalized x86 ``not (CF=0 and ZF=0)`` guard.

    The direct edge into a jump table after ``cmp selector, N; ja fallback``
    is the complement of unsigned-above.  Exact flag semantics expands that
    compact source condition into a Boolean formula; recognizing the formula
    here is independent of instruction spelling and still checks both CF and
    ZF terms against the same selector and bound.
    """

    inner = _not_operand(condition)
    operands = (
        None
        if inner is None
        else _binary_operands(inner, {"and_bool"})
    )
    if operands is None:
        return None
    zero_bounds: list[int] = []
    less_bounds: list[int] = []
    for operand in operands:
        negated = _not_operand(operand)
        if negated is None:
            return None
        zero_bound = _zero_comparison_bound(negated, selector)
        less_bound = _unsigned_less_bound(negated, selector)
        if zero_bound is not None:
            zero_bounds.append(zero_bound)
        elif less_bound is not None:
            less_bounds.append(less_bound)
        else:
            return None
    if len(zero_bounds) != 1 or len(less_bounds) != 1:
        return None
    if zero_bounds[0] != less_bounds[0] or zero_bounds[0] == 0xFFFFFFFF:
        return None
    result = zero_bounds[0] + 1
    return result if 0 < result <= _MAX_TABLE_ENTRIES else None


def _selector_domain(selector: Any) -> tuple[int, ...] | None:
    if not isinstance(selector, Mapping) or selector.get("op") != "and32":
        return None
    args = selector.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    mask = next((_constant(row) for row in args if _constant(row) is not None), None)
    if mask is None or mask >= _MAX_TABLE_ENTRIES:
        return None
    return tuple(value for value in range(mask + 1) if value & ~mask == 0)


def _evaluate_guard_expression(value: Any, selector: Any, selected: int) -> Any | None:
    if _normalize_expression(value) == selector:
        return selected
    constant = _constant(value)
    if constant is not None:
        return constant
    if not isinstance(value, Mapping):
        return value if isinstance(value, bool) else None
    op = str(value.get("op", "")).lower()
    args = value.get("args")
    if op == "not" and isinstance(args, list) and len(args) == 1:
        inner = _evaluate_guard_expression(args[0], selector, selected)
        return not inner if isinstance(inner, bool) else None
    binary = _binary_operands(
        value,
        {
            "add",
            "add32",
            "sub",
            "sub32",
            "and",
            "and32",
            "bit_and",
            "or32",
            "xor32",
            "eq",
            "neq",
            "ult",
            "ult32",
            "unsigned_less",
            "unsigned_lt",
            "ule",
            "ule32",
            "unsigned_less_equal",
            "unsigned_le",
            "and_bool",
            "or_bool",
        },
    )
    if binary is None:
        return None
    left = _evaluate_guard_expression(binary[0], selector, selected)
    right = _evaluate_guard_expression(binary[1], selector, selected)
    if op in {"and_bool", "or_bool"}:
        if not isinstance(left, bool) or not isinstance(right, bool):
            return None
        return left and right if op == "and_bool" else left or right
    if (
        not isinstance(left, int)
        or isinstance(left, bool)
        or not isinstance(right, int)
        or isinstance(right, bool)
    ):
        return None
    left &= 0xFFFFFFFF
    right &= 0xFFFFFFFF
    if op in {"add", "add32"}:
        return (left + right) & 0xFFFFFFFF
    if op in {"sub", "sub32"}:
        return (left - right) & 0xFFFFFFFF
    if op in {"and", "and32", "bit_and"}:
        return left & right
    if op == "or32":
        return left | right
    if op == "xor32":
        return left ^ right
    if op == "eq":
        return left == right
    if op == "neq":
        return left != right
    if op in {"ult", "ult32", "unsigned_less", "unsigned_lt"}:
        return left < right
    if op in {"ule", "ule32", "unsigned_less_equal", "unsigned_le"}:
        return left <= right
    return None


def _enumerated_condition_bound(condition: Any, selector: Any) -> int | None:
    domain = _selector_domain(selector)
    if domain is None:
        return None
    accepted: list[int] = []
    for selected in domain:
        result = _evaluate_guard_expression(condition, selector, selected)
        if not isinstance(result, bool):
            return None
        if result:
            accepted.append(selected)
    if not accepted:
        return None
    bound = max(accepted) + 1
    if bound > _MAX_TABLE_ENTRIES or accepted != list(range(bound)):
        return None
    return bound


def _section_for_rva(sections: Iterable[_Section], rva: int) -> _Section | None:
    rows = tuple(section for section in sections if section.rva_start <= rva < section.rva_end)
    return rows[0] if len(rows) == 1 else None


def _parse_pe(path: Path) -> tuple[bytes, int, tuple[_Section, ...]]:
    try:
        data = path.read_bytes()
        pe = pefile.PE(data=data, fast_load=True)
    except (OSError, pefile.PEFormatError) as exc:
        raise IndexedTargetEvidenceV3Error(f"cannot parse exact PE {path}: {exc}") from exc
    file_header = pe.FILE_HEADER
    optional_header = pe.OPTIONAL_HEADER
    if (
        file_header is None
        or optional_header is None
        or getattr(file_header, "Machine", None) != 0x14C
        or getattr(optional_header, "Magic", None) != 0x10B
    ):
        raise IndexedTargetEvidenceV3Error("indexed table provider requires x86 PE32")
    sections = tuple(
        _Section(
            section.Name.rstrip(b"\0").decode("ascii", errors="replace"),
            int(section.VirtualAddress),
            int(section.Misc_VirtualSize),
            int(section.PointerToRawData),
            int(section.SizeOfRawData),
            int(section.Characteristics),
        )
        for section in pe.sections
    )
    return data, int(getattr(optional_header, "ImageBase")), sections


def _read_exact_rva(data: bytes, section: _Section, rva: int, size: int) -> bytes | None:
    if not section.contains_raw(rva, size):
        return None
    start = section.raw_offset + rva - section.rva_start
    end = start + size
    if not 0 <= start <= end <= len(data):
        return None
    return data[start:end]


def _artifact_index(reader: ArtifactInputReaderV3, codec: Any) -> dict[str, Any]:
    return {
        record.record_id: codec.read(record).value
        for record in reader.iter_records()
    }


def _target_hint(reader: ArtifactInputReaderV3 | None, exit_id: str) -> Mapping[str, Any] | None:
    if reader is None:
        return None
    try:
        record = reader.get_record(exit_id)
    except KeyError:
        return None
    value = record.value.to_value()
    return value if isinstance(value, Mapping) else None


def _manifest_recovery(manifest: Mapping[str, Any], exit_id: str) -> tuple[Mapping[str, Any] | None, _Issue | None]:
    control = manifest.get("control")
    if not isinstance(control, Mapping):
        return None, None
    rows = control.get("recovered_indirect_targets")
    if rows is None:
        return None, None
    if not isinstance(rows, list):
        return None, _Issue("violated", "machine_manifest_target_inventory_malformed", "recovered_indirect_targets is not an array")
    matches = [row for row in rows if isinstance(row, Mapping) and row.get("id") == exit_id]
    if len(matches) > 1:
        return None, _Issue("violated", "machine_manifest_target_inventory_ambiguous", "machine manifest repeats the exact indirect exit")
    return (matches[0], None) if matches else (None, None)


def _machine_direct_targets(unit: Mapping[str, Any]) -> tuple[int, ...] | None:
    control = unit.get("control")
    if not isinstance(control, Mapping):
        return None
    values = control.get("direct_targets")
    if not isinstance(values, list) or any(
        not isinstance(value, int) or isinstance(value, bool) for value in values
    ):
        return None
    return tuple(sorted(set(values)))


def _checked_direct_predecessors(
    *,
    target_rva: int,
    machine_units: Mapping[str, Mapping[str, Any]],
    semantics: Mapping[str, SemanticIndexRecordV3],
    summaries: Mapping[str, TransitionSummaryRecordV3],
) -> tuple[
    tuple[tuple[SemanticIndexRecordV3, TransitionSummaryRecordV3], ...],
    _Issue | None,
]:
    predecessors: list[tuple[SemanticIndexRecordV3, TransitionSummaryRecordV3]] = []
    for unit_id, candidate in semantics.items():
        if target_rva not in candidate.direct_target_rvas:
            continue
        raw = machine_units.get(unit_id)
        summary = summaries.get(unit_id)
        if raw is None or summary is None:
            return (), _Issue(
                "violated",
                "indexed_predecessor_binding_missing",
                f"predecessor {unit_id} is absent from an exact input",
            )
        control = raw.get("control")
        if not isinstance(control, Mapping) or control.get("kind") not in {
            "branch",
            "direct_jump",
            "fallthrough",
            "jump",
        }:
            continue
        direct_targets = _machine_direct_targets(raw)
        if direct_targets is None or tuple(candidate.direct_target_rvas) != direct_targets:
            return (), _Issue(
                "violated",
                "indexed_predecessor_binding_contradiction",
                f"predecessor {unit_id} control inventory disagrees",
            )
        if (
            canonical_sha256_v3(raw) != candidate.unit_ir_sha256
            or summary.unit_ir_sha256 != candidate.unit_ir_sha256
        ):
            return (), _Issue(
                "violated",
                "indexed_predecessor_binding_contradiction",
                f"predecessor {unit_id} exact projections disagree",
            )
        predecessors.append((candidate, summary))
    return tuple(sorted(predecessors, key=lambda row: row[0].record_id)), None


def _bound_through_predecessor_chain(
    *,
    condition: Any,
    selector: Any,
    predecessor: SemanticIndexRecordV3,
    summary: TransitionSummaryRecordV3,
    machine_units: Mapping[str, Mapping[str, Any]],
    semantics: Mapping[str, SemanticIndexRecordV3],
    summaries: Mapping[str, TransitionSummaryRecordV3],
    depth: int = 0,
    visited: frozenset[str] = frozenset(),
    path_budget: list[int] | None = None,
) -> tuple[_BoundProof | None, _Issue | None]:
    """Prove one selector bound by replaying a finite direct-control prefix.

    The edge condition is stated over the predecessor's post-state. Replacing
    register and flag outputs rewrites it over the predecessor's input state;
    repeating that operation walks back to the instruction that established
    the compare operands. Every incoming direct path must establish the same
    bound, so a join cannot silently discard an alternative.
    """

    if path_budget is None:
        path_budget = [_MAX_GUARD_BACKTRACK_PATHS]
    if path_budget[0] <= 0:
        return None, _Issue(
            "incomplete",
            "indexed_selector_guard_path_budget_exceeded",
            "selector-bound proof exceeds the checked direct-path budget",
        )
    path_budget[0] -= 1
    if depth > _MAX_GUARD_BACKTRACK_DEPTH:
        return None, _Issue(
            "incomplete",
            "indexed_selector_guard_depth_exceeded",
            "selector-bound proof exceeds the checked predecessor depth",
        )
    if predecessor.record_id in visited:
        return None, _Issue(
            "incomplete",
            "indexed_selector_guard_cycle",
            f"selector-bound proof reaches cycle at {predecessor.record_id}",
        )

    rewritten_condition = _substitute_summary_outputs(condition, summary)
    rewritten_selector = _substitute_summary_outputs(selector, summary)
    bound = _condition_bound(rewritten_condition, rewritten_selector)
    if bound is not None:
        return (
            _BoundProof(
                upper_exclusive=bound,
                support_unit_ids=(predecessor.record_id,),
                support_summary_ids=(summary.summary_id,),
            ),
            None,
        )

    upstream, issue = _checked_direct_predecessors(
        target_rva=predecessor.rva_start,
        machine_units=machine_units,
        semantics=semantics,
        summaries=summaries,
    )
    if issue is not None:
        return None, issue
    if not upstream:
        return None, _Issue(
            "incomplete",
            "indexed_selector_guard_unsupported",
            f"no checked predecessor chain proves a bound before {predecessor.record_id}",
        )

    proofs: list[_BoundProof] = []
    next_visited = visited | {predecessor.record_id}
    for upstream_unit, upstream_summary in upstream:
        proof, issue = _bound_through_predecessor_chain(
            condition=rewritten_condition,
            selector=rewritten_selector,
            predecessor=upstream_unit,
            summary=upstream_summary,
            machine_units=machine_units,
            semantics=semantics,
            summaries=summaries,
            depth=depth + 1,
            visited=next_visited,
            path_budget=path_budget,
        )
        if issue is not None:
            return None, issue
        assert proof is not None
        proofs.append(proof)
    bounds = {proof.upper_exclusive for proof in proofs}
    if len(bounds) != 1:
        return None, _Issue(
            "incomplete",
            "indexed_selector_guard_ambiguous",
            f"predecessors of {predecessor.record_id} prove different bounds",
        )
    return (
        _BoundProof(
            upper_exclusive=next(iter(bounds)),
            support_unit_ids=tuple(
                sorted(
                    {
                        predecessor.record_id,
                        *(unit_id for proof in proofs for unit_id in proof.support_unit_ids),
                    }
                )
            ),
            support_summary_ids=tuple(
                sorted(
                    {
                        summary.summary_id,
                        *(summary_id for proof in proofs for summary_id in proof.support_summary_ids),
                    }
                )
            ),
        ),
        None,
    )


def _relevant_write_issue(
    summaries: Iterable[TransitionSummaryRecordV3],
    relevant_unit_ids: set[str],
    *,
    image_base: int,
    table_rva: int,
    table_size: int,
) -> _Issue | None:
    table_start = image_base + table_rva
    table_end = table_start + table_size
    for summary in summaries:
        if summary.unit_id not in relevant_unit_ids:
            continue
        for access in summary.memory_accesses:
            if access.memory_kind not in {"write", "read_write"}:
                continue
            address = _constant(access.address.to_value())
            if address is None:
                return _Issue(
                    "incomplete",
                    "indexed_table_write_alias_unknown",
                    f"{summary.unit_id} has a write whose address cannot be proved disjoint",
                )
            if address < table_end and table_start < address + access.width_bytes:
                return _Issue(
                    "violated",
                    "indexed_table_write_overlap",
                    f"{summary.unit_id} writes the purported immutable table",
                )
    return None


def _proof_for_exit(
    *,
    occurrence: IndirectExitOccurrenceV3,
    semantic: SemanticIndexRecordV3,
    proposal: StructuralTargetProposalV3 | None,
    machine_units: Mapping[str, Mapping[str, Any]],
    semantics: Mapping[str, SemanticIndexRecordV3],
    summaries: Mapping[str, TransitionSummaryRecordV3],
    hint: Mapping[str, Any] | None,
    prior: TargetEvaluationEvidenceV3 | None,
    manifest_recovery: Mapping[str, Any] | None,
    image_data: bytes,
    image_base: int,
    sections: tuple[_Section, ...],
) -> tuple[TargetEvaluationEvidenceV3 | None, dict[str, Any]]:
    expression = occurrence.target_expression.to_value()
    base_report: dict[str, Any] = {
        "exit_id": occurrence.exit_id,
        "source_unit_id": semantic.record_id,
        "source_rva": semantic.rva_start,
        "source_event_index": occurrence.event_index,
        "transfer_kind": occurrence.transfer_kind,
        "target_expression_sha256": canonical_sha256_v3(expression),
    }

    def fail(status: str, code: str, detail: str) -> tuple[None, dict[str, Any]]:
        return None, {
            **base_report,
            "status": status,
            "authorizing": False,
            "issue": _Issue(status, code, detail).to_payload(),
        }

    shape = _table_shape(expression)
    if shape is None:
        return fail(
            "incomplete",
            "indexed_target_expression_unsupported",
            "target is not a checked 32-bit base + selector * 4 PE load",
        )
    if not image_base <= shape.table_va < image_base + (1 << 32):
        return fail("incomplete", "indexed_table_base_outside_image", "table base is not an in-image PE32 VA")
    table_rva = shape.table_va - image_base
    section = _section_for_rva(sections, table_rva)
    if section is None:
        return fail("incomplete", "indexed_table_section_missing", "table base does not resolve to one PE section")
    if not section.readable:
        return fail("incomplete", "indexed_table_section_unreadable", "table section is not readable")
    if section.writable:
        return fail("incomplete", "indexed_table_section_mutable", "table section is writable")

    source_summary = summaries.get(semantic.record_id)
    source_unit = machine_units.get(semantic.record_id)
    if source_summary is None or source_unit is None:
        return fail("violated", "indexed_source_binding_missing", "source unit is absent from an exact input")
    if source_summary.status != "complete":
        return fail("incomplete", "indexed_source_semantics_incomplete", "source transition summary is incomplete")
    if source_summary.unit_ir_sha256 != semantic.unit_ir_sha256 or canonical_sha256_v3(source_unit) != semantic.unit_ir_sha256:
        return fail("violated", "indexed_source_binding_contradiction", "machine IR, semantic index, and transition summary disagree")

    predecessors, predecessor_issue = _checked_direct_predecessors(
        target_rva=semantic.rva_start,
        machine_units=machine_units,
        semantics=semantics,
        summaries=summaries,
    )
    if predecessor_issue is not None:
        return fail(
            predecessor_issue.status,
            predecessor_issue.code,
            predecessor_issue.detail,
        )
    if not predecessors:
        return fail("incomplete", "indexed_selector_predecessor_missing", "dispatch has no checked direct predecessor")

    bounds: set[int] = set()
    predecessor_rows: list[dict[str, Any]] = []
    for predecessor, summary in sorted(predecessors, key=lambda row: row[0].record_id):
        matching_guards = []
        for guard in summary.guards:
            row = guard.exact_record.to_value()
            if not isinstance(row, Mapping) or row.get("target_rva") != semantic.rva_start:
                continue
            matching_guards.append(row)
        if len(matching_guards) != 1:
            return fail(
                "incomplete",
                "indexed_selector_guard_coverage_missing",
                f"predecessor {predecessor.record_id} does not have one exact guard for the dispatch edge",
            )
        condition = matching_guards[0].get("condition")
        proof, issue = _bound_through_predecessor_chain(
            condition=condition,
            selector=shape.selector,
            predecessor=predecessor,
            summary=summary,
            machine_units=machine_units,
            semantics=semantics,
            summaries=summaries,
        )
        if issue is not None:
            return fail(
                issue.status,
                issue.code,
                issue.detail,
            )
        assert proof is not None
        bound = proof.upper_exclusive
        bounds.add(bound)
        predecessor_rows.append(
            {
                "source_unit_id": predecessor.record_id,
                "guard_sha256": canonical_sha256_v3(matching_guards[0]),
                "upper_exclusive": bound,
                "support_unit_ids": list(proof.support_unit_ids),
                "support_summary_ids": list(proof.support_summary_ids),
            }
        )
    if len(bounds) != 1:
        return fail("incomplete", "indexed_selector_guard_ambiguous", "direct predecessors prove different selector bounds")
    entry_count = next(iter(bounds))
    table_size = entry_count * 4
    if not section.contains_raw(table_rva, table_size):
        return fail("incomplete", "indexed_table_span_out_of_range", "bounded table does not fit exact raw PE bytes")
    table_bytes = _read_exact_rva(image_data, section, table_rva, table_size)
    if table_bytes is None or len(table_bytes) != table_size:
        return fail("violated", "indexed_table_bytes_unreadable", "exact PE table bytes are truncated or corrupt")
    table_sha256 = hashlib.sha256(table_bytes).hexdigest()

    expected_table_sha256 = None
    if manifest_recovery is not None:
        raw_table = manifest_recovery.get("table")
        if isinstance(raw_table, Mapping):
            raw_sha = raw_table.get("bytes_sha256", raw_table.get("sha256"))
            if isinstance(raw_sha, str):
                expected_table_sha256 = raw_sha
        direct_sha = manifest_recovery.get("table_sha256")
        if isinstance(direct_sha, str):
            if expected_table_sha256 is not None and direct_sha != expected_table_sha256:
                return fail("violated", "indexed_table_sha256_proposal_contradiction", "machine manifest carries two different table hashes")
            expected_table_sha256 = direct_sha
    if expected_table_sha256 is not None and expected_table_sha256 != table_sha256:
        return fail("violated", "indexed_table_sha256_contradiction", "exact PE bytes differ from the bound table hash")

    relevant_ids = {
        semantic.record_id,
        *(
            unit_id
            for predecessor_row in predecessor_rows
            for unit_id in predecessor_row["support_unit_ids"]
        ),
    }
    write_issue = _relevant_write_issue(
        summaries.values(),
        relevant_ids,
        image_base=image_base,
        table_rva=table_rva,
        table_size=table_size,
    )
    if write_issue is not None:
        return fail(write_issue.status, write_issue.code, write_issue.detail)

    unit_by_rva: dict[int, list[str]] = {}
    for target in semantics.values():
        unit_by_rva.setdefault(target.rva_start, []).append(target.record_id)
    target_unit_ids: set[str] = set()
    entries: list[dict[str, Any]] = []
    for index in range(entry_count):
        target_va = int.from_bytes(table_bytes[index * 4 : index * 4 + 4], "little")
        if not image_base <= target_va < image_base + (1 << 32):
            return fail("incomplete", "indexed_table_target_out_of_range", f"table entry {index} is not an in-image PE32 VA")
        target_rva = target_va - image_base
        target_section = _section_for_rva(sections, target_rva)
        if target_section is None or not target_section.executable:
            return fail("incomplete", "indexed_table_target_not_executable", f"table entry {index} does not resolve to executable PE bytes")
        target_ids = unit_by_rva.get(target_rva, [])
        if len(target_ids) != 1:
            return fail(
                "violated" if len(target_ids) > 1 else "incomplete",
                "indexed_table_target_ambiguous" if len(target_ids) > 1 else "indexed_table_target_unit_missing",
                f"table entry {index} resolves to {len(target_ids)} exact structural units",
            )
        target_id = target_ids[0]
        target_unit_ids.add(target_id)
        entries.append(
            {
                "index": index,
                "entry_rva": table_rva + index * 4,
                "target_rva": target_rva,
                "target_unit_id": target_id,
            }
        )
    ordered_targets = tuple(sorted(target_unit_ids))

    if proposal is None:
        return fail("violated", "indexed_structural_proposal_missing", "structural target inventory omits the exact exit")
    if (
        proposal.source_unit_id != semantic.record_id
        or proposal.source_rva != semantic.rva_start
        or proposal.source_event_index != occurrence.event_index
        or proposal.transfer_kind != occurrence.transfer_kind
    ):
        return fail("violated", "indexed_structural_binding_contradiction", "structural proposal is bound to another exit")
    if proposal.status == "violated":
        return fail("violated", "indexed_structural_proposal_violated", "structural proposal reports contradictory evidence")
    if proposal.status == "recovered" and (
        proposal.target_unit_ids != ordered_targets or proposal.external_targets
    ):
        return fail("violated", "indexed_structural_inventory_contradiction", "structural proposal differs from exact table targets")

    if hint is not None and hint.get("status") == "recovered":
        hinted = hint.get("target_unit_ids")
        if not isinstance(hinted, list) or tuple(sorted(set(hinted))) != ordered_targets:
            return fail("violated", "indexed_target_hint_contradiction", "recovered target hint differs from exact table targets")
    if prior is not None:
        if (
            prior.source_unit_id != semantic.record_id
            or prior.source_rva != semantic.rva_start
            or prior.source_event_index != occurrence.event_index
            or prior.transfer_kind != occurrence.transfer_kind
            or prior.target_expression_sha256 != canonical_sha256_v3(expression)
            or prior.target_unit_ids != ordered_targets
            or prior.external_targets
        ):
            return fail("violated", "indexed_prior_evidence_contradiction", "current target evidence differs from exact indexed-table proof")

    proof_payload = {
        **base_report,
        "image_base": image_base,
        "table_rva": table_rva,
        "entry_width": 4,
        "entry_count": entry_count,
        "table_sha256": table_sha256,
        "table_section": section.name,
        "selector": shape.selector,
        "selector_sha256": canonical_sha256_v3(shape.selector),
        "predecessors": predecessor_rows,
        "entries": entries,
        "target_unit_ids": list(ordered_targets),
    }
    evaluation_certificate = {
        "kind": "checked-indexed-pe-table-v3",
        "exit_id": occurrence.exit_id,
        "source_unit_id": semantic.record_id,
        "source_rva": semantic.rva_start,
        "source_event_index": occurrence.event_index,
        "transfer_kind": occurrence.transfer_kind,
        "target_expression_sha256": canonical_sha256_v3(expression),
        "image_base": image_base,
        "table_rva": table_rva,
        "entry_width": 4,
        "entry_count": entry_count,
        "table_sha256": table_sha256,
        "selector_sha256": canonical_sha256_v3(shape.selector),
        "predecessors": predecessor_rows,
        "entries": entries,
        "target_unit_ids": list(ordered_targets),
    }
    proof_sha256 = canonical_sha256_v3(evaluation_certificate)
    evidence = TargetEvaluationEvidenceV3.create(
        record_id=occurrence.exit_id,
        source_unit_id=semantic.record_id,
        source_rva=semantic.rva_start,
        source_event_index=occurrence.event_index,
        transfer_kind=occurrence.transfer_kind,
        target_expression=expression,
        evaluation_method="checked_indexed_pe_table",
        memory_record_id=f"checked-indexed-pe-table:{proof_sha256}",
        inductive_fact_id=None,
        target_unit_ids=ordered_targets,
        evaluation_certificate=evaluation_certificate,
    )
    return evidence, {
        **proof_payload,
        "status": "complete",
        "authorizing": False,
        "evidence_sha256": evidence.evidence_sha256,
        "note": "checked provider evidence; the target-certificate phase rechecks its exact semantic bindings",
    }


def generate_indexed_target_evidence_v3(
    *,
    binary_path: Path,
    machine_ir_path: Path,
    machine_ir_manifest_path: Path,
    semantic_index_path: Path,
    transition_summaries_path: Path,
    structural_targets_path: Path,
    output_directory: Path,
    target_hints_path: Path | None = None,
    target_evidence_path: Path | None = None,
) -> dict[str, Any]:
    """Generate deterministic checked evidence and a per-exit diagnostic report."""

    semantic_reader = open_artifact_reader_v3(semantic_index_path)
    transition_reader = open_artifact_reader_v3(transition_summaries_path)
    structural_reader = open_artifact_reader_v3(structural_targets_path)
    hints_reader = None if target_hints_path is None else open_artifact_reader_v3(target_hints_path)
    prior_reader = None if target_evidence_path is None else open_artifact_reader_v3(target_evidence_path)
    readers = {
        "semantic_index": semantic_reader,
        "transition_summaries": transition_reader,
        "structural_targets": structural_reader,
    }
    if hints_reader is not None:
        readers["target_hints"] = hints_reader
    if prior_reader is not None:
        readers["target_evidence"] = prior_reader

    global_issues: list[_Issue] = []
    expected_kinds = {
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        "transition_summaries": TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
        "structural_targets": STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
        "target_hints": TARGET_HINTS_ARTIFACT_KIND_V3,
        "target_evidence": TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3,
    }
    bindings: dict[str, ArtifactBindingV3] = {}
    for name, reader in readers.items():
        if reader.manifest.artifact_kind != expected_kinds[name]:
            global_issues.append(_Issue("violated", "indexed_input_kind_contradiction", f"{name} has kind {reader.manifest.artifact_kind!r}"))
        try:
            bindings[name] = _binary_binding(reader, name)
        except IndexedTargetEvidenceV3Error as exc:
            global_issues.append(_Issue("violated", "indexed_binary_binding_missing", str(exc)))
        if reader.manifest.status == "violated":
            global_issues.append(_Issue("violated", "indexed_input_artifact_violated", f"{name} status is violated"))
        elif reader.manifest.status != "complete":
            global_issues.append(_Issue("incomplete", "indexed_input_artifact_incomplete", f"{name} status is {reader.manifest.status}"))
    unique_bindings = set(bindings.values())
    if len(unique_bindings) != 1:
        global_issues.append(_Issue("violated", "indexed_binary_binding_contradiction", "v3 inputs do not share one exact PE binding"))
    output_binding = bindings.get("semantic_index")
    if output_binding is None:
        raise IndexedTargetEvidenceV3Error("semantic index has no usable binary binding")

    actual_pe_sha256 = _sha256_file(binary_path)
    if actual_pe_sha256 != output_binding.sha256:
        global_issues.append(_Issue("violated", "indexed_pe_sha256_contradiction", "exact PE path does not match the v3 binary binding"))
    machine_manifest = _read_json(machine_ir_manifest_path, "machine-IR manifest")
    actual_machine_ir_sha256 = _sha256_file(machine_ir_path)
    manifest_machine_ir_sha256 = _manifest_machine_ir_sha256(machine_manifest)
    if manifest_machine_ir_sha256 is None:
        global_issues.append(_Issue("incomplete", "indexed_machine_ir_manifest_binding_missing", "machine-IR manifest has no artifact SHA-256"))
    elif manifest_machine_ir_sha256 != actual_machine_ir_sha256:
        global_issues.append(_Issue("violated", "indexed_machine_ir_manifest_contradiction", "machine-IR manifest does not bind the exact machine IR bytes"))

    try:
        image_data, image_base, sections = _parse_pe(binary_path)
        machine_units = _read_machine_ir(machine_ir_path)
        semantics = _artifact_index(semantic_reader, SEMANTIC_INDEX_CODEC_V3)
        summaries = _artifact_index(transition_reader, TRANSITION_SUMMARY_CODEC_V3)
        structural_units = _artifact_index(structural_reader, STRUCTURAL_TARGET_UNIT_CODEC_V3)
        prior = {} if prior_reader is None else _artifact_index(prior_reader, TARGET_EVALUATION_EVIDENCE_CODEC_V3)
    except (IndexedTargetEvidenceV3Error, ValueError) as exc:
        global_issues.append(_Issue("violated", "indexed_input_decode_contradiction", str(exc)))
        image_data, image_base, sections = b"", 0, ()
        machine_units, semantics, summaries, structural_units, prior = {}, {}, {}, {}, {}

    records: list[ArtifactRecordV3] = []
    exit_reports: list[dict[str, Any]] = []
    if not any(issue.status == "violated" for issue in global_issues):
        for unit_id, semantic in sorted(semantics.items()):
            structural = structural_units.get(unit_id)
            proposals = {} if structural is None else {row.record_id: row for row in structural.proposals}
            for occurrence in semantic.indirect_exits:
                recovery, recovery_issue = _manifest_recovery(machine_manifest, occurrence.exit_id)
                if recovery_issue is not None:
                    exit_reports.append({
                        "exit_id": occurrence.exit_id,
                        "source_unit_id": unit_id,
                        "status": recovery_issue.status,
                        "authorizing": False,
                        "issue": recovery_issue.to_payload(),
                    })
                    continue
                evidence, report = _proof_for_exit(
                    occurrence=occurrence,
                    semantic=semantic,
                    proposal=proposals.get(occurrence.exit_id),
                    machine_units=machine_units,
                    semantics=semantics,
                    summaries=summaries,
                    hint=_target_hint(hints_reader, occurrence.exit_id),
                    prior=prior.get(occurrence.exit_id),
                    manifest_recovery=recovery,
                    image_data=image_data,
                    image_base=image_base,
                    sections=sections,
                )
                exit_reports.append(report)
                if evidence is not None:
                    records.append(TARGET_EVALUATION_EVIDENCE_CODEC_V3.write(evidence.record_id, evidence))

    statuses = [issue.status for issue in global_issues] + [str(row["status"]) for row in exit_reports]
    status = "violated" if "violated" in statuses else "incomplete" if "incomplete" in statuses else "complete"
    dependencies = tuple(_dependency(name, reader) for name, reader in sorted(readers.items()))
    output_directory.mkdir(parents=True, exist_ok=False)
    manifest = ArtifactSetWriterV3(
        artifact_kind=TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3,
        bindings=(output_binding,),
        dependencies=dependencies,
        status=status,
    ).write(
        output_directory / "artifact",
        sorted(records, key=lambda row: row.record_id),
    )
    report = {
        "format": INDEXED_TARGET_EVIDENCE_REPORT_V3,
        "status": status,
        "authorizing": False,
        "binary_binding": output_binding.to_payload(),
        "exact_pe_sha256": actual_pe_sha256,
        "machine_ir_sha256": actual_machine_ir_sha256,
        "machine_ir_manifest_sha256": canonical_sha256_v3(machine_manifest),
        "artifact_id": manifest.artifact_id,
        "artifact_manifest_sha256": hashlib.sha256(manifest.to_bytes()).hexdigest(),
        "counts": {
            "indirect_exits": len(exit_reports),
            "complete": sum(row["status"] == "complete" for row in exit_reports),
            "incomplete": sum(row["status"] == "incomplete" for row in exit_reports),
            "violated": sum(row["status"] == "violated" for row in exit_reports),
            "evidence_records": len(records),
        },
        "global_issues": [row.to_payload() for row in global_issues],
        "exits": sorted(exit_reports, key=lambda row: str(row["exit_id"])),
    }
    (output_directory / "indexed-target-evidence-report-v3.json").write_bytes(
        canonical_json_bytes_v3(report)
    )
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate fail-closed checked indexed PE table target evidence"
    )
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--machine-ir", type=Path, required=True)
    parser.add_argument("--machine-ir-manifest", type=Path, required=True)
    parser.add_argument("--semantic-index", type=Path, required=True)
    parser.add_argument("--transition-summaries", type=Path, required=True)
    parser.add_argument("--structural-targets", type=Path, required=True)
    parser.add_argument("--target-hints", type=Path)
    parser.add_argument("--target-evidence", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    generate_indexed_target_evidence_v3(
        binary_path=arguments.binary,
        machine_ir_path=arguments.machine_ir,
        machine_ir_manifest_path=arguments.machine_ir_manifest,
        semantic_index_path=arguments.semantic_index,
        transition_summaries_path=arguments.transition_summaries,
        structural_targets_path=arguments.structural_targets,
        target_hints_path=arguments.target_hints,
        target_evidence_path=arguments.target_evidence,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "INDEXED_TARGET_EVIDENCE_REPORT_V3",
    "IndexedTargetEvidenceV3Error",
    "generate_indexed_target_evidence_v3",
    "main",
]
