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
from ..authority.external_site_records import (
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    EXTERNAL_PROFILE_RECORD_V3_SCHEMA,
    ExternalProfileV3,
)
from ..authority.parametric_summary_records import (
    PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
    PARAMETRIC_SCC_SUMMARY_CODEC_V3,
    ParametricSccSummaryV3,
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
    _PE_STATIC_MEMORY_RECORD_NOT_APPLICABLE_V3,
    _PARAMETRIC_MEMORY_RECORD_NOT_APPLICABLE_V3,
)
from ..authority.transition_records import (
    TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)
from ..artifacts.artifact_set import (
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
)
from ..artifacts.formats import (
    MACHINE_IR_FORMAT as MACHINE_IR_FORMAT_V2,
    TARGET_HINTS_ARTIFACT_KIND as TARGET_HINTS_ARTIFACT_KIND_V3,
)
from ..artifacts.io import (
    ArtifactInputReaderV3,
    open_artifact_reader_v3,
)


INDEXED_TARGET_EVIDENCE_REPORT_V3 = (
    "spaghetti-extractor-indexed-target-evidence-report-v3"
)
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


@dataclass(frozen=True, order=True)
class _ImportSlot:
    slot_va: int
    slot_rva: int
    dll: str
    symbol: str | None
    ordinal: int | None


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


def _parse_pe(
    path: Path,
) -> tuple[bytes, int, tuple[_Section, ...], tuple[_ImportSlot, ...]]:
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
    image_base = int(getattr(optional_header, "ImageBase"))
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except (AttributeError, pefile.PEFormatError) as exc:
        raise IndexedTargetEvidenceV3Error(
            f"cannot parse exact PE import directory: {exc}"
        ) from exc
    imports: list[_ImportSlot] = []
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
        raw_dll = getattr(descriptor, "dll", None)
        if not isinstance(raw_dll, bytes):
            raise IndexedTargetEvidenceV3Error(
                "PE import descriptor has no exact DLL name"
            )
        try:
            dll = raw_dll.decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise IndexedTargetEvidenceV3Error(
                "PE import descriptor DLL name is not ASCII"
            ) from exc
        for imported in descriptor.imports:
            slot_va = int(imported.address)
            raw_name = imported.name
            try:
                symbol = (
                    raw_name.decode("ascii")
                    if isinstance(raw_name, bytes)
                    else None
                )
            except UnicodeDecodeError as exc:
                raise IndexedTargetEvidenceV3Error(
                    "PE import symbol is not ASCII"
                ) from exc
            ordinal = (
                int(imported.ordinal)
                if symbol is None
                and isinstance(imported.ordinal, int)
                and not isinstance(imported.ordinal, bool)
                else None
            )
            if (symbol is None) == (ordinal is None):
                raise IndexedTargetEvidenceV3Error(
                    "PE import is neither one named nor one ordinal import"
                )
            imports.append(
                _ImportSlot(
                    slot_va=slot_va,
                    slot_rva=slot_va - image_base,
                    dll=dll,
                    symbol=symbol,
                    ordinal=ordinal,
                )
            )
    if len({row.slot_va for row in imports}) != len(imports):
        raise IndexedTargetEvidenceV3Error("PE import slots are ambiguous")
    return data, image_base, sections, tuple(sorted(imports))


def _read_exact_rva(data: bytes, section: _Section, rva: int, size: int) -> bytes | None:
    if not section.contains_raw(rva, size):
        return None
    start = section.raw_offset + rva - section.rva_start
    end = start + size
    if not 0 <= start <= end <= len(data):
        return None
    return data[start:end]



__all__ = ["IndexedTargetEvidenceV3Error"]
