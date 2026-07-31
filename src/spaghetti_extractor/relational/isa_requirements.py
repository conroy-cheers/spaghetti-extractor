"""Exact-PE instruction requirements for relational Stage A proofs.

The inventory produced here is deliberately untrusted analysis.  It binds
diagnostic instruction forms and their occurrence scopes to exact PE hashes and
the relational product graph, but only generated Lean proofs may establish that
the bytes decode and have the claimed semantics.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import capstone
from capstone import x86_const

from ..isa_semantic_forms import (
    LEAN_ISA_REQUIREMENT_FORM_FORMAT,
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_core,
    lean_semantic_form_id,
)
from ..stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from ..util import sha256_bytes, sha256_file, write_json
from .preflight import instruction_supported
from .schema import RELATIONAL_ANALYSIS_KERNEL_MODULES, STAGE_A_RELATIONAL_MODEL_ID
from .side_extraction_artifact import request_payload as side_extraction_request_payload


ISA_REQUIREMENT_INVENTORY_FORMAT = "stage-a-isa-requirement-inventory-v1"
ISA_REQUIREMENT_FORM_FORMAT = "stage-a-x86-instruction-form-v1"
LEAN_ISA_FORM_INVENTORY_FORMAT = "stage-a-lean-isa-form-inventory-v1"
_LEAN_FORM_EXTRACTION_DRIVER_VERSION = "region-byte-slice-inventory-v4"

_SIDES = ("original", "candidate")
_PREFIX_NAMES = {
    0xF0: "lock",
    0xF2: "repne",
    0xF3: "rep",
    0x2E: "cs",
    0x36: "ss",
    0x3E: "ds",
    0x26: "es",
    0x64: "fs",
    0x65: "gs",
    0x66: "operand-size",
    0x67: "address-size",
}
_EMBEDDED_REGISTER_RANGES = (
    (0x40, 0x47, "40+rd"),
    (0x48, 0x4F, "48+rd"),
    (0x50, 0x57, "50+rd"),
    (0x58, 0x5F, "58+rd"),
    (0x70, 0x7F, "70+cc"),
    (0x90, 0x97, "90+rd"),
    (0xB0, 0xB7, "b0+rb"),
    (0xB8, 0xBF, "b8+rd"),
)

_LEAN_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "lean" / "StageA"


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _as_int_list(value: Any, context: str) -> list[int]:
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in value
    ):
        raise StageAInputError(f"{context} must be a list of non-negative integers")
    if value != sorted(set(value)):
        raise StageAInputError(f"{context} must be unique and canonically ordered")
    return list(value)


def _access_name(access: int) -> str:
    read = bool(access & capstone.CS_AC_READ)
    write = bool(access & capstone.CS_AC_WRITE)
    if read and write:
        return "read-write"
    if read:
        return "read"
    if write:
        return "write"
    return "implicit-or-unknown"


def _register_class(name: str, bits: int) -> str:
    lowered = name.lower()
    if lowered.startswith("st") or lowered in {
        "fpcw",
        "fpsw",
        "fptag",
    }:
        return "x87"
    if lowered in {"cs", "ds", "es", "fs", "gs", "ss"}:
        return "segment"
    if lowered in {"eip", "ip"}:
        return "instruction-pointer"
    if lowered in {"eflags", "flags"}:
        return "flags"
    if lowered.startswith(("xmm", "ymm", "zmm")):
        return "simd"
    if lowered.startswith("mm"):
        return "mmx"
    return f"gpr{bits}"


def _normalized_opcode(encoded: bytes) -> tuple[list[str], str]:
    index = 0
    prefixes: list[str] = []
    while index < len(encoded) and encoded[index] in _PREFIX_NAMES:
        prefixes.append(_PREFIX_NAMES[encoded[index]])
        index += 1
    if index >= len(encoded):
        return prefixes, "missing"
    first = encoded[index]
    if first == 0x0F and index + 1 < len(encoded):
        second = encoded[index + 1]
        if 0x40 <= second <= 0x4F:
            return prefixes, "0f40+cc"
        if 0x80 <= second <= 0x8F:
            return prefixes, "0f80+cc"
        if 0x90 <= second <= 0x9F:
            return prefixes, "0f90+cc"
        if second in {0x38, 0x3A} and index + 2 < len(encoded):
            return prefixes, f"0f{second:02x}{encoded[index + 2]:02x}"
        return prefixes, f"0f{second:02x}"
    for start, stop, name in _EMBEDDED_REGISTER_RANGES:
        if start <= first <= stop:
            return prefixes, name
    return prefixes, f"{first:02x}"


def _operand_shape(instruction: Any, operand: Any) -> dict[str, Any]:
    bits = int(operand.size) * 8
    access = _access_name(int(operand.access))
    if operand.type == x86_const.X86_OP_REG:
        name = instruction.reg_name(int(operand.reg))
        return {
            "kind": "register",
            "bits": bits,
            "class": _register_class(name, bits),
            "access": access,
        }
    if operand.type == x86_const.X86_OP_IMM:
        return {"kind": "immediate", "bits": bits, "access": access}
    if operand.type == x86_const.X86_OP_MEM:
        memory = operand.mem
        segment = instruction.reg_name(int(memory.segment)) if memory.segment else ""
        base = instruction.reg_name(int(memory.base)) if memory.base else ""
        index = instruction.reg_name(int(memory.index)) if memory.index else ""
        return {
            "kind": "memory",
            "bits": bits,
            "access": access,
            "segment": segment.lower() or "default",
            "base_class": _register_class(base, 32) if base else "none",
            "index_class": _register_class(index, 32) if index else "none",
            "scale": int(memory.scale) if index else 0,
            "has_displacement": bool(memory.disp),
        }
    return {"kind": "invalid", "bits": bits, "access": access}


def _instruction_features(instruction: Any, operands: list[dict[str, Any]]) -> list[str]:
    features: set[str] = set()
    groups = {
        instruction.group_name(group)
        for group in instruction.groups
        if instruction.group_name(group)
    }
    for group in groups:
        features.add("group:" + group.lower())
    mnemonic = str(instruction.mnemonic).lower()
    if mnemonic != "lea" and any(operand["kind"] == "memory" for operand in operands):
        features.add("memory")
        features.add("may-fault")
    _, opcode = _normalized_opcode(bytes(instruction.bytes))
    if mnemonic.startswith("f") and opcode[:2] in {
        f"{value:02x}" for value in range(0xD8, 0xE0)
    }:
        features.add("x87")
        features.add("may-fault")
    if mnemonic in {"div", "idiv", "into", "bound"}:
        features.add("may-fault")
    if mnemonic in {"push", "pop", "call", "ret", "retf", "enter", "leave"}:
        features.add("stack")
    if int(getattr(instruction, "eflags", 0)):
        features.add("eflags")
    return sorted(features)


def instruction_form_payload(instruction: Any) -> dict[str, Any]:
    """Return a stable diagnostic form for one Capstone-decoded instruction."""
    encoded = bytes(instruction.bytes)
    prefixes, opcode = _normalized_opcode(encoded)
    operands = [_operand_shape(instruction, operand) for operand in instruction.operands]
    modrm_offset = int(getattr(instruction, "modrm_offset", 0))
    modrm_kind = "none"
    if modrm_offset:
        modrm_kind = "register" if (int(instruction.modrm) >> 6) == 3 else "memory"
    core = {
        "format": ISA_REQUIREMENT_FORM_FORMAT,
        "architecture": "x86",
        "execution_mode": "protected-32",
        "mnemonic": str(instruction.mnemonic).lower(),
        "opcode": opcode,
        "prefixes": prefixes,
        "address_size": int(instruction.addr_size) * 8,
        "modrm_kind": modrm_kind,
        "displacement_size": int(getattr(instruction, "disp_size", 0)) * 8,
        "immediate_size": int(getattr(instruction, "imm_size", 0)) * 8,
        "operands": operands,
        "features": _instruction_features(instruction, operands),
    }
    return {"id": "x86-form-" + _canonical_sha256(core)[:20], **core}


@dataclass(frozen=True)
class InstructionOccurrence:
    id: str
    side: str
    node_id: int
    region_id: str
    rva: int
    size: int
    encoded: str
    form_id: str
    capstone_preflight_status: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "side": self.side,
            "node_id": self.node_id,
            "region_id": self.region_id,
            "rva": self.rva,
            "size": self.size,
            "bytes": self.encoded,
            "form_id": self.form_id,
            "capstone_preflight_status": self.capstone_preflight_status,
        }


@dataclass(frozen=True)
class RequirementScope:
    canonical_node_ids: tuple[int, ...]
    represented_rooted_node_ids: tuple[int, ...]
    conservative_required_node_ids: tuple[int, ...]
    root_node_ids: tuple[int, ...]
    control_closed: bool
    control_frontier_node_ids: tuple[int, ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "canonical_node_ids": list(self.canonical_node_ids),
            "represented_rooted_node_ids": list(self.represented_rooted_node_ids),
            "conservative_required_node_ids": list(
                self.conservative_required_node_ids
            ),
            "root_node_ids": list(self.root_node_ids),
            "control_closed": self.control_closed,
            "control_frontier_node_ids": list(self.control_frontier_node_ids),
        }


@dataclass(frozen=True)
class ISARequirementInventory:
    payload: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> "ISARequirementInventory":
        if not isinstance(value, Mapping):
            raise StageAInputError("ISA requirement inventory must be an object")
        expected = {
            "format",
            "status",
            "model",
            "inputs",
            "scope",
            "formal_binding",
            "forms",
            "occurrences",
            "gaps",
            "counts",
            "trust",
        }
        if set(value) != expected:
            raise StageAInputError("ISA requirement inventory has an invalid field inventory")
        if value.get("format") != ISA_REQUIREMENT_INVENTORY_FORMAT:
            raise StageAInputError("unsupported ISA requirement inventory format")
        scope = value.get("scope")
        if not isinstance(scope, Mapping):
            raise StageAInputError("ISA requirement inventory scope must be an object")
        canonical = _as_int_list(scope.get("canonical_node_ids"), "scope.canonical_node_ids")
        represented = _as_int_list(
            scope.get("represented_rooted_node_ids"),
            "scope.represented_rooted_node_ids",
        )
        required = _as_int_list(
            scope.get("conservative_required_node_ids"),
            "scope.conservative_required_node_ids",
        )
        roots = _as_int_list(scope.get("root_node_ids"), "scope.root_node_ids")
        frontier = _as_int_list(
            scope.get("control_frontier_node_ids"),
            "scope.control_frontier_node_ids",
        )
        canonical_set = set(canonical)
        if not set(represented).issubset(canonical_set):
            raise StageAInputError("represented rooted nodes escape the canonical inventory")
        if not set(required).issubset(canonical_set):
            raise StageAInputError("conservative required nodes escape the canonical inventory")
        if not set(roots).issubset(set(represented)):
            raise StageAInputError("root nodes are absent from represented reachability")
        if scope.get("control_closed") is not (not frontier):
            raise StageAInputError("control-closure status disagrees with its frontier")
        forms = value.get("forms")
        occurrences = value.get("occurrences")
        gaps = value.get("gaps")
        if not isinstance(forms, list) or not isinstance(occurrences, list) or not isinstance(gaps, list):
            raise StageAInputError("ISA requirements forms, occurrences, and gaps must be lists")
        form_ids = [row.get("id") for row in forms if isinstance(row, Mapping)]
        if len(form_ids) != len(forms) or form_ids != sorted(set(form_ids)):
            raise StageAInputError("ISA requirement form IDs must be unique and ordered")
        occurrence_ids = [
            row.get("id") for row in occurrences if isinstance(row, Mapping)
        ]
        if len(occurrence_ids) != len(occurrences) or occurrence_ids != sorted(set(occurrence_ids)):
            raise StageAInputError("ISA requirement occurrence IDs must be unique and ordered")
        if any(
            row.get("form_id") not in set(form_ids)
            or row.get("node_id") not in canonical_set
            for row in occurrences
            if isinstance(row, Mapping)
        ):
            raise StageAInputError("ISA occurrence references an unknown form or node")
        trust = value.get("trust")
        if not isinstance(trust, Mapping) or trust.get("proof_authority") is not False or trust.get("closes_stage_a_proof") is not False:
            raise StageAInputError("ISA requirement inventory cannot claim proof authority")
        return cls(dict(value))

    def to_payload(self) -> dict[str, Any]:
        return dict(self.payload)


@dataclass(frozen=True)
class ISARequirementReplayOccurrence:
    rva: int
    size: int
    encoded: bytes
    form_id: str
    semantic_form: str


@dataclass(frozen=True)
class ISARequirementReplayRegion:
    region_index: int
    target_id: int
    region_id: str
    occurrences: tuple[ISARequirementReplayOccurrence, ...]


def isa_requirement_replay_projection(
    inventory: Mapping[str, Any],
    relation_contract: Mapping[str, Any],
) -> dict[str, tuple[ISARequirementReplayRegion, ...]]:
    """Return the canonical proof-bearing projection of an ISA inventory.

    This remains untrusted generation logic.  The generated Lean certificate
    re-decodes every projected occurrence from the exact embedded PE bytes.
    """

    payload = ISARequirementInventory.parse(inventory).to_payload()
    regions_value = relation_contract.get("regions")
    if not isinstance(regions_value, list) or any(
        not isinstance(region, Mapping) for region in regions_value
    ):
        raise StageAInputError(
            "ISA replay relation contract regions must be a list of objects"
        )
    regions = list(regions_value)
    forms_value = payload.get("forms")
    occurrences_value = payload.get("occurrences")
    assert isinstance(forms_value, list)
    assert isinstance(occurrences_value, list)
    semantic_forms: dict[str, str] = {}
    for index, form in enumerate(forms_value):
        if not isinstance(form, Mapping):
            raise StageAInputError(f"ISA replay form {index} must be an object")
        form_id = form.get("id")
        semantic_form = form.get("semantic_form")
        if (
            not isinstance(form_id, str)
            or not form_id
            or not isinstance(semantic_form, str)
            or not semantic_form
        ):
            raise StageAInputError(f"ISA replay form {index} is malformed")
        semantic_forms[form_id] = semantic_form

    grouped: dict[tuple[str, int], list[ISARequirementReplayOccurrence]] = {
        (side, index): []
        for side in _SIDES
        for index in range(len(regions))
    }
    referenced_forms: set[str] = set()
    for index, occurrence in enumerate(occurrences_value):
        if not isinstance(occurrence, Mapping):
            raise StageAInputError(
                f"ISA replay occurrence {index} must be an object"
            )
        side = occurrence.get("side")
        node_id = occurrence.get("node_id")
        if (
            side not in _SIDES
            or isinstance(node_id, bool)
            or not isinstance(node_id, int)
            or not 0 <= node_id < len(regions)
        ):
            raise StageAInputError(
                f"ISA replay occurrence {index} has an invalid region identity"
            )
        region = regions[node_id]
        if occurrence.get("region_id") != str(region.get("id", "")):
            raise StageAInputError(
                f"ISA replay occurrence {index} names the wrong relation region"
            )
        rva = occurrence.get("rva")
        size = occurrence.get("size")
        encoded_hex = occurrence.get("bytes")
        form_id = occurrence.get("form_id")
        if (
            isinstance(rva, bool)
            or not isinstance(rva, int)
            or rva < 0
            or isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= 15
            or not isinstance(encoded_hex, str)
            or len(encoded_hex) != size * 2
            or not isinstance(form_id, str)
            or form_id not in semantic_forms
        ):
            raise StageAInputError(f"ISA replay occurrence {index} is malformed")
        try:
            encoded = bytes.fromhex(encoded_hex)
        except ValueError as exc:
            raise StageAInputError(
                f"ISA replay occurrence {index} has invalid encoded bytes"
            ) from exc
        if len(encoded) != size:
            raise StageAInputError(
                f"ISA replay occurrence {index} byte length disagrees with its size"
            )
        referenced_forms.add(form_id)
        grouped[(str(side), node_id)].append(
            ISARequirementReplayOccurrence(
                rva=rva,
                size=size,
                encoded=encoded,
                form_id=form_id,
                semantic_form=semantic_forms[form_id],
            )
        )
    if referenced_forms != set(semantic_forms):
        raise StageAInputError(
            "ISA replay inventory contains unreferenced semantic forms"
        )

    result: dict[str, tuple[ISARequirementReplayRegion, ...]] = {}
    for side in _SIDES:
        projected: list[ISARequirementReplayRegion] = []
        for region_index, region in enumerate(regions):
            numeric_id = region.get("numeric_id")
            span = region.get(side)
            if (
                isinstance(numeric_id, bool)
                or not isinstance(numeric_id, int)
                or numeric_id < 0
                or not isinstance(span, Mapping)
            ):
                raise StageAInputError(
                    f"ISA replay region {region_index} has no checked numeric identity"
                )
            start = span.get("rva_start")
            stop = span.get("rva_end")
            if (
                isinstance(start, bool)
                or not isinstance(start, int)
                or isinstance(stop, bool)
                or not isinstance(stop, int)
                or stop <= start
            ):
                raise StageAInputError(
                    f"ISA replay region {region_index} has an invalid {side} span"
                )
            rows = sorted(grouped[(side, region_index)], key=lambda row: row.rva)
            if not rows or rows[0].rva != start:
                raise StageAInputError(
                    f"ISA replay region {region_index} omits the start of its {side} span"
                )
            cursor = start
            for row in rows:
                if row.rva != cursor:
                    raise StageAInputError(
                        f"ISA replay region {region_index} has a gap or duplicate in its "
                        f"{side} occurrence inventory"
                    )
                cursor += row.size
            if cursor != stop:
                raise StageAInputError(
                    f"ISA replay region {region_index} does not cover its full {side} span"
                )
            projected.append(
                ISARequirementReplayRegion(
                    region_index=region_index,
                    target_id=numeric_id,
                    region_id=str(region.get("id", "")),
                    occurrences=tuple(rows),
                )
            )
        result[side] = tuple(projected)
    return result


def _lean_form_source_hashes() -> dict[str, str]:
    files = {
        f"{module}.lean": sha256_file(_LEAN_SOURCE_ROOT / f"{module}.lean")
        for module in RELATIONAL_ANALYSIS_KERNEL_MODULES
    }
    classifier = lean_semantic_form_classifier_sha256(_LEAN_SOURCE_ROOT)
    extractor = _canonical_sha256(
        {
            name: files[name]
            for name in (
                "RelationalPEExecution.lean",
                "RelationalISAQualification.lean",
            )
        }
    )
    return {
        "classifier_sha256": classifier,
        "extractor_sha256": extractor,
        "source_sha256": _canonical_sha256({
            "lean_sources": files,
            "driver_version": _LEAN_FORM_EXTRACTION_DRIVER_VERSION,
        }),
    }


def _lean_form_extraction_source(regions: list[Mapping[str, Any]]) -> str:
    requests: list[str] = []
    for node_id, region in enumerate(regions):
        for candidate, side in ((False, "original"), (True, "candidate")):
            span = region.get(side)
            if not isinstance(span, Mapping):
                raise StageAInputError(
                    f"relation region {node_id} has no {side} span"
                )
            requests.append(
                "{ candidate := "
                + ("true" if candidate else "false")
                + f", nodeId := {node_id}, span := {{ start := "
                + f"{int(span['rva_start'])}, size := {int(span['size'])} }} }}"
            )
    request_chunk_size = 128
    request_chunks = [
        requests[offset : offset + request_chunk_size]
        for offset in range(0, len(requests), request_chunk_size)
    ]
    request_chunks_literal = ",\n  ".join(
        "[\n    " + ",\n    ".join(chunk) + "\n  ]"
        for chunk in request_chunks
    )
    return """import Lean
import StageA.RelationalISAQualification

namespace StageA.GeneratedISARequirementInventory

open Lean StageA.Formal StageA.Relational

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

structure Request where
  candidate : Bool
  nodeId : Nat
  span : Span

def requestChunks : List (List Request) := [
  """ + request_chunks_literal + """
]

def run : IO Unit := do
  let originalData <- IO.FS.readBinFile "artifacts/original.pe"
  let candidateData <- IO.FS.readBinFile "artifacts/candidate.pe"
  let originalBytes : Bytes := originalData.toList.map (fun byte => byte.toNat)
  let candidateBytes : Bytes := candidateData.toList.map (fun byte => byte.toNat)
  let some originalPe := parsePE32 originalBytes |
    throw (IO.userError "original PE parse failed")
  let some candidatePe := parsePE32 candidateBytes |
    throw (IO.userError "candidate PE parse failed")
  for chunk in requestChunks do
    for request in chunk do
      let pe := if request.candidate then candidatePe else originalPe
      let some occurrences := decodeInstructionFormsSpan pe request.span |
        throw (IO.userError s!"region {request.nodeId} did not decode")
      IO.println <| Json.compress <| Json.mkObj [
        ("side", toJson (if request.candidate then "candidate" else "original")),
        ("node_id", toJson request.nodeId),
        ("occurrences", instructionFormInventoryJson occurrences)
      ]

end StageA.GeneratedISARequirementInventory

def main : IO Unit := StageA.GeneratedISARequirementInventory.run
"""


def _lean_side_form_extraction_source(
    side: str, regions: list[Mapping[str, Any]]
) -> str:
    if side not in _SIDES:
        raise StageAInputError(f"unsupported ISA extraction side {side!r}")
    requests: list[str] = []
    data_offset = 0
    for node_id, region in enumerate(regions):
        span = region.get("span")
        if not isinstance(span, Mapping):
            raise StageAInputError(
                f"ISA extraction request region {node_id} has no span"
            )
        size = int(span["size"])
        requests.append(
            f"{{ nodeId := {node_id}, dataOffset := {data_offset}, span := "
            + f"{{ start := {int(span['rva_start'])}, size := {size} }} }}"
        )
        data_offset += size
    request_chunk_size = 128
    request_chunks = [
        requests[offset : offset + request_chunk_size]
        for offset in range(0, len(requests), request_chunk_size)
    ]
    request_chunks_literal = ",\n  ".join(
        "[\n    " + ",\n    ".join(chunk) + "\n  ]"
        for chunk in request_chunks
    )
    return """import Lean
import StageA.RelationalISAQualification

namespace StageA.GeneratedSideISARequirementInventory

open Lean StageA.Formal StageA.Relational

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

structure Request where
  nodeId : Nat
  dataOffset : Nat
  span : Span

def requestChunks : List (List Request) := [
  """ + request_chunks_literal + """
]

def run : IO Unit := do
  let data <- IO.FS.readBinFile "artifacts/regions.bin"
  for chunk in requestChunks do
    for request in chunk do
      let dataStop := request.dataOffset + request.span.size
      if data.size < dataStop then
        throw (IO.userError s!"region {request.nodeId} bytes are truncated")
      let bytes : Bytes :=
        (data.extract request.dataOffset dataStop).toList.map
          (fun byte => byte.toNat)
      let some occurrences :=
          decodeInstructionFormsBytes request.span.start bytes |
        throw (IO.userError s!"region {request.nodeId} did not decode")
      IO.println <| Json.compress <| Json.mkObj [
        ("side", toJson """ + json.dumps(side) + """),
        ("node_id", toJson request.nodeId),
        ("occurrences", instructionFormInventoryJson occurrences)
      ]

end StageA.GeneratedSideISARequirementInventory

def main : IO Unit := StageA.GeneratedSideISARequirementInventory.run
"""


def _parse_lean_form_rows(
    rows: Any,
    region_count: int,
    *,
    sides: tuple[str, ...] = _SIDES,
    expected_spans: Mapping[tuple[str, int], tuple[int, int]] | None = None,
) -> dict[tuple[str, int], tuple[dict[str, Any], ...]]:
    if not isinstance(rows, list):
        raise StageAInputError("Lean ISA form inventory rows must be a list")
    expected = {
        (side, node_id)
        for side in sides
        for node_id in range(region_count)
    }
    result: dict[tuple[str, int], tuple[dict[str, Any], ...]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or set(row) != {
            "side",
            "node_id",
            "occurrences",
        }:
            raise StageAInputError(f"Lean ISA form row {index} is malformed")
        side = row.get("side")
        node_id = row.get("node_id")
        if side not in _SIDES or isinstance(node_id, bool) or not isinstance(node_id, int):
            raise StageAInputError(f"Lean ISA form row {index} has an invalid identity")
        identity = (str(side), node_id)
        if identity not in expected or identity in result:
            raise StageAInputError(f"Lean ISA form row {index} is unexpected or duplicate")
        raw_occurrences = row.get("occurrences")
        if not isinstance(raw_occurrences, list) or not raw_occurrences:
            raise StageAInputError(f"Lean ISA form row {index} has no occurrences")
        occurrences: list[dict[str, Any]] = []
        previous_stop: int | None = None
        for occurrence_index, occurrence in enumerate(raw_occurrences):
            if not isinstance(occurrence, Mapping) or set(occurrence) != {
                "rva",
                "size",
                "bytes",
                "form",
            }:
                raise StageAInputError(
                    f"Lean ISA form row {index} occurrence {occurrence_index} is malformed"
                )
            rva = occurrence.get("rva")
            size = occurrence.get("size")
            encoded = occurrence.get("bytes")
            form = occurrence.get("form")
            if (
                isinstance(rva, bool)
                or not isinstance(rva, int)
                or rva < 0
                or isinstance(size, bool)
                or not isinstance(size, int)
                or not 1 <= size <= 15
                or not isinstance(encoded, list)
                or len(encoded) != size
                or any(
                    isinstance(byte, bool)
                    or not isinstance(byte, int)
                    or not 0 <= byte <= 0xFF
                    for byte in encoded
                )
                or not isinstance(form, str)
                or not form
            ):
                raise StageAInputError(
                    f"Lean ISA form row {index} occurrence {occurrence_index} is invalid"
                )
            if previous_stop is not None and rva != previous_stop:
                raise StageAInputError(
                    f"Lean ISA form row {index} is not contiguous"
                )
            previous_stop = rva + size
            occurrences.append(
                {
                    "rva": rva,
                    "size": size,
                    "bytes": bytes(encoded).hex(),
                    "form": form,
                }
            )
        result[identity] = tuple(occurrences)
        if expected_spans is not None:
            expected_span = expected_spans.get(identity)
            if expected_span is None:
                raise StageAInputError(
                    f"Lean ISA form row {index} has no declared span"
                )
            if (
                occurrences[0]["rva"] != expected_span[0]
                or previous_stop != expected_span[0] + expected_span[1]
            ):
                raise StageAInputError(
                    f"Lean ISA form row {index} does not cover its declared span"
                )
    if set(result) != expected:
        raise StageAInputError("Lean ISA form inventory omitted a region side")
    return result


def extract_lean_instruction_forms_side(
    *,
    binary: Path,
    request: Mapping[str, Any],
    timeout_seconds: float = 300.0,
) -> tuple[dict[tuple[str, int], tuple[dict[str, Any], ...]], dict[str, Any]]:
    side = request.get("side")
    if side not in _SIDES:
        raise StageAInputError("side ISA extraction request has an invalid side")
    binary = Path(binary)
    binary_sha256 = sha256_file(binary)
    if request.get("binary_sha256") != binary_sha256:
        raise StageAInputError(f"{side} ISA extraction binary hash mismatch")
    regions_value = request.get("regions")
    if not isinstance(regions_value, list) or any(
        not isinstance(region, Mapping) for region in regions_value
    ):
        raise StageAInputError("side ISA extraction regions must be objects")
    regions = list(regions_value)
    expected_spans: dict[tuple[str, int], tuple[int, int]] = {}
    for index, region in enumerate(regions):
        if region.get("index") != index:
            raise StageAInputError(
                "side ISA extraction region indices are not canonical"
            )
        span = region.get("span")
        if not isinstance(span, Mapping):
            raise StageAInputError(f"side ISA extraction region {index} has no span")
        expected_spans[(str(side), index)] = (
            int(span.get("rva_start", -1)),
            int(span.get("size", -1)),
        )
    source_hashes = _lean_form_source_hashes()
    input_identity = {
        "format": "stage-a-lean-side-isa-form-inventory-v1",
        "side": side,
        "binary_sha256": binary_sha256,
        "request_sha256": _canonical_sha256(request),
        "lean_form_source_sha256": source_hashes["source_sha256"],
    }
    from .lean.compiler import _relational_cache_dir, _run_lean_relational

    cache_root = _relational_cache_dir()
    cache = (
        cache_root
        / "isa-form-inventory"
        / (_canonical_sha256(input_identity) + ".json")
        if cache_root is not None
        else None
    )
    if cache is not None and cache.is_file():
        try:
            cached = json.loads(cache.read_text(encoding="utf-8"))
            if (
                isinstance(cached, Mapping)
                and cached.get("format") == input_identity["format"]
                and cached.get("inputs") == input_identity
            ):
                rows = _parse_lean_form_rows(
                    cached.get("rows"),
                    len(regions),
                    sides=(str(side),),
                    expected_spans=expected_spans,
                )
                return rows, {
                    "status": "lean_extracted_untrusted",
                    "cache": "hit",
                    **source_hashes,
                    "row_count": len(rows),
                }
        except (OSError, json.JSONDecodeError, StageAInputError):
            pass
    lean = shutil.which("lean")
    if lean is None:
        raise StageAInputError("Lean is required to extract ISA semantic forms")
    with tempfile.TemporaryDirectory(
        prefix=f"stage-a-isa-{side}-requirements-"
    ) as temporary:
        lean_dir = Path(temporary)
        stage_a = lean_dir / "StageA"
        artifacts = lean_dir / "artifacts"
        stage_a.mkdir()
        artifacts.mkdir()
        for module in RELATIONAL_ANALYSIS_KERNEL_MODULES:
            shutil.copyfile(
                _LEAN_SOURCE_ROOT / f"{module}.lean",
                stage_a / f"{module}.lean",
            )
        parsed_binary = _parse_stage_a_pe(binary)
        region_bytes = bytearray()
        for index, region in enumerate(regions):
            span = region["span"]
            start = int(span["rva_start"])
            size = int(span["size"])
            encoded = parsed_binary.pe.get_data(start, size)
            if len(encoded) != size:
                raise StageAInputError(
                    f"{side} ISA extraction region {index} bytes are truncated"
                )
            region_bytes.extend(encoded)
        (artifacts / "regions.bin").write_bytes(region_bytes)
        bundle = f"GeneratedISARequirementInventory{str(side).title()}"
        (stage_a / f"{bundle}.lean").write_text(
            _lean_side_form_extraction_source(str(side), regions),
            encoding="utf-8",
        )
        compiled = _run_lean_relational(lean_dir, bundle=bundle)
        if compiled.get("status") != "checked":
            raise StageAInputError(
                f"Lean {side} ISA form extraction did not compile: "
                + str(compiled.get("stderr") or compiled.get("stdout"))
            )
        completed = subprocess.run(
            [lean, "--trust=0", "--run", f"StageA/{bundle}.lean"],
            cwd=lean_dir,
            env={**os.environ, "LEAN_PATH": "."},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise StageAInputError(
                f"Lean {side} ISA form extraction failed: "
                + str(completed.stderr or completed.stdout)
            )
        try:
            raw_rows = [
                json.loads(line)
                for line in completed.stdout.splitlines()
                if line.strip()
            ]
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"Lean {side} ISA form extraction emitted malformed JSON: {exc}"
            ) from exc
    rows = _parse_lean_form_rows(
        raw_rows,
        len(regions),
        sides=(str(side),),
        expected_spans=expected_spans,
    )
    if cache is not None:
        cache.parent.mkdir(parents=True, exist_ok=True)
        write_json(
            cache,
            {
                "format": input_identity["format"],
                "inputs": input_identity,
                "rows": raw_rows,
                "trust": {
                    "proof_authority": False,
                    "closes_stage_a_proof": False,
                },
            },
        )
    return rows, {
        "status": "lean_extracted_untrusted",
        "cache": "miss",
        **source_hashes,
        "row_count": len(rows),
    }


def extract_lean_instruction_forms(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Mapping[str, Any],
    timeout_seconds: float = 300.0,
) -> tuple[dict[tuple[str, int], tuple[dict[str, Any], ...]], dict[str, Any]]:
    """Run the Lean decoder over every exact relation span.

    This extraction is still untrusted data production. Generated Lean
    certificates must replay any occurrence inventory used by acceptance.
    """
    regions_value = relation_contract.get("regions")
    if not isinstance(regions_value, list) or any(
        not isinstance(region, Mapping) for region in regions_value
    ):
        raise StageAInputError("relation contract regions must be a list of objects")
    paths = {"original": Path(original), "candidate": Path(candidate)}
    merged: dict[tuple[str, int], tuple[dict[str, Any], ...]] = {}
    evidence_by_side: dict[str, dict[str, Any]] = {}
    for side in _SIDES:
        request = side_extraction_request_payload(
            relation_contract,
            side,
            sha256_file(paths[side]),
        )
        rows, evidence = extract_lean_instruction_forms_side(
            binary=paths[side],
            request=request,
            timeout_seconds=timeout_seconds,
        )
        merged.update(rows)
        evidence_by_side[side] = evidence
    source_hashes = _lean_form_source_hashes()
    for side, evidence in evidence_by_side.items():
        for field in ("classifier_sha256", "extractor_sha256", "source_sha256"):
            if evidence.get(field) != source_hashes[field]:
                raise StageAInputError(
                    f"{side} Lean ISA extraction source identity mismatch"
                )
    return merged, {
        "status": "lean_extracted_untrusted",
        "cache": {
            side: evidence_by_side[side]["cache"] for side in _SIDES
        },
        **source_hashes,
        "row_count": len(merged),
        "sides": evidence_by_side,
    }


def _scope_from_product_graph(
    product_graph: Mapping[str, Any], region_count: int
) -> RequirementScope:
    nodes = product_graph.get("nodes")
    evidence = product_graph.get("evidence")
    counts = product_graph.get("counts")
    if not isinstance(nodes, list) or len(nodes) != region_count:
        raise StageAInputError("product graph does not cover the canonical region inventory")
    canonical = list(range(region_count))
    if any(
        not isinstance(node, Mapping)
        or node.get("id") != index
        or node.get("target_id") != index
        for index, node in enumerate(nodes)
    ):
        raise StageAInputError("product graph nodes do not canonically index relation regions")
    if not isinstance(evidence, Mapping) or not isinstance(counts, Mapping):
        raise StageAInputError("product graph reachability evidence is missing")
    represented = _as_int_list(
        evidence.get("declared_reachable_node_ids"),
        "product graph declared reachability",
    )
    potential = _as_int_list(
        evidence.get("potential_reachable_node_ids"),
        "product graph potential reachability",
    )
    roots = _as_int_list(product_graph.get("root_node_ids"), "product graph roots")
    frontier = _as_int_list(
        evidence.get("reachable_decoded_control_frontier_node_ids"),
        "product graph decoded-control frontier",
    )
    canonical_set = set(canonical)
    if not set(represented).issubset(canonical_set) or not set(potential).issubset(canonical_set):
        raise StageAInputError("product graph reachability escapes its canonical nodes")
    if not set(represented).issubset(set(potential)):
        raise StageAInputError("potential reachability omits a represented rooted node")
    control_closed = bool(counts.get("declared_reachability_control_closed"))
    if control_closed != (not frontier):
        raise StageAInputError("product graph control closure disagrees with its frontier")
    return RequirementScope(
        canonical_node_ids=tuple(canonical),
        represented_rooted_node_ids=tuple(represented),
        conservative_required_node_ids=tuple(potential),
        root_node_ids=tuple(roots),
        control_closed=control_closed,
        control_frontier_node_ids=tuple(frontier),
    )


def _decode_occurrences(
    binary: StageABinary,
    side: str,
    regions: list[Mapping[str, Any]],
) -> tuple[list[InstructionOccurrence], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    occurrences: list[InstructionOccurrence] = []
    forms: dict[str, dict[str, Any]] = {}
    gaps: list[dict[str, Any]] = []
    for node_id, region in enumerate(regions):
        span = region.get(side)
        if not isinstance(span, Mapping):
            raise StageAInputError(f"relation region {node_id} has no {side} span")
        start = int(span.get("rva_start", -1))
        stop = int(span.get("rva_end", -1))
        if start < 0 or stop <= start:
            raise StageAInputError(f"relation region {node_id} has an invalid {side} span")
        encoded_region = binary.pe.get_data(start, stop - start)
        decoded = list(decoder.disasm(encoded_region, binary.image_base + start))
        if not decoded or sum(int(row.size) for row in decoded) != len(encoded_region):
            raise StageAInputError(
                f"relation region {node_id} does not decode exactly for {side} ISA inventory"
            )
        for instruction in decoded:
            form = instruction_form_payload(instruction)
            form_id = str(form["id"])
            forms.setdefault(form_id, form)
            rva = int(instruction.address - binary.image_base)
            encoded = bytes(instruction.bytes).hex()
            occurrence_identity = {
                "binary_sha256": binary.sha256,
                "side": side,
                "node_id": node_id,
                "rva": rva,
                "bytes": encoded,
                "form_id": form_id,
            }
            supported = instruction_supported(instruction)
            occurrence_id = "x86-occurrence-" + _canonical_sha256(
                occurrence_identity
            )[:20]
            occurrences.append(
                InstructionOccurrence(
                    id=occurrence_id,
                    side=side,
                    node_id=node_id,
                    region_id=str(region.get("id", "")),
                    rva=rva,
                    size=int(instruction.size),
                    encoded=encoded,
                    form_id=form_id,
                    capstone_preflight_status=(
                        "accepted" if supported else "unsupported"
                    ),
                )
            )
            if not supported:
                gaps.append(
                    {
                        "id": "isa-gap-" + _canonical_sha256(occurrence_identity)[:20],
                        "category": "diagnostic_preflight_instruction_unsupported",
                        "side": side,
                        "node_id": node_id,
                        "region_id": str(region.get("id", "")),
                        "rva": rva,
                        "bytes": encoded,
                        "form_id": form_id,
                        "mnemonic": str(instruction.mnemonic),
                        "op_str": str(instruction.op_str),
                    }
                )
    return occurrences, forms, gaps


def build_isa_requirement_inventory(
    *,
    original: StageABinary,
    candidate: StageABinary,
    relation_contract: Mapping[str, Any],
    product_graph: Mapping[str, Any],
    lean_forms: Mapping[tuple[str, int], tuple[dict[str, Any], ...]],
    lean_form_source_sha256: str,
    lean_form_extractor_sha256: str,
) -> ISARequirementInventory:
    regions_value = relation_contract.get("regions")
    if not isinstance(regions_value, list) or any(
        not isinstance(region, Mapping) for region in regions_value
    ):
        raise StageAInputError("relation contract regions must be a list of objects")
    regions = list(regions_value)
    scope = _scope_from_product_graph(product_graph, len(regions))
    all_occurrences: list[InstructionOccurrence] = []
    display_forms: dict[str, dict[str, Any]] = {}
    gaps: list[dict[str, Any]] = []
    for side, binary in (("original", original), ("candidate", candidate)):
        occurrences, side_forms, side_gaps = _decode_occurrences(binary, side, regions)
        all_occurrences.extend(occurrences)
        display_forms.update(side_forms)
        gaps.extend(side_gaps)
    all_occurrences.sort(key=lambda row: row.id)
    expected_region_sides = {
        (side, node_id)
        for side in _SIDES
        for node_id in range(len(regions))
    }
    if set(lean_forms) != expected_region_sides:
        raise StageAInputError(
            "Lean semantic-form inventory does not cover every relation region side"
        )
    capstone_by_region: dict[
        tuple[str, int], list[InstructionOccurrence]
    ] = {identity: [] for identity in expected_region_sides}
    for occurrence in all_occurrences:
        capstone_by_region[(occurrence.side, occurrence.node_id)].append(occurrence)
    formal_form_by_occurrence: dict[str, tuple[str, str]] = {}
    formal_forms: dict[str, dict[str, Any]] = {}
    for identity in sorted(expected_region_sides):
        capstone_rows = sorted(
            capstone_by_region[identity], key=lambda row: row.rva
        )
        formal_rows = list(lean_forms[identity])
        capstone_spans = [
            (row.rva, row.size, row.encoded) for row in capstone_rows
        ]
        formal_spans = [
            (int(row["rva"]), int(row["size"]), str(row["bytes"]))
            for row in formal_rows
        ]
        if capstone_spans != formal_spans:
            raise StageAInputError(
                "Capstone and Lean disagree on instruction spans or bytes for "
                f"{identity[0]} region {identity[1]}"
            )
        for occurrence, formal in zip(capstone_rows, formal_rows, strict=True):
            semantic_form = str(formal["form"])
            formal_core = lean_semantic_form_core(
                semantic_form,
                classifier_sha256=lean_form_source_sha256,
            )
            formal_id = lean_semantic_form_id(
                semantic_form,
                classifier_sha256=lean_form_source_sha256,
            )
            formal_form_by_occurrence[occurrence.id] = (
                formal_id,
                occurrence.form_id,
            )
            row = formal_forms.setdefault(
                formal_id,
                {
                    "id": formal_id,
                    **formal_core,
                    "capstone_display_form_ids": set(),
                },
            )
            row["capstone_display_form_ids"].add(occurrence.form_id)
    occurrence_payloads: list[dict[str, Any]] = []
    for occurrence in all_occurrences:
        formal_id, display_id = formal_form_by_occurrence[occurrence.id]
        row = occurrence.to_payload()
        row["form_id"] = formal_id
        row["capstone_display_form_id"] = display_id
        occurrence_payloads.append(row)
    for gap in gaps:
        matching = next(
            row
            for row in all_occurrences
            if row.side == gap["side"]
            and row.node_id == gap["node_id"]
            and row.rva == gap["rva"]
        )
        gap["capstone_display_form_id"] = gap.pop("form_id")
        gap["form_id"] = formal_form_by_occurrence[matching.id][0]
    gaps.sort(key=lambda row: row["id"])
    required_nodes = set(scope.conservative_required_node_ids)
    represented_nodes = set(scope.represented_rooted_node_ids)
    required_occurrences = [
        row for row in all_occurrences if row.node_id in required_nodes
    ]
    represented_occurrences = [
        row for row in all_occurrences if row.node_id in represented_nodes
    ]
    required_occurrence_ids = {row.id for row in required_occurrences}
    represented_occurrence_ids = {row.id for row in represented_occurrences}
    required_form_ids = sorted({
        formal_form_by_occurrence[row.id][0] for row in required_occurrences
    })
    represented_form_ids = sorted({
        formal_form_by_occurrence[row.id][0] for row in represented_occurrences
    })
    required_gaps = [gap for gap in gaps if gap["node_id"] in required_nodes]
    form_rows = []
    for form_id in sorted(formal_forms):
        form_occurrences = [
            row
            for row in all_occurrences
            if formal_form_by_occurrence[row.id][0] == form_id
        ]
        form_row = dict(formal_forms[form_id])
        display_ids = sorted(form_row.pop("capstone_display_form_ids"))
        form_row["capstone_display_forms"] = [
            display_forms[display_id] for display_id in display_ids
        ]
        form_row["counts"] = {
            "canonical_occurrences": len(form_occurrences),
            "represented_rooted_occurrences": sum(
                row.id in represented_occurrence_ids for row in form_occurrences
            ),
            "conservative_required_occurrences": sum(
                row.id in required_occurrence_ids for row in form_occurrences
            ),
        }
        form_row["capstone_preflight_status"] = (
            "accepted"
            if all(
                row.capstone_preflight_status == "accepted"
                for row in form_occurrences
            )
            else "unsupported"
        )
        form_rows.append(form_row)
    payload = {
        "format": ISA_REQUIREMENT_INVENTORY_FORMAT,
        "status": "complete" if not gaps else "incomplete",
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "inputs": {
            "original_sha256": original.sha256,
            "candidate_sha256": candidate.sha256,
            "relation_contract_sha256": _canonical_sha256(relation_contract),
            "product_graph_sha256": _canonical_sha256(product_graph),
            "lean_form_source_sha256": lean_form_source_sha256,
            "lean_form_extractor_sha256": lean_form_extractor_sha256,
        },
        "scope": scope.to_payload(),
        "formal_binding": {
            "status": "lean_decoder_extracted_replay_pending",
            "classifier_module": "StageA.ISAQualification",
            "span_decoder_module": "StageA.RelationalISAQualification",
            "classifier_sha256": lean_form_source_sha256,
            "extractor_sha256": lean_form_extractor_sha256,
            "instruction_spans_and_bytes_match_capstone": True,
            "acceptance_certificate_checked": False,
        },
        "forms": form_rows,
        "occurrences": occurrence_payloads,
        "gaps": gaps,
        "counts": {
            "canonical_nodes": len(scope.canonical_node_ids),
            "represented_rooted_nodes": len(scope.represented_rooted_node_ids),
            "conservative_required_nodes": len(
                scope.conservative_required_node_ids
            ),
            "canonical_forms": len(formal_forms),
            "represented_rooted_forms": len(represented_form_ids),
            "conservative_required_forms": len(required_form_ids),
            "canonical_occurrences": len(all_occurrences),
            "represented_rooted_occurrences": len(represented_occurrences),
            "conservative_required_occurrences": len(required_occurrences),
            "unsupported_occurrences": len(gaps),
            "conservative_required_unsupported_occurrences": len(required_gaps),
        },
        "trust": {
            "role": "untrusted_exact_pe_requirement_and_coverage_proposal",
            "proof_authority": False,
            "closes_stage_a_proof": False,
            "lean_checks_required": [
                "exact_pe_byte_decode",
                "region_instruction_adequacy",
                "root_and_product_graph_closure",
                "whole_program_composition",
            ],
            "conformance_rule": (
                "emulator or hardware disagreement may veto semantic qualification; "
                "emulator or hardware agreement never proves instruction semantics"
            ),
        },
    }
    return ISARequirementInventory.parse(payload)


def write_isa_requirement_inventory(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    product_graph: Path,
    out: Path,
) -> dict[str, Any]:
    try:
        contract_payload = json.loads(Path(relation_contract).read_text(encoding="utf-8"))
        graph_payload = json.loads(Path(product_graph).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read ISA requirement input: {exc}") from exc
    if not isinstance(contract_payload, Mapping) or not isinstance(graph_payload, Mapping):
        raise StageAInputError("ISA requirement contract and graph must be objects")
    lean_forms, lean_evidence = extract_lean_instruction_forms(
        original=Path(original),
        candidate=Path(candidate),
        relation_contract=contract_payload,
    )
    inventory = build_isa_requirement_inventory(
        original=_parse_stage_a_pe(Path(original)),
        candidate=_parse_stage_a_pe(Path(candidate)),
        relation_contract=contract_payload,
        product_graph=graph_payload,
        lean_forms=lean_forms,
        lean_form_source_sha256=str(lean_evidence["classifier_sha256"]),
        lean_form_extractor_sha256=str(lean_evidence["extractor_sha256"]),
    )
    write_json(Path(out), inventory.to_payload())
    return {
        "format": "stage-a-isa-requirement-inventory-result-v1",
        "status": inventory.payload["status"],
        "out": str(out),
        "sha256": sha256_file(Path(out)),
        "counts": inventory.payload["counts"],
        "control_closed": inventory.payload["scope"]["control_closed"],
        "formal_binding": inventory.payload["formal_binding"]["status"],
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


__all__ = [
    "ISA_REQUIREMENT_FORM_FORMAT",
    "ISA_REQUIREMENT_INVENTORY_FORMAT",
    "ISARequirementInventory",
    "InstructionOccurrence",
    "RequirementScope",
    "build_isa_requirement_inventory",
    "instruction_form_payload",
    "write_isa_requirement_inventory",
]
