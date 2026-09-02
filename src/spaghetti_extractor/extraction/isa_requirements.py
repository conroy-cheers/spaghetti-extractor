"""Exact-PE instruction requirements for ISA semantic qualification.

The inventory produced here is deliberately untrusted analysis.  It binds
diagnostic instruction forms and their occurrence scopes to exact PE hashes and
the selected executable inventory.  Qualification evidence can veto a decoder
or semantic implementation; it is not a whole-program equivalence proof.
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

from ..isa.semantic_forms import (
    lean_semantic_form_classifier_sha256,
)
from ..errors import ToolkitInputError
from ..pe32.image import parse_pe_image
from ..util import sha256_bytes, sha256_file, write_json
from .schema import ISA_FORM_EXTRACTION_MODULES


ISA_REQUIREMENT_INVENTORY_FORMAT = "spaghetti-extractor-isa-requirement-inventory-v1"
LEAN_ISA_FORM_INVENTORY_FORMAT = "spaghetti-extractor-lean-isa-form-inventory-v1"
_LEAN_FORM_EXTRACTION_DRIVER_VERSION = "runtime-request-table-v6"

_SIDES = ("original", "candidate")

_LEAN_SOURCE_ROOT = Path(__file__).resolve().parents[1] / "lean" / "SpaghettiExtractor/ISA"


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _as_int_list(value: Any, context: str) -> list[int]:
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in value
    ):
        raise ToolkitInputError(f"{context} must be a list of non-negative integers")
    if value != sorted(set(value)):
        raise ToolkitInputError(f"{context} must be unique and canonically ordered")
    return list(value)


@dataclass(frozen=True)
class ISARequirementInventory:
    payload: Mapping[str, Any]

    @classmethod
    def parse(cls, value: Any) -> "ISARequirementInventory":
        if not isinstance(value, Mapping):
            raise ToolkitInputError("ISA requirement inventory must be an object")
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
            raise ToolkitInputError("ISA requirement inventory has an invalid field inventory")
        if value.get("format") != ISA_REQUIREMENT_INVENTORY_FORMAT:
            raise ToolkitInputError("unsupported ISA requirement inventory format")
        scope = value.get("scope")
        if not isinstance(scope, Mapping):
            raise ToolkitInputError("ISA requirement inventory scope must be an object")
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
            raise ToolkitInputError("represented rooted nodes escape the canonical inventory")
        if not set(required).issubset(canonical_set):
            raise ToolkitInputError("conservative required nodes escape the canonical inventory")
        if not set(roots).issubset(set(represented)):
            raise ToolkitInputError("root nodes are absent from represented reachability")
        if scope.get("control_closed") is not (not frontier):
            raise ToolkitInputError("control-closure status disagrees with its frontier")
        forms = value.get("forms")
        occurrences = value.get("occurrences")
        gaps = value.get("gaps")
        if not isinstance(forms, list) or not isinstance(occurrences, list) or not isinstance(gaps, list):
            raise ToolkitInputError("ISA requirements forms, occurrences, and gaps must be lists")
        form_ids = [row.get("id") for row in forms if isinstance(row, Mapping)]
        if len(form_ids) != len(forms) or any(
            not isinstance(value, str) for value in form_ids
        ):
            raise ToolkitInputError("ISA requirement form IDs must be unique and ordered")
        typed_form_ids = [str(value) for value in form_ids]
        if typed_form_ids != sorted(set(typed_form_ids)):
            raise ToolkitInputError("ISA requirement form IDs must be unique and ordered")
        occurrence_ids = [
            row.get("id") for row in occurrences if isinstance(row, Mapping)
        ]
        if len(occurrence_ids) != len(occurrences) or any(
            not isinstance(value, str) for value in occurrence_ids
        ):
            raise ToolkitInputError("ISA requirement occurrence IDs must be unique and ordered")
        typed_occurrence_ids = [str(value) for value in occurrence_ids]
        if typed_occurrence_ids != sorted(set(typed_occurrence_ids)):
            raise ToolkitInputError("ISA requirement occurrence IDs must be unique and ordered")
        if any(
            row.get("form_id") not in set(typed_form_ids)
            or row.get("node_id") not in canonical_set
            for row in occurrences
            if isinstance(row, Mapping)
        ):
            raise ToolkitInputError("ISA occurrence references an unknown form or node")
        trust = value.get("trust")
        if (
            not isinstance(trust, Mapping)
            or set(trust) != {"role", "proof_authority", "lean_checks_required", "conformance_rule"}
            or trust.get("proof_authority") is not False
        ):
            raise ToolkitInputError("ISA requirement inventory cannot claim proof authority")
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
        raise ToolkitInputError(
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
            raise ToolkitInputError(f"ISA replay form {index} must be an object")
        form_id = form.get("id")
        semantic_form = form.get("semantic_form")
        if (
            not isinstance(form_id, str)
            or not form_id
            or not isinstance(semantic_form, str)
            or not semantic_form
        ):
            raise ToolkitInputError(f"ISA replay form {index} is malformed")
        semantic_forms[form_id] = semantic_form

    grouped: dict[tuple[str, int], list[ISARequirementReplayOccurrence]] = {
        (side, index): []
        for side in _SIDES
        for index in range(len(regions))
    }
    referenced_forms: set[str] = set()
    for index, occurrence in enumerate(occurrences_value):
        if not isinstance(occurrence, Mapping):
            raise ToolkitInputError(
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
            raise ToolkitInputError(
                f"ISA replay occurrence {index} has an invalid region identity"
            )
        region = regions[node_id]
        if occurrence.get("region_id") != str(region.get("id", "")):
            raise ToolkitInputError(
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
            raise ToolkitInputError(f"ISA replay occurrence {index} is malformed")
        try:
            encoded = bytes.fromhex(encoded_hex)
        except ValueError as exc:
            raise ToolkitInputError(
                f"ISA replay occurrence {index} has invalid encoded bytes"
            ) from exc
        if len(encoded) != size:
            raise ToolkitInputError(
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
        raise ToolkitInputError(
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
                raise ToolkitInputError(
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
                raise ToolkitInputError(
                    f"ISA replay region {region_index} has an invalid {side} span"
                )
            rows = sorted(grouped[(side, region_index)], key=lambda row: row.rva)
            if not rows or rows[0].rva != start:
                raise ToolkitInputError(
                    f"ISA replay region {region_index} omits the start of its {side} span"
                )
            cursor = start
            for row in rows:
                if row.rva != cursor:
                    raise ToolkitInputError(
                        f"ISA replay region {region_index} has a gap or duplicate in its "
                        f"{side} occurrence inventory"
                    )
                cursor += row.size
            if cursor != stop:
                raise ToolkitInputError(
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
        for module in ISA_FORM_EXTRACTION_MODULES
    }
    classifier = lean_semantic_form_classifier_sha256(_LEAN_SOURCE_ROOT)
    extractor = _canonical_sha256({"ISAInventory.lean": files["ISAInventory.lean"]})
    return {
        "classifier_sha256": classifier,
        "extractor_sha256": extractor,
        "source_sha256": _canonical_sha256({
            "lean_sources": files,
            "driver_version": _LEAN_FORM_EXTRACTION_DRIVER_VERSION,
        }),
    }


def _lean_form_requests(
    regions: list[Mapping[str, Any]],
) -> list[dict[str, int]]:
    requests: list[dict[str, int]] = []
    data_offset = 0
    for node_id, region in enumerate(regions):
        span = region.get("span")
        if not isinstance(span, Mapping):
            raise ToolkitInputError(
                f"ISA extraction request region {node_id} has no span"
            )
        size = int(span["size"])
        requests.append({
            "nodeId": node_id,
            "dataOffset": data_offset,
            "start": int(span["rva_start"]),
            "size": size,
        })
        data_offset += size
    return requests


def _lean_side_form_extraction_source(
    side: str,
    regions: list[Mapping[str, Any]],
    *,
    allow_decode_gaps: bool = False,
) -> str:
    if side not in _SIDES:
        raise ToolkitInputError(f"unsupported ISA extraction side {side!r}")
    _lean_form_requests(regions)
    decode_failure = (
        "IO.println <| Json.compress <| Json.mkObj [\n"
        "          (\"side\", toJson " + json.dumps(side) + "),\n"
        "          (\"node_id\", toJson request.nodeId),\n"
        "          (\"occurrences\", toJson ([] : List Json)),\n"
        "          (\"decode_error\", toJson \"unsupported_instruction_form\")\n"
        "        ]"
        if allow_decode_gaps
        else 'throw (IO.userError s!"region {request.nodeId} did not decode")'
    )
    return """import Lean
import SpaghettiExtractor.ISA.ISAInventory

namespace SpaghettiExtractor.ISA.GeneratedSideISARequirementInventory

open Lean SpaghettiExtractor.ISA.Formal SpaghettiExtractor.ISA.ISAInventory

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

structure Request where
  nodeId : Nat
  dataOffset : Nat
  start : Nat
  size : Nat
deriving FromJson

def run : IO Unit := do
  let requestText <- IO.FS.readFile "artifacts/requests.json"
  let requestJson <- match Json.parse requestText with
    | Except.ok value => pure value
    | Except.error message =>
      throw (IO.userError s!"request table is malformed JSON: {message}")
  let requests : List Request <- match
      (fromJson? requestJson : Except String (List Request)) with
    | Except.ok value => pure value
    | Except.error message =>
      throw (IO.userError s!"request table has an invalid schema: {message}")
  let data <- IO.FS.readBinFile "artifacts/regions.bin"
  for request in requests do
    let span : ISAInventory.Span := {
      start := request.start
      size := request.size
    }
    let dataStop := request.dataOffset + span.size
    if data.size < dataStop then
      throw (IO.userError s!"region {request.nodeId} bytes are truncated")
    let bytes : ISAInventory.Bytes :=
      (data.extract request.dataOffset dataStop).toList.map
        (fun byte => byte.toNat)
    match decodeInstructionFormsBytes span.start bytes with
    | none =>
      """ + decode_failure + """
    | some occurrences =>
      IO.println <| Json.compress <| Json.mkObj [
        ("side", toJson """ + json.dumps(side) + """),
        ("node_id", toJson request.nodeId),
        ("occurrences", instructionFormInventoryJson occurrences)
      ]

end SpaghettiExtractor.ISA.GeneratedSideISARequirementInventory

def main : IO Unit := SpaghettiExtractor.ISA.GeneratedSideISARequirementInventory.run
"""


def _parse_lean_form_rows(
    rows: Any,
    region_count: int,
    *,
    sides: tuple[str, ...] = _SIDES,
    expected_spans: Mapping[tuple[str, int], tuple[int, int]] | None = None,
    expected_identities: set[tuple[str, int]] | None = None,
) -> dict[tuple[str, int], tuple[dict[str, Any], ...]]:
    if not isinstance(rows, list):
        raise ToolkitInputError("Lean ISA form inventory rows must be a list")
    expected = (
        {
            (side, node_id)
            for side in sides
            for node_id in range(region_count)
        }
        if expected_identities is None
        else set(expected_identities)
    )
    result: dict[tuple[str, int], tuple[dict[str, Any], ...]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping) or set(row) != {
            "side",
            "node_id",
            "occurrences",
        }:
            raise ToolkitInputError(f"Lean ISA form row {index} is malformed")
        side = row.get("side")
        node_id = row.get("node_id")
        if side not in _SIDES or isinstance(node_id, bool) or not isinstance(node_id, int):
            raise ToolkitInputError(f"Lean ISA form row {index} has an invalid identity")
        identity = (str(side), node_id)
        if identity not in expected or identity in result:
            raise ToolkitInputError(f"Lean ISA form row {index} is unexpected or duplicate")
        raw_occurrences = row.get("occurrences")
        if not isinstance(raw_occurrences, list) or not raw_occurrences:
            raise ToolkitInputError(f"Lean ISA form row {index} has no occurrences")
        occurrences: list[dict[str, Any]] = []
        previous_stop: int | None = None
        for occurrence_index, occurrence in enumerate(raw_occurrences):
            if not isinstance(occurrence, Mapping) or set(occurrence) != {
                "rva",
                "size",
                "bytes",
                "form",
            }:
                raise ToolkitInputError(
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
                raise ToolkitInputError(
                    f"Lean ISA form row {index} occurrence {occurrence_index} is invalid"
                )
            if previous_stop is not None and rva != previous_stop:
                raise ToolkitInputError(
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
                raise ToolkitInputError(
                    f"Lean ISA form row {index} has no declared span"
                )
            if (
                occurrences[0]["rva"] != expected_span[0]
                or previous_stop != expected_span[0] + expected_span[1]
            ):
                raise ToolkitInputError(
                    f"Lean ISA form row {index} does not cover its declared span"
                )
    if set(result) != expected:
        raise ToolkitInputError("Lean ISA form inventory omitted a region side")
    return result


def _parse_lean_partial_form_rows(
    rows: Any,
    region_count: int,
    *,
    side: str,
    expected_spans: Mapping[tuple[str, int], tuple[int, int]],
) -> tuple[
    dict[tuple[str, int], tuple[dict[str, Any], ...]],
    list[dict[str, Any]],
]:
    if not isinstance(rows, list):
        raise ToolkitInputError("Lean ISA form inventory rows must be a list")
    successful: list[Mapping[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ToolkitInputError(f"Lean ISA form row {index} is malformed")
        row_side = row.get("side")
        node_id = row.get("node_id")
        if (
            row_side != side
            or isinstance(node_id, bool)
            or not isinstance(node_id, int)
            or not 0 <= node_id < region_count
        ):
            raise ToolkitInputError(
                f"Lean ISA form row {index} has an invalid identity"
            )
        identity = (str(row_side), node_id)
        if identity in seen:
            raise ToolkitInputError(
                f"Lean ISA form row {index} has a duplicate identity"
            )
        seen.add(identity)
        if "decode_error" not in row:
            successful.append(row)
            continue
        if (
            set(row) != {"side", "node_id", "occurrences", "decode_error"}
            or row.get("occurrences") != []
            or row.get("decode_error") != "unsupported_instruction_form"
        ):
            raise ToolkitInputError(f"Lean ISA gap row {index} is malformed")
        start, size = expected_spans[identity]
        gaps.append({
            "side": side,
            "node_id": node_id,
            "rva": start,
            "size": size,
            "code": str(row["decode_error"]),
        })
    expected = {(side, node_id) for node_id in range(region_count)}
    if seen != expected:
        raise ToolkitInputError("Lean ISA partial inventory omitted a region")
    successful_ids = expected - {
        (side, int(gap["node_id"])) for gap in gaps
    }
    parsed = _parse_lean_form_rows(
        successful,
        region_count,
        sides=(side,),
        expected_spans=expected_spans,
        expected_identities=successful_ids,
    )
    return parsed, sorted(gaps, key=lambda row: int(row["node_id"]))


def extract_lean_instruction_forms_side(
    *,
    binary: Path,
    request: Mapping[str, Any],
    timeout_seconds: float = 300.0,
    allow_decode_gaps: bool = False,
) -> tuple[dict[tuple[str, int], tuple[dict[str, Any], ...]], dict[str, Any]]:
    side = request.get("side")
    if side not in _SIDES:
        raise ToolkitInputError("side ISA extraction request has an invalid side")
    binary = Path(binary)
    binary_sha256 = sha256_file(binary)
    if request.get("binary_sha256") != binary_sha256:
        raise ToolkitInputError(f"{side} ISA extraction binary hash mismatch")
    regions_value = request.get("regions")
    if not isinstance(regions_value, list) or any(
        not isinstance(region, Mapping) for region in regions_value
    ):
        raise ToolkitInputError("side ISA extraction regions must be objects")
    regions = list(regions_value)
    expected_spans: dict[tuple[str, int], tuple[int, int]] = {}
    for index, region in enumerate(regions):
        if region.get("index") != index:
            raise ToolkitInputError(
                "side ISA extraction region indices are not canonical"
            )
        span = region.get("span")
        if not isinstance(span, Mapping):
            raise ToolkitInputError(f"side ISA extraction region {index} has no span")
        expected_spans[(str(side), index)] = (
            int(span.get("rva_start", -1)),
            int(span.get("size", -1)),
        )
    source_hashes = _lean_form_source_hashes()
    input_identity = {
        "format": "spaghetti-extractor-lean-side-isa-form-inventory-v1",
        "side": side,
        "binary_sha256": binary_sha256,
        "request_sha256": _canonical_sha256(request),
        "lean_form_source_sha256": source_hashes["source_sha256"],
        "allow_decode_gaps": allow_decode_gaps,
    }
    from ..build_support.lean_runner import run_lean_module_graph

    cache_root = None
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
                if allow_decode_gaps:
                    rows, gaps = _parse_lean_partial_form_rows(
                        cached.get("rows"),
                        len(regions),
                        side=str(side),
                        expected_spans=expected_spans,
                    )
                else:
                    rows = _parse_lean_form_rows(
                        cached.get("rows"),
                        len(regions),
                        sides=(str(side),),
                        expected_spans=expected_spans,
                    )
                    gaps = []
                return rows, {
                    "status": "lean_extracted_untrusted",
                    "cache": "hit",
                    **source_hashes,
                    "row_count": len(rows),
                    "decode_gaps": gaps,
                }
        except (OSError, json.JSONDecodeError, ToolkitInputError):
            pass
    lean = shutil.which("lean")
    if lean is None:
        raise ToolkitInputError("Lean is required to extract ISA semantic forms")
    with tempfile.TemporaryDirectory(
        prefix=f"spaghetti-extractor-isa-{side}-requirements-"
    ) as temporary:
        lean_dir = Path(temporary)
        isa_modules = lean_dir / "SpaghettiExtractor/ISA"
        artifacts = lean_dir / "artifacts"
        isa_modules.mkdir(parents=True)
        artifacts.mkdir()
        for module in ISA_FORM_EXTRACTION_MODULES:
            shutil.copyfile(
                _LEAN_SOURCE_ROOT / f"{module}.lean",
                isa_modules / f"{module}.lean",
            )
        kernel_cache = os.environ.get("SPAGHETTI_LEAN_KERNEL_CACHE")
        if kernel_cache:
            kernel_isa_cache = Path(kernel_cache) / "SpaghettiExtractor/ISA"
            for module in ISA_FORM_EXTRACTION_MODULES:
                cached = kernel_isa_cache / f"{module}.olean"
                if cached.is_file():
                    shutil.copyfile(cached, isa_modules / cached.name)
        parsed_binary = parse_pe_image(binary)
        region_bytes = bytearray()
        for index, region in enumerate(regions):
            span = region["span"]
            start = int(span["rva_start"])
            size = int(span["size"])
            encoded = parsed_binary.pe.get_data(start, size)
            if len(encoded) != size:
                raise ToolkitInputError(
                    f"{side} ISA extraction region {index} bytes are truncated"
                )
            region_bytes.extend(encoded)
        (artifacts / "regions.bin").write_bytes(region_bytes)
        write_json(artifacts / "requests.json", _lean_form_requests(regions))
        bundle = f"GeneratedISARequirementInventory{str(side).title()}"
        (isa_modules / f"{bundle}.lean").write_text(
            _lean_side_form_extraction_source(
                str(side),
                regions,
                allow_decode_gaps=allow_decode_gaps,
            ),
            encoding="utf-8",
        )
        compiled = run_lean_module_graph(lean_dir, bundle=bundle)
        if compiled.get("status") != "checked":
            raise ToolkitInputError(
                f"Lean {side} ISA form extraction did not compile: "
                + str(compiled.get("stderr") or compiled.get("stdout"))
            )
        completed = subprocess.run(
            [lean, "--trust=0", "--run", f"SpaghettiExtractor/ISA/{bundle}.lean"],
            cwd=lean_dir,
            env={**os.environ, "LEAN_PATH": "."},
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
        )
        if completed.returncode != 0:
            raise ToolkitInputError(
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
            raise ToolkitInputError(
                f"Lean {side} ISA form extraction emitted malformed JSON: {exc}"
            ) from exc
    if allow_decode_gaps:
        rows, gaps = _parse_lean_partial_form_rows(
            raw_rows,
            len(regions),
            side=str(side),
            expected_spans=expected_spans,
        )
    else:
        rows = _parse_lean_form_rows(
            raw_rows,
            len(regions),
            sides=(str(side),),
            expected_spans=expected_spans,
        )
        gaps = []
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
                },
            },
        )
    return rows, {
        "status": "lean_extracted_untrusted",
        "cache": "miss",
        **source_hashes,
        "row_count": len(rows),
        "decode_gaps": gaps,
    }




__all__ = [
    "ISA_REQUIREMENT_INVENTORY_FORMAT",
    "ISARequirementInventory",
    "ISARequirementReplayOccurrence",
    "ISARequirementReplayRegion",
    "extract_lean_instruction_forms_side",
    "isa_requirement_replay_projection",
]
