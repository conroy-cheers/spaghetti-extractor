"""Adapt exact side-ISA inventories into qualification pipeline inputs.

The adapter is deliberately untrusted. It preserves every exact occurrence and
proposes one executable encoding row per observed ``(semantic form, bytes)``
pair, but it cannot supply effects or defined-output masks. Lean replay and
candidate qualification remain separate requirements.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .isa_catalog import ISA_PROFILE_ID
from .isa_semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_core,
    lean_semantic_form_id,
)
from .analysis.isa_requirements import (
    ISA_REQUIREMENT_INVENTORY_FORMAT,
    ISARequirementInventory,
)
from .analysis.schema import STATIC_ANALYSIS_MODEL_ID
from .analysis.isa_inventory import parse_side_isa_unbound
from .stage_binary import StageAInputError
from .util import sha256_bytes, sha256_file, write_json


SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT = (
    "stage-a-side-isa-executable-catalog-proposal-v1"
)
SIDE_ISA_QUALIFICATION_ADAPTER_RESULT_FORMAT = (
    "stage-a-side-isa-qualification-adapter-result-v1"
)
_ADAPTER_VERSION = "side-isa-qualification-adapter-v1"
_SIDES = ("original", "candidate")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class _ParsedSide:
    side: str
    binary_sha256: str
    artifact_sha256: str
    classifier_sha256: str
    extractor_sha256: str
    source_sha256: str
    request: Any
    regions: tuple[tuple[dict[str, Any], ...], ...]


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def _read_mapping(path: Path, context: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context} {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return payload


def _hash_field(payload: Mapping[str, Any], field: str, context: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(
            f"{context} {field} must be 64 lowercase hex characters"
        )
    return value


def _parse_side(artifact: Path, binary: Path) -> _ParsedSide:
    payload = _read_mapping(artifact, "side ISA artifact")
    side = payload.get("side")
    if side not in _SIDES:
        raise StageAInputError("side ISA artifact side is invalid")
    binary_sha256 = _hash_field(payload, "binary_sha256", "side ISA artifact")
    actual_binary_sha256 = sha256_file(Path(binary))
    if binary_sha256 != actual_binary_sha256:
        raise StageAInputError(
            f"{side} side ISA artifact names a different binary"
        )
    classifier_sha256 = _hash_field(
        payload, "classifier_sha256", "side ISA artifact"
    )
    current_classifier = lean_semantic_form_classifier_sha256()
    if classifier_sha256 != current_classifier:
        raise StageAInputError(
            f"{side} side ISA artifact uses a stale semantic classifier"
        )
    extractor_sha256 = _hash_field(
        payload, "extractor_sha256", "side ISA artifact"
    )
    source_sha256 = _hash_field(payload, "source_sha256", "side ISA artifact")
    request, regions = parse_side_isa_unbound(
        payload,
        expected_side=side,
        expected_binary_sha256=binary_sha256,
        classifier_sha256=classifier_sha256,
        extractor_sha256=extractor_sha256,
        source_sha256=source_sha256,
    )
    return _ParsedSide(
        side=side,
        binary_sha256=binary_sha256,
        artifact_sha256=sha256_file(Path(artifact)),
        classifier_sha256=classifier_sha256,
        extractor_sha256=extractor_sha256,
        source_sha256=source_sha256,
        request=request,
        regions=tuple(regions),
    )


def _validate_side_set(sides: Sequence[_ParsedSide]) -> tuple[_ParsedSide, ...]:
    if not 1 <= len(sides) <= 2:
        raise StageAInputError(
            "side ISA qualification adaptation requires one or two inputs"
        )
    by_side = {side.side: side for side in sides}
    if len(by_side) != len(sides):
        raise StageAInputError("duplicate side ISA input")
    ordered = tuple(by_side[side] for side in _SIDES if side in by_side)
    classifier_ids = {side.classifier_sha256 for side in ordered}
    extractor_ids = {side.extractor_sha256 for side in ordered}
    source_ids = {side.source_sha256 for side in ordered}
    if len(classifier_ids) != 1:
        raise StageAInputError("side ISA inputs use different semantic classifiers")
    if len(extractor_ids) != 1 or len(source_ids) != 1:
        raise StageAInputError("side ISA inputs use different extraction revisions")
    return ordered


def _occurrence_id(
    *,
    side: str,
    node_id: int,
    region_id: str,
    rva: int,
    size: int,
    encoded: str,
    form_id: str,
) -> str:
    core = {
        "side": side,
        "node_id": node_id,
        "region_id": region_id,
        "rva": rva,
        "size": size,
        "bytes": encoded,
        "form_id": form_id,
    }
    return "isa-occurrence-" + _canonical_sha256(core)[:24]


def _encoding_id(form_id: str, encoded: str) -> str:
    return "lean-x86-encoding-" + _canonical_sha256({
        "form_id": form_id,
        "bytes": encoded,
    })[:24]


def adapt_side_isa_qualification_inputs(
    inputs: Sequence[tuple[Path, Path]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return exact requirements and an effect-incomplete catalog proposal."""

    parsed = _validate_side_set([
        _parse_side(Path(artifact), Path(binary))
        for artifact, binary in inputs
    ])
    classifier_sha256 = parsed[0].classifier_sha256
    extractor_sha256 = parsed[0].extractor_sha256
    source_sha256 = parsed[0].source_sha256
    side_node_offsets: dict[str, int] = {}
    node_count = 0
    for side_input in parsed:
        if not side_input.request.regions:
            raise StageAInputError(
                f"{side_input.side} side ISA input contains no regions"
            )
        side_node_offsets[side_input.side] = node_count
        node_count += len(side_input.request.regions)

    occurrences: list[dict[str, Any]] = []
    occurrence_ids: set[str] = set()
    form_occurrences: dict[str, list[str]] = defaultdict(list)
    semantic_forms: dict[str, str] = {}
    encodings: dict[tuple[str, str], dict[str, Any]] = {}
    form_by_bytes: dict[str, str] = {}

    for side_input in parsed:
        for region, rows in zip(
            side_input.request.regions,
            side_input.regions,
            strict=True,
        ):
            node_id = side_node_offsets[side_input.side] + region.index
            for row in rows:
                semantic_form = row["form"]
                form_core = lean_semantic_form_core(
                    semantic_form,
                    classifier_sha256=classifier_sha256,
                )
                form_id = lean_semantic_form_id(
                    semantic_form,
                    classifier_sha256=classifier_sha256,
                )
                previous_semantic = semantic_forms.setdefault(
                    form_id, semantic_form
                )
                if previous_semantic != semantic_form:
                    raise StageAInputError("Lean semantic-form identity collision")
                encoded = row["bytes"]
                previous_form = form_by_bytes.setdefault(encoded, form_id)
                if previous_form != form_id:
                    raise StageAInputError(
                        "one exact instruction encoding maps to multiple semantic forms"
                    )
                occurrence_id = _occurrence_id(
                    side=side_input.side,
                    node_id=node_id,
                    region_id=region.id,
                    rva=row["rva"],
                    size=row["size"],
                    encoded=encoded,
                    form_id=form_id,
                )
                if occurrence_id in occurrence_ids:
                    raise StageAInputError("duplicate canonical ISA occurrence")
                occurrence_ids.add(occurrence_id)
                form_occurrences[form_id].append(occurrence_id)
                occurrence = {
                    "id": occurrence_id,
                    "side": side_input.side,
                    "node_id": node_id,
                    "side_region_index": region.index,
                    "side_region_numeric_id": region.numeric_id,
                    "region_id": region.id,
                    "rva": row["rva"],
                    "size": row["size"],
                    "bytes": encoded,
                    "form_id": form_id,
                    "capstone_preflight_status": "not_applicable_lean_side_inventory",
                }
                occurrences.append(occurrence)
                key = (form_id, encoded)
                encoding = encodings.setdefault(
                    key,
                    {
                        "format": "stage-a-side-isa-executable-encoding-proposal-v1",
                        "encoding_id": _encoding_id(form_id, encoded),
                        "form_id": form_id,
                        "semantic_form": semantic_form,
                        "instruction_bytes": list(bytes.fromhex(encoded)),
                        "instruction_hex": encoded,
                        "source_occurrence_ids": [],
                        "representative": False,
                        "enrichment": {
                            "status": "missing",
                            "missing_fields": [
                                "defined_outputs",
                                "effects",
                                "required_features",
                            ],
                        },
                    },
                )
                encoding["source_occurrence_ids"].append(occurrence_id)

    occurrences.sort(key=lambda row: row["id"])
    for encoding in encodings.values():
        encoding["source_occurrence_ids"].sort()

    representative_by_form: dict[str, str] = {}
    for form_id in semantic_forms:
        candidates = [
            row for (candidate_form, _), row in encodings.items()
            if candidate_form == form_id
        ]
        representative = min(
            candidates,
            key=lambda row: (
                len(row["instruction_bytes"]),
                row["instruction_hex"],
            ),
        )
        representative["representative"] = True
        representative_by_form[form_id] = representative["encoding_id"]

    forms: list[dict[str, Any]] = []
    for form_id in sorted(semantic_forms):
        form_core = lean_semantic_form_core(
            semantic_forms[form_id],
            classifier_sha256=classifier_sha256,
        )
        canonical_count = len(form_occurrences[form_id])
        forms.append({
            "id": form_id,
            **form_core,
            "capstone_display_forms": [],
            "counts": {
                "canonical_occurrences": canonical_count,
                "represented_rooted_occurrences": 0,
                "conservative_required_occurrences": canonical_count,
            },
            "capstone_preflight_status": "not_applicable_lean_side_inventory",
        })

    side_sources = [
        {
            "side": side.side,
            "binary_sha256": side.binary_sha256,
            "artifact_sha256": side.artifact_sha256,
        }
        for side in parsed
    ]
    inputs_payload: dict[str, Any] = {
        "original_sha256": None,
        "candidate_sha256": None,
        "side_isa_artifacts": side_sources,
        "classifier_sha256": classifier_sha256,
        "extractor_sha256": extractor_sha256,
        "source_sha256": source_sha256,
        "adapter_version": _ADAPTER_VERSION,
    }
    for side in parsed:
        inputs_payload[f"{side.side}_sha256"] = side.binary_sha256

    canonical_nodes = list(range(node_count))
    requirements = {
        "format": ISA_REQUIREMENT_INVENTORY_FORMAT,
        "status": "complete",
        "model": STATIC_ANALYSIS_MODEL_ID,
        "inputs": inputs_payload,
        "scope": {
            "canonical_node_ids": canonical_nodes,
            "represented_rooted_node_ids": [],
            "conservative_required_node_ids": canonical_nodes,
            "root_node_ids": [],
            "control_closed": False,
            "control_frontier_node_ids": canonical_nodes,
        },
        "formal_binding": {
            "status": "lean_side_decode_extracted_replay_pending",
            "classifier_module": "StageA.ISAQualification",
            "span_decoder_module": "StageA.ISAInventory",
            "classifier_sha256": classifier_sha256,
            "extractor_sha256": extractor_sha256,
            "instruction_spans_and_bytes_match_capstone": False,
            "acceptance_certificate_checked": False,
        },
        "forms": forms,
        "occurrences": occurrences,
        "gaps": [],
        "counts": {
            "canonical_nodes": node_count,
            "represented_rooted_nodes": 0,
            "conservative_required_nodes": node_count,
            "canonical_forms": len(forms),
            "represented_rooted_forms": 0,
            "conservative_required_forms": len(forms),
            "canonical_occurrences": len(occurrences),
            "represented_rooted_occurrences": 0,
            "conservative_required_occurrences": len(occurrences),
            "unsupported_occurrences": 0,
            "conservative_required_unsupported_occurrences": 0,
        },
        "trust": {
            "role": "untrusted_side_isa_qualification_input_adapter",
            "proof_authority": False,
            "closes_stage_a_proof": False,
            "lean_checks_required": [
                "exact_pe_byte_decode",
                "region_instruction_adequacy",
                "root_and_product_graph_closure",
                "whole_program_composition",
            ],
            "conformance_rule": (
                "oracle agreement may qualify a reviewed semantic kernel revision; "
                "it never qualifies a reconstructed candidate"
            ),
        },
    }
    requirements = ISARequirementInventory.parse(requirements).to_payload()

    encoding_rows = sorted(
        encodings.values(),
        key=lambda row: (row["form_id"], row["instruction_hex"]),
    )
    catalog_proposal = {
        "format": SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT,
        "status": "incomplete_missing_effect_enrichment",
        "profile": ISA_PROFILE_ID,
        "model": STATIC_ANALYSIS_MODEL_ID,
        "classifier_sha256": classifier_sha256,
        "requirements_sha256": _canonical_sha256(requirements),
        "source": {
            "adapter": _ADAPTER_VERSION,
            "side_isa_artifacts": side_sources,
        },
        "forms": [
            {
                "form_id": form_id,
                "semantic_form": semantic_forms[form_id],
                "representative_encoding_id": representative_by_form[form_id],
                "encoding_ids": sorted(
                    row["encoding_id"]
                    for (candidate_form, _), row in encodings.items()
                    if candidate_form == form_id
                ),
            }
            for form_id in sorted(semantic_forms)
        ],
        "encodings": encoding_rows,
        "missing_enrichment": {
            "status": "required",
            "fields": ["defined_outputs", "effects", "required_features"],
            "encoding_count": len(encoding_rows),
            "corpus_generation_allowed": False,
        },
        "counts": {
            "forms": len(forms),
            "encodings": len(encoding_rows),
            "occurrences": len(occurrences),
            "representatives": len(representative_by_form),
        },
        "trust": {
            "role": "untrusted_executable_catalog_enrichment_proposal",
            "proof_authority": False,
            "closes_stage_a_proof": False,
        },
    }
    return requirements, catalog_proposal


def write_side_isa_qualification_inputs(
    *,
    side_isa_artifacts: Sequence[Path],
    binaries: Sequence[Path],
    requirements_out: Path,
    catalog_out: Path,
) -> dict[str, Any]:
    if len(side_isa_artifacts) != len(binaries):
        raise StageAInputError(
            "--side-isa and --binary must be supplied the same number of times"
        )
    requirements, catalog = adapt_side_isa_qualification_inputs(
        list(zip(side_isa_artifacts, binaries, strict=True))
    )
    write_json(Path(requirements_out), requirements)
    write_json(Path(catalog_out), catalog)
    return {
        "format": SIDE_ISA_QUALIFICATION_ADAPTER_RESULT_FORMAT,
        "status": "generated",
        "catalog_status": "incomplete_missing_effect_enrichment",
        "requirements_out": str(requirements_out),
        "requirements_sha256": sha256_file(Path(requirements_out)),
        "catalog_out": str(catalog_out),
        "catalog_sha256": sha256_file(Path(catalog_out)),
        "counts": catalog["counts"],
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


__all__ = [
    "SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT",
    "SIDE_ISA_QUALIFICATION_ADAPTER_RESULT_FORMAT",
    "adapt_side_isa_qualification_inputs",
    "write_side_isa_qualification_inputs",
]
