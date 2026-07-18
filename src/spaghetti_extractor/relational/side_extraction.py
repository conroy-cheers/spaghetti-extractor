from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from ..stage_binary import StageAInputError, _parse_stage_a_pe
from ..util import sha256_file, write_json
from .artifacts import read_json_object
from .binary_inventory import (
    parse_binary_cutpoint_inventory,
    side_extraction_request_from_inventory,
)
from .contract import _load_contract
from .extraction import (
    _extract_raw_side_behaviors,
    _raw_extraction_semantics_sha256,
)
from .lean.analysis_source import _copy_relational_analysis_kernel_sources
from .isa_requirements import (
    _lean_form_source_hashes,
    extract_lean_instruction_forms_side,
)
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID
from .side_extraction_artifact import (
    parse_request,
    parse_result,
    parse_result_unbound,
    request_payload,
    result_payload,
    select_result_spans,
)
from .side_isa_artifact import (
    select_side_isa_spans,
    side_isa_payload,
)


def stage_a_project_side_extraction_request(
    *,
    binary: Path,
    side: str,
    relation_contract: Path,
    out: Path,
) -> dict[str, Any]:
    binary = Path(binary)
    parsed_binary = _parse_stage_a_pe(binary)
    contract = _load_contract(Path(relation_contract))
    payload = request_payload(contract, side, parsed_binary.sha256)
    write_json(Path(out), payload)
    return {
        "format": "stage-a-relational-side-extraction-request-result-v1",
        "status": "generated",
        "side": side,
        "binary_sha256": parsed_binary.sha256,
        "out": str(out),
        "sha256": sha256_file(Path(out)),
    }


def stage_a_project_inventory_extraction_request(
    *,
    inventory: Path,
    scope: str = "base",
    out: Path,
) -> dict[str, Any]:
    inventory = Path(inventory)
    payload = side_extraction_request_from_inventory(
        read_json_object(inventory), scope=scope
    )
    write_json(Path(out), payload)
    parsed = parse_request(payload)
    return {
        "format": "stage-a-relational-side-extraction-request-result-v1",
        "status": "generated",
        "side": parsed.side,
        "binary_sha256": parsed.binary_sha256,
        "regions": len(parsed.regions),
        "scope": scope,
        "inventory_sha256": sha256_file(inventory),
        "out": str(out),
        "sha256": sha256_file(Path(out)),
    }


def stage_a_project_missing_side_extraction_request(
    *,
    binary: Path,
    side: str,
    relation_contract: Path,
    inventory: Path,
    out: Path,
) -> dict[str, Any]:
    binary = Path(binary)
    parsed_binary = _parse_stage_a_pe(binary)
    parsed_inventory = parse_binary_cutpoint_inventory(
        read_json_object(Path(inventory))
    )
    if parsed_inventory["status"] != "pass":
        raise StageAInputError(
            "incomplete binary inventory cannot authorize supplementary extraction"
        )
    if parsed_inventory["side"] != side:
        raise StageAInputError("binary inventory side mismatch")
    if parsed_inventory["binary_sha256"] != parsed_binary.sha256:
        raise StageAInputError("binary inventory hash mismatch")
    contract = _load_contract(Path(relation_contract))
    pair_request = parse_request(
        request_payload(contract, side, parsed_binary.sha256)
    )
    base_spans = {
        (int(region["span"]["rva_start"]), int(region["span"]["size"]))
        for region in parsed_inventory["regions"]
    }
    missing = [
        region
        for region in pair_request.regions
        if (region.span.rva_start, region.span.size) not in base_spans
    ]
    payload = parse_request({
        "format": pair_request.format,
        "profile": pair_request.profile,
        "model": pair_request.model,
        "side": side,
        "binary_sha256": parsed_binary.sha256,
        "regions": [
            {
                "index": index,
                "id": f"{side}-supplement-{region.span.rva_start:08x}-{region.span.size:08x}",
                "numeric_id": index,
                "span": region.span.to_payload(),
            }
            for index, region in enumerate(missing)
        ],
    }).to_payload()
    write_json(Path(out), payload)
    return {
        "format": "stage-a-relational-side-extraction-request-result-v1",
        "status": "generated",
        "side": side,
        "binary_sha256": parsed_binary.sha256,
        "regions": len(missing),
        "scope": "pair_supplement",
        "inventory_sha256": sha256_file(Path(inventory)),
        "relation_contract_sha256": sha256_file(Path(relation_contract)),
        "out": str(out),
        "sha256": sha256_file(Path(out)),
    }


def stage_a_merge_side_extractions(
    *,
    binary: Path,
    side: str,
    inputs: list[Path],
    out: Path,
) -> dict[str, Any]:
    if side not in {"original", "candidate"}:
        raise StageAInputError("side extraction merge side is invalid")
    if not inputs:
        raise StageAInputError("side extraction merge requires inputs")
    parsed_binary = _parse_stage_a_pe(Path(binary))
    decoder_semantics_sha256 = _raw_extraction_semantics_sha256()
    terms_by_span: dict[tuple[int, int], tuple[str, str]] = {}
    for input_path in map(Path, inputs):
        request, terms = parse_result_unbound(
            read_json_object(input_path),
            expected_side=side,
            expected_binary_sha256=parsed_binary.sha256,
            expected_decoder_semantics_sha256=decoder_semantics_sha256,
        )
        for region, term in zip(request.regions, terms, strict=True):
            key = (region.span.rva_start, region.span.size)
            if key in terms_by_span:
                raise StageAInputError(
                    f"side extraction merge duplicates span {key[0]:#x}+{key[1]}"
                )
            terms_by_span[key] = (region.id, term)
    ordered = sorted(terms_by_span.items())
    merged_request = parse_request({
        "format": "stage-a-relational-side-extraction-request-v1",
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "side": side,
        "binary_sha256": parsed_binary.sha256,
        "regions": [
            {
                "index": index,
                "id": f"{side}-merged-{start:08x}-{size:08x}",
                "numeric_id": index,
                "span": {"rva_start": start, "size": size},
            }
            for index, ((start, size), _) in enumerate(ordered)
        ],
    })
    payload = result_payload(
        merged_request,
        decoder_semantics_sha256,
        [value[1] for _, value in ordered],
    )
    write_json(Path(out), payload)
    return {
        "format": "stage-a-relational-side-extraction-result-v1",
        "status": "extracted",
        "side": side,
        "binary_sha256": parsed_binary.sha256,
        "regions": len(ordered),
        "inputs": [sha256_file(Path(path)) for path in inputs],
        "out": str(out),
        "sha256": sha256_file(Path(out)),
    }


def stage_a_extract_side(
    *,
    binary: Path,
    request: Path,
    out: Path,
) -> dict[str, Any]:
    binary = Path(binary)
    parsed_binary = _parse_stage_a_pe(binary)
    parsed_request = parse_request(read_json_object(Path(request)))
    if parsed_request.binary_sha256 != parsed_binary.sha256:
        raise StageAInputError("side extraction request binary hash mismatch")
    decoder_semantics_sha256 = _raw_extraction_semantics_sha256()
    with tempfile.TemporaryDirectory(
        prefix=f"stage-a-{parsed_request.side}-extraction-"
    ) as temporary:
        lean_dir = Path(temporary) / "lean"
        _copy_relational_analysis_kernel_sources(lean_dir / "StageA")
        terms, extraction = _extract_raw_side_behaviors(
            lean_dir,
            parsed_binary,
            binary.read_bytes(),
            parsed_request.to_payload(),
            use_cache=True,
        )
    if terms is None:
        raise StageAInputError(
            f"{parsed_request.side} raw extraction failed: "
            + str(extraction.get("stderr") or extraction.get("stdout"))
        )
    observed_decoder = extraction.get("decoder_semantics_sha256")
    if observed_decoder != decoder_semantics_sha256:
        raise StageAInputError("side extraction decoder semantics identity changed")
    payload = result_payload(
        parsed_request,
        decoder_semantics_sha256,
        terms,
    )
    write_json(Path(out), payload)
    parse_result(
        read_json_object(Path(out)),
        expected_request=parsed_request,
        expected_decoder_semantics_sha256=decoder_semantics_sha256,
    )
    return {
        "format": "stage-a-relational-side-extraction-result-v1",
        "status": "extracted",
        "side": parsed_request.side,
        "binary_sha256": parsed_binary.sha256,
        "regions": len(terms),
        "decoder_semantics_sha256": decoder_semantics_sha256,
        "cache": {
            "hits": extraction.get("cache_hits", 0),
            "misses": extraction.get("cache_misses", 0),
        },
        "out": str(out),
        "sha256": sha256_file(Path(out)),
    }


def stage_a_extract_side_isa(
    *,
    binary: Path,
    request: Path,
    out: Path,
) -> dict[str, Any]:
    binary = Path(binary)
    parsed_binary = _parse_stage_a_pe(binary)
    parsed_request = parse_request(read_json_object(Path(request)))
    if parsed_request.binary_sha256 != parsed_binary.sha256:
        raise StageAInputError("side ISA extraction request binary hash mismatch")
    forms, evidence = extract_lean_instruction_forms_side(
        binary=binary,
        request=parsed_request.to_payload(),
    )
    hashes = _lean_form_source_hashes()
    payload = side_isa_payload(
        parsed_request,
        forms=forms,
        classifier_sha256=hashes["classifier_sha256"],
        extractor_sha256=hashes["extractor_sha256"],
        source_sha256=hashes["source_sha256"],
    )
    write_json(Path(out), payload)
    return {
        "format": "stage-a-relational-side-isa-result-v1",
        "status": "extracted",
        "side": parsed_request.side,
        "binary_sha256": parsed_binary.sha256,
        "regions": len(parsed_request.regions),
        "cache": evidence.get("cache"),
        "out": str(out),
        "sha256": sha256_file(Path(out)),
    }


def load_side_extraction(
    *,
    path: Path,
    contract: dict[str, Any],
    side: str,
    binary_sha256: str,
) -> list[str]:
    request = parse_request(request_payload(contract, side, binary_sha256))
    decoder_semantics_sha256 = _raw_extraction_semantics_sha256()
    return select_result_spans(
        read_json_object(Path(path)),
        expected_request=request,
        expected_decoder_semantics_sha256=decoder_semantics_sha256,
    )


def load_side_isa(
    *,
    path: Path,
    contract: dict[str, Any],
    side: str,
    binary_sha256: str,
) -> dict[tuple[str, int], tuple[dict[str, Any], ...]]:
    request = parse_request(request_payload(contract, side, binary_sha256))
    hashes = _lean_form_source_hashes()
    return select_side_isa_spans(
        read_json_object(Path(path)),
        expected_request=request,
        classifier_sha256=hashes["classifier_sha256"],
        extractor_sha256=hashes["extractor_sha256"],
        source_sha256=hashes["source_sha256"],
    )


__all__ = [
    "load_side_extraction",
    "load_side_isa",
    "stage_a_extract_side",
    "stage_a_extract_side_isa",
    "stage_a_merge_side_extractions",
    "stage_a_project_inventory_extraction_request",
    "stage_a_project_missing_side_extraction_request",
    "stage_a_project_side_extraction_request",
]
