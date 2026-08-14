"""Static round-trip qualification for generated PE32 programs.

The corpus is an untrusted regression oracle for extraction and localization.
It does not claim binary equivalence: positive cases must survive independent
lowerings and static extraction, while negative cases must produce a localized
semantic violation at the injected mutation.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from ..extraction.binary_inventory import parse_binary_cutpoint_inventory
from ..stage_binary import StageAInputError
from ..util import sha256_file, write_json
from .model import CaseManifest, ExpectedDisposition, load_corpus_manifest
from .semantic import SemanticProgram


ROUNDTRIP_CASE_RESULT_FORMAT = "stage-a-roundtrip-case-result-v2"
ROUNDTRIP_RUN_RESULT_FORMAT = "stage-a-roundtrip-run-result-v2"


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read round-trip artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageAInputError(f"round-trip artifact must be an object: {path}")
    return value


def _semantic_difference(original: SemanticProgram, candidate: SemanticProgram) -> dict[str, Any] | None:
    original_blocks = {block.id: block.to_payload() for block in original.blocks}
    candidate_blocks = {block.id: block.to_payload() for block in candidate.blocks}
    for block_id in sorted(set(original_blocks) | set(candidate_blocks)):
        if original_blocks.get(block_id) != candidate_blocks.get(block_id):
            return {
                "family": "semantic-model",
                "location_id": block_id,
                "expected": original_blocks.get(block_id),
                "observed": candidate_blocks.get(block_id),
            }
    if original.to_payload() != candidate.to_payload():
        return {
            "family": "semantic-model",
            "location_id": original.id,
            "expected": original.to_payload(),
            "observed": candidate.to_payload(),
        }
    return None


def _run_case(case: CaseManifest, root: Path) -> dict[str, Any]:
    started = time.monotonic()
    artifacts = case.verify_artifacts(root)
    original = SemanticProgram.parse(_load_object(artifacts["semantic_program"]))
    candidate = SemanticProgram.parse(_load_object(artifacts["candidate_semantic_program"]))
    original_inventory = parse_binary_cutpoint_inventory(_load_object(artifacts["original_inventory"]))
    candidate_inventory = parse_binary_cutpoint_inventory(_load_object(artifacts["candidate_inventory"]))
    frontiers: list[dict[str, Any]] = []
    if original_inventory["binary_sha256"] != sha256_file(artifacts["original_pe"]):
        frontiers.append({"family": "artifact-binding", "reason": "original inventory hash mismatch"})
    if candidate_inventory["binary_sha256"] != sha256_file(artifacts["candidate_pe"]):
        frontiers.append({"family": "artifact-binding", "reason": "candidate inventory hash mismatch"})
    if original_inventory["status"] != "pass" or candidate_inventory["status"] != "pass":
        frontiers.append({"family": "static-inventory", "reason": "an executable span was not classified"})
    difference = _semantic_difference(original, candidate)
    if frontiers:
        actual = ExpectedDisposition.INCOMPLETE
    elif difference is not None:
        actual = ExpectedDisposition.VIOLATED
    else:
        actual = ExpectedDisposition.QUALIFIED
    violation = None
    if difference is not None:
        expected_location = case.mutation.location_id if case.mutation is not None else None
        violation = {
            **difference,
            "mutation_id": case.mutation.id if case.mutation is not None else None,
            "semantic_delta": case.mutation.semantic_delta if case.mutation is not None else None,
            "expected_location_id": expected_location,
            "location_matches": expected_location == difference["location_id"],
        }
        if expected_location is not None and not violation["location_matches"]:
            frontiers.append({"family": "mutation-localization", "reason": "violation was not localized to the injected block"})
            actual = ExpectedDisposition.INCOMPLETE
    return {
        "format": ROUNDTRIP_CASE_RESULT_FORMAT,
        "case_id": case.id,
        "status": actual.value,
        "expected_disposition": case.expectation.disposition.value,
        "actual_disposition": actual.value,
        "expectation_matched": actual is case.expectation.disposition,
        "duration_seconds": round(time.monotonic() - started, 6),
        "inventories": {
            "original_regions": original_inventory["counts"]["regions"],
            "candidate_regions": candidate_inventory["counts"]["regions"],
        },
        "violation": violation,
        "frontiers": frontiers,
    }


def run_roundtrip_corpus(
    *,
    corpus: Path,
    out: Path,
    case_ids: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    """Run static qualification for all selected corpus cases."""

    corpus_path = Path(corpus).resolve()
    manifest = load_corpus_manifest(corpus_path)
    selected_ids = tuple(case_ids)
    if len(selected_ids) != len(set(selected_ids)):
        raise StageAInputError("round-trip case selector contains duplicates")
    loaded = manifest.load_cases(corpus_path.parent)
    known = {case.id for case, _root in loaded}
    missing = sorted(set(selected_ids) - known)
    if missing:
        raise StageAInputError(f"round-trip corpus has no selected cases {missing}")
    selected = [entry for entry in loaded if not selected_ids or entry[0].id in set(selected_ids)]
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for case, root in selected:
        result = _run_case(case, root)
        case_out = out / "cases" / case.id
        case_out.mkdir(parents=True, exist_ok=True)
        write_json(case_out / "result.json", result)
        results.append(result)
    matched = all(item["expectation_matched"] for item in results)
    counts = {
        disposition.value: sum(item["actual_disposition"] == disposition.value for item in results)
        for disposition in ExpectedDisposition
    }
    report = {
        "format": ROUNDTRIP_RUN_RESULT_FORMAT,
        "status": "qualified" if matched else "violated",
        "corpus": {"path": str(corpus_path), "sha256": sha256_file(corpus_path)},
        "cases": results,
        "counts": {"cases": len(results), "expectations_matched": sum(bool(item["expectation_matched"]) for item in results), **counts},
        "authority": "untrusted-static-roundtrip-regression",
    }
    write_json(out / "result.json", report)
    return report


__all__ = ["run_roundtrip_corpus"]
