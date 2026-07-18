from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from ..stage_binary import StageAInputError, _parse_stage_a_pe
from ..util import sha256_bytes, sha256_file, write_json
from .artifacts import read_json_object
from .contract import _load_contract, _normalize_contract
from .extraction import (
    _normalize_raw_relational_behaviors,
    _raw_extraction_semantics_sha256,
)
from .lean import analysis_source as lean_analysis_source
from .lean.analysis_source import _copy_relational_analysis_kernel_sources
from .lean.compiler import _lean_toolchain_identity
from .pair_normalization_artifact import (
    pair_normalization_payload,
    parse_pair_normalization,
)
from .schema import (
    RELATIONAL_ANALYSIS_KERNEL_MODULES,
    STAGE_A_RELATIONAL_MODEL_ID,
)
from .side_extraction_artifact import (
    parse_request,
    request_payload,
    select_result_spans,
)


_LEAN_SOURCE_ROOT = Path(__file__).resolve().parent.parent / "lean" / "StageA"


def pair_normalization_semantics_sha256(
    *,
    lean_root: Path | None = None,
    lean_toolchain: str | None = None,
    normalizer_source_sha256: str | None = None,
    source_generator_sha256: str | None = None,
) -> str:
    root = _LEAN_SOURCE_ROOT if lean_root is None else Path(lean_root)
    payload = {
        "format": "stage-a-relational-pair-normalization-semantics-v1",
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "lean_toolchain": (
            _lean_toolchain_identity()
            if lean_toolchain is None
            else lean_toolchain
        ),
        "normalizer_source_sha256": (
            sha256_file(Path(__file__).with_name("extraction.py"))
            if normalizer_source_sha256 is None
            else normalizer_source_sha256
        ),
        "source_generator_sha256": (
            sha256_file(Path(lean_analysis_source.__file__))
            if source_generator_sha256 is None
            else source_generator_sha256
        ),
        "modules": {
            module: sha256_file(root / f"{module}.lean")
            for module in RELATIONAL_ANALYSIS_KERNEL_MODULES
        },
    }
    return sha256_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    )


def _normalization_failure(evidence: dict[str, Any]) -> StageAInputError:
    status = evidence.get("status", "unknown")
    stderr = str(evidence.get("stderr") or "").strip()
    detail = f": {stderr[-2000:]}" if stderr else ""
    return StageAInputError(
        f"Lean pair normalization failed with status {status}{detail}"
    )


def _load_side_extraction(
    *,
    path: Path,
    contract: dict[str, Any],
    side: str,
    binary_sha256: str,
) -> list[str]:
    request = parse_request(request_payload(contract, side, binary_sha256))
    return select_result_spans(
        read_json_object(Path(path)),
        expected_request=request,
        expected_decoder_semantics_sha256=(
            _raw_extraction_semantics_sha256()
        ),
    )


def stage_a_normalize_pair(
    *,
    original: Path,
    candidate: Path,
    relation_contract: Path,
    original_extraction: Path,
    candidate_extraction: Path,
    out: Path,
) -> dict[str, Any]:
    original = Path(original)
    candidate = Path(candidate)
    relation_contract = Path(relation_contract)
    original_extraction = Path(original_extraction)
    candidate_extraction = Path(candidate_extraction)
    out = Path(out)

    original_binary = _parse_stage_a_pe(original)
    candidate_binary = _parse_stage_a_pe(candidate)
    normalized, issues = _normalize_contract(
        _load_contract(relation_contract),
        original_binary,
        candidate_binary,
    )
    if issues:
        raise StageAInputError(
            "relational contract failed structural validation before pair "
            f"normalization: {issues[:3]}"
        )

    raw_behaviors = {
        (side, index): term
        for side, path, binary in (
            ("original", original_extraction, original_binary),
            ("candidate", candidate_extraction, candidate_binary),
        )
        for index, term in enumerate(
            _load_side_extraction(
                path=path,
                contract=normalized,
                side=side,
                binary_sha256=binary.sha256,
            )
        )
    }

    with tempfile.TemporaryDirectory(prefix="stage-a-pair-normalization-") as temporary:
        lean_dir = Path(temporary) / "lean"
        (lean_dir / "StageA").mkdir(parents=True)
        _copy_relational_analysis_kernel_sources(lean_dir / "StageA")
        behaviors, evidence = _normalize_raw_relational_behaviors(
            lean_dir,
            normalized,
            raw_behaviors,
        )
    if behaviors is None:
        raise _normalization_failure(evidence)

    semantics_sha256 = pair_normalization_semantics_sha256()
    payload = pair_normalization_payload(
        original_sha256=original_binary.sha256,
        candidate_sha256=candidate_binary.sha256,
        relation_contract=normalized,
        original_extraction_sha256=sha256_file(original_extraction),
        candidate_extraction_sha256=sha256_file(candidate_extraction),
        normalizer_semantics_sha256=semantics_sha256,
        behaviors=behaviors,
    )
    write_json(out, payload)
    return {
        "format": "stage-a-relational-pair-normalization-result-v1",
        "status": "normalized",
        "original_sha256": original_binary.sha256,
        "candidate_sha256": candidate_binary.sha256,
        "regions": len(behaviors),
        "packs": evidence.get("pack_count"),
        "jobs": evidence.get("jobs"),
        "out": str(out),
        "sha256": sha256_file(out),
    }


def load_pair_normalization(
    *,
    path: Path,
    normalized_contract: dict[str, Any],
    original_sha256: str,
    candidate_sha256: str,
    original_extraction: Path,
    candidate_extraction: Path,
) -> list[dict[str, Any]]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise StageAInputError(
            f"pair normalization artifact is invalid JSON: {exc}"
        ) from exc
    return parse_pair_normalization(
        payload,
        expected_original_sha256=original_sha256,
        expected_candidate_sha256=candidate_sha256,
        expected_relation_contract=normalized_contract,
        expected_original_extraction_sha256=sha256_file(
            Path(original_extraction)
        ),
        expected_candidate_extraction_sha256=sha256_file(
            Path(candidate_extraction)
        ),
        expected_normalizer_semantics_sha256=(
            pair_normalization_semantics_sha256()
        ),
    )


__all__ = [
    "load_pair_normalization",
    "pair_normalization_semantics_sha256",
    "stage_a_normalize_pair",
]
