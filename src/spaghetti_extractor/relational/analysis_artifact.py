from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..stage_binary import StageAInputError
from ..util import sha256_bytes, sha256_file, write_json
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID


RELATIONAL_ANALYSIS_FORMAT = "stage-a-relational-analysis-v1"
RELATIONAL_DECODED_BEHAVIORS_FORMAT = (
    "stage-a-relational-decoded-behaviors-v1"
)
RELATIONAL_SEGMENT_CANDIDATES_FORMAT = (
    "stage-a-relational-segment-candidates-v1"
)
RELATIONAL_ANALYSIS_MANIFEST = "relational-analysis-manifest.json"
RELATIONAL_ANALYSIS_REQUIRED_FILES = frozenset({
    "artifacts/original.pe",
    "artifacts/candidate.pe",
    "stage-a-interface-manifest.json",
    "relation-contract.json",
    "relational-proof-ir.json",
    "relational-decoded-behaviors.json",
    "relational-segment-candidates.json",
    "relational-semantic-ir.json",
    "relational-memory-contracts.json",
    "relational-static-word-relations.json",
    "relational-register-relations.json",
    "relational-register-dataflow-graph.json",
    "relational-stack-windows.json",
    "relational-segment-diagnostics.json",
    "relational-product-graph.json",
    "relational-invariants.json",
    "relational-machine-import-calls.json",
    "relational-external-call-sites.json",
    "relational-import-register-invariants.json",
    "relational-import-register-seeds.json",
    "isa-requirements.json",
    "semantic-gaps.json",
    "trusted-base.json",
})


def _json_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    )


def decoded_behaviors_payload(
    *,
    original_sha256: str,
    candidate_sha256: str,
    relation_contract_sha256: str,
    behaviors: list[dict[str, Any]],
) -> dict[str, Any]:
    payload = {
        "format": RELATIONAL_DECODED_BEHAVIORS_FORMAT,
        "status": "untrusted_proposal_requires_lean_decode_replay",
        "original_sha256": original_sha256,
        "candidate_sha256": candidate_sha256,
        "relation_contract_sha256": relation_contract_sha256,
        "regions": [
            {
                "index": index,
                "original_term": row.get("original"),
                "candidate_term": row.get("candidate"),
                "original_ir": row.get("original_ir"),
                "candidate_ir": row.get("candidate_ir"),
                "original_ir_sha256": _json_sha256(row.get("original_ir")),
                "candidate_ir_sha256": _json_sha256(row.get("candidate_ir")),
            }
            for index, row in enumerate(behaviors)
        ],
    }
    parse_decoded_behaviors(
        payload,
        expected_original_sha256=original_sha256,
        expected_candidate_sha256=candidate_sha256,
        expected_relation_contract_sha256=relation_contract_sha256,
        expected_region_count=len(behaviors),
    )
    return payload


def parse_decoded_behaviors(
    payload: Mapping[str, Any],
    *,
    expected_original_sha256: str,
    expected_candidate_sha256: str,
    expected_relation_contract_sha256: str,
    expected_region_count: int,
) -> list[dict[str, Any]]:
    if payload.get("format") != RELATIONAL_DECODED_BEHAVIORS_FORMAT:
        raise StageAInputError("unsupported decoded behavior artifact format")
    if payload.get("status") != "untrusted_proposal_requires_lean_decode_replay":
        raise StageAInputError("decoded behavior artifact has invalid status")
    expected_identities = {
        "original_sha256": expected_original_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "relation_contract_sha256": expected_relation_contract_sha256,
    }
    for field, expected in expected_identities.items():
        if payload.get(field) != expected:
            raise StageAInputError(f"decoded behavior {field} mismatch")
    regions = payload.get("regions")
    if not isinstance(regions, list) or len(regions) != expected_region_count:
        raise StageAInputError("decoded behavior count does not match the contract")
    behaviors: list[dict[str, Any]] = []
    for index, row in enumerate(regions):
        if not isinstance(row, Mapping) or row.get("index") != index:
            raise StageAInputError("decoded behavior region indices are not canonical")
        original_term = row.get("original_term")
        candidate_term = row.get("candidate_term")
        original_ir = row.get("original_ir")
        candidate_ir = row.get("candidate_ir")
        if not isinstance(original_term, str) or not original_term:
            raise StageAInputError("decoded original behavior term is missing")
        if not isinstance(candidate_term, str) or not candidate_term:
            raise StageAInputError("decoded candidate behavior term is missing")
        if not isinstance(original_ir, Mapping) or not isinstance(
            candidate_ir, Mapping
        ):
            raise StageAInputError("decoded behavior semantic IR is malformed")
        if row.get("original_ir_sha256") != _json_sha256(original_ir):
            raise StageAInputError("decoded original semantic IR hash mismatch")
        if row.get("candidate_ir_sha256") != _json_sha256(candidate_ir):
            raise StageAInputError("decoded candidate semantic IR hash mismatch")
        behaviors.append({
            "original": original_term,
            "candidate": candidate_term,
            "original_ir": dict(original_ir),
            "candidate_ir": dict(candidate_ir),
        })
    return behaviors


def segment_candidates_payload(
    *,
    candidates: list[dict[str, Any]],
    diagnostics_sha256: str,
    product_graph_sha256: str,
) -> dict[str, Any]:
    payload = {
        "format": RELATIONAL_SEGMENT_CANDIDATES_FORMAT,
        "status": "untrusted_proposal_requires_lean_refinement_replay",
        "diagnostics_sha256": diagnostics_sha256,
        "product_graph_sha256": product_graph_sha256,
        "candidates": candidates,
    }
    parse_segment_candidates(
        payload,
        expected_diagnostics_sha256=diagnostics_sha256,
        expected_product_graph_sha256=product_graph_sha256,
    )
    return payload


def parse_segment_candidates(
    payload: Mapping[str, Any],
    *,
    expected_diagnostics_sha256: str,
    expected_product_graph_sha256: str,
) -> list[dict[str, Any]]:
    if payload.get("format") != RELATIONAL_SEGMENT_CANDIDATES_FORMAT:
        raise StageAInputError("unsupported segment candidate artifact format")
    if payload.get("status") != (
        "untrusted_proposal_requires_lean_refinement_replay"
    ):
        raise StageAInputError("segment candidate artifact has invalid status")
    if payload.get("diagnostics_sha256") != expected_diagnostics_sha256:
        raise StageAInputError("segment candidate diagnostics hash mismatch")
    if payload.get("product_graph_sha256") != expected_product_graph_sha256:
        raise StageAInputError("segment candidate product graph hash mismatch")
    rows = payload.get("candidates")
    if not isinstance(rows, list):
        raise StageAInputError("segment candidate artifact is malformed")
    edge_ids: list[int] = []
    candidates: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise StageAInputError("segment candidate row is malformed")
        edge_id = row.get("edge_index")
        if not isinstance(edge_id, int) or isinstance(edge_id, bool) or edge_id < 0:
            raise StageAInputError("segment candidate edge index is invalid")
        edge_ids.append(edge_id)
        candidates.append(dict(row))
    if len(edge_ids) != len(set(edge_ids)):
        raise StageAInputError("segment candidate edge indices are ambiguous")
    return candidates


def _artifact_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError("analysis artifact path must be a nonempty string")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise StageAInputError(f"invalid analysis artifact path: {value!r}")
    return value


@dataclass(frozen=True)
class RelationalAnalysisManifest:
    original_sha256: str
    candidate_sha256: str
    files: Mapping[str, str]

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "RelationalAnalysisManifest":
        if payload.get("format") != RELATIONAL_ANALYSIS_FORMAT:
            raise StageAInputError("unsupported relational analysis artifact format")
        if payload.get("profile") != STAGE_A_RELATIONAL_PROFILE_ID:
            raise StageAInputError("relational analysis profile mismatch")
        if payload.get("model") != STAGE_A_RELATIONAL_MODEL_ID:
            raise StageAInputError("relational analysis model mismatch")
        original_sha256 = payload.get("original_sha256")
        candidate_sha256 = payload.get("candidate_sha256")
        if not isinstance(original_sha256, str) or len(original_sha256) != 64:
            raise StageAInputError("analysis original hash is invalid")
        if not isinstance(candidate_sha256, str) or len(candidate_sha256) != 64:
            raise StageAInputError("analysis candidate hash is invalid")
        rows = payload.get("files")
        if not isinstance(rows, list):
            raise StageAInputError("analysis manifest files must be a list")
        files: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, Mapping) or set(row) != {"path", "sha256"}:
                raise StageAInputError("analysis manifest file row is malformed")
            relative = _artifact_relative_path(row["path"])
            digest = row["sha256"]
            if not isinstance(digest, str) or len(digest) != 64:
                raise StageAInputError(
                    f"analysis artifact hash is invalid for {relative}"
                )
            if relative in files:
                raise StageAInputError(
                    f"analysis artifact path is duplicated: {relative}"
                )
            files[relative] = digest
        missing = sorted(RELATIONAL_ANALYSIS_REQUIRED_FILES - files.keys())
        if missing:
            raise StageAInputError(
                "analysis manifest is missing required files: " + ", ".join(missing)
            )
        return cls(
            original_sha256=original_sha256,
            candidate_sha256=candidate_sha256,
            files=files,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": RELATIONAL_ANALYSIS_FORMAT,
            "status": "analyzed",
            "profile": STAGE_A_RELATIONAL_PROFILE_ID,
            "model": STAGE_A_RELATIONAL_MODEL_ID,
            "original_sha256": self.original_sha256,
            "candidate_sha256": self.candidate_sha256,
            "files": [
                {"path": path, "sha256": digest}
                for path, digest in sorted(self.files.items())
            ],
        }


def write_relational_analysis_manifest(
    root: Path, *, original_sha256: str, candidate_sha256: str
) -> dict[str, Any]:
    root = Path(root)
    files = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and RELATIONAL_ANALYSIS_MANIFEST not in path.parts
        and "lean" not in path.relative_to(root).parts
        and "certificates" not in path.relative_to(root).parts
    }
    manifest = RelationalAnalysisManifest(
        original_sha256=original_sha256,
        candidate_sha256=candidate_sha256,
        files=files,
    )
    RelationalAnalysisManifest.parse(manifest.to_payload())
    payload = manifest.to_payload()
    write_json(root / RELATIONAL_ANALYSIS_MANIFEST, payload)
    return payload


def validate_relational_analysis(root: Path) -> RelationalAnalysisManifest:
    root = Path(root)
    manifest_path = root / RELATIONAL_ANALYSIS_MANIFEST
    if not manifest_path.is_file():
        raise StageAInputError("relational analysis manifest is missing")
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise StageAInputError("relational analysis manifest must be an object")
    manifest = RelationalAnalysisManifest.parse(payload)
    for relative, expected in manifest.files.items():
        path = root / relative
        if not path.is_file() or path.is_symlink():
            raise StageAInputError(f"analysis artifact file is missing: {relative}")
        observed = sha256_file(path)
        if observed != expected:
            raise StageAInputError(f"analysis artifact hash mismatch: {relative}")
    if sha256_file(root / "artifacts" / "original.pe") != manifest.original_sha256:
        raise StageAInputError("analysis original binary hash mismatch")
    if sha256_file(root / "artifacts" / "candidate.pe") != manifest.candidate_sha256:
        raise StageAInputError("analysis candidate binary hash mismatch")
    return manifest


def copy_relational_analysis(source: Path, destination: Path) -> None:
    source = Path(source)
    destination = Path(destination)
    manifest = validate_relational_analysis(source)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for relative in manifest.files:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
    shutil.copyfile(
        source / RELATIONAL_ANALYSIS_MANIFEST,
        destination / RELATIONAL_ANALYSIS_MANIFEST,
    )
    validate_relational_analysis(destination)
