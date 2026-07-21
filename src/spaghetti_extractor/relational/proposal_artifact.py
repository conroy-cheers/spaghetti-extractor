from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..errors import StageAInputError
from ..util import sha256_file, write_json
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID


RELATIONAL_PROPOSAL_FORMAT = "stage-a-relational-proposal-closure-v1"
RELATIONAL_PROPOSAL_MANIFEST = "relational-proposal-manifest.json"
RELATIONAL_PROPOSAL_REQUIRED_FILES = frozenset({
    "artifacts/original.pe",
    "artifacts/candidate.pe",
    "stage-a-interface-manifest.json",
    "relation-contract.json",
    "relational-proof-ir.json",
    "relational-decoded-behaviors.json",
    "relational-callsite-preservation.json",
    "relational-dynamic-range-flow.json",
    "relational-external-result-invariants.json",
    "relational-fixed-code-pointer-flow.json",
    "relational-import-register-invariants.json",
    "relational-import-register-seeds.json",
    "relational-indirect-call-targets.json",
    "relational-machine-import-calls.json",
    "relational-register-dataflow-graph.json",
    "relational-register-dataflow-problem-seed.json",
    "relational-register-program-dataflow-graph.json",
    "relational-register-relations.json",
    "relational-register-transfer-programs.json",
    "relational-register-transfer-table.json",
    "relational-runtime-frame-affine-viability.json",
    "relational-stack-windows.json",
    "relational-static-dynamic-pointer-slots.json",
    "relational-static-word-relations.json",
    "semantic-gaps.json",
    "trusted-base.json",
})


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RelationalProposalManifest:
    original_sha256: str
    candidate_sha256: str
    closure_sha256: str
    files: tuple[tuple[str, str], ...]

    @classmethod
    def parse(cls, payload: object) -> "RelationalProposalManifest":
        if not isinstance(payload, Mapping):
            raise StageAInputError("relational proposal manifest must be an object")
        expected_fields = {
            "format", "profile", "model", "status", "acceptance_authority",
            "original_sha256", "candidate_sha256", "files", "closure_sha256",
        }
        if set(payload) != expected_fields:
            raise StageAInputError("relational proposal manifest fields do not match")
        expected_identity = {
            "format": RELATIONAL_PROPOSAL_FORMAT,
            "profile": STAGE_A_RELATIONAL_PROFILE_ID,
            "model": STAGE_A_RELATIONAL_MODEL_ID,
            "status": "untrusted_proposal_requires_lean_replay",
            "acceptance_authority": False,
        }
        for field, expected in expected_identity.items():
            if payload[field] != expected:
                raise StageAInputError(
                    f"relational proposal manifest {field} does not match"
                )
        rows = payload["files"]
        if not isinstance(rows, list):
            raise StageAInputError("relational proposal files must be a list")
        files: list[tuple[str, str]] = []
        for row in rows:
            if not isinstance(row, Mapping) or set(row) != {"path", "sha256"}:
                raise StageAInputError("relational proposal file row is malformed")
            path = row["path"]
            digest = row["sha256"]
            if not isinstance(path, str) or not path or path.startswith("/"):
                raise StageAInputError("relational proposal file path is invalid")
            if Path(path).as_posix() != path:
                raise StageAInputError("relational proposal file path is invalid")
            if ".." in Path(path).parts:
                raise StageAInputError("relational proposal file path escapes its root")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise StageAInputError("relational proposal file digest is invalid")
            files.append((path, digest))
        if (
            files != sorted(files)
            or len(files) != len({path for path, _digest in files})
        ):
            raise StageAInputError("relational proposal files are not canonical")
        if {path for path, _digest in files} != RELATIONAL_PROPOSAL_REQUIRED_FILES:
            raise StageAInputError("relational proposal file inventory is incomplete")
        body = {key: value for key, value in payload.items() if key != "closure_sha256"}
        if payload["closure_sha256"] != _canonical_sha256(body):
            raise StageAInputError("relational proposal closure digest does not match")
        for field in ("original_sha256", "candidate_sha256"):
            value = payload[field]
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise StageAInputError(
                    f"relational proposal {field} is not a SHA-256 digest"
                )
        return cls(
            original_sha256=str(payload["original_sha256"]),
            candidate_sha256=str(payload["candidate_sha256"]),
            closure_sha256=str(payload["closure_sha256"]),
            files=tuple(files),
        )


def write_relational_proposal_manifest(
    root: Path,
    *,
    original_sha256: str,
    candidate_sha256: str,
) -> dict[str, Any]:
    root = Path(root)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != RELATIONAL_PROPOSAL_MANIFEST
    }
    if actual != RELATIONAL_PROPOSAL_REQUIRED_FILES:
        missing = sorted(RELATIONAL_PROPOSAL_REQUIRED_FILES - actual)
        unexpected = sorted(actual - RELATIONAL_PROPOSAL_REQUIRED_FILES)
        raise StageAInputError(
            "relational proposal file inventory differs: "
            f"missing={missing}, unexpected={unexpected}"
        )
    files = [
        {"path": relative, "sha256": sha256_file(root / relative)}
        for relative in sorted(actual)
    ]
    body = {
        "format": RELATIONAL_PROPOSAL_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": original_sha256,
        "candidate_sha256": candidate_sha256,
        "files": files,
    }
    payload = {**body, "closure_sha256": _canonical_sha256(body)}
    RelationalProposalManifest.parse(payload)
    write_json(root / RELATIONAL_PROPOSAL_MANIFEST, payload)
    return payload


def validate_relational_proposal(root: Path) -> RelationalProposalManifest:
    root = Path(root)
    manifest_path = root / RELATIONAL_PROPOSAL_MANIFEST
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(
            f"could not read relational proposal manifest: {exc}"
        ) from exc
    manifest = RelationalProposalManifest.parse(payload)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != RELATIONAL_PROPOSAL_MANIFEST
    }
    if actual != RELATIONAL_PROPOSAL_REQUIRED_FILES:
        raise StageAInputError("relational proposal directory inventory changed")
    for relative, expected in manifest.files:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise StageAInputError(
                f"relational proposal file is missing or not regular: {relative}"
            )
        if sha256_file(path) != expected:
            raise StageAInputError(
                f"relational proposal file hash mismatch: {relative}"
            )
    if sha256_file(root / "artifacts" / "original.pe") != manifest.original_sha256:
        raise StageAInputError("relational proposal original PE identity changed")
    if sha256_file(root / "artifacts" / "candidate.pe") != manifest.candidate_sha256:
        raise StageAInputError("relational proposal candidate PE identity changed")
    return manifest


def copy_relational_proposal(source: Path, destination: Path) -> None:
    source = Path(source)
    destination = Path(destination)
    validate_relational_proposal(source)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    for relative in sorted(RELATIONAL_PROPOSAL_REQUIRED_FILES):
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
    shutil.copyfile(
        source / RELATIONAL_PROPOSAL_MANIFEST,
        destination / RELATIONAL_PROPOSAL_MANIFEST,
    )
    validate_relational_proposal(destination)


__all__ = [
    "RELATIONAL_PROPOSAL_FORMAT",
    "RELATIONAL_PROPOSAL_MANIFEST",
    "RELATIONAL_PROPOSAL_REQUIRED_FILES",
    "RelationalProposalManifest",
    "copy_relational_proposal",
    "validate_relational_proposal",
    "write_relational_proposal_manifest",
]
