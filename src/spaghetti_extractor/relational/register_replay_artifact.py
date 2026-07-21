from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..errors import StageAInputError
from ..util import sha256_file, write_json
from .register_replay_format import REGISTER_REPLAY_FORMAT
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID


REGISTER_REPLAY_MANIFEST = "register-replay-manifest.json"
REGISTER_REPLAY_RELATIONS = "relational-register-relations.json"
REGISTER_REPLAY_REQUIRED_FILES = frozenset({REGISTER_REPLAY_RELATIONS})
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def _sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be a SHA-256 digest")
    return value


@dataclass(frozen=True)
class RegisterReplayManifest:
    original_sha256: str
    candidate_sha256: str
    proposal_closure_sha256: str
    aggregate_sha256: str
    aggregate_file_sha256: str
    register_relations_sha256: str
    replay_sha256: str

    @classmethod
    def parse(cls, payload: object) -> "RegisterReplayManifest":
        if not isinstance(payload, Mapping):
            raise StageAInputError("register replay manifest must be an object")
        expected_fields = {
            "format", "profile", "model", "status", "acceptance_authority",
            "original_sha256", "candidate_sha256",
            "proposal_closure_sha256", "aggregate_sha256",
            "aggregate_file_sha256", "register_relations_sha256",
            "replay_sha256",
        }
        if set(payload) != expected_fields:
            raise StageAInputError("register replay manifest fields do not match")
        expected_identity = {
            "format": REGISTER_REPLAY_FORMAT,
            "profile": STAGE_A_RELATIONAL_PROFILE_ID,
            "model": STAGE_A_RELATIONAL_MODEL_ID,
            "status": "untrusted_proposal_requires_lean_replay",
            "acceptance_authority": False,
        }
        for field, expected in expected_identity.items():
            if payload[field] != expected:
                raise StageAInputError(
                    f"register replay manifest {field} does not match"
                )
        digests = {
            field: _sha256(payload[field], f"register replay {field}")
            for field in (
                "original_sha256", "candidate_sha256",
                "proposal_closure_sha256", "aggregate_sha256",
                "aggregate_file_sha256", "register_relations_sha256",
            )
        }
        body = {key: value for key, value in payload.items() if key != "replay_sha256"}
        replay_sha256 = _sha256(
            payload["replay_sha256"], "register replay digest"
        )
        if replay_sha256 != _canonical_sha256(body):
            raise StageAInputError("register replay digest does not match")
        return cls(**digests, replay_sha256=replay_sha256)


def write_register_replay_manifest(
    root: Path,
    *,
    original_sha256: str,
    candidate_sha256: str,
    proposal_closure_sha256: str,
    aggregate_sha256: str,
    aggregate_file_sha256: str,
) -> dict[str, Any]:
    root = Path(root)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != REGISTER_REPLAY_MANIFEST
    }
    if actual != REGISTER_REPLAY_REQUIRED_FILES:
        raise StageAInputError(
            "register replay file inventory differs: "
            f"missing={sorted(REGISTER_REPLAY_REQUIRED_FILES - actual)}, "
            f"unexpected={sorted(actual - REGISTER_REPLAY_REQUIRED_FILES)}"
        )
    body = {
        "format": REGISTER_REPLAY_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": original_sha256,
        "candidate_sha256": candidate_sha256,
        "proposal_closure_sha256": proposal_closure_sha256,
        "aggregate_sha256": aggregate_sha256,
        "aggregate_file_sha256": aggregate_file_sha256,
        "register_relations_sha256": sha256_file(
            root / REGISTER_REPLAY_RELATIONS
        ),
    }
    payload = {**body, "replay_sha256": _canonical_sha256(body)}
    RegisterReplayManifest.parse(payload)
    write_json(root / REGISTER_REPLAY_MANIFEST, payload)
    return payload


def validate_register_replay(
    root: Path,
    *,
    expected_proposal_closure_sha256: str | None = None,
    expected_original_sha256: str | None = None,
    expected_candidate_sha256: str | None = None,
) -> RegisterReplayManifest:
    root = Path(root)
    try:
        payload = json.loads(
            (root / REGISTER_REPLAY_MANIFEST).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"could not read register replay manifest: {exc}") from exc
    manifest = RegisterReplayManifest.parse(payload)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != REGISTER_REPLAY_MANIFEST
    }
    if actual != REGISTER_REPLAY_REQUIRED_FILES:
        raise StageAInputError("register replay directory inventory changed")
    relations = root / REGISTER_REPLAY_RELATIONS
    if relations.is_symlink() or not relations.is_file():
        raise StageAInputError("register replay relations are missing or not regular")
    if sha256_file(relations) != manifest.register_relations_sha256:
        raise StageAInputError("register replay relations hash mismatch")
    expected = {
        "proposal_closure_sha256": expected_proposal_closure_sha256,
        "original_sha256": expected_original_sha256,
        "candidate_sha256": expected_candidate_sha256,
    }
    for field, value in expected.items():
        if value is not None and getattr(manifest, field) != value:
            raise StageAInputError(f"register replay {field} does not match")
    return manifest


__all__ = [
    "REGISTER_REPLAY_FORMAT",
    "REGISTER_REPLAY_MANIFEST",
    "REGISTER_REPLAY_RELATIONS",
    "RegisterReplayManifest",
    "validate_register_replay",
    "write_register_replay_manifest",
]
