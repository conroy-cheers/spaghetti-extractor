from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..errors import StageAInputError
from ..util import sha256_file, write_json
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID
from .semantic_products_format import SEMANTIC_PRODUCTS_FORMAT


SEMANTIC_PRODUCTS_MANIFEST = "semantic-products-manifest.json"
SEMANTIC_IR_FILE = "relational-semantic-ir.json"
INVARIANTS_FILE = "relational-invariants.json"
SEMANTIC_PRODUCTS_REQUIRED_FILES = frozenset({
    SEMANTIC_IR_FILE,
    INVARIANTS_FILE,
})
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
class SemanticProductsManifest:
    original_sha256: str
    candidate_sha256: str
    proposal_closure_sha256: str
    relation_contract_sha256: str
    decoded_behaviors_sha256: str
    semantic_ir_sha256: str
    invariants_sha256: str
    products_sha256: str

    @classmethod
    def parse(cls, payload: object) -> "SemanticProductsManifest":
        if not isinstance(payload, Mapping):
            raise StageAInputError("semantic products manifest must be an object")
        fields = {
            "format", "profile", "model", "status", "acceptance_authority",
            "original_sha256", "candidate_sha256",
            "proposal_closure_sha256", "relation_contract_sha256",
            "decoded_behaviors_sha256", "semantic_ir_sha256",
            "invariants_sha256", "products_sha256",
        }
        if set(payload) != fields:
            raise StageAInputError("semantic products manifest fields do not match")
        identity = {
            "format": SEMANTIC_PRODUCTS_FORMAT,
            "profile": STAGE_A_RELATIONAL_PROFILE_ID,
            "model": STAGE_A_RELATIONAL_MODEL_ID,
            "status": "untrusted_proposal_requires_lean_replay",
            "acceptance_authority": False,
        }
        for field, expected in identity.items():
            if payload[field] != expected:
                raise StageAInputError(
                    f"semantic products manifest {field} does not match"
                )
        digests = {
            field: _sha256(payload[field], f"semantic products {field}")
            for field in (
                "original_sha256", "candidate_sha256",
                "proposal_closure_sha256", "relation_contract_sha256",
                "decoded_behaviors_sha256", "semantic_ir_sha256",
                "invariants_sha256",
            )
        }
        body = {
            key: value for key, value in payload.items()
            if key != "products_sha256"
        }
        products_sha256 = _sha256(
            payload["products_sha256"], "semantic products digest"
        )
        if products_sha256 != _canonical_sha256(body):
            raise StageAInputError("semantic products digest does not match")
        return cls(**digests, products_sha256=products_sha256)


def write_semantic_products_manifest(
    root: Path,
    *,
    original_sha256: str,
    candidate_sha256: str,
    proposal_closure_sha256: str,
    relation_contract_sha256: str,
    decoded_behaviors_sha256: str,
) -> dict[str, Any]:
    root = Path(root)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != SEMANTIC_PRODUCTS_MANIFEST
    }
    if actual != SEMANTIC_PRODUCTS_REQUIRED_FILES:
        raise StageAInputError(
            "semantic products file inventory differs: "
            f"missing={sorted(SEMANTIC_PRODUCTS_REQUIRED_FILES - actual)}, "
            f"unexpected={sorted(actual - SEMANTIC_PRODUCTS_REQUIRED_FILES)}"
        )
    body = {
        "format": SEMANTIC_PRODUCTS_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": original_sha256,
        "candidate_sha256": candidate_sha256,
        "proposal_closure_sha256": proposal_closure_sha256,
        "relation_contract_sha256": relation_contract_sha256,
        "decoded_behaviors_sha256": decoded_behaviors_sha256,
        "semantic_ir_sha256": sha256_file(root / SEMANTIC_IR_FILE),
        "invariants_sha256": sha256_file(root / INVARIANTS_FILE),
    }
    payload = {**body, "products_sha256": _canonical_sha256(body)}
    SemanticProductsManifest.parse(payload)
    write_json(root / SEMANTIC_PRODUCTS_MANIFEST, payload)
    return payload


def validate_semantic_products(
    root: Path,
    *,
    expected_proposal_closure_sha256: str | None = None,
    expected_original_sha256: str | None = None,
    expected_candidate_sha256: str | None = None,
    expected_relation_contract_sha256: str | None = None,
    expected_decoded_behaviors_sha256: str | None = None,
) -> SemanticProductsManifest:
    root = Path(root)
    try:
        payload = json.loads(
            (root / SEMANTIC_PRODUCTS_MANIFEST).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"could not read semantic products: {exc}") from exc
    manifest = SemanticProductsManifest.parse(payload)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != SEMANTIC_PRODUCTS_MANIFEST
    }
    if actual != SEMANTIC_PRODUCTS_REQUIRED_FILES:
        raise StageAInputError("semantic products directory inventory changed")
    file_hashes = {
        SEMANTIC_IR_FILE: manifest.semantic_ir_sha256,
        INVARIANTS_FILE: manifest.invariants_sha256,
    }
    for relative, expected in file_hashes.items():
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise StageAInputError(f"semantic product is missing: {relative}")
        if sha256_file(path) != expected:
            raise StageAInputError(f"semantic product hash mismatch: {relative}")
    expected_fields = {
        "proposal_closure_sha256": expected_proposal_closure_sha256,
        "original_sha256": expected_original_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "relation_contract_sha256": expected_relation_contract_sha256,
        "decoded_behaviors_sha256": expected_decoded_behaviors_sha256,
    }
    for field, expected in expected_fields.items():
        if expected is not None and getattr(manifest, field) != expected:
            raise StageAInputError(f"semantic products {field} does not match")
    return manifest


__all__ = [
    "INVARIANTS_FILE",
    "SEMANTIC_IR_FILE",
    "SEMANTIC_PRODUCTS_MANIFEST",
    "SemanticProductsManifest",
    "validate_semantic_products",
    "write_semantic_products_manifest",
]
