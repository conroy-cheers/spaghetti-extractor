from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..errors import StageAInputError
from ..util import sha256_file, write_json
from .memory_products_format import MEMORY_PRODUCTS_FORMAT
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID


MEMORY_PRODUCTS_MANIFEST = "memory-products-manifest.json"
MEMORY_CONTRACTS_FILE = "relational-memory-contracts.json"
EXTERNAL_CALL_SITES_FILE = "relational-external-call-sites.json"
MEMORY_PRODUCTS_REQUIRED_FILES = frozenset({
    MEMORY_CONTRACTS_FILE,
    EXTERNAL_CALL_SITES_FILE,
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
class MemoryProductsManifest:
    original_sha256: str
    candidate_sha256: str
    proposal_closure_sha256: str
    register_replay_sha256: str
    register_relations_sha256: str
    relation_contract_sha256: str
    decoded_behaviors_sha256: str
    memory_contracts_sha256: str
    external_call_sites_sha256: str
    products_sha256: str

    @classmethod
    def parse(cls, payload: object) -> "MemoryProductsManifest":
        if not isinstance(payload, Mapping):
            raise StageAInputError("memory products manifest must be an object")
        fields = {
            "format", "profile", "model", "status", "acceptance_authority",
            "original_sha256", "candidate_sha256",
            "proposal_closure_sha256", "register_replay_sha256",
            "register_relations_sha256", "relation_contract_sha256",
            "decoded_behaviors_sha256", "memory_contracts_sha256",
            "external_call_sites_sha256", "products_sha256",
        }
        if set(payload) != fields:
            raise StageAInputError("memory products manifest fields do not match")
        identity = {
            "format": MEMORY_PRODUCTS_FORMAT,
            "profile": STAGE_A_RELATIONAL_PROFILE_ID,
            "model": STAGE_A_RELATIONAL_MODEL_ID,
            "status": "untrusted_proposal_requires_lean_replay",
            "acceptance_authority": False,
        }
        for field, expected in identity.items():
            if payload[field] != expected:
                raise StageAInputError(
                    f"memory products manifest {field} does not match"
                )
        digests = {
            field: _sha256(payload[field], f"memory products {field}")
            for field in (
                "original_sha256", "candidate_sha256",
                "proposal_closure_sha256", "register_replay_sha256",
                "register_relations_sha256", "relation_contract_sha256",
                "decoded_behaviors_sha256", "memory_contracts_sha256",
                "external_call_sites_sha256",
            )
        }
        body = {
            key: value for key, value in payload.items()
            if key != "products_sha256"
        }
        products_sha256 = _sha256(
            payload["products_sha256"], "memory products digest"
        )
        if products_sha256 != _canonical_sha256(body):
            raise StageAInputError("memory products digest does not match")
        return cls(**digests, products_sha256=products_sha256)


def write_memory_products_manifest(
    root: Path,
    *,
    original_sha256: str,
    candidate_sha256: str,
    proposal_closure_sha256: str,
    register_replay_sha256: str,
    register_relations_sha256: str,
    relation_contract_sha256: str,
    decoded_behaviors_sha256: str,
) -> dict[str, Any]:
    root = Path(root)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != MEMORY_PRODUCTS_MANIFEST
    }
    if actual != MEMORY_PRODUCTS_REQUIRED_FILES:
        raise StageAInputError(
            "memory products file inventory differs: "
            f"missing={sorted(MEMORY_PRODUCTS_REQUIRED_FILES - actual)}, "
            f"unexpected={sorted(actual - MEMORY_PRODUCTS_REQUIRED_FILES)}"
        )
    body = {
        "format": MEMORY_PRODUCTS_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": original_sha256,
        "candidate_sha256": candidate_sha256,
        "proposal_closure_sha256": proposal_closure_sha256,
        "register_replay_sha256": register_replay_sha256,
        "register_relations_sha256": register_relations_sha256,
        "relation_contract_sha256": relation_contract_sha256,
        "decoded_behaviors_sha256": decoded_behaviors_sha256,
        "memory_contracts_sha256": sha256_file(root / MEMORY_CONTRACTS_FILE),
        "external_call_sites_sha256": sha256_file(
            root / EXTERNAL_CALL_SITES_FILE
        ),
    }
    payload = {**body, "products_sha256": _canonical_sha256(body)}
    MemoryProductsManifest.parse(payload)
    write_json(root / MEMORY_PRODUCTS_MANIFEST, payload)
    return payload


def validate_memory_products(
    root: Path,
    *,
    expected_proposal_closure_sha256: str | None = None,
    expected_register_replay_sha256: str | None = None,
    expected_original_sha256: str | None = None,
    expected_candidate_sha256: str | None = None,
    expected_relation_contract_sha256: str | None = None,
    expected_decoded_behaviors_sha256: str | None = None,
) -> MemoryProductsManifest:
    root = Path(root)
    try:
        payload = json.loads(
            (root / MEMORY_PRODUCTS_MANIFEST).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"could not read memory products: {exc}") from exc
    manifest = MemoryProductsManifest.parse(payload)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != MEMORY_PRODUCTS_MANIFEST
    }
    if actual != MEMORY_PRODUCTS_REQUIRED_FILES:
        raise StageAInputError("memory products directory inventory changed")
    files = {
        MEMORY_CONTRACTS_FILE: manifest.memory_contracts_sha256,
        EXTERNAL_CALL_SITES_FILE: manifest.external_call_sites_sha256,
    }
    for relative, expected in files.items():
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise StageAInputError(f"memory product is missing: {relative}")
        if sha256_file(path) != expected:
            raise StageAInputError(f"memory product hash mismatch: {relative}")
    expected_fields = {
        "proposal_closure_sha256": expected_proposal_closure_sha256,
        "register_replay_sha256": expected_register_replay_sha256,
        "original_sha256": expected_original_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "relation_contract_sha256": expected_relation_contract_sha256,
        "decoded_behaviors_sha256": expected_decoded_behaviors_sha256,
    }
    for field, expected in expected_fields.items():
        if expected is not None and getattr(manifest, field) != expected:
            raise StageAInputError(f"memory products {field} does not match")
    return manifest


__all__ = [
    "EXTERNAL_CALL_SITES_FILE",
    "MEMORY_CONTRACTS_FILE",
    "MEMORY_PRODUCTS_MANIFEST",
    "MemoryProductsManifest",
    "validate_memory_products",
    "write_memory_products_manifest",
]
