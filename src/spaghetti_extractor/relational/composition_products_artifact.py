from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..errors import StageAInputError
from ..util import sha256_file, write_json
from .composition_products_format import COMPOSITION_PRODUCTS_FORMAT
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID


COMPOSITION_PRODUCTS_MANIFEST = "composition-products-manifest.json"
COMPOSITION_PRODUCTS_REQUIRED_FILES = frozenset({
    "relational-proof-ir.json",
    "relational-bounded-table-call-inputs.json",
    "relational-segment-diagnostics.json",
    "relational-product-graph.json",
    "isa-requirements.json",
    "relational-segment-candidates.json",
    "relational-runtime-frame-affine-viability.json",
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
class CompositionProductsManifest:
    original_sha256: str
    candidate_sha256: str
    proposal_closure_sha256: str
    register_replay_sha256: str
    semantic_products_sha256: str
    memory_products_sha256: str
    isa_mode: str
    original_isa_sha256: str | None
    candidate_isa_sha256: str | None
    files: tuple[tuple[str, str], ...]
    products_sha256: str

    @classmethod
    def parse(cls, payload: object) -> "CompositionProductsManifest":
        if not isinstance(payload, Mapping):
            raise StageAInputError("composition products manifest must be an object")
        fields = {
            "format", "profile", "model", "status", "acceptance_authority",
            "original_sha256", "candidate_sha256",
            "proposal_closure_sha256", "register_replay_sha256",
            "semantic_products_sha256", "memory_products_sha256",
            "isa_mode", "original_isa_sha256", "candidate_isa_sha256",
            "files", "products_sha256",
        }
        if set(payload) != fields:
            raise StageAInputError(
                "composition products manifest fields do not match"
            )
        identity = {
            "format": COMPOSITION_PRODUCTS_FORMAT,
            "profile": STAGE_A_RELATIONAL_PROFILE_ID,
            "model": STAGE_A_RELATIONAL_MODEL_ID,
            "status": "untrusted_proposal_requires_lean_replay",
            "acceptance_authority": False,
        }
        for field, expected in identity.items():
            if payload[field] != expected:
                raise StageAInputError(
                    f"composition products manifest {field} does not match"
                )
        digests = {
            field: _sha256(payload[field], f"composition products {field}")
            for field in (
                "original_sha256", "candidate_sha256",
                "proposal_closure_sha256", "register_replay_sha256",
                "semantic_products_sha256", "memory_products_sha256",
            )
        }
        isa_mode = payload["isa_mode"]
        if isa_mode not in {"side_artifacts", "lean_extracted"}:
            raise StageAInputError("composition products ISA mode is invalid")
        isa_values = (
            payload["original_isa_sha256"], payload["candidate_isa_sha256"]
        )
        if isa_mode == "side_artifacts":
            original_isa_sha256 = _sha256(
                isa_values[0], "composition original ISA"
            )
            candidate_isa_sha256 = _sha256(
                isa_values[1], "composition candidate ISA"
            )
        elif isa_values != (None, None):
            raise StageAInputError("extracted ISA mode must not bind side files")
        else:
            original_isa_sha256 = candidate_isa_sha256 = None
        raw_files = payload["files"]
        if not isinstance(raw_files, list):
            raise StageAInputError("composition products files must be a list")
        files = []
        for row in raw_files:
            if not isinstance(row, Mapping) or set(row) != {"path", "sha256"}:
                raise StageAInputError("composition product file row is malformed")
            path = row["path"]
            if not isinstance(path, str):
                raise StageAInputError("composition product path is invalid")
            files.append((path, _sha256(row["sha256"], path)))
        if (
            files != sorted(files)
            or len(files) != len({path for path, _digest in files})
            or {path for path, _digest in files}
                != COMPOSITION_PRODUCTS_REQUIRED_FILES
        ):
            raise StageAInputError("composition product inventory is not exact")
        body = {
            key: value for key, value in payload.items()
            if key != "products_sha256"
        }
        products_sha256 = _sha256(
            payload["products_sha256"], "composition products digest"
        )
        if products_sha256 != _canonical_sha256(body):
            raise StageAInputError("composition products digest does not match")
        return cls(
            **digests,
            isa_mode=isa_mode,
            original_isa_sha256=original_isa_sha256,
            candidate_isa_sha256=candidate_isa_sha256,
            files=tuple(files),
            products_sha256=products_sha256,
        )


def write_composition_products_manifest(
    root: Path,
    *,
    original_sha256: str,
    candidate_sha256: str,
    proposal_closure_sha256: str,
    register_replay_sha256: str,
    semantic_products_sha256: str,
    memory_products_sha256: str,
    original_isa_sha256: str | None,
    candidate_isa_sha256: str | None,
) -> dict[str, Any]:
    root = Path(root)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != COMPOSITION_PRODUCTS_MANIFEST
    }
    if actual != COMPOSITION_PRODUCTS_REQUIRED_FILES:
        raise StageAInputError(
            "composition products file inventory differs: "
            f"missing={sorted(COMPOSITION_PRODUCTS_REQUIRED_FILES - actual)}, "
            f"unexpected={sorted(actual - COMPOSITION_PRODUCTS_REQUIRED_FILES)}"
        )
    if (original_isa_sha256 is None) != (candidate_isa_sha256 is None):
        raise StageAInputError("composition side ISA binding is incomplete")
    body = {
        "format": COMPOSITION_PRODUCTS_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": original_sha256,
        "candidate_sha256": candidate_sha256,
        "proposal_closure_sha256": proposal_closure_sha256,
        "register_replay_sha256": register_replay_sha256,
        "semantic_products_sha256": semantic_products_sha256,
        "memory_products_sha256": memory_products_sha256,
        "isa_mode": (
            "side_artifacts" if original_isa_sha256 is not None
            else "lean_extracted"
        ),
        "original_isa_sha256": original_isa_sha256,
        "candidate_isa_sha256": candidate_isa_sha256,
        "files": [
            {"path": relative, "sha256": sha256_file(root / relative)}
            for relative in sorted(actual)
        ],
    }
    payload = {**body, "products_sha256": _canonical_sha256(body)}
    CompositionProductsManifest.parse(payload)
    write_json(root / COMPOSITION_PRODUCTS_MANIFEST, payload)
    return payload


def validate_composition_products(
    root: Path,
    *,
    expected_proposal_closure_sha256: str | None = None,
    expected_register_replay_sha256: str | None = None,
    expected_semantic_products_sha256: str | None = None,
    expected_memory_products_sha256: str | None = None,
    expected_original_sha256: str | None = None,
    expected_candidate_sha256: str | None = None,
    expected_original_isa_sha256: str | None = None,
    expected_candidate_isa_sha256: str | None = None,
) -> CompositionProductsManifest:
    root = Path(root)
    try:
        payload = json.loads(
            (root / COMPOSITION_PRODUCTS_MANIFEST).read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"could not read composition products: {exc}") from exc
    manifest = CompositionProductsManifest.parse(payload)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != COMPOSITION_PRODUCTS_MANIFEST
    }
    if actual != COMPOSITION_PRODUCTS_REQUIRED_FILES:
        raise StageAInputError("composition products directory inventory changed")
    for relative, expected in manifest.files:
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise StageAInputError(f"composition product is missing: {relative}")
        if sha256_file(path) != expected:
            raise StageAInputError(f"composition product hash mismatch: {relative}")
    expected_fields = {
        "proposal_closure_sha256": expected_proposal_closure_sha256,
        "register_replay_sha256": expected_register_replay_sha256,
        "semantic_products_sha256": expected_semantic_products_sha256,
        "memory_products_sha256": expected_memory_products_sha256,
        "original_sha256": expected_original_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "original_isa_sha256": expected_original_isa_sha256,
        "candidate_isa_sha256": expected_candidate_isa_sha256,
    }
    for field, expected in expected_fields.items():
        if expected is not None and getattr(manifest, field) != expected:
            raise StageAInputError(f"composition products {field} does not match")
    return manifest


__all__ = [
    "COMPOSITION_PRODUCTS_MANIFEST",
    "COMPOSITION_PRODUCTS_REQUIRED_FILES",
    "CompositionProductsManifest",
    "validate_composition_products",
    "write_composition_products_manifest",
]
