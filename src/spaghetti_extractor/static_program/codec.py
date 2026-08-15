"""Strict static-program contract parsing and filesystem binding."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import (
    STATIC_ANALYSIS_PROFILE_ID,
    STATIC_PROGRAM_CONTRACT_FORMAT,
)
from ..util import sha256_file
from .model import (
    StaticProgramContract,
    StaticProgramContractBinding,
    StaticProgramContractError,
)


_FIELDS = {
    "format",
    "generator",
    "profile",
    "status",
    "binary",
    "structural_universe",
    "families",
    "sidecars",
    "issues",
    "counts",
    "trust",
}


def parse_static_program_contract(value: Any) -> StaticProgramContract:
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise StaticProgramContractError("static-program contract schema is malformed")
    if value.get("format") != STATIC_PROGRAM_CONTRACT_FORMAT:
        raise StaticProgramContractError("unsupported static-program contract format")
    if value.get("generator") != "spaghetti-extractor-static-program":
        raise StaticProgramContractError("unsupported static-program contract producer")
    if value.get("profile") != STATIC_ANALYSIS_PROFILE_ID:
        raise StaticProgramContractError("unsupported static-program analysis profile")
    trust = value.get("trust")
    expected_trust = {
        "executes_original_binary": False,
        "uses_candidate_binary": False,
        "uses_binary_mapping": False,
        "claims_whole_program_equivalence": False,
        "behavioral_reachability_separate": True,
    }
    if trust != expected_trust:
        raise StaticProgramContractError("static-program trust policy is malformed")
    mappings = {
        name: value.get(name)
        for name in ("binary", "structural_universe", "families", "sidecars", "counts")
    }
    if any(not isinstance(item, Mapping) for item in mappings.values()):
        raise StaticProgramContractError("static-program contract objects are malformed")
    issues = value.get("issues")
    if not isinstance(issues, list) or any(not isinstance(row, Mapping) for row in issues):
        raise StaticProgramContractError("static-program issues are malformed")
    return StaticProgramContract(
        binary=mappings["binary"],
        structural_universe=mappings["structural_universe"],
        families=mappings["families"],
        sidecars=mappings["sidecars"],
        issues=tuple(issues),
        counts=mappings["counts"],
        status=str(value.get("status")),
    )


def load_static_program_contract_binding(
    path: Path, *, original_pe: Path | None = None
) -> StaticProgramContractBinding:
    path = Path(path).resolve()
    if not path.is_file() or path.is_symlink():
        raise StaticProgramContractError(
            "static-program contract must be a regular non-symlink file"
        )
    try:
        typed = parse_static_program_contract(
            json.loads(path.read_text(encoding="utf-8"))
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise StaticProgramContractError(f"cannot read static-program contract: {exc}") from exc
    binary_sha256 = typed.binary.get("sha256")
    if not isinstance(binary_sha256, str) or len(binary_sha256) != 64:
        raise StaticProgramContractError("static-program binary hash is invalid")
    if original_pe is not None and sha256_file(Path(original_pe)) != binary_sha256:
        raise StaticProgramContractError(
            "static-program contract is not bound to the supplied original PE"
        )
    semantic = typed.sidecars.get("semantic_transfers")
    if not isinstance(semantic, Mapping) or set(semantic) != {"path", "sha256"}:
        raise StaticProgramContractError(
            "static-program contract has no canonical semantic-transfer sidecar"
        )
    relative = semantic.get("path")
    if (
        not isinstance(relative, str)
        or not relative
        or Path(relative).is_absolute()
        or Path(relative).name != relative
    ):
        raise StaticProgramContractError("static-program semantic path is invalid")
    semantic_sha256 = semantic.get("sha256")
    if not isinstance(semantic_sha256, str) or len(semantic_sha256) != 64:
        raise StaticProgramContractError("static-program semantic hash is invalid")
    semantic_path = path.parent / relative
    if not semantic_path.is_file() or semantic_path.is_symlink():
        raise StaticProgramContractError(
            "static-program semantic sidecar must be a regular non-symlink file"
        )
    if sha256_file(semantic_path) != semantic_sha256:
        raise StaticProgramContractError(
            "static-program semantic sidecar differs from its contract binding"
        )
    return StaticProgramContractBinding(
        path=path,
        sha256=sha256_file(path),
        original_pe_sha256=binary_sha256,
        semantic_transfers=semantic_path.resolve(),
        semantic_transfers_sha256=semantic_sha256,
    )


__all__ = ["load_static_program_contract_binding", "parse_static_program_contract"]
