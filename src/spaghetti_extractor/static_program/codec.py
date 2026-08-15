"""Strict static-program contract parsing and filesystem binding."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import (
    STATIC_ANALYSIS_PROFILE_ID,
    STATIC_PROGRAM_CONTRACT_FORMAT,
)
from ..pe32.model import BlockSide
from ..util import sha256_file
from .model import (
    StaticBinaryIdentity,
    StaticCFGEdge,
    StaticIssue,
    StaticProgramContract,
    StaticProgramContractBinding,
    StaticProgramContractError,
    StaticRoot,
    StaticSidecar,
    StaticStructuralUnit,
    StaticStructuralUniverse,
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
        "input_image_count": 1,
        "uses_cross_image_mapping": False,
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
    binary = mappings["binary"]
    structure = mappings["structural_universe"]
    if "mapping" in structure:
        raise StaticProgramContractError(
            "static-program contracts cannot contain binary-pair fields"
        )
    units_value = structure.get("units")
    if not isinstance(units_value, list):
        raise StaticProgramContractError("static-program structural units are malformed")
    units = tuple(_parse_unit(row) for row in units_value)
    roots = tuple(_parse_root(row) for row in _object_list(structure, "roots"))
    cfg_edges = tuple(
        _parse_cfg_edge(row) for row in _object_list(structure, "cfg_edges")
    )
    padding = tuple(_object_list(structure, "padding"))
    sidecars = mappings["sidecars"]
    if set(sidecars) != {"semantic_transfers"}:
        raise StaticProgramContractError("static-program sidecars are malformed")
    semantic = sidecars.get("semantic_transfers")
    if not isinstance(semantic, Mapping) or set(semantic) != {"path", "sha256"}:
        raise StaticProgramContractError(
            "static-program contract has no canonical semantic-transfer sidecar"
        )
    counts = mappings["counts"]
    if any(
        not isinstance(name, str)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count < 0
        for name, count in counts.items()
    ):
        raise StaticProgramContractError("static-program counts are malformed")
    return StaticProgramContract(
        binary=StaticBinaryIdentity(
            machine=_string(binary.get("machine"), "binary machine"),
            bitness=_integer(binary.get("bitness"), "binary bitness"),
            sha256=_string(binary.get("sha256"), "binary SHA-256"),
            details={
                key: item
                for key, item in binary.items()
                if key not in {"machine", "bitness", "sha256"}
            },
        ),
        structural_universe=StaticStructuralUniverse(
            units=units,
            roots=roots,
            cfg_edges=cfg_edges,
            padding=padding,
        ),
        families=mappings["families"],
        semantic_transfers=StaticSidecar(
            path=_string(semantic.get("path"), "semantic sidecar path"),
            sha256=_string(semantic.get("sha256"), "semantic sidecar SHA-256"),
        ),
        issues=tuple(_parse_issue(row) for row in issues),
        counts=dict(counts),
        status=str(value.get("status")),
    )


def _parse_unit(value: Any) -> StaticStructuralUnit:
    if not isinstance(value, Mapping):
        raise StaticProgramContractError("static structural unit is malformed")
    span_value = value.get("span")
    span = None
    if span_value is not None:
        if not isinstance(span_value, Mapping):
            raise StaticProgramContractError("static structural unit span is malformed")
        start = _integer(span_value.get("rva_start"), "unit start RVA")
        end = _integer(span_value.get("rva_end"), "unit end RVA")
        size = _integer(span_value.get("size"), "unit size")
        if end - start != size or size <= 0:
            raise StaticProgramContractError("static structural unit span is invalid")
        span = BlockSide(start, end)
    return StaticStructuralUnit(
        id=_string(value.get("id"), "unit id"),
        kind=_string(value.get("kind"), "unit kind"),
        span=span,
        details={
            key: item for key, item in value.items() if key not in {"id", "kind", "span"}
        },
    )


def _parse_root(value: Any) -> StaticRoot:
    if not isinstance(value, Mapping):
        raise StaticProgramContractError("static root is malformed")
    return StaticRoot(
        kind=_string(value.get("kind"), "root kind"),
        rva=_integer(value.get("rva"), "root RVA"),
        details={key: item for key, item in value.items() if key not in {"kind", "rva"}},
    )


def _parse_cfg_edge(value: Any) -> StaticCFGEdge:
    if not isinstance(value, Mapping) or set(value) != {
        "source_unit_id",
        "target_rvas",
        "indirect",
    }:
        raise StaticProgramContractError("static CFG edge is malformed")
    targets = value.get("target_rvas")
    if not isinstance(targets, list):
        raise StaticProgramContractError("static CFG targets are malformed")
    return StaticCFGEdge(
        source_unit_id=_string(value.get("source_unit_id"), "CFG source unit"),
        target_rvas=tuple(_integer(item, "CFG target RVA") for item in targets),
        indirect=_boolean(value.get("indirect"), "CFG indirect flag"),
    )


def _parse_issue(value: Mapping[str, Any]) -> StaticIssue:
    return StaticIssue(
        id=_string(value.get("id"), "issue id"),
        status=_string(value.get("status"), "issue status"),
        category=_string(value.get("category"), "issue category"),
        details={
            key: item
            for key, item in value.items()
            if key not in {"id", "status", "category"}
        },
    )


def _object_list(value: Mapping[str, Any], field: str) -> list[Mapping[str, Any]]:
    rows = value.get(field, [])
    if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
        raise StaticProgramContractError(f"static-program {field} are malformed")
    return rows


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise StaticProgramContractError(f"static-program {label} is invalid")
    return value


def _integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StaticProgramContractError(f"static-program {label} is invalid")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise StaticProgramContractError(f"static-program {label} is invalid")
    return value


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
    binary_sha256 = typed.binary.sha256
    if original_pe is not None and sha256_file(Path(original_pe)) != binary_sha256:
        raise StaticProgramContractError(
            "static-program contract is not bound to the supplied original PE"
        )
    relative = typed.semantic_transfers.path
    semantic_sha256 = typed.semantic_transfers.sha256
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
