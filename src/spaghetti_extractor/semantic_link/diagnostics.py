"""Non-authorizing diagnostics over ``linked-semantic-module-v2``.

These projections never become link, provider, realization, or deployment
inputs.  They expose semantic holes, typed obligations, analysis frontiers,
local definition neighborhoods, invalidation dependencies, and module deltas
without reconstructing a second reachability or semantic pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .module_v2 import LinkedSemanticModuleV2


def _module(
    linked: LinkedSemanticModuleV2 | Mapping[str, Any] | Path | str,
) -> LinkedSemanticModuleV2:
    if isinstance(linked, (str, Path)):
        return LinkedSemanticModuleV2.load(Path(linked))
    if isinstance(linked, LinkedSemanticModuleV2):
        return linked
    if isinstance(linked, Mapping):
        return LinkedSemanticModuleV2.parse(linked)
    raise TypeError("semantic diagnostics require a linked semantic module V2")


def _count_by(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for row in rows:
        key = str(row.get(field, "unknown"))
        result[key] = result.get(key, 0) + 1
    return dict(sorted(result.items()))


def semantic_status_projection_v2(
    linked: LinkedSemanticModuleV2 | Mapping[str, Any] | Path | str,
) -> dict[str, Any]:
    """Return the separate semantic, obligation, and analysis domains."""

    module = _module(linked)
    payload = module.payload
    holes = [dict(row) for row in payload["semantic_holes"]]
    obligations = [dict(row) for row in payload["residual_obligations"]]
    frontiers = [dict(row) for row in payload["analysis_frontiers"]]
    return {
        "role": "diagnostic",
        "authority": False,
        "linked_semantic_module_sha256": module.identity,
        "semantic_status": payload["status"],
        "semantic_holes": holes,
        "residual_obligations": obligations,
        "analysis_frontiers": frontiers,
        "counts": {
            "semantic_holes": len(holes),
            "residual_obligations": len(obligations),
            "analysis_frontiers": len(frontiers),
            "semantic_holes_by_code": _count_by(holes, "code"),
            "residual_obligations_by_class": _count_by(obligations, "class"),
            "analysis_frontiers_by_class": _count_by(frontiers, "class"),
        },
    }


def semantic_cause_projection_v2(
    linked: LinkedSemanticModuleV2 | Mapping[str, Any] | Path | str,
) -> dict[str, Any]:
    """Group exact V2 incompleteness and residual-work causes."""

    module = _module(linked)
    payload = module.payload
    rows: list[dict[str, Any]] = []
    for domain, field, identity_field in (
        ("semantic_hole", "semantic_holes", "hole_id"),
        ("residual_obligation", "residual_obligations", "obligation_id"),
        ("analysis_frontier", "analysis_frontiers", "frontier_id"),
    ):
        for raw in payload[field]:
            row = dict(raw)
            cause = row.get("code", row.get("class", "unknown"))
            rows.append({
                "domain": domain,
                "cause": str(cause),
                "identity": str(row[identity_field]),
                "subject": row.get("subject", row.get("subjects")),
                "detail": row,
            })
    rows.sort(key=lambda row: (row["domain"], row["cause"], row["identity"]))
    return {
        "role": "diagnostic",
        "authority": False,
        "linked_semantic_module_sha256": module.identity,
        "causes": rows,
        "counts": {
            domain: sum(row["domain"] == domain for row in rows)
            for domain in (
                "semantic_hole", "residual_obligation", "analysis_frontier"
            )
        },
    }


def semantic_slice_projection_v2(
    linked: LinkedSemanticModuleV2 | Mapping[str, Any] | Path | str,
    *, source_rva: int,
) -> dict[str, Any]:
    """Project the exact V2 neighborhood for one original entry RVA."""

    if not isinstance(source_rva, int) or isinstance(source_rva, bool) or source_rva < 0:
        raise ValueError("semantic slice source RVA must be nonnegative")
    module = _module(linked)
    payload = module.payload
    symbols = [
        dict(row) for row in payload["active_symbols"]
        if row.get("original_rva") == source_rva
        and row.get("kind") == "function"
    ]
    if len(symbols) != 1:
        raise ValueError("semantic slice source RVA is not one active function")
    symbol = symbols[0]
    symbol_id = str(symbol["symbol_id"])
    definition_id = symbol.get("definition_id")
    definitions = [
        dict(row) for row in payload["definitions"]
        if row.get("definition_id") == definition_id
    ]
    relocations = [
        dict(row) for row in payload["active_relocations"]
        if row.get("source_symbol") == symbol_id
        or symbol_id in row.get("target_symbols", [])
    ]
    obligations = [
        dict(row) for row in payload["residual_obligations"]
        if definition_id in row.get("subject_definition_ids", [])
        or any(
            symbol_id in str(subject) or f"{source_rva:08x}" in str(subject)
            for subject in row.get("subjects", [])
        )
    ]
    effects = {
        group: [
            dict(row) for row in rows
            if row.get("source_rva") == source_rva
            or row.get("instruction_rva") == source_rva
            or row.get("source_symbol_id") == symbol_id
        ]
        for group, rows in payload["effects"].items()
    }
    return {
        "role": "diagnostic",
        "authority": False,
        "linked_semantic_module_sha256": module.identity,
        "source_rva": source_rva,
        "symbol": symbol,
        "definitions": definitions,
        "relocations": relocations,
        "residual_obligations": obligations,
        "effects": effects,
    }


def semantic_invalidation_projection_v2(
    linked: LinkedSemanticModuleV2 | Mapping[str, Any] | Path | str,
) -> dict[str, Any]:
    """Expose content dependencies without predicting an incremental build."""

    module = _module(linked)
    payload = module.payload
    rows = []
    for definition in payload["definitions"]:
        rows.append({
            "subject_kind": "definition",
            "subject_id": definition["definition_id"],
            "contract_sha256": definition["definition_sha256"],
            "dependency_contract_sha256s": list(
                definition["dependency_contract_sha256s"]
            ),
        })
    for obligation in payload["residual_obligations"]:
        rows.append({
            "subject_kind": "residual_obligation",
            "subject_id": obligation["obligation_id"],
            "contract_sha256": obligation["semantic_contract_sha256"],
            "dependency_contract_sha256s": list(
                obligation.get("evidence_dependencies", [])
            ),
        })
    rows.sort(key=lambda row: (row["subject_kind"], row["subject_id"]))
    fanout: dict[str, int] = {}
    for row in rows:
        for dependency in row["dependency_contract_sha256s"]:
            fanout[str(dependency)] = fanout.get(str(dependency), 0) + 1
    return {
        "role": "diagnostic",
        "authority": False,
        "linked_semantic_module_sha256": module.identity,
        "subjects": rows,
        "dependency_fanout": dict(sorted(fanout.items())),
    }


def semantic_delta_projection_v2(
    before: LinkedSemanticModuleV2 | Mapping[str, Any] | Path | str,
    after: LinkedSemanticModuleV2 | Mapping[str, Any] | Path | str,
) -> dict[str, Any]:
    """Compare exact V2 identities; removals are diagnostic vetoes only."""

    left = _module(before)
    right = _module(after)
    catalogs = {
        "active_symbols": ("active_symbols", "symbol_id"),
        "active_relocations": ("active_relocations", "relocation_id"),
        "semantic_holes": ("semantic_holes", "hole_id"),
        "residual_obligations": ("residual_obligations", "obligation_id"),
        "analysis_frontiers": ("analysis_frontiers", "frontier_id"),
    }
    delta = {}
    vetoes = []
    for name, (field, identity_field) in catalogs.items():
        before_ids = {str(row[identity_field]) for row in left.payload[field]}
        after_ids = {str(row[identity_field]) for row in right.payload[field]}
        removed = sorted(before_ids - after_ids)
        added = sorted(after_ids - before_ids)
        delta[name] = {"added": added, "removed": removed}
        vetoes.extend({"catalog": name, "removed_identity": item} for item in removed)
    return {
        "role": "diagnostic",
        "authority": False,
        "before_linked_semantic_module_sha256": left.identity,
        "after_linked_semantic_module_sha256": right.identity,
        "delta": delta,
        "regression_vetoes": vetoes,
    }


__all__ = [
    "semantic_cause_projection_v2",
    "semantic_delta_projection_v2",
    "semantic_invalidation_projection_v2",
    "semantic_slice_projection_v2",
    "semantic_status_projection_v2",
]
