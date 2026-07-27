from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .schema import ModuleGraph, SchemaError


SEMANTIC_INVALIDATION_REPORT_FORMAT = (
    "stage-a-semantic-invalidation-report-v1"
)


@dataclass(frozen=True)
class SemanticInvalidationReport:
    status: str
    direct_changes: tuple[str, ...]
    expected_invalidated: tuple[str, ...]
    observed_invalidated: tuple[str, ...]
    unexpected_invalidated: tuple[str, ...]
    missing_invalidated: tuple[str, ...]
    reused: tuple[str, ...]
    added: tuple[str, ...]
    removed: tuple[str, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "format": SEMANTIC_INVALIDATION_REPORT_FORMAT,
            "status": self.status,
            "direct_changes": list(self.direct_changes),
            "expected_invalidated": list(self.expected_invalidated),
            "observed_invalidated": list(self.observed_invalidated),
            "unexpected_invalidated": list(self.unexpected_invalidated),
            "missing_invalidated": list(self.missing_invalidated),
            "reused": list(self.reused),
            "added": list(self.added),
            "removed": list(self.removed),
            "counts": {
                "direct_changes": len(self.direct_changes),
                "expected_invalidated": len(self.expected_invalidated),
                "observed_invalidated": len(self.observed_invalidated),
                "unexpected_invalidated": len(self.unexpected_invalidated),
                "missing_invalidated": len(self.missing_invalidated),
                "reused": len(self.reused),
                "added": len(self.added),
                "removed": len(self.removed),
            },
        }


def _graph_nodes(payload: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    ModuleGraph.parse(payload)
    rows = payload.get("nodes")
    if not isinstance(rows, list):
        raise SchemaError("module graph nodes must be a list")
    return {str(row["id"]): row for row in rows}


def diff_semantic_invalidation(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> SemanticInvalidationReport:
    """Check that semantic identities change exactly along dependency edges."""

    before_nodes = _graph_nodes(before)
    after_nodes = _graph_nodes(after)
    before_ids = set(before_nodes)
    after_ids = set(after_nodes)
    shared = before_ids & after_ids
    added = after_ids - before_ids
    removed = before_ids - after_ids

    direct_changes = {
        node_id
        for node_id in shared
        if any(
            before_nodes[node_id].get(field) != after_nodes[node_id].get(field)
            for field in (
                "modules",
                "dependencies",
                "source_sha256",
                "semantic_recipe_version",
            )
        )
    }
    observed = {
        node_id
        for node_id in shared
        if before_nodes[node_id].get("semantic_id")
        != after_nodes[node_id].get("semantic_id")
    }

    reverse_dependencies: dict[str, set[str]] = {
        node_id: set() for node_id in after_ids
    }
    for node_id, node in after_nodes.items():
        for dependency in node.get("dependencies", []):
            reverse_dependencies.setdefault(str(dependency), set()).add(node_id)

    expected = set(direct_changes)
    pending = list(direct_changes)
    while pending:
        dependency = pending.pop()
        for descendant in reverse_dependencies.get(dependency, set()):
            if descendant in shared and descendant not in expected:
                expected.add(descendant)
                pending.append(descendant)

    unexpected = observed - expected
    missing = expected - observed
    reused = shared - observed
    status = (
        "satisfied"
        if not unexpected and not missing and not added and not removed
        else "violated"
    )
    return SemanticInvalidationReport(
        status=status,
        direct_changes=tuple(sorted(direct_changes)),
        expected_invalidated=tuple(sorted(expected)),
        observed_invalidated=tuple(sorted(observed)),
        unexpected_invalidated=tuple(sorted(unexpected)),
        missing_invalidated=tuple(sorted(missing)),
        reused=tuple(sorted(reused)),
        added=tuple(sorted(added)),
        removed=tuple(sorted(removed)),
    )
