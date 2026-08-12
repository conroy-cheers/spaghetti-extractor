"""Explain exactly why suite shards or tests changed identity."""

from __future__ import annotations

from typing import Mapping

from .diagnostics import Diagnostic, TestkitError
from .model import ImpactIndex, REBUILD_EXPLANATION_FORMAT, SuitePlan


def _delta(before: set[str], after: set[str]) -> dict[str, list[str]]:
    return {"added": sorted(after - before), "removed": sorted(before - after)}


def explain_plan_rebuild(
    before: SuitePlan,
    after: SuitePlan,
    *,
    artifact: str | None = None,
) -> dict[str, object]:
    old = {row.id: row for row in before.shards}
    new = {row.id: row for row in after.shards}
    known = set(old) | set(new)
    if artifact is not None and artifact not in known:
        raise TestkitError(
            Diagnostic(
                "error",
                "unknown_rebuild_artifact",
                f"shard {artifact!r} appears in neither plan",
                remediation=f"Choose one of: {', '.join(sorted(known)) or 'none'}.",
            )
        )
    selected = sorted({artifact} if artifact else known)
    rows: list[dict[str, object]] = []
    for shard_id in selected:
        left = old.get(shard_id)
        right = new.get(shard_id)
        if left is None:
            rows.append({"artifact": shard_id, "disposition": "added", "reasons": ["new shard identity"], "tests": _delta(set(), set(right.tests))})
            continue
        if right is None:
            rows.append({"artifact": shard_id, "disposition": "removed", "reasons": ["shard no longer selected"], "tests": _delta(set(left.tests), set())})
            continue
        reasons: list[str] = []
        if left.input_sha256 != right.input_sha256:
            reasons.append("test, imported source, resource, or fixture content changed")
        if left.resource_class != right.resource_class:
            reasons.append(f"resource class changed from {left.resource_class} to {right.resource_class}")
        test_delta = _delta(set(left.tests), set(right.tests))
        file_delta = _delta(set(left.files), set(right.files))
        if test_delta["added"] or test_delta["removed"]:
            reasons.append("shard test membership changed")
        if file_delta["added"] or file_delta["removed"]:
            reasons.append("source closure changed")
        rows.append(
            {
                "artifact": shard_id,
                "disposition": "rebuild" if reasons else "substitute",
                "reasons": reasons or ["all declared inputs are identical"],
                "tests": test_delta,
                "files": file_delta,
                "before_input_sha256": left.input_sha256,
                "after_input_sha256": right.input_sha256,
            }
        )
    return {
        "format": REBUILD_EXPLANATION_FORMAT,
        "kind": "suite-plan",
        "before": before.identity,
        "after": after.identity,
        "artifacts": rows,
        "counts": {
            "added": sum(row["disposition"] == "added" for row in rows),
            "removed": sum(row["disposition"] == "removed" for row in rows),
            "rebuild": sum(row["disposition"] == "rebuild" for row in rows),
            "substitute": sum(row["disposition"] == "substitute" for row in rows),
        },
    }


def explain_index_rebuild(before: ImpactIndex, after: ImpactIndex) -> dict[str, object]:
    old_tests = {row.id: row for row in before.tests}
    new_tests = {row.id: row for row in after.tests}
    old_modules = {row.path: row for row in before.modules}
    new_modules = {row.path: row for row in after.modules}
    changed_modules = sorted(
        path for path in set(old_modules) & set(new_modules) if old_modules[path].sha256 != new_modules[path].sha256
    )
    changed_tests = sorted(
        test_id for test_id in set(old_tests) & set(new_tests) if old_tests[test_id].input_sha256 != new_tests[test_id].input_sha256
    )
    return {
        "format": REBUILD_EXPLANATION_FORMAT,
        "kind": "impact-index",
        "before": before.identity,
        "after": after.identity,
        "modules": {**_delta(set(old_modules), set(new_modules)), "changed": changed_modules},
        "tests": {**_delta(set(old_tests), set(new_tests)), "changed": changed_tests},
    }


__all__ = ["explain_index_rebuild", "explain_plan_rebuild"]
