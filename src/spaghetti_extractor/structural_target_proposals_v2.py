"""Fast non-authorizing target proposals over the exact structural universe."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .artifact_identity_v2 import canonical_sha256
from .authority_bindings_v2 import canonical_json_bytes
from .control_analysis_v2 import exact_control_inventory_v2
from .transition_inventory_v2 import TransitionSummaryInventoryV2


STRUCTURAL_TARGET_PROPOSALS_V2_FORMAT = (
    "spaghetti-extractor-structural-target-proposals-v2"
)


class StructuralTargetProposalsV2Error(ValueError):
    """A structural target proposal contradicts the exact unit inventory."""


def build_structural_target_proposals_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    transition_summaries: TransitionSummaryInventoryV2 | Mapping[str, Any],
    proposed_recoveries: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Bind target hints to exact exits without running rooted propagation."""

    summaries = (
        transition_summaries
        if isinstance(transition_summaries, TransitionSummaryInventoryV2)
        else TransitionSummaryInventoryV2.parse(transition_summaries)
    )
    unit_ids = {str(row.get("id")) for row in units}
    if unit_ids != {row.unit.unit_id for row in summaries.summaries}:
        raise StructuralTargetProposalsV2Error(
            "transition summaries do not cover the exact structural universe"
        )
    exact = exact_control_inventory_v2(units)
    exact_by_id = {str(row["id"]): row for row in exact["indirect_exits"]}
    issues: list[dict[str, Any]] = [dict(row) for row in exact["issues"]]
    proposed_by_id: dict[str, list[Mapping[str, Any]]] = {}
    for index, raw in enumerate(proposed_recoveries):
        if not isinstance(raw, Mapping) or not isinstance(raw.get("id"), str):
            issues.append(_issue(
                "violated",
                "structural_target_proposal_malformed",
                f"proposal:{index}",
            ))
            continue
        proposed_by_id.setdefault(str(raw["id"]), []).append(raw)

    recoveries: list[dict[str, Any]] = []
    for exit_id, exact_row in sorted(exact_by_id.items()):
        matches = proposed_by_id.get(exit_id, ())
        if len(matches) > 1:
            issues.append(_issue(
                "violated", "structural_target_proposal_ambiguous", exit_id
            ))
            recoveries.append(_incomplete_recovery(exact_row))
            continue
        if not matches:
            issues.append(_issue(
                "incomplete", "structural_target_proposal_missing", exit_id
            ))
            recoveries.append(_incomplete_recovery(exact_row))
            continue
        proposal = matches[0]
        expected_identity = {
            "id": exit_id,
            "source_unit_id": exact_row["source_unit_id"],
            "source_rva": exact_row["source_rva"],
            "source_event_index": exact_row.get("source_event_index"),
            "kind": exact_row["kind"],
        }
        if any(proposal.get(key) != value for key, value in expected_identity.items()):
            issues.append(_issue(
                "violated", "structural_target_proposal_binding_mismatch", exit_id
            ))
            recoveries.append(_incomplete_recovery(exact_row))
            continue
        raw_targets = proposal.get("target_unit_ids")
        raw_external = proposal.get("external_targets", [])
        if (
            not isinstance(raw_targets, list)
            or not isinstance(raw_external, list)
            or any(not isinstance(value, str) for value in raw_targets)
            or any(not isinstance(value, Mapping) for value in raw_external)
        ):
            issues.append(_issue(
                "violated", "structural_target_proposal_target_set_malformed", exit_id
            ))
            recoveries.append(_incomplete_recovery(exact_row))
            continue
        targets = tuple(sorted(set(raw_targets)))
        unknown = tuple(sorted(set(targets) - unit_ids))
        if unknown:
            issues.append({
                **_issue(
                    "violated", "structural_target_proposal_target_unknown", exit_id
                ),
                "target_unit_ids": list(unknown),
            })
            recoveries.append(_incomplete_recovery(exact_row))
            continue
        external = sorted(
            (dict(row) for row in raw_external), key=canonical_json_bytes
        )
        recovered = (
            proposal.get("status") == "recovered"
            and bool(targets or external)
            and proposal.get("failure") is None
        )
        if not recovered:
            issues.append(_issue(
                "incomplete", "structural_target_proposal_incomplete", exit_id
            ))
        recoveries.append({
            **expected_identity,
            "status": "recovered" if recovered else "incomplete",
            "target_unit_ids": list(targets) if recovered else [],
            "external_targets": external if recovered else [],
            "proposal_sha256": canonical_sha256(proposal),
        })

    for extra in sorted(set(proposed_by_id) - set(exact_by_id)):
        issues.append(_issue(
            "violated", "structural_target_proposal_exit_unknown", extra
        ))
    canonical_issues = sorted(
        {canonical_json_bytes(row): row for row in issues}.values(),
        key=canonical_json_bytes,
    )
    status = (
        "violated"
        if any(row.get("status") == "violated" for row in canonical_issues)
        else "incomplete"
        if canonical_issues
        else "complete"
    )
    body = {
        "format": STRUCTURAL_TARGET_PROPOSALS_V2_FORMAT,
        "status": status,
        "authorizing": False,
        "binary": summaries.binary.to_payload(),
        "recovered_targets": recoveries,
        "issues": canonical_issues,
        "counts": {
            "exact_indirect_exits": len(exact_by_id),
            "recovered_targets": sum(
                row["status"] == "recovered" for row in recoveries
            ),
            "issues": len(canonical_issues),
        },
    }
    return {
        **body,
        "id": "structural-target-proposals-v2:" + canonical_sha256(body),
    }


def _incomplete_recovery(exact: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": exact["id"],
        "source_unit_id": exact["source_unit_id"],
        "source_rva": exact["source_rva"],
        "source_event_index": exact.get("source_event_index"),
        "kind": exact["kind"],
        "status": "incomplete",
        "target_unit_ids": [],
        "external_targets": [],
        "proposal_sha256": None,
    }


def _issue(status: str, code: str, subject_id: str) -> dict[str, str]:
    return {"status": status, "code": code, "subject_id": subject_id}


__all__ = [
    "STRUCTURAL_TARGET_PROPOSALS_V2_FORMAT",
    "StructuralTargetProposalsV2Error",
    "build_structural_target_proposals_v2",
]
