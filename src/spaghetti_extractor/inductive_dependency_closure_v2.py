"""Close induction dependencies through their dedicated authority artifacts.

The local invariant checker intentionally runs before external profiles and
callback entry contracts.  This phase replays those later artifacts and emits
typed receipts bound to the exact transition exits they justify.  A bare fact
or dependency ID is never accepted as authority.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .artifact_identity_v2 import canonical_sha256
from .authority_bindings_v2 import BinaryBinding, canonical_json_bytes
from .entry_state_analysis_v2 import (
    EntryStateAnalysisV2Error,
    derive_callback_entry_state_contracts_v2,
    parse_callback_entry_state_contracts_v2,
)
from .external_profile_authority_v2 import ExternalProfileAuthorityV2
from .external_site_proposals_v2 import (
    ExternalSiteProposalsV2Error,
    derive_external_site_proposals_v2,
    parse_external_site_proposals_v2,
)
from .hybrid_authority_v2 import AuthorityDataError, AuthorityStatus, EntryStateContract
from .global_slot_authority_v2 import apply_global_slot_authority_v2
from .inductive_authority_phase_v2 import (
    INDUCTIVE_AUTHORITY_PHASE_V2_FORMAT,
    check_inductive_authority_proposals_v2,
)
from .invariant_certificate_v2 import (
    DependencyDischargeV2,
    EntryFactsV2,
    ExportRequirementV2,
)
from .memory_version_graph_v2 import MemoryVersionGraphV2
from .transition_inventory_v2 import TransitionSummaryInventoryV2


class InductiveDependencyClosureV2Error(ValueError):
    """A late authority artifact is malformed or contradicts exact inputs."""


INDUCTIVE_DEPENDENCY_CLOSURE_V2_FORMAT = (
    "spaghetti-extractor-inductive-dependency-closure-v2"
)


def close_inductive_dependencies_v2(
    proposal: Mapping[str, Any],
    *,
    local_authority: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    transition_summaries: TransitionSummaryInventoryV2 | Mapping[str, Any],
    memory_version_graph: MemoryVersionGraphV2 | Mapping[str, Any],
    target_proposals: Mapping[str, Any],
    environment_interprocedural_proposal: Mapping[str, Any],
    profile_sha256: str,
    root_unit_ids: Sequence[str],
    root_entry_facts: Sequence[EntryFactsV2] = (),
    required_exports: Sequence[ExportRequirementV2] = (),
    reachable_unit_ids: Sequence[str],
    external_site_proposals: Mapping[str, Any],
    external_profile_authority: ExternalProfileAuthorityV2,
    callback_entry_contracts: Mapping[str, Any],
    callback_image_base: int,
    callback_size_of_image: int,
    global_slot_authority: Mapping[str, Any],
) -> dict[str, Any]:
    """Replay owner artifacts, then rerun induction with exact typed receipts."""

    summaries = _summary_inventory(transition_summaries)
    issues: list[dict[str, Any]] = []
    if (
        local_authority.get("format") != INDUCTIVE_AUTHORITY_PHASE_V2_FORMAT
        or local_authority.get("proposal_id") != proposal.get("id")
        or not _content_id_valid(local_authority)
    ):
        issues.append({
            "status": "violated",
            "code": "local_inductive_authority_binding_contradiction",
        })

    discharges: list[DependencyDischargeV2] = []
    discharges.extend(
        _external_site_discharges(
            units=units,
            summaries=summaries,
            interprocedural=environment_interprocedural_proposal,
            reachable_unit_ids=reachable_unit_ids,
            proposals=external_site_proposals,
            authority=external_profile_authority,
            issues=issues,
        )
    )
    try:
        expected_callbacks = derive_callback_entry_state_contracts_v2(
                pe_sha256=summaries.binary.pe_sha256,
                image_base=callback_image_base,
                size_of_image=callback_size_of_image,
                interface_provenance=apply_global_slot_authority_v2(
                    environment_interprocedural_proposal.get(
                        "operation_provenance", {}
                    ),
                    global_slot_authority,
                ),
                units=units,
                machine_ir_sha256=summaries.binary.machine_ir_sha256,
                global_slot_invariants=global_slot_authority.get(
                    "global_slot_invariants", []
                ),
            )
    except (AuthorityDataError, TypeError, ValueError) as exc:
        issues.append({
            "status": "violated",
            "code": "callback_entry_dependency_replay_failed",
            "detail": str(exc),
        })
        expected_callbacks = {}
    discharges.extend(
        _callback_entry_discharges(
            summaries=summaries,
            artifact=callback_entry_contracts,
            expected=expected_callbacks,
            issues=issues,
        )
    )
    canonical_discharges = tuple(sorted(set(discharges)))
    report = check_inductive_authority_proposals_v2(
        proposal,
        units=units,
        transition_summaries=summaries,
        memory_version_graph=memory_version_graph,
        interprocedural_proposal=target_proposals,
        profile_sha256=profile_sha256,
        root_unit_ids=root_unit_ids,
        root_entry_facts=root_entry_facts,
        required_exports=required_exports,
        dependency_discharges=canonical_discharges,
    )
    checked = _merge_issues(report, issues)
    body = {
        **{key: value for key, value in checked.items() if key != "id"},
        "format": INDUCTIVE_DEPENDENCY_CLOSURE_V2_FORMAT,
        "local_authority_id": local_authority.get("id"),
    }
    return {
        **body,
        "id": "inductive-dependency-closure-v2:" + canonical_sha256(body),
    }


def _external_site_discharges(
    *,
    units: Sequence[Mapping[str, Any]],
    summaries: TransitionSummaryInventoryV2,
    interprocedural: Mapping[str, Any],
    reachable_unit_ids: Sequence[str],
    proposals: Mapping[str, Any],
    authority: ExternalProfileAuthorityV2,
    issues: list[dict[str, Any]],
) -> tuple[DependencyDischargeV2, ...]:
    try:
        rows = parse_external_site_proposals_v2(
            proposals,
            pe_sha256=summaries.binary.pe_sha256,
            machine_ir_sha256=summaries.binary.machine_ir_sha256,
        )
        expected = derive_external_site_proposals_v2(
            machine_ir_rows=units,
            interprocedural=interprocedural,
            profile_authority=authority,
            pe_sha256=summaries.binary.pe_sha256,
            machine_ir_sha256=summaries.binary.machine_ir_sha256,
            reachable_unit_ids=reachable_unit_ids,
        )
        if proposals != expected:
            raise InductiveDependencyClosureV2Error(
                "external-site artifact does not replay from exact inputs"
            )
    except (
        ExternalSiteProposalsV2Error,
        InductiveDependencyClosureV2Error,
        TypeError,
        ValueError,
    ) as exc:
        issues.append({
            "status": "violated",
            "code": "external_site_dependency_artifact_contradiction",
            "detail": str(exc),
        })
        return ()

    if proposals.get("status") != "complete":
        issues.extend(
            dict(issue)
            for issue in proposals.get("issues", ())
            if isinstance(issue, Mapping)
        )
        return ()

    sites = {
        (str(row["unit_id"]), int(row["event_index"]))
        for row in rows
    }
    artifact_id = "external-sites-v2:" + str(proposals["content_sha256"])
    result: list[DependencyDischargeV2] = []
    for summary in summaries.summaries:
        for exit_row in summary.exits:
            if (
                exit_row.source_kind != "external_event"
                or exit_row.source_index is None
                or (summary.unit.unit_id, exit_row.source_index) not in sites
            ):
                continue
            result.append(
                DependencyDischargeV2(
                    dependency_id=f"external-site:{exit_row.exit_id}",
                    kind="external_site",
                    binding_sha256=canonical_sha256(exit_row.to_payload()),
                    authority_artifact_id=artifact_id,
                    evidence_sha256=canonical_sha256([
                        row
                        for row in rows
                        if row["unit_id"] == summary.unit.unit_id
                        and row["event_index"] == exit_row.source_index
                    ]),
                )
            )
    return tuple(sorted(result))


def _callback_entry_discharges(
    *,
    summaries: TransitionSummaryInventoryV2,
    artifact: Mapping[str, Any],
    expected: Mapping[str, Any],
    issues: list[dict[str, Any]],
) -> tuple[DependencyDischargeV2, ...]:
    try:
        parsed = parse_callback_entry_state_contracts_v2(artifact)
        if parsed != expected:
            raise InductiveDependencyClosureV2Error(
                "callback-entry artifact does not replay from exact inputs"
            )
        binary = parsed["binary"]
        if binary["pe_sha256"] != summaries.binary.pe_sha256 or (
            binary["machine_ir_sha256"] != summaries.binary.machine_ir_sha256
        ):
            raise InductiveDependencyClosureV2Error(
                "callback-entry artifact binds different binary inputs"
            )
    except (
        EntryStateAnalysisV2Error,
        InductiveDependencyClosureV2Error,
        TypeError,
        ValueError,
    ) as exc:
        issues.append({
            "status": "violated",
            "code": "callback_entry_dependency_artifact_contradiction",
            "detail": str(exc),
        })
        return ()

    if parsed["status"] != "complete":
        issues.extend(
            dict(issue)
            for issue in parsed["issues"]
            if isinstance(issue, Mapping)
        )
        return ()

    registration_evidence: dict[bytes, list[Mapping[str, Any]]] = {}
    try:
        for raw in parsed["contracts"]:
            contract = EntryStateContract.parse(raw)
            if (
                contract.status is not AuthorityStatus.COMPLETE
                or contract.alternatives is None
                or len(contract.alternatives.values) != 1
            ):
                continue
            facts = contract.alternatives.values[0].to_value()
            registration = facts.get("registration_event") if isinstance(facts, Mapping) else None
            if isinstance(registration, Mapping):
                registration_evidence.setdefault(
                    canonical_json_bytes(registration), []
                ).append(raw)
    except (AuthorityDataError, TypeError, ValueError) as exc:
        issues.append({
            "status": "violated",
            "code": "callback_entry_dependency_contract_contradiction",
            "detail": str(exc),
        })
        return ()

    artifact_id = "callback-entry-v2:" + str(parsed["analysis_sha256"])
    result: list[DependencyDischargeV2] = []
    for summary in summaries.summaries:
        for exit_row in summary.exits:
            if (
                exit_row.source_kind != "external_event"
                or exit_row.category != "callback"
                or exit_row.binding is None
            ):
                continue
            evidence = registration_evidence.get(
                canonical_json_bytes(exit_row.binding.to_payload())
            )
            if not evidence:
                continue
            result.append(
                DependencyDischargeV2(
                    dependency_id=f"callback-entry:{exit_row.exit_id}",
                    kind="callback_entry",
                    binding_sha256=canonical_sha256(exit_row.to_payload()),
                    authority_artifact_id=artifact_id,
                    evidence_sha256=canonical_sha256(evidence),
                )
            )
    return tuple(sorted(result))


def _merge_issues(
    report: Mapping[str, Any], issues: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    if not issues:
        return dict(report)
    body = dict(report)
    body.pop("id", None)
    merged = {
        canonical_json_bytes(row): dict(row)
        for row in (*report.get("issues", ()), *issues)
        if isinstance(row, Mapping)
    }
    body["issues"] = sorted(merged.values(), key=canonical_json_bytes)
    body["status"] = (
        "violated"
        if any(row.get("status") == "violated" for row in body["issues"])
        else "incomplete"
    )
    body["authorizing"] = False
    return {**body, "id": "inductive-authority-v2:" + canonical_sha256(body)}


def _content_id_valid(value: Mapping[str, Any]) -> bool:
    body = dict(value)
    observed = body.pop("id", None)
    return observed == "inductive-authority-v2:" + canonical_sha256(body)


def _summary_inventory(
    value: TransitionSummaryInventoryV2 | Mapping[str, Any],
) -> TransitionSummaryInventoryV2:
    return (
        value
        if isinstance(value, TransitionSummaryInventoryV2)
        else TransitionSummaryInventoryV2.parse(value)
    )


__all__ = [
    "InductiveDependencyClosureV2Error",
    "close_inductive_dependencies_v2",
]
