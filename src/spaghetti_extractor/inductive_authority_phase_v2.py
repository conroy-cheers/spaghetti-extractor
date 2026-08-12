"""Certificate-checked inductive authority over structural transition SCCs.

Proposal analysis remains useful for finite indirect target sets, entry facts,
and candidate invariants.  This phase turns those proposals into typed data and
rechecks every control edge, effect summary, memory version, dependency SCC,
and induction obligation.  No serialized fixed-point status authorizes a
certificate.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .analysis.scc_worklist import decompose_scc
from .artifact_identity_v2 import canonical_sha256
from .authority_bindings_v2 import BinaryBinding, canonical_json_bytes
from .control_analysis_v2 import exact_control_inventory_v2
from .invariant_certificate_v2 import (
    DependencyEdgeV2,
    DependencyDischargeV2,
    DependencyNodeV2,
    EntryFactsV2,
    ExportRequirementV2,
    ExitTargetSetV2,
    InvariantBudgetsV2,
    InvariantCertificateContextV2,
    InvariantCertificateV2,
    InvariantCertificateV2Error,
    InvariantFactV2,
    TransitionControlWitnessV2,
    TransitionWitnessInventoryV2,
    check_invariant_certificate_v2,
    synthesize_invariant_certificate_v2,
)
from .memory_version_graph_v2 import MemoryVersionGraphV2
from .transition_inventory_v2 import TransitionSummaryInventoryV2
from .transition_summary_v2 import TransitionExitV2, TransitionSummaryV2


INDUCTIVE_PROPOSAL_PHASE_V2_FORMAT = (
    "spaghetti-extractor-inductive-authority-proposals-v2"
)
INDUCTIVE_AUTHORITY_PHASE_V2_FORMAT = (
    "spaghetti-extractor-inductive-authority-check-v2"
)


class InductiveAuthorityPhaseV2Error(ValueError):
    """An inductive phase input is malformed or contradicts exact evidence."""


def build_inductive_authority_proposals_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    transition_summaries: TransitionSummaryInventoryV2 | Mapping[str, Any],
    memory_version_graph: MemoryVersionGraphV2 | Mapping[str, Any],
    interprocedural_proposal: Mapping[str, Any],
    profile_sha256: str,
    root_unit_ids: Sequence[str],
    root_entry_facts: Sequence[EntryFactsV2] = (),
    cutpoint_facts: Mapping[str, Sequence[InvariantFactV2]] | None = None,
    required_exports: Sequence[ExportRequirementV2] = (),
    budgets: InvariantBudgetsV2 = InvariantBudgetsV2(),
) -> dict[str, Any]:
    """Package deterministic certificate proposals without granting authority."""

    summaries = _summary_inventory(transition_summaries)
    memory = _memory_graph(memory_version_graph)
    _validate_common_inputs(units, summaries, memory, profile_sha256)
    dependencies, _unused_edges, witnesses, issues = _derive_checked_graph_inputs(
        units=units,
        summaries=summaries.summaries,
        interprocedural=interprocedural_proposal,
        memory=memory,
    )
    witness_inventory = TransitionWitnessInventoryV2.create(
        binary=summaries.binary,
        structural_universe_sha256=_structural_universe_sha256(units),
        summaries=summaries.summaries,
        control_witnesses=witnesses,
    )
    control_edges = tuple(
        (
            witness.witness_id,
            target_set.exit_id,
            witness.source_cutpoint,
            target,
        )
        for witness in witnesses
        for target_set in witness.exit_targets
        for target in target_set.target_cutpoints
    )
    incoming_control_edges = _index_incoming_control_edges(control_edges)
    components = decompose_scc(
        (summary.unit.unit_id for summary in summaries.summaries),
        ((source, target) for _, _, source, target in control_edges),
    ).components
    dependencies, edges, invariant_by_members = _bind_control_scc_dependencies(
        dependencies=dependencies,
        witnesses=witnesses,
        components=components,
    )
    checker_context = InvariantCertificateContextV2.create(
        transition_inventory=witness_inventory,
        canonical_summaries=summaries.summaries,
        dependency_nodes=dependencies,
        dependency_edges=edges,
        memory_version_graph=memory,
    )
    facts = {} if cutpoint_facts is None else cutpoint_facts
    root_set = frozenset(root_unit_ids)
    reachable = _rooted_control_closure(root_set, control_edges)
    root_entries = tuple(
        sorted(
            (
                row
                for row in root_entry_facts
                if row.kind == "root" and row.target_cutpoint in root_set
            ),
            key=lambda row: row.entry_id,
        )
    )
    certificates: list[dict[str, Any]] = []
    dependency_graph_id = canonical_sha256({
        "nodes": [row.to_payload() for row in dependencies],
        "edges": [row.to_payload() for row in edges],
    })
    export_inventory = tuple(
        sorted(set(required_exports), key=lambda row: row.export_id)
    )
    for members in components:
        if not set(members).intersection(reachable):
            continue
        dependency = invariant_by_members[tuple(members)]
        component_entries = _component_entries(
            members=members,
            control_edges=control_edges,
            incoming_control_edges=incoming_control_edges,
            allowed_sources=reachable,
            root_entries=root_entries,
            cutpoint_facts=facts,
        )
        component_facts = {
            member: tuple(sorted(facts.get(member, ()))) for member in members
        }
        certificate = synthesize_invariant_certificate_v2(
            transition_inventory=witness_inventory,
            dependency_nodes=dependencies,
            dependency_edges=edges,
            member_cutpoints=members,
            dependency_members=(dependency.node_id,),
            cutpoint_facts=component_facts,
            entry_facts=component_entries,
            required_exports=tuple(
                row for row in export_inventory if row.cutpoint in members
            ),
            profile_sha256=profile_sha256,
            budgets=budgets,
            context=checker_context,
        )
        certificates.append({
            "certificate": certificate.to_payload(),
            "dependency_members": [dependency.node_id],
            "entry_facts": [row.to_payload() for row in component_entries],
            "member_cutpoints": list(members),
        })
    body = {
        "format": INDUCTIVE_PROPOSAL_PHASE_V2_FORMAT,
        "status": "incomplete",
        "authorizing": False,
        "binary": summaries.binary.to_payload(),
        "profile_sha256": profile_sha256,
        "root_unit_ids": sorted(root_set),
        "transition_inventory_id": witness_inventory.inventory_id,
        "dependency_graph_id": dependency_graph_id,
        "certificates": certificates,
        "issues": issues,
        "counts": {
            "certificates": len(certificates),
            "dependency_nodes": len(dependencies),
            "dependency_nodes_by_kind": {
                kind: sum(row.kind == kind for row in dependencies)
                for kind in sorted({row.kind for row in dependencies})
            },
            "structural_units": len(summaries.summaries),
            "reachable_units": len(reachable),
        },
    }
    return {**body, "id": "inductive-proposals-v2:" + canonical_sha256(body)}


def check_inductive_authority_proposals_v2(
    proposal: Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]],
    transition_summaries: TransitionSummaryInventoryV2 | Mapping[str, Any],
    memory_version_graph: MemoryVersionGraphV2 | Mapping[str, Any],
    interprocedural_proposal: Mapping[str, Any],
    profile_sha256: str,
    root_unit_ids: Sequence[str],
    root_entry_facts: Sequence[EntryFactsV2] = (),
    dependency_discharges: Sequence[DependencyDischargeV2] = (),
    required_exports: Sequence[ExportRequirementV2] = (),
    budgets: InvariantBudgetsV2 = InvariantBudgetsV2(),
) -> dict[str, Any]:
    """Reconstruct all inventories and check submitted induction certificates."""

    try:
        if not isinstance(proposal, Mapping) or proposal.get("format") != (
            INDUCTIVE_PROPOSAL_PHASE_V2_FORMAT
        ):
            raise InductiveAuthorityPhaseV2Error(
                "inductive proposal phase has an unsupported format"
            )
        summaries = _summary_inventory(transition_summaries)
        memory = _memory_graph(memory_version_graph)
        _validate_common_inputs(units, summaries, memory, profile_sha256)
        dependencies, _unused_edges, witnesses, input_issues = _derive_checked_graph_inputs(
            units=units,
            summaries=summaries.summaries,
            interprocedural=interprocedural_proposal,
            memory=memory,
        )
        inventory = TransitionWitnessInventoryV2.create(
            binary=summaries.binary,
            structural_universe_sha256=_structural_universe_sha256(units),
            summaries=summaries.summaries,
            control_witnesses=witnesses,
        )
        control_edges = tuple(
            (
                witness.witness_id,
                target_set.exit_id,
                witness.source_cutpoint,
                target,
            )
            for witness in witnesses
            for target_set in witness.exit_targets
            for target in target_set.target_cutpoints
        )
        incoming_control_edges = _index_incoming_control_edges(control_edges)
        components = decompose_scc(
            (summary.unit.unit_id for summary in summaries.summaries),
            ((source, target) for _, _, source, target in control_edges),
        ).components
        dependencies, edges, invariant_by_members = _bind_control_scc_dependencies(
            dependencies=dependencies,
            witnesses=witnesses,
            components=components,
        )
        checker_context = InvariantCertificateContextV2.create(
            transition_inventory=inventory,
            canonical_summaries=summaries.summaries,
            dependency_nodes=dependencies,
            dependency_edges=edges,
            memory_version_graph=memory,
            dependency_discharges=dependency_discharges,
        )
        if proposal.get("binary") != summaries.binary.to_payload():
            raise InductiveAuthorityPhaseV2Error(
                "inductive proposal binary binding contradicts exact inputs"
            )
        if proposal.get("profile_sha256") != profile_sha256:
            raise InductiveAuthorityPhaseV2Error(
                "inductive proposal profile binding is stale"
            )
        expected_roots = sorted(set(root_unit_ids))
        if proposal.get("root_unit_ids") != expected_roots:
            raise InductiveAuthorityPhaseV2Error(
                "inductive proposal root inventory is stale"
            )
        if proposal.get("transition_inventory_id") != inventory.inventory_id:
            raise InductiveAuthorityPhaseV2Error(
                "inductive proposal control inventory is stale"
            )
        expected_dependency_graph_id = canonical_sha256({
            "nodes": [row.to_payload() for row in dependencies],
            "edges": [row.to_payload() for row in edges],
        })
        if proposal.get("dependency_graph_id") != expected_dependency_graph_id:
            raise InductiveAuthorityPhaseV2Error(
                "inductive proposal dependency graph is stale"
            )
        rows = proposal.get("certificates")
        if not isinstance(rows, list):
            raise InductiveAuthorityPhaseV2Error(
                "inductive proposal has no certificate inventory"
            )
        expected_units = {
            summary.unit.unit_id for summary in summaries.summaries
        }
        root_set = frozenset(root_unit_ids)
        reachable = _rooted_control_closure(root_set, control_edges)
        expected_covered = set(reachable).intersection(expected_units)
        parsed_rows: list[
            tuple[
                InvariantCertificateV2,
                tuple[str, ...],
                tuple[str, ...],
                tuple[EntryFactsV2, ...],
            ]
        ] = []
        proposed_facts: dict[str, tuple[InvariantFactV2, ...]] = {}
        covered: set[str] = set()
        for row in rows:
            if not isinstance(row, Mapping) or set(row) != {
                "certificate",
                "dependency_members",
                "entry_facts",
                "member_cutpoints",
            }:
                raise InductiveAuthorityPhaseV2Error(
                    "inductive certificate row is malformed"
                )
            certificate = InvariantCertificateV2.parse(row["certificate"])
            members = _strings(row["member_cutpoints"], "member cutpoints")
            if covered.intersection(members):
                raise InductiveAuthorityPhaseV2Error(
                    "inductive certificate SCCs overlap"
                )
            covered.update(members)
            dependency_members = _strings(
                row["dependency_members"], "dependency members"
            )
            if len(dependency_members) != 1:
                raise InductiveAuthorityPhaseV2Error(
                    "control SCC requires one canonical dependency node"
                )
            entries = tuple(
                EntryFactsV2.parse(item) for item in _array(row["entry_facts"])
            )
            for invariant in certificate.cutpoint_invariants:
                if invariant.cutpoint in proposed_facts:
                    raise InductiveAuthorityPhaseV2Error(
                        "cutpoint invariant occurs in multiple certificates"
                    )
                proposed_facts[invariant.cutpoint] = invariant.facts
            parsed_rows.append(
                (certificate, members, dependency_members, entries)
            )
        if covered != expected_covered:
            raise InductiveAuthorityPhaseV2Error(
                "inductive certificates do not partition the rooted closure"
            )
        supplied_roots = tuple(
            sorted(
                (
                    row
                    for row in root_entry_facts
                    if row.kind == "root" and row.target_cutpoint in root_set
                ),
                key=lambda row: row.entry_id,
            )
        )
        reports: list[dict[str, Any]] = []
        export_inventory = tuple(
            sorted(set(required_exports), key=lambda row: row.export_id)
        )
        orchestration_issues = [
            issue
            for issue in input_issues
            if issue.get("status") == "violated"
            or issue.get("source_unit_id") is None
            or issue.get("source_unit_id") in reachable
        ]
        unknown_roots = sorted(root_set - expected_units)
        for root in unknown_roots:
            orchestration_issues.append({
                "status": "violated",
                "code": "root_unit_absent_from_structural_universe",
                "subject_id": root,
            })
        for root in sorted(root_set):
            matching = [
                row for row in supplied_roots if row.target_cutpoint == root
            ]
            if not matching:
                orchestration_issues.append({
                    "status": "incomplete",
                    "code": "root_entry_facts_missing",
                    "subject_id": root,
                })
            elif len(matching) != 1:
                orchestration_issues.append({
                    "status": "violated",
                    "code": "root_entry_facts_ambiguous",
                    "subject_id": root,
                })
        for certificate, members, dependency_members, entries in parsed_rows:
            expected_entries = _component_entries(
                members=members,
                control_edges=control_edges,
                incoming_control_edges=incoming_control_edges,
                allowed_sources=reachable,
                root_entries=supplied_roots,
                cutpoint_facts=proposed_facts,
            )
            if entries != expected_entries:
                orchestration_issues.append({
                    "status": "violated",
                    "code": "certificate_entry_inventory_contradiction",
                    "subject_id": certificate.certificate_id,
                })
            if not set(members).intersection(reachable):
                continue
            expected_dependency = invariant_by_members.get(tuple(members))
            if (
                expected_dependency is None
                or dependency_members != (expected_dependency.node_id,)
            ):
                orchestration_issues.append({
                    "status": "violated",
                    "code": "certificate_dependency_scc_contradiction",
                    "subject_id": certificate.certificate_id,
                })
            report = check_invariant_certificate_v2(
                certificate,
                transition_inventory=inventory,
                canonical_summaries=summaries.summaries,
                dependency_nodes=dependencies,
                dependency_edges=edges,
                dependency_discharges=dependency_discharges,
                memory_version_graph=memory,
                expected_member_cutpoints=members,
                expected_dependency_members=dependency_members,
                entry_facts=entries,
                required_exports=tuple(
                    row for row in export_inventory if row.cutpoint in members
                ),
                profile_sha256=profile_sha256,
                budgets=budgets,
                context=checker_context,
            )
            reports.append(report)
        issues = orchestration_issues
        for report in reports:
            issues.extend(report["issues"])
        status = _status(issues)
        body = {
            "format": INDUCTIVE_AUTHORITY_PHASE_V2_FORMAT,
            "status": status,
            "authorizing": status == "complete",
            "proposal_id": proposal.get("id"),
            "binary": summaries.binary.to_payload(),
            "profile_sha256": profile_sha256,
            "root_unit_ids": expected_roots,
            "memory_version_graph_id": memory.graph_id,
            "transition_inventory_id": inventory.inventory_id,
            "certificate_reports": reports,
            "issues": _canonical_issues(issues),
            "checked_exports": [
                export
                for report in reports
                for export in report["checked_exports"]
            ],
            "dependency_discharges": [
                row.to_payload() for row in sorted(set(dependency_discharges))
            ],
            "counts": {
                "certificates": len(reports),
                "complete_certificates": sum(
                    report["status"] == "complete" for report in reports
                ),
                "structural_units": len(expected_units),
                "reachable_units": len(reachable),
            },
        }
        return {**body, "id": "inductive-authority-v2:" + canonical_sha256(body)}
    except (InvariantCertificateV2Error, KeyError, TypeError, ValueError) as exc:
        body = {
            "format": INDUCTIVE_AUTHORITY_PHASE_V2_FORMAT,
            "status": "violated",
            "authorizing": False,
            "proposal_id": proposal.get("id") if isinstance(proposal, Mapping) else None,
            "certificate_reports": [],
            "checked_exports": [],
            "issues": [{
                "status": "violated",
                "code": "inductive_authority_input_contradiction",
                "detail": str(exc),
            }],
            "counts": {"certificates": 0, "complete_certificates": 0, "structural_units": 0},
        }
        return {**body, "id": "inductive-authority-v2:" + canonical_sha256(body)}


def _derive_checked_graph_inputs(
    *,
    units: Sequence[Mapping[str, Any]],
    summaries: Sequence[TransitionSummaryV2],
    interprocedural: Mapping[str, Any],
    memory: MemoryVersionGraphV2,
) -> tuple[
    tuple[DependencyNodeV2, ...],
    tuple[DependencyEdgeV2, ...],
    tuple[TransitionControlWitnessV2, ...],
    list[dict[str, Any]],
]:
    exact = exact_control_inventory_v2(units)
    by_unit = {summary.unit.unit_id: summary for summary in summaries}
    by_rva = {summary.unit.rva_start: summary.unit.unit_id for summary in summaries}
    exact_indirect = {str(row["id"]): row for row in exact["indirect_exits"]}
    recoveries = {
        str(row.get("id")): row
        for row in interprocedural.get("recovered_targets", [])
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    dependencies: dict[str, DependencyNodeV2] = {}
    issues: list[dict[str, Any]] = []
    witnesses: list[TransitionControlWitnessV2] = []
    for summary in summaries:
        exit_targets: list[ExitTargetSetV2] = []
        summary_dependencies: set[str] = set()
        for exit_row in summary.exits:
            targets: tuple[str, ...] = ()
            exit_dependencies: tuple[str, ...] = ()
            record = exit_row.exact_record.to_value()
            direct_rvas = _exact_target_rvas(record)
            if direct_rvas:
                targets = tuple(
                    sorted(by_rva[rva] for rva in direct_rvas if rva in by_rva)
                )
            elif "indirect" in exit_row.transfer_kind:
                matching = _matching_indirect_exit(
                    summary.unit.unit_id, exit_row, exact_indirect
                )
                recovery = None if matching is None else recoveries.get(matching)
                if (
                    isinstance(recovery, Mapping)
                    and recovery.get("status") == "recovered"
                    and isinstance(recovery.get("target_unit_ids"), list)
                ):
                    targets = tuple(
                        sorted(
                            target
                            for target in recovery["target_unit_ids"]
                            if isinstance(target, str) and target in by_unit
                        )
                    )
                dependency_id = f"indirect-target:{exit_row.exit_id}"
                dependencies[dependency_id] = DependencyNodeV2(
                    dependency_id,
                    "indirect_target",
                    canonical_sha256(exit_row.to_payload()),
                )
                exit_dependencies = (dependency_id,)
                summary_dependencies.add(dependency_id)
                if recovery is None or not targets:
                    issues.append({
                        "status": "incomplete",
                        "code": "indirect_target_certificate_missing",
                        "subject_id": exit_row.exit_id,
                        "source_unit_id": summary.unit.unit_id,
                    })
            if exit_row.source_kind == "external_event":
                external_dependency_id = f"external-site:{exit_row.exit_id}"
                dependencies[external_dependency_id] = DependencyNodeV2(
                    external_dependency_id,
                    "external_site",
                    canonical_sha256(exit_row.to_payload()),
                )
                summary_dependencies.add(external_dependency_id)
                if exit_row.category == "callback":
                    callback_dependency_id = f"callback-entry:{exit_row.exit_id}"
                    dependencies[callback_dependency_id] = DependencyNodeV2(
                        callback_dependency_id,
                        "callback_entry",
                        canonical_sha256(exit_row.to_payload()),
                    )
                    summary_dependencies.add(callback_dependency_id)
            elif exit_row.category == "call":
                call_dependency_id = f"call-summary:{exit_row.exit_id}"
                dependencies[call_dependency_id] = DependencyNodeV2(
                    call_dependency_id,
                    "call_summary",
                    canonical_sha256(exit_row.to_payload()),
                )
                summary_dependencies.add(call_dependency_id)
            exit_targets.append(
                ExitTargetSetV2.create(
                    exit_id=exit_row.exit_id,
                    target_cutpoints=targets,
                    dependency_ids=exit_dependencies,
                )
            )
        for access in summary.memory_accesses:
            dependency_id = f"memory-access:{access.access_id}"
            dependencies[dependency_id] = DependencyNodeV2(
                dependency_id,
                "memory_version",
                canonical_sha256(access.to_payload()),
            )
            summary_dependencies.add(dependency_id)
        witnesses.append(
            TransitionControlWitnessV2.create(
                summary=summary,
                exit_targets=exit_targets,
                dependency_ids=tuple(sorted(summary_dependencies)),
            )
        )
    for issue in exact["issues"]:
        issues.append(dict(issue))
    return (
        tuple(sorted(dependencies.values())),
        (),
        tuple(sorted(witnesses, key=lambda row: row.witness_id)),
        _canonical_issues(issues),
    )


def _bind_control_scc_dependencies(
    *,
    dependencies: Sequence[DependencyNodeV2],
    witnesses: Sequence[TransitionControlWitnessV2],
    components: Sequence[Sequence[str]],
) -> tuple[
    tuple[DependencyNodeV2, ...],
    tuple[DependencyEdgeV2, ...],
    dict[tuple[str, ...], DependencyNodeV2],
]:
    """Bind each structural SCC to only the evidence its transitions consume."""

    by_source = {witness.source_cutpoint: witness for witness in witnesses}
    invariant_by_members: dict[tuple[str, ...], DependencyNodeV2] = {}
    edges: set[DependencyEdgeV2] = set()
    for raw_members in components:
        members = tuple(raw_members)
        invariant = DependencyNodeV2(
            f"control-scc:{canonical_sha256(list(members))[:24]}",
            "invariant",
            canonical_sha256({"control_scc": list(members)}),
        )
        invariant_by_members[members] = invariant
        consumed = {
            dependency
            for member in members
            for witness in (by_source[member],)
            for dependency in (
                *witness.dependency_ids,
                *(
                    dependency
                    for target_set in witness.exit_targets
                    for dependency in target_set.dependency_ids
                ),
            )
        }
        edges.update(
            DependencyEdgeV2(dependency, invariant.node_id, "consumes")
            for dependency in consumed
        )
    return (
        tuple(sorted((*dependencies, *invariant_by_members.values()))),
        tuple(sorted(edges)),
        invariant_by_members,
    )


def _component_entries(
    *,
    members: Sequence[str],
    control_edges: Sequence[tuple[str, str, str, str]],
    incoming_control_edges: Mapping[
        str, Sequence[tuple[str, str, str, str]]
    ] | None = None,
    allowed_sources: Sequence[str] | None = None,
    root_entries: Sequence[EntryFactsV2],
    cutpoint_facts: Mapping[str, Sequence[InvariantFactV2]],
) -> tuple[EntryFactsV2, ...]:
    member_set = frozenset(members)
    allowed = None if allowed_sources is None else frozenset(allowed_sources)
    result = [
        row for row in root_entries if row.target_cutpoint in member_set
    ]
    candidate_edges = (
        control_edges
        if incoming_control_edges is None
        else tuple(
            edge
            for target in members
            for edge in incoming_control_edges.get(target, ())
        )
    )
    for witness_id, exit_id, source, target in candidate_edges:
        if (
            source in member_set
            or target not in member_set
            or (allowed is not None and source not in allowed)
        ):
            continue
        result.append(
            EntryFactsV2(
                entry_id=(
                    f"incoming:{witness_id}:{exit_id}:{source}:{target}"
                ),
                kind="incoming",
                target_cutpoint=target,
                transition_id=witness_id,
                facts=tuple(sorted(cutpoint_facts.get(source, ()))),
                exit_id=exit_id,
            )
        )
    return tuple(sorted(result, key=lambda row: row.entry_id))


def _index_incoming_control_edges(
    control_edges: Sequence[tuple[str, str, str, str]],
) -> dict[str, tuple[tuple[str, str, str, str], ...]]:
    rows: dict[str, list[tuple[str, str, str, str]]] = {}
    for edge in control_edges:
        rows.setdefault(edge[3], []).append(edge)
    return {
        target: tuple(sorted(edges)) for target, edges in rows.items()
    }


def _rooted_control_closure(
    roots: Sequence[str],
    control_edges: Sequence[tuple[str, str, str, str]],
) -> frozenset[str]:
    outgoing: dict[str, set[str]] = {}
    for _witness_id, _exit_id, source, target in control_edges:
        outgoing.setdefault(source, set()).add(target)
    reached = set(roots)
    pending = list(sorted(reached))
    while pending:
        source = pending.pop()
        for target in sorted(outgoing.get(source, ())):
            if target not in reached:
                reached.add(target)
                pending.append(target)
    return frozenset(reached)


def _matching_indirect_exit(
    unit_id: str,
    exit_row: TransitionExitV2,
    exact: Mapping[str, Mapping[str, Any]],
) -> str | None:
    for exit_id, row in exact.items():
        if row.get("source_unit_id") != unit_id:
            continue
        if exit_row.source_kind == "outcome" and row.get("source_event_index") is None:
            return exit_id
        if exit_row.source_kind == "external_event" and row.get(
            "source_event_index"
        ) == exit_row.source_index:
            return exit_id
    return None


def _exact_target_rvas(value: Any) -> tuple[int, ...]:
    if not isinstance(value, Mapping):
        return ()
    values = {
        value[key]
        for key in ("target_rva", "fallthrough_rva", "continuation_rva", "return_rva")
        if isinstance(value.get(key), int) and not isinstance(value.get(key), bool)
    }
    direct = value.get("direct_targets")
    if isinstance(direct, list):
        values.update(
            item for item in direct if isinstance(item, int) and not isinstance(item, bool)
        )
    return tuple(sorted(value for value in values if value >= 0))


def _summary_inventory(
    value: TransitionSummaryInventoryV2 | Mapping[str, Any],
) -> TransitionSummaryInventoryV2:
    return value if isinstance(value, TransitionSummaryInventoryV2) else TransitionSummaryInventoryV2.parse(value)


def _memory_graph(
    value: MemoryVersionGraphV2 | Mapping[str, Any],
) -> MemoryVersionGraphV2:
    return value if isinstance(value, MemoryVersionGraphV2) else MemoryVersionGraphV2.parse(value)


def _validate_common_inputs(
    units: Sequence[Mapping[str, Any]],
    summaries: TransitionSummaryInventoryV2,
    memory: MemoryVersionGraphV2,
    profile_sha256: str,
) -> None:
    if len(profile_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in profile_sha256):
        raise InductiveAuthorityPhaseV2Error("profile binding is not SHA-256")
    unit_ids = {str(row.get("id")) for row in units}
    if unit_ids != {summary.unit.unit_id for summary in summaries.summaries}:
        raise InductiveAuthorityPhaseV2Error("transition summaries do not cover exact units")
    if memory.binary != summaries.binary:
        raise InductiveAuthorityPhaseV2Error("memory and transition binary bindings differ")
    if memory.transition_summary_ids != tuple(
        sorted(summary.summary_id for summary in summaries.summaries)
    ):
        raise InductiveAuthorityPhaseV2Error("memory graph is stale for transition summaries")


def _structural_universe_sha256(units: Sequence[Mapping[str, Any]]) -> str:
    return canonical_sha256({"units": list(units)})


def _strings(value: Any, context: str) -> tuple[str, ...]:
    rows = _array(value)
    if not all(isinstance(row, str) and row for row in rows):
        raise InductiveAuthorityPhaseV2Error(f"{context} must contain strings")
    result = tuple(rows)
    if result != tuple(sorted(set(result))):
        raise InductiveAuthorityPhaseV2Error(f"{context} is noncanonical")
    return result


def _array(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise InductiveAuthorityPhaseV2Error("expected a JSON array")
    return value


def _canonical_issues(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        {canonical_json_bytes(row): dict(row) for row in rows}.values(),
        key=canonical_json_bytes,
    )


def _status(issues: Sequence[Mapping[str, Any]]) -> str:
    if any(row.get("status") == "violated" for row in issues):
        return "violated"
    if issues:
        return "incomplete"
    return "complete"


__all__ = [
    "INDUCTIVE_AUTHORITY_PHASE_V2_FORMAT",
    "INDUCTIVE_PROPOSAL_PHASE_V2_FORMAT",
    "InductiveAuthorityPhaseV2Error",
    "build_inductive_authority_proposals_v2",
    "check_inductive_authority_proposals_v2",
]
