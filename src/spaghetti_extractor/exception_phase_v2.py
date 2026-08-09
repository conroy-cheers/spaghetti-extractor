"""Dependency-narrow exceptional-control proposal and replay phase."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .exception_invariants_v2 import (
    EXCEPTION_INVARIANT_CERTIFICATE_V2_FORMAT,
    EXCEPTION_INVARIANT_PROPOSAL_V2_FORMAT,
    canonical_sha256,
    check_exception_invariant_certificate_v2,
    synthesize_exception_invariant_certificate_v2,
)


EXCEPTION_PROPOSAL_PHASE_V2_FORMAT = (
    "spaghetti-extractor-exception-invariant-proposal-phase-v2"
)
EXCEPTION_REPLAY_PHASE_V2_FORMAT = (
    "spaghetti-extractor-exception-invariant-replay-phase-v2"
)


class ExceptionPhaseV2Error(ValueError):
    """Exceptional-control phase input is malformed."""


def derive_checked_exception_reports_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    graph: Mapping[str, Any],
    binary_sha256: str,
    machine_ir_sha256: str,
    submitted_evidence: Sequence[Mapping[str, Any]] = (),
    seh_inventories: Sequence[Mapping[str, Any]] = (),
) -> tuple[dict[str, Any], dict[str, Any], tuple[Mapping[str, Any], ...]]:
    """Synthesize and independently replay exceptional SCC certificates."""

    required_sccs = derive_faulting_rooted_sccs_v2(units=units, graph=graph)
    submitted_by_members: dict[
        tuple[str, ...], list[tuple[int, Mapping[str, Any]]]
    ] = {}
    submitted_results: list[dict[str, Any]] = []
    malformed_submitted_reports: list[tuple[int, Mapping[str, Any]]] = []
    for index, evidence in enumerate(submitted_evidence):
        certificate = _submitted_exception_certificate(evidence)
        if certificate is None:
            submitted_results.append({
                "submission_index": index,
                "status": "incomplete",
                "reason_code": "submitted_exception_certificate_missing",
            })
            continue
        members = _certificate_members(certificate)
        if members is None:
            report = check_exception_invariant_certificate_v2(
                certificate,
                units=units,
                binary_sha256=binary_sha256,
                machine_ir_sha256=machine_ir_sha256,
                seh_inventories=seh_inventories,
            )
            submitted_results.append({
                "submission_index": index,
                "status": report["status"],
                "reason_code": "submitted_exception_scc_binding_corrupt",
                "certificate_sha256": report["certificate_sha256"],
            })
            malformed_submitted_reports.append((index, report))
            continue
        submitted_by_members.setdefault(members, []).append((index, certificate))

    proposal_rows: list[dict[str, Any]] = []
    replay_rows: list[dict[str, Any]] = [
        {
            "scc_id": None,
            "source": "submitted",
            "submission_index": index,
            "report": report,
        }
        for index, report in malformed_submitted_reports
    ]
    authority_reports: list[Mapping[str, Any]] = [
        report for _index, report in malformed_submitted_reports
    ]
    required_member_sets = {tuple(row["members"]) for row in required_sccs}
    for scc in required_sccs:
        members = tuple(scc["members"])
        submitted_replays: list[tuple[int, Mapping[str, Any]]] = []
        for index, certificate in submitted_by_members.get(members, ()):
            report = check_exception_invariant_certificate_v2(
                certificate,
                units=units,
                binary_sha256=binary_sha256,
                machine_ir_sha256=machine_ir_sha256,
                seh_inventories=seh_inventories,
            )
            submitted_replays.append((index, report))
            submitted_results.append({
                "submission_index": index,
                "scc_id": scc["id"],
                "status": report["status"],
                "reason_code": None,
                "certificate_sha256": report["certificate_sha256"],
            })

        violated = sorted(
            (
                (index, report)
                for index, report in submitted_replays
                if report.get("status") == "violated"
            ),
            key=lambda item: (item[0], str(item[1].get("certificate_sha256"))),
        )
        complete = sorted(
            (
                (index, report)
                for index, report in submitted_replays
                if report.get("status") == "complete"
            ),
            key=lambda item: (str(item[1].get("certificate_sha256")), item[0]),
        )
        if violated:
            for index, report in violated:
                replay_rows.append({
                    "scc_id": scc["id"],
                    "source": "submitted",
                    "submission_index": index,
                    "report": report,
                })
                authority_reports.append(report)
            continue
        if complete:
            index, report = complete[0]
            replay_rows.append({
                "scc_id": scc["id"],
                "source": "submitted",
                "submission_index": index,
                "report": report,
            })
            authority_reports.append(report)
            continue

        proposal = synthesize_exception_invariant_certificate_v2(
            units=units,
            member_ids=members,
            binary_sha256=binary_sha256,
            machine_ir_sha256=machine_ir_sha256,
        )
        proposal_rows.append({
            "scc_id": scc["id"],
            "members": list(members),
            "proposal": proposal,
        })
        report = check_exception_invariant_certificate_v2(
            _object(
                proposal.get("certificate"),
                "synthesized exception certificate",
            ),
            units=units,
            binary_sha256=binary_sha256,
            machine_ir_sha256=machine_ir_sha256,
            seh_inventories=seh_inventories,
        )
        replay_rows.append({
            "scc_id": scc["id"],
            "source": "synthesized",
            "report": report,
        })
        authority_reports.append(report)

    for members, entries in sorted(submitted_by_members.items()):
        if members in required_member_sets:
            continue
        for index, _certificate in entries:
            submitted_results.append({
                "submission_index": index,
                "status": "violated",
                "reason_code": "submitted_exception_scc_not_required",
                "members": list(members),
            })

    proposal_body = {
        "format": EXCEPTION_PROPOSAL_PHASE_V2_FORMAT,
        "binary_sha256": binary_sha256,
        "machine_ir_sha256": machine_ir_sha256,
        "uses_bounded_paths": False,
        "required_sccs": required_sccs,
        "proposals": proposal_rows,
    }
    replay_body = {
        "format": EXCEPTION_REPLAY_PHASE_V2_FORMAT,
        "binary_sha256": binary_sha256,
        "machine_ir_sha256": machine_ir_sha256,
        "uses_bounded_paths": False,
        "seh_inventory_sha256s": sorted(
            canonical_sha256(row) for row in seh_inventories
        ),
        "submitted_evidence": sorted(
            submitted_results,
            key=lambda row: (
                int(row["submission_index"]),
                str(row.get("certificate_sha256", "")),
            ),
        ),
        "reports": replay_rows,
    }
    proposals = {
        **proposal_body,
        "id": "exception-proposals-v2:" + canonical_sha256(proposal_body),
    }
    replays = {
        **replay_body,
        "id": "exception-replays-v2:" + canonical_sha256(replay_body),
    }
    return proposals, replays, tuple(authority_reports)


def derive_faulting_rooted_sccs_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    graph: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Return deterministic rooted cyclic SCCs containing semantic faults."""

    by_id = {str(unit.get("id")): unit for unit in units}
    roots = {
        str(row.get("unit_id"))
        for row in graph.get("roots", ())
        if isinstance(row, Mapping) and str(row.get("unit_id")) in by_id
    }
    adjacency: dict[str, set[str]] = {unit_id: set() for unit_id in by_id}
    for edge in graph.get("direct_edges", ()):
        if not isinstance(edge, Mapping):
            continue
        source = str(edge.get("source_unit_id"))
        target = str(edge.get("target_unit_id"))
        if source in by_id and target in by_id:
            adjacency[source].add(target)
    for exit_row in graph.get("indirect_exits", ()):
        if not isinstance(exit_row, Mapping) or exit_row.get("status") != "complete":
            continue
        source = str(exit_row.get("source_unit_id"))
        if source not in by_id:
            continue
        for target_value in exit_row.get("target_unit_ids", ()):
            target = str(target_value)
            if target in by_id:
                adjacency[source].add(target)

    reachable: set[str] = set()
    pending = sorted(roots, reverse=True)
    while pending:
        unit_id = pending.pop()
        if unit_id in reachable:
            continue
        reachable.add(unit_id)
        pending.extend(sorted(adjacency[unit_id] - reachable, reverse=True))

    components = _strongly_connected_components({
        unit_id: adjacency[unit_id] & reachable
        for unit_id in sorted(reachable)
    })
    result: list[dict[str, Any]] = []
    for members in components:
        first_member = next(iter(members), None)
        if first_member is None:
            continue
        cyclic = len(members) > 1 or first_member in adjacency[first_member]
        fault_sites = []
        for unit_id in members:
            semantics = by_id[unit_id].get("semantics")
            faults = semantics.get("faults") if isinstance(semantics, Mapping) else None
            if not isinstance(faults, list):
                continue
            fault_sites.extend(
                {"unit_id": unit_id, "fault_index": index}
                for index, fault in enumerate(faults)
                if isinstance(fault, Mapping)
            )
        if not cyclic or not fault_sites:
            continue
        body = {"members": list(members), "fault_sites": fault_sites}
        result.append({
            **body,
            "id": "exception-scc-v2:" + canonical_sha256(body),
        })
    return sorted(result, key=lambda row: (tuple(row["members"]), row["id"]))


def _strongly_connected_components(
    adjacency: Mapping[str, set[str]],
) -> list[tuple[str, ...]]:
    index = 0
    indexes: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for target in sorted(adjacency.get(node, set())):
            if target not in indexes:
                visit(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[target])
        if lowlinks[node] != indexes[node]:
            return
        members: list[str] = []
        while True:
            member = stack.pop()
            on_stack.remove(member)
            members.append(member)
            if member == node:
                break
        components.append(tuple(sorted(members)))

    for node in sorted(adjacency):
        if node not in indexes:
            visit(node)
    return sorted(components)


def _submitted_exception_certificate(
    evidence: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    if evidence.get("format") == EXCEPTION_INVARIANT_CERTIFICATE_V2_FORMAT:
        return evidence
    certificate = evidence.get("certificate")
    if isinstance(certificate, Mapping):
        return certificate
    if evidence.get("format") == EXCEPTION_INVARIANT_PROPOSAL_V2_FORMAT:
        return None
    return None


def _certificate_members(
    certificate: Mapping[str, Any],
) -> tuple[str, ...] | None:
    scc = certificate.get("scc")
    members = scc.get("members") if isinstance(scc, Mapping) else None
    if (
        not isinstance(members, list)
        or not members
        or not all(isinstance(value, str) and value for value in members)
    ):
        return None
    return tuple(sorted(members))


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExceptionPhaseV2Error(f"{context} must be an object")
    return value


__all__ = [
    "EXCEPTION_PROPOSAL_PHASE_V2_FORMAT",
    "EXCEPTION_REPLAY_PHASE_V2_FORMAT",
    "ExceptionPhaseV2Error",
    "derive_checked_exception_reports_v2",
    "derive_faulting_rooted_sccs_v2",
]
