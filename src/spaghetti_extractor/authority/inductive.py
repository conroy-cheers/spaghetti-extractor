"""Native SCC-local inductive authority over checked v3 records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    CanonicalValueV3,
    canonical_json_bytes_v3,
)
from ..phase_framework_v3 import PhaseContextV3, SccWorkItemV3, map_sccs
from ._schema import fail, sorted_records, stable_id, text
from .inductive_records import (
    INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3,
    INDUCTIVE_AUTHORITY_CHECK_V3_FORMAT,
    INDUCTIVE_AUTHORITY_CODEC_V3,
    INDUCTIVE_AUTHORITY_RECORD_V3_SCHEMA,
    INDUCTIVE_INPUT_CODEC_V3,
    INDUCTIVE_INPUT_CONFIG_V3_SCHEMA,
    INDUCTIVE_INPUT_CUTPOINT_V3_SCHEMA,
    CutpointInvariantV3,
    DependencyDischargeV3,
    EntryFactsV3,
    ExportRequirementV3,
    InductiveAuthorityBodyV3,
    InductiveAuthorityRecordV3,
    InductiveCertificateReportV3,
    InductiveConfigV3,
    InductiveCutpointV3,
    InductiveIssueV3,
    InvariantBudgetsV3,
    InvariantFactV3,
)
from .memory_records import MEMORY_VERSION_CODEC_V3, MemoryVersionRecordV3
from .semantic_index import SEMANTIC_INDEX_CODEC_V3, SemanticIndexRecordV3
from .target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    IndirectTargetCertificateV3,
    flatten_indirect_target_certificates_v3,
)
from .transition_records import (
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)


@dataclass(frozen=True)
class _Inputs:
    semantic_units: tuple[SemanticIndexRecordV3, ...]
    summaries: tuple[TransitionSummaryRecordV3, ...]
    memory: MemoryVersionRecordV3
    target_certificates: tuple[IndirectTargetCertificateV3, ...]
    config: InductiveConfigV3
    cutpoints: tuple[InductiveCutpointV3, ...]


def _optional_input_record(
    context: PhaseContextV3, input_name: str, record_id: str
) -> ArtifactRecordV3 | None:
    return context.optional_record(input_name, record_id)


def _read_scc_inputs(
    context: PhaseContextV3,
    *,
    scc_id: str,
    unit_ids: tuple[str, ...],
) -> _Inputs:
    semantic_records = tuple(
        context.record("semantic_index", unit_id) for unit_id in unit_ids
    )
    summary_records = tuple(
        context.record("transition_summaries", unit_id) for unit_id in unit_ids
    )
    memory_record = context.record("memory_versions", scc_id)
    target_certificate_records = tuple(
        context.record("target_certificates", unit_id) for unit_id in unit_ids
    )
    config_record = context.record("inductive_inputs", "inductive-config")
    config_value = context.typed_record(
        "inductive_inputs", config_record.record_id, INDUCTIVE_INPUT_CODEC_V3
    ).value
    if not isinstance(config_value, InductiveConfigV3):
        fail(
            "inductive_config_cardinality",
            "inductive-config does not decode as the global SCC configuration",
            "emit one typed native v3 inductive config record",
        )

    cutpoint_records = tuple(
        record
        for unit_id in unit_ids
        if (record := _optional_input_record(context, "inductive_inputs", unit_id))
        is not None
    )
    cutpoints: list[InductiveCutpointV3] = []
    for record in cutpoint_records:
        value = context.typed_record(
            "inductive_inputs", record.record_id, INDUCTIVE_INPUT_CODEC_V3
        ).value
        if not isinstance(value, InductiveCutpointV3):
            fail(
                "inductive_cutpoint_kind_mismatch",
                f"inductive input {record.record_id!r} is not a cutpoint proposal",
                "emit one cutpoint record for each proposed local invariant",
            )
        cutpoints.append(value)

    unit_set = set(unit_ids)
    config = InductiveConfigV3(
        record_id="inductive-config",
        profile_sha256=config_value.profile_sha256,
        root_unit_ids=tuple(
            unit_id for unit_id in config_value.root_unit_ids if unit_id in unit_set
        ),
        root_entry_facts=tuple(
            row
            for row in config_value.root_entry_facts
            if row.target_cutpoint in unit_set
        ),
        required_exports=tuple(
            row for row in config_value.required_exports if row.cutpoint in unit_set
        ),
        dependency_discharges=config_value.dependency_discharges,
        budgets=config_value.budgets,
    )
    semantic_units = tuple(
        context.typed_record(
            "semantic_index", record.record_id, SEMANTIC_INDEX_CODEC_V3
        ).value
        for record in semantic_records
    )
    summaries = tuple(
        context.typed_record(
            "transition_summaries", record.record_id, TRANSITION_SUMMARY_CODEC_V3
        ).value
        for record in summary_records
    )
    memory = context.typed_record(
        "memory_versions", memory_record.record_id, MEMORY_VERSION_CODEC_V3
    ).value
    return _Inputs(
        semantic_units=semantic_units,
        summaries=summaries,
        memory=memory,
        target_certificates=flatten_indirect_target_certificates_v3(
            target_certificate_records
        ),
        config=config,
        cutpoints=tuple(sorted(cutpoints, key=lambda row: row.record_id)),
    )


def _issue(
    status: str,
    code: str,
    subject_id: str,
    *,
    dependencies: tuple[str, ...] = (),
    detail: Any | None = None,
) -> InductiveIssueV3:
    return InductiveIssueV3(
        status=status,
        code=code,
        subject_id=subject_id,
        dependencies=tuple(sorted(set(dependencies))),
        detail=None if detail is None else CanonicalValueV3.of(detail),
    )


def _canonical_issues(
    values: list[InductiveIssueV3] | tuple[InductiveIssueV3, ...],
) -> tuple[InductiveIssueV3, ...]:
    return tuple(
        sorted(
            set(values),
            key=lambda row: canonical_json_bytes_v3(row.to_payload()),
        )
    )


def _status(issues: tuple[InductiveIssueV3, ...]) -> str:
    if any(row.status == "violated" for row in issues):
        return "violated"
    return "incomplete" if issues else "complete"


def _predicate_values(fact: InvariantFactV3) -> tuple[Any, ...] | None:
    row = fact.predicate.to_value()
    assert isinstance(row, Mapping)
    if row["kind"] == "exact":
        return (row["value"],)
    if row["kind"] == "finite":
        values = row["values"]
        assert isinstance(values, list)
        return tuple(values)
    return None


def _predicate_accepts(fact: InvariantFactV3, value: Any) -> bool:
    row = fact.predicate.to_value()
    assert isinstance(row, Mapping)
    kind = row["kind"]
    if kind == "exact":
        return canonical_json_bytes_v3(value) == canonical_json_bytes_v3(row["value"])
    if kind == "finite":
        return canonical_json_bytes_v3(value) in {
            canonical_json_bytes_v3(item) for item in row["values"]
        }
    if kind == "range":
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and row["lower"] <= value <= row["upper"]
        )
    if kind == "congruence":
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value % row["modulus"] == row["remainder"]
        )
    return isinstance(value, str) and value in row["states"]


def _predicate_implies(source: InvariantFactV3, target: InvariantFactV3) -> bool:
    if source.subject != target.subject:
        return False
    source_values = _predicate_values(source)
    if source_values is not None:
        return all(_predicate_accepts(target, value) for value in source_values)
    source_row = source.predicate.to_value()
    target_row = target.predicate.to_value()
    assert isinstance(source_row, Mapping) and isinstance(target_row, Mapping)
    if source_row["kind"] == target_row["kind"] == "range":
        return (
            target_row["lower"] <= source_row["lower"]
            and source_row["upper"] <= target_row["upper"]
        )
    if source_row["kind"] == target_row["kind"] == "congruence":
        return (
            source_row["modulus"] % target_row["modulus"] == 0
            and source_row["remainder"] % target_row["modulus"]
            == target_row["remainder"]
        )
    if source_row["kind"] == target_row["kind"] == "resource_lifecycle":
        return (
            source_row["resource_id"] == target_row["resource_id"]
            and set(source_row["states"]).issubset(target_row["states"])
        )
    return canonical_json_bytes_v3(source_row) == canonical_json_bytes_v3(
        target_row
    )


def _constant_expression(value: Any) -> tuple[bool, Any]:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return False, None
    if set(value) not in ({"op", "value"}, {"op", "value", "width"}):
        return False, None
    return True, value.get("value")


def _memory_subject(subject: str) -> tuple[int, int] | None:
    parts = subject.split(":")
    if len(parts) != 3 or parts[0] != "memory-range":
        return None
    try:
        start = int(parts[1], 0)
        end = int(parts[2], 0)
    except ValueError:
        return None
    return (start, end) if 0 <= start < end <= 1 << 32 else None


def _transition_value_for_subject(
    summary: TransitionSummaryRecordV3,
    subject: str,
) -> tuple[str, Any | None]:
    """Return ``constant``, ``preserved``, or ``unknown`` for one subject."""

    if subject.startswith("register:"):
        register = subject.removeprefix("register:")
        writes = tuple(
            row
            for row in summary.outputs
            if row.category == "register" and row.destination == register
        )
        if not writes:
            return "preserved", None
        if len(writes) != 1:
            return "unknown", None
        known, value = _constant_expression(writes[0].value.to_value())
        return ("constant", value) if known else ("unknown", None)

    memory_range = _memory_subject(subject)
    if memory_range is None:
        return "unknown", None
    start, end = memory_range
    overlapping = []
    for access in summary.memory_accesses:
        if access.memory_kind not in {"write", "read_write"}:
            continue
        known_address, address = _constant_expression(access.address.to_value())
        if not known_address or not isinstance(address, int):
            return "unknown", None
        access_end = address + access.width_bytes
        if address < end and start < access_end:
            overlapping.append(access)
    if not overlapping:
        return "preserved", None
    if (
        len(overlapping) != 1
        or overlapping[0].width_bytes != end - start
        or _constant_expression(overlapping[0].address.to_value()) != (True, start)
        or overlapping[0].value is None
    ):
        return "unknown", None
    known, value = _constant_expression(overlapping[0].value.to_value())
    return ("constant", value) if known else ("unknown", None)


def _fact_witness(
    *,
    source_unit_id: str,
    target_unit_id: str,
    fact: InvariantFactV3,
    method: str,
    evidence_id: str,
) -> str:
    return stable_id(
        "inductive-preservation",
        {
            "source_unit_id": source_unit_id,
            "target_unit_id": target_unit_id,
            "fact_id": fact.fact_id,
            "method": method,
            "evidence_id": evidence_id,
        },
    )


def _budget_issues(
    inputs: _Inputs, invariants: Mapping[str, tuple[InvariantFactV3, ...]]
) -> list[InductiveIssueV3]:
    budgets = inputs.config.budgets
    issues: list[InductiveIssueV3] = []
    if len(inputs.summaries) > budgets.maximum_members:
        issues.append(
            _issue(
                "incomplete",
                "inductive_member_budget_exceeded",
                inputs.memory.record_id,
                detail={"count": len(inputs.summaries), "limit": budgets.maximum_members},
            )
        )
    transition_count = sum(len(row.exits) for row in inputs.summaries)
    if transition_count > budgets.maximum_transitions:
        issues.append(
            _issue(
                "incomplete",
                "inductive_transition_budget_exceeded",
                inputs.memory.record_id,
                detail={"count": transition_count, "limit": budgets.maximum_transitions},
            )
        )
    for unit_id, facts in invariants.items():
        if len(facts) > budgets.maximum_facts_per_cutpoint:
            issues.append(
                _issue(
                    "incomplete",
                    "inductive_fact_budget_exceeded",
                    unit_id,
                    detail={
                        "count": len(facts),
                        "limit": budgets.maximum_facts_per_cutpoint,
                    },
                )
            )
        for fact in facts:
            row = fact.predicate.to_value()
            assert isinstance(row, Mapping)
            if (
                row["kind"] == "finite"
                and len(row["values"]) > budgets.maximum_finite_values
            ):
                issues.append(
                    _issue(
                        "incomplete",
                        "inductive_finite_value_budget_exceeded",
                        fact.fact_id,
                    )
                )
            if (
                row["kind"] == "resource_lifecycle"
                and len(row["states"]) > budgets.maximum_resource_states
            ):
                issues.append(
                    _issue(
                        "incomplete",
                        "inductive_resource_state_budget_exceeded",
                        fact.fact_id,
                    )
                )
    if len(inputs.config.dependency_discharges) > budgets.maximum_dependencies:
        issues.append(
            _issue(
                "incomplete",
                "inductive_dependency_budget_exceeded",
                inputs.memory.record_id,
            )
        )
    return issues


def _check_input_bindings(inputs: _Inputs) -> list[InductiveIssueV3]:
    issues: list[InductiveIssueV3] = []
    semantic_by_id = {row.record_id: row for row in inputs.semantic_units}
    summary_by_id = {row.record_id: row for row in inputs.summaries}
    if set(semantic_by_id) != set(summary_by_id):
        return [
            _issue(
                "violated",
                "inductive_semantic_transition_inventory_contradiction",
                inputs.memory.record_id,
            )
        ]
    for unit_id in sorted(semantic_by_id):
        semantic = semantic_by_id[unit_id]
        summary = summary_by_id[unit_id]
        if (
            semantic.unit_sha256 != summary.unit_sha256
            or semantic.pe_sha256 != summary.pe_sha256
            or semantic.unit_ir_sha256 != summary.unit_ir_sha256
            or semantic.rva_start != summary.rva_start
            or semantic.rva_end != summary.rva_end
        ):
            issues.append(
                _issue(
                    "violated",
                    "semantic_transition_binding_mismatch",
                    unit_id,
                )
            )
        if semantic.unit_status != "qualified":
            issues.append(
                _issue(
                    "incomplete",
                    "semantic_unit_not_qualified",
                    unit_id,
                )
            )
        if summary.status != "complete":
            issues.append(
                _issue(
                    "incomplete",
                    "transition_summary_not_complete",
                    summary.summary_id,
                    dependencies=tuple(
                        row.effect_id for row in summary.unsupported_effects
                    ),
                )
            )
    pe_sha256s = {row.pe_sha256 for row in inputs.summaries}
    if len(pe_sha256s) != 1 or inputs.memory.binary.pe_sha256 not in pe_sha256s:
        issues.append(
            _issue(
                "violated",
                "memory_transition_binary_binding_mismatch",
                inputs.memory.record_id,
            )
        )
    expected_summary_ids = tuple(sorted(row.summary_id for row in inputs.summaries))
    if inputs.memory.transition_summary_ids != expected_summary_ids:
        issues.append(
            _issue(
                "violated",
                "memory_transition_inventory_contradiction",
                inputs.memory.record_id,
                detail={
                    "expected": list(expected_summary_ids),
                    "observed": list(inputs.memory.transition_summary_ids),
                },
            )
        )
    if inputs.memory.status != "complete":
        complete_target_sources = {
            row.source_unit_id
            for row in inputs.target_certificates
            if row.status == "complete" and row.authorizing
        }
        for row in inputs.memory.issues:
            if (
                row.code == "indirect_control_requires_target_certificate"
                and row.subject_id in complete_target_sources
            ):
                continue
            issues.append(
                _issue(
                    row.status,
                    row.code,
                    row.subject_id,
                    detail=row.detail.to_value(),
                )
            )
    expected_access_ids = {
        access.access_id
        for summary in inputs.summaries
        for access in summary.memory_accesses
    }
    observed_access_ids = {row.access_id for row in inputs.memory.access_versions}
    if expected_access_ids != observed_access_ids:
        issues.append(
            _issue(
                "violated",
                "memory_access_inventory_contradiction",
                inputs.memory.record_id,
                detail={
                    "missing": sorted(expected_access_ids - observed_access_ids),
                    "extra": sorted(observed_access_ids - expected_access_ids),
                },
            )
        )
    return issues


def _check_targets(
    inputs: _Inputs,
) -> tuple[list[InductiveIssueV3], tuple[str, ...], dict[str, tuple[str, ...]]]:
    issues: list[InductiveIssueV3] = []
    expected = {
        occurrence.exit_id: (semantic.record_id, occurrence)
        for semantic in inputs.semantic_units
        for occurrence in semantic.indirect_exits
    }
    observed = {row.exit_id: row for row in inputs.target_certificates}
    if set(expected) != set(observed):
        issues.append(
            _issue(
                "violated",
                "indirect_target_inventory_contradiction",
                inputs.memory.record_id,
                detail={
                    "missing": sorted(set(expected) - set(observed)),
                    "extra": sorted(set(observed) - set(expected)),
                },
            )
        )
    target_witnesses: list[str] = []
    targets_by_source: dict[str, set[str]] = {}
    for exit_id in sorted(set(expected).intersection(observed)):
        source_unit_id, occurrence = expected[exit_id]
        certificate = observed[exit_id]
        if (
            certificate.source_unit_id != source_unit_id
            or certificate.source_unit_sha256
            != next(
                row.unit_sha256
                for row in inputs.semantic_units
                if row.record_id == source_unit_id
            )
            or certificate.source_rva
            != next(
                row.rva_start
                for row in inputs.semantic_units
                if row.record_id == source_unit_id
            )
            or certificate.source_event_index != occurrence.event_index
            or certificate.transfer_kind != occurrence.transfer_kind
            or certificate.target_expression != occurrence.target_expression
        ):
            issues.append(
                _issue(
                    "violated",
                    "indirect_target_binding_contradiction",
                    exit_id,
                )
            )
            continue
        if certificate.status != "complete" or not certificate.authorizing:
            issues.append(
                _issue(
                    "violated"
                    if certificate.status == "violated"
                    else "incomplete",
                    (
                        certificate.primary_blocker.code
                        if certificate.primary_blocker is not None
                        else "indirect_target_certificate_not_complete"
                    ),
                    exit_id,
                )
            )
            continue
        target_witnesses.append(
            certificate.certificate_sha256
        )
        targets_by_source.setdefault(source_unit_id, set()).update(
            certificate.target_unit_ids
        )
    return (
        issues,
        tuple(sorted(target_witnesses)),
        {key: tuple(sorted(value)) for key, value in targets_by_source.items()},
    )


def _check_initiation(
    inputs: _Inputs,
    invariants: Mapping[str, tuple[InvariantFactV3, ...]],
) -> tuple[list[InductiveIssueV3], tuple[str, ...]]:
    issues: list[InductiveIssueV3] = []
    witnesses: list[str] = []
    entries_by_target: dict[str, list[EntryFactsV3]] = {}
    for entry in inputs.config.root_entry_facts:
        if entry.kind == "root":
            entries_by_target.setdefault(entry.target_cutpoint, []).append(entry)
    for root in inputs.config.root_unit_ids:
        entries = entries_by_target.get(root, [])
        if not entries:
            issues.append(_issue("incomplete", "root_entry_facts_missing", root))
            continue
        if len(entries) != 1:
            issues.append(_issue("violated", "root_entry_facts_ambiguous", root))
            continue
        entry = entries[0]
        supplied = {row.subject: row for row in entry.facts}
        for target_fact in invariants.get(root, ()):
            source_fact = supplied.get(target_fact.subject)
            if source_fact is None or not _predicate_implies(source_fact, target_fact):
                issues.append(
                    _issue(
                        "incomplete",
                        "inductive_initiation_not_established",
                        target_fact.fact_id,
                        dependencies=(entry.entry_id,),
                    )
                )
                continue
            witnesses.append(
                stable_id(
                    "inductive-initiation",
                    {
                        "entry_id": entry.entry_id,
                        "target_unit_id": root,
                        "source_fact_id": source_fact.fact_id,
                        "target_fact_id": target_fact.fact_id,
                    },
                )
            )
    return issues, tuple(sorted(witnesses))


def _check_preservation(
    inputs: _Inputs,
    invariants: Mapping[str, tuple[InvariantFactV3, ...]],
    indirect_targets: Mapping[str, tuple[str, ...]],
) -> tuple[list[InductiveIssueV3], tuple[str, ...], tuple[str, ...], int]:
    issues: list[InductiveIssueV3] = []
    preservation: list[str] = []
    target_witnesses: list[str] = []
    summary_by_id = {row.record_id: row for row in inputs.summaries}
    semantic_by_id = {row.record_id: row for row in inputs.semantic_units}
    unit_by_rva = {row.rva_start: row.record_id for row in inputs.semantic_units}
    local_edges: set[tuple[str, str]] = set()
    outgoing_exact: set[tuple[str, int]] = set()
    for source_id, semantic in semantic_by_id.items():
        for rva in semantic.direct_target_rvas:
            target_id = unit_by_rva.get(rva)
            if target_id is None:
                outgoing_exact.add((source_id, rva))
            else:
                local_edges.add((source_id, target_id))
        for target_id in indirect_targets.get(source_id, ()):
            if target_id in summary_by_id:
                local_edges.add((source_id, target_id))
    for source_id, rva in sorted(outgoing_exact):
        target_witnesses.append(
            stable_id(
                "inductive-exact-outgoing-target",
                {"source_unit_id": source_id, "target_rva": rva},
            )
        )
    for source_id, target_id in sorted(local_edges):
        summary = summary_by_id[source_id]
        source_facts = {row.subject: row for row in invariants.get(source_id, ())}
        target_witnesses.append(
            stable_id(
                "inductive-local-target",
                {
                    "source_unit_id": source_id,
                    "target_unit_id": target_id,
                    "summary_id": summary.summary_id,
                },
            )
        )
        for target_fact in invariants.get(target_id, ()):
            mode, value = _transition_value_for_subject(summary, target_fact.subject)
            if mode == "constant" and _predicate_accepts(target_fact, value):
                preservation.append(
                    _fact_witness(
                        source_unit_id=source_id,
                        target_unit_id=target_id,
                        fact=target_fact,
                        method="constant_output",
                        evidence_id=summary.summary_id,
                    )
                )
                continue
            source_fact = source_facts.get(target_fact.subject)
            if (
                mode == "preserved"
                and source_fact is not None
                and _predicate_implies(source_fact, target_fact)
            ):
                preservation.append(
                    _fact_witness(
                        source_unit_id=source_id,
                        target_unit_id=target_id,
                        fact=target_fact,
                        method="framed_preservation",
                        evidence_id=source_fact.fact_id,
                    )
                )
                continue
            issues.append(
                _issue(
                    "incomplete",
                    "inductive_preservation_not_established",
                    target_fact.fact_id,
                    dependencies=(summary.summary_id,),
                    detail={
                        "source_unit_id": source_id,
                        "target_unit_id": target_id,
                        "effect_class": mode,
                    },
                )
            )

    roots = set(inputs.config.root_unit_ids)
    reachable = set(roots)
    changed = True
    while changed:
        changed = False
        for source_id, target_id in local_edges:
            if source_id in reachable and target_id not in reachable:
                reachable.add(target_id)
                changed = True
    return (
        issues,
        tuple(sorted(preservation)),
        tuple(sorted(target_witnesses)),
        len(reachable),
    )


def _check_exports(
    inputs: _Inputs,
    invariants: Mapping[str, tuple[InvariantFactV3, ...]],
) -> tuple[list[InductiveIssueV3], tuple[str, ...]]:
    issues: list[InductiveIssueV3] = []
    checked: list[str] = []
    for export in inputs.config.required_exports:
        facts = {
            row.subject: row for row in invariants.get(export.cutpoint, ())
        }
        source = facts.get(export.fact.subject)
        if source is None or not _predicate_implies(source, export.fact):
            issues.append(
                _issue(
                    "incomplete",
                    "inductive_export_not_established",
                    export.export_id,
                )
            )
        else:
            checked.append(export.export_id)
    return issues, tuple(sorted(checked))


def _checked_scc_authority(inputs: _Inputs) -> InductiveAuthorityBodyV3:
    invariants = {
        row.record_id: row.invariant.facts for row in inputs.cutpoints
    }
    for unit in inputs.semantic_units:
        invariants.setdefault(unit.record_id, ())

    issues = _check_input_bindings(inputs)
    issues.extend(_budget_issues(inputs, invariants))
    target_issues, proposed_target_witnesses, indirect_targets = _check_targets(inputs)
    issues.extend(target_issues)
    initiation_issues, initiation = _check_initiation(inputs, invariants)
    issues.extend(initiation_issues)
    preservation_issues, preservation, target_witnesses, reachable_count = (
        _check_preservation(inputs, invariants, indirect_targets)
    )
    issues.extend(preservation_issues)
    export_issues, checked_exports = _check_exports(inputs, invariants)
    issues.extend(export_issues)
    canonical = _canonical_issues(issues)
    status = _status(canonical)
    report = InductiveCertificateReportV3.create(
        status=status,
        member_cutpoints=tuple(row.record_id for row in inputs.semantic_units),
        transition_summary_ids=tuple(row.summary_id for row in inputs.summaries),
        initiation_witnesses=initiation,
        preservation_witnesses=preservation,
        target_witnesses=(*proposed_target_witnesses, *target_witnesses),
        checked_export_ids=checked_exports,
        issues=canonical,
    )
    return InductiveAuthorityBodyV3.create(
        status=status,
        authorizing=status == "complete",
        profile_sha256=inputs.config.profile_sha256,
        binary_pe_sha256=(
            inputs.summaries[0].pe_sha256 if inputs.summaries else None
        ),
        memory_version_graph_id=inputs.memory.graph_id,
        transition_summary_ids=tuple(row.summary_id for row in inputs.summaries),
        root_unit_ids=inputs.config.root_unit_ids,
        certificate_reports=(report,),
        checked_exports=checked_exports,
        dependency_discharges=inputs.config.dependency_discharges,
        issues=canonical,
        structural_unit_count=len(inputs.semantic_units),
        reachable_unit_count=reachable_count,
    )


def _missing_config_authority(
    *, scc_id: str, unit_ids: tuple[str, ...]
) -> InductiveAuthorityBodyV3:
    issues = (
        _issue("incomplete", "inductive_config_missing", scc_id),
    )
    return InductiveAuthorityBodyV3.create(
        status="incomplete",
        authorizing=False,
        profile_sha256=None,
        binary_pe_sha256=None,
        memory_version_graph_id=None,
        transition_summary_ids=(),
        root_unit_ids=(),
        certificate_reports=(),
        checked_exports=(),
        dependency_discharges=(),
        issues=issues,
        structural_unit_count=len(unit_ids),
        reachable_unit_count=0,
    )


def _derive_scc_authority(
    context: PhaseContextV3, *, scc_id: str, unit_ids: tuple[str, ...]
) -> InductiveAuthorityRecordV3:
    body = (
        _missing_config_authority(scc_id=scc_id, unit_ids=unit_ids)
        if _optional_input_record(context, "inductive_inputs", "inductive-config")
        is None
        else _checked_scc_authority(
            _read_scc_inputs(context, scc_id=scc_id, unit_ids=unit_ids)
        )
    )
    return InductiveAuthorityRecordV3(
        record_id=scc_id,
        record_kind="scc_authority",
        authority_set_id=body.authority_id,
        status=body.status,
        authorizing=body.authorizing,
        body=CanonicalValueV3.of(body.to_payload()),
    )


def _transform_inductive_scc(
    context: PhaseContextV3, item: SccWorkItemV3
) -> ArtifactRecordV3:
    unit_ids = item.record_ids("semantic_index")
    value = _derive_scc_authority(context, scc_id=item.record_id, unit_ids=unit_ids)
    return INDUCTIVE_AUTHORITY_CODEC_V3.write(item.record_id, value)


def check_inductive_scc_authority_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    outputs = sorted_records(reader.iter_records())
    if not outputs:
        fail(
            "empty_inductive_authority",
            "inductive authority contains no checked SCC records",
            "run the phase over the checked dependency schedule",
        )
    for output in outputs:
        unit_ids = tuple(
            sorted(
                dependency.record_id
                for dependency in output.dependencies
                if dependency.input_name == "semantic_index"
            )
        )
        if not unit_ids:
            fail(
                "incomplete_record_dependencies",
                f"inductive SCC {output.record_id!r} lacks semantic-index dependencies",
                "let the map_sccs phase attach its scheduled semantic units",
            )
        expected = _derive_scc_authority(
            context, scc_id=output.record_id, unit_ids=unit_ids
        )
        if INDUCTIVE_AUTHORITY_CODEC_V3.read(output).value != expected:
            fail(
                "inductive_record_contradiction",
                f"inductive SCC authority {output.record_id!r} is stale",
                "rerun only that SCC and its composition descendants",
            )


INDUCTIVE_AUTHORITY_PHASE_V3 = map_sccs(
    name="inductive-authority-v3",
    version="5",
    input_artifact_kinds={
        "inductive_inputs": "inductive-inputs-v3",
        "memory_versions": "memory-versions-v3",
        "semantic_index": "semantic-index-v3",
        "target_certificates": INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
        "transition_summaries": "transition-summaries-v3",
    },
    output_artifact_kind=INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3,
    transform=_transform_inductive_scc,
    schedule_record_inputs=("semantic_index",),
    completeness=check_inductive_scc_authority_completeness_v3,
    unit_aligned_inputs=(
        "semantic_index",
        "target_certificates",
        "transition_summaries",
    ),
    scc_aligned_inputs=("memory_versions",),
)


__all__ = [
    "INDUCTIVE_AUTHORITY_ARTIFACT_KIND_V3",
    "INDUCTIVE_AUTHORITY_CHECK_V3_FORMAT",
    "INDUCTIVE_AUTHORITY_CODEC_V3",
    "INDUCTIVE_AUTHORITY_PHASE_V3",
    "INDUCTIVE_AUTHORITY_RECORD_V3_SCHEMA",
    "INDUCTIVE_INPUT_CODEC_V3",
    "INDUCTIVE_INPUT_CONFIG_V3_SCHEMA",
    "INDUCTIVE_INPUT_CUTPOINT_V3_SCHEMA",
    "CutpointInvariantV3",
    "DependencyDischargeV3",
    "EntryFactsV3",
    "ExportRequirementV3",
    "InductiveAuthorityBodyV3",
    "InductiveAuthorityRecordV3",
    "InductiveCertificateReportV3",
    "InductiveConfigV3",
    "InductiveCutpointV3",
    "InductiveIssueV3",
    "InvariantBudgetsV3",
    "InvariantFactV3",
    "check_inductive_scc_authority_completeness_v3",
]
