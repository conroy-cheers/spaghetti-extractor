"""Reconstruct and check finite-target authority for indirect transfers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import PhaseContextV3, map_units
from ._schema import (
    AnalysisV3Error,
    fail,
    mapping,
    require_record_ids,
    sequence,
    sorted_records,
)
from .authority_common import (
    PrimaryBlockerV3,
    aggregate_blockers_v3,
    canonical_dependencies_v3,
    manifest_blocker_v3,
)
from .inductive_records import (
    INDUCTIVE_INPUT_CODEC_V3,
    InductiveCutpointV3,
    InvariantFactV3,
)
from .memory_records import MEMORY_VERSION_CODEC_V3, MemoryVersionRecordV3
from .semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    IndirectExitOccurrenceV3,
    SemanticIndexRecordV3,
)
from .structural_targets import (
    STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
    STRUCTURAL_TARGET_UNIT_CODEC_V3,
    StructuralTargetProposalV3,
)
from .target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3,
    TARGET_EVALUATION_EVIDENCE_CODEC_V3,
    IndirectTargetCertificateUnitV3,
    IndirectTargetCertificateV3,
    TargetEvaluationEvidenceV3,
    _INDEXED_PE_TABLE_CERTIFICATE_KIND_V3,
)
from .transition_records import (
    TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionSummaryRecordV3,
)


def _record_or_none(
    context: PhaseContextV3, input_name: str, record_id: str
) -> ArtifactRecordV3 | None:
    return context.optional_record(input_name, record_id)


def _target_expression_subject(expression: Any) -> tuple[str | None, tuple[int, int] | None]:
    if not isinstance(expression, Mapping):
        return None, None
    if expression.get("op") == "reg" and isinstance(expression.get("name"), str):
        return f"register:{expression['name']}", None
    if expression.get("op") != "load":
        return None, None
    width = expression.get("width")
    address = expression.get("address")
    if (
        not isinstance(width, int)
        or isinstance(width, bool)
        or width <= 0
        or not isinstance(address, Mapping)
        or address.get("op") != "const"
        or not isinstance(address.get("value"), int)
        or isinstance(address.get("value"), bool)
    ):
        return None, None
    start = int(address["value"])
    end = start + width
    if not 0 <= start < end <= 1 << 32:
        return None, None
    return f"memory-range:{start}:{end}", (start, end)


def _finite_values(fact: InvariantFactV3) -> tuple[Any, ...] | None:
    predicate = mapping(fact.predicate.to_value(), "target invariant predicate")
    if predicate.get("kind") == "exact":
        return (predicate.get("value"),)
    if predicate.get("kind") == "finite":
        return tuple(sequence(predicate.get("values"), "target finite invariant values"))
    return None


def _external_machine_value(value: CanonicalValueV3) -> int | None:
    row = value.to_value()
    if not isinstance(row, Mapping):
        return None
    machine_value = row.get("machine_target_value")
    if (
        not isinstance(machine_value, int)
        or isinstance(machine_value, bool)
        or not 0 <= machine_value < 1 << 32
    ):
        return None
    return machine_value


def _checked_target_values(
    context: PhaseContextV3,
    evidence: TargetEvaluationEvidenceV3,
) -> tuple[tuple[int, ...], list[PrimaryBlockerV3], list[RecordDependencyV3]]:
    values: list[int] = []
    blockers: list[PrimaryBlockerV3] = []
    dependencies: list[RecordDependencyV3] = []
    for unit_id in evidence.target_unit_ids:
        dependency = RecordDependencyV3("semantic_index_global", unit_id)
        target_record = _record_or_none(context, dependency.input_name, unit_id)
        if target_record is None:
            blockers.append(
                PrimaryBlockerV3(
                    "violated", "indirect_target_unit_unknown"
                )
            )
            continue
        dependencies.append(dependency)
        target = SEMANTIC_INDEX_CODEC_V3.read(target_record).value
        values.append(target.rva_start)
    for target in evidence.external_targets:
        machine_value = _external_machine_value(target)
        if machine_value is None:
            blockers.append(
                PrimaryBlockerV3("incomplete", "external_target_membership_unproven")
            )
        else:
            values.append(machine_value)
    if len(values) != len(set(values)):
        blockers.append(
            PrimaryBlockerV3("incomplete", "indirect_target_value_mapping_ambiguous")
        )
    return tuple(sorted(set(values))), blockers, dependencies


def _checked_indexed_pe_table_blockers(
    context: PhaseContextV3,
    *,
    evidence: TargetEvaluationEvidenceV3,
    semantic: SemanticIndexRecordV3,
    occurrence: IndirectExitOccurrenceV3,
) -> list[PrimaryBlockerV3]:
    """Recheck the compact binding exported by the exact PE-table provider.

    Exact PE-byte, section, guard, and alias checking happens in the dedicated
    provider.  This phase checks that its immutable certificate still names
    this exact exit and the exact semantic-index targets consumed by graph
    composition.  The provider artifact itself is content-addressed and binds
    the PE, semantic index, transitions, and structural proposal manifests.
    """

    if evidence.evaluation_certificate is None:
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_missing")
        ]
    try:
        certificate = mapping(
            evidence.evaluation_certificate.to_value(),
            "indexed PE-table target certificate",
        )
    except AnalysisV3Error:
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
        ]
    required = {
        "kind",
        "exit_id",
        "source_unit_id",
        "source_rva",
        "source_event_index",
        "transfer_kind",
        "target_expression_sha256",
        "image_base",
        "table_rva",
        "entry_width",
        "entry_count",
        "table_sha256",
        "selector_sha256",
        "predecessors",
        "entries",
        "target_unit_ids",
    }
    if set(certificate) != required:
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
        ]
    if (
        certificate["kind"] != _INDEXED_PE_TABLE_CERTIFICATE_KIND_V3
        or certificate["exit_id"] != occurrence.exit_id
        or certificate["source_unit_id"] != semantic.record_id
        or certificate["source_rva"] != semantic.rva_start
        or certificate["source_event_index"] != occurrence.event_index
        or certificate["transfer_kind"] != occurrence.transfer_kind
        or certificate["target_expression_sha256"]
        != canonical_sha256_v3(occurrence.target_expression.to_value())
        or certificate["entry_width"] != 4
    ):
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
        ]
    scalar_uints = ("image_base", "table_rva", "entry_count")
    if any(
        not isinstance(certificate[field], int)
        or isinstance(certificate[field], bool)
        or certificate[field] < 0
        for field in scalar_uints
    ):
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
        ]
    if certificate["entry_count"] <= 0:
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
        ]
    for field in ("table_sha256", "selector_sha256"):
        value = certificate[field]
        if (
            not isinstance(value, str)
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
            ]
    raw_targets = certificate["target_unit_ids"]
    raw_entries = certificate["entries"]
    raw_predecessors = certificate["predecessors"]
    if (
        not isinstance(raw_targets, list)
        or any(not isinstance(row, str) or not row for row in raw_targets)
        or raw_targets != sorted(set(raw_targets))
        or tuple(raw_targets) != evidence.target_unit_ids
        or not isinstance(raw_entries, list)
        or len(raw_entries) != certificate["entry_count"]
        or not isinstance(raw_predecessors, list)
        or not raw_predecessors
    ):
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
        ]
    entry_targets: set[str] = set()
    for expected_index, row in enumerate(raw_entries):
        if not isinstance(row, Mapping) or set(row) != {
            "index",
            "entry_rva",
            "target_rva",
            "target_unit_id",
        }:
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
            ]
        target_id = row["target_unit_id"]
        target_record = (
            None
            if not isinstance(target_id, str)
            else _record_or_none(context, "semantic_index_global", target_id)
        )
        if (
            row["index"] != expected_index
            or not isinstance(row["entry_rva"], int)
            or isinstance(row["entry_rva"], bool)
            or not isinstance(row["target_rva"], int)
            or isinstance(row["target_rva"], bool)
            or target_record is None
        ):
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
            ]
        target = SEMANTIC_INDEX_CODEC_V3.read(target_record).value
        if target.rva_start != row["target_rva"]:
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
            ]
        entry_targets.add(target_id)
    if entry_targets != set(evidence.target_unit_ids):
        return [
            PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
        ]
    for row in raw_predecessors:
        if not isinstance(row, Mapping) or set(row) != {
            "source_unit_id",
            "guard_sha256",
            "upper_exclusive",
            "support_unit_ids",
            "support_summary_ids",
        }:
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_malformed")
            ]
        if (
            not isinstance(row["source_unit_id"], str)
            or _record_or_none(
                context, "semantic_index_global", row["source_unit_id"]
            ) is None
            or not isinstance(row["guard_sha256"], str)
            or len(row["guard_sha256"]) != 64
            or row["upper_exclusive"] != certificate["entry_count"]
            or not isinstance(row["support_unit_ids"], list)
            or row["support_unit_ids"] != sorted(set(row["support_unit_ids"]))
            or row["source_unit_id"] not in row["support_unit_ids"]
            or any(
                not isinstance(unit_id, str)
                or _record_or_none(context, "semantic_index_global", unit_id) is None
                for unit_id in row["support_unit_ids"]
            )
            or not isinstance(row["support_summary_ids"], list)
            or row["support_summary_ids"] != sorted(set(row["support_summary_ids"]))
            or not row["support_summary_ids"]
            or any(not isinstance(summary_id, str) for summary_id in row["support_summary_ids"])
        ):
            return [
                PrimaryBlockerV3("violated", "indexed_target_certificate_contradiction")
            ]
    return []


def _transition_binds_occurrence(
    summary: TransitionSummaryRecordV3, occurrence: IndirectExitOccurrenceV3
) -> bool:
    candidates = tuple(
        row
        for row in summary.exits
        if row.transfer_kind == occurrence.transfer_kind
        and (
            (occurrence.event_index is None and row.source_kind == "outcome")
            or (
                occurrence.event_index is not None
                and row.source_kind == "external_event"
                and row.source_index == occurrence.event_index
            )
        )
    )
    if len(candidates) != 1:
        return False
    exact = candidates[0].exact_record.to_value()
    return isinstance(exact, Mapping) and CanonicalValueV3.of(
        exact.get("target")
    ) == occurrence.target_expression


def _memory_blockers(
    memory: MemoryVersionRecordV3,
    *,
    semantic: SemanticIndexRecordV3,
    summary: TransitionSummaryRecordV3,
    memory_range: tuple[int, int] | None,
) -> list[PrimaryBlockerV3]:
    blockers: list[PrimaryBlockerV3] = []
    if memory.binary.pe_sha256 != semantic.pe_sha256:
        blockers.append(PrimaryBlockerV3("violated", "target_memory_binary_contradiction"))
    if summary.summary_id not in memory.transition_summary_ids:
        blockers.append(
            PrimaryBlockerV3("violated", "target_memory_transition_inventory_contradiction")
        )
    if memory_range is None:
        # Register and exact-value target proofs do not consume a memory alias
        # component. SCC-local memory frontiers therefore cannot invalidate
        # them; their register/call dependencies are checked by inductive
        # authority instead.
        return blockers
    start, end = memory_range
    components = tuple(
        component
        for component in memory.alias_components
        if any(row.start <= start and end <= row.end for row in component.ranges)
    )
    if len(components) != 1:
        blockers.append(
            PrimaryBlockerV3("incomplete", "target_memory_component_not_unique")
        )
        return blockers
    component_id = components[0].component_id
    component_access_ids = set(components[0].access_ids)
    unresolved = tuple(
        row
        for row in memory.issues
        if row.code != "indirect_control_requires_target_certificate"
        and not (
            row.code == "unknown_read_alias"
            and row.subject_id not in component_access_ids
        )
    )
    if unresolved:
        blockers.append(
            PrimaryBlockerV3(
                "violated"
                if any(row.status == "violated" for row in unresolved)
                else "incomplete",
                "target_memory_evidence_not_complete",
                "memory_versions",
                memory.record_id,
            )
        )
    if components[0].contains_unknown_address:
        blockers.append(PrimaryBlockerV3("incomplete", "target_memory_evidence_tainted"))
    if any(
        kill.affected_scope == "all_components"
        or component_id in kill.affected_component_ids
        for kill in memory.unknown_write_kills
    ):
        blockers.append(PrimaryBlockerV3("incomplete", "target_memory_evidence_tainted"))
    return blockers


def _derive_certificate(
    context: PhaseContextV3,
    *,
    semantic: SemanticIndexRecordV3,
    summary: TransitionSummaryRecordV3,
    proposal: StructuralTargetProposalV3 | None,
    occurrence: IndirectExitOccurrenceV3,
) -> IndirectTargetCertificateV3:
    dependencies: list[RecordDependencyV3] = [
        RecordDependencyV3("semantic_index", semantic.record_id),
        RecordDependencyV3("structural_targets", semantic.record_id),
        RecordDependencyV3("transition_summaries", summary.record_id),
    ]
    blockers: list[PrimaryBlockerV3] = []
    for input_name, code in (
        ("semantic_index", "target_semantic_artifact_not_complete"),
        ("structural_targets", "structural_target_artifact_not_complete"),
        ("transition_summaries", "target_transition_artifact_not_complete"),
    ):
        blocker = manifest_blocker_v3(context, input_name, code)
        if blocker is not None:
            blockers.append(blocker)
    # Partial evidence packs are expected: independently checked exits remain
    # useful while unrelated exits are unresolved.  A contradicted pack still
    # poisons every consumer because its integrity cannot be established.
    target_evidence_manifest = context.manifest("target_evidence")
    if target_evidence_manifest.status == "violated":
        blockers.append(
            PrimaryBlockerV3(
                "violated", "target_evaluation_evidence_artifact_not_complete"
            )
        )
    if not _transition_binds_occurrence(summary, occurrence):
        blockers.append(PrimaryBlockerV3("violated", "target_transition_binding_contradiction"))
    if proposal is None:
        blockers.append(
            PrimaryBlockerV3(
                "violated", "indirect_target_inventory_contradiction", "structural_targets", semantic.record_id
            )
        )
    elif (
        proposal.source_unit_id != semantic.record_id
        or proposal.source_rva != semantic.rva_start
        or proposal.source_event_index != occurrence.event_index
        or proposal.transfer_kind != occurrence.transfer_kind
    ):
        blockers.append(
            PrimaryBlockerV3(
                "violated", "indirect_target_binding_contradiction", "structural_targets", semantic.record_id
            )
        )

    evidence_record = _record_or_none(context, "target_evidence", occurrence.exit_id)
    evidence: TargetEvaluationEvidenceV3 | None = None
    if evidence_record is None:
        blockers.append(
            PrimaryBlockerV3("incomplete", "target_evaluation_evidence_missing")
        )
    else:
        dependencies.append(RecordDependencyV3("target_evidence", occurrence.exit_id))
        evidence = TARGET_EVALUATION_EVIDENCE_CODEC_V3.read(evidence_record).value
        if (
            evidence.record_id != occurrence.exit_id
            or evidence.source_unit_id != semantic.record_id
            or evidence.source_rva != semantic.rva_start
            or evidence.source_event_index != occurrence.event_index
            or evidence.transfer_kind != occurrence.transfer_kind
            or evidence.target_expression_sha256
            != canonical_sha256_v3(occurrence.target_expression.to_value())
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated", "target_evaluation_binding_contradiction", "target_evidence", occurrence.exit_id
                )
            )
        if proposal is not None and proposal.status == "recovered" and (
            evidence.target_unit_ids != proposal.target_unit_ids
            or evidence.external_targets != proposal.external_targets
        ):
            blockers.append(
                PrimaryBlockerV3(
                    "violated", "target_evaluation_inventory_contradiction", "target_evidence", occurrence.exit_id
                )
                )

    if (
        proposal is not None
        and proposal.status != "recovered"
        and (
            proposal.status == "violated"
            or evidence is None
        )
    ):
        blockers.append(
            PrimaryBlockerV3(
                "violated" if proposal.status == "violated" else "incomplete",
                proposal.issue_codes[0]
                if proposal.issue_codes
                else "indirect_target_not_recovered",
                "structural_targets",
                semantic.record_id,
            )
        )

    if evidence is not None:
        expression_subject, memory_range = _target_expression_subject(
            occurrence.target_expression.to_value()
        )
        if evidence.evaluation_method != "checked_indexed_pe_table":
            memory_dependency = RecordDependencyV3(
                "memory_versions", evidence.memory_record_id
            )
            dependencies.append(memory_dependency)
            memory_record = _record_or_none(
                context, memory_dependency.input_name, memory_dependency.record_id
            )
            if memory_record is None:
                blockers.append(
                    PrimaryBlockerV3(
                        "incomplete", "target_memory_evidence_missing", memory_dependency.input_name, memory_dependency.record_id
                    )
                )
            else:
                memory = MEMORY_VERSION_CODEC_V3.read(memory_record).value
                blockers.extend(
                    _memory_blockers(
                        memory,
                        semantic=semantic,
                        summary=summary,
                        memory_range=memory_range,
                    )
                )
        checked_values, value_blockers, target_dependencies = _checked_target_values(
            context, evidence
        )
        blockers.extend(value_blockers)
        dependencies.extend(target_dependencies)
        if evidence.evaluation_method == "exact_constant":
            raw = occurrence.target_expression.to_value()
            if (
                not isinstance(raw, Mapping)
                or raw.get("op") != "const"
                or not isinstance(raw.get("value"), int)
                or isinstance(raw.get("value"), bool)
            ):
                blockers.append(
                    PrimaryBlockerV3("violated", "constant_target_expression_contradiction")
                )
            elif checked_values != (raw["value"],):
                blockers.append(
                    PrimaryBlockerV3("violated", "constant_target_membership_contradiction")
                )
        elif evidence.evaluation_method == "inductive_finite_values":
            if expression_subject is None:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "target_expression_subject_unsupported")
                )
            inductive_record = _record_or_none(
                context, "inductive_inputs", semantic.record_id
            )
            if inductive_record is None:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "target_inductive_cutpoint_missing")
                )
            else:
                dependencies.append(
                    RecordDependencyV3("inductive_inputs", semantic.record_id)
                )
                cutpoint = INDUCTIVE_INPUT_CODEC_V3.read(inductive_record).value
                if not isinstance(cutpoint, InductiveCutpointV3):
                    blockers.append(
                        PrimaryBlockerV3("violated", "target_inductive_record_contradiction")
                    )
                else:
                    facts = tuple(
                        row
                        for row in cutpoint.invariant.facts
                        if row.fact_id == evidence.inductive_fact_id
                    )
                    if len(facts) != 1:
                        blockers.append(
                            PrimaryBlockerV3(
                                "incomplete" if not facts else "violated",
                                "target_inductive_fact_missing" if not facts else "target_inductive_fact_ambiguous",
                            )
                        )
                    else:
                        fact = facts[0]
                        if fact.subject != expression_subject:
                            blockers.append(
                                PrimaryBlockerV3("violated", "target_inductive_subject_contradiction")
                            )
                        values = _finite_values(fact)
                        if values is None:
                            blockers.append(
                                PrimaryBlockerV3("incomplete", "target_inductive_fact_not_finite")
                            )
                        elif (
                            any(not isinstance(row, int) or isinstance(row, bool) for row in values)
                            or tuple(sorted(set(values))) != checked_values
                        ):
                            blockers.append(
                                PrimaryBlockerV3("violated", "target_inductive_membership_contradiction")
                            )
        else:
            if evidence.evaluation_certificate is not None:
                raw_indexed = evidence.evaluation_certificate.to_value()
                if isinstance(raw_indexed, Mapping):
                    raw_predecessors = raw_indexed.get("predecessors")
                    if isinstance(raw_predecessors, list):
                        dependencies.extend(
                            RecordDependencyV3("semantic_index_global", source_id)
                            for row in raw_predecessors
                            if isinstance(row, Mapping)
                            for source_id in row.get("support_unit_ids", [])
                            if isinstance(source_id, str)
                            and source_id
                        )
            blockers.extend(
                _checked_indexed_pe_table_blockers(
                    context,
                    evidence=evidence,
                    semantic=semantic,
                    occurrence=occurrence,
                )
            )

    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return IndirectTargetCertificateV3.create(
        occurrence=occurrence,
        source=semantic,
        status=status,
        target_unit_ids=(
            () if evidence is None else evidence.target_unit_ids
        ),
        external_targets=(
            () if evidence is None else evidence.external_targets
        ),
        evaluation_method=(None if evidence is None else evidence.evaluation_method),
        evidence_sha256=(None if evidence is None else evidence.evidence_sha256),
        dependencies=dependencies,
        primary_blocker=primary,
    )


def _derive_unit(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> IndirectTargetCertificateUnitV3:
    semantic = context.typed_record(
        "semantic_index", source, SEMANTIC_INDEX_CODEC_V3
    ).value
    summary_record = context.record("transition_summaries", semantic.record_id)
    summary = context.typed_record(
        "transition_summaries", summary_record, TRANSITION_SUMMARY_CODEC_V3
    ).value
    target_record = context.record("structural_targets", semantic.record_id)
    target_unit = context.typed_record(
        "structural_targets", target_record, STRUCTURAL_TARGET_UNIT_CODEC_V3
    ).value
    proposal_by_id = {row.record_id: row for row in target_unit.proposals}
    expected_ids = {row.exit_id for row in semantic.indirect_exits}
    proposal_ids = set(proposal_by_id)
    certificates = tuple(
        _derive_certificate(
            context,
            semantic=semantic,
            summary=summary,
            proposal=proposal_by_id.get(occurrence.exit_id),
            occurrence=occurrence,
        )
        for occurrence in semantic.indirect_exits
    )
    dependencies = canonical_dependencies_v3(
        dependency
        for certificate in certificates
        for dependency in certificate.dependencies
    )
    if not certificates:
        dependencies = canonical_dependencies_v3(
            (
                RecordDependencyV3("semantic_index", semantic.record_id),
                RecordDependencyV3("structural_targets", semantic.record_id),
                RecordDependencyV3("transition_summaries", semantic.record_id),
            )
        )
    blockers = [
        row.primary_blocker
        for row in certificates
        if row.primary_blocker is not None
    ]
    if expected_ids != proposal_ids:
        blockers.append(
            PrimaryBlockerV3(
                "violated",
                "indirect_target_inventory_contradiction",
                "structural_targets",
                semantic.record_id,
            )
        )
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    return IndirectTargetCertificateUnitV3(
        record_id=semantic.record_id,
        source_unit_id=semantic.record_id,
        unit_sha256=semantic.unit_sha256,
        status=status,
        authorizing=status == "complete",
        certificates=certificates,
        dependencies=dependencies,
        primary_blocker=primary,
    )


def _transform_unit(
    context: PhaseContextV3, source: ArtifactRecordV3
) -> ArtifactRecordV3:
    value = _derive_unit(context, source)
    return INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.write(
        value.record_id, value
    )


def check_indirect_target_certificates_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs,
        (row.record_id for row in context.records("semantic_index")),
        "indirect-target certificate units",
    )
    expected_evidence_ids: set[str] = set()
    for output in outputs:
        source = context.record("semantic_index", output.record_id)
        expected = _derive_unit(context, source)
        submitted = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(output).value
        if submitted != expected:
            fail(
                "indirect_target_certificate_contradiction",
                f"target-certificate unit {output.record_id!r} is stale",
                "rerun target-certificate checking from exact inputs",
            )
        if output.dependencies != expected.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"target-certificate unit {output.record_id!r} has stale dependencies",
                "let the phase attach every exact semantic, memory, invariant, and target dependency",
            )
        expected_evidence_ids.update(row.exit_id for row in expected.certificates)
    evidence_ids = {
        row.record_id for row in context.records("target_evidence")
    }
    unknown = sorted(evidence_ids - expected_evidence_ids)
    if unknown:
        fail(
            "unknown_target_evaluation_evidence",
            f"target evidence names absent exact exits {unknown!r}",
            "remove stale evidence or bind it to an exact semantic indirect exit",
        )


INDIRECT_TARGET_CERTIFICATES_PHASE_V3 = map_units(
    name="indirect-target-certificates-v3",
    version="1",
    source_input="semantic_index",
    input_artifact_kinds={
        "inductive_inputs": "inductive-inputs-v3",
        "memory_versions": "memory-versions-v3",
        "semantic_index": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        "semantic_index_global": SEMANTIC_INDEX_ARTIFACT_KIND_V3,
        "structural_targets": STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
        "target_evidence": TARGET_EVALUATION_EVIDENCE_ARTIFACT_KIND_V3,
        "transition_summaries": TRANSITION_SUMMARIES_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
    transform=_transform_unit,
    completeness=check_indirect_target_certificates_completeness_v3,
    unit_aligned_inputs=("structural_targets", "transition_summaries"),
)


__all__ = [
    "INDIRECT_TARGET_CERTIFICATES_PHASE_V3",
    "check_indirect_target_certificates_completeness_v3",
]
