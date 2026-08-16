"""Check root-independent parametric summaries over exact authority inputs."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..artifacts.artifact_set import (
    ArtifactRecordV3,
    CanonicalValueV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..artifacts.io import ArtifactSetReaderV3
from ..artifacts.phases import PhaseContextV3, reduce
from ._schema import fail, mapping, require_record_ids, sorted_records
from .authority_common import (
    PrimaryBlockerV3,
    aggregate_blockers_v3,
    canonical_dependencies_v3,
)
from .external_site_records import (
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    EXTERNAL_PROFILE_RECORD_V3_SCHEMA,
    ExternalProfileV3,
)
from .memory_records import (
    MEMORY_VERSION_CODEC_V3,
    MEMORY_VERSIONS_ARTIFACT_KIND_V3,
    MemoryVersionRecordV3,
)
from .parametric_summary_records import (
    PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
    PARAMETRIC_SCC_SUMMARY_CODEC_V3,
    PARAMETRIC_SUMMARY_PROPOSALS_ARTIFACT_KIND_V3,
    PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3,
    PE32_CALLEE_PRESERVED_REGISTERS_V3,
    ParametricSccProposalV3,
    ParametricSccSummaryV3,
    ValueFactV3,
    ValueOriginV3,
    parametric_scc_id_v3,
    partition_call_graph_sccs_v3,
)
from .parametric_unit_facts import (
    PARAMETRIC_UNIT_FACT_CODEC_V3,
    PARAMETRIC_UNIT_FACTS_ARTIFACT_KIND_V3,
    ParametricUnitFactV3,
)
from .structural_targets import (
    STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
    STRUCTURAL_TARGET_UNIT_CODEC_V3,
    StructuralTargetProposalV3,
)
from .static_value_records import (
    PE32_IMPORT_SLOT_CODEC_V3,
    PE32_IMPORT_SLOT_RECORD_V3_SCHEMA,
    PE32_STATIC_IMAGE_CODEC_V3,
    PE32_STATIC_IMAGE_RECORD_V3_SCHEMA,
    STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3,
    PE32ImportSlotV3,
    PE32StaticImageV3,
)


_GENERAL_REGISTERS = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"})


from .parametric_summary_checks import (
    CheckedIndirectTargetEvidenceV3,
    DirectCallEvidenceV3,
    ExternalCallEvidenceV3,
    IndirectExpressionEvidenceV3,
    MemoryEffectEvidenceV3,
    ParametricSccEvidenceV3,
    StackAccessEvidenceV3,
    UnitSummaryEvidenceV3,
    _CheckedProfileIndexV3,
    _InternalPreservationResultV3,
    _call_blockers,
    _checked_internal_preservation_v3,
    _expression_constant,
    _indirect_blockers,
    _memory_blockers,
    _relation_blockers,
    _return_blockers,
    _stack_blockers,
)


def check_parametric_scc_proposal_v3(
    proposal: ParametricSccProposalV3 | None,
    evidence: ParametricSccEvidenceV3,
    *,
    preservation_cache: dict[tuple[str, ...], _InternalPreservationResultV3]
    | None = None,
    profile_index: _CheckedProfileIndexV3 | None = None,
) -> ParametricSccSummaryV3:
    """Validate one proposal without trusting a status or convergence bit."""

    blockers: list[PrimaryBlockerV3] = []
    if proposal is None:
        blockers.append(
            PrimaryBlockerV3("incomplete", "parametric_summary_proposal_missing")
        )
    else:
        if (
            proposal.scc_id != evidence.scc_id
            or proposal.member_unit_ids != evidence.member_unit_ids
        ):
            blockers.append(
                PrimaryBlockerV3("violated", "parametric_scc_binding_contradiction")
            )
        if proposal.dependencies != evidence.expected_dependencies:
            blockers.append(
                PrimaryBlockerV3("violated", "parametric_summary_dependencies_stale")
            )
        overflow = any(
            row.lattice == "finite" and len(row.origins) > proposal.value_budget
            for row in proposal.value_facts
        )
        if overflow:
            blockers.append(
                PrimaryBlockerV3("incomplete", "parametric_value_budget_exceeded")
            )
        fact_ids = {row.fact_id for row in proposal.value_facts}
        referenced = {
            *(row.value_fact_id for row in proposal.register_relations),
            *(
                row.value_fact_id
                for row in proposal.stack_accesses
                if row.value_fact_id is not None
            ),
            *(
                row.input_fact_id
                for row in proposal.memory_effects
                if row.input_fact_id is not None
            ),
            *(
                row.output_fact_id
                for row in proposal.memory_effects
                if row.output_fact_id is not None
            ),
            *(
                row_id
                for row in proposal.call_effects
                for row_id in (
                    *row.argument_fact_ids,
                    *(() if row.result_fact_id is None else (row.result_fact_id,)),
                )
            ),
            *(row.value_fact_id for row in proposal.indirect_exits),
        }
        if referenced - fact_ids:
            blockers.append(
                PrimaryBlockerV3("violated", "parametric_value_fact_reference_unknown")
            )
        if not overflow and fact_ids - referenced:
            blockers.append(
                PrimaryBlockerV3("violated", "parametric_value_fact_unjustified")
            )
        blockers.extend(_relation_blockers(proposal, evidence))
        blockers.extend(
            _call_blockers(
                proposal,
                evidence,
                preservation_cache,
                profile_index,
            )
        )
        blockers.extend(_return_blockers(proposal, evidence))
        blockers.extend(_stack_blockers(proposal, evidence))
        blockers.extend(_memory_blockers(proposal, evidence))
        blockers.extend(_indirect_blockers(proposal, evidence))
        if evidence.recursive:
            base_units = set(proposal.base_path_unit_ids)
            if not base_units:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "recursive_scc_base_path_missing")
                )
            elif not any(
                unit.unit_id in base_units
                and unit.returns
                and not any(
                    call.target_unit_id in set(evidence.member_unit_ids)
                    for call in unit.direct_calls
                )
                for unit in evidence.units
            ):
                blockers.append(
                    PrimaryBlockerV3("incomplete", "recursive_scc_base_path_unproved")
                )
    primary = aggregate_blockers_v3(blockers)
    status = "complete" if primary is None else primary.status
    accepted = proposal is not None and status == "complete"
    return ParametricSccSummaryV3(
        record_id=evidence.scc_id,
        scc_id=evidence.scc_id,
        status=status,
        authorizing=accepted,
        proposal_id=None if proposal is None else proposal.proposal_id,
        member_unit_ids=evidence.member_unit_ids,
        recursive=evidence.recursive,
        checked_base_path_unit_ids=(
            () if not accepted else proposal.base_path_unit_ids
        ),
        value_facts=() if not accepted else proposal.value_facts,
        register_relations=() if not accepted else proposal.register_relations,
        stack_accesses=() if not accepted else proposal.stack_accesses,
        stack_cleanup_bytes=None if not accepted else proposal.stack_cleanup_bytes,
        return_address_preserved=False
        if not accepted
        else proposal.return_address_preserved,
        memory_effects=() if not accepted else proposal.memory_effects,
        call_effects=() if not accepted else proposal.call_effects,
        returns=() if not accepted else proposal.returns,
        indirect_exits=() if not accepted else proposal.indirect_exits,
        primary_blocker=primary,
        dependencies=evidence.expected_dependencies,
    )


def _collect_inputs(
    context: PhaseContextV3,
) -> tuple[
    dict[str, ParametricUnitFactV3],
    tuple[MemoryVersionRecordV3, ...],
    tuple[StructuralTargetProposalV3, ...],
    tuple[ExternalProfileV3, ...],
    PE32StaticImageV3,
    tuple[PE32ImportSlotV3, ...],
    dict[str, tuple[ParametricSccProposalV3, ...]],
]:
    unit_facts = {
        row.record_id: row.value
        for row in context.typed_records("unit_facts", PARAMETRIC_UNIT_FACT_CODEC_V3)
    }
    memories = tuple(
        row.value
        for row in context.typed_records("memory_versions", MEMORY_VERSION_CODEC_V3)
    )
    structural = tuple(
        proposal
        for row in context.typed_records(
            "structural_targets", STRUCTURAL_TARGET_UNIT_CODEC_V3
        )
        for proposal in row.value.proposals
    )
    profile_rows: list[ExternalProfileV3] = []
    for record in context.records("external_profiles"):
        payload = record.value.to_value()
        if (
            isinstance(payload, Mapping)
            and payload.get("schema") == EXTERNAL_PROFILE_RECORD_V3_SCHEMA
        ):
            profile_rows.append(EXTERNAL_PROFILE_CODEC_V3.read(record).value)
    profiles = tuple(profile_rows)
    static_images: list[PE32StaticImageV3] = []
    import_slots: list[PE32ImportSlotV3] = []
    for record in context.records("static_value_origins"):
        payload = record.value.to_value()
        schema = payload.get("schema") if isinstance(payload, Mapping) else None
        if schema == PE32_STATIC_IMAGE_RECORD_V3_SCHEMA:
            static_images.append(PE32_STATIC_IMAGE_CODEC_V3.read(record).value)
        elif schema == PE32_IMPORT_SLOT_RECORD_V3_SCHEMA:
            import_slots.append(PE32_IMPORT_SLOT_CODEC_V3.read(record).value)
        else:
            fail(
                "static_value_record_schema_unknown",
                f"static-value record {record.record_id!r} has unknown schema",
                "regenerate exact PE32 static-value origins",
            )
    if len(static_images) != 1:
        fail(
            "static_image_context_missing",
            "static-value origins do not contain exactly one image context",
            "regenerate exact PE32 static-value origins",
        )
    proposals_by_scc: dict[str, list[ParametricSccProposalV3]] = {}
    for row in context.typed_records(
        "parametric_proposals", PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3
    ):
        proposals_by_scc.setdefault(row.value.scc_id, []).append(row.value)
    proposals = {
        scc_id: tuple(sorted(rows, key=lambda row: row.proposal_id))
        for scc_id, rows in proposals_by_scc.items()
    }
    return (
        unit_facts,
        memories,
        structural,
        profiles,
        static_images[0],
        tuple(sorted(import_slots)),
        proposals,
    )


@dataclass(frozen=True)
class _CheckedAbstractValueV3:
    lattice: str
    origins: tuple[ValueOriginV3, ...] = ()
    support_unit_ids: tuple[str, ...] = ()
    support_profile_ids: tuple[str, ...] = ()


def _checked_bottom_v3() -> _CheckedAbstractValueV3:
    return _CheckedAbstractValueV3("bottom")


def _checked_top_v3() -> _CheckedAbstractValueV3:
    return _CheckedAbstractValueV3("top")


def _checked_finite_v3(
    origins: tuple[ValueOriginV3, ...],
    *,
    support_unit_ids: tuple[str, ...] = (),
    support_profile_ids: tuple[str, ...] = (),
) -> _CheckedAbstractValueV3:
    canonical = tuple(sorted(set(origins)))
    if not canonical:
        return _checked_bottom_v3()
    return _CheckedAbstractValueV3(
        "finite",
        canonical,
        tuple(sorted(set(support_unit_ids))),
        tuple(sorted(set(support_profile_ids))),
    )


def _checked_join_v3(
    values: tuple[_CheckedAbstractValueV3, ...], *, budget: int
) -> _CheckedAbstractValueV3:
    if any(row.lattice == "top" for row in values):
        return _checked_top_v3()
    finite = tuple(row for row in values if row.lattice == "finite")
    if not finite:
        return _checked_bottom_v3()
    origins = tuple(sorted({origin for row in finite for origin in row.origins}))
    if len(origins) > budget:
        return _checked_top_v3()
    return _checked_finite_v3(
        origins,
        support_unit_ids=tuple(
            unit_id for row in finite for unit_id in row.support_unit_ids
        ),
        support_profile_ids=tuple(
            profile_id for row in finite for profile_id in row.support_profile_ids
        ),
    )


def _checked_import_identity_v3(slot: PE32ImportSlotV3) -> CanonicalValueV3:
    return CanonicalValueV3.of(
        {
            "kind": "import",
            "dll": slot.dll,
            "symbol": slot.symbol,
            "ordinal": slot.ordinal,
        }
    )


def _replay_target_dataflow_v3(
    evidence: ParametricSccEvidenceV3,
    *,
    budget: int,
    preservation_cache: dict[tuple[str, ...], _InternalPreservationResultV3]
    | None = None,
    profile_index: _CheckedProfileIndexV3 | None = None,
) -> tuple[CheckedIndirectTargetEvidenceV3, ...]:
    """Independently replay bounded register provenance over checked exits."""

    if evidence.static_image is None:
        return ()
    units = {row.unit_id: row for row in evidence.all_units()}
    if len(units) != len(evidence.all_units()):
        return ()
    slot_by_va = {row.slot_va: row for row in evidence.import_slots}
    if len(slot_by_va) != len(evidence.import_slots):
        return ()
    predecessors: dict[str, list[str]] = {unit_id: [] for unit_id in units}
    for source_id, unit in units.items():
        if unit.unresolved_direct_target_rvas:
            continue
        for target_id in unit.direct_target_unit_ids:
            if target_id in predecessors:
                predecessors[target_id].append(source_id)

    entry: dict[tuple[str, str], _CheckedAbstractValueV3] = {}
    output: dict[tuple[str, str], _CheckedAbstractValueV3] = {}
    indirect: dict[str, _CheckedAbstractValueV3] = {}
    if preservation_cache is None:
        preservation_cache = {}
    if profile_index is None:
        profile_index = _CheckedProfileIndexV3(evidence.external_profiles)
    unit_by_va = {
        evidence.static_image.image_base + row.rva_start: row.unit_id
        for row in units.values()
    }

    def classify_constant(value: int, unit_id: str) -> _CheckedAbstractValueV3:
        image = evidence.static_image
        assert image is not None
        if image.image_base <= value < image.image_base + image.size_of_image:
            target_id = unit_by_va.get(value)
            if target_id is not None:
                return _checked_finite_v3(
                    (ValueOriginV3("static_code_target", target_id, 0),),
                    support_unit_ids=(unit_id, target_id),
                )
        return _checked_finite_v3(
            (ValueOriginV3("exact_bits", exact_bits=value),),
            support_unit_ids=(unit_id,),
        )

    def evaluate(
        expression: Any,
        environment: Mapping[str, _CheckedAbstractValueV3],
        *,
        unit: UnitSummaryEvidenceV3,
    ) -> _CheckedAbstractValueV3:
        if isinstance(expression, Mapping) and expression.get("op") == "reg":
            register = expression.get("name")
            return (
                environment.get(register, _checked_top_v3())
                if isinstance(register, str)
                else _checked_top_v3()
            )
        constant = _expression_constant(expression)
        if constant is not None:
            return classify_constant(constant, unit.unit_id)
        if isinstance(expression, Mapping) and expression.get("op") == "load":
            if expression.get("width") != 4:
                return _checked_top_v3()
            address = _expression_constant(expression.get("address"))
            slot = None if address is None else slot_by_va.get(address)
            if slot is None:
                return _checked_top_v3()
            identity = _checked_import_identity_v3(slot)
            profiles = profile_index.exact_identity(identity)
            if not profiles:
                return _checked_top_v3()
            return _checked_finite_v3(
                tuple(
                    ValueOriginV3("import_target", row.record_id, 0) for row in profiles
                ),
                support_unit_ids=(unit.unit_id,),
                support_profile_ids=tuple(row.record_id for row in profiles),
            )
        if (
            not isinstance(expression, Mapping)
            or expression.get("op") != "call_response"
        ):
            return _checked_top_v3()
        event_index = expression.get("call_index")
        register = expression.get("register")
        if (
            not isinstance(event_index, int)
            or isinstance(event_index, bool)
            or register not in _GENERAL_REGISTERS
        ):
            return _checked_top_v3()
        preserved_sets: list[set[str]] = []
        support_units: set[str] = {unit.unit_id}
        support_profiles: set[str] = set()
        direct_targets = tuple(
            sorted(
                set(
                    call.target_unit_id
                    for call in unit.direct_calls
                    if call.event_index == event_index
                    and call.target_unit_id is not None
                )
            )
        )
        if direct_targets:
            preservation = preservation_cache.get(direct_targets)
            if preservation is None:
                preservation = _checked_internal_preservation_v3(
                    direct_targets, evidence, profile_index
                )
                preservation_cache[direct_targets] = preservation
            if not preservation.complete:
                return _checked_top_v3()
            preserved_sets.append(set(preservation.preserved_registers))
            support_units.update(preservation.consumed_unit_ids)
            support_profiles.update(preservation.consumed_profile_ids)
        matching_indirect = tuple(
            row
            for row in unit.indirect_expressions
            if row.event_index == event_index and row.transfer_kind == "indirect_call"
        )
        if matching_indirect:
            if len(matching_indirect) != 1:
                return _checked_top_v3()
            target = indirect.get(matching_indirect[0].exit_id, _checked_bottom_v3())
            if target.lattice != "finite":
                return _checked_top_v3()
            internal = tuple(
                sorted(
                    origin.subject_id
                    for origin in target.origins
                    if origin.kind == "static_code_target"
                    and origin.subject_id is not None
                )
            )
            if internal:
                preservation = preservation_cache.get(internal)
                if preservation is None:
                    preservation = _checked_internal_preservation_v3(
                        internal, evidence, profile_index
                    )
                    preservation_cache[internal] = preservation
                if not preservation.complete:
                    return _checked_top_v3()
                preserved_sets.append(set(preservation.preserved_registers))
                support_units.update(preservation.consumed_unit_ids)
                support_profiles.update(preservation.consumed_profile_ids)
            for origin in target.origins:
                if origin.kind == "import_target" and origin.subject_id is not None:
                    profile = profile_index.by_record_id.get(origin.subject_id)
                    if profile is None or "call" not in profile.allowed_transfers:
                        return _checked_top_v3()
                    preserved = profile_index.abi_preserved(profile)
                    if preserved is None:
                        return _checked_top_v3()
                    preserved_sets.append(set(preserved))
                    support_profiles.add(profile.record_id)
                elif origin.kind != "static_code_target":
                    return _checked_top_v3()
        else:
            external_calls = tuple(
                row for row in unit.external_calls if row.event_index == event_index
            )
            if external_calls:
                if len(external_calls) != 1:
                    return _checked_top_v3()
                matches = profile_index.matches_call(external_calls[0])
                preserved = profile_index.preserved_for_call(external_calls[0])
                if len(matches) != 1 or preserved is None:
                    return _checked_top_v3()
                preserved_sets.append(set(preserved))
                support_profiles.add(matches[0].record_id)
        if not preserved_sets or any(register not in row for row in preserved_sets):
            return _checked_top_v3()
        input_expression = unit.event_register_input(event_index, register)
        if input_expression is None:
            return _checked_top_v3()
        value = evaluate(input_expression, environment, unit=unit)
        if value.lattice != "finite":
            return value
        return _checked_finite_v3(
            value.origins,
            support_unit_ids=(*value.support_unit_ids, *support_units),
            support_profile_ids=(*value.support_profile_ids, *support_profiles),
        )

    for unit_id in units:
        for register in _GENERAL_REGISTERS:
            initial = (
                _checked_top_v3() if not predecessors[unit_id] else _checked_bottom_v3()
            )
            entry[(unit_id, register)] = initial
            output[(unit_id, register)] = initial
    successors = {
        unit_id: tuple(
            sorted(
                target_id
                for target_id in unit.direct_target_unit_ids
                if target_id in units
            )
        )
        if not unit.unresolved_direct_target_rvas
        else ()
        for unit_id, unit in units.items()
    }
    ordered_unit_ids = tuple(sorted(units))
    pending = set(ordered_unit_ids)
    worklist = deque(ordered_unit_ids)
    steps = 0
    maximum_steps = max(
        1,
        len(units) * (len(_GENERAL_REGISTERS) * (budget + 2) + 2),
    )
    while worklist and steps < maximum_steps:
        unit_id = worklist.popleft()
        pending.remove(unit_id)
        steps += 1
        unit = units[unit_id]
        incoming = predecessors[unit_id]
        environment: dict[str, _CheckedAbstractValueV3] = {}
        for register in _GENERAL_REGISTERS:
            value = (
                _checked_top_v3()
                if not incoming
                else _checked_join_v3(
                    tuple(output[(source, register)] for source in incoming),
                    budget=budget,
                )
            )
            environment[register] = value
            if entry[(unit_id, register)] != value:
                entry[(unit_id, register)] = value
        indirect_changed = False
        for occurrence in unit.indirect_expressions:
            value = evaluate(occurrence.expression, environment, unit=unit)
            if indirect.get(occurrence.exit_id) != value:
                indirect[occurrence.exit_id] = value
                indirect_changed = True
        output_changed = False
        for register in _GENERAL_REGISTERS:
            expression = unit.output(register)
            value = (
                environment[register]
                if expression is None
                else evaluate(expression, environment, unit=unit)
            )
            if output[(unit_id, register)] != value:
                output[(unit_id, register)] = value
                output_changed = True
        affected = successors[unit_id] if output_changed else ()
        if indirect_changed:
            affected = (*affected, unit_id)
        for target_id in sorted(set(affected)):
            if target_id not in pending:
                pending.add(target_id)
                worklist.append(target_id)
    if worklist:
        return ()
    result: list[CheckedIndirectTargetEvidenceV3] = []
    for unit in units.values():
        for occurrence in unit.indirect_expressions:
            value = indirect.get(occurrence.exit_id, _checked_bottom_v3())
            if value.lattice != "finite":
                continue
            transfer = "jump" if occurrence.transfer_kind == "indirect_jump" else "call"
            internal = tuple(
                sorted(
                    origin.subject_id
                    for origin in value.origins
                    if origin.kind == "static_code_target"
                    and origin.subject_id is not None
                )
            )
            external = tuple(
                sorted(
                    origin.subject_id
                    for origin in value.origins
                    if origin.kind == "import_target"
                    and origin.subject_id is not None
                    and (profile := evidence.external_profile(origin.subject_id))
                    is not None
                    and transfer in profile.allowed_transfers
                )
            )
            if len(value.origins) != len(internal) + len(external):
                continue
            result.append(
                CheckedIndirectTargetEvidenceV3(
                    occurrence.exit_id,
                    value.origins,
                    internal,
                    external,
                    value.support_unit_ids,
                    value.support_profile_ids,
                )
            )
    return tuple(sorted(result, key=lambda row: row.exit_id))


def _unit_summary_evidence_v3(
    compact: ParametricUnitFactV3,
    direct_calls: tuple[DirectCallEvidenceV3, ...],
    rva_to_unit: Mapping[int, str],
) -> tuple[UnitSummaryEvidenceV3, dict[str, tuple[str, str]]]:
    external_calls = tuple(
        ExternalCallEvidenceV3(row.event_index, row.transfer_kind, row.identity)
        for row in compact.external_calls
    )
    stack_accesses = tuple(
        StackAccessEvidenceV3(
            access.access_id,
            compact.record_id,
            access.kind,
            access.entry_esp_offset,
            access.width_bytes,
            None if access.value is None else access.value.to_value(),
        )
        for access in compact.stack_accesses
    )
    nonstack_accesses = {
        access.access_id: (compact.record_id, access.kind)
        for access in compact.nonstack_accesses
    }
    direct_target_unit_ids = tuple(
        sorted(
            rva_to_unit[target]
            for target in (
                () if compact.successor_rvas is None else compact.successor_rvas
            )
            if target in rva_to_unit
        )
    )
    unresolved_direct_target_rvas = tuple(
        target
        for target in (
            (1 << 32,) if compact.successor_rvas is None else compact.successor_rvas
        )
        if target not in rva_to_unit
    )
    return (
        UnitSummaryEvidenceV3(
            unit_id=compact.record_id,
            pe_sha256=compact.pe_sha256,
            transition_summary_id=compact.transition_summary_id,
            rva_start=compact.rva_start,
            input_registers=compact.input_registers,
            register_outputs=tuple(
                (register, expression.to_value())
                for register, expression in compact.register_outputs
            ),
            stack_net_bytes=compact.stack_net_bytes,
            returns=compact.returns,
            may_not_return=not compact.returns,
            external_calls=external_calls,
            direct_calls=direct_calls,
            indirect_expressions=tuple(
                IndirectExpressionEvidenceV3(
                    row.exit_id,
                    row.event_index,
                    row.transfer_kind,
                    row.expression.to_value(),
                    canonical_sha256_v3(row.expression.to_value()),
                )
                for row in compact.indirect_exits
            ),
            event_register_inputs=tuple(
                (
                    event_index,
                    tuple(
                        (register, expression.to_value())
                        for register, expression in inputs
                    ),
                )
                for event_index, inputs in compact.event_register_inputs
            ),
            stack_accesses=stack_accesses,
            indirect_call_event_indices=tuple(
                row.event_index
                for row in compact.indirect_exits
                if row.transfer_kind == "indirect_call" and row.event_index is not None
            ),
            direct_target_unit_ids=direct_target_unit_ids,
            unresolved_direct_target_rvas=unresolved_direct_target_rvas,
        ),
        nonstack_accesses,
    )


def _checked_memory_effects_v3(
    *,
    member_set: set[str],
    relevant_memories: tuple[MemoryVersionRecordV3, ...],
    nonstack_accesses: Mapping[str, tuple[str, str]],
) -> tuple[
    tuple[MemoryEffectEvidenceV3, ...],
    tuple[str, ...],
    tuple[str, ...],
]:
    """Replay memory effects owned by exactly one call-graph SCC."""

    effect_rank = {"preserved": 0, "write": 1, "unknown_kill": 2}
    checked_effects: dict[tuple[str, str], str] = {}
    versioned_accesses: set[str] = set()
    for row in relevant_memories:
        for link in row.access_versions:
            exact = nonstack_accesses.get(link.access_id)
            if exact is None:
                continue
            unit_id, access_kind = exact
            kind = "preserved" if access_kind == "read" else "write"
            key = (unit_id, link.component_id)
            if effect_rank[kind] > effect_rank.get(
                checked_effects.get(key, "preserved"), 0
            ):
                checked_effects[key] = kind
            else:
                checked_effects.setdefault(key, kind)
            versioned_accesses.add(link.access_id)
        component_ids = tuple(
            component.component_id for component in row.alias_components
        )
        for kill in row.unknown_write_kills:
            unit_id = kill.binding.unit.unit_id
            if unit_id not in member_set:
                continue
            affected = (
                component_ids
                if kill.affected_scope == "all_components"
                else kill.affected_component_ids
            )
            for component_id in affected:
                checked_effects[(unit_id, component_id)] = "unknown_kill"
            versioned_accesses.add(kill.access_id)
    kills = tuple(
        sorted(
            {
                component_id
                for (_unit_id, component_id), kind in checked_effects.items()
                if kind == "unknown_kill"
            }
        )
    )
    memory_effects = tuple(
        MemoryEffectEvidenceV3(unit_id, component_id, kind)
        for (unit_id, component_id), kind in sorted(checked_effects.items())
    )
    unversioned = tuple(sorted(set(nonstack_accesses) - versioned_accesses))
    return memory_effects, kills, unversioned


def _derive_parametric_summaries(
    context: PhaseContextV3,
) -> tuple[ParametricSccSummaryV3, ...]:
    (
        unit_facts,
        memories,
        structural,
        profiles,
        static_image,
        import_slots,
        proposals,
    ) = _collect_inputs(context)
    rva_to_unit = {row.rva_start: row.record_id for row in unit_facts.values()}
    if len(rva_to_unit) != len(unit_facts):
        fail(
            "parametric_unit_rva_ambiguous",
            "parametric units share an entry RVA",
            "repair the checked compact unit facts",
        )
    edges: dict[str, set[str]] = {unit_id: set() for unit_id in unit_facts}
    calls_by_unit: dict[str, tuple[DirectCallEvidenceV3, ...]] = {}
    for unit_id, row in unit_facts.items():
        calls = tuple(
            DirectCallEvidenceV3(
                unit_id,
                call.event_index,
                None if call.target_rva is None else rva_to_unit.get(call.target_rva),
            )
            for call in row.internal_calls
        )
        calls_by_unit[unit_id] = calls
        edges[unit_id].update(
            call.target_unit_id for call in calls if call.target_unit_id is not None
        )
    program_units: dict[str, UnitSummaryEvidenceV3] = {}
    program_nonstack: dict[str, dict[str, tuple[str, str]]] = {}
    for unit_id, compact in unit_facts.items():
        unit, nonstack = _unit_summary_evidence_v3(
            compact,
            calls_by_unit[unit_id],
            rva_to_unit,
        )
        program_units[unit_id] = unit
        program_nonstack[unit_id] = nonstack
    ordered_program_units = tuple(
        sorted(program_units.values(), key=lambda row: row.unit_id)
    )
    dataflow_evidence = ParametricSccEvidenceV3(
        scc_id="root-independent-target-dataflow-v3",
        member_unit_ids=tuple(sorted(program_units)),
        recursive=False,
        units=ordered_program_units,
        unknown_kill_components=(),
        memory_effects=(),
        unversioned_memory_access_ids=(),
        structural_targets=structural,
        external_profiles=profiles,
        expected_dependencies=(),
        program_units=ordered_program_units,
        static_image=static_image,
        import_slots=import_slots,
    )
    preservation_cache: dict[tuple[str, ...], _InternalPreservationResultV3] = {}
    profile_index = _CheckedProfileIndexV3(profiles)
    checked_indirect_targets = _replay_target_dataflow_v3(
        dataflow_evidence,
        budget=64,
        preservation_cache=preservation_cache,
        profile_index=profile_index,
    )
    memories_by_summary_id: dict[str, list[MemoryVersionRecordV3]] = {}
    for memory in memories:
        for summary_id in memory.transition_summary_ids:
            memories_by_summary_id.setdefault(summary_id, []).append(memory)
    components = partition_call_graph_sccs_v3(unit_facts, edges)
    outputs: list[ParametricSccSummaryV3] = []
    checked_scc_ids: set[str] = set()
    for members in components:
        member_set = set(members)
        local_edges = tuple(
            sorted(
                (source, target)
                for source in members
                for target in edges[source]
                if target in member_set
            )
        )
        scc_id = parametric_scc_id_v3(members, local_edges)
        checked_scc_ids.add(scc_id)
        recursive = len(members) > 1 or any(
            source == target for source, target in local_edges
        )
        dependencies: set[RecordDependencyV3] = set()
        units: list[UnitSummaryEvidenceV3] = []
        nonstack_accesses: dict[str, tuple[str, str]] = {}
        for unit_id in members:
            dependencies.add(RecordDependencyV3("unit_facts", unit_id))
            units.append(program_units[unit_id])
            nonstack_accesses.update(program_nonstack[unit_id])
            for call in calls_by_unit[unit_id]:
                if call.target_unit_id is None:
                    continue
                dependencies.update(
                    {
                        RecordDependencyV3("unit_facts", call.target_unit_id),
                        RecordDependencyV3("structural_targets", call.target_unit_id),
                    }
                )
        member_summary_ids = {
            unit_facts[unit_id].transition_summary_id for unit_id in members
        }
        relevant_memories_by_id = {
            row.record_id: row
            for summary_id in member_summary_ids
            for row in memories_by_summary_id.get(summary_id, ())
        }
        relevant_memories = tuple(
            relevant_memories_by_id[row_id]
            for row_id in sorted(relevant_memories_by_id)
        )
        for row in relevant_memories:
            dependencies.add(RecordDependencyV3("memory_versions", row.record_id))
        memory_effects, kills, unversioned = _checked_memory_effects_v3(
            member_set=member_set,
            relevant_memories=relevant_memories,
            nonstack_accesses=nonstack_accesses,
        )
        relevant_structural = tuple(
            row for row in structural if row.source_unit_id in member_set
        )
        profile_ids: set[str] = set()
        relevant_exit_ids = {
            occurrence.exit_id
            for unit_id in members
            for occurrence in unit_facts[unit_id].indirect_exits
        }
        relevant_checked_targets = tuple(
            row for row in checked_indirect_targets if row.exit_id in relevant_exit_ids
        )
        for target in relevant_checked_targets:
            dependencies.update(
                RecordDependencyV3("unit_facts", unit_id)
                for unit_id in target.support_unit_ids
            )
            profile_ids.update(target.support_profile_ids)
        if relevant_checked_targets:
            dependencies.add(
                RecordDependencyV3("static_value_origins", static_image.record_id)
            )
            dependencies.update(
                RecordDependencyV3("static_value_origins", row.record_id)
                for row in import_slots
            )
        for unit_id in members:
            dependencies.add(RecordDependencyV3("structural_targets", unit_id))
        proposal_rows = proposals.get(scc_id, ())
        proposal = proposal_rows[0] if len(proposal_rows) == 1 else None
        if proposal is not None:
            profile_ids.update(
                row.external_profile_record_id
                for row in proposal.call_effects
                if row.external_profile_record_id is not None
            )
            profile_ids.update(
                profile_id
                for row in proposal.indirect_exits
                for profile_id in row.external_profile_record_ids
            )
            dependencies.add(
                RecordDependencyV3("parametric_proposals", proposal.proposal_id)
            )
        elif proposal_rows:
            dependencies.update(
                RecordDependencyV3("parametric_proposals", row.proposal_id)
                for row in proposal_rows
            )
        preservation_evidence = ParametricSccEvidenceV3(
            scc_id=scc_id,
            member_unit_ids=members,
            recursive=recursive,
            units=tuple(sorted(units, key=lambda row: row.unit_id)),
            unknown_kill_components=kills,
            memory_effects=memory_effects,
            unversioned_memory_access_ids=unversioned,
            structural_targets=tuple(
                sorted(relevant_structural, key=lambda row: row.record_id)
            ),
            external_profiles=profiles,
            expected_dependencies=(),
            program_units=ordered_program_units,
            static_image=static_image,
            import_slots=import_slots,
            checked_indirect_targets=relevant_checked_targets,
        )
        for unit in units:
            for direct_call in unit.direct_calls:
                if direct_call.target_unit_id is None:
                    continue
                key = (direct_call.target_unit_id,)
                preservation = preservation_cache.get(key)
                if preservation is None:
                    preservation = _checked_internal_preservation_v3(
                        key, preservation_evidence, profile_index
                    )
                    preservation_cache[key] = preservation
                profile_ids.update(preservation.consumed_profile_ids)
        relevant_profiles = tuple(
            sorted(
                (row for row in profiles if row.record_id in profile_ids),
                key=lambda row: row.record_id,
            )
        )
        dependencies.update(
            RecordDependencyV3("external_profiles", row.record_id)
            for row in relevant_profiles
        )
        expected_dependencies = canonical_dependencies_v3(
            dependency
            for dependency in dependencies
            if dependency.input_name != "parametric_proposals"
        )
        evidence = ParametricSccEvidenceV3(
            scc_id=scc_id,
            member_unit_ids=members,
            recursive=recursive,
            units=tuple(sorted(units, key=lambda row: row.unit_id)),
            unknown_kill_components=kills,
            memory_effects=memory_effects,
            unversioned_memory_access_ids=unversioned,
            structural_targets=tuple(
                sorted(relevant_structural, key=lambda row: row.record_id)
            ),
            external_profiles=profiles,
            expected_dependencies=expected_dependencies,
            program_units=ordered_program_units,
            static_image=static_image,
            import_slots=import_slots,
            checked_indirect_targets=relevant_checked_targets,
        )
        checked = check_parametric_scc_proposal_v3(
            proposal,
            evidence,
            preservation_cache=preservation_cache,
            profile_index=profile_index,
        )
        if len(proposal_rows) > 1:
            checked = ParametricSccSummaryV3(
                **{
                    **checked.__dict__,
                    "status": "incomplete",
                    "authorizing": False,
                    "primary_blocker": PrimaryBlockerV3(
                        "incomplete", "parametric_summary_proposal_ambiguous"
                    ),
                }
            )
        outputs.append(
            ParametricSccSummaryV3(
                **{
                    **checked.__dict__,
                    "dependencies": canonical_dependencies_v3(
                        (
                            *checked.dependencies,
                            *(
                                RecordDependencyV3(
                                    "parametric_proposals", row.proposal_id
                                )
                                for row in proposal_rows
                            ),
                        )
                    ),
                }
            )
        )
    unknown_proposals = set(proposals) - checked_scc_ids
    if unknown_proposals:
        fail(
            "parametric_proposal_scc_unknown",
            f"proposals reference unknown call SCCs {sorted(unknown_proposals)!r}",
            "regenerate proposals from the exact root-independent call graph",
        )
    return tuple(sorted(outputs, key=lambda row: row.record_id))


def _transform_parametric_summaries(
    context: PhaseContextV3,
) -> tuple[ArtifactRecordV3, ...]:
    return tuple(
        PARAMETRIC_SCC_SUMMARY_CODEC_V3.write(
            row.record_id, row, dependencies=row.dependencies
        )
        for row in _derive_parametric_summaries(context)
    )


def check_parametric_scc_summaries_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    expected = _derive_parametric_summaries(context)
    outputs = sorted_records(reader.iter_records())
    require_record_ids(
        outputs, tuple(row.record_id for row in expected), "parametric SCC summaries"
    )
    for output, expected_row in zip(outputs, expected, strict=True):
        submitted = PARAMETRIC_SCC_SUMMARY_CODEC_V3.read(output).value
        if submitted != expected_row:
            fail(
                "parametric_summary_contradiction",
                f"parametric SCC summary {output.record_id!r} is stale",
                "rerun the root-independent summary checker",
            )
        if output.dependencies != expected_row.dependencies:
            fail(
                "incomplete_record_dependencies",
                f"parametric SCC summary {output.record_id!r} has stale dependencies",
                "let the reduce phase attach exact dependencies",
            )


# Temporary global orchestration: the shared scheduler currently identifies
# SCCs in the mixed direct-control dependency graph and map_sccs requires those
# scheduler IDs to become output IDs.  Parametric summaries intentionally use
# the call-only partition produced by partition_call_graph_sccs_v3.  Keeping
# the partition/ID helpers in the record layer and the checker pure per SCC
# permits a later dedicated call-SCC schedule to shard this phase without a
# record-schema or checker change.
PARAMETRIC_SCC_SUMMARIES_PHASE_V3 = reduce(
    name="parametric-scc-summaries-v3",
    version="4",
    input_artifact_kinds={
        "external_profiles": EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
        "memory_versions": MEMORY_VERSIONS_ARTIFACT_KIND_V3,
        "parametric_proposals": PARAMETRIC_SUMMARY_PROPOSALS_ARTIFACT_KIND_V3,
        "static_value_origins": STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3,
        "structural_targets": STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
        "unit_facts": PARAMETRIC_UNIT_FACTS_ARTIFACT_KIND_V3,
    },
    output_artifact_kind=PARAMETRIC_SCC_SUMMARIES_ARTIFACT_KIND_V3,
    transform=_transform_parametric_summaries,
    completeness=check_parametric_scc_summaries_completeness_v3,
    dependency_scope="artifact",
    output_value_codec="plain-json-v1",
)


__all__ = [
    "PARAMETRIC_SCC_SUMMARIES_PHASE_V3",
    "DirectCallEvidenceV3",
    "ExternalCallEvidenceV3",
    "MemoryEffectEvidenceV3",
    "StackAccessEvidenceV3",
    "ParametricSccEvidenceV3",
    "UnitSummaryEvidenceV3",
    "check_parametric_scc_proposal_v3",
    "check_parametric_scc_summaries_completeness_v3",
]
