"""Standalone construction of an exact v2 hybrid-authority bundle."""

from __future__ import annotations

import hashlib
from typing import Any, Callable, Iterable, Mapping, Sequence

from .analysis.scc_worklist import decompose_scc
from .hybrid_authority_v2 import (
    AuthorityBundle,
    AuthorityDependency,
    AuthorityRecord,
    AuthorityStatus,
    BinaryBinding,
    CallFrameSummary,
    CheckedExternalSite,
    EntryStateContract,
    EventBinding,
    EvidenceIssue,
    EvidenceIssueKind,
    FiniteAlternatives,
    GlobalSlotInvariant,
    ImageSpanBinding,
    IndirectExitCertificate,
    MachineABIPremiseAuthority,
    UnitBinding,
    ValueFact,
    canonical_json_bytes,
    external_target,
    internal_target,
    parse_authority_record,
)
from .authority_bindings_v2 import (
    AuthorityDataError,
    IndirectExitBinding,
    match_indirect_recovery_v2,
)
from .authority_record_core_v2 import _content_id_kind
from .authority_dependencies_v2 import (
    call_frame_family_dependency_id,
    call_frame_dependency_id,
    call_summary_family_node_id,
    parse_call_frame_dependency,
    parse_call_frame_family_dependency,
)
from .machine_ir_authority_v2 import (
    MACHINE_IR_AUTHORITY_BINDINGS_FORMAT,
    MachineIRAuthorityV2Error,
    build_machine_ir_authority_bindings,
    canonical_event_sha256,
    canonical_unit_sha256,
    machine_events,
    machine_ir_sha256,
    recompute_event_binding,
    recompute_unit_binding,
)
from .isa_kernel_selection import (
    ISAKernelSelectionAuthority,
    ISAKernelSelectionAuthorityCheck,
    SelectionAuthorityStatus,
    parse_isa_kernel_selection_authority,
)
from .machine_ir_isa_requirements_v2 import MachineIRISARequirementsV2
from .machine_ir_isa_selection_v2 import (
    MachineIRISASelectionCertificateV2,
    parse_machine_ir_isa_selection_certificate_v2,
)
from .internal_call_summaries import checked_summary_register_frame_complete
from .indirect_target_dependency_v2 import (
    IndirectTargetDependencyV2Error,
    validate_profile_dispatch_dependency_v2,
)
from .machine_abi import parse_normal_call_abi_premise


HybridAuthorityBuilderV2Error = MachineIRAuthorityV2Error


def build_hybrid_authority_v2(
    *,
    machine_ir_rows: Sequence[Mapping[str, Any]],
    machine_ir_manifest: Mapping[str, Any],
    pe_sha256: str,
    root_records: Sequence[Mapping[str, Any]] | Mapping[str, Any],
    interprocedural_result: Any,
    checked_external_site_rows: Sequence[AuthorityRecord | Mapping[str, Any]] = (),
    global_slot_records: Sequence[AuthorityRecord | Mapping[str, Any]] = (),
    entry_records: Sequence[AuthorityRecord | Mapping[str, Any]] = (),
    exceptional_records: Sequence[AuthorityRecord | Mapping[str, Any]] = (),
    validated_isa_authority: Any | None = None,
    validated_isa_requirements: MachineIRISARequirementsV2 | None = None,
    prepared_binary: BinaryBinding | None = None,
    prepared_units: Sequence[UnitBinding] | None = None,
) -> AuthorityBundle:
    """Build one fail-closed bundle without consulting v1 completeness state.

    Authorizing supplied records must be strict ``hybrid_authority_v2`` records.
    Legacy rows can identify a required subject, but are never converted into
    complete v2 evidence.
    """

    rows = tuple(_mapping(row, "machine-IR row") for row in machine_ir_rows)
    if not rows:
        raise HybridAuthorityBuilderV2Error("machine-IR rows must be nonempty")
    manifest = _mapping(machine_ir_manifest, "machine-IR manifest")
    if prepared_binary is None:
        binary = BinaryBinding(
            pe_sha256=pe_sha256,
            machine_ir_sha256=machine_ir_sha256(rows),
        )
        units = tuple(
            recompute_unit_binding(row, binary=binary) for row in rows
        )
    else:
        if (
            not isinstance(prepared_binary, BinaryBinding)
            or prepared_binary.pe_sha256 != pe_sha256
            or prepared_units is None
        ):
            raise HybridAuthorityBuilderV2Error(
                "prepared machine-IR authority is missing or binds another PE"
            )
        binary = prepared_binary
        units = tuple(prepared_units)
        if (
            len(units) != len(rows)
            or any(not isinstance(unit, UnitBinding) for unit in units)
            or any(unit.binary != binary for unit in units)
            or tuple(unit.unit_id for unit in units)
            != tuple(str(row.get("id")) for row in rows)
        ):
            raise HybridAuthorityBuilderV2Error(
                "prepared unit bindings do not match the machine-IR inventory"
            )
    by_id = {unit.unit_id: unit for unit in units}
    if len(by_id) != len(units):
        raise HybridAuthorityBuilderV2Error("machine-IR unit IDs are duplicated")
    by_rva = {unit.rva_start: unit for unit in units}
    if len(by_rva) != len(units):
        raise HybridAuthorityBuilderV2Error("machine-IR unit starts are duplicated")

    events = machine_events(rows, by_id)
    records: dict[str, AuthorityRecord] = {}
    required: set[str] = set()

    def add(record: AuthorityRecord, *, is_required: bool = True) -> None:
        records[record.content_id] = record
        if is_required:
            required.add(record.content_id)

    supplied_entries = _typed_records(entry_records)
    supplied_globals = _typed_records(global_slot_records)
    supplied_external = _typed_records(checked_external_site_rows)
    supplied_exceptional = _typed_records(exceptional_records)
    for record in supplied_entries:
        add(record)

    binding_issues = _binding_issues(
        manifest=manifest,
        pe_sha256=pe_sha256,
        rows=rows,
        units=units,
        events=events,
        machine_ir_digest=binary.machine_ir_sha256,
    )
    if binding_issues:
        add(_marker(units[0], "builder:machine_binding", binding_issues))

    entry_by_subject = {
        (record.entry.rva_start, record.entry_kind): record
        for record in supplied_entries
        if isinstance(record, EntryStateContract)
    }
    for root in _roots(root_records):
        rva = root.get("rva", root.get("target_rva"))
        kind = root.get("kind")
        unit = by_rva.get(rva) if isinstance(rva, int) else None
        record = entry_by_subject.get((rva, kind)) if (
            isinstance(rva, int) and isinstance(kind, str)
        ) else None
        if record is not None:
            required.add(record.content_id)
        elif unit is not None and isinstance(kind, str):
            add(EntryStateContract(
                entry=unit,
                entry_kind=kind,
                alternatives=None,
                issues=_issues((
                    _missing("root_entry_missing", f"root {kind} at RVA {rva:#x} has no v2 entry record"),
                )),
            ))
        else:
            add(_marker(
                units[0],
                "builder:root_binding",
                (_missing("root_unit_missing", "a behavioral root has no exact machine-IR unit"),),
            ))

    interprocedural = _interprocedural(interprocedural_result)
    summaries = {
        row.get("target_unit_id"): row
        for row in _rows(interprocedural.get("call_summaries"), "summaries")
        if isinstance(row.get("target_unit_id"), str)
    }
    recoveries = tuple(interprocedural.get("recovered_targets", ()))
    fixed = _mapping_or_empty(interprocedural.get("fixed_point"))
    machine_abi_premises = _machine_abi_premise_authorities(
        fixed=fixed,
        binary=binary,
    )
    replay_authoritative = (
        fixed.get("cold_replay_validated") is True
        and fixed.get("authority_replay_validated") is True
        and fixed.get("cold_initial_recoveries_empty") is True
        and fixed.get("static_recovery_authority_seeded") is False
        and fixed.get("global_slot_promotion") is False
    )
    globals_by_content_id = {
        record.content_id: record
        for record in supplied_globals
        if isinstance(record, GlobalSlotInvariant)
    }
    reachable_units = _rooted_reachable_units(
        rows=rows,
        roots=_roots(root_records),
        entry_records=supplied_entries,
        recoveries=recoveries,
    )

    requested_call_families: dict[
        tuple[str, int, str], set[tuple[str, str | None]]
    ] = {}
    for recovery in recoveries:
        if not isinstance(recovery, Mapping):
            continue
        raw_dependencies = recovery.get("analysis_dependencies", ())
        if not isinstance(raw_dependencies, Sequence) or isinstance(
            raw_dependencies, (str, bytes)
        ):
            continue
        for dependency_id in raw_dependencies:
            parsed = parse_call_frame_family_dependency(dependency_id)
            if parsed is None:
                continue
            source_unit_id, event_index, target_unit_id, family, subject = parsed
            requested_call_families.setdefault(
                (source_unit_id, event_index, target_unit_id), set()
            ).add((family, subject))

    call_frames_by_dependency: dict[str, CallFrameSummary] = {}
    for event in events:
        binding = event["binding"]
        if binding.unit.unit_id not in reachable_units:
            continue
        raw = event["row"]
        if binding.event_kind in {"internal_call", "indirect_call"}:
            recovery, _recovery_issues = (
                _matching_recovery(recoveries, event)
                if binding.event_kind == "indirect_call"
                else (None, ())
            )
            callees = _call_targets(raw, by_id, by_rva, recovery)
            callee = callees[0] if len(callees) == 1 else None
            external_alternatives = (
                recovery.get("external_targets", [])
                if isinstance(recovery, Mapping)
                else []
            )
            external_only = (
                binding.event_kind == "indirect_call"
                and not callees
                and isinstance(external_alternatives, list)
                and bool(external_alternatives)
            )
            if not external_only:
                frame_summaries = [summaries.get(item.unit_id) for item in callees]
                frame_premise_dependencies, frame_premise_issues = (
                    _summary_machine_abi_premise_dependencies(
                        frame_summaries,
                        machine_abi_premises=machine_abi_premises,
                    )
                )
                complete = (
                    replay_authoritative
                    and bool(frame_summaries)
                    and all(
                        isinstance(summary, Mapping)
                        and summary.get("status") == "complete"
                        and _call_frame_families_complete(summary)
                        for summary in frame_summaries
                    )
                    and not frame_premise_issues
                )
                call_issues: tuple[EvidenceIssue, ...] = ()
                if not replay_authoritative:
                    call_issues = (_missing("interprocedural_replay_invalid", "cold interprocedural replay is not authoritative"),)
                elif not callees:
                    call_issues = (_missing("call_target_missing", "reachable call has no finite exact internal callee inventory"),)
                elif not complete:
                    call_issues = (_missing("call_summary_missing", "at least one finite callee alternative has no complete frame summary"),)
                call_issues = _issues((*call_issues, *frame_premise_issues))
                frame = CallFrameSummary(
                    call_site=binding,
                    analysis_fact_id=(
                        f"call-frame:{binding.unit.unit_id}:{binding.event_index}"
                    ),
                    callee=callee,
                    abi=_call_abi(raw),
                    alternatives=(
                        FiniteAlternatives.of(
                            [
                                _call_frame_alternative(summary, target)
                                for target, summary in zip(
                                    callees, frame_summaries, strict=True
                                )
                                if isinstance(summary, Mapping)
                            ],
                            maximum=len(callees),
                        )
                        if callees
                        and all(
                            isinstance(summary, Mapping)
                            for summary in frame_summaries
                        )
                        else None
                    ),
                    dependencies=frame_premise_dependencies,
                    issues=_issues(call_issues),
                )
                add(frame)
                _add_machine_abi_premise_dependencies(
                    frame_premise_dependencies,
                    machine_abi_premises=machine_abi_premises,
                    add=add,
                )
                for target in callees:
                    call_frames_by_dependency[call_frame_dependency_id(
                        binding.unit.unit_id,
                        binding.event_index,
                        target.unit_id,
                    )] = frame
                for target, summary in zip(
                    callees, frame_summaries, strict=True
                ):
                    requests = requested_call_families.get((
                        binding.unit.unit_id,
                        binding.event_index,
                        target.unit_id,
                    ), ())
                    for family, subject in sorted(
                        requests,
                        key=lambda item: (item[0], item[1] or ""),
                    ):
                        family_premise_dependencies, family_premise_issues = (
                            _summary_machine_abi_premise_dependencies(
                                (summary,),
                                machine_abi_premises=machine_abi_premises,
                                include=(family == "register"),
                            )
                        )
                        alternative = (
                            _call_frame_family_alternative(
                                summary, target, family, subject
                            )
                            if isinstance(summary, Mapping)
                            else None
                        )
                        family_issues: tuple[EvidenceIssue, ...] = ()
                        if not replay_authoritative:
                            family_issues = (_missing(
                                "interprocedural_replay_invalid",
                                "cold interprocedural replay is not authoritative",
                            ),)
                        elif alternative is None or alternative.get(
                            "status"
                        ) != "complete":
                            family_issues = (_missing(
                                "call_summary_family_missing",
                                f"callee has no complete {family} frame family",
                            ),)
                        family_issues = _issues((
                            *family_issues,
                            *family_premise_issues,
                        ))
                        family_frame = CallFrameSummary(
                            call_site=binding,
                            analysis_fact_id=call_summary_family_node_id(
                                target.unit_id, family, subject
                            ),
                            callee=target,
                            abi=_call_abi(raw),
                            alternatives=(
                                FiniteAlternatives.of([alternative], maximum=1)
                                if alternative is not None
                                else None
                            ),
                            dependencies=family_premise_dependencies,
                            issues=_issues(family_issues),
                        )
                        # Family projections are rooted only when an indirect
                        # certificate consumes them. The aggregate frame above
                        # remains the independent whole-call requirement.
                        add(family_frame, is_required=False)
                        _add_machine_abi_premise_dependencies(
                            family_premise_dependencies,
                            machine_abi_premises=machine_abi_premises,
                            add=add,
                        )
                        dependency_id = call_frame_family_dependency_id(
                            binding.unit.unit_id,
                            binding.event_index,
                            target.unit_id,
                            family,
                            subject,
                        )
                        call_frames_by_dependency[dependency_id] = family_frame

    indirect_events: dict[
        str,
        tuple[
            Mapping[str, Any],
            IndirectExitBinding,
            Mapping[str, Any] | None,
            tuple[EvidenceIssue, ...],
        ],
    ] = {}
    for event in events:
        binding = event["binding"]
        if (
            binding.unit.unit_id not in reachable_units
            or binding.event_kind not in {"indirect_call", "indirect_jump"}
        ):
            continue
        indirect_binding = _indirect_exit_binding(event)
        recovery, recovery_issues = _matching_recovery(recoveries, event)
        indirect_events[indirect_binding.exit_id] = (
            event,
            indirect_binding,
            recovery,
            recovery_issues,
        )

    dependency_edges = {
        (dependency_id, exit_id)
        for exit_id, (_event, _binding, recovery, _issues) in indirect_events.items()
        for dependency_id in _indirect_analysis_dependency_ids(recovery)
        if dependency_id in indirect_events
    }
    decomposition = decompose_scc(
        indirect_events.keys(),
        dependency_edges,
    )
    certificates_by_exit: dict[str, IndirectExitCertificate] = {}
    for component in decomposition.components:
        cyclic = len(component) > 1 or any(
            source == target == component[0]
            for source, target in dependency_edges
        )
        cyclic_members = frozenset(component) if cyclic else frozenset()
        for exit_id in component:
            event, indirect_binding, recovery, recovery_issues = indirect_events[
                exit_id
            ]
            binding = event["binding"]
            raw = event["row"]
            mutable_dependencies, mutable_issues = _checked_mutable_dependencies(
                recovery,
                binary=binary,
                globals_by_content_id=globals_by_content_id,
            )
            call_dependencies, call_dependency_issues = (
                _checked_call_frame_dependencies(
                    recovery,
                    call_frames_by_dependency=call_frames_by_dependency,
                    machine_abi_premises=machine_abi_premises,
                    non_call_dependency_ids=frozenset(
                        {
                            dependency.content_id
                            for dependency in mutable_dependencies
                        }
                        | set(_global_slot_analysis_dependency_ids(recovery))
                    ),
                )
            )
            indirect_dependencies, indirect_dependency_issues = (
                _checked_indirect_exit_dependencies(
                    recovery,
                    certificates_by_exit=certificates_by_exit,
                    known_exit_ids=frozenset(indirect_events),
                    cyclic_dependency_ids=cyclic_members,
                )
            )
            targets = [] if recovery is None else recovery.get("target_unit_ids", [])
            valid_targets = [by_id[target] for target in targets if target in by_id]
            external_records = sorted(
                (
                    record
                    for record in supplied_external
                    if isinstance(record, CheckedExternalSite)
                    and record.site == binding
                ),
                key=lambda record: record.target_alternative_index,
            )
            raw_external_rows = (
                recovery.get("external_targets", [])
                if isinstance(recovery, Mapping)
                else []
            )
            external_rows = (
                sorted(
                    raw_external_rows,
                    key=lambda row: hashlib.sha256(
                        canonical_json_bytes(row)
                    ).hexdigest(),
                )
                if isinstance(raw_external_rows, list)
                and all(isinstance(row, Mapping) for row in raw_external_rows)
                else []
            )
            external_record_set_complete = (
                len(external_records) == len(external_rows)
                and all(
                    record.status is AuthorityStatus.COMPLETE
                    and record.target_alternative_index == index
                    and record.target_alternative_sha256
                    == hashlib.sha256(
                        canonical_json_bytes(external_rows[index])
                    ).hexdigest()
                    for index, record in enumerate(external_records)
                )
            )
            external_complete = (
                isinstance(raw_external_rows, list)
                and len(external_rows) == len(raw_external_rows)
                and (
                    not external_rows
                    or external_record_set_complete
                )
            )
            profile_dispatch_fact, profile_dispatch_issues = (
                _checked_profile_dispatch_value_fact(
                    recovery,
                    binding=binding,
                    dependencies=tuple(sorted({
                        *mutable_dependencies,
                        *call_dependencies,
                        *indirect_dependencies,
                    })),
                )
            )
            recovered = (
                replay_authoritative
                and recovery is not None
                and recovery.get("status") == "recovered"
                and len(valid_targets) == len(targets)
                and bool(valid_targets or external_rows)
                and external_complete
                and not mutable_issues
                and not call_dependency_issues
                and not indirect_dependency_issues
                and not profile_dispatch_issues
                and not recovery_issues
            )
            indirect_issues = (
                _issues((
                    *recovery_issues,
                    *mutable_issues,
                    *call_dependency_issues,
                    *indirect_dependency_issues,
                    *profile_dispatch_issues,
                ))
                if (
                    recovery_issues
                    or mutable_issues
                    or call_dependency_issues
                    or indirect_dependency_issues
                    or profile_dispatch_issues
                )
                else ()
                if recovered
                else (
                    _missing("indirect_targets_missing", "indirect exit has no complete finite v2 target inventory"),
                )
            )
            dependencies = [
                *mutable_dependencies,
                *call_dependencies,
                *indirect_dependencies,
            ]
            if profile_dispatch_fact is not None:
                add(profile_dispatch_fact, is_required=False)
                dependencies.append(AuthorityDependency(
                    "value_fact", profile_dispatch_fact.content_id
                ))
            for external_record in external_records:
                add(external_record, is_required=False)
                dependencies.append(AuthorityDependency(
                    "external_target", external_record.content_id
                ))
            for dependency in mutable_dependencies:
                global_record = globals_by_content_id.get(dependency.content_id)
                if global_record is not None:
                    add(global_record, is_required=False)
            for dependency in call_dependencies:
                premise_record = next(
                    (
                        record
                        for record in machine_abi_premises.values()
                        if record.content_id == dependency.content_id
                    ),
                    None,
                )
                if premise_record is not None:
                    add(premise_record, is_required=False)
                    continue
                frame = next(
                    (
                        record
                        for record in call_frames_by_dependency.values()
                        if record.content_id == dependency.content_id
                    ),
                    None,
                )
                if frame is not None:
                    add(frame, is_required=False)
            certificate = IndirectExitCertificate(
                exit_site=binding,
                analysis_fact_id=indirect_binding.exit_id,
                target_expression_sha256=indirect_binding.target_expression_sha256,
                alternatives=(
                    FiniteAlternatives.of(
                        [
                            *[internal_target(target) for target in valid_targets],
                            *[
                                external_target(record.content_id)
                                for record in external_records
                            ],
                        ],
                        maximum=len(valid_targets) + len(external_rows),
                    )
                    if recovered
                    else None
                ),
                dependencies=tuple(sorted(set(dependencies))),
                issues=_issues(indirect_issues),
            )
            add(certificate)
            certificates_by_exit[exit_id] = certificate

    external_by_binding: dict[EventBinding, list[CheckedExternalSite]] = {}
    for record in supplied_external:
        if isinstance(record, CheckedExternalSite):
            external_by_binding.setdefault(record.site, []).append(record)
    for site_records in external_by_binding.values():
        site_records.sort(key=lambda record: record.target_alternative_index)
    for event in events:
        binding = event["binding"]
        if binding.unit.unit_id not in reachable_units:
            continue
        if binding.event_kind not in {"external_call", "external_jump"}:
            continue
        site_records = external_by_binding.get(binding, [])
        if (
            len(site_records) == 1
            and site_records[0].target_alternative_index == 0
        ):
            add(site_records[0])
            continue
        add(CheckedExternalSite(
            site=binding,
            profile=None,
            transfer_kind=("call" if binding.event_kind.endswith("call") else "jump"),
            alternatives=None,
            target_alternative_index=0,
            target_alternative_sha256=None,
            issues=_issues((
                _missing("external_site_missing", "external site has no checked v2 site record"),
            )),
        ))

    exceptional_by_binding = {
        record.binding: record
        for record in supplied_exceptional
        if isinstance(record, ValueFact) and isinstance(record.binding, EventBinding)
    }
    for event in events:
        binding = event["binding"]
        if binding.unit.unit_id not in reachable_units:
            continue
        if binding.event_kind != "fault":
            continue
        record = exceptional_by_binding.get(binding)
        if record is not None:
            add(record)
            continue
        add(ValueFact(
            binding=binding,
            location="exceptional_control",
            width_bits=1,
            alternatives=None,
            issues=_issues((
                _missing("exceptional_record_missing", "fault has no v2 exceptional-control record"),
            )),
        ))

    isa_authority = _qualified_isa_authority(validated_isa_authority)
    if isa_authority is None:
        add(ValueFact(
            binding=units[0],
            location="isa_kernel_selection",
            width_bits=1,
            alternatives=None,
            issues=_issues((
                _missing(
                    "isa_kernel_selection_missing",
                    "the exact binary has no qualified ISA-selection authority",
                ),
            )),
        ))
    for form in _isa_forms(isa_authority, validated_isa_requirements):
        assert isa_authority is not None
        locations = form.get("source_locations")
        locations = locations if isinstance(locations, list) else []
        form_id = str(form.get("form_id", "unknown"))
        bound_locations: list[dict[str, Any]] = []
        bound_units: list[UnitBinding] = []
        for raw_location in locations:
            location = _mapping_or_empty(raw_location)
            rva = location.get("rva")
            byte_length = location.get("byte_length")
            if (
                location.get("image_sha256") != pe_sha256
                or not isinstance(rva, int)
                or isinstance(rva, bool)
                or not isinstance(byte_length, int)
                or isinstance(byte_length, bool)
                or byte_length <= 0
            ):
                continue
            containing = next(
                (
                    unit
                    for unit in units
                    if unit.rva_start <= rva
                    and rva + byte_length <= unit.rva_end
                ),
                None,
            )
            if containing is not None:
                bound_units.append(containing)
                bound_locations.append(dict(location))
        capability_id = _fallback_capability_id(isa_authority, form_id)
        complete = (
            bool(locations)
            and len(bound_locations) == len(locations)
            and capability_id is not None
        )
        add(ValueFact(
            binding=bound_units[0] if bound_units else units[0],
            location=f"isa_form:{form_id}"[:256],
            width_bits=1,
            alternatives=(
                FiniteAlternatives.of(
                    [{
                        "authority_sha256": _isa_authority_sha256(isa_authority),
                        "form_id": form_id,
                        "semantic_form": form.get("semantic_form"),
                        "source_locations": bound_locations,
                        "fallback_capability_id": capability_id,
                    }],
                    maximum=1,
                )
                if complete
                else None
            ),
            issues=(
                ()
                if complete
                else _issues((
                    _contradiction(
                        "isa_location_binding_mismatch",
                        "a qualified ISA form does not bind exact machine-IR locations and fallback capability",
                    ),
                ))
            ),
        ))

    return AuthorityBundle.of(
        binary=binary,
        records=tuple(records.values()),
        required_content_ids=tuple(required),
    )


def _rooted_reachable_units(
    *,
    rows: Sequence[Mapping[str, Any]],
    roots: Sequence[Mapping[str, Any]],
    entry_records: Sequence[AuthorityRecord],
    recoveries: Sequence[Mapping[str, Any]],
) -> frozenset[str]:
    """Recompute closure without consulting legacy row reachability fields."""

    by_id = {str(row["id"]): row for row in rows}
    by_rva = {
        int(row["source"]["original"]["rva_start"]): str(row["id"])
        for row in rows
    }
    successors: dict[str, set[str]] = {unit_id: set() for unit_id in by_id}
    for unit_id, row in by_id.items():
        control = _mapping_or_empty(row.get("control"))
        for target_rva in control.get("direct_targets", ()):
            target = by_rva.get(target_rva) if isinstance(target_rva, int) else None
            if target is not None:
                successors[unit_id].add(target)
        semantics = _mapping_or_empty(row.get("semantics"))
        events = semantics.get("external_events", ())
        if isinstance(events, list):
            for event in events:
                if not isinstance(event, Mapping) or event.get("kind") != "internal_call":
                    continue
                target_rva = event.get("target_rva")
                target = by_rva.get(target_rva) if isinstance(target_rva, int) else None
                if target is not None:
                    successors[unit_id].add(target)
    for recovery in recoveries:
        if recovery.get("status") != "recovered":
            continue
        source = recovery.get("source_unit_id")
        if not isinstance(source, str) or source not in by_id:
            continue
        successors[source].update(
            target
            for target in recovery.get("target_unit_ids", ())
            if isinstance(target, str) and target in by_id
        )
    initial = {
        by_rva[rva]
        for root in roots
        for rva in (root.get("rva", root.get("target_rva")),)
        if isinstance(rva, int) and rva in by_rva
    }
    initial.update(
        record.entry.unit_id
        for record in entry_records
        if isinstance(record, EntryStateContract)
        and record.status.value == "complete"
        and record.entry.unit_id in by_id
    )
    reached: set[str] = set()
    pending = sorted(initial, reverse=True)
    while pending:
        unit_id = pending.pop()
        if unit_id in reached:
            continue
        reached.add(unit_id)
        pending.extend(sorted(successors.get(unit_id, ()), reverse=True))
    return frozenset(reached)


def _binding_issues(
    *,
    manifest: Mapping[str, Any],
    pe_sha256: str,
    rows: Sequence[Mapping[str, Any]],
    units: Sequence[UnitBinding],
    events: Sequence[Mapping[str, Any]],
    machine_ir_digest: str,
) -> tuple[EvidenceIssue, ...]:
    issues: list[EvidenceIssue] = []
    binary = _mapping_or_empty(manifest.get("binary"))
    original = _mapping_or_empty(_mapping_or_empty(manifest.get("inputs")).get("original_pe"))
    for observed in (binary.get("sha256"), original.get("sha256")):
        if observed is not None and observed != pe_sha256:
            issues.append(_contradiction("pe_binding_mismatch", "manifest PE digest differs from the exact supplied PE digest"))
    artifact = _mapping_or_empty(_mapping_or_empty(manifest.get("artifacts")).get("machine_ir"))
    if artifact.get("sha256") != machine_ir_digest:
        issues.append(_contradiction("machine_ir_hash_mismatch", "canonical machine-IR rows differ from the manifest artifact binding"))

    authority = _mapping_or_empty(manifest.get("authority_bindings"))
    if authority.get("format") != MACHINE_IR_AUTHORITY_BINDINGS_FORMAT:
        issues.append(_missing("authority_bindings_missing", "manifest has no v2 unit/event authority bindings"))
        return _issues(issues)
    expected_units = {
        parsed.unit_id: parsed
        for raw in authority.get("units", [])
        for parsed in (UnitBinding.parse(raw),)
    }
    expected_events = {
        (parsed.unit.unit_id, parsed.event_kind, parsed.event_index): parsed
        for raw in authority.get("events", [])
        for parsed in (EventBinding.parse(raw),)
    }
    parsed_indirect_exits = [
        IndirectExitBinding.parse(raw)
        for raw in authority.get("indirect_exits", [])
    ]
    expected_indirect_exits = {
        parsed.exit_id: parsed for parsed in parsed_indirect_exits
    }
    if len(expected_indirect_exits) != len(parsed_indirect_exits):
        issues.append(_contradiction(
            "indirect_exit_binding_duplicated",
            "manifest indirect-exit bindings contain duplicate identities",
        ))
    for unit in units:
        expected = expected_units.get(unit.unit_id)
        if expected is None:
            issues.append(_missing("unit_binding_missing", f"manifest has no binding for unit {unit.unit_id}"))
        elif expected != unit:
            issues.append(_contradiction("unit_binding_mismatch", f"manifest binding for unit {unit.unit_id} is stale"))
    for item in events:
        event = item["binding"]
        key = (event.unit.unit_id, event.event_kind, event.event_index)
        expected = expected_events.get(key)
        if expected is None:
            issues.append(_missing("event_binding_missing", f"manifest has no binding for {key[0]} {key[1]} event {key[2]}"))
        elif expected != event:
            issues.append(_contradiction("event_binding_mismatch", f"manifest binding for {key[0]} {key[1]} event {key[2]} is stale"))
        indirect_exit = item.get("indirect_exit")
        if isinstance(indirect_exit, IndirectExitBinding):
            expected_exit = expected_indirect_exits.get(indirect_exit.exit_id)
            if expected_exit is None:
                issues.append(_missing(
                    "indirect_exit_binding_missing",
                    f"manifest has no binding for {indirect_exit.exit_id}",
                ))
            elif expected_exit != indirect_exit:
                issues.append(_contradiction(
                    "indirect_exit_binding_mismatch",
                    f"manifest binding for {indirect_exit.exit_id} is stale",
                ))
    observed_exit_ids = {
        item["indirect_exit"].exit_id
        for item in events
        if isinstance(item.get("indirect_exit"), IndirectExitBinding)
    }
    for unexpected_exit_id in sorted(set(expected_indirect_exits) - observed_exit_ids):
        issues.append(_contradiction(
            "indirect_exit_binding_unexpected",
            f"manifest contains stale indirect-exit binding {unexpected_exit_id}",
        ))
    for row, unit in zip(rows, units, strict=True):
        declared = _mapping_or_empty(row.get("source")).get("instruction_bytes_sha256")
        if declared != unit.instruction_bytes_sha256:
            issues.append(_contradiction("instruction_hash_mismatch", f"unit {unit.unit_id} instruction bytes contradict its declared digest"))
    return _issues(issues)


def _typed_records(values: Iterable[AuthorityRecord | Mapping[str, Any]]) -> tuple[AuthorityRecord, ...]:
    result: list[AuthorityRecord] = []
    for value in values:
        if isinstance(value, (EntryStateContract, ValueFact, MachineABIPremiseAuthority, GlobalSlotInvariant, CallFrameSummary, IndirectExitCertificate, CheckedExternalSite)):
            result.append(value)
        elif isinstance(value, Mapping) and value.get("schema_version") == 2:
            result.append(parse_authority_record(value))
        # Legacy authority rows are diagnostic-only and intentionally ignored.
    return tuple(result)


def _roots(value: Sequence[Mapping[str, Any]] | Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    raw = value.get("roots", ()) if isinstance(value, Mapping) else value
    return tuple(_mapping(row, "behavioral root") for row in raw)


def _interprocedural(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {
        "call_summaries": getattr(value, "call_summaries", {}),
        "recovered_targets": getattr(value, "recovered_targets", ()),
        "fixed_point": getattr(value, "fixed_point", {}),
    }


def _machine_abi_premise_authorities(
    *,
    fixed: Mapping[str, Any],
    binary: BinaryBinding,
) -> dict[str, MachineABIPremiseAuthority]:
    raw = fixed.get("normal_call_abi_premise")
    if raw is None:
        return {}
    try:
        premise = parse_normal_call_abi_premise(raw)
    except (TypeError, ValueError):
        return {}

    inventory = fixed.get("dependencies")
    rows = inventory if isinstance(inventory, list) else []
    matching = [
        row
        for row in rows
        if isinstance(row, Mapping)
        and (
            row.get("kind") == "normal_call_abi_premise"
            or str(row.get("id", "")).startswith("normal-call-abi-premise:")
        )
    ]
    valid = (
        len(matching) == 1
        and matching[0].get("id") == premise.dependency_id
        and matching[0].get("kind") == "normal_call_abi_premise"
        and matching[0].get("status") == "complete"
        and matching[0].get("lattice_complete") is True
        and matching[0].get("dependencies") == []
    )
    issues = () if valid else _issues((
        _contradiction(
            "normal_call_abi_premise_dependency_mismatch",
            "the reviewed machine ABI premise does not match its typed dependency node",
        ),
    ))
    record = MachineABIPremiseAuthority(
        binary=binary,
        premise=premise,
        issues=issues,
    )
    return {premise.dependency_id: record}


def _summary_machine_abi_premise_dependencies(
    summaries: Sequence[Any],
    *,
    machine_abi_premises: Mapping[str, MachineABIPremiseAuthority],
    include: bool = True,
) -> tuple[tuple[AuthorityDependency, ...], tuple[EvidenceIssue, ...]]:
    if not include:
        return (), ()
    dependencies: set[AuthorityDependency] = set()
    issues: list[EvidenceIssue] = []
    for summary in summaries:
        if not isinstance(summary, Mapping):
            continue
        raw_dependencies = summary.get("target_dependencies", ())
        if not isinstance(raw_dependencies, Sequence) or isinstance(
            raw_dependencies, (str, bytes)
        ):
            continue
        for dependency_id in raw_dependencies:
            if not isinstance(dependency_id, str) or not dependency_id.startswith(
                "normal-call-abi-premise:"
            ):
                continue
            premise = machine_abi_premises.get(dependency_id)
            if premise is None:
                issues.append(_contradiction(
                    "normal_call_abi_premise_dependency_invalid",
                    f"call summary requires invalid premise {dependency_id}",
                ))
                continue
            dependencies.add(AuthorityDependency(
                "machine_abi_premise", premise.content_id
            ))
            if premise.status is not AuthorityStatus.COMPLETE:
                issues.append(_contradiction(
                    "normal_call_abi_premise_dependency_invalid",
                    f"call summary requires contradictory premise {dependency_id}",
                ))
    return tuple(sorted(dependencies)), _issues(issues)


def _add_machine_abi_premise_dependencies(
    dependencies: Sequence[AuthorityDependency],
    *,
    machine_abi_premises: Mapping[str, MachineABIPremiseAuthority],
    add: Callable[..., None],
) -> None:
    by_content_id = {
        record.content_id: record for record in machine_abi_premises.values()
    }
    for dependency in dependencies:
        record = by_content_id.get(dependency.content_id)
        if record is not None:
            add(record, is_required=False)


def _rows(value: Any, key: str) -> tuple[Mapping[str, Any], ...]:
    rows = _mapping_or_empty(value).get(key, ())
    return tuple(row for row in rows if isinstance(row, Mapping))


def _indirect_exit_binding(event: Mapping[str, Any]) -> IndirectExitBinding:
    binding = event.get("indirect_exit")
    if not isinstance(binding, IndirectExitBinding):
        raise HybridAuthorityBuilderV2Error(
            "an indirect machine event has no exact indirect-exit binding"
        )
    return binding


def _matching_recovery(
    rows: Sequence[Any], event: Mapping[str, Any]
) -> tuple[Mapping[str, Any] | None, tuple[EvidenceIssue, ...]]:
    binding = _indirect_exit_binding(event)
    status, recovery, code = match_indirect_recovery_v2(rows, binding)
    if status == "complete":
        return recovery, ()
    assert code is not None
    issue = (
        _contradiction(code, f"indirect recovery for {binding.exit_id} is corrupt")
        if status == "violated"
        else _missing(code, f"indirect exit {binding.exit_id} has no recovery fact")
    )
    return None, (issue,)


def _checked_profile_dispatch_value_fact(
    recovery: Mapping[str, Any] | None,
    *,
    binding: EventBinding,
    dependencies: tuple[AuthorityDependency, ...],
) -> tuple[ValueFact | None, tuple[EvidenceIssue, ...]]:
    """Bind profile dispatch receiver instances into the v2 authority DAG."""

    if recovery is None:
        return None, ()
    external_targets = recovery.get("external_targets")
    if not isinstance(external_targets, list):
        return None, ()
    profile_kinds = {
        protocol.get("kind")
        for target in external_targets
        if isinstance(target, Mapping)
        for protocol in (target.get("external_protocol"),)
        if isinstance(protocol, Mapping)
        and protocol.get("kind") in {
            "pe32-interface-method", "pe32-operation"
        }
    }
    if not profile_kinds:
        return None, ()
    observed = recovery.get("target_set_dependency")
    if not isinstance(observed, Mapping):
        issue = _missing(
            "profile_dispatch_dependency_missing",
            "profile-backed indirect control has no checked receiver-instance certificate",
        )
        return ValueFact(
            binding=binding,
            location="indirect_target_receiver_instances",
            width_bits=32,
            alternatives=None,
            dependencies=dependencies,
            issues=(issue,),
        ), (issue,)
    try:
        certificate = validate_profile_dispatch_dependency_v2(recovery)
    except (IndirectTargetDependencyV2Error, TypeError, ValueError) as exc:
        issue = _contradiction(
            "profile_dispatch_dependency_corrupt",
            f"profile-backed receiver certificate is inconsistent: {exc}",
        )
        return ValueFact(
            binding=binding,
            location="indirect_target_receiver_instances",
            width_bits=32,
            alternatives=None,
            dependencies=dependencies,
            issues=(issue,),
        ), (issue,)
    instances = certificate.get("receiver_instances")
    if not isinstance(instances, list) or not instances:
        issue = _contradiction(
            "profile_dispatch_receiver_inventory_empty",
            "profile-backed receiver certificate contains no instances",
        )
        return ValueFact(
            binding=binding,
            location="indirect_target_receiver_instances",
            width_bits=32,
            alternatives=None,
            dependencies=dependencies,
            issues=(issue,),
        ), (issue,)
    return ValueFact(
        binding=binding,
        location="indirect_target_receiver_instances",
        width_bits=32,
        alternatives=FiniteAlternatives.of(
            instances,
            maximum=len(instances),
        ),
        dependencies=dependencies,
    ), ()


def _checked_call_frame_dependencies(
    recovery: Mapping[str, Any] | None,
    *,
    call_frames_by_dependency: Mapping[str, CallFrameSummary],
    machine_abi_premises: Mapping[str, MachineABIPremiseAuthority],
    non_call_dependency_ids: frozenset[str] = frozenset(),
) -> tuple[tuple[AuthorityDependency, ...], tuple[EvidenceIssue, ...]]:
    if recovery is None:
        return (), ()
    raw_dependencies = recovery.get("analysis_dependencies", ())
    if not isinstance(raw_dependencies, Sequence) or isinstance(
        raw_dependencies, (str, bytes)
    ):
        return (), _issues((
            _contradiction(
                "call_frame_dependency_corrupt",
                "call-frame dependency inventory is not an array",
            ),
        ))

    dependencies: set[AuthorityDependency] = set()
    issues: list[EvidenceIssue] = []
    for dependency_id in raw_dependencies:
        if not isinstance(dependency_id, str):
            issues.append(_contradiction(
                "call_frame_dependency_corrupt",
                "call-frame dependency ID is not text",
            ))
            continue
        if dependency_id in non_call_dependency_ids:
            continue
        if dependency_id.startswith("indirect-exit:"):
            continue
        if dependency_id.startswith("normal-call-abi-premise:"):
            premise = machine_abi_premises.get(dependency_id)
            if premise is None:
                issues.append(_contradiction(
                    "normal_call_abi_premise_dependency_invalid",
                    f"target provenance requires invalid premise {dependency_id}",
                ))
                continue
            dependencies.add(AuthorityDependency(
                "machine_abi_premise", premise.content_id
            ))
            if premise.status is not AuthorityStatus.COMPLETE:
                issues.append(_contradiction(
                    "normal_call_abi_premise_dependency_invalid",
                    f"target provenance requires contradictory premise {dependency_id}",
                ))
            continue
        if (
            parse_call_frame_dependency(dependency_id) is None
            and parse_call_frame_family_dependency(dependency_id) is None
        ):
            issues.append(_contradiction(
                "analysis_dependency_kind_unsupported",
                f"target provenance has unknown dependency {dependency_id}",
            ))
            continue
        frame = call_frames_by_dependency.get(dependency_id)
        if frame is None:
            issues.append(_missing(
                "call_frame_dependency_missing",
                f"target provenance requires unavailable frame {dependency_id}",
            ))
            continue
        dependencies.add(AuthorityDependency(
            "call_frame_summary", frame.content_id
        ))
        if frame.status is not AuthorityStatus.COMPLETE:
            issues.append(_missing(
                "call_frame_dependency_incomplete",
                f"target provenance crosses incomplete frame {dependency_id}",
            ))
    return tuple(sorted(dependencies)), _issues(issues)


def _indirect_analysis_dependency_ids(
    recovery: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    if recovery is None:
        return ()
    raw_dependencies = recovery.get("analysis_dependencies", ())
    if not isinstance(raw_dependencies, Sequence) or isinstance(
        raw_dependencies, (str, bytes)
    ):
        return ()
    return tuple(sorted({
        dependency_id
        for dependency_id in raw_dependencies
        if isinstance(dependency_id, str)
        and dependency_id.startswith("indirect-exit:")
    }))


def _checked_indirect_exit_dependencies(
    recovery: Mapping[str, Any] | None,
    *,
    certificates_by_exit: Mapping[str, IndirectExitCertificate],
    known_exit_ids: frozenset[str],
    cyclic_dependency_ids: frozenset[str] = frozenset(),
) -> tuple[tuple[AuthorityDependency, ...], tuple[EvidenceIssue, ...]]:
    """Bind recovered target provenance to earlier checked exit certificates."""

    dependencies: set[AuthorityDependency] = set()
    issues: list[EvidenceIssue] = []
    for dependency_id in _indirect_analysis_dependency_ids(recovery):
        if dependency_id in cyclic_dependency_ids:
            issues.append(_missing(
                "indirect_exit_dependency_cycle",
                f"target provenance participates in cycle through {dependency_id}",
            ))
            continue
        certificate = certificates_by_exit.get(dependency_id)
        if certificate is None:
            issues.append(_missing(
                "indirect_exit_dependency_missing",
                (
                    f"target provenance requires unavailable exit {dependency_id}"
                    if dependency_id in known_exit_ids
                    else f"target provenance names unknown exit {dependency_id}"
                ),
            ))
            continue
        dependencies.add(AuthorityDependency(
            "indirect_exit_certificate",
            certificate.content_id,
        ))
        if certificate.status is not AuthorityStatus.COMPLETE:
            issues.append(_missing(
                "indirect_exit_dependency_incomplete",
                f"target provenance crosses incomplete exit {dependency_id}",
            ))
    return tuple(sorted(dependencies)), _issues(issues)


def _checked_mutable_dependencies(
    recovery: Mapping[str, Any] | None,
    *,
    binary: BinaryBinding,
    globals_by_content_id: Mapping[str, GlobalSlotInvariant],
) -> tuple[tuple[AuthorityDependency, ...], tuple[EvidenceIssue, ...]]:
    """Resolve mutable-slot claims against canonical records, never row status."""

    if recovery is None:
        return (), ()
    raw_details = recovery.get("mutable_slot_dependencies", ())
    raw_dependencies = recovery.get("authority_dependencies", ())
    if (
        not isinstance(raw_details, Sequence)
        or isinstance(raw_details, (str, bytes))
        or not isinstance(raw_dependencies, Sequence)
        or isinstance(raw_dependencies, (str, bytes))
    ):
        return (), _issues((
            _contradiction(
                "mutable_slot_dependency_corrupt",
                "mutable-slot dependency inventories are not arrays",
            ),
        ))

    declared: set[str] = set()
    malformed_declaration = False
    for raw in raw_dependencies:
        if not isinstance(raw, Mapping):
            malformed_declaration = True
            continue
        if raw.get("role") != "mutable_slot_invariant":
            continue
        content_id = raw.get("content_id")
        if not isinstance(content_id, str):
            malformed_declaration = True
            continue
        declared.add(content_id)

    dependencies: set[AuthorityDependency] = set()
    observed: set[str] = set()
    issues: list[EvidenceIssue] = []
    seen_slots: set[tuple[int, int]] = set()
    for raw in raw_details:
        if not isinstance(raw, Mapping):
            issues.append(_contradiction(
                "mutable_slot_dependency_corrupt",
                "a mutable-slot dependency is not an object",
            ))
            continue
        slot_rva = raw.get("slot_rva")
        width_bytes = raw.get("width_bytes")
        content_id = raw.get("content_id")
        if (
            not isinstance(slot_rva, int)
            or isinstance(slot_rva, bool)
            or not 0 <= slot_rva <= 0xFFFF_FFFF
            or not isinstance(width_bytes, int)
            or isinstance(width_bytes, bool)
            or width_bytes != 4
        ):
            issues.append(_contradiction(
                "mutable_slot_dependency_corrupt",
                "a mutable-slot dependency has an invalid exact span",
            ))
            continue
        subject = (slot_rva, width_bytes)
        if subject in seen_slots:
            issues.append(_contradiction(
                "mutable_slot_dependency_duplicated",
                f"mutable slot RVA {slot_rva:#x} is declared more than once",
            ))
            continue
        seen_slots.add(subject)
        if not isinstance(content_id, str):
            issues.append(_missing(
                "mutable_slot_invariant_missing",
                f"mutable slot RVA {slot_rva:#x} has no exact v2 content ID",
            ))
            continue
        observed.add(content_id)
        record = globals_by_content_id.get(content_id)
        if record is None:
            issues.append(_missing(
                "mutable_slot_invariant_missing",
                f"mutable slot RVA {slot_rva:#x} has no supplied v2 invariant",
            ))
            continue
        record_binary = (
            record.binding.binary
            if isinstance(record.binding, (UnitBinding, ImageSpanBinding))
            else record.binding.unit.binary
        )
        if (
            record_binary != binary
            or record.slot_rva != slot_rva
            or record.width_bytes != width_bytes
        ):
            issues.append(_contradiction(
                "mutable_slot_invariant_binding_mismatch",
                f"mutable slot RVA {slot_rva:#x} does not match its exact v2 record",
            ))
            continue
        if content_id in declared:
            dependencies.add(AuthorityDependency(
                "mutable_slot_invariant", content_id
            ))
        if record.status is not AuthorityStatus.COMPLETE:
            issues.append(_missing(
                "mutable_slot_invariant_incomplete",
                f"mutable slot RVA {slot_rva:#x} has incomplete or tainted v2 evidence",
            ))
            continue
        if content_id not in declared:
            issues.append(_contradiction(
                "mutable_slot_dependency_undeclared",
                f"mutable slot RVA {slot_rva:#x} is not declared as an authority dependency",
            ))
            continue

    if malformed_declaration or declared != observed:
        issues.append(_contradiction(
            "mutable_slot_dependency_inventory_mismatch",
            "mutable-slot authority IDs and exact slot bindings disagree",
        ))
    return tuple(sorted(dependencies)), _issues(issues)


def _global_slot_analysis_dependency_ids(
    recovery: Mapping[str, Any] | None,
) -> tuple[str, ...]:
    """Classify well-formed slot IDs even when their evidence is unavailable."""

    if recovery is None:
        return ()
    values = recovery.get("analysis_dependencies", ())
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        return ()
    result: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            kind = _content_id_kind(value)
        except AuthorityDataError:
            continue
        if kind == GlobalSlotInvariant.KIND:
            result.add(value)
    return tuple(sorted(result))


def _call_targets(
    event: Mapping[str, Any],
    by_id: Mapping[str, UnitBinding],
    by_rva: Mapping[int, UnitBinding],
    recovery: Mapping[str, Any] | None,
) -> tuple[UnitBinding, ...]:
    unit_id = event.get("target_unit_id")
    if isinstance(unit_id, str):
        target = by_id.get(unit_id)
        return () if target is None else (target,)
    rva = event.get("target_rva")
    if isinstance(rva, int):
        target = by_rva.get(rva)
        return () if target is None else (target,)
    targets = recovery.get("target_unit_ids", []) if recovery is not None else []
    if not isinstance(targets, list):
        return ()
    return tuple(
        sorted(
            {
                by_id[target]
                for target in targets
                if isinstance(target, str) and target in by_id
            },
            key=lambda item: item.unit_id,
        )
    )


def _call_abi(event: Mapping[str, Any]) -> str:
    contract = _mapping_or_empty(event.get("abi_contract"))
    value = contract.get("template", event.get("abi"))
    return value if isinstance(value, str) and value else "x86-pe32-v2"


def _call_frame_alternative(
    summary: Mapping[str, Any], callee: UnitBinding
) -> dict[str, Any]:
    """Project one legacy analysis row into the stable v2 frame families."""

    preservation = _mapping_or_empty(summary.get("register_preservation"))
    preserved = summary.get("preserved_registers")
    return {
        "format": "spaghetti-extractor-call-frame-families-v2",
        "status": summary.get("status", "incomplete"),
        "callee": callee.to_payload(),
        "return_behavior": dict(
            _mapping_or_empty(summary.get("return_behavior"))
        ),
        "stack_cleanup": dict(
            _mapping_or_empty(summary.get("stack_cleanup"))
        ),
        "register_preservation": {
            **dict(preservation),
            "registers": sorted(
                str(register).lower()
                for register in preserved
                if isinstance(register, str)
            )
            if isinstance(preserved, list)
            else [],
        },
        "result_origins": dict(
            _mapping_or_empty(summary.get("result_register_origins"))
        ),
        "memory_effects": dict(
            _mapping_or_empty(summary.get("memory_effects"))
        ) or {"status": "incomplete"},
        "callback_effects": dict(
            _mapping_or_empty(summary.get("callback_effects"))
        ) or {"status": "incomplete"},
        "world_effects": dict(
            _mapping_or_empty(summary.get("world_effects"))
        ) or {"status": "incomplete"},
        "target_dependencies": sorted(
            str(value)
            for value in summary.get("target_dependencies", ())
            if isinstance(value, str)
        ),
        "blocker_codes": sorted(
            str(value)
            for value in summary.get("blocker_codes", ())
            if isinstance(value, str)
        ),
    }


def _call_frame_family_alternative(
    summary: Mapping[str, Any],
    callee: UnitBinding,
    family: str,
    subject: str | None,
) -> dict[str, Any]:
    """Project one independently checked call family into the v2 frame shape."""

    projection = _call_frame_family_projection(summary, family, subject)
    not_applicable = {"status": "not_applicable"}
    fields = {
        "return_behavior": dict(not_applicable),
        "stack_cleanup": dict(not_applicable),
        "register_preservation": dict(not_applicable),
        "result_origins": dict(not_applicable),
        "memory_effects": dict(not_applicable),
        "callback_effects": dict(not_applicable),
        "world_effects": dict(not_applicable),
    }
    field = {
        "memory": "memory_effects",
        "register": "register_preservation",
        "result": "result_origins",
        "return": "return_behavior",
        "stack": "stack_cleanup",
    }[family]
    fields[field] = projection
    complete = projection.get("status") == "complete"
    return {
        "format": "spaghetti-extractor-call-frame-families-v2",
        "status": "complete" if complete else "incomplete",
        "callee": callee.to_payload(),
        **fields,
        "target_dependencies": [],
        "blocker_codes": [] if complete else [f"{family}_frame_unknown"],
    }


def _call_frame_family_projection(
    summary: Mapping[str, Any],
    family: str,
    subject: str | None,
) -> dict[str, Any]:
    if family == "register":
        preserved = summary.get("preserved_registers")
        preservation = _mapping_or_empty(summary.get("register_preservation"))
        checked = preservation.get("checked_preserved_registers")
        if preservation.get("status") == "complete":
            checked = preserved
        if (
            isinstance(subject, str)
            and isinstance(preserved, list)
            and isinstance(checked, list)
            and all(isinstance(register, str) for register in preserved)
            and all(isinstance(register, str) for register in checked)
            and len(preserved) == len(set(preserved))
            and len(checked) == len(set(checked))
            and set(preserved) == set(checked)
            and subject in checked
        ):
            return {"status": "complete", "registers": [subject]}
        return {"status": "incomplete", "registers": []}

    if family == "stack":
        stack = _mapping_or_empty(summary.get("stack_cleanup"))
        instruction = _mapping_or_empty(
            summary.get("return_instruction_cleanup")
        )
        values = {
            value
            for value in (
                stack.get("stack_delta")
                if stack.get("status") == "complete"
                else None,
                instruction.get("cleanup_bytes")
                if instruction.get("status") == "complete"
                else None,
            )
            if isinstance(value, int)
            and not isinstance(value, bool)
            and 0 <= value <= 0xFFFFFFFF
        }
        if len(values) == 1:
            return {"status": "complete", "stack_delta": next(iter(values))}
        return {"status": "incomplete", "stack_delta": None}

    if family == "result":
        registers_row = _mapping_or_empty(
            summary.get("result_register_origins")
        )
        memory_row = _mapping_or_empty(summary.get("result_memory_origins"))
        registers = registers_row.get("registers")
        locations = memory_row.get("locations")
        registers_valid = (
            registers_row.get("status") == "complete"
            and isinstance(registers, Mapping)
            and all(
                isinstance(register, str)
                and register
                and isinstance(origin, Mapping)
                for register, origin in registers.items()
            )
        )
        checked_registers = (
            {
                str(register): dict(origin)
                for register, origin in registers.items()
            }
            if registers_valid
            else {}
        )
        checked_locations = (
            [dict(location) for location in locations]
            if memory_row.get("status") == "complete"
            and isinstance(locations, list)
            and all(isinstance(location, Mapping) for location in locations)
            else []
        )
        if checked_registers or checked_locations:
            return {
                "status": "complete",
                "registers": checked_registers,
                "memory_locations": checked_locations,
            }
        return {
            "status": "incomplete",
            "registers": {},
            "memory_locations": [],
        }

    if family == "memory":
        frame = _mapping_or_empty(summary.get("caller_memory_frame"))
        writes = frame.get("writes")
        if (
            set(frame) == {"status", "preserved", "writes"}
            and frame.get("status") == "complete"
            and isinstance(frame.get("preserved"), bool)
            and isinstance(writes, list)
            and all(
                isinstance(write, Mapping)
                and set(write) == {"base", "size"}
                and isinstance(write.get("base"), Mapping)
                and (
                    write.get("size") is None
                    or isinstance(write.get("size"), int)
                    and not isinstance(write.get("size"), bool)
                    and write["size"] >= 0
                )
                for write in writes
            )
        ):
            return {
                "status": "complete",
                "preserved": frame["preserved"],
                "writes": [dict(write) for write in writes],
            }
        legacy = _mapping_or_empty(summary.get("memory_effects"))
        if legacy.get("status") == "complete":
            return dict(legacy)
        return {"status": "incomplete"}

    if family == "return":
        behavior = _mapping_or_empty(summary.get("return_behavior"))
        if (
            behavior.get("status") == "complete"
            and isinstance(behavior.get("may_return"), bool)
            and isinstance(behavior.get("may_not_return"), bool)
        ):
            return dict(behavior)
        return {"status": "incomplete"}

    raise HybridAuthorityBuilderV2Error(
        f"unsupported call-summary family {family!r}"
    )


def _call_frame_families_complete(summary: Mapping[str, Any]) -> bool:
    required = (
        "stack_cleanup",
        "result_register_origins",
        "return_behavior",
        "memory_effects",
        "callback_effects",
        "world_effects",
    )
    return checked_summary_register_frame_complete(summary) and all(
        _mapping_or_empty(summary.get(family)).get("status")
        in {"complete", "not_applicable"}
        for family in required
    )


def _isa_forms(
    value: Any | None,
    requirements: MachineIRISARequirementsV2 | None,
) -> tuple[Mapping[str, Any], ...]:
    authority = getattr(value, "authority", value)
    if authority is None:
        return ()
    if isinstance(authority, MachineIRISASelectionCertificateV2):
        if requirements is None:
            return ()
        selection_by_id = {
            str(row["form_id"]): row for row in authority.forms
        }
        return tuple({
            "form_id": requirement.form_id,
            "semantic_form": requirement.semantic_form,
            "source_locations": [
                {
                    "image_id": location.image_id,
                    "image_sha256": location.image_sha256,
                    "rva": location.rva,
                    "byte_length": location.byte_length,
                }
                for location in requirement.source_locations
            ],
            "qualification_sha256": selection_by_id.get(
                requirement.form_id, {}
            ).get("qualification_sha256"),
            "status": selection_by_id.get(requirement.form_id, {}).get(
                "status", "incomplete"
            ),
        } for requirement in requirements.forms)
    requirements = getattr(authority, "requirements", None)
    if requirements is not None and hasattr(requirements, "to_payload"):
        requirements = requirements.to_payload()
    if requirements is None and isinstance(authority, Mapping):
        requirements = authority.get("requirements")
    forms = _mapping_or_empty(requirements).get("forms", ())
    return tuple(row for row in forms if isinstance(row, Mapping))


def _qualified_isa_authority(
    value: Any | None,
) -> ISAKernelSelectionAuthority | MachineIRISASelectionCertificateV2 | None:
    if isinstance(value, ISAKernelSelectionAuthorityCheck):
        if value.status is not SelectionAuthorityStatus.QUALIFIED:
            return None
        value = value.authority
    if value is None:
        return None
    if isinstance(value, MachineIRISASelectionCertificateV2):
        return value if value.status == "qualified" else None
    if isinstance(value, ISAKernelSelectionAuthority):
        authority = value
    elif isinstance(value, Mapping):
        try:
            if value.get("format") == (
                "spaghetti-extractor-machine-ir-isa-selection-certificate-v2"
            ):
                certificate = parse_machine_ir_isa_selection_certificate_v2(value)
                return certificate if certificate.status == "qualified" else None
            authority = parse_isa_kernel_selection_authority(value)
        except (TypeError, ValueError):
            return None
    else:
        return None
    return (
        authority
        if authority.status is SelectionAuthorityStatus.QUALIFIED
        else None
    )


def _fallback_capability_id(
    authority: ISAKernelSelectionAuthority | MachineIRISASelectionCertificateV2,
    form_id: str,
) -> str | None:
    if isinstance(authority, MachineIRISASelectionCertificateV2):
        return dict(authority.fallback_capability_ids).get(form_id)
    return next(
        (
            row.capability_id
            for row in authority.fallback_capability_ids
            if row.form_id == form_id
        ),
        None,
    )


def _isa_authority_sha256(
    authority: ISAKernelSelectionAuthority | MachineIRISASelectionCertificateV2,
) -> str:
    if isinstance(authority, MachineIRISASelectionCertificateV2):
        return authority.certificate_sha256
    return authority.authority_sha256


def _marker(
    unit: UnitBinding, location: str, issues: Sequence[EvidenceIssue]
) -> ValueFact:
    return ValueFact(
        binding=unit,
        location=location,
        width_bits=1,
        alternatives=FiniteAlternatives.of([{"checked": False}], maximum=1),
        issues=_issues(issues),
    )


def _missing(code: str, detail: str) -> EvidenceIssue:
    return EvidenceIssue(EvidenceIssueKind.MISSING, code, detail)


def _contradiction(code: str, detail: str) -> EvidenceIssue:
    return EvidenceIssue(EvidenceIssueKind.CONTRADICTORY, code, detail)


def _issues(values: Iterable[EvidenceIssue]) -> tuple[EvidenceIssue, ...]:
    return tuple(sorted(set(values), key=lambda row: (row.kind.value, row.code, row.detail)))


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise HybridAuthorityBuilderV2Error(f"{context} must be an object")
    return value


def _mapping_or_empty(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _sequence(value: Any, context: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise HybridAuthorityBuilderV2Error(f"{context} must be an array")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise HybridAuthorityBuilderV2Error(f"{context} must be nonempty text")
    return value


def _uint(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFFFFFF:
        raise HybridAuthorityBuilderV2Error(f"{context} must be an unsigned integer")
    return value


__all__ = [
    "MACHINE_IR_AUTHORITY_BINDINGS_FORMAT",
    "HybridAuthorityBuilderV2Error",
    "build_hybrid_authority_v2",
    "build_machine_ir_authority_bindings",
    "canonical_event_sha256",
    "canonical_unit_sha256",
    "machine_ir_sha256",
    "recompute_event_binding",
    "recompute_unit_binding",
]
