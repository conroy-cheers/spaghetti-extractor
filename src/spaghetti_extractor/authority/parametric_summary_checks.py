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
from .call_boundary_contracts import CallBoundaryContractV3
from .catalog_call_contracts import CatalogCallContractV1
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


@dataclass(frozen=True, order=True)
class DirectCallEvidenceV3:
    source_unit_id: str
    event_index: int
    target_unit_id: str | None


@dataclass(frozen=True, order=True)
class StackAccessEvidenceV3:
    access_id: str
    unit_id: str
    kind: str
    entry_esp_offset: int
    width_bytes: int
    value: Any | None = None


@dataclass(frozen=True, order=True)
class MemoryEffectEvidenceV3:
    unit_id: str
    alias_component_id: str
    kind: str


@dataclass(frozen=True, order=True)
class ExternalCallEvidenceV3:
    event_index: int
    transfer_kind: str
    identity: CanonicalValueV3


@dataclass(frozen=True)
class IndirectExpressionEvidenceV3:
    exit_id: str
    event_index: int | None
    transfer_kind: str
    expression: Any
    expression_sha256: str


@dataclass(frozen=True)
class CheckedIndirectTargetEvidenceV3:
    exit_id: str
    origins: tuple[ValueOriginV3, ...]
    target_unit_ids: tuple[str, ...]
    external_profile_record_ids: tuple[str, ...]
    support_unit_ids: tuple[str, ...]
    support_profile_ids: tuple[str, ...]


@dataclass(frozen=True)
class UnitSummaryEvidenceV3:
    unit_id: str
    pe_sha256: str
    transition_summary_id: str
    rva_start: int
    input_registers: tuple[str, ...]
    register_outputs: tuple[tuple[str, Any], ...]
    stack_net_bytes: int | None
    returns: bool
    may_not_return: bool
    external_calls: tuple[ExternalCallEvidenceV3, ...]
    direct_calls: tuple[DirectCallEvidenceV3, ...]
    indirect_expressions: tuple[IndirectExpressionEvidenceV3, ...]
    event_register_inputs: tuple[tuple[int, tuple[tuple[str, Any], ...]], ...]
    stack_accesses: tuple[StackAccessEvidenceV3, ...] = ()
    indirect_call_event_indices: tuple[int, ...] = ()
    direct_target_unit_ids: tuple[str, ...] = ()
    unresolved_direct_target_rvas: tuple[int, ...] = ()
    return_cleanup_bytes: int | None = None

    def output(self, register: str) -> Any | None:
        return next(
            (value for name, value in self.register_outputs if name == register), None
        )

    def event_register_input(self, event_index: int, register: str) -> Any | None:
        return next(
            (
                value
                for index, inputs in self.event_register_inputs
                if index == event_index
                for name, value in inputs
                if name == register
            ),
            None,
        )


@dataclass(frozen=True)
class ParametricSccEvidenceV3:
    scc_id: str
    member_unit_ids: tuple[str, ...]
    recursive: bool
    units: tuple[UnitSummaryEvidenceV3, ...]
    unknown_kill_components: tuple[str, ...]
    memory_effects: tuple[MemoryEffectEvidenceV3, ...]
    unversioned_memory_access_ids: tuple[str, ...]
    structural_targets: tuple[StructuralTargetProposalV3, ...]
    external_profiles: tuple[ExternalProfileV3, ...]
    expected_dependencies: tuple[RecordDependencyV3, ...]
    catalog_call_contracts: tuple[CatalogCallContractV1, ...] = ()
    call_boundary_contracts: tuple[CallBoundaryContractV3, ...] = ()
    invalid_catalog_call_contract_ids: tuple[str, ...] = ()
    program_units: tuple[UnitSummaryEvidenceV3, ...] = ()
    static_image: PE32StaticImageV3 | None = None
    import_slots: tuple[PE32ImportSlotV3, ...] = ()
    checked_indirect_targets: tuple[CheckedIndirectTargetEvidenceV3, ...] = ()
    program_memory_effects: tuple[MemoryEffectEvidenceV3, ...] = ()
    program_unversioned_memory_unit_ids: tuple[str, ...] = ()

    def unit(self, unit_id: str) -> UnitSummaryEvidenceV3 | None:
        return next((row for row in self.units if row.unit_id == unit_id), None)

    def structural_target(self, exit_id: str) -> StructuralTargetProposalV3 | None:
        return next(
            (row for row in self.structural_targets if row.record_id == exit_id), None
        )

    def external_profile(self, record_id: str) -> ExternalProfileV3 | None:
        return next(
            (row for row in self.external_profiles if row.record_id == record_id), None
        )

    def catalog_call_contract(
        self, target_entry_unit_id: str
    ) -> CatalogCallContractV1 | None:
        rows = tuple(
            row
            for row in self.catalog_call_contracts
            if row.target_entry_unit_id == target_entry_unit_id
            and row.contract_id not in self.invalid_catalog_call_contract_ids
        )
        return rows[0] if len(rows) == 1 else None

    def call_boundary_contract(
        self, target_entry_unit_id: str
    ) -> CallBoundaryContractV3 | None:
        rows = tuple(
            row
            for row in self.call_boundary_contracts
            if row.record_id == target_entry_unit_id and row.authorizing
        )
        return rows[0] if len(rows) == 1 else None

    def all_units(self) -> tuple[UnitSummaryEvidenceV3, ...]:
        return self.program_units or self.units

    def checked_indirect_target(
        self, exit_id: str
    ) -> CheckedIndirectTargetEvidenceV3 | None:
        return next(
            (row for row in self.checked_indirect_targets if row.exit_id == exit_id),
            None,
        )


def _expression_is_register(value: Any, register: str) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("op") == "reg"
        and value.get("name") == register
    )


def _expression_constant(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    result = value.get("value")
    if (
        not isinstance(result, int)
        or isinstance(result, bool)
        or not 0 <= result < 1 << 32
    ):
        return None
    return result


def _external_identity(value: Any) -> CanonicalValueV3:
    exact = mapping(value, "exact external-call record")
    imported = exact.get("import")
    source = imported if isinstance(imported, Mapping) else exact
    dll = source.get("dll")
    symbol = source.get("symbol")
    ordinal = source.get("ordinal")
    if (
        isinstance(dll, str)
        and dll
        and (
            (isinstance(symbol, str) and bool(symbol))
            != (isinstance(ordinal, int) and not isinstance(ordinal, bool))
        )
    ):
        return CanonicalValueV3.of(
            {
                "kind": "import",
                "dll": dll.lower(),
                "symbol": symbol if isinstance(symbol, str) and symbol else None,
                "ordinal": (
                    ordinal
                    if isinstance(ordinal, int) and not isinstance(ordinal, bool)
                    else None
                ),
            }
        )
    protocol = source.get("external_protocol")
    if isinstance(protocol, Mapping) and protocol:
        return CanonicalValueV3.of({"kind": "protocol", "protocol": dict(protocol)})
    return CanonicalValueV3.of({})


def _profile_matches_call_v3(
    profile: ExternalProfileV3, call: ExternalCallEvidenceV3
) -> bool:
    if call.transfer_kind not in profile.allowed_transfers:
        return False
    exact = mapping(call.identity.to_value(), "exact external-call identity")
    expected = mapping(profile.identity.to_value(), "external profile identity")
    return all(exact.get(key) == value for key, value in expected.items())


def _external_preserved_registers_v3(
    profiles: tuple[ExternalProfileV3, ...], call: ExternalCallEvidenceV3
) -> tuple[str, ...] | None:
    matches = tuple(
        profile for profile in profiles if _profile_matches_call_v3(profile, call)
    )
    if len(matches) != 1:
        return None
    contract = mapping(
        matches[0].machine_contract.to_value(), "external profile machine contract"
    )
    if contract.get("abi_template") not in {
        "pe32-cdecl-v1",
        "pe32-stdcall-v1",
    }:
        return None
    return PE32_CALLEE_PRESERVED_REGISTERS_V3


class _CheckedProfileIndexV3:
    """Run-local index for independently checked external profiles."""

    def __init__(self, profiles: tuple[ExternalProfileV3, ...]) -> None:
        self.profiles = profiles
        self.by_record_id = {row.record_id: row for row in profiles}
        self._call_matches: dict[tuple[bytes, str], tuple[ExternalProfileV3, ...]] = {}
        self._exact_matches: dict[bytes, tuple[ExternalProfileV3, ...]] = {}
        self._abi_preserved: dict[str, tuple[str, ...] | None] = {}

    def matches_call(
        self, call: ExternalCallEvidenceV3
    ) -> tuple[ExternalProfileV3, ...]:
        key = (call.identity.data, call.transfer_kind)
        if key not in self._call_matches:
            self._call_matches[key] = tuple(
                profile
                for profile in self.profiles
                if _profile_matches_call_v3(profile, call)
            )
        return self._call_matches[key]

    def exact_identity(
        self, identity: CanonicalValueV3
    ) -> tuple[ExternalProfileV3, ...]:
        if identity.data not in self._exact_matches:
            self._exact_matches[identity.data] = tuple(
                sorted(
                    (row for row in self.profiles if row.identity == identity),
                    key=lambda row: row.record_id,
                )
            )
        return self._exact_matches[identity.data]

    def abi_preserved(self, profile: ExternalProfileV3) -> tuple[str, ...] | None:
        if profile.record_id not in self._abi_preserved:
            contract = mapping(
                profile.machine_contract.to_value(),
                "external profile machine contract",
            )
            self._abi_preserved[profile.record_id] = (
                PE32_CALLEE_PRESERVED_REGISTERS_V3
                if contract.get("abi_template") in {"pe32-cdecl-v1", "pe32-stdcall-v1"}
                else None
            )
        return self._abi_preserved[profile.record_id]

    def preserved_for_call(
        self, call: ExternalCallEvidenceV3
    ) -> tuple[str, ...] | None:
        matches = self.matches_call(call)
        return self.abi_preserved(matches[0]) if len(matches) == 1 else None


@dataclass(frozen=True)
class _InternalPreservationResultV3:
    complete: bool
    preserved_registers: tuple[str, ...]
    consumed_unit_ids: tuple[str, ...]
    consumed_profile_ids: tuple[str, ...]
    consumed_contract_ids: tuple[str, ...] = ()
    consumed_boundary_contract_record_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class _InternalMemoryFrameResultV3:
    complete: bool
    written_component_ids: tuple[str, ...]
    consumed_unit_ids: tuple[str, ...]
    consumed_profile_ids: tuple[str, ...]
    consumed_contract_ids: tuple[str, ...] = ()


def _direct_control_closure_v3(
    entry_unit_id: str,
    units: Mapping[str, UnitSummaryEvidenceV3],
) -> tuple[tuple[str, ...], bool]:
    pending = [entry_unit_id]
    visited: set[str] = set()
    complete = True
    while pending:
        unit_id = pending.pop()
        if unit_id in visited:
            continue
        unit = units.get(unit_id)
        if unit is None:
            complete = False
            continue
        visited.add(unit_id)
        if unit.unresolved_direct_target_rvas:
            complete = False
        for target_id in unit.direct_target_unit_ids:
            if target_id not in units:
                complete = False
            elif target_id not in visited:
                pending.append(target_id)
    return tuple(sorted(visited)), complete


def _has_nonrecursive_return_path_v3(
    entry_unit_id: str,
    closure: tuple[str, ...],
    recursive_entries: frozenset[str],
    units: Mapping[str, UnitSummaryEvidenceV3],
    indirect_internal_targets: Mapping[str, tuple[str, ...]],
) -> bool:
    closure_set = set(closure)
    pending = [entry_unit_id]
    visited: set[str] = set()
    while pending:
        unit_id = pending.pop()
        if unit_id in visited or unit_id not in closure_set:
            continue
        visited.add(unit_id)
        unit = units[unit_id]
        if any(
            call.target_unit_id in recursive_entries for call in unit.direct_calls
        ) or any(
            target_id in recursive_entries
            for target_id in indirect_internal_targets.get(unit_id, ())
        ):
            continue
        if unit.returns:
            return True
        pending.extend(
            target_id
            for target_id in unit.direct_target_unit_ids
            if target_id not in visited
        )
    return False


def _checked_internal_preservation_v3(
    target_unit_ids: tuple[str, ...],
    evidence: ParametricSccEvidenceV3,
    profile_index: _CheckedProfileIndexV3 | None = None,
) -> _InternalPreservationResultV3:
    """Check normal-return preservation over finite control/call closures.

    The analysis starts every call-entry equation at true and removes equations
    contradicted by exact local semantics.  Recursive call SCCs therefore use
    an explicit greatest fixed point, while the separate base-path check rules
    out vacuous cycles with no normal return.
    """

    if profile_index is None:
        profile_index = _CheckedProfileIndexV3(evidence.external_profiles)
    catalog_contracts = tuple(
        evidence.catalog_call_contract(target) for target in target_unit_ids
    )
    if catalog_contracts and all(
        row is not None and row.preserved_registers is not None
        for row in catalog_contracts
    ):
        checked_contracts = tuple(
            row for row in catalog_contracts if row is not None
        )
        preserved = set(PE32_CALLEE_PRESERVED_REGISTERS_V3)
        for contract in checked_contracts:
            preserved.intersection_update(contract.preserved_registers or ())
        return _InternalPreservationResultV3(
            True,
            tuple(sorted(preserved)),
            tuple(sorted(set(target_unit_ids))),
            (),
            tuple(sorted(row.contract_id for row in checked_contracts)),
        )
    boundary_contracts = tuple(
        evidence.call_boundary_contract(target) for target in target_unit_ids
    )
    if boundary_contracts and all(row is not None for row in boundary_contracts):
        checked_boundaries = tuple(
            row for row in boundary_contracts if row is not None
        )
        preserved = set(PE32_CALLEE_PRESERVED_REGISTERS_V3)
        for contract in checked_boundaries:
            preserved.intersection_update(contract.preserved_registers)
        return _InternalPreservationResultV3(
            True,
            tuple(sorted(preserved)),
            tuple(sorted(set(target_unit_ids))),
            (),
            (),
            tuple(sorted(row.record_id for row in checked_boundaries)),
        )
    units = {row.unit_id: row for row in evidence.all_units()}
    if len(units) != len(evidence.all_units()):
        return _InternalPreservationResultV3(False, (), (), ())
    entries: set[str] = set(target_unit_ids)
    closures: dict[str, tuple[str, ...]] = {}
    indirect_internal_by_unit: dict[str, tuple[str, ...]] = {}
    indirect_external_by_unit: dict[str, tuple[tuple[str, ...] | None, ...]] = {}
    indirect_support_units: set[str] = set()
    consumed_profiles: set[str] = set()
    structurally_complete = True
    pending = list(target_unit_ids)
    while pending:
        entry = pending.pop()
        if entry in closures:
            continue
        closure, complete = _direct_control_closure_v3(entry, units)
        closures[entry] = closure
        structurally_complete &= complete and bool(closure)
        for unit_id in closure:
            unit = units[unit_id]
            for call in unit.direct_calls:
                if call.target_unit_id is None:
                    structurally_complete = False
                    continue
                if call.target_unit_id not in entries:
                    entries.add(call.target_unit_id)
                    pending.append(call.target_unit_id)
            internal_targets: set[str] = set()
            external_preserved: list[tuple[str, ...] | None] = []
            for occurrence in unit.indirect_expressions:
                target = evidence.checked_indirect_target(occurrence.exit_id)
                if target is None:
                    structurally_complete = False
                    continue
                internal_targets.update(target.target_unit_ids)
                indirect_support_units.update(target.support_unit_ids)
                consumed_profiles.update(target.support_profile_ids)
                transfer = (
                    "jump"
                    if "jump" in occurrence.transfer_kind
                    else "call"
                )
                for profile_id in target.external_profile_record_ids:
                    profile = profile_index.by_record_id.get(profile_id)
                    preserved = (
                        None
                        if profile is None
                        or transfer not in profile.allowed_transfers
                        else profile_index.abi_preserved(profile)
                    )
                    external_preserved.append(preserved)
                    consumed_profiles.add(profile_id)
                    if preserved is None:
                        structurally_complete = False
                if not target.target_unit_ids and not target.external_profile_record_ids:
                    structurally_complete = False
            indirect_internal_by_unit[unit_id] = tuple(sorted(internal_targets))
            indirect_external_by_unit[unit_id] = tuple(external_preserved)
            for target_id in internal_targets:
                if target_id not in units:
                    structurally_complete = False
                elif target_id not in entries:
                    entries.add(target_id)
                    pending.append(target_id)

    call_edges = {
        entry: {
            call.target_unit_id
            for unit_id in closures.get(entry, ())
            for call in units[unit_id].direct_calls
            if call.target_unit_id is not None
        }
        | {
            target_id
            for unit_id in closures.get(entry, ())
            for target_id in indirect_internal_by_unit.get(unit_id, ())
        }
        for entry in entries
    }
    recursive_components: list[frozenset[str]] = []
    for component in partition_call_graph_sccs_v3(entries, call_edges):
        recursive = len(component) > 1 or any(
            entry in call_edges.get(entry, set()) for entry in component
        )
        if recursive:
            recursive_components.append(frozenset(component))
    for component in recursive_components:
        if not any(
            _has_nonrecursive_return_path_v3(
                entry,
                closures.get(entry, ()),
                component,
                units,
                indirect_internal_by_unit,
            )
            for entry in component
        ):
            structurally_complete = False

    external_preservation: dict[tuple[str, int], tuple[str, ...] | None] = {}
    for entry in entries:
        for unit_id in closures.get(entry, ()):
            unit = units[unit_id]
            for call in unit.external_calls:
                matches = profile_index.matches_call(call)
                if len(matches) == 1:
                    consumed_profiles.add(matches[0].record_id)
                preserved = profile_index.preserved_for_call(call)
                external_preservation[(unit_id, call.event_index)] = preserved
                if preserved is None:
                    structurally_complete = False

    if not structurally_complete:
        return _InternalPreservationResultV3(
            False,
            (),
            tuple(
                sorted(
                    {unit for rows in closures.values() for unit in rows}
                    | indirect_support_units
                )
            ),
            tuple(sorted(consumed_profiles)),
        )

    preserved: list[str] = []
    consumed_units = tuple(
        sorted(
            {unit for rows in closures.values() for unit in rows}
            | indirect_support_units
        )
    )
    for register in PE32_CALLEE_PRESERVED_REGISTERS_V3:
        entry_equations = {entry: True for entry in entries}
        unit_equations = {unit_id: True for unit_id in consumed_units}
        changed = True
        while changed:
            changed = False
            for unit_id in consumed_units:
                unit = units[unit_id]
                output = unit.output(register)
                valid = output is None or _expression_is_register(output, register)
                valid &= all(
                    register in external_preservation[(unit_id, call.event_index)]
                    for call in unit.external_calls
                )
                valid &= all(
                    unit_equations.get(target_id, False)
                    for target_id in unit.direct_target_unit_ids
                )
                valid &= all(
                    call.target_unit_id is not None
                    and entry_equations.get(call.target_unit_id, False)
                    for call in unit.direct_calls
                )
                valid &= all(
                    entry_equations.get(target_id, False)
                    for target_id in indirect_internal_by_unit.get(unit_id, ())
                )
                valid &= all(
                    registers is not None and register in registers
                    for registers in indirect_external_by_unit.get(unit_id, ())
                )
                if unit_equations[unit_id] != valid:
                    unit_equations[unit_id] = valid
                    changed = True
            for entry in sorted(entries):
                valid = unit_equations.get(entry, False)
                if entry_equations[entry] != valid:
                    entry_equations[entry] = valid
                    changed = True
        if all(entry_equations.get(target, False) for target in target_unit_ids):
            preserved.append(register)
    return _InternalPreservationResultV3(
        True,
        tuple(preserved),
        consumed_units,
        tuple(sorted(consumed_profiles)),
    )


def _checked_internal_memory_frame_v3(
    target_unit_ids: tuple[str, ...],
    evidence: ParametricSccEvidenceV3,
    profile_index: _CheckedProfileIndexV3 | None = None,
) -> _InternalMemoryFrameResultV3:
    """Compose a finite callee footprint over exact unit summaries.

    The result is intentionally alias-component based. A caller may retain a
    preserved component only when every reachable callee transition is
    classified and none writes or kills that component. Recursive calls are
    handled by the finite visited set; no path enumeration is performed.
    """

    if profile_index is None:
        profile_index = _CheckedProfileIndexV3(evidence.external_profiles)
    contracts = tuple(
        evidence.catalog_call_contract(target) for target in target_unit_ids
    )
    if contracts and all(
        row is not None
        and row.boundary_effects is not None
        and not row.boundary_effects.writes
        for row in contracts
    ):
        checked = tuple(row for row in contracts if row is not None)
        return _InternalMemoryFrameResultV3(
            True,
            (),
            tuple(sorted(set(target_unit_ids))),
            (),
            tuple(sorted(row.contract_id for row in checked)),
        )

    units = {row.unit_id: row for row in evidence.all_units()}
    effects_by_unit: dict[str, list[MemoryEffectEvidenceV3]] = {}
    for effect in evidence.program_memory_effects:
        effects_by_unit.setdefault(effect.unit_id, []).append(effect)
    unversioned_units = set(evidence.program_unversioned_memory_unit_ids)
    pending = list(target_unit_ids)
    visited: set[str] = set()
    written: set[str] = set()
    profiles: set[str] = set()
    complete = True
    while pending:
        unit_id = pending.pop()
        if unit_id in visited:
            continue
        unit = units.get(unit_id)
        if unit is None:
            complete = False
            continue
        visited.add(unit_id)
        if unit.unresolved_direct_target_rvas or unit_id in unversioned_units:
            complete = False
        for effect in effects_by_unit.get(unit_id, ()):
            if effect.kind in {"write", "unknown_kill"}:
                written.add(effect.alias_component_id)
        for target_id in unit.direct_target_unit_ids:
            if target_id not in visited:
                pending.append(target_id)
        for call in unit.direct_calls:
            if call.target_unit_id is None:
                complete = False
            elif call.target_unit_id not in visited:
                pending.append(call.target_unit_id)
        for call in unit.external_calls:
            matches = profile_index.matches_call(call)
            if len(matches) != 1:
                complete = False
                continue
            profile = matches[0]
            profiles.add(profile.record_id)
            if profile.memory_effect != "none":
                complete = False
        for occurrence in unit.indirect_expressions:
            target = evidence.checked_indirect_target(occurrence.exit_id)
            if target is None:
                complete = False
                continue
            profiles.update(target.support_profile_ids)
            for profile_id in target.external_profile_record_ids:
                profile = evidence.external_profile(profile_id)
                if profile is None or profile.memory_effect != "none":
                    complete = False
            for target_id in target.target_unit_ids:
                if target_id not in visited:
                    pending.append(target_id)
    return _InternalMemoryFrameResultV3(
        complete,
        tuple(sorted(written)),
        tuple(sorted(visited)),
        tuple(sorted(profiles)),
    )


def _proposal_fact_map(proposal: ParametricSccProposalV3) -> dict[str, ValueFactV3]:
    return {row.fact_id: row for row in proposal.value_facts}


def _relation_blockers(
    proposal: ParametricSccProposalV3, evidence: ParametricSccEvidenceV3
) -> list[PrimaryBlockerV3]:
    blockers: list[PrimaryBlockerV3] = []
    facts = _proposal_fact_map(proposal)
    relations = {
        (row.unit_id, row.register): row for row in proposal.register_relations
    }
    if len(relations) != len(proposal.register_relations):
        return [PrimaryBlockerV3("violated", "duplicate_register_relation")]
    for unit in evidence.units:
        required = set(unit.input_registers) | {
            name for name, _value in unit.register_outputs
        }
        for register in sorted(required & _GENERAL_REGISTERS):
            relation = relations.get((unit.unit_id, register))
            if relation is None:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "register_relation_missing")
                )
                continue
            fact = facts.get(relation.value_fact_id)
            if fact is None:
                blockers.append(
                    PrimaryBlockerV3("violated", "register_relation_fact_unknown")
                )
                continue
            output = unit.output(register)
            if relation.kind == "preserved":
                if output is not None and not _expression_is_register(output, register):
                    blockers.append(
                        PrimaryBlockerV3(
                            "violated", "register_preservation_contradiction"
                        )
                    )
                if (
                    fact.lattice != "finite"
                    or tuple(row.kind for row in fact.origins) != ("entry_register",)
                    or fact.origins[0].subject_id != register
                    or fact.origins[0].offset not in {None, 0}
                ):
                    blockers.append(
                        PrimaryBlockerV3(
                            "violated", "register_preservation_origin_contradiction"
                        )
                    )
            elif relation.kind == "constant":
                constant = _expression_constant(output)
                exact = tuple(
                    row.exact_bits for row in fact.origins if row.kind == "exact_bits"
                )
                if constant is None or fact.lattice != "finite" or exact != (constant,):
                    blockers.append(
                        PrimaryBlockerV3("violated", "register_constant_contradiction")
                    )
            elif relation.kind == "clobbered":
                if output is None or fact.lattice != "top":
                    blockers.append(
                        PrimaryBlockerV3("violated", "register_clobber_contradiction")
                    )
            elif relation.kind in {"finite", "call_result"}:
                if output is None or fact.lattice != "finite":
                    blockers.append(
                        PrimaryBlockerV3(
                            "violated", "register_value_relation_contradiction"
                        )
                    )
                else:
                    blockers.append(
                        PrimaryBlockerV3(
                            "incomplete", "register_expression_witness_unsupported"
                        )
                    )
    for relation in proposal.register_relations:
        if evidence.unit(relation.unit_id) is None:
            blockers.append(
                PrimaryBlockerV3("violated", "register_relation_unit_unknown")
            )
    return blockers


def _call_blockers(
    proposal: ParametricSccProposalV3,
    evidence: ParametricSccEvidenceV3,
    preservation_cache: dict[tuple[str, ...], _InternalPreservationResultV3]
    | None = None,
    profile_index: _CheckedProfileIndexV3 | None = None,
    memory_frame_cache: dict[
        tuple[str, ...], _InternalMemoryFrameResultV3
    ] | None = None,
) -> list[PrimaryBlockerV3]:
    if preservation_cache is None:
        preservation_cache = {}
    if memory_frame_cache is None:
        memory_frame_cache = {}
    if profile_index is None:
        profile_index = _CheckedProfileIndexV3(evidence.external_profiles)
    blockers: list[PrimaryBlockerV3] = []
    calls = {
        (row.source_unit_id, row.event_index): row for row in proposal.call_effects
    }
    if len(calls) != len(proposal.call_effects):
        return [PrimaryBlockerV3("violated", "duplicate_call_effect")]
    for unit in evidence.units:
        direct_indices = {row.event_index for row in unit.direct_calls}
        for direct in unit.direct_calls:
            call = calls.get((unit.unit_id, direct.event_index))
            if call is None:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "direct_call_effect_missing")
                )
            elif direct.target_unit_id is None:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "direct_call_target_unresolved")
                )
            elif call.kind != "direct_internal" or call.target_unit_ids != (
                direct.target_unit_id,
            ):
                blockers.append(
                    PrimaryBlockerV3("violated", "direct_call_effect_contradiction")
                )
            checked_catalog_contract = (
                None
                if direct.target_unit_id is None
                else evidence.catalog_call_contract(direct.target_unit_id)
            )
            if call is not None:
                if checked_catalog_contract is None:
                    if call.catalog_contract_id is not None:
                        blockers.append(
                            PrimaryBlockerV3(
                                "violated",
                                "catalog_call_contract_binding_contradiction",
                            )
                        )
                elif call.catalog_contract_id is None:
                    blockers.append(
                        PrimaryBlockerV3(
                            "incomplete", "catalog_call_contract_binding_missing"
                        )
                    )
                elif (
                    call.catalog_contract_id
                    != checked_catalog_contract.contract_id
                ):
                    blockers.append(
                        PrimaryBlockerV3(
                            "violated",
                            "catalog_call_contract_binding_contradiction",
                        )
                    )
            raw_contracts = tuple(
                row
                for row in evidence.catalog_call_contracts
                if row.target_entry_unit_id == direct.target_unit_id
            )
            if any(
                row.contract_id in evidence.invalid_catalog_call_contract_ids
                for row in raw_contracts
            ):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "catalog_call_contract_machine_contradiction"
                    )
                )
        external_by_index = {row.event_index: row for row in unit.external_calls}
        for event_index in sorted(external_by_index):
            call = calls.get((unit.unit_id, event_index))
            if call is None:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "external_call_effect_missing")
                )
            elif call.kind != "external_profile":
                blockers.append(
                    PrimaryBlockerV3("violated", "external_call_effect_contradiction")
                )
        for call in (
            row
            for row in proposal.call_effects
            if row.source_unit_id == unit.unit_id and row.kind == "external_profile"
        ):
            exact_call = external_by_index.get(call.event_index)
            if exact_call is None:
                blockers.append(
                    PrimaryBlockerV3("violated", "external_call_event_unknown")
                )
                continue
            profile = evidence.external_profile(str(call.external_profile_record_id))
            if profile is None:
                blockers.append(
                    PrimaryBlockerV3("violated", "external_profile_dependency_unknown")
                )
                continue
            if exact_call.transfer_kind not in profile.allowed_transfers:
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "external_profile_transfer_contradiction"
                    )
                )
            exact_identity = mapping(
                exact_call.identity.to_value(), "exact external-call identity"
            )
            profile_identity = mapping(
                profile.identity.to_value(), "external profile identity"
            )
            if any(
                exact_identity.get(key) != value
                for key, value in profile_identity.items()
            ):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "external_profile_identity_contradiction"
                    )
                )
        for call in (
            row for row in proposal.call_effects if row.source_unit_id == unit.unit_id
        ):
            if (
                call.kind == "direct_internal"
                and call.event_index not in direct_indices
            ):
                blockers.append(
                    PrimaryBlockerV3("violated", "invented_direct_call_effect")
                )
            if call.kind == "finite_internal":
                if call.event_index not in set(unit.indirect_call_event_indices):
                    blockers.append(
                        PrimaryBlockerV3("violated", "finite_call_event_unknown")
                    )
                else:
                    structural_matches = [
                        row
                        for row in evidence.structural_targets
                        if row.source_unit_id == unit.unit_id
                        and row.source_event_index == call.event_index
                        and row.transfer_kind == "indirect_call"
                    ]
                    if (
                        len(structural_matches) != 1
                        or structural_matches[0].status != "recovered"
                    ):
                        blockers.append(
                            PrimaryBlockerV3(
                                "incomplete", "finite_call_targets_unavailable"
                            )
                        )
                    elif call.target_unit_ids != structural_matches[0].target_unit_ids:
                        blockers.append(
                            PrimaryBlockerV3(
                                "violated", "finite_call_targets_contradict_structure"
                            )
                        )
            if call.argument_fact_ids or call.result_fact_id is not None:
                blockers.append(
                    PrimaryBlockerV3(
                        "incomplete", "call_value_relation_checker_unsupported"
                    )
                )
        direct_effects_complete = all(
            (unit.unit_id, row.event_index) in calls for row in unit.direct_calls
        )
        if unit.direct_calls and direct_effects_complete:
            preserved_components = {
                row.alias_component_id
                for row in proposal.memory_effects
                if row.unit_id == unit.unit_id and row.kind == "preserved"
            }
            for direct in unit.direct_calls:
                if direct.target_unit_id is None:
                    continue
                key = (direct.target_unit_id,)
                frame = memory_frame_cache.get(key)
                if frame is None:
                    frame = _checked_internal_memory_frame_v3(
                        key, evidence, profile_index
                    )
                    memory_frame_cache[key] = frame
                if not frame.complete and preserved_components:
                    blockers.append(
                        PrimaryBlockerV3(
                            "incomplete",
                            "call_memory_postcondition_summary_missing",
                        )
                    )
                elif preserved_components.intersection(
                    frame.written_component_ids
                ):
                    blockers.append(
                        PrimaryBlockerV3(
                            "violated", "call_memory_postcondition_overclaim"
                        )
                    )
    for call in proposal.call_effects:
        if evidence.unit(call.source_unit_id) is None:
            blockers.append(PrimaryBlockerV3("violated", "call_effect_source_unknown"))
            continue
        checked_complete = True
        checked_registers: tuple[str, ...] = ()
        if call.kind in {"direct_internal", "finite_internal"}:
            preservation = preservation_cache.get(call.target_unit_ids)
            if preservation is None:
                preservation = _checked_internal_preservation_v3(
                    call.target_unit_ids, evidence, profile_index
                )
                preservation_cache[call.target_unit_ids] = preservation
            checked_complete = preservation.complete
            checked_registers = preservation.preserved_registers
        elif call.kind == "external_profile":
            profile = evidence.external_profile(str(call.external_profile_record_id))
            if profile is None:
                checked_complete = False
            else:
                contract = mapping(
                    profile.machine_contract.to_value(),
                    "external profile machine contract",
                )
                if contract.get("abi_template") in {
                    "pe32-cdecl-v1",
                    "pe32-stdcall-v1",
                }:
                    checked_registers = PE32_CALLEE_PRESERVED_REGISTERS_V3
                else:
                    checked_complete = False
        submitted = call.preserved_registers
        if not checked_complete:
            if submitted:
                blockers.append(
                    PrimaryBlockerV3("violated", "call_preserved_register_overclaim")
                )
            blockers.append(
                PrimaryBlockerV3(
                    "incomplete", "call_preserved_register_postcondition_unresolved"
                )
            )
        elif submitted is None:
            blockers.append(
                PrimaryBlockerV3(
                    "incomplete", "call_preserved_register_postcondition_missing"
                )
            )
        elif set(submitted) - set(checked_registers):
            blockers.append(
                PrimaryBlockerV3("violated", "call_preserved_register_overclaim")
            )
        elif submitted != checked_registers:
            blockers.append(
                PrimaryBlockerV3(
                    "violated", "call_preserved_register_inventory_contradiction"
                )
            )
    return blockers


def _return_blockers(
    proposal: ParametricSccProposalV3, evidence: ParametricSccEvidenceV3
) -> list[PrimaryBlockerV3]:
    blockers: list[PrimaryBlockerV3] = []
    returns = {row.unit_id: row for row in proposal.returns}
    if len(returns) != len(proposal.returns):
        return [PrimaryBlockerV3("violated", "duplicate_return_behavior")]
    cleanup_values: set[int] = set()
    for unit in evidence.units:
        row = returns.get(unit.unit_id)
        if row is None:
            blockers.append(PrimaryBlockerV3("incomplete", "return_behavior_missing"))
            continue
        expected_cleanup = None
        if unit.returns:
            if unit.return_cleanup_bytes is None:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "return_cleanup_unresolved")
                )
            else:
                expected_cleanup = unit.return_cleanup_bytes
                cleanup_values.add(expected_cleanup)
        if row.may_return != unit.returns or row.cleanup_bytes != expected_cleanup:
            blockers.append(
                PrimaryBlockerV3("violated", "return_behavior_contradiction")
            )
        if row.may_not_return != unit.may_not_return:
            blockers.append(
                PrimaryBlockerV3("violated", "nonreturn_behavior_contradiction")
            )
    if len(cleanup_values) > 1:
        blockers.append(PrimaryBlockerV3("incomplete", "scc_return_cleanup_nonuniform"))
    elif cleanup_values and proposal.stack_cleanup_bytes != next(iter(cleanup_values)):
        blockers.append(PrimaryBlockerV3("violated", "scc_stack_cleanup_contradiction"))
    if (
        any(unit.returns for unit in evidence.units)
        and not proposal.return_address_preserved
    ):
        blockers.append(
            PrimaryBlockerV3("incomplete", "return_address_preservation_missing")
        )
    return blockers


def _memory_blockers(
    proposal: ParametricSccProposalV3, evidence: ParametricSccEvidenceV3
) -> list[PrimaryBlockerV3]:
    blockers: list[PrimaryBlockerV3] = []
    effects = {
        (row.unit_id, row.alias_component_id): row for row in proposal.memory_effects
    }
    if len(effects) != len(proposal.memory_effects):
        return [PrimaryBlockerV3("violated", "duplicate_memory_effect")]
    for component in evidence.unknown_kill_components:
        matching = [
            row
            for (unit_id, component_id), row in effects.items()
            if component_id == component
        ]
        if not matching:
            blockers.append(
                PrimaryBlockerV3("incomplete", "unknown_alias_kill_unrepresented")
            )
        elif any(row.kind != "unknown_kill" for row in matching):
            blockers.append(
                PrimaryBlockerV3("violated", "unknown_alias_kill_contradiction")
            )
    expected = {
        (row.unit_id, row.alias_component_id): row.kind
        for row in evidence.memory_effects
    }
    for key, expected_kind in expected.items():
        if expected_kind == "unknown_kill":
            continue
        effect = effects.get(key)
        if effect is None:
            blockers.append(
                PrimaryBlockerV3("incomplete", "checked_memory_effect_unrepresented")
            )
        elif effect.kind != expected_kind:
            blockers.append(
                PrimaryBlockerV3("violated", "checked_memory_effect_contradiction")
            )
    if set(effects) - set(expected):
        blockers.append(PrimaryBlockerV3("violated", "invented_memory_effect"))
    if any(
        row.input_fact_id is not None or row.output_fact_id is not None
        for row in proposal.memory_effects
    ):
        blockers.append(
            PrimaryBlockerV3("incomplete", "memory_value_relation_checker_unsupported")
        )
    if evidence.unversioned_memory_access_ids:
        blockers.append(PrimaryBlockerV3("incomplete", "memory_access_version_missing"))
    return blockers


def _fact_matches_expression(fact: ValueFactV3, expression: Any) -> bool:
    constant = _expression_constant(expression)
    if constant is not None:
        return fact.lattice == "finite" and fact.origins == (
            ValueOriginV3("exact_bits", exact_bits=constant),
        )
    if isinstance(expression, Mapping) and expression.get("op") == "reg":
        register = expression.get("name")
        return (
            isinstance(register, str)
            and fact.lattice == "finite"
            and len(fact.origins) == 1
            and fact.origins[0].kind == "entry_register"
            and fact.origins[0].subject_id == register
        )
    return False


def _stack_blockers(
    proposal: ParametricSccProposalV3, evidence: ParametricSccEvidenceV3
) -> list[PrimaryBlockerV3]:
    blockers: list[PrimaryBlockerV3] = []
    facts = _proposal_fact_map(proposal)
    submitted = {row.access_id: row for row in proposal.stack_accesses}
    expected = {
        row.access_id: row for unit in evidence.units for row in unit.stack_accesses
    }
    for access_id, exact in expected.items():
        row = submitted.get(access_id)
        if row is None:
            blockers.append(
                PrimaryBlockerV3("incomplete", "stack_access_unrepresented")
            )
            continue
        if (
            row.unit_id != exact.unit_id
            or row.kind != exact.kind
            or row.entry_esp_offset != exact.entry_esp_offset
            or row.width_bytes != exact.width_bytes
        ):
            blockers.append(PrimaryBlockerV3("violated", "stack_access_contradiction"))
            continue
        if row.value_fact_id is not None:
            fact = facts.get(row.value_fact_id)
            if (
                fact is None
                or exact.value is None
                or not _fact_matches_expression(fact, exact.value)
            ):
                blockers.append(
                    PrimaryBlockerV3("violated", "stack_access_value_contradiction")
                )
    if set(submitted) - set(expected):
        blockers.append(PrimaryBlockerV3("violated", "invented_stack_access"))
    return blockers


def _indirect_blockers(
    proposal: ParametricSccProposalV3, evidence: ParametricSccEvidenceV3
) -> list[PrimaryBlockerV3]:
    blockers: list[PrimaryBlockerV3] = []
    facts = _proposal_fact_map(proposal)
    rows = {row.exit_id: row for row in proposal.indirect_exits}
    if len(rows) != len(proposal.indirect_exits):
        return [PrimaryBlockerV3("violated", "duplicate_parametric_indirect_exit")]
    exact_exit_ids = {
        occurrence.exit_id
        for unit in evidence.units
        for occurrence in unit.indirect_expressions
    }
    if set(rows) - exact_exit_ids:
        blockers.append(
            PrimaryBlockerV3("violated", "invented_parametric_indirect_exit")
        )
    for unit in evidence.units:
        for occurrence in unit.indirect_expressions:
            row = rows.get(occurrence.exit_id)
            checked = evidence.checked_indirect_target(occurrence.exit_id)
            if row is None:
                blockers.append(
                    PrimaryBlockerV3("incomplete", "parametric_indirect_exit_missing")
                )
                continue
            if (
                row.source_unit_id != unit.unit_id
                or row.expression_sha256 != occurrence.expression_sha256
            ):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "parametric_indirect_exit_binding_contradiction"
                    )
                )
            if checked is None:
                blockers.append(
                    PrimaryBlockerV3("violated", "parametric_indirect_exit_unproved")
                )
                continue
            fact = facts.get(row.value_fact_id)
            if fact is None or fact.lattice != "finite":
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "parametric_indirect_exit_fact_invalid"
                    )
                )
            else:
                internal_origins = tuple(
                    sorted(
                        origin.subject_id
                        for origin in fact.origins
                        if origin.kind == "static_code_target"
                        and origin.subject_id is not None
                    )
                )
                external_origins = tuple(
                    sorted(
                        origin.subject_id
                        for origin in fact.origins
                        if origin.kind == "import_target"
                        and origin.subject_id is not None
                    )
                )
                if len(fact.origins) != len(internal_origins) + len(external_origins):
                    blockers.append(
                        PrimaryBlockerV3(
                            "incomplete", "indirect_target_origin_checker_unsupported"
                        )
                    )
                elif (
                    fact.origins != checked.origins
                    or internal_origins != checked.target_unit_ids
                    or external_origins != checked.external_profile_record_ids
                    or row.target_unit_ids != checked.target_unit_ids
                    or row.external_profile_record_ids
                    != checked.external_profile_record_ids
                ):
                    blockers.append(
                        PrimaryBlockerV3(
                            "violated", "indirect_target_origin_contradiction"
                        )
                    )
            structural = evidence.structural_target(occurrence.exit_id)
            if structural is None:
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "structural_indirect_inventory_missing"
                    )
                )
            elif structural.status == "violated":
                blockers.append(
                    PrimaryBlockerV3("violated", "structural_indirect_targets_violated")
                )
            elif (
                structural.status == "recovered"
                and structural.target_unit_ids != row.target_unit_ids
            ):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "parametric_indirect_targets_contradict_structure"
                    )
                )
            if any(
                evidence.external_profile(profile_id) is None
                for profile_id in row.external_profile_record_ids
            ):
                blockers.append(
                    PrimaryBlockerV3(
                        "violated", "parametric_indirect_external_profile_unknown"
                    )
                )
    return blockers



__all__ = [
    "CheckedIndirectTargetEvidenceV3",
    "DirectCallEvidenceV3",
    "ExternalCallEvidenceV3",
    "IndirectExpressionEvidenceV3",
    "MemoryEffectEvidenceV3",
    "ParametricSccEvidenceV3",
    "StackAccessEvidenceV3",
    "UnitSummaryEvidenceV3",
]
