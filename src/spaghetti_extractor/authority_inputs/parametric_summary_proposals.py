"""Propose root-independent parametric SCC summaries from checked v3 inputs.

This module is intentionally outside the authority checker.  It performs a
bounded abstract interpretation over already checked local transition and
memory artifacts, but its output is only a proposal.  The registered
``parametric-scc-summaries-v3`` phase reconstructs the SCCs and independently
replays every relation before any fact can authorize candidate generation.
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..artifacts.artifact_set import (
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactRecordV3,
    ArtifactSetManifestV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
    PlainJsonCodecV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)
from ..artifacts.io import ArtifactInputReaderV3, open_artifact_reader_v3
from ..authority._schema import mapping, stable_id
from ..authority.authority_common import canonical_dependencies_v3
from ..authority.external_site_records import (
    EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
    EXTERNAL_PROFILE_CODEC_V3,
    EXTERNAL_PROFILE_RECORD_V3_SCHEMA,
    ExternalProfileV3,
)
from ..authority.memory_records import (
    MEMORY_VERSION_CODEC_V3,
    MEMORY_VERSIONS_ARTIFACT_KIND_V3,
    MemoryVersionRecordV3,
)
from ..authority.parametric_summary_records import (
    PARAMETRIC_SUMMARY_PROPOSALS_ARTIFACT_KIND_V3,
    PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3,
    PE32_CALLEE_PRESERVED_REGISTERS_V3,
    CallEffectV3,
    ParametricIndirectExitV3,
    ParametricSccProposalV3,
    RegisterRelationV3,
    ReturnBehaviorV3,
    StackAccessV3,
    StaticMemoryEffectV3,
    ValueFactV3,
    ValueOriginV3,
    parametric_scc_id_v3,
    partition_call_graph_sccs_v3,
)
from ..authority.parametric_unit_facts import (
    PARAMETRIC_UNIT_FACT_CODEC_V3,
    PARAMETRIC_UNIT_FACTS_ARTIFACT_KIND_V3,
    ParametricUnitFactV3,
)
from ..authority.structural_targets import (
    STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
    STRUCTURAL_TARGET_UNIT_CODEC_V3,
    StructuralTargetProposalV3,
)
from ..authority.static_value_records import (
    PE32_IMPORT_SLOT_CODEC_V3,
    PE32_IMPORT_SLOT_RECORD_V3_SCHEMA,
    PE32_STATIC_IMAGE_CODEC_V3,
    PE32_STATIC_IMAGE_RECORD_V3_SCHEMA,
    STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3,
    PE32ImportSlotV3,
    PE32StaticImageV3,
)


class ParametricSummaryProposalV3Error(ValueError):
    """The checked input boundary cannot produce a canonical proposal set."""


_GENERAL_REGISTERS = frozenset(
    {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
)


def _require_kind(
    reader: ArtifactInputReaderV3, expected: str, label: str
) -> None:
    if reader.manifest.artifact_kind != expected:
        raise ParametricSummaryProposalV3Error(
            f"{label} has artifact kind {reader.manifest.artifact_kind!r}, "
            f"expected {expected!r}"
        )


def _binary_binding(
    reader: ArtifactInputReaderV3, label: str
) -> ArtifactBindingV3:
    rows = tuple(
        row
        for row in reader.manifest.bindings
        if row.name == "binary" and row.kind == "pe32"
    )
    if len(rows) != 1:
        raise ParametricSummaryProposalV3Error(
            f"{label} must contain exactly one binary/pe32 binding"
        )
    return rows[0]


def _artifact_dependency(
    name: str, reader: ArtifactInputReaderV3
) -> ArtifactDependencyV3:
    return ArtifactDependencyV3(
        name=name,
        artifact_kind=reader.manifest.artifact_kind,
        artifact_id=reader.manifest.artifact_id,
        manifest_sha256=reader.manifest_sha256,
    )


def _expression_register(value: Any) -> str | None:
    if not isinstance(value, Mapping) or value.get("op") != "reg":
        return None
    name = value.get("name")
    return name if isinstance(name, str) and name in _GENERAL_REGISTERS else None


def _expression_constant(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    result = value.get("value")
    if not isinstance(result, int) or isinstance(result, bool):
        return None
    return result if 0 <= result < 1 << 32 else None


def _signed_u32(value: int) -> int:
    return value - (1 << 32) if value & (1 << 31) else value


def _esp_offset(value: Any) -> int | None:
    if _expression_register(value) == "esp":
        return 0
    if not isinstance(value, Mapping) or value.get("op") not in {"add", "add32"}:
        return None
    arguments = value.get("args")
    if not isinstance(arguments, list) or len(arguments) != 2:
        return None
    for register, constant in (arguments, tuple(reversed(arguments))):
        exact = _expression_constant(constant)
        if _expression_register(register) == "esp" and exact is not None:
            return _signed_u32(exact)
    return None


def _fact_id(kind: str, payload: Mapping[str, Any]) -> str:
    return stable_id(f"parametric-{kind}-fact-v3", payload)


def _relation_id(unit_id: str, register: str) -> str:
    return stable_id(
        "parametric-register-relation-v3",
        {"unit_id": unit_id, "register": register},
    )


def _profile_matches(
    profile: ExternalProfileV3, identity: CanonicalValueV3, transfer: str
) -> bool:
    if transfer not in profile.allowed_transfers:
        return False
    exact = mapping(identity.to_value(), "exact external identity")
    expected = mapping(profile.identity.to_value(), "external profile identity")
    return all(exact.get(key) == value for key, value in expected.items())


def _external_identity(exact_record: CanonicalValueV3) -> CanonicalValueV3:
    exact = mapping(exact_record.to_value(), "exact external call")
    imported = exact.get("import")
    source = imported if isinstance(imported, Mapping) else exact
    dll = source.get("dll")
    symbol = source.get("symbol")
    ordinal = source.get("ordinal")
    if isinstance(dll, str) and dll and (
        (isinstance(symbol, str) and bool(symbol))
        != (isinstance(ordinal, int) and not isinstance(ordinal, bool))
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
        return CanonicalValueV3.of(
            {"kind": "protocol", "protocol": dict(protocol)}
        )
    return CanonicalValueV3.of({})


def _external_target_identity(value: CanonicalValueV3) -> CanonicalValueV3:
    return _external_identity(value)


class _ProfileIndexV3:
    """Canonical profile lookup with one comparison pass per distinct identity."""

    def __init__(self, profiles: tuple[ExternalProfileV3, ...]) -> None:
        self.profiles = profiles
        self.by_record_id = {row.record_id: row for row in profiles}
        self._selection_cache: dict[
            tuple[bytes, str], ExternalProfileV3 | None
        ] = {}
        self._exact_cache: dict[
            tuple[bytes, str | None], tuple[ExternalProfileV3, ...]
        ] = {}

    def select(
        self, identity: CanonicalValueV3, transfer: str
    ) -> ExternalProfileV3 | None:
        key = (identity.data, transfer)
        if key not in self._selection_cache:
            candidates = tuple(
                row
                for row in self.profiles
                if _profile_matches(row, identity, transfer)
            )
            self._selection_cache[key] = (
                candidates[0] if len(candidates) == 1 else None
            )
        return self._selection_cache[key]

    def matching_exact(
        self,
        identity: CanonicalValueV3,
        transfer: str | None = None,
    ) -> tuple[ExternalProfileV3, ...]:
        key = (identity.data, transfer)
        if key not in self._exact_cache:
            self._exact_cache[key] = tuple(
                sorted(
                    (
                        row
                        for row in self.profiles
                        if row.identity == identity
                        and (
                            transfer is None
                            or transfer in row.allowed_transfers
                        )
                    ),
                    key=lambda row: row.record_id,
                )
            )
        return self._exact_cache[key]


@dataclass(frozen=True)
class _AbstractValueV3:
    lattice: str
    origins: tuple[ValueOriginV3, ...] = ()
    support_unit_ids: tuple[str, ...] = ()
    support_profile_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ProposedIndirectTargetV3:
    origins: tuple[ValueOriginV3, ...]
    target_unit_ids: tuple[str, ...]
    external_profile_record_ids: tuple[str, ...]
    support_unit_ids: tuple[str, ...]
    support_profile_ids: tuple[str, ...]


def _bottom_value_v3() -> _AbstractValueV3:
    return _AbstractValueV3("bottom")


def _top_value_v3() -> _AbstractValueV3:
    return _AbstractValueV3("top")


def _finite_value_v3(
    origins: Sequence[ValueOriginV3],
    *,
    support_unit_ids: Sequence[str] = (),
    support_profile_ids: Sequence[str] = (),
) -> _AbstractValueV3:
    exact = tuple(sorted(set(origins)))
    if not exact:
        return _bottom_value_v3()
    return _AbstractValueV3(
        "finite",
        exact,
        tuple(sorted(set(support_unit_ids))),
        tuple(sorted(set(support_profile_ids))),
    )


def _join_values_v3(
    values: Sequence[_AbstractValueV3], *, budget: int
) -> _AbstractValueV3:
    if not values:
        return _bottom_value_v3()
    if any(row.lattice == "top" for row in values):
        return _top_value_v3()
    finite = tuple(row for row in values if row.lattice == "finite")
    if not finite:
        return _bottom_value_v3()
    origins = tuple(sorted({origin for row in finite for origin in row.origins}))
    if len(origins) > budget:
        return _top_value_v3()
    return _finite_value_v3(
        origins,
        support_unit_ids=tuple(
            unit_id for row in finite for unit_id in row.support_unit_ids
        ),
        support_profile_ids=tuple(
            profile_id for row in finite for profile_id in row.support_profile_ids
        ),
    )


def _import_identity_v3(slot: PE32ImportSlotV3) -> CanonicalValueV3:
    return CanonicalValueV3.of(
        {
            "kind": "import",
            "dll": slot.dll,
            "symbol": slot.symbol,
            "ordinal": slot.ordinal,
        }
    )


def _matching_import_profiles_v3(
    slot: PE32ImportSlotV3,
    profile_index: _ProfileIndexV3,
    *,
    transfer: str | None = None,
) -> tuple[ExternalProfileV3, ...]:
    identity = _import_identity_v3(slot)
    return profile_index.matching_exact(identity, transfer)


def _abi_preserved_registers_v3(profile: ExternalProfileV3) -> tuple[str, ...] | None:
    contract = mapping(profile.machine_contract.to_value(), "external machine contract")
    if contract.get("abi_template") in {"pe32-cdecl-v1", "pe32-stdcall-v1"}:
        return PE32_CALLEE_PRESERVED_REGISTERS_V3
    return None


def _proposal_event_register_input_v3(
    unit: ParametricUnitFactV3,
    event_index: int,
    register: str,
) -> Any | None:
    return unit.event_register_input(event_index, register)


def _propose_target_dataflow_v3(
    *,
    units: Mapping[str, ParametricUnitFactV3],
    static_image: PE32StaticImageV3,
    import_slots: tuple[PE32ImportSlotV3, ...],
    profile_index: _ProfileIndexV3,
    calls: Mapping[str, tuple[tuple[int, str | None], ...]],
    rva_to_unit: Mapping[int, str],
    budget: int,
    preservation_cache: dict[
        tuple[str, ...], _ProposedPreservationV3
    ],
) -> dict[str, _ProposedIndirectTargetV3]:
    """Propose a bounded register-target fixed point over exact direct exits."""

    slot_by_va = {row.slot_va: row for row in import_slots}
    successors: dict[str, tuple[str, ...]] = {}
    predecessors: dict[str, list[str]] = {unit_id: [] for unit_id in units}
    for unit_id, unit in units.items():
        target_rvas = unit.successor_rvas
        if target_rvas is None:
            successors[unit_id] = ()
            continue
        target_ids = tuple(
            sorted(
                rva_to_unit[target]
                for target in target_rvas
                if target in rva_to_unit
            )
        )
        successors[unit_id] = target_ids
        for target_id in target_ids:
            predecessors[target_id].append(unit_id)

    entry: dict[tuple[str, str], _AbstractValueV3] = {}
    output: dict[tuple[str, str], _AbstractValueV3] = {}
    indirect: dict[str, _AbstractValueV3] = {}
    def classify_constant(value: int, support: Sequence[str]) -> _AbstractValueV3:
        if static_image.image_base <= value < static_image.image_base + static_image.size_of_image:
            target_id = rva_to_unit.get(value - static_image.image_base)
            if target_id is not None:
                return _finite_value_v3(
                    (ValueOriginV3("static_code_target", target_id, 0),),
                    support_unit_ids=(*support, target_id),
                )
        return _finite_value_v3(
            (ValueOriginV3("exact_bits", exact_bits=value),),
            support_unit_ids=support,
        )

    def evaluate(
        expression: Any,
        environment: Mapping[str, _AbstractValueV3],
        *,
        unit_id: str,
    ) -> _AbstractValueV3:
        register = _expression_register(expression)
        if register is not None:
            return environment.get(register, _top_value_v3())
        constant = _expression_constant(expression)
        if constant is not None:
            return classify_constant(constant, (unit_id,))
        if isinstance(expression, Mapping) and expression.get("op") == "load":
            if expression.get("width") != 4:
                return _top_value_v3()
            address = _expression_constant(expression.get("address"))
            slot = None if address is None else slot_by_va.get(address)
            if slot is None:
                return _top_value_v3()
            matches = _matching_import_profiles_v3(slot, profile_index)
            if not matches:
                return _top_value_v3()
            return _finite_value_v3(
                tuple(
                    ValueOriginV3("import_target", row.record_id, 0)
                    for row in matches
                ),
                support_unit_ids=(unit_id,),
                support_profile_ids=tuple(row.record_id for row in matches),
            )
        if isinstance(expression, Mapping) and expression.get("op") == "call_response":
            event_index = expression.get("call_index")
            register_name = expression.get("register")
            if (
                not isinstance(event_index, int)
                or isinstance(event_index, bool)
                or register_name not in _GENERAL_REGISTERS
            ):
                return _top_value_v3()
            preserved_sets: list[set[str]] = []
            support_units: set[str] = {unit_id}
            support_profiles: set[str] = set()
            direct_targets = tuple(
                target_id
                for index, target_id in calls[unit_id]
                if index == event_index and target_id is not None
            )
            if direct_targets:
                key = tuple(sorted(set(direct_targets)))
                preservation = preservation_cache.get(key)
                if preservation is None:
                    preservation = _propose_internal_preservation_v3(
                        key,
                        units,
                        profile_index,
                        calls,
                        rva_to_unit,
                    )
                    preservation_cache[key] = preservation
                if not preservation.complete:
                    return _top_value_v3()
                preserved_sets.append(set(preservation.registers))
                support_units.update(preservation.unit_ids)
                support_profiles.update(preservation.profile_ids)
            matching_indirect = tuple(
                row
                for row in units[unit_id].indirect_exits
                if row.event_index == event_index
                and row.transfer_kind == "indirect_call"
            )
            external_calls = tuple(
                row
                for row in units[unit_id].external_calls
                if row.event_index == event_index
            )
            if external_calls and not matching_indirect:
                if len(external_calls) != 1:
                    return _top_value_v3()
                profile = profile_index.select(
                    external_calls[0].identity,
                    external_calls[0].transfer_kind,
                )
                if profile is None:
                    return _top_value_v3()
                preserved = _abi_preserved_registers_v3(profile)
                if preserved is None:
                    return _top_value_v3()
                preserved_sets.append(set(preserved))
                support_profiles.add(profile.record_id)
            if matching_indirect:
                if len(matching_indirect) != 1:
                    return _top_value_v3()
                target_value = indirect.get(
                    matching_indirect[0].exit_id, _bottom_value_v3()
                )
                if target_value.lattice != "finite":
                    return _top_value_v3()
                target_preserved: list[set[str]] = []
                internal_ids = tuple(
                    sorted(
                        origin.subject_id
                        for origin in target_value.origins
                        if origin.kind == "static_code_target"
                        and origin.subject_id is not None
                    )
                )
                if internal_ids:
                    preservation = preservation_cache.get(internal_ids)
                    if preservation is None:
                        preservation = _propose_internal_preservation_v3(
                            internal_ids,
                            units,
                            profile_index,
                            calls,
                            rva_to_unit,
                        )
                        preservation_cache[internal_ids] = preservation
                    if not preservation.complete:
                        return _top_value_v3()
                    target_preserved.append(set(preservation.registers))
                    support_units.update(preservation.unit_ids)
                    support_profiles.update(preservation.profile_ids)
                for origin in target_value.origins:
                    if origin.kind == "import_target" and origin.subject_id is not None:
                        profile = profile_index.by_record_id.get(
                            origin.subject_id
                        )
                        if profile is not None and "call" not in profile.allowed_transfers:
                            profile = None
                        if profile is None:
                            return _top_value_v3()
                        preserved = _abi_preserved_registers_v3(profile)
                        if preserved is None:
                            return _top_value_v3()
                        target_preserved.append(set(preserved))
                        support_profiles.add(profile.record_id)
                    elif origin.kind != "static_code_target":
                        return _top_value_v3()
                if not target_preserved:
                    return _top_value_v3()
                preserved_sets.extend(target_preserved)
            if not preserved_sets or any(
                register_name not in registers for registers in preserved_sets
            ):
                return _top_value_v3()
            input_expression = _proposal_event_register_input_v3(
                units[unit_id], event_index, register_name
            )
            if input_expression is None:
                return _top_value_v3()
            value = evaluate(input_expression, environment, unit_id=unit_id)
            if value.lattice != "finite":
                return value
            return _finite_value_v3(
                value.origins,
                support_unit_ids=(*value.support_unit_ids, *support_units),
                support_profile_ids=(
                    *value.support_profile_ids,
                    *support_profiles,
                ),
            )
        return _top_value_v3()

    for unit_id in units:
        for register in _GENERAL_REGISTERS:
            initial = (
                _top_value_v3()
                if not predecessors[unit_id]
                else _bottom_value_v3()
            )
            entry[(unit_id, register)] = initial
            output[(unit_id, register)] = initial

    changed = True
    iterations = 0
    maximum_iterations = max(1, len(units) * (budget + 2))
    while changed and iterations < maximum_iterations:
        changed = False
        iterations += 1
        for unit_id in sorted(units):
            incoming = predecessors[unit_id]
            environment: dict[str, _AbstractValueV3] = {}
            for register in _GENERAL_REGISTERS:
                value = (
                    _top_value_v3()
                    if not incoming
                    else _join_values_v3(
                        [output[(source, register)] for source in incoming],
                        budget=budget,
                    )
                )
                environment[register] = value
                if entry[(unit_id, register)] != value:
                    entry[(unit_id, register)] = value
                    changed = True
            for occurrence in units[unit_id].indirect_exits:
                value = evaluate(
                    occurrence.expression.to_value(),
                    environment,
                    unit_id=unit_id,
                )
                if indirect.get(occurrence.exit_id) != value:
                    indirect[occurrence.exit_id] = value
                    changed = True
            outputs = {
                register: expression.to_value()
                for register, expression in units[unit_id].register_outputs
            }
            for register in _GENERAL_REGISTERS:
                value = (
                    environment[register]
                    if register not in outputs
                    else evaluate(outputs[register], environment, unit_id=unit_id)
                )
                if output[(unit_id, register)] != value:
                    output[(unit_id, register)] = value
                    changed = True
    if changed:
        return {}

    result: dict[str, _ProposedIndirectTargetV3] = {}
    for unit_id, row in units.items():
        for occurrence in row.indirect_exits:
            value = indirect.get(occurrence.exit_id, _bottom_value_v3())
            if value.lattice != "finite":
                continue
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
                    and (
                        (profile := profile_index.by_record_id.get(origin.subject_id))
                        is not None
                    )
                    and (
                        "jump"
                        if occurrence.transfer_kind == "indirect_jump"
                        else "call"
                    )
                    in profile.allowed_transfers
                )
            )
            if len(value.origins) != len(internal) + len(external):
                continue
            result[occurrence.exit_id] = _ProposedIndirectTargetV3(
                value.origins,
                internal,
                external,
                value.support_unit_ids,
                value.support_profile_ids,
            )
    return result


def _register_proposal(
    *, unit_id: str, register: str, output: Any | None
) -> tuple[ValueFactV3, RegisterRelationV3]:
    source = _expression_register(output)
    constant = _expression_constant(output)
    payload = {"unit_id": unit_id, "register": register}
    if output is None or source == register:
        fact = ValueFactV3(
            _fact_id("entry-register", payload),
            "finite",
            (ValueOriginV3("entry_register", register),),
        )
        kind = "preserved"
    elif constant is not None:
        fact = ValueFactV3(
            _fact_id("constant-register", {**payload, "value": constant}),
            "finite",
            (ValueOriginV3("exact_bits", exact_bits=constant),),
        )
        kind = "constant"
    else:
        fact = ValueFactV3(_fact_id("clobbered-register", payload), "top", ())
        kind = "clobbered"
    return fact, RegisterRelationV3(
        _relation_id(unit_id, register), unit_id, register, kind, fact.fact_id
    )


def _memory_effects(
    members: tuple[str, ...],
    units: Mapping[str, ParametricUnitFactV3],
    memories: tuple[MemoryVersionRecordV3, ...],
    *,
    memories_by_summary_id: Mapping[
        str, tuple[MemoryVersionRecordV3, ...]
    ]
    | None = None,
) -> tuple[tuple[MemoryVersionRecordV3, ...], tuple[StaticMemoryEffectV3, ...]]:
    member_set = set(members)
    member_summary_ids = {
        units[unit_id].transition_summary_id for unit_id in members
    }
    if memories_by_summary_id is None:
        indexed: dict[str, list[MemoryVersionRecordV3]] = {}
        for row in memories:
            for summary_id in row.transition_summary_ids:
                indexed.setdefault(summary_id, []).append(row)
        memories_by_summary_id = {
            summary_id: tuple(rows)
            for summary_id, rows in indexed.items()
        }
    relevant_by_id = {
        row.record_id: row
        for summary_id in member_summary_ids
        for row in memories_by_summary_id.get(summary_id, ())
    }
    relevant = tuple(relevant_by_id[row_id] for row_id in sorted(relevant_by_id))
    nonstack: dict[str, tuple[str, str]] = {}
    for unit_id in members:
        for access in units[unit_id].nonstack_accesses:
            nonstack[access.access_id] = (unit_id, access.kind)
    rank = {"preserved": 0, "write": 1, "unknown_kill": 2}
    effects: dict[tuple[str, str], str] = {}
    for graph in relevant:
        for link in graph.access_versions:
            exact = nonstack.get(link.access_id)
            if exact is None:
                continue
            unit_id, access_kind = exact
            kind = "preserved" if access_kind == "read" else "write"
            key = (unit_id, link.component_id)
            if rank[kind] > rank.get(effects.get(key, "preserved"), 0):
                effects[key] = kind
            else:
                effects.setdefault(key, kind)
        component_ids = tuple(row.component_id for row in graph.alias_components)
        for kill in graph.unknown_write_kills:
            if kill.binding.unit.unit_id not in member_set:
                continue
            affected = (
                component_ids
                if kill.affected_scope == "all_components"
                else kill.affected_component_ids
            )
            for component_id in affected:
                effects[(kill.binding.unit.unit_id, component_id)] = "unknown_kill"
    return relevant, tuple(
        StaticMemoryEffectV3(
            stable_id(
                "parametric-memory-effect-v3",
                {"unit_id": unit_id, "component_id": component_id},
            ),
            unit_id,
            component_id,
            kind,
            None,
            None,
        )
        for (unit_id, component_id), kind in sorted(effects.items())
    )


@dataclass(frozen=True)
class _ProposedPreservationV3:
    complete: bool
    registers: tuple[str, ...]
    unit_ids: tuple[str, ...]
    profile_ids: tuple[str, ...]


def _proposal_direct_closure_v3(
    entry: str,
    units: Mapping[str, ParametricUnitFactV3],
    rva_to_unit: Mapping[int, str],
) -> tuple[tuple[str, ...], bool]:
    pending = [entry]
    visited: set[str] = set()
    complete = True
    while pending:
        unit_id = pending.pop()
        if unit_id in visited:
            continue
        row = units.get(unit_id)
        if row is None:
            complete = False
            continue
        visited.add(unit_id)
        target_rvas = row.successor_rvas
        if target_rvas is None:
            complete = False
            continue
        for target_rva in target_rvas:
            target_id = rva_to_unit.get(target_rva)
            if target_id is None:
                complete = False
            elif target_id not in visited:
                pending.append(target_id)
    return tuple(sorted(visited)), complete


def _proposal_has_base_return_v3(
    entry: str,
    closure: tuple[str, ...],
    recursive_entries: frozenset[str],
    units: Mapping[str, ParametricUnitFactV3],
    calls: Mapping[str, tuple[tuple[int, str | None], ...]],
    rva_to_unit: Mapping[int, str],
) -> bool:
    closure_set = set(closure)
    pending = [entry]
    visited: set[str] = set()
    while pending:
        unit_id = pending.pop()
        if unit_id in visited or unit_id not in closure_set:
            continue
        visited.add(unit_id)
        if any(target in recursive_entries for _index, target in calls[unit_id]):
            continue
        if units[unit_id].returns:
            return True
        target_rvas = units[unit_id].successor_rvas
        if target_rvas is None:
            continue
        pending.extend(
            target_id
            for target_rva in target_rvas
            if (target_id := rva_to_unit.get(target_rva)) is not None
            and target_id not in visited
        )
    return False


def _propose_internal_preservation_v3(
    target_unit_ids: tuple[str, ...],
    units: Mapping[str, ParametricUnitFactV3],
    profile_index: _ProfileIndexV3,
    calls: Mapping[str, tuple[tuple[int, str | None], ...]],
    rva_to_unit: Mapping[int, str],
) -> _ProposedPreservationV3:
    entries: set[str] = set(target_unit_ids)
    closures: dict[str, tuple[str, ...]] = {}
    complete = True
    pending = list(target_unit_ids)
    while pending:
        entry = pending.pop()
        if entry in closures:
            continue
        closure, closed = _proposal_direct_closure_v3(
            entry, units, rva_to_unit
        )
        closures[entry] = closure
        complete &= closed and bool(closure)
        for unit_id in closure:
            for _event_index, target_id in calls[unit_id]:
                if target_id is None:
                    complete = False
                elif target_id not in entries:
                    entries.add(target_id)
                    pending.append(target_id)

    call_edges = {
        entry: {
            target_id
            for unit_id in closures.get(entry, ())
            for _event_index, target_id in calls[unit_id]
            if target_id is not None
        }
        for entry in entries
    }
    for component in partition_call_graph_sccs_v3(entries, call_edges):
        recursive = len(component) > 1 or any(
            entry in call_edges.get(entry, set()) for entry in component
        )
        recursive_entries = frozenset(component)
        if recursive and not any(
            _proposal_has_base_return_v3(
                entry,
                closures.get(entry, ()),
                recursive_entries,
                units,
                calls,
                rva_to_unit,
            )
            for entry in component
        ):
            complete = False

    external_preserved: dict[tuple[str, int], tuple[str, ...] | None] = {}
    profile_ids: set[str] = set()
    for closure in closures.values():
        for unit_id in closure:
            for row in units[unit_id].external_calls:
                profile = profile_index.select(
                    row.identity, row.transfer_kind
                )
                preserved = None
                if profile is not None:
                    profile_ids.add(profile.record_id)
                    contract = mapping(
                        profile.machine_contract.to_value(),
                        "external profile machine contract",
                    )
                    if contract.get("abi_template") in {
                        "pe32-cdecl-v1",
                        "pe32-stdcall-v1",
                    }:
                        preserved = PE32_CALLEE_PRESERVED_REGISTERS_V3
                external_preserved[(unit_id, row.event_index)] = preserved
                if preserved is None:
                    complete = False
    consumed_units = tuple(
        sorted({unit_id for closure in closures.values() for unit_id in closure})
    )
    if not complete:
        return _ProposedPreservationV3(
            False, (), consumed_units, tuple(sorted(profile_ids))
        )

    registers: list[str] = []
    for register in PE32_CALLEE_PRESERVED_REGISTERS_V3:
        entry_equations = {entry: True for entry in entries}
        unit_equations = {unit_id: True for unit_id in consumed_units}
        changed = True
        while changed:
            changed = False
            for unit_id in consumed_units:
                output = next(
                    (
                        expression.to_value()
                        for name, expression in units[unit_id].register_outputs
                        if name == register
                    ),
                    None,
                )
                valid = output is None or _expression_register(output) == register
                valid &= all(
                    register in external_preserved[(unit_id, row.event_index)]
                    for row in units[unit_id].external_calls
                )
                target_rvas = units[unit_id].successor_rvas
                valid &= target_rvas is not None and all(
                    unit_equations.get(target_id, False)
                    for target_rva in target_rvas
                    if (target_id := rva_to_unit.get(target_rva)) is not None
                )
                valid &= all(
                    target_id is not None
                    and entry_equations.get(target_id, False)
                    for _event_index, target_id in calls[unit_id]
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
            registers.append(register)
    return _ProposedPreservationV3(
        True,
        tuple(registers),
        consumed_units,
        tuple(sorted(profile_ids)),
    )


def _propose_scc(
    *,
    members: tuple[str, ...],
    call_edges: tuple[tuple[str, str], ...],
    units: Mapping[str, ParametricUnitFactV3],
    memories: tuple[MemoryVersionRecordV3, ...],
    memories_by_summary_id: Mapping[
        str, tuple[MemoryVersionRecordV3, ...]
    ],
    structural: Mapping[str, StructuralTargetProposalV3],
    profile_index: _ProfileIndexV3,
    calls: Mapping[str, tuple[tuple[int, str | None], ...]],
    rva_to_unit: Mapping[int, str],
    proposed_indirect_targets: Mapping[str, _ProposedIndirectTargetV3],
    static_value_record_ids: tuple[str, ...],
    preservation_cache: dict[
        tuple[str, ...], _ProposedPreservationV3
    ],
) -> ParametricSccProposalV3:
    scc_id = parametric_scc_id_v3(members, call_edges)
    recursive = len(members) > 1 or any(source == target for source, target in call_edges)
    facts: dict[str, ValueFactV3] = {}
    relations: list[RegisterRelationV3] = []
    stack: list[StackAccessV3] = []
    call_effects: list[CallEffectV3] = []
    returns: list[ReturnBehaviorV3] = []
    indirect: list[ParametricIndirectExitV3] = []
    dependencies: set[RecordDependencyV3] = set()
    cleanup_values: set[int] = set()
    profile_dependencies: set[str] = set()

    relevant_memories, memory_effects = _memory_effects(
        members,
        units,
        memories,
        memories_by_summary_id=memories_by_summary_id,
    )
    dependencies.update(
        RecordDependencyV3("memory_versions", row.record_id)
        for row in relevant_memories
    )

    for unit_id in members:
        unit = units[unit_id]
        dependencies.update(
            {
                RecordDependencyV3("unit_facts", unit_id),
                RecordDependencyV3("structural_targets", unit_id),
            }
        )
        outputs = {
            register: expression.to_value()
            for register, expression in unit.register_outputs
        }
        required = set(unit.input_registers) | set(outputs)
        for register in sorted(required & _GENERAL_REGISTERS):
            fact, relation = _register_proposal(
                unit_id=unit_id,
                register=register,
                output=outputs.get(register),
            )
            facts[fact.fact_id] = fact
            relations.append(relation)

        for access in unit.stack_accesses:
            stack.append(
                StackAccessV3(
                    access.access_id,
                    unit_id,
                    access.kind,
                    access.entry_esp_offset,
                    access.width_bytes,
                    None,
                )
            )

        for event_index, target_unit_id in calls[unit_id]:
            if target_unit_id is None:
                continue
            key = (target_unit_id,)
            preservation = preservation_cache.get(key)
            if preservation is None:
                preservation = _propose_internal_preservation_v3(
                    key,
                    units,
                    profile_index,
                    calls,
                    rva_to_unit,
                )
                preservation_cache[key] = preservation
            dependencies.update(
                {
                    RecordDependencyV3("unit_facts", target_unit_id),
                    RecordDependencyV3("structural_targets", target_unit_id),
                }
            )
            profile_dependencies.update(preservation.profile_ids)
            call_effects.append(
                CallEffectV3(
                    stable_id(
                        "parametric-direct-call-v3",
                        {
                            "source_unit_id": unit_id,
                            "event_index": event_index,
                            "target_unit_id": target_unit_id,
                        },
                    ),
                    unit_id,
                    event_index,
                    "direct_internal",
                    (target_unit_id,),
                    None,
                    (),
                    None,
                    preservation.registers if preservation.complete else None,
                )
            )

        for exit_record in unit.external_calls:
            profile = profile_index.select(
                exit_record.identity, exit_record.transfer_kind
            )
            if profile is None:
                continue
            profile_dependencies.add(profile.record_id)
            machine_contract = mapping(
                profile.machine_contract.to_value(),
                "external profile machine contract",
            )
            preserved_registers = (
                PE32_CALLEE_PRESERVED_REGISTERS_V3
                if machine_contract.get("abi_template")
                in {"pe32-cdecl-v1", "pe32-stdcall-v1"}
                else None
            )
            call_effects.append(
                CallEffectV3(
                    stable_id(
                        "parametric-external-call-v3",
                        {
                            "source_unit_id": unit_id,
                            "event_index": exit_record.event_index,
                            "profile_id": profile.record_id,
                        },
                    ),
                    unit_id,
                    exit_record.event_index,
                    "external_profile",
                    (),
                    profile.record_id,
                    (),
                    None,
                    preserved_registers,
                )
            )

        return_exit = unit.returns
        delta = unit.stack_net_bytes
        cleanup = delta - 4 if return_exit and delta is not None and delta >= 4 else None
        if cleanup is not None:
            cleanup_values.add(cleanup)
        returns.append(
            ReturnBehaviorV3(
                unit_id,
                return_exit,
                not return_exit,
                cleanup,
                return_exit,
            )
        )

        for occurrence in unit.indirect_exits:
            target = proposed_indirect_targets.get(occurrence.exit_id)
            if target is None:
                continue
            dependencies.update(
                RecordDependencyV3("static_value_origins", record_id)
                for record_id in static_value_record_ids
            )
            fact = ValueFactV3(
                _fact_id(
                    "indirect-target",
                    {
                        "exit_id": occurrence.exit_id,
                        "targets": list(target.target_unit_ids),
                        "profiles": list(target.external_profile_record_ids),
                    },
                ),
                "finite",
                target.origins,
            )
            facts[fact.fact_id] = fact
            profile_dependencies.update(target.external_profile_record_ids)
            profile_dependencies.update(target.support_profile_ids)
            dependencies.update(
                RecordDependencyV3("unit_facts", support_unit_id)
                for support_unit_id in target.support_unit_ids
            )
            indirect.append(
                ParametricIndirectExitV3(
                    occurrence.exit_id,
                    unit_id,
                    canonical_sha256_v3(occurrence.expression.to_value()),
                    fact.fact_id,
                    target.target_unit_ids,
                    target.external_profile_record_ids,
                )
            )

    dependencies.update(
        RecordDependencyV3("external_profiles", record_id)
        for record_id in profile_dependencies
    )
    cleanup = next(iter(cleanup_values)) if len(cleanup_values) == 1 else None
    base_paths = (
        tuple(sorted(row.unit_id for row in returns if row.may_return))[:1]
        if recursive
        else ()
    )
    return ParametricSccProposalV3.create(
        scc_id=scc_id,
        member_unit_ids=members,
        base_path_unit_ids=base_paths,
        value_budget=64,
        value_facts=tuple(facts.values()),
        register_relations=relations,
        stack_accesses=stack,
        stack_cleanup_bytes=cleanup,
        return_address_preserved=all(
            not row.may_return or row.return_address_preserved for row in returns
        ),
        memory_effects=memory_effects,
        call_effects=call_effects,
        returns=returns,
        indirect_exits=indirect,
        dependencies=canonical_dependencies_v3(dependencies),
    )


def generate_parametric_summary_proposals_v3(
    *,
    unit_facts_path: Path,
    memory_versions_path: Path,
    structural_targets_path: Path,
    external_profiles_path: Path,
    static_value_origins_path: Path,
    output_directory: Path,
) -> ArtifactSetManifestV3:
    readers = {
        "external_profiles": open_artifact_reader_v3(external_profiles_path),
        "memory_versions": open_artifact_reader_v3(memory_versions_path),
        "unit_facts": open_artifact_reader_v3(unit_facts_path),
        "structural_targets": open_artifact_reader_v3(structural_targets_path),
        "static_value_origins": open_artifact_reader_v3(
            static_value_origins_path
        ),
    }
    expected_kinds = {
        "external_profiles": EXTERNAL_PROFILE_ARTIFACT_KIND_V3,
        "memory_versions": MEMORY_VERSIONS_ARTIFACT_KIND_V3,
        "unit_facts": PARAMETRIC_UNIT_FACTS_ARTIFACT_KIND_V3,
        "structural_targets": STRUCTURAL_TARGETS_ARTIFACT_KIND_V3,
        "static_value_origins": STATIC_VALUE_ORIGINS_ARTIFACT_KIND_V3,
    }
    bindings = []
    for name, reader in readers.items():
        _require_kind(reader, expected_kinds[name], name)
        bindings.append(_binary_binding(reader, name))
    if len(set(bindings)) != 1:
        raise ParametricSummaryProposalV3Error(
            "parametric-summary inputs bind different PE32 binaries"
        )

    units = {
        row.record_id: PARAMETRIC_UNIT_FACT_CODEC_V3.read(row).value
        for row in readers["unit_facts"].iter_records()
    }
    memories = tuple(
        MEMORY_VERSION_CODEC_V3.read(row).value
        for row in readers["memory_versions"].iter_records()
    )
    profiles: list[ExternalProfileV3] = []
    for row in readers["external_profiles"].iter_records():
        payload = row.value.to_value()
        if (
            isinstance(payload, Mapping)
            and payload.get("schema") == EXTERNAL_PROFILE_RECORD_V3_SCHEMA
        ):
            profiles.append(EXTERNAL_PROFILE_CODEC_V3.read(row).value)
    profile_index = _ProfileIndexV3(tuple(profiles))
    memories_by_summary_id_lists: dict[
        str, list[MemoryVersionRecordV3]
    ] = {}
    for memory in memories:
        for summary_id in memory.transition_summary_ids:
            memories_by_summary_id_lists.setdefault(summary_id, []).append(memory)
    memories_by_summary_id = {
        summary_id: tuple(rows)
        for summary_id, rows in memories_by_summary_id_lists.items()
    }
    static_images: list[PE32StaticImageV3] = []
    import_slots: list[PE32ImportSlotV3] = []
    for row in readers["static_value_origins"].iter_records():
        payload = row.value.to_value()
        schema = payload.get("schema") if isinstance(payload, Mapping) else None
        if schema == PE32_STATIC_IMAGE_RECORD_V3_SCHEMA:
            static_images.append(PE32_STATIC_IMAGE_CODEC_V3.read(row).value)
        elif schema == PE32_IMPORT_SLOT_RECORD_V3_SCHEMA:
            import_slots.append(PE32_IMPORT_SLOT_CODEC_V3.read(row).value)
        else:
            raise ParametricSummaryProposalV3Error(
                f"static-value record {row.record_id!r} has unknown schema"
            )
    if len(static_images) != 1:
        raise ParametricSummaryProposalV3Error(
            "static-value origins require exactly one PE32 image context"
        )
    structural = {
        proposal.record_id: proposal
        for row in readers["structural_targets"].iter_records()
        for proposal in STRUCTURAL_TARGET_UNIT_CODEC_V3.read(row).value.proposals
    }
    rva_to_unit = {row.rva_start: row.record_id for row in units.values()}
    if len(rva_to_unit) != len(units):
        raise ParametricSummaryProposalV3Error(
            "semantic units have ambiguous entry RVAs"
        )
    calls = {
        unit_id: tuple(
            (
                occurrence.event_index,
                None
                if occurrence.target_rva is None
                else rva_to_unit.get(occurrence.target_rva),
            )
            for occurrence in row.internal_calls
        )
        for unit_id, row in units.items()
    }
    edges = {
        unit_id: tuple(
            target_id for _event_index, target_id in calls[unit_id] if target_id
        )
        for unit_id in units
    }
    preservation_cache: dict[
        tuple[str, ...], _ProposedPreservationV3
    ] = {}
    proposed_indirect_targets = _propose_target_dataflow_v3(
        units=units,
        static_image=static_images[0],
        import_slots=tuple(sorted(import_slots)),
        profile_index=profile_index,
        calls=calls,
        rva_to_unit=rva_to_unit,
        budget=64,
        preservation_cache=preservation_cache,
    )
    proposals: list[ParametricSccProposalV3] = []
    for members in partition_call_graph_sccs_v3(units, edges):
        member_set = set(members)
        local_edges = tuple(
            sorted(
                (source, target)
                for source in members
                for target in edges[source]
                if target in member_set
            )
        )
        proposals.append(
            _propose_scc(
                members=members,
                call_edges=local_edges,
                units=units,
                memories=memories,
                memories_by_summary_id=memories_by_summary_id,
                structural=structural,
                profile_index=profile_index,
                calls=calls,
                rva_to_unit=rva_to_unit,
                proposed_indirect_targets=proposed_indirect_targets,
                static_value_record_ids=tuple(
                    sorted(
                        (
                            static_images[0].record_id,
                            *(row.record_id for row in import_slots),
                        )
                    )
                ),
                preservation_cache=preservation_cache,
            )
        )
    records: list[ArtifactRecordV3] = [
        PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3.write(
            proposal.proposal_id,
            proposal,
            dependencies=proposal.dependencies,
        )
        for proposal in sorted(proposals, key=lambda row: row.proposal_id)
    ]
    return ArtifactSetWriterV3(
        artifact_kind=PARAMETRIC_SUMMARY_PROPOSALS_ARTIFACT_KIND_V3,
        bindings=(bindings[0],),
        dependencies=tuple(
            _artifact_dependency(name, reader)
            for name, reader in sorted(readers.items())
        ),
        status="complete",
        value_codec=PlainJsonCodecV3(),
    ).write(output_directory, records)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate non-authorizing parametric SCC summary proposals"
    )
    parser.add_argument("--unit-facts", type=Path, required=True)
    parser.add_argument("--memory-versions", type=Path, required=True)
    parser.add_argument("--structural-targets", type=Path, required=True)
    parser.add_argument("--external-profiles", type=Path, required=True)
    parser.add_argument("--static-value-origins", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    generate_parametric_summary_proposals_v3(
        unit_facts_path=arguments.unit_facts,
        memory_versions_path=arguments.memory_versions,
        structural_targets_path=arguments.structural_targets,
        external_profiles_path=arguments.external_profiles,
        static_value_origins_path=arguments.static_value_origins,
        output_directory=arguments.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ParametricSummaryProposalV3Error",
    "generate_parametric_summary_proposals_v3",
    "main",
]
