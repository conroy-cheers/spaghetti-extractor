"""Native SCC-local memory-version authority over checked v3 transitions."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..address_expressions import (
    affine_register_offset,
    affine_special_offset,
    constant_u32,
)
from ..artifact_set_v3 import (
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    canonical_sha256_v3,
)
from ..phase_framework_v3 import PhaseContextV3, SccWorkItemV3, map_sccs
from ._schema import fail, sorted_records
from .memory_records import (
    MEMORY_VERSION_CODEC_V3,
    MEMORY_VERSION_RECORD_V3_SCHEMA,
    MEMORY_VERSIONS_ARTIFACT_KIND_V3,
    ConcreteByteRangeV3,
    MemoryAccessVersionV3,
    MemoryAliasComponentV3,
    MemoryGraphIssueV3,
    MemoryMergeInputV3,
    MemoryMergeV3,
    MemoryVersionRecordV3,
    MemoryVersionV3,
    UnknownWriteKillV3,
)
from .semantic_index import SEMANTIC_INDEX_CODEC_V3, SemanticIndexRecordV3
from .transition_records import (
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionBinaryBindingV3,
    TransitionMemoryAccessV3,
    TransitionSummaryRecordV3,
)


def _concrete_ranges(
    access: TransitionMemoryAccessV3,
) -> tuple[ConcreteByteRangeV3, ...]:
    address = constant_u32(access.address.to_value())
    if address is None or address + access.width_bytes > 1 << 32:
        return ()
    return (ConcreteByteRangeV3.create(address, address + access.width_bytes),)


def _address_class(access: TransitionMemoryAccessV3) -> str:
    address = access.address.to_value()
    if constant_u32(address) is not None:
        return "concrete"
    if affine_register_offset(address, "esp") is not None:
        return "stack_frame"
    if affine_special_offset(address, "fs_base") is not None:
        return "tls"
    return "unknown"


def _alias_components(
    accesses: Sequence[TransitionMemoryAccessV3],
    *,
    ranges_by_access: Mapping[str, tuple[ConcreteByteRangeV3, ...]],
    address_class_by_access: Mapping[str, str],
    merge_unknown: bool,
) -> tuple[MemoryAliasComponentV3, ...]:
    exact = [access for access in accesses if ranges_by_access[access.access_id]]
    ordered = sorted(
        exact,
        key=lambda access: (
            ranges_by_access[access.access_id][0].start,
            ranges_by_access[access.access_id][0].end,
            access.access_id,
        ),
    )
    groups: list[list[TransitionMemoryAccessV3]] = []
    current: list[TransitionMemoryAccessV3] = []
    current_end = -1
    for access in ordered:
        memory_range = ranges_by_access[access.access_id][0]
        if current and memory_range.start >= current_end:
            groups.append(current)
            current = []
            current_end = -1
        current.append(access)
        current_end = max(current_end, memory_range.end)
    if current:
        groups.append(current)
    symbolic = [access for access in accesses if not ranges_by_access[access.access_id]]
    if merge_unknown and symbolic:
        all_ranges = tuple(
            item
            for access in exact
            for item in ranges_by_access[access.access_id]
        )
        return (
            MemoryAliasComponentV3.create(
                ranges=all_ranges,
                access_ids=tuple(access.access_id for access in accesses),
                address_class="unknown",
                contains_unknown_address=True,
            ),
        )
    result = [
        MemoryAliasComponentV3.create(
            ranges=tuple(
                item
                for access in rows
                for item in ranges_by_access[access.access_id]
            ),
            access_ids=tuple(access.access_id for access in rows),
            address_class="concrete",
            contains_unknown_address=False,
        )
        for rows in groups
    ]
    for address_class in ("stack_frame", "tls", "unknown"):
        rows = [
            access
            for access in symbolic
            if address_class_by_access[access.access_id] == address_class
        ]
        if rows:
            result.append(
                MemoryAliasComponentV3.create(
                    ranges=(),
                    access_ids=tuple(access.access_id for access in rows),
                    address_class=address_class,
                    contains_unknown_address=True,
                )
            )
    return tuple(sorted(result, key=lambda row: row.component_id))


def _direct_predecessors(
    semantic_units: Sequence[SemanticIndexRecordV3],
    summaries: Sequence[TransitionSummaryRecordV3],
) -> tuple[dict[str, tuple[str, ...]], tuple[MemoryGraphIssueV3, ...]]:
    by_start = {row.rva_start: row.record_id for row in semantic_units}
    if len(by_start) != len(semantic_units):
        fail(
            "duplicate_structural_rva",
            "semantic units contain duplicate structural entry RVAs",
            "repair exact-unit partitioning before memory analysis",
        )
    predecessors: dict[str, set[str]] = {
        row.record_id: set() for row in semantic_units
    }
    issues: list[MemoryGraphIssueV3] = []
    for row in semantic_units:
        for target in row.direct_target_rvas:
            target_id = by_start.get(target)
            if target_id is None:
                issues.append(
                    MemoryGraphIssueV3.create(
                        status="incomplete",
                        code="direct_control_target_unbound",
                        subject_id=row.record_id,
                        detail={"target_rva": target},
                    )
                )
            else:
                predecessors[target_id].add(row.record_id)
    for summary in summaries:
        if any(
            row.transfer_kind in {"indirect_call", "indirect_jump"}
            for row in summary.exits
        ):
            issues.append(
                MemoryGraphIssueV3.create(
                    status="incomplete",
                    code="indirect_control_requires_target_certificate",
                    subject_id=summary.unit_id,
                    detail={},
                )
            )
    return (
        {
            unit_id: tuple(sorted(values))
            for unit_id, values in predecessors.items()
        },
        tuple(issues),
    )


def _version_nodes(
    *,
    summaries: Sequence[TransitionSummaryRecordV3],
    components: Sequence[MemoryAliasComponentV3],
    component_by_access: Mapping[str, tuple[str, ...]],
    address_class_by_access: Mapping[str, str],
    ranges_by_access: Mapping[str, tuple[ConcreteByteRangeV3, ...]],
    predecessors: Mapping[str, tuple[str, ...]],
) -> tuple[
    tuple[MemoryVersionV3, ...],
    tuple[MemoryMergeV3, ...],
    tuple[MemoryAccessVersionV3, ...],
    tuple[UnknownWriteKillV3, ...],
]:
    summary_by_unit = {row.unit_id: row for row in summaries}
    initial = {
        component.component_id: MemoryVersionV3.create(
            component_id=component.component_id,
            kind="initial",
            defining_access_id=None,
            predecessor_version_ids=(),
        )
        for component in components
    }
    accesses_by_unit_component: dict[
        tuple[str, str], list[TransitionMemoryAccessV3]
    ] = {}
    for summary in summaries:
        for access in summary.memory_accesses:
            for component_id in component_by_access[access.access_id]:
                accesses_by_unit_component.setdefault(
                    (summary.unit_id, component_id), []
                ).append(access)

    def writing_accesses(
        unit_id: str, component_id: str
    ) -> list[TransitionMemoryAccessV3]:
        return [
            access
            for access in accesses_by_unit_component.get(
                (unit_id, component_id), ()
            )
            if access.memory_kind in {"write", "read_write"}
        ]

    merge_by_key: dict[tuple[str, str], MemoryMergeV3] = {}
    entry_cache: dict[tuple[str, str], str] = {}
    visiting: set[tuple[str, str]] = set()
    forced_merge_keys: set[tuple[str, str]] = set()

    def merge_id(component_id: str, unit_id: str) -> str:
        payload = {
            "component_id": component_id,
            "cutpoint": summary_by_unit[unit_id].unit.to_payload(),
        }
        return _stable_node_id("memory-merge", payload)

    def terminal_version_id(component_id: str, unit_id: str) -> str:
        writes = writing_accesses(unit_id, component_id)
        if writes:
            access = writes[-1]
            kind = (
                "write"
                if ranges_by_access[access.access_id]
                else "unknown_write_kill"
            )
            return _stable_node_id(
                "memory-version",
                {
                    "component_id": component_id,
                    "kind": kind,
                    "defining_access_id": access.access_id,
                },
            )
        return entry_version_id(component_id, unit_id)

    def entry_version_id(component_id: str, unit_id: str) -> str:
        key = (component_id, unit_id)
        cached = entry_cache.get(key)
        if cached is not None:
            return cached
        if key in visiting:
            forced_merge_keys.add(key)
            return merge_id(component_id, unit_id)
        visiting.add(key)
        incoming_units = predecessors[unit_id]
        if not incoming_units:
            result = initial[component_id].version_id
        else:
            incoming = tuple(
                MemoryMergeInputV3(
                    predecessor,
                    terminal_version_id(component_id, predecessor),
                )
                for predecessor in incoming_units
            )
            if len(incoming) == 1 and key not in forced_merge_keys:
                result = incoming[0].version_id
            else:
                merge = MemoryMergeV3.create(
                    component_id=component_id,
                    cutpoint=summary_by_unit[unit_id].unit,
                    incoming=incoming,
                )
                merge_by_key[key] = merge
                result = merge.merge_id
        visiting.remove(key)
        entry_cache[key] = result
        return result

    versions: list[MemoryVersionV3] = list(initial.values())
    links: list[MemoryAccessVersionV3] = []
    kills: list[UnknownWriteKillV3] = []
    for (unit_id, component_id), unit_accesses in sorted(
        accesses_by_unit_component.items()
    ):
        current = entry_version_id(component_id, unit_id)
        for access in unit_accesses:
            before = current
            if access.memory_kind in {"write", "read_write"}:
                kind = (
                    "write"
                    if ranges_by_access[access.access_id]
                    else "unknown_write_kill"
                )
                version = MemoryVersionV3.create(
                    component_id=component_id,
                    kind=kind,
                    defining_access_id=access.access_id,
                    predecessor_version_ids=(before,),
                )
                versions.append(version)
                current = version.version_id
                if kind == "unknown_write_kill":
                    address_class = address_class_by_access[access.access_id]
                    affected_scope = (
                        "all_components"
                        if address_class == "unknown"
                        else "finite_components"
                    )
                    kills.append(
                        UnknownWriteKillV3.create(
                            access_id=access.access_id,
                            binding=access.binding,
                            affected_scope=affected_scope,
                            affected_component_ids=(
                                ()
                                if affected_scope == "all_components"
                                else component_by_access[access.access_id]
                            ),
                            reason=(
                                "address expression has no exact concrete byte range"
                            ),
                        )
                    )
            links.append(
                MemoryAccessVersionV3.create(
                    access_id=access.access_id,
                    component_id=component_id,
                    ranges=ranges_by_access[access.access_id],
                    version_before=before,
                    version_after=current,
                )
            )
    return (
        tuple({row.version_id: row for row in versions}.values()),
        tuple(merge_by_key.values()),
        tuple({row.link_id: row for row in links}.values()),
        tuple({row.kill_id: row for row in kills}.values()),
    )


def _stable_node_id(prefix: str, payload: object) -> str:
    from ..artifact_set_v3 import canonical_sha256_v3

    return f"{prefix}:{canonical_sha256_v3(payload)[:24]}"


def _derive_scc_graph(
    context: PhaseContextV3, unit_ids: tuple[str, ...], *, record_id: str
) -> MemoryVersionRecordV3:
    if not unit_ids:
        fail(
            "empty_memory_scc",
            "memory-version SCC contains no semantic units",
            "regenerate the checked dependency schedule",
        )
    semantic_units = tuple(
        context.typed_record(
            "semantic_index", unit_id, SEMANTIC_INDEX_CODEC_V3
        ).value
        for unit_id in unit_ids
    )
    summaries = tuple(
        context.typed_record(
            "transition_summaries", unit_id, TRANSITION_SUMMARY_CODEC_V3
        ).value
        for unit_id in unit_ids
    )
    pe_sha256s = {row.pe_sha256 for row in semantic_units}
    if len(pe_sha256s) != 1:
        fail(
            "mixed_exact_universes",
            "memory SCC mixes exact PE identities",
            "regenerate the dependency schedule for one binary",
        )
    if any(
        semantic.record_id != summary.record_id
        or semantic.unit_sha256 != summary.unit_sha256
        or semantic.pe_sha256 != summary.pe_sha256
        for semantic, summary in zip(semantic_units, summaries, strict=True)
    ):
        fail(
            "semantic_transition_binding_mismatch",
            "memory SCC contains stale semantic and transition records",
            "rebuild the changed unit before memory analysis",
        )
    accesses = tuple(
        access for summary in summaries for access in summary.memory_accesses
    )
    ranges_by_access = {
        access.access_id: _concrete_ranges(access) for access in accesses
    }
    address_class_by_access = {
        access.access_id: _address_class(access) for access in accesses
    }
    components = _alias_components(
        accesses,
        ranges_by_access=ranges_by_access,
        address_class_by_access=address_class_by_access,
        merge_unknown=False,
    )
    component_by_access_lists: dict[str, list[str]] = {
        access.access_id: [] for access in accesses
    }
    for component in components:
        for access_id in component.access_ids:
            component_by_access_lists[access_id].append(component.component_id)
    component_by_access = {
        access_id: tuple(sorted(component_ids))
        for access_id, component_ids in component_by_access_lists.items()
    }
    predecessors, control_issues = _direct_predecessors(semantic_units, summaries)
    versions, merges, links, kills = _version_nodes(
        summaries=summaries,
        components=components,
        component_by_access=component_by_access,
        address_class_by_access=address_class_by_access,
        ranges_by_access=ranges_by_access,
        predecessors=predecessors,
    )
    issues = list(control_issues)
    for summary in summaries:
        if summary.status != "complete":
            issues.append(
                MemoryGraphIssueV3.create(
                    status="incomplete",
                    code="transition_summary_incomplete",
                    subject_id=summary.summary_id,
                    detail={
                        "unsupported_effect_ids": [
                            row.effect_id for row in summary.unsupported_effects
                        ]
                    },
                )
            )
        for exit_record in summary.exits:
            if exit_record.category in {"call", "external", "callback"}:
                issues.append(
                    MemoryGraphIssueV3.create(
                        status="incomplete",
                        code="call_memory_effect_requires_checked_summary",
                        subject_id=exit_record.exit_id,
                        detail={
                            "category": exit_record.category,
                            "transfer_kind": exit_record.transfer_kind,
                        },
                    )
                )
    for access in accesses:
        address_class = address_class_by_access[access.access_id]
        if address_class == "unknown":
            issues.append(
                MemoryGraphIssueV3.create(
                    status="incomplete",
                    code=(
                        "unknown_write_alias"
                        if access.memory_kind in {"write", "read_write"}
                        else "unknown_read_alias"
                    ),
                    subject_id=access.access_id,
                    detail={
                        "policy": "fail_closed",
                        "address_class": address_class,
                        "address": access.address.to_value(),
                        "affected_scope": "all_components",
                    },
                )
            )
    unique_issues = tuple(
        sorted(
            {row.issue_id: row for row in issues}.values(),
            key=lambda row: row.issue_id,
        )
    )
    status = (
        "violated"
        if any(row.status == "violated" for row in unique_issues)
        else "incomplete"
        if unique_issues
        else "complete"
    )
    graph_binding = TransitionBinaryBindingV3(
        summaries[0].pe_sha256,
        canonical_sha256_v3(
            {
                "schema": "memory-scc-compatibility-binding-v3",
                "units": [
                    {
                        "id": semantic.record_id,
                        "unit_sha256": semantic.unit_sha256,
                        "summary_id": summary.summary_id,
                    }
                    for semantic, summary in zip(
                        semantic_units, summaries, strict=True
                    )
                ],
            }
        ),
    )
    return MemoryVersionRecordV3.create(
        record_id=record_id,
        status=status,
        binary=graph_binding,
        transition_summary_ids=tuple(row.summary_id for row in summaries),
        alias_policy="fail_closed",
        alias_components=components,
        versions=versions,
        merges=merges,
        access_versions=links,
        unknown_write_kills=kills,
        issues=unique_issues,
    )


def memory_graph_from_scc_v3(
    value: MemoryVersionRecordV3,
) -> MemoryVersionRecordV3:
    """Return the native checked graph without a compatibility conversion."""

    return value


def _transform_memory_scc(
    context: PhaseContextV3, item: SccWorkItemV3
) -> ArtifactRecordV3:
    unit_ids = item.record_ids("semantic_index")
    value = _derive_scc_graph(context, unit_ids, record_id=item.record_id)
    return MEMORY_VERSION_CODEC_V3.write(item.record_id, value)


def check_memory_versions_completeness_v3(
    reader: ArtifactSetReaderV3, context: PhaseContextV3
) -> None:
    outputs = sorted_records(reader.iter_records())
    if not outputs:
        fail(
            "empty_memory_scc_inventory",
            "memory-version phase emitted no SCC graphs",
            "run it over the checked nonempty dependency schedule",
        )
    for output in outputs:
        submitted = MEMORY_VERSION_CODEC_V3.read(output).value
        semantic_ids = tuple(
            sorted(
                dependency.record_id
                for dependency in output.dependencies
                if dependency.input_name == "semantic_index"
            )
        )
        summary_ids = tuple(
            sorted(
                dependency.record_id
                for dependency in output.dependencies
                if dependency.input_name == "transition_summaries"
            )
        )
        if semantic_ids != summary_ids or not semantic_ids:
            fail(
                "incomplete_record_dependencies",
                f"memory SCC {output.record_id!r} lacks paired semantic/transition inputs",
                "let map_sccs read every scheduled unit and same-ID summary",
            )
        expected = _derive_scc_graph(
            context, semantic_ids, record_id=output.record_id
        )
        if submitted != expected:
            fail(
                "memory_version_contradiction",
                f"memory SCC {output.record_id!r} is stale",
                "rerun only that dependency SCC and its descendants",
            )


MEMORY_VERSIONS_PHASE_V3 = map_sccs(
    name="memory-versions-v3",
    version="3",
    input_artifact_kinds={
        "semantic_index": "semantic-index-v3",
        "transition_summaries": "transition-summaries-v3",
    },
    output_artifact_kind=MEMORY_VERSIONS_ARTIFACT_KIND_V3,
    transform=_transform_memory_scc,
    schedule_record_inputs=("semantic_index",),
    completeness=check_memory_versions_completeness_v3,
    unit_aligned_inputs=("semantic_index", "transition_summaries"),
)


__all__ = [
    "MEMORY_VERSION_CODEC_V3",
    "MEMORY_VERSION_RECORD_V3_SCHEMA",
    "MEMORY_VERSIONS_ARTIFACT_KIND_V3",
    "MEMORY_VERSIONS_PHASE_V3",
    "MemoryVersionRecordV3",
    "check_memory_versions_completeness_v3",
    "memory_graph_from_scc_v3",
]
