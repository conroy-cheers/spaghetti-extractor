"""Pure control-flow analyses used by reconstruction planning.

The helpers in this module deliberately consume small, generic mappings rather
than reconstruction package objects.  They do not mutate their inputs, open a
binary, or assign proof authority.  Callers provide an RVA reader after loading
a PE32 image and may serialize every returned mapping directly as JSON.
"""

from __future__ import annotations

import copy
import json
from collections import deque
from hashlib import sha256
from typing import Any, Callable, Iterable, Mapping, Sequence

from .external_operation_profiles import (
    ExternalOperationProfileError,
    parse_external_operation_contract,
)
from .machine_abi import resolve_machine_call_abi


RvaReader = Callable[[int, int], bytes]

_UNSIGNED_LESS_OPS = frozenset(
    {"unsigned_less", "unsigned_lt", "ult", "ult32"}
)
_UNSIGNED_LESS_EQUAL_OPS = frozenset(
    {"unsigned_less_equal", "unsigned_le", "ule", "ule32"}
)
_REGISTER_OPS = frozenset({"input_reg", "reg", "register"})


def pe32_jump_table_index_expression(
    target_expression: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Return the exact index expression from a supported PE32 table load."""

    shape = _indexed_load_shape(target_expression)
    return copy.deepcopy(dict(shape[1])) if shape is not None else None


def recover_static_pe32_jump_table_inventory(
    *,
    target_expression: Mapping[str, Any],
    predecessor_evidence: Sequence[Mapping[str, Any]],
    image_base: int,
    sections: Sequence[Mapping[str, Any] | Any],
    read_rva: RvaReader,
    finite_index_domain: Mapping[str, Any] | None = None,
    valid_target_rvas: Iterable[int] | None = None,
    max_entries: int = 4096,
) -> dict[str, Any]:
    """Recover one immutable PE32 absolute-pointer jump-table inventory.

    Supported target expressions are a 32-bit load from ``base + index * 4``;
    multiplication by four and a left shift by two are treated identically.
    The index domain may come from bounded machine-IR dataflow. Otherwise every
    incoming predecessor must establish the same unsigned upper bound. Wrapped
    or sparse domains are read entry-by-entry instead of widening their span.

    Analysis failures are data, not exceptions: an incomplete result has an
    empty target inventory and a stable failure code.  Invalid API parameters
    such as a non-positive resolver cap still raise ``ValueError``.
    """

    if max_entries <= 0:
        raise ValueError("max_entries must be positive")
    kind = "pe32_indexed_absolute_jump_table"
    if not _is_u32(image_base):
        return _table_failure(kind, "invalid_image_base", "image_base is not a PE32 value")

    shape = _indexed_load_shape(target_expression)
    if shape is None:
        return _table_failure(
            kind,
            "unsupported_target_expression",
            "target expression is not an exact 32-bit base + index * 4 load",
        )
    table_address, index_expression, expression_form = shape

    remap_shape = _immutable_byte_remap_shape(index_expression)
    bound_expression = (
        remap_shape[1] if remap_shape is not None else index_expression
    )
    evidence_rows: list[dict[str, Any]] = []
    index_values: list[int] | None = None
    dataflow_evidence: dict[str, Any] | None = None
    if (
        remap_shape is None
        and isinstance(finite_index_domain, Mapping)
        and finite_index_domain.get("status") == "complete"
    ):
        expected_expression_sha256 = sha256(
            _canonical_json(index_expression).encode("utf-8")
        ).hexdigest()
        raw_values = finite_index_domain.get("values")
        if (
            finite_index_domain.get("format")
            != "stage-a-finite-u32-expression-domain-v1"
            or finite_index_domain.get("expression_sha256")
            != expected_expression_sha256
            or not isinstance(raw_values, list)
            or any(not _is_u32(value) for value in raw_values)
        ):
            return _table_failure(
                kind,
                "invalid_finite_index_domain",
                (
                    "finite index-domain evidence is malformed or bound to "
                    "another expression"
                ),
            )
        index_values = sorted({int(value) for value in raw_values})
        if not index_values or len(index_values) > max_entries:
            return _table_failure(
                kind,
                "invalid_index_bound",
                "finite index domain is empty or exceeds the resolver cap",
            )
        dataflow_evidence = copy.deepcopy(dict(finite_index_domain))
        evidence_rows.append({
            "source_unit_id": str(
                finite_index_domain.get("source_unit_id", "finite-u32-dataflow")
            ),
            "values": index_values,
            "sources": ["finite_u32_dataflow"],
        })

    source_upper_exclusive: int | None = None
    if index_values is None:
        bounds: set[int] = set()
        if not predecessor_evidence:
            return _table_failure(
                kind,
                "missing_predecessor_evidence",
                "no predecessor proves a finite index bound",
            )
        for ordinal, row in enumerate(
            sorted(predecessor_evidence, key=_canonical_mapping_key)
        ):
            if not isinstance(row, Mapping):
                return _table_failure(
                    kind,
                    "invalid_predecessor_evidence",
                    "predecessor evidence contains a non-mapping row",
                )
            guard = _predecessor_path_guard(row)
            guard_bound = (
                _guard_upper_exclusive(guard, bound_expression)
                if guard is not None
                else None
            )
            instruction_bound = _instruction_upper_exclusive(row, bound_expression)
            row_bounds = {
                value
                for value in (guard_bound, instruction_bound)
                if value is not None
            }
            if len(row_bounds) > 1:
                return _table_failure(
                    kind,
                    "ambiguous_index_bound",
                    "guard and instruction evidence disagree on the index bound",
                )
            if not row_bounds:
                return _table_failure(
                    kind,
                    "unresolved_index_bound",
                    (
                        "an incoming predecessor does not prove a supported "
                        "unsigned bound"
                    ),
                )
            upper = next(iter(row_bounds))
            bounds.add(upper)
            sources = []
            if guard_bound is not None:
                sources.append("guard")
            if instruction_bound is not None:
                sources.append("instructions")
            evidence_rows.append(
                {
                    "source_unit_id": str(
                        row.get(
                            "source_unit_id",
                            row.get("unit_id", f"predecessor:{ordinal}"),
                        )
                    ),
                    "upper_exclusive": upper,
                    "sources": sources,
                }
            )
        if len(bounds) != 1:
            return _table_failure(
                kind,
                "ambiguous_index_bound",
                "incoming predecessors establish different index bounds",
            )
        source_upper_exclusive = next(iter(bounds))
        if source_upper_exclusive <= 0 or source_upper_exclusive > max_entries:
            return _table_failure(
                kind,
                "invalid_index_bound",
                "recovered index bound is empty or exceeds the resolver cap",
            )
        index_values = list(range(source_upper_exclusive))

    remap: dict[str, Any] | None = None
    if remap_shape is not None:
        assert source_upper_exclusive is not None
        remap_address, remap_index, remap_form = remap_shape
        remap_resolution = _resolve_section_address(
            remap_address,
            image_base=image_base,
            sections=sections,
            size=source_upper_exclusive,
            require_executable=False,
        )
        if remap_resolution is None:
            return _table_failure(
                kind,
                "invalid_index_remap_address",
                "byte-remap address does not identify one readable PE section range",
            )
        remap_rva, remap_section, remap_address_model = remap_resolution
        if not _section_flag(remap_section, "readable"):
            return _table_failure(
                kind,
                "unreadable_index_remap",
                "byte-remap table is not in a readable PE section",
            )
        if _section_flag(remap_section, "writable"):
            return _table_failure(
                kind,
                "writable_index_remap",
                "byte-remap table is writable and cannot bound static control",
            )
        try:
            remap_bytes = read_rva(remap_rva, source_upper_exclusive)
        except Exception:
            return _table_failure(
                kind,
                "unreadable_index_remap",
                "byte-remap bytes could not be read",
            )
        if (
            not isinstance(remap_bytes, bytes)
            or len(remap_bytes) != source_upper_exclusive
        ):
            return _table_failure(
                kind,
                "unreadable_index_remap",
                "byte-remap reader did not return the exact requested bytes",
            )
        index_values = sorted(set(remap_bytes))
        if not index_values:
            return _table_failure(
                kind,
                "empty_index_remap",
                "byte-remap table has no values",
            )
        if len(index_values) > max_entries:
            return _table_failure(
                kind,
                "invalid_index_bound",
                "byte-remap output exceeds the resolver cap",
            )
        remap = {
            "kind": "immutable_u8_lookup",
            "expression_form": remap_form,
            "source_expression": copy.deepcopy(dict(remap_index)),
            "source_upper_exclusive": source_upper_exclusive,
            "address": remap_address,
            "address_model": remap_address_model,
            "rva_start": remap_rva,
            "rva_end": remap_rva + source_upper_exclusive,
            "section": _section_name(remap_section),
            "bytes_sha256": sha256(remap_bytes).hexdigest(),
            "possible_values": index_values,
        }

    table_resolution = _resolve_section_address(
        table_address,
        image_base=image_base,
        sections=sections,
        size=1,
        require_executable=False,
    )
    if table_resolution is None:
        return _table_failure(
            kind,
            "invalid_table_address",
            "table address does not identify one readable PE section range",
        )
    table_rva, table_section, address_model = table_resolution
    if not _section_flag(table_section, "readable"):
        return _table_failure(
            kind,
            "unreadable_table",
            "jump table is not in a readable PE section",
        )
    if _section_flag(table_section, "writable"):
        return _table_failure(
            kind,
            "writable_table",
            "jump table is writable and cannot define a static target inventory",
        )

    allowed_targets = None
    if valid_target_rvas is not None:
        values = list(valid_target_rvas)
        if any(not _is_u32(value) for value in values):
            return _table_failure(
                kind,
                "invalid_target_domain",
                "valid_target_rvas contains a non-PE32 value",
            )
        allowed_targets = frozenset(int(value) for value in values)

    entries: list[dict[str, Any]] = []
    table_bytes_by_index: list[tuple[int, int, bytes]] = []
    for index in index_values:
        entry_address = (table_address + index * 4) & 0xFFFFFFFF
        entry_resolution = _resolve_section_address(
            entry_address,
            image_base=image_base,
            sections=sections,
            size=4,
            require_executable=False,
        )
        if entry_resolution is None:
            return _table_failure(
                kind,
                "invalid_table_address",
                f"jump-table index {index} does not identify one PE32 table entry",
            )
        entry_rva, entry_section, entry_address_model = entry_resolution
        if (
            not _section_flag(entry_section, "readable")
            or _section_flag(entry_section, "writable")
            or _section_name(entry_section) != _section_name(table_section)
        ):
            failure_code = (
                "writable_table"
                if _section_flag(entry_section, "writable")
                else "invalid_table_address"
            )
            return _table_failure(
                kind,
                failure_code,
                (
                    "jump-table entries do not remain in one immutable "
                    "readable section"
                ),
            )
        try:
            raw = read_rva(entry_rva, 4)
        except Exception:
            return _table_failure(
                kind,
                "unreadable_table",
                "jump-table bytes could not be read",
            )
        if not isinstance(raw, bytes) or len(raw) != 4:
            return _table_failure(
                kind,
                "unreadable_table",
                "jump-table reader did not return one exact entry",
            )
        table_bytes_by_index.append((index, entry_rva, raw))
        target_address = int.from_bytes(raw, "little")
        resolution = _resolve_section_address(
            target_address,
            image_base=image_base,
            sections=sections,
            size=1,
            require_executable=True,
        )
        if resolution is None:
            return _table_failure(
                kind,
                "invalid_table_target",
                f"jump-table entry {index} does not identify executable PE32 code",
            )
        target_rva, target_section, target_address_model = resolution
        if allowed_targets is not None and target_rva not in allowed_targets:
            return _table_failure(
                kind,
                "invalid_table_target",
                f"jump-table entry {index} is not a declared unit start",
            )
        entries.append(
            {
                "index": index,
                "entry_address": entry_address,
                "entry_address_model": entry_address_model,
                "entry_rva": entry_rva,
                "target_address": target_address,
                "target_address_model": target_address_model,
                "target_rva": target_rva,
                "target_section": _section_name(target_section),
            }
        )

    target_rvas = sorted({int(entry["target_rva"]) for entry in entries})
    entry_rvas = sorted(int(entry["entry_rva"]) for entry in entries)
    contiguous = entry_rvas == list(
        range(entry_rvas[0], entry_rvas[0] + len(entry_rvas) * 4, 4)
    )
    contiguous_from_zero = index_values == list(range(len(index_values)))
    # The range hash always follows ascending address order.  The inventory hash
    # separately preserves semantic index order, including wrapped negative
    # indices represented as uint32 values.
    table_bytes = b"".join(
        raw for _index, _entry_rva, raw in sorted(
            table_bytes_by_index, key=lambda item: item[1]
        )
    )
    table_inventory = b"".join(
        index.to_bytes(4, "little") + raw
        for index, _entry_rva, raw in table_bytes_by_index
    )
    return {
        "status": "recovered",
        "closure": "checked_finite_target_inventory",
        "kind": kind,
        "index": {
            "expression": copy.deepcopy(dict(index_expression)),
            "lower_inclusive": 0 if contiguous_from_zero else None,
            "upper_exclusive": len(index_values) if contiguous_from_zero else None,
            "values": index_values,
            "value_count": len(index_values),
            "dataflow_evidence": dataflow_evidence,
            "remap": remap,
            "bound_evidence": sorted(
                evidence_rows,
                key=_canonical_mapping_key,
            ),
        },
        "table": {
            "address": table_address,
            "address_model": address_model,
            "expression_form": expression_form,
            "rva_start": entry_rvas[0],
            "rva_end": entry_rvas[-1] + 4,
            "entry_width": 4,
            "entry_count": len(index_values),
            "index_values": index_values,
            "contiguous": contiguous,
            "section": _section_name(table_section),
            "bytes_sha256": sha256(table_bytes).hexdigest(),
            "inventory_sha256": sha256(table_inventory).hexdigest(),
        },
        "entries": entries,
        "target_rvas": target_rvas,
        "failure": None,
    }


def derive_rooted_reachable_units(
    *,
    units: Mapping[str, Any] | Sequence[str | Mapping[str, Any]],
    roots: Iterable[str],
    direct_edges: Sequence[Mapping[str, Any]] = (),
    internal_call_edges: Sequence[Mapping[str, Any]] = (),
    recovered_indirect_targets: Sequence[Mapping[str, Any]] = (),
    indirect_exits: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Derive a rooted finite unit slice and preserve unresolved frontiers.

    Direct edges, internal-call edges, and fully recovered indirect inventories
    participate in the fixed point.  A finite indirect inventory is all-or-
    nothing: if any target cannot be resolved to a supplied unit, no edge from
    that inventory is admitted.  Only frontiers whose source is reachable are
    retained in the result.
    """

    unit_ids, rva_index, issues = _unit_inventory(units)
    edge_rows: set[tuple[str, str, str]] = set()
    pending_frontiers: list[dict[str, Any]] = []

    for kind, records in (
        ("direct", direct_edges),
        ("internal_call", internal_call_edges),
    ):
        for record in records:
            parsed = _edge_endpoints(record, unit_ids, rva_index)
            if parsed is None:
                source = _source_unit_id(record)
                issues.append(
                    {
                        "code": f"unresolved_{kind}_edge",
                        "source_unit_id": source,
                    }
                )
                if source in unit_ids:
                    pending_frontiers.append(
                        _frontier(record, source, f"unresolved_{kind}_target")
                    )
                continue
            source, target = parsed
            edge_rows.add((kind, source, target))

    closed_exit_ids: set[str] = set()
    for record in recovered_indirect_targets:
        source = _source_unit_id(record)
        exit_id = _indirect_exit_id(record)
        if source not in unit_ids:
            issues.append(
                {"code": "unknown_indirect_source", "source_unit_id": source}
            )
            continue
        targets = _indirect_target_ids(record, unit_ids, rva_index)
        external_targets = _indirect_external_targets(record)
        if (
            record.get("status") != "recovered"
            or targets is None
            or external_targets is None
            or (not targets and not external_targets)
        ):
            pending_frontiers.append(
                _frontier(record, source, "unresolved_indirect_exit", exit_id=exit_id)
            )
            continue
        for target in targets:
            edge_rows.add(("recovered_indirect", source, target))
        if exit_id is not None:
            closed_exit_ids.add(exit_id)

    for record in indirect_exits:
        source = _source_unit_id(record)
        exit_id = _indirect_exit_id(record)
        if source not in unit_ids:
            issues.append(
                {"code": "unknown_indirect_source", "source_unit_id": source}
            )
        elif exit_id not in closed_exit_ids:
            pending_frontiers.append(
                _frontier(record, source, "unresolved_indirect_exit", exit_id=exit_id)
            )

    root_ids = {str(root) for root in roots}
    resolved_roots = sorted(root_ids & unit_ids)
    missing_roots = sorted(root_ids - unit_ids)
    issues.extend(
        {"code": "unknown_root", "unit_id": root} for root in missing_roots
    )
    adjacency = {unit_id: [] for unit_id in unit_ids}
    for _kind, source, target in sorted(edge_rows):
        adjacency[source].append(target)

    reachable: set[str] = set(resolved_roots)
    work = deque(resolved_roots)
    while work:
        source = work.popleft()
        for target in adjacency[source]:
            if target not in reachable:
                reachable.add(target)
                work.append(target)

    frontiers = _deduplicate_frontiers(
        frontier
        for frontier in pending_frontiers
        if frontier["source_unit_id"] in reachable
    )
    edges = [
        {
            "kind": kind,
            "source_unit_id": source,
            "target_unit_id": target,
        }
        for kind, source, target in sorted(edge_rows)
        if source in reachable
    ]
    # Edge proposals whose sources are outside the rooted closure cannot make
    # those sources reachable. Keep global inventory/root failures, but do not
    # let malformed outgoing control from a confirmed-unreached unit prevent a
    # complete rooted result.
    sorted_issues = _deduplicate_mappings(
        issue
        for issue in issues
        if not isinstance(issue.get("source_unit_id"), str)
        or issue["source_unit_id"] not in unit_ids
        or issue["source_unit_id"] in reachable
    )
    not_reached = unit_ids - reachable
    incomplete = bool(frontiers or sorted_issues)
    potential = not_reached if incomplete else set()
    unreachable = set() if incomplete else not_reached
    return {
        "status": "incomplete" if incomplete else "complete",
        "roots": resolved_roots,
        "reachable_units": sorted(reachable),
        "potential_units": sorted(potential),
        "unreachable_units": sorted(unreachable),
        "not_reached_units": sorted(not_reached),
        "edges": edges,
        "frontiers": frontiers,
        "issues": sorted_issues,
        "counts": {
            "units": len(unit_ids),
            "reachable_units": len(reachable),
            "potential_units": len(potential),
            "unreachable_units": len(unreachable),
            "not_reached_units": len(not_reached),
            "edges": len(edges),
            "unresolved_frontiers": len(frontiers),
        },
    }


def classify_overlapping_instruction_starts(
    *,
    units: Sequence[Mapping[str, Any]],
    reachable_unit_ids: Iterable[str],
    target_sources: Mapping[int, Sequence[str]] | None = None,
) -> dict[str, Any]:
    """Classify speculative unit starts inside rooted exact instructions.

    An x86 decoder may propose overlapping views, so overlap alone is not proof
    that one view is dead.  Only a non-reachable, independently untargeted view
    may be excluded.  If both views are rooted or a checked control source names
    the inner start, the ambiguity is retained as a conflict.
    """

    reached = {str(unit_id) for unit_id in reachable_unit_ids}
    targets = {
        int(rva): tuple(sorted({str(source) for source in sources}))
        for rva, sources in (target_sources or {}).items()
    }
    instructions: list[dict[str, Any]] = []
    for unit in units:
        unit_id = str(unit.get("id"))
        if unit_id not in reached:
            continue
        for instruction in unit.get("instructions", []):
            if not isinstance(instruction, Mapping):
                continue
            start = instruction.get("rva_start", instruction.get("rva"))
            end = instruction.get("rva_end")
            if (
                end is None
                and isinstance(start, int)
                and isinstance(instruction.get("size"), int)
            ):
                end = start + int(instruction["size"])
            if (
                not isinstance(start, int)
                or isinstance(start, bool)
                or not isinstance(end, int)
                or isinstance(end, bool)
                or not 0 <= start < end <= 2**32
            ):
                continue
            instructions.append({
                "owner_unit_id": unit_id,
                "rva_start": start,
                "rva_end": end,
                "instruction_sha256": instruction.get("instruction_sha256"),
            })

    excluded: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for unit in units:
        unit_id = str(unit.get("id"))
        start = _unit_start_rva(unit)
        if start is None:
            continue
        owners = [
            instruction
            for instruction in instructions
            if instruction["owner_unit_id"] != unit_id
            and instruction["rva_start"] < start < instruction["rva_end"]
        ]
        if not owners:
            continue
        evidence = sorted(
            owners,
            key=lambda row: (
                int(row["rva_start"]),
                int(row["rva_end"]),
                str(row["owner_unit_id"]),
            ),
        )
        row = {
            "unit_id": unit_id,
            "rva": start,
            "instruction_evidence": evidence,
        }
        if unit_id in reached or start in targets:
            conflicts.append({
                **row,
                "code": "independent_target_inside_reachable_instruction",
                "target_sources": list(targets.get(start, ())),
            })
        else:
            excluded.append({
                **row,
                "reason": "starts_inside_rooted_reachable_instruction",
            })
    excluded.sort(key=lambda row: (int(row["rva"]), str(row["unit_id"])))
    conflicts.sort(key=lambda row: (int(row["rva"]), str(row["unit_id"])))
    return {
        "format": "stage-a-overlapping-instruction-start-classification-v1",
        "status": "violated" if conflicts else "complete",
        "excluded_units": excluded,
        "conflicts": conflicts,
        "counts": {
            "reachable_instructions": len(instructions),
            "excluded_units": len(excluded),
            "conflicts": len(conflicts),
        },
    }


def _unit_start_rva(unit: Mapping[str, Any]) -> int | None:
    direct = unit.get("rva")
    if isinstance(direct, int) and not isinstance(direct, bool):
        return direct
    source = unit.get("source")
    original = source.get("original") if isinstance(source, Mapping) else None
    start = original.get("rva_start") if isinstance(original, Mapping) else None
    return start if isinstance(start, int) and not isinstance(start, bool) else None


def propose_semantic_clusters(
    *,
    units: Mapping[str, Any] | Sequence[str | Mapping[str, Any]],
    direct_edges: Sequence[Mapping[str, Any]],
    reachable_units: Iterable[str] | None = None,
    roots: Iterable[str] = (),
    internal_call_edges: Sequence[Mapping[str, Any]] = (),
    external_exits: Sequence[str | Mapping[str, Any]] = (),
    fault_exits: Sequence[str | Mapping[str, Any]] = (),
    indirect_exits: Sequence[str | Mapping[str, Any]] = (),
    max_cluster_units: int = 64,
) -> dict[str, Any]:
    """Propose deterministic loop SCCs and maximal straight-line clusters.

    Call, external, fault, and indirect sources are terminal cutpoints for this
    analysis.  Normal direct edges out of those units are kept as boundary
    metadata but are excluded from SCC and chain formation.  Cyclic SCCs are
    never split; an SCC larger than ``max_cluster_units`` is left unclustered
    and reported as incomplete instead of silently weakening its loop shape.
    """

    if max_cluster_units <= 0:
        raise ValueError("max_cluster_units must be positive")
    unit_ids, rva_index, issues = _unit_inventory(units)
    requested_reachable = (
        None
        if reachable_units is None
        else {str(unit_id) for unit_id in reachable_units}
    )
    active = set(unit_ids) if requested_reachable is None else requested_reachable & unit_ids
    if reachable_units is not None:
        assert requested_reachable is not None
        unknown = sorted(requested_reachable - unit_ids)
        issues.extend(
            {"code": "unknown_reachable_unit", "unit_id": unit_id}
            for unit_id in unknown
        )

    cutpoint_rows: set[tuple[str, str]] = set()
    for record in internal_call_edges:
        source = _source_unit_id(record)
        if source in active:
            cutpoint_rows.add((source, "call"))
    for kind, records in (
        ("external", external_exits),
        ("fault", fault_exits),
        ("indirect", indirect_exits),
    ):
        for record in records:
            source = str(record) if isinstance(record, str) else _source_unit_id(record)
            if source in active:
                cutpoint_rows.add((source, kind))

    all_direct: set[tuple[str, str]] = set()
    for record in direct_edges:
        parsed = _edge_endpoints(record, unit_ids, rva_index)
        source = _source_unit_id(record)
        if parsed is None:
            if source in active:
                cutpoint_rows.add((source, "external"))
            issues.append(
                {"code": "unresolved_direct_edge", "source_unit_id": source}
            )
            continue
        edge = parsed
        if edge[0] in active and edge[1] in active:
            all_direct.add(edge)

    cutpoint_sources = {source for source, _kind in cutpoint_rows}
    graph = {unit_id: [] for unit_id in sorted(active)}
    for source, target in sorted(all_direct):
        if source not in cutpoint_sources:
            graph[source].append(target)

    components = _strongly_connected_components(graph)
    cyclic_components: list[tuple[str, ...]] = []
    cyclic_units: set[str] = set()
    for component in components:
        cyclic = len(component) > 1 or (
            len(component) == 1 and component[0] in graph[component[0]]
        )
        if cyclic:
            cyclic_components.append(component)
            cyclic_units.update(component)

    groups: list[tuple[str, tuple[str, ...]]] = []
    oversized: set[str] = set()
    for component in sorted(cyclic_components):
        if len(component) > max_cluster_units:
            oversized.update(component)
            issues.append(
                {
                    "code": "oversized_loop_scc",
                    "unit_ids": list(component),
                    "limit": max_cluster_units,
                }
            )
        else:
            groups.append(("loop_scc", component))

    chain_nodes = active - cyclic_units
    chain_predecessors = {unit_id: [] for unit_id in chain_nodes}
    chain_successors = {unit_id: [] for unit_id in chain_nodes}
    for source, targets in graph.items():
        if source not in chain_nodes:
            continue
        for target in targets:
            if target in chain_nodes:
                chain_successors[source].append(target)
                chain_predecessors[target].append(source)
    for values in (*chain_predecessors.values(), *chain_successors.values()):
        values.sort()

    visited: set[str] = set()
    starts = [
        unit_id
        for unit_id in sorted(chain_nodes)
        if len(chain_predecessors[unit_id]) != 1
        or len(chain_successors[chain_predecessors[unit_id][0]]) != 1
    ]
    for start in starts:
        _append_bounded_chain_groups(
            start,
            chain_predecessors,
            chain_successors,
            visited,
            max_cluster_units,
            groups,
        )
    for start in sorted(chain_nodes - visited):
        _append_bounded_chain_groups(
            start,
            chain_predecessors,
            chain_successors,
            visited,
            max_cluster_units,
            groups,
        )

    groups.sort(key=lambda item: (item[1][0], item[0], item[1]))
    root_set = {str(root) for root in roots}
    cutpoints = [
        {"source_unit_id": source, "kind": kind}
        for source, kind in sorted(cutpoint_rows)
    ]
    clusters: list[dict[str, Any]] = []
    unit_to_cluster: dict[str, str] = {}
    for group_kind, members_tuple in groups:
        members = set(members_tuple)
        identity = _stable_id(
            "semantic-cluster",
            {"kind": group_kind, "unit_ids": list(members_tuple)},
        )
        entries = {
            target
            for source, target in all_direct
            if source not in members and target in members
        } | (members & root_set)
        exits = {
            source
            for source, target in all_direct
            if source in members and target not in members
        } | (members & cutpoint_sources)
        if not entries:
            entries.add(members_tuple[0])
        member_cutpoints = [
            row for row in cutpoints if row["source_unit_id"] in members
        ]
        cluster = {
            "id": identity,
            "kind": group_kind if len(members_tuple) > 1 else "singleton",
            "unit_ids": list(members_tuple),
            "entry_unit_ids": sorted(entries),
            "exit_unit_ids": sorted(exits),
            "cutpoints": member_cutpoints,
            "bounded": True,
        }
        clusters.append(cluster)
        for unit_id in members_tuple:
            unit_to_cluster[unit_id] = identity

    sorted_issues = _deduplicate_mappings(issues)
    unclustered = sorted((active - set(unit_to_cluster)) | oversized)
    return {
        "status": "incomplete" if sorted_issues or unclustered else "complete",
        "max_cluster_units": max_cluster_units,
        "clusters": clusters,
        "unit_to_cluster": dict(sorted(unit_to_cluster.items())),
        "cutpoints": cutpoints,
        "excluded_unit_ids": sorted(unit_ids - active),
        "unclustered_unit_ids": unclustered,
        "issues": sorted_issues,
        "counts": {
            "clusters": len(clusters),
            "loop_sccs": sum(cluster["kind"] == "loop_scc" for cluster in clusters),
            "clustered_units": len(unit_to_cluster),
            "unclustered_units": len(unclustered),
        },
    }


def _table_failure(kind: str, code: str, message: str) -> dict[str, Any]:
    return {
        "status": "incomplete",
        "closure": "unresolved",
        "kind": kind,
        "index": None,
        "table": None,
        "entries": [],
        "target_rvas": [],
        "failure": {"code": code, "message": message},
    }


def _indexed_load_shape(
    expression: Mapping[str, Any],
) -> tuple[int, Mapping[str, Any], str] | None:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op", "")).lower()
    if op == "read32":
        address = expression.get("address")
    elif op == "load":
        width = expression.get("width")
        width_bits = expression.get("width_bits")
        if width not in (None, 4) or width_bits not in (None, 32):
            return None
        if width is None and width_bits is None:
            return None
        address = expression.get("address")
    else:
        return None
    operands = _binary_operands(address, "add")
    if operands is None:
        return None
    candidates = []
    for base_expression, scaled_expression in (operands, reversed(operands)):
        base = _constant_value(base_expression)
        scaled = _scaled_index(scaled_expression)
        if base is not None and scaled is not None:
            index, form = scaled
            candidates.append((base, index, form))
    unique = {
        (base, _canonical_json(index), form): (base, index, form)
        for base, index, form in candidates
    }
    if len(unique) != 1:
        return None
    return next(iter(unique.values()))


def _scaled_index(expression: Any) -> tuple[Mapping[str, Any], str] | None:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op", "")).lower()
    if op in {"shift_left", "shl", "shl32"}:
        amount = expression.get("amount")
        if _constant_value(amount) == 2 or amount == 2:
            value = expression.get("value", expression.get("left"))
            if isinstance(value, Mapping):
                return value, "shift_left_2"
    if op in {"mul", "multiply", "mul32"}:
        operands = _binary_operands(expression, op)
        if operands is not None:
            for constant, index in (operands, reversed(operands)):
                if _constant_value(constant) == 4 and isinstance(index, Mapping):
                    return index, "multiply_4"
    return None


def _immutable_byte_remap_shape(
    expression: Mapping[str, Any],
) -> tuple[int, Mapping[str, Any], str] | None:
    byte_load = _strip_u8_preserving_operations(expression)
    if byte_load is None:
        return None
    address = byte_load.get("address")
    operands = _binary_operands(address, "add")
    if operands is None:
        return None
    candidates: list[tuple[int, Mapping[str, Any], str]] = []
    for base_expression, index_expression in (operands, reversed(operands)):
        base = _constant_value(base_expression)
        if base is not None and isinstance(index_expression, Mapping):
            candidates.append((base, index_expression, "base_plus_index"))
    unique = {
        (base, _canonical_json(index), form): (base, index, form)
        for base, index, form in candidates
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _strip_u8_preserving_operations(
    expression: Any,
) -> Mapping[str, Any] | None:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op", "")).lower()
    if op in {"load", "read8", "mem8"}:
        width = expression.get("width")
        width_bits = expression.get("width_bits")
        if op == "load" and width not in {1, None}:
            return None
        if op == "load" and width is None and width_bits != 8:
            return None
        if op != "load" and width_bits not in {8, None}:
            return None
        return expression
    if op in {"and", "and32", "bit_and"}:
        operands = _binary_operands(expression, op)
        if operands is None:
            return None
        for mask_expression, value_expression in (operands, reversed(operands)):
            mask = _constant_expression_value(mask_expression)
            if mask is not None and mask & 0xFF == 0xFF:
                stripped = _strip_u8_preserving_operations(value_expression)
                if stripped is not None:
                    return stripped
        return None
    if op in {"or", "or32", "bit_or"}:
        operands = _binary_operands(expression, op)
        if operands is None:
            return None
        for zero_expression, value_expression in (operands, reversed(operands)):
            if _constant_expression_value(zero_expression) == 0:
                stripped = _strip_u8_preserving_operations(value_expression)
                if stripped is not None:
                    return stripped
    return None


def _constant_expression_value(expression: Any) -> int | None:
    direct = _constant_value(expression)
    if direct is not None:
        return direct & 0xFFFFFFFF
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op", "")).lower()
    operands = _binary_operands(expression, op)
    if operands is None:
        return None
    left = _constant_expression_value(operands[0])
    right = _constant_expression_value(operands[1])
    if left is None or right is None:
        return None
    if op in {"and", "and32", "bit_and"}:
        return left & right
    if op in {"or", "or32", "bit_or"}:
        return left | right
    if op in {"add", "add32"}:
        return (left + right) & 0xFFFFFFFF
    if op in {"sub", "sub32"}:
        return (left - right) & 0xFFFFFFFF
    if op in {"mul", "multiply", "mul32"}:
        return (left * right) & 0xFFFFFFFF
    return None


def _predecessor_path_guard(row: Mapping[str, Any]) -> Mapping[str, Any] | None:
    for key in ("guard", "edge_guard"):
        value = row.get(key)
        if isinstance(value, Mapping):
            return value
    edge = row.get("edge")
    if isinstance(edge, Mapping) and isinstance(edge.get("guard"), Mapping):
        return edge["guard"]
    condition = row.get("condition")
    edge_kind = str(row.get("edge_kind", row.get("reaches_on", ""))).lower()
    if isinstance(condition, Mapping):
        if edge_kind in {"taken", "true"}:
            return condition
        if edge_kind in {"fallthrough", "not_taken", "false"}:
            return {"op": "not", "value": condition}
    return None


def _guard_upper_exclusive(guard: Any, index: Mapping[str, Any]) -> int | None:
    if not isinstance(guard, Mapping):
        return None
    op = str(guard.get("op", "")).lower()
    operands = _binary_operands(guard, op)
    if op in _UNSIGNED_LESS_OPS and operands is not None:
        left, right = operands
        upper = _constant_value(right)
        if _same_expression(left, index) and upper is not None and 0 < upper <= 0xFFFFFFFF:
            return upper
    if op in _UNSIGNED_LESS_EQUAL_OPS and operands is not None:
        left, right = operands
        upper = _constant_value(right)
        if _same_expression(left, index) and upper is not None and 0 <= upper < 0xFFFFFFFF:
            return upper + 1
    if op == "not" and isinstance(guard.get("value"), Mapping):
        inner = guard["value"]
        inner_op = str(inner.get("op", "")).lower()
        inner_operands = _binary_operands(inner, inner_op)
        if inner_op in _UNSIGNED_LESS_OPS and inner_operands is not None:
            lower, value = inner_operands
            limit = _constant_value(lower)
            if limit is not None and _same_expression(value, index) and limit < 0xFFFFFFFF:
                return limit + 1
        composite = _negated_greater_upper(inner, index)
        if composite is not None:
            return composite
    if op == "or" and operands is not None:
        less_bound = None
        equal_bound = None
        for child in operands:
            if not isinstance(child, Mapping):
                return None
            child_op = str(child.get("op", "")).lower()
            if child_op in _UNSIGNED_LESS_OPS:
                less_bound = _guard_upper_exclusive(child, index)
            elif child_op == "equal":
                equal_bound = _index_equal_constant(child, index)
        if less_bound is not None and equal_bound == less_bound:
            return less_bound + 1
    return None


def _negated_greater_upper(inner: Mapping[str, Any], index: Mapping[str, Any]) -> int | None:
    if str(inner.get("op", "")).lower() not in {"and", "bit_and"}:
        return None
    children = _binary_operands(inner, str(inner.get("op", "")).lower())
    if children is None:
        return None
    less_limit = None
    unequal_limit = None
    for child in children:
        if not isinstance(child, Mapping) or str(child.get("op", "")).lower() != "not":
            return None
        predicate = child.get("value")
        if not isinstance(predicate, Mapping):
            return None
        predicate_op = str(predicate.get("op", "")).lower()
        predicate_operands = _binary_operands(predicate, predicate_op)
        if predicate_op in _UNSIGNED_LESS_OPS and predicate_operands is not None:
            left, right = predicate_operands
            limit = _constant_value(right)
            if not _same_expression(left, index) or limit is None:
                return None
            less_limit = limit
        elif predicate_op == "equal":
            unequal_limit = _subtraction_zero_limit(predicate, index)
        else:
            return None
    if less_limit is None or unequal_limit != less_limit or less_limit >= 0xFFFFFFFF:
        return None
    return less_limit + 1


def _subtraction_zero_limit(predicate: Mapping[str, Any], index: Mapping[str, Any]) -> int | None:
    operands = _binary_operands(predicate, "equal")
    if operands is None:
        return None
    left, right = operands
    if _constant_value(left) == 0:
        left, right = right, left
    if _constant_value(right) != 0 or not isinstance(left, Mapping):
        return None
    subtraction = _binary_operands(left, "sub")
    if subtraction is None:
        return None
    value, limit_expression = subtraction
    limit = _constant_value(limit_expression)
    return limit if limit is not None and _same_expression(value, index) else None


def _index_equal_constant(predicate: Mapping[str, Any], index: Mapping[str, Any]) -> int | None:
    operands = _binary_operands(predicate, "equal")
    if operands is None:
        return None
    for value, constant in (operands, reversed(operands)):
        limit = _constant_value(constant)
        if limit is not None and _same_expression(value, index):
            return limit
    return None


def _instruction_upper_exclusive(
    row: Mapping[str, Any], index: Mapping[str, Any]
) -> int | None:
    instructions = row.get("instructions")
    if not isinstance(instructions, Sequence) or isinstance(instructions, (str, bytes)):
        return None
    index_register = _index_register(index)
    edge_kind = str(row.get("edge_kind", row.get("reaches_on", ""))).lower()
    if index_register is None or edge_kind not in {
        "taken",
        "true",
        "fallthrough",
        "not_taken",
        "false",
    }:
        return None
    branch_index = None
    branch_mnemonic = None
    for position in range(len(instructions) - 1, -1, -1):
        instruction = instructions[position]
        if not isinstance(instruction, Mapping):
            continue
        mnemonic = str(instruction.get("mnemonic", "")).lower()
        if mnemonic.startswith("j"):
            branch_index = position
            branch_mnemonic = mnemonic
            break
    if branch_index is None or branch_mnemonic is None:
        return None
    compare = None
    for position in range(branch_index - 1, -1, -1):
        instruction = instructions[position]
        if isinstance(instruction, Mapping) and str(
            instruction.get("mnemonic", "")
        ).lower() == "cmp":
            compare = instruction
            break
    if compare is None:
        return None
    operands = compare.get("operands")
    if not isinstance(operands, Sequence) or len(operands) != 2:
        return None
    register = _instruction_register(operands[0])
    immediate = _instruction_immediate(operands[1])
    if register != index_register or immediate is None or not 0 <= immediate <= 0xFFFFFFFF:
        return None
    taken = edge_kind in {"taken", "true"}
    if branch_mnemonic in {"jb", "jnae", "jc"} and taken:
        return immediate if immediate > 0 else None
    if branch_mnemonic in {"jae", "jnb", "jnc"} and not taken:
        return immediate if immediate > 0 else None
    if branch_mnemonic in {"jbe", "jna"} and taken and immediate < 0xFFFFFFFF:
        return immediate + 1
    if branch_mnemonic in {"ja", "jnbe"} and not taken and immediate < 0xFFFFFFFF:
        return immediate + 1
    return None


def _resolve_section_address(
    value: int,
    *,
    image_base: int,
    sections: Sequence[Mapping[str, Any] | Any],
    size: int,
    require_executable: bool,
) -> tuple[int, Mapping[str, Any] | Any, str] | None:
    if not _is_u32(value) or size <= 0:
        return None
    candidates: dict[int, set[str]] = {}
    candidates.setdefault(value, set()).add("rva")
    if value >= image_base:
        candidates.setdefault(value - image_base, set()).add("va")
    resolved = []
    for rva, models in candidates.items():
        if not _is_u32(rva) or rva + size > 0x100000000:
            continue
        matches = [
            section
            for section in sections
            if _section_covers(section, rva, rva + size)
            and (not require_executable or _section_flag(section, "executable"))
        ]
        if len(matches) == 1:
            model = "va_or_rva" if len(models) > 1 else next(iter(models))
            resolved.append((rva, matches[0], model))
        elif len(matches) > 1:
            return None
    if len(resolved) != 1:
        return None
    return resolved[0]


def _section_covers(section: Mapping[str, Any] | Any, start: int, end: int) -> bool:
    rva_start = _field(section, "rva_start")
    rva_end = _field(section, "rva_end")
    return (
        _is_u32(rva_start)
        and isinstance(rva_end, int)
        and not isinstance(rva_end, bool)
        and rva_start <= start < end <= rva_end <= 0x100000000
    )


def _section_flag(section: Mapping[str, Any] | Any, name: str) -> bool:
    return _field(section, name) is True


def _section_name(section: Mapping[str, Any] | Any) -> str | None:
    value = _field(section, "name")
    return str(value) if value is not None else None


def _field(value: Mapping[str, Any] | Any, name: str) -> Any:
    return value.get(name) if isinstance(value, Mapping) else getattr(value, name, None)


def _unit_inventory(
    units: Mapping[str, Any] | Sequence[str | Mapping[str, Any]],
) -> tuple[set[str], dict[int, set[str]], list[dict[str, Any]]]:
    rows: list[tuple[str, Any]] = []
    issues: list[dict[str, Any]] = []
    if isinstance(units, Mapping):
        rows = [(str(unit_id), value) for unit_id, value in units.items()]
    else:
        for index, value in enumerate(units):
            if isinstance(value, str):
                rows.append((value, None))
            elif isinstance(value, Mapping) and value.get("id") is not None:
                rows.append((str(value["id"]), value))
            else:
                issues.append({"code": "invalid_unit", "index": index})
    unit_ids = {unit_id for unit_id, _value in rows}
    if len(unit_ids) != len(rows):
        issues.append({"code": "duplicate_unit_id"})
    rva_index: dict[int, set[str]] = {}
    for unit_id, value in rows:
        rva = _unit_rva(value)
        if rva is not None:
            rva_index.setdefault(rva, set()).add(unit_id)
    return unit_ids, rva_index, issues


def _unit_rva(value: Any) -> int | None:
    if not isinstance(value, Mapping):
        return None
    for key in ("rva", "rva_start", "entry_rva"):
        if _is_u32(value.get(key)):
            return int(value[key])
    source = value.get("source")
    original = source.get("original") if isinstance(source, Mapping) else None
    if isinstance(original, Mapping) and _is_u32(original.get("rva_start")):
        return int(original["rva_start"])
    return None


def _edge_endpoints(
    record: Mapping[str, Any], unit_ids: set[str], rva_index: Mapping[int, set[str]]
) -> tuple[str, str] | None:
    if not isinstance(record, Mapping):
        return None
    source = _source_unit_id(record)
    if source not in unit_ids:
        return None
    target = None
    for key in ("target_unit_id", "resolved_unit_id", "target"):
        value = record.get(key)
        if value is not None and str(value) in unit_ids:
            target = str(value)
            break
    if target is None and _is_u32(record.get("target_rva")):
        matches = rva_index.get(int(record["target_rva"]), set())
        if len(matches) == 1:
            target = next(iter(matches))
    return (source, target) if target is not None else None


def _source_unit_id(record: Mapping[str, Any]) -> str:
    if not isinstance(record, Mapping):
        return ""
    value = record.get("source_unit_id", record.get("source", record.get("unit_id")))
    return "" if value is None else str(value)


def _indirect_exit_id(record: Mapping[str, Any]) -> str | None:
    for key in ("indirect_exit_id", "exit_id", "id"):
        value = record.get(key)
        if value is not None:
            return str(value)
    return None


def _indirect_target_ids(
    record: Mapping[str, Any], unit_ids: set[str], rva_index: Mapping[int, set[str]]
) -> tuple[str, ...] | None:
    raw_ids = record.get("target_unit_ids", record.get("target_ids"))
    id_targets: set[str] | None = None
    if isinstance(raw_ids, Sequence) and not isinstance(raw_ids, (str, bytes)):
        id_targets = {str(value) for value in raw_ids}
        if not id_targets <= unit_ids:
            return None
    raw_rvas = record.get("target_rvas")
    if isinstance(raw_rvas, Sequence) and not isinstance(raw_rvas, (str, bytes)):
        rva_targets = set()
        for raw_rva in raw_rvas:
            if not _is_u32(raw_rva):
                return None
            matches = rva_index.get(int(raw_rva), set())
            if len(matches) != 1:
                return None
            rva_targets.update(matches)
        if id_targets is not None and id_targets != rva_targets:
            return None
        return tuple(sorted(rva_targets))
    return tuple(sorted(id_targets)) if id_targets is not None else ()


def _indirect_external_targets(
    record: Mapping[str, Any],
) -> tuple[tuple[Any, ...], ...] | None:
    raw_targets = record.get("external_targets", [])
    if not isinstance(raw_targets, Sequence) or isinstance(raw_targets, (str, bytes)):
        return None
    result: set[tuple[Any, ...]] = set()
    for raw in raw_targets:
        if not isinstance(raw, Mapping):
            return None
        protocol = raw.get("external_protocol")
        if isinstance(protocol, Mapping):
            if raw.get("import") is not None:
                return None
            kind = protocol.get("kind")
            profile_id = protocol.get("profile_id")
            profile_sha256 = protocol.get("profile_sha256")
            if kind == "pe32-resolved-export":
                target_id = protocol.get("target_id")
                transfer_kind = protocol.get("transfer_kind")
                target = _canonical_import_identity(protocol.get("target"))
                resolver = _canonical_import_identity(
                    protocol.get("resolver_import")
                )
                loader = _canonical_import_identity(
                    protocol.get("loader_import")
                )
                module = protocol.get("module")
                name = protocol.get("name")
                abi = raw.get("abi")
                argument_words = raw.get("argument_words")
                contract = protocol.get("machine_contract")
                expected_abi = (
                    resolve_machine_call_abi(abi.get("template"))
                    if isinstance(abi, Mapping)
                    else None
                )
                arity = (
                    contract.get("arity")
                    if isinstance(contract, Mapping)
                    else None
                )
                effect = (
                    contract.get("effect_model")
                    if isinstance(contract, Mapping)
                    else None
                )
                if (
                    not _profile_identity(profile_id, profile_sha256)
                    or not _is_u32(target_id)
                    or transfer_kind not in {"call", "jump"}
                    or target is None
                    or resolver is None
                    or loader is None
                    or not isinstance(module, str)
                    or not module
                    or not isinstance(name, str)
                    or not name
                    or expected_abi is None
                    or dict(abi) != expected_abi.as_json()
                    or not isinstance(argument_words, int)
                    or isinstance(argument_words, bool)
                    or not 0 <= argument_words <= 64
                    or not isinstance(contract, Mapping)
                    or _canonical_import_identity(contract.get("import")) != target
                    or contract.get("abi_template") != abi.get("template")
                    or not isinstance(arity, Mapping)
                    or arity.get("kind") != "fixed"
                    or arity.get("words") != argument_words
                    or not isinstance(effect, Mapping)
                    or effect.get("kind") != "exact_native_dll_callthrough_v1"
                    or effect.get("prerequisites")
                    != {
                        "same_pinned_dll_implementation": True,
                        "exact_machine_arguments": True,
                        "candidate_address_space_used_directly": True,
                    }
                    or contract.get("memory_effect") != "nativeCallthrough"
                    or contract.get("world_effect") != "nativeCallthrough"
                    or contract.get("callback_effect") != "none"
                    or not isinstance(contract.get("memory_footprints"), list)
                    or not isinstance(
                        contract.get("result_register_relations"), list
                    )
                    or raw.get("out_interfaces") != []
                ):
                    return None
                result.add((
                    "resolved_export",
                    str(profile_id),
                    str(profile_sha256),
                    int(target_id),
                    str(transfer_kind),
                    target,
                    resolver,
                    loader,
                    module,
                    name,
                    json.dumps(contract, sort_keys=True, separators=(",", ":")),
                ))
                continue
            if kind == "pe32-operation":
                operation_id = protocol.get("operation_id")
                transfer_kind = protocol.get("transfer_kind")
                selectors = protocol.get("selectors")
                contract_id = protocol.get("environment_contract_id")
                abi = raw.get("abi")
                argument_words = raw.get("argument_words")
                output_rules = raw.get("output_rules")
                environment_contract = raw.get("environment_contract")
                expected_abi = (
                    resolve_machine_call_abi(abi.get("template"))
                    if isinstance(abi, Mapping)
                    else None
                )
                if (
                    not _profile_identity(profile_id, profile_sha256)
                    or not isinstance(operation_id, str)
                    or not operation_id
                    or transfer_kind != "call"
                    or not _operation_selectors(selectors, operation_id)
                    or not isinstance(contract_id, str)
                    or not contract_id
                    or expected_abi is None
                    or dict(abi) != expected_abi.as_json()
                    or not isinstance(argument_words, int)
                    or isinstance(argument_words, bool)
                    or not 0 <= argument_words <= 64
                    or not isinstance(output_rules, list)
                    or any(not isinstance(rule, Mapping) for rule in output_rules)
                    or not _operation_environment_contract(
                        environment_contract,
                        contract_id=contract_id,
                        argument_words=argument_words,
                    )
                ):
                    return None
                result.add((
                    "operation",
                    str(profile_id),
                    str(profile_sha256),
                    operation_id,
                    json.dumps(selectors, sort_keys=True, separators=(",", ":")),
                    contract_id,
                    json.dumps(abi, sort_keys=True, separators=(",", ":")),
                    argument_words,
                    json.dumps(output_rules, sort_keys=True, separators=(",", ":")),
                    json.dumps(
                        environment_contract,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                ))
                continue
            interface_id = protocol.get("interface_id")
            method = protocol.get("method")
            slot = protocol.get("slot")
            offset = protocol.get("offset")
            abi = raw.get("abi")
            argument_words = raw.get("argument_words")
            if (
                kind != "pe32-interface-method"
                or not isinstance(profile_id, str)
                or not profile_id
                or not isinstance(profile_sha256, str)
                or len(profile_sha256) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in profile_sha256
                )
                or not isinstance(interface_id, str)
                or not interface_id
                or not isinstance(method, str)
                or not method
                or not _is_u32(slot)
                or not _is_u32(offset)
                or int(offset) != int(slot) * 4
                or not isinstance(abi, Mapping)
                or abi.get("template")
                not in {"pe32-cdecl-v1", "pe32-stdcall-v1"}
                or not isinstance(argument_words, int)
                or isinstance(argument_words, bool)
                or not 1 <= argument_words <= 64
            ):
                return None
            result.add((
                "protocol",
                profile_sha256,
                interface_id,
                int(slot),
                method,
            ))
            continue
        imported = raw.get("import", raw)
        if not isinstance(imported, Mapping):
            return None
        dll = imported.get("dll")
        symbol = imported.get("symbol")
        ordinal = imported.get("ordinal")
        has_symbol = isinstance(symbol, str) and bool(symbol)
        has_ordinal = _is_u32(ordinal)
        if not isinstance(dll, str) or not dll or has_symbol == has_ordinal:
            return None
        result.add((
            dll.lower(),
            "symbol" if has_symbol else "ordinal",
            str(symbol) if has_symbol else int(ordinal),
        ))
    return tuple(sorted(result))


def canonical_indirect_external_targets(
    record: Mapping[str, Any],
) -> tuple[tuple[Any, ...], ...] | None:
    """Validate and canonicalize every external alternative fail closed."""

    return _indirect_external_targets(record)


def _canonical_import_identity(value: Any) -> tuple[Any, ...] | None:
    if not isinstance(value, Mapping):
        return None
    dll = value.get("dll")
    symbol = value.get("symbol")
    ordinal = value.get("ordinal")
    has_symbol = isinstance(symbol, str) and bool(symbol)
    has_ordinal = _is_u32(ordinal)
    if not isinstance(dll, str) or not dll or has_symbol == has_ordinal:
        return None
    return (
        dll.lower(),
        "symbol" if has_symbol else "ordinal",
        str(symbol) if has_symbol else int(ordinal),
    )


def _profile_identity(profile_id: Any, profile_sha256: Any) -> bool:
    return (
        isinstance(profile_id, str)
        and bool(profile_id)
        and isinstance(profile_sha256, str)
        and len(profile_sha256) == 64
        and all(character in "0123456789abcdef" for character in profile_sha256)
    )


def _operation_environment_contract(
    value: Any,
    *,
    contract_id: Any,
    argument_words: Any,
) -> bool:
    if not isinstance(value, Mapping) or not isinstance(argument_words, int):
        return False
    try:
        contract = parse_external_operation_contract(value)
    except ExternalOperationProfileError:
        return False
    if contract.contract_id != contract_id:
        return False
    if contract.status != "complete":
        return False
    for footprint in contract.memory_footprints:
        if footprint.base_argument >= argument_words:
            return False
        size_argument = getattr(footprint.size, "argument_index", None)
        if size_argument is not None and size_argument >= argument_words:
            return False
    return all(
        effect.argument_index is None
        or effect.argument_index < argument_words
        for effect in contract.world_effects
    )


def _operation_selectors(value: Any, operation_id: str) -> bool:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes))
        or not value
    ):
        return False
    keys: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping) or raw.get("operation_id") != operation_id:
            return False
        kind = raw.get("kind")
        if kind == "direct_import":
            imported = raw.get("import")
            if not isinstance(imported, Mapping):
                return False
            dll = imported.get("dll")
            symbol = imported.get("symbol")
            ordinal = imported.get("ordinal")
            if (
                not isinstance(dll, str)
                or not dll
                or (isinstance(symbol, str) and bool(symbol)) == _is_u32(ordinal)
            ):
                return False
        elif kind == "table_slot":
            if (
                not isinstance(raw.get("view_id"), str)
                or not raw.get("view_id")
                or not _is_u32(raw.get("slot"))
            ):
                return False
        elif kind == "resolver_result":
            if any(
                not isinstance(raw.get(field), str) or not raw.get(field)
                for field in ("resolver_operation_id", "result_id")
            ):
                return False
        elif kind == "callback":
            if not isinstance(raw.get("callback_id"), str) or not raw.get("callback_id"):
                return False
        else:
            return False
        canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"))
        if canonical in keys:
            return False
        keys.add(canonical)
    return True


def _frontier(
    record: Mapping[str, Any],
    source: str,
    reason: str,
    *,
    exit_id: str | None = None,
) -> dict[str, Any]:
    identity = exit_id or _stable_id(
        "frontier",
        {
            "source_unit_id": source,
            "kind": record.get("kind"),
            "reason": reason,
            "source_rva": record.get("source_rva"),
            "source_event_index": record.get("source_event_index"),
            "target_rva": record.get("target_rva"),
            "target_expression": record.get("target_expression"),
        },
    )
    result = {
        "id": identity,
        "source_unit_id": source,
        "kind": str(record.get("kind", "indirect")),
        "reason": reason,
    }
    for field in ("source_rva", "source_event_index", "target_rva"):
        if _is_u32(record.get(field)):
            result[field] = int(record[field])
    if "target_expression" in record:
        result["target_expression"] = copy.deepcopy(record["target_expression"])
    failure = record.get("failure")
    if isinstance(failure, Mapping):
        result["failure"] = copy.deepcopy(dict(failure))
    return result


def _strongly_connected_components(graph: Mapping[str, Sequence[str]]) -> list[tuple[str, ...]]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for successor in sorted(graph[node]):
            if successor not in indices:
                visit(successor)
                lowlinks[node] = min(lowlinks[node], lowlinks[successor])
            elif successor in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[successor])
        if lowlinks[node] == indices[node]:
            component = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            components.append(tuple(sorted(component)))

    for node in sorted(graph):
        if node not in indices:
            visit(node)
    return sorted(components)


def _append_bounded_chain_groups(
    start: str,
    predecessors: Mapping[str, Sequence[str]],
    successors: Mapping[str, Sequence[str]],
    visited: set[str],
    limit: int,
    groups: list[tuple[str, tuple[str, ...]]],
) -> None:
    current = start
    chunk: list[str] = []
    while current not in visited:
        visited.add(current)
        chunk.append(current)
        if len(chunk) == limit:
            groups.append(("straight_line_chain", tuple(chunk)))
            chunk = []
        outgoing = successors[current]
        if len(outgoing) != 1:
            break
        following = outgoing[0]
        if len(predecessors[following]) != 1 or following in visited:
            break
        current = following
    if chunk:
        groups.append(("straight_line_chain", tuple(chunk)))


def _binary_operands(expression: Any, expected_op: str) -> tuple[Any, Any] | None:
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op", "")).lower()
    aliases = {
        "add32": "add",
        "multiply": "mul",
        "mul32": "mul",
        "shl": "shift_left",
        "shl32": "shift_left",
    }
    if aliases.get(op, op) != aliases.get(expected_op, expected_op):
        return None
    if "left" in expression and "right" in expression:
        return expression["left"], expression["right"]
    arguments = expression.get("args")
    if (
        isinstance(arguments, Sequence)
        and not isinstance(arguments, (str, bytes))
        and len(arguments) == 2
    ):
        return arguments[0], arguments[1]
    return None


def _constant_value(expression: Any) -> int | None:
    if isinstance(expression, int) and not isinstance(expression, bool):
        return expression
    if not isinstance(expression, Mapping) or str(expression.get("op", "")).lower() not in {
        "constant",
        "const",
    }:
        return None
    value = expression.get("value")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _index_register(expression: Mapping[str, Any]) -> str | None:
    op = str(expression.get("op", "")).lower()
    if op in _REGISTER_OPS:
        value = expression.get("reg", expression.get("name"))
        return str(value).lower() if value is not None else None
    if op == "and32":
        operands = _binary_operands(expression, "and32")
        if operands is None:
            return None
        for register_expression, mask_expression in (operands, reversed(operands)):
            register = (
                _index_register(register_expression)
                if isinstance(register_expression, Mapping)
                else None
            )
            mask = _constant_value(mask_expression)
            if register is None:
                continue
            if mask == 0xFF and register in {"eax", "ebx", "ecx", "edx"}:
                return {"eax": "al", "ebx": "bl", "ecx": "cl", "edx": "dl"}[
                    register
                ]
            if mask == 0xFFFF and register in {"eax", "ebx", "ecx", "edx"}:
                return {"eax": "ax", "ebx": "bx", "ecx": "cx", "edx": "dx"}[
                    register
                ]
    return None


def _instruction_register(operand: Any) -> str | None:
    if not isinstance(operand, Mapping) or operand.get("kind") != "register":
        return None
    value = operand.get("name")
    return str(value).lower() if value is not None else None


def _instruction_immediate(operand: Any) -> int | None:
    if not isinstance(operand, Mapping) or operand.get("kind") != "immediate":
        return None
    value = operand.get("value")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _same_expression(left: Any, right: Any) -> bool:
    return _normalized_expression(left) == _normalized_expression(right)


def _normalized_expression(value: Any) -> Any:
    if isinstance(value, Mapping):
        op = str(value.get("op", "")).lower()
        if op in {"constant", "const"}:
            return ("constant", _constant_value(value))
        if op in _REGISTER_OPS:
            return ("register", _index_register(value))
        return tuple(
            sorted(
                (str(key), _normalized_expression(item))
                for key, item in value.items()
            )
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(_normalized_expression(item) for item in value)
    return value


def _is_u32(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFFFFFF


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _canonical_mapping_key(value: Any) -> str:
    if not isinstance(value, Mapping):
        return _canonical_json({"invalid": str(type(value).__name__)})
    return _canonical_json(value)


def _stable_id(prefix: str, value: Mapping[str, Any]) -> str:
    return f"{prefix}:{sha256(_canonical_json(value).encode('utf-8')).hexdigest()[:16]}"


def _deduplicate_mappings(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_key = {_canonical_json(value): copy.deepcopy(dict(value)) for value in values}
    return [by_key[key] for key in sorted(by_key)]


def _deduplicate_frontiers(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for value in sorted(values, key=_canonical_mapping_key):
        identity = str(value["id"])
        current = by_id.setdefault(identity, {})
        for key, item in value.items():
            if key not in current:
                current[key] = copy.deepcopy(item)
    return [by_id[identity] for identity in sorted(by_id)]


# The longer names are the preferred API; these aliases keep call sites terse.
recover_static_pe32_indexed_jump_table = recover_static_pe32_jump_table_inventory
derive_rooted_reachability = derive_rooted_reachable_units


__all__ = [
    "derive_rooted_reachability",
    "derive_rooted_reachable_units",
    "pe32_jump_table_index_expression",
    "propose_semantic_clusters",
    "recover_static_pe32_indexed_jump_table",
    "recover_static_pe32_jump_table_inventory",
]
