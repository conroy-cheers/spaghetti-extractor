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


RvaReader = Callable[[int, int], bytes]

_UNSIGNED_LESS_OPS = frozenset(
    {"unsigned_less", "unsigned_lt", "ult", "ult32"}
)
_UNSIGNED_LESS_EQUAL_OPS = frozenset(
    {"unsigned_less_equal", "unsigned_le", "ule", "ule32"}
)
_REGISTER_OPS = frozenset({"input_reg", "reg", "register"})


def recover_static_pe32_jump_table_inventory(
    *,
    target_expression: Mapping[str, Any],
    predecessor_evidence: Sequence[Mapping[str, Any]],
    image_base: int,
    sections: Sequence[Mapping[str, Any] | Any],
    read_rva: RvaReader,
    valid_target_rvas: Iterable[int] | None = None,
    max_entries: int = 4096,
) -> dict[str, Any]:
    """Recover one immutable PE32 absolute-pointer jump-table inventory.

    Supported target expressions are a 32-bit load from ``base + index * 4``;
    multiplication by four and a left shift by two are treated identically.
    Every incoming predecessor must establish the same unsigned upper bound.
    Guard expressions are preferred, while typed ``cmp``/unsigned-jcc evidence
    can independently establish or cross-check the bound.

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

    evidence_rows: list[dict[str, Any]] = []
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
            _guard_upper_exclusive(guard, index_expression)
            if guard is not None
            else None
        )
        instruction_bound = _instruction_upper_exclusive(row, index_expression)
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
                "an incoming predecessor does not prove a supported unsigned bound",
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
                    row.get("source_unit_id", row.get("unit_id", f"predecessor:{ordinal}"))
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
    upper_exclusive = next(iter(bounds))
    if upper_exclusive <= 0 or upper_exclusive > max_entries:
        return _table_failure(
            kind,
            "invalid_index_bound",
            "recovered index bound is empty or exceeds the resolver cap",
        )

    table_resolution = _resolve_section_address(
        table_address,
        image_base=image_base,
        sections=sections,
        size=upper_exclusive * 4,
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

    byte_count = upper_exclusive * 4
    try:
        table_bytes = read_rva(table_rva, byte_count)
    except Exception:
        return _table_failure(
            kind,
            "unreadable_table",
            "jump-table bytes could not be read",
        )
    if not isinstance(table_bytes, bytes) or len(table_bytes) != byte_count:
        return _table_failure(
            kind,
            "unreadable_table",
            "jump-table reader did not return the exact requested bytes",
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
    for index in range(upper_exclusive):
        raw = table_bytes[index * 4 : index * 4 + 4]
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
                "entry_rva": table_rva + index * 4,
                "target_address": target_address,
                "target_address_model": target_address_model,
                "target_rva": target_rva,
                "target_section": _section_name(target_section),
            }
        )

    target_rvas = sorted({int(entry["target_rva"]) for entry in entries})
    return {
        "status": "recovered",
        "closure": "checked_finite_target_inventory",
        "kind": kind,
        "index": {
            "expression": copy.deepcopy(dict(index_expression)),
            "lower_inclusive": 0,
            "upper_exclusive": upper_exclusive,
            "bound_evidence": sorted(
                evidence_rows,
                key=lambda row: (row["source_unit_id"], row["upper_exclusive"]),
            ),
        },
        "table": {
            "address": table_address,
            "address_model": address_model,
            "expression_form": expression_form,
            "rva_start": table_rva,
            "rva_end": table_rva + byte_count,
            "entry_width": 4,
            "entry_count": upper_exclusive,
            "section": _section_name(table_section),
            "bytes_sha256": sha256(table_bytes).hexdigest(),
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
        if record.get("status") != "recovered" or targets is None or not targets:
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
    if isinstance(raw_ids, Sequence) and not isinstance(raw_ids, (str, bytes)):
        targets = {str(value) for value in raw_ids}
        return tuple(sorted(targets)) if targets and targets <= unit_ids else None
    raw_rvas = record.get("target_rvas")
    if isinstance(raw_rvas, Sequence) and not isinstance(raw_rvas, (str, bytes)):
        result = set()
        for raw_rva in raw_rvas:
            if not _is_u32(raw_rva):
                return None
            matches = rva_index.get(int(raw_rva), set())
            if len(matches) != 1:
                return None
            result.update(matches)
        return tuple(sorted(result)) if result else None
    return None


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
            "target_expression": record.get("target_expression"),
        },
    )
    result = {
        "id": identity,
        "source_unit_id": source,
        "kind": str(record.get("kind", "indirect")),
        "reason": reason,
    }
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
    "propose_semantic_clusters",
    "recover_static_pe32_indexed_jump_table",
    "recover_static_pe32_jump_table_inventory",
]
