"""Rooted reachability, overlap classification, and external targets."""

from __future__ import annotations

import copy
import json
from collections import deque
from typing import Any, Mapping, Sequence

from ..external.operation_profiles import (
    ExternalOperationProfileError,
    parse_external_operation_contract,
)
from ..external.machine_abi import resolve_machine_call_abi
from .control_common import (
    _deduplicate_frontiers,
    _deduplicate_mappings,
    _is_u32,
    _stable_id,
)


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
        "format": "spaghetti-extractor-overlapping-instruction-start-classification-v1",
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
