"""Bounded, non-authorizing navigation over canonical direct call sites."""

from collections import Counter
from collections.abc import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .definedness import DefinednessAnalysisError, _build_nodes


def direct_caller_sites(rows: Sequence[Mapping], *, entry_unit_ids: Sequence[str],
                        max_sites: int = 64) -> dict:
    """Inventory direct calls in the supplied universe, without inferring owners.

    Indirect calls, callbacks, incoming host entries and direct tail branches
    are not resolved by this query. Neither an empty inventory nor a complete
    scan proves an entry unreachable or its caller preconditions satisfied.
    """
    if type(max_sites) is not int or not 1 <= max_sites <= 4096:
        raise DefinednessAnalysisError("caller site budget must be between 1 and 4096")
    if (not isinstance(rows, Sequence) or isinstance(rows, (str, bytes))
            or any(not isinstance(row, Mapping) for row in rows)):
        raise DefinednessAnalysisError("caller query requires semantic transfer rows")
    if (not isinstance(entry_unit_ids, Sequence) or isinstance(entry_unit_ids, (str, bytes))
            or not entry_unit_ids or any(not isinstance(unit, str) or not unit for unit in entry_unit_ids)
            or len(set(entry_unit_ids)) != len(entry_unit_ids)):
        raise DefinednessAnalysisError("caller query roots must be unique unit identities")
    materialized = sorted(rows, key=lambda row: str(row.get("id", "")))
    nodes, _, duplicate_ids, duplicate_rvas = _build_nodes(materialized)
    if duplicate_ids:
        raise DefinednessAnalysisError("caller query contains duplicate unit identities")
    entries = sorted(entry_unit_ids)
    if any(unit not in nodes or nodes[unit].rva_start is None
           or nodes[unit].rva_start in duplicate_rvas for unit in entries):
        raise DefinednessAnalysisError("caller query root is absent or ambiguous")
    targets = {nodes[unit].rva_start: unit for unit in entries}
    sites = []
    kinds = Counter()
    for node in nodes.values():
        events = node.row.get("external_events")
        if not isinstance(events, list) or any(not isinstance(event, Mapping) for event in events):
            raise DefinednessAnalysisError("caller query call inventory is malformed")
        for index, event in enumerate(events):
            kind = event.get("kind")
            if not isinstance(kind, str) or not kind:
                raise DefinednessAnalysisError("caller query call kind is malformed")
            kinds[kind] += 1
            if kind != "internal_call":
                continue
            target = event.get("target_rva")
            instruction = event.get("instruction_rva")
            original = node.row.get("original", {})
            if (type(target) is not int or not 0 < target <= 0xFFFFFFFF
                    or type(instruction) is not int or node.rva_start is None
                    or not isinstance(original, Mapping)
                    or type(original.get("rva_end")) is not int
                    or not node.rva_start <= instruction < original.get("rva_end", 0)):
                raise DefinednessAnalysisError("caller query direct call location is malformed")
            if target not in targets:
                continue
            sites.append({
                "callee_unit_id": targets[target], "callee_rva": target,
                "caller_unit_id": node.transfer_id, "instruction_rva": instruction,
                "event_index": index, "json_pointer": f"/external_events/{index}",
                "source_span": dict(original),
                "source_contract_sha256": node.row.get("contract_sha256"),
                "caller_transfer_sha256": canonical_sha256_v3(node.row),
                "call_sha256": canonical_sha256_v3(event),
                "caller_rva_ambiguous": node.rva_start in duplicate_rvas,
                "caller_transfer_status": node.row.get("status"),
                "input_expressions": {key: event.get(key) for key in
                    ("register_inputs", "flag_inputs", "stack_inputs")},
                "return_rva": event.get("return_rva"),
            })
    sites.sort(key=lambda site: (site["callee_unit_id"], site["instruction_rva"],
                                site["caller_unit_id"], site["event_index"]))
    complete = len(sites) <= max_sites
    return {
        "authority": False, "analysis_kind": "direct-caller-sites",
        "semantic_transfers_sha256": canonical_sha256_v3(materialized),
        "entry_unit_ids": entries, "analysis_complete": complete,
        "classification": "direct_call_sites_only", "caller_set_complete": False,
        "total_direct_sites": len(sites), "sites": sites[:max_sites],
        "truncated": not complete, "max_sites": max_sites,
        "input_call_kinds": dict(sorted(kinds.items())),
        "unresolved_indirect_site_count": kinds["indirect_call"],
        "policy": {"supplied_universe_only": True, "reachability_inferred": False,
                   "indirect_targets_resolved": False, "callbacks_resolved": False,
                   "host_entries_resolved": False, "tail_branches_included": False,
                   "caller_ownership_proved": False},
        "next_action": "Inspect these caller inputs and incoming control; prove origin, lifetime and intervening call contracts before consuming caller preconditions.",
    }
