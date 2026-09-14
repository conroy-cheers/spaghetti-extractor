"""Non-authorizing continuation review using the existing dependency graph.

No synthetic transfer or undefined-value receipt is introduced. A complete
graph still needs local semantic proofs and every recorded call obligation.
"""

from collections.abc import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .definedness import (
    DefinednessAnalysisError, _FLAG_NAMES, _REGISTER_NAMES, _Location,
    _build_dependency_graph, _build_nodes,
)


def analyze_entry_state_dependencies(
    rows: Sequence[Mapping], *, entry_unit_ids: Sequence[str],
    locations: Sequence[Mapping], max_states: int = 256,
) -> dict:
    """Plan the obligations for arbitrary differences in named input locations.

    This is a conservative whole-register analysis. It cannot authorize ignoring
    a register, a flag, memory, or any other part of the machine state.
    """
    if type(max_states) is not int or max_states <= 0:
        raise DefinednessAnalysisError("entry dependency state budget must be positive")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)) or any(
        not isinstance(row, Mapping) for row in rows
    ):
        raise DefinednessAnalysisError("entry dependencies require semantic transfer rows")
    if (not isinstance(entry_unit_ids, Sequence) or isinstance(entry_unit_ids, (str, bytes))
            or not entry_unit_ids or any(not isinstance(unit, str) or not unit for unit in entry_unit_ids)
            or len(set(entry_unit_ids)) != len(entry_unit_ids)):
        raise DefinednessAnalysisError("entry dependency roots must be unique unit identities")
    if not isinstance(locations, Sequence) or isinstance(locations, (str, bytes)) or not locations:
        raise DefinednessAnalysisError("entry dependency locations must be nonempty")
    parsed = []
    for location in locations:
        if not isinstance(location, Mapping) or set(location) != {"family", "name"}:
            raise DefinednessAnalysisError("entry dependency location fields are invalid")
        family, name = location["family"], location["name"]
        allowed = _REGISTER_NAMES if family == "register" else _FLAG_NAMES if family == "flag" else ()
        if not isinstance(name, str) or name not in allowed:
            raise DefinednessAnalysisError("entry dependency location is unsupported")
        parsed.append(_Location(family, name))
    if len(set(parsed)) != len(parsed):
        raise DefinednessAnalysisError("entry dependency locations are duplicated")
    materialized = sorted(rows, key=lambda row: str(row.get("id", "")))
    nodes, by_rva, duplicate_ids, duplicate_rvas = _build_nodes(materialized)
    entries = sorted(entry_unit_ids)
    if any(unit in duplicate_ids or unit not in nodes for unit in entries):
        raise DefinednessAnalysisError("entry dependency root is absent or ambiguous")
    input_digest = canonical_sha256_v3(materialized)
    # Bind the query to its actual inputs. This ID cannot coincide with a
    # supplied undefined-value ID without a self-referential digest preimage.
    query_id = "entry-state-dependencies:" + input_digest
    graph, blockers, obligations, sites = _build_dependency_graph(
        query_id, entries, nodes=nodes, nodes_by_rva=by_rva,
        duplicate_rvas=duplicate_rvas, max_states=max_states,
        synchronized=False, initial_live=frozenset(parsed),
    )
    return {
        "authority": False,
        "analysis_kind": "entry-state-dependencies",
        "semantic_transfers_sha256": input_digest,
        "entry_unit_ids": entries,
        "locations": [location.payload() for location in sorted(parsed)],
        "analysis_complete": not blockers,
        "classification": "unknown" if blockers else "requires_semantic_proof",
        "policy": {"whole_register_dependencies": True, "synthetic_transfers": False,
                   "local_dependency_soundness_required": True, "call_obligations_must_be_discharged": True},
        "graph": graph,
        "blocking_paths": blockers,
        "proof_obligations": obligations,
        "behavior_relevant_sites": sites,
    }
