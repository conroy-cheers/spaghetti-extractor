"""Shared primitives for the direct Portable-C bisimulation checker."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Mapping


UINT32_BYTES = 4
PROOF_PRIVATE_STACK_BELOW = 1024
PROOF_PRIVATE_STACK_ABOVE = 4096
PROOF_SOURCE_SYNC_STACK_BIAS = 512
PROOF_RELATION_WITNESS = "spx_bisimulation_relation_witness"
ASSERTION_SINGLE_STRATEGY = "inventory_function_grouped_paired_language_safety_with_entry_unwinding_reuse_v11"
ASSERTION_BATCH_STRATEGY = "inventory_function_grouped_paired_language_safety_with_bounded_authored_batches_v12"
PACKED_SAFETY_STRATEGY = "inventory_bounded_safety_groups_with_bounded_authored_batches_v13"
APPLICATION_FIRST_STRATEGY = "inventory_bounded_safety_groups_with_application_first_authored_batches_v14"
CUT_CONTROL_FIRST_STRATEGY = "inventory_bounded_safety_groups_with_cut_control_first_authored_batches_v15"
PACKED_SINGLE_STRATEGY = "inventory_bounded_safety_groups_with_single_authored_assertions_v16"
SINGLE_ASSERTION_STRATEGIES = (ASSERTION_SINGLE_STRATEGY, PACKED_SINGLE_STRATEGY)
ASSERTION_QUERY_STRATEGIES = (ASSERTION_SINGLE_STRATEGY, ASSERTION_BATCH_STRATEGY, PACKED_SAFETY_STRATEGY,
                              APPLICATION_FIRST_STRATEGY, CUT_CONTROL_FIRST_STRATEGY, PACKED_SINGLE_STRATEGY)

_TYPED_BARRIER_PROPERTIES = (
    (
        re.compile(r"spx-bisimulation-typed-call-public-memory:([0-9]+)"),
        "spx_proof_typed_service_begin",
        "typed_call",
    ),
    (
        re.compile(r"spx-bisimulation-typed-call-fields:([0-9]+)"),
        "spx_proof_typed_service_finish",
        "typed_call",
    ),
)


class BisimulationRefinementError(ValueError):
    """The direct exact-C/source-C bisimulation is malformed or inconclusive."""


def unit_rva(unit_id: str) -> int:
    match = re.search(r"-([0-9a-fA-F]{8})-[0-9a-fA-F]{8}$", unit_id)
    if match is None:
        raise BisimulationRefinementError(f"unit {unit_id!r} has no canonical RVA")
    return int(match.group(1), 16)


def include_path(path: Path) -> str:
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


def mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise BisimulationRefinementError(f"{context} must be an object")
    return value


def rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(row, Mapping) for row in value):
        raise BisimulationRefinementError(f"{context} must be an array of objects")
    return list(value)


def strings(value: object, context: str) -> list[str]:
    if not isinstance(value, list) or any(
        not isinstance(row, str) for row in value
    ):
        raise BisimulationRefinementError(f"{context} must be an array of strings")
    return list(value)


def uints(value: object, context: str) -> list[int]:
    if not isinstance(value, list) or any(
        not isinstance(row, int) or isinstance(row, bool) or row < 0
        for row in value
    ):
        raise BisimulationRefinementError(f"{context} must be unsigned integers")
    return list(value)


def property_entry_function(
    *, proof_function: str, description: str, source_function: str
) -> str:
    """Select the checked prefix entry for one typed-barrier assertion."""

    for pattern, expected_source, suffix in _TYPED_BARRIER_PROPERTIES:
        match = pattern.fullmatch(description)
        if match is not None and source_function == expected_source:
            indices = "_".join(match.groups())
            return f"{proof_function}_focus_{suffix}_{indices}"
    return proof_function


def property_query_order(assertion: Mapping[str, object], *, strategy=PACKED_SAFETY_STRATEGY) -> tuple[int, str]:
    """Schedule control disagreements before unchanged descriptor metadata."""

    description = str(assertion.get("description", ""))
    if description.startswith("spx-bisimulation-call-completion:"):
        return -2, str(assertion.get("property_id", ""))
    if strategy in (APPLICATION_FIRST_STRATEGY, CUT_CONTROL_FIRST_STRATEGY):
        # Normal source paths stop at cuts; the root exit assertion can cover
        # only residual faults. A timeout there must not hide a wrong successor.
        # V14 keeps its original order so previous bound queries remain readable.
        if strategy == CUT_CONTROL_FIRST_STRATEGY and description.startswith("spx-bisimulation-sync-alignment:"):
            return -1, str(assertion.get("property_id", ""))
        # Keep observable disagreement ahead of unchanged descriptor metadata.
        # This is scheduling only: every assertion and safety gate is retained.
        prefixes = (
            ("spx-bisimulation-exit-control:",),
            ("spx-bisimulation-exit-target:", "spx-bisimulation-exit-value:"),
            ("spx-bisimulation-exit-observable:", "spx-bisimulation-exit-world-memory:",
             "spx-bisimulation-exit-world-calls:", "spx-bisimulation-exit-world-atomics:"),
            ("spx-bisimulation-capture-reference-memory:",),
            ("spx-bisimulation-capture-methods:", "spx-bisimulation-capture-metadata:",
             "spx-bisimulation-capture-context:", "spx-bisimulation-capture-extent:"),
        )
        priority = next((i for i, names in enumerate(prefixes) if description.startswith(names)), len(prefixes))
        return priority, str(assertion.get("property_id", ""))
    priority = (
        0
        if description.startswith(("spx-bisimulation-exit-control:", "spx-bisimulation-capture-methods:",
                                   "spx-bisimulation-capture-metadata:", "spx-bisimulation-capture-context:",
                                   "spx-bisimulation-capture-extent:"))
        else 1
        if description.startswith((
            "spx-bisimulation-exit-target:",
            "spx-bisimulation-exit-value:",
        ))
        else 2
        if description.startswith("spx-bisimulation-exit-observable:")
        else 3
    )
    return priority, str(assertion.get("property_id", ""))


def assertion_policy_option(models):
    try:
        strategies = {segment['property_checker_command']['strategy']
            for operation in models['operation_models'] for segment in operation['obligation_models']}
    except (KeyError, TypeError):
        return None
    if len(strategies) != 1 or not strategies <= set(ASSERTION_QUERY_STRATEGIES):
        return None
    return ('authored-assertions=bounded-groups-formula-sliced' if not strategies.intersection(SINGLE_ASSERTION_STRATEGIES)
            else 'authored-assertions=per-property-formula-sliced')


def authored_query_ids(query, strategy, assertions):
    """Check exact selected IDs and one shared entry/source owner per process."""
    batched = strategy in (ASSERTION_BATCH_STRATEGY, PACKED_SAFETY_STRATEGY, APPLICATION_FIRST_STRATEGY,
                           CUT_CONTROL_FIRST_STRATEGY)
    field = 'property_ids' if batched else 'property_id'
    keys = {'kind', field, 'entry_function', 'status', 'code', 'properties', 'output_sha256'}
    if strategy not in ASSERTION_QUERY_STRATEGIES or set(query) not in (keys, keys | {'detail'}):
        return None
    identities = query.get(field) if batched else [query.get(field)]
    if (not isinstance(identities, list) or not 1 <= len(identities) <= (4 if batched else 1)
            or any(not isinstance(item, str) or item not in assertions for item in identities)
            or len(identities) != len(set(identities))
            or any(assertions[item]['entry_function'] != query.get('entry_function') for item in identities)
            or len({assertions[item]['source_function'] for item in identities}) != 1
            or (query.get('status') == 'satisfied' and query.get('properties') != len(identities))):
        return None
    return identities


def safety_property_groups(partition, property_ids, inventory, *, strategy=ASSERTION_BATCH_STRATEGY):
    """Partition safety IDs under the bound policy without changing coverage.

    Every group runs on the same model and paired entry. V13 packs sorted IDs
    into bounded groups across helper owners, avoiding a fresh symbolic run for
    every small helper. Legacy receipts retain their original grouping. Keep
    unwinding whole: its baseline has a different property-ID domain.
    """
    if strategy not in ASSERTION_QUERY_STRATEGIES:
        raise ValueError('unknown safety grouping strategy')
    if not property_ids:
        return []
    if partition == "unwinding" or len(property_ids) <= 1024:
        return [list(property_ids)]
    if strategy in (PACKED_SAFETY_STRATEGY, APPLICATION_FIRST_STRATEGY, CUT_CONTROL_FIRST_STRATEGY, PACKED_SINGLE_STRATEGY):
        return [list(property_ids[offset:offset + 1024]) for offset in range(0, len(property_ids), 1024)]
    owners = {row["property_id"]: row["source_function"] for row in inventory}
    groups: dict[str, list[str]] = {}
    for property_id in property_ids:
        groups.setdefault(owners[property_id], []).append(property_id)
    return [sorted(groups[owner]) for owner in sorted(groups)]


def safety_group_refinement(actual, expected, *, complete=True):
    """Check canonical subdivisions, allowing unfinished groups in diagnostics.

    Incomplete runs may stop inside a group while other already-started groups
    finish. Each started group still has an ordered, nonempty prefix. Successful
    proofs must cover every group and every ID without gaps.
    """
    group, offset = 0, 0
    for partition, identities in actual:
        if group >= len(expected) or not isinstance(identities, list) or not identities:
            return False
        expected_partition, expected_ids = expected[group]
        if (not complete and offset and
                (partition != expected_partition or
                 identities != expected_ids[offset:offset + len(identities)])):
            group, offset = group + 1, 0
            if group >= len(expected):
                return False
            expected_partition, expected_ids = expected[group]
        if (partition != expected_partition or
                identities != expected_ids[offset:offset + len(identities)] or
                (partition == "unwinding" and identities != expected_ids)):
            return False
        offset += len(identities)
        if offset == len(expected_ids):
            group, offset = group + 1, 0
    return not complete or (group == len(expected) and offset == 0)


__all__ = [
    "BisimulationRefinementError",
    "PROOF_PRIVATE_STACK_ABOVE",
    "PROOF_PRIVATE_STACK_BELOW",
    "PROOF_RELATION_WITNESS",
    "PROOF_SOURCE_SYNC_STACK_BIAS",
    "UINT32_BYTES",
    "include_path",
    "mapping",
    "property_entry_function",
    "property_query_order",
    "safety_property_groups",
    "safety_group_refinement",
    "rows",
    "strings",
    "uints",
    "unit_rva",
]


def typed_call_focus_source(name: str, max_calls: int) -> list[str]:
    """Use the normal proof entry, stopping after the selected typed interaction."""
    return [line for position in range(max_calls) for line in (
        f"void {name}_focus_typed_call_{position}(void) {{",
        "  spx_proof_property_focus_kind = UINT32_C(1);",
        f"  spx_proof_property_focus_position = UINT32_C({position});",
        f"  {name}();", "}", "",
    )]
