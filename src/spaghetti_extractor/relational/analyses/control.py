from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from ...stage_binary import StageABinary, StageAInputError
from ..extraction import _assembled_u32_after_register_writes
from ..model import _semantic_constant_bool
from ..schema import RELATIONAL_ACCEPTANCE_THEOREM, integer as _integer
from .invariants import _semantic_edges


def _relational_product_graph(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    *,
    original_image_base: int,
    candidate_image_base: int,
    indirect_call_candidates: list[dict[str, Any]] | None = None,
    dynamic_call_candidates: list[dict[str, Any]] | None = None,
    import_register_seeds: list[dict[str, Any]] | None = None,
    import_call_candidates: list[dict[str, Any]] | None = None,
    external_call_candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    targets_by_region: dict[int, list[dict[str, Any]]] = {}
    for target in contract.get("code_targets", []):
        targets_by_region.setdefault(int(target["region_index"]), []).append(target)

    node_targets: list[dict[str, Any]] = []
    for region_index, region in enumerate(contract.get("regions", [])):
        matching = [
            target for target in targets_by_region.get(region_index, [])
            if int(target["original_rva"]) == int(region["original"]["rva_start"])
            and int(target["candidate_rva"]) == int(region["candidate"]["rva_start"])
        ]
        if len(matching) != 1:
            raise StageAInputError(
                f"region {region.get('id', region_index)} has {len(matching)} canonical "
                "product-graph cutpoint targets"
            )
        node_targets.append(matching[0])

    edges: list[dict[str, Any]] = []
    outgoing: list[list[int]] = [[] for _ in node_targets]
    kind_names = {
        "jump": "jump",
        "branch_taken": "branchTaken",
        "branch_fallthrough": "branchFallthrough",
        "branch_converged": "jump",
        "call": "call",
        "call_return": "callReturn",
        "bulk_copy": "bulkCopy",
        "external_call": "externalCall",
        "checked_continue": "checkedContinue",
        "atomic_compare_exchange": "atomicCompareExchange",
    }
    for edge_id, relation_edge in enumerate(register_relations.get("edges", [])):
        source = int(relation_edge["source_region_index"])
        target = int(relation_edge["target_region_index"])
        kind = kind_names.get(str(relation_edge.get("kind")))
        if kind is None:
            raise StageAInputError(
                f"unsupported relational product edge kind {relation_edge.get('kind')!r}"
            )
        if not (0 <= source < len(node_targets) and 0 <= target < len(node_targets)):
            raise StageAInputError(f"product edge {edge_id} has an out-of-range node")
        outgoing[source].append(edge_id)
        edges.append({
            "id": edge_id,
            "source_node_id": source,
            "target_node_id": target,
            "source_target_id": int(node_targets[source]["id"]),
            "target_target_id": int(node_targets[target]["id"]),
            "kind": kind,
            "original_guard": relation_edge["original_guard"],
            "candidate_guard": relation_edge["candidate_guard"],
            "infeasible": (
                _semantic_constant_bool(relation_edge["original_guard"]) is False
                and _semantic_constant_bool(relation_edge["candidate_guard"]) is False
            ),
        })

    def code_target_guard(
        expression: dict[str, Any], image_base: int, primary_rva: int,
        aliases: list[int],
    ) -> dict[str, Any]:
        guard: dict[str, Any] = {
            "op": "equal",
            "left": expression,
            "right": {"op": "constant", "value": image_base + primary_rva},
        }
        for alias_rva in reversed(aliases):
            guard = {
                "op": "or",
                "left": {
                    "op": "equal",
                    "left": expression,
                    "right": {
                        "op": "constant",
                        "value": image_base + int(alias_rva),
                    },
                },
                "right": guard,
            }
        return guard

    dynamic_edge_groups: list[dict[str, Any]] = []
    dynamic_sources: set[int] = set()
    for candidate_index, dynamic_candidate in enumerate(
        dynamic_call_candidates or []
    ):
        source = int(dynamic_candidate["source_region_index"])
        if source in dynamic_sources:
            raise StageAInputError(
                f"product node {source} has duplicate dynamic indirect-call claims"
            )
        dynamic_sources.add(source)
        if not 0 <= source < len(node_targets):
            raise StageAInputError(
                f"dynamic indirect-call source {source} is out of range"
            )
        if outgoing[source]:
            raise StageAInputError(
                f"dynamic indirect-call source {source} already has submitted edges"
            )
        shape = _dynamic_range_indirect_call_shape(behaviors[source])
        if shape is None:
            raise StageAInputError(
                f"dynamic indirect-call source {source} no longer has the checked shape"
            )
        original_register, candidate_register, word_offset, continuation = shape
        relation = dynamic_candidate["range_relation"]
        if (
            str(relation.get("original")) != original_register
            or str(relation.get("candidate")) != candidate_register
            or int(dynamic_candidate["word_offset"]) != word_offset
            or int(dynamic_candidate["continuation_target_id"]) != continuation
        ):
            raise StageAInputError(
                f"dynamic indirect-call source {source} claim does not match decoded control"
            )
        original_expression = behaviors[source]["original_ir"]["outcome"]["target"]
        candidate_expression = behaviors[source]["candidate_ir"]["outcome"]["target"]
        edge_ids: list[int] = []
        for target_node_id, target in enumerate(node_targets):
            edge_id = len(edges)
            edge_ids.append(edge_id)
            outgoing[source].append(edge_id)
            edges.append({
                "id": edge_id,
                "source_node_id": source,
                "target_node_id": target_node_id,
                "source_target_id": int(node_targets[source]["id"]),
                "target_target_id": int(target["id"]),
                "kind": "call",
                "original_guard": code_target_guard(
                    original_expression,
                    original_image_base,
                    int(target["original_rva"]),
                    [int(alias) for alias in target.get("original_aliases", [])],
                ),
                "candidate_guard": code_target_guard(
                    candidate_expression,
                    candidate_image_base,
                    int(target["candidate_rva"]),
                    [int(alias) for alias in target.get("candidate_aliases", [])],
                ),
                "infeasible": False,
                "dynamic_indirect_call_candidate_index": candidate_index,
            })
        dynamic_edge_groups.append({
            "source_node_id": source,
            "candidate_index": candidate_index,
            "edge_ids": edge_ids,
        })

    root_node_ids = [
        index for index, region in enumerate(contract.get("regions", []))
        if bool(region.get("root"))
    ]
    proved_edge_ids = sorted(int(candidate["edge_index"]) for candidate in segment_candidates)
    complete = proved_edge_ids == list(range(len(edges)))
    nodes = [
        {
            "id": index,
            "target_id": int(node_targets[index]["id"]),
            "root": index in root_node_ids,
            "outgoing_edge_ids": outgoing[index],
        }
        for index in range(len(node_targets))
    ]
    region_by_numeric_id = {
        int(region["numeric_id"]): index
        for index, region in enumerate(contract.get("regions", []))
    }
    indirect_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (indirect_call_candidates or [])
    }
    import_call_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (import_call_candidates or [])
    }
    dynamic_call_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (dynamic_call_candidates or [])
    }
    if set(indirect_by_source).intersection(dynamic_call_by_source):
        raise StageAInputError(
            "a product node cannot have both immutable and dynamic indirect-call claims"
        )

    def decoded_control_edges(
        behavior: dict[str, Any],
        indirect_candidate: dict[str, Any] | None,
        dynamic_candidate: dict[str, Any] | None,
        import_call_candidate: dict[str, Any] | None,
        *,
        candidate_side: bool,
    ) -> list[dict[str, Any]] | None:
        outcome = behavior.get("outcome") or {}
        operation = outcome.get("op")
        if (
            operation == "indirect_call"
            and indirect_candidate is not None
            and indirect_candidate["profile"] ==
                "immutable_relocated_function_pointer_call_v1"
        ):
            return [{
                "kind": "call",
                "target_target_id": int(indirect_candidate["target_id"]),
                "guard": {"op": "bool_constant", "value": True},
            }]
        if (
            operation == "indirect_jump"
            and indirect_candidate is not None
            and indirect_candidate["profile"] ==
                "immutable_relocated_function_pointer_jump_v1"
        ):
            return [{
                "kind": "jump",
                "target_target_id": int(indirect_candidate["target_id"]),
                "guard": {"op": "bool_constant", "value": True},
            }]
        if operation == "indirect_call" and import_call_candidate is not None:
            continuation_index = int(
                import_call_candidate["continuation_region_index"]
            )
            return [{
                "kind": "externalCall",
                "target_target_id": int(node_targets[continuation_index]["id"]),
                "guard": {"op": "bool_constant", "value": True},
            }]
        if operation == "indirect_call" and dynamic_candidate is not None:
            expression = outcome["target"]
            image_base = candidate_image_base if candidate_side else original_image_base
            rva_key = "candidate_rva" if candidate_side else "original_rva"
            aliases_key = (
                "candidate_aliases" if candidate_side else "original_aliases"
            )
            return [
                {
                    "kind": "call",
                    "target_target_id": int(target["id"]),
                    "guard": code_target_guard(
                        expression,
                        image_base,
                        int(target[rva_key]),
                        [int(alias) for alias in target.get(aliases_key, [])],
                    ),
                }
                for target in node_targets
            ]
        if operation in {"indirect_call", "indirect_jump", "checked_continue"}:
            return None
        if operation in {"returned", "external_jump"}:
            return []
        decoded: list[dict[str, Any]] = []
        for edge in _semantic_edges(behavior):
            target_index = region_by_numeric_id.get(int(edge["target"]))
            kind = kind_names.get(str(edge.get("kind")))
            if target_index is None or kind is None:
                return None
            decoded.append({
                "kind": kind,
                "target_target_id": int(node_targets[target_index]["id"]),
                "guard": edge["guard"],
            })
        if operation not in {
            "jump",
            "branch",
            "call",
            "external_call",
            "bulk_copy",
            "atomic_compare_exchange",
        }:
            return None
        return decoded

    decoded_control_candidates: list[dict[str, int]] = []
    for node_id, (node, behavior_pair) in enumerate(
        zip(nodes, behaviors, strict=True)
    ):
        indirect_candidate = indirect_by_source.get(node_id)
        dynamic_candidate = dynamic_call_by_source.get(node_id)
        import_call_candidate = import_call_by_source.get(node_id)
        original_decoded = decoded_control_edges(
            behavior_pair["original_ir"], indirect_candidate, dynamic_candidate,
            import_call_candidate, candidate_side=False,
        )
        candidate_decoded = decoded_control_edges(
            behavior_pair["candidate_ir"], indirect_candidate, dynamic_candidate,
            import_call_candidate, candidate_side=True,
        )
        original_graph_decoded = [
            {
                "kind": edges[edge_id]["kind"],
                "target_target_id": edges[edge_id]["target_target_id"],
                "guard": edges[edge_id]["original_guard"],
            }
            for edge_id in node["outgoing_edge_ids"]
        ]
        candidate_graph_decoded = [
            {
                "kind": edges[edge_id]["kind"],
                "target_target_id": edges[edge_id]["target_target_id"],
                "guard": edges[edge_id]["candidate_guard"],
            }
            for edge_id in node["outgoing_edge_ids"]
        ]
        if (
            original_decoded is not None
            and candidate_decoded is not None
            and original_graph_decoded == original_decoded
            and candidate_graph_decoded == candidate_decoded
        ):
            decoded_candidate = {
                "node_id": node_id,
                "region_index": node_id,
                "profile": "direct_decoded_control_v1",
            }
            if indirect_candidate is not None:
                decoded_candidate.update(indirect_candidate)
            if dynamic_candidate is not None:
                decoded_candidate.update(dynamic_candidate)
            if import_call_candidate is not None:
                decoded_candidate.update(import_call_candidate)
                decoded_candidate["continuation_target_id"] = int(
                    node_targets[
                        int(import_call_candidate["continuation_region_index"])
                    ]["id"]
                )
            decoded_control_candidates.append(decoded_candidate)
    decoded_control_complete_node_ids = [
        candidate["node_id"] for candidate in decoded_control_candidates
    ]
    candidates_by_edge = {
        int(candidate["edge_index"]): candidate for candidate in segment_candidates
    }
    coverage_candidates = []
    for node in nodes:
        outgoing_edge_ids = node["outgoing_edge_ids"]
        if len(outgoing_edge_ids) != 1:
            continue
        edge_id = int(outgoing_edge_ids[0])
        edge = edges[edge_id]
        candidate = candidates_by_edge.get(edge_id)
        if (
            candidate is None
            or edge["original_guard"] != {"op": "bool_constant", "value": True}
            or edge["candidate_guard"] != {"op": "bool_constant", "value": True}
        ):
            continue
        coverage_candidates.append({
            "node_id": int(node["id"]),
            "edge_id": edge_id,
            "source_region_index": int(candidate["source_region_index"]),
            "target_region_index": int(candidate["target_region_index"]),
        })
    covered_node_ids = [item["node_id"] for item in coverage_candidates]
    runtime_call_continuations: dict[int, set[int]] = defaultdict(set)
    for relation_edge in register_relations.get("edges", []):
        claim = relation_edge.get("direct_call_push_claim")
        if not isinstance(claim, dict):
            continue
        source_node_id = int(relation_edge["source_region_index"])
        continuation_node_id = int(claim["continuation_region_index"])
        if not (
            0 <= source_node_id < len(nodes)
            and 0 <= continuation_node_id < len(nodes)
        ):
            raise StageAInputError(
                "direct-call continuation references an out-of-range product node"
            )
        runtime_call_continuations[source_node_id].add(continuation_node_id)
    reachable_node_ids_set = set(root_node_ids)
    reachability_worklist = list(root_node_ids)
    worklist_index = 0
    while worklist_index < len(reachability_worklist):
        source_node_id = reachability_worklist[worklist_index]
        worklist_index += 1
        for edge_id in nodes[source_node_id]["outgoing_edge_ids"]:
            if bool(edges[edge_id]["infeasible"]):
                continue
            target_node_id = int(edges[edge_id]["target_node_id"])
            if target_node_id in reachable_node_ids_set:
                continue
            reachable_node_ids_set.add(target_node_id)
            reachability_worklist.append(target_node_id)
        for continuation_node_id in sorted(
            runtime_call_continuations.get(source_node_id, set())
        ):
            if continuation_node_id in reachable_node_ids_set:
                continue
            reachable_node_ids_set.add(continuation_node_id)
            reachability_worklist.append(continuation_node_id)
    declared_reachable_node_ids = sorted(reachable_node_ids_set)
    declared_reachable_bits = [
        node_id in reachable_node_ids_set for node_id in range(len(nodes))
    ]
    reachable_covered_nodes = len(
        reachable_node_ids_set.intersection(covered_node_ids)
    )
    reachable_uncovered_nodes = (
        len(declared_reachable_node_ids) - reachable_covered_nodes
    )
    decoded_control_complete_node_ids_set = set(
        decoded_control_complete_node_ids
    )
    reachable_decoded_control_frontier_node_ids = sorted(
        reachable_node_ids_set - decoded_control_complete_node_ids_set
    )
    declared_reachability_control_closed = not (
        reachable_decoded_control_frontier_node_ids
    )
    potential_reachable_node_ids_set = set(root_node_ids)
    potential_reachability_worklist = list(root_node_ids)
    potential_worklist_index = 0
    potential_control_cuts: list[dict[str, Any]] = []
    potential_control_cut_nodes: set[int] = set()
    while potential_worklist_index < len(potential_reachability_worklist):
        source_node_id = potential_reachability_worklist[
            potential_worklist_index
        ]
        potential_worklist_index += 1
        for edge_id in nodes[source_node_id]["outgoing_edge_ids"]:
            if bool(edges[edge_id]["infeasible"]):
                continue
            target_node_id = int(edges[edge_id]["target_node_id"])
            if target_node_id not in potential_reachable_node_ids_set:
                potential_reachable_node_ids_set.add(target_node_id)
                potential_reachability_worklist.append(target_node_id)
        for continuation_node_id in sorted(
            runtime_call_continuations.get(source_node_id, set())
        ):
            if continuation_node_id in potential_reachable_node_ids_set:
                continue
            potential_reachable_node_ids_set.add(continuation_node_id)
            potential_reachability_worklist.append(continuation_node_id)
        if source_node_id in decoded_control_complete_node_ids_set:
            continue
        behavior_pair = behaviors[source_node_id]
        operations = sorted({
            str((behavior_pair[side].get("outcome") or {}).get("op"))
            for side in ("original_ir", "candidate_ir")
        })
        added_targets: set[int] = set()
        if any(
            operation in {"indirect_call", "indirect_jump", "checked_continue"}
            for operation in operations
        ):
            added_targets.update(range(len(nodes)))
            reason = "unresolved_indirect_control_all_canonical_targets"
        else:
            for side in ("original_ir", "candidate_ir"):
                for semantic_edge in _semantic_edges(behavior_pair[side]):
                    target_index = region_by_numeric_id.get(
                        int(semantic_edge["target"])
                    )
                    if target_index is not None:
                        added_targets.add(target_index)
            reason = "decoded_direct_control_not_represented"
        if source_node_id not in potential_control_cut_nodes:
            potential_control_cut_nodes.add(source_node_id)
            potential_control_cuts.append({
                "node_id": source_node_id,
                "operations": operations,
                "reason": reason,
                "potential_target_count": len(added_targets),
                "target_scope": (
                    "all_canonical_code_targets"
                    if len(added_targets) == len(nodes)
                    else "decoded_target_union"
                ),
            })
        for target_node_id in sorted(added_targets):
            if target_node_id in potential_reachable_node_ids_set:
                continue
            potential_reachable_node_ids_set.add(target_node_id)
            potential_reachability_worklist.append(target_node_id)
    potential_reachable_node_ids = sorted(potential_reachable_node_ids_set)
    potential_reachable_feasible_edge_ids = sorted(
        int(edge["id"])
        for edge in edges
        if int(edge["source_node_id"]) in potential_reachable_node_ids_set
        and not bool(edge["infeasible"])
    )
    potential_unrepresented_control_edges = sum(
        int(cut["potential_target_count"]) for cut in potential_control_cuts
    )
    external_proved_edge_ids = sorted({
        int(candidate["edge_index"])
        for candidate in (external_call_candidates or [])
        if "edge_index" in candidate
    })
    locally_refined_edge_ids = sorted(
        set(proved_edge_ids).union(external_proved_edge_ids)
    )
    reachable_feasible_edge_ids = sorted(
        int(edge["id"])
        for edge in edges
        if int(edge["source_node_id"]) in reachable_node_ids_set
        and not bool(edge["infeasible"])
    )
    locally_refined_edge_ids_set = set(locally_refined_edge_ids)
    reachable_locally_refined_edge_ids = [
        edge_id for edge_id in reachable_feasible_edge_ids
        if edge_id in locally_refined_edge_ids_set
    ]
    reachable_local_refinement_frontier_edge_ids = [
        edge_id for edge_id in reachable_feasible_edge_ids
        if edge_id not in locally_refined_edge_ids_set
    ]
    reachable_product_local_complete = (
        declared_reachability_control_closed
        and not reachable_local_refinement_frontier_edge_ids
    )
    return {
        "format": "stage-a-relational-product-graph-v1",
        "status": "candidate_requires_lean_replay",
        "model": "relational-cutpoint-product-graph-v1",
        "nodes": nodes,
        "edges": edges,
        "root_node_ids": root_node_ids,
        "evidence": {
            "proved_edge_ids": proved_edge_ids,
            "complete": complete,
            "covered_node_ids": covered_node_ids,
            "coverage_candidates": coverage_candidates,
            "declared_reachable_node_ids": declared_reachable_node_ids,
            "declared_reachable_bits": declared_reachable_bits,
            "decoded_control_complete_node_ids": decoded_control_complete_node_ids,
            "decoded_control_candidates": decoded_control_candidates,
            "import_register_seed_candidates": import_register_seeds or [],
            "dynamic_range_indirect_call_candidates": dynamic_call_candidates or [],
            "dynamic_range_indirect_call_edge_groups": dynamic_edge_groups,
            "runtime_call_continuations": [
                {
                    "source_node_id": source_node_id,
                    "continuation_node_ids": sorted(continuation_node_ids),
                }
                for source_node_id, continuation_node_ids in sorted(
                    runtime_call_continuations.items()
                )
            ],
            "reachable_decoded_control_frontier_node_ids": (
                reachable_decoded_control_frontier_node_ids
            ),
            "potential_reachable_node_ids": potential_reachable_node_ids,
            "potential_control_cuts": potential_control_cuts,
            "potential_reachable_feasible_edge_ids": (
                potential_reachable_feasible_edge_ids
            ),
            "external_proved_edge_ids": external_proved_edge_ids,
            "locally_refined_edge_ids": locally_refined_edge_ids,
            "reachable_feasible_edge_ids": reachable_feasible_edge_ids,
            "reachable_locally_refined_edge_ids": (
                reachable_locally_refined_edge_ids
            ),
            "reachable_local_refinement_frontier_edge_ids": (
                reachable_local_refinement_frontier_edge_ids
            ),
            "reachable_product_local_complete": reachable_product_local_complete,
        },
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "roots": len(root_node_ids),
            "proved_edges": len(proved_edge_ids),
            "incomplete_edges": len(edges) - len(proved_edge_ids),
            "covered_nodes": len(covered_node_ids),
            "uncovered_nodes": len(nodes) - len(covered_node_ids),
            "declared_reachable_nodes": len(declared_reachable_node_ids),
            "declared_reachable_covered_nodes": reachable_covered_nodes,
            "declared_reachable_uncovered_nodes": reachable_uncovered_nodes,
            "declared_unreachable_nodes": (
                len(nodes) - len(declared_reachable_node_ids)
            ),
            "potential_reachable_nodes": len(potential_reachable_node_ids),
            "potential_reachable_feasible_edges": len(
                potential_reachable_feasible_edge_ids
            ),
            "potential_unrepresented_control_edges": (
                potential_unrepresented_control_edges
            ),
            "reachability_truncated_by_control_frontier": bool(
                potential_reachable_node_ids_set - reachable_node_ids_set
            ),
            "decoded_control_complete_nodes": len(
                decoded_control_complete_node_ids
            ),
            "decoded_control_incomplete_nodes": (
                len(nodes) - len(decoded_control_complete_node_ids)
            ),
            "reachable_decoded_control_frontier_nodes": len(
                reachable_decoded_control_frontier_node_ids
            ),
            "external_proved_edges": len(external_proved_edge_ids),
            "locally_refined_edges": len(locally_refined_edge_ids),
            "reachable_feasible_edges": len(reachable_feasible_edge_ids),
            "reachable_locally_refined_edges": len(
                reachable_locally_refined_edge_ids
            ),
            "reachable_local_refinement_frontier_edges": len(
                reachable_local_refinement_frontier_edge_ids
            ),
            "reachable_product_local_complete": reachable_product_local_complete,
            "declared_reachability_control_closed": (
                declared_reachability_control_closed
            ),
        },
        "trust": {
            "role": "untrusted_graph_and_evidence_proposal",
            "lean_checks": [
                "indexed_nodes",
                "indexed_edges",
                "canonical_cutpoint_targets",
                "outgoing_edge_inventory",
                "declared_roots",
                "proved_edge_inventory",
                "unconditional_single-successor_coverage",
                "root_reachability_successor_closure",
                "exact_decoded_control_exit_inventory",
            ],
        },
    }

def _composition_progress(
    product_graph: dict[str, Any],
    semantic_preflight: dict[str, Any],
    external_call_sites: dict[str, Any],
    acceptance: dict[str, Any],
    stack_window_analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Summarize rooted composition without promoting proposal data to proof facts."""
    counts = product_graph["counts"]
    evidence = product_graph["evidence"]
    reachable_node_ids = [
        int(node_id) for node_id in evidence["declared_reachable_node_ids"]
    ]
    reachable_node_id_set = set(reachable_node_ids)
    reachable_edge_ids = [
        int(edge_id) for edge_id in evidence["reachable_feasible_edge_ids"]
    ]
    edges_by_id = {
        int(edge["id"]): edge for edge in product_graph["edges"]
    }
    reachable_external_edge_ids = [
        edge_id for edge_id in reachable_edge_ids
        if edges_by_id[edge_id]["kind"] == "externalCall"
    ]
    external_candidate_edge_ids = {
        int(site["edge_index"]) for site in external_call_sites["candidates"]
        if "edge_index" in site
    }
    external_gap_edge_ids = {
        int(site["edge_index"]) for site in external_call_sites["gaps"]
        if "edge_index" in site
    }
    reachable_external_candidate_edge_ids = sorted(
        set(reachable_external_edge_ids).intersection(external_candidate_edge_ids)
    )
    reachable_external_gap_edge_ids = sorted(
        set(reachable_external_edge_ids).intersection(external_gap_edge_ids)
    )
    reachable_external_thunk_candidates = [
        site for site in external_call_sites["candidates"]
        if site.get("site_kind") == "direct_import_thunk"
        and int(site["source_region_index"]) in reachable_node_id_set
    ]
    reachable_external_thunk_gaps = [
        gap for gap in external_call_sites["gaps"]
        if gap.get("site_kind") == "direct_import_thunk"
        and int(gap["source_region_index"]) in reachable_node_id_set
    ]
    environment_frontier_edge_ids = (
        []
        if acceptance.get("status") == "ready"
        else reachable_external_edge_ids
    )

    potential_control_cuts = evidence["potential_control_cuts"]
    unresolved_indirect_control_cuts = [
        cut for cut in potential_control_cuts
        if str(cut.get("reason", "")).startswith("unresolved_indirect_control")
    ]
    unresolved_indirect_node_ids = {
        int(cut["node_id"]) for cut in unresolved_indirect_control_cuts
    }
    unsupported_instruction_issues = [
        issue for issue in semantic_preflight.get("issues", [])
        if issue.get("category") == "formal_instruction_unsupported"
    ]
    acceptance_blockers = list(acceptance.get("blockers", []))
    acceptance_blocker_count = sum(
        int(blocker.get("count", 1)) for blocker in acceptance_blockers
    )
    local_frontier_edge_ids = [
        int(edge_id)
        for edge_id in evidence["reachable_local_refinement_frontier_edge_ids"]
    ]
    decoded_frontier_node_ids = [
        int(node_id)
        for node_id in evidence["reachable_decoded_control_frontier_node_ids"]
    ]
    reachable_node_id_set = set(reachable_node_ids)
    root_node_ids = {int(node_id) for node_id in product_graph["root_node_ids"]}
    checked_runtime_return_continuation_node_ids = {
        int(step["target_node_id"])
        for step in acceptance.get("node_steps", [])
        if step.get("kind") == "return"
        and step.get("stack_window_transfers")
        and isinstance(step.get("target_node_id"), int)
    }
    stack_invariant_frontier = [
        row for row in (stack_window_analysis or {}).get("frontier", [])
        if int(row["region_index"]) in reachable_node_id_set
        and not (
            row.get("reason") == "no_checked_incoming_edge"
            and int(row["region_index"]) in (
                root_node_ids | checked_runtime_return_continuation_node_ids
            )
        )
    ]
    relational_frame_reasons = {
        "recursive_call_window_requires_inductive_frame",
        "nonzero_stack_delta_cycle_requires_relational_frame",
    }
    relational_frame_frontier = [
        row for row in stack_invariant_frontier
        if row.get("reason") in relational_frame_reasons
    ]
    relational_frame_frontier_node_ids = sorted({
        int(row["region_index"]) for row in relational_frame_frontier
    })
    stack_invariant_frontier_node_ids = sorted({
        int(row["region_index"]) for row in stack_invariant_frontier
    })
    ready_for_lean = (
        acceptance.get("status") == "ready"
        and bool(counts["reachable_product_local_complete"])
        and not unresolved_indirect_control_cuts
        and not unsupported_instruction_issues
        and not environment_frontier_edge_ids
        and not stack_invariant_frontier
    )

    next_work: list[dict[str, Any]] = []
    if unresolved_indirect_control_cuts:
        next_work.append({
            "category": "unresolved_indirect_control",
            "count": len(unresolved_indirect_control_cuts),
            "example_ids": [
                int(cut["node_id"]) for cut in unresolved_indirect_control_cuts[:10]
            ],
            "next_action": (
                "classify the first indirect target by checked static, dynamic-range, "
                "import, jump-table, callback, or finite-target provenance"
            ),
        })
    direct_decoded_frontier_node_ids = [
        node_id for node_id in decoded_frontier_node_ids
        if node_id not in unresolved_indirect_node_ids
    ]
    if direct_decoded_frontier_node_ids:
        next_work.append({
            "category": "decoded_control_frontier",
            "count": len(direct_decoded_frontier_node_ids),
            "example_ids": direct_decoded_frontier_node_ids[:10],
            "next_action": (
                "recover and check the exact decoded exits for the first rooted frontier node"
            ),
        })
    if relational_frame_frontier_node_ids:
        next_work.append({
            "category": "relational_call_frame_frontier",
            "count": len(relational_frame_frontier_node_ids),
            "example_ids": relational_frame_frontier_node_ids[:10],
            "reason_counts": dict(sorted(Counter(
                str(row["reason"]) for row in relational_frame_frontier
            ).items())),
            "next_action": (
                "close the first non-zero or recursive stack cycle with a checked "
                "relational call-frame invariant instead of a finite flat stack window"
            ),
        })
    if local_frontier_edge_ids:
        next_work.append({
            "category": "segment_refinement_frontier",
            "count": len(local_frontier_edge_ids),
            "example_ids": local_frontier_edge_ids[:10],
            "next_action": (
                "close the first rooted feasible edge with a checked segment refinement"
            ),
        })
    if environment_frontier_edge_ids:
        next_work.append({
            "category": "environment_frontier",
            "count": len(environment_frontier_edge_ids),
            "example_ids": environment_frontier_edge_ids[:10],
            "next_action": (
                "close the first rooted external edge through a machine-level call "
                "contract and paired environment refinement"
            ),
        })
    if reachable_external_thunk_gaps:
        next_work.append({
            "category": "external_thunk_contract_frontier",
            "count": len(reachable_external_thunk_gaps),
            "example_ids": [
                int(gap["source_region_index"])
                for gap in reachable_external_thunk_gaps[:10]
            ],
            "reason_counts": dict(sorted(Counter(
                str(gap["reason"]) for gap in reachable_external_thunk_gaps
            ).items())),
            "next_action": (
                "close the first rooted direct import thunk with one matching "
                "machine-level contract, ABI argument proof, and continuation-specific site"
            ),
        })
    if unsupported_instruction_issues:
        next_work.append({
            "category": "unsupported_instruction",
            "count": len(unsupported_instruction_issues),
            "example_ids": [
                str(issue["id"]) for issue in unsupported_instruction_issues[:10]
            ],
            "next_action": (
                "add reviewed decode and machine semantics for the first unsupported form"
            ),
        })
    if acceptance_blockers and not next_work:
        next_work.append({
            "category": "acceptance_frontier",
            "count": acceptance_blocker_count,
            "example_ids": [
                str(blocker.get("code", "unknown"))
                for blocker in acceptance_blockers[:10]
            ],
            "next_action": str(
                acceptance_blockers[0].get(
                    "next_action", "close the first whole-program acceptance blocker"
                )
            ),
        })

    return {
        "format": "stage-a-composition-progress-v1",
        "status": "ready_for_lean" if ready_for_lean else "incomplete",
        "metric_policy": {
            "primary": "rooted_product_composition",
            "local_proof_counts_are_secondary": True,
            "reachability_source": "decoded_behavior_and_checked_runtime_continuations",
            "unresolved_control_fails_closed": True,
        },
        "counts": {
            "roots": int(counts["roots"]),
            "rooted_reachable_nodes": len(reachable_node_ids),
            "potential_reachable_nodes": int(counts["potential_reachable_nodes"]),
            "rooted_reachable_feasible_edges": len(reachable_edge_ids),
            "rooted_refined_segments": int(
                counts["reachable_locally_refined_edges"]
            ),
            "rooted_segment_refinement_frontier_edges": len(
                local_frontier_edge_ids
            ),
            "rooted_decoded_control_frontier_nodes": len(
                decoded_frontier_node_ids
            ),
            "rooted_stack_invariant_frontier_nodes": len(
                stack_invariant_frontier_node_ids
            ),
            "rooted_relational_call_frame_frontier_nodes": len(
                relational_frame_frontier_node_ids
            ),
            "unresolved_indirect_control_nodes": len(
                unresolved_indirect_control_cuts
            ),
            "unresolved_indirect_potential_targets": sum(
                int(cut["potential_target_count"])
                for cut in unresolved_indirect_control_cuts
            ),
            "unsupported_instructions": len(unsupported_instruction_issues),
            "rooted_external_edges": len(reachable_external_edge_ids),
            "rooted_external_refinement_candidates": len(
                reachable_external_candidate_edge_ids
            ),
            "rooted_external_contract_gap_edges": len(
                reachable_external_gap_edge_ids
            ),
            "rooted_external_thunk_refinement_candidates": len(
                reachable_external_thunk_candidates
            ),
            "rooted_external_thunk_contract_gaps": len(
                reachable_external_thunk_gaps
            ),
            "rooted_environment_frontier_edges": len(
                environment_frontier_edge_ids
            ),
            "acceptance_blockers": acceptance_blocker_count,
            "acceptance_blocker_categories": len(acceptance_blockers),
        },
        "reachability": {
            "rooted_node_ids": reachable_node_ids,
            "potential_node_ids": [
                int(node_id) for node_id in evidence["potential_reachable_node_ids"]
            ],
            "truncated_by_control_frontier": bool(
                counts["reachability_truncated_by_control_frontier"]
            ),
        },
        "frontiers": {
            "decoded_control_node_ids": decoded_frontier_node_ids,
            "segment_edge_ids": local_frontier_edge_ids,
            "stack_invariant": stack_invariant_frontier,
            "relational_call_frame": relational_frame_frontier,
            "unresolved_indirect_control": unresolved_indirect_control_cuts,
            "unsupported_instruction_issue_ids": [
                str(issue["id"]) for issue in unsupported_instruction_issues
            ],
            "external_edge_ids": environment_frontier_edge_ids,
            "external_contract_gaps": [
                gap for gap in external_call_sites["gaps"]
                if (
                    "edge_index" in gap
                    and int(gap["edge_index"]) in reachable_external_gap_edge_ids
                ) or gap in reachable_external_thunk_gaps
            ],
            "acceptance_blockers": acceptance_blockers,
        },
        "acceptance": {
            "status": acceptance.get("status"),
            "profile": acceptance.get("profile"),
            "theorem": acceptance.get("theorem"),
        },
        "next_work": next_work,
        "trust": {
            "role": "diagnostic_projection_of_hashed_proof_inputs",
            "acceptance_authority": False,
            "final_pass_requires": RELATIONAL_ACCEPTANCE_THEOREM,
        },
    }

def _attach_product_graph_analysis(
    proof_ir: dict[str, Any], product_graph: dict[str, Any]
) -> dict[str, Any]:
    complete = bool(product_graph["evidence"]["complete"])
    counts = product_graph["counts"]
    obligations = [
        {
            "id": "product-graph:structure",
            "kind": "relational_product_graph_structure",
            "status": "candidate_requires_lean_replay",
            "repair_class": "product_graph_structure",
            "blocker": None,
            "next_action": "replay the indexed node, edge, outgoing, and root inventories in Lean",
        },
        {
            "id": "product-graph:edge-completeness",
            "kind": "relational_product_graph_declared_edge_refinement",
            "status": "proved" if complete else "incomplete",
            "repair_class": "product_edge_refinement",
            "blocker": (
                None if complete else
                f"{counts['incomplete_edges']} declared product edges lack a checked "
                "RelationalSegmentRefinement theorem"
            ),
            "next_action": (
                "construct the complete product-edge refinement certificate in Lean"
                if complete else
                "close the highest-impact incomplete segment refinements, then regenerate the graph"
            ),
        },
        {
            "id": "product-graph:decoded-control-completeness",
            "kind": "relational_product_graph_decoded_exit_completeness",
            "status": (
                "candidate_requires_lean_replay"
                if counts["declared_reachability_control_closed"]
                else "incomplete"
            ),
            "repair_class": "decoded_exit_inventory",
            "blocker": (
                None
                if counts["declared_reachability_control_closed"]
                else
                f"{counts['reachable_decoded_control_frontier_nodes']} nodes in the "
                "declared root closure have decoded control exits not represented on both "
                "sides of the product graph; the checked graph closure contains "
                f"{counts['declared_reachable_nodes']} nodes, while conservative "
                f"potential reachability contains {counts['potential_reachable_nodes']}; "
                f"{counts['potential_unrepresented_control_edges']} conservative "
                "control transitions remain unsubmitted"
            ),
            "next_action": (
                "replay every root-closure decoded control-exit witness in Lean"
                if counts["declared_reachability_control_closed"]
                else
                "repair the first root-reachable omitted or mismatched branch, call, return, "
                "or indirect-target inventory before using graph reachability"
            ),
            "analysis": {
                "frontier_node_ids": product_graph["evidence"][
                    "reachable_decoded_control_frontier_node_ids"
                ],
                "checked_graph_reachable_nodes": counts[
                    "declared_reachable_nodes"
                ],
                "potential_reachable_nodes": counts[
                    "potential_reachable_nodes"
                ],
                "potential_control_cuts": product_graph["evidence"][
                    "potential_control_cuts"
                ],
            },
        },
        {
            "id": "product-graph:reachable-local-refinement",
            "kind": "relational_product_graph_reachable_local_refinement",
            "status": (
                "candidate_requires_lean_replay"
                if counts["reachable_product_local_complete"]
                else "incomplete"
            ),
            "repair_class": "reachable_product_edge_refinement",
            "blocker": (
                None
                if counts["reachable_product_local_complete"]
                else (
                    f"{counts['reachable_decoded_control_frontier_nodes']} reachable "
                    "nodes lack exact decoded-exit inventories and "
                    f"{counts['reachable_local_refinement_frontier_edges']} reachable "
                    "feasible edges lack internal or external refinement witnesses"
                )
            ),
            "next_action": (
                "replay the complete reachable product-local certificate in Lean"
                if counts["reachable_product_local_complete"]
                else "repair the first reachable decoded-control or local-refinement "
                "frontier item, then regenerate only its dependent proof nodes"
            ),
            "analysis": {
                "decoded_control_frontier_node_ids": product_graph["evidence"][
                    "reachable_decoded_control_frontier_node_ids"
                ],
                "local_refinement_frontier_edge_ids": product_graph["evidence"][
                    "reachable_local_refinement_frontier_edge_ids"
                ],
                "reachable_feasible_edge_ids": product_graph["evidence"][
                    "reachable_feasible_edge_ids"
                ],
            },
        },
        {
            "id": "whole-program:acceptance-certificate",
            "kind": "whole_program_observational_equivalence",
            "status": "incomplete",
            "repair_class": "rooted_product_simulation",
            "blocker": (
                "no closed WholeProgramCertificate currently connects launch, rooted "
                "reachability, relational call frames, paired environments, segment "
                "refinements, faults, returns, and termination"
            ),
            "next_action": (
                "prove ProductStepRefinement for the complete rooted graph and emit "
                f"{RELATIONAL_ACCEPTANCE_THEOREM} as a closed application of "
                "StageA.Relational.pe32ProgramsEquivalent"
            ),
            "lean_witness": "StageA.Relational.pe32ProgramsEquivalent",
        },
    ]
    attached = dict(proof_ir)
    attached["product_graph_summary"] = {
        **counts,
        "declared_edges_complete": complete,
        "interface": "StageA.Relational.RelationalProductGraph",
    }
    attached["obligations"] = [*proof_ir["obligations"], *obligations]
    attached["families"] = [
        *proof_ir["families"],
        {
            "family": "product_graph",
            "status": "incomplete",
        },
        {
            "family": "whole_program_observational_equivalence",
            "status": "incomplete",
        },
    ]
    attached["status"] = "incomplete"
    return attached

def _attach_dynamic_indirect_call_analysis(
    proof_ir: dict[str, Any],
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    product_graph: dict[str, Any],
) -> dict[str, Any]:
    candidate_by_region = {
        int(candidate["source_region_index"]): candidate for candidate in candidates
    }
    frontier = set(
        product_graph["evidence"]["reachable_decoded_control_frontier_node_ids"]
    )
    obligations: list[dict[str, Any]] = []
    for region_index, behavior_pair in enumerate(behaviors):
        shape = _dynamic_range_indirect_call_shape(behavior_pair)
        if shape is None or (
            region_index not in candidate_by_region and region_index not in frontier
        ):
            continue
        original_register, candidate_register, word_offset, continuation = shape
        region = contract["regions"][region_index]
        candidate = candidate_by_region.get(region_index)
        if candidate is not None:
            obligations.append({
                "id": f"dynamic-indirect-call:{region_index}",
                "kind": "dynamic_range_indirect_call_target",
                "status": "candidate_requires_lean_replay",
                "repair_class": "dynamic_code_pointer_relation",
                "region_id": region["id"],
                "region_index": region_index,
                "blocker": None,
                "next_action": (
                    "replay DynamicRangeIndirectCallTargetsClosed in Lean, then connect "
                    "the related runtime code pointer to a finite checked product-graph "
                    "target inventory"
                ),
                "analysis": candidate,
            })
            continue
        obligations.append({
            "id": f"dynamic-indirect-call:{region_index}",
            "kind": "dynamic_range_indirect_call_target",
            "status": "incomplete",
            "repair_class": "memory_loaded_code_pointer_relation",
            "region_id": region["id"],
            "region_index": region_index,
            "blocker": (
                "the paired indirect call loads its target from related-looking memory, "
                "but no unique checked range relation classifies that word as a code pointer"
            ),
            "next_action": (
                f"propagate a DynamicRegisterRangeRelation for original {original_register} "
                f"and candidate {candidate_register} into this region, classify byte offset "
                f"{word_offset} as codePointer, and prove the paired allocation or mutable "
                "static range plus its world update at the producer"
            ),
            "analysis": {
                "original_register": original_register,
                "candidate_register": candidate_register,
                "word_offset": word_offset,
                "continuation_target_id": continuation,
            },
        })
    if not obligations:
        return proof_ir
    attached = dict(proof_ir)
    attached["obligations"] = [*proof_ir["obligations"], *obligations]
    attached["dynamic_indirect_call_summary"] = {
        "sites": len(obligations),
        "lean_replay_candidates": sum(
            obligation["status"] == "candidate_requires_lean_replay"
            for obligation in obligations
        ),
        "incomplete": sum(
            obligation["status"] == "incomplete" for obligation in obligations
        ),
    }
    attached["status"] = "incomplete"
    return attached

def _attach_stack_window_analysis(
    proof_ir: dict[str, Any],
    contract: dict[str, Any],
    analysis: dict[str, Any],
) -> dict[str, Any]:
    obligations: list[dict[str, Any]] = []
    if analysis.get("windows", 0):
        obligations.append({
            "id": "stack-range:world-profile",
            "kind": "paired_stack_range_world",
            "status": "incomplete",
            "repair_class": "pe32_launch_stack_range",
            "blocker": (
                "the relational world does not yet establish paired non-wrapping stack "
                "ranges at the PE32 console launch boundary"
            ),
            "next_action": (
                "construct stack range 0 from the launch profile, prove both concrete "
                "ranges are disjoint from their PE images, and establish root windows"
            ),
            "lean_witness": "StageA.Relational.RelationalWorld.stackRangesValid",
        })
    for region_index, region in enumerate(contract.get("regions", [])):
        claims = region.get("stack_address_separation_claims", [])
        if claims:
            obligations.append({
                "id": f"stack-separation-inventory:{region_index}",
                "kind": "stack_address_separation_inventory",
                "status": "candidate_requires_lean_replay",
                "region_index": region_index,
                "region_id": region["id"],
                "windows": len(region.get("stack_windows", [])),
                "separation_claims": len(claims),
                "repair_class": "stack_window_image_disjointness",
                "blocker": None,
                "next_action": (
                    "replay the complete stack-window separation inventory against exact "
                    "PE image bounds and the paired runtime range validity theorem"
                ),
                "lean_witness": (
                    f"region{region_index}StackSeparationInventoryChecked"
                ),
            })
    for frontier_index, frontier in enumerate(analysis.get("frontier", [])):
        reason = frontier["reason"]
        obligations.append({
            "id": f"stack-window-frontier:{frontier_index}",
            "kind": "stack_window_reachability",
            "status": "incomplete",
            **frontier,
            "region_id": contract["regions"][int(frontier["region_index"])]["id"],
            "repair_class": (
                "stack_window_root_establishment"
                if reason == "no_checked_incoming_edge"
                else "stack_pointer_affine_transfer"
            ),
            "blocker": (
                "no checked incoming product edge currently establishes this stack window"
                if reason == "no_checked_incoming_edge" else
                "the incoming edge changes stack state or crosses an environment boundary "
                "without a checked affine stack-window transfer"
            ),
            "next_action": (
                "connect the cutpoint to a checked root/call edge and establish its window"
                if reason == "no_checked_incoming_edge" else
                "decode the paired stack-pointer adjustment and prove the transformed "
                "below/above window and paired range offset"
            ),
        })
    attached = dict(proof_ir)
    attached["stack_window_summary"] = analysis
    attached["obligations"] = [*proof_ir["obligations"], *obligations]
    attached["families"] = [
        *proof_ir["families"],
        {"family": "stack_windows", "status": "incomplete"},
    ]
    attached["status"] = "incomplete"
    return attached

def _attach_import_register_analysis(
    proof_ir: dict[str, Any],
    seeds: list[dict[str, Any]],
    analysis: dict[str, Any],
    segment_candidates: list[dict[str, Any]] | None = None,
    memory_contracts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    obligations: list[dict[str, Any]] = []
    if seeds:
        obligations.append({
            "id": "import-address-memory:state-relation",
            "kind": "iat_memory_relation_override",
            "status": "candidate_requires_lean_replay",
            "repair_class": "relational_memory_import_cells",
            "blocker": None,
            "next_action": (
                "compile the IAT-masked ordinary-memory relation and its StateRel projection "
                "in Lean; reject memory-dependent claims without checked non-IAT witnesses"
            ),
            "lean_witness": "StageA.Relational.StateRel.ordinaryMemoryRelation",
        })
    for row in (memory_contracts or {}).get("regions", []):
        assembled = row.get("assembled_iat_read_candidates", {})
        original_candidates = {
            (
                candidate["register"],
                json.dumps(candidate["import"], sort_keys=True),
            ): candidate
            for candidate in assembled.get("original", [])
        }
        candidate_candidates = {
            (
                candidate["register"],
                json.dumps(candidate["import"], sort_keys=True),
            ): candidate
            for candidate in assembled.get("candidate", [])
        }
        for key in sorted(original_candidates.keys() & candidate_candidates.keys()):
            original_candidate = original_candidates[key]
            candidate_candidate = candidate_candidates[key]
            if (
                original_candidate["status"] == "exact_iat_cell"
                and candidate_candidate["status"] == "exact_iat_cell"
            ):
                continue
            matching_seeds = [
                seed for seed in seeds
                if int(seed["region_index"]) == int(row["index"])
                and str(seed["original_register"]) == str(key[0])
                and str(seed["candidate_register"]) == str(key[0])
                and json.dumps(seed["import"], sort_keys=True) == key[1]
                and int(seed["original_iat_rva"])
                    == int(original_candidate["iat_rva"])
                and int(seed["candidate_iat_rva"])
                    == int(candidate_candidate["iat_rva"])
                and seed.get("assembled_read")
            ]
            replayable = len(matching_seeds) == 1
            obligations.append({
                "id": f"assembled-iat-read:{int(row['index'])}:{key[0]}",
                "kind": "assembled_iat_register_seed",
                "status": (
                    "candidate_requires_lean_replay" if replayable else "incomplete"
                ),
                "region_index": int(row["index"]),
                "region_id": row["id"],
                "register": key[0],
                "import": original_candidate["import"],
                "original": original_candidate,
                "candidate": candidate_candidate,
                "repair_class": "iat_assembled_dword_write_separation",
                "blocker": None if replayable else (
                    "the import pointer is assembled from four IAT byte reads after "
                    "intervening writes whose addresses are not yet proved disjoint "
                    "from the IAT cell"
                ),
                "next_action": (
                    "replay the generated write-separation inventory, assembled read32 "
                    "reduction, and ImportAddressPair binding in Lean"
                    if replayable else
                    "emit checked address-separation witnesses for every intervening "
                    "write, reduce the byte assembly to Memory.read32, and reuse the "
                    "ImportAddressPair binding as a register seed"
                ),
                "lean_witness": (
                    f"importSeed{seeds.index(matching_seeds[0])}Checked"
                    if replayable else None
                ),
            })
    for seed_index, seed in enumerate(seeds):
        obligations.append({
            "id": f"import-register-seed:{seed_index}",
            "kind": "iat_import_register_seed",
            "status": "candidate_requires_lean_replay",
            "region_index": int(seed["region_index"]),
            "original_register": seed["original_register"],
            "candidate_register": seed["candidate_register"],
            "import": seed["import"],
            "original_iat_rva": int(seed["original_iat_rva"]),
            "candidate_iat_rva": int(seed["candidate_iat_rva"]),
            "profile": seed["profile"],
            "intervening_writes": {
                "original": len(seed.get("original_writes", [])),
                "candidate": len(seed.get("candidate_writes", [])),
            },
            "repair_class": (
                "iat_assembled_dword_write_separation"
                if seed.get("assembled_read") else "iat_seed_identity"
            ),
            "blocker": None,
            "next_action": (
                "replay the parsed IAT identity, checked write-separation inventory, "
                "assembled read32 reduction, and normalized register-load expression in Lean"
                if seed.get("assembled_read") else
                "replay the parsed IAT identity and normalized register-load expression in Lean"
            ),
            "lean_witness": f"importSeed{seed_index}Checked",
        })
    for relation_index, relation in enumerate(analysis.get("relations", [])):
        relation_import = relation["import"]

        def claim_matches(claim: dict[str, Any]) -> bool:
            if claim["kind"] == "seed":
                original_register = claim["original_register"]
                candidate_register = claim["candidate_register"]
            else:
                original_register = claim["target_original_register"]
                candidate_register = claim["target_candidate_register"]
            return (
                str(original_register) == str(relation["original_register"])
                and str(candidate_register) == str(relation["candidate_register"])
                and json.dumps(claim["import"], sort_keys=True)
                    == json.dumps(relation_import, sort_keys=True)
            )

        incoming_pairs = {
            (
                int(edge["source_region_index"]),
                int(edge["target_region_index"]),
            )
            for edge in relation.get("incoming_edges", [])
            if not edge.get("environment_barrier")
        }
        has_environment_incoming = any(
            edge.get("environment_barrier")
            for edge in relation.get("incoming_edges", [])
        )
        covered_pairs = {
            (
                int(candidate["source_region_index"]),
                int(candidate["target_region_index"]),
            )
            for candidate in (segment_candidates or [])
            if int(candidate["target_region_index"]) == int(relation["region_index"])
            and any(
                claim_matches(claim)
                for claim in candidate.get("import_transfer_claims", [])
            )
        }
        incoming_rows = relation.get("incoming_edges", [])
        covered_incoming = [
            edge for edge in incoming_rows
            if not edge.get("environment_barrier")
            and (
                int(edge["source_region_index"]),
                int(edge["target_region_index"]),
            ) in covered_pairs
        ]
        uncovered_incoming = [
            edge for edge in incoming_rows if edge not in covered_incoming
        ]
        replay_candidate = (
            bool(incoming_pairs)
            and not has_environment_incoming
            and incoming_pairs <= covered_pairs
        )
        obligations.append({
            "id": f"import-register-invariant:{relation_index}",
            "kind": "inductive_import_register_relation",
            "status": (
                "candidate_requires_lean_replay" if replay_candidate else "incomplete"
            ),
            "region_index": int(relation["region_index"]),
            "original_register": relation["original_register"],
            "candidate_register": relation["candidate_register"],
            "import": relation["import"],
            "incoming_edge_indices": relation["incoming_edge_indices"],
            "analysis": {
                "incoming_edges": incoming_rows,
                "covered_incoming_edges": covered_incoming,
                "uncovered_incoming_edges": uncovered_incoming,
            },
            "repair_class": "import_pointer_scc_invariant",
            "blocker": (None if replay_candidate else
                f"{len(uncovered_incoming)} of {len(incoming_rows)} decoded incoming "
                "edges lack a checked import-register transfer or external-preservation "
                "witness"),
            "next_action": (
                "compile the generated seed/register-transfer segment witness in Lean"
                if replay_candidate else
                "emit checked seed, register-transfer, external-preservation, and SCC "
                "induction witnesses for this import-pointer invariant"
            ),
            "lean_witness": (
                "generated segment import-transfer certificate"
                if replay_candidate else None
            ),
        })
    for call_index, call in enumerate(analysis.get("indirect_import_calls", [])):
        obligations.append({
            "id": f"indirect-import-call:{call_index}",
            "kind": "indirect_import_call_environment_refinement",
            "status": "incomplete",
            "source_region_index": int(call["source_region_index"]),
            "continuation_region_index": int(call["continuation_region_index"]),
            "original_register": call["original_register"],
            "candidate_register": call["candidate_register"],
            "import": call["import"],
            "repair_class": "machine_import_call_contract",
            "blocker": (
                "call-target identity can be replayed locally, but argument recovery, "
                "resolver validity, ABI results, memory effects, and successor world are open"
            ),
            "next_action": (
                "instantiate paired machine-level import-call resolvers and prove the "
                "external environment transition preserves the continuation StateRel"
            ),
        })
    attached = dict(proof_ir)
    attached["import_register_summary"] = analysis["counts"]
    attached["obligations"] = [*proof_ir["obligations"], *obligations]
    attached["families"] = [
        *proof_ir["families"],
        {"family": "iat_import_register_seeds", "status": (
            "not_applicable" if not seeds else "satisfied"
        )},
        {"family": "iat_memory_relation", "status": (
            "not_applicable" if not seeds else "incomplete"
        )},
        {"family": "import_register_invariant_composition", "status": (
            "not_applicable" if not analysis.get("relations") else "incomplete"
        )},
        {"family": "indirect_import_environment_refinement", "status": (
            "not_applicable"
            if not analysis.get("indirect_import_calls") else "incomplete"
        )},
    ]
    attached["status"] = "incomplete"
    return attached

def _immutable_indirect_call_candidates(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    def immutable_read(
        expression: dict[str, Any],
    ) -> tuple[int, list[dict[str, Any]], bool] | None:
        direct = _constant_read32_address(expression)
        if direct is not None:
            return direct, [], False
        assembled = _assembled_u32_after_register_writes(expression)
        if assembled is None:
            return None
        address, writes = assembled
        return address, writes, True

    code_targets = contract.get("code_targets", [])
    region_by_numeric_id = {
        int(region["numeric_id"]): index
        for index, region in enumerate(contract.get("regions", []))
    }
    result: list[dict[str, Any]] = []
    for source_index, (region, behavior_pair) in enumerate(zip(
        contract.get("regions", []), behaviors, strict=True
    )):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        operation = str(original_outcome.get("op"))
        if (
            operation not in {"indirect_call", "indirect_jump"}
            or candidate_outcome.get("op") != operation
        ):
            continue
        original_read = immutable_read(
            original_outcome.get("target") or {}
        )
        candidate_read = immutable_read(
            candidate_outcome.get("target") or {}
        )
        if original_read is None or candidate_read is None:
            continue
        original_address, original_writes, original_assembled = original_read
        candidate_address, candidate_writes, candidate_assembled = candidate_read
        if not _register_writes_have_address_separations(
            region, "original", original_address, original_writes
        ) or not _register_writes_have_address_separations(
            region, "candidate", candidate_address, candidate_writes
        ):
            continue
        original_word = _immutable_image_u32(original_bin, original_address)
        candidate_word = _immutable_image_u32(candidate_bin, candidate_address)
        if original_word is None or candidate_word is None:
            continue
        matching_targets = [
            target for target in code_targets
            if original_word == original_bin.image_base + int(target["original_rva"])
            and candidate_word == candidate_bin.image_base + int(target["candidate_rva"])
        ]
        if len(matching_targets) != 1:
            continue
        target = matching_targets[0]
        mapped_words = []
        for value in contract.get("value_targets", []):
            original_offset = original_address - int(value["original_value"])
            candidate_offset = candidate_address - int(value["candidate_value"])
            if (
                original_offset == candidate_offset
                and 0 <= original_offset
                and original_offset + 4 <= int(value["mapped_size"])
                and original_offset in {
                    int(offset) for offset in value.get("relocation_offsets", [])
                }
            ):
                mapped_words.append(value)
        mapped_word_keys = {
            (
                int(value["original_value"]),
                int(value["candidate_value"]),
                int(value["mapped_size"]),
                tuple(int(offset) for offset in value.get("relocation_offsets", [])),
            )
            for value in mapped_words
        }
        if len(mapped_word_keys) != 1:
            continue
        mapped_word = min(mapped_words, key=lambda value: int(value["id"]))
        available_target_ids = {
            int(item["id"]) for item in region.get("code_targets", [])
        }
        if int(target["id"]) not in available_target_ids:
            continue
        row = {
            "profile": (
                "immutable_relocated_function_pointer_call_v1"
                if operation == "indirect_call"
                else "immutable_relocated_function_pointer_jump_v1"
            ),
            "source_region_index": source_index,
            "target_region_index": int(target["region_index"]),
            "target_id": int(target["id"]),
            "original_address": original_address,
            "candidate_address": candidate_address,
            "original_assembled_read": original_assembled,
            "candidate_assembled_read": candidate_assembled,
            "original_writes": original_writes,
            "candidate_writes": candidate_writes,
            "value_target_id": int(mapped_word["id"]),
        }
        if operation == "indirect_call":
            original_continuation = int(original_outcome.get("continuation", -1))
            candidate_continuation = int(candidate_outcome.get("continuation", -1))
            if original_continuation != candidate_continuation:
                continue
            continuation_index = region_by_numeric_id.get(original_continuation)
            if continuation_index is None:
                continue
            continuation_targets = [
                item for item in code_targets
                if int(item["region_index"]) == continuation_index
            ]
            if len(continuation_targets) != 1:
                continue
            continuation_target_id = int(continuation_targets[0]["id"])
            if continuation_target_id not in available_target_ids:
                continue
            row.update({
                "continuation_region_index": continuation_index,
                "continuation_target_id": continuation_target_id,
            })
        result.append(row)
    return result

def _dynamic_range_indirect_call_shape(
    behavior_pair: dict[str, Any],
) -> tuple[str, str, int, int] | None:
    def register_read(expression: Any) -> tuple[str, int] | None:
        if not isinstance(expression, dict) or expression.get("op") != "read32":
            return None
        address = expression.get("address") or {}
        if address.get("op") == "input_reg":
            return str(address.get("reg")), 0
        if address.get("op") != "add":
            return None
        left = address.get("left") or {}
        right = address.get("right") or {}
        if left.get("op") == "constant":
            left, right = right, left
        if left.get("op") != "input_reg" or right.get("op") != "constant":
            return None
        offset = _integer(right.get("value"))
        if offset is None or not 0 <= offset < 2**32:
            return None
        return str(left.get("reg")), offset

    original_outcome = behavior_pair["original_ir"].get("outcome") or {}
    candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
    if (
        original_outcome.get("op") != "indirect_call"
        or candidate_outcome.get("op") != "indirect_call"
    ):
        return None
    original_read = register_read(original_outcome.get("target"))
    candidate_read = register_read(candidate_outcome.get("target"))
    if original_read is None or candidate_read is None:
        return None
    original_register, original_word_offset = original_read
    candidate_register, candidate_word_offset = candidate_read
    if original_word_offset != candidate_word_offset:
        return None
    original_continuation = _integer(original_outcome.get("continuation"))
    candidate_continuation = _integer(candidate_outcome.get("continuation"))
    if (
        original_continuation is None
        or original_continuation != candidate_continuation
    ):
        return None
    return (
        original_register,
        candidate_register,
        original_word_offset,
        original_continuation,
    )

def _dynamic_range_indirect_call_candidates(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for source_index, (region, behavior_pair) in enumerate(zip(
        contract.get("regions", []), behaviors, strict=True
    )):
        shape = _dynamic_range_indirect_call_shape(behavior_pair)
        if shape is None:
            continue
        (
            original_register, candidate_register, original_word_offset,
            original_continuation,
        ) = shape
        matches = []
        for relation in region.get("input_dynamic_range_relations", []):
            if (
                relation.get("original") != original_register
                or relation.get("candidate") != candidate_register
                or int(relation.get("original_offset", -1)) !=
                    int(relation.get("candidate_offset", -2))
            ):
                continue
            required_offset = (
                int(relation["original_offset"]) + original_word_offset
            )
            if {
                "offset": required_offset,
                "kind": "codePointer",
            } not in relation.get("required_words", []):
                continue
            matches.append(relation)
        if len(matches) != 1:
            continue
        result.append({
            "profile": "dynamic_range_code_pointer_call_v1",
            "source_region_index": source_index,
            "range_relation": matches[0],
            "word_offset": original_word_offset,
            "continuation_target_id": original_continuation,
        })
    return result

def _constant_read32_address(expression: dict[str, Any]) -> int | None:
    if expression.get("op") != "read32":
        return None
    address = expression.get("address") or {}
    if address.get("op") != "constant":
        return None
    return int(address["value"]) & 0xFFFFFFFF

def _immutable_image_u32(binary: StageABinary, absolute: int) -> int | None:
    if absolute < binary.image_base:
        return None
    rva = absolute - binary.image_base
    section = next((
        section for section in binary.sections
        if not section.writable
        and section.rva_start <= rva
        and rva + 4 <= section.rva_end
    ), None)
    if section is None:
        return None
    data = binary.pe.get_data(rva, 4)
    if len(data) != 4:
        return None
    return int.from_bytes(data, "little")

def _register_writes_have_address_separations(
    region: dict[str, Any], side: str, word_address: int,
    writes: list[dict[str, Any]],
) -> bool:
    separations = region.get("address_separations", [])
    return all(
        any(
            str(separation.get(f"{side}_register")) == str(write["register"])
            and int(separation.get(f"{side}_offset", -1))
                == int(write["offset"]) + write_byte
            and int(separation.get(f"{side}_address", -1))
                == word_address + word_byte
            for separation in separations
        )
        for write in writes
        for word_byte in range(4)
        for write_byte in range(4)
    )
