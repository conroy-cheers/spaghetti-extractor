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
    bounded_table_candidates: list[dict[str, Any]] | None = None,
    bounded_table_call_candidates: list[dict[str, Any]] | None = None,
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
    node_targets_by_id = {
        int(target["id"]): target for target in node_targets
    }

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

    def table_index_guard(
        expression: dict[str, Any], index: int,
    ) -> dict[str, Any]:
        return {
            "op": "equal",
            "left": expression,
            "right": {"op": "constant", "value": index},
        }

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

    bounded_table_edge_groups: list[dict[str, Any]] = []
    bounded_table_sources: set[int] = set()
    for candidate_index, indirect_candidate in enumerate(
        bounded_table_candidates or []
    ):
        if indirect_candidate.get("profile") != (
            "bounded_immutable_relocation_table_jump_v1"
        ):
            continue
        source = int(indirect_candidate["source_region_index"])
        if source in bounded_table_sources:
            raise StageAInputError(
                f"product node {source} has duplicate bounded relocation-table claims"
            )
        bounded_table_sources.add(source)
        if not 0 <= source < len(node_targets):
            raise StageAInputError(
                f"bounded relocation-table source {source} is out of range"
            )
        if outgoing[source]:
            raise StageAInputError(
                f"bounded relocation-table source {source} already has submitted edges"
            )
        original_expression = behaviors[source]["original_ir"]["outcome"]["target"]
        candidate_expression = behaviors[source]["candidate_ir"]["outcome"]["target"]
        edge_ids: list[int] = []
        for target_id in indirect_candidate["target_ids"]:
            target = node_targets_by_id.get(int(target_id))
            if target is None:
                raise StageAInputError(
                    f"bounded relocation-table target {target_id} is not canonical"
                )
            edge_id = len(edges)
            edge_ids.append(edge_id)
            outgoing[source].append(edge_id)
            edges.append({
                "id": edge_id,
                "source_node_id": source,
                "target_node_id": int(target["region_index"]),
                "source_target_id": int(node_targets[source]["id"]),
                "target_target_id": int(target["id"]),
                "kind": "jump",
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
                "bounded_relocation_table_candidate_index": candidate_index,
            })
        bounded_table_edge_groups.append({
            "source_node_id": source,
            "candidate_index": candidate_index,
            "edge_ids": edge_ids,
        })

    bounded_table_call_edge_groups: list[dict[str, Any]] = []
    bounded_table_call_sources: set[int] = set()
    for candidate_index, table_candidate in enumerate(
        bounded_table_call_candidates or []
    ):
        if (
            table_candidate.get("profile")
            != "immutable_code_pointer_table_call_v1"
            or table_candidate.get("shape") != "direct_indexed_table_read"
            or table_candidate.get("input_contract")
            != "bounded_immutable_code_pointer_table_call_v1"
        ):
            raise StageAInputError(
                "product graph received a non-canonical bounded immutable "
                "code-pointer-table call input"
            )
        source = int(table_candidate["source_region_index"])
        if source in bounded_table_call_sources:
            raise StageAInputError(
                f"product node {source} has duplicate bounded table-call claims"
            )
        bounded_table_call_sources.add(source)
        if not 0 <= source < len(node_targets):
            raise StageAInputError(
                f"bounded table-call source {source} is out of range"
            )
        if outgoing[source]:
            raise StageAInputError(
                f"bounded table-call source {source} already has submitted edges"
            )
        original_outcome = behaviors[source]["original_ir"].get("outcome") or {}
        candidate_outcome = behaviors[source]["candidate_ir"].get("outcome") or {}
        if (
            original_outcome.get("op") != "indirect_call"
            or candidate_outcome.get("op") != "indirect_call"
            or original_outcome.get("target")
            != table_candidate["original_target_expression"]
            or candidate_outcome.get("target")
            != table_candidate["candidate_target_expression"]
        ):
            raise StageAInputError(
                f"bounded table-call source {source} no longer matches decoded control"
            )
        continuation_region_index = int(
            table_candidate["continuation_region_index"]
        )
        if not 0 <= continuation_region_index < len(node_targets):
            raise StageAInputError(
                f"bounded table-call source {source} has an out-of-range continuation"
            )
        if (
            int(table_candidate["continuation_target_id"])
            != int(node_targets[continuation_region_index]["id"])
        ):
            raise StageAInputError(
                f"bounded table-call source {source} has a non-canonical continuation"
            )

        original_index_expression = table_candidate["original_index_expression"]
        candidate_index_expression = table_candidate["candidate_index_expression"]
        edge_ids: list[int] = []
        for row in table_candidate["rows"]:
            target_id = int(row["target_id"])
            row_index = int(row["original_index"])
            target = node_targets_by_id.get(int(target_id))
            if target is None:
                raise StageAInputError(
                    f"bounded table-call target {target_id} is not canonical"
                )
            edge_id = len(edges)
            edge_ids.append(edge_id)
            outgoing[source].append(edge_id)
            edges.append({
                "id": edge_id,
                "source_node_id": source,
                "target_node_id": int(target["region_index"]),
                "source_target_id": int(node_targets[source]["id"]),
                "target_target_id": int(target["id"]),
                "kind": "call",
                "original_guard": table_index_guard(
                    original_index_expression, row_index
                ),
                "candidate_guard": table_index_guard(
                    candidate_index_expression, row_index
                ),
                "infeasible": False,
                "bounded_code_pointer_table_call_candidate_index": candidate_index,
            })
        if not edge_ids:
            raise StageAInputError(
                f"bounded table-call source {source} has an empty finite target set"
            )
        bounded_table_call_edge_groups.append({
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
    bounded_table_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (bounded_table_candidates or [])
    }
    bounded_table_call_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (bounded_table_call_candidates or [])
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
    if set(bounded_table_by_source).intersection(
        set(indirect_by_source)
        | set(dynamic_call_by_source)
        | set(bounded_table_call_by_source)
    ):
        raise StageAInputError(
            "a product node cannot have multiple indirect-control claims"
        )
    if set(bounded_table_call_by_source).intersection(
        set(indirect_by_source)
        | set(dynamic_call_by_source)
        | set(import_call_by_source)
    ):
        raise StageAInputError(
            "a product node cannot have multiple indirect-call claims"
        )

    def decoded_control_edges(
        behavior: dict[str, Any],
        indirect_candidate: dict[str, Any] | None,
        bounded_table_candidate: dict[str, Any] | None,
        bounded_table_call_candidate: dict[str, Any] | None,
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
            and indirect_candidate["profile"] in {
                "immutable_relocated_function_pointer_call_v1",
                "fixed_static_function_pointer_call_v1",
                "inductive_fixed_code_pointer_register_call_v1",
            }
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
        if (
            operation == "indirect_jump"
            and bounded_table_candidate is not None
            and bounded_table_candidate["profile"] ==
                "bounded_immutable_relocation_table_jump_v1"
        ):
            expression = outcome["target"]
            image_base = candidate_image_base if candidate_side else original_image_base
            rva_key = "candidate_rva" if candidate_side else "original_rva"
            aliases_key = (
                "candidate_aliases" if candidate_side else "original_aliases"
            )
            return [
                {
                    "kind": "jump",
                    "target_target_id": int(target["id"]),
                    "guard": code_target_guard(
                        expression,
                        image_base,
                        int(target[rva_key]),
                        [int(alias) for alias in target.get(aliases_key, [])],
                    ),
                }
                for target_id in bounded_table_candidate["target_ids"]
                if (target := node_targets_by_id.get(int(target_id))) is not None
            ]
        if (
            operation == "indirect_call"
            and bounded_table_call_candidate is not None
            and bounded_table_call_candidate["profile"]
            == "immutable_code_pointer_table_call_v1"
            and bounded_table_call_candidate["shape"]
            == "direct_indexed_table_read"
        ):
            index_key = (
                "candidate_index_expression"
                if candidate_side else "original_index_expression"
            )
            return [
                {
                    "kind": "call",
                    "target_target_id": int(target["id"]),
                    "guard": table_index_guard(
                        bounded_table_call_candidate[index_key],
                        int(row["original_index"]),
                    ),
                }
                for row in bounded_table_call_candidate["rows"]
                for target_id in [int(row["target_id"])]
                if (target := node_targets_by_id.get(int(target_id))) is not None
            ]
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
        bounded_table_candidate = bounded_table_by_source.get(node_id)
        bounded_table_call_candidate = bounded_table_call_by_source.get(node_id)
        dynamic_candidate = dynamic_call_by_source.get(node_id)
        import_call_candidate = import_call_by_source.get(node_id)
        original_decoded = decoded_control_edges(
            behavior_pair["original_ir"], indirect_candidate,
            bounded_table_candidate, bounded_table_call_candidate, dynamic_candidate,
            import_call_candidate, candidate_side=False,
        )
        candidate_decoded = decoded_control_edges(
            behavior_pair["candidate_ir"], indirect_candidate,
            bounded_table_candidate, bounded_table_call_candidate, dynamic_candidate,
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
            if bounded_table_candidate is not None:
                decoded_candidate.update(bounded_table_candidate)
            if bounded_table_call_candidate is not None:
                decoded_candidate.update(bounded_table_call_candidate)
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
    for table_candidate in bounded_table_call_candidates or []:
        runtime_call_continuations[int(table_candidate["source_region_index"])].add(
            int(table_candidate["continuation_region_index"])
        )
    for relation_edge in register_relations.get("edges", []):
        claim = (
            relation_edge.get("direct_call_push_claim")
            or relation_edge.get("indirect_call_push_claim")
        )
        if not isinstance(claim, dict):
            continue
        source_node_id = int(relation_edge["source_region_index"])
        continuation_node_id = int(claim["continuation_region_index"])
        if not (
            0 <= source_node_id < len(nodes)
            and 0 <= continuation_node_id < len(nodes)
        ):
            raise StageAInputError(
                "checked call continuation references an out-of-range product node"
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
        provenance: list[str] = []
        if any(
            operation in {"indirect_call", "indirect_jump", "checked_continue"}
            for operation in operations
        ):
            added_targets.update(range(len(nodes)))
            provenance = sorted({
                _indirect_control_expression_provenance(
                    (behavior_pair[side].get("outcome") or {}).get("target"),
                    str((behavior_pair[side].get("outcome") or {}).get("op")),
                )
                for side in ("original_ir", "candidate_ir")
            })
            reason = "unresolved_indirect_control_" + "_or_".join(provenance)
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
                "provenance": provenance if len(added_targets) == len(nodes) else [],
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
            "bounded_immutable_relocation_table_edge_groups": (
                bounded_table_edge_groups
            ),
            "bounded_immutable_code_pointer_table_call_candidates": (
                bounded_table_call_candidates or []
            ),
            "bounded_immutable_code_pointer_table_call_edge_groups": (
                bounded_table_call_edge_groups
            ),
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
            "outside_declared_reachability_nodes": (
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
    environment_frontier_edge_ids = sorted(
        set(reachable_external_edge_ids).difference(
            reachable_external_candidate_edge_ids
        )
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
        fixed_slots = [
            slot for slot in contract.get("static_word_relation_slots", [])
            if str(slot.get("relation")) == "fixed_code_pointer"
            and int(slot.get("original_address", -1)) == original_address
            and int(slot.get("candidate_address", -1)) == candidate_address
        ]
        target: dict[str, Any]
        profile: str
        value_target_id: int | None = None
        fixed_slot: dict[str, Any] | None = None
        if original_word is not None and candidate_word is not None:
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
            value_target_id = int(mapped_word["id"])
            profile = (
                "immutable_relocated_function_pointer_call_v1"
                if operation == "indirect_call"
                else "immutable_relocated_function_pointer_jump_v1"
            )
        else:
            if operation != "indirect_call":
                continue
            if len(fixed_slots) != 1:
                continue
            fixed_slot = fixed_slots[0]
            fixed_target_id = int(fixed_slots[0]["target_id"])
            matching_targets = [
                target for target in code_targets
                if int(target["id"]) == fixed_target_id
            ]
            if len(matching_targets) != 1:
                continue
            target = matching_targets[0]
            profile = "fixed_static_function_pointer_call_v1"
        available_target_ids = {
            int(item["id"]) for item in region.get("code_targets", [])
        }
        if int(target["id"]) not in available_target_ids:
            continue
        row = {
            "profile": profile,
            "source_region_index": source_index,
            "target_region_index": int(target["region_index"]),
            "target_id": int(target["id"]),
            "original_address": original_address,
            "candidate_address": candidate_address,
            "original_assembled_read": original_assembled,
            "candidate_assembled_read": candidate_assembled,
            "original_writes": original_writes,
            "candidate_writes": candidate_writes,
        }
        if value_target_id is not None:
            row["value_target_id"] = value_target_id
        if fixed_slot is not None:
            row["slot"] = fixed_slot
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


def _bounded_immutable_relocation_table_jump_candidates(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for source_index, (region, behavior_pair) in enumerate(zip(
        contract.get("regions", []), behaviors, strict=True
    )):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        if (
            original_outcome.get("op") != "indirect_jump"
            or candidate_outcome.get("op") != "indirect_jump"
        ):
            continue
        candidate = _bounded_immutable_relocation_table_jump_candidate(
            original_bin,
            candidate_bin,
            contract,
            region,
            source_index,
            original_outcome,
            candidate_outcome,
        )
        if candidate is not None:
            result.append(candidate)
    return result


def _immutable_code_pointer_table_call_candidates(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Propose finite indirect-call rows without making them proof facts."""
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
        if (
            original_outcome.get("op") != "indirect_call"
            or candidate_outcome.get("op") != "indirect_call"
        ):
            continue
        original_continuation = _integer(original_outcome.get("continuation"))
        candidate_continuation = _integer(candidate_outcome.get("continuation"))
        if (
            original_continuation is None
            or original_continuation != candidate_continuation
            or original_continuation not in region_by_numeric_id
        ):
            continue
        continuation_region_index = region_by_numeric_id[original_continuation]
        continuation_targets = {
            int(target["id"])
            for target in contract.get("code_targets", [])
            if int(target["region_index"]) == continuation_region_index
        }
        if len(continuation_targets) != 1:
            continue

        candidate = _direct_immutable_code_pointer_table_call_candidate(
            original_bin,
            candidate_bin,
            contract,
            behaviors,
            region,
            original_outcome,
            candidate_outcome,
        )
        if candidate is None:
            candidate = _cursor_immutable_code_pointer_table_call_candidate(
                original_bin,
                candidate_bin,
                contract,
                behaviors,
                region,
                source_index,
                original_outcome,
                candidate_outcome,
            )
        if candidate is None:
            continue
        candidate.update({
            "profile": "immutable_code_pointer_table_call_v1",
            "status": "candidate_requires_lean_replay",
            "acceptance_authority": False,
            "source_region_index": source_index,
            "continuation_region_index": continuation_region_index,
            "continuation_target_id": next(iter(continuation_targets)),
            "original_target_expression": original_outcome["target"],
            "candidate_target_expression": candidate_outcome["target"],
        })
        result.append(candidate)
    return result


def _bounded_immutable_code_pointer_table_call_inputs(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    proposals: list[dict[str, Any]],
    *,
    original_image_base: int,
    candidate_image_base: int,
) -> dict[str, Any]:
    """Canonicalize the narrow direct-table profile for Lean replay.

    The analyzer's proposal status is deliberately ignored.  This function only
    checks that a proposal is a complete, unambiguous serialization of decoded
    control and contract data; the generated Lean claim remains responsible for
    checking the PE bytes, relocations, invariant bound, and graph edges.
    """
    regions = contract.get("regions", [])
    if len(behaviors) != len(regions):
        raise StageAInputError(
            "bounded table-call input generation requires one behavior per region"
        )
    region_by_numeric_id: dict[int, int] = {}
    duplicate_numeric_ids: set[int] = set()
    for region_index, region in enumerate(regions):
        numeric_id = _integer(region.get("numeric_id"))
        if numeric_id is None:
            continue
        if numeric_id in region_by_numeric_id:
            duplicate_numeric_ids.add(numeric_id)
        else:
            region_by_numeric_id[numeric_id] = region_index

    targets_by_id: dict[int, list[dict[str, Any]]] = defaultdict(list)
    targets_by_region: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for target in contract.get("code_targets", []):
        target_id = _integer(target.get("id"))
        region_index = _integer(target.get("region_index"))
        if target_id is not None:
            targets_by_id[target_id].append(target)
        if region_index is not None:
            targets_by_region[region_index].append(target)

    incomplete: list[dict[str, Any]] = []

    def reject(
        proposal_index: int,
        proposal: dict[str, Any],
        reason: str,
    ) -> None:
        source = _integer(proposal.get("source_region_index"))
        incomplete.append({
            "proposal_index": proposal_index,
            "source_region_index": source,
            "profile": proposal.get("profile"),
            "shape": proposal.get("shape"),
            "reason": reason,
        })

    indexed: list[tuple[int, dict[str, Any], int]] = []
    for proposal_index, proposal in enumerate(proposals):
        if proposal.get("profile") != "immutable_code_pointer_table_call_v1":
            reject(proposal_index, proposal, "unsupported_profile")
            continue
        source = _integer(proposal.get("source_region_index"))
        if source is None or not 0 <= source < len(regions):
            reject(proposal_index, proposal, "invalid_source_region")
            continue
        indexed.append((proposal_index, proposal, source))

    source_counts = Counter(source for _index, _proposal, source in indexed)
    candidates: list[dict[str, Any]] = []
    for proposal_index, proposal, source in indexed:
        if source_counts[source] != 1:
            reject(proposal_index, proposal, "ambiguous_source_proposals")
            continue
        if proposal.get("shape") != "direct_indexed_table_read":
            reject(
                proposal_index,
                proposal,
                "cursor_loaded_or_non_direct_table_not_supported",
            )
            continue

        region = regions[source]
        behavior_pair = behaviors[source]
        original_outcome = behavior_pair.get("original_ir", {}).get("outcome") or {}
        candidate_outcome = behavior_pair.get("candidate_ir", {}).get("outcome") or {}
        if (
            original_outcome.get("op") != "indirect_call"
            or candidate_outcome.get("op") != "indirect_call"
        ):
            reject(proposal_index, proposal, "decoded_exit_is_not_paired_indirect_call")
            continue
        original_shape = _indexed_u32_table_read(original_outcome.get("target"))
        candidate_shape = _indexed_u32_table_read(candidate_outcome.get("target"))
        if original_shape is None or candidate_shape is None:
            reject(proposal_index, proposal, "decoded_target_is_not_direct_indexed_read")
            continue
        original_base, original_index = original_shape
        candidate_base, candidate_index = candidate_shape
        if (
            _integer(proposal.get("original_base")) != original_base
            or _integer(proposal.get("candidate_base")) != candidate_base
            or proposal.get("original_index_expression") != original_index
            or proposal.get("candidate_index_expression") != candidate_index
            or proposal.get("original_target_expression")
            != original_outcome.get("target")
            or proposal.get("candidate_target_expression")
            != candidate_outcome.get("target")
            or _integer(proposal.get("scale")) != 4
        ):
            reject(proposal_index, proposal, "proposal_does_not_match_decoded_table_read")
            continue

        matching_bounds: list[dict[str, Any]] = []
        for bound in region.get("bounds", []):
            original_bound_expression = bound.get("original_expression")
            if original_bound_expression is None and isinstance(
                bound.get("original"), str
            ):
                original_bound_expression = {
                    "op": "input_reg", "reg": bound["original"],
                }
            candidate_bound_expression = bound.get("candidate_expression")
            if candidate_bound_expression is None and isinstance(
                bound.get("candidate"), str
            ):
                candidate_bound_expression = {
                    "op": "input_reg", "reg": bound["candidate"],
                }
            upper = _integer(bound.get("unsigned_lt"))
            if (
                upper is not None
                and 0 < upper <= 4096
                and original_bound_expression == original_index
                and candidate_bound_expression == candidate_index
            ):
                matching_bounds.append(bound)
        index_evidence = proposal.get("index_evidence")
        if (
            len(matching_bounds) != 1
            or not isinstance(index_evidence, dict)
            or index_evidence.get("kind") != "paired_unsigned_bound"
            or index_evidence.get("bound") != matching_bounds[0]
            or index_evidence.get("original_expression") != original_index
            or index_evidence.get("candidate_expression") != candidate_index
            or _integer(index_evidence.get("scale")) != 4
        ):
            reject(proposal_index, proposal, "unique_checked_unsigned_bound_required")
            continue
        upper_exclusive = int(matching_bounds[0]["unsigned_lt"])
        original_index_register = _input_register(original_index)
        candidate_index_register = _input_register(candidate_index)
        if original_index_register is None or candidate_index_register is None:
            reject(
                proposal_index,
                proposal,
                "bounded_table_index_must_be_a_direct_register",
            )
            continue
        exact_index_relations = [
            relation for relation in region.get("input_relations", [])
            if relation.get("relation") == "exact"
            and relation.get("original") == original_index_register
            and relation.get("candidate") == candidate_index_register
        ]
        if len(exact_index_relations) != 1:
            reject(
                proposal_index,
                proposal,
                "unique_exact_index_register_relation_required",
            )
            continue

        matching_values: list[tuple[dict[str, Any], int]] = []
        for value in contract.get("value_targets", []):
            value_id = _integer(value.get("id"))
            original_value = _integer(value.get("original_value"))
            candidate_value = _integer(value.get("candidate_value"))
            mapped_size = _integer(value.get("mapped_size"))
            if (
                value_id is None
                or original_value is None
                or candidate_value is None
                or mapped_size is None
            ):
                continue
            original_offset = original_base - original_value
            candidate_offset = candidate_base - candidate_value
            if (
                original_offset != candidate_offset
                or original_offset < 0
                or original_offset + upper_exclusive * 4 > mapped_size
            ):
                continue
            relocation_offsets = {
                int(offset) for offset in value.get("relocation_offsets", [])
                if _integer(offset) is not None
            }
            required_offsets = {
                original_offset + index * 4 for index in range(upper_exclusive)
            }
            if required_offsets.issubset(relocation_offsets):
                matching_values.append((value, original_offset))
        matching_value_keys = {
            (int(value["id"]), offset) for value, offset in matching_values
        }
        if len(matching_value_keys) != 1 or len(matching_values) != 1:
            reject(
                proposal_index,
                proposal,
                "unique_relocation_backed_value_target_required",
            )
            continue
        table_value, table_offset = matching_values[0]

        original_continuation = _integer(original_outcome.get("continuation"))
        candidate_continuation = _integer(candidate_outcome.get("continuation"))
        if (
            original_continuation is None
            or original_continuation != candidate_continuation
            or original_continuation in duplicate_numeric_ids
            or original_continuation not in region_by_numeric_id
        ):
            reject(proposal_index, proposal, "paired_continuation_is_not_unique")
            continue
        continuation_region_index = region_by_numeric_id[original_continuation]
        continuation_targets = targets_by_region.get(continuation_region_index, [])
        canonical_continuations = [
            target for target in continuation_targets
            if _integer(target.get("original_rva"))
                == _integer(regions[continuation_region_index].get("original", {}).get("rva_start"))
            and _integer(target.get("candidate_rva"))
                == _integer(regions[continuation_region_index].get("candidate", {}).get("rva_start"))
        ]
        if len(canonical_continuations) != 1:
            reject(proposal_index, proposal, "continuation_target_is_not_canonical")
            continue
        continuation_target_id = int(canonical_continuations[0]["id"])
        if (
            len(targets_by_id.get(continuation_target_id, [])) != 1
            or _integer(proposal.get("continuation_region_index"))
                != continuation_region_index
            or _integer(proposal.get("continuation_target_id"))
                != continuation_target_id
        ):
            reject(proposal_index, proposal, "proposal_continuation_is_not_exact")
            continue

        ranges = proposal.get("ranges")
        if (
            not isinstance(ranges, list)
            or len(ranges) != 1
            or _integer(ranges[0].get("original_start")) != original_base
            or _integer(ranges[0].get("candidate_start")) != candidate_base
            or _integer(ranges[0].get("original_end"))
                != original_base + upper_exclusive * 4
            or _integer(ranges[0].get("candidate_end"))
                != candidate_base + upper_exclusive * 4
            or _integer(ranges[0].get("row_count")) != upper_exclusive
            or ranges[0].get("source") != "paired_unsigned_bound"
        ):
            reject(proposal_index, proposal, "table_range_does_not_match_bound")
            continue

        proposed_rows = proposal.get("rows")
        if not isinstance(proposed_rows, list) or len(proposed_rows) != upper_exclusive:
            reject(proposal_index, proposal, "table_rows_do_not_cover_bound")
            continue
        rows_by_index: dict[int, dict[str, Any]] = {}
        row_failure: str | None = None
        for row in proposed_rows:
            if not isinstance(row, dict):
                row_failure = "malformed_table_row"
                break
            original_row_index = _integer(row.get("original_index"))
            candidate_row_index = _integer(row.get("candidate_index"))
            if (
                original_row_index is None
                or original_row_index != candidate_row_index
                or not 0 <= original_row_index < upper_exclusive
                or original_row_index in rows_by_index
            ):
                row_failure = "ambiguous_or_out_of_range_table_row"
                break
            if (
                row.get("kind") != "code_pointer"
                or row.get("relocation_backed") is not True
                or _integer(row.get("original_word")) in {None, 0}
                or _integer(row.get("candidate_word")) in {None, 0}
            ):
                row_failure = "null_sentinel_or_non_relocation_row_not_supported"
                break
            target_id = _integer(row.get("target_id"))
            target_rows = targets_by_id.get(target_id, []) if target_id is not None else []
            if len(target_rows) != 1:
                row_failure = "table_row_target_id_is_not_unique"
                break
            target = target_rows[0]
            target_region_index = _integer(target.get("region_index"))
            if (
                target_region_index is None
                or not 0 <= target_region_index < len(regions)
                or _integer(target.get("original_rva"))
                    != _integer(regions[target_region_index].get("original", {}).get("rva_start"))
                or _integer(target.get("candidate_rva"))
                    != _integer(regions[target_region_index].get("candidate", {}).get("rva_start"))
            ):
                row_failure = "table_row_target_is_not_canonical"
                break
            original_slot = original_base + original_row_index * 4
            candidate_slot = candidate_base + original_row_index * 4
            original_rva = original_slot - original_image_base
            candidate_rva = candidate_slot - candidate_image_base
            original_address = original_image_base + int(target["original_rva"])
            candidate_address = candidate_image_base + int(target["candidate_rva"])
            if (
                _integer(row.get("original_slot")) != original_slot
                or _integer(row.get("candidate_slot")) != candidate_slot
                or _integer(row.get("original_rva")) != original_rva
                or _integer(row.get("candidate_rva")) != candidate_rva
                or _integer(row.get("original_relocation_rva")) != original_rva
                or _integer(row.get("candidate_relocation_rva")) != candidate_rva
                or _integer(row.get("range_index")) != 0
                or int(row["original_word"]) != original_address
                or int(row["candidate_word"]) != candidate_address
            ):
                row_failure = "table_row_does_not_match_slot_relocation_or_target"
                break
            rows_by_index[original_row_index] = row
        if row_failure is not None or set(rows_by_index) != set(range(upper_exclusive)):
            reject(
                proposal_index,
                proposal,
                row_failure or "table_rows_do_not_cover_every_index",
            )
            continue

        rows = [dict(rows_by_index[index]) for index in range(upper_exclusive)]
        entry_target_ids = [int(row["target_id"]) for row in rows]
        target_ids = sorted(set(entry_target_ids))
        if len(target_ids) != len(entry_target_ids):
            reject(
                proposal_index,
                proposal,
                "duplicate_table_targets_not_supported_by_profile",
            )
            continue
        proposed_target_ids = proposal.get("target_ids")
        if (
            not isinstance(proposed_target_ids, list)
            or any(_integer(value) is None for value in proposed_target_ids)
            or [int(value) for value in proposed_target_ids] != target_ids
        ):
            reject(proposal_index, proposal, "finite_target_inventory_is_not_canonical")
            continue

        candidates.append({
            "input_contract": "bounded_immutable_code_pointer_table_call_v1",
            "profile": "immutable_code_pointer_table_call_v1",
            "shape": "direct_indexed_table_read",
            "source_region_index": source,
            "continuation_region_index": continuation_region_index,
            "continuation_target_id": continuation_target_id,
            "original_base": original_base,
            "candidate_base": candidate_base,
            "value_target_id": int(table_value["id"]),
            "table_offset": table_offset,
            "scale": 4,
            "upper_exclusive": upper_exclusive,
            "original_index_register": original_index_register,
            "candidate_index_register": candidate_index_register,
            "original_index_expression": original_index,
            "candidate_index_expression": candidate_index,
            "original_target_expression": original_outcome["target"],
            "candidate_target_expression": candidate_outcome["target"],
            "bound": dict(matching_bounds[0]),
            "rows": rows,
            "entry_target_ids": entry_target_ids,
            "target_ids": target_ids,
            "status": "candidate_requires_lean_replay",
            "acceptance_authority": False,
        })

    candidates.sort(key=lambda candidate: int(candidate["source_region_index"]))
    incomplete.sort(key=lambda row: int(row["proposal_index"]))
    if incomplete:
        status = "incomplete"
    elif candidates:
        status = "candidate_requires_lean_replay"
    else:
        status = "not_applicable"
    return {
        "format": "stage-a-bounded-immutable-code-pointer-table-call-input-v1",
        "status": status,
        "acceptance_authority": False,
        "candidates": candidates,
        "incomplete": incomplete,
    }


def _direct_immutable_code_pointer_table_call_candidate(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    region: dict[str, Any],
    original_outcome: dict[str, Any],
    candidate_outcome: dict[str, Any],
) -> dict[str, Any] | None:
    original_shape = _indexed_u32_table_read(original_outcome.get("target"))
    candidate_shape = _indexed_u32_table_read(candidate_outcome.get("target"))
    if original_shape is None or candidate_shape is None:
        return None
    original_base, original_index = original_shape
    candidate_base, candidate_index = candidate_shape

    matching_bounds: list[dict[str, Any]] = []
    for bound in region.get("bounds", []):
        original_bound_expression = bound.get("original_expression") or {
            "op": "input_reg", "reg": str(bound.get("original")),
        }
        candidate_bound_expression = bound.get("candidate_expression") or {
            "op": "input_reg", "reg": str(bound.get("candidate")),
        }
        upper = _integer(bound.get("unsigned_lt"))
        if (
            upper is not None
            and upper > 0
            and original_bound_expression == original_index
            and candidate_bound_expression == candidate_index
        ):
            matching_bounds.append(bound)

    ranges: list[dict[str, Any]]
    index_evidence: dict[str, Any]
    if len(matching_bounds) == 1:
        upper_exclusive = int(matching_bounds[0]["unsigned_lt"])
        ranges = [{
            "original_start": original_base,
            "original_end": original_base + upper_exclusive * 4,
            "candidate_start": candidate_base,
            "candidate_end": candidate_base + upper_exclusive * 4,
            "source": "paired_unsigned_bound",
        }]
        index_evidence = {
            "kind": "paired_unsigned_bound",
            "bound": matching_bounds[0],
            "original_expression": original_index,
            "candidate_expression": candidate_index,
            "scale": 4,
        }
    elif not matching_bounds:
        reverse_evidence = _reverse_sentinel_table_index_evidence(
            original_bin,
            candidate_bin,
            contract,
            behaviors,
            region,
            original_base,
            candidate_base,
            original_index,
            candidate_index,
        )
        if reverse_evidence is None:
            return None
        ranges = [reverse_evidence.pop("range")]
        index_evidence = reverse_evidence
    else:
        return None

    checked_ranges = _paired_immutable_code_pointer_table_ranges(
        original_bin, candidate_bin, contract, ranges
    )
    if checked_ranges is None:
        return None
    checked_range_rows, rows = checked_ranges
    return {
        "shape": "direct_indexed_table_read",
        "original_base": original_base,
        "candidate_base": candidate_base,
        "scale": 4,
        "original_index_expression": original_index,
        "candidate_index_expression": candidate_index,
        "index_evidence": index_evidence,
        "ranges": checked_range_rows,
        "rows": rows,
        "target_ids": sorted({
            int(row["target_id"]) for row in rows if "target_id" in row
        }),
    }


def _cursor_immutable_code_pointer_table_call_candidate(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    region: dict[str, Any],
    source_index: int,
    original_outcome: dict[str, Any],
    candidate_outcome: dict[str, Any],
) -> dict[str, Any] | None:
    original_target_register = _input_register(original_outcome.get("target"))
    candidate_target_register = _input_register(candidate_outcome.get("target"))
    if original_target_register is None or candidate_target_register is None:
        return None
    function_id = region.get("function_id")
    if function_id is None:
        return None
    source_numeric_id = int(region["numeric_id"])

    producers: list[tuple[int, str, str]] = []
    for producer_index, (producer_region, producer_pair) in enumerate(zip(
        contract.get("regions", []), behaviors, strict=True
    )):
        if producer_region.get("function_id") != function_id:
            continue
        original_ir = producer_pair["original_ir"]
        candidate_ir = producer_pair["candidate_ir"]
        original_cursor = _input_register_read32(
            (original_ir.get("registers") or {}).get(original_target_register)
        )
        candidate_cursor = _input_register_read32(
            (candidate_ir.get("registers") or {}).get(candidate_target_register)
        )
        original_exit = original_ir.get("outcome") or {}
        candidate_exit = candidate_ir.get("outcome") or {}
        if (
            original_cursor is not None
            and candidate_cursor is not None
            and original_exit.get("op") == "branch"
            and candidate_exit.get("op") == "branch"
            and int(original_exit.get("fallthrough", -1)) == source_numeric_id
            and int(candidate_exit.get("fallthrough", -1)) == source_numeric_id
            and _is_zero_test(
                original_exit.get("condition"),
                {"op": "read32", "address": {
                    "op": "input_reg", "reg": original_cursor,
                }},
            )
            and _is_zero_test(
                candidate_exit.get("condition"),
                {"op": "read32", "address": {
                    "op": "input_reg", "reg": candidate_cursor,
                }},
            )
        ):
            producers.append((producer_index, original_cursor, candidate_cursor))
    if len(producers) != 1:
        return None
    producer_index, original_cursor, candidate_cursor = producers[0]
    producer_numeric_id = int(contract["regions"][producer_index]["numeric_id"])

    steps: list[tuple[int, str, str]] = []
    for step_index, (step_region, step_pair) in enumerate(zip(
        contract.get("regions", []), behaviors, strict=True
    )):
        if step_region.get("function_id") != function_id:
            continue
        original_ir = step_pair["original_ir"]
        candidate_ir = step_pair["candidate_ir"]
        original_step = _input_register_add(
            (original_ir.get("registers") or {}).get(original_cursor),
            original_cursor,
        )
        candidate_step = _input_register_add(
            (candidate_ir.get("registers") or {}).get(candidate_cursor),
            candidate_cursor,
        )
        original_exit = original_ir.get("outcome") or {}
        candidate_exit = candidate_ir.get("outcome") or {}
        if (
            original_step == 4
            and candidate_step == 4
            and original_exit.get("op") == "branch"
            and candidate_exit.get("op") == "branch"
            and int(original_exit.get("taken", -1)) == producer_numeric_id
            and int(candidate_exit.get("taken", -1)) == producer_numeric_id
        ):
            original_bound_register = _unsigned_less_bound_register(
                original_exit.get("condition"), original_cursor, 4
            )
            candidate_bound_register = _unsigned_less_bound_register(
                candidate_exit.get("condition"), candidate_cursor, 4
            )
            if (
                original_bound_register is not None
                and candidate_bound_register is not None
            ):
                steps.append((
                    step_index, original_bound_register, candidate_bound_register,
                ))
    if len(steps) != 1:
        return None
    step_index, original_bound_register, candidate_bound_register = steps[0]

    entry_regions = [
        index for index, candidate_region in enumerate(contract.get("regions", []))
        if candidate_region.get("function_id") == function_id
        and bool(candidate_region.get("function_entry"))
    ]
    if len(entry_regions) != 1:
        return None
    entry_region_index = entry_regions[0]
    entry_numeric_id = int(contract["regions"][entry_region_index]["numeric_id"])
    caller_ranges: list[dict[str, Any]] = []
    caller_indices: list[int] = []
    for caller_index, behavior_pair in enumerate(behaviors):
        original_ir = behavior_pair["original_ir"]
        candidate_ir = behavior_pair["candidate_ir"]
        original_exit = original_ir.get("outcome") or {}
        candidate_exit = candidate_ir.get("outcome") or {}
        original_calls_entry = (
            original_exit.get("op") == "call"
            and _integer(original_exit.get("target")) == entry_numeric_id
        )
        candidate_calls_entry = (
            candidate_exit.get("op") == "call"
            and _integer(candidate_exit.get("target")) == entry_numeric_id
        )
        if not original_calls_entry and not candidate_calls_entry:
            continue
        if not original_calls_entry or not candidate_calls_entry:
            return None
        original_arguments = _constant_stack_call_arguments(original_ir)
        candidate_arguments = _constant_stack_call_arguments(candidate_ir)
        if original_arguments is None or candidate_arguments is None:
            return None
        caller_indices.append(caller_index)
        caller_ranges.append({
            "original_start": original_arguments[0],
            "original_end": original_arguments[1],
            "candidate_start": candidate_arguments[0],
            "candidate_end": candidate_arguments[1],
            "source": "paired_static_call_arguments",
            "callsite_region_index": caller_index,
        })
    if not caller_ranges:
        return None

    checked_ranges = _paired_immutable_code_pointer_table_ranges(
        original_bin, candidate_bin, contract, caller_ranges
    )
    if checked_ranges is None:
        return None
    checked_range_rows, rows = checked_ranges
    return {
        "shape": "cursor_loaded_table_word",
        "original_target_register": original_target_register,
        "candidate_target_register": candidate_target_register,
        "original_cursor_register": original_cursor,
        "candidate_cursor_register": candidate_cursor,
        "original_bound_register": original_bound_register,
        "candidate_bound_register": candidate_bound_register,
        "scale": 4,
        "index_evidence": {
            "kind": "paired_static_call_range_cursor",
            "function_entry_region_index": entry_region_index,
            "producer_region_index": producer_index,
            "step_region_index": step_index,
            "callsite_region_indices": caller_indices,
            "original_expression": {
                "op": "input_reg", "reg": original_cursor,
            },
            "candidate_expression": {
                "op": "input_reg", "reg": candidate_cursor,
            },
            "scale": 4,
        },
        "ranges": checked_range_rows,
        "rows": rows,
        "target_ids": sorted({
            int(row["target_id"]) for row in rows if "target_id" in row
        }),
    }


def _reverse_sentinel_table_index_evidence(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    region: dict[str, Any],
    original_base: int,
    candidate_base: int,
    original_index: dict[str, Any],
    candidate_index: dict[str, Any],
) -> dict[str, Any] | None:
    original_register = _input_register(original_index)
    candidate_register = _input_register(candidate_index)
    if original_register is None or candidate_register is None:
        return None
    if (
        _immutable_section_u32(original_bin, original_base) != 0xFFFFFFFF
        or _immutable_section_u32(candidate_bin, candidate_base) != 0xFFFFFFFF
    ):
        return None
    function_id = region.get("function_id")
    if function_id is None:
        return None
    source_numeric_id = int(region["numeric_id"])

    header_producers = []
    decrement_regions = []
    nonzero_predecessors = []
    scanner_steps: list[tuple[int, str, str]] = []
    for region_index, (candidate_region, pair) in enumerate(zip(
        contract.get("regions", []), behaviors, strict=True
    )):
        if candidate_region.get("function_id") != function_id:
            continue
        original_ir = pair["original_ir"]
        candidate_ir = pair["candidate_ir"]
        original_registers = original_ir.get("registers") or {}
        candidate_registers = candidate_ir.get("registers") or {}
        if (
            _static_u32_read_address(original_registers.get(original_register))
                == original_base
            and _static_u32_read_address(candidate_registers.get(candidate_register))
                == candidate_base
        ):
            header_producers.append(region_index)

        original_decrement = _input_register_sub(
            original_registers.get(original_register), original_register
        )
        candidate_decrement = _input_register_sub(
            candidate_registers.get(candidate_register), candidate_register
        )
        original_exit = original_ir.get("outcome") or {}
        candidate_exit = candidate_ir.get("outcome") or {}
        if (
            original_decrement == 1
            and candidate_decrement == 1
            and original_exit.get("op") == "branch"
            and candidate_exit.get("op") == "branch"
            and int(original_exit.get("taken", -1)) == source_numeric_id
            and int(candidate_exit.get("taken", -1)) == source_numeric_id
            and _is_nonzero_test(
                original_exit.get("condition"),
                original_registers[original_register],
            )
            and _is_nonzero_test(
                candidate_exit.get("condition"),
                candidate_registers[candidate_register],
            )
        ):
            decrement_regions.append(region_index)

        if (
            original_exit.get("op") == "branch"
            and candidate_exit.get("op") == "branch"
            and int(original_exit.get("fallthrough", -1)) == source_numeric_id
            and int(candidate_exit.get("fallthrough", -1)) == source_numeric_id
            and _is_zero_test(
                original_exit.get("condition"), original_index
            )
            and _is_zero_test(
                candidate_exit.get("condition"), candidate_index
            )
        ):
            nonzero_predecessors.append(region_index)

        for original_scan_register, original_scan_expression in original_registers.items():
            if _input_register_add(original_scan_expression, original_scan_register) != 1:
                continue
            for candidate_scan_register, candidate_scan_expression in candidate_registers.items():
                if _input_register_add(candidate_scan_expression, candidate_scan_register) != 1:
                    continue
                if (
                    original_registers.get(original_register) != {
                        "op": "input_reg", "reg": original_scan_register,
                    }
                    or candidate_registers.get(candidate_register) != {
                        "op": "input_reg", "reg": candidate_scan_register,
                    }
                ):
                    continue
                original_scan_index = original_scan_expression
                candidate_scan_index = candidate_scan_expression
                original_reads_table = any(
                    _indexed_u32_table_read(expression)
                        == (original_base, original_scan_index)
                    for expression in original_registers.values()
                    if isinstance(expression, dict)
                )
                candidate_reads_table = any(
                    _indexed_u32_table_read(expression)
                        == (candidate_base, candidate_scan_index)
                    for expression in candidate_registers.values()
                    if isinstance(expression, dict)
                )
                if original_reads_table and candidate_reads_table:
                    scanner_steps.append((
                        region_index,
                        original_scan_register,
                        candidate_scan_register,
                    ))
    if not (
        len(header_producers) == 1
        and len(decrement_regions) == 1
        and len(nonzero_predecessors) == 1
        and len(scanner_steps) == 1
    ):
        return None

    scanner_region_index, original_scan_register, candidate_scan_register = (
        scanner_steps[0]
    )
    scanner_numeric_id = int(contract["regions"][scanner_region_index]["numeric_id"])
    scanner_initializers = []
    scanner_loops = []
    for region_index, (candidate_region, pair) in enumerate(zip(
        contract.get("regions", []), behaviors, strict=True
    )):
        if candidate_region.get("function_id") != function_id:
            continue
        original_ir = pair["original_ir"]
        candidate_ir = pair["candidate_ir"]
        original_exit = original_ir.get("outcome") or {}
        candidate_exit = candidate_ir.get("outcome") or {}
        if (
            original_exit.get("op") == "jump"
            and candidate_exit.get("op") == "jump"
            and int(original_exit.get("target", -1)) == scanner_numeric_id
            and int(candidate_exit.get("target", -1)) == scanner_numeric_id
            and (original_ir.get("registers") or {}).get(original_scan_register)
                == {"op": "constant", "value": 0}
            and (candidate_ir.get("registers") or {}).get(candidate_scan_register)
                == {"op": "constant", "value": 0}
        ):
            scanner_initializers.append(region_index)
        if (
            original_exit.get("op") == "branch"
            and candidate_exit.get("op") == "branch"
            and int(original_exit.get("taken", -1)) == scanner_numeric_id
            and int(candidate_exit.get("taken", -1)) == scanner_numeric_id
        ):
            scanner_loops.append(region_index)
    if len(scanner_initializers) != 1 or len(scanner_loops) != 1:
        return None

    terminator = _paired_immutable_table_terminator(
        original_bin, candidate_bin, contract, original_base, candidate_base
    )
    if terminator is None:
        return None
    original_end, candidate_end = terminator
    return {
        "kind": "paired_sentinel_terminated_reverse_count",
        "original_expression": original_index,
        "candidate_expression": candidate_index,
        "scale": 4,
        "header_producer_region_index": header_producers[0],
        "nonzero_predecessor_region_index": nonzero_predecessors[0],
        "decrement_region_index": decrement_regions[0],
        "scanner_initializer_region_index": scanner_initializers[0],
        "scanner_region_index": scanner_region_index,
        "scanner_loop_region_index": scanner_loops[0],
        "range": {
            "original_start": original_base + 4,
            "original_end": original_end,
            "candidate_start": candidate_base + 4,
            "candidate_end": candidate_end,
            "source": "paired_sentinel_terminated_reverse_count",
        },
    }


def _paired_immutable_table_terminator(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    original_base: int,
    candidate_base: int,
) -> tuple[int, int] | None:
    for index in range(1, 4097):
        original_slot = original_base + index * 4
        candidate_slot = candidate_base + index * 4
        original_word = _immutable_section_u32(original_bin, original_slot)
        candidate_word = _immutable_section_u32(candidate_bin, candidate_slot)
        if original_word is None or candidate_word is None:
            return None
        if original_word == 0 and candidate_word == 0:
            return original_slot + 4, candidate_slot + 4
        if _paired_relocated_code_pointer_row(
            original_bin,
            candidate_bin,
            contract,
            original_slot,
            candidate_slot,
            index,
        ) is None:
            return None
    return None


def _paired_immutable_code_pointer_table_ranges(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    ranges: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None:
    if original_bin.bitness != 32 or candidate_bin.bitness != 32:
        return None
    checked_ranges: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    total_rows = 0
    for range_index, candidate_range in enumerate(ranges):
        original_start_value = _integer(candidate_range.get("original_start"))
        candidate_start_value = _integer(candidate_range.get("candidate_start"))
        original_end_value = _integer(candidate_range.get("original_end"))
        candidate_end_value = _integer(candidate_range.get("candidate_end"))
        if (
            original_start_value is None
            or candidate_start_value is None
            or original_end_value is None
            or candidate_end_value is None
        ):
            return None
        original_start = int(original_start_value)
        candidate_start = int(candidate_start_value)
        original_end = int(original_end_value)
        candidate_end = int(candidate_end_value)
        original_size = original_end - original_start
        candidate_size = candidate_end - candidate_start
        if (
            original_size <= 0
            or original_size != candidate_size
            or original_size % 4 != 0
            or original_start % 4 != 0
            or candidate_start % 4 != 0
        ):
            return None
        row_count = original_size // 4
        total_rows += row_count
        if total_rows > 4096:
            return None
        checked_range = dict(candidate_range)
        checked_range["row_count"] = row_count
        checked_ranges.append(checked_range)
        for row_index in range(row_count):
            original_slot = original_start + row_index * 4
            candidate_slot = candidate_start + row_index * 4
            original_word = _immutable_section_u32(original_bin, original_slot)
            candidate_word = _immutable_section_u32(candidate_bin, candidate_slot)
            if original_word is None or candidate_word is None:
                return None
            if original_word == 0 and candidate_word == 0:
                row: dict[str, Any] = {
                    "kind": "null",
                    "original_slot": original_slot,
                    "candidate_slot": candidate_slot,
                    "original_rva": original_slot - original_bin.image_base,
                    "candidate_rva": candidate_slot - candidate_bin.image_base,
                    "original_index": row_index,
                    "candidate_index": row_index,
                    "range_index": range_index,
                    "relocation_backed": False,
                }
            else:
                row = _paired_relocated_code_pointer_row(
                    original_bin,
                    candidate_bin,
                    contract,
                    original_slot,
                    candidate_slot,
                    row_index,
                ) or {}
                if not row:
                    return None
                row["range_index"] = range_index
            rows.append(row)
    return checked_ranges, rows


def _paired_relocated_code_pointer_row(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    original_slot: int,
    candidate_slot: int,
    row_index: int,
) -> dict[str, Any] | None:
    original_word = _immutable_section_u32(original_bin, original_slot)
    candidate_word = _immutable_section_u32(candidate_bin, candidate_slot)
    if (
        original_word is None
        or original_word == 0
        or candidate_word is None
        or candidate_word == 0
    ):
        return None
    original_rva = original_slot - original_bin.image_base
    candidate_rva = candidate_slot - candidate_bin.image_base
    if (
        original_rva not in _base_relocation_rvas(original_bin)
        or candidate_rva not in _base_relocation_rvas(candidate_bin)
    ):
        return None
    matches = {
        int(target["id"])
        for target in contract.get("code_targets", [])
        if _absolute_code_target_matches(
            original_bin, target, "original", original_word
        )
        and _absolute_code_target_matches(
            candidate_bin, target, "candidate", candidate_word
        )
    }
    if len(matches) != 1:
        return None
    return {
        "kind": "code_pointer",
        "target_id": next(iter(matches)),
        "original_slot": original_slot,
        "candidate_slot": candidate_slot,
        "original_rva": original_rva,
        "candidate_rva": candidate_rva,
        "original_index": row_index,
        "candidate_index": row_index,
        "original_word": original_word,
        "candidate_word": candidate_word,
        "original_relocation_rva": original_rva,
        "candidate_relocation_rva": candidate_rva,
        "relocation_backed": True,
    }


def _base_relocation_rvas(binary: StageABinary) -> set[int]:
    relocation_type = 3 if binary.bitness == 32 else 10
    return {
        int(entry.rva)
        for block in getattr(binary.pe, "DIRECTORY_ENTRY_BASERELOC", []) or []
        for entry in block.entries
        if int(entry.type) == relocation_type
    }


def _immutable_section_u32(binary: StageABinary, absolute: int) -> int | None:
    if absolute < binary.image_base:
        return None
    rva = absolute - binary.image_base
    if not any(
        not section.writable
        and section.rva_start <= rva
        and rva + 4 <= section.rva_end
        for section in binary.sections
    ):
        return None
    return _immutable_image_u32(binary, absolute)


def _input_register(expression: Any) -> str | None:
    if not isinstance(expression, dict) or expression.get("op") != "input_reg":
        return None
    register = expression.get("reg")
    return str(register) if register is not None else None


def _input_register_read32(expression: Any) -> str | None:
    if not isinstance(expression, dict) or expression.get("op") != "read32":
        return None
    return _input_register(expression.get("address"))


def _input_register_add(expression: Any, register: str) -> int | None:
    return _input_register_arithmetic(expression, register, "add")


def _input_register_sub(expression: Any, register: str) -> int | None:
    return _input_register_arithmetic(expression, register, "sub")


def _input_register_arithmetic(
    expression: Any, register: str, operation: str,
) -> int | None:
    if not isinstance(expression, dict) or expression.get("op") != operation:
        return None
    if _input_register(expression.get("left")) != register:
        return None
    right = expression.get("right")
    if not isinstance(right, dict) or right.get("op") != "constant":
        return None
    return _integer(right.get("value"))


def _is_zero_test(condition: Any, expression: dict[str, Any]) -> bool:
    if not isinstance(condition, dict) or condition.get("op") != "equal":
        return False
    left = condition.get("left")
    right = condition.get("right")
    if left == {"op": "constant", "value": 0}:
        left, right = right, left
    if right != {"op": "constant", "value": 0}:
        return False
    return left == expression or (
        isinstance(left, dict)
        and left.get("op") == "bit_and"
        and left.get("left") == expression
        and left.get("right") == expression
    )


def _is_nonzero_test(condition: Any, expression: dict[str, Any]) -> bool:
    return (
        isinstance(condition, dict)
        and condition.get("op") == "not"
        and _is_zero_test(condition.get("value"), expression)
    )


def _unsigned_less_bound_register(
    condition: Any, cursor_register: str, step: int,
) -> str | None:
    if not isinstance(condition, dict) or condition.get("op") != "unsigned_less":
        return None
    if _input_register_add(condition.get("left"), cursor_register) != step:
        return None
    return _input_register(condition.get("right"))


def _static_u32_read_address(expression: Any) -> int | None:
    if not isinstance(expression, dict):
        return None
    direct = _constant_read32_address(expression)
    if direct is not None:
        return direct
    assembled = _assembled_u32_after_register_writes(expression)
    return int(assembled[0]) if assembled is not None else None


def _constant_stack_call_arguments(
    behavior: dict[str, Any],
) -> tuple[int, int] | None:
    values: dict[int, list[int]] = defaultdict(list)
    for write in behavior.get("writes", []):
        offset = _stack_pointer_offset(write.get("address"))
        value = write.get("value")
        if (
            offset in {0, 4}
            and isinstance(value, dict)
            and value.get("op") == "constant"
            and _integer(value.get("value")) is not None
        ):
            values[offset].append(int(value["value"]))
    if len(values[0]) != 1 or len(values[4]) != 1:
        return None
    return values[0][0], values[4][0]


def _stack_pointer_offset(expression: Any) -> int | None:
    if _input_register(expression) == "esp":
        return 0
    if not isinstance(expression, dict) or expression.get("op") != "add":
        return None
    left = expression.get("left")
    right = expression.get("right")
    if _input_register(right) == "esp":
        left, right = right, left
    if _input_register(left) != "esp" or not isinstance(right, dict):
        return None
    if right.get("op") != "constant":
        return None
    return _integer(right.get("value"))


def _bounded_immutable_relocation_table_jump_candidate(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    region: dict[str, Any],
    source_index: int,
    original_outcome: dict[str, Any],
    candidate_outcome: dict[str, Any],
) -> dict[str, Any] | None:
    original_shape = _indexed_u32_table_read(original_outcome.get("target"))
    candidate_shape = _indexed_u32_table_read(candidate_outcome.get("target"))
    if original_shape is None or candidate_shape is None:
        return None
    original_base, original_index = original_shape
    candidate_base, candidate_index = candidate_shape

    matching_bounds: list[dict[str, Any]] = []
    for bound in region.get("bounds", []):
        original_bound_expression = bound.get("original_expression") or {
            "op": "input_reg",
            "reg": str(bound.get("original")),
        }
        candidate_bound_expression = bound.get("candidate_expression") or {
            "op": "input_reg",
            "reg": str(bound.get("candidate")),
        }
        upper = _integer(bound.get("unsigned_lt"))
        if (
            upper is not None
            and upper > 0
            and original_bound_expression == original_index
            and candidate_bound_expression == candidate_index
        ):
            matching_bounds.append(bound)
    if len(matching_bounds) != 1:
        return None
    upper_exclusive = int(matching_bounds[0]["unsigned_lt"])

    matching_values = []
    for value in contract.get("value_targets", []):
        original_offset = original_base - int(value["original_value"])
        candidate_offset = candidate_base - int(value["candidate_value"])
        if (
            original_offset != candidate_offset
            or original_offset < 0
            or original_offset + upper_exclusive * 4 > int(value["mapped_size"])
        ):
            continue
        required_offsets = {
            original_offset + index * 4 for index in range(upper_exclusive)
        }
        if not required_offsets.issubset({
            int(offset) for offset in value.get("relocation_offsets", [])
        }):
            continue
        matching_values.append((value, original_offset))
    matching_value_keys = {
        (int(value["id"]), offset) for value, offset in matching_values
    }
    if len(matching_value_keys) != 1:
        return None
    table, table_offset = matching_values[0]

    code_targets = contract.get("code_targets", [])
    entry_target_ids: list[int] = []
    for index in range(upper_exclusive):
        original_word = _immutable_image_u32(
            original_bin, original_base + index * 4
        )
        candidate_word = _immutable_image_u32(
            candidate_bin, candidate_base + index * 4
        )
        if original_word is None or candidate_word is None:
            return None
        matches = [
            target for target in code_targets
            if _absolute_code_target_matches(
                original_bin, target, "original", original_word
            )
            and _absolute_code_target_matches(
                candidate_bin, target, "candidate", candidate_word
            )
        ]
        matching_target_ids = {int(target["id"]) for target in matches}
        if len(matching_target_ids) != 1:
            return None
        entry_target_ids.append(next(iter(matching_target_ids)))

    target_ids = sorted(set(entry_target_ids))
    available_target_ids = {
        int(item["id"]) for item in region.get("code_targets", [])
    }
    if not target_ids or not set(target_ids).issubset(available_target_ids):
        return None
    return {
        "profile": "bounded_immutable_relocation_table_jump_v1",
        "source_region_index": source_index,
        "value_target_id": int(table["id"]),
        "table_offset": table_offset,
        "original_base": original_base,
        "candidate_base": candidate_base,
        "original_index_expression": original_index,
        "candidate_index_expression": candidate_index,
        "upper_exclusive": upper_exclusive,
        "entry_target_ids": entry_target_ids,
        "target_ids": target_ids,
    }


def _indexed_u32_table_read(
    expression: Any,
) -> tuple[int, dict[str, Any]] | None:
    if not isinstance(expression, dict) or expression.get("op") != "read32":
        return None
    address = expression.get("address")
    if not isinstance(address, dict) or address.get("op") != "add":
        return None
    left = address.get("left")
    right = address.get("right")
    if isinstance(left, dict) and left.get("op") == "constant":
        left, right = right, left
    if (
        not isinstance(left, dict)
        or left.get("op") != "shift_left"
        or _integer(left.get("amount")) != 2
        or not isinstance(left.get("value"), dict)
        or not isinstance(right, dict)
        or right.get("op") != "constant"
    ):
        return None
    base = _integer(right.get("value"))
    if base is None or not 0 <= base < 2**32:
        return None
    return base, left["value"]


def _absolute_code_target_matches(
    binary: StageABinary,
    target: dict[str, Any],
    side: str,
    absolute: int,
) -> bool:
    rvas = [
        int(target[f"{side}_rva"]),
        *(int(alias) for alias in target.get(f"{side}_aliases", [])),
    ]
    return absolute in {binary.image_base + rva for rva in rvas}


def _indirect_control_expression_provenance(
    expression: Any,
    operation: str,
) -> str:
    if operation == "checked_continue":
        return "decoded_continue_without_target"
    if not isinstance(expression, dict):
        return "missing_target_expression"
    expression_op = expression.get("op")
    if expression_op == "constant":
        return "constant_code_address"
    if expression_op == "input_reg":
        return "register_word_without_producer_certificate"
    if expression_op == "read32":
        return _indirect_memory_address_provenance(expression.get("address"))
    read_addresses = _collect_byte_read_addresses(expression)
    if read_addresses:
        address_classes = {
            _indirect_memory_address_provenance(address)
            for address in read_addresses
        }
        if len(address_classes) == 1:
            return "assembled_" + next(iter(address_classes))
        return "assembled_mixed_memory_words"
    return "computed_word_without_producer_certificate"


def _indirect_memory_address_provenance(expression: Any) -> str:
    if not isinstance(expression, dict):
        return "memory_word_with_unknown_address"
    if expression.get("op") == "constant":
        return "static_word_without_immutability_certificate"
    if expression.get("op") != "add":
        return "memory_word_with_computed_address"
    left = expression.get("left")
    right = expression.get("right")
    operands = [item for item in (left, right) if isinstance(item, dict)]
    registers = {
        str(item.get("reg"))
        for item in operands
        if item.get("op") == "input_reg"
    }
    if registers.intersection({"esp", "ebp"}):
        return "stack_word_without_code_pointer_producer"
    if any(item.get("op") == "shift_left" for item in operands):
        return "indexed_static_word_without_finite_table_certificate"
    if registers:
        return "dynamic_memory_word_without_typed_range"
    return "memory_word_with_computed_address"


def _collect_byte_read_addresses(expression: Any) -> list[dict[str, Any]]:
    if not isinstance(expression, dict):
        return []
    if expression.get("op") in {"read8", "read8_after_write"}:
        address = expression.get("address")
        return [address] if isinstance(address, dict) else []
    result: list[dict[str, Any]] = []
    for value in expression.values():
        if isinstance(value, dict):
            result.extend(_collect_byte_read_addresses(value))
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
            } not in relation.get("active_words", []):
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
    if any(
        imported.thunk_rva is not None
        and rva < int(imported.thunk_rva) + 4
        and int(imported.thunk_rva) < rva + 4
        for imported in binary.imports
    ):
        return None
    in_headers = rva + 4 <= binary.size_of_headers
    in_immutable_section = any(
        not section.writable
        and section.rva_start <= rva
        and rva + 4 <= section.rva_end
        for section in binary.sections
    )
    if not in_headers and not in_immutable_section:
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
