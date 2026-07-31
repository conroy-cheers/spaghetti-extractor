from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any, Mapping

from ...stage_binary import StageABinary, StageAInputError
from ...util import sha256_bytes
from ..contract import _raw_base_relocations
from ..extraction import _assembled_u32_after_register_writes
from ..model import _semantic_constant_bool
from ..schema import integer as _integer
from .external import (
    _select_machine_import_call_contract,
    _semantic_external_target_identity,
)
from .semantic_control import _semantic_edges


_FINITE_STATIC_TABLE_JUMP_PROFILES = {
    "bounded_immutable_relocation_table_jump_v1",
    "predecessor_bounded_immutable_relocation_table_jump_v1",
}


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
        "bulk_fill": "bulkFill",
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
            "candidate_kind": kind_names.get(
                str(relation_edge.get("candidate_kind", relation_edge.get("kind")))
            ),
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
        if indirect_candidate.get("profile") not in (
            _FINITE_STATIC_TABLE_JUMP_PROFILES
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
            edge = {
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
            }
            if indirect_candidate["profile"] == (
                "bounded_immutable_relocation_table_jump_v1"
            ):
                edge["bounded_relocation_table_candidate_index"] = (
                    candidate_index
                )
            else:
                edge["finite_static_table_candidate_index"] = candidate_index
            edges.append(edge)
        edge_group = {
            "source_node_id": source,
            "candidate_index": candidate_index,
            "edge_ids": edge_ids,
        }
        if indirect_candidate["profile"] != (
            "bounded_immutable_relocation_table_jump_v1"
        ):
            edge_group.update({
                "profile": indirect_candidate["profile"],
                "target_ids": [
                    int(target_id)
                    for target_id in indirect_candidate["target_ids"]
                ],
            })
        bounded_table_edge_groups.append(edge_group)

    bounded_table_call_edge_groups: list[dict[str, Any]] = []
    bounded_table_call_sources: set[int] = set()
    for candidate_index, table_candidate in enumerate(
        bounded_table_call_candidates or []
    ):
        direct_table = (
            table_candidate.get("shape") == "direct_indexed_table_read"
            and table_candidate.get("layout") in {
                "zeroBasedBounded", "sentinelTerminatedReverseCount",
            }
        )
        cursor_table = (
            table_candidate.get("shape") == "cursor_loaded_table_word"
            and table_candidate.get("layout") == "staticCallRangeCursor"
        )
        if (
            table_candidate.get("profile")
            != "immutable_code_pointer_table_call_v1"
            or table_candidate.get("input_contract")
            != "bounded_immutable_code_pointer_table_call_v1"
            or not (direct_table or cursor_table)
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

        edge_ids: list[int] = []
        singleton_target = len(table_candidate["target_ids"]) == 1
        for target_id_value in table_candidate["target_ids"]:
            target_id = int(target_id_value)
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
                "original_guard": (
                    {"op": "bool_constant", "value": True}
                    if singleton_target
                    else code_target_guard(
                        original_outcome["target"],
                        original_image_base,
                        int(target["original_rva"]),
                        [
                            int(alias)
                            for alias in target.get("original_aliases", [])
                        ],
                    )
                ),
                "candidate_guard": (
                    {"op": "bool_constant", "value": True}
                    if singleton_target
                    else code_target_guard(
                        candidate_outcome["target"],
                        candidate_image_base,
                        int(target["candidate_rva"]),
                        [
                            int(alias)
                            for alias in target.get("candidate_aliases", [])
                        ],
                    )
                ),
                "infeasible": False,
                "bounded_code_pointer_table_call_candidate_index": candidate_index,
            })
        if (
            not edge_ids
            and table_candidate.get("layout") not in {
                "sentinelTerminatedReverseCount", "staticCallRangeCursor",
            }
        ):
            raise StageAInputError(
                f"bounded table-call source {source} has an empty finite target set"
            )
        bounded_table_call_edge_groups.append({
            "source_node_id": source,
            "candidate_index": candidate_index,
            "edge_ids": edge_ids,
            "target_ids": [
                int(target_id) for target_id in table_candidate["target_ids"]
            ],
        })

    submitted_indirect_sources = {
        int(candidate["source_region_index"])
        for candidates in (
            indirect_call_candidates or [],
            bounded_table_candidates or [],
            bounded_table_call_candidates or [],
            dynamic_call_candidates or [],
            import_call_candidates or [],
        )
        for candidate in candidates
    }
    provenance_candidates = _indirect_provenance_dataflow_candidates(
        contract,
        behaviors,
        register_relations,
        original_image_base=original_image_base,
        candidate_image_base=candidate_image_base,
        import_register_seeds=import_register_seeds,
        import_call_candidates=import_call_candidates,
        excluded_source_indices=submitted_indirect_sources,
    )
    provenance_edge_groups: list[dict[str, Any]] = []
    for candidate_index, provenance_candidate in enumerate(
        provenance_candidates
    ):
        source = int(provenance_candidate["source_region_index"])
        if not 0 <= source < len(node_targets):
            raise StageAInputError(
                f"indirect provenance source {source} is out of range"
            )
        if outgoing[source]:
            raise StageAInputError(
                f"indirect provenance source {source} already has submitted edges"
            )
        original_outcome = behaviors[source]["original_ir"].get("outcome") or {}
        candidate_outcome = behaviors[source]["candidate_ir"].get("outcome") or {}
        operation = str(provenance_candidate["operation"])
        if (
            original_outcome.get("op") != operation
            or candidate_outcome.get("op") != operation
        ):
            raise StageAInputError(
                f"indirect provenance source {source} no longer matches decoded control"
            )

        edge_ids: list[int] = []
        if provenance_candidate["target_kind"] == "internal_code":
            edge_kind = "call" if operation == "indirect_call" else "jump"
            for target_id in provenance_candidate["target_ids"]:
                target = node_targets_by_id.get(int(target_id))
                if target is None:
                    raise StageAInputError(
                        f"indirect provenance target {target_id} is not canonical"
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
                    "kind": edge_kind,
                    "original_guard": code_target_guard(
                        original_outcome["target"],
                        original_image_base,
                        int(target["original_rva"]),
                        [
                            int(alias)
                            for alias in target.get("original_aliases", [])
                        ],
                    ),
                    "candidate_guard": code_target_guard(
                        candidate_outcome["target"],
                        candidate_image_base,
                        int(target["candidate_rva"]),
                        [
                            int(alias)
                            for alias in target.get("candidate_aliases", [])
                        ],
                    ),
                    "infeasible": False,
                    "indirect_provenance_candidate_index": candidate_index,
                })
        else:
            continuation_region_index = int(
                provenance_candidate["continuation_region_index"]
            )
            if not 0 <= continuation_region_index < len(node_targets):
                raise StageAInputError(
                    f"indirect provenance source {source} has an invalid continuation"
                )
            edge_id = len(edges)
            edge_ids.append(edge_id)
            outgoing[source].append(edge_id)
            edges.append({
                "id": edge_id,
                "source_node_id": source,
                "target_node_id": continuation_region_index,
                "source_target_id": int(node_targets[source]["id"]),
                "target_target_id": int(
                    node_targets[continuation_region_index]["id"]
                ),
                "kind": "externalCall",
                "candidate_kind": "externalCall",
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
                "infeasible": False,
                "indirect_provenance_candidate_index": candidate_index,
            })
        provenance_edge_groups.append({
            "source_node_id": source,
            "candidate_index": candidate_index,
            "edge_ids": edge_ids,
            "target_kind": provenance_candidate["target_kind"],
            "target_ids": [
                int(target_id)
                for target_id in provenance_candidate.get("target_ids", [])
            ],
        })

    root_node_ids = {
        index for index, region in enumerate(contract.get("regions", []))
        if bool(region.get("root"))
    }
    target_region_by_id = {
        int(target["id"]): int(target["region_index"])
        for target in node_targets
    }
    for target_id in (contract.get("launch") or {}).get(
        "tls_callback_target_ids", []
    ):
        region_index = target_region_by_id.get(int(target_id))
        if region_index is None:
            raise StageAInputError(
                f"TLS callback target {int(target_id)} has no canonical product node"
            )
        root_node_ids.add(region_index)
    root_node_ids = sorted(root_node_ids)
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
    canonical_node_inventory = [
        {
            "node_id": index,
            "target_id": int(node_targets[index]["id"]),
            "region_id": str(contract["regions"][index].get("id", index)),
            "region_numeric_id": int(
                contract["regions"][index].get("numeric_id", index)
            ),
            "original_rva_start": int(
                contract["regions"][index]["original"]["rva_start"]
            ),
            "original_rva_end": int(
                contract["regions"][index]["original"].get(
                    "rva_end",
                    contract["regions"][index]["original"]["rva_start"],
                )
            ),
            "candidate_rva_start": int(
                contract["regions"][index]["candidate"]["rva_start"]
            ),
            "candidate_rva_end": int(
                contract["regions"][index]["candidate"].get(
                    "rva_end",
                    contract["regions"][index]["candidate"]["rva_start"],
                )
            ),
            "original_entry_aliases": sorted({
                int(alias)
                for alias in node_targets[index].get("original_aliases", [])
            }),
            "candidate_entry_aliases": sorted({
                int(alias)
                for alias in node_targets[index].get("candidate_aliases", [])
            }),
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
    provenance_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in provenance_candidates
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
        provenance_candidate: dict[str, Any] | None,
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
            and indirect_candidate["profile"] in {
                "immutable_relocated_function_pointer_jump_v1",
                "fixed_static_function_pointer_jump_v1",
                "fixed_code_address_indirect_jump_v1",
            }
        ):
            return [{
                "kind": "jump",
                "target_target_id": int(indirect_candidate["target_id"]),
                "guard": {"op": "bool_constant", "value": True},
            }]
        if (
            operation == "indirect_jump"
            and bounded_table_candidate is not None
            and bounded_table_candidate["profile"] in
                _FINITE_STATIC_TABLE_JUMP_PROFILES
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
        ):
            if bounded_table_call_candidate["shape"] not in {
                "cursor_loaded_table_word",
                "direct_indexed_table_read",
            }:
                return None
            expression = outcome["target"]
            image_base = (
                candidate_image_base if candidate_side else original_image_base
            )
            rva_key = "candidate_rva" if candidate_side else "original_rva"
            aliases_key = (
                "candidate_aliases" if candidate_side else "original_aliases"
            )
            singleton_target = (
                len(bounded_table_call_candidate["target_ids"]) == 1
            )
            return [
                {
                    "kind": "call",
                    "target_target_id": int(target["id"]),
                    "guard": (
                        {"op": "bool_constant", "value": True}
                        if singleton_target
                        else code_target_guard(
                            expression,
                            image_base,
                            int(target[rva_key]),
                            [
                                int(alias)
                                for alias in target.get(aliases_key, [])
                            ],
                        )
                    ),
                }
                for target_id in bounded_table_call_candidate["target_ids"]
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
        if provenance_candidate is not None:
            if provenance_candidate["target_kind"] == "import":
                continuation_index = int(
                    provenance_candidate["continuation_region_index"]
                )
                return [{
                    "kind": "externalCall",
                    "target_target_id": int(
                        node_targets[continuation_index]["id"]
                    ),
                    "guard": {"op": "bool_constant", "value": True},
                }]
            expression = outcome["target"]
            image_base = (
                candidate_image_base if candidate_side else original_image_base
            )
            rva_key = "candidate_rva" if candidate_side else "original_rva"
            aliases_key = (
                "candidate_aliases" if candidate_side else "original_aliases"
            )
            edge_kind = "call" if operation == "indirect_call" else "jump"
            return [
                {
                    "kind": edge_kind,
                    "target_target_id": int(target["id"]),
                    "guard": code_target_guard(
                        expression,
                        image_base,
                        int(target[rva_key]),
                        [
                            int(alias)
                            for alias in target.get(aliases_key, [])
                        ],
                    ),
                }
                for target_id in provenance_candidate["target_ids"]
                if (target := node_targets_by_id.get(int(target_id))) is not None
            ]
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
        if operation in {"indirect_call", "indirect_jump"}:
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
            "call_unmapped_return",
            "external_call",
            "bulk_copy",
            "bulk_fill",
            "checked_continue",
            "atomic_compare_exchange",
        }:
            return None
        return decoded

    x87_singleton_sources = {
        int(candidate["source_region_index"])
        for candidate in segment_candidates
        if str(candidate.get("certificate_profile", "")).startswith(
            "composable_x87_"
        )
    }
    decoded_control_candidates: list[dict[str, int]] = []
    for node_id, (node, behavior_pair) in enumerate(
        zip(nodes, behaviors, strict=True)
    ):
        indirect_candidate = indirect_by_source.get(node_id)
        bounded_table_candidate = bounded_table_by_source.get(node_id)
        bounded_table_call_candidate = bounded_table_call_by_source.get(node_id)
        dynamic_candidate = dynamic_call_by_source.get(node_id)
        import_call_candidate = import_call_by_source.get(node_id)
        provenance_candidate = provenance_by_source.get(node_id)
        original_decoded = decoded_control_edges(
            behavior_pair["original_ir"], indirect_candidate,
            bounded_table_candidate, bounded_table_call_candidate, dynamic_candidate,
            import_call_candidate, provenance_candidate, candidate_side=False,
        )
        candidate_decoded = decoded_control_edges(
            behavior_pair["candidate_ir"], indirect_candidate,
            bounded_table_candidate, bounded_table_call_candidate, dynamic_candidate,
            import_call_candidate, provenance_candidate, candidate_side=True,
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
                "kind": edges[edge_id].get(
                    "candidate_kind", edges[edge_id]["kind"]
                ),
                "target_target_id": edges[edge_id]["target_target_id"],
                "guard": edges[edge_id]["candidate_guard"],
            }
            for edge_id in node["outgoing_edge_ids"]
        ]

        def canonical_edges(
            values: list[dict[str, Any]],
        ) -> list[dict[str, Any]]:
            return sorted(
                values,
                key=lambda value: (
                    str(value["kind"]),
                    int(value["target_target_id"]),
                    json.dumps(value["guard"], sort_keys=True),
                ),
            )

        if (
            original_decoded is not None
            and candidate_decoded is not None
            and canonical_edges(original_graph_decoded)
                == canonical_edges(original_decoded)
            and canonical_edges(candidate_graph_decoded)
                == canonical_edges(candidate_decoded)
        ):
            decoded_candidate = {
                "node_id": node_id,
                "region_index": node_id,
                "profile": (
                    "x87_singleton_decoded_control_v1"
                    if node_id in x87_singleton_sources
                    else "direct_decoded_control_v1"
                ),
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
            if provenance_candidate is not None:
                decoded_candidate.update(provenance_candidate)
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
    runtime_continuation_contributors: dict[
        tuple[int, int], list[int | None]
    ] = defaultdict(list)
    for table_candidate in bounded_table_call_candidates or []:
        if (
            table_candidate.get("shape") == "cursor_loaded_table_word"
            and not table_candidate.get("target_ids")
        ):
            continue
        source_node_id = int(table_candidate["source_region_index"])
        continuation_node_id = int(table_candidate["continuation_region_index"])
        runtime_call_continuations[source_node_id].add(continuation_node_id)
        runtime_continuation_contributors[
            (source_node_id, continuation_node_id)
        ].append(None)
    for provenance_candidate in provenance_candidates:
        if (
            provenance_candidate["target_kind"] == "internal_code"
            and provenance_candidate["operation"] == "indirect_call"
        ):
            source_node_id = int(provenance_candidate["source_region_index"])
            continuation_node_id = int(
                provenance_candidate["continuation_region_index"]
            )
            runtime_call_continuations[source_node_id].add(continuation_node_id)
            runtime_continuation_contributors[
                (source_node_id, continuation_node_id)
            ].append(None)
    relation_edges = register_relations.get("edges", [])
    for relation_edge_index, relation_edge in enumerate(relation_edges):
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
        runtime_continuation_contributors[
            (source_node_id, continuation_node_id)
        ].append(relation_edge_index)

    external_sites_by_call_edge: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for site in external_call_candidates or []:
        call_edge_id = _integer(site.get("call_edge_index"))
        if site.get("site_kind") == "direct_import_thunk" and call_edge_id is not None:
            external_sites_by_call_edge[call_edge_id].append(site)

    def terminating_call_continuation(
        source_node_id: int,
        continuation_node_id: int,
        relation_edge_index: int,
    ) -> dict[str, int] | None:
        relation_edge = relation_edges[relation_edge_index]
        direct_claim = relation_edge.get("direct_call_push_claim")
        if (
            not isinstance(direct_claim, dict)
            or relation_edge.get("indirect_call_push_claim") is not None
            or int(relation_edge["source_region_index"]) != source_node_id
            or int(relation_edge["target_region_index"]) not in range(len(nodes))
            or int(direct_claim.get("continuation_region_index", -1))
                != continuation_node_id
        ):
            return None
        sites = external_sites_by_call_edge.get(relation_edge_index, [])
        if len(sites) != 1:
            return None
        site = sites[0]
        call_target_node_id = int(relation_edge["target_region_index"])
        external_jump_node_id = _integer(site.get("source_region_index"))
        external_site_id = _integer(site.get("id"))
        site_contract_id = _integer(site.get("machine_contract_id"))
        continuation_target_id = int(node_targets[continuation_node_id]["id"])
        if (
            site.get("dispatch_profile") != "checked_direct_import_thunk"
            or site.get("proof_profile") != "paired_direct_import_thunk_v1"
            or site.get("status") != "candidate_requires_lean_replay"
            or _integer(site.get("caller_region_index")) != source_node_id
            or _integer(site.get("call_target_region_index"))
                != call_target_node_id
            or _integer(site.get("target_region_index")) != continuation_node_id
            or _integer(site.get("continuation_target_id"))
                != continuation_target_id
            or external_jump_node_id is None
            or external_jump_node_id not in range(len(nodes))
            or external_site_id is None
            or site_contract_id is None
        ):
            return None
        original_outcome = (
            behaviors[external_jump_node_id].get("original_ir", {}).get("outcome")
            or {}
        )
        candidate_outcome = (
            behaviors[external_jump_node_id].get("candidate_ir", {}).get("outcome")
            or {}
        )
        if (
            original_outcome.get("op") != "external_jump"
            or candidate_outcome.get("op") != "external_jump"
        ):
            return None
        original_target = _semantic_external_target_identity(
            original_outcome.get("import")
        )
        candidate_target = _semantic_external_target_identity(
            candidate_outcome.get("import")
        )
        machine_contract, _selection_reason = _select_machine_import_call_contract(
            contract.get("machine_import_call_contracts"),
            original_target,
            candidate_target,
        )
        machine_contract_id = (
            _integer(machine_contract.get("id"))
            if machine_contract is not None else None
        )
        if (
            machine_contract is None
            or machine_contract_id != site_contract_id
            or machine_contract.get("disposition") != "terminates"
        ):
            return None
        return {
            "source_node_id": source_node_id,
            "continuation_node_id": continuation_node_id,
            "continuation_target_id": continuation_target_id,
            "call_edge_id": relation_edge_index,
            "call_target_node_id": call_target_node_id,
            "external_jump_node_id": external_jump_node_id,
            "external_site_id": external_site_id,
            "machine_contract_id": machine_contract_id,
        }

    terminating_call_continuations: list[dict[str, int]] = []
    for (source_node_id, continuation_node_id), contributors in sorted(
        runtime_continuation_contributors.items()
    ):
        # Suppression is safe only when this runtime continuation has one exact
        # direct-call origin and that origin has one checked terminating site.
        if len(contributors) != 1 or contributors[0] is None:
            continue
        row = terminating_call_continuation(
            source_node_id, continuation_node_id, contributors[0]
        )
        if row is not None:
            terminating_call_continuations.append(row)
    terminating_continuations_by_source: dict[int, set[int]] = defaultdict(set)
    for row in terminating_call_continuations:
        terminating_continuations_by_source[row["source_node_id"]].add(
            row["continuation_node_id"]
        )

    def behavioral_call_continuations(source_node_id: int) -> set[int]:
        return runtime_call_continuations.get(source_node_id, set()) - (
            terminating_continuations_by_source.get(source_node_id, set())
        )

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
            behavioral_call_continuations(source_node_id)
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
            behavioral_call_continuations(source_node_id)
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
            operation in {"indirect_call", "indirect_jump"}
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
                "potential_target_node_ids": sorted(added_targets),
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
            "canonical_node_inventory": canonical_node_inventory,
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
            "indirect_provenance_dataflow_candidates": provenance_candidates,
            "indirect_provenance_dataflow_edge_groups": provenance_edge_groups,
            "runtime_call_continuations": [
                {
                    "source_node_id": source_node_id,
                    "continuation_node_ids": sorted(continuation_node_ids),
                }
                for source_node_id, continuation_node_ids in sorted(
                    runtime_call_continuations.items()
                )
            ],
            "terminating_call_continuations": terminating_call_continuations,
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
            "terminating_call_continuations": len(
                terminating_call_continuations
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


def _checked_product_reachability_inventories(
    product_graph: dict[str, Any],
) -> dict[str, Any]:
    """Recompute every reported reachability inventory from canonical graph data."""
    nodes = product_graph["nodes"]
    edges = product_graph["edges"]
    evidence = product_graph["evidence"]
    counts = product_graph["counts"]
    expected_node_ids = list(range(len(nodes)))
    expected_node_id_set = set(expected_node_ids)
    node_ids = [int(node["id"]) for node in nodes]
    if node_ids != expected_node_ids:
        raise StageAInputError(
            "product graph nodes are not in canonical contiguous ID order"
        )

    expected_edge_ids = list(range(len(edges)))
    edge_ids = [int(edge["id"]) for edge in edges]
    if edge_ids != expected_edge_ids:
        raise StageAInputError(
            "product graph edges are not in canonical contiguous ID order"
        )

    root_node_ids = [int(node_id) for node_id in product_graph["root_node_ids"]]
    if (
        root_node_ids != sorted(set(root_node_ids))
        or any(node_id not in expected_node_id_set for node_id in root_node_ids)
        or [bool(node["root"]) for node in nodes]
        != [node_id in root_node_ids for node_id in expected_node_ids]
    ):
        raise StageAInputError("product graph has an inconsistent root inventory")

    outgoing_edge_ids: list[list[int]] = [[] for _ in nodes]
    feasible_successors: list[set[int]] = [set() for _ in nodes]
    for edge in edges:
        edge_id = int(edge["id"])
        source_node_id = int(edge["source_node_id"])
        target_node_id = int(edge["target_node_id"])
        if (
            source_node_id not in expected_node_id_set
            or target_node_id not in expected_node_id_set
        ):
            raise StageAInputError(
                f"product edge {edge_id} has an out-of-range endpoint"
            )
        outgoing_edge_ids[source_node_id].append(edge_id)
        if not bool(edge["infeasible"]):
            feasible_successors[source_node_id].add(target_node_id)
    if any(
        [int(edge_id) for edge_id in node["outgoing_edge_ids"]]
        != outgoing_edge_ids[int(node["id"])]
        for node in nodes
    ):
        raise StageAInputError(
            "product graph node outgoing-edge inventory does not match its edges"
        )

    runtime_continuations: dict[int, set[int]] = {}
    runtime_rows = evidence.get("runtime_call_continuations", [])
    for row in runtime_rows:
        source_node_id = int(row["source_node_id"])
        continuation_node_ids = [
            int(node_id) for node_id in row["continuation_node_ids"]
        ]
        if (
            source_node_id not in expected_node_id_set
            or source_node_id in runtime_continuations
            or continuation_node_ids != sorted(set(continuation_node_ids))
            or any(
                node_id not in expected_node_id_set
                for node_id in continuation_node_ids
            )
        ):
            raise StageAInputError(
                "product graph has an inconsistent runtime-call continuation inventory"
            )
        runtime_continuations[source_node_id] = set(continuation_node_ids)

    terminating_fields = {
        "source_node_id",
        "continuation_node_id",
        "continuation_target_id",
        "call_edge_id",
        "call_target_node_id",
        "external_jump_node_id",
        "external_site_id",
        "machine_contract_id",
    }
    terminating_rows = evidence.get("terminating_call_continuations", [])
    if not isinstance(terminating_rows, list):
        raise StageAInputError(
            "product graph terminating-call continuation inventory is not a list"
        )
    terminating_call_continuations: list[dict[str, int]] = []
    terminating_pairs: set[tuple[int, int]] = set()
    for raw_row in terminating_rows:
        if not isinstance(raw_row, dict) or set(raw_row) != terminating_fields:
            raise StageAInputError(
                "product graph has a malformed terminating-call continuation row"
            )
        parsed = {field: _integer(raw_row.get(field)) for field in terminating_fields}
        if any(value is None or value < 0 for value in parsed.values()):
            raise StageAInputError(
                "product graph terminating-call continuation fields must be non-negative integers"
            )
        row = {field: int(value) for field, value in parsed.items()}
        source_node_id = row["source_node_id"]
        continuation_node_id = row["continuation_node_id"]
        call_edge_id = row["call_edge_id"]
        pair = (source_node_id, continuation_node_id)
        if (
            source_node_id not in expected_node_id_set
            or continuation_node_id not in expected_node_id_set
            or row["call_target_node_id"] not in expected_node_id_set
            or row["external_jump_node_id"] not in expected_node_id_set
            or call_edge_id not in expected_edge_ids
            or continuation_node_id
                not in runtime_continuations.get(source_node_id, set())
            or pair in terminating_pairs
        ):
            raise StageAInputError(
                "product graph has an inconsistent terminating-call continuation row"
            )
        call_edge = edges[call_edge_id]
        if (
            bool(call_edge["infeasible"])
            or call_edge.get("kind") != "call"
            or int(call_edge["source_node_id"]) != source_node_id
            or int(call_edge["target_node_id"]) != row["call_target_node_id"]
            or int(nodes[continuation_node_id]["target_id"])
                != row["continuation_target_id"]
        ):
            raise StageAInputError(
                "product graph terminating-call continuation does not match its call edge"
            )
        terminating_pairs.add(pair)
        terminating_call_continuations.append(row)
    terminating_call_continuations.sort(key=lambda row: (
        row["source_node_id"],
        row["continuation_node_id"],
        row["call_edge_id"],
    ))
    if terminating_rows != terminating_call_continuations:
        raise StageAInputError(
            "product graph terminating-call continuation inventory is not canonical"
        )
    if int(product_graph["counts"].get(
        "terminating_call_continuations", 0
    )) != len(terminating_call_continuations):
        raise StageAInputError(
            "product graph terminating-call continuation count is inconsistent"
        )
    terminating_by_source: dict[int, set[int]] = defaultdict(set)
    for source_node_id, continuation_node_id in terminating_pairs:
        terminating_by_source[source_node_id].add(continuation_node_id)

    def closure(extra_successors: dict[int, set[int]] | None = None) -> list[int]:
        reached = set(root_node_ids)
        worklist = list(root_node_ids)
        cursor = 0
        while cursor < len(worklist):
            source_node_id = worklist[cursor]
            cursor += 1
            successors = (
                feasible_successors[source_node_id]
                | (
                    runtime_continuations.get(source_node_id, set())
                    - terminating_by_source.get(source_node_id, set())
                )
                | (extra_successors or {}).get(source_node_id, set())
            )
            for target_node_id in sorted(successors):
                if target_node_id in reached:
                    continue
                reached.add(target_node_id)
                worklist.append(target_node_id)
        return sorted(reached)

    represented_node_ids = closure()
    represented_node_id_set = set(represented_node_ids)
    declared_node_ids = [
        int(node_id) for node_id in evidence["declared_reachable_node_ids"]
    ]
    declared_bits = list(evidence["declared_reachable_bits"])
    expected_bits = [
        node_id in represented_node_id_set for node_id in expected_node_ids
    ]
    if (
        declared_node_ids != represented_node_ids
        or len(declared_bits) != len(nodes)
        or any(not isinstance(bit, bool) for bit in declared_bits)
        or declared_bits != expected_bits
    ):
        raise StageAInputError(
            "product graph declared reachability does not equal recomputed closure"
        )

    represented_edge_ids = [
        int(edge["id"])
        for edge in edges
        if int(edge["source_node_id"]) in represented_node_id_set
        and not bool(edge["infeasible"])
    ]
    if [
        int(edge_id) for edge_id in evidence["reachable_feasible_edge_ids"]
    ] != represented_edge_ids:
        raise StageAInputError(
            "product graph reachable feasible-edge inventory is inconsistent"
        )

    potential_extra_successors: dict[int, set[int]] = {}
    canonical_cuts: list[dict[str, Any]] = []
    for cut in evidence["potential_control_cuts"]:
        source_node_id = int(cut["node_id"])
        target_node_ids = [
            int(node_id) for node_id in cut["potential_target_node_ids"]
        ]
        if (
            source_node_id not in expected_node_id_set
            or target_node_ids != sorted(set(target_node_ids))
            or any(
                node_id not in expected_node_id_set
                for node_id in target_node_ids
            )
            or int(cut["potential_target_count"]) != len(target_node_ids)
        ):
            raise StageAInputError(
                "product graph has an inconsistent conservative control cut"
            )
        potential_extra_successors.setdefault(source_node_id, set()).update(
            target_node_ids
        )
        canonical_cuts.append({
            "node_id": source_node_id,
            "operations": sorted({str(item) for item in cut.get("operations", [])}),
            "reason": str(cut.get("reason", "")),
            "provenance": sorted({str(item) for item in cut.get("provenance", [])}),
            "potential_target_count": len(target_node_ids),
            "potential_target_node_ids": target_node_ids,
            "target_scope": str(cut.get("target_scope", "")),
        })
    canonical_cuts.sort(key=lambda cut: (
        int(cut["node_id"]),
        str(cut["reason"]),
        json.dumps(cut, sort_keys=True, separators=(",", ":")),
    ))
    if len({int(cut["node_id"]) for cut in canonical_cuts}) != len(canonical_cuts):
        raise StageAInputError(
            "product graph has duplicate conservative control cuts"
        )

    potential_node_ids = closure(potential_extra_successors)
    potential_node_id_set = set(potential_node_ids)
    declared_potential_node_ids = [
        int(node_id) for node_id in evidence["potential_reachable_node_ids"]
    ]
    if declared_potential_node_ids != potential_node_ids:
        raise StageAInputError(
            "product graph potential reachability does not equal recomputed closure"
        )
    potential_edge_ids = [
        int(edge["id"])
        for edge in edges
        if int(edge["source_node_id"]) in potential_node_id_set
        and not bool(edge["infeasible"])
    ]
    if [
        int(edge_id)
        for edge_id in evidence["potential_reachable_feasible_edge_ids"]
    ] != potential_edge_ids:
        raise StageAInputError(
            "product graph potential feasible-edge inventory is inconsistent"
        )

    decoded_complete_node_ids = sorted({
        int(node_id)
        for node_id in evidence["decoded_control_complete_node_ids"]
    })
    if any(
        node_id not in expected_node_id_set
        for node_id in decoded_complete_node_ids
    ):
        raise StageAInputError(
            "product graph decoded-control inventory has an out-of-range node"
        )
    expected_decoded_frontier = sorted(
        set(represented_node_ids).difference(decoded_complete_node_ids)
    )
    if [
        int(node_id)
        for node_id in evidence["reachable_decoded_control_frontier_node_ids"]
    ] != expected_decoded_frontier:
        raise StageAInputError(
            "product graph decoded-control frontier is inconsistent"
        )

    potential_only_node_ids = sorted(
        set(potential_node_ids).difference(represented_node_ids)
    )
    if (
        int(counts["declared_reachable_nodes"]) != len(represented_node_ids)
        or int(counts["potential_reachable_nodes"]) != len(potential_node_ids)
        or int(counts["potential_reachable_feasible_edges"])
        != len(potential_edge_ids)
        or int(counts["potential_unrepresented_control_edges"])
        != sum(len(targets) for targets in potential_extra_successors.values())
        or bool(counts["reachability_truncated_by_control_frontier"])
        != bool(potential_only_node_ids)
    ):
        raise StageAInputError(
            "product graph has inconsistent reachability counts"
        )

    canonical_node_inventory = sorted(
        (
            {
                "node_id": int(row["node_id"]),
                "target_id": int(row["target_id"]),
                "region_id": str(row["region_id"]),
                "region_numeric_id": int(row["region_numeric_id"]),
                "original_rva_start": int(row["original_rva_start"]),
                "original_rva_end": int(row["original_rva_end"]),
                "candidate_rva_start": int(row["candidate_rva_start"]),
                "candidate_rva_end": int(row["candidate_rva_end"]),
                "original_entry_aliases": sorted({
                    int(alias) for alias in row["original_entry_aliases"]
                }),
                "candidate_entry_aliases": sorted({
                    int(alias) for alias in row["candidate_entry_aliases"]
                }),
            }
            for row in evidence["canonical_node_inventory"]
        ),
        key=lambda row: int(row["node_id"]),
    )
    if [int(row["node_id"]) for row in canonical_node_inventory] != expected_node_ids:
        raise StageAInputError(
            "product graph canonical block inventory is inconsistent"
        )
    if any(
        int(row["target_id"]) != int(nodes[int(row["node_id"])]["target_id"])
        or int(row["original_rva_start"]) > int(row["original_rva_end"])
        or int(row["candidate_rva_start"]) > int(row["candidate_rva_end"])
        for row in canonical_node_inventory
    ):
        raise StageAInputError(
            "product graph canonical block identity does not match its nodes"
        )

    return {
        "canonical_node_ids": expected_node_ids,
        "canonical_node_inventory": canonical_node_inventory,
        "root_node_ids": root_node_ids,
        "represented_node_ids": represented_node_ids,
        "represented_edge_ids": represented_edge_ids,
        "potential_node_ids": potential_node_ids,
        "potential_edge_ids": potential_edge_ids,
        "potential_only_node_ids": potential_only_node_ids,
        "runtime_call_continuations": [
            {
                "source_node_id": source_node_id,
                "continuation_node_ids": sorted(continuation_node_ids),
            }
            for source_node_id, continuation_node_ids in sorted(
                runtime_continuations.items()
            )
        ],
        "terminating_call_continuations": terminating_call_continuations,
        "potential_control_cuts": canonical_cuts,
    }


def _affine_linked_composition_progress(
    product_graph: Mapping[str, Any],
    acceptance: Mapping[str, Any],
) -> dict[str, Any] | None:
    """Project affine linked-control certificates into non-authoritative metrics."""
    affine = acceptance.get("affine_linked_control")
    if not isinstance(affine, Mapping):
        return None
    states = affine.get("minimal_active_states")
    no_write = affine.get("minimal_transition_bindings")
    paired_write = affine.get("minimal_memory_transition_bindings")
    gaps = affine.get("minimal_transition_binding_gaps")
    links = affine.get("links")
    coverage_gaps = affine.get("coverage_gaps")
    graph_nodes = product_graph.get("nodes")
    graph_edges = product_graph.get("edges")
    graph_evidence = product_graph.get("evidence")
    if not all(isinstance(value, list) for value in (
        states, no_write, paired_write, gaps, links, graph_nodes, graph_edges,
    )) or not isinstance(coverage_gaps, Mapping) or not isinstance(
        graph_evidence, Mapping
    ):
        return None

    state_node_by_id = {
        int(state["id"]): int(state["node_id"])
        for state in states
        if isinstance(state, Mapping)
        and isinstance(state.get("id"), int)
        and isinstance(state.get("node_id"), int)
    }
    bindings = [
        binding for binding in [*no_write, *paired_write]
        if isinstance(binding, Mapping)
        and isinstance(binding.get("source_control_state_id"), int)
        and isinstance(binding.get("edge_id"), int)
    ]
    binding_context_keys = {
        (int(binding["source_control_state_id"]), int(binding["edge_id"]))
        for binding in bindings
        if int(binding["source_control_state_id"]) in state_node_by_id
    }
    state_ids_by_node: dict[int, set[int]] = defaultdict(set)
    for state_id, node_id in state_node_by_id.items():
        state_ids_by_node[node_id].add(state_id)
    candidate_dispatch_keys = {
        (state_node_by_id[state_id], edge_id)
        for state_id, edge_id in binding_context_keys
    }
    dispatch_keys = {
        (node_id, edge_id)
        for node_id, edge_id in candidate_dispatch_keys
        if all(
            (state_id, edge_id) in binding_context_keys
            for state_id in state_ids_by_node[node_id]
        )
    }
    locally_refined_edge_ids = {
        int(edge_id)
        for edge_id in graph_evidence.get("locally_refined_edge_ids", [])
        if isinstance(edge_id, int)
    }
    reachable_node_ids = {
        int(node_id)
        for node_id in graph_evidence.get("declared_reachable_node_ids", [])
        if isinstance(node_id, int)
    }
    reachable_edge_ids = {
        int(edge_id)
        for edge_id in graph_evidence.get("reachable_feasible_edge_ids", [])
        if isinstance(edge_id, int)
    }
    composition_ready_dispatch_keys = {
        (node_id, edge_id) for node_id, edge_id in dispatch_keys
        if edge_id in locally_refined_edge_ids
    }
    affine_segment_frontier_edge_ids = sorted({
        edge_id for _node_id, edge_id in dispatch_keys
        if edge_id not in locally_refined_edge_ids
    })
    rooted_dispatch_keys = {
        (node_id, edge_id) for node_id, edge_id in dispatch_keys
        if node_id in reachable_node_ids and edge_id in reachable_edge_ids
    }
    rooted_composition_ready_dispatch_keys = {
        (node_id, edge_id) for node_id, edge_id in rooted_dispatch_keys
        if edge_id in locally_refined_edge_ids
    }
    rooted_affine_segment_frontier_edge_ids = sorted({
        edge_id for _node_id, edge_id in rooted_dispatch_keys
        if edge_id not in locally_refined_edge_ids
    })
    ordinary_kinds = {"jump", "branchTaken", "branchFallthrough"}
    ordinary_edges_by_node: dict[int, set[int]] = defaultdict(set)
    rooted_ordinary_edges_by_node: dict[int, set[int]] = defaultdict(set)
    for edge in graph_edges:
        if (
            isinstance(edge, Mapping)
            and edge.get("kind") in ordinary_kinds
            and not bool(edge.get("infeasible"))
            and isinstance(edge.get("source_node_id"), int)
            and isinstance(edge.get("id"), int)
        ):
            ordinary_edges_by_node[int(edge["source_node_id"])].add(
                int(edge["id"])
            )
            if int(edge["id"]) in reachable_edge_ids:
                rooted_ordinary_edges_by_node[int(edge["source_node_id"])].add(
                    int(edge["id"])
                )
    active_node_ids = set(state_node_by_id.values())
    ordinary_control_complete_node_ids = sorted(
        node_id for node_id in active_node_ids
        if ordinary_edges_by_node.get(node_id)
        and all(
            (node_id, edge_id) in dispatch_keys
            for edge_id in ordinary_edges_by_node[node_id]
        )
    )
    ordinary_composition_ready_node_ids = sorted(
        node_id for node_id in active_node_ids
        if ordinary_edges_by_node.get(node_id)
        and all(
            (node_id, edge_id) in composition_ready_dispatch_keys
            for edge_id in ordinary_edges_by_node[node_id]
        )
    )
    rooted_active_node_ids = active_node_ids.intersection(reachable_node_ids)
    rooted_ordinary_control_complete_node_ids = sorted(
        node_id for node_id in rooted_active_node_ids
        if rooted_ordinary_edges_by_node.get(node_id)
        and all(
            (node_id, edge_id) in rooted_dispatch_keys
            for edge_id in rooted_ordinary_edges_by_node[node_id]
        )
    )
    rooted_ordinary_composition_ready_node_ids = sorted(
        node_id for node_id in rooted_active_node_ids
        if rooted_ordinary_edges_by_node.get(node_id)
        and all(
            (node_id, edge_id) in rooted_composition_ready_dispatch_keys
            for edge_id in rooted_ordinary_edges_by_node[node_id]
        )
    )
    unbound_calls = coverage_gaps.get("unbound_call_transition_ids", [])
    if not isinstance(unbound_calls, list):
        unbound_calls = []
    unbound_call_rows = coverage_gaps.get("unbound_call_transitions", [])
    if not isinstance(unbound_call_rows, list):
        unbound_call_rows = []
    unbound_call_context_rows = coverage_gaps.get(
        "unbound_active_call_contexts", []
    )
    if not isinstance(unbound_call_context_rows, list):
        unbound_call_context_rows = []
    rooted_unbound_call_rows = [
        row for row in unbound_call_rows
        if isinstance(row, Mapping)
        and isinstance(row.get("transition_id"), int)
        and isinstance(row.get("source_node_id"), int)
        and isinstance(row.get("edge_id"), int)
        and int(row["source_node_id"]) in reachable_node_ids
        and int(row["edge_id"]) in reachable_edge_ids
    ]
    valid_unbound_call_context_rows = [
        row for row in unbound_call_context_rows
        if isinstance(row, Mapping)
        and isinstance(row.get("transition_id"), int)
        and isinstance(row.get("source_control_state_id"), int)
        and isinstance(row.get("edge_id"), int)
        and isinstance(row.get("reason"), str)
        and int(row["source_control_state_id"]) in state_node_by_id
    ]
    rooted_unbound_call_context_rows = [
        row for row in valid_unbound_call_context_rows
        if state_node_by_id[int(row["source_control_state_id"])]
        in reachable_node_ids
        and int(row["edge_id"]) in reachable_edge_ids
    ]
    unbound_call_context_reason_counts = dict(sorted(Counter(
        str(row["reason"]) for row in valid_unbound_call_context_rows
    ).items()))
    rooted_unbound_call_context_reason_counts = dict(sorted(Counter(
        str(row["reason"]) for row in rooted_unbound_call_context_rows
    ).items()))
    return {
        "status": (
            "acceptance_ready"
            if affine.get("acceptance_authority") is True
            else "proofs_not_connected_to_acceptance"
        ),
        "acceptance_authority": affine.get("acceptance_authority") is True,
        "analyzed_control_states": len(states),
        "rooted_control_states": sum(
            node_id in reachable_node_ids
            for node_id in state_node_by_id.values()
        ),
        "ordinary_no_write_contexts": len(no_write),
        "ordinary_paired_write_contexts": len(paired_write),
        "ordinary_dispatch_node_edges": len(dispatch_keys),
        "rooted_ordinary_dispatch_node_edges": len(rooted_dispatch_keys),
        "ordinary_control_complete_node_ids": ordinary_control_complete_node_ids,
        "ordinary_control_complete_nodes": len(
            ordinary_control_complete_node_ids
        ),
        "ordinary_composition_ready_node_ids": (
            ordinary_composition_ready_node_ids
        ),
        "ordinary_composition_ready_nodes": len(
            ordinary_composition_ready_node_ids
        ),
        "ordinary_segment_refined_dispatch_node_edges": len(
            composition_ready_dispatch_keys
        ),
        "ordinary_segment_frontier_edge_ids": affine_segment_frontier_edge_ids,
        "rooted_ordinary_control_complete_node_ids": (
            rooted_ordinary_control_complete_node_ids
        ),
        "rooted_ordinary_control_complete_nodes": len(
            rooted_ordinary_control_complete_node_ids
        ),
        "rooted_ordinary_composition_ready_node_ids": (
            rooted_ordinary_composition_ready_node_ids
        ),
        "rooted_ordinary_composition_ready_nodes": len(
            rooted_ordinary_composition_ready_node_ids
        ),
        "rooted_ordinary_segment_refined_dispatch_node_edges": len(
            rooted_composition_ready_dispatch_keys
        ),
        "rooted_ordinary_segment_frontier_edge_ids": (
            rooted_affine_segment_frontier_edge_ids
        ),
        "ordinary_binding_gaps": len(gaps),
        "unbound_call_transition_ids": [
            int(value) for value in unbound_calls if isinstance(value, int)
        ],
        "rooted_unbound_call_transition_ids": [
            int(row["transition_id"]) for row in rooted_unbound_call_rows
        ],
        "unbound_active_call_contexts": len(valid_unbound_call_context_rows),
        "unbound_active_call_context_reason_counts": (
            unbound_call_context_reason_counts
        ),
        "rooted_unbound_active_call_contexts": len(
            rooted_unbound_call_context_rows
        ),
        "rooted_unbound_active_call_context_reason_counts": (
            rooted_unbound_call_context_reason_counts
        ),
        "nested_link_shapes": len(links),
        "next_action": (
            "compose affine call pushes, return resumes, and external cutpoints "
            "through the same LinkedControlAuthority, then make that authority "
            "the whole-program acceptance input"
        ),
        "trust": "diagnostic_projection_of_generated_lean_certificate_inventory",
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
    inventories = _checked_product_reachability_inventories(product_graph)
    reachable_node_ids = inventories["represented_node_ids"]
    reachable_node_id_set = set(reachable_node_ids)
    reachable_edge_ids = inventories["represented_edge_ids"]
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

    potential_control_cuts = inventories["potential_control_cuts"]
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
    affine_progress = _affine_linked_composition_progress(
        product_graph, acceptance
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
    potential_node_ids = inventories["potential_node_ids"]
    potential_edge_ids = inventories["potential_edge_ids"]
    canonical_node_ids = inventories["canonical_node_ids"]
    root_node_ids_list = inventories["root_node_ids"]
    potential_only_node_ids = inventories["potential_only_node_ids"]

    reachability_non_comparability_reasons: list[str] = []
    if not canonical_node_ids:
        reachability_non_comparability_reasons.append("no_canonical_nodes")
    if not root_node_ids_list:
        reachability_non_comparability_reasons.append("no_root_nodes")
    if decoded_frontier_node_ids:
        reachability_non_comparability_reasons.append(
            "represented_decoded_control_frontier"
        )
    if potential_control_cuts:
        reachability_non_comparability_reasons.append(
            "conservative_control_frontier"
        )
    if potential_only_node_ids:
        reachability_non_comparability_reasons.append(
            "represented_reachability_truncated"
        )
    reachability_scope_closed = not reachability_non_comparability_reasons
    canonical_block_inventory = {
        "format": "stage-a-canonical-block-inventory-v1",
        "nodes": inventories["canonical_node_inventory"],
    }
    canonical_block_inventory_sha256 = sha256_bytes(
        json.dumps(
            canonical_block_inventory, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    )
    comparison_scope = {
        "format": "stage-a-reachability-inventory-v2",
        "canonical_block_inventory_sha256": canonical_block_inventory_sha256,
        "canonical_nodes": inventories["canonical_node_inventory"],
        "root_node_ids": root_node_ids_list,
        "represented_rooted_node_ids": reachable_node_ids,
        "represented_feasible_edges": [
            {
                "id": edge_id,
                "source_node_id": int(edges_by_id[edge_id]["source_node_id"]),
                "target_node_id": int(edges_by_id[edge_id]["target_node_id"]),
                "kind": str(edges_by_id[edge_id]["kind"]),
            }
            for edge_id in reachable_edge_ids
        ],
        "runtime_call_continuations": inventories[
            "runtime_call_continuations"
        ],
        "terminating_call_continuations": inventories[
            "terminating_call_continuations"
        ],
        "conservative_potential_node_ids": potential_node_ids,
        "conservative_potential_feasible_edges": [
            {
                "id": edge_id,
                "source_node_id": int(edges_by_id[edge_id]["source_node_id"]),
                "target_node_id": int(edges_by_id[edge_id]["target_node_id"]),
                "kind": str(edges_by_id[edge_id]["kind"]),
            }
            for edge_id in potential_edge_ids
        ],
        "conservative_control_cuts": potential_control_cuts,
    }
    reachability_inventory_sha256 = sha256_bytes(
        json.dumps(
            comparison_scope, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    )
    reachability_assurance = {
        "format": "stage-a-reachability-assurance-v1",
        "status": "control_closed" if reachability_scope_closed else "incomplete",
        "represented_rooted_reachability": {
            "basis": (
                "submitted_product_edges_and_checked_runtime_continuations_"
                "excluding_checked_terminating_calls"
            ),
            "node_ids": reachable_node_ids,
            "node_count": len(reachable_node_ids),
            "feasible_edge_ids": reachable_edge_ids,
            "feasible_edge_count": len(reachable_edge_ids),
            "control_closed": reachability_scope_closed,
            "behavioral_reachability_claim": False,
        },
        "conservative_potential_reachability": {
            "basis": "unresolved_control_conservative_canonical_target_expansion",
            "node_ids": potential_node_ids,
            "node_count": len(potential_node_ids),
            "feasible_edge_ids": potential_edge_ids,
            "feasible_edge_count": len(potential_edge_ids),
            "unrepresented_control_transition_count": int(
                counts["potential_unrepresented_control_edges"]
            ),
            "control_closed": reachability_scope_closed,
            "behavioral_reachability_claim": False,
        },
        "truncation": {
            "present": bool(potential_only_node_ids),
            "potential_only_node_ids": potential_only_node_ids,
            "potential_only_node_count": len(potential_only_node_ids),
        },
        "frontiers": {
            "represented_decoded_control_node_ids": decoded_frontier_node_ids,
            "conservative_control_cuts": potential_control_cuts,
            "represented_local_refinement_edge_ids": local_frontier_edge_ids,
            "represented_stack_invariant_node_ids": stack_invariant_frontier_node_ids,
            "represented_environment_edge_ids": environment_frontier_edge_ids,
            "unsupported_instruction_issue_ids": sorted(
                str(issue["id"]) for issue in unsupported_instruction_issues
            ),
        },
        "blocker_totals": {
            "reported_total": acceptance_blocker_count,
            "reported_category_count": len(acceptance_blockers),
            "comparable": reachability_scope_closed,
            "coverage_bearing": False,
            "comparison_requires_matching_scope_sha256": True,
            "comparison_scope_sha256": reachability_inventory_sha256,
            "reachability_inventory_sha256": reachability_inventory_sha256,
            "canonical_block_inventory_sha256": (
                canonical_block_inventory_sha256
            ),
            "non_comparability_reasons": reachability_non_comparability_reasons,
        },
    }
    ready_for_lean = (
        acceptance.get("status") == "ready"
        and reachability_scope_closed
        and bool(counts["reachable_product_local_complete"])
        and not unresolved_indirect_control_cuts
        and not unsupported_instruction_issues
        and not environment_frontier_edge_ids
        and not stack_invariant_frontier
    )

    next_work: list[dict[str, Any]] = []
    if (
        affine_progress is not None
        and not affine_progress["acceptance_authority"]
    ):
        if affine_progress["rooted_ordinary_segment_frontier_edge_ids"]:
            next_work.append({
                "category": "affine_ordinary_segment_refinement",
                "count": len(
                    affine_progress[
                        "rooted_ordinary_segment_frontier_edge_ids"
                    ]
                ),
                "example_ids": affine_progress[
                    "rooted_ordinary_segment_frontier_edge_ids"
                ][:10],
                "next_action": (
                    "close the target StateRel segment refinement for each "
                    "affine-dispatched ordinary edge"
                ),
            })
        if affine_progress["rooted_unbound_call_transition_ids"]:
            next_work.append({
                "category": "affine_linked_acceptance_composition",
                "count": len(
                    affine_progress["rooted_unbound_call_transition_ids"]
                ),
                "example_ids": affine_progress[
                    "rooted_unbound_call_transition_ids"
                ][:10],
                "next_action": affine_progress["next_action"],
            })
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
            "reachability_source": (
                "decoded_behavior_and_checked_runtime_continuations_"
                "excluding_checked_terminating_calls"
            ),
            "unresolved_control_fails_closed": True,
            "blocker_totals_are_coverage_bearing": False,
            "blocker_totals_require_comparable_reachability_scope": True,
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
            **({
                "affine_linked_control_states": (
                    affine_progress["analyzed_control_states"]
                ),
                "affine_rooted_linked_control_states": (
                    affine_progress["rooted_control_states"]
                ),
                "affine_ordinary_no_write_contexts": (
                    affine_progress["ordinary_no_write_contexts"]
                ),
                "affine_ordinary_paired_write_contexts": (
                    affine_progress["ordinary_paired_write_contexts"]
                ),
                "affine_ordinary_dispatch_node_edges": (
                    affine_progress["ordinary_dispatch_node_edges"]
                ),
                "affine_rooted_ordinary_dispatch_node_edges": (
                    affine_progress["rooted_ordinary_dispatch_node_edges"]
                ),
                "affine_rooted_ordinary_control_complete_nodes": (
                    affine_progress[
                        "rooted_ordinary_control_complete_nodes"
                    ]
                ),
                "affine_rooted_ordinary_composition_ready_nodes": (
                    affine_progress[
                        "rooted_ordinary_composition_ready_nodes"
                    ]
                ),
                "affine_rooted_ordinary_segment_refined_dispatch_node_edges": (
                    affine_progress[
                        "rooted_ordinary_segment_refined_dispatch_node_edges"
                    ]
                ),
                "affine_rooted_ordinary_segment_frontier_edges": len(
                    affine_progress[
                        "rooted_ordinary_segment_frontier_edge_ids"
                    ]
                ),
                "affine_rooted_unbound_call_transitions": len(
                    affine_progress["rooted_unbound_call_transition_ids"]
                ),
                "affine_nested_link_shapes": affine_progress["nested_link_shapes"],
            } if affine_progress is not None else {}),
        },
        "reachability": {
            "rooted_node_ids": reachable_node_ids,
            "potential_node_ids": potential_node_ids,
            "truncated_by_control_frontier": bool(
                counts["reachability_truncated_by_control_frontier"]
            ),
        },
        "reachability_assurance": reachability_assurance,
        "frontiers": {
            **({"affine_linked_control": affine_progress}
               if affine_progress is not None else {}),
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
            "final_pass_requires": (
                acceptance.get("theorem")
                or acceptance.get("required_theorem")
            ),
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
                "a supported whole-program acceptance theorem as a closed "
                "application of the matching StageA.Relational equivalence theorem"
            ),
            "lean_witness": "StageA.Relational whole-program equivalence theorem",
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
        original_target_expression = original_outcome.get("target") or {}
        candidate_target_expression = candidate_outcome.get("target") or {}
        original_fixed_target = (
            _integer(original_target_expression.get("value"))
            if original_target_expression.get("op") == "constant" else None
        )
        candidate_fixed_target = (
            _integer(candidate_target_expression.get("value"))
            if candidate_target_expression.get("op") == "constant" else None
        )
        if (
            operation == "indirect_jump"
            and original_fixed_target is not None
            and candidate_fixed_target is not None
        ):
            matching_targets = [
                target for target in code_targets
                if _absolute_code_target_matches(
                    original_bin, target, "original", original_fixed_target,
                )
                and _absolute_code_target_matches(
                    candidate_bin, target, "candidate", candidate_fixed_target,
                )
            ]
            available_target_ids = {
                int(item["id"]) for item in region.get("code_targets", [])
            }
            if (
                len(matching_targets) == 1
                and int(matching_targets[0]["id"]) in available_target_ids
            ):
                target = matching_targets[0]
                target_inventory = _canonical_code_target_inventory(
                    contract, [int(target["id"])]
                )
                if target_inventory is None:
                    continue
                result.append({
                    "profile": "fixed_code_address_indirect_jump_v1",
                    "status": "candidate_requires_lean_replay",
                    "acceptance_authority": False,
                    "source_region_index": source_index,
                    "target_region_index": int(target["region_index"]),
                    "target_id": int(target["id"]),
                    "target_ids": [int(target["id"])],
                    "target_inventory": target_inventory,
                    "original_target": original_fixed_target,
                    "candidate_target": candidate_fixed_target,
                    "provenance": {
                        "profile": "paired_fixed_code_address_v1",
                        "original_target": original_fixed_target,
                        "candidate_target": candidate_fixed_target,
                    },
                })
            continue
        original_read = immutable_read(
            original_target_expression
        )
        candidate_read = immutable_read(
            candidate_target_expression
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
            mapped_word = min(
                mapped_words, key=lambda value: int(value["id"])
            )
            value_target_id = int(mapped_word["id"])
            profile = (
                "immutable_relocated_function_pointer_call_v1"
                if operation == "indirect_call"
                else "immutable_relocated_function_pointer_jump_v1"
            )
        else:
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
            if (
                operation == "indirect_jump"
                and (
                    target.get("original_aliases")
                    or target.get("candidate_aliases")
                )
            ):
                # The current exact-target execution theorem cannot yet consume
                # a runtime choice among code aliases. Keep that case explicit.
                continue
            profile = (
                "fixed_static_function_pointer_call_v1"
                if operation == "indirect_call"
                else "fixed_static_function_pointer_jump_v1"
            )
        available_target_ids = {
            int(item["id"]) for item in region.get("code_targets", [])
        }
        if int(target["id"]) not in available_target_ids:
            continue
        row = {
            "profile": profile,
            "status": "candidate_requires_lean_replay",
            "acceptance_authority": False,
            "source_region_index": source_index,
            "target_region_index": int(target["region_index"]),
            "target_id": int(target["id"]),
            "target_ids": [int(target["id"])],
            "original_address": original_address,
            "candidate_address": candidate_address,
            "original_assembled_read": original_assembled,
            "candidate_assembled_read": candidate_assembled,
            "original_writes": original_writes,
            "candidate_writes": candidate_writes,
        }
        target_inventory = _canonical_code_target_inventory(
            contract, [int(target["id"])]
        )
        if target_inventory is None:
            continue
        row["target_inventory"] = target_inventory
        if value_target_id is not None:
            row["value_target_id"] = value_target_id
            row["provenance"] = {
                "profile": "paired_immutable_relocated_word_v1",
                "value_target_id": value_target_id,
                "original_address": original_address,
                "candidate_address": candidate_address,
            }
        if fixed_slot is not None:
            row["slot"] = fixed_slot
            row["provenance"] = {
                "profile": "paired_static_word_slot_v1",
                "slot": fixed_slot,
                "original_writes": original_writes,
                "candidate_writes": candidate_writes,
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
            behaviors,
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
        target_inventory = _canonical_code_target_inventory(
            contract, [int(target_id) for target_id in candidate["target_ids"]]
        )
        if target_inventory is None:
            target_inventory = _code_target_inventory_from_relocation_rows(
                original_bin,
                candidate_bin,
                contract,
                candidate["rows"],
            )
        if target_inventory is None:
            continue
        candidate["target_inventory"] = target_inventory
        candidate["provenance"] = {
            "profile": "paired_immutable_code_pointer_table_rows_v1",
            "index_evidence": candidate["index_evidence"],
            "rows": candidate["rows"],
        }
        result.append(candidate)
    return result


def _attach_reverse_sentinel_table_source_invariants(
    contract: dict[str, Any], proposals: list[dict[str, Any]],
) -> dict[str, Any]:
    """Request the source bound needed by a reverse sentinel table proof.

    The request has no acceptance authority.  It becomes usable only when the
    generated Lean segment proofs establish it at every reachable predecessor,
    and the table-call theorem checks the exact PE table and decoded call shape.
    """
    refined = json.loads(json.dumps(contract))
    regions = refined.get("regions", [])
    reverse_proposals = [
        proposal for proposal in proposals
        if (
            proposal.get("profile") == "immutable_code_pointer_table_call_v1"
            and proposal.get("shape") == "direct_indexed_table_read"
            and isinstance(proposal.get("index_evidence"), dict)
            and proposal["index_evidence"].get("kind")
                == "paired_sentinel_terminated_reverse_count"
        )
    ]
    source_counts = Counter(
        source for proposal in reverse_proposals
        if (source := _integer(proposal.get("source_region_index"))) is not None
    )
    for proposal in reverse_proposals:
        source = _integer(proposal.get("source_region_index"))
        ranges = proposal.get("ranges")
        original_index = proposal.get("original_index_expression")
        candidate_index = proposal.get("candidate_index_expression")
        original_register = _input_register(original_index)
        candidate_register = _input_register(candidate_index)
        if (
            source is None
            or source_counts[source] != 1
            or not 0 <= source < len(regions)
            or not isinstance(ranges, list)
            or len(ranges) != 1
            or (row_count := _integer(ranges[0].get("row_count"))) is None
            or not 1 <= row_count <= 4097
            or original_register is None
            or candidate_register is None
        ):
            continue
        entry_count = row_count - 1
        if entry_count == 0:
            predicates = regions[source].setdefault("state_predicates", [])
            bottom = _uninhabited_state_predicate()
            if bottom not in predicates:
                predicates.append(bottom)
        else:
            bound = {
                "original": original_register,
                "candidate": candidate_register,
                "original_expression": {
                    "op": "sub",
                    "left": original_index,
                    "right": {"op": "constant", "value": 1},
                },
                "candidate_expression": {
                    "op": "sub",
                    "left": candidate_index,
                    "right": {"op": "constant", "value": 1},
                },
                "unsigned_lt": entry_count,
                "expression_source": (
                    "generated_reverse_sentinel_table_source_invariant_request"
                ),
            }
            bounds = regions[source].setdefault("bounds", [])
            if bound not in bounds:
                bounds.append(bound)
        evidence = proposal["index_evidence"]
        cluster = evidence.get("scanner_cluster")
        if not isinstance(cluster, dict):
            continue
        scanner_index = _integer(cluster.get("scanner_region_index"))
        test_index = _integer(cluster.get("test_region_index"))
        bridge_index = _integer(cluster.get("bridge_region_index"))
        gate_index = _integer(cluster.get("gate_region_index"))
        original_scanner = cluster.get("original_scanner_register")
        candidate_scanner = cluster.get("candidate_scanner_register")
        original_count = cluster.get("original_count_register")
        candidate_count = cluster.get("candidate_count_register")
        zero_flag = _integer(cluster.get("zero_flag_bit"))
        if not (
            all(
                index is not None and 0 <= index < len(regions)
                for index in (scanner_index, test_index, bridge_index, gate_index)
            )
            and all(
                isinstance(register, str)
                for register in (
                    original_scanner,
                    candidate_scanner,
                    original_count,
                    candidate_count,
                )
            )
            and zero_flag == 6
        ):
            continue
        scanner_bound = {
            "original": original_scanner,
            "candidate": candidate_scanner,
            "unsigned_lt": row_count,
            "expression_source": (
                "generated_reverse_sentinel_scanner_counter_invariant_request"
            ),
        }
        scanner_bounds = regions[scanner_index].setdefault("bounds", [])
        if scanner_bound not in scanner_bounds:
            scanner_bounds.append(scanner_bound)
        post_predicate = {
            "original": _reverse_sentinel_post_state_predicate(
                original_scanner, original_count, entry_count, zero_flag
            ),
            "candidate": _reverse_sentinel_post_state_predicate(
                candidate_scanner, candidate_count, entry_count, zero_flag
            ),
            "source": "generated_reverse_sentinel_scanner_post_state",
        }
        test_predicates = regions[test_index].setdefault("state_predicates", [])
        if post_predicate not in test_predicates:
            test_predicates.append(post_predicate)
        finished_predicate = {
            "original": _register_equals_constant(original_count, entry_count),
            "candidate": _register_equals_constant(candidate_count, entry_count),
            "source": "generated_reverse_sentinel_scanner_finished_state",
        }
        for index in (bridge_index, gate_index):
            predicates = regions[index].setdefault("state_predicates", [])
            if finished_predicate not in predicates:
                predicates.append(finished_predicate)
    return refined


def _uninhabited_state_predicate() -> dict[str, Any]:
    false = {"op": "bool_constant", "value": False}
    return {
        "original": false,
        "candidate": dict(false),
        "source": "generated_uninhabited_control_state",
    }


def _register_equals_constant(register: str, value: int) -> dict[str, Any]:
    return {
        "op": "equal",
        "left": {"op": "input_reg", "reg": register},
        "right": {"op": "constant", "value": value},
    }


def _reverse_sentinel_post_state_predicate(
    scanner_register: str,
    count_register: str,
    entry_count: int,
    zero_flag: int,
) -> dict[str, Any]:
    zero_flag_expression = {"op": "input_flag", "index": zero_flag}
    count_finished = _register_equals_constant(count_register, entry_count)
    return {
        "op": "and",
        "left": {
            "op": "equal",
            "left": {
                "op": "add",
                "left": {"op": "input_reg", "reg": count_register},
                "right": {"op": "constant", "value": 1},
            },
            "right": {"op": "input_reg", "reg": scanner_register},
        },
        "right": {
            "op": "and",
            "left": {
                "op": "not",
                "value": {
                    "op": "xor",
                    "left": zero_flag_expression,
                    "right": count_finished,
                },
            },
            "right": {
                "op": "or",
                "left": {
                    "op": "and",
                    "left": {"op": "not", "value": zero_flag_expression},
                    "right": {
                        "op": "unsigned_less",
                        "left": {"op": "input_reg", "reg": scanner_register},
                        "right": {"op": "constant", "value": entry_count + 1},
                    },
                },
                "right": {
                    "op": "and",
                    "left": zero_flag_expression,
                    "right": count_finished,
                },
            },
        },
    }


def _attach_reverse_sentinel_table_value_targets(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    proposals: list[dict[str, Any]],
) -> dict[str, Any]:
    """Add exact static-data mappings needed by reverse sentinel tables.

    The proposal remains untrusted.  This function independently checks both
    PE images, their HIGHLOW relocation inventories, and every callable row.
    Lean subsequently repeats the byte, relocation, and code-target checks.
    """
    refined = json.loads(json.dumps(contract))
    regions = refined.get("regions", [])
    values = refined.get("value_targets", [])
    code_targets = refined.get("code_targets", [])
    if (
        not isinstance(regions, list)
        or not isinstance(values, list)
        or not isinstance(code_targets, list)
        or [
            _integer(value.get("id")) if isinstance(value, dict) else None
            for value in values
        ] != list(range(len(values)))
    ):
        return refined

    targets_by_id: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for target in code_targets:
        if isinstance(target, dict) and (target_id := _integer(target.get("id"))) is not None:
            targets_by_id[target_id].append(target)

    def highlow_rows(binary: StageABinary) -> list[int]:
        return [
            int(relocation["rva"])
            for relocation in _raw_base_relocations(binary)
            if int(relocation["type"]) == 3
        ]

    original_highlow = highlow_rows(original_bin)
    candidate_highlow = highlow_rows(candidate_bin)

    def relocation_offsets(
        binary: StageABinary, base: int, span_size: int, rows: list[int],
    ) -> list[int] | None:
        base_rva = base - binary.image_base
        offsets = [
            rva - base_rva
            for rva in rows
            if base_rva <= rva and rva + 4 <= base_rva + span_size
        ]
        if len(offsets) != len(set(offsets)):
            return None
        return sorted(offsets)

    def reference_rvas(
        binary: StageABinary, base: int, rows: list[int],
    ) -> list[int]:
        return sorted({
            rva for rva in rows
            if int(binary.pe.get_dword_at_rva(rva) or 0) == base
        })

    reverse_proposals = [
        proposal
        for proposal in proposals
        if (
            isinstance(proposal, dict)
            and proposal.get("profile") == "immutable_code_pointer_table_call_v1"
            and proposal.get("shape") == "direct_indexed_table_read"
            and isinstance(proposal.get("index_evidence"), dict)
            and proposal["index_evidence"].get("kind")
                == "paired_sentinel_terminated_reverse_count"
        )
    ]
    source_counts = Counter(
        source
        for proposal in reverse_proposals
        if (source := _integer(proposal.get("source_region_index"))) is not None
    )
    reverse_proposals.sort(key=lambda proposal: (
        _integer(proposal.get("original_base")) or -1,
        _integer(proposal.get("candidate_base")) or -1,
        _integer(proposal.get("source_region_index")) or -1,
    ))

    for proposal in reverse_proposals:
        source = _integer(proposal.get("source_region_index"))
        original_base = _integer(proposal.get("original_base"))
        candidate_base = _integer(proposal.get("candidate_base"))
        ranges = proposal.get("ranges")
        rows = proposal.get("rows")
        if (
            source is None
            or source_counts[source] != 1
            or not 0 <= source < len(regions)
            or original_base is None
            or candidate_base is None
            or not isinstance(ranges, list)
            or len(ranges) != 1
            or not isinstance(ranges[0], dict)
            or (row_count := _integer(ranges[0].get("row_count"))) is None
            or not 1 <= row_count <= 4097
            or not isinstance(rows, list)
            or len(rows) != row_count
        ):
            continue
        entry_count = row_count - 1
        span_size = (entry_count + 2) * 4
        expected_offsets = list(range(4, 4 * (entry_count + 1), 4))
        if (
            _integer(ranges[0].get("original_start")) != original_base + 4
            or _integer(ranges[0].get("candidate_start")) != candidate_base + 4
            or _integer(ranges[0].get("original_end"))
                != original_base + span_size
            or _integer(ranges[0].get("candidate_end"))
                != candidate_base + span_size
            or ranges[0].get("source")
                != "paired_sentinel_terminated_reverse_count"
            or _immutable_image_u32(original_bin, original_base) != 0xFFFFFFFF
            or _immutable_image_u32(candidate_bin, candidate_base) != 0xFFFFFFFF
            or _immutable_image_u32(
                original_bin, original_base + (entry_count + 1) * 4
            ) != 0
            or _immutable_image_u32(
                candidate_bin, candidate_base + (entry_count + 1) * 4
            ) != 0
            or relocation_offsets(
                original_bin, original_base, span_size, original_highlow
            ) != expected_offsets
            or relocation_offsets(
                candidate_bin, candidate_base, span_size, candidate_highlow
            ) != expected_offsets
        ):
            continue

        callable_target_ids: list[int] = []
        rows_valid = True
        for logical_index, row in enumerate(rows):
            if not isinstance(row, dict):
                rows_valid = False
                break
            raw_index = logical_index + 1
            original_slot = original_base + raw_index * 4
            candidate_slot = candidate_base + raw_index * 4
            if logical_index == entry_count:
                rows_valid = (
                    row.get("kind") == "null"
                    and row.get("relocation_backed") is False
                    and _integer(row.get("original_slot")) == original_slot
                    and _integer(row.get("candidate_slot")) == candidate_slot
                    and "target_id" not in row
                )
                break
            target_id = _integer(row.get("target_id"))
            targets = targets_by_id.get(target_id, []) if target_id is not None else []
            if (
                row.get("kind") != "code_pointer"
                or row.get("relocation_backed") is not True
                or len(targets) != 1
                or _integer(row.get("original_slot")) != original_slot
                or _integer(row.get("candidate_slot")) != candidate_slot
                or _immutable_image_u32(original_bin, original_slot)
                    != original_bin.image_base + int(targets[0]["original_rva"])
                or _immutable_image_u32(candidate_bin, candidate_slot)
                    != candidate_bin.image_base + int(targets[0]["candidate_rva"])
            ):
                rows_valid = False
                break
            callable_target_ids.append(int(target_id))
        proposed_target_ids = proposal.get("target_ids")
        if (
            not rows_valid
            or not isinstance(proposed_target_ids, list)
            or sorted(set(callable_target_ids))
                != [int(value) for value in proposed_target_ids
                    if _integer(value) is not None]
            or len(proposed_target_ids)
                != len([value for value in proposed_target_ids if _integer(value) is not None])
        ):
            continue

        matching_values: list[dict[str, Any]] = []
        for value in values:
            original_value = _integer(value.get("original_value"))
            candidate_value = _integer(value.get("candidate_value"))
            mapped_size = _integer(value.get("mapped_size"))
            if original_value is None or candidate_value is None or mapped_size is None:
                continue
            original_offset = original_base - original_value
            candidate_offset = candidate_base - candidate_value
            if (
                original_offset == candidate_offset
                and original_offset >= 0
                and original_offset + span_size <= mapped_size
                and sorted(
                    int(offset) - original_offset
                    for offset in value.get("relocation_offsets", [])
                    if original_offset <= int(offset) < original_offset + span_size
                ) == expected_offsets
            ):
                matching_values.append(value)
        if len(matching_values) > 1:
            continue
        if matching_values:
            value_target = matching_values[0]
        else:
            original_references = reference_rvas(
                original_bin, original_base, original_highlow
            )
            candidate_references = reference_rvas(
                candidate_bin, candidate_base, candidate_highlow
            )
            if not original_references or not candidate_references:
                continue
            value_target = {
                "id": len(values),
                "original_value": original_base,
                "candidate_value": candidate_base,
                "original_relocation_rva": original_references[0],
                "candidate_relocation_rva": candidate_references[0],
                "mapped_size": span_size,
                "relocation_offsets": expected_offsets,
            }
            values.append(value_target)

        value_target_id = int(value_target["id"])
        index_evidence = proposal["index_evidence"]
        consumer_region_ids = {source}
        for role in (
            "header_producer_region_index",
            "nonzero_predecessor_region_index",
            "decrement_region_index",
            "scanner_initializer_region_index",
            "scanner_region_index",
            "scanner_loop_region_index",
        ):
            region_id = _integer(index_evidence.get(role))
            if region_id is not None and 0 <= region_id < len(regions):
                consumer_region_ids.add(region_id)

        for region_id in sorted(consumer_region_ids):
            region = regions[region_id]
            region_value_ids = region.setdefault("value_target_ids", [])
            region_value_ids[:] = sorted(set(region_value_ids) | {
                int(existing["id"])
                for existing in region.get("values", [])
                if isinstance(existing, dict)
                and _integer(existing.get("id")) is not None
            })
            if value_target_id not in region_value_ids:
                region_value_ids.append(value_target_id)
                region_value_ids.sort()
            region_values = region.setdefault("values", [])
            if not any(
                _integer(existing.get("id")) == value_target_id
                for existing in region_values
                if isinstance(existing, dict)
            ):
                region_values.append(value_target)
                region_values.sort(key=lambda value: int(value["id"]))

            region_target_ids = region.setdefault("target_ids", [])
            region_targets = region.setdefault("code_targets", [])
            region_target_ids[:] = sorted(set(region_target_ids) | {
                int(target["id"])
                for target in region_targets
                if isinstance(target, dict)
                and _integer(target.get("id")) is not None
            })
            for target_id in sorted(set(callable_target_ids)):
                if target_id not in region_target_ids:
                    region_target_ids.append(target_id)
                if not any(
                    _integer(target.get("id")) == target_id
                    for target in region_targets
                    if isinstance(target, dict)
                ):
                    region_targets.append(targets_by_id[target_id][0])
            region_target_ids.sort()
            region_targets.sort(key=lambda target: int(target["id"]))
    return refined


def _bounded_immutable_code_pointer_table_call_inputs(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    proposals: list[dict[str, Any]],
    *,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
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
    recomputed_reverse_by_source = {
        int(proposal["source_region_index"]): proposal
        for proposal in _immutable_code_pointer_table_call_candidates(
            original_bin, candidate_bin, contract, behaviors
        )
        if (
            isinstance(proposal.get("index_evidence"), dict)
            and proposal["index_evidence"].get("kind")
            == "paired_sentinel_terminated_reverse_count"
        )
    }
    recomputed_cursor_by_source = {
        int(proposal["source_region_index"]): proposal
        for proposal in _immutable_code_pointer_table_call_candidates(
            original_bin, candidate_bin, contract, behaviors
        )
        if proposal.get("shape") == "cursor_loaded_table_word"
    }
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
        if proposal.get("shape") == "cursor_loaded_table_word":
            recomputed = recomputed_cursor_by_source.get(source)
            index_evidence = proposal.get("index_evidence")
            recomputed_evidence = (
                recomputed.get("index_evidence")
                if isinstance(recomputed, dict) else None
            )
            evidence_fields = (
                "kind",
                "function_entry_region_index",
                "producer_region_index",
                "step_region_index",
                "callsite_region_indices",
                "original_expression",
                "candidate_expression",
                "scale",
            )
            if (
                recomputed is None
                or not isinstance(index_evidence, dict)
                or not isinstance(recomputed_evidence, dict)
                or any(
                    index_evidence.get(field) != recomputed_evidence.get(field)
                    for field in evidence_fields
                )
                or proposal.get("original_target_expression")
                    != recomputed.get("original_target_expression")
                or proposal.get("candidate_target_expression")
                    != recomputed.get("candidate_target_expression")
                or proposal.get("ranges") != recomputed.get("ranges")
                or proposal.get("rows") != recomputed.get("rows")
                or proposal.get("target_ids") != recomputed.get("target_ids")
            ):
                reject(
                    proposal_index,
                    proposal,
                    "cursor_loaded_or_non_direct_table_not_supported",
                )
                continue

            region = regions[source]
            behavior_pair = behaviors[source]
            original_outcome = (
                behavior_pair.get("original_ir", {}).get("outcome") or {}
            )
            candidate_outcome = (
                behavior_pair.get("candidate_ir", {}).get("outcome") or {}
            )
            original_continuation = _integer(
                original_outcome.get("continuation")
            )
            candidate_continuation = _integer(
                candidate_outcome.get("continuation")
            )
            if (
                original_outcome.get("op") != "indirect_call"
                or candidate_outcome.get("op") != "indirect_call"
                or original_outcome.get("target")
                    != recomputed["original_target_expression"]
                or candidate_outcome.get("target")
                    != recomputed["candidate_target_expression"]
                or original_continuation is None
                or original_continuation != candidate_continuation
                or original_continuation in duplicate_numeric_ids
                or original_continuation not in region_by_numeric_id
            ):
                reject(
                    proposal_index,
                    proposal,
                    "decoded_cursor_call_or_continuation_mismatch",
                )
                continue
            continuation_region_index = region_by_numeric_id[
                original_continuation
            ]
            canonical_continuations = [
                target for target in targets_by_region.get(
                    continuation_region_index, []
                )
                if _integer(target.get("original_rva"))
                    == _integer(regions[continuation_region_index].get(
                        "original", {}
                    ).get("rva_start"))
                and _integer(target.get("candidate_rva"))
                    == _integer(regions[continuation_region_index].get(
                        "candidate", {}
                    ).get("rva_start"))
            ]
            if (
                len(canonical_continuations) != 1
                or _integer(proposal.get("continuation_region_index"))
                    != continuation_region_index
                or _integer(proposal.get("continuation_target_id"))
                    != _integer(canonical_continuations[0].get("id"))
            ):
                reject(
                    proposal_index,
                    proposal,
                    "proposal_continuation_is_not_exact",
                )
                continue

            target_ids = [int(value) for value in recomputed["target_ids"]]
            target_inventory = _canonical_code_target_inventory(
                contract, target_ids
            )
            if target_inventory is None:
                reject(
                    proposal_index,
                    proposal,
                    "finite_target_inventory_is_not_canonical",
                )
                continue
            rows = [dict(row) for row in recomputed["rows"]]
            candidates.append({
                "input_contract": (
                    "bounded_immutable_code_pointer_table_call_v1"
                ),
                "profile": "immutable_code_pointer_table_call_v1",
                "shape": "cursor_loaded_table_word",
                "layout": "staticCallRangeCursor",
                "source_region_index": source,
                "continuation_region_index": continuation_region_index,
                "continuation_target_id": int(
                    canonical_continuations[0]["id"]
                ),
                "original_target_expression": original_outcome["target"],
                "candidate_target_expression": candidate_outcome["target"],
                "original_target_register": recomputed[
                    "original_target_register"
                ],
                "candidate_target_register": recomputed[
                    "candidate_target_register"
                ],
                "original_cursor_register": recomputed[
                    "original_cursor_register"
                ],
                "candidate_cursor_register": recomputed[
                    "candidate_cursor_register"
                ],
                "original_bound_register": recomputed[
                    "original_bound_register"
                ],
                "candidate_bound_register": recomputed[
                    "candidate_bound_register"
                ],
                "scale": 4,
                "index_evidence": dict(recomputed_evidence),
                "ranges": [dict(row) for row in recomputed["ranges"]],
                "rows": rows,
                "entry_target_ids": [
                    int(row["target_id"])
                    for row in rows if "target_id" in row
                ],
                "target_ids": target_ids,
                "target_inventory": target_inventory,
                "status": "candidate_requires_lean_replay",
                "acceptance_authority": False,
            })
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

        index_evidence = proposal.get("index_evidence")
        reverse_layout = (
            isinstance(index_evidence, dict)
            and index_evidence.get("kind")
            == "paired_sentinel_terminated_reverse_count"
        )
        layout = (
            "sentinelTerminatedReverseCount"
            if reverse_layout else "zeroBasedBounded"
        )
        proposal_ranges = proposal.get("ranges")
        reverse_entry_count: int | None = None
        if reverse_layout:
            recomputed = recomputed_reverse_by_source.get(source)
            role_fields = (
                "header_producer_region_index",
                "nonzero_predecessor_region_index",
                "decrement_region_index",
                "scanner_initializer_region_index",
                "scanner_region_index",
                "scanner_loop_region_index",
            )
            if (
                recomputed is None
                or not isinstance(recomputed.get("index_evidence"), dict)
                or any(
                    _integer(index_evidence.get(field))
                    != _integer(recomputed["index_evidence"].get(field))
                    for field in role_fields
                )
            ):
                reject(
                    proposal_index,
                    proposal,
                    "reverse_sentinel_control_evidence_mismatch",
                )
                continue
            if (
                not isinstance(proposal_ranges, list)
                or len(proposal_ranges) != 1
                or _integer(proposal_ranges[0].get("row_count")) is None
            ):
                reject(
                    proposal_index, proposal,
                    "reverse_sentinel_table_range_missing",
                )
                continue
            reverse_row_count = int(proposal_ranges[0]["row_count"])
            if not 1 <= reverse_row_count <= 4097:
                reject(
                    proposal_index, proposal,
                    "reverse_sentinel_table_row_count_invalid",
                )
                continue
            reverse_entry_count = reverse_row_count - 1
            shifted_original_index = {
                "op": "sub",
                "left": original_index,
                "right": {"op": "constant", "value": 1},
            }
            shifted_candidate_index = {
                "op": "sub",
                "left": candidate_index,
                "right": {"op": "constant", "value": 1},
            }
            expected_original_bound = shifted_original_index
            expected_candidate_bound = shifted_candidate_index
            expected_bound_upper = reverse_entry_count
        else:
            expected_original_bound = original_index
            expected_candidate_bound = candidate_index
            expected_bound_upper = None

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
                and 0 <= upper <= 4096
                and (
                    expected_bound_upper is None
                    and upper > 0
                    or upper == expected_bound_upper
                )
                and original_bound_expression == expected_original_bound
                and candidate_bound_expression == expected_candidate_bound
            ):
                matching_bounds.append(bound)
        empty_reverse_state_valid = (
            reverse_layout
            and reverse_entry_count == 0
            and region.get("state_predicates") == [
                _uninhabited_state_predicate()
            ]
            and not matching_bounds
        )
        bound_evidence_valid = (
            isinstance(index_evidence, dict)
            and index_evidence.get("original_expression") == original_index
            and index_evidence.get("candidate_expression") == candidate_index
            and _integer(index_evidence.get("scale")) == 4
            and (
                empty_reverse_state_valid
                or reverse_layout and len(matching_bounds) == 1
                or (
                    index_evidence.get("kind") == "paired_unsigned_bound"
                    and len(matching_bounds) == 1
                    and index_evidence.get("bound") == matching_bounds[0]
                )
            )
        )
        if not bound_evidence_valid:
            reject(proposal_index, proposal, "unique_checked_unsigned_bound_required")
            continue
        upper_exclusive = (
            int(reverse_entry_count) + 1
            if reverse_layout and reverse_entry_count is not None
            else int(matching_bounds[0]["unsigned_lt"])
        )
        lower_inclusive = 1 if reverse_layout else 0
        entry_count = upper_exclusive - lower_inclusive
        table_span_words = upper_exclusive + (1 if reverse_layout else 0)
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
        if entry_count > 0 and len(exact_index_relations) != 1:
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
                or original_offset + table_span_words * 4 > mapped_size
            ):
                continue
            relocation_offsets = {
                int(offset) for offset in value.get("relocation_offsets", [])
                if _integer(offset) is not None
            }
            required_offsets = {
                original_offset + index * 4
                for index in range(lower_inclusive, upper_exclusive)
            }
            relocation_offsets_in_table = {
                offset for offset in relocation_offsets
                if original_offset <= offset < original_offset + table_span_words * 4
            }
            if relocation_offsets_in_table == required_offsets:
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

        ranges = proposal_ranges
        expected_range_start_offset = 4 if reverse_layout else 0
        expected_range_words = (
            entry_count + 1 if reverse_layout else entry_count
        )
        expected_range_source = (
            "paired_sentinel_terminated_reverse_count"
            if reverse_layout else "paired_unsigned_bound"
        )
        if (
            not isinstance(ranges, list)
            or len(ranges) != 1
            or _integer(ranges[0].get("original_start"))
                != original_base + expected_range_start_offset
            or _integer(ranges[0].get("candidate_start"))
                != candidate_base + expected_range_start_offset
            or _integer(ranges[0].get("original_end"))
                != original_base + (expected_range_start_offset // 4
                    + expected_range_words) * 4
            or _integer(ranges[0].get("candidate_end"))
                != candidate_base + (expected_range_start_offset // 4
                    + expected_range_words) * 4
            or _integer(ranges[0].get("row_count")) != expected_range_words
            or ranges[0].get("source") != expected_range_source
        ):
            reject(proposal_index, proposal, "table_range_does_not_match_bound")
            continue

        proposed_rows = proposal.get("rows")
        if (
            not isinstance(proposed_rows, list)
            or len(proposed_rows) != expected_range_words
        ):
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
                or not 0 <= original_row_index < expected_range_words
            ):
                row_failure = "ambiguous_or_out_of_range_table_row"
                break
            raw_index = original_row_index + lower_inclusive
            if reverse_layout and original_row_index == entry_count:
                original_slot = original_base + raw_index * 4
                candidate_slot = candidate_base + raw_index * 4
                if (
                    row.get("kind") != "null"
                    or row.get("relocation_backed") is not False
                    or _integer(row.get("original_slot")) != original_slot
                    or _integer(row.get("candidate_slot")) != candidate_slot
                    or _integer(row.get("original_rva"))
                        != original_slot - original_image_base
                    or _integer(row.get("candidate_rva"))
                        != candidate_slot - candidate_image_base
                    or _integer(row.get("range_index")) != 0
                    or "target_id" in row
                ):
                    row_failure = "reverse_sentinel_terminator_mismatch"
                continue
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
            original_slot = original_base + raw_index * 4
            candidate_slot = candidate_base + raw_index * 4
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
            if raw_index in rows_by_index:
                row_failure = "ambiguous_or_out_of_range_table_row"
                break
            canonical_row = dict(row)
            canonical_row["original_index"] = raw_index
            canonical_row["candidate_index"] = raw_index
            rows_by_index[raw_index] = canonical_row
        expected_callable_indices = set(range(lower_inclusive, upper_exclusive))
        if row_failure is not None or set(rows_by_index) != expected_callable_indices:
            reject(
                proposal_index,
                proposal,
                row_failure or "table_rows_do_not_cover_every_index",
            )
            continue

        rows = [
            dict(rows_by_index[index])
            for index in range(lower_inclusive, upper_exclusive)
        ]
        entry_target_ids = [int(row["target_id"]) for row in rows]
        target_ids = sorted(set(entry_target_ids))
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
            "layout": layout,
            "scale": 4,
            "upper_exclusive": upper_exclusive,
            "original_index_register": original_index_register,
            "candidate_index_register": candidate_index_register,
            "original_index_expression": original_index,
            "candidate_index_expression": candidate_index,
            "original_target_expression": original_outcome["target"],
            "candidate_target_expression": candidate_outcome["target"],
            "index_evidence": dict(index_evidence),
            "rows": rows,
            "entry_target_ids": entry_target_ids,
            "target_ids": target_ids,
            "status": "candidate_requires_lean_replay",
            "acceptance_authority": False,
            **({"bound": dict(matching_bounds[0])} if matching_bounds else {}),
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
    regions = contract.get("regions", [])
    region_by_numeric_id: dict[int, int] = {}
    for region_index, candidate_region in enumerate(regions):
        numeric_id = _integer(candidate_region.get("numeric_id"))
        if numeric_id is None or numeric_id in region_by_numeric_id:
            return None
        region_by_numeric_id[numeric_id] = region_index
    source_numeric_id = _integer(region.get("numeric_id"))
    if source_numeric_id is None:
        return None

    producers: list[tuple[int, str, str]] = []
    for producer_index, (producer_region, producer_pair) in enumerate(zip(
        regions, behaviors, strict=True
    )):
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
            and _integer(original_exit.get("fallthrough")) == source_numeric_id
            and _integer(candidate_exit.get("fallthrough")) == source_numeric_id
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
        regions, behaviors, strict=True
    )):
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

    structural_predecessors: dict[int, set[int]] = defaultdict(set)
    for predecessor_index, behavior_pair in enumerate(behaviors):
        original_ir = behavior_pair["original_ir"]
        candidate_ir = behavior_pair["candidate_ir"]
        original_edges = [
            (str(edge["kind"]), int(edge["target"]))
            for edge in _semantic_edges(original_ir)
        ]
        candidate_edges = [
            (str(edge["kind"]), int(edge["target"]))
            for edge in _semantic_edges(candidate_ir)
        ]
        if original_edges != candidate_edges:
            continue
        for kind, numeric_target in original_edges:
            target_index = region_by_numeric_id.get(numeric_target)
            if target_index is not None and kind != "call":
                structural_predecessors[target_index].add(predecessor_index)
        original_continuation = _integer(
            (original_ir.get("outcome") or {}).get("continuation")
        )
        candidate_continuation = _integer(
            (candidate_ir.get("outcome") or {}).get("continuation")
        )
        if (
            original_continuation is not None
            and original_continuation == candidate_continuation
            and original_continuation in region_by_numeric_id
        ):
            structural_predecessors[
                region_by_numeric_id[original_continuation]
            ].add(predecessor_index)

    cursor_body = {producer_index}
    worklist = [producer_index]
    while worklist:
        target_index = worklist.pop()
        for predecessor_index in structural_predecessors.get(target_index, set()):
            if predecessor_index not in cursor_body:
                cursor_body.add(predecessor_index)
                worklist.append(predecessor_index)
    if source_index not in cursor_body or step_index not in cursor_body:
        return None
    entry_regions = sorted(
        region_index for region_index in cursor_body
        if not structural_predecessors.get(region_index, set()).intersection(
            cursor_body
        )
    )
    if len(entry_regions) != 1:
        return None
    entry_region_index = entry_regions[0]
    entry_numeric_id = int(regions[entry_region_index]["numeric_id"])
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
        if (
            not original_calls_entry
            or not candidate_calls_entry
            or caller_index in cursor_body
        ):
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
            "entry_evidence": "paired_structural_call_boundary",
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
    scanner_steps: list[tuple[int, str, str, str, str]] = []
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
                original_loaded = [
                    register for register, expression in original_registers.items()
                    if (
                        isinstance(expression, dict)
                        and _indexed_u32_table_read(expression)
                            == (original_base, original_scan_index)
                    )
                ]
                candidate_loaded = [
                    register for register, expression in candidate_registers.items()
                    if (
                        isinstance(expression, dict)
                        and _indexed_u32_table_read(expression)
                            == (candidate_base, candidate_scan_index)
                    )
                ]
                if len(original_loaded) == 1 and len(candidate_loaded) == 1:
                    scanner_steps.append((
                        region_index,
                        original_scan_register,
                        candidate_scan_register,
                        original_loaded[0],
                        candidate_loaded[0],
                    ))
    if not (
        len(header_producers) == 1
        and len(decrement_regions) == 1
        and len(nonzero_predecessors) == 1
        and len(scanner_steps) == 1
    ):
        return None

    (
        scanner_region_index,
        original_scan_register,
        candidate_scan_register,
        original_loaded_register,
        candidate_loaded_register,
    ) = scanner_steps[0]
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
    result = {
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
        "original_scanner_register": original_scan_register,
        "candidate_scanner_register": candidate_scan_register,
        "original_loaded_register": original_loaded_register,
        "candidate_loaded_register": candidate_loaded_register,
        "range": {
            "original_start": original_base + 4,
            "original_end": original_end,
            "candidate_start": candidate_base + 4,
            "candidate_end": candidate_end,
            "source": "paired_sentinel_terminated_reverse_count",
        },
    }
    split_cluster = _split_reverse_sentinel_scanner_cluster_evidence(
        contract,
        behaviors,
        header_producers[0],
        nonzero_predecessors[0],
        scanner_initializers[0],
        scanner_region_index,
        scanner_loops[0],
        original_register,
        candidate_register,
        original_scan_register,
        candidate_scan_register,
        original_loaded_register,
        candidate_loaded_register,
        original_base,
        candidate_base,
    )
    if split_cluster is not None:
        result["scanner_cluster"] = split_cluster
    return result


def _negated_input_flag(expression: Any) -> int | None:
    if not isinstance(expression, dict) or expression.get("op") != "not":
        return None
    value = expression.get("value")
    if not isinstance(value, dict) or value.get("op") != "input_flag":
        return None
    return _integer(value.get("index"))


def _split_reverse_sentinel_scanner_cluster_evidence(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    header_producer_region_index: int,
    gate_region_index: int,
    initializer_region_index: int,
    scanner_region_index: int,
    test_region_index: int,
    original_count_register: str,
    candidate_count_register: str,
    original_scanner_register: str,
    candidate_scanner_register: str,
    original_loaded_register: str,
    candidate_loaded_register: str,
    original_base: int,
    candidate_base: int,
) -> dict[str, Any] | None:
    """Check the exact split body/test shape used by a reverse sentinel scan."""
    regions = contract.get("regions", [])
    if not all(
        0 <= index < len(regions)
        for index in (
            header_producer_region_index,
            gate_region_index,
            initializer_region_index,
            scanner_region_index,
            test_region_index,
        )
    ):
        return None
    scanner_numeric_id = int(regions[scanner_region_index]["numeric_id"])
    test_numeric_id = int(regions[test_region_index]["numeric_id"])
    initializer_numeric_id = int(regions[initializer_region_index]["numeric_id"])
    gate_numeric_id = int(regions[gate_region_index]["numeric_id"])
    scanner_pair = behaviors[scanner_region_index]
    test_pair = behaviors[test_region_index]
    original_scanner = scanner_pair["original_ir"]
    candidate_scanner = scanner_pair["candidate_ir"]
    original_test = test_pair["original_ir"]
    candidate_test = test_pair["candidate_ir"]
    original_scanner_outcome = original_scanner.get("outcome") or {}
    candidate_scanner_outcome = candidate_scanner.get("outcome") or {}
    if not (
        original_scanner_outcome.get("op") == "jump"
        and candidate_scanner_outcome.get("op") == "jump"
        and _integer(original_scanner_outcome.get("target")) == test_numeric_id
        and _integer(candidate_scanner_outcome.get("target")) == test_numeric_id
        and not (original_scanner.get("writes") or [])
        and not (candidate_scanner.get("writes") or [])
    ):
        return None
    original_registers = original_scanner.get("registers") or {}
    candidate_registers = candidate_scanner.get("registers") or {}
    original_next_index = original_registers.get(original_scanner_register)
    candidate_next_index = candidate_registers.get(candidate_scanner_register)
    original_loaded = original_registers.get(original_loaded_register)
    candidate_loaded = candidate_registers.get(candidate_loaded_register)
    if not (
        original_registers.get(original_count_register)
            == {"op": "input_reg", "reg": original_scanner_register}
        and candidate_registers.get(candidate_count_register)
            == {"op": "input_reg", "reg": candidate_scanner_register}
        and _input_register_add(original_next_index, original_scanner_register) == 1
        and _input_register_add(candidate_next_index, candidate_scanner_register) == 1
        and _indexed_u32_table_read(original_loaded)
            == (original_base, original_next_index)
        and _indexed_u32_table_read(candidate_loaded)
            == (candidate_base, candidate_next_index)
        and _is_zero_test((original_scanner.get("flags") or {}).get("zero"), original_loaded)
        and _is_zero_test((candidate_scanner.get("flags") or {}).get("zero"), candidate_loaded)
    ):
        return None
    original_test_outcome = original_test.get("outcome") or {}
    candidate_test_outcome = candidate_test.get("outcome") or {}
    original_zero_flag = _negated_input_flag(original_test_outcome.get("condition"))
    candidate_zero_flag = _negated_input_flag(candidate_test_outcome.get("condition"))
    original_bridge_id = _integer(original_test_outcome.get("fallthrough"))
    candidate_bridge_id = _integer(candidate_test_outcome.get("fallthrough"))
    if not (
        original_test_outcome.get("op") == "branch"
        and candidate_test_outcome.get("op") == "branch"
        and _integer(original_test_outcome.get("taken")) == scanner_numeric_id
        and _integer(candidate_test_outcome.get("taken")) == scanner_numeric_id
        and original_bridge_id is not None
        and original_bridge_id == candidate_bridge_id
        and original_zero_flag == candidate_zero_flag == 6
        and not (original_test.get("writes") or [])
        and not (candidate_test.get("writes") or [])
    ):
        return None
    bridge_indices = [
        index for index, region in enumerate(regions)
        if _integer(region.get("numeric_id")) == original_bridge_id
    ]
    if len(bridge_indices) != 1:
        return None
    bridge_region_index = bridge_indices[0]
    bridge_pair = behaviors[bridge_region_index]
    original_bridge_outcome = (bridge_pair["original_ir"].get("outcome") or {})
    candidate_bridge_outcome = (bridge_pair["candidate_ir"].get("outcome") or {})
    if not (
        original_bridge_outcome.get("op") == "jump"
        and candidate_bridge_outcome.get("op") == "jump"
        and _integer(original_bridge_outcome.get("target")) == gate_numeric_id
        and _integer(candidate_bridge_outcome.get("target")) == gate_numeric_id
        and not (bridge_pair["original_ir"].get("writes") or [])
        and not (bridge_pair["candidate_ir"].get("writes") or [])
    ):
        return None
    header_branches = []
    for index, pair in enumerate(behaviors):
        original_outcome = pair["original_ir"].get("outcome") or {}
        candidate_outcome = pair["candidate_ir"].get("outcome") or {}
        if original_outcome.get("op") != "branch" or candidate_outcome.get("op") != "branch":
            continue
        if {
            _integer(original_outcome.get("taken")),
            _integer(original_outcome.get("fallthrough")),
        } != {initializer_numeric_id, gate_numeric_id}:
            continue
        if {
            _integer(candidate_outcome.get("taken")),
            _integer(candidate_outcome.get("fallthrough")),
        } != {initializer_numeric_id, gate_numeric_id}:
            continue
        header_branches.append(index)
    if len(header_branches) != 1:
        return None
    header_branch_region_index = header_branches[0]
    header_branch_numeric_id = int(regions[header_branch_region_index]["numeric_id"])
    header_pair = behaviors[header_producer_region_index]
    original_header_outcome = header_pair["original_ir"].get("outcome") or {}
    candidate_header_outcome = header_pair["candidate_ir"].get("outcome") or {}
    if not (
        original_header_outcome.get("op") == "jump"
        and candidate_header_outcome.get("op") == "jump"
        and _integer(original_header_outcome.get("target")) == header_branch_numeric_id
        and _integer(candidate_header_outcome.get("target")) == header_branch_numeric_id
    ):
        return None
    return {
        "profile": "bounded_reverse_sentinel_scanner_cluster_v1",
        "header_producer_region_index": header_producer_region_index,
        "header_branch_region_index": header_branch_region_index,
        "initializer_region_index": initializer_region_index,
        "scanner_region_index": scanner_region_index,
        "test_region_index": test_region_index,
        "bridge_region_index": bridge_region_index,
        "gate_region_index": gate_region_index,
        "original_count_register": original_count_register,
        "candidate_count_register": candidate_count_register,
        "original_scanner_register": original_scanner_register,
        "candidate_scanner_register": candidate_scanner_register,
        "original_loaded_register": original_loaded_register,
        "candidate_loaded_register": candidate_loaded_register,
        "zero_flag_bit": 6,
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


def _substitute_predecessor_register_outputs(
    expression: Any, registers: Mapping[str, Any],
) -> Any:
    if isinstance(expression, list):
        return [
            _substitute_predecessor_register_outputs(item, registers)
            for item in expression
        ]
    if not isinstance(expression, dict):
        return expression
    if expression.get("op") == "input_reg":
        replacement = registers.get(str(expression.get("reg")))
        return replacement if isinstance(replacement, dict) else expression
    return {
        key: _substitute_predecessor_register_outputs(value, registers)
        for key, value in expression.items()
    }


def _substitute_predecessor_flag_outputs(
    expression: Any, flags: Mapping[str, Any],
) -> Any:
    flag_names = {
        0: "carry",
        2: "parity",
        4: "auxiliary",
        6: "zero",
        7: "sign",
        11: "overflow",
    }
    if isinstance(expression, list):
        return [
            _substitute_predecessor_flag_outputs(item, flags)
            for item in expression
        ]
    if not isinstance(expression, dict):
        return expression
    if expression.get("op") == "input_flag":
        index = _integer(expression.get("index"))
        flag_name = flag_names.get(index) if index is not None else None
        replacement = flags.get(flag_name) if flag_name is not None else None
        return replacement if isinstance(replacement, dict) else expression
    return {
        key: _substitute_predecessor_flag_outputs(value, flags)
        for key, value in expression.items()
    }


def _normalized_static_index_expression(expression: Any) -> Any:
    if isinstance(expression, list):
        return [_normalized_static_index_expression(item) for item in expression]
    if not isinstance(expression, dict):
        return expression
    normalized = {
        key: _normalized_static_index_expression(value)
        for key, value in expression.items()
    }
    operation = normalized.get("op")
    if operation == "constant":
        value = _integer(normalized.get("value"))
        return (
            {"op": "constant", "value": value & 0xFFFFFFFF}
            if value is not None else normalized
        )
    if operation != "bit_and":
        return normalized
    left = normalized.get("left")
    right = normalized.get("right")
    if isinstance(left, dict) and left.get("op") == "constant":
        left, right = right, left
    mask = (
        _integer(right.get("value"))
        if isinstance(right, dict) and right.get("op") == "constant"
        else None
    )
    if not isinstance(left, dict) or mask is None:
        return normalized
    mask &= 0xFFFFFFFF
    if left.get("op") == "constant":
        value = _integer(left.get("value"))
        if value is not None:
            return {"op": "constant", "value": value & mask}
    if mask == 0xFFFFFFFF:
        return left
    if left.get("op") in {"read8", "read8_after_write"} and mask == 0xFF:
        return left
    if left.get("op") == "bit_and":
        nested_right = left.get("right")
        nested_mask = (
            _integer(nested_right.get("value"))
            if isinstance(nested_right, dict)
            and nested_right.get("op") == "constant"
            else None
        )
        if nested_mask is not None and (nested_mask & 0xFFFFFFFF) == mask:
            return left
    return {"op": "bit_and", "left": left, "right": {
        "op": "constant", "value": mask,
    }}


def _static_index_domain_mask(expression: Any) -> int | None:
    normalized = _normalized_static_index_expression(expression)
    if not isinstance(normalized, dict):
        return None
    if normalized.get("op") in {"read8", "read8_after_write"}:
        return 0xFF
    if normalized.get("op") != "bit_and":
        return None
    right = normalized.get("right")
    if not isinstance(right, dict) or right.get("op") != "constant":
        return None
    mask = _integer(right.get("value"))
    return (mask & 0xFFFFFFFF) if mask is not None else None


def _static_index_zero_equality_limit(
    expression: Any, index_expression: Any,
) -> int | None:
    normalized = _normalized_static_index_expression(expression)
    index = _normalized_static_index_expression(index_expression)
    if not isinstance(normalized, dict) or normalized.get("op") != "equal":
        return None
    left = normalized.get("left")
    right = normalized.get("right")
    if isinstance(left, dict) and left == {"op": "constant", "value": 0}:
        left, right = right, left
    if right != {"op": "constant", "value": 0} or not isinstance(left, dict):
        return None
    domain_mask = _static_index_domain_mask(index)
    if left.get("op") == "bit_and":
        mask_expression = left.get("right")
        mask = (
            _integer(mask_expression.get("value"))
            if isinstance(mask_expression, dict)
            and mask_expression.get("op") == "constant"
            else None
        )
        if mask is None or domain_mask != (mask & 0xFFFFFFFF):
            return None
        left = left.get("left")
    if not isinstance(left, dict) or left.get("op") != "sub":
        return None
    limit_expression = left.get("right")
    limit = (
        _integer(limit_expression.get("value"))
        if isinstance(limit_expression, dict)
        and limit_expression.get("op") == "constant"
        else None
    )
    if (
        limit is None
        or _normalized_static_index_expression(left.get("left")) != index
    ):
        return None
    return limit & 0xFFFFFFFF


def _static_index_guard_upper_exclusive(
    guard: Any, index_expression: Any,
) -> int | None:
    normalized = _normalized_static_index_expression(guard)
    index = _normalized_static_index_expression(index_expression)
    if not isinstance(normalized, dict):
        return None
    if normalized.get("op") == "unsigned_less":
        upper_expression = normalized.get("right")
        upper = (
            _integer(upper_expression.get("value"))
            if isinstance(upper_expression, dict)
            and upper_expression.get("op") == "constant"
            else None
        )
        if (
            upper is not None
            and _normalized_static_index_expression(normalized.get("left"))
                == index
            and 0 < upper <= 0xFFFFFFFF
        ):
            return upper
        return None
    if normalized.get("op") != "not":
        return None
    greater = normalized.get("value")
    if not isinstance(greater, dict) or greater.get("op") != "and":
        return None
    children = [greater.get("left"), greater.get("right")]
    lower_limit: int | None = None
    unequal_limit: int | None = None
    for child in children:
        if not isinstance(child, dict) or child.get("op") != "not":
            return None
        predicate = child.get("value")
        if not isinstance(predicate, dict):
            return None
        if predicate.get("op") == "unsigned_less":
            limit_expression = predicate.get("right")
            limit = (
                _integer(limit_expression.get("value"))
                if isinstance(limit_expression, dict)
                and limit_expression.get("op") == "constant"
                else None
            )
            if (
                limit is None
                or _normalized_static_index_expression(predicate.get("left"))
                    != index
            ):
                return None
            lower_limit = limit & 0xFFFFFFFF
        elif predicate.get("op") == "equal":
            unequal_limit = _static_index_zero_equality_limit(predicate, index)
        else:
            return None
    if (
        lower_limit is None
        or unequal_limit != lower_limit
        or lower_limit == 0xFFFFFFFF
    ):
        return None
    return lower_limit + 1


def _paired_flag_predecessor_table_bound(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    branch_index: int,
    original_index: dict[str, Any],
    candidate_index: dict[str, Any],
    original_guard: dict[str, Any],
    candidate_guard: dict[str, Any],
) -> dict[str, Any] | None:
    regions = contract.get("regions", [])
    if not 0 <= branch_index < len(regions) or len(regions) != len(behaviors):
        return None
    branch_region = regions[branch_index]
    if branch_region.get("root") or branch_region.get("function_entry"):
        return None
    branch_numeric_id = _integer(branch_region.get("numeric_id"))
    branch_target_ids = {
        int(target["id"])
        for target in contract.get("code_targets", [])
        if int(target.get("region_index", -1)) == branch_index
    }
    if branch_numeric_id is None or len(branch_target_ids) != 1:
        return None
    declared_producers = {
        region_index
        for region_index, region in enumerate(regions)
        if any(
            int(target.get("id", -1)) in branch_target_ids
            for target in region.get("code_targets", [])
        )
    }
    if not declared_producers:
        return None

    producer_rows: list[dict[str, Any]] = []
    semantic_producers: set[int] = set()
    upper_exclusive: int | None = None
    for producer_index, behavior_pair in enumerate(behaviors):
        incoming: dict[str, list[dict[str, Any]]] = {}
        for side in ("original", "candidate"):
            incoming[side] = [
                edge
                for edge in _semantic_edges(behavior_pair[f"{side}_ir"])
                if _integer(edge.get("target")) == branch_numeric_id
            ]
        if not incoming["original"] and not incoming["candidate"]:
            continue
        semantic_producers.add(producer_index)
        if (
            producer_index not in declared_producers
            or len(incoming["original"]) != 1
            or len(incoming["candidate"]) != 1
            or incoming["original"][0].get("kind")
                != incoming["candidate"][0].get("kind")
        ):
            return None
        original_behavior = behavior_pair["original_ir"]
        candidate_behavior = behavior_pair["candidate_ir"]
        if original_behavior.get("writes") or candidate_behavior.get("writes"):
            return None
        original_at_producer = _substitute_predecessor_register_outputs(
            original_index, original_behavior.get("registers") or {}
        )
        candidate_at_producer = _substitute_predecessor_register_outputs(
            candidate_index, candidate_behavior.get("registers") or {}
        )
        original_transformed_guard = _substitute_predecessor_register_outputs(
            _substitute_predecessor_flag_outputs(
                original_guard, original_behavior.get("flags") or {}
            ),
            original_behavior.get("registers") or {},
        )
        candidate_transformed_guard = _substitute_predecessor_register_outputs(
            _substitute_predecessor_flag_outputs(
                candidate_guard, candidate_behavior.get("flags") or {}
            ),
            candidate_behavior.get("registers") or {},
        )
        original_upper = _static_index_guard_upper_exclusive(
            original_transformed_guard, original_at_producer
        )
        candidate_upper = _static_index_guard_upper_exclusive(
            candidate_transformed_guard, candidate_at_producer
        )
        if original_upper is None or original_upper != candidate_upper:
            return None
        if upper_exclusive is None:
            upper_exclusive = original_upper
        elif upper_exclusive != original_upper:
            return None
        producer_rows.append({
            "region_index": producer_index,
            "edge_kind": str(incoming["original"][0]["kind"]),
            "original_edge_guard": incoming["original"][0]["guard"],
            "candidate_edge_guard": incoming["candidate"][0]["guard"],
            "original_index_at_producer": original_at_producer,
            "candidate_index_at_producer": candidate_at_producer,
            "original_transformed_guard": original_transformed_guard,
            "candidate_transformed_guard": candidate_transformed_guard,
        })
    if (
        upper_exclusive is None
        or semantic_producers != declared_producers
    ):
        return None
    return {
        "profile": "paired_flag_predecessor_unsigned_bound_v1",
        "branch_region_index": branch_index,
        "branch_target_ids": sorted(branch_target_ids),
        "upper_exclusive": upper_exclusive,
        "producers": sorted(
            producer_rows, key=lambda row: int(row["region_index"])
        ),
    }


def _paired_direct_predecessor_table_bound(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    source_index: int,
    original_index: dict[str, Any],
    candidate_index: dict[str, Any],
) -> dict[str, Any] | None:
    regions = contract.get("regions", [])
    if not 0 <= source_index < len(regions) or len(regions) != len(behaviors):
        return None
    source_region = regions[source_index]
    if source_region.get("root") or source_region.get("function_entry"):
        return None
    source_numeric_id = _integer(source_region.get("numeric_id"))
    source_target_ids = {
        int(target["id"])
        for target in contract.get("code_targets", [])
        if int(target.get("region_index", -1)) == source_index
    }
    if source_numeric_id is None or len(source_target_ids) != 1:
        return None
    declared_predecessors = {
        region_index
        for region_index, region in enumerate(regions)
        if any(
            int(target.get("id", -1)) in source_target_ids
            for target in region.get("code_targets", [])
        )
    }
    if not declared_predecessors:
        return None

    predecessor_rows: list[dict[str, Any]] = []
    upper_exclusive: int | None = None
    semantic_predecessors: set[int] = set()
    used_flag_dataflow = False
    for predecessor_index, behavior_pair in enumerate(behaviors):
        incoming: dict[str, list[dict[str, Any]]] = {}
        for side in ("original", "candidate"):
            incoming[side] = [
                edge
                for edge in _semantic_edges(behavior_pair[f"{side}_ir"])
                if _integer(edge.get("target")) == source_numeric_id
            ]
        if not incoming["original"] and not incoming["candidate"]:
            continue
        semantic_predecessors.add(predecessor_index)
        if (
            predecessor_index not in declared_predecessors
            or len(incoming["original"]) != 1
            or len(incoming["candidate"]) != 1
            or incoming["original"][0].get("kind")
                != incoming["candidate"][0].get("kind")
        ):
            return None
        original_behavior = behavior_pair["original_ir"]
        candidate_behavior = behavior_pair["candidate_ir"]
        if original_behavior.get("writes") or candidate_behavior.get("writes"):
            return None
        original_at_predecessor = _substitute_predecessor_register_outputs(
            original_index, original_behavior.get("registers") or {}
        )
        candidate_at_predecessor = _substitute_predecessor_register_outputs(
            candidate_index, candidate_behavior.get("registers") or {}
        )
        original_upper = _static_index_guard_upper_exclusive(
            incoming["original"][0].get("guard"), original_at_predecessor
        )
        candidate_upper = _static_index_guard_upper_exclusive(
            incoming["candidate"][0].get("guard"), candidate_at_predecessor
        )
        flag_dataflow = None
        if original_upper is None and candidate_upper is None:
            flag_dataflow = _paired_flag_predecessor_table_bound(
                contract,
                behaviors,
                predecessor_index,
                original_at_predecessor,
                candidate_at_predecessor,
                incoming["original"][0]["guard"],
                incoming["candidate"][0]["guard"],
            )
            if flag_dataflow is not None:
                original_upper = int(flag_dataflow["upper_exclusive"])
                candidate_upper = original_upper
                used_flag_dataflow = True
        if original_upper is None or original_upper != candidate_upper:
            return None
        if upper_exclusive is None:
            upper_exclusive = original_upper
        elif upper_exclusive != original_upper:
            return None
        predecessor_row = {
            "region_index": predecessor_index,
            "edge_kind": str(incoming["original"][0]["kind"]),
            "original_guard": incoming["original"][0]["guard"],
            "candidate_guard": incoming["candidate"][0]["guard"],
            "original_index_at_predecessor": original_at_predecessor,
            "candidate_index_at_predecessor": candidate_at_predecessor,
        }
        if flag_dataflow is not None:
            predecessor_row["flag_dataflow"] = flag_dataflow
        predecessor_rows.append(predecessor_row)
    if (
        upper_exclusive is None
        or semantic_predecessors != declared_predecessors
    ):
        return None
    return {
        "profile": (
            "paired_flag_dataflow_unsigned_bound_v1"
            if used_flag_dataflow
            else "paired_direct_predecessor_unsigned_bound_v1"
        ),
        "source_target_ids": sorted(source_target_ids),
        "upper_exclusive": upper_exclusive,
        "predecessors": sorted(
            predecessor_rows, key=lambda row: int(row["region_index"])
        ),
    }


def _canonical_code_target_inventory(
    contract: dict[str, Any], target_ids: list[int],
) -> list[dict[str, Any]] | None:
    inventory: list[dict[str, Any]] = []
    for target_id in sorted(set(target_ids)):
        matches = [
            target for target in contract.get("code_targets", [])
            if int(target.get("id", -1)) == target_id
        ]
        if len(matches) != 1:
            return None
        target = matches[0]
        inventory.append({
            "target_id": target_id,
            "target_region_index": int(target["region_index"]),
            "original_rva": int(target["original_rva"]),
            "candidate_rva": int(target["candidate_rva"]),
            "original_aliases": sorted({
                int(alias) for alias in target.get("original_aliases", [])
            }),
            "candidate_aliases": sorted({
                int(alias) for alias in target.get("candidate_aliases", [])
            }),
        })
    return inventory


def _code_target_inventory_from_relocation_rows(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]] | None:
    inventory: list[dict[str, Any]] = []
    target_ids = sorted({
        int(row["target_id"])
        for row in rows
        if row.get("kind") == "code_pointer"
    })
    for target_id in target_ids:
        target_rows = [
            row for row in rows
            if row.get("kind") == "code_pointer"
            and int(row["target_id"]) == target_id
        ]
        matches = [
            target for target in contract.get("code_targets", [])
            if int(target.get("id", -1)) == target_id
            and all(
                _absolute_code_target_matches(
                    original_bin, target, "original", int(row["original_word"])
                )
                and _absolute_code_target_matches(
                    candidate_bin, target, "candidate", int(row["candidate_word"])
                )
                for row in target_rows
            )
        ]
        if len(matches) != 1:
            return None
        target = matches[0]
        inventory.append({
            "target_id": target_id,
            "target_region_index": int(target["region_index"]),
            "original_rva": int(target["original_rva"]),
            "candidate_rva": int(target["candidate_rva"]),
            "original_aliases": sorted({
                int(alias) for alias in target.get("original_aliases", [])
            }),
            "candidate_aliases": sorted({
                int(alias) for alias in target.get("candidate_aliases", [])
            }),
        })
    return inventory


def _predecessor_bounded_immutable_relocation_table_jump_candidate(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    source_index: int,
    behaviors: list[dict[str, Any]],
    original_base: int,
    candidate_base: int,
    original_index: dict[str, Any],
    candidate_index: dict[str, Any],
) -> dict[str, Any] | None:
    bound = _paired_direct_predecessor_table_bound(
        contract, behaviors, source_index, original_index, candidate_index
    )
    if bound is None:
        return None
    upper_exclusive = int(bound["upper_exclusive"])
    relocation_type = 3 if original_bin.bitness == 32 else 10
    if candidate_bin.bitness != original_bin.bitness:
        return None
    original_relocations = Counter(
        int(relocation["rva"])
        for relocation in _raw_base_relocations(original_bin)
        if int(relocation["type"]) == relocation_type
    )
    candidate_relocations = Counter(
        int(relocation["rva"])
        for relocation in _raw_base_relocations(candidate_bin)
        if int(relocation["type"]) == relocation_type
    )
    if (
        upper_exclusive <= 0
        or upper_exclusive > len(original_relocations)
        or upper_exclusive > len(candidate_relocations)
    ):
        return None

    rows: list[dict[str, Any]] = []
    entry_target_ids: list[int] = []
    for index in range(upper_exclusive):
        original_slot = original_base + index * 4
        candidate_slot = candidate_base + index * 4
        original_rva = original_slot - original_bin.image_base
        candidate_rva = candidate_slot - candidate_bin.image_base
        if (
            original_relocations[original_rva] != 1
            or candidate_relocations[candidate_rva] != 1
        ):
            return None
        original_word = _immutable_section_u32(original_bin, original_slot)
        candidate_word = _immutable_section_u32(candidate_bin, candidate_slot)
        if original_word is None or candidate_word is None:
            return None
        matches = [
            target for target in contract.get("code_targets", [])
            if _absolute_code_target_matches(
                original_bin, target, "original", original_word
            )
            and _absolute_code_target_matches(
                candidate_bin, target, "candidate", candidate_word
            )
        ]
        if len(matches) != 1:
            return None
        target_id = int(matches[0]["id"])
        entry_target_ids.append(target_id)
        rows.append({
            "index": index,
            "target_id": target_id,
            "original_slot": original_slot,
            "candidate_slot": candidate_slot,
            "original_relocation_rva": original_rva,
            "candidate_relocation_rva": candidate_rva,
            "original_word": original_word,
            "candidate_word": candidate_word,
        })
    target_ids = sorted(set(entry_target_ids))
    target_inventory = _canonical_code_target_inventory(contract, target_ids)
    if not target_ids or target_inventory is None:
        return None
    return {
        "profile": "predecessor_bounded_immutable_relocation_table_jump_v1",
        "status": "candidate_requires_lean_replay",
        "acceptance_authority": False,
        "source_region_index": source_index,
        "original_base": original_base,
        "candidate_base": candidate_base,
        "original_index_expression": original_index,
        "candidate_index_expression": candidate_index,
        "upper_exclusive": upper_exclusive,
        "entry_target_ids": entry_target_ids,
        "target_ids": target_ids,
        "target_inventory": target_inventory,
        "provenance": {
            "profile": "paired_bounded_immutable_relocation_rows_v1",
            "bound": bound,
            "rows": rows,
        },
    }


def _bounded_immutable_relocation_table_jump_candidate(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    contract: dict[str, Any],
    region: dict[str, Any],
    source_index: int,
    behaviors: list[dict[str, Any]],
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
        return _predecessor_bounded_immutable_relocation_table_jump_candidate(
            original_bin,
            candidate_bin,
            contract,
            source_index,
            behaviors,
            original_base,
            candidate_base,
            original_index,
            candidate_index,
        )
    matched_bound = matching_bounds[0]
    upper_exclusive = int(matched_bound["unsigned_lt"])

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
    exact_start_values = [
        (value, offset) for value, offset in matching_values if offset == 0
    ]
    if exact_start_values:
        matching_values = exact_start_values
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
    target_inventory = _canonical_code_target_inventory(contract, target_ids)
    available_target_ids = {
        int(item["id"]) for item in region.get("code_targets", [])
    }
    if (
        not target_ids
        or target_inventory is None
        or not set(target_ids).issubset(available_target_ids)
    ):
        return None
    return {
        "profile": "bounded_immutable_relocation_table_jump_v1",
        "status": "candidate_requires_lean_replay",
        "acceptance_authority": False,
        "source_region_index": source_index,
        "value_target_id": int(table["id"]),
        "table_offset": table_offset,
        "original_base": original_base,
        "candidate_base": candidate_base,
        "original_index_expression": original_index,
        "candidate_index_expression": candidate_index,
        "original_index_register": str(matched_bound["original"]),
        "candidate_index_register": str(matched_bound["candidate"]),
        "upper_exclusive": upper_exclusive,
        "entry_target_ids": entry_target_ids,
        "target_ids": target_ids,
        "target_inventory": target_inventory,
        "provenance": {
            "profile": "declared_bound_mapped_relocation_table_v1",
            "bound": matched_bound,
            "value_target_id": int(table["id"]),
            "table_offset": table_offset,
            "relocation_offsets": [
                table_offset + index * 4
                for index in range(upper_exclusive)
            ],
        },
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


def _affine_input_register_offset(
    expression: Any, register: str,
) -> int | None:
    if _input_register(expression) == register:
        return 0
    if not isinstance(expression, dict):
        return None
    operation = expression.get("op")
    if operation not in {"add", "sub"}:
        return None
    left = _affine_input_register_offset(expression.get("left"), register)
    right = expression.get("right")
    constant = (
        _integer(right.get("value"))
        if isinstance(right, dict) and right.get("op") == "constant"
        else None
    )
    if left is None or constant is None:
        return None
    return (
        left + constant if operation == "add" else left - constant
    ) & 0xFFFFFFFF


def _normalize_subtracted_register_writes(expression: Any) -> Any:
    if isinstance(expression, list):
        return [
            _normalize_subtracted_register_writes(item) for item in expression
        ]
    if not isinstance(expression, dict):
        return expression
    normalized = {
        key: _normalize_subtracted_register_writes(value)
        for key, value in expression.items()
    }
    if normalized.get("op") != "sub":
        return normalized
    register = _input_register(normalized.get("left"))
    right = normalized.get("right")
    constant = (
        _integer(right.get("value"))
        if isinstance(right, dict) and right.get("op") == "constant"
        else None
    )
    if register is None or constant is None:
        return normalized
    return {
        "op": "add",
        "left": {"op": "input_reg", "reg": register},
        "right": {"op": "constant", "value": (-constant) & 0xFFFFFFFF},
    }


def _assembled_static_word_after_writes(
    expression: Any,
) -> tuple[int, list[dict[str, Any]]] | None:
    if not isinstance(expression, dict):
        return None
    assembled = _assembled_u32_after_register_writes(expression)
    if assembled is not None:
        return assembled
    normalized = _normalize_subtracted_register_writes(expression)
    return (
        _assembled_u32_after_register_writes(normalized)
        if isinstance(normalized, dict) else None
    )


def _register_writes_have_stack_window_separations(
    region: Mapping[str, Any],
    side: str,
    word_address: int,
    writes: list[dict[str, Any]],
) -> bool:
    claims = [
        claim for claim in region.get("stack_address_separation_claims", [])
        if isinstance(claim, dict)
        and isinstance(claim.get("window"), dict)
        and isinstance(claim.get("separation"), dict)
    ]
    for write in writes:
        register = str(write.get("register"))
        offset = _integer(write.get("offset"))
        if offset is None:
            return False
        signed_offset = offset if offset < 2**31 else offset - 2**32
        matching_windows = [
            claim["window"] for claim in claims
            if str(claim["window"].get(f"{side}_register")) == register
            and -int(claim["window"].get("bytes_below", -1))
                <= signed_offset
            and signed_offset + 3
                <= int(claim["window"].get("bytes_above", -1))
        ]
        if not matching_windows:
            return False
        if not any(
            all(
                any(
                    claim["window"] == window
                    and int(claim["separation"].get(
                        f"{side}_address", -1
                    )) == word_address + byte
                    for claim in claims
                )
                for byte in range(4)
            )
            for window in matching_windows
        ):
            return False
    return True


def _indirect_provenance_dataflow_candidates(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
    *,
    original_image_base: int,
    candidate_image_base: int,
    import_register_seeds: list[dict[str, Any]] | None = None,
    import_call_candidates: list[dict[str, Any]] | None = None,
    excluded_source_indices: set[int] | None = None,
    finite_target_budget: int = 64,
) -> list[dict[str, Any]]:
    """Recover finite indirect targets from paired producer evidence.

    This pass deliberately runs after register analysis. It never treats raw
    writable image bytes as runtime state: static words must already have a
    fixed-code-pointer certificate, and imports must come from paired IAT seeds.
    Every incoming producer must resolve before a proposal is emitted.
    """
    regions = contract.get("regions", [])
    if len(regions) != len(behaviors):
        raise StageAInputError(
            "indirect provenance dataflow requires one behavior per region"
        )
    excluded = excluded_source_indices or set()
    relation_regions = register_relations.get("regions", [])

    target_rows_by_id: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for target in contract.get("code_targets", []):
        target_id = _integer(target.get("id"))
        if target_id is not None:
            target_rows_by_id[target_id].append(target)
    canonical_targets = {
        target_id: rows[0]
        for target_id, rows in target_rows_by_id.items()
        if len(rows) == 1
        and 0 <= int(rows[0].get("region_index", -1)) < len(regions)
        and int(rows[0].get("original_rva", -1))
            == int(regions[int(rows[0]["region_index"])]["original"]["rva_start"])
        and int(rows[0].get("candidate_rva", -1))
            == int(regions[int(rows[0]["region_index"])]["candidate"]["rva_start"])
    }
    absolute_targets: dict[str, dict[int, set[int]]] = {
        "original": defaultdict(set),
        "candidate": defaultdict(set),
    }
    for target_id, target in canonical_targets.items():
        for side, image_base in (
            ("original", original_image_base),
            ("candidate", candidate_image_base),
        ):
            for rva in (
                int(target[f"{side}_rva"]),
                *(
                    int(alias)
                    for alias in target.get(f"{side}_aliases", [])
                ),
            ):
                absolute_targets[side][(image_base + rva) & 0xFFFFFFFF].add(
                    target_id
                )

    static_slot_targets: dict[tuple[int, int], set[int]] = defaultdict(set)
    for slot in contract.get("static_word_relation_slots", []):
        target_id = _integer(slot.get("target_id"))
        original_address = _integer(slot.get("original_address"))
        candidate_address = _integer(slot.get("candidate_address"))
        if (
            slot.get("relation") == "fixed_code_pointer"
            and target_id in canonical_targets
            and original_address is not None
            and candidate_address is not None
        ):
            static_slot_targets[
                (original_address & 0xFFFFFFFF, candidate_address & 0xFFFFFFFF)
            ].add(int(target_id))

    import_identity_by_key: dict[str, dict[str, Any]] = {}
    import_slot_keys: dict[tuple[int, int], set[str]] = defaultdict(set)
    for seed in import_register_seeds or []:
        original_address = _integer(seed.get("original_absolute_address"))
        candidate_address = _integer(seed.get("candidate_absolute_address"))
        imported = seed.get("import")
        if (
            original_address is None
            or candidate_address is None
            or not isinstance(imported, dict)
        ):
            continue
        identity_key = json.dumps(imported, sort_keys=True, separators=(",", ":"))
        import_identity_by_key[identity_key] = dict(imported)
        import_slot_keys[
            (original_address & 0xFFFFFFFF, candidate_address & 0xFFFFFFFF)
        ].add(identity_key)

    incoming_edges: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for edge in register_relations.get("edges", []):
        source = _integer(edge.get("source_region_index"))
        target = _integer(edge.get("target_region_index"))
        kind = str(edge.get("kind"))
        candidate_kind = str(edge.get("candidate_kind", kind))
        if (
            source is None
            or target is None
            or not 0 <= source < len(regions)
            or not 0 <= target < len(regions)
            or kind != candidate_kind
            or bool(edge.get("environment_barrier"))
            or bool(edge.get("requires_call_stack_proof"))
        ):
            continue
        incoming_edges[target].append(edge)

    region_by_numeric_id: dict[int, int] = {}
    duplicate_numeric_ids: set[int] = set()
    for index, region in enumerate(regions):
        numeric_id = _integer(region.get("numeric_id"))
        if numeric_id is None:
            continue
        if numeric_id in region_by_numeric_id:
            duplicate_numeric_ids.add(numeric_id)
        else:
            region_by_numeric_id[numeric_id] = index

    external_continuations: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for call in import_call_candidates or []:
        source = _integer(call.get("source_region_index"))
        continuation = _integer(call.get("continuation_region_index"))
        imported = call.get("import")
        if (
            source is None
            or continuation is None
            or not 0 <= source < len(regions)
            or not 0 <= continuation < len(regions)
            or not isinstance(imported, dict)
        ):
            continue
        contracts = [
            item for item in contract.get("machine_import_call_contracts", [])
            if item.get("import") == imported
            and item.get("disposition") == "returns"
            and item.get("memory_effect") == "readOnly"
            and _integer(item.get("stack_result_delta")) is not None
        ]
        if len(contracts) != 1:
            continue
        external_continuations[continuation].append({
            "source_region_index": source,
            "import": dict(imported),
            "stack_result_delta": int(contracts[0]["stack_result_delta"]),
            "preserved_registers": sorted({
                str(register)
                for register in contracts[0].get("preserved_registers", [])
            }),
        })

    def code_facts(target_ids: set[int]) -> frozenset[str]:
        return frozenset(f"code:{target_id}" for target_id in target_ids)

    def import_facts(identity_keys: set[str]) -> frozenset[str]:
        return frozenset(f"import:{key}" for key in identity_keys)

    cycle = object()

    def unresolved(resolution: Any) -> bool:
        return resolution is None or resolution is cycle

    def merge_resolutions(
        resolutions: list[Any], step: dict[str, Any],
    ) -> Any:
        if not resolutions or any(resolution is None for resolution in resolutions):
            return None
        concrete = [
            resolution for resolution in resolutions if resolution is not cycle
        ]
        if not concrete:
            return cycle
        facts = frozenset(
            fact for resolution in concrete for fact in resolution[0]
        )
        if not facts or len(facts) > finite_target_budget:
            return None
        evidence = [
            row for resolution in concrete for row in resolution[1]
        ]
        evidence.append(step)
        return facts, evidence

    def fixed_register_relation(
        region_index: int,
        relation_key: str,
        original_register: str,
        candidate_register: str,
    ) -> Any:
        if not 0 <= region_index < len(relation_regions):
            return None
        matches = [
            relation
            for relation in relation_regions[region_index].get(relation_key, [])
            if relation.get("relation") == "fixed_code_pointer"
            and relation.get("original") == original_register
            and relation.get("candidate") == candidate_register
            and _integer(relation.get("target_id")) in canonical_targets
        ]
        target_ids = {int(relation["target_id"]) for relation in matches}
        if len(target_ids) != 1:
            return None
        target_id = next(iter(target_ids))
        return code_facts({target_id}), [{
            "kind": f"checked_register_{relation_key[:-1]}",
            "region_index": region_index,
            "original_register": original_register,
            "candidate_register": candidate_register,
            "target_id": target_id,
        }]

    def static_resolution(
        region_index: int,
        original_expression: Any,
        candidate_expression: Any,
    ) -> Any:
        original_direct = (
            _constant_read32_address(original_expression)
            if isinstance(original_expression, dict) else None
        )
        candidate_direct = (
            _constant_read32_address(candidate_expression)
            if isinstance(candidate_expression, dict) else None
        )
        original_writes: list[dict[str, Any]] = []
        candidate_writes: list[dict[str, Any]] = []
        assembled = False
        if original_direct is None or candidate_direct is None:
            original_assembled = _assembled_static_word_after_writes(
                original_expression
            )
            candidate_assembled = _assembled_static_word_after_writes(
                candidate_expression
            )
            if original_assembled is None or candidate_assembled is None:
                return None
            original_direct, original_writes = original_assembled
            candidate_direct, candidate_writes = candidate_assembled
            assembled = True
            region = regions[region_index]
            if not (
                _register_writes_have_address_separations(
                    region, "original", original_direct, original_writes
                )
                or _register_writes_have_stack_window_separations(
                    region, "original", original_direct, original_writes
                )
            ) or not (
                _register_writes_have_address_separations(
                    region, "candidate", candidate_direct, candidate_writes
                )
                or _register_writes_have_stack_window_separations(
                    region, "candidate", candidate_direct, candidate_writes
                )
            ):
                return None
        key = (original_direct & 0xFFFFFFFF, candidate_direct & 0xFFFFFFFF)
        target_ids = static_slot_targets.get(key, set())
        if len(target_ids) == 1:
            target_id = next(iter(target_ids))
            return code_facts({target_id}), [{
                "kind": (
                    "assembled_certified_static_code_pointer"
                    if assembled else "certified_static_code_pointer"
                ),
                "region_index": region_index,
                "original_address": key[0],
                "candidate_address": key[1],
                "target_id": target_id,
                "original_writes": original_writes,
                "candidate_writes": candidate_writes,
            }]
        identity_keys = import_slot_keys.get(key, set())
        if len(identity_keys) == 1 and not assembled:
            identity_key = next(iter(identity_keys))
            return import_facts({identity_key}), [{
                "kind": "paired_iat_seed",
                "region_index": region_index,
                "original_address": key[0],
                "candidate_address": key[1],
                "import": import_identity_by_key[identity_key],
            }]
        return None

    def constant_resolution(
        region_index: int,
        original_expression: Any,
        candidate_expression: Any,
    ) -> Any:
        if not (
            isinstance(original_expression, dict)
            and original_expression.get("op") == "constant"
            and isinstance(candidate_expression, dict)
            and candidate_expression.get("op") == "constant"
        ):
            return None
        original_value = _integer(original_expression.get("value"))
        candidate_value = _integer(candidate_expression.get("value"))
        if original_value is None or candidate_value is None:
            return None
        original_targets = absolute_targets["original"].get(
            original_value & 0xFFFFFFFF, set()
        )
        candidate_targets = absolute_targets["candidate"].get(
            candidate_value & 0xFFFFFFFF, set()
        )
        if not original_targets or original_targets != candidate_targets:
            return None
        return code_facts(set(original_targets)), [{
            "kind": "paired_constant_code_address",
            "region_index": region_index,
            "original_value": original_value & 0xFFFFFFFF,
            "candidate_value": candidate_value & 0xFFFFFFFF,
            "target_ids": sorted(original_targets),
        }]

    def stack_write_value(
        behavior: Mapping[str, Any], offset: int,
    ) -> tuple[Any, bool]:
        selected: Any = None
        target_signed = offset if offset < 2**31 else offset - 2**32
        for write in behavior.get("writes", []):
            write_offset = _affine_input_register_offset(
                write.get("address"), "esp"
            )
            if write_offset is None:
                address = write.get("address")
                if not (
                    isinstance(address, dict)
                    and address.get("op") == "constant"
                ):
                    return None, False
                continue
            write_signed = (
                write_offset if write_offset < 2**31 else write_offset - 2**32
            )
            if max(write_signed, target_signed) < min(
                write_signed + 4, target_signed + 4
            ):
                if write_offset != offset:
                    return None, False
                selected = write.get("value")
        return selected, True

    def resolve_source_stack(
        source: int,
        original_offset: int,
        candidate_offset: int,
        active: set[tuple[Any, ...]],
    ) -> Any:
        original_value, original_valid = stack_write_value(
            behaviors[source]["original_ir"], original_offset
        )
        candidate_value, candidate_valid = stack_write_value(
            behaviors[source]["candidate_ir"], candidate_offset
        )
        if not original_valid or not candidate_valid:
            return None
        if (original_value is None) != (candidate_value is None):
            return None
        if original_value is not None:
            resolution = resolve_expression(
                source, original_value, candidate_value, active
            )
            if unresolved(resolution):
                return resolution
            return resolution[0], [*resolution[1], {
                "kind": "paired_stack_write_producer",
                "region_index": source,
                "original_offset": original_offset,
                "candidate_offset": candidate_offset,
            }]
        return resolve_stack_input(
            source, original_offset, candidate_offset, active
        )

    def resolve_stack_input(
        region_index: int,
        original_offset: int,
        candidate_offset: int,
        active: set[tuple[Any, ...]],
    ) -> Any:
        state = (
            "stack", region_index, original_offset & 0xFFFFFFFF,
            candidate_offset & 0xFFFFFFFF,
        )
        if state in active:
            return cycle
        next_active = {*active, state}
        resolutions: list[Any] = []
        for edge in incoming_edges.get(region_index, []):
            source = int(edge["source_region_index"])
            original_esp = behaviors[source]["original_ir"].get(
                "registers", {}
            ).get("esp")
            candidate_esp = behaviors[source]["candidate_ir"].get(
                "registers", {}
            ).get("esp")
            original_delta = _affine_input_register_offset(original_esp, "esp")
            candidate_delta = _affine_input_register_offset(candidate_esp, "esp")
            if original_delta is None or candidate_delta is None:
                return None
            resolutions.append(resolve_source_stack(
                source,
                (original_offset + original_delta) & 0xFFFFFFFF,
                (candidate_offset + candidate_delta) & 0xFFFFFFFF,
                next_active,
            ))
        for continuation in external_continuations.get(region_index, []):
            source = int(continuation["source_region_index"])
            delta = int(continuation["stack_result_delta"])
            resolution = resolve_source_stack(
                source,
                (original_offset + delta) & 0xFFFFFFFF,
                (candidate_offset + delta) & 0xFFFFFFFF,
                next_active,
            )
            if not unresolved(resolution):
                resolution = resolution[0], [*resolution[1], {
                    "kind": "checked_external_stack_transfer",
                    "source_region_index": source,
                    "target_region_index": region_index,
                    "stack_result_delta": delta,
                    "import": continuation["import"],
                }]
            resolutions.append(resolution)
        return merge_resolutions(resolutions, {
            "kind": "paired_stack_input_join",
            "region_index": region_index,
            "original_offset": original_offset & 0xFFFFFFFF,
            "candidate_offset": candidate_offset & 0xFFFFFFFF,
        })

    def resolve_register_input(
        region_index: int,
        original_register: str,
        candidate_register: str,
        active: set[tuple[Any, ...]],
    ) -> Any:
        fixed = fixed_register_relation(
            region_index, "inputs", original_register, candidate_register
        )
        if fixed is not None:
            return fixed
        state = (
            "register", region_index, original_register, candidate_register,
        )
        if state in active:
            return cycle
        next_active = {*active, state}
        resolutions: list[Any] = []
        for edge in incoming_edges.get(region_index, []):
            source = int(edge["source_region_index"])
            fixed_output = fixed_register_relation(
                source, "outputs", original_register, candidate_register
            )
            if fixed_output is not None:
                resolution = fixed_output
            else:
                original_expression = behaviors[source]["original_ir"].get(
                    "registers", {}
                ).get(original_register)
                candidate_expression = behaviors[source]["candidate_ir"].get(
                    "registers", {}
                ).get(candidate_register)
                resolution = resolve_expression(
                    source, original_expression, candidate_expression, next_active
                )
            if not unresolved(resolution):
                resolution = resolution[0], [*resolution[1], {
                    "kind": "checked_register_edge",
                    "source_region_index": source,
                    "target_region_index": region_index,
                    "original_register": original_register,
                    "candidate_register": candidate_register,
                }]
            resolutions.append(resolution)
        for continuation in external_continuations.get(region_index, []):
            if (
                original_register not in continuation["preserved_registers"]
                or candidate_register not in continuation["preserved_registers"]
            ):
                resolutions.append(None)
                continue
            source = int(continuation["source_region_index"])
            resolution = resolve_register_input(
                source, original_register, candidate_register, next_active
            )
            if not unresolved(resolution):
                resolution = resolution[0], [*resolution[1], {
                    "kind": "checked_external_register_preservation",
                    "source_region_index": source,
                    "target_region_index": region_index,
                    "original_register": original_register,
                    "candidate_register": candidate_register,
                    "import": continuation["import"],
                }]
            resolutions.append(resolution)
        return merge_resolutions(resolutions, {
            "kind": "paired_register_input_join",
            "region_index": region_index,
            "original_register": original_register,
            "candidate_register": candidate_register,
        })

    def resolve_expression(
        region_index: int,
        original_expression: Any,
        candidate_expression: Any,
        active: set[tuple[Any, ...]],
    ) -> Any:
        original_register = _input_register(original_expression)
        candidate_register = _input_register(candidate_expression)
        if original_register is not None or candidate_register is not None:
            if original_register is None or candidate_register is None:
                return None
            return resolve_register_input(
                region_index, original_register, candidate_register, active
            )
        constant = constant_resolution(
            region_index, original_expression, candidate_expression
        )
        if constant is not None:
            return constant
        static = static_resolution(
            region_index, original_expression, candidate_expression
        )
        if static is not None:
            return static
        if not (
            isinstance(original_expression, dict)
            and original_expression.get("op") == "read32"
            and isinstance(candidate_expression, dict)
            and candidate_expression.get("op") == "read32"
        ):
            return None
        original_offset = _affine_input_register_offset(
            original_expression.get("address"), "esp"
        )
        candidate_offset = _affine_input_register_offset(
            candidate_expression.get("address"), "esp"
        )
        if original_offset is None or candidate_offset is None:
            return None
        return resolve_stack_input(
            region_index, original_offset, candidate_offset, active
        )

    result: list[dict[str, Any]] = []
    for source, (region, behavior_pair) in enumerate(zip(
        regions, behaviors, strict=True
    )):
        if source in excluded:
            continue
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        operation = str(original_outcome.get("op"))
        if (
            operation not in {"indirect_call", "indirect_jump"}
            or candidate_outcome.get("op") != operation
        ):
            continue
        resolution = resolve_expression(
            source,
            original_outcome.get("target"),
            candidate_outcome.get("target"),
            set(),
        )
        if unresolved(resolution):
            continue
        facts, evidence = resolution
        code_target_ids = sorted({
            int(fact.removeprefix("code:"))
            for fact in facts if fact.startswith("code:")
        })
        import_keys = sorted({
            fact.removeprefix("import:")
            for fact in facts if fact.startswith("import:")
        })
        if bool(code_target_ids) == bool(import_keys):
            continue
        continuation_region_index: int | None = None
        continuation_target_id: int | None = None
        if operation == "indirect_call":
            original_continuation = _integer(original_outcome.get("continuation"))
            candidate_continuation = _integer(candidate_outcome.get("continuation"))
            if (
                original_continuation is None
                or original_continuation != candidate_continuation
                or original_continuation in duplicate_numeric_ids
                or original_continuation not in region_by_numeric_id
            ):
                continue
            continuation_region_index = region_by_numeric_id[original_continuation]
            continuation_targets = [
                target for target in canonical_targets.values()
                if int(target["region_index"]) == continuation_region_index
            ]
            if len(continuation_targets) != 1:
                continue
            continuation_target_id = int(continuation_targets[0]["id"])
        unique_evidence = {
            json.dumps(row, sort_keys=True, separators=(",", ":")): row
            for row in evidence
        }
        provenance = {
            "profile": "paired_indirect_provenance_dataflow_v1",
            "steps": [
                unique_evidence[key] for key in sorted(unique_evidence)
            ],
        }
        row: dict[str, Any] = {
            "profile": "finite_indirect_provenance_dataflow_v1",
            "status": "candidate_requires_lean_replay",
            "acceptance_authority": False,
            "source_region_index": source,
            "operation": operation,
            "provenance": provenance,
        }
        if code_target_ids:
            target_inventory = _canonical_code_target_inventory(
                contract, code_target_ids
            )
            if target_inventory is None:
                continue
            row.update({
                "target_kind": "internal_code",
                "target_ids": code_target_ids,
                "target_inventory": target_inventory,
            })
        else:
            if operation != "indirect_call" or len(import_keys) != 1:
                continue
            identity_key = import_keys[0]
            if identity_key not in import_identity_by_key:
                continue
            machine_contracts = [
                item for item in contract.get("machine_import_call_contracts", [])
                if item.get("import") == import_identity_by_key[identity_key]
                and item.get("disposition") in {"returns", "terminates"}
            ]
            if len(machine_contracts) != 1:
                continue
            row.update({
                "target_kind": "import",
                "target_ids": [],
                "import": import_identity_by_key[identity_key],
                "machine_contract_id": int(machine_contracts[0]["id"]),
            })
        if continuation_region_index is not None:
            row.update({
                "continuation_region_index": continuation_region_index,
                "continuation_target_id": continuation_target_id,
            })
        result.append(row)
    return result


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
