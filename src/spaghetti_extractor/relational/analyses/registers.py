from __future__ import annotations

import json
from typing import Any

from ...stage_binary import StageABinary
from ..contract import _import_identity, _semantic_expr_is_pure
from ..extraction import (
    _assembled_u32_after_register_writes,
    _semantic_exact_memory_inputs,
    _unique_import_at_absolute_address,
)
from ..model import _semantic_constant_bool, _semantic_hash
from ..schema import STAGE_A_RELATIONAL_MODEL_ID
from .control import _constant_read32_address, _immutable_image_u32
from .external import _semantic_external_target_identity
from .invariants import _semantic_edges
from .segments import _semantic_expr_registers
from .stack import (
    _attach_return_slot_contracts,
    _direct_call_push_claim,
    _indirect_call_push_claim,
    _return_pop_claim,
)


_REGISTER_RELATION_KINDS = {
    "exact", "code_pointer", "data_pointer", "related_word",
}
_PE32_EXTERNAL_REGISTER_POLICY_ID = "win32-cdecl-stdcall-registers-v1"
_PE32_EXTERNAL_PRESERVED_REGISTERS = frozenset({
    "ebx", "esi", "edi", "ebp", "esp",
})


def _machine_result_invariant_relation(relation: dict[str, Any]) -> str:
    return "exact" if relation.get("relation") == "exact" else "related_word"


def _semantic_index_from_address(
    address: dict[str, Any], base: int, element_size: int
) -> dict[str, Any] | None:
    if address.get("op") != "add":
        return None
    for constant_side, scaled_side in (("left", "right"), ("right", "left")):
        constant = address.get(constant_side)
        scaled = address.get(scaled_side)
        if not isinstance(constant, dict) or constant.get("op") != "constant":
            continue
        offset = (int(constant["value"]) - base) & 0xFFFFFFFF
        if offset >= element_size or not isinstance(scaled, dict):
            continue
        if element_size == 1:
            return scaled
        if element_size & (element_size - 1) == 0:
            shift = element_size.bit_length() - 1
            if scaled.get("op") == "shift_left" and int(scaled.get("amount", -1)) == shift:
                return scaled.get("value")
        if scaled.get("op") == "multiply":
            for factor, value in ((scaled.get("left"), scaled.get("right")),
                                  (scaled.get("right"), scaled.get("left"))):
                if (
                    isinstance(factor, dict)
                    and factor.get("op") == "constant"
                    and int(factor["value"]) == element_size
                    and isinstance(value, dict)
                ):
                    return value
    return None

def _semantic_read_addresses(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if value.get("op") in {"read8", "read32"} and isinstance(value.get("address"), dict):
            result.append(value["address"])
        for key, child in value.items():
            if key != "op":
                result.extend(_semantic_read_addresses(child))
    elif isinstance(value, list):
        for child in value:
            result.extend(_semantic_read_addresses(child))
    return result

def _exact_index_expression(
    region: dict[str, Any], behavior: dict[str, Any], bound: dict[str, Any], side: str
) -> dict[str, Any] | None:
    upper = int(bound["unsigned_lt"])
    register = str(bound[side])
    matches: dict[str, dict[str, Any]] = {}
    for target in region.get("values", []):
        mapped_size = int(target.get("mapped_size", 0))
        if upper <= 0 or mapped_size <= 0 or mapped_size % upper != 0:
            continue
        element_size = mapped_size // upper
        if element_size not in {1, 2, 4, 8}:
            continue
        base = int(target[f"{side}_value"])
        for address in _semantic_read_addresses(behavior):
            expression = _semantic_index_from_address(address, base, element_size)
            if (
                expression is not None
                and register in _semantic_expr_registers(expression)
                and _semantic_expr_is_pure(expression)
            ):
                matches[_semantic_hash(expression)] = expression
    if len(matches) != 1:
        return None
    return next(iter(matches.values()))

def _refine_contract_bounds(
    contract: dict[str, Any], behaviors: list[dict[str, Any]]
) -> dict[str, Any]:
    refined = json.loads(json.dumps(contract))
    for region, behavior_pair in zip(refined["regions"], behaviors, strict=True):
        for bound in region.get("bounds", []):
            found = True
            for side in ("original", "candidate"):
                expression = _exact_index_expression(
                    region, behavior_pair[f"{side}_ir"], bound, side
                )
                if expression is None:
                    found = False
                    break
                bound[f"{side}_expression"] = expression
            if found:
                bound["expression_source"] = "lean_exact_effective_address"
            else:
                bound.pop("original_expression", None)
                bound.pop("candidate_expression", None)
                bound.pop("expression_source", None)
    return refined

def _register_relation_join(relations: list[str]) -> str:
    unique = set(relations)
    if not unique:
        return "related_word"
    if len(unique) == 1:
        return next(iter(unique))
    return "related_word"

def _register_relation_implies(source: str, target: str) -> bool:
    return source == target or target == "related_word"

def _paired_constant_relation(
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
    contract: dict[str, Any],
    original_image_base: int,
    candidate_image_base: int,
) -> str | None:
    if (
        original_expression.get("op") != "constant"
        or candidate_expression.get("op") != "constant"
    ):
        return None
    original_value = int(original_expression["value"]) & 0xFFFFFFFF
    candidate_value = int(candidate_expression["value"]) & 0xFFFFFFFF
    if original_value == candidate_value:
        return "exact"
    if any(
        int(target["original_value"]) == original_value
        and int(target["candidate_value"]) == candidate_value
        for target in contract.get("value_targets", [])
    ):
        return "data_pointer"
    if any(
        original_image_base + int(target["original_rva"]) == original_value
        and candidate_image_base + int(target["candidate_rva"]) == candidate_value
        for target in contract.get("code_targets", [])
    ):
        return "code_pointer"
    return None

def _infer_register_output_relation(
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
    input_relations: dict[str, str],
    contract: dict[str, Any],
    original_image_base: int,
    candidate_image_base: int,
    global_values_empty: bool,
    original_bin: StageABinary | None = None,
    candidate_bin: StageABinary | None = None,
) -> tuple[str, str]:
    constant_relation = _paired_constant_relation(
        original_expression,
        candidate_expression,
        contract,
        original_image_base,
        candidate_image_base,
    )
    if constant_relation is not None:
        return constant_relation, "paired_constant"
    static_slot = _matching_static_word_relation_slot(
        original_expression, candidate_expression, contract,
    )
    if static_slot is not None:
        relation = str(static_slot["relation"])
        if relation in {"fixed_code_pointer", "fixedCodePointer"}:
            relation = "code_pointer"
        return relation, "static_word_slot"
    original_address = _constant_read32_address(original_expression)
    candidate_address = _constant_read32_address(candidate_expression)
    if (
        original_bin is not None
        and candidate_bin is not None
        and original_address is not None
        and candidate_address is not None
    ):
        original_value = _immutable_image_u32(original_bin, original_address)
        candidate_value = _immutable_image_u32(candidate_bin, candidate_address)
        if original_value is not None and candidate_value is not None:
            immutable_relation = _paired_constant_relation(
                {"op": "constant", "value": original_value},
                {"op": "constant", "value": candidate_value},
                contract,
                original_image_base,
                candidate_image_base,
            )
            if immutable_relation is not None:
                return immutable_relation, "immutable_image_word"
    if original_expression == candidate_expression:
        if original_expression.get("op") == "input_reg":
            register = str(original_expression.get("reg"))
            return input_relations.get(register, "related_word"), "identity_transfer"
        dependencies = _semantic_expr_registers(original_expression)
        if _semantic_expr_is_pure(original_expression) and all(
            input_relations.get(register) == "exact" for register in dependencies
        ):
            return "exact", "lean_exact_memory_free_expression"
        if global_values_empty and _semantic_exact_memory_inputs(
            original_expression,
            {
                register for register, relation in input_relations.items()
                if relation == "exact"
            },
        ):
            return "exact", "lean_exact_memory_expression"
    return "related_word", "unsupported_or_mixed_relation"


def _matching_static_word_relation_slot(
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
    contract: dict[str, Any],
) -> dict[str, Any] | None:
    original_address = _constant_read32_address(original_expression)
    candidate_address = _constant_read32_address(candidate_expression)
    if original_address is None or candidate_address is None:
        return None
    matches = [
        slot
        for slot in contract.get("static_word_relation_slots", [])
        if int(slot.get("original_address", -1)) == original_address
        and int(slot.get("candidate_address", -1)) == candidate_address
        and str(slot.get("relation")) in _REGISTER_RELATION_KINDS
    ]
    return dict(matches[0]) if len(matches) == 1 else None

def _iat_seed_read(
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

def _iat_import_register_seed_candidates(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    behaviors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for region_index, behavior_pair in enumerate(behaviors):
        original_registers = behavior_pair["original_ir"].get("registers") or {}
        candidate_registers = behavior_pair["candidate_ir"].get("registers") or {}
        for original_register, original_expression in sorted(original_registers.items()):
            original_read = _iat_seed_read(original_expression)
            if original_read is None:
                continue
            original_address, original_writes, original_assembled = original_read
            original_import = _unique_import_at_absolute_address(
                original_bin, original_address
            )
            original_identity = (
                _import_identity(original_import) if original_import is not None else None
            )
            if original_identity is None:
                continue
            matches: list[dict[str, Any]] = []
            for candidate_register, candidate_expression in sorted(
                candidate_registers.items()
            ):
                candidate_read = _iat_seed_read(candidate_expression)
                if candidate_read is None:
                    continue
                candidate_address, candidate_writes, candidate_assembled = candidate_read
                candidate_import = _unique_import_at_absolute_address(
                    candidate_bin, candidate_address
                )
                if (
                    candidate_import is None
                    or _import_identity(candidate_import) != original_identity
                    or candidate_assembled != original_assembled
                    or len(candidate_writes) != len(original_writes)
                ):
                    continue
                matches.append({
                    "profile": (
                        "assembled_iat_register_seed_v1"
                        if original_assembled else "iat_register_seed_v1"
                    ),
                    "region_index": region_index,
                    "original_register": original_register,
                    "candidate_register": candidate_register,
                    "original_iat_rva": int(original_import.thunk_rva),
                    "candidate_iat_rva": int(candidate_import.thunk_rva),
                    "original_absolute_address": original_address,
                    "candidate_absolute_address": candidate_address,
                    "assembled_read": original_assembled,
                    "original_writes": original_writes,
                    "candidate_writes": candidate_writes,
                    "import": {
                        "dll": original_identity[0],
                        original_identity[1]: original_identity[2],
                    },
                })
            if len(matches) == 1:
                result.append(matches[0])
    return result

def _attach_import_seed_address_separations(
    contract: dict[str, Any], seeds: list[dict[str, Any]],
) -> dict[str, Any]:
    refined = json.loads(json.dumps(contract))
    regions = refined.get("regions", [])
    for seed in seeds:
        if not seed.get("assembled_read"):
            continue
        original_writes = seed.get("original_writes", [])
        candidate_writes = seed.get("candidate_writes", [])
        if len(original_writes) != len(candidate_writes):
            continue
        region_index = int(seed["region_index"])
        if not 0 <= region_index < len(regions):
            continue
        rows = regions[region_index].setdefault("address_separations", [])
        keys = {
            (
                str(row["original_register"]), str(row["candidate_register"]),
                int(row["original_offset"]), int(row["candidate_offset"]),
                int(row["original_address"]), int(row["candidate_address"]),
            )
            for row in rows
        }
        for original_write, candidate_write in zip(
            original_writes, candidate_writes, strict=True
        ):
            for word_byte in range(4):
                for write_byte in range(4):
                    key = (
                        str(original_write["register"]),
                        str(candidate_write["register"]),
                        (int(original_write["offset"]) + write_byte) & 0xFFFFFFFF,
                        (int(candidate_write["offset"]) + write_byte) & 0xFFFFFFFF,
                        (int(seed["original_absolute_address"]) + word_byte) & 0xFFFFFFFF,
                        (int(seed["candidate_absolute_address"]) + word_byte) & 0xFFFFFFFF,
                    )
                    if key in keys:
                        continue
                    rows.append({
                        "original_register": key[0],
                        "candidate_register": key[1],
                        "original_offset": key[2],
                        "candidate_offset": key[3],
                        "original_address": key[4],
                        "candidate_address": key[5],
                        "source": "assembled_iat_write_separation",
                    })
                    keys.add(key)
        rows.sort(key=lambda row: (
            str(row["original_register"]), str(row["candidate_register"]),
            int(row["original_offset"]), int(row["candidate_offset"]),
            int(row["original_address"]), int(row["candidate_address"]),
        ))
    return refined

def _infer_import_register_invariants(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    seeds: list[dict[str, Any]],
) -> dict[str, Any]:
    region_by_numeric_id = {
        int(region["numeric_id"]): index
        for index, region in enumerate(contract.get("regions", []))
    }
    nonvolatile = {"ebx", "esi", "edi", "ebp"}

    def identity_key(imported: dict[str, Any]) -> tuple[str, str, str | int]:
        if "symbol" in imported:
            return (str(imported["dll"]).lower(), "symbol", str(imported["symbol"]))
        return (str(imported["dll"]).lower(), "ordinal", int(imported["ordinal"]))

    identities = {
        identity_key(seed["import"]): seed["import"] for seed in seeds
    }
    seed_facts: dict[int, set[tuple[str, str, tuple[str, str, str | int]]]] = {}
    for seed in seeds:
        seed_facts.setdefault(int(seed["region_index"]), set()).add((
            str(seed["original_register"]),
            str(seed["candidate_register"]),
            identity_key(seed["import"]),
        ))

    edges: list[dict[str, Any]] = []
    incoming: list[list[int]] = [[] for _ in behaviors]
    for source_index, behavior_pair in enumerate(behaviors):
        original_edges = _semantic_edges(behavior_pair["original_ir"])
        candidate_edges = _semantic_edges(behavior_pair["candidate_ir"])
        if len(original_edges) == len(candidate_edges):
            for original_edge, candidate_edge in zip(
                original_edges, candidate_edges, strict=True
            ):
                if (
                    int(original_edge["target"]) != int(candidate_edge["target"])
                    or str(original_edge["kind"]) != str(candidate_edge["kind"])
                ):
                    continue
                target_index = region_by_numeric_id.get(int(original_edge["target"]))
                if target_index is None:
                    continue
                if (
                    _semantic_constant_bool(original_edge["guard"]) is False
                    and _semantic_constant_bool(candidate_edge["guard"]) is False
                ):
                    continue
                edge = {
                    "source_region_index": source_index,
                    "target_region_index": target_index,
                    "kind": str(original_edge["kind"]),
                    "environment_barrier": bool(
                        original_edge.get("environment_barrier")
                        or candidate_edge.get("environment_barrier")
                    ),
                }
                incoming[target_index].append(len(edges))
                edges.append(edge)
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        if (
            original_outcome.get("op") == "indirect_call"
            and candidate_outcome.get("op") == "indirect_call"
            and int(original_outcome.get("continuation", -1))
                == int(candidate_outcome.get("continuation", -2))
        ):
            target_index = region_by_numeric_id.get(
                int(original_outcome["continuation"])
            )
            if target_index is not None:
                incoming[target_index].append(len(edges))
                edges.append({
                    "source_region_index": source_index,
                    "target_region_index": target_index,
                    "kind": "indirect_external_call_continuation",
                    "environment_barrier": True,
                })

    def transferred_source_fact(
        edge: dict[str, Any],
        target_fact: tuple[str, str, tuple[str, str, str | int]],
    ) -> tuple[str, str, tuple[str, str, str | int]] | None:
        source_index = int(edge["source_region_index"])
        original_register, candidate_register, imported = target_fact
        original_expression = (
            behaviors[source_index]["original_ir"].get("registers") or {}
        ).get(original_register) or {}
        candidate_expression = (
            behaviors[source_index]["candidate_ir"].get("registers") or {}
        ).get(candidate_register) or {}
        if (
            original_expression.get("op") != "input_reg"
            or candidate_expression.get("op") != "input_reg"
        ):
            return None
        if edge["environment_barrier"] and (
            original_register not in nonvolatile
            or candidate_register not in nonvolatile
        ):
            return None
        return (
            str(original_expression["reg"]),
            str(candidate_expression["reg"]),
            imported,
        )

    def edge_supports(
        edge: dict[str, Any],
        target_fact: tuple[str, str, tuple[str, str, str | int]],
        facts: set[tuple[int, str, str, tuple[str, str, str | int]]],
    ) -> bool:
        source_index = int(edge["source_region_index"])
        if target_fact in seed_facts.get(source_index, set()):
            return True
        source_fact = transferred_source_fact(edge, target_fact)
        return source_fact is not None and (source_index, *source_fact) in facts

    facts: set[tuple[int, str, str, tuple[str, str, str | int]]] = set()
    changed = True
    while changed:
        changed = False
        for target_index, edge_indices in enumerate(incoming):
            for edge_index in edge_indices:
                source_index = int(edges[edge_index]["source_region_index"])
                proposals = set(seed_facts.get(source_index, set()))
                proposals.update(
                    (original_register, candidate_register, imported)
                    for region_index, original_register, candidate_register, imported in facts
                    if region_index == source_index
                )
                for proposal in proposals:
                    transferred = transferred_source_fact(edges[edge_index], proposal)
                    candidates = {proposal}
                    if transferred is not None:
                        candidates.add((
                            proposal[0], proposal[1], proposal[2]
                        ))
                    for candidate_fact in candidates:
                        fact = (target_index, *candidate_fact)
                        if fact not in facts and edge_supports(
                            edges[edge_index], candidate_fact, facts
                        ):
                            facts.add(fact)
                            changed = True

    changed = True
    while changed:
        changed = False
        for fact in list(facts):
            target_index, original_register, candidate_register, imported = fact
            edge_indices = incoming[target_index]
            target_fact = (original_register, candidate_register, imported)
            if not edge_indices or not all(
                edge_supports(edges[edge_index], target_fact, facts)
                for edge_index in edge_indices
            ):
                facts.remove(fact)
                changed = True

    relation_rows = []
    for region_index, original_register, candidate_register, imported in sorted(facts):
        relation_rows.append({
            "region_index": region_index,
            "original_register": original_register,
            "candidate_register": candidate_register,
            "import": identities[imported],
            "incoming_edge_indices": incoming[region_index],
            "incoming_edges": [edges[index] for index in incoming[region_index]],
        })

    call_rows = []
    facts_by_region: dict[int, list[dict[str, Any]]] = {}
    for row in relation_rows:
        facts_by_region.setdefault(int(row["region_index"]), []).append(row)
    for source_index, behavior_pair in enumerate(behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_target = original_outcome.get("target") or {}
        candidate_target = candidate_outcome.get("target") or {}
        if (
            original_outcome.get("op") != "indirect_call"
            or candidate_outcome.get("op") != "indirect_call"
            or original_target.get("op") != "input_reg"
            or candidate_target.get("op") != "input_reg"
        ):
            continue
        matches = [
            row for row in facts_by_region.get(source_index, [])
            if row["original_register"] == original_target.get("reg")
            and row["candidate_register"] == candidate_target.get("reg")
        ]
        if len(matches) != 1:
            continue
        continuation = int(original_outcome.get("continuation", -1))
        if continuation != int(candidate_outcome.get("continuation", -2)):
            continue
        continuation_index = region_by_numeric_id.get(continuation)
        if continuation_index is None:
            continue
        call_rows.append({
            "profile": "inductive_iat_register_call_v1",
            "source_region_index": source_index,
            "continuation_region_index": continuation_index,
            "original_register": str(original_target["reg"]),
            "candidate_register": str(candidate_target["reg"]),
            "import": matches[0]["import"],
        })

    return {
        "format": "stage-a-relational-import-register-invariants-v1",
        "status": "proposal_requires_edge_and_scc_lean_replay",
        "abi_profile": "pe32-win32-nonvolatile-registers-v1",
        "nonvolatile_registers": sorted(nonvolatile),
        "relations": relation_rows,
        "indirect_import_calls": call_rows,
        "counts": {
            "seeds": len(seeds),
            "relations": len(relation_rows),
            "indirect_import_calls": len(call_rows),
        },
    }

def _attach_import_register_invariants(
    contract: dict[str, Any], analysis: dict[str, Any],
) -> dict[str, Any]:
    refined = json.loads(json.dumps(contract))
    relations_by_region: dict[int, list[dict[str, Any]]] = {}
    for relation in analysis.get("relations", []):
        relations_by_region.setdefault(int(relation["region_index"]), []).append({
            "original": str(relation["original_register"]),
            "candidate": str(relation["candidate_register"]),
            "import": relation["import"],
        })
    for region_index, region in enumerate(refined.get("regions", [])):
        region["input_import_relations"] = sorted(
            relations_by_region.get(region_index, []),
            key=lambda item: (
                item["original"], item["candidate"],
                json.dumps(item["import"], sort_keys=True),
            ),
        )
        region["output_import_relations"] = []
    return refined

def _synthesize_register_relations(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    *,
    original_image_base: int,
    candidate_image_base: int,
    indirect_call_candidates: list[dict[str, Any]] | None = None,
    import_call_candidates: list[dict[str, Any]] | None = None,
    original_bin: StageABinary | None = None,
    candidate_bin: StageABinary | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    refined = json.loads(json.dumps(contract))
    regions = refined["regions"]
    region_by_id = {int(region["numeric_id"]): index for index, region in enumerate(regions)}
    predecessors: list[
        list[tuple[int, bool, str, frozenset[str], dict[str, str]]]
    ] = [[] for _ in regions]
    edges: list[dict[str, Any]] = []
    pending_indirect_edges: list[dict[str, Any]] = []
    pending_indirect_jump_edges: list[dict[str, Any]] = []
    pending_import_edges: list[dict[str, Any]] = []
    indirect_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (indirect_call_candidates or [])
    }
    import_call_by_source = {
        int(candidate["source_region_index"]): candidate
        for candidate in (import_call_candidates or [])
    }
    contracts_by_target: dict[
        tuple[str, str, str | int], list[dict[str, Any]]
    ] = {}
    for item in refined.get("machine_import_call_contracts", []):
        imported = item.get("import") or {}
        identity = (
            str(imported.get("dll", "")).lower(),
            "symbol" if "symbol" in imported else "ordinal",
            imported.get("symbol", imported.get("ordinal")),
        )
        contracts_by_target.setdefault(identity, []).append(item)

    def paired_machine_contract(
        original_outcome: dict[str, Any], candidate_outcome: dict[str, Any],
    ) -> dict[str, Any] | None:
        original_identity = _semantic_external_target_identity(
            original_outcome.get("import")
        )
        candidate_identity = _semantic_external_target_identity(
            candidate_outcome.get("import")
        )
        contracts = (
            contracts_by_target.get(original_identity, [])
            if original_identity is not None
            and original_identity == candidate_identity else []
        )
        if len(contracts) != 1:
            return None
        return contracts[0]

    for source_index, behavior_pair in enumerate(behaviors):
        original_outcome = behavior_pair["original_ir"].get("outcome") or {}
        candidate_outcome = behavior_pair["candidate_ir"].get("outcome") or {}
        original_edges = _semantic_edges(behavior_pair["original_ir"])
        candidate_edges = _semantic_edges(behavior_pair["candidate_ir"])
        if len(original_edges) != len(candidate_edges):
            continue
        paired_edges = list(zip(original_edges, candidate_edges, strict=True))
        if any(
            int(original_edge["target"]) != int(candidate_edge["target"])
            or str(original_edge["kind"]) != str(candidate_edge["kind"])
            or bool(original_edge.get("environment_barrier")) !=
                bool(candidate_edge.get("environment_barrier"))
            for original_edge, candidate_edge in paired_edges
        ):
            continue
        for original_edge, candidate_edge in paired_edges:
            target_index = region_by_id.get(int(original_edge["target"]))
            if target_index is None:
                continue
            barrier = bool(original_edge.get("environment_barrier"))
            machine_contract = (
                paired_machine_contract(original_outcome, candidate_outcome)
                if barrier else None
            )
            result_relations = (
                {
                    str(relation["register"]):
                        _machine_result_invariant_relation(relation)
                    for relation in machine_contract.get(
                        "result_register_relations", []
                    )
                }
                if machine_contract is not None else {}
            )
            predecessors[target_index].append(
                (
                    source_index, barrier, str(original_edge["kind"]),
                    _PE32_EXTERNAL_PRESERVED_REGISTERS,
                    result_relations,
                )
            )
            edges.append({
                "source_region_index": source_index,
                "target_region_index": target_index,
                "kind": str(original_edge["kind"]),
                "original_guard": original_edge["guard"],
                "candidate_guard": candidate_edge["guard"],
                "environment_barrier": barrier,
                "requires_call_stack_proof": False,
                "machine_contract_id": (
                    int(machine_contract["id"])
                    if machine_contract is not None else None
                ),
            })
        indirect_candidate = indirect_by_source.get(source_index)
        if indirect_candidate is not None:
            target_index = int(indirect_candidate["target_region_index"])
            indirect_kind = (
                "jump"
                if indirect_candidate["profile"] in {
                    "immutable_relocated_function_pointer_jump_v1",
                    "fixed_static_function_pointer_jump_v1",
                }
                else "call"
            )
            predecessors[target_index].append(
                (
                    source_index, False, indirect_kind,
                    _PE32_EXTERNAL_PRESERVED_REGISTERS,
                    {},
                )
            )
            pending_edge = {
                "source_region_index": source_index,
                "target_region_index": target_index,
                "kind": indirect_kind,
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
                "environment_barrier": False,
                "requires_call_stack_proof": False,
                "indirect_target_profile": indirect_candidate["profile"],
                "indirect_target_claim": indirect_candidate,
            }
            if indirect_kind == "jump":
                pending_indirect_jump_edges.append(pending_edge)
            else:
                pending_indirect_edges.append(pending_edge)
        import_call_candidate = import_call_by_source.get(source_index)
        if import_call_candidate is not None:
            target_index = int(import_call_candidate["continuation_region_index"])
            import_outcome = {"import": import_call_candidate["import"]}
            machine_contract = paired_machine_contract(
                import_outcome, import_outcome
            )
            result_relations = (
                {
                    str(relation["register"]):
                        _machine_result_invariant_relation(relation)
                    for relation in machine_contract.get(
                        "result_register_relations", []
                    )
                }
                if machine_contract is not None else {}
            )
            predecessors[target_index].append(
                (
                    source_index, True, "external_call",
                    _PE32_EXTERNAL_PRESERVED_REGISTERS,
                    result_relations,
                )
            )
            pending_import_edges.append({
                "source_region_index": source_index,
                "target_region_index": target_index,
                "kind": "external_call",
                "original_guard": {"op": "bool_constant", "value": True},
                "candidate_guard": {"op": "bool_constant", "value": True},
                "environment_barrier": True,
                "requires_call_stack_proof": False,
                "indirect_target_profile": import_call_candidate["profile"],
                "import": import_call_candidate["import"],
                "machine_contract_id": (
                    int(machine_contract["id"])
                    if machine_contract is not None else None
                ),
            })
    for edge in edges:
        if edge.get("kind") != "call":
            continue
        caller_index = int(edge["source_region_index"])
        thunk_index = int(edge["target_region_index"])
        caller_outcome = behaviors[caller_index]["original_ir"].get("outcome") or {}
        candidate_caller_outcome = (
            behaviors[caller_index]["candidate_ir"].get("outcome") or {}
        )
        thunk_outcome = behaviors[thunk_index]["original_ir"].get("outcome") or {}
        candidate_thunk_outcome = (
            behaviors[thunk_index]["candidate_ir"].get("outcome") or {}
        )
        if (
            caller_outcome.get("op") != "call"
            or candidate_caller_outcome.get("op") != "call"
            or caller_outcome.get("continuation")
                != candidate_caller_outcome.get("continuation")
            or thunk_outcome.get("op") != "external_jump"
            or candidate_thunk_outcome.get("op") != "external_jump"
        ):
            continue
        original_identity = _semantic_external_target_identity(
            thunk_outcome.get("import")
        )
        candidate_identity = _semantic_external_target_identity(
            candidate_thunk_outcome.get("import")
        )
        contracts = (
            contracts_by_target.get(original_identity, [])
            if original_identity is not None
            and original_identity == candidate_identity else []
        )
        continuation = caller_outcome.get("continuation")
        continuation_index = (
            region_by_id.get(int(continuation))
            if isinstance(continuation, int) else None
        )
        if len(contracts) != 1 or continuation_index is None:
            continue
        predecessors[continuation_index].append((
            thunk_index,
            True,
            "external_jump_return",
            frozenset(
                {str(item) for item in contracts[0]["preserved_registers"]}
                | {"esp"}
            ),
            {
                str(relation["register"]):
                    _machine_result_invariant_relation(relation)
                for relation in contracts[0].get(
                    "result_register_relations", []
                )
            },
        ))

    # A return destination is selected by the checked runtime call frame, not by
    # untrusted function recovery. Return continuations therefore participate
    # in rooted reachability but remain absent from decoded predecessor edges;
    # Lean checks the concrete runtime frame at composition time.

    # Keep existing direct edge IDs stable when a new checked indirect-target
    # profile becomes available. Product-graph arrays remain contiguous, while
    # an added indirect edge only changes the tail chunk and its source node's
    # outgoing inventory.
    edges.extend(pending_indirect_edges)
    edges.extend(pending_import_edges)
    edges.extend(pending_indirect_jump_edges)
    for edge in edges:
        edge["direct_call_push_claim"] = _direct_call_push_claim(
            regions[int(edge["source_region_index"])],
            behaviors[int(edge["source_region_index"])],
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
        ) if edge["kind"] == "call" else None
        edge["indirect_call_push_claim"] = _indirect_call_push_claim(
            regions[int(edge["source_region_index"])],
            behaviors[int(edge["source_region_index"])],
            original_image_base=original_image_base,
            candidate_image_base=candidate_image_base,
        ) if (
            edge["kind"] == "call"
            and edge.get("indirect_target_profile") in {
                "immutable_relocated_function_pointer_call_v1",
                "fixed_static_function_pointer_call_v1",
            }
        ) else None

    register_order = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    stack_window_input_pairs = [
        {
            (str(window["original_register"]), str(window["candidate_register"]))
            for window in region.get("stack_windows", [])
        }
        for region in regions
    ]
    input_pair_candidates = [
        {
            str(pair["original"]): str(pair["candidate"])
            for pair in region.get("inputs", [])
        }
        for region in regions
    ]
    input_kinds = [
        {register: "exact" for register in register_order}
        for _ in regions
    ]
    output_kinds = [dict(kinds) for kinds in input_kinds]
    output_reasons = [
        {register: "initial_exact_candidate" for register in register_order}
        for _ in regions
    ]
    max_iterations = max(1, len(regions) * len(register_order) + 1)
    converged = False
    for iteration in range(max_iterations):
        next_outputs: list[dict[str, str]] = []
        next_reasons: list[dict[str, str]] = []
        for region_index, behavior_pair in enumerate(behaviors):
            kinds: dict[str, str] = {}
            reasons: dict[str, str] = {}
            original_registers = behavior_pair["original_ir"]["registers"]
            candidate_registers = behavior_pair["candidate_ir"]["registers"]
            for register in register_order:
                kinds[register], reasons[register] = _infer_register_output_relation(
                    original_registers[register],
                    candidate_registers[register],
                    input_kinds[region_index],
                    refined,
                    original_image_base,
                    candidate_image_base,
                    not refined.get("value_targets"),
                    original_bin,
                    candidate_bin,
                )
            next_outputs.append(kinds)
            next_reasons.append(reasons)

        next_inputs: list[dict[str, str]] = []
        for region_index, region in enumerate(regions):
            incoming = predecessors[region_index]
            kinds: dict[str, str] = {}
            for register in register_order:
                candidates: list[str] = []
                if region.get("root"):
                    candidates.append("exact")
                for source_index, barrier, _, preserved, results in incoming:
                    candidates.append(
                        next_outputs[source_index][register]
                        if not barrier
                        else results[register]
                        if register in results
                        else next_outputs[source_index][register]
                        if register in preserved
                        else "related_word"
                    )
                if not candidates:
                    candidates.append("related_word")
                kinds[register] = _register_relation_join(candidates)
                candidate_register = input_pair_candidates[region_index].get(register)
                if (
                    candidate_register is not None
                    and (register, candidate_register)
                        in stack_window_input_pairs[region_index]
                ):
                    # A stack window relates offsets inside paired concrete
                    # ranges; it does not imply literal register equality.
                    kinds[register] = "related_word"
            next_inputs.append(kinds)
        if next_inputs == input_kinds and next_outputs == output_kinds:
            output_reasons = next_reasons
            converged = True
            break
        input_kinds = next_inputs
        output_kinds = next_outputs
        output_reasons = next_reasons
    else:
        iteration = max_iterations - 1

    relation_rows: list[dict[str, Any]] = []
    exact_claims = 0
    input_import_pairs = [
        {
            (str(relation["original"]), str(relation["candidate"]))
            for relation in region.get("input_import_relations", [])
        }
        for region in regions
    ]
    output_import_pairs: list[set[tuple[str, str]]] = [set() for _ in regions]
    for edge in edges:
        if not edge["environment_barrier"] and not edge["requires_call_stack_proof"]:
            output_import_pairs[int(edge["source_region_index"])].update(
                input_import_pairs[int(edge["target_region_index"])]
            )
    for region_index, region in enumerate(regions):
        input_pairs = {pair["original"]: pair for pair in region["inputs"]}
        output_pairs = {pair["original"]: pair for pair in region["outputs"]}
        region["input_relations"] = [
            {
                "original": input_pairs[register]["original"],
                "candidate": input_pairs[register]["candidate"],
                "relation": input_kinds[region_index][register],
            }
            for register in register_order
            if register in input_pairs
            and (
                input_pairs[register]["original"],
                input_pairs[register]["candidate"],
            ) not in input_import_pairs[region_index]
        ]
        region["output_relations"] = [
            {
                "original": output_pairs[register]["original"],
                "candidate": output_pairs[register]["candidate"],
                "relation": output_kinds[region_index][register],
            }
            for register in register_order
            if register in output_pairs
            and (
                output_pairs[register]["original"],
                output_pairs[register]["candidate"],
            ) not in output_import_pairs[region_index]
        ]
        claims = []
        output_claims = []
        input_relation_by_original = {
            relation["original"]: relation for relation in region["input_relations"]
        }
        for relation in region["output_relations"]:
            register = relation["original"]
            original_expression = behaviors[region_index]["original_ir"]["registers"][register]
            candidate_expression = behaviors[region_index]["candidate_ir"]["registers"][
                relation["candidate"]
            ]
            reason = output_reasons[region_index][register]
            if (
                relation["relation"] == "exact"
                and relation["original"] == relation["candidate"]
                and original_expression == candidate_expression
                and reason not in {
                    "lean_exact_memory_expression", "immutable_image_word",
                    "static_word_slot",
                }
            ):
                claims.append({
                    "register": register,
                    "relation": "exact",
                    "reason": reason,
                    "expression": original_expression,
                })
            if reason == "identity_transfer":
                input_register = str(original_expression["reg"])
                input_relation = input_relation_by_original.get(input_register)
                if (
                    input_relation is not None
                    and candidate_expression.get("op") == "input_reg"
                    and str(candidate_expression["reg"]) == input_relation["candidate"]
                    and input_relation["relation"] == relation["relation"]
                ):
                    output_claims.append({
                        "kind": "identity",
                        "input": input_relation,
                        "output": relation,
                    })
            elif reason == "paired_constant":
                output_claims.append({
                    "kind": "constant",
                    "output": relation,
                    "original_value": int(original_expression["value"]),
                    "candidate_value": int(candidate_expression["value"]),
                })
            elif reason == "lean_exact_memory_expression":
                output_claims.append({
                    "kind": "exact_memory",
                    "output": relation,
                    "expression": original_expression,
                })
            elif reason == "immutable_image_word":
                original_address = _constant_read32_address(original_expression)
                candidate_address = _constant_read32_address(candidate_expression)
                original_value = (
                    _immutable_image_u32(original_bin, original_address)
                    if original_bin is not None and original_address is not None
                    else None
                )
                candidate_value = (
                    _immutable_image_u32(candidate_bin, candidate_address)
                    if candidate_bin is not None and candidate_address is not None
                    else None
                )
                if (
                    original_address is not None
                    and candidate_address is not None
                    and original_value is not None
                    and candidate_value is not None
                ):
                    output_claims.append({
                        "kind": "immutable_image_word",
                        "output": relation,
                        "original_address": original_address,
                        "candidate_address": candidate_address,
                        "original_value": original_value,
                        "candidate_value": candidate_value,
                    })
            elif relation["relation"] == "exact" and any(
                claim["register"] == register for claim in claims
            ):
                output_claims.append({
                    "kind": "exact_expression",
                    "output": relation,
                    "expression": original_expression,
                })
        exact_claims += len(claims)
        relation_rows.append({
            "region_id": region["id"],
            "region_index": region_index,
            "inputs": region["input_relations"],
            "outputs": region["output_relations"],
            "runtime_frame_inputs": json.loads(json.dumps(
                region["input_relations"]
            )),
            "runtime_frame_outputs": json.loads(json.dumps(
                region["output_relations"]
            )),
            "exact_output_claims": claims,
            "output_claims": output_claims,
            "return_pop_claim": _return_pop_claim(
                behaviors[region_index], region=region
            ),
            "is_return": (
                (behaviors[region_index]["original_ir"].get("outcome") or {}).get("op")
                    == "returned"
                and (behaviors[region_index]["candidate_ir"].get("outcome") or {}).get("op")
                    == "returned"
            ),
            "fully_exact_output_transfer": (
                len(claims) == len(region["output_relations"])
                and bool(region["output_relations"])
            ),
            "fully_supported_output_transfer": (
                len(output_claims) == len(region["output_relations"])
                and bool(region["output_relations"])
            ),
            "predecessor_count": len(predecessors[region_index]),
            "environment_barrier": any(
                barrier for _, barrier, _, _, _ in predecessors[region_index]
            ),
        })

    unsupported_edges = 0
    fully_exact_edges = 0
    exact_pair_edge_claims = 0
    edges_with_exact_pair_claims = 0
    for edge in edges:
        source = edge["source_region_index"]
        target = edge["target_region_index"]
        indirect_control = bool(edge.get("indirect_target_profile"))
        immutable_indirect_jump = (
            edge.get("indirect_target_profile") ==
            "immutable_relocated_function_pointer_jump_v1"
        )
        source_claims = {
            claim["register"]: claim
            for claim in relation_rows[source]["exact_output_claims"]
        }
        source_outputs = {
            relation["original"]: relation
            for relation in relation_rows[source]["outputs"]
        }
        pair_claims = [] if (
            edge["environment_barrier"] or edge["requires_call_stack_proof"]
            or indirect_control
        ) else [
            {
                "register": target_relation["original"],
                "target_relation": target_relation["relation"],
                "expression": source_claims[target_relation["original"]]["expression"],
            }
            for target_relation in relation_rows[target]["inputs"]
            if target_relation["relation"] in {"exact", "related_word"}
            and target_relation["original"] in source_claims
            and source_outputs[target_relation["original"]]["candidate"]
                == target_relation["candidate"]
        ]
        edge["exact_output_pair_claims"] = pair_claims
        supported = (
            not edge["environment_barrier"]
            and not edge["requires_call_stack_proof"]
            and (not indirect_control or immutable_indirect_jump)
            and all(
            _register_relation_implies(
                output_kinds[source][register], input_kinds[target][register]
            )
            for register in register_order
            )
        )
        edge["relation_preservation_proposed"] = supported
        edge["environment_register_policy"] = (
            {
                "id": _PE32_EXTERNAL_REGISTER_POLICY_ID,
                "preserved": sorted(_PE32_EXTERNAL_PRESERVED_REGISTERS),
                "clobbered": sorted(
                    set(register_order) - _PE32_EXTERNAL_PRESERVED_REGISTERS
                ),
                "status": "requires_relational_environment_compatibility",
            }
            if edge["environment_barrier"]
            else None
        )
        edge["fully_exact_edge_proposed"] = (
            not edge["environment_barrier"]
            and not edge["requires_call_stack_proof"]
            and not indirect_control
            and relation_rows[source]["fully_exact_output_transfer"]
            and all(
                relation["relation"] == "exact"
                for relation in relation_rows[target]["inputs"]
            )
            and relation_rows[source]["outputs"] == relation_rows[target]["inputs"]
        )
        unsupported_edges += not supported
        fully_exact_edges += edge["fully_exact_edge_proposed"]
        exact_pair_edge_claims += len(pair_claims)
        edges_with_exact_pair_claims += bool(pair_claims)
    return_slot_analysis = _attach_return_slot_contracts(
        behaviors, relation_rows, edges,
        machine_import_call_contracts=refined.get(
            "machine_import_call_contracts", []
        ),
    )
    counts = {
        "regions": len(regions),
        "direct_edges": len(edges),
        "exact_input_relations": sum(
            kind == "exact" for kinds in input_kinds for kind in kinds.values()
        ),
        "exact_output_relations": sum(
            kind == "exact" for kinds in output_kinds for kind in kinds.values()
        ),
        "code_pointer_output_relations": sum(
            kind == "code_pointer" for kinds in output_kinds for kind in kinds.values()
        ),
        "data_pointer_output_relations": sum(
            kind == "data_pointer" for kinds in output_kinds for kind in kinds.values()
        ),
        "lean_exact_output_claims": exact_claims,
        "fully_exact_output_regions": sum(
            row["fully_exact_output_transfer"] for row in relation_rows
        ),
        "register_output_claims": sum(
            len(row["output_claims"]) for row in relation_rows
        ),
        "fully_supported_output_regions": sum(
            row["fully_supported_output_transfer"] for row in relation_rows
        ),
        "environment_barrier_edges": sum(edge["environment_barrier"] for edge in edges),
        "environment_register_policy_edges": sum(
            edge["environment_register_policy"] is not None for edge in edges
        ),
        "call_return_edges": sum(
            edge["requires_call_stack_proof"] for edge in edges
        ),
        "direct_call_edges": sum(
            edge["kind"] == "call" and not edge.get("indirect_target_profile")
            for edge in edges
        ),
        "checked_direct_call_pushes": sum(
            edge["direct_call_push_claim"] is not None for edge in edges
        ),
        "checked_indirect_call_pushes": sum(
            edge.get("indirect_call_push_claim") is not None for edge in edges
        ),
        "return_regions": sum(
            (behavior["original_ir"].get("outcome") or {}).get("op") == "returned"
            and (behavior["candidate_ir"].get("outcome") or {}).get("op") == "returned"
            for behavior in behaviors
        ),
        "checked_return_pops": sum(
            row["return_pop_claim"] is not None for row in relation_rows
        ),
        "return_slot_seed_edges": int(return_slot_analysis["seed_edges"]),
        "return_slot_transfer_claims": int(return_slot_analysis["transfer_claims"]),
        "return_slot_transfer_rules": int(return_slot_analysis["transfer_rules"]),
        "return_slot_return_transfer_claims": int(
            return_slot_analysis["return_transfer_claims"]
        ),
        "return_slot_return_transfer_rules": int(
            return_slot_analysis["return_transfer_rules"]
        ),
        "return_slot_call_summary_claims": int(
            return_slot_analysis["call_summary_claims"]
        ),
        "replayable_return_slot_call_summaries": int(
            return_slot_analysis["replayable_call_summaries"]
        ),
        "regions_with_return_slot_offsets": int(
            return_slot_analysis["regions_with_offsets"]
        ),
        "return_regions_with_aligned_runtime_frame": int(
            return_slot_analysis["aligned_returns"]
        ),
        "return_slot_overflow_regions": len(return_slot_analysis["overflow_regions"]),
        "unsupported_edge_proposals": unsupported_edges,
        "fully_exact_edge_proposals": fully_exact_edges,
        "exact_pair_edge_claims": exact_pair_edge_claims,
        "edges_with_exact_pair_claims": edges_with_exact_pair_claims,
    }
    artifact = {
        "format": "stage-a-relational-register-relations-v1",
        "status": "proposal_requires_generated_lean_replay",
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "converged": converged,
        "iterations": iteration + 1,
        "relation_kinds": sorted(_REGISTER_RELATION_KINDS),
        "trust": {
            "role": "analysis_and_proof_proposal_only",
            "acceptance_rule": (
                "exact output claims and every direct-edge implication must be reconstructed "
                "from decoded behavior and checked by Lean"
            ),
        },
        "return_slot_analysis": return_slot_analysis,
        "counts": counts,
        "regions": relation_rows,
        "edges": edges,
    }
    return refined, artifact
