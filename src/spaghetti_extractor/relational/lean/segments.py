from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from ...stage_binary import StageABinary, StageAInputError
from ...util import sha256_bytes, write_json
from ..analyses.external import (
    _external_call_site_candidates,
    _semantic_external_target_identity,
)
from ..analyses.stack import _stack_window_transfer_claims
from ..artifacts import write_text_if_changed as _write_text_if_changed
from ..contract import _raw_base_relocations
from ..model import _semantic_hash, _target_shaped_register_output_claims
from ..schema import (
    FLAG_BITS,
    REGISTERS,
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_KERNEL_MODULES,
)


_LEAN_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "lean" / "StageA"
from .common import (
    _lean_register_relation_pair,
    _lean_relation_constructor,
)
from .expressions import (
    _lean_acceptance_outcome,
    _lean_dynamic_range_argument_claim,
    _lean_dynamic_range_relation,
    _lean_dynamic_stack_range_relation,
    _lean_external_target,
    _lean_import_register_seed_claim,
    _lean_machine_import_call_contract,
    _lean_masked_successor_tautology_proof,
    _lean_direct_call_prepared_writes_claim,
    _lean_direct_call_stack_writes_claim,
    _lean_paired_prepared_word_writes_claim,
    _lean_paired_exact_expr_witness,
    _lean_paired_stack_word_value_claim,
    _lean_paired_stack_word_write_claim,
    _lean_paired_stack_word_writes_claim,
    _lean_prepared_dynamic_stack_spill_claim,
    _lean_register_argument_claim,
    _lean_register_offset_witness,
    _lean_register_output_claim,
    _lean_return_slot_offset_pair,
    _lean_semantic_bool_expr,
    _lean_semantic_expr,
    _lean_stack_address_separation_claim,
    _lean_stack_adjustment,
    _lean_stack_window,
    _lean_stack_window_argument_claim,
    _lean_stack_window_transfer_claim,
    _lean_static_dynamic_pointer_slot,
    _lean_static_word_relation_slot,
    _lean_successor_tautology_proof,
    _lean_symbolic_x87_state,
)
from .definitions import (
    _normalized_behavior_fast_path,
)
from .scanner import _lean_reverse_sentinel_scanner_claim


def _write_relational_invariant_modules(
    lean_dir: Path,
    contract: dict[str, Any],
    synthesis: dict[str, Any],
    definition_modules: list[str],
    shard_groups: list[list[int]],
) -> list[dict[str, str]]:
    definition_by_region = {
        region_index: definition_modules[shard_index]
        for shard_index, indices in enumerate(shard_groups)
        for region_index in indices
    }
    requirement_to_obligation = {
        predicate["id"]: predicate["obligation_id"]
        for region in synthesis["region_invariants"]
        for predicate in region["predicates"]
    }
    requirement_by_id = {
        predicate["id"]: predicate
        for region in synthesis["region_invariants"]
        for predicate in region["predicates"]
    }
    predicates_by_location: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for region in synthesis["region_invariants"]:
        for predicate in region["predicates"]:
            predicates_by_location.setdefault(
                (predicate["obligation_id"], region["side"], region["region_index"]), []
            ).append(predicate["predicate"])

    modules: list[dict[str, str]] = []
    closed = [
        obligation for obligation in synthesis["obligations"]
        if obligation["status"] == "candidate_requires_lean_replay"
    ]
    for obligation_index, obligation in enumerate(closed):
        obligation_id = obligation["id"]
        edges = [
            edge for edge in synthesis["edge_obligations"]
            if requirement_to_obligation.get(edge["requirement_id"]) == obligation_id
        ]
        if not edges:
            continue
        source_indices = sorted({edge["source_index"] for edge in edges})
        imports = "import StageA.RelationalInvariant\n" + "\n".join(
            f"import StageA.{module}"
            for module in sorted({definition_by_region[index] for index in source_indices})
        )
        module = f"RelationalInvariantFamily{obligation_index}"
        normalized_names: dict[tuple[str, int], str] = {}
        definitions: list[str] = []
        target_specs_by_side: dict[str, list[tuple[int, dict[str, Any]]]] = {
            "original": [], "candidate": [],
        }
        for region in synthesis["region_invariants"]:
            for predicate in region["predicates"]:
                if predicate["obligation_id"] == obligation_id:
                    target_specs_by_side[region["side"]].append((
                        int(contract["regions"][region["region_index"]]["numeric_id"]),
                        predicate["predicate"],
                    ))
        for side, source_index in sorted({
            (edge["side"], edge["source_index"]) for edge in edges
        }):
            name = f"invariant{side.capitalize()}Behavior{source_index}"
            normalized_names[(side, source_index)] = name
            candidate = "true" if side == "candidate" else "false"
            definitions.append(
                f"def {name} : NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior {candidate} region{source_index}.targets "
                f"{side}Behavior{source_index}).get (by decide)"
            )
        list_names: dict[tuple[str, int], str] = {}
        locations = sorted({
            (edge["side"], edge["source_index"]) for edge in edges
        } | {
            (edge["side"], edge["target_index"]) for edge in edges
        })
        for side, region_index in locations:
            name = f"invariant{obligation_index}{side.capitalize()}Region{region_index}"
            list_names[(side, region_index)] = name
            predicates = predicates_by_location.get((obligation_id, side, region_index), [])
            literal = ", ".join(_lean_semantic_bool_expr(predicate) for predicate in predicates)
            definitions.append(f"def {name} : List BoolExpr := [{literal}]")

        theorem_names: list[str] = []
        claims: list[str] = []
        for edge_index, edge in enumerate(edges):
            side = edge["side"]
            source_index = edge["source_index"]
            target_index = edge["target_index"]
            behavior_name = normalized_names[(side, source_index)]
            source_name = list_names[(side, source_index)]
            target_predicate_name = (
                f"invariantFamily{obligation_index}Edge{edge_index}TargetPredicate"
            )
            precondition_name = (
                f"invariantFamily{obligation_index}Edge{edge_index}Precondition"
            )
            target_predicate = requirement_by_id[edge["requirement_id"]]["predicate"]
            definitions.append(
                f"def {target_predicate_name} : BoolExpr := "
                f"{_lean_semantic_bool_expr(target_predicate)}"
            )
            definitions.append(
                f"def {precondition_name} : BoolExpr := "
                f"{_lean_semantic_bool_expr(edge['precondition'])}"
            )
            theorem_name = f"invariantFamily{obligation_index}Edge{edge_index}Checked"
            theorem_names.append(theorem_name)
            claim = (
                f"InvariantWP.NormalizedInvariantPredicateEdgeClosed {behavior_name} "
                f"{source_name} {target_predicate_name} "
                f"{contract['regions'][target_index]['numeric_id']}"
            )
            claims.append(claim)
            proof = [
                f"theorem {theorem_name} : {claim} := by",
                "  apply InvariantWP.invariantPredicateEdgeClosed_of_wp "
                f"{behavior_name} {source_name} {target_predicate_name} "
                f"{precondition_name} "
                f"{contract['regions'][target_index]['numeric_id']}",
                "  · decide",
                "  · decide",
                "  · intro state sourceInvariant",
            ]
            if edge["analysis_status"] == "requires_predecessor_invariant":
                proof.extend([
                    f"    exact InvariantWP.stateInvariantsHold_member {source_name}",
                    f"      {precondition_name} state (by decide) sourceInvariant",
                ])
            else:
                specialized = _lean_masked_successor_tautology_proof(
                    precondition_name, edge["precondition"]
                )
                if specialized is None:
                    specialized = _lean_successor_tautology_proof(
                        precondition_name, edge["precondition"]
                    )
                if specialized is not None:
                    proof.extend(specialized)
                else:
                    proof.extend([
                        "    rcases state with "
                        "⟨⟨eax, ebx, ecx, edx, esi, edi, ebp, esp⟩, memory, "
                        "undefinedValue, x87, eflags, fsBase⟩",
                        f"    simp [{precondition_name}, StageA.Formal.BoolExpr.eval,",
                        "      StageA.Formal.Expr.eval, StageA.Formal.Registers.get]",
                        "    all_goals bv_decide",
                    ])
            definitions.append("\n".join(proof))
        claims_name = f"invariantFamily{obligation_index}Claims"
        checked_name = f"invariantFamily{obligation_index}Checked"
        definitions.append(f"def {claims_name} : List Prop := [{', '.join(claims)}]")
        all_proof = (
            "".join(f"And.intro {theorem_name} (" for theorem_name in theorem_names)
            + "True.intro"
            + ")" * len(theorem_names)
        )
        definitions.append(
            f"theorem {checked_name} : AllInvariantClaims {claims_name} := by\n"
            f"  exact {all_proof}"
        )
        source = (
            imports
            + "\n\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)
        modules.append({
            "module": module,
            "obligation_id": obligation_id,
            "claims": claims_name,
            "theorem": checked_name,
        })
        inventory_pack_count = min(
            len(shard_groups),
            max(1, int(os.environ.get(
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_INVARIANT_INVENTORY_PACKS", "64"
            ))),
        )
        shards_per_inventory_pack = (
            len(shard_groups) + inventory_pack_count - 1
        ) // inventory_pack_count
        for pack_index, shard_offset in enumerate(
            range(0, len(shard_groups), shards_per_inventory_pack)
        ):
            shard_indices = range(
                shard_offset,
                min(len(shard_groups), shard_offset + shards_per_inventory_pack),
            )
            inventory_region_indices = [
                region_index
                for shard_index in shard_indices
                for region_index in shard_groups[shard_index]
            ]
            inventory_module = (
                f"RelationalInvariantFamily{obligation_index}Inventory{pack_index}"
            )
            inventory_imports = "\n".join(
                f"import StageA.{definition_modules[shard_index]}"
                for shard_index in range(
                    shard_offset,
                    min(len(shard_groups), shard_offset + shards_per_inventory_pack),
                )
            )
            inventory_definitions: list[str] = []
            inventory_theorems: list[str] = []
            inventory_claims: list[str] = []
            for side in ("original", "candidate"):
                side_name = side.capitalize()
                candidate = "true" if side == "candidate" else "false"
                prefix = f"invariantFamily{obligation_index}Inventory{pack_index}{side_name}"
                target_rows = ", ".join(
                    "{ target := "
                    f"{target}, predicate := {_lean_semantic_bool_expr(predicate)} }}"
                    for target, predicate in target_specs_by_side[side]
                )
                inventory_definitions.append(
                    f"def {prefix}Targets : List InvariantTargetSpec := [{target_rows}]"
                )
                source_rows = ", ".join(
                    f"({index}, ((normalizeSymbolicBehavior {candidate} "
                    f"region{index}.targets {side}Behavior{index}).get "
                    "(by decide)).outcome)"
                    for index in inventory_region_indices
                )
                inventory_definitions.append(
                    f"def {prefix}Sources : List (Nat × NormalizedOutcomeExpr) := "
                    f"[{source_rows}]"
                )
                inventory_region_set = set(inventory_region_indices)
                claimed_rows = ", ".join(
                    "{ sourceIndex := "
                    f"{edge['source_index']}, target := "
                    f"{contract['regions'][edge['target_index']]['numeric_id']}, "
                    "predicate := "
                    f"{_lean_semantic_bool_expr(requirement_by_id[edge['requirement_id']]['predicate'])} }}"
                    for edge in edges
                    if edge["side"] == side
                    and edge["source_index"] in inventory_region_set
                )
                inventory_definitions.append(
                    f"def {prefix}ClaimedEdges : List InvariantEdgeSpec := [{claimed_rows}]"
                )
                theorem_name = f"{prefix}Checked"
                claim = (
                    f"invariantEdgeInventoryClosed {prefix}Sources {prefix}Targets "
                    f"{prefix}ClaimedEdges = true"
                )
                inventory_theorems.append(theorem_name)
                inventory_claims.append(claim)
                inventory_definitions.append(
                    f"theorem {theorem_name} : {claim} := by decide"
                )
            inventory_claims_name = (
                f"invariantFamily{obligation_index}Inventory{pack_index}Claims"
            )
            inventory_checked_name = (
                f"invariantFamily{obligation_index}Inventory{pack_index}Checked"
            )
            inventory_definitions.append(
                f"def {inventory_claims_name} : List Prop := "
                f"[{', '.join(inventory_claims)}]"
            )
            inventory_all_proof = (
                "".join(f"And.intro {name} (" for name in inventory_theorems)
                + "True.intro"
                + ")" * len(inventory_theorems)
            )
            inventory_definitions.append(
                f"theorem {inventory_checked_name} : "
                f"AllInvariantClaims {inventory_claims_name} := by\n"
                f"  exact {inventory_all_proof}"
            )
            inventory_source = (
                "import StageA.RelationalInvariant\n"
                + inventory_imports
                + "\n\nnamespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
                + "\n\n".join(inventory_definitions)
                + "\n\nend StageA.GeneratedRelational\n"
            )
            _write_text_if_changed(
                lean_dir / "StageA" / f"{inventory_module}.lean", inventory_source
            )
            modules.append({
                "module": inventory_module,
                "obligation_id": obligation_id,
                "claims": inventory_claims_name,
                "theorem": inventory_checked_name,
            })
    return modules

def _write_relational_memory_pullback_modules(
    lean_dir: Path,
    contract: dict[str, Any],
    memory_contracts: dict[str, Any],
    definition_modules: list[str],
    shard_groups: list[list[int]],
    decode_chunk_regions: list[list[int]],
    *,
    original_image_base: int,
    candidate_image_base: int,
) -> list[dict[str, str]]:
    definition_by_region = {
        region_index: definition_modules[shard_index]
        for shard_index, indices in enumerate(shard_groups)
        for region_index in indices
    }
    index_by_numeric_id = {
        region["numeric_id"]: index
        for index, region in enumerate(contract["regions"])
    }
    modules: list[dict[str, str]] = []
    for chunk_index, source_indices in enumerate(decode_chunk_regions):
        edges: list[tuple[int, int, int]] = []
        for source_index in source_indices:
            row = memory_contracts["regions"][source_index]
            if not row["pullback"]["paired_direct_successors"]:
                continue
            for target_id in dict.fromkeys(row["successors"]["direct"]):
                target_index = index_by_numeric_id.get(target_id)
                if target_index is None:
                    continue
                target_pullback = memory_contracts["regions"][target_index]["pullback"]
                if all(
                    target_pullback[side]["all_ordinary_reads_supported"]
                    for side in ("original", "candidate")
                ):
                    edges.append((source_index, target_index, target_id))
        if not edges:
            continue

        involved = sorted({index for edge in edges for index in edge[:2]})
        imports = "\n".join(
            f"import StageA.{module}"
            for module in sorted({definition_by_region[index] for index in involved})
        )
        definitions: list[str] = []
        for index in involved:
            for side in ("original", "candidate"):
                candidate = "true" if side == "candidate" else "false"
                side_name = side.capitalize()
                definitions.append(
                    f"def memoryPullbackChunk{chunk_index}{side_name}Behavior{index} : "
                    "NormalizedSymbolicBehavior :=\n"
                    f"  (normalizeSymbolicBehavior {candidate} region{index}.targets "
                    f"{side}Behavior{index}).get (by decide)"
                )

        theorem_names: list[str] = []
        claims: list[str] = []
        x87_theorem_names: list[str] = []
        x87_claims: list[str] = []
        for edge_index, (source_index, target_index, target_id) in enumerate(edges):
            requirement = next(
                item
                for item in memory_contracts["regions"][source_index][
                    "successor_read_requirements"
                ]
                if item["numeric_id"] == target_id
            )
            for side in ("original", "candidate"):
                side_name = side.capitalize()
                theorem_name = (
                    f"memoryPullbackChunk{chunk_index}Edge{edge_index}{side_name}Checked"
                )
                source_name = (
                    f"memoryPullbackChunk{chunk_index}{side_name}Behavior{source_index}"
                )
                target_name = (
                    f"memoryPullbackChunk{chunk_index}{side_name}Behavior{target_index}"
                )
                claim = (
                    f"InvariantWP.MemoryReadPullbackEdgeClosed {source_name} "
                    f"{target_name} {target_id}"
                )
                theorem_names.append(theorem_name)
                claims.append(claim)
                definitions.append(
                    f"theorem {theorem_name} : {claim} :=\n"
                    "  InvariantWP.memoryReadPullbackEdgeClosed_of_checked "
                    f"{source_name} {target_name} {target_id} (by decide) (by decide)"
                )
                if (
                    requirement["x87_load_observations"] > 0
                    and requirement["x87_load_pullback_pair_supported"]
                ):
                    x87_theorem_name = (
                        f"x87LoadPullbackChunk{chunk_index}Edge{edge_index}"
                        f"{side_name}Checked"
                    )
                    x87_claim = (
                        f"InvariantWP.X87LoadPullbackEdgeClosed {source_name} "
                        f"{target_name} {target_id}"
                    )
                    x87_theorem_names.append(x87_theorem_name)
                    x87_claims.append(x87_claim)
                    definitions.append(
                        f"theorem {x87_theorem_name} : {x87_claim} :=\n"
                        "  InvariantWP.x87LoadPullbackEdgeClosed_of_checked "
                        f"{source_name} {target_name} {target_id} (by decide) (by decide)"
                    )
            pair_claim_names: list[str] = []
            for pair_index, pair_claim in enumerate(
                requirement["exact_pullback_pair_claims"]
            ):
                expression_name = (
                    f"memoryPullbackChunk{chunk_index}Edge{edge_index}"
                    f"Pair{pair_index}Read"
                )
                pulled_name = expression_name + "Pulled"
                claim_name = expression_name + "Claim"
                theorem_name = expression_name + "Checked"
                source_original = (
                    f"memoryPullbackChunk{chunk_index}OriginalBehavior{source_index}"
                )
                source_candidate = (
                    f"memoryPullbackChunk{chunk_index}CandidateBehavior{source_index}"
                )
                target_original = (
                    f"memoryPullbackChunk{chunk_index}OriginalBehavior{target_index}"
                )
                target_candidate = (
                    f"memoryPullbackChunk{chunk_index}CandidateBehavior{target_index}"
                )
                definitions.append(
                    f"def {expression_name} : Expr := "
                    f"{_lean_semantic_expr(pair_claim['expression'])}"
                )
                definitions.append(
                    f"def {pulled_name} : Expr :=\n"
                    f"  ({expression_name}.pullbackMemoryRead {source_original}).get "
                    "(by decide)"
                )
                definitions.append(
                    f"def {claim_name} : InvariantWP.ExactMemoryReadPullbackPairClaim := "
                    f"{{ originalRead := {expression_name}, candidateRead := {expression_name}, "
                    f"pulled := {pulled_name} }}"
                )
                pair_claim_names.append(claim_name)
                claim = (
                    f"InvariantWP.ExactMemoryReadPullbackPairEdgeClosed "
                    f"{original_image_base} {candidate_image_base} globalCodeTargets "
                    f"globalValueTargets region{source_index} "
                    f"region{target_index} {source_original} {source_candidate} "
                    f"{claim_name}"
                )
                theorem_names.append(theorem_name)
                claims.append(claim)
                definitions.append(
                    f"theorem {theorem_name} : {claim} := by\n"
                    f"  apply InvariantWP.exactMemoryReadPullbackPairEdgeClosed_of_checked "
                    f"{original_image_base} {candidate_image_base} globalCodeTargets "
                    f"globalValueTargets region{source_index} "
                    f"region{target_index} {source_original} {source_candidate} "
                    f"{target_original} {target_candidate} {claim_name}\n"
                    "  · decide\n"
                    "  · decide\n"
                    "  · decide"
                )
            if requirement["exact_memory_transition_proposed"]:
                transition_claims = (
                    f"memoryPullbackChunk{chunk_index}Edge{edge_index}"
                    "ExactTransitionClaims"
                )
                transition_proposition = (
                    f"memoryPullbackChunk{chunk_index}Edge{edge_index}"
                    "ExactTransitionClosed"
                )
                transition_theorem = (
                    f"memoryPullbackChunk{chunk_index}Edge{edge_index}"
                    "ExactTransitionChecked"
                )
                source_original = (
                    f"memoryPullbackChunk{chunk_index}OriginalBehavior{source_index}"
                )
                source_candidate = (
                    f"memoryPullbackChunk{chunk_index}CandidateBehavior{source_index}"
                )
                target_original = (
                    f"memoryPullbackChunk{chunk_index}OriginalBehavior{target_index}"
                )
                target_candidate = (
                    f"memoryPullbackChunk{chunk_index}CandidateBehavior{target_index}"
                )
                definitions.append(
                    f"def {transition_claims} : List "
                    "InvariantWP.ExactMemoryReadPullbackPairClaim := "
                    f"[{', '.join(pair_claim_names)}]"
                )
                transition_claim = (
                    f"MemoryObservationTransitionClosed {original_image_base} "
                    f"{candidate_image_base} globalCodeTargets globalValueTargets "
                    f"region{source_index} ({transition_claims}.map "
                    "InvariantWP.ExactMemoryReadPullbackPairClaim.requirement) [] "
                    f"{source_original} {source_candidate}"
                )
                definitions.append(
                    f"def {transition_proposition} : Prop := {transition_claim}"
                )
                definitions.append(
                    f"theorem {transition_theorem} : {transition_proposition} := by\n"
                    f"  apply InvariantWP.memoryObservationTransitionClosed_of_exact_pullback_pairs "
                    f"{original_image_base} {candidate_image_base} globalCodeTargets "
                    f"globalValueTargets region{source_index} "
                    f"region{target_index} {source_original} {source_candidate} "
                    f"{target_original} {target_candidate} {transition_claims}\n"
                    "  decide"
                )
                theorem_names.append(transition_theorem)
                claims.append(transition_claim)

        claims_name = f"memoryPullbackChunk{chunk_index}Claims"
        checked_name = f"memoryPullbackChunk{chunk_index}Checked"
        definitions.append(f"def {claims_name} : List Prop := [{', '.join(claims)}]")
        all_proof = (
            "".join(f"And.intro {name} (" for name in theorem_names)
            + "True.intro"
            + ")" * len(theorem_names)
        )
        definitions.append(
            f"theorem {checked_name} : AllInvariantClaims {claims_name} := by\n"
            f"  exact {all_proof}"
        )
        x87_claims_name = f"x87LoadPullbackChunk{chunk_index}Claims"
        x87_checked_name = f"x87LoadPullbackChunk{chunk_index}Checked"
        definitions.append(
            f"def {x87_claims_name} : List Prop := [{', '.join(x87_claims)}]"
        )
        x87_all_proof = (
            "".join(f"And.intro {name} (" for name in x87_theorem_names)
            + "True.intro"
            + ")" * len(x87_theorem_names)
        )
        definitions.append(
            f"theorem {x87_checked_name} : AllInvariantClaims {x87_claims_name} := by\n"
            f"  exact {x87_all_proof}"
        )
        module = f"RelationalMemoryPullbackChunk{chunk_index}"
        source = (
            "import StageA.RelationalGlobalMappingContext\n"
            "import StageA.RelationalInvariant\n"
            + imports
            + "\n\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)
        modules.append({
            "module": module,
            "ordinary_claims": claims_name,
            "ordinary_theorem": checked_name,
            "x87_claims": x87_claims_name,
            "x87_theorem": x87_checked_name,
            "edges": str(len(edges)),
        })
    return modules

def _write_relational_register_relation_modules(
    lean_dir: Path,
    contract: dict[str, Any],
    register_relations: dict[str, Any],
    definition_modules: list[str],
    shard_groups: list[list[int]],
    decode_chunk_regions: list[list[int]],
    *,
    original_image_base: int,
    candidate_image_base: int,
) -> list[dict[str, str]]:
    definition_by_region = {
        region_index: definition_modules[shard_index]
        for shard_index, indices in enumerate(shard_groups)
        for region_index in indices
    }
    relation_by_region = {
        int(row["region_index"]): row for row in register_relations["regions"]
    }
    contracts_by_id = {
        int(item["id"]): item
        for item in contract.get("machine_import_call_contracts", [])
    }
    modules: list[dict[str, str]] = []
    for chunk_index, region_indices in enumerate(decode_chunk_regions):
        exact_edges = [
            edge for edge in register_relations["edges"]
            if edge["source_region_index"] in region_indices
            and edge["fully_exact_edge_proposed"]
        ]
        pair_edges = [
            edge for edge in register_relations["edges"]
            if edge["source_region_index"] in region_indices
            and edge["exact_output_pair_claims"]
        ]
        environment_edges = [
            edge for edge in register_relations["edges"]
            if edge["source_region_index"] in region_indices
            and _external_register_policy_replay_candidate(contract, edge)
        ]
        call_return_edges = [
            edge for edge in register_relations["edges"]
            if edge["source_region_index"] in region_indices
            and edge["requires_call_stack_proof"]
        ]
        call_push_edges = [
            edge for edge in register_relations["edges"]
            if edge["source_region_index"] in region_indices
            and edge.get("direct_call_push_claim") is not None
        ]
        indirect_call_push_edges = [
            edge for edge in register_relations["edges"]
            if edge["source_region_index"] in region_indices
            and edge.get("indirect_call_push_claim") is not None
        ]
        return_slot_edges = [
            edge for edge in register_relations["edges"]
            if edge["source_region_index"] in region_indices
            and edge.get("return_slot_transfer_claims")
        ]
        return_slot_rule_edges = [
            edge for edge in register_relations["edges"]
            if edge["source_region_index"] in region_indices
            and edge.get("return_slot_transfer_rules")
        ]
        call_summary_edges = [
            edge for edge in register_relations["edges"]
            if edge["source_region_index"] in region_indices
            and edge.get("return_slot_call_summary_claims")
        ]
        selected = sorted(set(
            index for index in region_indices
            if relation_by_region[index]["output_claims"]
            or relation_by_region[index].get("return_pop_claim") is not None
        ) | {
            int(edge["source_region_index"]) for edge in environment_edges
        } | {
            int(edge["source_region_index"]) for edge in call_return_edges
        } | {
            int(edge["source_region_index"]) for edge in call_push_edges
        } | {
            int(edge["source_region_index"]) for edge in indirect_call_push_edges
        } | {
            int(edge["source_region_index"]) for edge in return_slot_edges
        } | {
            int(edge["source_region_index"]) for edge in return_slot_rule_edges
        } | {
            int(edge["source_region_index"]) for edge in call_summary_edges
        })
        if not selected:
            continue
        involved = set(selected) | {
            int(edge["target_region_index"]) for edge in exact_edges
        } | {
            int(edge["target_region_index"]) for edge in pair_edges
        } | {
            int(edge["target_region_index"]) for edge in environment_edges
        } | {
            int(edge["callsite_region_index"]) for edge in call_return_edges
        } | {
            int(edge["callee_entry_region_index"]) for edge in call_return_edges
        } | {
            int(edge["target_region_index"]) for edge in call_return_edges
        } | {
            int(claim["return_region_index"])
            for edge in call_summary_edges
            for claim in edge["return_slot_call_summary_claims"]
        }
        imports = "\n".join(
            f"import StageA.{module}"
            for module in sorted({definition_by_region[index] for index in involved})
        )
        definitions: list[str] = []
        theorem_names: list[str] = []
        proposition_names: list[str] = []
        extra_behavior_indices = sorted(({
            int(edge["callsite_region_index"]) for edge in call_return_edges
        } | {
            int(claim["return_region_index"])
            for edge in call_summary_edges
            for claim in edge["return_slot_call_summary_claims"]
        }) - set(selected))
        for index in extra_behavior_indices:
            definitions.extend([
                f"def registerRelationChunk{chunk_index}OriginalBehavior{index} : "
                "NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior false region{index}.targets "
                f"originalBehavior{index}).get (by decide)",
                f"def registerRelationChunk{chunk_index}CandidateBehavior{index} : "
                "NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior true region{index}.targets "
                f"candidateBehavior{index}).get (by decide)",
            ])
        for index in selected:
            row = relation_by_region[index]
            original_name = f"registerRelationChunk{chunk_index}OriginalBehavior{index}"
            candidate_name = f"registerRelationChunk{chunk_index}CandidateBehavior{index}"
            claims_name = f"registerRelationChunk{chunk_index}Region{index}Claims"
            theorem_name = f"registerRelationChunk{chunk_index}Region{index}Checked"
            proposition_name = f"registerRelationChunk{chunk_index}Region{index}Closed"
            definitions.extend([
                f"def {original_name} : NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior false region{index}.targets "
                f"originalBehavior{index}).get (by decide)",
                f"def {candidate_name} : NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior true region{index}.targets "
                f"candidateBehavior{index}).get (by decide)",
            ])
            return_claim = row.get("return_pop_claim")
            if return_claim is not None:
                return_claim_name = (
                    f"registerRelationChunk{chunk_index}Region{index}ReturnPopClaim"
                )
                return_proposition_name = (
                    f"registerRelationChunk{chunk_index}Region{index}ReturnPopClosed"
                )
                return_theorem_name = (
                    f"registerRelationChunk{chunk_index}Region{index}ReturnPopChecked"
                )
                after_writes = (
                    return_claim["profile"]
                    == "esp_relative_return_after_static_writes_v1"
                )
                if after_writes:
                    definitions.append(
                        f"def {return_claim_name} : ReturnPopAfterWritesClaim := {{\n"
                        "  originalStack := "
                        f"{_lean_register_offset_witness(return_claim['original_stack_witness'])}\n"
                        "  candidateStack := "
                        f"{_lean_register_offset_witness(return_claim['candidate_stack_witness'])}\n"
                        "  originalOutput := "
                        f"{_lean_register_offset_witness(return_claim['original_output_witness'])}\n"
                        "  candidateOutput := "
                        f"{_lean_register_offset_witness(return_claim['candidate_output_witness'])}\n"
                        f"  popBytes := {int(return_claim['pop_bytes'])}\n"
                        "}"
                    )
                    definitions.append(
                        f"def {return_proposition_name} : Prop :=\n"
                        f"  ReturnPopAfterWritesClosed region{index}.inputInvariant "
                        f"{original_name} {candidate_name} {return_claim_name}"
                    )
                    definitions.append(
                        f"theorem {return_theorem_name} : {return_proposition_name} := by\n"
                        "  apply returnPopAfterWritesClosed_of_checked\n"
                        "  decide"
                    )
                else:
                    definitions.append(
                        f"def {return_claim_name} : ReturnPopClaim := {{\n"
                        "  originalStackAddress := "
                        f"{_lean_semantic_expr(return_claim['original_stack_address'])}\n"
                        "  candidateStackAddress := "
                        f"{_lean_semantic_expr(return_claim['candidate_stack_address'])}\n"
                        f"  popBytes := {int(return_claim['pop_bytes'])}\n"
                        "}"
                    )
                    definitions.append(
                        f"def {return_proposition_name} : Prop :=\n"
                        f"  ReturnPopClosed {original_name} {candidate_name} "
                        f"{return_claim_name}"
                    )
                    definitions.append(
                        f"theorem {return_theorem_name} : {return_proposition_name} := by\n"
                        "  apply returnPopClosed_of_checked\n"
                        "  decide"
                    )
                theorem_names.append(return_theorem_name)
                proposition_names.append(return_proposition_name)
                for frame_index, frame_claim in enumerate(
                    row.get("return_pop_frame_claims", [])
                ):
                    frame_name = (
                        f"registerRelationChunk{chunk_index}Region{index}"
                        f"ReturnFrame{frame_index}Claim"
                    )
                    frame_proposition = f"{frame_name}Closed"
                    frame_theorem = f"{frame_name}Checked"
                    definitions.append(
                        f"def {frame_name} : ReturnPopFrameClaim := {{\n"
                        "  offsets := "
                        f"{_lean_return_slot_offset_pair(frame_claim['offsets'])}\n"
                        "  originalSlot := "
                        f"{_lean_register_offset_witness(frame_claim['original_slot_witness'])}\n"
                        "  candidateSlot := "
                        f"{_lean_register_offset_witness(frame_claim['candidate_slot_witness'])}\n"
                        "}"
                    )
                    if after_writes:
                        definitions.append(
                            f"def {frame_proposition} : Prop :=\n"
                            "  ReturnPopAfterWritesFrameClaimClosed "
                            f"{return_claim_name} {frame_name}"
                        )
                        definitions.append(
                            f"theorem {frame_theorem} : {frame_proposition} := by\n"
                            "  apply returnPopAfterWritesFrameClaimClosed_of_checked\n"
                            "  decide"
                        )
                        semantic_proposition = f"{frame_name}TargetsRuntimeFrame"
                        semantic_theorem = f"{semantic_proposition}Checked"
                        definitions.append(
                            f"def {semantic_proposition} : Prop :=\n"
                            "  forall world frame originalState candidateState,\n"
                            f"    StateRel staticProofContext world region{index}.inputInvariant "
                            "originalState candidateState ->\n"
                            f"    {frame_name}.offsets.holds frame originalState.registers "
                            "candidateState.registers ->\n"
                            "    frame.memoryHolds originalState.memory candidateState.memory ->\n"
                            f"    {original_name}.outcome.eval originalState = "
                            ".returned frame.originalReturnAddress /\\\n"
                            f"      {candidate_name}.outcome.eval candidateState = "
                            ".returned frame.candidateReturnAddress"
                        )
                        definitions.append(
                            f"theorem {semantic_theorem} : {semantic_proposition} := by\n"
                            "  intro world frame originalState candidateState related "
                            "offsetsHold memoryHolds\n"
                            "  exact returnPopAfterWritesTargetsRuntimeFrame_of_checked\n"
                            f"    staticProofContext world region{index}.inputInvariant "
                            f"{original_name} {candidate_name}\n"
                            f"    {return_claim_name} {frame_name} frame originalState "
                            "candidateState (by decide) (by decide) related offsetsHold memoryHolds"
                        )
                        theorem_names.append(semantic_theorem)
                        proposition_names.append(semantic_proposition)
                    else:
                        definitions.append(
                            f"def {frame_proposition} : Prop :=\n"
                            f"  ReturnPopFrameClaimClosed {return_claim_name} {frame_name}"
                        )
                        definitions.append(
                            f"theorem {frame_theorem} : {frame_proposition} := by\n"
                            "  apply returnPopFrameClaimClosed_of_checked\n"
                            "  decide"
                        )
                    theorem_names.append(frame_theorem)
                    proposition_names.append(frame_proposition)
            claim_literals = []
            for claim in row["exact_output_claims"]:
                register = claim["register"]
                claim_literals.append(
                    "{ output := { original := ." + register
                    + ", candidate := ." + register
                    + ", relation := .exact }, expression := "
                    + _lean_semantic_expr(claim["expression"])
                    + " }"
                )
            definitions.append(
                f"def {claims_name} : List InvariantWP.ExactRegisterOutputClaim := "
                f"[{', '.join(claim_literals)}]"
            )
            output_claims_name = (
                f"registerRelationChunk{chunk_index}Region{index}OutputClaims"
            )
            output_claim_literals = [
                _lean_register_output_claim(claim)
                for claim in row["output_claims"]
            ]
            definitions.append(
                f"def {output_claims_name} : List InvariantWP.RegisterOutputClaim := "
                f"[{', '.join(output_claim_literals)}]"
            )
            definitions.append(
                f"def {proposition_name} : Prop :=\n"
                f"  InvariantWP.AllExactRegisterOutputClaims {original_image_base} "
                f"{candidate_image_base} globalCodeTargets globalValueTargets "
                f"region{index} {original_name} {candidate_name} {claims_name}"
            )
            definitions.append(
                f"theorem {theorem_name} : {proposition_name} := by\n"
                f"  apply InvariantWP.allExactRegisterOutputClaims_of_checked "
                f"{original_image_base} {candidate_image_base} globalCodeTargets "
                f"globalValueTargets region{index} "
                f"{original_name} {candidate_name} {claims_name}\n"
                "  decide"
            )
            theorem_names.append(theorem_name)
            proposition_names.append(proposition_name)
            output_proposition_name = (
                f"registerRelationChunk{chunk_index}Region{index}OutputClaimsClosed"
            )
            output_theorem_name = (
                f"registerRelationChunk{chunk_index}Region{index}OutputClaimsChecked"
            )
            state_rel_only_claims = {
                "immutable_image_word",
                "fixed_immutable_expression",
                "static_word_slot",
                "stack_read32_sub",
                "stack_read32_relative",
                "stack_window_identity",
            }
            if not any(
                claim["kind"] in state_rel_only_claims
                for claim in row["output_claims"]
            ):
                definitions.append(
                    f"def {output_proposition_name} : Prop :=\n"
                    f"  InvariantWP.AllRegisterOutputClaims {original_image_base} "
                    f"{candidate_image_base} globalCodeTargets globalValueTargets "
                    f"region{index} {original_name} {candidate_name} "
                    f"{output_claims_name}"
                )
                definitions.append(
                    f"theorem {output_theorem_name} : {output_proposition_name} := by\n"
                    f"  apply InvariantWP.allRegisterOutputClaims_of_checked "
                    f"{original_image_base} {candidate_image_base} globalCodeTargets "
                    f"globalValueTargets region{index} "
                    f"{original_name} {candidate_name} {output_claims_name}\n"
                    "  decide"
                )
                theorem_names.append(output_theorem_name)
                proposition_names.append(output_proposition_name)
            if row["fully_supported_output_transfer"] and not any(
                claim["kind"] in state_rel_only_claims
                for claim in row["output_claims"]
            ):
                supported_transfer_name = (
                    f"registerRelationChunk{chunk_index}Region{index}"
                    "SupportedTransferClosed"
                )
                supported_transfer_theorem = (
                    f"registerRelationChunk{chunk_index}Region{index}"
                    "SupportedTransferChecked"
                )
                definitions.append(
                    f"def {supported_transfer_name} : Prop :=\n"
                    f"  InvariantWP.RegisterTransferClosed {original_image_base} "
                    f"{candidate_image_base} globalCodeTargets globalValueTargets "
                    f"region{index} {original_name} {candidate_name}"
                )
                definitions.append(
                    f"theorem {supported_transfer_theorem} : "
                    f"{supported_transfer_name} := by\n"
                    f"  apply InvariantWP.registerTransferClosed_of_checked "
                    f"{original_image_base} {candidate_image_base} globalCodeTargets "
                    f"globalValueTargets region{index} "
                    f"{original_name} {candidate_name} {output_claims_name}\n"
                    "  · decide\n"
                    "  · decide"
                )
                theorem_names.append(supported_transfer_theorem)
                proposition_names.append(supported_transfer_name)
            if row["fully_exact_output_transfer"]:
                transfer_name = (
                    f"registerRelationChunk{chunk_index}Region{index}TransferClosed"
                )
                transfer_theorem = (
                    f"registerRelationChunk{chunk_index}Region{index}TransferChecked"
                )
                definitions.append(
                    f"def {transfer_name} : Prop :=\n"
                    f"  InvariantWP.ExactRegisterTransferClosed {original_image_base} "
                    f"{candidate_image_base} globalCodeTargets globalValueTargets "
                    f"region{index} {original_name} {candidate_name}"
                )
                definitions.append(
                    f"theorem {transfer_theorem} : {transfer_name} := by\n"
                    f"  apply InvariantWP.exactRegisterTransferClosed_of_checked "
                    f"{original_image_base} {candidate_image_base} globalCodeTargets "
                    f"globalValueTargets region{index} "
                    f"{original_name} {candidate_name} {claims_name}\n"
                    "  · decide\n"
                    "  · decide"
                )
                theorem_names.append(transfer_theorem)
                proposition_names.append(transfer_name)
        for edge_index, edge in enumerate(exact_edges):
            source_index = int(edge["source_region_index"])
            target_index = int(edge["target_region_index"])
            original_name = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{source_index}"
            )
            candidate_name = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{source_index}"
            )
            source_claims = (
                f"registerRelationChunk{chunk_index}Region{source_index}Claims"
            )
            proposition_name = (
                f"registerRelationChunk{chunk_index}Edge{edge_index}Closed"
            )
            theorem_name = (
                f"registerRelationChunk{chunk_index}Edge{edge_index}Checked"
            )
            definitions.append(
                f"def {proposition_name} : Prop :=\n"
                f"  InvariantWP.ExactRegisterRelationEdgeClosed {original_image_base} "
                f"{candidate_image_base} globalCodeTargets globalValueTargets "
                f"region{source_index} region{target_index} "
                f"{original_name} {candidate_name}"
            )
            definitions.append(
                f"theorem {theorem_name} : {proposition_name} := by\n"
                f"  apply InvariantWP.exactRegisterRelationEdgeClosed_of_checked "
                f"{original_image_base} {candidate_image_base} globalCodeTargets "
                f"globalValueTargets region{source_index} "
                f"region{target_index} {original_name} {candidate_name} {source_claims}\n"
                "  · decide\n"
                "  · decide\n"
                "  · decide\n"
                "  · decide\n"
                "  · decide\n"
                "  · decide"
            )
            theorem_names.append(theorem_name)
            proposition_names.append(proposition_name)
        for edge_index, edge in enumerate(pair_edges):
            source_index = int(edge["source_region_index"])
            target_index = int(edge["target_region_index"])
            original_name = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{source_index}"
            )
            candidate_name = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{source_index}"
            )
            target_inputs = {
                relation["original"]: relation
                for relation in relation_by_region[target_index]["inputs"]
            }
            for pair_index, pair_claim in enumerate(edge["exact_output_pair_claims"]):
                register = pair_claim["register"]
                if register not in target_inputs:
                    continue
                target_relation = target_inputs[register]
                relation_constructor = {
                    "exact": "exact",
                    "related_word": "relatedWord",
                }[target_relation["relation"]]
                claim_name = (
                    f"registerRelationChunk{chunk_index}Edge{edge_index}"
                    f"Pair{pair_index}Claim"
                )
                proposition_name = (
                    f"registerRelationChunk{chunk_index}Edge{edge_index}"
                    f"Pair{pair_index}Closed"
                )
                theorem_name = (
                    f"registerRelationChunk{chunk_index}Edge{edge_index}"
                    f"Pair{pair_index}Checked"
                )
                definitions.append(
                    f"def {claim_name} : InvariantWP.ExactRegisterRelationPairEdgeClaim := "
                    "{ sourceOutput := { output := { original := ." + register
                    + ", candidate := ." + target_relation["candidate"]
                    + ", relation := .exact }, expression := "
                    + _lean_semantic_expr(pair_claim["expression"])
                    + " }, targetInput := { original := ." + register
                    + ", candidate := ." + target_relation["candidate"]
                    + ", relation := ." + relation_constructor + " } }"
                )
                definitions.append(
                    f"def {proposition_name} : Prop :=\n"
                    f"  InvariantWP.ExactRegisterRelationPairEdgeClosed "
                    f"{original_image_base} {candidate_image_base} globalCodeTargets "
                    f"globalValueTargets region{source_index} "
                    f"region{target_index} {original_name} {candidate_name} {claim_name}"
                )
                definitions.append(
                    f"theorem {theorem_name} : {proposition_name} := by\n"
                    f"  apply InvariantWP.exactRegisterRelationPairEdgeClosed_of_checked "
                    f"{original_image_base} {candidate_image_base} globalCodeTargets "
                    f"globalValueTargets region{source_index} "
                    f"region{target_index} {original_name} {candidate_name} {claim_name}\n"
                    "  · decide\n"
                    "  · decide\n"
                    "  · decide"
                )
                theorem_names.append(theorem_name)
                proposition_names.append(proposition_name)
        for edge_index, edge in enumerate(environment_edges):
            source_index = int(edge["source_region_index"])
            target_index = int(edge["target_region_index"])
            machine_contract_id = int(edge["machine_contract_id"])
            machine_contract = contracts_by_id.get(machine_contract_id)
            if machine_contract is None:
                raise StageAInputError(
                    f"external register-policy edge {edge_index} has no "
                    f"machine contract {machine_contract_id}"
                )
            original_name = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{source_index}"
            )
            candidate_name = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{source_index}"
            )
            proposition_name = (
                f"registerRelationChunk{chunk_index}EnvironmentEdge{edge_index}Closed"
            )
            theorem_name = (
                f"registerRelationChunk{chunk_index}EnvironmentEdge{edge_index}Checked"
            )
            contract_name = (
                f"registerRelationChunk{chunk_index}EnvironmentEdge{edge_index}Contract"
            )
            definitions.append(
                f"def {contract_name} : MachineImportCallContract := "
                f"{_lean_machine_import_call_contract(machine_contract)}"
            )
            definitions.append(
                f"def {proposition_name} : Prop :=\n"
                "  machineImportCallContractById? staticProofContext "
                f"{machine_contract_id} = some {contract_name} \u2227\n"
                "    InvariantWP.ExternalRegisterPolicyEdgeClosed "
                f"region{source_index} region{target_index} "
                f"{contract_name} {original_name} {candidate_name}"
            )
            definitions.append(
                f"theorem {theorem_name} : {proposition_name} := by\n"
                "  constructor\n"
                "  \u00b7 decide\n"
                "  \u00b7 apply InvariantWP.externalRegisterPolicyEdgeClosed_of_checked\n"
                "    decide"
            )
            theorem_names.append(theorem_name)
            proposition_names.append(proposition_name)
        for edge_index, edge in enumerate(call_return_edges):
            return_index = int(edge["source_region_index"])
            continuation_index = int(edge["target_region_index"])
            callsite_index = int(edge["callsite_region_index"])
            callee_index = int(edge["callee_entry_region_index"])
            original_caller = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{callsite_index}"
            )
            candidate_caller = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{callsite_index}"
            )
            original_return = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{return_index}"
            )
            candidate_return = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{return_index}"
            )
            proposition_name = (
                f"registerRelationChunk{chunk_index}CallReturnEdge{edge_index}ShapeClosed"
            )
            theorem_name = (
                f"registerRelationChunk{chunk_index}CallReturnEdge{edge_index}ShapeChecked"
            )
            definitions.append(
                f"def {proposition_name} : Prop :=\n"
                "  InvariantWP.CallReturnEdgeShapeClosed "
                f"region{callee_index} region{continuation_index} "
                f"{original_caller} {candidate_caller} "
                f"{original_return} {candidate_return}"
            )
            definitions.append(
                f"theorem {theorem_name} : {proposition_name} := by\n"
                "  apply InvariantWP.callReturnEdgeShapeClosed_of_checked\n"
                "  decide"
            )
            theorem_names.append(theorem_name)
            proposition_names.append(proposition_name)
        for edge_index, edge in enumerate(return_slot_edges):
            source_index = int(edge["source_region_index"])
            original_name = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{source_index}"
            )
            candidate_name = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{source_index}"
            )
            for claim_index, claim in enumerate(edge["return_slot_transfer_claims"]):
                claim_name = (
                    f"registerRelationChunk{chunk_index}ReturnSlotEdge{edge_index}"
                    f"Claim{claim_index}"
                )
                proposition_name = f"{claim_name}Closed"
                theorem_name = f"{claim_name}Checked"
                definitions.append(
                    f"def {claim_name} : ReturnSlotTransferClaim := {{\n"
                    f"  source := {_lean_return_slot_offset_pair(claim['source'])}\n"
                    f"  target := {_lean_return_slot_offset_pair(claim['target'])}\n"
                    "  originalOutput := "
                    f"{_lean_register_offset_witness(claim['original_output_witness'])}\n"
                    "  candidateOutput := "
                    f"{_lean_register_offset_witness(claim['candidate_output_witness'])}\n"
                    "}"
                )
                definitions.append(
                    f"def {proposition_name} : Prop :=\n"
                    f"  ReturnSlotTransferClosed {original_name} {candidate_name} "
                    f"{claim_name}"
                )
                definitions.append(
                    f"theorem {theorem_name} : {proposition_name} := by\n"
                    "  apply returnSlotTransferClosed_of_checked\n"
                    "  decide"
                )
                theorem_names.append(theorem_name)
                proposition_names.append(proposition_name)
        transfer_rules_by_source: dict[int, dict[str, dict[str, Any]]] = {}
        for edge in return_slot_rule_edges:
            source_index = int(edge["source_region_index"])
            bucket = transfer_rules_by_source.setdefault(source_index, {})
            for rule in edge["return_slot_transfer_rules"]:
                bucket[json.dumps(rule, sort_keys=True)] = rule
        for source_index in selected:
            bucket = transfer_rules_by_source.setdefault(source_index, {})
            for rule in relation_by_region[source_index].get(
                "return_slot_return_transfer_rules", []
            ):
                bucket[json.dumps(rule, sort_keys=True)] = rule
        for source_index, rule_map in sorted(transfer_rules_by_source.items()):
            original_name = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{source_index}"
            )
            candidate_name = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{source_index}"
            )
            for rule_index, rule in enumerate(rule_map.values()):
                rule_name = (
                    f"registerRelationChunk{chunk_index}Region{source_index}"
                    f"ReturnSlotTransferRule{rule_index}"
                )
                proposition_name = f"{rule_name}Closed"
                theorem_name = f"{rule_name}Checked"
                definitions.append(
                    f"def {rule_name} : ReturnSlotTransferRule := {{\n"
                    f"  originalSourceRegister := .{rule['original_source_register']}\n"
                    f"  candidateSourceRegister := .{rule['candidate_source_register']}\n"
                    f"  originalTargetRegister := .{rule['original_target_register']}\n"
                    f"  candidateTargetRegister := .{rule['candidate_target_register']}\n"
                    "  originalOutput := "
                    f"{_lean_register_offset_witness(rule['original_output_witness'])}\n"
                    "  candidateOutput := "
                    f"{_lean_register_offset_witness(rule['candidate_output_witness'])}\n"
                    f"  originalDelta := BitVec.ofNat 32 {int(rule['original_delta'])}\n"
                    f"  candidateDelta := BitVec.ofNat 32 {int(rule['candidate_delta'])}\n"
                    "}"
                )
                definitions.append(
                    f"def {proposition_name} : Prop :=\n"
                    f"  ReturnSlotTransferRuleClosed {original_name} {candidate_name} "
                    f"{rule_name}"
                )
                definitions.append(
                    f"theorem {theorem_name} : {proposition_name} := by\n"
                    "  apply returnSlotTransferRuleClosed_of_checked\n"
                    "  decide"
                )
                theorem_names.append(theorem_name)
                proposition_names.append(proposition_name)
        for source_index in selected:
            row = relation_by_region[source_index]
            original_name = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{source_index}"
            )
            candidate_name = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{source_index}"
            )
            for claim_index, claim in enumerate(
                row.get("return_slot_return_transfer_claims", [])
            ):
                claim_name = (
                    f"registerRelationChunk{chunk_index}Region{source_index}"
                    f"ReturnSlotTransferClaim{claim_index}"
                )
                proposition_name = f"{claim_name}Closed"
                theorem_name = f"{claim_name}Checked"
                definitions.append(
                    f"def {claim_name} : ReturnSlotTransferClaim := {{\n"
                    f"  source := {_lean_return_slot_offset_pair(claim['source'])}\n"
                    f"  target := {_lean_return_slot_offset_pair(claim['target'])}\n"
                    "  originalOutput := "
                    f"{_lean_register_offset_witness(claim['original_output_witness'])}\n"
                    "  candidateOutput := "
                    f"{_lean_register_offset_witness(claim['candidate_output_witness'])}\n"
                    "}"
                )
                definitions.append(
                    f"def {proposition_name} : Prop :=\n"
                    f"  ReturnSlotTransferClosed {original_name} {candidate_name} "
                    f"{claim_name}"
                )
                definitions.append(
                    f"theorem {theorem_name} : {proposition_name} := by\n"
                    "  apply returnSlotTransferClosed_of_checked\n"
                    "  decide"
                )
                theorem_names.append(theorem_name)
                proposition_names.append(proposition_name)
        call_push_claim_by_source: dict[int, tuple[str, bool]] = {}
        for edge_index, edge in enumerate(call_push_edges):
            source_index = int(edge["source_region_index"])
            claim = edge["direct_call_push_claim"]
            original_name = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{source_index}"
            )
            candidate_name = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{source_index}"
            )
            claim_name = (
                f"registerRelationChunk{chunk_index}CallPushEdge{edge_index}Claim"
            )
            call_push_claim_by_source[source_index] = (claim_name, False)
            proposition_name = (
                f"registerRelationChunk{chunk_index}CallPushEdge{edge_index}Closed"
            )
            theorem_name = (
                f"registerRelationChunk{chunk_index}CallPushEdge{edge_index}Checked"
            )
            definitions.append(
                f"def {claim_name} : DirectCallPushClaim := {{\n"
                f"  calleeTargetId := {int(claim['callee_target_id'])}\n"
                f"  continuationTargetId := {int(claim['continuation_target_id'])}\n"
                f"  originalReturnAddress := {int(claim['original_return_address'])}\n"
                f"  candidateReturnAddress := {int(claim['candidate_return_address'])}\n"
                "  originalStackAddress := "
                f"{_lean_semantic_expr(claim['original_stack_address'])}\n"
                "  candidateStackAddress := "
                f"{_lean_semantic_expr(claim['candidate_stack_address'])}\n"
                "}"
            )
            definitions.append(
                f"def {proposition_name} : Prop :=\n"
                f"  DirectCallPushClosed staticProofContext {original_name} "
                f"{candidate_name} {claim_name}"
            )
            definitions.append(
                f"theorem {theorem_name} : {proposition_name} := by\n"
                "  apply directCallPushClosed_of_checked\n"
                "  decide"
            )
            theorem_names.append(theorem_name)
            proposition_names.append(proposition_name)
        for edge_index, edge in enumerate(indirect_call_push_edges):
            source_index = int(edge["source_region_index"])
            claim = edge["indirect_call_push_claim"]
            original_name = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{source_index}"
            )
            candidate_name = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{source_index}"
            )
            claim_name = (
                f"registerRelationChunk{chunk_index}IndirectCallPushEdge{edge_index}Claim"
            )
            call_push_claim_by_source[source_index] = (claim_name, True)
            proposition_name = (
                f"registerRelationChunk{chunk_index}IndirectCallPushEdge{edge_index}Closed"
            )
            theorem_name = (
                f"registerRelationChunk{chunk_index}IndirectCallPushEdge{edge_index}Checked"
            )
            definitions.append(
                f"def {claim_name} : IndirectCallPushClaim := {{\n"
                f"  continuationTargetId := {int(claim['continuation_target_id'])}\n"
                f"  originalReturnAddress := {int(claim['original_return_address'])}\n"
                f"  candidateReturnAddress := {int(claim['candidate_return_address'])}\n"
                "  originalStackAddress := "
                f"{_lean_semantic_expr(claim['original_stack_address'])}\n"
                "  candidateStackAddress := "
                f"{_lean_semantic_expr(claim['candidate_stack_address'])}\n"
                "}"
            )
            definitions.append(
                f"def {proposition_name} : Prop :=\n"
                f"  IndirectCallPushClosed staticProofContext {original_name} "
                f"{candidate_name} {claim_name}"
            )
            definitions.append(
                f"theorem {theorem_name} : {proposition_name} := by\n"
                "  apply indirectCallPushClosed_of_checked\n"
                "  decide"
            )
            theorem_names.append(theorem_name)
            proposition_names.append(proposition_name)
        for edge_index, edge in enumerate(call_summary_edges):
            source_index = int(edge["source_region_index"])
            original_call = (
                f"registerRelationChunk{chunk_index}OriginalBehavior{source_index}"
            )
            candidate_call = (
                f"registerRelationChunk{chunk_index}CandidateBehavior{source_index}"
            )
            call_claim_name, indirect_call = call_push_claim_by_source[source_index]
            summary_proposition = (
                "IndirectReturnSlotCallSummaryClosed"
                if indirect_call else "ReturnSlotCallSummaryClosed"
            )
            summary_theorem = (
                "indirectReturnSlotCallSummaryClosed_of_checked"
                if indirect_call else "returnSlotCallSummaryClosed_of_checked"
            )
            for claim_index, claim in enumerate(
                edge["return_slot_call_summary_claims"]
            ):
                return_index = int(claim["return_region_index"])
                original_return = (
                    f"registerRelationChunk{chunk_index}OriginalBehavior{return_index}"
                )
                candidate_return = (
                    f"registerRelationChunk{chunk_index}CandidateBehavior{return_index}"
                )
                claim_name = (
                    f"registerRelationChunk{chunk_index}CallSummaryEdge{edge_index}"
                    f"Claim{claim_index}"
                )
                proposition_name = f"{claim_name}Closed"
                theorem_name = f"{claim_name}Checked"
                definitions.append(
                    f"def {claim_name} : ReturnSlotCallSummaryClaim := {{\n"
                    f"  source := {_lean_return_slot_offset_pair(claim['source'])}\n"
                    f"  target := {_lean_return_slot_offset_pair(claim['target'])}\n"
                    "  originalCallEsp := "
                    f"{_lean_register_offset_witness(claim['original_call_witness'])}\n"
                    "  candidateCallEsp := "
                    f"{_lean_register_offset_witness(claim['candidate_call_witness'])}\n"
                    "  originalReturnSlot := "
                    f"{_lean_register_offset_witness(claim['original_return_slot_witness'])}\n"
                    "  candidateReturnSlot := "
                    f"{_lean_register_offset_witness(claim['candidate_return_slot_witness'])}\n"
                    "  originalReturnOutput := "
                    f"{_lean_register_offset_witness(claim['original_return_output_witness'])}\n"
                    "  candidateReturnOutput := "
                    f"{_lean_register_offset_witness(claim['candidate_return_output_witness'])}\n"
                    f"  popBytes := {int(claim['pop_bytes'])}\n"
                    "}"
                )
                definitions.append(
                    f"def {proposition_name} : Prop :=\n"
                    f"  {summary_proposition} "
                    f"{original_call} {candidate_call} {original_return} "
                    f"{candidate_return} {call_claim_name} {claim_name}"
                )
                definitions.append(
                    f"theorem {theorem_name} : {proposition_name} := by\n"
                    f"  apply {summary_theorem}\n"
                    "  decide"
                )
                theorem_names.append(theorem_name)
                proposition_names.append(proposition_name)
        claims_name = f"registerRelationChunk{chunk_index}Claims"
        checked_name = f"registerRelationChunk{chunk_index}Checked"
        definitions.append(
            f"def {claims_name} : List Prop := [{', '.join(proposition_names)}]"
        )
        proof = (
            "".join(f"And.intro {name} (" for name in theorem_names)
            + "True.intro"
            + ")" * len(theorem_names)
        )
        definitions.append(
            f"theorem {checked_name} : AllInvariantClaims {claims_name} := by\n"
            f"  exact {proof}"
        )
        module = f"RelationalRegisterRelationsChunk{chunk_index}"
        source = (
            "import StageA.RelationalComposition\n"
            "import StageA.RelationalEnvironment\n"
            "import StageA.RelationalGlobalMappingContext\n"
            "import StageA.RelationalStaticContextBase\n"
            + imports
            + "\n\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)
        modules.append({
            "module": module,
            "claims": claims_name,
            "theorem": checked_name,
            "regions": str(len(selected)),
            "exact_output_claims": str(sum(
                len(relation_by_region[index]["exact_output_claims"])
                for index in selected
            )),
            "output_claims": str(sum(
                len(relation_by_region[index]["output_claims"])
                for index in selected
            )),
            "fully_exact_edges": str(len(exact_edges)),
            "exact_pair_edge_claims": str(sum(
                len(edge["exact_output_pair_claims"]) for edge in pair_edges
            )),
            "environment_policy_edges": str(len(environment_edges)),
            "call_return_shape_edges": str(len(call_return_edges)),
            "direct_call_push_edges": str(len(call_push_edges)),
            "return_slot_transfer_claims": str(sum(
                len(edge["return_slot_transfer_claims"])
                for edge in return_slot_edges
            )),
            "return_slot_transfer_rules": str(sum(
                len(rules) for rules in transfer_rules_by_source.values()
            )),
            "return_slot_return_transfer_claims": str(sum(
                len(relation_by_region[index].get(
                    "return_slot_return_transfer_claims", []
                ))
                for index in selected
            )),
            "return_slot_call_summary_claims": str(sum(
                len(edge["return_slot_call_summary_claims"])
                for edge in call_summary_edges
            )),
            "return_pop_regions": str(sum(
                relation_by_region[index].get("return_pop_claim") is not None
                for index in selected
            )),
        })
    return modules

def _external_register_policy_replay_candidate(
    contract: dict[str, Any], edge: dict[str, Any],
) -> bool:
    if not edge.get("environment_barrier"):
        return False
    # Register-indirect imports remain indirect calls in the normalized IR.
    # Their transition belongs to the import/environment refinement proof, not
    # the direct external-call register-policy checker.
    if edge.get("indirect_target_profile"):
        return False
    if edge.get("machine_contract_id") is None:
        return False
    target = contract["regions"][int(edge["target_region_index"])]
    return not target.get("input_import_relations")

def _write_relational_segment_refinement_modules(
    lean_dir: Path,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    memory_contracts: dict[str, Any],
    register_relations: dict[str, Any],
    product_graph: dict[str, Any],
    decode_chunk_regions: list[list[int]],
    import_register_seeds: list[dict[str, Any]],
    segment_candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates = segment_candidates
    chunk_by_region = {
        region_index: chunk_index
        for chunk_index, region_indices in enumerate(decode_chunk_regions)
        for region_index in region_indices
    }
    product_proof_chunk_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_PRODUCT_PROOF_CHUNK", "16"))
    )
    decoded_control_chunk_by_node = {
        int(candidate["node_id"]): candidate_index // product_proof_chunk_size
        for candidate_index, candidate in enumerate(
            product_graph["evidence"]["decoded_control_candidates"]
        )
    }
    grouped: dict[tuple[int, int | None], list[dict[str, Any]]] = {}
    for candidate in candidates:
        source_chunk = chunk_by_region[int(candidate["source_region_index"])]
        isolated_edge = (
            int(candidate["edge_index"])
            if candidate.get("certificate_profile")
            == "composable_register_zero_guard_contradiction_v1"
            else None
        )
        grouped.setdefault((source_chunk, isolated_edge), []).append(candidate)
    modules: list[dict[str, Any]] = []
    for (chunk_index, isolated_edge), selected in sorted(
        grouped.items(),
        key=lambda item: (
            item[0][0],
            item[0][1] is not None,
            item[0][1] or -1,
        ),
    ):
        definitions: list[str] = []
        proposition_names: list[str] = []
        theorem_names: list[str] = []
        for candidate in selected:
            edge_index = int(candidate["edge_index"])
            source_index = int(candidate["source_region_index"])
            target_index = int(candidate["target_region_index"])
            source_target_id = int(candidate["source_target_id"])
            target_id = int(candidate["target_id"])
            prefix = f"segmentRefinementEdge{edge_index}"
            edge_name = f"{prefix}Spec"
            local_code_targets_name = f"{prefix}LocalCodeTargetsResolved"
            local_values_name = f"{prefix}LocalValuesResolved"
            code_map_name = f"{prefix}CodeMapExact"
            data_map_name = f"{prefix}DataMapExact"
            inputs_name = f"{prefix}InputRelationsExact"
            shape_name = f"{prefix}ShapeChecked"
            registers_name = f"{prefix}RegisterTransferChecked"
            transition_name = f"{prefix}TransitionChecked"
            proposition_name = f"{prefix}Closed"
            theorem_name = f"{prefix}Checked"
            if candidate["certificate_profile"] == (
                "composable_register_zero_guard_contradiction_v1"
            ):
                raw_claim = candidate.get(
                    "register_zero_guard_contradiction_claim"
                )
                if not isinstance(raw_claim, dict) or raw_claim.get(
                    "profile"
                ) != "register_zero_guard_contradiction_v1":
                    raise StageAInputError(
                        "register-zero guard contradiction segment lacks its claim"
                    )
                original_register = raw_claim.get("original_register")
                candidate_register = raw_claim.get("candidate_register")
                if (
                    original_register not in REGISTERS
                    or candidate_register not in REGISTERS
                ):
                    raise StageAInputError(
                        "register-zero guard contradiction claim has an invalid register"
                    )
                claim_name = f"{prefix}RegisterZeroGuardContradictionClaim"
                claim_checked_name = f"{claim_name}Checked"
                definitions.extend([
                    (
                        f"def {edge_name} : RelationalSegmentEdge := {{\n"
                        f"  sourceTargetId := {source_target_id}\n"
                        f"  exit := .internal {target_id}\n"
                        f"  originalSpan := region{source_index}.original\n"
                        f"  candidateSpan := region{source_index}.candidate\n"
                        "  localCodeTargetIds := ["
                        + ", ".join(
                            str(item)
                            for item in candidate["local_code_target_ids"]
                        )
                        + "]\n  localValueTargetIds := ["
                        + ", ".join(
                            str(item)
                            for item in candidate["local_value_target_ids"]
                        )
                        + "]\n"
                        f"  originalGuard := {_lean_semantic_bool_expr(candidate['original_guard'])}\n"
                        f"  candidateGuard := {_lean_semantic_bool_expr(candidate['candidate_guard'])}\n"
                        "}"
                    ),
                    (
                        f"theorem {local_code_targets_name} :\n"
                        f"    staticProofContext.codeMap.resolveIds "
                        f"{edge_name}.localCodeTargetIds = "
                        f"some region{source_index}.targets := by decide"
                    ),
                    (
                        f"theorem {local_values_name} :\n"
                        f"    staticProofContext.dataMap.resolveIds "
                        f"{edge_name}.localValueTargetIds = "
                        f"some region{source_index}.values := by decide"
                    ),
                    (
                        f"def {claim_name} : RegisterZeroGuardContradictionClaim := {{\n"
                        f"  originalRegister := .{original_register}\n"
                        f"  candidateRegister := .{candidate_register}\n"
                        "}"
                    ),
                    (
                        f"theorem {claim_checked_name} :\n"
                        f"    {claim_name}.checked {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant = true := by decide"
                    ),
                    (
                        f"theorem {transition_name} :\n"
                        f"    SegmentTransitionClosed staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} :=\n"
                        "  segmentTransitionClosed_of_register_zero_guard_contradiction\n"
                        f"    staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"    originalBehavior{source_index} "
                        f"candidateBehavior{source_index} {claim_name}\n"
                        f"    region{source_index}.targets region{source_index}.values\n"
                        f"    {local_code_targets_name} {local_values_name} "
                        f"{claim_checked_name}"
                    ),
                    (
                        f"def {proposition_name} : Prop :=\n"
                        f"  RelationalSegmentRefinement staticProofContext "
                        f"{edge_name} region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant"
                    ),
                    (
                        f"theorem {theorem_name} : {proposition_name} :=\n"
                        "  relationalSegmentRefinement_of_decoded "
                        f"staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"    originalBehavior{source_index} "
                        f"candidateBehavior{source_index}\n"
                        f"    originalBehavior{source_index}CheckedDecoded "
                        f"candidateBehavior{source_index}CheckedDecoded "
                        f"{transition_name}"
                    ),
                ])
                proposition_names.append(proposition_name)
                theorem_names.append(theorem_name)
                continue
            if candidate["certificate_profile"] in {
                "composable_local_no_write_v1", "composable_direct_call_v1",
                "composable_known_indirect_call_v1",
                "composable_direct_call_prepared_writes_v1",
                "composable_direct_call_stack_writes_v1",
                "composable_immutable_indirect_jump_v1",
                "composable_fixed_code_address_indirect_jump_v1",
                "composable_paired_stack_word_write_v1",
                "composable_paired_stack_word_writes_v1",
                "composable_paired_prepared_word_writes_v1",
                "composable_reverse_sentinel_scanner_v1",
                "composable_reverse_sentinel_scanner_loop_v1",
                "composable_reverse_sentinel_scanner_exit_v1",
            }:
                direct_call = (
                    candidate["certificate_profile"] == "composable_direct_call_v1"
                )
                known_indirect_call = candidate["certificate_profile"] in {
                    "composable_known_indirect_call_v1",
                }
                direct_call_stack_writes = (
                    candidate["certificate_profile"] in {
                        "composable_direct_call_stack_writes_v1",
                    }
                )
                direct_call_prepared_writes = (
                    candidate["certificate_profile"] in {
                        "composable_direct_call_prepared_writes_v1",
                    }
                )
                paired_stack_write = (
                    candidate["certificate_profile"]
                    == "composable_paired_stack_word_write_v1"
                )
                paired_stack_writes = (
                    candidate["certificate_profile"]
                    == "composable_paired_stack_word_writes_v1"
                )
                paired_prepared_writes = (
                    candidate["certificate_profile"]
                    == "composable_paired_prepared_word_writes_v1"
                )
                immutable_indirect_jump = (
                    candidate["certificate_profile"] ==
                    "composable_immutable_indirect_jump_v1"
                )
                fixed_code_address_indirect_jump = (
                    candidate["certificate_profile"] ==
                    "composable_fixed_code_address_indirect_jump_v1"
                )
                reverse_sentinel_scanner_body = (
                    candidate["certificate_profile"] ==
                    "composable_reverse_sentinel_scanner_v1"
                )
                reverse_sentinel_scanner_loop = (
                    candidate["certificate_profile"] ==
                    "composable_reverse_sentinel_scanner_loop_v1"
                )
                reverse_sentinel_scanner_exit = (
                    candidate["certificate_profile"] ==
                    "composable_reverse_sentinel_scanner_exit_v1"
                )
                reverse_sentinel_scanner = (
                    reverse_sentinel_scanner_body
                    or reverse_sentinel_scanner_loop
                    or reverse_sentinel_scanner_exit
                )
                normalized_behavior_definitions: list[str] = []
                normalized_fast_path = _normalized_behavior_fast_path(
                    contract["regions"][source_index], behaviors[source_index]
                )
                if (
                    immutable_indirect_jump
                    or fixed_code_address_indirect_jump
                    or known_indirect_call
                ):
                    original_normalized_behavior = (
                        f"productNode{source_index}OriginalNormalized"
                    )
                    candidate_normalized_behavior = (
                        f"productNode{source_index}CandidateNormalized"
                    )
                    original_normalized_checked = (
                        f"productNode{source_index}OriginalNormalizedChecked"
                    )
                    candidate_normalized_checked = (
                        f"productNode{source_index}CandidateNormalizedChecked"
                    )
                    normalized_x87_rewrites = (
                        f"productNode{source_index}OriginalNormalizedX87, "
                        f"productNode{source_index}CandidateNormalizedX87"
                    )
                    normalized_register_rewrites = ""
                    normalized_shape_rewrites = (
                        f"productNode{source_index}OriginalNormalizedWrites, "
                        f"productNode{source_index}CandidateNormalizedWrites"
                        if known_indirect_call else ""
                    )
                elif normalized_fast_path:
                    original_normalized_behavior = (
                        f"region{source_index}NormalizedBehavior"
                    )
                    candidate_normalized_behavior = original_normalized_behavior
                    original_normalized_checked = (
                        f"region{source_index}OriginalNormalized"
                    )
                    candidate_normalized_checked = (
                        f"region{source_index}CandidateNormalized"
                    )
                    normalized_x87_rewrites = (
                        f"region{source_index}NormalizedX87"
                    )
                    normalized_register_rewrites = (
                        f"region{source_index}NormalizedRegisters"
                    )
                    normalized_shape_rewrites = (
                        f"region{source_index}NormalizedWrites, "
                        f"region{source_index}NormalizedOutcome"
                    )
                else:
                    original_normalized_behavior = (
                        f"{prefix}OriginalNormalizedBehavior"
                    )
                    candidate_normalized_behavior = (
                        f"{prefix}CandidateNormalizedBehavior"
                    )
                    original_normalized_checked = (
                        f"{prefix}OriginalNormalizedChecked"
                    )
                    candidate_normalized_checked = (
                        f"{prefix}CandidateNormalizedChecked"
                    )
                    original_normalized_x87 = (
                        f"{prefix}OriginalNormalizedX87"
                    )
                    candidate_normalized_x87 = (
                        f"{prefix}CandidateNormalizedX87"
                    )
                    original_normalized_registers = (
                        f"{prefix}OriginalNormalizedRegisters"
                    )
                    candidate_normalized_registers = (
                        f"{prefix}CandidateNormalizedRegisters"
                    )
                    original_normalized_writes = (
                        f"{prefix}OriginalNormalizedWrites"
                    )
                    candidate_normalized_writes = (
                        f"{prefix}CandidateNormalizedWrites"
                    )
                    original_normalized_outcome = (
                        f"{prefix}OriginalNormalizedOutcome"
                    )
                    candidate_normalized_outcome = (
                        f"{prefix}CandidateNormalizedOutcome"
                    )
                    normalized_x87_rewrites = (
                        f"{original_normalized_x87}, {candidate_normalized_x87}"
                    )
                    normalized_register_rewrites = (
                        f"{original_normalized_registers}, "
                        f"{candidate_normalized_registers}"
                    )
                    normalized_shape_rewrites = (
                        f"{original_normalized_writes}, "
                        f"{candidate_normalized_writes}, "
                        f"{original_normalized_outcome}, "
                        f"{candidate_normalized_outcome}"
                    )
                    original_outcome = _lean_acceptance_outcome(
                        behaviors[source_index]["original_ir"]["outcome"]
                    )
                    candidate_outcome = _lean_acceptance_outcome(
                        behaviors[source_index]["candidate_ir"]["outcome"]
                    )
                    normalized_behavior_definitions.extend([
                        (
                            f"def {original_normalized_behavior} : "
                            "NormalizedSymbolicBehavior :=\n"
                            f"  (normalizeSymbolicBehavior false "
                            f"region{source_index}.targets "
                            f"originalBehavior{source_index}).get (by decide)"
                        ),
                        (
                            f"def {candidate_normalized_behavior} : "
                            "NormalizedSymbolicBehavior :=\n"
                            f"  (normalizeSymbolicBehavior true "
                            f"region{source_index}.targets "
                            f"candidateBehavior{source_index}).get (by decide)"
                        ),
                        (
                            f"theorem {original_normalized_checked} :\n"
                            f"    normalizeSymbolicBehavior false "
                            f"region{source_index}.targets "
                            f"originalBehavior{source_index} = "
                            f"some {original_normalized_behavior} := by decide"
                        ),
                        (
                            f"theorem {candidate_normalized_checked} :\n"
                            f"    normalizeSymbolicBehavior true "
                            f"region{source_index}.targets "
                            f"candidateBehavior{source_index} = "
                            f"some {candidate_normalized_behavior} := by decide"
                        ),
                        (
                            f"theorem {original_normalized_x87} : "
                            f"{original_normalized_behavior}.x87 = "
                            f"originalBehavior{source_index}.x87 := by decide"
                        ),
                        (
                            f"theorem {candidate_normalized_x87} : "
                            f"{candidate_normalized_behavior}.x87 = "
                            f"candidateBehavior{source_index}.x87 := by decide"
                        ),
                        (
                            f"theorem {original_normalized_registers} : "
                            f"{original_normalized_behavior}.registers = "
                            f"originalBehavior{source_index}.registers := by decide"
                        ),
                        (
                            f"theorem {candidate_normalized_registers} : "
                            f"{candidate_normalized_behavior}.registers = "
                            f"candidateBehavior{source_index}.registers := by decide"
                        ),
                        (
                            f"theorem {original_normalized_writes} : "
                            f"{original_normalized_behavior}.writes = "
                            f"originalBehavior{source_index}.writes := by decide"
                        ),
                        (
                            f"theorem {candidate_normalized_writes} : "
                            f"{candidate_normalized_behavior}.writes = "
                            f"candidateBehavior{source_index}.writes := by decide"
                        ),
                        (
                            f"theorem {original_normalized_outcome} : "
                            f"{original_normalized_behavior}.outcome = "
                            f"{original_outcome} := by decide"
                        ),
                        (
                            f"theorem {candidate_normalized_outcome} : "
                            f"{candidate_normalized_behavior}.outcome = "
                            f"{candidate_outcome} := by decide"
                        ),
                    ])
                composition_name = f"{prefix}RegisterCompositionChecked"
                state_name = f"{prefix}StateTransferChecked"
                import_transfer_name = f"{prefix}ImportTransferChecked"
                dynamic_transfer_name = f"{prefix}DynamicTransferChecked"
                guard_claim_name = f"{prefix}GuardClaim"
                scanner_claim_name = f"{prefix}ReverseSentinelScannerClaim"
                scanner_claim_checked_name = (
                    f"{prefix}ReverseSentinelScannerClaimChecked"
                )
                scanner_claim_definitions: list[str] = []
                if reverse_sentinel_scanner:
                    scanner_claim = candidate.get(
                        "reverse_sentinel_scanner_claim"
                    )
                    if not isinstance(scanner_claim, dict):
                        raise StageAInputError(
                            "reverse-sentinel scanner segment lacks its checked claim"
                        )
                    scanner_checked_operation = (
                        "checked" if reverse_sentinel_scanner_body
                        else "loopChecked" if reverse_sentinel_scanner_loop
                        else "exitChecked"
                    )
                    scanner_checked_head = (
                        f"{scanner_claim_name}.{scanner_checked_operation} "
                        + ("staticProofContext " if reverse_sentinel_scanner_body else "")
                    )
                    scanner_claim_definitions.extend([
                        (
                            f"def {scanner_claim_name} : ReverseSentinelScannerClaim := "
                            + _lean_reverse_sentinel_scanner_claim(scanner_claim)
                        ),
                        (
                            f"theorem {scanner_claim_checked_name} :\n"
                            f"    {scanner_checked_head}region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"      {original_normalized_behavior} "
                            f"{candidate_normalized_behavior} = true := by decide"
                        ),
                    ])
                import_claim_definitions: list[str] = []
                import_transfer_facts: list[str] = []
                import_fact_names: list[str] = []
                for claim_index, claim in enumerate(
                    candidate.get("import_transfer_claims", [])
                ):
                    claim_name = f"{prefix}ImportClaim{claim_index}"
                    fact_name = f"{prefix}ImportFact{claim_index}"
                    import_fact_names.append(fact_name)
                    if claim["kind"] == "seed":
                        import_claim_definitions.append(
                            f"def {claim_name} : ImportRegisterSeedClaim := "
                            + _lean_import_register_seed_claim(claim)
                        )
                        import_transfer_facts.append(
                            f"  have {fact_name} := importRegisterSeedOutputHolds_of_checked\n"
                            f"    staticProofContext world region{source_index}.inputInvariant\n"
                            f"    {original_normalized_behavior} "
                            f"{candidate_normalized_behavior} {claim_name} (by decide)\n"
                            "    originalState candidateState related"
                        )
                    else:
                        import_claim_definitions.append(
                            f"def {claim_name} : ImportRegisterPreserveClaim := {{\n"
                            f"  imported := {_lean_external_target(claim['import'])}\n"
                            f"  sourceOriginalRegister := .{claim['source_original_register']}\n"
                            f"  sourceCandidateRegister := .{claim['source_candidate_register']}\n"
                            f"  targetOriginalRegister := .{claim['target_original_register']}\n"
                            f"  targetCandidateRegister := .{claim['target_candidate_register']}\n"
                            "}"
                        )
                        import_transfer_facts.append(
                            f"  have {fact_name} := importRegisterPreserveOutputHolds_of_checked\n"
                            f"    staticProofContext world region{source_index}.inputInvariant\n"
                            f"    region{target_index}.inputInvariant "
                            f"{original_normalized_behavior}\n"
                            f"    {candidate_normalized_behavior} {claim_name} (by decide)\n"
                            "    originalState candidateState related"
                        )
                dynamic_claim_definitions: list[str] = []
                dynamic_transfer_facts: list[str] = []
                dynamic_fact_names: list[str] = []
                for claim_index, claim in enumerate(
                    candidate.get("dynamic_transfer_claims", [])
                ):
                    claim_name = f"{prefix}DynamicClaim{claim_index}"
                    fact_name = f"{prefix}DynamicFact{claim_index}"
                    dynamic_fact_names.append(fact_name)
                    if claim["kind"] == "nullable_pointer":
                        dynamic_claim_definitions.append(
                            f"def {claim_name} : DynamicRegisterRangeNextClaim := {{\n"
                            f"  sourceRelation := "
                            f"{_lean_dynamic_range_relation(claim['source_relation'])}\n"
                            f"  targetRelation := "
                            f"{_lean_dynamic_range_relation(claim['target_relation'])}\n"
                            f"  pointerOffset := {int(claim['pointer_offset'])}\n"
                            "}"
                        )
                        dynamic_transfer_facts.append(
                            f"  have {fact_name} := "
                            "dynamicRegisterRangeNextOutputActiveHolds_of_checked\n"
                            f"    staticProofContext world region{source_index}.inputInvariant\n"
                            f"    region{target_index}.inputInvariant "
                            f"{original_normalized_behavior}\n"
                            f"    {candidate_normalized_behavior} "
                            f"{edge_name}.originalGuard {edge_name}.candidateGuard\n"
                            f"    {claim_name} (by decide) originalState candidateState "
                            "related guardTrue"
                        )
                    elif claim["kind"] == "stack_reload":
                        dynamic_claim_definitions.append(
                            f"def {claim_name} : DynamicStackRangeReloadClaim := {{\n"
                            f"  sourceRelation := "
                            f"{_lean_dynamic_stack_range_relation(claim['source_relation'])}\n"
                            f"  targetRelation := "
                            f"{_lean_dynamic_range_relation(claim['target_relation'])}\n"
                            "}"
                        )
                        dynamic_transfer_facts.append(
                            f"  have {fact_name} := "
                            "dynamicStackRangeReloadOutputActiveHolds_of_checked\n"
                            f"    staticProofContext world region{source_index}.inputInvariant\n"
                            f"    region{target_index}.inputInvariant "
                            f"{original_normalized_behavior}\n"
                            f"    {candidate_normalized_behavior} "
                            f"{claim_name} (by decide) (by decide) (by decide) "
                            "originalState candidateState related"
                        )
                    elif claim["kind"] == "static_pointer_seed":
                        dynamic_claim_definitions.append(
                            f"def {claim_name} : StaticDynamicPointerSeedClaim := {{\n"
                            f"  slot := {_lean_static_dynamic_pointer_slot(claim['slot'])}\n"
                            f"  targetRelation := "
                            f"{_lean_dynamic_range_relation(claim['target_relation'])}\n"
                            "}"
                        )
                        dynamic_transfer_facts.append(
                            f"  have {fact_name} := "
                            "staticDynamicPointerSeedOutputActiveHolds_of_checked\n"
                            f"    staticProofContext world region{source_index}.inputInvariant\n"
                            f"    region{target_index}.inputInvariant "
                            f"{original_normalized_behavior}\n"
                            f"    {candidate_normalized_behavior} "
                            f"{edge_name}.originalGuard {edge_name}.candidateGuard\n"
                            f"    {claim_name} (by decide) originalState candidateState "
                            "related guardTrue"
                        )
                    elif claim["kind"] == "prepared_preserve":
                        dynamic_claim_definitions.append(
                            f"def {claim_name} : DynamicRegisterRangePreserveClaim := {{\n"
                            f"  sourceRelation := "
                            f"{_lean_dynamic_range_relation(claim['source_relation'])}\n"
                            f"  targetRelation := "
                            f"{_lean_dynamic_range_relation(claim['target_relation'])}\n"
                            "}"
                        )
                        dynamic_transfer_facts.append(
                            f"  have {fact_name} := "
                            "dynamicRegisterRangePreparedPreserveOutputActiveHolds_of_checked\n"
                            f"    staticProofContext world region{source_index}.inputInvariant\n"
                            f"    region{target_index}.inputInvariant "
                            f"{prefix}PairedPreparedWritesClaim\n"
                            f"    {original_normalized_behavior} "
                            f"{candidate_normalized_behavior} {claim_name}\n"
                            "    staticProofContextChecked (by decide) (by decide) "
                            "(by decide) (by decide)\n"
                            "    originalState candidateState related"
                        )
                    elif claim["kind"] == "activate":
                        dynamic_claim_definitions.append(
                            f"def {claim_name} : DynamicRegisterRangeActivateClaim := {{\n"
                            f"  sourceRelation := "
                            f"{_lean_dynamic_range_relation(claim['source_relation'])}\n"
                            f"  targetRelation := "
                            f"{_lean_dynamic_range_relation(claim['target_relation'])}\n"
                            "  relation := { offset := "
                            f"{int(claim['relation']['offset'])}, kind := "
                            f".{claim['relation']['kind']} }}\n"
                            f"  originalAmount := {int(claim['original_amount'])}\n"
                            f"  candidateAmount := {int(claim['candidate_amount'])}\n"
                            f"  value := {_lean_paired_stack_word_value_claim(claim['value'])}\n"
                            "}"
                        )
                        dynamic_transfer_facts.append(
                            f"  have {fact_name} := "
                            "dynamicRegisterRangeActivateOutputActiveHolds_of_checked\n"
                            f"    staticProofContext world region{source_index}.inputInvariant\n"
                            f"    region{target_index}.inputInvariant "
                            f"{prefix}PairedPreparedWritesClaim\n"
                            f"    {original_normalized_behavior} "
                            f"{candidate_normalized_behavior} {claim_name} (by decide)\n"
                            "    originalState candidateState related"
                        )
                    else:
                        dynamic_claim_definitions.append(
                            f"def {claim_name} : DynamicRegisterRangePreserveClaim := {{\n"
                            f"  sourceRelation := "
                            f"{_lean_dynamic_range_relation(claim['source_relation'])}\n"
                            f"  targetRelation := "
                            f"{_lean_dynamic_range_relation(claim['target_relation'])}\n"
                            "}"
                        )
                        dynamic_transfer_facts.append(
                            f"  have {fact_name} := "
                            "dynamicRegisterRangePreserveOutputActiveHolds_of_checked\n"
                            f"    staticProofContext world region{source_index}.inputInvariant\n"
                            f"    region{target_index}.inputInvariant "
                            f"{original_normalized_behavior}\n"
                            f"    {candidate_normalized_behavior} {claim_name} (by decide)\n"
                            "    (by decide) (by decide) originalState candidateState related"
                        )
                guard_claim = candidate.get("guard_relation_claim")
                candidate_outcome_condition_name = (
                    f"region{source_index}OutcomeCondition"
                )
                candidate_outcome = behaviors[source_index]["candidate_ir"].get(
                    "outcome"
                ) or {}
                if guard_claim is not None and candidate_outcome.get("op") == "branch":
                    candidate_outcome_condition_name = (
                        f"{prefix}CandidateOutcomeCondition"
                    )
                    import_claim_definitions.append(
                        f"def {candidate_outcome_condition_name} : BoolExpr := "
                        f"{_lean_semantic_bool_expr(candidate_outcome['condition'])}"
                    )
                if (
                    guard_claim is not None
                    and guard_claim["profile"] == "related_word_zero_guard_v1"
                ):
                    import_claim_definitions.append(
                        f"def {guard_claim_name} : RelatedWordZeroGuardClaim := {{\n"
                        f"  originalRegister := .{guard_claim['original_register']}\n"
                        f"  candidateRegister := .{guard_claim['candidate_register']}\n"
                        f"  valueRelation := .{_lean_relation_constructor(guard_claim['value_relation'])}\n"
                        f"  notCount := {int(guard_claim['not_count'])}\n"
                        "}"
                    )
                if (
                    guard_claim is not None
                    and guard_claim["profile"] == "input_flags_guard_v1"
                ):
                    import_claim_definitions.append(
                        f"def {guard_claim_name} : InputFlagsGuardClaim := {{\n"
                        f"  guard := {_lean_semantic_bool_expr(guard_claim['guard'])}\n"
                        "}"
                    )
                if (
                    guard_claim is not None
                    and guard_claim["profile"] == "exact_pure_guard_v1"
                ):
                    import_claim_definitions.append(
                        f"def {guard_claim_name} : ExactPureGuardClaim := {{\n"
                        f"  guard := {_lean_semantic_bool_expr(guard_claim['guard'])}\n"
                        "}"
                    )
                if (
                    guard_claim is not None
                    and guard_claim["profile"] == "paired_exact_guard_v1"
                ):
                    import_claim_definitions.append(
                        f"def {guard_claim_name} : PairedExactGuardClaim := {{\n"
                        "  originalGuard := "
                        f"{_lean_semantic_bool_expr(guard_claim['original_guard'])}\n"
                        "  candidateGuard := "
                        f"{_lean_semantic_bool_expr(guard_claim['candidate_guard'])}\n"
                        "  witness := "
                        f"{_lean_paired_exact_expr_witness(guard_claim['witness'])}\n"
                        "}"
                    )
                if (
                    guard_claim is not None
                    and guard_claim["profile"] == "static_dynamic_pointer_guard_v1"
                ):
                    import_claim_definitions.append(
                        f"def {guard_claim_name} : StaticDynamicPointerGuardClaim := {{\n"
                        f"  slot := {_lean_static_dynamic_pointer_slot(guard_claim['slot'])}\n"
                        f"  kind := .{guard_claim['kind']}\n"
                        "}"
                    )
                if (
                    guard_claim is not None
                    and guard_claim["profile"] == "static_word_zero_guard_v1"
                ):
                    import_claim_definitions.append(
                        f"def {guard_claim_name} : StaticWordZeroGuardClaim := {{\n"
                        f"  slot := {_lean_static_word_relation_slot(guard_claim['slot'])}\n"
                        f"  originalAddress := {int(guard_claim['original_address'])}\n"
                        f"  candidateAddress := {int(guard_claim['candidate_address'])}\n"
                        f"  masked := {'true' if guard_claim['masked'] else 'false'}\n"
                        f"  notCount := {int(guard_claim['not_count'])}\n"
                        "}"
                    )
                if (
                    guard_claim is not None
                    and guard_claim["profile"] == "paired_stack_read_guard_v1"
                ):
                    import_claim_definitions.append(
                        f"def {guard_claim_name} : StackWordZeroGuardClaim := {{\n"
                        f"  window := {_lean_stack_window(guard_claim['window'])}\n"
                        f"  offset := {int(guard_claim['offset'])}\n"
                        f"  notCount := {int(guard_claim['not_count'])}\n"
                        "}"
                        )
                if (
                    guard_claim is not None
                    and guard_claim["profile"]
                        == "paired_stack_read_relative_guard_v1"
                ):
                    import_claim_definitions.append(
                        f"def {guard_claim_name} : StackWordZeroRelativeGuardClaim := {{\n"
                        f"  window := {_lean_stack_window(guard_claim['window'])}\n"
                        "  adjustment := "
                        f"{_lean_stack_adjustment(guard_claim['adjustment'])}\n"
                        "  originalAddress := "
                        f"{_lean_semantic_expr(guard_claim['original_address'])}\n"
                        "  candidateAddress := "
                        f"{_lean_semantic_expr(guard_claim['candidate_address'])}\n"
                        "  masked := "
                        f"{'true' if guard_claim['masked'] else 'false'}\n"
                        f"  notCount := {int(guard_claim['not_count'])}\n"
                        "}"
                    )
                if guard_claim is None:
                    guard_agreement_setup = ""
                elif guard_claim["profile"] == "related_word_zero_guard_v1":
                    guard_agreement_setup = (
                        "  have guardAgreement := "
                        "relatedWordZeroGuard_eval_equal_of_checked "
                        "staticProofContext world region"
                        f"{source_index}.inputInvariant {edge_name}.originalGuard "
                        f"{edge_name}.candidateGuard {guard_claim_name} (by decide) "
                        "originalState candidateState related\n"
                    )
                elif guard_claim["profile"] == "input_flags_guard_v1":
                    guard_agreement_setup = (
                        "  have guardAgreement := "
                        "inputFlagsGuard_eval_equal_of_checked\n"
                        f"    staticProofContext world region{source_index}.inputInvariant\n"
                        f"    {edge_name}.originalGuard {edge_name}.candidateGuard "
                        f"{guard_claim_name} (by decide)\n"
                        "    originalState candidateState related\n"
                    )
                elif guard_claim["profile"] == "exact_pure_guard_v1":
                    guard_agreement_setup = (
                        "  have guardAgreement := "
                        "exactPureGuard_eval_equal_of_checked\n"
                        f"    staticProofContext world region{source_index}.inputInvariant\n"
                        f"    {edge_name}.originalGuard {edge_name}.candidateGuard "
                        f"{guard_claim_name} (by decide)\n"
                        "    originalState candidateState related\n"
                    )
                elif guard_claim["profile"] == "paired_exact_guard_v1":
                    guard_agreement_setup = (
                        "  have guardAgreement := "
                        "pairedExactGuard_eval_equal_of_checked\n"
                        f"    staticProofContext world region{source_index}.inputInvariant\n"
                        f"    {edge_name}.originalGuard {edge_name}.candidateGuard "
                        f"{guard_claim_name} (by decide)\n"
                        "    originalState candidateState related\n"
                    )
                elif guard_claim["profile"] == "paired_stack_read_guard_v1":
                    guard_agreement_setup = (
                        "  have guardAgreement := "
                        "stackWordZeroGuard_eval_equal_of_checked\n"
                        f"    staticProofContext world region{source_index}.inputInvariant\n"
                        f"    {edge_name}.originalGuard {edge_name}.candidateGuard "
                        f"{guard_claim_name} (by decide)\n"
                        "    originalState candidateState related\n"
                    )
                elif (
                    guard_claim["profile"]
                    == "paired_stack_read_relative_guard_v1"
                ):
                    guard_agreement_setup = (
                        "  have guardAgreement := "
                        "stackWordZeroRelativeGuard_eval_equal_of_checked\n"
                        f"    staticProofContext world region{source_index}.inputInvariant\n"
                        f"    {edge_name}.originalGuard {edge_name}.candidateGuard "
                        f"{guard_claim_name} (by decide)\n"
                        "    originalState candidateState related\n"
                    )
                elif guard_claim["profile"] == "static_dynamic_pointer_guard_v1":
                    guard_agreement_setup = (
                        "  have guardAgreement := "
                        "staticDynamicPointerGuardsAgree_of_checked\n"
                        f"    staticProofContext world region{source_index}.inputInvariant\n"
                        f"    {edge_name}.originalGuard {edge_name}.candidateGuard "
                        f"{guard_claim_name} (by decide)\n"
                        "    originalState candidateState related\n"
                    )
                elif guard_claim["profile"] == "static_word_zero_guard_v1":
                    guard_agreement_setup = (
                        "  have guardAgreement := "
                        "staticWordZeroGuard_eval_equal_of_checked\n"
                        f"    staticProofContext world region{source_index}.inputInvariant\n"
                        f"    {edge_name}.originalGuard {edge_name}.candidateGuard "
                        f"{guard_claim_name} (by decide)\n"
                        "    originalState candidateState related\n"
                    )
                elif (
                    guard_claim["profile"]
                    == "reverse_sentinel_scanner_guard_v1"
                ):
                    guard_agreement_setup = (
                        "  have guardAgreement := "
                        "reverseSentinelScannerGuardsAgree_of_checked\n"
                        f"    staticProofContext region{source_index}.inputInvariant\n"
                        f"    {edge_name}.originalGuard {edge_name}.candidateGuard "
                        f"{scanner_claim_name} (by decide)\n"
                        "    world originalState candidateState related\n"
                    )
                else:
                    dynamic_guard_claim_name = (
                        f"{prefix}DynamicClaim{int(guard_claim['claim_index'])}"
                    )
                    guard_agreement_setup = (
                        "  have guardAgreement := "
                        "dynamicRegisterRangeNextGuardsAgree_of_checked\n"
                        f"    staticProofContext world region{source_index}.inputInvariant\n"
                        f"    region{target_index}.inputInvariant "
                        f"{original_normalized_behavior}\n"
                        f"    {candidate_normalized_behavior} "
                        f"{edge_name}.originalGuard {edge_name}.candidateGuard\n"
                        f"    {dynamic_guard_claim_name} (by decide) originalState "
                        "candidateState related\n"
                    )
                guard_expected = (
                    "true" if candidate.get("original_guard") is not None
                    and candidate.get("guard_relation_claim") is not None
                    and register_relations["edges"][edge_index].get("kind")
                        == "branch_taken"
                    else "false"
                )
                if guard_claim is None:
                    guard_shape_setup = (
                        "  refine ⟨rfl, ?_⟩\n"
                        "  intro guard\n"
                    )
                    guard_shape_finish = ""
                else:
                    guard_shape_setup = (
                        guard_agreement_setup
                        + "  refine ⟨guardAgreement, ?_⟩\n"
                        "  intro guard\n"
                        "  have candidateGuard : "
                        f"{edge_name}.candidateGuard.eval candidateState = true := by\n"
                        "    rw [← guardAgreement]\n"
                        "    exact guard\n"
                        "  have originalCondition : "
                        f"region{source_index}OutcomeCondition.eval originalState = "
                        f"{guard_expected} := by\n"
                        "    exact normalizedBranchCondition_eval_of_guard_true "
                        f"region{source_index}OutcomeCondition {edge_name}.originalGuard "
                        f"{guard_expected} originalState (by decide) guard\n"
                        "  have candidateCondition : "
                        f"{candidate_outcome_condition_name}.eval candidateState = "
                        f"{guard_expected} := by\n"
                        "    exact normalizedBranchCondition_eval_of_guard_true "
                        f"{candidate_outcome_condition_name} {edge_name}.candidateGuard "
                        f"{guard_expected} candidateState (by decide) candidateGuard\n"
                    )
                    guard_shape_finish = (
                        "\n  exact ⟨originalCondition, candidateCondition, "
                        "originalCondition.trans candidateCondition.symm⟩"
                    )
                flag_bits = contract["regions"][target_index].get(
                    "flag_inputs", list(FLAG_BITS)
                )
                if flag_bits == []:
                    flag_proof = "  · rfl"
                else:
                    flag_claim = candidate.get("flag_transfer_claim") or {}
                    scanner_flags = (
                        reverse_sentinel_scanner_body
                        and flag_claim.get("profile")
                            == "reverse_sentinel_scanner_flags_v1"
                    )
                    if (
                        flag_claim.get("profile") != "preserved_input_flags_v1"
                        and not scanner_flags
                    ):
                        raise ValueError(
                            "nonempty target flags require a checked transfer claim"
                        )
                    flag_theorems = {
                        0: "evalNormalizedFlags_extract_cf_input_of_checked",
                        2: "evalNormalizedFlags_extract_pf_input_of_checked",
                        6: "evalNormalizedFlags_extract_zf_input_of_checked",
                        7: "evalNormalizedFlags_extract_sf_input_of_checked",
                        11: "evalNormalizedFlags_extract_of_input_of_checked",
                    }
                    proof_lines = ["  · apply flagsRelated_cons_of_eq"]
                    for bit_index, bit in enumerate(flag_bits):
                        indent = " " * (4 + 2 * bit_index)
                        proof_lines.append(
                            f"{indent}· simp only "
                            "[NormalizedSymbolicBehavior.eval_eflags]"
                        )
                        if scanner_flags and bit == 6:
                            proof_lines.append(
                                f"{indent}  exact "
                                "reverseSentinelScannerZeroFlagRelated_of_checked\n"
                                f"{indent}    staticProofContext "
                                f"region{source_index}.inputInvariant "
                                f"region{target_index}.inputInvariant\n"
                                f"{indent}    {original_normalized_behavior} "
                                f"{candidate_normalized_behavior} "
                                f"{scanner_claim_name}\n"
                                f"{indent}    {scanner_claim_checked_name} world "
                                "originalState candidateState\n"
                                f"{indent}    relatedForRegisterTransfer"
                            )
                        elif bit == 10:
                            proof_lines.append(
                                f"{indent}  rw [evalNormalizedFlags_extract_df, "
                                "evalNormalizedFlags_extract_df]"
                            )
                        elif not scanner_flags or bit in flag_claim.get(
                            "preserved_bits", []
                        ):
                            theorem = flag_theorems[bit]
                            proof_lines.append(
                                f"{indent}  rw [{theorem} originalState "
                                f"{original_normalized_behavior}.flags (by decide), "
                                f"{theorem} candidateState "
                                f"{candidate_normalized_behavior}.flags (by decide)]"
                            )
                        else:
                            raise ValueError(
                                f"scanner flag {bit} is neither produced nor preserved"
                            )
                        if not (scanner_flags and bit == 6):
                            proof_lines.append(
                                f"{indent}  exact flagsRelated_of_contains "
                                f"region{source_index}.flagInputs originalState.eflags "
                                "candidateState.eflags inputFlags (by decide)"
                            )
                        proof_lines.append(
                            f"{indent}· "
                            + (
                                "apply flagsRelated_cons_of_eq"
                                if bit_index + 1 < len(flag_bits)
                                else "rfl"
                            )
                        )
                    flag_proof = "\n".join(proof_lines)
                if contract["regions"][target_index].get("stack_windows"):
                    stack_transfer_rows = ", ".join(
                        _lean_stack_window_transfer_claim(claim)
                        for claim in candidate["stack_transfer_claims"]
                    )
                    stack_window_setup = (
                        "  have outputStackWindows := "
                        "stackWindowsRelated_after_affine_of_checked staticProofContext world "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant "
                        f"{original_normalized_behavior} "
                        f"{candidate_normalized_behavior} [{stack_transfer_rows}] "
                        "originalState candidateState stackRangesValid inputStackWindows "
                        "(by decide)\n"
                    )
                    stack_window_proof = "  · exact outputStackWindows\n"
                else:
                    stack_window_setup = ""
                    stack_window_proof = (
                        f"  · simp [RegionRelation.inputInvariant, region{target_index}, "
                        "stackWindowsRelated]\n"
                    )
                target_stack_claims = contract["regions"][target_index].get(
                    "stack_address_separation_claims", []
                )
                if target_stack_claims:
                    claim_rows = ", ".join(
                        _lean_stack_address_separation_claim(claim)
                        for claim in target_stack_claims
                    )
                    stack_separation_proof = (
                        "  · exact addressSeparationsRelated_of_stack_windows "
                        "staticProofContext world "
                        f"region{target_index}.inputInvariant [{claim_rows}] "
                        f"({original_normalized_behavior}.eval originalState).registers "
                        f"({candidate_normalized_behavior}.eval candidateState).registers "
                        "stackRangesValid outputStackWindows (by decide)\n"
                    )
                else:
                    stack_separation_proof = (
                        f"  · simp [RegionRelation.inputInvariant, region{target_index}, "
                        "addressSeparationsRelated]\n"
                    )
                dynamic_register_outputs = candidate.get(
                    "dynamic_register_output_claims", []
                )
                scanner_register_transfer = candidate.get(
                    "reverse_sentinel_scanner_register_transfer_claim"
                )
                scanner_register_output = (
                    scanner_register_transfer.get("output")
                    if isinstance(scanner_register_transfer, dict) else None
                )
                target_output_claims_name = f"{prefix}TargetRegisterOutputClaims"
                target_output_claims = candidate.get("register_output_claims", [])
                if reverse_sentinel_scanner_body and isinstance(
                    scanner_register_output, dict
                ):
                    if not isinstance(scanner_register_transfer, dict):
                        raise StageAInputError(
                            "scanner body lacks its checked register-transfer claim"
                        )
                    register_inventory_definition = ""
                    register_inventory_statement = "True"
                elif dynamic_register_outputs:
                    register_inventory_definition = ""
                    register_inventory_statement = (
                        f"region{source_index}.outputRelations = "
                        f"region{target_index}.inputRelations"
                    )
                else:
                    target_output_claim_literals = ", ".join(
                        _lean_register_output_claim(claim)
                        for claim in target_output_claims
                    )
                    register_inventory_definition = (
                        f"def {target_output_claims_name} : "
                        "List InvariantWP.RegisterOutputClaim := "
                        f"[{target_output_claim_literals}]"
                    )
                    register_inventory_statement = (
                        f"{target_output_claims_name}.map "
                        "InvariantWP.RegisterOutputClaim.output = "
                        f"region{target_index}.inputRelations"
                    )
                if reverse_sentinel_scanner_body and isinstance(
                    scanner_register_output, dict
                ):
                    ordinary_fact_setup = (
                        "  have ordinaryRegisterFacts := "
                        "InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
                        f"    staticProofContext world region{source_index} "
                        f"{original_normalized_behavior} "
                        f"{candidate_normalized_behavior}\n"
                        f"    registerRelationChunk{chunk_index}Region{source_index}OutputClaims "
                        "(by decide) originalState candidateState relatedForRegisterTransfer\n"
                        "  simp only [registerRelationsHold, List.all_eq_true] "
                        "at ordinaryRegisterFacts\n"
                    )
                    output_facts: dict[tuple[str, str, str], str] = {}
                    ordinary_fact_rows: list[str] = []
                    for fact_index, output_claim in enumerate(
                        register_relations["regions"][source_index].get(
                            "output_claims", []
                        )
                    ):
                        output = output_claim.get("output")
                        if not isinstance(output, dict):
                            continue
                        fact_name = f"ordinaryRegisterFact{fact_index}"
                        ordinary_fact_rows.append(
                            f"  have {fact_name} := ordinaryRegisterFacts "
                            f"{_lean_register_relation_pair(output)} (by decide)\n"
                        )
                        output_facts[(
                            output["original"], output["candidate"],
                            output["relation"],
                        )] = fact_name
                    scanner_fact_name = "scannerLoadedRegisterFact"
                    output_facts[(
                        scanner_register_output["original"],
                        scanner_register_output["candidate"],
                        scanner_register_output["relation"],
                    )] = scanner_fact_name
                    scanner_fact_setup = (
                        f"  have {scanner_fact_name} := "
                        "reverseSentinelScannerLoadedOutputRelated_of_checked\n"
                        f"    staticProofContext region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"    {original_normalized_behavior} "
                        f"{candidate_normalized_behavior} {scanner_claim_name}\n"
                        f"    {scanner_claim_checked_name} world originalState "
                        "candidateState relatedForRegisterTransfer\n"
                    )
                    target_fact_names = [
                        output_facts[(
                            output["original"], output["candidate"],
                            output["relation"],
                        )]
                        for output in contract["regions"][target_index].get(
                            "input_relations", []
                        )
                    ]
                    register_transfer_body = (
                        ordinary_fact_setup
                        + "".join(ordinary_fact_rows)
                        + scanner_fact_setup
                        + f"  simpa [RegionRelation.inputInvariant, region{target_index}, "
                        "registerRelationsHold] using (⟨"
                        + ", ".join(target_fact_names)
                        + "⟩)\n"
                    )
                    register_transfer_proof = (
                        "  · "
                        + register_transfer_body.lstrip().replace("\n  ", "\n    ")
                    )
                elif not dynamic_register_outputs:
                    register_transfer_proof = (
                        f"  · rw [RegionRelation.inputInvariant, ← {composition_name}]\n"
                        "    exact InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims "
                        f"staticProofContext world region{source_index} "
                        f"{original_normalized_behavior} "
                        f"{candidate_normalized_behavior} "
                        f"{target_output_claims_name} (by decide) "
                        "originalState candidateState "
                        "relatedForRegisterTransfer\n"
                    )
                else:
                    ordinary_fact_setup = (
                        "  have ordinaryRegisterFacts := "
                        "InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
                        f"    staticProofContext world region{source_index} "
                        f"{original_normalized_behavior} "
                        f"{candidate_normalized_behavior}\n"
                        f"    registerRelationChunk{chunk_index}Region{source_index}OutputClaims "
                        "(by decide) originalState candidateState relatedForRegisterTransfer\n"
                        "  simp only [registerRelationsHold, List.all_eq_true] "
                        "at ordinaryRegisterFacts\n"
                    )
                    output_facts: dict[tuple[str, str, str], str] = {}
                    ordinary_fact_rows: list[str] = []
                    for fact_index, output_claim in enumerate(
                        register_relations["regions"][source_index].get(
                            "output_claims", []
                        )
                    ):
                        output = output_claim.get("output")
                        if not isinstance(output, dict):
                            continue
                        fact_name = f"ordinaryRegisterFact{fact_index}"
                        ordinary_fact_rows.append(
                            f"  have {fact_name} := ordinaryRegisterFacts "
                            f"{_lean_register_relation_pair(output)} (by decide)\n"
                        )
                        output_facts[(
                            output["original"], output["candidate"],
                            output["relation"],
                        )] = fact_name
                    dynamic_fact_rows: list[str] = []
                    for fact_index, output_claim in enumerate(dynamic_register_outputs):
                        dynamic_claim = output_claim["claim"]
                        output = output_claim["output"]
                        word_fact = f"dynamicRegisterWordFact{fact_index}"
                        if dynamic_claim["kind"] == "static_pointer_zero":
                            claim_name = f"{prefix}StaticZeroOutputClaim{fact_index}"
                            dynamic_claim_definitions.append(
                                f"def {claim_name} : "
                                "StaticDynamicPointerZeroOutputClaim := {\n"
                                f"  slot := {_lean_static_dynamic_pointer_slot(dynamic_claim['slot'])}\n"
                                f"  output := {_lean_register_relation_pair(output)}\n"
                                "}"
                            )
                            dynamic_fact_rows.append(
                                f"  have {word_fact} := "
                                "staticDynamicPointerZeroOutputRelated_of_checked\n"
                                f"    staticProofContext world region{source_index}.inputInvariant\n"
                                f"    {original_normalized_behavior} "
                                f"{candidate_normalized_behavior}\n"
                                f"    {edge_name}.originalGuard {edge_name}.candidateGuard "
                                f"{claim_name} (by decide)\n"
                                "    originalState candidateState "
                                "relatedForRegisterTransfer guardTrue\n"
                            )
                            output_facts[(
                                output["original"], output["candidate"],
                                output["relation"],
                            )] = word_fact
                            continue
                        claim_index = candidate["dynamic_transfer_claims"].index(
                            dynamic_claim
                        )
                        claim_name = f"{prefix}DynamicClaim{claim_index}"
                        range_fact = f"dynamicRegisterRangeFact{fact_index}"
                        range_theorem = (
                            "staticDynamicPointerSeedOutputHolds_of_checked"
                            if dynamic_claim["kind"] == "static_pointer_seed"
                            else "dynamicStackRangeReloadOutputHolds_of_checked"
                            if dynamic_claim["kind"] == "stack_reload"
                            else "dynamicRegisterRangeNextOutputHolds_of_checked"
                        )
                        guarded_arguments = (
                            f"{edge_name}.originalGuard {edge_name}.candidateGuard\n"
                            if dynamic_claim["kind"] != "stack_reload" else ""
                        )
                        guard_proof = (
                            " guardTrue"
                            if dynamic_claim["kind"] != "stack_reload" else ""
                        )
                        dynamic_fact_rows.append(
                            f"  have {range_fact} := "
                            f"{range_theorem}\n"
                            f"    staticProofContext world region{source_index}.inputInvariant\n"
                            f"    region{target_index}.inputInvariant "
                            f"{original_normalized_behavior}\n"
                            f"    {candidate_normalized_behavior} "
                            f"{guarded_arguments}"
                            f"    {claim_name} (by decide) originalState candidateState "
                            f"relatedForRegisterTransfer{guard_proof}\n"
                            f"  have {word_fact} := "
                            "dynamicRegisterRangeHolds_relatedWord_of_zero_offsets\n"
                            f"    staticProofContext world {claim_name}.targetRelation\n"
                            f"    ({original_normalized_behavior}.eval "
                            "originalState).registers\n"
                            f"    ({candidate_normalized_behavior}.eval "
                            "candidateState).registers\n"
                            f"    relatedForRegisterTransfer.1 (by decide) (by decide) "
                            f"{range_fact}\n"
                        )
                        output_facts[(
                            output["original"], output["candidate"],
                            output["relation"],
                        )] = word_fact
                    target_fact_names = [
                        output_facts[(
                            output["original"], output["candidate"],
                            output["relation"],
                        )]
                        for output in contract["regions"][target_index].get(
                            "input_relations", []
                        )
                    ]
                    register_transfer_body = (
                        ordinary_fact_setup
                        + "".join(ordinary_fact_rows)
                        + "".join(dynamic_fact_rows)
                        + f"  simpa [RegionRelation.inputInvariant, region{target_index}, "
                        "registerRelationsHold] using (⟨"
                        + ", ".join(target_fact_names)
                        + "⟩)\n"
                    )
                    register_transfer_proof = (
                        "  · "
                        + register_transfer_body.lstrip().replace("\n  ", "\n    ")
                    )
                direct_call_shape_definition = ""
                direct_call_transition_definition = ""
                paired_stack_write_shape_definition = ""
                paired_stack_write_transition_definition = ""
                paired_prepared_write_shape_definition = ""
                paired_prepared_write_transition_definition = ""
                immutable_indirect_jump_shape_definition = ""
                if direct_call_prepared_writes:
                    prepared_claim_name = (
                        f"{prefix}DirectCallPreparedWritesClaim"
                    )
                    prepared_claim = candidate[
                        "direct_call_prepared_writes_claim"
                    ]
                    assert isinstance(prepared_claim, dict)
                    stack_amount = int(prepared_claim["stack_amount"])
                    stack_amount_twos_complement = 2**32 - stack_amount
                    direct_call_shape_definition = (
                        f"def {prepared_claim_name} : "
                        "DirectCallPreparedWritesClaim := "
                        f"{_lean_direct_call_prepared_writes_claim(prepared_claim)}\n\n"
                        f"theorem {shape_name} :\n"
                        "    DirectCallPreparedWritesSegmentShapeClosed "
                        f"staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"{prepared_claim_name}\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} := by\n"
                        "  unfold DirectCallPreparedWritesSegmentShapeClosed\n"
                        f"  rw [{local_code_targets_name}, {local_values_name}]\n"
                        "  intro world originalState candidateState related\n"
                        "  refine ⟨rfl, ?_⟩\n"
                        "  intro guard\n"
                        f"  refine ⟨{original_normalized_behavior}.eval originalState, "
                        f"{candidate_normalized_behavior}.eval candidateState, "
                        "?_, ?_, ?_⟩\n"
                        f"  · simp [evalBehavior, {original_normalized_checked}]\n"
                        f"  · simp [evalBehavior, {candidate_normalized_checked}]\n"
                        "  have stackAddressRewrite (value : Word) :\n"
                        f"      value + BitVec.ofNat 32 {stack_amount_twos_complement} =\n"
                        f"        value - BitVec.ofNat 32 {stack_amount} := by\n"
                        f"    exact word_add_ia32_twos_complement value {stack_amount} "
                        "(by decide)\n"
                        "  simp [NormalizedSymbolicBehavior.eval, "
                        f"{normalized_shape_rewrites}, evalNormalizedWrites,\n"
                        f"    originalBehavior{source_index}, "
                        f"candidateBehavior{source_index},\n"
                        f"    {prepared_claim_name}, "
                        "DirectCallPreparedWritesClaim.originalWrites,\n"
                        "    DirectCallPreparedWritesClaim.candidateWrites,\n"
                        "    DirectCallPreparedWritesClaim.originalPushAddress,\n"
                        "    DirectCallPreparedWritesClaim.candidatePushAddress,\n"
                        "    PairedPreparedWordWritesClaim.originalWrites,\n"
                        "    PairedPreparedWordWritesClaim.candidateWrites,\n"
                        "    PairedPreparedWordWriteItem.originalAddress,\n"
                        "    PairedPreparedWordWriteItem.candidateAddress,\n"
                        "    PairedPreparedWordWriteItem.value, pairedStackWordAddress,\n"
                        "    NormalizedOutcomeExpr.eval,\n"
                        f"    {edge_name}, PureOutcome.segmentExitFor,\n"
                        "    PureOutcome.segmentExit, outcomesRelated, "
                        "StageA.Formal.Expr.eval, stackAddressRewrite]\n"
                    )
                    direct_call_transition_definition = (
                        f"theorem {transition_name} :\n"
                        f"    SegmentTransitionClosed staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} :=\n"
                        "  segmentTransitionClosed_of_direct_call_prepared_writes "
                        f"staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"    {prepared_claim_name} originalBehavior{source_index} "
                        f"candidateBehavior{source_index}\n"
                        f"    {original_normalized_behavior} "
                        f"{candidate_normalized_behavior}\n"
                        f"    region{source_index}.targets region{source_index}.values\n"
                        f"    {local_code_targets_name} {local_values_name} "
                        "staticProofContextChecked\n"
                        "    (by decide) (by decide) (by decide) (by decide) "
                        f"{shape_name} {state_name}"
                    )
                elif direct_call_stack_writes:
                    stack_claim_name = f"{prefix}DirectCallStackWritesClaim"
                    stack_claim = candidate["direct_call_stack_writes_claim"]
                    assert isinstance(stack_claim, dict)
                    stack_amount = int(stack_claim["stack_amount"])
                    stack_amount_twos_complement = 2**32 - stack_amount
                    direct_call_shape_definition = (
                        f"def {stack_claim_name} : DirectCallStackWritesClaim := "
                        f"{_lean_direct_call_stack_writes_claim(stack_claim)}\n\n"
                        f"theorem {shape_name} :\n"
                        "    DirectCallStackWritesSegmentShapeClosed staticProofContext "
                        f"{edge_name} region{source_index}.inputInvariant "
                        f"{stack_claim_name}\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} := by\n"
                        "  unfold DirectCallStackWritesSegmentShapeClosed\n"
                        f"  rw [{local_code_targets_name}, {local_values_name}]\n"
                        "  intro world originalState candidateState related\n"
                        "  refine ⟨rfl, ?_⟩\n"
                        "  intro guard\n"
                        f"  refine ⟨{original_normalized_behavior}.eval originalState, "
                        f"{candidate_normalized_behavior}.eval candidateState, "
                        "?_, ?_, ?_⟩\n"
                        f"  · simp [evalBehavior, {original_normalized_checked}]\n"
                        f"  · simp [evalBehavior, {candidate_normalized_checked}]\n"
                        "  have stackAddressRewrite (value : Word) :\n"
                        f"      value + BitVec.ofNat 32 {stack_amount_twos_complement} =\n"
                        f"        value - BitVec.ofNat 32 {stack_amount} := by\n"
                        f"    exact word_add_ia32_twos_complement value {stack_amount} "
                        "(by decide)\n"
                        "  simp [NormalizedSymbolicBehavior.eval, "
                        f"{normalized_shape_rewrites}, evalNormalizedWrites,\n"
                        f"    originalBehavior{source_index}, candidateBehavior{source_index},\n"
                        f"    {stack_claim_name}, DirectCallStackWritesClaim.originalWrites,\n"
                        "    DirectCallStackWritesClaim.candidateWrites,\n"
                        "    DirectCallStackWritesClaim.originalPushAddress,\n"
                        "    DirectCallStackWritesClaim.candidatePushAddress,\n"
                        "    PairedStackWordWritesClaim.originalWrites,\n"
                        "    PairedStackWordWritesClaim.candidateWrites,\n"
                        "    PairedStackWordWriteItem.originalAddress,\n"
                        "    PairedStackWordWriteItem.candidateAddress,\n"
                        "    pairedStackWordAddress, NormalizedOutcomeExpr.eval,\n"
                        f"    {edge_name}, PureOutcome.segmentExitFor,\n"
                        "    PureOutcome.segmentExit, outcomesRelated, "
                        "StageA.Formal.Expr.eval, stackAddressRewrite]\n"
                    )
                    direct_call_transition_definition = (
                        f"theorem {transition_name} :\n"
                        f"    SegmentTransitionClosed staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} :=\n"
                        "  segmentTransitionClosed_of_direct_call_stack_writes "
                        f"staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"    {stack_claim_name} originalBehavior{source_index} "
                        f"candidateBehavior{source_index}\n"
                        f"    {original_normalized_behavior} "
                        f"{candidate_normalized_behavior}\n"
                        f"    region{source_index}.targets region{source_index}.values\n"
                        f"    {local_code_targets_name} {local_values_name} "
                        "staticProofContextChecked\n"
                        "    (by decide) (by decide) (by decide) (by decide) "
                        "(by decide) "
                        f"{shape_name} {state_name}"
                    )
                elif direct_call or known_indirect_call:
                    source_window = _lean_stack_window(
                        candidate["source_stack_window"]
                    )
                    original_return = int(candidate["original_return_address"])
                    candidate_return = int(candidate["candidate_return_address"])
                    stack_amount = int(candidate["stack_amount"])
                    stack_amount_twos_complement = 2**32 - stack_amount
                    continuation_target = int(candidate["continuation_target_id"])
                    indirect_target = int(candidate.get("callee_target_id", target_index))
                    normalized_shape_simp = (
                        f"{normalized_shape_rewrites}, "
                        if normalized_shape_rewrites else ""
                    )
                    indirect_target_setup = (
                        f"  rcases "
                        f"productNode{source_index}ImmutableIndirectCallClosed world "
                        "originalState candidateState related with\n"
                        "    \u27e8originalTarget, candidateTarget, originalOutcome, "
                        "candidateOutcome, originalTargetMatches, "
                        "candidateTargetMatches\u27e9\n"
                        "  have originalTargetResolved :\n"
                        "      resolveMappedCodeTarget false "
                        "staticProofContext.originalPe.imageBase "
                        "staticProofContext.codeMap.entries.toList originalTarget = "
                        f"some {indirect_target} := by\n"
                        "    simpa using knownIndirectCodeTargetResolved "
                        "staticProofContext "
                        f"{indirect_target} false originalTarget (by decide) "
                        "(by simpa using originalTargetMatches)\n"
                        "  have candidateTargetResolved :\n"
                        "      resolveMappedCodeTarget true "
                        "staticProofContext.candidatePe.imageBase "
                        "staticProofContext.codeMap.entries.toList candidateTarget = "
                        f"some {indirect_target} := by\n"
                        "    simpa using knownIndirectCodeTargetResolved "
                        "staticProofContext "
                        f"{indirect_target} true candidateTarget (by decide) "
                        "(by simpa using candidateTargetMatches)\n"
                        if known_indirect_call else ""
                    )
                    call_shape_body = (
                        f"  refine \u27e8{original_normalized_behavior}.eval originalState, "
                        f"{candidate_normalized_behavior}.eval candidateState, "
                        "?_, ?_, ?_, ?_, ?_, ?_, ?_\u27e9\n"
                        f"  \u00b7 simp [evalBehavior, {original_normalized_checked}]\n"
                        f"  \u00b7 simp [evalBehavior, {candidate_normalized_checked}]\n"
                        "  \u00b7 simp [NormalizedSymbolicBehavior.eval, "
                        f"{normalized_shape_simp}evalNormalizedWrites,\n"
                        f"      originalBehavior{source_index}, "
                        "StageA.Formal.Expr.eval, stackAddressRewrite]\n"
                        "  \u00b7 simp [NormalizedSymbolicBehavior.eval, "
                        f"{normalized_shape_simp}evalNormalizedWrites,\n"
                        f"      candidateBehavior{source_index}, "
                        "StageA.Formal.Expr.eval, stackAddressRewrite]\n"
                        "  \u00b7 simp only [NormalizedSymbolicBehavior.eval_outcome]\n"
                        "    rw [originalOutcome]\n"
                        f"    simp [PureOutcome.segmentExitFor, originalTargetResolved, {edge_name}]\n"
                        "  \u00b7 simp only [NormalizedSymbolicBehavior.eval_outcome]\n"
                        "    rw [candidateOutcome]\n"
                        f"    simp [PureOutcome.segmentExitFor, candidateTargetResolved, {edge_name}]\n"
                        "  \u00b7 simp only [NormalizedSymbolicBehavior.eval_outcome]\n"
                        "    rw [originalOutcome, candidateOutcome]\n"
                        "    exact knownIndirectCallOutcomesRelated staticProofContext "
                        f"{indirect_target} region{source_index}.targets "
                        f"region{source_index}.values originalTarget candidateTarget "
                        f"{continuation_target} (by decide) (by decide)\n"
                        "      (by simpa using originalTargetMatches)\n"
                        "      (by simpa using candidateTargetMatches)\n"
                        if known_indirect_call else
                        f"  refine \u27e8{original_normalized_behavior}.eval originalState, "
                        f"{candidate_normalized_behavior}.eval candidateState, "
                        "?_, ?_, ?_\u27e9\n"
                        f"  \u00b7 simp [evalBehavior, {original_normalized_checked}]\n"
                        f"  \u00b7 simp [evalBehavior, {candidate_normalized_checked}]\n"
                        "  simp [NormalizedSymbolicBehavior.eval, "
                        f"{normalized_shape_rewrites}, evalNormalizedWrites,\n"
                        f"    originalBehavior{source_index}, "
                        f"candidateBehavior{source_index},\n"
                        f"NormalizedOutcomeExpr.eval,\n    {edge_name}, "
                        "PureOutcome.segmentExitFor, PureOutcome.segmentExit, "
                        "outcomesRelated, StageA.Formal.Expr.eval, "
                        "stackAddressRewrite]\n"
                    )
                    direct_call_shape_definition = (
                        f"theorem {shape_name} :\n"
                        "    DirectCallSegmentShapeClosed staticProofContext "
                        f"{edge_name} region{source_index}.inputInvariant\n"
                        f"      {source_window} {stack_amount} "
                        f"(BitVec.ofNat 32 {original_return}) "
                        f"(BitVec.ofNat 32 {candidate_return})\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} := by\n"
                        "  unfold DirectCallSegmentShapeClosed\n"
                        f"  rw [{local_code_targets_name}, {local_values_name}]\n"
                        "  intro world originalState candidateState related\n"
                        + indirect_target_setup +
                        "  refine ⟨rfl, ?_⟩\n"
                        "  intro guard\n"
                        "  have stackAddressRewrite (value : Word) :\n"
                        f"      value + BitVec.ofNat 32 {stack_amount_twos_complement} =\n"
                        f"        value - BitVec.ofNat 32 {stack_amount} := by\n"
                        f"    exact word_add_ia32_twos_complement value {stack_amount} "
                        "(by decide)\n"
                        + call_shape_body
                    )
                    direct_call_transition_definition = (
                        f"theorem {transition_name} :\n"
                        f"    SegmentTransitionClosed staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} :=\n"
                        + (
                            "  segmentTransitionClosed_of_direct_call_with_imports "
                            "staticProofContext "
                            if import_fact_names else
                            "  segmentTransitionClosed_of_direct_call "
                            "staticProofContext "
                        )
                        + f"{edge_name} region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"    {source_window} {stack_amount} "
                        f"(BitVec.ofNat 32 {original_return}) "
                        f"(BitVec.ofNat 32 {candidate_return})\n"
                        f"    originalBehavior{source_index} candidateBehavior{source_index} "
                        f"region{source_index}.targets region{source_index}.values\n"
                        f"    {local_code_targets_name} {local_values_name} "
                        "staticProofContextChecked (by decide) (by decide) "
                        "(by decide) (by decide)\n"
                        "    (by\n"
                        "      intro world\n"
                        "      apply codeTargetIdAddresses_wordRelated staticProofContext world "
                        f"{continuation_target}\n"
                        f"        (BitVec.ofNat 32 {original_return}) "
                        f"(BitVec.ofNat 32 {candidate_return})\n"
                        "      · decide\n"
                        "      · decide)\n"
                        + (
                            f"    (by decide) (by decide) {shape_name} "
                            f"{state_name} {import_transfer_name}"
                            if import_fact_names else
                            f"    (by decide) (by decide) (by decide) "
                            f"{shape_name} {state_name}"
                        )
                    )
                elif paired_prepared_writes:
                    prepared_claim_name = f"{prefix}PairedPreparedWritesClaim"
                    prepared_claim = candidate["paired_prepared_writes_claim"]
                    assert isinstance(prepared_claim, dict)
                    paired_prepared_write_shape_definition = (
                        f"def {prepared_claim_name} : PairedPreparedWordWritesClaim := "
                        f"{_lean_paired_prepared_word_writes_claim(prepared_claim)}\n\n"
                        f"theorem {shape_name} :\n"
                        "    PairedPreparedWordWritesSegmentShapeClosed "
                        f"staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant {prepared_claim_name}\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} := by\n"
                        "  unfold PairedPreparedWordWritesSegmentShapeClosed\n"
                        f"  rw [{local_code_targets_name}, {local_values_name}]\n"
                        "  intro world originalState candidateState related\n"
                        + guard_shape_setup
                        + f"  refine ⟨{original_normalized_behavior}.eval originalState, "
                        f"{candidate_normalized_behavior}.eval candidateState, "
                        "?_, ?_, ?_⟩\n"
                        f"  · simp [evalBehavior, {original_normalized_checked}]\n"
                        f"  · simp [evalBehavior, {candidate_normalized_checked}]\n"
                        "  simp [NormalizedSymbolicBehavior.eval, "
                        f"{normalized_shape_rewrites}, evalNormalizedWrites,\n"
                        f"    originalBehavior{source_index}, candidateBehavior{source_index},\n"
                        + ("" if guard_claim is None else
                           f"region{source_index}OutcomeCondition, "
                           f"{candidate_outcome_condition_name}, ")
                        + "NormalizedOutcomeExpr.eval,\n"
                        f"    {prepared_claim_name}, "
                        "PairedPreparedWordWritesClaim.originalWrites,\n"
                        "    PairedPreparedWordWritesClaim.candidateWrites,\n"
                        "    PairedPreparedWordWriteItem.originalAddress,\n"
                        "    PairedPreparedWordWriteItem.candidateAddress,\n"
                        "    PairedPreparedWordWriteItem.value, pairedStackWordAddress,\n"
                        f"    pairedDynamicWordAddress, {edge_name}, "
                        "PureOutcome.segmentExitFor,\n"
                        "    PureOutcome.segmentExit, outcomesRelated, "
                        "StageA.Formal.Expr.eval]\n"
                        + guard_shape_finish
                    )
                    spill_claim = candidate.get(
                        "prepared_dynamic_stack_spill_claim"
                    )
                    spill_claim_name = f"{prefix}DynamicStackSpillClaim"
                    spill_base_name = f"{prefix}SpillBasePreserved"
                    if isinstance(spill_claim, dict):
                        paired_prepared_write_shape_definition += (
                            "\n"
                            f"def {spill_claim_name} : "
                            "PreparedDynamicStackRangeSpillClaim := "
                            f"{_lean_prepared_dynamic_stack_spill_claim(spill_claim)}\n\n"
                            f"theorem {spill_base_name} :\n"
                            "    PairedPreparedWordWritesOutputBasePreserved "
                            f"staticProofContext {edge_name} {spill_claim_name}\n"
                            f"      originalBehavior{source_index} "
                            f"candidateBehavior{source_index} := by\n"
                            "  unfold PairedPreparedWordWritesOutputBasePreserved\n"
                            f"  rw [{local_code_targets_name}]\n"
                            "  intro originalState candidateState originalResult "
                            "candidateResult originalEval candidateEval\n"
                            f"  simp [evalBehavior, {original_normalized_checked}] "
                            "at originalEval\n"
                            f"  simp [evalBehavior, {candidate_normalized_checked}] "
                            "at candidateEval\n"
                            "  subst originalResult\n"
                            "  subst candidateResult\n"
                            "  simp [NormalizedSymbolicBehavior.eval, "
                            "evalNormalizedRegisters, "
                            f"{normalized_register_rewrites}, "
                            f"{normalized_shape_rewrites}, "
                            f"originalBehavior{source_index}, "
                            f"candidateBehavior{source_index}, "
                            f"{spill_claim_name}, "
                            "PreparedDynamicStackRangeSpillClaim.window, "
                            "StageA.Formal.Registers.get, "
                            "StageA.Formal.Expr.eval]\n"
                        )
                    if isinstance(spill_claim, dict) and dynamic_fact_names:
                        paired_prepared_write_transition_definition = (
                            f"theorem {transition_name} :\n"
                            f"    SegmentTransitionClosed staticProofContext {edge_name} "
                            f"region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"      originalBehavior{source_index} "
                            f"candidateBehavior{source_index} :=\n"
                            "  segmentTransitionClosed_of_paired_prepared_word_writes_with_dynamic_spill "
                            f"staticProofContext {edge_name} "
                            f"region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"    {prepared_claim_name} {spill_claim_name} "
                            f"originalBehavior{source_index} "
                            f"candidateBehavior{source_index}\n"
                            f"    region{source_index}.targets region{source_index}.values\n"
                            f"    {local_code_targets_name} {local_values_name} "
                            "staticProofContextChecked\n"
                            "    (by decide) (by decide) (by decide) (by decide) "
                            f"{shape_name} {spill_base_name} {state_name} "
                            f"{dynamic_transfer_name}"
                        )
                    elif isinstance(spill_claim, dict):
                        paired_prepared_write_transition_definition = (
                            f"theorem {transition_name} :\n"
                            f"    SegmentTransitionClosed staticProofContext {edge_name} "
                            f"region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"      originalBehavior{source_index} "
                            f"candidateBehavior{source_index} :=\n"
                            "  segmentTransitionClosed_of_paired_prepared_word_writes_with_spill "
                            f"staticProofContext {edge_name} "
                            f"region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"    {prepared_claim_name} {spill_claim_name} "
                            f"originalBehavior{source_index} "
                            f"candidateBehavior{source_index}\n"
                            f"    region{source_index}.targets region{source_index}.values\n"
                            f"    {local_code_targets_name} {local_values_name} "
                            "staticProofContextChecked\n"
                            "    (by decide) (by decide) (by decide) (by decide) "
                            "(by decide) "
                            f"{shape_name} {spill_base_name} {state_name}"
                        )
                    elif dynamic_fact_names:
                        paired_prepared_write_transition_definition = (
                            f"theorem {transition_name} :\n"
                            f"    SegmentTransitionClosed staticProofContext {edge_name} "
                            f"region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"      originalBehavior{source_index} "
                            f"candidateBehavior{source_index} :=\n"
                            "  segmentTransitionClosed_of_paired_prepared_word_writes_with_dynamic "
                            f"staticProofContext {edge_name} "
                            f"region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"    {prepared_claim_name} originalBehavior{source_index} "
                            f"candidateBehavior{source_index}\n"
                            f"    region{source_index}.targets region{source_index}.values\n"
                            f"    {local_code_targets_name} {local_values_name} "
                            "staticProofContextChecked\n"
                            "    (by decide) (by decide) (by decide) "
                            f"{shape_name} {state_name} {dynamic_transfer_name}"
                        )
                    else:
                        paired_prepared_write_transition_definition = (
                            f"theorem {transition_name} :\n"
                            f"    SegmentTransitionClosed staticProofContext {edge_name} "
                            f"region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"      originalBehavior{source_index} "
                            f"candidateBehavior{source_index} :=\n"
                            "  segmentTransitionClosed_of_paired_prepared_word_writes "
                            f"staticProofContext {edge_name} "
                            f"region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"    {prepared_claim_name} originalBehavior{source_index} "
                            f"candidateBehavior{source_index}\n"
                            f"    region{source_index}.targets region{source_index}.values\n"
                            f"    {local_code_targets_name} {local_values_name} "
                            "staticProofContextChecked\n"
                            "    (by decide) (by decide) (by decide) (by decide) "
                            f"{shape_name} {state_name}"
                        )
                elif paired_stack_write:
                    stack_claim_name = f"{prefix}PairedStackWriteClaim"
                    stack_claim = candidate["paired_stack_write_claim"]
                    assert isinstance(stack_claim, dict)
                    paired_stack_write_shape_definition = (
                        f"def {stack_claim_name} : PairedStackWordWriteClaim := "
                        f"{_lean_paired_stack_word_write_claim(stack_claim)}\n\n"
                        f"theorem {shape_name} :\n"
                        "    PairedStackWordWriteSegmentShapeClosed staticProofContext "
                        f"{edge_name} region{source_index}.inputInvariant {stack_claim_name}\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} := by\n"
                        "  unfold PairedStackWordWriteSegmentShapeClosed\n"
                        f"  rw [{local_code_targets_name}, {local_values_name}]\n"
                        "  intro world originalState candidateState related\n"
                        + guard_shape_setup
                        + f"  refine ⟨{original_normalized_behavior}.eval originalState, "
                        f"{candidate_normalized_behavior}.eval candidateState, "
                        "?_, ?_, ?_⟩\n"
                        f"  · simp [evalBehavior, {original_normalized_checked}]\n"
                        f"  · simp [evalBehavior, {candidate_normalized_checked}]\n"
                        "  simp [NormalizedSymbolicBehavior.eval, "
                        f"{normalized_shape_rewrites}, evalNormalizedWrites,\n"
                        f"    originalBehavior{source_index}, candidateBehavior{source_index},\n"
                        + ("" if guard_claim is None else
                           f"region{source_index}OutcomeCondition, "
                           f"{candidate_outcome_condition_name}, ")
                        + "NormalizedOutcomeExpr.eval,\n"
                        f"    {stack_claim_name}, PairedStackWordWriteClaim.originalAddress,\n"
                        "    PairedStackWordWriteClaim.candidateAddress, "
                        f"{edge_name}, PureOutcome.segmentExitFor,\n"
                        "    PureOutcome.segmentExit, outcomesRelated, StageA.Formal.Expr.eval]\n"
                        + guard_shape_finish
                    )
                    paired_stack_write_transition_definition = (
                        f"theorem {transition_name} :\n"
                        f"    SegmentTransitionClosed staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} :=\n"
                        "  segmentTransitionClosed_of_paired_stack_word_write "
                        f"staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"    {stack_claim_name} originalBehavior{source_index} "
                        f"candidateBehavior{source_index}\n"
                        f"    {original_normalized_behavior} "
                        f"{candidate_normalized_behavior}\n"
                        f"    region{source_index}.targets region{source_index}.values\n"
                        f"    {local_code_targets_name} {local_values_name} "
                        "staticProofContextChecked\n"
                        f"    (by decide) (by decide) (by decide) (by decide) "
                        "(by decide) "
                        f"{shape_name} {state_name}"
                    )
                elif paired_stack_writes:
                    stack_claim_name = f"{prefix}PairedStackWritesClaim"
                    stack_claim = candidate["paired_stack_writes_claim"]
                    assert isinstance(stack_claim, dict)
                    paired_stack_write_shape_definition = (
                        f"def {stack_claim_name} : PairedStackWordWritesClaim := "
                        f"{_lean_paired_stack_word_writes_claim(stack_claim)}\n\n"
                        f"theorem {shape_name} :\n"
                        "    PairedStackWordWritesSegmentShapeClosed staticProofContext "
                        f"{edge_name} region{source_index}.inputInvariant {stack_claim_name}\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} := by\n"
                        "  unfold PairedStackWordWritesSegmentShapeClosed\n"
                        f"  rw [{local_code_targets_name}, {local_values_name}]\n"
                        "  intro world originalState candidateState related\n"
                        + guard_shape_setup
                        + f"  refine ⟨{original_normalized_behavior}.eval originalState, "
                        f"{candidate_normalized_behavior}.eval candidateState, "
                        "?_, ?_, ?_⟩\n"
                        f"  · simp [evalBehavior, {original_normalized_checked}]\n"
                        f"  · simp [evalBehavior, {candidate_normalized_checked}]\n"
                        "  simp [NormalizedSymbolicBehavior.eval, "
                        f"{normalized_shape_rewrites}, evalNormalizedWrites,\n"
                        f"    originalBehavior{source_index}, candidateBehavior{source_index},\n"
                        + ("" if guard_claim is None else
                           f"region{source_index}OutcomeCondition, "
                           f"{candidate_outcome_condition_name}, ")
                        + "NormalizedOutcomeExpr.eval,\n"
                        f"    {stack_claim_name}, "
                        "PairedStackWordWritesClaim.originalWrites,\n"
                        "    PairedStackWordWritesClaim.candidateWrites, "
                        "PairedStackWordWriteItem.originalAddress,\n"
                        "    PairedStackWordWriteItem.candidateAddress, "
                        f"{edge_name}, PureOutcome.segmentExitFor,\n"
                        "    PureOutcome.segmentExit, outcomesRelated, "
                        "pairedStackWordAddress, StageA.Formal.Expr.eval]\n"
                        + guard_shape_finish
                    )
                    paired_stack_write_transition_definition = (
                        f"theorem {transition_name} :\n"
                        f"    SegmentTransitionClosed staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} :=\n"
                        "  segmentTransitionClosed_of_paired_stack_word_writes "
                        f"staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"    {stack_claim_name} originalBehavior{source_index} "
                        f"candidateBehavior{source_index}\n"
                        f"    {original_normalized_behavior} "
                        f"{candidate_normalized_behavior}\n"
                        f"    region{source_index}.targets region{source_index}.values\n"
                        f"    {local_code_targets_name} {local_values_name} "
                        "staticProofContextChecked\n"
                        f"    (by decide) (by decide) (by decide) (by decide) "
                        "(by decide) "
                        f"{shape_name} {state_name}"
                    )
                elif immutable_indirect_jump or fixed_code_address_indirect_jump:
                    target_closed = (
                        f"productNode{source_index}ImmutableIndirectJumpClosed"
                        if immutable_indirect_jump else
                        f"productNode{source_index}FixedCodeAddressIndirectJumpClosed"
                    )
                    immutable_indirect_jump_shape_definition = (
                        f"theorem {shape_name} :\n"
                        "    NoWriteSegmentShapeClosed staticProofContext "
                        f"{edge_name} region{source_index}.inputInvariant\n"
                        f"      originalBehavior{source_index} "
                        f"candidateBehavior{source_index} := by\n"
                        "  unfold NoWriteSegmentShapeClosed\n"
                        f"  rw [{local_code_targets_name}, {local_values_name}]\n"
                        "  intro world originalState candidateState related\n"
                        f"  have indirectTargets := {target_closed} world "
                        "originalState candidateState related\n"
                        "  refine ⟨rfl, ?_⟩\n"
                        "  intro _guard\n"
                        f"  refine ⟨{original_normalized_behavior}.eval originalState, "
                        f"{candidate_normalized_behavior}.eval candidateState, "
                        "?_, ?_, ?_, ?_, ?_, ?_, ?_⟩\n"
                        f"  · simp [evalBehavior, {original_normalized_checked}]\n"
                        f"  · simp [evalBehavior, {candidate_normalized_checked}]\n"
                        "  · simp [NormalizedSymbolicBehavior.eval, "
                        f"{original_normalized_behavior}WritesEmpty, "
                        "evalNormalizedWrites]\n"
                        "  · simp [NormalizedSymbolicBehavior.eval, "
                        f"{candidate_normalized_behavior}WritesEmpty, "
                        "evalNormalizedWrites]\n"
                        "  · simp only [NormalizedSymbolicBehavior.eval_outcome]\n"
                        "    rw [indirectTargets.1]\n"
                        f"    decide\n"
                        "  · simp only [NormalizedSymbolicBehavior.eval_outcome]\n"
                        "    rw [indirectTargets.2]\n"
                        f"    decide\n"
                        "  · simp only [NormalizedSymbolicBehavior.eval_outcome]\n"
                        "    rw [indirectTargets.1, indirectTargets.2]\n"
                        "    decide"
                    )
                definitions.extend([
                    *normalized_behavior_definitions,
                    *scanner_claim_definitions,
                    *import_claim_definitions,
                    *dynamic_claim_definitions,
                    (
                        f"def {edge_name} : RelationalSegmentEdge := {{\n"
                        f"  sourceTargetId := {source_target_id}\n"
                        f"  exit := .internal {target_id}\n"
                        f"  originalSpan := region{source_index}.original\n"
                        f"  candidateSpan := region{source_index}.candidate\n"
                        "  localCodeTargetIds := ["
                        + ", ".join(
                            str(item) for item in candidate["local_code_target_ids"]
                        )
                        + "]\n  localValueTargetIds := ["
                        + ", ".join(
                            str(item) for item in candidate["local_value_target_ids"]
                        )
                        + "]\n"
                        f"  originalGuard := {_lean_semantic_bool_expr(candidate['original_guard'])}\n"
                        f"  candidateGuard := {_lean_semantic_bool_expr(candidate['candidate_guard'])}\n"
                        "}"
                    ),
                    (
                        f"theorem {local_code_targets_name} :\n"
                        f"    staticProofContext.codeMap.resolveIds "
                        f"{edge_name}.localCodeTargetIds = some region{source_index}.targets := "
                        "by decide"
                    ),
                    (
                        f"theorem {local_values_name} :\n"
                        f"    staticProofContext.dataMap.resolveIds "
                        f"{edge_name}.localValueTargetIds = some region{source_index}.values := "
                        "by decide"
                    ),
                    (
                        register_inventory_definition
                    ),
                    (
                        f"theorem {composition_name} : {register_inventory_statement} "
                        ":= by decide"
                    ),
                    direct_call_shape_definition
                    or paired_prepared_write_shape_definition
                    or paired_stack_write_shape_definition
                    or immutable_indirect_jump_shape_definition
                    or (
                        f"theorem {shape_name} :\n"
                        f"    NoWriteSegmentShapeClosed staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant\n"
                        f"      originalBehavior{source_index} candidateBehavior{source_index} := by\n"
                        "  unfold NoWriteSegmentShapeClosed\n"
                        f"  rw [{local_code_targets_name}, {local_values_name}]\n"
                        "  intro world originalState candidateState related\n"
                        + guard_shape_setup
                        + f"  refine ⟨{original_normalized_behavior}.eval originalState, "
                        f"{candidate_normalized_behavior}.eval candidateState, ?_, ?_, ?_⟩\n"
                        f"  · simp [evalBehavior, {original_normalized_checked}]\n"
                        f"  · simp [evalBehavior, {candidate_normalized_checked}]\n"
                        "  simp [NormalizedSymbolicBehavior.eval, "
                        + (
                            f"{normalized_shape_rewrites}, "
                            f"region{source_index}OriginalWritesEmpty,\n"
                            if normalized_fast_path else
                            f"{normalized_shape_rewrites},\n"
                            f"    originalBehavior{source_index}, "
                            f"candidateBehavior{source_index},\n"
                        )
                        + "    evalNormalizedWrites,\n"
                        + ("" if guard_claim is None else
                           f"    region{source_index}OutcomeCondition,\n"
                           f"    {candidate_outcome_condition_name},\n")
                        + f"    NormalizedOutcomeExpr.eval, {edge_name}, "
                        "PureOutcome.segmentExitFor, PureOutcome.segmentExit, "
                        "outcomesRelated]"
                        + guard_shape_finish
                    ),
                    (
                        f"theorem {state_name} :\n"
                        f"    NoWriteSegmentStateTransferClosed staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant region{target_index}.inputInvariant\n"
                        f"      originalBehavior{source_index} candidateBehavior{source_index} := by\n"
                        "  unfold NoWriteSegmentStateTransferClosed\n"
                        f"  rw [{local_code_targets_name}]\n"
                        "  intro world originalState candidateState originalResult candidateResult related\n"
                        "    originalEval candidateEval guardTrue\n"
                        f"  simp [evalBehavior, {original_normalized_checked}] at originalEval\n"
                        f"  simp [evalBehavior, {candidate_normalized_checked}] at candidateEval\n"
                        "  subst originalResult\n"
                        "  subst candidateResult\n"
                        "  have relatedForRegisterTransfer := related\n"
                        "  rcases related with ⟨_worldStatic, stackRangesValid, _stackMemory, "
                        "_importsStatic, _importsComplete, _importsMemory, _originalImmutable, _candidateImmutable, "
                        "relatedCore, _importRegisters⟩\n"
                        "  rcases relatedCore with ⟨inputRegisters, inputBounds, inputSeparations, "
                        "inputStackWindows, inputMemory, _inputDynamicWords, inputUndefined, inputX87, inputFlags, "
                        "inputFsBase⟩\n"
                        + stack_window_setup
                        + "  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_⟩\n"
                        + register_transfer_proof
                        + (
                            "  · exact reverseSentinelScannerLoopBoundClosed_of_checked\n"
                            f"      staticProofContext region{source_index}.inputInvariant\n"
                            f"      region{target_index}.inputInvariant "
                            f"{original_normalized_behavior}\n"
                            f"      {candidate_normalized_behavior} "
                            f"{scanner_claim_name}\n"
                            f"      {scanner_claim_checked_name} world originalState "
                            "candidateState\n"
                            "      relatedForRegisterTransfer guardTrue\n"
                            if reverse_sentinel_scanner_loop
                            else
                            f"  · simp [RegionRelation.inputInvariant, region{target_index}, "
                            "boundsRelated]\n"
                        )
                        + stack_separation_proof
                        + stack_window_proof
                        +
                        "  · simp only [RelationalBehavior.nextMachineState, "
                        "NormalizedSymbolicBehavior.eval_x87, "
                        f"{normalized_x87_rewrites}]\n"
                        "    rcases originalState with "
                        "⟨originalRegisters, originalMemory, originalUndefined, originalX87, "
                        "originalFlags, originalFsBase⟩\n"
                        "    rcases candidateState with "
                        "⟨candidateRegisters, candidateMemory, candidateUndefined, candidateX87, "
                        "candidateFlags, candidateFsBase⟩\n"
                        "    change originalX87 = candidateX87 at inputX87\n"
                        "    subst candidateX87\n"
                        f"    simp [evalNormalizedX87, "
                        f"originalBehavior{source_index}, candidateBehavior{source_index}, "
                        "StageA.Formal.X87Expr.eval, StageA.Formal.Expr.eval]\n"
                        + flag_proof
                        + "\n"
                        + (
                            "  · exact "
                            "reverseSentinelScannerPostconditionClosed_of_checked\n"
                            f"      staticProofContext region{source_index}.inputInvariant\n"
                            f"      region{target_index}.inputInvariant "
                            f"{original_normalized_behavior}\n"
                            f"      {candidate_normalized_behavior} "
                            f"{scanner_claim_name}\n"
                            f"      {scanner_claim_checked_name} world originalState "
                            "candidateState\n"
                            "      relatedForRegisterTransfer\n"
                            if reverse_sentinel_scanner_body
                            else
                            "  · exact "
                            "reverseSentinelScannerFinishedPostconditionClosed_of_checked\n"
                            f"      staticProofContext region{source_index}.inputInvariant\n"
                            f"      region{target_index}.inputInvariant "
                            f"{original_normalized_behavior}\n"
                            f"      {candidate_normalized_behavior} "
                            f"{scanner_claim_name}\n"
                            f"      {scanner_claim_checked_name} world originalState "
                            "candidateState\n"
                            "      relatedForRegisterTransfer guardTrue\n"
                            if reverse_sentinel_scanner_exit
                            else
                            f"  · simp [RegionRelation.inputInvariant, region{target_index}, "
                            "pairedStatePredicatesHold, PairedStatePredicate.holds]\n"
                        )
                    ),
                    *([] if not import_fact_names else [
                        (
                            f"theorem {import_transfer_name} :\n"
                            "    NoWriteSegmentImportTransferClosed staticProofContext "
                            f"{edge_name} region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"      originalBehavior{source_index} "
                            f"candidateBehavior{source_index} := by\n"
                            "  unfold NoWriteSegmentImportTransferClosed\n"
                            f"  rw [{local_code_targets_name}]\n"
                            "  intro world originalState candidateState originalResult "
                            "candidateResult related originalEval candidateEval\n"
                            f"  simp [evalBehavior, {original_normalized_checked}] "
                            "at originalEval\n"
                            f"  simp [evalBehavior, {candidate_normalized_checked}] "
                            "at candidateEval\n"
                            "  subst originalResult\n"
                            "  subst candidateResult\n"
                            + "\n".join(import_transfer_facts)
                            + "\n  simpa [RegionRelation.inputInvariant, "
                            f"region{target_index}, importRegisterRelationsHold, "
                            "ImportRegisterSeedClaim.relation, "
                            "ImportRegisterPreserveClaim.targetRelation] using "
                            + (import_fact_names[0] if len(import_fact_names) == 1 else
                               "\u27e8" + ", ".join(import_fact_names) + "\u27e9")
                        )
                    ]),
                    *([] if not dynamic_fact_names else [
                        (
                            f"theorem {dynamic_transfer_name} :\n"
                            "    NoWriteSegmentDynamicTransferClosed staticProofContext "
                            f"{edge_name} region{source_index}.inputInvariant "
                            f"region{target_index}.inputInvariant\n"
                            f"      originalBehavior{source_index} "
                            f"candidateBehavior{source_index} := by\n"
                            "  unfold NoWriteSegmentDynamicTransferClosed\n"
                            f"  rw [{local_code_targets_name}]\n"
                            "  intro world originalState candidateState originalResult "
                            "candidateResult related originalEval candidateEval guardTrue\n"
                            f"  simp [evalBehavior, {original_normalized_checked}] "
                            "at originalEval\n"
                            f"  simp [evalBehavior, {candidate_normalized_checked}] "
                            "at candidateEval\n"
                            "  subst originalResult\n"
                            "  subst candidateResult\n"
                            + "\n".join(dynamic_transfer_facts)
                            + "\n  simpa [RegionRelation.inputInvariant, "
                            f"region{target_index}, activeDynamicRegisterRangeRelationsHold] using "
                            + (dynamic_fact_names[0] if len(dynamic_fact_names) == 1 else
                               "⟨" + ", ".join(dynamic_fact_names) + "⟩")
                        )
                    ]),
                    direct_call_transition_definition
                    or paired_prepared_write_transition_definition
                    or paired_stack_write_transition_definition
                    or (
                        f"theorem {transition_name} :\n"
                        f"    SegmentTransitionClosed staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant region{target_index}.inputInvariant\n"
                        f"      originalBehavior{source_index} candidateBehavior{source_index} :=\n"
                        + (
                            "  segmentTransitionClosed_of_no_write_with_imports_and_dynamic staticProofContext "
                            if import_fact_names and dynamic_fact_names else
                            "  segmentTransitionClosed_of_no_write_with_imports staticProofContext "
                            if import_fact_names else
                            "  segmentTransitionClosed_of_no_write_with_dynamic staticProofContext "
                            if dynamic_fact_names else
                            "  segmentTransitionClosed_of_no_write staticProofContext "
                        )
                        + f"{edge_name} region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"    originalBehavior{source_index} candidateBehavior{source_index} "
                        f"region{source_index}.targets region{source_index}.values\n"
                        f"    {local_code_targets_name} {local_values_name} "
                        + (
                            f"{shape_name} {state_name} {import_transfer_name} "
                            f"{dynamic_transfer_name} (by decide)"
                            if import_fact_names and dynamic_fact_names else
                            f"{shape_name} {state_name} {import_transfer_name} "
                            "(by decide) (by decide)"
                            if import_fact_names else
                            f"(by decide) (by decide) {shape_name} {state_name} "
                            f"{dynamic_transfer_name}"
                            if dynamic_fact_names else
                            f"(by decide) (by decide) (by decide) "
                            f"{shape_name} {state_name}"
                        )
                    ),
                    (
                        f"def {proposition_name} : Prop :=\n"
                        f"  RelationalSegmentRefinement staticProofContext {edge_name} "
                        f"region{source_index}.inputInvariant region{target_index}.inputInvariant"
                    ),
                    (
                        f"theorem {theorem_name} : {proposition_name} :=\n"
                        "  relationalSegmentRefinement_of_decoded staticProofContext "
                        f"{edge_name} region{source_index}.inputInvariant "
                        f"region{target_index}.inputInvariant\n"
                        f"    originalBehavior{source_index} candidateBehavior{source_index}\n"
                        f"    originalBehavior{source_index}CheckedDecoded "
                        f"candidateBehavior{source_index}CheckedDecoded {transition_name}"
                    ),
                ])
                proposition_names.append(proposition_name)
                theorem_names.append(theorem_name)
                continue
            raise StageAInputError(
                f"unsupported segment certificate profile: "
                f"{candidate.get('certificate_profile')!r}"
            )
        module_suffix = (
            f"Edge{isolated_edge}"
            if isolated_edge is not None
            else f"Chunk{chunk_index}"
        )
        claims_name = f"segmentRefinement{module_suffix}Claims"
        checked_name = (
            f"segmentRefinement{module_suffix}ClaimsChecked"
            if isolated_edge is not None
            else f"segmentRefinement{module_suffix}Checked"
        )
        definitions.append(
            f"def {claims_name} : List Prop := [{', '.join(proposition_names)}]"
        )
        proof = (
            "".join(f"And.intro {theorem} (" for theorem in theorem_names)
            + "True.intro"
            + ")" * len(theorem_names)
        )
        definitions.append(
            f"theorem {checked_name} : AllInvariantClaims {claims_name} := by\n"
            f"  exact {proof}"
        )
        module = f"RelationalSegmentRefinement{module_suffix}"
        target_chunk_imports = sorted({
            chunk_by_region[int(candidate["target_region_index"])]
            for candidate in selected
            if chunk_by_region[int(candidate["target_region_index"])] != chunk_index
        })
        indirect_control_chunk_imports = sorted({
            decoded_control_chunk_by_node[int(candidate["source_region_index"])]
            for candidate in selected
            if candidate.get("certificate_profile") in {
                "composable_immutable_indirect_jump_v1",
                "composable_fixed_code_address_indirect_jump_v1",
                "composable_known_indirect_call_v1",
            }
        })
        definitions_source = "\n\n".join(definitions)
        requires_full_static_context = "staticProofContextChecked" in definitions_source
        source = (
            "import StageA.RelationalComposition\n"
            + (
                "import StageA.RelationalStaticContext\n"
                if requires_full_static_context
                else ""
            )
            + "import StageA.RelationalStaticContextBase\n"
            f"import StageA.RelationalProofOriginalDecodeChunk{chunk_index}\n"
            f"import StageA.RelationalProofCandidateDecodeChunk{chunk_index}\n"
            + (
                f"import StageA.RelationalRegisterRelationsChunk{chunk_index}\n"
                if isolated_edge is None
                else ""
            )
            + "".join(
                f"import StageA.RelationalRegionChunk{target_chunk}\n"
                for target_chunk in target_chunk_imports
            )
            + "".join(
                f"import StageA.RelationalProductDecodedControlChunk{source_chunk}\n"
                for source_chunk in indirect_control_chunk_imports
            )
            + "\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            + definitions_source
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)
        modules.append({
            "module": module,
            "claims": claims_name,
            "theorem": checked_name,
            "edges": str(len(selected)),
            "edge_ids": [int(candidate["edge_index"]) for candidate in selected],
        })
    return modules

def _write_relational_external_call_refinement_modules(
    lean_dir: Path,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
    product_graph: dict[str, Any],
    decode_chunk_regions: list[list[int]],
    import_call_candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    analysis = _external_call_site_candidates(
        contract, behaviors, register_relations, import_call_candidates
    )
    chunk_by_region = {
        region_index: chunk_index
        for chunk_index, region_indices in enumerate(decode_chunk_regions)
        for region_index in region_indices
    }
    contracts_by_id = {
        int(item["id"]): item
        for item in contract.get("machine_import_call_contracts", [])
    }
    graph_edges_by_id = {
        int(edge["id"]): edge for edge in product_graph.get("edges", [])
    }
    modules: list[dict[str, Any]] = []
    for site in analysis["candidates"]:
        if site.get("site_kind") == "direct_import_thunk":
            continue
        edge_id = int(site["edge_index"])
        source_index = int(site["source_region_index"])
        target_index = int(site["target_region_index"])
        source = contract["regions"][source_index]
        graph_edge = graph_edges_by_id.get(edge_id)
        if graph_edge is None or (
            graph_edge.get("kind") != "externalCall"
            or int(graph_edge["source_node_id"]) != source_index
            or int(graph_edge["target_node_id"]) != target_index
        ):
            raise StageAInputError(
                f"external call site {edge_id} has no exact product-edge match"
            )
        machine_contract = contracts_by_id.get(int(site["machine_contract_id"]))
        if machine_contract is None:
            raise StageAInputError(
                f"external call site {edge_id} has no machine contract"
            )
        chunk_index = chunk_by_region[source_index]
        prefix = f"externalCallEdge{edge_id}"
        edge_name = f"{prefix}Spec"
        contract_name = f"{prefix}MachineContract"
        original_normalized = f"{prefix}OriginalNormalized"
        candidate_normalized = f"{prefix}CandidateNormalized"
        local_code_targets = f"{prefix}LocalCodeTargetsResolved"
        local_values = f"{prefix}LocalValuesResolved"
        contract_resolved = f"{prefix}MachineContractResolved"
        original_normalized_checked = f"{prefix}OriginalNormalizedChecked"
        candidate_normalized_checked = f"{prefix}CandidateNormalizedChecked"
        original_x87_checked = f"{prefix}OriginalX87Checked"
        candidate_x87_checked = f"{prefix}CandidateX87Checked"
        original_outcome_checked = f"{prefix}OriginalOutcomeChecked"
        candidate_outcome_checked = f"{prefix}CandidateOutcomeChecked"
        original_decoded = f"{prefix}OriginalDecoded"
        candidate_decoded = f"{prefix}CandidateDecoded"
        output_claims_name = f"{prefix}RegisterOutputClaims"
        shape_name = f"{prefix}ShapeChecked"
        boundary_name = f"{prefix}BoundaryTransferChecked"
        transition_name = f"{prefix}TransitionChecked"
        refinement_name = f"{prefix}RefinementChecked"
        product_resolved_name = f"{prefix}ProductResolved"
        product_name = f"{prefix}ProductRefinementChecked"
        register_dispatch = site["dispatch_profile"] == "checked_import_register"
        original_behavior_name = f"originalBehavior{source_index}"
        candidate_behavior_name = f"candidateBehavior{source_index}"
        original_decoded_normalized = f"{prefix}OriginalDecodedNormalized"
        candidate_decoded_normalized = f"{prefix}CandidateDecodedNormalized"
        original_externalized = f"{prefix}OriginalExternalized"
        candidate_externalized = f"{prefix}CandidateExternalized"
        dispatch_claim_name = f"{prefix}DispatchClaim"
        target_closed_name = f"{prefix}DispatchTargetsClosed"
        original_externalized_checked = f"{prefix}OriginalExternalizedChecked"
        candidate_externalized_checked = f"{prefix}CandidateExternalizedChecked"
        original_decoded_normalized_checked = (
            f"{prefix}OriginalDecodedNormalizedChecked"
        )
        candidate_decoded_normalized_checked = (
            f"{prefix}CandidateDecodedNormalizedChecked"
        )
        proof_original_behavior = (
            original_externalized if register_dispatch else original_behavior_name
        )
        proof_candidate_behavior = (
            candidate_externalized if register_dispatch else candidate_behavior_name
        )
        original_argument_words = "[" + ", ".join(
            f"({_lean_semantic_expr(expression)}).eval originalState"
            for expression in site["argument_expressions"]
        ) + "]"
        candidate_argument_words = "[" + ", ".join(
            f"({_lean_semantic_expr(expression)}).eval candidateState"
            for expression in site["argument_expressions"]
        ) + "]"
        argument_expressions = "[" + ", ".join(
            _lean_semantic_expr(expression)
            for expression in site["argument_expressions"]
        ) + "]"
        output_claims = ", ".join(
            _lean_register_output_claim(claim)
            for claim in site["register_output_claims"]
        )
        stack_claims = ", ".join(
            _lean_stack_window_transfer_claim(claim)
            for claim in site["stack_transfer_claims"]
        )
        original_x87 = _lean_symbolic_x87_state(
            behaviors[source_index]["original_ir"]["x87"]
        )
        candidate_x87 = _lean_symbolic_x87_state(
            behaviors[source_index]["candidate_ir"]["x87"]
        )
        flag_bits = site["boundary_invariant"].get("flag_bits", [])
        if flag_bits == []:
            flag_proof = "  · rfl\n"
        elif flag_bits == [10]:
            flag_proof = (
                "  · apply flagsRelated_cons_of_eq\n"
                "    · simp only [RelationalBehavior.nextMachineState, "
                "NormalizedSymbolicBehavior.eval_eflags]\n"
                "      rw [evalNormalizedFlags_extract_df, "
                "evalNormalizedFlags_extract_df]\n"
                f"      exact flagsRelated_of_contains region{source_index}.flagInputs "
                "originalState.eflags candidateState.eflags inputFlags (by decide)\n"
                "    · rfl\n"
            )
        else:
            raise StageAInputError(
                f"external call site {edge_id} has unsupported boundary flags"
            )
        source_target_ids = ", ".join(
            str(int(item["id"])) for item in source.get("code_targets", [])
        )
        source_value_ids = ", ".join(
            str(int(item["id"])) for item in source.get("values", [])
        )
        dispatch_definitions = ""
        dispatch_theorems = ""
        product_refinement = f"Or.inl {refinement_name}"
        if register_dispatch:
            dispatch_registers = site["dispatch_registers"]
            assert dispatch_registers is not None
            dispatch_definitions = (
                f"def {dispatch_claim_name} : ImportRegisterIndirectCallClaim := {{\n"
                f"  imported := {contract_name}.imported\n"
                f"  originalRegister := .{dispatch_registers['original']}\n"
                f"  candidateRegister := .{dispatch_registers['candidate']}\n"
                f"  continuationTargetId := {int(site['continuation_target_id'])}\n"
                "}\n\n"
                f"def {original_decoded_normalized} : NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior false region{source_index}.targets "
                f"{original_behavior_name}).get (by decide)\n\n"
                f"def {candidate_decoded_normalized} : NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior true region{source_index}.targets "
                f"{candidate_behavior_name}).get (by decide)\n\n"
                f"def {original_externalized} : SymbolicBehavior :=\n"
                f"  (externalizeRegisterImportCall {contract_name} "
                f".{dispatch_registers['original']} {original_behavior_name}).get "
                "(by decide)\n\n"
                f"def {candidate_externalized} : SymbolicBehavior :=\n"
                f"  (externalizeRegisterImportCall {contract_name} "
                f".{dispatch_registers['candidate']} {candidate_behavior_name}).get "
                "(by decide)\n\n"
            )
            dispatch_theorems = (
                f"theorem {original_decoded_normalized_checked} :\n"
                f"    normalizeSymbolicBehavior false region{source_index}.targets "
                f"{original_behavior_name} = some {original_decoded_normalized} := by decide\n\n"
                f"theorem {candidate_decoded_normalized_checked} :\n"
                f"    normalizeSymbolicBehavior true region{source_index}.targets "
                f"{candidate_behavior_name} = some {candidate_decoded_normalized} := by decide\n\n"
                f"theorem {target_closed_name} :\n"
                f"    ImportRegisterIndirectCallTargetsClosed "
                f"region{source_index}.inputInvariant {original_decoded_normalized} "
                f"{candidate_decoded_normalized} {dispatch_claim_name} :=\n"
                "  importRegisterIndirectCallTargetsClosed_of_checked "
                f"region{source_index}.inputInvariant {original_decoded_normalized} "
                f"{candidate_decoded_normalized} {dispatch_claim_name} (by decide)\n\n"
                f"theorem {original_externalized_checked} :\n"
                f"    externalizeRegisterImportCall {contract_name} "
                f".{dispatch_registers['original']} {original_behavior_name} = "
                f"some {original_externalized} := by decide\n\n"
                f"theorem {candidate_externalized_checked} :\n"
                f"    externalizeRegisterImportCall {contract_name} "
                f".{dispatch_registers['candidate']} {candidate_behavior_name} = "
                f"some {candidate_externalized} := by decide\n\n"
            )
            product_refinement = f"Or.inr {refinement_name}"

        argument_claim_definitions: list[str] = []
        argument_fact_rows: list[str] = []
        argument_fact_names: list[str] = []
        for argument_index, claim in enumerate(site["argument_relation_claims"]):
            claim_name = f"{prefix}ArgumentClaim{argument_index}"
            fact_name = f"{prefix}ArgumentRelated{argument_index}"
            argument_fact_names.append(fact_name)
            if claim["kind"] == "dynamic_related_word_read":
                argument_claim_definitions.append(
                    f"def {claim_name} : DynamicRangeArgumentClaim := "
                    f"{_lean_dynamic_range_argument_claim(claim)}"
                )
                argument_fact_rows.append(
                    f"  have {fact_name} := dynamicRangeArgumentWordsRelated_of_checked\n"
                    f"    staticProofContext world region{source_index}.inputInvariant\n"
                    f"    ({_lean_semantic_expr(claim['original_expression'])})\n"
                    f"    ({_lean_semantic_expr(claim['candidate_expression'])}) "
                    f"{claim_name} (by decide) originalState candidateState related"
                )
            elif claim["kind"] == "stack_word_read":
                argument_claim_definitions.append(
                    f"def {claim_name} : StackWindowArgumentClaim := "
                    f"{_lean_stack_window_argument_claim(claim)}"
                )
                argument_fact_rows.append(
                    f"  have {fact_name} := stackWindowArgumentWordsRelated_of_checked\n"
                    f"    staticProofContext world region{source_index}.inputInvariant\n"
                    f"    ({_lean_semantic_expr(claim['original_expression'])})\n"
                    f"    ({_lean_semantic_expr(claim['candidate_expression'])}) "
                    f"{claim_name} (by decide) originalState candidateState related"
                )
            elif claim["kind"] == "register_word":
                argument_claim_definitions.append(
                    f"def {claim_name} : RegisterArgumentClaim := "
                    f"{_lean_register_argument_claim(claim)}"
                )
                argument_fact_rows.append(
                    f"  have {fact_name} := registerArgumentWordsRelated_of_checked\n"
                    f"    staticProofContext world region{source_index}.inputInvariant\n"
                    f"    ({_lean_semantic_expr(claim['original_expression'])})\n"
                    f"    ({_lean_semantic_expr(claim['candidate_expression'])}) "
                    f"{claim_name} (by decide) originalState candidateState related"
                )
            elif claim["kind"] == "self":
                argument_fact_rows.append(
                    f"  have {fact_name} :\n"
                    "      wordRelated staticProofContext.originalPe.imageBase\n"
                    "        staticProofContext.candidatePe.imageBase\n"
                    "        staticProofContext.codeMap.entries.toList\n"
                    "        (staticProofContext.relationalValueTargets world)\n"
                    f"        (({_lean_semantic_expr(claim['original_expression'])}).eval "
                    "originalState)\n"
                    f"        (({_lean_semantic_expr(claim['candidate_expression'])}).eval "
                    "candidateState) = true := by\n"
                    "    simp [StageA.Formal.Expr.eval]"
                )
            else:
                raise StageAInputError(
                    f"external call site {edge_id} has unsupported argument relation "
                    f"{claim['kind']}"
                )
        argument_list_proof = "(by rfl)"
        for fact_name in reversed(argument_fact_names):
            argument_list_proof = (
                f"wordsRelated_cons_of_true {fact_name} ({argument_list_proof})"
            )
        argument_setup = (
            ("\n".join(argument_fact_rows) + "\n")
            + "  have argumentWordsRelated :\n"
            "      wordsRelated staticProofContext.originalPe.imageBase\n"
            "        staticProofContext.candidatePe.imageBase\n"
            "        staticProofContext.codeMap.entries.toList\n"
            "        (staticProofContext.relationalValueTargets world)\n"
            f"        {original_argument_words} {candidate_argument_words} = true := by\n"
            f"    exact {argument_list_proof}\n"
        )

        import_claim_definitions: list[str] = []
        import_fact_rows: list[str] = []
        import_fact_names: list[str] = []
        for claim_index, claim in enumerate(site["import_transfer_claims"]):
            claim_name = f"{prefix}ImportClaim{claim_index}"
            fact_name = f"{prefix}ImportFact{claim_index}"
            import_fact_names.append(fact_name)
            import_claim_definitions.append(
                f"def {claim_name} : ImportRegisterPreserveClaim := {{\n"
                f"  imported := {_lean_external_target(claim['import'])}\n"
                f"  sourceOriginalRegister := .{claim['source_original_register']}\n"
                f"  sourceCandidateRegister := .{claim['source_candidate_register']}\n"
                f"  targetOriginalRegister := .{claim['target_original_register']}\n"
                f"  targetCandidateRegister := .{claim['target_candidate_register']}\n"
                "}"
            )
            import_fact_rows.append(
                f"  have {fact_name} := importRegisterPreserveOutputHolds_of_checked\n"
                f"    staticProofContext world region{source_index}.inputInvariant\n"
                f"    externalCallSite{edge_id}.boundaryInvariant {original_normalized}\n"
                f"    {candidate_normalized} {claim_name} (by decide)\n"
                "    originalState candidateState relatedForRegisterTransfer"
            )
        dynamic_claim_definitions: list[str] = []
        dynamic_fact_rows: list[str] = []
        dynamic_fact_names: list[str] = []
        for claim_index, claim in enumerate(site["dynamic_transfer_claims"]):
            claim_name = f"{prefix}DynamicClaim{claim_index}"
            fact_name = f"{prefix}DynamicFact{claim_index}"
            dynamic_fact_names.append(fact_name)
            dynamic_claim_definitions.append(
                f"def {claim_name} : DynamicRegisterRangePreserveClaim := {{\n"
                f"  sourceRelation := {_lean_dynamic_range_relation(claim['source_relation'])}\n"
                f"  targetRelation := {_lean_dynamic_range_relation(claim['target_relation'])}\n"
                "}"
            )
            dynamic_fact_rows.append(
                f"  have {fact_name} := "
                "dynamicRegisterRangePreserveOutputActiveHolds_of_checked\n"
                f"    staticProofContext world region{source_index}.inputInvariant\n"
                f"    externalCallSite{edge_id}.boundaryInvariant {original_normalized}\n"
                f"    {candidate_normalized} {claim_name} (by decide) "
                "(by decide) (by decide)\n"
                "    originalState candidateState relatedForRegisterTransfer"
            )
        boundary_fact_setup = "\n".join([*import_fact_rows, *dynamic_fact_rows])
        if boundary_fact_setup:
            boundary_fact_setup += "\n"
        import_boundary_proof = (
            "  · simpa [externalCallSite" + str(edge_id)
            + ", importRegisterRelationsHold, "
            "ImportRegisterPreserveClaim.targetRelation] using "
            + (import_fact_names[0] if len(import_fact_names) == 1 else
               "\u27e8" + ", ".join(import_fact_names) + "\u27e9")
            + "\n"
            if import_fact_names else
            f"  · simp [externalCallSite{edge_id}, importRegisterRelationsHold]\n"
        )
        dynamic_boundary_proof = (
            f"  · simpa [externalCallSite{edge_id}, "
            "activeDynamicRegisterRangeRelationsHold] using "
            + (dynamic_fact_names[0] if len(dynamic_fact_names) == 1 else
               "\u27e8" + ", ".join(dynamic_fact_names) + "\u27e9")
            + "\n\n"
            if dynamic_fact_names else
            f"  · simp [externalCallSite{edge_id}, "
            "activeDynamicRegisterRangeRelationsHold]\n\n"
        )
        support_definitions = dispatch_definitions + "\n\n".join([
            *argument_claim_definitions,
            *import_claim_definitions,
            *dynamic_claim_definitions,
        ])
        if support_definitions:
            support_definitions += "\n\n"
        if register_dispatch:
            refinement_source = (
                f"theorem {refinement_name} :\n"
                f"    RelationalRegisterExternalCallRefinement staticProofContext "
                f"externalCallSite{edge_id} {edge_name} "
                f"region{source_index}.inputInvariant := by\n"
                "  unfold RelationalRegisterExternalCallRefinement\n"
                f"  rw [{local_code_targets}]\n"
                f"  refine \u27e8{contract_name}, {original_behavior_name}, "
                f"{candidate_behavior_name}, {original_decoded_normalized}, "
                f"{candidate_decoded_normalized}, {original_externalized}, "
                f"{candidate_externalized}, {dispatch_claim_name}, "
                f"{contract_resolved}, rfl, rfl, rfl, {original_decoded}, "
                f"{candidate_decoded}, {original_decoded_normalized_checked}, "
                f"{candidate_decoded_normalized_checked}, {target_closed_name}, "
                f"{original_externalized_checked}, {candidate_externalized_checked}, "
                f"{transition_name}\u27e9\n\n"
            )
        else:
            refinement_source = (
                f"theorem {refinement_name} :\n"
                f"    RelationalExternalCallRefinement staticProofContext "
                f"externalCallSite{edge_id} {edge_name} "
                f"region{source_index}.inputInvariant := by\n"
                f"  refine \u27e8{contract_name}, {original_behavior_name}, "
                f"{candidate_behavior_name}, {contract_resolved}, rfl, "
                f"{original_decoded}, {candidate_decoded}, {transition_name}\u27e9\n\n"
            )
        source_text = (
            "import StageA.RelationalExternalCallSites\n"
            "import StageA.RelationalProductGraphContext\n"
            f"import StageA.RelationalRegisterRelationsChunk{chunk_index}\n\n"
            f"import StageA.RelationalProofOriginalDecodeChunk{chunk_index}\n"
            f"import StageA.RelationalProofCandidateDecodeChunk{chunk_index}\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            f"def {contract_name} : MachineImportCallContract := "
            f"{_lean_machine_import_call_contract(machine_contract)}\n\n"
            f"def {edge_name} : RelationalSegmentEdge := {{\n"
            f"  sourceTargetId := {int(site['source_target_id'])}\n"
            f"  exit := .external {contract_name}.imported\n"
            f"  originalSpan := region{source_index}.original\n"
            f"  candidateSpan := region{source_index}.candidate\n"
            f"  localCodeTargetIds := [{source_target_ids}]\n"
            f"  localValueTargetIds := [{source_value_ids}]\n"
            f"  originalGuard := {_lean_semantic_bool_expr(graph_edge['original_guard'])}\n"
            f"  candidateGuard := {_lean_semantic_bool_expr(graph_edge['candidate_guard'])}\n"
            "}\n\n"
            + support_definitions
            + f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
            f"  (normalizeSymbolicBehavior false region{source_index}.targets "
            f"{proof_original_behavior}).get (by decide)\n\n"
            f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
            f"  (normalizeSymbolicBehavior true region{source_index}.targets "
            f"{proof_candidate_behavior}).get (by decide)\n\n"
            f"def {output_claims_name} : List InvariantWP.RegisterOutputClaim := "
            f"[{output_claims}]\n\n"
            f"theorem {local_code_targets} :\n"
            f"    staticProofContext.codeMap.resolveIds {edge_name}.localCodeTargetIds = "
            f"some region{source_index}.targets := by decide\n\n"
            f"theorem {local_values} :\n"
            f"    staticProofContext.dataMap.resolveIds {edge_name}.localValueTargetIds = "
            f"some region{source_index}.values := by decide\n\n"
            f"theorem {contract_resolved} :\n"
            f"    machineImportCallContractById? staticProofContext "
            f"{int(site['machine_contract_id'])} = some {contract_name} := by decide\n\n"
            f"theorem {original_normalized_checked} :\n"
            f"    normalizeSymbolicBehavior false region{source_index}.targets "
            f"{proof_original_behavior} = some {original_normalized} := by decide\n\n"
            f"theorem {candidate_normalized_checked} :\n"
            f"    normalizeSymbolicBehavior true region{source_index}.targets "
            f"{proof_candidate_behavior} = some {candidate_normalized} := by decide\n\n"
            + dispatch_theorems
            + f"theorem {original_x87_checked} :\n"
            f"    {original_normalized}.x87 = {original_x87} := by decide\n\n"
            f"theorem {candidate_x87_checked} :\n"
            f"    {candidate_normalized}.x87 = {candidate_x87} := by decide\n\n"
            f"theorem {original_outcome_checked} :\n"
            f"    {original_normalized}.outcome = .externalCall "
            f"{contract_name}.imported {argument_expressions} "
            f"{int(site['continuation_target_id'])} := by decide\n\n"
            f"theorem {candidate_outcome_checked} :\n"
            f"    {candidate_normalized}.outcome = .externalCall "
            f"{contract_name}.imported {argument_expressions} "
            f"{int(site['continuation_target_id'])} := by decide\n\n"
            f"theorem {original_decoded} :\n"
            "    regionBehaviorWithMachineCallContracts staticProofContext.originalPe "
            "staticProofContext.originalImports staticProofContext.machineImportCallContracts "
            f"{edge_name}.originalSpan = some originalBehavior{source_index} := by\n"
            f"  simpa [{edge_name}, staticProofContext, "
            f"originalMachineImportCallContractsChunk{chunk_index}] using "
            f"originalBehavior{source_index}CheckedDecoded\n\n"
            f"theorem {candidate_decoded} :\n"
            "    regionBehaviorWithMachineCallContracts staticProofContext.candidatePe "
            "staticProofContext.candidateImports staticProofContext.machineImportCallContracts "
            f"{edge_name}.candidateSpan = some candidateBehavior{source_index} := by\n"
            f"  simpa [{edge_name}, staticProofContext, "
            f"candidateMachineImportCallContractsChunk{chunk_index}] using "
            f"candidateBehavior{source_index}CheckedDecoded\n\n"
            f"theorem {shape_name} :\n"
            f"    ExternalCallShapeClosed staticProofContext externalCallSite{edge_id} "
            f"{contract_name} {edge_name} region{source_index}.inputInvariant\n"
            f"      {proof_original_behavior} {proof_candidate_behavior} := by\n"
            "  unfold ExternalCallShapeClosed\n"
            f"  rw [{local_code_targets}, {local_values}]\n"
            "  intro world originalState candidateState related\n"
            + argument_setup
            + "  refine \u27e8rfl, ?_\u27e9\n"
            "  intro _guardTrue\n"
            f"  refine \u27e8{original_normalized}.eval originalState, "
            f"{candidate_normalized}.eval candidateState, {original_argument_words}, "
            f"{candidate_argument_words}, ?_, ?_, ?_, ?_, ?_, ?_, ?_\u27e9\n"
            "  · unfold evalBehavior\n"
            f"    rw [{original_normalized_checked}]\n"
            "    rfl\n"
            "  · unfold evalBehavior\n"
            f"    rw [{candidate_normalized_checked}]\n"
            "    rfl\n"
            f"  · simp only [NormalizedSymbolicBehavior.eval_outcome, "
            f"{original_outcome_checked}, NormalizedOutcomeExpr.eval, "
            "StageA.Formal.Expr.eval, List.map_cons, List.map_nil]\n"
            f"    simpa [externalCallSite{edge_id}]\n"
            f"  · simp only [NormalizedSymbolicBehavior.eval_outcome, "
            f"{candidate_outcome_checked}, NormalizedOutcomeExpr.eval, "
            "StageA.Formal.Expr.eval, List.map_cons, List.map_nil]\n"
            f"    simpa [externalCallSite{edge_id}]\n"
            f"  · rfl\n"
            f"  · simpa [{original_outcome_checked}, {candidate_outcome_checked}, "
            "NormalizedOutcomeExpr.eval, StageA.Formal.Expr.eval, outcomesRelated] "
            "using argumentWordsRelated\n"
            "  · unfold externalCallArgumentsRelated\n"
            "    exact argumentWordsRelated\n\n"
            f"theorem {boundary_name} :\n"
            f"    ExternalBoundaryTransferClosed staticProofContext "
            f"externalCallSite{edge_id} {edge_name} region{source_index}.inputInvariant\n"
            f"      {proof_original_behavior} {proof_candidate_behavior} := by\n"
            "  unfold ExternalBoundaryTransferClosed\n"
            f"  rw [{local_code_targets}]\n"
            "  intro world originalState candidateState originalResult candidateResult related\n"
            "    originalEval candidateEval\n"
            f"  simp [evalBehavior, {original_normalized_checked}] at originalEval\n"
            f"  simp [evalBehavior, {candidate_normalized_checked}] at candidateEval\n"
            "  subst originalResult\n"
            "  subst candidateResult\n"
            "  have relatedForRegisterTransfer := related\n"
            "  rcases related with \u27e8worldValid, stackRangesValid, _stackMemory, "
            "_importsStatic, _importsComplete, _importsMemory, _originalImmutable, "
            "_candidateImmutable, relatedCore, importDynamic\u27e9\n"
            "  rcases relatedCore with \u27e8inputRegisters, inputBounds, "
            "inputSeparations, inputStackWindows, inputMemory, _inputDynamicWords, "
            "inputUndefined, inputX87, inputFlags, inputFsBase\u27e9\n"
            + boundary_fact_setup
            + "  have outputStackWindows := "
            "stackWindowsRelated_after_affine_of_checked staticProofContext world "
            f"region{source_index}.inputInvariant "
            f"externalCallSite{edge_id}.boundaryInvariant {original_normalized} "
            f"{candidate_normalized} [{stack_claims}] originalState candidateState "
            "stackRangesValid inputStackWindows (by decide)\n"
            "  refine \u27e8worldValid, stackRangesValid, ?_, ?_, ?_, ?_, ?_, ?_, "
            "?_, ?_, ?_, ?_, ?_\u27e9\n"
            "  · exact InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
            f"      staticProofContext world region{source_index} {original_normalized} "
            f"{candidate_normalized} {output_claims_name} (by decide)\n"
            "      originalState candidateState relatedForRegisterTransfer\n"
            f"  · simp [{edge_name}, externalCallSite{edge_id}, boundsRelated]\n"
            f"  · simp [{edge_name}, externalCallSite{edge_id}, "
            "addressSeparationsRelated]\n"
            "  · exact outputStackWindows\n"
            "  · simpa [RelationalBehavior.nextMachineState] using inputUndefined\n"
            "  · rcases originalState with \u27e8originalRegisters, originalMemory, "
            "originalUndefined, originalX87, originalFlags, originalFsBase\u27e9\n"
            "    rcases candidateState with \u27e8candidateRegisters, candidateMemory, "
            "candidateUndefined, candidateX87, candidateFlags, candidateFsBase\u27e9\n"
            "    change originalX87 = candidateX87 at inputX87\n"
            "    subst candidateX87\n"
            f"    simp [RelationalBehavior.nextMachineState, {original_x87_checked}, "
            f"{candidate_x87_checked}, evalNormalizedX87, "
            "StageA.Formal.X87Expr.eval, StageA.Formal.Expr.eval]\n"
            + flag_proof
            + "  · simpa [RelationalBehavior.nextMachineState] using inputFsBase\n"
            + import_boundary_proof
            + dynamic_boundary_proof
            + f"  · simp [externalCallSite{edge_id}, "
            "activeDynamicStackRangeRelationsHold]\n\n"
            + f"theorem {transition_name} :\n"
            f"    ExternalCallTransitionClosed staticProofContext "
            f"externalCallSite{edge_id} {contract_name} {edge_name} "
            f"region{source_index}.inputInvariant {proof_original_behavior} "
            f"{proof_candidate_behavior} :=\n"
            "  externalCallTransitionClosed_of_shape_and_transfer "
            f"staticProofContext externalCallSite{edge_id} {contract_name} "
            f"{edge_name} region{source_index}.inputInvariant "
            f"{proof_original_behavior} {proof_candidate_behavior} "
            f"{shape_name} {boundary_name}\n\n"
            + refinement_source
            + f"theorem {product_resolved_name} :\n"
            f"    relationalProductGraph.getEdge? {edge_id} = "
            f"some relationalProductGraph.edges[{edge_id}] := by decide\n\n"
            f"theorem {product_name} :\n"
            f"    RelationalExternalProductEdgeRefinement staticProofContext "
            f"relationalProductGraph {edge_id} externalCallSite{edge_id} "
            f"{edge_name} region{source_index}.inputInvariant := by\n"
            "  unfold RelationalExternalProductEdgeRefinement\n"
            f"  rw [{product_resolved_name}]\n"
            f"  exact \u27e8rfl, rfl, rfl, {product_refinement}\u27e9\n\n"
            "end StageA.GeneratedRelational\n"
        )
        module = f"RelationalExternalCallRefinementEdge{edge_id}"
        _write_text_if_changed(
            lean_dir / "StageA" / f"{module}.lean", source_text
        )
        modules.append({
            "module": module,
            "edge_id": edge_id,
            "source_region_index": source_index,
            "theorem": product_name,
            "proposition": (
                "RelationalExternalProductEdgeRefinement staticProofContext "
                f"relationalProductGraph {edge_id} externalCallSite{edge_id} "
                f"{edge_name} region{source_index}.inputInvariant"
            ),
        })

    certificate_type = " \u2227 ".join(
        [item["proposition"] for item in modules] + ["True"]
    )
    certificate_proof = (
        "".join(f"And.intro {item['theorem']} (" for item in modules)
        + "True.intro"
        + ")" * len(modules)
    )
    certificate_source = (
        "".join(f"import StageA.{item['module']}\n" for item in modules)
        + "import StageA.RelationalEnvironment\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        f"def GeneratedExternalCallRefinementCertificate : Prop := "
        f"{certificate_type}\n\n"
        "theorem generatedExternalCallRefinementCertificateChecked :\n"
        "    GeneratedExternalCallRefinementCertificate := by\n"
        f"  exact {certificate_proof}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalExternalCallRefinementCertificate.lean",
        certificate_source,
    )
    return modules


def _write_relational_external_jump_refinement_modules(
    lean_dir: Path,
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
    decode_chunk_regions: list[list[int]],
    import_call_candidates: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    analysis = _external_call_site_candidates(
        contract, behaviors, register_relations, import_call_candidates
    )
    chunk_by_region = {
        region_index: chunk_index
        for chunk_index, region_indices in enumerate(decode_chunk_regions)
        for region_index in region_indices
    }
    contracts_by_id = {
        int(item["id"]): item
        for item in contract.get("machine_import_call_contracts", [])
    }
    modules: list[dict[str, Any]] = []
    for site in analysis["candidates"]:
        if site.get("site_kind") != "direct_import_thunk":
            continue
        site_id = int(site["id"])
        source_index = int(site["source_region_index"])
        machine_contract = contracts_by_id.get(int(site["machine_contract_id"]))
        if machine_contract is None:
            raise StageAInputError(
                f"external jump site {site_id} has no machine contract"
            )
        chunk_index = chunk_by_region[source_index]
        prefix = f"externalJumpSite{site_id}"
        contract_name = f"{prefix}MachineContract"
        original_normalized = f"{prefix}OriginalNormalized"
        candidate_normalized = f"{prefix}CandidateNormalized"
        original_boundary = f"{prefix}OriginalBoundaryNormalized"
        candidate_boundary = f"{prefix}CandidateBoundaryNormalized"
        output_claims_name = f"{prefix}RegisterOutputClaims"
        contract_resolved = f"{prefix}MachineContractResolved"
        original_normalized_checked = f"{prefix}OriginalNormalizedChecked"
        candidate_normalized_checked = f"{prefix}CandidateNormalizedChecked"
        original_x87_checked = f"{prefix}OriginalX87Checked"
        candidate_x87_checked = f"{prefix}CandidateX87Checked"
        original_outcome_checked = f"{prefix}OriginalOutcomeChecked"
        candidate_outcome_checked = f"{prefix}CandidateOutcomeChecked"
        original_decoded = f"{prefix}OriginalDecoded"
        candidate_decoded = f"{prefix}CandidateDecoded"
        shape_name = f"{prefix}ShapeChecked"
        boundary_name = f"{prefix}BoundaryTransferChecked"
        transition_name = f"{prefix}TransitionChecked"
        refinement_name = f"{prefix}RefinementChecked"
        original_argument_words = "[" + ", ".join(
            f"({_lean_semantic_expr(expression)}).eval originalState"
            for expression in site["argument_expressions"]
        ) + "]"
        candidate_argument_words = "[" + ", ".join(
            f"({_lean_semantic_expr(expression)}).eval candidateState"
            for expression in site["argument_expressions"]
        ) + "]"
        argument_expressions = "[" + ", ".join(
            _lean_semantic_expr(expression)
            for expression in site["argument_expressions"]
        ) + "]"
        output_claims = ", ".join(
            _lean_register_output_claim(claim)
            for claim in site["register_output_claims"]
        )
        stack_claims = ", ".join(
            _lean_stack_window_transfer_claim(claim)
            for claim in site["stack_transfer_claims"]
        )

        argument_claim_definitions: list[str] = []
        argument_fact_rows: list[str] = []
        argument_fact_names: list[str] = []
        for argument_index, claim in enumerate(site["argument_relation_claims"]):
            claim_name = f"{prefix}ArgumentClaim{argument_index}"
            fact_name = f"{prefix}ArgumentRelated{argument_index}"
            argument_fact_names.append(fact_name)
            if claim["kind"] == "dynamic_related_word_read":
                argument_claim_definitions.append(
                    f"def {claim_name} : DynamicRangeArgumentClaim := "
                    f"{_lean_dynamic_range_argument_claim(claim)}"
                )
                argument_fact_rows.append(
                    f"  have {fact_name} := dynamicRangeArgumentWordsRelated_of_checked\n"
                    f"    staticProofContext world region{source_index}.inputInvariant\n"
                    f"    ({_lean_semantic_expr(claim['original_expression'])})\n"
                    f"    ({_lean_semantic_expr(claim['candidate_expression'])}) "
                    f"{claim_name} (by decide) originalState candidateState related"
                )
            elif claim["kind"] == "stack_word_read":
                argument_claim_definitions.append(
                    f"def {claim_name} : StackWindowArgumentClaim := "
                    f"{_lean_stack_window_argument_claim(claim)}"
                )
                argument_fact_rows.append(
                    f"  have {fact_name} := stackWindowArgumentWordsRelated_of_checked\n"
                    f"    staticProofContext world region{source_index}.inputInvariant\n"
                    f"    ({_lean_semantic_expr(claim['original_expression'])})\n"
                    f"    ({_lean_semantic_expr(claim['candidate_expression'])}) "
                    f"{claim_name} (by decide) originalState candidateState related"
                )
            elif claim["kind"] == "register_word":
                argument_claim_definitions.append(
                    f"def {claim_name} : RegisterArgumentClaim := "
                    f"{_lean_register_argument_claim(claim)}"
                )
                argument_fact_rows.append(
                    f"  have {fact_name} := registerArgumentWordsRelated_of_checked\n"
                    f"    staticProofContext world region{source_index}.inputInvariant\n"
                    f"    ({_lean_semantic_expr(claim['original_expression'])})\n"
                    f"    ({_lean_semantic_expr(claim['candidate_expression'])}) "
                    f"{claim_name} (by decide) originalState candidateState related"
                )
            elif claim["kind"] == "self":
                argument_fact_rows.append(
                    f"  have {fact_name} :\n"
                    "      wordRelated staticProofContext.originalPe.imageBase\n"
                    "        staticProofContext.candidatePe.imageBase\n"
                    "        staticProofContext.codeMap.entries.toList\n"
                    "        (staticProofContext.relationalValueTargets world)\n"
                    f"        (({_lean_semantic_expr(claim['original_expression'])}).eval "
                    "originalState)\n"
                    f"        (({_lean_semantic_expr(claim['candidate_expression'])}).eval "
                    "candidateState) = true := by\n"
                    "    simp [StageA.Formal.Expr.eval]"
                )
            else:
                raise StageAInputError(
                    f"external jump site {site_id} has unsupported argument relation "
                    f"{claim['kind']}"
                )
        argument_list_proof = "(by rfl)"
        for fact_name in reversed(argument_fact_names):
            argument_list_proof = (
                f"wordsRelated_cons_of_true {fact_name} ({argument_list_proof})"
            )
        argument_setup = (
            ("\n".join(argument_fact_rows) + "\n")
            + "  have argumentWordsRelated :\n"
            "      wordsRelated staticProofContext.originalPe.imageBase\n"
            "        staticProofContext.candidatePe.imageBase\n"
            "        staticProofContext.codeMap.entries.toList\n"
            "        (staticProofContext.relationalValueTargets world)\n"
            f"        {original_argument_words} {candidate_argument_words} = true := by\n"
            f"    exact {argument_list_proof}\n"
        )
        support_definitions = "\n\n".join(argument_claim_definitions)
        if support_definitions:
            support_definitions += "\n\n"
        original_x87 = _lean_symbolic_x87_state(
            behaviors[source_index]["original_ir"]["x87"]
        )
        candidate_x87 = _lean_symbolic_x87_state(
            behaviors[source_index]["candidate_ir"]["x87"]
        )
        flag_bits = site["boundary_invariant"].get("flag_bits", [])
        if flag_bits == []:
            flag_proof = "  · rfl\n"
        elif flag_bits == [10]:
            flag_proof = (
                "  · apply flagsRelated_cons_of_eq\n"
                "    · simp only [normalizeImportReturnSlotState, "
                "RelationalBehavior.nextMachineState, "
                "NormalizedSymbolicBehavior.eval_eflags]\n"
                "      rw [evalNormalizedFlags_extract_df, "
                "evalNormalizedFlags_extract_df]\n"
                f"      exact flagsRelated_of_contains region{source_index}.flagInputs "
                "originalState.eflags candidateState.eflags inputFlags (by decide)\n"
                "    · rfl\n"
            )
        else:
            raise StageAInputError(
                f"external jump site {site_id} has unsupported boundary flags"
            )

        source_text = (
            "import StageA.RelationalExternalCallSites\n"
            f"import StageA.RelationalRegisterRelationsChunk{chunk_index}\n"
            f"import StageA.RelationalProofOriginalDecodeChunk{chunk_index}\n"
            f"import StageA.RelationalProofCandidateDecodeChunk{chunk_index}\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
            "set_option linter.unusedSimpArgs false\n\n"
            f"def {contract_name} : MachineImportCallContract := "
            f"{_lean_machine_import_call_contract(machine_contract)}\n\n"
            + support_definitions
            + f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
            f"  (normalizeSymbolicBehavior false region{source_index}.targets "
            f"originalBehavior{source_index}).get (by decide)\n\n"
            f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
            f"  (normalizeSymbolicBehavior true region{source_index}.targets "
            f"candidateBehavior{source_index}).get (by decide)\n\n"
            f"def {original_boundary} : NormalizedSymbolicBehavior := {{\n"
            f"  {original_normalized} with\n"
            f"  registers := {original_normalized}.registers.set .esp\n"
            f"    ({original_normalized}.registers.esp.offset 4)\n"
            "}\n\n"
            f"def {candidate_boundary} : NormalizedSymbolicBehavior := {{\n"
            f"  {candidate_normalized} with\n"
            f"  registers := {candidate_normalized}.registers.set .esp\n"
            f"    ({candidate_normalized}.registers.esp.offset 4)\n"
            "}\n\n"
            f"def {output_claims_name} : List InvariantWP.RegisterOutputClaim := "
            f"[{output_claims}]\n\n"
            f"theorem {contract_resolved} :\n"
            "    machineImportCallContractById? staticProofContext "
            f"{int(site['machine_contract_id'])} = some {contract_name} := by decide\n\n"
            f"theorem {original_normalized_checked} :\n"
            f"    normalizeSymbolicBehavior false region{source_index}.targets "
            f"originalBehavior{source_index} = some {original_normalized} := by decide\n\n"
            f"theorem {candidate_normalized_checked} :\n"
            f"    normalizeSymbolicBehavior true region{source_index}.targets "
            f"candidateBehavior{source_index} = some {candidate_normalized} := by decide\n\n"
            f"theorem {original_x87_checked} :\n"
            f"    {original_normalized}.x87 = originalBehavior{source_index}.x87 := by "
            "decide\n\n"
            f"theorem {candidate_x87_checked} :\n"
            f"    {candidate_normalized}.x87 = candidateBehavior{source_index}.x87 := by "
            "decide\n\n"
            f"theorem {original_outcome_checked} :\n"
            f"    {original_normalized}.outcome = .externalJump "
            f"{contract_name}.imported {argument_expressions} := by decide\n\n"
            f"theorem {candidate_outcome_checked} :\n"
            f"    {candidate_normalized}.outcome = .externalJump "
            f"{contract_name}.imported {argument_expressions} := by decide\n\n"
            f"theorem {original_decoded} :\n"
            "    regionBehaviorWithMachineCallContracts staticProofContext.originalPe "
            "staticProofContext.originalImports staticProofContext.machineImportCallContracts "
            f"region{source_index}.original = some originalBehavior{source_index} := by\n"
            f"  simpa [staticProofContext, originalMachineImportCallContractsChunk{chunk_index}] "
            f"using originalBehavior{source_index}CheckedDecoded\n\n"
            f"theorem {candidate_decoded} :\n"
            "    regionBehaviorWithMachineCallContracts staticProofContext.candidatePe "
            "staticProofContext.candidateImports staticProofContext.machineImportCallContracts "
            f"region{source_index}.candidate = some candidateBehavior{source_index} := by\n"
            f"  simpa [staticProofContext, candidateMachineImportCallContractsChunk{chunk_index}] "
            f"using candidateBehavior{source_index}CheckedDecoded\n\n"
            f"theorem {shape_name} :\n"
            f"    ExternalJumpShapeClosed staticProofContext externalCallSite{site_id} "
            f"{contract_name} region{source_index} originalBehavior{source_index} "
            f"candidateBehavior{source_index} := by\n"
            "  unfold ExternalJumpShapeClosed\n"
            "  intro world originalState candidateState related\n"
            + argument_setup
            + f"  simp only [evalBehavior, {original_normalized_checked}, "
            f"{candidate_normalized_checked}, Option.bind_some]\n"
            f"  refine ⟨{original_argument_words}, {candidate_argument_words}, ?_, ?_, ?_⟩\n"
            f"  · simp only [NormalizedSymbolicBehavior.eval_outcome, "
            f"{original_outcome_checked}, NormalizedOutcomeExpr.eval, "
            "StageA.Formal.Expr.eval, List.map_cons, List.map_nil]\n"
            f"  · simp only [NormalizedSymbolicBehavior.eval_outcome, "
            f"{candidate_outcome_checked}, NormalizedOutcomeExpr.eval, "
            "StageA.Formal.Expr.eval, List.map_cons, List.map_nil]\n"
            "  · unfold externalCallArgumentsRelated\n"
            "    exact argumentWordsRelated\n\n"
            f"theorem {boundary_name} :\n"
            f"    ExternalJumpBoundaryTransferClosed staticProofContext "
            f"externalCallSite{site_id} region{source_index} originalBehavior{source_index} "
            f"candidateBehavior{source_index} := by\n"
            "  unfold ExternalJumpBoundaryTransferClosed\n"
            "  intro world originalState candidateState originalResult candidateResult related\n"
            "    originalEval candidateEval\n"
            f"  simp [evalBehavior, {original_normalized_checked}] at originalEval\n"
            f"  simp [evalBehavior, {candidate_normalized_checked}] at candidateEval\n"
            "  subst originalResult\n"
            "  subst candidateResult\n"
            "  have relatedForRegisterTransfer := related\n"
            "  rcases related with ⟨worldValid, stackRangesValid, _stackMemory, "
            "_importsStatic, _importsComplete, _importsMemory, _originalImmutable, "
            "_candidateImmutable, relatedCore, _importDynamic⟩\n"
            "  rcases relatedCore with ⟨_inputRegisters, _inputBounds, "
            "_inputSeparations, inputStackWindows, _inputMemory, _inputDynamicWords, "
            "inputUndefined, inputX87, inputFlags, inputFsBase⟩\n"
            "  have outputRegistersRaw := "
            "InvariantWP.registerRelationsHold_of_nonMemoryOutputClaims\n"
            f"    staticProofContext world region{source_index} {original_boundary} "
            f"{candidate_boundary} {output_claims_name} (by decide)\n"
            "    originalState candidateState relatedForRegisterTransfer\n"
            "  have outputRegisters : registerRelationsHold\n"
            "      staticProofContext.originalPe.imageBase\n"
            "      staticProofContext.candidatePe.imageBase\n"
            "      staticProofContext.codeMap.entries.toList\n"
            "      (staticProofContext.relationalValueTargets world)\n"
            f"      externalCallSite{site_id}.boundaryInvariant.registerRelations\n"
            f"      (normalizeImportReturnSlotState (({original_normalized}.eval "
            "        originalState).nextMachineState originalState)).registers\n"
            f"      (normalizeImportReturnSlotState (({candidate_normalized}.eval "
            "        candidateState).nextMachineState candidateState)).registers = true := by\n"
            f"    simpa [{original_boundary}, {candidate_boundary}, "
            "normalizeImportReturnSlotState, RelationalBehavior.nextMachineState, "
            "NormalizedSymbolicBehavior.eval, evalNormalizedRegisters, "
            "Registers.set, StageA.Formal.Expr.eval] using outputRegistersRaw\n"
            "  have outputStackWindowsRaw := "
            "stackWindowsRelated_after_affine_of_checked staticProofContext world "
            f"region{source_index}.inputInvariant "
            f"externalCallSite{site_id}.boundaryInvariant {original_boundary} "
            f"{candidate_boundary} [{stack_claims}] originalState candidateState "
            "stackRangesValid inputStackWindows (by decide)\n"
            "  have outputStackWindows : stackWindowsRelated world\n"
            f"      externalCallSite{site_id}.boundaryInvariant.stackWindows\n"
            f"      (normalizeImportReturnSlotState (({original_normalized}.eval "
            "        originalState).nextMachineState originalState)).registers\n"
            f"      (normalizeImportReturnSlotState (({candidate_normalized}.eval "
            "        candidateState).nextMachineState candidateState)).registers = true := by\n"
            f"    simpa [{original_boundary}, {candidate_boundary}, "
            "normalizeImportReturnSlotState, RelationalBehavior.nextMachineState, "
            "NormalizedSymbolicBehavior.eval, evalNormalizedRegisters, "
            "Registers.set, StageA.Formal.Expr.eval] using outputStackWindowsRaw\n"
            "  refine ⟨worldValid, stackRangesValid, outputRegisters, ?_, ?_, "
            "outputStackWindows, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩\n"
            f"  · simp [externalCallSite{site_id}, boundsRelated]\n"
            f"  · simp [externalCallSite{site_id}, addressSeparationsRelated]\n"
            "  · simpa [normalizeImportReturnSlotState, "
            "RelationalBehavior.nextMachineState] using inputUndefined\n"
            "  · rcases originalState with ⟨originalRegisters, originalMemory, "
            "originalUndefined, originalX87, originalFlags, originalFsBase⟩\n"
            "    rcases candidateState with ⟨candidateRegisters, candidateMemory, "
            "candidateUndefined, candidateX87, candidateFlags, candidateFsBase⟩\n"
            "    change originalX87 = candidateX87 at inputX87\n"
            "    subst candidateX87\n"
            "    simp only [normalizeImportReturnSlotState, "
            "RelationalBehavior.nextMachineState, NormalizedSymbolicBehavior.eval_x87, "
            f"{original_x87_checked}, {candidate_x87_checked}]\n"
            f"    simp [evalNormalizedX87, originalBehavior{source_index}, "
            f"candidateBehavior{source_index}, "
            "StageA.Formal.X87Expr.eval, StageA.Formal.Expr.eval]\n"
            + flag_proof
            + "  · simpa [normalizeImportReturnSlotState, "
            "RelationalBehavior.nextMachineState] using inputFsBase\n"
            f"  · simp [externalCallSite{site_id}, importRegisterRelationsHold]\n"
            f"  · simp [externalCallSite{site_id}, "
            "activeDynamicRegisterRangeRelationsHold]\n"
            f"  · simp [externalCallSite{site_id}, "
            "activeDynamicStackRangeRelationsHold]\n\n"
            f"theorem {transition_name} :\n"
            f"    ExternalJumpTransitionClosed staticProofContext "
            f"externalCallSite{site_id} {contract_name} region{source_index} "
            f"originalBehavior{source_index} candidateBehavior{source_index} :=\n"
            "  externalJumpTransitionClosed_of_shape_and_transfer staticProofContext "
            f"externalCallSite{site_id} {contract_name} region{source_index} "
            f"originalBehavior{source_index} candidateBehavior{source_index} "
            f"{shape_name} {boundary_name}\n\n"
            f"theorem {refinement_name} :\n"
            f"    RelationalExternalJumpRefinement staticProofContext "
            f"externalCallSite{site_id} region{source_index} := by\n"
            "  unfold RelationalExternalJumpRefinement\n"
            f"  exact ⟨{contract_name}, originalBehavior{source_index}, "
            f"candidateBehavior{source_index}, {contract_resolved}, rfl, "
            f"{original_decoded}, {candidate_decoded}, {transition_name}⟩\n\n"
            "end StageA.GeneratedRelational\n"
        )
        module = f"RelationalExternalJumpRefinementSite{site_id}"
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source_text)
        modules.append({
            "module": module,
            "site_id": site_id,
            "source_region_index": source_index,
            "theorem": refinement_name,
            "proposition": (
                "RelationalExternalJumpRefinement staticProofContext "
                f"externalCallSite{site_id} region{source_index}"
            ),
        })

    certificate_type = " ∧ ".join(
        [item["proposition"] for item in modules] + ["True"]
    )
    certificate_proof = (
        "".join(f"And.intro {item['theorem']} (" for item in modules)
        + "True.intro"
        + ")" * len(modules)
    )
    certificate_source = (
        "".join(f"import StageA.{item['module']}\n" for item in modules)
        + "import StageA.RelationalEnvironment\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        f"def GeneratedExternalJumpRefinementCertificate : Prop := {certificate_type}\n\n"
        "theorem generatedExternalJumpRefinementCertificateChecked :\n"
        "    GeneratedExternalJumpRefinementCertificate := by\n"
        f"  exact {certificate_proof}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalExternalJumpRefinementCertificate.lean",
        certificate_source,
    )
    return modules
