from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from ...stage_binary import StageABinary, StageAInputError
from ..artifacts import write_text_if_changed as _write_text_if_changed
from ..schema import (
    FLAG_BITS,
    RELATIONAL_KERNEL_MODULES,
)


_LEAN_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "lean" / "StageA"
from .common import (
    _lean_bool,
    _lean_byte_tree_definitions,
    _lean_code_aliases,
    _lean_import_certificate,
    _lean_index_tree,
    _lean_padding_alias_certificate,
    _lean_pe,
    _lean_relocations,
    _lean_sorted_span_certificate,
    _lean_span,
    _side_coverage_spans,
    _side_padding,
)
from .expressions import (
    _lean_machine_import_call_contract,
    _lean_region_bound_setup,
    _lean_region_definition,
    _lean_region_flag_setup,
    _lean_region_index_masks,
    _lean_region_indexed_memory_fact_names,
    _lean_region_indexed_memory_lemma_specs,
    _lean_region_indexed_relocation_word_specs,
    _lean_region_memory_lemma_names,
    _lean_region_memory_lemmas,
    _lean_region_memory_setup,
    _lean_region_relocation_memory_setup,
    _lean_region_separation_setup,
    _lean_region_static_relocation_word_specs,
    _lean_static_dynamic_pointer_slot,
    _lean_static_word_relation_slot,
    _lean_semantic_expr,
    _lean_value_target,
)


def _copy_relational_kernel_sources(destination: Path) -> None:
    source_root = _LEAN_SOURCE_ROOT
    destination.mkdir(parents=True, exist_ok=True)
    for module in RELATIONAL_KERNEL_MODULES:
        _write_text_if_changed(
            destination / f"{module}.lean",
            (source_root / f"{module}.lean").read_text(encoding="utf-8"),
        )

def _lean_extraction_source(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    contract: dict[str, Any],
    *,
    requests: set[tuple[str, int]],
) -> str:
    evaluations: list[str] = []
    definitions: list[str] = []
    machine_call_contracts = ", ".join(
        _lean_machine_import_call_contract(item)
        for item in contract.get("machine_import_call_contracts", [])
    )
    definitions.append(
        "def machineImportCallContracts : List MachineImportCallContract := "
        f"[{machine_call_contracts}]"
    )
    for index, region in enumerate(contract["regions"]):
        if not any((side, index) in requests for side in ("original", "candidate")):
            continue
        definitions.append(_lean_region_definition(index, region))
        for side in ("original", "candidate"):
            if (side, index) not in requests:
                continue
            span = region[side]
            span_literal = f"{{ start := {span['rva_start']}, size := {span['size']} }}"
            candidate_literal = "true" if side == "candidate" else "false"
            evaluations.extend((
                f"  let some {side}Behavior{index} := "
                f"regionBehaviorWithMachineCallContracts {side}Pe {side}Imports "
                f"machineImportCallContracts {span_literal} | "
                f'throw (IO.userError "{side} region {index} did not decode")',
                f"  let some {side}Normalized{index} := normalizeSymbolicBehavior "
                f"{candidate_literal} region{index}.targets {side}Behavior{index} | "
                f'throw (IO.userError "{side} region {index} did not normalize")',
                f'  IO.println ("STAGE_A_BEHAVIOR_BEGIN {side} {index}\\n" ++ '
                f'reprStr (some {side}Behavior{index}) ++ "\\nSTAGE_A_BEHAVIOR_IR\\n" ++ '
                f'SemanticIR.normalizedBehaviorString {side}Normalized{index} ++ '
                '"\\nSTAGE_A_BEHAVIOR_END")',
            ))
    return (
        "import StageA.Relational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + "\n\n".join(definitions)
        + "\n\n"
        "def main : IO Unit := do\n"
        "  let originalData ← IO.FS.readBinFile \"../artifacts/original.pe\"\n"
        "  let candidateData ← IO.FS.readBinFile \"../artifacts/candidate.pe\"\n"
        "  let originalBytes : Bytes := originalData.toList.map (fun byte => byte.toNat)\n"
        "  let candidateBytes : Bytes := candidateData.toList.map (fun byte => byte.toNat)\n"
        "  let some originalPe := parsePE32 originalBytes | throw (IO.userError \"original PE parse failed\")\n"
        "  let some candidatePe := parsePE32 candidateBytes | throw (IO.userError \"candidate PE parse failed\")\n"
        "  let some originalImports := parseImports originalPe | throw (IO.userError \"original imports parse failed\")\n"
        "  let some candidateImports := parseImports candidatePe | throw (IO.userError \"candidate imports parse failed\")\n"
        + "\n".join(evaluations)
        + "\n"
    )

def _lean_counterexample_source(
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    original: bytes,
    candidate: bytes,
    targets: list[dict[str, Any]],
    machine_import_call_contracts: list[dict[str, Any]],
    region: dict[str, Any],
    index: int,
    behaviors: dict[str, str],
    assignment: dict[str, int],
) -> str:
    machine_call_contract_rows = ", ".join(
        _lean_machine_import_call_contract(item)
        for item in machine_import_call_contracts
    )
    def registers(side: str) -> str:
        fields = ", ".join(
            f"{register} := BitVec.ofNat 32 {assignment[f'{side}{register}']}"
            for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
        )
        return "{ " + fields + " }"

    return (
        "import StageA.Relational\n\n"
        "namespace StageA.GeneratedRelationalCounterexample\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + _lean_byte_tree_definitions("originalBytes", original)
        + "\n\n"
        + _lean_byte_tree_definitions("candidateBytes", candidate)
        + "\n\n"
        f"def originalPe : PE32 := {_lean_pe(original_bin, 'originalBytes')}\n\n"
        f"def candidatePe : PE32 := {_lean_pe(candidate_bin, 'candidateBytes')}\n\n"
        f"def originalImportCertificate : ImportTableCertificate := {_lean_import_certificate(original_bin)}\n\n"
        f"def candidateImportCertificate : ImportTableCertificate := {_lean_import_certificate(candidate_bin)}\n\n"
        "def originalImports : List PEImport := originalImportCertificate.imports\n\n"
        "def candidateImports : List PEImport := candidateImportCertificate.imports\n\n"
        f"def machineImportCallContracts : List MachineImportCallContract := [{machine_call_contract_rows}]\n\n"
        "theorem originalMetadataParsed : parsePEMetadataTree originalBytes = some originalPe.metadata := by decide\n\n"
        "theorem candidateMetadataParsed : parsePEMetadataTree candidateBytes = some candidatePe.metadata := by decide\n\n"
        "theorem originalParsed : parsePE32Tree originalBytes = some originalPe := by\n  simp [parsePE32Tree, originalMetadataParsed, PE32.metadata, PEMetadata.toPE32, originalPe]\n\n"
        "theorem candidateParsed : parsePE32Tree candidateBytes = some candidatePe := by\n  simp [parsePE32Tree, candidateMetadataParsed, PE32.metadata, PEMetadata.toPE32, candidatePe]\n\n"
        "theorem originalImportsChecked : importTableValid originalPe originalImportCertificate = true := by decide\n\n"
        "theorem candidateImportsChecked : importTableValid candidatePe candidateImportCertificate = true := by decide\n\n"
        + _lean_region_definition(index, region)
        + "\n\n"
        + f"def originalBehavior : SymbolicBehavior := {behaviors['original']}\n\n"
        + f"def candidateBehavior : SymbolicBehavior := {behaviors['candidate']}\n\n"
        + f"def originalState : MachineState := {{ registers := {registers('o')}, memory := fun _ => BitVec.ofNat 8 0 }}\n\n"
        + f"def candidateState : MachineState := {{ registers := {registers('c')}, memory := fun _ => BitVec.ofNat 8 0 }}\n\n"
        + f"theorem originalBehaviorCachedDecoded : regionBehaviorWithMachineCallContracts originalPe originalImports machineImportCallContracts region{index}.original = some originalBehavior := by decide\n\n"
        + f"theorem candidateBehaviorCachedDecoded : regionBehaviorWithMachineCallContracts candidatePe candidateImports machineImportCallContracts region{index}.candidate = some candidateBehavior := by decide\n\n"
        + f"theorem inputsRelated : statesRelated originalPe.imageBase candidatePe.imageBase "
        + f"region{index}.targets region{index}.flagInputs region{index}.bounds "
        + f"region{index}.addressSeparations region{index}.values region{index}.inputs "
        + "originalState candidateState := by\n"
        + "  constructor\n  · decide\n  · constructor\n    · decide\n    · constructor\n      · decide\n      · exact ⟨rfl, rfl, rfl, rfl, rfl⟩\n\n"
        + "def outputsMatch : Bool :=\n"
        + f"  match evalBehavior false region{index}.targets originalState originalBehavior,\n"
        + f"      evalBehavior true region{index}.targets candidateState candidateBehavior with\n"
        + "  | some originalResult, some candidateResult =>\n"
        + f"      registersRelatedValues originalPe.imageBase candidatePe.imageBase region{index}.targets region{index}.values region{index}.outputs originalResult.registers candidateResult.registers &&\n"
        + "      decide (originalResult.x87 = candidateResult.x87) &&\n"
        + f"      writesRelated originalPe.imageBase candidatePe.imageBase region{index}.targets region{index}.values originalResult.writes candidateResult.writes &&\n"
        + f"      flagsRelated region{index}.flagOutputs originalResult.eflags candidateResult.eflags &&\n"
        + f"      outcomesRelated originalPe.imageBase candidatePe.imageBase region{index}.targets region{index}.values originalResult.outcome candidateResult.outcome\n"
        + "  | _, _ => false\n\n"
        + "theorem outputsMismatch : outputsMatch = false := by decide\n\n"
        + "theorem exactCounterexample :\n"
        + "    parsePE32Tree originalBytes = some originalPe ∧\n"
        + "    parsePE32Tree candidateBytes = some candidatePe ∧\n"
        + "    importTableValid originalPe originalImportCertificate = true ∧\n"
        + "    importTableValid candidatePe candidateImportCertificate = true ∧\n"
        + f"    regionBehaviorWithMachineCallContracts originalPe originalImports machineImportCallContracts region{index}.original = some originalBehavior ∧\n"
        + f"    regionBehaviorWithMachineCallContracts candidatePe candidateImports machineImportCallContracts region{index}.candidate = some candidateBehavior ∧\n"
        + f"    statesRelated originalPe.imageBase candidatePe.imageBase region{index}.targets "
        + f"region{index}.flagInputs region{index}.bounds region{index}.addressSeparations "
        + f"region{index}.values region{index}.inputs originalState candidateState ∧ "
        + "outputsMatch = false :=\n"
        + "  ⟨originalParsed, candidateParsed, originalImportsChecked, candidateImportsChecked, originalBehaviorCachedDecoded, candidateBehaviorCachedDecoded, inputsRelated, outputsMismatch⟩\n\n"
        + "#print axioms exactCounterexample\n\nend StageA.GeneratedRelationalCounterexample\n"
    )

def _lean_targets_definition(targets: list[dict[str, Any]]) -> str:
    target_rows = ", ".join(
        f"{{ id := {target['id']}, regionIndex := {target['region_index']}, originalRva := {target['original_rva']}, candidateRva := {target['candidate_rva']}, "
        f"originalAliases := {_lean_code_aliases(target, 'original')}, candidateAliases := {_lean_code_aliases(target, 'candidate')} }}"
        for target in targets
    )
    return f"def allTargets : List CodeTargetPair := [{target_rows}]"


def _lean_bounded_immutable_relocation_table_jump_claim(
    candidate: dict[str, Any],
) -> str:
    entry_target_ids = ", ".join(
        str(int(target_id)) for target_id in candidate["entry_target_ids"]
    )
    finite_target_ids = ", ".join(
        str(int(target_id)) for target_id in candidate["target_ids"]
    )
    return (
        "{ valueTargetId := " + str(int(candidate["value_target_id"]))
        + ", tableOffset := " + str(int(candidate["table_offset"]))
        + ", originalBase := " + str(int(candidate["original_base"]))
        + ", candidateBase := " + str(int(candidate["candidate_base"]))
        + ", upperExclusive := " + str(int(candidate["upper_exclusive"]))
        + ", originalIndex := "
        + _lean_semantic_expr(candidate["original_index_expression"])
        + ", candidateIndex := "
        + _lean_semantic_expr(candidate["candidate_index_expression"])
        + ", entryTargetIds := [" + entry_target_ids + "]"
        + ", finiteTargetIds := [" + finite_target_ids + "] }"
    )

def _lean_global_mapping_context_source(contract: dict[str, Any]) -> str:
    target_rows = ", ".join(
        f"{{ id := {target['id']}, regionIndex := {target['region_index']}, "
        f"originalRva := {target['original_rva']}, candidateRva := {target['candidate_rva']}, "
        f"originalAliases := {_lean_code_aliases(target, 'original')}, "
        f"candidateAliases := {_lean_code_aliases(target, 'candidate')} }}"
        for target in contract.get("code_targets", [])
    )
    value_rows = ", ".join(
        _lean_value_target(target) for target in contract.get("value_targets", [])
    )

    def code_addresses(side: str) -> str:
        addresses: list[tuple[int, str]] = []
        for target in contract.get("code_targets", []):
            target_id = int(target["id"])
            addresses.append((
                int(target[f"{side}_rva"]),
                f"{{ targetId := {target_id}, kind := .canonical }}",
            ))
            addresses.extend(
                (
                    int(alias),
                    f"{{ targetId := {target_id}, kind := .alias {alias_index} }}",
                )
                for alias_index, alias in enumerate(
                    target.get(f"{side}_aliases", [])
                )
            )
        return ", ".join(row for _, row in sorted(addresses))

    original_value_order = ", ".join(
        str(target["id"])
        for target in sorted(
            contract.get("value_targets", []),
            key=lambda target: (target["original_value"], target["id"]),
        )
    )
    candidate_value_order = ", ".join(
        str(target["id"])
        for target in sorted(
            contract.get("value_targets", []),
            key=lambda target: (target["candidate_value"], target["id"]),
        )
    )
    return (
        "import StageA.RelationalMachine\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        f"def globalCodeTargetIndex : Array CodeTargetPair := #[{target_rows}]\n\n"
        "def globalCodeTargets : List CodeTargetPair := globalCodeTargetIndex.toList\n\n"
        f"def globalValueTargetIndex : Array ValueTargetPair := #[{value_rows}]\n\n"
        "def globalValueTargets : List ValueTargetPair := globalValueTargetIndex.toList\n\n"
        "def globalCodeMap : StaticCodeMap := {\n"
        "  entries := globalCodeTargetIndex\n"
        f"  originalAddresses := #[{code_addresses('original')}]\n"
        f"  candidateAddresses := #[{code_addresses('candidate')}]\n"
        "}\n\n"
        "def globalDataMap : StaticDataMap := {\n"
        "  entries := globalValueTargetIndex\n"
        f"  originalOrder := [{original_value_order}]\n"
        f"  candidateOrder := [{candidate_value_order}]\n"
        "}\n\n"
        "end StageA.GeneratedRelational\n"
    )

def _lean_static_proof_context_base_source(
    contract: dict[str, Any],
    *,
    original_entrypoint_rva: int,
    candidate_entrypoint_rva: int,
) -> str:
    code_targets = contract.get("code_targets", [])
    roots: list[tuple[int, str]] = []
    for region in contract["regions"]:
        if not region.get("root"):
            continue
        target = next((
            target for target in code_targets
            if target["original_rva"] == region["original"]["rva_start"]
            and target["candidate_rva"] == region["candidate"]["rva_start"]
        ), None)
        if target is None:
            raise StageAInputError(
                f"root region {region['id']} has no canonical code-map target"
            )
        root_kind = region.get("function_root_kind")
        is_entrypoint = (
            region["original"]["rva_start"] == original_entrypoint_rva
            and region["candidate"]["rva_start"] == candidate_entrypoint_rva
        )
        kind = "entrypoint" if is_entrypoint else {
            "export": "exported",
            "exported": "exported",
            "callback": "callback",
            "tls": "tlsInitializer",
            "tls_initializer": "tlsInitializer",
        }.get(root_kind, "exported")
        roots.append((int(target["id"]), kind))
    root_rows = ", ".join(
        f"{{ targetId := {target_id}, kind := .{kind} }}"
        for target_id, kind in roots
    )
    has_callbacks = any(kind == "callback" for _, kind in roots)
    has_tls = any(kind == "tlsInitializer" for _, kind in roots)
    static_dynamic_pointer_slots = ", ".join(
        _lean_static_dynamic_pointer_slot(slot)
        for slot in contract.get("static_dynamic_pointer_slots", [])
    )
    static_word_relation_slots = ", ".join(
        _lean_static_word_relation_slot(slot)
        for slot in contract.get("static_word_relation_slots", [])
    )
    return (
        "import StageA.RelationalProofBase\n"
        "import StageA.RelationalGlobalMappingContext\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "def staticProofContext : StaticProofContext := {\n"
        "  originalPe\n"
        "  candidatePe\n"
        "  originalImportCertificate\n"
        "  candidateImportCertificate\n"
        "  originalRelocations\n"
        "  candidateRelocations\n"
        "  codeMap := globalCodeMap\n"
        "  dataMap := globalDataMap\n"
        f"  roots := [{root_rows}]\n"
        "  observations := { "
        f"callbacks := {_lean_bool(has_callbacks)}, tls := {_lean_bool(has_tls)} "
        "}\n"
        f"  staticDynamicPointerSlots := [{static_dynamic_pointer_slots}]\n"
        f"  staticWordRelationSlots := [{static_word_relation_slots}]\n"
        "  machineImportCallContracts\n"
        "}\n\n"
        "end StageA.GeneratedRelational\n"
    )

def _static_index_ranges(size: int, chunk_size: int) -> list[tuple[int, int]]:
    return [
        (start, min(chunk_size, size - start))
        for start in range(0, size, chunk_size)
    ]

def _lean_static_range(name: str, start: int, size: int) -> str:
    return f"def {name} : Span := {{ start := {start}, size := {size} }}"

def _write_relational_static_context_modules(
    lean_dir: Path,
    contract: dict[str, Any],
    *,
    original_entrypoint_rva: int,
    candidate_entrypoint_rva: int,
) -> list[str]:
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalStaticContextBase.lean",
        _lean_static_proof_context_base_source(
            contract,
            original_entrypoint_rva=original_entrypoint_rva,
            candidate_entrypoint_rva=candidate_entrypoint_rva,
        ),
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalStaticDataContext.lean",
        (
            "import StageA.RelationalStaticContextBase\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            "theorem staticDataMapChecked :\n"
            "    staticProofContext.dataMap.valid originalPe candidatePe = true := by decide\n\n"
            "end StageA.GeneratedRelational\n"
        ),
    )
    chunk_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_STATIC_MAP_CHUNK", "16"))
    )
    target_count = len(contract.get("code_targets", []))
    original_address_count = target_count + sum(
        len(target.get("original_aliases", []))
        for target in contract.get("code_targets", [])
    )
    candidate_address_count = target_count + sum(
        len(target.get("candidate_aliases", []))
        for target in contract.get("code_targets", [])
    )
    families = {
        "Entry": {
            "count": target_count,
            "predicate": "(globalCodeMap.entryAtValid)",
        },
        "OriginalAddress": {
            "count": original_address_count,
            "predicate": "(globalCodeMap.addressAtValid false originalPe)",
        },
        "CandidateAddress": {
            "count": candidate_address_count,
            "predicate": "(globalCodeMap.addressAtValid true candidatePe)",
        },
    }
    ranges = {
        family: _static_index_ranges(int(spec["count"]), chunk_size)
        for family, spec in families.items()
    }
    module_count = max((len(items) for items in ranges.values()), default=0)
    modules: list[str] = []
    range_nodes: dict[str, list[dict[str, Any]]] = {
        family: [] for family in families
    }
    count_range_nodes: dict[str, list[dict[str, Any]]] = {
        "OriginalCount": [],
        "CandidateCount": [],
    }
    address_count_prefixes: dict[str, list[int]] = {}
    for family, side in (
        ("OriginalCount", "original"),
        ("CandidateCount", "candidate"),
    ):
        prefix = [0]
        for target in contract.get("code_targets", []):
            prefix.append(
                prefix[-1] + 1 + len(target.get(f"{side}_aliases", []))
            )
        address_count_prefixes[family] = prefix
    for chunk_index in range(module_count):
        module = f"RelationalStaticCodeMapChunk{chunk_index}"
        modules.append(module)
        definitions: list[str] = []
        for family, spec in families.items():
            if chunk_index >= len(ranges[family]):
                continue
            start, count = ranges[family][chunk_index]
            range_name = f"static{family}Range{chunk_index}"
            theorem_name = f"static{family}Range{chunk_index}Checked"
            predicate = str(spec["predicate"])
            definitions.append(_lean_static_range(range_name, start, count))
            definitions.append(
                f"theorem {theorem_name} :\n"
                f"    IndexedBoolRangeHolds {predicate} {range_name} :=\n"
                f"  indexedBoolRangeHolds_of_checked {predicate} {range_name} (by decide)"
            )
            range_nodes[family].append({
                "module": module,
                "range": range_name,
                "theorem": theorem_name,
                "start": start,
                "size": count,
            })
        if chunk_index < len(ranges["Entry"]):
            start, count = ranges["Entry"][chunk_index]
            for family, candidate in (
                ("OriginalCount", "false"),
                ("CandidateCount", "true"),
            ):
                range_name = f"static{family}Range{chunk_index}"
                theorem_name = f"static{family}Range{chunk_index}Checked"
                before = address_count_prefixes[family][start]
                after = address_count_prefixes[family][start + count]
                value = f"(globalCodeMap.addressContribution {candidate})"
                definitions.append(_lean_static_range(range_name, start, count))
                definitions.append(
                    f"theorem {theorem_name} :\n"
                    f"    IndexedNatRangeFoldHolds {value} {range_name} "
                    f"{before} {after} := by\n"
                    "  unfold IndexedNatRangeFoldHolds\n"
                    "  decide"
                )
                count_range_nodes[family].append({
                    "module": module,
                    "range": range_name,
                    "theorem": theorem_name,
                    "start": start,
                    "size": count,
                    "before": before,
                    "after": after,
                })
        source = (
            "import StageA.RelationalStaticContextBase\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    range_roots: dict[str, dict[str, Any]] = {}
    tree_fanout = max(
        2, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_STATIC_TREE_FANOUT", "16"))
    )
    for family, nodes in range_nodes.items():
        if not nodes:
            raise StageAInputError(
                f"canonical static {family} inventory cannot be empty"
            )
        level = 0
        while len(nodes) > 1:
            next_nodes: list[dict[str, Any]] = []
            for group_offset in range(0, len(nodes), tree_fanout):
                group = nodes[group_offset : group_offset + tree_fanout]
                if len(group) == 1:
                    next_nodes.append(group[0])
                    continue
                node_index = group_offset // tree_fanout
                module = f"RelationalStatic{family}Tree{level}Node{node_index}"
                predicate = str(families[family]["predicate"])
                imports = "\n".join(
                    f"import StageA.{name}"
                    for name in dict.fromkeys(
                        ["RelationalStaticTree"]
                        + [str(child["module"]) for child in group]
                    )
                )
                definitions: list[str] = []
                current = group[0]
                for merge_index, right in enumerate(group[1:], 1):
                    if (
                        int(right["start"])
                        != int(current["start"]) + int(current["size"])
                    ):
                        raise StageAInputError(
                            f"canonical static {family} certificate ranges are not adjacent"
                        )
                    range_name = (
                        f"static{family}Tree{level}Node{node_index}Step{merge_index}Range"
                    )
                    theorem_name = f"{range_name}Checked"
                    start = int(current["start"])
                    size = int(current["size"]) + int(right["size"])
                    definitions.extend([
                        _lean_static_range(range_name, start, size),
                        (
                            f"theorem {theorem_name} :\n"
                            f"    IndexedBoolRangeHolds {predicate} {range_name} :=\n"
                            f"  indexedBoolRangeHolds_append {predicate} "
                            f"{current['range']} {right['range']} (by decide)\n"
                            f"    {current['theorem']} {right['theorem']}"
                        ),
                    ])
                    current = {
                        "module": module,
                        "range": range_name,
                        "theorem": theorem_name,
                        "start": start,
                        "size": size,
                    }
                source = (
                    imports
                    + "\n\nnamespace StageA.GeneratedRelational\n\n"
                    "open StageA.Formal StageA.Relational\n\n"
                    "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
                    + "\n\n".join(definitions)
                    + "\n\n"
                    "end StageA.GeneratedRelational\n"
                )
                _write_text_if_changed(
                    lean_dir / "StageA" / f"{module}.lean", source
                )
                modules.append(module)
                next_nodes.append(current)
            nodes = next_nodes
            level += 1
        range_roots[family] = nodes[0]

    count_roots: dict[str, dict[str, Any]] = {}
    for family, nodes in count_range_nodes.items():
        candidate = "true" if family == "CandidateCount" else "false"
        value = f"(globalCodeMap.addressContribution {candidate})"
        level = 0
        while len(nodes) > 1:
            next_nodes: list[dict[str, Any]] = []
            for group_offset in range(0, len(nodes), tree_fanout):
                group = nodes[group_offset : group_offset + tree_fanout]
                if len(group) == 1:
                    next_nodes.append(group[0])
                    continue
                node_index = group_offset // tree_fanout
                module = f"RelationalStatic{family}Tree{level}Node{node_index}"
                imports = "\n".join(
                    f"import StageA.{name}"
                    for name in dict.fromkeys(
                        ["RelationalStaticTree"]
                        + [str(child["module"]) for child in group]
                    )
                )
                definitions: list[str] = []
                current = group[0]
                for merge_index, right in enumerate(group[1:], 1):
                    if (
                        int(right["start"])
                        != int(current["start"]) + int(current["size"])
                        or int(right["before"]) != int(current["after"])
                    ):
                        raise StageAInputError(
                            f"canonical static {family} fold ranges do not compose"
                        )
                    range_name = (
                        f"static{family}Tree{level}Node{node_index}Step{merge_index}Range"
                    )
                    theorem_name = f"{range_name}Checked"
                    start = int(current["start"])
                    size = int(current["size"]) + int(right["size"])
                    before = int(current["before"])
                    middle = int(current["after"])
                    after = int(right["after"])
                    definitions.extend([
                        _lean_static_range(range_name, start, size),
                        (
                            f"theorem {theorem_name} :\n"
                            f"    IndexedNatRangeFoldHolds {value} {range_name} "
                            f"{before} {after} :=\n"
                            f"  indexedNatRangeFoldHolds_append {value} "
                            f"{current['range']} {right['range']} "
                            f"{before} {middle} {after} (by decide)\n"
                            f"    {current['theorem']} {right['theorem']}"
                        ),
                    ])
                    current = {
                        "module": module,
                        "range": range_name,
                        "theorem": theorem_name,
                        "start": start,
                        "size": size,
                        "before": before,
                        "after": after,
                    }
                source = (
                    imports
                    + "\n\nnamespace StageA.GeneratedRelational\n\n"
                    "open StageA.Formal StageA.Relational\n\n"
                    "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
                    + "\n\n".join(definitions)
                    + "\n\nend StageA.GeneratedRelational\n"
                )
                _write_text_if_changed(
                    lean_dir / "StageA" / f"{module}.lean", source
                )
                modules.append(module)
                next_nodes.append(current)
            nodes = next_nodes
            level += 1
        count_roots[family] = nodes[0]

    final_imports = "\n".join(
        f"import StageA.{module}"
        for module in dict.fromkeys(
            root["module"]
            for root in [*range_roots.values(), *count_roots.values()]
        )
    ) + "\nimport StageA.RelationalStaticDataContext"
    final_parts: list[str] = []
    holds_names: dict[str, str] = {}
    for family, spec in families.items():
        predicate = str(spec["predicate"])
        root = range_roots[family]
        ranges_name = f"static{family}Ranges"
        certificate_name = f"static{family}Certificate"
        ranges_checked_name = f"static{family}RangesChecked"
        holds_name = f"static{family}IndexChecked"
        holds_names[family] = holds_name
        final_parts.extend([
            f"def {ranges_name} : List Span := [{root['range']}]",
            f"def {certificate_name} : IndexedBoolCertificate := {{ ranges := {ranges_name} }}",
            (
                f"theorem {ranges_checked_name} :\n"
                f"    AllIndexedBoolRangesHold {predicate} {ranges_name} := by\n"
                f"  exact ⟨{root['theorem']}, True.intro⟩"
            ),
            (
                f"theorem {holds_name} :\n"
                f"    {certificate_name}.Holds {predicate} {int(spec['count'])} :=\n"
                f"  IndexedBoolCertificate.holds_of_ranges {predicate} {int(spec['count'])}\n"
                f"    {certificate_name} (by decide) {ranges_checked_name}"
            ),
        ])
    original_count_root = count_roots["OriginalCount"]
    candidate_count_root = count_roots["CandidateCount"]
    final_parts.extend([
        (
            "theorem staticCodeEntryCountChecked :\n"
            f"    globalCodeMap.entries.size = {target_count} := by decide"
        ),
        (
            "theorem staticOriginalExpectedAddressCountChecked :\n"
            "    globalCodeMap.expectedAddressCount false = "
            f"{original_address_count} := by\n"
            "  unfold StaticCodeMap.expectedAddressCount\n"
            "  rw [staticCodeEntryCountChecked]\n"
            f"  simpa [IndexedNatRangeFoldHolds, {original_count_root['range']}] using "
            f"{original_count_root['theorem']}"
        ),
        (
            "theorem staticCandidateExpectedAddressCountChecked :\n"
            "    globalCodeMap.expectedAddressCount true = "
            f"{candidate_address_count} := by\n"
            "  unfold StaticCodeMap.expectedAddressCount\n"
            "  rw [staticCodeEntryCountChecked]\n"
            f"  simpa [IndexedNatRangeFoldHolds, {candidate_count_root['range']}] using "
            f"{candidate_count_root['theorem']}"
        ),
        (
            "theorem staticOriginalAddressArrayCountChecked :\n"
            f"    globalCodeMap.originalAddresses.size = {original_address_count} := by decide"
        ),
        (
            "theorem staticCandidateAddressArrayCountChecked :\n"
            f"    globalCodeMap.candidateAddresses.size = {candidate_address_count} := by decide"
        ),
        (
            "theorem staticOriginalAddressCountChecked :\n"
            "    globalCodeMap.originalAddresses.size =\n"
            "      globalCodeMap.expectedAddressCount false :=\n"
            "  staticOriginalAddressArrayCountChecked.trans\n"
            "    staticOriginalExpectedAddressCountChecked.symm"
        ),
        (
            "theorem staticCandidateAddressCountChecked :\n"
            "    globalCodeMap.candidateAddresses.size =\n"
            "      globalCodeMap.expectedAddressCount true :=\n"
            "  staticCandidateAddressArrayCountChecked.trans\n"
            "    staticCandidateExpectedAddressCountChecked.symm"
        ),
        (
            "theorem staticCodeMapChecked :\n"
            "    globalCodeMap.IndexedValid originalPe candidatePe :=\n"
            f"  ⟨{holds_names['Entry']}, staticOriginalAddressCountChecked,\n"
            "    staticCandidateAddressCountChecked, "
            f"{holds_names['OriginalAddress']}, {holds_names['CandidateAddress']}⟩"
        ),
        "theorem staticRootsChecked : rootsValid staticProofContext = true := by decide",
        (
            "theorem staticDynamicPointerSlotsChecked :\n"
            "    staticDynamicPointerSlotsValid staticProofContext = true := by decide"
        ),
        (
            "theorem staticWordRelationSlotsChecked :\n"
            "    staticWordRelationSlotsValid staticProofContext = true := by decide"
        ),
        (
            "theorem staticOriginalMachineCallContractsChecked :\n"
            "    machineImportCallContractsValid originalImports\n"
            "      staticProofContext.machineImportCallContracts = true := by decide"
        ),
        (
            "theorem staticCandidateMachineCallContractsChecked :\n"
            "    machineImportCallContractsValid candidateImports\n"
            "      staticProofContext.machineImportCallContracts = true := by decide"
        ),
        (
            "theorem staticObservationsChecked :\n"
            "    observationProfileValid staticProofContext.observations = true := by decide"
        ),
        (
            "theorem staticProofContextChecked : staticProofContext.StructurallyValid :=\n"
            "  StaticProofContext.structurallyValid_of_components staticProofContext\n"
            "    originalParsed candidateParsed originalImportsChecked candidateImportsChecked\n"
            "    originalRelocationsParsed candidateRelocationsParsed staticCodeMapChecked\n"
            "    staticDataMapChecked staticDynamicPointerSlotsChecked\n"
            "    staticWordRelationSlotsChecked\n"
            "    staticOriginalMachineCallContractsChecked\n"
            "    staticCandidateMachineCallContractsChecked staticRootsChecked\n"
            "    staticObservationsChecked"
        ),
    ])
    final_source = (
        final_imports
        + "\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + "\n\n".join(final_parts)
        + "\n\nend StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalStaticContext.lean", final_source
    )
    return modules

def _normalized_behavior_structure_matches(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> bool:
    registers = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
    for field in ("inputs", "outputs"):
        pairs = region.get(field, [])
        if {
            pair["original"] for pair in pairs
            if pair.get("original") == pair.get("candidate")
        } != registers or len(pairs) != len(registers):
            return False
    if region.get("bounds") or region.get("values"):
        return False

    marker = ", outcome := "
    try:
        original_core, original_outcome = behaviors["original"].rsplit(marker, 1)
        candidate_core, candidate_outcome = behaviors["candidate"].rsplit(marker, 1)
    except ValueError:
        return False
    if original_core != candidate_core:
        return False
    def target_id(side: str, rva: int) -> int | None:
        for target in region.get("code_targets", []):
            if rva == target[f"{side}_rva"] or rva in target.get(f"{side}_aliases", []):
                return target["id"]
        return None

    def outcome_key(side: str, outcome: str) -> tuple[Any, ...] | None:
        if side == "candidate" and outcome == original_outcome:
            return ("exact", outcome)
        jump = re.fullmatch(
            r"some \(StageA\.Formal\.OutcomeExpr\.jump (\d+)\) \}",
            outcome,
        )
        if jump is not None:
            mapped = target_id(side, int(jump.group(1)))
            return ("jump", mapped) if mapped is not None else None

        branch = re.fullmatch(
            r"some \(StageA\.Formal\.OutcomeExpr\.branch (.*) (\d+) (\d+)\) \}",
            outcome,
        )
        if branch is not None:
            taken = target_id(side, int(branch.group(2)))
            fallthrough = target_id(side, int(branch.group(3)))
            if taken is not None and fallthrough is not None:
                return ("branch", branch.group(1), taken, fallthrough)
            return None

        call = re.fullmatch(
            r"some \(StageA\.Formal\.OutcomeExpr\.call (\d+) (\d+) \d+\) \}",
            outcome,
        )
        if call is not None:
            target = target_id(side, int(call.group(1)))
            continuation = target_id(side, int(call.group(2)))
            if target is not None and continuation is not None:
                return ("call", target, continuation)
            return None

        continuation_form = re.fullmatch(
            r"some \(StageA\.Formal\.OutcomeExpr\.(externalCall|bulkCopy|checkedContinue|atomicCompareExchange) "
            r"(.*) (\d+)\) \}",
            outcome,
        )
        if continuation_form is not None:
            continuation = target_id(side, int(continuation_form.group(3)))
            if continuation is not None:
                return (
                    continuation_form.group(1),
                    continuation_form.group(2),
                    continuation,
                )
            return None

        indirect_call = re.fullmatch(
            r"some \(StageA\.Formal\.OutcomeExpr\.indirectCall (.*) (\d+) \d+\) \}",
            outcome,
        )
        if indirect_call is not None:
            continuation = target_id(side, int(indirect_call.group(2)))
            if continuation is not None:
                return ("indirectCall", indirect_call.group(1), continuation)
        return None

    if original_outcome == candidate_outcome:
        return True
    original_key = outcome_key("original", original_outcome)
    candidate_key = outcome_key("candidate", candidate_outcome)
    return original_key is not None and original_key == candidate_key

def _normalized_behavior_fast_path(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> bool:
    all_flag_bits = list(FLAG_BITS)
    return (
        region.get("flag_inputs", all_flag_bits) == all_flag_bits
        and region.get("flag_outputs", all_flag_bits) == all_flag_bits
        and _normalized_behavior_structure_matches(region, behaviors)
    )

def _lean_behavior_field(source: str, field: str, next_field: str) -> str | None:
    end_marker = f", {next_field} := "
    for start_marker in (f", {field} := ", f"{{ {field} := "):
        try:
            return source.split(start_marker, 1)[1].split(end_marker, 1)[0]
        except (AttributeError, IndexError):
            continue
    return None

def _lean_behavior_fields_memory_free(
    behaviors: dict[str, str], field: str, next_field: str
) -> bool:
    values = [
        _lean_behavior_field(behaviors.get(side, ""), field, next_field)
        for side in ("original", "candidate")
    ]
    if any(value is None for value in values):
        return False
    memory_dependencies = (
        "StageA.Formal.X87Expr.load ",
        "StageA.Formal.Expr.read8 ",
        "StageA.Formal.Expr.read32 ",
        "StageA.Formal.Expr.read8AfterWrite ",
    )
    return all(
        not any(marker in value for marker in memory_dependencies)
        for value in values if value is not None
    )

def _lean_identical_state_only_write_registers(
    region: dict[str, Any], behaviors: dict[str, str]
) -> list[str] | None:
    original = _lean_behavior_field(behaviors.get("original", ""), "writes", "comparison")
    candidate = _lean_behavior_field(behaviors.get("candidate", ""), "writes", "comparison")
    if original is None or original != candidate:
        return None
    non_register_state_dependencies = (
        "StageA.Formal.Expr.inputFlagValue ",
        "StageA.Formal.Expr.inputFsBase",
        "StageA.Formal.Expr.inputX87Control",
        "StageA.Formal.Expr.inputX87Status",
        "StageA.Formal.Expr.read8 ",
        "StageA.Formal.Expr.read32 ",
        "StageA.Formal.Expr.read8AfterWrite ",
        "StageA.Formal.Expr.undefinedValue ",
    )
    if any(marker in original for marker in non_register_state_dependencies):
        return None
    registers = sorted(set(re.findall(
        r"StageA\.Formal\.Expr\.inputReg \(StageA\.Formal\.Reg\.([a-z0-9]+)\)",
        original,
    )))
    same_register_inputs = {
        pair["original"]
        for pair in region.get("inputs", [])
        if pair.get("original") == pair.get("candidate")
    }
    if not set(registers).issubset(same_register_inputs):
        return None
    return registers

def _lean_identical_state_only_writes_component(
    index: int,
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str | None:
    registers = _lean_identical_state_only_write_registers(region, behaviors)
    if registers is None:
        return None
    name = f"region{index}"
    inputs = region.get("inputs", [])
    input_hypotheses = [f"inputRelated{pair_index}" for pair_index in range(len(inputs))]
    rows: list[str] = []
    register_equalities: list[str] = []
    if registers:
        rows.extend((
            "  unfold statesRelated StateRelCore at related",
            "  simp only [registerRelationsHold_exactRegisterRelations] at related",
            "  have registerInputs := related.1",
            f"  simp [registersRelated, StageA.Formal.Registers.get, {name}] at registerInputs",
        ))
        if len(inputs) == 1:
            rows.append(f"  have {input_hypotheses[0]} := registerInputs")
        else:
            rows.append(
                "  rcases registerInputs with ⟨"
                + ", ".join(input_hypotheses)
                + "⟩"
            )
        for register in registers:
            pair_index = next(
                pair_index for pair_index, pair in enumerate(inputs)
                if pair.get("original") == register
                and pair.get("candidate") == register
            )
            equality = f"{register}GetRelated"
            rows.extend((
                f"  have {equality} : originalState.registers.get Reg.{register} =",
                f"      candidateState.registers.get Reg.{register} := by",
                "    simpa [StageA.Formal.Registers.get] using "
                f"{input_hypotheses[pair_index]}",
            ))
            register_equalities.append(equality)
    simplifiers = ", ".join(register_equalities)
    if simplifiers:
        simplifiers = ", " + simplifiers
    rows.extend((
        "  have writesEqual :",
        f"      evalNormalizedWrites originalState originalBehavior{index}.writes =",
        f"        evalNormalizedWrites candidateState candidateBehavior{index}.writes := by",
        "    simp [evalNormalizedWrites, StageA.Formal.Expr.eval, "
        f"originalBehavior{index}, candidateBehavior{index}{simplifiers}]",
        "  rw [writesEqual]",
        "  apply writesRelated_self",
    ))
    return "\n".join(rows) + "\n"

def _lean_x87_state_only_pair(behaviors: dict[str, str]) -> bool:
    original = _lean_behavior_field(behaviors.get("original", ""), "x87", "writes")
    candidate = _lean_behavior_field(behaviors.get("candidate", ""), "x87", "writes")
    if original is None or original != candidate:
        return False
    external_dependencies = (
        "StageA.Formal.X87Expr.load ",
        "StageA.Formal.Expr.inputReg ",
        "StageA.Formal.Expr.inputFlagValue ",
        "StageA.Formal.Expr.inputFsBase",
        "StageA.Formal.Expr.read8 ",
        "StageA.Formal.Expr.read32 ",
        "StageA.Formal.Expr.read8AfterWrite ",
        "StageA.Formal.Expr.undefinedValue ",
    )
    return not any(marker in original for marker in external_dependencies)

def _lean_normalized_static_outcome(
    region: dict[str, Any],
    behaviors: dict[str, str],
) -> str | None:
    try:
        outcome = behaviors["original"].rsplit(", outcome := ", 1)[1]
    except (KeyError, ValueError):
        return None

    def target_id(rva: int) -> int | None:
        for target in region.get("code_targets", []):
            if rva == target["original_rva"] or rva in target.get("original_aliases", []):
                return int(target["id"])
        return None

    jump = re.fullmatch(r"some \(StageA\.Formal\.OutcomeExpr\.jump (\d+)\) \}", outcome)
    if jump is not None:
        target = target_id(int(jump.group(1)))
        return (
            f"StageA.Relational.NormalizedOutcomeExpr.jump {target}"
            if target is not None else None
        )

    branch = re.fullmatch(
        r"some \(StageA\.Formal\.OutcomeExpr\.branch (.*) (\d+) (\d+)\) \}",
        outcome,
    )
    if branch is not None:
        taken = target_id(int(branch.group(2)))
        fallthrough = target_id(int(branch.group(3)))
        if taken is not None and fallthrough is not None:
            return (
                "StageA.Relational.NormalizedOutcomeExpr.branch "
                f"({branch.group(1)}) {taken} {fallthrough}"
            )
        return None

    call = re.fullmatch(
        r"some \(StageA\.Formal\.OutcomeExpr\.call (\d+) (\d+) \d+\) \}",
        outcome,
    )
    if call is not None:
        target = target_id(int(call.group(1)))
        continuation = target_id(int(call.group(2)))
        if target is not None and continuation is not None:
            return (
                "StageA.Relational.NormalizedOutcomeExpr.call "
                f"{target} {continuation}"
            )
    return None

def _lean_normalized_branch_parts(outcome: str) -> tuple[str, int, int] | None:
    branch = re.fullmatch(
        r"StageA\.Relational\.NormalizedOutcomeExpr\.branch \((.*)\) (\d+) (\d+)",
        outcome,
    )
    if branch is None:
        return None
    return branch.group(1), int(branch.group(2)), int(branch.group(3))

def _lean_bundle_source(original_bin: StageABinary, candidate_bin: StageABinary, original: bytes, candidate: bytes, contract: dict[str, Any], behaviors: list[dict[str, str]], *, replay: bool, certificates: list[dict[str, Any]] | None = None) -> str:
    certificate_by_region = {entry.get("region_id"): entry for entry in certificates or []}
    machine_call_contract_rows = ", ".join(
        _lean_machine_import_call_contract(item)
        for item in contract.get("machine_import_call_contracts", [])
    )
    region_defs: list[str] = []
    theorem_defs: list[str] = []
    theorem_names: list[str] = []
    for index, region in enumerate(contract["regions"]):
        name = f"region{index}"
        theorem_name = f"{name}Checked"
        memory_lemmas = ", ".join(
            _lean_region_memory_lemma_names(index, region, behaviors[index])
        )
        memory_lemma_line = f"    {memory_lemmas},\n" if memory_lemmas else ""
        memory_normalizer_line = (
            "    normalizeDataAddress, valueTargetContainsCandidate,\n"
            if region.get("values") and not _lean_region_indexed_memory_lemma_specs(region) else ""
        )
        bound_setup = _lean_region_bound_setup(index, region, behaviors[index])
        flag_setup, flag_hypotheses = _lean_region_flag_setup(index, region)
        flag_lemma_line = f"    {flag_hypotheses},\n" if flag_hypotheses else ""
        normalized_flag_simplifiers = f", {flag_hypotheses}" if flag_hypotheses else ""
        relocation_memory_setup = _lean_region_relocation_memory_setup(
            index, region, behaviors[index]
        )
        separation_setup, separation_hypotheses = _lean_region_separation_setup(index, region)
        separation_lemma_line = (
            f"    {separation_hypotheses},\n" if separation_hypotheses else ""
        )
        indexed_memory_facts = _lean_region_indexed_memory_fact_names(index, region)
        index_mask_facts = [
            f"region{index}IndexMaskFact{mask_index}"
            for mask_index in range(len(_lean_region_index_masks(region, behaviors[index])))
        ]
        indexed_memory_rewrite = (
            (
                f"  all_goals try simp only [{', '.join(index_mask_facts)}]\n"
                if index_mask_facts else ""
            )
            + f"  all_goals try simp only [{', '.join(indexed_memory_facts)}]\n"
            + "  all_goals try simp\n"
            if indexed_memory_facts else ""
        )
        has_relocation_word_facts = bool(
            _lean_region_static_relocation_word_specs(region, behaviors[index])
            or _lean_region_indexed_relocation_word_specs(region)
        )
        word_relation_simplifiers = (
            "wordRelated_self"
            if has_relocation_word_facts else
            "wordRelated, codePointerRelated, codeAddressMatches, mappedValueRelated"
        )
        image_simplifiers = "" if has_relocation_word_facts else "originalPe, candidatePe, "
        memory_read_simplifiers = (
            "machineStateRead32_eq_memoryRead32, assembledMemoryRead32_eq, "
            "assembledMemoryRead32OfNat_eq"
            if has_relocation_word_facts else
            "StageA.Formal.MachineState.read32, Memory.read32"
        )
        flag_eval_simplifiers = (
            "StageA.Formal.FlagsExpr.eval_extract_cf, "
            "StageA.Formal.FlagsExpr.eval_extract_pf, "
            "StageA.Formal.FlagsExpr.eval_extract_zf, "
            "StageA.Formal.FlagsExpr.eval_extract_sf, "
            "StageA.Formal.FlagsExpr.eval_extract_df, "
            "StageA.Formal.FlagsExpr.eval_extract_of, StageA.Formal.evalFlagBit"
        )
        theorem_names.append(theorem_name)
        region_defs.append(_lean_region_definition(index, region))
        region_defs.append(_lean_region_memory_lemmas(index, region, behaviors[index]))
        region_defs.append(f"def originalBehavior{index} : SymbolicBehavior := {behaviors[index]['original']}")
        region_defs.append(f"def candidateBehavior{index} : SymbolicBehavior := {behaviors[index]['candidate']}")
        if replay:
            certificate = certificate_by_region.get(region["id"])
            if certificate and certificate.get("kind") == "lrat":
                tactic = f"bv_check \"../../certificates/{certificate['path']}\""
            elif certificate and certificate.get("kind") == "lean_normalization":
                tactic = "bv_normalize"
            else:
                tactic = "fail_if_success trivial"
        else:
            tactic = "bv_decide? (config := { timeout := 120, trimProofs := false })"
        input_hypotheses = [f"inputRelated{pair_index}" for pair_index in range(len(region["inputs"]))]
        if len(input_hypotheses) > 1:
            relation_destructure = "  rcases related with ⟨" + ", ".join(input_hypotheses) + "⟩\n"
        else:
            relation_destructure = ""
        substitutions = "".join(
            f"  subst c{pair['candidate']}\n" for pair in region["inputs"]
        )
        normalized_fast_path = _normalized_behavior_fast_path(region, behaviors[index])
        normalized_theorem = (
            f"theorem {name}NormalizedBehavior : "
            f"normalizeSymbolicBehavior false {name}.targets originalBehavior{index} = "
            f"normalizeSymbolicBehavior true {name}.targets candidateBehavior{index} := by decide\n\n"
            f"theorem {name}NormalizedBehaviorExists : "
            f"(normalizeSymbolicBehavior false {name}.targets originalBehavior{index}).isSome := by decide\n\n"
            if normalized_fast_path else ""
        )
        proof_steps = (
            f"  unfold evalBehavior\n"
            f"  rw [← {name}NormalizedBehavior]\n"
            f"  cases normalized : normalizeSymbolicBehavior false {name}.targets originalBehavior{index} with\n"
            f"  | none => simpa [normalized] using {name}NormalizedBehaviorExists\n"
            "  | some behavior =>\n"
            f"    simp [normalized, NormalizedSymbolicBehavior.eval, NormalizedOutcomeExpr.eval, "
            f"registersRelatedValues, writesRelated_self, outcomesRelated_self, "
            f"StageA.Relational.flagsRelated, "
            f"wordRelated{normalized_flag_simplifiers}, {name}]\n"
            if normalized_fast_path else (
                "  simp [evalBehavior, evalBehaviorRegisters, evalBehaviorX87, evalBehaviorWrites, "
                "evalBehaviorFlags, evalBehaviorOutcome, normalizeSymbolicBehavior, normalizeOutcomeExpr, "
                "NormalizedSymbolicBehavior.eval, NormalizedOutcomeExpr.eval, "
                "evalNormalizedRegisters, evalNormalizedX87, evalNormalizedWrites, evalNormalizedFlags, "
                "StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval, "
                f"{flag_eval_simplifiers},\n"
                f"    {memory_read_simplifiers}, StageA.Formal.MachineState.readX87Word,\n"
                "    StageA.Formal.read8AfterWriteValue,\n"
                "    StageA.Formal.X87LoadFormat.byteWidth, registersRelated, registersRelatedValues,\n"
                "    StageA.Formal.Registers.get, StageA.Formal.Registers.set, normalizeCodeTarget, normalizeImport,\n"
                f"    writesRelated, wordsRelated, outcomesRelated, "
                f"StageA.Relational.flagsRelated, "
                f"{word_relation_simplifiers}, "
                f"{image_simplifiers}\n"
                + memory_normalizer_line
                + memory_lemma_line
                + separation_lemma_line
                + flag_lemma_line
                + f"    originalBehavior{index}, candidateBehavior{index}, {name}]\n"
                + indexed_memory_rewrite
                + f"  all_goals first | rfl | {tactic}\n"
            )
        )
        theorem_defs.append(
            f"theorem originalBehavior{index}CachedDecoded : regionBehaviorWithMachineCallContracts originalPe originalImports machineImportCallContracts {name}.original = some originalBehavior{index} := by decide\n\n"
            + f"theorem candidateBehavior{index}CachedDecoded : regionBehaviorWithMachineCallContracts candidatePe candidateImports machineImportCallContracts {name}.candidate = some candidateBehavior{index} := by decide\n\n"
            + normalized_theorem
            + f"theorem {theorem_name}DirectBehavior : behaviorsEquivalent originalPe.imageBase candidatePe.imageBase originalBehavior{index} candidateBehavior{index} {name} := by\n"
            "  unfold behaviorsEquivalent\n"
            "  intro originalState candidateState related\n"
            "  unfold statesRelated StateRelCore at related\n"
            "  simp only [registerRelationsHold_exactRegisterRelations] at related\n"
            "  rcases originalState with ⟨⟨oeax, oebx, oecx, oedx, oesi, oedi, oebp, oesp⟩, originalMemory, originalUndefined, originalX87, originalFlags, originalFsBase⟩\n"
            "  rcases candidateState with ⟨⟨ceax, cebx, cecx, cedx, cesi, cedi, cebp, cesp⟩, candidateMemory, candidateUndefined, candidateX87, candidateFlags, candidateFsBase⟩\n"
            "  rcases related with ⟨related, boundsSatisfied, separationsSatisfied, memoryRelated, undefinedRelated, x87Related, flagsRelated, fsBaseRelated⟩\n"
            + _lean_region_memory_setup(
                index, region, "originalPe.imageBase", "candidatePe.imageBase",
            )
            + "  change originalUndefined = candidateUndefined at undefinedRelated\n"
            "  subst candidateUndefined\n"
            "  change originalX87 = candidateX87 at x87Related\n"
            "  subst candidateX87\n"
            + flag_setup
            + "  change originalFsBase = candidateFsBase at fsBaseRelated\n"
            "  subst candidateFsBase\n"
            "  simp [registersRelated, StageA.Formal.Registers.get, " + name + "] at related\n"
            + relation_destructure
            + substitutions
            + "  simp [StageA.Relational.boundsRelated, StageA.Relational.boundValue, evalExprPure, StageA.Formal.Registers.get, " + name + "] at boundsSatisfied\n"
            + bound_setup
            + relocation_memory_setup
            + separation_setup
            + proof_steps
            + f"\ntheorem {theorem_name}Direct : regionEquivalentWithImports originalPe candidatePe originalImports candidateImports machineImportCallContracts {name} :=\n"
            f"  regionEquivalentWithImports_of_decoded originalPe candidatePe originalImports candidateImports machineImportCallContracts {name} originalBehavior{index} candidateBehavior{index}\n"
            f"    originalBehavior{index}CachedDecoded candidateBehavior{index}CachedDecoded {theorem_name}DirectBehavior\n"
            f"\ntheorem {theorem_name} : regionGoal proofBundle {name} := by\n"
            "  unfold regionGoal parsedImages proofBundle\n"
            "  rw [originalParsed, candidateParsed]\n"
            f"  exact {theorem_name}Direct\n"
        )
    regions_literal = ", ".join(f"region{index}" for index in range(len(contract["regions"])))
    region_index_literal = _lean_index_tree(
        [f"region{index}" for index in range(len(contract["regions"]))]
    )
    original_padding = ", ".join(
        _lean_span(item) for item in contract["padding"] if item["side"] in {"original", "both"}
    )
    candidate_padding = ", ".join(
        _lean_span(item) for item in contract["padding"] if item["side"] in {"candidate", "both"}
    )
    original_coverage = _lean_sorted_span_certificate(
        _side_coverage_spans(contract, "original")
    )
    candidate_coverage = _lean_sorted_span_certificate(
        _side_coverage_spans(contract, "candidate")
    )
    original_alias_coverage = _lean_padding_alias_certificate(
        _side_padding(contract, "original")
    )
    candidate_alias_coverage = _lean_padding_alias_certificate(
        _side_padding(contract, "candidate")
    )
    all_proof = (
        "".join(f"And.intro {name} (" for name in theorem_names)
        + "True.intro"
        + ")" * len(theorem_names)
    )
    return (
        "import StageA.RelationalImage\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n"
        "set_option linter.unusedSimpArgs false\n\n"
        + _lean_byte_tree_definitions("originalBytes", original)
        + "\n\n"
        + _lean_byte_tree_definitions("candidateBytes", candidate)
        + "\n\n"
        f"def originalPe : PE32 := {_lean_pe(original_bin, 'originalBytes')}\n\n"
        f"def candidatePe : PE32 := {_lean_pe(candidate_bin, 'candidateBytes')}\n\n"
        f"def originalImportCertificate : ImportTableCertificate := {_lean_import_certificate(original_bin)}\n\n"
        f"def candidateImportCertificate : ImportTableCertificate := {_lean_import_certificate(candidate_bin)}\n\n"
        "def originalImports : List PEImport := originalImportCertificate.imports\n\n"
        "def candidateImports : List PEImport := candidateImportCertificate.imports\n\n"
        f"def machineImportCallContracts : List MachineImportCallContract := [{machine_call_contract_rows}]\n\n"
        f"def originalRelocations : List BaseRelocation := {_lean_relocations(original_bin)}\n\n"
        f"def candidateRelocations : List BaseRelocation := {_lean_relocations(candidate_bin)}\n\n"
        + "\n\n"
        "theorem originalMetadataParsed : parsePEMetadataTree originalBytes = some originalPe.metadata := by decide\n\n"
        "theorem candidateMetadataParsed : parsePEMetadataTree candidateBytes = some candidatePe.metadata := by decide\n\n"
        "theorem originalParsed : parsePE32Tree originalBytes = some originalPe := by\n  simp [parsePE32Tree, originalMetadataParsed, PE32.metadata, PEMetadata.toPE32, originalPe]\n\n"
        "theorem candidateParsed : parsePE32Tree candidateBytes = some candidatePe := by\n  simp [parsePE32Tree, candidateMetadataParsed, PE32.metadata, PEMetadata.toPE32, candidatePe]\n\n"
        "theorem originalImportsChecked : importTableValid originalPe originalImportCertificate = true := by decide\n\n"
        "theorem candidateImportsChecked : importTableValid candidatePe candidateImportCertificate = true := by decide\n\n"
        "theorem originalRelocationsParsed : parseRelocations originalPe = some originalRelocations := by decide\n\n"
        "theorem candidateRelocationsParsed : parseRelocations candidatePe = some candidateRelocations := by decide\n\n"
        + "\n\n".join(region_defs)
        + f"\n\ndef allRegionIndex : IndexTree RegionRelation := {region_index_literal}\n\n"
        + f"def proofBundle : StageA.Relational.ProofBundle := {{ originalBytes, candidateBytes, originalImports := originalImportCertificate, candidateImports := candidateImportCertificate, machineImportCallContracts, regions := allRegionIndex.toList, regionIndex := allRegionIndex, originalPadding := [{original_padding}], candidatePadding := [{candidate_padding}], originalCoverage := {original_coverage}, candidateCoverage := {candidate_coverage}, originalAliasCoverage := {original_alias_coverage}, candidateAliasCoverage := {candidate_alias_coverage} }}\n\n"
        + "\n".join(theorem_defs)
        + "\ntheorem structuralChecked : structuralEligible proofBundle = true := by decide\n\n"
        + "theorem valueRegionsChecked : valueRegionsClosed originalPe candidatePe "
        "originalRelocations candidateRelocations proofBundle.regions = true := by decide\n\n"
        + "def GeneratedMappedRelocationImageCertificate : Prop :=\n"
        "  AllMappedRelocationImageRelations originalPe candidatePe originalRelocations "
        "candidateRelocations proofBundle.regions\n\n"
        + "theorem generatedMappedRelocationImageCertificateChecked :\n"
        "    GeneratedMappedRelocationImageCertificate :=\n"
        "  allMappedRelocationImageRelations_of_valueRegionsClosed originalPe candidatePe "
        "originalRelocations candidateRelocations proofBundle.regions valueRegionsChecked\n\n"
        + "theorem importsChecked : importTablesCertified proofBundle := by\n  unfold importTablesCertified parsedImages proofBundle\n  rw [originalParsed, candidateParsed]\n  exact ⟨originalImportsChecked, candidateImportsChecked⟩\n\n"
        + "theorem allRegionsChecked : allRegionGoals proofBundle proofBundle.regions := by\n  change "
        + " ∧ ".join([f"regionGoal proofBundle region{index}" for index in range(len(contract["regions"]))] + ["True"])
        + "\n  exact "
        + all_proof
        + "\n\ntheorem regionalRelationalCertificate : RelationalImageCertificate proofBundle :=\n"
        "  relationalImageCertificate_intro proofBundle structuralChecked importsChecked allRegionsChecked\n\n"
        "theorem candidateRelationalImageCertificate :\n"
        "    RelationalImageCertificate proofBundle ∧ GeneratedMappedRelocationImageCertificate :=\n"
        "  ⟨regionalRelationalCertificate, generatedMappedRelocationImageCertificateChecked⟩\n\n"
        "#print axioms candidateRelationalImageCertificate\n\nend StageA.GeneratedRelational\n"
    )
