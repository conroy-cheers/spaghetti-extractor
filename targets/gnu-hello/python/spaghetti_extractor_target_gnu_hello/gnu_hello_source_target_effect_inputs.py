"""Produce exact GNU hello source-target effect authority inputs.

The adapter is intentionally deterministic and fail closed.  It reconstructs
the target/RVA index from the checked mixed-original Lean data, intersects it
with the canonical semantic-source partition, and emits Lean proof shards for
every rooted target.  The JSON inventory names only declarations in those
shards.  It never turns extractor status fields or Python classifications into
proof authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from spaghetti_extractor.errors import StageAInputError
from .gnu_hello_source_target_effects import (
    GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_FORMAT,
    GNU_HELLO_SOURCE_TARGET_EFFECTS_MODULE_PREFIX,
    GNU_HELLO_SOURCE_TARGET_EFFECTS_NAMESPACE,
    ArtifactSet,
    GnuHelloSourceTargetEffectsError,
    _artifact_bindings,
    _array,
    _find_generated_declaration,
    _natural,
    _object,
    _read_rows,
    _sha256,
    _string,
    _validate_artifacts,
    _validate_module_sources,
)
from .gnu_hello_source_transition_index import LeanDeclaration
from spaghetti_extractor.relational.lean.interpreter_normalization import _ordinary_items, is_x87_row


GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_MANIFEST_FORMAT = (
    "stage-a-gnu-hello-source-target-effect-inputs-manifest-v1"
)
GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_MODULE_PREFIX = (
    "GeneratedGnuHelloSourceTargetEffectInputs"
)
GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloSourceTargetEffectInputs"
)

_TARGET_ROW = re.compile(
    r"\{\s*id := ([0-9]+),\s*regionIndex := ([0-9]+),\s*"
    r"rva := ([0-9]+),\s*aliases := \[([^]]*)\]\s*\}"
)
_ALIAS_RVA = re.compile(r"\{\s*rva := ([0-9]+),\s*paddingIndex := [0-9]+\s*\}")
_DECLARATION = re.compile(
    r"^\s*(?:noncomputable\s+)?(?:abbrev|def|theorem)\s+"
    r"([A-Za-z_][A-Za-z0-9_']*)\b",
    re.MULTILINE,
)
_FORBIDDEN_PROOF_MARKER = re.compile(
    r"^\s*(?:axiom|opaque)\b|\b(?:admit|sorry)\b", re.MULTILINE
)


class GnuHelloSourceTargetEffectInputsError(StageAInputError):
    """Exact source-target authority inputs are incomplete or inconsistent."""


@dataclass(frozen=True)
class GeneratedSourceTargetEffectInputs:
    modules: tuple[Path, ...]
    authority_inventory: Path
    manifest: Path
    target_count: int
    ordinary_count: int
    x87_count: int


@dataclass(frozen=True)
class _Target:
    target_id: int
    source_rva: int
    kind: str
    source_index: int
    continuation_target_id: int | None
    dependencies: tuple[LeanDeclaration, ...]


def _module_declarations(root: Path) -> dict[str, set[str]]:
    stage_a = root / "StageA"
    if not stage_a.is_dir():
        raise GnuHelloSourceTargetEffectInputsError(
            f"exact mixed-original root {root} has no StageA directory"
        )
    modules = [
        ".".join(path.relative_to(root).with_suffix("").parts)
        for path in sorted(stage_a.rglob("*.lean"))
    ]
    try:
        return _validate_module_sources(
            root, {"modules": modules}, "exact mixed-original modules"
        )
    except GnuHelloSourceTargetEffectsError as error:
        raise GnuHelloSourceTargetEffectInputsError(str(error)) from error


def _target_index(root: Path, mixed: Mapping[str, Any]) -> tuple[dict[int, int], dict[int, int]]:
    by_id: dict[int, int] = {}
    by_rva: dict[int, int] = {}
    for source in sorted((root / "StageA").rglob("*.lean")):
        text = source.read_text(encoding="utf-8")
        for match in _TARGET_ROW.finditer(text):
            target_id, region_index, rva = map(int, match.group(1, 2, 3))
            if target_id != region_index:
                raise GnuHelloSourceTargetEffectInputsError(
                    f"mixed target {target_id} has region index {region_index}"
                )
            prior = by_id.setdefault(target_id, rva)
            if prior != rva:
                raise GnuHelloSourceTargetEffectInputsError(
                    f"mixed target {target_id} has conflicting RVAs"
                )
            for address in (rva, *map(int, _ALIAS_RVA.findall(match.group(4)))):
                prior_target = by_rva.setdefault(address, target_id)
                if prior_target != target_id:
                    raise GnuHelloSourceTargetEffectInputsError(
                        f"mixed code RVA {address} maps to multiple targets"
                    )
    counts = _object(mixed.get("counts"), "mixed counts")
    region_count = _natural(counts.get("regions"), "mixed counts.regions")
    expected_ids = set(range(region_count))
    if set(by_id) != expected_ids:
        missing = sorted(expected_ids - set(by_id))
        unexpected = sorted(set(by_id) - expected_ids)
        raise GnuHelloSourceTargetEffectInputsError(
            "exact mixed target index is incomplete "
            f"(missing={missing[:16]}, unexpected={unexpected[:16]})"
        )
    return by_id, by_rva


def _find(
    declarations: Mapping[str, set[str]], name: str, label: str
) -> LeanDeclaration:
    try:
        return _find_generated_declaration(declarations, name, label)
    except GnuHelloSourceTargetEffectsError as error:
        raise GnuHelloSourceTargetEffectInputsError(str(error)) from error


def _targets(
    rows: list[dict[str, Any]],
    mixed: Mapping[str, Any],
    declaration_sets: tuple[dict[str, set[str]], ...],
    exact_declarations: Mapping[str, set[str]],
    target_rvas: Mapping[int, int],
    target_by_rva: Mapping[int, int],
) -> list[_Target]:
    ordinary = _ordinary_items(rows)
    ordinary_by_rva = {item["start"]: (index, item) for index, item in ordinary}
    x87_rows = sorted(
        (row for row in rows if is_x87_row(row)),
        key=lambda row: (
            _natural(_object(row.get("original"), "x87 original").get("rva_start"), "x87 rva"),
            _string(row.get("id"), "x87 id"),
        ),
    )
    x87_by_rva = {
        _natural(_object(row["original"], "x87 original")["rva_start"], "x87 rva"):
            (index, row)
        for index, row in enumerate(x87_rows)
    }
    source_modules, normalization_modules, semantic_modules, x87_modules = declaration_sets
    result: list[_Target] = []
    reachable = [
        _natural(value, "reachable_target_ids[]")
        for value in _array(mixed.get("reachable_target_ids"), "reachable_target_ids")
    ]
    if reachable != sorted(set(reachable)):
        raise GnuHelloSourceTargetEffectInputsError(
            "reachable target identifiers must be sorted and unique"
        )
    for target_id in reachable:
        if target_id not in target_rvas:
            raise GnuHelloSourceTargetEffectInputsError(
                f"reachable target {target_id} is absent from the exact mixed index"
            )
        rva = target_rvas[target_id]
        ordinary_item = ordinary_by_rva.get(rva)
        x87_item = x87_by_rva.get(rva)
        if (ordinary_item is None) == (x87_item is None):
            raise GnuHelloSourceTargetEffectInputsError(
                f"reachable target {target_id} at RVA {rva} does not select "
                "exactly one semantic-source partition"
            )
        if ordinary_item is not None:
            index, _item = ordinary_item
            dependencies = (
                _find(source_modules, f"semanticInterpreterProgramRecord{index}", f"target {target_id} record"),
                _find(source_modules, f"semanticInterpreterTransfer{index}", f"target {target_id} transfer"),
                _find(normalization_modules, f"exactNormalizedTransferPath{index}", f"target {target_id} path"),
                _find(normalization_modules, f"exactNormalizedTransferPath{index}Certificate", f"target {target_id} normalization"),
                _find(semantic_modules, f"exactNormalizedTransferFusedMachineRefinement{index}", f"target {target_id} semantic refinement"),
            )
            result.append(_Target(target_id, rva, "ordinary", index, None, dependencies))
            continue
        assert x87_item is not None
        index, row = x87_item
        stop = _natural(_object(row["original"], "x87 original")["rva_end"], "x87 stop RVA")
        continuation = target_by_rva.get(stop)
        if continuation is None:
            raise GnuHelloSourceTargetEffectInputsError(
                f"x87 target {target_id} continuation RVA {stop} is not in the exact code map"
            )
        dependencies = (
            _find(x87_modules, f"checkedInterpreterX87Schedule{index:04d}Witness", f"target {target_id} x87 witness"),
            _find(x87_modules, f"checkedInterpreterX87Schedule{index:04d}SingletonFacts", f"target {target_id} x87 singleton facts"),
        )
        result.append(_Target(target_id, rva, "x87", index, continuation, dependencies))
    return result


def _base_source(
    *,
    state_machine_sha256: str,
    target_ids: list[int],
    source_declarations: Mapping[str, set[str]],
    normalization_declarations: Mapping[str, set[str]],
    x87_declarations: Mapping[str, set[str]],
    exact_declarations: Mapping[str, set[str]],
) -> tuple[str, dict[str, LeanDeclaration]]:
    records = _find(source_declarations, "semanticInterpreterProgramRecords", "semantic record inventory")
    records_unique = _find(source_declarations, "semanticInterpreterProgramSourceRvasUnique", "semantic record uniqueness")
    bindings = _find(normalization_declarations, "exactNormalizedOrdinaryRecordBindings", "ordinary binding inventory")
    witnesses = _find(x87_declarations, "checkedInterpreterX87ScheduleBundleWitnesses", "x87 witness inventory")
    x87_rvas = _find(x87_declarations, "checkedInterpreterX87ScheduleBundleSourceRvas", "x87 source inventory")
    x87_unique = _find(x87_declarations, "checkedInterpreterX87ScheduleBundleSourceRvasNodup", "x87 source uniqueness")
    mixed_program = _find(exact_declarations, "generatedOriginalCombinedProgram", "mixed original program")
    mixed_hash = _find(exact_declarations, "generatedOriginalStateMachineSha256", "mixed state-machine identity")
    mixed_targets = _find(exact_declarations, "generatedOriginalCombinedReachableTargetIds", "mixed target inventory")
    mixed_targets_unique = _find(exact_declarations, "generatedOriginalCombinedReachableTargetIdsUnique", "mixed target uniqueness")
    imports = sorted({
        records.module, records_unique.module, bindings.module, witnesses.module,
        x87_rvas.module, x87_unique.module, mixed_program.module,
        mixed_hash.module, mixed_targets.module, mixed_targets_unique.module,
    })
    target_literal = "[" + ", ".join(map(str, target_ids)) + "]"
    source = f"""{chr(10).join(f'import {module}' for module in imports)}
import StageA.RelationalSourceInterpreterKernel

namespace {GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_NAMESPACE}

open StageA.Formal StageA.Relational
open StageA.Relational.SourceWorld.InterpreterKernel

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedStateMachineSha256 : String := "{state_machine_sha256}"

theorem generatedStateMachineSha256Exact :
    generatedStateMachineSha256 = {mixed_hash.declaration} := by
  rfl

abbrev generatedWorldProgram : DecodedWorldProgram :=
  {mixed_program.declaration}

abbrev generatedOriginalPe : PE32 :=
  StageA.GeneratedRelational.originalPe

theorem generatedOriginalSide : generatedWorldProgram.candidate = false := by
  rfl

theorem generatedOriginalPeExact :
    generatedWorldProgram.context.originalPe = generatedOriginalPe := by
  rfl

def generatedX87Provider : X87Provider :=
  exactX87Provider {witnesses.declaration}

def generatedSourceProgramConstructor
    (worldProgram : DecodedWorldProgram) : Program := {{
  worldProgram
  records := {records.declaration}
  x87SourceRvas := {x87_rvas.declaration}
  x87Provider := generatedX87Provider
}}

theorem generatedOrdinaryRecordsExact :
    {bindings.declaration}.map (fun binding => binding.path.record) =
      {records.declaration} := by
  native_decide

def generatedExactBindingPartition (worldProgram : DecodedWorldProgram) :
    ExactBindingPartition generatedOriginalPe
      (generatedSourceProgramConstructor worldProgram) := {{
  ordinaryBindings := {bindings.declaration}
  ordinaryRecordsExact := by
    simpa only [generatedSourceProgramConstructor] using
      generatedOrdinaryRecordsExact
  recordsUnique := by
    simpa only [generatedSourceProgramConstructor] using
      {records_unique.declaration}
  x87SourcesUnique := by
    simpa only [generatedSourceProgramConstructor] using
      {x87_unique.declaration}
  x87Witnesses := {witnesses.declaration}
  x87WitnessesCovered := by
    intro sourceRva member
    change List.Mem sourceRva {x87_rvas.declaration} at member
    change List.Mem sourceRva ({witnesses.declaration}.map
      (fun witness => witness.schedule.sourceRva)) at member
    exact List.mem_map.mp member
  x87ProviderExact := by
    intro sourceRva _ witness member sourceExact state
    subst sourceRva
    simpa only [generatedSourceProgramConstructor, generatedX87Provider] using
      (exactX87Provider_execute
        (by simpa only [{x87_rvas.declaration}] using {x87_unique.declaration})
        member state)
}}

def generatedExactBindingConstructor
    (worldProgram : DecodedWorldProgram)
    (originalSide : worldProgram.candidate = false)
    (originalPeExact : worldProgram.context.originalPe = generatedOriginalPe) :
    ExactBinding generatedOriginalPe
      (generatedSourceProgramConstructor worldProgram) :=
  (generatedExactBindingPartition worldProgram).toExactBinding
    (by simpa only [generatedSourceProgramConstructor] using originalSide)
    (by simpa only [generatedSourceProgramConstructor] using originalPeExact)

theorem generatedInstructionSemanticsAdequate :
    (generatedSourceProgramConstructor
      generatedWorldProgram).worldProgram.InstructionSemanticsAdequate :=
  DecodedWorldProgram.instructionSemanticsAdequate_of_checked _ (by
    decide +kernel)

abbrev generatedTargetInventory : List Nat :=
  {mixed_targets.declaration}

theorem generatedTargetInventoryUnique : generatedTargetInventory.Nodup :=
  {mixed_targets_unique.declaration}

theorem generatedSubmittedTargetIdsExact :
    {target_literal} = generatedTargetInventory := by
  rfl

end {GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_NAMESPACE}
"""
    module = f"StageA.{GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_MODULE_PREFIX}Data"
    namespace = GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_NAMESPACE
    declarations = {
        "world_program": LeanDeclaration(module, f"{namespace}.generatedWorldProgram"),
        "original_pe": LeanDeclaration(module, f"{namespace}.generatedOriginalPe"),
        "original_side": LeanDeclaration(module, f"{namespace}.generatedOriginalSide"),
        "original_pe_exact": LeanDeclaration(module, f"{namespace}.generatedOriginalPeExact"),
        "source_program_constructor": LeanDeclaration(module, f"{namespace}.generatedSourceProgramConstructor"),
        "instruction_semantics_adequate": LeanDeclaration(module, f"{namespace}.generatedInstructionSemanticsAdequate"),
        "exact_binding_constructor": LeanDeclaration(module, f"{namespace}.generatedExactBindingConstructor"),
        "target_inventory": LeanDeclaration(module, f"{namespace}.generatedTargetInventory"),
        "target_inventory_unique": LeanDeclaration(module, f"{namespace}.generatedTargetInventoryUnique"),
        "submitted_target_ids_exact": LeanDeclaration(module, f"{namespace}.generatedSubmittedTargetIdsExact"),
    }
    return source, declarations


_REPLAY_SIMPLIFIER = """ordinaryStep?, ordinaryStepWithCalls?,
      applyOrdinaryMachineImportContractsToStep?,
      applyOrdinaryMachineImportContracts?, callActionIndices,
      terminalCallIndex?, callBoundary?, callBoundaryOutcome?,
      completionOutcome?, completionForCall, callBoundaryMacroResult,
      DecodedWorldProgram.machineImportContractsAt,
      regionBehaviorWithMachineCallContracts, regionBehaviorWithImports,
      executePE32SymbolicSpan, runPE32SymbolicSpanFuel,
      normalizeSymbolicBehavior, NormalizedSymbolicBehavior.eval,
      evaluatedEffectOfBehavior, ProgramRecord.interpret,
      SemanticTransfer.execute, SemanticTransfer.executeBody,
      SemanticTransfer.executeAction, SemanticWordNode.evaluate,
      SemanticOutcome.complete, evalPrimitive, RuntimeState.setWord,
      Register.ofIndex?, machineFromFormal,
      StageA.Relational.InterpreterMachineBridge.formalFromInterpreter,
      StageA.Relational.InterpreterMachineBridge.formalRegister,
      RelationalBehavior.nextMachineState, Registers.get, Registers.set,
      StageA.Formal.Expr.eval, StageA.Formal.X87Expr.eval,
      StageA.Formal.BoolExpr.eval, StageA.Formal.FlagsExpr.eval,
      StageA.Formal.applyWrites, Memory.read32"""


def _ordinary_target_source(target: _Target, data_module: str) -> tuple[str, dict[str, LeanDeclaration]]:
    record, transfer, path, certificate, fused = target.dependencies
    namespace = GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_NAMESPACE
    prefix = f"generatedOrdinary{target.target_id}"
    common = f"""generatedSourceProgramConstructor generatedWorldProgram,
      generatedWorldProgram, generatedOriginalPe, {prefix}Region,
      {record.declaration}, {transfer.declaration}, {path.declaration},
      {certificate.declaration}, {_REPLAY_SIMPLIFIER}"""
    source = f"""def {prefix}Region : RegionRelation :=
  (regionById generatedWorldProgram.regions {target.target_id}).get
    (by decide +kernel)

theorem {prefix}SourceExact :
    sourceRvaForTarget?
      (generatedSourceProgramConstructor generatedWorldProgram)
      {target.target_id} = some {target.source_rva} := by
  decide +kernel

theorem {prefix}ClassificationExact :
    x87Classified (generatedSourceProgramConstructor generatedWorldProgram)
      {target.source_rva} = some false := by
  decide +kernel

theorem {prefix}RecordLookupExact :
    lookupRecord?
      (generatedSourceProgramConstructor generatedWorldProgram).records
      {target.source_rva} = some {record.declaration} := by
  decide +kernel

theorem {prefix}RegionExact :
    regionById generatedWorldProgram.regions {target.target_id} =
      some {prefix}Region := by
  exact (Option.some_get (by decide +kernel)).symm

theorem {prefix}PathRecordExact :
    {path.declaration}.record = {record.declaration} := by
  rfl

theorem {prefix}PathSourceExact :
    {path.declaration}.sourceRva = {target.source_rva} := by
  rfl

theorem {prefix}RegionStartExact :
    {prefix}Region.original.start = {path.declaration}.sourceRva := by
  decide +kernel

theorem {prefix}RegionStopExact :
    {prefix}Region.original.stop = {path.declaration}.stopRva := by
  decide +kernel

theorem {prefix}NonX87 :
    StageA.Relational.X87.spanStartsWithX87Command generatedOriginalPe
      {prefix}Region.original = false := by
  decide +kernel

theorem {prefix}RecordMember :
    List.Mem {record.declaration}
      (generatedSourceProgramConstructor generatedWorldProgram).records := by
  decide +kernel

theorem {prefix}NotX87 :
    Not (List.Mem {target.source_rva}
      (generatedSourceProgramConstructor generatedWorldProgram).x87SourceRvas) := by
  decide +kernel

noncomputable def {prefix}SemanticReplay
    (binding : ExactOrdinaryTargetBinding generatedOriginalPe
      (generatedSourceProgramConstructor generatedWorldProgram)
      {target.target_id} {target.source_rva} {record.declaration}
      {path.declaration} {transfer.declaration} {prefix}Region) :
    ExactOrdinaryTargetSemanticReplay binding :=
  ExactOrdinaryTargetSemanticReplay.ofCheckedEvaluators binding
    (by
      intro state
      simp (config := {{ maxSteps := 4000000 }}) [{common}])
    (by
      intro state calls
      rcases calls with _ | continuation tail <;>
        simp (config := {{ maxSteps := 4000000 }}) [{common}])
    (by
      intro calls
      rcases calls with _ | continuation tail <;>
        simp (config := {{ maxSteps := 4000000 }}) [{common}])
    (by
      intro calls
      rcases calls with _ | continuation tail <;>
        simp (config := {{ maxSteps := 4000000 }}) [{common}])
    (by
      intro state calls
      have fusedMachine := {fused.declaration}
      rcases calls with _ | continuation tail <;>
        simp (config := {{ maxSteps := 4000000 }}) [{common}])
"""
    module = f"StageA.{data_module}"
    def declaration(local: str) -> LeanDeclaration:
        return LeanDeclaration(module, f"{namespace}.{prefix}{local}")
    fields = {
        "region": declaration("Region"),
        "source_exact": declaration("SourceExact"),
        "classification_exact": declaration("ClassificationExact"),
        "record_lookup_exact": declaration("RecordLookupExact"),
        "region_exact": declaration("RegionExact"),
        "path_record_exact": declaration("PathRecordExact"),
        "path_source_exact": declaration("PathSourceExact"),
        "region_start_exact": declaration("RegionStartExact"),
        "region_stop_exact": declaration("RegionStopExact"),
        "non_x87": declaration("NonX87"),
        "record_member": declaration("RecordMember"),
        "not_x87": declaration("NotX87"),
        "semantic_replay": declaration("SemanticReplay"),
    }
    return source, fields


def _x87_target_source(target: _Target, data_module: str) -> tuple[str, dict[str, LeanDeclaration]]:
    witness, schedule = target.dependencies
    assert target.continuation_target_id is not None
    namespace = GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_NAMESPACE
    prefix = f"generatedX87{target.target_id}"
    source = f"""def {prefix}Region : RegionRelation :=
  (regionById generatedWorldProgram.regions {target.target_id}).get
    (by decide +kernel)

theorem {prefix}SourceRvaExact :
    sourceRvaForTarget?
      (generatedSourceProgramConstructor generatedWorldProgram)
      {target.target_id} = some {witness.declaration}.schedule.sourceRva := by
  decide +kernel

theorem {prefix}ClassificationExact :
    x87Classified (generatedSourceProgramConstructor generatedWorldProgram)
      {witness.declaration}.schedule.sourceRva = some true := by
  decide +kernel

theorem {prefix}Classified :
    List.Mem {witness.declaration}.schedule.sourceRva
      (generatedSourceProgramConstructor generatedWorldProgram).x87SourceRvas := by
  decide +kernel

abbrev {prefix}Partition :=
  generatedExactBindingPartition generatedWorldProgram

theorem {prefix}WitnessMember :
    List.Mem {witness.declaration} {prefix}Partition.x87Witnesses := by
  decide +kernel

theorem {prefix}RegionExact :
    regionById generatedWorldProgram.regions {target.target_id} =
      some {prefix}Region := by
  exact (Option.some_get (by decide +kernel)).symm

theorem {prefix}RegionSpanExact :
    {prefix}Region.original = {schedule.declaration}.record.span := by
  decide +kernel

theorem {prefix}SourceContinuationExact :
    targetIdForRva? (generatedSourceProgramConstructor generatedWorldProgram)
      {schedule.declaration}.record.span.stop =
        some {target.continuation_target_id} := by
  decide +kernel

theorem {prefix}DecodedContinuationExact :
    normalizeCodeTarget false {prefix}Region.targets
      {schedule.declaration}.record.span.stop =
        some {target.continuation_target_id} := by
  decide +kernel
"""
    module = f"StageA.{data_module}"
    def declaration(local: str) -> LeanDeclaration:
        return LeanDeclaration(module, f"{namespace}.{prefix}{local}")
    fields = {
        "source_rva_exact": declaration("SourceRvaExact"),
        "classification_exact": declaration("ClassificationExact"),
        "classified": declaration("Classified"),
        "partition": declaration("Partition"),
        "witness_member": declaration("WitnessMember"),
        "region": declaration("Region"),
        "region_exact": declaration("RegionExact"),
        "region_span_exact": declaration("RegionSpanExact"),
        "source_continuation_exact": declaration("SourceContinuationExact"),
        "decoded_continuation_exact": declaration("DecodedContinuationExact"),
    }
    return source, fields


def _decl_json(declaration: LeanDeclaration) -> dict[str, str]:
    return {"module": declaration.module, "declaration": declaration.declaration}


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )


def generate_gnu_hello_source_target_effect_inputs(
    out: Path | str,
    *,
    state_machine: Path | str,
    mixed_original_plan: Path | str,
    source_program_root: Path | str,
    source_program_manifest: Path | str,
    normalization_root: Path | str,
    normalization_inventory: Path | str,
    semantic_refinement_root: Path | str,
    semantic_refinement_inventory: Path | str,
    x87_root: Path | str,
    x87_inventory: Path | str,
    exact_original_root: Path | str,
    shard_span: int = 64,
) -> GeneratedSourceTargetEffectInputs:
    """Generate hash-bound Lean authority for every mixed reachable target."""

    if not isinstance(shard_span, int) or isinstance(shard_span, bool) or shard_span <= 0:
        raise GnuHelloSourceTargetEffectInputsError("shard_span must be positive")
    artifacts = ArtifactSet(
        *(Path(value) for value in (
            state_machine, mixed_original_plan, source_program_root,
            source_program_manifest, normalization_root,
            normalization_inventory, semantic_refinement_root,
            semantic_refinement_inventory, x87_root, x87_inventory,
            exact_original_root,
        ))
    )
    try:
        rows, mixed, _target_kinds, declaration_sets = _validate_artifacts(artifacts)
    except (GnuHelloSourceTargetEffectsError, StageAInputError) as error:
        raise GnuHelloSourceTargetEffectInputsError(str(error)) from error
    exact_declarations = _module_declarations(artifacts.exact_original_root)
    target_rvas, target_by_rva = _target_index(artifacts.exact_original_root, mixed)
    targets = _targets(
        rows, mixed, declaration_sets, exact_declarations, target_rvas,
        target_by_rva,
    )
    reachable = [target.target_id for target in targets]
    source, base = _base_source(
        state_machine_sha256=_sha256(artifacts.state_machine),
        target_ids=reachable,
        source_declarations=declaration_sets[0],
        normalization_declarations=declaration_sets[1],
        x87_declarations=declaration_sets[3],
        exact_declarations=exact_declarations,
    )

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    modules: list[Path] = []
    data_name = f"{GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_MODULE_PREFIX}Data"
    data_path = stage_a / f"{data_name}.lean"
    data_path.write_text(source, encoding="ascii")
    modules.append(data_path)

    target_fields: dict[int, dict[str, LeanDeclaration]] = {}
    for bucket_start in range(0, len(targets), shard_span):
        members = targets[bucket_start : bucket_start + shard_span]
        shard_index = bucket_start // shard_span
        module_name = (
            f"{GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_MODULE_PREFIX}"
            f"Shard{shard_index:06d}"
        )
        dependency_imports = sorted({
            declaration.module
            for target in members
            for declaration in target.dependencies
        })
        bodies: list[str] = []
        for target in members:
            if target.kind == "ordinary":
                body, fields = _ordinary_target_source(target, module_name)
            else:
                body, fields = _x87_target_source(target, module_name)
            bodies.append(body)
            target_fields[target.target_id] = fields
        shard_source = f"""import StageA.{data_name}
{chr(10).join(f'import {module}' for module in dependency_imports)}
import StageA.RelationalSourceOrdinaryTargetRouting
import StageA.RelationalSourceX87TargetRouting

namespace {GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_NAMESPACE}

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterSemanticRefinement
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{chr(10).join(bodies)}
end {GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_NAMESPACE}
"""
        if _FORBIDDEN_PROOF_MARKER.search(shard_source):
            raise GnuHelloSourceTargetEffectInputsError(
                f"generated shard {module_name} contains an unchecked proof marker"
            )
        path = stage_a / f"{module_name}.lean"
        path.write_text(shard_source, encoding="ascii")
        modules.append(path)

    authority_targets: list[dict[str, Any]] = []
    for target in targets:
        fields = target_fields[target.target_id]
        if target.kind == "ordinary":
            authority_targets.append({
                "target_id": target.target_id,
                "source_rva": target.source_rva,
                "kind": "ordinary",
                "evidence": {
                    "region": _decl_json(fields["region"]),
                    "static": {
                        name: _decl_json(fields[name])
                        for name in (
                            "source_exact", "classification_exact",
                            "record_lookup_exact", "region_exact",
                            "path_record_exact", "path_source_exact",
                            "region_start_exact", "region_stop_exact",
                            "non_x87", "record_member", "not_x87",
                        )
                    },
                    "dynamic": {
                        "semantic_replay": _decl_json(fields["semantic_replay"])
                    },
                },
            })
        else:
            authority_targets.append({
                "target_id": target.target_id,
                "source_rva": target.source_rva,
                "kind": "x87",
                "evidence": {
                    "continuation_target_id": target.continuation_target_id,
                    **{name: _decl_json(fields[name]) for name in (
                        "source_rva_exact", "classification_exact",
                        "classified", "partition", "witness_member", "region",
                        "region_exact", "region_span_exact",
                        "source_continuation_exact",
                        "decoded_continuation_exact",
                    )},
                },
            })

    authority = {
        "format": GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_FORMAT,
        "imports": [f"StageA.{path.stem}" for path in modules],
        "authority_modules": {
            f"StageA.{path.stem}": _sha256(path) for path in modules
        },
        "namespace": GNU_HELLO_SOURCE_TARGET_EFFECTS_NAMESPACE,
        "module_prefix": GNU_HELLO_SOURCE_TARGET_EFFECTS_MODULE_PREFIX,
        "shard_span": shard_span,
        "artifact_bindings": _artifact_bindings(artifacts),
        **{name: _decl_json(value) for name, value in base.items()},
        "targets": authority_targets,
    }
    authority_path = root / "source-target-effect-inputs.json"
    _write_json(authority_path, authority)
    manifest = {
        "format": GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_MANIFEST_FORMAT,
        "proof_authority": False,
        "acceptance_authority": False,
        "validation_required": "lean-kernel-check-and-axiom-audit",
        "state_machine_sha256": _sha256(artifacts.state_machine),
        "artifact_bindings": authority["artifact_bindings"],
        "authority": {
            "path": authority_path.name,
            "sha256": _sha256(authority_path),
        },
        "modules": {
            f"StageA.{path.stem}": {
                "source_sha256": _sha256(path),
                "declarations": sorted(
                    set(_DECLARATION.findall(path.read_text(encoding="ascii")))
                ),
            }
            for path in modules
        },
        "counts": {
            "targets": len(targets),
            "ordinary": sum(target.kind == "ordinary" for target in targets),
            "x87": sum(target.kind == "x87" for target in targets),
            "shards": len(modules) - 1,
        },
    }
    manifest_path = root / "source-target-effect-inputs-manifest.json"
    _write_json(manifest_path, manifest)
    return GeneratedSourceTargetEffectInputs(
        modules=tuple(modules),
        authority_inventory=authority_path,
        manifest=manifest_path,
        target_count=len(targets),
        ordinary_count=manifest["counts"]["ordinary"],
        x87_count=manifest["counts"]["x87"],
    )


__all__ = [
    "GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_MANIFEST_FORMAT",
    "GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_MODULE_PREFIX",
    "GNU_HELLO_SOURCE_TARGET_EFFECT_INPUTS_NAMESPACE",
    "GeneratedSourceTargetEffectInputs",
    "GnuHelloSourceTargetEffectInputsError",
    "generate_gnu_hello_source_target_effect_inputs",
]
