from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from ...errors import StageAInputError
from .interpreter_normalization import (
    _bytes_literal,
    _local_name,
    _ordinary_items,
    _stage_a_module,
)


RELATIONAL_INTERPRETER_SEMANTIC_REFINEMENT_FORMAT = (
    "stage-a-relational-interpreter-semantic-refinement-v2"
)


_SIMPLIFIER_DEFINITIONS = """ExactNormalizedTransferPath.instructions,
      ExactDecodedInstruction.decode?,
      runExactDecodedInstructions, executeExactDecodedInstruction?,
      exactInstructionMemoryEvents?, executeInstruction,
      executeInstructionWithContext, originalImports,
      SemanticTransfer.execute, SemanticTransfer.executeBody,
      SemanticTransfer.executeAction, SemanticWordNode.evaluate,
      SemanticOutcome.complete, halted, evalPrimitive,
      RuntimeState.setWord, Register.ofIndex?,
      StageA.Relational.InterpreterMachineBridge.formalRegister,
      MemoryWidth.ofBytes?, machineFromFormal,
      StageA.Relational.InterpreterMachineBridge.machineFromFormal,
      exactResult, exactReadEvent, exactWriteEvent,
      concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Addressing.expression, Registers.set, Registers.get,
      Expr.addNormalized, StageA.Formal.Expr.eval,
      evalInputRegisterOffset, symbolicRead32,
      exactWrite32WithDisjointTail?,
      StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      readMemory, InterpreterMachine.setRegister,
      StageA.Relational.InterpreterMachineBridge.machineFromFormal_syncEflags,
      StageA.Relational.InterpreterMachineBridge.flagsFromEflags_syncEflags,
      Memory.read32,
      reconstructedInputFlags"""

_FUSED_SYMBOLIC_SIMPLIFIER_DEFINITIONS = """executePE32SymbolicSpan,
      runPE32SymbolicSpanFuel, Span.stop,
      executeInstruction, executeInstructionWithContext, originalImports,
      initialSymbolic,
      initialSymbolicX87, Addressing.expression, Registers.set, Registers.get,
      Expr.addNormalized, signExtendImmediate8"""

_FUSED_TRANSFER_SIMPLIFIER_DEFINITIONS = """SemanticTransfer.execute,
      SemanticTransfer.executeBody, SemanticTransfer.executeAction,
      SemanticWordNode.evaluate, SemanticOutcome.complete, halted,
      evalPrimitive, RuntimeState.setWord, Register.ofIndex?,
      StageA.Relational.InterpreterMachineBridge.formalRegister,
      machineFromFormal, InterpreterMachine.setRegister"""

_FUSED_MACHINE_SIMPLIFIER_DEFINITIONS = """NormalizedSymbolicBehavior.eval,
      RelationalBehavior.nextMachineState, machineFromFormal,
      evalNormalizedRegisters, evalNormalizedX87, evalNormalizedWrites,
      evalNormalizedFlags, applyConcreteWrites, StageA.Formal.applyWrites,
      InterpreterTransfer.applyWrites, StageA.Formal.Expr.eval,
      StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, Expr.addNormalized, signExtendImmediate8,
      reconstructedInputFlags"""

_REGISTER_FUNCTION_SIMPLIFIER_DEFINITIONS = """Registers.get,
      StageA.Relational.InterpreterMachineBridge.formalRegister,
      Expr.addNormalized, signExtendImmediate8, StageA.Formal.Expr.eval,
      BitVec.add_comm"""


def _exact_byte_facts(item: Mapping[str, Any]) -> tuple[str, list[str]]:
    definitions: list[str] = []
    names: list[str] = []
    for instruction_index, (rva, encoded) in enumerate(item["instructions"]):
        name = f"exactBytes{instruction_index}"
        decoded = f"exactDecoded{instruction_index}"
        decoded_fact = f"exactDecodedFact{instruction_index}"
        names.extend((name, decoded, decoded_fact))
        definitions.append(
            f"""    have {name} :
      exactRvaBytes originalPe {rva} {len(encoded)} =
        some {_bytes_literal(encoded)} := by
      decide +kernel"""
        )
        definitions.append(
            f"""    let {decoded} : DecodedInstruction :=
      exactDecodedInstruction% {_bytes_literal(encoded)}
    have {decoded_fact} :
      decodeInstructionExact {_bytes_literal(encoded)} =
        some {decoded} := by
      rfl"""
        )
    return "\n".join(definitions), names


def _exact_window_facts(
    item: Mapping[str, Any], *, indent: str = "  "
) -> tuple[str, list[str]]:
    definitions: list[str] = []
    names: list[str] = []
    encoded_span = b"".join(encoded for _, encoded in item["instructions"])
    for instruction_index, (rva, _) in enumerate(item["instructions"]):
        offset = rva - item["start"]
        window = encoded_span[offset : offset + min(15, item["stop"] - rva)]
        name = f"exactWindow{instruction_index}"
        decoded = f"exactWindowDecoded{instruction_index}"
        decoded_fact = f"exactWindowDecodedFact{instruction_index}"
        names.extend((name, decoded, decoded_fact))
        definitions.append(
            f"""{indent}have {name} :
{indent}    executableSpanInstructionWindow originalPe {rva} {item['stop']} =
{indent}      some {_bytes_literal(window)} := by
{indent}    decide +kernel"""
        )
        definitions.append(
            f"""{indent}let {decoded} : DecodedInstruction :=
{indent}  exactDecodedInstruction% {_bytes_literal(window)}
{indent}have {decoded_fact} :
{indent}    decodeInstructionExact {_bytes_literal(window)} =
{indent}      some {decoded} := by
{indent}  rfl"""
        )
    return "\n".join(definitions), names


def _theorem(
    source_index: int, item: Mapping[str, Any], *, emit_fused: bool
) -> str:
    path = f"exactNormalizedTransferPath{source_index}"
    transfer = f"semanticInterpreterTransfer{source_index}"
    exact_facts, exact_names = _exact_byte_facts(item)
    simplifier_inputs = ",\n      ".join(
        [path, transfer, *exact_names, _SIMPLIFIER_DEFINITIONS]
    )
    exact_windows, exact_window_names = _exact_window_facts(item)
    fused_symbolic_inputs = ",\n      ".join(
        [*exact_window_names, _FUSED_SYMBOLIC_SIMPLIFIER_DEFINITIONS]
    )
    exact_theorem = f"""set_option maxHeartbeats 0 in
theorem exactNormalizedTransferSemanticRefinement{source_index} :
    SemanticTransferRefinesExactPath originalPe {path} {transfer} := by
  apply semanticTransferRefinesOfExactExecution originalPe originalImports
  · decide +kernel
  · decide +kernel
  · intro state environment
{exact_facts}
    set_option maxHeartbeats 0 in
      simp (config := {{ maxSteps := 4000000 }})
        [{simplifier_inputs}]
    all_goals
      funext register
      cases register <;>
        simp [{_REGISTER_FUNCTION_SIMPLIFIER_DEFINITIONS}]
"""
    if not emit_fused:
        return exact_theorem

    return exact_theorem + f"""
set_option maxHeartbeats 0 in
theorem exactNormalizedTransferFusedMachineRefinement{source_index} :
    ExactSemanticTransferFusedMachineRefinement originalPe originalImports
      {{ start := {item['start']}, size := {item['stop'] - item['start']} }}
      {transfer} := by
  intro targets state environment symbolic behavior result symbolicExact
    evaluated transferExact
{exact_windows}
  set_option maxHeartbeats 0 in
    simp (config := {{ maxSteps := 4000000 }})
      [{fused_symbolic_inputs}] at symbolicExact
  subst symbolic
  unfold evalBehavior at evaluated
  generalize normalizedExact :
      normalizeSymbolicBehavior false targets _ = normalized at evaluated
  cases normalized with
  | none => simp at evaluated
  | some normalized =>
      injection evaluated with evaluated
      subst behavior
      set_option maxHeartbeats 0 in
        simp (config := {{ maxSteps := 4000000 }})
          [{transfer}, {_FUSED_TRANSFER_SIMPLIFIER_DEFINITIONS}] at transferExact
      subst result
      obtain ⟨registersExact, x87Exact, writesExact, flagsExact⟩ :=
        normalizeSymbolicBehavior_fields false targets _ normalized
          normalizedExact
      simp [registersExact, x87Exact, writesExact, flagsExact,
        {_FUSED_MACHINE_SIMPLIFIER_DEFINITIONS}]
      all_goals
        funext register
        cases register <;>
          simp [{_REGISTER_FUNCTION_SIMPLIFIER_DEFINITIONS}]
"""


def relational_interpreter_semantic_refinement_bundle_sources(
    rows: Iterable[Mapping[str, Any]],
    *,
    pe_module: str,
    path_module_prefix: str = "GeneratedInterpreterNormalizationShard",
    module_prefix: str = "GeneratedInterpreterSemanticRefinement",
    shard_size: int = 48,
    emit_fused: bool = True,
) -> dict[str, str]:
    """Emit Lean-checked ordinary transfer refinements in deterministic shards.

    Python only validates and renders immutable terms.  Every emitted theorem
    universally quantifies over machine state and external environment; Lean
    re-reads the PE bytes and checks the exact-path reduction. By default it
    also checks the fused-span reduction used by binary-to-binary composition.
    Source equivalence may disable that unrelated layer and import only the
    lightweight exact-refinement kernel. A semantic form that does not reduce
    through the reviewed runners leaves its shard unbuildable. X87 schedule
    rows remain owned by the separate exact X87 replay pipeline.
    """

    pe_module, _ = _stage_a_module(pe_module, "pe_module")
    path_module_prefix = _local_name(path_module_prefix, "path_module_prefix")
    module_prefix = _local_name(module_prefix, "module_prefix")
    if shard_size <= 0:
        raise StageAInputError("semantic refinement shard_size must be positive")
    selected = _ordinary_items(rows)
    sources: dict[str, str] = {}
    shard_modules: list[str] = []
    theorem_names: list[str] = []
    fused_theorem_names: list[str] = []
    for shard_start in range(0, len(selected), shard_size):
        shard = selected[shard_start : shard_start + shard_size]
        shard_index = shard_start // shard_size
        module = f"{module_prefix}Shard{shard_index:04d}"
        path_module = f"{path_module_prefix}{shard_index:04d}Data"
        shard_modules.append(module)
        theorem_names.extend(
            f"exactNormalizedTransferSemanticRefinement{source_index}"
            for source_index, _ in shard
        )
        if emit_fused:
            fused_theorem_names.extend(
                f"exactNormalizedTransferFusedMachineRefinement{source_index}"
                for source_index, _ in shard
            )
        theorems = "\n".join(
            _theorem(source_index, item, emit_fused=emit_fused)
            for source_index, item in shard
        )
        refinement_kernel = (
            "StageA.RelationalInterpreterSemanticRefinement"
            if emit_fused
            else "StageA.RelationalInterpreterExactRefinement"
        )
        sources[module] = f"""import {refinement_kernel}
import {pe_module}
import StageA.{path_module}

set_option linter.unusedSimpArgs false
set_option maxHeartbeats 0

namespace StageA.GeneratedRelational

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterSemanticRefinement

{theorems}
end StageA.GeneratedRelational
"""

    bundle = f"{module_prefix}Bundle"
    imports = "\n".join(f"import StageA.{module}" for module in shard_modules)
    theorem_inventory = ",\n  ".join(f'"{name}"' for name in theorem_names)
    fused_theorem_inventory = ",\n  ".join(
        f'"{name}"' for name in fused_theorem_names
    )
    sources[bundle] = f"""{imports}

namespace StageA.GeneratedRelational

def exactNormalizedTransferSemanticRefinementTheorems : List String := [
  {theorem_inventory}
]

theorem exactNormalizedTransferSemanticRefinementTheoremCount :
    exactNormalizedTransferSemanticRefinementTheorems.length =
      {len(theorem_names)} := by decide +kernel

def exactNormalizedTransferFusedMachineRefinementTheorems : List String := [
  {fused_theorem_inventory}
]

theorem exactNormalizedTransferFusedMachineRefinementTheoremCount :
    exactNormalizedTransferFusedMachineRefinementTheorems.length =
      {len(fused_theorem_names)} := by decide +kernel

end StageA.GeneratedRelational
"""
    return sources


def relational_interpreter_semantic_refinement_inventory(
    sources: Mapping[str, str], *, transfer_count: int
) -> dict[str, Any]:
    if transfer_count <= 0:
        raise StageAInputError("semantic refinement transfer_count must be positive")
    modules = sorted(sources)
    shards = [module for module in modules if module.endswith(tuple("0123456789"))]
    theorem_count = sum(
        len(
            re.findall(
                r"^theorem exactNormalizedTransferSemanticRefinement[0-9]+\s*:",
                source,
                re.MULTILINE,
            )
        )
        for source in sources.values()
    )
    fused_theorem_count = sum(
        len(
            re.findall(
                r"^theorem "
                r"exactNormalizedTransferFusedMachineRefinement[0-9]+\s*:",
                source,
                re.MULTILINE,
            )
        )
        for source in sources.values()
    )
    if theorem_count != transfer_count:
        raise StageAInputError(
            "semantic refinement theorem inventory changed cardinality"
        )
    if fused_theorem_count != transfer_count:
        raise StageAInputError(
            "fused semantic refinement theorem inventory changed cardinality"
        )
    return {
        "format": RELATIONAL_INTERPRETER_SEMANTIC_REFINEMENT_FORMAT,
        "status": "lean_check_required",
        "proof_authority": False,
        "transfer_count": transfer_count,
        "theorem_count": theorem_count,
        "fused_theorem_count": fused_theorem_count,
        "shard_count": len(shards),
        "modules": modules,
        "target": "GeneratedInterpreterSemanticRefinementBundle",
    }
