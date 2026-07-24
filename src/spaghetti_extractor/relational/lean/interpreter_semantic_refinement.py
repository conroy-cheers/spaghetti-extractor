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
    "stage-a-relational-interpreter-semantic-refinement-v1"
)


_SIMPLIFIER_DEFINITIONS = """ExactNormalizedTransferPath.instructions,
      ExactDecodedInstruction.decode?, decodeInstructionExact,
      DecodedInstruction.consumesExactly, decodeInstruction,
      runExactDecodedInstructions, executeExactDecodedInstruction?,
      exactInstructionMemoryEvents?, executeInstruction,
      SemanticTransfer.execute, SemanticTransfer.executeBody,
      SemanticTransfer.executeAction, SemanticWordNode.evaluate,
      SemanticOutcome.complete, halted, evalPrimitive,
      RuntimeState.setWord, Register.ofIndex?, formalRegister,
      machineFromFormal, exactResult, concreteBehaviorNextMachineState,
      SymbolicBehavior.eval, initialSymbolic, initialSymbolicX87,
      Addressing.expression, Registers.set, Registers.get,
      Expr.addNormalized, StageA.Formal.Expr.eval,
      StageA.Formal.X87Expr.eval, StageA.Formal.BoolExpr.eval,
      StageA.Formal.FlagsExpr.eval, StageA.Formal.applyWrites,
      readMemory, InterpreterMachine.setRegister, reconstructedInputFlags"""


def _exact_byte_facts(item: Mapping[str, Any]) -> tuple[str, list[str]]:
    definitions: list[str] = []
    names: list[str] = []
    for instruction_index, (rva, encoded) in enumerate(item["instructions"]):
        name = f"exactBytes{instruction_index}"
        names.append(name)
        definitions.append(
            f"""    have {name} :
      exactRvaBytes originalPe {rva} {len(encoded)} =
        some {_bytes_literal(encoded)} := by
      decide +kernel"""
        )
    return "\n".join(definitions), names


def _theorem(source_index: int, item: Mapping[str, Any]) -> str:
    path = f"exactNormalizedTransferPath{source_index}"
    transfer = f"semanticInterpreterTransfer{source_index}"
    exact_facts, exact_names = _exact_byte_facts(item)
    simplifier_inputs = ",\n      ".join(
        [path, transfer, *exact_names, _SIMPLIFIER_DEFINITIONS]
    )
    return f"""theorem exactNormalizedTransferSemanticRefinement{source_index} :
    SemanticTransferRefinesExactPath originalPe {path} {transfer} := by
  apply semanticTransferRefinesOfExactExecution originalPe originalImports
  · decide +kernel
  · decide +kernel
  · intro state environment
{exact_facts}
    simp (config := {{ maxSteps := 4000000 }})
      [{simplifier_inputs}]
"""


def relational_interpreter_semantic_refinement_bundle_sources(
    rows: Iterable[Mapping[str, Any]],
    *,
    pe_module: str,
    path_module_prefix: str = "GeneratedInterpreterNormalizationShard",
    module_prefix: str = "GeneratedInterpreterSemanticRefinement",
    shard_size: int = 48,
) -> dict[str, str]:
    """Emit Lean-checked ordinary transfer refinements in deterministic shards.

    Python only validates and renders immutable terms.  Every emitted theorem
    universally quantifies over machine state and external environment; Lean
    re-reads the PE bytes and checks the reduction.  A semantic form that does
    not reduce through the reviewed exact runner leaves its shard unbuildable.
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
        theorems = "\n".join(
            _theorem(source_index, item) for source_index, item in shard
        )
        sources[module] = f"""import StageA.RelationalInterpreterSemanticRefinement
import {pe_module}
import StageA.{path_module}

namespace StageA.GeneratedRelational

set_option linter.unusedSimpArgs false

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
    sources[bundle] = f"""{imports}

namespace StageA.GeneratedRelational

def exactNormalizedTransferSemanticRefinementTheorems : List String := [
  {theorem_inventory}
]

theorem exactNormalizedTransferSemanticRefinementTheoremCount :
    exactNormalizedTransferSemanticRefinementTheorems.length =
      {len(theorem_names)} := by decide +kernel

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
    if theorem_count != transfer_count:
        raise StageAInputError(
            "semantic refinement theorem inventory changed cardinality"
        )
    return {
        "format": RELATIONAL_INTERPRETER_SEMANTIC_REFINEMENT_FORMAT,
        "status": "lean_check_required",
        "proof_authority": False,
        "transfer_count": transfer_count,
        "theorem_count": theorem_count,
        "shard_count": len(shards),
        "modules": modules,
        "target": "GeneratedInterpreterSemanticRefinementBundle",
    }
