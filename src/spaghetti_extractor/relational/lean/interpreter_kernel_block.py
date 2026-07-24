"""Generate Lean-reflected soundness obligations for compiled kernel blocks.

Python only partitions the already proposed kernel plan.  Lean re-parses the
candidate PE, rechecks imports, re-decodes every ``KernelInstruction``, and
symbolically executes each finite block.  Generated modules deliberately leave
the universal concrete-agreement proposition as a proof argument.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...errors import StageAInputError
from ...stage_binary import _parse_stage_a_pe
from ...util import sha256_bytes, write_json
from .common import _lean_import_certificate, _lean_pe
from .interpreter_kernel import InterpreterKernelPlan


INTERPRETER_KERNEL_BLOCK_PLAN_FORMAT = (
    "stage-a-relational-interpreter-kernel-block-plan-v1"
)
INTERPRETER_KERNEL_BLOCK_MODULE_INVENTORY_FORMAT = (
    "stage-a-relational-interpreter-kernel-block-module-inventory-v1"
)
INTERPRETER_KERNEL_BLOCK_PLAN_FILENAME = "interpreter-kernel-block-plan.json"
INTERPRETER_KERNEL_BLOCK_MODULE_INVENTORY_FILENAME = "module-inventory.json"
INTERPRETER_KERNEL_BLOCK_STANDALONE_MODULES_FILENAME = "standalone-modules.json"

_LEAN_LOCAL_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")
_LEAN_MODULE = re.compile(r"(?:[A-Za-z][A-Za-z0-9_]*)(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z")
_STAGE_A_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_.]+)$", re.MULTILINE)


class RelationalInterpreterKernelBlockGenerationError(StageAInputError):
    """The block proof graph cannot bind the submitted candidate and plan."""


@dataclass(frozen=True)
class KernelBlockProofObligation:
    ordinal: int
    function_index: int
    block_index: int
    function_role: str
    entry_rva: int
    instruction_count: int

    @property
    def local_name(self) -> str:
        return f"generatedKernelBlock{self.ordinal:04d}"

    @property
    def block_name(self) -> str:
        return (
            f"generatedKernelFunction{self.function_index:04d}"
            f"Block{self.block_index:04d}"
        )

    def payload(self) -> dict[str, Any]:
        return {
            "id": f"compiled-kernel-block:{self.entry_rva:08x}",
            "ordinal": self.ordinal,
            "function_index": self.function_index,
            "block_index": self.block_index,
            "function_role": self.function_role,
            "entry_rva": self.entry_rva,
            "instruction_count": self.instruction_count,
            "status": "pending_lean_universal_agreement",
        }


@dataclass(frozen=True)
class InterpreterKernelBlockProofPlan:
    candidate_sha256: str
    source_module: str
    source_namespace: str
    context_module: str
    module_prefix: str
    shard_size: int
    pe_literal: str
    import_certificate_literal: str
    obligations: tuple[KernelBlockProofObligation, ...]

    @property
    def shards(self) -> tuple[tuple[KernelBlockProofObligation, ...], ...]:
        return tuple(
            self.obligations[index : index + self.shard_size]
            for index in range(0, len(self.obligations), self.shard_size)
        )

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_BLOCK_PLAN_FORMAT,
            "status": "proof-obligations-generated",
            "acceptance_authority": False,
            "candidate_sha256": self.candidate_sha256,
            "source_module": self.source_module,
            "source_namespace": self.source_namespace,
            "context_module": self.context_module,
            "module_prefix": self.module_prefix,
            "shard_size": self.shard_size,
            "counts": {
                "blocks": len(self.obligations),
                "instructions": sum(
                    obligation.instruction_count for obligation in self.obligations
                ),
                "shards": len(self.shards),
                "closed_universal_agreements": 0,
            },
            "proof_obligations": [
                obligation.payload() for obligation in self.obligations
            ],
        }


def build_relational_interpreter_kernel_block_plan(
    kernel_plan: InterpreterKernelPlan,
    *,
    candidate_pe: Path | str,
    shard_size: int = 24,
    source_module: str = "GeneratedRelationalInterpreterKernel",
    source_namespace: str = "StageA.GeneratedRelational.InterpreterKernel",
    context_module: str = "GeneratedRelationalInterpreterKernelBlockContext",
    module_prefix: str = "GeneratedRelationalInterpreterKernelBlockShard",
) -> InterpreterKernelBlockProofPlan:
    """Bind every proposed kernel block to a deterministic Lean proof shard."""

    if shard_size <= 0 or shard_size > 256:
        raise RelationalInterpreterKernelBlockGenerationError(
            "kernel block shard size must be between 1 and 256"
        )
    for value, label, pattern in (
        (source_module, "source module", _LEAN_LOCAL_NAME),
        (source_namespace, "source namespace", _LEAN_MODULE),
        (context_module, "context module", _LEAN_LOCAL_NAME),
        (module_prefix, "module prefix", _LEAN_LOCAL_NAME),
    ):
        if pattern.fullmatch(value) is None:
            raise RelationalInterpreterKernelBlockGenerationError(
                f"invalid Lean {label}: {value!r}"
            )

    path = Path(candidate_pe)
    candidate_bytes = path.read_bytes()
    if candidate_bytes != kernel_plan.candidate_bytes:
        raise RelationalInterpreterKernelBlockGenerationError(
            "kernel block plan candidate differs from the compiled-kernel plan"
        )
    binary = _parse_stage_a_pe(path)
    try:
        obligations: list[KernelBlockProofObligation] = []
        seen_rvas: set[int] = set()
        for function_index, function in enumerate(kernel_plan.functions):
            for block_index, block in enumerate(function.blocks):
                if block.entry_rva in seen_rvas:
                    raise RelationalInterpreterKernelBlockGenerationError(
                        f"duplicate compiled-kernel block RVA 0x{block.entry_rva:x}"
                    )
                seen_rvas.add(block.entry_rva)
                obligations.append(
                    KernelBlockProofObligation(
                        ordinal=len(obligations),
                        function_index=function_index,
                        block_index=block_index,
                        function_role=function.role,
                        entry_rva=block.entry_rva,
                        instruction_count=len(block.instructions),
                    )
                )
        if not obligations:
            raise RelationalInterpreterKernelBlockGenerationError(
                "compiled-kernel plan contains no blocks"
            )
        return InterpreterKernelBlockProofPlan(
            candidate_sha256=sha256_bytes(candidate_bytes),
            source_module=source_module,
            source_namespace=source_namespace,
            context_module=context_module,
            module_prefix=module_prefix,
            shard_size=shard_size,
            pe_literal=_lean_pe(binary, "generatedKernelCandidateBytes"),
            import_certificate_literal=_lean_import_certificate(binary),
            obligations=tuple(obligations),
        )
    finally:
        binary.pe.close()


def _context_source(plan: InterpreterKernelBlockProofPlan) -> str:
    return f"""import StageA.RelationalInterpreterKernelBlock
import StageA.{plan.source_module}

namespace StageA.GeneratedRelational.InterpreterKernelBlock

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelBlock
open {plan.source_namespace}

def generatedKernelBlockCandidatePe : PE32 :=
  {plan.pe_literal}

def generatedKernelBlockImportCertificate : ImportTableCertificate :=
  {plan.import_certificate_literal}

def generatedKernelBlockImports : List PEImport :=
  generatedKernelBlockImportCertificate.imports

theorem generatedKernelBlockCandidateParsed :
    parsePE32Tree generatedKernelCandidateBytes =
      some generatedKernelBlockCandidatePe := by
  decide +kernel

theorem generatedKernelBlockImportsParsed :
    parseImports generatedKernelBlockCandidatePe =
      some generatedKernelBlockImports := by
  decide +kernel

end StageA.GeneratedRelational.InterpreterKernelBlock
"""


def _obligation_source(obligation: KernelBlockProofObligation) -> str:
    name = obligation.local_name
    block = obligation.block_name
    return f"""
def {name}Reflection : ReflectedKernelBlock :=
  (reflectKernelBlock? generatedKernelBlockCandidatePe
    generatedKernelBlockImports {block}).getD {{
      block := {block}
      instructions := []
      behavior := initialSymbolic
    }}

theorem {name}Reflected :
    reflectKernelBlock? generatedKernelBlockCandidatePe
      generatedKernelBlockImports {block} = some {name}Reflection := by
  decide +kernel

theorem {name}BlockExact : {name}Reflection.block = {block} := by
  decide +kernel

theorem {name}SymbolicExact :
    {block}.symbolicBehavior? generatedKernelBlockCandidatePe
      generatedKernelBlockImports = some {name}Reflection.behavior := by
  decide +kernel

/-- The sole semantic obligation left by reflection.  It quantifies over every
concrete machine state and cannot be discharged by extraction metadata. -/
def {name}UniversalAgreementGoal : Prop :=
  forall input,
    {block}.symbolicConcreteAgree {name}Reflection.behavior input
      (runKernelBlockConcrete generatedKernelBlockCandidatePe
        generatedKernelBlockImports 0 input {block}.instructions)

def {name}Certificate
    (agreement : {name}UniversalAgreementGoal) :
    ReflectiveBlockCertificate generatedKernelBlockCandidatePe
      generatedKernelBlockImports {block} := {{
  reflection := {name}Reflection
  reflected := {name}Reflected
  blockExact := {name}BlockExact
  symbolicExact := {name}SymbolicExact
  agrees := agreement
}}

theorem {name}Sound
    (agreement : {name}UniversalAgreementGoal) :
    {block}.SymbolicExecutionSound generatedKernelBlockCandidatePe
      generatedKernelBlockImports :=
  ({name}Certificate agreement).sound
"""


def relational_interpreter_kernel_block_bundle_sources(
    plan: InterpreterKernelBlockProofPlan,
) -> dict[str, str]:
    sources = {plan.context_module: _context_source(plan)}
    shard_modules: list[str] = []
    goal_names: list[str] = []
    for shard_index, obligations in enumerate(plan.shards):
        module = f"{plan.module_prefix}{shard_index:04d}"
        shard_modules.append(module)
        body = "\n".join(_obligation_source(item) for item in obligations)
        sources[module] = f"""import StageA.{plan.context_module}

namespace StageA.GeneratedRelational.InterpreterKernelBlock

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelBlock
open {plan.source_namespace}

{body}

end StageA.GeneratedRelational.InterpreterKernelBlock
"""
        goal_names.extend(
            f"{item.local_name}UniversalAgreementGoal" for item in obligations
        )

    bundle_module = f"{plan.module_prefix}Bundle"
    imports = "\n".join(f"import StageA.{module}" for module in shard_modules)
    goals = ",\n  ".join(goal_names)
    sources[bundle_module] = f"""{imports}

namespace StageA.GeneratedRelational.InterpreterKernelBlock

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open {plan.source_namespace}

def generatedKernelBlockUniversalAgreementGoals : List Prop := [
  {goals}
]

theorem generatedKernelBlockUniversalAgreementGoalCount :
    generatedKernelBlockUniversalAgreementGoals.length =
      {len(plan.obligations)} := by decide

/-- This remains a proposition until every shard supplies its universal
agreement theorem.  It is exactly the existing compiled-kernel block target. -/
abbrev GeneratedInterpreterKernelBlockSoundnessGoal : Prop :=
  GeneratedKernelBlockSoundnessGoal generatedKernelBlockCandidatePe
    generatedKernelBlockImports

end StageA.GeneratedRelational.InterpreterKernelBlock
"""
    return sources


def relational_interpreter_kernel_block_module_inventory(
    plan: InterpreterKernelBlockProofPlan,
) -> dict[str, Any]:
    sources = relational_interpreter_kernel_block_bundle_sources(plan)
    bundle_module = f"{plan.module_prefix}Bundle"
    modules = {
        module: {
            "imports": _STAGE_A_IMPORT.findall(source),
            "source_sha256": sha256_bytes(source.encode("utf-8")),
            "source_bytes": len(source.encode("utf-8")),
        }
        for module, source in sources.items()
    }
    generated = set(modules)
    external = sorted(
        {
            dependency
            for metadata in modules.values()
            for dependency in metadata["imports"]
            if dependency not in generated
        }
    )
    return {
        "format": INTERPRETER_KERNEL_BLOCK_MODULE_INVENTORY_FORMAT,
        "status": "proof-obligations-generated",
        "proof_authority": False,
        "modules": modules,
        "required_external_modules": external,
        "targets": {
            "context_node": plan.context_module,
            "shard_nodes": [
                f"{plan.module_prefix}{index:04d}"
                for index in range(len(plan.shards))
            ],
            "bundle_node": bundle_module,
        },
        "counts": {
            "blocks": len(plan.obligations),
            "instructions": sum(
                obligation.instruction_count for obligation in plan.obligations
            ),
            "shards": len(plan.shards),
            "generated_modules": len(sources),
        },
    }


def write_relational_interpreter_kernel_block_bundle(
    *,
    out: Path | str,
    kernel_plan: InterpreterKernelPlan,
    candidate_pe: Path | str,
    shard_size: int = 24,
    **kwargs: Any,
) -> InterpreterKernelBlockProofPlan:
    output = Path(out)
    stage_a = output / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_block_plan(
        kernel_plan,
        candidate_pe=candidate_pe,
        shard_size=shard_size,
        **kwargs,
    )
    sources = relational_interpreter_kernel_block_bundle_sources(plan)
    for module, source in sources.items():
        (stage_a / f"{module}.lean").write_text(source, encoding="utf-8")
    inventory = relational_interpreter_kernel_block_module_inventory(plan)
    write_json(output / INTERPRETER_KERNEL_BLOCK_PLAN_FILENAME, plan.payload())
    write_json(
        output / INTERPRETER_KERNEL_BLOCK_MODULE_INVENTORY_FILENAME,
        inventory,
    )
    write_json(
        output / INTERPRETER_KERNEL_BLOCK_STANDALONE_MODULES_FILENAME,
        sorted(sources),
    )
    return plan
