"""Generate the exact native ``programLookup`` proof interface.

The planner rejects every candidate outside the reviewed 161-byte template and
binds the generated module to the actual candidate bytes.  Its JSON output is
diagnostic only.  Lean obtains authority from the exact kernel-data module, the
reflected function summary, and the reviewed native instruction semantics.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_summary import (
    InterpreterKernelFunctionSummaryPlan,
    RelationalInterpreterKernelSummaryGenerationError,
    build_relational_interpreter_kernel_summary_plan,
)


INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT = (
    "stage-a-relational-interpreter-kernel-lookup-native-plan-v1"
)
INTERPRETER_KERNEL_LOOKUP_NATIVE_PLAN_FILENAME = (
    "interpreter-kernel-lookup-native-plan.json"
)
INTERPRETER_KERNEL_LOOKUP_NATIVE_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelLookupNative.lean"
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class RelationalInterpreterKernelLookupNativeGenerationError(StageAInputError):
    """The supplied candidate and proof inventories cannot be bound exactly."""


@dataclass(frozen=True)
class InterpreterKernelLookupNativePlan:
    summary: InterpreterKernelFunctionSummaryPlan
    candidate_path: Path
    candidate_size: int

    @property
    def candidate_sha256(self) -> str:
        return self.summary.candidate_sha256

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT,
            "acceptance_authority": False,
            "operation": "programLookup",
            "candidate": {
                "path": self.candidate_path.name,
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "kernel_plan": {
                    "path": self.summary.kernel_plan_path.name,
                    "sha256": self.summary.kernel_plan_sha256,
                },
                "data_inventory": {
                    "path": self.summary.data_inventory_path.name,
                    "sha256": self.summary.data_inventory_sha256,
                },
            },
            "template": {
                "bytes": self.summary.function_end_rva
                - self.summary.function_entry_rva,
                "blocks": self.summary.block_count,
                "instructions": len(self.summary.instruction_rvas),
                "entry_rva": self.summary.function_entry_rva,
                "function_sha256": self.summary.function_sha256,
                "function_symbol": self.summary.generated_function_name,
            },
            "fixed_native_chunks": [
                {"id": "prologue", "fuel": 7},
                {"id": "lower_iteration", "fuel": 25},
                {"id": "upper_iteration", "fuel": 23},
                {"id": "finish", "fuel_min": 1, "fuel_max": 22},
                {"id": "epilogue", "fuel": 3},
            ],
            "constructed_lean_evidence": [
                "ProgramLookupNativeTemplateCertificate",
                "programLookupNativeLocalSemantics",
                "ProgramLookupNativeConcreteABI",
                "KernelOperationRefinesUsing_composition",
            ],
            "remaining_semantic_premises": [],
            "remaining_static_premises": [
                "programLookupNativeTemplateChecked",
                "ConcreteKernelABI.program_equals_generated_program",
            ],
            "forbidden_submitted_evidence": [
                "whole_native_path",
                "caller_selected_final_state",
                "caller_selected_response",
                "python_status_as_proof",
            ],
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelLookupNativeGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelLookupNativeGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _kernel_candidate_size(path: Path) -> int:
    try:
        payload = _object(
            json.loads(path.read_text(encoding="utf-8")), "kernel plan"
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelLookupNativeGenerationError(
            f"unable to read kernel plan: {path}"
        ) from exc
    candidate = _object(payload.get("candidate"), "kernel candidate")
    return _nat(candidate.get("size"), "kernel candidate size")


def build_relational_interpreter_kernel_lookup_native_plan(
    *,
    kernel_plan: Path | str,
    data_inventory: Path | str,
    candidate_pe: Path | str,
) -> InterpreterKernelLookupNativePlan:
    kernel_path = Path(kernel_plan)
    candidate_path = Path(candidate_pe)
    try:
        summary = build_relational_interpreter_kernel_summary_plan(
            kernel_path, Path(data_inventory)
        )
    except RelationalInterpreterKernelSummaryGenerationError as exc:
        raise RelationalInterpreterKernelLookupNativeGenerationError(
            str(exc)
        ) from exc
    try:
        candidate_size = candidate_path.stat().st_size
        candidate_sha256 = sha256_file(candidate_path)
    except OSError as exc:
        raise RelationalInterpreterKernelLookupNativeGenerationError(
            f"unable to read candidate PE: {candidate_path}"
        ) from exc
    planned_size = _kernel_candidate_size(kernel_path)
    if (
        candidate_sha256 != summary.candidate_sha256
        or candidate_size != planned_size
    ):
        raise RelationalInterpreterKernelLookupNativeGenerationError(
            "candidate PE identity "
            f"(sha256={candidate_sha256}, size={candidate_size}) disagrees with "
            "the exact kernel/data inventories "
            f"(sha256={summary.candidate_sha256}, size={planned_size})"
        )
    return InterpreterKernelLookupNativePlan(
        summary=summary,
        candidate_path=candidate_path,
        candidate_size=candidate_size,
    )


def _validate_module(module: str, context: str) -> str:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelLookupNativeGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )
    return module


def _instruction_certificate_source(plan: InterpreterKernelLookupNativePlan) -> str:
    entry = plan.summary.function_entry_rva
    offsets = [rva - entry for rva in plan.summary.instruction_rvas]
    definitions: list[str] = []
    names: list[str] = []
    for index, offset in enumerate(offsets):
        name = f"generatedProgramLookupInstructionCertificate{index:02d}"
        names.append(name)
        definitions.append(
            f"""def {name} :
    ProgramLookupNativeInstructionCertificate
      generatedInterpreterKernelCandidatePe
      generatedProgramLookupNativeParameters := {{
  offset := {offset}
  checked := by decide
}}
"""
        )
    inventory = ",\n    ".join(names)
    parameters = f"""def generatedProgramLookupNativeParameters :
    ProgramLookupTemplateParameters := {{
  entryRva := {entry}
  tableRva := {plan.summary.table_rva}
  countRva := {plan.summary.count_rva}
}}

"""
    return parameters + "\n".join(definitions) + f"""
def generatedProgramLookupInstructionInventory :
    ProgramLookupNativeInstructionInventory
      generatedInterpreterKernelCandidatePe
      generatedProgramLookupNativeParameters := {{
  certificates := [
    {inventory}
  ]
  offsetsExact := by decide
}}
"""


def relational_interpreter_kernel_lookup_native_source(
    plan: InterpreterKernelLookupNativePlan,
    *,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    summary_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelSummary"
    ),
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> str:
    for context, module in (
        ("kernel module", kernel_module),
        ("summary module", summary_module),
        ("data module", data_module),
    ):
        _validate_module(module, context)
    function_name = plan.summary.generated_function_name
    instruction_certificates = _instruction_certificate_source(plan)
    return f"""import StageA.RelationalInterpreterKernelLookupABI
import StageA.RelationalInterpreterKernelLookupNative
import {kernel_module}
import {summary_module}
import {data_module}

namespace StageA.GeneratedRelational.InterpreterKernelLookupNative

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelLookupABI
open StageA.Relational.InterpreterKernelLookupNative
open StageA.Relational.InterpreterKernelSummary
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelData

set_option maxRecDepth 1000000

/-! The generated module contains no submitted execution or result.  Its exact
candidate types come from the Lean-reparsed PE and reflected kernel modules. -/

{instruction_certificates}

abbrev GeneratedProgramLookupConcreteKernelABI :=
  ConcreteKernelABI generatedInterpreterKernelCandidatePe
    generatedInterpreterKernelImports generatedInterpreterKernelRelocations
    generatedInterpreterKernelTableRva generatedInterpreterKernelCountRva
    semanticInterpreterProgramRecords

abbrev GeneratedProgramLookupSummary
    (abi : GeneratedProgramLookupConcreteKernelABI) :=
  KernelFunctionSummary abi.program
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    (ConcreteKernelABI.relation abi) generatedInterpreterKernelRelocations
    generatedInterpreterKernelTableRva generatedInterpreterKernelCountRva
    semanticInterpreterProgramRecords {function_name}

/-- Native effect annotations are derived from the exact reflected template;
there is no second candidate-controlled shape certificate. -/
def generatedProgramLookupNativeTemplateCertificate
    (abi : GeneratedProgramLookupConcreteKernelABI)
    (summary : GeneratedProgramLookupSummary abi)
    (nativeChecked : programLookupNativeTemplateChecked
      abi.program generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports {function_name}
      summary.templateCertificate.parameters = true) :
    ProgramLookupNativeTemplateCertificate abi.program
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      {function_name} :=
  programLookupTemplateCertificateToNative summary.templateCertificate
    nativeChecked

def GeneratedProgramLookupNativeTemplateCheckedGoal
    (abi : GeneratedProgramLookupConcreteKernelABI)
    (summary : GeneratedProgramLookupSummary abi) : Prop :=
  programLookupNativeTemplateChecked abi.program
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    {function_name} summary.templateCertificate.parameters = true

def GeneratedProgramLookupNativeStaticBindingGoal
    (abi : GeneratedProgramLookupConcreteKernelABI) : Prop :=
  abi.program = generatedCompiledKernelProgram

theorem generatedProgramLookupNativeParametersExact
    (abi : GeneratedProgramLookupConcreteKernelABI)
    (summary : GeneratedProgramLookupSummary abi)
    (nativeChecked : GeneratedProgramLookupNativeTemplateCheckedGoal abi
      summary) :
    generatedProgramLookupNativeParameters =
      (generatedProgramLookupNativeTemplateCertificate abi summary
        nativeChecked).template.parameters := by
  apply ProgramLookupTemplateParameters.ext
  next =>
    simpa [generatedProgramLookupNativeParameters,
      generatedProgramLookupNativeTemplateCertificate, {function_name}] using
      (StageA.Relational.InterpreterKernelLookupNative.ProgramLookupTemplateCertificate.entryRva_eq_functionStart
        summary.templateCertificate).symm
  next =>
    simpa [generatedProgramLookupNativeParameters,
      generatedProgramLookupNativeTemplateCertificate] using
      summary.tableParameterExact.symm
  next =>
    simpa [generatedProgramLookupNativeParameters,
      generatedProgramLookupNativeTemplateCertificate] using
      summary.countParameterExact.symm

noncomputable def generatedProgramLookupNativeLocalSemantics
    (environment : NativeEnvironment)
    (abi : GeneratedProgramLookupConcreteKernelABI)
    (summary : GeneratedProgramLookupSummary abi)
    (nativeChecked : GeneratedProgramLookupNativeTemplateCheckedGoal abi
      summary) :
    ProgramLookupNativeLocalSemantics generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports environment
      semanticInterpreterProgramRecords abi.tableCertificate.transferCount
      (generatedProgramLookupNativeTemplateCertificate abi summary
        nativeChecked) := by
  let certificate :=
    generatedProgramLookupNativeTemplateCertificate abi summary nativeChecked
  have inventory : ProgramLookupNativeInstructionInventory
      generatedInterpreterKernelCandidatePe certificate.template.parameters := by
    rw [(generatedProgramLookupNativeParametersExact abi summary
      nativeChecked).symm]
    exact generatedProgramLookupInstructionInventory
  exact programLookupNativeLocalSemantics certificate inventory environment
    semanticInterpreterProgramRecords summary.sourceRvasSorted
    abi.tableCertificate.transferCount

noncomputable def generatedProgramLookupNativeConcreteABI
    (abi : GeneratedProgramLookupConcreteKernelABI)
    (summary : GeneratedProgramLookupSummary abi)
    (nativeChecked : GeneratedProgramLookupNativeTemplateCheckedGoal abi
      summary)
    (recordSourcesFit : programLookupRecordSourcesFit
      semanticInterpreterProgramRecords = true) :
    ProgramLookupNativeConcreteABI generatedInterpreterKernelCandidatePe
      (ConcreteKernelABI.relation abi) semanticInterpreterProgramRecords
      abi.tableCertificate.transferCount
      (generatedProgramLookupNativeTemplateCertificate abi summary
        nativeChecked) := by
  exact programLookupNativeConcreteABI abi
    (generatedProgramLookupNativeTemplateCertificate abi summary nativeChecked)
    (by simpa [generatedProgramLookupNativeTemplateCertificate] using
      summary.tableParameterExact)
    (by simpa [generatedProgramLookupNativeTemplateCertificate] using
      summary.countParameterExact) recordSourcesFit

theorem generatedProgramLookupNativeRecordSourcesFit :
    programLookupRecordSourcesFit semanticInterpreterProgramRecords = true := by
  decide +kernel

/-- This is the public operation theorem.  It composes only fixed local chunk
laws and machine-level ABI facts; no complete path, final state, response, or
Python verdict is an argument. -/
theorem GeneratedProgramLookupNativeRefinesUsing
    (environment : NativeEnvironment)
    (abi : GeneratedProgramLookupConcreteKernelABI)
    (summary : GeneratedProgramLookupSummary abi)
    (programExact : GeneratedProgramLookupNativeStaticBindingGoal abi)
    (nativeChecked : GeneratedProgramLookupNativeTemplateCheckedGoal abi summary) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram
      (ConcreteKernelABI.relation abi)
      (NativeDispatches generatedInterpreterKernelCandidatePe
        generatedInterpreterKernelImports environment) .programLookup := by
  have semantics := generatedProgramLookupNativeLocalSemantics environment abi
    summary nativeChecked
  have refined := semantics.programLookupRefinesUsingNative
    (generatedProgramLookupNativeConcreteABI abi summary nativeChecked
      generatedProgramLookupNativeRecordSourcesFit) (by
      simpa [generatedProgramLookupNativeTemplateCertificate] using
        summary.entryRvaExact)
  rw [programExact] at refined
  exact refined

#print axioms generatedProgramLookupNativeTemplateCertificate
#print axioms generatedProgramLookupNativeLocalSemantics
#print axioms GeneratedProgramLookupNativeRefinesUsing

end StageA.GeneratedRelational.InterpreterKernelLookupNative
"""


def write_relational_interpreter_kernel_lookup_native_bundle(
    *,
    kernel_plan: Path | str,
    data_inventory: Path | str,
    candidate_pe: Path | str,
    out: Path | str,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    summary_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelSummary"
    ),
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> InterpreterKernelLookupNativePlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_lookup_native_plan(
        kernel_plan=kernel_plan,
        data_inventory=data_inventory,
        candidate_pe=candidate_pe,
    )
    write_json(
        output / INTERPRETER_KERNEL_LOOKUP_NATIVE_PLAN_FILENAME, plan.payload()
    )
    (output / INTERPRETER_KERNEL_LOOKUP_NATIVE_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_lookup_native_source(
            plan,
            kernel_module=kernel_module,
            summary_module=summary_module,
            data_module=data_module,
        ),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT",
    "INTERPRETER_KERNEL_LOOKUP_NATIVE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_LOOKUP_NATIVE_PLAN_FILENAME",
    "InterpreterKernelLookupNativePlan",
    "RelationalInterpreterKernelLookupNativeGenerationError",
    "build_relational_interpreter_kernel_lookup_native_plan",
    "relational_interpreter_kernel_lookup_native_source",
    "write_relational_interpreter_kernel_lookup_native_bundle",
]
