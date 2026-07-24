"""Emit a closed native ``programLookup`` operation certificate.

The planner only cross-checks artifact identity and compatibility.  The emitted
Lean module constructs the exact summary from the PE-backed ABI certificate and
then applies ``GeneratedProgramLookupNativeRefinesUsing`` without accepting a
path, final state, solver status, or proof premise from Python.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_abi import INTERPRETER_KERNEL_ABI_FORMAT
from .interpreter_kernel import INTERPRETER_KERNEL_PLAN_FORMAT
from .interpreter_kernel_data import INTERPRETER_KERNEL_DATA_FORMAT
from .interpreter_kernel_lookup_native import (
    INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT,
)


INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT = (
    "stage-a-relational-interpreter-kernel-program-lookup-operation-plan-v1"
)
INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_PLAN_FILENAME = (
    "interpreter-kernel-program-lookup-operation-plan.json"
)
INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelProgramLookupOperation.lean"
)
INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelProgramLookupOperation."
    "generatedProgramLookupOperationRefinesUsing"
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_DATA_INVENTORY_FORMATS = {
    f"stage-a-interpreter-kernel-data-inventory-v{version}"
    for version in range(1, 8)
} | {INTERPRETER_KERNEL_DATA_FORMAT}


class RelationalInterpreterKernelProgramLookupOperationGenerationError(
    StageAInputError
):
    """The concrete ABI and lookup artifacts cannot close the operation."""


@dataclass(frozen=True)
class InterpreterKernelProgramLookupOperationPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    kernel_plan_path: Path
    kernel_plan_sha256: str
    data_inventory_path: Path
    data_inventory_sha256: str
    lookup_native_plan_path: Path
    lookup_native_plan_sha256: str
    abi_plan_path: Path
    abi_plan_sha256: str
    function_index: int
    function_symbol: str
    function_entry_rva: int
    function_end_rva: int
    table_rva: int
    count_rva: int
    transfer_count: int

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT,
            "acceptance_authority": False,
            "operation": "programLookup",
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "kernel_plan": {
                    "path": self.kernel_plan_path.name,
                    "sha256": self.kernel_plan_sha256,
                },
                "data_inventory": {
                    "path": self.data_inventory_path.name,
                    "sha256": self.data_inventory_sha256,
                },
                "lookup_native_plan": {
                    "path": self.lookup_native_plan_path.name,
                    "sha256": self.lookup_native_plan_sha256,
                },
                "abi_plan": {
                    "path": self.abi_plan_path.name,
                    "sha256": self.abi_plan_sha256,
                },
            },
            "checked_artifact_compatibility": {
                "function_symbol": self.function_symbol,
                "entry_rva": self.function_entry_rva,
                "table_rva": self.table_rva,
                "count_rva": self.count_rva,
                "record_count": self.transfer_count,
            },
            "lean_evidence": [
                "generatedConcreteInterpreterKernelABI",
                "generatedInterpreterKernelCandidateParsed",
                "exactDecodeInventoryChecked_sound",
                "sourceRvasAdjacentSortedChecked_sound",
                "KernelFunctionSummaryCore.withConcreteABI",
                "GeneratedProgramLookupNativeRefinesUsing",
            ],
            "remaining_proof_premises": [],
            "result": {
                "status": "ready-for-lean-check",
                "theorem": INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM,
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _read_abi_plan(path: Path) -> Mapping[str, Any]:
    try:
        payload = _object(json.loads(path.read_text(encoding="utf-8")), "ABI plan")
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            f"unable to read ABI plan: {path}"
        ) from exc
    if payload.get("format") != INTERPRETER_KERNEL_ABI_FORMAT:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "ABI plan format is unsupported"
        )
    return payload


def _read_json_object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            f"unable to read {context}: {path}"
        ) from exc


def _sha256(value: object, context: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _matching_input_sha256(
    payload: Mapping[str, Any], key: str, expected: str
) -> None:
    inputs = _object(payload.get("inputs"), "ABI plan inputs")
    row = _object(inputs.get(key), f"ABI plan {key} input")
    if row.get("sha256") != expected:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            f"ABI plan {key} identity disagrees with the lookup artifacts"
        )


def build_relational_interpreter_kernel_program_lookup_operation_plan(
    *,
    kernel_plan: Path | str,
    data_inventory: Path | str,
    candidate_pe: Path | str,
    lookup_native_plan: Path | str,
    abi_plan: Path | str,
) -> InterpreterKernelProgramLookupOperationPlan:
    kernel_path = Path(kernel_plan)
    data_path = Path(data_inventory)
    candidate_path = Path(candidate_pe)
    lookup_path = Path(lookup_native_plan)
    kernel = _read_json_object(kernel_path, "kernel plan")
    data = _read_json_object(data_path, "data inventory")
    lookup = _read_json_object(lookup_path, "lookup-native plan")
    if kernel.get("format") != INTERPRETER_KERNEL_PLAN_FORMAT:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "kernel plan format is unsupported"
        )
    if data.get("format") not in _DATA_INVENTORY_FORMATS:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "data inventory format is unsupported"
        )
    if lookup.get("format") != INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "lookup-native plan format is unsupported"
        )
    try:
        candidate_size = candidate_path.stat().st_size
        candidate_sha256 = sha256_file(candidate_path)
    except OSError as exc:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            f"unable to read candidate PE: {candidate_path}"
        ) from exc
    kernel_candidate = _object(kernel.get("candidate"), "kernel candidate")
    data_sha256 = _sha256(data.get("candidate_sha256"), "data candidate SHA-256")
    if (
        _sha256(kernel_candidate.get("pe_sha256"), "kernel candidate SHA-256")
        != candidate_sha256
        or _nat(kernel_candidate.get("size"), "kernel candidate size")
        != candidate_size
        or data_sha256 != candidate_sha256
        or _nat(data.get("candidate_bytes"), "data candidate size")
        != candidate_size
    ):
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "candidate PE identity disagrees with kernel or data artifacts"
        )
    kernel_hash = sha256_file(kernel_path)
    data_hash = sha256_file(data_path)
    lookup_candidate = _object(lookup.get("candidate"), "lookup candidate")
    lookup_inputs = _object(lookup.get("inputs"), "lookup inputs")
    if (
        lookup_candidate.get("sha256") != candidate_sha256
        or lookup_candidate.get("size") != candidate_size
        or _object(lookup_inputs.get("kernel_plan"), "lookup kernel input").get(
            "sha256"
        )
        != kernel_hash
        or _object(
            lookup_inputs.get("data_inventory"), "lookup data input"
        ).get("sha256")
        != data_hash
    ):
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "lookup-native plan identity disagrees with candidate artifacts"
        )

    functions = _array(kernel.get("kernel_functions"), "kernel functions")
    matches = [
        (index, _object(row, "kernel function"))
        for index, row in enumerate(functions)
        if isinstance(row, Mapping) and row.get("role") == "programLookup"
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "kernel plan must contain exactly one programLookup function"
        )
    function_index, function = matches[0]
    function_entry = _nat(function.get("rva_start"), "programLookup start RVA")
    function_end = _nat(function.get("rva_end"), "programLookup end RVA")
    function_symbol = f"generatedKernelFunction{function_index:04d}"
    template = _object(lookup.get("template"), "lookup template")
    if (
        template.get("function_symbol") != function_symbol
        or template.get("entry_rva") != function_entry
        or template.get("function_sha256") != function.get("sha256")
        or template.get("bytes") != function_end - function_entry
        or template.get("blocks") != len(_array(function.get("blocks"), "blocks"))
    ):
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "lookup-native template disagrees with the exact kernel function"
        )
    table_rva = _nat(data.get("table_rva"), "program table RVA")
    count_rva = _nat(data.get("count_rva"), "program count RVA")
    counts = _object(data.get("counts"), "data inventory counts")
    transfer_count = _nat(
        counts.get("transfers", counts.get("records")), "program record count"
    )

    abi_path = Path(abi_plan)
    payload = _read_abi_plan(abi_path)
    if payload.get("candidate_pe_sha256") != candidate_sha256:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "ABI plan candidate identity disagrees with the lookup artifacts"
        )
    _matching_input_sha256(
        payload, "kernel_plan", kernel_hash
    )
    _matching_input_sha256(
        payload, "data_inventory", data_hash
    )

    offsets = _object(payload.get("candidate_offsets"), "ABI candidate offsets")
    expected_offsets = {
        "program_table": table_rva,
        "program_count": count_rva,
    }
    for name, expected in expected_offsets.items():
        observed = _nat(offsets.get(name), f"ABI {name} offset")
        if observed != expected:
            raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
                f"ABI {name} offset {observed} disagrees with lookup value {expected}"
            )
    records = _nat(payload.get("program_records"), "ABI program record count")
    if records != transfer_count:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "ABI program record count disagrees with the lookup table"
        )
    operations = _array(payload.get("operations"), "ABI operations")
    matching = [
        _object(row, "ABI operation")
        for row in operations
        if isinstance(row, Mapping) and row.get("role") == "programLookup"
    ]
    if len(matching) != 1:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "ABI plan must contain exactly one programLookup operation"
        )
    if matching[0].get("function_index") != function_index:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "ABI programLookup function index disagrees with the lookup summary"
        )
    if payload.get("failure_mode") != "none":
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            "ABI plan did not close its static checker inputs"
        )
    return InterpreterKernelProgramLookupOperationPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        kernel_plan_path=kernel_path,
        kernel_plan_sha256=kernel_hash,
        data_inventory_path=data_path,
        data_inventory_sha256=data_hash,
        lookup_native_plan_path=lookup_path,
        lookup_native_plan_sha256=sha256_file(lookup_path),
        abi_plan_path=abi_path,
        abi_plan_sha256=sha256_file(abi_path),
        function_index=function_index,
        function_symbol=function_symbol,
        function_entry_rva=function_entry,
        function_end_rva=function_end,
        table_rva=table_rva,
        count_rva=count_rva,
        transfer_count=transfer_count,
    )


def _validate_module(module: str, context: str) -> str:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelProgramLookupOperationGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )
    return module


def relational_interpreter_kernel_program_lookup_operation_source(
    plan: InterpreterKernelProgramLookupOperationPlan,
    *,
    abi_module: str = "StageA.GeneratedRelationalInterpreterKernelABI",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
    summary_module: str = "StageA.GeneratedRelationalInterpreterKernelSummary",
    lookup_native_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelLookupNative"
    ),
) -> str:
    modules = (
        ("ABI module", abi_module),
        ("kernel module", kernel_module),
        ("data module", data_module),
        ("summary module", summary_module),
        ("lookup native module", lookup_native_module),
    )
    for context, module in modules:
        _validate_module(module, context)
    function = plan.function_symbol
    return f"""import StageA.RelationalInterpreterKernelProgramLookupOperation
import {abi_module}
import {kernel_module}
import {data_module}
import {summary_module}
import {lookup_native_module}

namespace StageA.GeneratedRelational.InterpreterKernelProgramLookupOperation

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelLookupABI
open StageA.Relational.InterpreterKernelLookupNative
open StageA.Relational.InterpreterKernelProgramLookupOperation
open StageA.Relational.InterpreterKernelSummary
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterKernelSummary
open StageA.GeneratedRelational.InterpreterKernelLookupNative

set_option maxRecDepth 1000000

theorem generatedProgramLookupABIProgramExact :
    generatedConcreteInterpreterKernelABI.program =
      generatedCompiledKernelProgram := by
  rfl

theorem generatedProgramLookupTemplateReflectionPresent :
    (reflectProgramLookupTemplate? generatedInterpreterKernelCandidatePe
      {function}).isSome = true := by
  decide +kernel

def generatedProgramLookupTemplateReflection : ReflectedProgramLookupTemplate :=
  (reflectProgramLookupTemplate? generatedInterpreterKernelCandidatePe
    {function}).get generatedProgramLookupTemplateReflectionPresent

theorem generatedProgramLookupTemplateReflected :
    reflectProgramLookupTemplate? generatedInterpreterKernelCandidatePe
      {function} = some generatedProgramLookupTemplateReflection :=
  option_eq_some_get _ generatedProgramLookupTemplateReflectionPresent

theorem generatedProgramLookupTemplateChecked :
    GeneratedProgramLookupTemplateCheckedGoal := by
  decide +kernel

def generatedProgramLookupTemplateCertificateForABI :
    ProgramLookupTemplateCertificate
      generatedConcreteInterpreterKernelABI.program
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      {function} := by
  rw [generatedProgramLookupABIProgramExact]
  exact generatedProgramLookupTemplateCertificate
    generatedProgramLookupTemplateReflection
    generatedProgramLookupTemplateReflected
    generatedProgramLookupTemplateChecked

theorem generatedProgramLookupInstructionDecodes :
    ExactDecodeInventory generatedInterpreterKernelCandidatePe
      {function}.instructions := by
  apply exactDecodeInventoryChecked_sound
  decide +kernel

theorem generatedProgramLookupSourceRvasSorted :
    sourceRvasStrictlySorted semanticInterpreterProgramRecords := by
  apply sourceRvasAdjacentSortedChecked_sound
  decide +kernel

noncomputable def generatedProgramLookupSummaryCore :
    KernelFunctionSummaryCore generatedConcreteInterpreterKernelABI
      {function} := {{
  candidateParsed := generatedInterpreterKernelCandidateParsed
  templateCertificate := generatedProgramLookupTemplateCertificateForABI
  tableParameterExact := by rfl
  countParameterExact := by rfl
  instructionDecodes := generatedProgramLookupInstructionDecodes
  sourceRvasSorted := generatedProgramLookupSourceRvasSorted
  entryRvaExact := by
    rw [generatedProgramLookupABIProgramExact]
    decide +kernel
}}

noncomputable def generatedProgramLookupSummary :
    GeneratedProgramLookupSummary generatedConcreteInterpreterKernelABI :=
  generatedProgramLookupSummaryCore.withConcreteABI

theorem generatedProgramLookupNativeTemplateChecked :
    GeneratedProgramLookupNativeTemplateCheckedGoal
      generatedConcreteInterpreterKernelABI generatedProgramLookupSummary := by
  rw [generatedProgramLookupABIProgramExact]
  decide +kernel

/-- Closed operation proof for the exact generated candidate.  The environment
is universally quantified data, not a proof premise or selected execution. -/
theorem generatedProgramLookupOperationRefinesUsing
    (environment : NativeEnvironment) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (NativeDispatches generatedInterpreterKernelCandidatePe
        generatedInterpreterKernelImports environment) .programLookup := by
  simpa [generatedInterpreterKernelABIRelation] using
    GeneratedProgramLookupNativeRefinesUsing environment
      generatedConcreteInterpreterKernelABI generatedProgramLookupSummary
      generatedProgramLookupABIProgramExact
      generatedProgramLookupNativeTemplateChecked

#print axioms generatedProgramLookupOperationRefinesUsing

end StageA.GeneratedRelational.InterpreterKernelProgramLookupOperation
"""


def write_relational_interpreter_kernel_program_lookup_operation_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelProgramLookupOperationPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_program_lookup_operation_plan(
        **kwargs
    )
    write_json(
        output / INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output / INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_program_lookup_operation_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT",
    "INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_LEAN_FILENAME",
    "INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_PLAN_FILENAME",
    "INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM",
    "InterpreterKernelProgramLookupOperationPlan",
    "RelationalInterpreterKernelProgramLookupOperationGenerationError",
    "build_relational_interpreter_kernel_program_lookup_operation_plan",
    "relational_interpreter_kernel_program_lookup_operation_source",
    "write_relational_interpreter_kernel_program_lookup_operation_bundle",
]
