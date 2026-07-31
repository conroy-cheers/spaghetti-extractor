"""Bind exact ProgramLookup semantics to a caller-parametric NativeWorld.

The planner cross-checks the closed ProgramLookup operation with the exact
``interpreterStep`` rel32 call site.  The generated theorem replays the already
checked local semantics in ``NativeWorldKernelDispatches``.  It never selects a
world and deliberately has no dependency on mixed-acceptance launch bindings.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_lookup_native import (
    INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT,
)
from .interpreter_kernel_program_lookup_operation import (
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT,
)
from .interpreter_kernel_step_program_lookup_call import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT,
)


INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_FORMAT = (
    "stage-a-relational-interpreter-kernel-program-lookup-native-world-bridge-v1"
)
INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_PLAN_FILENAME = (
    "interpreter-kernel-program-lookup-native-world-bridge.json"
)
INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelProgramLookupNativeWorldBridge.lean"
)
INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelProgramLookupNativeWorldBridge."
    "generatedProgramLookupNativeWorldRefines"
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
    StageAInputError
):
    """The ProgramLookup and Step-call artifacts do not describe one PE."""


@dataclass(frozen=True)
class InterpreterKernelProgramLookupNativeWorldBridgePlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    lookup_native_plan_path: Path
    lookup_native_plan_sha256: str
    lookup_operation_plan_path: Path
    lookup_operation_plan_sha256: str
    step_call_plan_path: Path
    step_call_plan_sha256: str
    entry_rva: int
    call_site_rva: int
    continuation_rva: int

    def payload(self) -> dict[str, Any]:
        return {
            "format": (
                INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_FORMAT
            ),
            "acceptance_authority": False,
            "operation": "programLookup",
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "lookup_native_plan": {
                    "path": self.lookup_native_plan_path.name,
                    "sha256": self.lookup_native_plan_sha256,
                },
                "lookup_operation_plan": {
                    "path": self.lookup_operation_plan_path.name,
                    "sha256": self.lookup_operation_plan_sha256,
                },
                "step_call_plan": {
                    "path": self.step_call_plan_path.name,
                    "sha256": self.step_call_plan_sha256,
                },
            },
            "checked_static_authority": {
                "entry_rva": self.entry_rva,
                "step_call_site_rva": self.call_site_rva,
                "step_call_target_rva": self.entry_rva,
                "step_continuation_rva": self.continuation_rva,
            },
            "world_contract": {
                "mode": "caller-parametric",
                "successor": "same-relational-world",
                "mixed_acceptance_launch_world_assumed": False,
            },
            "closed_components": [
                "exact_event_free_native_fuel_replay",
                "native_world_kernel_dispatch",
                "program_lookup_response_facts",
                "program_lookup_memory_frame",
                "exact_step_rel32_target_and_continuation",
            ],
            "remaining_proof_premises": [],
            "integration_frontiers": [
                {
                    "id": "interpreter-step:program-lookup-caller-prefix",
                    "rva": self.call_site_rva,
                    "reason": (
                        "GeneratedInterpreterStepProgramLookupWorldCall still "
                        "requires the exact Step prefix, __chkstk_ms return, "
                        "and nested cdecl request facts"
                    ),
                },
                {
                    "id": "mixed-acceptance:program-lookup-world-binding",
                    "reason": (
                        "mixed acceptance may specialize this theorem to "
                        "generatedLaunchWorld only after the exact Step caller "
                        "path is proved to use that same world"
                    ),
                },
            ],
            "result": {
                "theorem": (
                    INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_THEOREM
                )
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            f"{context} must be an object"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            f"cannot read {context}: {path}"
        ) from exc


def _candidate(
    payload: Mapping[str, Any], context: str
) -> tuple[str, int]:
    candidate = _object(payload.get("candidate"), f"{context} candidate")
    digest = candidate.get("sha256")
    size = candidate.get("size")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            f"{context} candidate SHA-256 is invalid"
        )
    return digest, _nat(size, f"{context} candidate size")


def build_relational_interpreter_kernel_program_lookup_native_world_bridge_plan(
    *,
    candidate_pe: Path | str,
    lookup_native_plan: Path | str,
    lookup_operation_plan: Path | str,
    step_call_plan: Path | str,
) -> InterpreterKernelProgramLookupNativeWorldBridgePlan:
    candidate_path = Path(candidate_pe)
    native_path = Path(lookup_native_plan)
    operation_path = Path(lookup_operation_plan)
    call_path = Path(step_call_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            "candidate PE does not exist"
        )
    identity = (sha256_file(candidate_path), candidate_path.stat().st_size)
    native = _load(native_path, "lookup-native plan")
    operation = _load(operation_path, "ProgramLookup operation plan")
    call = _load(call_path, "Step ProgramLookup call plan")
    if native.get("format") != INTERPRETER_KERNEL_LOOKUP_NATIVE_FORMAT:
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            "lookup-native plan format is unsupported"
        )
    if (
        operation.get("format")
        != INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_FORMAT
    ):
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            "ProgramLookup operation plan format is unsupported"
        )
    if call.get("format") != INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT:
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            "Step ProgramLookup call plan format is unsupported"
        )
    if any(
        _candidate(payload, context) != identity
        for payload, context in (
            (native, "lookup-native"),
            (operation, "ProgramLookup operation"),
            (call, "Step ProgramLookup call"),
        )
    ):
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            "candidate identity mismatch across ProgramLookup artifacts"
        )
    operation_inputs = _object(
        operation.get("inputs"), "ProgramLookup operation inputs"
    )
    native_input = _object(
        operation_inputs.get("lookup_native_plan"),
        "ProgramLookup lookup-native input",
    )
    if native_input.get("sha256") != sha256_file(native_path):
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            "ProgramLookup operation was not built from this lookup-native plan"
        )
    compatibility = _object(
        operation.get("checked_artifact_compatibility"),
        "ProgramLookup operation compatibility",
    )
    static = _object(call.get("checked_static_authority"), "Step call authority")
    entry = _nat(compatibility.get("entry_rva"), "ProgramLookup entry RVA")
    target = _nat(static.get("target_rva"), "Step call target RVA")
    call_site = _nat(static.get("call_site_rva"), "Step call-site RVA")
    continuation = _nat(
        static.get("continuation_rva"), "Step call continuation RVA"
    )
    if (
        operation.get("operation") != "programLookup"
        or call.get("operation") != "interpreterStep.programLookupCall"
        or target != entry
        or continuation != call_site + 5
    ):
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            "Step rel32 call does not target the exact ProgramLookup entry"
        )
    return InterpreterKernelProgramLookupNativeWorldBridgePlan(
        candidate_path=candidate_path,
        candidate_sha256=identity[0],
        candidate_size=identity[1],
        lookup_native_plan_path=native_path,
        lookup_native_plan_sha256=sha256_file(native_path),
        lookup_operation_plan_path=operation_path,
        lookup_operation_plan_sha256=sha256_file(operation_path),
        step_call_plan_path=call_path,
        step_call_plan_sha256=sha256_file(call_path),
        entry_rva=entry,
        call_site_rva=call_site,
        continuation_rva=continuation,
    )


def _module(value: str, context: str) -> str:
    if _LEAN_MODULE.fullmatch(value) is None:
        raise RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )
    return value


def relational_interpreter_kernel_program_lookup_native_world_bridge_source(
    plan: InterpreterKernelProgramLookupNativeWorldBridgePlan,
    *,
    lookup_operation_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelProgramLookupOperation"
    ),
    step_call_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelStepProgramLookupCall"
    ),
) -> str:
    lookup_operation_module = _module(
        lookup_operation_module, "ProgramLookup operation module"
    )
    step_call_module = _module(step_call_module, "Step call module")
    return f"""import StageA.RelationalInterpreterKernelProgramLookupNativeWorldBridge
import {lookup_operation_module}
import {step_call_module}

namespace StageA.GeneratedRelational.InterpreterKernelProgramLookupNativeWorldBridge

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelLookupNative
open StageA.Relational.InterpreterKernelProgramLookupNativeWorldBridge
open StageA.Relational.InterpreterKernelStepProgramLookupCall
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelLookupNative
open StageA.GeneratedRelational.InterpreterKernelProgramLookupOperation
open StageA.GeneratedRelational.InterpreterKernelStepNative
open StageA.GeneratedRelational.InterpreterKernelStepOperation
open StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCall

def generatedProgramLookupNativeWorldBridgeCandidateSha256 : String :=
  "{plan.candidate_sha256}"

theorem generatedProgramLookupStepCallExact :
    generatedInterpreterStepProgramLookupCallSiteParameters.callSiteRva =
        {plan.call_site_rva} /\\
      generatedInterpreterStepProgramLookupCallSiteParameters.targetRva =
        {plan.entry_rva} /\\
      generatedInterpreterStepProgramLookupCallSiteParameters.continuationRva =
        {plan.continuation_rva} := by
  decide

/-- The world is universally quantified and is the same world used by the
exact candidate path.  In particular this theorem does not mention or infer a
mixed-acceptance launch world. -/
noncomputable theorem generatedProgramLookupNativeWorldRefines
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram
      generatedInterpreterKernelABIRelation
      (NativeWorldKernelDispatches
        (generatedInterpreterStepNativeProgram environment) world)
      .programLookup := by
  simpa [generatedInterpreterKernelABIRelation,
    generatedInterpreterStepNativeProgram] using
    programLookupNativeLocalSemantics_programLookupRefinesUsingNativeWorld
      (candidate := generatedInterpreterStepNativeProgram environment)
      (generatedProgramLookupNativeLocalSemantics
        programLookupIdentityNativeEnvironment
        generatedConcreteInterpreterKernelABI generatedProgramLookupSummary
        generatedProgramLookupNativeTemplateChecked)
      (generatedProgramLookupNativeConcreteABI
        generatedConcreteInterpreterKernelABI generatedProgramLookupSummary
        generatedProgramLookupNativeTemplateChecked
        generatedProgramLookupNativeRecordSourcesFit)
      (by
        simpa [generatedProgramLookupNativeTemplateCertificate] using
          generatedProgramLookupSummary.entryRvaExact)
      world

structure GeneratedProgramLookupNativeWorldAtStepCall
    (environment : NativeWorldEnvironment) (world : RelationalWorld) where
  site : InterpreterStepProgramLookupCallSiteCertificate
    generatedCompiledKernelProgram
    (generatedInterpreterStepNativeProgram environment)
    (generatedInterpreterStepOperationStatic environment)
  refines : KernelOperationRefinesUsing generatedCompiledKernelProgram
    generatedInterpreterKernelABIRelation
    (NativeWorldKernelDispatches
      (generatedInterpreterStepNativeProgram environment) world)
    .programLookup

/-- Exact binding at the checked call `{plan.call_site_rva} -> {plan.entry_rva}`,
retaining the
caller's world as an index.  Constructing the surrounding Step caller prefix
remains a separate exact-execution obligation. -/
noncomputable def generatedProgramLookupNativeWorldAtStepCall
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :
    GeneratedProgramLookupNativeWorldAtStepCall environment world := {{
  site := generatedInterpreterStepProgramLookupCallSite environment
  refines := generatedProgramLookupNativeWorldRefines environment world
}}

#print axioms generatedProgramLookupStepCallExact
#print axioms generatedProgramLookupNativeWorldRefines
#print axioms generatedProgramLookupNativeWorldAtStepCall

end StageA.GeneratedRelational.InterpreterKernelProgramLookupNativeWorldBridge
"""


def write_relational_interpreter_kernel_program_lookup_native_world_bridge_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterKernelProgramLookupNativeWorldBridgePlan:
    output = Path(out)
    lean_output = output / "StageA"
    lean_output.mkdir(parents=True, exist_ok=True)
    plan = (
        build_relational_interpreter_kernel_program_lookup_native_world_bridge_plan(
            **kwargs
        )
    )
    write_json(
        output
        / INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_PLAN_FILENAME,
        plan.payload(),
    )
    (
        lean_output
        / INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_program_lookup_native_world_bridge_source(
            plan
        ),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_FORMAT",
    "INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_PLAN_FILENAME",
    "INTERPRETER_KERNEL_PROGRAM_LOOKUP_NATIVE_WORLD_BRIDGE_THEOREM",
    "InterpreterKernelProgramLookupNativeWorldBridgePlan",
    "RelationalInterpreterKernelProgramLookupNativeWorldBridgeGenerationError",
    "build_relational_interpreter_kernel_program_lookup_native_world_bridge_plan",
    "relational_interpreter_kernel_program_lookup_native_world_bridge_source",
    "write_relational_interpreter_kernel_program_lookup_native_world_bridge_bundle",
]
