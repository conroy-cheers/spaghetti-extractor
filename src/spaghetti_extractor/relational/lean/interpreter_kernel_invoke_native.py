"""Bind the reflected ``invokeCall`` wrapper to exact native-world execution.

This artifact is deliberately non-authoritative.  It cross-checks the supplied
candidate, invoke template, and callback inventory, then emits Lean goals whose
paths can only be built by the reviewed native bridge.  Disagreeing artifacts
remain useful diagnostics, but never become proof inputs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...stage_binary import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_callback import INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT
from .interpreter_kernel_invoke import (
    InterpreterKernelInvokePlan,
    build_relational_interpreter_kernel_invoke_plan,
)


INTERPRETER_KERNEL_INVOKE_NATIVE_FORMAT = (
    "stage-a-relational-interpreter-kernel-invoke-native-plan-v1"
)
INTERPRETER_KERNEL_INVOKE_NATIVE_PLAN_FILENAME = (
    "interpreter-kernel-invoke-native-plan.json"
)
INTERPRETER_KERNEL_INVOKE_NATIVE_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelInvokeNative.lean"
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class RelationalInterpreterKernelInvokeNativeGenerationError(StageAInputError):
    """The supplied invoke/native artifacts disagree or are unsupported."""


@dataclass(frozen=True)
class InvokeNativeIssue:
    code: str
    message: str
    expected: object | None = None
    observed: object | None = None
    site_rva: int | None = None

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.expected is not None:
            result["expected"] = self.expected
        if self.observed is not None:
            result["observed"] = self.observed
        if self.site_rva is not None:
            result["site_rva"] = self.site_rva
        return result


@dataclass(frozen=True)
class InterpreterKernelInvokeNativePlan:
    invoke: InterpreterKernelInvokePlan
    callback_plan_path: Path
    callback_plan_sha256: str
    callback_candidate_sha256: str
    callback_candidate_size: int
    callback_site_index: int | None
    callback_site_rva: int
    callback_continuation_rva: int
    callback_target_rvas: tuple[int, ...]
    issues: tuple[InvokeNativeIssue, ...]

    @property
    def candidate_sha256(self) -> str:
        return self.invoke.candidate_sha256

    @property
    def candidate_size(self) -> int:
        return self.invoke.candidate_size

    def payload(self) -> dict[str, Any]:
        internal_continuation = self.invoke.function_entry_rva + 67
        indirect_run_continuation = self.invoke.function_entry_rva + 162
        external_wrapper_continuation = self.invoke.function_entry_rva + 196
        return {
            "format": INTERPRETER_KERNEL_INVOKE_NATIVE_FORMAT,
            "acceptance_authority": False,
            "status": "incomplete" if self.issues else "semantic_proof_required",
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "invoke_plan_sha256": self.invoke.kernel_plan_sha256,
                "callback_plan": self.callback_plan_path.name,
                "callback_plan_sha256": self.callback_plan_sha256,
            },
            "invoke": {
                "entry_rva": self.invoke.function_entry_rva,
                "run_function_rva": self.invoke.run_function_rva,
                "external_dispatch_rva": self.invoke.external_dispatch_rva,
            },
            "arms": {
                "internal": {
                    "call_rva": self.invoke.function_entry_rva + 62,
                    "continuation_rva": internal_continuation,
                    "derivation": [
                        "exact_wrapper_prelude",
                        "run_function_operation_refinement",
                        "exact_wrapper_epilogue",
                    ],
                },
                "indirect": {
                    "resolver_site_rva": self.callback_site_rva,
                    "resolver_continuation_rva": self.callback_continuation_rva,
                    "resolver_target_rvas": list(self.callback_target_rvas),
                    "run_function_call_rva": self.invoke.function_entry_rva + 157,
                    "run_function_continuation_rva": indirect_run_continuation,
                    "derivation": [
                        "checked_callback_target_inventory",
                        "exact_resolver_instruction",
                        "exact_callback_target_path",
                        "run_function_operation_refinement",
                        "exact_wrapper_epilogue",
                    ],
                },
                "external": {
                    "helper_call_rva": self.invoke.function_entry_rva + 191,
                    "wrapper_continuation_rva": external_wrapper_continuation,
                    "helper_rva": self.invoke.external_dispatch_rva,
                    "derivation": [
                        "exact_helper_prelude",
                        "external_environment_action",
                        "exact_helper_and_wrapper_epilogue",
                    ],
                },
            },
            "residual_obligations": [
                "exact_finite_segment_fuels_and_endpoints",
                "run_function_operation_refinement",
                "resolver_callback_target_execution",
                "external_environment_action",
            ],
            "forbidden_submitted_evidence": [
                "whole_arm_path",
                "final_abi_response",
                "final_memory_frame",
            ],
            "issues": [issue.payload() for issue in self.issues],
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelInvokeNativeGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelInvokeNativeGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelInvokeNativeGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RelationalInterpreterKernelInvokeNativeGenerationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelInvokeNativeGenerationError(
            f"unable to read {context}: {path}"
        ) from exc


def _candidate_pe_identity(path: Path) -> tuple[str, int]:
    try:
        size = path.stat().st_size
        digest = sha256_file(path)
    except OSError as exc:
        raise RelationalInterpreterKernelInvokeNativeGenerationError(
            f"unable to read candidate PE: {path}"
        ) from exc
    return digest, size


def _kernel_plan_candidate_identity(path: Path) -> tuple[str, int]:
    payload = _read_json(path, "kernel invoke plan")
    candidate = _object(payload.get("candidate"), "kernel plan candidate")
    return (
        _digest(candidate.get("pe_sha256"), "kernel plan candidate digest"),
        _nat(candidate.get("size"), "kernel plan candidate size"),
    )


def build_relational_interpreter_kernel_invoke_native_plan(
    *,
    kernel_plan: Path | str,
    callback_plan: Path | str,
    candidate_pe: Path | str,
) -> InterpreterKernelInvokeNativePlan:
    kernel_path = Path(kernel_plan)
    candidate_path = Path(candidate_pe)
    candidate_identity = _candidate_pe_identity(candidate_path)
    kernel_identity = _kernel_plan_candidate_identity(kernel_path)
    if candidate_identity != kernel_identity:
        raise RelationalInterpreterKernelInvokeNativeGenerationError(
            "candidate PE identity "
            f"(sha256={candidate_identity[0]}, size={candidate_identity[1]}) "
            "disagrees with kernel invoke plan identity "
            f"(sha256={kernel_identity[0]}, size={kernel_identity[1]})"
        )
    invoke = build_relational_interpreter_kernel_invoke_plan(
        kernel_path, candidate_pe=candidate_path
    )

    callback_path = Path(callback_plan)
    callback = _read_json(callback_path, "callback plan")
    if callback.get("format") != INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT:
        raise RelationalInterpreterKernelInvokeNativeGenerationError(
            "callback plan has an unsupported format"
        )
    callback_candidate = _object(callback.get("candidate"), "callback candidate")
    callback_sha256 = _digest(
        callback_candidate.get("sha256"), "callback candidate digest"
    )
    callback_size = _nat(callback_candidate.get("size"), "callback candidate size")
    expected_site = invoke.function_entry_rva + invoke.resolver_call_offset
    expected_continuation = expected_site + 2
    issues: list[InvokeNativeIssue] = []
    stale = (
        callback_sha256 != invoke.candidate_sha256
        or callback_size != invoke.candidate_size
    )
    if stale:
        issues.append(
            InvokeNativeIssue(
                code="callback_candidate_mismatch",
                message=(
                    "callback plan candidate identity disagrees with the exact "
                    "candidate PE and kernel invoke plan"
                ),
                expected={
                    "source": "candidate_pe_and_kernel_invoke_plan",
                    "sha256": invoke.candidate_sha256,
                    "size": invoke.candidate_size,
                },
                observed={
                    "source": "callback_plan",
                    "sha256": callback_sha256,
                    "size": callback_size,
                },
                site_rva=expected_site,
            )
        )

    sites = [
        _object(item, f"callback site {index}")
        for index, item in enumerate(
            _array(callback.get("sites"), "callback sites")
        )
    ]
    matching = [
        (index, site)
        for index, site in enumerate(sites)
        if site.get("rva") == expected_site
    ]
    callback_site_index: int | None = None
    callback_target_rvas: tuple[int, ...] = ()
    if len(matching) != 1:
        observed_resolvers = [
            {
                "rva": site.get("rva"),
                "continuation_rva": site.get("continuation_rva"),
            }
            for site in sites
            if site.get("function_role") == "invokeCall"
            or site.get("role") == "runtime_resolve_code_target"
        ]
        issues.append(
            InvokeNativeIssue(
                code=(
                    "callback_resolver_site_mismatch"
                    if stale
                    else "missing_callback_resolver_site"
                ),
                message=(
                    "callback inventory does not contain exactly one resolver "
                    "site for the reflected invokeCall instruction"
                ),
                expected={
                    "rva": expected_site,
                    "continuation_rva": expected_continuation,
                },
                observed=observed_resolvers,
                site_rva=expected_site,
            )
        )
    else:
        callback_site_index, site = matching[0]
        continuation = _nat(site.get("continuation_rva"), "resolver continuation")
        role = site.get("role")
        function_role = site.get("function_role")
        raw_targets = [
            _object(item, f"resolver target {index}")
            for index, item in enumerate(
                _array(site.get("targets"), "resolver targets")
            )
        ]
        callback_target_rvas = tuple(
            _nat(target.get("rva"), f"resolver target {index} RVA")
            for index, target in enumerate(raw_targets)
        )
        if (
            continuation != expected_continuation
            or role != "runtime_resolve_code_target"
            or function_role != "invokeCall"
            or not callback_target_rvas
        ):
            issues.append(
                InvokeNativeIssue(
                    code="invalid_callback_resolver_site",
                    message=(
                        "invokeCall resolver callback metadata is not the "
                        "reviewed finite-target site"
                    ),
                    expected={
                        "continuation_rva": expected_continuation,
                        "role": "runtime_resolve_code_target",
                        "function_role": "invokeCall",
                        "minimum_targets": 1,
                    },
                    observed={
                        "continuation_rva": continuation,
                        "role": role,
                        "function_role": function_role,
                        "target_rvas": list(callback_target_rvas),
                    },
                    site_rva=expected_site,
                )
            )

    return InterpreterKernelInvokeNativePlan(
        invoke=invoke,
        callback_plan_path=callback_path,
        callback_plan_sha256=sha256_file(callback_path),
        callback_candidate_sha256=callback_sha256,
        callback_candidate_size=callback_size,
        callback_site_index=callback_site_index,
        callback_site_rva=expected_site,
        callback_continuation_rva=expected_continuation,
        callback_target_rvas=callback_target_rvas,
        issues=tuple(issues),
    )


def _validate_module(value: str, context: str) -> str:
    if _LEAN_MODULE.fullmatch(value) is None:
        raise RelationalInterpreterKernelInvokeNativeGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )
    return value


def relational_interpreter_kernel_invoke_native_source(
    plan: InterpreterKernelInvokeNativePlan,
    *,
    invoke_module: str = "StageA.GeneratedRelationalInterpreterKernelInvoke",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> str:
    modules = {
        "invoke module": invoke_module,
        "kernel module": kernel_module,
        "callback module": callback_module,
        "data module": data_module,
    }
    for context, module in modules.items():
        _validate_module(module, context)
    if plan.callback_site_index is None or plan.issues:
        raise RelationalInterpreterKernelInvokeNativeGenerationError(
            "cannot emit native Lean goals from stale or incomplete callback evidence"
        )
    site_name = f"generatedKernelCallbackSite{plan.callback_site_index:04d}"
    target_name = f"generatedKernelCallback{plan.callback_site_index:04d}Target0000"
    return f"""import StageA.RelationalInterpreterKernelInvokeNative
import {invoke_module}
import {kernel_module}
import {callback_module}
import {data_module}

namespace StageA.GeneratedRelational.InterpreterKernelInvokeNative

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelInvoke
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelCallback
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterKernelInvoke

def generatedInvokeCallNativeProgram
    (environment : NativeWorldEnvironment) : ExactNativeWorldProgram := {{
  pe := generatedInterpreterKernelCandidatePe
  imports := generatedInterpreterKernelImports
  environment := environment
}}

def generatedInvokeCallResolverSiteRva : Nat := {plan.callback_site_rva}
def generatedInvokeCallResolverContinuationRva : Nat := {plan.callback_continuation_rva}
def generatedInvokeCallRunFunctionRva : Nat := {plan.invoke.run_function_rva}
def generatedInvokeCallExternalDispatchRva : Nat := {plan.invoke.external_dispatch_rva}

def GeneratedInvokeCallNativeStaticGoal : Prop :=
  generatedInvokeCallTemplate.checked generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedKernelCallbackInventory {plan.invoke.generated_function_name} = true /\\
    generatedKernelCallbackInventory.checked generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports = true /\\
    callbackSiteAt? generatedKernelCallbackInventory
      generatedInvokeCallResolverSiteRva = some {site_name} /\\
    {target_name} ∈ {site_name}.targets.entries

def GeneratedInvokeCallRunFunctionNativeGoal
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (abi : KernelABIRelation) (continuationRva : Nat) : Prop :=
  KernelOperationRefinesUsing generatedCompiledKernelProgram abi
    (NativeWorldSubroutineDispatches
      (generatedInvokeCallNativeProgram environment) world continuationRva
      (BitVec.ofNat 32
        (generatedInterpreterKernelCandidatePe.imageBase + continuationRva)))
    .runFunction

def GeneratedInvokeCallExternalNativeGoal
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before after : MachineState) (event : NativeExternalEvent) : Prop :=
  NativeWorldKernelDispatches (generatedInvokeCallNativeProgram environment)
    world generatedInvokeCallTemplate.entryRva before after
    [event]

def GeneratedInvokeCallIndirectNativeGoal
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (before after : MachineState) (events : List NativeExternalEvent) : Prop :=
  NativeWorldKernelDispatches (generatedInvokeCallNativeProgram environment)
    world generatedInvokeCallTemplate.entryRva before after events

end StageA.GeneratedRelational.InterpreterKernelInvokeNative
"""


def write_relational_interpreter_kernel_invoke_native_bundle(
    *,
    kernel_plan: Path | str,
    callback_plan: Path | str,
    candidate_pe: Path | str,
    out: Path | str,
    invoke_module: str = "StageA.GeneratedRelationalInterpreterKernelInvoke",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> InterpreterKernelInvokeNativePlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_invoke_native_plan(
        kernel_plan=kernel_plan,
        callback_plan=callback_plan,
        candidate_pe=candidate_pe,
    )
    write_json(output / INTERPRETER_KERNEL_INVOKE_NATIVE_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_INVOKE_NATIVE_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_invoke_native_source(
            plan,
            invoke_module=invoke_module,
            kernel_module=kernel_module,
            callback_module=callback_module,
            data_module=data_module,
        ),
        encoding="utf-8",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_INVOKE_NATIVE_FORMAT",
    "INTERPRETER_KERNEL_INVOKE_NATIVE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_INVOKE_NATIVE_PLAN_FILENAME",
    "InterpreterKernelInvokeNativePlan",
    "InvokeNativeIssue",
    "RelationalInterpreterKernelInvokeNativeGenerationError",
    "build_relational_interpreter_kernel_invoke_native_plan",
    "relational_interpreter_kernel_invoke_native_source",
    "write_relational_interpreter_kernel_invoke_native_bundle",
]
