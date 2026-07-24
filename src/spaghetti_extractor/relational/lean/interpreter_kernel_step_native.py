"""Generate exact-native proof data for the compiled interpreter Step.

The generator classifies only statically checked machine boundaries.  It does
not emit execution paths, final states, ABI responses, or semantic results.
Lean rechecks every byte, direct target, block cutpoint, and callback target
against the exact candidate PE before the local proof interface can be used.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_callback import INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT
from .interpreter_kernel_step import (
    InterpreterKernelStepPlan,
    build_relational_interpreter_kernel_step_plan,
)


INTERPRETER_KERNEL_STEP_NATIVE_FORMAT = (
    "stage-a-relational-interpreter-kernel-step-native-plan-v1"
)
INTERPRETER_KERNEL_STEP_NATIVE_PLAN_FILENAME = (
    "interpreter-kernel-step-native-plan.json"
)
INTERPRETER_KERNEL_STEP_NATIVE_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelStepNative.lean"
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_ROLE = "interpreterStep"
_EFFECTS = {
    "internal": "internal",
    "loop_header": "loopHeader",
    "loop_latch": "loopLatch",
    "direct_helper_call": "directHelperCall",
    "program_lookup_call": "programLookupCall",
    "invoke_call": "invokeCallCall",
    "indirect_callback_call": "indirectCallbackCall",
    "return": "return",
}


class RelationalInterpreterKernelStepNativeGenerationError(StageAInputError):
    """Exact native Step evidence is stale, ambiguous, or unsupported."""


@dataclass(frozen=True)
class StepNativeIssue:
    code: str
    message: str
    rva: int | None = None
    expected: object | None = None
    observed: object | None = None

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.rva is not None:
            result["rva"] = self.rva
        if self.expected is not None:
            result["expected"] = self.expected
        if self.observed is not None:
            result["observed"] = self.observed
        return result


@dataclass(frozen=True)
class StepNativeDirectCall:
    offset: int
    target_rva: int
    continuation_offset: int


@dataclass(frozen=True)
class StepNativeIndirectCall:
    offset: int
    continuation_offset: int
    target_rvas: tuple[int, ...]


@dataclass(frozen=True)
class StepNativeCutpoint:
    entry_rva: int
    instruction_count: int
    effect: str
    allowed_rvas: tuple[int, ...]


@dataclass(frozen=True)
class InterpreterKernelStepNativePlan:
    step: InterpreterKernelStepPlan
    candidate_size: int
    callback_plan_path: Path
    callback_plan_sha256: str
    direct_calls: tuple[StepNativeDirectCall, ...]
    indirect_calls: tuple[StepNativeIndirectCall, ...]
    program_lookup_call_offset: int | None
    program_lookup_entry_rva: int | None
    invoke_call_offset: int | None
    invoke_call_entry_rva: int | None
    helper_target_rvas: tuple[int, ...]
    callback_site_rvas: tuple[int, ...]
    callback_target_rvas: tuple[int, ...]
    cutpoints: tuple[StepNativeCutpoint, ...]
    issues: tuple[StepNativeIssue, ...]

    @property
    def candidate_sha256(self) -> str:
        return self.step.candidate_sha256

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_STEP_NATIVE_FORMAT,
            "acceptance_authority": False,
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "kernel_plan": self.step.kernel_plan_path.name,
                "kernel_plan_sha256": self.step.kernel_plan_sha256,
                "callback_plan": self.callback_plan_path.name,
                "callback_plan_sha256": self.callback_plan_sha256,
            },
            "function": {
                "role": _ROLE,
                "rva_start": self.step.function_entry_rva,
                "rva_end": self.step.function_end_rva,
                "sha256": self.step.function_sha256,
                "blocks": len(self.cutpoints),
                "instructions": self.step.instruction_count,
            },
            "calls": {
                "program_lookup": {
                    "offset": self.program_lookup_call_offset,
                    "target_rva": self.program_lookup_entry_rva,
                },
                "invoke_call": {
                    "offset": self.invoke_call_offset,
                    "target_rva": self.invoke_call_entry_rva,
                },
                "direct_helpers": list(self.helper_target_rvas),
                "indirect_sites": list(self.callback_site_rvas),
                "callback_targets": list(self.callback_target_rvas),
                "indirect_calls": [
                    {
                        "offset": call.offset,
                        "continuation_offset": call.continuation_offset,
                        "target_rvas": list(call.target_rvas),
                    }
                    for call in self.indirect_calls
                ],
            },
            "cutpoints": [
                {
                    "entry_rva": cutpoint.entry_rva,
                    "instruction_count": cutpoint.instruction_count,
                    "effect": cutpoint.effect,
                    "allowed_rvas": list(cutpoint.allowed_rvas),
                }
                for cutpoint in self.cutpoints
            ],
            "status": "incomplete" if self.issues else "local_semantics_required",
            "remaining_inhabitants": [
                "abi_entry_and_record_identity",
                "exact_program_lookup_call_and_continuation",
                "per_action_loop_invariants_and_native_chunks",
                "direct_helper_subroutine_refinements",
                "invoke_call_operation_refinement",
                "x87_replay_callback_refinement",
                "abi_epilogue_response_and_memory_frame",
            ],
            "forbidden_submitted_evidence": [
                "whole_operation_path",
                "whole_operation_final_state",
                "operation_level_result",
                "status_field_as_proof",
            ],
            "issues": [issue.payload() for issue in self.issues],
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _digest(value: object, context: str) -> str:
    result = _string(value, context)
    if _SHA256.fullmatch(result) is None:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return result


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"unable to read {context}: {path}"
        ) from exc


def _instruction_bytes(value: Mapping[str, Any], context: str) -> bytes:
    raw = _string(value.get("bytes"), f"{context} bytes")
    try:
        result = bytes.fromhex(raw)
    except ValueError as exc:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"{context} bytes are not hexadecimal"
        ) from exc
    if not result:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"{context} bytes must not be empty"
        )
    return result


def _direct_target(rva: int, data: bytes) -> int | None:
    if len(data) != 5 or data[0] != 0xE8:
        return None
    displacement = int.from_bytes(data[1:], "little", signed=True)
    return (rva + len(data) + displacement) & 0xFFFFFFFF


def _unique(values: list[int]) -> tuple[int, ...]:
    return tuple(dict.fromkeys(values))


def build_relational_interpreter_kernel_step_native_plan(
    *,
    kernel_plan: Path | str,
    callback_plan: Path | str,
    candidate_pe: Path | str,
) -> InterpreterKernelStepNativePlan:
    kernel_path = Path(kernel_plan)
    callback_path = Path(callback_plan)
    candidate_path = Path(candidate_pe)
    try:
        step = build_relational_interpreter_kernel_step_plan(kernel_path)
    except StageAInputError as exc:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"invalid reflected interpreterStep plan: {exc}"
        ) from exc
    kernel = _read_json(kernel_path, "kernel plan")
    candidate = _object(kernel.get("candidate"), "kernel candidate")
    kernel_size = _nat(candidate.get("size"), "kernel candidate size")
    try:
        actual_size = candidate_path.stat().st_size
        actual_sha256 = sha256_file(candidate_path)
    except OSError as exc:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"unable to read candidate PE: {candidate_path}"
        ) from exc
    if (actual_sha256, actual_size) != (step.candidate_sha256, kernel_size):
        raise RelationalInterpreterKernelStepNativeGenerationError(
            "candidate PE identity disagrees with the kernel plan: "
            f"expected sha256={step.candidate_sha256}, size={kernel_size}; "
            f"observed sha256={actual_sha256}, size={actual_size}"
        )

    functions = [
        _object(value, f"kernel function {index}")
        for index, value in enumerate(
            _array(kernel.get("kernel_functions"), "kernel functions")
        )
    ]
    step_functions = [value for value in functions if value.get("role") == _ROLE]
    if len(step_functions) != 1:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"kernel plan has {len(step_functions)} interpreterStep functions"
        )
    function = step_functions[0]
    entries: dict[int, str] = {}
    for index, value in enumerate(functions):
        entry = _nat(value.get("rva_start"), f"kernel function {index} start RVA")
        role = _string(value.get("role"), f"kernel function {index} role")
        if entry in entries:
            raise RelationalInterpreterKernelStepNativeGenerationError(
                f"duplicate kernel function entry RVA {entry}"
            )
        entries[entry] = role

    callback = _read_json(callback_path, "callback plan")
    if callback.get("format") != INTERPRETER_KERNEL_CALLBACK_PLAN_FORMAT:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            "callback plan has an unsupported format"
        )
    callback_candidate = _object(callback.get("candidate"), "callback candidate")
    callback_identity = (
        _digest(callback_candidate.get("sha256"), "callback candidate digest"),
        _nat(callback_candidate.get("size"), "callback candidate size"),
    )
    issues: list[StepNativeIssue] = []
    if callback_identity != (actual_sha256, actual_size):
        issues.append(
            StepNativeIssue(
                "callback_candidate_mismatch",
                "callback inventory describes a different candidate PE",
                expected={"sha256": actual_sha256, "size": actual_size},
                observed={
                    "sha256": callback_identity[0],
                    "size": callback_identity[1],
                },
            )
        )

    start = step.function_entry_rva
    direct_calls: list[StepNativeDirectCall] = []
    indirect_sites: list[tuple[int, int]] = []
    block_rows: list[tuple[int, list[Mapping[str, Any]], tuple[int, ...]]] = []
    for block_index, raw_block in enumerate(
        _array(function.get("blocks"), "interpreterStep blocks")
    ):
        block = _object(raw_block, f"interpreterStep block {block_index}")
        entry_rva = _nat(block.get("entry_rva"), f"block {block_index} entry")
        instructions = [
            _object(value, f"block {block_index} instruction {instruction_index}")
            for instruction_index, value in enumerate(
                _array(block.get("instructions"), f"block {block_index} instructions")
            )
        ]
        if not instructions:
            issues.append(
                StepNativeIssue(
                    "empty_step_block",
                    "a native Step cutpoint has no exact instructions",
                    rva=entry_rva,
                )
            )
            continue
        successors = tuple(
            _nat(value, f"block {block_index} successor")
            for value in _array(block.get("successors"), f"block {block_index} successors")
        )
        block_rows.append((entry_rva, instructions, successors))
        for instruction_index, instruction in enumerate(instructions):
            if instruction.get("mnemonic") != "call":
                continue
            rva = _nat(instruction.get("rva"), "call instruction RVA")
            data = _instruction_bytes(instruction, f"call at RVA {rva}")
            if instruction_index != len(instructions) - 1:
                issues.append(
                    StepNativeIssue(
                        "nonterminal_call_in_step_block",
                        "a call must terminate its exact native basic block",
                        rva=rva,
                    )
                )
            target = _direct_target(rva, data)
            if target is not None:
                direct_calls.append(
                    StepNativeDirectCall(rva - start, target, rva + len(data) - start)
                )
                if target not in entries:
                    issues.append(
                        StepNativeIssue(
                            "unresolved_step_direct_target",
                            "direct Step call does not target a checked kernel function",
                            rva=rva,
                            observed=target,
                        )
                    )
                expected_successors = {target, rva + len(data)}
                if not expected_successors.issubset(successors):
                    issues.append(
                        StepNativeIssue(
                            "incomplete_step_call_successors",
                            "direct call block omits its target or continuation",
                            rva=rva,
                            expected=sorted(expected_successors),
                            observed=list(successors),
                        )
                    )
            elif data[0] == 0xFF:
                indirect_sites.append((rva, rva + len(data)))
                if rva + len(data) not in successors:
                    issues.append(
                        StepNativeIssue(
                            "missing_indirect_continuation",
                            "indirect callback block omits its continuation",
                            rva=rva,
                            expected=rva + len(data),
                            observed=list(successors),
                        )
                    )
            else:
                issues.append(
                    StepNativeIssue(
                        "unsupported_step_call_encoding",
                        "Step call is neither rel32 nor a checked indirect form",
                        rva=rva,
                        observed=data.hex(),
                    )
                )

    observed_call_offsets = tuple(
        sorted(
            [call.offset for call in direct_calls]
            + [rva - start for rva, _ in indirect_sites]
        )
    )
    if observed_call_offsets != tuple(sorted(step.call_offsets)):
        issues.append(
            StepNativeIssue(
                "step_call_inventory_mismatch",
                "native call recovery disagrees with the reflected Step template",
                expected=list(step.call_offsets),
                observed=list(observed_call_offsets),
            )
        )

    lookup_calls = [
        call for call in direct_calls if entries.get(call.target_rva) == "programLookup"
    ]
    invoke_calls = [
        call for call in direct_calls if entries.get(call.target_rva) == "invokeCall"
    ]
    if len(lookup_calls) != 1:
        issues.append(
            StepNativeIssue(
                "ambiguous_program_lookup_call",
                "Step must contain exactly one direct call to programLookup",
                observed=[call.offset for call in lookup_calls],
            )
        )
    if len(invoke_calls) != 1:
        issues.append(
            StepNativeIssue(
                "ambiguous_invoke_call",
                "Step must contain exactly one direct call to invokeCall",
                observed=[call.offset for call in invoke_calls],
            )
        )
    lookup = lookup_calls[0] if len(lookup_calls) == 1 else None
    invoke = invoke_calls[0] if len(invoke_calls) == 1 else None
    helper_targets = _unique(
        [
            call.target_rva
            for call in direct_calls
            if call not in lookup_calls and call not in invoke_calls
        ]
    )

    callback_sites = [
        _object(value, f"callback site {index}")
        for index, value in enumerate(_array(callback.get("sites"), "callback sites"))
    ]
    indirect_calls: list[StepNativeIndirectCall] = []
    callback_targets: list[int] = []
    for rva, continuation in indirect_sites:
        matches = [
            site
            for site in callback_sites
            if site.get("rva") == rva and site.get("function_role") == _ROLE
        ]
        if len(matches) != 1:
            issues.append(
                StepNativeIssue(
                    "missing_step_callback_site",
                    "indirect Step call has no unique checked callback site",
                    rva=rva,
                    observed=len(matches),
                )
            )
            continue
        site = matches[0]
        observed_continuation = _nat(
            site.get("continuation_rva"), "callback continuation RVA"
        )
        targets = [
            _nat(
                _object(value, f"callback target {index}").get("rva"),
                f"callback target {index} RVA",
            )
            for index, value in enumerate(_array(site.get("targets"), "callback targets"))
        ]
        if observed_continuation != continuation or not targets:
            issues.append(
                StepNativeIssue(
                    "invalid_step_callback_site",
                    "callback continuation or finite target set is invalid",
                    rva=rva,
                    expected={"continuation_rva": continuation, "minimum_targets": 1},
                    observed={
                        "continuation_rva": observed_continuation,
                        "targets": targets,
                    },
                )
            )
        indirect_calls.append(
            StepNativeIndirectCall(
                offset=rva - start,
                continuation_offset=continuation - start,
                target_rvas=tuple(targets),
            )
        )
        callback_targets.extend(targets)
    callback_target_rvas = _unique(callback_targets)

    loop_headers = {start + loop.header_offset for loop in step.loops}
    loop_latches = {start + loop.latch_offset for loop in step.loops}
    return_rvas = {start + offset for offset in step.return_offsets}
    lookup_offset = lookup.offset if lookup is not None else None
    invoke_offset = invoke.offset if invoke is not None else None
    direct_offsets = {call.offset for call in direct_calls}
    indirect_offsets = {rva - start for rva, _ in indirect_sites}
    cutpoints: list[StepNativeCutpoint] = []
    indirect_targets_by_offset = {
        call.offset: call.target_rvas for call in indirect_calls
    }
    for entry_rva, instructions, successors in block_rows:
        instruction_rvas = {
            _nat(value.get("rva"), "block instruction RVA") for value in instructions
        }
        relative_rvas = {rva - start for rva in instruction_rvas}
        if lookup_offset is not None and lookup_offset in relative_rvas:
            effect = "program_lookup_call"
        elif invoke_offset is not None and invoke_offset in relative_rvas:
            effect = "invoke_call"
        elif relative_rvas & indirect_offsets:
            effect = "indirect_callback_call"
        elif relative_rvas & direct_offsets:
            effect = "direct_helper_call"
        elif instruction_rvas & return_rvas:
            effect = "return"
        elif entry_rva in loop_headers:
            effect = "loop_header"
        elif entry_rva in loop_latches:
            effect = "loop_latch"
        else:
            effect = "internal"
        allowed = list(successors)
        if effect == "indirect_callback_call":
            for offset in sorted(relative_rvas & indirect_offsets):
                allowed.extend(indirect_targets_by_offset.get(offset, ()))
        cutpoints.append(
            StepNativeCutpoint(
                entry_rva=entry_rva,
                instruction_count=len(instructions),
                effect=effect,
                allowed_rvas=tuple(allowed),
            )
        )

    return InterpreterKernelStepNativePlan(
        step=step,
        candidate_size=actual_size,
        callback_plan_path=callback_path,
        callback_plan_sha256=sha256_file(callback_path),
        direct_calls=tuple(direct_calls),
        indirect_calls=tuple(indirect_calls),
        program_lookup_call_offset=None if lookup is None else lookup.offset,
        program_lookup_entry_rva=None if lookup is None else lookup.target_rva,
        invoke_call_offset=None if invoke is None else invoke.offset,
        invoke_call_entry_rva=None if invoke is None else invoke.target_rva,
        helper_target_rvas=helper_targets,
        callback_site_rvas=tuple(rva for rva, _ in indirect_sites),
        callback_target_rvas=callback_target_rvas,
        cutpoints=tuple(cutpoints),
        issues=tuple(issues),
    )


def _validate_module(value: str, context: str) -> str:
    if _LEAN_MODULE.fullmatch(value) is None:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )
    return value


def _lean_nats(values: tuple[int, ...]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def _lean_direct_call(value: StepNativeDirectCall) -> str:
    return (
        "{ offset := "
        f"{value.offset}, targetRva := {value.target_rva}, "
        f"continuationOffset := {value.continuation_offset} }}"
    )


def _lean_indirect_call(value: StepNativeIndirectCall) -> str:
    return (
        "{ offset := "
        f"{value.offset}, continuationOffset := {value.continuation_offset}, "
        f"targetRvas := {_lean_nats(value.target_rvas)} }}"
    )


def _lean_cutpoint(value: StepNativeCutpoint) -> str:
    return (
        "{ entryRva := "
        f"{value.entry_rva}, instructionCount := {value.instruction_count}, "
        f"effect := .{_EFFECTS[value.effect]}, "
        f"allowedRvas := {_lean_nats(value.allowed_rvas)} }}"
    )


def relational_interpreter_kernel_step_native_source(
    plan: InterpreterKernelStepNativePlan,
    *,
    step_module: str = "StageA.GeneratedRelationalInterpreterKernelStep",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> str:
    for context, module in (
        ("step module", step_module),
        ("kernel module", kernel_module),
        ("callback module", callback_module),
        ("data module", data_module),
    ):
        _validate_module(module, context)
    if plan.issues:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            "cannot emit Lean proof data for incomplete exact-native Step evidence"
        )
    if plan.program_lookup_call_offset is None or plan.invoke_call_offset is None:
        raise RelationalInterpreterKernelStepNativeGenerationError(
            "cannot emit Lean proof data without unique kernel operation calls"
        )
    direct_calls = ",\n  ".join(_lean_direct_call(value) for value in plan.direct_calls)
    indirect_calls = ",\n  ".join(
        _lean_indirect_call(value) for value in plan.indirect_calls
    )
    cutpoints = ",\n  ".join(_lean_cutpoint(value) for value in plan.cutpoints)
    function_name = plan.step.generated_function_name
    return f"""import StageA.RelationalInterpreterKernelStepNative
import {step_module}
import {kernel_module}
import {callback_module}
import {data_module}

namespace StageA.GeneratedRelational.InterpreterKernelStepNative

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelStep
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.SymbolicSoundness
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelCallback
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterKernelStep

def generatedInterpreterStepNativeCandidateSha256 : String :=
  \"{plan.candidate_sha256}\"

def generatedInterpreterStepNativeCandidateSize : Nat := {plan.candidate_size}

def generatedInterpreterStepNativeTemplate : InterpreterStepNativeTemplate := {{
  machine := generatedInterpreterStepTemplate
  directCalls := [
  {direct_calls}
  ]
  indirectCalls := [
  {indirect_calls}
  ]
  programLookupCallOffset := {plan.program_lookup_call_offset}
  invokeCallOffset := {plan.invoke_call_offset}
  helperTargetRvas := {_lean_nats(plan.helper_target_rvas)}
  cutpoints := [
  {cutpoints}
  ]
}}

def generatedInterpreterStepNativeProgram
    (environment : NativeWorldEnvironment) : ExactNativeWorldProgram := {{
  pe := generatedInterpreterKernelCandidatePe
  imports := generatedInterpreterKernelImports
  environment := environment
}}

def GeneratedInterpreterStepNativeStaticGoal : Prop :=
  parsePE32Tree generatedInterpreterKernelCandidateBytes =
      some generatedInterpreterKernelCandidatePe /\\
    generatedInterpreterStepNativeTemplate.checked generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedKernelCallbackInventory {function_name} = true /\\
    ExactDecodeInventory generatedInterpreterKernelCandidatePe
      {function_name}.instructions

def GeneratedInterpreterStepNativeCertificateGoal
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (abi : KernelABIRelation) (semanticRecords : List ProgramRecord) : Prop :=
  Nonempty (InterpreterStepNativeMachineCertificate
    generatedCompiledKernelProgram abi semanticRecords
    (generatedInterpreterStepNativeProgram environment) world)

def GeneratedInterpreterStepNativeConcreteCertificateGoal
    (environment : NativeWorldEnvironment) (world : RelationalWorld)
    (semanticRecords : List ProgramRecord)
    (abi : ConcreteKernelABI generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva generatedInterpreterKernelCountRva
      semanticRecords) : Prop :=
  abi.program = generatedCompiledKernelProgram /\\
    Nonempty (InterpreterStepNativeMachineCertificate
      generatedCompiledKernelProgram abi.relation semanticRecords
      (generatedInterpreterStepNativeProgram environment) world)

theorem GeneratedInterpreterStepNativeRefines
    {{environment : NativeWorldEnvironment}} {{world : RelationalWorld}}
    {{abi : KernelABIRelation}} {{semanticRecords : List ProgramRecord}}
    (certificate : InterpreterStepNativeMachineCertificate
      generatedCompiledKernelProgram abi semanticRecords
      (generatedInterpreterStepNativeProgram environment) world) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram abi
      (InterpreterStepNativeDispatches
        (generatedInterpreterStepNativeProgram environment) world)
      .interpreterStep :=
  certificate.refines

#print axioms GeneratedInterpreterStepNativeRefines

end StageA.GeneratedRelational.InterpreterKernelStepNative
"""


def write_relational_interpreter_kernel_step_native_bundle(
    *,
    kernel_plan: Path | str,
    callback_plan: Path | str,
    candidate_pe: Path | str,
    out: Path | str,
    step_module: str = "StageA.GeneratedRelationalInterpreterKernelStep",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> InterpreterKernelStepNativePlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_step_native_plan(
        kernel_plan=kernel_plan,
        callback_plan=callback_plan,
        candidate_pe=candidate_pe,
    )
    write_json(output / INTERPRETER_KERNEL_STEP_NATIVE_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_STEP_NATIVE_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_step_native_source(
            plan,
            step_module=step_module,
            kernel_module=kernel_module,
            callback_module=callback_module,
            data_module=data_module,
        ),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_STEP_NATIVE_FORMAT",
    "INTERPRETER_KERNEL_STEP_NATIVE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_NATIVE_PLAN_FILENAME",
    "InterpreterKernelStepNativePlan",
    "RelationalInterpreterKernelStepNativeGenerationError",
    "StepNativeCutpoint",
    "StepNativeDirectCall",
    "StepNativeIndirectCall",
    "StepNativeIssue",
    "build_relational_interpreter_kernel_step_native_plan",
    "relational_interpreter_kernel_step_native_source",
    "write_relational_interpreter_kernel_step_native_bundle",
]
