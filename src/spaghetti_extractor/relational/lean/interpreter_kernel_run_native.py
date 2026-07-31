"""Generate exact native ``runFunction`` template and local replay evidence.

The planner performs only fail-fast proposal checks.  The emitted Lean module
rechecks the canonical O0 template against the exact candidate PE and exposes
the local semantic premises consumed by the checked-call-tree operation proof.
It does not expose a parallel whole-operation refinement theorem.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...errors import StageAInputError
from ...util import write_json
from .interpreter_kernel_run import (
    InterpreterKernelRunPlan,
    RelationalInterpreterKernelRunGenerationError,
    build_relational_interpreter_kernel_run_plan,
)


INTERPRETER_KERNEL_RUN_NATIVE_FORMAT = (
    "stage-a-relational-interpreter-kernel-run-native-plan-v1"
)
INTERPRETER_KERNEL_RUN_NATIVE_PLAN_FILENAME = "interpreter-kernel-run-native-plan.json"
INTERPRETER_KERNEL_RUN_NATIVE_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelRunNative.lean"
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)

_O0_PREFIX = bytes.fromhex(
    "5589e557565381ec2c010000837d10007406837d1400750a"
    "b801000000e9240100008b55108d85ecfeffff89d3ba3f000000"
    "89c789de89d1f3a58d85e0feffff8b550c8954240c8d95ecfeffff"
    "895424088b550889542404890424e8"
)
_O0_SUFFIX = bytes.fromhex(
    "8b85e0feffff83f802770e8b85e4feffff89450ce9c8000000"
    "8b85e0feffff83f804754b837d080074308b45088b401485c07426"
    "8b45088b40148b95e8feffff8d8ddcfeffff894c240889542404"
    "8b5508891424ffd085c0740ab801000000e982000000"
    "8b85dcfeffff89450ceb728b85e0feffff83f803740b"
    "8b85e0feffff83f809751f8b451489c38d85ecfeffffba3f000000"
    "89df89c689d1f3a5b800000000eb428b85e0feffff83f805742b"
    "8b85e0feffff83f80674198b85e0feffff83f8087507"
    "b804000000eb1ab801000000eb13b803000000eb0c"
    "b802000000eb05e9f4feffff81c42c0100005b5e5f5d31d231c9c3"
)
_BLOCK_OFFSETS = (
    0,
    18,
    24,
    34,
    58,
    96,
    107,
    121,
    132,
    138,
    148,
    182,
    186,
    196,
    207,
    218,
    229,
    260,
    271,
    282,
    293,
    300,
    307,
    314,
    321,
    326,
)
_BLOCK_INSTRUCTION_COUNTS = (
    8,
    2,
    2,
    8,
    9,
    3,
    3,
    3,
    2,
    4,
    9,
    2,
    2,
    3,
    3,
    3,
    10,
    3,
    3,
    3,
    2,
    2,
    2,
    2,
    1,
    8,
)
_LOOP_BODY_OFFSETS = (
    58,
    96,
    107,
    121,
    132,
    138,
    148,
    182,
    186,
    196,
    207,
    218,
    229,
    260,
    271,
    282,
    293,
    300,
    307,
    314,
    321,
)

_OUTPUT_STATE_O0_BYTES = bytes.fromhex(
    "5589e557565381ec2c0100008b450c8945e4837d10007406837d1400750a"
    "b801000000e9570100008b55108d85e8feffff89d3ba3f00000089c789de"
    "89d1f3a58d85dcfeffff8b550c8954240c8d95e8feffff895424088b5508"
    "89542404890424e814f5ffff8b85dcfeffff83f802770e8b85e0feffff89"
    "450ce9fb0000008b85dcfeffff83f8047572837d080074308b45088b4014"
    "85c074268b45088b40148b95e4feffff8d8dd8feffff894c240889542404"
    "8b5508891424ffd085c0742e8b451489c38d85e8feffffba3f00000089df"
    "89c689d1f3a58b45148b55e48990f8000000b801000000e9910000008b85"
    "d8feffff89450ce944ffffff8b451489c38d85e8feffffba3f00000089df"
    "89c689d1f3a58b45148b55e48990f80000008b85dcfeffff83f803740b8b"
    "85dcfeffff83f8097507b800000000eb428b85dcfeffff83f8057507b802"
    "000000eb308b85dcfeffff83f8067507b803000000eb1e8b85dcfeffff83"
    "f8087507b804000000eb0cb801000000eb05e9c1feffff81c42c0100005b"
    "5e5f5d31d231c9c3"
)
_OUTPUT_STATE_REL32_OFFSET = 97
_OUTPUT_STATE_O0_PREFIX = _OUTPUT_STATE_O0_BYTES[: _OUTPUT_STATE_REL32_OFFSET + 1]
_OUTPUT_STATE_O0_SUFFIX = _OUTPUT_STATE_O0_BYTES[_OUTPUT_STATE_REL32_OFFSET + 5 :]
_OUTPUT_STATE_BLOCK_OFFSETS = (
    0,
    24,
    30,
    40,
    64,
    102,
    113,
    127,
    138,
    144,
    154,
    188,
    192,
    238,
    252,
    299,
    310,
    317,
    328,
    335,
    346,
    353,
    364,
    371,
    378,
    383,
)
_OUTPUT_STATE_BLOCK_INSTRUCTION_COUNTS = (
    10,
    2,
    2,
    8,
    9,
    3,
    3,
    3,
    2,
    4,
    9,
    2,
    13,
    3,
    14,
    3,
    2,
    3,
    2,
    3,
    2,
    3,
    2,
    2,
    1,
    8,
)
_OUTPUT_STATE_FIRST_LOOP_BODY_OFFSETS = (
    64,
    102,
    113,
    127,
    138,
    144,
    154,
    188,
    192,
    238,
)
_OUTPUT_STATE_SECOND_LOOP_BODY_OFFSETS = (
    64,
    102,
    113,
    127,
    138,
    144,
    154,
    188,
    192,
    238,
    252,
    299,
    310,
    317,
    328,
    335,
    346,
    353,
    364,
    371,
    378,
)


@dataclass(frozen=True)
class _RunNativeTemplateProfile:
    identifier: str
    size: int
    rel32_offset: int
    prefix: bytes
    suffix: bytes
    block_offsets: tuple[int, ...]
    block_instruction_counts: tuple[int, ...]
    loop_inventory: tuple[tuple[int, int, tuple[int, ...]], ...]
    direct_call_offset: int
    indirect_call_offset: int
    return_offset: int
    frame_teardown_offset: int
    entry_fuel: int
    step_prelude_fuel: int
    direct_completion_fuel: int
    resolver_prelude_fuel: int
    resolver_suffix_fuel: int
    terminal_fuels: tuple[tuple[str, int], ...]
    epilogue_fuel: int

    @property
    def masked_rel32_bytes(self) -> list[int]:
        return list(range(self.rel32_offset + 1, self.rel32_offset + 5))


_LEGACY_O0_PROFILE = _RunNativeTemplateProfile(
    identifier="cdecl-o0-v1",
    size=341,
    rel32_offset=91,
    prefix=_O0_PREFIX,
    suffix=_O0_SUFFIX,
    block_offsets=_BLOCK_OFFSETS,
    block_instruction_counts=_BLOCK_INSTRUCTION_COUNTS,
    loop_inventory=((58, 321, _LOOP_BODY_OFFSETS),),
    direct_call_offset=91,
    indirect_call_offset=180,
    return_offset=340,
    frame_teardown_offset=335,
    entry_fuel=18,
    step_prelude_fuel=9,
    direct_completion_fuel=7,
    resolver_prelude_fuel=21,
    resolver_suffix_fuel=6,
    terminal_fuels=(
        ("ok_returned", 19),
        ("ok_external_jump", 22),
        ("divide_error", 17),
        ("memory_fault", 20),
        ("external_fault", 23),
        ("unimplemented", 23),
    ),
    epilogue_fuel=8,
)
_OUTPUT_STATE_O0_PROFILE = _RunNativeTemplateProfile(
    identifier="cdecl-o0-output-state-v2",
    size=398,
    rel32_offset=_OUTPUT_STATE_REL32_OFFSET,
    prefix=_OUTPUT_STATE_O0_PREFIX,
    suffix=_OUTPUT_STATE_O0_SUFFIX,
    block_offsets=_OUTPUT_STATE_BLOCK_OFFSETS,
    block_instruction_counts=_OUTPUT_STATE_BLOCK_INSTRUCTION_COUNTS,
    loop_inventory=(
        (64, 238, _OUTPUT_STATE_FIRST_LOOP_BODY_OFFSETS),
        (64, 378, _OUTPUT_STATE_SECOND_LOOP_BODY_OFFSETS),
    ),
    direct_call_offset=97,
    indirect_call_offset=186,
    return_offset=397,
    frame_teardown_offset=392,
    entry_fuel=20,
    step_prelude_fuel=9,
    direct_completion_fuel=7,
    resolver_prelude_fuel=21,
    resolver_suffix_fuel=5,
    terminal_fuels=(
        ("ok_returned", 22),
        ("ok_external_jump", 25),
        ("divide_error", 28),
        ("memory_fault", 31),
        ("external_fault", 34),
        ("unimplemented", 34),
    ),
    epilogue_fuel=8,
)
_REVIEWED_O0_PROFILES = (_LEGACY_O0_PROFILE, _OUTPUT_STATE_O0_PROFILE)


class RelationalInterpreterKernelRunNativeGenerationError(StageAInputError):
    """The candidate does not match the reviewed native run template."""


@dataclass(frozen=True)
class InterpreterKernelRunNativePlan:
    run: InterpreterKernelRunPlan
    candidate_path: Path
    template_profile: _RunNativeTemplateProfile

    @property
    def candidate_sha256(self) -> str:
        return self.run.candidate_sha256

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_RUN_NATIVE_FORMAT,
            "acceptance_authority": False,
            "operation": "runFunction",
            "candidate": {
                "path": self.candidate_path.name,
                "sha256": self.candidate_sha256,
                "size": self.run.candidate_size,
            },
            "template": {
                "reviewed_profile": self.template_profile.identifier,
                "bytes": len(self.run.function_bytes),
                "blocks": len(self.run.blocks),
                "instructions": self.run.instruction_count,
                "loops": len(self.run.loops),
                "semantic_loop_header_offset": self.run.semantic_loop_header_offset,
                "backedge_latch_offsets": list(self.run.backedge_latch_offsets),
                "entry_rva": self.run.function_entry_rva,
                "function_sha256": self.run.function_sha256,
                "function_symbol": self.run.generated_function_name,
                "masked_rel32_bytes": self.template_profile.masked_rel32_bytes,
            },
            "fixed_native_chunks": [
                {"id": "entry", "fuel": self.template_profile.entry_fuel},
                {
                    "id": "interpreter_step_prelude",
                    "fuel": self.template_profile.step_prelude_fuel,
                },
                {
                    "id": "direct_completion",
                    "fuel": self.template_profile.direct_completion_fuel,
                },
                {
                    "id": "resolver_prelude",
                    "fuel": self.template_profile.resolver_prelude_fuel,
                },
                {
                    "id": "resolver_suffix",
                    "fuel": self.template_profile.resolver_suffix_fuel,
                },
                {
                    "id": "terminal_dispatch",
                    "fuel_by_status": dict(self.template_profile.terminal_fuels),
                },
                {
                    "id": "epilogue",
                    "fuel": self.template_profile.epilogue_fuel,
                },
            ],
            "constructed_lean_evidence": [
                "RunFunctionNativeTemplateCertificate",
                "RunFunctionNativeChunk.path",
                "RunFunctionNativeResolverExecution.path",
                "RunFunctionNativeContinuationLocal.path",
            ],
            "remaining_semantic_premises": [
                "request-local checked Step refinement for every retained derivation",
                "entry chunk establishes the copied-state loop invariant",
                "step response establishes completion-tag and state-copy cutpoints",
                "checked resolver callback target preserves the nested runtime",
                "fixed completion chunks preserve the loop invariant",
                "epilogue establishes the cdecl ABI response and memory frame",
            ],
            "forbidden_submitted_evidence": [
                "whole_native_path",
                "caller_selected_final_state",
                "caller_selected_response",
                "python_status_as_proof",
            ],
        }


def _validate_o0_template(
    plan: InterpreterKernelRunPlan,
) -> _RunNativeTemplateProfile:
    data = plan.function_bytes
    observed_offsets = tuple(block.entry_offset for block in plan.blocks)
    observed_counts = tuple(len(block.instructions) for block in plan.blocks)
    observed_loops = tuple(
        (loop.header_offset, loop.latch_offset, loop.body_offsets)
        for loop in plan.loops
    )
    matches = [
        profile
        for profile in _REVIEWED_O0_PROFILES
        if len(data) == profile.size
        and data[: profile.rel32_offset + 1] == profile.prefix
        and data[profile.rel32_offset + 5 :] == profile.suffix
    ]
    if not matches:
        raise RelationalInterpreterKernelRunNativeGenerationError(
            "runFunction does not match the reviewed O0 instruction template"
        )
    matches = [
        profile
        for profile in matches
        if observed_offsets == profile.block_offsets
        and observed_counts == profile.block_instruction_counts
    ]
    if not matches:
        raise RelationalInterpreterKernelRunNativeGenerationError(
            "runFunction block boundaries do not match the reviewed O0 template"
        )
    matches = [
        profile for profile in matches if observed_loops == profile.loop_inventory
    ]
    if not matches:
        raise RelationalInterpreterKernelRunNativeGenerationError(
            "runFunction loop does not match the reviewed O0 template"
        )
    matches = [
        profile
        for profile in matches
        if plan.direct_call_offsets == (profile.direct_call_offset,)
        and plan.direct_call_targets == (plan.interpreter_step_rva,)
        and plan.indirect_call_offsets == (profile.indirect_call_offset,)
        and plan.return_offsets == (profile.return_offset,)
        and plan.frame_push_offset == 0
        and plan.frame_setup_offset == 1
        and plan.frame_teardown_offsets == (profile.frame_teardown_offset,)
        and plan.frame_return_offsets == (profile.return_offset,)
        and not plan.x87_frame_offsets
        and not plan.x87_command_offsets
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelRunNativeGenerationError(
            "runFunction calls, frame, or return do not match the reviewed O0 template"
        )
    return matches[0]


def build_relational_interpreter_kernel_run_native_plan(
    *, kernel_plan: Path | str, candidate_pe: Path | str
) -> InterpreterKernelRunNativePlan:
    candidate_path = Path(candidate_pe)
    try:
        run = build_relational_interpreter_kernel_run_plan(
            kernel_plan, candidate_pe=candidate_path
        )
    except RelationalInterpreterKernelRunGenerationError as exc:
        raise RelationalInterpreterKernelRunNativeGenerationError(str(exc)) from exc
    template_profile = _validate_o0_template(run)
    return InterpreterKernelRunNativePlan(
        run=run,
        candidate_path=candidate_path,
        template_profile=template_profile,
    )


def _validate_module(module: str, context: str) -> str:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelRunNativeGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )
    return module


def relational_interpreter_kernel_run_native_source(
    plan: InterpreterKernelRunNativePlan,
    *,
    run_module: str = "StageA.GeneratedRelationalInterpreterKernelRun",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBase",
) -> str:
    for context, module in (
        ("run module", run_module),
        ("kernel module", kernel_module),
        ("callback module", callback_module),
        ("data module", data_module),
    ):
        _validate_module(module, context)
    function_name = plan.run.generated_function_name
    return f"""import StageA.RelationalInterpreterKernelRun
import {run_module}
import {kernel_module}
import {callback_module}
import {data_module}

namespace StageA.GeneratedRelational.InterpreterKernelRunNative

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelCallback
open StageA.GeneratedRelational.InterpreterKernelRun
open StageA.GeneratedRelational.InterpreterKernelData

def GeneratedRunFunctionNativeO0TemplateGoal : Prop :=
  runFunctionNativeO0TemplateChecked generatedRunFunctionTemplate = true

def generatedRunFunctionNativeTemplateCertificate
    (static : GeneratedRunFunctionTemplateGoal)
    (native : GeneratedRunFunctionNativeO0TemplateGoal) :
    RunFunctionNativeTemplateCertificate generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      {function_name} := {{
  reflected := {{
    template := generatedRunFunctionTemplate
    callbacks := generatedKernelCallbackInventory
    checked := static.1
    exactDecodes := static.2
  }}
  nativeChecked := native
}}

def GeneratedRunFunctionNativeLocalSemanticsGoal
    (static : GeneratedRunFunctionTemplateGoal)
    (native : GeneratedRunFunctionNativeO0TemplateGoal)
    (abi : KernelABIRelation) (candidate : ExactNativeWorldProgram)
    (records : List ProgramRecord) (stepEntryRva : Nat) : Type :=
  let certificate := generatedRunFunctionNativeTemplateCertificate static native
  RunFunctionNativeLocalSemantics generatedCompiledKernelProgram abi candidate
    generatedRunFunctionTemplate records stepEntryRva certificate.resolverTargets

#print axioms generatedRunFunctionNativeTemplateCertificate

end StageA.GeneratedRelational.InterpreterKernelRunNative
"""


def write_relational_interpreter_kernel_run_native_bundle(
    *,
    kernel_plan: Path | str,
    candidate_pe: Path | str,
    out: Path | str,
    run_module: str = "StageA.GeneratedRelationalInterpreterKernelRun",
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    callback_module: str = "StageA.GeneratedRelationalInterpreterKernelCallback",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBase",
) -> InterpreterKernelRunNativePlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_run_native_plan(
        kernel_plan=kernel_plan, candidate_pe=candidate_pe
    )
    write_json(output / INTERPRETER_KERNEL_RUN_NATIVE_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_RUN_NATIVE_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_run_native_source(
            plan,
            run_module=run_module,
            kernel_module=kernel_module,
            callback_module=callback_module,
            data_module=data_module,
        ),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_RUN_NATIVE_FORMAT",
    "INTERPRETER_KERNEL_RUN_NATIVE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_RUN_NATIVE_PLAN_FILENAME",
    "InterpreterKernelRunNativePlan",
    "RelationalInterpreterKernelRunNativeGenerationError",
    "build_relational_interpreter_kernel_run_native_plan",
    "relational_interpreter_kernel_run_native_source",
    "write_relational_interpreter_kernel_run_native_bundle",
]
