"""Generate exact-data obligations for the compiled Stage B interpreter kernel.

The linker map and Capstone are proposal mechanisms only.  The emitted Lean
module re-parses the candidate, re-reads every range, and re-decodes every
instruction with the authoritative Stage A semantics.  This module never emits
a semantic certificate or an acceptance status.
"""

from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import capstone
from capstone import x86_const

from ...stage_b_interpreter_backend import STAGE_B_INTERPRETER_PROGRAM_FORMAT
from ...stage_b_engine_layout import (
    EngineLayoutFormatError,
    parse_stage_b_engine_layout_payload,
)
from ...stage_b_interpreter_native_build import INTERPRETER_NATIVE_BUILD_FORMAT
from ...stage_binary import (
    StageABinary,
    StageAInputError,
    _parse_linker_map_functions,
    _parse_stage_a_pe,
)
from ...util import sha256_bytes, sha256_file, write_json
from ..x86_instruction_profile import is_reviewed_x87_frame_instruction
from .artifact_byte_packs import (
    DEFAULT_ARTIFACT_BYTE_PACK_SIZE,
    ExternalArtifactBytesBinding,
    generate_artifact_byte_pack_bundle,
)
from .common import _lean_byte_tree_definitions, _lean_bytes


INTERPRETER_KERNEL_PLAN_FORMAT = "stage-a-relational-interpreter-kernel-plan-v2"
INTERPRETER_KERNEL_PLAN_FILENAME = "interpreter-kernel-plan.json"
INTERPRETER_KERNEL_LEAN_FILENAME = "GeneratedRelationalInterpreterKernel.lean"

_PROOF_COMPILE_POLICY = "deterministic-freestanding-proof-o0-v1"
_REQUIRED_FLAGS = frozenset({"-O0", "-fno-inline", "-fno-omit-frame-pointer"})
_FORBIDDEN_OPTIMIZATION = re.compile(r"-O(?:[1-9]|g|s|fast)\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GNU_SYMBOL = re.compile(
    r"^\s*(0x[0-9a-fA-F]+)\s+([A-Za-z_.$@?][A-Za-z0-9_.$@?~-]*)\s*$"
)
_MSVC_SYMBOL = re.compile(
    r"^\s*[0-9a-fA-F]{4}:[0-9a-fA-F]{8,16}\s+"
    r"(\S+)\s+([0-9a-fA-F]{8,16})(?:\s+.*)?$"
)
_STAGE_A_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LEAN_NAMESPACE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LEAN_LOCAL_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")

_FUNCTION_ROLES = (
    ("stage_b_program_lookup", "programLookup"),
    ("stage_b_interpreter_step", "interpreterStep"),
    ("stage_b_run_function", "runFunction"),
    ("stage_b_invoke_call", "invokeCall"),
)

_TRANSFER_RECORD_SIZE = 40
_WORD_NODE_SIZE = 36
_X87_NODE_SIZE = 36
_ACTION_SIZE = 32
_CALL_SIZE = 64
_X87_REPLAY_SIZE = 44
_X87_FRAME_SIZE = 108


class RelationalInterpreterKernelGenerationError(StageAInputError):
    """A native kernel artifact is stale, ambiguous, or malformed."""


@dataclass(frozen=True)
class KernelIssue:
    code: str
    message: str
    rva_start: int | None = None
    rva_end: int | None = None
    function_role: str | None = None

    def payload(self) -> dict[str, Any]:
        value: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.rva_start is not None:
            value["rva_start"] = self.rva_start
        if self.rva_end is not None:
            value["rva_end"] = self.rva_end
        if self.function_role is not None:
            value["function_role"] = self.function_role
        return value


@dataclass(frozen=True)
class ExactRange:
    role: str
    start: int
    data: bytes

    @property
    def end(self) -> int:
        return self.start + len(self.data)

    @property
    def sha256(self) -> str:
        return sha256_bytes(self.data)

    def payload(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "rva_start": self.start,
            "rva_end": self.end,
            "size": len(self.data),
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class KernelInstructionPlan:
    rva: int
    data: bytes
    mnemonic: str

    def payload(self) -> dict[str, Any]:
        return {
            "rva": self.rva,
            "bytes": self.data.hex(),
            "mnemonic": self.mnemonic,
        }


@dataclass(frozen=True)
class KernelX87FramePlan:
    rva: int
    data: bytes
    operation: str
    base_register: str | None
    index_register: str | None
    scale: int
    displacement: int

    @property
    def successor(self) -> int:
        return self.rva + len(self.data)

    def payload(self) -> dict[str, Any]:
        return {
            "rva": self.rva,
            "bytes": self.data.hex(),
            "mnemonic": self.operation,
            "frame_size": _X87_FRAME_SIZE,
            "addressing": {
                "base_register": self.base_register,
                "index_register": self.index_register,
                "scale": self.scale,
                "displacement": self.displacement,
            },
            "successor": self.successor,
        }


@dataclass(frozen=True)
class KernelBlockPlan:
    entry_rva: int
    instructions: tuple[KernelInstructionPlan, ...]
    successors: tuple[int, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "entry_rva": self.entry_rva,
            "instructions": [item.payload() for item in self.instructions],
            "successors": list(self.successors),
        }


@dataclass(frozen=True)
class KernelLoopPlan:
    header_rva: int
    latch_rva: int
    body_entries: tuple[int, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "header_rva": self.header_rva,
            "latch_rva": self.latch_rva,
            "body_entries": list(self.body_entries),
        }


@dataclass(frozen=True)
class KernelFunctionPlan:
    role: str
    hint: str
    start: int
    data: bytes
    blocks: tuple[KernelBlockPlan, ...]
    x87_frames: tuple[KernelX87FramePlan, ...]
    x87_commands: tuple[KernelInstructionPlan, ...]
    padding: tuple[tuple[int, int], ...]
    loops: tuple[KernelLoopPlan, ...]
    frame_required: bool
    frame_push_rva: int
    frame_setup_rva: int
    frame_teardown_rvas: tuple[int, ...]
    return_rvas: tuple[int, ...]

    @property
    def end(self) -> int:
        return self.start + len(self.data)

    def payload(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "lookup_hint": self.hint,
            "rva_start": self.start,
            "rva_end": self.end,
            "size": len(self.data),
            "sha256": sha256_bytes(self.data),
            "blocks": [block.payload() for block in self.blocks],
            "x87_frames": [frame.payload() for frame in self.x87_frames],
            "x87_commands": [command.payload() for command in self.x87_commands],
            "padding": [
                {"rva_start": start, "rva_end": end}
                for start, end in self.padding
            ],
            "loops": [loop.payload() for loop in self.loops],
            "frame": {
                "required": self.frame_required,
                "push_rva": self.frame_push_rva,
                "setup_rva": self.frame_setup_rva,
                "teardown_rvas": list(self.frame_teardown_rvas),
                "return_rvas": list(self.return_rvas),
            },
        }


@dataclass(frozen=True)
class InterpreterKernelPlan:
    candidate_bytes: bytes
    program_manifest_bytes: bytes
    engine_layout_bytes: bytes
    engine_layout_range: ExactRange
    compiled_program_ranges: tuple[ExactRange, ...]
    program_transfer_count: int
    functions: tuple[KernelFunctionPlan, ...]
    unbound_executable_ranges: tuple[tuple[int, int], ...]
    issues: tuple[KernelIssue, ...]
    native_build_manifest_sha256: str

    @property
    def compiled_program_bytes(self) -> bytes:
        return b"".join(item.data for item in self.compiled_program_ranges)

    @property
    def obligations(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for function_index, function in enumerate(self.functions):
            for block_index, block in enumerate(function.blocks):
                rows.append(
                    {
                        "id": (
                            f"kernel-block-sound:{function_index:04d}:"
                            f"{block_index:04d}"
                        ),
                        "family": "native_symbolic_execution_soundness",
                        "function_role": function.role,
                        "rva_start": block.entry_rva,
                        "rva_end": (
                            block.instructions[-1].rva
                            + len(block.instructions[-1].data)
                        ),
                        "status": "pending_lean_theorem",
                    }
                )
                for instruction in block.instructions:
                    rows.append(
                        {
                            "id": f"kernel-instruction:{instruction.rva:08x}",
                            "family": "exact_decoded_instruction_semantics",
                            "function_role": function.role,
                            "rva_start": instruction.rva,
                            "rva_end": instruction.rva + len(instruction.data),
                            "status": "pending_lean_check",
                        }
                    )
            for frame_index, frame in enumerate(function.x87_frames):
                rows.append(
                    {
                        "id": (
                            f"kernel-x87-frame:{function_index:04d}:"
                            f"{frame_index:04d}"
                        ),
                        "family": "exact_x87_frame_protocol_semantics",
                        "function_role": function.role,
                        "rva_start": frame.rva,
                        "rva_end": frame.successor,
                        "status": "pending_lean_check",
                    }
                )
            for command_index, command in enumerate(function.x87_commands):
                rows.append(
                    {
                        "id": (
                            f"kernel-x87-command:{function_index:04d}:"
                            f"{command_index:04d}"
                        ),
                        "family": "exact_x87_command_semantics",
                        "function_role": function.role,
                        "rva_start": command.rva,
                        "rva_end": command.rva + len(command.data),
                        "status": "pending_lean_check",
                    }
                )
            for loop_index, loop in enumerate(function.loops):
                rows.append(
                    {
                        "id": f"kernel-loop:{function_index:02d}:{loop_index:04d}",
                        "family": "native_loop_invariant",
                        "function_role": function.role,
                        "rva_start": loop.header_rva,
                        "rva_end": loop.latch_rva,
                        "status": "pending_lean_proof",
                    }
                )
            rows.append(
                {
                    "id": f"kernel-function:{function_index:02d}",
                    "family": "exact_native_function_cfg",
                    "function_role": function.role,
                    "rva_start": function.start,
                    "rva_end": function.end,
                    "status": "pending_lean_check",
                }
            )
        rows.extend(
            {
                "id": f"kernel-operation:{role}",
                "family": "compiled_kernel_operation_refinement",
                "function_role": role,
                "status": "pending_lean_theorem",
            }
            for _, role in _FUNCTION_ROLES
        )
        rows.extend(
            {
                "id": f"kernel-frontier:{index:04d}",
                "family": "frontier_resolution",
                "status": "blocked",
                "issue": issue.payload(),
            }
            for index, issue in enumerate(self.issues)
        )
        return rows

    def payload(self) -> dict[str, Any]:
        core: dict[str, Any] = {
            "format": INTERPRETER_KERNEL_PLAN_FORMAT,
            "status": "incomplete",
            "acceptance_authority": False,
            "compiler_profile": {
                "id": "o0-no-inline-frame-pointer-v1",
                "required_flags": sorted(_REQUIRED_FLAGS),
                "semantic_authority": False,
                "native_build_manifest_sha256": self.native_build_manifest_sha256,
            },
            "candidate": {
                "pe_sha256": sha256_bytes(self.candidate_bytes),
                "size": len(self.candidate_bytes),
            },
            "program": {
                "manifest_sha256": sha256_bytes(self.program_manifest_bytes),
                "compiled_ranges_sha256": sha256_bytes(self.compiled_program_bytes),
                "compiled_ranges": [
                    item.payload() for item in self.compiled_program_ranges
                ],
                "transfer_count": self.program_transfer_count,
            },
            "engine_layout": {
                "artifact_sha256": sha256_bytes(self.engine_layout_bytes),
                "compiled_range": self.engine_layout_range.payload(),
            },
            "kernel_functions": [item.payload() for item in self.functions],
            "kernel_binding_scope": {
                "classification": (
                    "rooted-kernel-closure-byte-bound"
                    if not self.unbound_executable_ranges
                    else "partial-rooted-kernel-closure-byte-bound"
                ),
                "function_ranges": len(self.functions),
                "classified_function_bytes": sum(
                    len(item.data) for item in self.functions
                ),
                "unbound_executable_ranges": [
                    {"rva_start": start, "rva_end": end, "size": end - start}
                    for start, end in self.unbound_executable_ranges
                ],
                "semantic_authority": False,
                "structural_certificate_ready": not self.issues,
                "required_operation_roles": [role for _, role in _FUNCTION_ROLES],
                "operation_refinement_authority": "lean-theorem-only",
            },
            "issues": [item.payload() for item in self.issues],
            "proof_obligations": self.obligations,
        }
        encoded = json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        return {**core, "artifact_sha256": hashlib.sha256(encoded).hexdigest()}


@dataclass(frozen=True)
class _FunctionHint:
    name: str
    aliases: tuple[str, ...]
    start: int
    end: int
    end_authoritative: bool


def build_relational_interpreter_kernel_plan(
    *,
    candidate_pe: Path | str,
    linker_map: Path | str,
    interpreter_program_manifest: Path | str,
    engine_layout: Path | str,
    native_build_manifest: Path | str,
) -> InterpreterKernelPlan:
    candidate_path = _file(candidate_pe, "candidate PE")
    map_path = _file(linker_map, "linker map")
    program_path = _file(interpreter_program_manifest, "interpreter program manifest")
    layout_path = _file(engine_layout, "engine layout")
    build_path = _file(native_build_manifest, "native build manifest")

    build = _json_object(build_path, "native build manifest")
    _validate_proof_profile(build)
    program = _json_object(program_path, "interpreter program manifest")
    transfers = _program_transfers(program)
    layout_bytes = layout_path.read_bytes()
    try:
        parse_stage_b_engine_layout_payload(
            layout_bytes, expected_x87_slot_count=8
        )
    except EngineLayoutFormatError as exc:
        raise RelationalInterpreterKernelGenerationError(
            f"engine layout cannot support the checked x87 frame protocol: {exc}"
        ) from exc
    candidate_bytes = candidate_path.read_bytes()

    binary = _parse_stage_a_pe(candidate_path)
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise RelationalInterpreterKernelGenerationError(
                "interpreter kernel candidate must be i386 PE32"
            )
        if sha256_file(candidate_path) != _manifest_output_digest(build, "candidate"):
            raise RelationalInterpreterKernelGenerationError(
                "native build manifest binds a different candidate PE"
            )
        symbols = _load_symbols(map_path, binary)
        map_function_hints = _load_function_hints(map_path, binary)
        function_hints = (
            *map_function_hints,
            *_direct_call_target_hints(binary, map_function_hints),
        )
        layout_rva = _locate_unique_immutable(binary, layout_bytes, "engine layout")
        program_ranges = _bind_compiled_program(binary, symbols, transfers)
        functions: list[KernelFunctionPlan] = []
        issues: list[KernelIssue] = []
        required_by_start: dict[int, str] = {}
        for symbol, role in _FUNCTION_ROLES:
            required_by_start[_unique_function_hint(function_hints, symbol).start] = role
        unique_hints = {
            (hint.start, hint.end): hint for hint in function_hints
        }
        hints_by_start: dict[int, _FunctionHint] = {}
        for hint in sorted(unique_hints.values(), key=lambda item: (item.start, item.end)):
            prior = hints_by_start.get(hint.start)
            if prior is not None and prior.end != hint.end:
                raise RelationalInterpreterKernelGenerationError(
                    f"ambiguous linker-map ranges begin at RVA 0x{hint.start:x}"
                )
            hints_by_start[hint.start] = hint

        # Only the decoded transitive closure of the four fixed kernel exports
        # belongs in this reusable proof.  Pulling every CRT/linker-map symbol
        # into the kernel graph made unrelated x87 and startup code appear as
        # kernel proof obligations and invalidated the cache on irrelevant
        # changes.
        pending = sorted(required_by_start)
        analyzed: dict[int, KernelFunctionPlan] = {}
        while pending:
            start = pending.pop(0)
            if start in analyzed:
                continue
            hint = hints_by_start.get(start)
            if hint is None:
                issues.append(KernelIssue(
                    "unbound_direct_kernel_target",
                    f"reachable kernel target RVA 0x{start:x} has no unique map range",
                    start,
                    start + 1,
                ))
                continue
            role = required_by_start.get(start, f"helper {start}")
            function, function_issues = _analyze_function(binary, hint, role)
            analyzed[start] = function
            issues.extend(function_issues)
            for block in function.blocks:
                for target in block.successors:
                    if function.start <= target < function.end:
                        continue
                    if target in hints_by_start and target not in analyzed:
                        pending.append(target)
            pending.sort()
        functions.extend(analyzed.values())
        functions.sort(key=lambda item: (item.start, item.end))
        direct_target_issues = _unbound_direct_target_issues(binary, functions)
        issues.extend(direct_target_issues)
        unbound_ranges = sorted({
            (issue.rva_start, issue.rva_end)
            for issue in direct_target_issues
            if issue.rva_start is not None and issue.rva_end is not None
        })
        return InterpreterKernelPlan(
            candidate_bytes=candidate_bytes,
            program_manifest_bytes=program_path.read_bytes(),
            engine_layout_bytes=layout_bytes,
            engine_layout_range=ExactRange("engine_layout", layout_rva, layout_bytes),
            compiled_program_ranges=tuple(program_ranges),
            program_transfer_count=len(transfers),
            functions=tuple(functions),
            unbound_executable_ranges=tuple(unbound_ranges),
            issues=tuple(_deduplicate_issues(issues)),
            native_build_manifest_sha256=sha256_file(build_path),
        )
    finally:
        binary.pe.close()


def relational_interpreter_kernel_source(
    plan: InterpreterKernelPlan,
    *,
    candidate_data_module: str | None = None,
    candidate_data_namespace: str | None = None,
    candidate_bytes_symbol: str | None = None,
    candidate_pe_symbol: str | None = None,
    program_manifest_data: ExternalArtifactBytesBinding | None = None,
    compiled_program_data: ExternalArtifactBytesBinding | None = None,
    engine_layout_data: ExternalArtifactBytesBinding | None = None,
) -> str:
    """Render checked kernel goals with optional external exact-byte bindings.

    The four ``candidate_*`` names are an all-or-none binding.  Their imported
    values remain proof inputs: the structural goal checks that the supplied
    PE is exactly the parse result of the supplied byte tree.  Artifact byte
    bindings only replace large literals; SHA-256 and mapped-range equality
    remain obligations of ``KernelArtifactBinding.checked`` in Lean.
    """
    external_candidate_data = _external_candidate_data_binding(
        candidate_data_module=candidate_data_module,
        candidate_data_namespace=candidate_data_namespace,
        candidate_bytes_symbol=candidate_bytes_symbol,
        candidate_pe_symbol=candidate_pe_symbol,
    )
    function_definitions, function_names = _lean_function_definitions(plan.functions)
    functions = ",\n  ".join(function_names)
    ranges = ",\n  ".join(_lean_exact_range(item) for item in plan.compiled_program_ranges)
    external_artifacts = (
        ("program_manifest_data", program_manifest_data),
        ("compiled_program_data", compiled_program_data),
        ("engine_layout_data", engine_layout_data),
    )
    for label, binding in external_artifacts:
        if binding is not None and not isinstance(
            binding, ExternalArtifactBytesBinding
        ):
            raise RelationalInterpreterKernelGenerationError(
                f"{label} must be an ExternalArtifactBytesBinding"
            )
    import_modules = ["StageA.RelationalInterpreterKernel"]
    if external_candidate_data is None:
        candidate_definitions = _lean_byte_tree_definitions(
            "generatedKernelCandidateBytes", plan.candidate_bytes
        )
        structural_goal = """exists pe imports,
    parsePE32Tree generatedKernelCandidateBytes = some pe /\\
    parseImports pe = some imports /\\
    generatedKernelArtifactBinding.checked pe = true /\\
    generatedCompiledKernelProgram.checked pe imports = true"""
    else:
        data_module, data_namespace, bytes_symbol, pe_symbol = external_candidate_data
        import_modules.append(data_module)
        candidate_definitions = f"""def generatedKernelCandidateBytes : ByteTree :=
  {data_namespace}.{bytes_symbol}

def generatedKernelCandidatePe : PE32 :=
  {data_namespace}.{pe_symbol}"""
        structural_goal = """parsePE32Tree generatedKernelCandidateBytes =
      some generatedKernelCandidatePe /\\
    exists imports,
      parseImports generatedKernelCandidatePe = some imports /\\
      generatedKernelArtifactBinding.checked generatedKernelCandidatePe = true /\\
      generatedCompiledKernelProgram.checked generatedKernelCandidatePe imports = true"""
    for _, binding in external_artifacts:
        if binding is not None:
            import_modules.append(binding.module)
    imports = "\n".join(
        f"import {module}" for module in dict.fromkeys(import_modules)
    )

    def artifact_bytes_definition(
        name: str, data: bytes, binding: ExternalArtifactBytesBinding | None
    ) -> str:
        value = _lean_bytes(data) if binding is None else binding.qualified_bytes_name
        return f"def {name} : Bytes :=\n  {value}"

    artifact_definitions = "\n\n".join(
        (
            artifact_bytes_definition(
                "generatedKernelProgramManifestBytes",
                plan.program_manifest_bytes,
                program_manifest_data,
            ),
            artifact_bytes_definition(
                "generatedKernelCompiledProgramBytes",
                plan.compiled_program_bytes,
                compiled_program_data,
            ),
            artifact_bytes_definition(
                "generatedKernelEngineLayoutBytes",
                plan.engine_layout_bytes,
                engine_layout_data,
            ),
        )
    )
    return f"""{imports}

namespace StageA.GeneratedRelational.InterpreterKernel

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

{candidate_definitions}

{artifact_definitions}

def generatedKernelCompiledProgramRanges : List ImmutableArtifactRange := [
  {ranges}
]

def generatedKernelEngineLayoutRange : ImmutableArtifactRange :=
  {_lean_exact_range(plan.engine_layout_range)}

def generatedKernelArtifactBinding : KernelArtifactBinding := {{
  compilerProfile := .o0NoInlineFramePointer
  candidatePeBytes := generatedKernelCandidateBytes
  candidatePeSha256 := {_lean_string(sha256_bytes(plan.candidate_bytes))}
  programManifestBytes := generatedKernelProgramManifestBytes
  programManifestSha256 := {_lean_string(sha256_bytes(plan.program_manifest_bytes))}
  compiledProgramBytes := generatedKernelCompiledProgramBytes
  compiledProgramSha256 := {_lean_string(sha256_bytes(plan.compiled_program_bytes))}
  compiledProgramRanges := generatedKernelCompiledProgramRanges
  engineLayoutBytes := generatedKernelEngineLayoutBytes
  engineLayoutSha256 := {_lean_string(sha256_bytes(plan.engine_layout_bytes))}
  engineLayoutRange := generatedKernelEngineLayoutRange
}}

{function_definitions}

def generatedKernelFunctions : List KernelFunction := [
  {functions}
]

def generatedCompiledKernelProgram : CompiledKernelProgram := {{
  functions := generatedKernelFunctions
}}

/-- This is a proof goal, not a generated theorem.  It re-parses the exact PE,
derives imports from it, and asks the reviewed decoder/semantics to qualify all
proposed function bytes. -/
def GeneratedInterpreterKernelStructuralGoal : Prop :=
  {structural_goal}

/-- Successful decoding is not a local semantic proof.  This separate target
requires every submitted symbolic block summary to agree with exact concrete
PE stepping for every machine state. -/
def GeneratedKernelBlockSoundnessGoal (pe : PE32)
    (imports : List PEImport) : Prop :=
  forall function, List.Mem function generatedKernelFunctions ->
    forall block, List.Mem block function.blocks ->
      block.SymbolicExecutionSound pe imports

/-- Final semantic handoff.  It is parameterized rather than existential, so
an empty ABI relation cannot satisfy the generated target vacuously.  The four
operation refinements must be actual Lean theorems. -/
def GeneratedCompiledKernelRefinementGoal
    (pe : PE32) (imports : List PEImport)
    (nativeEnvironment : NativeEnvironment) (abi : KernelABIRelation) : Prop :=
  CompiledKernelRefinement generatedKernelArtifactBinding
    generatedCompiledKernelProgram pe imports nativeEnvironment abi

end StageA.GeneratedRelational.InterpreterKernel
"""


def write_relational_interpreter_kernel_bundle(
    *,
    out: Path | str,
    candidate_data_module: str | None = None,
    candidate_data_namespace: str | None = None,
    candidate_bytes_symbol: str | None = None,
    candidate_pe_symbol: str | None = None,
    program_manifest_data: ExternalArtifactBytesBinding | None = None,
    compiled_program_data: ExternalArtifactBytesBinding | None = None,
    engine_layout_data: ExternalArtifactBytesBinding | None = None,
    externalize_artifacts: bool = False,
    artifact_pack_size: int = DEFAULT_ARTIFACT_BYTE_PACK_SIZE,
    **kwargs: Any,
) -> InterpreterKernelPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_plan(**kwargs)
    explicit_bindings = (
        program_manifest_data,
        compiled_program_data,
        engine_layout_data,
    )
    if externalize_artifacts and any(binding is not None for binding in explicit_bindings):
        raise RelationalInterpreterKernelGenerationError(
            "automatic artifact externalization cannot be combined with explicit "
            "artifact byte bindings"
        )
    if externalize_artifacts:
        artifact_root = output / "exact-artifacts"
        artifact_root.mkdir(exist_ok=True)
        artifacts = (
            (
                "program-manifest.bin",
                plan.program_manifest_bytes,
                "GeneratedKernelProgramManifest",
                "generatedKernelProgramManifestArtifact",
                "generatedKernelProgramManifestBytes",
            ),
            (
                "compiled-program.bin",
                plan.compiled_program_bytes,
                "GeneratedKernelCompiledProgram",
                "generatedKernelCompiledProgramArtifact",
                "generatedKernelCompiledProgramBytes",
            ),
            (
                "engine-layout.bin",
                plan.engine_layout_bytes,
                "GeneratedKernelEngineLayout",
                "generatedKernelEngineLayoutArtifact",
                "generatedKernelEngineLayoutBytes",
            ),
        )
        bindings: list[ExternalArtifactBytesBinding] = []
        inventories: list[dict[str, Any]] = []
        for filename, data, prefix, aggregate_value, aggregate_bytes in artifacts:
            artifact = artifact_root / filename
            artifact.write_bytes(data)
            inventory = generate_artifact_byte_pack_bundle(
                artifact_path=artifact,
                out_dir=output,
                module_prefix=prefix,
                namespace=(
                    "StageA.GeneratedRelational.InterpreterKernelArtifacts"
                ),
                pack_size=artifact_pack_size,
                chunk_size=min(1024, artifact_pack_size),
                standalone=False,
                aggregate_value_name=aggregate_value,
                aggregate_bytes_name=aggregate_bytes,
                inventory_filename=f"{prefix}-artifact-byte-packs.json",
            )
            bindings.append(inventory.binding)
            inventories.append(inventory.payload())
        program_manifest_data, compiled_program_data, engine_layout_data = bindings
        write_json(
            output / "artifact-byte-pack-inventories.json",
            {
                "format": "stage-a-relational-interpreter-kernel-artifacts-v1",
                "artifacts": inventories,
            },
        )
    write_json(output / INTERPRETER_KERNEL_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_source(
            plan,
            candidate_data_module=candidate_data_module,
            candidate_data_namespace=candidate_data_namespace,
            candidate_bytes_symbol=candidate_bytes_symbol,
            candidate_pe_symbol=candidate_pe_symbol,
            program_manifest_data=program_manifest_data,
            compiled_program_data=compiled_program_data,
            engine_layout_data=engine_layout_data,
        ),
        encoding="utf-8",
    )
    return plan


def _external_candidate_data_binding(
    *,
    candidate_data_module: str | None,
    candidate_data_namespace: str | None,
    candidate_bytes_symbol: str | None,
    candidate_pe_symbol: str | None,
) -> tuple[str, str, str, str] | None:
    values = (
        candidate_data_module,
        candidate_data_namespace,
        candidate_bytes_symbol,
        candidate_pe_symbol,
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise RelationalInterpreterKernelGenerationError(
            "external candidate data requires module, namespace, bytes symbol, "
            "and PE symbol"
        )
    assert candidate_data_module is not None
    assert candidate_data_namespace is not None
    assert candidate_bytes_symbol is not None
    assert candidate_pe_symbol is not None
    if _STAGE_A_LEAN_MODULE.fullmatch(candidate_data_module) is None:
        raise RelationalInterpreterKernelGenerationError(
            "candidate_data_module must be a qualified StageA Lean module"
        )
    if _LEAN_NAMESPACE.fullmatch(candidate_data_namespace) is None:
        raise RelationalInterpreterKernelGenerationError(
            "candidate_data_namespace must be a canonical Lean namespace"
        )
    for name, value in (
        ("candidate_bytes_symbol", candidate_bytes_symbol),
        ("candidate_pe_symbol", candidate_pe_symbol),
    ):
        if _LEAN_LOCAL_IDENTIFIER.fullmatch(value) is None:
            raise RelationalInterpreterKernelGenerationError(
                f"{name} must be a local Lean identifier"
            )
    return (
        candidate_data_module,
        candidate_data_namespace,
        candidate_bytes_symbol,
        candidate_pe_symbol,
    )


def _validate_proof_profile(manifest: Mapping[str, Any]) -> None:
    if manifest.get("format") != INTERPRETER_NATIVE_BUILD_FORMAT:
        raise RelationalInterpreterKernelGenerationError(
            "unsupported native build manifest format"
        )
    if manifest.get("status") != "candidate-generated":
        raise RelationalInterpreterKernelGenerationError(
            "native build manifest does not describe a generated candidate"
        )
    commands = _mapping(manifest.get("commands"), "native build commands")
    if commands.get("compile_flags_policy") != _PROOF_COMPILE_POLICY:
        raise RelationalInterpreterKernelGenerationError(
            "native candidate was not built with the proof compiler profile"
        )
    objects = manifest.get("objects")
    if not isinstance(objects, list) or not objects:
        raise RelationalInterpreterKernelGenerationError(
            "native build manifest has no object inventory"
        )
    for index, value in enumerate(objects):
        row = _mapping(value, f"native object {index}")
        flags = row.get("flags")
        if not isinstance(flags, list) or any(not isinstance(item, str) for item in flags):
            raise RelationalInterpreterKernelGenerationError(
                f"native object {index} has malformed compiler flags"
            )
        flag_set = set(flags)
        if not _REQUIRED_FLAGS <= flag_set or any(
            _FORBIDDEN_OPTIMIZATION.fullmatch(flag) for flag in flags
        ):
            raise RelationalInterpreterKernelGenerationError(
                f"native object {index} violates the proof compiler profile"
            )


def _manifest_output_digest(manifest: Mapping[str, Any], name: str) -> str:
    outputs = _mapping(manifest.get("outputs"), "native build outputs")
    row = _mapping(outputs.get(name), f"native build output {name}")
    return _digest(row.get("sha256"), f"native build output {name} SHA-256")


def _program_transfers(program: Mapping[str, Any]) -> tuple[dict[str, int], ...]:
    if program.get("format") != STAGE_B_INTERPRETER_PROGRAM_FORMAT:
        raise RelationalInterpreterKernelGenerationError(
            "unsupported interpreter program manifest format"
        )
    raw = program.get("transfers")
    if not isinstance(raw, list) or not raw:
        raise RelationalInterpreterKernelGenerationError(
            "interpreter program manifest has no transfers"
        )
    result: list[dict[str, int]] = []
    seen_rvas: set[int] = set()
    for index, value in enumerate(raw):
        row = _mapping(value, f"program transfer {index}")
        counts = _mapping(row.get("counts"), f"program transfer {index} counts")
        parsed = {
            "rva": _u32(row.get("rva_start"), "program transfer RVA"),
            "word": _count(counts.get("word_nodes"), "word node count", 1024),
            "x87": _count(counts.get("x87_nodes"), "x87 node count", 256),
            "action": _count(counts.get("actions"), "action count", 8192),
            "call": _count(counts.get("calls"), "call count", 1024),
            "replay": _count(counts.get("x87_replays", 0), "x87 replay count", 1024),
        }
        if parsed["rva"] in seen_rvas:
            raise RelationalInterpreterKernelGenerationError(
                "interpreter program has duplicate source RVAs"
            )
        seen_rvas.add(parsed["rva"])
        result.append(parsed)
    if [item["rva"] for item in result] != sorted(item["rva"] for item in result):
        raise RelationalInterpreterKernelGenerationError(
            "interpreter program transfer order is not canonical"
        )
    return tuple(result)


def _bind_compiled_program(
    binary: StageABinary,
    symbols: Mapping[str, tuple[int, ...]],
    transfers: Sequence[Mapping[str, int]],
) -> list[ExactRange]:
    table_rva = _unique_symbol(symbols, "stage_b_program_transfers")
    count_rva = _unique_symbol(symbols, "stage_b_program_transfer_count")
    count = _read_immutable(binary, count_rva, 4, "program transfer count")
    if struct.unpack("<I", count)[0] != len(transfers):
        raise RelationalInterpreterKernelGenerationError(
            "compiled transfer count differs from the program manifest"
        )
    table = _read_immutable(
        binary, table_rva, len(transfers) * _TRANSFER_RECORD_SIZE,
        "program transfer table",
    )
    ranges = [ExactRange("program_transfer_count", count_rva, count)]
    ranges.append(ExactRange("program_transfer_table", table_rva, table))
    occupied: list[tuple[int, int, str]] = [
        (count_rva, count_rva + 4, "program_transfer_count"),
        (table_rva, table_rva + len(table), "program_transfer_table"),
    ]
    for index, expected in enumerate(transfers):
        record = table[index * _TRANSFER_RECORD_SIZE : (index + 1) * _TRANSFER_RECORD_SIZE]
        fields = struct.unpack("<10I", record)
        source, word, x87, action, replay = fields[:5]
        if (source, word, x87, action, replay) != (
            expected["rva"], expected["word"], expected["x87"],
            expected["action"], expected["replay"],
        ):
            raise RelationalInterpreterKernelGenerationError(
                f"compiled transfer descriptor {index} differs from its manifest"
            )
        specs = (
            ("word_nodes", fields[5], max(word, 1) * _WORD_NODE_SIZE),
            ("x87_nodes", fields[6], max(x87, 1) * _X87_NODE_SIZE),
            ("actions", fields[7], action * _ACTION_SIZE),
            ("calls", fields[8], max(expected["call"], 1) * _CALL_SIZE),
            ("x87_replays", fields[9], max(replay, 1) * _X87_REPLAY_SIZE),
        )
        bound_by_role: dict[str, tuple[int, bytes]] = {}
        for role, pointer, size in specs:
            if size <= 0:
                raise RelationalInterpreterKernelGenerationError(
                    f"compiled transfer {index} has empty {role} data"
                )
            rva = _pointer_rva(binary, pointer, f"transfer {index} {role}")
            data = _read_immutable(binary, rva, size, f"transfer {index} {role}")
            ranges.append(ExactRange(f"transfer_{index:06d}_{role}", rva, data))
            occupied.append((rva, rva + size, f"transfer {index} {role}"))
            bound_by_role[role] = (rva, data)
        calls_rva, calls_data = bound_by_role["calls"]
        for call_index in range(expected["call"]):
            call = calls_data[call_index * _CALL_SIZE : (call_index + 1) * _CALL_SIZE]
            fields = struct.unpack("<16I", call)
            argument_count = _count(fields[13], "compiled call argument count", 64)
            stack_count = _count(fields[15], "compiled call stack count", 64)
            nested = (
                ("register_nodes", fields[10], 8 * 4),
                ("flag_nodes", fields[11], 6 * 4),
                ("argument_nodes", fields[12], max(argument_count, 1) * 4),
                ("stack_inputs", fields[14], max(stack_count, 1) * 12),
            )
            for nested_role, pointer, size in nested:
                rva = _pointer_rva(
                    binary, pointer,
                    f"transfer {index} call {call_index} {nested_role}",
                )
                data = _read_immutable(
                    binary, rva, size,
                    f"transfer {index} call {call_index} {nested_role}",
                )
                ranges.append(ExactRange(
                    f"transfer_{index:06d}_call_{call_index:04d}_{nested_role}",
                    rva, data,
                ))
            for nested_role, pointer in (("dll", fields[6]), ("symbol", fields[7])):
                if pointer == 0:
                    continue
                rva = _pointer_rva(
                    binary, pointer,
                    f"transfer {index} call {call_index} {nested_role}",
                )
                data = _read_c_string(
                    binary, rva,
                    f"transfer {index} call {call_index} {nested_role}",
                )
                ranges.append(ExactRange(
                    f"transfer_{index:06d}_call_{call_index:04d}_{nested_role}",
                    rva, data,
                ))
        replay_rva, replay_data = bound_by_role["x87_replays"]
        for replay_index in range(expected["replay"]):
            replay = replay_data[
                replay_index * _X87_REPLAY_SIZE : (replay_index + 1) * _X87_REPLAY_SIZE
            ]
            fields = struct.unpack("<11I", replay)
            byte_count = _count(fields[4], "compiled x87 replay byte count", 15)
            instruction_rva = _pointer_rva(
                binary, fields[5],
                f"transfer {index} x87 replay {replay_index} instruction bytes",
            )
            instruction_bytes = _read_immutable(
                binary, instruction_rva, byte_count,
                f"transfer {index} x87 replay {replay_index} instruction bytes",
            )
            ranges.append(ExactRange(
                f"transfer_{index:06d}_x87_replay_{replay_index:04d}_bytes",
                instruction_rva, instruction_bytes,
            ))
            string_roles = (
                "instruction_sha256", "transfer_sha256", "contract_sha256",
                "checked_decoder", "checked_executor",
            )
            for string_role, pointer in zip(string_roles, fields[6:], strict=True):
                rva = _pointer_rva(
                    binary, pointer,
                    f"transfer {index} x87 replay {replay_index} {string_role}",
                )
                data = _read_c_string(
                    binary, rva,
                    f"transfer {index} x87 replay {replay_index} {string_role}",
                )
                ranges.append(ExactRange(
                    f"transfer_{index:06d}_x87_replay_{replay_index:04d}_{string_role}",
                    rva, data,
                ))
    _reject_overlaps(occupied)
    return ranges


def _kernel_x87_frame_plan(
    instruction: Any, rva: int
) -> KernelX87FramePlan | None:
    """Recognize only the reviewed 32-bit FNSAVE/FRSTOR frame protocol.

    Capstone is a proposal mechanism here.  Lean independently re-decodes the
    exact PE bytes and checks the same operation and effective-address form.
    Prefixes and segment overrides are rejected so 16-bit environment images
    and alternate address spaces cannot be confused with the 108-byte frame.
    """

    operation = {
        x86_const.X86_INS_FNSAVE: "fnsave",
        x86_const.X86_INS_FRSTOR: "frstor",
    }.get(instruction.id)
    if operation is None or not is_reviewed_x87_frame_instruction(instruction):
        return None
    data = bytes(instruction.bytes)
    operands = instruction.operands
    memory = operands[0].mem
    return KernelX87FramePlan(
        rva=rva,
        data=data,
        operation=operation,
        base_register=(
            None
            if memory.base == x86_const.X86_REG_INVALID
            else instruction.reg_name(memory.base).lower()
        ),
        index_register=(
            None
            if memory.index == x86_const.X86_REG_INVALID
            else instruction.reg_name(memory.index).lower()
        ),
        scale=int(memory.scale),
        displacement=int(memory.disp),
    )


def _analyze_function(
    binary: StageABinary, hint: _FunctionHint, role: str
) -> tuple[KernelFunctionPlan, list[KernelIssue]]:
    data = _read_executable(binary, hint.start, hint.end, role)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    pending = [hint.start]
    decoded: dict[int, Any] = {}
    successors: dict[int, tuple[int, ...]] = {}
    x87_frames: dict[int, KernelX87FramePlan] = {}
    x87_commands: dict[int, KernelInstructionPlan] = {}
    issues: list[KernelIssue] = []
    while pending:
        cursor = pending.pop()
        while hint.start <= cursor < hint.end:
            if cursor in decoded:
                break
            raw = binary.pe.get_data(cursor, min(15, hint.end - cursor))
            rows = list(decoder.disasm(raw, binary.image_base + cursor, count=1))
            if not rows:
                issues.append(KernelIssue(
                    "kernel_decode_failure", f"{role} does not decode at RVA 0x{cursor:x}",
                    cursor, cursor + 1, role,
                ))
                break
            instruction = rows[0]
            rva = int(instruction.address) - binary.image_base
            end = rva + int(instruction.size)
            if rva != cursor or end > hint.end:
                issues.append(KernelIssue(
                    "kernel_decode_crosses_range", f"{role} decode crosses its map hint",
                    cursor, min(end, hint.end), role,
                ))
                break
            decoded[rva] = instruction
            if instruction.group(capstone.x86.X86_GRP_FPU):
                frame = _kernel_x87_frame_plan(instruction, rva)
                if frame is None:
                    x87_commands[rva] = KernelInstructionPlan(
                        rva, bytes(instruction.bytes), instruction.mnemonic.lower()
                    )
                else:
                    x87_frames[rva] = frame
            if instruction.group(capstone.x86.X86_GRP_SSE1) or instruction.group(
                capstone.x86.X86_GRP_SSE2
            ):
                issues.append(KernelIssue(
                    "unsupported_kernel_simd", f"{role} uses SIMD instruction {instruction.mnemonic}",
                    rva, end, role,
                ))
            mnemonic = instruction.mnemonic.lower()
            if mnemonic in {"int", "int1", "int3", "into", "syscall", "sysenter", "iret", "iretd"}:
                issues.append(KernelIssue(
                    "unsupported_native_escape", f"{role} uses native escape {mnemonic}",
                    rva, end, role,
                ))
            next_rva = end
            if instruction.group(capstone.CS_GRP_RET):
                edge = ()
                successors[rva] = edge
                break
            if instruction.group(capstone.CS_GRP_CALL):
                target = _direct_target(binary, instruction)
                if target is None:
                    # The dynamic callee remains a fail-closed callback-target
                    # frontier, but the architectural return continuation is
                    # statically decoded and belongs in the local CFG.
                    successors[rva] = (next_rva,)
                    issues.append(KernelIssue(
                        "unsupported_indirect_kernel_call",
                        f"{role} has indirect call requiring a checked target classifier",
                        rva, end, role,
                    ))
                else:
                    successors[rva] = (target, next_rva)
                if next_rva < hint.end:
                    pending.append(next_rva)
                break
            if instruction.group(capstone.CS_GRP_JUMP):
                target = _direct_target(binary, instruction)
                if target is None:
                    successors[rva] = ()
                    issues.append(KernelIssue(
                        "unsupported_indirect_kernel_jump",
                        f"{role} has indirect jump requiring a checked target classifier",
                        rva, end, role,
                    ))
                    break
                conditional = instruction.id != x86_const.X86_INS_JMP
                successors[rva] = (target, next_rva) if conditional else (target,)
                if hint.start <= target < hint.end:
                    pending.append(target)
                if conditional and next_rva < hint.end:
                    pending.append(next_rva)
                break
            successors[rva] = (next_rva,)
            cursor = next_rva
        else:
            issues.append(KernelIssue(
                "kernel_fallthrough", f"{role} falls through its map hint",
                hint.end - 1, hint.end, role,
            ))

    leaders = {hint.start}
    for frame in x87_frames.values():
        if frame.successor < hint.end:
            leaders.add(frame.successor)
    for command in x87_commands.values():
        successor = command.rva + len(command.data)
        if successor < hint.end:
            leaders.add(successor)
    for source, targets in successors.items():
        instruction = decoded[source]
        end = source + int(instruction.size)
        if instruction.group(capstone.CS_GRP_CALL) or instruction.group(capstone.CS_GRP_JUMP):
            leaders.update(target for target in targets if hint.start <= target < hint.end)
            if end < hint.end:
                leaders.add(end)
    blocks: list[KernelBlockPlan] = []
    for leader in sorted(leaders):
        if leader not in decoded or leader in x87_frames or leader in x87_commands:
            continue
        rows: list[KernelInstructionPlan] = []
        cursor = leader
        block_successors: tuple[int, ...] = ()
        while cursor in decoded:
            instruction = decoded[cursor]
            item = KernelInstructionPlan(
                cursor, bytes(instruction.bytes), instruction.mnemonic.lower()
            )
            rows.append(item)
            next_rva = cursor + len(item.data)
            terminal = (
                instruction.group(capstone.CS_GRP_RET)
                or instruction.group(capstone.CS_GRP_CALL)
                or instruction.group(capstone.CS_GRP_JUMP)
                or next_rva in x87_frames
                or next_rva in x87_commands
            )
            if terminal or next_rva in leaders:
                block_successors = successors.get(cursor, (next_rva,))
                break
            cursor = next_rva
        blocks.append(KernelBlockPlan(leader, tuple(rows), block_successors))

    owned = sorted(
        byte
        for instruction in decoded.values()
        for byte in range(
            int(instruction.address) - binary.image_base,
            int(instruction.address) - binary.image_base + int(instruction.size),
        )
    )
    effective_end = hint.end
    if owned:
        reachable_end = min(hint.end, owned[-1] + 1)
        trailing = binary.pe.get_data(reachable_end, hint.end - reachable_end)
        if not hint.end_authoritative or (
            reachable_end < hint.end and _padding_bytes(trailing)
        ):
            # A recovered target has only an upper bound.  An authoritative
            # linker range may likewise include alignment after every
            # entry-reachable path has terminated.  Keep verified alignment
            # outside the semantic function span; global executable coverage
            # still classifies it as padding.  Authoritative non-padding tails
            # remain inside the span and fail below as unclassified code.
            effective_end = reachable_end
    padding: list[tuple[int, int]] = []
    for start, end in _missing_ranges(hint.start, effective_end, owned):
        gap = binary.pe.get_data(start, end - start)
        if _padding_bytes(gap):
            padding.append((start, end))
        else:
            issues.append(KernelIssue(
                "unclassified_kernel_bytes",
                f"{role} has non-padding bytes not reached from its entry",
                start, end, role,
            ))

    block_entries = {block.entry_rva for block in blocks}
    loops: list[KernelLoopPlan] = []
    for block in blocks:
        for target in block.successors:
            if target <= block.entry_rva and target in block_entries:
                body = tuple(
                    entry for entry in sorted(block_entries)
                    if target <= entry <= block.entry_rva
                )
                loops.append(KernelLoopPlan(target, block.entry_rva, body))

    first = blocks[0].instructions if blocks else ()
    frame_push = first[0].rva if len(first) >= 1 else hint.start
    frame_setup = first[1].rva if len(first) >= 2 else hint.start
    returns = tuple(
        item.rva
        for block in blocks
        for item in block.instructions
        if item.mnemonic.startswith("ret")
    )
    frame_required = len(first) >= 2 and first[0].data == b"\x55" and first[1].data in {
        b"\x89\xe5", b"\x8b\xec"
    }
    if role in {value for _, value in _FUNCTION_ROLES} and not frame_required:
        issues.append(KernelIssue(
            "noncanonical_proof_frame",
            f"{role} lacks a canonical EBP prologue under the proof profile",
            hint.start, min(hint.start + 4, hint.end), role,
        ))
    teardowns: list[int] = []
    for return_rva in returns:
        return_block = next(
            (block for block in blocks if any(item.rva == return_rva for item in block.instructions)),
            None,
        )
        teardown = None if return_block is None else next(
            (
                item for item in reversed(return_block.instructions)
                if item.rva < return_rva and item.data in {b"\xc9", b"\x5d"}
            ),
            None,
        )
        teardowns.append(hint.start if teardown is None else teardown.rva)
        if frame_required and teardown is None:
            issues.append(KernelIssue(
                "noncanonical_proof_epilogue",
                f"{role} return at 0x{return_rva:x} is not preceded by leave",
                return_rva, return_rva + 1, role,
            ))
    return (
        KernelFunctionPlan(
            role=role,
            hint=hint.name,
            start=hint.start,
            data=_read_executable(binary, hint.start, effective_end, role),
            blocks=tuple(blocks),
            x87_frames=tuple(x87_frames[rva] for rva in sorted(x87_frames)),
            x87_commands=tuple(x87_commands[rva] for rva in sorted(x87_commands)),
            padding=tuple(padding),
            loops=tuple(loops),
            frame_required=frame_required,
            frame_push_rva=frame_push,
            frame_setup_rva=frame_setup,
            frame_teardown_rvas=tuple(teardowns),
            return_rvas=returns,
        ),
        issues,
    )


def _lean_exact_range(value: ExactRange) -> str:
    return (
        "{ role := " + _lean_string(value.role)
        + f"\n    span := {{ start := {value.start}, size := {len(value.data)} }}"
        + "\n    bytes := " + _lean_bytes(value.data)
        + "\n    sha256 := " + _lean_string(value.sha256) + " }"
    )


def _lean_instruction(value: KernelInstructionPlan) -> str:
    return (
        "{\n          rva := " + str(value.rva)
        + "\n          bytes := " + _lean_bytes(value.data)
        + "\n        }"
    )


def _lean_x87_frame(value: KernelX87FramePlan) -> str:
    operation = "fnSave" if value.operation == "fnsave" else "frStor"
    return (
        "{\n      rva := " + str(value.rva)
        + "\n      bytes := " + _lean_bytes(value.data)
        + "\n      operation := ." + operation
        + "\n    }"
    )


def _lean_x87_command(value: KernelInstructionPlan) -> str:
    return (
        "{\n      rva := " + str(value.rva)
        + "\n      bytes := " + _lean_bytes(value.data)
        + "\n    }"
    )


def _lean_block(value: KernelBlockPlan) -> str:
    instructions = ", ".join(_lean_instruction(item) for item in value.instructions)
    successors = ", ".join(str(item) for item in value.successors)
    return (
        f"{{\n        entryRva := {value.entry_rva}\n"
        f"        instructions := [{instructions}]\n"
        f"        successors := [{successors}]\n      }}"
    )


def _lean_loop(value: KernelLoopPlan) -> str:
    body = ", ".join(str(item) for item in value.body_entries)
    return (
        f"{{\n      headerRva := {value.header_rva}\n"
        f"      latchRva := {value.latch_rva}\n"
        f"      bodyEntries := [{body}]\n    }}"
    )


def _lean_function(
    value: KernelFunctionPlan,
    *,
    blocks: Sequence[str] | None = None,
    loops: Sequence[str] | None = None,
) -> str:
    block_values = (
        list(blocks)
        if blocks is not None
        else [_lean_block(item) for item in value.blocks]
    )
    loop_values = (
        list(loops)
        if loops is not None
        else [_lean_loop(item) for item in value.loops]
    )
    rendered_blocks = ",\n      ".join(block_values)
    rendered_loops = ", ".join(loop_values)
    x87_frames = ", ".join(_lean_x87_frame(item) for item in value.x87_frames)
    x87_commands = ", ".join(
        _lean_x87_command(item) for item in value.x87_commands
    )
    padding = ", ".join(
        f"{{ start := {start}, size := {end - start} }}"
        for start, end in value.padding
    )
    returns = ", ".join(str(item) for item in value.return_rvas)
    teardowns = ", ".join(str(item) for item in value.frame_teardown_rvas)
    return f"""{{
    role := .{value.role}
    hint := {_lean_string(value.hint)}
    span := {{ start := {value.start}, size := {len(value.data)} }}
    bytes := {_lean_bytes(value.data)}
    sha256 := {_lean_string(sha256_bytes(value.data))}
    blocks := [
      {rendered_blocks}
    ]
    x87Frames := [{x87_frames}]
    x87Commands := [{x87_commands}]
    padding := [{padding}]
    loops := [{rendered_loops}]
    frame := {{
      required := {str(value.frame_required).lower()}
      pushRva := {value.frame_push_rva}
      setupRva := {value.frame_setup_rva}
      teardownRvas := [{teardowns}]
      returnRvas := [{returns}]
    }}
  }}"""


def _lean_function_definitions(
    functions: Sequence[KernelFunctionPlan],
) -> tuple[str, list[str]]:
    definitions: list[str] = []
    function_names: list[str] = []
    for function_index, function in enumerate(functions):
        prefix = f"generatedKernelFunction{function_index:04d}"
        block_names: list[str] = []
        for block_index, block in enumerate(function.blocks):
            name = f"{prefix}Block{block_index:04d}"
            definitions.append(f"def {name} : KernelBlock :=\n  {_lean_block(block)}")
            block_names.append(name)
        loop_names: list[str] = []
        for loop_index, loop in enumerate(function.loops):
            name = f"{prefix}Loop{loop_index:04d}"
            definitions.append(f"def {name} : KernelLoop :=\n  {_lean_loop(loop)}")
            loop_names.append(name)
        definitions.append(
            f"def {prefix} : KernelFunction :=\n  "
            + _lean_function(function, blocks=block_names, loops=loop_names)
        )
        function_names.append(prefix)
    return "\n\n".join(definitions), function_names


def _load_function_hints(path: Path, binary: StageABinary) -> tuple[_FunctionHint, ...]:
    result: list[_FunctionHint] = []
    for row in _parse_linker_map_functions(path, binary):
        result.append(
            _FunctionHint(
                name=_string(row.get("name"), "function name"),
                aliases=tuple(str(item) for item in row.get("aliases", [])),
                start=_u32(row.get("rva_start"), "function start"),
                end=_u32(row.get("rva_end"), "function end"),
                end_authoritative=True,
            )
        )
    if not result:
        raise RelationalInterpreterKernelGenerationError(
            "linker map has no executable function hints"
        )
    return tuple(result)


def _direct_call_target_hints(
    binary: StageABinary, map_hints: Sequence[_FunctionHint]
) -> tuple[_FunctionHint, ...]:
    """Propose ranges for reachable static helpers omitted by linker maps.

    Direct call destinations are strong function-entry hints for the fixed O0
    profile.  Capstone remains untrusted: exact bytes, control successors, and
    rooted closure are all rechecked by Lean.
    """

    mapped_starts = {hint.start for hint in map_hints}
    targets: set[int] = set()
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoder.skipdata = True
    executable_bounds: list[tuple[int, int]] = []
    for section in binary.sections:
        if not section.executable or section.raw_size <= 0:
            continue
        start = section.rva_start
        end = start + section.raw_size
        executable_bounds.append((start, end))
        data = bytes(binary.pe.get_data(start, section.raw_size))
        for instruction in decoder.disasm(data, binary.image_base + start):
            if instruction.id == 0 or not instruction.group(capstone.CS_GRP_CALL):
                continue
            target = _direct_target(binary, instruction)
            if target is not None and start <= target < end:
                targets.add(target)

    proposed: list[_FunctionHint] = []
    all_starts = mapped_starts | targets
    for target in sorted(targets - mapped_starts):
        containing = next(
            ((start, end) for start, end in executable_bounds if start <= target < end),
            None,
        )
        if containing is None:
            continue
        section_end = containing[1]
        end = min(
            (value for value in all_starts if target < value <= section_end),
            default=section_end,
        )
        if target < end:
            proposed.append(_FunctionHint(
                name=f"recovered-direct-call-{target:08x}",
                aliases=(),
                start=target,
                end=end,
                end_authoritative=False,
            ))
    return tuple(proposed)


def _unique_function_hint(
    values: Sequence[_FunctionHint], symbol: str
) -> _FunctionHint:
    key = _symbol_key(symbol)
    matches = [
        value for value in values
        if key in {_symbol_key(value.name), *(_symbol_key(item) for item in value.aliases)}
    ]
    unique = {(item.start, item.end): item for item in matches}
    if len(unique) != 1:
        raise RelationalInterpreterKernelGenerationError(
            f"linker map has {len(unique)} ranges for required kernel role {symbol}"
        )
    return next(iter(unique.values()))


def _load_symbols(path: Path, binary: StageABinary) -> dict[str, tuple[int, ...]]:
    result: dict[str, set[int]] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = _GNU_SYMBOL.match(line)
        if match is not None:
            address, name = int(match.group(1), 16), match.group(2)
        else:
            match = _MSVC_SYMBOL.match(line)
            if match is None:
                continue
            name, address = match.group(1), int(match.group(2), 16)
        rva = address - binary.image_base if address >= binary.image_base else address
        if 0 <= rva < binary.size_of_image:
            result.setdefault(_symbol_key(name), set()).add(rva)
    return {key: tuple(sorted(items)) for key, items in result.items()}


def _unique_symbol(symbols: Mapping[str, tuple[int, ...]], name: str) -> int:
    values = symbols.get(_symbol_key(name), ())
    if len(values) != 1:
        raise RelationalInterpreterKernelGenerationError(
            f"linker map has {len(values)} addresses for required data role {name}"
        )
    return values[0]


def _direct_target(binary: StageABinary, instruction: Any) -> int | None:
    operands = instruction.operands
    if len(operands) != 1 or operands[0].type != capstone.x86.X86_OP_IMM:
        return None
    value = int(operands[0].imm) & 0xFFFFFFFF
    return value - binary.image_base if value >= binary.image_base else value


def _locate_unique_immutable(binary: StageABinary, data: bytes, label: str) -> int:
    if not data:
        raise RelationalInterpreterKernelGenerationError(f"{label} is empty")
    matches: list[int] = []
    image = binary.path.read_bytes()
    for section in binary.sections:
        if section.writable or section.executable or section.raw_size < len(data):
            continue
        raw = image[section.raw_pointer : section.raw_pointer + section.raw_size]
        cursor = 0
        while True:
            found = raw.find(data, cursor)
            if found < 0:
                break
            matches.append(section.rva_start + found)
            cursor = found + 1
    if len(matches) != 1:
        raise RelationalInterpreterKernelGenerationError(
            f"candidate has {len(matches)} immutable copies of {label}"
        )
    return matches[0]


def _read_immutable(binary: StageABinary, rva: int, size: int, label: str) -> bytes:
    matches = [
        section for section in binary.sections
        if not section.writable
        and section.rva_start <= rva
        and rva + size <= section.rva_start + section.raw_size
    ]
    if len(matches) != 1 or size <= 0:
        raise RelationalInterpreterKernelGenerationError(
            f"{label} is not in one immutable raw section"
        )
    data = bytes(binary.pe.get_data(rva, size))
    if len(data) != size:
        raise RelationalInterpreterKernelGenerationError(f"{label} is truncated")
    return data


def _read_executable(binary: StageABinary, start: int, end: int, label: str) -> bytes:
    matches = [
        section for section in binary.sections
        if section.executable and section.rva_start <= start
        and end <= section.rva_start + section.raw_size
    ]
    if len(matches) != 1 or end <= start:
        raise RelationalInterpreterKernelGenerationError(
            f"{label} is not in one executable raw section"
        )
    data = bytes(binary.pe.get_data(start, end - start))
    if len(data) != end - start:
        raise RelationalInterpreterKernelGenerationError(f"{label} is truncated")
    return data


def _read_c_string(binary: StageABinary, rva: int, label: str) -> bytes:
    matches = [
        section for section in binary.sections
        if not section.writable and section.rva_start <= rva
        < section.rva_start + section.raw_size
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelGenerationError(
            f"{label} is not in one immutable raw section"
        )
    section = matches[0]
    maximum = min(512, section.rva_start + section.raw_size - rva)
    raw = bytes(binary.pe.get_data(rva, maximum))
    terminal = raw.find(b"\0")
    if terminal < 0:
        raise RelationalInterpreterKernelGenerationError(
            f"{label} is not a bounded C string"
        )
    return raw[: terminal + 1]


def _pointer_rva(binary: StageABinary, value: int, label: str) -> int:
    rva = value - binary.image_base if value >= binary.image_base else value
    if not 0 <= rva < binary.size_of_image:
        raise RelationalInterpreterKernelGenerationError(
            f"{label} pointer is outside the candidate image"
        )
    return rva


def _reject_overlaps(ranges: Sequence[tuple[int, int, str]]) -> None:
    ordered = sorted(ranges)
    for left, right in zip(ordered, ordered[1:]):
        if right[0] < left[1]:
            raise RelationalInterpreterKernelGenerationError(
                f"compiled program ranges overlap: {left[2]} and {right[2]}"
            )


def _missing_ranges(start: int, end: int, occupied: Sequence[int]) -> list[tuple[int, int]]:
    present = set(occupied)
    result: list[tuple[int, int]] = []
    cursor = start
    while cursor < end:
        if cursor in present:
            cursor += 1
            continue
        gap = cursor
        while cursor < end and cursor not in present:
            cursor += 1
        result.append((gap, cursor))
    return result


def _unbound_executable_ranges(
    binary: StageABinary, functions: Sequence[KernelFunctionPlan]
) -> list[tuple[int, int]]:
    if not functions:
        return []
    start = min(item.start for item in functions)
    end = max(item.end for item in functions)
    occupied = [
        byte
        for function in functions
        for byte in range(function.start, function.end)
    ]
    return [
        (gap_start, gap_end)
        for gap_start, gap_end in _missing_ranges(start, end, occupied)
        if not _padding_bytes(binary.pe.get_data(gap_start, gap_end - gap_start))
    ]


def _recovered_gap_hints(
    binary: StageABinary, functions: Sequence[KernelFunctionPlan]
) -> list[_FunctionHint]:
    targets = {
        block.successors[0]
        for function in functions
        for block in function.blocks
        if block.instructions
        and block.successors
        and (
            block.instructions[-1].mnemonic.startswith("call")
            or block.instructions[-1].mnemonic == "jmp"
        )
    }
    result: list[_FunctionHint] = []
    for gap_start, gap_end in _unbound_executable_ranges(binary, functions):
        boundaries = sorted(
            {gap_start, gap_end, *(target for target in targets if gap_start < target < gap_end)}
        )
        for index, (start, end) in enumerate(zip(boundaries, boundaries[1:])):
            data = bytes(binary.pe.get_data(start, end - start))
            if not data or _padding_bytes(data):
                continue
            result.append(_FunctionHint(
                name=f"recovered-executable-range-{start:08x}",
                aliases=(),
                start=start,
                end=end,
                end_authoritative=False,
            ))
    return result


def _unbound_direct_target_issues(
    binary: StageABinary, functions: Sequence[KernelFunctionPlan]
) -> list[KernelIssue]:
    def bound(target: int) -> bool:
        return any(function.start <= target < function.end for function in functions)

    def executable(target: int) -> bool:
        return any(
            section.executable
            and section.rva_start <= target < section.rva_start + section.raw_size
            for section in binary.sections
        )

    issues: list[KernelIssue] = []
    for function in functions:
        for block in function.blocks:
            if not block.instructions:
                continue
            source = block.instructions[-1]
            for target in block.successors:
                if executable(target) and not bound(target):
                    issues.append(KernelIssue(
                        "unbound_direct_kernel_target",
                        f"direct control target RVA 0x{target:x} is outside every bound kernel function",
                        source.rva,
                        source.rva + len(source.data),
                        function.role,
                    ))
    return issues


def _padding_bytes(data: bytes) -> bool:
    return all(byte in {0x00, 0x90, 0xCC} for byte in data)


def _deduplicate_issues(values: Iterable[KernelIssue]) -> list[KernelIssue]:
    unique = {
        (item.code, item.message, item.rva_start, item.rva_end, item.function_role): item
        for item in values
    }
    return sorted(
        unique.values(),
        key=lambda item: (
            item.function_role or "",
            -1 if item.rva_start is None else item.rva_start,
            item.code,
        ),
    )


def _symbol_key(value: str) -> str:
    return value.lstrip("_").split("@", 1)[0]


def _lean_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _file(value: Path | str, label: str) -> Path:
    path = Path(value)
    if not path.is_file() or path.is_symlink():
        raise RelationalInterpreterKernelGenerationError(
            f"{label} is not a regular file: {path}"
        )
    return path


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelGenerationError(
            f"cannot read {label}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise RelationalInterpreterKernelGenerationError(f"{label} must be an object")
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelGenerationError(f"{label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelGenerationError(f"{label} must be a string")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RelationalInterpreterKernelGenerationError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _u32(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise RelationalInterpreterKernelGenerationError(f"{label} must be a uint32")
    return value


def _count(value: Any, label: str, maximum: int) -> int:
    parsed = _u32(value, label)
    if parsed > maximum:
        raise RelationalInterpreterKernelGenerationError(
            f"{label} exceeds the checked maximum {maximum}"
        )
    return parsed


__all__ = [
    "INTERPRETER_KERNEL_LEAN_FILENAME",
    "INTERPRETER_KERNEL_PLAN_FILENAME",
    "INTERPRETER_KERNEL_PLAN_FORMAT",
    "InterpreterKernelPlan",
    "RelationalInterpreterKernelGenerationError",
    "build_relational_interpreter_kernel_plan",
    "relational_interpreter_kernel_source",
    "write_relational_interpreter_kernel_bundle",
]
