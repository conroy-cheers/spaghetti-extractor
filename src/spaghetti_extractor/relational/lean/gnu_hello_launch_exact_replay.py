"""Generate granular exact replay modules for the GNU hello launch span.

The generated block proofs re-decode and symbolically execute exact candidate
PE bytes in Lean.  Python supplies only deterministic function ranges, block
leaders, and module partitioning.  Any decode issue, indirect exit, missing
continuation, or uncovered direct target rejects generation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from ...errors import StageAInputError
from ...stage_binary import _parse_stage_a_pe
from ...util import sha256_bytes, write_json
from .interpreter_kernel import (
    KernelBlockPlan,
    KernelFunctionPlan,
    _analyze_function,
    _direct_call_target_hints,
    _load_function_hints,
)


GNU_HELLO_LAUNCH_EXACT_REPLAY_FORMAT = (
    "stage-a-gnu-hello-launch-exact-replay-v1"
)
GNU_HELLO_LAUNCH_EXACT_REPLAY_MANIFEST = (
    "gnu-hello-launch-exact-replay.json"
)
GNU_HELLO_LAUNCH_REPLAY_CANDIDATE_MODULE = (
    "GeneratedRelationalInterpreterGnuHelloLaunchReplayCandidate"
)
GNU_HELLO_LAUNCH_REPLAY_FUNCTION_PREFIX = (
    "GeneratedRelationalInterpreterGnuHelloLaunchReplayFunction"
)
GNU_HELLO_LAUNCH_REPLAY_BUNDLE_MODULE = (
    "GeneratedRelationalInterpreterGnuHelloLaunchReplayBundle"
)
GNU_HELLO_LAUNCH_REPLAY_INDEX_MODULE = (
    "GeneratedRelationalInterpreterGnuHelloLaunchReplayIndex"
)

GNU_HELLO_CALLBACK_RVA = 278423
GNU_HELLO_RUN_FUNCTION_RVA = 288298
GNU_HELLO_PROGRAM_LOOKUP_RVA = 285217
GNU_HELLO_NESTED_CALLBACK_RVA = 292024

# This closure contains every direct callee that can be encountered while
# executing the callback and runtime functions before entering runFunction.
# The full CFG of each listed function is retained, including fail-fast arms.
_REPLAY_FUNCTION_ENTRIES = (
    276343,  # stage_b_native_callback_entry_for
    276819,  # stage_b_native_dispatch_bridge
    277373,  # stage_b_native_fnsave_to_state
    277800,  # stage_b_native_unpack_flags
    277924,  # stage_b_native_pack_flags
    GNU_HELLO_CALLBACK_RVA,
    288900,  # stage_b_native_u16
    288942,  # stage_b_native_u32
    289018,  # stage_b_native_range_end
    289144,  # stage_b_native_validate_image
    289636,  # stage_b_native_validate_stack
    289771,  # stage_b_native_transfer_table_valid
    291124,  # stage_b_native_unpack_flags
    291323,  # stage_b_native_has_transfer
    291532,  # stage_b_native_run_initialized
    291704,  # stage_b_native_runtime_run_at_rva
)
_BOUNDARY_TARGETS = (
    GNU_HELLO_PROGRAM_LOOKUP_RVA,
    GNU_HELLO_RUN_FUNCTION_RVA,
    GNU_HELLO_NESTED_CALLBACK_RVA,
)

_LOCAL_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")
_QUALIFIED_MODULE = re.compile(
    r"StageA\.[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z"
)
_NAMESPACE = re.compile(
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z"
)


class GnuHelloLaunchExactReplayError(StageAInputError):
    """The launch replay proposal is incomplete or stale."""


@dataclass(frozen=True)
class GnuHelloLaunchExactReplaySpec:
    candidate_module: str = GNU_HELLO_LAUNCH_REPLAY_CANDIDATE_MODULE
    function_prefix: str = GNU_HELLO_LAUNCH_REPLAY_FUNCTION_PREFIX
    bundle_module: str = GNU_HELLO_LAUNCH_REPLAY_BUNDLE_MODULE
    index_module: str = GNU_HELLO_LAUNCH_REPLAY_INDEX_MODULE
    namespace: str = (
        "StageA.GeneratedRelational.InterpreterGnuHelloLaunchReplay"
    )
    candidate_data_module: str = (
        "StageA.GeneratedInterpreterKernelDataBase"
    )
    candidate_data_namespace: str = (
        "StageA.GeneratedRelational.InterpreterKernelData"
    )


@dataclass(frozen=True)
class GnuHelloLaunchExactReplayFunction:
    ordinal: int
    function: KernelFunctionPlan
    module_prefix: str = GNU_HELLO_LAUNCH_REPLAY_FUNCTION_PREFIX
    operation_blocks: tuple[KernelBlockPlan, ...] = ()

    @property
    def module_name(self) -> str:
        return f"{self.module_prefix}{self.ordinal:04d}"

    @property
    def proof_list_name(self) -> str:
        return f"generatedGnuHelloLaunchFunction{self.ordinal:04d}BlockProofs"

    @property
    def inventory_module_name(self) -> str:
        return f"{self.module_name}Inventory"

    @property
    def entry_list_name(self) -> str:
        return f"generatedGnuHelloLaunchFunction{self.ordinal:04d}EntryRvas"

    @property
    def shard_name(self) -> str:
        return f"generatedGnuHelloLaunchFunction{self.ordinal:04d}ReplayShard"

    @property
    def replay_blocks(self) -> tuple[KernelBlockPlan, ...]:
        return self.operation_blocks or self.function.blocks

    def payload(self) -> dict[str, object]:
        return {
            "ordinal": self.ordinal,
            "module": self.module_name,
            "entry_rva": self.function.start,
            "end_rva": self.function.start + len(self.function.data),
            "role": self.function.hint,
            "analyzed_blocks": len(self.function.blocks),
            "blocks": len(self.replay_blocks),
            "instructions": sum(
                len(block.instructions) for block in self.replay_blocks
            ),
            "proof_list": self.proof_list_name,
            "inventory_module": self.inventory_module_name,
        }


@dataclass(frozen=True)
class GnuHelloLaunchExactReplayPlan:
    spec: GnuHelloLaunchExactReplaySpec
    candidate_sha256: str
    candidate_size: int
    candidate_data_inventory_format: str
    candidate_data_module_sha256: str
    functions: tuple[GnuHelloLaunchExactReplayFunction, ...]
    boundary_targets: tuple[int, ...]

    @property
    def block_count(self) -> int:
        return sum(len(item.replay_blocks) for item in self.functions)

    @property
    def instruction_count(self) -> int:
        return sum(
            len(block.instructions)
            for item in self.functions
            for block in item.replay_blocks
        )

    @property
    def entry_rvas(self) -> tuple[int, ...]:
        return tuple(
            block.entry_rva
            for item in self.functions
            for block in item.replay_blocks
        )

    def payload(self) -> dict[str, object]:
        return {
            "format": GNU_HELLO_LAUNCH_EXACT_REPLAY_FORMAT,
            "acceptance_authority": False,
            "proof_authority": False,
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "candidate_data": {
                "inventory_format": self.candidate_data_inventory_format,
                "module": self.spec.candidate_data_module,
                "module_source_sha256": self.candidate_data_module_sha256,
            },
            "source_rva": GNU_HELLO_CALLBACK_RVA,
            "destination_rva": GNU_HELLO_RUN_FUNCTION_RVA,
            "candidate_module": self.spec.candidate_module,
            "index_module": self.spec.index_module,
            "bundle_module": self.spec.bundle_module,
            "function_modules": [
                function.payload() for function in self.functions
            ],
            "boundary_targets": list(self.boundary_targets),
            "coverage": {
                "functions": len(self.functions),
                "blocks": self.block_count,
                "instructions": self.instruction_count,
                "decoded_exits_uncovered": 0,
                "guard_arms_omitted": 0,
            },
            "exact_replay_complete": True,
            "route_invariant_complete": False,
        }


def build_gnu_hello_launch_exact_replay_plan(
    *,
    candidate_pe: Path | str,
    linker_map: Path | str,
    candidate_data_inventory: Path | str,
    spec: GnuHelloLaunchExactReplaySpec | None = None,
) -> GnuHelloLaunchExactReplayPlan:
    selected = spec or GnuHelloLaunchExactReplaySpec()
    _validate_spec(selected)
    candidate_path = Path(candidate_pe)
    linker_map_path = Path(linker_map)
    candidate_bytes = candidate_path.read_bytes()
    candidate_sha256 = sha256_bytes(candidate_bytes)
    inventory_format, data_module_sha256 = _validate_candidate_data_inventory(
        Path(candidate_data_inventory),
        candidate_sha256=candidate_sha256,
        candidate_size=len(candidate_bytes),
        candidate_data_module=selected.candidate_data_module,
    )
    binary = _parse_stage_a_pe(candidate_path)
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise GnuHelloLaunchExactReplayError(
                "launch replay requires an x86 PE32 candidate"
            )
        map_hints = _load_function_hints(linker_map_path, binary)
        hints = (*map_hints, *_direct_call_target_hints(binary, map_hints))
        by_start: dict[int, list[Any]] = {}
        for hint in hints:
            by_start.setdefault(hint.start, []).append(hint)

        functions: list[GnuHelloLaunchExactReplayFunction] = []
        for ordinal, entry_rva in enumerate(_REPLAY_FUNCTION_ENTRIES):
            matches = by_start.get(entry_rva, [])
            unique = {
                (hint.start, hint.end, hint.name): hint for hint in matches
            }
            if len(unique) != 1:
                raise GnuHelloLaunchExactReplayError(
                    f"launch replay function 0x{entry_rva:x} has "
                    f"{len(unique)} recovered ranges"
                )
            hint = next(iter(unique.values()))
            function, issues = _analyze_function(
                binary, hint, f"launch-replay-{entry_rva:08x}"
            )
            if issues:
                issue = issues[0]
                raise GnuHelloLaunchExactReplayError(
                    f"{issue.code} at RVA 0x{issue.rva_start:x}: "
                    f"{issue.message}"
                )
            if not function.blocks:
                raise GnuHelloLaunchExactReplayError(
                    f"launch replay function 0x{entry_rva:x} has no blocks"
                )
            functions.append(
                GnuHelloLaunchExactReplayFunction(
                    ordinal,
                    function,
                    selected.function_prefix,
                    _build_operation_blocks(function),
                )
            )

        _validate_exit_coverage(functions, _BOUNDARY_TARGETS)
    finally:
        binary.pe.close()

    return GnuHelloLaunchExactReplayPlan(
        spec=selected,
        candidate_sha256=candidate_sha256,
        candidate_size=len(candidate_bytes),
        candidate_data_inventory_format=inventory_format,
        candidate_data_module_sha256=data_module_sha256,
        functions=tuple(functions),
        boundary_targets=tuple(sorted(_BOUNDARY_TARGETS)),
    )


def _validate_exit_coverage(
    functions: Sequence[GnuHelloLaunchExactReplayFunction],
    boundary_targets: Sequence[int],
) -> None:
    blocks = {
        block.entry_rva: block
        for function in functions
        for block in function.replay_blocks
    }
    if sum(
        len(function.replay_blocks) for function in functions
    ) != len(blocks):
        raise GnuHelloLaunchExactReplayError(
            "launch replay has duplicate operation-block entries"
        )
    entries = {function.function.start for function in functions}
    covered = set(blocks) | entries | set(boundary_targets)
    for function in functions:
        for block in function.replay_blocks:
            if not block.instructions:
                raise GnuHelloLaunchExactReplayError(
                    f"empty block at RVA 0x{block.entry_rva:x}"
                )
            _validate_operation_exit_shape(block)
            for target in block.successors:
                if target not in covered:
                    raise GnuHelloLaunchExactReplayError(
                        "uncovered decoded exit "
                        f"0x{block.instructions[-1].rva:x} -> 0x{target:x}"
                    )

    # These boundaries are semantic interfaces, not a way to hide missing
    # local blocks.  Require each one to occur as a decoded successor.
    successors = {
        target
        for function in functions
        for block in function.replay_blocks
        for target in block.successors
    }
    for target in boundary_targets:
        if target not in successors:
            raise GnuHelloLaunchExactReplayError(
                f"declared boundary 0x{target:x} is not a decoded exit"
            )


def _build_operation_blocks(
    function: KernelFunctionPlan,
) -> tuple[KernelBlockPlan, ...]:
    """Split one disassembled CFG into exact operation-level replay paths.

    Capstone basic blocks may end at a join leader even though the final
    instruction is an ordinary fallthrough.  Conversely, the Stage A machine
    model treats checked bulk operations such as ``rep movsd`` as a stopped
    transition even when Capstone retains them inside a basic block.  Replay
    blocks therefore start at every CFG leader and every post-stop
    continuation, then follow exact contiguous instructions to the next
    machine-model stop.

    Shared tails may occur in more than one replay block.  This is intentional:
    each exported block is an independently exact path from its entry to a
    stopped transition, while the byte decoder remains the authority.
    """

    instructions: dict[int, Any] = {}
    terminal_successors: dict[int, tuple[int, ...]] = {}
    leaders: set[int] = set()
    for block in function.blocks:
        leaders.add(block.entry_rva)
        if not block.instructions:
            raise GnuHelloLaunchExactReplayError(
                f"empty analyzed block at RVA 0x{block.entry_rva:x}"
            )
        terminal_successors[block.instructions[-1].rva] = block.successors
        for instruction in block.instructions:
            previous = instructions.get(instruction.rva)
            if previous is not None and previous != instruction:
                raise GnuHelloLaunchExactReplayError(
                    "conflicting instruction proposals at RVA "
                    f"0x{instruction.rva:x}"
                )
            instructions[instruction.rva] = instruction

    for instruction in instructions.values():
        if _operation_instruction_stops(instruction):
            continuation = instruction.rva + len(instruction.data)
            if continuation in instructions:
                leaders.add(continuation)

    operation_blocks: list[KernelBlockPlan] = []
    for leader in sorted(leaders):
        rows: list[Any] = []
        cursor = leader
        visited: set[int] = set()
        while True:
            if cursor in visited:
                raise GnuHelloLaunchExactReplayError(
                    "operation replay encountered an unstopped cycle at RVA "
                    f"0x{cursor:x}"
                )
            visited.add(cursor)
            instruction = instructions.get(cursor)
            if instruction is None:
                raise GnuHelloLaunchExactReplayError(
                    "operation replay has no instruction at RVA "
                    f"0x{cursor:x}"
                )
            rows.append(instruction)
            continuation = instruction.rva + len(instruction.data)
            if _operation_instruction_stops(instruction):
                successors = terminal_successors.get(instruction.rva)
                if successors is None:
                    if _is_checked_linear_stop(instruction):
                        successors = (continuation,)
                    else:
                        raise GnuHelloLaunchExactReplayError(
                            "control instruction is not an analyzed terminal "
                            f"at RVA 0x{instruction.rva:x}"
                        )
                operation_blocks.append(
                    KernelBlockPlan(leader, tuple(rows), successors)
                )
                break
            if continuation not in instructions:
                raise GnuHelloLaunchExactReplayError(
                    "operation replay path reaches no stopped transition "
                    f"after RVA 0x{instruction.rva:x}"
                )
            cursor = continuation

    return tuple(operation_blocks)


def _operation_instruction_stops(instruction: Any) -> bool:
    mnemonic = instruction.mnemonic.lower()
    return (
        mnemonic == "call"
        or mnemonic == "ret"
        or mnemonic == "retf"
        or mnemonic == "iret"
        or mnemonic == "jmp"
        or mnemonic.startswith("j")
        or _is_checked_linear_stop(instruction)
    )


def _is_checked_linear_stop(instruction: Any) -> bool:
    mnemonic = instruction.mnemonic.lower()
    return mnemonic.startswith("rep ") or mnemonic.startswith("lock ")


def _validate_operation_exit_shape(block: KernelBlockPlan) -> None:
    terminal = block.instructions[-1]
    mnemonic = terminal.mnemonic.lower()
    successors = block.successors
    continuation = terminal.rva + len(terminal.data)
    if mnemonic == "call":
        if (
            len(successors) != 2
            or successors[1] != continuation
            or successors[0] == successors[1]
        ):
            raise GnuHelloLaunchExactReplayError(
                "direct call must expose one target and its exact "
                f"continuation at RVA 0x{terminal.rva:x}"
            )
    elif mnemonic == "jmp":
        if len(successors) != 1:
            raise GnuHelloLaunchExactReplayError(
                f"jump at RVA 0x{terminal.rva:x} has {len(successors)} arms"
            )
    elif mnemonic.startswith("j"):
        if len(successors) != 2 or successors[0] == successors[1]:
            raise GnuHelloLaunchExactReplayError(
                "conditional branch must expose two distinct guard arms at "
                f"RVA 0x{terminal.rva:x}"
            )
        if continuation not in successors:
            raise GnuHelloLaunchExactReplayError(
                "conditional branch omits its fallthrough guard arm at RVA "
                f"0x{terminal.rva:x}"
            )
    elif mnemonic in {"ret", "retf", "iret"}:
        if successors:
            raise GnuHelloLaunchExactReplayError(
                f"return at RVA 0x{terminal.rva:x} has static successors"
            )
    elif _is_checked_linear_stop(terminal):
        if successors != (continuation,):
            raise GnuHelloLaunchExactReplayError(
                "checked linear stop must expose its exact continuation at "
                f"RVA 0x{terminal.rva:x}"
            )
    else:
        raise GnuHelloLaunchExactReplayError(
            "operation replay block does not end in a checked stop at RVA "
            f"0x{terminal.rva:x} ({terminal.mnemonic})"
        )


def gnu_hello_launch_replay_candidate_source(
    plan: GnuHelloLaunchExactReplayPlan,
) -> str:
    spec = plan.spec
    return f"""import StageA.RelationalInterpreterNativeWorld
import {spec.candidate_data_module}

namespace {spec.namespace}

open StageA.Relational.InterpreterNativeWorld
open {spec.candidate_data_namespace}

/-- Exact PE/import/indirect-target authority shared by all granular launch
replay shards.  This span has no decoded indirect instruction, so an empty
inventory fails closed if one is introduced. -/
def generatedGnuHelloLaunchReplayCandidate
    (environment : NativeWorldEnvironment) : ExactNativeWorldProgram := {{
  pe := generatedInterpreterKernelCandidatePe
  imports := generatedInterpreterKernelImports
  environment
  indirectTargets := {{}}
}}

def generatedGnuHelloLaunchReplayCheckEnvironment :
    NativeWorldEnvironment := {{
  action := fun _ _ _ => .blocked .missingRuntimeContinuation
}}

theorem generatedGnuHelloLaunchReplayCandidateTargetsValid :
    forall environment,
      (generatedGnuHelloLaunchReplayCandidate environment).indirectTargets.valid
        (generatedGnuHelloLaunchReplayCandidate environment).pe = true := by
  intro environment
  rfl

#print axioms generatedGnuHelloLaunchReplayCandidateTargetsValid

end {spec.namespace}
"""


def gnu_hello_launch_replay_function_source(
    plan: GnuHelloLaunchExactReplayPlan,
    selected: GnuHelloLaunchExactReplayFunction,
) -> str:
    definitions: list[str] = []
    audits: list[str] = []
    for block_ordinal, block in enumerate(selected.replay_blocks):
        block_prefix = (
            f"generatedGnuHelloLaunchFunction{selected.ordinal:04d}"
            f"Block{block_ordinal:04d}"
        )
        running_edges: list[str] = []
        for instruction_ordinal, instruction in enumerate(block.instructions):
            instruction_prefix = (
                f"{block_prefix}Instruction{instruction_ordinal:04d}"
            )
            definitions.append(
                f"""def {instruction_prefix} : KernelInstruction :=
  {{ rva := {instruction.rva}, bytes := {_lean_bytes(instruction.data)} }}"""
            )
            if instruction_ordinal + 1 < len(block.instructions):
                definitions.append(
                    _running_instruction_source(
                        instruction_prefix, instruction_ordinal
                    )
                )
                running_edges.append(f"{instruction_prefix}Edge environment")
            else:
                definitions.append(
                    _stopped_instruction_source(
                        instruction_prefix, instruction_ordinal
                    )
                )
        terminal_prefix = (
            f"{block_prefix}Instruction{len(block.instructions) - 1:04d}"
        )
        if running_edges:
            trace_name = f"{block_prefix}RunningTrace"
            definitions.append(
                f"""def {trace_name}
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationRunningTrace
      (generatedGnuHelloLaunchReplayCandidate environment) := {{
  first := {running_edges[0]}
  tail := [{", ".join(running_edges[1:])}]
  checked := by
    change checkedNativeOperationRunningTrace [
      {", ".join(edge.replace("environment", "generatedGnuHelloLaunchReplayCheckEnvironment") for edge in running_edges)}
    ] = true
    decide +kernel
}}"""
            )
            running = f"some ({trace_name} environment)"
        else:
            running = "none"
        proof_name = f"{block_prefix}Proof"
        definitions.append(
            f"""def {proof_name}
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationBlock
      (generatedGnuHelloLaunchReplayCandidate environment) := {{
  running := {running}
  terminal := {terminal_prefix}Edge environment
  checked := by
    change checkedNativeOperationBlock
      ({running.replace("environment", "generatedGnuHelloLaunchReplayCheckEnvironment")})
      ({terminal_prefix}Edge
        generatedGnuHelloLaunchReplayCheckEnvironment) = true
    decide +kernel
}}"""
        )
        audits.append(f"#print axioms {proof_name}")

    block_terms = ",\n  ".join(
        (
            f"generatedGnuHelloLaunchFunction{selected.ordinal:04d}"
            f"Block{ordinal:04d}Proof environment"
        )
        for ordinal, _block in enumerate(selected.replay_blocks)
    )
    definitions.append(
        f"""def {selected.proof_list_name}
    (environment : NativeWorldEnvironment) :
    List (CheckedNativeOperationBlock
      (generatedGnuHelloLaunchReplayCandidate environment)) := [
  {block_terms}
]"""
    )
    return f"""import StageA.RelationalInterpreterKernelOperationTraceChecker
import StageA.{plan.spec.candidate_module}

namespace {plan.spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{"\n\n".join(definitions)}

{"\n".join(audits)}

end {plan.spec.namespace}
"""


def gnu_hello_launch_replay_index_source(
    plan: GnuHelloLaunchExactReplayPlan,
) -> str:
    entries = ", ".join(str(value) for value in plan.entry_rvas)
    boundaries = ", ".join(str(value) for value in plan.boundary_targets)
    return f"""import StageA.RelationalInterpreterMixedLaunchExactReplayGraphChecker

namespace {plan.spec.namespace}

def generatedGnuHelloLaunchReplayEntryRvas : List Nat := [
  {entries}
]

def generatedGnuHelloLaunchReplayBoundaryTargets : List Nat := [
  {boundaries}
]

end {plan.spec.namespace}
"""


def gnu_hello_launch_replay_inventory_source(
    plan: GnuHelloLaunchExactReplayPlan,
    selected: GnuHelloLaunchExactReplayFunction,
) -> str:
    entries = ", ".join(
        str(block.entry_rva) for block in selected.replay_blocks
    )
    return f"""import StageA.{selected.module_name}
import StageA.{plan.spec.index_module}

namespace {plan.spec.namespace}

open StageA.Relational.InterpreterMixedLaunchExactReplayGraphChecker
open StageA.Relational.InterpreterNativeWorld

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def {selected.entry_list_name} : List Nat := [
  {entries}
]

theorem {selected.entry_list_name}Exact :
    forall environment,
      exactNativeLaunchBlockEntries
          ({selected.proof_list_name} environment) =
        exactNativeLaunchDeclaredEntries {selected.entry_list_name} := by
  intro environment
  change exactNativeLaunchBlockEntries
      ({selected.proof_list_name}
        generatedGnuHelloLaunchReplayCheckEnvironment) =
    exactNativeLaunchDeclaredEntries {selected.entry_list_name}
  decide +kernel

theorem {selected.entry_list_name}ControlsComplete :
    forall environment,
      checkedExactNativeLaunchControlInventoryAgainstEntries
        ({selected.proof_list_name} environment)
        generatedGnuHelloLaunchReplayEntryRvas
        generatedGnuHelloLaunchReplayBoundaryTargets = true := by
  intro environment
  change checkedExactNativeLaunchControlInventoryAgainstEntries
      ({selected.proof_list_name}
        generatedGnuHelloLaunchReplayCheckEnvironment)
      generatedGnuHelloLaunchReplayEntryRvas
      generatedGnuHelloLaunchReplayBoundaryTargets = true
  decide +kernel

def {selected.shard_name}
    (environment : NativeWorldEnvironment) :
    CheckedExactNativeLaunchReplayShard
      (generatedGnuHelloLaunchReplayCandidate environment)
      generatedGnuHelloLaunchReplayEntryRvas
      generatedGnuHelloLaunchReplayBoundaryTargets := {{
  blocks := {selected.proof_list_name} environment
  entries := {selected.entry_list_name}
  entriesExact := {selected.entry_list_name}Exact environment
  controlsComplete := {selected.entry_list_name}ControlsComplete environment
}}

#print axioms {selected.entry_list_name}Exact
#print axioms {selected.entry_list_name}ControlsComplete

end {plan.spec.namespace}
"""


def gnu_hello_launch_replay_bundle_source(
    plan: GnuHelloLaunchExactReplayPlan,
) -> str:
    imports = "\n".join(
        f"import StageA.{function.inventory_module_name}"
        for function in plan.functions
    )
    shards = ",\n  ".join(
        f"{function.shard_name} environment"
        for function in plan.functions
    )
    entry_lists = ",\n      ".join(
        function.entry_list_name for function in plan.functions
    )
    return f"""{imports}
import StageA.{plan.spec.index_module}

namespace {plan.spec.namespace}

open StageA.Relational.InterpreterMixedLaunchExactReplayGraphChecker
open StageA.Relational.InterpreterNativeWorld

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedGnuHelloLaunchReplayShards
    (environment : NativeWorldEnvironment) :
    List (CheckedExactNativeLaunchReplayShard
      (generatedGnuHelloLaunchReplayCandidate environment)
      generatedGnuHelloLaunchReplayEntryRvas
      generatedGnuHelloLaunchReplayBoundaryTargets) := [
  {shards}
]

def generatedGnuHelloLaunchReplayBundle
    (environment : NativeWorldEnvironment) :
    CheckedExactNativeLaunchReplayBundle
      (generatedGnuHelloLaunchReplayCandidate environment) := {{
    globalEntries := generatedGnuHelloLaunchReplayEntryRvas
    boundaries := generatedGnuHelloLaunchReplayBoundaryTargets
    shards := generatedGnuHelloLaunchReplayShards environment
    entriesUnique := by decide +kernel
    entriesComplete := by
      change List.flatten [
        {entry_lists}
      ] = generatedGnuHelloLaunchReplayEntryRvas
      decide +kernel
}}

theorem generatedGnuHelloLaunchReplayExact :
    forall environment,
      Nonempty (CheckedExactNativeLaunchReplayBundle
        (generatedGnuHelloLaunchReplayCandidate environment)) := by
  intro environment
  exact Nonempty.intro (generatedGnuHelloLaunchReplayBundle environment)

#print axioms generatedGnuHelloLaunchReplayExact

end {plan.spec.namespace}
"""


def write_gnu_hello_launch_exact_replay(
    out: Path | str,
    *,
    candidate_pe: Path | str,
    linker_map: Path | str,
    candidate_data_inventory: Path | str,
    spec: GnuHelloLaunchExactReplaySpec | None = None,
) -> GnuHelloLaunchExactReplayPlan:
    plan = build_gnu_hello_launch_exact_replay_plan(
        candidate_pe=candidate_pe,
        linker_map=linker_map,
        candidate_data_inventory=candidate_data_inventory,
        spec=spec,
    )
    output = Path(out)
    stage_a = output / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    (stage_a / f"{plan.spec.candidate_module}.lean").write_text(
        gnu_hello_launch_replay_candidate_source(plan),
        encoding="ascii",
    )
    (stage_a / f"{plan.spec.index_module}.lean").write_text(
        gnu_hello_launch_replay_index_source(plan),
        encoding="ascii",
    )
    for function in plan.functions:
        (stage_a / f"{function.module_name}.lean").write_text(
            gnu_hello_launch_replay_function_source(plan, function),
            encoding="ascii",
        )
        (stage_a / f"{function.inventory_module_name}.lean").write_text(
            gnu_hello_launch_replay_inventory_source(plan, function),
            encoding="ascii",
        )
    (stage_a / f"{plan.spec.bundle_module}.lean").write_text(
        gnu_hello_launch_replay_bundle_source(plan),
        encoding="ascii",
    )
    write_json(
        output / GNU_HELLO_LAUNCH_EXACT_REPLAY_MANIFEST,
        plan.payload(),
    )
    return plan


def _running_instruction_source(prefix: str, slot: int) -> str:
    return f"""def {prefix}Replay
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationRunningInstruction
      (generatedGnuHelloLaunchReplayCandidate environment)
      {prefix} {slot} :=
  .ofCanonicalChecked
    (generatedGnuHelloLaunchReplayCandidate environment)
    {prefix} {slot}
    (by
      change canonicalNativeOperationInstructionChecked
        (generatedGnuHelloLaunchReplayCandidate
          generatedGnuHelloLaunchReplayCheckEnvironment)
        {prefix} {slot} = true
      decide +kernel)
    (by
      change checkedNativeOperationRunningResult
        ((CheckedNativeOperationInstructionReplay.ofCanonicalChecked
          (generatedGnuHelloLaunchReplayCandidate
            generatedGnuHelloLaunchReplayCheckEnvironment)
          {prefix} {slot} (by decide +kernel)).symbolic) = true
      decide +kernel)

def {prefix}Cutpoint
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationRunningCutpoint ({prefix}Replay environment) :=
  .ofTrivial ({prefix}Replay environment)

def {prefix}Edge
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationRunningEdge
      (generatedGnuHelloLaunchReplayCandidate environment) := {{
  instruction := {prefix}
  undefinedSlot := {slot}
  replay := {prefix}Replay environment
  cutpoint := {prefix}Cutpoint environment
}}"""


def _stopped_instruction_source(prefix: str, slot: int) -> str:
    return f"""def {prefix}Replay
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationStoppedInstruction
      (generatedGnuHelloLaunchReplayCandidate environment)
      {prefix} {slot} :=
  .ofCanonicalChecked
    (generatedGnuHelloLaunchReplayCandidate environment)
    {prefix} {slot}
    (by
      change canonicalNativeOperationInstructionChecked
        (generatedGnuHelloLaunchReplayCandidate
          generatedGnuHelloLaunchReplayCheckEnvironment)
        {prefix} {slot} = true
      decide +kernel)
    (by
      change checkedNativeOperationStoppedResult
        ((CheckedNativeOperationInstructionReplay.ofCanonicalChecked
          (generatedGnuHelloLaunchReplayCandidate
            generatedGnuHelloLaunchReplayCheckEnvironment)
          {prefix} {slot} (by decide +kernel)).symbolic) = true
      decide +kernel)

def {prefix}Postcondition
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationPostcondition
      ({prefix}Replay environment).behavior :=
  .ofStoppedReplay ({prefix}Replay environment)

def {prefix}Cutpoint
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationStoppedCutpoint ({prefix}Replay environment) :=
  .ofTrivial ({prefix}Replay environment)
    ({prefix}Postcondition environment)

def {prefix}Edge
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationStoppedEdge
      (generatedGnuHelloLaunchReplayCandidate environment) := {{
  instruction := {prefix}
  undefinedSlot := {slot}
  replay := {prefix}Replay environment
  cutpoint := {prefix}Cutpoint environment
}}"""


def _validate_spec(spec: GnuHelloLaunchExactReplaySpec) -> None:
    for label, value in (
        ("candidate_module", spec.candidate_module),
        ("function_prefix", spec.function_prefix),
        ("bundle_module", spec.bundle_module),
        ("index_module", spec.index_module),
    ):
        if _LOCAL_NAME.fullmatch(value) is None:
            raise ValueError(f"{label} must be one Lean identifier")
    for label, value in (
        ("candidate_data_module", spec.candidate_data_module),
    ):
        if _QUALIFIED_MODULE.fullmatch(value) is None:
            raise ValueError(f"{label} must be a qualified StageA module")
    for label, value in (
        ("namespace", spec.namespace),
        ("candidate_data_namespace", spec.candidate_data_namespace),
    ):
        if _NAMESPACE.fullmatch(value) is None:
            raise ValueError(f"{label} must be a qualified Lean namespace")


def _validate_candidate_data_inventory(
    path: Path,
    *,
    candidate_sha256: str,
    candidate_size: int,
    candidate_data_module: str,
) -> tuple[str, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GnuHelloLaunchExactReplayError(
            f"cannot read candidate data inventory {path}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise GnuHelloLaunchExactReplayError(
            "candidate data inventory must be a JSON object"
        )
    inventory_format = payload.get("format")
    if inventory_format != "stage-a-interpreter-kernel-data-inventory-v7":
        raise GnuHelloLaunchExactReplayError(
            "candidate data inventory has unsupported format "
            f"{inventory_format!r}"
        )
    if payload.get("candidate_sha256") != candidate_sha256:
        raise GnuHelloLaunchExactReplayError(
            "candidate data inventory SHA-256 does not match candidate PE"
        )
    if payload.get("candidate_bytes") != candidate_size:
        raise GnuHelloLaunchExactReplayError(
            "candidate data inventory size does not match candidate PE"
        )
    module_name = candidate_data_module.removeprefix("StageA.")
    modules = payload.get("modules")
    if not isinstance(modules, list):
        raise GnuHelloLaunchExactReplayError(
            "candidate data inventory has no module inventory"
        )
    matches = [
        module
        for module in modules
        if isinstance(module, dict) and module.get("name") == module_name
    ]
    if len(matches) != 1:
        raise GnuHelloLaunchExactReplayError(
            f"candidate data module {module_name!r} has {len(matches)} "
            "inventory entries"
        )
    source_sha256 = matches[0].get("source_sha256")
    if not isinstance(source_sha256, str) or re.fullmatch(
        r"[0-9a-f]{64}", source_sha256
    ) is None:
        raise GnuHelloLaunchExactReplayError(
            f"candidate data module {module_name!r} has no source SHA-256"
        )
    return inventory_format, source_sha256


def _lean_bytes(data: bytes) -> str:
    return "[" + ", ".join(str(value) for value in data) + "]"


__all__ = [
    "GNU_HELLO_CALLBACK_RVA",
    "GNU_HELLO_LAUNCH_EXACT_REPLAY_FORMAT",
    "GNU_HELLO_LAUNCH_EXACT_REPLAY_MANIFEST",
    "GNU_HELLO_LAUNCH_REPLAY_BUNDLE_MODULE",
    "GNU_HELLO_LAUNCH_REPLAY_CANDIDATE_MODULE",
    "GNU_HELLO_LAUNCH_REPLAY_FUNCTION_PREFIX",
    "GNU_HELLO_LAUNCH_REPLAY_INDEX_MODULE",
    "GNU_HELLO_RUN_FUNCTION_RVA",
    "GnuHelloLaunchExactReplayError",
    "GnuHelloLaunchExactReplayFunction",
    "GnuHelloLaunchExactReplayPlan",
    "GnuHelloLaunchExactReplaySpec",
    "build_gnu_hello_launch_exact_replay_plan",
    "gnu_hello_launch_replay_bundle_source",
    "gnu_hello_launch_replay_candidate_source",
    "gnu_hello_launch_replay_function_source",
    "gnu_hello_launch_replay_index_source",
    "gnu_hello_launch_replay_inventory_source",
    "write_gnu_hello_launch_exact_replay",
]
