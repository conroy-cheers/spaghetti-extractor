"""Generate the checked control prefix for a native Run operation.

This phase deliberately consumes the immutable operation-instantiation
manifest instead of rebuilding that binary-wide analysis.  It is therefore a
small proof-certificate layer: changing the route proposal invalidates only
this module and its Lean descendants.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


INTERPRETER_KERNEL_RUN_ENTRY_ROUTE_FORMAT = (
    "stage-a-relational-interpreter-kernel-run-entry-route-v1"
)
INTERPRETER_KERNEL_RUN_ENTRY_ROUTE_LEAN_MODULE = (
    "GeneratedRelationalInterpreterKernelRunEntryRoute"
)
INTERPRETER_KERNEL_RUN_ENTRY_ROUTE_MANIFEST = (
    "interpreter-kernel-run-entry-route.json"
)
INTERPRETER_KERNEL_RUN_ENTRY_BEHAVIOR_REQUEST = (
    "interpreter-kernel-run-entry-behavior-request.json"
)
_OPERATION_INSTANTIATION_FORMAT = (
    "stage-a-relational-interpreter-kernel-operation-instantiation-v1"
)
_BLOCK_FUNCTION_PREFIX = (
    "GeneratedRelationalInterpreterKernelOperationBlockFunction"
)
_OPERATION_CANDIDATE_CORE_MODULE = (
    "GeneratedRelationalInterpreterKernelOperationCandidateCore"
)


class InterpreterKernelRunEntryRouteError(ValueError):
    """The operation manifest does not describe one checked Run prefix."""


@dataclass(frozen=True)
class _Instruction:
    ordinal: int
    rva: int
    size: int

    @classmethod
    def parse(cls, payload: Any) -> "_Instruction":
        if not isinstance(payload, dict):
            raise InterpreterKernelRunEntryRouteError(
                "Run instruction must be an object"
            )
        ordinal = payload.get("ordinal")
        rva = payload.get("rva")
        size = payload.get("size")
        if (
            not isinstance(ordinal, int)
            or ordinal < 0
            or not isinstance(rva, int)
            or rva < 0
            or not isinstance(size, int)
            or size <= 0
            or rva + size > 2**32
        ):
            raise InterpreterKernelRunEntryRouteError(
                "Run instruction has invalid span metadata"
            )
        return cls(ordinal=ordinal, rva=rva, size=size)


@dataclass(frozen=True)
class _Block:
    ordinal: int
    entry_rva: int
    terminal_class: str
    successors: tuple[int, ...]
    instructions: tuple[_Instruction, ...]

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @classmethod
    def parse(cls, payload: Any) -> "_Block":
        if not isinstance(payload, dict):
            raise InterpreterKernelRunEntryRouteError(
                "Run block must be an object"
            )
        ordinal = payload.get("ordinal")
        entry_rva = payload.get("entry_rva")
        terminal_class = payload.get("terminal_class")
        successors = payload.get("successors")
        instructions = payload.get("instructions")
        if (
            not isinstance(ordinal, int)
            or ordinal < 0
            or not isinstance(entry_rva, int)
            or entry_rva < 0
            or not isinstance(terminal_class, str)
            or not isinstance(successors, list)
            or not isinstance(instructions, list)
            or not instructions
            or any(
                not isinstance(successor, int) or successor < 0
                for successor in successors
            )
        ):
            raise InterpreterKernelRunEntryRouteError(
                "Run block has invalid control metadata"
            )
        parsed_instructions = tuple(
            _Instruction.parse(instruction) for instruction in instructions
        )
        if [instruction.ordinal for instruction in parsed_instructions] != list(
            range(len(parsed_instructions))
        ):
            raise InterpreterKernelRunEntryRouteError(
                "Run instruction ordinals are not canonical"
            )
        return cls(
            ordinal=ordinal,
            entry_rva=entry_rva,
            terminal_class=terminal_class,
            successors=tuple(successors),
            instructions=parsed_instructions,
        )


@dataclass(frozen=True)
class RunEntryRoute:
    candidate_sha256: str
    function_ordinal: int
    function_entry_rva: int
    controls: tuple[_Block, ...]
    bulk: _Block
    loop: _Block

    @property
    def path(self) -> tuple[_Block, ...]:
        return (*self.controls, self.bulk)

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_RUN_ENTRY_ROUTE_FORMAT,
            "status": "locally_closed",
            "proof_authority": False,
            "acceptance_authority": False,
            "candidate_sha256": self.candidate_sha256,
            "function_ordinal": self.function_ordinal,
            "function_entry_rva": self.function_entry_rva,
            "control_block_rvas": [
                block.entry_rva for block in self.controls
            ],
            "bulk_block_rva": self.bulk.entry_rva,
            "loop_block_rva": self.loop.entry_rva,
            "remaining_proof_premises": [],
            "result": {
                "lean_module": (
                    f"StageA.{INTERPRETER_KERNEL_RUN_ENTRY_ROUTE_LEAN_MODULE}"
                ),
                "lean_theorem": (
                    "StageA.GeneratedRelational."
                    "InterpreterKernelOperationInstantiation."
                    "generatedRunEntryToLoopPath"
                ),
            },
        }


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InterpreterKernelRunEntryRouteError(
            f"cannot read operation-instantiation manifest {path}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise InterpreterKernelRunEntryRouteError(
            "operation-instantiation manifest must be an object"
        )
    if payload.get("format") != _OPERATION_INSTANTIATION_FORMAT:
        raise InterpreterKernelRunEntryRouteError(
            "unsupported operation-instantiation manifest format"
        )
    return payload


def build_run_entry_route(manifest_path: Path | str) -> RunEntryRoute:
    """Recover one unambiguous entry-to-first-loop Run control prefix."""

    manifest = _load_manifest(Path(manifest_path))
    candidate = manifest.get("candidate")
    candidate_sha256 = (
        candidate.get("sha256") if isinstance(candidate, dict) else None
    )
    if (
        not isinstance(candidate_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", candidate_sha256) is None
    ):
        raise InterpreterKernelRunEntryRouteError(
            "operation manifest omits the candidate SHA-256"
        )
    inventory = manifest.get("checked_native_replay_inventory")
    if not isinstance(inventory, dict):
        raise InterpreterKernelRunEntryRouteError(
            "operation manifest omits checked native replay inventory"
        )
    functions = inventory.get("function_replays")
    if not isinstance(functions, list):
        raise InterpreterKernelRunEntryRouteError(
            "operation manifest omits native function replays"
        )
    run_functions = [
        function
        for function in functions
        if isinstance(function, dict)
        and function.get("role") == "runFunction"
        and isinstance(function.get("families"), list)
        and "run" in function["families"]
    ]
    if len(run_functions) != 1:
        raise InterpreterKernelRunEntryRouteError(
            "expected exactly one checked Run function"
        )
    function = run_functions[0]
    ordinal = function.get("ordinal")
    entry_rva = function.get("entry_rva")
    graph = function.get("block_graph")
    if (
        not isinstance(ordinal, int)
        or ordinal < 0
        or not isinstance(entry_rva, int)
        or entry_rva < 0
        or not isinstance(graph, list)
    ):
        raise InterpreterKernelRunEntryRouteError(
            "Run function has invalid replay metadata"
        )
    blocks = tuple(_Block.parse(block) for block in graph)
    if len({block.ordinal for block in blocks}) != len(blocks):
        raise InterpreterKernelRunEntryRouteError(
            "Run function has duplicate block ordinals"
        )
    by_entry = {block.entry_rva: block for block in blocks}
    if len(by_entry) != len(blocks):
        raise InterpreterKernelRunEntryRouteError(
            "Run function has duplicate block entry RVAs"
        )
    call_blocks = sorted(
        (block for block in blocks if block.terminal_class == "call"),
        key=lambda block: block.entry_rva,
    )
    if not call_blocks:
        raise InterpreterKernelRunEntryRouteError(
            "Run function has no checked call cutpoint"
        )
    loop = call_blocks[0]
    bulk_predecessors = [
        block
        for block in blocks
        if block.terminal_class == "bulk"
        and block.successors == (loop.entry_rva,)
    ]
    if len(bulk_predecessors) != 1:
        raise InterpreterKernelRunEntryRouteError(
            "Run entry does not have one bulk-copy predecessor"
        )
    bulk = bulk_predecessors[0]

    paths: list[tuple[_Block, ...]] = []

    def visit(
        block: _Block,
        active: frozenset[int],
        prefix: tuple[_Block, ...],
    ) -> None:
        if block.entry_rva in active:
            return
        current = (*prefix, block)
        if block == bulk:
            paths.append(current)
            return
        if block.terminal_class not in {"branch", "jump"}:
            return
        for target in block.successors:
            successor = by_entry.get(target)
            if successor is not None:
                visit(successor, active | {block.entry_rva}, current)

    entry = by_entry.get(entry_rva)
    if entry is None:
        raise InterpreterKernelRunEntryRouteError(
            "Run entry RVA is not a checked block"
        )
    visit(entry, frozenset(), ())
    if len(paths) != 1 or len(paths[0]) < 2 or paths[0][-1] != bulk:
        raise InterpreterKernelRunEntryRouteError(
            "Run entry-to-bulk route is absent or ambiguous"
        )
    return RunEntryRoute(
        candidate_sha256=candidate_sha256,
        function_ordinal=ordinal,
        function_entry_rva=entry_rva,
        controls=paths[0][:-1],
        bulk=bulk,
        loop=loop,
    )


def run_entry_behavior_request_payload(
    route: RunEntryRoute,
) -> dict[str, Any]:
    """Return exact single-instruction spans for compact behavior extraction."""

    instructions = [
        (block, instruction)
        for block in route.path
        for instruction in block.instructions
    ]
    return {
        "format": "stage-a-relational-side-extraction-request-v1",
        "profile": "x86-pe32-lean-relational-v3",
        "model": "x86-pe32-relational-v3",
        "side": "candidate",
        "binary_sha256": route.candidate_sha256,
        "regions": [
            {
                "index": index,
                "id": (
                    f"run-entry-function-{route.function_ordinal:04d}-"
                    f"block-{block.ordinal:04d}-"
                    f"instruction-{instruction.ordinal:04d}"
                ),
                "numeric_id": index,
                "span": {
                    "rva_start": instruction.rva,
                    "size": instruction.size,
                },
            }
            for index, (block, instruction) in enumerate(instructions)
        ],
    }


def run_entry_route_lean_source(route: RunEntryRoute) -> str:
    """Render the route as data checked by the generic Lean route kernel."""

    path = route.path
    blocks = (*path, route.loop)
    block_imports = "\n".join(
        "import StageA."
        f"{_BLOCK_FUNCTION_PREFIX}{route.function_ordinal:04d}"
        f"Block{ordinal:04d}"
        for ordinal in dict.fromkeys(block.ordinal for block in blocks)
    )
    step_count = len(route.controls)
    bulk_index = step_count
    loop_index = len(path)

    def block_term(block: _Block) -> str:
        return (
            "generatedNativeOperationFunctionReplay"
            f"{route.function_ordinal:04d}Block{block.ordinal:04d}"
            "Proof environment"
        )

    def block_prefix(block: _Block) -> str:
        return (
            "generatedNativeOperationFunctionReplay"
            f"{route.function_ordinal:04d}Block{block.ordinal:04d}"
        )

    def instruction_prefix(block: _Block, ordinal: int) -> str:
        return f"{block_prefix(block)}Instruction{ordinal:04d}"

    block_defs = "\n".join(
        f"""abbrev generatedRunEntryBlock{index}
    (environment : NativeWorldEnvironment) :=
  {block_term(block)}"""
        for index, block in enumerate(blocks)
    )
    block_list = ", ".join(
        f"generatedRunEntryBlock{index} environment"
        for index in range(len(blocks))
    )
    bulk_prefix = block_prefix(route.bulk)
    bulk_terminal_prefix = instruction_prefix(
        route.bulk, route.bulk.instruction_count - 1
    )
    bulk_terminal_behavior = f"{bulk_terminal_prefix}Behavior"
    bulk_terminal_outcome = f"{bulk_prefix}TerminalOutcome"
    bulk_running_trace = f"{bulk_prefix}RunningTrace"
    bulk_running_behaviors = f"{bulk_prefix}RunningBehaviors"
    if route.bulk.instruction_count > 1:
        bulk_prelude = f""".runningStaticPullback
    ({bulk_running_trace} environment)
    generatedRunEntryInvariant{bulk_index}
    generatedRunEntryBulkTerminalInvariant
    (by rfl)
    {bulk_running_behaviors}
    ({bulk_running_behaviors}Exact environment)
    (by decide +kernel)"""
        bulk_invariant = f"""abbrev generatedRunEntryInvariant{bulk_index} :
    NativeOperationInvariant :=
  (checkedNativeOperationPredicateBehaviorTracePullback?
    {bulk_running_behaviors}
    generatedRunEntryBulkTerminalInvariant).get
      (by decide +kernel)"""
    else:
        bulk_prelude = f""".noRunning
    generatedRunEntryBulkTerminalInvariant
    (by rfl)"""
        bulk_invariant = f"""abbrev generatedRunEntryInvariant{bulk_index} :
    NativeOperationInvariant :=
  generatedRunEntryBulkTerminalInvariant"""
    definitions = [
        f"""def generatedRunEntryBlocks
    (environment : NativeWorldEnvironment) :
    List (CheckedNativeOperationBlock
      (generatedClosedKernelOperationNativeProgram environment)) := [
  {block_list}
]

abbrev generatedRunEntryBulkSuccessor :
    NativeOperationLocalSuccessor :=
  (nativeOperationLocalSuccessorForTarget?
    {bulk_terminal_outcome}
    {route.loop.entry_rva}).get (by decide +kernel)

abbrev generatedRunEntryBulkTerminalInvariant :
    NativeOperationInvariant :=
  (nativeOperationSelectedTerminalInvariant?
    {bulk_terminal_behavior}
    {bulk_terminal_outcome}
    generatedRunEntryBulkSuccessor
    trivialNativeOperationInvariant).get
      (by decide +kernel)

theorem generatedRunEntryBulkTerminalInvariantTrivial :
    generatedRunEntryBulkTerminalInvariant =
      trivialNativeOperationInvariant := by
  decide +kernel

{bulk_invariant}"""
    ]
    for index in reversed(range(step_count)):
        source = blocks[index]
        target = blocks[index + 1]
        source_prefix = block_prefix(source)
        terminal_prefix = instruction_prefix(
            source, source.instruction_count - 1
        )
        terminal_behavior = f"{terminal_prefix}Behavior"
        terminal_outcome = f"{source_prefix}TerminalOutcome"
        running_trace = f"{source_prefix}RunningTrace"
        running_behaviors = f"{source_prefix}RunningBehaviors"
        if source.instruction_count > 1:
            prelude = f""".runningStaticPullback
    ({running_trace} environment)
    generatedRunEntryInvariant{index}
    generatedRunEntryTerminalInvariant{index}
    (by rfl)
    {running_behaviors}
    ({running_behaviors}Exact environment)
    (by decide +kernel)"""
            invariant_definition = f"""abbrev generatedRunEntryInvariant{index} :
    NativeOperationInvariant :=
  (checkedNativeOperationPredicateBehaviorTracePullback?
    {running_behaviors}
    generatedRunEntryTerminalInvariant{index}).get
      (by decide +kernel)"""
        else:
            prelude = f""".noRunning
    generatedRunEntryTerminalInvariant{index}
    (by rfl)"""
            invariant_definition = f"""abbrev generatedRunEntryInvariant{index} :
    NativeOperationInvariant :=
  generatedRunEntryTerminalInvariant{index}"""
        definitions.append(
            f"""abbrev generatedRunEntrySuccessor{index} :
    NativeOperationLocalSuccessor :=
  (nativeOperationLocalSuccessorForTarget?
    {terminal_outcome}
    {target.entry_rva}).get (by decide +kernel)

abbrev generatedRunEntryTerminalInvariant{index} :
    NativeOperationInvariant :=
  (nativeOperationSelectedTerminalInvariant?
    {terminal_behavior}
    {terminal_outcome}
    generatedRunEntrySuccessor{index}
    generatedRunEntryInvariant{index + 1}).get
      (by decide +kernel)

{invariant_definition}

abbrev generatedRunEntrySelectorInvariant{index} :
    NativeOperationInvariant :=
  (nativeOperationLocalSuccessorSelectorInvariant?
    {terminal_outcome}
    generatedRunEntrySuccessor{index}).get
      (by decide +kernel)

theorem generatedRunEntrySelectorInvariant{index}Checked
    (environment : NativeWorldEnvironment) :
    checkedNativeOperationLocalSuccessor
        generatedRunEntrySelectorInvariant{index}
        (generatedRunEntryBlock{index}
          environment).terminal.cutpoint.postcondition.outcome.expected
        generatedRunEntrySuccessor{index} =
      true := by
  rw [show
    (generatedRunEntryBlock{index}
      environment).terminal.cutpoint.postcondition.outcome =
        {terminal_outcome} by
    simpa [generatedRunEntryBlock{index}] using
      {terminal_outcome}Exact environment]
  decide +kernel

def generatedRunEntryStep{index}
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationPredicateBlockStep
      (generatedRunEntryBlocks environment)
      (generatedRunEntryBlock{index} environment)
      generatedRunEntryInvariant{index}
      (generatedRunEntryBlock{index + 1} environment)
      generatedRunEntryInvariant{index + 1} := {{
  sourceMember := by
    simp [generatedRunEntryBlocks]
  targetMember := by
    simp [generatedRunEntryBlocks]
  terminalInvariant := generatedRunEntryTerminalInvariant{index}
  prelude := {prelude}
  terminalEffect :=
    (operationInvariantEffect? {terminal_behavior}).get
      (by decide +kernel)
  terminalEffectExact := by
    rw [show
      (generatedRunEntryBlock{index} environment).terminal.replay.behavior =
        {terminal_behavior} by
      simpa [generatedRunEntryBlock{index}, {source_prefix}Proof,
        {terminal_prefix}Edge] using
        {terminal_prefix}BehaviorExact environment]
    decide +kernel
  terminalInvariantChecked := by
    decide +kernel
  successor := generatedRunEntrySuccessor{index}
  successorChecked := by
    rw [show
      (generatedRunEntryBlock{index}
        environment).terminal.cutpoint.postcondition.outcome =
          {terminal_outcome} by
      simpa [generatedRunEntryBlock{index}] using
        {terminal_outcome}Exact environment]
    decide +kernel
  statePreserving := by
    decide +kernel
  framesPreserved := by
    intro frames
    exact nativeOperationFramePreservingSuccessorCallFrames
      generatedRunEntrySuccessor{index} (by decide +kernel) frames
  alwaysRunningLocal := by
    rw [show
      (generatedRunEntryBlock{index}
        environment).terminal.cutpoint.postcondition.outcome =
          {terminal_outcome} by
      simpa [generatedRunEntryBlock{index}] using
        {terminal_outcome}Exact environment]
    decide +kernel
  graphInvariantChecked := by
    rfl
  targetRvaExact := by
    rw [show
      (generatedRunEntryBlock{index + 1} environment).entryRva =
        {target.entry_rva} by rfl]
    decide +kernel
  targetSlotExact := by
    rfl
}}"""
        )
    step_names = [
        f"generatedRunEntryStep{index}"
        for index in range(step_count)
    ]
    route_term = f".one _ _ _ _ ({step_names[-1]} environment)"
    for step_name in reversed(step_names[:-1]):
        route_term = (
            f".cons _ _ _ _ _ _ ({step_name} environment) ({route_term})"
        )
    definitions.append(
        f"""def generatedRunEntryControlRoute
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationPredicateRoute
      (generatedClosedKernelOperationNativeProgram environment)
      (generatedRunEntryBlocks environment)
      (generatedRunEntryBlock0 environment)
      generatedRunEntryInvariant0
      (generatedRunEntryBlock{step_count} environment)
      generatedRunEntryInvariant{step_count} :=
  {route_term}

theorem generatedRunEntryControlRouteChecked
    (environment : NativeWorldEnvironment) :
    Nonempty
      (CheckedNativeOperationPredicateRoute
        (generatedClosedKernelOperationNativeProgram environment)
        (generatedRunEntryBlocks environment)
        (generatedRunEntryBlock0 environment)
        generatedRunEntryInvariant0
        (generatedRunEntryBlock{step_count} environment)
        generatedRunEntryInvariant{step_count}) :=
  Nonempty.intro (generatedRunEntryControlRoute environment)

abbrev generatedRunEntryBulkOutcome : OutcomeExpr :=
  ({bulk_terminal_outcome}.expected).get (by decide +kernel)

abbrev generatedRunEntryBulkCopyAndContinuation : Prod BulkCopyExpr Nat :=
  (outcomeBulkCopy? generatedRunEntryBulkOutcome).get (by decide +kernel)

theorem generatedRunEntryBulkOutcomeIsCopy :
    generatedRunEntryBulkOutcome =
      .bulkCopy generatedRunEntryBulkCopyAndContinuation.1
        generatedRunEntryBulkCopyAndContinuation.2 := by
  decide +kernel

/-- Materialize the four REP operands next to the exact terminal-outcome
binding.  Downstream ABI certificates consume this opaque theorem instead of
re-evaluating the generated block and outcome projection. -/
theorem generatedRunEntryBulkCopyOperandsExact :
    generatedRunEntryBulkCopyAndContinuation.1 = {{
      destination := .inputReg .edi
      source := .inputReg .esi
      count := .inputReg .ecx
      direction := .bit initialSymbolic.eflagsExpression 10
    }} := by
  decide +kernel

def generatedRunEntryBulkStep
    (environment : NativeWorldEnvironment) :
    CheckedNativeOperationEffectfulBlockStep
      (generatedRunEntryBlocks environment)
      (generatedRunEntryBlock{bulk_index} environment)
      generatedRunEntryInvariant{bulk_index}
      (fun _ => True)
      (generatedRunEntryBlock{loop_index} environment)
      (fun _ => True) := {{
  sourceMember := by
    simp [generatedRunEntryBlocks]
  targetMember := by
    simp [generatedRunEntryBlocks]
  terminalInvariant := generatedRunEntryBulkTerminalInvariant
  prelude := {bulk_prelude}
  outcome := generatedRunEntryBulkOutcome
  outcomeExact := by
    rw [show
      (generatedRunEntryBlock{bulk_index}
        environment).terminal.cutpoint.postcondition.outcome =
          {bulk_terminal_outcome} by
      simpa [generatedRunEntryBlock{bulk_index}] using
        {bulk_terminal_outcome}Exact environment]
    decide +kernel
  successor := generatedRunEntryBulkSuccessor
  successorChecked := by
    decide +kernel
  framesPreserved := by
    intro frames
    exact nativeOperationFramePreservingSuccessorCallFrames
      generatedRunEntryBulkSuccessor (by decide +kernel) frames
  alwaysRunningLocal := by
    rw [show
      (generatedRunEntryBlock{bulk_index}
        environment).terminal.cutpoint.postcondition.outcome =
          {bulk_terminal_outcome} by
      simpa [generatedRunEntryBlock{bulk_index}] using
        {bulk_terminal_outcome}Exact environment]
    decide +kernel
  graphInvariantChecked := by
    rfl
  targetRvaExact := by
    rw [show
      (generatedRunEntryBlock{loop_index} environment).entryRva =
        {route.loop.entry_rva} by rfl]
    decide +kernel
  targetSlotExact := by
    rfl
  targetRelationHolds := by
    intro state sourceHolds sourceRelationHolds
    trivial
}}

/-- The exact bulk block strengthened with the represented engine-state
relation used by Run.  Address and range facts remain explicit source
premises; the generic kernel proves the byte transport once. -/
def generatedRunEntryBulkEngineStep
    (environment : NativeWorldEnvironment)
    (layout : EngineLayout) (sourceBase destinationBase : Word)
    (logical : InterpreterMachine) (sourceRva : Nat) :
    CheckedNativeOperationEffectfulBlockStep
      (generatedRunEntryBlocks environment)
      (generatedRunEntryBlock{bulk_index} environment)
      generatedRunEntryInvariant{bulk_index}
      (ForwardEngineBulkCopySourceFacts
        (generatedRunEntryBlock{bulk_index} environment)
        generatedRunEntryBulkCopyAndContinuation.1 layout sourceBase
        destinationBase logical sourceRva)
      (generatedRunEntryBlock{loop_index} environment)
      (EngineStateHolds layout destinationBase logical sourceRva) :=
  checkedNativeOperationEffectfulBlockStepWithForwardEngineState
    (generatedRunEntryBulkStep environment)
    generatedRunEntryBulkCopyAndContinuation.1
    generatedRunEntryBulkCopyAndContinuation.2
    generatedRunEntryBulkOutcomeIsCopy
    layout sourceBase destinationBase logical sourceRva

theorem generatedRunEntryToLoopPath
    (environment : NativeWorldEnvironment)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : generatedRunEntryInvariant0.Holds state) :
    NonemptyRelatedPath
      (generatedClosedKernelOperationNativeProgram environment).transitionSystem
      (.running
        (generatedRunEntryBlock0 environment).entryRva
        (generatedRunEntryBlock0 environment).entrySlot
        state calls eventIndex events world)
      []
      (.running
        (generatedRunEntryBlock{loop_index} environment).entryRva
        (generatedRunEntryBlock{loop_index} environment).entrySlot
        ((generatedRunEntryBulkStep environment).targetState
          (runCheckedNativeOperationPredicateRoute
            (generatedRunEntryControlRoute environment) state))
        calls eventIndex events world) := by
  let prefixResult :=
    (generatedRunEntryControlRoute environment).executeExact
      state calls eventIndex events world sourceHolds
  let bulkResult :=
    (generatedRunEntryBulkStep environment).execute
      (runCheckedNativeOperationPredicateRoute
        (generatedRunEntryControlRoute environment) state)
      calls eventIndex events world prefixResult.2 True.intro
  exact prefixResult.1.trans bulkResult.1

theorem generatedRunEntryToLoopEnginePath
    (environment : NativeWorldEnvironment)
    (layout : EngineLayout) (sourceBase destinationBase : Word)
    (logical : InterpreterMachine) (sourceRva : Nat)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (sourceHolds : generatedRunEntryInvariant0.Holds state)
    (bulkFacts : ForwardEngineBulkCopySourceFacts
      (generatedRunEntryBlock{bulk_index} environment)
      generatedRunEntryBulkCopyAndContinuation.1 layout sourceBase
      destinationBase logical sourceRva
      (runCheckedNativeOperationPredicateRoute
        (generatedRunEntryControlRoute environment) state)) :
    NonemptyRelatedPath
      (generatedClosedKernelOperationNativeProgram environment).transitionSystem
      (.running
        (generatedRunEntryBlock0 environment).entryRva
        (generatedRunEntryBlock0 environment).entrySlot
        state calls eventIndex events world)
      []
      (.running
        (generatedRunEntryBlock{loop_index} environment).entryRva
        (generatedRunEntryBlock{loop_index} environment).entrySlot
        ((generatedRunEntryBulkEngineStep environment layout sourceBase
          destinationBase logical sourceRva).targetState
            (runCheckedNativeOperationPredicateRoute
              (generatedRunEntryControlRoute environment) state))
        calls eventIndex events world) /\\
    EngineStateHolds layout destinationBase logical sourceRva
      ((generatedRunEntryBulkEngineStep environment layout sourceBase
        destinationBase logical sourceRva).targetState
          (runCheckedNativeOperationPredicateRoute
            (generatedRunEntryControlRoute environment) state)) := by
  let prefixResult :=
    (generatedRunEntryControlRoute environment).executeExact
      state calls eventIndex events world sourceHolds
  let bulkResult :=
    (generatedRunEntryBulkEngineStep environment layout sourceBase
      destinationBase logical sourceRva).execute
        (runCheckedNativeOperationPredicateRoute
          (generatedRunEntryControlRoute environment) state)
        calls eventIndex events world prefixResult.2 bulkFacts
  exact And.intro (prefixResult.1.trans bulkResult.1) bulkResult.2"""
    )
    definitions.append(
        f"""/-- Build the exact bulk-copy source certificate from an engine
state at Run entry and state-indexed footprint evidence for the decoded
control prefix.  This is the reusable bridge from cdecl entry facts to the
first semantic loop cutpoint. -/
theorem generatedRunEntryBulkSourceFactsOfEntry
    (environment : NativeWorldEnvironment)
    (layout : EngineLayout) (sourceBase destinationBase : Word)
    (logical : InterpreterMachine) (sourceRva : Nat)
    (state : MachineState)
    (entryHolds :
      EngineStateHolds layout sourceBase logical sourceRva state)
    (sourceRangeFits :
      sourceBase.toNat + layout.stateSize < 2 ^ 32)
    (controlDisjoint :
      checkedNativeOperationPredicateRouteFootprintsDisjointAt
        (generatedRunEntryControlRoute environment)
        (CandidateWordRange sourceBase layout.stateSize)
        state)
    (bulkDisjoint :
      checkedNativeOperationBlockFootprintsDisjointAt
        (generatedRunEntryBlock{bulk_index} environment)
        (CandidateWordRange sourceBase layout.stateSize)
        (runCheckedNativeOperationPredicateRoute
          (generatedRunEntryControlRoute environment) state))
    (sourceExact :
      sourceBase =
        generatedRunEntryBulkCopyAndContinuation.1.source.eval
          ((generatedRunEntryBlock{bulk_index}
            environment).terminalState
              (runCheckedNativeOperationPredicateRoute
                (generatedRunEntryControlRoute environment) state)))
    (destinationExact :
      destinationBase =
        generatedRunEntryBulkCopyAndContinuation.1.destination.eval
          ((generatedRunEntryBlock{bulk_index}
            environment).terminalState
              (runCheckedNativeOperationPredicateRoute
                (generatedRunEntryControlRoute environment) state)))
    (directionExact :
      generatedRunEntryBulkCopyAndContinuation.1.direction.eval
          ((generatedRunEntryBlock{bulk_index}
            environment).terminalState
              (runCheckedNativeOperationPredicateRoute
                (generatedRunEntryControlRoute environment) state)) =
        false)
    (destinationFits :
      (generatedRunEntryBulkCopyAndContinuation.1.destination.eval
          ((generatedRunEntryBlock{bulk_index}
            environment).terminalState
              (runCheckedNativeOperationPredicateRoute
                (generatedRunEntryControlRoute environment) state))).toNat +
          (generatedRunEntryBulkCopyAndContinuation.1.count.eval
            ((generatedRunEntryBlock{bulk_index}
              environment).terminalState
                (runCheckedNativeOperationPredicateRoute
                  (generatedRunEntryControlRoute environment) state))).toNat *
            4 < 2 ^ 32)
    (sourceFits :
      (generatedRunEntryBulkCopyAndContinuation.1.source.eval
          ((generatedRunEntryBlock{bulk_index}
            environment).terminalState
              (runCheckedNativeOperationPredicateRoute
                (generatedRunEntryControlRoute environment) state))).toNat +
          (generatedRunEntryBulkCopyAndContinuation.1.count.eval
            ((generatedRunEntryBlock{bulk_index}
              environment).terminalState
                (runCheckedNativeOperationPredicateRoute
                  (generatedRunEntryControlRoute environment) state))).toNat *
            4 < 2 ^ 32)
    (disjoint :
      (generatedRunEntryBulkCopyAndContinuation.1.source.eval
          ((generatedRunEntryBlock{bulk_index}
            environment).terminalState
              (runCheckedNativeOperationPredicateRoute
                (generatedRunEntryControlRoute environment) state))).toNat +
            (generatedRunEntryBulkCopyAndContinuation.1.count.eval
              ((generatedRunEntryBlock{bulk_index}
                environment).terminalState
                  (runCheckedNativeOperationPredicateRoute
                    (generatedRunEntryControlRoute environment) state))).toNat *
              4 <=
          (generatedRunEntryBulkCopyAndContinuation.1.destination.eval
            ((generatedRunEntryBlock{bulk_index}
              environment).terminalState
                (runCheckedNativeOperationPredicateRoute
                  (generatedRunEntryControlRoute environment) state))).toNat \\/
        (generatedRunEntryBulkCopyAndContinuation.1.destination.eval
          ((generatedRunEntryBlock{bulk_index}
            environment).terminalState
              (runCheckedNativeOperationPredicateRoute
                (generatedRunEntryControlRoute environment) state))).toNat +
            (generatedRunEntryBulkCopyAndContinuation.1.count.eval
              ((generatedRunEntryBlock{bulk_index}
                environment).terminalState
                  (runCheckedNativeOperationPredicateRoute
                    (generatedRunEntryControlRoute environment) state))).toNat *
              4 <=
          (generatedRunEntryBulkCopyAndContinuation.1.source.eval
            ((generatedRunEntryBlock{bulk_index}
              environment).terminalState
                (runCheckedNativeOperationPredicateRoute
                  (generatedRunEntryControlRoute environment) state))).toNat)
    (covers :
      layout.stateSize <=
        (generatedRunEntryBulkCopyAndContinuation.1.count.eval
          ((generatedRunEntryBlock{bulk_index}
            environment).terminalState
              (runCheckedNativeOperationPredicateRoute
                (generatedRunEntryControlRoute environment) state))).toNat * 4) :
    ForwardEngineBulkCopySourceFacts
      (generatedRunEntryBlock{bulk_index} environment)
      generatedRunEntryBulkCopyAndContinuation.1 layout sourceBase
      destinationBase logical sourceRva
      (runCheckedNativeOperationPredicateRoute
        (generatedRunEntryControlRoute environment) state) := by
  let prefixState :=
    runCheckedNativeOperationPredicateRoute
      (generatedRunEntryControlRoute environment) state
  have controlFrame :=
    checkedNativeOperationPredicateRoute_memoryAgreesOn_at
      (generatedRunEntryControlRoute environment)
      (CandidateWordRange sourceBase layout.stateSize)
      state controlDisjoint
  have bulkFrame :=
    checkedNativeOperationBlock_memoryAgreesOn_at
      (generatedRunEntryBlock{bulk_index} environment)
      (CandidateWordRange sourceBase layout.stateSize)
      prefixState bulkDisjoint
  have memoryFrame := controlFrame.trans bulkFrame
  have layoutValid : layout.Valid :=
    StageA.Relational.InterpreterKernelEngineCopy.EngineStateHolds.layoutValid
      entryHolds
  have representationFrame :=
    memoryFrame.mono
      (candidateAddressObserved_engineRepAt_in_wordRange
        layout sourceBase state.x87Semantics layoutValid sourceRangeFits)
  have controlSemantics :=
    checkedNativeOperationPredicateRoute_x87Semantics
      (generatedRunEntryControlRoute environment) state
  have bulkSemantics :=
    checkedNativeOperationBlock_after_x87Semantics
      (generatedRunEntryBlock{bulk_index} environment) prefixState
  have semantics :
      ((generatedRunEntryBlock{bulk_index}
        environment).terminal.after
          ((generatedRunEntryBlock{bulk_index}
            environment).terminalState prefixState)).x87Semantics =
        state.x87Semantics :=
    bulkSemantics.trans controlSemantics
  exact {{
    holds := EngineStateHolds.preserveRepresentation entryHolds
      representationFrame.candidateMemoryAgreesOnRepresentation semantics
    sourceExact := sourceExact
    destinationExact := destinationExact
    directionExact := directionExact
    destinationFits := destinationFits
    sourceFits := sourceFits
    disjoint := disjoint
    covers := covers
  }}

#print axioms generatedRunEntryBulkSourceFactsOfEntry"""
    )
    return f"""import StageA.RelationalInterpreterKernelOperationPredicateRoute
import StageA.RelationalInterpreterKernelOperationEffectChecker
import StageA.RelationalInterpreterKernelEngineCopy
import StageA.RelationalInterpreterKernelOperationMemoryRoute
import StageA.{_OPERATION_CANDIDATE_CORE_MODULE}
{block_imports}

namespace StageA.GeneratedRelational.InterpreterKernelOperationInstantiation

open StageA.Formal StageA.Relational
open StageA.Relational.Engine
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationEffectChecker
open StageA.Relational.InterpreterKernelEngineCopy
open StageA.Relational.InterpreterKernelOperationFrameChecker
open StageA.Relational.InterpreterKernelOperationGraphChecker
open StageA.Relational.InterpreterKernelOperationMemoryRoute
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationPredicateRoute
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelOperationCandidate

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{block_defs}

{chr(10).join(definitions)}

#print axioms StageA.GeneratedRelational.InterpreterKernelOperationInstantiation.generatedRunEntryControlRouteChecked
#print axioms StageA.GeneratedRelational.InterpreterKernelOperationInstantiation.generatedRunEntryToLoopPath
#print axioms StageA.GeneratedRelational.InterpreterKernelOperationInstantiation.generatedRunEntryToLoopEnginePath

end StageA.GeneratedRelational.InterpreterKernelOperationInstantiation
"""


def write_run_entry_route_bundle(
    *,
    operation_manifest: Path | str,
    out: Path | str,
) -> RunEntryRoute:
    route = build_run_entry_route(operation_manifest)
    output = Path(out)
    lean_output = output / "StageA"
    lean_output.mkdir(parents=True, exist_ok=True)
    (lean_output / f"{INTERPRETER_KERNEL_RUN_ENTRY_ROUTE_LEAN_MODULE}.lean").write_text(
        run_entry_route_lean_source(route),
        encoding="ascii",
    )
    (output / INTERPRETER_KERNEL_RUN_ENTRY_ROUTE_MANIFEST).write_text(
        json.dumps(route.payload(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / INTERPRETER_KERNEL_RUN_ENTRY_BEHAVIOR_REQUEST).write_text(
        json.dumps(
            run_entry_behavior_request_payload(route),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return route


__all__ = [
    "INTERPRETER_KERNEL_RUN_ENTRY_ROUTE_FORMAT",
    "INTERPRETER_KERNEL_RUN_ENTRY_ROUTE_LEAN_MODULE",
    "INTERPRETER_KERNEL_RUN_ENTRY_ROUTE_MANIFEST",
    "INTERPRETER_KERNEL_RUN_ENTRY_BEHAVIOR_REQUEST",
    "InterpreterKernelRunEntryRouteError",
    "RunEntryRoute",
    "build_run_entry_route",
    "run_entry_behavior_request_payload",
    "run_entry_route_lean_source",
    "write_run_entry_route_bundle",
]
