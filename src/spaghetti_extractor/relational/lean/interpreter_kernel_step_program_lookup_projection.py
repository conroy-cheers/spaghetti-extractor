"""Generate the checked Step-to-ProgramLookup ABI projection.

The candidate side extractor proposes one behavior per instruction.  The
materialization module binds every proposal to exact PE decoding.  This module
then projects only the stack, source word, direction flag, and write footprint
needed to establish the nested ProgramLookup cdecl frame.
"""

from __future__ import annotations

from pathlib import Path

from .interpreter_kernel_step_world_program_lookup import (
    InterpreterKernelStepWorldProgramLookupPlan,
)


INTERPRETER_STEP_PROGRAM_LOOKUP_PROJECTION_LEAN_MODULE = (
    "GeneratedRelationalInterpreterStepProgramLookupProjection"
)


def _edge_prefix(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
    instruction: int,
) -> str:
    return (
        "generatedNativeOperationFunctionReplay"
        f"{plan.step_function_ordinal:04d}"
        f"Block{plan.call_block_ordinal:04d}"
        f"Instruction{instruction:04d}Edge"
    )


def _behavior(instruction: int) -> str:
    return (
        "generatedInterpreterStepProgramLookupCall"
        f"Instruction{instruction:04d}MaterializedBehavior"
    )


def _behavior_exact(instruction: int) -> str:
    return f"{_behavior(instruction)}EdgeBehaviorExact"


def _state(index: int) -> str:
    return f"generatedInterpreterStepProgramLookupProjectionState{index:04d}"


def _state_handle(index: int) -> str:
    return f"{_state(index)}Handle"


def _state_exact(index: int) -> str:
    return f"{_state(index)}Exact"


def _depth_exact(depth: int) -> str:
    return (
        "generatedInterpreterStepProgramLookupProjection"
        f"Depth{depth:04d}Exact"
    )


def _disjoint_exact(depth: int) -> str:
    return (
        "generatedInterpreterStepProgramLookupProjection"
        f"SourceWordDisjointDepth{depth:04d}"
    )


def _stack_offset_exact(offset: int, depth: int) -> str:
    return (
        "generatedInterpreterStepProgramLookupProjection"
        f"StackOffset{offset:04d}Depth{depth:04d}Exact"
    )


def _arithmetic_helpers() -> str:
    depth_expressions = {
        4: "base + BitVec.ofNat 32 4294967292",
        8: "base - word32 4 + BitVec.ofNat 32 4294967292",
        12: "base - word32 8 + BitVec.ofNat 32 4294967292",
        16: "base - word32 12 + BitVec.ofNat 32 4294967292",
        2572: "base - word32 16 - word32 2556",
        2576: "base - word32 2572 + BitVec.ofNat 32 4294967292",
    }
    helpers = [
        f"""private theorem {_depth_exact(depth)} (base : Word) :
    {expression} = base - word32 {depth} := by
  simp only [word32, BitVec.sub_eq_add_neg, BitVec.add_assoc]
  apply congrArg (fun offset : Word => base + offset)
  decide"""
        for depth, expression in depth_expressions.items()
    ]
    for depth in (4, 8, 12, 16):
        helpers.append(
            f"""private theorem {_disjoint_exact(depth)} (base : Word) :
    wordOffsetsDisjoint
      (base + word32 16) (base - word32 {depth}) = true := by
  simpa only [BitVec.sub_eq_add_neg] using
    wordOffsetsDisjoint_add_left base (word32 16) (-word32 {depth})
      (by decide)"""
        )
    for offset, depth in (
        (2592, 4),
        (2588, 8),
        (2584, 12),
        (2580, 16),
        (24, 2572),
        (20, 2576),
    ):
        helpers.append(
            f"""private theorem {_stack_offset_exact(offset, depth)}
    (base : Word) :
    base - word32 2596 + word32 {offset} =
      base - word32 {depth} := by
  simp only [word32, BitVec.sub_eq_add_neg, BitVec.add_assoc]
  apply congrArg (fun shifted : Word => base + shifted)
  decide"""
        )
    helpers.extend(
        [
            """private theorem generatedInterpreterStepProgramLookupProjectionEaxAddressExact
    (base : Word) :
    base - word32 4 + word32 20 = base + word32 16 := by
  simp only [word32, BitVec.sub_eq_add_neg, BitVec.add_assoc]
  apply congrArg (fun shifted : Word => base + shifted)
  decide""",
            """private theorem generatedInterpreterStepProgramLookupProjectionSourceAddressExact
    (base : Word) :
    base - word32 2576 + word32 4 = base - word32 2572 := by
  simp only [word32, BitVec.sub_eq_add_neg, BitVec.add_assoc]
  apply congrArg (fun shifted : Word => base + shifted)
  decide""",
            """private theorem generatedInterpreterStepProgramLookupProjectionSourceReturnDisjoint
    (base : Word) :
    wordOffsetsDisjoint
      (base - word32 2572) (base - word32 2576) = true := by
  simpa only [BitVec.sub_eq_add_neg] using
    wordOffsetsDisjoint_add_left base (-word32 2572) (-word32 2576)
      (by decide)""",
            """private theorem generatedInterpreterStepProgramLookupProjectionFrameByteExact
    (base : Word) (offset : Nat) :
    programLookupFrameByte (base - word32 2576) offset =
      base - word32 2596 + word32 offset := by
  unfold programLookupFrameByte
  rw [show 2 ^ 32 - 20 + offset = (2 ^ 32 - 20) + offset by rfl,
    BitVec.ofNat_add]
  simp only [word32, BitVec.sub_eq_add_neg, BitVec.add_assoc]
  rw [← BitVec.add_assoc (-BitVec.ofNat 32 2576)
    (BitVec.ofNat 32 (2 ^ 32 - 20)) (BitVec.ofNat 32 offset)]
  apply congrArg (fun shifted : Word => base + shifted)
  apply congrArg (fun offsetBase : Word =>
    offsetBase + BitVec.ofNat 32 offset)
  decide""",
        ]
    )
    return "\n\n".join(helpers)


def _state_definitions(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
) -> str:
    definitions = [
        f"""def {_state(0)}
    (_environment : NativeWorldEnvironment) (state : MachineState) :
    MachineState :=
  state"""
    ]
    for instruction in range(plan.call_block_instruction_count):
        source = _state(instruction)
        target = _state(instruction + 1)
        edge = _edge_prefix(plan, instruction)
        definitions.append(
            f"""opaque {_state_handle(instruction + 1)}
    (environment : NativeWorldEnvironment) (state : MachineState) :
    {{ next : MachineState //
      next = ({edge} environment).after
        ({source} environment state) }} :=
  Subtype.mk (({edge} environment).after ({source} environment state)) rfl

def {target}
    (environment : NativeWorldEnvironment) (state : MachineState) :
    MachineState :=
  ({_state_handle(instruction + 1)} environment state).val

theorem {_state_exact(instruction + 1)}
    (environment : NativeWorldEnvironment) (state : MachineState) :
    {target} environment state =
      ({edge} environment).after ({source} environment state) :=
  ({_state_handle(instruction + 1)} environment state).property"""
        )
    return "\n\n".join(definitions)


def _word_checked(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
    instruction: int,
    *,
    source_state: str,
    source_facts: str | None,
    entry_esp_exact: str | None,
    write_depth: int | None,
) -> str:
    behavior = _behavior(instruction)
    exact = _behavior_exact(instruction)
    if write_depth is None:
        return f"""    exact symbolicWritesAvoidWordChecked_nil
      (frame.entryEsp + word32 16)
      ({source_state} environment state)"""
    rewrite = (
        entry_esp_exact
        if entry_esp_exact is not None
        else f"{source_facts}.espExact"
    )
    source_unfold = f", {source_state}" if source_facts is None else ""
    return f"""    apply symbolicWritesAvoidWordChecked_singleton
      (concreteAddress := frame.entryEsp - word32 {write_depth})
    · simp only [{behavior}, Expr.eval, Registers.get{source_unfold}]
      rw [{rewrite}]
      exact {_depth_exact(write_depth)} frame.entryEsp
    · exact {_disjoint_exact(write_depth)} frame.entryEsp"""


def _frame_projection_theorem(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
    instruction: int,
    target_depth: int,
    *,
    source_depth: int,
    source_type: str,
    source_facts: str,
    write_depth: int | None,
    source_has_frame: bool = True,
) -> str:
    source = _state(instruction)
    target = _state(instruction + 1)
    edge = _edge_prefix(plan, instruction)
    behavior = _behavior(instruction)
    exact = _behavior_exact(instruction)
    theorem_kind = (
        "CheckedNativeOperationStoppedEdge"
        if instruction == plan.call_block_instruction_count - 1
        else "CheckedNativeOperationRunningEdge"
    )
    word_checked = _word_checked(
        plan,
        instruction,
        source_state=source,
        source_facts=source_facts if source_has_frame else None,
        entry_esp_exact=(
            f"{source_facts}.espExact" if not source_has_frame else None
        ),
        write_depth=write_depth,
    )
    ebp_rewrites = (
        f"{source_facts}.ebpExact"
        if source_has_frame
        else f"{source_facts}.espExact"
    )
    if source_depth == target_depth:
        esp_proof = f"    exact {source_facts}.espExact"
    else:
        esp_proof = f"""    rw [{source_facts}.espExact]
    exact {_depth_exact(target_depth)} frame.entryEsp"""
    return f"""theorem generatedInterpreterStepProgramLookupProjectionState{instruction + 1:04d}Facts
    (environment : NativeWorldEnvironment) (state : MachineState)
    (frame : KernelOperationABIFrame)
    (prior : {source_type}) :
    FrameWordDirectionProjection
      ({target} environment state)
      (frame.entryEsp - word32 {target_depth})
      (frame.entryEsp - word32 4)
      (frame.entryEsp + word32 16)
      (word32 sourceRva) := by
  rw [{_state_exact(instruction + 1)}]
  apply
    {theorem_kind}.after_frameWordDirectionProjection
      ({edge} environment) ({source} environment state)
  · rw [{exact} environment]
    simp only [{behavior}, Expr.eval, Registers.get]
{esp_proof}
  · rw [{exact} environment]
    simp only [{behavior}, Expr.eval, Registers.get]
    exact {ebp_rewrites}
  · rw [{exact} environment]
{word_checked}
  · rw [{exact} environment]
    rfl
  · exact {source_facts}.wordExact
  · exact {source_facts}.directionClear"""


def _running_inside(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
    instruction: int,
    write_offset: int | None,
    write_depth: int | None,
    source_facts: str | None,
) -> str:
    source = _state(instruction)
    edge = _edge_prefix(plan, instruction)
    behavior = _behavior(instruction)
    exact = _behavior_exact(instruction)
    if write_offset is None or write_depth is None:
        return f"""  have inside{instruction} :
      symbolicBehaviorWritesInside
        (addressInSpan abi.parameters.writableWorkspace)
        ({edge} environment).replay.behavior
        ({source} environment state) := by
    apply symbolicBehaviorWritesInside_of_writes_nil
    rw [{exact} environment]
    rfl"""
    source_unfold = f", {source}" if source_facts is None else ""
    source_esp_exact = (
        "entryEspExact"
        if source_facts is None
        else f"{source_facts}.espExact"
    )
    if instruction == 7:
        address_proof = f"""      change
        ({source} environment state).registers.esp =
          frame.entryEsp - word32 {write_depth}
      exact {source_esp_exact}"""
    else:
        source_expression = (
            "state"
            if source_facts is None
            else f"({source} environment state)"
        )
        address_proof = f"""      change
        {source_expression}.registers.esp +
            BitVec.ofNat 32 4294967292 =
          frame.entryEsp - word32 {write_depth}
      rw [{source_esp_exact}]
      exact {_depth_exact(write_depth)} frame.entryEsp"""
    return f"""  have inside{instruction} :
      symbolicBehaviorWritesInside
        (addressInSpan abi.parameters.writableWorkspace)
        ({edge} environment).replay.behavior
        ({source} environment state) := by
    apply symbolicBehaviorWritesInside_of_writes_singleton
      (address := ({behavior}.writes.getD 0
        (.constant 0, .constant 0)).1)
      (value := ({behavior}.writes.getD 0
        (.constant 0, .constant 0)).2)
      (concreteAddress := frame.entryEsp - word32 {write_depth})
    · rw [{exact} environment]
      rfl
    · simp only [{behavior}{source_unfold}]
{address_proof}
    · apply addressRangeInSpan_containsWordBytes
      have range :=
        fits.addressRangeInWorkspace generatedInterpreterStepProgramLookupStackUse
          frame abi.parameters.writableWorkspace {write_offset} 4 (by decide)
      have addressExact :=
        {_stack_offset_exact(write_offset, write_depth)} frame.entryEsp
      simp only [generatedInterpreterStepProgramLookupStackUse] at range
      rw [addressExact] at range
      exact range"""


def interpreter_step_program_lookup_projection_source(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
) -> str:
    if (
        plan.call_block_instruction_count != 9
        or plan.step_entry_rva != plan.call_block_entry_rva
        or plan.prefix_kind != "direct_entry_call"
    ):
        raise ValueError(
            "Step ProgramLookup projection requires the checked direct "
            "nine-instruction entry block"
        )
    states = _state_definitions(plan)
    arithmetic_helpers = _arithmetic_helpers()
    edge = lambda instruction: _edge_prefix(plan, instruction)
    state2_type = f"""StackWordDirectionProjection
      ({_state(1)} environment state)
      (frame.entryEsp - word32 4)
      (frame.entryEsp + word32 16)
      (word32 sourceRva)"""
    frame_projections = [
        _frame_projection_theorem(
            plan,
            1,
            4,
            source_depth=4,
            source_type=state2_type,
            source_facts="prior",
            write_depth=None,
            source_has_frame=False,
        )
    ]
    depths = {2: 8, 3: 12, 4: 16, 5: 2572, 6: 2572}
    write_depths = {2: 8, 3: 12, 4: 16}
    for instruction, target_depth in depths.items():
        source_depth = 4 if instruction == 2 else depths[instruction - 1]
        source_type = f"""FrameWordDirectionProjection
      ({_state(instruction)} environment state)
      (frame.entryEsp - word32 {source_depth})
      (frame.entryEsp - word32 4)
      (frame.entryEsp + word32 16)
      (word32 sourceRva)"""
        frame_projections.append(
            _frame_projection_theorem(
                plan,
                instruction,
                target_depth,
                source_depth=source_depth,
                source_type=source_type,
                source_facts="prior",
                write_depth=write_depths.get(instruction),
            )
        )
    write_offsets = {
        0: (2592, 4, None),
        1: (None, None, None),
        2: (2588, 8, "state2"),
        3: (2584, 12, "state3"),
        4: (2580, 16, "state4"),
        5: (None, None, None),
        6: (None, None, None),
        7: (24, 2572, "state7"),
        8: (20, 2576, "state8"),
    }
    inside_proofs = "\n\n".join(
        _running_inside(plan, instruction, *write_offsets[instruction])
        for instruction in range(9)
    )
    return f"""import StageA.RelationalInterpreterKernelOperationMemoryRoute
import StageA.RelationalInterpreterKernelOperationNestedABIFrame
import StageA.GeneratedRelationalInterpreterStepProgramLookupCallBehaviors

namespace StageA.GeneratedRelational.InterpreterStepProgramLookupProjection

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelSummary
open StageA.Relational.InterpreterKernelOperationABIFrame
open StageA.Relational.InterpreterKernelOperationMemoryRoute
open StageA.Relational.InterpreterKernelOperationNestedABIFrame
open StageA.Relational.InterpreterKernelOperationProjection
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelOperationCandidate
open StageA.GeneratedRelational.InterpreterKernelOperationInstantiation

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedInterpreterStepProgramLookupStackUse :
    KernelOperationABIStackUse := {{
  belowEntry := 2596
  atOrAboveEntry := 20
}}

{arithmetic_helpers}

{states}

theorem generatedInterpreterStepProgramLookupProjectionState0001Facts
    (environment : NativeWorldEnvironment) (state : MachineState)
    (frame : KernelOperationABIFrame)
    (entryEspExact : state.registers.esp = frame.entryEsp)
    (sourceWord :
      Memory.read32 state.memory (frame.entryEsp + word32 16) = word32 sourceRva)
    (directionClear : DirectionFlagClear state) :
    StackWordDirectionProjection
      ({_state(1)} environment state)
      (frame.entryEsp - word32 4)
      (frame.entryEsp + word32 16) (word32 sourceRva) := by
  rw [{_state_exact(1)}]
  apply
    CheckedNativeOperationRunningEdge.after_stackWordDirectionProjection
      ({edge(0)} environment) ({_state(0)} environment state)
  · rw [{_behavior_exact(0)} environment]
    simp only [{_behavior(0)}, Expr.eval, Registers.get, {_state(0)}]
    rw [entryEspExact]
    exact {_depth_exact(4)} frame.entryEsp
  · rw [{_behavior_exact(0)} environment]
    apply symbolicWritesAvoidWordChecked_singleton
      (concreteAddress := frame.entryEsp - word32 4)
    · simp only [{_behavior(0)}, Expr.eval, Registers.get, {_state(0)}]
      rw [entryEspExact]
      exact {_depth_exact(4)} frame.entryEsp
    · exact {_disjoint_exact(4)} frame.entryEsp
  · rw [{_behavior_exact(0)} environment]
    rfl
  · exact sourceWord
  · exact directionClear

{chr(10).join(frame_projections)}

theorem generatedInterpreterStepProgramLookupProjectionState0007Eax
    (environment : NativeWorldEnvironment) (state : MachineState)
    (frame : KernelOperationABIFrame)
    (prior : FrameWordDirectionProjection
      ({_state(6)} environment state)
      (frame.entryEsp - word32 2572)
      (frame.entryEsp - word32 4)
      (frame.entryEsp + word32 16) (word32 sourceRva)) :
    ({_state(7)} environment state).registers.eax = word32 sourceRva := by
  rw [{_state_exact(7)}]
  change
    (({edge(6)} environment).after
      ({_state(6)} environment state)).registers.get .eax =
        word32 sourceRva
  rw [CheckedNativeOperationRunningEdge.after_register]
  rw [{_behavior_exact(6)} environment]
  simp only [{_behavior(6)}, Registers.get, Expr.eval, prior.ebpExact]
  change
    Memory.read32 ({_state(6)} environment state).memory
        (frame.entryEsp - word32 4 + word32 20) =
      word32 sourceRva
  have addressExact :
      frame.entryEsp - word32 4 + word32 20 =
        frame.entryEsp + word32 16 := by
    exact
      generatedInterpreterStepProgramLookupProjectionEaxAddressExact
        frame.entryEsp
  rw [addressExact]
  exact prior.wordExact

theorem generatedInterpreterStepProgramLookupProjectionState0008Facts
    (environment : NativeWorldEnvironment) (state : MachineState)
    (frame : KernelOperationABIFrame)
    (fits : generatedInterpreterStepProgramLookupStackUse.Fits frame workspace)
    (prior : FrameWordDirectionProjection
      ({_state(7)} environment state)
      (frame.entryEsp - word32 2572)
      (frame.entryEsp - word32 4)
      (frame.entryEsp + word32 16) (word32 sourceRva))
    (eaxExact :
      ({_state(7)} environment state).registers.eax = word32 sourceRva) :
    FrameWordDirectionProjection
        ({_state(8)} environment state)
        (frame.entryEsp - word32 2572)
        (frame.entryEsp - word32 4)
        (frame.entryEsp - word32 2572) (word32 sourceRva) := by
  have argumentFits :
      (frame.entryEsp - word32 2572).toNat + 4 <= 2 ^ 32 := by
    have fit :=
      fits.addressBytesFit generatedInterpreterStepProgramLookupStackUse frame
        workspace 24 4 (by decide)
    have addressExact :=
      {_stack_offset_exact(24, 2572)} frame.entryEsp
    simp only [generatedInterpreterStepProgramLookupStackUse] at fit
    rw [addressExact] at fit
    exact fit
  rw [{_state_exact(8)}]
  constructor
  · constructor
    · change
        (({edge(7)} environment).after
          ({_state(7)} environment state)).registers.get .esp =
            frame.entryEsp - word32 2572
      rw [CheckedNativeOperationRunningEdge.after_register,
        {_behavior_exact(7)} environment]
      simpa only [{_behavior(7)}, Registers.get, Expr.eval] using prior.espExact
    · rw [CheckedNativeOperationRunningEdge.after_memory,
        {_behavior_exact(7)} environment]
      simp only [{_behavior(7)}, applyWrites, List.foldl_cons,
        List.foldl_nil, Expr.eval, Registers.get, prior.espExact, eaxExact]
      exact Memory.read32_write32_same_of_fits
        ({_state(7)} environment state).memory
        (frame.entryEsp - word32 2572) (word32 sourceRva) argumentFits
    · rw [CheckedNativeOperationRunningEdge.after_eflags_extract_df,
        {_behavior_exact(7)} environment]
      simpa only [{_behavior(7)}, Option.getD, inputEflagsExpression_eval]
        using prior.directionClear
  · change
      (({edge(7)} environment).after
        ({_state(7)} environment state)).registers.get .ebp =
          frame.entryEsp - word32 4
    rw [CheckedNativeOperationRunningEdge.after_register,
      {_behavior_exact(7)} environment]
    simpa only [{_behavior(7)}, Registers.get, Expr.eval] using prior.ebpExact

theorem generatedInterpreterStepProgramLookupProjectionState0009Facts
    (environment : NativeWorldEnvironment) (state : MachineState)
    (frame : KernelOperationABIFrame)
    (fits : generatedInterpreterStepProgramLookupStackUse.Fits frame workspace)
    (prior : FrameWordDirectionProjection
      ({_state(8)} environment state)
      (frame.entryEsp - word32 2572)
      (frame.entryEsp - word32 4)
      (frame.entryEsp - word32 2572) (word32 sourceRva)) :
    WordsAt ({_state(9)} environment state).memory
        (frame.entryEsp - word32 2576)
        [word32 ((generatedClosedKernelOperationNativeProgram environment).pe.imageBase +
          {plan.continuation_rva}), word32 sourceRva] /\\
      ({_state(9)} environment state).registers.esp =
        frame.entryEsp - word32 2576 /\\
      DirectionFlagClear ({_state(9)} environment state) := by
  have returnFits :
      (frame.entryEsp - word32 2576).toNat + 4 <= 2 ^ 32 := by
    have fit :=
      fits.addressBytesFit generatedInterpreterStepProgramLookupStackUse frame
        workspace 20 4 (by decide)
    have addressExact :=
      {_stack_offset_exact(20, 2576)} frame.entryEsp
    simp only [generatedInterpreterStepProgramLookupStackUse] at fit
    rw [addressExact] at fit
    exact fit
  have sourcePreserved :
      Memory.read32 ({_state(9)} environment state).memory
          (frame.entryEsp - word32 2572) =
        word32 sourceRva := by
    rw [{_state_exact(9)},
      CheckedNativeOperationStoppedEdge.after_memory,
      {_behavior_exact(8)} environment]
    simp only [{_behavior(8)}, applyWrites, List.foldl_cons,
      List.foldl_nil, Expr.eval, Registers.get, prior.espExact]
    rw [{_depth_exact(2576)} frame.entryEsp]
    rw [Memory.read32_write32_of_avoids]
    · exact prior.wordExact
    · exact write32AvoidsWord_of_wordOffsetsDisjoint
        (generatedInterpreterStepProgramLookupProjectionSourceReturnDisjoint
          frame.entryEsp)
  have returnExact :
      Memory.read32 ({_state(9)} environment state).memory
          (frame.entryEsp - word32 2576) =
        word32 ((generatedClosedKernelOperationNativeProgram environment).pe.imageBase +
          {plan.continuation_rva}) := by
    rw [{_state_exact(9)},
      CheckedNativeOperationStoppedEdge.after_memory,
      {_behavior_exact(8)} environment]
    simp only [{_behavior(8)}, applyWrites, List.foldl_cons,
      List.foldl_nil, Expr.eval, Registers.get, prior.espExact]
    rw [{_depth_exact(2576)} frame.entryEsp]
    rw [Memory.read32_write32_same_of_fits _ _ _ returnFits]
    decide +kernel
  have espExact :
      ({_state(9)} environment state).registers.esp =
        frame.entryEsp - word32 2576 := by
    rw [{_state_exact(9)}]
    change
      (({edge(8)} environment).after
        ({_state(8)} environment state)).registers.get .esp =
          frame.entryEsp - word32 2576
    rw [CheckedNativeOperationStoppedEdge.after_register,
      {_behavior_exact(8)} environment]
    simp only [{_behavior(8)}, Registers.get, Expr.eval]
    rw [prior.espExact]
    exact {_depth_exact(2576)} frame.entryEsp
  have directionClear :
      DirectionFlagClear ({_state(9)} environment state) := by
    rw [{_state_exact(9)}]
    change
      (({edge(8)} environment).after
        ({_state(8)} environment state)).eflags.extractLsb' 10 1 =
          BitVec.ofNat 1 0
    rw [CheckedNativeOperationStoppedEdge.after_eflags_extract_df,
      {_behavior_exact(8)} environment]
    simpa only [{_behavior(8)}, Option.getD, inputEflagsExpression_eval]
      using prior.directionClear
  refine And.intro ?_ (And.intro espExact directionClear)
  simp only [WordsAt]
  refine And.intro returnExact (And.intro ?_ True.intro)
  have sourceAddressExact :
      frame.entryEsp - word32 2576 + word32 4 =
        frame.entryEsp - word32 2572 := by
    exact
      generatedInterpreterStepProgramLookupProjectionSourceAddressExact
        frame.entryEsp
  rw [sourceAddressExact]
  exact sourcePreserved

theorem generatedInterpreterStepProgramLookupProjectionNestedEntry
    (environment : NativeWorldEnvironment)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (semanticEnvironment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (state : MachineState) (frame : KernelOperationABIFrame)
    (entry : frame.EntryFacts abi
      (.interpreterStep records semanticEnvironment sourceRva logical) state)
    (fits :
      generatedInterpreterStepProgramLookupStackUse.Fits frame
        abi.parameters.writableWorkspace) :
    KernelOperationNestedEntryProjection abi
      (.programLookup records sourceRva) frame.stackSpan state
      ({_state(9)} environment state) := by
  rcases entry.cdecl with
    ⟨_operationExact, entryEspExact, _ebx, _esi, _edi, _ebp, words,
      stackRange⟩
  have sourceWord :
      Memory.read32 state.memory (frame.entryEsp + word32 16) =
        word32 sourceRva := by
    simpa [WordsAt, KernelOperationABIFrame.requestArguments,
      BitVec.add_assoc, word32, ← BitVec.ofNat_add] using
      words.2.2.2.2.1
  have state1 :=
    generatedInterpreterStepProgramLookupProjectionState0001Facts
      environment state frame entryEspExact sourceWord
      entry.directionFlagClear
  have state2 :=
    generatedInterpreterStepProgramLookupProjectionState0002Facts
      environment state frame state1
  have state3 :=
    generatedInterpreterStepProgramLookupProjectionState0003Facts
      environment state frame state2
  have state4 :=
    generatedInterpreterStepProgramLookupProjectionState0004Facts
      environment state frame state3
  have state5 :=
    generatedInterpreterStepProgramLookupProjectionState0005Facts
      environment state frame state4
  have state6 :=
    generatedInterpreterStepProgramLookupProjectionState0006Facts
      environment state frame state5
  have state7 :=
    generatedInterpreterStepProgramLookupProjectionState0007Facts
      environment state frame state6
  have state7Eax :=
    generatedInterpreterStepProgramLookupProjectionState0007Eax
      environment state frame state6
  have state8 :=
    generatedInterpreterStepProgramLookupProjectionState0008Facts
      environment state frame fits state7 state7Eax
  have state9 :=
    generatedInterpreterStepProgramLookupProjectionState0009Facts
      environment state frame fits state8

{inside_proofs}

  have tail8 :
      checkedNativeOperationRunningTraceWritesInsideAt
        ([] : List (CheckedNativeOperationRunningEdge
          (generatedClosedKernelOperationNativeProgram environment)))
        (addressInSpan abi.parameters.writableWorkspace)
        ({_state(8)} environment state) :=
    True.intro
  have tail7 :
      checkedNativeOperationRunningTraceWritesInsideAt
        [{edge(7)} environment]
        (addressInSpan abi.parameters.writableWorkspace)
        ({_state(7)} environment state) :=
    And.intro inside7 (by
      rw [({_state_exact(8)} environment state).symm]
      exact tail8)
  have tail6 :
      checkedNativeOperationRunningTraceWritesInsideAt
        [{edge(6)} environment, {edge(7)} environment]
        (addressInSpan abi.parameters.writableWorkspace)
        ({_state(6)} environment state) :=
    And.intro inside6 (by
      rw [({_state_exact(7)} environment state).symm]
      exact tail7)
  have tail5 :
      checkedNativeOperationRunningTraceWritesInsideAt
        [{edge(5)} environment, {edge(6)} environment, {edge(7)} environment]
        (addressInSpan abi.parameters.writableWorkspace)
        ({_state(5)} environment state) :=
    And.intro inside5 (by
      rw [({_state_exact(6)} environment state).symm]
      exact tail6)
  have tail4 :
      checkedNativeOperationRunningTraceWritesInsideAt
        [{edge(4)} environment, {edge(5)} environment, {edge(6)} environment,
          {edge(7)} environment]
        (addressInSpan abi.parameters.writableWorkspace)
        ({_state(4)} environment state) :=
    And.intro inside4 (by
      rw [({_state_exact(5)} environment state).symm]
      exact tail5)
  have tail3 :
      checkedNativeOperationRunningTraceWritesInsideAt
        [{edge(3)} environment, {edge(4)} environment, {edge(5)} environment,
          {edge(6)} environment, {edge(7)} environment]
        (addressInSpan abi.parameters.writableWorkspace)
        ({_state(3)} environment state) :=
    And.intro inside3 (by
      rw [({_state_exact(4)} environment state).symm]
      exact tail4)
  have tail2 :
      checkedNativeOperationRunningTraceWritesInsideAt
        [{edge(2)} environment, {edge(3)} environment, {edge(4)} environment,
          {edge(5)} environment, {edge(6)} environment, {edge(7)} environment]
        (addressInSpan abi.parameters.writableWorkspace)
        ({_state(2)} environment state) :=
    And.intro inside2 (by
      rw [({_state_exact(3)} environment state).symm]
      exact tail3)
  have tail1 :
      checkedNativeOperationRunningTraceWritesInsideAt
        [{edge(1)} environment, {edge(2)} environment, {edge(3)} environment,
          {edge(4)} environment, {edge(5)} environment, {edge(6)} environment,
          {edge(7)} environment]
        (addressInSpan abi.parameters.writableWorkspace)
        ({_state(1)} environment state) :=
    And.intro inside1 (by
      rw [({_state_exact(2)} environment state).symm]
      exact tail2)
  have runningInside :
      checkedNativeOperationRunningTraceWritesInsideAt
        ({edge(0)} environment ::
          [{edge(1)} environment, {edge(2)} environment, {edge(3)} environment,
            {edge(4)} environment, {edge(5)} environment, {edge(6)} environment,
            {edge(7)} environment])
        (addressInSpan abi.parameters.writableWorkspace) state :=
    And.intro inside0 (by
      rw [{_state_exact(1)} environment state] at tail1
      simpa only [{_state(0)}] using tail1)
  let block :=
    generatedNativeOperationFunctionReplay{plan.step_function_ordinal:04d}Block{plan.call_block_ordinal:04d}Proof
      environment
  have terminalStateExact :
      block.terminalState state = {_state(8)} environment state := by
    rw [{", ".join(_state_exact(index) for index in range(8, 0, -1))}]
    rfl
  have blockInside :
      checkedNativeOperationBlockWritesInsideAt block
        (addressInSpan abi.parameters.writableWorkspace) state := by
    constructor
    · simpa [block, CheckedNativeOperationRunningTrace.edges] using runningInside
    · rw [terminalStateExact]
      exact inside8
  have memoryFrame :
      MemoryAgreesOutside
        (addressInSpan abi.parameters.writableWorkspace)
        ({_state(9)} environment state).memory state.memory := by
    have checked :=
      checkedNativeOperationBlock_memoryAgreesOutside_at block
        (addressInSpan abi.parameters.writableWorkspace) state blockInside
    rw [terminalStateExact] at checked
    change
      MemoryAgreesOutside
        (addressInSpan abi.parameters.writableWorkspace)
        (({edge(8)} environment).after
          ({_state(8)} environment state)).memory state.memory at checked
    rw [← {_state_exact(9)} environment state] at checked
    exact checked
  have nestedEntryExact :
      ({_state(9)} environment state).registers.esp =
        (frame.entryEsp - word32 2596) + word32 20 := by
    exact state9.2.1.trans
      ({_stack_offset_exact(20, 2576)} frame.entryEsp).symm
  have nestedFrameValid :
      (kernelOperationABIFrameAtInStackSpan
        abi.parameters.writableWorkspace frame.stackSpan .programLookup
        ({_state(9)} environment state)).Valid
          abi.parameters.writableWorkspace abi.engineLayout := by
    unfold KernelOperationABIFrame.Valid
    simp only [kernelOperationABIFrameAtInStackSpan,
      kernelOperationABIFrameAt, AbstractKernelRequest.operation]
    refine And.intro ?_ <| And.intro entry.frameValid.2.1 <|
      And.intro entry.frameValid.2.2.1 <| And.intro ?_ ?_
    · rw [state9.2.1]
      have range :=
        fits.addressRangeInWorkspace
          generatedInterpreterStepProgramLookupStackUse frame
          abi.parameters.writableWorkspace 20 8 (by decide)
      simp only [generatedInterpreterStepProgramLookupStackUse] at range
      rw [{_stack_offset_exact(20, 2576)} frame.entryEsp] at range
      exact range
    · rw [state9.2.1,
        ← {_stack_offset_exact(20, 2576)} frame.entryEsp]
      have addressNat :=
        fits.addressToNat generatedInterpreterStepProgramLookupStackUse frame
          abi.parameters.writableWorkspace 20 (by decide)
      simp only [generatedInterpreterStepProgramLookupStackUse] at addressNat
      rw [addressNat]
      rcases fits with
        ⟨belowEntry, _upperDoesNotWrap, _stackUse, _workspaceUse⟩
      simp only [generatedInterpreterStepProgramLookupStackUse] at belowEntry
      omega
    · intro address member
      rcases member with ⟨offset, offsetBefore, rfl⟩
      have range :=
        fits.addressRangeInWorkspace
          generatedInterpreterStepProgramLookupStackUse frame
          abi.parameters.writableWorkspace 0 20 (by decide)
      have atOffset := range offset offsetBefore
      simp only [generatedInterpreterStepProgramLookupStackUse] at atOffset
      rw [state9.2.1,
        generatedInterpreterStepProgramLookupProjectionFrameByteExact]
      simpa [word32, BitVec.add_assoc] using atOffset
  refine {{
    frameValid := nestedFrameValid
    words := ?_
    stackRange
    directionFlagClear := state9.2.2
    memoryFrame
    payload := ?_
  }}
  · change
      WordsAt ({_state(9)} environment state).memory
        ({_state(9)} environment state).registers.esp
        [Memory.read32 ({_state(9)} environment state).memory
          ({_state(9)} environment state).registers.esp, word32 sourceRva]
    have words := state9.1
    simp only [WordsAt] at words ⊢
    refine And.intro True.intro (And.intro ?_ True.intro)
    rw [state9.2.1]
    exact words.2.1
  · rcases entry.payload with ⟨recordsExact, sourceFits, _engineState⟩
    exact ⟨recordsExact, sourceFits⟩

theorem generatedInterpreterStepProgramLookupProjectionBlockEndpointExact
    (environment : NativeWorldEnvironment) (state : MachineState) :
    {_state(9)} environment state =
      (generatedNativeOperationFunctionReplay{plan.step_function_ordinal:04d}Block{plan.call_block_ordinal:04d}Proof
        environment).terminal.after
        ((generatedNativeOperationFunctionReplay{plan.step_function_ordinal:04d}Block{plan.call_block_ordinal:04d}Proof
          environment).terminalState state) := by
  rw [{_state_exact(9)}]
  congr 1
  rw [{", ".join(_state_exact(index) for index in range(8, 0, -1))}]
  rfl

#print axioms generatedInterpreterStepProgramLookupProjectionNestedEntry
#print axioms
  generatedInterpreterStepProgramLookupProjectionBlockEndpointExact

end StageA.GeneratedRelational.InterpreterStepProgramLookupProjection
"""


def write_interpreter_step_program_lookup_projection(
    *,
    plan: InterpreterKernelStepWorldProgramLookupPlan,
    out: Path | str,
) -> None:
    output = Path(out) / "StageA"
    output.mkdir(parents=True, exist_ok=True)
    (
        output
        / f"{INTERPRETER_STEP_PROGRAM_LOOKUP_PROJECTION_LEAN_MODULE}.lean"
    ).write_text(
        interpreter_step_program_lookup_projection_source(plan),
        encoding="utf-8",
    )


__all__ = [
    "INTERPRETER_STEP_PROGRAM_LOOKUP_PROJECTION_LEAN_MODULE",
    "interpreter_step_program_lookup_projection_source",
    "write_interpreter_step_program_lookup_projection",
]
