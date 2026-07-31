"""Generate compact checked state projections for the native Run entry.

The generated modules deliberately split the exact entry route by block.
Each checkpoint consumes one exact decoded edge and the preceding opaque
checkpoint.  Lean therefore evaluates each instruction projection once
instead of repeatedly normalizing the complete nested MachineState.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .interpreter_kernel_run_entry_route import (
    RunEntryRoute,
    build_run_entry_route,
)


RUN_ENTRY_PROJECTION_BLOCK0_MODULE = (
    "GeneratedRelationalInterpreterKernelRunEntryProjectionBlock0"
)
RUN_ENTRY_PROJECTION_BLOCK1_MODULE = (
    "GeneratedRelationalInterpreterKernelRunEntryProjectionBlock1"
)
RUN_ENTRY_PROJECTION_BLOCK2_MODULE = (
    "GeneratedRelationalInterpreterKernelRunEntryProjectionBlock2"
)
RUN_ENTRY_PROJECTION_BLOCK2_BASE_MODULE = (
    "GeneratedRelationalInterpreterKernelRunEntryProjectionBlock2Base"
)
RUN_ENTRY_FOOTPRINT_MODULE = (
    "GeneratedRelationalInterpreterKernelRunEntryFootprints"
)


def _block2_step_module(instruction: int) -> str:
    return (
        "GeneratedRelationalInterpreterKernelRunEntryProjection"
        f"Block2Step{instruction}"
    )


class InterpreterKernelRunEntryProjectionError(ValueError):
    """The selected Run entry route cannot instantiate this certificate."""


@dataclass(frozen=True)
class _ABIConstants:
    entry_esp: int
    input_address: int
    output_address: int


def _load_object(path: Path, context: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InterpreterKernelRunEntryProjectionError(
            f"cannot read {context} {path}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise InterpreterKernelRunEntryProjectionError(
            f"{context} must be an object"
        )
    return payload


def _abi_constants(path: Path) -> _ABIConstants:
    payload = _load_object(path, "kernel ABI plan")
    if payload.get("format") != (
        "stage-a-relational-interpreter-kernel-abi-plan-v1"
    ):
        raise InterpreterKernelRunEntryProjectionError(
            "unsupported kernel ABI plan format"
        )
    engine = payload.get("engine")
    workspace = payload.get("invocation_workspace")
    state_size = engine.get("state_size") if isinstance(engine, dict) else None
    start = workspace.get("start") if isinstance(workspace, dict) else None
    reserve = (
        workspace.get("stack_reserve_per_operation")
        if isinstance(workspace, dict)
        else None
    )
    if (
        not isinstance(state_size, int)
        or state_size <= 0
        or not isinstance(start, int)
        or start < 0
        or not isinstance(reserve, int)
        or reserve <= 20
    ):
        raise InterpreterKernelRunEntryProjectionError(
            "kernel ABI plan has invalid workspace dimensions"
        )
    fixed_bytes = 64 + 2 * state_size + 52 + 12
    entry_esp = start + fixed_bytes + 3 * reserve - 20
    input_address = start + 64
    if entry_esp >= 2**32 or input_address >= 2**32:
        raise InterpreterKernelRunEntryProjectionError(
            "kernel ABI projection addresses overflow IA-32"
        )
    return _ABIConstants(
        entry_esp=entry_esp,
        input_address=input_address,
        output_address=input_address + state_size,
    )


def _validate_route(route: RunEntryRoute) -> None:
    counts = tuple(block.instruction_count for block in route.path)
    terminals = tuple(block.terminal_class for block in route.path)
    if len(route.controls) != 2 or counts != (10, 2, 8):
        raise InterpreterKernelRunEntryProjectionError(
            "Run entry projection requires the checked 10/2/8 route shape"
        )
    if terminals != ("branch", "branch", "bulk"):
        raise InterpreterKernelRunEntryProjectionError(
            "Run entry projection terminal classes do not match"
        )


def _instruction_prefix(
    route: RunEntryRoute, block_index: int, instruction: int
) -> str:
    block = route.path[block_index]
    return (
        "generatedNativeOperationFunctionReplay"
        f"{route.function_ordinal:04d}Block{block.ordinal:04d}"
        f"Instruction{instruction:04d}"
    )


def _edge(route: RunEntryRoute, block: int, instruction: int) -> str:
    return f"{_instruction_prefix(route, block, instruction)}Edge"


def _behavior(block: int, instruction: int) -> str:
    return (
        f"generatedRunEntryBlock{block}"
        f"Instruction{instruction:04d}MaterializedBehavior"
    )


def _behavior_exact(block: int, instruction: int) -> str:
    return f"{_behavior(block, instruction)}EdgeBehaviorExact"


def _state(block: int, index: int) -> str:
    return f"generatedRunEntryProjectionBlock{block}State{index:04d}"


def _state_handle(block: int, index: int) -> str:
    return f"{_state(block, index)}Handle"


def _state_exact(block: int, index: int) -> str:
    return f"{_state(block, index)}Exact"


def _input(register: str) -> str:
    return f".inputReg .{register}"


def _constant(value: int) -> str:
    return f".constant {value}"


def _add(left: str, right: str) -> str:
    return f".add ({left}) ({right})"


def _sub(left: str, right: str) -> str:
    return f".sub ({left}) ({right})"


def _read32(address: str) -> str:
    return f".read32 ({address})"


def _compact_projection_specs() -> tuple[tuple[dict[str, Any], ...], ...]:
    registers = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")

    def spec(
        *,
        updates: dict[str, str] | None = None,
        writes: tuple[tuple[str, str], ...] = (),
    ) -> dict[str, Any]:
        projected = {register: _input(register) for register in registers}
        projected.update(updates or {})
        return {
            "registers": projected,
            "writes": writes,
            "flags_base": "none",
        }

    esp_minus_4 = _add(_input("esp"), _constant(2**32 - 4))
    return (
        (
            spec(
                updates={"esp": esp_minus_4},
                writes=((esp_minus_4, _input("ebp")),),
            ),
            spec(updates={"ebp": _input("esp")}),
            spec(
                updates={"esp": esp_minus_4},
                writes=((esp_minus_4, _input("edi")),),
            ),
            spec(
                updates={"esp": esp_minus_4},
                writes=((esp_minus_4, _input("esi")),),
            ),
            spec(
                updates={"esp": esp_minus_4},
                writes=((esp_minus_4, _input("ebx")),),
            ),
            spec(updates={"esp": _sub(_input("esp"), _constant(300))}),
            spec(
                updates={
                    "eax": _read32(
                        _add(_input("ebp"), _constant(12))
                    )
                }
            ),
            spec(
                writes=(
                    (
                        _add(_input("ebp"), _constant(2**32 - 28)),
                        _input("eax"),
                    ),
                )
            ),
            spec(),
            spec(),
        ),
        (spec(), spec()),
        (
            spec(
                updates={
                    "edx": _read32(
                        _add(_input("ebp"), _constant(16))
                    )
                }
            ),
            spec(
                updates={
                    "eax": _add(
                        _input("ebp"), _constant(2**32 - 280)
                    )
                }
            ),
            spec(updates={"ebx": _input("edx")}),
            spec(updates={"edx": _constant(63)}),
            spec(updates={"edi": _input("eax")}),
            spec(updates={"esi": _input("ebx")}),
            spec(updates={"ecx": _input("edx")}),
            spec(),
        ),
    )


def _projection(block: int, instruction: int) -> str:
    return (
        f"generatedRunEntryBlock{block}Instruction{instruction:04d}"
        "CompactProjection"
    )


def _projection_field_exact(
    block: int, instruction: int, field: str
) -> str:
    return f"{_projection(block, instruction)}{field.title()}Exact"


def _compact_projection_definitions(
    block: int,
    *,
    instruction_count: int | None = None,
) -> str:
    all_specs = _compact_projection_specs()[block]
    stop_instruction = (
        len(all_specs)
        if instruction_count is None
        else instruction_count
    )
    specs = all_specs[:stop_instruction]
    compact_projection = (
        "StageA.Relational.InterpreterKernelOperationProjection."
        "SymbolicBehavior.compactProjection"
    )
    definitions: list[str] = []
    for instruction, spec in enumerate(specs):
        registers = spec["registers"]
        writes = ", ".join(
            f"({address}, {value})"
            for address, value in spec["writes"]
        )
        projection = _projection(block, instruction)
        behavior = _behavior(block, instruction)
        definitions.append(
            f"""def {projection} : CompactBehaviorProjection := {{
  eax := {registers["eax"]}
  ebx := {registers["ebx"]}
  ecx := {registers["ecx"]}
  edx := {registers["edx"]}
  esi := {registers["esi"]}
  edi := {registers["edi"]}
  ebp := {registers["ebp"]}
  esp := {registers["esp"]}
  writes := [{writes}]
  flagsBase := {spec["flags_base"]}
}}

theorem {projection}Exact :
    {compact_projection} {behavior} = {projection} := by
  rfl"""
        )
        for field in (
            "eax",
            "ebx",
            "ecx",
            "edx",
            "esi",
            "edi",
            "ebp",
            "esp",
            "writes",
            "flagsBase",
        ):
            source_field = (
                f"{behavior}.registers.get .{field}"
                if field not in {"writes", "flagsBase"}
                else f"{behavior}.{field}"
            )
            definitions.append(
                f"""theorem {_projection_field_exact(block, instruction, field)} :
    {source_field} = {projection}.{field} := by
  simpa only [{compact_projection}, Registers.get] using
    congrArg CompactBehaviorProjection.{field} {projection}Exact"""
            )
    return "\n\n".join(definitions)


def _common_open(
    *, definitions: bool, constants: _ABIConstants | None = None
) -> str:
    prefix = """open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationPredicateRoute
open StageA.Relational.InterpreterKernelOperationProjection
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelOperationInstantiation

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
"""
    if not definitions:
        return prefix
    if constants is None:
        raise AssertionError("ABI constants are required for shared definitions")
    return prefix + """
abbrev generatedRunEntryProjectionLayout :=
  generatedInterpreterEngineLayout

abbrev generatedRunEntryProjectionParameters :=
  generatedInterpreterKernelABIParameters

def generatedRunEntryProjectionEntryEsp : Word :=
  word32 %d

def generatedRunEntryProjectionInputAddress : Word :=
  word32 %d

def generatedRunEntryProjectionInputWordAddress : Word :=
  generatedRunEntryProjectionEntryEsp + word32 12

def generatedRunEntryProjectionOutputAddress : Word :=
  word32 %d

def generatedRunEntryProjectionOutputWordAddress : Word :=
  generatedRunEntryProjectionEntryEsp + word32 16

def generatedRunEntryProjectionWorkingAddress : Word :=
  generatedRunEntryProjectionEntryEsp - word32 284

theorem generatedRunEntryProjectionEntryEspExact :
    generatedRunEntryProjectionParameters.entryEsp
        generatedRunEntryProjectionLayout .runFunction =
      generatedRunEntryProjectionEntryEsp := by
  decide +kernel

theorem generatedRunEntryProjectionInputAddressExact :
    generatedRunEntryProjectionParameters.inputAddress =
      generatedRunEntryProjectionInputAddress := by
  decide +kernel

theorem generatedRunEntryProjectionOutputAddressExact :
    generatedRunEntryProjectionParameters.outputAddress
        generatedRunEntryProjectionLayout =
      generatedRunEntryProjectionOutputAddress := by
  decide +kernel

theorem generatedRunEntryProjectionFrameArgumentAddressExact :
    generatedRunEntryProjectionEntryEsp - word32 4 + word32 16 =
      generatedRunEntryProjectionInputWordAddress := by
  decide +kernel

theorem generatedRunEntryProjectionFrameOutputArgumentAddressExact :
    generatedRunEntryProjectionEntryEsp - word32 4 + word32 20 =
      generatedRunEntryProjectionOutputWordAddress := by
  decide +kernel

theorem generatedRunEntryProjectionWorkingAddressFromFrameExact :
    generatedRunEntryProjectionEntryEsp - word32 4 +
        word32 4294967016 =
      generatedRunEntryProjectionWorkingAddress := by
  decide +kernel
""" % (
        constants.entry_esp,
        constants.input_address,
        constants.output_address,
    )


def _state_definitions(
    route: RunEntryRoute, block: int, instruction_count: int
) -> str:
    definitions = [_state_zero_definition(block)]
    definitions.extend(
        _state_transition_definition(route, block, instruction)
        for instruction in range(instruction_count)
    )
    return "\n\n".join(definitions)


def _state_zero_definition(block: int) -> str:
    return f"""def {_state(block, 0)}
    (_environment : NativeWorldEnvironment) (state : MachineState) :
    MachineState :=
  state"""


def _state_transition_definition(
    route: RunEntryRoute, block: int, instruction: int
) -> str:
    source = _state(block, instruction)
    target = _state(block, instruction + 1)
    handle = _state_handle(block, instruction + 1)
    exact = _state_exact(block, instruction + 1)
    edge = _edge(route, block, instruction)
    return f"""opaque {handle}
    (environment : NativeWorldEnvironment) (state : MachineState) :
    {{ next : MachineState //
      next = ({edge} environment).after
        ({source} environment state) }} :=
  ⟨({edge} environment).after ({source} environment state), rfl⟩

def {target}
    (environment : NativeWorldEnvironment) (state : MachineState) :
    MachineState :=
  ({handle} environment state).val

theorem {exact}
    (environment : NativeWorldEnvironment) (state : MachineState) :
    {target} environment state =
      ({edge} environment).after ({source} environment state) :=
  ({handle} environment state).property"""


def _state_exact_rewrites(block: int, instruction_count: int) -> str:
    return ", ".join(
        _state_exact(block, index)
        for index in range(instruction_count, 0, -1)
    )


def _simp_terms(
    block: int,
    instruction: int,
    prior: str | None,
    *,
    prior_has_frame: bool = True,
) -> str:
    terms = [
        _projection(block, instruction),
        "Expr.eval",
        "Registers.get",
        "generatedRunEntryProjectionEntryEsp",
        "generatedRunEntryProjectionInputWordAddress",
        "generatedRunEntryProjectionOutputWordAddress",
        "generatedRunEntryProjectionWorkingAddress",
        "generatedRunEntryProjectionInputAddress",
        "generatedRunEntryProjectionOutputAddress",
    ]
    if prior is not None:
        terms.append(f"{prior}.espExact")
        if prior_has_frame:
            terms.append(f"{prior}.ebpExact")
    return ", ".join(terms)


def _word_checked_proof(
    *,
    block: int,
    instruction: int,
    source_state: str,
    simp_terms: str,
    concrete_write_address: str | None,
    word_address: str = "generatedRunEntryProjectionInputWordAddress",
    indentation: int = 4,
) -> str:
    writes = _compact_projection_specs()[block][instruction]["writes"]
    projection = _projection(block, instruction)
    if not writes:
        body = f"""simpa only [{projection}] using
  symbolicWritesAvoidWordChecked_nil
    {word_address}
    ({source_state} environment state)"""
    elif len(writes) == 1 and concrete_write_address is not None:
        body = f"""simp only [{projection}]
apply symbolicWritesAvoidWordChecked_singleton
  (concreteAddress := {concrete_write_address})
· simp only [{simp_terms}] <;> decide +kernel
· decide +kernel"""
    else:
        raise InterpreterKernelRunEntryProjectionError(
            "Run entry write projection requires one concrete address witness"
        )
    prefix = " " * indentation
    return "\n".join(
        f"{prefix}{line}" if line else line for line in body.splitlines()
    )


def _frame_step_theorem(
    *,
    route: RunEntryRoute,
    block: int,
    instruction: int,
    edge_kind: str,
    source_fact_type: str,
    expected_esp: str,
    theorem_name: str,
    source_has_frame: bool = True,
    concrete_write_address: str | None = None,
) -> str:
    source_state = _state(block, instruction)
    target_state = _state(block, instruction + 1)
    edge = _edge(route, block, instruction)
    exact = _behavior_exact(block, instruction)
    esp_shape = _projection_field_exact(block, instruction, "esp")
    ebp_shape = _projection_field_exact(block, instruction, "ebp")
    writes_shape = _projection_field_exact(block, instruction, "writes")
    flags_shape = _projection_field_exact(block, instruction, "flagsBase")
    simp_terms = _simp_terms(
        block,
        instruction,
        "prior",
        prior_has_frame=source_has_frame,
    )
    theorem = (
        "CheckedNativeOperationRunningEdge"
        if edge_kind == "running"
        else "CheckedNativeOperationStoppedEdge"
    )
    word_checked = _word_checked_proof(
        block=block,
        instruction=instruction,
        source_state=source_state,
        simp_terms=simp_terms,
        concrete_write_address=concrete_write_address,
    )
    output_word_checked = _word_checked_proof(
        block=block,
        instruction=instruction,
        source_state=source_state,
        simp_terms=simp_terms,
        concrete_write_address=concrete_write_address,
        word_address="generatedRunEntryProjectionOutputWordAddress",
    )
    return f"""theorem {theorem_name}
    (environment : NativeWorldEnvironment) (state : MachineState)
    (prior : {source_fact_type}) :
    FrameWordPairDirectionProjection
      ({target_state} environment state)
      {expected_esp}
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress := by
  rw [{_state_exact(block, instruction + 1)}]
  apply
    StageA.Relational.InterpreterKernelOperationProjection.{theorem}.after_frameWordPairDirectionProjection
      ({edge} environment)
      ({source_state} environment state)
  · rw [{exact} environment, {esp_shape}]
    simp only [{simp_terms}] <;> decide +kernel
  · rw [{exact} environment, {ebp_shape}]
    simp only [{simp_terms}] <;> decide +kernel
  · rw [{exact} environment, {writes_shape}]
{word_checked}
  · rw [{exact} environment, {writes_shape}]
{output_word_checked}
  · rw [{exact} environment, {flags_shape}]
    rfl
  · exact prior.wordExact
  · exact prior.secondWordExact
  · exact prior.directionClear"""


def _block0_source(route: RunEntryRoute, constants: _ABIConstants) -> str:
    state0 = _state(0, 0)
    state1 = _state(0, 1)
    edge0 = _edge(route, 0, 0)
    exact0 = _behavior_exact(0, 0)
    first_simp = f"{_simp_terms(0, 0, None)}, {state0}"
    pieces = [
        f"""import StageA.GeneratedRelationalInterpreterKernelRunEntryRoute
import StageA.GeneratedRelationalInterpreterKernelRunEntryBehaviors
import StageA.GeneratedRelationalInterpreterKernelABIParameters
import StageA.RelationalInterpreterKernelOperationProjection

namespace StageA.GeneratedRelational.InterpreterKernelRunEntryProjection

{_common_open(definitions=True, constants=constants)}

{_state_definitions(route, 0, 10)}

{_compact_projection_definitions(0)}

theorem generatedRunEntryProjectionBlock0State0001Facts
    (environment : NativeWorldEnvironment) (state : MachineState)
    (espExact :
      state.registers.esp = generatedRunEntryProjectionEntryEsp)
    (wordExact :
      Memory.read32 state.memory
        generatedRunEntryProjectionInputWordAddress =
        generatedRunEntryProjectionInputAddress)
    (outputWordExact :
      Memory.read32 state.memory
        generatedRunEntryProjectionOutputWordAddress =
        generatedRunEntryProjectionOutputAddress)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    StackWordPairDirectionProjection ({state1} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress := by
  rw [{_state_exact(0, 1)}]
  apply
    StageA.Relational.InterpreterKernelOperationProjection.CheckedNativeOperationRunningEdge.after_stackWordPairDirectionProjection
      ({edge0} environment) ({state0} environment state)
  · rw [{exact0} environment,
      {_projection_field_exact(0, 0, "esp")}]
    simp only [{first_simp}, espExact] <;> decide +kernel
  · rw [{exact0} environment,
      {_projection_field_exact(0, 0, "writes")}]
    simp only [{_projection(0, 0)}]
    apply symbolicWritesAvoidWordChecked_singleton
      (concreteAddress :=
        generatedRunEntryProjectionEntryEsp - word32 4)
    · simp only [{first_simp}, espExact] <;> decide +kernel
    · decide +kernel
  · rw [{exact0} environment,
      {_projection_field_exact(0, 0, "writes")}]
    simp only [{_projection(0, 0)}]
    apply symbolicWritesAvoidWordChecked_singleton
      (concreteAddress :=
        generatedRunEntryProjectionEntryEsp - word32 4)
    · simp only [{first_simp}, espExact] <;> decide +kernel
    · decide +kernel
  · rw [{exact0} environment,
      {_projection_field_exact(0, 0, "flagsBase")}]
    rfl
  · exact wordExact
  · exact outputWordExact
  · exact directionClear"""
    ]
    state1_type = f"""StackWordPairDirectionProjection
      ({state1} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress"""
    pieces.append(
        _frame_step_theorem(
            route=route,
            block=0,
            instruction=1,
            edge_kind="running",
            source_fact_type=state1_type,
            expected_esp="(generatedRunEntryProjectionEntryEsp - word32 4)",
            theorem_name="generatedRunEntryProjectionBlock0State0002Facts",
            source_has_frame=False,
        )
    )
    depths = (8, 12, 16, 316, 316, 316, 316, 316)
    concrete_write_addresses = {
        2: "(generatedRunEntryProjectionEntryEsp - word32 8)",
        3: "(generatedRunEntryProjectionEntryEsp - word32 12)",
        4: "(generatedRunEntryProjectionEntryEsp - word32 16)",
        7: "(generatedRunEntryProjectionEntryEsp - word32 32)",
    }
    for target_index, depth in enumerate(depths, start=3):
        instruction = target_index - 1
        prior_state = _state(0, instruction)
        prior_depth = 4 if instruction == 2 else depths[instruction - 3]
        source_type = f"""FrameWordPairDirectionProjection
      ({prior_state} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 {prior_depth})
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress"""
        pieces.append(
            _frame_step_theorem(
                route=route,
                block=0,
                instruction=instruction,
                edge_kind="stopped" if instruction == 9 else "running",
                source_fact_type=source_type,
                expected_esp=(
                    f"(generatedRunEntryProjectionEntryEsp - word32 {depth})"
                ),
                theorem_name=(
                    f"generatedRunEntryProjectionBlock0State"
                    f"{target_index:04d}Facts"
                ),
                concrete_write_address=concrete_write_addresses.get(
                    instruction
                ),
            )
        )
    state8 = _state(0, 8)
    state9 = _state(0, 9)
    edge8 = _edge(route, 0, 8)
    behavior8 = _behavior(0, 8)
    behavior_exact8 = _behavior_exact(0, 8)
    pieces.append(
        f"""theorem generatedRunEntryProjectionBlock0ZeroFlagFalse
    (environment : NativeWorldEnvironment) (state : MachineState)
    (prior : FrameWordPairDirectionProjection
      ({state8} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 316)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress) :
    BoolExpr.eval ({state9} environment state) (.inputFlag 6) = false := by
  rw [{_state_exact(0, 9)}]
  let flags : FlagsExpr :=
    {behavior8}.flags.get (by decide +kernel)
  let zero : BoolExpr :=
    flags.zero.get (by decide +kernel)
  have baseExact :
      ({edge8} environment).replay.behavior.flagsBase = none := by
    rw [{behavior_exact8} environment]
    rfl
  have flagsExact :
      ({edge8} environment).replay.behavior.flags = some flags := by
    rw [{behavior_exact8} environment]
    rfl
  have zeroExact : flags.zero = some zero := by
    rfl
  have projected :=
    StageA.Relational.InterpreterKernelOperationProjection.CheckedNativeOperationRunningEdge.after_inputFlagSix_of_flags
      ({edge8} environment)
      ({state8} environment state)
      flags zero baseExact flagsExact zeroExact
  have expressionExact :
      zero =
        .equal
          (.read32 (.add (.inputReg .ebp) (.constant 16)))
          (.constant 0) := by
    decide +kernel
  have comparedWord :
      ({state8} environment state).read32
          (({state8} environment state).registers.ebp + word32 16) =
        generatedRunEntryProjectionInputAddress := by
    change
      Memory.read32 ({state8} environment state).memory
          (({state8} environment state).registers.ebp + word32 16) =
        generatedRunEntryProjectionInputAddress
    rw [show
      ({state8} environment state).registers.ebp =
          generatedRunEntryProjectionEntryEsp - word32 4 by
        simpa [Registers.get] using prior.ebpExact]
    rw [generatedRunEntryProjectionFrameArgumentAddressExact]
    exact prior.wordExact
  have comparedWordExact :
      ({state8} environment state).read32
          (({state8} environment state).registers.ebp +
            BitVec.ofNat 32 16) =
        generatedRunEntryProjectionInputAddress := by
    simpa only [word32] using comparedWord
  rw [expressionExact] at projected
  rw [projected]
  simp only [BoolExpr.eval, Expr.eval, Registers.get, comparedWordExact,
    generatedRunEntryProjectionInputAddress]
  decide +kernel

theorem generatedRunEntryProjectionBlock0SelectorHolds
    (environment : NativeWorldEnvironment) (state : MachineState)
    (prior : FrameWordPairDirectionProjection
      ({state8} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 316)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress) :
    generatedRunEntrySelectorInvariant0.Holds
      ((generatedRunEntryBlock0 environment).terminalState state) := by
  have terminalStateExact :
      (generatedRunEntryBlock0 environment).terminalState state =
        {state9} environment state := by
    rw [{_state_exact_rewrites(0, 9)}]
    rfl
  rw [terminalStateExact]
  have selectorExact :
      generatedRunEntrySelectorInvariant0 =
        {{ predicates := [.not (.inputFlag 6)] }} := by
    decide +kernel
  rw [selectorExact]
  have notHolds :
      BoolExpr.eval ({state9} environment state)
          (.not (.inputFlag 6)) = true := by
    rw [show
      BoolExpr.eval ({state9} environment state) (.not (.inputFlag 6)) =
        !(BoolExpr.eval ({state9} environment state) (.inputFlag 6)) by
      rfl]
    rw [generatedRunEntryProjectionBlock0ZeroFlagFalse
      environment state prior]
    decide +kernel
  simpa only [NativeOperationInvariant.Holds, List.all_cons, List.all_nil,
    Bool.and_true] using notHolds"""
    )
    pieces.append(
        f"""theorem generatedRunEntryProjectionBlock0EndpointExact
    (environment : NativeWorldEnvironment) (state : MachineState) :
    (generatedRunEntryStep0 environment).targetState state =
      {_state(0, 10)} environment state := by
  rw [{_state_exact_rewrites(0, 10)}]
  rfl

theorem generatedRunEntryProjectionBlock0ControlFacts
    (environment : NativeWorldEnvironment) (state : MachineState)
    (espExact :
      state.registers.esp = generatedRunEntryProjectionEntryEsp)
    (inputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionInputWordAddress =
        generatedRunEntryProjectionInputAddress)
    (outputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionOutputWordAddress =
        generatedRunEntryProjectionOutputAddress)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    generatedRunEntrySelectorInvariant0.Holds
        ((generatedRunEntryBlock0 environment).terminalState state) /\\
      FrameWordPairDirectionProjection
        ((generatedRunEntryStep0 environment).targetState state)
        (generatedRunEntryProjectionEntryEsp - word32 316)
        (generatedRunEntryProjectionEntryEsp - word32 4)
        generatedRunEntryProjectionInputWordAddress
        generatedRunEntryProjectionInputAddress
        generatedRunEntryProjectionOutputWordAddress
        generatedRunEntryProjectionOutputAddress := by
  have state1 :=
    generatedRunEntryProjectionBlock0State0001Facts environment state
      espExact inputWord outputWord directionClear
  have state2 :=
    generatedRunEntryProjectionBlock0State0002Facts environment state state1
  have state3 :=
    generatedRunEntryProjectionBlock0State0003Facts environment state state2
  have state4 :=
    generatedRunEntryProjectionBlock0State0004Facts environment state state3
  have state5 :=
    generatedRunEntryProjectionBlock0State0005Facts environment state state4
  have state6 :=
    generatedRunEntryProjectionBlock0State0006Facts environment state state5
  have state7 :=
    generatedRunEntryProjectionBlock0State0007Facts environment state state6
  have state8 :=
    generatedRunEntryProjectionBlock0State0008Facts environment state state7
  have state9 :=
    generatedRunEntryProjectionBlock0State0009Facts environment state state8
  have state10 :=
    generatedRunEntryProjectionBlock0State0010Facts environment state state9
  exact And.intro
    (generatedRunEntryProjectionBlock0SelectorHolds
      environment state state8)
    (generatedRunEntryProjectionBlock0EndpointExact environment state ▸ state10)

#print axioms generatedRunEntryProjectionBlock0State0010Facts
#print axioms generatedRunEntryProjectionBlock0ControlFacts
#print axioms generatedRunEntryProjectionBlock0EndpointExact

end StageA.GeneratedRelational.InterpreterKernelRunEntryProjection"""
    )
    return "\n\n".join(pieces)


def _block1_source(route: RunEntryRoute) -> str:
    source = _state(1, 0)
    pieces = [
        f"""import StageA.{RUN_ENTRY_PROJECTION_BLOCK0_MODULE}

namespace StageA.GeneratedRelational.InterpreterKernelRunEntryProjection

{_common_open(definitions=False)}

{_state_definitions(route, 1, 2)}"""
        + f"""

{_compact_projection_definitions(1)}"""
    ]
    prior_type = f"""FrameWordPairDirectionProjection
      ({source} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 316)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress"""
    pieces.append(
        _frame_step_theorem(
            route=route,
            block=1,
            instruction=0,
            edge_kind="running",
            source_fact_type=prior_type,
            expected_esp="(generatedRunEntryProjectionEntryEsp - word32 316)",
            theorem_name="generatedRunEntryProjectionBlock1State0001Facts",
        )
    )
    prior_type = f"""FrameWordPairDirectionProjection
      ({_state(1, 1)} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 316)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress"""
    pieces.append(
        _frame_step_theorem(
            route=route,
            block=1,
            instruction=1,
            edge_kind="stopped",
            source_fact_type=prior_type,
            expected_esp="(generatedRunEntryProjectionEntryEsp - word32 316)",
            theorem_name="generatedRunEntryProjectionBlock1State0002Facts",
        )
    )
    state0 = _state(1, 0)
    state1 = _state(1, 1)
    edge0 = _edge(route, 1, 0)
    behavior0 = _behavior(1, 0)
    behavior_exact0 = _behavior_exact(1, 0)
    pieces.append(
        f"""theorem generatedRunEntryProjectionBlock1ZeroFlagFalse
    (environment : NativeWorldEnvironment) (state : MachineState)
    (prior : FrameWordPairDirectionProjection
      ({state0} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 316)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress) :
    BoolExpr.eval ({state1} environment state) (.inputFlag 6) = false := by
  rw [{_state_exact(1, 1)}]
  let flags : FlagsExpr :=
    {behavior0}.flags.get (by decide +kernel)
  let zero : BoolExpr :=
    flags.zero.get (by decide +kernel)
  have baseExact :
      ({edge0} environment).replay.behavior.flagsBase = none := by
    rw [{behavior_exact0} environment]
    rfl
  have flagsExact :
      ({edge0} environment).replay.behavior.flags = some flags := by
    rw [{behavior_exact0} environment]
    rfl
  have zeroExact : flags.zero = some zero := by
    rfl
  have projected :=
    StageA.Relational.InterpreterKernelOperationProjection.CheckedNativeOperationRunningEdge.after_inputFlagSix_of_flags
      ({edge0} environment)
      ({state0} environment state)
      flags zero baseExact flagsExact zeroExact
  have expressionExact :
      zero =
        .equal
          (.read32 (.add (.inputReg .ebp) (.constant 20)))
          (.constant 0) := by
    decide +kernel
  have comparedWord :
      ({state0} environment state).read32
          (({state0} environment state).registers.ebp + word32 20) =
        generatedRunEntryProjectionOutputAddress := by
    change
      Memory.read32 ({state0} environment state).memory
          (({state0} environment state).registers.ebp + word32 20) =
        generatedRunEntryProjectionOutputAddress
    rw [show
      ({state0} environment state).registers.ebp =
          generatedRunEntryProjectionEntryEsp - word32 4 by
        simpa [Registers.get] using prior.ebpExact]
    rw [generatedRunEntryProjectionFrameOutputArgumentAddressExact]
    exact prior.secondWordExact
  have comparedWordExact :
      ({state0} environment state).read32
          (({state0} environment state).registers.ebp +
            BitVec.ofNat 32 20) =
        generatedRunEntryProjectionOutputAddress := by
    simpa only [word32] using comparedWord
  rw [expressionExact] at projected
  rw [projected]
  simp only [BoolExpr.eval, Expr.eval, Registers.get, comparedWordExact,
    generatedRunEntryProjectionOutputAddress]
  decide +kernel

theorem generatedRunEntryProjectionBlock1SelectorHolds
    (environment : NativeWorldEnvironment) (state : MachineState)
    (prior : FrameWordPairDirectionProjection
      ({state0} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 316)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress) :
    generatedRunEntrySelectorInvariant1.Holds
      ((generatedRunEntryBlock1 environment).terminalState state) := by
  have terminalStateExact :
      (generatedRunEntryBlock1 environment).terminalState state =
        {state1} environment state := by
    rw [{_state_exact_rewrites(1, 1)}]
    rfl
  rw [terminalStateExact]
  have selectorExact :
      generatedRunEntrySelectorInvariant1 =
        {{ predicates := [.not (.inputFlag 6)] }} := by
    decide +kernel
  rw [selectorExact]
  have notHolds :
      BoolExpr.eval ({state1} environment state)
          (.not (.inputFlag 6)) = true := by
    rw [show
      BoolExpr.eval ({state1} environment state) (.not (.inputFlag 6)) =
        !(BoolExpr.eval ({state1} environment state) (.inputFlag 6)) by
      rfl]
    rw [generatedRunEntryProjectionBlock1ZeroFlagFalse
      environment state prior]
    decide +kernel
  simpa only [NativeOperationInvariant.Holds, List.all_cons, List.all_nil,
    Bool.and_true] using notHolds"""
    )
    pieces.append(
        f"""theorem generatedRunEntryProjectionBlock1EndpointExact
    (environment : NativeWorldEnvironment) (state : MachineState) :
    (generatedRunEntryStep1 environment).targetState state =
      {_state(1, 2)} environment state := by
  rw [{_state_exact_rewrites(1, 2)}]
  rfl

theorem generatedRunEntryProjectionBlock1ControlFacts
    (environment : NativeWorldEnvironment) (state : MachineState)
    (prior : FrameWordPairDirectionProjection state
      (generatedRunEntryProjectionEntryEsp - word32 316)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress) :
    generatedRunEntrySelectorInvariant1.Holds
        ((generatedRunEntryBlock1 environment).terminalState state) /\\
      FrameWordPairDirectionProjection
        ((generatedRunEntryStep1 environment).targetState state)
        (generatedRunEntryProjectionEntryEsp - word32 316)
        (generatedRunEntryProjectionEntryEsp - word32 4)
        generatedRunEntryProjectionInputWordAddress
        generatedRunEntryProjectionInputAddress
        generatedRunEntryProjectionOutputWordAddress
        generatedRunEntryProjectionOutputAddress := by
  have state1 :=
    generatedRunEntryProjectionBlock1State0001Facts environment state prior
  have state2 :=
    generatedRunEntryProjectionBlock1State0002Facts environment state state1
  exact And.intro
    (generatedRunEntryProjectionBlock1SelectorHolds environment state prior)
    (generatedRunEntryProjectionBlock1EndpointExact environment state ▸ state2)

theorem generatedRunEntryProjectionControlEndpointExact
    (environment : NativeWorldEnvironment) (state : MachineState) :
    runCheckedNativeOperationPredicateRoute
        (generatedRunEntryControlRoute environment) state =
      {_state(1, 2)} environment ({_state(0, 10)} environment state) := by
  rw [{_state_exact_rewrites(1, 2)},
    {_state_exact_rewrites(0, 10)}]
  rfl

#print axioms generatedRunEntryProjectionBlock1State0002Facts
#print axioms generatedRunEntryProjectionBlock1ControlFacts
#print axioms generatedRunEntryProjectionControlEndpointExact

end StageA.GeneratedRelational.InterpreterKernelRunEntryProjection"""
    )
    return "\n\n".join(pieces)


def _bulk_projection_type(state_term: str, expected: tuple[str, ...]) -> str:
    fields = "\n      ".join(f"({field})" for field in expected)
    return f"""RunEntryBulkRegisterProjection
      {state_term}
      {fields}"""


def _bulk_step(
    *,
    route: RunEntryRoute,
    instruction: int,
    expected: tuple[str, ...],
    prior_expected: tuple[str, ...] | None,
) -> str:
    source_state = _state(2, instruction)
    target_state = _state(2, instruction + 1)
    edge = _edge(route, 2, instruction)
    exact = _behavior_exact(2, instruction)
    register_shapes = {
        register: _projection_field_exact(2, instruction, register)
        for register in ("eax", "ebx", "ecx", "edx", "esi", "edi")
    }
    esp_shape = _projection_field_exact(2, instruction, "esp")
    ebp_shape = _projection_field_exact(2, instruction, "ebp")
    writes_shape = _projection_field_exact(2, instruction, "writes")
    flags_shape = _projection_field_exact(2, instruction, "flagsBase")
    projection = _projection(2, instruction)
    theorem_name = (
        f"generatedRunEntryProjectionBlock2State{instruction + 1:04d}Facts"
    )
    if prior_expected is None:
        prior_type = f"""FrameWordPairDirectionProjection
      ({source_state} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 316)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress"""
    else:
        prior_type = _bulk_projection_type(
            f"({source_state} environment state)", prior_expected
        )
    word_checked = _word_checked_proof(
        block=2,
        instruction=instruction,
        source_state=source_state,
        simp_terms="",
        concrete_write_address=None,
        indentation=4,
    )
    register_names = ("eax", "ebx", "ecx", "edx", "esi", "edi")
    field_exact_names = {
        register: f"edge{register.title()}ExpressionExact"
        for register in register_names
    }
    field_witnesses = []
    for register in register_names:
        field_witnesses.append(
            f"""  have {field_exact_names[register]} :
      ({edge} environment).replay.behavior.registers.get .{register} =
        {projection}.{register} :=
    (congrArg
      (fun behavior => behavior.registers.get .{register})
      ({exact} environment)).trans
        {register_shapes[register]}"""
        )
    field_witnesses.extend(
        (
            f"""  have edgeEspExpressionExact :
      ({edge} environment).replay.behavior.registers.get .esp =
        {projection}.esp :=
    (congrArg
      (fun behavior => behavior.registers.get .esp)
      ({exact} environment)).trans
        {esp_shape}""",
            f"""  have edgeEbpExpressionExact :
      ({edge} environment).replay.behavior.registers.get .ebp =
        {projection}.ebp :=
    (congrArg
      (fun behavior => behavior.registers.get .ebp)
      ({exact} environment)).trans
        {ebp_shape}""",
            f"""  have edgeWritesExact :
      ({edge} environment).replay.behavior.writes =
        {projection}.writes :=
    (congrArg
      (fun behavior => behavior.writes)
      ({exact} environment)).trans
        {writes_shape}""",
            f"""  have edgeFlagsBaseExact :
      ({edge} environment).replay.behavior.flagsBase =
        {projection}.flagsBase :=
    (congrArg
      (fun behavior => behavior.flagsBase)
      ({exact} environment)).trans
        {flags_shape}""",
        )
    )
    register_proofs = []
    for register in register_names:
        proof_prefix = f"""  · refine
      (congrArg
        (fun next => next.registers.get .{register})
        targetStateExact).trans ?_
    refine
      (CheckedNativeOperationRunningEdge.after_register_of_exact
        ({edge} environment)
        ({source_state} environment state)
        .{register} {projection}.{register}
        {field_exact_names[register]}).trans ?_"""
        if instruction == 0 and register == "edx":
            register_proofs.append(
                f"""{proof_prefix}
    change
      Memory.read32 ({source_state} environment state).memory
          (({source_state} environment state).registers.ebp + word32 16) =
        generatedRunEntryProjectionInputAddress
    rw [prior.ebpExact,
      generatedRunEntryProjectionFrameArgumentAddressExact]
    exact prior.wordExact"""
            )
            continue
        if instruction == 1 and register == "eax":
            register_proofs.append(
                f"""{proof_prefix}
    rfl"""
            )
            continue
        moved_from = {
            (2, "ebx"): "edx",
            (4, "edi"): "eax",
            (5, "esi"): "ebx",
            (6, "ecx"): "edx",
        }.get((instruction, register))
        if moved_from is not None:
            register_proofs.append(
                f"""{proof_prefix}
    change
      ({source_state} environment state).registers.{moved_from} =
        {expected[register_names.index(register)]}
    exact prior.{moved_from}Exact"""
            )
            continue
        if instruction == 3 and register == "edx":
            register_proofs.append(f"""{proof_prefix}
    rfl""")
            continue
        if instruction == 0:
            register_proofs.append(f"""{proof_prefix}
    rfl""")
            continue
        register_proofs.append(
            f"""{proof_prefix}
    change
      ({source_state} environment state).registers.{register} =
        {expected[register_names.index(register)]}
    exact prior.{register}Exact"""
        )
    return f"""theorem {theorem_name}
    (environment : NativeWorldEnvironment) (state : MachineState)
    (prior : {prior_type}) :
    {_bulk_projection_type(f"({target_state} environment state)", expected)} := by
{chr(10).join(field_witnesses)}
  have edgeEspExact :
      (({edge} environment).replay.behavior.registers.get .esp).eval
          ({source_state} environment state) =
        generatedRunEntryProjectionEntryEsp - word32 316 := by
    refine
      (congrArg
        (fun expression =>
          expression.eval ({source_state} environment state))
        edgeEspExpressionExact).trans ?_
    change
      ({source_state} environment state).registers.esp =
        generatedRunEntryProjectionEntryEsp - word32 316
    exact prior.espExact
  have edgeEbpExact :
      (({edge} environment).replay.behavior.registers.get .ebp).eval
          ({source_state} environment state) =
        generatedRunEntryProjectionEntryEsp - word32 4 := by
    refine
      (congrArg
        (fun expression =>
          expression.eval ({source_state} environment state))
        edgeEbpExpressionExact).trans ?_
    change
      ({source_state} environment state).registers.ebp =
        generatedRunEntryProjectionEntryEsp - word32 4
    exact prior.ebpExact
  have projectedWordChecked :
      symbolicWritesAvoidWordChecked
          generatedRunEntryProjectionInputWordAddress
          ({source_state} environment state)
          {projection}.writes =
        true := by
{word_checked}
  have edgeWordChecked :
      symbolicWritesAvoidWordChecked
          generatedRunEntryProjectionInputWordAddress
          ({source_state} environment state)
          ({edge} environment).replay.behavior.writes =
        true :=
    symbolicWritesAvoidWordChecked_of_exact
      generatedRunEntryProjectionInputWordAddress
      ({source_state} environment state)
      ({edge} environment).replay.behavior.writes
      {projection}.writes edgeWritesExact projectedWordChecked
  have edgeFlagsBasePreserved :
      ({edge} environment).replay.behavior.flagsBase = none := by
    simpa only [{projection}] using edgeFlagsBaseExact
  have edgeFrame :
      FrameWordDirectionProjection
        (({edge} environment).after
          ({source_state} environment state))
        (generatedRunEntryProjectionEntryEsp - word32 316)
        (generatedRunEntryProjectionEntryEsp - word32 4)
        generatedRunEntryProjectionInputWordAddress
        generatedRunEntryProjectionInputAddress :=
    StageA.Relational.InterpreterKernelOperationProjection.CheckedNativeOperationRunningEdge.after_frameWordDirectionProjection
      ({edge} environment)
      ({source_state} environment state)
      (generatedRunEntryProjectionEntryEsp - word32 316)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      edgeEspExact edgeEbpExact edgeWordChecked edgeFlagsBasePreserved
      prior.wordExact prior.directionClear
  have targetStateExact :=
    {_state_exact(2, instruction + 1)} environment state
  constructor
  · exact
      (congrArg
        (fun next =>
          FrameWordDirectionProjection next
            (generatedRunEntryProjectionEntryEsp - word32 316)
            (generatedRunEntryProjectionEntryEsp - word32 4)
            generatedRunEntryProjectionInputWordAddress
            generatedRunEntryProjectionInputAddress)
        targetStateExact).mpr edgeFrame
{chr(10).join(register_proofs)}"""


def _block2_expected_rows() -> tuple[tuple[str, ...], ...]:
    input_address = "generatedRunEntryProjectionInputAddress"
    source_register = lambda name: (
        f"({_state(2, 0)} environment state).registers.{name}"
    )
    working = (
        f"(({_state(2, 1)} environment state).registers.ebp + "
        "word32 4294967016)"
    )
    return (
        (
            source_register("eax"),
            source_register("ebx"),
            source_register("ecx"),
            input_address,
            source_register("esi"),
            source_register("edi"),
        ),
        (
            working,
            source_register("ebx"),
            source_register("ecx"),
            input_address,
            source_register("esi"),
            source_register("edi"),
        ),
        (
            working,
            input_address,
            source_register("ecx"),
            input_address,
            source_register("esi"),
            source_register("edi"),
        ),
        (
            working,
            input_address,
            source_register("ecx"),
            "word32 63",
            source_register("esi"),
            source_register("edi"),
        ),
        (
            working,
            input_address,
            source_register("ecx"),
            "word32 63",
            source_register("esi"),
            working,
        ),
        (
            working,
            input_address,
            source_register("ecx"),
            "word32 63",
            input_address,
            working,
        ),
        (
            working,
            input_address,
            "word32 63",
            "word32 63",
            input_address,
            working,
        ),
    )


def _block2_base_source(route: RunEntryRoute) -> str:
    entry = "generatedRunEntryProjectionEntryEsp"
    input_address = "generatedRunEntryProjectionInputAddress"
    return f"""import StageA.{RUN_ENTRY_PROJECTION_BLOCK1_MODULE}

namespace StageA.GeneratedRelational.InterpreterKernelRunEntryProjection

{_common_open(definitions=False)}

{_state_zero_definition(2)}

{_compact_projection_definitions(2, instruction_count=7)}

structure RunEntryBulkRegisterProjection
    (state : MachineState)
    (expectedEax expectedEbx expectedEcx expectedEdx expectedEsi
      expectedEdi : Word) : Prop
    extends FrameWordDirectionProjection state
      ({entry} - word32 316)
      ({entry} - word32 4)
      generatedRunEntryProjectionInputWordAddress
      {input_address} where
  eaxExact : state.registers.eax = expectedEax
  ebxExact : state.registers.ebx = expectedEbx
  ecxExact : state.registers.ecx = expectedEcx
  edxExact : state.registers.edx = expectedEdx
  esiExact : state.registers.esi = expectedEsi
  ediExact : state.registers.edi = expectedEdi

end StageA.GeneratedRelational.InterpreterKernelRunEntryProjection"""


def _block2_step_source(route: RunEntryRoute, instruction: int) -> str:
    expected_rows = _block2_expected_rows()
    imported = (
        RUN_ENTRY_PROJECTION_BLOCK2_BASE_MODULE
        if instruction == 0
        else _block2_step_module(instruction - 1)
    )
    theorem_name = (
        f"generatedRunEntryProjectionBlock2State{instruction + 1:04d}Facts"
    )
    return f"""import StageA.{imported}

namespace StageA.GeneratedRelational.InterpreterKernelRunEntryProjection

{_common_open(definitions=False)}

{_state_transition_definition(route, 2, instruction)}

{_bulk_step(
    route=route,
    instruction=instruction,
    expected=expected_rows[instruction],
    prior_expected=(
        None if instruction == 0 else expected_rows[instruction - 1]
    ),
)}

#print axioms {theorem_name}

end StageA.GeneratedRelational.InterpreterKernelRunEntryProjection"""


def _block2_source(route: RunEntryRoute) -> str:
    entry = "generatedRunEntryProjectionEntryEsp"
    input_address = "generatedRunEntryProjectionInputAddress"
    working = "generatedRunEntryProjectionWorkingAddress"
    return (
        f"""import StageA.{_block2_step_module(6)}

namespace StageA.GeneratedRelational.InterpreterKernelRunEntryProjection

{_common_open(definitions=False)}

theorem generatedRunEntryProjectionBlock2EndpointExact
    (environment : NativeWorldEnvironment) (state : MachineState) :
    (generatedRunEntryBlock2 environment).terminalState state =
      {_state(2, 7)} environment state := by
  rw [{_state_exact_rewrites(2, 7)}]
  rfl

theorem generatedRunEntryDecodedBulkOperandsProjection
    (environment : NativeWorldEnvironment) (state : MachineState)
    (espExact : state.registers.esp = {entry})
    (inputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionInputWordAddress =
        {input_address})
    (outputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionOutputWordAddress =
        generatedRunEntryProjectionOutputAddress)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    let controlState :=
      runCheckedNativeOperationPredicateRoute
        (generatedRunEntryControlRoute environment) state
    let bulkState :=
      (generatedRunEntryBlock2 environment).terminalState controlState
    bulkState.registers.esi = {input_address} /\\
      bulkState.registers.edi = {working} /\\
      bulkState.registers.ecx = word32 63 /\\
      bulkState.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0 := by
  have block0State1 :=
    generatedRunEntryProjectionBlock0State0001Facts environment state
      espExact inputWord outputWord directionClear
  have block0State2 :=
    generatedRunEntryProjectionBlock0State0002Facts environment state
      block0State1
  have block0State3 :=
    generatedRunEntryProjectionBlock0State0003Facts environment state
      block0State2
  have block0State4 :=
    generatedRunEntryProjectionBlock0State0004Facts environment state
      block0State3
  have block0State5 :=
    generatedRunEntryProjectionBlock0State0005Facts environment state
      block0State4
  have block0State6 :=
    generatedRunEntryProjectionBlock0State0006Facts environment state
      block0State5
  have block0State7 :=
    generatedRunEntryProjectionBlock0State0007Facts environment state
      block0State6
  have block0State8 :=
    generatedRunEntryProjectionBlock0State0008Facts environment state
      block0State7
  have block0State9 :=
    generatedRunEntryProjectionBlock0State0009Facts environment state
      block0State8
  have block0State10 :=
    generatedRunEntryProjectionBlock0State0010Facts environment state
      block0State9
  let afterBlock0 := {_state(0, 10)} environment state
  have block1State1 :=
    generatedRunEntryProjectionBlock1State0001Facts environment afterBlock0
      block0State10
  have block1State2 :=
    generatedRunEntryProjectionBlock1State0002Facts environment afterBlock0
      block1State1
  let afterControl := {_state(1, 2)} environment afterBlock0
  have block2State1 :=
    generatedRunEntryProjectionBlock2State0001Facts environment afterControl
      block1State2
  have block2State2 :=
    generatedRunEntryProjectionBlock2State0002Facts environment afterControl
      block2State1
  have block2State3 :=
    generatedRunEntryProjectionBlock2State0003Facts environment afterControl
      block2State2
  have block2State4 :=
    generatedRunEntryProjectionBlock2State0004Facts environment afterControl
      block2State3
  have block2State5 :=
    generatedRunEntryProjectionBlock2State0005Facts environment afterControl
      block2State4
  have block2State6 :=
    generatedRunEntryProjectionBlock2State0006Facts environment afterControl
      block2State5
  have block2State7 :=
    generatedRunEntryProjectionBlock2State0007Facts environment afterControl
      block2State6
  have block2WorkingExact :
      ({_state(2, 1)} environment afterControl).registers.ebp +
          word32 4294967016 =
        {working} :=
    (congrArg (fun base => base + word32 4294967016)
      block2State1.ebpExact).trans
        generatedRunEntryProjectionWorkingAddressFromFrameExact
  have controlStateExact :
      runCheckedNativeOperationPredicateRoute
          (generatedRunEntryControlRoute environment) state =
        afterControl :=
    generatedRunEntryProjectionControlEndpointExact environment state
  have bulkStateExact :
      (generatedRunEntryBlock2 environment).terminalState
          (runCheckedNativeOperationPredicateRoute
            (generatedRunEntryControlRoute environment) state) =
        {_state(2, 7)} environment afterControl :=
    (congrArg
      (generatedRunEntryBlock2 environment).terminalState
      controlStateExact).trans
        (generatedRunEntryProjectionBlock2EndpointExact
          environment afterControl)
  dsimp only
  exact And.intro
    ((congrArg (fun next => next.registers.esi) bulkStateExact).trans
      block2State7.esiExact)
    (And.intro
      (((congrArg (fun next => next.registers.edi) bulkStateExact).trans
        block2State7.ediExact).trans block2WorkingExact)
      (And.intro
        ((congrArg (fun next => next.registers.ecx) bulkStateExact).trans
          block2State7.ecxExact)
        ((congrArg
          (fun next => next.eflags.extractLsb' 10 1)
          bulkStateExact).trans block2State7.directionClear)))

#print axioms generatedRunEntryProjectionBlock2EndpointExact
#print axioms generatedRunEntryDecodedBulkOperandsProjection

end StageA.GeneratedRelational.InterpreterKernelRunEntryProjection"""
    )


def _footprint_theorem(block: int, instruction: int) -> str:
    return (
        f"generatedRunEntryBlock{block}Instruction{instruction:04d}"
        "FootprintDisjoint"
    )


def _edge_footprint_source(
    route: RunEntryRoute,
    *,
    block: int,
    instruction: int,
    edge_kind: str,
    write_depth: int | None,
) -> str:
    edge = _edge(route, block, instruction)
    projection = _projection(block, instruction)
    behavior_exact = _behavior_exact(block, instruction)
    writes_shape = _projection_field_exact(block, instruction, "writes")
    writes = _compact_projection_specs()[block][instruction]["writes"]
    theorem = _footprint_theorem(block, instruction)
    edge_type = (
        "CheckedNativeOperationRunningEdge"
        if edge_kind == "running"
        else "CheckedNativeOperationStoppedEdge"
    )
    footprint = (
        "symbolicWriteFootprint "
        f"({edge} environment).replay.behavior state"
        if edge_kind == "running"
        else (
            f"({edge} environment).cutpoint.postcondition."
            "writeFootprint state"
        )
    )
    if not writes:
        if block == 2 and instruction == 7:
            return f"""theorem {theorem}
    (environment : NativeWorldEnvironment) (state : MachineState) :
    CandidateFootprintsDisjoint generatedRunEntryProtectedRange
      ({footprint}).contains := by
  have materializedWritesExact :
      {_behavior(block, instruction)}.writes = [] := by
    rfl
  have edgeWritesExact :
      ({edge} environment).replay.behavior.writes = [] :=
    (congrArg (fun behavior => behavior.writes)
      ({behavior_exact} environment)).trans materializedWritesExact
  exact
    {edge_type}.footprintDisjoint_of_writes_nil
      ({edge} environment) generatedRunEntryProtectedRange state
      edgeWritesExact"""
        return f"""theorem {theorem}
    (environment : NativeWorldEnvironment) (state : MachineState) :
    CandidateFootprintsDisjoint generatedRunEntryProtectedRange
      ({footprint}).contains := by
  have edgeWritesExact :
      ({edge} environment).replay.behavior.writes = [] := by
    have projected :
        ({edge} environment).replay.behavior.writes =
          {projection}.writes :=
      (congrArg (fun behavior => behavior.writes)
        ({behavior_exact} environment)).trans
          {writes_shape}
    simpa only [{projection}] using projected
  exact
    {edge_type}.footprintDisjoint_of_writes_nil
      ({edge} environment) generatedRunEntryProtectedRange state
      edgeWritesExact"""
    if len(writes) != 1 or write_depth is None:
        raise InterpreterKernelRunEntryProjectionError(
            "Run footprint projection requires one checked stack write"
        )
    address, value = writes[0]
    return f"""theorem {theorem}
    (environment : NativeWorldEnvironment) (state : MachineState)
    (addressExact :
      ({address} : Expr).eval state =
        generatedRunEntryProjectionEntryEsp - word32 {write_depth}) :
    CandidateFootprintsDisjoint generatedRunEntryProtectedRange
      ({footprint}).contains := by
  have edgeWritesExact :
      ({edge} environment).replay.behavior.writes =
        [({address}, {value})] := by
    have projected :
        ({edge} environment).replay.behavior.writes =
          {projection}.writes :=
      (congrArg (fun behavior => behavior.writes)
        ({behavior_exact} environment)).trans
          {writes_shape}
    simpa only [{projection}] using projected
  exact
    {edge_type}.footprintDisjoint_wordRange_singleton
      ({edge} environment)
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionLayout.stateSize state
      ({address} : Expr) ({value} : Expr)
      (generatedRunEntryProjectionEntryEsp - word32 {write_depth})
      edgeWritesExact addressExact
      generatedRunEntryStackWriteDepth{write_depth}BytesAfter"""


def _stack_write_bytes_after_source(depth: int) -> str:
    return f"""theorem generatedRunEntryStackWriteDepth{depth}BytesAfter :
    ∀ byte,
      byte ∈ wordByteAddresses
          (generatedRunEntryProjectionEntryEsp - word32 {depth}) ->
        generatedRunEntryProjectionInputAddress.toNat +
            generatedRunEntryProjectionLayout.stateSize <=
          byte.toNat := by
  intro byte member
  simp [wordByteAddresses] at member
  rcases member with rfl | rfl | rfl | rfl <;> decide +kernel"""


def _running_footprint_fold(
    route: RunEntryRoute,
    *,
    block: int,
    running_count: int,
    state_argument: str,
    address_exact_names: dict[int, str] | None = None,
) -> str:
    address_exact_names = address_exact_names or {}
    domain = "generatedRunEntryProtectedRange"
    candidate = (
        "generatedClosedKernelOperationNativeProgram environment"
    )
    lines = [
        f"""  have block{block}Tail{running_count} :
      checkedNativeOperationRunningTraceFootprintsDisjointAt
        ([] : List (CheckedNativeOperationRunningEdge ({candidate})))
        {domain}
        ({_state(block, running_count)} environment {state_argument}) :=
    True.intro"""
    ]
    for instruction in range(running_count - 1, -1, -1):
        tail = ", ".join(
            f"{_edge(route, block, member)} environment"
            for member in range(instruction + 1, running_count)
        )
        tail_list = f"[{tail}]"
        call = (
            f"{_footprint_theorem(block, instruction)} environment "
            f"({_state(block, instruction)} environment {state_argument})"
        )
        if instruction in address_exact_names:
            call += f" {address_exact_names[instruction]}"
        lines.append(
            f"""  have block{block}Tail{instruction} :
      checkedNativeOperationRunningTraceFootprintsDisjointAt
        ({_edge(route, block, instruction)} environment :: {tail_list})
        {domain}
        ({_state(block, instruction)} environment {state_argument}) :=
    checkedNativeOperationRunningTraceFootprintsDisjointAt_cons_projected
      ({_edge(route, block, instruction)} environment)
      {tail_list} {domain}
      ({_state(block, instruction)} environment {state_argument})
      ({_state(block, instruction + 1)} environment {state_argument})
      ({_state_exact(block, instruction + 1)}
        environment {state_argument})
      ({call})
      block{block}Tail{instruction + 1}"""
        )
    trace = (
        f"generatedNativeOperationFunctionReplay"
        f"{route.function_ordinal:04d}Block{route.path[block].ordinal:04d}"
        "RunningTrace"
    )
    lines.append(
        f"""  have block{block}Running :
      checkedNativeOperationRunningTraceFootprintsDisjointAt
        ({trace} environment).edges
        {domain}
        ({_state(block, 0)} environment {state_argument}) := by
    simpa only [{trace},
      CheckedNativeOperationRunningTrace.edges] using block{block}Tail0"""
    )
    return "\n".join(lines)


def _block0_footprint_source(route: RunEntryRoute) -> str:
    facts = [
        f"""  have block0State1 :=
    generatedRunEntryProjectionBlock0State0001Facts environment state
      espExact inputWord outputWord directionClear"""
    ]
    for index in range(2, 11):
        facts.append(
            f"""  have block0State{index} :=
    generatedRunEntryProjectionBlock0State{index:04d}Facts
      environment state block0State{index - 1}"""
        )
    addresses = {
        0: (
            "(.add (.inputReg .esp) (.constant 4294967292))",
            "generatedRunEntryProjectionBlock0State0000 environment state",
            "state.registers.esp",
            "espExact",
            4,
        ),
        2: (
            "(.add (.inputReg .esp) (.constant 4294967292))",
            "generatedRunEntryProjectionBlock0State0002 environment state",
            (
                "(generatedRunEntryProjectionBlock0State0002 "
                "environment state).registers.esp"
            ),
            "block0State2.espExact",
            8,
        ),
        3: (
            "(.add (.inputReg .esp) (.constant 4294967292))",
            "generatedRunEntryProjectionBlock0State0003 environment state",
            (
                "(generatedRunEntryProjectionBlock0State0003 "
                "environment state).registers.esp"
            ),
            "block0State3.espExact",
            12,
        ),
        4: (
            "(.add (.inputReg .esp) (.constant 4294967292))",
            "generatedRunEntryProjectionBlock0State0004 environment state",
            (
                "(generatedRunEntryProjectionBlock0State0004 "
                "environment state).registers.esp"
            ),
            "block0State4.espExact",
            16,
        ),
        7: (
            "(.add (.inputReg .ebp) (.constant 4294967268))",
            "generatedRunEntryProjectionBlock0State0007 environment state",
            (
                "(generatedRunEntryProjectionBlock0State0007 "
                "environment state).registers.ebp"
            ),
            "block0State7.ebpExact",
            32,
        ),
    }
    address_proofs = []
    for instruction, (
        expression,
        source_state,
        register,
        register_exact,
        depth,
    ) in addresses.items():
        address_proofs.append(
            f"""  have block0Address{instruction} :
      ({expression} : Expr).eval ({source_state}) =
        generatedRunEntryProjectionEntryEsp - word32 {depth} := by
    change {register} + word32 {int(expression.rsplit(' ', 1)[1][:-2])} =
      generatedRunEntryProjectionEntryEsp - word32 {depth}
    rw [{register_exact}]
    decide +kernel"""
        )
    fold = _running_footprint_fold(
        route,
        block=0,
        running_count=9,
        state_argument="state",
        address_exact_names={
            instruction: f"block0Address{instruction}"
            for instruction in addresses
        },
    )
    terminal_edge = _edge(route, 0, 9)
    running_trace = (
        "generatedNativeOperationFunctionReplay"
        f"{route.function_ordinal:04d}Block{route.path[0].ordinal:04d}"
        "RunningTrace"
    )
    return f"""theorem generatedRunEntryBlock0FootprintsAndEndpointFacts
    (environment : NativeWorldEnvironment) (state : MachineState)
    (espExact :
      state.registers.esp = generatedRunEntryProjectionEntryEsp)
    (inputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionInputWordAddress =
        generatedRunEntryProjectionInputAddress)
    (outputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionOutputWordAddress =
        generatedRunEntryProjectionOutputAddress)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    checkedNativeOperationBlockFootprintsDisjointAt
        (generatedRunEntryBlock0 environment)
        generatedRunEntryProtectedRange state /\\
      FrameWordPairDirectionProjection
        ({_state(0, 10)} environment state)
        (generatedRunEntryProjectionEntryEsp - word32 316)
        (generatedRunEntryProjectionEntryEsp - word32 4)
        generatedRunEntryProjectionInputWordAddress
        generatedRunEntryProjectionInputAddress
        generatedRunEntryProjectionOutputWordAddress
        generatedRunEntryProjectionOutputAddress := by
{chr(10).join(facts)}
{chr(10).join(address_proofs)}
{fold}
  have terminalStateExact :
      (generatedRunEntryBlock0 environment).terminalState state =
        {_state(0, 9)} environment state := by
    rw [{_state_exact_rewrites(0, 9)}]
    rfl
  have block0Terminal :
      CandidateFootprintsDisjoint generatedRunEntryProtectedRange
        ((generatedRunEntryBlock0 environment).terminal.cutpoint.postcondition.writeFootprint
          ((generatedRunEntryBlock0 environment).terminalState state)).contains := by
    rw [terminalStateExact]
    exact
      {_footprint_theorem(0, 9)} environment
        ({_state(0, 9)} environment state)
  exact And.intro
    (checkedNativeOperationBlockFootprintsDisjointAt_of_exact
      (generatedRunEntryBlock0 environment)
      ({running_trace} environment)
      generatedRunEntryProtectedRange state
      (by rfl) block0Running block0Terminal)
    block0State10"""


def _block1_footprint_source(route: RunEntryRoute) -> str:
    fold = _running_footprint_fold(
        route,
        block=1,
        running_count=1,
        state_argument="state",
    )
    running_trace = (
        "generatedNativeOperationFunctionReplay"
        f"{route.function_ordinal:04d}Block{route.path[1].ordinal:04d}"
        "RunningTrace"
    )
    return f"""theorem generatedRunEntryBlock1FootprintsAndEndpointFacts
    (environment : NativeWorldEnvironment) (state : MachineState)
    (prior : FrameWordPairDirectionProjection state
      (generatedRunEntryProjectionEntryEsp - word32 316)
      (generatedRunEntryProjectionEntryEsp - word32 4)
      generatedRunEntryProjectionInputWordAddress
      generatedRunEntryProjectionInputAddress
      generatedRunEntryProjectionOutputWordAddress
      generatedRunEntryProjectionOutputAddress) :
    checkedNativeOperationBlockFootprintsDisjointAt
        (generatedRunEntryBlock1 environment)
        generatedRunEntryProtectedRange state /\\
      FrameWordPairDirectionProjection
        ({_state(1, 2)} environment state)
        (generatedRunEntryProjectionEntryEsp - word32 316)
        (generatedRunEntryProjectionEntryEsp - word32 4)
        generatedRunEntryProjectionInputWordAddress
        generatedRunEntryProjectionInputAddress
        generatedRunEntryProjectionOutputWordAddress
        generatedRunEntryProjectionOutputAddress := by
  have block1State1 :=
    generatedRunEntryProjectionBlock1State0001Facts
      environment state prior
  have block1State2 :=
    generatedRunEntryProjectionBlock1State0002Facts
      environment state block1State1
{fold}
  have terminalStateExact :
      (generatedRunEntryBlock1 environment).terminalState state =
        {_state(1, 1)} environment state := by
    rw [{_state_exact_rewrites(1, 1)}]
    rfl
  have block1Terminal :
      CandidateFootprintsDisjoint generatedRunEntryProtectedRange
        ((generatedRunEntryBlock1 environment).terminal.cutpoint.postcondition.writeFootprint
          ((generatedRunEntryBlock1 environment).terminalState state)).contains := by
    rw [terminalStateExact]
    exact
      {_footprint_theorem(1, 1)} environment
        ({_state(1, 1)} environment state)
  exact And.intro
    (checkedNativeOperationBlockFootprintsDisjointAt_of_exact
      (generatedRunEntryBlock1 environment)
      ({running_trace} environment)
      generatedRunEntryProtectedRange state
      (by rfl) block1Running block1Terminal)
    block1State2"""


def _control_footprint_source() -> str:
    return """theorem generatedRunEntryControlFootprintsDisjoint
    (environment : NativeWorldEnvironment) (state : MachineState)
    (espExact :
      state.registers.esp = generatedRunEntryProjectionEntryEsp)
    (inputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionInputWordAddress =
        generatedRunEntryProjectionInputAddress)
    (outputWord :
      Memory.read32 state.memory
          generatedRunEntryProjectionOutputWordAddress =
        generatedRunEntryProjectionOutputAddress)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    checkedNativeOperationPredicateRouteFootprintsDisjointAt
      (generatedRunEntryControlRoute environment)
      generatedRunEntryProtectedRange state := by
  have block0 :=
    generatedRunEntryBlock0FootprintsAndEndpointFacts
      environment state espExact inputWord outputWord directionClear
  let afterBlock0 :=
    generatedRunEntryProjectionBlock0State0010 environment state
  have block1 :=
    generatedRunEntryBlock1FootprintsAndEndpointFacts
      environment afterBlock0 block0.2
  have endpointExact :
      (generatedRunEntryStep0 environment).targetState state =
        afterBlock0 :=
    generatedRunEntryProjectionBlock0EndpointExact environment state
  have block1AtEndpoint :
      checkedNativeOperationBlockFootprintsDisjointAt
        (generatedRunEntryBlock1 environment)
        generatedRunEntryProtectedRange
        ((generatedRunEntryStep0 environment).targetState state) :=
    (congrArg
      (checkedNativeOperationBlockFootprintsDisjointAt
        (generatedRunEntryBlock1 environment)
        generatedRunEntryProtectedRange)
      endpointExact).mpr block1.1
  simpa only [generatedRunEntryControlRoute,
    checkedNativeOperationPredicateRouteFootprintsDisjointAt] using
      And.intro block0.1 block1AtEndpoint"""


def _block2_footprint_source(route: RunEntryRoute) -> str:
    fold = _running_footprint_fold(
        route,
        block=2,
        running_count=7,
        state_argument="state",
    )
    running_trace = (
        "generatedNativeOperationFunctionReplay"
        f"{route.function_ordinal:04d}Block{route.path[2].ordinal:04d}"
        "RunningTrace"
    )
    return f"""theorem generatedRunEntryBulkFootprintsDisjoint
    (environment : NativeWorldEnvironment) (state : MachineState) :
    checkedNativeOperationBlockFootprintsDisjointAt
      (generatedRunEntryBlock2 environment)
      generatedRunEntryProtectedRange state := by
{fold}
  have terminalStateExact :
      (generatedRunEntryBlock2 environment).terminalState state =
        {_state(2, 7)} environment state :=
    generatedRunEntryProjectionBlock2EndpointExact environment state
  have block2Terminal :
      CandidateFootprintsDisjoint generatedRunEntryProtectedRange
        ((generatedRunEntryBlock2 environment).terminal.cutpoint.postcondition.writeFootprint
          ((generatedRunEntryBlock2 environment).terminalState state)).contains := by
    rw [terminalStateExact]
    exact
      {_footprint_theorem(2, 7)} environment
        ({_state(2, 7)} environment state)
  exact
    checkedNativeOperationBlockFootprintsDisjointAt_of_exact
      (generatedRunEntryBlock2 environment)
      ({running_trace} environment)
      generatedRunEntryProtectedRange state
      (by rfl) block2Running block2Terminal"""


def _footprint_source(route: RunEntryRoute) -> str:
    write_depths = {
        (0, 0): 4,
        (0, 2): 8,
        (0, 3): 12,
        (0, 4): 16,
        (0, 7): 32,
    }
    edge_sources = []
    for block, count in enumerate((10, 2, 8)):
        for instruction in range(count):
            edge_sources.append(
                _edge_footprint_source(
                    route,
                    block=block,
                    instruction=instruction,
                    edge_kind=(
                        "stopped" if instruction == count - 1 else "running"
                    ),
                    write_depth=write_depths.get((block, instruction)),
                )
            )
    return f"""import StageA.{RUN_ENTRY_PROJECTION_BLOCK2_MODULE}
import StageA.RelationalInterpreterKernelOperationFootprintProjection

namespace StageA.GeneratedRelational.InterpreterKernelRunEntryProjection

{_common_open(definitions=False)}
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
open StageA.Relational.InterpreterKernelEngineCopy
open StageA.Relational.InterpreterKernelOperationFootprintProjection
open StageA.Relational.InterpreterKernelOperationMemoryRoute
open StageA.GeneratedRelational.InterpreterKernelOperationCandidate

abbrev generatedRunEntryProtectedRange : CandidateFootprint :=
  CandidateWordRange generatedRunEntryProjectionInputAddress
    generatedRunEntryProjectionLayout.stateSize

{chr(10).join(_stack_write_bytes_after_source(depth)
    for depth in sorted(set(write_depths.values())))}

{chr(10).join(edge_sources)}

{_block0_footprint_source(route)}

{_block1_footprint_source(route)}

{_control_footprint_source()}

{_block2_footprint_source(route)}

#print axioms generatedRunEntryControlFootprintsDisjoint
#print axioms generatedRunEntryBulkFootprintsDisjoint

end StageA.GeneratedRelational.InterpreterKernelRunEntryProjection"""


def run_entry_projection_sources(
    route: RunEntryRoute, constants: _ABIConstants
) -> dict[str, str]:
    _validate_route(route)
    return {
        RUN_ENTRY_PROJECTION_BLOCK0_MODULE: _block0_source(route, constants),
        RUN_ENTRY_PROJECTION_BLOCK1_MODULE: _block1_source(route),
        RUN_ENTRY_PROJECTION_BLOCK2_BASE_MODULE: _block2_base_source(route),
        **{
            _block2_step_module(instruction): _block2_step_source(
                route, instruction
            )
            for instruction in range(7)
        },
        RUN_ENTRY_PROJECTION_BLOCK2_MODULE: _block2_source(route),
        RUN_ENTRY_FOOTPRINT_MODULE: _footprint_source(route),
    }


def write_run_entry_projection_bundle(
    *,
    operation_manifest: Path | str,
    abi_plan: Path | str,
    out: Path | str,
) -> None:
    route = build_run_entry_route(operation_manifest)
    constants = _abi_constants(Path(abi_plan))
    output = Path(out) / "StageA"
    output.mkdir(parents=True, exist_ok=True)
    for module, source in run_entry_projection_sources(
        route, constants
    ).items():
        (output / f"{module}.lean").write_text(source, encoding="utf-8")


__all__ = [
    "RUN_ENTRY_PROJECTION_BLOCK0_MODULE",
    "RUN_ENTRY_PROJECTION_BLOCK1_MODULE",
    "RUN_ENTRY_PROJECTION_BLOCK2_BASE_MODULE",
    "RUN_ENTRY_PROJECTION_BLOCK2_MODULE",
    "RUN_ENTRY_FOOTPRINT_MODULE",
    "InterpreterKernelRunEntryProjectionError",
    "run_entry_projection_sources",
    "write_run_entry_projection_bundle",
]
