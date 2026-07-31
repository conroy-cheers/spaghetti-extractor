"""Generate exact runtime evidence for the native x87 replay bridge.

The existing target inventory binds the descriptor table and finite indirect
targets.  This phase additionally binds every replay operand that the PE loader
may relocate.  It emits compact target-indexed static execution facts; the
generic Lean kernel derives dynamic execution universally from those facts.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...stage_binary import StageAInputError, _parse_stage_a_pe
from ...util import sha256_bytes, sha256_file
from .interpreter_kernel_x87_execution import (
    interpreter_kernel_x87_execution_lean_snippet,
)
from .interpreter_x87_replay_bridge_target import (
    X87_REPLAY_BRIDGE_BODY_SIZE,
    X87_REPLAY_BRIDGE_CAPTURE_OFFSET,
    X87_REPLAY_BRIDGE_INSTRUCTION_OFFSET,
    X87_REPLAY_BRIDGE_RETURN_OFFSET,
    X87_REPLAY_BRIDGE_TARGET_PLAN_FORMAT,
    _candidate_bytes,
    _highlow_relocation_counts,
)


X87_REPLAY_BRIDGE_RUNTIME_PLAN_FORMAT = (
    "stage-a-relational-x87-replay-bridge-runtime-plan-v1"
)
X87_REPLAY_BRIDGE_RUNTIME_PLAN_FILENAME = (
    "x87-replay-bridge-runtime-plan.json"
)
X87_REPLAY_BRIDGE_RUNTIME_LEAN_BUNDLE = (
    "GeneratedRelationalInterpreterX87ReplayBridgeRuntime"
)
X87_REPLAY_BRIDGE_RUNTIME_PACK_PREFIX = (
    "GeneratedRelationalInterpreterX87ReplayBridgeRuntimePack"
)
X87_REPLAY_FIXED_TEMPLATE_CHECKS_TYPE = (
    "StageA.GeneratedRelational.InterpreterX87ReplayBridgeRuntime."
    "GeneratedX87ReplayBridgeFixedTemplateChecks"
)
X87_REPLAY_FIXED_TEMPLATE_AUTHORIZING_THEOREM = (
    "StageA.GeneratedRelational.InterpreterX87ReplayBridgeRuntime."
    "generatedX87ReplayBridgeKernelExecutionClosed"
)
X87_REPLAY_FIXED_TEMPLATE_CHECKED_BUNDLE_PREMISE = (
    f"{X87_REPLAY_FIXED_TEMPLATE_CHECKS_TYPE} carrier"
)

_ENGINE_PLAN_FORMAT = "stage-b-native-engine-plan-v1"
_X87_REPLAY_FORMAT = "stage-b-native-exact-x87-command-replay-program-v1"
X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES: tuple[str, ...] = ()
X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS = (
    "source_frame.engineRelated",
    "source_frame.candidateRegisters",
    "source_frame.popFlagsCpl3",
    "source_frame.engineAddressRelation",
    "source_frame.candidateMemory",
    "source_frame.callerSemantics",
    "source_frame.layoutCompatible",
    "source_frame.engineBase",
    "source_frame.memoryUnmapped",
    "source_frame.frameAddressNonzero",
    "source_frame.inputX87FrameAddressValid",
    "source_frame.outputX87FrameAddressValid",
    "source_frame.descriptorMember",
    "source_frame.callTarget",
    "source_frame.targetBefore",
    "source_frame.activeBefore",
    "source_frame.parentBefore",
    "source_frame.inputPointer",
    "source_frame.outputPointer",
    "source_frame.inputOutputAlias",
    "source_frame.representationDisjointImage",
    "source_frame.stackDisjoint",
    "source_frame.frameDisjointImage",
    "source_frame.frameDisjointOperand",
    "source_frame.privateStackPointerNonzero",
    "source_frame.privateStackAddressValid",
    "source_frame.privateStackDisjointFrame",
    "source_frame.privateStackDisjointRepresentation",
    "source_frame.privateStackDisjointOperand",
    "source_frame.privateStackDisjointImage",
    "source_frame.logicalScratchDisjointFrame",
    "source_frame.logicalScratchAddressValid",
    "source_frame.logicalScratchDisjointPrivateStack",
    "source_frame.logicalScratchDisjointRepresentation",
    "source_frame.logicalScratchDisjointOperand",
    "source_frame.logicalScratchDisjointImage",
    "source_frame.operandDisjointRepresentation",
    "source_frame.operandDisjointRuntimeCells",
    "source_frame.inputFrame.encoded",
    "source_frame.inputFrame.related",
    "source_frame.inputCandidateRepresentable",
    "source_frame.candidateX87",
    "source_frame.commandInput",
    "source_frame.faultFree",
)
X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES: tuple[str, ...] = ()
X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES: tuple[str, ...] = ()
X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES = (
    X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES
)


class X87ReplayBridgeRuntimeGenerationError(StageAInputError):
    """The runtime evidence inputs are malformed, stale, or ambiguous."""


@dataclass(frozen=True)
class X87ReplayRelocatedOperandPlan:
    descriptor_id: int
    byte_offset: int
    original_operand_rva: int
    candidate_operand_rva: int
    target_rva: int

    def payload(self) -> dict[str, int]:
        return {
            "descriptor_id": self.descriptor_id,
            "byte_offset": self.byte_offset,
            "original_operand_rva": self.original_operand_rva,
            "candidate_operand_rva": self.candidate_operand_rva,
            "target_rva": self.target_rva,
        }


@dataclass(frozen=True)
class X87ReplayRuntimeTargetPlan:
    descriptor_id: int
    descriptor_rva: int
    bridge_target_rva: int
    instruction_rva: int
    instruction_bytes: bytes
    operand: X87ReplayRelocatedOperandPlan | None

    def payload(self) -> dict[str, Any]:
        return {
            "descriptor_id": self.descriptor_id,
            "descriptor_rva": self.descriptor_rva,
            "bridge_target_rva": self.bridge_target_rva,
            "instruction_rva": self.instruction_rva,
            "instruction_bytes": self.instruction_bytes.hex(),
            "operand": None if self.operand is None else self.operand.payload(),
        }


@dataclass(frozen=True)
class X87ReplayBridgeRuntimePlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    target_plan_sha256: str
    native_engine_plan_sha256: str
    targets: tuple[X87ReplayRuntimeTargetPlan, ...]

    @property
    def relocated_operand_count(self) -> int:
        return sum(target.operand is not None for target in self.targets)

    def payload(self) -> dict[str, Any]:
        core: dict[str, Any] = {
            "format": X87_REPLAY_BRIDGE_RUNTIME_PLAN_FORMAT,
            "status": "complete",
            "diagnostic_status": "kernel_execution_closed",
            "acceptance_authority": False,
            "static_evidence": True,
            "conditional_theorem": (
                "StageA.Relational.InterpreterKernelX87Execution."
                "executeKernelReduction"
            ),
            "checked_executor": (
                "StageA.Relational.InterpreterKernelX87Execution."
                "exactNativeX87ReplayFixedTemplateCertificate_isSome"
            ),
            "checked_execution_type": X87_REPLAY_FIXED_TEMPLATE_CHECKS_TYPE,
            "checked_bundle_inhabited": True,
            "x87_semantics_profile": (
                "arbitrary-shared-deterministic-stage-a-x87-semantics"
            ),
            "fault_profile": "checked-fault-free-singleton",
            "post_state_contract": (
                "checked-split-engine-state-v1:"
                "non-x87-fields+memory-effects+physical-x87-frame"
            ),
            "authorizing_theorem": X87_REPLAY_FIXED_TEMPLATE_AUTHORIZING_THEOREM,
            "authorizing_theorem_premises": [],
            "required_checked_target_terms": [
                "StageA.GeneratedRelational.InterpreterX87ReplayBridgeRuntime."
                "generatedX87ReplayBridgeFixedTemplateStaticExecution"
                f"{target.descriptor_id:04d}"
                for target in self.targets
            ],
            "remaining_proof_premises": list(
                X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES
            ),
            "assumed_source_frame_fields": list(
                X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS
            ),
            "remaining_program_binding_fields": list(
                X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES
            ),
            "remaining_fixed_template_fields": list(
                X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES
            ),
            "remaining_executor_fields": list(
                X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES
            ),
            "candidate": {
                "path": self.candidate_path.name,
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "target_plan_sha256": self.target_plan_sha256,
                "native_engine_plan_sha256": self.native_engine_plan_sha256,
            },
            "counts": {
                "runtime_targets": len(self.targets),
                "relocated_operands": self.relocated_operand_count,
                "unbound_relocated_operands": 0,
            },
            "targets": [target.payload() for target in self.targets],
        }
        core["artifact_sha256"] = sha256_bytes(
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        )
        return core


def build_x87_replay_bridge_runtime_plan(
    *,
    candidate_pe: Path | str,
    target_plan: Path | str,
    native_engine_plan: Path | str,
) -> X87ReplayBridgeRuntimePlan:
    candidate_path = _regular_file(candidate_pe, "candidate PE")
    target_path = _regular_file(target_plan, "x87 replay target plan")
    engine_path = _regular_file(native_engine_plan, "native engine plan")
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    target_payload = _json_object(target_path, "x87 replay target plan")
    engine_payload = _json_object(engine_path, "native engine plan")

    if target_payload.get("format") != X87_REPLAY_BRIDGE_TARGET_PLAN_FORMAT:
        raise X87ReplayBridgeRuntimeGenerationError(
            "x87 replay target plan has an unsupported format"
        )
    target_candidate = _object(target_payload.get("candidate"), "target candidate")
    if (
        target_candidate.get("sha256") != candidate_sha256
        or target_candidate.get("size") != candidate_size
    ):
        raise X87ReplayBridgeRuntimeGenerationError(
            "x87 replay target plan is bound to a different candidate PE"
        )
    if engine_payload.get("format") != _ENGINE_PLAN_FORMAT:
        raise X87ReplayBridgeRuntimeGenerationError(
            "native engine plan has an unsupported format"
        )
    target_inputs = _object(target_payload.get("inputs"), "target plan inputs")
    if target_inputs.get("native_engine_plan_sha256") != sha256_file(engine_path):
        raise X87ReplayBridgeRuntimeGenerationError(
            "x87 replay target plan is bound to a different native engine plan"
        )

    table = _object(target_payload.get("table"), "x87 replay target table")
    descriptors = _objects(table.get("descriptors"), "x87 replay descriptors")
    mappings = _objects(table.get("frame_mappings"), "x87 replay frame mappings")
    replays = _objects(engine_payload.get("x87_replays"), "native x87 replays")
    if not descriptors or len(descriptors) != len(mappings) or len(descriptors) != len(
        replays
    ):
        raise X87ReplayBridgeRuntimeGenerationError(
            "descriptor, frame-mapping, and native replay inventories differ"
        )

    binary = _parse_stage_a_pe(candidate_path)
    try:
        relocation_counts = _highlow_relocation_counts(binary)
        targets = tuple(
            _runtime_target(
                binary=binary,
                relocation_counts=relocation_counts,
                descriptor=descriptor,
                mapping=mapping,
                replay=replay,
                expected_id=index,
            )
            for index, (descriptor, mapping, replay) in enumerate(
                zip(descriptors, mappings, replays, strict=True)
            )
        )
    finally:
        binary.pe.close()

    return X87ReplayBridgeRuntimePlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        target_plan_sha256=sha256_file(target_path),
        native_engine_plan_sha256=sha256_file(engine_path),
        targets=targets,
    )


def x87_replay_bridge_runtime_lean_sources(
    plan: X87ReplayBridgeRuntimePlan,
    *,
    target_module: str = "GeneratedRelationalInterpreterX87ReplayBridgeTarget",
    candidate_replay_module: str = (
        "GeneratedInterpreterX87CandidateReplayBundle"
    ),
    candidate_replay_namespace: str = (
        "StageA.GeneratedRelational.CandidateX87Replay"
    ),
    candidate_replay_handler: str = (
        "checkedInterpreterX87CandidateReplayBundleHandler"
    ),
    candidate_replay_inventory: str = (
        "checkedInterpreterX87CandidateReplayBundleExactInventory"
    ),
    original_pe_name: str = "StageA.GeneratedRelational.originalPe",
    pack_size: int = 32,
) -> dict[str, str]:
    if pack_size <= 0:
        raise X87ReplayBridgeRuntimeGenerationError("pack size must be positive")
    if not plan.targets:
        raise X87ReplayBridgeRuntimeGenerationError(
            "runtime target inventory must not be empty"
        )

    sources: dict[str, str] = {}
    pack_modules: list[str] = []
    static_execution_accessors: list[str] = []
    runtime_target_names: list[str] = []
    for pack_index, start in enumerate(range(0, len(plan.targets), pack_size)):
        rows = plan.targets[start : start + pack_size]
        module = f"{X87_REPLAY_BRIDGE_RUNTIME_PACK_PREFIX}{pack_index:04d}"
        pack_modules.append(module)
        definitions: list[str] = []
        for row in rows:
            suffix = f"{row.descriptor_id:04d}"
            operand_name = f"generatedX87ReplayBridgeOperand{suffix}"
            runtime_name = f"generatedX87ReplayBridgeRuntimeTarget{suffix}"
            static_execution_name = (
                f"generatedX87ReplayBridgeFixedTemplateStaticExecution{suffix}"
            )
            runtime_target_names.append(runtime_name)
            static_execution_accessors.append(static_execution_name)
            definitions.append(_lean_operand(operand_name, row.operand))
            definitions.append(
                f"""def {runtime_name} :
    ExactNativeX87ReplayRuntimeTarget generatedX87ReplayBridgeTable
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks := {{
  target := generatedX87ReplayBridgeTargetBinding{suffix}
  operand := {operand_name}
  operandChecked := by decide +kernel
  layoutChecked := by decide +kernel
}}"""
            )
            definitions.append(
                f"""def {static_execution_name} :
    ExactNativeX87ReplayFixedTemplateStaticExecution {runtime_name} :=
  exactNativeX87ReplayFixedTemplateStaticExecutionOfIsSome {runtime_name}
    (by decide +kernel)"""
            )
        sources[f"{module}.lean"] = f"""import StageA.RelationalInterpreterKernelX87Execution
import StageA.{target_module}

namespace StageA.GeneratedRelational.InterpreterX87ReplayBridgeRuntime

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterKernelX87Execution
open StageA.Relational.InterpreterX87ReplayBridgeTarget
open StageA.Relational.InterpreterX87ReplayBridgeRuntime
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterX87ReplayBridgeTarget

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{"\n\n".join(definitions)}

end StageA.GeneratedRelational.InterpreterX87ReplayBridgeRuntime
"""

    imports = "\n".join(f"import StageA.{module}" for module in pack_modules)
    kernel_execution = interpreter_kernel_x87_execution_lean_snippet()
    static_case_proofs = _lean_static_target_cases(static_execution_accessors)
    sources[f"{X87_REPLAY_BRIDGE_RUNTIME_LEAN_BUNDLE}.lean"] = f"""{imports}
import StageA.RelationalInterpreterKernelX87Execution
import StageA.{candidate_replay_module}

namespace StageA.GeneratedRelational.InterpreterX87ReplayBridgeRuntime

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterKernelX87Execution
open StageA.Relational.InterpreterX87ReplayBridgeTarget
open StageA.Relational.InterpreterX87ReplayBridgeRuntime
open StageA.GeneratedRelational.InterpreterKernelData
open StageA.GeneratedRelational.InterpreterX87ReplayBridgeTarget

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedX87ReplayBridgeRuntimeTargets : List
    (ExactNativeX87ReplayRuntimeTarget generatedX87ReplayBridgeTable
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks) :=
  [{", ".join(runtime_target_names)}]

def generatedX87ReplayBridgeRuntimeInventory :
    ExactNativeX87ReplayRuntimeInventory generatedX87ReplayBridgeTable
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks := {{
  static := generatedX87ReplayBridgeTargetInventory
  targets := generatedX87ReplayBridgeRuntimeTargets
  targetsExact := by rfl
  relocatedOperandCount := {plan.relocated_operand_count}
  relocatedOperandsExact := by decide +kernel
}}

def generatedX87ReplayBridgeFixedTemplateStaticInventory :
    ExactNativeX87ReplayFixedTemplateStaticInventory
      generatedX87ReplayBridgeRuntimeInventory := {{
  forTarget := by
    intro runtimeTarget member
    change List.Mem runtimeTarget generatedX87ReplayBridgeRuntimeTargets at member
    unfold generatedX87ReplayBridgeRuntimeTargets at member
{static_case_proofs}
}}

def generatedX87ReplayBridgeOriginalPe : PE32 := {original_pe_name}

def generatedX87ReplayBridgeHandler : CandidateReplayHandler :=
  {candidate_replay_namespace}.{candidate_replay_handler}

def generatedX87ReplayBridgeSemanticInventory :=
  {candidate_replay_namespace}.{candidate_replay_inventory}

theorem generatedX87ReplayBridgeHandlerMatchesSemanticInventory :
    generatedX87ReplayBridgeHandler =
      {candidate_replay_namespace}.{candidate_replay_handler} := rfl

def generatedX87ReplayBridgeHandlerInventoryCorrespondence :
    ExactNativeX87ReplayHandlerInventoryCorrespondence
      generatedX87ReplayBridgeRuntimeInventory generatedX87ReplayBridgeOriginalPe
      generatedX87ReplayBridgeHandler := {{
  handlerExact := rfl
}}

def GeneratedX87ReplayBridgeSourceFrameGoal
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      generatedX87ReplayBridgeTable generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks)
    (caller logicalInput : MachineState) :=
  ExactNativeX87ReplaySourceFrame runtimeTarget generatedX87ReplayBridgeOriginalPe
    caller logicalInput

def GeneratedX87ReplayBridgeSourceFrameHolds
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      generatedX87ReplayBridgeTable generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks)
    (caller logicalInput : MachineState) : Prop :=
  ExactNativeX87ReplaySourceFrameHolds runtimeTarget
    generatedX87ReplayBridgeOriginalPe caller logicalInput

theorem generatedX87ReplayBridgeSourceFrameEntails
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      generatedX87ReplayBridgeTable generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks)
    (caller logicalInput : MachineState)
    (source : GeneratedX87ReplayBridgeSourceFrameGoal runtimeTarget caller
      logicalInput) :
    GeneratedX87ReplayBridgeSourceFrameHolds runtimeTarget caller logicalInput :=
  Nonempty.intro source

def GeneratedX87ReplayBridgeTemplateExecutionGoal
    (program : ExactNestedNativeWorldProgram) : Prop :=
  ExactNativeX87ReplayTemplateExecution
    generatedX87ReplayBridgeRuntimeInventory program
    generatedX87ReplayBridgeOriginalPe generatedX87ReplayBridgeHandler

def GeneratedX87ReplayBridgeKernelExecutionGoal
    (program : ExactNestedNativeWorldProgram) : Prop :=
  ExactNativeX87ReplayBridgeKernelExecution
    generatedX87ReplayBridgeRuntimeInventory program
    generatedX87ReplayBridgeOriginalPe generatedX87ReplayBridgeHandler

/-- Compatibility goal retained for downstream theorem interfaces.  Universal
dynamic execution is kernel-derived from the checked static inventory, so no
target-indexed execution premise remains. -/
def GeneratedX87ReplayBridgeFixedTemplateChecks
    (_carrier : ExactNestedNativeWorldProgram) : Prop :=
  True

theorem generatedX87ReplayBridgeFixedTemplateChecks
    (carrier : ExactNestedNativeWorldProgram) :
    GeneratedX87ReplayBridgeFixedTemplateChecks carrier :=
  True.intro

def generatedX87ReplayBridgeFixedTemplateExecutor
    (carrier : ExactNestedNativeWorldProgram)
    (_checked : GeneratedX87ReplayBridgeFixedTemplateChecks carrier) :
    ExactNativeX87ReplayFixedTemplateExecutor
      generatedX87ReplayBridgeRuntimeInventory
      (bindExactNativeX87ReplayNestedProgram
        generatedX87ReplayBridgeRuntimeInventory carrier)
      generatedX87ReplayBridgeOriginalPe := {{
  staticInventory := generatedX87ReplayBridgeFixedTemplateStaticInventory
}}

{kernel_execution}

theorem generatedX87ReplayBridgeTemplateExecutionClosed
    (carrier : ExactNestedNativeWorldProgram) :
    GeneratedX87ReplayBridgeTemplateExecutionGoal
      (generatedX87ReplayBridgeNestedProgram carrier) :=
  generatedX87ReplayBridgeTemplateExecution carrier
    (generatedX87ReplayBridgeFixedTemplateChecks carrier)

theorem generatedX87ReplayBridgeRunForSourceFrame
    (program : ExactNestedNativeWorldProgram)
    (certificate : GeneratedX87ReplayBridgeTemplateExecutionGoal program)
    (runtimeTarget : ExactNativeX87ReplayRuntimeTarget
      generatedX87ReplayBridgeTable generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks)
    (member : List.Mem runtimeTarget generatedX87ReplayBridgeRuntimeTargets)
    (caller logicalInput : MachineState)
    (source : GeneratedX87ReplayBridgeSourceFrameGoal runtimeTarget caller
      logicalInput) :
    Nonempty (ExactNativeX87ReplayBridgeTemplateRun runtimeTarget program
      generatedX87ReplayBridgeHandler) := by
  apply Exists.elim
    (certificate.runForTarget runtimeTarget member caller logicalInput source)
  intro run _runExact
  exact Nonempty.intro run

#print axioms generatedX87ReplayBridgeSourceFrameEntails
#print axioms generatedX87ReplayBridgeFixedTemplateStaticInventory
#print axioms generatedX87ReplayBridgeFixedTemplateChecks
#print axioms generatedX87ReplayBridgeFixedTemplateExecutor
#print axioms generatedX87ReplayBridgeTemplateExecutionClosed
#print axioms generatedX87ReplayBridgeRunForSourceFrame

end StageA.GeneratedRelational.InterpreterX87ReplayBridgeRuntime
"""
    return sources


def _runtime_target(
    *,
    binary: Any,
    relocation_counts: Mapping[int, int],
    descriptor: Mapping[str, Any],
    mapping: Mapping[str, Any],
    replay: Mapping[str, Any],
    expected_id: int,
) -> X87ReplayRuntimeTargetPlan:
    descriptor_id = _u32(descriptor.get("id"), "descriptor id")
    mapping_id = _u32(mapping.get("descriptor_id"), "frame mapping descriptor id")
    replay_id = _u32(replay.get("id"), "native replay id")
    if (descriptor_id, mapping_id, replay_id) != (
        expected_id,
        expected_id,
        expected_id,
    ):
        raise X87ReplayBridgeRuntimeGenerationError(
            "x87 replay IDs are not contiguous and aligned"
        )
    if replay.get("format") != _X87_REPLAY_FORMAT:
        raise X87ReplayBridgeRuntimeGenerationError(
            f"x87 replay {expected_id} has an unsupported format"
        )
    instruction = _hex_bytes(
        descriptor.get("instruction_bytes"), "descriptor instruction bytes"
    )
    replay_instruction = _hex_bytes(
        replay.get("instruction_bytes"), "native replay instruction bytes"
    )
    path = _hex_bytes(
        mapping.get("instruction_path_bytes"), "candidate instruction path"
    )
    instruction_rva = _u32(mapping.get("instruction_rva"), "instruction RVA")
    bridge_target_rva = _u32(
        mapping.get("bridge_target_rva"), "bridge target RVA"
    )
    bridge_body = _hex_bytes(
        mapping.get("bridge_body_bytes"), "candidate bridge body"
    )
    if (
        not instruction
        or instruction != replay_instruction
        or path != instruction
        or _candidate_bytes(
            binary, instruction_rva, len(instruction), "candidate replay instruction"
        )
        != instruction
    ):
        raise X87ReplayBridgeRuntimeGenerationError(
            f"x87 replay {expected_id} instruction bytes are not exact"
        )
    if (
        len(bridge_body) != X87_REPLAY_BRIDGE_BODY_SIZE
        or X87_REPLAY_BRIDGE_INSTRUCTION_OFFSET + len(instruction)
        > X87_REPLAY_BRIDGE_CAPTURE_OFFSET
        or bridge_body[0:5] != b"\x55\x53\x56\x57\xa1"
        or instruction_rva
        != bridge_target_rva + X87_REPLAY_BRIDGE_INSTRUCTION_OFFSET
        or bridge_body[9:52]
        != bytes.fromhex(
            "89600cdd60148b40048b58048b48088b70108b78148b68188b601c"
            "ffb0f0000000ff308b500c589d909090"
        )
        or bridge_body[52 : 52 + len(instruction)] != instruction
        or bridge_body[52 + len(instruction) : X87_REPLAY_BRIDGE_CAPTURE_OFFSET]
        != b"\x90" * (
            X87_REPLAY_BRIDGE_CAPTURE_OFFSET
            - X87_REPLAY_BRIDGE_INSTRUCTION_OFFSET
            - len(instruction)
        )
        or bridge_body[72:75] != b"\x9c\x50\xa1"
        or bridge_body[79:X87_REPLAY_BRIDGE_BODY_SIZE]
        != bytes.fromhex(
            "ddb0800000008b50088b0c24890a0f9242200f9a42300f9442240f984228"
            "0f90422c8b5c24048b48048b89f000000081e12af3ffff81e3d50c000009"
            "d9898af0000000"
            "90909090909090909090"
            "c74010000000008b600cfc5f5e5b5dc390909090"
        )
        or bridge_body[X87_REPLAY_BRIDGE_RETURN_OFFSET] != 0xC3
    ):
        raise X87ReplayBridgeRuntimeGenerationError(
            f"x87 replay {expected_id} bridge template is not exact"
        )

    relocation = replay.get("base_relocation")
    operand: X87ReplayRelocatedOperandPlan | None
    span_relocations = sum(
        relocation_counts.get(instruction_rva + offset, 0)
        for offset in range(len(instruction))
    )
    if relocation is None:
        if span_relocations != 0:
            raise X87ReplayBridgeRuntimeGenerationError(
                f"x87 replay {expected_id} has an unbound candidate relocation"
            )
        operand = None
    else:
        raw = _object(relocation, f"x87 replay {expected_id} relocation")
        byte_offset = _u32(raw.get("operand_byte_offset"), "relocation byte offset")
        target_rva = _u32(raw.get("target_rva"), "relocation target RVA")
        original_operand_rva = _u32(
            raw.get("source_rva"), "original relocation operand RVA"
        )
        if (
            raw.get("kind") != "highlow"
            or raw.get("type") != 3
            or raw.get("width") != 4
            or byte_offset + 4 > len(instruction)
            or original_operand_rva
            != _u32(replay.get("rva_start"), "replay start RVA") + byte_offset
            or struct.unpack_from("<I", instruction, byte_offset)[0]
            != _u32(replay.get("image_base"), "replay image base") + target_rva
        ):
            raise X87ReplayBridgeRuntimeGenerationError(
                f"x87 replay {expected_id} has malformed relocation metadata"
            )
        candidate_operand_rva = instruction_rva + byte_offset
        candidate_value = struct.unpack(
            "<I",
            _candidate_bytes(
                binary, candidate_operand_rva, 4, "candidate replay operand"
            ),
        )[0]
        if (
            candidate_value != binary.image_base + target_rva
            or relocation_counts.get(candidate_operand_rva, 0) != 1
            or span_relocations != 1
        ):
            raise X87ReplayBridgeRuntimeGenerationError(
                f"x87 replay {expected_id} candidate relocation is not exact"
            )
        operand = X87ReplayRelocatedOperandPlan(
            descriptor_id=descriptor_id,
            byte_offset=byte_offset,
            original_operand_rva=original_operand_rva,
            candidate_operand_rva=candidate_operand_rva,
            target_rva=target_rva,
        )

    return X87ReplayRuntimeTargetPlan(
        descriptor_id=descriptor_id,
        descriptor_rva=_u32(descriptor.get("descriptor_rva"), "descriptor RVA"),
        bridge_target_rva=_u32(
            descriptor.get("bridge_target_rva"), "bridge target RVA"
        ),
        instruction_rva=instruction_rva,
        instruction_bytes=instruction,
        operand=operand,
    )


def _lean_operand(
    name: str, operand: X87ReplayRelocatedOperandPlan | None
) -> str:
    if operand is None:
        return f"def {name} : NativeX87ReplayOperandBinding := .none"
    return f"""def {name} : NativeX87ReplayOperandBinding :=
  .relocated {{
    descriptorId := {operand.descriptor_id}
    byteOffset := {operand.byte_offset}
    originalOperandRva := {operand.original_operand_rva}
    candidateOperandRva := {operand.candidate_operand_rva}
    targetRva := {operand.target_rva}
  }}"""


def _lean_static_target_cases(
    accessors: Sequence[str],
    *,
    indent: str = "    ",
) -> str:
    lines: list[str] = []
    for accessor in accessors:
        lines.extend(
            (
                f"{indent}rcases List.mem_cons.mp member with targetExact | member",
                f"{indent}all_goals first",
                f"{indent}  | (subst runtimeTarget; exact Nonempty.intro {accessor})",
                f"{indent}  | skip",
            )
        )
    lines.append(f"{indent}exact (List.not_mem_nil member).elim")
    return "\n".join(lines)


def _regular_file(value: Path | str, label: str) -> Path:
    path = Path(value)
    if not path.is_file() or path.is_symlink():
        raise X87ReplayBridgeRuntimeGenerationError(
            f"{label} is not a regular file: {path}"
        )
    return path


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise X87ReplayBridgeRuntimeGenerationError(
            f"cannot read {label}: {exc}"
        ) from exc
    return _object(value, label)


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise X87ReplayBridgeRuntimeGenerationError(f"{label} must be an object")
    return value


def _objects(value: Any, label: str) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list):
        raise X87ReplayBridgeRuntimeGenerationError(f"{label} must be an array")
    return tuple(_object(item, f"{label} entry") for item in value)


def _u32(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise X87ReplayBridgeRuntimeGenerationError(f"{label} must be a uint32")
    return value


def _hex_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise X87ReplayBridgeRuntimeGenerationError(
            f"{label} must be even-length hexadecimal"
        )
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise X87ReplayBridgeRuntimeGenerationError(
            f"{label} must be hexadecimal"
        ) from exc


__all__ = [
    "X87_REPLAY_BRIDGE_RUNTIME_LEAN_BUNDLE",
    "X87_REPLAY_BRIDGE_RUNTIME_PACK_PREFIX",
    "X87_REPLAY_BRIDGE_RUNTIME_PLAN_FILENAME",
    "X87_REPLAY_BRIDGE_RUNTIME_PLAN_FORMAT",
    "X87_REPLAY_FIXED_TEMPLATE_AUTHORIZING_THEOREM",
    "X87_REPLAY_FIXED_TEMPLATE_CERTIFICATE_PREMISES",
    "X87_REPLAY_FIXED_TEMPLATE_CHECKED_BUNDLE_PREMISE",
    "X87_REPLAY_FIXED_TEMPLATE_CHECKS_TYPE",
    "X87_REPLAY_FIXED_TEMPLATE_EXECUTOR_PREMISES",
    "X87_REPLAY_FIXED_TEMPLATE_PROGRAM_BINDING_PREMISES",
    "X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES",
    "X87_REPLAY_FIXED_TEMPLATE_SOURCE_FRAME_ASSUMPTIONS",
    "X87ReplayBridgeRuntimeGenerationError",
    "X87ReplayBridgeRuntimePlan",
    "X87ReplayRelocatedOperandPlan",
    "X87ReplayRuntimeTargetPlan",
    "build_x87_replay_bridge_runtime_plan",
    "x87_replay_bridge_runtime_lean_sources",
]
