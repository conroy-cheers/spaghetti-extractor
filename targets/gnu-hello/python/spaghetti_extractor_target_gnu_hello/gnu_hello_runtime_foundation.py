"""Bind GNU hello to the checked mixed runtime-foundation interfaces.

The GNU acceptance profile is synchronous and callback-free at its parent
external boundary.  A separate nested contract retains the exact callback
relation for later callback-capable carriers.  Root state facts select the
launch side of the phase-aware machine relation; wrapper replay must establish
the runtime side.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.util import write_json


GNU_HELLO_RUNTIME_FOUNDATION_FORMAT = (
    "stage-a-gnu-hello-runtime-foundation-v1"
)
GNU_HELLO_RUNTIME_FOUNDATION_MODULE = "GeneratedGnuHelloRuntimeFoundation"
GNU_HELLO_RUNTIME_FOUNDATION_MANIFEST = "gnu-hello-runtime-foundation.json"

_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")


@dataclass(frozen=True)
class GnuHelloRuntimeFoundationSpec:
    module_name: str = GNU_HELLO_RUNTIME_FOUNDATION_MODULE
    namespace: str = (
        "StageA.GeneratedRelational.GnuHelloRuntimeFoundation"
    )
    requirements_module: str = "StageA.GeneratedGnuHelloAcceptanceRequirements"
    requirements_namespace: str = (
        "StageA.GeneratedRelational.GnuHelloAcceptanceRequirements"
    )

    def validate(self) -> None:
        if _LOCAL_NAME.fullmatch(self.module_name) is None:
            raise StageAInputError(
                "GNU hello runtime foundation module_name must be a Lean name"
            )
        for label, value in (
            ("namespace", self.namespace),
            ("requirements_module", self.requirements_module),
            ("requirements_namespace", self.requirements_namespace),
        ):
            if _LEAN_NAME.fullmatch(value) is None:
                raise StageAInputError(
                    f"GNU hello runtime foundation {label} must be a Lean name"
                )


@dataclass(frozen=True)
class GnuHelloRuntimeFoundationPlan:
    spec: GnuHelloRuntimeFoundationSpec

    def payload(self) -> dict[str, object]:
        return {
            "format": GNU_HELLO_RUNTIME_FOUNDATION_FORMAT,
            "phase": "gnu-hello-runtime-foundation",
            "complete": True,
            "status": "source-ready",
            "acceptance_authority": False,
            "report_authority": False,
            "lean_check_required": True,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "failure_mode": "fail-closed",
            "outputs": {
                "lean_module": f"StageA/{self.spec.module_name}.lean",
            },
            "constructed_terms": {
                "continuation_targets": (
                    "generatedContinuationTargetsRelated"
                ),
                "callback_return_addresses": (
                    "generatedCallbackReturnAddressesRelated"
                ),
                "external_frames": "generatedExternalFrames",
                "nested_external_frames": "generatedNestedExternalFrames",
                "launch_world": "generatedLaunchWorld",
                "launch_state_pair": "generatedConcreteLaunchPair",
                "launch_states_related": "generatedLaunchRelated",
                "launch_realizable": "generatedLaunchRealizable",
            },
            "gnu_profile": {
                "parent_external_callbacks": "must-be-empty",
                "nested_callback_relation": "exact-recursive",
                "root_bootstrap_relation": "launch",
                "post_wrapper_machine_phase": "runtime",
            },
            "blocking_obligations": [],
            "forbidden_shortcuts": [
                "trivial relation",
                "submitted runtime state relation",
                "manifest or status authority",
                "callback-frame erasure",
            ],
        }


def build_gnu_hello_runtime_foundation_plan(
    spec: GnuHelloRuntimeFoundationSpec | None = None,
) -> GnuHelloRuntimeFoundationPlan:
    selected = spec or GnuHelloRuntimeFoundationSpec()
    selected.validate()
    return GnuHelloRuntimeFoundationPlan(selected)


def gnu_hello_runtime_foundation_source(
    plan: GnuHelloRuntimeFoundationPlan,
) -> str:
    spec = plan.spec
    spec.validate()
    return f"""import {spec.requirements_module}
import StageA.RelationalInterpreterMixedRuntimeFoundation

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedRuntimeFoundation
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

namespace Requirements := {spec.requirements_namespace}
namespace SourceRules :=
  StageA.GeneratedRelational.GnuHelloConstructiveSourceRules

/-- GNU continuation IDs and candidate RVAs are related only by the canonical
checked anchor map. -/
def generatedContinuationTargetsRelated
    (parameters : Requirements.Parameters) : Nat -> Nat -> Prop :=
  CheckedMixedCallbackTargetsRelated Requirements.generatedOriginalContext
    (Requirements.generatedCandidateProgram parameters)
    (Requirements.generatedRelationCore parameters).anchors

/-- Callback return words must resolve through the same checked static code
anchors.  Equality or a submitted callback relation is not substituted. -/
def generatedCallbackReturnAddressesRelated
    (parameters : Requirements.Parameters) : Word -> Word -> Prop :=
  CheckedMixedAnchorValuesRelated Requirements.generatedOriginalContext
    (Requirements.generatedCandidateProgram parameters)
    (Requirements.generatedRelationCore parameters).anchors

/-- Exact recursive ordinary-frame relation for the concrete GNU authorities.
Every continuation is checked against the canonical anchor map and every
native return word is tied to the candidate image base and continuation RVA. -/
def generatedExternalFrames
    (parameters : Requirements.Parameters) : MixedExternalFrameContract :=
  exactMixedExternalFrameContract
    (Requirements.generatedCandidateProgram parameters).pe.imageBase
    (generatedContinuationTargetsRelated parameters)

/-- Callback-capable extension.  The current acceptance record retains only
its callback-free parent; nested external composition must consume this full
term rather than erasing the candidate external-frame stack. -/
def generatedNestedExternalFrames
    (parameters : Requirements.Parameters) :
    MixedNestedExternalFrameContract :=
  exactMixedNestedExternalFrameContract
    (Requirements.generatedCandidateProgram parameters).pe.imageBase
    (generatedContinuationTargetsRelated parameters)
    (generatedCallbackReturnAddressesRelated parameters)

@[simp] theorem generatedExternalFramesCallbacksEmpty
    (parameters : Requirements.Parameters)
    (originalCalls : List Nat)
    (callbacks : List WorldExternalCallbackRuntime)
    (candidateCalls : List NativeCallFrame)
    (related : (generatedExternalFrames parameters).callFramesRelated
      originalCalls callbacks candidateCalls) :
    callbacks = [] :=
  related.1

set_option maxRecDepth 1000000

/-- Deterministic paired import addresses.  The address is an abstract loader
choice outside either image; exact import identity and IAT membership remain
kernel-checked below. -/
def generatedLaunchImportAddressesFrom (nextId : Nat) :
    List PEImport -> List ImportAddressPair
  | [] => []
  | imported :: rest =>
      {{
        id := nextId
        imported := normalizeImport imported
        originalIatRva := imported.iatRva
        candidateIatRva := imported.iatRva
        originalAddress := BitVec.ofNat 32 (0x70000000 + nextId * 0x10)
        candidateAddress := BitVec.ofNat 32 (0x70000000 + nextId * 0x10)
      }} :: generatedLaunchImportAddressesFrom (nextId + 1) rest

def generatedLaunchImportAddresses :
    List ImportAddressPair :=
  generatedLaunchImportAddressesFrom 0
    Requirements.generatedOriginalContext.imports

def generatedLaunchRange (id base size : Nat) : DynamicAddressRangePair := {{
  id
  originalBase := BitVec.ofNat 32 base
  candidateBase := BitVec.ofNat 32 base
  size
  wordRelations := []
}}

def generatedStackRange := generatedLaunchRange 0 0xc0000000 0x100
def generatedTebRange := generatedLaunchRange 1 0xc0010000 0x38
def generatedPebRange := generatedLaunchRange 2 0xc0020000 0x14
def generatedProcessParametersRange :=
  generatedLaunchRange 3 0xc0030000 0x4c
def generatedArgvRange := generatedLaunchRange 4 0xc0040000 0x04
def generatedEnvironmentRange := generatedLaunchRange 5 0xc0050000 0x04
def generatedTlsArrayRange := generatedLaunchRange 6 0xc0060000 0x04

def generatedLaunchWorld : RelationalWorld := {{
  dynamicRanges := [generatedTebRange, generatedPebRange,
    generatedProcessParametersRange, generatedArgvRange,
    generatedEnvironmentRange, generatedTlsArrayRange]
  stackRanges := [generatedStackRange]
  opaqueResources := []
  importAddresses := generatedLaunchImportAddresses
  registeredCallbacks := []
  tlsState := {{}}
}}

def generatedLaunchRangeWrites : List MixedLaunchRangeWrite := [
  {{ rangeBase := generatedTebRange.originalBase
     rangeSize := generatedTebRange.size
     offset := 0x18
     value := generatedTebRange.originalBase }},
  {{ rangeBase := generatedTebRange.originalBase
     rangeSize := generatedTebRange.size
     offset := 0x2c
     value := generatedTlsArrayRange.originalBase }},
  {{ rangeBase := generatedTebRange.originalBase
     rangeSize := generatedTebRange.size
     offset := 0x30
     value := generatedPebRange.originalBase }},
  {{ rangeBase := generatedTebRange.originalBase
     rangeSize := generatedTebRange.size
     offset := 0x34
     value := BitVec.ofNat 32 0 }},
  {{ rangeBase := generatedPebRange.originalBase
     rangeSize := generatedPebRange.size
     offset := 0x10
     value := generatedProcessParametersRange.originalBase }},
  {{ rangeBase := generatedProcessParametersRange.originalBase
     rangeSize := generatedProcessParametersRange.size
     offset := 0x44
     value := generatedArgvRange.originalBase }},
  {{ rangeBase := generatedProcessParametersRange.originalBase
     rangeSize := generatedProcessParametersRange.size
     offset := 0x48
     value := generatedEnvironmentRange.originalBase }}
]

def generatedOriginalLaunchMemory (parameters : Requirements.Parameters) :
    Memory :=
  applyMixedLaunchRangeWrites
    (mixedLoaderPopulatedPreferredBaseMemory false
      Requirements.generatedOriginalContext
      (Requirements.generatedCandidateProgram parameters)
      generatedLaunchWorld)
    generatedLaunchRangeWrites

def generatedCandidateLaunchMemory (parameters : Requirements.Parameters) :
    Memory :=
  applyMixedLaunchRangeWrites
    (mixedLoaderPopulatedPreferredBaseMemory true
      Requirements.generatedOriginalContext
      (Requirements.generatedCandidateProgram parameters)
      generatedLaunchWorld)
    generatedLaunchRangeWrites

def generatedLaunchRegisters : Registers Word := {{
  eax := BitVec.ofNat 32 0
  ebx := BitVec.ofNat 32 0
  ecx := BitVec.ofNat 32 0
  edx := BitVec.ofNat 32 0
  esi := BitVec.ofNat 32 0
  edi := BitVec.ofNat 32 0
  ebp := BitVec.ofNat 32 0
  esp := generatedStackRange.originalBase + BitVec.ofNat 32 0x80
}}

def generatedOriginalLaunchState
    (parameters : Requirements.Parameters) : MachineState := {{
  registers := generatedLaunchRegisters
  memory := generatedOriginalLaunchMemory parameters
  fsBase := generatedTebRange.originalBase
}}

def generatedCandidateLaunchState
    (parameters : Requirements.Parameters) : MachineState := {{
  registers := generatedLaunchRegisters
  memory := generatedCandidateLaunchMemory parameters
  fsBase := generatedTebRange.candidateBase
}}

theorem generatedCandidateImportsMatch
    (parameters : Requirements.Parameters) :
    (Requirements.generatedCandidateProgram parameters).imports =
      Requirements.generatedOriginalContext.imports := by
  decide +kernel

theorem generatedLaunchWorldValid
    (parameters : Requirements.Parameters) :
    CanonicalMixedRelationalWorldValid Requirements.generatedOriginalContext
      (Requirements.generatedCandidateProgram parameters)
      (Requirements.generatedRelationCore parameters).anchors
      generatedLaunchWorld = true := by
  decide +kernel

theorem generatedLaunchWorldShape
    (parameters : Requirements.Parameters) :
    CanonicalMixedLaunchWorldShape Requirements.generatedOriginalContext
      (Requirements.generatedCandidateProgram parameters)
      (Requirements.generatedRelationCore parameters).launchMemoryProfile
      generatedLaunchWorld = true := by
  decide +kernel

theorem generatedLaunchBindingsValid
    (parameters : Requirements.Parameters) :
    generatedLaunchWorld.importAddresses.all
      (mixedImportAddressValid Requirements.generatedOriginalContext
        (Requirements.generatedCandidateProgram parameters)) = true := by
  decide +kernel

theorem generatedOriginalImportsBounded :
    Requirements.generatedOriginalContext.imports.all (fun imported =>
      imported.iatRva + 4 <=
        Requirements.generatedOriginalContext.pe.sizeOfImage) = true := by
  decide +kernel

theorem generatedCandidateImportsBounded
    (parameters : Requirements.Parameters) :
    (Requirements.generatedCandidateProgram parameters).imports.all
      (fun imported =>
        imported.iatRva + 4 <=
          (Requirements.generatedCandidateProgram parameters).pe.sizeOfImage) =
      true := by
  decide +kernel

theorem generatedOriginalImageBounded :
    Requirements.generatedOriginalContext.pe.imageBase +
        Requirements.generatedOriginalContext.pe.sizeOfImage <= 2 ^ 32 := by
  decide +kernel

theorem generatedCandidateImageBounded
    (parameters : Requirements.Parameters) :
    (Requirements.generatedCandidateProgram parameters).pe.imageBase +
        (Requirements.generatedCandidateProgram parameters).pe.sizeOfImage <=
      2 ^ 32 := by
  decide +kernel

theorem generatedOriginalRangeWritesPreserveImage :
    mixedLaunchRangeWritesPreserveImageChecked
      Requirements.generatedOriginalContext.pe generatedLaunchRangeWrites =
        true := by
  decide +kernel

theorem generatedCandidateRangeWritesPreserveImage
    (parameters : Requirements.Parameters) :
    mixedLaunchRangeWritesPreserveImageChecked
      (Requirements.generatedCandidateProgram parameters).pe
      generatedLaunchRangeWrites = true := by
  decide +kernel

theorem generatedRangeMemoryChecked
    (parameters : Requirements.Parameters) :
    canonicalMixedExactRangeMemoryChecked generatedLaunchWorld
      (generatedOriginalLaunchMemory parameters)
      (generatedCandidateLaunchMemory parameters) = true := by
  decide +kernel

theorem generatedImportMemoryChecked
    (parameters : Requirements.Parameters) :
    canonicalMixedImportAddressesMemoryChecked
      Requirements.generatedOriginalContext
      (Requirements.generatedCandidateProgram parameters)
      generatedLaunchWorld
      (generatedOriginalLaunchMemory parameters)
      (generatedCandidateLaunchMemory parameters) = true := by
  decide +kernel

theorem generatedOriginalImageMemory
    (parameters : Requirements.Parameters) :
    PreferredBaseImageMemory Requirements.generatedOriginalContext.pe
      Requirements.generatedOriginalContext.imports
      (generatedOriginalLaunchMemory parameters) := by
  apply PreferredBaseImageMemory.afterMixedLaunchRangeWrites
    generatedOriginalImageBounded generatedOriginalRangeWritesPreserveImage
  exact mixedLoaderPopulatedPreferredBaseMemory_maps_original
    (generatedLaunchBindingsValid parameters) generatedOriginalImportsBounded
    generatedOriginalImageBounded

theorem generatedCandidateImageMemory
    (parameters : Requirements.Parameters) :
    PreferredBaseImageMemory
      (Requirements.generatedCandidateProgram parameters).pe
      (Requirements.generatedCandidateProgram parameters).imports
      (generatedCandidateLaunchMemory parameters) := by
  apply PreferredBaseImageMemory.afterMixedLaunchRangeWrites
    (generatedCandidateImageBounded parameters)
    (generatedCandidateRangeWritesPreserveImage parameters)
  exact mixedLoaderPopulatedPreferredBaseMemory_maps_candidate
    (generatedLaunchBindingsValid parameters)
    (generatedCandidateImportsBounded parameters)
    (generatedCandidateImageBounded parameters)

def generatedConcreteLaunchPair
    (parameters : Requirements.Parameters) :
    CanonicalMixedPE32ConsoleLaunchStatePair
      Requirements.generatedOriginalContext
      (Requirements.generatedCandidateProgram parameters)
      (Requirements.generatedRelationCore parameters).anchors
      (Requirements.generatedRelationCore parameters).launchMemoryProfile
      generatedLaunchWorld generatedLaunchWorld
      (generatedOriginalLaunchState parameters)
      (generatedCandidateLaunchState parameters) := {{
  worldsRelated := ⟨rfl, generatedLaunchWorldValid parameters⟩
  worldShape := generatedLaunchWorldShape parameters
  rangeMemory := canonicalMixedRangeMemoryRelated_of_exact_checked
    (generatedRangeMemoryChecked parameters)
  importsMemory := canonicalMixedImportAddressesMemoryHold_of_checked
    (generatedImportMemoryChecked parameters)
  originalImageMemory := generatedOriginalImageMemory parameters
  candidateImageMemory := generatedCandidateImageMemory parameters
  registersRelated := by
    intro register _member
    apply Or.inl
    exact wordRelated_self _ _ _ _ _
  registersExact := rfl
  flagsExact := rfl
  undefinedExact := rfl
  x87Exact := ⟨rfl, rfl, rfl⟩
  fsBaseExact := rfl
  stackRange := generatedStackRange
  stackRangeExact := by decide +kernel
  stackPointerOffset := 0x80
  stackPointerInside := by decide +kernel
  originalStackPointer := rfl
  candidateStackPointer := rfl
  tebRange := generatedTebRange
  tebRangeExact := by decide +kernel
  tebHeaderInside := by decide +kernel
  originalFsBase := rfl
  candidateFsBase := rfl
  originalTebSelf := by decide +kernel
  candidateTebSelf := by decide +kernel
  pebRange := generatedPebRange
  pebRangeExact := by decide +kernel
  pebHeaderInside := by decide +kernel
  processParametersRange := generatedProcessParametersRange
  processParametersRangeExact := by decide +kernel
  processParametersHeaderInside := by decide +kernel
  argvRange := generatedArgvRange
  argvRangeExact := by decide +kernel
  environmentRange := generatedEnvironmentRange
  environmentRangeExact := by decide +kernel
  tlsArrayRange := generatedTlsArrayRange
  tlsArrayRangeExact := by decide +kernel
  originalTebTlsArray := by decide +kernel
  candidateTebTlsArray := by decide +kernel
  originalTebPeb := by decide +kernel
  candidateTebPeb := by decide +kernel
  originalLastError := by decide +kernel
  candidateLastError := by decide +kernel
  originalProcessParameters := by decide +kernel
  candidateProcessParameters := by decide +kernel
  originalArgv := by decide +kernel
  candidateArgv := by decide +kernel
  originalEnvironment := by decide +kernel
  candidateEnvironment := by decide +kernel
  tlsSlotsMemory := by
    intro slot member
    simp [generatedLaunchWorld] at member
}}

def generatedLaunchRelated
    (parameters : Requirements.Parameters) :
    MixedLaunchStatesRelated Requirements.generatedOriginalContext
      (Requirements.generatedCandidateProgram parameters)
      (Requirements.generatedRelationCore parameters).contract
      generatedLaunchWorld generatedLaunchWorld
      (generatedOriginalLaunchState parameters)
      (generatedCandidateLaunchState parameters) :=
  ⟨generatedOriginalImageMemory parameters,
    generatedCandidateImageMemory parameters,
    (generatedConcreteLaunchPair parameters).worldsRelated,
    ⟨generatedConcreteLaunchPair parameters⟩⟩

def generatedLaunchRealizable
    (parameters : Requirements.Parameters) :
    MixedLaunchRealizable Requirements.generatedOriginalContext
      (Requirements.generatedCandidateProgram parameters)
      (Requirements.generatedRelationCore parameters).contract :=
  mixedLaunchRealizable_of_related (generatedLaunchRelated parameters)

#print axioms generatedContinuationTargetsRelated
#print axioms generatedCallbackReturnAddressesRelated
#print axioms generatedExternalFrames
#print axioms generatedNestedExternalFrames
#print axioms generatedExternalFramesCallbacksEmpty
#print axioms generatedLaunchWorldValid
#print axioms generatedLaunchWorldShape
#print axioms generatedOriginalImageMemory
#print axioms generatedCandidateImageMemory
#print axioms generatedConcreteLaunchPair
#print axioms generatedLaunchRelated
#print axioms generatedLaunchRealizable

end {spec.namespace}
"""


def write_gnu_hello_runtime_foundation(
    out: Path | str,
    spec: GnuHelloRuntimeFoundationSpec | None = None,
) -> GnuHelloRuntimeFoundationPlan:
    plan = build_gnu_hello_runtime_foundation_plan(spec)
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    (stage_a / f"{plan.spec.module_name}.lean").write_text(
        gnu_hello_runtime_foundation_source(plan), encoding="utf-8"
    )
    write_json(
        root / GNU_HELLO_RUNTIME_FOUNDATION_MANIFEST,
        plan.payload(),
    )
    return plan
