"""Generate the exact original/source static launch-context boundary.

The generic Lean kernel owns the proof types.  This producer only binds those
types to declarations emitted by the exact transition, combined-inventory,
and compiled-source authority phases.  It deliberately emits no legacy
preservation context until every typed premise has a checked declaration.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from spaghetti_extractor.errors import StageAInputError


ORIGINAL_SOURCE_LAUNCH_CONTEXT_FORMAT = (
    "stage-a-original-source-launch-context-v1"
)
ORIGINAL_SOURCE_LAUNCH_CONTEXT_MODULE = (
    "GeneratedOriginalSourceLaunchContextBindings"
)
ORIGINAL_SOURCE_LAUNCH_CONTEXT_NAMESPACE = (
    "StageA.GeneratedRelational.OriginalSourceLaunchContext"
)

_COMBINED_FORMAT = (
    "stage-a-original-combined-execution-inventory-declarations-v1"
)
_TRANSITION_FORMAT = "stage-a-gnu-hello-source-transition-index-v1"
_COMPILED_FORMAT = (
    "stage-a-gnu-hello-native-source-compiled-authority-declarations-v1"
)
_RUNTIME_FORMAT = "stage-a-gnu-hello-runtime-foundation-v1"
_TARGET_STEP_FORMAT = "stage-a-original-execution-proof-v1"
CHECKED_PROTOCOL_RESPONSES_DECLARATIONS_FORMAT = (
    "stage-a-original-combined-machine-protocol-responses-declarations-v1"
)
_COMBINED_MODULE = "StageA.GeneratedRelationalOriginalCombinedInventory"
_COMBINED_NAMESPACE = "StageA.GeneratedRelational.OriginalCombinedInventory"
_TRANSITION_DATA_MODULE = "GeneratedGnuHelloSourceTransitionIndexData"
_TRANSITION_MODULE = "GeneratedGnuHelloSourceTransitionIndex"
_TRANSITION_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloSourceTransitionIndex"
)
_COMPILED_MODULE = "GeneratedGnuHelloNativeSourceCompiledAuthority"
_COMPILED_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloNativeSourceCompiledAuthority"
)
_RUNTIME_MODULE = "StageA.GeneratedGnuHelloRuntimeFoundation"
_RUNTIME_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloRuntimeFoundation"
)
_MIXED_ORIGINAL_BASE_MODULE = (
    "StageA.GeneratedRelationalInterpreterMixedOriginalBase"
)
_MIXED_ORIGINAL_BASE_NAMESPACE = (
    "StageA.GeneratedRelational.InterpreterMixedOriginalBase"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_NAME = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class OriginalSourceLaunchContextError(StageAInputError):
    """The exact launch-context inputs are incomplete or inconsistent."""


@dataclass(frozen=True)
class GeneratedOriginalSourceLaunchContext:
    module: Path
    manifest: Path
    ready: bool
    blockers: tuple[str, ...]


@dataclass(frozen=True)
class _Bindings:
    combined_module: str
    inventory: str
    original_context: str
    transition_namespace: str
    exact_binding: str
    active_targets: str
    target_ids_exact: str
    compiled_module: str
    compiled_namespace: str
    runtime_module: str
    runtime_namespace: str
    static_requirements: tuple[str, ...]
    target_step_module: str
    target_step_index: str
    protocol_module: str
    protocol_responses: str

    @property
    def source_program(self) -> str:
        return f"{self.transition_namespace}.generatedExactSourceProgram"

    @property
    def project(self) -> str:
        return f"{self.compiled_namespace}.generatedNativeSourceProject"


def generate_original_source_launch_context(
    out: Path | str,
    *,
    combined_inventory_manifest: Path | str,
    transition_index_manifest: Path | str,
    compiled_authority_declarations: Path | str,
    runtime_foundation_manifest: Path | str,
    target_step_manifest: Path | str,
    protocol_responses_declarations: Path | str,
    preservation_inputs: Mapping[str, Path | str] | None = None,
) -> GeneratedOriginalSourceLaunchContext:
    """Bind exact launch declarations and emit truthful remaining premises.

    ``preservation_inputs`` carries the other production preservation inputs
    solely so the resulting context identity covers the same evidence closure.
    Their contents never supply declaration names or proof statuses.
    """

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    primary = {
        "combined_inventory_manifest": Path(combined_inventory_manifest),
        "transition_index_manifest": Path(transition_index_manifest),
        "compiled_authority_declarations": Path(
            compiled_authority_declarations
        ),
        "runtime_foundation_manifest": Path(runtime_foundation_manifest),
        "target_step_manifest": Path(target_step_manifest),
        "protocol_responses_declarations": Path(
            protocol_responses_declarations
        ),
    }
    extras = {
        _input_name(name): Path(path)
        for name, path in sorted((preservation_inputs or {}).items())
    }
    if set(primary) & set(extras):
        raise OriginalSourceLaunchContextError(
            "preservation input names collide with canonical inputs"
        )
    paths = {**primary, **extras}
    documents = {
        name: _read_object(path, name) for name, path in primary.items()
    }
    hashes = {name: _sha256(path) for name, path in paths.items()}
    bindings = _bindings(
        documents["combined_inventory_manifest"],
        documents["transition_index_manifest"],
        documents["compiled_authority_declarations"],
        documents["runtime_foundation_manifest"],
        documents["target_step_manifest"],
        documents["protocol_responses_declarations"],
        hashes,
    )

    module_path = stage_a / f"{ORIGINAL_SOURCE_LAUNCH_CONTEXT_MODULE}.lean"
    module_path.write_text(_lean_source(bindings, hashes), encoding="ascii")
    module_digest = _sha256(module_path)

    blockers: list[dict[str, object]] = []
    manifest_path = root / "original-source-launch-context.json"
    _write_json(
        manifest_path,
        {
            "format": ORIGINAL_SOURCE_LAUNCH_CONTEXT_FORMAT,
            "ready": True,
            "proof_authority": False,
            "acceptance_authority": False,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": dict(sorted(hashes.items())),
            "lean": {
                "module": f"StageA.{ORIGINAL_SOURCE_LAUNCH_CONTEXT_MODULE}",
                "namespace": ORIGINAL_SOURCE_LAUNCH_CONTEXT_NAMESPACE,
                "source_sha256": module_digest,
                "declarations": _declarations(),
            },
            "closed_context": (
                f"{ORIGINAL_SOURCE_LAUNCH_CONTEXT_NAMESPACE}."
                "generatedClosedContext"
            ),
            "blockers": blockers,
        },
    )
    return GeneratedOriginalSourceLaunchContext(
        module=module_path,
        manifest=manifest_path,
        ready=True,
        blockers=(),
    )


def _bindings(
    combined: dict[str, Any],
    transition: dict[str, Any],
    compiled: dict[str, Any],
    runtime: dict[str, Any],
    target_step: dict[str, Any],
    protocol: dict[str, Any],
    hashes: Mapping[str, str],
) -> _Bindings:
    _require_format(combined, _COMBINED_FORMAT, "combined inventory")
    _require_format(transition, _TRANSITION_FORMAT, "transition index")
    _require_format(compiled, _COMPILED_FORMAT, "compiled authority")
    _require_format(runtime, _RUNTIME_FORMAT, "runtime foundation")
    _require_format(target_step, _TARGET_STEP_FORMAT, "target-step proof")
    _require_format(
        protocol,
        CHECKED_PROTOCOL_RESPONSES_DECLARATIONS_FORMAT,
        "checked protocol responses",
    )

    combined_lean = _object(combined.get("lean"), "combined inventory lean")
    combined_module = _stage_a_name(
        combined_lean.get("module"), "combined inventory lean.module"
    )
    if combined_module != _COMBINED_MODULE:
        raise OriginalSourceLaunchContextError(
            "combined inventory does not name the canonical generated module"
        )
    combined_namespace = _lean_name(
        combined_lean.get("namespace"), "combined inventory lean.namespace"
    )
    if combined_namespace != _COMBINED_NAMESPACE:
        raise OriginalSourceLaunchContextError(
            "combined inventory does not name the canonical generated namespace"
        )
    inventory = _lean_name(
        combined_lean.get("inventory"), "combined inventory lean.inventory"
    )
    original_context = _lean_name(
        combined_lean.get("original_context"),
        "combined inventory lean.original_context",
    )
    static_rows = combined.get("static_word_slots")
    if not isinstance(static_rows, list):
        raise OriginalSourceLaunchContextError(
            "combined inventory static_word_slots must be a list"
        )
    static_requirements: list[str] = []
    for index, row_value in enumerate(static_rows):
        row = _object(row_value, f"combined static_word_slots[{index}]")
        declaration = _lean_name(
            row.get("declaration"),
            f"combined static_word_slots[{index}].declaration",
        )
        expected_declaration = (
            f"{combined_namespace}.generatedStaticWordRequirement{index:04d}"
        )
        if declaration != expected_declaration:
            raise OriginalSourceLaunchContextError(
                "combined static-word declarations are not canonical and ordered"
            )
        static_requirements.append(declaration)
    for name, value in (
        ("inventory", inventory),
        ("original_context", original_context),
    ):
        if not value.startswith(combined_namespace + "."):
            raise OriginalSourceLaunchContextError(
                f"combined inventory {name} is outside its canonical namespace"
            )

    modules = _string_list(transition.get("modules"), "transition modules")
    for required in (_TRANSITION_DATA_MODULE, _TRANSITION_MODULE):
        if required not in modules:
            raise OriginalSourceLaunchContextError(
                f"transition index omits required module {required}"
            )
    exports = _object(transition.get("exports"), "transition exports")
    expected_export_names = {
        "concrete_exact_binding",
        "active_target_transition_index",
        "active_target_ids_exact",
    }
    if set(exports) != expected_export_names:
        raise OriginalSourceLaunchContextError(
            "transition exports must contain the exact checked binding, index, "
            "and target-id equality"
        )
    exact_binding = _lean_name(
        exports["concrete_exact_binding"], "transition exact binding"
    )
    active_targets = _lean_name(
        exports["active_target_transition_index"], "transition active targets"
    )
    target_ids_exact = _lean_name(
        exports["active_target_ids_exact"], "transition target ids exact"
    )
    transition_namespace = _namespace_of(exact_binding)
    if transition_namespace != _TRANSITION_NAMESPACE:
        raise OriginalSourceLaunchContextError(
            "transition exports do not use the canonical generated namespace"
        )
    expected = {
        "concrete_exact_binding": "generatedConcreteExactBinding",
        "active_target_transition_index": "generatedActiveTargetTransitionIndex",
        "active_target_ids_exact": "generatedActiveTargetIdsExact",
    }
    for key, suffix in expected.items():
        if exports[key] != f"{transition_namespace}.{suffix}":
            raise OriginalSourceLaunchContextError(
                f"transition export {key} is not the canonical checked declaration"
            )

    compiled_lean = _object(compiled.get("lean"), "compiled authority lean")
    compiled_module_local = _local_name(
        compiled_lean.get("output_module"), "compiled authority output_module"
    )
    compiled_namespace = _lean_name(
        compiled_lean.get("namespace"), "compiled authority namespace"
    )
    if compiled_module_local != _COMPILED_MODULE:
        raise OriginalSourceLaunchContextError(
            "compiled authority does not name the canonical generated module"
        )
    if compiled_namespace != _COMPILED_NAMESPACE:
        raise OriginalSourceLaunchContextError(
            "compiled authority does not name the canonical generated namespace"
        )

    runtime_outputs = _object(runtime.get("outputs"), "runtime outputs")
    if runtime_outputs.get("lean_module") != (
        f"StageA/{_RUNTIME_MODULE.rsplit('.', 1)[-1]}.lean"
    ):
        raise OriginalSourceLaunchContextError(
            "runtime foundation does not name the canonical generated module"
        )

    target_exports = _object(target_step.get("exports"), "target-step exports")
    target_step_ref = _lean_ref(
        target_exports.get("target_step_index"), "target-step index"
    )
    _validate_bound_input_hashes(
        target_step, hashes, "target-step proof", required=False
    )

    protocol_lean = _object(protocol.get("lean"), "checked protocol lean")
    protocol_module = _stage_a_name(
        protocol_lean.get("module"), "checked protocol lean.module"
    )
    protocol_responses = _lean_name(
        protocol_lean.get("responses"), "checked protocol lean.responses"
    )
    _validate_bound_input_hashes(
        protocol, hashes, "checked protocol responses", required=True
    )
    return _Bindings(
        combined_module=combined_module,
        inventory=inventory,
        original_context=original_context,
        transition_namespace=transition_namespace,
        exact_binding=exact_binding,
        active_targets=active_targets,
        target_ids_exact=target_ids_exact,
        compiled_module=f"StageA.{compiled_module_local}",
        compiled_namespace=compiled_namespace,
        runtime_module=_RUNTIME_MODULE,
        runtime_namespace=_RUNTIME_NAMESPACE,
        static_requirements=tuple(static_requirements),
        target_step_module=target_step_ref[0],
        target_step_index=target_step_ref[1],
        protocol_module=protocol_module,
        protocol_responses=protocol_responses,
    )


def _lean_source(bindings: _Bindings, hashes: Mapping[str, str]) -> str:
    hash_defs = "\n".join(
        f'def generatedInputSha256_{name} : String := "{digest}"'
        for name, digest in sorted(hashes.items())
    )
    static_inventory = (
        f"{_COMBINED_NAMESPACE}.generatedStaticWordInventory"
    )
    static_unfolds = ", ".join(
        (bindings.inventory, static_inventory, *bindings.static_requirements)
    )
    if bindings.static_requirements:
        static_cases = " | ".join("rfl" for _ in bindings.static_requirements)
        static_valid_proof = f"""  intro requirement member
  simp [generatedInventory, {static_unfolds}] at member
  rcases member with {static_cases}
  all_goals decide +kernel"""
    else:
        static_valid_proof = f"""  intro requirement member
  simp [generatedInventory, {static_unfolds}] at member"""
    return f"""import {bindings.combined_module}
import StageA.{_TRANSITION_DATA_MODULE}
import StageA.{_TRANSITION_MODULE}
import {bindings.compiled_module}
import {bindings.runtime_module}
import {_MIXED_ORIGINAL_BASE_MODULE}
import {bindings.target_step_module}
import {bindings.protocol_module}
import StageA.RelationalOriginalSourceLaunchConstruction

namespace {ORIGINAL_SOURCE_LAUNCH_CONTEXT_NAMESPACE}

open StageA.Relational
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCombinedAwaitingExternalPreservation
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalSourceLaunchConstruction
open StageA.Relational.OriginalSourceLaunchContext
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

namespace Runtime := {bindings.runtime_namespace}
namespace OriginalBase := {_MIXED_ORIGINAL_BASE_NAMESPACE}

noncomputable section

{hash_defs}

abbrev generatedSourceProgram : Program :=
  {bindings.source_program}

abbrev generatedProject : NativeSourceProject :=
  {bindings.project}

abbrev generatedOriginalContext : OriginalDecodedStaticContext :=
  {bindings.original_context}

abbrev generatedInventory : OriginalCombinedExecutionInventory
    generatedProject.program.worldProgram generatedOriginalContext :=
  {bindings.inventory}

theorem generatedProjectProgramExact :
    generatedProject.program = generatedSourceProgram := by
  rfl

theorem generatedProjectStaticContextExact :
    generatedProject.program.worldProgram.context =
      OriginalBase.generatedOriginalCarrierContext := by
  rfl

theorem generatedProjectStaticContextStructurallyValid :
    generatedProject.program.worldProgram.context.StructurallyValid := by
  rw [generatedProjectStaticContextExact]
  exact OriginalBase.generatedOriginalCarrierContextStructurallyValid

abbrev generatedExactBinding : ExactBinding
    generatedProject.program.worldProgram.context.originalPe
    generatedProject.program :=
  {bindings.exact_binding}

abbrev generatedActiveTargets : ActiveTargetTransitionIndex
    generatedExactBinding :=
  {bindings.active_targets}

theorem generatedActiveTargetIdsExact :
    generatedActiveTargets.certificates.map
        (fun certificate => certificate.targetId) =
      generatedInventory.reachableTargets.targetIds := by
  simpa only [generatedActiveTargets, generatedInventory] using
    {bindings.target_ids_exact}

def generatedInstructionSemanticsChecked : Bool :=
  generatedProject.program.worldProgram.instructionSemanticsAdequateChecked

theorem generatedInstructionSemanticsAdequateOfChecked
    (checked : generatedInstructionSemanticsChecked = true) :
    generatedProject.program.worldProgram.InstructionSemanticsAdequate :=
  DecodedWorldProgram.instructionSemanticsAdequate_of_checked _ checked

theorem generatedInstructionSemanticsCheckedProof :
    generatedInstructionSemanticsChecked = true := by
  decide +kernel

def generatedInstructionSemanticsAdequate :
    generatedProject.program.worldProgram.InstructionSemanticsAdequate :=
  generatedInstructionSemanticsAdequateOfChecked
    generatedInstructionSemanticsCheckedProof

theorem generatedStaticWordRequirementsValid : forall requirement,
    List.Mem requirement generatedInventory.staticWords.requirements ->
      requirement.Valid generatedProject.program.worldProgram.context := by
{static_valid_proof}

def generatedCombinedLaunchSeedChecked : Bool :=
  combinedLaunchSeedChecked generatedProject generatedOriginalContext
    generatedInventory

theorem generatedCombinedLaunchSeedCheckedProof :
    generatedCombinedLaunchSeedChecked = true := by
  decide +kernel

abbrev generatedLaunchSeedRequirement : Prop :=
  OriginalCombinedPE32ConsoleLaunchSeed generatedProject
    generatedOriginalContext generatedInventory

def generatedLaunchSeed : generatedLaunchSeedRequirement :=
  combinedLaunchSeedChecked_sound generatedProject generatedOriginalContext
    generatedInventory generatedProjectStaticContextStructurallyValid
    generatedStaticWordRequirementsValid generatedCombinedLaunchSeedCheckedProof

theorem generatedLaunchInventoryHoldsOfSeed
    (seed : generatedLaunchSeedRequirement)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch generatedProject sourceRoot) :
    generatedInventory.Holds sourceRoot.toWorldExecution :=
  OriginalCombinedPE32ConsoleLaunchSeed.holds seed sourceRoot launch

def generatedSourceLaunchWorld : RelationalWorld := {{
  Runtime.generatedLaunchWorld with dynamicRanges := []
}}

def generatedSourceLaunchMemory : Memory :=
  loaderPopulatedPreferredBaseMemory false
    generatedProject.program.worldProgram.context generatedSourceLaunchWorld

def generatedSourceLaunchState : MachineState := {{
  registers := Runtime.generatedLaunchRegisters
  memory := generatedSourceLaunchMemory
}}

def generatedSourceLaunchTargetId : Nat :=
  OriginalBase.generatedOriginalLaunch.entryTargetId

def generatedSourceLaunchRoot : SourceExecution :=
  .running generatedSourceLaunchTargetId generatedSourceLaunchState [] 0
    generatedSourceLaunchWorld

theorem generatedSourceLaunchWorldValid :
    PE32ConsoleLaunchWorldV1.Valid
      generatedProject.program.worldProgram.context generatedSourceLaunchWorld := by
  decide +kernel

theorem generatedSourceLaunchImageMemory :
    PreferredBaseImageMemory
      generatedProject.program.worldProgram.context.originalPe
      generatedProject.program.worldProgram.context.originalImports
      generatedSourceLaunchMemory := by
  exact loaderPopulatedPreferredBaseMemory_maps_image false
    generatedProject.program.worldProgram.context generatedSourceLaunchWorld
    (by decide +kernel) (by decide +kernel) (by decide +kernel)

theorem generatedSourceLaunchImportMemory : forall binding,
    List.Mem binding generatedSourceLaunchWorld.importAddresses ->
      Memory.read32 generatedSourceLaunchMemory
          (BitVec.ofNat 32
            (generatedProject.program.worldProgram.context.originalPe.imageBase +
              binding.originalIatRva)) = binding.originalAddress := by
  have checked : ImportAddressesMemoryHold
      generatedProject.program.worldProgram.context generatedSourceLaunchWorld
      generatedSourceLaunchMemory generatedSourceLaunchMemory :=
    importAddressesMemoryHold_of_checked _ _ _ _ (by decide +kernel)
  intro binding member
  exact (checked binding member).1

def generatedCheckedSourceLaunch :
    CheckedNativeSourcePE32ConsoleLaunch generatedProject
      generatedSourceLaunchRoot where
  launch := by
    refine Exists.intro generatedSourceLaunchTargetId ?_
    refine Exists.intro generatedSourceLaunchState ?_
    refine Exists.intro generatedSourceLaunchWorld ?_
    exact And.intro rfl
      (And.intro generatedExactBinding.originalSide
        (And.intro (by decide +kernel)
          (And.intro generatedSourceLaunchWorldValid
            (And.intro generatedSourceLaunchImageMemory
              generatedSourceLaunchImportMemory))))

theorem generatedLaunchRealizable : exists sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch generatedProject sourceRoot :=
  Exists.intro generatedSourceLaunchRoot generatedCheckedSourceLaunch

def generatedStaticLaunchContext :
    CheckedOriginalSourceStaticLaunchContext generatedProject
      generatedOriginalContext generatedInventory where
  exactBinding := generatedExactBinding
  instructionSemanticsAdequate := generatedInstructionSemanticsAdequate
  activeTargets := generatedActiveTargets
  activeTargetIdsExact := generatedActiveTargetIdsExact
  launchSeed := generatedLaunchSeed
  launchRealizable := generatedLaunchRealizable

abbrev generatedProtocolResponsesRequirement : Type :=
  CheckedOriginalCombinedMachineProtocolResponses
    generatedProject.program.worldProgram generatedOriginalContext
    generatedInventory

abbrev generatedProtocolResponses : generatedProtocolResponsesRequirement :=
  {bindings.protocol_responses}

def generatedExternalHook :
    OriginalSourceAwaitingExternalHook generatedOriginalContext
      generatedInventory where
  preservation := generatedProtocolResponses.toAwaitingExternalPreservation

abbrev generatedTargetStepIndex : OriginalCombinedTargetStepIndex
    generatedExactBinding generatedOriginalContext generatedInventory :=
  {bindings.target_step_index}

theorem generatedTargetStepIndexExact :
    generatedTargetStepIndex.transitions = generatedActiveTargets := by
  rfl

def generatedClosedContext : CheckedOriginalSourceLaunchContext
    generatedProject generatedOriginalContext generatedInventory where
  static := generatedStaticLaunchContext
  targetStepIndex := generatedTargetStepIndex
  targetStepIndexExact := generatedTargetStepIndexExact
  external := generatedExternalHook

theorem generatedProgramRecordKernelCompatibility
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch generatedProject sourceRoot) :
    ProgramRecordKernelMatchesDecodedSemantics generatedProject.program
      (generatedClosedContext.launchFamilyEvidence.domainAtLaunch sourceRoot
        launch) :=
  generatedClosedContext.programRecordKernelCompatibility sourceRoot launch

end
end {ORIGINAL_SOURCE_LAUNCH_CONTEXT_NAMESPACE}
"""


def _declarations() -> dict[str, dict[str, str]]:
    module = f"StageA.{ORIGINAL_SOURCE_LAUNCH_CONTEXT_MODULE}"
    prefix = ORIGINAL_SOURCE_LAUNCH_CONTEXT_NAMESPACE
    names = (
        "generatedSourceProgram",
        "generatedProject",
        "generatedOriginalContext",
        "generatedInventory",
        "generatedProjectProgramExact",
        "generatedProjectStaticContextExact",
        "generatedProjectStaticContextStructurallyValid",
        "generatedExactBinding",
        "generatedActiveTargets",
        "generatedActiveTargetIdsExact",
        "generatedInstructionSemanticsChecked",
        "generatedInstructionSemanticsCheckedProof",
        "generatedInstructionSemanticsAdequateOfChecked",
        "generatedInstructionSemanticsAdequate",
        "generatedStaticWordRequirementsValid",
        "generatedCombinedLaunchSeedChecked",
        "generatedCombinedLaunchSeedCheckedProof",
        "generatedLaunchSeedRequirement",
        "generatedLaunchSeed",
        "generatedLaunchInventoryHoldsOfSeed",
        "generatedSourceLaunchWorld",
        "generatedSourceLaunchMemory",
        "generatedSourceLaunchState",
        "generatedSourceLaunchTargetId",
        "generatedSourceLaunchRoot",
        "generatedSourceLaunchWorldValid",
        "generatedSourceLaunchImageMemory",
        "generatedSourceLaunchImportMemory",
        "generatedCheckedSourceLaunch",
        "generatedLaunchRealizable",
        "generatedStaticLaunchContext",
        "generatedProtocolResponsesRequirement",
        "generatedProtocolResponses",
        "generatedExternalHook",
        "generatedTargetStepIndex",
        "generatedTargetStepIndexExact",
        "generatedClosedContext",
        "generatedProgramRecordKernelCompatibility",
    )
    return {
        name: {"module": module, "declaration": f"{prefix}.{name}"}
        for name in names
    }
def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise OriginalSourceLaunchContextError(
            f"cannot read {label}: {error}"
        ) from error
    return _object(value, label)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise OriginalSourceLaunchContextError(f"{label} must be an object")
    return dict(value)


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise OriginalSourceLaunchContextError(f"{label} must be a string list")
    return list(value)


def _require_format(value: Mapping[str, Any], expected: str, label: str) -> None:
    if value.get("format") != expected:
        raise OriginalSourceLaunchContextError(
            f"{label} has unsupported format {value.get('format')!r}"
        )


def _lean_name(value: object, label: str) -> str:
    if not isinstance(value, str) or _LEAN_NAME.fullmatch(value) is None:
        raise OriginalSourceLaunchContextError(
            f"{label} must be a canonical StageA Lean declaration"
        )
    return value


def _stage_a_name(value: object, label: str) -> str:
    return _lean_name(value, label)


def _lean_ref(value: object, label: str) -> tuple[str, str]:
    row = _object(value, label)
    if set(row) != {"module", "declaration"}:
        raise OriginalSourceLaunchContextError(
            f"{label} must contain exactly module and declaration"
        )
    return (
        _stage_a_name(row["module"], f"{label}.module"),
        _lean_name(row["declaration"], f"{label}.declaration"),
    )


def _validate_bound_input_hashes(
    document: Mapping[str, Any],
    hashes: Mapping[str, str],
    label: str,
    *,
    required: bool,
) -> None:
    raw_inputs = document.get("inputs")
    if raw_inputs is None:
        if required:
            raise OriginalSourceLaunchContextError(
                f"{label} must bind the exact launch-context inputs"
            )
        return
    inputs = _object(raw_inputs, f"{label}.inputs")
    canonical = (
        "combined_inventory_manifest",
        "transition_index_manifest",
        "compiled_authority_declarations",
    )
    if required and any(name not in inputs for name in canonical):
        raise OriginalSourceLaunchContextError(
            f"{label} omits a canonical launch-context input hash"
        )
    for name, digest_value in inputs.items():
        digest = digest_value
        if isinstance(digest_value, dict):
            digest = digest_value.get("sha256")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise OriginalSourceLaunchContextError(
                f"{label} input {name} must contain a SHA-256 digest"
            )
        if name not in hashes:
            continue
        if digest != hashes[name]:
            raise OriginalSourceLaunchContextError(
                f"{label} binds a different {name}"
            )


def _local_name(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_']*", value) is None
    ):
        raise OriginalSourceLaunchContextError(
            f"{label} must be a local Lean identifier"
        )
    return value


def _namespace_of(declaration: str) -> str:
    return declaration.rsplit(".", 1)[0]


def _input_name(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9_]*", value) is None:
        raise OriginalSourceLaunchContextError(
            "preservation input names must be lower-case identifiers"
        )
    return value


def _sha256(path: Path) -> str:
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise OriginalSourceLaunchContextError(
            f"cannot hash input {path}: {error}"
        ) from error
    if _SHA256.fullmatch(digest) is None:
        raise OriginalSourceLaunchContextError("internal SHA-256 failure")
    return digest


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )


__all__ = [
    "CHECKED_PROTOCOL_RESPONSES_DECLARATIONS_FORMAT",
    "GeneratedOriginalSourceLaunchContext",
    "ORIGINAL_SOURCE_LAUNCH_CONTEXT_FORMAT",
    "ORIGINAL_SOURCE_LAUNCH_CONTEXT_MODULE",
    "ORIGINAL_SOURCE_LAUNCH_CONTEXT_NAMESPACE",
    "OriginalSourceLaunchContextError",
    "generate_original_source_launch_context",
]
