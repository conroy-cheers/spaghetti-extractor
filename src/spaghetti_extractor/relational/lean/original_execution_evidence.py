"""Generate checked original-execution evidence from exact Lean declarations.

This module is deliberately generic.  It does not inspect GNU symbols, infer a
transfer rule, or promote an analysis status to proof authority.  Callers bind
one exact source program, combined invariant inventory, target-transition
index, and finite set of target-local preservation proofs.  The generated Lean
modules then assemble those facts through the reviewed Stage A kernels.

The target providers are sharded so that changing one target invalidates only
its provider shard and the small composition descendants.  The aggregate
module proves that the concatenated provider inventory is definitionally the
exact transition inventory; an omitted, duplicated, reordered, or unrelated
certificate therefore fails during Lean elaboration.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ...errors import StageAInputError


ORIGINAL_EXECUTION_PRESERVATION_INPUTS_FORMAT = (
    "stage-a-original-execution-preservation-inputs-v1"
)
ORIGINAL_EXECUTION_PROOF_FORMAT = "stage-a-original-execution-proof-v1"

_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

TargetKind = Literal["ordinary", "x87"]


class OriginalExecutionEvidenceError(StageAInputError):
    """The submitted original-execution proof inventory is incomplete."""


@dataclass(frozen=True)
class LeanRef:
    """One exact declaration exported by one canonical Stage A module."""

    module: str
    declaration: str

    def validate(self, label: str) -> None:
        if _MODULE.fullmatch(self.module) is None:
            raise OriginalExecutionEvidenceError(
                f"{label}.module must be a canonical StageA module"
            )
        if _IDENTIFIER.fullmatch(self.declaration) is None:
            raise OriginalExecutionEvidenceError(
                f"{label}.declaration must be a canonical Lean declaration"
            )

    @classmethod
    def from_json(cls, value: object, label: str) -> "LeanRef":
        row = _object(value, label)
        _exact_keys(row, {"module", "declaration"}, label)
        result = cls(
            module=_string(row["module"], f"{label}.module"),
            declaration=_string(row["declaration"], f"{label}.declaration"),
        )
        result.validate(label)
        return result

    @classmethod
    def from_qualified(cls, module: str, declaration: str) -> "LeanRef":
        result = cls(module=module, declaration=declaration)
        result.validate("Lean declaration")
        return result

    def to_json(self) -> dict[str, str]:
        return {"module": self.module, "declaration": self.declaration}

    def to_fact_json(self) -> dict[str, str]:
        namespace, symbol = self.declaration.rsplit(".", 1)
        return {
            "module": self.module,
            "namespace": namespace,
            "symbol": symbol,
        }


@dataclass(frozen=True)
class TargetEffect:
    kind: TargetKind
    ordinary_checked: LeanRef | None = None
    x87_facts: LeanRef | None = None
    x87_components: LeanRef | None = None

    def validate(self, label: str) -> None:
        if self.kind == "ordinary":
            if self.ordinary_checked is None:
                raise OriginalExecutionEvidenceError(
                    f"{label} lacks CheckedOrdinaryTargetEffect evidence"
                )
            self.ordinary_checked.validate(f"{label}.ordinary_checked")
            if self.x87_facts is not None or self.x87_components is not None:
                raise OriginalExecutionEvidenceError(
                    f"{label} mixes ordinary and x87 effect evidence"
                )
            return
        if self.kind == "x87":
            if self.x87_facts is None or self.x87_components is None:
                raise OriginalExecutionEvidenceError(
                    f"{label} lacks complete x87 target-effect evidence"
                )
            self.x87_facts.validate(f"{label}.x87_facts")
            self.x87_components.validate(f"{label}.x87_components")
            if self.ordinary_checked is not None:
                raise OriginalExecutionEvidenceError(
                    f"{label} mixes ordinary and x87 effect evidence"
                )
            return
        raise OriginalExecutionEvidenceError(f"{label}.kind is unsupported")

    @property
    def imports(self) -> set[str]:
        refs = (
            self.ordinary_checked,
            self.x87_facts,
            self.x87_components,
        )
        return {ref.module for ref in refs if ref is not None}


@dataclass(frozen=True)
class TargetPreservation:
    target_id: int
    effect: TargetEffect
    certificate: LeanRef
    cases: LeanRef

    def validate(self, label: str) -> None:
        _natural(self.target_id, f"{label}.target_id")
        self.effect.validate(f"{label}.effect")
        self.certificate.validate(f"{label}.certificate")
        self.cases.validate(f"{label}.cases")


@dataclass(frozen=True)
class FrontierProjection:
    category: str
    source_rva: int
    source_target_id: int
    static_authority: LeanRef
    target_membership: LeanRef
    running_target_membership: LeanRef
    callback_target_membership: LeanRef

    def validate(self, label: str) -> None:
        if self.category not in {
            "writable_static_slot",
            "register_target",
            "stack_dynamic",
        }:
            raise OriginalExecutionEvidenceError(
                f"{label}.category is unsupported"
            )
        _natural(self.source_rva, f"{label}.source_rva", word=True)
        _natural(self.source_target_id, f"{label}.source_target_id")
        for name in (
            "static_authority",
            "target_membership",
            "running_target_membership",
            "callback_target_membership",
        ):
            getattr(self, name).validate(f"{label}.{name}")


@dataclass(frozen=True)
class OriginalExecutionEvidenceSpec:
    namespace: str
    module_prefix: str
    shard_size: int
    source_program: LeanRef
    original_context: LeanRef
    inventory: LeanRef
    exact_binding: LeanRef
    transition_index: LeanRef
    target_ids_exact: LeanRef
    instruction_semantics_adequate: LeanRef
    protocol_responses: LeanRef
    project: LeanRef
    launch_inventory_holds: LeanRef
    launch_realizable: LeanRef
    compatibility_program_record_kernel_matches: LeanRef
    targets: tuple[TargetPreservation, ...]
    frontiers: tuple[FrontierProjection, ...]
    input_hashes: tuple[tuple[str, str], ...]

    def validate(self) -> None:
        if _IDENTIFIER.fullmatch(self.namespace) is None or not self.namespace.startswith(
            "StageA."
        ):
            raise OriginalExecutionEvidenceError(
                "namespace must be a canonical StageA namespace"
            )
        if _LOCAL.fullmatch(self.module_prefix) is None:
            raise OriginalExecutionEvidenceError(
                "module_prefix must be a local Lean identifier"
            )
        if self.shard_size <= 0:
            raise OriginalExecutionEvidenceError("shard_size must be positive")
        for name in (
            "source_program",
            "original_context",
            "inventory",
            "exact_binding",
            "transition_index",
            "target_ids_exact",
            "instruction_semantics_adequate",
            "protocol_responses",
            "project",
            "launch_inventory_holds",
            "launch_realizable",
            "compatibility_program_record_kernel_matches",
        ):
            getattr(self, name).validate(name)
        if not self.targets:
            raise OriginalExecutionEvidenceError(
                "at least one reachable target preservation is required"
            )
        target_ids = [target.target_id for target in self.targets]
        if target_ids != sorted(set(target_ids)):
            raise OriginalExecutionEvidenceError(
                "target preservations must be sorted and duplicate-free"
            )
        for index, target in enumerate(self.targets):
            target.validate(f"targets[{index}]")
        frontier_keys = [
            (frontier.category, frontier.source_rva)
            for frontier in self.frontiers
        ]
        if frontier_keys != sorted(set(frontier_keys)):
            raise OriginalExecutionEvidenceError(
                "frontier projections must be sorted and duplicate-free"
            )
        for index, frontier in enumerate(self.frontiers):
            frontier.validate(f"frontiers[{index}]")
        names = [name for name, _digest in self.input_hashes]
        if names != sorted(set(names)):
            raise OriginalExecutionEvidenceError(
                "input hashes must have sorted unique names"
            )
        for name, digest in self.input_hashes:
            if _LOCAL.fullmatch(name) is None or _SHA256.fullmatch(digest) is None:
                raise OriginalExecutionEvidenceError(
                    f"input hash {name!r} is not canonical"
                )


@dataclass(frozen=True)
class GeneratedOriginalExecutionEvidence:
    modules: tuple[Path, ...]
    audit: Path
    manifest: Path
    target_count: int
    shard_count: int


def generate_original_execution_evidence(
    out: Path | str, spec: OriginalExecutionEvidenceSpec
) -> GeneratedOriginalExecutionEvidence:
    """Write the generic checked evidence DAG below ``out/StageA``."""

    spec.validate()
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    data_module = f"{spec.module_prefix}Data"
    data_path = stage_a / f"{data_module}.lean"
    _write(data_path, _data_source(spec))
    written.append(data_path)

    shard_modules: list[str] = []
    for shard_index, start in enumerate(range(0, len(spec.targets), spec.shard_size)):
        targets = spec.targets[start : start + spec.shard_size]
        module = f"{spec.module_prefix}TargetShard{shard_index:04d}"
        path = stage_a / f"{module}.lean"
        _write(
            path,
            _target_shard_source(
                spec, data_module, module, shard_index, targets
            ),
        )
        written.append(path)
        shard_modules.append(module)

    index_module = f"{spec.module_prefix}TargetIndex"
    index_path = stage_a / f"{index_module}.lean"
    _write(index_path, _target_index_source(spec, shard_modules))
    written.append(index_path)

    external_module = f"{spec.module_prefix}External"
    external_path = stage_a / f"{external_module}.lean"
    _write(external_path, _external_source(spec, data_module))
    written.append(external_path)

    acceptance_module = spec.module_prefix
    acceptance_path = stage_a / f"{acceptance_module}.lean"
    _write(
        acceptance_path,
        _acceptance_source(spec, index_module, external_module),
    )
    written.append(acceptance_path)

    audit_module = f"{spec.module_prefix}Audit"
    audit_path = stage_a / f"{audit_module}.lean"
    _write(audit_path, _audit_source(spec, acceptance_module))

    manifest_path = root / "original-execution-proof.json"
    exports = _exports(
        spec,
        data_module=data_module,
        index_module=index_module,
        external_module=external_module,
        acceptance_module=acceptance_module,
    )
    manifest = {
        "format": ORIGINAL_EXECUTION_PROOF_FORMAT,
        "proof_authority": False,
        "acceptance_authority": False,
        "validation_required": "lean-kernel-check-and-detached-axiom-audit",
        "executes_original_binary": False,
        "executes_candidate_binary": False,
        "inputs": dict(spec.input_hashes),
        "counts": {
            "targets": len(spec.targets),
            "target_shards": len(shard_modules),
            "frontiers": len(spec.frontiers),
        },
        "modules": [f"StageA.{path.stem}" for path in written],
        "audit_module": f"StageA.{audit_module}",
        "exports": {name: ref.to_json() for name, ref in exports.items()},
    }
    _write(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return GeneratedOriginalExecutionEvidence(
        modules=tuple(written),
        audit=audit_path,
        manifest=manifest_path,
        target_count=len(spec.targets),
        shard_count=len(shard_modules),
    )


def _base_imports(spec: OriginalExecutionEvidenceSpec) -> set[str]:
    refs = (
        spec.source_program,
        spec.original_context,
        spec.inventory,
        spec.exact_binding,
        spec.transition_index,
        spec.target_ids_exact,
        spec.instruction_semantics_adequate,
        spec.project,
        spec.launch_inventory_holds,
        spec.launch_realizable,
        spec.compatibility_program_record_kernel_matches,
    )
    return {ref.module for ref in refs}


def _data_source(spec: OriginalExecutionEvidenceSpec) -> str:
    imports = sorted(_base_imports(spec))
    return f"""{_imports(imports)}
import StageA.RelationalNativeSourceLaunchFamily
import StageA.RelationalOriginalTargetPreservation

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

noncomputable section

abbrev generatedSourceProgram : Program :=
  {spec.source_program.declaration}

abbrev generatedWorldProgram : DecodedWorldProgram :=
  generatedSourceProgram.worldProgram

abbrev generatedOriginalContext : OriginalDecodedStaticContext :=
  {spec.original_context.declaration}

abbrev generatedInventory : OriginalCombinedExecutionInventory
    generatedWorldProgram generatedOriginalContext :=
  {spec.inventory.declaration}

abbrev generatedExactBinding : ExactBinding
    generatedWorldProgram.context.originalPe generatedSourceProgram :=
  {spec.exact_binding.declaration}

abbrev generatedActiveTransitionIndex :
    ActiveTargetTransitionIndex generatedExactBinding :=
  {spec.transition_index.declaration}

theorem generatedActiveTargetIdsExact :
    generatedActiveTransitionIndex.certificates.map
        (fun certificate => certificate.targetId) =
      generatedInventory.reachableTargets.targetIds :=
  {spec.target_ids_exact.declaration}

theorem generatedInstructionSemanticsAdequate :
    generatedWorldProgram.InstructionSemanticsAdequate :=
  {spec.instruction_semantics_adequate.declaration}

abbrev generatedNativeSourceProject : NativeSourceProject :=
  {spec.project.declaration}

end
end {spec.namespace}
"""


def _target_effect_source(target: TargetPreservation) -> str:
    prefix = f"generatedTarget{target.target_id}"
    if target.effect.kind == "ordinary":
        assert target.effect.ordinary_checked is not None
        expression = (
            "CheckedOriginalTargetEffect.ofOrdinary "
            f"{target.effect.ordinary_checked.declaration} "
            "generatedInstructionSemanticsAdequate"
        )
    else:
        assert target.effect.x87_facts is not None
        assert target.effect.x87_components is not None
        expression = (
            "CheckedOriginalTargetEffect.ofX87 "
            f"{target.effect.x87_facts.declaration} "
            f"{target.effect.x87_components.declaration} "
            "generatedInstructionSemanticsAdequate"
        )
    return f"""def {prefix}CheckedEffect :
    CheckedOriginalTargetEffect generatedSourceProgram {target.target_id} :=
  {expression}

abbrev {prefix}Certificate : ActiveTargetTransitionCertificate
    generatedExactBinding :=
  {target.certificate.declaration}

def {prefix}Provider : CheckedOriginalTargetPreservationProvider
    generatedOriginalContext generatedInventory {prefix}Certificate where
  checked := {prefix}CheckedEffect
  cases := {target.cases.declaration}

def {prefix}FamilyPreservation :
    OriginalCombinedTargetFamilyPreservation generatedOriginalContext
      generatedInventory {prefix}Certificate :=
  {prefix}Provider.toFamilyPreservation
"""


def _target_shard_source(
    spec: OriginalExecutionEvidenceSpec,
    data_module: str,
    module: str,
    shard_index: int,
    targets: tuple[TargetPreservation, ...],
) -> str:
    imports = sorted(
        {
            ref_module
            for target in targets
            for ref_module in (
                *target.effect.imports,
                target.certificate.module,
                target.cases.module,
            )
        }
    )
    body = "\n\n".join(_target_effect_source(target) for target in targets)
    certificate_names = [
        f"generatedTarget{target.target_id}Certificate" for target in targets
    ]
    preservation_names = [
        f"generatedTarget{target.target_id}FamilyPreservation"
        for target in targets
    ]
    alternatives = " | ".join("rfl" for _target in targets)
    cases = "  all_goals first\n" + "\n".join(
        f"    | exact {name}" for name in preservation_names
    )
    suffix = f"{shard_index:04d}"
    return f"""import StageA.{data_module}
{_imports(imports)}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld.ProgramCertificate

noncomputable section

{body}

def generatedShardCertificates{suffix} : List
    (ActiveTargetTransitionCertificate generatedExactBinding) :=
  [{', '.join(certificate_names)}]

theorem generatedShardPreserves{suffix}
    (certificate : ActiveTargetTransitionCertificate generatedExactBinding)
    (member : Membership.mem generatedShardCertificates{suffix} certificate) :
    OriginalCombinedTargetFamilyPreservation generatedOriginalContext
      generatedInventory certificate := by
  simp only [generatedShardCertificates{suffix}, List.mem_cons,
    List.not_mem_nil, or_false] at member
  rcases member with {alternatives}
{cases}

end
end {spec.namespace}
"""


def _target_index_source(
    spec: OriginalExecutionEvidenceSpec, shard_modules: list[str]
) -> str:
    shard_lists = [f"generatedShardCertificates{index:04d}" for index in range(len(shard_modules))]
    shard_proofs = [f"generatedShardPreserves{index:04d}" for index in range(len(shard_modules))]
    append_expression = " ++ ".join(shard_lists)
    if len(shard_modules) == 1:
        dispatch = f"exact {shard_proofs[0]} certificate member"
    else:
        alternatives = " | ".join(
            f"member{index:04d}" for index in range(len(shard_modules))
        )
        branches = "  all_goals first\n" + "\n".join(
            f"    | exact {proof} certificate member{index:04d}"
            for index, proof in enumerate(shard_proofs)
        )
        dispatch = f"""simp only [generatedPreservationCertificates,
      List.mem_append] at member
  rcases member with {alternatives}
{branches}"""
    return f"""{chr(10).join(f'import StageA.{module}' for module in shard_modules)}
import StageA.RelationalOriginalCombinedTargetStepIndex

namespace {spec.namespace}

open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.SourceWorld.ProgramCertificate

noncomputable section

def generatedPreservationCertificates : List
    (ActiveTargetTransitionCertificate generatedExactBinding) :=
  {append_expression}

theorem generatedPreservationCertificatesExact :
    generatedPreservationCertificates =
      generatedActiveTransitionIndex.certificates := by
  rfl

theorem generatedAllTargetsPreserve
    (certificate : ActiveTargetTransitionCertificate generatedExactBinding)
    (member : Membership.mem generatedActiveTransitionIndex.certificates certificate) :
    OriginalCombinedTargetFamilyPreservation generatedOriginalContext
      generatedInventory certificate := by
  rw [<- generatedPreservationCertificatesExact] at member
  {dispatch}

def generatedCombinedTargetStepIndex : OriginalCombinedTargetStepIndex
    generatedExactBinding generatedOriginalContext generatedInventory where
  transitions := generatedActiveTransitionIndex
  targetIdsExact := generatedActiveTargetIdsExact
  preserves := generatedAllTargetsPreserve

end
end {spec.namespace}
"""


def _external_source(spec: OriginalExecutionEvidenceSpec, data_module: str) -> str:
    return f"""import StageA.{data_module}
import {spec.protocol_responses.module}
import StageA.RelationalOriginalCombinedAwaitingExternalPreservation

namespace {spec.namespace}

open StageA.Relational.OriginalCombinedAwaitingExternalPreservation
open StageA.Relational.OriginalCombinedTargetStepIndex

noncomputable section

abbrev generatedProtocolResponses :
    CheckedOriginalCombinedMachineProtocolResponses generatedWorldProgram
      generatedOriginalContext generatedInventory :=
  {spec.protocol_responses.declaration}

def generatedAwaitingExternalPreservation :
    OriginalCombinedAwaitingExternalPreservation generatedOriginalContext
      generatedInventory :=
  generatedProtocolResponses.toAwaitingExternalPreservation

end
end {spec.namespace}
"""


def _frontier_source(index: int, frontier: FrontierProjection) -> str:
    prefix = f"generatedFrontier{index:04d}"
    return f"""def {prefix}TargetMembership :
    RelationalWorld -> MachineState -> Prop :=
  {frontier.target_membership.declaration}

theorem {prefix}RunningTargetMembership
    {{state : MachineState}} {{calls : List Nat}} {{eventIndex : Nat}}
    {{world : RelationalWorld}}
    (holds : generatedCombinedInvariant.holds
      (.running {frontier.source_target_id} state calls eventIndex world)) :
    {prefix}TargetMembership world state :=
  {frontier.running_target_membership.declaration} holds

theorem {prefix}CallbackTargetMembership
    {{state : MachineState}} {{calls : List Nat}} {{eventIndex : Nat}}
    {{world : RelationalWorld}}
    {{callbacks : List WorldExternalCallbackRuntime}}
    (holds : generatedCombinedInvariant.holds
      (.callbackRunning {frontier.source_target_id} state calls eventIndex world
        callbacks)) : {prefix}TargetMembership world state :=
  {frontier.callback_target_membership.declaration} holds
"""


def _acceptance_source(
    spec: OriginalExecutionEvidenceSpec,
    index_module: str,
    external_module: str,
) -> str:
    extra_imports = sorted(
        {
            ref.module
            for frontier in spec.frontiers
            for ref in (
                frontier.static_authority,
                frontier.target_membership,
                frontier.running_target_membership,
                frontier.callback_target_membership,
            )
        }
    )
    frontiers = "\n\n".join(
        _frontier_source(index, frontier)
        for index, frontier in enumerate(spec.frontiers)
    )
    return f"""import StageA.{index_module}
import StageA.{external_module}
{_imports(extra_imports)}
import StageA.RelationalNativeSourceLaunchFamily

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

noncomputable section

def generatedCheckedCombinedInvariant : CheckedOriginalCombinedExecutionInvariant
    generatedWorldProgram generatedOriginalContext generatedInventory :=
  originalCombinedInvariant_of_indexedTargets generatedCombinedTargetStepIndex
    generatedAwaitingExternalPreservation

abbrev generatedCombinedInvariant :
    OriginalWorldExecutionInvariant generatedWorldProgram :=
  generatedCheckedCombinedInvariant.toOriginalInvariant

def generatedInvariantFamilyEvidence :
    CheckedOriginalInvariantFamilyEvidence generatedWorldProgram :=
  generatedCheckedCombinedInvariant.toInvariantFamilyEvidence

def generatedTargetIds : List Nat :=
  generatedInvariantFamilyEvidence.targetIds

theorem generatedTargetIdsUnique : generatedTargetIds.Nodup :=
  generatedInvariantFamilyEvidence.targetIdsUnique

theorem generatedReachabilityProjection (execution : WorldExecution)
    (holds : generatedCombinedInvariant.holds execution) :
    OriginalExecutionReachable generatedTargetIds execution :=
  generatedInvariantFamilyEvidence.reachabilityProjection execution holds

theorem generatedTargetRoundTrips (targetId : Nat)
    (member : Membership.mem generatedTargetIds targetId) : exists eip,
    generatedWorldProgram.canonicalRawEip? targetId = some eip /\\
      generatedWorldProgram.resolveRawEip eip = some targetId :=
  generatedInvariantFamilyEvidence.targetRoundTrips targetId member

theorem generatedInvariantAtLaunch (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch generatedNativeSourceProject
      sourceRoot) :
    generatedCombinedInvariant.holds sourceRoot.toWorldExecution :=
  {spec.launch_inventory_holds.declaration} sourceRoot launch

theorem generatedLaunchRealizable : exists sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch generatedNativeSourceProject sourceRoot :=
  {spec.launch_realizable.declaration}

def generatedInvariantLaunchFamilyEvidence :
    CheckedNativeSourceInvariantLaunchFamilyEvidence
      generatedNativeSourceProject where
  exactBinding := generatedExactBinding
  instructionSemanticsAdequate := generatedInstructionSemanticsAdequate
  original := generatedInvariantFamilyEvidence
  invariantAtLaunch := generatedInvariantAtLaunch
  activeTargets := generatedActiveTransitionIndex
  activeTargetIdsExact := generatedActiveTargetIdsExact
  launchRealizable := generatedLaunchRealizable

def generatedCheckedNativeSourceLaunchFamily :
    CheckedNativeSourceLaunchFamily generatedNativeSourceProject :=
  generatedInvariantLaunchFamilyEvidence.toCheckedNativeSourceLaunchFamily

abbrev generatedCompatibilityProgramRecordKernelMatches :=
  {spec.compatibility_program_record_kernel_matches.declaration}

{frontiers}

end
end {spec.namespace}
"""


def _audit_source(spec: OriginalExecutionEvidenceSpec, module: str) -> str:
    prefix = spec.namespace
    target_audits = "\n".join(
        f"#print axioms {prefix}.generatedTarget{target.target_id}Provider"
        for target in spec.targets
    )
    frontier_audits = "\n".join(
        f"#print axioms {prefix}.generatedFrontier{index:04d}RunningTargetMembership\n"
        f"#print axioms {prefix}.generatedFrontier{index:04d}CallbackTargetMembership"
        for index, _frontier in enumerate(spec.frontiers)
    )
    return f"""import StageA.{module}

{target_audits}
#print axioms {prefix}.generatedCombinedTargetStepIndex
#print axioms {prefix}.generatedAwaitingExternalPreservation
#print axioms {prefix}.generatedCheckedCombinedInvariant
#print axioms {prefix}.generatedInvariantAtLaunch
#print axioms {prefix}.generatedInvariantLaunchFamilyEvidence
#print axioms {prefix}.generatedCheckedNativeSourceLaunchFamily
{frontier_audits}
"""


def _exports(
    spec: OriginalExecutionEvidenceSpec,
    *,
    data_module: str,
    index_module: str,
    external_module: str,
    acceptance_module: str,
) -> dict[str, LeanRef]:
    prefix = spec.namespace
    names = {
        "project": (data_module, "generatedNativeSourceProject"),
        "combined_invariant": (acceptance_module, "generatedCombinedInvariant"),
        "target_ids": (acceptance_module, "generatedTargetIds"),
        "target_ids_unique": (acceptance_module, "generatedTargetIdsUnique"),
        "reachability_projection": (
            acceptance_module,
            "generatedReachabilityProjection",
        ),
        "target_round_trips": (acceptance_module, "generatedTargetRoundTrips"),
        "invariant_at_launch": (acceptance_module, "generatedInvariantAtLaunch"),
        "exact_binding": (data_module, "generatedExactBinding"),
        "instruction_semantics_adequate": (
            data_module,
            "generatedInstructionSemanticsAdequate",
        ),
        "program_record_kernel_matches": (
            acceptance_module,
            "generatedCompatibilityProgramRecordKernelMatches",
        ),
        "launch_realizable": (acceptance_module, "generatedLaunchRealizable"),
        "target_step_index": (index_module, "generatedCombinedTargetStepIndex"),
        "external_preservation": (
            external_module,
            "generatedAwaitingExternalPreservation",
        ),
        "checked_combined_invariant": (
            acceptance_module,
            "generatedCheckedCombinedInvariant",
        ),
        "invariant_family_evidence": (
            acceptance_module,
            "generatedInvariantFamilyEvidence",
        ),
        "launch_family": (
            acceptance_module,
            "generatedCheckedNativeSourceLaunchFamily",
        ),
    }
    return {
        name: LeanRef.from_qualified(
            f"StageA.{module}", f"{prefix}.{symbol}"
        )
        for name, (module, symbol) in names.items()
    }


def sha256_file(path: Path | str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _imports(modules: list[str] | set[str]) -> str:
    return "\n".join(f"import {module}" for module in sorted(set(modules)))


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="ascii")


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise OriginalExecutionEvidenceError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise OriginalExecutionEvidenceError(f"{label} must be a non-empty string")
    return value


def _natural(value: object, label: str, *, word: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OriginalExecutionEvidenceError(f"{label} must be a natural number")
    if word and value > 0xFFFFFFFF:
        raise OriginalExecutionEvidenceError(f"{label} must fit in a 32-bit word")
    return value


def _exact_keys(
    row: dict[str, object], expected: set[str], label: str
) -> None:
    if set(row) != expected:
        raise OriginalExecutionEvidenceError(
            f"{label} fields differ (missing={sorted(expected - set(row))}, "
            f"unexpected={sorted(set(row) - expected)})"
        )


__all__ = [
    "ORIGINAL_EXECUTION_PRESERVATION_INPUTS_FORMAT",
    "ORIGINAL_EXECUTION_PROOF_FORMAT",
    "FrontierProjection",
    "GeneratedOriginalExecutionEvidence",
    "LeanRef",
    "OriginalExecutionEvidenceError",
    "OriginalExecutionEvidenceSpec",
    "TargetEffect",
    "TargetPreservation",
    "generate_original_execution_evidence",
    "sha256_file",
]
