"""Generate GNU hello exact fused bindings and ordinary evidence adapters.

Every non-x87 semantic row receives a Lean definition that combines its exact
normalization certificate with its cached fused-machine refinement theorem.
Only call-free, non-external rows receive an ordinary one-step evidence
adapter. X87, call/return, and external-boundary rows remain explicit residual
factory cases owned by their dedicated proof pipelines.

The JSON inventory is diagnostic only. Lean definitions consume structural
equalities checked by the kernel; no submitted path, endpoint, status, or
completion count can authorize a mixed component.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from ...errors import StageAInputError
from .interpreter_normalization import (
    _is_x87_row,
    _ordinary_items,
    _validated_row,
)


GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_FORMAT = (
    "stage-a-gnu-hello-mixed-fused-semantic-evidence-v1"
)
GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_BUNDLE = (
    "GeneratedGnuHelloMixedFusedSemanticEvidenceBundle"
)
GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_INVENTORY = (
    "gnu-hello-mixed-fused-semantic-evidence.json"
)

_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_QUALIFIED_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_FORBIDDEN = frozenset(
    {
        "admit",
        "axiom",
        "by",
        "def",
        "import",
        "native_decide",
        "opaque",
        "sorry",
        "theorem",
        "unsafe",
    }
)
_ORDINARY_OUTCOMES = frozenset(
    {"fallthrough", "jump", "branch", "return", "indirect_jump"}
)


class GnuHelloMixedFusedSemanticEvidenceGenerationError(StageAInputError):
    """The requested source inventory or Lean naming scheme is malformed."""


@dataclass(frozen=True)
class GnuHelloMixedFusedSemanticEvidenceSpec:
    """Stable generated-module and theorem naming inputs."""

    pe_module: str = "StageA.GeneratedGnuHelloOriginalPE"
    normalization_module_prefix: str = (
        "StageA.GeneratedInterpreterNormalizationShard"
    )
    refinement_module_prefix: str = (
        "StageA.GeneratedInterpreterSemanticRefinementShard"
    )
    namespace: str = "StageA.GeneratedRelational"
    module_prefix: str = "GeneratedGnuHelloMixedFusedSemanticEvidence"
    bundle_module: str = GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_BUNDLE
    original_pe: str = "StageA.GeneratedRelational.originalPe"
    original_imports: str = "StageA.GeneratedRelational.originalImports"
    record_prefix: str = "StageA.GeneratedRelational.semanticInterpreterProgramRecord"
    transfer_prefix: str = "StageA.GeneratedRelational.semanticInterpreterTransfer"
    path_prefix: str = "StageA.GeneratedRelational.exactNormalizedTransferPath"
    certificate_suffix: str = "Certificate"
    fused_prefix: str = (
        "StageA.GeneratedRelational."
        "exactNormalizedTransferFusedMachineRefinement"
    )
    shard_size: int = 48

    def validate(self) -> None:
        for field, value in (
            ("pe_module", self.pe_module),
            ("normalization_module_prefix", self.normalization_module_prefix),
            ("refinement_module_prefix", self.refinement_module_prefix),
        ):
            if _STAGE_A_MODULE.fullmatch(value) is None:
                raise GnuHelloMixedFusedSemanticEvidenceGenerationError(
                    f"{field} must be a canonical StageA module prefix"
                )
        for field, value in (
            ("namespace", self.namespace),
            ("original_pe", self.original_pe),
            ("original_imports", self.original_imports),
            ("record_prefix", self.record_prefix),
            ("transfer_prefix", self.transfer_prefix),
            ("path_prefix", self.path_prefix),
            ("fused_prefix", self.fused_prefix),
        ):
            if not _valid_identifier(value):
                raise GnuHelloMixedFusedSemanticEvidenceGenerationError(
                    f"{field} must be a canonical Lean identifier"
                )
        for field, value in (
            ("module_prefix", self.module_prefix),
            ("bundle_module", self.bundle_module),
            ("certificate_suffix", self.certificate_suffix),
        ):
            if not _valid_local_identifier(value):
                raise GnuHelloMixedFusedSemanticEvidenceGenerationError(
                    f"{field} must be a canonical Lean local identifier"
                )
        if self.shard_size <= 0:
            raise GnuHelloMixedFusedSemanticEvidenceGenerationError(
                "shard_size must be positive"
            )


@dataclass(frozen=True)
class GnuHelloMixedFusedSemanticEvidenceBundle:
    """Generated Lean sources plus a non-authoritative residual inventory."""

    sources: Mapping[str, str]
    inventory: Mapping[str, Any]


def generate_gnu_hello_mixed_fused_semantic_evidence(
    rows: Iterable[Mapping[str, Any]],
    spec: GnuHelloMixedFusedSemanticEvidenceSpec | None = None,
) -> GnuHelloMixedFusedSemanticEvidenceBundle:
    spec = spec or GnuHelloMixedFusedSemanticEvidenceSpec()
    spec.validate()
    materialized = [dict(row) for row in rows]
    validated = [_validated_row(row) for row in materialized]
    try:
        ordinary = _ordinary_items(materialized)
    except StageAInputError as error:
        raise GnuHelloMixedFusedSemanticEvidenceGenerationError(
            str(error)
        ) from error
    row_by_start = {item["start"]: item["row"] for item in validated}
    if len(row_by_start) != len(validated):
        raise GnuHelloMixedFusedSemanticEvidenceGenerationError(
            "semantic source RVAs must be unique"
        )

    x87_residuals = [
        _residual(None, item, "dedicated-x87-replay")
        for row, item in zip(materialized, validated, strict=True)
        if _is_x87_row(row)
    ]
    binding_rows: list[dict[str, Any]] = []
    residuals = list(x87_residuals)
    for ordinary_index, item in ordinary:
        row = row_by_start[item["start"]]
        family = _factory_family(row)
        evidence_name = (
            f"generatedCheckedMixedOrdinarySemanticEvidence{ordinary_index}"
            if family == "ordinary-one-step"
            else None
        )
        binding_rows.append(
            {
                "ordinary_index": ordinary_index,
                "id": item["id"],
                "start": item["start"],
                "stop": item["stop"],
                "family": family,
                "binding_definition": (
                    "generatedCheckedFusedOriginalSemanticBinding"
                    f"{ordinary_index}"
                ),
                "evidence_definition": evidence_name,
            }
        )
        if evidence_name is None:
            residuals.append(_residual(ordinary_index, item, family))

    binding_rows.sort(key=lambda item: (item["start"], item["ordinary_index"]))
    residuals.sort(
        key=lambda item: (
            item["start"],
            -1 if item["ordinary_index"] is None else item["ordinary_index"],
        )
    )
    if len(binding_rows) + len(x87_residuals) != len(materialized):
        raise GnuHelloMixedFusedSemanticEvidenceGenerationError(
            "ordinary and x87 rows do not form an exact input partition"
        )
    sources: dict[str, str] = {}
    shard_modules: list[str] = []
    for shard_start in range(0, len(binding_rows), spec.shard_size):
        shard_rows = binding_rows[shard_start : shard_start + spec.shard_size]
        shard_index = shard_start // spec.shard_size
        module = f"{spec.module_prefix}Shard{shard_index:04d}"
        shard_modules.append(module)
        sources[module] = _shard_source(spec, shard_index, shard_rows)

    binding_names = [
        row["binding_definition"] for row in binding_rows
    ]
    evidence_names = [
        row["evidence_definition"]
        for row in binding_rows
        if row["evidence_definition"] is not None
    ]
    sources[spec.bundle_module] = _bundle_source(
        spec, shard_modules, binding_names, evidence_names
    )
    residual_counts = Counter(item["family"] for item in residuals)
    family_counts = Counter(item["family"] for item in binding_rows)
    inventory = {
        "format": GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_FORMAT,
        "proof_authority": False,
        "acceptance_authority": False,
        "classification_authority": False,
        "input_rows": len(materialized),
        "non_x87_binding_rows": len(binding_rows),
        "ordinary_one_step_evidence_rows": len(evidence_names),
        "x87_rows": len(x87_residuals),
        "family_counts": dict(sorted(family_counts.items())),
        "residual_factory_counts": dict(sorted(residual_counts.items())),
        "residual_factory_cases": residuals,
        "modules": sorted(sources),
        "target": spec.bundle_module,
        "validation_required": "lean-kernel-check",
        "checked_boundary": {
            "bindings_require_exact_source_record_rva_and_span_equalities": True,
            "ordinary_evidence_requires_exact_source_and_step_facts": True,
            "candidate_path_starts_at_exact_candidate_before_world": True,
            "dispatch_anchored_to_candidate_before_machine": True,
            "kernel_dispatch_relation_world_indexed": False,
            "full_world_dispatch_identity_requires_exact_replay_lift": True,
            "paths_endpoints_and_statuses_accepted_from_json": False,
        },
    }
    return GnuHelloMixedFusedSemanticEvidenceBundle(
        sources=sources, inventory=inventory
    )


def write_gnu_hello_mixed_fused_semantic_evidence(
    out: Path | str,
    bundle: GnuHelloMixedFusedSemanticEvidenceBundle,
) -> tuple[Path, tuple[Path, ...]]:
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for module, source in sorted(bundle.sources.items()):
        path = stage_a / f"{module}.lean"
        path.write_text(source, encoding="utf-8")
        paths.append(path)
    inventory_path = root / GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_INVENTORY
    inventory_path.write_text(
        json.dumps(bundle.inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return inventory_path, tuple(paths)


def _factory_family(row: Mapping[str, Any]) -> str:
    calls = [
        instruction
        for instruction in row.get("instructions", [])
        if str(instruction.get("mnemonic", "")).lower().startswith("call")
    ]
    if calls:
        if all(
            str(instruction.get("op_str", "")).strip().lower().startswith("0x")
            for instruction in calls
        ):
            return "dedicated-direct-call-return"
        return "dedicated-indirect-or-import-call"
    outcome = row.get("outcome")
    kind = outcome.get("kind") if isinstance(outcome, Mapping) else None
    if kind == "external_jump":
        return "dedicated-external-boundary"
    if kind in _ORDINARY_OUTCOMES:
        return "ordinary-one-step"
    raise GnuHelloMixedFusedSemanticEvidenceGenerationError(
        f"semantic row {row.get('id')!r} has unsupported outcome {kind!r}"
    )


def _residual(
    ordinary_index: int | None, item: Mapping[str, Any], family: str
) -> dict[str, Any]:
    return {
        "ordinary_index": ordinary_index,
        "id": item["id"],
        "start": item["start"],
        "stop": item["stop"],
        "family": family,
    }


def _shard_source(
    spec: GnuHelloMixedFusedSemanticEvidenceSpec,
    shard_index: int,
    rows: list[dict[str, Any]],
) -> str:
    normalization_module = (
        f"{spec.normalization_module_prefix}{shard_index:04d}"
    )
    refinement_module = f"{spec.refinement_module_prefix}{shard_index:04d}"
    definitions = "\n".join(
        _binding_definition(spec, row)
        + (
            "\n" + _ordinary_evidence_definition(spec, row)
            if row["evidence_definition"] is not None
            else ""
        )
        for row in rows
    )
    return f"""import StageA.RelationalInterpreterMixedFusedSemanticEvidenceAdapter
import {spec.pe_module}
import {normalization_module}
import {refinement_module}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedFusedSemanticEvidenceAdapter
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedOriginalSemanticReplay
open StageA.Relational.InterpreterMixedSemanticOperationComponent
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterSemanticRefinement

{definitions}
end {spec.namespace}
"""


def _binding_definition(
    spec: GnuHelloMixedFusedSemanticEvidenceSpec, row: Mapping[str, Any]
) -> str:
    index = row["ordinary_index"]
    start = row["start"]
    stop = row["stop"]
    size = stop - start
    name = row["binding_definition"]
    path = f"{spec.path_prefix}{index}"
    transfer = f"{spec.transfer_prefix}{index}"
    record = f"{spec.record_prefix}{index}"
    certificate = f"{path}{spec.certificate_suffix}"
    fused = f"{spec.fused_prefix}{index}"
    span = f"({{ start := {start}, size := {size} }} : Span)"
    return f"""def {name}
    {{context : OriginalDecodedStaticContext}}
    {{authority : ExactOriginalDecodedAuthority context}}
    {{launch : PE32ConsoleLaunchV2}}
    {{root : DirectExactOriginalDecodedLaunchRoot context launch}}
    {{reachability :
      ExactOriginalDecodedReachability context authority launch root}}
    {{candidate : ExactNativeWorldProgram}}
    {{candidateAuthority : ExactNativeCandidateAuthority candidate}}
    (source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority)
    (contextPeExact : context.pe = {spec.original_pe})
    (contextImportsExact : context.imports = {spec.original_imports})
    (sourceRecordExact : source.record = {record})
    (sourceRvaExact : source.source.target.rva = {start})
    (sourceSpanExact : source.source.region.span = {span}) :
    CheckedFusedOriginalSemanticTransferBinding context authority launch root
      reachability candidate candidateAuthority source := by
  let binding : ExactOriginalSemanticTransferBinding context authority launch
      root reachability candidate candidateAuthority source := {{
    path := {path}
    transfer := {transfer}
    pathRecordExact := by
      change {record} = source.record
      exact sourceRecordExact.symm
    pathSourceExact := by
      change {start} = source.source.target.rva
      exact sourceRvaExact.symm
    pathStopExact := by
      change {stop} = source.source.region.span.stop
      rw [sourceSpanExact]
      rfl
    normalization := by
      simpa only [contextPeExact] using {certificate}
  }}
  exact {{
    binding
    fused := by
      change ExactSemanticTransferFusedMachineRefinement context.pe
        context.imports source.source.region.span {transfer}
      simpa only [contextPeExact, contextImportsExact, sourceSpanExact] using
        {fused}
  }}
"""


def _ordinary_evidence_definition(
    spec: GnuHelloMixedFusedSemanticEvidenceSpec,
    row: Mapping[str, Any],
) -> str:
    index = row["ordinary_index"]
    binding = row["binding_definition"]
    evidence = row["evidence_definition"]
    return f"""noncomputable def {evidence}
    {{context : OriginalDecodedStaticContext}}
    {{authority : ExactOriginalDecodedAuthority context}}
    {{launch : PE32ConsoleLaunchV2}}
    {{root : DirectExactOriginalDecodedLaunchRoot context launch}}
    {{reachability :
      ExactOriginalDecodedReachability context authority launch root}}
    {{original : DecodedWorldProgram}}
    {{candidate : ExactNativeWorldProgram}}
    {{candidateAuthority : ExactNativeCandidateAuthority candidate}}
    {{contract : MixedRelationContract}}
    {{invariant : MixedExecutionInvariant reachability.targetIds contract}}
    {{program : CompiledKernelProgram}}
    {{abi : KernelABIRelation}}
    {{dispatches : KernelDispatchRelation}}
    {{source : ExactOriginalSemanticSource context authority launch root
      reachability candidate candidateAuthority}}
    {{entryRva : Nat}}
    {{originalBefore : WorldExecution}}
    {{candidateBefore : NativeWorldExecution}}
    {{ClassificationEvidence : Prop}}
    {{beforeRelated : invariant.holds originalBefore candidateBefore}}
    {{classified : ClassificationEvidence}}
    {{sourceFacts : ExactOrdinaryOriginalSemanticSourceFacts context original
      source.targetId source.source}}
    {{stepFacts : ExactOrdinaryOriginalSemanticStepFacts original source.targetId
      sourceFacts originalBefore}}
    {{environment : StageA.Relational.Interpreter.Environment}}
    {{resolveCodeTarget : Word -> Option Nat}}
    (contextPeExact : context.pe = {spec.original_pe})
    (contextImportsExact :
      context.imports = {spec.original_imports})
    (sourceRecordExact :
      source.record = {spec.record_prefix}{index})
    (sourceRvaExact : source.source.target.rva = {row['start']})
    (sourceSpanExact : source.source.region.span =
      ({{ start := {row['start']}, size := {row['stop'] - row['start']} }} : Span))
    (input : CheckedOrdinaryMixedSemanticOperationInput context authority launch
      root reachability original candidate candidateAuthority contract invariant
      program abi dispatches source
      ({binding} source contextPeExact contextImportsExact sourceRecordExact
        sourceRvaExact sourceSpanExact)
      entryRva originalBefore candidateBefore ClassificationEvidence
      beforeRelated classified sourceFacts stepFacts environment
      resolveCodeTarget) :
    CheckedMixedSemanticOperationEvidence original candidate candidateAuthority
      contract invariant program abi dispatches source.source.target.rva
      source.record .interpreterStep entryRva originalBefore candidateBefore
      ClassificationEvidence beforeRelated classified :=
  input.toEvidence
"""


def _bundle_source(
    spec: GnuHelloMixedFusedSemanticEvidenceSpec,
    modules: list[str],
    bindings: list[str],
    evidence: list[str],
) -> str:
    imports = "\n".join(f"import StageA.{module}" for module in modules)
    binding_inventory = ",\n  ".join(f'"{name}"' for name in bindings)
    evidence_inventory = ",\n  ".join(f'"{name}"' for name in evidence)
    return f"""{imports}

namespace {spec.namespace}

def generatedGnuHelloFusedSemanticBindingNames : List String := [
  {binding_inventory}
]

theorem generatedGnuHelloFusedSemanticBindingNameCount :
    generatedGnuHelloFusedSemanticBindingNames.length = {len(bindings)} := by
  decide

def generatedGnuHelloOrdinarySemanticEvidenceNames : List String := [
  {evidence_inventory}
]

theorem generatedGnuHelloOrdinarySemanticEvidenceNameCount :
    generatedGnuHelloOrdinarySemanticEvidenceNames.length = {len(evidence)} := by
  decide

end {spec.namespace}
"""


def _valid_identifier(value: str) -> bool:
    return (
        _QUALIFIED_IDENTIFIER.fullmatch(value) is not None
        and all(part not in _FORBIDDEN for part in value.split("."))
    )


def _valid_local_identifier(value: str) -> bool:
    return (
        _LOCAL_IDENTIFIER.fullmatch(value) is not None
        and value not in _FORBIDDEN
    )


__all__ = [
    "GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_BUNDLE",
    "GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_FORMAT",
    "GNU_HELLO_MIXED_FUSED_SEMANTIC_EVIDENCE_INVENTORY",
    "GnuHelloMixedFusedSemanticEvidenceBundle",
    "GnuHelloMixedFusedSemanticEvidenceGenerationError",
    "GnuHelloMixedFusedSemanticEvidenceSpec",
    "generate_gnu_hello_mixed_fused_semantic_evidence",
    "write_gnu_hello_mixed_fused_semantic_evidence",
]
