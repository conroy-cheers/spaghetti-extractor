"""Generate GNU hello direct-call mixed semantic evidence adapters.

The generated shards select only non-x87 semantic rows containing immediate
direct calls. Each definition reuses the row's exact fused semantic binding
and the generic checked direct-call adapter. Runtime paths, endpoints,
observations, statuses, and invariant claims are never generated from JSON.
They remain Lean proof inputs indexed by exact PE-backed summaries and the
exact candidate-before world.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from spaghetti_extractor.errors import StageAInputError
from .gnu_hello_mixed_fused_semantic_evidence import _factory_family
from spaghetti_extractor.relational.lean.interpreter_normalization import (
    _is_x87_row,
    _ordinary_items,
    _validated_row,
)


GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_FORMAT = (
    "stage-a-gnu-hello-mixed-direct-call-semantic-evidence-v1"
)
GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_BUNDLE = (
    "GeneratedGnuHelloMixedDirectCallSemanticEvidenceBundle"
)
GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_INVENTORY = (
    "gnu-hello-mixed-direct-call-semantic-evidence.json"
)

_DIRECT_FAMILY = "dedicated-direct-call-return"
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


class GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
    StageAInputError
):
    """The direct-call source inventory or Lean naming scheme is malformed."""


@dataclass(frozen=True)
class GnuHelloMixedDirectCallSemanticEvidenceSpec:
    """Stable generated-module and theorem naming inputs."""

    fused_module_prefix: str = (
        "StageA.GeneratedGnuHelloMixedFusedSemanticEvidenceShard"
    )
    namespace: str = "StageA.GeneratedRelational"
    module_prefix: str = "GeneratedGnuHelloMixedDirectCallSemanticEvidence"
    bundle_module: str = (
        GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_BUNDLE
    )
    fused_binding_prefix: str = (
        "StageA.GeneratedRelational."
        "generatedCheckedFusedOriginalSemanticBinding"
    )
    record_prefix: str = (
        "StageA.GeneratedRelational.semanticInterpreterProgramRecord"
    )
    fused_shard_size: int = 48
    shard_size: int = 32

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.fused_module_prefix) is None:
            raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
                "fused_module_prefix must be a canonical StageA module prefix"
            )
        for field, value in (
            ("namespace", self.namespace),
            ("fused_binding_prefix", self.fused_binding_prefix),
            ("record_prefix", self.record_prefix),
        ):
            if not _valid_identifier(value):
                raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
                    f"{field} must be a canonical Lean identifier"
                )
        for field, value in (
            ("module_prefix", self.module_prefix),
            ("bundle_module", self.bundle_module),
        ):
            if not _valid_local_identifier(value):
                raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
                    f"{field} must be a canonical Lean local identifier"
                )
        if self.fused_shard_size <= 0:
            raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
                "fused_shard_size must be positive"
            )
        if self.shard_size <= 0:
            raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
                "shard_size must be positive"
            )


@dataclass(frozen=True)
class GnuHelloMixedDirectCallSemanticEvidenceBundle:
    """Generated Lean sources plus a non-authoritative residual inventory."""

    sources: Mapping[str, str]
    inventory: Mapping[str, Any]


def generate_gnu_hello_mixed_direct_call_semantic_evidence(
    rows: Iterable[Mapping[str, Any]],
    spec: GnuHelloMixedDirectCallSemanticEvidenceSpec | None = None,
) -> GnuHelloMixedDirectCallSemanticEvidenceBundle:
    spec = spec or GnuHelloMixedDirectCallSemanticEvidenceSpec()
    spec.validate()
    materialized = [dict(row) for row in rows]
    validated = [_validated_row(row) for row in materialized]
    try:
        ordinary = _ordinary_items(materialized)
    except StageAInputError as error:
        raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
            str(error)
        ) from error

    row_by_start = {item["start"]: item["row"] for item in validated}
    if len(row_by_start) != len(validated):
        raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
            "semantic source RVAs must be unique"
        )

    non_x87_rows: list[dict[str, Any]] = []
    family_counts: Counter[str] = Counter()
    for ordinary_index, item in ordinary:
        row = row_by_start[item["start"]]
        try:
            family = _factory_family(row)
        except StageAInputError as error:
            raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
                str(error)
            ) from error
        family_counts[family] += 1
        if family == _DIRECT_FAMILY:
            call_count = sum(
                str(instruction.get("mnemonic", "")).lower().startswith(
                    "call"
                )
                for instruction in row.get("instructions", [])
            )
            if call_count != 1:
                raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
                    f"semantic row {item['id']!r} must contain exactly one "
                    "immediate direct call for one call/return adapter"
                )
        non_x87_rows.append(
            {
                "ordinary_index": ordinary_index,
                "id": item["id"],
                "start": item["start"],
                "stop": item["stop"],
                "family": family,
            }
        )

    non_x87_rows.sort(
        key=lambda item: (item["start"], item["ordinary_index"])
    )
    fused_position = {
        item["ordinary_index"]: position
        for position, item in enumerate(non_x87_rows)
    }
    direct_rows: list[dict[str, Any]] = []
    residuals: list[dict[str, Any]] = []
    for item in non_x87_rows:
        if item["family"] == _DIRECT_FAMILY:
            index = item["ordinary_index"]
            direct_rows.append(
                {
                    **item,
                    "fused_shard_index": (
                        fused_position[index] // spec.fused_shard_size
                    ),
                    "evidence_definition": (
                        "generatedCheckedMixedDirectCallSemanticEvidence"
                        f"{index}"
                    ),
                }
            )
        else:
            residuals.append(dict(item))

    x87_rows = [
        {
            "ordinary_index": None,
            "id": item["id"],
            "start": item["start"],
            "stop": item["stop"],
            "family": "dedicated-x87-replay",
        }
        for row, item in zip(materialized, validated, strict=True)
        if _is_x87_row(row)
    ]
    family_counts["dedicated-x87-replay"] += len(x87_rows)
    residuals.extend(x87_rows)
    residuals.sort(
        key=lambda item: (
            item["start"],
            -1 if item["ordinary_index"] is None else item["ordinary_index"],
        )
    )
    if len(non_x87_rows) + len(x87_rows) != len(materialized):
        raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
            "non-x87 and x87 rows do not form an exact input partition"
        )

    sources: dict[str, str] = {}
    shard_modules: list[str] = []
    for shard_start in range(0, len(direct_rows), spec.shard_size):
        shard_rows = direct_rows[shard_start : shard_start + spec.shard_size]
        shard_index = shard_start // spec.shard_size
        module = f"{spec.module_prefix}Shard{shard_index:04d}"
        shard_modules.append(module)
        sources[module] = _shard_source(spec, shard_rows)

    evidence_names = [
        item["evidence_definition"] for item in direct_rows
    ]
    sources[spec.bundle_module] = _bundle_source(
        spec, shard_modules, evidence_names
    )
    residual_counts = Counter(item["family"] for item in residuals)
    inventory = {
        "format": GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_FORMAT,
        "proof_authority": False,
        "acceptance_authority": False,
        "classification_authority": False,
        "input_rows": len(materialized),
        "direct_call_return_rows": len(direct_rows),
        "generated_direct_call_evidence_adapters": len(evidence_names),
        "family_counts": dict(sorted(family_counts.items())),
        "unowned_family_counts": dict(sorted(residual_counts.items())),
        "unowned_factory_cases": residuals,
        "direct_row_runtime_obligations": {
            "rows": len(direct_rows),
            "required_per_row": [
                "complete exact PE-backed direct-call/call-tree premises",
                "related source for completeness-derived execution",
                "call-aware checked interpreter Step derivation",
                "semantic result equality at the computed original exit",
                "restored event index and callback stack",
                "exact candidate replay from candidateBefore",
                "pointwise related observations",
                "target mixed invariant",
            ],
        },
        "modules": sorted(sources),
        "target": spec.bundle_module,
        "validation_required": "lean-kernel-check",
        "checked_boundary": {
            "original_path_selected_by_exact_direct_call_summary": True,
            "actual_execution_derived_from_operational_completeness": True,
            "one_exact_direct_call_per_generated_adapter": True,
            "original_path_starts_at_exact_summary_source_world": True,
            "candidate_path_starts_at_exact_candidate_before_world": True,
            "dispatch_anchored_to_candidate_before_machine": True,
            "kernel_dispatch_relation_world_indexed": False,
            "full_world_dispatch_identity_requires_exact_replay_lift": True,
            "semantic_result_compared_to_computed_original_exit": True,
            "observations_and_target_invariant_remain_lean_obligations": True,
            "paths_endpoints_statuses_accepted_from_json": False,
        },
    }
    return GnuHelloMixedDirectCallSemanticEvidenceBundle(
        sources=sources, inventory=inventory
    )


def write_gnu_hello_mixed_direct_call_semantic_evidence(
    out: Path | str,
    bundle: GnuHelloMixedDirectCallSemanticEvidenceBundle,
) -> tuple[Path, tuple[Path, ...]]:
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for module, source in sorted(bundle.sources.items()):
        path = stage_a / f"{module}.lean"
        path.write_text(source, encoding="utf-8")
        paths.append(path)
    inventory_path = (
        root / GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_INVENTORY
    )
    inventory_path.write_text(
        json.dumps(bundle.inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return inventory_path, tuple(paths)


def _shard_source(
    spec: GnuHelloMixedDirectCallSemanticEvidenceSpec,
    rows: list[dict[str, Any]],
) -> str:
    fused_modules = sorted(
        {item["fused_shard_index"] for item in rows}
    )
    imports = "\n".join(
        f"import {spec.fused_module_prefix}{index:04d}"
        for index in fused_modules
    )
    definitions = "\n".join(
        _evidence_definition(spec, row) for row in rows
    )
    source = f"""import StageA.RelationalInterpreterMixedDirectCallSemanticEvidenceAdapter
{imports}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedDirectCallSemanticEvidenceAdapter
open StageA.Relational.InterpreterMixedFusedSemanticEvidenceAdapter
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedSemanticOperationComponent
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

{definitions}
end {spec.namespace}
"""
    _reject_forbidden_source(source)
    return source


def _evidence_definition(
    spec: GnuHelloMixedDirectCallSemanticEvidenceSpec,
    row: Mapping[str, Any],
) -> str:
    index = row["ordinary_index"]
    start = row["start"]
    stop = row["stop"]
    size = stop - start
    name = row["evidence_definition"]
    binding = f"{spec.fused_binding_prefix}{index}"
    record = f"{spec.record_prefix}{index}"
    return f"""noncomputable def {name}
    {{context : OriginalDecodedStaticContext}}
    {{authority : ExactOriginalDecodedAuthority context}}
    {{launch : PE32ConsoleLaunchV2}}
    {{root : DirectExactOriginalDecodedLaunchRoot context launch}}
    {{reachability :
      ExactOriginalDecodedReachability context authority launch root}}
    {{staticContext : StaticProofContext}}
    {{tree : SummaryTree}}
    {{premises : IntegratedSummaryPremises staticContext tree}}
    {{summarySource : RelatedDirectCallSource staticContext tree
      premises.callEntry}}
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
    {{candidateBefore : NativeWorldExecution}}
    {{ClassificationEvidence : Prop}}
    {{beforeRelated : invariant.holds
      (checkedActualDirectCallForSource premises
        summarySource).source.original.execution candidateBefore}}
    {{classified : ClassificationEvidence}}
    {{environment : StageA.Relational.Interpreter.Environment}}
    {{resolveCodeTarget : Word -> Option Nat}}
    (contextPeExact :
      context.pe = StageA.GeneratedRelational.originalPe)
    (contextImportsExact :
      context.imports = StageA.GeneratedRelational.originalImports)
    (sourceRecordExact : source.record = {record})
    (sourceRvaExact : source.source.target.rva = {start})
    (sourceSpanExact : source.source.region.span =
      ({{ start := {start}, size := {size} }} : Span))
    (input : CheckedDirectCallMixedSemanticOperationInput context authority
      launch root reachability staticContext tree premises summarySource
      candidate candidateAuthority contract invariant program abi dispatches
      source
      ({binding} source contextPeExact contextImportsExact sourceRecordExact
        sourceRvaExact sourceSpanExact)
      entryRva candidateBefore ClassificationEvidence beforeRelated classified
      environment resolveCodeTarget) :
    CheckedMixedSemanticOperationEvidence
      premises.operational.originalProgram candidate candidateAuthority contract
      invariant program abi dispatches source.source.target.rva source.record
      .interpreterStep entryRva
      (checkedActualDirectCallForSource premises
        summarySource).source.original.execution
      candidateBefore ClassificationEvidence beforeRelated classified :=
  input.toEvidence
"""


def _bundle_source(
    spec: GnuHelloMixedDirectCallSemanticEvidenceSpec,
    modules: list[str],
    evidence: list[str],
) -> str:
    imports = "\n".join(f"import StageA.{module}" for module in modules)
    evidence_inventory = ",\n  ".join(f'"{name}"' for name in evidence)
    source = f"""{imports}

namespace {spec.namespace}

def generatedGnuHelloDirectCallSemanticEvidenceNames : List String := [
  {evidence_inventory}
]

theorem generatedGnuHelloDirectCallSemanticEvidenceNameCount :
    generatedGnuHelloDirectCallSemanticEvidenceNames.length =
      {len(evidence)} := by
  decide

end {spec.namespace}
"""
    _reject_forbidden_source(source)
    return source


def _reject_forbidden_source(source: str) -> None:
    for forbidden in ("sorry", "native_decide", "axiom ", "unsafe "):
        if forbidden in source:
            raise GnuHelloMixedDirectCallSemanticEvidenceGenerationError(
                f"generated source unexpectedly contains {forbidden.strip()}"
            )


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
    "GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_BUNDLE",
    "GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_FORMAT",
    "GNU_HELLO_MIXED_DIRECT_CALL_SEMANTIC_EVIDENCE_INVENTORY",
    "GnuHelloMixedDirectCallSemanticEvidenceBundle",
    "GnuHelloMixedDirectCallSemanticEvidenceGenerationError",
    "GnuHelloMixedDirectCallSemanticEvidenceSpec",
    "generate_gnu_hello_mixed_direct_call_semantic_evidence",
    "write_gnu_hello_mixed_direct_call_semantic_evidence",
]
