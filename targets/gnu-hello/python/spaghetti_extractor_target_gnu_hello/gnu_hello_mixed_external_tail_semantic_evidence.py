"""Generate exact external-tail mixed semantic evidence adapters.

The owned rows remain semantic-transfer classifier cases. Each generated
definition specializes an exact fused PE binding and delegates to the generic
external-tail adapter. JSON is diagnostic only; Lean receives no submitted
path fuel, endpoint, observations, status, or count as proof authority.
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


GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_FORMAT = (
    "stage-a-gnu-hello-mixed-external-tail-semantic-evidence-v1"
)
GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_BUNDLE = (
    "GeneratedGnuHelloMixedExternalTailSemanticEvidenceBundle"
)
GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_INVENTORY = (
    "gnu-hello-mixed-external-tail-semantic-evidence.json"
)

_OWNED_FAMILY = "dedicated-external-boundary"
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


class GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
    StageAInputError
):
    """The semantic inventory or generated Lean naming is malformed."""


@dataclass(frozen=True)
class GnuHelloMixedExternalTailSemanticEvidenceSpec:
    """Stable generated module and theorem names."""

    fused_module_prefix: str = (
        "StageA.GeneratedGnuHelloMixedFusedSemanticEvidenceShard"
    )
    namespace: str = "StageA.GeneratedRelational"
    module_prefix: str = (
        "GeneratedGnuHelloMixedExternalTailSemanticEvidence"
    )
    bundle_module: str = (
        GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_BUNDLE
    )
    fused_binding_prefix: str = (
        "StageA.GeneratedRelational."
        "generatedCheckedFusedOriginalSemanticBinding"
    )
    record_prefix: str = (
        "StageA.GeneratedRelational.semanticInterpreterProgramRecord"
    )
    fused_shard_size: int = 48
    shard_size: int = 16

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.fused_module_prefix) is None:
            raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
                "fused_module_prefix must be a canonical StageA module prefix"
            )
        for field, value in (
            ("namespace", self.namespace),
            ("fused_binding_prefix", self.fused_binding_prefix),
            ("record_prefix", self.record_prefix),
        ):
            if not _valid_identifier(value):
                raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
                    f"{field} must be a canonical Lean identifier"
                )
        for field, value in (
            ("module_prefix", self.module_prefix),
            ("bundle_module", self.bundle_module),
        ):
            if not _valid_local_identifier(value):
                raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
                    f"{field} must be a canonical Lean local identifier"
                )
        if self.fused_shard_size <= 0:
            raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
                "fused_shard_size must be positive"
            )
        if self.shard_size <= 0:
            raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
                "shard_size must be positive"
            )


@dataclass(frozen=True)
class GnuHelloMixedExternalTailSemanticEvidenceBundle:
    """Generated Lean sources and a non-authoritative inventory."""

    sources: Mapping[str, str]
    inventory: Mapping[str, Any]


def generate_gnu_hello_mixed_external_tail_semantic_evidence(
    rows: Iterable[Mapping[str, Any]],
    spec: GnuHelloMixedExternalTailSemanticEvidenceSpec | None = None,
) -> GnuHelloMixedExternalTailSemanticEvidenceBundle:
    spec = spec or GnuHelloMixedExternalTailSemanticEvidenceSpec()
    spec.validate()
    materialized = [dict(row) for row in rows]
    validated = [_validated_row(row) for row in materialized]
    try:
        ordinary = _ordinary_items(materialized)
    except StageAInputError as error:
        raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
            str(error)
        ) from error

    row_by_start = {item["start"]: item["row"] for item in validated}
    if len(row_by_start) != len(validated):
        raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
            "semantic source RVAs must be unique"
        )

    non_x87_rows: list[dict[str, Any]] = []
    family_counts: Counter[str] = Counter()
    for ordinary_index, item in ordinary:
        row = row_by_start[item["start"]]
        try:
            family = _factory_family(row)
        except StageAInputError as error:
            raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
                str(error)
            ) from error
        family_counts[family] += 1
        route_kind = None
        if family == _OWNED_FAMILY:
            route_kind = _validate_external_tail_row(item["id"], row)
        non_x87_rows.append(
            {
                "ordinary_index": ordinary_index,
                "id": item["id"],
                "start": item["start"],
                "stop": item["stop"],
                "family": family,
                "route_kind": route_kind,
            }
        )

    non_x87_rows.sort(
        key=lambda item: (item["start"], item["ordinary_index"])
    )
    fused_position = {
        item["ordinary_index"]: position
        for position, item in enumerate(non_x87_rows)
    }
    owned_rows: list[dict[str, Any]] = []
    residuals: list[dict[str, Any]] = []
    for item in non_x87_rows:
        if item["family"] == _OWNED_FAMILY:
            index = item["ordinary_index"]
            owned_rows.append(
                {
                    **item,
                    "fused_shard_index": (
                        fused_position[index] // spec.fused_shard_size
                    ),
                    "evidence_definition": (
                        "generatedCheckedMixedExternalTailSemanticEvidence"
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
            "route_kind": None,
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
        raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
            "non-x87 and x87 rows do not form an exact input partition"
        )

    sources: dict[str, str] = {}
    shard_modules: list[str] = []
    for shard_start in range(0, len(owned_rows), spec.shard_size):
        shard_rows = owned_rows[shard_start : shard_start + spec.shard_size]
        shard_index = shard_start // spec.shard_size
        module = f"{spec.module_prefix}Shard{shard_index:04d}"
        shard_modules.append(module)
        sources[module] = _shard_source(spec, shard_rows)

    evidence_names = [item["evidence_definition"] for item in owned_rows]
    sources[spec.bundle_module] = _bundle_source(
        spec, shard_modules, evidence_names
    )
    route_counts = Counter(item["route_kind"] for item in owned_rows)
    residual_counts = Counter(item["family"] for item in residuals)
    inventory = {
        "format": GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_FORMAT,
        "proof_authority": False,
        "acceptance_authority": False,
        "classification_authority": False,
        "input_rows": len(materialized),
        "external_tail_rows": len(owned_rows),
        "generated_external_tail_evidence_adapters": len(evidence_names),
        "route_kind_counts": dict(sorted(route_counts.items())),
        "family_counts": dict(sorted(family_counts.items())),
        "unowned_family_counts": dict(sorted(residual_counts.items())),
        "unowned_factory_cases": residuals,
        "runtime_obligations": {
            "rows": len(owned_rows),
            "required_per_row": [
                "exact normalization-bound external call and tail outcome",
                "canonical machine import identity and returning disposition",
                "active caller continuation and exact external-site resolution",
                "one-step PE/CFG operational completeness at every source",
                "call-aware checked interpreter Step derivation",
                "semantic result equality at the computed original exit",
                "exact candidate replay from candidateBefore",
                "checked one-to-one external response trace",
                "pointwise related observations",
                "target mixed invariant",
            ],
        },
        "modules": sorted(sources),
        "target": spec.bundle_module,
        "validation_required": "lean-kernel-check",
        "checked_boundary": {
            "classifier_remains_semantic_transfer": True,
            "semantic_outcome_is_external_jump": True,
            "external_operation_classifier_used": False,
            "external_boundary_classifier_used": False,
            "import_bound_to_canonical_machine_contract": True,
            "original_path_is_definitionally_one_pe_step": True,
            "existing_caller_continuation_is_consumed": True,
            "candidate_path_starts_at_exact_candidate_before_world": True,
            "external_event_trace_checked_separately": True,
            "paths_endpoints_observations_statuses_counts_accepted_from_json": (
                False
            ),
        },
    }
    return GnuHelloMixedExternalTailSemanticEvidenceBundle(
        sources=sources, inventory=inventory
    )


def write_gnu_hello_mixed_external_tail_semantic_evidence(
    out: Path | str,
    bundle: GnuHelloMixedExternalTailSemanticEvidenceBundle,
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
        root / GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_INVENTORY
    )
    inventory_path.write_text(
        json.dumps(bundle.inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return inventory_path, tuple(paths)


def _validate_external_tail_row(
    identity: str, row: Mapping[str, Any]
) -> str:
    events = list(row.get("external_events", []))
    if len(events) != 1:
        raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
            f"semantic row {identity!r} must contain exactly one external "
            "tail event"
        )
    event = events[0]
    if str(event.get("kind", "")) != "external_call":
        raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
            f"semantic row {identity!r} external tail event must have "
            "kind 'external_call'"
        )
    outcome = row.get("outcome")
    if not isinstance(outcome, Mapping) or outcome.get("kind") != (
        "external_jump"
    ):
        raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
            f"semantic row {identity!r} must end in external_jump"
        )
    for field in ("dll", "symbol", "ordinal"):
        if event.get(field) != outcome.get(field):
            raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
                f"semantic row {identity!r} external event and outcome "
                f"differ in {field}"
            )
    instructions = list(row.get("instructions", []))
    if not instructions or not str(
        instructions[-1].get("mnemonic", "")
    ).lower().startswith("jmp"):
        raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
            f"semantic row {identity!r} external tail must end in a jump"
        )
    operand = str(instructions[-1].get("op_str", "")).strip().lower()
    return "direct" if operand.startswith("0x") else "indirect"


def _shard_source(
    spec: GnuHelloMixedExternalTailSemanticEvidenceSpec,
    rows: list[dict[str, Any]],
) -> str:
    fused_modules = sorted({item["fused_shard_index"] for item in rows})
    imports = "\n".join(
        f"import {spec.fused_module_prefix}{index:04d}"
        for index in fused_modules
    )
    definitions = "\n".join(
        _evidence_definition(spec, row) for row in rows
    )
    source = f"""import StageA.RelationalInterpreterMixedExternalTailSemanticEvidenceAdapter
{imports}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedExternalTailSemanticEvidenceAdapter
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
    spec: GnuHelloMixedExternalTailSemanticEvidenceSpec,
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
    {{atSource :
      originalExecutionAtTargetId source.targetId originalBefore}}
    {{candidateBefore : NativeWorldExecution}}
    {{ClassificationEvidence : Prop}}
    {{beforeRelated : invariant.holds originalBefore candidateBefore}}
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
    (static :
      CheckedExternalTailStaticBinding context authority launch root
        reachability staticContext original candidate candidateAuthority source
        ({binding} source contextPeExact contextImportsExact sourceRecordExact
          sourceRvaExact sourceSpanExact))
    (operational : ExactExternalTailOperationalCompleteness source
      ({binding} source contextPeExact contextImportsExact sourceRecordExact
        sourceRvaExact sourceSpanExact)
      static)
    (input : CheckedExternalTailMixedSemanticOperationInput context authority
      launch root reachability staticContext original candidate
      candidateAuthority contract invariant program abi dispatches source
      ({binding} source contextPeExact contextImportsExact sourceRecordExact
        sourceRvaExact sourceSpanExact)
      static operational entryRva originalBefore atSource candidateBefore
      ClassificationEvidence beforeRelated classified environment
      resolveCodeTarget) :
    CheckedMixedSemanticOperationEvidence original candidate candidateAuthority
      contract invariant program abi dispatches source.source.target.rva
      source.record .interpreterStep entryRva originalBefore candidateBefore
      ClassificationEvidence beforeRelated classified :=
  input.toEvidence
"""


def _bundle_source(
    spec: GnuHelloMixedExternalTailSemanticEvidenceSpec,
    modules: list[str],
    evidence: list[str],
) -> str:
    imports = "\n".join(f"import StageA.{module}" for module in modules)
    evidence_inventory = ",\n  ".join(f'"{name}"' for name in evidence)
    source = f"""{imports}

namespace {spec.namespace}

def generatedGnuHelloExternalTailSemanticEvidenceNames : List String := [
  {evidence_inventory}
]

theorem generatedGnuHelloExternalTailSemanticEvidenceNameCount :
    generatedGnuHelloExternalTailSemanticEvidenceNames.length =
      {len(evidence)} := by
  decide

end {spec.namespace}
"""
    _reject_forbidden_source(source)
    return source


def _reject_forbidden_source(source: str) -> None:
    for forbidden in ("sorry", "native_decide", "axiom ", "unsafe "):
        if forbidden in source:
            raise GnuHelloMixedExternalTailSemanticEvidenceGenerationError(
                "generated source unexpectedly contains "
                f"{forbidden.strip()}"
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
    "GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_BUNDLE",
    "GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_FORMAT",
    "GNU_HELLO_MIXED_EXTERNAL_TAIL_SEMANTIC_EVIDENCE_INVENTORY",
    "GnuHelloMixedExternalTailSemanticEvidenceBundle",
    "GnuHelloMixedExternalTailSemanticEvidenceGenerationError",
    "GnuHelloMixedExternalTailSemanticEvidenceSpec",
    "generate_gnu_hello_mixed_external_tail_semantic_evidence",
    "write_gnu_hello_mixed_external_tail_semantic_evidence",
]
