"""Generate checked indirect/import-call mixed semantic evidence adapters.

The generator owns only rows whose exact semantic transfer contains one
non-immediate call. Each generated definition reuses the row's fused exact
normalization binding and the generic indirect/import-call adapter.

The JSON inventory is diagnostic. Generated Lean accepts no path fuel,
endpoint, observation list, status, or completion count.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from ...errors import StageAInputError
from .gnu_hello_mixed_fused_semantic_evidence import _factory_family
from .interpreter_normalization import (
    _is_x87_row,
    _ordinary_items,
    _validated_row,
)


GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_FORMAT = (
    "stage-a-gnu-hello-mixed-indirect-import-call-semantic-evidence-v1"
)
GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_BUNDLE = (
    "GeneratedGnuHelloMixedIndirectImportCallSemanticEvidenceBundle"
)
GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_INVENTORY = (
    "gnu-hello-mixed-indirect-import-call-semantic-evidence.json"
)

_OWNED_FAMILY = "dedicated-indirect-or-import-call"
_CALL_KINDS = frozenset({"external_call", "internal_call", "indirect_call"})
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


class GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
    StageAInputError
):
    """The source inventory or generated Lean naming scheme is malformed."""


@dataclass(frozen=True)
class GnuHelloMixedIndirectImportCallSemanticEvidenceSpec:
    """Stable generated-module and theorem naming inputs."""

    fused_module_prefix: str = (
        "StageA.GeneratedGnuHelloMixedFusedSemanticEvidenceShard"
    )
    namespace: str = "StageA.GeneratedRelational"
    module_prefix: str = (
        "GeneratedGnuHelloMixedIndirectImportCallSemanticEvidence"
    )
    bundle_module: str = (
        GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_BUNDLE
    )
    fused_binding_prefix: str = (
        "StageA.GeneratedRelational."
        "generatedCheckedFusedOriginalSemanticBinding"
    )
    record_prefix: str = (
        "StageA.GeneratedRelational.semanticInterpreterProgramRecord"
    )
    fused_shard_size: int = 48
    shard_size: int = 24

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.fused_module_prefix) is None:
            raise (
                GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                    "fused_module_prefix must be a canonical StageA module "
                    "prefix"
                )
            )
        for field, value in (
            ("namespace", self.namespace),
            ("fused_binding_prefix", self.fused_binding_prefix),
            ("record_prefix", self.record_prefix),
        ):
            if not _valid_identifier(value):
                raise (
                    GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                        f"{field} must be a canonical Lean identifier"
                    )
                )
        for field, value in (
            ("module_prefix", self.module_prefix),
            ("bundle_module", self.bundle_module),
        ):
            if not _valid_local_identifier(value):
                raise (
                    GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                        f"{field} must be a canonical Lean local identifier"
                    )
                )
        if self.fused_shard_size <= 0:
            raise (
                GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                    "fused_shard_size must be positive"
                )
            )
        if self.shard_size <= 0:
            raise (
                GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                    "shard_size must be positive"
                )
            )


@dataclass(frozen=True)
class GnuHelloMixedIndirectImportCallSemanticEvidenceBundle:
    """Generated Lean sources plus a non-authoritative residual inventory."""

    sources: Mapping[str, str]
    inventory: Mapping[str, Any]


def generate_gnu_hello_mixed_indirect_import_call_semantic_evidence(
    rows: Iterable[Mapping[str, Any]],
    spec: GnuHelloMixedIndirectImportCallSemanticEvidenceSpec | None = None,
) -> GnuHelloMixedIndirectImportCallSemanticEvidenceBundle:
    spec = spec or GnuHelloMixedIndirectImportCallSemanticEvidenceSpec()
    spec.validate()
    materialized = [dict(row) for row in rows]
    validated = [_validated_row(row) for row in materialized]
    try:
        ordinary = _ordinary_items(materialized)
    except StageAInputError as error:
        raise (
            GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                str(error)
            )
        ) from error

    row_by_start = {item["start"]: item["row"] for item in validated}
    if len(row_by_start) != len(validated):
        raise GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
            "semantic source RVAs must be unique"
        )

    non_x87_rows: list[dict[str, Any]] = []
    family_counts: Counter[str] = Counter()
    for ordinary_index, item in ordinary:
        row = row_by_start[item["start"]]
        try:
            family = _factory_family(row)
        except StageAInputError as error:
            raise (
                GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                    str(error)
                )
            ) from error
        family_counts[family] += 1
        call_kind = None
        if family == _OWNED_FAMILY:
            calls = [
                instruction
                for instruction in row.get("instructions", [])
                if str(instruction.get("mnemonic", ""))
                .lower()
                .startswith("call")
            ]
            if len(calls) != 1:
                raise (
                    GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                        f"semantic row {item['id']!r} must contain exactly "
                        "one non-immediate call"
                    )
                )
            events = list(row.get("external_events", []))
            if len(events) != 1:
                raise (
                    GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                        f"semantic row {item['id']!r} must contain exactly "
                        "one semantic call event"
                    )
                )
            call_kind = str(events[0].get("kind", ""))
            if call_kind not in _CALL_KINDS:
                raise (
                    GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                        f"semantic row {item['id']!r} has unsupported call "
                        f"kind {call_kind!r}"
                    )
                )
        non_x87_rows.append(
            {
                "ordinary_index": ordinary_index,
                "id": item["id"],
                "start": item["start"],
                "stop": item["stop"],
                "family": family,
                "call_kind": call_kind,
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
                        "generatedCheckedMixedIndirectImportCallSemanticEvidence"
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
            "call_kind": None,
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
        raise GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
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

    evidence_names = [
        item["evidence_definition"] for item in owned_rows
    ]
    sources[spec.bundle_module] = _bundle_source(
        spec, shard_modules, evidence_names
    )
    call_kind_counts = Counter(
        item["call_kind"] for item in owned_rows
    )
    residual_counts = Counter(item["family"] for item in residuals)
    inventory = {
        "format": (
            GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_FORMAT
        ),
        "proof_authority": False,
        "acceptance_authority": False,
        "classification_authority": False,
        "input_rows": len(materialized),
        "indirect_import_call_rows": len(owned_rows),
        "generated_indirect_import_call_evidence_adapters": len(
            evidence_names
        ),
        "semantic_call_kind_counts": dict(sorted(call_kind_counts.items())),
        "family_counts": dict(sorted(family_counts.items())),
        "unowned_family_counts": dict(sorted(residual_counts.items())),
        "unowned_factory_cases": residuals,
        "runtime_obligations": {
            "rows": len(owned_rows),
            "required_per_row": [
                "exact normalization-bound semantic call and call boundary",
                "checked import, internal-code, or finite indirect route",
                "PE/CFG operational completeness at every actual source",
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
            "semantic_call_bound_to_exact_normalized_pe_span": True,
            "call_boundary_bound_to_exact_decoded_instruction": True,
            "indirect_targets_use_generic_checked_provenance": True,
            "imports_use_checked_machine_and_site_contracts": True,
            "original_path_selected_by_operational_completeness": True,
            "candidate_path_starts_at_exact_candidate_before_world": True,
            "external_event_trace_checked_separately": True,
            "paths_endpoints_observations_statuses_accepted_from_json": False,
        },
    }
    return GnuHelloMixedIndirectImportCallSemanticEvidenceBundle(
        sources=sources, inventory=inventory
    )


def write_gnu_hello_mixed_indirect_import_call_semantic_evidence(
    out: Path | str,
    bundle: GnuHelloMixedIndirectImportCallSemanticEvidenceBundle,
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
        root
        / GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_INVENTORY
    )
    inventory_path.write_text(
        json.dumps(bundle.inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return inventory_path, tuple(paths)


def _shard_source(
    spec: GnuHelloMixedIndirectImportCallSemanticEvidenceSpec,
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
    source = f"""import StageA.RelationalInterpreterMixedIndirectImportCallSemanticEvidenceAdapter
{imports}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedFusedSemanticEvidenceAdapter
open StageA.Relational.InterpreterMixedIndirectImportCallSemanticEvidenceAdapter
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
    spec: GnuHelloMixedIndirectImportCallSemanticEvidenceSpec,
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
    {{sourceInvariant : StateInvariant}}
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
      CheckedIndirectOrImportCallStaticBinding context authority launch root
        reachability staticContext sourceInvariant original candidate
        candidateAuthority source
        ({binding} source contextPeExact contextImportsExact sourceRecordExact
          sourceRvaExact sourceSpanExact))
    (operational :
      ExactIndirectOrImportCallOperationalCompleteness original source.targetId)
    (input : CheckedIndirectOrImportMixedSemanticOperationInput context
      authority launch root reachability staticContext sourceInvariant original
      candidate candidateAuthority contract invariant program abi dispatches
      source
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
    spec: GnuHelloMixedIndirectImportCallSemanticEvidenceSpec,
    modules: list[str],
    evidence: list[str],
) -> str:
    imports = "\n".join(f"import StageA.{module}" for module in modules)
    evidence_inventory = ",\n  ".join(f'"{name}"' for name in evidence)
    source = f"""{imports}

namespace {spec.namespace}

def generatedGnuHelloIndirectImportCallSemanticEvidenceNames : List String := [
  {evidence_inventory}
]

theorem generatedGnuHelloIndirectImportCallSemanticEvidenceNameCount :
    generatedGnuHelloIndirectImportCallSemanticEvidenceNames.length =
      {len(evidence)} := by
  decide

end {spec.namespace}
"""
    _reject_forbidden_source(source)
    return source


def _reject_forbidden_source(source: str) -> None:
    for forbidden in ("sorry", "native_decide", "axiom ", "unsafe "):
        if forbidden in source:
            raise (
                GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError(
                    "generated source unexpectedly contains "
                    f"{forbidden.strip()}"
                )
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
    "GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_BUNDLE",
    "GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_FORMAT",
    "GNU_HELLO_MIXED_INDIRECT_IMPORT_CALL_SEMANTIC_EVIDENCE_INVENTORY",
    "GnuHelloMixedIndirectImportCallSemanticEvidenceBundle",
    "GnuHelloMixedIndirectImportCallSemanticEvidenceGenerationError",
    "GnuHelloMixedIndirectImportCallSemanticEvidenceSpec",
    "generate_gnu_hello_mixed_indirect_import_call_semantic_evidence",
    "write_gnu_hello_mixed_indirect_import_call_semantic_evidence",
]
