"""Generate GNU hello's exact one-sided source transition index.

The producer is a strict artifact assembler.  JSON manifests establish that
the mixed-original carrier, source program, ordinary normalization, and x87
schedule artifacts came from one state-machine generation.  A separate Lean
declaration inventory names the checked facts used to build each target
certificate.  Python never promotes a report status or an analysis claim into
proof authority.

Generated target shards contain only adapters from
``CheckedOrdinaryTargetEffect`` or ``ExactX87SingletonTargetFacts`` to the
stable source-program certificate interfaces.  The aggregate module binds the
source program to the concrete mixed-original ``DecodedWorldProgram`` and
exports an exact, duplicate-free ``ActiveTargetTransitionIndex``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from spaghetti_extractor.artifact_formats import SOURCE_TRANSITION_DECLARATIONS_FORMAT
from spaghetti_extractor.errors import StageAInputError


GNU_HELLO_SOURCE_TRANSITION_DECLARATIONS_FORMAT = SOURCE_TRANSITION_DECLARATIONS_FORMAT
GNU_HELLO_SOURCE_TRANSITION_OUTPUT_FORMAT = (
    "stage-a-gnu-hello-source-transition-index-v1"
)
GNU_HELLO_SOURCE_TRANSITION_MODULE = "GeneratedGnuHelloSourceTransitionIndex"
GNU_HELLO_SOURCE_TRANSITION_DATA_MODULE = (
    "GeneratedGnuHelloSourceTransitionIndexData"
)
GNU_HELLO_SOURCE_TRANSITION_AUDIT_MODULE = (
    "GeneratedGnuHelloSourceTransitionIndexAudit"
)

_MIXED_ORIGINAL_FORMAT = "stage-a-interpreter-mixed-original-v1"
_PHASE_FORMAT = "stage-a-relational-phase-v1"
_NORMALIZATION_FORMAT = (
    "stage-a-relational-interpreter-normalization-inventory-v1"
)
_SOURCE_PROGRAM_PHASE = "semantic-program-lean"
_X87_PHASE = "x87-lean"

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FORBIDDEN_NAME_PARTS = frozenset(
    {
        "admit",
        "axiom",
        "by",
        "def",
        "else",
        "end",
        "import",
        "in",
        "inductive",
        "instance",
        "let",
        "match",
        "native_decide",
        "opaque",
        "partial",
        "protected",
        "sorry",
        "structure",
        "theorem",
        "then",
        "unsafe",
        "where",
        "with",
    }
)

TargetKind = Literal["ordinary", "x87"]


class GnuHelloSourceTransitionIndexError(StageAInputError):
    """The source transition-index request is incomplete or inconsistent."""


@dataclass(frozen=True)
class LeanDeclaration:
    module: str
    declaration: str

    @classmethod
    def from_json(cls, value: object, label: str) -> "LeanDeclaration":
        row = _object(value, label)
        _exact_keys(row, {"module", "declaration"}, label)
        result = cls(
            module=_string(row["module"], f"{label}.module"),
            declaration=_string(row["declaration"], f"{label}.declaration"),
        )
        result.validate(label)
        return result

    def validate(self, label: str) -> None:
        if not _valid_stage_a_module(self.module):
            raise GnuHelloSourceTransitionIndexError(
                f"{label}.module must be a canonical StageA module"
            )
        if not _valid_identifier(self.declaration):
            raise GnuHelloSourceTransitionIndexError(
                f"{label}.declaration must be a canonical Lean declaration"
            )


@dataclass(frozen=True)
class OrdinaryTargetEvidence:
    binding: LeanDeclaration
    checked_effect: LeanDeclaration
    record: LeanDeclaration
    record_member: LeanDeclaration
    not_x87: LeanDeclaration

    @classmethod
    def from_json(cls, value: object, label: str) -> "OrdinaryTargetEvidence":
        row = _object(value, label)
        names = {"binding", "checked_effect", "record", "record_member", "not_x87"}
        _exact_keys(row, names, label)
        return cls(
            **{
                name: LeanDeclaration.from_json(row[name], f"{label}.{name}")
                for name in sorted(names)
            }
        )

    @property
    def imports(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    self.binding.module,
                    self.checked_effect.module,
                    self.record.module,
                    self.record_member.module,
                    self.not_x87.module,
                }
            )
        )


@dataclass(frozen=True)
class X87TargetEvidence:
    facts: LeanDeclaration

    @classmethod
    def from_json(cls, value: object, label: str) -> "X87TargetEvidence":
        row = _object(value, label)
        _exact_keys(row, {"facts"}, label)
        return cls(facts=LeanDeclaration.from_json(row["facts"], f"{label}.facts"))

    @property
    def imports(self) -> tuple[str, ...]:
        return (self.facts.module,)


@dataclass(frozen=True)
class TargetEvidence:
    target_id: int
    source_rva: int
    kind: TargetKind
    ordinary: OrdinaryTargetEvidence | None = None
    x87: X87TargetEvidence | None = None

    @classmethod
    def from_json(cls, value: object, label: str) -> "TargetEvidence":
        row = _object(value, label)
        common = {"target_id", "source_rva", "kind", "evidence"}
        _exact_keys(row, common, label)
        target_id = _natural(row["target_id"], f"{label}.target_id")
        source_rva = _natural(row["source_rva"], f"{label}.source_rva", word=True)
        kind = _string(row["kind"], f"{label}.kind")
        if kind == "ordinary":
            return cls(
                target_id=target_id,
                source_rva=source_rva,
                kind="ordinary",
                ordinary=OrdinaryTargetEvidence.from_json(
                    row["evidence"], f"{label}.evidence"
                ),
            )
        if kind == "x87":
            return cls(
                target_id=target_id,
                source_rva=source_rva,
                kind="x87",
                x87=X87TargetEvidence.from_json(
                    row["evidence"], f"{label}.evidence"
                ),
            )
        raise GnuHelloSourceTransitionIndexError(
            f"{label}.kind must be ordinary or x87"
        )

    @property
    def imports(self) -> tuple[str, ...]:
        if self.kind == "ordinary" and self.ordinary is not None:
            return self.ordinary.imports
        if self.kind == "x87" and self.x87 is not None:
            return self.x87.imports
        raise GnuHelloSourceTransitionIndexError(
            f"target {self.target_id} lacks exact {self.kind} effect evidence"
        )


@dataclass(frozen=True)
class TransitionIndexDeclarations:
    imports: tuple[str, ...]
    world_program: LeanDeclaration
    original_pe: LeanDeclaration
    original_side: LeanDeclaration
    original_pe_exact: LeanDeclaration
    source_program_constructor: LeanDeclaration
    instruction_semantics_adequate: LeanDeclaration
    exact_binding_constructor: LeanDeclaration
    target_inventory: LeanDeclaration
    target_inventory_unique: LeanDeclaration
    submitted_target_ids_exact: LeanDeclaration
    targets: tuple[TargetEvidence, ...]
    namespace: str
    module_prefix: str
    shard_span: int

    @classmethod
    def from_json(cls, value: object) -> "TransitionIndexDeclarations":
        row = _object(value, "declaration inventory")
        names = {
            "format",
            "imports",
            "world_program",
            "original_pe",
            "original_side",
            "original_pe_exact",
            "source_program_constructor",
            "instruction_semantics_adequate",
            "exact_binding_constructor",
            "target_inventory",
            "target_inventory_unique",
            "submitted_target_ids_exact",
            "targets",
            "namespace",
            "module_prefix",
            "shard_span",
        }
        _exact_keys(row, names, "declaration inventory")
        if row["format"] != GNU_HELLO_SOURCE_TRANSITION_DECLARATIONS_FORMAT:
            raise GnuHelloSourceTransitionIndexError(
                "unsupported source transition declaration inventory format"
            )
        imports_value = _list(row["imports"], "imports")
        imports = tuple(_string(value, "imports[]") for value in imports_value)
        targets_value = _list(row["targets"], "targets")
        result = cls(
            imports=imports,
            world_program=LeanDeclaration.from_json(
                row["world_program"], "world_program"
            ),
            original_pe=LeanDeclaration.from_json(row["original_pe"], "original_pe"),
            original_side=LeanDeclaration.from_json(
                row["original_side"], "original_side"
            ),
            original_pe_exact=LeanDeclaration.from_json(
                row["original_pe_exact"], "original_pe_exact"
            ),
            source_program_constructor=LeanDeclaration.from_json(
                row["source_program_constructor"], "source_program_constructor"
            ),
            instruction_semantics_adequate=LeanDeclaration.from_json(
                row["instruction_semantics_adequate"],
                "instruction_semantics_adequate",
            ),
            exact_binding_constructor=LeanDeclaration.from_json(
                row["exact_binding_constructor"], "exact_binding_constructor"
            ),
            target_inventory=LeanDeclaration.from_json(
                row["target_inventory"], "target_inventory"
            ),
            target_inventory_unique=LeanDeclaration.from_json(
                row["target_inventory_unique"], "target_inventory_unique"
            ),
            submitted_target_ids_exact=LeanDeclaration.from_json(
                row["submitted_target_ids_exact"], "submitted_target_ids_exact"
            ),
            targets=tuple(
                TargetEvidence.from_json(target, f"targets[{index}]")
                for index, target in enumerate(targets_value)
            ),
            namespace=_string(row["namespace"], "namespace"),
            module_prefix=_string(row["module_prefix"], "module_prefix"),
            shard_span=_natural(row["shard_span"], "shard_span"),
        )
        result.validate()
        return result

    def validate(self) -> None:
        if not self.imports:
            raise GnuHelloSourceTransitionIndexError("imports must not be empty")
        if len(set(self.imports)) != len(self.imports):
            raise GnuHelloSourceTransitionIndexError("imports must not contain duplicates")
        for module in self.imports:
            if not _valid_stage_a_module(module):
                raise GnuHelloSourceTransitionIndexError(
                    "imports must contain canonical StageA modules"
                )
        if not _valid_identifier(self.namespace):
            raise GnuHelloSourceTransitionIndexError(
                "namespace must be a canonical Lean namespace"
            )
        if not _valid_local_name(self.module_prefix):
            raise GnuHelloSourceTransitionIndexError(
                "module_prefix must be a canonical local identifier"
            )
        if self.shard_span <= 0:
            raise GnuHelloSourceTransitionIndexError("shard_span must be positive")
        if not self.targets:
            raise GnuHelloSourceTransitionIndexError(
                "targets must contain exact effect evidence"
            )
        target_ids = tuple(target.target_id for target in self.targets)
        if target_ids != tuple(sorted(target_ids)):
            raise GnuHelloSourceTransitionIndexError(
                "targets must be in deterministic target-id order"
            )
        if len(set(target_ids)) != len(target_ids):
            raise GnuHelloSourceTransitionIndexError(
                "targets must not contain duplicate target identifiers"
            )
        source_rvas = tuple(target.source_rva for target in self.targets)
        if len(set(source_rvas)) != len(source_rvas):
            raise GnuHelloSourceTransitionIndexError(
                "targets must not contain duplicate source RVAs"
            )
        for target in self.targets:
            target.imports


@dataclass(frozen=True)
class GeneratedTransitionIndex:
    modules: tuple[Path, ...]
    audit: Path
    manifest: Path
    target_count: int
    ordinary_count: int
    x87_count: int


def _valid_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and _LEAN_IDENTIFIER.fullmatch(value) is not None
        and all(
            part.casefold() not in _FORBIDDEN_NAME_PARTS
            for part in value.split(".")
        )
    )


def _valid_local_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and _LOCAL_NAME.fullmatch(value) is not None
        and value.casefold() not in _FORBIDDEN_NAME_PARTS
    )


def _valid_stage_a_module(value: object) -> bool:
    return (
        isinstance(value, str)
        and _STAGE_A_MODULE.fullmatch(value) is not None
        and all(
            part.casefold() not in _FORBIDDEN_NAME_PARTS
            for part in value.split(".")
        )
    )


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GnuHelloSourceTransitionIndexError(f"{label} must be an object")
    return value


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GnuHelloSourceTransitionIndexError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GnuHelloSourceTransitionIndexError(
            f"{label} must be a non-empty string"
        )
    return value


def _natural(value: object, label: str, *, word: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GnuHelloSourceTransitionIndexError(
            f"{label} must be a non-negative integer"
        )
    if word and value > 0xFFFFFFFF:
        raise GnuHelloSourceTransitionIndexError(f"{label} must fit in 32 bits")
    return value


def _exact_keys(row: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(row)
    if actual != expected:
        raise GnuHelloSourceTransitionIndexError(
            f"{label} fields differ (missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)})"
        )


def _load(path: Path | str, label: str) -> tuple[Path, dict[str, Any]]:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GnuHelloSourceTransitionIndexError(
            f"cannot read {label}: {error}"
        ) from error
    return source, _object(value, label)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest_state_machine_hash(row: dict[str, Any], label: str) -> str:
    inputs = _object(row.get("inputs"), f"{label}.inputs")
    state_machine = _object(
        inputs.get("state_machine"), f"{label}.inputs.state_machine"
    )
    digest = _string(
        state_machine.get("sha256"), f"{label}.inputs.state_machine.sha256"
    )
    if _SHA256.fullmatch(digest) is None:
        raise GnuHelloSourceTransitionIndexError(
            f"{label} state-machine hash must be lowercase SHA-256"
        )
    return digest


def _validate_manifests(
    mixed: dict[str, Any],
    source_program: dict[str, Any],
    normalization: dict[str, Any],
    x87: dict[str, Any],
    declarations: TransitionIndexDeclarations,
) -> tuple[int, ...]:
    if mixed.get("format") != _MIXED_ORIGINAL_FORMAT:
        raise GnuHelloSourceTransitionIndexError(
            "mixed-original manifest has unsupported format"
        )
    if source_program.get("format") != _PHASE_FORMAT or source_program.get(
        "phase"
    ) != _SOURCE_PROGRAM_PHASE:
        raise GnuHelloSourceTransitionIndexError(
            "source-program manifest has unsupported format or phase"
        )
    if normalization.get("format") != _NORMALIZATION_FORMAT:
        raise GnuHelloSourceTransitionIndexError(
            "normalization manifest has unsupported format"
        )
    if x87.get("format") != _PHASE_FORMAT or x87.get("phase") != _X87_PHASE:
        raise GnuHelloSourceTransitionIndexError(
            "x87 manifest has unsupported format or phase"
        )

    mixed_hash = _string(mixed.get("state_machine_sha256"), "state_machine_sha256")
    hashes = {
        mixed_hash,
        _manifest_state_machine_hash(source_program, "source_program"),
        _manifest_state_machine_hash(x87, "x87"),
    }
    if _SHA256.fullmatch(mixed_hash) is None or len(hashes) != 1:
        raise GnuHelloSourceTransitionIndexError(
            "mixed-original, source-program, and x87 state-machine hashes differ"
        )

    source_counts = _object(source_program.get("counts"), "source_program.counts")
    transfers = _natural(source_counts.get("transfers"), "counts.transfers")
    ordinary = _natural(
        source_counts.get("ordinary_transfers"), "counts.ordinary_transfers"
    )
    x87_count = _natural(source_counts.get("x87_transfers"), "counts.x87_transfers")
    normalized_total = _natural(
        normalization.get("total_transfers"), "normalization.total_transfers"
    )
    ready = _natural(
        normalization.get("ready_for_lean_check"),
        "normalization.ready_for_lean_check",
    )
    blocked = _natural(normalization.get("blocked"), "normalization.blocked")
    if transfers != normalized_total or ordinary != ready or x87_count != blocked:
        raise GnuHelloSourceTransitionIndexError(
            "source-program and normalization structural inventories differ"
        )
    if transfers != ordinary + x87_count:
        raise GnuHelloSourceTransitionIndexError(
            "source-program transfer partition is inconsistent"
        )

    raw_ids = _list(mixed.get("reachable_target_ids"), "reachable_target_ids")
    target_ids = tuple(
        _natural(value, "reachable_target_ids[]") for value in raw_ids
    )
    if target_ids != tuple(sorted(target_ids)) or len(set(target_ids)) != len(
        target_ids
    ):
        raise GnuHelloSourceTransitionIndexError(
            "reachable target inventory must be sorted and unique"
        )
    submitted = tuple(target.target_id for target in declarations.targets)
    if submitted != target_ids:
        missing = sorted(set(target_ids) - set(submitted))
        unexpected = sorted(set(submitted) - set(target_ids))
        raise GnuHelloSourceTransitionIndexError(
            "exact effect declarations must cover every reachable target "
            f"(missing={missing}, unexpected={unexpected})"
        )
    return target_ids


def _lean_nat_list(values: tuple[int, ...]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def _data_source(spec: TransitionIndexDeclarations) -> str:
    imports = sorted(
        {
            *spec.imports,
            spec.world_program.module,
            spec.original_pe.module,
            spec.original_side.module,
            spec.original_pe_exact.module,
            spec.source_program_constructor.module,
            spec.instruction_semantics_adequate.module,
            spec.exact_binding_constructor.module,
            spec.target_inventory.module,
            spec.target_inventory_unique.module,
            spec.submitted_target_ids_exact.module,
        }
    )
    return f"""{chr(10).join(f'import {module}' for module in imports)}
import StageA.RelationalSourceInterpreterKernel

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.SourceWorld.InterpreterKernel

noncomputable section

abbrev generatedExactMixedOriginalWorldProgram : DecodedWorldProgram :=
  {spec.world_program.declaration}

abbrev generatedExactSourceProgram : Program :=
  {spec.source_program_constructor.declaration}
    generatedExactMixedOriginalWorldProgram

theorem generatedInstructionSemanticsAdequate :
    generatedExactSourceProgram.worldProgram.InstructionSemanticsAdequate :=
  {spec.instruction_semantics_adequate.declaration}

def generatedConcreteExactBinding :
    ExactBinding {spec.original_pe.declaration} generatedExactSourceProgram :=
  {spec.exact_binding_constructor.declaration}
    generatedExactMixedOriginalWorldProgram
    {spec.original_side.declaration}
    {spec.original_pe_exact.declaration}

abbrev generatedExactReachableTargetInventory : List Nat :=
  {spec.target_inventory.declaration}

end
end {spec.namespace}
"""


def _target_names(target_id: int) -> tuple[str, str, str, str]:
    return (
        f"generatedBoundTargetSelection_{target_id}",
        f"generatedTargetLocalEffectExact_{target_id}",
        f"generatedExactBoundTargetStepEquality_{target_id}",
        f"generatedActiveTargetTransitionCertificate_{target_id}",
    )


def _target_source(spec: TransitionIndexDeclarations, target: TargetEvidence) -> str:
    selection, local_effect, equality, certificate = _target_names(target.target_id)
    if target.kind == "ordinary":
        if target.ordinary is None:
            raise GnuHelloSourceTransitionIndexError(
                f"target {target.target_id} lacks CheckedOrdinaryTargetEffect evidence"
            )
        evidence = target.ordinary
        selection_body = f"""BoundTargetSelection.ordinary
    {target.source_rva} {evidence.record.declaration}
    {evidence.binding.declaration}.sourceExact
    {evidence.binding.declaration}.classificationExact
    {evidence.binding.declaration}.recordLookupExact
    {evidence.record_member.declaration}
    {evidence.not_x87.declaration}"""
        local_body = (
            f"CheckedOrdinaryTargetEffect.toLocalEffectExact "
            f"{evidence.checked_effect.declaration}"
        )
    else:
        if target.x87 is None:
            raise GnuHelloSourceTransitionIndexError(
                f"target {target.target_id} lacks ExactX87SingletonTargetFacts evidence"
            )
        selection_body = (
            f"ExactX87SingletonTargetFacts.toBoundTargetSelection "
            f"{target.x87.facts.declaration}"
        )
        local_body = (
            f"ExactX87SingletonTargetFacts.toLocalEffectExact "
            f"{target.x87.facts.declaration}"
        )
    return f"""def {selection} :
    BoundTargetSelection generatedExactSourceProgram {target.target_id} :=
  {selection_body}

def {local_effect} :
    TargetLocalEffectExact generatedExactSourceProgram {target.target_id} :=
  {local_body}

def {equality} :
    ExactBoundTargetStepEquality generatedConcreteExactBinding
      {target.target_id} :=
  ExactBoundTargetStepEquality.ofSelectionAndRouting {selection}
    (TargetLocalEffectExact.toWorldRoutingExact {local_effect})

def {certificate} :
    ActiveTargetTransitionCertificate generatedConcreteExactBinding :=
  ActiveTargetTransitionCertificate.ofExactBound {equality}"""


def _shard_source(
    spec: TransitionIndexDeclarations,
    module_name: str,
    targets: tuple[TargetEvidence, ...],
) -> str:
    imports = sorted({module for target in targets for module in target.imports})
    bodies = "\n\n".join(_target_source(spec, target) for target in targets)
    return f"""import StageA.{GNU_HELLO_SOURCE_TRANSITION_DATA_MODULE}
{chr(10).join(f'import {module}' for module in imports)}
import StageA.RelationalSourceOrdinaryTargetRouting
import StageA.RelationalSourceProgramCertificate
import StageA.RelationalSourceX87TargetRouting

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting
open StageA.Relational.SourceWorld.ProgramCertificate

noncomputable section

{bodies}

end
end {spec.namespace}
"""


def _aggregate_source(
    spec: TransitionIndexDeclarations,
    target_ids: tuple[int, ...],
    shard_modules: tuple[str, ...],
) -> str:
    certificate_names = [
        f"generatedActiveTargetTransitionCertificate_{target_id}"
        for target_id in target_ids
    ]
    certificate_list = "[" + ", ".join(certificate_names) + "]"
    target_list = _lean_nat_list(target_ids)
    return f"""{chr(10).join(f'import StageA.{module}' for module in shard_modules)}
import StageA.RelationalSourceProgramCertificate

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

noncomputable section

def generatedSubmittedTargetIds : List Nat := {target_list}

theorem generatedSubmittedTargetIdsExact :
    generatedSubmittedTargetIds = generatedExactReachableTargetInventory := by
  simpa only [generatedSubmittedTargetIds,
    generatedExactReachableTargetInventory] using
      {spec.submitted_target_ids_exact.declaration}

def generatedActiveTargetTransitionIndex :
    ActiveTargetTransitionIndex generatedConcreteExactBinding := {{
  certificates := {certificate_list}
  targetIdsUnique := by
    have inventoryUnique : generatedExactReachableTargetInventory.Nodup := by
      simpa only [generatedExactReachableTargetInventory] using
        {spec.target_inventory_unique.declaration}
    rw [<- generatedSubmittedTargetIdsExact] at inventoryUnique
    simpa only [generatedSubmittedTargetIds,
      {', '.join(certificate_names)},
      ActiveTargetTransitionCertificate.ofExactBound,
      ExactBoundTargetStepEquality.ofSelectionAndRouting] using inventoryUnique
}}

theorem generatedActiveTargetIdsExact :
    generatedActiveTargetTransitionIndex.certificates.map
        (fun certificate => certificate.targetId) =
      generatedExactReachableTargetInventory := by
  simpa only [generatedActiveTargetTransitionIndex,
    generatedSubmittedTargetIds,
    {', '.join(certificate_names)},
    ActiveTargetTransitionCertificate.ofExactBound,
    ExactBoundTargetStepEquality.ofSelectionAndRouting] using
      generatedSubmittedTargetIdsExact

#print axioms generatedConcreteExactBinding
#print axioms generatedActiveTargetIdsExact

end
end {spec.namespace}
"""


def _audit_source(spec: TransitionIndexDeclarations) -> str:
    return f"""import StageA.{GNU_HELLO_SOURCE_TRANSITION_MODULE}

#print axioms {spec.namespace}.generatedInstructionSemanticsAdequate
#print axioms {spec.namespace}.generatedConcreteExactBinding
#print axioms {spec.namespace}.generatedActiveTargetTransitionIndex
#print axioms {spec.namespace}.generatedActiveTargetIdsExact
"""


def _write_ascii(path: Path, source: str) -> None:
    path.write_text(source, encoding="ascii")


def generate_gnu_hello_source_transition_index(
    out: Path | str,
    *,
    mixed_original_manifest: Path | str,
    source_program_manifest: Path | str,
    normalization_manifest: Path | str,
    x87_manifest: Path | str,
    declaration_inventory: Path | str,
) -> GeneratedTransitionIndex:
    """Validate all inputs and generate the exact transition-index modules."""

    mixed_path, mixed = _load(mixed_original_manifest, "mixed-original manifest")
    source_path, source = _load(source_program_manifest, "source-program manifest")
    normalization_path, normalization = _load(
        normalization_manifest, "normalization manifest"
    )
    x87_path, x87 = _load(x87_manifest, "x87 manifest")
    declarations_path, declarations_json = _load(
        declaration_inventory, "declaration inventory"
    )
    declarations = TransitionIndexDeclarations.from_json(declarations_json)
    target_ids = _validate_manifests(
        mixed, source, normalization, x87, declarations
    )

    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    modules: list[Path] = []

    data_path = stage_a / f"{GNU_HELLO_SOURCE_TRANSITION_DATA_MODULE}.lean"
    _write_ascii(data_path, _data_source(declarations))
    modules.append(data_path)

    buckets: dict[int, list[TargetEvidence]] = {}
    for target in declarations.targets:
        buckets.setdefault(target.target_id // declarations.shard_span, []).append(
            target
        )
    shard_names: list[str] = []
    for bucket, targets in sorted(buckets.items()):
        module_name = f"{declarations.module_prefix}Shard{bucket:06d}"
        shard_names.append(module_name)
        path = stage_a / f"{module_name}.lean"
        _write_ascii(
            path,
            _shard_source(declarations, module_name, tuple(targets)),
        )
        modules.append(path)

    aggregate_path = stage_a / f"{GNU_HELLO_SOURCE_TRANSITION_MODULE}.lean"
    _write_ascii(
        aggregate_path,
        _aggregate_source(declarations, target_ids, tuple(shard_names)),
    )
    modules.append(aggregate_path)

    audit_path = stage_a / f"{GNU_HELLO_SOURCE_TRANSITION_AUDIT_MODULE}.lean"
    _write_ascii(audit_path, _audit_source(declarations))

    input_paths = {
        "mixed_original_manifest": mixed_path,
        "source_program_manifest": source_path,
        "normalization_manifest": normalization_path,
        "x87_manifest": x87_path,
        "declaration_inventory": declarations_path,
    }
    ordinary_count = sum(target.kind == "ordinary" for target in declarations.targets)
    x87_count = sum(target.kind == "x87" for target in declarations.targets)
    manifest_path = Path(out) / "source-transition-index.json"
    manifest = {
        "format": GNU_HELLO_SOURCE_TRANSITION_OUTPUT_FORMAT,
        "executes_original_binary": False,
        "executes_candidate_binary": False,
        "inputs": {
            name: {"path": path.name, "sha256": _sha256(path)}
            for name, path in sorted(input_paths.items())
        },
        "counts": {
            "targets": len(target_ids),
            "ordinary": ordinary_count,
            "x87": x87_count,
            "shards": len(shard_names),
        },
        "modules": [path.stem for path in modules],
        "audit_module": audit_path.stem,
        "exports": {
            "exact_source_program": (
                f"{declarations.namespace}.generatedExactSourceProgram"
            ),
            "instruction_semantics_adequate": (
                f"{declarations.namespace}.generatedInstructionSemanticsAdequate"
            ),
            "concrete_exact_binding": (
                f"{declarations.namespace}.generatedConcreteExactBinding"
            ),
            "active_target_transition_index": (
                f"{declarations.namespace}.generatedActiveTargetTransitionIndex"
            ),
            "active_target_ids_exact": (
                f"{declarations.namespace}.generatedActiveTargetIdsExact"
            ),
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )
    return GeneratedTransitionIndex(
        modules=tuple(modules),
        audit=audit_path,
        manifest=manifest_path,
        target_count=len(target_ids),
        ordinary_count=ordinary_count,
        x87_count=x87_count,
    )


__all__ = [
    "GNU_HELLO_SOURCE_TRANSITION_AUDIT_MODULE",
    "GNU_HELLO_SOURCE_TRANSITION_DATA_MODULE",
    "GNU_HELLO_SOURCE_TRANSITION_DECLARATIONS_FORMAT",
    "GNU_HELLO_SOURCE_TRANSITION_MODULE",
    "GNU_HELLO_SOURCE_TRANSITION_OUTPUT_FORMAT",
    "GeneratedTransitionIndex",
    "GnuHelloSourceTransitionIndexError",
    "LeanDeclaration",
    "OrdinaryTargetEvidence",
    "TargetEvidence",
    "TransitionIndexDeclarations",
    "X87TargetEvidence",
    "generate_gnu_hello_source_transition_index",
]
