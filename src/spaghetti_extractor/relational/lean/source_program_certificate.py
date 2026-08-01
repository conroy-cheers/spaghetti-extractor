"""Generate exact-bound active-target source-program certificates.

The generator is intentionally data-only.  It assembles transition equalities
proved by imported Lean modules, binds the resulting finite index to one
``ExactBinding``, and derives rooted-domain coverage from a checked target
inventory.  It never invents a transition equality from Python analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


SOURCE_PROGRAM_CERTIFICATE_MODULE = "GeneratedSourceProgramCertificate"

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
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
        "namespace",
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


class SourceProgramCertificateGenerationError(StageAInputError):
    """A source-program certificate request is malformed or incomplete."""


@dataclass(frozen=True)
class ActiveTargetCertificateSpec:
    """Checked exact-bound declarations for one stable target identifier."""

    target_id: int
    selection_exact: str
    local_effect_exact: str

    def validate(self) -> None:
        if not isinstance(self.target_id, int) or isinstance(self.target_id, bool):
            raise SourceProgramCertificateGenerationError(
                "target_id must be a non-negative integer"
            )
        if self.target_id < 0:
            raise SourceProgramCertificateGenerationError(
                "target_id must be a non-negative integer"
            )
        for name, value in (
            ("selection_exact", self.selection_exact),
            ("local_effect_exact", self.local_effect_exact),
        ):
            if not _valid_identifier(value):
                raise SourceProgramCertificateGenerationError(
                    f"{name} must be a canonical Lean declaration"
                )


@dataclass(frozen=True)
class SourceProgramCertificateSpec:
    """Stable declarations used to assemble one exact source certificate."""

    imports: tuple[str, ...]
    program: str
    exact_binding: str
    domain: str
    target_inventory: str
    target_inventory_exact: str
    target_inventory_nodup: str
    running_target_member: str
    callback_target_member: str
    target_ids: tuple[int, ...]
    targets: tuple[ActiveTargetCertificateSpec, ...]
    namespace: str = "StageA.GeneratedRelational.SourceProgramCertificate"
    output_module: str = SOURCE_PROGRAM_CERTIFICATE_MODULE
    target_inventory_name: str = "generatedActiveTargetIds"
    target_inventory_nodup_name: str = "generatedActiveTargetIdsNodup"
    index_name: str = "generatedActiveTargetTransitionIndex"
    exact_bound_index_name: str = (
        "generatedExactBoundActiveTargetTransitionIndex"
    )
    index_targets_exact_name: str = "generatedActiveTargetIdsExact"
    coverage_name: str = "generatedActiveTargetDomainCoverage"
    step_matches_name: str = (
        "generatedProgramRecordKernelMatchesDecodedSemantics"
    )

    def validate(self) -> None:
        if not self.imports:
            raise SourceProgramCertificateGenerationError(
                "imports must contain at least one StageA module"
            )
        if len(set(self.imports)) != len(self.imports):
            raise SourceProgramCertificateGenerationError(
                "imports must not contain duplicates"
            )
        for module in self.imports:
            if not _valid_stage_a_module(module):
                raise SourceProgramCertificateGenerationError(
                    "imports must contain canonical StageA modules"
                )

        local_fields = {
            "output_module",
            "target_inventory_name",
            "target_inventory_nodup_name",
            "index_name",
            "exact_bound_index_name",
            "index_targets_exact_name",
            "coverage_name",
            "step_matches_name",
        }
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name in {"imports", "target_ids", "targets"}:
                continue
            if field.name in local_fields:
                valid = _valid_local_name(value)
                expected = "a canonical local Lean identifier"
            else:
                valid = _valid_identifier(value)
                expected = "a canonical Lean identifier"
            if not valid:
                raise SourceProgramCertificateGenerationError(
                    f"{field.name} must be {expected}"
                )

        generated_names = [
            getattr(self, name) for name in local_fields - {"output_module"}
        ]
        if len(set(generated_names)) != len(generated_names):
            raise SourceProgramCertificateGenerationError(
                "generated declaration names must be distinct"
            )

        for target in self.targets:
            if not isinstance(target, ActiveTargetCertificateSpec):
                raise SourceProgramCertificateGenerationError(
                    "targets must contain ActiveTargetCertificateSpec values"
                )
            target.validate()

        if any(
            not isinstance(target_id, int) or isinstance(target_id, bool)
            for target_id in self.target_ids
        ):
            raise SourceProgramCertificateGenerationError(
                "target_ids must contain non-negative integers"
            )
        if any(target_id < 0 for target_id in self.target_ids):
            raise SourceProgramCertificateGenerationError(
                "target_ids must contain non-negative integers"
            )
        if tuple(sorted(self.target_ids)) != self.target_ids:
            raise SourceProgramCertificateGenerationError(
                "target_ids must be in deterministic ascending order"
            )
        if len(set(self.target_ids)) != len(self.target_ids):
            raise SourceProgramCertificateGenerationError(
                "target_ids must not contain duplicates"
            )

        submitted_ids = tuple(target.target_id for target in self.targets)
        if len(set(submitted_ids)) != len(submitted_ids):
            raise SourceProgramCertificateGenerationError(
                "targets must not contain duplicate target identifiers"
            )
        if set(submitted_ids) != set(self.target_ids):
            missing = sorted(set(self.target_ids) - set(submitted_ids))
            unexpected = sorted(set(submitted_ids) - set(self.target_ids))
            raise SourceProgramCertificateGenerationError(
                "targets must exactly cover target_ids "
                f"(missing={missing}, unexpected={unexpected})"
            )


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


def _lean_nat_list(values: tuple[int, ...]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def source_program_certificate_source(
    spec: SourceProgramCertificateSpec,
) -> str:
    """Emit a deterministic exact-bound transition index and coverage proof."""

    spec.validate()
    targets_by_id = {target.target_id: target for target in spec.targets}
    ordered_targets = [targets_by_id[target_id] for target_id in spec.target_ids]

    equality_names = [
        f"generatedExactBoundTargetStepEquality_{target.target_id}"
        for target in ordered_targets
    ]
    certificate_names = [
        f"generatedActiveTargetTransitionCertificate_{target.target_id}"
        for target in ordered_targets
    ]
    certificates = []
    for target, equality_name, name in zip(
        ordered_targets, equality_names, certificate_names, strict=True
    ):
        certificates.append(
            f"""def {equality_name} :
    ExactBoundTargetStepEquality {spec.exact_binding} {target.target_id} :=
  ExactBoundTargetStepEquality.ofSelectionAndRouting
    {target.selection_exact}
    (TargetLocalEffectExact.toWorldRoutingExact {target.local_effect_exact})

def {name} : ActiveTargetTransitionCertificate {spec.exact_binding} :=
  ActiveTargetTransitionCertificate.ofExactBound {equality_name}"""
        )

    certificate_list = "[" + ", ".join(certificate_names) + "]"
    certificate_reductions = ", ".join(
        [
            *certificate_names,
            *equality_names,
            "ActiveTargetTransitionCertificate.ofExactBound",
            "ExactBoundTargetStepEquality.ofSelectionAndRouting",
        ]
    )
    target_list = _lean_nat_list(spec.target_ids)
    imports = "\n".join(
        [*(f"import {module}" for module in spec.imports),
         "import StageA.RelationalSourceProgramCertificate"]
    )
    certificate_source = "\n\n".join(certificates)
    return f"""{imports}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

set_option maxRecDepth 100000

noncomputable section

{certificate_source}

def {spec.target_inventory_name} : List Nat := {target_list}

theorem {spec.target_inventory_nodup_name} :
    {spec.target_inventory_name}.Nodup := by
  have authoritative := {spec.target_inventory_nodup}
  rw [{spec.target_inventory_exact}] at authoritative
  simpa [{spec.target_inventory_name}] using authoritative

def {spec.index_name} :
    ActiveTargetTransitionIndex {spec.exact_binding} := {{
  certificates := {certificate_list}
  targetIdsUnique := by
    simpa [{spec.target_inventory_name}, {certificate_reductions}] using
      {spec.target_inventory_nodup_name}
}}

/-- The transition index and exact source binding are one acceptance artifact.
The index proves equality against decoded PE semantics; the binding proves the
ProgramRecord and x87 inventories came from that exact PE. -/
def {spec.exact_bound_index_name} :
    ExactBoundActiveTargetTransitionIndex {spec.exact_binding} := {{
  index := {spec.index_name}
}}

/-- Fail closed if the supplied rooted-reachability inventory omitted or added
an active target relative to the generated certificates. -/
theorem {spec.index_targets_exact_name} :
    {spec.index_name}.certificates.map
        (fun certificate => certificate.targetId) =
      {spec.target_inventory} := by
  simpa [{spec.index_name}, {spec.target_inventory_name},
    {certificate_reductions}] using {spec.target_inventory_exact}.symm

def {spec.coverage_name} :
    ActiveTargetDomainCoverage {spec.index_name} {spec.domain} :=
  ActiveTargetDomainCoverage.ofTargetMembership
    {spec.index_name} {spec.domain} {spec.target_inventory}
    {spec.index_targets_exact_name} {spec.running_target_member}
    {spec.callback_target_member}

theorem {spec.step_matches_name} :
    ProgramRecordKernelMatchesDecodedSemantics {spec.program} {spec.domain} :=
  programRecordKernelMatchesDecodedSemantics_of_checkedTargets
    {spec.index_name} {spec.domain} {spec.coverage_name}

#print axioms {spec.index_targets_exact_name}
#print axioms {spec.step_matches_name}

end
end {spec.namespace}
"""


def write_source_program_certificate(
    out: Path | str, spec: SourceProgramCertificateSpec
) -> Path:
    """Write the generated source certificate below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = stage_a / f"{spec.output_module}.lean"
    destination.write_text(
        source_program_certificate_source(spec), encoding="ascii"
    )
    return destination


__all__ = [
    "SOURCE_PROGRAM_CERTIFICATE_MODULE",
    "ActiveTargetCertificateSpec",
    "SourceProgramCertificateGenerationError",
    "SourceProgramCertificateSpec",
    "source_program_certificate_source",
    "write_source_program_certificate",
]
