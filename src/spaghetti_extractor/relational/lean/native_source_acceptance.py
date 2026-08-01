"""Generate environment-family native-source acceptance and axiom audits.

Final acceptance is parameterized by an explicit relation on both external
environments.  The generator consumes one static ``ExactNativeCompilation``
and a checked admitted-pair evidence package; it cannot assemble a final
theorem from a project or machine authority that hides one fixed response
schedule.

The old fixed-environment launch-family theorem remains available through the
explicitly named intermediate API at the bottom of this module.  It is useful
while producing one member of the environment family, but it is not the final
native-source acceptance target.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


NATIVE_SOURCE_ACCEPTANCE_MODULE = "GeneratedNativeSourceAcceptance"
NATIVE_SOURCE_ACCEPTANCE_AUDIT_MODULE = (
    "GeneratedNativeSourceAcceptanceAudit"
)
NATIVE_SOURCE_FIXED_ENVIRONMENT_INTERMEDIATE_MODULE = (
    "GeneratedNativeSourceFixedEnvironmentIntermediate"
)
NATIVE_SOURCE_FIXED_ENVIRONMENT_INTERMEDIATE_AUDIT_MODULE = (
    "GeneratedNativeSourceFixedEnvironmentIntermediateAudit"
)

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
        "variable",
        "where",
        "with",
    }
)


class NativeSourceAcceptanceGenerationError(StageAInputError):
    """A native-source acceptance request is malformed or ambiguous."""


@dataclass(frozen=True)
class NativeSourceAcceptanceSpec:
    """Checked declarations comprising admitted environment-family acceptance."""

    imports: tuple[str, ...]
    context: str
    sites: str
    static_compilation: str
    static_authority: str
    pair_relation: str
    admitted_pair_evidence: str
    toolchain_correct: str
    namespace: str = "StageA.GeneratedRelational.NativeSourceAcceptance"
    output_module: str = NATIVE_SOURCE_ACCEPTANCE_MODULE
    audit_output_module: str = NATIVE_SOURCE_ACCEPTANCE_AUDIT_MODULE
    compilation_name: str = "generatedStaticExactNativeCompilation"
    pair_relation_name: str = "GeneratedPairRelated"
    environment_family_name: str = (
        "generatedCheckedNativeSourceAdmittedEnvironmentFamily"
    )
    theorem_name: str = (
        "generatedNativeSourceWholeProgramEnvironmentFamilyEquivalence"
    )

    def validate(self) -> None:
        _validate_spec(
            self,
            local_fields={
                "output_module",
                "audit_output_module",
                "compilation_name",
                "pair_relation_name",
                "environment_family_name",
                "theorem_name",
            },
            generated_names=(
                self.compilation_name,
                self.pair_relation_name,
                self.environment_family_name,
                self.theorem_name,
            ),
        )


@dataclass(frozen=True)
class NativeSourceFixedEnvironmentIntermediateSpec:
    """Compatibility assembly for one fixed-environment intermediate lemma.

    The result has type
    ``ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence``.  It cannot
    authorize environment-family acceptance and deliberately uses distinct
    module, declaration, and theorem names.
    """

    imports: tuple[str, ...]
    profile: str
    project: str
    artifact: str
    machine_authority: str
    source_family: str
    project_valid: str
    profile_pinned: str
    profile_matches: str
    built_from: str
    launch_realizable: str
    namespace: str = (
        "StageA.GeneratedRelational.NativeSourceFixedEnvironmentIntermediate"
    )
    output_module: str = NATIVE_SOURCE_FIXED_ENVIRONMENT_INTERMEDIATE_MODULE
    audit_output_module: str = (
        NATIVE_SOURCE_FIXED_ENVIRONMENT_INTERMEDIATE_AUDIT_MODULE
    )
    compilation_name: str = "generatedFixedEnvironmentExactNativeCompilation"
    source_family_name: str = (
        "generatedFixedEnvironmentCheckedNativeSourceLaunchFamily"
    )
    theorem_name: str = "generatedFixedEnvironmentLaunchFamilyIntermediate"
    toolchain_hypothesis_name: str = "fixedEnvironmentToolchainCorrect"

    def validate(self) -> None:
        _validate_spec(
            self,
            local_fields={
                "output_module",
                "audit_output_module",
                "compilation_name",
                "source_family_name",
                "theorem_name",
                "toolchain_hypothesis_name",
            },
            generated_names=(
                self.compilation_name,
                self.source_family_name,
                self.theorem_name,
                self.toolchain_hypothesis_name,
            ),
        )


def _validate_spec(
    spec: object,
    *,
    local_fields: set[str],
    generated_names: tuple[str, ...],
) -> None:
    imports = getattr(spec, "imports")
    if not isinstance(imports, tuple) or not imports:
        raise NativeSourceAcceptanceGenerationError(
            "imports must be a non-empty tuple of canonical StageA modules"
        )
    if len(set(imports)) != len(imports):
        raise NativeSourceAcceptanceGenerationError(
            "imports must not contain duplicates"
        )
    for module in imports:
        if not _valid_stage_a_module(module):
            raise NativeSourceAcceptanceGenerationError(
                "imports must contain canonical StageA modules"
            )

    for field in fields(spec):
        if field.name == "imports":
            continue
        value = getattr(spec, field.name)
        if field.name in local_fields:
            valid = _valid_local_name(value)
            expected = "a canonical local Lean identifier"
        else:
            valid = _valid_identifier(value)
            expected = "a canonical Lean declaration"
        if not valid:
            raise NativeSourceAcceptanceGenerationError(
                f"{field.name} must be {expected}"
            )

    if getattr(spec, "output_module") == getattr(spec, "audit_output_module"):
        raise NativeSourceAcceptanceGenerationError(
            "acceptance and audit output modules must be distinct"
        )
    if len(set(generated_names)) != len(generated_names):
        raise NativeSourceAcceptanceGenerationError(
            "generated declaration names must be distinct"
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


def native_source_acceptance_source(
    spec: NativeSourceAcceptanceSpec,
) -> str:
    """Emit deterministic final environment-family acceptance assembly."""

    spec.validate()
    modules = sorted(
        {*spec.imports, "StageA.RelationalNativeSourceEnvironmentFamilyEvidence"}
    )
    imports = "\n".join(f"import {module}" for module in modules)
    return f"""{imports}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge
open StageA.Relational.NativeSource

noncomputable section

/-- Re-export the exact static compilation.  Operational environments are
retargeted only after a proof that the pair is admitted. -/
abbrev {spec.compilation_name} : ExactNativeCompilation :=
  {spec.static_compilation}

abbrev {spec.pair_relation_name}
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) : Prop :=
  {spec.pair_relation} sourceEnvironment nativeEnvironment

/-- Assemble the relation-indexed evidence package.  Nonvacuity, exact
external evidence, and both launch families are carried by one checked value. -/
def {spec.environment_family_name} :
    CheckedNativeSourceAdmittedEnvironmentFamily {spec.context} {spec.sites}
      {spec.compilation_name} {spec.pair_relation_name} := {{
  staticAuthority := {spec.static_authority}
  admittedPairs := {spec.admitted_pair_evidence}
  toolchainCorrectAt := {spec.toolchain_correct}
}}

/-- Final conditional whole-program equivalence for every checked pair of
source and native external response schedules. -/
theorem {spec.theorem_name} :
    ExactRawOriginalPECompiledArtifactAdmittedEnvironmentFamilyEquivalence
      {spec.context} {spec.sites} {spec.compilation_name}
        {spec.pair_relation_name} :=
  compiledArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    {spec.environment_family_name}

end

end {spec.namespace}
"""


def native_source_acceptance_axiom_audit_source(
    spec: NativeSourceAcceptanceSpec,
) -> str:
    """Emit the separate audit for the environment-family theorem."""

    spec.validate()
    theorem = f"{spec.namespace}.{spec.theorem_name}"
    return f"import StageA.{spec.output_module}\n\n#print axioms {theorem}\n"


def write_native_source_acceptance(
    out: Path | str, spec: NativeSourceAcceptanceSpec
) -> tuple[Path, Path]:
    """Write final environment-family acceptance below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    acceptance = stage_a / f"{spec.output_module}.lean"
    audit = stage_a / f"{spec.audit_output_module}.lean"
    acceptance.write_text(
        native_source_acceptance_source(spec), encoding="ascii"
    )
    audit.write_text(
        native_source_acceptance_axiom_audit_source(spec), encoding="ascii"
    )
    return acceptance, audit


def native_source_fixed_environment_intermediate_source(
    spec: NativeSourceFixedEnvironmentIntermediateSpec,
) -> str:
    """Emit one fixed-environment launch-family intermediate lemma."""

    spec.validate()
    modules = sorted({*spec.imports, "StageA.RelationalNativeSource"})
    imports = "\n".join(f"import {module}" for module in modules)
    return f"""{imports}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.SourceWorld
open StageA.Relational.NativeSource

noncomputable section

/-- One fixed-environment exact compilation.  This is intermediate evidence
only and cannot authorize environment-family acceptance. -/
def {spec.compilation_name} : ExactNativeCompilation := {{
  profile := {spec.profile}
  project := {spec.project}
  artifact := {spec.artifact}
  machineAuthority := {spec.machine_authority}
  projectValid := {spec.project_valid}
  profilePinned := {spec.profile_pinned}
  profileMatches := {spec.profile_matches}
  builtFrom := {spec.built_from}
}}

def {spec.source_family_name} :
    CheckedNativeSourceLaunchFamily {spec.compilation_name}.project :=
  {spec.source_family}

/-- Per-environment lemma for use when constructing a checked environment
family.  This proposition is not the final acceptance target. -/
theorem {spec.theorem_name}
    ({spec.toolchain_hypothesis_name} :
      CorrectPinnedNativeSourceStackHypothesis {spec.compilation_name}) :
    ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence
      {spec.compilation_name} :=
  compiledArtifactLaunchFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    {spec.compilation_name} {spec.source_family_name}
    {spec.launch_realizable} {spec.toolchain_hypothesis_name}

end

end {spec.namespace}
"""


def native_source_fixed_environment_intermediate_axiom_audit_source(
    spec: NativeSourceFixedEnvironmentIntermediateSpec,
) -> str:
    """Emit an audit for the explicitly intermediate fixed theorem."""

    spec.validate()
    theorem = f"{spec.namespace}.{spec.theorem_name}"
    return f"import StageA.{spec.output_module}\n\n#print axioms {theorem}\n"


def write_native_source_fixed_environment_intermediate(
    out: Path | str, spec: NativeSourceFixedEnvironmentIntermediateSpec
) -> tuple[Path, Path]:
    """Write fixed-environment intermediate modules below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    acceptance = stage_a / f"{spec.output_module}.lean"
    audit = stage_a / f"{spec.audit_output_module}.lean"
    acceptance.write_text(
        native_source_fixed_environment_intermediate_source(spec),
        encoding="ascii",
    )
    audit.write_text(
        native_source_fixed_environment_intermediate_axiom_audit_source(spec),
        encoding="ascii",
    )
    return acceptance, audit


__all__ = [
    "NATIVE_SOURCE_ACCEPTANCE_AUDIT_MODULE",
    "NATIVE_SOURCE_ACCEPTANCE_MODULE",
    "NATIVE_SOURCE_FIXED_ENVIRONMENT_INTERMEDIATE_AUDIT_MODULE",
    "NATIVE_SOURCE_FIXED_ENVIRONMENT_INTERMEDIATE_MODULE",
    "NativeSourceAcceptanceGenerationError",
    "NativeSourceAcceptanceSpec",
    "NativeSourceFixedEnvironmentIntermediateSpec",
    "native_source_acceptance_axiom_audit_source",
    "native_source_acceptance_source",
    "native_source_fixed_environment_intermediate_axiom_audit_source",
    "native_source_fixed_environment_intermediate_source",
    "write_native_source_acceptance",
    "write_native_source_fixed_environment_intermediate",
]
