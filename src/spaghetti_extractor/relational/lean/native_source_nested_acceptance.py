"""Generate callback-capable native-source acceptance and axiom audits.

The generated acceptance module combines a checked protocol-response family,
its checked completion, and exactly one pinned compiler-stack theorem.  The
response family remains the authority for admissible environment pairs;
Python status fields and diagnostic inventories cannot authorize acceptance.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .native_source_acceptance import (
    NativeSourceAcceptanceGenerationError,
    _validate_spec,
)


NATIVE_SOURCE_NESTED_ACCEPTANCE_MODULE = (
    "GeneratedNativeSourceNestedAcceptance"
)
NATIVE_SOURCE_NESTED_ACCEPTANCE_AUDIT_MODULE = (
    "GeneratedNativeSourceNestedAcceptanceAudit"
)


@dataclass(frozen=True)
class NativeSourceNestedAcceptanceSpec:
    """Checked declarations comprising callback-capable final acceptance."""

    imports: tuple[str, ...]
    context: str
    classified_sites: str
    ordinary_sites: str
    static_compilation: str
    mixed_contract: str
    nested_frames: str
    checked_response_family: str
    checked_response_family_completion: str
    toolchain_correct: str
    namespace: str = (
        "StageA.GeneratedRelational.NativeSourceNestedAcceptance"
    )
    output_module: str = NATIVE_SOURCE_NESTED_ACCEPTANCE_MODULE
    audit_output_module: str = NATIVE_SOURCE_NESTED_ACCEPTANCE_AUDIT_MODULE
    compilation_name: str = "generatedStaticExactNativeCompilation"
    response_family_name: str = "generatedCheckedProtocolResponseFamily"
    pair_relation_name: str = "GeneratedNestedPairRelated"
    environment_family_name: str = (
        "generatedCheckedNestedNativeSourceAdmittedEnvironmentFamily"
    )
    theorem_name: str = (
        "generatedNativeSourceNestedWholeProgramEnvironmentFamilyEquivalence"
    )

    def validate(self) -> None:
        _validate_spec(
            self,
            local_fields={
                "output_module",
                "audit_output_module",
                "compilation_name",
                "response_family_name",
                "pair_relation_name",
                "environment_family_name",
                "theorem_name",
            },
            generated_names=(
                self.compilation_name,
                self.response_family_name,
                self.pair_relation_name,
                self.environment_family_name,
                self.theorem_name,
            ),
        )


def native_source_nested_acceptance_source(
    spec: NativeSourceNestedAcceptanceSpec,
) -> str:
    """Emit deterministic callback-capable final acceptance assembly."""

    spec.validate()
    modules = sorted(
        {
            *spec.imports,
            "StageA.RelationalNativeSourceNestedAdmittedResponseFamily",
        }
    )
    imports = "\n".join(f"import {module}" for module in modules)
    return f"""{imports}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.NativeSource

noncomputable section

/-- Re-export the exact static compilation used by the checked response
family.  No runtime response schedule is selected by this module. -/
abbrev {spec.compilation_name} : ExactNativeCompilation :=
  {spec.static_compilation}

/-- Checked callback/protocol evidence.  Its `Related` predicate remains the
authority for admitted source/native response-environment pairs. -/
abbrev {spec.response_family_name} :
    CheckedWorldNativeAdmittedProtocolResponseFamily {spec.context}
      {spec.classified_sites} {spec.ordinary_sites} {spec.compilation_name}
        {spec.mixed_contract} {spec.nested_frames} :=
  {spec.checked_response_family}

abbrev {spec.pair_relation_name}
    (sourceEnvironment : SourceWorldResponseEnvironment)
    (nativeEnvironment : NativeWorldResponseEnvironment) : Prop :=
  {spec.response_family_name}.Related sourceEnvironment nativeEnvironment

/-- Assemble the nested evidence package.  The checked family supplies pair
realizability, exact response evidence, and launch families.  The one separate
premise is correctness of the pinned compiler stack for each admitted pair. -/
def {spec.environment_family_name} :
    CheckedNestedNativeSourceAdmittedEnvironmentFamily {spec.context}
      {spec.classified_sites} {spec.ordinary_sites} {spec.compilation_name}
        {spec.mixed_contract} {spec.nested_frames} {spec.pair_relation_name} :=
  {spec.response_family_name}.toNestedAcceptance
    {spec.checked_response_family_completion} {spec.toolchain_correct}

/-- Final conditional whole-program equivalence over the callback-capable
compiled carrier for every checked response-environment pair. -/
theorem {spec.theorem_name} :
    ExactRawOriginalPENestedCompiledArtifactAdmittedEnvironmentFamilyEquivalence
      {spec.context} {spec.classified_sites} {spec.ordinary_sites}
        {spec.compilation_name} {spec.mixed_contract} {spec.nested_frames}
          {spec.pair_relation_name} :=
  compiledNestedArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    {spec.environment_family_name}

end

end {spec.namespace}
"""


def native_source_nested_acceptance_axiom_audit_source(
    spec: NativeSourceNestedAcceptanceSpec,
) -> str:
    """Emit the detached audit for the nested environment-family theorem."""

    spec.validate()
    theorem = f"{spec.namespace}.{spec.theorem_name}"
    return f"import StageA.{spec.output_module}\n\n#print axioms {theorem}\n"


def write_native_source_nested_acceptance(
    out: Path | str, spec: NativeSourceNestedAcceptanceSpec
) -> tuple[Path, Path]:
    """Write nested final acceptance below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    acceptance = stage_a / f"{spec.output_module}.lean"
    audit = stage_a / f"{spec.audit_output_module}.lean"
    acceptance.write_text(
        native_source_nested_acceptance_source(spec), encoding="ascii"
    )
    audit.write_text(
        native_source_nested_acceptance_axiom_audit_source(spec),
        encoding="ascii",
    )
    return acceptance, audit


__all__ = [
    "NATIVE_SOURCE_NESTED_ACCEPTANCE_AUDIT_MODULE",
    "NATIVE_SOURCE_NESTED_ACCEPTANCE_MODULE",
    "NativeSourceAcceptanceGenerationError",
    "NativeSourceNestedAcceptanceSpec",
    "native_source_nested_acceptance_axiom_audit_source",
    "native_source_nested_acceptance_source",
    "write_native_source_nested_acceptance",
]
