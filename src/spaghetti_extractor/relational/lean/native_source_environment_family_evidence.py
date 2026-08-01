"""Generate checked environment-family evidence for native-source acceptance.

The generated Lean module retargets one exact static source compilation across
the source/native environment pairs admitted by one explicit relation.  It
does not invent external semantics: a caller must provide a nonempty relation
and machine-level ``ExactWorldNativeExternalEvidence`` for every admitted pair.

Exactly one semantic assumption is emitted, under the explicit local name
``pinnedCompilerLoweringCorrect``.  It represents correctness of the complete
pinned renderer/lowering/runtime/compiler/assembler/linker/ABI stack.  All
source launch, compiled launch, static binding, and external evidence remains
ordinary Lean declarations and is required fail-closed at generation time.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


NATIVE_SOURCE_ENVIRONMENT_FAMILY_EVIDENCE_MODULE = (
    "GeneratedNativeSourceEnvironmentFamilyEvidence"
)
NATIVE_SOURCE_ENVIRONMENT_FAMILY_EVIDENCE_AUDIT_MODULE = (
    "GeneratedNativeSourceEnvironmentFamilyEvidenceAudit"
)
NATIVE_SOURCE_ACCEPTANCE_DECLARATIONS_FORMAT = (
    "stage-a-gnu-hello-native-source-acceptance-declarations-v3"
)
NATIVE_SOURCE_ENVIRONMENT_FAMILY_AXIOM_EXPECTATION_FORMAT = (
    "stage-a-native-source-environment-family-axiom-expectation-v1"
)

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


class NativeSourceEnvironmentFamilyEvidenceGenerationError(StageAInputError):
    """Environment-family evidence is malformed or under-specified."""


@dataclass(frozen=True)
class NativeSourceAcceptanceBindings:
    """Literal provenance checked again by the acceptance driver."""

    compiled_authority_manifest_sha256: str
    source_bundle_sha256: str
    attestation_core_sha256: str
    candidate_sha256: str
    source_entry_rva: int
    compiled_entry_rva: int

    def validate(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if field.name.endswith("_sha256"):
                if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
                    raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
                        f"{field.name} must be a lowercase SHA-256 digest"
                    )
            elif not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
                    f"{field.name} must be a non-negative integer"
                )

    def as_json(self) -> dict[str, str | int]:
        self.validate()
        return {field.name: getattr(self, field.name) for field in fields(self)}


@dataclass(frozen=True)
class NativeSourceEnvironmentFamilyEvidenceSpec:
    """Lean declarations needed to construct a nonempty environment family.

    ``pair_relation`` and ``pair_realizable`` define which environment pairs
    the fixture admits.  ``external_evidence_at`` must establish exact
    machine-level external evidence for every admitted pair; equality or an
    unqualified identity relation is not accepted as a substitute.
    """

    imports: tuple[str, ...]
    context: str
    sites: str
    static_compilation: str
    static_authority: str
    pair_relation: str
    pair_realizable: str
    external_evidence_at: str
    source_family_at: str
    launch_realizable_at: str
    acceptance_bindings: NativeSourceAcceptanceBindings

    namespace: str = (
        "StageA.GeneratedRelational.NativeSourceEnvironmentFamilyEvidence"
    )
    output_module: str = NATIVE_SOURCE_ENVIRONMENT_FAMILY_EVIDENCE_MODULE
    audit_output_module: str = (
        NATIVE_SOURCE_ENVIRONMENT_FAMILY_EVIDENCE_AUDIT_MODULE
    )
    static_compilation_name: str = "staticCompilation"
    pair_relation_name: str = "PairRelated"
    admitted_pair_evidence_name: str = "admittedPairEvidence"
    toolchain_axiom_name: str = "pinnedCompilerLoweringCorrect"

    acceptance_namespace: str = (
        "StageA.GeneratedRelational.NativeSourceAcceptance"
    )
    acceptance_output_module: str = "GeneratedNativeSourceAcceptance"
    acceptance_audit_output_module: str = (
        "GeneratedNativeSourceAcceptanceAudit"
    )
    acceptance_compilation_name: str = "generatedStaticExactNativeCompilation"
    acceptance_family_name: str = (
        "generatedCheckedNativeSourceAdmittedEnvironmentFamily"
    )
    acceptance_theorem_name: str = (
        "generatedNativeSourceWholeProgramEnvironmentFamilyEquivalence"
    )

    def validate(self) -> None:
        if not isinstance(self.imports, tuple) or not self.imports:
            raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
                "imports must be a non-empty tuple of canonical StageA modules"
            )
        if len(set(self.imports)) != len(self.imports):
            raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
                "imports must not contain duplicates"
            )
        for module in self.imports:
            _validate_stage_a_module(module, "import")

        declaration_fields = {
            "context",
            "sites",
            "static_compilation",
            "static_authority",
            "pair_relation",
            "pair_realizable",
            "external_evidence_at",
            "source_family_at",
            "launch_realizable_at",
            "namespace",
            "acceptance_namespace",
        }
        local_fields = {
            "output_module",
            "audit_output_module",
            "static_compilation_name",
            "pair_relation_name",
            "admitted_pair_evidence_name",
            "toolchain_axiom_name",
            "acceptance_output_module",
            "acceptance_audit_output_module",
            "acceptance_compilation_name",
            "acceptance_family_name",
            "acceptance_theorem_name",
        }
        for name in declaration_fields:
            _validate_identifier(getattr(self, name), name)
        for name in local_fields:
            _validate_local_name(getattr(self, name), name)
        generated = tuple(
            getattr(self, name)
            for name in (
                "static_compilation_name",
                "pair_relation_name",
                "admitted_pair_evidence_name",
                "toolchain_axiom_name",
            )
        )
        if len(set(generated)) != len(generated):
            raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
                "generated evidence declaration names must be distinct"
            )
        if self.output_module == self.audit_output_module:
            raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
                "evidence and audit output modules must be distinct"
            )
        if self.acceptance_output_module == self.acceptance_audit_output_module:
            raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
                "acceptance and audit output modules must be distinct"
            )
        if self.toolchain_axiom_name != "pinnedCompilerLoweringCorrect":
            raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
                "the sole toolchain axiom must be named "
                "pinnedCompilerLoweringCorrect"
            )
        self.acceptance_bindings.validate()


def _validate_identifier(value: object, label: str) -> None:
    if not (
        isinstance(value, str)
        and _LEAN_IDENTIFIER.fullmatch(value) is not None
        and all(
            part.casefold() not in _FORBIDDEN_NAME_PARTS
            for part in value.split(".")
        )
    ):
        raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
            f"{label} must be a canonical Lean declaration"
        )


def _validate_local_name(value: object, label: str) -> None:
    if not (
        isinstance(value, str)
        and _LOCAL_NAME.fullmatch(value) is not None
        and value.casefold() not in _FORBIDDEN_NAME_PARTS
    ):
        raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
            f"{label} must be a canonical local Lean identifier"
        )


def _validate_stage_a_module(value: object, label: str) -> None:
    if not (
        isinstance(value, str)
        and _STAGE_A_MODULE.fullmatch(value) is not None
        and all(
            part.casefold() not in _FORBIDDEN_NAME_PARTS
            for part in value.split(".")
        )
    ):
        raise NativeSourceEnvironmentFamilyEvidenceGenerationError(
            f"{label} must be a canonical StageA module"
        )


def native_source_environment_family_evidence_source(
    spec: NativeSourceEnvironmentFamilyEvidenceSpec,
) -> str:
    """Emit deterministic admitted-pair evidence and one named axiom."""

    spec.validate()
    modules = sorted(
        {
            *spec.imports,
            "StageA.RelationalNativeSourceEnvironmentFamilyEvidence",
        }
    )
    imports = "\n".join(f"import {module}" for module in modules)
    return f"""{imports}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge
open StageA.Relational.NativeSource

noncomputable section

abbrev {spec.static_compilation_name} : ExactNativeCompilation :=
  {spec.static_compilation}

abbrev {spec.pair_relation_name}
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) : Prop :=
  {spec.pair_relation} sourceEnvironment nativeEnvironment

/-- Nonvacuity, exact external evidence, source launch coverage, and compiled
launch realizability share one checked admission witness. -/
def {spec.admitted_pair_evidence_name} :
    CheckedNativeSourceAdmittedPairEvidence {spec.context} {spec.sites}
      {spec.static_compilation_name} {spec.pair_relation_name} := {{
  pairRealizable := {spec.pair_realizable}
  externalEvidenceAt := {spec.external_evidence_at}
  sourceFamilyAt := {spec.source_family_at}
  launchRealizableAt := {spec.launch_realizable_at}
}}

/-- Sole admitted semantic assumption: the complete pinned compiler/lowering
stack correctly implements every checked corresponding environment pair. -/
axiom {spec.toolchain_axiom_name} :
    forall sourceEnvironment nativeEnvironment,
      {spec.pair_relation_name} sourceEnvironment nativeEnvironment ->
      CorrectPinnedNativeSourceStackHypothesis
        (exactNativeCompilationAtEnvironments {spec.static_compilation_name}
          sourceEnvironment nativeEnvironment)

end

end {spec.namespace}
"""


def native_source_environment_family_evidence_audit_source(
    spec: NativeSourceEnvironmentFamilyEvidenceSpec,
) -> str:
    """Emit a detached audit for all exported family evidence."""

    spec.validate()
    declarations = (
        spec.static_compilation_name,
        spec.pair_relation_name,
        spec.admitted_pair_evidence_name,
        spec.toolchain_axiom_name,
    )
    lines = "\n".join(
        f"#print axioms {spec.namespace}.{name}" for name in declarations
    )
    return f"import StageA.{spec.output_module}\n\n{lines}\n"


def native_source_acceptance_declarations(
    spec: NativeSourceEnvironmentFamilyEvidenceSpec,
) -> dict[str, object]:
    """Return the exact v2 declaration schema consumed by the driver."""

    spec.validate()
    module = f"StageA.{spec.output_module}"
    return {
        "format": NATIVE_SOURCE_ACCEPTANCE_DECLARATIONS_FORMAT,
        "bindings": spec.acceptance_bindings.as_json(),
        "lean": {
            "imports": [module],
            "context": spec.context,
            "sites": spec.sites,
            "static_compilation": (
                f"{spec.namespace}.{spec.static_compilation_name}"
            ),
            "static_authority": spec.static_authority,
            "pair_relation": f"{spec.namespace}.{spec.pair_relation_name}",
            "admitted_pair_evidence": (
                f"{spec.namespace}.{spec.admitted_pair_evidence_name}"
            ),
            "toolchain_correct": (
                f"{spec.namespace}.{spec.toolchain_axiom_name}"
            ),
            "namespace": spec.acceptance_namespace,
            "output_module": spec.acceptance_output_module,
            "audit_output_module": spec.acceptance_audit_output_module,
            "compilation_name": spec.acceptance_compilation_name,
            "environment_family_name": spec.acceptance_family_name,
            "theorem_name": spec.acceptance_theorem_name,
        },
    }


def native_source_environment_family_axiom_expectation(
    spec: NativeSourceEnvironmentFamilyEvidenceSpec,
) -> dict[str, object]:
    """Describe the sole project-specific axiom allowed at final audit."""

    spec.validate()
    pinned = f"{spec.namespace}.{spec.toolchain_axiom_name}"
    return {
        "format": NATIVE_SOURCE_ENVIRONMENT_FAMILY_AXIOM_EXPECTATION_FORMAT,
        "theorem": (
            f"{spec.acceptance_namespace}.{spec.acceptance_theorem_name}"
        ),
        "approved_axioms": [
            "propext",
            "Classical.choice",
            "Quot.sound",
            pinned,
        ],
        "required_axioms": [pinned],
    }


def write_native_source_environment_family_evidence(
    out: Path | str, spec: NativeSourceEnvironmentFamilyEvidenceSpec
) -> tuple[Path, Path, Path, Path]:
    """Write Lean evidence, detached audit, and driver/audit JSON inputs."""

    spec.validate()
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    evidence_path = stage_a / f"{spec.output_module}.lean"
    audit_path = stage_a / f"{spec.audit_output_module}.lean"
    declarations_path = root / "acceptance-declarations.json"
    expectation_path = root / "axiom-audit-expectation.json"
    evidence_path.write_text(
        native_source_environment_family_evidence_source(spec), encoding="ascii"
    )
    audit_path.write_text(
        native_source_environment_family_evidence_audit_source(spec),
        encoding="ascii",
    )
    declarations_path.write_text(
        json.dumps(
            native_source_acceptance_declarations(spec),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    expectation_path.write_text(
        json.dumps(
            native_source_environment_family_axiom_expectation(spec),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    return evidence_path, audit_path, declarations_path, expectation_path
