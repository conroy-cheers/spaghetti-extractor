"""Generate exact compiled-PE authority for native-source acceptance.

The generated static declarations are independent of any concrete launch.
They bind exact Lean-resident content, parsed PE metadata, imports,
relocations, loader checks, the native environment, source-project
provenance, and the pinned toolchain profile.  A small parameterized adapter
is emitted for the currently root-indexed ``ExactNativeCompilation`` API; it
does not select or certify a particular launch.

All semantic and byte facts are imported Lean declarations.  Python only
validates names and literal provenance metadata before assembling dependent
records.  It cannot turn a manifest status into a proof.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


NATIVE_SOURCE_COMPILED_AUTHORITY_MODULE = (
    "GeneratedNativeSourceCompiledAuthority"
)
NATIVE_SOURCE_COMPILED_AUTHORITY_AUDIT_MODULE = (
    "GeneratedNativeSourceCompiledAuthorityAudit"
)

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NAR_HASH = re.compile(r"sha256-(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{44})\Z")
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


class NativeSourceCompiledAuthorityGenerationError(StageAInputError):
    """A compiled-authority request is malformed or under-specified."""


@dataclass(frozen=True)
class NixRealizationSpec:
    """Literal identity for one Nix derivation and realized output."""

    derivation_path: str
    derivation_sha256: str
    output_path: str
    nar_hash: str

    def validate(self, label: str) -> None:
        if not _absolute_path(self.derivation_path) or not self.derivation_path.endswith(
            ".drv"
        ):
            raise NativeSourceCompiledAuthorityGenerationError(
                f"{label} derivation_path must be an absolute .drv path"
            )
        if _SHA256.fullmatch(self.derivation_sha256) is None:
            raise NativeSourceCompiledAuthorityGenerationError(
                f"{label} derivation_sha256 must be lowercase SHA-256"
            )
        if not _absolute_path(self.output_path):
            raise NativeSourceCompiledAuthorityGenerationError(
                f"{label} output_path must be absolute"
            )
        if _NAR_HASH.fullmatch(self.nar_hash) is None:
            raise NativeSourceCompiledAuthorityGenerationError(
                f"{label} nar_hash must be an SRI SHA-256"
            )


@dataclass(frozen=True)
class PinnedToolArtifactSpec:
    """One named tool component tied to exact Lean-resident bytes."""

    identifier: str
    exact_artifact: str

    def validate(self, label: str) -> None:
        _validate_literal(self.identifier, f"{label} identifier")
        _validate_identifier(self.exact_artifact, f"{label} exact_artifact")


@dataclass(frozen=True)
class NativeSourceCompiledAuthoritySpec:
    """All exact declarations needed for root-independent static authority."""

    imports: tuple[str, ...]

    world_program: str
    checked_input: str
    checked_input_nonempty: str
    bundle_manifest_artifact: str
    renderer_input_artifact: str
    source_artifacts: tuple[str, ...]
    source_artifact_roles_nodup: str
    project_nix: NixRealizationSpec

    profile_identifier: str
    profile_nix: NixRealizationSpec
    renderer: PinnedToolArtifactSpec
    lowering: PinnedToolArtifactSpec
    runtime: PinnedToolArtifactSpec
    compiler: PinnedToolArtifactSpec
    assembler: PinnedToolArtifactSpec
    linker: PinnedToolArtifactSpec
    abi: PinnedToolArtifactSpec

    compiled_identity: str
    compiled_identity_valid: str
    compiled_bytes: str
    compiled_pe: str
    compiled_byte_length_exact: str
    compiled_pe_parsed_exact: str
    compiled_pe_bytes_exact: str
    build_nix: NixRealizationSpec

    import_certificate: str
    imports_parsed: str
    relocations: str
    relocations_parsed: str
    loader_image_valid: str
    environment: str
    indirect_targets: str
    indirect_targets_valid: str
    callable_external: str | None = None
    callable_bound: str | None = None

    namespace: str = "StageA.GeneratedRelational.NativeSourceCompiledAuthority"
    output_module: str = NATIVE_SOURCE_COMPILED_AUTHORITY_MODULE
    audit_output_module: str = NATIVE_SOURCE_COMPILED_AUTHORITY_AUDIT_MODULE
    project_nix_name: str = "generatedNativeSourceProjectNixIdentity"
    profile_nix_name: str = "generatedNativeSourceProfileNixIdentity"
    build_nix_name: str = "generatedNativeSourceBuildNixIdentity"
    source_artifacts_name: str = "generatedNativeSourceArtifactIdentities"
    source_artifacts_valid_name: str = "generatedNativeSourceArtifactsValid"
    project_name: str = "generatedNativeSourceProject"
    project_valid_name: str = "generatedNativeSourceProjectValid"
    profile_name: str = "generatedPinnedNativeSourceToolchainProfile"
    profile_pinned_name: str = "generatedPinnedNativeSourceToolchainProfileValid"
    profile_matches_name: str = "generatedNativeSourceProfileMatches"
    artifact_name: str = "generatedNativeSourceCompiledArtifact"
    authority_name: str = "generatedNativeSourceCompiledPE32Authority"
    built_from_name: str = "generatedNativeSourceArtifactBuiltFrom"
    launch_constructor_name: str = "checkedNativeSourceLaunch"
    compilation_constructor_name: str = "exactNativeSourceCompilation"

    def validate(self) -> None:
        if not isinstance(self.imports, tuple) or not self.imports:
            raise NativeSourceCompiledAuthorityGenerationError(
                "imports must be a non-empty tuple of canonical StageA modules"
            )
        if len(set(self.imports)) != len(self.imports):
            raise NativeSourceCompiledAuthorityGenerationError(
                "imports must not contain duplicates"
            )
        for module in self.imports:
            _validate_stage_a_module(module, "import")

        if not isinstance(self.source_artifacts, tuple) or not self.source_artifacts:
            raise NativeSourceCompiledAuthorityGenerationError(
                "source_artifacts must be a non-empty tuple"
            )
        if len(set(self.source_artifacts)) != len(self.source_artifacts):
            raise NativeSourceCompiledAuthorityGenerationError(
                "source_artifacts must not contain duplicate declarations"
            )

        declaration_fields = {
            "world_program",
            "checked_input",
            "checked_input_nonempty",
            "bundle_manifest_artifact",
            "renderer_input_artifact",
            "source_artifact_roles_nodup",
            "compiled_identity",
            "compiled_identity_valid",
            "compiled_bytes",
            "compiled_pe",
            "compiled_byte_length_exact",
            "compiled_pe_parsed_exact",
            "compiled_pe_bytes_exact",
            "import_certificate",
            "imports_parsed",
            "relocations",
            "relocations_parsed",
            "loader_image_valid",
            "environment",
            "indirect_targets",
            "indirect_targets_valid",
        }
        local_fields = {
            "output_module",
            "audit_output_module",
            "project_nix_name",
            "profile_nix_name",
            "build_nix_name",
            "source_artifacts_name",
            "source_artifacts_valid_name",
            "project_name",
            "project_valid_name",
            "profile_name",
            "profile_pinned_name",
            "profile_matches_name",
            "artifact_name",
            "authority_name",
            "built_from_name",
            "launch_constructor_name",
            "compilation_constructor_name",
        }
        for field in fields(self):
            if field.name in declaration_fields:
                _validate_identifier(getattr(self, field.name), field.name)
            elif field.name in local_fields:
                _validate_local_name(getattr(self, field.name), field.name)
        for index, declaration in enumerate(self.source_artifacts):
            _validate_identifier(declaration, f"source_artifacts[{index}]")

        _validate_identifier(self.namespace, "namespace")
        _validate_literal(self.profile_identifier, "profile_identifier")
        self.project_nix.validate("project_nix")
        self.profile_nix.validate("profile_nix")
        self.build_nix.validate("build_nix")
        for label in (
            "renderer",
            "lowering",
            "runtime",
            "compiler",
            "assembler",
            "linker",
            "abi",
        ):
            getattr(self, label).validate(label)

        if (self.callable_external is None) != (self.callable_bound is None):
            raise NativeSourceCompiledAuthorityGenerationError(
                "callable_external and callable_bound must be supplied together"
            )
        if self.callable_external is not None:
            _validate_identifier(self.callable_external, "callable_external")
            _validate_identifier(self.callable_bound, "callable_bound")

        if self.output_module == self.audit_output_module:
            raise NativeSourceCompiledAuthorityGenerationError(
                "authority and audit output modules must be distinct"
            )
        generated_names = tuple(
            getattr(self, name) for name in local_fields - {"output_module", "audit_output_module"}
        )
        if len(set(generated_names)) != len(generated_names):
            raise NativeSourceCompiledAuthorityGenerationError(
                "generated declaration names must be distinct"
            )


def _absolute_path(value: object) -> bool:
    return isinstance(value, str) and value.startswith("/") and "\n" not in value


def _validate_literal(value: object, label: str) -> None:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise NativeSourceCompiledAuthorityGenerationError(
            f"{label} must be a non-empty printable string"
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


def _validate_identifier(value: object, label: str) -> None:
    if not _valid_identifier(value):
        raise NativeSourceCompiledAuthorityGenerationError(
            f"{label} must be a canonical Lean declaration"
        )


def _validate_local_name(value: object, label: str) -> None:
    if not (
        isinstance(value, str)
        and _LOCAL_NAME.fullmatch(value) is not None
        and value.casefold() not in _FORBIDDEN_NAME_PARTS
    ):
        raise NativeSourceCompiledAuthorityGenerationError(
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
        raise NativeSourceCompiledAuthorityGenerationError(
            f"{label} must be a canonical StageA module"
        )


def _lean_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _and_intro(proofs: list[str]) -> str:
    if not proofs:
        raise NativeSourceCompiledAuthorityGenerationError(
            "internal error: conjunction proof inventory is empty"
        )
    expression = proofs[-1]
    for proof in reversed(proofs[:-1]):
        expression = f"And.intro ({proof}) ({expression})"
    return expression


def _nix_identity_source(name: str, value: NixRealizationSpec) -> str:
    return f"""def {name} : NixRealizationIdentity := {{
  derivationPath := {_lean_string(value.derivation_path)}
  derivationSha256 := {_lean_string(value.derivation_sha256)}
  outputPath := {_lean_string(value.output_path)}
  narHash := {_lean_string(value.nar_hash)}
}}

theorem {name}Valid : {name}.Valid := by
  unfold NixRealizationIdentity.Valid {name}
  decide
"""


def _source_artifacts_valid_proof(spec: NativeSourceCompiledAuthoritySpec) -> str:
    identities = ", ".join(
        f"{artifact}.identity" for artifact in spec.source_artifacts
    )
    steps = "\n".join(
        "  rcases List.mem_cons.mp member with rfl | member\n"
        f"  exact {artifact}.identityValid"
        for artifact in spec.source_artifacts
    )
    return f"""theorem {spec.source_artifacts_valid_name} :
    forall identity, List.Mem identity {spec.source_artifacts_name} ->
      identity.Valid := by
  intro identity member
  change List.Mem identity [{identities}] at member
{steps}
  simp at member
"""


def native_source_compiled_authority_source(
    spec: NativeSourceCompiledAuthoritySpec,
) -> str:
    """Emit deterministic root-independent compiled-artifact authority."""

    spec.validate()
    modules = sorted({*spec.imports, "StageA.RelationalNativeSource"})
    imports = "\n".join(f"import {module}" for module in modules)
    source_identities = ",\n  ".join(
        f"{artifact}.identity" for artifact in spec.source_artifacts
    )
    components = {
        "renderer": spec.renderer,
        "lowering": spec.lowering,
        "runtime": spec.runtime,
        "compiler": spec.compiler,
        "assembler": spec.assembler,
        "linker": spec.linker,
        "abi": spec.abi,
    }
    profile_fields = "\n".join(
        f"  {name}Identifier := {_lean_string(component.identifier)}\n"
        f"  {name}Sha256 := {component.exact_artifact}.identity.sha256"
        for name, component in components.items()
    )
    profile_pinned_proofs = [
        "by decide",
        "by rfl",
        f"by simpa only [{spec.profile_name}] using {spec.profile_nix_name}Valid",
    ]
    for component in components.values():
        profile_pinned_proofs.extend(
            (
                "by decide",
                "by simpa only "
                f"[{spec.profile_name}] using "
                f"{component.exact_artifact}.identityValid.2.1",
            )
        )
    profile_pinned = _and_intro(profile_pinned_proofs)
    callable_value = (
        "none"
        if spec.callable_external is None
        else f"some {spec.callable_external}"
    )
    if spec.callable_external is None:
        callable_proof = "by simp"
    else:
        callable_proof = f"""by
    intro config selected
    simp only [Option.some.injEq] at selected
    subst config
    simpa only [{spec.artifact_name}] using {spec.callable_bound}"""

    return f"""{imports}

namespace {spec.namespace}

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.SourceWorld
open StageA.Relational.NativeSource

noncomputable section

{_nix_identity_source(spec.project_nix_name, spec.project_nix)}

{_nix_identity_source(spec.profile_nix_name, spec.profile_nix)}

{_nix_identity_source(spec.build_nix_name, spec.build_nix)}

def {spec.source_artifacts_name} : List ArtifactIdentity := [
  {source_identities}
]

{_source_artifacts_valid_proof(spec)}

/-- Exact semantic project identity.  Content identities are projections of
checked exact artifacts, rather than free hash strings. -/
def {spec.project_name} : NativeSourceProject := {{
  profile := .checkedInterpreterV1
  worldProgram := {spec.world_program}
  checkedInput := {spec.checked_input}
  bundleManifest := {spec.bundle_manifest_artifact}.identity
  rendererInputArtifact := {spec.renderer_input_artifact}.identity
  sourceArtifacts := {spec.source_artifacts_name}
  nixIdentity := {spec.project_nix_name}
}}

theorem {spec.project_valid_name} : {spec.project_name}.Valid := by
  unfold NativeSourceProject.Valid
  exact {_and_intro([
      'by rfl',
      f'by simpa only [{spec.project_name}] using {spec.checked_input_nonempty}',
      f'by simpa only [{spec.project_name}] using {spec.bundle_manifest_artifact}.identityValid',
      f'by simpa only [{spec.project_name}] using {spec.renderer_input_artifact}.identityValid',
      f'by simp [{spec.project_name}, {spec.source_artifacts_name}]',
      f'by simpa only [{spec.project_name}] using {spec.source_artifacts_valid_name}',
      f'by simpa only [{spec.project_name}, {spec.source_artifacts_name}] using {spec.source_artifact_roles_nodup}',
      f'by simpa only [{spec.project_name}] using {spec.project_nix_name}Valid',
  ])}

/-- Every tool hash is projected from exact Lean-resident content.  Nix
provenance remains an explicit conditional identity, as required by the
pinned-stack premise. -/
def {spec.profile_name} : PinnedNativeSourceToolchainProfile := {{
  identifier := {_lean_string(spec.profile_identifier)}
  sourceProfile := .checkedInterpreterV1
  nixIdentity := {spec.profile_nix_name}
{profile_fields}
}}

theorem {spec.profile_pinned_name} : {spec.profile_name}.FullStackPinned := by
  unfold PinnedNativeSourceToolchainProfile.FullStackPinned
  exact {profile_pinned}

theorem {spec.profile_matches_name} :
    {spec.project_name}.profile = {spec.profile_name}.sourceProfile := by
  rfl

/-- Exact compiled bytes and PE parse.  The digest in `identity` is external
provenance only; semantic authority is the Lean-resident byte tree and its
exact parse. -/
def {spec.artifact_name} : CompiledArtifact := {{
  identity := {spec.compiled_identity}
  buildIdentity := {spec.build_nix_name}
  sourceProjectNarHash := {spec.project_name}.nixIdentity.narHash
  toolchainNarHash := {spec.profile_name}.nixIdentity.narHash
  bytes := {spec.compiled_bytes}
  pe := {spec.compiled_pe}
  identityValid := {spec.compiled_identity_valid}
  byteLengthExact := {spec.compiled_byte_length_exact}
  parsedExactly := {spec.compiled_pe_parsed_exact}
  peBytesExact := {spec.compiled_pe_bytes_exact}
}}

def {spec.built_from_name} :
    {spec.artifact_name}.BuiltFrom {spec.profile_name} {spec.project_name} := {{
  buildIdentityValid := {spec.build_nix_name}Valid
  sourceProjectExact := rfl
  toolchainExact := rfl
}}

/-- Root-independent machine authority for the exact compiled artifact. -/
def {spec.authority_name} : ExactCompiledPE32Authority {spec.artifact_name} := {{
  importCertificate := {spec.import_certificate}
  relocations := {spec.relocations}
  environment := {spec.environment}
  callableExternal := {callable_value}
  indirectTargets := {spec.indirect_targets}
  importsParsed := by
    simpa only [{spec.artifact_name}] using {spec.imports_parsed}
  relocationsParsed := by
    simpa only [{spec.artifact_name}] using {spec.relocations_parsed}
  loaderImageValid := by
    simpa only [{spec.artifact_name}] using {spec.loader_image_valid}
  callableBound := {callable_proof}
  indirectTargetsValid := by
    simpa only [{spec.artifact_name}] using {spec.indirect_targets_valid}
}}

/-- Adapter for the current root-indexed launch API.  The static authority
above commits to no concrete launch; callers must provide every launch fact. -/
def {spec.launch_constructor_name}
    (sourceRoot : SourceExecution) (compiledRoot : NativeWorldExecution)
    (sourceLaunch : CheckedNativeSourcePE32ConsoleLaunch
      {spec.project_name} sourceRoot)
    (compiledState : MachineState) (compiledWorld : RelationalWorld)
    (compiledEntry : compiledRoot =
      .running {spec.artifact_name}.pe.entrypointRva 0 compiledState [] 0 []
        compiledWorld)
    (compiledImageMapped : PreferredBaseImageMemory {spec.artifact_name}.pe
      {spec.authority_name}.importCertificate.imports compiledState.memory)
    (compiledImportMemory : NativeImportAddressesMemoryHold
      {spec.artifact_name}.pe {spec.authority_name}.importCertificate.imports
      compiledWorld compiledState.memory)
    (phaseMatches : ExecutionPhaseMatches sourceRoot compiledRoot) :
    CheckedNativeCompilationLaunch {spec.project_name} sourceRoot
      {spec.authority_name} compiledRoot := {{
  sourceLaunch
  compiledLaunch := Exists.intro compiledState (Exists.intro compiledWorld
    (And.intro compiledEntry
      (And.intro compiledImageMapped compiledImportMemory)))
  phaseMatches
}}

/-- Assemble the root-independent exact compilation.  Concrete source and
compiled roots remain inputs to ``checkedNativeSourceLaunch`` and final
acceptance, so this static artifact cannot accidentally certify one launch. -/
def {spec.compilation_constructor_name} : ExactNativeCompilation := {{
  profile := {spec.profile_name}
  project := {spec.project_name}
  artifact := {spec.artifact_name}
  machineAuthority := {spec.authority_name}
  projectValid := {spec.project_valid_name}
  profilePinned := {spec.profile_pinned_name}
  profileMatches := {spec.profile_matches_name}
  builtFrom := {spec.built_from_name}
}}

end

end {spec.namespace}
"""


def native_source_compiled_authority_axiom_audit_source(
    spec: NativeSourceCompiledAuthoritySpec,
) -> str:
    """Emit a separate audit for every generated authority boundary."""

    spec.validate()
    names = (
        spec.project_valid_name,
        spec.profile_pinned_name,
        spec.artifact_name,
        spec.built_from_name,
        spec.authority_name,
        spec.launch_constructor_name,
        spec.compilation_constructor_name,
    )
    lines = "\n".join(
        f"#print axioms {spec.namespace}.{name}" for name in names
    )
    return f"import StageA.{spec.output_module}\n\n{lines}\n"


def write_native_source_compiled_authority(
    out: Path | str, spec: NativeSourceCompiledAuthoritySpec
) -> tuple[Path, Path]:
    """Write the authority and separate audit below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    authority = stage_a / f"{spec.output_module}.lean"
    audit = stage_a / f"{spec.audit_output_module}.lean"
    authority.write_text(
        native_source_compiled_authority_source(spec), encoding="ascii"
    )
    audit.write_text(
        native_source_compiled_authority_axiom_audit_source(spec),
        encoding="ascii",
    )
    return authority, audit


__all__ = [
    "NATIVE_SOURCE_COMPILED_AUTHORITY_AUDIT_MODULE",
    "NATIVE_SOURCE_COMPILED_AUTHORITY_MODULE",
    "NativeSourceCompiledAuthorityGenerationError",
    "NativeSourceCompiledAuthoritySpec",
    "NixRealizationSpec",
    "PinnedToolArtifactSpec",
    "native_source_compiled_authority_axiom_audit_source",
    "native_source_compiled_authority_source",
    "write_native_source_compiled_authority",
]
