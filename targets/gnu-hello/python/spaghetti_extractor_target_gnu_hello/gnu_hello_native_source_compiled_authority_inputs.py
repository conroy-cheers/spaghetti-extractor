"""Materialize GNU hello compiled-authority declaration inputs.

The compiled-authority evidence producer deliberately consumes small, strict
manifests instead of inferring Lean declarations or tool identities.  This
adapter closes that gap for the GNU hello experiment.  It revalidates the
native-source bundle and compilation attestation, checks the generated source
program and candidate static-authority interfaces, and emits:

* exact Lean ``ExactSourceArtifact`` declarations for every required byte
  artifact;
* the exact source-project declaration manifest;
* a content-addressed runtime declaration manifest; and
* the seven-role pinned native-source toolchain profile.

The adapter is not proof authority.  Generated declarations remain untrusted
until Lean elaborates them, and the downstream detached axiom audit remains
mandatory.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.native_source_equivalence import (
    validate_native_source_bundle_manifest,
    validate_native_source_compilation_attestation,
)
from spaghetti_extractor.util import sha256_file
from .gnu_hello_native_source_compiled_authority_evidence import (
    CANDIDATE_STATIC_AUTHORITY_FORMAT,
    PROFILE_IDENTIFIER,
    PROJECT_DECLARATIONS_FORMAT,
    RUNTIME_DECLARATIONS_FORMAT,
    TOOLCHAIN_PROFILE_FILENAME,
    TOOLCHAIN_PROFILE_FORMAT,
)


SOURCE_PROGRAM_PHASE_FORMAT = "stage-a-relational-phase-v1"
SOURCE_PROGRAM_PHASE = "native-source-program"
SOURCE_PROGRAM_MODULE = "StageA.GeneratedGnuHelloNativeSourceProgram"
SOURCE_PROGRAM_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloNativeSourceProgram"
)
PROJECT_MODULE = "StageA.GeneratedGnuHelloNativeSourceProjectDeclarations"
PROJECT_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloNativeSourceProjectDeclarations"
)
INPUTS_MANIFEST_FORMAT = (
    "stage-a-gnu-hello-native-source-compiled-authority-inputs-v1"
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LEAN_DECLARATION = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LEAN_LOCAL = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")

_TOOL_ROLES = (
    "renderer",
    "lowering",
    "runtime",
    "compiler",
    "assembler",
    "linker",
    "abi",
)
_STATIC_INTERFACE_FIELDS = frozenset(
    {
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
    }
)
_STATIC_TOP_LEVEL_FIELDS = frozenset(
    {
        "format",
        "phase",
        "status",
        "candidate",
        "kernel_data",
        "module",
        "namespace",
        "compiled_identity_interface",
        "constructors",
        "trust",
    }
)
_STATIC_TRUST = {
    "executes_original_binary": False,
    "executes_candidate_binary": False,
    "exact_candidate_bytes_checked_in_lean": True,
    "imports_parsed_from_candidate_exe": True,
    "relocations_parsed_from_candidate_exe": True,
    "environment_parameterized": True,
    "indirect_target_shape_is_completeness": False,
    "indirect_target_completeness_proved": False,
    "whole_program_acceptance_authority": False,
}


class GnuHelloCompiledAuthorityInputError(StageAInputError):
    """The GNU hello compiled-authority inputs are incomplete or inconsistent."""


@dataclass(frozen=True)
class RuntimeDeclarationSpec:
    """Exact declarations exported by one candidate runtime Lean module."""

    module: str
    source: Path
    environment: str
    indirect_targets: str
    indirect_targets_valid: str
    callable_external: str | None = None
    callable_bound: str | None = None

    def validate(self) -> None:
        if _LEAN_MODULE.fullmatch(self.module) is None:
            raise GnuHelloCompiledAuthorityInputError(
                "runtime module must be a canonical StageA module"
            )
        source = self.source.resolve()
        if not source.is_file() or source.suffix != ".lean":
            raise GnuHelloCompiledAuthorityInputError(
                "runtime module source must be a regular Lean file"
            )
        declarations = {
            "environment": self.environment,
            "indirect_targets": self.indirect_targets,
            "indirect_targets_valid": self.indirect_targets_valid,
        }
        if (self.callable_external is None) != (self.callable_bound is None):
            raise GnuHelloCompiledAuthorityInputError(
                "callable external declaration and bound proof must be supplied together"
            )
        if self.callable_external is not None:
            declarations["callable_external"] = self.callable_external
            declarations["callable_bound"] = self.callable_bound
        for label, declaration in declarations.items():
            if (
                not isinstance(declaration, str)
                or _LEAN_DECLARATION.fullmatch(declaration) is None
                or not declaration.startswith("StageA.")
            ):
                raise GnuHelloCompiledAuthorityInputError(
                    f"runtime {label} must be a canonical StageA declaration"
                )
        source_text = source.read_text(encoding="utf-8")
        _verify_declaration(
            source_text,
            self.environment,
            "runtime environment",
            required_type="NativeWorldEnvironment",
        )
        _verify_declaration(
            source_text,
            self.indirect_targets,
            "runtime indirect-target inventory",
            required_type="NativeIndirectTargetInventory",
        )
        _verify_declaration(
            source_text,
            self.indirect_targets_valid,
            "runtime indirect-target proof",
        )
        if self.callable_external is not None:
            _verify_declaration(
                source_text,
                self.callable_external,
                "runtime callable-external declaration",
            )
            _verify_declaration(
                source_text,
                self.callable_bound or "",
                "runtime callable-external bound proof",
            )


@dataclass(frozen=True)
class GnuHelloCompiledAuthorityInputOutputs:
    project_declarations: Path
    runtime_declarations: Path
    toolchain_profile: Path
    inputs_manifest: Path


@dataclass(frozen=True)
class _Artifact:
    role: str
    path: Path
    sha256: str
    size: int


@dataclass(frozen=True)
class _ExactDeclaration:
    module: str
    declaration: str
    source: Path
    sha256: str

    def ref(self, kind: str = "exact_source_artifact") -> dict[str, str]:
        return {
            "module": self.module,
            "declaration": self.declaration,
            "kind": kind,
        }


BundleValidator = Callable[[Path | str], dict[str, Any]]
AttestationValidator = Callable[[Path | str], dict[str, Any]]


def write_gnu_hello_native_source_compiled_authority_inputs(
    *,
    source_bundle: Path | str,
    compilation_attestation: Path | str,
    native_source_program_manifest: Path | str,
    candidate_static_authority: Path | str,
    runtime: RuntimeDeclarationSpec,
    out: Path | str,
    bundle_validator: BundleValidator = validate_native_source_bundle_manifest,
    attestation_validator: AttestationValidator = (
        validate_native_source_compilation_attestation
    ),
) -> GnuHelloCompiledAuthorityInputOutputs:
    """Write deterministic, fail-closed inputs for compiled-authority evidence."""

    bundle_path = Path(source_bundle).resolve()
    attestation_path = Path(compilation_attestation).resolve()
    program_manifest_path = Path(native_source_program_manifest).resolve()
    static_manifest_path = Path(candidate_static_authority).resolve()
    root = Path(out).resolve()
    root.mkdir(parents=True, exist_ok=True)

    bundle = bundle_validator(bundle_path)
    attestation = attestation_validator(attestation_path)
    _validate_attestation_binding(bundle_path, bundle, attestation_path, attestation)
    source_program_source = _validate_source_program(program_manifest_path)
    candidate_path, candidate_sha256 = _attested_candidate(attestation)
    static_module = _validate_static_authority(
        static_manifest_path, candidate_path, candidate_sha256
    )
    runtime.validate()

    source_artifacts, special_artifacts, tool_artifacts = _collect_artifacts(
        bundle_path, bundle, attestation
    )
    if len({artifact.sha256 for artifact in source_artifacts}) != len(
        source_artifacts
    ):
        raise GnuHelloCompiledAuthorityInputError(
            "exact project source artifacts must have distinct SHA-256 identities"
        )

    all_artifacts = {
        artifact.sha256: artifact
        for artifact in (
            *source_artifacts,
            *special_artifacts.values(),
            *tool_artifacts.values(),
        )
    }
    exact_declarations = {
        digest: _write_exact_artifact_module(root, artifact)
        for digest, artifact in sorted(all_artifacts.items())
    }

    project_module_path = _write_project_module(
        root,
        exact_declarations=exact_declarations,
        source_artifacts=source_artifacts,
    )
    project_manifest = _write_project_manifest(
        root,
        bundle=bundle,
        bundle_path=bundle_path,
        source_program_source=source_program_source,
        project_module_path=project_module_path,
        exact_declarations=exact_declarations,
        source_artifacts=source_artifacts,
        special_artifacts=special_artifacts,
        tool_artifacts=tool_artifacts,
    )
    runtime_manifest = _write_runtime_manifest(
        root, runtime=runtime, candidate_sha256=candidate_sha256
    )
    toolchain_profile = _write_toolchain_profile(root, tool_artifacts)
    inputs_manifest = root / "compiled-authority-inputs.json"
    _write_json(
        inputs_manifest,
        {
            "format": INPUTS_MANIFEST_FORMAT,
            "bindings": {
                "source_bundle_sha256": _source_bundle_sha256(bundle),
                "source_bundle_artifact_sha256": sha256_file(bundle_path),
                "compilation_attestation_sha256": sha256_file(attestation_path),
                "native_source_program_sha256": sha256_file(source_program_source),
                "candidate_static_authority_sha256": sha256_file(
                    static_manifest_path
                ),
                "candidate_static_module_sha256": sha256_file(static_module),
                "candidate_sha256": candidate_sha256,
                "runtime_module_sha256": sha256_file(runtime.source.resolve()),
            },
            "outputs": {
                "project_declarations": project_manifest.name,
                "runtime_declarations": runtime_manifest.name,
                "toolchain_profile": toolchain_profile.name,
            },
        },
    )
    return GnuHelloCompiledAuthorityInputOutputs(
        project_declarations=project_manifest,
        runtime_declarations=runtime_manifest,
        toolchain_profile=toolchain_profile,
        inputs_manifest=inputs_manifest,
    )


def _validate_attestation_binding(
    bundle_path: Path,
    bundle: Mapping[str, Any],
    attestation_path: Path,
    attestation: Mapping[str, Any],
) -> None:
    if not bundle_path.is_file() or not attestation_path.is_file():
        raise GnuHelloCompiledAuthorityInputError(
            "source bundle and compilation attestation must be regular files"
        )
    source = _object(attestation.get("source_bundle"), "attested source bundle")
    expected = {
        "path": str(bundle_path),
        "artifact_sha256": sha256_file(bundle_path),
        "source_bundle_sha256": _source_bundle_sha256(bundle),
    }
    for name, value in expected.items():
        observed = source.get(name)
        if name == "path" and isinstance(observed, str):
            observed = str(Path(observed).resolve())
        if observed != value:
            raise GnuHelloCompiledAuthorityInputError(
                "compilation attestation binds a different source bundle"
            )


def _validate_source_program(manifest_path: Path) -> Path:
    manifest = _read_object(manifest_path, "native-source program manifest")
    _exact_fields(
        manifest,
        {
            "format",
            "phase",
            "executes_original_binary",
            "executes_candidate_binary",
            "inputs",
            "status",
            "modules",
            "targets",
        },
        "native-source program manifest",
    )
    if manifest != {
        "format": SOURCE_PROGRAM_PHASE_FORMAT,
        "phase": SOURCE_PROGRAM_PHASE,
        "executes_original_binary": False,
        "executes_candidate_binary": False,
        "inputs": {},
        "status": "source-ready",
        "modules": [SOURCE_PROGRAM_MODULE.rsplit(".", 1)[-1]],
        "targets": [SOURCE_PROGRAM_MODULE.rsplit(".", 1)[-1]],
    }:
        raise GnuHelloCompiledAuthorityInputError(
            "native-source program manifest is not the canonical GNU hello program"
        )
    source = manifest_path.parent / "StageA" / (
        SOURCE_PROGRAM_MODULE.rsplit(".", 1)[-1] + ".lean"
    )
    if not source.is_file():
        raise GnuHelloCompiledAuthorityInputError(
            "generated GNU hello native-source program module is missing"
        )
    text = source.read_text(encoding="utf-8")
    required = (
        "import StageA.GeneratedGnuHelloOriginalPE",
        f"namespace {SOURCE_PROGRAM_NAMESPACE}",
        "def generatedNativeSourceProgram (worldProgram : DecodedWorldProgram)",
        "def generatedNativeSourceExactBindingPartition (worldProgram : DecodedWorldProgram)",
        "def generatedNativeSourceExactBinding",
        "theorem generatedNativeSourceX87WitnessRvasNodup",
    )
    if any(fragment not in text for fragment in required):
        raise GnuHelloCompiledAuthorityInputError(
            "generated GNU hello native-source program interface changed"
        )
    for declaration in (
        "generatedNativeSourceProgram",
        "generatedNativeSourceExactBindingPartition",
        "generatedNativeSourceExactBinding",
        "generatedNativeSourceX87WitnessRvasNodup",
    ):
        _reject_unchecked(text, declaration, f"source-program {declaration}")
    return source.resolve()


def _attested_candidate(attestation: Mapping[str, Any]) -> tuple[Path, str]:
    row = _object(attestation.get("candidate"), "attested candidate")
    candidate = Path(_string(row.get("path"), "attested candidate path")).resolve()
    if not candidate.is_file() or candidate.is_symlink():
        raise GnuHelloCompiledAuthorityInputError(
            "attested candidate must be a regular file"
        )
    digest = sha256_file(candidate)
    if row.get("sha256") != digest or row.get("size") != candidate.stat().st_size:
        raise GnuHelloCompiledAuthorityInputError(
            "candidate bytes differ from the compilation attestation"
        )
    return candidate, digest


def _validate_static_authority(
    manifest_path: Path, candidate: Path, candidate_sha256: str
) -> Path:
    manifest = _read_object(manifest_path, "candidate static-authority manifest")
    _exact_fields(manifest, _STATIC_TOP_LEVEL_FIELDS, "candidate static-authority manifest")
    if (
        manifest["format"] != CANDIDATE_STATIC_AUTHORITY_FORMAT
        or manifest["phase"] != "native-source-candidate-static-authority"
        or manifest["status"] != "source-ready"
        or manifest["trust"] != _STATIC_TRUST
    ):
        raise GnuHelloCompiledAuthorityInputError(
            "candidate static-authority profile or trust contract changed"
        )
    row = _object(manifest["candidate"], "candidate static-authority binding")
    _exact_fields(row, {"path", "sha256", "size"}, "candidate static-authority binding")
    if (
        Path(_string(row["path"], "static candidate path")).resolve()
        != candidate
        or row["sha256"] != candidate_sha256
        or row["size"] != candidate.stat().st_size
    ):
        raise GnuHelloCompiledAuthorityInputError(
            "candidate static authority binds different candidate bytes"
        )
    module = _string(manifest["module"], "candidate static-authority module")
    if _LEAN_LOCAL.fullmatch(module) is None:
        raise GnuHelloCompiledAuthorityInputError(
            "candidate static-authority module is invalid"
        )
    namespace = _string(
        manifest["namespace"], "candidate static-authority namespace"
    )
    if _LEAN_DECLARATION.fullmatch(namespace) is None or not namespace.startswith(
        "StageA."
    ):
        raise GnuHelloCompiledAuthorityInputError(
            "candidate static-authority namespace is invalid"
        )
    source = manifest_path.parent / "StageA" / f"{module}.lean"
    if not source.is_file():
        raise GnuHelloCompiledAuthorityInputError(
            "candidate static-authority Lean module is missing"
        )
    text = source.read_text(encoding="utf-8")
    interface = _object(
        manifest["compiled_identity_interface"], "compiled identity interface"
    )
    _exact_fields(interface, _STATIC_INTERFACE_FIELDS, "compiled identity interface")
    for name in sorted(_STATIC_INTERFACE_FIELDS):
        declaration = _string(interface[name], f"compiled identity interface.{name}")
        if not declaration.startswith(namespace + "."):
            raise GnuHelloCompiledAuthorityInputError(
                f"compiled identity interface.{name} escapes its namespace"
            )
        _verify_declaration(text, declaration, f"compiled identity interface.{name}")
    constructors = _object(manifest["constructors"], "static constructors")
    _exact_fields(
        constructors,
        {"compiled_artifact", "machine_authority"},
        "static constructors",
    )
    for name, declaration in constructors.items():
        declaration = _string(declaration, f"static constructors.{name}")
        if not declaration.startswith(namespace + "."):
            raise GnuHelloCompiledAuthorityInputError(
                f"static constructor {name} escapes its namespace"
            )
        _verify_declaration(text, declaration, f"static constructors.{name}")
    kernel_data = _object(manifest["kernel_data"], "static kernel-data binding")
    _exact_fields(
        kernel_data,
        {"inventory", "format", "relocation_packs", "relocation_blocks"},
        "static kernel-data binding",
    )
    inventory = Path(
        _string(kernel_data["inventory"], "static kernel-data inventory")
    ).resolve()
    inventory_payload = _read_object(inventory, "static kernel-data inventory")
    if (
        inventory_payload.get("format") != kernel_data["format"]
        or inventory_payload.get("candidate_sha256") != candidate_sha256
        or inventory_payload.get("candidate_bytes") != candidate.stat().st_size
    ):
        raise GnuHelloCompiledAuthorityInputError(
            "candidate static-authority kernel-data binding changed"
        )
    counts = _object(inventory_payload.get("counts"), "kernel-data counts")
    if (
        counts.get("relocation_packs") != kernel_data["relocation_packs"]
        or counts.get("relocation_blocks") != kernel_data["relocation_blocks"]
        or not isinstance(kernel_data["relocation_packs"], int)
        or kernel_data["relocation_packs"] <= 0
        or not isinstance(kernel_data["relocation_blocks"], int)
        or kernel_data["relocation_blocks"] <= 0
    ):
        raise GnuHelloCompiledAuthorityInputError(
            "candidate static-authority relocation inventory changed"
        )
    modules = _list(inventory_payload.get("modules"), "kernel-data modules")
    roles = {
        row.get("role")
        for index, value in enumerate(modules)
        for row in [_object(value, f"kernel-data modules[{index}]")]
        if isinstance(row.get("role"), str)
    }
    required_roles = {"candidate-pe-binding", "candidate-relocation-bundle"}
    if not required_roles <= roles:
        raise GnuHelloCompiledAuthorityInputError(
            "candidate static-authority kernel-data roles are incomplete"
        )
    return source.resolve()


def _collect_artifacts(
    bundle_path: Path,
    bundle: Mapping[str, Any],
    attestation: Mapping[str, Any],
) -> tuple[list[_Artifact], dict[str, _Artifact], dict[str, _Artifact]]:
    state = _artifact_from_row(
        _object(bundle.get("state_machine"), "source state machine"),
        "renderer-input",
    )
    packages = _object(bundle.get("packages"), "source packages")
    if set(packages) != {"interpreter", "native_engine", "native_runtime"}:
        raise GnuHelloCompiledAuthorityInputError(
            "source bundle package ownership changed"
        )
    source_artifacts: list[_Artifact] = []
    package_roles: dict[tuple[str, str], _Artifact] = {}
    for owner in sorted(packages):
        package = _object(packages[owner], f"source package {owner}")
        root = Path(_string(package.get("root"), f"source package {owner} root"))
        if not root.is_absolute() or not root.is_dir():
            raise GnuHelloCompiledAuthorityInputError(
                f"source package {owner} root is not a realized directory"
            )
        rows = _list(package.get("artifacts"), f"source package {owner} artifacts")
        if not rows:
            raise GnuHelloCompiledAuthorityInputError(
                f"source package {owner} has no artifacts"
            )
        for index, value in enumerate(rows):
            row = _object(value, f"source package {owner} artifacts[{index}]")
            if row.get("owner") != owner:
                raise GnuHelloCompiledAuthorityInputError(
                    f"source package {owner} artifact owner changed"
                )
            role = _string(row.get("role"), f"source package {owner} role")
            artifact = _artifact_from_row(
                row,
                f"source-{owner}-{role}",
                root=root,
            )
            if (owner, role) in package_roles:
                raise GnuHelloCompiledAuthorityInputError(
                    f"source package role {owner}/{role} is ambiguous"
                )
            package_roles[(owner, role)] = artifact
            source_artifacts.append(artifact)

    required_package_roles = {
        ("native_engine", "plan"): "lowering",
        ("native_runtime", "native_runtime_source"): "runtime",
        ("native_runtime", "native_runtime_header"): "abi",
    }
    missing = set(required_package_roles) - set(package_roles)
    if missing:
        raise GnuHelloCompiledAuthorityInputError(
            "source bundle omits required package roles: "
            + ", ".join(f"{owner}/{role}" for owner, role in sorted(missing))
        )

    attested_tools: dict[str, _Artifact] = {}
    for index, value in enumerate(_list(attestation.get("tools"), "attested tools")):
        row = _object(value, f"attested tools[{index}]")
        role = _string(row.get("role"), f"attested tools[{index}].role")
        artifact = _artifact_from_row(row, f"tool-{role}")
        if role in attested_tools:
            raise GnuHelloCompiledAuthorityInputError(
                f"attested tool role {role} is ambiguous"
            )
        attested_tools[role] = artifact
    if not {"compiler", "assembler", "linker"} <= set(attested_tools):
        raise GnuHelloCompiledAuthorityInputError(
            "compilation attestation omits compiler, assembler, or linker"
        )

    bundle_artifact = _Artifact(
        role="native-source-bundle-manifest",
        path=bundle_path,
        sha256=sha256_file(bundle_path),
        size=bundle_path.stat().st_size,
    )
    tools = {
        "renderer": state,
        "lowering": package_roles[("native_engine", "plan")],
        "runtime": package_roles[("native_runtime", "native_runtime_source")],
        "compiler": attested_tools["compiler"],
        "assembler": attested_tools["assembler"],
        "linker": attested_tools["linker"],
        "abi": package_roles[("native_runtime", "native_runtime_header")],
    }
    return (
        sorted(source_artifacts, key=lambda item: (item.sha256, item.role)),
        {"bundle": bundle_artifact, "renderer": state},
        tools,
    )


def _artifact_from_row(
    row: Mapping[str, Any], role: str, *, root: Path | None = None
) -> _Artifact:
    raw_path = Path(_string(row.get("path"), f"{role} path"))
    path = raw_path if raw_path.is_absolute() else (root / raw_path if root else raw_path)
    path = path.resolve()
    if not path.is_file():
        raise GnuHelloCompiledAuthorityInputError(f"{role} is not a regular file")
    digest = _sha256(row.get("sha256"), f"{role} SHA-256")
    size = row.get("size", path.stat().st_size)
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size != path.stat().st_size
        or digest != sha256_file(path)
    ):
        raise GnuHelloCompiledAuthorityInputError(
            f"{role} bytes differ from their declared identity"
        )
    return _Artifact(role=role, path=path, sha256=digest, size=size)


def _write_exact_artifact_module(root: Path, artifact: _Artifact) -> _ExactDeclaration:
    suffix = artifact.sha256
    local_module = f"GeneratedGnuHelloNativeSourceArtifact{suffix}"
    module = f"StageA.{local_module}"
    namespace = (
        "StageA.GeneratedRelational.GnuHelloNativeSourceArtifacts."
        f"Artifact{suffix}"
    )
    destination = root / "StageA" / f"{local_module}.lean"
    destination.parent.mkdir(parents=True, exist_ok=True)
    bytes_source = _lean_bytes(artifact.path.read_bytes())
    destination.write_text(
        f"""import StageA.RelationalNativeSource

namespace {namespace}

open StageA.Formal
open StageA.Relational.NativeSource

def identity : ArtifactIdentity := {{
  role := {json.dumps('sha256-' + artifact.sha256, ensure_ascii=True)}
  sha256 := \"{artifact.sha256}\"
  byteLength := {artifact.size}
}}

def artifactBytes : Bytes := {bytes_source}

def exactArtifact : ExactSourceArtifact := {{
  identity
  bytes := artifactBytes
  identityValid := by
    constructor
    . decide
    constructor <;> native_decide
  byteLengthExact := by rfl
  sha256Exact := by native_decide
}}

end {namespace}
""",
        encoding="ascii",
    )
    return _ExactDeclaration(
        module=module,
        declaration=f"{namespace}.exactArtifact",
        source=destination,
        sha256=artifact.sha256,
    )


def _write_project_module(
    root: Path,
    *,
    exact_declarations: Mapping[str, _ExactDeclaration],
    source_artifacts: list[_Artifact],
) -> Path:
    imports = [SOURCE_PROGRAM_MODULE, *sorted({value.module for value in exact_declarations.values()})]
    artifact_identities = ",\n    ".join(
        f"{exact_declarations[item.sha256].declaration}.identity"
        for item in source_artifacts
    )
    destination = root / "StageA" / f"{PROJECT_MODULE.rsplit('.', 1)[-1]}.lean"
    destination.write_text(
        "\n".join(f"import {module}" for module in imports)
        + f"""

namespace {PROJECT_NAMESPACE}

open StageA.Formal
open StageA.Relational
open StageA.Relational.NativeSource
open StageA.Relational.SourceWorld.InterpreterKernel

abbrev worldProgram : DecodedWorldProgram :=
  StageA.GeneratedRelational.originalProgram

def checkedInput : CheckedNativeProgramInput worldProgram := {{
  ir := {{
    records :=
      ({SOURCE_PROGRAM_NAMESPACE}.generatedNativeSourceProgram
        worldProgram).records
    x87Witnesses :=
      ({SOURCE_PROGRAM_NAMESPACE}.generatedNativeSourceExactBindingPartition
        worldProgram).x87Witnesses
  }}
  recordsUnique :=
    ({SOURCE_PROGRAM_NAMESPACE}.generatedNativeSourceExactBindingPartition
      worldProgram).recordsUnique
  x87SourcesUnique := by
    simpa only [CanonicalNativeProgramIR.x87SourceRvas,
      {SOURCE_PROGRAM_NAMESPACE}.generatedNativeSourceExactBindingPartition]
      using
        {SOURCE_PROGRAM_NAMESPACE}.generatedNativeSourceX87WitnessRvasNodup
}}

theorem checkedInputNonempty :
    0 < checkedInput.ir.records.length + checkedInput.ir.x87Witnesses.length := by
  native_decide

theorem sourceArtifactRolesNodup :
    ([
    {artifact_identities}
    ].map fun artifact : ArtifactIdentity => artifact.role).Nodup := by
  native_decide

end {PROJECT_NAMESPACE}
""",
        encoding="ascii",
    )
    return destination


def _write_project_manifest(
    root: Path,
    *,
    bundle: Mapping[str, Any],
    bundle_path: Path,
    source_program_source: Path,
    project_module_path: Path,
    exact_declarations: Mapping[str, _ExactDeclaration],
    source_artifacts: list[_Artifact],
    special_artifacts: Mapping[str, _Artifact],
    tool_artifacts: Mapping[str, _Artifact],
) -> Path:
    module_sources = [
        _module_source(PROJECT_MODULE, project_module_path, root),
        _module_source(SOURCE_PROGRAM_MODULE, source_program_source, root),
    ]
    module_sources.extend(
        _module_source(value.module, value.source, root)
        for value in sorted(exact_declarations.values(), key=lambda item: item.module)
    )
    project_ref = lambda name, kind: {
        "module": PROJECT_MODULE,
        "declaration": f"{PROJECT_NAMESPACE}.{name}",
        "kind": kind,
    }
    exact_ref = lambda artifact: {
        "ref": exact_declarations[artifact.sha256].ref(),
        "evidence_sha256": artifact.sha256,
    }
    payload = {
        "format": PROJECT_DECLARATIONS_FORMAT,
        "bindings": {
            "source_bundle_sha256": _source_bundle_sha256(bundle),
            "source_bundle_artifact_sha256": sha256_file(bundle_path),
        },
        "lean": {
            "module_sources": sorted(module_sources, key=lambda row: row["module"]),
            "world_program": project_ref("worldProgram", "decoded_world_program"),
            "checked_input": project_ref(
                "checkedInput", "checked_native_program_input"
            ),
            "checked_input_nonempty": project_ref("checkedInputNonempty", "proof"),
            "bundle_manifest_artifact": exact_ref(special_artifacts["bundle"]),
            "renderer_input_artifact": exact_ref(special_artifacts["renderer"]),
            "source_artifacts": [exact_ref(item) for item in source_artifacts],
            "source_artifact_roles_nodup": project_ref(
                "sourceArtifactRolesNodup", "proof"
            ),
            "profile_identifier": PROFILE_IDENTIFIER,
            "tools": {
                role: {
                    "identifier": _tool_identifier(role, tool_artifacts[role]),
                    "artifact": exact_declarations[
                        tool_artifacts[role].sha256
                    ].ref(),
                    "evidence_sha256": tool_artifacts[role].sha256,
                }
                for role in _TOOL_ROLES
            },
        },
    }
    destination = root / "project-declarations.json"
    _write_json(destination, payload)
    return destination


def _write_runtime_manifest(
    root: Path, *, runtime: RuntimeDeclarationSpec, candidate_sha256: str
) -> Path:
    module_parts = runtime.module.split(".")
    destination = (
        root
        / "runtime-modules"
        / "StageA"
        / Path(*module_parts[1:]).with_suffix(".lean")
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(runtime.source.resolve(), destination)

    def ref(declaration: str, kind: str) -> dict[str, str]:
        return {
            "module": runtime.module,
            "declaration": declaration,
            "kind": kind,
        }

    payload = {
        "format": RUNTIME_DECLARATIONS_FORMAT,
        "candidate_sha256": candidate_sha256,
        "lean": {
            "module_sources": [
                {
                    "module": runtime.module,
                    "path": str(destination.relative_to(root)),
                    "sha256": sha256_file(destination),
                }
            ],
            "environment": ref(runtime.environment, "native_world_environment"),
            "indirect_targets": ref(
                runtime.indirect_targets, "native_indirect_target_inventory"
            ),
            "indirect_targets_valid": ref(runtime.indirect_targets_valid, "proof"),
            "callable_external": (
                None
                if runtime.callable_external is None
                else ref(runtime.callable_external, "native_callable_external")
            ),
            "callable_bound": (
                None
                if runtime.callable_bound is None
                else ref(runtime.callable_bound, "proof")
            ),
        },
    }
    manifest = root / "runtime-declarations.json"
    _write_json(manifest, payload)
    return manifest


def _write_toolchain_profile(
    root: Path, tools: Mapping[str, _Artifact]
) -> Path:
    profile = root / TOOLCHAIN_PROFILE_FILENAME
    _write_json(
        profile,
        {
            "format": TOOLCHAIN_PROFILE_FORMAT,
            "identifier": PROFILE_IDENTIFIER,
            "tools": [
                {
                    "role": role,
                    "identifier": _tool_identifier(role, tools[role]),
                    "path": str(tools[role].path),
                    "sha256": tools[role].sha256,
                }
                for role in sorted(_TOOL_ROLES)
            ],
        },
    )
    return profile


def _module_source(module: str, path: Path, root: Path) -> dict[str, str]:
    try:
        rendered = str(path.relative_to(root))
    except ValueError:
        rendered = str(path)
    return {"module": module, "path": rendered, "sha256": sha256_file(path)}


def _tool_identifier(role: str, artifact: _Artifact) -> str:
    return f"gnu-hello-native-source-{role}-{artifact.sha256[:16]}"


def _source_bundle_sha256(bundle: Mapping[str, Any]) -> str:
    hashes = _object(bundle.get("hashes"), "source bundle hashes")
    return _sha256(hashes.get("source_bundle_sha256"), "source bundle SHA-256")


def _verify_declaration(
    source: str, declaration: str, label: str, *, required_type: str | None = None
) -> None:
    if _LEAN_DECLARATION.fullmatch(declaration) is None:
        raise GnuHelloCompiledAuthorityInputError(
            f"{label} is not a canonical Lean declaration"
        )
    symbol = declaration.rsplit(".", 1)[-1]
    _reject_unchecked(source, symbol, label)
    match = re.search(
        rf"(?m)^\s*(?:def|abbrev|theorem)\s+{re.escape(symbol)}\b",
        source,
    )
    if match is None:
        raise GnuHelloCompiledAuthorityInputError(
            f"{label} is absent from its Lean module"
        )
    if required_type is not None:
        tail = source[match.start() :]
        declaration_head = tail.split(":=", 1)[0]
        if required_type not in declaration_head:
            raise GnuHelloCompiledAuthorityInputError(
                f"{label} is not visibly typed as {required_type}"
            )


def _reject_unchecked(source: str, declaration: str, label: str) -> None:
    symbol = declaration.rsplit(".", 1)[-1]
    if re.search(rf"(?m)^\s*(?:axiom|opaque)\s+{re.escape(symbol)}\b", source):
        raise GnuHelloCompiledAuthorityInputError(
            f"{label} uses an unchecked declaration form"
        )


def _lean_bytes(value: bytes, *, width: int = 24) -> str:
    if not value:
        raise GnuHelloCompiledAuthorityInputError(
            "exact source artifacts must not be empty"
        )
    rows = [
        ", ".join(str(byte) for byte in value[index : index + width])
        for index in range(0, len(value), width)
    ]
    return "[\n    " + ",\n    ".join(rows) + "\n  ]"


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GnuHelloCompiledAuthorityInputError(
            f"cannot read {label}: {error}"
        ) from error
    return _object(value, label)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise GnuHelloCompiledAuthorityInputError(f"{label} must be an object")
    return dict(value)


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GnuHelloCompiledAuthorityInputError(f"{label} must be an array")
    return list(value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise GnuHelloCompiledAuthorityInputError(
            f"{label} must be a non-empty printable string"
        )
    return value


def _sha256(value: object, label: str) -> str:
    text = _string(value, label)
    if _SHA256.fullmatch(text) is None:
        raise GnuHelloCompiledAuthorityInputError(
            f"{label} must be a lowercase SHA-256"
        )
    return text


def _exact_fields(value: Mapping[str, Any], expected: set[str] | frozenset[str], label: str) -> None:
    if set(value) != set(expected):
        raise GnuHelloCompiledAuthorityInputError(
            f"{label} must contain exactly " + ", ".join(sorted(expected))
        )


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )


def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-bundle", required=True)
    parser.add_argument("--compilation-attestation", required=True)
    parser.add_argument("--native-source-program-manifest", required=True)
    parser.add_argument("--candidate-static-authority", required=True)
    parser.add_argument("--runtime-module", required=True)
    parser.add_argument("--runtime-source", required=True)
    parser.add_argument("--runtime-environment", required=True)
    parser.add_argument("--runtime-indirect-targets", required=True)
    parser.add_argument("--runtime-indirect-targets-valid", required=True)
    parser.add_argument("--runtime-callable-external")
    parser.add_argument("--runtime-callable-bound")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    write_gnu_hello_native_source_compiled_authority_inputs(
        source_bundle=args.source_bundle,
        compilation_attestation=args.compilation_attestation,
        native_source_program_manifest=args.native_source_program_manifest,
        candidate_static_authority=args.candidate_static_authority,
        runtime=RuntimeDeclarationSpec(
            module=args.runtime_module,
            source=Path(args.runtime_source),
            environment=args.runtime_environment,
            indirect_targets=args.runtime_indirect_targets,
            indirect_targets_valid=args.runtime_indirect_targets_valid,
            callable_external=args.runtime_callable_external,
            callable_bound=args.runtime_callable_bound,
        ),
        out=args.out,
    )


if __name__ == "__main__":
    _main()


__all__ = [
    "GnuHelloCompiledAuthorityInputError",
    "GnuHelloCompiledAuthorityInputOutputs",
    "INPUTS_MANIFEST_FORMAT",
    "PROJECT_MODULE",
    "PROJECT_NAMESPACE",
    "RuntimeDeclarationSpec",
    "SOURCE_PROGRAM_MODULE",
    "SOURCE_PROGRAM_NAMESPACE",
    "write_gnu_hello_native_source_compiled_authority_inputs",
]
