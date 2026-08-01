"""Produce GNU hello's checked environment-family adapter inputs.

This is a fail-closed evidence assembler.  It binds the exact source execution,
compiled authority, source bundle, candidate runtime, and candidate static PE
inventories, then emits the concrete Lean declarations consumed by
``gnu_hello_native_source_environment_family``.

The current candidate-runtime v1 interface contains only one environment value
and static indirect-control data.  That cannot establish machine-level
external refinement or launch coverage for an admitted environment pair.  Such
an input is rejected with a precise interface diagnostic.  The v2 interface
accepted here adds explicit, content-addressed theorem declarations; their
types are checked by Lean after generation.  Python never treats a status field
or declaration name as proof.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from ...errors import StageAInputError
from ...native_source_equivalence import validate_native_source_bundle_manifest
from .gnu_hello_native_source_environment_family import (
    GNU_HELLO_ENVIRONMENT_FAMILY_INPUT_FORMAT,
)


GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_MODULE = (
    "GeneratedGnuHelloNativeSourceEnvironmentFamilyInputs"
)
GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloNativeSourceEnvironmentFamilyInputs"
)
GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_REPORT_FORMAT = (
    "stage-a-gnu-hello-native-source-environment-family-input-producer-v1"
)

_COMPILED_AUTHORITY_FORMAT = "stage-a-relational-phase-v1"
_SOURCE_EXECUTION_FORMAT = "stage-a-gnu-hello-source-execution-assembly-v2"
_RUNTIME_V1_FORMAT = "stage-a-native-source-candidate-runtime-declarations-v1"
_RUNTIME_V2_FORMAT = "stage-a-native-source-candidate-runtime-declarations-v2"
_STATIC_FORMAT = "stage-a-native-source-candidate-static-authority-v1"

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_DECLARATION = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)

_RUNTIME_BASE_FIELDS = {
    "module_sources",
    "environment",
    "indirect_targets",
    "indirect_targets_valid",
    "callable_external",
    "callable_bound",
}
_ENVIRONMENT_INTERFACE_FIELDS = {
    "context",
    "sites",
    "static_authority",
    "pair_relation",
    "pair_realizable",
    "external_evidence_at",
    "source_family_at",
    "launch_realizable_at",
}
_ENVIRONMENT_INTERFACE_KINDS = {
    "context": "static_proof_context",
    "sites": "opaque_lockstep_call_sites",
    "static_authority": "static_native_source_environment_family_authority",
    "pair_relation": "native_source_environment_pair_relation",
    "pair_realizable": "proof",
    "external_evidence_at": "exact_world_native_external_evidence_family",
    "source_family_at": "checked_native_source_launch_family",
    "launch_realizable_at": "native_compilation_launch_realizable_family",
}

_MISSING_INTERFACE = (
    "candidate runtime declarations lack lean.environment_family; the smallest "
    "missing upstream interface is a content-addressed declaration inventory "
    "for context, sites, static_authority, pair_relation, pair_realizable, "
    "external_evidence_at, source_family_at, and launch_realizable_at. A fixed "
    "NativeWorldEnvironment value cannot prove ExactWorldNativeExternalEvidence "
    "or admitted-pair source/compiled launch coverage"
)


class GnuHelloEnvironmentFamilyInputProducerError(StageAInputError):
    """The exact inputs cannot soundly produce an environment family."""


@dataclass(frozen=True)
class GnuHelloEnvironmentFamilyInputOutputs:
    module: Path
    environment_inputs: Path
    report: Path


@dataclass(frozen=True)
class _LeanRef:
    module: str
    declaration: str
    kind: str

    @classmethod
    def read(
        cls,
        value: object,
        label: str,
        *,
        expected_kind: str | None = None,
    ) -> "_LeanRef":
        row = _object(value, label)
        _exact_keys(row, {"module", "declaration", "kind"}, label)
        result = cls(
            module=_stage_a_module(row["module"], f"{label}.module"),
            declaration=_lean_declaration(
                row["declaration"], f"{label}.declaration"
            ),
            kind=_string(row["kind"], f"{label}.kind"),
        )
        if expected_kind is not None and result.kind != expected_kind:
            raise GnuHelloEnvironmentFamilyInputProducerError(
                f"{label}.kind must be {expected_kind}"
            )
        return result


def write_gnu_hello_native_source_environment_family_inputs(
    out: Path | str,
    *,
    source_execution_manifest: Path | str,
    compiled_authority_manifest: Path | str,
    source_bundle_manifest: Path | str,
    candidate_runtime_declarations: Path | str,
    candidate_static_authority: Path | str,
    bundle_validator: Callable[[Path | str], dict[str, Any]] = (
        validate_native_source_bundle_manifest
    ),
) -> GnuHelloEnvironmentFamilyInputOutputs:
    """Bind exact inventories and emit the downstream module/input JSON.

    Neither binary is opened or executed.  Candidate identity comes entirely
    from mutually checked static/runtime/compiled manifests.
    """

    execution_path = Path(source_execution_manifest)
    authority_path = Path(compiled_authority_manifest)
    bundle_path = Path(source_bundle_manifest)
    runtime_path = Path(candidate_runtime_declarations)
    static_path = Path(candidate_static_authority)

    execution = _read_json(execution_path, "source-execution manifest")
    authority = _read_json(authority_path, "compiled-authority manifest")
    runtime = _read_json(runtime_path, "candidate runtime declarations")
    static = _read_json(static_path, "candidate static authority")
    bundle = bundle_validator(bundle_path)
    if not isinstance(bundle, dict):
        raise GnuHelloEnvironmentFamilyInputProducerError(
            "source bundle validator did not return an object"
        )

    execution_lean, execution_module = _source_execution(execution)
    authority_exports, authority_bindings, authority_module = (
        _compiled_authority(authority)
    )
    source_bundle_sha256, source_entry_rva = _source_bundle(bundle)
    runtime_environment, interface, runtime_modules, runtime_candidate = (
        _runtime_interface(runtime, runtime_path)
    )
    static_pe, static_module, static_candidate = _static_interface(
        static, static_path
    )

    candidate_sha256 = _sha_field(
        authority_bindings, "candidate_sha256", "compiled-authority bindings"
    )
    for label, observed in (
        ("candidate runtime", runtime_candidate),
        ("candidate static authority", static_candidate),
    ):
        if observed != candidate_sha256:
            raise GnuHelloEnvironmentFamilyInputProducerError(
                f"{label} binds different candidate bytes"
            )
    if (
        _sha_field(
            authority_bindings,
            "source_bundle_sha256",
            "compiled-authority bindings",
        )
        != source_bundle_sha256
    ):
        raise GnuHelloEnvironmentFamilyInputProducerError(
            "compiled authority binds a different source bundle"
        )

    exact_compilation = _lean_declaration(
        authority_exports.get("exact_compilation"),
        "compiled-authority exact compilation",
    )
    launch_family = execution_lean["launch_family"]
    modules = sorted(
        {
            authority_module,
            execution_module,
            static_module,
            *runtime_modules,
            *(ref.module for ref in interface.values()),
        }
    )
    source = _lean_source(
        modules=modules,
        exact_compilation=exact_compilation,
        launch_family=launch_family,
        runtime_environment=runtime_environment,
        static_pe=static_pe,
        interface=interface,
    )

    bindings: dict[str, str | int] = {
        "compiled_authority_manifest_sha256": _file_sha256(authority_path),
        "source_execution_manifest_sha256": _file_sha256(execution_path),
        "source_bundle_sha256": source_bundle_sha256,
        "attestation_core_sha256": _sha_field(
            authority_bindings,
            "attestation_core_sha256",
            "compiled-authority bindings",
        ),
        "candidate_sha256": candidate_sha256,
        "source_entry_rva": source_entry_rva,
        "compiled_entry_rva": _natural(
            authority_bindings.get("candidate_entry_rva"),
            "compiled-authority candidate entry RVA",
            word=True,
        ),
    }
    generated_module = f"StageA.{GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_MODULE}"
    namespace = GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_NAMESPACE
    inputs = {
        "format": GNU_HELLO_ENVIRONMENT_FAMILY_INPUT_FORMAT,
        "bindings": bindings,
        "lean": {
            "imports": [authority_module, execution_module, generated_module],
            "context": f"{namespace}.context",
            "sites": f"{namespace}.sites",
            "static_compilation": exact_compilation,
            "static_authority": f"{namespace}.staticAuthority",
            "source_launch_family": launch_family,
            "pair_relation": f"{namespace}.PairRelated",
            "pair_realizable": f"{namespace}.pairRealizable",
            "external_evidence_at": f"{namespace}.externalEvidenceAt",
            "source_family_at": f"{namespace}.sourceFamilyAt",
            "launch_realizable_at": f"{namespace}.launchRealizableAt",
        },
    }

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    module_path = stage_a / f"{GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_MODULE}.lean"
    inputs_path = root / "environment-family-inputs.json"
    report_path = root / "environment-family-input-producer.json"
    module_path.write_text(source, encoding="ascii")
    _write_json(inputs_path, inputs)
    _write_json(
        report_path,
        {
            "format": GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_REPORT_FORMAT,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "proof_authority": False,
            "acceptance_authority": False,
            "inputs": {
                "candidate_runtime_declarations_sha256": _file_sha256(runtime_path),
                "candidate_static_authority_sha256": _file_sha256(static_path),
                "compiled_authority_manifest_sha256": _file_sha256(authority_path),
                "source_bundle_manifest_sha256": _file_sha256(bundle_path),
                "source_execution_manifest_sha256": _file_sha256(execution_path),
            },
            "module": generated_module,
            "environment_family_input_sha256": _file_sha256(inputs_path),
        },
    )
    return GnuHelloEnvironmentFamilyInputOutputs(
        module=module_path,
        environment_inputs=inputs_path,
        report=report_path,
    )


def _lean_source(
    *,
    modules: list[str],
    exact_compilation: str,
    launch_family: str,
    runtime_environment: str,
    static_pe: str,
    interface: Mapping[str, _LeanRef],
) -> str:
    imports = "\n".join(
        f"import {module}"
        for module in sorted(
            {*modules, "StageA.RelationalNativeSourceEnvironmentFamilyEvidence"}
        )
    )
    namespace = GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_NAMESPACE
    ref = lambda name: interface[name].declaration
    return f"""{imports}

namespace {namespace}

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge
open StageA.Relational.NativeSource

noncomputable section

abbrev staticCompilation : ExactNativeCompilation :=
  {exact_compilation}

abbrev context : StaticProofContext :=
  {ref("context")}

def sites : List OpaqueLockstepCallSite :=
  {ref("sites")}

abbrev candidateRuntimeEnvironment : NativeWorldEnvironment :=
  {runtime_environment}

abbrev exactCandidatePe : PE32 :=
  {static_pe}

/-- Bind the source-execution proof to the exact project selected by the
compiled authority. -/
def sourceLaunchFamilyAnchor :
    CheckedNativeSourceLaunchFamily staticCompilation.project :=
  {launch_family}

theorem candidateRuntimeEnvironmentExact :
    staticCompilation.machineAuthority.environment =
      candidateRuntimeEnvironment := by
  rfl

theorem exactCandidatePeBound :
    staticCompilation.artifact.pe = exactCandidatePe := by
  rfl

def staticAuthority :
    StaticNativeSourceEnvironmentFamilyAuthority context staticCompilation :=
  {ref("static_authority")}

abbrev PairRelated
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) : Prop :=
  {ref("pair_relation")} sourceEnvironment nativeEnvironment

theorem pairRealizable : exists sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment :=
  {ref("pair_realizable")}

theorem externalEvidenceAt : forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
    ExactWorldNativeExternalEvidence context
      (exactNativeCompilationAtEnvironments staticCompilation sourceEnvironment
        nativeEnvironment).project.worldProgram
      (exactNativeCompilationAtEnvironments staticCompilation sourceEnvironment
        nativeEnvironment).machineAuthority.program sites sourceEnvironment :=
  {ref("external_evidence_at")}

theorem sourceFamilyAt : forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
    CheckedNativeSourceLaunchFamily
      (nativeSourceProjectWithExternalEnvironment staticCompilation.project
        sourceEnvironment) :=
  {ref("source_family_at")}

theorem launchRealizableAt : forall sourceEnvironment nativeEnvironment,
    PairRelated sourceEnvironment nativeEnvironment ->
    NativeCompilationLaunchRealizable
      (exactCompiledPE32AuthorityWithEnvironment
        staticCompilation.machineAuthority nativeEnvironment) :=
  {ref("launch_realizable_at")}

/-- The kernel checks the four relation-indexed evidence families as one
package, so their admission relation cannot drift independently. -/
def admittedPairEvidence :
    CheckedNativeSourceAdmittedPairEvidence context sites staticCompilation
      PairRelated := {{
  pairRealizable := pairRealizable
  externalEvidenceAt := externalEvidenceAt
  sourceFamilyAt := sourceFamilyAt
  launchRealizableAt := launchRealizableAt
}}

end

end {namespace}
"""


def _runtime_interface(
    value: dict[str, Any], path: Path
) -> tuple[str, dict[str, _LeanRef], set[str], str]:
    _exact_keys(value, {"format", "candidate_sha256", "lean"}, "runtime declarations")
    runtime_format = value["format"]
    lean = _object(value["lean"], "runtime Lean declarations")
    if runtime_format == _RUNTIME_V1_FORMAT:
        if set(lean) != _RUNTIME_BASE_FIELDS:
            _exact_keys(lean, _RUNTIME_BASE_FIELDS, "runtime Lean declarations")
        raise GnuHelloEnvironmentFamilyInputProducerError(_MISSING_INTERFACE)
    if runtime_format != _RUNTIME_V2_FORMAT:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            "unsupported candidate runtime declaration format"
        )
    _exact_keys(
        lean,
        _RUNTIME_BASE_FIELDS | {"environment_family"},
        "runtime Lean declarations",
    )
    sources = _module_sources(lean["module_sources"], path.parent)
    environment = _LeanRef.read(
        lean["environment"],
        "runtime environment",
        expected_kind="native_world_environment",
    )
    _verify_ref(environment, sources, "runtime environment")
    raw_interface = _object(
        lean["environment_family"], "runtime environment-family interface"
    )
    _exact_keys(
        raw_interface,
        _ENVIRONMENT_INTERFACE_FIELDS,
        "runtime environment-family interface",
    )
    interface = {
        name: _LeanRef.read(
            raw_interface[name],
            f"runtime environment-family {name}",
            expected_kind=_ENVIRONMENT_INTERFACE_KINDS[name],
        )
        for name in sorted(_ENVIRONMENT_INTERFACE_FIELDS)
    }
    for name, declaration in interface.items():
        _verify_ref(
            declaration, sources, f"runtime environment-family {name}"
        )
    return (
        environment.declaration,
        interface,
        set(sources),
        _sha(value["candidate_sha256"], "runtime candidate SHA-256"),
    )


def _static_interface(
    value: dict[str, Any], path: Path
) -> tuple[str, str, str]:
    if value.get("format") != _STATIC_FORMAT:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            "unsupported candidate static-authority format"
        )
    candidate = _object(value.get("candidate"), "static candidate binding")
    candidate_sha256 = _sha(
        candidate.get("sha256"), "static candidate SHA-256"
    )
    module_name = _string(value.get("module"), "static authority module")
    module = _stage_a_module(f"StageA.{module_name}", "static authority module")
    source = path.parent / "StageA" / f"{module_name}.lean"
    if not source.is_file():
        raise GnuHelloEnvironmentFamilyInputProducerError(
            "candidate static-authority Lean module is missing"
        )
    interface = _object(
        value.get("compiled_identity_interface"), "compiled identity interface"
    )
    compiled_pe = _lean_declaration(
        interface.get("compiled_pe"), "compiled identity interface.compiled_pe"
    )
    _verify_declared_symbol(source, compiled_pe, "compiled PE")
    return compiled_pe, module, candidate_sha256


def _source_execution(value: dict[str, Any]) -> tuple[dict[str, str], str]:
    if (
        value.get("format") != _SOURCE_EXECUTION_FORMAT
        or value.get("launch_scope") != "all_checked_pe32_console_launches"
        or value.get("launch_family_complete") is not True
        or value.get("acceptance_authority") is not False
        or value.get("blockers") != []
    ):
        raise GnuHelloEnvironmentFamilyInputProducerError(
            "source execution is not a complete all-launch proof"
        )
    lean = _object(value.get("lean"), "source-execution Lean exports")
    required = {
        "proof_module",
        "audit_module",
        "domain",
        "invariant_family_evidence",
        "launch_family",
    }
    _exact_keys(lean, required, "source-execution Lean exports")
    result = {
        name: _lean_declaration(raw, f"source-execution {name}")
        for name, raw in lean.items()
    }
    return result, _stage_a_module(result["proof_module"], "source proof module")


def _compiled_authority(
    value: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], str]:
    if (
        value.get("format") != _COMPILED_AUTHORITY_FORMAT
        or value.get("phase") != "native-source-compiled-authority"
        or value.get("executes_original_binary") is not False
        or value.get("executes_candidate_binary") is not False
        or value.get("proof_authority") is not False
        or value.get("acceptance_authority") is not False
    ):
        raise GnuHelloEnvironmentFamilyInputProducerError(
            "compiled authority has an invalid trust role"
        )
    exports = _object(value.get("exports"), "compiled-authority exports")
    bindings = _object(value.get("bindings"), "compiled-authority bindings")
    modules = value.get("modules")
    if not isinstance(modules, list):
        raise GnuHelloEnvironmentFamilyInputProducerError(
            "compiled-authority modules must be an array"
        )
    proof_modules = [
        module for module in modules
        if isinstance(module, str) and not module.endswith("Audit")
    ]
    if len(proof_modules) != 1:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            "compiled authority must export exactly one proof module"
        )
    return (
        exports,
        bindings,
        _stage_a_module(f"StageA.{proof_modules[0]}", "authority proof module"),
    )


def _source_bundle(value: dict[str, Any]) -> tuple[str, int]:
    hashes = _object(value.get("hashes"), "source-bundle hashes")
    return (
        _sha(hashes.get("source_bundle_sha256"), "source-bundle SHA-256"),
        _natural(value.get("entry_rva"), "source-bundle entry RVA", word=True),
    )


def _module_sources(value: object, root: Path) -> dict[str, Path]:
    if not isinstance(value, list) or not value:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            "runtime module_sources must be a non-empty array"
        )
    result: dict[str, Path] = {}
    for index, raw in enumerate(value):
        label = f"runtime module_sources[{index}]"
        row = _object(raw, label)
        _exact_keys(row, {"module", "path", "sha256"}, label)
        module = _stage_a_module(row["module"], f"{label}.module")
        path = Path(_string(row["path"], f"{label}.path"))
        source = path if path.is_absolute() else root / path
        source = source.resolve()
        if module in result or not source.is_file() or source.suffix != ".lean":
            raise GnuHelloEnvironmentFamilyInputProducerError(
                f"{label} is duplicate or not a Lean source"
            )
        if _file_sha256(source) != _sha(row["sha256"], f"{label}.sha256"):
            raise GnuHelloEnvironmentFamilyInputProducerError(
                f"{label} source hash mismatch"
            )
        result[module] = source
    return result


def _verify_ref(
    ref: _LeanRef, sources: Mapping[str, Path], label: str
) -> None:
    source = sources.get(ref.module)
    if source is None:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} module is absent from content-addressed module_sources"
        )
    _verify_declared_symbol(source, ref.declaration, label)


def _verify_declared_symbol(source: Path, declaration: str, label: str) -> None:
    text = source.read_text(encoding="utf-8")
    symbol = re.escape(declaration.rsplit(".", 1)[-1])
    if re.search(rf"(?m)^\s*(?:axiom|opaque)\s+{symbol}\b", text):
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} refers to an unchecked axiom or opaque declaration"
        )
    if not re.search(rf"(?m)^\s*(?:def|abbrev|theorem)\s+{symbol}\b", text):
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} is not declared by its content-addressed Lean module"
        )


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"cannot read {label}: {error}"
        ) from error
    return _object(value, label)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} must be an object"
        )
    return dict(value)


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} has a non-canonical schema: "
            f"missing={sorted(expected - set(value))}, "
            f"unexpected={sorted(set(value) - expected)}"
        )


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} must be a non-empty printable string"
        )
    return value


def _sha(value: object, label: str) -> str:
    text = _string(value, label)
    if _SHA256.fullmatch(text) is None:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} must be a lowercase SHA-256"
        )
    return text


def _sha_field(value: Mapping[str, Any], name: str, label: str) -> str:
    return _sha(value.get(name), f"{label}.{name}")


def _natural(value: object, label: str, *, word: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} must be a natural number"
        )
    if word and value > 0xFFFFFFFF:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} must fit a 32-bit word"
        )
    return value


def _lean_declaration(value: object, label: str) -> str:
    text = _string(value, label)
    if _LEAN_DECLARATION.fullmatch(text) is None or not text.startswith("StageA."):
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} must be a canonical StageA Lean declaration"
        )
    return text


def _stage_a_module(value: object, label: str) -> str:
    text = _string(value, label)
    if _STAGE_A_MODULE.fullmatch(text) is None:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"{label} must be a canonical StageA module"
        )
    return text


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise GnuHelloEnvironmentFamilyInputProducerError(
            f"cannot hash {path}: {error}"
        ) from error


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )

__all__ = [
    "GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_MODULE",
    "GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_NAMESPACE",
    "GNU_HELLO_ENVIRONMENT_FAMILY_INPUTS_REPORT_FORMAT",
    "GnuHelloEnvironmentFamilyInputOutputs",
    "GnuHelloEnvironmentFamilyInputProducerError",
    "write_gnu_hello_native_source_environment_family_inputs",
]
