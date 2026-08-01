"""Bind GNU hello artifacts to the generic native-source environment family.

This module is a fixture adapter.  It does not manufacture environment
semantics or promote report status to proof authority.  It validates the
exact compiled-authority and original/source-execution manifests, binds them
to a revalidated native-source bundle, and passes explicit Lean evidence to
the generic environment-family generator.

The generated Lean types enforce the important semantic boundary:

* the admitted environment relation is inhabited;
* every admitted pair has ``ExactWorldNativeExternalEvidence``;
* source and compiled launch evidence is universal over admitted pairs; and
* compiler correctness is the sole project-specific axiom.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...native_source_equivalence import (
    NativeSourceEquivalenceError,
    validate_native_source_bundle_manifest,
)
from .native_source_environment_family_evidence import (
    NativeSourceAcceptanceBindings,
    NativeSourceEnvironmentFamilyEvidenceSpec,
    write_native_source_environment_family_evidence,
)


GNU_HELLO_ENVIRONMENT_FAMILY_INPUT_FORMAT = (
    "stage-a-gnu-hello-native-source-environment-family-input-v1"
)
GNU_HELLO_ENVIRONMENT_FAMILY_RESOLVED_FORMAT = (
    "stage-a-gnu-hello-native-source-environment-family-resolved-v1"
)
GNU_HELLO_ENVIRONMENT_FAMILY_MODULE = (
    "GeneratedGnuHelloNativeSourceEnvironmentFamilyEvidence"
)
GNU_HELLO_ENVIRONMENT_FAMILY_AUDIT_MODULE = (
    "GeneratedGnuHelloNativeSourceEnvironmentFamilyEvidenceAudit"
)

_COMPILED_AUTHORITY_FORMAT = "stage-a-relational-phase-v1"
_SOURCE_EXECUTION_FORMAT = "stage-a-gnu-hello-source-execution-assembly-v2"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_NAME_PARTS = frozenset(
    {
        "admit",
        "axiom",
        "by",
        "def",
        "import",
        "native_decide",
        "opaque",
        "partial",
        "sorry",
        "theorem",
        "unsafe",
    }
)


class GnuHelloEnvironmentFamilyAdapterError(StageAInputError):
    """GNU hello environment-family inputs are incomplete or inconsistent."""


@dataclass(frozen=True)
class GnuHelloEnvironmentFamilyOutputs:
    """Files emitted by the adapter and generic evidence generator."""

    evidence: Path
    audit: Path
    acceptance_declarations: Path
    axiom_expectation: Path
    resolved_inputs: Path


def write_gnu_hello_native_source_environment_family(
    out: Path | str,
    *,
    compiled_authority_manifest: Path | str,
    source_execution_manifest: Path | str,
    source_bundle_manifest: Path | str,
    environment_inputs: Path | str,
) -> GnuHelloEnvironmentFamilyOutputs:
    """Validate GNU hello bindings and emit generic family evidence.

    ``environment_inputs`` contains only explicit static-context and
    environment-pair declarations plus literal artifact bindings.  The exact
    compilation and the two artifact proof modules are inferred from checked
    phase manifests, preventing the adapter input from silently selecting a
    different compiled project.
    """

    authority_path = Path(compiled_authority_manifest)
    execution_path = Path(source_execution_manifest)
    bundle_path = Path(source_bundle_manifest)
    inputs_path = Path(environment_inputs)

    authority = _read_json(authority_path, "compiled-authority manifest")
    execution = _read_json(execution_path, "source-execution manifest")
    inputs = _read_json(inputs_path, "environment-family inputs")
    try:
        bundle = validate_native_source_bundle_manifest(bundle_path)
    except (OSError, NativeSourceEquivalenceError) as error:
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"source bundle did not revalidate: {error}"
        ) from error

    authority_exports, authority_bindings, authority_module = (
        _validate_compiled_authority(authority)
    )
    execution_lean, execution_module = _validate_source_execution(execution)
    source_bundle_sha256, source_entry_rva = _validate_source_bundle(bundle)
    bindings, lean = _validate_environment_inputs(inputs)

    actual_bindings: dict[str, str | int] = {
        "compiled_authority_manifest_sha256": _sha256(authority_path),
        "source_execution_manifest_sha256": _sha256(execution_path),
        "source_bundle_sha256": source_bundle_sha256,
        "attestation_core_sha256": _sha_field(
            authority_bindings,
            "attestation_core_sha256",
            "compiled-authority bindings",
        ),
        "candidate_sha256": _sha_field(
            authority_bindings,
            "candidate_sha256",
            "compiled-authority bindings",
        ),
        "source_entry_rva": source_entry_rva,
        "compiled_entry_rva": _natural(
            authority_bindings.get("candidate_entry_rva"),
            "compiled-authority candidate entry RVA",
            word=True,
        ),
    }
    for name, actual in actual_bindings.items():
        if bindings.get(name) != actual:
            raise GnuHelloEnvironmentFamilyAdapterError(
                f"environment-family {name} mismatch"
            )

    exact_compilation = _lean_identifier(
        authority_exports.get("exact_compilation"),
        "compiled-authority exact compilation",
    )
    if lean["static_compilation"] != exact_compilation:
        raise GnuHelloEnvironmentFamilyAdapterError(
            "environment-family static compilation differs from the exact "
            "compiled-authority export"
        )
    if lean["source_launch_family"] != execution_lean["launch_family"]:
        raise GnuHelloEnvironmentFamilyAdapterError(
            "environment-family source launch anchor differs from the exact "
            "source-execution export"
        )

    imports = tuple(lean["imports"])
    required_imports = {authority_module, execution_module}
    missing_imports = sorted(required_imports - set(imports))
    if missing_imports:
        raise GnuHelloEnvironmentFamilyAdapterError(
            "environment-family imports omit exact artifact modules: "
            + ", ".join(missing_imports)
        )

    spec = NativeSourceEnvironmentFamilyEvidenceSpec(
        imports=imports,
        context=lean["context"],
        sites=lean["sites"],
        static_compilation=exact_compilation,
        static_authority=lean["static_authority"],
        pair_relation=lean["pair_relation"],
        pair_realizable=lean["pair_realizable"],
        external_evidence_at=lean["external_evidence_at"],
        source_family_at=lean["source_family_at"],
        launch_realizable_at=lean["launch_realizable_at"],
        acceptance_bindings=NativeSourceAcceptanceBindings(
            compiled_authority_manifest_sha256=str(
                actual_bindings["compiled_authority_manifest_sha256"]
            ),
            source_bundle_sha256=source_bundle_sha256,
            attestation_core_sha256=str(
                actual_bindings["attestation_core_sha256"]
            ),
            candidate_sha256=str(actual_bindings["candidate_sha256"]),
            source_entry_rva=source_entry_rva,
            compiled_entry_rva=int(actual_bindings["compiled_entry_rva"]),
        ),
        namespace=(
            "StageA.GeneratedRelational."
            "GnuHelloNativeSourceEnvironmentFamilyEvidence"
        ),
        output_module=GNU_HELLO_ENVIRONMENT_FAMILY_MODULE,
        audit_output_module=GNU_HELLO_ENVIRONMENT_FAMILY_AUDIT_MODULE,
        acceptance_namespace=(
            "StageA.GeneratedRelational.GnuHelloNativeSourceAcceptance"
        ),
        acceptance_output_module="GeneratedGnuHelloNativeSourceAcceptance",
        acceptance_audit_output_module=(
            "GeneratedGnuHelloNativeSourceAcceptanceAudit"
        ),
        acceptance_theorem_name=(
            "gnuHelloNativeSourceEnvironmentFamilyEquivalence"
        ),
    )

    root = Path(out)
    evidence, audit, declarations, expectation = (
        write_native_source_environment_family_evidence(root, spec)
    )
    resolved_path = root / "environment-family-resolved-inputs.json"
    resolved_path.write_text(
        json.dumps(
            {
                "format": GNU_HELLO_ENVIRONMENT_FAMILY_RESOLVED_FORMAT,
                "bindings": actual_bindings,
                "inputs": {
                    "compiled_authority_manifest_sha256": _sha256(authority_path),
                    "environment_inputs_sha256": _sha256(inputs_path),
                    "source_bundle_manifest_sha256": _sha256(bundle_path),
                    "source_execution_manifest_sha256": _sha256(execution_path),
                },
                "lean": {
                    "imports": list(imports),
                    "context": spec.context,
                    "sites": spec.sites,
                    "static_compilation": spec.static_compilation,
                    "static_authority": spec.static_authority,
                    "source_launch_family": lean["source_launch_family"],
                    "pair_relation": spec.pair_relation,
                    "pair_realizable": spec.pair_realizable,
                    "external_evidence_at": spec.external_evidence_at,
                    "source_family_at": spec.source_family_at,
                    "launch_realizable_at": spec.launch_realizable_at,
                    "generated_admitted_pair_evidence": (
                        f"{spec.namespace}.{spec.admitted_pair_evidence_name}"
                    ),
                },
                "policy": {
                    "admitted_environment_pair_nonempty": True,
                    "external_evidence": "ExactWorldNativeExternalEvidence",
                    "source_launch_scope": "all_admitted_source_environments",
                    "compiled_launch_scope": "all_admitted_native_environments",
                    "admission_witness_threaded": True,
                    "project_specific_axioms": [
                        f"{spec.namespace}.{spec.toolchain_axiom_name}"
                    ],
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="ascii",
    )
    return GnuHelloEnvironmentFamilyOutputs(
        evidence=evidence,
        audit=audit,
        acceptance_declarations=declarations,
        axiom_expectation=expectation,
        resolved_inputs=resolved_path,
    )


def _validate_compiled_authority(
    value: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], str]:
    expected = {
        "format",
        "phase",
        "executes_original_binary",
        "executes_candidate_binary",
        "inputs",
        "proof_authority",
        "acceptance_authority",
        "modules",
        "exports",
        "bindings",
    }
    _exact_keys(value, expected, "compiled-authority manifest")
    if (
        value["format"] != _COMPILED_AUTHORITY_FORMAT
        or value["phase"] != "native-source-compiled-authority"
        or value["executes_original_binary"] is not False
        or value["executes_candidate_binary"] is not False
        or value["proof_authority"] is not False
        or value["acceptance_authority"] is not False
    ):
        raise GnuHelloEnvironmentFamilyAdapterError(
            "compiled-authority manifest has an invalid trust role"
        )
    exports = _object(value["exports"], "compiled-authority exports")
    _exact_keys(
        exports,
        {
            "profile",
            "project",
            "artifact",
            "machine_authority",
            "project_valid",
            "profile_pinned",
            "profile_matches",
            "built_from",
            "exact_compilation",
        },
        "compiled-authority exports",
    )
    bindings = _object(value["bindings"], "compiled-authority bindings")
    _exact_keys(
        bindings,
        {
            "source_bundle_sha256",
            "attestation_core_sha256",
            "candidate_sha256",
            "candidate_entry_rva",
            "candidate_imports_sha256",
            "relocation_inventory_sha256",
        },
        "compiled-authority bindings",
    )
    for name in (
        "source_bundle_sha256",
        "attestation_core_sha256",
        "candidate_sha256",
        "candidate_imports_sha256",
        "relocation_inventory_sha256",
    ):
        _sha_field(bindings, name, "compiled-authority bindings")
    _natural(
        bindings["candidate_entry_rva"],
        "compiled-authority candidate entry RVA",
        word=True,
    )
    modules = _string_list(value["modules"], "compiled-authority modules")
    proof_modules = [module for module in modules if not module.endswith("Audit")]
    if len(proof_modules) != 1:
        raise GnuHelloEnvironmentFamilyAdapterError(
            "compiled-authority manifest must name exactly one proof module"
        )
    module = _stage_a_module(f"StageA.{proof_modules[0]}", "authority module")
    _lean_identifier(exports["exact_compilation"], "exact compilation")
    return exports, bindings, module


def _validate_source_execution(
    value: dict[str, Any],
) -> tuple[dict[str, str], str]:
    _exact_keys(
        value,
        {
            "format",
            "launch_scope",
            "inputs",
            "counts",
            "lean",
            "launch_family_complete",
            "acceptance_authority",
            "blockers",
            "frontiers",
        },
        "source-execution manifest",
    )
    if (
        value["format"] != _SOURCE_EXECUTION_FORMAT
        or value["launch_scope"] != "all_checked_pe32_console_launches"
        or value["launch_family_complete"] is not True
        or value["acceptance_authority"] is not False
        or value["blockers"] != []
    ):
        raise GnuHelloEnvironmentFamilyAdapterError(
            "source-execution manifest is not a complete all-launch proof"
        )
    lean_raw = _object(value["lean"], "source-execution Lean exports")
    _exact_keys(
        lean_raw,
        {
            "proof_module",
            "audit_module",
            "domain",
            "invariant_family_evidence",
            "launch_family",
        },
        "source-execution Lean exports",
    )
    lean = {
        name: _lean_identifier(raw, f"source-execution {name}")
        for name, raw in lean_raw.items()
    }
    module = _stage_a_module(lean["proof_module"], "source-execution proof module")
    _stage_a_module(lean["audit_module"], "source-execution audit module")
    return lean, module


def _validate_source_bundle(value: Mapping[str, Any]) -> tuple[str, int]:
    hashes = _object(value.get("hashes"), "source-bundle hashes")
    digest = _sha_field(hashes, "source_bundle_sha256", "source-bundle hashes")
    entry = _natural(value.get("entry_rva"), "source-bundle entry RVA", word=True)
    return digest, entry


def _validate_environment_inputs(
    value: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    _exact_keys(value, {"format", "bindings", "lean"}, "environment-family inputs")
    if value["format"] != GNU_HELLO_ENVIRONMENT_FAMILY_INPUT_FORMAT:
        raise GnuHelloEnvironmentFamilyAdapterError(
            "unsupported environment-family input format"
        )
    bindings = _object(value["bindings"], "environment-family bindings")
    _exact_keys(
        bindings,
        {
            "compiled_authority_manifest_sha256",
            "source_execution_manifest_sha256",
            "source_bundle_sha256",
            "attestation_core_sha256",
            "candidate_sha256",
            "source_entry_rva",
            "compiled_entry_rva",
        },
        "environment-family bindings",
    )
    for name in (
        "compiled_authority_manifest_sha256",
        "source_execution_manifest_sha256",
        "source_bundle_sha256",
        "attestation_core_sha256",
        "candidate_sha256",
    ):
        _sha_field(bindings, name, "environment-family bindings")
    for name in ("source_entry_rva", "compiled_entry_rva"):
        _natural(bindings[name], f"environment-family {name}", word=True)

    lean = _object(value["lean"], "environment-family Lean inputs")
    _exact_keys(
        lean,
        {
            "imports",
            "context",
            "sites",
            "static_compilation",
            "static_authority",
            "source_launch_family",
            "pair_relation",
            "pair_realizable",
            "external_evidence_at",
            "source_family_at",
            "launch_realizable_at",
        },
        "environment-family Lean inputs",
    )
    imports = _string_list(lean["imports"], "environment-family imports")
    lean["imports"] = [
        _stage_a_module(module, f"environment-family imports[{index}]")
        for index, module in enumerate(imports)
    ]
    for name in set(lean) - {"imports"}:
        lean[name] = _lean_identifier(
            lean[name], f"environment-family {name}"
        )
    return bindings, lean


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"cannot read {label}: {error}"
        ) from error
    return _object(value, label)


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"cannot hash {path}: {error}"
        ) from error


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GnuHelloEnvironmentFamilyAdapterError(f"{label} must be an object")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        unexpected = sorted(set(value) - expected)
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"{label} has a non-canonical schema: missing={missing}, "
            f"unexpected={unexpected}"
        )


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"{label} must be a non-empty array"
        )
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise GnuHelloEnvironmentFamilyAdapterError(
                f"{label}[{index}] must be a non-empty string"
            )
        result.append(item)
    if len(set(result)) != len(result):
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"{label} must not contain duplicates"
        )
    return result


def _sha_field(value: Mapping[str, Any], name: str, label: str) -> str:
    raw = value.get(name)
    if not isinstance(raw, str) or _SHA256.fullmatch(raw) is None:
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"{label}.{name} must be lowercase SHA-256"
        )
    return raw


def _natural(value: object, label: str, *, word: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"{label} must be a natural number"
        )
    if word and value > 0xFFFFFFFF:
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"{label} must fit a 32-bit word"
        )
    return value


def _lean_identifier(value: object, label: str) -> str:
    if not (
        isinstance(value, str)
        and _LEAN_IDENTIFIER.fullmatch(value) is not None
        and all(
            part.casefold() not in _FORBIDDEN_NAME_PARTS
            for part in value.split(".")
        )
    ):
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"{label} must be a canonical Lean declaration"
        )
    return value


def _stage_a_module(value: object, label: str) -> str:
    declaration = _lean_identifier(value, label)
    if _STAGE_A_MODULE.fullmatch(declaration) is None:
        raise GnuHelloEnvironmentFamilyAdapterError(
            f"{label} must be a canonical StageA module"
        )
    return declaration


__all__ = [
    "GNU_HELLO_ENVIRONMENT_FAMILY_AUDIT_MODULE",
    "GNU_HELLO_ENVIRONMENT_FAMILY_INPUT_FORMAT",
    "GNU_HELLO_ENVIRONMENT_FAMILY_MODULE",
    "GNU_HELLO_ENVIRONMENT_FAMILY_RESOLVED_FORMAT",
    "GnuHelloEnvironmentFamilyAdapterError",
    "GnuHelloEnvironmentFamilyOutputs",
    "write_gnu_hello_native_source_environment_family",
]
