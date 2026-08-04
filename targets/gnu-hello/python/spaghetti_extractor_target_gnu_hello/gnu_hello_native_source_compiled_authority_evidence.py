"""Build GNU hello's native-source compiled-authority evidence package.

This module is deliberately an evidence producer, not a proof producer.  It
revalidates the source bundle and compilation attestation, derives every
binary binding from the candidate PE, checks exact Lean declaration exports,
and records live Nix realization identities.  The resulting declarations are
still untrusted input to :mod:`native_source_compiled_authority`; Lean must
elaborate the referenced artifacts before they have proof authority.

No manifest status is inspected.  Input declaration manifests describe only
content-addressed module sources and typed exports.  In particular, an
``axiom`` or ``opaque`` declaration cannot be presented as an exact source
artifact by this layer, and the final detached Lean axiom audit remains
mandatory.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.native_source_equivalence import (
    validate_native_source_bundle_manifest,
    validate_native_source_compilation_attestation,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.util import sha256_file


COMPILED_AUTHORITY_DECLARATIONS_FORMAT = (
    "stage-a-gnu-hello-native-source-compiled-authority-declarations-v1"
)
PROJECT_DECLARATIONS_FORMAT = (
    "stage-a-gnu-hello-native-source-project-declarations-v1"
)
RUNTIME_DECLARATIONS_FORMAT = (
    "stage-a-native-source-candidate-runtime-declarations-v1"
)
CANDIDATE_STATIC_AUTHORITY_FORMAT = (
    "stage-a-native-source-candidate-static-authority-v1"
)
NIX_REALIZATION_INPUT_FORMAT = "stage-a-nix-realization-identity-v1"
TOOLCHAIN_PROFILE_FORMAT = "stage-a-native-source-toolchain-profile-v1"
TOOLCHAIN_PROFILE_FILENAME = "native-source-toolchain-profile.json"

PROFILE_IDENTIFIER = "gnu-hello-native-source-checked-interpreter-v1"
OUTPUT_MODULE = "GeneratedGnuHelloNativeSourceCompiledAuthority"
AUDIT_OUTPUT_MODULE = "GeneratedGnuHelloNativeSourceCompiledAuthorityAudit"
OUTPUT_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloNativeSourceCompiledAuthority"
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NAR_HASH = re.compile(r"sha256-(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{44})\Z")
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LEAN_DECLARATION = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)

_PROJECT_LEAN_FIELDS = frozenset(
    {
        "module_sources",
        "world_program",
        "checked_input",
        "checked_input_nonempty",
        "bundle_manifest_artifact",
        "renderer_input_artifact",
        "source_artifacts",
        "source_artifact_roles_nodup",
        "profile_identifier",
        "tools",
    }
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
_RUNTIME_LEAN_FIELDS = frozenset(
    {
        "module_sources",
        "environment",
        "indirect_targets",
        "indirect_targets_valid",
        "callable_external",
        "callable_bound",
    }
)
_TOOL_ROLES = (
    "renderer",
    "lowering",
    "runtime",
    "compiler",
    "assembler",
    "linker",
    "abi",
)


class GnuHelloCompiledAuthorityEvidenceError(StageAInputError):
    """The compiled-authority evidence closure is incomplete or inconsistent."""


@dataclass(frozen=True)
class NixRealizationIdentity:
    """Expected identity of one already-realized Nix output."""

    output: Path
    derivation: Path
    nar_hash: str

    @classmethod
    def from_json(cls, path: Path | str) -> "NixRealizationIdentity":
        payload = _read_object(Path(path), "Nix realization identity")
        _require_exact_fields(
            payload,
            {"format", "output", "derivation", "nar_hash"},
            "Nix realization identity",
        )
        if payload["format"] != NIX_REALIZATION_INPUT_FORMAT:
            raise GnuHelloCompiledAuthorityEvidenceError(
                "unsupported Nix realization identity format"
            )
        output = Path(_string(payload["output"], "Nix output"))
        derivation = Path(_string(payload["derivation"], "Nix derivation"))
        nar_hash = _string(payload["nar_hash"], "Nix NAR hash")
        identity = cls(output=output, derivation=derivation, nar_hash=nar_hash)
        identity.validate()
        return identity

    def validate(self) -> None:
        if not self.output.is_absolute() or not self.output.is_dir():
            raise GnuHelloCompiledAuthorityEvidenceError(
                "Nix output must be an absolute realized directory"
            )
        if (
            not self.derivation.is_absolute()
            or self.derivation.suffix != ".drv"
            or not self.derivation.is_file()
        ):
            raise GnuHelloCompiledAuthorityEvidenceError(
                "Nix derivation must be an absolute realized .drv file"
            )
        if _NAR_HASH.fullmatch(self.nar_hash) is None:
            raise GnuHelloCompiledAuthorityEvidenceError(
                "Nix NAR hash must be an SRI SHA-256"
            )

    def canonical_payload(self) -> dict[str, str]:
        self.validate()
        return {
            "output": str(self.output.resolve()),
            "derivation": str(self.derivation.resolve()),
            "registered_deriver": str(self.derivation.resolve()),
            "nar_hash": self.nar_hash,
        }


NixInspector = Callable[[NixRealizationIdentity], NixRealizationIdentity]


def inspect_live_nix_realization(
    expected: NixRealizationIdentity,
) -> NixRealizationIdentity:
    """Read the registered deriver and NAR identity from the local Nix store."""

    expected.validate()
    try:
        info_process = subprocess.run(
            [
                "nix",
                "path-info",
                "--json-format",
                "1",
                str(expected.output.resolve()),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(info_process.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as error:
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"cannot inspect live Nix output: {error}"
        ) from error
    if not isinstance(payload, dict) or len(payload) != 1:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "Nix path-info did not return exactly one realized output"
        )
    raw_output, raw_info = next(iter(payload.items()))
    info = _object(raw_info, "Nix path-info record")
    registered = Path(_string(info.get("deriver"), "registered Nix deriver"))
    nar_hash = _string(info.get("narHash"), "registered Nix NAR hash")
    observed = NixRealizationIdentity(
        output=Path(raw_output), derivation=registered, nar_hash=nar_hash
    )
    observed.validate()
    return observed


def inspect_offline_nix_realization(
    expected: NixRealizationIdentity,
) -> NixRealizationIdentity:
    """Re-hash a graph-owned output without consulting the Nix database.

    The selected ``.drv`` path is supplied by Nix evaluation and is itself the
    content-addressed recipe identity.  A remote build sandbox need not contain
    that derivation file, and a CA output may have a different registered
    deriver after substitution.  Re-querying either fact inside the sandbox is
    therefore both unreliable and unnecessary.  We retain the selected recipe
    path verbatim and independently recompute the realized output's NAR hash.
    """

    expected.validate()
    try:
        hash_process = subprocess.run(
            [
                "nix",
                "--extra-experimental-features",
                "nix-command",
                "hash",
                "path",
                "--sri",
                str(expected.output.resolve()),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        observed = NixRealizationIdentity(
            output=expected.output.resolve(),
            derivation=expected.derivation,
            nar_hash=hash_process.stdout.strip(),
        )
        observed.validate()
        return observed
    except (
        OSError,
        subprocess.CalledProcessError,
        GnuHelloCompiledAuthorityEvidenceError,
    ) as error:
        if isinstance(error, GnuHelloCompiledAuthorityEvidenceError):
            raise
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"cannot inspect offline Nix realization: {error}"
        ) from error


@dataclass(frozen=True)
class LeanDeclarationRef:
    module: str
    declaration: str
    kind: str

    @classmethod
    def from_json(cls, value: object, label: str) -> "LeanDeclarationRef":
        row = _object(value, label)
        _require_exact_fields(row, {"module", "declaration", "kind"}, label)
        result = cls(
            module=_string(row["module"], f"{label}.module"),
            declaration=_string(row["declaration"], f"{label}.declaration"),
            kind=_string(row["kind"], f"{label}.kind"),
        )
        if _LEAN_MODULE.fullmatch(result.module) is None:
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"{label}.module is not a canonical StageA module"
            )
        if _LEAN_DECLARATION.fullmatch(result.declaration) is None:
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"{label}.declaration is not a canonical Lean declaration"
            )
        if not result.declaration.startswith("StageA."):
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"{label}.declaration must be below StageA"
            )
        return result


@dataclass(frozen=True)
class ExactArtifactRef:
    declaration: LeanDeclarationRef
    evidence_sha256: str

    @classmethod
    def from_json(cls, value: object, label: str) -> "ExactArtifactRef":
        row = _object(value, label)
        _require_exact_fields(row, {"ref", "evidence_sha256"}, label)
        declaration = LeanDeclarationRef.from_json(row["ref"], f"{label}.ref")
        if declaration.kind != "exact_source_artifact":
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"{label}.ref must have kind exact_source_artifact"
            )
        digest = _sha256(row["evidence_sha256"], f"{label}.evidence_sha256")
        return cls(declaration=declaration, evidence_sha256=digest)


def _module_sources(value: object, root: Path) -> dict[str, Path]:
    rows = _list(value, "Lean module sources")
    result: dict[str, Path] = {}
    for index, value in enumerate(rows):
        label = f"Lean module sources[{index}]"
        row = _object(value, label)
        _require_exact_fields(row, {"module", "path", "sha256"}, label)
        module = _string(row["module"], f"{label}.module")
        if _LEAN_MODULE.fullmatch(module) is None or module in result:
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"{label}.module is invalid or duplicated"
            )
        raw_path = Path(_string(row["path"], f"{label}.path"))
        source = raw_path if raw_path.is_absolute() else root / raw_path
        source = source.resolve()
        if not source.is_file() or source.suffix != ".lean":
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"{label}.path is not a Lean source file"
            )
        if sha256_file(source) != _sha256(row["sha256"], f"{label}.sha256"):
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"{label}.source hash mismatch"
            )
        result[module] = source
    if not result:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "Lean module source inventory must not be empty"
        )
    return result


def _verify_ref(
    ref: LeanDeclarationRef,
    module_sources: Mapping[str, Path],
    label: str,
) -> None:
    source_path = module_sources.get(ref.module)
    if source_path is None:
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"{label} refers to a module absent from module_sources"
        )
    source = source_path.read_text(encoding="utf-8")
    symbol = re.escape(ref.declaration.rsplit(".", 1)[-1])
    forbidden = re.compile(rf"(?m)^\s*(?:axiom|opaque)\s+{symbol}\b")
    if forbidden.search(source):
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"{label} refers to an unchecked declaration form"
        )
    declaration = re.compile(
        rf"(?m)^\s*(?:def|abbrev|theorem)\s+{symbol}\b"
    )
    if declaration.search(source) is None:
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"{label} is not declared by its content-addressed Lean module"
        )
    if ref.kind == "exact_source_artifact":
        exact = re.compile(
            rf"(?s)(?:def|abbrev)\s+{symbol}\b.*?:\s*ExactSourceArtifact\b"
        )
        if exact.search(source) is None:
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"{label} is not visibly typed as ExactSourceArtifact"
            )


def _actual_file_binding(path: Path, row: Mapping[str, Any], label: str) -> str:
    if not path.is_file() or path.is_symlink():
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"{label} is not a regular file"
        )
    digest = sha256_file(path)
    if digest != _sha256(row.get("sha256"), f"{label}.sha256"):
        raise GnuHelloCompiledAuthorityEvidenceError(f"{label} hash mismatch")
    size = row.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"{label}.size must be positive"
        )
    if path.stat().st_size != size:
        raise GnuHelloCompiledAuthorityEvidenceError(f"{label} size mismatch")
    return digest


@dataclass(frozen=True)
class SourceClosure:
    bundle_sha256: str
    bundle_artifact_sha256: str
    renderer_digest: str
    project_artifact_digests: frozenset[str]
    lowering_digest: str
    runtime_digest: str
    abi_digest: str
    all_digests: frozenset[str]


def _source_closure(bundle: Mapping[str, Any], bundle_path: Path) -> SourceClosure:
    hashes = _object(bundle.get("hashes"), "source bundle hashes")
    bundle_sha256 = _sha256(
        hashes.get("source_bundle_sha256"), "source bundle closure SHA-256"
    )
    all_digests = {sha256_file(bundle_path)}
    state = _object(bundle.get("state_machine"), "source state machine")
    state_path = Path(_string(state.get("path"), "source state-machine path"))
    renderer = _actual_file_binding(state_path, state, "source state machine")
    all_digests.add(renderer)

    contract = _object(bundle.get("load_image_contract"), "load-image contract")
    contract_path = Path(_string(contract.get("path"), "load-image contract path"))
    contract_digest = _actual_file_binding(
        contract_path,
        {
            "sha256": contract.get("artifact_sha256"),
            "size": contract.get("size"),
        },
        "load-image contract",
    )
    all_digests.add(contract_digest)

    packages = _object(bundle.get("packages"), "source packages")
    expected_owners = {"interpreter", "native_engine", "native_runtime"}
    if set(packages) != expected_owners:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "source bundle package ownership changed"
        )
    project_digests: set[str] = set()
    role_digests: dict[tuple[str, str], str] = {}
    for owner in sorted(packages):
        package = _object(packages[owner], f"source package {owner}")
        root = Path(_string(package.get("root"), f"source package {owner} root"))
        if not root.is_absolute() or not root.is_dir():
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"source package {owner} root is not realized"
            )
        manifest = _object(
            package.get("manifest"), f"source package {owner} manifest"
        )
        manifest_path = root / _string(
            manifest.get("path"), f"source package {owner} manifest path"
        )
        manifest_digest = _actual_file_binding(
            manifest_path, manifest, f"source package {owner} manifest"
        )
        all_digests.add(manifest_digest)
        rows = _list(package.get("artifacts"), f"source package {owner} artifacts")
        if not rows:
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"source package {owner} has no artifacts"
            )
        for index, value in enumerate(rows):
            label = f"source package {owner} artifacts[{index}]"
            row = _object(value, label)
            if row.get("owner") != owner:
                raise GnuHelloCompiledAuthorityEvidenceError(
                    f"{label} owner mismatch"
                )
            role = _string(row.get("role"), f"{label}.role")
            key = (owner, role)
            if key in role_digests:
                raise GnuHelloCompiledAuthorityEvidenceError(
                    f"source package role {owner}/{role} is ambiguous"
                )
            artifact_path = root / _string(row.get("path"), f"{label}.path")
            digest = _actual_file_binding(artifact_path, row, label)
            role_digests[key] = digest
            project_digests.add(digest)
            all_digests.add(digest)

    required = {
        ("native_engine", "plan"): "lowering",
        ("native_runtime", "native_runtime_source"): "runtime",
        ("native_runtime", "native_runtime_header"): "abi",
    }
    missing = [name for key, name in required.items() if key not in role_digests]
    if missing:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "source bundle lacks unique " + ", ".join(sorted(missing))
        )
    return SourceClosure(
        bundle_sha256=bundle_sha256,
        bundle_artifact_sha256=sha256_file(bundle_path),
        renderer_digest=renderer,
        project_artifact_digests=frozenset(project_digests),
        lowering_digest=role_digests[("native_engine", "plan")],
        runtime_digest=role_digests[("native_runtime", "native_runtime_source")],
        abi_digest=role_digests[("native_runtime", "native_runtime_header")],
        all_digests=frozenset(all_digests),
    )


def _expected_realization(
    expected: NixRealizationIdentity,
    inspector: NixInspector,
    label: str,
) -> NixRealizationIdentity:
    expected.validate()
    observed = inspector(expected)
    observed.validate()
    canonical_expected = (
        expected.output.resolve(),
        expected.derivation.resolve(),
        expected.nar_hash,
    )
    canonical_observed = (
        observed.output.resolve(),
        observed.derivation.resolve(),
        observed.nar_hash,
    )
    if canonical_expected != canonical_observed:
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"{label} differs from the live Nix realization"
        )
    return observed


def _candidate_import_inventory(binary: object) -> list[dict[str, object]]:
    return [
        {
            "dll": imported.dll,
            "symbol": imported.symbol,
            "ordinal": imported.ordinal,
            "thunk_rva": imported.thunk_rva,
        }
        for imported in binary.imports
    ]


def _validate_profile_output(
    profile: NixRealizationIdentity,
    generated_tools: Mapping[str, object],
) -> None:
    manifest_path = profile.output / TOOLCHAIN_PROFILE_FILENAME
    manifest = _read_object(manifest_path, "toolchain profile manifest")
    _require_exact_fields(
        manifest,
        {"format", "identifier", "tools"},
        "toolchain profile manifest",
    )
    if (
        manifest["format"] != TOOLCHAIN_PROFILE_FORMAT
        or manifest["identifier"] != PROFILE_IDENTIFIER
    ):
        raise GnuHelloCompiledAuthorityEvidenceError(
            "toolchain profile manifest selects a different profile"
        )
    rows = _list(manifest["tools"], "toolchain profile tools")
    observed: dict[str, tuple[str, str]] = {}
    for index, value in enumerate(rows):
        label = f"toolchain profile tools[{index}]"
        row = _object(value, label)
        _require_exact_fields(
            row, {"role", "identifier", "path", "sha256"}, label
        )
        role = _string(row["role"], f"{label}.role")
        identifier = _string(row["identifier"], f"{label}.identifier")
        path = Path(_string(row["path"], f"{label}.path"))
        digest = _sha256(row["sha256"], f"{label}.sha256")
        if role in observed or not path.is_file() or sha256_file(path) != digest:
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"toolchain profile role {role} is ambiguous or changed"
            )
        observed[role] = (identifier, digest)
    if set(observed) != set(_TOOL_ROLES):
        raise GnuHelloCompiledAuthorityEvidenceError(
            "toolchain profile does not contain exactly the pinned component roles"
        )
    expected = {
        role: (
            _string(value["identifier"], f"generated tool {role} identifier"),
            _sha256(value["evidence_sha256"], f"generated tool {role} digest"),
        )
        for role, raw in generated_tools.items()
        for value in [_object(raw, f"generated tool {role}")]
    }
    if observed != expected:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "toolchain profile realization differs from exact Lean tool artifacts"
        )


def _load_project_declarations(
    manifest_path: Path,
    closure: SourceClosure,
    attested_tools: Mapping[str, str],
) -> tuple[dict[str, object], set[str]]:
    manifest = _read_object(manifest_path, "project declaration manifest")
    _require_exact_fields(manifest, {"format", "bindings", "lean"}, "project declaration manifest")
    if manifest["format"] != PROJECT_DECLARATIONS_FORMAT:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "unsupported project declaration manifest"
        )
    bindings = _object(manifest["bindings"], "project declaration bindings")
    _require_exact_fields(
        bindings,
        {"source_bundle_sha256", "source_bundle_artifact_sha256"},
        "project declaration bindings",
    )
    if bindings != {
        "source_bundle_sha256": closure.bundle_sha256,
        "source_bundle_artifact_sha256": closure.bundle_artifact_sha256,
    }:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "project declarations bind a different source bundle"
        )
    lean = _object(manifest["lean"], "project Lean declarations")
    _require_exact_fields(lean, _PROJECT_LEAN_FIELDS, "project Lean declarations")
    if lean["profile_identifier"] != PROFILE_IDENTIFIER:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "project declarations select an unsupported toolchain profile"
        )
    modules = _module_sources(lean["module_sources"], manifest_path.parent)

    simple_refs: dict[str, LeanDeclarationRef] = {}
    for name in (
        "world_program",
        "checked_input",
        "checked_input_nonempty",
        "source_artifact_roles_nodup",
    ):
        ref = LeanDeclarationRef.from_json(lean[name], f"project Lean {name}")
        _verify_ref(ref, modules, f"project Lean {name}")
        simple_refs[name] = ref

    bundle_artifact = ExactArtifactRef.from_json(
        lean["bundle_manifest_artifact"], "bundle manifest artifact"
    )
    renderer_artifact = ExactArtifactRef.from_json(
        lean["renderer_input_artifact"], "renderer input artifact"
    )
    if bundle_artifact.evidence_sha256 != closure.bundle_artifact_sha256:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "bundle artifact declaration binds different bytes"
        )
    if renderer_artifact.evidence_sha256 != closure.renderer_digest:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "renderer input declaration binds different bytes"
        )
    _verify_ref(bundle_artifact.declaration, modules, "bundle manifest artifact")
    _verify_ref(renderer_artifact.declaration, modules, "renderer input artifact")

    source_rows = _list(lean["source_artifacts"], "source artifacts")
    source_artifacts = tuple(
        ExactArtifactRef.from_json(value, f"source artifacts[{index}]")
        for index, value in enumerate(source_rows)
    )
    source_digests = [artifact.evidence_sha256 for artifact in source_artifacts]
    if len(source_digests) != len(set(source_digests)):
        raise GnuHelloCompiledAuthorityEvidenceError(
            "source artifact evidence is not one-to-one"
        )
    if frozenset(source_digests) != closure.project_artifact_digests:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "source artifact declarations do not cover the exact project closure"
        )
    for index, artifact in enumerate(source_artifacts):
        _verify_ref(artifact.declaration, modules, f"source artifacts[{index}]")

    tools = _object(lean["tools"], "tool declarations")
    _require_exact_fields(tools, set(_TOOL_ROLES), "tool declarations")
    expected_tool_digests = {
        "renderer": closure.renderer_digest,
        "lowering": closure.lowering_digest,
        "runtime": closure.runtime_digest,
        "compiler": attested_tools.get("compiler"),
        "assembler": attested_tools.get("assembler"),
        "linker": attested_tools.get("linker"),
        "abi": closure.abi_digest,
    }
    output_tools: dict[str, object] = {}
    for role in _TOOL_ROLES:
        row = _object(tools[role], f"tool declarations.{role}")
        _require_exact_fields(
            row,
            {"identifier", "artifact", "evidence_sha256"},
            f"tool declarations.{role}",
        )
        artifact = LeanDeclarationRef.from_json(
            row["artifact"], f"tool declarations.{role}.artifact"
        )
        if artifact.kind != "exact_source_artifact":
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"tool declarations.{role} must use an exact source artifact"
            )
        _verify_ref(artifact, modules, f"tool declarations.{role}.artifact")
        evidence = _sha256(
            row["evidence_sha256"], f"tool declarations.{role}.evidence_sha256"
        )
        if expected_tool_digests[role] is None or evidence != expected_tool_digests[role]:
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"tool declaration {role} binds different bytes"
            )
        output_tools[role] = {
            "identifier": _string(row["identifier"], f"tool {role} identifier"),
            "exact_artifact": artifact.declaration,
            "evidence_sha256": evidence,
        }

    output = {
        "imports": sorted(modules),
        **{name: ref.declaration for name, ref in simple_refs.items()},
        "bundle_manifest_artifact": bundle_artifact.declaration.declaration,
        "renderer_input_artifact": renderer_artifact.declaration.declaration,
        "source_artifacts": [
            artifact.declaration.declaration for artifact in source_artifacts
        ],
        "source_artifact_evidence_sha256s": source_digests,
        "profile_identifier": PROFILE_IDENTIFIER,
        "tools": output_tools,
    }
    return output, set(modules)


def _load_static_authority(
    manifest_path: Path, candidate: Path, candidate_sha256: str
) -> tuple[dict[str, str], str]:
    manifest = _read_object(manifest_path, "candidate static-authority manifest")
    if manifest.get("format") != CANDIDATE_STATIC_AUTHORITY_FORMAT:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "unsupported candidate static-authority manifest"
        )
    candidate_row = _object(manifest.get("candidate"), "static candidate binding")
    if (
        Path(_string(candidate_row.get("path"), "static candidate path")).resolve()
        != candidate.resolve()
        or candidate_row.get("sha256") != candidate_sha256
        or candidate_row.get("size") != candidate.stat().st_size
    ):
        raise GnuHelloCompiledAuthorityEvidenceError(
            "candidate static authority binds different bytes"
        )
    module_name = _string(manifest.get("module"), "static authority module")
    module = f"StageA.{module_name}"
    source = manifest_path.parent / "StageA" / f"{module_name}.lean"
    if not source.is_file():
        raise GnuHelloCompiledAuthorityEvidenceError(
            "candidate static-authority Lean module is missing"
        )
    interface = _object(
        manifest.get("compiled_identity_interface"),
        "compiled identity interface",
    )
    _require_exact_fields(interface, _STATIC_INTERFACE_FIELDS, "compiled identity interface")
    result: dict[str, str] = {}
    module_sources = {module: source.resolve()}
    for name in sorted(_STATIC_INTERFACE_FIELDS):
        declaration = _string(interface[name], f"compiled identity interface.{name}")
        ref = LeanDeclarationRef(module, declaration, "checked_static_fact")
        if _LEAN_DECLARATION.fullmatch(declaration) is None:
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"compiled identity interface.{name} is not a Lean declaration"
            )
        _verify_ref(ref, module_sources, f"compiled identity interface.{name}")
        result[name] = declaration
    return result, module


def _load_runtime_declarations(
    manifest_path: Path, candidate_sha256: str
) -> tuple[dict[str, object], set[str]]:
    manifest = _read_object(manifest_path, "candidate runtime declaration manifest")
    _require_exact_fields(
        manifest,
        {"format", "candidate_sha256", "lean"},
        "candidate runtime declaration manifest",
    )
    if manifest["format"] != RUNTIME_DECLARATIONS_FORMAT:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "unsupported candidate runtime declaration manifest"
        )
    if manifest["candidate_sha256"] != candidate_sha256:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "candidate runtime declarations bind different bytes"
        )
    lean = _object(manifest["lean"], "candidate runtime Lean declarations")
    _require_exact_fields(
        lean, _RUNTIME_LEAN_FIELDS, "candidate runtime Lean declarations"
    )
    modules = _module_sources(lean["module_sources"], manifest_path.parent)
    result: dict[str, object] = {}
    for name in ("environment", "indirect_targets", "indirect_targets_valid"):
        ref = LeanDeclarationRef.from_json(lean[name], f"runtime Lean {name}")
        _verify_ref(ref, modules, f"runtime Lean {name}")
        result[name] = ref.declaration
    callable_external = lean["callable_external"]
    callable_bound = lean["callable_bound"]
    if (callable_external is None) != (callable_bound is None):
        raise GnuHelloCompiledAuthorityEvidenceError(
            "callable external declaration and proof must be supplied together"
        )
    for name, value in (
        ("callable_external", callable_external),
        ("callable_bound", callable_bound),
    ):
        if value is None:
            result[name] = None
        else:
            ref = LeanDeclarationRef.from_json(value, f"runtime Lean {name}")
            _verify_ref(ref, modules, f"runtime Lean {name}")
            result[name] = ref.declaration
    return result, set(modules)


def write_gnu_hello_native_source_compiled_authority_evidence(
    *,
    source_bundle: Path | str,
    compilation_attestation: Path | str,
    project_declarations: Path | str,
    candidate_static_authority: Path | str,
    runtime_declarations: Path | str,
    project_realization: NixRealizationIdentity,
    profile_realization: NixRealizationIdentity,
    build_realization: NixRealizationIdentity,
    out: Path | str,
    nix_inspector: NixInspector = inspect_live_nix_realization,
    bundle_validator: Callable[[Path | str], dict[str, Any]] = (
        validate_native_source_bundle_manifest
    ),
    attestation_validator: Callable[[Path | str], dict[str, Any]] = (
        validate_native_source_compilation_attestation
    ),
    pe_parser: Callable[[Path], object] = _parse_stage_a_pe,
) -> tuple[Path, Path, Path, Path]:
    """Write declarations and three canonical, live-checked Nix identities."""

    bundle_path = Path(source_bundle).resolve()
    attestation_path = Path(compilation_attestation).resolve()
    bundle = bundle_validator(bundle_path)
    attestation = attestation_validator(attestation_path)
    closure = _source_closure(bundle, bundle_path)

    source_binding = _object(attestation.get("source_bundle"), "attested source bundle")
    if (
        Path(_string(source_binding.get("path"), "attested source path")).resolve()
        != bundle_path
        or source_binding.get("artifact_sha256") != closure.bundle_artifact_sha256
        or source_binding.get("source_bundle_sha256") != closure.bundle_sha256
    ):
        raise GnuHelloCompiledAuthorityEvidenceError(
            "compilation attestation binds a different source bundle"
        )
    candidate_row = _object(attestation.get("candidate"), "attested candidate")
    candidate = Path(_string(candidate_row.get("path"), "attested candidate path")).resolve()
    candidate_sha256 = sha256_file(candidate)
    if (
        candidate_row.get("sha256") != candidate_sha256
        or candidate_row.get("size") != candidate.stat().st_size
    ):
        raise GnuHelloCompiledAuthorityEvidenceError(
            "candidate bytes differ from the compilation attestation"
        )

    tools = _list(attestation.get("tools"), "attested tools")
    attested_tools: dict[str, str] = {}
    for index, value in enumerate(tools):
        row = _object(value, f"attested tools[{index}]")
        role = _string(row.get("role"), f"attested tools[{index}].role")
        path = Path(_string(row.get("path"), f"attested tools[{index}].path"))
        digest = _sha256(row.get("sha256"), f"attested tools[{index}].sha256")
        if role in attested_tools or not path.is_file() or sha256_file(path) != digest:
            raise GnuHelloCompiledAuthorityEvidenceError(
                f"attested tool {role} is ambiguous or changed"
            )
        attested_tools[role] = digest
    if not {"compiler", "assembler", "linker"} <= set(attested_tools):
        raise GnuHelloCompiledAuthorityEvidenceError(
            "compilation attestation omits compiler, assembler, or linker"
        )

    project_lean, project_modules = _load_project_declarations(
        Path(project_declarations), closure, attested_tools
    )
    static_lean, static_module = _load_static_authority(
        Path(candidate_static_authority), candidate, candidate_sha256
    )
    runtime_lean, runtime_modules = _load_runtime_declarations(
        Path(runtime_declarations), candidate_sha256
    )

    project_live = _expected_realization(
        project_realization, nix_inspector, "project Nix realization"
    )
    profile_live = _expected_realization(
        profile_realization, nix_inspector, "profile Nix realization"
    )
    build_live = _expected_realization(
        build_realization, nix_inspector, "build Nix realization"
    )
    if project_live.output.resolve() != bundle_path.parent.resolve():
        raise GnuHelloCompiledAuthorityEvidenceError(
            "project Nix output is not the source-bundle output"
        )
    if build_live.output.resolve() != candidate.parent.resolve():
        raise GnuHelloCompiledAuthorityEvidenceError(
            "build Nix output is not the candidate output"
        )
    _validate_profile_output(profile_live, project_lean["tools"])
    attested_nix = _object(attestation.get("nix"), "attested build Nix identity")
    if {
        "output": str(build_live.output.resolve()),
        "derivation": str(build_live.derivation.resolve()),
        "registered_deriver": str(build_live.derivation.resolve()),
        "nar_hash": build_live.nar_hash,
    } != dict(attested_nix):
        raise GnuHelloCompiledAuthorityEvidenceError(
            "build Nix realization differs from the compilation attestation"
        )

    binary = pe_parser(candidate)
    try:
        if binary.machine != "i386" or binary.bitness != 32:
            raise GnuHelloCompiledAuthorityEvidenceError(
                "compiled authority requires an i386 PE32 candidate"
            )
        entry_rva = binary.entrypoint_rva
        image_base = binary.image_base
        imports = _candidate_import_inventory(binary)
    finally:
        binary.pe.close()

    relocation = _object(attestation.get("relocations"), "relocation inventory")
    required_relocation = {
        "sha256",
        "canonical_sha256",
        "payload_sha256",
        "count",
        "complete",
    }
    if not required_relocation <= set(relocation) or relocation.get("complete") is not True:
        raise GnuHelloCompiledAuthorityEvidenceError(
            "relocation inventory is incomplete"
        )
    relocation_binding = {name: relocation[name] for name in required_relocation}

    declarations = {
        "format": COMPILED_AUTHORITY_DECLARATIONS_FORMAT,
        "bindings": {
            "source_bundle_sha256": closure.bundle_sha256,
            "source_bundle_artifact_sha256": closure.bundle_artifact_sha256,
            "attestation_core_sha256": _sha256(
                _object(attestation.get("hashes"), "attestation hashes").get(
                    "attestation_core_sha256"
                ),
                "attestation core SHA-256",
            ),
            "attestation_artifact_sha256": sha256_file(attestation_path),
            "candidate_sha256": candidate_sha256,
            "candidate_size": candidate.stat().st_size,
            "candidate_entry_rva": entry_rva,
            "candidate_image_base": image_base,
            "candidate_imports": imports,
            "relocation_inventory": relocation_binding,
            "project_nar_hash": project_live.nar_hash,
            "profile_nar_hash": profile_live.nar_hash,
            "build_nar_hash": build_live.nar_hash,
        },
        "lean": {
            **project_lean,
            **static_lean,
            **runtime_lean,
            "imports": sorted(
                {*project_modules, static_module, *runtime_modules}
            ),
            "namespace": OUTPUT_NAMESPACE,
            "output_module": OUTPUT_MODULE,
            "audit_output_module": AUDIT_OUTPUT_MODULE,
        },
    }

    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    declarations_path = root / "compiled-authority-declarations.json"
    project_path = root / "project-nix-provenance.json"
    profile_path = root / "profile-nix-provenance.json"
    build_path = root / "build-nix-provenance.json"
    _write_json(declarations_path, declarations)
    _write_json(project_path, project_live.canonical_payload())
    _write_json(profile_path, profile_live.canonical_payload())
    _write_json(build_path, build_live.canonical_payload())
    return declarations_path, project_path, profile_path, build_path


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"cannot read {label}: {error}"
        ) from error
    return _object(value, label)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise GnuHelloCompiledAuthorityEvidenceError(f"{label} must be an object")
    return dict(value)


def _list(value: object, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GnuHelloCompiledAuthorityEvidenceError(f"{label} must be an array")
    return list(value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"{label} must be a non-empty printable string"
        )
    return value


def _sha256(value: object, label: str) -> str:
    text = _string(value, label)
    if _SHA256.fullmatch(text) is None:
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"{label} must be a lowercase SHA-256"
        )
    return text


def _require_exact_fields(
    value: Mapping[str, Any], fields: set[str] | frozenset[str], label: str
) -> None:
    if set(value) != set(fields):
        raise GnuHelloCompiledAuthorityEvidenceError(
            f"{label} must contain exactly " + ", ".join(sorted(fields))
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
    parser.add_argument("--project-declarations", required=True)
    parser.add_argument("--candidate-static-authority", required=True)
    parser.add_argument("--runtime-declarations", required=True)
    parser.add_argument("--project-realization", required=True)
    parser.add_argument("--profile-realization", required=True)
    parser.add_argument("--build-realization", required=True)
    parser.add_argument("--offline-nix-inspection", action="store_true")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    write_gnu_hello_native_source_compiled_authority_evidence(
        source_bundle=args.source_bundle,
        compilation_attestation=args.compilation_attestation,
        project_declarations=args.project_declarations,
        candidate_static_authority=args.candidate_static_authority,
        runtime_declarations=args.runtime_declarations,
        project_realization=NixRealizationIdentity.from_json(args.project_realization),
        profile_realization=NixRealizationIdentity.from_json(args.profile_realization),
        build_realization=NixRealizationIdentity.from_json(args.build_realization),
        out=args.out,
        nix_inspector=(
            inspect_offline_nix_realization
            if args.offline_nix_inspection
            else inspect_live_nix_realization
        ),
    )


if __name__ == "__main__":
    _main()


__all__ = [
    "AUDIT_OUTPUT_MODULE",
    "CANDIDATE_STATIC_AUTHORITY_FORMAT",
    "COMPILED_AUTHORITY_DECLARATIONS_FORMAT",
    "GnuHelloCompiledAuthorityEvidenceError",
    "NIX_REALIZATION_INPUT_FORMAT",
    "NixRealizationIdentity",
    "OUTPUT_MODULE",
    "OUTPUT_NAMESPACE",
    "PROFILE_IDENTIFIER",
    "PROJECT_DECLARATIONS_FORMAT",
    "RUNTIME_DECLARATIONS_FORMAT",
    "TOOLCHAIN_PROFILE_FILENAME",
    "TOOLCHAIN_PROFILE_FORMAT",
    "inspect_live_nix_realization",
    "inspect_offline_nix_realization",
    "write_gnu_hello_native_source_compiled_authority_evidence",
]
