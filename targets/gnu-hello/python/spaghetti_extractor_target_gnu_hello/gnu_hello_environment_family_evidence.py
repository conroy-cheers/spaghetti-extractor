"""Package checked GNU hello external-environment family evidence.

This producer is deliberately profile driven.  It does not infer API behavior
from import names and it does not manufacture an environment theorem from a
status field.  A content-addressed Lean module must already prove the exact
one-to-one machine-call relation.  This module binds those declarations to the
candidate runtime v2 schema and then invokes the normal GNU hello acceptance
input assembler.

Source and compiled launch evidence is indexed by the exact environment pair
admitted by ``PairRelated``.  The relation must be explicitly inhabited, and
every admitted pair must separately carry exact one-to-one machine-call
evidence.  This avoids both a vacuous relation and the unsound overreach of
requiring source semantics for adversarial, unrelated environments.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.native_source_equivalence import validate_native_source_bundle_manifest
from .gnu_hello_native_source_environment_family_inputs import (
    GnuHelloEnvironmentFamilyInputOutputs,
    write_gnu_hello_native_source_environment_family_inputs,
)


GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_MODULE = (
    "GeneratedGnuHelloEnvironmentFamilyEvidence"
)
GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloEnvironmentFamilyEvidence"
)
GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_PROFILE_FORMAT = (
    "stage-a-gnu-hello-environment-family-evidence-profile-v1"
)
GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_REPORT_FORMAT = (
    "stage-a-gnu-hello-environment-family-evidence-producer-v1"
)
GNU_HELLO_RUNTIME_DECLARATIONS_V1_FORMAT = (
    "stage-a-native-source-candidate-runtime-declarations-v1"
)
GNU_HELLO_RUNTIME_DECLARATIONS_V2_FORMAT = (
    "stage-a-native-source-candidate-runtime-declarations-v2"
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_DECLARATION = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_UNCHECKED_DECLARATION = re.compile(
    r"(?m)^\s*(?:axiom|opaque)\s+[A-Za-z_][A-Za-z0-9_']*\b"
)
_UNCHECKED_TERM = re.compile(r"\b(?:sorry|admit)\b")

_BASE_RUNTIME_FIELDS = {
    "module_sources",
    "environment",
    "indirect_targets",
    "indirect_targets_valid",
    "callable_external",
    "callable_bound",
}
_PROFILE_REFS = {
    "context",
    "sites",
    "static_authority",
    "pair_relation",
    "pair_realizable",
    "external_evidence_at",
    "source_family_at",
    "launch_realizable_at",
}
_INTERFACE_KINDS = {
    "context": "static_proof_context",
    "sites": "opaque_lockstep_call_sites",
    "static_authority": "static_native_source_environment_family_authority",
    "pair_relation": "native_source_environment_pair_relation",
    "pair_realizable": "proof",
    "external_evidence_at": "exact_world_native_external_evidence_family",
    "source_family_at": "checked_native_source_launch_family",
    "launch_realizable_at": "native_compilation_launch_realizable_family",
}


class GnuHelloEnvironmentFamilyEvidenceError(StageAInputError):
    """Checked environment-family evidence is absent or malformed."""


@dataclass(frozen=True)
class GnuHelloEnvironmentFamilyEvidenceOutputs:
    module: Path
    runtime_declarations: Path
    acceptance_inputs: Path
    acceptance_module: Path
    report: Path


@dataclass(frozen=True)
class _LeanRef:
    module: str
    declaration: str

    @classmethod
    def read(
        cls,
        value: object,
        label: str,
        sources: Mapping[str, Path],
    ) -> "_LeanRef":
        row = _object(value, label)
        _exact_keys(row, {"module", "declaration"}, label)
        result = cls(
            module=_module(row["module"], f"{label}.module"),
            declaration=_declaration(
                row["declaration"], f"{label}.declaration"
            ),
        )
        source = sources.get(result.module)
        if source is None:
            raise GnuHelloEnvironmentFamilyEvidenceError(
                f"{label} module is absent from module_sources"
            )
        _require_checked_declaration(source, result.declaration, label)
        return result


def write_gnu_hello_environment_family_evidence(
    out: Path | str,
    *,
    profile_manifest: Path | str,
    source_execution_manifest: Path | str,
    compiled_authority_manifest: Path | str,
    source_bundle_manifest: Path | str,
    candidate_runtime_declarations: Path | str,
    candidate_static_authority: Path | str,
    bundle_validator: Callable[[Path | str], dict[str, Any]] = (
        validate_native_source_bundle_manifest
    ),
) -> GnuHelloEnvironmentFamilyEvidenceOutputs:
    """Emit runtime v2 and acceptance inputs from checked environment proofs."""

    profile_path = Path(profile_manifest)
    runtime_path = Path(candidate_runtime_declarations)
    profile = _read_json(profile_path, "environment-family profile")
    runtime = _read_json(runtime_path, "candidate runtime declarations")

    candidate_sha256, base_runtime, runtime_sources = _runtime_v1(
        runtime, runtime_path
    )
    profile_candidate = _sha(
        profile.get("candidate_sha256"), "profile candidate SHA-256"
    )
    if profile_candidate != candidate_sha256:
        raise GnuHelloEnvironmentFamilyEvidenceError(
            "environment-family profile binds different candidate bytes"
        )

    _exact_keys(
        profile,
        {"format", "candidate_sha256", "lockstep", "lean"},
        "environment-family profile",
    )
    if profile["format"] != GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_PROFILE_FORMAT:
        raise GnuHelloEnvironmentFamilyEvidenceError(
            "unsupported environment-family profile format"
        )
    _validate_lockstep_profile(profile["lockstep"])

    lean = _object(profile["lean"], "environment-family profile Lean evidence")
    _exact_keys(
        lean,
        {"module_sources", "source_family_scope", "launch_scope"} | _PROFILE_REFS,
        "environment-family profile Lean evidence",
    )
    if lean["source_family_scope"] != "admitted_pairs":
        raise GnuHelloEnvironmentFamilyEvidenceError(
            "source_family_scope must be admitted_pairs"
        )
    if lean["launch_scope"] != "admitted_pairs":
        raise GnuHelloEnvironmentFamilyEvidenceError(
            "launch_scope must be admitted_pairs"
        )

    profile_sources = _module_sources(
        lean["module_sources"], profile_path.parent, "profile"
    )
    refs = {
        name: _LeanRef.read(
            lean[name], f"environment-family profile {name}", profile_sources
        )
        for name in sorted(_PROFILE_REFS)
    }

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    module_path = stage_a / f"{GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_MODULE}.lean"
    module_path.write_text(_lean_source(refs), encoding="ascii")

    generated_module = f"StageA.{GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_MODULE}"
    generated_ref = lambda name, kind: {
        "module": generated_module,
        "declaration": (
            f"{GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_NAMESPACE}.{name}"
        ),
        "kind": kind,
    }
    module_sources = _canonical_module_source_rows(
        runtime_sources, profile_sources, generated_module, module_path
    )
    runtime_v2 = {
        "format": GNU_HELLO_RUNTIME_DECLARATIONS_V2_FORMAT,
        "candidate_sha256": candidate_sha256,
        "lean": {
            **base_runtime,
            "module_sources": module_sources,
            "environment_family": {
                name: generated_ref(name, _INTERFACE_KINDS[name])
                for name in sorted(_PROFILE_REFS)
            },
        },
    }
    runtime_v2_path = root / "runtime-declarations-v2.json"
    _write_json(runtime_v2_path, runtime_v2)

    assembled: GnuHelloEnvironmentFamilyInputOutputs = (
        write_gnu_hello_native_source_environment_family_inputs(
            root,
            source_execution_manifest=source_execution_manifest,
            compiled_authority_manifest=compiled_authority_manifest,
            source_bundle_manifest=source_bundle_manifest,
            candidate_runtime_declarations=runtime_v2_path,
            candidate_static_authority=candidate_static_authority,
            bundle_validator=bundle_validator,
        )
    )
    report_path = root / "environment-family-evidence-producer.json"
    _write_json(
        report_path,
        {
            "format": GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_REPORT_FORMAT,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "proof_authority": False,
            "acceptance_authority": False,
            "candidate_sha256": candidate_sha256,
            "lockstep_mode": "exact-1:1-machine-import-v1",
            "module": generated_module,
            "module_sha256": _file_sha256(module_path),
            "runtime_declarations_sha256": _file_sha256(runtime_v2_path),
            "acceptance_inputs_sha256": _file_sha256(
                assembled.environment_inputs
            ),
        },
    )
    return GnuHelloEnvironmentFamilyEvidenceOutputs(
        module=module_path,
        runtime_declarations=runtime_v2_path,
        acceptance_inputs=assembled.environment_inputs,
        acceptance_module=assembled.module,
        report=report_path,
    )


def _lean_source(refs: Mapping[str, _LeanRef]) -> str:
    imports = "\n".join(
        f"import {module}" for module in sorted({ref.module for ref in refs.values()})
    )
    ns = GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_NAMESPACE
    return f"""{imports}

namespace {ns}

/-- Content-addressed checked declarations; their full types are checked again
by the generated acceptance-input module. -/
abbrev context := {refs['context'].declaration}
def sites := {refs['sites'].declaration}
def static_authority := {refs['static_authority'].declaration}
abbrev pair_relation := {refs['pair_relation'].declaration}
def pair_realizable := {refs['pair_realizable'].declaration}
def external_evidence_at := {refs['external_evidence_at'].declaration}
def source_family_at := {refs['source_family_at'].declaration}
def launch_realizable_at := {refs['launch_realizable_at'].declaration}

end {ns}
"""


def _validate_lockstep_profile(value: object) -> None:
    profile = _object(value, "lockstep profile")
    _exact_keys(profile, {"mode", "sites"}, "lockstep profile")
    if profile["mode"] != "exact-1:1-machine-import-v1":
        raise GnuHelloEnvironmentFamilyEvidenceError(
            "lockstep mode must be exact-1:1-machine-import-v1"
        )
    sites = profile["sites"]
    if not isinstance(sites, list) or not sites:
        raise GnuHelloEnvironmentFamilyEvidenceError(
            "lockstep profile must contain at least one checked import site"
        )
    ids: set[int] = set()
    for index, raw in enumerate(sites):
        label = f"lockstep sites[{index}]"
        site = _object(raw, label)
        _exact_keys(
            site,
            {
                "id",
                "import_identity",
                "disposition",
                "argument_sources",
                "read_footprints",
                "write_footprints",
                "callbacks",
                "footprints_complete",
                "callbacks_complete",
            },
            label,
        )
        site_id = site["id"]
        if not isinstance(site_id, int) or isinstance(site_id, bool) or site_id < 0:
            raise GnuHelloEnvironmentFamilyEvidenceError(
                f"{label}.id must be a natural number"
            )
        if site_id in ids:
            raise GnuHelloEnvironmentFamilyEvidenceError(
                f"{label}.id is duplicated"
            )
        ids.add(site_id)
        _string(site["import_identity"], f"{label}.import_identity")
        if site["disposition"] not in {"returns", "terminates"}:
            raise GnuHelloEnvironmentFamilyEvidenceError(
                f"{label}.disposition is unsupported"
            )
        for field in (
            "argument_sources",
            "read_footprints",
            "write_footprints",
            "callbacks",
        ):
            if not isinstance(site[field], list):
                raise GnuHelloEnvironmentFamilyEvidenceError(
                    f"{label}.{field} must be an explicit array"
                )
        if site["footprints_complete"] is not True:
            raise GnuHelloEnvironmentFamilyEvidenceError(
                f"{label} lacks complete import read/write footprints"
            )
        if site["callbacks_complete"] is not True:
            raise GnuHelloEnvironmentFamilyEvidenceError(
                f"{label} lacks complete callback footprints"
            )


def _runtime_v1(
    value: Mapping[str, Any], path: Path
) -> tuple[str, dict[str, object], dict[str, Path]]:
    _exact_keys(value, {"format", "candidate_sha256", "lean"}, "runtime declarations")
    if value["format"] != GNU_HELLO_RUNTIME_DECLARATIONS_V1_FORMAT:
        raise GnuHelloEnvironmentFamilyEvidenceError(
            "environment evidence must extend exact runtime declarations v1"
        )
    lean = _object(value["lean"], "runtime Lean declarations")
    _exact_keys(lean, _BASE_RUNTIME_FIELDS, "runtime Lean declarations")
    sources = _module_sources(lean["module_sources"], path.parent, "runtime")
    for name in _BASE_RUNTIME_FIELDS - {"module_sources"}:
        ref = lean[name]
        if ref is None:
            if name not in {"callable_external", "callable_bound"}:
                raise GnuHelloEnvironmentFamilyEvidenceError(
                    f"runtime declaration {name} must not be null"
                )
            continue
        row = _object(ref, f"runtime declaration {name}")
        _exact_keys(row, {"module", "declaration", "kind"}, f"runtime declaration {name}")
        checked = _LeanRef.read(
            {"module": row["module"], "declaration": row["declaration"]},
            f"runtime declaration {name}",
            sources,
        )
        if checked.module != row["module"]:
            raise AssertionError("canonical module validation changed a value")
    return _sha(value["candidate_sha256"], "runtime candidate SHA-256"), dict(lean), sources


def _module_sources(
    value: object, root: Path, owner: str
) -> dict[str, Path]:
    if not isinstance(value, list) or not value:
        raise GnuHelloEnvironmentFamilyEvidenceError(
            f"{owner} module_sources must be a non-empty array"
        )
    result: dict[str, Path] = {}
    for index, raw in enumerate(value):
        label = f"{owner} module_sources[{index}]"
        row = _object(raw, label)
        _exact_keys(row, {"module", "path", "sha256"}, label)
        module = _module(row["module"], f"{label}.module")
        raw_path = Path(_string(row["path"], f"{label}.path"))
        source = raw_path if raw_path.is_absolute() else root / raw_path
        source = source.resolve()
        if module in result or not source.is_file() or source.suffix != ".lean":
            raise GnuHelloEnvironmentFamilyEvidenceError(
                f"{label} is duplicate or not a Lean source"
            )
        if _file_sha256(source) != _sha(row["sha256"], f"{label}.sha256"):
            raise GnuHelloEnvironmentFamilyEvidenceError(
                f"{label} source hash mismatch"
            )
        text = source.read_text(encoding="utf-8")
        if _UNCHECKED_DECLARATION.search(text) or _UNCHECKED_TERM.search(text):
            raise GnuHelloEnvironmentFamilyEvidenceError(
                f"{label} contains an unchecked Lean declaration or term"
            )
        result[module] = source
    return result


def _canonical_module_source_rows(
    runtime: Mapping[str, Path],
    profile: Mapping[str, Path],
    generated_module: str,
    generated_path: Path,
) -> list[dict[str, str]]:
    merged = dict(runtime)
    for module, path in profile.items():
        previous = merged.get(module)
        if previous is not None and _file_sha256(previous) != _file_sha256(path):
            raise GnuHelloEnvironmentFamilyEvidenceError(
                f"module {module} has conflicting content-addressed sources"
            )
        merged[module] = path
    merged[generated_module] = generated_path.resolve()
    return [
        {
            "module": module,
            "path": str(path),
            "sha256": _file_sha256(path),
        }
        for module, path in sorted(merged.items())
    ]


def _require_checked_declaration(source: Path, declaration: str, label: str) -> None:
    text = source.read_text(encoding="utf-8")
    symbol = re.escape(declaration.rsplit(".", 1)[-1])
    if re.search(rf"(?m)^\s*(?:axiom|opaque)\s+{symbol}\b", text):
        raise GnuHelloEnvironmentFamilyEvidenceError(
            f"{label} refers to an unchecked declaration"
        )
    if not re.search(rf"(?m)^\s*(?:def|abbrev|theorem)\s+{symbol}\b", text):
        raise GnuHelloEnvironmentFamilyEvidenceError(
            f"{label} is not declared by its content-addressed module"
        )


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GnuHelloEnvironmentFamilyEvidenceError(
            f"cannot read {label}: {error}"
        ) from error
    return _object(value, label)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise GnuHelloEnvironmentFamilyEvidenceError(f"{label} must be an object")
    return dict(value)


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise GnuHelloEnvironmentFamilyEvidenceError(
            f"{label} has a non-canonical schema: "
            f"missing={sorted(expected - set(value))}, "
            f"unexpected={sorted(set(value) - expected)}"
        )


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 32 for char in value):
        raise GnuHelloEnvironmentFamilyEvidenceError(
            f"{label} must be a non-empty printable string"
        )
    return value


def _sha(value: object, label: str) -> str:
    text = _string(value, label)
    if _SHA256.fullmatch(text) is None:
        raise GnuHelloEnvironmentFamilyEvidenceError(
            f"{label} must be a lowercase SHA-256"
        )
    return text


def _module(value: object, label: str) -> str:
    text = _string(value, label)
    if _STAGE_A_MODULE.fullmatch(text) is None:
        raise GnuHelloEnvironmentFamilyEvidenceError(
            f"{label} must be a canonical StageA module"
        )
    return text


def _declaration(value: object, label: str) -> str:
    text = _string(value, label)
    if _LEAN_DECLARATION.fullmatch(text) is None or not text.startswith("StageA."):
        raise GnuHelloEnvironmentFamilyEvidenceError(
            f"{label} must be a canonical StageA declaration"
        )
    return text


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise GnuHelloEnvironmentFamilyEvidenceError(
            f"cannot hash {path}: {error}"
        ) from error


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )


__all__ = [
    "ADMITTED_PAIR_SCHEMA_BLOCKER",
    "GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_MODULE",
    "GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_NAMESPACE",
    "GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_PROFILE_FORMAT",
    "GNU_HELLO_ENVIRONMENT_FAMILY_EVIDENCE_REPORT_FORMAT",
    "GnuHelloEnvironmentFamilyEvidenceError",
    "GnuHelloEnvironmentFamilyEvidenceOutputs",
    "write_gnu_hello_environment_family_evidence",
]
