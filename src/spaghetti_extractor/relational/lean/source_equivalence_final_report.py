"""Consolidate checked source-equivalence evidence into a final report.

The emitted JSON is a provenance summary, not proof authority.  A
``conditional_pass`` is available only after reconciling a Lean-checked
acceptance theorem, its detached axiom audit, the complete source/build
closure, exact candidate-PE metadata, and a candidate-only functional run.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Mapping

from ...artifact_formats import SOURCE_EQUIVALENCE_REPORT_FORMAT
from ...errors import StageAInputError
from ...native_source_equivalence import (
    validate_native_source_bundle_manifest,
    validate_native_source_compilation_attestation,
)
from ...util import sha256_file, write_json


CHECKED_ACCEPTANCE_FORMAT = (
    "stage-a-native-source-conditional-acceptance-checked-v1"
)
DETACHED_AXIOM_AUDIT_FORMAT = "stage-a-checked-detached-axiom-audit-v1"
CANDIDATE_PE_METADATA_FORMAT = (
    "stage-a-native-source-candidate-static-authority-v1"
)
FUNCTIONAL_REPORT_FORMAT = "stage-b-functional-report-v1"
FINAL_REPORT_FILENAME = "source-equivalence-report.json"

STANDARD_LOGICAL_AXIOMS = (
    "propext",
    "Classical.choice",
    "Quot.sound",
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_DECLARATION = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_ACCEPTANCE_FIELDS = frozenset(
    {
        "format",
        "status",
        "theorem",
        "approved_toolchain_axiom",
        "proof_bundle",
        "detached_axiom_audit",
        "runtime_authority",
        "execution",
        "bindings",
    }
)
_ACCEPTANCE_BINDING_FIELDS = frozenset(
    {
        "source_bundle_artifact_sha256",
        "source_bundle_sha256",
        "compilation_attestation_artifact_sha256",
        "attestation_core_sha256",
        "original_pe_sha256",
        "candidate_pe_sha256",
        "candidate_pe_size",
    }
)
_ACCEPTANCE_EXECUTION = {
    "original_binary_executed": False,
    "candidate_binary_executed": False,
}
_CANDIDATE_TRUST = {
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


class SourceEquivalenceFinalReportError(StageAInputError):
    """Final source-equivalence evidence is malformed or inconsistent."""


def build_source_equivalence_final_report(
    *,
    checked_acceptance: Path | str,
    detached_axiom_audit: Path | str,
    source_bundle: Path | str,
    compilation_attestation: Path | str,
    candidate_pe_metadata: Path | str,
    functional_report: Path | str,
    approved_toolchain_axiom: str,
) -> dict[str, Any]:
    """Validate and consolidate one conditional source-equivalence result."""

    toolchain_axiom = _lean_declaration(
        approved_toolchain_axiom, "approved toolchain axiom"
    )
    if toolchain_axiom in STANDARD_LOGICAL_AXIOMS:
        raise SourceEquivalenceFinalReportError(
            "approved toolchain axiom must be distinct from logical axioms"
        )

    paths = {
        "checked_acceptance": _file(checked_acceptance, "checked acceptance"),
        "detached_axiom_audit": _file(
            detached_axiom_audit, "detached axiom audit"
        ),
        "source_bundle": _file(source_bundle, "source bundle"),
        "compilation_attestation": _file(
            compilation_attestation, "compilation attestation"
        ),
        "candidate_pe_metadata": _file(
            candidate_pe_metadata, "candidate PE metadata"
        ),
        "functional_report": _file(functional_report, "functional report"),
    }

    acceptance = _read_object(paths["checked_acceptance"], "checked acceptance")
    audit = _read_object(paths["detached_axiom_audit"], "detached axiom audit")
    candidate_metadata = _read_object(
        paths["candidate_pe_metadata"], "candidate PE metadata"
    )
    functional = _read_object(paths["functional_report"], "functional report")
    source = validate_native_source_bundle_manifest(paths["source_bundle"])
    attestation = validate_native_source_compilation_attestation(
        paths["compilation_attestation"]
    )

    theorem, acceptance_bindings, proof_bundle = _checked_acceptance(
        acceptance,
        toolchain_axiom=toolchain_axiom,
        acceptance_path=paths["checked_acceptance"],
        audit_path=paths["detached_axiom_audit"],
    )
    proof_bundle_manifest = _proof_bundle_manifest(proof_bundle)
    _detached_audit(
        audit,
        theorem=theorem,
        toolchain_axiom=toolchain_axiom,
        proof_bundle=proof_bundle,
    )

    source_identity = _source_identity(source)
    attested_identity = _attested_identity(attestation)
    candidate_identity = _candidate_identity(candidate_metadata)
    _reconcile_static_provenance(
        acceptance_bindings=acceptance_bindings,
        source_identity=source_identity,
        attested_identity=attested_identity,
        candidate_identity=candidate_identity,
        paths=paths,
    )
    functional_identity = _functional_identity(
        functional, expected_candidate=candidate_identity
    )

    input_sha256s = {
        name: sha256_file(path)
        for name, path in sorted(paths.items())
    }
    return {
        "format": SOURCE_EQUIVALENCE_REPORT_FORMAT,
        "verdict": "conditional_pass",
        "status": "conditional_pass",
        "theorem": theorem,
        "original": {
            "pe_sha256": source_identity["original_pe_sha256"],
        },
        "candidate": {
            "pe_sha256": candidate_identity["sha256"],
            "size": candidate_identity["size"],
        },
        "source_bundle": {
            "source_bundle_sha256": source_identity["source_bundle_sha256"],
            "artifact_sha256": input_sha256s["source_bundle"],
        },
        "compilation_attestation": {
            "attestation_core_sha256": attested_identity[
                "attestation_core_sha256"
            ],
            "artifact_sha256": input_sha256s["compilation_attestation"],
        },
        "lean_proof": {
            "status": "checked",
            "proof_bundle": str(proof_bundle),
            "proof_bundle_manifest_sha256": sha256_file(proof_bundle_manifest),
            "detached_axiom_audit_sha256": input_sha256s[
                "detached_axiom_audit"
            ],
        },
        "approved_premise": {
            "kind": "pinned_toolchain_correctness",
            "lean_axiom": toolchain_axiom,
            "conditional": True,
            "only_nonlogical_axiom": True,
        },
        "runtime_validation": {
            "status": "pass",
            "candidate_only": True,
            "target_name": functional_identity["target_name"],
            "suite_id": functional_identity["suite_id"],
            "cases": functional_identity["cases"],
            "original_runtime_executions": 0,
            "original_runtime_observations": False,
            "runtime_authority": False,
        },
        "zero_original_runtime": {
            "asserted": True,
            "original_runtime_executions": 0,
            "source_bundle_declares_original_not_executed": True,
            "acceptance_declares_original_not_executed": True,
            "functional_report_declares_no_original_observations": True,
        },
        "input_sha256s": input_sha256s,
        "acceptance_authority": False,
        "proof_authority": False,
        "trust": {
            "generated_json_is_authority": False,
            "lean_checked_theorem_is_authority": True,
            "detached_axiom_audit_required": True,
            "runtime_validation_is_authority": False,
            "compiler_toolchain_correctness_is_explicit_premise": True,
        },
    }


def write_source_equivalence_final_report(
    *,
    out: Path | str,
    checked_acceptance: Path | str,
    detached_axiom_audit: Path | str,
    source_bundle: Path | str,
    compilation_attestation: Path | str,
    candidate_pe_metadata: Path | str,
    functional_report: Path | str,
    approved_toolchain_axiom: str,
) -> dict[str, Any]:
    """Write a deterministic, non-authoritative consolidated report."""

    report = build_source_equivalence_final_report(
        checked_acceptance=checked_acceptance,
        detached_axiom_audit=detached_axiom_audit,
        source_bundle=source_bundle,
        compilation_attestation=compilation_attestation,
        candidate_pe_metadata=candidate_pe_metadata,
        functional_report=functional_report,
        approved_toolchain_axiom=approved_toolchain_axiom,
    )
    destination = Path(out) / FINAL_REPORT_FILENAME
    write_json(destination, report)
    return report


def _checked_acceptance(
    value: Mapping[str, Any],
    *,
    toolchain_axiom: str,
    acceptance_path: Path,
    audit_path: Path,
) -> tuple[str, dict[str, Any], Path]:
    _exact_fields(value, _ACCEPTANCE_FIELDS, "checked acceptance")
    if (
        value["format"] != CHECKED_ACCEPTANCE_FORMAT
        or value["status"] != "checked"
        or value["runtime_authority"] is not False
        or value["execution"] != _ACCEPTANCE_EXECUTION
    ):
        raise SourceEquivalenceFinalReportError(
            "checked acceptance status, trust role, or execution policy changed"
        )
    theorem = _lean_declaration(value["theorem"], "acceptance theorem")
    if value["approved_toolchain_axiom"] != toolchain_axiom:
        raise SourceEquivalenceFinalReportError(
            "checked acceptance names a different toolchain axiom"
        )
    bindings = _object(value["bindings"], "acceptance bindings")
    _exact_fields(bindings, _ACCEPTANCE_BINDING_FIELDS, "acceptance bindings")
    for name in _ACCEPTANCE_BINDING_FIELDS - {"candidate_pe_size"}:
        _sha256(bindings[name], f"acceptance bindings.{name}")
    _positive_int(bindings["candidate_pe_size"], "acceptance candidate PE size")

    proof_bundle = _directory(value["proof_bundle"], "acceptance proof bundle")
    if not _reference_matches(
        value["detached_axiom_audit"], audit_path, "axiom-audit.json"
    ):
        raise SourceEquivalenceFinalReportError(
            "checked acceptance points at a different detached axiom audit"
        )
    if acceptance_path == audit_path:
        raise SourceEquivalenceFinalReportError(
            "acceptance and detached audit must be separate artifacts"
        )
    return theorem, bindings, proof_bundle


def _detached_audit(
    value: Mapping[str, Any],
    *,
    theorem: str,
    toolchain_axiom: str,
    proof_bundle: Path,
) -> None:
    required = {
        "format",
        "status",
        "declaration",
        "inventory",
        "approved_axioms",
        "required_axioms",
        "proof_bundle",
    }
    _exact_fields(value, required, "detached axiom audit")
    if (
        value["format"] != DETACHED_AXIOM_AUDIT_FORMAT
        or value["status"] != "checked"
        or value["declaration"] != theorem
    ):
        raise SourceEquivalenceFinalReportError(
            "detached axiom audit does not check the accepted theorem"
        )
    inventory = _unique_strings(value["inventory"], "audit inventory")
    approved = _unique_strings(value["approved_axioms"], "approved axioms")
    required_axioms = _unique_strings(value["required_axioms"], "required axioms")
    allowed = {*STANDARD_LOGICAL_AXIOMS, toolchain_axiom}
    if set(approved) != allowed:
        raise SourceEquivalenceFinalReportError(
            "detached audit must approve exactly the standard logical axioms "
            "and one explicit toolchain axiom"
        )
    if required_axioms != (toolchain_axiom,):
        raise SourceEquivalenceFinalReportError(
            "detached audit must require exactly the explicit toolchain axiom"
        )
    if toolchain_axiom not in inventory or not set(inventory) <= allowed:
        raise SourceEquivalenceFinalReportError(
            "detached audit inventory omits the toolchain axiom or adds an "
            "unapproved axiom"
        )
    if _directory(value["proof_bundle"], "audit proof bundle") != proof_bundle:
        raise SourceEquivalenceFinalReportError(
            "acceptance and detached audit bind different proof bundles"
        )


def _source_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("status") != "ready":
        raise SourceEquivalenceFinalReportError("source bundle is not ready")
    trust = _object(value.get("trust"), "source-bundle trust")
    if (
        trust.get("acceptance_authority") is not False
        or trust.get("original_binary_executed") is not False
        or trust.get("original_binary_consumed_statically") is not True
        or trust.get("lean_whole_program_proof_required") is not True
        or trust.get("compiler_correctness_assumed_by_source_equivalence")
        is not True
    ):
        raise SourceEquivalenceFinalReportError(
            "source bundle does not preserve the source-equivalence trust boundary"
        )
    hashes = _object(value.get("hashes"), "source-bundle hashes")
    contract = _object(
        value.get("load_image_contract"), "source-bundle load-image contract"
    )
    return {
        "source_bundle_sha256": _sha256(
            hashes.get("source_bundle_sha256"), "source-bundle closure SHA-256"
        ),
        "original_pe_sha256": _sha256(
            contract.get("bound_original_pe_sha256"), "original PE SHA-256"
        ),
    }


def _attested_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    if value.get("status") != "complete":
        raise SourceEquivalenceFinalReportError(
            "compilation attestation is not complete"
        )
    trust = _object(value.get("trust"), "compilation-attestation trust")
    if (
        trust.get("acceptance_authority") is not False
        or trust.get("build_manifest_is_provenance_not_proof") is not True
        or trust.get("lean_whole_program_proof_required") is not True
        or trust.get("compiler_assembler_linker_correctness_assumed") is not True
    ):
        raise SourceEquivalenceFinalReportError(
            "compilation attestation has an invalid trust role"
        )
    hashes = _object(value.get("hashes"), "attestation hashes")
    source = _object(value.get("source_bundle"), "attested source bundle")
    candidate = _object(value.get("candidate"), "attested candidate")
    return {
        "attestation_core_sha256": _sha256(
            hashes.get("attestation_core_sha256"), "attestation core SHA-256"
        ),
        "source_bundle_artifact_sha256": _sha256(
            source.get("artifact_sha256"), "attested source-bundle artifact SHA-256"
        ),
        "source_bundle_sha256": _sha256(
            source.get("source_bundle_sha256"), "attested source-bundle SHA-256"
        ),
        "candidate_path": _path(candidate.get("path"), "attested candidate path"),
        "candidate_sha256": _sha256(
            candidate.get("sha256"), "attested candidate SHA-256"
        ),
        "candidate_size": _positive_int(
            candidate.get("size"), "attested candidate size"
        ),
    }


def _candidate_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    if (
        value.get("format") != CANDIDATE_PE_METADATA_FORMAT
        or value.get("phase") != "native-source-candidate-static-authority"
        or value.get("status") != "source-ready"
    ):
        raise SourceEquivalenceFinalReportError(
            "candidate PE metadata is not checked static-authority metadata"
        )
    trust = _object(value.get("trust"), "candidate PE metadata trust")
    for name, expected in _CANDIDATE_TRUST.items():
        if trust.get(name) is not expected:
            raise SourceEquivalenceFinalReportError(
                f"candidate PE metadata trust field {name} changed"
            )
    candidate = _object(value.get("candidate"), "candidate PE binding")
    path = _file(candidate.get("path"), "candidate PE")
    digest = _sha256(candidate.get("sha256"), "candidate PE SHA-256")
    size = _positive_int(candidate.get("size"), "candidate PE size")
    if sha256_file(path) != digest or path.stat().st_size != size:
        raise SourceEquivalenceFinalReportError(
            "candidate PE bytes differ from checked metadata"
        )
    return {"path": path, "sha256": digest, "size": size}


def _reconcile_static_provenance(
    *,
    acceptance_bindings: Mapping[str, Any],
    source_identity: Mapping[str, Any],
    attested_identity: Mapping[str, Any],
    candidate_identity: Mapping[str, Any],
    paths: Mapping[str, Path],
) -> None:
    actual = {
        "source_bundle_artifact_sha256": sha256_file(paths["source_bundle"]),
        "source_bundle_sha256": source_identity["source_bundle_sha256"],
        "compilation_attestation_artifact_sha256": sha256_file(
            paths["compilation_attestation"]
        ),
        "attestation_core_sha256": attested_identity[
            "attestation_core_sha256"
        ],
        "original_pe_sha256": source_identity["original_pe_sha256"],
        "candidate_pe_sha256": candidate_identity["sha256"],
        "candidate_pe_size": candidate_identity["size"],
    }
    if dict(acceptance_bindings) != actual:
        raise SourceEquivalenceFinalReportError(
            "checked acceptance provenance does not match the supplied artifacts"
        )
    if (
        attested_identity["source_bundle_artifact_sha256"]
        != actual["source_bundle_artifact_sha256"]
        or attested_identity["source_bundle_sha256"]
        != actual["source_bundle_sha256"]
        or attested_identity["candidate_sha256"]
        != candidate_identity["sha256"]
        or attested_identity["candidate_size"] != candidate_identity["size"]
        or attested_identity["candidate_path"] != candidate_identity["path"]
    ):
        raise SourceEquivalenceFinalReportError(
            "source bundle, compilation attestation, and candidate metadata disagree"
        )


def _functional_identity(
    value: Mapping[str, Any], *, expected_candidate: Mapping[str, Any]
) -> dict[str, Any]:
    if value.get("format") != FUNCTIONAL_REPORT_FORMAT or value.get("status") != "pass":
        raise SourceEquivalenceFinalReportError(
            "candidate functional report did not pass"
        )
    runner = _object(value.get("runner"), "functional-report runner")
    if (
        runner.get("name") != "stage-b-run-functional-suite"
        or runner.get("report_format") != FUNCTIONAL_REPORT_FORMAT
    ):
        raise SourceEquivalenceFinalReportError(
            "functional report was not emitted by the candidate-only runner"
        )
    oracle = _object(value.get("oracle"), "functional-report oracle")
    if (
        oracle.get("kind") != "expected_output"
        or oracle.get("original_runtime_observations") is not False
    ):
        raise SourceEquivalenceFinalReportError(
            "functional report is not a zero-original expected-output run"
        )
    commands = _object(value.get("commands"), "functional-report commands")
    bindings = _object(
        value.get("binary_bindings"), "functional-report binary bindings"
    )
    if set(commands) != {"candidate"} or set(bindings) != {"candidate"}:
        raise SourceEquivalenceFinalReportError(
            "functional report must contain candidate-only commands and bindings"
        )
    command = commands["candidate"]
    if not isinstance(command, list) or not command or not all(
        isinstance(item, str) and item for item in command
    ):
        raise SourceEquivalenceFinalReportError(
            "functional candidate command is incomplete"
        )
    candidate = _object(bindings["candidate"], "functional candidate binding")
    if (
        candidate.get("provided") is not True
        or candidate.get("exists") is not True
        or candidate.get("command_contains_path") is not True
        or _path(candidate.get("path"), "functional candidate path")
        != expected_candidate["path"]
        or _sha256(candidate.get("sha256"), "functional candidate SHA-256")
        != expected_candidate["sha256"]
        or _positive_int(candidate.get("size"), "functional candidate size")
        != expected_candidate["size"]
    ):
        raise SourceEquivalenceFinalReportError(
            "functional report does not bind the checked candidate PE"
        )
    counts = _object(value.get("counts"), "functional-report counts")
    cases = _positive_int(counts.get("cases"), "functional case count")
    passed = _positive_int(counts.get("passed"), "functional passed count")
    failed = _nonnegative_int(counts.get("failed"), "functional failed count")
    rows = value.get("cases")
    if (
        cases != passed
        or failed != 0
        or not isinstance(rows, list)
        or len(rows) != cases
        or any(not isinstance(row, dict) or row.get("status") != "pass" for row in rows)
    ):
        raise SourceEquivalenceFinalReportError(
            "functional report case accounting is not a complete pass"
        )
    target_name = _nonempty_string(value.get("target_name"), "functional target")
    suite_id = _nonempty_string(value.get("suite_id"), "functional suite ID")
    return {"target_name": target_name, "suite_id": suite_id, "cases": cases}


def _proof_bundle_manifest(root: Path) -> Path:
    path = root / "bundle.json"
    if not path.is_file() or path.is_symlink():
        raise SourceEquivalenceFinalReportError(
            "checked proof bundle omits a regular bundle.json"
        )
    return path


def _reference_matches(value: object, actual: Path, filename: str) -> bool:
    reference = _path(value, "artifact reference")
    if reference == actual:
        return True
    return reference.is_dir() and reference / filename == actual


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SourceEquivalenceFinalReportError(
            f"{label} is not valid JSON: {exc}"
        ) from exc
    return _object(value, label)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SourceEquivalenceFinalReportError(
                f"JSON object contains duplicate field {key!r}"
            )
        result[key] = value
    return result


def _exact_fields(
    value: Mapping[str, Any],
    expected: set[str] | frozenset[str],
    label: str,
) -> None:
    if set(value) != set(expected):
        raise SourceEquivalenceFinalReportError(
            f"{label} fields differ: expected {sorted(expected)}, got {sorted(value)}"
        )


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SourceEquivalenceFinalReportError(f"{label} must be an object")
    return value


def _unique_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise SourceEquivalenceFinalReportError(f"{label} must be a string array")
    if len(set(value)) != len(value):
        raise SourceEquivalenceFinalReportError(f"{label} contains duplicates")
    return tuple(value)


def _lean_declaration(value: object, label: str) -> str:
    if not isinstance(value, str) or _LEAN_DECLARATION.fullmatch(value) is None:
        raise SourceEquivalenceFinalReportError(
            f"{label} must be a canonical Lean declaration"
        )
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise SourceEquivalenceFinalReportError(
            f"{label} must be lowercase SHA-256"
        )
    return value


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SourceEquivalenceFinalReportError(f"{label} must be positive")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SourceEquivalenceFinalReportError(f"{label} must be nonnegative")
    return value


def _nonempty_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise SourceEquivalenceFinalReportError(f"{label} must be non-empty")
    return value


def _path(value: object, label: str) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise SourceEquivalenceFinalReportError(f"{label} must be a path")
    return Path(value).resolve()


def _file(value: object, label: str) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise SourceEquivalenceFinalReportError(f"{label} must be a path")
    raw_path = Path(value)
    if raw_path.is_symlink():
        raise SourceEquivalenceFinalReportError(
            f"{label} is not a regular file: {raw_path}"
        )
    path = raw_path.resolve()
    if not path.is_file():
        raise SourceEquivalenceFinalReportError(
            f"{label} is not a regular file: {path}"
        )
    return path


def _directory(value: object, label: str) -> Path:
    if not isinstance(value, (str, Path)) or not str(value):
        raise SourceEquivalenceFinalReportError(f"{label} must be a path")
    raw_path = Path(value)
    if raw_path.is_symlink():
        raise SourceEquivalenceFinalReportError(
            f"{label} is not a regular directory: {raw_path}"
        )
    path = raw_path.resolve()
    if not path.is_dir():
        raise SourceEquivalenceFinalReportError(
            f"{label} is not a regular directory: {path}"
        )
    return path


def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checked-acceptance", required=True)
    parser.add_argument("--detached-axiom-audit", required=True)
    parser.add_argument("--source-bundle", required=True)
    parser.add_argument("--compilation-attestation", required=True)
    parser.add_argument("--candidate-pe-metadata", required=True)
    parser.add_argument("--functional-report", required=True)
    parser.add_argument("--approved-toolchain-axiom", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    write_source_equivalence_final_report(
        out=args.out,
        checked_acceptance=args.checked_acceptance,
        detached_axiom_audit=args.detached_axiom_audit,
        source_bundle=args.source_bundle,
        compilation_attestation=args.compilation_attestation,
        candidate_pe_metadata=args.candidate_pe_metadata,
        functional_report=args.functional_report,
        approved_toolchain_axiom=args.approved_toolchain_axiom,
    )


if __name__ == "__main__":
    _main()


__all__ = [
    "FINAL_REPORT_FILENAME",
    "STANDARD_LOGICAL_AXIOMS",
    "SourceEquivalenceFinalReportError",
    "build_source_equivalence_final_report",
    "write_source_equivalence_final_report",
]
