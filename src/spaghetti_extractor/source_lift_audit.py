"""Non-authorizing audit of a static-to-idiomatic source lifting workflow."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pefile

from .util import sha256_file, write_json


SOURCE_LIFT_AUDIT_FORMAT = "spaghetti-extractor-source-lift-audit-v1"
SOURCE_ITERATION_AUDIT_FORMAT = (
    "spaghetti-extractor-source-iteration-audit-v1"
)


class SourceLiftAuditError(ValueError):
    """Inputs to a source-lift audit are malformed or mutually stale."""


def _group_authority_frontiers(
    rows: Any, *, example_limit: int = 5
) -> list[dict[str, Any]]:
    if not isinstance(rows, list):
        raise SourceLiftAuditError("authority frontiers are malformed")
    groups: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for value in rows:
        if not isinstance(value, Mapping):
            raise SourceLiftAuditError("authority frontier is malformed")
        key = (
            str(value.get("status", "incomplete")),
            str(value.get("family", "unknown")),
            str(value.get("code", "unknown")),
        )
        groups.setdefault(key, []).append(value)
    return [
        {
            "status": status,
            "family": family,
            "code": code,
            "count": len(values),
            "examples": [
                {
                    "record_id": value.get("record_id"),
                    "source_location": value.get("source_location"),
                }
                for value in values[:example_limit]
            ],
        }
        for (status, family, code), values in sorted(groups.items())
    ]


def _source_iteration_result(
    *,
    machine_ir: Path,
    source_binding: Path,
    source_evidence_plan: Path,
    candidate_build: Path,
) -> dict[str, Any]:
    """Check the cheap, root-independent inputs to one source iteration."""

    machine_path = _resolve(machine_ir, "machine-ir-manifest.json")
    binding_path = _resolve(source_binding, "source-project-binding.json")
    evidence_path = _resolve(
        source_evidence_plan, "source-component-evidence.json"
    )
    candidate_path = _resolve(candidate_build, "source-project-build.json")
    machine = _read(machine_path, "stage-a-machine-ir-v2", "machine IR")
    binding = _read(
        binding_path,
        "stage-b-source-project-binding-v1",
        "source binding",
    )
    evidence = _read(
        evidence_path,
        "stage-b-source-component-evidence-plan-v1",
        "source evidence plan",
    )
    candidate = _read(
        candidate_path,
        "stage-b-source-project-build-v1",
        "candidate build",
    )
    import_surface = _compare_import_surfaces(
        machine=machine,
        candidate=candidate,
        candidate_root=candidate_path.parent,
    )

    binary_sha256 = _object(machine.get("binary"), "machine binary").get(
        "sha256"
    )
    bindings = _object(binding.get("bindings"), "source bindings")
    if bindings.get("machine_ir_manifest_sha256") != sha256_file(machine_path):
        raise SourceLiftAuditError("source binding does not bind this machine IR")
    if bindings.get("original_binary_sha256") != binary_sha256:
        raise SourceLiftAuditError("source binding uses another original binary")
    specification_sha256 = bindings.get("specification_sha256")
    if evidence.get("source_project_specification_sha256") != specification_sha256:
        raise SourceLiftAuditError("source evidence plan uses another specification")
    candidate_inputs = _object(candidate.get("inputs"), "candidate inputs")
    if (
        candidate_inputs.get("source_project_specification_sha256")
        != specification_sha256
    ):
        raise SourceLiftAuditError("candidate build uses another specification")
    bound_sources = {
        str(row.get("path")): row.get("sha256")
        for row in _objects(binding.get("sources"), "bound sources")
    }
    candidate_sources = {
        str(row.get("path")): row.get("sha256")
        for row in _objects(candidate_inputs.get("sources"), "candidate sources")
    }
    if bound_sources != candidate_sources:
        raise SourceLiftAuditError("candidate source hashes differ from the binding")
    if (
        candidate_inputs.get("source_project_binding_sha256")
        != binding.get("binding_sha256")
        or candidate_inputs.get("source_project_binding_artifact_sha256")
        != sha256_file(binding_path)
    ):
        raise SourceLiftAuditError(
            "candidate build does not bind this exact source project"
        )

    coverage = _object(binding.get("coverage"), "source coverage")
    linked = coverage.get("linked_islands")
    linked_complete = (
        isinstance(linked, Mapping)
        and linked.get("unknown_units") == 0
        and linked.get("remaining_application_units") == 0
    )
    source_semantics_complete = (
        binding.get("equivalence_status") == "proven"
        and _object(binding.get("authority"), "source authority").get(
            "proves_source_semantics"
        )
        is True
    )
    blockers: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    if not linked_complete:
        blockers.append(
            _blocker(
                "linked_island_classification_incomplete",
                "source-binding",
                "classify every non-source machine unit and leave no unknown or unlifted application units",
                detail={
                    "linked_islands": linked,
                    "remaining_machine_units": coverage.get(
                        "remaining_machine_units"
                    ),
                },
            )
        )
    if not source_semantics_complete:
        warnings.append(
            {
                "code": "machine_to_source_semantics_not_proven",
                "family": "source-assurance",
                "detail": {
                    "equivalence_status": binding.get("equivalence_status"),
                    "accepted_assumptions": evidence.get(
                        "accepted_assumptions"
                    ),
                },
                "next_action": (
                    "complete explicit source-call, dependency-envelope, and "
                    "candidate-only component validation for the "
                    "validation-qualified profile, or provide checked semantic "
                    "refinement for the stronger proof profile"
                ),
            }
        )
    if import_surface["status"] == "different":
        warnings.append(
            {
                "code": "candidate_static_import_surface_differs",
                "family": "external-protocol",
                "detail": import_surface,
                "next_action": (
                    "review source/runtime substitutions that add or remove imported "
                    "operations; final authority must still prove the reachable external "
                    "event sequence"
                ),
            }
        )

    machine_issues = _objects(machine.get("issues", []), "machine issues")
    grouped = Counter(str(row.get("category", "malformed")) for row in machine_issues)
    machine_frontiers = [
        {
            "category": category,
            "count": count,
            "examples": [
                {
                    "id": row.get("id"),
                    "location": row.get("location"),
                    "next_action": row.get("next_action"),
                }
                for row in machine_issues
                if row.get("category") == category
            ][:3],
        }
        for category, count in sorted(grouped.items())
    ]
    stages = {
        "machine_ir": {
            "status": machine.get("status"),
            "units": _object(machine.get("counts"), "machine counts").get(
                "units"
            ),
            "issues": len(machine_issues),
        },
        "source_binding": {
            "status": binding.get("status"),
            "reviewed_source_units": coverage.get("source_bound_units"),
            "machine_units": coverage.get("machine_units"),
            "linked_classification_complete": linked_complete,
        },
        "source_assurance": {
            "status": (
                "checked_semantic_refinement"
                if source_semantics_complete
                else "validation_pending"
            ),
            "proves_source_semantics": source_semantics_complete,
            "validation_backed_profile_available": True,
        },
        "candidate_build": {
            "status": candidate.get("status"),
            "candidate": _object(
                _object(candidate.get("outputs"), "candidate outputs").get(
                    "candidate"
                ),
                "candidate output",
            ),
        },
        "candidate_import_surface": import_surface,
        "final_authority_join": {
            "status": "not_evaluated",
            "authorizing": False,
            "next_action": (
                "build the final source-lift audit only when release authority "
                "or runtime permission is required"
            ),
        },
        "candidate_behavior": {
            "status": "not_run",
            "authorized_to_run": False,
            "original_runtime_observations": False,
        },
    }
    return {
        "format": SOURCE_ITERATION_AUDIT_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "source_iteration_complete": not blockers,
        "original_binary_executed": False,
        "bindings": {
            "original_binary_sha256": binary_sha256,
            "machine_ir_manifest_sha256": sha256_file(machine_path),
            "source_binding_sha256": binding.get("binding_sha256"),
            "source_evidence_plan_sha256": evidence.get("plan_sha256"),
            "candidate_sha256": stages["candidate_build"]["candidate"].get(
                "sha256"
            ),
        },
        "stages": stages,
        "blockers": blockers,
        "warnings": warnings,
        "machine_ir_frontiers": machine_frontiers,
        "trust": {
            "authorizes_candidate_generation": False,
            "authorizes_runtime_testing": False,
            "diagnostic_only": True,
        },
    }


def audit_source_iteration(
    *,
    machine_ir: Path,
    source_binding: Path,
    source_evidence_plan: Path,
    candidate_build: Path,
    out: Path,
) -> dict[str, Any]:
    """Emit cheap source-lift feedback without evaluating Stage A authority."""

    result = _source_iteration_result(
        machine_ir=machine_ir,
        source_binding=source_binding,
        source_evidence_plan=source_evidence_plan,
        candidate_build=candidate_build,
    )
    write_json(out, result)
    return result


def _join_source_lift_values(
    iteration: Mapping[str, Any], authority: Mapping[str, Any]
) -> dict[str, Any]:
    if iteration.get("format") != SOURCE_ITERATION_AUDIT_FORMAT:
        raise SourceLiftAuditError("unsupported source iteration audit format")
    if authority.get("format") != "spaghetti-extractor-authority-diagnostics-v3":
        raise SourceLiftAuditError("unsupported authority diagnostics format")
    iteration_bindings = _object(iteration.get("bindings"), "iteration bindings")
    authority_bindings = _objects(
        authority.get("binary_bindings"), "authority binary bindings"
    )
    expected_binary = iteration_bindings.get("original_binary_sha256")
    matching_bindings = [
        row
        for row in authority_bindings
        if row.get("name") == "binary"
        and row.get("kind") == "pe32"
        and row.get("sha256") == expected_binary
    ]
    if len(matching_bindings) != 1 or len(authority_bindings) != 1:
        raise SourceLiftAuditError(
            "authority diagnostics do not bind exactly this original PE32 binary"
        )

    authority_complete = authority.get("authorizing") is True
    blockers = [
        _object(row, "iteration blocker")
        for row in _objects(iteration.get("blockers"), "iteration blockers")
    ]
    if not authority_complete:
        blockers.insert(
            0,
            _blocker(
                "static_authority_incomplete",
                "static-authority",
                "close the primary v3 authority frontiers before any candidate runtime test",
                detail=authority.get("final_authority"),
            ),
        )
    blockers.append(
        _blocker(
            "candidate_validation_not_joined",
            "candidate-validation",
            (
                "run the separately gated candidate-only validation graph and "
                "join it through the validation-qualified completion receipt"
            ),
            detail={"authority_permits_validation": authority_complete},
        )
    )
    stages = _object(iteration.get("stages"), "iteration stages")
    stages["final_authority_join"] = {
        "status": authority.get("status"),
        "authorizing": authority_complete,
    }
    stages["candidate_behavior"] = {
        "status": "not_run",
        "authorized_to_run": authority_complete,
        "original_runtime_observations": False,
    }
    return {
        "format": SOURCE_LIFT_AUDIT_FORMAT,
        "status": "complete" if not blockers else "incomplete",
        "whole_program_lift_complete": False,
        "original_binary_executed": False,
        "bindings": iteration_bindings,
        "stages": stages,
        "blockers": blockers,
        "warnings": _objects(iteration.get("warnings"), "iteration warnings"),
        "machine_ir_frontiers": _objects(
            iteration.get("machine_ir_frontiers"), "machine IR frontiers"
        ),
        "authority_frontiers": _group_authority_frontiers(
            authority.get("primary_frontiers", [])
        ),
        "trust": {
            "authorizes_candidate_generation": False,
            "authorizes_runtime_testing": False,
            "diagnostic_only": True,
        },
    }


def join_source_lift_authority(
    *, source_iteration_audit: Path, authority_diagnostics: Path, out: Path
) -> dict[str, Any]:
    """Join cheap source feedback to the expensive final authority boundary."""

    iteration_path = _resolve(
        source_iteration_audit, "source-iteration-audit.json"
    )
    authority_path = _resolve(
        authority_diagnostics, "authority-diagnostics-v3.json"
    )
    iteration = _read(
        iteration_path, SOURCE_ITERATION_AUDIT_FORMAT, "source iteration audit"
    )
    authority = _read(
        authority_path,
        "spaghetti-extractor-authority-diagnostics-v3",
        "authority diagnostics",
    )
    result = _join_source_lift_values(iteration, authority)
    result["bindings"]["source_iteration_audit_sha256"] = sha256_file(
        iteration_path
    )
    result["bindings"]["authority_diagnostics_sha256"] = sha256_file(
        authority_path
    )
    write_json(out, result)
    return result


def audit_source_lift(
    *,
    machine_ir: Path,
    authority_diagnostics: Path,
    source_binding: Path,
    source_evidence_plan: Path,
    candidate_build: Path,
    out: Path,
) -> dict[str, Any]:
    """Compatibility entry point for an in-process full diagnostic audit."""

    iteration = _source_iteration_result(
        machine_ir=machine_ir,
        source_binding=source_binding,
        source_evidence_plan=source_evidence_plan,
        candidate_build=candidate_build,
    )
    authority_path = _resolve(
        authority_diagnostics, "authority-diagnostics-v3.json"
    )
    authority = _read(
        authority_path,
        "spaghetti-extractor-authority-diagnostics-v3",
        "authority diagnostics",
    )
    result = _join_source_lift_values(iteration, authority)
    result["bindings"]["authority_diagnostics_sha256"] = sha256_file(
        authority_path
    )
    write_json(out, result)
    return result


def _compare_import_surfaces(
    *,
    machine: Mapping[str, Any],
    candidate: Mapping[str, Any],
    candidate_root: Path,
) -> dict[str, Any]:
    original_rows = _object(machine.get("binary"), "machine binary").get(
        "imports"
    )
    output = _object(candidate.get("outputs"), "candidate outputs").get(
        "candidate"
    )
    candidate_row = _object(output, "candidate output")
    relative = candidate_row.get("path")
    if not isinstance(original_rows, list) or not isinstance(relative, str):
        return {
            "status": "unavailable",
            "same_static_import_set": None,
            "diagnostic_only": True,
        }
    root = candidate_root.resolve()
    binary = (root / relative).resolve()
    try:
        binary.relative_to(root)
    except ValueError as error:
        raise SourceLiftAuditError("candidate binary path escapes its build") from error
    if not binary.is_file():
        return {
            "status": "unavailable",
            "same_static_import_set": None,
            "diagnostic_only": True,
        }
    expected_sha256 = candidate_row.get("sha256")
    expected_bytes = candidate_row.get("bytes")
    if expected_sha256 != sha256_file(binary) or expected_bytes != binary.stat().st_size:
        raise SourceLiftAuditError(
            "candidate build manifest does not bind the inspected PE"
        )
    original = sorted(
        {
            _import_identity(_object(row, "original import"))
            for row in original_rows
        }
    )
    observed = _pe_import_identities(binary)
    original_set = set(original)
    observed_set = set(observed)
    same = original_set == observed_set
    return {
        "status": "matching" if same else "different",
        "same_static_import_set": same,
        "original_imports": len(original),
        "candidate_imports": len(observed),
        "only_original": [
            _import_payload(value) for value in sorted(original_set - observed_set)
        ],
        "only_candidate": [
            _import_payload(value) for value in sorted(observed_set - original_set)
        ],
        "diagnostic_only": True,
        "static_import_identity_does_not_prove_event_equivalence": True,
    }


def _pe_import_identities(path: Path) -> list[tuple[str, str, int]]:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
            ]
        )
    except pefile.PEFormatError as error:
        raise SourceLiftAuditError(f"candidate is not a valid PE: {error}") from error
    result = set()
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
        dll = descriptor.dll.decode("ascii", errors="replace").lower()
        for imported in descriptor.imports:
            symbol = (
                imported.name.decode("ascii", errors="replace")
                if imported.name is not None
                else ""
            )
            result.add((dll, symbol, int(imported.ordinal or 0)))
    pe.close()
    return sorted(result)


def _import_identity(row: Mapping[str, Any]) -> tuple[str, str, int]:
    dll = row.get("dll")
    symbol = row.get("symbol")
    ordinal = row.get("ordinal")
    if not isinstance(dll, str):
        raise SourceLiftAuditError("original import has no DLL identity")
    if symbol is not None and not isinstance(symbol, str):
        raise SourceLiftAuditError("original import symbol is malformed")
    if ordinal is not None and not isinstance(ordinal, int):
        raise SourceLiftAuditError("original import ordinal is malformed")
    return (dll.lower(), symbol or "", ordinal or 0)


def _import_payload(value: tuple[str, str, int]) -> dict[str, Any]:
    dll, symbol, ordinal = value
    return {
        "dll": dll,
        "symbol": symbol or None,
        "ordinal": ordinal or None,
    }


def _resolve(path: Path, filename: str) -> Path:
    return path / filename if path.is_dir() else path


def _read(path: Path, expected_format: str, description: str) -> dict[str, Any]:
    import json

    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise SourceLiftAuditError(f"cannot read {description}: {error}") from error
    row = _object(value, description)
    if row.get("format") != expected_format:
        raise SourceLiftAuditError(f"unsupported {description} format")
    return row


def _object(value: Any, description: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceLiftAuditError(f"{description} is not an object")
    return dict(value)


def _objects(value: Any, description: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise SourceLiftAuditError(f"{description} is not an array")
    return [_object(row, description) for row in value]


def _blocker(
    code: str, stage: str, next_action: str, *, detail: Any
) -> dict[str, Any]:
    return {
        "status": "incomplete",
        "code": code,
        "stage": stage,
        "next_action": next_action,
        "detail": detail,
    }


__all__ = [
    "SOURCE_ITERATION_AUDIT_FORMAT",
    "SOURCE_LIFT_AUDIT_FORMAT",
    "SourceLiftAuditError",
    "audit_source_iteration",
    "audit_source_lift",
    "join_source_lift_authority",
]
