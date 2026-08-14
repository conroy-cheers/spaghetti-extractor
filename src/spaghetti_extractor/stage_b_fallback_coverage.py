"""Hash-bound implementation coverage for static-hybrid candidate generation.

This receipt has no behavioral or static-completeness authority.  It checks
only that every unit in the exact structural machine-IR inventory has one
selected dispatch implementation and that every fallback entry exists in the
selected semantic-interpreter lowering.  The independent v2 final audit is the
sole static authority consumed by the candidate-authority receipt.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .artifact_formats import MACHINE_IR_FORMAT
from .stage_b_interpreter_backend import (
    STAGE_B_INTERPRETER_PACKAGE_FORMAT,
    STAGE_B_INTERPRETER_PROGRAM_FORMAT,
)
from .util import sha256_bytes, sha256_file, write_json


FALLBACK_COVERAGE_RECEIPT_FORMAT = "stage-b-fallback-coverage-receipt-v3"
FALLBACK_COVERAGE_CHECKER_ID = "spaghetti-extractor-fallback-coverage-checker"
FALLBACK_COVERAGE_CHECKER_VERSION = 3
PORTABLE_REPLACEMENT_SELECTION_FORMAT = (
    "stage-b-portable-replacement-selection-v1"
)
PORTABLE_COMPONENT_SELECTION_V2_FORMAT = (
    "spaghetti-extractor-portable-component-selection-v2"
)

_PORTABLE_SELECTION_FIELDS = frozenset({
    "unit_id",
    "rva",
    "replacement_id",
    "cluster_id",
    "component_manifest_sha256",
    "fallback_on_unimplemented",
})
_PORTABLE_SELECTION_FIELDS_V2 = _PORTABLE_SELECTION_FIELDS | frozenset(
    {"dispatch_role", "entry_rva"}
)


class FallbackCoverageReceiptError(ValueError):
    """Coverage evidence is malformed, stale, incomplete, or ambiguous."""


@dataclass(frozen=True)
class FallbackCoverageReceipt:
    """Validated implementation coverage bound to exact build inputs."""

    path: Path
    artifact_sha256: str
    receipt_sha256: str
    machine_ir_sha256: str
    machine_ir_manifest_sha256: str
    interpreter_package_sha256: str
    interpreter_program_sha256: str
    payload: Mapping[str, Any]

    def manifest_binding(self) -> dict[str, Any]:
        return {
            "format": FALLBACK_COVERAGE_RECEIPT_FORMAT,
            "status": "complete",
            "artifact_sha256": self.artifact_sha256,
            "receipt_sha256": self.receipt_sha256,
            "machine_ir_sha256": self.machine_ir_sha256,
            "machine_ir_manifest_sha256": self.machine_ir_manifest_sha256,
            "interpreter_package_sha256": self.interpreter_package_sha256,
            "interpreter_program_sha256": self.interpreter_program_sha256,
        }


def write_stage_b_fallback_coverage_receipt(
    *,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    interpreter_package: Path | str,
    out: Path | str,
    portable_replacements: (
        Sequence[Mapping[str, Any]] | Path | str | None
    ) = None,
) -> dict[str, Any]:
    """Write a deterministic receipt for the complete structural universe."""

    payload = _expected_fallback_coverage_payload(
        machine_ir=Path(machine_ir),
        machine_ir_manifest=Path(machine_ir_manifest),
        interpreter_package=Path(interpreter_package),
        portable_replacements=portable_replacements,
    )
    write_json(Path(out), payload)
    return payload


def validate_stage_b_fallback_coverage_receipt(
    *,
    receipt: Path | str,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    interpreter_package: Path | str,
    portable_replacements: (
        Sequence[Mapping[str, Any]] | Path | str | None
    ) = None,
) -> FallbackCoverageReceipt:
    """Recompute every receipt field from the submitted artifacts."""

    receipt_path = _file(Path(receipt), "fallback-coverage receipt")
    actual = _read_object(receipt_path, "fallback-coverage receipt")
    expected = _expected_fallback_coverage_payload(
        machine_ir=Path(machine_ir),
        machine_ir_manifest=Path(machine_ir_manifest),
        interpreter_package=Path(interpreter_package),
        portable_replacements=portable_replacements,
    )
    if actual != expected:
        raise FallbackCoverageReceiptError(
            "fallback-coverage receipt is stale or binds different inputs"
        )
    inputs = _object(actual.get("inputs"), "fallback-coverage inputs")
    lowering = _object(
        inputs.get("semantic_interpreter_lowering"),
        "semantic-interpreter lowering binding",
    )
    return FallbackCoverageReceipt(
        path=receipt_path,
        artifact_sha256=sha256_file(receipt_path),
        receipt_sha256=_sha256(
            actual.get("receipt_sha256"), "fallback-coverage receipt SHA-256"
        ),
        machine_ir_sha256=_artifact_sha256(inputs, "machine_ir"),
        machine_ir_manifest_sha256=_artifact_sha256(
            inputs, "machine_ir_manifest"
        ),
        interpreter_package_sha256=_artifact_sha256(lowering, "package"),
        interpreter_program_sha256=_artifact_sha256(lowering, "program"),
        payload=actual,
    )


def _expected_fallback_coverage_payload(
    *,
    machine_ir: Path,
    machine_ir_manifest: Path,
    interpreter_package: Path,
    portable_replacements: Sequence[Mapping[str, Any]] | Path | str | None,
) -> dict[str, Any]:
    machine_ir = _file(machine_ir, "machine IR")
    machine_ir_manifest = _file(machine_ir_manifest, "machine-IR manifest")
    package_path, program_path = _interpreter_artifact_paths(interpreter_package)

    machine_ir_sha256 = sha256_file(machine_ir)
    manifest_sha256 = sha256_file(machine_ir_manifest)
    units = _read_machine_ir_units(machine_ir)
    unit_by_id = {unit["id"]: unit for unit in units}
    manifest = _read_object(machine_ir_manifest, "machine-IR manifest")
    _validate_manifest_binding(
        manifest, machine_ir_sha256=machine_ir_sha256, units=unit_by_id
    )
    package = _read_object(package_path, "semantic-interpreter package")
    program = _read_object(program_path, "semantic-interpreter program")
    lowering_binding, lowering_by_id = _validate_interpreter_lowering(
        package_path=package_path,
        package=package,
        program_path=program_path,
        program=program,
        machine_ir_sha256=machine_ir_sha256,
        units=unit_by_id,
    )

    structural_ids = set(unit_by_id)
    missing_lowerings = sorted(structural_ids - set(lowering_by_id))
    if missing_lowerings:
        raise FallbackCoverageReceiptError(
            "structural machine-IR unit cannot be lowered: "
            + ", ".join(missing_lowerings)
        )
    if set(lowering_by_id) != structural_ids:
        raise FallbackCoverageReceiptError(
            "semantic-interpreter lowering does not exactly cover the structural universe"
        )
    replacements, replacement_binding = _portable_replacement_selections(
        portable_replacements,
        structural_ids=structural_ids,
        units=unit_by_id,
    )

    entries: list[dict[str, Any]] = []
    for unit_id in sorted(
        structural_ids, key=lambda identity: (unit_by_id[identity]["rva"], identity)
    ):
        unit = unit_by_id[unit_id]
        lowering = lowering_by_id[unit_id]
        replacement = replacements.get(unit_id)
        implementation_kind = (
            "machine_ir_fallback"
            if replacement is None
            else "portable_replacement"
            if replacement["dispatch_role"] == "entry"
            else "portable_component_member"
        )
        body: dict[str, Any] = {
            "unit_id": unit_id,
            "rva": unit["rva"],
            "unit_contract_sha256": unit["contract_sha256"],
            "source_span_sha256": unit["source_span_sha256"],
            "machine_ir_record_sha256": unit["record_sha256"],
            "lowering_transfer_sha256": lowering["transfer_sha256"],
            "implementation_kind": implementation_kind,
            "dispatch_lookup": (
                "stage_b_region_override_lookup"
                if implementation_kind == "portable_replacement"
                else "component_entry_subsumed"
                if implementation_kind == "portable_component_member"
                else "stage_b_program_lookup"
            ),
            "portable_replacement": replacement,
        }
        entries.append({**body, "entry_sha256": _canonical_sha256(body)})

    if len(entries) != len(structural_ids) or len({
        row["unit_id"] for row in entries
    }) != len(entries):
        raise FallbackCoverageReceiptError(
            "structural units do not have exactly one implementation kind"
        )

    core: dict[str, Any] = {
        "format": FALLBACK_COVERAGE_RECEIPT_FORMAT,
        "status": "complete",
        "authority": (
            "implementation availability only; no reachability or behavioral acceptance authority"
        ),
        "checker": {
            "id": FALLBACK_COVERAGE_CHECKER_ID,
            "version": FALLBACK_COVERAGE_CHECKER_VERSION,
        },
        "schemas": {
            "receipt": FALLBACK_COVERAGE_RECEIPT_FORMAT,
            "machine_ir": MACHINE_IR_FORMAT,
            "semantic_interpreter_package": STAGE_B_INTERPRETER_PACKAGE_FORMAT,
            "semantic_interpreter_program": STAGE_B_INTERPRETER_PROGRAM_FORMAT,
        },
        "policy": {
            "potential_transfers_may_be_deferred": False,
            "structural_units_require_lowering": True,
            "one_implementation_kind_per_structural_unit": True,
            "rooted_containment_authority": False,
            "default_implementation_kind": "machine_ir_fallback",
            "portable_replacements_must_be_explicit": True,
            "portable_fallback_on_unimplemented": False,
            "candidate_generation_fails_closed": True,
        },
        "inputs": {
            "machine_ir": _artifact_binding(machine_ir, machine_ir_sha256),
            "machine_ir_manifest": _artifact_binding(
                machine_ir_manifest, manifest_sha256
            ),
            "semantic_interpreter_lowering": lowering_binding,
            "portable_replacements": replacement_binding,
        },
        "counts": {
            "structural_units": len(structural_ids),
            "implementation_entries": len(entries),
            "machine_ir_fallback": sum(
                row["implementation_kind"] == "machine_ir_fallback"
                for row in entries
            ),
            "portable_replacement": sum(
                row["implementation_kind"] == "portable_replacement"
                for row in entries
            ),
            "portable_component_member": sum(
                row["implementation_kind"] == "portable_component_member"
                for row in entries
            ),
            "blockers": 0,
        },
        "entries": entries,
        "blockers": [],
    }
    return {**core, "receipt_sha256": _canonical_sha256(core)}


def _read_machine_ir_units(path: Path) -> tuple[dict[str, Any], ...]:
    result: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_rvas: set[int] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise FallbackCoverageReceiptError(f"cannot read machine IR: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line, object_pairs_hook=_reject_duplicates)
        except (json.JSONDecodeError, ValueError) as exc:
            raise FallbackCoverageReceiptError(
                f"cannot read machine IR line {line_number}: {exc}"
            ) from exc
        unit = _object(raw, f"machine IR line {line_number}")
        if unit.get("format") != MACHINE_IR_FORMAT or unit.get("record_kind") != "unit":
            raise FallbackCoverageReceiptError(
                f"machine IR line {line_number} has an unsupported format"
            )
        identity = _identity(unit.get("id"), f"machine IR line {line_number} id")
        source = _object(unit.get("source"), f"{identity} source")
        original = _object(source.get("original"), f"{identity} original span")
        rva = _u32(original.get("rva_start"), f"{identity} start RVA")
        contract_sha256 = _sha256(
            source.get("contract_sha256"), f"{identity} unit contract SHA-256"
        )
        source_span_sha256 = _sha256(
            source.get("instruction_bytes_sha256"),
            f"{identity} source-span SHA-256",
        )
        if identity in seen_ids:
            raise FallbackCoverageReceiptError(
                f"machine IR contains duplicate unit id {identity}"
            )
        if rva in seen_rvas:
            raise FallbackCoverageReceiptError(
                f"machine IR contains duplicate dispatch RVA 0x{rva:x}"
            )
        seen_ids.add(identity)
        seen_rvas.add(rva)
        result.append({
            "id": identity,
            "rva": rva,
            "contract_sha256": contract_sha256,
            "source_span_sha256": source_span_sha256,
            "record_sha256": _canonical_sha256(unit),
        })
    if not result:
        raise FallbackCoverageReceiptError("machine IR contains no units")
    return tuple(result)


def _validate_manifest_binding(
    manifest: Mapping[str, Any],
    *,
    machine_ir_sha256: str,
    units: Mapping[str, Mapping[str, Any]],
) -> None:
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise FallbackCoverageReceiptError(
            "machine-IR manifest has an unsupported format"
        )
    artifacts = _object(manifest.get("artifacts"), "machine-IR artifacts")
    artifact = _object(artifacts.get("machine_ir"), "machine-IR artifact")
    if (
        artifact.get("format") != MACHINE_IR_FORMAT
        or artifact.get("sha256") != machine_ir_sha256
    ):
        raise FallbackCoverageReceiptError(
            "machine-IR manifest does not bind the submitted machine IR"
        )
    counts = _object(manifest.get("counts"), "machine-IR counts")
    if counts.get("units") != len(units):
        raise FallbackCoverageReceiptError(
            "machine-IR manifest unit count does not match the submitted structural universe"
        )


def _interpreter_artifact_paths(path: Path) -> tuple[Path, Path]:
    if path.is_dir():
        package_path = path / "state-machine-interpreter-package.json"
    else:
        package_path = path
    package_path = _file(package_path, "semantic-interpreter package")
    package = _read_object(package_path, "semantic-interpreter package")
    program_binding = _object(
        package.get("program"), "semantic-interpreter program binding"
    )
    program_name = program_binding.get("path")
    if (
        not isinstance(program_name, str)
        or not program_name
        or Path(program_name).name != program_name
    ):
        raise FallbackCoverageReceiptError(
            "semantic-interpreter program path must be one local file name"
        )
    return package_path, _file(
        package_path.parent / program_name, "semantic-interpreter program"
    )


def _validate_interpreter_lowering(
    *,
    package_path: Path,
    package: Mapping[str, Any],
    program_path: Path,
    program: Mapping[str, Any],
    machine_ir_sha256: str,
    units: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    package_counts = _object(package.get("counts"), "interpreter package counts")
    package_blockers = _list(package.get("blockers"), "interpreter blockers")
    package_coverage = _object(
        package.get("semantic_coverage"), "interpreter semantic coverage"
    )
    if (
        package.get("format") != STAGE_B_INTERPRETER_PACKAGE_FORMAT
        or package.get("status") != "ready"
        or package.get("input_mode") != "sanitized_machine_ir_v2"
        or package_blockers
        or package_counts.get("input_transfers") != len(units)
        or package_counts.get("blocked_transfers") != 0
        or package_counts.get("deferred_transfers") != 0
        or package_coverage.get("status") != "complete"
        or package.get("execution_policy") != "complete_transfer_inventory_v1"
    ):
        raise FallbackCoverageReceiptError(
            "selected semantic-interpreter package is not a complete machine-IR lowering"
        )
    machine_binding = _object(
        package.get("machine_ir"), "interpreter machine-IR binding"
    )
    if machine_binding.get("sha256") != machine_ir_sha256:
        raise FallbackCoverageReceiptError(
            "semantic-interpreter package binds a different machine IR"
        )
    program_binding = _object(
        package.get("program"), "semantic-interpreter program binding"
    )
    program_sha256 = sha256_file(program_path)
    if (
        program_binding.get("path") != program_path.name
        or program_binding.get("sha256") != program_sha256
    ):
        raise FallbackCoverageReceiptError(
            "semantic-interpreter package does not bind its exact program artifact"
        )
    sources = _validated_lowering_sources(package_path.parent, package.get("sources"))
    adapted_semantics = _validated_adapted_semantics(
        package_path.parent, package.get("adapted_semantics")
    )

    program_counts = _object(program.get("counts"), "interpreter program counts")
    program_blockers = _list(program.get("blockers"), "interpreter program blockers")
    program_coverage = _object(
        program.get("semantic_coverage"), "interpreter program coverage"
    )
    transfers = _list(program.get("transfers"), "interpreter program transfers")
    if (
        program.get("format") != STAGE_B_INTERPRETER_PROGRAM_FORMAT
        or program.get("status") != "ready"
        or program.get("state_machine_sha256") != machine_ir_sha256
        or program_blockers
        or program_counts.get("input_transfers") != len(units)
        or program_counts.get("transfers") != len(transfers)
        or package_counts.get("transfers") != len(transfers)
        or program_counts.get("blocked_transfers") != 0
        or program_counts.get("deferred_transfers") != 0
        or program_coverage.get("status") != "complete"
        or program.get("execution_policy") != "complete_transfer_inventory_v1"
    ):
        raise FallbackCoverageReceiptError(
            "selected semantic-interpreter program is not a complete lowering"
        )

    lowered: dict[str, dict[str, Any]] = {}
    seen_rvas: set[int] = set()
    for index, raw in enumerate(transfers):
        transfer = _object(raw, f"interpreter transfer {index}")
        identity = _identity(transfer.get("id"), f"interpreter transfer {index} id")
        if identity in lowered:
            raise FallbackCoverageReceiptError(
                f"semantic-interpreter program contains duplicate transfer {identity}"
            )
        unit = units.get(identity)
        if unit is None:
            raise FallbackCoverageReceiptError(
                f"semantic-interpreter program contains unknown transfer {identity}"
            )
        rva = _u32(transfer.get("rva_start"), f"{identity} lowering RVA")
        if rva in seen_rvas:
            raise FallbackCoverageReceiptError(
                f"semantic-interpreter program contains duplicate RVA 0x{rva:x}"
            )
        if rva != unit["rva"]:
            raise FallbackCoverageReceiptError(
                f"{identity} lowering binds a different dispatch RVA"
            )
        if (
            _sha256(
                transfer.get("contract_sha256"),
                f"{identity} lowering contract SHA-256",
            )
            != unit["contract_sha256"]
        ):
            raise FallbackCoverageReceiptError(
                f"{identity} lowering binds a different unit contract"
            )
        if (
            _sha256(
                transfer.get("source_span_sha256"),
                f"{identity} lowering source-span SHA-256",
            )
            != unit["source_span_sha256"]
        ):
            raise FallbackCoverageReceiptError(
                f"{identity} lowering binds a different source span"
            )
        seen_rvas.add(rva)
        lowered[identity] = {
            "transfer_sha256": _canonical_sha256(transfer),
        }
    artifact_rows = [
        {"role": "program", "path": program_path.name, "sha256": program_sha256},
        *sources,
        adapted_semantics,
    ]
    return (
        {
            "package": {
                **_artifact_binding(package_path, sha256_file(package_path)),
                "format": STAGE_B_INTERPRETER_PACKAGE_FORMAT,
            },
            "program": {
                **_artifact_binding(program_path, program_sha256),
                "format": STAGE_B_INTERPRETER_PROGRAM_FORMAT,
            },
            "sources": sources,
            "adapted_semantics": adapted_semantics,
            "artifact_set_sha256": _canonical_sha256(artifact_rows),
        },
        lowered,
    )


def _validated_lowering_sources(root: Path, value: Any) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    seen_roles: set[str] = set()
    seen_paths: set[str] = set()
    for index, raw in enumerate(_list(value, "interpreter package sources")):
        row = _object(raw, f"interpreter source {index}")
        if set(row) != {"role", "path", "sha256"}:
            raise FallbackCoverageReceiptError(
                f"interpreter source {index} fields are not canonical"
            )
        role = _identity(row.get("role"), f"interpreter source {index} role")
        name = row.get("path")
        if not isinstance(name, str) or not name or Path(name).name != name:
            raise FallbackCoverageReceiptError(
                f"interpreter source {index} path must be one local file name"
            )
        if role in seen_roles or name in seen_paths:
            raise FallbackCoverageReceiptError(
                "semantic-interpreter source inventory contains duplicates"
            )
        path = _file(root / name, f"interpreter source {name}")
        digest = _sha256(row.get("sha256"), f"interpreter source {name} SHA-256")
        if sha256_file(path) != digest:
            raise FallbackCoverageReceiptError(
                f"semantic-interpreter package has a stale source binding for {name}"
            )
        seen_roles.add(role)
        seen_paths.add(name)
        result.append({"role": role, "path": name, "sha256": digest})
    return sorted(result, key=lambda row: (row["role"], row["path"]))


def _validated_adapted_semantics(root: Path, value: Any) -> dict[str, str]:
    row = _object(value, "interpreter adapted-semantics binding")
    if set(row) != {"role", "path", "sha256"}:
        raise FallbackCoverageReceiptError(
            "interpreter adapted-semantics binding fields are not canonical"
        )
    if row.get("role") != "byte_free_definedness_analysis_input":
        raise FallbackCoverageReceiptError(
            "interpreter adapted-semantics binding has an unsupported role"
        )
    name = row.get("path")
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise FallbackCoverageReceiptError(
            "interpreter adapted-semantics path must be one local file name"
        )
    path = _file(root / name, "interpreter adapted semantics")
    digest = _sha256(
        row.get("sha256"), "interpreter adapted-semantics SHA-256"
    )
    if sha256_file(path) != digest:
        raise FallbackCoverageReceiptError(
            "semantic-interpreter package has a stale adapted-semantics binding"
        )
    return {"role": str(row["role"]), "path": name, "sha256": digest}


def _portable_replacement_selections(
    value: Sequence[Mapping[str, Any]] | Path | str | None,
    *,
    structural_ids: set[str],
    units: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any] | None]:
    artifact_binding: dict[str, Any] | None = None
    if value is None:
        raw_values: Sequence[Any] = ()
    elif isinstance(value, (Path, str)):
        path = _file(Path(value), "portable-replacement selection")
        payload = _read_json(path, "portable-replacement selection")
        if isinstance(payload, Mapping):
            selection_format = payload.get("format")
            if selection_format not in {
                PORTABLE_REPLACEMENT_SELECTION_FORMAT,
                PORTABLE_COMPONENT_SELECTION_V2_FORMAT,
            }:
                raise FallbackCoverageReceiptError(
                    "portable-replacement selection has an unsupported format"
                )
            raw_values = _list(
                payload.get(
                    "entries"
                    if selection_format == PORTABLE_COMPONENT_SELECTION_V2_FORMAT
                    else "replacements"
                ),
                "portable-replacement selections",
            )
        else:
            raw_values = _list(payload, "portable-replacement selections")
        artifact_binding = _artifact_binding(path, sha256_file(path))
    else:
        if isinstance(value, (str, bytes)):
            raise FallbackCoverageReceiptError(
                "portable replacements must be a sequence of objects"
            )
        raw_values = value

    result: dict[str, dict[str, Any]] = {}
    seen_rvas: set[int] = set()
    for index, raw in enumerate(raw_values):
        row = _object(raw, f"portable replacement {index}")
        v2 = set(row) == _PORTABLE_SELECTION_FIELDS_V2
        if not v2 and set(row) != _PORTABLE_SELECTION_FIELDS:
            raise FallbackCoverageReceiptError(
                f"portable replacement {index} fields are not canonical"
            )
        identity = _identity(
            row.get("unit_id"), f"portable replacement {index} unit id"
        )
        rva = _u32(row.get("rva"), f"portable replacement {index} RVA")
        unit = units.get(identity)
        if identity not in structural_ids or unit is None or unit["rva"] != rva:
            raise FallbackCoverageReceiptError(
                "portable replacement does not bind one structural machine-IR unit"
            )
        if identity in result or rva in seen_rvas:
            raise FallbackCoverageReceiptError(
                "portable replacement selection contains duplicate dispatch assignments"
            )
        if row.get("fallback_on_unimplemented") is not False:
            raise FallbackCoverageReceiptError(
                "portable replacements must disable machine-IR fallback"
            )
        normalized = {
            "replacement_id": _identity(
                row.get("replacement_id"),
                f"portable replacement {index} replacement id",
            ),
            "cluster_id": _identity(
                row.get("cluster_id"),
                f"portable replacement {index} cluster id",
            ),
            "component_manifest_sha256": _sha256(
                row.get("component_manifest_sha256"),
                f"portable replacement {index} component manifest SHA-256",
            ),
            "fallback_on_unimplemented": False,
            "dispatch_role": (
                _identity(
                    row.get("dispatch_role"),
                    f"portable replacement {index} dispatch role",
                )
                if v2
                else "entry"
            ),
            "entry_rva": (
                _u32(
                    row.get("entry_rva"),
                    f"portable replacement {index} entry RVA",
                )
                if v2
                else rva
            ),
        }
        if normalized["dispatch_role"] not in {"entry", "subsumed_member"}:
            raise FallbackCoverageReceiptError(
                "portable component dispatch role is unsupported"
            )
        if normalized["dispatch_role"] == "entry" and normalized["entry_rva"] != rva:
            raise FallbackCoverageReceiptError(
                "portable component entry does not dispatch at its own RVA"
            )
        result[identity] = normalized
        seen_rvas.add(rva)
    entry_keys = {
        (
            value["entry_rva"],
            value["cluster_id"],
            value["component_manifest_sha256"],
        )
        for value in result.values()
        if value["dispatch_role"] == "entry"
    }
    for value in result.values():
        if value["dispatch_role"] == "subsumed_member" and (
            value["entry_rva"],
            value["cluster_id"],
            value["component_manifest_sha256"],
        ) not in entry_keys:
            raise FallbackCoverageReceiptError(
                "portable component member has no selected boundary entry"
            )
    selections = [
        {"unit_id": unit_id, "rva": units[unit_id]["rva"], **result[unit_id]}
        for unit_id in sorted(result, key=lambda item: (units[item]["rva"], item))
    ]
    binding = (
        None
        if not selections and artifact_binding is None
        else {
            "format": (
                PORTABLE_COMPONENT_SELECTION_V2_FORMAT
                if any(value["dispatch_role"] != "entry" for value in result.values())
                else PORTABLE_REPLACEMENT_SELECTION_FORMAT
            ),
            "artifact": artifact_binding,
            "selection_sha256": _canonical_sha256(selections),
            "count": len(selections),
        }
    )
    return result, binding


def _artifact_binding(path: Path, digest: str) -> dict[str, str]:
    return {"path": path.name, "sha256": digest}


def _artifact_sha256(parent: Mapping[str, Any], field: str) -> str:
    return _sha256(
        _object(parent.get(field), field).get("sha256"), f"{field} SHA-256"
    )


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    )


def _read_json(path: Path, context: str) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise FallbackCoverageReceiptError(f"cannot read {context}: {exc}") from exc


def _read_object(path: Path, context: str) -> Mapping[str, Any]:
    return _object(_read_json(path, context), context)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise FallbackCoverageReceiptError(f"{context} must be an object")
    return value


def _list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise FallbackCoverageReceiptError(f"{context} must be a list")
    return value


def _identity(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise FallbackCoverageReceiptError(f"{context} must be a nonempty string")
    return value


def _sha256(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise FallbackCoverageReceiptError(f"{context} must be lowercase SHA-256")
    return value


def _u32(value: Any, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 0xFFFFFFFF
    ):
        raise FallbackCoverageReceiptError(f"{context} must be an unsigned 32-bit integer")
    return value


def _file(path: Path, context: str) -> Path:
    if not path.is_file():
        raise FallbackCoverageReceiptError(f"{context} does not exist: {path}")
    return path


# Short aliases keep the artifact API readable for non-Nix callers.
write_fallback_coverage_receipt = write_stage_b_fallback_coverage_receipt
validate_fallback_coverage_receipt = validate_stage_b_fallback_coverage_receipt


__all__ = [
    "FALLBACK_COVERAGE_CHECKER_ID",
    "FALLBACK_COVERAGE_CHECKER_VERSION",
    "FALLBACK_COVERAGE_RECEIPT_FORMAT",
    "PORTABLE_REPLACEMENT_SELECTION_FORMAT",
    "PORTABLE_COMPONENT_SELECTION_V2_FORMAT",
    "FallbackCoverageReceipt",
    "FallbackCoverageReceiptError",
    "validate_fallback_coverage_receipt",
    "validate_stage_b_fallback_coverage_receipt",
    "write_fallback_coverage_receipt",
    "write_stage_b_fallback_coverage_receipt",
]
