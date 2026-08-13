"""Bind analysis-v3 fallback coverage to an actual interpreter build.

The semantic interpreter package is generated from exact machine IR, but its
package manifest intentionally has no Stage A authority.  This adapter bridges
that boundary conservatively: it revalidates the complete lowering, binds
actual built engine files, intersects it with checked ISA qualifications, and
emits the existing per-unit ``implementation-capabilities-v3`` records.

The engine manifest is one package-level attestation.  Per-unit records are
only projections of that attestation; they never invent supported ISA forms.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

from .analysis_v3.fallback_coverage import (
    IMPLEMENTATION_CAPABILITIES_ARTIFACT_KIND_V3,
    IMPLEMENTATION_CAPABILITY_CODEC_V3,
    ImplementationCapabilityV3,
    implementation_capability_sha256_v3,
)
from .analysis_v3.isa_qualification import (
    ISA_QUALIFICATION_ARTIFACT_KIND_V3,
    ISA_QUALIFICATION_CODEC_V3,
)
from .analysis_v3.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    semantic_universe_sha256_v3,
)
from .artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactInputReaderV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    RecordDependencyV3,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
    open_artifact_reader_v3,
)
from .stage_b_fallback_coverage import (
    FallbackCoverageReceiptError,
    validate_stage_b_fallback_coverage_receipt,
)
from .util import sha256_file


FALLBACK_ENGINE_CAPABILITY_MANIFEST_V3_FORMAT = (
    "spaghetti-extractor-fallback-engine-capability-manifest-v3"
)
FALLBACK_ENGINE_CAPABILITY_REPORT_V3_FORMAT = (
    "spaghetti-extractor-fallback-engine-capability-report-v3"
)

_ROLE_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}")

CapabilityStatusV3 = Literal["complete", "incomplete", "violated"]


class ImplementationCapabilitiesV3Error(ValueError):
    """Implementation evidence is malformed, stale, or contradictory."""


@dataclass(frozen=True, order=True)
class CapabilityIssueV3:
    status: Literal["incomplete", "violated"]
    code: str
    location: str
    remediation: str

    def to_payload(self) -> dict[str, str]:
        return {
            "status": self.status,
            "code": self.code,
            "location": self.location,
            "remediation": self.remediation,
        }


@dataclass(frozen=True, order=True)
class BuiltFileV3:
    role: str
    path: str
    size_bytes: int
    sha256: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


def _resolve(path: Path, filename: str) -> Path:
    return path / filename if path.is_dir() else path


def _read_machine_units(path: Path) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ImplementationCapabilitiesV3Error(
            f"cannot read machine IR {path}: {exc}"
        ) from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ImplementationCapabilitiesV3Error(
                f"machine-IR line {line_number} is invalid JSON: {exc}"
            ) from exc
        if not isinstance(value, Mapping):
            raise ImplementationCapabilitiesV3Error(
                f"machine-IR line {line_number} is not an object"
            )
        unit_id = value.get("id")
        if not isinstance(unit_id, str) or not unit_id or unit_id in result:
            raise ImplementationCapabilitiesV3Error(
                f"machine-IR line {line_number} has an invalid or duplicate unit ID"
            )
        result[unit_id] = value
    if not result:
        raise ImplementationCapabilitiesV3Error("machine IR contains no units")
    return result


def _one_pe_binding(
    semantic: ArtifactInputReaderV3, isa: ArtifactInputReaderV3
) -> ArtifactBindingV3:
    if semantic.manifest.artifact_kind != SEMANTIC_INDEX_ARTIFACT_KIND_V3:
        raise ImplementationCapabilitiesV3Error(
            "semantic-index input has the wrong artifact kind"
        )
    if isa.manifest.artifact_kind != ISA_QUALIFICATION_ARTIFACT_KIND_V3:
        raise ImplementationCapabilitiesV3Error(
            "ISA-qualification input has the wrong artifact kind"
        )
    semantic_pe = tuple(
        row
        for row in semantic.manifest.bindings
        if row.name == "binary" and row.kind == "pe32"
    )
    isa_pe = tuple(
        row
        for row in isa.manifest.bindings
        if row.name == "binary" and row.kind == "pe32"
    )
    if len(semantic_pe) != 1 or isa_pe != semantic_pe:
        raise ImplementationCapabilitiesV3Error(
            "semantic-index and ISA qualification do not share one exact PE32 binding"
        )
    return semantic_pe[0]


def _built_files(
    files: Mapping[str, Path], output_directory: Path
) -> tuple[tuple[BuiltFileV3, ...], tuple[CapabilityIssueV3, ...]]:
    if not files:
        return (), (
            CapabilityIssueV3(
                "incomplete",
                "fallback_engine_bytes_missing",
                "engine",
                "build the fallback engine and pass at least one implementation file",
            ),
        )
    rows: list[BuiltFileV3] = []
    issues: list[CapabilityIssueV3] = []
    destination = output_directory / "engine"
    destination.mkdir(parents=True, exist_ok=True)
    for role, source in sorted(files.items()):
        if _ROLE_RE.fullmatch(role) is None:
            raise ImplementationCapabilitiesV3Error(
                f"implementation file role {role!r} is not canonical"
            )
        source = Path(source)
        if not source.is_file():
            issues.append(
                CapabilityIssueV3(
                    "incomplete",
                    "fallback_engine_file_missing",
                    role,
                    "build and provide the exact implementation file",
                )
            )
            continue
        suffix = source.suffix if source.suffix and len(source.suffix) <= 16 else ".bin"
        relative = Path("engine") / f"{role}{suffix}"
        target = output_directory / relative
        shutil.copyfile(source, target)
        rows.append(
            BuiltFileV3(
                role=role,
                path=relative.as_posix(),
                size_bytes=target.stat().st_size,
                sha256=sha256_file(target),
            )
        )
    return tuple(rows), tuple(issues)


def _status(issues: Sequence[CapabilityIssueV3]) -> CapabilityStatusV3:
    if any(row.status == "violated" for row in issues):
        return "violated"
    if issues:
        return "incomplete"
    return "complete"


def _manifest_sha256(payload: Mapping[str, Any]) -> str:
    body = dict(payload)
    body.pop("manifest_sha256", None)
    return canonical_sha256_v3(body)


def emit_implementation_capabilities_v3(
    *,
    machine_ir: Path,
    machine_ir_manifest: Path,
    semantic_index_path: Path,
    isa_qualification_path: Path,
    interpreter_package: Path,
    fallback_coverage_receipt: Path | None,
    implementation_files: Mapping[str, Path],
    capability_id: str,
    output_directory: Path,
    build_package_identity: str | None = None,
) -> dict[str, Any]:
    """Emit one engine attestation and exact per-unit capability projections."""

    if not capability_id or any(ord(character) < 0x20 for character in capability_id):
        raise ImplementationCapabilitiesV3Error("capability ID is invalid")
    machine_ir = _resolve(machine_ir, "machine-ir.jsonl")
    machine_ir_manifest = _resolve(machine_ir_manifest, "machine-ir-manifest.json")
    if fallback_coverage_receipt is not None:
        fallback_coverage_receipt = _resolve(
            fallback_coverage_receipt, "fallback-coverage-receipt.json"
        )
    semantic = open_artifact_reader_v3(semantic_index_path)
    isa = open_artifact_reader_v3(isa_qualification_path)
    pe_binding = _one_pe_binding(semantic, isa)
    semantic_rows = tuple(
        SEMANTIC_INDEX_CODEC_V3.read(row).value
        for row in semantic.iter_records()
    )
    semantic_by_id = {row.record_id: row for row in semantic_rows}
    if len(semantic_by_id) != len(semantic_rows):
        raise ImplementationCapabilitiesV3Error(
            "semantic index repeats unit IDs"
        )
    isa_by_id = {
        row.record_id: ISA_QUALIFICATION_CODEC_V3.read(row).value
        for row in isa.iter_records()
    }
    machine_by_id = _read_machine_units(machine_ir)

    output_directory = Path(output_directory)
    if output_directory.exists():
        raise ImplementationCapabilitiesV3Error(
            f"output directory already exists: {output_directory}"
        )
    output_directory.mkdir(parents=True)
    built_files, built_issues = _built_files(
        implementation_files, output_directory
    )
    issues: list[CapabilityIssueV3] = list(built_issues)
    for name, reader in (("semantic-index", semantic), ("isa-qualification", isa)):
        if reader.manifest.status != "complete":
            issues.append(
                CapabilityIssueV3(
                    "violated"
                    if reader.manifest.status == "violated"
                    else "incomplete",
                    f"{name}-artifact-not-complete",
                    name,
                    f"close the {name} artifact before projecting implementation authority",
                )
            )

    receipt = None
    if fallback_coverage_receipt is None:
        issues.append(
            CapabilityIssueV3(
                "incomplete",
                "fallback_coverage_receipt_missing",
                "interpreter-package",
                "close every deferred transfer and build the exact fallback-coverage receipt",
            )
        )
    else:
        try:
            receipt = validate_stage_b_fallback_coverage_receipt(
                receipt=fallback_coverage_receipt,
                machine_ir=machine_ir,
                machine_ir_manifest=machine_ir_manifest,
                interpreter_package=interpreter_package,
            )
        except FallbackCoverageReceiptError as exc:
            issues.append(
                CapabilityIssueV3(
                    "violated",
                    "fallback_lowering_binding_contradiction",
                    "interpreter-package",
                    str(exc),
                )
            )

    expected_ids = set(semantic_by_id)
    if set(machine_by_id) != expected_ids:
        issues.append(
            CapabilityIssueV3(
                "violated",
                "machine_ir_unit_inventory_mismatch",
                "machine-ir",
                "regenerate semantic index and interpreter package from one exact machine IR",
            )
        )
    if set(isa_by_id) != expected_ids:
        issues.append(
            CapabilityIssueV3(
                "violated",
                "isa_qualification_unit_inventory_mismatch",
                "isa-qualification",
                "regenerate ISA qualification from the exact semantic-index universe",
            )
        )

    valid_units: dict[str, tuple[str, ...]] = {}
    all_selected_forms: set[str] = set()
    for unit_id in sorted(expected_ids):
        semantic_row = semantic_by_id[unit_id]
        machine_row = machine_by_id.get(unit_id)
        if machine_row is None:
            continue
        machine_sha256 = canonical_sha256_v3(machine_row)
        if (
            semantic_row.pe_sha256 != pe_binding.sha256
            or semantic_row.unit_ir_sha256 != machine_sha256
            or semantic_row.unit_sha256 != machine_sha256
        ):
            issues.append(
                CapabilityIssueV3(
                    "violated",
                    "implementation_unit_binding_contradiction",
                    unit_id,
                    "regenerate exact units, semantic index, and fallback lowering together",
                )
            )
            continue
        if semantic_row.unit_status != "qualified":
            issues.append(
                CapabilityIssueV3(
                    "incomplete",
                    "machine_ir_unit_not_qualified",
                    unit_id,
                    "complete exact machine-IR semantics before compiling fallback coverage",
                )
            )
            continue
        isa_row = isa_by_id.get(unit_id)
        if isa_row is None:
            issues.append(
                CapabilityIssueV3(
                    "incomplete",
                    "isa_qualification_record_missing",
                    unit_id,
                    "qualify every exact instruction occurrence for this unit",
                )
            )
            continue
        if (
            isa_row.unit_sha256 != semantic_row.unit_sha256
            or isa_row.pe_sha256 != semantic_row.pe_sha256
            or isa_row.unit_ir_sha256 != semantic_row.unit_ir_sha256
        ):
            issues.append(
                CapabilityIssueV3(
                    "violated",
                    "isa_qualification_binding_contradiction",
                    unit_id,
                    "rerun ISA qualification from the exact semantic index",
                )
            )
            continue
        if isa_row.status != "complete" or not isa_row.authorizing:
            issues.append(
                CapabilityIssueV3(
                    "violated" if isa_row.status == "violated" else "incomplete",
                    (
                        isa_row.primary_blocker.code
                        if isa_row.primary_blocker is not None
                        else "isa_qualification_not_complete"
                    ),
                    unit_id,
                    "close every reachable ISA occurrence before claiming fallback coverage",
                )
            )
            continue
        selected_forms = tuple(sorted({row.form_id for row in isa_row.selections}))
        selected_capabilities = {
            row.fallback_capability_id for row in isa_row.selections
        }
        if selected_capabilities not in ({capability_id}, set()):
            issues.append(
                CapabilityIssueV3(
                    "violated",
                    "fallback_capability_id_mismatch",
                    unit_id,
                    "use the exact capability ID selected by checked ISA qualification",
                )
            )
            continue
        valid_units[unit_id] = selected_forms
        all_selected_forms.update(selected_forms)

    receipt_payload: Mapping[str, Any] | None = None
    if receipt is not None:
        receipt_payload = receipt.payload
        entries = receipt_payload.get("entries")
        if not isinstance(entries, list):
            issues.append(
                CapabilityIssueV3(
                    "violated",
                    "fallback_receipt_entries_missing",
                    "fallback-coverage-receipt",
                    "regenerate the complete fallback-coverage receipt",
                )
            )
        else:
            receipt_units = {
                row.get("unit_id")
                for row in entries
                if isinstance(row, Mapping)
                and row.get("implementation_kind") == "machine_ir_fallback"
            }
            if receipt_units != expected_ids:
                issues.append(
                    CapabilityIssueV3(
                        "violated",
                        "fallback_receipt_unit_inventory_mismatch",
                        "fallback-coverage-receipt",
                        "select exact machine-IR fallback for every projected unit",
                    )
                )

    package_binding = (
        None
        if receipt is None
        else {
            "fallback_receipt_sha256": receipt.receipt_sha256,
            "interpreter_package_sha256": receipt.interpreter_package_sha256,
            "interpreter_program_sha256": receipt.interpreter_program_sha256,
            "machine_ir_sha256": receipt.machine_ir_sha256,
        }
    )
    implementation_identity_payload = {
        "format": FALLBACK_ENGINE_CAPABILITY_MANIFEST_V3_FORMAT,
        "capability_id": capability_id,
        "implementation_kind": "machine_ir_fallback",
        "build_package_identity": build_package_identity,
        "package": package_binding,
        "built_files": [row.to_payload() for row in built_files],
        "selected_qualified_form_ids": sorted(all_selected_forms),
    }
    implementation_sha256 = canonical_sha256_v3(
        implementation_identity_payload
    )

    global_status = _status(issues)
    projections: list[ArtifactRecordV3] = []
    if built_files and receipt is not None and global_status != "violated":
        for unit_id, selected_forms in sorted(valid_units.items()):
            semantic_row = semantic_by_id[unit_id]
            provisional = ImplementationCapabilityV3(
                record_id=unit_id,
                capability_id=capability_id,
                implementation_kind="machine_ir_fallback",
                implementation_sha256=implementation_sha256,
                pe_sha256=semantic_row.pe_sha256,
                unit_ir_sha256=semantic_row.unit_ir_sha256,
                unit_id=unit_id,
                unit_sha256=semantic_row.unit_sha256,
                selected_form_ids=selected_forms,
                capability_sha256="0" * 64,
            )
            capability = replace(
                provisional,
                capability_sha256=implementation_capability_sha256_v3(
                    provisional
                ),
            )
            projections.append(
                IMPLEMENTATION_CAPABILITY_CODEC_V3.write(
                    unit_id,
                    capability,
                    dependencies=(
                        RecordDependencyV3("isa_qualification", unit_id),
                        RecordDependencyV3("semantic_index", unit_id),
                    ),
                )
            )

    dependencies = (
        semantic.dependency_binding("semantic_index"),
        isa.dependency_binding("isa_qualification"),
    )
    projection_manifest = ArtifactSetWriterV3(
        artifact_kind=IMPLEMENTATION_CAPABILITIES_ARTIFACT_KIND_V3,
        bindings=(pe_binding,),
        dependencies=dependencies,
        status=global_status,
    ).write(output_directory / "implementation-capabilities", projections)
    (output_directory / "projection-metadata.json").write_bytes(
        canonical_json_bytes_v3(
            {
                "format": "spaghetti-extractor-implementation-capability-projection-metadata-v3",
                "artifact_kind": projection_manifest.artifact_kind,
                "record_ids": sorted(record.record_id for record in projections),
                "status": global_status,
            }
        )
    )
    manifest: dict[str, Any] = {
        "format": FALLBACK_ENGINE_CAPABILITY_MANIFEST_V3_FORMAT,
        "status": global_status,
        "capability_id": capability_id,
        "implementation_kind": "machine_ir_fallback",
        "implementation_sha256": implementation_sha256,
        "build_package_identity": build_package_identity,
        "binary": {
            "identity": pe_binding.identity,
            "pe_sha256": pe_binding.sha256,
            "semantic_universe_sha256": semantic_universe_sha256_v3(
                semantic_rows
            ),
        },
        "package": package_binding,
        "built_files": [row.to_payload() for row in built_files],
        "selected_qualified_form_ids": sorted(all_selected_forms),
        "coverage": {
            "required_units": len(expected_ids),
            "projected_units": len(projections),
            "unprojected_unit_ids": sorted(
                expected_ids - {row.record_id for row in projections}
            ),
        },
        "inputs": {
            "semantic_index": semantic.dependency_binding(
                "semantic_index"
            ).to_payload(),
            "isa_qualification": isa.dependency_binding(
                "isa_qualification"
            ).to_payload(),
        },
        "projections": {
            "artifact_kind": projection_manifest.artifact_kind,
            "artifact_id": projection_manifest.artifact_id,
            "manifest_sha256": projection_manifest.manifest_sha256,
        },
        "issues": [row.to_payload() for row in sorted(set(issues))],
        "manifest_sha256": "0" * 64,
    }
    manifest["manifest_sha256"] = _manifest_sha256(manifest)
    (output_directory / "engine-capability-manifest.json").write_bytes(
        canonical_json_bytes_v3(manifest)
    )
    report = {
        "format": FALLBACK_ENGINE_CAPABILITY_REPORT_V3_FORMAT,
        "status": global_status,
        "manifest_sha256": manifest["manifest_sha256"],
        "counts": {
            "built_files": len(built_files),
            "selected_forms": len(all_selected_forms),
            "required_units": len(expected_ids),
            "projected_units": len(projections),
            "issues": len(issues),
        },
        "issues": manifest["issues"],
    }
    (output_directory / "report.json").write_bytes(
        canonical_json_bytes_v3(report)
    )
    return manifest


def validate_implementation_capabilities_v3(
    *, output_directory: Path, expected_implementation_files: Mapping[str, Path]
) -> Mapping[str, Any]:
    """Validate output bytes and all per-unit projections fail closed."""

    root = Path(output_directory)
    try:
        manifest = json.loads(
            (root / "engine-capability-manifest.json").read_text(
                encoding="ascii"
            )
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ImplementationCapabilitiesV3Error(
            f"cannot read engine capability manifest: {exc}"
        ) from exc
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("format")
        != FALLBACK_ENGINE_CAPABILITY_MANIFEST_V3_FORMAT
        or manifest.get("manifest_sha256") != _manifest_sha256(manifest)
    ):
        raise ImplementationCapabilitiesV3Error(
            "engine capability manifest is malformed or stale"
        )
    built = manifest.get("built_files")
    if not isinstance(built, list):
        raise ImplementationCapabilitiesV3Error(
            "engine capability manifest has no built-file inventory"
        )
    expected_roles = set(expected_implementation_files)
    observed_roles: set[str] = set()
    for row in built:
        if not isinstance(row, Mapping):
            raise ImplementationCapabilitiesV3Error(
                "engine built-file inventory is malformed"
            )
        role = row.get("role")
        relative = row.get("path")
        if (
            not isinstance(role, str)
            or role in observed_roles
            or not isinstance(relative, str)
            or Path(relative).is_absolute()
            or ".." in Path(relative).parts
        ):
            raise ImplementationCapabilitiesV3Error(
                "engine built-file binding is ambiguous"
            )
        path = root / relative
        if (
            not path.is_file()
            or row.get("sha256") != sha256_file(path)
            or row.get("size_bytes") != path.stat().st_size
        ):
            raise ImplementationCapabilitiesV3Error(
                f"engine implementation hash mismatch for {role}"
            )
        source = expected_implementation_files.get(role)
        if source is None or sha256_file(Path(source)) != row.get("sha256"):
            raise ImplementationCapabilitiesV3Error(
                f"engine implementation input mismatch for {role}"
            )
        observed_roles.add(role)
    if observed_roles != expected_roles:
        raise ImplementationCapabilitiesV3Error(
            "engine implementation file inventory changed"
        )
    projections = ArtifactSetReaderV3(root / "implementation-capabilities")
    projection_binding = manifest.get("projections")
    if not isinstance(projection_binding, Mapping) or (
        projections.manifest.artifact_id != projection_binding.get("artifact_id")
        or projections.manifest_sha256
        != projection_binding.get("manifest_sha256")
    ):
        raise ImplementationCapabilitiesV3Error(
            "implementation-capability projection binding is stale"
        )
    implementation_sha256 = manifest.get("implementation_sha256")
    selected_forms = set(manifest.get("selected_qualified_form_ids", []))
    for record in projections.iter_records():
        value = IMPLEMENTATION_CAPABILITY_CODEC_V3.read(record).value
        if (
            value.implementation_sha256 != implementation_sha256
            or value.capability_id != manifest.get("capability_id")
            or not set(value.selected_form_ids) <= selected_forms
            or value.capability_sha256
            != implementation_capability_sha256_v3(value)
        ):
            raise ImplementationCapabilitiesV3Error(
                f"implementation-capability projection {record.record_id!r} is stale"
            )
    return manifest


def _implementation_file(value: str) -> tuple[str, Path]:
    role, separator, path = value.partition("=")
    if not separator or _ROLE_RE.fullmatch(role) is None or not path:
        raise argparse.ArgumentTypeError(
            "implementation files must use canonical-role=/path syntax"
        )
    return role, Path(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bind a built fallback engine to analysis-v3 exact units"
    )
    parser.add_argument("--machine-ir", type=Path, required=True)
    parser.add_argument("--machine-ir-manifest", type=Path, required=True)
    parser.add_argument("--semantic-index", type=Path, required=True)
    parser.add_argument("--isa-qualification", type=Path, required=True)
    parser.add_argument("--interpreter-package", type=Path, required=True)
    parser.add_argument("--fallback-coverage-receipt", type=Path)
    parser.add_argument(
        "--implementation-file",
        action="append",
        type=_implementation_file,
        default=[],
    )
    parser.add_argument("--capability-id", required=True)
    parser.add_argument("--build-package-identity")
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    files = dict(arguments.implementation_file)
    if len(files) != len(arguments.implementation_file):
        raise ImplementationCapabilitiesV3Error(
            "implementation file roles are duplicated"
        )
    manifest = emit_implementation_capabilities_v3(
        machine_ir=arguments.machine_ir,
        machine_ir_manifest=arguments.machine_ir_manifest,
        semantic_index_path=arguments.semantic_index,
        isa_qualification_path=arguments.isa_qualification,
        interpreter_package=arguments.interpreter_package,
        fallback_coverage_receipt=arguments.fallback_coverage_receipt,
        implementation_files=files,
        capability_id=arguments.capability_id,
        output_directory=arguments.out,
        build_package_identity=arguments.build_package_identity,
    )
    if manifest["status"] == "complete":
        validate_implementation_capabilities_v3(
            output_directory=arguments.out,
            expected_implementation_files=files,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
