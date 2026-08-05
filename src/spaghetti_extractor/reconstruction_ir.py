"""Export a byte-free machine IR package for high-assurance reconstruction.

The canonical Stage B state machine still contains exact instruction encodings
because Stage A uses them to bind semantic transfers to the original image.
This module is the sanitizing boundary: it checks those bindings statically,
then emits only normalized semantics, typed instruction descriptions, and
cryptographic digests.  The original binary is parsed but never executed.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from .external_interface_profiles import (
    ExternalInterfaceProfile,
    load_external_interface_profile,
)
from .external_operation_profiles import (
    ExternalOperationProfile,
    load_external_operation_profile,
)
from .finite_value_domain import FiniteU32Dataflow
from .import_abi import SelectedImportABI, load_selected_import_abis
from .interface_provenance import recover_external_interface_targets
from .internal_call_summaries import derive_internal_call_preservation_summaries
from .machine_import_profiles import MachineImportIdentity
from .operation_provenance import operation_provenance_view
from .reconstruction_control import (
    canonical_indirect_external_targets,
    derive_rooted_reachable_units,
    pe32_jump_table_index_expression,
    recover_static_pe32_jump_table_inventory,
)
from .stage_b_state_machine import (
    STAGE_A_REFERENCE_CONTRACT_FORMAT,
    STAGE_B_STATE_MACHINE_FORMAT,
    load_stage_a_reference_contract_binding,
    normalize_stage_a_semantic_transfer,
)
from .stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from .util import sha256_bytes, sha256_file, write_json
from .value_provenance import legacy_value_provenance_view


MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
MACHINE_IR_FILENAME = "machine-ir.jsonl"
MACHINE_IR_MANIFEST_FILENAME = "machine-ir-manifest.json"
PREPARED_MACHINE_IR_FORMAT = "stage-a-prepared-machine-ir-v1"
PREPARED_MACHINE_IR_FILENAME = "prepared-machine-ir.jsonl"
PREPARED_MACHINE_IR_MANIFEST_FILENAME = "prepared-machine-ir-manifest.json"
X87_MICRO_OP_FORMAT = "stage-a-x87-micro-op-v1"
INDIRECT_TARGET_PROFILE_FORMAT = "stage-a-indirect-target-profile-v1"

_SEMANTIC_FIELDS = (
    "pre_state",
    "register_writes",
    "flag_writes",
    "memory_events",
    "external_events",
    "faults",
    "ordered_events",
    "edge_conditions",
    "outcome",
    "stack_delta",
    "counts",
)
_RAW_INSTRUCTION_FIELDS = frozenset(
    {
        "bytes",
        "instruction_bytes",
        "opcode_bytes",
        "raw_bytes",
        "encoded_instruction",
    }
)
_DIRECT_OUTCOME_FIELDS = {
    "fallthrough": ("target_rva",),
    "jump": ("target_rva",),
    "branch": ("true_target_rva", "false_target_rva"),
}
_CONTROL_FLOW_GROUPS = frozenset({
    "branch_relative",
    "call",
    "int",
    "iret",
    "jump",
    "ret",
})
_NON_FALLTHROUGH_MNEMONICS = frozenset({
    "hlt",
    "int",
    "int1",
    "int3",
    "into",
    "iret",
    "iretd",
    "iretq",
    "syscall",
    "sysenter",
    "sysexit",
    "sysret",
    "ud0",
    "ud1",
    "ud2",
})


class MachineIRExportError(StageAInputError):
    """The input package cannot safely cross the reconstruction boundary."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "malformed_machine_ir_input",
        unit_id: str | None = None,
        rva: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.unit_id = unit_id
        self.rva = rva


@dataclass(frozen=True, order=True)
class RvaSpan:
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start

    def payload(self) -> dict[str, int]:
        return {"rva_start": self.start, "rva_end": self.end, "size": self.size}


@dataclass(frozen=True)
class SourceLocation:
    unit_id: str | None
    function: str | None
    block_id: str | None
    span: RvaSpan | None
    field: str | None = None

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.unit_id is not None:
            result["unit_id"] = self.unit_id
        if self.function is not None:
            result["function"] = self.function
        if self.block_id is not None:
            result["block_id"] = self.block_id
        if self.span is not None:
            result.update(self.span.payload())
        if self.field is not None:
            result["field"] = self.field
        return result


@dataclass(frozen=True)
class ExportIssue:
    status: str
    category: str
    message: str
    next_action: str
    location: SourceLocation

    def payload(self) -> dict[str, Any]:
        body = {
            "status": self.status,
            "category": self.category,
            "message": self.message,
            "next_action": self.next_action,
            "location": self.location.payload(),
        }
        body["id"] = "machine-ir-issue:" + sha256_bytes(_canonical_json(body))[:20]
        return body


@dataclass(frozen=True)
class MachineIRPackage:
    manifest: Path
    machine_ir: Path
    status: str
    unit_count: int
    issue_count: int


@dataclass(frozen=True)
class PreparedMachineIRPackage:
    manifest: Path
    prepared_units: Path
    unit_count: int
    reused_unit_count: int


@dataclass(frozen=True)
class _Instruction:
    rva: int
    size: int
    digest: str
    mnemonic: str
    operands: tuple[dict[str, Any], ...]
    registers_read: tuple[str, ...]
    registers_written: tuple[str, ...]
    groups: tuple[str, ...]

    @property
    def end(self) -> int:
        return self.rva + self.size

    def payload(self) -> dict[str, Any]:
        return {
            "rva_start": self.rva,
            "rva_end": self.end,
            "size": self.size,
            "instruction_sha256": self.digest,
            "mnemonic": self.mnemonic,
            "operands": [copy.deepcopy(item) for item in self.operands],
            "registers_read": list(self.registers_read),
            "registers_written": list(self.registers_written),
            "groups": list(self.groups),
        }


def prepare_machine_ir_units_package(
    *,
    state_machine: Path,
    original_pe: Path,
    out: Path,
    reference_contract: Path | None = None,
    prepared_machine_ir: Path | None = None,
) -> PreparedMachineIRPackage:
    """Prepare exact byte-bound units independently of global control analysis."""

    state_path = _regular_file(state_machine, "canonical state machine")
    original_path = _regular_file(original_pe, "original PE")
    binary = _parse_stage_a_pe(original_path)
    if binary.machine != "i386" or binary.bitness != 32:
        raise MachineIRExportError(
            "machine IR v2 supports x86 PE32 inputs only",
            code="unsupported_binary_model",
        )
    reference_sha256: str | None = None
    if reference_contract is not None:
        reference_path = _regular_file(reference_contract, "reference contract")
        reference_sha256 = load_stage_a_reference_contract_binding(
            reference_path, original_pe=original_path
        ).sha256

    rows = _read_canonical_rows(state_path)
    _validate_unique_units(rows)
    reusable = _load_reusable_prepared_units(
        prepared_machine_ir,
        binary_sha256=binary.sha256,
        reference_sha256=reference_sha256,
    )
    prepared, reused_units = _prepare_units(
        rows,
        binary=binary,
        reference_sha256=reference_sha256,
        reusable=reusable,
    )
    prepared_bytes = b"".join(_canonical_json(unit) + b"\n" for unit in prepared)
    manifest = {
        "format": PREPARED_MACHINE_IR_FORMAT,
        "status": "prepared",
        "authority": "static candidate-generation input; no original execution",
        "inputs": {
            "state_machine": {
                "path": state_path.name,
                "sha256": sha256_file(state_path),
            },
            "original_pe": {"path": original_path.name, "sha256": binary.sha256},
            "reference_contract": (
                None
                if reference_contract is None
                else {
                    "path": Path(reference_contract).name,
                    "sha256": reference_sha256,
                }
            ),
            "prepared_machine_ir": (
                None
                if prepared_machine_ir is None
                else {
                    "path": Path(prepared_machine_ir).name,
                    "sha256": sha256_file(
                        _machine_ir_artifact_path(Path(prepared_machine_ir))
                    ),
                }
            ),
        },
        "binary": _binary_inventory(binary),
        "artifacts": {
            "prepared_units": {
                "path": PREPARED_MACHINE_IR_FILENAME,
                "sha256": sha256_bytes(prepared_bytes),
                "format": MACHINE_IR_FORMAT,
            }
        },
        "counts": {
            "units": len(prepared),
            "units_reused": reused_units,
            "units_computed": len(prepared) - reused_units,
        },
        "constraints": {
            "original_binary_executed": False,
            "unit_bytes_bound_to_original_pe": True,
            "prepared_unit_reuse_is_exact_input_hash_bound": True,
        },
    }
    _assert_byte_free(manifest)
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    units_path = output / PREPARED_MACHINE_IR_FILENAME
    manifest_path = output / PREPARED_MACHINE_IR_MANIFEST_FILENAME
    units_path.write_bytes(prepared_bytes)
    write_json(manifest_path, manifest)
    return PreparedMachineIRPackage(
        manifest=manifest_path.resolve(),
        prepared_units=units_path.resolve(),
        unit_count=len(prepared),
        reused_unit_count=reused_units,
    )


def export_machine_ir_package(
    *,
    state_machine: Path,
    original_pe: Path,
    out: Path,
    reference_contract: Path | None = None,
    indirect_target_profile: Path | None = None,
    machine_import_profiles: Sequence[Path] = (),
    external_interface_profiles: Sequence[Path] = (),
    external_operation_profiles: Sequence[Path] = (),
    prepared_machine_ir: Path | None = None,
) -> MachineIRPackage:
    """Validate and export a deterministic, byte-free PE32 machine IR package."""

    state_path = _regular_file(state_machine, "canonical state machine")
    original_path = _regular_file(original_pe, "original PE")
    binary = _parse_stage_a_pe(original_path)
    if binary.machine != "i386" or binary.bitness != 32:
        raise MachineIRExportError(
            "machine IR v2 supports x86 PE32 inputs only",
            code="unsupported_binary_model",
        )

    reference_payload: dict[str, Any] | None = None
    reference_sha256: str | None = None
    if reference_contract is not None:
        reference_path = _regular_file(reference_contract, "reference contract")
        binding = load_stage_a_reference_contract_binding(
            reference_path, original_pe=original_path
        )
        reference_sha256 = binding.sha256
        reference_payload = _json_object(reference_path, "reference contract")
        if reference_payload.get("format") != STAGE_A_REFERENCE_CONTRACT_FORMAT:
            raise MachineIRExportError(
                "reference contract format changed after validation",
                code="reference_contract_format_mismatch",
            )

    reference = _reference_inventory(reference_payload)
    target_profile = _load_indirect_target_profile(indirect_target_profile)
    import_profile_paths = tuple(
        _regular_file(path, "machine import profile")
        for path in machine_import_profiles
    )
    import_abis = load_selected_import_abis(import_profile_paths)
    interface_profile_paths = tuple(
        _regular_file(path, "external interface profile")
        for path in external_interface_profiles
    )
    interface_profiles = tuple(
        load_external_interface_profile(path) for path in interface_profile_paths
    )
    operation_profile_paths = tuple(
        _regular_file(path, "external operation profile")
        for path in external_operation_profiles
    )
    operation_profiles = tuple(
        load_external_operation_profile(path) for path in operation_profile_paths
    )
    rows = _read_canonical_rows(state_path)
    _validate_unique_units(rows)
    reusable = _load_reusable_prepared_units(
        prepared_machine_ir,
        binary_sha256=binary.sha256,
        reference_sha256=reference_sha256,
    )
    prepared, reused_units = _prepare_units(
        rows,
        binary=binary,
        reference_sha256=reference_sha256,
        reusable=reusable,
    )

    issues = _unit_issues(prepared)
    coverage, coverage_issues = _coverage_inventory(
        binary, prepared, reference.get("noncode_ranges", [])
    )
    issues.extend(coverage_issues)
    control, control_issues = _control_inventory(
        binary,
        prepared,
        reference,
        target_profile=target_profile,
        import_abis=import_abis,
        interface_profiles=interface_profiles,
        operation_profiles=operation_profiles,
    )
    issues.extend(control_issues)
    external = _external_inventory(prepared)
    issues.extend(_reference_issues(reference_payload))
    issue_payloads = [
        issue.payload()
        for issue in sorted(
            issues,
            key=lambda issue: (
                0 if issue.status == "violated" else 1,
                issue.location.span.start if issue.location.span else -1,
                issue.category,
                issue.message,
            ),
        )
    ]
    status = _aggregate_status(issue_payloads)

    for unit in prepared:
        _assert_byte_free(unit)
    source_map = [
        {
            "unit_id": unit["id"],
            "function": unit["source_location"].get("function"),
            "block_id": unit["source_location"].get("block_id"),
            "rva_start": unit["source_location"]["rva_start"],
            "rva_end": unit["source_location"]["rva_end"],
            "contract_sha256": unit["source"]["contract_sha256"],
        }
        for unit in prepared
    ]

    jsonl_bytes = b"".join(
        _canonical_json(unit) + b"\n" for unit in prepared
    )
    manifest = {
        "format": MACHINE_IR_FORMAT,
        "record_kind": "manifest",
        "status": status,
        "model": "x86-pe32-static-reconstruction-v2",
        "authority": (
            "static sanitizing export; no original execution; qualification requires "
            "independent downstream evidence"
        ),
        "inputs": {
            "state_machine": {
                "path": state_path.name,
                "sha256": sha256_file(state_path),
            },
            "original_pe": {
                "path": original_path.name,
                "sha256": binary.sha256,
            },
            "reference_contract": (
                {
                    "path": Path(reference_contract).name,
                    "sha256": reference_sha256,
                }
                if reference_contract is not None
                else None
            ),
            "indirect_target_profile": (
                None
                if indirect_target_profile is None
                else {
                    "path": Path(indirect_target_profile).name,
                    "sha256": sha256_file(Path(indirect_target_profile)),
                    "id": target_profile["id"],
                }
            ),
            "machine_import_profiles": [
                {"path": path.name, "sha256": sha256_file(path)}
                for path in import_profile_paths
            ],
            "external_interface_profiles": [
                {
                    "path": path.name,
                    "sha256": profile.sha256,
                    "id": profile.profile_id,
                }
                for path, profile in zip(
                    interface_profile_paths, interface_profiles, strict=True
                )
            ],
            "external_operation_profiles": [
                {
                    "path": path.name,
                    "sha256": profile.sha256,
                    "id": profile.profile_id,
                }
                for path, profile in zip(
                    operation_profile_paths, operation_profiles, strict=True
                )
            ],
            "prepared_machine_ir": (
                None
                if prepared_machine_ir is None
                else {
                    "path": Path(prepared_machine_ir).name,
                    "sha256": sha256_file(
                        _machine_ir_artifact_path(Path(prepared_machine_ir))
                    ),
                }
            ),
        },
        "binary": _binary_inventory(binary),
        "artifacts": {
            "machine_ir": {
                "path": MACHINE_IR_FILENAME,
                "sha256": sha256_bytes(jsonl_bytes),
                "format": MACHINE_IR_FORMAT,
            }
        },
        "coverage": coverage,
        "control": control,
        "trust_assumptions": (
            [] if target_profile is None else [copy.deepcopy(target_profile["assumption"])]
        ),
        "external": external,
        "reference_inventory": reference["public"],
        "source_map": source_map,
        "issues": issue_payloads,
        "counts": {
            "units": len(prepared),
            "prepared_units_reused": reused_units,
            "prepared_units_computed": len(prepared) - reused_units,
            "instructions": sum(len(unit["instructions"]) for unit in prepared),
            "x87_micro_ops": sum(len(unit["x87_micro_ops"]) for unit in prepared),
            "external_events": len(external["events"]),
            "issues": len(issue_payloads),
            "incomplete_issues": sum(
                issue["status"] == "incomplete" for issue in issue_payloads
            ),
            "violated_issues": sum(
                issue["status"] == "violated" for issue in issue_payloads
            ),
        },
        "constraints": {
            "original_binary_executed": False,
            "raw_instruction_bytes_exported": False,
            "source_rows_canonically_hashed": True,
            "unit_bytes_bound_to_original_pe": True,
            "deterministic_serialization": True,
            "prepared_unit_reuse_is_exact_input_hash_bound": True,
        },
    }
    _assert_byte_free(manifest)

    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)
    machine_path = out_path / MACHINE_IR_FILENAME
    manifest_path = out_path / MACHINE_IR_MANIFEST_FILENAME
    machine_path.write_bytes(jsonl_bytes)
    write_json(manifest_path, manifest)
    return MachineIRPackage(
        manifest=manifest_path.resolve(),
        machine_ir=machine_path.resolve(),
        status=status,
        unit_count=len(prepared),
        issue_count=len(issue_payloads),
    )


def _read_canonical_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise MachineIRExportError(
                f"invalid state-machine JSON on line {line_number}: {exc}",
                code="malformed_state_machine_json",
            ) from exc
        if not isinstance(raw, dict):
            raise MachineIRExportError(
                f"state-machine line {line_number} is not an object",
                code="malformed_state_machine_unit",
            )
        if raw.get("stage_b_format") != STAGE_B_STATE_MACHINE_FORMAT:
            raise MachineIRExportError(
                f"state-machine line {line_number} is not canonical {STAGE_B_STATE_MACHINE_FORMAT}",
                code="noncanonical_state_machine_unit",
            )
        expected = normalize_stage_a_semantic_transfer(raw)
        if raw.get("contract_sha256") != expected.get("contract_sha256"):
            raise MachineIRExportError(
                f"state-machine line {line_number} has a stale contract digest",
                code="state_machine_contract_digest_mismatch",
                unit_id=str(raw.get("id") or "") or None,
            )
        rows.append(raw)
    if not rows:
        raise MachineIRExportError(
            "canonical state machine is empty", code="empty_state_machine"
        )
    return rows


def _preparation_input_sha256(
    row: Mapping[str, Any], *, binary_sha256: str, reference_sha256: str | None
) -> str:
    return sha256_bytes(
        _canonical_json(
            {
                "format": "stage-a-machine-ir-unit-preparation-input-v1",
                "binary_sha256": binary_sha256,
                "reference_contract_sha256": reference_sha256,
                "state_machine_row": row,
            }
        )
    )


def _machine_ir_artifact_path(value: Path) -> Path:
    path = value
    if path.is_dir():
        candidates = [
            candidate
            for candidate in (
                path / PREPARED_MACHINE_IR_FILENAME,
                path / MACHINE_IR_FILENAME,
            )
            if candidate.is_file()
        ]
        if len(candidates) != 1:
            raise MachineIRExportError(
                "prepared machine IR directory must contain exactly one unit artifact",
                code="prepared_machine_ir_artifact_ambiguous",
            )
        path = candidates[0]
    return _regular_file(path, "prepared machine IR")


def _load_reusable_prepared_units(
    value: Path | None,
    *,
    binary_sha256: str,
    reference_sha256: str | None,
) -> dict[str, dict[str, Any]]:
    if value is None:
        return {}
    machine_path = _machine_ir_artifact_path(Path(value))
    manifest_path = machine_path.parent / (
        PREPARED_MACHINE_IR_MANIFEST_FILENAME
        if machine_path.name == PREPARED_MACHINE_IR_FILENAME
        else MACHINE_IR_MANIFEST_FILENAME
    )
    manifest = _json_object(
        _regular_file(manifest_path, "prepared machine IR manifest"),
        "prepared machine IR manifest",
    )
    manifest_format = manifest.get("format")
    if manifest_format not in {MACHINE_IR_FORMAT, PREPARED_MACHINE_IR_FORMAT}:
        raise MachineIRExportError(
            "prepared machine IR has an unsupported format",
            code="prepared_machine_ir_format_mismatch",
        )
    binary = manifest.get("binary")
    inputs = manifest.get("inputs")
    artifact_key = (
        "prepared_units"
        if manifest_format == PREPARED_MACHINE_IR_FORMAT
        else "machine_ir"
    )
    artifacts = manifest.get("artifacts")
    artifact = artifacts.get(artifact_key) if isinstance(artifacts, Mapping) else None
    reference = inputs.get("reference_contract") if isinstance(inputs, Mapping) else None
    reference_binding_sha256 = (
        reference.get("sha256") if isinstance(reference, Mapping) else None
    )
    if (
        not isinstance(binary, Mapping)
        or binary.get("sha256") != binary_sha256
        or not isinstance(inputs, Mapping)
        or (reference is not None and not isinstance(reference, Mapping))
        or reference_binding_sha256 != reference_sha256
        or not isinstance(artifact, Mapping)
        or artifact.get("sha256") != sha256_file(machine_path)
    ):
        raise MachineIRExportError(
            "prepared machine IR input or artifact binding is stale",
            code="prepared_machine_ir_binding_mismatch",
        )

    units: dict[str, dict[str, Any]] = {}
    for line_number, line in enumerate(
        machine_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise MachineIRExportError(
                f"prepared machine IR line {line_number} is not JSON",
                code="prepared_machine_ir_malformed",
            ) from exc
        if not isinstance(raw, dict) or raw.get("format") != MACHINE_IR_FORMAT:
            raise MachineIRExportError(
                f"prepared machine IR line {line_number} is malformed",
                code="prepared_machine_ir_malformed",
            )
        _assert_byte_free(raw)
        identity = _required_string(raw.get("id"), "prepared machine IR unit id")
        preparation = raw.get("preparation")
        if (
            not isinstance(preparation, Mapping)
            or preparation.get("format")
            != "stage-a-machine-ir-unit-preparation-v1"
            or not isinstance(preparation.get("input_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", preparation["input_sha256"]) is None
        ):
            raise MachineIRExportError(
                f"prepared machine IR unit {identity} has no checked preparation binding",
                code="prepared_machine_ir_unit_binding_missing",
                unit_id=identity,
            )
        if identity in units:
            raise MachineIRExportError(
                f"prepared machine IR repeats unit {identity}",
                code="duplicate_prepared_machine_ir_unit",
                unit_id=identity,
            )
        units[identity] = raw
    counts = manifest.get("counts")
    if not isinstance(counts, Mapping) or len(units) != counts.get("units"):
        raise MachineIRExportError(
            "prepared machine IR unit count differs from its manifest",
            code="prepared_machine_ir_count_mismatch",
        )
    return units


def _prepare_units(
    rows: Sequence[Mapping[str, Any]],
    *,
    binary: StageABinary,
    reference_sha256: str | None,
    reusable: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    prepared: list[dict[str, Any]] = []
    reused_units = 0
    for row in rows:
        identity = _required_string(row.get("id"), "unit id")
        preparation_input_sha256 = _preparation_input_sha256(
            row,
            binary_sha256=binary.sha256,
            reference_sha256=reference_sha256,
        )
        cached = reusable.get(identity)
        if (
            cached is not None
            and cached.get("preparation", {}).get("input_sha256")
            == preparation_input_sha256
        ):
            unit = copy.deepcopy(dict(cached))
            unit["reachable"] = False
            unit.pop("reachability", None)
            reused_units += 1
        else:
            unit = _prepare_unit(
                row,
                binary=binary,
                reference_sha256=reference_sha256,
            )
        _assert_byte_free(unit)
        prepared.append(unit)
    prepared.sort(
        key=lambda item: (
            int(item["source"]["original"]["rva_start"]),
            str(item["id"]),
        )
    )
    return prepared, reused_units


def _validate_unique_units(rows: Sequence[Mapping[str, Any]]) -> None:
    ids: dict[str, int] = {}
    spans: dict[tuple[int, int], str] = {}
    for index, row in enumerate(rows):
        identity = _required_string(row.get("id"), f"unit {index} id")
        if identity in ids:
            raise MachineIRExportError(
                f"duplicate machine unit id {identity!r}",
                code="duplicate_machine_unit_id",
                unit_id=identity,
            )
        ids[identity] = index
        span = _unit_span(row, identity)
        span_key = (span.start, span.end)
        if span_key in spans:
            raise MachineIRExportError(
                f"units {spans[span_key]!r} and {identity!r} have the same RVA span",
                code="duplicate_machine_unit_span",
                unit_id=identity,
                rva=span.start,
            )
        spans[span_key] = identity


def _prepare_unit(
    row: Mapping[str, Any],
    *,
    binary: StageABinary,
    reference_sha256: str | None,
) -> dict[str, Any]:
    identity = _required_string(row.get("id"), "unit id")
    span = _unit_span(row, identity)
    _validate_semantic_shape(row, identity, span)
    location = SourceLocation(
        unit_id=identity,
        function=_optional_string(row.get("function")),
        block_id=_optional_string(row.get("block_id")),
        span=span,
    )
    binding = row.get("stage_a_export")
    if reference_sha256 is not None:
        if not isinstance(binding, Mapping):
            raise MachineIRExportError(
                f"{identity}: supplied reference contract is not bound by the state machine",
                code="missing_reference_contract_binding",
                unit_id=identity,
                rva=span.start,
            )
        if isinstance(binding, Mapping) and binding.get(
            "reference_contract_sha256"
        ) != reference_sha256:
            raise MachineIRExportError(
                f"{identity}: state-machine reference-contract binding differs",
                code="reference_contract_binding_mismatch",
                unit_id=identity,
                rva=span.start,
            )

    instructions, encoded = _instructions(row, identity, binary, span)
    transfer_digest = _digest(
        row.get("instruction_bytes_sha256"), f"{identity} instruction digest"
    )
    if sha256_bytes(encoded) != transfer_digest:
        raise MachineIRExportError(
            f"{identity}: instruction inventory does not match its transfer digest",
            code="instruction_digest_mismatch",
            unit_id=identity,
            rva=span.start,
        )
    image_bytes = bytes(binary.pe.get_data(span.start, span.size))
    if len(image_bytes) != span.size or image_bytes != encoded:
        raise MachineIRExportError(
            f"{identity}: transfer bytes do not match the supplied original PE",
            code="original_pe_unit_binding_mismatch",
            unit_id=identity,
            rva=span.start,
        )

    schedule, x87_micro_ops, fpu_state = _x87_projection(
        row,
        identity=identity,
        span=span,
        instructions=instructions,
        transfer_digest=transfer_digest,
    )
    semantics = {
        field: _semantic_copy(row.get(field), field, identity)
        for field in _SEMANTIC_FIELDS
    }
    semantics["fpu_state"] = fpu_state
    semantics["instruction_effect_schedule"] = schedule
    control_recovery = _recover_unknown_fallthrough(
        semantics["outcome"], instructions, span
    )
    if control_recovery is not None:
        semantics["outcome"] = copy.deepcopy(control_recovery["outcome"])
    control_disposition = _control_disposition(row, identity)
    control_targets = _outcome_targets(
        semantics["outcome"],
        identity,
        terminating=control_disposition is not None,
    )
    unit = {
        "format": MACHINE_IR_FORMAT,
        "record_kind": "unit",
        "preparation": {
            "format": "stage-a-machine-ir-unit-preparation-v1",
            "input_sha256": _preparation_input_sha256(
                row,
                binary_sha256=binary.sha256,
                reference_sha256=reference_sha256,
            ),
        },
        "id": identity,
        "unit_kind": row.get("unit_kind", "semantic_transfer"),
        "status": (
            "qualified"
            if _semantic_unit_qualified(row, x87_micro_ops)
            else "incomplete"
        ),
        # This value is an upstream proposal only.  _control_inventory replaces
        # ``reachable`` with rooted, decoded-graph reachability after every
        # direct and recoverable indirect edge has been checked.
        "reachable": False,
        "source": {
            "original": span.payload(),
            "contract_sha256": _digest(
                row.get("contract_sha256"), f"{identity} contract digest"
            ),
            "instruction_bytes_sha256": transfer_digest,
            "semantic_transfer_format": row.get("format"),
            "semantic_export": _binding_projection(binding),
        },
        "source_location": location.payload(),
        "expression_model": row.get("expression_model"),
        "instructions": [instruction.payload() for instruction in instructions],
        "x87_micro_ops": x87_micro_ops,
        "semantics": semantics,
        "control": {
            "kind": semantics["outcome"].get("kind")
            if isinstance(semantics["outcome"], Mapping)
            else None,
            "direct_targets": control_targets,
            "has_indirect_target": (
                isinstance(semantics["outcome"], Mapping)
                and semantics["outcome"].get("kind") in {"indirect_call", "indirect_jump"}
            ),
            "disposition": control_disposition,
            "recovery": control_recovery,
        },
        "source_status": {
            "reachable": row.get("reachable"),
            "status": row.get("status"),
            "acceptance": row.get("acceptance"),
            "blocker_category": row.get("blocker_category"),
            "blocker": row.get("blocker"),
            "next_action": row.get("next_action"),
        },
    }
    return unit


def _recover_unknown_fallthrough(
    outcome: Any,
    instructions: Sequence[_Instruction],
    span: RvaSpan,
) -> dict[str, Any] | None:
    if (
        not isinstance(outcome, Mapping)
        or outcome.get("kind") != "unknown"
        or not instructions
    ):
        return None
    last = instructions[-1]
    if (
        last.end != span.end
        or _CONTROL_FLOW_GROUPS.intersection(last.groups)
        or last.mnemonic.lower() in _NON_FALLTHROUGH_MNEMONICS
    ):
        return None
    return {
        "kind": "exact_decode_non_control_fallthrough",
        "proof_authority": False,
        "required_replay": "Lean must decode the exact terminal instruction as non-control",
        "terminal_instruction": {
            "rva": last.rva,
            "sha256": last.digest,
            "mnemonic_guidance": last.mnemonic,
        },
        "outcome": {"kind": "fallthrough", "target_rva": span.end},
    }


def _semantic_unit_qualified(
    row: Mapping[str, Any], x87_micro_ops: Sequence[Mapping[str, Any]]
) -> bool:
    if row.get("status") == "reimplementable":
        return True
    return bool(x87_micro_ops) and row.get("blocker_category") in {
        "x87_physical_state_requires_native_exact_command_replay",
        "x87_typed_lowering_required",
    }


def _instructions(
    row: Mapping[str, Any],
    identity: str,
    binary: StageABinary,
    span: RvaSpan,
) -> tuple[tuple[_Instruction, ...], bytes]:
    raw_instructions = row.get("instructions")
    if not isinstance(raw_instructions, list) or not raw_instructions:
        raise MachineIRExportError(
            f"{identity}: instructions must be a non-empty list",
            code="missing_instruction_inventory",
            unit_id=identity,
            rva=span.start,
        )
    result: list[_Instruction] = []
    reconstructed = bytearray()
    expected_rva = span.start
    for index, raw in enumerate(raw_instructions):
        if not isinstance(raw, Mapping):
            raise MachineIRExportError(
                f"{identity}: instruction {index} is not an object",
                unit_id=identity,
                rva=expected_rva,
            )
        rva = _u32(raw.get("rva"), f"{identity} instruction {index} RVA")
        encoded = _hex_bytes(raw.get("bytes"), f"{identity} instruction {index} bytes")
        size = raw.get("size", len(encoded))
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise MachineIRExportError(
                f"{identity}: instruction {index} has an invalid size",
                unit_id=identity,
                rva=rva,
            )
        if rva != expected_rva or len(encoded) != size:
            raise MachineIRExportError(
                f"{identity}: instruction {index} is not an exact contiguous span",
                code="noncontiguous_instruction_inventory",
                unit_id=identity,
                rva=rva,
            )
        decoded = _decode_one(encoded, binary.image_base + rva, identity, rva)
        mnemonic = decoded.mnemonic.lower()
        declared_mnemonic = raw.get("mnemonic")
        if isinstance(declared_mnemonic, str) and declared_mnemonic.lower() != mnemonic:
            raise MachineIRExportError(
                f"{identity}: instruction at 0x{rva:x} has mnemonic drift",
                code="instruction_mnemonic_mismatch",
                unit_id=identity,
                rva=rva,
            )
        result.append(_instruction_projection(decoded, rva, encoded))
        reconstructed.extend(encoded)
        expected_rva += size
    if expected_rva != span.end:
        raise MachineIRExportError(
            f"{identity}: instruction inventory does not cover its exact unit span",
            code="incomplete_instruction_inventory",
            unit_id=identity,
            rva=expected_rva,
        )
    return tuple(result), bytes(reconstructed)


def _decode_one(encoded: bytes, address: int, identity: str, rva: int) -> Any:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoded = list(decoder.disasm(encoded, address))
    if len(decoded) != 1 or int(decoded[0].size) != len(encoded):
        raise MachineIRExportError(
            f"{identity}: bytes at 0x{rva:x} do not decode as one exact IA-32 instruction",
            code="instruction_decode_mismatch",
            unit_id=identity,
            rva=rva,
        )
    return decoded[0]


def _instruction_projection(decoded: Any, rva: int, encoded: bytes) -> _Instruction:
    operands = tuple(_operand_projection(decoded, operand) for operand in decoded.operands)
    try:
        reads, writes = decoded.regs_access()
    except capstone.CsError:
        reads, writes = (), ()
    return _Instruction(
        rva=rva,
        size=len(encoded),
        digest=sha256_bytes(encoded),
        mnemonic=str(decoded.mnemonic).lower(),
        operands=operands,
        registers_read=tuple(decoded.reg_name(value) for value in reads),
        registers_written=tuple(decoded.reg_name(value) for value in writes),
        groups=tuple(decoded.group_name(value) for value in decoded.groups),
    )


def _operand_projection(decoded: Any, operand: Any) -> dict[str, Any]:
    common = {
        "width_bits": int(operand.size) * 8,
        "access": _operand_access(int(getattr(operand, "access", 0))),
    }
    if operand.type == X86_OP_REG:
        return {"kind": "register", "name": decoded.reg_name(operand.reg), **common}
    if operand.type == X86_OP_IMM:
        return {"kind": "immediate", "value": int(operand.imm), **common}
    if operand.type == X86_OP_MEM:
        memory = operand.mem
        return {
            "kind": "memory",
            "segment": decoded.reg_name(memory.segment) or None,
            "base": decoded.reg_name(memory.base) or None,
            "index": decoded.reg_name(memory.index) or None,
            "scale": int(memory.scale),
            "displacement": int(memory.disp),
            **common,
        }
    raise MachineIRExportError(
        f"unsupported Capstone operand type {operand.type}",
        code="unsupported_typed_operand",
    )


def _operand_access(access: int) -> str:
    read = bool(access & capstone.CS_AC_READ)
    write = bool(access & capstone.CS_AC_WRITE)
    if read and write:
        return "read_write"
    if read:
        return "read"
    if write:
        return "write"
    return "implicit_or_unspecified"


def _x87_projection(
    row: Mapping[str, Any],
    *,
    identity: str,
    span: RvaSpan,
    instructions: Sequence[_Instruction],
    transfer_digest: str,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], Any]:
    fpu = row.get("fpu_state")
    schedule_raw = row.get("instruction_effect_schedule")
    schedule = _sanitize_schedule(schedule_raw, identity) if schedule_raw is not None else None
    if fpu is None:
        return schedule, [], None
    if not isinstance(fpu, Mapping):
        raise MachineIRExportError(
            f"{identity}: fpu_state must be an object or null",
            unit_id=identity,
            rva=span.start,
        )
    if fpu.get("model") != "native_exact_x87_command_replay_obligation_v1":
        return schedule, [], _semantic_copy(fpu, "fpu_state", identity)

    replay = fpu.get("replay")
    if not isinstance(replay, Mapping):
        raise MachineIRExportError(
            f"{identity}: x87 replay metadata is missing",
            code="malformed_x87_replay",
            unit_id=identity,
            rva=span.start,
        )
    replay_bytes = _hex_bytes(replay.get("bytes"), f"{identity} x87 replay bytes")
    replay_digest = _digest(replay.get("bytes_sha256"), f"{identity} x87 replay digest")
    if (
        sha256_bytes(replay_bytes) != replay_digest
        or replay_digest != transfer_digest
        or replay.get("rva_start") != span.start
        or replay.get("rva_end") != span.end
    ):
        raise MachineIRExportError(
            f"{identity}: x87 replay does not bind the exact transfer",
            code="malformed_x87_replay",
            unit_id=identity,
            rva=span.start,
        )
    replay_instructions = replay.get("instructions")
    if not isinstance(replay_instructions, list) or len(replay_instructions) != len(instructions):
        raise MachineIRExportError(
            f"{identity}: x87 replay instruction inventory differs from the transfer",
            code="malformed_x87_replay",
            unit_id=identity,
            rva=span.start,
        )
    for index, (raw, instruction) in enumerate(zip(replay_instructions, instructions, strict=True)):
        if not isinstance(raw, Mapping):
            raise MachineIRExportError(f"{identity}: malformed x87 replay instruction {index}")
        encoded = _hex_bytes(raw.get("bytes"), f"{identity} x87 replay instruction {index}")
        if (
            raw.get("rva") != instruction.rva
            or raw.get("size") != instruction.size
            or sha256_bytes(encoded) != instruction.digest
        ):
            raise MachineIRExportError(
                f"{identity}: x87 replay instruction {index} has drifted",
                code="malformed_x87_replay",
                unit_id=identity,
                rva=instruction.rva,
            )

    selected = _x87_instruction_indices(schedule_raw, instructions, identity)
    micro_ops = []
    for index in selected:
        instruction = instructions[index]
        micro_ops.append(
            {
                "format": X87_MICRO_OP_FORMAT,
                "id": f"{identity}:x87:{instruction.rva:08x}",
                "unit_id": identity,
                "rva_start": instruction.rva,
                "rva_end": instruction.end,
                "size": instruction.size,
                "instruction_sha256": instruction.digest,
                "transfer_instruction_sha256": transfer_digest,
                "mnemonic": instruction.mnemonic,
                "operands": [copy.deepcopy(item) for item in instruction.operands],
                "implicit_registers_read": list(instruction.registers_read),
                "implicit_registers_written": list(instruction.registers_written),
                "checked_decoder": replay.get("checked_decoder"),
                "checked_executor": replay.get("checked_executor"),
                "physical_state_effect": "defined_by_checked_typed_x87_executor",
            }
        )
    metadata = {
        key: _semantic_copy(value, f"fpu_state.{key}", identity)
        for key, value in fpu.items()
        if key != "replay"
    }
    metadata["typed_replay"] = {
        "source_format": replay.get("format"),
        "architecture": replay.get("architecture"),
        "bitness": replay.get("bitness"),
        "image_base": replay.get("image_base"),
        "rva_start": replay.get("rva_start"),
        "rva_end": replay.get("rva_end"),
        "instruction_bytes_sha256": replay_digest,
        "checked_decoder": replay.get("checked_decoder"),
        "checked_executor": replay.get("checked_executor"),
        "micro_op_ids": [item["id"] for item in micro_ops],
    }
    return schedule, micro_ops, metadata


def _x87_instruction_indices(
    schedule: Any, instructions: Sequence[_Instruction], identity: str
) -> tuple[int, ...]:
    if schedule is None:
        return tuple(range(len(instructions)))
    if not isinstance(schedule, Mapping) or not isinstance(schedule.get("records"), list):
        raise MachineIRExportError(
            f"{identity}: x87 instruction effect schedule is malformed",
            code="malformed_x87_instruction_effect_schedule",
        )
    records = schedule["records"]
    if len(records) != len(instructions):
        raise MachineIRExportError(
            f"{identity}: x87 effect schedule does not cover every instruction",
            code="malformed_x87_instruction_effect_schedule",
        )
    selected: list[int] = []
    for index, raw in enumerate(records):
        if not isinstance(raw, Mapping):
            raise MachineIRExportError(f"{identity}: x87 schedule record {index} is malformed")
        if raw.get("instruction_class") == "x87_singleton_checked_replay":
            selected.append(index)
    if not selected:
        raise MachineIRExportError(
            f"{identity}: replay-backed FPU state has no typed x87 schedule records",
            code="malformed_x87_instruction_effect_schedule",
        )
    return tuple(selected)


def _sanitize_schedule(value: Any, identity: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MachineIRExportError(f"{identity}: instruction effect schedule must be an object")
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key in _RAW_INSTRUCTION_FIELDS:
            continue
        if key == "records":
            if not isinstance(item, list):
                raise MachineIRExportError(f"{identity}: schedule records must be a list")
            result[key] = [_sanitize_metadata(record, identity) for record in item]
        elif key == "blockers":
            if not isinstance(item, list):
                raise MachineIRExportError(f"{identity}: schedule blockers must be a list")
            result[key] = [_sanitize_metadata(record, identity) for record in item]
        else:
            result[key] = _sanitize_metadata(item, identity)
    if "schedule_sha256" in value:
        result["source_schedule_sha256"] = value["schedule_sha256"]
        result.pop("schedule_sha256", None)
    return result


def _sanitize_metadata(value: Any, identity: str) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _sanitize_metadata(item, identity)
            for key, item in value.items()
            if key not in _RAW_INSTRUCTION_FIELDS
        }
    if isinstance(value, list):
        return [_sanitize_metadata(item, identity) for item in value]
    return _json_scalar(value, f"{identity} metadata")


def _semantic_copy(value: Any, field: str, identity: str) -> Any:
    copied = copy.deepcopy(value)
    _assert_semantics_have_no_instruction_bytes(copied, field, identity)
    return copied


def _assert_semantics_have_no_instruction_bytes(value: Any, field: str, identity: str) -> None:
    if isinstance(value, Mapping):
        forbidden = sorted(str(key) for key in value if key in _RAW_INSTRUCTION_FIELDS)
        if forbidden:
            raise MachineIRExportError(
                f"{identity}: semantic field {field} contains raw instruction material: "
                + ", ".join(forbidden),
                code="raw_instruction_bytes_in_semantics",
                unit_id=identity,
            )
        for key, item in value.items():
            _assert_semantics_have_no_instruction_bytes(item, f"{field}.{key}", identity)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_semantics_have_no_instruction_bytes(item, f"{field}[{index}]", identity)


def _unit_issues(units: Sequence[Mapping[str, Any]]) -> list[ExportIssue]:
    issues: list[ExportIssue] = []
    for unit in units:
        if unit["status"] == "qualified":
            continue
        location = _location_from_unit(unit, "source_status")
        source_status = unit["source_status"]
        issues.append(
            ExportIssue(
                status="incomplete",
                category=str(source_status.get("blocker_category") or "incomplete_semantic_unit"),
                message=str(source_status.get("blocker") or "source semantic unit is not reimplementable"),
                next_action=str(
                    source_status.get("next_action")
                    or "complete the generic semantic transfer before reconstruction"
                ),
                location=location,
            )
        )
    return issues


def _coverage_inventory(
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    noncode_ranges: Sequence[RvaSpan],
) -> tuple[dict[str, Any], list[ExportIssue]]:
    executable = [
        RvaSpan(section.rva_start, section.rva_end)
        for section in binary.sections
        if section.executable
    ]
    code_ranges = [
        RvaSpan(
            int(unit["source"]["original"]["rva_start"]),
            int(unit["source"]["original"]["rva_end"]),
        )
        for unit in units
    ]
    issues: list[ExportIssue] = []
    for unit, span in zip(units, code_ranges, strict=True):
        if sum(section.start <= span.start and span.end <= section.end for section in executable) != 1:
            issues.append(
                ExportIssue(
                    status="violated",
                    category="semantic_unit_outside_executable_section",
                    message="semantic unit is not contained in one executable PE section",
                    next_action="repair static unit extraction and regenerate the state machine",
                    location=_location_from_unit(unit, "source.original"),
                )
            )
    effective_noncode = [
        remainder
        for span in noncode_ranges
        for remainder in _subtract_ranges(span, _merge_ranges(code_ranges))
    ]
    classified = _merge_ranges([*code_ranges, *effective_noncode])
    gaps = [gap for section in executable for gap in _subtract_ranges(section, classified)]
    for gap in gaps:
        issues.append(
            ExportIssue(
                status="incomplete",
                category="unclassified_executable_span",
                message=(
                    f"executable bytes 0x{gap.start:x}-0x{gap.end:x} are not represented "
                    "by a semantic unit or checked non-code classification"
                ),
                next_action="classify the span as semantic code, checked padding, or embedded data",
                location=SourceLocation(None, None, None, gap, "executable_coverage"),
            )
        )
    executable_bytes = sum(span.size for span in executable)
    covered_code = sum(
        overlap.size
        for section in executable
        for overlap in _intersections(section, _merge_ranges(code_ranges))
    )
    covered_noncode = sum(
        overlap.size
        for section in executable
        for overlap in _intersections(section, _merge_ranges(effective_noncode))
    )
    return (
        {
            "status": "qualified" if not gaps and not any(i.status == "violated" for i in issues) else "incomplete",
            "executable_sections": [span.payload() for span in executable],
            "semantic_code_ranges": [span.payload() for span in _merge_ranges(code_ranges)],
            "checked_noncode_ranges": [span.payload() for span in _merge_ranges(effective_noncode)],
            "unknown_ranges": [span.payload() for span in gaps],
            "counts": {
                "executable_bytes": executable_bytes,
                "semantic_code_bytes": covered_code,
                "checked_noncode_bytes": covered_noncode,
                "unknown_bytes": sum(span.size for span in gaps),
            },
        },
        issues,
    )


def _control_provenance_fixed_point(
    *,
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    root_unit_ids: Sequence[str],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    static_recoveries: Sequence[Mapping[str, Any]],
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    interface_profiles: Sequence[ExternalInterfaceProfile],
    operation_profiles: Sequence[ExternalOperationProfile],
    max_rounds: int = 16,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
    int,
    bool,
]:
    imports = [
        {
            "dll": imported.dll,
            "symbol": imported.symbol,
            "ordinal": imported.ordinal,
            "thunk_rva": imported.thunk_rva,
        }
        for imported in binary.imports
    ]
    selected_recoveries = [copy.deepcopy(dict(row)) for row in static_recoveries]
    previous_signature: str | None = None
    internal_summaries: dict[str, Any] = {
        "format": "stage-a-internal-call-preservation-v1",
        "status": "complete",
        "proof_authority": False,
        "summaries": [],
        "counts": {"call_targets": 0, "complete_summaries": 0},
    }
    provenance: dict[str, Any] = {}
    interface_provenance: dict[str, Any] = {
        "format": "stage-a-external-interface-provenance-v1",
        "status": (
            "complete"
            if not interface_profiles and not operation_profiles
            else "incomplete"
        ),
        "resolutions": [],
        "counts": {
            "recovered_method_exits": 0,
            "recovered_operation_exits": 0,
            "recovered_indirect_exits": 0,
        },
    }
    converged = False
    rounds = 0
    for rounds in range(1, max_rounds + 1):
        internal_summaries = derive_internal_call_preservation_summaries(
            units=units,
            roots=root_unit_ids,
            direct_edges=direct_edges,
            internal_call_edges=internal_call_edges,
            recovered_indirect_targets=selected_recoveries,
            indirect_exits=indirect_exits,
            import_abis=import_abis,
        )
        preserved_by_address = {
            (binary.image_base + int(row["target_rva"])) & 0xFFFFFFFF:
                frozenset(str(register) for register in row["preserved_registers"])
            for row in internal_summaries["summaries"]
            if row.get("status") == "complete"
            and isinstance(row.get("target_rva"), int)
            and isinstance(row.get("preserved_registers"), list)
        }
        stack_cleanup_by_address = {
            (binary.image_base + int(row["target_rva"]))
            & 0xFFFFFFFF: int(row["stack_cleanup"]["stack_delta"])
            for row in internal_summaries["summaries"]
            if row.get("status") == "complete"
            and isinstance(row.get("target_rva"), int)
            and isinstance(row.get("stack_cleanup"), Mapping)
            and row["stack_cleanup"].get("status") == "complete"
            and isinstance(row["stack_cleanup"].get("stack_delta"), int)
        }
        interface_provenance = recover_external_interface_targets(
            units=units,
            roots=root_unit_ids,
            direct_edges=direct_edges,
            internal_call_edges=internal_call_edges,
            recovered_indirect_edges=selected_recoveries,
            indirect_exits=indirect_exits,
            profiles=interface_profiles,
            operation_profiles=operation_profiles,
            imports=imports,
            import_abis=import_abis,
            internal_call_preserved_registers=preserved_by_address,
            image_base=binary.image_base,
            internal_call_stack_cleanup=stack_cleanup_by_address,
            static_data_reader=_immutable_static_data_reader(binary),
        )
        provenance = legacy_value_provenance_view(
            interface_provenance,
            finite_target_budget=int(
                interface_provenance["budgets"]["finite_values"]
            ),
        )
        selected_recoveries = _prefer_indirect_recoveries(
            static_recoveries,
            provenance["resolutions"],
            interface_provenance["resolutions"],
        )
        signature = _control_fixed_point_signature(
            internal_summaries, selected_recoveries
        )
        if signature == previous_signature:
            converged = True
            break
        previous_signature = signature
    return (
        provenance,
        interface_provenance,
        internal_summaries,
        selected_recoveries,
        rounds,
        converged,
    )


def _prefer_indirect_recoveries(
    static_recoveries: Sequence[Mapping[str, Any]],
    *proposal_sets: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    proposals_by_id = [
        {str(row.get("id")): row for row in proposals}
        for proposals in proposal_sets
    ]
    result: list[dict[str, Any]] = []
    for static in static_recoveries:
        candidates = [
            candidate
            for candidate in (
                static,
                *(
                    proposals.get(str(static.get("id")))
                    for proposals in proposals_by_id
                ),
            )
            if isinstance(candidate, Mapping)
            and candidate.get("status") == "recovered"
        ]
        signatures = {
            _indirect_recovery_signature(candidate) for candidate in candidates
        }
        if len(signatures) > 1:
            selected = {
                **dict(static),
                "status": "incomplete",
                "closure": "unresolved",
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [],
                "failure": {
                    "code": "conflicting_indirect_recovery_evidence",
                    "message": "independent finite target mechanisms disagree",
                },
            }
        else:
            selected = candidates[0] if candidates else static
        result.append(copy.deepcopy(dict(selected)))
    return result


def _indirect_recovery_signature(recovery: Mapping[str, Any]) -> str:
    return sha256_bytes(json.dumps(
        {
            "target_rvas": recovery.get("target_rvas", []),
            "target_unit_ids": recovery.get("target_unit_ids", []),
            "external_targets": recovery.get("external_targets", []),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8"))


def _control_fixed_point_signature(
    summaries: Mapping[str, Any], recoveries: Sequence[Mapping[str, Any]]
) -> str:
    payload = {
        "summaries": [
            {
                "target_unit_id": row.get("target_unit_id"),
                "status": row.get("status"),
                "preserved_registers": row.get("preserved_registers"),
            }
            for row in summaries.get("summaries", [])
            if isinstance(row, Mapping)
        ],
        "recoveries": [
            {
                "id": row.get("id"),
                "status": row.get("status"),
                "target_unit_ids": row.get("target_unit_ids"),
                "external_targets": row.get("external_targets"),
            }
            for row in recoveries
        ],
    }
    return sha256_bytes(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _immutable_static_data_reader(
    binary: StageABinary,
):
    def read(address: int, size: int) -> bytes | None:
        if size <= 0:
            return None
        rva = address - binary.image_base
        for section in binary.sections:
            initialized_end = min(
                section.rva_end,
                section.rva_start + section.raw_size,
            )
            if (
                section.readable
                and not section.writable
                and section.rva_start <= rva
                and rva + size <= initialized_end
            ):
                data = bytes(binary.pe.get_data(rva, size))
                return data if len(data) == size else None
        return None

    return read


def _control_inventory(
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    reference: Mapping[str, Any],
    *,
    target_profile: Mapping[str, Any] | None,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI],
    interface_profiles: Sequence[ExternalInterfaceProfile],
    operation_profiles: Sequence[ExternalOperationProfile],
) -> tuple[dict[str, Any], list[ExportIssue]]:
    starts = {int(unit["source"]["original"]["rva_start"]): unit for unit in units}
    block_starts = {
        str(unit["source_location"]["block_id"]): int(
            unit["source"]["original"]["rva_start"]
        )
        for unit in units
        if unit["source_location"].get("block_id")
    }
    submitted_roots = [
        _resolved_root(root, block_starts)
        for root in reference.get("roots", [])
        if isinstance(root, Mapping)
    ]
    binary_roots: list[dict[str, Any]] = [
        {"kind": "pe_entrypoint", "rva": binary.entrypoint_rva}
    ]
    binary_roots.extend(
        {"kind": "pe_export", "rva": exported.rva, "name": exported.name}
        for exported in binary.exports or ()
        if exported.kind == "code"
    )
    binary_roots.extend(
        {"kind": "pe_tls_callback", "rva": rva}
        for rva in binary.tls_callback_rvas or ()
    )
    roots_by_rva: dict[int, dict[str, Any]] = {}
    for root in (*binary_roots, *submitted_roots):
        raw_rva = root.get("rva", root.get("target_rva"))
        if not isinstance(raw_rva, int):
            continue
        canonical = roots_by_rva.setdefault(raw_rva, copy.deepcopy(dict(root)))
        for key, value in root.items():
            canonical.setdefault(key, copy.deepcopy(value))
    callback_root_proposals = _callback_registration_roots(binary, units)
    roots = list(roots_by_rva.values())

    direct: list[dict[str, Any]] = []
    indirect: list[dict[str, Any]] = []
    issues: list[ExportIssue] = []
    for unit in units:
        location = _location_from_unit(unit, "semantics.outcome")
        control = unit["control"]
        edge_guards = {
            int(edge["target_rva"]): copy.deepcopy(edge.get("condition"))
            for edge in unit.get("semantics", {}).get("edge_conditions", [])
            if isinstance(edge, Mapping)
            and isinstance(edge.get("target_rva"), int)
        }
        for target in control["direct_targets"]:
            resolved = target in starts
            item = {
                "kind": "direct_control",
                "source_unit_id": unit["id"],
                "source_rva": unit["source"]["original"]["rva_start"],
                "target_rva": target,
                "resolved_unit_id": starts[target]["id"] if resolved else None,
                "status": "resolved" if resolved else "incomplete",
                "guard": edge_guards.get(target),
            }
            direct.append(item)
            if not resolved:
                issues.append(
                    ExportIssue(
                        status="incomplete",
                        category="unresolved_direct_control_target",
                        message=f"direct control target 0x{target:x} has no machine IR unit",
                        next_action="export the target unit or prove the edge terminating/infeasible",
                        location=location,
                    )
                )
        if control["has_indirect_target"]:
            item = {
                    "source_unit_id": unit["id"],
                    "source_rva": unit["source"]["original"]["rva_start"],
                    "kind": control["kind"],
                    "target_expression": copy.deepcopy(unit["semantics"]["outcome"].get("target")),
                }
            item["id"] = _indirect_exit_id(item)
            indirect.append(item)
        raw_events = unit["semantics"].get("external_events")
        if isinstance(raw_events, list):
            for event_index, event in enumerate(raw_events):
                if not isinstance(event, Mapping):
                    continue
                kind = event.get("kind")
                if kind == "internal_call" and isinstance(event.get("target_rva"), int):
                    target = _u32(
                        event.get("target_rva"),
                        f"{unit['id']} internal call target",
                    )
                    resolved = target in starts
                    direct.append(
                        {
                            "kind": "internal_call",
                            "source_unit_id": unit["id"],
                            "source_rva": unit["source"]["original"]["rva_start"],
                            "source_event_index": event_index,
                            "target_rva": target,
                            "resolved_unit_id": starts[target]["id"] if resolved else None,
                            "status": "resolved" if resolved else "incomplete",
                        }
                    )
                    if not resolved:
                        issues.append(
                            ExportIssue(
                                status="incomplete",
                                category="unresolved_internal_call_target",
                                message=f"internal call target 0x{target:x} has no machine IR unit",
                                next_action="export the callee unit or correct its target recovery",
                                location=_location_from_unit(
                                    unit, f"semantics.external_events[{event_index}]"
                                ),
                            )
                        )
                elif kind in {"indirect_call", "indirect_jump"}:
                    item = {
                            "source_unit_id": unit["id"],
                            "source_rva": unit["source"]["original"]["rva_start"],
                            "source_event_index": event_index,
                            "kind": kind,
                            "target_expression": copy.deepcopy(event.get("target")),
                        }
                    item["id"] = _indirect_exit_id(item)
                    indirect.append(item)
    for root in roots:
        rva = root.get("rva", root.get("target_rva")) if isinstance(root, Mapping) else None
        if isinstance(rva, int) and rva not in starts:
            issues.append(
                ExportIssue(
                    status="incomplete",
                    category="unresolved_behavioral_root",
                    message=f"behavioral root 0x{rva:x} has no machine IR unit",
                    next_action="export a unit beginning at the root or correct root recovery",
                    location=SourceLocation(None, None, None, RvaSpan(rva, rva + 1), "control.roots"),
                )
            )
    checked_targets = reference.get("jump_table_targets", [])
    root_unit_ids = [
        starts[int(root["rva"])]["id"]
        for root in roots
        if isinstance(root.get("rva"), int) and int(root["rva"]) in starts
    ]
    direct_control_edges = [
        item for item in direct if item["kind"] == "direct_control"
    ]
    internal_call_edges = [
        item for item in direct if item["kind"] == "internal_call"
    ]
    static_recoveries: list[dict[str, Any]] = []
    static_control_rounds = 0
    static_control_converged = True
    control_fixed_point_rounds = 0
    control_fixed_point_converged = True
    while True:
        root_unit_ids = [
            starts[int(root["rva"])]["id"]
            for root in roots
            if isinstance(root.get("rva"), int) and int(root["rva"]) in starts
        ]
        (
            static_recoveries,
            static_rounds,
            static_converged,
        ) = _static_jump_table_recovery_fixed_point(
            binary=binary,
            units=units,
            starts=starts,
            indirect_exits=indirect,
            root_unit_ids=root_unit_ids,
        )
        static_control_rounds += static_rounds
        static_control_converged &= static_converged
        (
            value_provenance,
            external_interface_provenance,
            internal_call_preservation,
            recovered_targets,
            fixed_point_rounds,
            fixed_point_converged,
        ) = _control_provenance_fixed_point(
            binary=binary,
            units=units,
            root_unit_ids=root_unit_ids,
            direct_edges=direct_control_edges,
            internal_call_edges=internal_call_edges,
            indirect_exits=indirect,
            static_recoveries=static_recoveries,
            import_abis=import_abis,
            interface_profiles=interface_profiles,
            operation_profiles=operation_profiles,
        )
        control_fixed_point_rounds += fixed_point_rounds
        control_fixed_point_converged &= fixed_point_converged
        reachability = derive_rooted_reachable_units(
            units=units,
            roots=root_unit_ids,
            direct_edges=direct_control_edges,
            internal_call_edges=internal_call_edges,
            recovered_indirect_targets=recovered_targets,
            indirect_exits=indirect,
        )
        reachable_sources = set(reachability["reachable_units"])
        newly_eligible = _newly_eligible_callback_roots(
            callback_root_proposals, reachable_sources, roots_by_rva
        )
        if not newly_eligible:
            break
        for proposal in newly_eligible:
            roots_by_rva[int(proposal["rva"])] = proposal
        roots = list(roots_by_rva.values())

    if not control_fixed_point_converged:
        issues.append(
            ExportIssue(
                status="incomplete",
                category="control_provenance_fixed_point_budget_exceeded",
                message="call preservation and value provenance did not converge",
                next_action="increase the generic fixed-point budget or reduce the abstract domain",
                location=SourceLocation(
                    None, None, None, RvaSpan(binary.entrypoint_rva, binary.entrypoint_rva + 1),
                    "control.fixed_point",
                ),
            )
        )
    if not static_control_converged:
        issues.append(
            ExportIssue(
                status="incomplete",
                category="static_jump_table_fixed_point_budget_exceeded",
                message="finite index domains and static target inventories did not converge",
                next_action="increase the generic fixed-point budget or reduce the finite domain",
                location=SourceLocation(
                    None,
                    None,
                    None,
                    RvaSpan(binary.entrypoint_rva, binary.entrypoint_rva + 1),
                    "control.static_jump_tables",
                ),
            )
        )

    for exit_record, static_recovery, selected_recovery in zip(
        indirect, static_recoveries, recovered_targets, strict=True
    ):
        source_unit = next(
            unit for unit in units if unit["id"] == exit_record["source_unit_id"]
        )
        unit_binding_complete = _indirect_recovery_unit_binding_complete(
            selected_recovery, starts
        )
        if selected_recovery["status"] == "recovered" and unit_binding_complete:
            exit_record["closure"] = "checked_finite_target_inventory"
            exit_record["target_rvas"] = list(
                selected_recovery.get("target_rvas", [])
            )
            exit_record["target_unit_ids"] = list(
                selected_recovery.get("target_unit_ids", [])
            )
            exit_record["external_targets"] = copy.deepcopy(
                selected_recovery.get("external_targets", [])
            )
            if static_recovery["status"] == "recovered":
                exit_record["recovery"] = {
                    "kind": static_recovery["kind"],
                    "index": static_recovery["index"],
                    "table": static_recovery["table"],
                    "entries": static_recovery["entries"],
                }
            else:
                exit_record["recovery"] = {
                    "kind": (
                        "bounded_external_interface_provenance"
                        if selected_recovery.get("closure")
                        == "checked_profile_interface_method_inventory"
                        else "bounded_external_operation_provenance"
                        if selected_recovery.get("closure")
                        == "checked_external_operation_inventory"
                        else "bounded_value_provenance"
                    ),
                    "closure": selected_recovery["closure"],
                    "origin_count": selected_recovery.get("origin_count"),
                }
            continue

        checked = _indirect_exit_has_checked_targets(
            exit_record, checked_targets, units
        )
        profiled = target_profile is not None
        exit_record["closure"] = (
            "checked_target_marker_without_inventory"
            if checked
            else "explicit_trusted_target_profile_without_inventory"
            if profiled
            else "unresolved"
        )
        if selected_recovery.get("status") == "recovered":
            recovery_failure: Mapping[str, Any] = {
                "code": "unmaterialized_indirect_target",
                "message": (
                    "a checked finite target inventory contains an executable "
                    "RVA without one exact machine-IR unit"
                ),
            }
        else:
            recovery_failure = selected_recovery.get("failure")
        if not isinstance(recovery_failure, Mapping):
            recovery_failure = static_recovery["failure"]
        exit_record["recovery_failure"] = copy.deepcopy(recovery_failure)
        issues.append(
            ExportIssue(
                status="incomplete",
                category="unresolved_indirect_control",
                message=(
                    "indirect control exit has no checked finite target inventory: "
                    + str(recovery_failure["message"])
                ),
                next_action=(
                    "supply path-sensitive bounds and an immutable checked target table; "
                    "a marker or global target profile does not establish rooted closure"
                ),
                location=_location_from_unit(source_unit, "control.indirect_target"),
            )
        )

    exact_reachable = set(reachability["reachable_units"])
    starts_by_id = {str(unit["id"]): unit for unit in units}
    potentially_reachable = (
        set(starts_by_id)
        if reachability["status"] != "complete"
        else exact_reachable
    )
    for unit in units:
        unit_id = str(unit["id"])
        unit["reachable"] = unit_id in exact_reachable
        unit["reachability"] = (
            "reachable"
            if unit_id in exact_reachable
            else "potential"
            if unit_id in potentially_reachable
            else "unreachable"
        )
    reachability["potential_units"] = sorted(potentially_reachable - exact_reachable)
    reachability["confirmed_unreachable_units"] = (
        sorted(set(starts_by_id) - exact_reachable)
        if reachability["status"] == "complete"
        else []
    )
    reachability["counts"].update(
        {
            "potential_units": len(potentially_reachable - exact_reachable),
            "confirmed_unreachable_units": len(
                reachability["confirmed_unreachable_units"]
            ),
        }
    )
    return (
        {
            "roots": sorted(roots, key=_root_sort_key),
            "direct_targets": sorted(direct, key=lambda item: (item["source_rva"], item["target_rva"])),
            "indirect_exits": sorted(indirect, key=lambda item: (item["source_rva"], item["source_unit_id"])),
            "recovered_indirect_targets": sorted(
                recovered_targets,
                key=lambda item: (item["source_rva"], item["source_unit_id"]),
            ),
            "value_provenance": value_provenance,
            "external_interface_provenance": external_interface_provenance,
            "operation_provenance": operation_provenance_view(
                external_interface_provenance
            ),
            "internal_call_preservation": internal_call_preservation,
            "callback_cutpoint_proposals": callback_root_proposals,
            "analysis_fixed_point": {
                "status": (
                    "complete"
                    if control_fixed_point_converged and static_control_converged
                    else "incomplete"
                ),
                "rounds": control_fixed_point_rounds,
                "static_jump_table_rounds": static_control_rounds,
                "static_jump_table_converged": static_control_converged,
                "callback_root_reanalysis": True,
            },
            "reachability": reachability,
            "checked_jump_table_targets": checked_targets,
            "indirect_target_profile": (
                None
                if target_profile is None
                else {
                    "id": target_profile["id"],
                    "internal_target_domain": target_profile["internal_target_domain"],
                    "external_target_domain": target_profile["external_target_domain"],
                    "runtime_rejection_required": True,
                }
            ),
            "counts": {
                "roots": len(roots),
                "direct_targets": len(direct),
                "unresolved_direct_targets": sum(item["status"] != "resolved" for item in direct),
                "indirect_exits": len(indirect),
                "closed_indirect_exits": sum(
                    item["closure"] == "checked_finite_target_inventory"
                    for item in indirect
                ),
                "exact_reachable_units": len(exact_reachable),
                "potential_reachable_units": len(
                    potentially_reachable - exact_reachable
                ),
                "rooted_frontiers": len(reachability["frontiers"]),
                "checked_jump_table_targets": len(checked_targets),
                "callback_cutpoint_proposals": len(callback_root_proposals),
            },
        },
        issues,
    )


def _indirect_recovery_unit_binding_complete(
    recovery: Mapping[str, Any],
    starts: Mapping[int, Mapping[str, Any]],
) -> bool:
    raw_rvas = recovery.get("target_rvas", [])
    raw_ids = recovery.get("target_unit_ids", [])
    if (
        not isinstance(raw_rvas, Sequence)
        or isinstance(raw_rvas, (str, bytes))
        or not isinstance(raw_ids, Sequence)
        or isinstance(raw_ids, (str, bytes))
    ):
        return False
    target_rvas = []
    for raw_rva in raw_rvas:
        if (
            isinstance(raw_rva, bool)
            or not isinstance(raw_rva, int)
            or not 0 <= raw_rva < 2**32
        ):
            return False
        target_rvas.append(raw_rva)
    if any(rva not in starts for rva in target_rvas):
        return False
    expected_ids = {str(starts[rva]["id"]) for rva in target_rvas}
    if {str(value) for value in raw_ids} != expected_ids:
        return False
    external = canonical_indirect_external_targets(recovery)
    return external is not None and bool(target_rvas or external)


def _static_jump_table_recovery_fixed_point(
    *,
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    starts: Mapping[int, Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
    root_unit_ids: Sequence[str],
    max_rounds: int = 16,
) -> tuple[list[dict[str, Any]], int, bool]:
    units_by_id = {str(unit["id"]): unit for unit in units}
    selected: list[dict[str, Any]] = []
    previous_signature: str | None = None
    for round_index in range(1, max_rounds + 1):
        dataflow = FiniteU32Dataflow(
            units=units,
            roots=root_unit_ids,
            recovered_indirect_targets=selected,
        )
        recoveries: list[dict[str, Any]] = []
        for exit_record in indirect_exits:
            source_unit_id = str(exit_record["source_unit_id"])
            source_unit = units_by_id[source_unit_id]
            target_expression = exit_record.get("target_expression") or {}
            index_expression = pe32_jump_table_index_expression(target_expression)
            finite_domain = (
                dataflow.expression_domain(source_unit_id, index_expression)
                if index_expression is not None
                else None
            )
            recovery = recover_static_pe32_jump_table_inventory(
                target_expression=target_expression,
                predecessor_evidence=_indirect_predecessor_evidence(
                    source_unit, units
                ),
                image_base=binary.image_base,
                sections=binary.sections,
                read_rva=lambda rva, size: bytes(binary.pe.get_data(rva, size)),
                finite_index_domain=finite_domain,
                valid_target_rvas=None,
            )
            target_rvas = [
                int(rva)
                for rva in recovery.get("target_rvas", [])
                if isinstance(rva, int) and not isinstance(rva, bool)
            ]
            resolved_target_rvas = sorted(
                rva for rva in target_rvas if rva in starts
            )
            unmaterialized_target_rvas = sorted(
                rva for rva in target_rvas if rva not in starts
            )
            recovery.update(
                {
                    "id": exit_record["id"],
                    "source_unit_id": source_unit_id,
                    "source_rva": exit_record["source_rva"],
                    "source_event_index": exit_record.get("source_event_index"),
                    "kind": exit_record["kind"],
                    "finite_index_domain": finite_domain,
                    "target_unit_ids": [
                        starts[rva]["id"] for rva in resolved_target_rvas
                    ],
                    "unit_binding": {
                        "status": (
                            "complete"
                            if recovery.get("status") == "recovered"
                            and not unmaterialized_target_rvas
                            else "incomplete"
                        ),
                        "resolved_target_rvas": resolved_target_rvas,
                        "unmaterialized_target_rvas": unmaterialized_target_rvas,
                    },
                }
            )
            recoveries.append(recovery)
        signature = sha256_bytes(
            json.dumps(
                [
                    {
                        "id": row.get("id"),
                        "status": row.get("status"),
                        "index_values": (
                            row["index"].get("values")
                            if isinstance(row.get("index"), Mapping)
                            else None
                        ),
                        "target_rvas": row.get("target_rvas"),
                        "target_unit_ids": row.get("target_unit_ids"),
                        "failure": row.get("failure"),
                    }
                    for row in recoveries
                ],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
        selected = recoveries
        if signature == previous_signature:
            return selected, round_index, True
        previous_signature = signature
    return selected, max_rounds, False


def _callback_registration_roots(
    binary: StageABinary, units: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    starts = {
        int(unit["source"]["original"]["rva_start"]): unit for unit in units
    }
    executable_sections = tuple(
        section
        for section in getattr(binary, "sections", ())
        if getattr(section, "executable", False)
    )
    result: dict[int, dict[str, Any]] = {}
    for unit in units:
        events = unit.get("semantics", {}).get("external_events", [])
        if not isinstance(events, list):
            continue
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping):
                continue
            abi = event.get("abi_contract")
            if not isinstance(abi, Mapping) or abi.get("world_effect") != "callbackRegistration":
                continue
            argument_index = abi.get("world_effect_argument")
            arguments = _checked_external_argument_values(event)
            if (
                not isinstance(argument_index, int)
                or isinstance(argument_index, bool)
                or not 0 <= argument_index < len(arguments)
            ):
                continue
            expression = _forward_callback_argument_expression(
                arguments[argument_index],
                unit=unit,
                event=event,
            )
            value = (
                expression.get("value")
                if isinstance(expression, Mapping)
                and expression.get("op") in {"const", "constant"}
                else None
            )
            if not isinstance(value, int) or isinstance(value, bool) or value == 0:
                continue
            candidates = [value]
            if value >= binary.image_base:
                candidates.insert(0, value - binary.image_base)
            rva = next(
                (
                    candidate
                    for candidate in candidates
                    if (
                        any(
                            section.rva_start <= candidate < section.rva_end
                            for section in executable_sections
                        )
                        if executable_sections
                        else candidate in starts
                    )
                ),
                None,
            )
            if rva is None:
                continue
            result.setdefault(
                rva,
                {
                    "kind": "registered_callback",
                    "rva": rva,
                    "source_unit_id": unit["id"],
                    "source_event_index": event_index,
                    "dll": event.get("dll"),
                    "symbol": event.get("symbol"),
                    "callback_abi": copy.deepcopy(abi.get("callback_abi")),
                },
            )
    return [result[rva] for rva in sorted(result)]


def _forward_callback_argument_expression(
    expression: Any,
    *,
    unit: Mapping[str, Any],
    event: Mapping[str, Any],
) -> Any:
    if (
        not isinstance(expression, Mapping)
        or expression.get("op") != "load"
        or expression.get("width") != 4
    ):
        return expression
    address = expression.get("address")
    instruction_rva = event.get("instruction_rva")
    ordered = unit.get("semantics", {}).get("ordered_events", [])
    if not isinstance(ordered, list):
        return expression
    if not isinstance(instruction_rva, int):
        matching_calls = [
            item
            for item in ordered
            if isinstance(item, Mapping)
            and item.get("family") == "external"
            and item.get("kind") == event.get("kind")
            and item.get("dll") == event.get("dll")
            and item.get("symbol") == event.get("symbol")
            and item.get("ordinal") == event.get("ordinal")
            and item.get("return_rva") == event.get("return_rva")
            and isinstance(item.get("instruction_rva"), int)
        ]
        if len(matching_calls) != 1:
            return expression
        instruction_rva = int(matching_calls[0]["instruction_rva"])
    writes = [
        item
        for item in ordered
        if isinstance(item, Mapping)
        and item.get("family") == "memory"
        and item.get("kind") == "write"
        and item.get("width") == 4
        and item.get("address") == address
        and isinstance(item.get("instruction_rva"), int)
        and item.get("instruction_rva") < instruction_rva
    ]
    if not writes:
        return expression
    latest_rva = max(int(item["instruction_rva"]) for item in writes)
    latest = [item for item in writes if item.get("instruction_rva") == latest_rva]
    return latest[0].get("value") if len(latest) == 1 else expression


def _checked_external_argument_values(event: Mapping[str, Any]) -> list[Any]:
    stack_inputs = event.get("stack_inputs")
    if isinstance(stack_inputs, list) and stack_inputs and all(
        isinstance(item, Mapping) and "value" in item for item in stack_inputs
    ):
        return [
            item["value"]
            for item in sorted(
                stack_inputs,
                key=lambda item: (
                    int(item["offset"])
                    if isinstance(item.get("offset"), int)
                    and not isinstance(item.get("offset"), bool)
                    else 0x1_0000_0000
                ),
            )
        ]
    arguments = event.get("arguments")
    return list(arguments) if isinstance(arguments, list) else []


def _newly_eligible_callback_roots(
    proposals: Sequence[Mapping[str, Any]],
    reachable_sources: set[str],
    existing_roots: Mapping[int, Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    return [
        proposal
        for proposal in proposals
        if str(proposal["source_unit_id"]) in reachable_sources
        and int(proposal["rva"]) not in existing_roots
    ]


def _indirect_predecessor_evidence(
    source_unit: Mapping[str, Any], units: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    source_rva = int(source_unit["source"]["original"]["rva_start"])
    predecessors_by_target: dict[int, list[Mapping[str, Any]]] = {}
    for candidate in units:
        control = candidate.get("control")
        if not isinstance(control, Mapping):
            continue
        for target in control.get("direct_targets", []):
            if isinstance(target, int) and not isinstance(target, bool):
                predecessors_by_target.setdefault(target, []).append(candidate)
    result: list[dict[str, Any]] = []
    for predecessor in predecessors_by_target.get(source_rva, []):
        outcome = predecessor.get("semantics", {}).get("outcome", {})
        edge_kind = "fallthrough"
        if isinstance(outcome, Mapping) and outcome.get("kind") == "branch":
            edge_kind = (
                "taken"
                if outcome.get("true_target_rva") == source_rva
                else "fallthrough"
            )
        guard = None
        for edge in predecessor.get("semantics", {}).get("edge_conditions", []):
            if isinstance(edge, Mapping) and edge.get("target_rva") == source_rva:
                guard = copy.deepcopy(edge.get("condition"))
                break
        instructions = _bounded_predecessor_instruction_history(
            predecessor,
            predecessors_by_target=predecessors_by_target,
        )
        result.append(
            {
                "source_unit_id": predecessor["id"],
                "edge_kind": edge_kind,
                "guard": guard,
                "instructions": instructions,
            }
        )
    return sorted(result, key=lambda item: str(item["source_unit_id"]))


def _bounded_predecessor_instruction_history(
    predecessor: Mapping[str, Any],
    *,
    predecessors_by_target: Mapping[int, Sequence[Mapping[str, Any]]],
    max_units: int = 8,
) -> list[dict[str, Any]]:
    history = [
        copy.deepcopy(dict(instruction))
        for instruction in predecessor.get("instructions", [])
        if isinstance(instruction, Mapping)
    ]
    cursor = predecessor
    visited = {str(predecessor.get("id"))}
    for _ in range(max_units - 1):
        if any(
            str(instruction.get("mnemonic", "")).lower() == "cmp"
            for instruction in history
        ):
            break
        source = cursor.get("source", {}).get("original", {})
        start = source.get("rva_start") if isinstance(source, Mapping) else None
        if not isinstance(start, int) or isinstance(start, bool):
            break
        candidates = []
        for candidate in predecessors_by_target.get(start, []):
            candidate_id = str(candidate.get("id"))
            candidate_source = candidate.get("source", {}).get("original", {})
            candidate_outcome = candidate.get("semantics", {}).get("outcome", {})
            candidate_events = candidate.get("semantics", {}).get(
                "external_events", []
            )
            if (
                candidate_id in visited
                or not isinstance(candidate_source, Mapping)
                or candidate_source.get("rva_end") != start
                or not isinstance(candidate_outcome, Mapping)
                or candidate_outcome.get("kind") != "fallthrough"
                or candidate_outcome.get("target_rva") != start
                or (isinstance(candidate_events, list) and candidate_events)
            ):
                continue
            candidates.append(candidate)
        if len(candidates) != 1:
            break
        cursor = candidates[0]
        visited.add(str(cursor.get("id")))
        prefix = [
            copy.deepcopy(dict(instruction))
            for instruction in cursor.get("instructions", [])
            if isinstance(instruction, Mapping)
        ]
        history = prefix + history
    return history


def _indirect_exit_id(value: Mapping[str, Any]) -> str:
    identity = {
        "source_unit_id": value.get("source_unit_id"),
        "source_rva": value.get("source_rva"),
        "source_event_index": value.get("source_event_index"),
        "kind": value.get("kind"),
        "target_expression": value.get("target_expression"),
    }
    return "indirect-exit:" + sha256_bytes(_canonical_json(identity))[:20]


def _load_indirect_target_profile(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    value = _json_object(_regular_file(Path(path), "indirect target profile"), "indirect target profile")
    expected = {
        "format": INDIRECT_TARGET_PROFILE_FORMAT,
        "id": "pe32-static-cutpoints-and-paired-callables-v1",
        "status": "accepted_assumption",
        "internal_target_domain": "all_checked_machine_ir_unit_starts",
        "external_target_domain": "paired_external_callable_resources",
        "runtime_rejection_required": True,
    }
    for key, expected_value in expected.items():
        if value.get(key) != expected_value:
            raise MachineIRExportError(
                f"indirect target profile has unsupported {key}",
                code="invalid_indirect_target_profile",
            )
    assumption = value.get("assumption")
    if not isinstance(assumption, Mapping) or {
        key for key in ("id", "scope", "statement") if not isinstance(assumption.get(key), str)
    }:
        raise MachineIRExportError(
            "indirect target profile has no explicit assumption",
            code="invalid_indirect_target_profile",
        )
    return copy.deepcopy(dict(value))


def _external_inventory(units: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    events: list[dict[str, Any]] = []
    for unit in units:
        raw_events = unit["semantics"].get("external_events")
        if not isinstance(raw_events, list):
            continue
        for index, event in enumerate(raw_events):
            if not isinstance(event, Mapping):
                continue
            events.append(
                {
                    "unit_id": unit["id"],
                    "unit_rva": unit["source"]["original"]["rva_start"],
                    "event_index": index,
                    "kind": event.get("kind"),
                    "instruction_rva": event.get("instruction_rva"),
                    "dll": event.get("dll"),
                    "symbol": event.get("symbol"),
                    "ordinal": event.get("ordinal"),
                    "event": copy.deepcopy(event),
                }
            )
    events.sort(key=lambda item: (item["unit_rva"], item["event_index"], str(item["kind"])))
    imports = sorted(
        {
            (str(item.get("dll") or "").lower(), str(item.get("symbol") or ""), item.get("ordinal"))
            for item in events
            if item.get("dll")
        },
        key=lambda item: (item[0], item[1], -1 if item[2] is None else int(item[2])),
    )
    return {
        "events": events,
        "normalized_imports": [
            {"dll": dll, "symbol": symbol or None, "ordinal": ordinal}
            for dll, symbol, ordinal in imports
        ],
        "counts": {"events": len(events), "normalized_imports": len(imports)},
    }


def _reference_inventory(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    empty = {
        "roots": [],
        "jump_table_targets": [],
        "noncode_ranges": [],
        "public": None,
    }
    if payload is None:
        return empty
    constraints = payload.get("constraints")
    if not isinstance(constraints, Mapping):
        return empty
    coverage = constraints.get("executable_byte_coverage")
    original_coverage = coverage.get("original") if isinstance(coverage, Mapping) else None
    waiver_values = (
        original_coverage.get("waived_noncode_ranges", [])
        if isinstance(original_coverage, Mapping)
        else []
    )
    noncode = [span for value in waiver_values if (span := _optional_range(value)) is not None]
    roots_constraint = constraints.get("roots_and_jump_tables")
    roots = (
        [_sanitize_metadata(item, "reference") for item in roots_constraint.get("roots", [])]
        if isinstance(roots_constraint, Mapping) and isinstance(roots_constraint.get("roots"), list)
        else []
    )
    targets = (
        [_sanitize_metadata(item, "reference") for item in roots_constraint.get("jump_table_targets", [])]
        if isinstance(roots_constraint, Mapping) and isinstance(roots_constraint.get("jump_table_targets"), list)
        else []
    )
    public = {
        "executable_byte_coverage": _constraint_projection(coverage),
        "function_ranges": _constraint_projection(constraints.get("function_ranges")),
        "basic_blocks_and_cfg": _constraint_projection(constraints.get("basic_blocks_and_cfg")),
        "roots_and_jump_tables": _constraint_projection(roots_constraint),
        "import_thunks": _constraint_projection(constraints.get("import_thunks")),
    }
    return {
        "roots": roots,
        "jump_table_targets": targets,
        "noncode_ranges": noncode,
        "public": public,
    }


def _constraint_projection(value: Any) -> Any:
    return _sanitize_metadata(value, "reference") if isinstance(value, Mapping) else None


def _reference_issues(payload: Mapping[str, Any] | None) -> list[ExportIssue]:
    if payload is None:
        return []
    result: list[ExportIssue] = []
    constraints = payload.get("constraints")
    if isinstance(constraints, Mapping):
        # The reconstruction frontend consumes only static binary facts needed
        # to prevent omitted code or malformed external boundaries. Optional
        # layout and symbol-derived families remain advisory.
        for family in (
            "pe_sections_imports_relocations_image_base",
            "executable_byte_coverage",
            "basic_blocks_and_cfg",
            "roots_and_jump_tables",
            "import_thunks",
            "padding_alignment",
        ):
            constraint = constraints.get(family)
            if not isinstance(constraint, Mapping):
                continue
            raw_status = constraint.get("status")
            if raw_status not in {"failed", "violated", "incomplete", "not_provided"}:
                continue
            status = "violated" if raw_status in {"failed", "violated"} else "incomplete"
            result.append(
                ExportIssue(
                    status=status,
                    category=f"reference_{family}_{raw_status}",
                    message=str(
                        constraint.get("blocker")
                        or f"reference contract family {family} is {raw_status}"
                    ),
                    next_action=str(
                        constraint.get("next_action")
                        or f"complete the reference contract {family} evidence"
                    ),
                    location=SourceLocation(
                        None,
                        None,
                        None,
                        None,
                        f"reference_contract.constraints.{family}",
                    ),
                )
            )
    return result


def _binary_inventory(binary: StageABinary) -> dict[str, Any]:
    return {
        "sha256": binary.sha256,
        "machine": binary.machine,
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "entrypoint_rva": binary.entrypoint_rva,
        "size_of_image": binary.size_of_image,
        "sections": [
            {
                "name": section.name,
                "rva_start": section.rva_start,
                "rva_end": section.rva_end,
                "mapped_size": section.rva_end - section.rva_start,
                "executable": section.executable,
                "readable": section.readable,
                "writable": section.writable,
            }
            for section in binary.sections
        ],
        "imports": [
            {
                "dll": imported.dll,
                "symbol": imported.symbol,
                "ordinal": imported.ordinal,
                "thunk_rva": imported.thunk_rva,
            }
            for imported in binary.imports
        ],
    }


def _outcome_targets(
    value: Any, identity: str, *, terminating: bool = False
) -> list[int]:
    if not isinstance(value, Mapping):
        raise MachineIRExportError(f"{identity}: outcome must be an object", unit_id=identity)
    kind = value.get("kind")
    if terminating:
        return []
    fields = _DIRECT_OUTCOME_FIELDS.get(str(kind), ())
    return [_u32(value.get(field), f"{identity} outcome {field}") for field in fields]


def _control_disposition(value: Mapping[str, Any], identity: str) -> dict[str, str] | None:
    raw = value.get("control_disposition")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise MachineIRExportError(
            f"{identity}: control disposition must be an object",
            code="malformed_control_disposition",
            unit_id=identity,
        )
    expected = {
        "kind": "terminates_after_external_event",
        "authority": "external_profile_machine_import_contract",
    }
    result = {key: raw.get(key) for key in expected}
    if result != expected:
        raise MachineIRExportError(
            f"{identity}: unsupported control disposition",
            code="malformed_control_disposition",
            unit_id=identity,
        )
    events = value.get("external_events")
    if not isinstance(events, list) or not any(
        isinstance(event, Mapping) and event.get("kind") == "external_call"
        for event in events
    ):
        raise MachineIRExportError(
            f"{identity}: terminating control disposition has no external call",
            code="malformed_control_disposition",
            unit_id=identity,
        )
    return result


def _binding_projection(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    return {
        key: value.get(key)
        for key in (
            "format",
            "reference_contract_sha256",
            "semantic_transfer_sha256",
        )
    }


def _resolved_root(root: Mapping[str, Any], block_starts: Mapping[str, int]) -> dict[str, Any]:
    result = copy.deepcopy(dict(root))
    if not isinstance(result.get("rva"), int):
        block_id = result.get("block_id")
        if isinstance(block_id, str) and block_id in block_starts:
            result["rva"] = block_starts[block_id]
    return result


def _root_sort_key(root: Mapping[str, Any]) -> tuple[int, str, str]:
    raw_rva = root.get("rva", root.get("target_rva"))
    rva = raw_rva if isinstance(raw_rva, int) else -1
    return rva, str(root.get("kind") or ""), str(root.get("block_id") or "")


def _indirect_exit_has_checked_targets(
    exit_record: Mapping[str, Any],
    targets: Any,
    units: Sequence[Mapping[str, Any]],
) -> bool:
    if not isinstance(targets, list) or not targets:
        return False
    source = next(
        unit for unit in units if unit["id"] == exit_record["source_unit_id"]
    )
    source_block = source["source_location"].get("block_id")
    source_function = source["source_location"].get("function")
    return any(
        isinstance(target, Mapping)
        and (
            target.get("block_id") == source_block
            or (
                source_function is not None
                and target.get("function") == source_function
                and target.get("instruction_rva")
                in {None, exit_record.get("source_rva")}
            )
        )
        for target in targets
    )


def _location_from_unit(unit: Mapping[str, Any], field: str) -> SourceLocation:
    source = unit["source_location"]
    return SourceLocation(
        unit_id=str(unit["id"]),
        function=_optional_string(source.get("function")),
        block_id=_optional_string(source.get("block_id")),
        span=RvaSpan(int(source["rva_start"]), int(source["rva_end"])),
        field=field,
    )


def _unit_span(row: Mapping[str, Any], identity: str) -> RvaSpan:
    original = row.get("original")
    if not isinstance(original, Mapping):
        raise MachineIRExportError(f"{identity}: original span is missing", unit_id=identity)
    start = _u32(original.get("rva_start"), f"{identity} original.rva_start")
    end = _u32(original.get("rva_end"), f"{identity} original.rva_end")
    if end <= start or original.get("size", end - start) != end - start:
        raise MachineIRExportError(
            f"{identity}: original span is empty or inconsistent",
            code="malformed_machine_unit_span",
            unit_id=identity,
            rva=start,
        )
    return RvaSpan(start, end)


def _validate_semantic_shape(
    row: Mapping[str, Any], identity: str, span: RvaSpan
) -> None:
    if not isinstance(row.get("status"), str) or not row.get("status"):
        raise MachineIRExportError(
            f"{identity}: semantic unit status is missing",
            code="malformed_semantic_unit_status",
            unit_id=identity,
            rva=span.start,
        )
    if not isinstance(row.get("expression_model"), str) or not row.get("expression_model"):
        raise MachineIRExportError(
            f"{identity}: expression model is missing",
            code="malformed_semantic_unit_model",
            unit_id=identity,
            rva=span.start,
        )
    if not isinstance(row.get("pre_state"), Mapping):
        raise MachineIRExportError(
            f"{identity}: pre_state must be an object",
            code="malformed_semantic_unit_effects",
            unit_id=identity,
            rva=span.start,
        )
    for field in (
        "register_writes",
        "flag_writes",
        "memory_events",
        "external_events",
        "faults",
        "ordered_events",
        "edge_conditions",
    ):
        values = row.get(field)
        if not isinstance(values, list) or any(
            not isinstance(item, Mapping) for item in values
        ):
            raise MachineIRExportError(
                f"{identity}: {field} must be a list of objects",
                code="malformed_semantic_unit_effects",
                unit_id=identity,
                rva=span.start,
            )
    outcome = row.get("outcome")
    if (
        not isinstance(outcome, Mapping)
        or not isinstance(outcome.get("kind"), str)
        or not outcome.get("kind")
    ):
        raise MachineIRExportError(
            f"{identity}: outcome must name a control kind",
            code="malformed_semantic_unit_control",
            unit_id=identity,
            rva=span.start,
        )
    stack_delta = row.get("stack_delta")
    if stack_delta is not None and not isinstance(stack_delta, Mapping):
        raise MachineIRExportError(
            f"{identity}: stack_delta must be an object or null",
            code="malformed_semantic_unit_effects",
            unit_id=identity,
            rva=span.start,
        )
    counts = row.get("counts")
    if counts is not None and not isinstance(counts, Mapping):
        raise MachineIRExportError(
            f"{identity}: counts must be an object or null",
            code="malformed_semantic_unit_effects",
            unit_id=identity,
            rva=span.start,
        )


def _merge_ranges(ranges: Iterable[RvaSpan]) -> list[RvaSpan]:
    merged: list[RvaSpan] = []
    for span in sorted(ranges):
        if not merged or span.start > merged[-1].end:
            merged.append(span)
        else:
            merged[-1] = RvaSpan(merged[-1].start, max(merged[-1].end, span.end))
    return merged


def _subtract_ranges(whole: RvaSpan, classified: Sequence[RvaSpan]) -> list[RvaSpan]:
    cursor = whole.start
    result: list[RvaSpan] = []
    for span in classified:
        if span.end <= cursor or span.start >= whole.end:
            continue
        if span.start > cursor:
            result.append(RvaSpan(cursor, min(span.start, whole.end)))
        cursor = max(cursor, span.end)
        if cursor >= whole.end:
            break
    if cursor < whole.end:
        result.append(RvaSpan(cursor, whole.end))
    return result


def _intersections(whole: RvaSpan, ranges: Sequence[RvaSpan]) -> list[RvaSpan]:
    return [
        RvaSpan(max(whole.start, span.start), min(whole.end, span.end))
        for span in ranges
        if max(whole.start, span.start) < min(whole.end, span.end)
    ]


def _optional_range(value: Any) -> RvaSpan | None:
    if not isinstance(value, Mapping):
        return None
    start = value.get("rva_start", value.get("rva"))
    end = value.get("rva_end")
    if end is None and isinstance(start, int) and isinstance(value.get("size"), int):
        end = start + value["size"]
    if (
        isinstance(start, int)
        and not isinstance(start, bool)
        and isinstance(end, int)
        and not isinstance(end, bool)
        and 0 <= start < end <= 2**32
    ):
        return RvaSpan(start, end)
    return None


def _aggregate_status(issues: Sequence[Mapping[str, Any]]) -> str:
    if any(issue.get("status") == "violated" for issue in issues):
        return "violated"
    if issues:
        return "incomplete"
    return "qualified"


def _assert_byte_free(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            numeric_byte_count = (
                key == "bytes"
                and isinstance(item, int)
                and not isinstance(item, bool)
                and item >= 0
            )
            if key in _RAW_INSTRUCTION_FIELDS and not numeric_byte_count:
                raise AssertionError(f"raw instruction field {path}.{key} crossed the machine IR boundary")
            _assert_byte_free(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_byte_free(item, f"{path}[{index}]")


def _regular_file(value: Path, label: str) -> Path:
    supplied = Path(value)
    if supplied.is_symlink() or not supplied.is_file():
        raise MachineIRExportError(f"{label} must be a regular non-symlink file")
    return supplied.resolve()


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MachineIRExportError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise MachineIRExportError(f"{label} must contain one JSON object")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MachineIRExportError(f"{label} must be a non-empty string")
    return value


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise MachineIRExportError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _u32(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**32:
        raise MachineIRExportError(f"{label} must be an unsigned 32-bit integer")
    return value


def _hex_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise MachineIRExportError(f"{label} must be an even-length hexadecimal string")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise MachineIRExportError(f"{label} must be hexadecimal") from exc


def _json_scalar(value: Any, label: str) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise MachineIRExportError(f"{label} contains a non-JSON value {type(value).__name__}")


__all__ = [
    "MACHINE_IR_FILENAME",
    "MACHINE_IR_FORMAT",
    "MACHINE_IR_MANIFEST_FILENAME",
    "PREPARED_MACHINE_IR_FILENAME",
    "PREPARED_MACHINE_IR_FORMAT",
    "PREPARED_MACHINE_IR_MANIFEST_FILENAME",
    "MachineIRExportError",
    "MachineIRPackage",
    "PreparedMachineIRPackage",
    "X87_MICRO_OP_FORMAT",
    "export_machine_ir_package",
    "prepare_machine_ir_units_package",
]
