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

from .callback_contracts import parse_callback_source
from .authority_bindings_v2 import indirect_exit_id_v2
from .finite_value_domain import FiniteU32Dataflow
from .indirect_target_dependency_v2 import (
    build_bounded_selector_dependency_v2,
)
from .machine_ir_authority_v2 import build_machine_ir_authority_bindings
from .reconstruction_control import (
    canonical_indirect_external_targets,
    classify_overlapping_instruction_starts,
    derive_rooted_reachable_units,
    pe32_jump_table_index_expression,
    recover_static_pe32_jump_table_inventory,
)
from .recovered_executable_data import (
    RECOVERED_EXECUTABLE_DATA_FILENAME,
    RECOVERED_EXECUTABLE_DATA_FORMAT,
    build_recovered_executable_data_contract,
    recover_executable_data_ranges,
)
from .reconstruction_validation import check_straight_line_semantic_claim
from .stage_b_state_machine import (
    STAGE_A_REFERENCE_CONTRACT_FORMAT,
    STAGE_B_STATE_MACHINE_FORMAT,
    load_stage_a_reference_contract_binding,
    normalize_stage_a_semantic_transfer,
)
from .stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from .static_indirect_replay_v2 import (
    bounded_predecessor_instruction_history as _bounded_predecessor_instruction_history,
    direct_predecessors_by_target as _direct_predecessors_by_target,
    indirect_predecessor_evidence as _indirect_predecessor_evidence,
)
from .util import sha256_bytes, sha256_file, write_json


MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
MACHINE_IR_FILENAME = "machine-ir.jsonl"
MACHINE_IR_MANIFEST_FILENAME = "machine-ir-manifest.json"
PREPARED_MACHINE_IR_FORMAT = "stage-a-prepared-machine-ir-v1"
PREPARED_MACHINE_IR_FILENAME = "prepared-machine-ir.jsonl"
PREPARED_MACHINE_IR_MANIFEST_FILENAME = "prepared-machine-ir-manifest.json"
X87_MICRO_OP_FORMAT = "stage-a-x87-micro-op-v1"
INDIRECT_TARGET_PROFILE_FORMAT = "stage-a-indirect-target-profile-v1"
DECODED_CONTROL_RECONCILIATION_FORMAT = (
    "stage-a-decoded-control-reconciliation-v1"
)

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
    recovered_executable_data: Path
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
    manifest["authority_bindings"] = build_machine_ir_authority_bindings(
        prepared,
        pe_sha256=binary.sha256,
    )
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
    callable_external_profiles: Sequence[Path] = (),
    internal_function_contract_profiles: Sequence[Path] = (),
    prepared_machine_ir: Path | None = None,
    interprocedural_control: bool = False,
) -> MachineIRPackage:
    """Validate and export a deterministic, byte-free PE32 machine IR package.

    The historical profile arguments remain accepted so older callers can read
    v1 diagnostics.  They cannot affect this exact extraction artifact; v2
    interprocedural, external-site, and candidate-authority phases consume them
    after extraction.
    """

    _ = interprocedural_control

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
    diagnostic_profile_paths = {
        "machine_import_profiles": tuple(
            _regular_file(path, "machine import profile")
            for path in machine_import_profiles
        ),
        "external_interface_profiles": tuple(
            _regular_file(path, "external interface profile")
            for path in external_interface_profiles
        ),
        "external_operation_profiles": tuple(
            _regular_file(path, "external operation profile")
            for path in external_operation_profiles
        ),
        "callable_external_profiles": tuple(
            _regular_file(path, "callable external profile")
            for path in callable_external_profiles
        ),
        "internal_function_contract_profiles": tuple(
            _regular_file(path, "internal function contract profile")
            for path in internal_function_contract_profiles
        ),
    }
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
    prepared_input_units = len(prepared)
    (
        prepared,
        executable_classification,
        classification_issues,
        preclassified_static_recoveries,
    ) = (
        _classify_executable_data_before_control(
            binary=binary,
            units=prepared,
            reference=reference,
        )
    )
    issues = _unit_issues(prepared)
    issues.extend(classification_issues)
    classified_noncode_ranges = [
        RvaSpan(int(row["rva_start"]), int(row["rva_end"]))
        for row in executable_classification["immutable_data_ranges"]
    ]
    coverage, coverage_issues = _coverage_inventory(
        binary,
        prepared,
        [*reference.get("noncode_ranges", []), *classified_noncode_ranges],
    )
    issues.extend(coverage_issues)
    control, control_issues = _control_inventory(
        binary,
        prepared,
        reference,
        executable_classification=executable_classification,
        preclassified_static_recoveries=preclassified_static_recoveries,
        target_profile=target_profile,
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
    machine_ir_sha256 = sha256_bytes(jsonl_bytes)
    executable_data = build_recovered_executable_data_contract(
        binary=binary,
        control=control,
        source_map=source_map,
        machine_ir_sha256=machine_ir_sha256,
    )
    executable_data_payload = executable_data.to_payload()
    executable_data_bytes = _canonical_json(executable_data_payload) + b"\n"
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
                    "id": (
                        target_profile["id"]
                        if target_profile is not None
                        else None
                    ),
                }
            ),
            **{
                name: [
                    {
                        "path": path.name,
                        "sha256": sha256_file(path),
                        "authority": "diagnostic_only",
                    }
                    for path in paths
                ]
                for name, paths in diagnostic_profile_paths.items()
            },
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
                "sha256": machine_ir_sha256,
                "format": MACHINE_IR_FORMAT,
            },
            "recovered_executable_data": {
                "path": RECOVERED_EXECUTABLE_DATA_FILENAME,
                "sha256": sha256_bytes(executable_data_bytes),
                "format": RECOVERED_EXECUTABLE_DATA_FORMAT,
                "contract_sha256": executable_data_payload["hashes"][
                    "contract_sha256"
                ],
                "ranges": len(executable_data.ranges),
                "data_size": sum(item.size for item in executable_data.ranges),
            },
        },
        "coverage": coverage,
        "control": control,
        "trust_assumptions": (
            []
            if target_profile is None
            else [
                {
                    **copy.deepcopy(target_profile["assumption"]),
                    "authority": "diagnostic_only",
                }
            ]
        ),
        "external": external,
        "reference_inventory": reference["public"],
        "source_map": source_map,
        "issues": issue_payloads,
        "counts": {
            "units": len(prepared),
            "prepared_input_units": prepared_input_units,
            "prepared_units_reused": reused_units,
            "prepared_units_computed": prepared_input_units - reused_units,
            "precontrol_excluded_units": executable_classification["counts"][
                "excluded_units"
            ],
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
    manifest["authority_bindings"] = build_machine_ir_authority_bindings(
        prepared,
        pe_sha256=binary.sha256,
    )
    _assert_byte_free(manifest)

    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)
    machine_path = out_path / MACHINE_IR_FILENAME
    manifest_path = out_path / MACHINE_IR_MANIFEST_FILENAME
    executable_data_path = out_path / RECOVERED_EXECUTABLE_DATA_FILENAME
    machine_path.write_bytes(jsonl_bytes)
    executable_data_path.write_bytes(executable_data_bytes)
    write_json(manifest_path, manifest)
    return MachineIRPackage(
        manifest=manifest_path.resolve(),
        machine_ir=machine_path.resolve(),
        recovered_executable_data=executable_data_path.resolve(),
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
            and cached.get("preparation", {}).get(
                "decoded_control_reconciliation"
            )
            == DECODED_CONTROL_RECONCILIATION_FORMAT
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
    decoded_control_reconciliation = _decoded_control_reconciliation(
        binary=binary,
        instructions=instructions,
        span=span,
        outcome=semantics["outcome"],
        direct_targets=control_targets,
        external_events=semantics["external_events"],
        ordered_events=semantics["ordered_events"],
        control_disposition=control_disposition,
    )
    _bind_checked_call_event_sites(
        semantics["external_events"], decoded_control_reconciliation
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
            "decoded_control_reconciliation": (
                DECODED_CONTROL_RECONCILIATION_FORMAT
            ),
        },
        "id": identity,
        "unit_kind": row.get("unit_kind", "semantic_transfer"),
        "status": (
            "qualified"
            if (
                _semantic_unit_qualified(row, x87_micro_ops)
                and decoded_control_reconciliation["status"] == "complete"
            )
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
            "decoded_reconciliation": decoded_control_reconciliation,
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


def _bind_checked_call_event_sites(
    external_events: Any,
    decoded_control_reconciliation: Mapping[str, Any],
) -> None:
    """Copy independently checked decode sites into canonical call events."""

    semantic_events = _semantic_call_events(external_events)
    decoded_sites = decoded_control_reconciliation.get("decoded_call_sites")
    if (
        decoded_control_reconciliation.get("status") != "complete"
        or not isinstance(decoded_sites, list)
        or len(decoded_sites) != len(semantic_events)
    ):
        return
    for event, decoded in zip(semantic_events, decoded_sites, strict=True):
        if not isinstance(event, dict) or not isinstance(decoded, Mapping):
            return
        instruction_rva = decoded.get("instruction_rva")
        if not isinstance(instruction_rva, int) or isinstance(
            instruction_rva, bool
        ):
            return
        event["instruction_rva"] = instruction_rva


def _decoded_control_reconciliation(
    *,
    binary: StageABinary,
    instructions: Sequence[_Instruction],
    span: RvaSpan,
    outcome: Any,
    direct_targets: Sequence[int],
    external_events: Any,
    ordered_events: Any,
    control_disposition: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Reconcile semantic control against an independent exact x86 decode."""

    checks: list[dict[str, Any]] = []

    def record(
        code: str,
        status: str,
        message: str,
        *,
        expected: Any = None,
        actual: Any = None,
    ) -> None:
        item: dict[str, Any] = {
            "code": code,
            "status": status,
            "message": message,
        }
        if expected is not None:
            item["expected"] = copy.deepcopy(expected)
        if actual is not None:
            item["actual"] = copy.deepcopy(actual)
        checks.append(item)

    terminal = instructions[-1]
    terminal_effect = _decoded_control_effect(binary, terminal)
    decoded_call_sites = [
        effect
        for instruction in instructions
        for effect in [_decoded_control_effect(binary, instruction)]
        if effect["class"]
        in {"direct_call", "indirect_call", "external_call", "external_jump"}
    ]
    semantic_outcome_kind = (
        str(outcome.get("kind")) if isinstance(outcome, Mapping) else None
    )
    expected_outcome_kinds = _decoded_expected_outcome_kinds(terminal_effect)

    if expected_outcome_kinds is None:
        record(
            "terminal_outcome_class_unresolved",
            "incomplete",
            "the decoded terminal control class has no exact aggregate semantic representation",
            actual=semantic_outcome_kind,
        )
    elif semantic_outcome_kind == "unknown":
        record(
            "terminal_outcome_unknown",
            "incomplete",
            "the aggregate semantic outcome is unknown",
            expected=sorted(expected_outcome_kinds),
            actual=semantic_outcome_kind,
        )
    elif semantic_outcome_kind == "fault" and terminal_effect["class"] == "fallthrough":
        record(
            "terminal_fault_not_decodable_as_control",
            "incomplete",
            "exact decoding alone cannot establish the declared terminal fault",
            expected="independently checked fault behavior",
            actual=semantic_outcome_kind,
        )
    elif semantic_outcome_kind not in expected_outcome_kinds:
        record(
            "terminal_outcome_class_mismatch",
            "violated",
            "the decoded terminal instruction disagrees with the aggregate semantic outcome",
            expected=sorted(expected_outcome_kinds),
            actual=semantic_outcome_kind,
        )
    else:
        record(
            "terminal_outcome_class",
            "complete",
            "the decoded terminal instruction agrees with the aggregate semantic outcome",
            expected=sorted(expected_outcome_kinds),
            actual=semantic_outcome_kind,
        )

    expected_targets = _decoded_expected_direct_targets(
        terminal_effect,
        span=span,
        terminating=control_disposition is not None,
    )
    if semantic_outcome_kind == "fault" and terminal_effect["class"] == "fallthrough":
        expected_targets = []
    actual_targets = [int(target) for target in direct_targets]
    if expected_targets is None:
        record(
            "direct_targets_unresolved",
            "incomplete",
            "the decoded terminal target cannot be reduced to exact PE RVAs",
            actual=actual_targets,
        )
    elif actual_targets != expected_targets:
        record(
            "direct_targets_mismatch",
            "violated",
            "decoded control targets disagree with the aggregate direct-target inventory",
            expected=expected_targets,
            actual=actual_targets,
        )
    else:
        record(
            "direct_targets",
            "complete",
            "decoded control targets agree with the aggregate direct-target inventory",
            expected=expected_targets,
            actual=actual_targets,
        )

    decoded_return_class = terminal_effect.get("return_class")
    if decoded_return_class == "interrupt_return":
        record(
            "return_class_unrepresented",
            "incomplete",
            "the aggregate semantic schema does not represent interrupt-return state restoration",
            expected=decoded_return_class,
            actual=semantic_outcome_kind,
        )
    elif decoded_return_class == "far_return":
        record(
            "return_class_unrepresented",
            "incomplete",
            "the aggregate semantic schema does not distinguish far returns",
            expected=decoded_return_class,
            actual=semantic_outcome_kind,
        )
    elif decoded_return_class == "near_return" and semantic_outcome_kind != "return":
        record(
            "return_class_mismatch",
            "violated",
            "a decoded near return is not declared as an aggregate return",
            expected="return",
            actual=semantic_outcome_kind,
        )
    elif decoded_return_class is None and semantic_outcome_kind == "return":
        record(
            "return_class_mismatch",
            "violated",
            "an aggregate return is not backed by a decoded return instruction",
            expected="decoded return",
            actual=terminal_effect["class"],
        )
    else:
        record(
            "return_class",
            "complete",
            "the decoded return class agrees with the aggregate semantic outcome",
            expected=decoded_return_class or "not_return",
            actual="return" if semantic_outcome_kind == "return" else "not_return",
        )

    if control_disposition is not None:
        terminal_call_site = decoded_call_sites[-1] if decoded_call_sites else None
        if (
            terminal_effect["class"] not in {"external_call", "external_jump"}
            or terminal_call_site is None
            or terminal_call_site["instruction_rva"] != terminal.rva
        ):
            record(
                "terminating_disposition_site_mismatch",
                "violated",
                "the terminating external disposition is not backed by the decoded terminal transfer",
                expected="terminal PE import call or jump",
                actual=terminal_effect["class"],
            )
        else:
            record(
                "terminating_disposition_site",
                "complete",
                "the terminating external disposition is bound to the decoded terminal transfer",
                expected=terminal.rva,
                actual=terminal_call_site["instruction_rva"],
            )

    _reconcile_decoded_call_events(
        decoded_call_sites,
        external_events=external_events,
        ordered_events=ordered_events,
        record=record,
    )

    status = (
        "violated"
        if any(check["status"] == "violated" for check in checks)
        else (
            "incomplete"
            if any(check["status"] == "incomplete" for check in checks)
            else "complete"
        )
    )
    return {
        "format": DECODED_CONTROL_RECONCILIATION_FORMAT,
        "status": status,
        "authority": "independent_static_x86_pe32_decode",
        "proof_authority": False,
        "decoder": "capstone",
        "terminal_instruction": {
            "rva": terminal.rva,
            "rva_end": terminal.end,
            "instruction_sha256": terminal.digest,
            "mnemonic": terminal.mnemonic,
            "decoded_class": terminal_effect["class"],
            "return_class": decoded_return_class,
        },
        "decoded_call_sites": decoded_call_sites,
        "semantic": {
            "outcome_kind": semantic_outcome_kind,
            "direct_targets": actual_targets,
            "call_event_count": len(
                _semantic_call_events(external_events)
            ),
            "terminating_external_disposition": control_disposition is not None,
        },
        "checks": checks,
    }


def _decoded_control_effect(
    binary: StageABinary, instruction: _Instruction
) -> dict[str, Any]:
    groups = frozenset(instruction.groups)
    mnemonic = instruction.mnemonic.lower()
    operand = instruction.operands[0] if instruction.operands else None
    direct_target = _decoded_immediate_target_rva(binary, operand)
    imported = _decoded_import_identity(binary, instruction, direct_target)
    result: dict[str, Any] = {
        "instruction_rva": instruction.rva,
        "return_rva": instruction.end,
        "mnemonic": mnemonic,
        "class": "fallthrough",
    }

    if "call" in groups:
        if imported is not None:
            result["class"] = "external_call"
            result["import"] = imported
        elif operand is not None and operand.get("kind") == "immediate":
            result["class"] = "direct_call"
            result["target_rva"] = direct_target
        else:
            result["class"] = "indirect_call"
            result["target"] = copy.deepcopy(operand)
        return result
    if "iret" in groups:
        result["class"] = "interrupt_return"
        result["return_class"] = "interrupt_return"
        return result
    if "ret" in groups:
        result["class"] = "return"
        result["return_class"] = (
            "far_return" if mnemonic in {"retf", "lret"} else "near_return"
        )
        return result
    if "jump" in groups or "branch_relative" in groups:
        if imported is not None and mnemonic in {"jmp", "ljmp"}:
            result["class"] = "external_jump"
            result["import"] = imported
        elif mnemonic in {"jmp", "ljmp"}:
            result["class"] = (
                "direct_jump" if direct_target is not None else "indirect_jump"
            )
        else:
            result["class"] = (
                "direct_branch" if direct_target is not None else "indirect_branch"
            )
        if direct_target is not None:
            result["target_rva"] = direct_target
        elif operand is not None:
            result["target"] = copy.deepcopy(operand)
        return result
    if "int" in groups or mnemonic in _NON_FALLTHROUGH_MNEMONICS:
        result["class"] = "terminal_system"
    return result


def _decoded_immediate_target_rva(
    binary: StageABinary, operand: Mapping[str, Any] | None
) -> int | None:
    if operand is None or operand.get("kind") != "immediate":
        return None
    value = operand.get("value")
    if not isinstance(value, int) or isinstance(value, bool):
        return None
    return (value - binary.image_base) & 0xFFFFFFFF


def _decoded_import_identity(
    binary: StageABinary,
    instruction: _Instruction,
    direct_target_rva: int | None,
) -> dict[str, Any] | None:
    if not instruction.operands:
        return None
    operand = instruction.operands[0]
    thunk_rva = _decoded_absolute_memory_rva(binary, operand)
    if thunk_rva is None and direct_target_rva is not None:
        thunk_rva = _decoded_direct_import_thunk_rva(binary, direct_target_rva)
    if thunk_rva is None:
        return None
    imported = next(
        (item for item in binary.imports if item.thunk_rva == thunk_rva),
        None,
    )
    if imported is None:
        return None
    return {
        "dll": imported.dll,
        "symbol": imported.symbol,
        "ordinal": imported.ordinal,
        "thunk_rva": imported.thunk_rva,
    }


def _decoded_absolute_memory_rva(
    binary: StageABinary, operand: Mapping[str, Any]
) -> int | None:
    if (
        operand.get("kind") != "memory"
        or operand.get("base") is not None
        or operand.get("index") is not None
    ):
        return None
    displacement = operand.get("displacement")
    if not isinstance(displacement, int) or isinstance(displacement, bool):
        return None
    address = displacement & 0xFFFFFFFF
    if binary.image_base <= address < binary.image_base + binary.size_of_image:
        return address - binary.image_base
    if 0 <= address < binary.size_of_image:
        return address
    return None


def _decoded_direct_import_thunk_rva(
    binary: StageABinary, target_rva: int
) -> int | None:
    if not any(
        section.executable and section.rva_start <= target_rva < section.rva_end
        for section in binary.sections
    ):
        return None
    encoded = bytes(binary.pe.get_data(target_rva, 15))
    if not encoded:
        return None
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    decoded = next(
        iter(decoder.disasm(encoded, binary.image_base + target_rva, count=1)),
        None,
    )
    if decoded is None or not decoded.group(capstone.CS_GRP_JUMP):
        return None
    projection = _instruction_projection(
        decoded, target_rva, bytes(decoded.bytes)
    )
    if not projection.operands:
        return None
    return _decoded_absolute_memory_rva(binary, projection.operands[0])


def _decoded_expected_outcome_kinds(
    terminal_effect: Mapping[str, Any],
) -> frozenset[str] | None:
    effect_class = terminal_effect.get("class")
    if effect_class in {"fallthrough", "direct_call", "indirect_call", "external_call"}:
        return frozenset({"fallthrough"})
    if effect_class == "direct_jump":
        return frozenset({"jump"})
    if effect_class == "direct_branch":
        return frozenset({"branch"})
    if effect_class in {"indirect_jump", "indirect_branch"}:
        return frozenset({"indirect_jump", "indirect_jump_table"})
    if effect_class == "external_jump":
        return frozenset({"external_jump"})
    if effect_class == "return":
        return frozenset({"return"})
    return None


def _decoded_expected_direct_targets(
    terminal_effect: Mapping[str, Any],
    *,
    span: RvaSpan,
    terminating: bool,
) -> list[int] | None:
    effect_class = terminal_effect.get("class")
    if terminating:
        return []
    if effect_class in {"fallthrough", "direct_call", "indirect_call", "external_call"}:
        return [span.end]
    if effect_class == "direct_jump":
        target = terminal_effect.get("target_rva")
        return [int(target)] if isinstance(target, int) else None
    if effect_class == "direct_branch":
        target = terminal_effect.get("target_rva")
        return [int(target), span.end] if isinstance(target, int) else None
    if effect_class in {
        "indirect_jump",
        "indirect_branch",
        "external_jump",
        "return",
        "interrupt_return",
        "terminal_system",
    }:
        return []
    return None


def _semantic_call_events(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [
        event
        for event in value
        if isinstance(event, Mapping)
        and event.get("kind") in {"external_call", "internal_call", "indirect_call"}
    ]


def _reconcile_decoded_call_events(
    decoded_sites: Sequence[Mapping[str, Any]],
    *,
    external_events: Any,
    ordered_events: Any,
    record: Any,
) -> None:
    semantic_events = _semantic_call_events(external_events)
    ordered = [
        event
        for event in _semantic_call_events(ordered_events)
        if event.get("family") in {None, "external"}
    ]
    if len(decoded_sites) != len(semantic_events):
        record(
            "call_event_count_mismatch",
            "violated",
            "decoded call transfers disagree with the aggregate external-event inventory",
            expected=len(decoded_sites),
            actual=len(semantic_events),
        )
    else:
        record(
            "call_event_count",
            "complete",
            "decoded call transfers agree with the aggregate external-event count",
            expected=len(decoded_sites),
            actual=len(semantic_events),
        )
    if ordered and len(ordered) != len(semantic_events):
        record(
            "ordered_call_event_count_mismatch",
            "violated",
            "ordered call events disagree with the aggregate external-event inventory",
            expected=len(semantic_events),
            actual=len(ordered),
        )

    for index, (decoded, event) in enumerate(
        zip(decoded_sites, semantic_events, strict=False)
    ):
        ordered_event = ordered[index] if index < len(ordered) else None
        instruction_rva = event.get("instruction_rva")
        if instruction_rva is None and ordered_event is not None:
            instruction_rva = ordered_event.get("instruction_rva")
        if instruction_rva is None:
            record(
                f"call_event_{index}_site_missing",
                "incomplete",
                "the semantic call event is not bound to an instruction RVA",
                expected=decoded["instruction_rva"],
            )
        elif instruction_rva != decoded["instruction_rva"]:
            record(
                f"call_event_{index}_site_mismatch",
                "violated",
                "the semantic call event is bound to a different decoded instruction",
                expected=decoded["instruction_rva"],
                actual=instruction_rva,
            )
        if (
            ordered_event is not None
            and ordered_event.get("instruction_rva") != decoded["instruction_rva"]
        ):
            record(
                f"call_event_{index}_ordered_site_mismatch",
                "violated",
                "the ordered call event is bound to a different decoded instruction",
                expected=decoded["instruction_rva"],
                actual=ordered_event.get("instruction_rva"),
            )

        expected_kind = {
            "direct_call": "internal_call",
            "indirect_call": "indirect_call",
            "external_call": "external_call",
            "external_jump": "external_call",
        }[str(decoded["class"])]
        if event.get("kind") != expected_kind:
            record(
                f"call_event_{index}_kind_mismatch",
                "violated",
                "the semantic call event class disagrees with the decoded transfer",
                expected=expected_kind,
                actual=event.get("kind"),
            )

        return_rva = event.get("return_rva")
        if return_rva is None:
            record(
                f"call_event_{index}_return_missing",
                "incomplete",
                "the semantic call event omits its decoded return RVA",
                expected=decoded["return_rva"],
            )
        elif return_rva != decoded["return_rva"]:
            record(
                f"call_event_{index}_return_mismatch",
                "violated",
                "the semantic call event return RVA disagrees with the decoded call",
                expected=decoded["return_rva"],
                actual=return_rva,
            )

        target_rva = decoded.get("target_rva")
        if decoded["class"] == "direct_call" and event.get("target_rva") != target_rva:
            record(
                f"call_event_{index}_target_mismatch",
                "violated",
                "the semantic internal-call target disagrees with the decoded target",
                expected=target_rva,
                actual=event.get("target_rva"),
            )
        imported = decoded.get("import")
        if isinstance(imported, Mapping):
            actual_import = {
                "dll": event.get("dll"),
                "symbol": event.get("symbol"),
                "ordinal": event.get("ordinal"),
            }
            expected_import = {
                "dll": imported.get("dll"),
                "symbol": imported.get("symbol"),
                "ordinal": imported.get("ordinal"),
            }
            if (
                not isinstance(actual_import["dll"], str)
                or str(actual_import["dll"]).lower()
                != str(expected_import["dll"]).lower()
                or actual_import["symbol"] != expected_import["symbol"]
                or actual_import["ordinal"] != expected_import["ordinal"]
            ):
                record(
                    f"call_event_{index}_import_mismatch",
                    "violated",
                    "the semantic external call identity disagrees with the PE import transfer",
                    expected=expected_import,
                    actual=actual_import,
                )

        if ordered_event is not None:
            compared_fields = (
                "kind",
                "dll",
                "symbol",
                "ordinal",
                "target_rva",
                "return_rva",
            )
            aggregate_projection = {
                field: event.get(field) for field in compared_fields
            }
            ordered_projection = {
                field: ordered_event.get(field) for field in compared_fields
            }
            if aggregate_projection != ordered_projection:
                record(
                    f"call_event_{index}_ordered_mismatch",
                    "violated",
                    "the ordered call event disagrees with the aggregate event",
                    expected=aggregate_projection,
                    actual=ordered_projection,
                )


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
    source_schedule_digest = _verified_embedded_digest(
        value,
        "schedule_sha256",
        f"{identity}: source instruction effect schedule",
    )
    result: dict[str, Any] = {}
    for key, item in value.items():
        if key in _RAW_INSTRUCTION_FIELDS or key == "schedule_sha256":
            continue
        if key == "records":
            if not isinstance(item, list):
                raise MachineIRExportError(f"{identity}: schedule records must be a list")
            result[key] = [
                _sanitize_schedule_record(record, identity, index)
                for index, record in enumerate(item)
            ]
        elif key == "blockers":
            if not isinstance(item, list):
                raise MachineIRExportError(f"{identity}: schedule blockers must be a list")
            result[key] = [_sanitize_metadata(record, identity) for record in item]
        else:
            result[key] = _sanitize_metadata(item, identity)
    existing_source_digest = result.get("source_schedule_sha256")
    if existing_source_digest is not None and existing_source_digest != source_schedule_digest:
        raise MachineIRExportError(
            f"{identity}: source instruction effect schedule digest is ambiguous"
        )
    result["source_schedule_sha256"] = source_schedule_digest
    result["schedule_sha256"] = sha256_bytes(_canonical_json(result))
    return result


def _sanitize_schedule_record(
    value: Any, identity: str, index: int
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise MachineIRExportError(f"{identity}: schedule record {index} must be an object")
    source_record_digest = _verified_embedded_digest(
        value,
        "record_sha256",
        f"{identity}: source schedule record {index}",
    )
    sanitized = _sanitize_metadata(value, identity)
    if not isinstance(sanitized, dict):
        raise AssertionError("mapping metadata sanitization did not produce an object")
    sanitized.pop("record_sha256", None)
    existing_source_digest = sanitized.get("source_record_sha256")
    if existing_source_digest is not None and existing_source_digest != source_record_digest:
        raise MachineIRExportError(
            f"{identity}: source schedule record {index} digest is ambiguous"
        )
    sanitized["source_record_sha256"] = source_record_digest
    sanitized["record_sha256"] = sha256_bytes(_canonical_json(sanitized))
    return sanitized


def _verified_embedded_digest(
    value: Mapping[str, Any], field: str, label: str
) -> str:
    expected = _digest(value.get(field), f"{label} digest")
    body = dict(value)
    del body[field]
    if sha256_bytes(_canonical_json(body)) != expected:
        raise MachineIRExportError(f"{label} digest does not match its contents")
    return expected


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
        reconciliation = unit.get("control", {}).get("decoded_reconciliation")
        reconciliation_status = (
            reconciliation.get("status")
            if isinstance(reconciliation, Mapping)
            else "incomplete"
        )
        if reconciliation_status != "complete":
            issues.append(
                ExportIssue(
                    status=(
                        "violated"
                        if reconciliation_status == "violated"
                        else "incomplete"
                    ),
                    category="decoded_control_reconciliation",
                    message=(
                        "exact decoded x86 control does not reconcile with the "
                        "aggregate semantic control contract"
                        if reconciliation_status == "violated"
                        else "exact decoded x86 control reconciliation is incomplete"
                    ),
                    next_action=(
                        "regenerate the semantic transfer from the exact PE bytes "
                        "and reconcile its outcome, targets, call events, and return class"
                    ),
                    location=_location_from_unit(
                        unit, "control.decoded_reconciliation"
                    ),
                )
            )
        source_status = unit["source_status"]
        if unit["status"] == "qualified" or _semantic_unit_qualified(
            source_status, unit.get("x87_micro_ops", [])
        ):
            continue
        location = _location_from_unit(unit, "source_status")
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


def _exact_only_control_inventory(
    *,
    binary: StageABinary,
    units: Sequence[dict[str, Any]],
    roots: Sequence[Mapping[str, Any]],
    direct: Sequence[Mapping[str, Any]],
    indirect: Sequence[dict[str, Any]],
    direct_control_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    static_recoveries: Sequence[Mapping[str, Any]],
    executable_classification: Mapping[str, Any],
    callback_root_proposals: Sequence[Mapping[str, Any]],
    checked_targets: Sequence[Any],
    static_rounds: int,
    static_converged: bool,
    target_profile: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[ExportIssue]]:
    """Emit exact units/direct control without running superseded provenance."""

    starts = {
        int(unit["source"]["original"]["rva_start"]): unit for unit in units
    }
    root_unit_ids = [
        str(starts[rva]["id"])
        for root in roots
        for rva in (root.get("rva"),)
        if isinstance(rva, int) and rva in starts
    ]
    issues: list[ExportIssue] = []
    recovered: list[dict[str, Any]] = []
    for exit_record, raw_recovery in zip(
        indirect, static_recoveries, strict=True
    ):
        recovery = copy.deepcopy(dict(raw_recovery))
        complete = (
            recovery.get("status") == "recovered"
            and _indirect_recovery_unit_binding_complete(recovery, starts)
        )
        if complete:
            exit_record["closure"] = "checked_static_target_inventory"
            exit_record["target_rvas"] = list(recovery.get("target_rvas", ()))
            exit_record["target_unit_ids"] = list(
                recovery.get("target_unit_ids", ())
            )
            exit_record["external_targets"] = []
        else:
            exit_record["closure"] = (
                "explicit_trusted_target_profile_without_inventory"
                if target_profile is not None
                else "awaiting_interprocedural_v2"
            )
            failure = recovery.get("failure")
            failure = (
                failure
                if isinstance(failure, Mapping)
                else {"code": "static_target_recovery_incomplete"}
            )
            exit_record["recovery_failure"] = copy.deepcopy(dict(failure))
            source = next(
                unit for unit in units
                if str(unit["id"]) == str(exit_record["source_unit_id"])
            )
            issues.append(ExportIssue(
                status="incomplete",
                category="interprocedural_target_certificate_deferred",
                message=(
                    "indirect target awaits the v2 SCC analysis: "
                    + _recovery_failure_message(failure)
                ),
                next_action=(
                    "run the dependency-aware v2 interprocedural phase; "
                    "machine-IR extraction does not authorize target recovery"
                ),
                location=_location_from_unit(source, "control.indirect_target"),
            ))
        recovered.append(recovery)
    reachability = derive_rooted_reachable_units(
        units=units,
        roots=root_unit_ids,
        direct_edges=direct_control_edges,
        internal_call_edges=internal_call_edges,
        recovered_indirect_targets=recovered,
        indirect_exits=indirect,
    )
    exact_reachable = set(reachability["reachable_units"])
    potentially_reachable = (
        set(str(unit["id"]) for unit in units)
        if reachability["status"] != "complete"
        else exact_reachable
    )
    for unit in units:
        unit_id = str(unit["id"])
        unit["reachable"] = unit_id in exact_reachable
        unit["reachability"] = (
            "reachable"
            if unit_id in exact_reachable
            else "potential" if unit_id in potentially_reachable else "unreachable"
        )
    potential = sorted(potentially_reachable - exact_reachable)
    reachability["potential_units"] = potential
    reachability["confirmed_unreachable_units"] = (
        sorted(set(str(unit["id"]) for unit in units) - exact_reachable)
        if reachability["status"] == "complete"
        else []
    )
    reachability["counts"].update({
        "potential_units": len(potential),
        "confirmed_unreachable_units": len(
            reachability["confirmed_unreachable_units"]
        ),
    })
    call_summaries = {
        "status": "incomplete",
        "summaries": [],
        "reason": "owned_by_interprocedural_v2_phase",
    }
    for unit in units:
        if str(unit["id"]) not in exact_reachable:
            continue
        semantics = unit.get("semantics")
        outcome = semantics.get("outcome") if isinstance(semantics, Mapping) else None
        faults = semantics.get("faults") if isinstance(semantics, Mapping) else None
        if (
            isinstance(outcome, Mapping)
            and outcome.get("kind") == "fault"
            and isinstance(faults, list)
            and not faults
        ):
            issues.append(
                ExportIssue(
                    status="incomplete",
                    category="terminal_fault_missing_fault_record",
                    message=(
                        "an explicit terminal fault outcome has no exact fault "
                        "predicate or architectural fault class"
                    ),
                    next_action=(
                        "emit the instruction-bound fault record before treating "
                        "the outcome as checked exceptional termination"
                    ),
                    location=_location_from_unit(unit, "semantics.faults"),
                )
            )
    exceptional = _exceptional_control_inventory(
        units,
        root_rvas={
            int(root["rva"])
            for root in roots
            if isinstance(root.get("rva"), int)
        },
        indirect_exits=indirect,
        internal_call_preservation=call_summaries,
    )
    provenance = {
        "format": "stage-a-external-interface-provenance-v1",
        "status": "incomplete",
        "resolutions": [],
        "static_interface_slots": [],
        "rejected_tainted_slots": [],
        "callback_registrations": [],
        "issues": [{
            "code": "owned_by_interprocedural_v2_phase",
        }],
    }
    control = {
        "executable_classification": copy.deepcopy(
            dict(executable_classification)
        ),
        "roots": sorted(roots, key=_root_sort_key),
        "direct_targets": sorted(
            direct,
            key=lambda item: (item["source_rva"], item["target_rva"]),
        ),
        "indirect_exits": sorted(
            indirect,
            key=lambda item: (item["source_rva"], item["source_unit_id"]),
        ),
        "recovered_indirect_targets": sorted(
            recovered,
            key=lambda item: (item["source_rva"], item["source_unit_id"]),
        ),
        "value_provenance": {"status": "incomplete", "resolutions": []},
        "external_interface_provenance": provenance,
        "operation_provenance": {
            "format": "stage-a-operation-provenance-v2",
            "status": "incomplete",
            "resolutions": [],
            "callback_registrations": [],
            "issues": [{"code": "owned_by_interprocedural_v2_phase"}],
        },
        "internal_call_preservation": call_summaries,
        "exceptional_control": exceptional,
        "callback_cutpoint_proposals": list(callback_root_proposals),
        "analysis_fixed_point": {
            "format": "stage-a-interprocedural-analysis-v2",
            "status": "incomplete",
            "rounds": 0,
            "cold_replay_validated": False,
            "global_slot_promotion": False,
            "failure_reasons": ["owned_by_interprocedural_v2_phase"],
            "static_jump_table_rounds": static_rounds,
            "static_jump_table_converged": static_converged,
        },
        "reachability": reachability,
        "checked_jump_table_targets": list(checked_targets),
        "indirect_target_profile": (
            None
            if target_profile is None
            else {
                "id": target_profile["id"],
                "authority": "diagnostic_only",
            }
        ),
        "counts": {
            "roots": len(roots),
            "direct_targets": len(direct),
            "unresolved_direct_targets": sum(
                item["status"] != "resolved" for item in direct
            ),
            "indirect_exits": len(indirect),
            "closed_indirect_exits": sum(
                item["closure"] == "checked_static_target_inventory"
                for item in indirect
            ),
            "exact_reachable_units": len(exact_reachable),
            "potential_reachable_units": len(potential),
            "rooted_frontiers": len(reachability["frontiers"]),
            "exceptional_transitions": len(exceptional["transitions"]),
            "complete_exceptional_transitions": sum(
                transition["status"] == "complete"
                for transition in exceptional["transitions"]
            ),
            "checked_jump_table_targets": len(checked_targets),
            "callback_cutpoint_proposals": len(callback_root_proposals),
        },
    }
    return control, issues


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


def _classify_executable_data_before_control(
    *,
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    reference: Mapping[str, Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
    list[ExportIssue],
    list[dict[str, Any]],
]:
    """Remove checked executable data and false overlapping decodes first.

    Static extraction intentionally over-approximates possible unit starts.  A
    rooted control graph must not be built over rows that are already proven to
    be immutable jump-table data, nor over a speculative start in the interior
    of an instruction reached from a real root.  This prepass has no authority
    to discard a competing root or incoming edge: those conflicts fail closed.
    """

    starts = {
        int(unit["source"]["original"]["rva_start"]): unit for unit in units
    }
    block_starts = {
        str(unit["source_location"]["block_id"]): int(
            unit["source"]["original"]["rva_start"]
        )
        for unit in units
        if unit["source_location"].get("block_id")
    }
    root_rows = _initial_control_roots(binary, reference, block_starts)
    root_unit_ids = [
        str(starts[rva]["id"])
        for root in root_rows
        if isinstance((rva := root.get("rva")), int) and rva in starts
    ]
    direct_edges, internal_call_edges = _precontrol_direct_edges(units)
    indirect_exits = _precontrol_indirect_exits(units)
    static_recoveries, rounds, converged = _static_jump_table_recovery_fixed_point(
        binary=binary,
        units=units,
        starts=starts,
        indirect_exits=indirect_exits,
        root_unit_ids=root_unit_ids,
    )
    data_ranges = recover_executable_data_ranges(
        binary=binary,
        recoveries=static_recoveries,
        known_code_unit_rvas=set(starts),
    )
    data_spans = [RvaSpan(item.rva_start, item.rva_end) for item in data_ranges]
    issues: list[ExportIssue] = []
    conflicts: list[dict[str, Any]] = []

    if not converged:
        issues.append(
            ExportIssue(
                status="incomplete",
                category="precontrol_static_data_fixed_point_budget_exceeded",
                message="static executable-data recovery did not converge",
                next_action=(
                    "increase the generic fixed-point budget or reduce the "
                    "finite control domain"
                ),
                location=SourceLocation(
                    None,
                    None,
                    None,
                    RvaSpan(binary.entrypoint_rva, binary.entrypoint_rva + 1),
                    "executable_classification",
                ),
            )
        )

    excluded: dict[str, dict[str, Any]] = {}
    for unit in units:
        unit_span = _unit_original_span(unit)
        overlaps = [
            item
            for item in data_ranges
            if unit_span.start < item.rva_end and item.rva_start < unit_span.end
        ]
        if not overlaps:
            continue
        excluded[str(unit["id"])] = {
            "unit_id": str(unit["id"]),
            "rva_start": unit_span.start,
            "rva_end": unit_span.end,
            "reason": "intersects_checked_immutable_executable_data",
            "evidence_ids": [item.identity for item in overlaps],
        }

    excluded_ids = set(excluded)
    for root in root_rows:
        rva = root.get("rva")
        if isinstance(rva, int):
            match = _range_containing(data_ranges, rva)
            if match is not None:
                conflicts.append({
                    "code": "behavioral_root_inside_immutable_executable_data",
                    "rva": rva,
                    "evidence_id": match.identity,
                })
                issues.append(
                    _classification_conflict_issue(
                        category="behavioral_root_inside_immutable_executable_data",
                        message=(
                            f"behavioral root 0x{rva:x} lies inside checked "
                            "immutable executable data"
                        ),
                        rva=rva,
                        field="control.roots",
                    )
                )

    for edge in (*direct_edges, *internal_call_edges):
        source_id = str(edge.get("source_unit_id"))
        target = edge.get("target_rva")
        if source_id in excluded_ids or not isinstance(target, int):
            continue
        match = _range_containing(data_ranges, target)
        if match is None:
            continue
        conflicts.append({
            "code": "control_target_inside_immutable_executable_data",
            "source_unit_id": source_id,
            "target_rva": target,
            "evidence_id": match.identity,
        })
        issues.append(
            _classification_conflict_issue(
                category="control_target_inside_immutable_executable_data",
                message=(
                    f"control target 0x{target:x} lies inside checked immutable "
                    "executable data"
                ),
                rva=target,
                field="control.direct_target",
                unit_id=source_id,
            )
        )

    for recovery in static_recoveries:
        if str(recovery.get("source_unit_id")) in excluded_ids:
            continue
        for target in recovery.get("target_rvas", []):
            if not isinstance(target, int):
                continue
            match = _range_containing(data_ranges, target)
            if match is None:
                continue
            conflicts.append({
                "code": "recovered_target_inside_immutable_executable_data",
                "source_unit_id": recovery.get("source_unit_id"),
                "target_rva": target,
                "evidence_id": match.identity,
            })
            issues.append(
                _classification_conflict_issue(
                    category="recovered_target_inside_immutable_executable_data",
                    message=(
                        f"finite indirect target 0x{target:x} lies inside checked "
                        "immutable executable data"
                    ),
                    rva=target,
                    field="control.indirect_target",
                    unit_id=str(recovery.get("source_unit_id")),
                )
            )

    active = [unit for unit in units if str(unit["id"]) not in excluded_ids]
    active_ids = {str(unit["id"]) for unit in active}
    reachability = derive_rooted_reachable_units(
        units=active,
        roots=(unit_id for unit_id in root_unit_ids if unit_id in active_ids),
        direct_edges=[
            edge for edge in direct_edges if edge["source_unit_id"] in active_ids
        ],
        internal_call_edges=[
            edge
            for edge in internal_call_edges
            if edge["source_unit_id"] in active_ids
        ],
        recovered_indirect_targets=[
            recovery
            for recovery in static_recoveries
            if recovery.get("source_unit_id") in active_ids
        ],
        indirect_exits=[
            exit_record
            for exit_record in indirect_exits
            if exit_record.get("source_unit_id") in active_ids
        ],
    )
    reached_ids = set(reachability["reachable_units"])
    target_sources = _precontrol_target_sources(
        root_rows=root_rows,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        recoveries=static_recoveries,
        eligible_source_ids=reached_ids,
    )
    overlap_classification = classify_overlapping_instruction_starts(
        units=active,
        reachable_unit_ids=reached_ids,
        target_sources=target_sources,
    )
    active_by_id = {str(unit["id"]): unit for unit in active}
    for row in overlap_classification["excluded_units"]:
        unit_id = str(row["unit_id"])
        unit = active_by_id[unit_id]
        excluded[unit_id] = {
            "unit_id": unit_id,
            "rva_start": int(unit["source"]["original"]["rva_start"]),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "reason": row["reason"],
            "instruction_evidence": copy.deepcopy(row["instruction_evidence"]),
        }
    for row in overlap_classification["conflicts"]:
        conflicts.append(copy.deepcopy(row))
        start = int(row["rva"])
        issues.append(
            _classification_conflict_issue(
                category="independent_target_inside_reachable_instruction",
                message=(
                    f"unit start 0x{start:x} lies inside an instruction on "
                    "another rooted path"
                ),
                rva=start,
                field="executable_classification.instruction_interiors",
                unit_id=str(row["unit_id"]),
            )
        )

    retained = [
        copy.deepcopy(dict(unit))
        for unit in units
        if str(unit["id"]) not in excluded
    ]
    range_rows = [_classification_range_payload(item) for item in data_ranges]
    excluded_rows = sorted(
        excluded.values(), key=lambda row: (int(row["rva_start"]), str(row["unit_id"]))
    )
    conflicts = sorted(
        {
            _canonical_json(row): copy.deepcopy(row) for row in conflicts
        }.values(),
        key=lambda row: (
            int(row.get("rva", row.get("target_rva", -1))),
            str(row.get("code")),
            str(row.get("source_unit_id", row.get("unit_id", ""))),
        ),
    )
    status = (
        "violated"
        if conflicts
        else "incomplete"
        if not converged
        else "complete"
    )
    return retained, {
        "format": "stage-a-precontrol-executable-classification-v1",
        "status": status,
        "proof_authority": False,
        "ordering": "before_rooted_control_closure",
        "immutable_data_ranges": range_rows,
        "excluded_units": excluded_rows,
        "conflicts": conflicts,
        "analysis": {
            "static_jump_table_rounds": rounds,
            "static_jump_table_converged": converged,
            "preclassification_reachable_units": sorted(reached_ids),
        },
        "counts": {
            "input_units": len(units),
            "retained_units": len(retained),
            "excluded_units": len(excluded_rows),
            "immutable_data_ranges": len(range_rows),
            "immutable_data_bytes": sum(item.size for item in data_ranges),
            "conflicts": len(conflicts),
        },
    }, issues, static_recoveries


def _initial_control_roots(
    binary: StageABinary,
    reference: Mapping[str, Any],
    block_starts: Mapping[str, int],
) -> list[dict[str, Any]]:
    submitted = [
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
    for root in (*binary_roots, *submitted):
        raw_rva = root.get("rva", root.get("target_rva"))
        if not isinstance(raw_rva, int):
            continue
        canonical = roots_by_rva.setdefault(raw_rva, copy.deepcopy(dict(root)))
        for key, value in root.items():
            canonical.setdefault(key, copy.deepcopy(value))
    return list(roots_by_rva.values())


def _precontrol_direct_edges(
    units: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    direct: list[dict[str, Any]] = []
    internal: list[dict[str, Any]] = []
    for unit in units:
        source_id = str(unit["id"])
        source_rva = int(unit["source"]["original"]["rva_start"])
        for target in unit["control"]["direct_targets"]:
            direct.append({
                "kind": "direct_control",
                "source_unit_id": source_id,
                "source_rva": source_rva,
                "target_rva": int(target),
            })
        events = unit.get("semantics", {}).get("external_events", [])
        if not isinstance(events, list):
            continue
        for event_index, event in enumerate(events):
            if (
                isinstance(event, Mapping)
                and event.get("kind") == "internal_call"
                and isinstance(event.get("target_rva"), int)
            ):
                internal.append({
                    "kind": "internal_call",
                    "source_unit_id": source_id,
                    "source_rva": source_rva,
                    "source_event_index": event_index,
                    "target_rva": int(event["target_rva"]),
                })
    return direct, internal


def _precontrol_indirect_exits(
    units: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    exits: list[dict[str, Any]] = []
    for unit in units:
        source_id = str(unit["id"])
        source_rva = int(unit["source"]["original"]["rva_start"])
        if unit["control"]["has_indirect_target"]:
            row = {
                "source_unit_id": source_id,
                "source_rva": source_rva,
                "kind": unit["control"]["kind"],
                "target_expression": copy.deepcopy(
                    unit["semantics"]["outcome"].get("target")
                ),
            }
            row["id"] = indirect_exit_id_v2(row)
            exits.append(row)
        events = unit.get("semantics", {}).get("external_events", [])
        if not isinstance(events, list):
            continue
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping) or event.get("kind") not in {
                "indirect_call",
                "indirect_jump",
            }:
                continue
            row = {
                "source_unit_id": source_id,
                "source_rva": source_rva,
                "source_event_index": event_index,
                "kind": event["kind"],
                "target_expression": copy.deepcopy(event.get("target")),
            }
            row["id"] = indirect_exit_id_v2(row)
            exits.append(row)
    return exits


def _precontrol_target_sources(
    *,
    root_rows: Sequence[Mapping[str, Any]],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recoveries: Sequence[Mapping[str, Any]],
    eligible_source_ids: set[str],
) -> dict[int, list[str]]:
    result: dict[int, set[str]] = {}
    for root in root_rows:
        if isinstance(root.get("rva"), int):
            result.setdefault(int(root["rva"]), set()).add("behavioral_root")
    for edge in (*direct_edges, *internal_call_edges):
        if (
            edge.get("source_unit_id") in eligible_source_ids
            and isinstance(edge.get("target_rva"), int)
        ):
            result.setdefault(int(edge["target_rva"]), set()).add(
                str(edge.get("kind"))
            )
    for recovery in recoveries:
        if recovery.get("source_unit_id") not in eligible_source_ids:
            continue
        for target in recovery.get("target_rvas", []):
            if isinstance(target, int):
                result.setdefault(target, set()).add("finite_indirect_target")
    return {rva: sorted(sources) for rva, sources in result.items()}


def _unit_original_span(unit: Mapping[str, Any]) -> RvaSpan:
    source = unit["source"]["original"]
    return RvaSpan(int(source["rva_start"]), int(source["rva_end"]))


def _range_containing(ranges: Sequence[Any], rva: int) -> Any | None:
    return next(
        (item for item in ranges if item.rva_start <= rva < item.rva_end),
        None,
    )


def _classification_range_payload(item: Any) -> dict[str, Any]:
    return {
        "id": item.identity,
        "rva_start": item.rva_start,
        "rva_end": item.rva_end,
        "size": item.size,
        "section_index": item.section_index,
        "section_name": item.section_name,
        "bytes_sha256": item.bytes_sha256,
        "kinds": list(item.kinds),
        "recovery_ids": list(item.recovery_ids),
    }


def _classification_conflict_issue(
    *,
    category: str,
    message: str,
    rva: int,
    field: str,
    unit_id: str | None = None,
) -> ExportIssue:
    return ExportIssue(
        status="violated",
        category=category,
        message=message,
        next_action=(
            "repair static code/data classification or provide checked evidence "
            "for an intentional overlapping-code entry"
        ),
        location=SourceLocation(
            unit_id,
            None,
            None,
            RvaSpan(rva, rva + 1),
            field,
        ),
    )


def _control_inventory(
    binary: StageABinary,
    units: Sequence[dict[str, Any]],
    reference: Mapping[str, Any],
    *,
    executable_classification: Mapping[str, Any],
    preclassified_static_recoveries: Sequence[Mapping[str, Any]],
    target_profile: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[ExportIssue]]:
    starts = {int(unit["source"]["original"]["rva_start"]): unit for unit in units}
    block_starts = {
        str(unit["source_location"]["block_id"]): int(
            unit["source"]["original"]["rva_start"]
        )
        for unit in units
        if unit["source_location"].get("block_id")
    }
    initial_roots = _initial_control_roots(binary, reference, block_starts)
    roots_by_rva: dict[int, dict[str, Any]] = {}
    for root in initial_roots:
        raw_rva = root.get("rva", root.get("target_rva"))
        if not isinstance(raw_rva, int):
            continue
        canonical = roots_by_rva.setdefault(raw_rva, copy.deepcopy(dict(root)))
        for key, value in root.items():
            canonical.setdefault(key, copy.deepcopy(value))
    callback_root_proposals = _local_callback_cutpoint_proposals(binary, units)
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
            item["id"] = indirect_exit_id_v2(item)
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
                    item["id"] = indirect_exit_id_v2(item)
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
    if preclassified_static_recoveries:
        exact_static_recoveries = _rebind_preclassified_static_recoveries(
            indirect_exits=indirect,
            recoveries=preclassified_static_recoveries,
            starts=starts,
        )
        static_rounds = 0
        static_converged = True
    else:
        (
            exact_static_recoveries,
            static_rounds,
            static_converged,
        ) = _static_jump_table_recovery_fixed_point(
            binary=binary,
            units=units,
            starts=starts,
            indirect_exits=indirect,
            root_unit_ids=root_unit_ids,
        )
    return _exact_only_control_inventory(
        binary=binary,
        units=units,
        roots=roots,
        direct=direct,
        indirect=indirect,
        direct_control_edges=direct_control_edges,
        internal_call_edges=internal_call_edges,
        static_recoveries=exact_static_recoveries,
        executable_classification=executable_classification,
        callback_root_proposals=callback_root_proposals,
        checked_targets=checked_targets,
        static_rounds=static_rounds,
        static_converged=static_converged,
        target_profile=target_profile,
    )


def _exceptional_control_inventory(
    units: Sequence[Mapping[str, Any]],
    *,
    root_rvas: Iterable[int] = (),
    indirect_exits: Sequence[Mapping[str, Any]] = (),
    internal_call_preservation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project exact reachable fault sites into fail-closed control records.

    A symbolic fault predicate does not establish whether Windows SEH handles the
    fault.  A site can close locally only when the semantic outcome explicitly
    terminates in that fault or the explicit arithmetic predicate is proved false
    for every machine-IR input.  Every other site remains an unresolved frontier.
    """

    # v1 retains this projection for diagnostics only. Non-local fault
    # infeasibility is authoritative only through the v2 SCC invariant checker;
    # bounded predecessor enumeration cannot establish loop-wide behavior.
    del root_rvas, indirect_exits, internal_call_preservation
    transitions: list[dict[str, Any]] = []
    for unit in units:
        if unit.get("reachable") is not True:
            continue
        unit_id = str(unit["id"])
        source_rva = int(unit["source"]["original"]["rva_start"])
        source_contract_sha256 = str(unit["source"]["contract_sha256"])
        semantics = unit.get("semantics")
        if not isinstance(semantics, Mapping):
            continue
        faults = semantics.get("faults")
        if not isinstance(faults, list):
            continue
        outcome = semantics.get("outcome")
        for fault_index, raw_fault in enumerate(faults):
            if not isinstance(raw_fault, Mapping):
                continue
            fault = copy.deepcopy(dict(raw_fault))
            fault_sha256 = sha256_bytes(_canonical_json(fault))
            terminal_fault = _is_explicit_terminal_fault(unit, fault)
            outcome_sha256 = (
                sha256_bytes(_canonical_json(outcome)) if terminal_fault else None
            )
            infeasibility = (
                None
                if terminal_fault
                else _checked_fault_infeasibility(
                    unit=unit,
                    fault=fault,
                    fault_index=fault_index,
                    fault_sha256=fault_sha256,
                )
            )
            if (
                isinstance(infeasibility, Mapping)
                and infeasibility.get("status") != "complete"
            ):
                infeasibility = {
                    **dict(infeasibility),
                    "scc_invariant_requirement": {
                        "format": "stage-a-scc-exception-invariant-requirement-v2",
                        "status": "incomplete",
                        "source_unit_id": unit_id,
                        "source_fault_index": fault_index,
                        "fault_sha256": fault_sha256,
                        "reason": "checked_scc_invariant_certificate_required",
                    },
                }
            transition: dict[str, Any] = {
                "source_unit_id": unit_id,
                "source_fault_index": fault_index,
                "source_rva": source_rva,
                "instruction_rva": fault.get("instruction_rva"),
                "fault_kind": fault.get("kind"),
                "fault_sha256": fault_sha256,
            }
            if terminal_fault:
                certificate = {
                    "format": "stage-a-explicit-terminal-fault-certificate-v1",
                    "source_unit_id": unit_id,
                    "source_fault_index": fault_index,
                    "source_contract_sha256": source_contract_sha256,
                    "fault_sha256": fault_sha256,
                    "outcome_sha256": outcome_sha256,
                }
                transition.update(
                    {
                        "status": "complete",
                        "disposition": {
                            "kind": "termination",
                            "observable": True,
                            "evidence": {
                                "status": "checked",
                                "checker": (
                                    "stage-a-machine-ir-explicit-terminal-fault-v1"
                                ),
                                "certificate_sha256": sha256_bytes(
                                    _canonical_json(certificate)
                                ),
                                "certificate": certificate,
                            },
                        },
                    }
                )
            elif infeasibility is not None and infeasibility["status"] == "complete":
                transition.update(
                    {
                        "status": "complete",
                        "disposition": {
                            "kind": "infeasible",
                            "observable": False,
                            "evidence": infeasibility["evidence"],
                        },
                    }
                )
            else:
                feasibility = (
                    infeasibility.get("feasibility")
                    if isinstance(infeasibility, Mapping)
                    else None
                )
                analysis = (
                    infeasibility.get("analysis")
                    if isinstance(infeasibility, Mapping)
                    else None
                )
                scc_invariant_requirement = (
                    infeasibility.get("scc_invariant_requirement")
                    if isinstance(infeasibility, Mapping)
                    else None
                )
                abstract_possible = (
                    isinstance(analysis, Mapping)
                    and bool(analysis.get("stateful_leaf_abstractions"))
                    and isinstance(feasibility, Mapping)
                    and feasibility.get("status") == "violated"
                )
                reason = (
                    (
                        "fault predicate is satisfiable in the conservative "
                        "stateful-leaf over-approximation and has no checked "
                        "infeasibility or SEH target"
                    )
                    if abstract_possible
                    else "fault predicate is satisfiable and has no checked SEH target"
                    if isinstance(feasibility, Mapping)
                    and feasibility.get("status") == "violated"
                    else (
                        "fault predicate is outside the checked local "
                        "infeasibility fragment and has no terminal outcome or "
                        "SEH target"
                    )
                )
                transition.update(
                    {
                        "status": "incomplete",
                        "disposition": {
                            "kind": "unresolved",
                            "reason": reason,
                            "evidence": {
                                "status": (
                                    "checked_abstract_possible"
                                    if abstract_possible
                                    else "checked_possible"
                                    if isinstance(feasibility, Mapping)
                                    and feasibility.get("status") == "violated"
                                    else "unchecked"
                                ),
                                "checker": (
                                    "stage-a-machine-ir-exceptional-control-v1"
                                ),
                                **(
                                    {"feasibility": feasibility}
                                    if isinstance(feasibility, Mapping)
                                    else {}
                                ),
                                **(
                                    {"analysis": analysis}
                                    if isinstance(analysis, Mapping)
                                    else {}
                                ),
                                **(
                                    {
                                        "scc_invariant_requirement": (
                                            scc_invariant_requirement
                                        )
                                    }
                                    if isinstance(
                                        scc_invariant_requirement, Mapping
                                    )
                                    else {}
                                ),
                            },
                        },
                    }
                )
            transitions.append(transition)
    transitions.sort(
        key=lambda row: (
            int(row["source_rva"]),
            str(row["source_unit_id"]),
            int(row["source_fault_index"]),
        )
    )
    return {
        "format": "stage-a-exceptional-control-v1",
        "status": (
            "complete"
            if all(row["status"] == "complete" for row in transitions)
            else "incomplete"
        ),
        "transitions": transitions,
        "counts": {
            "transitions": len(transitions),
            "complete": sum(row["status"] == "complete" for row in transitions),
            "incomplete": sum(
                row["status"] == "incomplete" for row in transitions
            ),
        },
    }


_QF_BV_LOCALLY_DECIDABLE_FAULT_KINDS = frozenset({"divide_error"})
def _checked_fault_infeasibility(
    *,
    unit: Mapping[str, Any],
    fault: Mapping[str, Any],
    fault_index: int,
    fault_sha256: str,
) -> dict[str, Any] | None:
    """Prove an explicit, local arithmetic fault predicate is always false.

    The checker intentionally excludes segment-, page-, x87-, and
    platform-mediated fault classes.  Their absence cannot be established from
    a straight-line bitvector predicate alone.  Stateful bitvector leaves are
    over-approximated as independent inputs, so only an unsatisfiable predicate
    can close the transition.
    """

    fault_kind = fault.get("kind")
    condition = fault.get("condition")
    if (
        fault_kind not in _QF_BV_LOCALLY_DECIDABLE_FAULT_KINDS
        or not isinstance(condition, Mapping)
    ):
        return None

    abstract_condition, abstractions, input_widths = (
        _abstract_fault_predicate_stateful_leaves(condition)
    )
    result = check_straight_line_semantic_claim(
        {"fault_condition": abstract_condition},
        {
            "fault_condition": {
                "op": "const",
                "value": 0,
                "width": 32,
            }
        },
        input_widths=input_widths,
        solver_timeout_ms=2_000,
    )
    result_payload = result.to_payload()
    analysis = {
        "format": "stage-a-qf-bv-fault-predicate-analysis-v1",
        "fault_sha256": fault_sha256,
        "predicate_sha256": sha256_bytes(_canonical_json(condition)),
        "abstract_predicate_sha256": sha256_bytes(
            _canonical_json(abstract_condition)
        ),
        "stateful_leaf_abstractions": abstractions,
    }
    if result.status != "qualified":
        return {
            "status": "incomplete",
            "feasibility": result_payload,
            "analysis": analysis,
        }

    unit_id = str(unit["id"])
    source_contract_sha256 = str(unit["source"]["contract_sha256"])
    predicate_sha256 = sha256_bytes(_canonical_json(condition))
    certificate = {
        "format": "stage-a-qf-bv-fault-infeasibility-certificate-v1",
        "source_unit_id": unit_id,
        "source_fault_index": fault_index,
        "source_contract_sha256": source_contract_sha256,
        "fault_kind": fault_kind,
        "fault_sha256": fault_sha256,
        "predicate_sha256": predicate_sha256,
        "abstract_predicate_sha256": analysis["abstract_predicate_sha256"],
        "stateful_leaf_abstractions": abstractions,
        "claim": "fault_condition_is_zero_for_all_machine_ir_inputs",
        "checked_claims": list(result.checked_claims),
    }
    return {
        "status": "complete",
        "evidence": {
            "status": "checked",
            "checker": "stage-a-machine-ir-qf-bv-fault-infeasibility-v1",
            "trust_boundary": result.trust_boundary,
            "certificate_sha256": sha256_bytes(_canonical_json(certificate)),
            "certificate": certificate,
        },
    }


_FAULT_PREDICATE_ABSTRACT_LEAF_OPS = frozenset(
    {
        "call_flag",
        "call_response",
        "load",
        "undefined_bv",
        "undefined_flag",
    }
)


def _abstract_fault_predicate_stateful_leaves(
    condition: Mapping[str, Any],
    *,
    share_identical: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    """Over-approximate stateful bitvector leaves with independent inputs.

    Independence deliberately forgets load aliasing and external-state
    constraints.  Proving the fault predicate false in this larger state space
    is sound; a satisfying assignment is diagnostic only and never closes the
    transition.
    """

    abstractions: list[dict[str, Any]] = []
    input_widths: dict[str, int] = {}
    shared_names: dict[tuple[str, str, int], str] = {}

    def visit(value: Any) -> Any:
        if isinstance(value, list):
            return [visit(item) for item in value]
        if not isinstance(value, Mapping):
            return copy.deepcopy(value)
        op = value.get("op")
        if op in _FAULT_PREDICATE_ABSTRACT_LEAF_OPS:
            if op == "load":
                raw_width = value.get("width")
                width = (
                    int(raw_width) * 8
                    if isinstance(raw_width, int)
                    and not isinstance(raw_width, bool)
                    and raw_width in {1, 2, 4}
                    else 32
                )
            elif op in {"call_flag", "undefined_flag"}:
                width = 1
            else:
                raw_width = value.get("width", 32)
                width = (
                    int(raw_width)
                    if isinstance(raw_width, int)
                    and not isinstance(raw_width, bool)
                    and 1 <= int(raw_width) <= 32
                    else 32
                )
            source_sha256 = sha256_bytes(_canonical_json(value))
            shared_key = (str(op), source_sha256, width)
            name = shared_names.get(shared_key) if share_identical else None
            if name is None:
                name = f"fault_leaf_{len(abstractions):04d}"
                abstractions.append(
                    {
                        "name": name,
                        "source_op": op,
                        "source_sha256": source_sha256,
                        "width": width,
                        "relation": (
                            "identical_expression_shared_arbitrary_value_"
                            "overapproximation"
                            if share_identical
                            else "independent_arbitrary_value_overapproximation"
                        ),
                    }
                )
                if share_identical:
                    shared_names[shared_key] = name
            input_widths[name] = width
            return {"op": "reg", "name": name, "width": width}
        return {str(key): visit(item) for key, item in value.items()}

    return visit(condition), abstractions, input_widths


def _is_explicit_terminal_fault(
    unit: Mapping[str, Any], fault: Mapping[str, Any]
) -> bool:
    semantics = unit.get("semantics")
    outcome = semantics.get("outcome") if isinstance(semantics, Mapping) else None
    if not isinstance(outcome, Mapping) or outcome.get("kind") != "fault":
        return False
    fault_kind = fault.get("kind")
    if not isinstance(fault_kind, str) or not fault_kind or fault_kind == "unknown":
        return False
    declared_kind = outcome.get("fault_kind")
    if declared_kind is not None and declared_kind != fault_kind:
        return False
    instruction_rva = fault.get("instruction_rva")
    source = unit.get("source")
    original = source.get("original") if isinstance(source, Mapping) else None
    if (
        not isinstance(instruction_rva, int)
        or isinstance(instruction_rva, bool)
        or not isinstance(original, Mapping)
        or not isinstance(original.get("rva_start"), int)
        or not isinstance(original.get("rva_end"), int)
        or not int(original["rva_start"]) <= instruction_rva < int(original["rva_end"])
    ):
        return False
    condition = fault.get("condition")
    if not isinstance(condition, Mapping):
        return False
    if condition.get("op") == "true":
        return True
    return (
        condition.get("op") == "const"
        and isinstance(condition.get("value"), int)
        and not isinstance(condition.get("value"), bool)
        and condition.get("value") != 0
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


def _recovery_failure_message(failure: Mapping[str, Any]) -> str:
    """Render legacy diagnostics without adding prose to v2 authority records."""

    message = failure.get("message")
    if isinstance(message, str) and message:
        return message
    code = failure.get("code")
    if isinstance(code, str) and code:
        return code
    return "indirect target recovery is incomplete"


def _rebind_preclassified_static_recoveries(
    *,
    indirect_exits: Sequence[Mapping[str, Any]],
    recoveries: Sequence[Mapping[str, Any]],
    starts: Mapping[int, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Bind pre-control recovery facts to the filtered canonical unit index."""

    by_id = {
        str(recovery.get("id")): recovery
        for recovery in recoveries
        if isinstance(recovery, Mapping) and isinstance(recovery.get("id"), str)
    }
    rebound: list[dict[str, Any]] = []
    for exit_record in indirect_exits:
        identity = str(exit_record["id"])
        source = by_id.get(identity)
        if source is None:
            raise MachineIRExportError(
                f"pre-control recovery inventory omits {identity}",
                code="precontrol_recovery_inventory_mismatch",
                unit_id=str(exit_record.get("source_unit_id")),
                rva=int(exit_record.get("source_rva", 0)),
            )
        recovery = copy.deepcopy(dict(source))
        recovery_kind = recovery.get("recovery_kind")
        target_rvas = [
            int(rva)
            for rva in recovery.get("target_rvas", [])
            if isinstance(rva, int) and not isinstance(rva, bool)
        ]
        resolved = sorted(rva for rva in target_rvas if rva in starts)
        unresolved = sorted(rva for rva in target_rvas if rva not in starts)
        recovery["target_unit_ids"] = [starts[rva]["id"] for rva in resolved]
        recovery["unit_binding"] = {
            "status": (
                "complete"
                if recovery.get("status") == "recovered" and not unresolved
                else "incomplete"
            ),
            "resolved_target_rvas": resolved,
            "unmaterialized_target_rvas": unresolved,
        }
        if (
            recovery.get("status") == "recovered"
            and recovery.get("closure") == "checked_finite_target_inventory"
            and recovery_kind == "pe32_indexed_absolute_jump_table"
            and recovery.get("failure") is None
            and _indirect_recovery_unit_binding_complete(recovery, starts)
        ):
            recovery["target_set_dependency"] = (
                build_bounded_selector_dependency_v2(recovery)
            )
        rebound.append(recovery)
    return rebound


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
    predecessors_by_target = _direct_predecessors_by_target(units)
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
                    source_unit,
                    predecessors_by_target=predecessors_by_target,
                ),
                image_base=binary.image_base,
                sections=binary.sections,
                read_rva=lambda rva, size: bytes(binary.pe.get_data(rva, size)),
                finite_index_domain=finite_domain,
                valid_target_rvas=None,
            )
            recovery_kind = recovery.get("kind")
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
                    "recovery_kind": recovery_kind,
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
            if (
                recovery.get("status") == "recovered"
                and recovery.get("closure") == "checked_finite_target_inventory"
                and recovery_kind == "pe32_indexed_absolute_jump_table"
                and recovery.get("failure") is None
                and _indirect_recovery_unit_binding_complete(recovery, starts)
            ):
                recovery["target_set_dependency"] = (
                    build_bounded_selector_dependency_v2(recovery)
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


def _callback_root_proposals_from_provenance(
    provenance: Mapping[str, Any],
) -> list[dict[str, Any]]:
    raw = provenance.get("callback_registrations")
    if not isinstance(raw, list):
        return []
    result: list[dict[str, Any]] = []
    for registration in raw:
        if not isinstance(registration, Mapping) or (
            registration.get("status") != "complete"
        ):
            continue
        targets = registration.get("target_rvas")
        if not isinstance(targets, list):
            continue
        imported = registration.get("import")
        for target in targets:
            if not isinstance(target, int) or isinstance(target, bool):
                continue
            result.append({
                "kind": "registered_callback",
                "rva": target,
                "source_unit_id": registration.get("unit_id"),
                "source_event_index": registration.get("event_index"),
                "dll": (
                    imported.get("dll")
                    if isinstance(imported, Mapping)
                    else None
                ),
                "symbol": (
                    imported.get("symbol")
                    if isinstance(imported, Mapping)
                    else None
                ),
                "callback_source": copy.deepcopy(
                    registration.get("callback_source")
                ),
                "callback_abi": copy.deepcopy(
                    registration.get("callback_abi")
                ),
                "provenance_format": registration.get("format"),
            })
    return result


def _local_callback_cutpoint_proposals(
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Bootstrap exact cutpoints for locally visible direct callback words.

    These proposals are deliberately conservative and have no proof authority.
    They may add roots but never remove behavior; regenerated provenance must
    still bind each callback to an exact decoded unit before Stage B can adapt it.
    """

    executable_sections = tuple(
        section
        for section in getattr(binary, "sections", ())
        if getattr(section, "executable", False)
    )
    result: dict[tuple[int, str, int], dict[str, Any]] = {}
    for unit in units:
        events = unit.get("semantics", {}).get("external_events", [])
        if not isinstance(events, list):
            continue
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping):
                continue
            abi = event.get("abi_contract")
            if (
                not isinstance(abi, Mapping)
                or abi.get("world_effect") != "callbackRegistration"
            ):
                continue
            argument_words = abi.get("argument_words")
            if (
                not isinstance(argument_words, int)
                or isinstance(argument_words, bool)
                or not 0 <= argument_words <= 64
            ):
                continue
            source = parse_callback_source(
                abi,
                argument_words=argument_words,
                context=f"{unit.get('id')} callback cutpoint proposal",
            )
            if source.kind != "argument_word":
                continue
            arguments = _checked_external_argument_values(event)
            if source.argument_index >= len(arguments):
                continue
            expression = _forward_local_callback_expression(
                arguments[source.argument_index],
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
            rva = value - binary.image_base if value >= binary.image_base else value
            if not any(
                section.rva_start <= rva < section.rva_end
                for section in executable_sections
            ):
                continue
            key = (rva, str(unit.get("id")), event_index)
            result[key] = {
                "kind": "registered_callback",
                "rva": rva,
                "source_unit_id": str(unit.get("id")),
                "source_event_index": event_index,
                "dll": event.get("dll"),
                "symbol": event.get("symbol"),
                "callback_source": source.as_json(),
                "callback_abi": copy.deepcopy(abi.get("callback_abi")),
                "proposal_basis": "local_exact_callback_argument",
                "proof_authority": False,
            }
    return [result[key] for key in sorted(result)]


def _forward_local_callback_expression(
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
        matching = [
            item
            for item in ordered
            if isinstance(item, Mapping)
            and item.get("kind") in {"external_call", "indirect_call"}
            and all(
                item.get(field) == event.get(field)
                for field in ("kind", "dll", "symbol", "ordinal", "return_rva")
            )
            and isinstance(item.get("instruction_rva"), int)
        ]
        if len(matching) != 1:
            return expression
        instruction_rva = int(matching[0]["instruction_rva"])
    writes = [
        item
        for item in ordered
        if isinstance(item, Mapping)
        and item.get("kind") == "write"
        and item.get("width") == 4
        and item.get("address") == address
        and isinstance(item.get("instruction_rva"), int)
        and int(item["instruction_rva"]) < instruction_rva
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


def _merge_callback_root_proposals(
    prior: Sequence[Mapping[str, Any]],
    proposed: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_key: dict[tuple[int, str, int], dict[str, Any]] = {}
    for raw in (*prior, *proposed):
        rva = raw.get("rva")
        source = raw.get("source_unit_id")
        event_index = raw.get("source_event_index")
        if (
            isinstance(rva, int)
            and not isinstance(rva, bool)
            and isinstance(source, str)
            and isinstance(event_index, int)
            and not isinstance(event_index, bool)
        ):
            by_key[(rva, source, event_index)] = copy.deepcopy(dict(raw))
    return [by_key[key] for key in sorted(by_key)]


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
    return dict(expected)


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
    "RECOVERED_EXECUTABLE_DATA_FILENAME",
    "MachineIRExportError",
    "MachineIRPackage",
    "PreparedMachineIRPackage",
    "X87_MICRO_OP_FORMAT",
    "export_machine_ir_package",
    "prepare_machine_ir_units_package",
]
