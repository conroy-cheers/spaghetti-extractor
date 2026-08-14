"""Deterministic machine-IR package export orchestration."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable, Sequence

from ..authority_inputs.machine_ir_authority import build_machine_ir_authority_bindings
from ..pe32.recovered_executable_data import (
    RECOVERED_EXECUTABLE_DATA_FILENAME,
    RECOVERED_EXECUTABLE_DATA_FORMAT,
    build_recovered_executable_data_contract,
)
from ..candidate.state_machine import (
    STAGE_A_REFERENCE_CONTRACT_FORMAT,
    load_stage_a_reference_contract_binding,
)
from ..pe32.stage_binary import _parse_stage_a_pe
from ..util import sha256_bytes, sha256_file, write_json
from .ir_evidence import (
    _binary_inventory,
    _external_inventory,
    _load_indirect_target_profile,
    _reference_inventory,
    _reference_issues,
)
from .ir_inventory import _control_inventory, _coverage_inventory, _unit_issues
from .ir_materialization import (
    _classify_executable_data_before_control,
    _materialize_recovered_target_cutpoints,
)
from .ir_model import (
    MACHINE_IR_FILENAME,
    MACHINE_IR_FORMAT,
    MACHINE_IR_MANIFEST_FILENAME,
    MachineIRExportError,
    MachineIRPackage,
    RvaSpan,
    _aggregate_status,
    _assert_byte_free,
    _canonical_json,
    _default_finite_dataflow_factory,
    _json_object,
    _regular_file,
)
from .ir_preparation import (
    _load_reusable_prepared_units,
    _machine_ir_artifact_path,
    _prepare_units,
    _read_canonical_rows,
    _validate_unique_units,
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
    finite_dataflow_factory: Callable[..., Any] | None = None,
) -> MachineIRPackage:
    """Validate and export a deterministic, byte-free PE32 machine IR package.

    The historical profile arguments remain accepted so older callers can read
    v1 diagnostics.  They cannot affect this exact extraction artifact; v2
    interprocedural, external-site, and candidate-authority phases consume them
    after extraction.
    """

    _ = interprocedural_control
    dataflow_factory = (
        finite_dataflow_factory
        if finite_dataflow_factory is not None
        else _default_finite_dataflow_factory()
    )

    state_path = _regular_file(state_machine, "canonical state machine")
    state_sha256 = sha256_file(state_path)
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
    reusable, reusable_state_sha256 = _load_reusable_prepared_units(
        prepared_machine_ir,
        binary_sha256=binary.sha256,
        reference_sha256=reference_sha256,
    )
    if (
        prepared_machine_ir is not None
        and reusable_state_sha256 == state_sha256
    ):
        prepared = [dict(unit) for unit in reusable.values()]
        for unit in prepared:
            unit["reachable"] = False
            unit.pop("reachability", None)
        prepared.sort(
            key=lambda item: (
                int(item["source"]["original"]["rva_start"]),
                str(item["id"]),
            )
        )
        reused_units = len(prepared)
    else:
        rows = _read_canonical_rows(state_path)
        _validate_unique_units(rows)
        prepared, reused_units = _prepare_units(
            rows,
            binary=binary,
            reference_sha256=reference_sha256,
            reusable=reusable,
        )
    prepared_input_units = len(prepared)
    (
        prepared,
        target_cutpoint_materialization,
        materialization_issues,
        materialized_static_recoveries,
        materialized_data_ranges,
    ) = (
        _materialize_recovered_target_cutpoints(
            binary=binary,
            units=prepared,
            reference=reference,
            reference_sha256=reference_sha256,
            finite_dataflow_factory=dataflow_factory,
        )
    )
    materialized_target_units = target_cutpoint_materialization["counts"][
        "materialized_units"
    ]
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
            precomputed_static_recoveries=materialized_static_recoveries,
            precomputed_data_ranges=materialized_data_ranges,
            precomputed_static_rounds=target_cutpoint_materialization[
                "static_recovery_rounds"
            ],
            finite_dataflow_factory=dataflow_factory,
        )
    )
    issues = _unit_issues(prepared)
    issues.extend(materialization_issues)
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
        finite_dataflow_factory=dataflow_factory,
    )
    control["target_cutpoint_materialization"] = target_cutpoint_materialization
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
                "sha256": state_sha256,
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
            "materialized_target_units": materialized_target_units,
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
