"""Exact unit preparation and reusable prepared-machine-IR loading."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..authority_inputs.machine_ir_authority import build_machine_ir_authority_bindings
from ..candidate.state_machine import (
    STAGE_B_STATE_MACHINE_FORMAT,
    load_stage_a_reference_contract_binding,
    normalize_stage_a_semantic_transfer,
)
from ..pe32.stage_binary import StageABinary, _parse_stage_a_pe
from ..util import sha256_bytes, sha256_file, write_json
from .ir_decoding import _semantic_call_events
from .ir_decoding import (
    _decoded_control_reconciliation,
    _instructions,
    _recover_unknown_fallthrough,
    _semantic_copy,
    _semantic_unit_qualified,
    _x87_projection,
)
from .ir_evidence import (
    _binary_inventory,
    _binding_projection,
    _control_disposition,
    _outcome_targets,
    _unit_span,
)
from .ir_model import (
    DECODED_CONTROL_RECONCILIATION_FORMAT,
    MACHINE_IR_FILENAME,
    MACHINE_IR_FORMAT,
    MACHINE_IR_MANIFEST_FILENAME,
    PREPARED_MACHINE_IR_FILENAME,
    PREPARED_MACHINE_IR_FORMAT,
    PREPARED_MACHINE_IR_MANIFEST_FILENAME,
    MachineIRExportError,
    PreparedMachineIRPackage,
    SourceLocation,
    _SEMANTIC_FIELDS,
    _assert_byte_free,
    _canonical_json,
    _digest,
    _json_object,
    _optional_string,
    _regular_file,
    _required_string,
    _validate_semantic_shape,
)


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
    state_sha256 = sha256_file(state_path)
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
    reusable, _reusable_state_sha256 = _load_reusable_prepared_units(
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
                "sha256": state_sha256,
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
) -> tuple[dict[str, dict[str, Any]], str | None]:
    if value is None:
        return {}, None
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
    state_machine = inputs.get("state_machine") if isinstance(inputs, Mapping) else None
    reference_binding_sha256 = (
        reference.get("sha256") if isinstance(reference, Mapping) else None
    )
    if (
        not isinstance(binary, Mapping)
        or binary.get("sha256") != binary_sha256
        or not isinstance(inputs, Mapping)
        or not isinstance(state_machine, Mapping)
        or not isinstance(state_machine.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", state_machine["sha256"]) is None
        or (reference is not None and not isinstance(reference, Mapping))
        or reference_binding_sha256 != reference_sha256
        or not isinstance(artifact, Mapping)
        or not isinstance(artifact.get("sha256"), str)
    ):
        raise MachineIRExportError(
            "prepared machine IR input or artifact binding is stale",
            code="prepared_machine_ir_binding_mismatch",
        )

    units: dict[str, dict[str, Any]] = {}
    digest = hashlib.sha256()
    with machine_path.open("rb") as stream:
        for line_number, line in enumerate(stream, start=1):
            digest.update(line)
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
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
                or re.fullmatch(r"[0-9a-f]{64}", preparation["input_sha256"])
                is None
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
    if digest.hexdigest() != artifact.get("sha256"):
        raise MachineIRExportError(
            "prepared machine IR input or artifact binding is stale",
            code="prepared_machine_ir_binding_mismatch",
        )
    counts = manifest.get("counts")
    if not isinstance(counts, Mapping) or len(units) != counts.get("units"):
        raise MachineIRExportError(
            "prepared machine IR unit count differs from its manifest",
            code="prepared_machine_ir_count_mismatch",
        )
    return units, str(state_machine["sha256"])


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
            # Checked prepared units are immutable.  Final extraction adds only
            # top-level reachability fields, while any newly materialized unit
            # is created independently below.  A deep copy here traversed the
            # complete semantic expression tree before the control phase made
            # its own working copy.
            unit = dict(cached)
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
