"""External, static-program, binary, and source-location inventory helpers."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..pe32.model import ParsedPEImage
from .ir_decoding import _sanitize_metadata
from .ir_model import (
    INDIRECT_TARGET_PROFILE_FORMAT,
    ExportIssue,
    MachineIRExportError,
    RvaSpan,
    SourceLocation,
    _DIRECT_OUTCOME_FIELDS,
    _json_object,
    _optional_range,
    _optional_string,
    _regular_file,
    _u32,
)


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


def _static_program_inventory(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    empty = {
        "roots": [],
        "jump_table_targets": [],
        "noncode_ranges": [],
        "public": None,
    }
    if payload is None:
        return empty
    structural = payload.get("structural_universe")
    families = payload.get("families")
    if not isinstance(structural, Mapping) or not isinstance(families, Mapping):
        return empty
    padding = structural.get("padding")
    noncode = [
        span
        for row in padding if isinstance(padding, list) and isinstance(row, Mapping)
        for span in [_optional_range(row.get("span"))]
        if span is not None
    ] if isinstance(padding, list) else []
    roots_raw = structural.get("roots")
    roots = (
        [_sanitize_metadata(item, "static_program") for item in roots_raw]
        if isinstance(roots_raw, list)
        else []
    )
    public = {
        "pe_layout": _constraint_projection(families.get("pe_layout")),
        "executable_coverage": _constraint_projection(
            families.get("executable_coverage")
        ),
        "structural_units": _constraint_projection(families.get("structural_units")),
        "roots": _constraint_projection(families.get("roots")),
        "cfg": _constraint_projection(families.get("cfg")),
        "imports": _constraint_projection(families.get("imports")),
    }
    return {
        "roots": roots,
        # Structural CFG destinations are not finite-target certificates.
        # Indirect targets become authoritative only through the dedicated
        # checked target-recovery phase.
        "jump_table_targets": [],
        "noncode_ranges": noncode,
        "public": public,
    }


def _constraint_projection(value: Any) -> Any:
    return (
        _sanitize_metadata(value, "static_program")
        if isinstance(value, Mapping)
        else None
    )


def _static_program_issues(payload: Mapping[str, Any] | None) -> list[ExportIssue]:
    if payload is None:
        return []
    result: list[ExportIssue] = []
    families = payload.get("families")
    if isinstance(families, Mapping):
        for family, constraint in families.items():
            if not isinstance(constraint, Mapping):
                continue
            raw_status = constraint.get("status")
            if raw_status not in {"violated", "incomplete"}:
                continue
            status = str(raw_status)
            result.append(
                ExportIssue(
                    status=status,
                    category=f"static_program_{family}_{raw_status}",
                    message=str(
                        constraint.get("blocker")
                        or f"static-program family {family} is {raw_status}"
                    ),
                    next_action=str(
                        constraint.get("next_action")
                        or f"complete the static-program {family} evidence"
                    ),
                    location=SourceLocation(
                        None,
                        None,
                        None,
                        None,
                        f"static_program_contract.families.{family}",
                    ),
                )
            )
    return result


def _binary_inventory(binary: ParsedPEImage) -> dict[str, Any]:
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
            "static_program_contract_sha256",
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
