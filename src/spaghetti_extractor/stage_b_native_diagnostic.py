"""Decode candidate-only native diagnostic records into actionable evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from pathlib import Path
import struct
from typing import Any

from .util import sha256_bytes, sha256_file


NATIVE_DIAGNOSTIC_REPORT_FORMAT = "stage-b-native-diagnostic-report-v1"
_DIAGNOSTIC_MAGIC = 0x31444553
_DIAGNOSTIC_VERSION = 4
_HEADER_WORDS = 45
_HEADER_SIZE = _HEADER_WORDS * 4
_MAX_EXTERNAL_RANGES = 8192
_MAX_EXTERNAL_LIFECYCLE_EVENTS = 64
_MAX_EXTERNAL_TRACE_EVENTS = 128
_MAX_TRANSFER_TRACE_EVENTS = 1024

_STATUS_NAMES = {
    0: "ok",
    1: "unimplemented",
    2: "divide_error",
    3: "memory_fault",
    4: "external_fault",
}

_REASON_CATALOG: dict[int, tuple[str, str, str, str]] = {
    0x1003: (
        "dynamic_import_target_mismatch",
        "external target differs from the checked IAT binding",
        "external_target_provenance",
        "recover the exact import origin and preserve it through the call site",
    ),
    0x1005: (
        "external_preserved_register_mismatch",
        "the native call changed a register required to be callee-preserved",
        "external_abi",
        "correct the call ABI or the preserved-register contract",
    ),
    0x1006: (
        "external_call_with_direction_flag_set",
        "the candidate reached a native call with DF set",
        "machine_state_normalization",
        "prove or restore the ABI-required clear direction flag before the call",
    ),
    0x2001: (
        "external_result_context_invalid",
        "the external result could not be bound to the active call snapshot",
        "external_call_frame",
        "repair the external call frame and continuation binding",
    ),
    0x2002: (
        "callable_result_provenance_missing",
        "a callable resolver result could not be recorded safely",
        "external_target_provenance",
        "add a checked callable-result provenance and lifetime contract",
    ),
    0x2003: (
        "external_call_context_invalid",
        "the runtime was not initialized for this external call",
        "runtime_initialization",
        "repair candidate runtime initialization or the call entry state",
    ),
    0x2004: (
        "external_contract_ambiguous",
        "multiple external contracts disagree about argument layout",
        "external_abi",
        "make the site resolve to one exact machine-level ABI contract",
    ),
    0x2005: (
        "external_argument_unreadable",
        "an external argument word is outside the checked readable footprint",
        "external_abi",
        "recover the exact argument base, arity, and readable memory footprint",
    ),
    0x2006: (
        "external_argument_mismatch",
        "the runtime argument differs from the statically checked expression",
        "external_abi",
        "repair argument reconstruction at the reported call site",
    ),
    0x2008: (
        "external_profile_binding_ambiguous",
        "more than one incompatible external profile binding matched the site",
        "external_profile_selection",
        "select one exact library identity and machine contract for the site",
    ),
    0x2009: (
        "external_site_not_authorized",
        "an unresolved external target was blocked before native execution",
        "external_target_provenance",
        "recover the target identity and exact machine ABI; do not authorize the observed runtime address directly",
    ),
    0x200A: (
        "candidate_image_target_misclassified_external",
        "an indirect target inside the candidate image reached external dispatch",
        "internal_target_recovery",
        "materialize the target as an exact internal unit and add its dispatch edge",
    ),
    0x2101: (
        "external_result_range_invalid",
        "an allocation-like result did not satisfy its range contract",
        "external_memory_effect",
        "correct the result register, extent, nullability, or allocation contract",
    ),
    0x2201: (
        "external_release_argument_invalid",
        "the resource-release argument could not be recovered",
        "external_resource_lifetime",
        "recover the exact release argument and its resource provenance",
    ),
    0x2202: (
        "external_range_release_unknown",
        "the candidate released an address with no live paired range",
        "external_resource_lifetime",
        "repair allocation provenance or the resource lifetime sequence",
    ),
    0x2203: (
        "external_range_double_release",
        "the candidate released an external range more than once",
        "external_resource_lifetime",
        "repair the duplicated release or the lifetime-state transition",
    ),
    0x2204: (
        "external_range_interior_release",
        "the candidate released an interior pointer instead of its range base",
        "external_resource_lifetime",
        "recover and pass the owning range base to the release call",
    ),
    0x2301: (
        "external_result_pointee_invalid",
        "a returned pointer graph did not satisfy its checked shape",
        "external_memory_effect",
        "correct the result-pointer and pointee range contract",
    ),
    0x2401: (
        "external_argument_pointee_invalid",
        "an argument pointer graph did not satisfy its checked shape",
        "external_memory_effect",
        "correct the argument-pointer and pointee range contract",
    ),
    0x2501: (
        "external_interface_output_invalid",
        "an interface out-parameter did not produce a valid object graph",
        "external_interface_contract",
        "recover the interface out-parameter, object, and vtable extents",
    ),
    0x2F01: (
        "external_effect_unsupported",
        "the selected external contract requests an unsupported world effect",
        "external_environment",
        "implement the generic world-effect class or select the correct contract",
    ),
    0x3001: (
        "memory_read_outside_checked_ranges",
        "machine-IR attempted a read outside the candidate memory model",
        "memory_provenance",
        "recover the address origin and add a checked readable range or fix the translated address",
    ),
    0x3002: (
        "memory_write_outside_checked_ranges",
        "machine-IR attempted a write outside the candidate memory model",
        "memory_provenance",
        "recover the address origin and add a checked writable range or fix the translated address",
    ),
    0x4001: (
        "external_call_probe",
        "candidate diagnostic probe captured an external call boundary",
        "external_trace",
        "inspect the captured call arguments and continue candidate-only diagnosis",
    ),
    0x5001: (
        "behavior_relevant_undefined_value",
        "execution consumed an undefined value without an accepted witness",
        "definedness",
        "supply a checked related input or prove the value noninterfering",
    ),
}


class StageBNativeDiagnosticError(ValueError):
    """Raised when a native diagnostic artifact is malformed or inconsistent."""


def _hex32(value: int) -> str:
    return f"0x{value:08x}"


def _row(words: Sequence[int], names: Sequence[str]) -> dict[str, int | str]:
    result: dict[str, int | str] = dict(zip(names, words, strict=True))
    for name in names:
        if name not in {"sequence", "phase", "kind", "status", "operation", "generation"}:
            result[f"{name}_hex"] = _hex32(int(result[name]))
    return result


def _ring_rows(
    rows: list[dict[str, int | str]],
    *,
    count: int,
    next_index: int,
    capacity: int,
    context: str,
) -> list[dict[str, int | str]]:
    if count > capacity or next_index >= capacity:
        raise StageBNativeDiagnosticError(f"{context} ring metadata is out of range")
    if count < capacity:
        if next_index != count:
            raise StageBNativeDiagnosticError(
                f"{context} partially filled ring has an inconsistent next index"
            )
        return rows
    return rows[next_index:] + rows[:next_index]


def _load_json_object(
    value: Path | str | Mapping[str, Any] | None,
    *,
    context: str,
) -> tuple[dict[str, Any] | None, str | None]:
    if value is None:
        return None, None
    if isinstance(value, Mapping):
        return dict(value), None
    path = Path(value)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageBNativeDiagnosticError(f"cannot read {context}") from exc
    if not isinstance(payload, dict):
        raise StageBNativeDiagnosticError(f"{context} must be a JSON object")
    return payload, sha256_file(path)


def _matching_rows(
    payload: Mapping[str, Any] | None,
    path: Sequence[str],
    *,
    instruction_rva: int,
) -> list[dict[str, Any]]:
    value: Any = payload
    for key in path:
        if not isinstance(value, Mapping):
            return []
        value = value.get(key)
    if not isinstance(value, list):
        return []
    return [
        dict(row)
        for row in value
        if isinstance(row, Mapping) and row.get("instruction_rva") == instruction_rva
    ]


def decode_stage_b_native_diagnostic(
    data: bytes,
    *,
    native_engine_plan: Path | str | Mapping[str, Any] | None = None,
    native_runtime_package: Path | str | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Decode and statically contextualize one candidate-only v4 record."""

    if len(data) < _HEADER_SIZE:
        raise StageBNativeDiagnosticError("native diagnostic is shorter than its header")
    words = struct.unpack_from(f"<{_HEADER_WORDS}I", data)
    if words[0] != _DIAGNOSTIC_MAGIC or words[1] != _DIAGNOSTIC_VERSION:
        raise StageBNativeDiagnosticError("native diagnostic magic or version is unsupported")

    (
        status,
        failure_rva,
        reason,
        value,
        aux,
        detail,
        external_range_count,
        lifecycle_count,
        lifecycle_next,
        lifecycle_sequence,
        external_trace_count,
        external_trace_next,
        external_trace_sequence,
        transfer_trace_count,
        transfer_trace_next,
        transfer_trace_sequence,
    ) = words[2:18]
    if external_range_count > _MAX_EXTERNAL_RANGES:
        raise StageBNativeDiagnosticError("native diagnostic range count is out of range")
    if lifecycle_count > _MAX_EXTERNAL_LIFECYCLE_EVENTS:
        raise StageBNativeDiagnosticError("native diagnostic lifecycle count is out of range")
    if external_trace_count > _MAX_EXTERNAL_TRACE_EVENTS:
        raise StageBNativeDiagnosticError("native diagnostic external trace count is out of range")
    if transfer_trace_count > _MAX_TRANSFER_TRACE_EVENTS:
        raise StageBNativeDiagnosticError("native diagnostic transfer trace count is out of range")

    expected_size = _HEADER_SIZE + 20 * external_range_count
    expected_size += 36 * lifecycle_count
    expected_size += 40 * external_trace_count
    expected_size += 16 * transfer_trace_count
    if len(data) != expected_size:
        raise StageBNativeDiagnosticError(
            f"native diagnostic has {len(data)} bytes; expected {expected_size}"
        )

    offset = _HEADER_SIZE

    def rows(count: int, width: int, names: Sequence[str]) -> list[dict[str, int | str]]:
        nonlocal offset
        result = []
        for _ in range(count):
            values = struct.unpack_from(f"<{width}I", data, offset)
            offset += width * 4
            result.append(_row(values, names))
        return result

    ranges = rows(
        external_range_count,
        5,
        ("start", "size", "producer_rva", "producer_action", "generation"),
    )
    lifecycle = _ring_rows(
        rows(
            lifecycle_count,
            9,
            (
                "sequence",
                "operation",
                "status",
                "instruction_rva",
                "start",
                "size",
                "producer_rva",
                "producer_action",
                "generation",
            ),
        ),
        count=lifecycle_count,
        next_index=lifecycle_next,
        capacity=_MAX_EXTERNAL_LIFECYCLE_EVENTS,
        context="external lifecycle",
    )
    external_trace = _ring_rows(
        rows(
            external_trace_count,
            10,
            (
                "sequence",
                "phase",
                "instruction_rva",
                "target_rva",
                "target_iat_rva",
                "kind",
                "status",
                "eax",
                "esp",
                "eflags",
            ),
        ),
        count=external_trace_count,
        next_index=external_trace_next,
        capacity=_MAX_EXTERNAL_TRACE_EVENTS,
        context="external trace",
    )
    transfer_trace = _ring_rows(
        rows(
            transfer_trace_count,
            4,
            ("sequence", "rva", "df", "esp"),
        ),
        count=transfer_trace_count,
        next_index=transfer_trace_next,
        capacity=_MAX_TRANSFER_TRACE_EVENTS,
        context="transfer trace",
    )
    if offset != len(data):
        raise StageBNativeDiagnosticError("native diagnostic decoder did not consume all bytes")

    engine, engine_sha256 = _load_json_object(
        native_engine_plan, context="native-engine plan"
    )
    runtime, runtime_sha256 = _load_json_object(
        native_runtime_package, context="native-runtime package"
    )
    reason_row = _REASON_CATALOG.get(reason)
    if reason_row is None:
        reason_row = (
            "unknown_runtime_diagnostic_reason",
            "the runtime emitted an unrecognized diagnostic reason",
            "runtime_diagnostic",
            "update the diagnostic decoder and inspect the bound candidate artifacts",
        )
    category, summary, repair_class, next_action = reason_row
    engine_sites = _matching_rows(
        engine, ("external_sites",), instruction_rva=failure_rva
    )
    engine_frontiers = _matching_rows(
        engine, ("diagnostic_frontiers",), instruction_rva=failure_rva
    )
    runtime_blocked = _matching_rows(
        runtime,
        ("inputs", "external_dispatch", "blocked_sites"),
        instruction_rva=failure_rva,
    )
    registers = dict(zip(
        ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags", "fs_base"),
        words[18:28],
        strict=True,
    ))
    stack_word_count = words[28]
    if stack_word_count > 16:
        raise StageBNativeDiagnosticError("native diagnostic stack word count is out of range")
    stack_words = list(words[29 : 29 + stack_word_count])
    return {
        "format": NATIVE_DIAGNOSTIC_REPORT_FORMAT,
        "status": "decoded",
        "proof_authority": False,
        "source": {
            "format": "stage-b-native-diagnostic-v4",
            "sha256": sha256_bytes(data),
            "size": len(data),
        },
        "failure": {
            "status": status,
            "status_name": _STATUS_NAMES.get(status, "unknown"),
            "rva": failure_rva,
            "rva_hex": _hex32(failure_rva),
            "reason": reason,
            "reason_hex": _hex32(reason),
            "category": category,
            "summary": summary,
            "likely_repair_class": repair_class,
            "next_action": next_action,
            "value": value,
            "value_hex": _hex32(value),
            "aux": aux,
            "aux_hex": _hex32(aux),
            "detail": detail,
            "detail_hex": _hex32(detail),
            "registers": {
                name: {"value": register, "hex": _hex32(register)}
                for name, register in registers.items()
            },
            "stack_words": [
                {"offset": index * 4, "value": word, "hex": _hex32(word)}
                for index, word in enumerate(stack_words)
            ],
        },
        "counts": {
            "external_ranges": external_range_count,
            "external_lifecycle_events": lifecycle_count,
            "external_trace_events": external_trace_count,
            "transfer_trace_events": transfer_trace_count,
        },
        "sequences": {
            "external_lifecycle": lifecycle_sequence,
            "external_trace": external_trace_sequence,
            "transfer_trace": transfer_trace_sequence,
        },
        "external_ranges": ranges,
        "external_lifecycle": lifecycle,
        "external_trace": external_trace,
        "transfer_trace": transfer_trace,
        "static_context": {
            "native_engine_plan_sha256": engine_sha256,
            "native_runtime_package_sha256": runtime_sha256,
            "external_sites": engine_sites,
            "diagnostic_frontiers": engine_frontiers,
            "blocked_external_sites": runtime_blocked,
        },
    }


def decode_stage_b_native_diagnostic_file(
    diagnostic: Path | str,
    *,
    native_engine_plan: Path | str | Mapping[str, Any] | None = None,
    native_runtime_package: Path | str | Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    path = Path(diagnostic)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise StageBNativeDiagnosticError("cannot read native diagnostic") from exc
    return decode_stage_b_native_diagnostic(
        data,
        native_engine_plan=native_engine_plan,
        native_runtime_package=native_runtime_package,
    )


__all__ = [
    "NATIVE_DIAGNOSTIC_REPORT_FORMAT",
    "StageBNativeDiagnosticError",
    "decode_stage_b_native_diagnostic",
    "decode_stage_b_native_diagnostic_file",
]
