"""Schema normalization for regional replacement artifacts."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from ..stage_binary import StageAInputError
from .region_replacement_model import (
    REGION_OBSERVATIONS_FORMAT,
    REGION_REPLACEMENT_BUNDLE_FORMAT,
    _CALLING_CONVENTIONS,
    _CONTROL_KINDS,
    _C_ID_RE,
    _EVIDENCE_CLASSES,
    _HEX_RE,
    _ID_RE,
    _LIVE_KINDS,
    _MEMORY_ACCESS,
    _REGION_REPLACEMENT_FORMATS,
    _REGISTERS,
    _SHA256_RE,
    _STATUSES,
    _TYPE_BASES,
    _UINT32_MAX,
    RegionReplacementManifest,
    _array,
    _canonical_sha256,
    _json_copy,
    _object,
)


def _parse_manifest(payload: Mapping[str, Any]) -> RegionReplacementManifest:
    normalized = _normalize_manifest(payload, expect_digest=True)
    digest = str(normalized.pop("manifest_sha256"))
    expected = _canonical_sha256(normalized)
    if digest != expected:
        raise StageAInputError("region replacement manifest hash does not match its content")
    normalized["manifest_sha256"] = digest
    return RegionReplacementManifest(payload=normalized)


def _normalize_manifest(
    payload: Mapping[str, Any], *, expect_digest: bool
) -> dict[str, Any]:
    context = "region replacement manifest"
    format_name = payload.get("format")
    if format_name not in _REGION_REPLACEMENT_FORMATS:
        raise StageAInputError(
            "region replacement manifest must use a supported version: "
            f"{sorted(_REGION_REPLACEMENT_FORMATS)}"
        )
    expected = {
        "format", "id", "bindings", "cluster", "source", "abi",
        "type_hypotheses", "live_state", "memory_views", "expectations",
        "evidence",
    }
    if format_name == REGION_REPLACEMENT_BUNDLE_FORMAT:
        expected.add("support_sources")
    if expect_digest:
        expected.add("manifest_sha256")
    _exact_fields(payload, expected, context)
    bindings = _object(payload["bindings"], f"{context}.bindings")
    _exact_fields(
        bindings,
        {"machine_ir_sha256", "baseline_program_sha256", "cluster_contract_sha256"},
        f"{context}.bindings",
    )
    normalized_bindings = {
        key: _digest(bindings[key], f"{context}.bindings.{key}")
        for key in sorted(bindings)
    }

    cluster = _normalize_cluster(_object(payload["cluster"], f"{context}.cluster"))
    source = _normalize_source(_object(payload["source"], f"{context}.source"))
    support_sources = []
    if format_name == REGION_REPLACEMENT_BUNDLE_FORMAT:
        support_sources = [
            _normalize_support_source(
                _object(item, f"{context}.support_sources[{index}]")
            )
            for index, item in enumerate(
                _array(payload["support_sources"], f"{context}.support_sources")
            )
        ]
        _require_unique(
            (item["path"] for item in support_sources),
            f"{context}.support_sources paths",
        )
        if source["path"] in {item["path"] for item in support_sources}:
            raise StageAInputError("replacement source is duplicated as a support source")
        support_sources.sort(key=lambda item: item["path"])

    raw_evidence = _array(payload["evidence"], f"{context}.evidence")
    evidence = [
        _normalize_evidence(_object(item, f"{context}.evidence[{index}]"))
        for index, item in enumerate(raw_evidence)
    ]
    _require_unique((item["id"] for item in evidence), f"{context}.evidence ids")
    evidence.sort(key=lambda item: item["id"])
    evidence_ids = {item["id"] for item in evidence}
    if not evidence_ids:
        raise StageAInputError("region replacement manifest requires evidence")

    abi = _normalize_abi(_object(payload["abi"], f"{context}.abi"), evidence_ids)
    hypotheses = [
        _normalize_type_hypothesis(
            _object(item, f"{context}.type_hypotheses[{index}]"), evidence_ids
        )
        for index, item in enumerate(
            _array(payload["type_hypotheses"], f"{context}.type_hypotheses")
        )
    ]
    _require_unique((item["id"] for item in hypotheses), f"{context}.type_hypotheses ids")
    hypotheses.sort(key=lambda item: item["id"])
    live_state = _normalize_live_state(
        _object(payload["live_state"], f"{context}.live_state"), evidence_ids
    )
    memory_views = [
        _normalize_memory_view(
            _object(item, f"{context}.memory_views[{index}]"), evidence_ids
        )
        for index, item in enumerate(
            _array(payload["memory_views"], f"{context}.memory_views")
        )
    ]
    _require_unique((item["id"] for item in memory_views), f"{context}.memory_views ids")
    memory_views.sort(key=lambda item: item["id"])
    expectations = _normalize_expectations(
        _object(payload["expectations"], f"{context}.expectations"), evidence_ids
    )
    normalized = {
        "format": format_name,
        "id": _identifier(payload["id"], f"{context}.id"),
        "bindings": normalized_bindings,
        "cluster": cluster,
        "source": source,
        "abi": abi,
        "type_hypotheses": hypotheses,
        "live_state": live_state,
        "memory_views": memory_views,
        "expectations": expectations,
        "evidence": evidence,
    }
    if format_name == REGION_REPLACEMENT_BUNDLE_FORMAT:
        normalized["support_sources"] = support_sources
    if expect_digest:
        normalized["manifest_sha256"] = _digest(
            payload["manifest_sha256"], f"{context}.manifest_sha256"
        )
    return normalized


def _normalize_cluster(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "region replacement cluster"
    _exact_fields(
        payload,
        {"id", "entry_unit_id", "entry_rva", "unit_ids", "rva_spans"},
        context,
    )
    unit_ids = sorted(
        _identifier(item, f"{context}.unit_ids[{index}]")
        for index, item in enumerate(_array(payload["unit_ids"], f"{context}.unit_ids"))
    )
    _require_unique(unit_ids, f"{context}.unit_ids")
    if not unit_ids:
        raise StageAInputError(f"{context}.unit_ids must not be empty")
    entry_unit_id = _identifier(payload["entry_unit_id"], f"{context}.entry_unit_id")
    if entry_unit_id not in unit_ids:
        raise StageAInputError(f"{context}.entry_unit_id is not in unit_ids")
    spans = []
    for index, item in enumerate(_array(payload["rva_spans"], f"{context}.rva_spans")):
        span = _object(item, f"{context}.rva_spans[{index}]")
        _exact_fields(span, {"start", "end"}, f"{context}.rva_spans[{index}]")
        start = _uint32(span["start"], f"{context}.rva_spans[{index}].start")
        end = _uint32(span["end"], f"{context}.rva_spans[{index}].end")
        if end <= start:
            raise StageAInputError(f"{context}.rva_spans[{index}] must be nonempty")
        spans.append({"start": start, "end": end})
    if not spans:
        raise StageAInputError(f"{context}.rva_spans must not be empty")
    spans.sort(key=lambda span: (span["start"], span["end"]))
    _reject_overlapping_spans(spans, context)
    entry_rva = _uint32(payload["entry_rva"], f"{context}.entry_rva")
    if sum(span["start"] <= entry_rva < span["end"] for span in spans) != 1:
        raise StageAInputError(f"{context}.entry_rva is not in exactly one RVA span")
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "entry_unit_id": entry_unit_id,
        "entry_rva": entry_rva,
        "unit_ids": unit_ids,
        "rva_spans": spans,
    }


def _normalize_source(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "region replacement source"
    _exact_fields(
        payload, {"path", "sha256", "symbol", "line_start", "line_end"}, context
    )
    line_start = _positive_int(payload["line_start"], f"{context}.line_start")
    line_end = _positive_int(payload["line_end"], f"{context}.line_end")
    if line_end < line_start:
        raise StageAInputError(f"{context}.line_end must not precede line_start")
    return {
        "path": _relative_path(payload["path"], f"{context}.path"),
        "sha256": _digest(payload["sha256"], f"{context}.sha256"),
        "symbol": _c_identifier(payload["symbol"], f"{context}.symbol"),
        "line_start": line_start,
        "line_end": line_end,
    }


def _normalize_support_source(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "region replacement support source"
    _exact_fields(payload, {"path", "sha256", "role"}, context)
    return {
        "path": _relative_path(payload["path"], f"{context}.path"),
        "sha256": _digest(payload["sha256"], f"{context}.sha256"),
        "role": _choice(
            payload["role"],
            frozenset({"portable_source", "portable_header", "adapter_support"}),
            f"{context}.role",
        ),
    }


def _normalize_evidence(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "region replacement evidence"
    _exact_fields(payload, {"id", "class", "status", "artifact_sha256", "detail"}, context)
    evidence_class = _choice(payload["class"], _EVIDENCE_CLASSES, f"{context}.class")
    status = _choice(payload["status"], _STATUSES, f"{context}.status")
    if evidence_class == "unsupported" and status == "qualified":
        raise StageAInputError("unsupported replacement evidence cannot be qualified")
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "class": evidence_class,
        "status": status,
        "artifact_sha256": _digest(payload["artifact_sha256"], f"{context}.artifact_sha256"),
        "detail": _string(payload["detail"], f"{context}.detail"),
    }


def _normalize_abi(payload: Mapping[str, Any], evidence: set[str]) -> dict[str, Any]:
    context = "region replacement ABI"
    _exact_fields(
        payload,
        {
            "calling_convention", "stack_delta", "parameters", "results",
            "preserved_registers", "clobbered_registers", "evidence_ids",
        },
        context,
    )
    parameters = [
        _normalize_abi_value(
            _object(item, f"{context}.parameters[{index}]"),
            evidence,
            parameter=True,
        )
        for index, item in enumerate(_array(payload["parameters"], f"{context}.parameters"))
    ]
    results = [
        _normalize_abi_value(
            _object(item, f"{context}.results[{index}]"), evidence, parameter=False
        )
        for index, item in enumerate(_array(payload["results"], f"{context}.results"))
    ]
    _require_unique((item["id"] for item in parameters), f"{context}.parameter ids")
    _require_unique((item["ordinal"] for item in parameters), f"{context}.parameter ordinals")
    _require_unique((item["id"] for item in results), f"{context}.result ids")
    parameters.sort(key=lambda item: (item["ordinal"], item["id"]))
    results.sort(key=lambda item: item["id"])
    preserved = _register_list(payload["preserved_registers"], f"{context}.preserved_registers")
    clobbered = _register_list(payload["clobbered_registers"], f"{context}.clobbered_registers")
    if set(preserved) & set(clobbered):
        raise StageAInputError("ABI preserved and clobbered registers overlap")
    stack_delta = payload["stack_delta"]
    if isinstance(stack_delta, bool) or not isinstance(stack_delta, int):
        raise StageAInputError(f"{context}.stack_delta must be an integer")
    if not -(1 << 31) <= stack_delta < (1 << 31):
        raise StageAInputError(f"{context}.stack_delta is outside signed 32-bit range")
    return {
        "calling_convention": _choice(
            payload["calling_convention"], _CALLING_CONVENTIONS,
            f"{context}.calling_convention",
        ),
        "stack_delta": stack_delta,
        "parameters": parameters,
        "results": results,
        "preserved_registers": preserved,
        "clobbered_registers": clobbered,
        "evidence_ids": _evidence_refs(payload["evidence_ids"], evidence, f"{context}.evidence_ids"),
    }


def _normalize_abi_value(
    payload: Mapping[str, Any], evidence: set[str], *, parameter: bool
) -> dict[str, Any]:
    context = "ABI parameter" if parameter else "ABI result"
    fields = {"id", "name", "c_type", "location", "width_bits", "evidence_ids"}
    if parameter:
        fields |= {"ordinal", "direction"}
    _exact_fields(payload, fields, context)
    result = {
        "id": _identifier(payload["id"], f"{context}.id"),
        "name": _c_identifier(payload["name"], f"{context}.name"),
        "c_type": _string(payload["c_type"], f"{context}.c_type"),
        "location": _string(payload["location"], f"{context}.location"),
        "width_bits": _positive_int(payload["width_bits"], f"{context}.width_bits"),
        "evidence_ids": _evidence_refs(payload["evidence_ids"], evidence, f"{context}.evidence_ids"),
    }
    if parameter:
        result["ordinal"] = _nonnegative_int(payload["ordinal"], f"{context}.ordinal")
        result["direction"] = _choice(
            payload["direction"], frozenset({"in", "out", "in_out"}),
            f"{context}.direction",
        )
    return result


def _normalize_type_hypothesis(payload: Mapping[str, Any], evidence: set[str]) -> dict[str, Any]:
    context = "region replacement type hypothesis"
    _exact_fields(payload, {"id", "subject", "c_type", "basis", "evidence_ids"}, context)
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "subject": _string(payload["subject"], f"{context}.subject"),
        "c_type": _string(payload["c_type"], f"{context}.c_type"),
        "basis": _choice(payload["basis"], _TYPE_BASES, f"{context}.basis"),
        "evidence_ids": _evidence_refs(payload["evidence_ids"], evidence, f"{context}.evidence_ids"),
    }


def _normalize_live_state(payload: Mapping[str, Any], evidence: set[str]) -> dict[str, Any]:
    context = "region replacement live state"
    _exact_fields(payload, {"inputs", "outputs"}, context)
    result: dict[str, Any] = {}
    for direction in ("inputs", "outputs"):
        values = [
            _normalize_live_value(
                _object(item, f"{context}.{direction}[{index}]"), evidence
            )
            for index, item in enumerate(_array(payload[direction], f"{context}.{direction}"))
        ]
        _require_unique((item["id"] for item in values), f"{context}.{direction} ids")
        values.sort(key=lambda item: item["id"])
        result[direction] = values
    return result


def _normalize_live_value(payload: Mapping[str, Any], evidence: set[str]) -> dict[str, Any]:
    context = "region replacement live value"
    _exact_fields(payload, {"id", "kind", "location", "width_bits", "encoding", "evidence_ids"}, context)
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "kind": _choice(payload["kind"], _LIVE_KINDS, f"{context}.kind"),
        "location": _string(payload["location"], f"{context}.location"),
        "width_bits": _positive_int(payload["width_bits"], f"{context}.width_bits"),
        "encoding": _string(payload["encoding"], f"{context}.encoding"),
        "evidence_ids": _evidence_refs(payload["evidence_ids"], evidence, f"{context}.evidence_ids"),
    }


def _normalize_memory_view(payload: Mapping[str, Any], evidence: set[str]) -> dict[str, Any]:
    context = "region replacement memory view"
    _exact_fields(
        payload,
        {
            "id", "base_expression", "byte_length", "length_expression",
            "access", "representation", "evidence_ids",
        },
        context,
    )
    byte_length = payload["byte_length"]
    length_expression = payload["length_expression"]
    if (byte_length is None) == (length_expression is None):
        raise StageAInputError(
            f"{context} requires exactly one of byte_length or length_expression"
        )
    normalized_length = (
        None if byte_length is None else _positive_int(byte_length, f"{context}.byte_length")
    )
    normalized_expression = (
        None
        if length_expression is None
        else _string(length_expression, f"{context}.length_expression")
    )
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "base_expression": _string(payload["base_expression"], f"{context}.base_expression"),
        "byte_length": normalized_length,
        "length_expression": normalized_expression,
        "access": _choice(payload["access"], _MEMORY_ACCESS, f"{context}.access"),
        "representation": _string(payload["representation"], f"{context}.representation"),
        "evidence_ids": _evidence_refs(payload["evidence_ids"], evidence, f"{context}.evidence_ids"),
    }


def _normalize_expectations(payload: Mapping[str, Any], evidence: set[str]) -> dict[str, Any]:
    context = "region replacement expectations"
    _exact_fields(payload, {"control", "fault", "external_events"}, context)
    controls = [
        _normalize_control_variant(
            _object(item, f"{context}.control[{index}]"), evidence
        )
        for index, item in enumerate(_array(payload["control"], f"{context}.control"))
    ]
    _require_unique((item["id"] for item in controls), f"{context}.control ids")
    if not controls:
        raise StageAInputError(f"{context}.control must declare at least one exit")
    controls.sort(key=lambda item: item["id"])
    fault = _object(payload["fault"], f"{context}.fault")
    _exact_fields(fault, {"allow_none", "variants"}, f"{context}.fault")
    if not isinstance(fault["allow_none"], bool):
        raise StageAInputError(f"{context}.fault.allow_none must be a boolean")
    faults = [
        _normalize_fault_variant(
            _object(item, f"{context}.fault.variants[{index}]"), evidence
        )
        for index, item in enumerate(
            _array(fault["variants"], f"{context}.fault.variants")
        )
    ]
    _require_unique((item["id"] for item in faults), f"{context}.fault variant ids")
    if not fault["allow_none"] and not faults:
        raise StageAInputError(f"{context}.fault cannot forbid every outcome")
    faults.sort(key=lambda item: item["id"])
    events = [
        _normalize_external_expectation(
            _object(item, f"{context}.external_events[{index}]"), evidence
        )
        for index, item in enumerate(
            _array(payload["external_events"], f"{context}.external_events")
        )
    ]
    _require_unique((item["id"] for item in events), f"{context}.external event ids")
    events.sort(key=lambda item: item["id"])
    return {
        "control": controls,
        "fault": {"allow_none": fault["allow_none"], "variants": faults},
        "external_events": events,
    }


def _normalize_control_variant(payload: Mapping[str, Any], evidence: set[str]) -> dict[str, Any]:
    context = "region replacement control expectation"
    _exact_fields(
        payload,
        {
            "id", "kind", "target_unit_ids", "target_rvas", "target_values",
            "evidence_ids",
        },
        context,
        optional={"target_values"},
    )
    unit_ids = sorted(
        _identifier(item, f"{context}.target_unit_ids[{index}]")
        for index, item in enumerate(_array(payload["target_unit_ids"], f"{context}.target_unit_ids"))
    )
    target_rvas = sorted(
        _uint32(item, f"{context}.target_rvas[{index}]")
        for index, item in enumerate(_array(payload["target_rvas"], f"{context}.target_rvas"))
    )
    target_values = sorted(
        _uint32(item, f"{context}.target_values[{index}]")
        for index, item in enumerate(
            _array(payload.get("target_values", []), f"{context}.target_values")
        )
    )
    _require_unique(unit_ids, f"{context}.target_unit_ids")
    _require_unique(target_rvas, f"{context}.target_rvas")
    _require_unique(target_values, f"{context}.target_values")
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "kind": _choice(payload["kind"], _CONTROL_KINDS, f"{context}.kind"),
        "target_unit_ids": unit_ids,
        "target_rvas": target_rvas,
        "target_values": target_values,
        "evidence_ids": _evidence_refs(payload["evidence_ids"], evidence, f"{context}.evidence_ids"),
    }


def _normalize_fault_variant(payload: Mapping[str, Any], evidence: set[str]) -> dict[str, Any]:
    context = "region replacement fault expectation"
    _exact_fields(payload, {"id", "kind", "evidence_ids"}, context)
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "kind": _string(payload["kind"], f"{context}.kind"),
        "evidence_ids": _evidence_refs(payload["evidence_ids"], evidence, f"{context}.evidence_ids"),
    }


def _normalize_external_expectation(payload: Mapping[str, Any], evidence: set[str]) -> dict[str, Any]:
    context = "region replacement external-event expectation"
    required = {"id", "kind", "identity", "evidence_ids"}
    site_fields = {"instruction_rva", "return_rva"}
    optional = site_fields | {"comparison"}
    _exact_fields(payload, required | optional, context, optional=optional)
    present_site_fields = set(payload) & site_fields
    if present_site_fields not in (set(), site_fields):
        raise StageAInputError(
            f"{context} must provide instruction_rva and return_rva together"
        )
    result = {
        "id": _identifier(payload["id"], f"{context}.id"),
        "kind": _string(payload["kind"], f"{context}.kind"),
        "identity": _string(payload["identity"], f"{context}.identity"),
        "evidence_ids": _evidence_refs(payload["evidence_ids"], evidence, f"{context}.evidence_ids"),
    }
    if present_site_fields:
        result["instruction_rva"] = _uint32(
            payload["instruction_rva"], f"{context}.instruction_rva"
        )
        result["return_rva"] = _uint32(
            payload["return_rva"], f"{context}.return_rva"
        )
    if "comparison" in payload:
        result["comparison"] = _normalize_external_comparison(
            _object(payload["comparison"], f"{context}.comparison")
        )
    return result


def _normalize_external_comparison(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "region replacement external-event comparison"
    _exact_fields(
        payload,
        {
            "mode",
            "abi_contract_sha256",
            "template",
            "profile_id",
            "profile_sha256",
            "contract_id",
        },
        context,
    )
    mode = _choice(
        payload["mode"], {"checked_machine_abi_v1"}, f"{context}.mode"
    )
    return {
        "mode": mode,
        "abi_contract_sha256": _digest(
            payload["abi_contract_sha256"], f"{context}.abi_contract_sha256"
        ),
        "template": _string(payload["template"], f"{context}.template"),
        "profile_id": _identifier(payload["profile_id"], f"{context}.profile_id"),
        "profile_sha256": _digest(
            payload["profile_sha256"], f"{context}.profile_sha256"
        ),
        "contract_id": _uint32(payload["contract_id"], f"{context}.contract_id"),
    }


def _normalize_observations(
    payload: Mapping[str, Any], manifest: RegionReplacementManifest
) -> dict[str, Any]:
    context = "region observations"
    _exact_fields(payload, {"format", "manifest_sha256", "cases"}, context)
    if payload["format"] != REGION_OBSERVATIONS_FORMAT:
        raise StageAInputError(f"{context} use an unsupported format")
    if _digest(payload["manifest_sha256"], f"{context}.manifest_sha256") != manifest.manifest_sha256:
        raise StageAInputError(f"{context} are not bound to the replacement manifest")
    cases = [
        _normalize_observation_case(_object(item, f"{context}.cases[{index}]"))
        for index, item in enumerate(_array(payload["cases"], f"{context}.cases"))
    ]
    _require_unique((item["id"] for item in cases), f"{context}.case ids")
    cases.sort(key=lambda item: item["id"])
    return {
        "format": REGION_OBSERVATIONS_FORMAT,
        "manifest_sha256": manifest.manifest_sha256,
        "cases": cases,
    }


def _normalize_observation_case(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "region observation case"
    _exact_fields(
        payload,
        {
            "id", "entry_unit_id", "live_inputs", "live_outputs",
            "memory_views", "guest_memory_writes", "control", "fault",
            "external_events",
        },
        context,
        optional={"guest_memory_writes"},
    )
    result = {
        "id": _identifier(payload["id"], f"{context}.id"),
        "entry_unit_id": _identifier(payload["entry_unit_id"], f"{context}.entry_unit_id"),
    }
    for field in ("live_inputs", "live_outputs"):
        values = [
            _normalize_observed_value(_object(item, f"{context}.{field}[{index}]"))
            for index, item in enumerate(_array(payload[field], f"{context}.{field}"))
        ]
        _require_unique((item["id"] for item in values), f"{context}.{field} ids")
        values.sort(key=lambda item: item["id"])
        result[field] = values
    memory = [
        _normalize_observed_memory(_object(item, f"{context}.memory_views[{index}]"))
        for index, item in enumerate(_array(payload["memory_views"], f"{context}.memory_views"))
    ]
    _require_unique((item["id"] for item in memory), f"{context}.memory view ids")
    memory.sort(key=lambda item: item["id"])
    result["memory_views"] = memory
    guest_writes = [
        _normalize_observed_guest_write(
            _object(item, f"{context}.guest_memory_writes[{index}]")
        )
        for index, item in enumerate(
            _array(
                payload.get("guest_memory_writes", []),
                f"{context}.guest_memory_writes",
            )
        )
    ]
    _require_unique(
        (item["address"] for item in guest_writes),
        f"{context}.guest_memory_writes addresses",
    )
    guest_writes.sort(key=lambda item: item["address"])
    result["guest_memory_writes"] = guest_writes
    result["control"] = _normalize_observed_control(
        _object(payload["control"], f"{context}.control")
    )
    fault = payload["fault"]
    result["fault"] = (
        None
        if fault is None
        else _normalize_observed_fault(_object(fault, f"{context}.fault"))
    )
    result["external_events"] = [
        _normalize_observed_external(
            _object(item, f"{context}.external_events[{index}]")
        )
        for index, item in enumerate(
            _array(payload["external_events"], f"{context}.external_events")
        )
    ]
    return result


def _normalize_observed_value(payload: Mapping[str, Any]) -> dict[str, Any]:
    _exact_fields(payload, {"id", "value"}, "observed live value")
    return {
        "id": _identifier(payload["id"], "observed live value id"),
        "value": _canonical_json_value(payload["value"], "observed live value"),
    }


def _normalize_observed_memory(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "observed memory view"
    _exact_fields(payload, {"id", "base", "before", "after"}, context)
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "base": _uint32(payload["base"], f"{context}.base"),
        "before": _hex_bytes(payload["before"], f"{context}.before"),
        "after": _hex_bytes(payload["after"], f"{context}.after"),
    }


def _normalize_observed_guest_write(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "observed guest-memory write"
    _exact_fields(payload, {"address", "after"}, context)
    after = _hex_bytes(payload["after"], f"{context}.after")
    if len(after) != 2:
        raise StageAInputError(f"{context}.after must contain exactly one byte")
    return {
        "address": _uint32(payload["address"], f"{context}.address"),
        "after": after,
    }


def _normalize_observed_control(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "observed control"
    _exact_fields(payload, {"id", "kind", "target_unit_id", "target_rva", "value"}, context)
    target_unit = payload["target_unit_id"]
    target_rva = payload["target_rva"]
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "kind": _choice(payload["kind"], _CONTROL_KINDS, f"{context}.kind"),
        "target_unit_id": (
            None if target_unit is None else _identifier(target_unit, f"{context}.target_unit_id")
        ),
        "target_rva": None if target_rva is None else _uint32(target_rva, f"{context}.target_rva"),
        "value": _canonical_json_value(payload["value"], f"{context}.value"),
    }


def _normalize_observed_fault(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "observed fault"
    _exact_fields(payload, {"id", "kind", "instruction_rva", "code"}, context)
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "kind": _string(payload["kind"], f"{context}.kind"),
        "instruction_rva": _uint32(payload["instruction_rva"], f"{context}.instruction_rva"),
        "code": _canonical_json_value(payload["code"], f"{context}.code"),
    }


def _normalize_observed_external(payload: Mapping[str, Any]) -> dict[str, Any]:
    context = "observed external event"
    _exact_fields(
        payload,
        {
            "id", "kind", "identity", "arguments", "memory_reads", "result",
            "memory_writes", "callbacks", "machine_call",
        },
        context,
        optional={"machine_call"},
    )
    result = {
        "id": _identifier(payload["id"], f"{context}.id"),
        "kind": _string(payload["kind"], f"{context}.kind"),
        "identity": _string(payload["identity"], f"{context}.identity"),
        "arguments": _canonical_json_value(payload["arguments"], f"{context}.arguments"),
        "memory_reads": _canonical_json_value(payload["memory_reads"], f"{context}.memory_reads"),
        "result": _canonical_json_value(payload["result"], f"{context}.result"),
        "memory_writes": _canonical_json_value(payload["memory_writes"], f"{context}.memory_writes"),
        "callbacks": _canonical_json_value(payload["callbacks"], f"{context}.callbacks"),
    }
    if "machine_call" in payload:
        result["machine_call"] = _canonical_json_value(
            payload["machine_call"], f"{context}.machine_call"
        )
    return result


def _read_json_object(path: Path, context: str) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise StageAInputError(f"{context} must be a regular non-symlink file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context}: {exc}") from exc
    return _object(payload, context)


def _canonical_json_value(value: Any, context: str) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, float):
        raise StageAInputError(
            f"{context} must encode floating-point values as exact bit strings"
        )
    if isinstance(value, list):
        return [
            _canonical_json_value(item, f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str) or not key:
                raise StageAInputError(f"{context} object keys must be nonempty strings")
            result[key] = _canonical_json_value(value[key], f"{context}.{key}")
        return result
    raise StageAInputError(f"{context} contains a non-JSON value")


def _exact_fields(
    payload: Mapping[str, Any],
    expected: set[str],
    context: str,
    *,
    optional: set[str] | frozenset[str] = frozenset(),
) -> None:
    if not optional <= expected:
        raise ValueError("optional fields must be included in expected fields")
    missing = sorted((expected - optional) - set(payload))
    extra = sorted(set(payload) - expected)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing fields {missing}")
        if extra:
            details.append(f"unexpected fields {extra}")
        raise StageAInputError(f"{context} has " + " and ".join(details))


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 0x20 for char in value):
        raise StageAInputError(f"{context} must be a nonempty string without control characters")
    return value


def _identifier(value: Any, context: str) -> str:
    text = _string(value, context)
    if _ID_RE.fullmatch(text) is None:
        raise StageAInputError(f"{context} is not a stable identifier")
    return text


def _c_identifier(value: Any, context: str) -> str:
    text = _string(value, context)
    if _C_ID_RE.fullmatch(text) is None:
        raise StageAInputError(f"{context} is not a C identifier")
    return text


def _choice(value: Any, choices: frozenset[str], context: str) -> str:
    text = _string(value, context)
    if text not in choices:
        raise StageAInputError(f"{context} must be one of {sorted(choices)}")
    return text


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be 64 lowercase hexadecimal characters")
    return value


def _uint32(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _UINT32_MAX:
        raise StageAInputError(f"{context} must be an unsigned 32-bit integer")
    return value


def _positive_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise StageAInputError(f"{context} must be a positive integer")
    return value


def _nonnegative_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StageAInputError(f"{context} must be a nonnegative integer")
    return value


def _relative_path(value: Any, context: str) -> str:
    raw = _string(value, context)
    if "\\" in raw:
        raise StageAInputError(f"{context} must use POSIX separators")
    path = PurePosixPath(raw)
    if path.is_absolute() or path.as_posix() != raw or ".." in path.parts:
        raise StageAInputError(f"{context} must be a canonical contained path")
    if any(part in {"", "."} for part in path.parts):
        raise StageAInputError(f"{context} contains an empty or dot component")
    return raw


def _hex_bytes(value: Any, context: str) -> str:
    if not isinstance(value, str) or _HEX_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be lowercase hexadecimal bytes")
    return value


def _register_list(value: Any, context: str) -> list[str]:
    result = sorted(
        _choice(item, _REGISTERS, f"{context}[{index}]")
        for index, item in enumerate(_array(value, context))
    )
    _require_unique(result, context)
    return result


def _evidence_refs(value: Any, available: set[str], context: str) -> list[str]:
    refs = sorted(
        _identifier(item, f"{context}[{index}]")
        for index, item in enumerate(_array(value, context))
    )
    _require_unique(refs, context)
    if not refs:
        raise StageAInputError(f"{context} must not be empty")
    unknown = sorted(set(refs) - available)
    if unknown:
        raise StageAInputError(f"{context} references unknown evidence {unknown}")
    return refs


def _require_unique(values: Iterable[Any], context: str) -> None:
    observed = list(values)
    if len(observed) != len(set(observed)):
        raise StageAInputError(f"{context} must not contain duplicates")


def _reject_overlapping_spans(spans: Sequence[Mapping[str, Any]], context: str) -> None:
    for left, right in zip(spans, spans[1:]):
        if int(right["start"]) < int(left["end"]):
            raise StageAInputError(f"{context} contains overlapping RVA spans")
