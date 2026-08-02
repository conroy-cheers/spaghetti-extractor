"""Contracts and candidate-only validation for regional C replacements.

This module deliberately consumes no original executable or source.  A
replacement is bound to stable machine-IR and cluster identities, while its
behavior is checked against observations from the generated baseline.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from .artifact_formats import REGION_REPLACEMENT_BUNDLE_FORMAT
from .stage_binary import StageAInputError
from .util import sha256_file, write_json


REGION_REPLACEMENT_FORMAT = "stage-b-region-replacement-v1"
_REGION_REPLACEMENT_FORMATS = frozenset(
    {REGION_REPLACEMENT_FORMAT, REGION_REPLACEMENT_BUNDLE_FORMAT}
)
REGION_OBSERVATIONS_FORMAT = "stage-b-region-observations-v1"
REGION_REPLACEMENT_VALIDATION_FORMAT = (
    "stage-b-region-replacement-validation-v1"
)
REGION_OVERRIDE_TABLE_FORMAT = "stage-b-region-override-table-v1"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ID_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:/-]{0,254}[A-Za-z0-9])?")
_C_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_HEX_RE = re.compile(r"(?:[0-9a-f]{2})*")
_UINT32_MAX = (1 << 32) - 1
_REGISTERS = frozenset(
    {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
        "cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of",
        "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
    }
)
_EVIDENCE_CLASSES = frozenset(
    {
        "formal",
        "exhaustive",
        "solver",
        "differential",
        "fuzzed",
        "integration",
        "assumed",
        "unsupported",
    }
)
_STATUSES = frozenset({"qualified", "incomplete", "violated"})
_CALLING_CONVENTIONS = frozenset(
    {"machine_state", "cdecl", "stdcall", "fastcall", "thiscall", "custom"}
)
_LIVE_KINDS = frozenset(
    {"register", "flag", "x87", "memory", "resource", "external_world"}
)
_MEMORY_ACCESS = frozenset({"read", "write", "read_write"})
_CONTROL_KINDS = frozenset(
    {
        "fallthrough",
        "jump",
        "branch",
        "return",
        "indirect_jump",
        "external_jump",
        "terminate",
    }
)
_TYPE_BASES = frozenset({"checked", "inferred", "manual"})


@dataclass(frozen=True)
class RegionReplacementManifest:
    """A validated, canonical regional replacement contract."""

    payload: Mapping[str, Any]

    @property
    def id(self) -> str:
        return str(self.payload["id"])

    @property
    def manifest_sha256(self) -> str:
        return str(self.payload["manifest_sha256"])

    @property
    def cluster(self) -> Mapping[str, Any]:
        return _object(self.payload["cluster"], "replacement cluster")

    @property
    def source(self) -> Mapping[str, Any]:
        return _object(self.payload["source"], "replacement source")

    @property
    def support_sources(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            _object(item, "replacement support source")
            for item in self.payload.get("support_sources", [])
        )

    @property
    def bindings(self) -> Mapping[str, Any]:
        return _object(self.payload["bindings"], "replacement bindings")

    @property
    def evidence(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            _object(item, "replacement evidence")
            for item in _array(self.payload["evidence"], "replacement evidence")
        )

    def to_payload(self) -> dict[str, Any]:
        return _json_copy(self.payload)


@dataclass(frozen=True)
class RegionOverrideTableArtifacts:
    header: Path
    source: Path
    manifest: Path
    count: int


def write_region_replacement_manifest(
    path: Path,
    payload: Mapping[str, Any],
    *,
    source_root: Path,
) -> RegionReplacementManifest:
    """Canonicalize, bind, verify, and write a replacement manifest."""

    raw = _json_copy(payload)
    raw.pop("manifest_sha256", None)
    if raw.get("format") not in _REGION_REPLACEMENT_FORMATS:
        raise StageAInputError(
            "region replacement manifest must use a supported version: "
            f"{sorted(_REGION_REPLACEMENT_FORMATS)}"
        )
    normalized = _normalize_manifest(raw, expect_digest=False)
    normalized["manifest_sha256"] = _canonical_sha256(normalized)
    manifest = _parse_manifest(normalized)
    _verify_source_binding(manifest, Path(source_root))
    write_json(Path(path), manifest.to_payload())
    return manifest


def load_region_replacement_manifest(
    path: Path,
    *,
    source_root: Path,
) -> RegionReplacementManifest:
    payload = _read_json_object(Path(path), "region replacement manifest")
    manifest = _parse_manifest(payload)
    _verify_source_binding(manifest, Path(source_root))
    return manifest


def validate_region_replacement(
    *,
    manifest: Path | Mapping[str, Any] | RegionReplacementManifest,
    baseline_observations: Path | Mapping[str, Any],
    replacement_observations: Path | Mapping[str, Any],
    source_root: Path,
    out: Path | None = None,
) -> dict[str, Any]:
    """Compare candidate-only baseline and replacement observations.

    Structural absence or an invalid test setup is ``incomplete``.  A concrete
    difference in outputs, memory, control, faults, or external events is
    ``violated``.  A violated result dominates incomplete diagnostics because
    it is already a concrete counterexample to the regional contract.
    """

    contract = _coerce_manifest(manifest, source_root=Path(source_root))
    deltas: list[dict[str, Any]] = []
    for evidence in contract.evidence:
        status = str(evidence["status"])
        if status != "qualified":
            _append_delta(
                deltas,
                contract,
                status=status,
                family="evidence",
                case_id=None,
                path=f"/evidence/{_pointer(str(evidence['id']))}",
                expected="qualified",
                observed=status,
                message=f"evidence {evidence['id']} is not qualified",
                next_action="close or replace the named evidence before qualifying the region",
            )

    baseline = _load_observations_for_validation(
        baseline_observations, contract, "baseline", deltas
    )
    replacement = _load_observations_for_validation(
        replacement_observations, contract, "replacement", deltas
    )
    compared_cases = 0
    if baseline is not None and replacement is not None:
        baseline_cases = {case["id"]: case for case in baseline["cases"]}
        replacement_cases = {case["id"]: case for case in replacement["cases"]}
        if not baseline_cases:
            _append_delta(
                deltas,
                contract,
                status="incomplete",
                family="case_inventory",
                case_id=None,
                path="/cases",
                expected="at least one baseline case",
                observed=[],
                message="the baseline observation set is empty",
                next_action="capture candidate-only baseline observations for this region",
            )
        for case_id in sorted(set(baseline_cases) - set(replacement_cases)):
            _append_delta(
                deltas,
                contract,
                status="incomplete",
                family="case_inventory",
                case_id=case_id,
                path=f"/cases/{_pointer(case_id)}",
                expected="replacement observation",
                observed=None,
                message=f"replacement observations omit case {case_id}",
                next_action="run the replacement on the missing baseline case",
            )
        for case_id in sorted(set(replacement_cases) - set(baseline_cases)):
            _append_delta(
                deltas,
                contract,
                status="incomplete",
                family="case_inventory",
                case_id=case_id,
                path=f"/cases/{_pointer(case_id)}",
                expected="matching baseline observation",
                observed="replacement-only case",
                message=f"case {case_id} has no baseline observation",
                next_action="capture the same case from the generated baseline",
            )
        for case_id in sorted(set(baseline_cases) & set(replacement_cases)):
            baseline_case = baseline_cases[case_id]
            replacement_case = replacement_cases[case_id]
            _check_case_against_contract(
                contract, baseline_case, side="baseline", deltas=deltas
            )
            _check_case_against_contract(
                contract, replacement_case, side="replacement", deltas=deltas
            )
            _compare_cases(contract, baseline_case, replacement_case, deltas)
            compared_cases += 1

    deltas.sort(
        key=lambda item: (
            0 if item["status"] == "violated" else 1,
            item["family"],
            item["case_id"] or "",
            item["path"],
            item["id"],
        )
    )
    status = (
        "violated"
        if any(item["status"] == "violated" for item in deltas)
        else "incomplete"
        if deltas
        else "qualified"
    )
    report = {
        "format": REGION_REPLACEMENT_VALIDATION_FORMAT,
        "status": status,
        "executes_original_binary": False,
        "bindings": {
            "replacement_manifest_sha256": contract.manifest_sha256,
            "machine_ir_sha256": contract.bindings["machine_ir_sha256"],
            "baseline_program_sha256": contract.bindings[
                "baseline_program_sha256"
            ],
            "baseline_observations_sha256": (
                None if baseline is None else _canonical_sha256(baseline)
            ),
            "replacement_observations_sha256": (
                None if replacement is None else _canonical_sha256(replacement)
            ),
        },
        "counts": {
            "compared_cases": compared_cases,
            "deltas": len(deltas),
            "violated": sum(item["status"] == "violated" for item in deltas),
            "incomplete": sum(item["status"] == "incomplete" for item in deltas),
        },
        "deltas": deltas,
    }
    if out is not None:
        write_json(Path(out), report)
    return report


def generate_region_override_table(
    *,
    manifests: Sequence[Path | Mapping[str, Any] | RegionReplacementManifest],
    source_root: Path,
    out_dir: Path,
    runtime_header: str = "state-machine-runtime.h",
) -> RegionOverrideTableArtifacts:
    """Generate a deterministic interpreter override lookup table."""

    if not manifests:
        raise StageAInputError("region override table requires at least one manifest")
    runtime_header = _relative_path(runtime_header, "override runtime header")
    contracts = [
        _coerce_manifest(item, source_root=Path(source_root)) for item in manifests
    ]
    _validate_override_inventory(contracts)
    contracts.sort(key=lambda item: (int(item.cluster["entry_rva"]), item.id))

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    header_path = out_dir / "region-overrides.h"
    source_path = out_dir / "region-overrides.c"
    manifest_path = out_dir / "region-overrides-manifest.json"
    header_path.write_text(
        _render_override_header(contracts, runtime_header), encoding="ascii"
    )
    source_path.write_text(_render_override_source(contracts), encoding="ascii")

    entries = [_override_entry(contract) for contract in contracts]
    table_core = {
        "machine_ir_sha256": contracts[0].bindings["machine_ir_sha256"],
        "baseline_program_sha256": contracts[0].bindings[
            "baseline_program_sha256"
        ],
        "entries": entries,
    }
    payload = {
        "format": REGION_OVERRIDE_TABLE_FORMAT,
        "status": "ready",
        "executes_original_binary": False,
        "table_sha256": _canonical_sha256(table_core),
        **table_core,
        "artifacts": {
            "header": {"path": header_path.name, "sha256": sha256_file(header_path)},
            "source": {"path": source_path.name, "sha256": sha256_file(source_path)},
        },
        "checks": {
            "manifest_hashes": "verified",
            "source_hashes": "verified",
            "unique_ids": "verified",
            "unique_units": "verified",
            "unique_entry_rvas": "verified",
            "non_overlapping_rva_spans": "verified",
            "qualified_evidence": "verified",
        },
    }
    write_json(manifest_path, payload)
    return RegionOverrideTableArtifacts(
        header=header_path,
        source=source_path,
        manifest=manifest_path,
        count=len(contracts),
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
    _exact_fields(payload, {"id", "kind", "identity", "evidence_ids"}, context)
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "kind": _string(payload["kind"], f"{context}.kind"),
        "identity": _string(payload["identity"], f"{context}.identity"),
        "evidence_ids": _evidence_refs(payload["evidence_ids"], evidence, f"{context}.evidence_ids"),
    }


def _verify_source_binding(manifest: RegionReplacementManifest, root: Path) -> Path:
    root = root.resolve()
    source = manifest.source
    unresolved = root / str(source["path"])
    if unresolved.is_symlink():
        raise StageAInputError("replacement source must be a regular non-symlink file")
    path = unresolved.resolve()
    if path == root or root not in path.parents:
        raise StageAInputError("replacement source escapes its declared source root")
    if path.is_symlink() or not path.is_file():
        raise StageAInputError("replacement source must be a regular non-symlink file")
    if sha256_file(path) != source["sha256"]:
        raise StageAInputError("replacement source hash does not match its manifest")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise StageAInputError("replacement source must be UTF-8 text") from exc
    if int(source["line_end"]) > len(lines):
        raise StageAInputError("replacement source location exceeds the source file")
    selected = "\n".join(
        lines[int(source["line_start"]) - 1 : int(source["line_end"])]
    )
    if re.search(rf"\b{re.escape(str(source['symbol']))}\b", selected) is None:
        raise StageAInputError(
            "replacement source symbol is outside its declared source location"
        )
    for support in manifest.support_sources:
        unresolved_support = root / str(support["path"])
        if unresolved_support.is_symlink():
            raise StageAInputError(
                "replacement support source must be a regular non-symlink file"
            )
        support_path = unresolved_support.resolve()
        if support_path == root or root not in support_path.parents:
            raise StageAInputError("replacement support source escapes its source root")
        if support_path.is_symlink() or not support_path.is_file():
            raise StageAInputError("replacement support source must be a regular file")
        if sha256_file(support_path) != support["sha256"]:
            raise StageAInputError(
                "replacement support source hash does not match its manifest"
            )
    return path


def _load_observations_for_validation(
    value: Path | Mapping[str, Any],
    manifest: RegionReplacementManifest,
    side: str,
    deltas: list[dict[str, Any]],
) -> dict[str, Any] | None:
    try:
        payload = (
            _read_json_object(value, f"{side} region observations")
            if isinstance(value, Path)
            else _object(value, f"{side} region observations")
        )
        return _normalize_observations(payload, manifest)
    except (StageAInputError, OSError, json.JSONDecodeError) as exc:
        _append_delta(
            deltas,
            manifest,
            status="incomplete",
            family="observation_schema",
            case_id=None,
            path="/",
            expected=REGION_OBSERVATIONS_FORMAT,
            observed=str(exc),
            message=f"{side} observation artifact is unusable",
            next_action=f"regenerate structurally valid {side} observations",
        )
        return None


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
            "memory_views", "control", "fault", "external_events",
        },
        context,
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
            "memory_writes", "callbacks",
        },
        context,
    )
    return {
        "id": _identifier(payload["id"], f"{context}.id"),
        "kind": _string(payload["kind"], f"{context}.kind"),
        "identity": _string(payload["identity"], f"{context}.identity"),
        "arguments": _canonical_json_value(payload["arguments"], f"{context}.arguments"),
        "memory_reads": _canonical_json_value(payload["memory_reads"], f"{context}.memory_reads"),
        "result": _canonical_json_value(payload["result"], f"{context}.result"),
        "memory_writes": _canonical_json_value(payload["memory_writes"], f"{context}.memory_writes"),
        "callbacks": _canonical_json_value(payload["callbacks"], f"{context}.callbacks"),
    }


def _check_case_against_contract(
    manifest: RegionReplacementManifest,
    case: Mapping[str, Any],
    *,
    side: str,
    deltas: list[dict[str, Any]],
) -> None:
    case_id = str(case["id"])
    if case["entry_unit_id"] != manifest.cluster["entry_unit_id"]:
        _append_delta(
            deltas, manifest, status="incomplete", family="test_setup",
            case_id=case_id, path="/entry_unit_id",
            expected=manifest.cluster["entry_unit_id"], observed=case["entry_unit_id"],
            message=f"{side} case starts at the wrong unit",
            next_action="invoke both implementations at the declared cluster entry",
        )
    live = _object(manifest.payload["live_state"], "manifest live state")
    for field in ("live_inputs", "live_outputs"):
        declaration_field = "inputs" if field == "live_inputs" else "outputs"
        expected = {item["id"] for item in live[declaration_field]}
        observed = {item["id"] for item in case[field]}
        _inventory_deltas(
            manifest, deltas, side=side, case_id=case_id, family=field,
            expected=expected, observed=observed, path=f"/{field}",
        )
    view_declarations = {
        item["id"]: item for item in manifest.payload["memory_views"]
    }
    observed_views = {item["id"]: item for item in case["memory_views"]}
    _inventory_deltas(
        manifest, deltas, side=side, case_id=case_id, family="memory_view",
        expected=set(view_declarations), observed=set(observed_views), path="/memory_views",
    )
    for view_id in sorted(set(view_declarations) & set(observed_views)):
        declared_length = view_declarations[view_id]["byte_length"]
        if declared_length is None:
            continue
        for phase in ("before", "after"):
            observed_length = len(observed_views[view_id][phase]) // 2
            if observed_length != declared_length:
                _append_delta(
                    deltas, manifest, status="incomplete", family="memory_view",
                    case_id=case_id,
                    path=f"/memory_views/{_pointer(view_id)}/{phase}",
                    expected=declared_length, observed=observed_length,
                    message=f"{side} memory view {view_id} has the wrong byte length",
                    next_action="capture the complete declared memory view",
                )

    control = case["control"]
    control_catalog = {item["id"]: item for item in manifest.payload["expectations"]["control"]}
    expected_control = control_catalog.get(control["id"])
    if expected_control is None:
        _contract_expectation_delta(
            manifest, deltas, side, case_id, "control", "/control/id",
            sorted(control_catalog), control["id"], "control exit is not declared",
        )
    elif control["kind"] != expected_control["kind"] or not _control_target_allowed(
        control, expected_control
    ):
        _contract_expectation_delta(
            manifest, deltas, side, case_id, "control", "/control",
            expected_control, control, "control exit does not satisfy its declaration",
        )

    fault_contract = manifest.payload["expectations"]["fault"]
    fault_catalog = {item["id"]: item for item in fault_contract["variants"]}
    fault = case["fault"]
    if fault is None and not fault_contract["allow_none"]:
        _contract_expectation_delta(
            manifest, deltas, side, case_id, "fault", "/fault",
            "one declared fault", None, "a required fault is absent",
        )
    elif fault is not None:
        expected_fault = fault_catalog.get(fault["id"])
        if expected_fault is None or expected_fault["kind"] != fault["kind"]:
            _contract_expectation_delta(
                manifest, deltas, side, case_id, "fault", "/fault",
                sorted(fault_catalog), fault, "fault is not declared",
            )

    event_catalog = {
        item["id"]: item for item in manifest.payload["expectations"]["external_events"]
    }
    for index, event in enumerate(case["external_events"]):
        expected_event = event_catalog.get(event["id"])
        if (
            expected_event is None
            or expected_event["kind"] != event["kind"]
            or expected_event["identity"] != event["identity"]
        ):
            _contract_expectation_delta(
                manifest, deltas, side, case_id, "external_event",
                f"/external_events/{index}", expected_event, event,
                "external event is not declared",
            )


def _compare_cases(
    manifest: RegionReplacementManifest,
    baseline: Mapping[str, Any],
    replacement: Mapping[str, Any],
    deltas: list[dict[str, Any]],
) -> None:
    case_id = str(baseline["id"])
    _compare_id_values(
        manifest, deltas, case_id, "live_input", baseline["live_inputs"],
        replacement["live_inputs"], status="incomplete",
        next_action="run baseline and replacement from the same live input state",
    )
    _compare_id_values(
        manifest, deltas, case_id, "live_output", baseline["live_outputs"],
        replacement["live_outputs"], status="violated",
        next_action="repair the mapped replacement output expression",
    )
    baseline_views = {item["id"]: item for item in baseline["memory_views"]}
    replacement_views = {item["id"]: item for item in replacement["memory_views"]}
    for view_id in sorted(set(baseline_views) & set(replacement_views)):
        left = baseline_views[view_id]
        right = replacement_views[view_id]
        for field in ("base", "before"):
            if left[field] != right[field]:
                _append_delta(
                    deltas, manifest, status="incomplete", family="memory_input",
                    case_id=case_id,
                    path=f"/memory_views/{_pointer(view_id)}/{field}",
                    expected=left[field], observed=right[field],
                    message=f"memory view {view_id} did not start from the same state",
                    next_action="run baseline and replacement with identical mapped memory",
                )
        left_bytes = [left["after"][index:index + 2] for index in range(0, len(left["after"]), 2)]
        right_bytes = [right["after"][index:index + 2] for index in range(0, len(right["after"]), 2)]
        _recursive_differences(
            left_bytes,
            right_bytes,
            path=f"/memory_views/{_pointer(view_id)}/after",
            callback=lambda path, expected, observed: _append_delta(
                deltas, manifest, status="violated", family="memory_output",
                case_id=case_id, path=path, expected=expected, observed=observed,
                message=f"replacement changed memory view {view_id} differently",
                next_action="repair writes through the named memory view",
            ),
        )
    for family, field, next_action in (
        ("control", "control", "repair the replacement exit and target selection"),
        ("fault", "fault", "repair fault conditions and fault metadata"),
        (
            "external_event", "external_events",
            "repair the external call identity, ordering, arguments, effects, or callback protocol",
        ),
    ):
        _recursive_differences(
            baseline[field], replacement[field], path=f"/{field}",
            callback=lambda path, expected, observed, family=family, action=next_action: _append_delta(
                deltas, manifest, status="violated", family=family,
                case_id=case_id, path=path, expected=expected, observed=observed,
                message=f"replacement {family.replace('_', ' ')} differs from baseline",
                next_action=action,
            ),
        )


def _control_target_allowed(
    observed: Mapping[str, Any], expected: Mapping[str, Any]
) -> bool:
    unit_targets = set(expected["target_unit_ids"])
    rva_targets = set(expected["target_rvas"])
    observed_unit = observed["target_unit_id"]
    observed_rva = observed["target_rva"]
    target_values = set(expected.get("target_values", []))
    if expected["kind"] == "indirect_jump" and target_values:
        return (
            observed_unit is None
            and observed_rva is None
            and isinstance(observed["value"], int)
            and not isinstance(observed["value"], bool)
            and observed["value"] in target_values
        )
    if not unit_targets and not rva_targets:
        return observed_unit is None and observed_rva is None
    if observed_unit is None and observed_rva is None:
        return False
    if observed_unit is not None and observed_unit not in unit_targets:
        return False
    if observed_rva is not None and observed_rva not in rva_targets:
        return False
    return True


def _compare_id_values(
    manifest: RegionReplacementManifest,
    deltas: list[dict[str, Any]],
    case_id: str,
    family: str,
    baseline: Sequence[Mapping[str, Any]],
    replacement: Sequence[Mapping[str, Any]],
    *,
    status: str,
    next_action: str,
) -> None:
    left = {item["id"]: item["value"] for item in baseline}
    right = {item["id"]: item["value"] for item in replacement}
    for identity in sorted(set(left) & set(right)):
        _recursive_differences(
            left[identity], right[identity], path=f"/{family}s/{_pointer(identity)}/value",
            callback=lambda path, expected, observed: _append_delta(
                deltas, manifest, status=status, family=family,
                case_id=case_id, path=path, expected=expected, observed=observed,
                message=f"replacement {family.replace('_', ' ')} {identity} differs from baseline",
                next_action=next_action,
            ),
        )


def _recursive_differences(
    expected: Any,
    observed: Any,
    *,
    path: str,
    callback: Any,
) -> None:
    if type(expected) is not type(observed):
        callback(path, expected, observed)
        return
    if isinstance(expected, Mapping):
        for key in sorted(set(expected) | set(observed)):
            child = f"{path}/{_pointer(str(key))}"
            if key not in expected:
                callback(child, None, observed[key])
            elif key not in observed:
                callback(child, expected[key], None)
            else:
                _recursive_differences(expected[key], observed[key], path=child, callback=callback)
        return
    if isinstance(expected, list):
        for index in range(max(len(expected), len(observed))):
            child = f"{path}/{index}"
            if index >= len(expected):
                callback(child, None, observed[index])
            elif index >= len(observed):
                callback(child, expected[index], None)
            else:
                _recursive_differences(expected[index], observed[index], path=child, callback=callback)
        return
    if expected != observed:
        callback(path, expected, observed)


def _inventory_deltas(
    manifest: RegionReplacementManifest,
    deltas: list[dict[str, Any]],
    *,
    side: str,
    case_id: str,
    family: str,
    expected: set[str],
    observed: set[str],
    path: str,
) -> None:
    for identity in sorted(expected - observed):
        _append_delta(
            deltas, manifest, status="incomplete", family=family,
            case_id=case_id, path=f"{path}/{_pointer(identity)}",
            expected="declared observation", observed=None,
            message=f"{side} observations omit declared {family} {identity}",
            next_action=f"capture the complete {family} inventory",
        )
    for identity in sorted(observed - expected):
        _append_delta(
            deltas, manifest, status="incomplete", family=family,
            case_id=case_id, path=f"{path}/{_pointer(identity)}",
            expected=None, observed="undeclared observation",
            message=f"{side} observations contain undeclared {family} {identity}",
            next_action=f"update the contract or remove the stray {family} observation",
        )


def _contract_expectation_delta(
    manifest: RegionReplacementManifest,
    deltas: list[dict[str, Any]],
    side: str,
    case_id: str,
    family: str,
    path: str,
    expected: Any,
    observed: Any,
    message: str,
) -> None:
    _append_delta(
        deltas, manifest,
        status="incomplete" if side == "baseline" else "violated",
        family=family, case_id=case_id, path=path,
        expected=expected, observed=observed,
        message=f"{side} {message}",
        next_action=(
            "repair the baseline observation contract before using it as an oracle"
            if side == "baseline"
            else "repair the replacement to stay within the declared regional behavior"
        ),
    )


def _append_delta(
    deltas: list[dict[str, Any]],
    manifest: RegionReplacementManifest,
    *,
    status: str,
    family: str,
    case_id: str | None,
    path: str,
    expected: Any,
    observed: Any,
    message: str,
    next_action: str,
) -> None:
    source = manifest.source
    location = {
        "cluster_id": manifest.cluster["id"],
        "unit_ids": list(manifest.cluster["unit_ids"]),
        "rva_spans": _json_copy(manifest.cluster["rva_spans"]),
        "source": {
            "path": source["path"],
            "symbol": source["symbol"],
            "line_start": source["line_start"],
            "line_end": source["line_end"],
        },
    }
    core = {
        "status": status,
        "family": family,
        "case_id": case_id,
        "path": path,
        "expected": _json_copy(expected),
        "observed": _json_copy(observed),
        "location": location,
        "message": message,
        "next_action": next_action,
    }
    core["id"] = "region-delta-" + _canonical_sha256(core)[:20]
    deltas.append(core)


def _validate_override_inventory(contracts: Sequence[RegionReplacementManifest]) -> None:
    for contract in contracts:
        nonqualified = [item["id"] for item in contract.evidence if item["status"] != "qualified"]
        if nonqualified:
            raise StageAInputError(
                f"replacement {contract.id} has non-qualified evidence {nonqualified}"
            )
    for name, values in (
        ("replacement ids", [item.id for item in contracts]),
        ("cluster ids", [str(item.cluster["id"]) for item in contracts]),
        ("entry unit ids", [str(item.cluster["entry_unit_id"]) for item in contracts]),
        ("entry RVAs", [int(item.cluster["entry_rva"]) for item in contracts]),
        ("C symbols", [str(item.source["symbol"]) for item in contracts]),
    ):
        _require_unique(values, f"override {name}")
    unit_ids = [unit for item in contracts for unit in item.cluster["unit_ids"]]
    _require_unique(unit_ids, "override unit ids")
    bindings = {
        (
            item.bindings["machine_ir_sha256"],
            item.bindings["baseline_program_sha256"],
        )
        for item in contracts
    }
    if len(bindings) != 1:
        raise StageAInputError("override manifests do not bind the same machine IR and baseline")
    spans = [
        {**span, "replacement_id": item.id}
        for item in contracts
        for span in item.cluster["rva_spans"]
    ]
    spans.sort(key=lambda span: (span["start"], span["end"], span["replacement_id"]))
    for left, right in zip(spans, spans[1:]):
        if right["start"] < left["end"]:
            raise StageAInputError(
                "override RVA spans overlap between "
                f"{left['replacement_id']} and {right['replacement_id']}"
            )


def _render_override_header(
    contracts: Sequence[RegionReplacementManifest], runtime_header: str
) -> str:
    prototypes = "\n".join(
        f"stage_b_step_result {item.source['symbol']}(stage_b_runtime *, stage_b_machine_state *);"
        for item in contracts
    )
    return f"""#ifndef STAGE_B_REGION_OVERRIDES_H
#define STAGE_B_REGION_OVERRIDES_H

#include <stdint.h>
#include \"{runtime_header}\"

typedef stage_b_step_result (*stage_b_region_override_fn)(
    stage_b_runtime *, stage_b_machine_state *);

typedef struct stage_b_region_override {{
  uint32_t entry_rva;
  stage_b_region_override_fn function;
  const char *replacement_id;
  const char *cluster_id;
}} stage_b_region_override;

{prototypes}

extern const stage_b_region_override stage_b_region_overrides[];
extern const uint32_t stage_b_region_override_count;
const stage_b_region_override *stage_b_region_override_lookup(uint32_t entry_rva);

#endif
"""


def _render_override_source(contracts: Sequence[RegionReplacementManifest]) -> str:
    entries = "\n".join(
        "  { UINT32_C(%d), %s, %s, %s },"
        % (
            int(item.cluster["entry_rva"]),
            item.source["symbol"],
            _c_string(item.id),
            _c_string(str(item.cluster["id"])),
        )
        for item in contracts
    )
    return f"""#include <stdint.h>
#include \"region-overrides.h\"

const stage_b_region_override stage_b_region_overrides[] = {{
{entries}
}};

const uint32_t stage_b_region_override_count =
    (uint32_t)(sizeof(stage_b_region_overrides) / sizeof(stage_b_region_overrides[0]));

const stage_b_region_override *stage_b_region_override_lookup(uint32_t entry_rva) {{
  uint32_t low = 0U, high = stage_b_region_override_count;
  while (low < high) {{
    uint32_t middle = low + (high - low) / 2U;
    uint32_t observed = stage_b_region_overrides[middle].entry_rva;
    if (observed < entry_rva) low = middle + 1U;
    else if (observed > entry_rva) high = middle;
    else return &stage_b_region_overrides[middle];
  }}
  return (const stage_b_region_override *)0;
}}
"""


def _override_entry(contract: RegionReplacementManifest) -> dict[str, Any]:
    return {
        "replacement_id": contract.id,
        "manifest_sha256": contract.manifest_sha256,
        "cluster_id": contract.cluster["id"],
        "entry_unit_id": contract.cluster["entry_unit_id"],
        "entry_rva": contract.cluster["entry_rva"],
        "unit_ids": list(contract.cluster["unit_ids"]),
        "rva_spans": _json_copy(contract.cluster["rva_spans"]),
        "symbol": contract.source["symbol"],
        "source": _json_copy(contract.source),
        "support_sources": _json_copy(contract.support_sources),
    }


def _coerce_manifest(
    value: Path | Mapping[str, Any] | RegionReplacementManifest,
    *,
    source_root: Path,
) -> RegionReplacementManifest:
    if isinstance(value, RegionReplacementManifest):
        manifest = _parse_manifest(value.to_payload())
        _verify_source_binding(manifest, source_root)
        return manifest
    if isinstance(value, Path):
        return load_region_replacement_manifest(value, source_root=source_root)
    manifest = _parse_manifest(_object(value, "region replacement manifest"))
    _verify_source_binding(manifest, source_root)
    return manifest


def _read_json_object(path: Path, context: str) -> Mapping[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise StageAInputError(f"{context} must be a regular non-symlink file")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context}: {exc}") from exc
    return _object(payload, context)


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


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


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, ensure_ascii=True))


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    return value


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


def _pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


__all__ = [
    "REGION_OBSERVATIONS_FORMAT",
    "REGION_OVERRIDE_TABLE_FORMAT",
    "REGION_REPLACEMENT_FORMAT",
    "REGION_REPLACEMENT_BUNDLE_FORMAT",
    "REGION_REPLACEMENT_VALIDATION_FORMAT",
    "RegionOverrideTableArtifacts",
    "RegionReplacementManifest",
    "generate_region_override_table",
    "load_region_replacement_manifest",
    "validate_region_replacement",
    "write_region_replacement_manifest",
]
