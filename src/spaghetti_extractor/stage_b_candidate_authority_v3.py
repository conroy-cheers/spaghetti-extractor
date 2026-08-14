"""Fail-closed v3 authority receipt for Stage B candidate generation.

This module validates static artifacts only.  It neither executes nor permits
execution of the original program.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .analysis_v3.final_authority import (
    FINAL_AUTHORITY_ARTIFACT_KIND_V3,
    FINAL_AUTHORITY_CODEC_V3,
    FinalAuthorityRecordV3,
)
from .artifact_formats import MACHINE_IR_FORMAT
from .artifact_set_v3 import (
    ArtifactSetReaderV3,
    ArtifactV3Error,
    canonical_json_bytes_v3,
    canonical_sha256_v3,
    parse_canonical_json_v3,
)
from .stage_b_fallback_coverage import FALLBACK_COVERAGE_RECEIPT_FORMAT
from .components.formats import (
    COMPONENT_RUNTIME_COMPLETION_V3_FORMAT,
    COMPONENT_RUNTIME_PACKAGE_V3_FORMAT,
)


STAGE_B_CANDIDATE_AUTHORITY_V3_FORMAT = (
    "spaghetti-extractor-stage-b-candidate-authority-receipt-v3"
)
STAGE_B_CANDIDATE_AUTHORITY_V3_VERSION = 3

_CONTENT_ID_RE = re.compile(r"stage-b-candidate-authority-v3:[0-9a-f]{64}")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_AUTHORITY = "stage_b_candidate_generation_only"
_POLICY = {
    "candidate_generation_fails_closed": True,
    "candidate_generation_only": True,
    "complete_fallback_coverage_required": True,
    "component_runtime_package_required": True,
    "exact_machine_ir_binding_required": True,
    "final_authority_v3_required": True,
    "original_execution_forbidden": True,
}
_CHECK_NAMES = frozenset({
    "candidate_only_policy",
    "exact_unit_count_agrees",
    "exact_unit_inventory_agrees",
    "exact_universe_agrees",
    "fallback_coverage_complete",
    "fallback_exact_inputs_agree",
    "component_runtime_complete",
    "component_runtime_exact_inputs_agree",
    "final_artifact_complete",
    "final_artifact_kind",
    "final_record_authorizing",
    "final_record_complete",
    "final_record_unique",
    "machine_ir_manifest_binds_exact_bytes",
    "pe_sha256_agrees",
})
_FALLBACK_POLICY = {
    "candidate_generation_fails_closed": True,
    "one_implementation_kind_per_structural_unit": True,
    "potential_transfers_may_be_deferred": False,
    "rooted_containment_authority": False,
    "structural_units_require_lowering": True,
}


class CandidateAuthorityV3Error(ValueError):
    """A v3 candidate receipt or one of its exact inputs is invalid."""


class CandidateAuthorityV3Status(str, Enum):
    AUTHORIZED = "authorized"
    INCOMPLETE = "incomplete"
    VIOLATED = "violated"


@dataclass(frozen=True, order=True)
class CandidateAuthorityV3Issue:
    status: CandidateAuthorityV3Status
    code: str
    detail: str

    def __post_init__(self) -> None:
        if self.status is CandidateAuthorityV3Status.AUTHORIZED:
            raise CandidateAuthorityV3Error("an issue cannot be authorized")
        if not self.code or not self.detail:
            raise CandidateAuthorityV3Error("an issue requires code and detail")

    def to_payload(self) -> dict[str, str]:
        return {
            "status": self.status.value,
            "code": self.code,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CandidateAuthorityV3Receipt:
    status: CandidateAuthorityV3Status
    inputs: Mapping[str, Any]
    checks: Mapping[str, bool]
    issues: tuple[CandidateAuthorityV3Issue, ...]
    content_id: str

    @property
    def authorizing(self) -> bool:
        return self.status is CandidateAuthorityV3Status.AUTHORIZED

    @property
    def authorizes(self) -> bool:
        return self.authorizing

    def _core_payload(self) -> dict[str, Any]:
        return {
            "format": STAGE_B_CANDIDATE_AUTHORITY_V3_FORMAT,
            "schema_version": STAGE_B_CANDIDATE_AUTHORITY_V3_VERSION,
            "status": self.status.value,
            "authorizing": self.authorizing,
            "authority": _AUTHORITY,
            "policy": dict(_POLICY),
            "inputs": _json_value(self.inputs),
            "checks": _json_value(self.checks),
            "issues": [issue.to_payload() for issue in self.issues],
        }

    def to_payload(self) -> dict[str, Any]:
        core = self._core_payload()
        return {**core, "content_id": _content_id(core)}

    def to_bytes(self) -> bytes:
        return canonical_json_bytes_v3(self.to_payload())

    def to_json(self) -> str:
        return self.to_bytes().decode("ascii")


class CandidateAuthorityV3GateError(CandidateAuthorityV3Error):
    def __init__(self, receipt: CandidateAuthorityV3Receipt) -> None:
        self.status = receipt.status
        self.issues = receipt.issues
        codes = ", ".join(issue.code for issue in receipt.issues) or "unknown"
        super().__init__(f"candidate generation is {receipt.status.value}: {codes}")


@dataclass(frozen=True)
class _MachineUnit:
    unit_id: str
    rva: int
    contract_sha256: str
    instruction_bytes_sha256: str
    unit_ir_sha256: str


@dataclass(frozen=True)
class _MachineIR:
    sha256: str
    units: tuple[_MachineUnit, ...]

    @property
    def inventory_sha256(self) -> str:
        return canonical_sha256_v3([row.unit_id for row in self.units])

    def exact_universe_sha256(self, pe_sha256: str) -> str:
        return canonical_sha256_v3({
            "pe_sha256": pe_sha256,
            "units": [
                {"id": row.unit_id, "unit_ir_sha256": row.unit_ir_sha256}
                for row in self.units
            ],
        })


@dataclass(frozen=True)
class _MachineManifest:
    sha256: str
    pe_sha256: str


@dataclass
class _Decision:
    issues: list[CandidateAuthorityV3Issue]
    checks: dict[str, bool]

    def incomplete(self, code: str, detail: str) -> None:
        self.issues.append(CandidateAuthorityV3Issue(
            CandidateAuthorityV3Status.INCOMPLETE, code, detail
        ))

    def violated(self, code: str, detail: str) -> None:
        self.issues.append(CandidateAuthorityV3Issue(
            CandidateAuthorityV3Status.VIOLATED, code, detail
        ))


def build_stage_b_candidate_authority_v3(
    *,
    final_authority: Path | str,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    fallback_coverage_receipt: Path | str,
    component_runtime_package: Path | str,
) -> CandidateAuthorityV3Receipt:
    """Recompute candidate authority from exact v3/static input artifacts."""

    decision = _Decision([], {name: False for name in _CHECK_NAMES})
    decision.checks["candidate_only_policy"] = True

    machine = _load_machine_ir(Path(machine_ir), decision)
    manifest = _load_machine_manifest(
        Path(machine_ir_manifest), machine=machine, decision=decision
    )
    final, final_binding = _load_final_authority(
        Path(final_authority), decision
    )
    fallback_binding = _check_fallback_coverage(
        Path(fallback_coverage_receipt),
        machine=machine,
        manifest=manifest,
        decision=decision,
    )
    component_runtime_binding = _check_component_runtime(
        Path(component_runtime_package),
        machine=machine,
        fallback_binding=fallback_binding,
        decision=decision,
    )

    if machine is not None and manifest is not None and final is not None:
        pe_agrees = (
            final.status == "complete"
            and final.pe_sha256 == manifest.pe_sha256
        )
        decision.checks["pe_sha256_agrees"] = pe_agrees
        if final.status == "complete" and not pe_agrees:
            decision.violated(
                "final_authority_pe_mismatch",
                "final authority binds a different PE than the machine-IR manifest",
            )

        count_agrees = final.exact_unit_count == len(machine.units)
        decision.checks["exact_unit_count_agrees"] = count_agrees
        if not count_agrees:
            decision.violated(
                "final_authority_unit_count_mismatch",
                "final authority exact-unit count is stale",
            )

        inventory_agrees = (
            final.exact_unit_inventory_sha256 == machine.inventory_sha256
        )
        decision.checks["exact_unit_inventory_agrees"] = inventory_agrees
        if not inventory_agrees:
            decision.violated(
                "final_authority_unit_inventory_mismatch",
                "final authority exact-unit inventory is stale",
            )

        universe_agrees = (
            final.status == "complete"
            and final.exact_universe_sha256
            == machine.exact_universe_sha256(manifest.pe_sha256)
        )
        decision.checks["exact_universe_agrees"] = universe_agrees
        if final.status == "complete" and not universe_agrees:
            decision.violated(
                "final_authority_exact_universe_mismatch",
                "final authority does not bind the exact machine-IR unit content",
            )

    inputs = {
        "final_authority": final_binding,
        "machine_ir": {
            "format": MACHINE_IR_FORMAT if machine is not None else None,
            "sha256": None if machine is None else machine.sha256,
            "unit_count": None if machine is None else len(machine.units),
            "unit_inventory_sha256": (
                None if machine is None else machine.inventory_sha256
            ),
        },
        "machine_ir_manifest": {
            "format": MACHINE_IR_FORMAT if manifest is not None else None,
            "sha256": None if manifest is None else manifest.sha256,
            "pe_sha256": None if manifest is None else manifest.pe_sha256,
        },
        "fallback_coverage_receipt": fallback_binding,
        "component_runtime_package": component_runtime_binding,
    }

    issues = tuple(sorted(set(decision.issues), key=_issue_key))
    status = _status_from_issues(issues)
    checks = dict(sorted(decision.checks.items()))
    if status is CandidateAuthorityV3Status.AUTHORIZED and not all(checks.values()):
        issues = (*issues, CandidateAuthorityV3Issue(
            CandidateAuthorityV3Status.VIOLATED,
            "authorizing_check_false",
            "an authorizing check is false without a corresponding issue",
        ))
        issues = tuple(sorted(set(issues), key=_issue_key))
        status = CandidateAuthorityV3Status.VIOLATED
    provisional = CandidateAuthorityV3Receipt(
        status=status,
        inputs=inputs,
        checks=checks,
        issues=issues,
        content_id="stage-b-candidate-authority-v3:" + "0" * 64,
    )
    return CandidateAuthorityV3Receipt(
        status=status,
        inputs=inputs,
        checks=checks,
        issues=issues,
        content_id=_content_id(provisional._core_payload()),
    )


def parse_stage_b_candidate_authority_v3(
    value: Mapping[str, Any] | str | bytes,
) -> CandidateAuthorityV3Receipt:
    """Parse canonical receipt JSON and rederive every local integrity field."""

    if isinstance(value, (str, bytes)):
        raw = value.encode("ascii") if isinstance(value, str) else value
        try:
            value = parse_canonical_json_v3(raw, location="candidate receipt")
        except (UnicodeError, ArtifactV3Error) as exc:
            raise CandidateAuthorityV3Error(str(exc)) from exc
    row = _strict_object(
        value,
        {
            "format", "schema_version", "status", "authorizing", "authority",
            "policy", "inputs", "checks", "issues", "content_id",
        },
        "candidate receipt",
    )
    if (
        row["format"] != STAGE_B_CANDIDATE_AUTHORITY_V3_FORMAT
        or row["schema_version"] != STAGE_B_CANDIDATE_AUTHORITY_V3_VERSION
    ):
        raise CandidateAuthorityV3Error("receipt is not candidate authority v3")
    if row["authority"] != _AUTHORITY or row["policy"] != _POLICY:
        raise CandidateAuthorityV3Error("candidate scope or policy is stale")
    try:
        status = CandidateAuthorityV3Status(row["status"])
    except (TypeError, ValueError) as exc:
        raise CandidateAuthorityV3Error("candidate status is invalid") from exc
    if row["authorizing"] is not (status is CandidateAuthorityV3Status.AUTHORIZED):
        raise CandidateAuthorityV3Error("candidate authorization bit is stale")
    inputs = _strict_object(
        row["inputs"],
        {
            "final_authority", "machine_ir", "machine_ir_manifest",
            "fallback_coverage_receipt",
            "component_runtime_package",
        },
        "candidate inputs",
    )
    checks = _strict_object(row["checks"], set(_CHECK_NAMES), "candidate checks")
    if any(not isinstance(item, bool) for item in checks.values()):
        raise CandidateAuthorityV3Error("candidate checks must be Boolean")
    raw_issues = row["issues"]
    if not isinstance(raw_issues, list):
        raise CandidateAuthorityV3Error("candidate issues must be an array")
    issues = tuple(_parse_issue(item) for item in raw_issues)
    if issues != tuple(sorted(set(issues), key=_issue_key)):
        raise CandidateAuthorityV3Error("candidate issues are not sorted and unique")
    if _status_from_issues(issues) is not status:
        raise CandidateAuthorityV3Error("candidate status is stale")
    if status is CandidateAuthorityV3Status.AUTHORIZED and not all(checks.values()):
        raise CandidateAuthorityV3Error("authorized receipt contains a failed check")
    content_id = row["content_id"]
    if not isinstance(content_id, str) or _CONTENT_ID_RE.fullmatch(content_id) is None:
        raise CandidateAuthorityV3Error("candidate content ID is malformed")
    receipt = CandidateAuthorityV3Receipt(
        status=status,
        inputs=_json_value(inputs),
        checks=_json_value(checks),
        issues=issues,
        content_id=content_id,
    )
    if receipt.to_payload() != _json_value(row):
        raise CandidateAuthorityV3Error("candidate content ID is stale")
    return receipt


def validate_stage_b_candidate_authority_v3(
    *,
    receipt: Path | str | Mapping[str, Any] | CandidateAuthorityV3Receipt,
    final_authority: Path | str,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    fallback_coverage_receipt: Path | str,
    component_runtime_package: Path | str,
    require_authorized: bool = True,
) -> CandidateAuthorityV3Receipt:
    """Reject a receipt unless it exactly equals a fresh input recomputation."""

    if isinstance(receipt, CandidateAuthorityV3Receipt):
        actual = parse_stage_b_candidate_authority_v3(receipt.to_payload())
    elif isinstance(receipt, Mapping):
        actual = parse_stage_b_candidate_authority_v3(receipt)
    else:
        try:
            actual = parse_stage_b_candidate_authority_v3(Path(receipt).read_bytes())
        except OSError as exc:
            raise CandidateAuthorityV3Error(f"cannot read candidate receipt: {exc}") from exc
    expected = build_stage_b_candidate_authority_v3(
        final_authority=final_authority,
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
        fallback_coverage_receipt=fallback_coverage_receipt,
        component_runtime_package=component_runtime_package,
    )
    if actual.to_payload() != expected.to_payload():
        raise CandidateAuthorityV3Error(
            "candidate receipt is stale or binds different inputs"
        )
    if require_authorized:
        require_stage_b_candidate_authority_v3(actual)
    return actual


def require_stage_b_candidate_authority_v3(
    receipt: CandidateAuthorityV3Receipt,
) -> CandidateAuthorityV3Receipt:
    if not isinstance(receipt, CandidateAuthorityV3Receipt):
        raise CandidateAuthorityV3Error("candidate gate requires a parsed v3 receipt")
    if not receipt.authorizing:
        raise CandidateAuthorityV3GateError(receipt)
    return receipt


def _load_machine_ir(path: Path, decision: _Decision) -> _MachineIR | None:
    if not path.is_file():
        decision.incomplete("machine_ir_missing", "exact machine-IR JSONL is missing")
        return None
    try:
        data = path.read_bytes()
        units: list[_MachineUnit] = []
        seen_ids: set[str] = set()
        seen_rvas: set[int] = set()
        for line_number, line in enumerate(data.splitlines(), start=1):
            if not line.strip():
                continue
            value = parse_canonical_json_v3(
                line, location=f"{path}:{line_number}"
            )
            row = _mapping(value, f"machine-IR line {line_number}")
            if row.get("format") != MACHINE_IR_FORMAT or row.get("record_kind") != "unit":
                raise CandidateAuthorityV3Error(
                    f"machine-IR line {line_number} is not one exact unit"
                )
            unit_id = _text(row.get("id"), "machine-IR unit ID")
            source = _mapping(row.get("source"), f"{unit_id} source")
            original = _mapping(source.get("original"), f"{unit_id} original span")
            rva = _uint(original.get("rva_start"), f"{unit_id} start RVA")
            end = _uint(original.get("rva_end"), f"{unit_id} end RVA")
            if end <= rva or unit_id in seen_ids or rva in seen_rvas:
                raise CandidateAuthorityV3Error(
                    "machine IR has a duplicate identity/RVA or invalid unit span"
                )
            seen_ids.add(unit_id)
            seen_rvas.add(rva)
            units.append(_MachineUnit(
                unit_id=unit_id,
                rva=rva,
                contract_sha256=_digest(
                    source.get("contract_sha256"), f"{unit_id} contract SHA-256"
                ),
                instruction_bytes_sha256=_digest(
                    source.get("instruction_bytes_sha256"),
                    f"{unit_id} instruction-byte SHA-256",
                ),
                unit_ir_sha256=hashlib.sha256(line).hexdigest(),
            ))
        if not units:
            decision.incomplete(
                "machine_ir_empty", "exact machine-IR JSONL contains no units"
            )
            return None
        return _MachineIR(
            sha256=hashlib.sha256(data).hexdigest(),
            units=tuple(sorted(units, key=lambda row: row.unit_id)),
        )
    except (OSError, ArtifactV3Error, CandidateAuthorityV3Error) as exc:
        decision.violated("machine_ir_corrupt", str(exc))
        return None


def _load_machine_manifest(
    path: Path, *, machine: _MachineIR | None, decision: _Decision
) -> _MachineManifest | None:
    if not path.is_file():
        decision.incomplete(
            "machine_ir_manifest_missing", "machine-IR manifest is missing"
        )
        return None
    try:
        data = path.read_bytes()
        row = _read_json_object(data, "machine-IR manifest")
        if row.get("format") != MACHINE_IR_FORMAT:
            raise CandidateAuthorityV3Error("machine-IR manifest format is wrong")
        artifact = _mapping(
            _mapping(row.get("artifacts"), "machine-IR artifacts").get("machine_ir"),
            "machine-IR artifact binding",
        )
        if artifact.get("format") != MACHINE_IR_FORMAT:
            raise CandidateAuthorityV3Error("manifest machine-IR format is wrong")
        bound_machine = _digest(
            artifact.get("sha256"), "manifest machine-IR SHA-256"
        )
        counts = _mapping(row.get("counts"), "machine-IR counts")
        unit_count = _uint(counts.get("units"), "manifest unit count")
        candidates: list[str] = []
        binary = row.get("binary")
        if isinstance(binary, Mapping) and binary.get("sha256") is not None:
            candidates.append(_digest(binary.get("sha256"), "manifest PE SHA-256"))
        inputs = row.get("inputs")
        if isinstance(inputs, Mapping):
            original = inputs.get("original_pe")
            if isinstance(original, Mapping) and original.get("sha256") is not None:
                candidates.append(_digest(
                    original.get("sha256"), "manifest original PE SHA-256"
                ))
        if not candidates:
            decision.incomplete(
                "manifest_pe_binding_missing", "machine-IR manifest lacks a PE hash"
            )
            return None
        if len(set(candidates)) != 1:
            raise CandidateAuthorityV3Error("machine-IR manifest PE hashes conflict")
        exact = (
            machine is not None
            and bound_machine == machine.sha256
            and unit_count == len(machine.units)
        )
        decision.checks["machine_ir_manifest_binds_exact_bytes"] = exact
        if machine is not None and not exact:
            decision.violated(
                "machine_ir_manifest_binding_mismatch",
                "manifest does not bind the exact JSONL bytes and unit count",
            )
        return _MachineManifest(
            sha256=hashlib.sha256(data).hexdigest(), pe_sha256=candidates[0]
        )
    except (OSError, UnicodeError, json.JSONDecodeError, CandidateAuthorityV3Error) as exc:
        decision.violated("machine_ir_manifest_corrupt", str(exc))
        return None


def _load_final_authority(
    path: Path, decision: _Decision
) -> tuple[FinalAuthorityRecordV3 | None, dict[str, Any]]:
    binding = {
        "artifact_kind": None,
        "artifact_id": None,
        "manifest_sha256": None,
        "record_id": None,
        "record_sha256": None,
    }
    try:
        reader = ArtifactSetReaderV3(path)
        manifest = reader.manifest
        binding.update({
            "artifact_kind": manifest.artifact_kind,
            "artifact_id": manifest.artifact_id,
            "manifest_sha256": reader.manifest_sha256,
        })
        kind_ok = manifest.artifact_kind == FINAL_AUTHORITY_ARTIFACT_KIND_V3
        decision.checks["final_artifact_kind"] = kind_ok
        if not kind_ok:
            decision.violated(
                "final_authority_artifact_kind_mismatch",
                "artifact is not final-authority-v3",
            )
        artifact_complete = manifest.status == "complete"
        decision.checks["final_artifact_complete"] = artifact_complete
        if manifest.status == "incomplete":
            decision.incomplete(
                "final_authority_artifact_incomplete",
                "final-authority-v3 ArtifactSet is incomplete",
            )
        elif not artifact_complete:
            decision.violated(
                "final_authority_artifact_violated",
                "final-authority-v3 ArtifactSet is violated",
            )
        records = tuple(reader.iter_records())
        unique = len(records) == 1
        decision.checks["final_record_unique"] = unique
        if not records:
            decision.incomplete(
                "final_authority_record_missing", "final authority record is missing"
            )
            return None, binding
        if not unique:
            decision.violated(
                "final_authority_record_ambiguous",
                "final authority ArtifactSet contains more than one record",
            )
            return None, binding
        source = records[0]
        binding["record_id"] = source.record_id
        binding["record_sha256"] = hashlib.sha256(source.value.data).hexdigest()
        typed = FINAL_AUTHORITY_CODEC_V3.read(source).value
        if typed.record_id != source.record_id:
            decision.violated(
                "final_authority_envelope_mismatch",
                "typed final authority ID differs from its ArtifactSet envelope",
            )
        complete = typed.status == "complete"
        authorizing = typed.authorizing
        decision.checks["final_record_complete"] = complete
        decision.checks["final_record_authorizing"] = authorizing
        if typed.status == "incomplete":
            decision.incomplete(
                "final_authority_incomplete", "final authority record is incomplete"
            )
        elif typed.status == "violated":
            decision.violated(
                "final_authority_violated", "final authority record is violated"
            )
        elif not complete or not authorizing:
            decision.violated(
                "final_authority_not_authorizing",
                "final authority record is not complete and authorizing",
            )
        return typed, binding
    except ArtifactV3Error as exc:
        if exc.code == "missing_manifest":
            decision.incomplete(
                "final_authority_missing", "final-authority-v3 ArtifactSet is missing"
            )
        else:
            decision.violated("final_authority_corrupt", str(exc))
        return None, binding


def _check_fallback_coverage(
    path: Path,
    *,
    machine: _MachineIR | None,
    manifest: _MachineManifest | None,
    decision: _Decision,
) -> dict[str, Any]:
    binding = {
        "format": None,
        "artifact_sha256": None,
        "receipt_sha256": None,
        "portable_selection_artifact_sha256": None,
    }
    if not path.is_file():
        decision.incomplete(
            "fallback_coverage_missing", "fallback-coverage receipt is missing"
        )
        return binding
    try:
        data = path.read_bytes()
        receipt = _read_json_object(data, "fallback-coverage receipt")
        binding["artifact_sha256"] = hashlib.sha256(data).hexdigest()
        binding["format"] = receipt.get("format")
        binding["receipt_sha256"] = receipt.get("receipt_sha256")
        if receipt.get("format") != FALLBACK_COVERAGE_RECEIPT_FORMAT:
            raise CandidateAuthorityV3Error("fallback receipt format is wrong")
        status = receipt.get("status")
        if status == "incomplete":
            decision.incomplete(
                "fallback_coverage_incomplete", "fallback coverage is incomplete"
            )
        elif status == "violated":
            decision.violated(
                "fallback_coverage_violated", "fallback coverage is violated"
            )
        elif status != "complete":
            raise CandidateAuthorityV3Error("fallback status is invalid")
        declared = _digest(
            receipt.get("receipt_sha256"), "fallback receipt SHA-256"
        )
        body = dict(receipt)
        body.pop("receipt_sha256")
        identity_ok = declared == canonical_sha256_v3(body)
        if not identity_ok:
            decision.violated(
                "fallback_coverage_identity_stale",
                "fallback receipt identity does not bind its canonical payload",
            )
        policy = _mapping(receipt.get("policy"), "fallback policy")
        policy_ok = all(policy.get(key) == expected for key, expected in _FALLBACK_POLICY.items())
        if not policy_ok:
            decision.violated(
                "fallback_coverage_policy_unsafe",
                "fallback receipt does not preserve fail-closed candidate-only policy",
            )
        inputs = _mapping(receipt.get("inputs"), "fallback inputs")
        portable = inputs.get("portable_replacements")
        if isinstance(portable, Mapping):
            artifact = portable.get("artifact")
            if isinstance(artifact, Mapping):
                binding["portable_selection_artifact_sha256"] = artifact.get("sha256")
        machine_binding = _mapping(inputs.get("machine_ir"), "fallback machine IR")
        manifest_binding = _mapping(
            inputs.get("machine_ir_manifest"), "fallback machine-IR manifest"
        )
        exact_inputs = (
            machine is not None
            and manifest is not None
            and machine_binding.get("sha256") == machine.sha256
            and manifest_binding.get("sha256") == manifest.sha256
        )
        decision.checks["fallback_exact_inputs_agree"] = exact_inputs
        if machine is not None and manifest is not None and not exact_inputs:
            decision.violated(
                "fallback_coverage_input_mismatch",
                "fallback receipt binds different machine-IR inputs",
            )
        blockers = receipt.get("blockers")
        entries = receipt.get("entries")
        counts = receipt.get("counts")
        if not isinstance(blockers, list) or not isinstance(entries, list) or not isinstance(counts, Mapping):
            raise CandidateAuthorityV3Error("fallback inventories are malformed")
        entries_ok = machine is not None and _fallback_entries_match(entries, machine)
        counts_ok = machine is not None and _fallback_counts_match(
            counts, entries=entries, blockers=blockers, unit_count=len(machine.units)
        )
        if (
            status == "complete"
            and machine is not None
            and (blockers or not entries_ok or not counts_ok)
        ):
            decision.violated(
                "fallback_coverage_claim_conflict",
                "complete fallback receipt does not exactly cover every machine-IR unit",
            )
        complete = (
            status == "complete"
            and identity_ok
            and policy_ok
            and exact_inputs
            and not blockers
            and entries_ok
            and counts_ok
        )
        decision.checks["fallback_coverage_complete"] = complete
        return binding
    except (OSError, UnicodeError, json.JSONDecodeError, CandidateAuthorityV3Error) as exc:
        decision.violated("fallback_coverage_corrupt", str(exc))
        return binding


def _check_component_runtime(
    path: Path,
    *,
    machine: _MachineIR | None,
    fallback_binding: Mapping[str, Any],
    decision: _Decision,
) -> dict[str, Any]:
    manifest_path = path / "component-runtime-package.json" if path.is_dir() else path
    binding: dict[str, Any] = {
        "format": None,
        "artifact_sha256": None,
        "runtime_package_sha256": None,
        "completion_sha256": None,
        "portable_selection_artifact_sha256": None,
    }
    if not manifest_path.is_file():
        decision.incomplete(
            "component_runtime_missing", "component runtime package is missing"
        )
        return binding
    try:
        data = manifest_path.read_bytes()
        payload = _read_json_object(data, "component runtime package")
        binding["format"] = payload.get("format")
        binding["artifact_sha256"] = hashlib.sha256(data).hexdigest()
        binding["runtime_package_sha256"] = payload.get("runtime_package_sha256")
        if payload.get("format") != COMPONENT_RUNTIME_PACKAGE_V3_FORMAT:
            raise CandidateAuthorityV3Error("component runtime format is wrong")
        body = dict(payload)
        declared = _digest(
            body.pop("runtime_package_sha256", None),
            "component runtime package SHA-256",
        )
        identity_ok = declared == canonical_sha256_v3(body)
        if not identity_ok:
            decision.violated(
                "component_runtime_identity_stale",
                "component runtime identity does not bind its canonical payload",
            )
        policy = _mapping(payload.get("policy"), "component runtime policy")
        policy_ok = (
            policy.get("runtime_package_is_sole_candidate_authority") is True
            and policy.get("enabled_components_must_be_qualified") is True
            and policy.get("subsumed_members_may_not_fallback") is True
            and policy.get("fallback_on_unimplemented") is False
            and policy.get("original_execution_forbidden") is True
            and payload.get("executes_original_binary") is False
        )
        if not policy_ok:
            decision.violated(
                "component_runtime_policy_unsafe",
                "component runtime does not preserve fail-closed activation policy",
            )
        inputs = _mapping(payload.get("bindings"), "component runtime bindings")
        exact_machine = machine is not None and inputs.get("machine_ir_sha256") == machine.sha256
        artifacts = _mapping(payload.get("artifacts"), "component runtime artifacts")
        selection = _mapping(
            artifacts.get("portable_selection"), "portable component selection"
        )
        selection_name = selection.get("path")
        if (
            not isinstance(selection_name, str)
            or not selection_name
            or Path(selection_name).name != selection_name
        ):
            raise CandidateAuthorityV3Error(
                "portable component selection path is not local"
            )
        selection_path = manifest_path.parent / selection_name
        selection_sha256 = hashlib.sha256(selection_path.read_bytes()).hexdigest()
        binding["portable_selection_artifact_sha256"] = selection_sha256
        fallback_selection_sha256 = fallback_binding.get(
            "portable_selection_artifact_sha256"
        )
        selection_ok = (
            selection.get("sha256") == selection_sha256
            and fallback_selection_sha256 == selection_sha256
        )
        if fallback_binding.get("artifact_sha256") is None:
            decision.incomplete(
                "component_runtime_fallback_binding_missing",
                "component runtime cannot be joined until fallback coverage exists",
            )
        completion_path = manifest_path.parent / "component-runtime-completion.json"
        completion = _read_json_object(
            completion_path.read_bytes(), "component runtime completion"
        )
        if completion.get("format") != COMPONENT_RUNTIME_COMPLETION_V3_FORMAT:
            raise CandidateAuthorityV3Error("component runtime completion format is wrong")
        completion_body = dict(completion)
        completion_sha256 = _digest(
            completion_body.pop("completion_sha256", None),
            "component runtime completion SHA-256",
        )
        binding["completion_sha256"] = completion_sha256
        completion_ok = (
            completion_sha256 == canonical_sha256_v3(completion_body)
            and completion.get("status") == "complete"
            and completion.get("runtime_package_sha256") == declared
            and completion.get("ownership_complete") is True
            and completion.get("ownership_exclusive") is True
            and completion.get("executes_original_binary") is False
        )
        exact_inputs = exact_machine and selection_ok
        complete = (
            payload.get("status") == "ready"
            and identity_ok
            and policy_ok
            and exact_inputs
            and completion_ok
        )
        decision.checks["component_runtime_exact_inputs_agree"] = exact_inputs
        decision.checks["component_runtime_complete"] = complete
        if (
            machine is not None
            and fallback_binding.get("artifact_sha256") is not None
            and not exact_inputs
        ):
            decision.violated(
                "component_runtime_input_mismatch",
                "component runtime and fallback coverage bind different exact inputs",
            )
        if not completion_ok:
            decision.violated(
                "component_runtime_completion_invalid",
                "component runtime completion is stale or incomplete",
            )
        return binding
    except (OSError, UnicodeError, json.JSONDecodeError, CandidateAuthorityV3Error) as exc:
        decision.violated("component_runtime_corrupt", str(exc))
        return binding


def _fallback_entries_match(entries: list[Any], machine: _MachineIR) -> bool:
    by_id: dict[str, Mapping[str, Any]] = {}
    for value in entries:
        if not isinstance(value, Mapping) or not isinstance(value.get("unit_id"), str):
            return False
        if value["unit_id"] in by_id:
            return False
        by_id[value["unit_id"]] = value
    units = {row.unit_id: row for row in machine.units}
    if set(by_id) != set(units):
        return False
    for unit_id, unit in units.items():
        entry = by_id[unit_id]
        core = dict(entry)
        declared = core.pop("entry_sha256", None)
        kind = entry.get("implementation_kind")
        if not (
            declared == canonical_sha256_v3(core)
            and entry.get("rva") == unit.rva
            and entry.get("unit_contract_sha256") == unit.contract_sha256
            and entry.get("source_span_sha256") == unit.instruction_bytes_sha256
            and entry.get("machine_ir_record_sha256") == unit.unit_ir_sha256
            and _DIGEST_RE.fullmatch(str(entry.get("lowering_transfer_sha256")))
            and kind in {
                "machine_ir_fallback",
                "portable_replacement",
                "portable_component_member",
            }
        ):
            return False
        if kind == "machine_ir_fallback" and (
            entry.get("dispatch_lookup") != "stage_b_program_lookup"
            or entry.get("portable_replacement") is not None
        ):
            return False
        if kind == "portable_replacement" and (
            entry.get("dispatch_lookup") != "stage_b_region_override_lookup"
            or not isinstance(entry.get("portable_replacement"), Mapping)
            or entry["portable_replacement"].get("fallback_on_unimplemented") is not False
        ):
            return False
        if kind == "portable_component_member" and (
            entry.get("dispatch_lookup") != "component_entry_subsumed"
            or not isinstance(entry.get("portable_replacement"), Mapping)
            or entry["portable_replacement"].get("dispatch_role") != "subsumed_member"
            or entry["portable_replacement"].get("fallback_on_unimplemented") is not False
        ):
            return False
    return True


def _fallback_counts_match(
    counts: Mapping[str, Any], *, entries: list[Any], blockers: list[Any], unit_count: int
) -> bool:
    fallback = counts.get("machine_ir_fallback")
    portable = counts.get("portable_replacement")
    portable_member = counts.get("portable_component_member", 0)
    return (
        counts.get("structural_units") == unit_count
        and counts.get("implementation_entries") == len(entries)
        and counts.get("blockers") == len(blockers)
        and isinstance(fallback, int)
        and not isinstance(fallback, bool)
        and isinstance(portable, int)
        and not isinstance(portable, bool)
        and isinstance(portable_member, int)
        and not isinstance(portable_member, bool)
        and fallback + portable + portable_member == len(entries)
    )


def _parse_issue(value: Any) -> CandidateAuthorityV3Issue:
    row = _strict_object(value, {"status", "code", "detail"}, "candidate issue")
    try:
        status = CandidateAuthorityV3Status(row["status"])
    except (TypeError, ValueError) as exc:
        raise CandidateAuthorityV3Error("candidate issue status is invalid") from exc
    return CandidateAuthorityV3Issue(
        status=status,
        code=_text(row["code"], "candidate issue code"),
        detail=_text(row["detail"], "candidate issue detail"),
    )


def _status_from_issues(
    issues: tuple[CandidateAuthorityV3Issue, ...],
) -> CandidateAuthorityV3Status:
    if any(issue.status is CandidateAuthorityV3Status.VIOLATED for issue in issues):
        return CandidateAuthorityV3Status.VIOLATED
    if issues:
        return CandidateAuthorityV3Status.INCOMPLETE
    return CandidateAuthorityV3Status.AUTHORIZED


def _issue_key(issue: CandidateAuthorityV3Issue) -> tuple[str, str, str]:
    return issue.status.value, issue.code, issue.detail


def _content_id(core: Mapping[str, Any]) -> str:
    return "stage-b-candidate-authority-v3:" + canonical_sha256_v3(core)


def _read_json_object(data: bytes, context: str) -> Mapping[str, Any]:
    value = json.loads(
        data.decode("utf-8"),
        object_pairs_hook=_reject_duplicates,
        parse_float=_reject_number,
        parse_constant=_reject_number,
    )
    return _mapping(value, context)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateAuthorityV3Error(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def _reject_number(value: str) -> Any:
    raise CandidateAuthorityV3Error(f"noncanonical JSON number {value!r}")


def _strict_object(value: Any, fields: set[str], context: str) -> Mapping[str, Any]:
    row = _mapping(value, context)
    if set(row) != fields:
        raise CandidateAuthorityV3Error(
            f"{context} must contain exactly {sorted(fields)!r}"
        )
    return row


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise CandidateAuthorityV3Error(f"{context} must be an object")
    return value


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or any(ord(char) < 0x20 for char in value):
        raise CandidateAuthorityV3Error(f"{context} must be nonempty text")
    return value


def _digest(value: Any, context: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise CandidateAuthorityV3Error(f"{context} must be lowercase SHA-256")
    return value


def _uint(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CandidateAuthorityV3Error(f"{context} must be an unsigned integer")
    return value


def _json_value(value: Any) -> Any:
    return json.loads(canonical_json_bytes_v3(value).decode("ascii"))


__all__ = [
    "STAGE_B_CANDIDATE_AUTHORITY_V3_FORMAT",
    "STAGE_B_CANDIDATE_AUTHORITY_V3_VERSION",
    "CandidateAuthorityV3Error",
    "CandidateAuthorityV3GateError",
    "CandidateAuthorityV3Issue",
    "CandidateAuthorityV3Receipt",
    "CandidateAuthorityV3Status",
    "build_stage_b_candidate_authority_v3",
    "parse_stage_b_candidate_authority_v3",
    "require_stage_b_candidate_authority_v3",
    "validate_stage_b_candidate_authority_v3",
]
