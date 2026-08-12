"""Strict v2 authority receipts for Stage B candidate generation.

The receipt produced here is the only object in this module with candidate-
generation authority.  It joins an exact static-hybrid v2 audit and authority
bundle with the exact machine IR and a complete fallback-coverage receipt.
Legacy v1 closure, completeness, and authorization artifacts may be recorded
for diagnostics, but they are deliberately excluded from every authorizing
check.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from .artifact_formats import (
    MACHINE_IR_FORMAT,
    STATIC_HYBRID_FINAL_AUDIT_V2_FORMAT,
)
from .hybrid_authority_builder_v2 import MACHINE_IR_AUTHORITY_BINDINGS_FORMAT
from .hybrid_authority_v2 import (
    AUTHORITY_BUNDLE_FORMAT,
    AuthorityBundle,
    AuthorityDataError,
    AuthorityStatus,
    canonical_json_bytes,
)
from .stage_b_fallback_coverage import FALLBACK_COVERAGE_RECEIPT_FORMAT


STAGE_B_CANDIDATE_AUTHORITY_V2_FORMAT = (
    "spaghetti-extractor-stage-b-candidate-authority-v2"
)
STAGE_B_CANDIDATE_AUTHORITY_V2_VERSION = 2

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_CONTENT_ID_RE = re.compile(
    r"stage-b-candidate-authority-v2:([0-9a-f]{64})"
)
_REQUIRED_AUDIT_POLICY = {
    "v2_authority_is_only_candidate_authority": True,
    "tainted_accepted_facts_forbidden": True,
    "deferred_transfers_forbidden": True,
}
_RECEIPT_POLICY = {
    "v2_static_audit_required": True,
    "v2_authority_bundle_required": True,
    "exact_machine_ir_binding_required": True,
    "complete_fallback_coverage_required": True,
    "tainted_accepted_facts_forbidden": True,
    "deferred_transfers_forbidden": True,
    "v1_authority_accepted": False,
    "candidate_generation_fails_closed": True,
}
_TAINT_KEYS = frozenset({
    "taint",
    "tainted",
    "provenance_tainted",
    "rejected_tainted",
})
_TAINT_VALUES = frozenset({
    "taint",
    "tainted",
    "unknown_taint",
    "unknown_write_taint",
    "aliasing_write_taint",
})
_DEFERRED_BOOLEAN_KEYS = frozenset({
    "allow_deferred_potential_transfers",
    "potential_transfers_may_be_deferred",
})
_DEFERRED_COLLECTION_KEYS = frozenset({
    "deferred_transfers",
    "potential_units",
    "frontiers",
})


class CandidateAuthorityV2Error(ValueError):
    """A candidate-authority artifact is malformed or binds stale inputs."""


class CandidateAuthorityV2GateError(CandidateAuthorityV2Error):
    """Candidate generation was attempted without an authorizing receipt."""

    def __init__(self, receipt: "CandidateAuthorityV2Receipt") -> None:
        self.status = receipt.status
        self.issues = receipt.issues
        summary = ", ".join(issue.code for issue in receipt.issues) or "unknown"
        super().__init__(
            f"candidate generation is {receipt.status.value}: {summary}"
        )


class CandidateAuthorityV2Status(str, Enum):
    AUTHORIZED = "authorized"
    INCOMPLETE = "incomplete"
    VIOLATED = "violated"


@dataclass(frozen=True, order=True)
class CandidateAuthorityV2Issue:
    status: CandidateAuthorityV2Status
    code: str
    detail: str

    def __post_init__(self) -> None:
        if self.status is CandidateAuthorityV2Status.AUTHORIZED:
            raise CandidateAuthorityV2Error(
                "an authority issue cannot have authorized status"
            )
        if not isinstance(self.code, str) or not self.code:
            raise CandidateAuthorityV2Error("authority issue code is missing")
        if not isinstance(self.detail, str) or not self.detail:
            raise CandidateAuthorityV2Error("authority issue detail is missing")

    def to_payload(self) -> dict[str, str]:
        return {
            "status": self.status.value,
            "code": self.code,
            "detail": self.detail,
        }

    @classmethod
    def parse(cls, value: Any) -> "CandidateAuthorityV2Issue":
        row = _exact_object(value, {"status", "code", "detail"}, "issue")
        try:
            status = CandidateAuthorityV2Status(row["status"])
        except (TypeError, ValueError) as exc:
            raise CandidateAuthorityV2Error(
                "authority issue has an invalid status"
            ) from exc
        return cls(
            status=status,
            code=_string(row["code"], "authority issue code"),
            detail=_string(row["detail"], "authority issue detail"),
        )


@dataclass(frozen=True)
class CandidateAuthorityV2Receipt:
    """Immutable candidate-generation decision bound to exact input artifacts."""

    status: CandidateAuthorityV2Status
    inputs: Mapping[str, Any]
    checks: Mapping[str, bool]
    issues: tuple[CandidateAuthorityV2Issue, ...]
    legacy_diagnostics: tuple[Mapping[str, Any], ...]
    content_id: str

    @property
    def authorizes(self) -> bool:
        return self.status is CandidateAuthorityV2Status.AUTHORIZED

    def _core_payload(self) -> dict[str, Any]:
        return {
            "format": STAGE_B_CANDIDATE_AUTHORITY_V2_FORMAT,
            "schema_version": STAGE_B_CANDIDATE_AUTHORITY_V2_VERSION,
            "status": self.status.value,
            "authorizes": self.authorizes,
            "authority": "stage_b_candidate_generation_only",
            "policy": dict(_RECEIPT_POLICY),
            "inputs": _json_value(self.inputs, "receipt inputs"),
            "checks": _json_value(self.checks, "receipt checks"),
            "issues": [issue.to_payload() for issue in self.issues],
            "legacy_diagnostics": [
                _json_value(item, "legacy diagnostic")
                for item in self.legacy_diagnostics
            ],
        }

    def to_payload(self) -> dict[str, Any]:
        core = self._core_payload()
        return {**core, "content_id": _candidate_content_id(core)}

    def to_json(self) -> str:
        return canonical_json_bytes(self.to_payload()).decode("ascii")


@dataclass(frozen=True)
class _LoadedArtifact:
    label: str
    payload: Mapping[str, Any] | None
    artifact_sha256: str | None
    missing: bool = False
    malformed: bool = False
    detail: str | None = None


@dataclass
class _Decision:
    issues: list[CandidateAuthorityV2Issue]
    checks: dict[str, bool]

    def incomplete(self, code: str, detail: str) -> None:
        self.issues.append(CandidateAuthorityV2Issue(
            CandidateAuthorityV2Status.INCOMPLETE, code, detail
        ))

    def violated(self, code: str, detail: str) -> None:
        self.issues.append(CandidateAuthorityV2Issue(
            CandidateAuthorityV2Status.VIOLATED, code, detail
        ))

    def check(self, name: str, value: bool) -> None:
        self.checks[name] = bool(value)


def build_stage_b_candidate_authority_v2(
    *,
    final_static_hybrid_audit: Path | str | Mapping[str, Any],
    authority_bundle: Path | str | Mapping[str, Any] | AuthorityBundle,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    fallback_coverage_receipt: Path | str | Mapping[str, Any],
    legacy_diagnostic_artifacts: Sequence[
        Path | str | Mapping[str, Any]
    ] = (),
) -> CandidateAuthorityV2Receipt:
    """Derive a v2 candidate receipt without consulting v1 authority state.

    Missing evidence produces an ``incomplete`` receipt.  Malformed,
    contradictory, or stale evidence produces ``violated``.  Call
    :func:`require_stage_b_candidate_authority_v2` at the candidate build gate.
    """

    decision = _Decision([], {})
    audit_artifact = _load_json_artifact(
        final_static_hybrid_audit, "final static-hybrid v2 audit"
    )
    bundle_artifact = _load_bundle_artifact(authority_bundle)
    machine_artifact, machine_rows = _load_machine_ir(Path(machine_ir))
    manifest_artifact = _load_json_artifact(
        Path(machine_ir_manifest), "machine-IR manifest"
    )
    fallback_artifact = _load_json_artifact(
        fallback_coverage_receipt, "fallback-coverage receipt"
    )

    for artifact, missing_code, malformed_code in (
        (audit_artifact, "final_v2_audit_missing", "final_v2_audit_corrupt"),
        (bundle_artifact, "authority_bundle_missing", "authority_bundle_corrupt"),
        (machine_artifact, "machine_ir_missing", "machine_ir_corrupt"),
        (
            manifest_artifact,
            "machine_ir_manifest_missing",
            "machine_ir_manifest_corrupt",
        ),
        (
            fallback_artifact,
            "fallback_coverage_receipt_missing",
            "fallback_coverage_receipt_corrupt",
        ),
    ):
        if artifact.missing:
            decision.incomplete(missing_code, artifact.detail or artifact.label)
        elif artifact.malformed:
            decision.violated(malformed_code, artifact.detail or artifact.label)

    bundle: AuthorityBundle | None = None
    if bundle_artifact.payload is not None:
        try:
            bundle = AuthorityBundle.parse(bundle_artifact.payload)
        except AuthorityDataError as exc:
            decision.violated("authority_bundle_corrupt", str(exc))

    _check_bundle(bundle, decision)
    _check_machine_and_manifest(
        machine_artifact=machine_artifact,
        machine_rows=machine_rows,
        manifest_artifact=manifest_artifact,
        bundle=bundle,
        decision=decision,
    )
    _check_final_audit(
        artifact=audit_artifact,
        bundle_artifact=bundle_artifact,
        bundle=bundle,
        machine_artifact=machine_artifact,
        manifest_artifact=manifest_artifact,
        decision=decision,
    )
    _check_fallback_coverage(
        artifact=fallback_artifact,
        machine_artifact=machine_artifact,
        manifest_artifact=manifest_artifact,
        machine_rows=machine_rows,
        decision=decision,
    )

    if bundle is not None and _bundle_contains_taint(bundle):
        decision.violated(
            "tainted_accepted_fact",
            "the accepted v2 authority closure contains a tainted value",
        )
        decision.check("no_tainted_accepted_fact", False)
    else:
        decision.check("no_tainted_accepted_fact", bundle is not None)

    deferred = _deferred_evidence(
        manifest_artifact.payload,
        fallback_artifact.payload,
    )
    if deferred:
        decision.violated(
            "deferred_transfer_present",
            "candidate inputs retain deferred or potential transfers: "
            + ", ".join(deferred),
        )
        decision.check("no_deferred_transfers", False)
    else:
        decision.check(
            "no_deferred_transfers",
            manifest_artifact.payload is not None
            and fallback_artifact.payload is not None,
        )

    issues = tuple(sorted(set(decision.issues)))
    status = _status_from_issues(issues)
    checks = dict(sorted(decision.checks.items()))
    if status is CandidateAuthorityV2Status.AUTHORIZED and not all(checks.values()):
        issues = (*issues, CandidateAuthorityV2Issue(
            CandidateAuthorityV2Status.VIOLATED,
            "authorizing_check_false",
            "an authorizing check is false without a corresponding issue",
        ))
        status = CandidateAuthorityV2Status.VIOLATED

    diagnostic_rows = tuple(
        _legacy_diagnostic_binding(value)
        for value in legacy_diagnostic_artifacts
    )
    inputs = {
        "final_static_hybrid_audit": _artifact_binding(
            audit_artifact,
            extra=_audit_identity(audit_artifact.payload),
        ),
        "authority_bundle": _artifact_binding(
            bundle_artifact,
            extra=(
                {
                    "format": AUTHORITY_BUNDLE_FORMAT,
                    "content_id": bundle.content_id,
                    "status": bundle.status.value,
                    "authorizes": bundle.authorizes,
                }
                if bundle is not None
                else {}
            ),
        ),
        "machine_ir": _artifact_binding(
            machine_artifact,
            extra={"format": MACHINE_IR_FORMAT},
        ),
        "machine_ir_manifest": _artifact_binding(
            manifest_artifact,
            extra={"format": MACHINE_IR_FORMAT},
        ),
        "fallback_coverage_receipt": _artifact_binding(
            fallback_artifact,
            extra=_fallback_identity(fallback_artifact.payload),
        ),
    }
    provisional = CandidateAuthorityV2Receipt(
        status=status,
        inputs=inputs,
        checks=checks,
        issues=issues,
        legacy_diagnostics=diagnostic_rows,
        content_id="stage-b-candidate-authority-v2:" + "0" * 64,
    )
    content_id = _candidate_content_id(provisional._core_payload())
    return CandidateAuthorityV2Receipt(
        status=status,
        inputs=inputs,
        checks=checks,
        issues=issues,
        legacy_diagnostics=diagnostic_rows,
        content_id=content_id,
    )


def parse_stage_b_candidate_authority_v2(
    value: Mapping[str, Any] | str | bytes,
) -> CandidateAuthorityV2Receipt:
    """Parse one canonical v2 receipt and rederive its local integrity fields."""

    if isinstance(value, (str, bytes)):
        try:
            raw = value.encode("utf-8") if isinstance(value, str) else value
            parsed = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_reject_duplicates
            )
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise CandidateAuthorityV2Error(
                f"candidate-authority receipt is not valid JSON: {exc}"
            ) from exc
        if canonical_json_bytes(parsed) != raw:
            raise CandidateAuthorityV2Error(
                "candidate-authority receipt JSON is not canonical"
            )
        value = parsed
    row = _exact_object(
        value,
        {
            "format",
            "schema_version",
            "status",
            "authorizes",
            "authority",
            "policy",
            "inputs",
            "checks",
            "issues",
            "legacy_diagnostics",
            "content_id",
        },
        "candidate-authority receipt",
    )
    if (
        row["format"] != STAGE_B_CANDIDATE_AUTHORITY_V2_FORMAT
        or row["schema_version"] != STAGE_B_CANDIDATE_AUTHORITY_V2_VERSION
    ):
        raise CandidateAuthorityV2Error(
            "v1 and unknown candidate-authority receipts are not authorizing"
        )
    if row["authority"] != "stage_b_candidate_generation_only":
        raise CandidateAuthorityV2Error("candidate authority scope is corrupt")
    if row["policy"] != _RECEIPT_POLICY:
        raise CandidateAuthorityV2Error("candidate authority policy is stale")
    try:
        status = CandidateAuthorityV2Status(row["status"])
    except (TypeError, ValueError) as exc:
        raise CandidateAuthorityV2Error(
            "candidate-authority receipt has an invalid status"
        ) from exc
    if row["authorizes"] is not (status is CandidateAuthorityV2Status.AUTHORIZED):
        raise CandidateAuthorityV2Error("candidate authorization bit is stale")
    inputs = _exact_object(
        row["inputs"],
        {
            "final_static_hybrid_audit",
            "authority_bundle",
            "machine_ir",
            "machine_ir_manifest",
            "fallback_coverage_receipt",
        },
        "candidate-authority inputs",
    )
    checks = _mapping(row["checks"], "candidate-authority checks")
    if any(not isinstance(value, bool) for value in checks.values()):
        raise CandidateAuthorityV2Error("candidate-authority checks must be booleans")
    issues_raw = _list(row["issues"], "candidate-authority issues")
    issues = tuple(CandidateAuthorityV2Issue.parse(item) for item in issues_raw)
    if issues != tuple(sorted(set(issues))):
        raise CandidateAuthorityV2Error(
            "candidate-authority issues must be sorted and unique"
        )
    if _status_from_issues(issues) is not status:
        raise CandidateAuthorityV2Error("candidate-authority status is stale")
    if status is CandidateAuthorityV2Status.AUTHORIZED and (
        issues or not checks or not all(checks.values())
    ):
        raise CandidateAuthorityV2Error(
            "authorized candidate receipt contains failed checks"
        )
    legacy = tuple(
        _exact_object(
            item,
            {"artifact_sha256", "format", "status", "authorizes"},
            "legacy diagnostic",
        )
        for item in _list(
            row["legacy_diagnostics"], "legacy candidate diagnostics"
        )
    )
    if any(item["authorizes"] is not False for item in legacy):
        raise CandidateAuthorityV2Error("legacy input cannot authorize")
    content_id = _string(row["content_id"], "candidate content ID")
    if _CONTENT_ID_RE.fullmatch(content_id) is None:
        raise CandidateAuthorityV2Error("candidate content ID is malformed")
    provisional = CandidateAuthorityV2Receipt(
        status=status,
        inputs=_json_value(inputs, "candidate-authority inputs"),
        checks=_json_value(checks, "candidate-authority checks"),
        issues=issues,
        legacy_diagnostics=tuple(
            _json_value(item, "legacy diagnostic") for item in legacy
        ),
        content_id=content_id,
    )
    if provisional.to_payload() != _json_value(row, "candidate-authority receipt"):
        raise CandidateAuthorityV2Error(
            "candidate-authority content ID or derived fields are stale"
        )
    return provisional


def validate_stage_b_candidate_authority_v2(
    *,
    receipt: Path | str | Mapping[str, Any] | CandidateAuthorityV2Receipt,
    final_static_hybrid_audit: Path | str | Mapping[str, Any],
    authority_bundle: Path | str | Mapping[str, Any] | AuthorityBundle,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    fallback_coverage_receipt: Path | str | Mapping[str, Any],
    legacy_diagnostic_artifacts: Sequence[
        Path | str | Mapping[str, Any]
    ] = (),
    require_authorized: bool = True,
) -> CandidateAuthorityV2Receipt:
    """Recompute the receipt from its exact inputs and reject stale copies."""

    if isinstance(receipt, CandidateAuthorityV2Receipt):
        actual = parse_stage_b_candidate_authority_v2(receipt.to_payload())
    elif isinstance(receipt, Mapping):
        actual = parse_stage_b_candidate_authority_v2(receipt)
    else:
        path = Path(receipt)
        try:
            actual = parse_stage_b_candidate_authority_v2(path.read_bytes())
        except OSError as exc:
            raise CandidateAuthorityV2Error(
                f"cannot read candidate-authority receipt: {exc}"
            ) from exc
    expected = build_stage_b_candidate_authority_v2(
        final_static_hybrid_audit=final_static_hybrid_audit,
        authority_bundle=authority_bundle,
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
        fallback_coverage_receipt=fallback_coverage_receipt,
        legacy_diagnostic_artifacts=legacy_diagnostic_artifacts,
    )
    if actual.to_payload() != expected.to_payload():
        raise CandidateAuthorityV2Error(
            "candidate-authority receipt is stale or binds different inputs"
        )
    if require_authorized:
        require_stage_b_candidate_authority_v2(actual)
    return actual


def require_stage_b_candidate_authority_v2(
    receipt: CandidateAuthorityV2Receipt,
) -> CandidateAuthorityV2Receipt:
    """Fail the candidate build gate unless the recomputed receipt authorizes."""

    if not isinstance(receipt, CandidateAuthorityV2Receipt):
        raise CandidateAuthorityV2Error(
            "candidate build gate requires a parsed v2 receipt"
        )
    if not receipt.authorizes:
        raise CandidateAuthorityV2GateError(receipt)
    return receipt


def _check_bundle(
    bundle: AuthorityBundle | None, decision: _Decision
) -> None:
    if bundle is None:
        decision.check("authority_bundle_authorizes", False)
        return
    if bundle.status is AuthorityStatus.INCOMPLETE:
        decision.incomplete(
            "authority_bundle_incomplete",
            "the v2 authority dependency closure is incomplete",
        )
    elif bundle.status is AuthorityStatus.VIOLATED:
        decision.violated(
            "authority_bundle_violated",
            "the v2 authority dependency closure is contradictory",
        )
    decision.check("authority_bundle_authorizes", bundle.authorizes)


def _check_machine_and_manifest(
    *,
    machine_artifact: _LoadedArtifact,
    machine_rows: tuple[Mapping[str, Any], ...],
    manifest_artifact: _LoadedArtifact,
    bundle: AuthorityBundle | None,
    decision: _Decision,
) -> None:
    if machine_artifact.payload is None or manifest_artifact.payload is None:
        decision.check("exact_machine_ir_hashes_agree", False)
        decision.check("rooted_reachability_complete", False)
        return
    manifest = manifest_artifact.payload
    manifest_format = manifest.get("format")
    if manifest_format is None:
        decision.incomplete(
            "machine_ir_manifest_format_missing",
            "the machine-IR manifest lacks its format",
        )
    elif manifest_format != MACHINE_IR_FORMAT:
        decision.violated(
            "machine_ir_manifest_format_mismatch",
            "the machine-IR manifest has an unsupported format",
        )
    artifacts = _optional_mapping(manifest.get("artifacts"))
    ir_binding = _optional_mapping(artifacts.get("machine_ir"))
    declared_ir_hash = ir_binding.get("sha256")
    if declared_ir_hash is None:
        decision.incomplete(
            "manifest_machine_ir_binding_missing",
            "the machine-IR manifest lacks an exact machine-IR hash",
        )
    elif not _is_sha256(declared_ir_hash):
        decision.violated(
            "manifest_machine_ir_binding_corrupt",
            "the machine-IR manifest contains a malformed machine-IR hash",
        )
    elif declared_ir_hash != machine_artifact.artifact_sha256:
        decision.violated(
            "manifest_machine_ir_hash_mismatch",
            "the machine-IR manifest binds different machine-IR bytes",
        )

    pe_candidates = _manifest_pe_hash_candidates(manifest)
    malformed_pe_hashes = [
        value for value in pe_candidates
        if value is not None and not _is_sha256(value)
    ]
    pe_hashes = {
        value for value in pe_candidates
        if isinstance(value, str) and _is_sha256(value)
    }
    if malformed_pe_hashes:
        decision.violated(
            "manifest_pe_binding_corrupt",
            "the machine-IR manifest contains a malformed PE hash",
        )
    if not pe_hashes:
        decision.incomplete(
            "manifest_pe_binding_missing",
            "the machine-IR manifest lacks an exact PE hash",
        )
    elif len(pe_hashes) != 1:
        decision.violated(
            "manifest_pe_binding_conflict",
            "the machine-IR manifest contains contradictory PE hashes",
        )

    authority_bindings = _optional_mapping(manifest.get("authority_bindings"))
    authority_format = authority_bindings.get("format")
    if authority_format is None:
        decision.incomplete(
            "manifest_v2_authority_bindings_missing",
            "the machine-IR manifest lacks v2 authority bindings",
        )
    elif authority_format != MACHINE_IR_AUTHORITY_BINDINGS_FORMAT:
        decision.violated(
            "manifest_v2_authority_bindings_corrupt",
            "the machine-IR manifest has unsupported authority bindings",
        )
    authority_binary = _optional_mapping(authority_bindings.get("binary"))
    for key in ("machine_ir_sha256", "pe_sha256"):
        value = authority_binary.get(key)
        if value is not None and not _is_sha256(value):
            decision.violated(
                "manifest_v2_authority_binary_corrupt",
                f"the v2 authority binary binding has a malformed {key}",
            )

    expected_machine_hash = machine_artifact.artifact_sha256
    expected_pe_hash = next(iter(pe_hashes)) if len(pe_hashes) == 1 else None
    comparisons = (
        declared_ir_hash == expected_machine_hash,
        authority_binary.get("machine_ir_sha256") == expected_machine_hash,
        bundle is not None
        and bundle.binary.machine_ir_sha256 == expected_machine_hash,
        expected_pe_hash is not None
        and authority_binary.get("pe_sha256") == expected_pe_hash,
        bundle is not None
        and expected_pe_hash is not None
        and bundle.binary.pe_sha256 == expected_pe_hash,
    )
    if all(comparisons):
        decision.check("exact_machine_ir_hashes_agree", True)
    else:
        if bundle is not None and all(value is not None for value in (
            declared_ir_hash,
            authority_binary.get("machine_ir_sha256"),
            authority_binary.get("pe_sha256"),
        )):
            decision.violated(
                "exact_binary_binding_mismatch",
                "the v2 bundle, manifest, PE, and machine IR do not share exact hashes",
            )
        decision.check("exact_machine_ir_hashes_agree", False)

    _check_manifest_reachability(manifest, machine_rows, decision)


def _check_manifest_reachability(
    manifest: Mapping[str, Any],
    machine_rows: tuple[Mapping[str, Any], ...],
    decision: _Decision,
) -> None:
    control = _optional_mapping(manifest.get("control"))
    reachability = _optional_mapping(control.get("reachability"))
    if not reachability:
        decision.incomplete(
            "rooted_reachability_missing",
            "the machine-IR manifest lacks rooted reachability closure",
        )
        decision.check("rooted_reachability_complete", False)
        return
    unit_ids = {
        row.get("id") for row in machine_rows if isinstance(row.get("id"), str)
    }
    roots = _string_set(reachability.get("roots"))
    reachable = _string_set(reachability.get("reachable_units"))
    potential = _string_set(reachability.get("potential_units"))
    unreachable = _string_set(reachability.get("confirmed_unreachable_units"))
    frontiers = reachability.get("frontiers")
    complete = (
        reachability.get("status") == "complete"
        and bool(roots)
        and roots <= reachable
        and reachable | unreachable == unit_ids
        and not reachable & unreachable
        and not potential
        and isinstance(frontiers, list)
        and not frontiers
    )
    if not complete:
        if reachability.get("status") == "violated":
            decision.violated(
                "rooted_reachability_violated",
                "rooted reachability evidence is contradictory",
            )
        else:
            decision.incomplete(
                "rooted_reachability_incomplete",
                "rooted reachability is not a complete unit partition",
            )
    decision.check("rooted_reachability_complete", complete)


def _check_final_audit(
    *,
    artifact: _LoadedArtifact,
    bundle_artifact: _LoadedArtifact,
    bundle: AuthorityBundle | None,
    machine_artifact: _LoadedArtifact,
    manifest_artifact: _LoadedArtifact,
    decision: _Decision,
) -> None:
    audit = artifact.payload
    if audit is None:
        decision.check("final_v2_audit_passes", False)
        return
    if audit.get("format") != STATIC_HYBRID_FINAL_AUDIT_V2_FORMAT:
        decision.violated(
            "final_v2_audit_format_mismatch",
            "the final static-hybrid audit is not a v2 audit",
        )
        decision.check("final_v2_audit_passes", False)
        return
    declared = audit.get("audit_sha256")
    body = dict(audit)
    body.pop("audit_sha256", None)
    if not _is_sha256(declared):
        decision.incomplete(
            "final_v2_audit_identity_missing",
            "the final v2 audit lacks its canonical identity",
        )
    elif declared != _canonical_sha256(body):
        decision.violated(
            "final_v2_audit_identity_corrupt",
            "the final v2 audit canonical identity is stale",
        )
    status = audit.get("status")
    if status == "incomplete":
        decision.incomplete(
            "final_v2_audit_incomplete", "the final v2 audit is incomplete"
        )
    elif status == "violated":
        decision.violated(
            "final_v2_audit_violated", "the final v2 audit is violated"
        )
    elif status != "pass":
        decision.violated(
            "final_v2_audit_status_corrupt",
            "the final v2 audit has an invalid status",
        )
    if status == "pass" and (bundle is None or not bundle.authorizes):
        decision.violated(
            "final_v2_audit_authority_conflict",
            "the final v2 audit passes a non-authorizing authority bundle",
        )

    findings = audit.get("findings")
    if not isinstance(findings, list):
        decision.incomplete(
            "final_v2_audit_findings_missing",
            "the final v2 audit lacks a findings inventory",
        )
    elif status == "pass" and findings:
        decision.violated(
            "final_v2_audit_pass_has_findings",
            "a passing final v2 audit contains unresolved findings",
        )

    policy = _optional_mapping(audit.get("policy"))
    missing_policy = [
        key for key, expected in _REQUIRED_AUDIT_POLICY.items()
        if policy.get(key) is not expected
    ]
    if missing_policy:
        decision.incomplete(
            "final_v2_audit_policy_missing",
            "the final v2 audit lacks required policy: "
            + ", ".join(sorted(missing_policy)),
        )

    bundle_binding = _optional_mapping(audit.get("authority_bundle"))
    machine_binding = _optional_mapping(audit.get("machine_ir"))
    manifest_binding = _optional_mapping(audit.get("machine_ir_manifest"))
    expected_bundle = {
        "format": AUTHORITY_BUNDLE_FORMAT,
        "content_id": None if bundle is None else bundle.content_id,
        "artifact_sha256": bundle_artifact.artifact_sha256,
    }
    bindings_match = (
        all(bundle_binding.get(key) == value for key, value in expected_bundle.items())
        and machine_binding.get("sha256") == machine_artifact.artifact_sha256
        and manifest_binding.get("sha256") == manifest_artifact.artifact_sha256
    )
    if not bindings_match:
        if not bundle_binding or not machine_binding or not manifest_binding:
            decision.incomplete(
                "final_v2_audit_bindings_missing",
                "the final v2 audit lacks exact authority or machine bindings",
            )
        else:
            decision.violated(
                "final_v2_audit_binding_mismatch",
                "the final v2 audit binds different authority or machine artifacts",
            )
    passes = (
        status == "pass"
        and findings == []
        and not missing_policy
        and bindings_match
        and _is_sha256(declared)
        and declared == _canonical_sha256(body)
    )
    decision.check("final_v2_audit_passes", passes)


def _check_fallback_coverage(
    *,
    artifact: _LoadedArtifact,
    machine_artifact: _LoadedArtifact,
    manifest_artifact: _LoadedArtifact,
    machine_rows: tuple[Mapping[str, Any], ...],
    decision: _Decision,
) -> None:
    receipt = artifact.payload
    if receipt is None:
        decision.check("fallback_coverage_complete", False)
        return
    if receipt.get("format") != FALLBACK_COVERAGE_RECEIPT_FORMAT:
        decision.violated(
            "fallback_coverage_format_mismatch",
            "the fallback-coverage receipt has an unsupported format",
        )
        decision.check("fallback_coverage_complete", False)
        return
    declared = receipt.get("receipt_sha256")
    body = dict(receipt)
    body.pop("receipt_sha256", None)
    if not _is_sha256(declared):
        decision.incomplete(
            "fallback_coverage_identity_missing",
            "the fallback-coverage receipt lacks its canonical identity",
        )
    elif declared != _canonical_sha256(body):
        decision.violated(
            "fallback_coverage_identity_corrupt",
            "the fallback-coverage receipt canonical identity is stale",
        )
    status = receipt.get("status")
    if status == "incomplete":
        decision.incomplete(
            "fallback_coverage_incomplete",
            "fallback implementation coverage is incomplete",
        )
    elif status == "violated":
        decision.violated(
            "fallback_coverage_violated",
            "fallback implementation coverage is contradictory",
        )
    elif status != "complete":
        decision.violated(
            "fallback_coverage_status_corrupt",
            "fallback implementation coverage has an invalid status",
        )

    policy = _optional_mapping(receipt.get("policy"))
    for key, expected in (
        ("potential_transfers_may_be_deferred", False),
        ("structural_units_require_lowering", True),
        ("one_implementation_kind_per_structural_unit", True),
        ("rooted_containment_authority", False),
        ("candidate_generation_fails_closed", True),
    ):
        observed = policy.get(key)
        if observed is None:
            decision.incomplete(
                "fallback_coverage_policy_missing",
                f"fallback coverage lacks required policy {key}",
            )
        elif observed is not expected:
            decision.violated(
                "fallback_coverage_policy_unsafe",
                f"fallback coverage has unsafe policy {key}",
            )

    inputs = _optional_mapping(receipt.get("inputs"))
    machine_binding = _optional_mapping(inputs.get("machine_ir"))
    manifest_binding = _optional_mapping(inputs.get("machine_ir_manifest"))
    exact_inputs = (
        machine_binding.get("sha256") == machine_artifact.artifact_sha256
        and manifest_binding.get("sha256") == manifest_artifact.artifact_sha256
    )
    if not exact_inputs:
        if not machine_binding or not manifest_binding:
            decision.incomplete(
                "fallback_exact_inputs_missing",
                "fallback coverage lacks exact machine-IR bindings",
            )
        else:
            decision.violated(
                "fallback_exact_input_mismatch",
                "fallback coverage binds different machine-IR artifacts",
            )

    blockers = receipt.get("blockers")
    counts = _optional_mapping(receipt.get("counts"))
    if not isinstance(blockers, list):
        decision.incomplete(
            "fallback_blocker_inventory_missing",
            "fallback coverage lacks a blocker inventory",
        )
        blockers = []
    elif status == "complete" and blockers:
        decision.violated(
            "fallback_complete_with_blockers",
            "complete fallback coverage contains blockers",
        )

    entries = receipt.get("entries")
    if not isinstance(entries, list):
        decision.incomplete(
            "fallback_entry_inventory_missing",
            "fallback coverage lacks implementation entries",
        )
        entries = []
    unit_rows = {
        str(row.get("id")): row
        for row in machine_rows
        if isinstance(row.get("id"), str)
    }
    entry_by_id: dict[str, Mapping[str, Any]] = {}
    duplicate = False
    for item in entries:
        if not isinstance(item, Mapping) or not isinstance(item.get("unit_id"), str):
            decision.violated(
                "fallback_entry_corrupt",
                "fallback coverage contains a malformed implementation entry",
            )
            continue
        unit_id = item["unit_id"]
        if unit_id in entry_by_id:
            duplicate = True
        entry_by_id[unit_id] = item
    if duplicate:
        decision.violated(
            "fallback_entry_duplicate",
            "fallback coverage contains duplicate implementation entries",
        )

    structural_ids = set(unit_rows)
    complete_entries = (
        set(entry_by_id) == structural_ids
        and all(_fallback_entry_matches(entry_by_id[unit_id], unit_rows[unit_id])
                for unit_id in structural_ids)
    )
    if not complete_entries:
        if status == "complete":
            decision.violated(
                "fallback_coverage_claim_conflict",
                "complete fallback coverage does not exactly cover structural units",
            )
        else:
            decision.incomplete(
                "fallback_coverage_units_missing",
                "fallback coverage does not exactly cover structural units",
            )

    fallback_count = counts.get("machine_ir_fallback")
    portable_count = counts.get("portable_replacement")
    implementation_total_matches = (
        isinstance(fallback_count, int)
        and not isinstance(fallback_count, bool)
        and isinstance(portable_count, int)
        and not isinstance(portable_count, bool)
        and fallback_count + portable_count == len(entries)
    )
    count_matches = (
        _exact_count(counts.get("structural_units"), len(structural_ids))
        and _exact_count(counts.get("implementation_entries"), len(entries))
        and _exact_count(counts.get("blockers"), len(blockers))
        and implementation_total_matches
    )
    if not count_matches:
        if status == "complete":
            decision.violated(
                "fallback_coverage_counts_corrupt",
                "complete fallback coverage counts contradict its inventories",
            )
        else:
            decision.incomplete(
                "fallback_coverage_counts_incomplete",
                "fallback coverage counts do not describe complete coverage",
            )

    complete = (
        status == "complete"
        and declared == _canonical_sha256(body)
        and exact_inputs
        and blockers == []
        and complete_entries
        and count_matches
        and policy.get("potential_transfers_may_be_deferred") is False
        and policy.get("structural_units_require_lowering") is True
        and policy.get("one_implementation_kind_per_structural_unit") is True
        and policy.get("rooted_containment_authority") is False
        and policy.get("candidate_generation_fails_closed") is True
    )
    decision.check("fallback_coverage_complete", complete)


def _fallback_entry_matches(
    entry: Mapping[str, Any], unit: Mapping[str, Any]
) -> bool:
    source = _optional_mapping(unit.get("source"))
    original = _optional_mapping(source.get("original"))
    core = dict(entry)
    declared_entry_hash = core.pop("entry_sha256", None)
    return (
        entry.get("rva") == original.get("rva_start")
        and entry.get("unit_contract_sha256") == source.get("contract_sha256")
        and entry.get("source_span_sha256")
        == source.get("instruction_bytes_sha256")
        and entry.get("machine_ir_record_sha256") == _canonical_sha256(unit)
        and entry.get("implementation_kind")
        in {"machine_ir_fallback", "portable_replacement"}
        and _is_sha256(entry.get("lowering_transfer_sha256"))
        and _is_sha256(declared_entry_hash)
        and declared_entry_hash == _canonical_sha256(core)
    )


def _load_bundle_artifact(
    value: Path | str | Mapping[str, Any] | AuthorityBundle,
) -> _LoadedArtifact:
    if isinstance(value, AuthorityBundle):
        payload = value.to_payload()
        return _LoadedArtifact(
            "v2 authority bundle",
            payload,
            _canonical_sha256(payload),
        )
    return _load_json_artifact(value, "v2 authority bundle")


def _load_json_artifact(
    value: Path | str | Mapping[str, Any], label: str
) -> _LoadedArtifact:
    if isinstance(value, Mapping):
        try:
            payload = _json_value(value, label)
            return _LoadedArtifact(
                label, payload, _canonical_sha256(payload)
            )
        except CandidateAuthorityV2Error as exc:
            return _LoadedArtifact(
                label, None, None, malformed=True, detail=str(exc)
            )
    path = Path(value)
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return _LoadedArtifact(
            label, None, None, missing=True, detail=f"{label} is missing"
        )
    except OSError as exc:
        return _LoadedArtifact(
            label, None, None, malformed=True, detail=f"cannot read {label}: {exc}"
        )
    try:
        payload = json.loads(
            data.decode("utf-8"), object_pairs_hook=_reject_duplicates
        )
        payload = _mapping(payload, label)
    except (UnicodeError, json.JSONDecodeError, ValueError, CandidateAuthorityV2Error) as exc:
        return _LoadedArtifact(
            label, None, _sha256_bytes(data), malformed=True, detail=str(exc)
        )
    return _LoadedArtifact(label, payload, _sha256_bytes(data))


def _load_machine_ir(
    path: Path,
) -> tuple[_LoadedArtifact, tuple[Mapping[str, Any], ...]]:
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return (
            _LoadedArtifact(
                "machine IR", None, None, missing=True, detail="machine IR is missing"
            ),
            (),
        )
    except OSError as exc:
        return (
            _LoadedArtifact(
                "machine IR", None, None, malformed=True,
                detail=f"cannot read machine IR: {exc}",
            ),
            (),
        )
    rows: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    try:
        for line_number, line in enumerate(data.splitlines(keepends=True), start=1):
            if not line.strip():
                raise CandidateAuthorityV2Error(
                    f"machine IR line {line_number} is empty"
                )
            if not line.endswith(b"\n"):
                raise CandidateAuthorityV2Error(
                    "machine IR must end every record with a newline"
                )
            raw = line[:-1]
            row = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_reject_duplicates
            )
            row = _mapping(row, f"machine IR line {line_number}")
            if canonical_json_bytes(row) != raw:
                raise CandidateAuthorityV2Error(
                    f"machine IR line {line_number} is not canonical"
                )
            if row.get("format") != MACHINE_IR_FORMAT or row.get("record_kind") != "unit":
                raise CandidateAuthorityV2Error(
                    f"machine IR line {line_number} is not a v2 unit"
                )
            unit_id = _string(row.get("id"), f"machine IR line {line_number} ID")
            if unit_id in seen:
                raise CandidateAuthorityV2Error(
                    f"machine IR contains duplicate unit {unit_id}"
                )
            seen.add(unit_id)
            rows.append(row)
        if not rows:
            raise CandidateAuthorityV2Error("machine IR contains no units")
    except (UnicodeError, json.JSONDecodeError, ValueError, CandidateAuthorityV2Error) as exc:
        return (
            _LoadedArtifact(
                "machine IR", None, _sha256_bytes(data), malformed=True,
                detail=str(exc),
            ),
            (),
        )
    payload = {"format": MACHINE_IR_FORMAT, "unit_count": len(rows)}
    return _LoadedArtifact("machine IR", payload, _sha256_bytes(data)), tuple(rows)


def _bundle_contains_taint(bundle: AuthorityBundle) -> bool:
    by_id = {record.content_id: record for record in bundle.records}
    visited: set[str] = set()

    def visit(content_id: str) -> bool:
        if content_id in visited:
            return False
        visited.add(content_id)
        record = by_id.get(content_id)
        if record is None:
            return False
        payload = record.to_payload()
        if _value_contains_taint(payload):
            return True
        return any(visit(dependency.content_id) for dependency in record.dependencies)

    return any(visit(content_id) for content_id in bundle.required_content_ids)


def _value_contains_taint(value: Any, *, key: str | None = None) -> bool:
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            normalized = str(child_key).lower()
            if normalized in _TAINT_KEYS and child is True:
                return True
            if normalized in {"kind", "status", "origin", "provenance"} and (
                isinstance(child, str) and child.lower() in _TAINT_VALUES
            ):
                return True
            if _value_contains_taint(child, key=normalized):
                return True
        return False
    if isinstance(value, list):
        return any(_value_contains_taint(item, key=key) for item in value)
    return bool(
        key == "code"
        and isinstance(value, str)
        and "taint" in value.lower()
    )


def _deferred_evidence(*values: Mapping[str, Any] | None) -> tuple[str, ...]:
    found: set[str] = set()

    def walk(value: Any, path: str) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                if key in _DEFERRED_BOOLEAN_KEYS and child is True:
                    found.add(child_path)
                if key in _DEFERRED_COLLECTION_KEYS and (
                    (isinstance(child, int) and not isinstance(child, bool) and child > 0)
                    or (isinstance(child, (list, tuple, dict)) and bool(child))
                ):
                    found.add(child_path)
                if key in {"runtime_disposition", "disposition"} and (
                    isinstance(child, str) and "deferred" in child.lower()
                ):
                    found.add(child_path)
                walk(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")

    for index, value in enumerate(values):
        if value is not None:
            walk(value, f"input{index}")
    return tuple(sorted(found))


def _legacy_diagnostic_binding(
    value: Path | str | Mapping[str, Any]
) -> Mapping[str, Any]:
    artifact = _load_json_artifact(value, "legacy diagnostic")
    payload = artifact.payload or {}
    return {
        "artifact_sha256": artifact.artifact_sha256,
        "format": payload.get("format"),
        "status": payload.get("status"),
        "authorizes": False,
    }


def _manifest_pe_hash_candidates(manifest: Mapping[str, Any]) -> list[Any]:
    return [
        _optional_mapping(manifest.get("binary")).get("sha256"),
        _optional_mapping(
            _optional_mapping(manifest.get("inputs")).get("original_pe")
        ).get("sha256"),
        _optional_mapping(
            _optional_mapping(manifest.get("authority_bindings")).get("binary")
        ).get("pe_sha256"),
    ]


def _artifact_binding(
    artifact: _LoadedArtifact, *, extra: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "artifact_sha256": artifact.artifact_sha256,
        **({} if extra is None else dict(extra)),
    }


def _audit_identity(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    return {
        "format": value.get("format"),
        "status": value.get("status"),
        "audit_sha256": value.get("audit_sha256"),
    }


def _fallback_identity(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    return {
        "format": value.get("format"),
        "status": value.get("status"),
        "receipt_sha256": value.get("receipt_sha256"),
    }


def _status_from_issues(
    issues: Sequence[CandidateAuthorityV2Issue],
) -> CandidateAuthorityV2Status:
    if any(issue.status is CandidateAuthorityV2Status.VIOLATED for issue in issues):
        return CandidateAuthorityV2Status.VIOLATED
    if issues:
        return CandidateAuthorityV2Status.INCOMPLETE
    return CandidateAuthorityV2Status.AUTHORIZED


def _candidate_content_id(core: Mapping[str, Any]) -> str:
    return "stage-b-candidate-authority-v2:" + _canonical_sha256(core)


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and _SHA256_RE.fullmatch(value) is not None


def _exact_count(value: Any, expected: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise CandidateAuthorityV2Error(f"{context} must be a nonempty string")
    return value


def _mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise CandidateAuthorityV2Error(f"{context} must be an object")
    return value


def _optional_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _exact_object(
    value: Any, expected: set[str], context: str
) -> Mapping[str, Any]:
    row = _mapping(value, context)
    if set(row) != expected:
        raise CandidateAuthorityV2Error(f"{context} has noncanonical fields")
    return row


def _list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise CandidateAuthorityV2Error(f"{context} must be an array")
    return value


def _string_set(value: Any) -> set[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        return set()
    return set(value)


def _json_value(value: Any, context: str) -> Any:
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            if not isinstance(key, str):
                raise CandidateAuthorityV2Error(
                    f"{context} has a non-string key"
                )
            result[key] = _json_value(child, f"{context}.{key}")
        return result
    if isinstance(value, (list, tuple)):
        return [
            _json_value(child, f"{context}[{index}]")
            for index, child in enumerate(value)
        ]
    raise CandidateAuthorityV2Error(f"{context} is not canonical JSON data")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


__all__ = [
    "STAGE_B_CANDIDATE_AUTHORITY_V2_FORMAT",
    "STATIC_HYBRID_FINAL_AUDIT_V2_FORMAT",
    "CandidateAuthorityV2Error",
    "CandidateAuthorityV2GateError",
    "CandidateAuthorityV2Issue",
    "CandidateAuthorityV2Receipt",
    "CandidateAuthorityV2Status",
    "build_stage_b_candidate_authority_v2",
    "parse_stage_b_candidate_authority_v2",
    "require_stage_b_candidate_authority_v2",
    "validate_stage_b_candidate_authority_v2",
]
