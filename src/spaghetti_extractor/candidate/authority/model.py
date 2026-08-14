"""Immutable candidate-authority receipt model and canonical serialization."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ...artifact_set_v3 import canonical_json_bytes_v3, canonical_sha256_v3


STAGE_B_CANDIDATE_AUTHORITY_V3_FORMAT = (
    "spaghetti-extractor-stage-b-candidate-authority-receipt-v3"
)
STAGE_B_CANDIDATE_AUTHORITY_V3_VERSION = 3

AUTHORITY = "stage_b_candidate_generation_only"
POLICY = {
    "candidate_generation_fails_closed": True,
    "candidate_generation_only": True,
    "complete_fallback_coverage_required": True,
    "component_runtime_package_required": True,
    "exact_machine_ir_binding_required": True,
    "final_authority_v3_required": True,
    "original_execution_forbidden": True,
}
CHECK_NAMES = frozenset({
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
FALLBACK_POLICY = {
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
            "authority": AUTHORITY,
            "policy": dict(POLICY),
            "inputs": json_value(self.inputs),
            "checks": json_value(self.checks),
            "issues": [issue.to_payload() for issue in self.issues],
        }

    def to_payload(self) -> dict[str, Any]:
        core = self._core_payload()
        return {**core, "content_id": content_id(core)}

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


def make_candidate_authority_receipt(
    *,
    status: CandidateAuthorityV3Status,
    inputs: Mapping[str, Any],
    checks: Mapping[str, bool],
    issues: tuple[CandidateAuthorityV3Issue, ...],
) -> CandidateAuthorityV3Receipt:
    """Construct a receipt whose identity binds its canonical core payload."""

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
        content_id=content_id(provisional._core_payload()),
    )


def content_id(core: Mapping[str, Any]) -> str:
    return "stage-b-candidate-authority-v3:" + canonical_sha256_v3(core)


def issue_key(issue: CandidateAuthorityV3Issue) -> tuple[str, str, str]:
    return issue.status.value, issue.code, issue.detail


def status_from_issues(
    issues: tuple[CandidateAuthorityV3Issue, ...],
) -> CandidateAuthorityV3Status:
    if any(issue.status is CandidateAuthorityV3Status.VIOLATED for issue in issues):
        return CandidateAuthorityV3Status.VIOLATED
    if issues:
        return CandidateAuthorityV3Status.INCOMPLETE
    return CandidateAuthorityV3Status.AUTHORIZED


def json_value(value: Any) -> Any:
    return json.loads(canonical_json_bytes_v3(value).decode("ascii"))


__all__ = [
    "STAGE_B_CANDIDATE_AUTHORITY_V3_FORMAT",
    "STAGE_B_CANDIDATE_AUTHORITY_V3_VERSION",
    "CandidateAuthorityV3Error",
    "CandidateAuthorityV3GateError",
    "CandidateAuthorityV3Issue",
    "CandidateAuthorityV3Receipt",
    "CandidateAuthorityV3Status",
]
