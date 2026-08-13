"""Profile-aware completion receipt for the portable lifting workflow.

The receipt is a compact join over content-addressed evidence.  It does not
trust a copied success bit: status and issues are deterministically rederived
from the typed bindings on construction and parse.  Artifact-set integration
is responsible for resolving every identity to its exact content.
"""

from __future__ import annotations

from collections import Counter
import hashlib
from dataclasses import dataclass
from enum import Enum
from functools import cached_property
from typing import Any, Mapping, Sequence

from .authority_bindings_v2 import (
    AuthorityDataError,
    _array,
    _json_value,
    _object,
    _sha256,
    _text,
    canonical_json,
    canonical_json_bytes,
)
from .implementation_ledger_v2 import (
    ArtifactIdentityV2,
    CompletionProfileV2,
    CompletionStatusV2,
    ImplementationLedgerBindingV2,
    ImplementationOwnerKindV2,
)


LIFT_COMPLETION_RECEIPT_V2_FORMAT = (
    "spaghetti-extractor-lift-completion-receipt-v2"
)
LIFT_COMPLETION_RECEIPT_V2_SCHEMA_VERSION = 2


class CandidatePlatformV2(str, Enum):
    PE32 = "pe32"
    NON_X86 = "non_x86"


_X86_ARCHITECTURES = {
    "x86",
    "i386",
    "i486",
    "i586",
    "i686",
    "x86_64",
    "amd64",
}


def _status(value: Any, context: str) -> CompletionStatusV2:
    try:
        return CompletionStatusV2(value)
    except (TypeError, ValueError) as exc:
        raise AuthorityDataError(f"{context} has an invalid status") from exc


def _profile(value: Any, context: str) -> CompletionProfileV2:
    try:
        return CompletionProfileV2(value)
    except (TypeError, ValueError) as exc:
        raise AuthorityDataError(f"{context} has an invalid profile") from exc


def _platform(value: Any, context: str) -> CandidatePlatformV2:
    try:
        return CandidatePlatformV2(value)
    except (TypeError, ValueError) as exc:
        raise AuthorityDataError(f"{context} has an invalid platform") from exc


def _content_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True, order=True)
class CompletionEvidenceV2:
    identity: ArtifactIdentityV2
    status: CompletionStatusV2

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ArtifactIdentityV2):
            raise AuthorityDataError("completion evidence identity must be typed")
        if not isinstance(self.status, CompletionStatusV2):
            raise AuthorityDataError("completion evidence status must be typed")

    def to_payload(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_payload(),
            "status": self.status.value,
        }

    @classmethod
    def parse(cls, value: Any) -> "CompletionEvidenceV2":
        row = _object(
            value,
            {"identity", "status"},
            "completion evidence",
        )
        return cls(
            identity=ArtifactIdentityV2.parse(row["identity"]),
            status=_status(row["status"], "completion evidence"),
        )


@dataclass(frozen=True, order=True)
class FinalAuthorityEvidenceV2:
    identity: ArtifactIdentityV2
    status: CompletionStatusV2
    authorizing: bool
    original_pe_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ArtifactIdentityV2):
            raise AuthorityDataError("final authority identity must be typed")
        if self.identity.artifact_kind != "final-authority-v3":
            raise AuthorityDataError("final authority has the wrong artifact kind")
        if not isinstance(self.status, CompletionStatusV2):
            raise AuthorityDataError("final authority status must be typed")
        if not isinstance(self.authorizing, bool):
            raise AuthorityDataError("final authority authorizing flag must be Boolean")
        _sha256(self.original_pe_sha256, "final authority original PE SHA-256")

    def to_payload(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_payload(),
            "status": self.status.value,
            "authorizing": self.authorizing,
            "original_pe_sha256": self.original_pe_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "FinalAuthorityEvidenceV2":
        row = _object(
            value,
            {"identity", "status", "authorizing", "original_pe_sha256"},
            "final authority evidence",
        )
        return cls(
            identity=ArtifactIdentityV2.parse(row["identity"]),
            status=_status(row["status"], "final authority evidence"),
            authorizing=row["authorizing"],
            original_pe_sha256=_sha256(
                row["original_pe_sha256"],
                "final authority original PE SHA-256",
            ),
        )


@dataclass(frozen=True, order=True)
class CandidateIdentityV2:
    identity: ArtifactIdentityV2
    platform: CandidatePlatformV2
    architecture: str
    target_triple: str
    binary_sha256: str
    build_manifest_sha256: str
    source_project_sha256: str
    runtime_lock_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ArtifactIdentityV2):
            raise AuthorityDataError("candidate artifact identity must be typed")
        if not isinstance(self.platform, CandidatePlatformV2):
            raise AuthorityDataError("candidate platform must be typed")
        _text(self.architecture, "candidate architecture", maximum=64)
        _text(self.target_triple, "candidate target triple", maximum=128)
        _sha256(self.binary_sha256, "candidate binary SHA-256")
        _sha256(self.build_manifest_sha256, "candidate build-manifest SHA-256")
        _sha256(self.source_project_sha256, "candidate source-project SHA-256")
        _sha256(self.runtime_lock_sha256, "candidate runtime-lock SHA-256")
        normalized = self.architecture.lower()
        if self.platform is CandidatePlatformV2.PE32 and normalized not in {
            "x86",
            "i386",
            "i486",
            "i586",
            "i686",
        }:
            raise AuthorityDataError("PE32 candidate must identify an x86 architecture")
        if self.platform is CandidatePlatformV2.NON_X86 and normalized in _X86_ARCHITECTURES:
            raise AuthorityDataError("non-x86 candidate identifies an x86 architecture")

    def to_payload(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_payload(),
            "platform": self.platform.value,
            "architecture": self.architecture,
            "target_triple": self.target_triple,
            "binary_sha256": self.binary_sha256,
            "build_manifest_sha256": self.build_manifest_sha256,
            "source_project_sha256": self.source_project_sha256,
            "runtime_lock_sha256": self.runtime_lock_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "CandidateIdentityV2":
        row = _object(
            value,
            {
                "identity",
                "platform",
                "architecture",
                "target_triple",
                "binary_sha256",
                "build_manifest_sha256",
                "source_project_sha256",
                "runtime_lock_sha256",
            },
            "candidate identity",
        )
        return cls(
            identity=ArtifactIdentityV2.parse(row["identity"]),
            platform=_platform(row["platform"], "candidate identity"),
            architecture=_text(
                row["architecture"], "candidate architecture", maximum=64
            ),
            target_triple=_text(
                row["target_triple"], "candidate target triple", maximum=128
            ),
            binary_sha256=_sha256(
                row["binary_sha256"], "candidate binary SHA-256"
            ),
            build_manifest_sha256=_sha256(
                row["build_manifest_sha256"],
                "candidate build-manifest SHA-256",
            ),
            source_project_sha256=_sha256(
                row["source_project_sha256"],
                "candidate source-project SHA-256",
            ),
            runtime_lock_sha256=_sha256(
                row["runtime_lock_sha256"], "candidate runtime-lock SHA-256"
            ),
        )


@dataclass(frozen=True, order=True)
class ValidationEvidenceV2:
    identity: ArtifactIdentityV2
    status: CompletionStatusV2
    pe32_candidate_sha256: str
    non_x86_candidate_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.identity, ArtifactIdentityV2):
            raise AuthorityDataError("validation evidence identity must be typed")
        if not isinstance(self.status, CompletionStatusV2):
            raise AuthorityDataError("validation evidence status must be typed")
        _sha256(
            self.pe32_candidate_sha256,
            "validation PE32 candidate SHA-256",
        )
        _sha256(
            self.non_x86_candidate_sha256,
            "validation non-x86 candidate SHA-256",
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "identity": self.identity.to_payload(),
            "status": self.status.value,
            "pe32_candidate_sha256": self.pe32_candidate_sha256,
            "non_x86_candidate_sha256": self.non_x86_candidate_sha256,
        }

    @classmethod
    def parse(cls, value: Any) -> "ValidationEvidenceV2":
        row = _object(
            value,
            {
                "identity",
                "status",
                "pe32_candidate_sha256",
                "non_x86_candidate_sha256",
            },
            "validation evidence",
        )
        return cls(
            identity=ArtifactIdentityV2.parse(row["identity"]),
            status=_status(row["status"], "validation evidence"),
            pe32_candidate_sha256=_sha256(
                row["pe32_candidate_sha256"],
                "validation PE32 candidate SHA-256",
            ),
            non_x86_candidate_sha256=_sha256(
                row["non_x86_candidate_sha256"],
                "validation non-x86 candidate SHA-256",
            ),
        )


@dataclass(frozen=True, order=True)
class CompletionIssueV2:
    status: CompletionStatusV2
    code: str
    location: str
    detail: str

    def __post_init__(self) -> None:
        if self.status is CompletionStatusV2.COMPLETE:
            raise AuthorityDataError("completion issues cannot have complete status")
        _text(self.code, "completion issue code", maximum=128)
        _text(self.location, "completion issue location", maximum=512)
        _text(self.detail, "completion issue detail", maximum=1024)

    def to_payload(self) -> dict[str, str]:
        return {
            "status": self.status.value,
            "code": self.code,
            "location": self.location,
            "detail": self.detail,
        }

    @classmethod
    def parse(cls, value: Any) -> "CompletionIssueV2":
        row = _object(
            value,
            {"status", "code", "location", "detail"},
            "lift-completion issue",
        )
        return cls(
            status=_status(row["status"], "lift-completion issue"),
            code=_text(row["code"], "completion issue code", maximum=128),
            location=_text(
                row["location"], "completion issue location", maximum=512
            ),
            detail=_text(row["detail"], "completion issue detail", maximum=1024),
        )


def _issue(
    status: CompletionStatusV2,
    code: str,
    location: str,
    detail: str,
) -> CompletionIssueV2:
    return CompletionIssueV2(status, code, location, detail)


def _derive_status(issues: Sequence[CompletionIssueV2]) -> CompletionStatusV2:
    if any(issue.status is CompletionStatusV2.VIOLATED for issue in issues):
        return CompletionStatusV2.VIOLATED
    if issues:
        return CompletionStatusV2.INCOMPLETE
    return CompletionStatusV2.COMPLETE


@dataclass(frozen=True)
class LiftCompletionReceiptV2:
    profile: CompletionProfileV2
    final_authority: FinalAuthorityEvidenceV2 | None
    fallback_coverage: CompletionEvidenceV2 | None
    implementation_ledger: ImplementationLedgerBindingV2 | None
    source_qualifications: tuple[CompletionEvidenceV2, ...]
    library_qualifications: tuple[CompletionEvidenceV2, ...]
    runtime_lock: CompletionEvidenceV2 | None
    pe32_candidate: CandidateIdentityV2 | None
    non_x86_candidate: CandidateIdentityV2 | None
    validation: ValidationEvidenceV2 | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.profile, CompletionProfileV2):
            raise AuthorityDataError("lift-completion profile must be typed")
        for value, expected, context in (
            (self.final_authority, FinalAuthorityEvidenceV2, "final authority"),
            (self.fallback_coverage, CompletionEvidenceV2, "fallback coverage"),
            (
                self.implementation_ledger,
                ImplementationLedgerBindingV2,
                "implementation ledger",
            ),
            (self.runtime_lock, CompletionEvidenceV2, "runtime lock"),
            (self.pe32_candidate, CandidateIdentityV2, "PE32 candidate"),
            (self.non_x86_candidate, CandidateIdentityV2, "non-x86 candidate"),
            (self.validation, ValidationEvidenceV2, "validation evidence"),
        ):
            if value is not None and not isinstance(value, expected):
                raise AuthorityDataError(f"{context} must be typed")
        for values, context in (
            (self.source_qualifications, "source qualifications"),
            (self.library_qualifications, "library qualifications"),
        ):
            if not isinstance(values, tuple) or any(
                not isinstance(item, CompletionEvidenceV2) for item in values
            ):
                raise AuthorityDataError(f"{context} must be a typed tuple")

    @classmethod
    def create(
        cls,
        *,
        profile: CompletionProfileV2,
        final_authority: FinalAuthorityEvidenceV2 | None,
        fallback_coverage: CompletionEvidenceV2 | None,
        implementation_ledger: ImplementationLedgerBindingV2 | None,
        source_qualifications: Sequence[CompletionEvidenceV2] = (),
        library_qualifications: Sequence[CompletionEvidenceV2] = (),
        runtime_lock: CompletionEvidenceV2 | None,
        pe32_candidate: CandidateIdentityV2 | None = None,
        non_x86_candidate: CandidateIdentityV2 | None = None,
        validation: ValidationEvidenceV2 | None = None,
    ) -> "LiftCompletionReceiptV2":
        key = lambda row: row.identity
        return cls(
            profile=profile,
            final_authority=final_authority,
            fallback_coverage=fallback_coverage,
            implementation_ledger=implementation_ledger,
            source_qualifications=tuple(sorted(source_qualifications, key=key)),
            library_qualifications=tuple(sorted(library_qualifications, key=key)),
            runtime_lock=runtime_lock,
            pe32_candidate=pe32_candidate,
            non_x86_candidate=non_x86_candidate,
            validation=validation,
        )

    @cached_property
    def issues(self) -> tuple[CompletionIssueV2, ...]:
        issues: set[CompletionIssueV2] = set()

        required = (
            ("final_authority", self.final_authority),
            ("fallback_coverage", self.fallback_coverage),
            ("implementation_ledger", self.implementation_ledger),
            ("runtime_lock", self.runtime_lock),
        )
        for location, value in required:
            if value is None:
                issues.add(_issue(
                    CompletionStatusV2.INCOMPLETE,
                    "required_evidence_missing",
                    location,
                    "completion profile lacks required checked evidence",
                ))

        evidence_rows: list[tuple[str, CompletionEvidenceV2]] = []
        if self.fallback_coverage is not None:
            evidence_rows.append(("fallback_coverage", self.fallback_coverage))
            if self.fallback_coverage.identity.artifact_kind != "fallback-coverage-v3":
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "evidence_artifact_kind_mismatch",
                    "fallback_coverage",
                    "fallback coverage does not bind fallback-coverage-v3",
                ))
        if self.runtime_lock is not None:
            evidence_rows.append(("runtime_lock", self.runtime_lock))
            if self.runtime_lock.identity.artifact_kind != "runtime-lock-v1":
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "evidence_artifact_kind_mismatch",
                    "runtime_lock",
                    "runtime lock does not bind runtime-lock-v1",
                ))
        evidence_rows.extend(
            (f"source_qualifications:{row.identity.artifact_id}", row)
            for row in self.source_qualifications
        )
        evidence_rows.extend(
            (f"library_qualifications:{row.identity.artifact_id}", row)
            for row in self.library_qualifications
        )
        for location, evidence in evidence_rows:
            if evidence.status is CompletionStatusV2.VIOLATED:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "bound_evidence_violated",
                    location,
                    "bound evidence reports a contradiction or corruption",
                ))
            elif evidence.status is CompletionStatusV2.INCOMPLETE:
                issues.add(_issue(
                    CompletionStatusV2.INCOMPLETE,
                    "bound_evidence_incomplete",
                    location,
                    "bound evidence is not complete",
                ))

        if self.final_authority is not None:
            final = self.final_authority
            if final.status is CompletionStatusV2.VIOLATED:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "final_authority_violated",
                    "final_authority",
                    "final Stage A authority reports a violation",
                ))
            elif final.status is CompletionStatusV2.INCOMPLETE:
                issues.add(_issue(
                    CompletionStatusV2.INCOMPLETE,
                    "final_authority_incomplete",
                    "final_authority",
                    "final Stage A authority is incomplete",
                ))
            if final.status is CompletionStatusV2.COMPLETE and not final.authorizing:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "final_authority_decision_inconsistent",
                    "final_authority",
                    "complete final authority is not authorizing",
                ))
            if final.status is not CompletionStatusV2.COMPLETE and final.authorizing:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "final_authority_decision_inconsistent",
                    "final_authority",
                    "incomplete or violated final authority claims authorization",
                ))

        ledger = self.implementation_ledger
        if ledger is not None:
            if ledger.profile is not self.profile:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "ledger_profile_mismatch",
                    "implementation_ledger",
                    "implementation ledger binds a different completion profile",
                ))
            if ledger.status is CompletionStatusV2.VIOLATED:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "implementation_ledger_violated",
                    "implementation_ledger",
                    "implementation ledger contains contradictory ownership",
                ))
            elif ledger.status is CompletionStatusV2.INCOMPLETE:
                issues.add(_issue(
                    CompletionStatusV2.INCOMPLETE,
                    "implementation_ledger_incomplete",
                    "implementation_ledger",
                    "implementation ownership is not complete for this profile",
                ))
            if (
                self.final_authority is not None
                and ledger.binary.pe_sha256
                != self.final_authority.original_pe_sha256
            ):
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "original_pe_binding_mismatch",
                    "implementation_ledger",
                    "ledger and final authority bind different original PEs",
                ))

        source_ids = [row.identity for row in self.source_qualifications]
        library_ids = [row.identity for row in self.library_qualifications]
        for rows, identities, location in (
            (
                self.source_qualifications,
                source_ids,
                "source_qualifications",
            ),
            (
                self.library_qualifications,
                library_ids,
                "library_qualifications",
            ),
        ):
            if rows != tuple(sorted(rows, key=lambda row: row.identity)):
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "noncanonical_qualification_order",
                    location,
                    "qualification evidence is not in canonical identity order",
                ))
            duplicates = {
                identity
                for identity, count in Counter(identities).items()
                if count > 1
            }
            for identity in duplicates:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "duplicate_qualification_evidence",
                    f"{location}:{identity.artifact_id}",
                    "qualification evidence is duplicated",
                ))
        for identity in set(source_ids) & set(library_ids):
            issues.add(_issue(
                CompletionStatusV2.VIOLATED,
                "ambiguous_qualification_evidence",
                identity.artifact_id,
                "one qualification is classified as both source and library evidence",
            ))

        source_set = set(source_ids)
        library_set = set(library_ids)
        if ledger is not None:
            for requirement in ledger.qualification_requirements:
                identity = requirement.qualification
                if requirement.owner_kind is ImplementationOwnerKindV2.PORTABLE_COMPONENT:
                    if identity not in source_set:
                        issues.add(_issue(
                            CompletionStatusV2.INCOMPLETE,
                            "source_qualification_missing",
                            identity.artifact_id,
                            "portable component qualification is not bound by the receipt",
                        ))
                elif requirement.owner_kind is ImplementationOwnerKindV2.LIBRARY_SUBSTITUTION:
                    if identity not in library_set:
                        issues.add(_issue(
                            CompletionStatusV2.INCOMPLETE,
                            "library_qualification_missing",
                            identity.artifact_id,
                            "library substitution qualification is not bound by the receipt",
                        ))
                elif requirement.owner_kind is ImplementationOwnerKindV2.MACHINE_IR_FALLBACK:
                    if (
                        self.fallback_coverage is None
                        or identity != self.fallback_coverage.identity
                    ):
                        issues.add(_issue(
                            CompletionStatusV2.INCOMPLETE,
                            "fallback_qualification_missing",
                            identity.artifact_id,
                            "machine-IR owner is not bound to checked fallback coverage",
                        ))

        candidates_required = self.profile in {
            CompletionProfileV2.PORTABLE_APPLICATION,
            CompletionProfileV2.VALIDATION_QUALIFIED,
        }
        if candidates_required:
            for location, candidate in (
                ("pe32_candidate", self.pe32_candidate),
                ("non_x86_candidate", self.non_x86_candidate),
            ):
                if candidate is None:
                    issues.add(_issue(
                        CompletionStatusV2.INCOMPLETE,
                        "candidate_identity_missing",
                        location,
                        "portable completion requires both candidate builds",
                    ))
        if (self.pe32_candidate is None) != (self.non_x86_candidate is None):
            issues.add(_issue(
                CompletionStatusV2.INCOMPLETE,
                "candidate_pair_incomplete",
                "candidates",
                "candidate identities must be supplied as a PE32/non-x86 pair",
            ))
        if self.pe32_candidate is not None:
            if self.pe32_candidate.platform is not CandidatePlatformV2.PE32:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "candidate_platform_mismatch",
                    "pe32_candidate",
                    "PE32 candidate slot contains a non-PE32 identity",
                ))
        if self.non_x86_candidate is not None:
            if self.non_x86_candidate.platform is not CandidatePlatformV2.NON_X86:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "candidate_platform_mismatch",
                    "non_x86_candidate",
                    "non-x86 candidate slot contains a PE32 identity",
                ))

        if self.pe32_candidate is not None and self.non_x86_candidate is not None:
            pe32 = self.pe32_candidate
            native = self.non_x86_candidate
            if pe32.identity == native.identity or pe32.binary_sha256 == native.binary_sha256:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "candidate_identity_overlap",
                    "candidates",
                    "PE32 and non-x86 candidate identities are not distinct",
                ))
            if pe32.source_project_sha256 != native.source_project_sha256:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "candidate_source_project_mismatch",
                    "candidates",
                    "candidate builds bind different source projects",
                ))
            if self.runtime_lock is not None:
                expected_lock = self.runtime_lock.identity.sha256
                if (
                    pe32.runtime_lock_sha256 != expected_lock
                    or native.runtime_lock_sha256 != expected_lock
                ):
                    issues.add(_issue(
                        CompletionStatusV2.VIOLATED,
                        "candidate_runtime_lock_mismatch",
                        "candidates",
                        "candidate builds do not bind the receipt runtime lock",
                    ))

        if self.validation is not None:
            if self.validation.status is CompletionStatusV2.VIOLATED:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "validation_violated",
                    "validation",
                    "candidate-only validation reports a failure or contradiction",
                ))
            elif self.validation.status is CompletionStatusV2.INCOMPLETE:
                issues.add(_issue(
                    CompletionStatusV2.INCOMPLETE,
                    "validation_incomplete",
                    "validation",
                    "candidate-only validation is incomplete",
                ))
            if self.pe32_candidate is None or self.non_x86_candidate is None:
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "validation_candidate_binding_missing",
                    "validation",
                    "validation cannot be checked without both candidate identities",
                ))
            elif (
                self.validation.pe32_candidate_sha256
                != self.pe32_candidate.binary_sha256
                or self.validation.non_x86_candidate_sha256
                != self.non_x86_candidate.binary_sha256
            ):
                issues.add(_issue(
                    CompletionStatusV2.VIOLATED,
                    "validation_candidate_binding_mismatch",
                    "validation",
                    "validation binds different candidate binaries",
                ))
        elif self.profile is CompletionProfileV2.VALIDATION_QUALIFIED:
            issues.add(_issue(
                CompletionStatusV2.INCOMPLETE,
                "validation_evidence_missing",
                "validation",
                "validation-qualified completion requires candidate-only validation",
            ))

        return tuple(
            sorted(
                issues,
                key=lambda item: (
                    item.status.value,
                    item.code,
                    item.location,
                    item.detail,
                ),
            )
        )

    @property
    def status(self) -> CompletionStatusV2:
        return _derive_status(self.issues)

    @property
    def authorizing(self) -> bool:
        return self.status is CompletionStatusV2.COMPLETE

    def _core_payload(self) -> dict[str, Any]:
        def optional(value: Any) -> Any:
            return None if value is None else value.to_payload()

        return {
            "format": LIFT_COMPLETION_RECEIPT_V2_FORMAT,
            "schema_version": LIFT_COMPLETION_RECEIPT_V2_SCHEMA_VERSION,
            "profile": self.profile.value,
            "status": self.status.value,
            "authorizing": self.authorizing,
            "final_authority": optional(self.final_authority),
            "fallback_coverage": optional(self.fallback_coverage),
            "implementation_ledger": optional(self.implementation_ledger),
            "source_qualifications": [
                row.to_payload() for row in self.source_qualifications
            ],
            "library_qualifications": [
                row.to_payload() for row in self.library_qualifications
            ],
            "runtime_lock": optional(self.runtime_lock),
            "pe32_candidate": optional(self.pe32_candidate),
            "non_x86_candidate": optional(self.non_x86_candidate),
            "validation": optional(self.validation),
            "issues": [issue.to_payload() for issue in self.issues],
        }

    @cached_property
    def receipt_id(self) -> str:
        return f"lift-completion-receipt-v2:{_content_sha256(self._core_payload())}"

    def to_payload(self) -> dict[str, Any]:
        return {**self._core_payload(), "receipt_id": self.receipt_id}

    def to_json(self) -> str:
        return canonical_json(self.to_payload())

    @cached_property
    def artifact_identity(self) -> ArtifactIdentityV2:
        return ArtifactIdentityV2(
            artifact_kind="lift-completion-receipt-v2",
            artifact_id=self.receipt_id,
            sha256=_content_sha256(self.to_payload()),
        )

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "LiftCompletionReceiptV2":
        row = _object(
            value,
            {
                "format",
                "schema_version",
                "receipt_id",
                "profile",
                "status",
                "authorizing",
                "final_authority",
                "fallback_coverage",
                "implementation_ledger",
                "source_qualifications",
                "library_qualifications",
                "runtime_lock",
                "pe32_candidate",
                "non_x86_candidate",
                "validation",
                "issues",
            },
            "lift-completion-receipt-v2",
        )
        if (
            row["format"] != LIFT_COMPLETION_RECEIPT_V2_FORMAT
            or row["schema_version"] != LIFT_COMPLETION_RECEIPT_V2_SCHEMA_VERSION
        ):
            raise AuthorityDataError("only lift-completion-receipt-v2 is authorizing")
        result = cls(
            profile=_profile(row["profile"], "lift-completion-receipt-v2"),
            final_authority=(
                None
                if row["final_authority"] is None
                else FinalAuthorityEvidenceV2.parse(row["final_authority"])
            ),
            fallback_coverage=(
                None
                if row["fallback_coverage"] is None
                else CompletionEvidenceV2.parse(row["fallback_coverage"])
            ),
            implementation_ledger=(
                None
                if row["implementation_ledger"] is None
                else ImplementationLedgerBindingV2.parse(
                    row["implementation_ledger"]
                )
            ),
            source_qualifications=tuple(
                CompletionEvidenceV2.parse(item)
                for item in _array(
                    row["source_qualifications"], "source qualifications"
                )
            ),
            library_qualifications=tuple(
                CompletionEvidenceV2.parse(item)
                for item in _array(
                    row["library_qualifications"], "library qualifications"
                )
            ),
            runtime_lock=(
                None
                if row["runtime_lock"] is None
                else CompletionEvidenceV2.parse(row["runtime_lock"])
            ),
            pe32_candidate=(
                None
                if row["pe32_candidate"] is None
                else CandidateIdentityV2.parse(row["pe32_candidate"])
            ),
            non_x86_candidate=(
                None
                if row["non_x86_candidate"] is None
                else CandidateIdentityV2.parse(row["non_x86_candidate"])
            ),
            validation=(
                None
                if row["validation"] is None
                else ValidationEvidenceV2.parse(row["validation"])
            ),
        )
        observed = _json_value(value, context="lift-completion-receipt-v2")
        if result.to_payload() != observed:
            raise AuthorityDataError(
                "lift-completion status, issues, bindings, or ID is stale"
            )
        return result


__all__ = [
    "LIFT_COMPLETION_RECEIPT_V2_FORMAT",
    "CandidateIdentityV2",
    "CandidatePlatformV2",
    "CompletionEvidenceV2",
    "CompletionIssueV2",
    "FinalAuthorityEvidenceV2",
    "LiftCompletionReceiptV2",
    "ValidationEvidenceV2",
]
