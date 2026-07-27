"""Deterministic coverage and frontier planning for ISA qualification.

The planner consumes the generic XED form catalog and optional qualification
evidence.  It groups and ranks forms only by profile disposition, category,
ISA set, exact selection requirements, and qualification status.  Instruction
names and encodings never participate in dispatch.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any

from .isa_catalog import (
    ISA_PROFILE_ID,
    DispositionReason,
    ProfileDisposition,
    XEDInstructionCatalog,
    serialize_xed_instruction_catalog,
)
from .isa_kernel_qualification import (
    ISAKernelQualification,
    ISAKernelSelection,
    QualificationStatus,
    SemanticKernelBinding,
    artifact_sha256,
    parse_kernel_qualification,
    parse_kernel_selection,
)


ISA_QUALIFICATION_CAMPAIGN_FORMAT = "stage-a-isa-qualification-campaign-v1"
ISA_QUALIFICATION_CAMPAIGN_TRUST_ROLE = "isa_qualification_campaign_planning_only"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_REASON_CODE_RE = re.compile(r"[a-z0-9]+(?:_[a-z0-9]+)*")


class ISAQualificationCampaignError(ValueError):
    """Raised when a campaign input or serialized plan is inconsistent."""


class CampaignQualificationStatus(str, Enum):
    QUALIFIED = "qualified"
    UNQUALIFIED = "unqualified"
    INCOMPLETE = "incomplete"
    DISPUTED = "disputed"
    VETOED = "vetoed"
    NOT_APPLICABLE = "not_applicable"


class CampaignPriority(str, Enum):
    REQUIRED_EXACT_SEMANTIC_FORM = "required_exact_semantic_form"
    CORE_FORM = "core_form"
    SEPARATELY_QUALIFIED_FORM = "separately_qualified_form"
    VISIBILITY_ONLY = "visibility_only"


class CampaignNextAction(str, Enum):
    QUALIFY_EXACT_LEAN_SEMANTIC_FORM = "qualify_exact_lean_semantic_form"
    IMPLEMENT_AND_QUALIFY_CORE_FORM = "implement_and_qualify_core_form"
    COMPLETE_CORE_FORM_EVIDENCE = "complete_core_form_evidence"
    RESOLVE_CORE_FORM_ORACLE_DISPUTE = "resolve_core_form_oracle_dispute"
    REPAIR_CORE_FORM_LEAN_SEMANTICS = "repair_core_form_lean_semantics"
    IMPLEMENT_AND_QUALIFY_SEPARATE_FORM = "implement_and_qualify_separate_form"
    COMPLETE_SEPARATE_FORM_EVIDENCE = "complete_separate_form_evidence"
    RESOLVE_SEPARATE_FORM_ORACLE_DISPUTE = (
        "resolve_separate_form_oracle_dispute"
    )
    REPAIR_SEPARATE_FORM_LEAN_SEMANTICS = (
        "repair_separate_form_lean_semantics"
    )
    DEFINE_EXTERNAL_PLATFORM_CONTRACT = "define_external_platform_contract"
    RETAIN_EXCLUSION_OR_EXPAND_PROFILE = "retain_exclusion_or_expand_profile"


class CampaignReasonCode(str, Enum):
    REQUIRED_EXACT_SEMANTIC_FORM = "required_exact_semantic_form"
    QUALIFICATION_EVIDENCE_AGREES = "qualification_evidence_agrees"
    QUALIFICATION_EVIDENCE_MISSING = "qualification_evidence_missing"
    QUALIFICATION_EVIDENCE_INCOMPLETE = "qualification_evidence_incomplete"
    QUALIFICATION_EVIDENCE_DISPUTED = "qualification_evidence_disputed"
    LEAN_SEMANTICS_VETOED = "lean_semantics_vetoed"
    EXTERNAL_PLATFORM_NOT_KERNEL_QUALIFIED = (
        "external_platform_not_kernel_qualified"
    )
    EXCLUDED_UNSUPPORTED_NOT_KERNEL_QUALIFIED = (
        "excluded_unsupported_not_kernel_qualified"
    )


@dataclass(frozen=True)
class CampaignTrust:
    role: str = ISA_QUALIFICATION_CAMPAIGN_TRUST_ROLE
    proof_authority: bool = False
    closes_stage_a_proof: bool = False


@dataclass(frozen=True)
class CampaignCatalogBinding:
    sha256: str
    generator_name: str
    xed_version: str
    templates: int


@dataclass(frozen=True)
class CampaignEvidenceBinding:
    kernel_qualification_sha256: str | None
    kernel_qualification_supplied: bool
    kernel_selection_sha256: str | None
    selected_binary_id: str | None
    selected_binary_sha256: str | None
    semantic_kernel: SemanticKernelBinding | None


@dataclass(frozen=True)
class CampaignCoverage:
    form_id: str
    table_indices: tuple[int, ...]
    category: str
    isa_set: str
    disposition: ProfileDisposition
    disposition_reasons: tuple[DispositionReason, ...]
    required: bool
    semantic_form: str | None
    evidence_qualification_sha256: str | None
    evidence_status: QualificationStatus | None
    qualification_status: CampaignQualificationStatus
    counts_as_qualified: bool
    reason_codes: tuple[CampaignReasonCode, ...]
    evidence_reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class CampaignFrontierItem:
    rank: int | None
    priority: CampaignPriority
    form_id: str
    semantic_form: str | None
    qualification_status: CampaignQualificationStatus
    reason_codes: tuple[CampaignReasonCode, ...]
    evidence_reason_codes: tuple[str, ...]
    next_action: CampaignNextAction


@dataclass(frozen=True)
class ISAQualificationCampaign:
    profile: str
    catalog: CampaignCatalogBinding
    evidence: CampaignEvidenceBinding
    coverage: tuple[CampaignCoverage, ...]
    frontier: tuple[CampaignFrontierItem, ...]
    counts: Mapping[str, Any]
    trust: CampaignTrust = CampaignTrust()
    format: str = ISA_QUALIFICATION_CAMPAIGN_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "ISAQualificationCampaign":
        return parse_isa_qualification_campaign(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_isa_qualification_campaign(self)

    def sha256(self) -> str:
        return isa_qualification_campaign_sha256(self)

    @property
    def ranked_next_work(self) -> tuple[CampaignFrontierItem, ...]:
        return tuple(row for row in self.frontier if row.rank is not None)

    @property
    def visibility_only(self) -> tuple[CampaignFrontierItem, ...]:
        return tuple(row for row in self.frontier if row.rank is None)


ISACampaignPlan = ISAQualificationCampaign


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ISAQualificationCampaignError(f"{context} must be an object")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    missing = expected - set(value)
    unknown = set(value) - expected
    if not missing and not unknown:
        return
    details: list[str] = []
    if missing:
        details.append(f"missing fields {sorted(missing)!r}")
    if unknown:
        details.append(f"unknown fields {sorted(unknown, key=str)!r}")
    raise ISAQualificationCampaignError(
        f"{context} has " + " and ".join(details)
    )


def _string(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ISAQualificationCampaignError(
            f"{context} must be a non-empty string without surrounding whitespace"
        )
    return value


def _optional_string(value: Any, context: str) -> str | None:
    return None if value is None else _string(value, context)


def _sha256(value: Any, context: str) -> str:
    digest = _string(value, context)
    if _SHA256_RE.fullmatch(digest) is None:
        raise ISAQualificationCampaignError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return digest


def _optional_sha256(value: Any, context: str) -> str | None:
    return None if value is None else _sha256(value, context)


def _count(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ISAQualificationCampaignError(
            f"{context} must be a non-negative integer"
        )
    return value


def _positive_count(value: Any, context: str) -> int:
    result = _count(value, context)
    if result == 0:
        raise ISAQualificationCampaignError(
            f"{context} must be a positive integer"
        )
    return result


def _uint32(value: Any, context: str) -> int:
    result = _count(value, context)
    if result >= 2**32:
        raise ISAQualificationCampaignError(
            f"{context} must be an unsigned 32-bit integer"
        )
    return result


def _boolean(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise ISAQualificationCampaignError(f"{context} must be a boolean")
    return value


def _enum(enum_type: type[Enum], value: Any, context: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ISAQualificationCampaignError(
            f"{context} is unsupported"
        ) from exc


def _ordered_strings(
    value: Any,
    context: str,
    *,
    allow_empty: bool,
    reason_codes: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ISAQualificationCampaignError(f"{context} must be a list")
    rows = tuple(
        _string(row, f"{context}[{index}]")
        for index, row in enumerate(value)
    )
    if not allow_empty and not rows:
        raise ISAQualificationCampaignError(f"{context} must not be empty")
    if rows != tuple(sorted(set(rows))):
        raise ISAQualificationCampaignError(
            f"{context} must be unique and canonically ordered"
        )
    if reason_codes and any(
        _REASON_CODE_RE.fullmatch(row) is None for row in rows
    ):
        raise ISAQualificationCampaignError(
            f"{context} must contain stable snake_case reason codes"
        )
    return rows


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ISAQualificationCampaignError(
            "campaign payload must be canonical JSON data"
        ) from exc


def xed_instruction_catalog_sha256(catalog: XEDInstructionCatalog) -> str:
    if not isinstance(catalog, XEDInstructionCatalog):
        raise ISAQualificationCampaignError(
            "catalog must be a typed XEDInstructionCatalog"
        )
    return hashlib.sha256(
        _canonical_json_bytes(serialize_xed_instruction_catalog(catalog))
    ).hexdigest()


def _catalog_payload(value: CampaignCatalogBinding) -> dict[str, Any]:
    return {
        "sha256": value.sha256,
        "generator": {
            "name": value.generator_name,
            "xed_version": value.xed_version,
        },
        "templates": value.templates,
    }


def _parse_catalog_binding(value: Any) -> CampaignCatalogBinding:
    payload = _object(value, "ISA campaign.catalog")
    _exact_fields(payload, {"sha256", "generator", "templates"}, "ISA campaign.catalog")
    generator = _object(payload.get("generator"), "ISA campaign.catalog.generator")
    _exact_fields(
        generator,
        {"name", "xed_version"},
        "ISA campaign.catalog.generator",
    )
    return CampaignCatalogBinding(
        sha256=_sha256(payload.get("sha256"), "ISA campaign.catalog.sha256"),
        generator_name=_string(
            generator.get("name"), "ISA campaign.catalog.generator.name"
        ),
        xed_version=_string(
            generator.get("xed_version"),
            "ISA campaign.catalog.generator.xed_version",
        ),
        templates=_positive_count(
            payload.get("templates"), "ISA campaign.catalog.templates"
        ),
    )


def _kernel_payload(value: SemanticKernelBinding) -> dict[str, Any]:
    return {
        "id": value.id,
        "decoder_sha256": value.decoder_sha256,
        "semantics_sha256": value.semantics_sha256,
        "lean_version": value.lean_version,
    }


def _parse_kernel_binding(value: Any) -> SemanticKernelBinding:
    payload = _object(value, "ISA campaign.evidence.semantic_kernel")
    _exact_fields(
        payload,
        {"id", "decoder_sha256", "semantics_sha256", "lean_version"},
        "ISA campaign.evidence.semantic_kernel",
    )
    return SemanticKernelBinding(
        id=_string(payload.get("id"), "ISA campaign.evidence.semantic_kernel.id"),
        decoder_sha256=_sha256(
            payload.get("decoder_sha256"),
            "ISA campaign.evidence.semantic_kernel.decoder_sha256",
        ),
        semantics_sha256=_sha256(
            payload.get("semantics_sha256"),
            "ISA campaign.evidence.semantic_kernel.semantics_sha256",
        ),
        lean_version=_string(
            payload.get("lean_version"),
            "ISA campaign.evidence.semantic_kernel.lean_version",
        ),
    )


def _evidence_payload(value: CampaignEvidenceBinding) -> dict[str, Any]:
    return {
        "kernel_qualification_sha256": value.kernel_qualification_sha256,
        "kernel_qualification_supplied": value.kernel_qualification_supplied,
        "kernel_selection_sha256": value.kernel_selection_sha256,
        "selected_binary": (
            None
            if value.selected_binary_id is None
            else {
                "id": value.selected_binary_id,
                "sha256": value.selected_binary_sha256,
            }
        ),
        "semantic_kernel": (
            None
            if value.semantic_kernel is None
            else _kernel_payload(value.semantic_kernel)
        ),
    }


def _parse_evidence_binding(value: Any) -> CampaignEvidenceBinding:
    payload = _object(value, "ISA campaign.evidence")
    _exact_fields(
        payload,
        {
            "kernel_qualification_sha256",
            "kernel_qualification_supplied",
            "kernel_selection_sha256",
            "selected_binary",
            "semantic_kernel",
        },
        "ISA campaign.evidence",
    )
    qualification_sha256 = _optional_sha256(
        payload.get("kernel_qualification_sha256"),
        "ISA campaign.evidence.kernel_qualification_sha256",
    )
    qualification_supplied = _boolean(
        payload.get("kernel_qualification_supplied"),
        "ISA campaign.evidence.kernel_qualification_supplied",
    )
    selection_sha256 = _optional_sha256(
        payload.get("kernel_selection_sha256"),
        "ISA campaign.evidence.kernel_selection_sha256",
    )
    raw_binary = payload.get("selected_binary")
    if raw_binary is None:
        binary_id = None
        binary_sha256 = None
    else:
        binary = _object(raw_binary, "ISA campaign.evidence.selected_binary")
        _exact_fields(
            binary,
            {"id", "sha256"},
            "ISA campaign.evidence.selected_binary",
        )
        binary_id = _string(
            binary.get("id"), "ISA campaign.evidence.selected_binary.id"
        )
        binary_sha256 = _sha256(
            binary.get("sha256"),
            "ISA campaign.evidence.selected_binary.sha256",
        )
    raw_kernel = payload.get("semantic_kernel")
    kernel = (
        None if raw_kernel is None else _parse_kernel_binding(raw_kernel)
    )
    if qualification_supplied and qualification_sha256 is None:
        raise ISAQualificationCampaignError(
            "supplied kernel qualification requires its SHA-256 binding"
        )
    if (
        qualification_sha256 is not None
        and not qualification_supplied
        and selection_sha256 is None
    ):
        raise ISAQualificationCampaignError(
            "unsupplied qualification may only be referenced by a kernel selection"
        )
    if selection_sha256 is None:
        if raw_binary is not None:
            raise ISAQualificationCampaignError(
                "selected_binary requires a kernel selection"
            )
    elif raw_binary is None or qualification_sha256 is None:
        raise ISAQualificationCampaignError(
            "kernel selection requires binary and qualification bindings"
        )
    if qualification_sha256 is None:
        if kernel is not None:
            raise ISAQualificationCampaignError(
                "semantic kernel requires qualification evidence"
            )
    elif kernel is None:
        raise ISAQualificationCampaignError(
            "qualification evidence requires a semantic kernel binding"
        )
    return CampaignEvidenceBinding(
        kernel_qualification_sha256=qualification_sha256,
        kernel_qualification_supplied=qualification_supplied,
        kernel_selection_sha256=selection_sha256,
        selected_binary_id=binary_id,
        selected_binary_sha256=binary_sha256,
        semantic_kernel=kernel,
    )


def _campaign_status(
    disposition: ProfileDisposition,
    evidence_status: QualificationStatus | None,
) -> CampaignQualificationStatus:
    if disposition in {
        ProfileDisposition.EXTERNAL_PLATFORM,
        ProfileDisposition.EXCLUDED_UNSUPPORTED,
    }:
        return CampaignQualificationStatus.NOT_APPLICABLE
    if evidence_status is None:
        return CampaignQualificationStatus.UNQUALIFIED
    return CampaignQualificationStatus(evidence_status.value)


def _reason_codes(
    *,
    disposition: ProfileDisposition,
    required: bool,
    status: CampaignQualificationStatus,
) -> tuple[CampaignReasonCode, ...]:
    result: set[CampaignReasonCode] = set()
    if required:
        result.add(CampaignReasonCode.REQUIRED_EXACT_SEMANTIC_FORM)
    if disposition is ProfileDisposition.EXTERNAL_PLATFORM:
        result.add(
            CampaignReasonCode.EXTERNAL_PLATFORM_NOT_KERNEL_QUALIFIED
        )
    elif disposition is ProfileDisposition.EXCLUDED_UNSUPPORTED:
        result.add(
            CampaignReasonCode.EXCLUDED_UNSUPPORTED_NOT_KERNEL_QUALIFIED
        )
    else:
        result.add(
            {
                CampaignQualificationStatus.QUALIFIED: (
                    CampaignReasonCode.QUALIFICATION_EVIDENCE_AGREES
                ),
                CampaignQualificationStatus.UNQUALIFIED: (
                    CampaignReasonCode.QUALIFICATION_EVIDENCE_MISSING
                ),
                CampaignQualificationStatus.INCOMPLETE: (
                    CampaignReasonCode.QUALIFICATION_EVIDENCE_INCOMPLETE
                ),
                CampaignQualificationStatus.DISPUTED: (
                    CampaignReasonCode.QUALIFICATION_EVIDENCE_DISPUTED
                ),
                CampaignQualificationStatus.VETOED: (
                    CampaignReasonCode.LEAN_SEMANTICS_VETOED
                ),
                CampaignQualificationStatus.NOT_APPLICABLE: (
                    CampaignReasonCode.QUALIFICATION_EVIDENCE_MISSING
                ),
            }[status]
        )
    return tuple(sorted(result, key=lambda row: row.value))


def _validate_disposition_reasons(
    disposition: ProfileDisposition,
    reasons: tuple[DispositionReason, ...],
    context: str,
) -> None:
    expected: dict[ProfileDisposition, set[tuple[DispositionReason, ...]]] = {
        ProfileDisposition.CORE: {
            (DispositionReason.CORE_STATE,),
        },
        ProfileDisposition.EXTERNAL_PLATFORM: {
            (DispositionReason.EXTERNAL_EVENT_CATEGORY,),
        },
        ProfileDisposition.EXCLUDED_UNSUPPORTED: {
            (DispositionReason.UNSUPPORTED_SYSTEM_CATEGORY,),
            (DispositionReason.PRIVILEGED_ATTRIBUTE,),
            (DispositionReason.PRIVILEGED_OPERAND_CLASS,),
        },
    }
    if disposition is ProfileDisposition.SEPARATELY_QUALIFIED:
        allowed = {
            DispositionReason.AMBIGUOUS_SPECIAL_STATE_CATEGORY,
            DispositionReason.X87_STATE,
            DispositionReason.COMPLEX_FLAG_STATE,
        }
        if reasons and len(reasons) == len(set(reasons)) and set(reasons) <= allowed:
            return
        raise ISAQualificationCampaignError(
            f"{context} do not match profile disposition {disposition.value}"
        )
    if reasons not in expected[disposition]:
        raise ISAQualificationCampaignError(
            f"{context} do not match profile disposition {disposition.value}"
        )


def _coverage_payload(value: CampaignCoverage) -> dict[str, Any]:
    return {
        "form_id": value.form_id,
        "table_indices": list(value.table_indices),
        "category": value.category,
        "isa_set": value.isa_set,
        "profile_disposition": value.disposition.value,
        "disposition_reasons": [
            reason.value for reason in value.disposition_reasons
        ],
        "required": value.required,
        "semantic_form": value.semantic_form,
        "evidence_qualification_sha256": value.evidence_qualification_sha256,
        "evidence_status": (
            None if value.evidence_status is None else value.evidence_status.value
        ),
        "qualification_status": value.qualification_status.value,
        "counts_as_qualified": value.counts_as_qualified,
        "reason_codes": [reason.value for reason in value.reason_codes],
        "evidence_reason_codes": list(value.evidence_reason_codes),
    }


def _parse_coverage(value: Any, index: int) -> CampaignCoverage:
    context = f"ISA campaign.coverage[{index}]"
    payload = _object(value, context)
    _exact_fields(
        payload,
        {
            "form_id",
            "table_indices",
            "category",
            "isa_set",
            "profile_disposition",
            "disposition_reasons",
            "required",
            "semantic_form",
            "evidence_qualification_sha256",
            "evidence_status",
            "qualification_status",
            "counts_as_qualified",
            "reason_codes",
            "evidence_reason_codes",
        },
        context,
    )
    raw_indices = payload.get("table_indices")
    if not isinstance(raw_indices, list):
        raise ISAQualificationCampaignError(
            f"{context}.table_indices must be a list"
        )
    table_indices = tuple(
        _uint32(row, f"{context}.table_indices[{row_index}]")
        for row_index, row in enumerate(raw_indices)
    )
    if not table_indices or table_indices != tuple(sorted(set(table_indices))):
        raise ISAQualificationCampaignError(
            f"{context}.table_indices must be non-empty, unique, and ordered"
        )
    disposition = _enum(
        ProfileDisposition,
        payload.get("profile_disposition"),
        f"{context}.profile_disposition",
    )
    raw_reasons = payload.get("disposition_reasons")
    if not isinstance(raw_reasons, list):
        raise ISAQualificationCampaignError(
            f"{context}.disposition_reasons must be a list"
        )
    disposition_reasons = tuple(
        _enum(
            DispositionReason,
            row,
            f"{context}.disposition_reasons[{row_index}]",
        )
        for row_index, row in enumerate(raw_reasons)
    )
    _validate_disposition_reasons(
        disposition, disposition_reasons, f"{context}.disposition_reasons"
    )
    required = _boolean(payload.get("required"), f"{context}.required")
    semantic_form = _optional_string(
        payload.get("semantic_form"), f"{context}.semantic_form"
    )
    if required and semantic_form is None:
        raise ISAQualificationCampaignError(
            f"{context} required form must name its exact semantic_form"
        )
    raw_evidence_status = payload.get("evidence_status")
    evidence_status = (
        None
        if raw_evidence_status is None
        else _enum(
            QualificationStatus,
            raw_evidence_status,
            f"{context}.evidence_status",
        )
    )
    status = _enum(
        CampaignQualificationStatus,
        payload.get("qualification_status"),
        f"{context}.qualification_status",
    )
    if status is not _campaign_status(disposition, evidence_status):
        raise ISAQualificationCampaignError(
            f"{context}.qualification_status is inconsistent"
        )
    counts_as_qualified = _boolean(
        payload.get("counts_as_qualified"),
        f"{context}.counts_as_qualified",
    )
    if counts_as_qualified is not (
        status is CampaignQualificationStatus.QUALIFIED
    ):
        raise ISAQualificationCampaignError(
            f"{context}.counts_as_qualified is inconsistent"
        )
    raw_reason_codes = _ordered_strings(
        payload.get("reason_codes"),
        f"{context}.reason_codes",
        allow_empty=False,
        reason_codes=True,
    )
    reason_codes = tuple(
        _enum(
            CampaignReasonCode,
            row,
            f"{context}.reason_codes[{row_index}]",
        )
        for row_index, row in enumerate(raw_reason_codes)
    )
    if reason_codes != _reason_codes(
        disposition=disposition,
        required=required,
        status=status,
    ):
        raise ISAQualificationCampaignError(
            f"{context}.reason_codes are inconsistent"
        )
    evidence_reason_codes = _ordered_strings(
        payload.get("evidence_reason_codes"),
        f"{context}.evidence_reason_codes",
        allow_empty=True,
        reason_codes=True,
    )
    evidence_sha256 = _optional_sha256(
        payload.get("evidence_qualification_sha256"),
        f"{context}.evidence_qualification_sha256",
    )
    if evidence_status is None and (
        evidence_sha256 is not None
        or semantic_form is not None
        or evidence_reason_codes
    ):
        raise ISAQualificationCampaignError(
            f"{context} has evidence fields without an evidence status"
        )
    if evidence_status is not None and semantic_form is None:
        raise ISAQualificationCampaignError(
            f"{context} evidence must bind a semantic_form"
        )
    if (
        evidence_status is QualificationStatus.QUALIFIED
        and evidence_sha256 is None
    ):
        raise ISAQualificationCampaignError(
            f"{context} qualified evidence requires its artifact SHA-256"
        )
    return CampaignCoverage(
        form_id=_string(payload.get("form_id"), f"{context}.form_id"),
        table_indices=table_indices,
        category=_string(payload.get("category"), f"{context}.category"),
        isa_set=_string(payload.get("isa_set"), f"{context}.isa_set"),
        disposition=disposition,
        disposition_reasons=disposition_reasons,
        required=required,
        semantic_form=semantic_form,
        evidence_qualification_sha256=evidence_sha256,
        evidence_status=evidence_status,
        qualification_status=status,
        counts_as_qualified=counts_as_qualified,
        reason_codes=reason_codes,
        evidence_reason_codes=evidence_reason_codes,
    )


def _priority(value: CampaignCoverage) -> CampaignPriority:
    if value.disposition in {
        ProfileDisposition.EXTERNAL_PLATFORM,
        ProfileDisposition.EXCLUDED_UNSUPPORTED,
    }:
        return CampaignPriority.VISIBILITY_ONLY
    if value.required:
        return CampaignPriority.REQUIRED_EXACT_SEMANTIC_FORM
    if value.disposition is ProfileDisposition.CORE:
        return CampaignPriority.CORE_FORM
    return CampaignPriority.SEPARATELY_QUALIFIED_FORM


def _next_action(value: CampaignCoverage) -> CampaignNextAction:
    if value.disposition is ProfileDisposition.EXTERNAL_PLATFORM:
        return CampaignNextAction.DEFINE_EXTERNAL_PLATFORM_CONTRACT
    if value.disposition is ProfileDisposition.EXCLUDED_UNSUPPORTED:
        return CampaignNextAction.RETAIN_EXCLUSION_OR_EXPAND_PROFILE
    if value.required:
        return CampaignNextAction.QUALIFY_EXACT_LEAN_SEMANTIC_FORM
    actions = {
        ProfileDisposition.CORE: {
            CampaignQualificationStatus.UNQUALIFIED: (
                CampaignNextAction.IMPLEMENT_AND_QUALIFY_CORE_FORM
            ),
            CampaignQualificationStatus.INCOMPLETE: (
                CampaignNextAction.COMPLETE_CORE_FORM_EVIDENCE
            ),
            CampaignQualificationStatus.DISPUTED: (
                CampaignNextAction.RESOLVE_CORE_FORM_ORACLE_DISPUTE
            ),
            CampaignQualificationStatus.VETOED: (
                CampaignNextAction.REPAIR_CORE_FORM_LEAN_SEMANTICS
            ),
        },
        ProfileDisposition.SEPARATELY_QUALIFIED: {
            CampaignQualificationStatus.UNQUALIFIED: (
                CampaignNextAction.IMPLEMENT_AND_QUALIFY_SEPARATE_FORM
            ),
            CampaignQualificationStatus.INCOMPLETE: (
                CampaignNextAction.COMPLETE_SEPARATE_FORM_EVIDENCE
            ),
            CampaignQualificationStatus.DISPUTED: (
                CampaignNextAction.RESOLVE_SEPARATE_FORM_ORACLE_DISPUTE
            ),
            CampaignQualificationStatus.VETOED: (
                CampaignNextAction.REPAIR_SEPARATE_FORM_LEAN_SEMANTICS
            ),
        },
    }
    try:
        return actions[value.disposition][value.qualification_status]
    except KeyError as exc:
        raise ISAQualificationCampaignError(
            "qualified coverage cannot appear on the campaign frontier"
        ) from exc


_PRIORITY_ORDER = {
    CampaignPriority.REQUIRED_EXACT_SEMANTIC_FORM: 0,
    CampaignPriority.CORE_FORM: 1,
    CampaignPriority.SEPARATELY_QUALIFIED_FORM: 2,
    CampaignPriority.VISIBILITY_ONLY: 3,
}


def _build_frontier(
    coverage: tuple[CampaignCoverage, ...],
) -> tuple[CampaignFrontierItem, ...]:
    pending = [row for row in coverage if not row.counts_as_qualified]
    pending.sort(
        key=lambda row: (
            _PRIORITY_ORDER[_priority(row)],
            row.category,
            row.isa_set,
            row.form_id,
        )
    )
    rank = 0
    result: list[CampaignFrontierItem] = []
    for row in pending:
        priority = _priority(row)
        row_rank: int | None
        if priority is CampaignPriority.VISIBILITY_ONLY:
            row_rank = None
        else:
            rank += 1
            row_rank = rank
        result.append(
            CampaignFrontierItem(
                rank=row_rank,
                priority=priority,
                form_id=row.form_id,
                semantic_form=row.semantic_form,
                qualification_status=row.qualification_status,
                reason_codes=row.reason_codes,
                evidence_reason_codes=row.evidence_reason_codes,
                next_action=_next_action(row),
            )
        )
    return tuple(result)


def _frontier_payload(value: CampaignFrontierItem) -> dict[str, Any]:
    return {
        "rank": value.rank,
        "priority": value.priority.value,
        "form_id": value.form_id,
        "semantic_form": value.semantic_form,
        "qualification_status": value.qualification_status.value,
        "reason_codes": [reason.value for reason in value.reason_codes],
        "evidence_reason_codes": list(value.evidence_reason_codes),
        "next_action": value.next_action.value,
    }


def _parse_frontier(value: Any, index: int) -> CampaignFrontierItem:
    context = f"ISA campaign.frontier[{index}]"
    payload = _object(value, context)
    _exact_fields(
        payload,
        {
            "rank",
            "priority",
            "form_id",
            "semantic_form",
            "qualification_status",
            "reason_codes",
            "evidence_reason_codes",
            "next_action",
        },
        context,
    )
    raw_rank = payload.get("rank")
    rank = (
        None if raw_rank is None else _positive_count(raw_rank, f"{context}.rank")
    )
    reason_code_values = _ordered_strings(
        payload.get("reason_codes"),
        f"{context}.reason_codes",
        allow_empty=False,
        reason_codes=True,
    )
    return CampaignFrontierItem(
        rank=rank,
        priority=_enum(
            CampaignPriority, payload.get("priority"), f"{context}.priority"
        ),
        form_id=_string(payload.get("form_id"), f"{context}.form_id"),
        semantic_form=_optional_string(
            payload.get("semantic_form"), f"{context}.semantic_form"
        ),
        qualification_status=_enum(
            CampaignQualificationStatus,
            payload.get("qualification_status"),
            f"{context}.qualification_status",
        ),
        reason_codes=tuple(
            _enum(
                CampaignReasonCode,
                row,
                f"{context}.reason_codes[{row_index}]",
            )
            for row_index, row in enumerate(reason_code_values)
        ),
        evidence_reason_codes=_ordered_strings(
            payload.get("evidence_reason_codes"),
            f"{context}.evidence_reason_codes",
            allow_empty=True,
            reason_codes=True,
        ),
        next_action=_enum(
            CampaignNextAction,
            payload.get("next_action"),
            f"{context}.next_action",
        ),
    )


def _group_counts(
    coverage: tuple[CampaignCoverage, ...],
    key,
    keys: tuple[str, ...],
) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for group in keys:
        rows = [row for row in coverage if key(row) == group]
        qualified = sum(row.counts_as_qualified for row in rows)
        result[group] = {
            "forms": len(rows),
            "qualified": qualified,
            "frontier": len(rows) - qualified,
        }
    return result


def _build_counts(
    coverage: tuple[CampaignCoverage, ...],
    frontier: tuple[CampaignFrontierItem, ...],
) -> dict[str, Any]:
    qualified = sum(row.counts_as_qualified for row in coverage)
    required = sum(row.required for row in coverage)
    required_qualified = sum(
        row.required and row.counts_as_qualified for row in coverage
    )
    categories = tuple(sorted({row.category for row in coverage}))
    isa_sets = tuple(sorted({row.isa_set for row in coverage}))
    disposition_keys = tuple(row.value for row in ProfileDisposition)
    return {
        "forms": len(coverage),
        "qualified": qualified,
        "frontier": len(frontier),
        "required_forms": required,
        "required_qualified": required_qualified,
        "ranked_next_work": sum(row.rank is not None for row in frontier),
        "visibility_only": sum(row.rank is None for row in frontier),
        "by_profile_disposition": _group_counts(
            coverage,
            lambda row: row.disposition.value,
            disposition_keys,
        ),
        "by_category": _group_counts(
            coverage, lambda row: row.category, categories
        ),
        "by_isa_set": _group_counts(
            coverage, lambda row: row.isa_set, isa_sets
        ),
        "by_qualification_status": {
            status.value: sum(
                row.qualification_status is status for row in coverage
            )
            for status in CampaignQualificationStatus
        },
    }


def _validate_group_counts(
    value: Any,
    expected: Mapping[str, Mapping[str, int]],
    context: str,
) -> None:
    payload = _object(value, context)
    if set(payload) != set(expected):
        raise ISAQualificationCampaignError(
            f"{context} has inconsistent group keys"
        )
    for group, expected_counts in expected.items():
        counts = _object(payload.get(group), f"{context}.{group}")
        _exact_fields(
            counts, {"forms", "qualified", "frontier"}, f"{context}.{group}"
        )
        observed = {
            name: _count(counts.get(name), f"{context}.{group}.{name}")
            for name in ("forms", "qualified", "frontier")
        }
        if observed != expected_counts:
            raise ISAQualificationCampaignError(
                f"{context}.{group} is inconsistent"
            )


def _validate_counts(
    value: Any, expected: Mapping[str, Any]
) -> dict[str, Any]:
    context = "ISA campaign.counts"
    payload = _object(value, context)
    _exact_fields(payload, set(expected), context)
    scalar_fields = (
        "forms",
        "qualified",
        "frontier",
        "required_forms",
        "required_qualified",
        "ranked_next_work",
        "visibility_only",
    )
    for field in scalar_fields:
        if _count(payload.get(field), f"{context}.{field}") != expected[field]:
            raise ISAQualificationCampaignError(
                f"{context}.{field} is inconsistent"
            )
    for field in (
        "by_profile_disposition",
        "by_category",
        "by_isa_set",
    ):
        _validate_group_counts(
            payload.get(field), expected[field], f"{context}.{field}"
        )
    statuses = _object(
        payload.get("by_qualification_status"),
        f"{context}.by_qualification_status",
    )
    if set(statuses) != set(expected["by_qualification_status"]):
        raise ISAQualificationCampaignError(
            f"{context}.by_qualification_status has inconsistent keys"
        )
    for status, expected_count in expected["by_qualification_status"].items():
        if (
            _count(
                statuses.get(status),
                f"{context}.by_qualification_status.{status}",
            )
            != expected_count
        ):
            raise ISAQualificationCampaignError(
                f"{context}.by_qualification_status.{status} is inconsistent"
            )
    return dict(expected)


def _trust_payload(value: CampaignTrust) -> dict[str, Any]:
    if value != CampaignTrust():
        raise ISAQualificationCampaignError(
            "ISA campaign cannot claim proof authority"
        )
    return {
        "role": value.role,
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


def _parse_trust(value: Any) -> CampaignTrust:
    payload = _object(value, "ISA campaign.trust")
    _exact_fields(
        payload,
        {"role", "proof_authority", "closes_stage_a_proof"},
        "ISA campaign.trust",
    )
    if payload.get("role") != ISA_QUALIFICATION_CAMPAIGN_TRUST_ROLE:
        raise ISAQualificationCampaignError(
            "ISA campaign.trust.role is unsupported"
        )
    if payload.get("proof_authority") is not False:
        raise ISAQualificationCampaignError(
            "ISA campaign.trust.proof_authority must be false"
        )
    if payload.get("closes_stage_a_proof") is not False:
        raise ISAQualificationCampaignError(
            "ISA campaign.trust.closes_stage_a_proof must be false"
        )
    return CampaignTrust()


def _typed_qualification(
    value: ISAKernelQualification | Mapping[str, Any] | None,
) -> ISAKernelQualification | None:
    if value is None or isinstance(value, ISAKernelQualification):
        return value
    if isinstance(value, Mapping):
        return parse_kernel_qualification(value)
    raise ISAQualificationCampaignError(
        "qualification must be an ISAKernelQualification artifact"
    )


def _typed_selection(
    value: ISAKernelSelection | Mapping[str, Any] | None,
) -> ISAKernelSelection | None:
    if value is None or isinstance(value, ISAKernelSelection):
        return value
    if isinstance(value, Mapping):
        return parse_kernel_selection(value)
    raise ISAQualificationCampaignError(
        "selection must be an ISAKernelSelection artifact"
    )


def build_isa_qualification_campaign(
    *,
    catalog: XEDInstructionCatalog,
    qualification: ISAKernelQualification | Mapping[str, Any] | None = None,
    selection: ISAKernelSelection | Mapping[str, Any] | None = None,
    catalog_form_to_qualification_form: Mapping[str, str] | None = None,
) -> ISAQualificationCampaign:
    """Build the complete deterministic campaign for ``pe32-i686-v1``."""
    if not isinstance(catalog, XEDInstructionCatalog):
        raise ISAQualificationCampaignError(
            "catalog must be a typed XEDInstructionCatalog"
        )
    if catalog.profile.id != ISA_PROFILE_ID:
        raise ISAQualificationCampaignError(
            f"catalog profile must be {ISA_PROFILE_ID}"
        )
    typed_qualification = _typed_qualification(qualification)
    typed_selection = _typed_selection(selection)
    for label, artifact in (
        ("qualification", typed_qualification),
        ("selection", typed_selection),
    ):
        if artifact is not None and artifact.profile.id != catalog.profile.id:
            raise ISAQualificationCampaignError(
                f"{label} profile does not match the XED catalog"
            )
    qualification_sha256 = (
        None
        if typed_qualification is None
        else artifact_sha256(typed_qualification)
    )
    if typed_selection is not None:
        if (
            typed_qualification is not None
            and typed_selection.kernel_qualification_sha256
            != qualification_sha256
        ):
            raise ISAQualificationCampaignError(
                "selection does not bind the supplied kernel qualification"
            )
        if (
            typed_qualification is not None
            and (
                typed_selection.profile != typed_qualification.profile
                or typed_selection.semantic_kernel
                != typed_qualification.semantic_kernel
            )
        ):
            raise ISAQualificationCampaignError(
                "selection and qualification bindings disagree"
            )
        qualification_binding_sha256 = (
            typed_selection.kernel_qualification_sha256
        )
        semantic_kernel = typed_selection.semantic_kernel
    elif typed_qualification is not None:
        qualification_binding_sha256 = qualification_sha256
        semantic_kernel = typed_qualification.semantic_kernel
    else:
        qualification_binding_sha256 = None
        semantic_kernel = None

    catalog_form_ids = {row.form_id for row in catalog.templates}
    qualification_forms = (
        {}
        if typed_qualification is None
        else {row.form_id: row for row in typed_qualification.forms}
    )
    selected_forms = (
        {}
        if typed_selection is None
        else {row.form_id: row for row in typed_selection.selected_forms}
    )
    form_crosswalk = dict(catalog_form_to_qualification_form or {})
    if any(
        not isinstance(source, str)
        or not isinstance(target, str)
        or not source
        or not target
        for source, target in form_crosswalk.items()
    ):
        raise ISAQualificationCampaignError(
            "catalog-to-qualification form crosswalk must contain non-empty strings"
        )
    unknown_catalog_forms = sorted(set(form_crosswalk) - catalog_form_ids)
    if unknown_catalog_forms:
        raise ISAQualificationCampaignError(
            "form crosswalk contains forms absent from the XED catalog: "
            f"{unknown_catalog_forms!r}"
        )
    evidence_form_ids = set(qualification_forms) | set(selected_forms)
    unknown_targets = sorted(set(form_crosswalk.values()) - evidence_form_ids)
    if unknown_targets:
        raise ISAQualificationCampaignError(
            "form crosswalk targets forms absent from qualification evidence: "
            f"{unknown_targets!r}"
        )
    referenced_evidence = {
        form_crosswalk.get(form_id, form_id) for form_id in catalog_form_ids
    }
    unknown_qualification = sorted(
        set(qualification_forms) - referenced_evidence
    )
    unknown_selection = sorted(set(selected_forms) - referenced_evidence)
    if unknown_qualification:
        raise ISAQualificationCampaignError(
            "qualification contains forms not referenced by the XED catalog crosswalk: "
            f"{unknown_qualification!r}"
        )
    if unknown_selection:
        raise ISAQualificationCampaignError(
            "selection contains forms not referenced by the XED catalog crosswalk: "
            f"{unknown_selection!r}"
        )

    coverage: list[CampaignCoverage] = []
    for template in sorted(catalog.templates, key=lambda row: row.form_id):
        evidence_form_id = form_crosswalk.get(
            template.form_id, template.form_id
        )
        selected = selected_forms.get(evidence_form_id)
        qualified = qualification_forms.get(evidence_form_id)
        if selected is not None:
            required = True
            semantic_form = selected.semantic_form
            evidence_status = selected.status
            evidence_sha256 = selected.qualification_sha256
            evidence_reason_codes = tuple(
                sorted({row.code for row in selected.diagnostics})
            )
        elif qualified is not None:
            required = False
            semantic_form = qualified.semantic_form
            evidence_status = qualified.status
            evidence_sha256 = qualified.sha256()
            evidence_reason_codes = tuple(
                sorted({row.code for row in qualified.diagnostics})
            )
        else:
            required = False
            semantic_form = None
            evidence_status = None
            evidence_sha256 = None
            evidence_reason_codes = ()
        status = _campaign_status(template.disposition, evidence_status)
        row = CampaignCoverage(
            form_id=template.form_id,
            table_indices=template.table_indices,
            category=template.category,
            isa_set=template.isa_set,
            disposition=template.disposition,
            disposition_reasons=template.disposition_reasons,
            required=required,
            semantic_form=semantic_form,
            evidence_qualification_sha256=evidence_sha256,
            evidence_status=evidence_status,
            qualification_status=status,
            counts_as_qualified=(
                status is CampaignQualificationStatus.QUALIFIED
            ),
            reason_codes=_reason_codes(
                disposition=template.disposition,
                required=required,
                status=status,
            ),
            evidence_reason_codes=evidence_reason_codes,
        )
        coverage.append(row)
    coverage_rows = tuple(coverage)
    frontier = _build_frontier(coverage_rows)
    result = ISAQualificationCampaign(
        profile=catalog.profile.id,
        catalog=CampaignCatalogBinding(
            sha256=xed_instruction_catalog_sha256(catalog),
            generator_name=catalog.generator.name,
            xed_version=catalog.generator.xed_version,
            templates=len(catalog.templates),
        ),
        evidence=CampaignEvidenceBinding(
            kernel_qualification_sha256=qualification_binding_sha256,
            kernel_qualification_supplied=typed_qualification is not None,
            kernel_selection_sha256=(
                None
                if typed_selection is None
                else artifact_sha256(typed_selection)
            ),
            selected_binary_id=(
                None if typed_selection is None else typed_selection.binary_id
            ),
            selected_binary_sha256=(
                None
                if typed_selection is None
                else typed_selection.binary_sha256
            ),
            semantic_kernel=semantic_kernel,
        ),
        coverage=coverage_rows,
        frontier=frontier,
        counts=_build_counts(coverage_rows, frontier),
    )
    # Validate every emitted invariant through the public strict parser.
    return parse_isa_qualification_campaign(
        _serialize_isa_qualification_campaign(result)
    )


def _serialize_isa_qualification_campaign(
    value: ISAQualificationCampaign,
) -> dict[str, Any]:
    return {
        "format": value.format,
        "profile": value.profile,
        "catalog": _catalog_payload(value.catalog),
        "evidence": _evidence_payload(value.evidence),
        "coverage": [_coverage_payload(row) for row in value.coverage],
        "frontier": [_frontier_payload(row) for row in value.frontier],
        "counts": dict(value.counts),
        "trust": _trust_payload(value.trust),
    }


def serialize_isa_qualification_campaign(
    value: ISAQualificationCampaign,
) -> dict[str, Any]:
    if not isinstance(value, ISAQualificationCampaign):
        raise ISAQualificationCampaignError(
            "campaign must be an ISAQualificationCampaign"
        )
    payload = _serialize_isa_qualification_campaign(value)
    if parse_isa_qualification_campaign(payload) != value:
        raise ISAQualificationCampaignError(
            "campaign is not a valid typed instance"
        )
    return payload


def parse_isa_qualification_campaign(value: Any) -> ISAQualificationCampaign:
    payload = _object(value, "ISA campaign")
    _exact_fields(
        payload,
        {
            "format",
            "profile",
            "catalog",
            "evidence",
            "coverage",
            "frontier",
            "counts",
            "trust",
        },
        "ISA campaign",
    )
    if payload.get("format") != ISA_QUALIFICATION_CAMPAIGN_FORMAT:
        raise ISAQualificationCampaignError(
            "unsupported ISA qualification campaign format"
        )
    if payload.get("profile") != ISA_PROFILE_ID:
        raise ISAQualificationCampaignError(
            f"ISA campaign.profile must be {ISA_PROFILE_ID}"
        )
    raw_coverage = payload.get("coverage")
    if not isinstance(raw_coverage, list) or not raw_coverage:
        raise ISAQualificationCampaignError(
            "ISA campaign.coverage must be a non-empty list"
        )
    coverage = tuple(
        _parse_coverage(row, index)
        for index, row in enumerate(raw_coverage)
    )
    form_ids = tuple(row.form_id for row in coverage)
    if form_ids != tuple(sorted(set(form_ids))):
        raise ISAQualificationCampaignError(
            "ISA campaign.coverage form IDs must be unique and ordered"
        )
    all_table_indices = [
        table_index for row in coverage for table_index in row.table_indices
    ]
    if len(all_table_indices) != len(set(all_table_indices)):
        raise ISAQualificationCampaignError(
            "ISA campaign.coverage table indices must be globally unique"
        )
    catalog = _parse_catalog_binding(payload.get("catalog"))
    if catalog.templates != len(coverage):
        raise ISAQualificationCampaignError(
            "ISA campaign catalog template count is inconsistent"
        )
    evidence = _parse_evidence_binding(payload.get("evidence"))
    if evidence.kernel_selection_sha256 is None and any(
        row.required for row in coverage
    ):
        raise ISAQualificationCampaignError(
            "required semantic forms require a kernel selection binding"
        )
    if evidence.kernel_selection_sha256 is not None and not any(
        row.required for row in coverage
    ):
        raise ISAQualificationCampaignError(
            "kernel selection must contribute at least one required form"
        )
    if evidence.kernel_qualification_sha256 is None and any(
        row.evidence_status is not None for row in coverage
    ):
        raise ISAQualificationCampaignError(
            "coverage evidence requires a kernel qualification binding"
        )
    raw_frontier = payload.get("frontier")
    if not isinstance(raw_frontier, list):
        raise ISAQualificationCampaignError(
            "ISA campaign.frontier must be a list"
        )
    frontier = tuple(
        _parse_frontier(row, index)
        for index, row in enumerate(raw_frontier)
    )
    expected_frontier = _build_frontier(coverage)
    if frontier != expected_frontier:
        raise ISAQualificationCampaignError(
            "ISA campaign.frontier is inconsistent with coverage"
        )
    counts = _validate_counts(
        payload.get("counts"), _build_counts(coverage, frontier)
    )
    return ISAQualificationCampaign(
        profile=ISA_PROFILE_ID,
        catalog=catalog,
        evidence=evidence,
        coverage=coverage,
        frontier=frontier,
        counts=counts,
        trust=_parse_trust(payload.get("trust")),
    )


def canonical_isa_qualification_campaign_input(
    value: ISAQualificationCampaign,
) -> bytes:
    return _canonical_json_bytes(serialize_isa_qualification_campaign(value)) + b"\n"


def isa_qualification_campaign_sha256(
    value: ISAQualificationCampaign,
) -> str:
    return hashlib.sha256(
        canonical_isa_qualification_campaign_input(value)
    ).hexdigest()


# Concise aliases for callers that use the module's shorter campaign name.
build_isa_campaign_plan = build_isa_qualification_campaign
plan_isa_qualification_campaign = build_isa_qualification_campaign
parse_isa_campaign_plan = parse_isa_qualification_campaign
serialize_isa_campaign_plan = serialize_isa_qualification_campaign
isa_campaign_sha256 = isa_qualification_campaign_sha256


__all__ = [
    "CampaignCatalogBinding",
    "CampaignCoverage",
    "CampaignEvidenceBinding",
    "CampaignFrontierItem",
    "CampaignNextAction",
    "CampaignPriority",
    "CampaignQualificationStatus",
    "CampaignReasonCode",
    "CampaignTrust",
    "ISACampaignPlan",
    "ISAQualificationCampaign",
    "ISAQualificationCampaignError",
    "ISA_QUALIFICATION_CAMPAIGN_FORMAT",
    "ISA_QUALIFICATION_CAMPAIGN_TRUST_ROLE",
    "build_isa_campaign_plan",
    "build_isa_qualification_campaign",
    "canonical_isa_qualification_campaign_input",
    "isa_campaign_sha256",
    "isa_qualification_campaign_sha256",
    "parse_isa_campaign_plan",
    "parse_isa_qualification_campaign",
    "plan_isa_qualification_campaign",
    "serialize_isa_campaign_plan",
    "serialize_isa_qualification_campaign",
    "xed_instruction_catalog_sha256",
]
