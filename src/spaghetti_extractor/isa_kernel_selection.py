"""Binary-specific authority for selecting the qualified ISA kernel.

This module joins the exact-binary requirement, kernel qualification, binary
selection, and fallback capability for every reachable form. The strict v2
static gate consumes this artifact but still recomputes exact PE/form/location
bindings. Qualification gaps remain incomplete; contradictions and oracle
disputes are violations.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import copy
from dataclasses import dataclass, replace
from enum import Enum
import re
from typing import Any

from .isa_kernel_qualification import (
    BinaryFormRequirement,
    BinaryQualificationRequirements,
    ISA_KERNEL_QUALIFICATION_FORMAT,
    ISA_KERNEL_SELECTION_FORMAT,
    ISAKernelQualification,
    ISAKernelQualificationError,
    ISAKernelSelection,
    QualificationStatus,
    SelectedFormQualification,
    SourceLocation,
    artifact_sha256,
    parse_binary_qualification_requirements,
    parse_kernel_qualification,
    parse_kernel_selection,
    select_isa_kernel_qualification,
    serialize_binary_qualification_requirements,
    serialize_kernel_qualification,
    serialize_kernel_selection,
)


ISA_KERNEL_SELECTION_AUTHORITY_FORMAT = (
    "stage-a-binary-isa-kernel-selection-authority-v1"
)
BINARY_ISA_KERNEL_SELECTION_AUTHORITY_FORMAT = (
    ISA_KERNEL_SELECTION_AUTHORITY_FORMAT
)

_CAPABILITY_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_AUTHORITY = (
    "binary-specific ISA kernel selection only; "
    "no static-completeness authority"
)
_POLICY = {
    "exact_binary_required": True,
    "reachable_locations_and_forms_must_match": True,
    "qualified_decode_and_semantics_required": True,
    "oracle_disputes_veto_selection": True,
    "fallback_capability_ids_must_match": True,
    "static_completeness_authority": False,
}
_CONTRADICTORY_INCOMPLETE_CODES = frozenset({
    "semantic_form_binding_mismatch",
})


class ISAKernelSelectionAuthorityError(ValueError):
    """The authority artifact is malformed or internally inconsistent."""


class SelectionAuthorityStatus(str, Enum):
    QUALIFIED = "qualified"
    INCOMPLETE = "incomplete"
    VIOLATED = "violated"


@dataclass(frozen=True, order=True)
class FallbackCapabilityBinding:
    form_id: str
    capability_id: str


@dataclass(frozen=True)
class SelectionAuthorityIssue:
    status: SelectionAuthorityStatus
    code: str
    form_id: str | None
    message: str
    expected: Any
    observed: Any


@dataclass(frozen=True)
class ISAKernelSelectionAuthority:
    requirements: BinaryQualificationRequirements
    qualification: ISAKernelQualification
    selection: ISAKernelSelection | None
    fallback_capability_ids: tuple[FallbackCapabilityBinding, ...]
    status: SelectionAuthorityStatus
    issues: tuple[SelectionAuthorityIssue, ...]
    counts: Mapping[str, int]
    authority_sha256: str
    format: str = ISA_KERNEL_SELECTION_AUTHORITY_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "ISAKernelSelectionAuthority":
        return parse_isa_kernel_selection_authority(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_isa_kernel_selection_authority(self)

    def sha256(self) -> str:
        return artifact_sha256(self.to_payload())


@dataclass(frozen=True)
class ISAKernelSelectionAuthorityCheck:
    status: SelectionAuthorityStatus
    authority: ISAKernelSelectionAuthority | None
    issues: tuple[SelectionAuthorityIssue, ...]

    @property
    def usable(self) -> bool:
        return self.status is SelectionAuthorityStatus.QUALIFIED

    def to_payload(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "usable": self.usable,
            "authority_sha256": (
                None
                if self.authority is None
                else self.authority.authority_sha256
            ),
            "issues": [_issue_payload(issue) for issue in self.issues],
        }


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ISAKernelSelectionAuthorityError(f"{context} must be an object")
    if any(not isinstance(key, str) for key in value):
        raise ISAKernelSelectionAuthorityError(
            f"{context} field names must be strings"
        )
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing fields {missing}")
        if extra:
            details.append(f"unexpected fields {extra}")
        raise ISAKernelSelectionAuthorityError(
            f"{context} has " + " and ".join(details)
        )


def _string(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ISAKernelSelectionAuthorityError(
            f"{context} must be a nonempty canonical string"
        )
    return value


def _sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ISAKernelSelectionAuthorityError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _capability_id(value: Any, context: str) -> str:
    if not isinstance(value, str) or _CAPABILITY_ID_RE.fullmatch(value) is None:
        raise ISAKernelSelectionAuthorityError(
            f"{context} must be a stable lowercase capability ID"
        )
    return value


def _json_value(value: Any, context: str) -> Any:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, list):
        return [
            _json_value(item, f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ISAKernelSelectionAuthorityError(
                f"{context} object keys must be strings"
            )
        return {
            key: _json_value(value[key], f"{context}.{key}")
            for key in sorted(value)
        }
    raise ISAKernelSelectionAuthorityError(f"{context} is not JSON")


def _location_key(value: SourceLocation) -> tuple[str, str, int, int]:
    return (
        value.image_id,
        value.image_sha256,
        value.rva,
        value.byte_length,
    )


def _normalize_requirements(
    *,
    binary_id: str,
    binary_sha256: str,
    reachable_forms: Iterable[BinaryFormRequirement],
    qualification: ISAKernelQualification,
) -> BinaryQualificationRequirements:
    forms: list[BinaryFormRequirement] = []
    for row in reachable_forms:
        if not isinstance(row, BinaryFormRequirement):
            raise ISAKernelSelectionAuthorityError(
                "reachable forms must be BinaryFormRequirement values"
            )
        forms.append(
            BinaryFormRequirement(
                form_id=row.form_id,
                semantic_form=row.semantic_form,
                source_locations=tuple(
                    sorted(row.source_locations, key=_location_key)
                ),
            )
        )
    requirements = BinaryQualificationRequirements(
        binary_id=_string(binary_id, "binary ID"),
        binary_sha256=_sha256(binary_sha256, "binary SHA-256"),
        profile_id=qualification.profile.id,
        semantic_kernel_id=qualification.semantic_kernel.id,
        forms=tuple(sorted(forms, key=lambda row: row.form_id)),
    )
    try:
        return parse_binary_qualification_requirements(
            serialize_binary_qualification_requirements(requirements)
        )
    except ISAKernelQualificationError as exc:
        raise ISAKernelSelectionAuthorityError(str(exc)) from exc


def _parse_qualification_input(
    value: ISAKernelQualification | Mapping[str, Any],
) -> ISAKernelQualification:
    try:
        if isinstance(value, ISAKernelQualification):
            return value
        return parse_kernel_qualification(value)
    except ISAKernelQualificationError as exc:
        raise ISAKernelSelectionAuthorityError(
            f"invalid ISA kernel qualification: {exc}"
        ) from exc


def _parse_selection_input(
    value: ISAKernelSelection | Mapping[str, Any] | None,
) -> ISAKernelSelection | None:
    if value is None:
        return None
    try:
        if isinstance(value, ISAKernelSelection):
            return value
        return parse_kernel_selection(value)
    except ISAKernelQualificationError as exc:
        raise ISAKernelSelectionAuthorityError(
            f"invalid ISA kernel selection: {exc}"
        ) from exc


def _normalize_fallbacks(
    value: (
        Mapping[str, str]
        | Iterable[FallbackCapabilityBinding]
    ),
) -> tuple[FallbackCapabilityBinding, ...]:
    if isinstance(value, Mapping):
        raw_rows = tuple(
            FallbackCapabilityBinding(str(form_id), str(capability_id))
            for form_id, capability_id in value.items()
        )
    else:
        raw_rows = tuple(value)
    rows: list[FallbackCapabilityBinding] = []
    for index, row in enumerate(raw_rows):
        if not isinstance(row, FallbackCapabilityBinding):
            raise ISAKernelSelectionAuthorityError(
                "fallback capabilities must be a mapping or "
                "FallbackCapabilityBinding values"
            )
        rows.append(FallbackCapabilityBinding(
            form_id=_string(row.form_id, f"fallback capability {index} form ID"),
            capability_id=_capability_id(
                row.capability_id,
                f"fallback capability {index} capability ID",
            ),
        ))
    result = tuple(sorted(rows))
    if len({row.form_id for row in result}) != len(result):
        raise ISAKernelSelectionAuthorityError(
            "fallback capability form IDs must be unique"
        )
    return result


def _issue(
    status: SelectionAuthorityStatus,
    code: str,
    message: str,
    *,
    form_id: str | None = None,
    expected: Any = None,
    observed: Any = None,
) -> SelectionAuthorityIssue:
    return SelectionAuthorityIssue(
        status=status,
        code=code,
        form_id=form_id,
        message=message,
        expected=_json_value(expected, f"issue {code} expected"),
        observed=_json_value(observed, f"issue {code} observed"),
    )


def _issue_key(value: SelectionAuthorityIssue) -> tuple[int, str, str]:
    return (
        0 if value.status is SelectionAuthorityStatus.VIOLATED else 1,
        value.form_id or "",
        value.code,
    )


def _issue_payload(value: SelectionAuthorityIssue) -> dict[str, Any]:
    return {
        "status": value.status.value,
        "code": value.code,
        "form_id": value.form_id,
        "message": value.message,
        "expected": copy.deepcopy(value.expected),
        "observed": copy.deepcopy(value.observed),
    }


def _parse_issue(value: Any, context: str) -> SelectionAuthorityIssue:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {"status", "code", "form_id", "message", "expected", "observed"},
        context,
    )
    try:
        status = SelectionAuthorityStatus(payload.get("status"))
    except ValueError as exc:
        raise ISAKernelSelectionAuthorityError(
            f"{context}.status is unsupported"
        ) from exc
    if status is SelectionAuthorityStatus.QUALIFIED:
        raise ISAKernelSelectionAuthorityError(
            f"{context}.status cannot be qualified"
        )
    form_id_value = payload.get("form_id")
    form_id = (
        None
        if form_id_value is None
        else _string(form_id_value, f"{context}.form_id")
    )
    return SelectionAuthorityIssue(
        status=status,
        code=_string(payload.get("code"), f"{context}.code"),
        form_id=form_id,
        message=_string(payload.get("message"), f"{context}.message"),
        expected=_json_value(payload.get("expected"), f"{context}.expected"),
        observed=_json_value(payload.get("observed"), f"{context}.observed"),
    )


def _requirements_projection(
    requirements: BinaryQualificationRequirements,
) -> list[dict[str, Any]]:
    return [
        {
            "form_id": row.form_id,
            "semantic_form": row.semantic_form,
            "source_locations": [
                {
                    "image_id": location.image_id,
                    "image_sha256": location.image_sha256,
                    "rva": location.rva,
                    "byte_length": location.byte_length,
                }
                for location in row.source_locations
            ],
        }
        for row in requirements.forms
    ]


def _selection_projection(value: ISAKernelSelection) -> list[dict[str, Any]]:
    return [
        {
            "form_id": row.form_id,
            "semantic_form": row.semantic_form,
            "source_locations": [
                {
                    "image_id": location.image_id,
                    "image_sha256": location.image_sha256,
                    "rva": location.rva,
                    "byte_length": location.byte_length,
                }
                for location in row.source_locations
            ],
        }
        for row in value.selected_forms
    ]


def _selection_matches_requirements(
    selection: ISAKernelSelection,
    requirements: BinaryQualificationRequirements,
) -> bool:
    if len(selection.selected_forms) != len(requirements.forms):
        return False
    return all(
        selected.form_id == required.form_id
        and selected.semantic_form == required.semantic_form
        and selected.source_locations == required.source_locations
        for selected, required in zip(
            selection.selected_forms, requirements.forms, strict=True
        )
    )


def _qualification_issue(
    row: SelectedFormQualification,
) -> SelectionAuthorityIssue | None:
    if row.status is QualificationStatus.QUALIFIED:
        return None
    diagnostic_codes = sorted({item.code for item in row.diagnostics})
    if row.status in {QualificationStatus.DISPUTED, QualificationStatus.VETOED}:
        return _issue(
            SelectionAuthorityStatus.VIOLATED,
            "oracle_dispute_veto",
            "oracle disagreement vetoes ISA kernel selection for this form",
            form_id=row.form_id,
            expected="qualified",
            observed={
                "status": row.status.value,
                "diagnostic_codes": diagnostic_codes,
            },
        )
    if _CONTRADICTORY_INCOMPLETE_CODES.intersection(diagnostic_codes):
        return _issue(
            SelectionAuthorityStatus.VIOLATED,
            "qualification_binding_contradiction",
            "the selected form contradicts its semantic-form binding",
            form_id=row.form_id,
            expected={
                "form_id": row.form_id,
                "semantic_form": row.semantic_form,
            },
            observed={"diagnostic_codes": diagnostic_codes},
        )
    return _issue(
        SelectionAuthorityStatus.INCOMPLETE,
        "qualification_evidence_incomplete",
        "qualified decode and semantics evidence is unavailable for this form",
        form_id=row.form_id,
        expected="qualified",
        observed={
            "status": row.status.value,
            "diagnostic_codes": diagnostic_codes,
        },
    )


def _derive_issues(
    *,
    requirements: BinaryQualificationRequirements,
    qualification: ISAKernelQualification,
    selection: ISAKernelSelection | None,
    expected_selection: ISAKernelSelection,
    fallback_capability_ids: tuple[FallbackCapabilityBinding, ...],
) -> tuple[SelectionAuthorityIssue, ...]:
    issues: list[SelectionAuthorityIssue] = []
    if requirements.profile_id != qualification.profile.id:
        issues.append(_issue(
            SelectionAuthorityStatus.VIOLATED,
            "profile_binding_mismatch",
            "reachable requirements and qualification bind different profiles",
            expected=requirements.profile_id,
            observed=qualification.profile.id,
        ))
    if requirements.semantic_kernel_id != qualification.semantic_kernel.id:
        issues.append(_issue(
            SelectionAuthorityStatus.VIOLATED,
            "semantic_kernel_binding_mismatch",
            "reachable requirements and qualification bind different kernels",
            expected=requirements.semantic_kernel_id,
            observed=qualification.semantic_kernel.id,
        ))
    if qualification.format != ISA_KERNEL_QUALIFICATION_FORMAT:
        issues.append(_issue(
            SelectionAuthorityStatus.INCOMPLETE,
            "unsupported_qualification_format",
            "kernel selection authority requires the current layered "
            "qualification format",
            expected=ISA_KERNEL_QUALIFICATION_FORMAT,
            observed=qualification.format,
        ))

    if selection is None:
        issues.append(_issue(
            SelectionAuthorityStatus.INCOMPLETE,
            "kernel_selection_missing",
            "binary-specific ISA kernel selection evidence is missing",
            expected=ISA_KERNEL_SELECTION_FORMAT,
            observed=None,
        ))
    else:
        if selection.binary_id != requirements.binary_id:
            issues.append(_issue(
                SelectionAuthorityStatus.VIOLATED,
                "binary_id_mismatch",
                "kernel selection names a different binary",
                expected=requirements.binary_id,
                observed=selection.binary_id,
            ))
        if selection.binary_sha256 != requirements.binary_sha256:
            issues.append(_issue(
                SelectionAuthorityStatus.VIOLATED,
                "binary_sha256_mismatch",
                "kernel selection binds a different binary digest",
                expected=requirements.binary_sha256,
                observed=selection.binary_sha256,
            ))
        if selection.format != ISA_KERNEL_SELECTION_FORMAT:
            issues.append(_issue(
                SelectionAuthorityStatus.INCOMPLETE,
                "unsupported_selection_format",
                "kernel selection authority requires the current layered "
                "selection format",
                expected=ISA_KERNEL_SELECTION_FORMAT,
                observed=selection.format,
            ))
        if not _selection_matches_requirements(selection, requirements):
            issues.append(_issue(
                SelectionAuthorityStatus.VIOLATED,
                "reachable_form_selection_mismatch",
                "kernel selection does not cover the exact reachable "
                "locations and forms",
                expected=_requirements_projection(requirements),
                observed=_selection_projection(selection),
            ))
        expected_for_format = replace(
            expected_selection,
            format=selection.format,
        )
        if selection != expected_for_format:
            issues.append(_issue(
                SelectionAuthorityStatus.VIOLATED,
                "selection_evidence_mismatch",
                "kernel selection does not replay from the bound qualification",
                expected=artifact_sha256(expected_for_format),
                observed=artifact_sha256(selection),
            ))

    for row in expected_selection.selected_forms:
        issue = _qualification_issue(row)
        if issue is not None:
            issues.append(issue)

    required_ids = {row.form_id for row in requirements.forms}
    fallback_by_form = {
        row.form_id: row.capability_id for row in fallback_capability_ids
    }
    for form_id in sorted(required_ids - set(fallback_by_form)):
        issues.append(_issue(
            SelectionAuthorityStatus.INCOMPLETE,
            "fallback_capability_missing",
            "reachable form has no bound fallback capability ID",
            form_id=form_id,
            expected="stable capability ID",
            observed=None,
        ))
    for form_id in sorted(set(fallback_by_form) - required_ids):
        issues.append(_issue(
            SelectionAuthorityStatus.VIOLATED,
            "fallback_capability_out_of_scope",
            "fallback capability names a form outside reachable scope",
            form_id=form_id,
            expected=sorted(required_ids),
            observed=fallback_by_form[form_id],
        ))
    return tuple(sorted(issues, key=_issue_key))


def _status(issues: Iterable[SelectionAuthorityIssue]) -> SelectionAuthorityStatus:
    statuses = {issue.status for issue in issues}
    if SelectionAuthorityStatus.VIOLATED in statuses:
        return SelectionAuthorityStatus.VIOLATED
    if SelectionAuthorityStatus.INCOMPLETE in statuses:
        return SelectionAuthorityStatus.INCOMPLETE
    return SelectionAuthorityStatus.QUALIFIED


def _counts(
    *,
    requirements: BinaryQualificationRequirements,
    qualification: ISAKernelQualification,
    fallback_capability_ids: tuple[FallbackCapabilityBinding, ...],
    issues: tuple[SelectionAuthorityIssue, ...],
    expected_selection: ISAKernelSelection,
) -> dict[str, int]:
    statuses = [row.status for row in expected_selection.selected_forms]
    return {
        "reachable_forms": len(requirements.forms),
        "reachable_locations": sum(
            len(row.source_locations) for row in requirements.forms
        ),
        "qualified_forms": statuses.count(QualificationStatus.QUALIFIED),
        "incomplete_forms": statuses.count(QualificationStatus.INCOMPLETE),
        "disputed_forms": statuses.count(QualificationStatus.DISPUTED),
        "vetoed_forms": statuses.count(QualificationStatus.VETOED),
        "fallback_capability_ids": len(fallback_capability_ids),
        "issues": len(issues),
    }


def _kernel_payload(qualification: ISAKernelQualification) -> dict[str, str]:
    return {
        "profile_id": qualification.profile.id,
        "semantic_kernel_id": qualification.semantic_kernel.id,
        "decoder_sha256": qualification.semantic_kernel.decoder_sha256,
        "semantics_sha256": qualification.semantic_kernel.semantics_sha256,
    }


def _payload_without_self_hash(
    value: ISAKernelSelectionAuthority,
) -> dict[str, Any]:
    qualification_payload = serialize_kernel_qualification(value.qualification)
    selection_payload = (
        None
        if value.selection is None
        else serialize_kernel_selection(value.selection)
    )
    return {
        "format": value.format,
        "authority": _AUTHORITY,
        "requirements": serialize_binary_qualification_requirements(
            value.requirements
        ),
        "kernel": _kernel_payload(value.qualification),
        "evidence": {
            "kernel_qualification": {
                "sha256": artifact_sha256(qualification_payload),
                "artifact": qualification_payload,
            },
            "binary_kernel_selection": (
                None
                if selection_payload is None
                else {
                    "sha256": artifact_sha256(selection_payload),
                    "artifact": selection_payload,
                }
            ),
        },
        "fallback_capability_ids": [
            {
                "form_id": row.form_id,
                "capability_id": row.capability_id,
            }
            for row in value.fallback_capability_ids
        ],
        "policy": dict(_POLICY),
        "status": value.status.value,
        "issues": [_issue_payload(issue) for issue in value.issues],
        "counts": dict(value.counts),
    }


def build_isa_kernel_selection_authority(
    *,
    binary_id: str,
    binary_sha256: str,
    reachable_forms: Iterable[BinaryFormRequirement],
    qualification: ISAKernelQualification | Mapping[str, Any],
    selection: ISAKernelSelection | Mapping[str, Any] | None,
    fallback_capability_ids: (
        Mapping[str, str] | Iterable[FallbackCapabilityBinding]
    ),
) -> ISAKernelSelectionAuthority:
    """Build a replayable authority artifact for one exact binary."""

    parsed_qualification = _parse_qualification_input(qualification)
    requirements = _normalize_requirements(
        binary_id=binary_id,
        binary_sha256=binary_sha256,
        reachable_forms=reachable_forms,
        qualification=parsed_qualification,
    )
    parsed_selection = _parse_selection_input(selection)
    fallbacks = _normalize_fallbacks(fallback_capability_ids)
    expected_selection = select_isa_kernel_qualification(
        binary_id=requirements.binary_id,
        binary_sha256=requirements.binary_sha256,
        requirements=requirements.forms,
        qualification=parsed_qualification,
    )
    issues = _derive_issues(
        requirements=requirements,
        qualification=parsed_qualification,
        selection=parsed_selection,
        expected_selection=expected_selection,
        fallback_capability_ids=fallbacks,
    )
    provisional = ISAKernelSelectionAuthority(
        requirements=requirements,
        qualification=parsed_qualification,
        selection=parsed_selection,
        fallback_capability_ids=fallbacks,
        status=_status(issues),
        issues=issues,
        counts=_counts(
            requirements=requirements,
            qualification=parsed_qualification,
            fallback_capability_ids=fallbacks,
            issues=issues,
            expected_selection=expected_selection,
        ),
        authority_sha256="0" * 64,
    )
    core = _payload_without_self_hash(provisional)
    result = replace(provisional, authority_sha256=artifact_sha256(core))
    payload = dict(core)
    payload["authority_sha256"] = result.authority_sha256
    return parse_isa_kernel_selection_authority(payload)


def _parse_evidence_binding(
    value: Any,
    context: str,
    *,
    parser: Any,
) -> tuple[str, Any]:
    payload = _object(value, context)
    _exact_fields(payload, {"sha256", "artifact"}, context)
    digest = _sha256(payload.get("sha256"), f"{context}.sha256")
    try:
        artifact = parser(payload.get("artifact"))
    except ISAKernelQualificationError as exc:
        raise ISAKernelSelectionAuthorityError(
            f"{context}.artifact is invalid: {exc}"
        ) from exc
    if artifact_sha256(artifact) != digest:
        raise ISAKernelSelectionAuthorityError(
            f"{context} SHA-256 does not match its artifact"
        )
    return digest, artifact


def parse_isa_kernel_selection_authority(
    value: Any,
) -> ISAKernelSelectionAuthority:
    """Strictly parse and replay every authority claim."""

    payload = _object(value, "ISA kernel selection authority")
    _exact_fields(
        payload,
        {
            "format",
            "authority",
            "requirements",
            "kernel",
            "evidence",
            "fallback_capability_ids",
            "policy",
            "status",
            "issues",
            "counts",
            "authority_sha256",
        },
        "ISA kernel selection authority",
    )
    if payload.get("format") != ISA_KERNEL_SELECTION_AUTHORITY_FORMAT:
        raise ISAKernelSelectionAuthorityError(
            "unsupported ISA kernel selection authority format"
        )
    if payload.get("authority") != _AUTHORITY:
        raise ISAKernelSelectionAuthorityError(
            "ISA kernel selection authority has unsupported authority scope"
        )
    try:
        requirements = parse_binary_qualification_requirements(
            payload.get("requirements")
        )
    except ISAKernelQualificationError as exc:
        raise ISAKernelSelectionAuthorityError(
            f"ISA kernel selection authority requirements are invalid: {exc}"
        ) from exc

    evidence = _object(payload.get("evidence"), "authority evidence")
    _exact_fields(
        evidence,
        {"kernel_qualification", "binary_kernel_selection"},
        "authority evidence",
    )
    _, qualification = _parse_evidence_binding(
        evidence.get("kernel_qualification"),
        "kernel qualification evidence",
        parser=parse_kernel_qualification,
    )
    selection_value = evidence.get("binary_kernel_selection")
    selection = None
    if selection_value is not None:
        _, selection = _parse_evidence_binding(
            selection_value,
            "binary kernel selection evidence",
            parser=parse_kernel_selection,
        )

    kernel = _object(payload.get("kernel"), "selected kernel binding")
    _exact_fields(
        kernel,
        {
            "profile_id",
            "semantic_kernel_id",
            "decoder_sha256",
            "semantics_sha256",
        },
        "selected kernel binding",
    )
    expected_kernel = _kernel_payload(qualification)
    if dict(kernel) != expected_kernel:
        raise ISAKernelSelectionAuthorityError(
            "selected kernel binding contradicts qualification evidence"
        )

    fallback_value = payload.get("fallback_capability_ids")
    if not isinstance(fallback_value, list):
        raise ISAKernelSelectionAuthorityError(
            "fallback_capability_ids must be a list"
        )
    fallbacks: list[FallbackCapabilityBinding] = []
    for index, raw in enumerate(fallback_value):
        context = f"fallback_capability_ids[{index}]"
        row = _object(raw, context)
        _exact_fields(row, {"form_id", "capability_id"}, context)
        fallbacks.append(FallbackCapabilityBinding(
            form_id=_string(row.get("form_id"), f"{context}.form_id"),
            capability_id=_capability_id(
                row.get("capability_id"), f"{context}.capability_id"
            ),
        ))
    fallback_rows = tuple(fallbacks)
    if fallback_rows != tuple(sorted(set(fallback_rows))):
        raise ISAKernelSelectionAuthorityError(
            "fallback capability bindings must be unique and ordered"
        )
    if len({row.form_id for row in fallback_rows}) != len(fallback_rows):
        raise ISAKernelSelectionAuthorityError(
            "fallback capability form IDs must be unique"
        )

    policy = _object(payload.get("policy"), "authority policy")
    if dict(policy) != _POLICY:
        raise ISAKernelSelectionAuthorityError(
            "ISA kernel selection authority policy is unsupported"
        )
    issues_value = payload.get("issues")
    if not isinstance(issues_value, list):
        raise ISAKernelSelectionAuthorityError("authority issues must be a list")
    issues = tuple(
        _parse_issue(row, f"authority issues[{index}]")
        for index, row in enumerate(issues_value)
    )
    if issues != tuple(sorted(issues, key=_issue_key)):
        raise ISAKernelSelectionAuthorityError(
            "authority issues must be ordered"
        )
    expected_selection = select_isa_kernel_qualification(
        binary_id=requirements.binary_id,
        binary_sha256=requirements.binary_sha256,
        requirements=requirements.forms,
        qualification=qualification,
    )
    expected_issues = _derive_issues(
        requirements=requirements,
        qualification=qualification,
        selection=selection,
        expected_selection=expected_selection,
        fallback_capability_ids=fallback_rows,
    )
    if issues != expected_issues:
        raise ISAKernelSelectionAuthorityError(
            "authority issues do not replay from bound evidence"
        )
    try:
        status = SelectionAuthorityStatus(payload.get("status"))
    except ValueError as exc:
        raise ISAKernelSelectionAuthorityError(
            "ISA kernel selection authority status is unsupported"
        ) from exc
    if status is not _status(issues):
        raise ISAKernelSelectionAuthorityError(
            "ISA kernel selection authority status is inconsistent"
        )
    counts_value = _object(payload.get("counts"), "authority counts")
    expected_counts = _counts(
        requirements=requirements,
        qualification=qualification,
        fallback_capability_ids=fallback_rows,
        issues=issues,
        expected_selection=expected_selection,
    )
    if dict(counts_value) != expected_counts or any(
        isinstance(item, bool) or not isinstance(item, int) or item < 0
        for item in counts_value.values()
    ):
        raise ISAKernelSelectionAuthorityError(
            "ISA kernel selection authority counts are inconsistent"
        )
    authority_sha256 = _sha256(
        payload.get("authority_sha256"), "authority SHA-256"
    )
    core = dict(payload)
    del core["authority_sha256"]
    if artifact_sha256(core) != authority_sha256:
        raise ISAKernelSelectionAuthorityError(
            "ISA kernel selection authority self-hash is stale"
        )
    return ISAKernelSelectionAuthority(
        requirements=requirements,
        qualification=qualification,
        selection=selection,
        fallback_capability_ids=fallback_rows,
        status=status,
        issues=issues,
        counts=expected_counts,
        authority_sha256=authority_sha256,
    )


def serialize_isa_kernel_selection_authority(
    value: ISAKernelSelectionAuthority,
) -> dict[str, Any]:
    if not isinstance(value, ISAKernelSelectionAuthority):
        raise ISAKernelSelectionAuthorityError(
            "authority must be an ISAKernelSelectionAuthority"
        )
    payload = _payload_without_self_hash(value)
    payload["authority_sha256"] = value.authority_sha256
    return payload


def _check_issue(
    status: SelectionAuthorityStatus,
    code: str,
    message: str,
    *,
    expected: Any = None,
    observed: Any = None,
) -> ISAKernelSelectionAuthorityCheck:
    issue = _issue(
        status,
        code,
        message,
        expected=expected,
        observed=observed,
    )
    return ISAKernelSelectionAuthorityCheck(
        status=status,
        authority=None,
        issues=(issue,),
    )


def validate_isa_kernel_selection_authority(
    authority: ISAKernelSelectionAuthority | Mapping[str, Any] | None,
    *,
    binary_id: str,
    binary_sha256: str,
    reachable_forms: Iterable[BinaryFormRequirement],
    qualification: ISAKernelQualification | Mapping[str, Any],
    selection: ISAKernelSelection | Mapping[str, Any] | None,
    fallback_capability_ids: (
        Mapping[str, str] | Iterable[FallbackCapabilityBinding]
    ),
) -> ISAKernelSelectionAuthorityCheck:
    """Replay an authority against current inputs and fail closed on drift."""

    try:
        expected = build_isa_kernel_selection_authority(
            binary_id=binary_id,
            binary_sha256=binary_sha256,
            reachable_forms=reachable_forms,
            qualification=qualification,
            selection=selection,
            fallback_capability_ids=fallback_capability_ids,
        )
    except (ISAKernelSelectionAuthorityError, TypeError, ValueError) as exc:
        return _check_issue(
            SelectionAuthorityStatus.VIOLATED,
            "selection_evidence_corrupted",
            "submitted selection inputs are malformed",
            expected="strictly parseable selection evidence",
            observed=str(exc),
        )
    if authority is None:
        return _check_issue(
            SelectionAuthorityStatus.INCOMPLETE,
            "selection_authority_missing",
            "binary-specific ISA kernel selection authority is missing",
            expected=ISA_KERNEL_SELECTION_AUTHORITY_FORMAT,
            observed=None,
        )
    try:
        actual = (
            parse_isa_kernel_selection_authority(authority.to_payload())
            if isinstance(authority, ISAKernelSelectionAuthority)
            else parse_isa_kernel_selection_authority(authority)
        )
    except (ISAKernelSelectionAuthorityError, TypeError, ValueError) as exc:
        return _check_issue(
            SelectionAuthorityStatus.VIOLATED,
            "selection_authority_corrupted",
            "ISA kernel selection authority is malformed or contradictory",
            expected=ISA_KERNEL_SELECTION_AUTHORITY_FORMAT,
            observed=str(exc),
        )
    if actual.to_payload() == expected.to_payload():
        return ISAKernelSelectionAuthorityCheck(
            status=actual.status,
            authority=actual,
            issues=actual.issues,
        )

    mismatches: list[SelectionAuthorityIssue] = []
    if actual.requirements.binary_sha256 != expected.requirements.binary_sha256:
        mismatches.append(_issue(
            SelectionAuthorityStatus.VIOLATED,
            "binary_sha256_mismatch",
            "authority binds a different binary digest than the checked input",
            expected=expected.requirements.binary_sha256,
            observed=actual.requirements.binary_sha256,
        ))
    if (
        actual.qualification.sha256()
        != expected.qualification.sha256()
    ):
        mismatches.append(_issue(
            SelectionAuthorityStatus.VIOLATED,
            "qualification_evidence_mismatch",
            "authority binds different decode and semantics evidence",
            expected=expected.qualification.sha256(),
            observed=actual.qualification.sha256(),
        ))
    actual_selection_sha = (
        None if actual.selection is None else actual.selection.sha256()
    )
    expected_selection_sha = (
        None if expected.selection is None else expected.selection.sha256()
    )
    if actual_selection_sha != expected_selection_sha:
        mismatches.append(_issue(
            SelectionAuthorityStatus.VIOLATED,
            "selection_evidence_mismatch",
            "authority binds different binary selection evidence",
            expected=expected_selection_sha,
            observed=actual_selection_sha,
        ))
    if actual.fallback_capability_ids != expected.fallback_capability_ids:
        mismatches.append(_issue(
            SelectionAuthorityStatus.VIOLATED,
            "fallback_capability_mismatch",
            "authority fallback capability IDs differ from the checked inputs",
            expected=[
                {"form_id": row.form_id, "capability_id": row.capability_id}
                for row in expected.fallback_capability_ids
            ],
            observed=[
                {"form_id": row.form_id, "capability_id": row.capability_id}
                for row in actual.fallback_capability_ids
            ],
        ))
    if not mismatches:
        mismatches.append(_issue(
            SelectionAuthorityStatus.VIOLATED,
            "selection_authority_replay_mismatch",
            "authority does not exactly replay from the checked inputs",
            expected=expected.authority_sha256,
            observed=actual.authority_sha256,
        ))
    return ISAKernelSelectionAuthorityCheck(
        status=SelectionAuthorityStatus.VIOLATED,
        authority=actual,
        issues=tuple(sorted(mismatches, key=_issue_key)),
    )


check_isa_kernel_selection_authority = validate_isa_kernel_selection_authority
build_binary_isa_kernel_selection_authority = (
    build_isa_kernel_selection_authority
)
parse_binary_isa_kernel_selection_authority = (
    parse_isa_kernel_selection_authority
)
check_binary_isa_kernel_selection_authority = (
    validate_isa_kernel_selection_authority
)


__all__ = [
    "BINARY_ISA_KERNEL_SELECTION_AUTHORITY_FORMAT",
    "FallbackCapabilityBinding",
    "ISAKernelSelectionAuthority",
    "ISAKernelSelectionAuthorityCheck",
    "ISAKernelSelectionAuthorityError",
    "ISA_KERNEL_SELECTION_AUTHORITY_FORMAT",
    "SelectionAuthorityIssue",
    "SelectionAuthorityStatus",
    "build_binary_isa_kernel_selection_authority",
    "build_isa_kernel_selection_authority",
    "check_binary_isa_kernel_selection_authority",
    "check_isa_kernel_selection_authority",
    "parse_binary_isa_kernel_selection_authority",
    "parse_isa_kernel_selection_authority",
    "serialize_isa_kernel_selection_authority",
    "validate_isa_kernel_selection_authority",
]
