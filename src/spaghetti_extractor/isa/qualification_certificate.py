"""Compact checked projection of a full ISA qualification transcript."""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from .formats import ISA_KERNEL_QUALIFICATION_CERTIFICATE_FORMAT
from .kernel_qualification import (
    ISAKernelQualification,
    artifact_sha256,
    parse_kernel_qualification,
)
from .semantic_forms import lean_semantic_form_classifier_sha256


_FIELDS = {
    "format", "status", "authority", "target_independent", "profile",
    "classifier_sha256", "semantic_kernel", "qualification", "forms",
    "counts", "trust", "certificate_sha256",
}
_FORM_FIELDS = {
    "form_id", "semantic_form", "structural_status", "oracle_status",
    "qualification_sha256",
}
_STATUSES = {"qualified", "incomplete", "disputed", "vetoed"}


class ISAKernelQualificationCertificateError(ToolkitInputError):
    """The compact ISA qualification projection failed closed."""


def _fail(message: str) -> None:
    raise ISAKernelQualificationCertificateError(message)


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _sha256(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{context} must be lowercase SHA-256")
    return value


def build_isa_kernel_qualification_certificate_v1(
    *,
    qualification: ISAKernelQualification,
    qualification_payload: Mapping[str, Any],
    qualification_content_sha256: str,
) -> dict[str, Any]:
    """Reduce an already checked transcript without replaying its oracles."""

    if not isinstance(qualification, ISAKernelQualification):
        _fail("qualification must be a typed ISA kernel qualification")
    payload = dict(_object(qualification_payload, "qualification payload"))
    if parse_kernel_qualification(payload) != qualification:
        _fail("qualification payload disagrees with its typed value")
    _sha256(
        qualification_content_sha256,
        "qualification content SHA-256",
    )
    if qualification.structural_status.value != "complete":
        _fail("qualification has incomplete structural form coverage")
    form_sha256s = payload["form_sha256s"]
    forms = [
        {
            "form_id": form.form_id,
            "semantic_form": form.semantic_form,
            "structural_status": form.structural_status.value,
            "oracle_status": form.status.value,
            "qualification_sha256": form_sha256,
        }
        for form, form_sha256 in zip(
            qualification.forms, form_sha256s, strict=True
        )
    ]
    result: dict[str, Any] = {
        "format": ISA_KERNEL_QUALIFICATION_CERTIFICATE_FORMAT,
        "status": "complete",
        "authority": False,
        "target_independent": True,
        "classifier_sha256": lean_semantic_form_classifier_sha256(),
        "profile": {
            "id": qualification.profile.id,
            "architecture": qualification.profile.architecture,
            "cpu": qualification.profile.cpu,
            "execution_mode": qualification.profile.execution_mode,
            "environment": qualification.profile.environment,
            "features": list(qualification.profile.features),
        },
        "semantic_kernel": {
            "id": qualification.semantic_kernel.id,
            "decoder_sha256": qualification.semantic_kernel.decoder_sha256,
            "semantics_sha256": qualification.semantic_kernel.semantics_sha256,
            "lean_version": qualification.semantic_kernel.lean_version,
        },
        "qualification": {
            "sha256": artifact_sha256(payload),
            "content_sha256": qualification_content_sha256,
        },
        "forms": forms,
        "counts": {
            "forms": len(forms),
            "qualified": qualification.counts["qualified"],
            "incomplete": qualification.counts["incomplete"],
            "disputed": qualification.counts["disputed"],
            "vetoed": qualification.counts["vetoed"],
        },
        "trust": {
            "role": "checked_projection_of_shared_isa_qualification",
            "proof_authority": False,
        },
    }
    result["certificate_sha256"] = canonical_sha256_v3(result)
    return parse_isa_kernel_qualification_certificate_v1(result)


def parse_isa_kernel_qualification_certificate_v1(
    value: object,
) -> dict[str, Any]:
    payload = dict(_object(value, "ISA qualification certificate"))
    if (
        set(payload) != _FIELDS
        or payload.get("format")
        != ISA_KERNEL_QUALIFICATION_CERTIFICATE_FORMAT
        or payload.get("status") != "complete"
        or payload.get("authority") is not False
        or payload.get("target_independent") is not True
    ):
        _fail("ISA qualification certificate fields or disposition are invalid")
    declared = _sha256(
        payload.get("certificate_sha256"), "certificate SHA-256"
    )
    core = {
        key: item for key, item in payload.items()
        if key != "certificate_sha256"
    }
    if declared != canonical_sha256_v3(core):
        _fail("ISA qualification certificate self hash is stale")
    qualification = _object(payload.get("qualification"), "qualification")
    if set(qualification) != {"sha256", "content_sha256"}:
        _fail("ISA qualification binding fields are invalid")
    _sha256(qualification.get("sha256"), "qualification SHA-256")
    _sha256(
        qualification.get("content_sha256"),
        "qualification content SHA-256",
    )
    if payload.get("classifier_sha256") != (
        lean_semantic_form_classifier_sha256()
    ):
        _fail("ISA qualification classifier binding is stale")
    profile = _object(payload.get("profile"), "profile")
    if set(profile) != {
        "id", "architecture", "cpu", "execution_mode", "environment",
        "features",
    } or not all(
        isinstance(profile.get(field), str) and profile[field]
        for field in (
            "id", "architecture", "cpu", "execution_mode", "environment"
        )
    ):
        _fail("ISA qualification profile is malformed")
    features = profile.get("features")
    if (
        not isinstance(features, list)
        or not all(isinstance(item, str) and item for item in features)
        or features != sorted(set(features))
    ):
        _fail("ISA qualification profile features are not canonical")
    kernel = _object(payload.get("semantic_kernel"), "semantic kernel")
    if set(kernel) != {
        "id", "decoder_sha256", "semantics_sha256", "lean_version"
    } or not all(
        isinstance(kernel.get(field), str) and kernel[field]
        for field in ("id", "lean_version")
    ):
        _fail("ISA qualification semantic kernel is malformed")
    _sha256(kernel.get("decoder_sha256"), "kernel decoder SHA-256")
    _sha256(kernel.get("semantics_sha256"), "kernel semantics SHA-256")
    raw_forms = payload.get("forms")
    if not isinstance(raw_forms, list) or not raw_forms:
        _fail("ISA qualification certificate forms must be nonempty")
    forms: list[dict[str, Any]] = []
    for index, value_row in enumerate(raw_forms):
        row = dict(_object(value_row, f"forms[{index}]"))
        if set(row) != _FORM_FIELDS:
            _fail(f"forms[{index}] fields are invalid")
        if not all(
            isinstance(row.get(field), str) and row[field]
            for field in ("form_id", "semantic_form")
        ):
            _fail(f"forms[{index}] identity is malformed")
        if row.get("structural_status") != "complete":
            _fail(f"forms[{index}] lacks structural coverage")
        if row.get("oracle_status") not in _STATUSES:
            _fail(f"forms[{index}] oracle status is invalid")
        _sha256(
            row.get("qualification_sha256"),
            f"forms[{index}] qualification SHA-256",
        )
        forms.append(row)
    form_ids = [row["form_id"] for row in forms]
    if form_ids != sorted(set(form_ids)):
        _fail("ISA qualification certificate forms are not unique and ordered")
    counts = _object(payload.get("counts"), "counts")
    expected_counts = Counter(row["oracle_status"] for row in forms)
    expected = {
        "forms": len(forms),
        **{status: expected_counts[status] for status in sorted(_STATUSES)},
    }
    if counts != expected:
        _fail("ISA qualification certificate counts are stale")
    if payload.get("trust") != {
        "role": "checked_projection_of_shared_isa_qualification",
        "proof_authority": False,
    }:
        _fail("ISA qualification certificate trust is invalid")
    return payload


__all__ = [
    "ISAKernelQualificationCertificateError",
    "build_isa_kernel_qualification_certificate_v1",
    "parse_isa_kernel_qualification_certificate_v1",
]
