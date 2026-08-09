"""Bind generic ISA qualification evidence to one exact machine-IR image."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
from collections.abc import Mapping
from typing import Any

from .isa_kernel_qualification import (
    parse_kernel_qualification,
    select_isa_kernel_qualification,
)
from .isa_kernel_selection import build_isa_kernel_selection_authority
from .machine_ir_isa_requirements_v2 import (
    MachineIRISARequirementsV2,
    compare_selection_to_machine_ir_requirements_v2,
    parse_machine_ir_isa_requirements_v2,
)


class MachineIRISASelectionV2Error(ValueError):
    """Qualification evidence cannot be bound to the exact image inventory."""


MACHINE_IR_ISA_SELECTION_CERTIFICATE_V2_FORMAT = (
    "spaghetti-extractor-machine-ir-isa-selection-certificate-v2"
)


@dataclass(frozen=True)
class MachineIRISASelectionCertificateV2:
    """Compact downstream handle for already checked ISA oracle evidence.

    The full qualification corpus is parsed once by the producing phase.  This
    certificate binds its digest and the resulting per-form decisions to the
    independently supplied exact machine-IR requirements.  Static closure does
    not need to deserialize the corpus again.
    """

    status: str
    binary_id: str
    binary_sha256: str
    requirements_sha256: str
    selection_authority_sha256: str
    kernel: Mapping[str, str]
    forms: tuple[Mapping[str, Any], ...]
    fallback_capability_ids: tuple[tuple[str, str], ...]
    issues: tuple[Mapping[str, Any], ...]
    counts: Mapping[str, int]
    certificate_sha256: str

    def to_payload(self) -> dict[str, Any]:
        body = _certificate_body(self)
        return {**body, "certificate_sha256": self.certificate_sha256}


def build_machine_ir_isa_selection_certificate_v2(
    *,
    requirements: Mapping[str, Any] | MachineIRISARequirementsV2,
    authority: Mapping[str, Any] | Any,
) -> dict[str, Any]:
    """Project full qualification authority into a compact static-gate input."""

    from .isa_kernel_selection import (
        ISAKernelSelectionAuthority,
        SelectionAuthorityStatus,
        parse_isa_kernel_selection_authority,
    )

    typed_requirements = (
        requirements
        if isinstance(requirements, MachineIRISARequirementsV2)
        else parse_machine_ir_isa_requirements_v2(requirements)
    )
    typed_authority = (
        authority
        if isinstance(authority, ISAKernelSelectionAuthority)
        else parse_isa_kernel_selection_authority(authority)
    )
    comparison_issues = compare_selection_to_machine_ir_requirements_v2(
        typed_requirements, typed_authority
    )
    issues = [
        {
            "status": issue.status.value,
            "code": issue.code,
            "form_id": issue.form_id,
        }
        for issue in typed_authority.issues
    ]
    issues.extend(
        {
            "status": str(issue.get("status", "violated")),
            "code": str(issue.get("code", "selection_requirement_mismatch")),
            "form_id": None,
        }
        for issue in comparison_issues
    )
    issues = sorted(
        {_canonical_json(issue): issue for issue in issues}.values(),
        key=_canonical_json,
    )
    if any(issue["status"] == "violated" for issue in issues):
        status = "violated"
    elif (
        typed_requirements.status != "complete"
        or typed_authority.status is not SelectionAuthorityStatus.QUALIFIED
        or issues
    ):
        status = "incomplete"
    else:
        status = "qualified"
    selected_by_id = {
        row.form_id: row
        for row in (
            ()
            if typed_authority.selection is None
            else typed_authority.selection.selected_forms
        )
    }
    forms = []
    for requirement in sorted(
        typed_requirements.forms, key=lambda row: row.form_id
    ):
        selected = selected_by_id.get(requirement.form_id)
        forms.append({
            "form_id": requirement.form_id,
            "semantic_form": requirement.semantic_form,
            "qualification_sha256": (
                None if selected is None else selected.qualification_sha256
            ),
            "status": "incomplete" if selected is None else selected.status.value,
        })
    fallbacks = tuple(sorted(
        (row.form_id, row.capability_id)
        for row in typed_authority.fallback_capability_ids
    ))
    provisional = MachineIRISASelectionCertificateV2(
        status=status,
        binary_id=typed_authority.requirements.binary_id,
        binary_sha256=typed_requirements.binary_sha256,
        requirements_sha256=_requirements_sha256(typed_requirements),
        selection_authority_sha256=typed_authority.authority_sha256,
        kernel={
            "profile_id": typed_authority.qualification.profile.id,
            "semantic_kernel_id": typed_authority.qualification.semantic_kernel.id,
            "decoder_sha256": typed_authority.qualification.semantic_kernel.decoder_sha256,
            "semantics_sha256": typed_authority.qualification.semantic_kernel.semantics_sha256,
        },
        forms=tuple(forms),
        fallback_capability_ids=fallbacks,
        issues=tuple(issues),
        counts={
            "forms": len(forms),
            "qualified_forms": sum(row["status"] == "qualified" for row in forms),
            "fallback_capability_ids": len(fallbacks),
            "issues": len(issues),
        },
        certificate_sha256="0" * 64,
    )
    body = _certificate_body(provisional)
    result = MachineIRISASelectionCertificateV2(
        **{
            **provisional.__dict__,
            "certificate_sha256": _sha256_json(body),
        }
    )
    return parse_machine_ir_isa_selection_certificate_v2(
        result.to_payload()
    ).to_payload()


def parse_machine_ir_isa_selection_certificate_v2(
    value: Any,
) -> MachineIRISASelectionCertificateV2:
    payload = _object(value, "ISA selection certificate")
    expected_fields = {
        "format",
        "status",
        "binary",
        "requirements_sha256",
        "selection_authority_sha256",
        "kernel",
        "forms",
        "fallback_capability_ids",
        "issues",
        "counts",
        "trust",
        "certificate_sha256",
    }
    if set(payload) != expected_fields:
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate field inventory is invalid"
        )
    if payload.get("format") != MACHINE_IR_ISA_SELECTION_CERTIFICATE_V2_FORMAT:
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate format is unsupported"
        )
    status = payload.get("status")
    if status not in {"qualified", "incomplete", "violated"}:
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate status is unsupported"
        )
    binary = _object(payload.get("binary"), "ISA selection certificate binary")
    if set(binary) != {"id", "sha256"}:
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate binary binding is invalid"
        )
    binary_id = _string(binary.get("id"), "binary ID")
    binary_sha256 = _digest(binary.get("sha256"), "binary SHA-256")
    requirements_sha256 = _digest(
        payload.get("requirements_sha256"), "requirements SHA-256"
    )
    authority_sha256 = _digest(
        payload.get("selection_authority_sha256"),
        "selection authority SHA-256",
    )
    kernel = _object(payload.get("kernel"), "ISA selection certificate kernel")
    if set(kernel) != {
        "profile_id", "semantic_kernel_id", "decoder_sha256", "semantics_sha256"
    }:
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate kernel binding is invalid"
        )
    normalized_kernel = {
        "profile_id": _string(kernel.get("profile_id"), "profile ID"),
        "semantic_kernel_id": _string(
            kernel.get("semantic_kernel_id"), "semantic kernel ID"
        ),
        "decoder_sha256": _digest(
            kernel.get("decoder_sha256"), "decoder SHA-256"
        ),
        "semantics_sha256": _digest(
            kernel.get("semantics_sha256"), "semantics SHA-256"
        ),
    }
    raw_forms = payload.get("forms")
    if not isinstance(raw_forms, list):
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate forms must be an array"
        )
    forms: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_forms):
        row = _object(raw, f"ISA selection certificate form {index}")
        if set(row) != {
            "form_id", "semantic_form", "qualification_sha256", "status"
        }:
            raise MachineIRISASelectionV2Error(
                "ISA selection certificate form fields are invalid"
            )
        form_status = row.get("status")
        if form_status not in {"qualified", "incomplete", "disputed", "vetoed"}:
            raise MachineIRISASelectionV2Error(
                "ISA selection certificate form status is unsupported"
            )
        qualification_sha256 = row.get("qualification_sha256")
        if qualification_sha256 is not None:
            qualification_sha256 = _digest(
                qualification_sha256, "form qualification SHA-256"
            )
        forms.append({
            "form_id": _string(row.get("form_id"), "form ID"),
            "semantic_form": _string(
                row.get("semantic_form"), "semantic form"
            ),
            "qualification_sha256": qualification_sha256,
            "status": form_status,
        })
    forms.sort(key=lambda row: row["form_id"])
    if len({row["form_id"] for row in forms}) != len(forms):
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate form IDs are duplicated"
        )
    fallbacks = _fallbacks(payload.get("fallback_capability_ids"))
    issues = _issues(payload.get("issues"))
    counts = _object(payload.get("counts"), "ISA selection certificate counts")
    expected_counts = {
        "forms": len(forms),
        "qualified_forms": sum(row["status"] == "qualified" for row in forms),
        "fallback_capability_ids": len(fallbacks),
        "issues": len(issues),
    }
    if dict(counts) != expected_counts:
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate counts are stale"
        )
    if payload.get("trust") != {
        "full_oracle_evidence_checked_upstream": True,
        "static_gate_replays_exact_requirements": True,
        "certificate_closes_whole_program_authority": False,
    }:
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate trust policy is invalid"
        )
    expected_status = (
        "violated"
        if any(issue["status"] == "violated" for issue in issues)
        else "incomplete"
        if issues or any(row["status"] != "qualified" for row in forms)
        else "qualified"
    )
    if status != expected_status:
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate status is stale"
        )
    certificate_sha256 = _digest(
        payload.get("certificate_sha256"), "certificate SHA-256"
    )
    result = MachineIRISASelectionCertificateV2(
        status=status,
        binary_id=binary_id,
        binary_sha256=binary_sha256,
        requirements_sha256=requirements_sha256,
        selection_authority_sha256=authority_sha256,
        kernel=normalized_kernel,
        forms=tuple(forms),
        fallback_capability_ids=fallbacks,
        issues=issues,
        counts=expected_counts,
        certificate_sha256=certificate_sha256,
    )
    if _sha256_json(_certificate_body(result)) != certificate_sha256:
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate self-hash is stale"
        )
    return result


def compare_isa_selection_certificate_to_requirements_v2(
    certificate: MachineIRISASelectionCertificateV2,
    requirements: MachineIRISARequirementsV2,
) -> list[dict[str, Any]]:
    """Replay compact selection bindings against exact decoded requirements."""

    issues: list[dict[str, Any]] = []
    if certificate.binary_sha256 != requirements.binary_sha256:
        issues.append({"status": "violated", "code": "isa_selection_binary_mismatch"})
    if certificate.requirements_sha256 != _requirements_sha256(requirements):
        issues.append({
            "status": "violated",
            "code": "isa_selection_requirements_digest_mismatch",
        })
    expected_forms = [
        (row.form_id, row.semantic_form)
        for row in sorted(requirements.forms, key=lambda row: row.form_id)
    ]
    observed_forms = [
        (str(row["form_id"]), str(row["semantic_form"]))
        for row in certificate.forms
    ]
    if observed_forms != expected_forms:
        issues.append({
            "status": "violated",
            "code": "isa_selection_exact_form_inventory_mismatch",
        })
    if certificate.fallback_capability_ids != requirements.fallback_capability_ids:
        issues.append({
            "status": "violated",
            "code": "isa_selection_fallback_inventory_mismatch",
        })
    return issues


def _requirements_sha256(requirements: MachineIRISARequirementsV2) -> str:
    return _digest(
        requirements.payload.get("requirements_sha256"),
        "requirements SHA-256",
    )


def _certificate_body(
    value: MachineIRISASelectionCertificateV2,
) -> dict[str, Any]:
    return {
        "format": MACHINE_IR_ISA_SELECTION_CERTIFICATE_V2_FORMAT,
        "status": value.status,
        "binary": {"id": value.binary_id, "sha256": value.binary_sha256},
        "requirements_sha256": value.requirements_sha256,
        "selection_authority_sha256": value.selection_authority_sha256,
        "kernel": dict(value.kernel),
        "forms": [copy.deepcopy(dict(row)) for row in value.forms],
        "fallback_capability_ids": [
            {"form_id": form_id, "capability_id": capability_id}
            for form_id, capability_id in value.fallback_capability_ids
        ],
        "issues": [copy.deepcopy(dict(row)) for row in value.issues],
        "counts": dict(value.counts),
        "trust": {
            "full_oracle_evidence_checked_upstream": True,
            "static_gate_replays_exact_requirements": True,
            "certificate_closes_whole_program_authority": False,
        },
    }


def _fallbacks(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        raise MachineIRISASelectionV2Error(
            "fallback capability bindings must be an array"
        )
    result = tuple(sorted(
        (
            _string(_object(row, "fallback binding").get("form_id"), "form ID"),
            _string(_object(row, "fallback binding").get("capability_id"), "capability ID"),
        )
        for row in value
    ))
    if len({form_id for form_id, _ in result}) != len(result):
        raise MachineIRISASelectionV2Error(
            "fallback capability form IDs are duplicated"
        )
    return result


def _issues(value: Any) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list):
        raise MachineIRISASelectionV2Error(
            "ISA selection certificate issues must be an array"
        )
    result = []
    for raw in value:
        row = _object(raw, "ISA selection certificate issue")
        if set(row) != {"status", "code", "form_id"}:
            raise MachineIRISASelectionV2Error(
                "ISA selection certificate issue fields are invalid"
            )
        if row.get("status") not in {"incomplete", "violated"}:
            raise MachineIRISASelectionV2Error(
                "ISA selection certificate issue status is invalid"
            )
        form_id = row.get("form_id")
        if form_id is not None:
            form_id = _string(form_id, "issue form ID")
        result.append({
            "status": str(row["status"]),
            "code": _string(row.get("code"), "issue code"),
            "form_id": form_id,
        })
    result.sort(key=_canonical_json)
    return tuple(result)


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise MachineIRISASelectionV2Error(f"{context} must be an object")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise MachineIRISASelectionV2Error(
            f"{context} must be a nonempty canonical string"
        )
    return value


def _digest(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise MachineIRISASelectionV2Error(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("ascii")).hexdigest()


def build_machine_ir_isa_selection_authority_v2(
    *,
    requirements: Mapping[str, Any],
    qualification: Mapping[str, Any],
    binary_id: str = "original",
) -> dict[str, Any]:
    """Select and localize checked semantic evidence for every reachable form."""

    try:
        typed_requirements = parse_machine_ir_isa_requirements_v2(requirements)
        typed_qualification = parse_kernel_qualification(qualification)
    except ValueError as exc:
        raise MachineIRISASelectionV2Error(str(exc)) from exc
    if typed_requirements.status != "complete":
        raise MachineIRISASelectionV2Error(
            "exact machine-IR ISA requirements are not complete"
        )
    try:
        selection = select_isa_kernel_qualification(
            binary_id=binary_id,
            binary_sha256=typed_requirements.binary_sha256,
            requirements=typed_requirements.forms,
            qualification=typed_qualification,
        )
        authority = build_isa_kernel_selection_authority(
            binary_id=binary_id,
            binary_sha256=typed_requirements.binary_sha256,
            reachable_forms=typed_requirements.forms,
            qualification=typed_qualification,
            selection=selection,
            fallback_capability_ids=dict(
                typed_requirements.fallback_capability_ids
            ),
        )
    except ValueError as exc:
        raise MachineIRISASelectionV2Error(str(exc)) from exc
    return authority.to_payload()


__all__ = [
    "MACHINE_IR_ISA_SELECTION_CERTIFICATE_V2_FORMAT",
    "MachineIRISASelectionCertificateV2",
    "MachineIRISASelectionV2Error",
    "build_machine_ir_isa_selection_certificate_v2",
    "build_machine_ir_isa_selection_authority_v2",
    "compare_isa_selection_certificate_to_requirements_v2",
    "parse_machine_ir_isa_selection_certificate_v2",
]
