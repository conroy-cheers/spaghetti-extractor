"""Exact target occurrence selection from ``qualified-platform-v1``.

This module is deliberately an in-memory compiler operation, not an artifact
family.  It binds Lean-decoded target requirements to the one shared platform
catalog.  The legacy ISA-evidence projection and semantic-object frontend use
the same operation while consumers migrate, preventing two selection
semantics from developing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .requirements import (
    MachineIRISARequirementsV2,
    parse_machine_ir_isa_requirements_v2,
)
from ..errors import ToolkitInputError
from ..isa.qualification_certificate import (
    parse_isa_kernel_qualification_certificate_v1,
)
from ..util import json_dumps, sha256_bytes
from .formats import QUALIFIED_PLATFORM_FORMAT
from .native_catalog import native_primitive_catalog_payload_v1


_PLATFORM_FIELDS = {
    "format", "status", "role", "authority", "target_independent",
    "bindings", "members", "primitive_catalog", "runtime_provider_catalog",
    "isa_form_catalog", "abi_profiles", "native_primitives", "evidence",
    "holes", "counts", "platform_sha256",
}
_X87_FORM_PREFIX = (
    "SpaghettiExtractor.ISA.Formal.InstructionSemanticForm.x87"
)
_X87_REPLAY_PROVIDER_ID = "native.pe32.x87-exact-replay-v1"
_X87_REPLAY_FEATURES = {
    "typed_x87_execution", "x87_state_export", "x87_state_import",
}


class QualifiedPlatformSelectionError(ToolkitInputError):
    """A platform-to-target semantic-form selection failed closed."""


def _fail(message: str) -> None:
    raise QualifiedPlatformSelectionError(message)


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{context} must be an array")
    return value


def _canonical_bytes(value: object) -> bytes:
    return (json_dumps(value) + "\n").encode("utf-8")


def _load_canonical(path: Path, context: str) -> tuple[dict[str, Any], str]:
    source = Path(path)
    try:
        data = source.read_bytes()
        value = json.loads(data)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {context}: {exc}")
    payload = dict(_object(value, context))
    if data != _canonical_bytes(payload):
        _fail(f"{context} must be canonical JSON")
    return payload, sha256_bytes(data)


def load_qualified_platform_selection_source_v1(
    path: Path,
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Validate the closed release coordinates needed for target selection."""

    source = Path(path)
    platform, platform_content_sha256 = _load_canonical(
        source, "qualified platform"
    )
    if (
        set(platform) != _PLATFORM_FIELDS
        or platform.get("format") != QUALIFIED_PLATFORM_FORMAT
        or platform.get("status") != "complete"
        or platform.get("role") != "qualified_platform_release"
        or platform.get("authority") is not True
        or platform.get("target_independent") is not True
    ):
        _fail("qualified platform disposition or field inventory is invalid")
    declared = platform.get("platform_sha256")
    core = {
        key: value for key, value in platform.items()
        if key != "platform_sha256"
    }
    if declared != canonical_sha256_v3(core):
        _fail("qualified platform self hash is stale")

    members = _object(platform.get("members"), "qualified platform members")
    certificate_member = _object(
        members.get("isa_form_qualification_certificate"),
        "qualified platform ISA certificate member",
    )
    if set(certificate_member) != {"path", "content_sha256", "identity"}:
        _fail("qualified platform ISA certificate member is malformed")
    member_path = certificate_member.get("path")
    if member_path != "isa-form-qualification-certificate.json":
        _fail("qualified platform ISA certificate member path is not canonical")
    certificate_raw, certificate_content_sha256 = _load_canonical(
        source.parent / member_path, "qualified platform ISA certificate"
    )
    try:
        certificate = parse_isa_kernel_qualification_certificate_v1(
            certificate_raw
        )
    except ValueError as exc:
        _fail(f"qualified platform ISA certificate is invalid: {exc}")
    bindings = _object(platform.get("bindings"), "qualified platform bindings")
    if (
        certificate_member.get("identity") != certificate["certificate_sha256"]
        or certificate_member.get("content_sha256")
        != certificate_content_sha256
        or bindings.get("isa_form_qualification_certificate_sha256")
        != certificate["certificate_sha256"]
        or bindings.get("isa_form_qualification_certificate_content_sha256")
        != certificate_content_sha256
        or bindings.get("classifier_sha256")
        != certificate["classifier_sha256"]
    ):
        _fail("qualified platform ISA certificate binding is stale")

    catalog = _array(platform.get("isa_form_catalog"), "ISA form catalog")
    catalog_by_id: dict[str, Mapping[str, Any]] = {}
    for index, raw in enumerate(catalog):
        row = _object(raw, f"ISA form catalog row {index}")
        form_id = row.get("form_id")
        if not isinstance(form_id, str) or not form_id or form_id in catalog_by_id:
            _fail("qualified platform ISA form identities are malformed or repeated")
        catalog_by_id[form_id] = row
    certificate_by_id = {row["form_id"]: row for row in certificate["forms"]}
    if set(catalog_by_id) != set(certificate_by_id):
        _fail("qualified platform catalog and certificate form sets disagree")
    for form_id, certified in certificate_by_id.items():
        row = catalog_by_id[form_id]
        qualification = _object(
            row.get("qualification"), f"ISA form {form_id} qualification"
        )
        if (
            row.get("semantic_form") != certified["semantic_form"]
            or qualification.get("status") != certified["oracle_status"]
            or qualification.get("structural_status")
            != certified["structural_status"]
            or qualification.get("evidence_id")
            != certified["qualification_sha256"]
        ):
            _fail(f"qualified platform ISA form {form_id!r} is stale")
    return (
        platform,
        certificate,
        platform_content_sha256,
        certificate_content_sha256,
    )


def _native_x87_exact_replay_qualification(
    platform: Mapping[str, Any],
) -> dict[str, str] | None:
    """Return the reviewed exact-replay authority carried by the platform."""

    native_rows = _array(
        platform.get("native_primitives"),
        "qualified platform native primitives",
    )
    if native_rows != native_primitive_catalog_payload_v1():
        _fail("qualified platform native primitive catalog is stale")
    matches = [
        _object(row, "qualified platform native primitive")
        for row in native_rows
        if isinstance(row, Mapping)
        and row.get("provider_id") == _X87_REPLAY_PROVIDER_ID
    ]
    if not matches:
        return None
    if len(matches) != 1:
        _fail("qualified platform repeats the native x87 replay primitive")
    row = matches[0]
    qualification = _object(
        row.get("qualification"), "native x87 replay qualification"
    )
    review_sha256 = qualification.get("review_sha256")
    if (
        row.get("target") != "i686-pc-windows-pe32"
        or row.get("isa_profile") != "pe32-i686-v1"
        or set(_array(row.get("features"), "native x87 replay features"))
        != _X87_REPLAY_FEATURES
        or qualification.get("status") != "complete"
        or qualification.get("authority")
        != "reviewed_native_primitive_contract"
        or qualification.get("test_results_authorizing") is not False
        or not isinstance(review_sha256, str)
        or len(review_sha256) != 64
        or any(character not in "0123456789abcdef" for character in review_sha256)
    ):
        _fail("qualified platform native x87 replay authority is malformed")
    return {
        "provider_id": _X87_REPLAY_PROVIDER_ID,
        "qualification_sha256": review_sha256,
    }


def _form_selection_v1(
    *,
    semantic_form: str,
    certified: Mapping[str, Any] | None,
    native_x87_replay: Mapping[str, str] | None,
) -> tuple[str, str, str | None, str | None]:
    """Select one semantic implementation without conflating its veto model."""

    oracle_status = None if certified is None else str(certified["oracle_status"])
    if (
        certified is not None
        and certified.get("structural_status") == "complete"
        and oracle_status != "qualified"
        and semantic_form.startswith(_X87_FORM_PREFIX)
        and native_x87_replay is not None
    ):
        return (
            "qualified",
            "native_exact_replay",
            native_x87_replay["qualification_sha256"],
            oracle_status,
        )
    if certified is None:
        return "incomplete", "unavailable", None, None
    return (
        oracle_status or "incomplete",
        "lean_semantics" if oracle_status == "qualified" else "unavailable",
        str(certified["qualification_sha256"]),
        oracle_status,
    )


def _native_x87_exact_replay_issues_v1(
    *,
    transfer_plan: Mapping[str, Any] | None,
    occurrences: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Bind fallback-selected x87 forms to exact singleton replay effects."""

    transfers = (
        transfer_plan.get("transfers")
        if isinstance(transfer_plan, Mapping) else None
    )
    transfers_by_id: dict[str, Mapping[str, Any]] = {}
    if isinstance(transfers, list):
        for raw in transfers:
            if not isinstance(raw, Mapping):
                continue
            identity = raw.get("identity")
            if isinstance(identity, str) and identity not in transfers_by_id:
                transfers_by_id[identity] = raw

    issues: list[dict[str, Any]] = []
    for occurrence in occurrences:
        unit_id = str(occurrence["unit_id"])
        form_id = str(occurrence["form_id"])
        start = int(occurrence["rva_start"])
        stop = int(occurrence["rva_end"])
        transfer = transfers_by_id.get(unit_id)
        valid = False
        if transfer is not None:
            source = transfer.get("source")
            intrinsics = transfer.get("x87_intrinsics")
            effects = transfer.get("effects")
            if (
                isinstance(source, Mapping)
                and source.get("rva_start") == start
                and source.get("rva_end") == stop
                and source.get("instruction_bytes_sha256")
                == occurrence["instruction_bytes_sha256"]
                and isinstance(intrinsics, list)
                and isinstance(effects, list)
            ):
                matches = [
                    row for row in intrinsics
                    if isinstance(row, Mapping)
                    and row.get("rva_start") == start
                    and row.get("rva_end") == stop
                    and row.get("checked_decoder")
                    == "SpaghettiExtractor.ISA.Formal.decodeInstructionExact"
                    and row.get("checked_executor")
                    == "SpaghettiExtractor.ISA.Formal.executeInstruction"
                    and isinstance(row.get("operation"), Mapping)
                    and row["operation"].get("source_size") == stop - start
                ]
                if len(matches) == 1:
                    intrinsic_id = matches[0].get("id")
                    references = [
                        row for row in effects
                        if isinstance(row, Mapping)
                        and row.get("op") == "typed_x87"
                        and row.get("operands") == [intrinsic_id]
                    ]
                    valid = len(references) == 1
        if not valid:
            issues.append({
                "status": "incomplete",
                "code": "qualified_platform_exact_x87_replay_unbound",
                "form_id": form_id,
                "unit_id": unit_id,
                "rva_start": start,
                "rva_end": stop,
            })
    return sorted(issues, key=lambda row: (
        str(row["form_id"]), int(row["rva_start"]), str(row["unit_id"])
    ))


def select_isa_requirements_from_certificate_v1(
    requirements: MachineIRISARequirementsV2,
    certificate_payload: Mapping[str, Any],
    *,
    platform_sha256: str | None = None,
    platform_content_sha256: str | None = None,
    native_x87_replay: Mapping[str, str] | None = None,
    transfer_plan: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Return one canonical in-memory selection for exact target occurrences."""

    try:
        certificate = parse_isa_kernel_qualification_certificate_v1(
            certificate_payload
        )
    except ValueError as exc:
        _fail(f"qualified-platform ISA certificate is invalid: {exc}")
    profile = certificate["profile"]
    if (
        requirements.classifier_sha256 != certificate["classifier_sha256"]
        or profile["id"] != "pe32-i686-v1"
        or profile["architecture"] != "x86"
        or profile["cpu"] != "i686"
        or profile["execution_mode"] != "protected-32"
        or profile["environment"] != "pe32"
    ):
        _fail(
            "qualified-platform ISA certificate disagrees with exact target "
            "classifier or profile"
        )
    certified_by_id = {
        row["form_id"]: row for row in certificate["forms"]
    }
    fallback_by_id = dict(requirements.fallback_capability_ids)
    forms: list[dict[str, Any]] = []
    form_by_id: dict[str, dict[str, Any]] = {}
    issues = [dict(row) for row in requirements.issues]
    for requirement in sorted(requirements.forms, key=lambda row: row.form_id):
        certified = certified_by_id.get(requirement.form_id)
        if (
            certified is not None
            and certified["semantic_form"] != requirement.semantic_form
        ):
            _fail(
                "qualified-platform semantic form disagrees for "
                f"{requirement.form_id!r}"
            )
        status, qualification_kind, qualification_sha256, oracle_status = (
            _form_selection_v1(
                semantic_form=requirement.semantic_form,
                certified=certified,
                native_x87_replay=native_x87_replay,
            )
        )
        row = {
            "form_id": requirement.form_id,
            "semantic_form": requirement.semantic_form,
            "status": status,
            "qualification_kind": qualification_kind,
            "qualification_sha256": qualification_sha256,
            "oracle_status": oracle_status,
            "fallback_capability_id": fallback_by_id.get(requirement.form_id),
        }
        if row["fallback_capability_id"] is None:
            _fail(f"ISA form {requirement.form_id!r} has no fallback capability")
        forms.append(row)
        form_by_id[requirement.form_id] = row
        if status != "qualified":
            issues.append({
                "status": "incomplete",
                "code": "qualified_platform_form_unavailable",
                "form_id": requirement.form_id,
                "platform_status": status,
            })

    occurrences: list[dict[str, Any]] = []
    for index, raw in enumerate(requirements.payload["occurrences"]):
        occurrence = _object(raw, f"ISA requirement occurrence {index}")
        form_id = str(occurrence["form_id"])
        selected = form_by_id.get(form_id)
        if selected is None:
            _fail(f"ISA occurrence references unknown form {form_id!r}")
        encoded = bytes.fromhex(str(occurrence["bytes"]))
        identity_body = {
            "binary_sha256": requirements.binary_sha256,
            "unit_id": occurrence["unit_id"],
            "instruction_index": occurrence["instruction_index"],
            "rva_start": occurrence["rva"],
            "rva_end": int(occurrence["rva"]) + int(occurrence["byte_length"]),
            "instruction_bytes_sha256": sha256_bytes(encoded),
            "form_id": form_id,
        }
        occurrences.append({
            "occurrence_id": "isa-occurrence:" + canonical_sha256_v3(identity_body),
            "unit_id": occurrence["unit_id"],
            "instruction_index": occurrence["instruction_index"],
            "rva_start": occurrence["rva"],
            "rva_end": int(occurrence["rva"]) + int(occurrence["byte_length"]),
            "instruction_bytes_sha256": sha256_bytes(encoded),
            "form_id": form_id,
        })
    occurrences.sort(key=lambda row: (
        int(row["rva_start"]), str(row["unit_id"]),
        int(row["instruction_index"]),
    ))
    exact_replay_form_ids = {
        str(row["form_id"])
        for row in forms
        if row["qualification_kind"] == "native_exact_replay"
    }
    if exact_replay_form_ids:
        replay_issues = _native_x87_exact_replay_issues_v1(
            transfer_plan=transfer_plan,
            occurrences=[
                row for row in occurrences
                if row["form_id"] in exact_replay_form_ids
            ],
        )
        issues.extend(replay_issues)
        unavailable_forms = {
            str(row["form_id"]) for row in replay_issues
        }
        for row in forms:
            if row["form_id"] in unavailable_forms:
                row["status"] = "incomplete"
                row["qualification_kind"] = "native_exact_replay_unbound"
    status = (
        "qualified"
        if requirements.status == "complete"
        and all(row["status"] == "qualified" for row in forms)
        else "incomplete"
    )
    result: dict[str, Any] = {
        "status": status,
        "source": "qualified-platform-v1",
        "bindings": {
            "binary_sha256": requirements.binary_sha256,
            "machine_ir_sha256": requirements.machine_ir_sha256,
            "requirements_sha256": requirements.payload["requirements_sha256"],
            "classifier_sha256": certificate["classifier_sha256"],
            "platform_sha256": platform_sha256,
            "platform_content_sha256": platform_content_sha256,
            "certificate_sha256": certificate["certificate_sha256"],
            "semantic_kernel_id": certificate["semantic_kernel"]["id"],
            "semantic_kernel_decoder_sha256": certificate["semantic_kernel"][
                "decoder_sha256"
            ],
            "semantic_kernel_semantics_sha256": certificate["semantic_kernel"][
                "semantics_sha256"
            ],
            "profile_id": profile["id"],
        },
        "forms": forms,
        "occurrences": occurrences,
        "issues": sorted(issues, key=lambda row: json_dumps(row)),
        "counts": {
            "forms": len(forms),
            "forms_qualified": sum(row["status"] == "qualified" for row in forms),
            "forms_native_exact_replay": sum(
                row["qualification_kind"] == "native_exact_replay"
                for row in forms
            ),
            "occurrences": len(occurrences),
            "occurrences_qualified": sum(
                form_by_id[row["form_id"]]["status"] == "qualified"
                for row in occurrences
            ),
            "occurrences_native_exact_replay": sum(
                form_by_id[row["form_id"]]["qualification_kind"]
                == "native_exact_replay"
                for row in occurrences
            ),
            "issues": len(issues),
        },
    }
    result["selection_sha256"] = canonical_sha256_v3(result)
    return result


def select_isa_requirements_from_platform_v1(
    requirements_payload: Mapping[str, Any], qualified_platform: Path,
    *, transfer_plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Validate one platform release and select all exact target occurrences."""

    try:
        requirements = parse_machine_ir_isa_requirements_v2(requirements_payload)
    except ValueError as exc:
        _fail(f"exact ISA requirements are invalid: {exc}")
    platform, certificate, platform_content_sha256, _ = (
        load_qualified_platform_selection_source_v1(qualified_platform)
    )
    selection = select_isa_requirements_from_certificate_v1(
        requirements,
        certificate,
        platform_sha256=str(platform["platform_sha256"]),
        platform_content_sha256=platform_content_sha256,
        native_x87_replay=_native_x87_exact_replay_qualification(platform),
        transfer_plan=transfer_plan,
    )
    return selection, platform, certificate


__all__ = [
    "QualifiedPlatformSelectionError",
    "load_qualified_platform_selection_source_v1",
    "select_isa_requirements_from_certificate_v1",
    "select_isa_requirements_from_platform_v1",
]
