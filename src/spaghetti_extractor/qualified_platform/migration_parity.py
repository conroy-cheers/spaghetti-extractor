"""Veto-only reducer for the milestone-3 ISA migration corpus.

The old qualification campaign hashes are deliberately target-corpus-bound.
This reducer does not pretend that those hashes are reusable platform proof.
It checks that every exact target selection made the same semantic decision,
then emits the union of decoded forms and encodings as a non-authorizing
prototype input for the target-independent platform campaign.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .requirements import (
    parse_machine_ir_isa_requirements_v2,
)
from .target_selection import (
    compare_isa_selection_certificate_to_requirements_v2,
    parse_machine_ir_isa_selection_certificate_v2,
)
from ..errors import ToolkitInputError
from ..isa.kernel_qualification import parse_kernel_qualification
from ..isa.semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from ..util import sha256_file, write_json
from .formats import (
    QUALIFIED_PLATFORM_FORMAT,
    QUALIFIED_PLATFORM_MIGRATION_PARITY_FORMAT,
)


MAX_MIGRATION_INPUT_BYTES = 64 * 1024 * 1024
_FORM_STATUSES = ("qualified", "incomplete", "disputed", "vetoed")
_STATUS_RANK = {status: index for index, status in enumerate(_FORM_STATUSES)}
_FIELDS = {
    "format",
    "status",
    "role",
    "authority",
    "platform",
    "campaigns",
    "prototype_form_catalog",
    "blockers",
    "counts",
    "trust",
    "parity_sha256",
}


class QualifiedPlatformMigrationParityError(ToolkitInputError):
    """The migration corpus or its parity receipt is malformed."""


def _fail(message: str) -> None:
    raise QualifiedPlatformMigrationParityError(message)


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _load_json(path: Path, context: str) -> dict[str, Any]:
    source = Path(path)
    try:
        if source.stat().st_size > MAX_MIGRATION_INPUT_BYTES:
            _fail(f"{context} exceeds the migration input byte bound")
        payload = json.loads(source.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read {context}: {exc}")
    return dict(_object(payload, context))


def _digest(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        _fail(f"{context} must be lowercase SHA-256")
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        _fail(f"{context} must be a nonempty canonical string")
    return value


def _instruction_hex(value: object, context: str) -> str:
    encoded = _string(value, context)
    if (
        len(encoded) % 2
        or not 1 <= len(encoded) // 2 <= 15
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        _fail(f"{context} must be one canonical x86 instruction")
    return encoded


def _platform_binding(path: Path) -> dict[str, Any]:
    payload = _load_json(path, "qualified platform")
    if (
        payload.get("format") != QUALIFIED_PLATFORM_FORMAT
        or payload.get("authority") is not False
        or payload.get("target_independent") is not True
    ):
        _fail("migration parity input is not the target-independent platform")
    declared = _digest(payload.get("platform_sha256"), "platform SHA-256")
    core = {key: value for key, value in payload.items() if key != "platform_sha256"}
    if declared != canonical_sha256_v3(core):
        _fail("qualified platform self hash is stale")
    bindings = _object(payload.get("bindings"), "platform bindings")
    raw_forms = payload.get("isa_form_catalog")
    if not isinstance(raw_forms, list) or not raw_forms:
        _fail("qualified platform has no ISA form catalog")
    forms: dict[str, dict[str, str]] = {}
    for index, raw in enumerate(raw_forms):
        row = _object(raw, f"platform ISA form {index}")
        qualification = _object(
            row.get("qualification"), f"platform ISA form {index} qualification"
        )
        form_id = _string(row.get("form_id"), "platform form ID")
        projected = {
            "semantic_form": _string(
                row.get("semantic_form"), "platform semantic form"
            ),
            "status": _string(
                qualification.get("status"), "platform form status"
            ),
        }
        if projected["status"] not in _STATUS_RANK or form_id in forms:
            _fail("qualified platform ISA form catalog is malformed")
        forms[form_id] = projected
    return {
        "sha256": declared,
        "content_sha256": sha256_file(path),
        "classifier_sha256": _digest(
            bindings.get("classifier_sha256"), "platform classifier SHA-256"
        ),
        "semantic_kernel_id": _string(
            bindings.get("semantic_kernel_id"), "platform semantic kernel ID"
        ),
        "semantic_kernel_decoder_sha256": _digest(
            bindings.get("semantic_kernel_decoder_sha256"),
            "platform decoder SHA-256",
        ),
        "semantic_kernel_semantics_sha256": _digest(
            bindings.get("semantic_kernel_semantics_sha256"),
            "platform semantics SHA-256",
        ),
        "forms": forms,
    }


def _campaign_decisions(
    *,
    campaign_id: str,
    requirements_path: Path,
    qualification_path: Path,
    selection_certificate_path: Path,
    platform: Mapping[str, str],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    requirements_payload = _load_json(
        requirements_path, f"{campaign_id} exact ISA requirements"
    )
    qualification_payload = _load_json(
        qualification_path, f"{campaign_id} ISA qualification"
    )
    certificate_payload = _load_json(
        selection_certificate_path, f"{campaign_id} ISA selection certificate"
    )
    try:
        requirements = parse_machine_ir_isa_requirements_v2(requirements_payload)
        qualification = parse_kernel_qualification(qualification_payload)
        certificate = parse_machine_ir_isa_selection_certificate_v2(
            certificate_payload
        )
    except ValueError as exc:
        _fail(f"{campaign_id} ISA campaign does not replay: {exc}")

    binding = _object(requirements_payload.get("binding"), "requirements binding")
    kernel = qualification.semantic_kernel
    common_mismatches = []
    expected_bindings = {
        "classifier_sha256": binding.get("classifier_sha256"),
        "semantic_kernel_id": kernel.id,
        "semantic_kernel_decoder_sha256": kernel.decoder_sha256,
        "semantic_kernel_semantics_sha256": kernel.semantics_sha256,
    }
    for field, observed in expected_bindings.items():
        if observed != platform[field]:
            common_mismatches.append({
                "kind": "platform_binding_mismatch",
                "campaign_id": campaign_id,
                "field": field,
                "expected": platform[field],
                "observed": observed,
            })

    certificate_issues = compare_isa_selection_certificate_to_requirements_v2(
        certificate, requirements
    )
    for issue in certificate_issues:
        common_mismatches.append({
            "kind": "selection_certificate_requirement_mismatch",
            "campaign_id": campaign_id,
            "issue": issue,
        })
    qualification_by_id = {row.form_id: row for row in qualification.forms}
    exact_forms = {row.form_id: row for row in requirements.forms}
    occurrences: dict[str, set[str]] = defaultdict(set)
    for raw in requirements_payload.get("occurrences", []):
        row = _object(raw, f"{campaign_id} ISA occurrence")
        form_id = _string(row.get("form_id"), "occurrence form ID")
        encoded = _string(row.get("bytes"), "occurrence bytes")
        if form_id not in exact_forms:
            _fail(f"{campaign_id} occurrence names an unknown form")
        occurrences[form_id].add(encoded)

    decisions = []
    selected_by_id = {row["form_id"]: row for row in certificate.forms}
    blockers = list(common_mismatches)
    for form_id in sorted(exact_forms):
        requirement = exact_forms[form_id]
        qualified = qualification_by_id.get(form_id)
        selected = selected_by_id.get(form_id)
        if qualified is None or selected is None:
            blockers.append({
                "kind": "campaign_form_selection_missing",
                "campaign_id": campaign_id,
                "form_id": form_id,
            })
            continue
        status = qualified.status.value
        if selected["status"] != status:
            blockers.append({
                "kind": "campaign_form_selection_disagrees",
                "campaign_id": campaign_id,
                "form_id": form_id,
                "qualification_status": status,
                "selection_status": selected["status"],
            })
        decisions.append({
            "form_id": form_id,
            "semantic_form": requirement.semantic_form,
            "status": status,
            "qualification_sha256": qualified.sha256(),
            "instruction_hexes": sorted(occurrences[form_id]),
        })

    counts = _object(requirements_payload.get("counts"), "requirements counts")
    campaign = {
        "id": campaign_id,
        "requirements_status": requirements.status,
        "selection_status": certificate.status,
        "requirements_content_sha256": sha256_file(requirements_path),
        "qualification_content_sha256": sha256_file(qualification_path),
        "selection_certificate_content_sha256": sha256_file(
            selection_certificate_path
        ),
        "forms": len(decisions),
        "occurrences": int(counts.get("occurrences", 0)),
        "source_issues": len(requirements.issues) + len(certificate.issues),
    }
    return campaign, decisions, blockers


def reduce_qualified_platform_migration_decisions_v1(
    campaigns: Mapping[str, list[Mapping[str, Any]]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Reduce already checked decisions without granting platform authority."""

    forms: dict[str, dict[str, Any]] = {}
    blockers: list[dict[str, Any]] = []
    for campaign_id in sorted(campaigns):
        rows = campaigns[campaign_id]
        if not isinstance(rows, list) or not rows:
            _fail(f"migration campaign {campaign_id} has no form decisions")
        seen: set[str] = set()
        for raw in rows:
            row = _object(raw, f"{campaign_id} form decision")
            form_id = _string(row.get("form_id"), "form ID")
            semantic_form = _string(row.get("semantic_form"), "semantic form")
            status = row.get("status")
            if status not in _STATUS_RANK:
                _fail(f"{campaign_id} form {form_id} has an invalid status")
            if form_id in seen:
                _fail(f"{campaign_id} repeats form {form_id}")
            seen.add(form_id)
            if form_id != lean_semantic_form_id(
                semantic_form,
                classifier_sha256=lean_semantic_form_classifier_sha256(),
            ):
                _fail(f"{campaign_id} form {form_id} identity is stale")
            entry = forms.setdefault(form_id, {
                "semantic_forms": set(),
                "statuses": {},
                "qualification_variants": {},
                "instruction_hexes": set(),
            })
            entry["semantic_forms"].add(semantic_form)
            entry["statuses"][campaign_id] = status
            entry["qualification_variants"][campaign_id] = _digest(
                row.get("qualification_sha256"), "form qualification SHA-256"
            )
            encodings = row.get("instruction_hexes")
            if not isinstance(encodings, list) or not encodings:
                _fail(f"{campaign_id} form {form_id} has no exact encoding")
            entry["instruction_hexes"].update(
                _instruction_hex(encoded, f"{campaign_id} form {form_id} encoding")
                for encoded in encodings
            )

    result = []
    for form_id in sorted(forms):
        entry = forms[form_id]
        semantic_forms = sorted(entry["semantic_forms"])
        statuses = dict(sorted(entry["statuses"].items()))
        observed_statuses = sorted(set(statuses.values()), key=_STATUS_RANK.get)
        if len(semantic_forms) != 1:
            blockers.append({
                "kind": "semantic_form_identity_conflict",
                "form_id": form_id,
                "semantic_forms": semantic_forms,
            })
        if len(observed_statuses) != 1:
            blockers.append({
                "kind": "qualification_status_conflict",
                "form_id": form_id,
                "campaign_statuses": statuses,
            })
        normalized_status = max(observed_statuses, key=_STATUS_RANK.get)
        semantic_form = semantic_forms[0]
        normalized = {
            "form_id": form_id,
            "semantic_form": semantic_form,
            "status": normalized_status,
        }
        result.append({
            **normalized,
            "normalized_result_sha256": canonical_sha256_v3(normalized),
            "instruction_hexes": sorted(entry["instruction_hexes"]),
            "campaign_ids": sorted(statuses),
            "qualification_variants": [
                {
                    "campaign_id": campaign_id,
                    "qualification_sha256": qualification_sha256,
                }
                for campaign_id, qualification_sha256 in sorted(
                    entry["qualification_variants"].items()
                )
            ],
        })
    return result, blockers


def build_qualified_platform_migration_parity_v1(
    *,
    platform_path: Path,
    campaigns: Mapping[str, Mapping[str, Path]],
) -> dict[str, Any]:
    if not isinstance(campaigns, Mapping) or len(campaigns) < 2:
        _fail("migration parity requires at least two target campaigns")
    platform = _platform_binding(Path(platform_path))
    campaign_rows = []
    decisions: dict[str, list[Mapping[str, Any]]] = {}
    blockers = []
    for campaign_id in sorted(campaigns):
        source = _object(campaigns[campaign_id], f"{campaign_id} campaign paths")
        if set(source) != {"requirements", "qualification", "selection_certificate"}:
            _fail(f"{campaign_id} campaign path inventory is invalid")
        campaign, rows, source_blockers = _campaign_decisions(
            campaign_id=campaign_id,
            requirements_path=Path(source["requirements"]),
            qualification_path=Path(source["qualification"]),
            selection_certificate_path=Path(source["selection_certificate"]),
            platform=platform,
        )
        campaign_rows.append(campaign)
        decisions[campaign_id] = rows
        blockers.extend(source_blockers)
    form_catalog, reduction_blockers = (
        reduce_qualified_platform_migration_decisions_v1(decisions)
    )
    blockers.extend(reduction_blockers)
    migration_by_id = {row["form_id"]: row for row in form_catalog}
    platform_forms = platform["forms"]
    for form_id in sorted(set(migration_by_id) | set(platform_forms)):
        migration = migration_by_id.get(form_id)
        released = platform_forms.get(form_id)
        if migration is None or released is None:
            blockers.append({
                "kind": "platform_form_inventory_mismatch",
                "form_id": form_id,
                "migration_present": migration is not None,
                "platform_present": released is not None,
            })
            continue
        if (
            migration["semantic_form"] != released["semantic_form"]
            or migration["status"] != released["status"]
        ):
            blockers.append({
                "kind": "platform_form_decision_mismatch",
                "form_id": form_id,
                "migration": {
                    "semantic_form": migration["semantic_form"],
                    "status": migration["status"],
                },
                "platform": dict(released),
            })
    status_counts = Counter(row["status"] for row in form_catalog)
    payload: dict[str, Any] = {
        "format": QUALIFIED_PLATFORM_MIGRATION_PARITY_FORMAT,
        "status": "complete" if not blockers else "violated",
        "role": "migration_veto_only",
        "authority": False,
        "platform": {
            key: value for key, value in platform.items() if key != "forms"
        },
        "campaigns": campaign_rows,
        "prototype_form_catalog": form_catalog,
        "blockers": blockers,
        "counts": {
            "campaigns": len(campaign_rows),
            "union_forms": len(form_catalog),
            "qualified_forms": status_counts["qualified"],
            "incomplete_forms": status_counts["incomplete"],
            "disputed_forms": status_counts["disputed"],
            "vetoed_forms": status_counts["vetoed"],
            "encodings": sum(
                len(row["instruction_hexes"]) for row in form_catalog
            ),
            "blockers": len(blockers),
        },
        "trust": {
            "authorizes_platform": False,
            "authorizes_occurrences": False,
            "target_campaigns_remain_authoritative_during_migration": True,
            "corpus_specific_qualification_hashes_are_reusable": False,
            "normalized_status_is_veto_only": True,
        },
    }
    payload["parity_sha256"] = canonical_sha256_v3(payload)
    return parse_qualified_platform_migration_parity_v1(payload)


def parse_qualified_platform_migration_parity_v1(
    value: object,
) -> dict[str, Any]:
    payload = dict(_object(value, "qualified-platform migration parity"))
    if set(payload) != _FIELDS:
        _fail("migration parity field inventory is invalid")
    if payload.get("format") != QUALIFIED_PLATFORM_MIGRATION_PARITY_FORMAT:
        _fail("migration parity format is unsupported")
    declared = _digest(payload.get("parity_sha256"), "parity SHA-256")
    core = {key: item for key, item in payload.items() if key != "parity_sha256"}
    if declared != canonical_sha256_v3(core):
        _fail("migration parity self hash is stale")
    if payload.get("authority") is not False or payload.get("role") != "migration_veto_only":
        _fail("migration parity receipt claimed authority")
    campaigns = payload.get("campaigns")
    forms = payload.get("prototype_form_catalog")
    blockers = payload.get("blockers")
    if not all(isinstance(value, list) for value in (campaigns, forms, blockers)):
        _fail("migration parity inventories must be arrays")
    if [row.get("id") for row in campaigns] != sorted(
        {row.get("id") for row in campaigns}
    ):
        _fail("migration campaigns are not canonical")
    form_ids = [row.get("form_id") for row in forms]
    if form_ids != sorted(set(form_ids)):
        _fail("prototype form catalog is not canonical")
    counts = _object(payload.get("counts"), "migration parity counts")
    status_counts = Counter(row.get("status") for row in forms)
    expected_counts = {
        "campaigns": len(campaigns),
        "union_forms": len(forms),
        "qualified_forms": status_counts["qualified"],
        "incomplete_forms": status_counts["incomplete"],
        "disputed_forms": status_counts["disputed"],
        "vetoed_forms": status_counts["vetoed"],
        "encodings": sum(len(row.get("instruction_hexes", [])) for row in forms),
        "blockers": len(blockers),
    }
    if dict(counts) != expected_counts:
        _fail("migration parity counts are stale")
    expected_status = "complete" if not blockers else "violated"
    if payload.get("status") != expected_status:
        _fail("migration parity status is stale")
    return payload


def write_qualified_platform_migration_parity_v1(
    *,
    platform_path: Path,
    campaigns: Mapping[str, Mapping[str, Path]],
    out: Path,
) -> dict[str, Any]:
    payload = build_qualified_platform_migration_parity_v1(
        platform_path=platform_path,
        campaigns=campaigns,
    )
    write_json(Path(out), payload)
    return payload


__all__ = [
    "MAX_MIGRATION_INPUT_BYTES",
    "QualifiedPlatformMigrationParityError",
    "build_qualified_platform_migration_parity_v1",
    "parse_qualified_platform_migration_parity_v1",
    "reduce_qualified_platform_migration_decisions_v1",
    "write_qualified_platform_migration_parity_v1",
]
