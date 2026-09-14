"""Local operator projections over existing domain artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..util import sha256_file
from .work_status import build_operator_work_status_v2


_LOCATION_FIELDS = (
    "symbol_id", "definition_id", "obligation_id", "provider_id", "facet",
    "operation_id", "site_id", "relocation_id", "hole_id", "root_id", "unit_id",
    "rva", "detail",
)


def normalize_blocker(
    row: Mapping[str, Any], *, default_family: str, default_code: str,
) -> dict[str, str | None]:
    location = next((
        row.get(field) for field in _LOCATION_FIELDS if row.get(field) is not None
    ), None)
    return {
        "family": str(row.get("family") or default_family),
        "code": str(row.get("code") or default_code),
        "location": None if location is None else str(location),
    }


def _artifact_value(path: Path, value: object | None) -> object:
    if value is not None:
        return value
    return json.loads(path.read_text(encoding="utf-8"))


def project_missing_component(
    *, target_id: str, component_id: str, products: Sequence[str],
) -> dict[str, Any]:
    required = ("interface", "bindingIntent", "semanticSlice", "workPackage")
    missing = [product for product in required if product not in products]
    blockers = [{
        "family": "component-contract",
        "code": "component_product_missing",
        "location": product,
    } for product in missing]
    return build_operator_work_status_v2(
        target_id=target_id,
        scope="component-development",
        subjects=[{
            "subject": f"component:{component_id}",
            "kind": "component",
            "state": "incomplete",
            "authority": "not-applicable",
            "stage": "component-contract",
            "sources": [],
            "blockers": blockers,
            "next_action": "author the missing component contract products",
        }],
    )


def project_component_work_package(
    *, target_id: str, component_id: str, path: Path, value: object | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    from ..components.work_package_v6 import ComponentWorkPackageV6

    work_package = ComponentWorkPackageV6.parse(_artifact_value(path, value))
    payload = work_package.payload
    if payload["component_id"] != component_id:
        raise ValueError("component work package binds another component")
    raw_blockers = [dict(row) for row in payload["blockers"]]
    blockers = [
        normalize_blocker(
            row,
            default_family="component-development",
            default_code="component_development_blocker",
        )
        for row in raw_blockers
    ]
    return build_operator_work_status_v2(
        target_id=target_id,
        scope="component-development",
        subjects=[{
            "subject": f"component:{component_id}",
            "kind": "component",
            "state": "complete" if not blockers else "incomplete",
            "authority": "not-applicable",
            "stage": blockers[0]["family"] if blockers else None,
            "sources": [{
                "role": "component-work-package",
                "format": str(payload["format"]),
                "sha256": sha256_file(path),
            }],
            "blockers": blockers,
            "next_action": (
                "run the component qualification check"
                if not blockers else "resolve the first component development blocker"
            ),
        }],
    ), raw_blockers


def project_component_qualification(
    *, target_id: str, component_id: str, path: Path, value: object | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    from ..semantic_providers.qualification_v2 import SemanticProviderQualificationV2

    qualification = SemanticProviderQualificationV2.parse(
        _artifact_value(path, value)
    )
    payload = qualification.payload
    expected_suffix = f".{component_id}.portable-c"
    if not qualification.provider_id.endswith(expected_suffix):
        raise ValueError("component qualification binds another component")
    raw_blockers = [dict(row) for row in payload["blockers"]]
    blockers = [
        normalize_blocker(
            row,
            default_family="provider-qualification",
            default_code="provider_qualification_blocker",
        )
        for row in raw_blockers
    ]
    state = str(payload["status"])
    return build_operator_work_status_v2(
        target_id=target_id,
        scope="component-qualification",
        subjects=[{
            "subject": f"component:{component_id}",
            "kind": "component",
            "state": state,
            "authority": "held" if state == "complete" else "missing",
            "stage": blockers[0]["family"] if blockers else None,
            "sources": [{
                "role": "semantic-provider-qualification",
                "format": str(payload["format"]),
                "sha256": sha256_file(path),
            }],
            "blockers": blockers,
            "next_action": (
                "select the component in a candidate configuration"
                if state == "complete" else "resolve the first qualification blocker"
            ),
        }],
    ), raw_blockers


def project_candidate_selection(
    *,
    target_id: str,
    configuration_id: str,
    path: Path,
    value: object | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    from ..semantic_providers.selection_v2 import ImplementationSelectionV2

    selection = ImplementationSelectionV2.parse(_artifact_value(path, value))
    payload = selection.payload
    raw_blockers = [dict(row) for row in payload["blockers"]]
    blockers = [
        normalize_blocker(
            row,
            default_family="provider-selection",
            default_code="provider_selection_blocker",
        )
        for row in raw_blockers
    ]
    state = str(payload["status"])
    status = build_operator_work_status_v2(
        target_id=target_id,
        scope="candidate",
        subjects=[{
            "subject": f"configuration:{target_id}:{configuration_id}",
            "kind": "configuration",
            "state": state,
            "authority": "not-applicable",
            "stage": blockers[0]["family"] if blockers else None,
            "sources": [{
                "role": "implementation-selection",
                "format": str(payload["format"]),
                "sha256": sha256_file(path),
            }],
            "blockers": blockers,
            "next_action": (
                f"build candidate configuration {configuration_id}"
                if state == "complete" else "resolve the first provider-selection blocker"
            ),
        }],
    )
    status["provider_coverage"] = _candidate_provider_coverage(payload)
    return status, raw_blockers


def _candidate_provider_coverage(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Summarize selected providers without re-reading semantic authority.

    Candidate selection is already the exact, source-bound provider inventory.
    Keeping this projection local preserves the operator clean cut while making
    generated fallback impossible to mistake for portable-C progress.
    """

    from ..semantic_providers.qualification_v2 import SEMANTIC_PROVIDER_KINDS_V2

    kinds = sorted(SEMANTIC_PROVIDER_KINDS_V2)

    def counts(field: str) -> dict[str, Any]:
        rows = payload[field]
        by_kind = {kind: 0 for kind in kinds}
        for row in rows:
            by_kind[str(row["provider_kind"])] += 1
        selected = len(rows)
        portable = by_kind["qualified_portable_c"]
        generated = by_kind["generated_behavioral_c"]
        pinned = by_kind["pinned_binary"]
        return {
            "selected": selected,
            "by_kind": by_kind,
            "portable_c": portable,
            "generated_behavioral_c": generated,
            "pinned_binary": pinned,
            "portable_share_of_selected_basis_points": (
                None if selected == 0 else portable * 10_000 // selected
            ),
        }

    definitions = counts("definition_selections")
    obligations = counts("obligation_selections")
    fallback_selections = (
        definitions["generated_behavioral_c"]
        + definitions["pinned_binary"]
        + obligations["generated_behavioral_c"]
        + obligations["pinned_binary"]
    )
    exact_complete = payload["status"] == "complete"
    portable_count = (
        int(definitions["portable_c"]) + int(obligations["portable_c"])
    )
    return {
        "exact_selection": "complete" if exact_complete else "incomplete",
        "portable_progress": (
            "fallback-free"
            if exact_complete and fallback_selections == 0
            else "partial"
            if portable_count
            else "not-started"
        ),
        "fallback_free": exact_complete and fallback_selections == 0,
        "definitions": definitions,
        "obligations": obligations,
    }


__all__ = [
    "normalize_blocker",
    "_candidate_provider_coverage",
    "project_candidate_selection",
    "project_component_qualification",
    "project_component_work_package",
    "project_missing_component",
]
