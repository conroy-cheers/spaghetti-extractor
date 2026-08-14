"""Build exact, independently cacheable contracts for component lift units."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Mapping

from ..artifact_formats import SEMANTIC_COMPONENT_DECLARATIONS_FORMAT
from .formats import (
    COMPONENT_BOUNDARY_REVIEW_V2_FORMAT,
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_RESOLUTION_V2_FORMAT,
)
from ..component_interface import (
    check_component_interface,
    finalize_component_interface_spec,
    synthesize_component_interface_spec,
)
from ..semantic_components import build_semantic_component_catalog
from ..util import write_json
from .intent import ComponentIntentError
from .model import ComponentBoundaryReviewV2


_INTERFACE_OVERRIDE_FIELDS = frozenset(
    {"parameters", "results", "objects", "services", "claims", "policy"}
)


def build_lift_unit_contract_v2(
    *,
    machine_ir: Path | str,
    reconstruction_plan: Path | str,
    resolution: Path | str | Mapping[str, object],
    lift_unit_id: str,
    out_dir: Path | str,
    review: Path | str | Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Derive and check one leaf or aggregate contract from exact machine units.

    Alternative groups intentionally receive separate catalogs.  Their machine
    units may overlap other alternatives without weakening the selected
    configuration's exclusive ownership check.
    """

    resolution_payload = _load_object(resolution, "component resolution")
    _check_resolution(resolution_payload)
    lift_unit = _find_lift_unit(resolution_payload, lift_unit_id)
    declarations = _declarations(resolution_payload, lift_unit)
    catalog = build_semantic_component_catalog(
        machine_ir=machine_ir,
        reconstruction_plan=reconstruction_plan,
        declarations=declarations,
    )
    synthesized = synthesize_component_interface_spec(
        catalog=catalog,
        machine_ir=machine_ir,
        component_id=lift_unit_id,
    )
    review_payload = None if review is None else _load_review(review, lift_unit_id)
    reviewed = _apply_review(synthesized, review_payload)
    refinement = check_component_interface(
        catalog=catalog,
        machine_ir=machine_ir,
        component_id=lift_unit_id,
        interface_spec=reviewed,
    )

    catalog_invalid = catalog.get("definition_status") != "valid"
    refinement_status = refinement.get("status")
    if catalog_invalid or refinement_status == "violated":
        status = "violated"
    elif review_payload is None or refinement_status != "checked":
        status = "incomplete"
    else:
        status = "checked"
    blockers: list[dict[str, object]] = []
    if review_payload is None:
        blockers.append(
            {
                "code": "operator_boundary_review_missing",
                "status": "incomplete",
                "lift_unit_id": lift_unit_id,
                "remediation": (
                    "review the synthesized interface and add a v2 boundary-review file"
                ),
            }
        )
    blockers.extend(copy.deepcopy(refinement.get("issues", [])))
    blockers.extend(copy.deepcopy(catalog.get("issues", [])))
    core = {
        "format": COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
        "status": status,
        "lift_unit": {
            "kind": lift_unit["kind"],
            "id": lift_unit_id,
            "label": lift_unit["label"],
            "unit_ids": copy.deepcopy(lift_unit["unit_ids"]),
            "evidence_profile": lift_unit["evidence_profile"],
        },
        "bindings": {
            "component_resolution_sha256": resolution_payload[
                "resolution_sha256"
            ],
            "semantic_component_catalog_sha256": catalog["catalog_sha256"],
            "component_sha256": catalog["components"][0]["component_sha256"],
            "interface_spec_sha256": reviewed["interface_spec_sha256"],
            "interface_refinement_sha256": refinement["refinement_sha256"],
        },
        "authority": {
            "membership": "exact_machine_unit_membership_v2",
            "machine_boundary": "derived_from_exact_machine_ir_v2",
            "logical_interface": (
                "operator_reviewed_and_machine_effect_checked_v2"
                if status == "checked"
                else "none"
            ),
            "activation_authorized": False,
            "activation_requires_separate_behavioral_evidence": True,
        },
        "review": {
            "status": "checked" if review_payload is not None else "missing",
            "accept_derived_machine_boundary": (
                review_payload.accept_derived_machine_boundary
                if review_payload is not None
                else False
            ),
        },
        "artifacts": {
            "declarations": "semantic-component-declarations.json",
            "catalog": "semantic-component-catalog.json",
            "synthesized_interface": "synthesized-interface.json",
            "reviewed_interface": "reviewed-interface.json",
            "interface_refinement": "interface-refinement.json",
        },
        "blockers": sorted(blockers, key=_blocker_key),
    }
    result = {**core, "contract_sha256": _canonical_sha256(core)}
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "semantic-component-declarations.json", declarations)
    write_json(output / "semantic-component-catalog.json", catalog)
    write_json(output / "synthesized-interface.json", synthesized)
    write_json(output / "reviewed-interface.json", reviewed)
    write_json(output / "interface-refinement.json", refinement)
    write_json(output / "contract.json", result)
    return result


def load_component_boundary_review_v2(
    value: Path | str | Mapping[str, object], *, lift_unit_id: str
) -> ComponentBoundaryReviewV2:
    """Parse the small authored review layer without accepting generated facts."""

    return _load_review(value, lift_unit_id)


def _declarations(
    resolution: Mapping[str, object], lift_unit: Mapping[str, object]
) -> dict[str, object]:
    logical = {
        "status": "proposed",
        "parameters": [],
        "results": [],
        "objects": [],
        "persistent_state": [],
        "services": [],
        "preconditions": [],
        "postconditions": [],
        "observations": [],
    }
    component = {
        "id": lift_unit["id"],
        "label": lift_unit["label"],
        "purpose": "Operator-defined independently liftable semantic component",
        "kind": "aggregate" if lift_unit["kind"] == "group" else "procedure",
        "sharing": "exclusive",
        "expected_reachability": "any",
        "membership": {
            "unit_ids": copy.deepcopy(lift_unit["unit_ids"]),
            "cluster_ids": [],
        },
        "children": [],
        "component_calls": [],
        "logical_interface": logical,
        "refinement": {
            "status": "not_started",
            "stages": [
                {
                    "kind": "component_resolution_v2",
                    "resolution_sha256": resolution["resolution_sha256"],
                    "lift_unit_id": lift_unit["id"],
                }
            ],
        },
        "emission": {
            "policy": "subsystem" if lift_unit["kind"] == "group" else "function"
        },
        "evidence": [],
        "assumptions": [],
    }
    return {
        "format": SEMANTIC_COMPONENT_DECLARATIONS_FORMAT,
        "program_id": resolution["program_id"],
        "bindings": copy.deepcopy(resolution["bindings"]),
        "components": [component],
    }


def _apply_review(
    synthesized: Mapping[str, object], review: ComponentBoundaryReviewV2 | None
) -> dict[str, object]:
    result = copy.deepcopy(dict(synthesized))
    if review is not None:
        for key, value in review.overrides.items():
            result[key] = copy.deepcopy(value)
    return finalize_component_interface_spec(result)


def _load_review(
    value: Path | str | Mapping[str, object], lift_unit_id: str
) -> ComponentBoundaryReviewV2:
    row = _load_object(value, "component boundary review")
    _exact_keys(
        row,
        {
            "format",
            "lift_unit_id",
            "accept_derived_machine_boundary",
            "overrides",
        },
        "component boundary review",
    )
    if row.get("format") != COMPONENT_BOUNDARY_REVIEW_V2_FORMAT:
        raise ComponentIntentError("unsupported component boundary-review format")
    if row.get("lift_unit_id") != lift_unit_id:
        raise ComponentIntentError("component boundary review targets another lift unit")
    if row.get("accept_derived_machine_boundary") is not True:
        raise ComponentIntentError(
            "component boundary review must explicitly accept the derived boundary"
        )
    overrides = _object(row.get("overrides"), "component boundary review overrides")
    unknown = sorted(set(overrides) - _INTERFACE_OVERRIDE_FIELDS)
    if unknown:
        raise ComponentIntentError(
            f"unsupported component boundary-review overrides: {unknown}"
        )
    _reject_generated(overrides, "component boundary review")
    return ComponentBoundaryReviewV2(
        lift_unit_id=lift_unit_id,
        accept_derived_machine_boundary=True,
        overrides=copy.deepcopy(dict(overrides)),
    )


def _check_resolution(payload: Mapping[str, object]) -> None:
    if payload.get("format") != COMPONENT_RESOLUTION_V2_FORMAT:
        raise ComponentIntentError("unsupported component resolution format")
    expected = payload.get("resolution_sha256")
    core = copy.deepcopy(dict(payload))
    core.pop("resolution_sha256", None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError("component resolution self-hash is stale")


def _find_lift_unit(
    resolution: Mapping[str, object], lift_unit_id: str
) -> dict[str, object]:
    matches = [
        copy.deepcopy(dict(row))
        for field in ("components", "groups")
        for row in _array(resolution.get(field), f"resolved {field}")
        if isinstance(row, Mapping) and row.get("id") == lift_unit_id
    ]
    if len(matches) != 1:
        raise ComponentIntentError(
            f"lift unit {lift_unit_id!r} resolved to {len(matches)} definitions"
        )
    return matches[0]


def _load_object(
    value: Path | str | Mapping[str, object], description: str
) -> dict[str, object]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    try:
        payload = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {description}: {exc}") from exc
    return dict(_object(payload, description))


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{description} must be an object")
    return value


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{description} must be an array")
    return value


def _exact_keys(
    value: Mapping[str, object], allowed: set[str], description: str
) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted(allowed - set(value))
    if unknown or missing:
        raise ComponentIntentError(
            f"{description} fields differ: missing={missing}, unknown={unknown}"
        )


def _reject_generated(value: object, context: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if key in {"status", "bindings", "blockers"} or key.endswith("_sha256"):
                raise ComponentIntentError(
                    f"{context} contains generated-only field {key!r}"
                )
            _reject_generated(child, context)
    elif isinstance(value, list):
        for child in value:
            _reject_generated(child, context)


def _blocker_key(value: object) -> tuple[str, str, str]:
    row = value if isinstance(value, Mapping) else {}
    return (
        str(row.get("status", "")),
        str(row.get("code", "")),
        str(row.get("id", "")),
    )


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()
