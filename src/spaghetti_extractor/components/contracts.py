"""Build exact, independently cacheable contracts for component lift units."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Mapping

from ..artifacts.formats import SEMANTIC_COMPONENT_DECLARATIONS_FORMAT
from .formats import (
    COMPONENT_BOUNDARY_REVIEW_V2_FORMAT,
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_RESOLUTION_SLICE_V1_FORMAT,
    COMPONENT_RESOLUTION_V2_FORMAT,
)
from .interface import (
    check_component_interface,
    finalize_component_interface_spec,
    synthesize_component_interface_spec,
)
from .interface_ir import (
    ComponentInterfaceIRError,
    ComponentInterfaceIRV1,
    PortableComponentInterfaceV2,
    parse_component_interface,
)
from .external_sites import load_component_external_site_slice
from .semantic import build_semantic_component_catalog
from ..util import write_json
from .intent import ComponentIntentError
from .model import ComponentBoundaryReview


_INTERFACE_OVERRIDE_FIELDS = frozenset(
    {
        "parameters",
        "results",
        "objects",
        "services",
        "adapter_effects",
        "completion",
        "claims",
        "policy",
        "source_abi",
        "portable_interface_ir",
    }
)


def build_lift_unit_contract(
    *,
    machine_ir: Path | str,
    reconstruction_plan: Path | str,
    resolution: Path | str | Mapping[str, object],
    lift_unit_id: str,
    out_dir: Path | str,
    review: Path | str | Mapping[str, object] | None = None,
    external_sites: Path | str | Mapping[str, object] | None = None,
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
    external_site_slice = (
        None
        if external_sites is None
        else load_component_external_site_slice(external_sites)
    )
    if external_site_slice is not None:
        expected_units = tuple(sorted(str(value) for value in lift_unit["unit_ids"]))
        if (
            external_site_slice.lift_unit_id != lift_unit_id
            or external_site_slice.unit_ids != expected_units
        ):
            raise ComponentIntentError(
                "component external-site slice is bound to a different lift unit"
            )
    synthesized = synthesize_component_interface_spec(
        catalog=catalog,
        machine_ir=machine_ir,
        component_id=lift_unit_id,
        external_sites=external_site_slice,
    )
    review_payload = None if review is None else _load_review(review, lift_unit_id)
    reviewed = _apply_review(synthesized, review_payload)
    portable_interface = _portable_interface(reviewed)
    refinement = check_component_interface(
        catalog=catalog,
        machine_ir=machine_ir,
        component_id=lift_unit_id,
        interface_spec=reviewed,
        external_sites=external_site_slice,
    )

    catalog_invalid = catalog.get("definition_status") != "valid"
    refinement_status = refinement.get("status")
    if (
        catalog_invalid
        or refinement_status == "violated"
        or (
            external_site_slice is not None
            and external_site_slice.status == "violated"
        )
    ):
        status = "violated"
    elif (
        review_payload is None
        or refinement_status != "checked"
        or (
            external_site_slice is not None
            and external_site_slice.status != "checked"
        )
    ):
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
    if external_site_slice is not None:
        blockers.extend(copy.deepcopy(list(external_site_slice.issues)))
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
            "portable_interface_ir_sha256": (
                None
                if portable_interface is None
                else _canonical_sha256(reviewed["portable_interface_ir"])
            ),
            "external_site_projection_sha256": (
                None
                if external_site_slice is None
                else external_site_slice.projection_sha256
            ),
        },
        "authority": {
            "membership": "exact_machine_unit_membership_v2",
            "machine_boundary": "derived_from_exact_machine_ir_v2",
            "logical_interface": (
                "operator_reviewed_portable_interface_ir_v2"
                if status == "checked"
                and isinstance(portable_interface, PortableComponentInterfaceV2)
                else "operator_reviewed_portable_interface_ir_v1"
                if status == "checked" and portable_interface is not None
                else "operator_reviewed_and_machine_effect_checked_v2"
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
            "portable_interface_header": (
                "portable-interface.h" if portable_interface is not None else None
            ),
            "external_sites": (
                "external-sites.json" if external_site_slice is not None else None
            ),
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
    if portable_interface is not None:
        (output / "portable-interface.h").write_text(
            (
                portable_interface.render_public_header()
                if isinstance(portable_interface, PortableComponentInterfaceV2)
                else portable_interface.render_c_header()
            ),
            encoding="ascii",
        )
    if external_site_slice is not None:
        if isinstance(external_sites, Mapping):
            write_json(
                output / "external-sites.json",
                copy.deepcopy(dict(external_sites)),
            )
        else:
            source = Path(external_sites)  # type: ignore[arg-type]
            source = source / "external-sites.json" if source.is_dir() else source
            (output / "external-sites.json").write_bytes(source.read_bytes())
    write_json(output / "contract.json", result)
    return result


def _portable_interface(
    reviewed: Mapping[str, object],
) -> ComponentInterfaceIRV1 | PortableComponentInterfaceV2 | None:
    payload = reviewed.get("portable_interface_ir")
    if payload is None:
        return None
    try:
        return parse_component_interface(payload)
    except ComponentInterfaceIRError as exc:
        raise ComponentIntentError(f"portable component interface is invalid: {exc}") from exc


def load_component_boundary_review(
    value: Path | str | Mapping[str, object], *, lift_unit_id: str
) -> ComponentBoundaryReview:
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
    synthesized: Mapping[str, object], review: ComponentBoundaryReview | None
) -> dict[str, object]:
    result = copy.deepcopy(dict(synthesized))
    if review is not None:
        for key, value in review.overrides.items():
            if key == "adapter_effects" and isinstance(value, Mapping):
                result[key] = _inherit_adapter_effects(synthesized, value)
            else:
                result[key] = copy.deepcopy(value)
    return finalize_component_interface_spec(result)


def _inherit_adapter_effects(
    synthesized: Mapping[str, object], value: Mapping[str, object]
) -> list[dict[str, object]]:
    _exact_keys(
        value,
        {"inherit_synthesized_except"},
        "component adapter-effect inheritance",
    )
    exclusions = [
        _object(raw, "component adapter-effect exclusion")
        for raw in _array(
            value.get("inherit_synthesized_except"),
            "component adapter-effect exclusions",
        )
    ]
    exclusion_keys: set[tuple[str, str, int]] = set()
    for exclusion in exclusions:
        _exact_keys(
            exclusion,
            {"family", "unit_id", "index"},
            "component adapter-effect exclusion",
        )
        family = exclusion.get("family")
        unit_id = exclusion.get("unit_id")
        index = exclusion.get("index")
        if (
            not isinstance(family, str)
            or not family
            or not isinstance(unit_id, str)
            or not unit_id
            or not isinstance(index, int)
            or isinstance(index, bool)
            or index < 0
        ):
            raise ComponentIntentError(
                "component adapter-effect exclusion is malformed"
            )
        key = (family, unit_id, index)
        if key in exclusion_keys:
            raise ComponentIntentError(
                "component adapter-effect exclusions are duplicated"
            )
        exclusion_keys.add(key)

    inherited = [
        copy.deepcopy(dict(_object(raw, "synthesized adapter effect")))
        for raw in _array(
            synthesized.get("adapter_effects"), "synthesized adapter effects"
        )
    ]
    available = {
        _effect_key(
            _object(row.get("effect"), "synthesized adapter-effect reference")
        )
        for row in inherited
    }
    missing = sorted(exclusion_keys - available)
    if missing:
        raise ComponentIntentError(
            f"component adapter-effect exclusions are stale: {missing}"
        )
    return [
        row
        for row in inherited
        if _effect_key(
            _object(row.get("effect"), "synthesized adapter-effect reference")
        )
        not in exclusion_keys
    ]


def _effect_key(value: Mapping[str, object]) -> tuple[str, str, int]:
    family = value.get("family")
    unit_id = value.get("unit_id")
    index = value.get("index")
    if (
        not isinstance(family, str)
        or not isinstance(unit_id, str)
        or not isinstance(index, int)
        or isinstance(index, bool)
    ):
        raise ComponentIntentError("synthesized adapter-effect reference is malformed")
    return family, unit_id, index


def _load_review(
    value: Path | str | Mapping[str, object], lift_unit_id: str
) -> ComponentBoundaryReview:
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
    return ComponentBoundaryReview(
        lift_unit_id=lift_unit_id,
        accept_derived_machine_boundary=True,
        overrides=copy.deepcopy(dict(overrides)),
    )


def _check_resolution(payload: Mapping[str, object]) -> None:
    if payload.get("format") not in {
        COMPONENT_RESOLUTION_V2_FORMAT,
        COMPONENT_RESOLUTION_SLICE_V1_FORMAT,
    }:
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
