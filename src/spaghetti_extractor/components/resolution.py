"""Resolve components, alternative groups, and active ownership configurations."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Mapping

from ..util import write_json
from .formats import (
    COMPONENT_CONFIGURATION_RESOLUTION_V2_FORMAT,
    COMPONENT_RESOLUTION_SLICE_V1_FORMAT,
    COMPONENT_RESOLUTION_V2_FORMAT,
)
from .intent import ComponentIntentError, load_component_catalog_intent
from .model import ComponentCatalogIntent
from .proposal_package import load_component_proposal_package_v2
from .proposal_selection import (
    load_component_proposal_selection_v1,
    proposal_matches,
    select_component_proposals,
)


def resolve_component_catalog(
    *, proposals: Path | str, intent: Path | str, out: Path | str
) -> dict[str, object]:
    try:
        proposal_package = load_component_proposal_package_v2(proposals)
    except ValueError as exc:
        raise ComponentIntentError(f"cannot read component proposals: {exc}") from exc
    catalog = load_component_catalog_intent(intent, require_references=False)
    selected = select_component_proposals(package=proposal_package, catalog=catalog)
    return _resolve_component_catalog(
        catalog=catalog,
        selected=selected,
        bindings=proposal_package.index.get("bindings", {}),
        out=out,
    )


def resolve_component_catalog_from_selection(
    *, selection: Path | str, intent: Path | str, out: Path | str
) -> dict[str, object]:
    selected_input = load_component_proposal_selection_v1(selection)
    catalog = load_component_catalog_intent(intent, require_references=False)
    if selected_input.program_id != catalog.program_id:
        raise ComponentIntentError("component proposal selection has wrong program ID")
    expected_ids = {component.identity for component in catalog.components}
    if set(selected_input.proposals) != expected_ids:
        raise ComponentIntentError("component proposal selection inventory is stale")
    for component in catalog.components:
        proposal = selected_input.proposals[component.identity]
        if not proposal_matches(proposal, component.selector):
            raise ComponentIntentError(
                f"component {component.identity} selected proposal contradicts intent"
            )
    return _resolve_component_catalog(
        catalog=catalog,
        selected=selected_input.proposals,
        bindings=selected_input.bindings,
        out=out,
    )


def slice_component_resolution(
    *,
    resolution: Path | str | Mapping[str, object],
    lift_unit_id: str,
    out: Path | str,
) -> dict[str, object]:
    """Emit the stable resolution dependency needed by one lift unit."""

    payload = _load_resolution(resolution)
    matches = [
        (field, copy.deepcopy(dict(row)))
        for field in ("components", "groups")
        for row in _array(payload.get(field), f"resolved {field}")
        if isinstance(row, Mapping) and row.get("id") == lift_unit_id
    ]
    if len(matches) != 1:
        raise ComponentIntentError(
            f"lift unit {lift_unit_id!r} resolved to {len(matches)} definitions"
        )
    field, lift_unit = matches[0]
    core = {
        "format": COMPONENT_RESOLUTION_SLICE_V1_FORMAT,
        "status": "checked",
        "program_id": payload["program_id"],
        "executes_original_binary": False,
        "permitted_activation_profiles": copy.deepcopy(
            payload["permitted_activation_profiles"]
        ),
        "bindings": copy.deepcopy(payload["bindings"]),
        "components": [lift_unit] if field == "components" else [],
        "groups": [lift_unit] if field == "groups" else [],
        "configurations": [],
    }
    result = {**core, "resolution_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def _resolve_component_catalog(
    *,
    catalog: ComponentCatalogIntent,
    selected: Mapping[str, Mapping[str, object]],
    bindings: object,
    out: Path | str,
) -> dict[str, object]:
    resolved_components: dict[str, dict[str, object]] = {}
    for component in catalog.components:
        proposal = selected[component.identity]
        membership = proposal.get("membership")
        if not isinstance(membership, Mapping):
            raise ComponentIntentError(
                f"component {component.identity} proposal has no membership"
            )
        unit_ids = membership.get("unit_ids")
        if (
            not isinstance(unit_ids, list)
            or not unit_ids
            or any(not isinstance(value, str) or not value for value in unit_ids)
        ):
            raise ComponentIntentError(
                f"component {component.identity} proposal has invalid unit IDs"
            )
        if len(set(unit_ids)) != len(unit_ids):
            raise ComponentIntentError(
                f"component {component.identity} proposal repeats machine units"
            )
        proposal_bindings = proposal.get("bindings")
        resolved_components[component.identity] = {
            "kind": "component",
            "id": component.identity,
            "label": component.label,
            "proposal_id": proposal.get("id"),
            "proposal_binding_sha256": (
                proposal_bindings.get("membership_bindings_sha256")
                if isinstance(proposal_bindings, Mapping)
                else None
            ),
            "unit_ids": sorted(unit_ids),
            "evidence_profile": component.evidence_profile,
            "interface_review": (
                None if component.interface_review is None else component.interface_review.as_posix()
            ),
            "source": _source_payload(component.source),
            "verification": _verification_payload(component.verification),
        }
    resolved_groups = _resolve_groups(catalog, resolved_components)
    configurations = [
        _resolve_configuration(
            catalog=catalog,
            configuration=configuration,
            components=resolved_components,
            groups=resolved_groups,
        )
        for configuration in catalog.configurations
    ]
    core = {
        "format": COMPONENT_RESOLUTION_V2_FORMAT,
        "status": "checked",
        "program_id": catalog.program_id,
        "executes_original_binary": False,
        "permitted_activation_profiles": list(catalog.permitted_activation_profiles),
        "bindings": copy.deepcopy(
            dict(bindings) if isinstance(bindings, Mapping) else {}
        ),
        "components": [resolved_components[key] for key in sorted(resolved_components)],
        "groups": [resolved_groups[key] for key in sorted(resolved_groups)],
        "configurations": configurations,
    }
    result = {**core, "resolution_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def _resolve_groups(
    catalog: ComponentCatalogIntent,
    components: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    group_intents = {item.identity: item for item in catalog.groups}
    result: dict[str, dict[str, object]] = {}

    def resolve(identity: str) -> dict[str, object]:
        if identity in result:
            return result[identity]
        group = group_intents[identity]
        unit_ids: set[str] = set()
        leaf_ids: set[str] = set()
        for member in group.members:
            if member in components:
                unit_ids.update(str(value) for value in components[member]["unit_ids"])
                leaf_ids.add(member)
            else:
                nested = resolve(member)
                unit_ids.update(str(value) for value in nested["unit_ids"])
                leaf_ids.update(str(value) for value in nested["leaf_component_ids"])
        row = {
            "kind": "group",
            "id": group.identity,
            "label": group.label,
            "members": list(group.members),
            "leaf_component_ids": sorted(leaf_ids),
            "unit_ids": sorted(unit_ids),
            "evidence_profile": group.evidence_profile,
            "interface_review": (
                None if group.interface_review is None else group.interface_review.as_posix()
            ),
            "source": _source_payload(group.source),
            "verification": _verification_payload(group.verification),
        }
        result[identity] = row
        return row

    for identity in sorted(group_intents):
        resolve(identity)
    return result


def _resolve_configuration(
    *,
    catalog: ComponentCatalogIntent,
    configuration: object,
    components: Mapping[str, Mapping[str, object]],
    groups: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    selections = []
    owners: dict[str, str] = {}
    for selection in configuration.selections:  # type: ignore[attr-defined]
        unit = (
            components[selection.identity]
            if selection.kind == "component"
            else groups[selection.identity]
        )
        overlaps = sorted(set(str(value) for value in unit["unit_ids"]) & set(owners))
        if overlaps:
            conflicts = sorted({owners[value] for value in overlaps})
            raise ComponentIntentError(
                f"configuration {configuration.identity} overlaps {selection.identity} "
                f"with {conflicts} at units {overlaps[:8]}"
            )
        for unit_id in unit["unit_ids"]:
            owners[str(unit_id)] = selection.identity
        selections.append(
            {
                "kind": selection.kind,
                "id": selection.identity,
                "activation": selection.activation,
                "evidence_profile": unit["evidence_profile"],
                "unit_ids": copy.deepcopy(unit["unit_ids"]),
                "source": copy.deepcopy(unit.get("source")),
            }
        )
    enabled = [row for row in selections if row["activation"] == "enabled"]
    core = {
        "format": COMPONENT_CONFIGURATION_RESOLUTION_V2_FORMAT,
        "id": configuration.identity,  # type: ignore[attr-defined]
        "label": configuration.label,  # type: ignore[attr-defined]
        "status": "checked",
        "selections": selections,
        "enabled_lift_unit_ids": sorted(str(row["id"]) for row in enabled),
        "owned_unit_ids": sorted(owners),
        "unit_owners": dict(sorted(owners.items())),
    }
    return {**core, "configuration_sha256": _canonical_sha256(core)}


def _source_payload(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "files": [path.as_posix() for path in value.files],
        "shared_inputs": [path.as_posix() for path in value.shared_inputs],
        "entry": {
            "abi": value.entry_abi,
            "symbol": value.entry_symbol,
        },
    }


def _verification_payload(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "producer": value.producer,
        "parameter_domains": [copy.deepcopy(dict(row)) for row in value.parameter_domains],
        "cases": [copy.deepcopy(dict(row)) for row in value.cases],
    }


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


def _load_resolution(
    value: Path | str | Mapping[str, object],
) -> dict[str, object]:
    if isinstance(value, Mapping):
        payload = copy.deepcopy(dict(value))
    else:
        try:
            loaded = json.loads(Path(value).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ComponentIntentError(f"cannot read component resolution: {exc}") from exc
        if not isinstance(loaded, Mapping):
            raise ComponentIntentError("component resolution must be an object")
        payload = copy.deepcopy(dict(loaded))
    if payload.get("format") != COMPONENT_RESOLUTION_V2_FORMAT:
        raise ComponentIntentError("unsupported component resolution format")
    expected = payload.get("resolution_sha256")
    core = copy.deepcopy(payload)
    core.pop("resolution_sha256", None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError("component resolution self-hash is stale")
    return payload


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{description} must be an array")
    return value
