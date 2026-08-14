"""Resolve components, alternative groups, and active ownership configurations."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Mapping

from ..artifact_formats import COMPONENT_PROPOSAL_SET_FORMAT
from ..util import write_json
from .formats import (
    COMPONENT_CONFIGURATION_RESOLUTION_V2_FORMAT,
    COMPONENT_RESOLUTION_V2_FORMAT,
)
from .intent import ComponentIntentError, load_component_catalog_intent_v2
from .model import ComponentCatalogIntentV2


def resolve_component_catalog_v2(
    *, proposals: Path | str, intent: Path | str, out: Path | str
) -> dict[str, object]:
    proposal_path = Path(proposals)
    try:
        proposal_set = json.loads(proposal_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read component proposals: {exc}") from exc
    if not isinstance(proposal_set, Mapping) or proposal_set.get("format") != COMPONENT_PROPOSAL_SET_FORMAT:
        raise ComponentIntentError("unsupported component proposal-set format")
    _check_proposal_set(proposal_set)
    if proposal_set.get("executes_original_binary") is not False:
        raise ComponentIntentError("component proposal set has invalid runtime authority")
    catalog = load_component_catalog_intent_v2(intent, require_references=False)
    proposals_raw = proposal_set.get("proposals")
    if not isinstance(proposals_raw, list):
        raise ComponentIntentError("component proposal set has no proposal array")
    resolved_components: dict[str, dict[str, object]] = {}
    for component in catalog.components:
        matches = [
            row
            for row in proposals_raw
            if isinstance(row, Mapping) and _proposal_matches(row, component.selector)
        ]
        if len(matches) != 1:
            raise ComponentIntentError(
                f"component {component.identity} resolved to {len(matches)} proposals"
            )
        proposal = matches[0]
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
        bindings = proposal.get("bindings")
        resolved_components[component.identity] = {
            "kind": "component",
            "id": component.identity,
            "label": component.label,
            "proposal_id": proposal.get("id"),
            "proposal_binding_sha256": (
                bindings.get("membership_bindings_sha256")
                if isinstance(bindings, Mapping)
                else None
            ),
            "unit_ids": sorted(unit_ids),
            "evidence_profile": component.evidence_profile,
            "interface_review": (
                None if component.interface_review is None else component.interface_review.as_posix()
            ),
            "source": _source_payload(component.source),
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
        "bindings": copy.deepcopy(dict(proposal_set.get("bindings", {}))),
        "components": [resolved_components[key] for key in sorted(resolved_components)],
        "groups": [resolved_groups[key] for key in sorted(resolved_groups)],
        "configurations": configurations,
    }
    result = {**core, "resolution_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def _resolve_groups(
    catalog: ComponentCatalogIntentV2,
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
        }
        result[identity] = row
        return row

    for identity in sorted(group_intents):
        resolve(identity)
    return result


def _resolve_configuration(
    *,
    catalog: ComponentCatalogIntentV2,
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


def _proposal_matches(proposal: Mapping[str, object], selector: Mapping[str, object]) -> bool:
    allowed = {"entry_rva", "end_rva", "proposal_kind", "contains_rva"}
    unknown = sorted(set(selector) - allowed)
    if unknown:
        raise ComponentIntentError(f"unsupported component selector fields: {unknown}")
    if not selector:
        raise ComponentIntentError("component selector must not be empty")
    membership = proposal.get("membership")
    if not isinstance(membership, Mapping):
        raise ComponentIntentError("component proposal has no membership object")
    for key, expected in selector.items():
        if key == "entry_rva":
            if membership.get("rva_start") != expected:
                return False
        elif key == "end_rva":
            if membership.get("rva_end") != expected:
                return False
        elif key == "proposal_kind":
            proposal_kinds = proposal.get("proposal_kinds")
            if not isinstance(proposal_kinds, list) or expected not in proposal_kinds:
                return False
        else:
            start = membership.get("rva_start")
            end = membership.get("rva_end")
            if (
                not isinstance(expected, int)
                or not isinstance(start, int)
                or not isinstance(end, int)
                or not start <= expected < end
            ):
                return False
    return True


def _source_payload(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    return {
        "files": [path.as_posix() for path in value.files],
        "shared_inputs": [path.as_posix() for path in value.shared_inputs],
    }


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


def _check_proposal_set(payload: Mapping[str, object]) -> None:
    expected = payload.get("proposal_set_sha256")
    if not isinstance(expected, str) or len(expected) != 64:
        raise ComponentIntentError("component proposal set has no canonical self-hash")
    core = copy.deepcopy(dict(payload))
    core.pop("proposal_set_sha256", None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError("component proposal-set self-hash is stale")
