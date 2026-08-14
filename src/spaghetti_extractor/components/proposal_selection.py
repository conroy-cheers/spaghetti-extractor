"""Content-stable selected-proposal boundary for the component DAG."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..util import json_dumps, write_json
from .formats import COMPONENT_PROPOSAL_SELECTION_V1_FORMAT
from .intent import ComponentIntentError, load_component_catalog_intent
from .model import ComponentCatalogIntent
from .proposal_package import (
    ComponentProposalPackageV2,
    load_component_proposal_package_v2,
)


@dataclass(frozen=True)
class SelectedComponentProposalsV1:
    program_id: str
    bindings: Mapping[str, Any]
    proposals: Mapping[str, Mapping[str, Any]]


def write_component_proposal_selection_v1(
    *, proposals: Path | str, intent: Path | str, out: Path | str
) -> dict[str, Any]:
    """Resolve authored selectors and emit checked resolution projections."""

    try:
        package = load_component_proposal_package_v2(proposals)
    except ValueError as exc:
        raise ComponentIntentError(f"cannot read component proposals: {exc}") from exc
    catalog = load_component_catalog_intent(intent, require_references=False)
    selected = select_component_proposals(package=package, catalog=catalog)
    core = {
        "format": COMPONENT_PROPOSAL_SELECTION_V1_FORMAT,
        "status": "checked",
        "authority": {
            "class": "checked_component_proposal_selection",
            "can_authorize_replacement": False,
        },
        "executes_original_binary": False,
        "program_id": catalog.program_id,
        "bindings": copy.deepcopy(dict(package.index.get("bindings", {}))),
        "selections": [
            {
                "component_id": component.identity,
                "selector": copy.deepcopy(dict(component.selector)),
                "proposal": _resolution_projection(selected[component.identity]),
            }
            for component in catalog.components
        ],
    }
    result = {**core, "selection_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def load_component_proposal_selection_v1(
    path: Path | str,
) -> SelectedComponentProposalsV1:
    payload = _read_object(Path(path), "component proposal selection")
    if payload.get("format") != COMPONENT_PROPOSAL_SELECTION_V1_FORMAT:
        raise ComponentIntentError("unsupported component proposal selection")
    expected = payload.get("selection_sha256")
    core = copy.deepcopy(payload)
    core.pop("selection_sha256", None)
    if not _digest(expected) or expected != _canonical_sha256(core):
        raise ComponentIntentError("component proposal selection self-hash is stale")
    if payload.get("status") != "checked" or payload.get(
        "executes_original_binary"
    ) is not False:
        raise ComponentIntentError("component proposal selection is not static-checked")
    authority = payload.get("authority")
    if not isinstance(authority, Mapping) or authority.get(
        "can_authorize_replacement"
    ) is not False:
        raise ComponentIntentError("component proposal selection grants authority")
    program_id = payload.get("program_id")
    bindings = payload.get("bindings")
    rows = payload.get("selections")
    if (
        not isinstance(program_id, str)
        or not program_id
        or not isinstance(bindings, Mapping)
        or not isinstance(rows, list)
        or not rows
    ):
        raise ComponentIntentError("component proposal selection is malformed")
    proposals: dict[str, Mapping[str, Any]] = {}
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise ComponentIntentError(f"selected proposal {index} is not an object")
        component_id = raw.get("component_id")
        selector = raw.get("selector")
        proposal = raw.get("proposal")
        if (
            not isinstance(component_id, str)
            or not component_id
            or component_id in proposals
            or not isinstance(selector, Mapping)
            or not isinstance(proposal, Mapping)
        ):
            raise ComponentIntentError(
                f"selected proposal {index} is stale or contradictory"
            )
        _validate_resolution_projection(proposal, index=index)
        if not proposal_matches(proposal, selector):
            raise ComponentIntentError(
                f"selected proposal {index} is stale or contradictory"
            )
        proposals[component_id] = copy.deepcopy(dict(proposal))
    return SelectedComponentProposalsV1(
        program_id=program_id,
        bindings=copy.deepcopy(dict(bindings)),
        proposals=proposals,
    )


def select_component_proposals(
    *, package: ComponentProposalPackageV2, catalog: ComponentCatalogIntent
) -> dict[str, dict[str, Any]]:
    raw_proposals = package.index.get("proposals")
    if not isinstance(raw_proposals, list):
        raise ComponentIntentError("component proposal index has no proposal array")
    result: dict[str, dict[str, Any]] = {}
    for component in catalog.components:
        matches = [
            row
            for row in raw_proposals
            if isinstance(row, Mapping) and proposal_matches(row, component.selector)
        ]
        if len(matches) != 1:
            raise ComponentIntentError(
                f"component {component.identity} resolved to {len(matches)} proposals"
            )
        proposal_id = matches[0].get("id")
        if not isinstance(proposal_id, str):
            raise ComponentIntentError(
                f"component {component.identity} proposal has no identity"
            )
        try:
            proposal = package.get_proposal(proposal_id)
        except ValueError as exc:
            raise ComponentIntentError(
                f"component {component.identity} proposal is stale: {exc}"
            ) from exc
        if not proposal_matches(proposal, component.selector):
            raise ComponentIntentError(
                f"component {component.identity} selected proposal contradicts its index"
            )
        result[component.identity] = proposal
    return result


def proposal_matches(
    proposal: Mapping[str, object], selector: Mapping[str, object]
) -> bool:
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
            kinds = proposal.get("proposal_kinds")
            if not isinstance(kinds, list) or expected not in kinds:
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


def _resolution_projection(proposal: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only checked fields consumed by component resolution."""

    return {
        "id": proposal.get("id"),
        "proposal_kinds": copy.deepcopy(proposal.get("proposal_kinds")),
        "membership": copy.deepcopy(proposal.get("membership")),
        "bindings": {
            "membership_bindings_sha256": (
                proposal.get("bindings", {}).get("membership_bindings_sha256")
                if isinstance(proposal.get("bindings"), Mapping)
                else None
            )
        },
    }


def _validate_resolution_projection(
    proposal: Mapping[str, Any], *, index: int
) -> None:
    if set(proposal) != {"id", "proposal_kinds", "membership", "bindings"}:
        raise ComponentIntentError(
            f"selected proposal {index} has unexpected resolution fields"
        )
    identity = proposal.get("id")
    kinds = proposal.get("proposal_kinds")
    membership = proposal.get("membership")
    bindings = proposal.get("bindings")
    if not isinstance(identity, str) or not identity:
        raise ComponentIntentError(f"selected proposal {index} has no identity")
    if (
        not isinstance(kinds, list)
        or not kinds
        or any(not isinstance(value, str) or not value for value in kinds)
        or len(set(kinds)) != len(kinds)
    ):
        raise ComponentIntentError(f"selected proposal {index} has invalid kinds")
    if not isinstance(membership, Mapping):
        raise ComponentIntentError(f"selected proposal {index} has no membership")
    unit_ids = membership.get("unit_ids")
    start = membership.get("rva_start")
    end = membership.get("rva_end")
    if (
        not isinstance(unit_ids, list)
        or not unit_ids
        or any(not isinstance(value, str) or not value for value in unit_ids)
        or len(set(unit_ids)) != len(unit_ids)
        or membership.get("unit_count") != len(unit_ids)
        or not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or end <= start
        or not isinstance(membership.get("noncontiguous"), bool)
    ):
        raise ComponentIntentError(
            f"selected proposal {index} has invalid membership"
        )
    if (
        not isinstance(bindings, Mapping)
        or set(bindings) != {"membership_bindings_sha256"}
        or not _digest(bindings.get("membership_bindings_sha256"))
    ):
        raise ComponentIntentError(
            f"selected proposal {index} has invalid membership binding"
        )


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="ascii")
        value = json.loads(text)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ComponentIntentError(f"{label} must be an object")
    if text != json_dumps(value) + "\n":
        raise ComponentIntentError(f"{label} is not canonical compact JSON")
    return value


def _digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json_dumps(value).encode("ascii")).hexdigest()


__all__ = [
    "SelectedComponentProposalsV1",
    "load_component_proposal_selection_v1",
    "proposal_matches",
    "select_component_proposals",
    "write_component_proposal_selection_v1",
]
