"""Strict parser for operator-authored component v2 intent."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

from .formats import COMPONENT_CATALOG_INTENT_V2_FORMAT
from .model import (
    ACTIVATION_MODES,
    EVIDENCE_PROFILES,
    LIFT_UNIT_KINDS,
    ComponentCatalogIntentV2,
    ComponentConfigurationV2,
    ComponentGroupIntentV2,
    ComponentIntentV2,
    ConfigurationSelectionV2,
    SourceInputV2,
)


_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\Z")
_FORBIDDEN_GENERATED_KEYS = frozenset(
    {
        "artifact_sha256",
        "bindings",
        "blockers",
        "counts",
        "proposal_id",
        "proposal_set_sha256",
        "qualification_sha256",
        "status",
    }
)


class ComponentIntentError(ValueError):
    """Operator-authored component intent is unsafe or ambiguous."""


def load_component_catalog_intent_v2(
    path: Path | str, *, require_references: bool = True
) -> ComponentCatalogIntentV2:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read component intent: {exc}") from exc
    root = _object(payload, "component catalog intent")
    _exact_keys(
        root,
        {
            "format",
            "program_id",
            "permitted_activation_profiles",
            "components",
            "groups",
            "configurations",
        },
        "component catalog intent",
    )
    if root.get("format") != COMPONENT_CATALOG_INTENT_V2_FORMAT:
        raise ComponentIntentError("unsupported component catalog intent format")
    _reject_generated(root, "component catalog intent")

    program_id = _identifier(root.get("program_id"), "program id")
    permitted = tuple(
        _profile(value, "permitted activation profile")
        for value in _array(
            root.get("permitted_activation_profiles"),
            "permitted activation profiles",
        )
    )
    if not permitted or "structural-draft-v1" in permitted:
        raise ComponentIntentError(
            "permitted activation profiles must contain activation-capable profiles only"
        )
    if len(set(permitted)) != len(permitted):
        raise ComponentIntentError("permitted activation profiles are duplicated")

    components = tuple(
        _component(
            _object(value, f"component {index}"),
            source.parent,
            index,
            require_references=require_references,
        )
        for index, value in enumerate(_array(root.get("components"), "components"))
    )
    groups = tuple(
        _group(
            _object(value, f"group {index}"),
            source.parent,
            index,
            require_references=require_references,
        )
        for index, value in enumerate(_array(root.get("groups"), "groups"))
    )
    configurations = tuple(
        _configuration(_object(value, f"configuration {index}"), index)
        for index, value in enumerate(
            _array(root.get("configurations"), "configurations")
        )
    )
    if not components:
        raise ComponentIntentError("component catalog intent has no components")
    _unique((item.identity for item in components), "component")
    _unique((item.identity for item in groups), "group")
    _unique((item.identity for item in configurations), "configuration")
    overlap = {item.identity for item in components} & {item.identity for item in groups}
    if overlap:
        raise ComponentIntentError(
            f"component and group identifiers overlap: {sorted(overlap)}"
        )
    known = {item.identity for item in components} | {item.identity for item in groups}
    for group in groups:
        missing = sorted(set(group.members) - known)
        if missing:
            raise ComponentIntentError(
                f"group {group.identity} references unknown members: {missing}"
            )
        if group.identity in group.members:
            raise ComponentIntentError(f"group {group.identity} contains itself")
    _check_group_cycles(groups)
    component_ids = {item.identity for item in components}
    group_ids = {item.identity for item in groups}
    for configuration in configurations:
        for selection in configuration.selections:
            expected = component_ids if selection.kind == "component" else group_ids
            if selection.identity not in expected:
                raise ComponentIntentError(
                    f"configuration {configuration.identity} selects unknown "
                    f"{selection.kind} {selection.identity}"
                )
            selected = next(
                item
                for item in (*components, *groups)
                if item.identity == selection.identity
            )
            if (
                selection.activation == "enabled"
                and selected.evidence_profile not in permitted
            ):
                raise ComponentIntentError(
                    f"configuration {configuration.identity} enables "
                    f"{selection.identity} with disallowed profile "
                    f"{selected.evidence_profile}"
                )
            if selection.activation == "enabled" and selected.source is None:
                raise ComponentIntentError(
                    f"configuration {configuration.identity} enables "
                    f"{selection.identity} without portable source"
                )
    return ComponentCatalogIntentV2(
        program_id=program_id,
        permitted_activation_profiles=permitted,
        components=components,
        groups=groups,
        configurations=configurations,
    )


def _component(
    row: Mapping[str, object],
    root: Path,
    index: int,
    *,
    require_references: bool,
) -> ComponentIntentV2:
    _exact_keys(
        row,
        {
            "id",
            "label",
            "selector",
            "evidence_profile",
            "interface_review",
            "source",
        },
        f"component {index}",
        optional={"interface_review", "source"},
    )
    return ComponentIntentV2(
        identity=_identifier(row.get("id"), f"component {index} id"),
        label=_string(row.get("label"), f"component {index} label"),
        selector=dict(_object(row.get("selector"), f"component {index} selector")),
        evidence_profile=_profile(
            row.get("evidence_profile"), f"component {index} evidence profile"
        ),
        interface_review=_optional_path(
            row.get("interface_review"),
            root,
            f"component {index} interface review",
            require_exists=require_references,
        ),
        source=_source(
            row.get("source"),
            root,
            f"component {index} source",
            require_references=require_references,
        ),
    )


def _group(
    row: Mapping[str, object],
    root: Path,
    index: int,
    *,
    require_references: bool,
) -> ComponentGroupIntentV2:
    _exact_keys(
        row,
        {
            "id",
            "label",
            "members",
            "evidence_profile",
            "interface_review",
            "source",
        },
        f"group {index}",
        optional={"interface_review", "source"},
    )
    members = tuple(
        _identifier(value, f"group {index} member")
        for value in _array(row.get("members"), f"group {index} members")
    )
    if not members or len(set(members)) != len(members):
        raise ComponentIntentError(f"group {index} members must be nonempty and unique")
    return ComponentGroupIntentV2(
        identity=_identifier(row.get("id"), f"group {index} id"),
        label=_string(row.get("label"), f"group {index} label"),
        members=members,
        evidence_profile=_profile(
            row.get("evidence_profile"), f"group {index} evidence profile"
        ),
        interface_review=_optional_path(
            row.get("interface_review"),
            root,
            f"group {index} interface review",
            require_exists=require_references,
        ),
        source=_source(
            row.get("source"),
            root,
            f"group {index} source",
            require_references=require_references,
        ),
    )


def _configuration(row: Mapping[str, object], index: int) -> ComponentConfigurationV2:
    _exact_keys(row, {"id", "label", "selections"}, f"configuration {index}")
    selections = tuple(
        _selection(_object(value, f"configuration {index} selection"), index)
        for value in _array(row.get("selections"), f"configuration {index} selections")
    )
    if not selections:
        raise ComponentIntentError(f"configuration {index} has no selections")
    keys = [(item.kind, item.identity) for item in selections]
    if len(set(keys)) != len(keys):
        raise ComponentIntentError(f"configuration {index} selections are duplicated")
    return ComponentConfigurationV2(
        identity=_identifier(row.get("id"), f"configuration {index} id"),
        label=_string(row.get("label"), f"configuration {index} label"),
        selections=selections,
    )


def _selection(row: Mapping[str, object], index: int) -> ConfigurationSelectionV2:
    _exact_keys(row, {"kind", "id", "activation"}, f"configuration {index} selection")
    kind = _string(row.get("kind"), "selection kind")
    activation = _string(row.get("activation"), "selection activation")
    if kind not in LIFT_UNIT_KINDS:
        raise ComponentIntentError(f"unsupported selection kind: {kind}")
    if activation not in ACTIVATION_MODES:
        raise ComponentIntentError(f"unsupported selection activation: {activation}")
    return ConfigurationSelectionV2(
        kind=kind,
        identity=_identifier(row.get("id"), "selection id"),
        activation=activation,
    )


def _source(
    value: object,
    root: Path,
    context: str,
    *,
    require_references: bool,
) -> SourceInputV2 | None:
    if value is None:
        return None
    row = _object(value, context)
    _exact_keys(row, {"files", "shared_inputs"}, context, optional={"shared_inputs"})
    files = tuple(
        _path(item, root, f"{context} file", require_exists=require_references)
        for item in _array(row.get("files"), f"{context} files")
    )
    shared = tuple(
        _path(
            item,
            root,
            f"{context} shared input",
            require_exists=require_references,
        )
        for item in _array(row.get("shared_inputs", []), f"{context} shared inputs")
    )
    if not files:
        raise ComponentIntentError(f"{context} has no files")
    if len(set((*files, *shared))) != len((*files, *shared)):
        raise ComponentIntentError(f"{context} paths are duplicated")
    return SourceInputV2(files=files, shared_inputs=shared)


def _check_group_cycles(groups: Sequence[ComponentGroupIntentV2]) -> None:
    group_ids = {item.identity for item in groups}
    edges = {
        item.identity: tuple(member for member in item.members if member in group_ids)
        for item in groups
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identity: str) -> None:
        if identity in visiting:
            raise ComponentIntentError(f"component group cycle contains {identity}")
        if identity in visited:
            return
        visiting.add(identity)
        for member in edges.get(identity, ()):
            visit(member)
        visiting.remove(identity)
        visited.add(identity)

    for identity in sorted(edges):
        visit(identity)


def _reject_generated(value: object, context: str) -> None:
    if isinstance(value, Mapping):
        forbidden = sorted(set(value) & _FORBIDDEN_GENERATED_KEYS)
        if forbidden:
            raise ComponentIntentError(
                f"{context} contains generated fields: {forbidden}"
            )
        for key, child in value.items():
            _reject_generated(child, f"{context}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_generated(child, f"{context}[{index}]")


def _path(
    value: object, root: Path, context: str, *, require_exists: bool
) -> PurePosixPath:
    text = _string(value, context)
    path = PurePosixPath(text)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ComponentIntentError(f"{context} must be a safe relative path")
    if require_exists and not (root / Path(*path.parts)).is_file():
        raise ComponentIntentError(f"{context} does not exist: {path}")
    return path


def _optional_path(
    value: object,
    root: Path,
    context: str,
    *,
    require_exists: bool,
) -> PurePosixPath | None:
    return (
        None
        if value is None
        else _path(value, root, context, require_exists=require_exists)
    )


def _profile(value: object, context: str) -> str:
    profile = _string(value, context)
    if profile not in EVIDENCE_PROFILES:
        raise ComponentIntentError(f"{context} is unsupported: {profile}")
    return profile


def _identifier(value: object, context: str) -> str:
    text = _string(value, context)
    if _IDENTIFIER.fullmatch(text) is None:
        raise ComponentIntentError(f"{context} must be a stable lowercase identifier")
    return text


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{context} must be a nonempty string")
    return value


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ComponentIntentError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{context} must be an array")
    return value


def _exact_keys(
    value: Mapping[str, object],
    allowed: set[str],
    context: str,
    *,
    optional: set[str] = frozenset(),
) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted((allowed - optional) - set(value))
    if unknown or missing:
        raise ComponentIntentError(
            f"{context} keys mismatch: missing={missing}, unknown={unknown}"
        )


def _unique(values: Sequence[str] | object, context: str) -> None:
    rows = list(values)  # type: ignore[arg-type]
    duplicates = sorted({value for value in rows if rows.count(value) > 1})
    if duplicates:
        raise ComponentIntentError(f"duplicate {context} identifiers: {duplicates}")
