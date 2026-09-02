"""Canonical structural intent for the V5 component lifting workflow.

This file deliberately carries no machine selector, legacy evidence profile,
interface review, or machine-binding path.  Those facts live in the V5
interface and binding packages and are independently content-bound there.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import (
    BoundaryModelError,
    array,
    canonical,
    exact,
    identifier,
    object_,
)
from .formats import COMPONENT_LIFTING_INTENT_V1_FORMAT


_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_ACTIVATIONS = frozenset({"draft", "enabled", "disabled"})
_KINDS = frozenset({"component", "group"})


@dataclass(frozen=True)
class ComponentLiftingIntentV1:
    program_id: str
    components: tuple[Mapping[str, object], ...]
    groups: tuple[Mapping[str, object], ...]
    configurations: tuple[Mapping[str, object], ...]
    intent_sha256: str

    @classmethod
    def create(
        cls,
        *,
        program_id: str,
        components: Sequence[Mapping[str, object]],
        groups: Sequence[Mapping[str, object]],
        configurations: Sequence[Mapping[str, object]],
    ) -> "ComponentLiftingIntentV1":
        normalized_components = tuple(
            _component(item, index) for index, item in enumerate(components)
        )
        component_ids = tuple(str(item["id"]) for item in normalized_components)
        if not component_ids or len(component_ids) != len(set(component_ids)):
            raise BoundaryModelError("component lifting intent identities are empty or duplicated")

        normalized_groups = tuple(
            _group(item, index) for index, item in enumerate(groups)
        )
        group_ids = tuple(str(item["id"]) for item in normalized_groups)
        if len(group_ids) != len(set(group_ids)) or set(group_ids) & set(component_ids):
            raise BoundaryModelError("component lifting group identities are duplicated")
        known_lift_units = set(component_ids) | set(group_ids)
        for group in normalized_groups:
            members = set(str(item) for item in group["members"])
            if not members <= known_lift_units or group["id"] in members:
                raise BoundaryModelError("component lifting group membership is invalid")
        _check_group_cycles(normalized_groups)

        normalized_configurations = tuple(
            _configuration(
                item,
                index,
                component_ids=set(component_ids),
                group_ids=set(group_ids),
            )
            for index, item in enumerate(configurations)
        )
        configuration_ids = tuple(
            str(item["id"]) for item in normalized_configurations
        )
        if not configuration_ids or len(configuration_ids) != len(set(configuration_ids)):
            raise BoundaryModelError("component lifting configuration identities are empty or duplicated")

        core = {
            "format": COMPONENT_LIFTING_INTENT_V1_FORMAT,
            "program_id": identifier(program_id, "component lifting program"),
            "components": list(normalized_components),
            "groups": list(normalized_groups),
            "configurations": list(normalized_configurations),
            "policy": {
                "machine_authority_from_v5_bindings_only": True,
                "operation_symbols_only": True,
                "tests_authorize": False,
            },
        }
        return cls(
            str(core["program_id"]),
            normalized_components,
            normalized_groups,
            normalized_configurations,
            canonical_sha256_v3(core),
        )

    @classmethod
    def parse(cls, value: object) -> "ComponentLiftingIntentV1":
        row = object_(value, "component lifting intent V1")
        exact(
            row,
            {
                "format", "program_id", "components", "groups",
                "configurations", "policy", "intent_sha256",
            },
            "component lifting intent V1",
        )
        if row["format"] != COMPONENT_LIFTING_INTENT_V1_FORMAT:
            raise BoundaryModelError("component lifting intent format is unsupported")
        result = cls.create(
            program_id=str(row["program_id"]),
            components=[
                dict(object_(item, f"component lifting component {index}"))
                for index, item in enumerate(array(row["components"], "components"))
            ],
            groups=[
                dict(object_(item, f"component lifting group {index}"))
                for index, item in enumerate(array(row["groups"], "groups"))
            ],
            configurations=[
                dict(object_(item, f"component lifting configuration {index}"))
                for index, item in enumerate(
                    array(row["configurations"], "configurations")
                )
            ],
        )
        if row["policy"] != result.to_payload()["policy"]:
            raise BoundaryModelError("component lifting intent policy is unsupported")
        if row["intent_sha256"] != result.intent_sha256:
            raise BoundaryModelError("component lifting intent digest is stale")
        return result

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": COMPONENT_LIFTING_INTENT_V1_FORMAT,
            "program_id": self.program_id,
            "components": [canonical(dict(item)) for item in self.components],
            "groups": [canonical(dict(item)) for item in self.groups],
            "configurations": [
                canonical(dict(item)) for item in self.configurations
            ],
            "policy": {
                "machine_authority_from_v5_bindings_only": True,
                "operation_symbols_only": True,
                "tests_authorize": False,
            },
        }
        return {**core, "intent_sha256": self.intent_sha256}


def _component(value: Mapping[str, object], index: int) -> Mapping[str, object]:
    row = object_(value, f"component lifting component {index}")
    allowed = {
        "id", "label", "source", "relation_intent", "induction_intent",
        "proof_classification",
    }
    if not set(row) <= allowed or not {"id", "label"} <= set(row):
        raise BoundaryModelError(f"component lifting component {index} fields are not canonical")
    result: dict[str, object] = {
        "id": identifier(row["id"], "component lifting component"),
        "label": _label(row["label"], "component lifting component label"),
    }
    if "source" in row:
        result["source"] = _source(row["source"], index)
    if "proof_classification" in row:
        classification = row["proof_classification"]
        if classification not in {"machine_overlay", "encapsulated_owned"}:
            raise BoundaryModelError(
                "component lifting proof classification is unsupported"
            )
        result["proof_classification"] = classification
    for field in ("relation_intent", "induction_intent"):
        if field in row:
            result[field] = _relative(row[field], f"component {field}")
    return canonical(result)


def _source(value: object, index: int) -> Mapping[str, object]:
    row = object_(value, f"component lifting source {index}")
    exact(row, {"files", "shared_inputs", "operation_symbols"}, "component source intent")
    files = tuple(_relative(item, "component source file") for item in array(row["files"], "source files"))
    shared = tuple(_relative(item, "component shared input") for item in array(row["shared_inputs"], "shared inputs"))
    if not files or len(set((*files, *shared))) != len(files) + len(shared):
        raise BoundaryModelError("component source paths are empty or duplicated")
    symbols = object_(row["operation_symbols"], "component operation symbols")
    if not symbols:
        raise BoundaryModelError("component operation symbol map is empty")
    normalized_symbols: dict[str, str] = {}
    for operation_id, raw_symbol in symbols.items():
        operation = identifier(operation_id, "component operation symbol id")
        if not isinstance(raw_symbol, str) or _C_IDENTIFIER.fullmatch(raw_symbol) is None:
            raise BoundaryModelError("component operation symbol is not a C identifier")
        normalized_symbols[operation] = raw_symbol
    if len(set(normalized_symbols.values())) != len(normalized_symbols):
        raise BoundaryModelError("component operation symbols are duplicated")
    return {
        "files": list(files),
        "shared_inputs": list(shared),
        "operation_symbols": dict(sorted(normalized_symbols.items())),
    }


def _group(value: Mapping[str, object], index: int) -> Mapping[str, object]:
    row = object_(value, f"component lifting group {index}")
    exact(row, {"id", "label", "members"}, "component lifting group")
    members = tuple(identifier(item, "component group member") for item in array(row["members"], "group members"))
    if not members or len(members) != len(set(members)):
        raise BoundaryModelError("component lifting group membership is invalid")
    return {
        "id": identifier(row["id"], "component lifting group"),
        "label": _label(row["label"], "component lifting group label"),
        "members": list(members),
    }


def _check_group_cycles(groups: Sequence[Mapping[str, object]]) -> None:
    group_ids = {str(row["id"]) for row in groups}
    edges = {
        str(row["id"]): {
            str(member) for member in row["members"] if str(member) in group_ids
        }
        for row in groups
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identity: str) -> None:
        if identity in visiting:
            raise BoundaryModelError("component lifting groups contain a cycle")
        if identity in visited:
            return
        visiting.add(identity)
        for target in edges[identity]:
            visit(target)
        visiting.remove(identity)
        visited.add(identity)

    for identity in sorted(group_ids):
        visit(identity)


def _configuration(
    value: Mapping[str, object],
    index: int,
    *,
    component_ids: set[str],
    group_ids: set[str],
) -> Mapping[str, object]:
    row = object_(value, f"component lifting configuration {index}")
    exact(row, {"id", "label", "selections"}, "component lifting configuration")
    selections: list[Mapping[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for selection_index, raw in enumerate(array(row["selections"], "configuration selections")):
        selection = object_(raw, f"configuration selection {selection_index}")
        exact(selection, {"kind", "id", "activation"}, "configuration selection")
        kind = identifier(selection["kind"], "configuration selection kind")
        identity = identifier(selection["id"], "configuration selection id")
        activation = identifier(selection["activation"], "configuration activation")
        if (
            kind not in _KINDS
            or activation not in _ACTIVATIONS
            or (kind == "component" and identity not in component_ids)
            or (kind == "group" and identity not in group_ids)
            or (kind, identity) in seen
        ):
            raise BoundaryModelError("component configuration selection is invalid")
        seen.add((kind, identity))
        selections.append({"kind": kind, "id": identity, "activation": activation})
    if not selections:
        raise BoundaryModelError("component lifting configuration is empty")
    return {
        "id": identifier(row["id"], "component lifting configuration"),
        "label": _label(row["label"], "component lifting configuration label"),
        "selections": selections,
    }


def _relative(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise BoundaryModelError(f"{context} must be a relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise BoundaryModelError(f"{context} must be a safe relative path")
    return path.as_posix()


def _label(value: object, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BoundaryModelError(f"{context} must be nonempty text")
    return value


__all__ = ["ComponentLiftingIntentV1"]
