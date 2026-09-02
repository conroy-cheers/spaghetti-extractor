"""Content-bound indexes for the clean-cut V5 component inputs."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import (
    BoundaryModelError,
    array,
    canonical,
    digest,
    exact,
    identifier,
    object_,
)
from .binding_intent import ComponentMachineBindingIntentV1
from .formats import (
    COMPONENT_INTERFACE_INDEX_V5_FORMAT,
    COMPONENT_MACHINE_BINDING_INDEX_V5_FORMAT,
)
from .interface_package_v5 import ComponentInterfaceIntentV1


_KINDS = {
    "interface": (
        COMPONENT_INTERFACE_INDEX_V5_FORMAT,
        "interface_intent",
    ),
    "machine_binding": (
        COMPONENT_MACHINE_BINDING_INDEX_V5_FORMAT,
        "binding_intent",
    ),
}


@dataclass(frozen=True)
class ComponentIntentIndexV5:
    kind: str
    status: str
    components: tuple[Mapping[str, object], ...]
    blockers: tuple[Mapping[str, object], ...]
    index_sha256: str

    @classmethod
    def create(
        cls,
        *,
        kind: str,
        components: Sequence[Mapping[str, object]],
        blockers: Sequence[Mapping[str, object]],
    ) -> "ComponentIntentIndexV5":
        try:
            format_name, path_field = _KINDS[kind]
        except KeyError as exc:
            raise BoundaryModelError("component V5 index kind is unsupported") from exc
        normalized_components = tuple(sorted(
            (_component(item, path_field=path_field) for item in components),
            key=lambda item: str(item["component_id"]),
        ))
        component_ids = tuple(str(item["component_id"]) for item in normalized_components)
        if len(component_ids) != len(set(component_ids)):
            raise BoundaryModelError("component V5 index identities are duplicated")
        normalized_blockers = tuple(sorted(
            (_blocker(item) for item in blockers),
            key=lambda item: (str(item["component_id"]), str(item["code"])),
        ))
        blocker_keys = tuple(
            (str(item["component_id"]), str(item["code"]))
            for item in normalized_blockers
        )
        if len(blocker_keys) != len(set(blocker_keys)):
            raise BoundaryModelError("component V5 index blockers are duplicated")
        status = "incomplete" if normalized_blockers else "complete"
        core = {
            "format": format_name,
            "status": status,
            "components": list(normalized_components),
            "blockers": list(normalized_blockers),
        }
        return cls(
            kind,
            status,
            normalized_components,
            normalized_blockers,
            canonical_sha256_v3(core),
        )

    @classmethod
    def parse(cls, value: object, *, kind: str) -> "ComponentIntentIndexV5":
        row = object_(value, "component V5 input index")
        exact(
            row,
            {"format", "status", "components", "blockers", "index_sha256"},
            "component V5 input index",
        )
        if kind not in _KINDS or row["format"] != _KINDS[kind][0]:
            raise BoundaryModelError("component V5 input index format is unsupported")
        result = cls.create(
            kind=kind,
            components=[
                dict(object_(item, f"component V5 index row {index}"))
                for index, item in enumerate(array(row["components"], "components"))
            ],
            blockers=[
                dict(object_(item, f"component V5 blocker {index}"))
                for index, item in enumerate(array(row["blockers"], "blockers"))
            ],
        )
        if row["status"] != result.status:
            raise BoundaryModelError("component V5 input index status is stale")
        if row["index_sha256"] != result.index_sha256:
            raise BoundaryModelError("component V5 input index digest is stale")
        return result

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": _KINDS[self.kind][0],
            "status": self.status,
            "components": [canonical(dict(item)) for item in self.components],
            "blockers": [canonical(dict(item)) for item in self.blockers],
        }
        return {**core, "index_sha256": self.index_sha256}


def load_component_intent_index_v5(
    value: Path | str, *, kind: str
) -> ComponentIntentIndexV5:
    path = Path(value)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BoundaryModelError(f"cannot read component V5 input index: {exc}") from exc
    result = ComponentIntentIndexV5.parse(payload, kind=kind)
    path_field = _KINDS[kind][1]
    for row in result.components:
        child_path = path.parent / str(row[path_field])
        try:
            child = json.loads(child_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise BoundaryModelError(
                f"cannot read indexed component V5 intent {child_path.name!r}: {exc}"
            ) from exc
        parsed = (
            ComponentInterfaceIntentV1.parse(child)
            if kind == "interface"
            else ComponentMachineBindingIntentV1.parse(child)
        )
        if (
            parsed.component_id != row["component_id"]
            or parsed.intent_sha256 != row["intent_sha256"]
        ):
            raise BoundaryModelError(
                f"indexed component V5 intent {child_path.name!r} is stale"
            )
    actual_files = {
        child.name
        for child in path.parent.glob("*.json")
        if child.name != path.name
    }
    listed_files = {str(row[path_field]) for row in result.components}
    if actual_files != listed_files:
        raise BoundaryModelError(
            "component V5 index has missing or unlisted intent files: "
            f"missing={sorted(listed_files - actual_files)}, "
            f"unlisted={sorted(actual_files - listed_files)}"
        )
    return result


def _component(value: Mapping[str, object], *, path_field: str) -> Mapping[str, object]:
    row = object_(value, "component V5 index row")
    exact(row, {"component_id", path_field, "intent_sha256"}, "component V5 index row")
    path = _safe_filename(row[path_field], "component V5 intent filename")
    return canonical({
        "component_id": identifier(row["component_id"], "component V5 index identity"),
        path_field: path,
        "intent_sha256": digest(row["intent_sha256"], "component V5 intent digest"),
    })


def _blocker(value: Mapping[str, object]) -> Mapping[str, object]:
    row = object_(value, "component V5 index blocker")
    exact(row, {"code", "component_id"}, "component V5 index blocker")
    return canonical({
        "code": identifier(row["code"], "component V5 blocker code"),
        "component_id": identifier(row["component_id"], "component V5 blocker identity"),
    })


def _safe_filename(value: object, context: str) -> str:
    if not isinstance(value, str):
        raise BoundaryModelError(f"{context} must be a string")
    path = PurePosixPath(value)
    if len(path.parts) != 1 or path.suffix != ".json" or path.name == "index.json":
        raise BoundaryModelError(f"{context} must be one safe JSON filename")
    return path.name


__all__ = ["ComponentIntentIndexV5", "load_component_intent_index_v5"]
