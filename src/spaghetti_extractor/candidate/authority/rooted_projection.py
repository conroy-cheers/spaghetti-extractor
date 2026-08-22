"""Typed root-scoped projection for candidate behavioral acceptance."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from ...artifacts.artifact_set import canonical_sha256_v3
from ...artifacts.io import open_artifact_reader_v3
from ...authority.root_closure import (
    LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3,
    LAUNCH_ROOT_CLOSURE_CODEC_V3,
)
from ...authority.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    semantic_universe_sha256_v3,
)


ROOTED_BEHAVIORAL_PROJECTION_V1_FORMAT = (
    "spaghetti-extractor-rooted-behavioral-projection-v1"
)


class RootedBehavioralProjectionError(ValueError):
    """Root closure and structural inventory do not form one checked scope."""


@dataclass(frozen=True)
class RootedBehavioralProjectionV1:
    root_unit_ids: tuple[str, ...]
    reachable_unit_ids: tuple[str, ...]
    structural_unit_count: int
    root_closure_manifest_sha256: str
    semantic_index_manifest_sha256: str
    semantic_universe_sha256: str
    projection_sha256: str

    def __post_init__(self) -> None:
        if (
            not self.root_unit_ids
            or self.root_unit_ids != tuple(sorted(set(self.root_unit_ids)))
            or not self.reachable_unit_ids
            or self.reachable_unit_ids
            != tuple(sorted(set(self.reachable_unit_ids)))
            or not set(self.root_unit_ids) <= set(self.reachable_unit_ids)
        ):
            raise RootedBehavioralProjectionError(
                "rooted behavioral unit inventories are malformed"
            )
        if (
            not isinstance(self.structural_unit_count, int)
            or isinstance(self.structural_unit_count, bool)
            or self.structural_unit_count < len(self.reachable_unit_ids)
        ):
            raise RootedBehavioralProjectionError(
                "rooted behavioral structural-unit count is malformed"
            )
        for value, label in (
            (self.root_closure_manifest_sha256, "root-closure manifest"),
            (self.semantic_index_manifest_sha256, "semantic-index manifest"),
            (self.semantic_universe_sha256, "semantic universe"),
            (self.projection_sha256, "rooted behavioral projection"),
        ):
            if not _is_digest(value):
                raise RootedBehavioralProjectionError(f"{label} digest is malformed")

    @property
    def reachable_unit_id_set(self) -> frozenset[str]:
        return frozenset(self.reachable_unit_ids)

    def includes_unit(self, unit_id: str) -> bool:
        return unit_id in self.reachable_unit_id_set

    def core_payload(self) -> dict[str, object]:
        return {
            "format": ROOTED_BEHAVIORAL_PROJECTION_V1_FORMAT,
            "root_unit_ids": list(self.root_unit_ids),
            "reachable_unit_ids": list(self.reachable_unit_ids),
            "structural_unit_count": self.structural_unit_count,
            "bindings": {
                "root_closure_manifest_sha256": self.root_closure_manifest_sha256,
                "semantic_index_manifest_sha256": self.semantic_index_manifest_sha256,
                "semantic_universe_sha256": self.semantic_universe_sha256,
            },
        }

    def to_payload(self) -> dict[str, object]:
        return {**self.core_payload(), "projection_sha256": self.projection_sha256}

    @classmethod
    def parse(cls, value: object) -> "RootedBehavioralProjectionV1":
        row = _object(value, "rooted behavioral projection")
        if set(row) != {
            "format",
            "root_unit_ids",
            "reachable_unit_ids",
            "structural_unit_count",
            "bindings",
            "projection_sha256",
        }:
            raise RootedBehavioralProjectionError(
                "rooted behavioral projection fields are noncanonical"
            )
        if row.get("format") != ROOTED_BEHAVIORAL_PROJECTION_V1_FORMAT:
            raise RootedBehavioralProjectionError(
                "rooted behavioral projection format is unsupported"
            )
        bindings = _object(row.get("bindings"), "rooted projection bindings")
        if set(bindings) != {
            "root_closure_manifest_sha256",
            "semantic_index_manifest_sha256",
            "semantic_universe_sha256",
        }:
            raise RootedBehavioralProjectionError(
                "rooted behavioral projection bindings are noncanonical"
            )
        result = cls(
            root_unit_ids=_strings(row.get("root_unit_ids"), "root unit IDs"),
            reachable_unit_ids=_strings(
                row.get("reachable_unit_ids"), "reachable unit IDs"
            ),
            structural_unit_count=row.get("structural_unit_count"),  # type: ignore[arg-type]
            root_closure_manifest_sha256=str(
                bindings.get("root_closure_manifest_sha256")
            ),
            semantic_index_manifest_sha256=str(
                bindings.get("semantic_index_manifest_sha256")
            ),
            semantic_universe_sha256=str(bindings.get("semantic_universe_sha256")),
            projection_sha256=str(row.get("projection_sha256")),
        )
        if result.projection_sha256 != canonical_sha256_v3(result.core_payload()):
            raise RootedBehavioralProjectionError(
                "rooted behavioral projection digest is stale"
            )
        return result


def derive_rooted_behavioral_projection_v1(
    *, root_closure: Path | str, semantic_index: Path | str
) -> RootedBehavioralProjectionV1:
    root_reader = open_artifact_reader_v3(Path(root_closure))
    semantic_reader = open_artifact_reader_v3(Path(semantic_index))
    if root_reader.manifest.artifact_kind != LAUNCH_ROOT_CLOSURE_ARTIFACT_KIND_V3:
        raise RootedBehavioralProjectionError(
            "rooted projection input has the wrong root-closure artifact kind"
        )
    if semantic_reader.manifest.artifact_kind != SEMANTIC_INDEX_ARTIFACT_KIND_V3:
        raise RootedBehavioralProjectionError(
            "rooted projection input has the wrong semantic-index artifact kind"
        )
    root_records = tuple(root_reader.iter_records())
    if len(root_records) != 1:
        raise RootedBehavioralProjectionError(
            "rooted projection requires exactly one root closure"
        )
    root = LAUNCH_ROOT_CLOSURE_CODEC_V3.read(root_records[0]).value
    if root.status != "complete" or not root.authorizing or root.frontier_ids:
        raise RootedBehavioralProjectionError(
            "rooted projection requires a complete frontier-free root closure"
        )
    semantic_records = tuple(
        SEMANTIC_INDEX_CODEC_V3.read(record).value
        for record in semantic_reader.iter_records()
    )
    structural_ids = tuple(sorted(row.record_id for row in semantic_records))
    if not structural_ids or len(set(structural_ids)) != len(structural_ids):
        raise RootedBehavioralProjectionError(
            "rooted projection requires one semantic record per structural unit"
        )
    reachable = set(root.reachable_unit_ids)
    unknown = sorted(reachable - set(structural_ids))
    if unknown:
        raise RootedBehavioralProjectionError(
            f"rooted projection names units outside the structural universe: {unknown[:3]!r}"
        )
    if any(
        edge.source_unit_id not in reachable or edge.target_unit_id not in reachable
        for edge in root.edges
    ):
        raise RootedBehavioralProjectionError(
            "rooted projection contains an edge outside its reachable universe"
        )
    core = {
        "format": ROOTED_BEHAVIORAL_PROJECTION_V1_FORMAT,
        "root_unit_ids": list(root.root_unit_ids),
        "reachable_unit_ids": list(root.reachable_unit_ids),
        "structural_unit_count": len(structural_ids),
        "bindings": {
            "root_closure_manifest_sha256": root_reader.manifest_sha256,
            "semantic_index_manifest_sha256": semantic_reader.manifest_sha256,
            "semantic_universe_sha256": semantic_universe_sha256_v3(
                semantic_records
            ),
        },
    }
    return RootedBehavioralProjectionV1.parse(
        {**core, "projection_sha256": canonical_sha256_v3(core)}
    )


def load_rooted_behavioral_projection_v1(
    value: Path | str | Mapping[str, object],
) -> RootedBehavioralProjectionV1:
    if isinstance(value, Mapping):
        payload: object = value
    else:
        path = Path(value)
        if path.is_dir():
            candidates = sorted(path.glob("*.json"))
            if len(candidates) != 1:
                raise RootedBehavioralProjectionError(
                    "rooted projection directory must contain exactly one JSON artifact"
                )
            path = candidates[0]
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RootedBehavioralProjectionError(
                f"cannot read rooted behavioral projection: {exc}"
            ) from exc
    return RootedBehavioralProjectionV1.parse(payload)


def write_rooted_behavioral_projection_v1(
    path: Path | str, projection: RootedBehavioralProjectionV1
) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(projection.to_payload(), indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise RootedBehavioralProjectionError(f"{description} must be an object")
    return value


def _strings(value: object, description: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise RootedBehavioralProjectionError(f"{description} must be strings")
    return tuple(value)


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


__all__ = [
    "ROOTED_BEHAVIORAL_PROJECTION_V1_FORMAT",
    "RootedBehavioralProjectionError",
    "RootedBehavioralProjectionV1",
    "derive_rooted_behavioral_projection_v1",
    "load_rooted_behavioral_projection_v1",
    "write_rooted_behavioral_projection_v1",
]
