"""Immutable authored and resolved records for composable lift units."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping


ACTIVATION_MODES = frozenset({"draft", "enabled"})
EVIDENCE_PROFILES = frozenset(
    {
        "structural-draft-v1",
        "bounded-equivalence-v1",
        "validation-backed-v1",
    }
)
LIFT_UNIT_KINDS = frozenset({"component", "group"})


@dataclass(frozen=True)
class SourceInputV2:
    files: tuple[PurePosixPath, ...]
    shared_inputs: tuple[PurePosixPath, ...] = ()


@dataclass(frozen=True)
class ComponentIntentV2:
    identity: str
    label: str
    selector: Mapping[str, object]
    evidence_profile: str
    interface_review: PurePosixPath | None
    source: SourceInputV2 | None


@dataclass(frozen=True)
class ComponentGroupIntentV2:
    identity: str
    label: str
    members: tuple[str, ...]
    evidence_profile: str
    interface_review: PurePosixPath | None
    source: SourceInputV2 | None


@dataclass(frozen=True)
class ConfigurationSelectionV2:
    kind: str
    identity: str
    activation: str


@dataclass(frozen=True)
class ComponentConfigurationV2:
    identity: str
    label: str
    selections: tuple[ConfigurationSelectionV2, ...]


@dataclass(frozen=True)
class ComponentCatalogIntentV2:
    program_id: str
    permitted_activation_profiles: tuple[str, ...]
    components: tuple[ComponentIntentV2, ...]
    groups: tuple[ComponentGroupIntentV2, ...]
    configurations: tuple[ComponentConfigurationV2, ...]


@dataclass(frozen=True)
class ComponentBoundaryReviewV2:
    lift_unit_id: str
    accept_derived_machine_boundary: bool
    overrides: Mapping[str, object]
