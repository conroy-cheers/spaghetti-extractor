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
class SourceInput:
    files: tuple[PurePosixPath, ...]
    shared_inputs: tuple[PurePosixPath, ...] = ()
    entry_abi: str = "logical-c-v1"
    entry_symbol: str = ""


@dataclass(frozen=True)
class ComponentEvidencePlan:
    producer: str
    parameter_domains: tuple[Mapping[str, object], ...] = ()


@dataclass(frozen=True)
class ComponentIntent:
    identity: str
    label: str
    selector: Mapping[str, object]
    evidence_profile: str
    interface_review: PurePosixPath | None
    source: SourceInput | None
    verification: ComponentEvidencePlan | None


@dataclass(frozen=True)
class ComponentGroupIntent:
    identity: str
    label: str
    members: tuple[str, ...]
    evidence_profile: str
    interface_review: PurePosixPath | None
    source: SourceInput | None
    verification: ComponentEvidencePlan | None


@dataclass(frozen=True)
class ConfigurationSelection:
    kind: str
    identity: str
    activation: str


@dataclass(frozen=True)
class ComponentConfiguration:
    identity: str
    label: str
    selections: tuple[ConfigurationSelection, ...]


@dataclass(frozen=True)
class ComponentCatalogIntent:
    program_id: str
    permitted_activation_profiles: tuple[str, ...]
    components: tuple[ComponentIntent, ...]
    groups: tuple[ComponentGroupIntent, ...]
    configurations: tuple[ComponentConfiguration, ...]


@dataclass(frozen=True)
class ComponentBoundaryReview:
    lift_unit_id: str
    accept_derived_machine_boundary: bool
    overrides: Mapping[str, object]
