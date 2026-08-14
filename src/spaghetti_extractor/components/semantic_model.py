"""Data model for operator-authored semantic components."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class SemanticComponentError(ValueError):
    """Semantic component inputs are structurally malformed."""


@dataclass(frozen=True)
class LogicalInterface:
    status: str
    parameters: tuple[dict[str, Any], ...]
    results: tuple[dict[str, Any], ...]
    objects: tuple[dict[str, Any], ...]
    persistent_state: tuple[dict[str, Any], ...]
    services: tuple[dict[str, Any], ...]
    preconditions: tuple[dict[str, Any], ...]
    postconditions: tuple[dict[str, Any], ...]
    observations: tuple[dict[str, Any], ...]

    def payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "authority": "operator_proposal_not_machine_truth",
            "parameters": copy.deepcopy(list(self.parameters)),
            "results": copy.deepcopy(list(self.results)),
            "objects": copy.deepcopy(list(self.objects)),
            "persistent_state": copy.deepcopy(list(self.persistent_state)),
            "services": copy.deepcopy(list(self.services)),
            "preconditions": copy.deepcopy(list(self.preconditions)),
            "postconditions": copy.deepcopy(list(self.postconditions)),
            "observations": copy.deepcopy(list(self.observations)),
        }


@dataclass(frozen=True)
class ComponentDeclaration:
    identity: str
    label: str
    purpose: str
    kind: str
    sharing: str
    expected_reachability: str
    unit_ids: tuple[str, ...]
    cluster_ids: tuple[str, ...]
    child_ids: tuple[str, ...]
    component_calls: tuple[dict[str, Any], ...]
    logical_interface: LogicalInterface
    refinement_status: str
    refinement_stages: tuple[dict[str, Any], ...]
    emission_policy: str
    emission_symbol: str | None
    evidence: tuple[dict[str, Any], ...]
    assumptions: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class _MachineInputs:
    manifest_path: Path
    ir_path: Path
    manifest: dict[str, Any]
    units: tuple[dict[str, Any], ...]
    units_by_id: dict[str, dict[str, Any]]
    units_by_rva: dict[int, dict[str, Any]]
