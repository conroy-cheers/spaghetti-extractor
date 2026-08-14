"""Shared data model and primitives for component discovery."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import (
    COMPONENT_PROPOSAL_SET_FORMAT,
    MACHINE_IR_FORMAT,
    RECONSTRUCTION_PLAN_FORMAT,
)

PROPOSAL_SET_FORMAT = COMPONENT_PROPOSAL_SET_FORMAT
MACHINE_IR_MANIFEST_FILENAME = "machine-ir-manifest.json"
MACHINE_IR_FILENAME = "machine-ir.jsonl"
_EVIDENCE_SAMPLE_LIMIT = 1
_INTERFACE_ITEM_LIMIT = 4
_ALTERNATIVE_SAMPLE_LIMIT = 32


class ComponentDiscoveryError(ValueError):
    """Discovery inputs are malformed, stale, or internally inconsistent."""


@dataclass(frozen=True)
class _Inputs:
    manifest_path: Path
    ir_path: Path
    plan_path: Path
    manifest: dict[str, Any]
    plan: dict[str, Any]
    units: tuple[dict[str, Any], ...]
    by_id: dict[str, dict[str, Any]]
    by_rva: dict[int, str]
    cluster_by_unit: dict[str, tuple[str, ...]]
    clusters: dict[str, tuple[str, ...]]
    ir_sha256: str
    manifest_sha256: str
    plan_file_sha256: str
    unit_hint_facts: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class _Edge:
    kind: str
    source: str
    target: str | None
    target_rva: int | None
    event_index: int | None = None
    certificate_id: str | None = None

    def payload(self, index: int) -> dict[str, Any]:
        result: dict[str, Any] = {
            "index": index,
            "id": "component-edge:" + _canonical_sha256(
                {
                    "kind": self.kind,
                    "source": self.source,
                    "target": self.target,
                    "target_rva": self.target_rva,
                    "event_index": self.event_index,
                    "certificate_id": self.certificate_id,
                }
            )[:20],
            "kind": self.kind,
            "source_unit_id": self.source,
        }
        if self.target is not None:
            result["target_unit_id"] = self.target
        if self.target_rva is not None:
            result["target_rva"] = self.target_rva
        if self.event_index is not None:
            result["event_index"] = self.event_index
        if self.certificate_id is not None:
            result["certificate_id"] = self.certificate_id
        return result


@dataclass
class _Candidate:
    members: frozenset[str]
    seed_ids: set[str] = field(default_factory=set)
    kinds: set[str] = field(default_factory=set)
    history: list[dict[str, Any]] = field(default_factory=list)
    extra_blockers: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _Graph:
    edges: tuple[_Edge, ...]
    outgoing: dict[str, tuple[_Edge, ...]]
    incoming: dict[str, tuple[_Edge, ...]]
    control_outgoing: dict[str, tuple[_Edge, ...]]
    roots: tuple[str, ...]
    indirect: dict[str, dict[str, Any]]
    scc_by_unit: dict[str, str]
    sccs: dict[str, tuple[str, ...]]


def _issue(
    inputs: _Inputs,
    unit_id: str,
    *,
    category: str,
    message: str,
    remediation: str,
    field: str = "membership",
    expected: Any = None,
    observed: Any = None,
) -> dict[str, Any]:
    core = {
        "status": "incomplete",
        "category": category,
        "severity": "blocker",
        "message": message,
        "source_location": _location(inputs, unit_id, field=field),
        "expected": expected,
        "observed": observed,
        "remediation": {
            "action": category.replace("_", "-"),
            "details": remediation,
        },
    }
    return {"id": "component-gap:" + _canonical_sha256(core)[:20], **core}


def _location(inputs: _Inputs, unit_id: str, *, field: str | None = None) -> dict[str, Any]:
    start, end = _unit_span(inputs.by_id[unit_id])
    result = {
        "artifact": str(inputs.ir_path),
        "unit_id": unit_id,
        "rva_start": start,
        "rva_end": end,
    }
    if field is not None:
        result["field"] = field
    return result


def _noncontiguous(spans: Sequence[tuple[int, int]]) -> bool:
    ordered = sorted(spans)
    return any(left[1] != right[0] for left, right in zip(ordered, ordered[1:]))


def _unique_dicts(values: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    unique = {_canonical_sha256(value): copy.deepcopy(dict(value)) for value in values}
    return [unique[key] for key in sorted(unique)]


def _evidence_summary(
    values: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    evidence = _unique_dicts(
        {
            key: copy.deepcopy(value)
            for key, value in item.items()
            if key != "source_location"
        }
        for item in values
    )
    return {
        "location_source": "graph_facts.nodes_by_unit_id",
        "evidence": evidence[:_EVIDENCE_SAMPLE_LIMIT],
        "evidence_count": len(evidence),
        "evidence_truncated": len(evidence) > _EVIDENCE_SAMPLE_LIMIT,
    }


def _unit_binding(unit: Mapping[str, Any]) -> dict[str, Any]:
    source = unit.get("source", {})
    source = source if isinstance(source, Mapping) else {}
    return {
        "unit_id": str(unit.get("id", "")),
        "contract_sha256": source.get("contract_sha256"),
        "instruction_bytes_sha256": source.get("instruction_bytes_sha256"),
    }


def _ordered_unit_ids(inputs: _Inputs) -> list[str]:
    return sorted(inputs.by_id, key=lambda value: _unit_key(inputs.by_id[value]))


def _unit_key(unit: Mapping[str, Any]) -> tuple[int, int, str]:
    start, end = _unit_span(unit)
    return start, end, str(unit.get("id", ""))


def _unit_span(unit: Mapping[str, Any]) -> tuple[int, int]:
    source = _mapping(unit.get("source"), "machine IR unit source")
    original = _mapping(source.get("original"), "machine IR original source")
    start = original.get("rva_start")
    end = original.get("rva_end")
    if not isinstance(start, int) or not isinstance(end, int):
        raise ComponentDiscoveryError("machine IR unit has no exact original RVA span")
    return start, end


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ComponentDiscoveryError(f"{label} must be an object")
    return value


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
