"""Derive explicit portability debt from the checked component graph."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .dependency_graph import (
    ComponentDependencyGraphV3,
    read_component_dependency_graph_v3,
)
from .formats import COMPONENT_RETIREMENT_REPORT_V1_FORMAT
from .universal_binding import (
    ComponentMachineBindingV3,
    read_component_machine_binding_v3,
)


class ComponentRetirementError(ValueError):
    """A retirement report input is malformed or stale."""


def build_component_retirement_report_v1(
    *,
    graph: ComponentDependencyGraphV3 | Path | str | Mapping[str, object],
    machine_bindings: Mapping[
        str, ComponentMachineBindingV3 | Path | str | Mapping[str, object]
    ],
    root_component_ids: Sequence[str],
    out: Path | str | None = None,
) -> dict[str, object]:
    checked_graph = (
        graph
        if isinstance(graph, ComponentDependencyGraphV3)
        else read_component_dependency_graph_v3(graph)
    )
    bindings = {
        component_id: (
            value
            if isinstance(value, ComponentMachineBindingV3)
            else read_component_machine_binding_v3(value)
        )
        for component_id, value in machine_bindings.items()
    }
    roots = tuple(sorted(set(root_component_ids)))
    graph_components = {item[0] for item in checked_graph.contracts}
    unknown_roots = sorted(set(roots) - graph_components)
    if unknown_roots:
        raise ComponentRetirementError(
            f"retirement roots reference unknown components: {unknown_roots!r}"
        )
    reverse = {
        str(row.get("provider_component_id")): row
        for row in checked_graph.reverse_dependencies
    }
    implementation_by_component = {
        component_id: (implementation_id, kind, digest)
        for component_id, implementation_id, kind, digest
        in checked_graph.implementations
    }
    issues: list[dict[str, object]] = []
    if checked_graph.status != "checked":
        issues.append(
            {
                "status": (
                    "violated"
                    if checked_graph.status == "violated"
                    else "incomplete"
                ),
                "code": "component_dependency_graph_not_checked",
            }
        )
    components = []
    retained_units: set[str] = set()
    retired_units: set[str] = set()
    for component_id in sorted(graph_components):
        implementation = implementation_by_component.get(component_id)
        binding = bindings.get(component_id)
        consumers = list(reverse.get(component_id, {}).get("consumers", []))
        is_root = component_id in roots
        kind = None if implementation is None else implementation[1]
        if kind in {"portable_c", "pinned_binary", "machine_ir"} and binding is None:
            issues.append(
                {
                    "status": "incomplete",
                    "code": "structural_component_binding_missing",
                    "component_id": component_id,
                }
            )
        unit_ids = () if binding is None else binding.unit_ids
        retirable = (
            kind in {"pinned_binary", "machine_ir"}
            and not is_root
            and not consumers
            and binding is not None
            and binding.authorizing
        )
        if retirable:
            retired_units.update(unit_ids)
        else:
            retained_units.update(unit_ids)
        components.append(
            {
                "component_id": component_id,
                "implementation_kind": kind,
                "root": is_root,
                "consumer_count": len(consumers),
                "consumers": consumers,
                "unit_ids": list(unit_ids),
                "retirable": retirable,
                "next_action": (
                    None
                    if kind not in {"pinned_binary", "machine_ir"} or retirable
                    else "replace or remove every listed consumer before retiring this dependency"
                ),
            }
        )
    overlap = retained_units & retired_units
    if overlap:
        issues.append(
            {
                "status": "violated",
                "code": "retained_and_retired_unit_overlap",
                "unit_ids": sorted(overlap),
            }
        )
    status = (
        "violated"
        if any(item["status"] == "violated" for item in issues)
        else "incomplete"
        if issues
        else "checked"
    )
    core: dict[str, object] = {
        "format": COMPONENT_RETIREMENT_REPORT_V1_FORMAT,
        "status": status,
        "graph_sha256": checked_graph.graph_sha256,
        "root_component_ids": list(roots),
        "components": components,
        "retained_unit_ids": sorted(retained_units),
        "retired_unit_ids": sorted(retired_units),
        "counts": {
            "components": len(components),
            "pinned_dependencies": sum(
                row["implementation_kind"] == "pinned_binary" for row in components
            ),
            "machine_ir_components": sum(
                row["implementation_kind"] == "machine_ir" for row in components
            ),
            "retirable_components": sum(bool(row["retirable"]) for row in components),
            "retained_units": len(retained_units),
            "retired_units": len(retired_units),
        },
        "issues": sorted(
            issues,
            key=lambda item: (
                str(item.get("status", "")), str(item.get("code", "")),
                str(item.get("component_id", "")),
            ),
        ),
        "policy": {
            "diagnostic_only": True,
            "retirement_requires_no_consumers_and_no_root": True,
            "retirement_never_authorizes_execution": True,
            "original_binary_executed": False,
        },
    }
    result = {**core, "report_sha256": canonical_sha256_v3(core)}
    if out is not None:
        path = Path(out)
        if path.suffix != ".json":
            path.mkdir(parents=True, exist_ok=True)
            path = path / "component-retirement-report-v1.json"
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return result


__all__ = [
    "ComponentRetirementError",
    "build_component_retirement_report_v1",
]
