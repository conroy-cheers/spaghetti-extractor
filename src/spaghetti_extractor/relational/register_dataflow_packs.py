from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from ..errors import StageAInputError
from .analyses.dataflow import parse_stable_dataflow_graph
from .analyses.dataflow_schedule import stable_dataflow_schedule
from .register_dataflow_artifact import parse_register_transfer_table
from .register_dataflow_formats import (
    REGISTER_DATAFLOW_PACK_INPUT_FORMAT,
    REGISTER_DATAFLOW_PACK_MANIFEST_FORMAT,
    parse_register_dataflow_pack_input,
    parse_register_dataflow_pack_manifest,
)
from .register_transfer_core import parse_register_transfer_programs


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class RegisterDataflowPackProjection:
    manifest: dict[str, Any]
    inputs: dict[str, dict[str, Any]]
    transfer_context: dict[str, Any] | None = None


def _validate_component_semantics(
    *,
    components: tuple[Any, ...],
    transfer_by_region: Mapping[str, Mapping[str, Any]],
    edges: tuple[dict[str, Any], ...],
) -> None:
    edge_pairs = {
        (str(edge["source_id"]), str(edge["target_id"])) for edge in edges
    }
    for component in components:
        members = set(component.region_ids)
        internal_edges = sorted(
            (source, target)
            for source, target in edge_pairs
            if source in members and target in members
        )
        incoming_edges = sorted(
            (source, target)
            for source, target in edge_pairs
            if source not in members and target in members
        )
        outgoing_edges = sorted(
            (source, target)
            for source, target in edge_pairs
            if source in members and target not in members
        )
        local_semantics_sha256 = _canonical_sha256({
            "profile": "stage-a-register-dataflow-local-semantics-v1",
            "transfers": sorted(
                (
                    region_id,
                    transfer_by_region[region_id][
                        "transfer_semantics_sha256"
                    ],
                )
                for region_id in members
            ),
            "internal_edges": internal_edges,
        })
        boundary_sha256 = _canonical_sha256({
            "profile": "stage-a-register-dataflow-boundary-v1",
            "incoming_edges": incoming_edges,
            "outgoing_edges": outgoing_edges,
        })
        if (
            local_semantics_sha256 != component.local_semantics_sha256
            or boundary_sha256 != component.boundary_sha256
        ):
            raise StageAInputError(
                f"register component {component.id} does not match transfer data"
            )


def project_register_dataflow_packs(
    *,
    graph_payload: object,
    transfer_table_payload: object | None,
    expected_original_sha256: str,
    expected_candidate_sha256: str,
    transfer_programs_payload: object | None = None,
    pack_region_budget: int = 128,
) -> RegisterDataflowPackProjection:
    try:
        graph = parse_stable_dataflow_graph(graph_payload)
    except ValueError as exc:
        raise StageAInputError(f"register dataflow graph is invalid: {exc}") from exc
    table = (
        parse_register_transfer_table(
            transfer_table_payload,
            expected_original_sha256=expected_original_sha256,
            expected_candidate_sha256=expected_candidate_sha256,
            expected_graph_sha256=graph.graph_sha256,
        )
        if transfer_table_payload is not None else None
    )
    transfer_by_region = (
        {region["id"]: region for region in table.regions}
        if table is not None else {}
    )
    transfer_context = None
    program_by_region: dict[str, dict[str, Any]] = {}
    if transfer_programs_payload is not None:
        parsed_programs = parse_register_transfer_programs(
            transfer_programs_payload,
            expected_original_sha256=expected_original_sha256,
            expected_candidate_sha256=expected_candidate_sha256,
            expected_graph_sha256=graph.graph_sha256,
        )
        transfer_context = parsed_programs["context"]
        program_by_region = {
            program["region_id"]: program
            for program in parsed_programs["programs"]
        }
        transfer_by_region = {
            program["region_id"]: {
                "id": program["region_id"],
                "context_sha256": program["program_sha256"],
                "transfer_semantics_sha256": program["program_sha256"],
            }
            for program in parsed_programs["programs"]
        }
        propagation_regions = parsed_programs["propagation"]["regions"]
        propagation_edges = parsed_programs["propagation"]["edges"]
    elif table is not None:
        propagation_regions = table.propagation_regions
        propagation_edges = table.propagation_edges
    else:
        raise StageAInputError(
            "register dataflow planning requires transfer programs or a table"
        )
    schedule = stable_dataflow_schedule(
        graph, region_budget=pack_region_budget
    )
    propagation_by_region = {
        region["id"]: region for region in propagation_regions
    }
    graph_region_ids = {
        region_id
        for component in graph.components
        for region_id in component.region_ids
    }
    if (
        set(transfer_by_region) != graph_region_ids
        or set(propagation_by_region) != graph_region_ids
        or program_by_region and set(program_by_region) != graph_region_ids
    ):
        raise StageAInputError(
            "register transfer table does not cover the dataflow graph"
        )
    _validate_component_semantics(
        components=graph.components,
        transfer_by_region=transfer_by_region,
        edges=tuple(propagation_edges),
    )

    component_by_id = {component.id: component for component in graph.components}
    component_by_region = {
        region_id: component.id
        for component in graph.components
        for region_id in component.region_ids
    }
    pack_by_component = {
        component_id: pack.id
        for pack in schedule.packs
        for component_id in pack.component_ids
    }
    pack_by_region = {
        region_id: pack_by_component[component_id]
        for region_id, component_id in component_by_region.items()
    }

    pack_inputs: dict[str, dict[str, Any]] = {}
    manifest_rows = []
    for pack_id in schedule.topological_pack_ids:
        pack = next(item for item in schedule.packs if item.id == pack_id)
        local_region_ids = sorted(
            region_id
            for component_id in pack.component_ids
            for region_id in component_by_id[component_id].region_ids
        )
        local_region_set = set(local_region_ids)
        local_edges = []
        for edge in propagation_edges:
            if edge["target_id"] not in local_region_set:
                continue
            source_pack_id = pack_by_region[edge["source_id"]]
            if (
                source_pack_id != pack.id
                and source_pack_id not in pack.predecessor_ids
            ):
                raise StageAInputError(
                    f"register pack {pack.id} has an undeclared predecessor"
                )
            local_edges.append({
                **edge,
                "source_pack_id": (
                    None if source_pack_id == pack.id else source_pack_id
                ),
            })
        body = {
            "format": REGISTER_DATAFLOW_PACK_INPUT_FORMAT,
            "status": "untrusted_proposal_requires_lean_replay",
            "acceptance_authority": False,
            "id": pack.id,
            "local_semantics_sha256": pack.local_semantics_sha256,
            "resource_class": pack.resource_class,
            "component_ids": list(pack.component_ids),
            "predecessor_ids": list(pack.predecessor_ids),
            "transfer_context_sha256": (
                transfer_context["context_sha256"]
                if transfer_context is not None else None
            ),
            "components": [
                {
                    "id": component_id,
                    "region_ids": list(component_by_id[component_id].region_ids),
                }
                for component_id in pack.component_ids
            ],
            "regions": [
                {
                    **(
                        {
                            key: value
                            for key, value in transfer_by_region[region_id].items()
                            if key != "observations"
                        }
                        if program_by_region
                        else transfer_by_region[region_id]
                    ),
                    **(
                        {"program": program_by_region[region_id]}
                        if program_by_region else {}
                    ),
                    "seed_relation": propagation_by_region[region_id][
                        "seed_relation"
                    ],
                    "stack_window_registers": propagation_by_region[region_id][
                        "stack_window_registers"
                    ],
                }
                for region_id in local_region_ids
            ],
            "edges": local_edges,
        }
        input_sha256 = _canonical_sha256(body)
        payload = {**body, "input_sha256": input_sha256}
        pack_inputs[pack.id] = payload
        manifest_rows.append({
            "id": pack.id,
            "input_sha256": input_sha256,
            "predecessor_ids": list(pack.predecessor_ids),
            "resource_class": pack.resource_class,
            "region_count": pack.region_count,
        })
    manifest_body = {
        "format": REGISTER_DATAFLOW_PACK_MANIFEST_FORMAT,
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "original_sha256": expected_original_sha256,
        "candidate_sha256": expected_candidate_sha256,
        "graph_sha256": graph.graph_sha256,
        "transfer_context_sha256": (
            transfer_context["context_sha256"]
            if transfer_context is not None else None
        ),
        "pack_count": len(manifest_rows),
        "topological_pack_ids": list(schedule.topological_pack_ids),
        "packs": manifest_rows,
    }
    manifest = {
        **manifest_body,
        "manifest_sha256": _canonical_sha256(manifest_body),
    }
    return RegisterDataflowPackProjection(
        manifest=manifest,
        inputs=pack_inputs,
        transfer_context=transfer_context,
    )


__all__ = [
    "REGISTER_DATAFLOW_PACK_INPUT_FORMAT",
    "REGISTER_DATAFLOW_PACK_MANIFEST_FORMAT",
    "RegisterDataflowPackProjection",
    "parse_register_dataflow_pack_input",
    "parse_register_dataflow_pack_manifest",
    "project_register_dataflow_packs",
]
