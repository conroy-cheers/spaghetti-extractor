"""Reduce a Stage B transfer inventory from checked rooted reachability.

This is candidate-generation machinery.  It accepts only a prepared Stage A
artifact whose whole-program acceptance plan is ready and whose decoded
product graph is both control-closed and locally complete.  The selected rows
still carry no proof authority; the rebuilt candidate must pass Stage A again.
"""

from __future__ import annotations

import json
from bisect import bisect_right
from pathlib import Path
from typing import Any, Mapping

from .relational.schema import SchemaError, selected_relational_acceptance_theorem
from .stage_binary import StageAInputError
from .util import sha256_file, write_json


STAGE_B_REACHABLE_SLICE_FORMAT = "stage-b-reachable-transfer-slice-v1"


def write_stage_b_reachable_slice(
    *,
    prepared_proof: Path,
    product_graph: Path,
    whole_program_acceptance: Path,
    state_machine: Path,
    out_dir: Path,
) -> dict[str, Any]:
    """Write the exact transfer subset admitted by a closed rooted graph."""

    prepared_proof = Path(prepared_proof).resolve()
    product_graph = Path(product_graph).resolve()
    whole_program_acceptance = Path(whole_program_acceptance).resolve()
    state_machine = Path(state_machine).resolve()
    out_dir = Path(out_dir).resolve()

    prepared = _json_object(prepared_proof, "prepared proof")
    graph = _json_object(product_graph, "product graph")
    acceptance = _json_object(
        whole_program_acceptance, "whole-program acceptance"
    )
    rows = _jsonl_objects(state_machine, "state machine")

    prepared_format = prepared.get("format")
    if prepared_format not in {
        "stage-a-prepared-relational-v1",
        "stage-a-prepared-relational-v2",
    }:
        raise StageAInputError("reachable slicing requires a relational v3 prepared proof")
    if (
        prepared_format == "stage-a-prepared-relational-v2"
        and not isinstance(prepared.get("artifact_manifest_sha256"), str)
    ):
        raise StageAInputError(
            "reachable slicing requires a v2 prepared proof bound to its artifact manifest"
        )
    if prepared.get("status") != "prepared":
        raise StageAInputError("reachable slicing requires a prepared Stage A proof")
    if prepared.get("acceptance") != acceptance:
        raise StageAInputError("prepared proof acceptance does not match the supplied artifact")
    if prepared.get("product_graph_sha256") != sha256_file(product_graph):
        raise StageAInputError("prepared proof product-graph binding changed")
    if prepared.get("whole_program_acceptance_sha256") != sha256_file(
        whole_program_acceptance
    ):
        raise StageAInputError("prepared proof acceptance binding changed")
    try:
        theorem = selected_relational_acceptance_theorem(acceptance)
    except SchemaError as exc:
        raise StageAInputError(
            f"reachable slicing requires a final-theorem-ready acceptance plan: {exc}"
        ) from exc
    if theorem is None:
        raise StageAInputError(
            "reachable slicing requires a final-theorem-ready acceptance plan"
        )
    if prepared.get("expected_final_theorem") != theorem:
        raise StageAInputError("prepared proof final theorem does not match acceptance")

    if graph.get("format") != "stage-a-relational-product-graph-v1":
        raise StageAInputError("reachable slicing requires a relational product graph")
    counts = _mapping(graph.get("counts"), "product graph counts")
    evidence = _mapping(graph.get("evidence"), "product graph evidence")
    if counts.get("declared_reachability_control_closed") is not True:
        raise StageAInputError(
            "reachable slicing requires decoded control closure with no indirect frontier"
        )
    if counts.get("reachable_product_local_complete") is not True:
        raise StageAInputError(
            "reachable slicing requires every rooted feasible edge to be locally refined"
        )
    if counts.get("reachable_decoded_control_frontier_nodes") != 0:
        raise StageAInputError("reachable slicing refuses a decoded-control frontier")
    if counts.get("reachable_local_refinement_frontier_edges") != 0:
        raise StageAInputError("reachable slicing refuses a local-refinement frontier")

    node_inventory = evidence.get("canonical_node_inventory")
    reachable_node_ids = evidence.get("declared_reachable_node_ids")
    if not isinstance(node_inventory, list) or not isinstance(
        reachable_node_ids, list
    ):
        raise StageAInputError("product graph omits canonical rooted reachability evidence")
    nodes_by_id: dict[int, Mapping[str, Any]] = {}
    for raw in node_inventory:
        node = _mapping(raw, "canonical node")
        node_id = _natural(node.get("node_id"), "canonical node id")
        if node_id in nodes_by_id:
            raise StageAInputError(f"duplicate canonical node id {node_id}")
        nodes_by_id[node_id] = node
    reachable_ids = tuple(
        _natural(value, "reachable node id") for value in reachable_node_ids
    )
    if tuple(sorted(set(reachable_ids))) != reachable_ids:
        raise StageAInputError("reachable node ids must be unique and canonical")
    if int(counts.get("declared_reachable_nodes", -1)) != len(reachable_ids):
        raise StageAInputError("reachable node count disagrees with its checked inventory")

    row_by_rva: dict[int, dict[str, Any]] = {}
    row_spans: list[tuple[int, int, dict[str, Any]]] = []
    for row in rows:
        original = _mapping(row.get("original"), "state-machine original span")
        rva = _natural(original.get("rva_start"), "state-machine original RVA")
        end_rva = _natural(
            original.get("rva_end"), "state-machine original end RVA"
        )
        if end_rva <= rva:
            raise StageAInputError(
                f"state-machine transfer at RVA 0x{rva:x} has an empty span"
            )
        if rva in row_by_rva:
            raise StageAInputError(f"ambiguous state-machine transfer RVA 0x{rva:x}")
        row_by_rva[rva] = row
        row_spans.append((rva, end_rva, row))
    row_spans.sort(key=lambda item: item[0])
    for previous, current in zip(row_spans, row_spans[1:]):
        if current[0] < previous[1]:
            raise StageAInputError(
                "state-machine transfer spans overlap at RVA "
                f"0x{current[0]:x}"
            )
    row_starts = [start for start, _end, _row in row_spans]

    def owning_transfer(rva: int) -> tuple[int, dict[str, Any]] | None:
        index = bisect_right(row_starts, rva) - 1
        if index < 0:
            return None
        start, end, row = row_spans[index]
        return (start, row) if rva < end else None

    selected_rvas: set[int] = set()
    selected_node_ids_by_rva: dict[int, list[int]] = {}
    for node_id in reachable_ids:
        node = nodes_by_id.get(node_id)
        if node is None:
            raise StageAInputError(f"reachable node {node_id} has no canonical inventory row")
        rva = _natural(node.get("original_rva_start"), "canonical original RVA")
        owner = owning_transfer(rva)
        if owner is None:
            raise StageAInputError(
                f"reachable node {node_id} at RVA 0x{rva:x} has no semantic transfer"
            )
        transfer_rva, _row = owner
        selected_rvas.add(transfer_rva)
        selected_node_ids_by_rva.setdefault(transfer_rva, []).append(node_id)

    selected_rows = [row_by_rva[rva] for rva in sorted(selected_rvas)]
    out_dir.mkdir(parents=True, exist_ok=True)
    state_machine_out = out_dir / "state-machine-reachable.jsonl"
    state_machine_out.write_text(
        "".join(
            json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
            for row in selected_rows
        ),
        encoding="utf-8",
    )
    manifest_path = out_dir / "reachable-slice.json"
    manifest = {
        "format": STAGE_B_REACHABLE_SLICE_FORMAT,
        "status": "ready",
        "acceptance_theorem": theorem,
        "inputs": {
            "prepared_proof_sha256": sha256_file(prepared_proof),
            "product_graph_sha256": sha256_file(product_graph),
            "whole_program_acceptance_sha256": sha256_file(
                whole_program_acceptance
            ),
            "state_machine_sha256": sha256_file(state_machine),
        },
        "output": {
            "path": state_machine_out.name,
            "sha256": sha256_file(state_machine_out),
        },
        "counts": {
            "input_transfers": len(rows),
            "reachable_nodes": len(reachable_ids),
            "selected_transfers": len(selected_rows),
            "omitted_transfers": len(rows) - len(selected_rows),
            "aliased_reachable_nodes": sum(
                len(node_ids) - 1
                for node_ids in selected_node_ids_by_rva.values()
            ),
        },
        "selected": [
            {
                "rva": rva,
                "transfer_id": row_by_rva[rva].get("id"),
                "node_ids": selected_node_ids_by_rva[rva],
            }
            for rva in sorted(selected_rvas)
        ],
        "authority": (
            "candidate generation only with no proof authority; the reduced "
            "candidate must independently "
            "pass the Lean-checked Stage A whole-program theorem"
        ),
    }
    write_json(manifest_path, manifest)
    return manifest


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    return value


def _natural(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{context} must be a natural number")
    return value


def _json_object(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {context} {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageAInputError(f"{context} must be a JSON object")
    return value


def _jsonl_objects(path: Path, context: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise StageAInputError(f"cannot read {context} {path}: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StageAInputError(
                f"invalid {context} JSON on line {line_number}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise StageAInputError(
                f"{context} line {line_number} must be a JSON object"
            )
        rows.append(value)
    if not rows:
        raise StageAInputError(f"{context} is empty")
    return rows
