from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..util import write_json
from .register_dataflow_packs import project_register_dataflow_packs
from .register_dataflow_problem import parse_register_dataflow_problem


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="spaghetti-extractor-dataflow-plan")
    parser.add_argument("--problem", type=Path)
    parser.add_argument("--graph", type=Path)
    parser.add_argument("--transfer-table", type=Path)
    parser.add_argument("--transfer-programs", type=Path)
    parser.add_argument("--original-sha256")
    parser.add_argument("--candidate-sha256")
    parser.add_argument("--out-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.problem is not None:
        if any(item is not None for item in (
            arguments.graph, arguments.transfer_table,
            arguments.transfer_programs, arguments.original_sha256,
            arguments.candidate_sha256,
        )):
            parser.error("--problem cannot be combined with split problem inputs")
        raw_problem = _read(arguments.problem)
        if not isinstance(raw_problem, dict):
            parser.error("--problem must contain an object")
        problem = parse_register_dataflow_problem(
            raw_problem,
            expected_original_sha256=str(raw_problem.get("original_sha256", "")),
            expected_candidate_sha256=str(raw_problem.get("candidate_sha256", "")),
            expected_contract_sha256=str(raw_problem.get("contract_sha256", "")),
            expected_behaviors_sha256=str(raw_problem.get("behaviors_sha256", "")),
        )
        graph_payload = problem["graph"]
        transfer_table_payload = None
        transfer_programs_payload = problem["transfer_programs"]
        original_sha256 = problem["original_sha256"]
        candidate_sha256 = problem["candidate_sha256"]
    else:
        if arguments.graph is None:
            parser.error("--graph is required without --problem")
        if arguments.original_sha256 is None or arguments.candidate_sha256 is None:
            parser.error("binary identities are required without --problem")
        if arguments.transfer_table is None and arguments.transfer_programs is None:
            parser.error("one of --transfer-programs or --transfer-table is required")
        graph_payload = _read(arguments.graph)
        transfer_table_payload = (
            _read(arguments.transfer_table)
            if arguments.transfer_table is not None else None
        )
        transfer_programs_payload = (
            _read(arguments.transfer_programs)
            if arguments.transfer_programs is not None else None
        )
        original_sha256 = arguments.original_sha256
        candidate_sha256 = arguments.candidate_sha256
    projection = project_register_dataflow_packs(
        graph_payload=graph_payload,
        transfer_table_payload=transfer_table_payload,
        expected_original_sha256=original_sha256,
        expected_candidate_sha256=candidate_sha256,
        transfer_programs_payload=transfer_programs_payload,
    )
    arguments.out_dir.mkdir(parents=True, exist_ok=True)
    packs_dir = arguments.out_dir / "packs"
    packs_dir.mkdir()
    for pack_id, payload in projection.inputs.items():
        write_json(packs_dir / f"{pack_id}.json", payload)
    write_json(arguments.out_dir / "manifest.json", projection.manifest)
    if projection.transfer_context is not None:
        write_json(
            arguments.out_dir / "transfer-context.json",
            projection.transfer_context,
        )
    print(json.dumps({
        "status": "planned",
        "pack_count": len(projection.inputs),
        "out_dir": str(arguments.out_dir),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
