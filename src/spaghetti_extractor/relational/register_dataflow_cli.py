from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..util import write_json
from .register_dataflow_aggregate import (
    aggregate_register_dataflow_pack_results,
)
from .register_dataflow_packs import project_register_dataflow_packs
from .register_dataflow_compare import compare_register_dataflow_aggregate
from .register_dataflow_solver import solve_register_dataflow_pack


def _read(path: Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spaghetti-extractor-dataflow")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan")
    plan.add_argument("--graph", type=Path, required=True)
    plan.add_argument("--transfer-table", type=Path, required=True)
    plan.add_argument("--original-sha256", required=True)
    plan.add_argument("--candidate-sha256", required=True)
    plan.add_argument("--out-dir", type=Path, required=True)

    solve = subparsers.add_parser("solve")
    solve.add_argument("--pack", type=Path, required=True)
    solve.add_argument("--predecessor", type=Path, action="append", default=[])
    solve.add_argument("--out", type=Path, required=True)

    aggregate = subparsers.add_parser("aggregate")
    aggregate.add_argument("--manifest", type=Path, required=True)
    aggregate.add_argument("--result", type=Path, action="append", required=True)
    aggregate.add_argument("--out", type=Path, required=True)

    compare = subparsers.add_parser("compare")
    compare.add_argument("--aggregate", type=Path, required=True)
    compare.add_argument("--register-relations", type=Path, required=True)
    compare.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.command == "plan":
        projection = project_register_dataflow_packs(
            graph_payload=_read(arguments.graph),
            transfer_table_payload=_read(arguments.transfer_table),
            expected_original_sha256=arguments.original_sha256,
            expected_candidate_sha256=arguments.candidate_sha256,
        )
        arguments.out_dir.mkdir(parents=True, exist_ok=True)
        packs_dir = arguments.out_dir / "packs"
        packs_dir.mkdir()
        for pack_id, payload in projection.inputs.items():
            write_json(packs_dir / f"{pack_id}.json", payload)
        write_json(arguments.out_dir / "manifest.json", projection.manifest)
        print(json.dumps({
            "status": "planned",
            "pack_count": len(projection.inputs),
            "out_dir": str(arguments.out_dir),
        }, sort_keys=True))
        return 0
    if arguments.command == "solve":
        result = solve_register_dataflow_pack(
            pack_payload=_read(arguments.pack),
            predecessor_payloads=[
                _read(path) for path in arguments.predecessor
            ],
        )
        write_json(arguments.out, result)
        print(json.dumps({
            "status": result["status"],
            "pack_id": result["pack_id"],
            "out": str(arguments.out),
        }, sort_keys=True))
        return 0
    if arguments.command == "aggregate":
        result = aggregate_register_dataflow_pack_results(
            manifest_payload=_read(arguments.manifest),
            result_payloads=[_read(path) for path in arguments.result],
        )
        write_json(arguments.out, result)
        print(json.dumps({
            "status": result["status"],
            "pack_count": len(result["pack_results"]),
            "out": str(arguments.out),
        }, sort_keys=True))
        return 0
    result = compare_register_dataflow_aggregate(
        aggregate_payload=_read(arguments.aggregate),
        register_relations_payload=_read(arguments.register_relations),
    )
    write_json(arguments.out, result)
    print(json.dumps({
        "status": result["status"],
        "region_count": result["region_count"],
        "mismatch_count": result["mismatch_count"],
        "out": str(arguments.out),
    }, sort_keys=True))
    return 0 if result["status"] == "match" else 1


if __name__ == "__main__":
    raise SystemExit(main())
