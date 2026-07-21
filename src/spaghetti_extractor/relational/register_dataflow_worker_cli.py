from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..util import write_json
from .register_dataflow_formats import parse_register_dataflow_pack_manifest
from .register_dataflow_solver import solve_register_dataflow_pack
from .register_dataflow_summary_format import (
    register_dataflow_pack_summary_payload,
)


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-dataflow-worker"
    )
    parser.add_argument("--pack", type=Path)
    parser.add_argument("--predecessor", type=Path, action="append", default=[])
    parser.add_argument("--out", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--packs-root", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--transfer-context", type=Path)
    arguments = parser.parse_args(argv)
    batch_values = (arguments.manifest, arguments.packs_root, arguments.out_dir)
    batch_mode = any(value is not None for value in batch_values)
    if batch_mode:
        if not all(value is not None for value in batch_values):
            parser.error("batch mode requires --manifest, --packs-root, and --out-dir")
        if arguments.pack is not None or arguments.out is not None:
            parser.error("batch mode does not accept --pack or --out")
        if arguments.predecessor:
            parser.error("batch mode does not accept --predecessor")
        manifest = parse_register_dataflow_pack_manifest(
            _read(arguments.manifest)
        )
        arguments.out_dir.mkdir(parents=True, exist_ok=True)
        results: dict[str, dict[str, Any]] = {}
        summaries: dict[str, dict[str, Any]] = {}
        input_by_id = {
            pack_id: _read(arguments.packs_root / f"{pack_id}.json")
            for pack_id in manifest["topological_pack_ids"]
        }
        transfer_context = (
            _read(arguments.transfer_context)
            if arguments.transfer_context is not None else None
        )
        for pack_id in manifest["topological_pack_ids"]:
            pack = input_by_id[pack_id]
            result = solve_register_dataflow_pack(
                pack_payload=pack,
                predecessor_payloads=[
                    summaries[predecessor_id]
                    for predecessor_id in pack["predecessor_ids"]
                ],
                transfer_context_payload=transfer_context,
            )
            write_json(arguments.out_dir / f"{pack_id}.json", result)
            results[pack_id] = result
            summaries[pack_id] = register_dataflow_pack_summary_payload(
                pack_id=result["pack_id"],
                status=result["status"],
                regions=result["regions"],
            )
        incomplete = sum(
            result["status"] != "complete" for result in results.values()
        )
        print(json.dumps({
            "status": "complete" if incomplete == 0 else "incomplete",
            "pack_count": len(results),
            "incomplete_pack_count": incomplete,
            "out_dir": str(arguments.out_dir),
        }, sort_keys=True))
        return 0
    if arguments.pack is None or arguments.out is None:
        parser.error("single-pack mode requires --pack and --out")
    result = solve_register_dataflow_pack(
        pack_payload=_read(arguments.pack),
        predecessor_payloads=[
            _read(path) for path in arguments.predecessor
        ],
        transfer_context_payload=(
            _read(arguments.transfer_context)
            if arguments.transfer_context is not None else None
        ),
    )
    write_json(arguments.out, result)
    print(json.dumps({
        "status": result["status"],
        "pack_id": result["pack_id"],
        "out": str(arguments.out),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
