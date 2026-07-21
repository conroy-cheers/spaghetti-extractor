from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..util import write_json
from .register_dataflow_aggregate import (
    aggregate_register_dataflow_pack_results,
)


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-dataflow-aggregate"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--result", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
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


if __name__ == "__main__":
    raise SystemExit(main())
