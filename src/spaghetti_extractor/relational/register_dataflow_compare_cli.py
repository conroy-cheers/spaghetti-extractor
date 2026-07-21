from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..util import write_json
from .register_dataflow_compare import compare_register_dataflow_aggregate


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-dataflow-compare"
    )
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--register-relations", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
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
