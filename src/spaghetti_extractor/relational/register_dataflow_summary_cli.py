from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..util import write_json
from .register_dataflow_summary import summarize_register_dataflow_pack_result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-dataflow-summary"
    )
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
    result = json.loads(arguments.result.read_text(encoding="utf-8"))
    summary = summarize_register_dataflow_pack_result(result)
    write_json(arguments.out, summary)
    print(json.dumps({
        "status": summary["status"],
        "pack_id": summary["pack_id"],
        "summary_sha256": summary["summary_sha256"],
        "out": str(arguments.out),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
