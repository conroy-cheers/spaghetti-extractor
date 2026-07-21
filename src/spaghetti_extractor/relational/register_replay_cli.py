from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..errors import StageAInputError
from .register_replay import stage_a_replay_register_dataflow


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-register-replay"
    )
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument(
        "--register-dataflow-aggregate", type=Path, required=True
    )
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        result = stage_a_replay_register_dataflow(
            proposal=arguments.proposal,
            register_dataflow_aggregate=arguments.register_dataflow_aggregate,
            out=arguments.out,
        )
    except (OSError, StageAInputError, ValueError) as exc:
        print(json.dumps({"status": "incomplete", "error": str(exc)}))
        return 1
    print(json.dumps({
        "status": result["status"],
        "replay_sha256": result["replay_sha256"],
        "out": str(arguments.out),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
