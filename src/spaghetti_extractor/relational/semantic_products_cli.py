from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..errors import StageAInputError
from .semantic_products import stage_a_produce_semantic_products


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-semantic-products"
    )
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        result = stage_a_produce_semantic_products(
            proposal=arguments.proposal,
            out=arguments.out,
        )
    except (OSError, StageAInputError, ValueError) as exc:
        print(json.dumps({"status": "incomplete", "error": str(exc)}))
        return 1
    print(json.dumps({
        "status": result["status"],
        "products_sha256": result["products_sha256"],
        "out": str(arguments.out),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
