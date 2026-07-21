from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..errors import StageAInputError
from .composition_products import stage_a_produce_composition_products


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-composition-products"
    )
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--register-replay", type=Path, required=True)
    parser.add_argument("--semantic-products", type=Path, required=True)
    parser.add_argument("--memory-products", type=Path, required=True)
    parser.add_argument("--original-isa", type=Path)
    parser.add_argument("--candidate-isa", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        result = stage_a_produce_composition_products(
            proposal=arguments.proposal,
            register_replay=arguments.register_replay,
            semantic_products=arguments.semantic_products,
            memory_products=arguments.memory_products,
            original_isa=arguments.original_isa,
            candidate_isa=arguments.candidate_isa,
            out=arguments.out,
        )
    except (OSError, StageAInputError, ValueError, KeyError) as exc:
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
