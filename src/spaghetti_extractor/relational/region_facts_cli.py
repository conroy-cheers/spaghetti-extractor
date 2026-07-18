from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..stage_binary import StageAInputError
from .region_facts import stage_a_analyze_region_facts


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spaghetti-extractor-region-facts")
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--relation-contract", type=Path, required=True)
    parser.add_argument("--original-extraction", type=Path, required=True)
    parser.add_argument("--candidate-extraction", type=Path, required=True)
    parser.add_argument("--normalized-behaviors", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        result = stage_a_analyze_region_facts(
            original=args.original,
            candidate=args.candidate,
            relation_contract=args.relation_contract,
            original_extraction=args.original_extraction,
            candidate_extraction=args.candidate_extraction,
            normalized_behaviors=args.normalized_behaviors,
            out=args.out,
        )
    except (OSError, StageAInputError, ValueError) as exc:
        result = {
            "format": "stage-a-relational-region-facts-result-v1",
            "status": "incomplete",
            "blocker": str(exc),
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "analyzed" else 1


if __name__ == "__main__":
    sys.exit(main())
