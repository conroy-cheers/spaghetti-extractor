from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..stage_binary import StageAInputError
from .pair_normalization import stage_a_normalize_pair


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-pair-normalization"
    )
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--relation-contract", type=Path, required=True)
    parser.add_argument("--original-extraction", type=Path, required=True)
    parser.add_argument("--candidate-extraction", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        result = stage_a_normalize_pair(
            original=args.original,
            candidate=args.candidate,
            relation_contract=args.relation_contract,
            original_extraction=args.original_extraction,
            candidate_extraction=args.candidate_extraction,
            out=args.out,
        )
    except (OSError, StageAInputError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
