from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..stage_binary import StageAInputError


def _prepare_relational(args: argparse.Namespace) -> dict[str, Any]:
    from .pipeline import stage_a_prepare_relational

    return stage_a_prepare_relational(
        original=args.original,
        candidate=args.candidate,
        relation_contract=args.relation_contract,
        out=args.out,
    )


def _generate_relational(args: argparse.Namespace) -> dict[str, Any]:
    from .pipeline import stage_a_generate_relational

    return stage_a_generate_relational(
        analysis=args.analysis,
        out=args.out,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spaghetti-extractor-preparation")
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare-relational")
    prepare.add_argument("--original", type=Path, required=True)
    prepare.add_argument("--candidate", type=Path, required=True)
    prepare.add_argument("--relation-contract", type=Path, required=True)
    prepare.add_argument("--out", type=Path, required=True)
    prepare.set_defaults(handler=_prepare_relational)

    generate = commands.add_parser("generate-relational")
    generate.add_argument("--analysis", type=Path, required=True)
    generate.add_argument("--out", type=Path, required=True)
    generate.set_defaults(handler=_generate_relational)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
    except (StageAInputError, OSError, ValueError) as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("status") == "prepared" else 1


if __name__ == "__main__":
    raise SystemExit(main())
