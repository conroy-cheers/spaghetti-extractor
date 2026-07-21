"""Command surface for the immutable relational proposal phase."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..stage_binary import StageAInputError
from .pipeline import stage_a_discover_relational_proposals


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spaghetti-extractor-proposal")
    commands = parser.add_subparsers(dest="command", required=True)

    discover = commands.add_parser("discover-proposals")
    discover.add_argument("--original", type=Path, required=True)
    discover.add_argument("--candidate", type=Path, required=True)
    discover.add_argument("--relation-contract", type=Path, required=True)
    discover.add_argument("--original-extraction", type=Path)
    discover.add_argument("--candidate-extraction", type=Path)
    discover.add_argument("--normalized-behaviors", type=Path)
    discover.add_argument("--region-facts", type=Path)
    discover.add_argument("--out", type=Path, required=True)

    validate = commands.add_parser("validate-proposal")
    validate.add_argument("--proposal", type=Path, required=True)
    return parser


def _run(args: argparse.Namespace) -> dict[str, object]:
    if args.command == "discover-proposals":
        return stage_a_discover_relational_proposals(
            original=args.original,
            candidate=args.candidate,
            relation_contract=args.relation_contract,
            original_extraction=args.original_extraction,
            candidate_extraction=args.candidate_extraction,
            normalized_behaviors=args.normalized_behaviors,
            region_facts=args.region_facts,
            out=args.out,
        )
    from .proposal_artifact import validate_relational_proposal

    manifest = validate_relational_proposal(args.proposal)
    return {
        "format": "stage-a-relational-proposal-validation-v1",
        "status": "validated",
        "original_sha256": manifest.original_sha256,
        "candidate_sha256": manifest.candidate_sha256,
        "closure_sha256": manifest.closure_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    try:
        result = _run(_build_parser().parse_args(argv))
    except (OSError, StageAInputError, ValueError) as exc:
        print(json.dumps({"status": "incomplete", "error": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
