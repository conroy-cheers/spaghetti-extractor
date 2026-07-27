from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..stage_binary import StageAInputError
from .binary_inventory import stage_a_inventory_binary
from .side_extraction import (
    stage_a_extract_side,
    stage_a_extract_side_isa,
    stage_a_merge_side_extraction_requests,
    stage_a_merge_side_extractions,
    stage_a_project_inventory_extraction_request,
    stage_a_project_missing_side_extraction_request,
    stage_a_project_side_extraction_request,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spaghetti-extractor-side")
    commands = parser.add_subparsers(dest="command", required=True)

    inventory = commands.add_parser("inventory-binary")
    inventory.add_argument("--binary", type=Path, required=True)
    inventory.add_argument("--linker-map", type=Path)
    inventory.add_argument(
        "--side", choices=("original", "candidate"), required=True
    )
    inventory.add_argument("--out", type=Path, required=True)
    inventory.set_defaults(
        handler=lambda args: stage_a_inventory_binary(
            binary=args.binary,
            linker_map=args.linker_map,
            side=args.side,
            out=args.out,
        )
    )

    project_inventory = commands.add_parser(
        "project-inventory-extraction-request"
    )
    project_inventory.add_argument("--inventory", type=Path, required=True)
    project_inventory.add_argument(
        "--scope", choices=("base", "superset"), default="base"
    )
    project_inventory.add_argument("--out", type=Path, required=True)
    project_inventory.set_defaults(
        handler=lambda args: stage_a_project_inventory_extraction_request(
            inventory=args.inventory,
            scope=args.scope,
            out=args.out,
        )
    )

    merge_requests = commands.add_parser("merge-side-extraction-requests")
    merge_requests.add_argument(
        "--input", type=Path, action="append", required=True
    )
    merge_requests.add_argument("--out", type=Path, required=True)
    merge_requests.set_defaults(
        handler=lambda args: stage_a_merge_side_extraction_requests(
            inputs=args.input,
            out=args.out,
        )
    )

    project_missing = commands.add_parser(
        "project-missing-side-extraction-request"
    )
    project_missing.add_argument("--binary", type=Path, required=True)
    project_missing.add_argument(
        "--side", choices=("original", "candidate"), required=True
    )
    project_missing.add_argument(
        "--relation-contract", type=Path, required=True
    )
    project_missing.add_argument("--inventory", type=Path, required=True)
    project_missing.add_argument("--out", type=Path, required=True)
    project_missing.set_defaults(
        handler=lambda args: stage_a_project_missing_side_extraction_request(
            binary=args.binary,
            side=args.side,
            relation_contract=args.relation_contract,
            inventory=args.inventory,
            out=args.out,
        )
    )

    merge = commands.add_parser("merge-side-extractions")
    merge.add_argument("--binary", type=Path, required=True)
    merge.add_argument(
        "--side", choices=("original", "candidate"), required=True
    )
    merge.add_argument("--input", type=Path, action="append", required=True)
    merge.add_argument("--out", type=Path, required=True)
    merge.set_defaults(
        handler=lambda args: stage_a_merge_side_extractions(
            binary=args.binary,
            side=args.side,
            inputs=args.input,
            out=args.out,
        )
    )

    project = commands.add_parser("project-side-extraction-request")
    project.add_argument("--binary", type=Path, required=True)
    project.add_argument(
        "--side", choices=("original", "candidate"), required=True
    )
    project.add_argument("--relation-contract", type=Path, required=True)
    project.add_argument("--out", type=Path, required=True)
    project.set_defaults(
        handler=lambda args: stage_a_project_side_extraction_request(
            binary=args.binary,
            side=args.side,
            relation_contract=args.relation_contract,
            out=args.out,
        )
    )

    extract = commands.add_parser("extract-side")
    extract.add_argument("--binary", type=Path, required=True)
    extract.add_argument("--request", type=Path, required=True)
    extract.add_argument("--out", type=Path, required=True)
    extract.set_defaults(
        handler=lambda args: stage_a_extract_side(
            binary=args.binary,
            request=args.request,
            out=args.out,
        )
    )

    extract_isa = commands.add_parser("extract-side-isa")
    extract_isa.add_argument("--binary", type=Path, required=True)
    extract_isa.add_argument("--request", type=Path, required=True)
    extract_isa.add_argument("--out", type=Path, required=True)
    extract_isa.set_defaults(
        handler=lambda args: stage_a_extract_side_isa(
            binary=args.binary,
            request=args.request,
            out=args.out,
        )
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.handler(args)
    except (OSError, StageAInputError, ValueError) as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    status = result.get("status", result.get("verdict"))
    return 0 if status in {"extracted", "generated", "pass"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
