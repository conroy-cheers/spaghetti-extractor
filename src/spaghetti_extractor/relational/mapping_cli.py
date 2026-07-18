from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..stage_binary import StageAInputError
from .contract import stage_a_generate_relation_contract
from .mapping import stage_a_generate_map


def _proof_metadata(
    value: str | None, path: Path | None,
) -> dict[str, Any] | None:
    if value is not None and path is not None:
        raise StageAInputError(
            "provide only one of --proof-metadata-json and --proof-metadata"
        )
    if path is not None:
        value = path.read_text(encoding="utf-8")
    if value is None:
        return None
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as exc:
        raise StageAInputError(f"invalid proof metadata JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageAInputError("proof metadata must be a JSON object")
    return payload


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="spaghetti-extractor-mapping")
    commands = parser.add_subparsers(dest="command", required=True)

    generate_map = commands.add_parser("generate-map")
    generate_map.add_argument("--original", type=Path, required=True)
    generate_map.add_argument("--candidate", type=Path, required=True)
    generate_map.add_argument(
        "--linker-map-original", type=Path, required=True
    )
    generate_map.add_argument(
        "--linker-map-candidate", type=Path, required=True
    )
    generate_map.add_argument("--out", type=Path, required=True)
    generate_map.add_argument("--layout-contract-out", type=Path)
    generate_map.add_argument("--original-flags", default="")
    generate_map.add_argument("--candidate-flags", default="")
    generate_map.add_argument(
        "--proof-rule", default="same_source_layout_preserving_build_v1"
    )
    generate_map.add_argument("--proof-metadata-json")
    generate_map.add_argument("--proof-metadata", type=Path)
    generate_map.set_defaults(
        handler=lambda args: stage_a_generate_map(
            original=args.original,
            candidate=args.candidate,
            linker_map_original=args.linker_map_original,
            linker_map_candidate=args.linker_map_candidate,
            out=args.out,
            layout_contract_out=args.layout_contract_out,
            original_flags=args.original_flags,
            candidate_flags=args.candidate_flags,
            proof_rule=args.proof_rule,
            proof_metadata=_proof_metadata(
                args.proof_metadata_json, args.proof_metadata
            ),
        )
    )

    generate_contract = commands.add_parser("generate-relation-contract")
    generate_contract.add_argument("--original", type=Path, required=True)
    generate_contract.add_argument("--candidate", type=Path, required=True)
    generate_contract.add_argument("--mapping", type=Path, required=True)
    generate_contract.add_argument(
        "--external-profile",
        type=Path,
        action="append",
        dest="external_profiles",
    )
    generate_contract.add_argument("--out", type=Path, required=True)
    generate_contract.set_defaults(
        handler=lambda args: stage_a_generate_relation_contract(
            original=args.original,
            candidate=args.candidate,
            mapping=args.mapping,
            external_profile=args.external_profiles,
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
    return 0 if result.get("status") in {"generated", "pass"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
