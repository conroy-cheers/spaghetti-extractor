from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..stage_binary import StageAInputError
from .analysis import stage_a_analyze_relational
from .analysis_artifact import validate_relational_analysis
from .contract import stage_a_generate_relation_contract
from .mapping import stage_a_generate_map


def _json_object(value: str | None, path: Path | None) -> dict[str, Any] | None:
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


def _validate_analysis(path: Path) -> dict[str, Any]:
    manifest = validate_relational_analysis(path)
    return {
        "format": "stage-a-relational-analysis-validation-v1",
        "status": "analyzed",
        "original_sha256": manifest.original_sha256,
        "candidate_sha256": manifest.candidate_sha256,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-relational-analysis"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze-relational")
    analyze.add_argument("--original", type=Path, required=True)
    analyze.add_argument("--candidate", type=Path, required=True)
    analyze.add_argument("--relation-contract", type=Path, required=True)
    analyze.add_argument("--out", type=Path, required=True)
    analyze.set_defaults(
        handler=lambda args: stage_a_analyze_relational(
            original=args.original,
            candidate=args.candidate,
            relation_contract=args.relation_contract,
            out=args.out,
        )
    )

    generate_map = commands.add_parser("generate-map")
    generate_map.add_argument("--original", type=Path, required=True)
    generate_map.add_argument("--candidate", type=Path, required=True)
    generate_map.add_argument("--linker-map-original", type=Path, required=True)
    generate_map.add_argument("--linker-map-candidate", type=Path, required=True)
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
            proof_metadata=_json_object(
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

    validate = commands.add_parser("validate-analysis")
    validate.add_argument("--analysis", type=Path, required=True)
    validate.set_defaults(handler=lambda args: _validate_analysis(args.analysis))
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
    status = result.get("status", result.get("verdict"))
    return 0 if status in {"analyzed", "generated", "prepared", "pass"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
