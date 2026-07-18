from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from ..stage_binary import StageAInputError
from .binary_inventory import stage_a_inventory_binary
from .contract import stage_a_generate_relation_contract
from .mapping import stage_a_generate_map
from .side_extraction import (
    stage_a_extract_side,
    stage_a_extract_side_isa,
    stage_a_merge_side_extractions,
    stage_a_project_inventory_extraction_request,
    stage_a_project_missing_side_extraction_request,
    stage_a_project_side_extraction_request,
)


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
    from .analysis_artifact import validate_relational_analysis

    manifest = validate_relational_analysis(path)
    return {
        "format": "stage-a-relational-analysis-validation-v1",
        "status": "analyzed",
        "original_sha256": manifest.original_sha256,
        "candidate_sha256": manifest.candidate_sha256,
    }


def _analyze_relational(args: argparse.Namespace) -> dict[str, Any]:
    from .analysis import stage_a_analyze_relational

    return stage_a_analyze_relational(
        original=args.original,
        candidate=args.candidate,
        relation_contract=args.relation_contract,
        original_extraction=args.original_extraction,
        candidate_extraction=args.candidate_extraction,
        normalized_behaviors=args.normalized_behaviors,
        original_isa=args.original_isa,
        candidate_isa=args.candidate_isa,
        region_facts=args.region_facts,
        out=args.out,
    )


def _analyze_region_facts(args: argparse.Namespace) -> dict[str, Any]:
    from .region_facts import stage_a_analyze_region_facts

    return stage_a_analyze_region_facts(
        original=args.original,
        candidate=args.candidate,
        relation_contract=args.relation_contract,
        original_extraction=args.original_extraction,
        candidate_extraction=args.candidate_extraction,
        normalized_behaviors=args.normalized_behaviors,
        out=args.out,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-relational-analysis"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze-relational")
    analyze.add_argument("--original", type=Path, required=True)
    analyze.add_argument("--candidate", type=Path, required=True)
    analyze.add_argument("--relation-contract", type=Path, required=True)
    analyze.add_argument("--original-extraction", type=Path)
    analyze.add_argument("--candidate-extraction", type=Path)
    analyze.add_argument("--normalized-behaviors", type=Path)
    analyze.add_argument("--original-isa", type=Path)
    analyze.add_argument("--candidate-isa", type=Path)
    analyze.add_argument("--region-facts", type=Path)
    analyze.add_argument("--out", type=Path, required=True)
    analyze.set_defaults(handler=_analyze_relational)

    analyze_facts = commands.add_parser("analyze-region-facts")
    analyze_facts.add_argument("--original", type=Path, required=True)
    analyze_facts.add_argument("--candidate", type=Path, required=True)
    analyze_facts.add_argument("--relation-contract", type=Path, required=True)
    analyze_facts.add_argument("--original-extraction", type=Path, required=True)
    analyze_facts.add_argument("--candidate-extraction", type=Path, required=True)
    analyze_facts.add_argument("--normalized-behaviors", type=Path, required=True)
    analyze_facts.add_argument("--out", type=Path, required=True)
    analyze_facts.set_defaults(handler=_analyze_region_facts)

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

    inventory_binary = commands.add_parser("inventory-binary")
    inventory_binary.add_argument("--binary", type=Path, required=True)
    inventory_binary.add_argument("--linker-map", type=Path, required=True)
    inventory_binary.add_argument(
        "--side", choices=("original", "candidate"), required=True
    )
    inventory_binary.add_argument("--out", type=Path, required=True)
    inventory_binary.set_defaults(
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

    merge_side = commands.add_parser("merge-side-extractions")
    merge_side.add_argument("--binary", type=Path, required=True)
    merge_side.add_argument(
        "--side", choices=("original", "candidate"), required=True
    )
    merge_side.add_argument(
        "--input", type=Path, action="append", required=True
    )
    merge_side.add_argument("--out", type=Path, required=True)
    merge_side.set_defaults(
        handler=lambda args: stage_a_merge_side_extractions(
            binary=args.binary,
            side=args.side,
            inputs=args.input,
            out=args.out,
        )
    )

    project_side = commands.add_parser("project-side-extraction-request")
    project_side.add_argument("--binary", type=Path, required=True)
    project_side.add_argument(
        "--side", choices=("original", "candidate"), required=True
    )
    project_side.add_argument("--relation-contract", type=Path, required=True)
    project_side.add_argument("--out", type=Path, required=True)
    project_side.set_defaults(
        handler=lambda args: stage_a_project_side_extraction_request(
            binary=args.binary,
            side=args.side,
            relation_contract=args.relation_contract,
            out=args.out,
        )
    )

    extract_side = commands.add_parser("extract-side")
    extract_side.add_argument("--binary", type=Path, required=True)
    extract_side.add_argument("--request", type=Path, required=True)
    extract_side.add_argument("--out", type=Path, required=True)
    extract_side.set_defaults(
        handler=lambda args: stage_a_extract_side(
            binary=args.binary,
            request=args.request,
            out=args.out,
        )
    )

    extract_side_isa = commands.add_parser("extract-side-isa")
    extract_side_isa.add_argument("--binary", type=Path, required=True)
    extract_side_isa.add_argument("--request", type=Path, required=True)
    extract_side_isa.add_argument("--out", type=Path, required=True)
    extract_side_isa.set_defaults(
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
    except (StageAInputError, OSError, ValueError) as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    status = result.get("status", result.get("verdict"))
    return 0 if status in {
        "analyzed",
        "extracted",
        "generated",
        "prepared",
        "pass",
    } else 1


if __name__ == "__main__":
    raise SystemExit(main())
