from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..errors import StageAInputError
from .analysis_reference import validate_relational_analysis_view
from .assembly import stage_a_assemble_relational_analysis


def _assemble(arguments: argparse.Namespace) -> dict[str, object]:
    return stage_a_assemble_relational_analysis(
        proposal=arguments.proposal,
        register_replay=arguments.register_replay,
        semantic_products=arguments.semantic_products,
        memory_products=arguments.memory_products,
        composition_products=arguments.composition_products,
        out=arguments.out,
    )


def _validate(arguments: argparse.Namespace) -> dict[str, object]:
    manifest = validate_relational_analysis_view(arguments.analysis)
    return {
        "format": "stage-a-relational-analysis-validation-v1",
        "status": "analyzed",
        "original_sha256": manifest.original_sha256,
        "candidate_sha256": manifest.candidate_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="spaghetti-extractor-relational-assembly"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    assemble = commands.add_parser("assemble-relational")
    assemble.add_argument("--proposal", type=Path, required=True)
    assemble.add_argument("--register-replay", type=Path, required=True)
    assemble.add_argument("--semantic-products", type=Path, required=True)
    assemble.add_argument("--memory-products", type=Path, required=True)
    assemble.add_argument("--composition-products", type=Path, required=True)
    assemble.add_argument("--out", type=Path, required=True)
    assemble.set_defaults(handler=_assemble)

    validate = commands.add_parser("validate-analysis")
    validate.add_argument("--analysis", type=Path, required=True)
    validate.set_defaults(handler=_validate)

    arguments = parser.parse_args(argv)
    try:
        result = arguments.handler(arguments)
    except (OSError, StageAInputError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "incomplete", "error": str(exc)}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
