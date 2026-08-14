"""ISA inventory and conformance commands."""

from __future__ import annotations

import argparse
from typing import Any

from ..extraction.isa_inventory import write_binary_isa_inventory
from ..isa_catalog_enrichment import write_enriched_side_isa_catalog
from ..isa_conformance_nix import stage_a_check_isa_conformance_nix
from .common import Handler, path_argument


def _run_isa_conformance_nix(args: argparse.Namespace) -> dict[str, Any]:
    return stage_a_check_isa_conformance_nix(
        corpus=args.corpus,
        backend=args.backend,
        out=args.out,
        forms_out=args.forms_out,
        bochs_runner=args.bochs_runner,
        flake=args.flake,
        builders_file=args.builders_file,
        builder_trusted_public_keys_file=args.builder_trusted_public_keys_file,
    )


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "stage-a-inventory-isa":
        path_argument(command, "binary", required=True)
        path_argument(command, "inventory", required=True)
        command.add_argument("--scope", choices=("base", "superset"), default="superset")
        path_argument(command, "out", required=True)
        return lambda a: write_binary_isa_inventory(
            binary=a.binary, inventory=a.inventory, scope=a.scope, out=a.out
        )

    if name == "stage-a-check-isa-conformance":
        path_argument(command, "corpus", required=True)
        command.add_argument(
            "--backend", choices=("lean", "unicorn", "bochs"), required=True
        )
        path_argument(command, "bochs_runner")
        path_argument(command, "forms_out")
        path_argument(command, "flake")
        path_argument(command, "builders_file")
        path_argument(command, "builder_trusted_public_keys_file")
        path_argument(command, "out", required=True)
        return _run_isa_conformance_nix

    if name == "stage-a-enrich-isa-catalog":
        path_argument(command, "proposal", required=True)
        command.add_argument("--timeout-seconds", type=float, default=300.0)
        path_argument(command, "out", required=True)
        return lambda a: write_enriched_side_isa_catalog(
            proposal=a.proposal, out=a.out, timeout_seconds=a.timeout_seconds
        )

    raise ValueError(f"unsupported ISA command: {name}")


__all__ = ["configure_command"]
