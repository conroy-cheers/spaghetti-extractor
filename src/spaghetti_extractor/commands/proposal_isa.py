"""Non-authorizing ISA inventory and enrichment commands."""

from __future__ import annotations

import argparse

from ..extraction.isa_inventory import write_binary_isa_inventory
from ..isa.catalog_enrichment import write_enriched_side_isa_catalog
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "isa-inventory":
        path_argument(command, "binary", required=True)
        path_argument(command, "inventory", required=True)
        command.add_argument("--scope", choices=("base", "superset"), default="superset")
        path_argument(command, "out", required=True)
        return lambda a: write_binary_isa_inventory(
            binary=a.binary, inventory=a.inventory, scope=a.scope, out=a.out
        )

    if name == "isa-enrich-catalog":
        path_argument(command, "proposal", required=True)
        command.add_argument("--timeout-seconds", type=float, default=300.0)
        path_argument(command, "out", required=True)
        return lambda a: write_enriched_side_isa_catalog(
            proposal=a.proposal, out=a.out, timeout_seconds=a.timeout_seconds
        )

    raise ValueError(f"unsupported ISA proposal command: {name}")


__all__ = ["configure_command"]
