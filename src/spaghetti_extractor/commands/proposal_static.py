"""Non-authorizing static extraction and contract-proposal commands."""

from __future__ import annotations

import argparse

from ..extraction.binary_inventory import spx_inventory_binary
from ..external.import_abi import expand_import_abi_policy
from ..pe32.behavioral_roots import generate_behavioral_roots
from ..reconstruction.static_export import export_static_reconstruction
from ..util import write_json
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "static-inventory-binary":
        path_argument(command, "binary", required=True)
        path_argument(command, "linker_map")
        path_argument(command, "out", required=True)
        return lambda a: spx_inventory_binary(
            binary=a.binary, linker_map=a.linker_map, side="original", out=a.out
        )

    if name == "static-export-roots":
        path_argument(command, "original", required=True)
        path_argument(command, "out", required=True)
        return lambda a: write_json(a.out, generate_behavioral_roots(a.original))

    if name == "static-program-export":
        path_argument(command, "original", required=True)
        path_argument(command, "inventory", required=True)
        path_argument(command, "out", required=True)
        return lambda a: export_static_reconstruction(
            original=a.original, inventory=a.inventory, out=a.out
        )

    if name == "external-bind-import-abi":
        path_argument(command, "original", required=True)
        path_argument(command, "policy", required=True)
        path_argument(command, "out", required=True)
        return lambda a: expand_import_abi_policy(
            original_pe=a.original, policy=a.policy, out=a.out
        )

    raise ValueError(f"unsupported static proposal command: {name}")


__all__ = ["configure_command"]
