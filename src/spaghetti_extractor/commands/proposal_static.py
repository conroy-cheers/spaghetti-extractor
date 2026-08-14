"""Non-authorizing static extraction and contract-proposal commands."""

from __future__ import annotations

import argparse

from ..extraction.binary_inventory import stage_a_inventory_binary
from ..external.import_abi import expand_import_abi_policy
from ..pe32.behavioral_roots import generate_behavioral_roots
from ..reference_contract.common import REFERENCE_CONTRACT_MODEL_ID
from ..reference_contract.generation import stage_a_export_reference_contract
from ..reconstruction.opaque import stage_a_export_opaque_reconstruction
from ..util import write_json
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "stage-a-inventory-binary":
        path_argument(command, "binary", required=True)
        path_argument(command, "linker_map")
        path_argument(command, "out", required=True)
        return lambda a: stage_a_inventory_binary(
            binary=a.binary, linker_map=a.linker_map, side="original", out=a.out
        )

    if name == "stage-a-export-behavioral-roots":
        path_argument(command, "original", required=True)
        path_argument(command, "out", required=True)
        return lambda a: write_json(a.out, generate_behavioral_roots(a.original))

    if name == "stage-a-export-opaque-reconstruction":
        path_argument(command, "original", required=True)
        path_argument(command, "inventory", required=True)
        path_argument(command, "out", required=True)
        return lambda a: stage_a_export_opaque_reconstruction(
            original=a.original, inventory=a.inventory, out=a.out
        )

    if name == "stage-a-export-reference-contract":
        path_argument(command, "original", required=True)
        path_argument(command, "mapping")
        path_argument(command, "sidecar_dir")
        path_argument(command, "unit_contract_dir")
        path_argument(command, "out", required=True)
        return lambda a: stage_a_export_reference_contract(
            original=a.original,
            mapping=a.mapping,
            out=a.out,
            sidecar_dir=a.sidecar_dir,
            unit_contract_dir=a.unit_contract_dir,
            model=REFERENCE_CONTRACT_MODEL_ID,
        )

    if name == "stage-a-expand-import-abi":
        path_argument(command, "original", required=True)
        path_argument(command, "policy", required=True)
        path_argument(command, "out", required=True)
        return lambda a: expand_import_abi_policy(
            original_pe=a.original, policy=a.policy, out=a.out
        )

    raise ValueError(f"unsupported static proposal command: {name}")


__all__ = ["configure_command"]
