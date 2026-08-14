"""Static extraction and reference-contract commands."""

from __future__ import annotations

import argparse

from ..analysis.binary_inventory import stage_a_inventory_binary
from ..behavioral_roots import generate_behavioral_roots
from ..contract_tools import (
    REFERENCE_CONTRACT_MODEL_ID,
    stage_a_diff_obligations,
    stage_a_explain_obligations,
    stage_a_export_reference_contract,
    stage_a_smoke_contract,
)
from ..import_abi import expand_import_abi_policy
from ..opaque_reconstruction import stage_a_export_opaque_reconstruction
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

    if name == "stage-a-smoke-contract":
        path_argument(command, "reference_contract", required=True)
        path_argument(command, "out")
        return lambda a: stage_a_smoke_contract(
            reference_contract=a.reference_contract, out=a.out
        )

    if name == "stage-a-explain-contract":
        path_argument(command, "reference_contract", required=True)
        command.add_argument("--focus", required=True)
        path_argument(command, "out")
        return lambda a: stage_a_explain_obligations(
            reference_contract=a.reference_contract, focus=a.focus, out=a.out
        )

    if name == "stage-a-diff-contract":
        path_argument(command, "before", required=True)
        path_argument(command, "after", required=True)
        path_argument(command, "out")
        return lambda a: stage_a_diff_obligations(
            before=a.before, after=a.after, out=a.out
        )

    if name == "stage-a-expand-import-abi":
        path_argument(command, "original", required=True)
        path_argument(command, "policy", required=True)
        path_argument(command, "out", required=True)
        return lambda a: expand_import_abi_policy(
            original_pe=a.original, policy=a.policy, out=a.out
        )

    raise ValueError(f"unsupported static-analysis command: {name}")


__all__ = ["configure_command"]
