"""Machine-IR reconstruction commands."""

from __future__ import annotations

import argparse
from typing import Any

from ..reconstruction_ir import export_machine_ir_package
from .common import Handler, many_path_arguments, path_argument


def _export_machine_ir(args: argparse.Namespace) -> Any:
    package = export_machine_ir_package(
        state_machine=args.state_machine,
        original_pe=args.original,
        out=args.out,
        reference_contract=args.reference_contract,
        indirect_target_profile=args.indirect_target_profile,
        machine_import_profiles=args.machine_import_profile,
        external_interface_profiles=args.external_interface_profile,
        external_operation_profiles=args.external_operation_profile,
    )
    return package.manifest


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name != "stage-a-export-machine-ir":
        raise ValueError(f"unsupported reconstruction command: {name}")
    path_argument(command, "state_machine", required=True)
    path_argument(command, "original", required=True)
    path_argument(command, "reference_contract")
    path_argument(command, "indirect_target_profile")
    many_path_arguments(command, "machine_import_profile")
    many_path_arguments(command, "external_interface_profile")
    many_path_arguments(command, "external_operation_profile")
    path_argument(command, "out", required=True)
    return _export_machine_ir


__all__ = ["configure_command"]
