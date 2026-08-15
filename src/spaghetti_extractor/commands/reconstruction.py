"""Machine-IR reconstruction commands."""

from __future__ import annotations

import argparse
from typing import Any

from ..reconstruction.ir import export_machine_ir_package
from .common import Handler, path_argument


def _export_machine_ir(args: argparse.Namespace) -> Any:
    package = export_machine_ir_package(
        state_machine=args.state_machine,
        original_pe=args.original,
        out=args.out,
        static_program_contract=args.static_program_contract,
        indirect_target_profile=args.indirect_target_profile,
    )
    return package.manifest


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name != "machine-ir-export":
        raise ValueError(f"unsupported reconstruction command: {name}")
    path_argument(command, "state_machine", required=True)
    path_argument(command, "original", required=True)
    path_argument(command, "static_program_contract")
    path_argument(command, "indirect_target_profile")
    path_argument(command, "out", required=True)
    return _export_machine_ir


__all__ = ["configure_command"]
