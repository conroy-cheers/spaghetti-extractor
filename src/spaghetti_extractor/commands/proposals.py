"""Optional, non-authorizing extraction proposal commands."""

from __future__ import annotations

import argparse

from ..extraction.ghidra import export_ghidra_proposal
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name != "stage-a-export-ghidra-proposal":
        raise ValueError(f"unsupported proposal command: {name}")
    path_argument(command, "binary", required=True)
    path_argument(command, "out", required=True)
    command.add_argument("--analyze-headless")
    path_argument(command, "script_path")
    path_argument(command, "project_dir")
    command.add_argument("--timeout-seconds", type=int)
    return lambda args: export_ghidra_proposal(
        binary=args.binary,
        out=args.out,
        analyze_headless=args.analyze_headless,
        script_path=args.script_path,
        project_dir=args.project_dir,
        timeout_seconds=args.timeout_seconds,
    )


__all__ = ["configure_command"]
