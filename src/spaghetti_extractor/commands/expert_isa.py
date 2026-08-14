"""Checked ISA conformance command."""

from __future__ import annotations

import argparse
from typing import Any

from ..isa.conformance_nix import stage_a_check_isa_conformance_nix
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

    raise ValueError(f"unsupported expert ISA command: {name}")


__all__ = ["configure_command"]
