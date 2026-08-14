"""Non-authorizing component discovery command."""

from __future__ import annotations

import argparse

from ..components.discovery import write_component_proposals
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name != "stage-b-discover-components":
        raise ValueError(f"unsupported component proposal command: {name}")
    path_argument(command, "machine_ir", required=True)
    path_argument(command, "reconstruction_plan", required=True)
    command.add_argument("--max-units", type=int, default=512)
    command.add_argument("--max-candidates-per-seed", type=int, default=12)
    path_argument(command, "out", required=True)
    return lambda a: write_component_proposals(
        machine_ir=a.machine_ir,
        reconstruction_plan=a.reconstruction_plan,
        out=a.out,
        max_units=a.max_units,
        max_candidates_per_seed=a.max_candidates_per_seed,
    )


__all__ = ["configure_command"]
