"""Non-authorizing reference-contract diagnostic commands."""

from __future__ import annotations

import argparse

from ..reference_contract.diagnostics import (
    stage_a_diff_obligations,
    stage_a_explain_obligations,
    stage_a_smoke_contract,
)
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
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

    raise ValueError(f"unsupported contract diagnostic command: {name}")


__all__ = ["configure_command"]
