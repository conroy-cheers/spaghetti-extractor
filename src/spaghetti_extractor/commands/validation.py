"""Candidate-only behavioral validation commands."""

from __future__ import annotations

import argparse

from ..stage_b_functional import stage_b_run_functional_suite
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name != "stage-b-run-functional-suite":
        raise ValueError(f"unsupported validation command: {name}")
    command.add_argument("--candidate-command", nargs="+", required=True)
    path_argument(command, "candidate_binary")
    path_argument(command, "suite", required=True)
    path_argument(command, "out", required=True)
    return lambda a: stage_b_run_functional_suite(
        candidate_command=tuple(a.candidate_command),
        candidate_binary=a.candidate_binary,
        suite=a.suite,
        out=a.out,
    )


__all__ = ["configure_command"]
