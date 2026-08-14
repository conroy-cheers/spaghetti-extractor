"""Round-trip fuzz corpus commands."""

from __future__ import annotations

import argparse

from ..roundtrip_fuzz.generator import generate_spike_corpus
from ..roundtrip_fuzz.runner import run_roundtrip_corpus
from .common import Handler, path_argument


def configure_command(name: str, command: argparse.ArgumentParser) -> Handler:
    if name == "roundtrip-generate":
        path_argument(command, "out", required=True)
        command.add_argument("--seed", type=int, default=0)
        command.add_argument("--count", type=int, default=36)
        command.add_argument(
            "--toolchain", choices=("gnu", "llvm-msvc"), default="gnu"
        )
        command.add_argument("--compiler")
        command.add_argument("--linker")
        command.add_argument("--force", action="store_true")
        return lambda a: generate_spike_corpus(
            out=a.out,
            seed=a.seed,
            count=a.count,
            toolchain=a.toolchain,
            compiler=a.compiler,
            linker=a.linker,
            force=a.force,
        )

    if name == "roundtrip-run":
        path_argument(command, "corpus", required=True)
        command.add_argument("--case", action="append", default=[])
        path_argument(command, "out", required=True)
        return lambda a: run_roundtrip_corpus(
            corpus=a.corpus, out=a.out, case_ids=tuple(a.case)
        )

    raise ValueError(f"unsupported round-trip command: {name}")


__all__ = ["configure_command"]
