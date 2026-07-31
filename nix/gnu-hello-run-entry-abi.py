#!/usr/bin/env python3
"""Emit the checked GNU hello Run-entry ABI instantiation."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_run_entry_abi import (
    write_run_entry_abi_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_entry_projection import (
    write_run_entry_projection_bundle,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation-manifest", type=Path, required=True)
    parser.add_argument("--abi-plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    write_run_entry_projection_bundle(
        operation_manifest=arguments.operation_manifest,
        abi_plan=arguments.abi_plan,
        out=arguments.out,
    )
    write_run_entry_abi_bundle(arguments.out)


if __name__ == "__main__":
    main()
