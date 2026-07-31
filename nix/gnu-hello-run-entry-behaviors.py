#!/usr/bin/env python3
"""Bind untrusted Run-entry behavior literals to exact Lean decoding."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_operation_behavior_materialization import (
    write_run_entry_behavior_materialization_bundle,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation-manifest", type=Path, required=True)
    parser.add_argument("--extraction", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    write_run_entry_behavior_materialization_bundle(
        operation_manifest=arguments.operation_manifest,
        extraction=arguments.extraction,
        out=arguments.out,
    )


if __name__ == "__main__":
    main()
