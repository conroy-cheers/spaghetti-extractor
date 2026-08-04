#!/usr/bin/env python3
"""Emit the checked GNU hello Run entry control-route proposal."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_run_entry_route import (
    write_run_entry_route_bundle,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation-manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    write_run_entry_route_bundle(
        operation_manifest=arguments.operation_manifest,
        out=arguments.out,
    )


if __name__ == "__main__":
    main()
