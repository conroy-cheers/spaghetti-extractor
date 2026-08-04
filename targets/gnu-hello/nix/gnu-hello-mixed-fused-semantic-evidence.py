#!/usr/bin/env python3
"""Emit exact fused semantic bindings for the GNU hello round-trip lane."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor_target_gnu_hello.gnu_hello_mixed_fused_semantic_evidence import (
    generate_gnu_hello_mixed_fused_semantic_evidence,
    write_gnu_hello_mixed_fused_semantic_evidence,
)
from spaghetti_extractor.relational.lean.interpreter_normalization import (
    _read_rows,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-machine", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    bundle = generate_gnu_hello_mixed_fused_semantic_evidence(
        _read_rows(arguments.state_machine)
    )
    write_gnu_hello_mixed_fused_semantic_evidence(arguments.out, bundle)


if __name__ == "__main__":
    main()
