#!/usr/bin/env python3
"""Narrow CLI for GNU hello direct-call semantic source generation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from spaghetti_extractor.relational.lean.internal_direct_call_semantics_bundle import (
    write_mixed_original_direct_call_semantics,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True)
    parser.add_argument("--state-machine", required=True)
    parser.add_argument("--proposal-report", required=True)
    parser.add_argument("--semantic-input")
    parser.add_argument("--kernel-checks")
    parser.add_argument("--out", required=True)
    arguments = parser.parse_args()
    kernel_checks: Mapping[str, Any] | None = None
    if arguments.kernel_checks is not None:
        value = json.loads(
            Path(arguments.kernel_checks).read_text(encoding="utf-8")
        )
        if not isinstance(value, Mapping):
            raise ValueError("kernel-check inventory is not an object")
        kernel_checks = value
    write_mixed_original_direct_call_semantics(
        original=Path(arguments.original),
        state_machine=Path(arguments.state_machine),
        proposal_report=Path(arguments.proposal_report),
        semantic_input=(
            None
            if arguments.semantic_input is None
            else Path(arguments.semantic_input)
        ),
        out=Path(arguments.out),
        kernel_checks=kernel_checks,
    )


if __name__ == "__main__":
    main()
