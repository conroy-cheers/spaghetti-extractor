#!/usr/bin/env python3
"""Emit the fixed-name public mixed-chunked Stage A acceptance wrapper."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_chunked_acceptance import (
    InterpreterMixedChunkedAcceptanceSpec,
    write_relational_interpreter_mixed_chunked_acceptance,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binding-module", required=True)
    parser.add_argument("--source-parameter-type", required=True)
    parser.add_argument("--source-profile", required=True)
    parser.add_argument("--source-theorem", required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    write_relational_interpreter_mixed_chunked_acceptance(
        arguments.out,
        InterpreterMixedChunkedAcceptanceSpec(
            binding_module=arguments.binding_module,
            source_parameter_type=arguments.source_parameter_type,
            source_profile=arguments.source_profile,
            source_theorem=arguments.source_theorem,
        ),
    )


if __name__ == "__main__":
    main()
