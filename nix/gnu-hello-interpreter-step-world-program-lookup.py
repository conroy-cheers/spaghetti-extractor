#!/usr/bin/env python3
"""Bind GNU hello Step to its nested world-indexed ProgramLookup call."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_step_world_program_lookup import (
    write_relational_interpreter_kernel_step_world_program_lookup_bundle,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument(
        "--program-lookup-native-world-bridge-plan",
        type=Path,
        required=True,
    )
    parser.add_argument("--step-operation-plan", type=Path, required=True)
    parser.add_argument(
        "--operation-instantiation-plan", type=Path, required=True
    )
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    write_relational_interpreter_kernel_step_world_program_lookup_bundle(
        out=arguments.out,
        candidate_pe=arguments.candidate,
        program_lookup_native_world_bridge_plan=(
            arguments.program_lookup_native_world_bridge_plan
        ),
        step_operation_plan=arguments.step_operation_plan,
        operation_instantiation_plan=arguments.operation_instantiation_plan,
    )


if __name__ == "__main__":
    main()
