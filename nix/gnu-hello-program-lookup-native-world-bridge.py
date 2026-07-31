#!/usr/bin/env python3
"""Bind GNU hello ProgramLookup to its exact NativeWorld execution."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_program_lookup_native_world_bridge import (
    write_relational_interpreter_kernel_program_lookup_native_world_bridge_bundle,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--lookup-native-plan", type=Path, required=True)
    parser.add_argument("--lookup-operation-plan", type=Path, required=True)
    parser.add_argument("--step-call-plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    write_relational_interpreter_kernel_program_lookup_native_world_bridge_bundle(
        out=arguments.out,
        candidate_pe=arguments.candidate,
        lookup_native_plan=arguments.lookup_native_plan,
        lookup_operation_plan=arguments.lookup_operation_plan,
        step_call_plan=arguments.step_call_plan,
    )


if __name__ == "__main__":
    main()
