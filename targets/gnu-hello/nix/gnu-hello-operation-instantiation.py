#!/usr/bin/env python3
"""Emit the concrete GNU hello operation-instantiation bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_operation_instantiation import (
    write_relational_interpreter_kernel_operation_instantiation_bundle,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--kernel-plan", type=Path, required=True)
    parser.add_argument("--state-machine", type=Path, required=True)
    parser.add_argument("--data-inventory", type=Path, required=True)
    parser.add_argument("--step-operation-plan", type=Path, required=True)
    parser.add_argument("--run-operation-plan", type=Path, required=True)
    parser.add_argument("--invoke-operation-plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    write_relational_interpreter_kernel_operation_instantiation_bundle(
        out=arguments.out,
        candidate_pe=arguments.candidate,
        kernel_plan=arguments.kernel_plan,
        state_machine=arguments.state_machine,
        data_inventory=arguments.data_inventory,
        step_operation_plan=arguments.step_operation_plan,
        run_operation_plan=arguments.run_operation_plan,
        invoke_operation_plan=arguments.invoke_operation_plan,
    )


if __name__ == "__main__":
    main()
