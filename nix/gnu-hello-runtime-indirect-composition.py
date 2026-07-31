#!/usr/bin/env python3
"""Emit the exact GNU hello runtime-indirect static composition."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path

from spaghetti_extractor.relational.lean.gnu_hello_runtime_indirect_composition import (
    GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_FORMAT,
    GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_LEAN_FILENAME,
    plan_gnu_hello_runtime_indirect_composition,
    write_gnu_hello_runtime_indirect_composition_module,
)
from spaghetti_extractor.util import sha256_file, write_json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cutpoint-graph", type=Path, required=True)
    parser.add_argument("--stack-dynamic-closure", type=Path, required=True)
    parser.add_argument("--runtime-value-carry", type=Path, required=True)
    parser.add_argument("--rooted-unreachability", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()

    inputs = {
        "cutpoint_graph": arguments.cutpoint_graph,
        "stack_dynamic_closure": arguments.stack_dynamic_closure,
        "runtime_value_carry": arguments.runtime_value_carry,
        "rooted_unreachability": arguments.rooted_unreachability,
    }
    plan = plan_gnu_hello_runtime_indirect_composition(**inputs)
    destination = (
        arguments.out
        / "StageA"
        / GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_LEAN_FILENAME
    )
    write_gnu_hello_runtime_indirect_composition_module(destination, plan)
    write_json(
        arguments.out / "gnu-hello-runtime-indirect-composition.json",
        {
            "format": GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_FORMAT,
            "phase": "gnu-hello-runtime-indirect-composition",
            "status": "incomplete",
            "acceptance_authority": False,
            "proof_authority": False,
            "lean_check_required": True,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "failure_mode": "incomplete",
            "inputs": {
                name: {
                    "path": path.name,
                    "sha256": sha256_file(path),
                }
                for name, path in inputs.items()
            },
            "outputs": {
                "lean_module": (
                    "StageA/"
                    + GNU_HELLO_RUNTIME_INDIRECT_COMPOSITION_LEAN_FILENAME
                ),
            },
            "evidence_gaps": [asdict(gap) for gap in plan.evidence_gaps],
            "targets": [
                "GeneratedRelationalGNUHelloRuntimeIndirectComposition"
            ],
        },
    )


if __name__ == "__main__":
    main()
