#!/usr/bin/env python3
"""Bind GNU hello candidate artifacts to the generic native launch graph."""

from __future__ import annotations

import argparse
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_native_launch import (
    INTERPRETER_NATIVE_LAUNCH_GRAPH_PLAN_FILENAME,
    native_launch_graph_spec_from_engine_artifacts,
    write_relational_interpreter_native_launch_graph,
)
from spaghetti_extractor.util import sha256_file, write_json


PHASE_FORMAT = "stage-a-gnu-hello-native-launch-graph-v1"


def generate(
    *,
    candidate: Path,
    linker_map: Path,
    native_engine_plan: Path,
    engine_segments: Path,
    out: Path,
) -> None:
    binding = native_launch_graph_spec_from_engine_artifacts(
        candidate_pe=candidate,
        linker_map=linker_map,
        native_engine_plan=native_engine_plan,
    )
    plan = write_relational_interpreter_native_launch_graph(
        out,
        candidate_pe=candidate,
        engine_segments=engine_segments,
        spec=binding.spec,
    )
    write_json(out / "native-launch-graph-artifact-binding.json", binding.payload())
    write_json(
        out / "phase-manifest.json",
        {
            "format": PHASE_FORMAT,
            "phase": "native-launch-graph",
            "status": "source-ready",
            "acceptance_authority": False,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "candidate_sha256": plan.candidate_sha256,
            "inputs": {
                "linker_map_sha256": sha256_file(linker_map),
                "native_engine_plan_sha256": sha256_file(native_engine_plan),
                "engine_segments_sha256": plan.engine_segments_sha256,
            },
            "counts": {
                "canonical_roots": 1 + len(plan.tls_callback_rvas),
                "cutpoints": len(plan.cutpoints),
                "routes": len(plan.routes),
                "decoded_nodes": sum(len(route.nodes) for route in plan.routes),
            },
            "outputs": {
                "artifact_binding": "native-launch-graph-artifact-binding.json",
                "graph_plan": INTERPRETER_NATIVE_LAUNCH_GRAPH_PLAN_FILENAME,
                "lean_module": (
                    "StageA/GeneratedRelationalInterpreterNativeLaunchGraph.lean"
                ),
            },
            "failure_mode": "incomplete",
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--linker-map", type=Path, required=True)
    parser.add_argument("--native-engine-plan", type=Path, required=True)
    parser.add_argument("--engine-segments", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    generate(
        candidate=args.candidate,
        linker_map=args.linker_map,
        native_engine_plan=args.native_engine_plan,
        engine_segments=args.engine_segments,
        out=args.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
