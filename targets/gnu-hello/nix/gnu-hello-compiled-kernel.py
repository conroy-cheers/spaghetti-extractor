#!/usr/bin/env python3
"""Generate exact compiled-kernel facts without the broad proof driver."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_FUNCTION_MODULE_PREFIX,
    INTERPRETER_KERNEL_LEAN_FILENAME,
    write_relational_interpreter_kernel_bundle,
)
from spaghetti_extractor.util import sha256_file, write_json


def generate(
    *,
    candidate: Path,
    linker_map: Path,
    program_manifest: Path,
    engine_layout: Path,
    native_build_manifest: Path,
    out: Path,
) -> None:
    out.mkdir(parents=True, exist_ok=True)
    plan = write_relational_interpreter_kernel_bundle(
        out=out,
        candidate_data_module="StageA.GeneratedInterpreterKernelDataBase",
        candidate_data_namespace=(
            "StageA.GeneratedRelational.InterpreterKernelData"
        ),
        candidate_bytes_symbol="generatedInterpreterKernelCandidateBytes",
        candidate_pe_symbol="generatedInterpreterKernelCandidatePe",
        candidate_pe=candidate,
        linker_map=linker_map,
        interpreter_program_manifest=program_manifest,
        engine_layout=engine_layout,
        native_build_manifest=native_build_manifest,
        externalize_artifacts=True,
    )
    stage_a = out / "StageA"
    stage_a.mkdir(exist_ok=True)
    shutil.move(
        str(out / INTERPRETER_KERNEL_LEAN_FILENAME),
        str(stage_a / INTERPRETER_KERNEL_LEAN_FILENAME),
    )
    for source in sorted(
        out.glob(f"{INTERPRETER_KERNEL_FUNCTION_MODULE_PREFIX}*.lean")
    ):
        shutil.move(str(source), str(stage_a / source.name))
    modules = sorted(path.stem for path in stage_a.glob("*.lean"))
    function_modules = [
        module
        for module in modules
        if module.startswith(INTERPRETER_KERNEL_FUNCTION_MODULE_PREFIX)
    ]
    if len(function_modules) != len(plan.functions):
        raise RuntimeError(
            "compiled-kernel function module count does not match the plan"
        )
    inputs = {
        "candidate": candidate,
        "engine_layout": engine_layout,
        "linker_map": linker_map,
        "native_build_manifest": native_build_manifest,
        "program_manifest": program_manifest,
    }
    write_json(
        out / "phase-manifest.json",
        {
            "format": "stage-a-relational-phase-v1",
            "phase": "compiled-kernel",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {
                role: {"path": path.name, "sha256": sha256_file(path)}
                for role, path in sorted(inputs.items())
            },
            "status": "source-ready",
            "diagnostic_status": plan.payload().get(
                "status", "semantic_proof_required"
            ),
            "modules": modules,
            "targets": [Path(INTERPRETER_KERNEL_LEAN_FILENAME).stem],
            "counts": {
                "modules": len(modules),
                "function_modules": len(function_modules),
            },
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--linker-map", type=Path, required=True)
    parser.add_argument("--program-manifest", type=Path, required=True)
    parser.add_argument("--engine-layout", type=Path, required=True)
    parser.add_argument("--native-build-manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    generate(
        candidate=args.candidate,
        linker_map=args.linker_map,
        program_manifest=args.program_manifest,
        engine_layout=args.engine_layout,
        native_build_manifest=args.native_build_manifest,
        out=args.out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
