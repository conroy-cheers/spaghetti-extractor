"""Isolated GNU hello kernel-data proof-source driver.

This entry point deliberately imports only the exact-data generator.  Keeping
it separate from the orchestration driver prevents unrelated proof-generator
changes from invalidating the large, immutable kernel-data certificate graph.
"""

from __future__ import annotations

import argparse
import sys
import types
from pathlib import Path

import spaghetti_extractor

# Importing the public roundtrip_fuzz facade eagerly loads discovery and report
# tooling.  Kernel-data extraction needs only the exact image-contract module,
# so expose the package path without importing that unrelated orchestration.
roundtrip_fuzz = types.ModuleType("spaghetti_extractor.roundtrip_fuzz")
roundtrip_fuzz.__path__ = [
    str(Path(spaghetti_extractor.__file__).parent / "roundtrip_fuzz")
]
sys.modules[roundtrip_fuzz.__name__] = roundtrip_fuzz

from spaghetti_extractor.relational.lean.interpreter_kernel_data import (
    generate_interpreter_kernel_data_bundle,
)
from spaghetti_extractor.util import sha256_file, write_json


def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--linker-map", required=True)
    parser.add_argument("--state-machine", required=True)
    parser.add_argument("--lean-source-root", required=True)
    parser.add_argument("--shard-size", required=True, type=int)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    out = Path(args.out)
    candidate = Path(args.candidate)
    linker_map = Path(args.linker_map)
    state_machine = Path(args.state_machine)
    inventory = generate_interpreter_kernel_data_bundle(
        candidate_pe=candidate,
        linker_map=linker_map,
        state_machine=state_machine,
        out_dir=out,
        shard_size=args.shard_size,
        lean_source_root=args.lean_source_root,
    )
    write_json(
        out / "phase-manifest.json",
        {
            "format": "stage-a-gnu-hello-roundtrip-phase-v1",
            "phase": "compiled-kernel-data",
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {
                role: {"path": path.name, "sha256": sha256_file(path)}
                for role, path in sorted(
                    {
                        "candidate": candidate,
                        "linker_map": linker_map,
                        "state_machine": state_machine,
                    }.items()
                )
            },
            "status": "source-ready",
            "modules": sorted(
                path.stem for path in (out / "StageA").glob("*.lean")
            ),
            "targets": ["GeneratedInterpreterKernelDataBundle"],
            "counts": inventory.payload()["counts"],
        },
    )


if __name__ == "__main__":
    _main()
