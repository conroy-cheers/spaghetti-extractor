from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_abi import (
    INTERPRETER_KERNEL_ABI_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_data import (
    INTERPRETER_KERNEL_DATA_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_lookup_native import (
    build_relational_interpreter_kernel_lookup_native_plan,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_program_lookup_operation import (
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_summary import (
    _PROGRAM_LOOKUP_TEMPLATE_BLOCKS,
    _program_lookup_template_bytes,
)
from spaghetti_extractor.util import sha256_file


def _program_lookup_function() -> dict[str, object]:
    start = 0x1000
    blob = _program_lookup_template_bytes(0x403020, 0x403000)
    offsets = sorted(
        offset
        for _, _, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
        for offset in instructions
    )
    ends = {
        offset: offsets[index + 1] if index + 1 < len(offsets) else len(blob)
        for index, offset in enumerate(offsets)
    }
    return {
        "role": "programLookup",
        "rva_start": start,
        "rva_end": start + len(blob),
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "blocks": [
            {
                "entry_rva": start + entry,
                "successors": [start + successor for successor in successors],
                "instructions": [
                    {
                        "rva": start + offset,
                        "bytes": blob[offset : ends[offset]].hex(),
                    }
                    for offset in instructions
                ],
            }
            for entry, successors, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
        ],
        "x87_frames": [],
    }


class StageAGnuRoundtripProgramLookupOperationPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[1]
        self.driver = self.repo / "targets/gnu-hello/nix/gnu-hello-roundtrip-driver.py"
        self.lane = self.repo / "targets/gnu-hello/default.nix"
        self.flake = self.repo / "flake.nix"

    def test_source_phase_pins_artifacts_and_exposes_theorem(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate.exe"
            kernel = root / "interpreter-kernel-plan.json"
            data = root / "module-inventory.json"
            lookup = root / "interpreter-kernel-lookup-native-plan.json"
            abi = root / "interpreter-kernel-abi-plan.json"
            out = root / "out"

            candidate.write_bytes(b"programLookup pipeline candidate" * 11)
            candidate_hash = sha256_file(candidate)
            kernel.write_text(
                json.dumps(
                    {
                        "format": INTERPRETER_KERNEL_PLAN_FORMAT,
                        "candidate": {
                            "pe_sha256": candidate_hash,
                            "size": candidate.stat().st_size,
                        },
                        "program": {"transfer_count": 7},
                        "kernel_functions": [_program_lookup_function()],
                        "issues": [],
                    }
                ),
                encoding="utf-8",
            )
            data.write_text(
                json.dumps(
                    {
                        "format": INTERPRETER_KERNEL_DATA_FORMAT,
                        "candidate_sha256": candidate_hash,
                        "candidate_bytes": candidate.stat().st_size,
                        "table_rva": 0x3000,
                        "count_rva": 0x3020,
                        "counts": {"transfers": 7},
                    }
                ),
                encoding="utf-8",
            )
            lookup_plan = build_relational_interpreter_kernel_lookup_native_plan(
                kernel_plan=kernel,
                data_inventory=data,
                candidate_pe=candidate,
            )
            lookup.write_text(
                json.dumps(lookup_plan.payload()), encoding="utf-8"
            )
            abi.write_text(
                json.dumps(
                    {
                        "format": INTERPRETER_KERNEL_ABI_FORMAT,
                        "candidate_pe_sha256": candidate_hash,
                        "inputs": {
                            "kernel_plan": {
                                "path": kernel.name,
                                "sha256": sha256_file(kernel),
                            },
                            "data_inventory": {
                                "path": data.name,
                                "sha256": sha256_file(data),
                            },
                            "engine_layout": {
                                "path": "engine-layout.bin",
                                "sha256": "0" * 64,
                            },
                        },
                        "candidate_offsets": {
                            "engine_layout": {"start": 0x4000, "size": 64},
                            "program_table": 0x3000,
                            "program_count": 0x3020,
                        },
                        "program_records": 7,
                        "operations": [
                            {
                                "role": "programLookup",
                                "function_index": 0,
                                "image_offset": 0x1000,
                                "return_offsets": [0x10A0],
                            }
                        ],
                        "failure_mode": "none",
                    }
                ),
                encoding="utf-8",
            )

            process = subprocess.run(
                [
                    sys.executable,
                    str(self.driver),
                    "kernel-lookup-operation",
                    "--candidate",
                    str(candidate),
                    "--kernel-plan",
                    str(kernel),
                    "--kernel-data-inventory",
                    str(data),
                    "--lookup-native-plan",
                    str(lookup),
                    "--abi-plan",
                    str(abi),
                    "--out",
                    str(out),
                ],
                cwd=self.repo,
                env={
                    **os.environ,
                    "PYTHONPATH": str(self.repo / "src"),
                },
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            manifest = json.loads(
                (out / "phase-manifest.json").read_text(encoding="utf-8")
            )
            resources = json.loads(
                (out / "module-resources.json").read_text(encoding="utf-8")
            )
            source = (
                out
                / "StageA/"
                "GeneratedRelationalInterpreterKernelProgramLookupOperation.lean"
            ).read_text(encoding="ascii")
            expected_inputs = {
                role: {"path": path.name, "sha256": sha256_file(path)}
                for role, path in {
                    "candidate": candidate,
                    "kernel_plan": kernel,
                    "kernel_data_inventory": data,
                    "lookup_native_plan": lookup,
                    "abi_plan": abi,
                }.items()
            }

        self.assertEqual(
            manifest["phase"], "compiled-kernel-program-lookup-operation"
        )
        self.assertEqual(
            manifest["theorem"],
            INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM,
        )
        self.assertEqual(manifest["remaining_proof_premises"], [])
        self.assertFalse(manifest["proof_authority"])
        self.assertEqual(
            resources,
            {
                "GeneratedRelationalInterpreterKernelProgramLookupOperation": {
                    "resource_class": "high-memory",
                    "estimated_memory_mb": 16384,
                }
            },
        )
        self.assertEqual(set(manifest["inputs"]), set(expected_inputs))
        for role, expected in expected_inputs.items():
            with self.subTest(role=role):
                self.assertEqual(manifest["inputs"][role], expected)
        self.assertIn(
            "theorem generatedProgramLookupOperationRefinesUsing", source
        )

    def test_nix_phase_is_in_proof_sources_and_exported(self) -> None:
        lane = self.lane.read_text(encoding="utf-8")
        flake = self.flake.read_text(encoding="utf-8")
        phase_start = lane.index("kernelLookupOperationLean = mkPhase")
        phase_end = lane.index("kernelStepLean =", phase_start)
        phase = lane[phase_start:phase_end]
        proof_start = lane.index("proofSources = mkPhase")
        proof_end = lane.index("proofModules =", proof_start)
        proof_sources = lane[proof_start:proof_end]

        for required in (
            "kernel-lookup-operation",
            "--candidate ${candidate}/candidate.exe",
            "--kernel-plan ${kernelLean}/interpreter-kernel-plan.json",
            "--kernel-data-inventory ${kernelDataLean}/module-inventory.json",
            "${kernelLookupNativeLean}/"
            "interpreter-kernel-lookup-native-plan.json",
            "--abi-plan ${kernelAbiLean}/interpreter-kernel-abi-plan.json",
            INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM,
        ):
            self.assertIn(required, phase)
        self.assertIn("--source ${kernelLookupOperationLean}", proof_sources)
        self.assertIn("kernelLookupOperationLean", lane)
        self.assertIn(
            "stage-a-gnu-hello-roundtrip-kernel-lookup-operation-source",
            flake,
        )


if __name__ == "__main__":
    unittest.main()
