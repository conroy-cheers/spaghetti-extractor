from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_operation_behavior_materialization import (
    InterpreterKernelOperationBehaviorMaterializationError,
    run_entry_behavior_materialization_source,
    write_run_entry_behavior_materialization_bundle,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_entry_route import (
    build_run_entry_route,
    run_entry_behavior_request_payload,
)


def _operation_manifest() -> dict[str, object]:
    def instructions(start: int) -> list[dict[str, int]]:
        return [
            {"ordinal": 0, "rva": start, "size": 1},
            {"ordinal": 1, "rva": start + 1, "size": 1},
        ]

    return {
        "format": (
            "stage-a-relational-interpreter-kernel-operation-instantiation-v1"
        ),
        "candidate": {"sha256": "b" * 64, "size": 4096},
        "checked_native_replay_inventory": {
            "function_replays": [
                {
                    "ordinal": 9,
                    "entry_rva": 0x1000,
                    "role": "runFunction",
                    "families": ["run"],
                    "block_graph": [
                        {
                            "ordinal": 0,
                            "entry_rva": 0x1000,
                            "terminal_class": "branch",
                            "successors": [0x1020],
                            "instructions": instructions(0x1000),
                        },
                        {
                            "ordinal": 1,
                            "entry_rva": 0x1020,
                            "terminal_class": "bulk",
                            "successors": [0x1030],
                            "instructions": instructions(0x1020),
                        },
                        {
                            "ordinal": 2,
                            "entry_rva": 0x1030,
                            "terminal_class": "call",
                            "successors": [0x2000, 0x1040],
                            "instructions": instructions(0x1030),
                        },
                    ],
                }
            ]
        },
    }


def _extraction(request: dict[str, object]) -> dict[str, object]:
    term = "StageA.Formal.initialSymbolic"
    digest = hashlib.sha256(term.encode("utf-8")).hexdigest()
    return {
        "format": "stage-a-relational-side-extraction-v1",
        "profile": request["profile"],
        "model": request["model"],
        "status": "untrusted_proposal_requires_lean_decode_replay",
        "side": "candidate",
        "binary_sha256": request["binary_sha256"],
        "request_sha256": "c" * 64,
        "decoder_semantics_sha256": "d" * 64,
        "regions": [
            {
                **region,
                "behavior_term": term,
                "behavior_sha256": digest,
            }
            for region in request["regions"]
        ],
    }


class OperationBehaviorMaterializationTests(unittest.TestCase):
    def test_emits_exact_decoder_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "operation.json"
            manifest.write_text(
                json.dumps(_operation_manifest()), encoding="utf-8"
            )
            route = build_run_entry_route(manifest)
            source = run_entry_behavior_materialization_source(
                route,
                tuple(
                    "StageA.Formal.initialSymbolic"
                    for _ in run_entry_behavior_request_payload(route)["regions"]
                ),
            )
            for ordinal in (0, 1):
                self.assertIn(
                    "import StageA."
                    "GeneratedRelationalInterpreterKernelOperation"
                    f"BlockFunction0009Block{ordinal:04d}",
                    source,
                )
            self.assertNotIn(
                "import StageA."
                "GeneratedRelationalInterpreterKernelOperation"
                "BlockFunction0009\n",
                source,
            )
            self.assertIn(
                "generatedRunEntryBlock1Instruction0001MaterializedBehaviorExact",
                source,
            )
            self.assertIn(
                "generatedRunEntryBlock1Instruction0001"
                "MaterializedBehaviorEdgeBehaviorExact",
                source,
            )
            self.assertIn(
                (
                    "{ (StageA.Formal.initialSymbolic : SymbolicBehavior) "
                    "with outcome := none }"
                ),
                source,
            )
            self.assertIn("decide +kernel", source)
            self.assertIn(
                (
                    "#print axioms StageA.GeneratedRelational."
                    "InterpreterKernelOperationInstantiation."
                    "generatedRunEntryBlock1Instruction0001"
                    "MaterializedBehaviorExact"
                ),
                source,
            )
            self.assertNotIn("native_decide", source)

    def test_rejects_corrupted_behavior_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "operation.json"
            manifest.write_text(
                json.dumps(_operation_manifest()), encoding="utf-8"
            )
            route = build_run_entry_route(manifest)
            extraction = _extraction(run_entry_behavior_request_payload(route))
            extraction["regions"][0]["behavior_sha256"] = "0" * 64
            extraction_path = root / "extraction.json"
            extraction_path.write_text(
                json.dumps(extraction), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                InterpreterKernelOperationBehaviorMaterializationError,
                "term mismatch",
            ):
                write_run_entry_behavior_materialization_bundle(
                    operation_manifest=manifest,
                    extraction=extraction_path,
                    out=root / "out",
                )


if __name__ == "__main__":
    unittest.main()
