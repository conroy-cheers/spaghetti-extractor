from __future__ import annotations

import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    INTERPRETER_KERNEL_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_block import (
    INTERPRETER_KERNEL_BLOCK_PLAN_FORMAT,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_helper_path import (
    INTERPRETER_KERNEL_HELPER_PATH_FORMAT,
    RelationalInterpreterKernelHelperPathGenerationError,
    build_relational_interpreter_kernel_helper_path_plan,
    relational_interpreter_kernel_helper_path_source,
    write_relational_interpreter_kernel_helper_path_bundle,
)


def _block(entry: int, successors: list[int], mnemonic: str, data: str) -> dict:
    return {
        "entry_rva": entry,
        "successors": successors,
        "instructions": [
            {"rva": entry, "bytes": data, "mnemonic": mnemonic}
        ],
    }


class StageARelationalInterpreterKernelHelperPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.kernel = self.root / "interpreter-kernel-plan.json"
        self.blocks = self.root / "interpreter-kernel-block-plan.json"
        digest = "a" * 64
        helper_blocks = [
            _block(0x100, [0x110, 0x120], "jne", "750e"),
            _block(0x110, [0x130], "jmp", "eb1e"),
            _block(0x120, [0x130], "jmp", "eb0e"),
            _block(0x130, [0x140], "call", "ff15"),
            _block(0x140, [], "ret", "c3"),
        ]
        kernel = {
            "format": INTERPRETER_KERNEL_PLAN_FORMAT,
            "candidate": {"pe_sha256": digest, "size": 4096},
            "kernel_functions": [
                {
                    "role": "helper 256",
                    "rva_start": 0x100,
                    "rva_end": 0x141,
                    "size": 0x41,
                    "sha256": "b" * 64,
                    "blocks": helper_blocks,
                    "x87_frames": [],
                }
            ],
            "issues": [],
        }
        obligations = [
            {
                "id": f"compiled-kernel-block:{block['entry_rva']:08x}",
                "ordinal": index,
                "function_index": 0,
                "block_index": index,
                "function_role": "helper 256",
                "entry_rva": block["entry_rva"],
                "instruction_count": len(block["instructions"]),
                "status": "pending_lean_universal_agreement",
            }
            for index, block in enumerate(helper_blocks)
        ]
        block_plan = {
            "format": INTERPRETER_KERNEL_BLOCK_PLAN_FORMAT,
            "candidate_sha256": digest,
            "source_module": "GeneratedRelationalInterpreterKernel",
            "source_namespace": "StageA.GeneratedRelational.InterpreterKernel",
            "context_module": "GeneratedRelationalInterpreterKernelBlockContext",
            "module_prefix": "GeneratedRelationalInterpreterKernelBlockShard",
            "shard_size": 2,
            "proof_obligations": obligations,
        }
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        self.blocks.write_text(json.dumps(block_plan), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _build(self, **kwargs):
        return build_relational_interpreter_kernel_helper_path_plan(
            kernel_plan=self.kernel,
            block_plan=self.blocks,
            helper_entry_rva=0x100,
            external_call_rvas=[0x130],
            **kwargs,
        )

    def test_builds_strict_acyclic_diamond_with_decreasing_ranks(self) -> None:
        plan = self._build()
        payload = plan.payload()
        self.assertEqual(payload["format"], INTERPRETER_KERNEL_HELPER_PATH_FORMAT)
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["control_mode"], "strict-acyclic")
        self.assertIn(
            "well_founded_multi_block_composition",
            payload["closed_components"],
        )
        self.assertEqual(
            payload["remaining_proof_premises"],
            [
                "per_block_universal_symbolic_concrete_agreement",
                "entry_invariant_establishment",
                "per_node_exact_computed_progress",
            ],
        )
        self.assertEqual([node.entry_rva for node in plan.nodes], [
            0x100,
            0x110,
            0x130,
            0x120,
        ])
        by_entry = {node.entry_rva: node for node in plan.nodes}
        self.assertGreater(by_entry[0x100].rank, by_entry[0x110].rank)
        self.assertGreater(by_entry[0x100].rank, by_entry[0x120].rank)
        self.assertGreater(by_entry[0x110].rank, by_entry[0x130].rank)
        self.assertEqual(by_entry[0x130].targets, ())
        self.assertEqual(
            plan.required_block_modules,
            (
                "GeneratedRelationalInterpreterKernelBlockShard0000",
                "GeneratedRelationalInterpreterKernelBlockShard0001",
            ),
        )

    def test_source_requires_reflective_agreements_and_local_progress(
        self,
    ) -> None:
        source = relational_interpreter_kernel_helper_path_source(self._build())
        for required in (
            "generatedHelperPathGraphStrictChecked",
            "GeneratedHelperPathBlockAgreements",
            "generatedHelperPathReflectiveInventory",
            "GeneratedHelperPathEntryInvariantGoal",
            "GeneratedHelperPathNodeProgressGoals",
            "ExactComputedHelperNodeProgress",
            "generatedHelperPathLocalProgressCertificate",
            "generatedUniversalHelperPathExecutionCertificate",
        ):
            self.assertIn(required, source)
        self.assertIn("UniversalAgreementGoal", source)
        self.assertIn("control := Or.inl", source)
        for forbidden in (
            "GeneratedHelperPathCompletionGoal",
            "universal_exact_helper_path_completion",
            "complete := completion",
        ):
            self.assertNotIn(forbidden, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_rejects_cycles_and_unresolved_exits_without_authority(self) -> None:
        kernel = json.loads(self.kernel.read_text(encoding="utf-8"))
        kernel["kernel_functions"][0]["blocks"][1]["successors"] = [0x100]
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelHelperPathGenerationError,
            "cyclic helper path",
        ):
            self._build()

        kernel["kernel_functions"][0]["blocks"][1]["successors"] = []
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelHelperPathGenerationError,
            "unresolved helper-path exit",
        ):
            self._build()

    def test_exceptional_control_requires_explicit_targets_and_typed_authority(
        self,
    ) -> None:
        kernel = json.loads(self.kernel.read_text(encoding="utf-8"))
        kernel["kernel_functions"][0]["blocks"][1]["successors"] = []
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelHelperPathGenerationError,
            "require explicit invariant/ranking authority",
        ):
            self._build(exceptional_targets={0x110: [0x130]})

        plan = self._build(
            exceptional_targets={0x110: [0x130]},
            exceptional_authority="helper_path_frame_invariant_v1",
        )
        self.assertEqual(plan.payload()["control_mode"], "typed-invariant-ranking")
        source = relational_interpreter_kernel_helper_path_source(plan)
        self.assertIn("exceptionalAuthority :", source)
        self.assertIn("HelperPathInvariantRankingAuthority", source)
        self.assertIn("control := Or.inr", source)
        self.assertNotIn("generatedHelperPathGraphStrictChecked", source)

    def test_rejects_ambiguous_blocks_targets_and_stale_certificates(self) -> None:
        kernel = json.loads(self.kernel.read_text(encoding="utf-8"))
        duplicate = {
            "role": "helper 512",
            "rva_start": 0x200,
            "rva_end": 0x210,
            "size": 0x10,
            "sha256": "c" * 64,
            "blocks": [_block(0x110, [0x130], "jmp", "eb1e")],
            "x87_frames": [],
        }
        kernel["kernel_functions"].append(duplicate)
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelHelperPathGenerationError,
            "ambiguous compiled block",
        ):
            self._build()

        kernel["kernel_functions"].pop()
        kernel["kernel_functions"][0]["blocks"][0]["successors"] = [0x110, 0x110]
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelHelperPathGenerationError,
            "duplicate targets",
        ):
            self._build()

        kernel["kernel_functions"][0]["blocks"][0]["successors"] = [0x110, 0x120]
        self.kernel.write_text(json.dumps(kernel), encoding="utf-8")
        block_plan = json.loads(self.blocks.read_text(encoding="utf-8"))
        block_plan["proof_obligations"][1]["block_index"] = 4
        self.blocks.write_text(json.dumps(block_plan), encoding="utf-8")
        with self.assertRaisesRegex(
            RelationalInterpreterKernelHelperPathGenerationError,
            "lacks its exact reflective certificate",
        ):
            self._build()

    def test_writer_is_deterministic(self) -> None:
        first = self.root / "first"
        second = self.root / "second"
        kwargs = {
            "kernel_plan": self.kernel,
            "block_plan": self.blocks,
            "helper_entry_rva": 0x100,
            "external_call_rvas": [0x130],
        }
        write_relational_interpreter_kernel_helper_path_bundle(
            out=first, **kwargs
        )
        write_relational_interpreter_kernel_helper_path_bundle(
            out=second, **kwargs
        )
        self.assertEqual(
            sorted(path.name for path in first.iterdir()),
            sorted(path.name for path in second.iterdir()),
        )
        for path in first.iterdir():
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())


if __name__ == "__main__":
    unittest.main()
