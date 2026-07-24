from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

if "tests" not in sys.modules:
    tests_package = types.ModuleType("tests")
    tests_package.__path__ = [str(Path(__file__).parent)]
    sys.modules["tests"] = tests_package

from tests.test_stage_b_interpreter_native_build import _Packages

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    build_relational_interpreter_kernel_plan,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_block import (
    INTERPRETER_KERNEL_BLOCK_MODULE_INVENTORY_FILENAME,
    INTERPRETER_KERNEL_BLOCK_PLAN_FILENAME,
    RelationalInterpreterKernelBlockGenerationError,
    build_relational_interpreter_kernel_block_plan,
    relational_interpreter_kernel_block_bundle_sources,
    write_relational_interpreter_kernel_block_bundle,
)
from spaghetti_extractor.stage_b_interpreter_native_build import (
    INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME,
    build_stage_b_interpreter_native_candidate,
)


@unittest.skipUnless(
    shutil.which("i686-w64-mingw32-gcc"), "i686 MinGW compiler unavailable"
)
class StageARelationalInterpreterKernelBlockGenerationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.packages = _Packages(cls.root / "inputs")
        cls.candidate = cls.root / "candidate"
        build_stage_b_interpreter_native_candidate(
            interpreter_package=cls.packages.interpreter,
            native_engine_package=cls.packages.engine,
            native_runtime_package=cls.packages.runtime,
            load_image_contract=cls.packages.contract,
            anchor_manifest=cls.packages.anchors,
            out_dir=cls.candidate,
        )
        cls.kernel_plan = build_relational_interpreter_kernel_plan(
            candidate_pe=cls.candidate / "candidate.exe",
            linker_map=cls.candidate / "payload.map",
            interpreter_program_manifest=(
                cls.packages.interpreter / "state-machine-interpreter-program.json"
            ),
            engine_layout=cls.candidate / "engine-layout.bin",
            native_build_manifest=(
                cls.candidate / INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME
            ),
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_partitions_every_block_into_deterministic_proof_shards(self) -> None:
        plan = build_relational_interpreter_kernel_block_plan(
            self.kernel_plan,
            candidate_pe=self.candidate / "candidate.exe",
            shard_size=17,
        )
        expected_blocks = sum(
            len(function.blocks) for function in self.kernel_plan.functions
        )
        expected_instructions = sum(
            len(block.instructions)
            for function in self.kernel_plan.functions
            for block in function.blocks
        )
        self.assertEqual(len(plan.obligations), expected_blocks)
        self.assertEqual(
            tuple(item for shard in plan.shards for item in shard),
            plan.obligations,
        )
        self.assertEqual(
            sum(item.instruction_count for item in plan.obligations),
            expected_instructions,
        )
        self.assertEqual(
            [item.ordinal for item in plan.obligations],
            list(range(expected_blocks)),
        )
        self.assertEqual(
            len({item.entry_rva for item in plan.obligations}), expected_blocks
        )
        payload = plan.payload()
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["counts"]["closed_universal_agreements"], 0)
        self.assertTrue(
            all(
                item["status"] == "pending_lean_universal_agreement"
                for item in payload["proof_obligations"]
            )
        )

    def test_sources_reflect_exact_data_but_require_universal_proofs(self) -> None:
        plan = build_relational_interpreter_kernel_block_plan(
            self.kernel_plan,
            candidate_pe=self.candidate / "candidate.exe",
            shard_size=29,
        )
        sources = relational_interpreter_kernel_block_bundle_sources(plan)
        context = sources[plan.context_module]
        self.assertIn("parsePE32Tree generatedKernelCandidateBytes", context)
        self.assertIn("parseImports generatedKernelBlockCandidatePe", context)
        self.assertIn("decide +kernel", context)

        shard = sources[f"{plan.module_prefix}0000"]
        self.assertIn("reflectKernelBlock?", shard)
        self.assertIn("UniversalAgreementGoal", shard)
        self.assertIn("forall input", shard)
        self.assertIn("runKernelBlockConcrete", shard)
        self.assertRegex(
            shard,
            re.compile(r"theorem generatedKernelBlock\d+Sound\s+\(agreement :"),
        )
        for source in sources.values():
            for marker in ("sorry", "axiom", "unsafe", "native_decide"):
                self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_writes_nix_graph_ready_inventory_without_claiming_proof(self) -> None:
        output = self.root / "block-proof-bundle"
        plan = write_relational_interpreter_kernel_block_bundle(
            out=output,
            kernel_plan=self.kernel_plan,
            candidate_pe=self.candidate / "candidate.exe",
            shard_size=31,
        )
        payload = json.loads(
            (output / INTERPRETER_KERNEL_BLOCK_PLAN_FILENAME).read_text(
                encoding="utf-8"
            )
        )
        inventory = json.loads(
            (
                output / INTERPRETER_KERNEL_BLOCK_MODULE_INVENTORY_FILENAME
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(payload["status"], "proof-obligations-generated")
        self.assertFalse(inventory["proof_authority"])
        self.assertEqual(inventory["counts"]["blocks"], len(plan.obligations))
        self.assertEqual(
            len(inventory["targets"]["shard_nodes"]), len(plan.shards)
        )
        for module in inventory["modules"]:
            self.assertTrue((output / "StageA" / f"{module}.lean").is_file())

    def test_rejects_stale_candidate_and_invalid_shard_size(self) -> None:
        stale = self.root / "stale.exe"
        data = bytearray((self.candidate / "candidate.exe").read_bytes())
        data[-1] ^= 1
        stale.write_bytes(data)
        with self.assertRaisesRegex(
            RelationalInterpreterKernelBlockGenerationError,
            "differs from the compiled-kernel plan",
        ):
            build_relational_interpreter_kernel_block_plan(
                self.kernel_plan,
                candidate_pe=stale,
            )
        with self.assertRaisesRegex(
            RelationalInterpreterKernelBlockGenerationError, "shard size"
        ):
            build_relational_interpreter_kernel_block_plan(
                self.kernel_plan,
                candidate_pe=self.candidate / "candidate.exe",
                shard_size=0,
            )


if __name__ == "__main__":
    unittest.main()
