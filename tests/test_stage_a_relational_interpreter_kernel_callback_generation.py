from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.pe_fixtures import pe32_image

from spaghetti_extractor.relational.lean.interpreter_kernel import (
    build_relational_interpreter_kernel_plan,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_callback import (
    INTERPRETER_KERNEL_CALLBACK_CONTRACT_FORMAT,
    build_relational_interpreter_kernel_callback_plan,
    propose_stage_b_interpreter_kernel_callback_contract,
    relational_interpreter_kernel_callback_source,
)
from spaghetti_extractor.relational.lean import interpreter_kernel_callback
from spaghetti_extractor.stage_binary import _parse_stage_a_pe


class StageARelationalInterpreterKernelCallbackGenerationTests(unittest.TestCase):
    def test_bridge_table_is_not_required_without_bridge_dispatch_site(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        candidate = root / "candidate.exe"
        linker_map = root / "candidate.map"
        engine_plan = root / "engine.json"
        candidate.write_bytes(pe32_image(b"\xc3"))
        linker_map.write_text("", encoding="utf-8")
        engine_plan.write_text('{"external_sites": []}', encoding="utf-8")

        with (
            mock.patch.object(
                interpreter_kernel_callback,
                "_discover_indirect_sites",
                return_value=(),
            ),
            mock.patch.object(
                interpreter_kernel_callback,
                "_unique_symbol",
                return_value=0x2000,
            ),
            mock.patch.object(
                interpreter_kernel_callback,
                "_locate_bridge_table",
                side_effect=AssertionError("bridge table lookup was not lazy"),
            ),
        ):
            contract = propose_stage_b_interpreter_kernel_callback_contract(
                candidate_pe=candidate,
                kernel_plan={"kernel_functions": []},
                linker_map=linker_map,
                native_engine_plan=engine_plan,
            )

        self.assertEqual(contract["sites"], [])

    def test_current_three_argument_undefined_hook_is_classified(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        candidate = root / "candidate.exe"
        linker_map = root / "candidate.map"
        engine_plan = root / "engine.json"
        candidate.write_bytes(pe32_image(b"\xc3"))
        linker_map.write_text("", encoding="utf-8")
        engine_plan.write_text('{"external_sites": []}', encoding="utf-8")
        parsed = _parse_stage_a_pe(candidate)
        site = interpreter_kernel_callback._IndirectSite(
            function_role="helper",
            instruction=interpreter_kernel_callback._Instruction(
                rva=0x1000, data=b"\xff\xd0"
            ),
            prefix=(),
            target_operand={"kind": "register", "register": "eax"},
            target_register="eax",
            target_field_offset=12,
            argument_offsets=(0, 4, 8),
        )

        with (
            mock.patch.object(
                interpreter_kernel_callback,
                "_discover_indirect_sites",
                return_value=(site,),
            ),
            mock.patch.object(
                interpreter_kernel_callback,
                "_map_symbols",
                return_value=(),
            ),
            mock.patch.object(
                interpreter_kernel_callback,
                "_unique_symbol",
                return_value=0x2000,
            ),
            mock.patch.object(
                interpreter_kernel_callback,
                "_read_u32",
                return_value=parsed.image_base + 0x1100,
            ),
            mock.patch.object(
                interpreter_kernel_callback,
                "_pointer_to_rva",
                return_value=0x1100,
            ),
        ):
            contract = propose_stage_b_interpreter_kernel_callback_contract(
                candidate_pe=candidate,
                kernel_plan={"kernel_functions": []},
                linker_map=linker_map,
                native_engine_plan=engine_plan,
            )

        self.assertEqual(len(contract["sites"]), 1)
        classified = contract["sites"][0]
        self.assertEqual(classified["role"], "runtime_undefined_value")
        self.assertEqual(classified["argument_count"], 3)
        self.assertEqual(classified["pointer_cells"], [0x200C])
        self.assertEqual(classified["target_rvas"], [0x1100])

    def test_four_argument_undefined_hook_is_classified(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        candidate = root / "candidate.exe"
        linker_map = root / "candidate.map"
        engine_plan = root / "engine.json"
        candidate.write_bytes(pe32_image(b"\xc3"))
        linker_map.write_text("", encoding="utf-8")
        engine_plan.write_text('{"external_sites": []}', encoding="utf-8")
        parsed = _parse_stage_a_pe(candidate)
        site = interpreter_kernel_callback._IndirectSite(
            function_role="helper",
            instruction=interpreter_kernel_callback._Instruction(
                rva=0x1000, data=b"\xff\xd0"
            ),
            prefix=(),
            target_operand={"kind": "register", "register": "eax"},
            target_register="eax",
            target_field_offset=12,
            argument_offsets=(0, 4, 8, 12),
        )

        with (
            mock.patch.object(
                interpreter_kernel_callback,
                "_discover_indirect_sites",
                return_value=(site,),
            ),
            mock.patch.object(
                interpreter_kernel_callback,
                "_map_symbols",
                return_value=(),
            ),
            mock.patch.object(
                interpreter_kernel_callback,
                "_unique_symbol",
                return_value=0x2000,
            ),
            mock.patch.object(
                interpreter_kernel_callback,
                "_read_u32",
                return_value=parsed.image_base + 0x1100,
            ),
            mock.patch.object(
                interpreter_kernel_callback,
                "_pointer_to_rva",
                return_value=0x1100,
            ),
        ):
            contract = propose_stage_b_interpreter_kernel_callback_contract(
                candidate_pe=candidate,
                kernel_plan={"kernel_functions": []},
                linker_map=linker_map,
                native_engine_plan=engine_plan,
            )

        self.assertEqual(len(contract["sites"]), 1)
        classified = contract["sites"][0]
        self.assertEqual(classified["role"], "runtime_undefined_value")
        self.assertEqual(classified["argument_count"], 4)
        self.assertEqual(classified["pointer_cells"], [0x200C])
        self.assertEqual(classified["target_rvas"], [0x1100])

    def test_unknown_target_remains_incomplete(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        candidate = root / "candidate.exe"
        candidate.write_bytes(pe32_image(b"\xff\xd0\xc3"))
        parsed = _parse_stage_a_pe(candidate)
        kernel_plan = {
            "kernel_functions": [{
                "role": "interpreterStep",
                "blocks": [{
                    "instructions": [
                        {"rva": 0x1000, "bytes": "ffd0", "mnemonic": "call"}
                    ]
                }],
            }]
        }
        contract = {
            "format": INTERPRETER_KERNEL_CALLBACK_CONTRACT_FORMAT,
            "candidate_sha256": parsed.sha256,
            "sites": [{
                "site_rva": 0x1000,
                "role": "unknown",
                "argument_count": 0,
                "return_kind": "word_in_eax",
                "target_provenance": "unknown",
                "pointer_cells": [],
                "target_rvas": [],
                "dynamic_requirements": ["finite_target_inventory_required"],
            }],
        }

        plan = build_relational_interpreter_kernel_callback_plan(
            candidate_pe=candidate,
            kernel_plan=kernel_plan,
            classification_contract=contract,
        )
        payload = plan.payload()
        self.assertEqual(payload["status"], "incomplete")
        self.assertFalse(payload["acceptance_authority"])
        self.assertEqual(payload["counts"]["classified_sites"], 0)
        self.assertEqual(payload["counts"]["indirect_sites"], 1)
        self.assertEqual(
            [issue.code for issue in plan.issues],
            ["unknown_indirect_callback_target"],
        )

    def test_generated_source_contains_goals_not_certificates(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        candidate = root / "candidate.exe"
        candidate.write_bytes(pe32_image(b"\xff\xd0\xc3"))
        parsed = _parse_stage_a_pe(candidate)
        plan = build_relational_interpreter_kernel_callback_plan(
            candidate_pe=candidate,
            kernel_plan={
                "kernel_functions": [{
                    "role": "interpreterStep",
                    "blocks": [{"instructions": [
                        {"rva": 0x1000, "bytes": "ffd0", "mnemonic": "call"}
                    ]}],
                }]
            },
            classification_contract={
                "format": INTERPRETER_KERNEL_CALLBACK_CONTRACT_FORMAT,
                "candidate_sha256": parsed.sha256,
                "sites": [],
            },
        )
        source = relational_interpreter_kernel_callback_source(plan)
        self.assertIn("GeneratedKernelCallbackStaticGoal", source)
        self.assertIn("GeneratedKernelCallbackRefinementGoal", source)
        self.assertIn("generatedKernelCallbackTargetCells", source)
        self.assertIn("GeneratedKernelCallbackEntryRefinementGoal", source)
        self.assertIn("GeneratedKernelCallbackAwareOperationGoal", source)
        self.assertIn("generatedNativeIndirectTargetInventory", source)
        self.assertIn("GeneratedKernelCallbackNativeWorldGoal", source)
        self.assertIn("ExactKernelCallbackNativeWorldBinding", source)
        self.assertNotRegex(source, r"\btheorem\b")
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)


class StageARelationalInterpreterKernelCallbackGNUHelloTests(unittest.TestCase):
    root = Path(__file__).parents[1] / "build/stage-b-gnu-hello-roundtrip"

    @classmethod
    def setUpClass(cls) -> None:
        required = (
            cls.root / "interpreter-candidate-v5/candidate.exe",
            cls.root / "interpreter-candidate-v5/payload.map",
            cls.root / "interpreter-candidate-v5/engine-layout.bin",
            cls.root
            / "interpreter-candidate-v5/interpreter-native-build-manifest.json",
            cls.root
            / "interpreter-x87-schedule-v3/state-machine-interpreter-program.json",
            cls.root / "native-engine-v10/native-engine-plan.json",
        )
        if not all(path.is_file() for path in required):
            raise unittest.SkipTest("GNU hello round-trip kernel artifacts unavailable")

    def test_classifies_all_eight_current_kernel_sites(self) -> None:
        root = self.root
        kernel = build_relational_interpreter_kernel_plan(
            candidate_pe=root / "interpreter-candidate-v5/candidate.exe",
            linker_map=root / "interpreter-candidate-v5/payload.map",
            interpreter_program_manifest=(
                root
                / "interpreter-x87-schedule-v3/state-machine-interpreter-program.json"
            ),
            engine_layout=root / "interpreter-candidate-v5/engine-layout.bin",
            native_build_manifest=(
                root
                / "interpreter-candidate-v5/interpreter-native-build-manifest.json"
            ),
        )
        contract = propose_stage_b_interpreter_kernel_callback_contract(
            candidate_pe=root / "interpreter-candidate-v5/candidate.exe",
            kernel_plan=kernel,
            linker_map=root / "interpreter-candidate-v5/payload.map",
            native_engine_plan=root / "native-engine-v10/native-engine-plan.json",
        )
        plan = build_relational_interpreter_kernel_callback_plan(
            candidate_pe=root / "interpreter-candidate-v5/candidate.exe",
            kernel_plan=kernel,
            classification_contract=contract,
        )
        payload = plan.payload()

        self.assertEqual(payload["counts"]["indirect_sites"], 8)
        self.assertEqual(payload["counts"]["classified_sites"], 8)
        self.assertEqual(payload["counts"]["finite_targets"], 395)
        self.assertEqual(payload["counts"]["static_frontiers"], 0)
        self.assertEqual(payload["counts"]["pending_lean_obligations"], 56)
        self.assertFalse(plan.issues)
        self.assertEqual(
            [(site.rva, site.role, len(site.argument_offsets)) for site in plan.sites],
            [
                (0x631A6, "runtime_read", 4),
                (0x6322C, "native_bridge_dispatch", 0),
                (0x63328, "runtime_read", 4),
                (0x6337B, "runtime_write", 5),
                (0x633B0, "runtime_undefined_value", 2),
                (0x65FD3, "runtime_replay_checked_x87", 4),
                (0x661AA, "runtime_resolve_code_target", 3),
                (0x662C7, "runtime_resolve_code_target", 3),
            ],
        )
        self.assertTrue(all(site.dynamic_requirements for site in plan.sites))
        self.assertTrue(
            all(target.entry_bytes for site in plan.sites for target in site.targets)
        )


if __name__ == "__main__":
    unittest.main()
