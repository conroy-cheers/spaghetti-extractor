from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_import_image
from tests.stage_a_relational_support import _pe32_image_with_immutable_indirect_call

from spaghetti_extractor.relational.lean.interpreter_kernel_callback import (
    INTERPRETER_KERNEL_CALLBACK_CONTRACT_FORMAT,
    InterpreterKernelCallbackPlan,
    build_relational_interpreter_kernel_callback_plan,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_indirect import (
    build_relational_interpreter_kernel_indirect_plan,
    relational_interpreter_kernel_indirect_source,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe


def _kernel_plan(instruction_rva: int, instruction: bytes) -> dict[str, object]:
    return {
        "kernel_functions": [{
            "role": "fixtureKernel",
            "blocks": [{
                "entry_rva": instruction_rva,
                "instructions": [{
                    "rva": instruction_rva,
                    "bytes": instruction.hex(),
                    "mnemonic": "call",
                }],
                "successors": [instruction_rva + len(instruction)],
            }],
        }],
        "issues": [{
            "code": "unsupported_indirect_kernel_call",
            "function_role": "fixtureKernel",
            "message": "fixture indirect call",
            "rva_start": instruction_rva,
            "rva_end": instruction_rva + len(instruction),
        }],
    }


class StageARelationalInterpreterKernelIndirectGenerationTests(unittest.TestCase):
    def _relocation_case(
        self, *, writable: bool, include_preservation: bool = True
    ) -> tuple[dict[str, object], InterpreterKernelCallbackPlan, Path]:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        candidate = root / "candidate.exe"
        data_rva = 0x3000
        target_rva = 0x1030
        candidate.write_bytes(_pe32_image_with_immutable_indirect_call(
            data_rva, callee_rva=target_rva, writable=writable,
            argument_writes=False,
        ))
        instruction = b"\xff\x15" + struct.pack("<I", 0x400000 + data_rva)
        kernel = _kernel_plan(0x1000, instruction)
        parsed = _parse_stage_a_pe(candidate)
        requirements = ["callback_target_execution_refinement"]
        if include_preservation:
            requirements.extend((
                "runtime_pointer_identity",
                "runtime_target_cell_preserved",
            ))
        callback = build_relational_interpreter_kernel_callback_plan(
            candidate_pe=candidate,
            kernel_plan=kernel,
            classification_contract={
                "format": INTERPRETER_KERNEL_CALLBACK_CONTRACT_FORMAT,
                "candidate_sha256": parsed.sha256,
                "sites": [{
                    "site_rva": 0x1000,
                    "role": "fixture_callback",
                    "argument_count": 0,
                    "return_kind": "word_in_eax",
                    "target_provenance": "explicit_fixture",
                    "pointer_cells": [data_rva],
                    "target_rvas": [target_rva],
                    "dynamic_requirements": requirements,
                }],
            },
        )
        return kernel, callback, candidate

    def test_writable_relocation_is_classified_with_preservation_obligation(self) -> None:
        kernel, callback, candidate = self._relocation_case(writable=True)
        plan = build_relational_interpreter_kernel_indirect_plan(
            candidate_pe=candidate, kernel_plan=kernel, callback_plan=callback
        )
        payload = plan.payload()

        self.assertEqual(payload["classification_status"], "satisfied")
        self.assertEqual(payload["counts"]["classified_sites"], 1)
        self.assertEqual(payload["counts"]["writable_relocation_sites"], 1)
        self.assertEqual(payload["counts"]["resolved_kernel_frontiers"], 1)
        self.assertEqual(payload["sites"][0]["cells"][0]["provenance"],
                         "writable_relocation_cell")
        self.assertTrue(payload["sites"][0]["cells"][0][
            "requires_runtime_preservation"
        ])
        self.assertFalse(plan.issues)

    def test_writable_relocation_without_preservation_fails_closed(self) -> None:
        kernel, callback, candidate = self._relocation_case(
            writable=True, include_preservation=False
        )
        plan = build_relational_interpreter_kernel_indirect_plan(
            candidate_pe=candidate, kernel_plan=kernel, callback_plan=callback
        )

        self.assertEqual(plan.payload()["classification_status"], "incomplete")
        self.assertEqual(plan.payload()["counts"]["classified_sites"], 0)
        self.assertIn(
            "writable_target_cell_unbounded",
            {issue.code for issue in plan.issues},
        )

    def test_immutable_relocation_does_not_require_dynamic_preservation(self) -> None:
        kernel, callback, candidate = self._relocation_case(
            writable=False, include_preservation=False
        )
        plan = build_relational_interpreter_kernel_indirect_plan(
            candidate_pe=candidate, kernel_plan=kernel, callback_plan=callback
        )

        self.assertEqual(plan.payload()["classification_status"], "satisfied")
        self.assertEqual(
            plan.payload()["sites"][0]["cells"][0]["provenance"],
            "immutable_relocation_cell",
        )

    def test_direct_iat_call_is_classified_by_exact_import_identity(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        candidate = root / "candidate.exe"
        instruction = b"\xff\x15" + struct.pack("<I", 0x402040)
        candidate.write_bytes(pe32_import_image(
            instruction + b"\xc3", symbol="WriteFile", iat_offset=0x40
        ))
        parsed = _parse_stage_a_pe(candidate)
        callback = InterpreterKernelCallbackPlan(
            candidate_sha256=parsed.sha256,
            candidate_size=parsed.size,
            sites=(),
            issues=(),
        )
        plan = build_relational_interpreter_kernel_indirect_plan(
            candidate_pe=candidate,
            kernel_plan=_kernel_plan(0x1000, instruction),
            callback_plan=callback,
        )

        payload = plan.payload()
        self.assertEqual(payload["classification_status"], "satisfied")
        self.assertEqual(payload["counts"]["iat_sites"], 1)
        self.assertEqual(payload["sites"][0]["kind"], "iat_import")
        self.assertEqual(bytes.fromhex(payload["sites"][0]["import"]["symbol_hex"]),
                         b"WriteFile")

    def test_unknown_register_target_remains_incomplete(self) -> None:
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        candidate = root / "candidate.exe"
        candidate.write_bytes(_pe32_image_with_immutable_indirect_call(
            0x3000, writable=True, argument_writes=False
        ))
        image = bytearray(candidate.read_bytes())
        image[0x200:0x202] = b"\xff\xd0"
        candidate.write_bytes(image)
        parsed = _parse_stage_a_pe(candidate)
        callback = InterpreterKernelCallbackPlan(
            candidate_sha256=parsed.sha256,
            candidate_size=parsed.size,
            sites=(),
            issues=(),
        )
        plan = build_relational_interpreter_kernel_indirect_plan(
            candidate_pe=candidate,
            kernel_plan=_kernel_plan(0x1000, b"\xff\xd0"),
            callback_plan=callback,
        )

        self.assertEqual(plan.payload()["classification_status"], "incomplete")
        self.assertIn(
            "unknown_or_writable_unbounded_target",
            {issue.code for issue in plan.issues},
        )

    def test_generated_source_has_goals_and_no_unchecked_proof_constructs(self) -> None:
        kernel, callback, candidate = self._relocation_case(writable=True)
        plan = build_relational_interpreter_kernel_indirect_plan(
            candidate_pe=candidate, kernel_plan=kernel, callback_plan=callback
        )
        source = relational_interpreter_kernel_indirect_source(plan)

        self.assertIn("GeneratedKernelIndirectStaticGoal", source)
        self.assertIn("GeneratedKernelIndirectSemanticGoal", source)
        self.assertIn(".writable", source)
        self.assertNotIn("theorem", source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertNotIn(marker, source)


if __name__ == "__main__":
    unittest.main()
