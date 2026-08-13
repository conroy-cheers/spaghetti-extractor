from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spaghetti_extractor.isa_conformance import ISAConformanceError, X87Mask
from spaghetti_extractor.isa_conformance_lean import (
    LEAN_KERNEL_CACHE_ENV,
    X87DefinednessEvidence,
    _generated_module,
    _lean_input,
    _unsupported_reason,
    _x87_definedness_evidence,
    mask_x87_outputs,
    run_lean_isa_conformance,
)
from tests.test_stage_a_isa_conformance_unicorn import _case, _corpus, _x87_mask


class StageAISAConformanceLeanFixtureTests(unittest.TestCase):
    def test_checked_x87_definedness_masks_reserved_and_undefined_bits(self) -> None:
        full = X87Mask(
            control_word=0xFFFF,
            status_word=0xFFFF,
            tag_word=0xFFFF,
            last_opcode=0x7FF,
            instruction_pointer=0xFFFFFFFF,
            data_pointer=0xFFFFFFFF,
            registers=(bytes([0xFF] * 10),) * 8,
        )
        evidence = X87DefinednessEvidence(
            control_word=0x1F3F,
            status_word=0xBAFF,
            tag_word=0xFFFF,
            last_opcode=0x7FF,
            instruction_pointer=0xFFFFFFFF,
            data_pointer=0,
            registers=(bytes([0xFF] * 10),) * 8,
        )

        masked = mask_x87_outputs(full, evidence)

        self.assertEqual(masked.control_word, 0x1F3F)
        self.assertEqual(masked.status_word, 0xBAFF)
        self.assertEqual(masked.data_pointer, 0)
        self.assertEqual(masked.tag_word, 0xFFFF)
        self.assertEqual(masked.last_opcode, 0x7FF)
        self.assertEqual(masked.instruction_pointer, 0xFFFFFFFF)

    def test_x87_definedness_parser_rejects_missing_or_oversized_masks(self) -> None:
        observed = {
            "x87_defined_control": 0x1F3F,
            "x87_defined_status": 0xBAFF,
            "x87_defined_tag": 0xFFFF,
            "x87_defined_last_opcode": 0x7FF,
            "x87_defined_instruction_pointer": 0xFFFFFFFF,
            "x87_defined_data_pointer": 0,
            "x87_defined_stack": [2**80 - 1] * 8,
        }
        evidence = _x87_definedness_evidence(observed)
        self.assertEqual(evidence.status_word, 0xBAFF)
        self.assertEqual(evidence.data_pointer, 0)

        for key, value in (
            ("x87_defined_status", 2**16),
            ("x87_defined_last_opcode", 2**11),
            ("x87_defined_stack", [2**80 - 1] * 7),
        ):
            with self.subTest(key=key):
                invalid = dict(observed)
                invalid[key] = value
                with self.assertRaises(ISAConformanceError):
                    _x87_definedness_evidence(invalid)

    def test_x87_opcode_family_is_not_rejected_before_lean_decoding(self) -> None:
        instructions = {
            "wait": [0x9B],
            "add-stack": [0xD8, 0xC1],
            "load-constant": [0xD9, 0xE8],
            "add-int32": [0xDA, 0x00],
            "load-int32": [0xDB, 0x00],
            "add-stack-reversed": [0xDC, 0xC1],
            "store-pop": [0xDD, 0xD8],
            "add-pop": [0xDE, 0xC1],
            "store-status": [0xDF, 0xE0],
        }
        for name, instruction in instructions.items():
            with self.subTest(name=name):
                payload = _case(case_id=f"x87-{name}")
                payload["instruction_bytes"] = instruction
                case = _corpus(payload).cases[0]
                self.assertIsNone(_unsupported_reason(case))

    def test_x87_case_is_routed_to_concrete_physical_executor(self) -> None:
        payload = _case(case_id="x87-fld1")
        payload["instruction_bytes"] = [0xD9, 0xE8]
        payload["defined_outputs"]["x87"] = {
            key: value
            for key, value in _x87_mask().items()
        }
        payload["defined_outputs"]["x87"].update(
            {
                "control_word": 0xFFFF,
                "status_word": 0xFFFF,
                "tag_word": 0xFFFF,
                "last_opcode": 0x7FF,
                "instruction_pointer": 0xFFFFFFFF,
                "data_pointer": 0xFFFFFFFF,
                "registers": [[0xFF] * 10 for _ in range(8)],
            }
        )
        case = _corpus(payload).cases[0]

        self.assertIsNone(_unsupported_reason(case))
        lean_input = _lean_input(case)
        self.assertIn("x87Tag := 0xffff", lean_input)
        self.assertIn("x87LastOpcode := 0x0", lean_input)
        generated = _generated_module([case], executable_case_ids={case.id})
        self.assertIn("emitISAConformanceCase", generated)
        self.assertIn("x87Profile := .concreteBinaryRationalV1", generated)
        self.assertNotIn("emitISAConformanceClassification \"x87-fld1\"", generated)

    def test_missing_shared_kernel_fails_with_supported_command(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                ISAConformanceError,
                r"nix run \.#test -- affected",
            ):
                run_lean_isa_conformance(_corpus())

    def test_incomplete_shared_kernel_names_missing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.dict(
                os.environ,
                {LEAN_KERNEL_CACHE_ENV: temporary},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    ISAConformanceError,
                    r"StageA/X87\.olean",
                ):
                    run_lean_isa_conformance(_corpus())

    def test_explicit_cache_takes_precedence_over_environment(self) -> None:
        with tempfile.TemporaryDirectory() as explicit:
            with mock.patch.dict(
                os.environ,
                {LEAN_KERNEL_CACHE_ENV: str(Path(explicit) / "environment")},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    ISAConformanceError,
                    re.escape(str(Path(explicit))) + r".*StageA/X87\.olean",
                ):
                    run_lean_isa_conformance(
                        _corpus(), kernel_cache=Path(explicit)
                    )


if __name__ == "__main__":
    unittest.main()
