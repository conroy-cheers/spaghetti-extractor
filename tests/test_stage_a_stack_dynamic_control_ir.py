from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.relational.stack_dynamic_control_ir import (
    StackDynamicControlIRError,
    load_stack_dynamic_control_input,
    stack_dynamic_control_input_from_plan,
)
from spaghetti_extractor.util import write_json


class StageAStackDynamicControlIRTests(unittest.TestCase):
    def _plan(self):
        expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "reg", "name": "esp"},
                    {"op": "const", "value": 32},
                ],
            },
        }
        return SimpleNamespace(
            state_machine_sha256="b" * 64,
            regions=(
                SimpleNamespace(target_id=7, rva=0x2000),
                SimpleNamespace(target_id=8, rva=0x2040),
            ),
            blockers=(
                SimpleNamespace(
                    reason_code="unresolved_indirect_control",
                    rva=0x2000,
                    detail="stack_or_dynamic_pointer requires runtime proof",
                ),
            ),
            indirect_sites=(
                SimpleNamespace(
                    source_rva=0x2000,
                    instruction_rva=0x203C,
                    category="stack_or_dynamic_pointer",
                    is_call=True,
                    continuation_rva=0x2040,
                    target_expression=expression,
                ),
            ),
        )

    def test_round_trip_preserves_only_phase_input(self) -> None:
        projected = stack_dynamic_control_input_from_plan(
            self._plan(),
            original_pe_sha256="a" * 64,
        )
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input.json"
            write_json(source, projected.to_json())
            loaded = load_stack_dynamic_control_input(
                source,
                original_pe_sha256="a" * 64,
                state_machine_sha256="b" * 64,
            )

        self.assertEqual(loaded, projected)
        self.assertEqual(loaded.remaining_source_rvas, (0x2000,))
        self.assertEqual(len(loaded.regions), 2)
        self.assertEqual(len(loaded.indirect_sites), 1)

    def test_load_rejects_wrong_binary_identity(self) -> None:
        projected = stack_dynamic_control_input_from_plan(
            self._plan(),
            original_pe_sha256="a" * 64,
        )
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input.json"
            write_json(source, projected.to_json())
            with self.assertRaisesRegex(
                StackDynamicControlIRError,
                "does not match the original PE",
            ):
                load_stack_dynamic_control_input(
                    source,
                    original_pe_sha256="c" * 64,
                    state_machine_sha256="b" * 64,
                )


if __name__ == "__main__":
    unittest.main()
