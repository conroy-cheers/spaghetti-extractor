from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.stage_b_c_backend import write_stage_b_semantic_c_backend


def _transfer(*, fpu_state: object = None) -> dict[str, object]:
    row: dict[str, object] = {
        "format": "stage-a-semantic-transfer-contract-v1",
        "id": "semantic-transfer:replay-only-x87",
        "function": "fixture",
        "block_id": "fixture",
        "status": "reimplementable",
        "expression_model": "stage-a-semantic-ir-v1",
        "original": {"rva_start": 0x2000, "rva_end": 0x2001},
        "instructions": [],
        "register_writes": [],
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "outcome": {"kind": "fallthrough", "target_rva": 0x2001},
    }
    if fpu_state is not None:
        row["fpu_state"] = fpu_state
    return row


class StageBSemanticCBackendX87Tests(unittest.TestCase):
    def test_symbolic_x87_fails_closed_in_favor_of_checked_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = write_stage_b_semantic_c_backend(
                root,
                [
                    _transfer(
                        fpu_state={
                            "model": "symbolic_x87_stack_v1",
                            "stack": [],
                        }
                    )
                ],
            )

            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(
                report["counts"], {"transfers": 1, "generated": 0, "unsupported": 1}
            )
            self.assertEqual(report["reason_counts"]["x87_checked_replay_required"], 1)
            self.assertFalse(report["constraints"]["x87_supported"])
            self.assertEqual(
                report["constraints"]["x87_semantics"],
                "checked_replay_interpreter_required",
            )
            repairs = (root / "state-machine-repairs.c").read_text(encoding="ascii")
            self.assertIn("x87_checked_replay_required", repairs)
            self.assertIn("STAGE_B_UNIMPLEMENTED", repairs)
            for source in root.glob("*.c"):
                rendered = source.read_text(encoding="ascii")
                self.assertNotIn("long double", rendered)
                self.assertNotIn("stage_b_x87_binary", rendered)
                self.assertNotIn("stage_b_x87_unpack", rendered)

    def test_non_x87_direct_backend_has_no_host_floating_helpers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = write_stage_b_semantic_c_backend(root, [_transfer()])

            self.assertEqual(report["status"], "complete")
            source = (root / "state-machine-transfers.c").read_text(encoding="ascii")
            self.assertNotIn("long double", source)
            self.assertNotIn("stage_b_copy_bytes", source)
            self.assertNotIn("x87_fault", source)

            compiler = shutil.which("cc")
            if compiler is not None:
                subprocess.run(
                    [
                        compiler,
                        "-std=c11",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-c",
                        "state-machine-transfers.c",
                        "-o",
                        "transfers.o",
                    ],
                    cwd=root,
                    check=True,
                    text=True,
                    capture_output=True,
                )

    def test_shared_machine_state_keeps_replay_physical_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_stage_b_semantic_c_backend(root, [_transfer()])
            header = (root / "state-machine-runtime.h").read_text(encoding="ascii")

            for declaration in (
                "stage_b_x87_value x87_stack[8]",
                "uint16_t x87_control",
                "uint16_t x87_status",
                "uint8_t x87_pending_exception",
                "uint16_t x87_last_opcode",
                "uint32_t x87_instruction_pointer",
                "uint16_t x87_code_selector",
                "uint32_t x87_data_pointer",
                "uint16_t x87_data_selector",
            ):
                self.assertIn(declaration, header)


if __name__ == "__main__":
    unittest.main()
