from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any

from spaghetti_extractor.relational.analyses.memory import (
    _attach_initial_static_code_pointer_slots,
)
from spaghetti_extractor.stage_binary import StageABinary, _parse_stage_a_pe
from tests.stage_a_relational_support import (
    _pe32_image_with_immutable_indirect_call,
    _pe32_image_with_relocation_pointer_table,
)


class StageAInitialStaticCodePointerTests(unittest.TestCase):
    @staticmethod
    def _read(address: int) -> dict[str, object]:
        return {
            "op": "read32",
            "address": {"op": "constant", "value": address},
        }

    @classmethod
    def _behavior(
        cls, original_address: int, candidate_address: int,
    ) -> dict[str, object]:
        return {
            "original_ir": {
                "registers": {"eax": cls._read(original_address)},
            },
            "candidate_ir": {
                "registers": {"eax": cls._read(candidate_address)},
            },
        }

    @staticmethod
    def _write_binary(path: Path, image: bytes | bytearray) -> StageABinary:
        path.write_bytes(image)
        return _parse_stage_a_pe(path)

    def _fixture(
        self, root: Path, *, missing_original_relocation: bool = False,
        writable: bool = True,
    ) -> tuple[
        StageABinary, StageABinary, dict[str, Any], list[dict[str, Any]],
    ]:
        original_image = bytearray(_pe32_image_with_immutable_indirect_call(
            0x2000, callee_rva=0x1030, writable=writable, jump=True,
        ))
        if missing_original_relocation:
            # The second relocation block describes the writable word at RVA 0x2000.
            struct.pack_into("<H", original_image, 0x614, 0)
        original = self._write_binary(root / "original.exe", original_image)
        candidate = self._write_binary(
            root / "candidate.exe",
            _pe32_image_with_immutable_indirect_call(
                0x3000, callee_rva=0x1030, writable=writable, jump=True,
            ),
        )
        contract: dict[str, Any] = {
            "code_targets": [{
                "id": 7,
                "original_rva": 0x1030,
                "candidate_rva": 0x1030,
            }],
            "regions": [{"id": "load-launch-pointer"}],
            "static_word_relation_slots": [],
        }
        behaviors = [self._behavior(0x402000, 0x403000)]
        return original, candidate, contract, behaviors

    def test_infers_unique_relocated_launch_fixed_code_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(
                Path(temporary)
            )

            updated, diagnostics = _attach_initial_static_code_pointer_slots(
                contract, behaviors, original, candidate,
            )

            self.assertEqual(contract["static_word_relation_slots"], [])
            self.assertEqual(updated["static_word_relation_slots"], [{
                "id": 0,
                "original_address": 0x402000,
                "candidate_address": 0x403000,
                "relation": "fixed_code_pointer",
                "target_id": 7,
            }])
            self.assertEqual(
                diagnostics["format"],
                "spaghetti-extractor-initial-static-code-pointer-slots-v1",
            )
            self.assertEqual(
                diagnostics["status"], "proposal_requires_generated_lean_replay"
            )
            self.assertEqual(diagnostics["counts"], {
                "existing": 0,
                "inferred": 1,
                "already_present": 0,
                "rejected": 0,
            })
            repeated = _attach_initial_static_code_pointer_slots(
                contract, behaviors, original, candidate,
            )
            self.assertEqual((updated, diagnostics), repeated)

    def test_readonly_pointer_is_left_to_immutable_image_proof(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(
                Path(temporary), writable=False,
            )

            updated, diagnostics = _attach_initial_static_code_pointer_slots(
                contract, behaviors, original, candidate,
            )

            self.assertEqual(updated["static_word_relation_slots"], [])
            self.assertEqual(diagnostics["counts"]["inferred"], 0)
            self.assertEqual(diagnostics["counts"]["rejected"], 0)

    def test_missing_highlow_relocation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(
                Path(temporary), missing_original_relocation=True,
            )

            updated, diagnostics = _attach_initial_static_code_pointer_slots(
                contract, behaviors, original, candidate,
            )

            self.assertEqual(updated["static_word_relation_slots"], [])
            self.assertEqual(diagnostics["status"], "incomplete")
            self.assertEqual(diagnostics["counts"]["rejected"], 1)
            rejection = diagnostics["rejected"][0]
            self.assertEqual(
                rejection["category"],
                "initial_static_code_pointer_slot_inference_rejected",
            )
            self.assertEqual(rejection["original_highlow_relocations"], 0)
            self.assertEqual(rejection["candidate_highlow_relocations"], 1)

    def test_ambiguous_canonical_target_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original, candidate, contract, behaviors = self._fixture(
                Path(temporary)
            )
            contract["code_targets"].append({
                "id": 8,
                "original_rva": 0x1030,
                "candidate_rva": 0x1030,
            })

            updated, diagnostics = _attach_initial_static_code_pointer_slots(
                contract, behaviors, original, candidate,
            )

            self.assertEqual(updated["static_word_relation_slots"], [])
            self.assertEqual(diagnostics["status"], "incomplete")
            self.assertEqual(
                diagnostics["rejected"][0]["category"],
                "initial_static_code_pointer_target_ambiguous",
            )
            self.assertEqual(
                diagnostics["rejected"][0]["original_target_ids"], [7, 8]
            )

    def test_non_bijective_slot_pairing_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_image = bytearray(
                _pe32_image_with_relocation_pointer_table(0x2000)
            )
            candidate_image = bytearray(
                _pe32_image_with_relocation_pointer_table(0x3000)
            )
            struct.pack_into("<II", original_image, 0x400, 0x401000, 0x401000)
            struct.pack_into("<II", candidate_image, 0x400, 0x401000, 0x401000)
            original = self._write_binary(root / "original.exe", original_image)
            candidate = self._write_binary(root / "candidate.exe", candidate_image)
            contract = {
                "code_targets": [{
                    "id": 3,
                    "original_rva": 0x1000,
                    "candidate_rva": 0x1000,
                }],
                "regions": [{"id": "first-read"}, {"id": "second-read"}],
                "static_word_relation_slots": [],
            }
            behaviors = [
                self._behavior(0x402000, 0x403000),
                self._behavior(0x402000, 0x403004),
            ]

            updated, diagnostics = _attach_initial_static_code_pointer_slots(
                contract, behaviors, original, candidate,
            )

            self.assertEqual(updated["static_word_relation_slots"], [])
            self.assertEqual(diagnostics["status"], "incomplete")
            self.assertEqual(diagnostics["counts"]["rejected"], 2)
            self.assertEqual(
                {
                    rejection["category"]
                    for rejection in diagnostics["rejected"]
                },
                {"initial_static_code_pointer_slot_mapping_ambiguous"},
            )


if __name__ == "__main__":
    unittest.main()
