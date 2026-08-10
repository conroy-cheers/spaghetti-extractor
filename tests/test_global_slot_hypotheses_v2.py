from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.global_slot_hypotheses_v2 import (
    GlobalSlotHypothesisV2Error,
    GlobalSlotInductionHypothesisV2,
    derive_global_slot_induction_hypotheses_v2,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from tests.pe_fixtures import pe32_image_with_writable_data


MACHINE_IR_SHA256 = "b" * 64


class GlobalSlotHypothesesV2Tests(unittest.TestCase):
    def _binary(
        self,
        *,
        value: int = 0x401000,
        relocated: bool = False,
        data_size: int = 4,
    ):
        raw = bytearray(pe32_image_with_writable_data(
            b"\xc3",
            relocation_offsets=[0] if relocated else [],
            relocation_page_rva=0x2000,
            data_size=data_size,
        ))
        struct.pack_into("<I", raw, 0x400, value)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "fixture.exe"
        path.write_bytes(raw)
        return _parse_stage_a_pe(path)

    @staticmethod
    def _dependency(
        *, slot_rva: int = 0x2000, exit_id: str = "exit:a"
    ) -> dict[str, object]:
        return {
            "slot_rva": slot_rva,
            "exit_id": exit_id,
            "unit_id": "unit:read",
            "event_index": 0,
            "proof_authority": False,
        }

    def test_exact_launch_value_produces_non_authorizing_typed_hypothesis(self) -> None:
        binary = self._binary(relocated=True)
        hypotheses = derive_global_slot_induction_hypotheses_v2(
            binary,
            machine_ir_sha256=MACHINE_IR_SHA256,
            proposal_slot_dependencies=[self._dependency()],
        )

        self.assertEqual(len(hypotheses), 1)
        hypothesis = hypotheses[0]
        self.assertEqual(hypothesis.invariant.slot_rva, 0x2000)
        self.assertEqual(hypothesis.invariant.binding.relocation_kind, "pe32_highlow")
        self.assertEqual(
            hypothesis.invariant.alternatives.to_payload()["values"],
            [{"kind": "exact_bits", "value": 0x401000, "width_bits": 32}],
        )
        payload = hypothesis.to_payload()
        self.assertFalse(payload["proof_authority"])
        self.assertEqual(
            GlobalSlotInductionHypothesisV2.parse(payload), hypothesis
        )

    def test_duplicate_dependencies_are_grouped_deterministically(self) -> None:
        binary = self._binary()
        dependencies = [
            self._dependency(exit_id="exit:b"),
            self._dependency(exit_id="exit:a"),
            self._dependency(exit_id="exit:b"),
        ]
        first = derive_global_slot_induction_hypotheses_v2(
            binary,
            machine_ir_sha256=MACHINE_IR_SHA256,
            proposal_slot_dependencies=dependencies,
        )
        second = derive_global_slot_induction_hypotheses_v2(
            binary,
            machine_ir_sha256=MACHINE_IR_SHA256,
            proposal_slot_dependencies=list(reversed(dependencies)),
        )

        self.assertEqual(first, second)
        self.assertEqual(first[0].exit_ids, ("exit:a", "exit:b"))

    def test_zero_fill_slot_has_exact_zero_hypothesis(self) -> None:
        binary = self._binary(data_size=0x1000)
        hypothesis = derive_global_slot_induction_hypotheses_v2(
            binary,
            machine_ir_sha256=MACHINE_IR_SHA256,
            proposal_slot_dependencies=[self._dependency(slot_rva=0x2200)],
        )[0]

        self.assertEqual(hypothesis.invariant.binding.initialization_kind, "zero_fill")
        self.assertEqual(
            hypothesis.invariant.alternatives.to_payload()["values"],
            [{"kind": "exact_bits", "value": 0, "width_bits": 32}],
        )

    def test_nonwritable_or_authorizing_dependency_fails_closed(self) -> None:
        binary = self._binary()
        with self.assertRaisesRegex(
            GlobalSlotHypothesisV2Error, "not writable image data"
        ):
            derive_global_slot_induction_hypotheses_v2(
                binary,
                machine_ir_sha256=MACHINE_IR_SHA256,
                proposal_slot_dependencies=[self._dependency(slot_rva=0x1000)],
            )

        authorizing = self._dependency()
        authorizing["proof_authority"] = True
        with self.assertRaisesRegex(GlobalSlotHypothesisV2Error, "malformed"):
            derive_global_slot_induction_hypotheses_v2(
                binary,
                machine_ir_sha256=MACHINE_IR_SHA256,
                proposal_slot_dependencies=[authorizing],
            )

    def test_corrupted_wrapper_identity_is_rejected(self) -> None:
        hypothesis = derive_global_slot_induction_hypotheses_v2(
            self._binary(),
            machine_ir_sha256=MACHINE_IR_SHA256,
            proposal_slot_dependencies=[self._dependency()],
        )[0]
        payload = hypothesis.to_payload()
        payload["id"] = "global-slot-induction-hypothesis-v2:" + "0" * 64

        with self.assertRaisesRegex(
            GlobalSlotHypothesisV2Error, "identity does not match"
        ):
            GlobalSlotInductionHypothesisV2.parse(payload)


if __name__ == "__main__":
    unittest.main()
