from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.global_slot_hypotheses_v2 import (
    GlobalSlotHypothesisV2Error,
    GlobalSlotInductionHypothesisV2,
    derive_event_bound_global_slot_induction_hypotheses_v2,
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

    @staticmethod
    def _read_unit(*, address: int = 0x402000) -> dict[str, object]:
        return {
            "id": "unit:read",
            "source": {
                "original": {"rva_start": 0x1000, "rva_end": 0x1002},
                "instruction_bytes_sha256": "c" * 64,
            },
            "semantics": {
                "memory_events": [{
                    "kind": "read",
                    "instruction_rva": 0x1000,
                    "address": {
                        "op": "const",
                        "value": address,
                        "width": 32,
                    },
                    "width": 4,
                    "value": {"op": "reg", "name": "eax", "width": 32},
                }],
            },
        }

    @staticmethod
    def _indexed_read_unit(*, table_address: int = 0x402000) -> dict[str, object]:
        address = {
            "op": "add32",
            "args": [
                {"op": "const", "value": table_address, "width": 32},
                {
                    "op": "mul32",
                    "args": [
                        {"op": "reg", "name": "edx", "width": 32},
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            ],
        }
        unit = GlobalSlotHypothesesV2Tests._read_unit(address=table_address)
        unit["semantics"]["memory_events"][0]["address"] = address
        return unit

    @staticmethod
    def _proposal_analysis(
        alternatives: list[dict[str, object]],
        *,
        instruction_rva: int = 0x1000,
        address: int = 0x402000,
    ) -> dict[str, object]:
        return {
            "format": "stage-a-global-slot-analysis-v2",
            "global_slot_evidence": [{
                "address": address,
                "width": 4,
                "read_inventory": [{
                    "site": {
                        "unit_id": "unit:read",
                        "event_index": 0,
                        "instruction_rva": instruction_rva,
                    },
                    "status": "incomplete",
                    "state": {
                        "reachable": True,
                        "initialized": True,
                        "tainted": True,
                        "overflow": False,
                        "alternatives": alternatives,
                    },
                }],
            }],
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

    def test_bootstrap_read_produces_exact_event_bound_hypothesis(self) -> None:
        binary = self._binary()
        interface_origin = {
            "kind": "interface_object",
            "key": ["d" * 64, "ITestInterface"],
        }
        hypotheses = derive_event_bound_global_slot_induction_hypotheses_v2(
            binary,
            units=[self._read_unit(address=binary.image_base + 0x2000)],
            machine_ir_sha256=MACHINE_IR_SHA256,
            proposal_slot_dependencies=[self._dependency()],
            proposal_global_slot_analysis=self._proposal_analysis(
                [interface_origin],
                address=binary.image_base + 0x2000,
            ),
        )

        self.assertEqual(len(hypotheses), 1)
        hypothesis = hypotheses[0]
        binding = hypothesis.invariant.binding
        self.assertEqual(binding.unit.unit_id, "unit:read")
        self.assertEqual(binding.event_index, 0)
        self.assertEqual(binding.event_kind, "read")
        self.assertEqual(hypothesis.invariant.invariant_kind, "finite_set_at_read")
        self.assertEqual(
            hypothesis.invariant.alternatives.to_payload()["values"],
            [interface_origin],
        )
        self.assertFalse(hypothesis.to_payload()["proof_authority"])

    def test_event_hypothesis_rejects_contradictory_read_binding(self) -> None:
        binary = self._binary()
        with self.assertRaisesRegex(
            GlobalSlotHypothesisV2Error, "contradicts its exact event binding"
        ):
            derive_event_bound_global_slot_induction_hypotheses_v2(
                binary,
                units=[self._read_unit(address=binary.image_base + 0x2000)],
                machine_ir_sha256=MACHINE_IR_SHA256,
                proposal_slot_dependencies=[self._dependency()],
                proposal_global_slot_analysis=self._proposal_analysis(
                    [{"kind": "exact_bits", "value": 0, "width_bits": 32}],
                    instruction_rva=0x1001,
                    address=binary.image_base + 0x2000,
                ),
            )

    def test_event_hypothesis_skips_over_budget_read(self) -> None:
        binary = self._binary()
        hypotheses = derive_event_bound_global_slot_induction_hypotheses_v2(
            binary,
            units=[self._read_unit(address=binary.image_base + 0x2000)],
            machine_ir_sha256=MACHINE_IR_SHA256,
            proposal_slot_dependencies=[self._dependency()],
            proposal_global_slot_analysis=self._proposal_analysis(
                [
                    {"kind": "exact_bits", "value": 0, "width_bits": 32},
                    {"kind": "exact_bits", "value": 1, "width_bits": 32},
                ],
                address=binary.image_base + 0x2000,
            ),
            finite_value_budget=1,
        )

        self.assertEqual(hypotheses, ())

    def test_indexed_read_produces_conditional_hypothesis_per_slot(self) -> None:
        binary = self._binary(data_size=8)
        first = binary.image_base + 0x1010
        second = binary.image_base + 0x1020
        analysis = {
            "format": "stage-a-global-slot-analysis-v2",
            "global_slot_evidence": [
                {
                    "address": binary.image_base + slot_rva,
                    "width": 4,
                    "read_inventory": [{
                        "site": {
                            "unit_id": "unit:read",
                            "event_index": 0,
                            "instruction_rva": 0x1000,
                        },
                        "status": "incomplete",
                        "state": {
                            "reachable": True,
                            "initialized": True,
                            "tainted": True,
                            "overflow": False,
                            "alternatives": [{
                                "kind": "exact_bits",
                                "value": value,
                                "width_bits": 32,
                            }],
                        },
                    }],
                }
                for slot_rva, value in ((0x2000, first), (0x2004, second))
            ],
        }

        hypotheses = derive_event_bound_global_slot_induction_hypotheses_v2(
            binary,
            units=[self._indexed_read_unit(
                table_address=binary.image_base + 0x2000
            )],
            machine_ir_sha256=MACHINE_IR_SHA256,
            proposal_slot_dependencies=[
                self._dependency(slot_rva=0x2000, exit_id="exit:first"),
                self._dependency(slot_rva=0x2004, exit_id="exit:second"),
            ],
            proposal_global_slot_analysis=analysis,
        )

        by_slot = {item.invariant.slot_rva: item for item in hypotheses}
        self.assertEqual(sorted(by_slot), [0x2000, 0x2004])
        self.assertEqual(
            {
                slot_rva: item.invariant.alternatives.to_payload()["values"][0][
                    "value"
                ]
                for slot_rva, item in by_slot.items()
            },
            {0x2000: first, 0x2004: second},
        )
        self.assertEqual(
            {item.invariant.binding.event_index for item in hypotheses}, {0}
        )

    def test_event_hypothesis_rejects_nonpersistent_origin(self) -> None:
        binary = self._binary()
        with self.assertRaisesRegex(
            GlobalSlotHypothesisV2Error, "is not persistent"
        ):
            derive_event_bound_global_slot_induction_hypotheses_v2(
                binary,
                units=[self._read_unit(address=binary.image_base + 0x2000)],
                machine_ir_sha256=MACHINE_IR_SHA256,
                proposal_slot_dependencies=[self._dependency()],
                proposal_global_slot_analysis=self._proposal_analysis(
                    [{"kind": "register", "key": ["eax"]}],
                    address=binary.image_base + 0x2000,
                ),
            )


if __name__ == "__main__":
    unittest.main()
