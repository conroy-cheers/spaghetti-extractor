from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.authority_bindings_v2 import BinaryBinding
from spaghetti_extractor.checked_memory_access_v2 import (
    CheckedMemoryAccessV2Error,
    MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
    prepare_checked_memory_access_facts_v2,
    seal_checked_memory_access_facts_v2,
    validate_checked_memory_access_facts_v2,
)
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256


PE_SHA256 = "a" * 64
AUTHORITY_SHA256 = "c" * 64


def _unit() -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "id": "entry",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1004},
            "contract_sha256": "d" * 64,
            "instruction_bytes_sha256": "e" * 64,
        },
        "semantics": {
            "memory_events": [{
                "kind": "write",
                "width": 4,
                "instruction_rva": 0x1000,
                "address": {"op": "reg", "name": "esp", "width": 32},
                "value": {"op": "const", "value": 1, "width": 32},
            }],
        },
        "control": {"direct_targets": [], "has_indirect_target": False},
    }


def _proposal(*, dependencies: list[str] | None = None) -> dict[str, object]:
    deps = [] if dependencies is None else dependencies
    return {
        "format": MEMORY_ACCESS_PROPOSAL_V2_FORMAT,
        "status": "complete",
        "unit_id": "entry",
        "event_index": 0,
        "memory_kind": "write",
        "width_bytes": 4,
        "address_expression": {"op": "reg", "name": "esp", "width": 32},
        "address_origins": [{
            "kind": "stack_location",
            "key": [0],
            **({} if not deps else {"authority_dependencies": deps}),
        }],
        "authority_dependencies": deps,
    }


class CheckedMemoryAccessV2Tests(unittest.TestCase):
    def _binary(self, units: list[dict[str, object]]) -> BinaryBinding:
        return BinaryBinding(PE_SHA256, machine_ir_sha256(units))

    def test_exact_event_round_trip(self) -> None:
        units = [_unit()]
        prepared = prepare_checked_memory_access_facts_v2(
            [_proposal()], units=units, binary=self._binary(units)
        )
        sealed = seal_checked_memory_access_facts_v2(
            prepared,
            interprocedural_authority_sha256=AUTHORITY_SHA256,
        )

        facts = validate_checked_memory_access_facts_v2(
            sealed,
            units=units,
            binary=self._binary(units),
            interprocedural_authority_sha256=AUTHORITY_SHA256,
        )

        self.assertEqual(list(facts), ["event:entry:0"])
        fact = facts["event:entry:0"]
        self.assertEqual(fact.memory_kind, "write")
        self.assertEqual(
            fact.address_origins[0].to_value(),
            {"kind": "stack_location", "key": [0]},
        )

    def test_corrupt_event_binding_is_rejected(self) -> None:
        units = [_unit()]
        prepared = prepare_checked_memory_access_facts_v2(
            [_proposal()], units=units, binary=self._binary(units)
        )
        sealed = list(seal_checked_memory_access_facts_v2(
            prepared,
            interprocedural_authority_sha256=AUTHORITY_SHA256,
        ))
        sealed[0] = copy.deepcopy(sealed[0])
        sealed[0]["binding"]["event_index"] = 1

        with self.assertRaises(CheckedMemoryAccessV2Error):
            validate_checked_memory_access_facts_v2(
                sealed,
                units=units,
                binary=self._binary(units),
                interprocedural_authority_sha256=AUTHORITY_SHA256,
            )

    def test_stale_interprocedural_binding_is_rejected(self) -> None:
        units = [_unit()]
        prepared = prepare_checked_memory_access_facts_v2(
            [_proposal()], units=units, binary=self._binary(units)
        )
        sealed = seal_checked_memory_access_facts_v2(
            prepared,
            interprocedural_authority_sha256=AUTHORITY_SHA256,
        )

        with self.assertRaises(CheckedMemoryAccessV2Error):
            validate_checked_memory_access_facts_v2(
                sealed,
                units=units,
                binary=self._binary(units),
                interprocedural_authority_sha256="f" * 64,
            )

    def test_mutable_slot_dependency_is_rejected(self) -> None:
        units = [_unit()]
        dependency = "hybrid-authority-v2:global_slot_invariant:" + "1" * 64
        with self.assertRaises(CheckedMemoryAccessV2Error):
            prepare_checked_memory_access_facts_v2(
                [_proposal(dependencies=[dependency])],
                units=units,
                binary=self._binary(units),
            )


if __name__ == "__main__":
    unittest.main()
