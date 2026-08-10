from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.authority_bindings_v2 import BinaryBinding
from spaghetti_extractor.checked_memory_address_domain_v2 import (
    CONTEXTUAL_MEMORY_COVERAGE_V1_FORMAT,
    MEMORY_ADDRESS_DOMAIN_PROPOSAL_V2_FORMAT,
    CheckedMemoryAddressDomainV2Error,
    prepare_checked_memory_address_domains_v2,
    seal_checked_memory_address_domains_v2,
    validate_checked_memory_address_domains_v2,
)
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256


PE_SHA256 = "a" * 64
AUTHORITY_SHA256 = "c" * 64


def _unit() -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "id": "read:cursor",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1004},
            "contract_sha256": "d" * 64,
            "instruction_bytes_sha256": "e" * 64,
        },
        "semantics": {
            "memory_events": [{
                "kind": "read",
                "width": 4,
                "instruction_rva": 0x1000,
                "address": {"op": "reg", "name": "esi", "width": 32},
            }],
        },
        "control": {"direct_targets": [], "has_indirect_target": False},
    }


def _coverage() -> dict[str, object]:
    return {
        "format": CONTEXTUAL_MEMORY_COVERAGE_V1_FORMAT,
        "status": "complete",
        "root_unit_ids": ["root"],
        "relevant_unit_ids": ["read:cursor", "root"],
        "context_states": 6,
        "context_depth": 2,
        "contexts_per_unit": 64,
        "truncated_calls": 0,
        "dropped_contexts": 0,
        "work_budget_exceeded": False,
    }


def _proposal() -> dict[str, object]:
    return {
        "format": MEMORY_ADDRESS_DOMAIN_PROPOSAL_V2_FORMAT,
        "status": "complete",
        "unit_id": "read:cursor",
        "event_index": 0,
        "memory_kind": "read",
        "width_bytes": 4,
        "address_expression": {"op": "reg", "name": "esi", "width": 32},
        "addresses": [0x403000, 0x403004],
        "authority_dependencies": ["indirect-exit:caller"],
        "context_coverage": _coverage(),
    }


class CheckedMemoryAddressDomainV2Tests(unittest.TestCase):
    def _binary(self, units: list[dict[str, object]]) -> BinaryBinding:
        return BinaryBinding(PE_SHA256, machine_ir_sha256(units))

    def _sealed(
        self, proposal: dict[str, object] | None = None
    ) -> tuple[dict[str, object], ...]:
        units = [_unit()]
        prepared = prepare_checked_memory_address_domains_v2(
            [_proposal() if proposal is None else proposal],
            units=units,
            binary=self._binary(units),
        )
        return seal_checked_memory_address_domains_v2(
            prepared,
            interprocedural_authority_sha256=AUTHORITY_SHA256,
        )

    def test_exact_event_round_trip(self) -> None:
        units = [_unit()]
        domains = validate_checked_memory_address_domains_v2(
            self._sealed(),
            units=units,
            binary=self._binary(units),
            interprocedural_authority_sha256=AUTHORITY_SHA256,
        )

        self.assertEqual(list(domains), ["event:read:cursor:0"])
        self.assertEqual(
            domains["event:read:cursor:0"].addresses,
            (0x403000, 0x403004),
        )

    def test_dropped_context_is_rejected(self) -> None:
        proposal = _proposal()
        proposal["context_coverage"] = {
            **_coverage(),
            "dropped_contexts": 1,
        }
        with self.assertRaisesRegex(
            CheckedMemoryAddressDomainV2Error, "not exhaustive"
        ):
            self._sealed(proposal)

    def test_context_key_truncation_is_recorded_but_not_dropped(self) -> None:
        proposal = _proposal()
        proposal["context_coverage"] = {
            **_coverage(),
            "truncated_calls": 1,
        }
        sealed = self._sealed(proposal)
        self.assertEqual(sealed[0]["context_coverage"]["truncated_calls"], 1)

    def test_budget_exhaustion_is_rejected(self) -> None:
        proposal = _proposal()
        proposal["context_coverage"] = {
            **_coverage(),
            "work_budget_exceeded": True,
        }
        with self.assertRaisesRegex(
            CheckedMemoryAddressDomainV2Error, "not exhaustive"
        ):
            self._sealed(proposal)

    def test_stale_event_binding_is_rejected(self) -> None:
        sealed = list(self._sealed())
        sealed[0] = copy.deepcopy(sealed[0])
        sealed[0]["binding"]["event_index"] = 1
        units = [_unit()]

        with self.assertRaises(CheckedMemoryAddressDomainV2Error):
            validate_checked_memory_address_domains_v2(
                sealed,
                units=units,
                binary=self._binary(units),
                interprocedural_authority_sha256=AUTHORITY_SHA256,
            )

    def test_noncanonical_or_mutable_domain_is_rejected(self) -> None:
        duplicate = _proposal()
        duplicate["addresses"] = [0x403000, 0x403000]
        with self.assertRaises(CheckedMemoryAddressDomainV2Error):
            self._sealed(duplicate)

        mutable = _proposal()
        mutable["authority_dependencies"] = [
            "global-slot-invariant:untrusted"
        ]
        with self.assertRaises(CheckedMemoryAddressDomainV2Error):
            self._sealed(mutable)


if __name__ == "__main__":
    unittest.main()
