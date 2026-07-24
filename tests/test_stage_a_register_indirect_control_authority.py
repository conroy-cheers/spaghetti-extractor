from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.register_indirect_control_authority import (
    RegisterIndirectControlAuthorityError,
    consume_register_indirect_control_authorities,
    load_register_indirect_control_authorities,
)
from spaghetti_extractor.relational.lean.register_indirect_control_proposal import (
    write_register_indirect_control_authorities,
)
from tests.test_stage_a_register_indirect_control_proposal import (
    EXPECTED_REGISTER_SITES,
    EXPECTED_STACK_SITES,
    _instruction_rva,
    _paths_present,
    bindings_for,
    gnu_register_case,
)


def _load(report: Path):
    mixed, proposal = gnu_register_case()
    references = load_register_indirect_control_authorities(
        report,
        original_sha256=proposal.original_sha256,
        state_machine_sha256=proposal.state_machine_sha256,
        machine_import_report_sha256=proposal.machine_import_report_sha256,
        mixed_original_plan=mixed,
        writable_slot_report_sha256=proposal.writable_slot_report_sha256,
    )
    return mixed, proposal, references


@unittest.skipUnless(_paths_present(), "pinned GNU hello artifacts are required")
class StageARegisterIndirectControlAuthorityTests(unittest.TestCase):
    def test_named_terms_partition_exactly_the_thirteen_register_sites(self) -> None:
        mixed, proposal = gnu_register_case()
        with tempfile.TemporaryDirectory() as temporary:
            report = write_register_indirect_control_authorities(
                temporary, proposal, bindings_for(proposal)
            )
            loaded_mixed, _, references = _load(report)
            self.assertEqual(loaded_mixed, mixed)
            consumed = consume_register_indirect_control_authorities(mixed, references)

        self.assertEqual(
            set(consumed.closed_instruction_rvas),
            EXPECTED_REGISTER_SITES,
        )
        self.assertEqual(len(consumed.authorized_blockers), 13)
        self.assertEqual(
            {
                _instruction_rva(blocker.detail)
                for blocker in consumed.remaining_blockers
            },
            EXPECTED_STACK_SITES,
        )
        self.assertEqual(len(consumed.imported_modules), 13)
        self.assertEqual(len(consumed.authorizing_terms), 13)
        self.assertTrue(
            all(
                term.endswith(".generatedAuthority")
                for term in consumed.authorizing_terms
            )
        )

    def test_stale_input_hash_is_rejected(self) -> None:
        _, proposal = gnu_register_case()
        with tempfile.TemporaryDirectory() as temporary:
            report = write_register_indirect_control_authorities(
                temporary, proposal, bindings_for(proposal)
            )
            with self.assertRaisesRegex(
                RegisterIndirectControlAuthorityError,
                "original_sha256 does not match",
            ):
                load_register_indirect_control_authorities(
                    report,
                    original_sha256="0" * 64,
                    state_machine_sha256=proposal.state_machine_sha256,
                    machine_import_report_sha256=(
                        proposal.machine_import_report_sha256
                    ),
                    mixed_original_plan=gnu_register_case()[0],
                    writable_slot_report_sha256=(proposal.writable_slot_report_sha256),
                )

    def test_unknown_inventory_kind_is_rejected(self) -> None:
        _, proposal = gnu_register_case()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = write_register_indirect_control_authorities(
                root, proposal, bindings_for(proposal)
            )
            value = json.loads(report.read_text(encoding="utf-8"))
            value["sites"][0]["inventory"]["kind"] = "trusted_status"
            report.write_text(
                json.dumps(value, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RegisterIndirectControlAuthorityError,
                "inventory.kind is unsupported",
            ):
                _load(report)

    def test_reused_lean_term_is_rejected(self) -> None:
        _, proposal = gnu_register_case()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = write_register_indirect_control_authorities(
                root, proposal, bindings_for(proposal)
            )
            value = json.loads(report.read_text(encoding="utf-8"))
            value["sites"][1]["authorizing_lean_term"] = value["sites"][0][
                "authorizing_lean_term"
            ]
            report.write_text(
                json.dumps(value, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RegisterIndirectControlAuthorityError,
                "reuses one Lean term",
            ):
                _load(report)

    def test_omitted_producer_inventory_is_rejected(self) -> None:
        _, proposal = gnu_register_case()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = write_register_indirect_control_authorities(
                root, proposal, bindings_for(proposal)
            )
            value = json.loads(report.read_text(encoding="utf-8"))
            value["sites"][0]["inventory"]["producers"] = []
            report.write_text(
                json.dumps(value, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RegisterIndirectControlAuthorityError,
                "producers must be a nonempty list",
            ):
                _load(report)


if __name__ == "__main__":
    unittest.main()
