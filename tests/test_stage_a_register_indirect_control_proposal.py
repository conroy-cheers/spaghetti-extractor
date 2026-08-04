from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
import re
import tempfile
import unittest
from functools import lru_cache
from pathlib import Path

from spaghetti_extractor.relational.lean.register_indirect_control_proposal import (
    LeanBindings,
    ProposalPlan,
    construct_register_indirect_control_authorities,
    write_register_indirect_control_authorities,
)


ROOT = Path(__file__).parents[1]
ORIGINAL = Path(
    "/nix/store/iawh49a2apvibazhcdl5dl28idmwwwqp-"
    "stage-a-gnu-hello-original-i686-w64-mingw32-2.12.3/share/"
    "spaghetti-extractor/stage-a-gnu-hello-fixtures/original/hello.exe"
)
STATIC = Path(
    "/nix/store/53aqcxwyjhw1miiqlsngfngq1insl2pg-"
    "stage-a-gnu-hello-roundtrip-static-export"
)
IMPORTS = Path(
    "/nix/store/rly1y4bbdalss7jj2pmrdm97yyvwwvaa-"
    "stage-a-gnu-hello-roundtrip-static-machine-import-contracts-lean"
)
WRITABLE = Path(
    "/nix/store/p6l141v46ngzcikn66krgd5aqs9pibxz-"
    "stage-a-gnu-hello-roundtrip-mixed-original-writable-slot-authority-lean"
)
PINNED = Path(
    "/nix/store/wf9q8vndgcb41sz46ldspn8hyhgyc26y-"
    "stage-a-gnu-hello-roundtrip-mixed-original-lean/"
    "interpreter-mixed-original-plan.json"
)

EXPECTED_REGISTER_SITES = {
    0x1847,
    0x18DB,
    0x18F4,
    0x194B,
    0x1B4F,
    0x1B63,
    0x1B71,
    0x20C3,
    0x2978,
    0xA95D,
    0x14159,
    0x1417B,
    0x141C6,
}
EXPECTED_STACK_SITES = {0x203C, 0xA220, 0xAB8C}
_SITE = re.compile(r" at 0x([0-9a-fA-F]+):")


def _instruction_rva(detail: str) -> int:
    match = _SITE.search(detail)
    if match is None:
        raise AssertionError(f"blocker has no instruction RVA: {detail}")
    return int(match.group(1), 16)


def _paths_present() -> bool:
    return all(
        path.exists()
        for path in (
            ORIGINAL,
            STATIC / "reference-contract.json",
            STATIC / "state-machine.jsonl",
            STATIC / "load-image-contract.json",
            IMPORTS / "machine-import-contract-report.json",
            WRITABLE / "relocated-writable-static-pointer-slot-authorities.json",
            PINNED,
        )
    )


@lru_cache(maxsize=1)
def gnu_register_case():
    specification = importlib.util.spec_from_file_location(
        "gnu_roundtrip_driver_register_test",
        ROOT / "targets/gnu-hello/nix/gnu-hello-roundtrip-driver.py",
    )
    assert specification is not None and specification.loader is not None
    driver = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(driver)
    arguments = argparse.Namespace(
        original=ORIGINAL,
        reference_contract=STATIC / "reference-contract.json",
        state_machine=STATIC / "state-machine.jsonl",
        load_image_contract=STATIC / "load-image-contract.json",
        machine_import_report=IMPORTS / "machine-import-contract-report.json",
        writable_slot_authority_report=None,
        shard_size=128,
    )
    baseline = driver._mixed_original_plan_with_contracts(arguments)
    pinned = json.loads(PINNED.read_text(encoding="utf-8"))
    pinned_sites = {
        _instruction_rva(str(blocker["detail"])) for blocker in pinned["blockers"]
    }
    selected = tuple(
        blocker
        for blocker in baseline.blockers
        if _instruction_rva(blocker.detail) in pinned_sites
    )
    if len(selected) != 16:
        raise AssertionError(
            f"current decoded plan selected {len(selected)} of 16 pinned blockers"
        )
    mixed = dataclasses.replace(baseline, blockers=selected)
    callable_resource_ids = {
        0x14140: 0,
        0x1417B: 1,
    }
    proposal = construct_register_indirect_control_authorities(
        original=ORIGINAL,
        state_machine=STATIC / "state-machine.jsonl",
        machine_import_report=IMPORTS / "machine-import-contract-report.json",
        mixed_original_plan=mixed,
        writable_slot_authority_report=(
            WRITABLE / "relocated-writable-static-pointer-slot-authorities.json"
        ),
        callable_resource_ids_by_instruction_rva=callable_resource_ids,
    )
    return mixed, proposal


def bindings_for(plan: ProposalPlan) -> dict[int, LeanBindings]:
    return {
        site.site_id: LeanBindings(
            context_module="StageA.GeneratedContext",
            context_term="StageA.GeneratedContext.context",
            exact_authority_term="StageA.GeneratedContext.authority",
            runtime_premise_module="StageA.GeneratedRuntime",
            runtime_reachability_term=(
                f"StageA.GeneratedRuntime.reachable{site.site_id}"
            ),
            runtime_premise_term=(f"StageA.GeneratedRuntime.runtime{site.site_id}"),
        )
        for site in plan.sites
    }


@unittest.skipUnless(_paths_present(), "pinned GNU hello artifacts are required")
class StageARegisterIndirectControlProposalTests(unittest.TestCase):
    def test_pinned_gnu_plan_proposes_all_thirteen_nonstack_sites(self) -> None:
        _, proposal = gnu_register_case()
        self.assertEqual(proposal.blockers, ())
        self.assertEqual(
            {site.instruction_rva for site in proposal.sites},
            EXPECTED_REGISTER_SITES,
        )
        self.assertEqual(
            {
                _instruction_rva(blocker.detail)
                for blocker in proposal.untouched_blockers
            },
            EXPECTED_STACK_SITES,
        )

    def test_gnu_inventories_are_exact_and_finite(self) -> None:
        _, proposal = gnu_register_case()
        sites = {site.instruction_rva: site for site in proposal.sites}
        self.assertTrue(all(site.inventory.producers for site in proposal.sites))

        for rva in (0x1847, 0x18DB, 0x18F4, 0x20C3):
            inventory = sites[rva].inventory
            self.assertEqual(inventory.kind, "internal_code")
            self.assertEqual(inventory.slot_rva, 0x200D0)
            self.assertEqual(inventory.target_rvas, (0x143A0,))

        for rva in (0x1B4F, 0x1B63, 0x1B71):
            imported = sites[rva].inventory.imported
            self.assertIsNotNone(imported)
            self.assertEqual(imported.symbol, "_errno")
            self.assertEqual(imported.iat_rva, 0x321E4)
        argv = sites[0x2978].inventory.imported
        self.assertIsNotNone(argv)
        self.assertEqual(argv.symbol, "__p___argv")
        self.assertEqual(argv.iat_rva, 0x321BC)

        self.assertEqual(sites[0x194B].inventory.target_ids, ())
        self.assertEqual(sites[0x194B].inventory.slot_rva, 0x30028)
        self.assertEqual(sites[0xA95D].inventory.target_rvas, (0xA390,))
        self.assertEqual(sites[0xA95D].inventory.slot_rva, 0x30358)

        resolver = sites[0x14159].inventory
        self.assertEqual(
            {
                (
                    query.call_rva,
                    query.resource_id,
                    query.identity_rva,
                    query.identity_bytes,
                )
                for query in resolver.resolver_queries
            },
            {
                (0x14140, 0, 0x27D03, b"___lc_codepage_func"),
                (0x1417B, 1, 0x27D17, b"__lc_codepage"),
            },
        )
        self.assertEqual(resolver.target_rvas, (0x140C0,))
        self.assertEqual(sites[0x14159].carries, ())

        table = sites[0x141C6].inventory
        self.assertEqual(table.kind, "nullable_code_table")
        self.assertEqual(
            (table.table_start_rva, table.table_end_rva), (0x28100, 0x28104)
        )
        self.assertEqual(table.table_entries, (None,))

    def test_carry_inventory_covers_calls_and_stack_restoration(self) -> None:
        _, proposal = gnu_register_case()
        sites = {site.instruction_rva: site for site in proposal.sites}
        first = {(carry.instruction_rva, carry.kind) for carry in sites[0x1847].carries}
        self.assertEqual(
            first,
            {
                (0x1821, "target_call"),
                (0x1826, "machine_import"),
                (0x1837, "internal_call"),
            },
        )
        stack = [
            carry for carry in sites[0x20C3].carries if carry.kind == "stack_restore"
        ]
        self.assertEqual(len(stack), 1)
        self.assertEqual((stack[0].save_rva, stack[0].restore_rva), (0x2018, 0x20B8))
        self.assertTrue(stack[0].save_bytes)
        self.assertTrue(stack[0].restore_bytes)

    def test_generated_sources_and_report_are_reproducible(self) -> None:
        _, proposal = gnu_register_case()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            report_a = write_register_indirect_control_authorities(
                first, proposal, bindings_for(proposal)
            )
            report_b = write_register_indirect_control_authorities(
                second, proposal, bindings_for(proposal)
            )
            self.assertEqual(report_a.read_bytes(), report_b.read_bytes())
            sources_a = sorted((first / "StageA").glob("*.lean"))
            sources_b = sorted((second / "StageA").glob("*.lean"))
            self.assertEqual(len(sources_a), 13)
            self.assertEqual(
                [path.read_bytes() for path in sources_a],
                [path.read_bytes() for path in sources_b],
            )

    def test_missing_machine_contract_fails_closed_with_reason_code(self) -> None:
        mixed, _ = gnu_register_case()
        report = json.loads(
            (IMPORTS / "machine-import-contract-report.json").read_text(
                encoding="utf-8"
            )
        )
        report["signatures"] = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "machine-import-contract-report.json"
            path.write_text(
                json.dumps(report, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            proposal = construct_register_indirect_control_authorities(
                original=ORIGINAL,
                state_machine=STATIC / "state-machine.jsonl",
                machine_import_report=path,
                mixed_original_plan=mixed,
                writable_slot_authority_report=(
                    WRITABLE / "relocated-writable-static-pointer-slot-authorities.json"
                ),
                callable_resource_ids_by_instruction_rva={
                    0x14140: 0,
                    0x1417B: 1,
                },
            )
        self.assertIn(
            "machine_import_preservation_missing",
            {blocker.reason_code for blocker in proposal.blockers},
        )

    def test_resolver_without_canonical_callable_capability_fails_closed(self) -> None:
        mixed, _ = gnu_register_case()
        proposal = construct_register_indirect_control_authorities(
            original=ORIGINAL,
            state_machine=STATIC / "state-machine.jsonl",
            machine_import_report=IMPORTS / "machine-import-contract-report.json",
            mixed_original_plan=mixed,
            writable_slot_authority_report=(
                WRITABLE / "relocated-writable-static-pointer-slot-authorities.json"
            ),
            callable_resource_ids_by_instruction_rva={0x14140: 0},
        )
        self.assertIn(
            "resolver_capability_unbound",
            {blocker.reason_code for blocker in proposal.blockers},
        )
        self.assertNotIn(
            0x14159,
            {site.instruction_rva for site in proposal.sites},
        )


if __name__ == "__main__":
    unittest.main()
