from __future__ import annotations

import dataclasses
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.original_indirect_control_authority import (
    OriginalIndirectControlAuthorityBinding,
    OriginalTargetExpressionSpec,
)
from spaghetti_extractor.relational.lean.original_stack_dynamic_control_closure import (
    DynamicCallbackAuthorityHint,
    OriginalStackDynamicControlClosureError,
    OriginalStackDynamicControlClosureSpec,
    StackCarryAuthorityHint,
    original_stack_dynamic_control_closure_source,
    plan_original_stack_dynamic_control_closure,
    write_original_stack_dynamic_control_closure,
)
from spaghetti_extractor.relational.lean.stack_dynamic_indirect_control import (
    IndexedEmptyTableProposal,
    StackDynamicBlocker,
    StackDynamicIndirectControlPlan,
    StackDynamicSiteFinding,
)
from spaghetti_extractor.relational.lean.stack_fixed_code_pointer import (
    LeanStackAdjustment,
)


GNU_PE_SHA256 = "71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c"
GNU_STATE_SHA256 = "c5e86855c7757dc0cc71d2a1f21988980621b49206ec4bee54d23497dd88072c"


def _blocker(reason: str) -> tuple[StackDynamicBlocker, ...]:
    return (StackDynamicBlocker(reason, "missing runtime fact", "prove it"),)


def _proposal() -> StackDynamicIndirectControlPlan:
    return StackDynamicIndirectControlPlan(
        original_pe_sha256=GNU_PE_SHA256,
        state_machine_sha256=GNU_STATE_SHA256,
        original_pe_bytes=b"exact-pe-bytes",
        findings=(
            StackDynamicSiteFinding(
                stable_id="gnu-stack-203c",
                source_target_id=291,
                source_rva=0x2033,
                instruction_rva=0x203C,
                instruction_bytes=bytes.fromhex("ff542420"),
                continuation_target_id=292,
                provenance_class="stack_slot",
                target=OriginalTargetExpressionSpec(
                    "stack_read",
                    "esp",
                    adjustment=LeanStackAdjustment("add", 32),
                ),
                static_facts={
                    "stack_adjustment": {"amount": 32, "kind": "add"},
                    "stack_register": "esp",
                },
                indexed_empty_table=None,
                blockers=_blocker("stack_value_provenance_missing"),
            ),
            StackDynamicSiteFinding(
                stable_id="gnu-table-a220",
                source_target_id=2591,
                source_rva=0xA220,
                instruction_rva=0xA220,
                instruction_bytes=bytes.fromhex("ff149de8804200"),
                continuation_target_id=2592,
                provenance_class="indexed_immutable_table",
                target=OriginalTargetExpressionSpec(
                    "indexed_table",
                    "ebx",
                    base_address=0x4280E8,
                    scale=4,
                ),
                static_facts={
                    "address_scale": 4,
                    "index_register": "ebx",
                    "table_base_rva": 0x280E8,
                    "word_0": 0xFFFFFFFF,
                    "word_1": 0,
                },
                indexed_empty_table=IndexedEmptyTableProposal(
                    table_rva=0x280E8,
                    range_rva=0x280EC,
                    index_register="ebx",
                    lower_inclusive=1,
                    address_scale=4,
                    header_words=(0xFFFFFFFF,),
                ),
                blockers=_blocker("indexed_table_reachability_bound_missing"),
            ),
            StackDynamicSiteFinding(
                stable_id="gnu-dynamic-ab8c",
                source_target_id=2760,
                source_rva=0xAB86,
                instruction_rva=0xAB8C,
                instruction_bytes=bytes.fromhex("ffd0"),
                continuation_target_id=2761,
                provenance_class="dynamic_range_field",
                target=OriginalTargetExpressionSpec(
                    "dynamic_field", "ebx", offset=4
                ),
                static_facts={"base_register": "ebx", "field_offset": 4},
                indexed_empty_table=None,
                blockers=_blocker("dynamic_callback_registration_missing"),
            ),
        ),
    )


def _spec() -> OriginalStackDynamicControlClosureSpec:
    return OriginalStackDynamicControlClosureSpec(
        stack_hints=(
            StackCarryAuthorityHint(
                stable_id="gnu-stack-203c",
                seed_slot_rva=0x200D0,
                seed_target_id=5250,
            ),
        ),
        dynamic_hints=(
            DynamicCallbackAuthorityHint(
                stable_id="gnu-dynamic-ab8c",
                mode="source_uninhabited",
            ),
        ),
    )


def _binding() -> OriginalIndirectControlAuthorityBinding:
    return OriginalIndirectControlAuthorityBinding(
        dependency_module="StageA.GeneratedGnuHelloOriginal",
        namespace="StageA.Generated.GnuStackDynamicClosure",
        context_name="StageA.GeneratedGnuHelloOriginal.originalContext",
        authority_name="StageA.GeneratedGnuHelloOriginal.originalAuthority",
    )


class StageAOriginalStackDynamicControlClosureTests(unittest.TestCase):
    def _plan(self):
        return plan_original_stack_dynamic_control_closure(
            _proposal(),
            _spec(),
            original_pe_sha256=GNU_PE_SHA256,
            state_machine_sha256=GNU_STATE_SHA256,
        )

    def test_exact_gnu_sites_emit_checked_static_authority_and_typed_premises(
        self,
    ) -> None:
        plan = self._plan()
        report = plan.to_json()
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["artifact_role"]["acceptance_authority"])
        self.assertFalse(
            report["artifact_role"]["report_status_closes_obligations"]
        )
        self.assertEqual(
            [site["instruction_rva"] for site in report["sites"]],
            [0x203C, 0xA220, 0xAB8C],
        )
        self.assertEqual(
            [site["premise_type"] for site in report["sites"]],
            [
                "CompleteStackCarryPremise",
                "CompleteEmptyIndexedSourcePredecessorPremise",
                "CompleteDynamicSourceUninhabitedPremise",
            ],
        )
        self.assertEqual(report["sites"][0]["allowed_target_ids"], [5250])
        source = original_stack_dynamic_control_closure_source(
            plan, _binding()
        )
        for expected in (
            GNU_PE_SHA256,
            GNU_STATE_SHA256,
            "sourceTargetId := 291",
            "instructionRva := 8252",
            "instructionBytes := [255, 84, 36, 32]",
            "transfer := .call 292",
            "slotRva := 131280",
            "targetId := 5250",
            "sourceTargetId := 2591",
            "instructionRva := 41504",
            "instructionBytes := [255, 20, 157, 232, 128, 66, 0]",
            "transfer := .call 2592",
            "sourceTargetId := 2760",
            "instructionRva := 43916",
            "instructionBytes := [255, 208]",
            "transfer := .call 2761",
            "CompleteStackCarryPremise",
            "CompleteEmptyIndexedSourcePredecessorPremise",
            "CompleteDynamicSourceUninhabitedPremise",
            "CheckedEmptyIndexedSourceAuthority",
            "emptyIndexedSourceClosure_of_complete",
            "decide +kernel",
        ):
            self.assertIn(expected, source)
        self.assertNotIn("generatedOriginalStackDynamicClosure1TableBytes", source)
        self.assertNotIn("IndexedImmutableTableClaim", source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_hash_and_exact_site_mutations_are_rejected(self) -> None:
        with self.assertRaisesRegex(
            OriginalStackDynamicControlClosureError, "PE SHA-256"
        ):
            plan_original_stack_dynamic_control_closure(
                _proposal(),
                _spec(),
                original_pe_sha256="0" * 64,
                state_machine_sha256=GNU_STATE_SHA256,
            )
        with self.assertRaisesRegex(
            OriginalStackDynamicControlClosureError, "state-machine SHA-256"
        ):
            plan_original_stack_dynamic_control_closure(
                _proposal(),
                _spec(),
                original_pe_sha256=GNU_PE_SHA256,
                state_machine_sha256="0" * 64,
            )
        findings = list(_proposal().findings)
        findings[0] = dataclasses.replace(findings[0], instruction_bytes=b"")
        with self.assertRaisesRegex(
            OriginalStackDynamicControlClosureError, "no instruction bytes"
        ):
            plan_original_stack_dynamic_control_closure(
                dataclasses.replace(_proposal(), findings=tuple(findings)),
                _spec(),
                original_pe_sha256=GNU_PE_SHA256,
                state_machine_sha256=GNU_STATE_SHA256,
            )
        duplicate = dataclasses.replace(
            _proposal(), findings=(_proposal().findings[0],) * 2
        )
        with self.assertRaisesRegex(
            OriginalStackDynamicControlClosureError, "duplicate exact site"
        ):
            plan_original_stack_dynamic_control_closure(
                duplicate,
                OriginalStackDynamicControlClosureSpec(
                    stack_hints=_spec().stack_hints,
                    dynamic_hints=(),
                ),
                original_pe_sha256=GNU_PE_SHA256,
                state_machine_sha256=GNU_STATE_SHA256,
            )

    def test_report_status_and_classifier_blockers_cannot_close_a_site(
        self,
    ) -> None:
        proposal = dataclasses.replace(
            _proposal(),
            findings=tuple(
                dataclasses.replace(finding, blockers=())
                for finding in _proposal().findings
            ),
        )
        plan = plan_original_stack_dynamic_control_closure(
            proposal,
            _spec(),
            original_pe_sha256=GNU_PE_SHA256,
            state_machine_sha256=GNU_STATE_SHA256,
        )
        self.assertFalse(plan.runtime_complete)
        self.assertEqual(plan.to_json()["status"], "incomplete")
        source = original_stack_dynamic_control_closure_source(
            plan, _binding()
        )
        self.assertEqual(source.count("RuntimePremise"), 6)
        self.assertNotIn("closure_status", source)
        self.assertNotIn("blockers", source)

    def test_write_emits_hash_bound_report_and_lean_module(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report, lean = write_original_stack_dynamic_control_closure(
                Path(temporary), self._plan(), _binding()
            )
            payload = report.read_text(encoding="utf-8")
            source = lean.read_text(encoding="utf-8")
        self.assertIn(GNU_PE_SHA256, payload)
        self.assertIn(GNU_STATE_SHA256, payload)
        self.assertIn(
            "GeneratedRelationalOriginalStackDynamicControlClosure.lean",
            str(lean),
        )
        self.assertIn("generatedOriginalStackDynamicPeSha256", source)


if __name__ == "__main__":
    unittest.main()
