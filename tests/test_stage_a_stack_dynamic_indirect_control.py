from __future__ import annotations

import re
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.original_indirect_control_authority import (
    OriginalIndirectControlAuthorityBinding,
    OriginalTargetExpressionSpec,
)
from spaghetti_extractor.relational.lean.stack_dynamic_indirect_control import (
    IndexedEmptyTableProposal,
    StackDynamicBlocker,
    StackDynamicIndirectControlPlan,
    StackDynamicSiteFinding,
    stack_dynamic_indirect_control_source,
)
from spaghetti_extractor.relational.lean.stack_fixed_code_pointer import (
    LeanStackAdjustment,
)


def _binding() -> OriginalIndirectControlAuthorityBinding:
    return OriginalIndirectControlAuthorityBinding(
        dependency_module="StageA.GeneratedOriginalFixture",
        namespace="StageA.Generated.StackDynamicFixture",
        context_name="StageA.GeneratedOriginalFixture.originalContext",
        authority_name="StageA.GeneratedOriginalFixture.originalAuthority",
    )


def _blocker(reason: str) -> tuple[StackDynamicBlocker, ...]:
    return (StackDynamicBlocker(reason, "precise missing fact", "prove it"),)


def _plan() -> StackDynamicIndirectControlPlan:
    findings = (
        StackDynamicSiteFinding(
            stable_id="stack-dynamic-stack",
            source_target_id=7,
            source_rva=0x2033,
            instruction_rva=0x203C,
            instruction_bytes=bytes.fromhex("ff542420"),
            continuation_target_id=8,
            provenance_class="stack_slot",
            target=OriginalTargetExpressionSpec(
                "stack_read", "esp", adjustment=LeanStackAdjustment("add", 32)
            ),
            static_facts={"stack_register": "esp"},
            indexed_empty_table=None,
            blockers=_blocker("stack_value_provenance_missing"),
        ),
        StackDynamicSiteFinding(
            stable_id="stack-dynamic-table",
            source_target_id=9,
            source_rva=0xA220,
            instruction_rva=0xA220,
            instruction_bytes=bytes.fromhex("ff149de8804200"),
            continuation_target_id=10,
            provenance_class="indexed_immutable_table",
            target=OriginalTargetExpressionSpec(
                "indexed_table", "ebx", base_address=0x4280E8, scale=4
            ),
            static_facts={"word_0": 0xFFFFFFFF, "word_1": 0},
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
            stable_id="stack-dynamic-callback",
            source_target_id=11,
            source_rva=0xAB86,
            instruction_rva=0xAB8C,
            instruction_bytes=bytes.fromhex("ffd0"),
            continuation_target_id=12,
            provenance_class="dynamic_range_field",
            target=OriginalTargetExpressionSpec(
                "dynamic_field", "ebx", offset=4
            ),
            static_facts={"base_register": "ebx", "field_offset": 4},
            indexed_empty_table=None,
            blockers=_blocker("dynamic_callback_registration_missing"),
        ),
    )
    return StackDynamicIndirectControlPlan(
        original_pe_sha256="a" * 64,
        state_machine_sha256="b" * 64,
        original_pe_bytes=b"fixture-pe",
        findings=findings,
    )


class StageAStackDynamicIndirectControlTests(unittest.TestCase):
    def test_report_is_proposal_only_and_keeps_each_runtime_gap(self) -> None:
        payload = _plan().to_json()
        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(payload["counts"], {
            "closed": 0,
            "incomplete": 3,
            "sites": 3,
        })
        self.assertFalse(payload["artifact_role"]["acceptance_authority"])
        self.assertFalse(payload["artifact_role"]["runtime_membership_inferred"])
        self.assertNotIn("original_pe_bytes", payload)
        self.assertEqual(
            [item["provenance_class"] for item in payload["findings"]],
            ["stack_slot", "indexed_immutable_table", "dynamic_range_field"],
        )

    def test_source_rechecks_sites_and_empty_interval_in_lean(self) -> None:
        source = stack_dynamic_indirect_control_source(_plan(), _binding())
        self.assertIn("instructionBytes := [255, 84, 36, 32]", source)
        self.assertIn(".stackRead .esp .add 32", source)
        self.assertIn(".indexedTable 4358376 .ebx 4", source)
        self.assertIn(".dynamicField .ebx 4", source)
        self.assertIn("generatedStackDynamicTable1Checked", source)
        self.assertIn("generatedStackDynamicIndexedClaim1Checked", source)
        self.assertIn("generatedStackDynamicIndexedClaim1NoRuntimeIndex", source)
        self.assertIn("generatedStackDynamicIndexedClaim1SourceUnreachable", source)
        self.assertIn("ReachabilityBound actualReachable", source)
        self.assertIn("decide +kernel", source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_reviewed_lean_layer_keeps_runtime_authority_explicit(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalStackDynamicIndirectControl.lean"
        ).read_text(encoding="utf-8")
        for required in (
            "stackRangeMember : stackRange ∈ world.stackRanges",
            "valueExact : Memory.read32 state.memory",
            "RuntimeIndexBound",
            "ReachabilityBound",
            "noRuntimeIndex_of_emptyInterval",
            "sourceUnreachable_of_emptyInterval",
            "DynamicCallbackControlRuntime context claim world state",
        ):
            self.assertIn(required, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)


if __name__ == "__main__":
    unittest.main()
