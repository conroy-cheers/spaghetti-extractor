from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.relational.lean.original_indirect_control_authority import (
    OriginalIndirectControlAuthorityBinding,
    OriginalTargetExpressionSpec,
)
from spaghetti_extractor.relational.lean.stack_dynamic_indirect_control import (
    IndexedEmptyTableProposal,
    StackDynamicBlocker,
    StackDynamicIndirectControlPlan,
    StackDynamicSiteFinding,
    stable_stack_dynamic_site_id,
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


def _load_gnu_hello_driver():
    path = (
        Path(__file__).parents[1]
        / "targets/gnu-hello/nix/gnu-hello-stack-dynamic-authority.py"
    )
    name = "test_gnu_hello_stack_dynamic_authority_driver"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class StageAStackDynamicIndirectControlTests(unittest.TestCase):
    def test_stable_site_id_does_not_depend_on_target_numbering(self) -> None:
        expected = "stack-dynamic-8174534cc03bae3851d1"
        for _unrelated_target_id in (17, 298, 9001):
            self.assertEqual(
                stable_stack_dynamic_site_id(
                    original_pe_sha256=(
                        "71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c"
                    ),
                    source_rva=8243,
                    instruction_rva=8252,
                    instruction_bytes=bytes.fromhex("ff542420"),
                    provenance_class="stack_slot",
                ),
                expected,
            )

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
        self.assertIn(".stackRead .esp (.add 32)", source)
        self.assertIn(".indexedTable 4358376 .ebx 4", source)
        self.assertIn(".dynamicField .ebx 4", source)
        self.assertIn(
            "generatedStackDynamicEmptyIndexedAuthority1",
            source,
        )
        self.assertIn("CheckedEmptyIndexedSourceAuthority", source)
        self.assertIn("targetShape := by simp", source)
        self.assertIn(
            "generatedStackDynamicEmptyIndexedAuthority1NoRuntimeIndex",
            source,
        )
        self.assertIn(
            "generatedStackDynamicEmptyIndexedAuthority1SourceUnreachable",
            source,
        )
        self.assertIn("ReachabilityBound reachable", source)
        self.assertNotIn("generatedStackDynamicTable1Bytes", source)
        self.assertNotIn("IndexedImmutableTableClaim", source)
        self.assertLess(len(source), 20_000)
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
            "emptyInterval",
            "noRuntimeIndex_of_emptyChecked",
            "noRuntimeIndex_of_emptyInterval",
            "sourceUnreachable_of_emptyInterval",
            "DynamicCallbackControlRuntime context claim world state",
        ):
            self.assertIn(required, source)
        closure = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalOriginalStackDynamicControlClosure.lean"
        ).read_text(encoding="utf-8")
        for required in (
            "CheckedEmptyIndexedSourceAuthority",
            "CompleteEmptyIndexedSourcePredecessorPremise",
            "emptyIndexedSourceClosure_of_complete",
        ):
            self.assertIn(required, closure)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_gnu_hello_combined_evidence_uses_checked_generic_kernels(self) -> None:
        driver = _load_gnu_hello_driver()
        plan = driver._CombinedEvidencePlan(
            stack_site_index=0,
            constructor_site_index=1,
            dynamic_site_index=2,
            stack_source_target_id=7,
            stack_continuation_target_id=8,
            stack_target_id=9,
            stack_route_index=3,
            stack_call_frame_transfer_index=4,
            constructor_source_target_id=10,
            constructor_table_rva=0x280E8,
            constructor_branch_target_ids=(11, 12),
            constructor_decoded_outcomes=((11, (0xA248, 0xA20F)),),
            dynamic_source_target_id=13,
            dynamic_head_rva=0x30364,
            entry_target_id=14,
            tls_target_ids=(15, 16),
            dynamic_branch_target_ids=(17, 18),
            dynamic_decoded_outcomes=((17, (0xAB95, 0xAB61)),),
            registration_target_ids=(19, 20),
            registration_writer_target_ids=(21, 22),
            zero_writer_target_id=23,
        )
        graph = SimpleNamespace(
            regions=tuple(
                SimpleNamespace(target_id=target_id, rva=0x1000 + target_id)
                for target_id in range(7, 24)
            )
        )

        source = driver._combined_evidence_source(plan, graph)

        for required in (
            "RelationalOriginalCombinedExecutionInvariant",
            "OriginalStackDynamicTargetRequirement",
            "StackRelocatedCodePointerRuntime",
            "generatedStackCallFrameTransferAuthority",
            "generatedDecodedOutcomeTargetRvas?",
            "generatedConstructorDecodedOutcomesExact",
            "ImmutableImageWordMemory.read32_of_checked",
            "PreferredBaseImageMemory",
            "PE32TlsProcessAttachArgumentsHold",
            "PE32ConsoleLaunchWorldV1.Valid",
            "KnownCallbackRuntime",
            "generatedExactLaunchRootTargetIds",
            "generatedNoRegistrationEntriesChecked",
            "generatedCombinedRequirements",
            "generatedCombinedEvidenceChecked",
        ):
            self.assertIn(required, source)
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)
        driver_source = Path(driver.__file__).read_text(encoding="utf-8")
        self.assertIn('status=combined_evidence["status"]', driver_source)
        self.assertNotIn('status="checked"', driver_source)


if __name__ == "__main__":
    unittest.main()
