from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.artifacts.artifact_set import RecordDependencyV3
from spaghetti_extractor.authority._schema import AnalysisV3Error
from spaghetti_extractor.authority.parametric_summary_records import (
    PARAMETRIC_SCC_SUMMARY_CODEC_V3,
    PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3,
    CallEffectV3,
    ParametricSccProposalV3,
    ParametricSccSummaryV3,
    RegisterRelationV3,
    ReturnBehaviorV3,
    ValueFactV3,
    ValueOriginV3,
)


def _proposal() -> ParametricSccProposalV3:
    return ParametricSccProposalV3.create(
        scc_id="scc:one",
        member_unit_ids=("unit:a",),
        base_path_unit_ids=(),
        value_budget=4,
        value_facts=(
            ValueFactV3(
                "fact:eax",
                "finite",
                (ValueOriginV3("entry_register", "eax", 0),),
            ),
        ),
        register_relations=(
            RegisterRelationV3(
                "relation:eax", "unit:a", "eax", "preserved", "fact:eax"
            ),
        ),
        stack_accesses=(),
        stack_cleanup_bytes=None,
        return_address_preserved=True,
        memory_effects=(),
        call_effects=(
            CallEffectV3(
                "call:0",
                "unit:a",
                0,
                "direct_internal",
                ("unit:b",),
                None,
                (),
                None,
                ("ebp", "ebx", "edi", "esi"),
            ),
        ),
        returns=(ReturnBehaviorV3("unit:a", False, True, None, False),),
        indirect_exits=(),
        dependencies=(RecordDependencyV3("semantic_index", "unit:a"),),
    )


class ParametricSummaryRecordTests(unittest.TestCase):
    def test_world_origins_and_signed_stack_offsets_round_trip(self) -> None:
        origins = (
            ValueOriginV3("entry_stack_word", "entry:arg0", -12),
            ValueOriginV3("stack_frame_location", "frame:main", -32),
            ValueOriginV3("static_code_target", "unit:callback", 4),
            ValueOriginV3("static_data_location", "section:.data", 16),
            ValueOriginV3("import_target", "profile:malloc", 0),
            ValueOriginV3("dynamic_range_location", "allocation:7", 24),
            ValueOriginV3("opaque_resource", "resource:surface", None),
        )

        self.assertEqual(
            tuple(ValueOriginV3.parse(row.to_payload()) for row in origins),
            origins,
        )

    def test_impossible_return_and_register_shapes_fail_at_record_boundary(self) -> None:
        with self.assertRaises(AnalysisV3Error):
            ReturnBehaviorV3("unit:a", False, False, None, False)
        with self.assertRaises(AnalysisV3Error):
            RegisterRelationV3(
                "relation:bad", "unit:a", "rip", "preserved", "fact:eax"
            )

    def test_recursive_complete_summary_requires_checked_base_path(self) -> None:
        proposal = _proposal()
        with self.assertRaises(AnalysisV3Error) as raised:
            ParametricSccSummaryV3(
                record_id=proposal.scc_id,
                scc_id=proposal.scc_id,
                status="complete",
                authorizing=True,
                proposal_id=proposal.proposal_id,
                member_unit_ids=proposal.member_unit_ids,
                recursive=True,
                checked_base_path_unit_ids=(),
                value_facts=proposal.value_facts,
                register_relations=proposal.register_relations,
                stack_accesses=(),
                stack_cleanup_bytes=None,
                return_address_preserved=True,
                memory_effects=(),
                call_effects=proposal.call_effects,
                returns=proposal.returns,
                indirect_exits=(),
                primary_blocker=None,
                dependencies=proposal.dependencies,
            )
        self.assertEqual(raised.exception.code, "fail_open_parametric_summary")

    def test_proposal_round_trip_has_stable_root_independent_identity(self) -> None:
        proposal = _proposal()
        payload = PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3.encode(proposal)

        self.assertEqual(PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3.decode(payload), proposal)
        self.assertTrue(payload["root_independent"])
        self.assertNotIn("launch_roots", payload)
        self.assertNotIn("reachable_unit_ids", payload)
        self.assertEqual(ParametricSccProposalV3.create(
            scc_id="scc:one",
            member_unit_ids=("unit:a",),
            base_path_unit_ids=(),
            value_budget=4,
            value_facts=proposal.value_facts,
            register_relations=proposal.register_relations,
            stack_accesses=(),
            stack_cleanup_bytes=None,
            return_address_preserved=True,
            memory_effects=(),
            call_effects=proposal.call_effects,
            returns=proposal.returns,
            indirect_exits=(),
            dependencies=proposal.dependencies,
        ).proposal_id, proposal.proposal_id)

    def test_typed_queries_hide_wire_payloads(self) -> None:
        proposal = _proposal()

        self.assertEqual(proposal.value_fact("fact:eax"), proposal.value_facts[0])
        self.assertEqual(
            proposal.register_relation("unit:a", "eax"),
            proposal.register_relations[0],
        )
        self.assertEqual(proposal.call_effect("unit:a", 0), proposal.call_effects[0])
        self.assertIsNone(proposal.indirect_exit("missing"))

    def test_checked_summary_queries_member_coverage_and_preservation(self) -> None:
        proposal = _proposal()
        summary = ParametricSccSummaryV3(
            record_id=proposal.scc_id,
            scc_id=proposal.scc_id,
            status="complete",
            authorizing=True,
            proposal_id=proposal.proposal_id,
            member_unit_ids=proposal.member_unit_ids,
            recursive=False,
            checked_base_path_unit_ids=(),
            value_facts=proposal.value_facts,
            register_relations=proposal.register_relations,
            stack_accesses=(),
            stack_cleanup_bytes=None,
            return_address_preserved=True,
            memory_effects=(),
            call_effects=proposal.call_effects,
            returns=proposal.returns,
            indirect_exits=(),
            primary_blocker=None,
            dependencies=proposal.dependencies,
        )
        payload = PARAMETRIC_SCC_SUMMARY_CODEC_V3.encode(summary)

        decoded = PARAMETRIC_SCC_SUMMARY_CODEC_V3.decode(payload)
        self.assertEqual(decoded.member_unit_ids, ("unit:a",))
        self.assertTrue(decoded.preserves_register("unit:a", "eax"))
        self.assertEqual(decoded.call_effect("unit:a", 0), proposal.call_effects[0])

    def test_corrupted_proposal_identity_fails_closed(self) -> None:
        payload = PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3.encode(_proposal())
        corrupted = copy.deepcopy(payload)
        corrupted["value_budget"] = 5

        with self.assertRaises(AnalysisV3Error) as raised:
            PARAMETRIC_SUMMARY_PROPOSAL_CODEC_V3.decode(corrupted)
        self.assertEqual(raised.exception.code, "stale_record_id")


if __name__ == "__main__":
    unittest.main()
