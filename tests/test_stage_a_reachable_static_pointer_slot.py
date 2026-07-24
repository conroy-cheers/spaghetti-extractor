from __future__ import annotations

import dataclasses
import unittest

from spaghetti_extractor.relational.lean.reachable_static_pointer_slot import (
    GuardedNonzeroEdgeProposal,
    IndirectSlotSiteProposal,
    LeanAuthorityBinding,
    ReachableStaticPointerSlotCertificateSpec,
    ReachableStaticPointerSlotGenerationError,
    RegionBindingProposal,
    WriteClassificationProposal,
    reachable_static_pointer_slot_source,
)


def minimal_spec() -> ReachableStaticPointerSlotCertificateSpec:
    return ReachableStaticPointerSlotCertificateSpec(
        definition_name="fixtureCertificate",
        authority=LeanAuthorityBinding(
            module="StageA.GeneratedReachableSlotFixture",
            namespace="StageA.GeneratedReachableSlotFixture",
            context_name="originalContext",
            authority_name="originalAuthority",
        ),
        slot_rva=0x2020,
        reachable_target_ids=(0,),
        allowed_target_ids=(),
        regions=(),
        guarded_nonzero_edges=(),
        indirect_slot_sites=(),
        aliases=(),
    )


class StageAReachableStaticPointerSlotTests(unittest.TestCase):
    def test_emits_only_finite_proposal_and_kernel_obligations(self) -> None:
        source = reachable_static_pointer_slot_source(minimal_spec())
        self.assertIn("fixtureCertificate.checked", source)
        self.assertIn("decide +kernel", source)
        self.assertIn("ExactOriginalDecodedAuthority", source)
        self.assertIn("KernelEvidence", source)
        self.assertIn("Certificate.trace_preserves", source)
        self.assertNotIn("native_decide", source)
        self.assertNotIn("sorry", source)
        self.assertNotIn("axiom ", source)

    def test_unknown_inventories_remain_explicit_and_fail_closed_in_lean(self) -> None:
        source = reachable_static_pointer_slot_source(
            dataclasses.replace(
                minimal_spec(),
                definition_name="unknownCertificate",
                reachable_target_ids=None,
                regions=None,
            ),
            expectation="rejected",
        )
        self.assertGreaterEqual(source.count(".unknown"), 2)
        self.assertIn("= false", source)
        self.assertNotIn("unknownCertificateEvidence", source)

    def test_serializes_write_guard_and_indirect_bindings(self) -> None:
        source = reachable_static_pointer_slot_source(
            dataclasses.replace(
                minimal_spec(),
                allowed_target_ids=(7,),
                regions=(
                    RegionBindingProposal(
                        target_id=0,
                        writes=(
                            WriteClassificationProposal("absolute_disjoint"),
                            WriteClassificationProposal("runtime_separated"),
                            WriteClassificationProposal(
                                "slot_code_target", target_id=7
                            ),
                        ),
                    ),
                ),
                guarded_nonzero_edges=(
                    GuardedNonzeroEdgeProposal(0, 1),
                ),
                indirect_slot_sites=(IndirectSlotSiteProposal(1),),
            )
        )
        self.assertIn(".absoluteDisjoint", source)
        self.assertIn(".runtimeSeparated", source)
        self.assertIn(".slotCodeTarget 7", source)
        self.assertIn("nonzeroTargetId := 1", source)
        self.assertIn("indirectSlotSites := .exact", source)

    def test_rejects_unrepresentable_names_words_and_classifications(self) -> None:
        cases = (
            dataclasses.replace(minimal_spec(), definition_name="bad-name"),
            dataclasses.replace(minimal_spec(), slot_rva=1 << 32),
            dataclasses.replace(
                minimal_spec(),
                regions=(
                    RegionBindingProposal(
                        target_id=0,
                        writes=(
                            WriteClassificationProposal(
                                "slot_code_target", target_id=None
                            ),
                        ),
                    ),
                ),
            ),
        )
        for spec in cases:
            with self.subTest(spec=spec):
                with self.assertRaises(
                    ReachableStaticPointerSlotGenerationError
                ):
                    reachable_static_pointer_slot_source(spec)


if __name__ == "__main__":
    unittest.main()
