from __future__ import annotations

import dataclasses
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.reachable_static_pointer_slot import (
    IndirectSlotSiteProposal,
)
from spaghetti_extractor.relational.lean.reachable_static_pointer_slot_proposal import (
    construct_reachable_static_pointer_slot_proposal,
)
from tests import test_stage_a_reachable_static_pointer_slot_kernel as _slot_kernel
from tests.test_stage_a_reachable_static_pointer_slot_proposal import (
    SLOT_A_RVA,
    SLOT_B_VA,
    _two_slot_rows,
    _write_artifacts,
)


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageAReachableStaticPointerSlotProposalKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kernel = _slot_kernel.StageAReachableStaticPointerSlotKernelTests(
            methodName="runTest"
        )

    def _plan(self):
        rows = _two_slot_rows()
        code = b"".join(
            bytes.fromhex(row["instructions"][0]["bytes"]) for row in rows
        )
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        paths = _write_artifacts(
            root,
            pe_bytes=_slot_kernel._fixture_pe(
                code=code, slot_word=0, other_slot_word=0
            ),
            rows=rows,
        )
        plan = construct_reachable_static_pointer_slot_proposal(
            *paths, SLOT_A_RVA
        )
        self.assertEqual(plan.blockers, ())
        self.assertIsNotNone(plan.proposal)
        return temporary, plan.proposal, code

    def test_exact_planner_output_is_kernel_checked(self) -> None:
        temporary, spec, code = self._plan()
        assert spec is not None
        try:
            result = self.kernel._compile(
                spec,
                pe_bytes=_slot_kernel._fixture_pe(
                    code=code, slot_word=0, other_slot_word=0
                ),
                code_size=len(code),
                authority_options={
                    "check_size": 2,
                    "entries": ", ".join((
                        "{ id := 0, regionIndex := 0, rva := 0x1000 }",
                        "{ id := 1, regionIndex := 1, rva := 0x1006 }",
                    )),
                    "addresses": ", ".join((
                        "{ targetId := 0, kind := .canonical }",
                        "{ targetId := 1, kind := .canonical }",
                    )),
                    "regions": ", ".join((
                        "{ id := 0, span := { start := 0x1000, size := 6 }, "
                        "root := true, targets := [] }",
                        "{ id := 1, span := { start := 0x1006, size := 6 }, "
                        "root := true, targets := [] }",
                    )),
                },
                expectation="accepted",
            )
            self.kernel._assert_kernel_checked(result)
        finally:
            temporary.cleanup()

    def test_omitted_mutated_and_misclassified_sites_kernel_reject(self) -> None:
        temporary, spec, code = self._plan()
        assert spec is not None
        authority_options = {
            "check_size": 2,
            "entries": ", ".join((
                "{ id := 0, regionIndex := 0, rva := 0x1000 }",
                "{ id := 1, regionIndex := 1, rva := 0x1006 }",
            )),
            "addresses": ", ".join((
                "{ targetId := 0, kind := .canonical }",
                "{ targetId := 1, kind := .canonical }",
            )),
            "regions": ", ".join((
                "{ id := 0, span := { start := 0x1000, size := 6 }, root := true, targets := [] }",
                "{ id := 1, span := { start := 0x1006, size := 6 }, root := true, targets := [] }",
            )),
        }
        cases = (
            (
                "omitted",
                dataclasses.replace(
                    spec,
                    definition_name="omittedPlannedSiteCertificate",
                    indirect_slot_sites=(),
                ),
                code,
            ),
            (
                "misclassified",
                dataclasses.replace(
                    spec,
                    definition_name="misclassifiedPlannedSiteCertificate",
                    indirect_slot_sites=(IndirectSlotSiteProposal(1),),
                ),
                code,
            ),
            (
                "mutated-exact-bytes",
                dataclasses.replace(
                    spec,
                    definition_name="mutatedPlannedSiteCertificate",
                ),
                b"\xff\x25"
                + SLOT_B_VA.to_bytes(4, "little")
                + code[6:],
            ),
        )
        try:
            for label, changed_spec, changed_code in cases:
                with self.subTest(label=label):
                    result = self.kernel._compile(
                        changed_spec,
                        pe_bytes=_slot_kernel._fixture_pe(
                            code=changed_code,
                            slot_word=0,
                            other_slot_word=0,
                        ),
                        code_size=len(changed_code),
                        authority_options=authority_options,
                        expectation="rejected",
                    )
                    self.kernel._assert_kernel_checked(result)
        finally:
            temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
