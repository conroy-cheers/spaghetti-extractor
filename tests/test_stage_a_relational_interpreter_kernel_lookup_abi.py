from __future__ import annotations

import re
import unittest
from pathlib import Path


class StageARelationalInterpreterKernelLookupABITests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterKernelLookupABI.lean"
        ).read_text(encoding="utf-8")

    def test_adapter_derives_concrete_lookup_facts(self) -> None:
        for required in (
            "structure ProgramLookupStaticFacts",
            "programLookupFrameInWorkspace",
            "programLookupStackHasFrame",
            "programLookupReturnedFrameHolds",
            "programLookupFrameMemory_preservesCandidateImage",
            "programLookupFrameMemory_preservesImageRead32",
            "programLookupFrameMemory_preservesProgramTable",
            "programTableCertificate_transferCount_eq_records_length",
            "request.payload.2",
            "request.originalProgramTable.countWord",
            "request.originalProgramTable.sourceWords",
            "structure ConcreteProgramLookupInvocation",
            "ProgramLookupConcreteEntry",
            "noncomputable def ConcreteKernelABI.programLookupConcreteABI",
            "theorem ConcreteKernelABI.programLookupConcreteABISpecializes",
            "ProgramLookupConcreteABI pe (ConcreteKernelABI.relation abi)",
            "structure KernelFunctionSummaryCore",
            "noncomputable def KernelFunctionSummaryCore.withConcreteABI",
            "theorem KernelFunctionSummaryCore.concreteABISpecializes",
        ):
            self.assertIn(required, self.source)

    def test_no_final_state_or_frame_fact_is_accepted(self) -> None:
        invocation = self.source.split(
            "noncomputable def concreteProgramLookupInvocation", 1
        )[1].split("noncomputable def ConcreteKernelABI.programLookupConcreteABI", 1)[0]
        for forbidden_parameter in (
            "(after : MachineState)",
            "(response : ABIResponseFacts",
            "(memoryFrame :",
            "(loadedEntry : ProgramLookupLoadedEntry",
            "(sourceDomain :",
            "(tableInterpretation :",
        ):
            self.assertNotIn(forbidden_parameter, invocation)
        self.assertIn("let facts := ConcreteKernelABI.programLookupStaticFacts abi", self.source)
        self.assertIn("programLookupReturnWord", self.source)

    def test_shared_api_retains_request_origin_and_is_fail_closed(self) -> None:
        for removed in (
            "ProgramLookupSourceAdmissible",
            "ProgramLookupTableInterpretation",
            "ProgramLookupConcreteABISharedGap",
            "responseEntryOriginMissing",
        ):
            self.assertNotIn(removed, self.source)
        constructor = self.source.split(
            "noncomputable def ConcreteKernelABI.programLookupConcreteABI", 1
        )[1].split("theorem ConcreteKernelABI.programLookupConcreteABISpecializes", 1)[0]
        self.assertIn("have request := entry.requestRelated", constructor)
        self.assertIn("invocation.entry", constructor)
        self.assertNotIn("Classical.choice", constructor)

    def test_proof_source_has_no_unchecked_escape_hatches(self) -> None:
        for marker in ("sorry", "axiom", "unsafe", "native_decide"):
            self.assertIsNone(re.search(rf"\b{marker}\b", self.source), marker)


if __name__ == "__main__":
    unittest.main()
