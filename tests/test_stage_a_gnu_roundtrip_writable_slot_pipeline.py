from __future__ import annotations

import unittest
from pathlib import Path


class StageAGnuRoundtripWritableSlotPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[1]
        self.driver = (
            self.repo / "nix/gnu-hello-roundtrip-driver.py"
        ).read_text(encoding="utf-8")
        self.lane = (
            self.repo / "nix/gnu-hello-roundtrip.nix"
        ).read_text(encoding="utf-8")

    def test_driver_uses_named_checked_authorities_and_consumed_plan(self) -> None:
        start = self.driver.index(
            "def _mixed_original_writable_slot_authority"
        )
        stop = self.driver.index(
            "def _checked_mixed_original_base_plan", start
        )
        phase = self.driver[start:stop]

        for required in (
            "construct_relocated_writable_static_pointer_slot_authorities",
            "write_relocated_writable_static_pointer_slot_authorities",
            "load_relocated_writable_static_pointer_slot_authorities",
            "consume_relocated_writable_static_pointer_slot_authorities",
            "write_relational_interpreter_mixed_original_base",
            "decompose_interpreter_mixed_original_base",
            "write_decomposed_writable_static_pointer_slot_adapters",
            "generatedExactOriginalDecodedAuthority",
            "authorizing_lean_terms=list(consumed.authorizing_terms)",
            "adapter_terms=[adapter.valid_term for adapter in adapters]",
            "indirect_exit_certificate_terms=[",
            "adapter.indirect_exit_term for adapter in adapters",
            'failure_mode="incomplete"',
        ):
            self.assertIn(required, phase)
        self.assertNotIn('status == "pass"', phase)
        self.assertNotIn('payload.get("status")', phase)

    def test_nix_phase_replaces_raw_base_in_composition_and_checks_counts(
        self,
    ) -> None:
        phase_start = self.lane.index(
            "mixedOriginalWritableSlotAuthorityLean = mkPhase"
        )
        phase_end = self.lane.index(
            "mixedOriginalDirectCallProposalsLean =", phase_start
        )
        phase = self.lane[phase_start:phase_end]
        carrier_start = self.lane.index(
            "mixedOriginalCarrierBindingProofSources = mkPhase"
        )
        carrier_end = self.lane.index(
            "mixedOriginalCarrierBindingProofModules =", carrier_start
        )
        carrier = self.lane[carrier_start:carrier_end]
        proof_start = self.lane.index("proofSources = mkPhase")
        proof_end = self.lane.index("proofModules =", proof_start)
        proof_sources = self.lane[proof_start:proof_end]

        for required in (
            "mixed-original-writable-slot-authority",
            "${originalPe}",
            "${staticExport}/state-machine.jsonl",
            "${staticMachineImportContractsLean}/"
            "machine-import-contract-report.json",
            "${mixedOriginalBaseLean}/"
            "interpreter-mixed-original-base-plan.json",
            ".counts.authority_terms > 0",
            ".counts.blockers_before ==",
            "(.counts.blockers_after + .counts.authority_terms)",
            ".artifact_role.lean_checker_must_reparse_and_redecode",
        ):
            self.assertIn(required, phase)
        self.assertIn(
            "--source ${mixedOriginalWritableSlotAuthorityLean}", carrier
        )
        self.assertIn(
            "--source ${mixedOriginalWritableSlotAuthorityLean}",
            proof_sources,
        )
        self.assertNotIn("--source ${mixedOriginalBaseLean}", carrier)
        self.assertNotIn("--source ${mixedOriginalBaseLean}", proof_sources)
        self.assertIn(
            "mixedOriginalWritableSlotAuthorityLean", self.lane.rsplit(
                "in\n{", 1
            )[-1]
        )

    def test_downstream_plans_are_hash_bound_to_the_authority_report(
        self,
    ) -> None:
        for command, successor in (
            (
                "mixedOriginalDirectCallProposalsLean",
                "mixedOriginalDirectCallSemanticsLean",
            ),
            ("mixedOriginalLean", "mixedOriginalCarrierBindingLean"),
        ):
            start = self.lane.index(f"{command} = mkPhase")
            stop = self.lane.index(f"{successor} =", start)
            phase = self.lane[start:stop]
            self.assertIn("--writable-slot-authority-report", phase)
            self.assertIn(
                "${mixedOriginalWritableSlotAuthorityLean}/"
                "relocated-writable-static-pointer-slot-authorities.json",
                phase,
            )


if __name__ == "__main__":
    unittest.main()
