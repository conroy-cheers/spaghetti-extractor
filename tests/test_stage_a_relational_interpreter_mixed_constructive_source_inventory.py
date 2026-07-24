from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_mixed_constructive_source_inventory import (
    CheckedKernelEntryBinding,
    ConstructiveClassifierTerms,
    ConstructiveSourceInventoryGenerationError,
    ConstructiveSourceInventorySpec,
    ConstructiveSourceRuleBinding,
    ExactSemanticSourceBinding,
    build_constructive_source_inventory_plan,
    relational_interpreter_mixed_constructive_source_inventory_source,
    write_constructive_source_inventory_bundle,
)


def _source(index: int) -> ExactSemanticSourceBinding:
    return ExactSemanticSourceBinding(
        name=f"source{index}",
        target_id=index,
        source_rva=0x1000 + index * 0x10,
        record_index=index,
        source_term=f"requirements.source{index}",
        target_id_exact=f"requirements.source{index}TargetIdExact",
        source_rva_exact=f"requirements.source{index}RvaExact",
        record_at_index_exact=f"requirements.source{index}RecordExact",
    )


def _entry(name: str, operation: str, entry_rva: int) -> CheckedKernelEntryBinding:
    return CheckedKernelEntryBinding(
        name=name,
        operation=operation,
        entry_rva=entry_rva,
        function_entry_exact=f"requirements.{name}EntryExact",
    )


def _spec() -> ConstructiveSourceInventorySpec:
    sources = tuple(_source(index) for index in range(4))
    entries = (
        _entry("lookup", "programLookup", 0x2000),
        _entry("invoke", "invokeCall", 0x2100),
        _entry("run", "runFunction", 0x2200),
    )
    return ConstructiveSourceInventorySpec(
        binding_module="StageA.ConstructiveSourceInventoryFixture",
        parameter_name="requirements",
        parameter_type="StageA.ConstructiveSourceInventoryFixture.Requirements",
        namespace="StageA.GeneratedRelational.ConstructiveSourceInventory",
        terms=ConstructiveClassifierTerms(
            original_context="requirements.originalContext",
            original_authority="requirements.originalAuthority",
            launch_profile="requirements.launchProfile",
            original_root="requirements.originalRoot",
            reachability="requirements.reachability",
            original_program="requirements.originalProgram",
            candidate="requirements.candidate",
            candidate_authority="requirements.candidateAuthority",
            compiled_program="requirements.program",
            kernel_abi="requirements.abi",
            kernel_dispatches="requirements.dispatches",
            relation_contract="requirements.contract",
            candidate_root_rva="requirements.candidateRootRva",
            launch_root_target_id_exact="requirements.launchRootTargetIdExact",
            candidate_root_rva_exact="requirements.candidateRootRvaExact",
            candidate_record_count_exact="requirements.candidateRecordCountExact",
            reachability_target_ids_exact=("requirements.reachabilityTargetIdsExact"),
        ),
        candidate_root_rva=0x3000,
        launch_root_target_id=0,
        candidate_record_count=4,
        expected_target_ids=(0, 1, 2, 3),
        expected_operations=("programLookup", "invokeCall", "runFunction"),
        sources=sources,
        entries=entries,
        rules=(
            ConstructiveSourceRuleBinding("source0", "launch"),
            ConstructiveSourceRuleBinding("source1", "semantic_transfer", "lookup"),
            ConstructiveSourceRuleBinding("source2", "external_operation", "invoke"),
            ConstructiveSourceRuleBinding(
                "source3",
                "external_boundary",
                "run",
                candidate_rva=0x2300,
            ),
        ),
    )


class StageARelationalInterpreterMixedConstructiveSourceInventoryTests(
    unittest.TestCase
):
    def test_plan_is_deterministic_and_serializes_typed_residuals(self) -> None:
        spec = _spec()
        reversed_spec = replace(
            spec,
            sources=tuple(reversed(spec.sources)),
            entries=tuple(reversed(spec.entries)),
            rules=tuple(reversed(spec.rules)),
        )
        first = build_constructive_source_inventory_plan(spec)
        second = build_constructive_source_inventory_plan(reversed_spec)

        self.assertEqual(first.payload(), second.payload())
        payload = first.payload()
        self.assertFalse(payload["acceptance_authority"])
        self.assertNotIn("status", payload)
        self.assertNotIn("verdict", payload)
        self.assertEqual(
            payload["checked_finite_facts"]["record_indices"], [0, 1, 2, 3]
        )
        self.assertEqual(payload["checked_finite_facts"]["one_rule_per_source"], True)
        self.assertTrue(
            payload["checked_finite_facts"]["all_reachable_sources_associated"]
        )
        self.assertTrue(
            payload["checked_finite_facts"][
                "candidate_record_associations_unique_and_in_bounds"
            ]
        )
        self.assertTrue(
            payload["checked_finite_facts"]["unused_candidate_records_allowed"]
        )
        self.assertEqual(
            payload["typed_residuals"][:2],
            [
                "ConstructiveMixedKernelStateFacts reachability.targetIds "
                "relationContract originalBefore candidateBefore",
                "constructiveMixedKernelSourceEvidence? generatedRules "
                "originalBefore candidateBefore = some evidence",
            ],
        )

    def test_source_emits_checked_rules_and_no_residual_inhabitants(self) -> None:
        source = relational_interpreter_mixed_constructive_source_inventory_source(
            build_constructive_source_inventory_plan(_spec())
        )
        for required in (
            "ExactOriginalSemanticSource",
            "generatedCandidateRecordSourceRvasUnique",
            "generatedSourceSource0RecordAtIndexExact",
            "generatedRecordIndicesUnique",
            "generatedRecordIndicesInBounds",
            "generatedReachabilityTargetIdsExact",
            "ExactCandidateKernelEntry",
            "entryExact := requirements.lookupEntryExact",
            ".launch",
            ".semanticTransfer",
            ".externalOperation",
            ".externalBoundary",
            "generatedConstructiveSourceRules",
            "generatedRuleSourceTargetId",
            "generatedRuleCandidateRva",
            "generatedRuleMatchKey",
            "generatedRuleSourceTargetIdsExact",
            "generatedRulesCoverReachability",
            "generatedRuleMatchKeysExact",
            "generatedRuleMatchKeysUnique",
            "generatedRuleSourceTargetIdsUnique",
            "generatedActualRuleMatchKeysUnique",
            "constructiveMixedKernelInvariant",
            "constructiveMixedKernelSourceClassifier",
            "inductive GeneratedConstructiveRuleSemanticResidual",
            "MixedKernelChunkPaths",
            "MixedKernelOperationComponentCertificate",
            "structure GeneratedConstructiveSourceResidual",
            "ConstructiveMixedKernelStateFacts",
            "classificationExact",
            "semantic :",
            "constructiveMixedKernelInvariant_holds",
        ):
            self.assertIn(required, source)
        for forbidden in (
            r"\bstatus\b",
            r"\bverdict\b",
            r"\baxiom\b",
            r"\bsorry\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bhello\b",
            r"\bjq\b",
        ):
            self.assertNotRegex(source, forbidden)
        residual = source.split("structure GeneratedConstructiveSourceResidual", 1)[
            1
        ].split("theorem GeneratedConstructiveSourceResidual.invariantHolds", 1)[0]
        self.assertNotIn(":=", residual)

    def test_missing_and_ambiguous_source_mappings_fail_closed(self) -> None:
        spec = _spec()
        with self.assertRaisesRegex(
            ConstructiveSourceInventoryGenerationError, "missing=.*source3"
        ):
            build_constructive_source_inventory_plan(
                replace(spec, rules=spec.rules[:-1])
            )
        with self.assertRaisesRegex(
            ConstructiveSourceInventoryGenerationError,
            "ambiguous=.*source1",
        ):
            build_constructive_source_inventory_plan(
                replace(
                    spec,
                    rules=spec.rules
                    + (
                        ConstructiveSourceRuleBinding(
                            "source1", "external_operation", "invoke"
                        ),
                    ),
                )
            )

    def test_duplicate_and_out_of_bounds_exact_associations_fail_closed(self) -> None:
        spec = _spec()
        duplicate_target = replace(spec.sources[1], target_id=0)
        with self.assertRaisesRegex(
            ConstructiveSourceInventoryGenerationError,
            "duplicate exact source target ID",
        ):
            build_constructive_source_inventory_plan(
                replace(
                    spec,
                    sources=(spec.sources[0], duplicate_target) + spec.sources[2:],
                )
            )
        with self.assertRaisesRegex(
            ConstructiveSourceInventoryGenerationError,
            "outside the candidate table",
        ):
            build_constructive_source_inventory_plan(
                replace(
                    spec,
                    sources=spec.sources[:-1]
                    + (replace(spec.sources[-1], record_index=7),),
                )
            )

    def test_unused_candidate_records_are_allowed(self) -> None:
        plan = build_constructive_source_inventory_plan(
            replace(_spec(), candidate_record_count=6)
        )

        self.assertEqual(
            plan.payload()["checked_finite_facts"]["record_indices"],
            [0, 1, 2, 3],
        )
        source = relational_interpreter_mixed_constructive_source_inventory_source(
            plan
        )
        self.assertIn("index < 6", source)
        self.assertNotIn("List.range 6", source)

    def test_duplicate_rules_entries_and_unknown_terms_are_rejected(self) -> None:
        spec = _spec()
        with self.assertRaisesRegex(
            ConstructiveSourceInventoryGenerationError,
            "duplicate constructive source rule",
        ):
            build_constructive_source_inventory_plan(
                replace(spec, rules=spec.rules + (spec.rules[-1],))
            )
        with self.assertRaisesRegex(
            ConstructiveSourceInventoryGenerationError,
            "duplicate candidate operation entry",
        ):
            build_constructive_source_inventory_plan(
                replace(
                    spec,
                    entries=spec.entries
                    + (_entry("lookupAgain", "programLookup", 0x2400),),
                )
            )
        with self.assertRaisesRegex(
            ConstructiveSourceInventoryGenerationError,
            "canonical Lean identifier",
        ):
            build_constructive_source_inventory_plan(
                replace(
                    spec,
                    sources=(
                        replace(
                            spec.sources[0],
                            source_term="requirements.source0; exact False.elim",
                        ),
                    )
                    + spec.sources[1:],
                )
            )
        with self.assertRaisesRegex(
            ConstructiveSourceInventoryGenerationError,
            "canonical Lean identifier",
        ):
            build_constructive_source_inventory_plan(
                replace(
                    spec,
                    terms=replace(
                        spec.terms,
                        reachability_target_ids_exact=(
                            "requirements.bad; exact False.elim"
                        ),
                    ),
                )
            )

    def test_bundle_is_reproducible(self) -> None:
        plan = build_constructive_source_inventory_plan(_spec())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = write_constructive_source_inventory_bundle(root / "first", plan)
            second = write_constructive_source_inventory_bundle(root / "second", plan)
            self.assertEqual(first[0].read_bytes(), second[0].read_bytes())
            self.assertEqual(first[1].read_bytes(), second[1].read_bytes())
            persisted = json.loads(first[0].read_text(encoding="utf-8"))
            self.assertEqual(persisted, plan.payload())

    def test_bundle_filename_tracks_output_module(self) -> None:
        spec = replace(_spec(), output_module="GeneratedAlternateInventory")
        plan = build_constructive_source_inventory_plan(spec)
        with tempfile.TemporaryDirectory() as temporary:
            _, lean_path = write_constructive_source_inventory_bundle(
                Path(temporary),
                plan,
            )

        self.assertEqual(lean_path.name, "GeneratedAlternateInventory.lean")


if __name__ == "__main__":
    unittest.main()
