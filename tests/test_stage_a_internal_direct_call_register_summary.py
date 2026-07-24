from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.relational.lean.internal_direct_call_register_summary import (
    INTERNAL_DIRECT_CALL_REGISTER_SUMMARY_LEAN_FILENAME,
    InternalDirectCallRegisterSummaryGenerationError,
    InternalDirectCallRegisterSummaryLeanBindings,
    LeanCalleeEdge,
    LeanExactRegionPair,
    LeanFiniteOriginCallDependency,
    LeanFiniteOriginCallTarget,
    LeanFiniteOriginTailDependency,
    LeanFiniteOriginTailTarget,
    LeanFiniteIndirectJumpDependency,
    LeanInternalDirectCallRegisterCertificate,
    LeanInternalDirectCallRegisterSummaryTree,
    LeanMachineImportDependency,
    LeanNestedSummaryDependency,
    LeanReturnInventoryEntry,
    LeanSpan,
    LeanStackSaveRestoreWitness,
    internal_direct_call_register_summary_module_dag,
    internal_direct_call_register_summary_source,
    write_internal_direct_call_register_summary,
)


def region(region_id: int, start: int, size: int) -> LeanExactRegionPair:
    span = LeanSpan(start, size)
    return LeanExactRegionPair(region_id, span, span)


CALL = region(0, 0, 5)
OUTER_CONTINUATION = region(1, 5, 1)


def nested_summary() -> LeanInternalDirectCallRegisterSummaryTree:
    nested_call = region(10, 10, 5)
    outer_return = region(11, 15, 1)
    nested_entry = region(20, 20, 2)
    nested_return = region(21, 22, 1)
    child = LeanInternalDirectCallRegisterCertificate(
        summary_id=2,
        dependency_depth=0,
        caller=nested_call,
        callsite=nested_call,
        callee_entry=nested_entry,
        continuation=outer_return,
        callee_regions=(nested_entry, nested_return),
        edges=(LeanCalleeEdge(20, 21, "direct"),),
        returns=(LeanReturnInventoryEntry(21, 11),),
        requested_registers=("esi", "esp"),
    )
    parent = LeanInternalDirectCallRegisterCertificate(
        summary_id=1,
        dependency_depth=1,
        caller=CALL,
        callsite=CALL,
        callee_entry=nested_call,
        continuation=OUTER_CONTINUATION,
        callee_regions=(nested_call, outer_return),
        edges=(LeanCalleeEdge(10, 11, "nested_summary", 100),),
        returns=(LeanReturnInventoryEntry(11, 1),),
        requested_registers=("esi",),
        nested_dependencies=(LeanNestedSummaryDependency(100, 10, 11, 2),),
    )
    return LeanInternalDirectCallRegisterSummaryTree(
        parent, (LeanInternalDirectCallRegisterSummaryTree(child),)
    )


def push_pop_summary() -> LeanInternalDirectCallRegisterSummaryTree:
    save = region(10, 10, 3)
    body = region(11, 13, 7)
    restore = region(12, 20, 2)
    certificate = LeanInternalDirectCallRegisterCertificate(
        summary_id=3,
        dependency_depth=0,
        caller=CALL,
        callsite=CALL,
        callee_entry=save,
        continuation=OUTER_CONTINUATION,
        callee_regions=(save, body, restore),
        edges=(
            LeanCalleeEdge(10, 11, "direct"),
            LeanCalleeEdge(11, 12, "direct"),
        ),
        returns=(LeanReturnInventoryEntry(12, 1),),
        requested_registers=("esi",),
        original_frame_bytes=4,
        candidate_frame_bytes=4,
        stack_witnesses=(
            LeanStackSaveRestoreWitness("esi", 10, (12,), 4, 4, 4, 4),
        ),
    )
    return LeanInternalDirectCallRegisterSummaryTree(certificate)


def bindings(*, extra_imports: tuple[str, ...] = ()):
    return InternalDirectCallRegisterSummaryLeanBindings(
        original_pe="StageA.Generated.InternalDirectCallFixture.pe",
        candidate_pe="StageA.Generated.InternalDirectCallFixture.pe",
        original_imports="StageA.Generated.InternalDirectCallFixture.imports",
        candidate_imports="StageA.Generated.InternalDirectCallFixture.imports",
        imports=extra_imports,
    )


class StageAInternalDirectCallRegisterSummaryGenerationTests(unittest.TestCase):
    def test_nested_summary_emits_exact_inventory_and_structural_evidence(self) -> None:
        source = internal_direct_call_register_summary_source(
            nested_summary(),
            bindings(extra_imports=("StageA.InternalDirectCallFixture",)),
        )

        self.assertIn("dependencyDepth := 1", source)
        self.assertIn("kind := .nestedSummary 100", source)
        self.assertIn("requestedRegisters := [.esi]", source)
        self.assertIn("SummaryTree.checked_structuralEvidence", source)
        self.assertIn("StructuralCheckerEvidence", source)
        self.assertIn("#print axioms", source)
        for untrusted in (
            "certificate_hash",
            "proposal_status",
            "native_decide",
        ):
            self.assertNotIn(untrusted, source)
        self.assertNotIn(".Preserves", source)
        self.assertNotIn("checked_sound", source)

    def test_repeated_subtree_is_emitted_once_and_composed_by_checked_theorem(
        self,
    ) -> None:
        original = nested_summary()
        repeated = LeanInternalDirectCallRegisterSummaryTree(
            original.certificate,
            (original.nested[0], original.nested[0]),
        )

        source = internal_direct_call_register_summary_source(
            repeated, bindings()
        )

        self.assertEqual(source.count(": Certificate :="), 2)
        self.assertEqual(source.count("def generatedSummaryNode"), 2)
        self.assertNotIn(".node ({ summaryId :=", source)
        self.assertIn(
            "SummaryTree.checked_node_of_certificate_and_children", source
        )

    def test_module_dag_exposes_one_cacheable_module_per_unique_node(
        self,
    ) -> None:
        original = nested_summary()
        repeated = LeanInternalDirectCallRegisterSummaryTree(
            original.certificate,
            (original.nested[0], original.nested[0]),
        )

        dag = internal_direct_call_register_summary_module_dag(
            repeated,
            bindings(extra_imports=("StageA.InternalDirectCallFixture",)),
            root_namespace="StageA.Generated.RepeatedSummaryRoot",
        )

        self.assertEqual(len(dag.node_modules), 2)
        self.assertEqual(len({module.module for module in dag.node_modules}), 2)
        self.assertTrue(all(
            module.module.startswith(
                "StageA.GeneratedRelationalInternalDirectCallSummaryNode"
            )
            for module in dag.node_modules
        ))
        self.assertIn(f"import {dag.root_node_module}", dag.root_source)
        self.assertIn(
            "generatedInternalDirectCallRegisterSummaryChecked",
            dag.root_source,
        )

    def test_module_dag_node_imports_its_finite_origin_route_authority(
        self,
    ) -> None:
        dependency = LeanFiniteOriginTailDependency(
            dependency_id=19,
            source_region_id=11,
            route_term="StageA.Generated.FiniteRoute.route",
            internal_targets=(
                LeanFiniteOriginTailTarget(target_id=3, region_id=11),
            ),
            authority_module="StageA.Generated.FiniteRoute",
            route_authority_term=(
                "StageA.Generated.FiniteRoute.checkedAuthority"
            ),
        )
        original = push_pop_summary()
        summary = LeanInternalDirectCallRegisterSummaryTree(
            replace(
                original.certificate,
                finite_origin_tail_dependencies=(dependency,),
            )
        )

        dag = internal_direct_call_register_summary_module_dag(
            summary,
            bindings(),
            root_namespace="StageA.Generated.FiniteRouteSummaryRoot",
        )

        self.assertEqual(len(dag.node_modules), 1)
        self.assertIn(
            "import StageA.Generated.FiniteRoute",
            dag.node_modules[0].source,
        )

    def test_generated_artifact_explicitly_denies_acceptance_authority(self) -> None:
        source = internal_direct_call_register_summary_source(
            nested_summary(), bindings()
        )

        self.assertIn("SemanticIntegrationRequirements", source)
        self.assertIn("StandaloneAcceptanceAuthority : Bool", source)
        self.assertIn("NotAcceptanceAuthority", source)
        self.assertIn("StandaloneAcceptanceAuthority = false", source)

    def test_push_pop_witness_is_serialized_without_python_verdict(self) -> None:
        source = internal_direct_call_register_summary_source(
            push_pop_summary(), bindings()
        )

        self.assertIn("saveRegionId := 10", source)
        self.assertIn("restoreRegionIds := [12]", source)
        self.assertIn("originalSaveOffset := 4", source)
        self.assertNotIn("status :=", source)

    def test_stack_witness_is_checked_once_and_composed_into_preservation(
        self,
    ) -> None:
        dag = internal_direct_call_register_summary_module_dag(
            push_pop_summary(),
            bindings(),
            root_namespace="StageA.Generated.CompactPreservation",
        )
        source = dag.node_modules[0].source

        self.assertEqual(source.count("StackWitness0000Checked :"), 1)
        self.assertIn(
            "Certificate.registerPreservedChecked_of_stackWitness",
            source,
        )
        self.assertIn(
            "Certificate.preservationChecked_of_registers",
            source,
        )
        self.assertNotIn("Frame0000OriginalSaveChecked", source)
        self.assertNotIn("OriginalProtectedWritesChecked", source)
        preservation = source.split(
            "theorem generatedSummaryCertificatePreservationChecked :", 1
        )[1].split(
            "theorem generatedSummaryCertificateChecked :", 1
        )[0]
        self.assertNotIn("decide", preservation)

    def test_finite_indirect_dependency_serializes_exact_table_inventory(self) -> None:
        dependency = LeanFiniteIndirectJumpDependency(
            dependency_id=17,
            source_region_id=10,
            original_table_base=0x400020,
            candidate_table_base=0x400020,
            upper_exclusive=2,
            original_index_expression={"op": "reg", "name": "eax"},
            candidate_index_expression={"op": "reg", "name": "eax"},
            entry_target_region_ids=(24, 26),
        )

        encoded = dependency.lean()

        self.assertIn("sourceRegionId := 10", encoded)
        self.assertIn("originalTableBase := 4194336", encoded)
        self.assertIn("originalIndexExpression := .inputReg .eax", encoded)
        self.assertIn("entryTargetRegionIds := [24, 26]", encoded)

    def test_finite_origin_call_serializes_exact_target_and_continuation_inventory(
        self,
    ) -> None:
        dependency = LeanFiniteOriginCallDependency(
            dependency_id=0x1010,
            source_region_id=0x1010,
            continuation_region_id=0x1012,
            continuation_target_id=91,
            internal_targets=(
                LeanFiniteOriginCallTarget(
                    target_id=77,
                    region_id=0x1020,
                    summary_id=(1 << 64) + (0x1010 << 32) + 0x1020,
                ),
            ),
            authority_module="StageA.Generated.FiniteOriginAuthority",
            indirect_exit_authority_term=(
                "StageA.Generated.FiniteOriginAuthority.checkedExit"
            ),
        )

        encoded = dependency.lean()

        self.assertIn("sourceRegionId := 4112", encoded)
        self.assertIn("continuationRegionId := 4114", encoded)
        self.assertIn("continuationTargetId := 91", encoded)
        self.assertIn("targetId := 77", encoded)
        self.assertIn("regionId := 4128", encoded)
        self.assertIn("summaryId := 18446761734615076896", encoded)

    def test_negative_expectation_asks_lean_to_prove_rejection(self) -> None:
        source = internal_direct_call_register_summary_source(
            push_pop_summary(), bindings(), expectation="rejected"
        )

        self.assertIn("= false := by", source)
        self.assertNotIn("generatedInternalDirectCallRegisterSummaryStructuralEvidence", source)
        self.assertIn("generatedInternalDirectCallRegisterSummaryNotAcceptanceAuthority", source)

    def test_machine_dependencies_accept_only_qualified_grounding_symbols(self) -> None:
        dependency = LeanMachineImportDependency(
            7,
            10,
            11,
            "Fixture.required",
            "Fixture.required",
            "Fixture.signatures",
            "Fixture.signatures",
            "Fixture.boundary; #eval 1",
            "Fixture.boundary",
        )
        summary = push_pop_summary()
        certificate = replace(
            summary.certificate,
            machine_import_dependencies=(dependency,),
        )

        with self.assertRaisesRegex(
            InternalDirectCallRegisterSummaryGenerationError,
            "qualified Lean identifier",
        ):
            internal_direct_call_register_summary_source(
                LeanInternalDirectCallRegisterSummaryTree(certificate), bindings()
            )

    def test_unsupported_register_and_ambiguous_edge_are_not_emitted(self) -> None:
        invalid_register = replace(
            push_pop_summary().certificate, requested_registers=("rip",)
        )
        with self.assertRaisesRegex(
            InternalDirectCallRegisterSummaryGenerationError,
            "supported IA-32 register",
        ):
            internal_direct_call_register_summary_source(
                LeanInternalDirectCallRegisterSummaryTree(invalid_register), bindings()
            )

        invalid_edge = LeanCalleeEdge(10, 11, "direct", 9)
        with self.assertRaisesRegex(
            InternalDirectCallRegisterSummaryGenerationError,
            "only valid for dependency edges",
        ):
            invalid_edge.lean()

    def test_writer_uses_the_standalone_generated_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / INTERNAL_DIRECT_CALL_REGISTER_SUMMARY_LEAN_FILENAME
            written = write_internal_direct_call_register_summary(
                destination, nested_summary(), bindings()
            )

            self.assertEqual(written, destination)
            self.assertIn("def generatedInternal", destination.read_text())


if __name__ == "__main__":
    unittest.main()
