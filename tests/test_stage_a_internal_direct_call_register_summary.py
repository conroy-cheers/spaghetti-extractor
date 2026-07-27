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
    LeanCallerFrameWord,
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
        self.assertIn(
            "generatedInternalDirectCallRegisterSummaryCertificateExact",
            dag.root_source,
        )
        self.assertIn(
            ".generatedSummaryNodeCertificate",
            dag.root_source,
        )
        root_data = next(
            artifact for artifact in dag.artifact_modules
            if artifact.module == f"{dag.root_node_module}Data"
        )
        child_module = next(
            module.module for module in dag.node_modules
            if module.module != dag.root_node_module
        )
        self.assertIn(f"import {child_module}Data", root_data.source)
        self.assertNotIn(f"import {child_module}\n", root_data.source)

    def test_wide_child_inventory_is_split_into_cacheable_packs(self) -> None:
        original = nested_summary()
        repeated_child = original.nested[0]
        wide = LeanInternalDirectCallRegisterSummaryTree(
            original.certificate,
            (repeated_child,) * 33,
        )

        dag = internal_direct_call_register_summary_module_dag(
            wide,
            bindings(extra_imports=("StageA.InternalDirectCallFixture",)),
            root_namespace="StageA.Generated.WideChildSummaryRoot",
        )

        root_artifacts = tuple(
            artifact
            for artifact in dag.artifact_modules
            if artifact.module.startswith(dag.root_node_module)
        )
        child_packs = tuple(
            artifact for artifact in root_artifacts
            if "ChildrenPack" in artifact.module
        )
        self.assertEqual(len(child_packs), 2)
        child_aggregate = next(
            artifact for artifact in root_artifacts
            if artifact.module.endswith("ChildrenChecked")
        )
        data = next(
            artifact for artifact in root_artifacts
            if artifact.module.endswith("Data")
        )
        root = next(
            module for module in dag.node_modules
            if module.module == dag.root_node_module
        )

        self.assertIn("generatedSummaryChildrenParts.flatten", data.source)
        self.assertIn(
            "listAll_flatten_of_parts",
            child_aggregate.source,
        )
        self.assertIn(f"import {child_aggregate.module}", root.source)
        self.assertNotIn(
            "theorem generatedSummaryChildrenChecked",
            root.source,
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
        data_module = next(
            module
            for module in dag.artifact_modules
            if module.module.endswith("Data")
        )
        self.assertIn(
            "import StageA.Generated.FiniteRoute",
            data_module.source,
        )

    def test_module_dag_compiles_structural_families_independently(
        self,
    ) -> None:
        dag = internal_direct_call_register_summary_module_dag(
            nested_summary(),
            bindings(extra_imports=("StageA.InternalDirectCallFixture",)),
            root_namespace="StageA.Generated.StructuralFamilies",
        )

        artifact_names = {
            module.module.removeprefix(dag.root_node_module)
            for module in dag.artifact_modules
            if module.module.startswith(dag.root_node_module)
        }
        self.assertEqual(
            artifact_names,
            {
                "Data",
                "StructureShape",
                "StructureDecode",
                "StructureControl",
                "StructureDependencies",
                "StructureStack",
                "Preservation",
            },
        )
        final_source = next(
            module.source
            for module in dag.node_modules
            if module.module == dag.root_node_module
        )
        self.assertIn(
            "Certificate.structureCheckedWithChildCertificates_of_families",
            final_source,
        )
        structural_section = final_source.split(
            "theorem generatedSummaryCertificateCompactStructureChecked :", 1
        )[1].split(
            "theorem generatedSummaryChildrenCertificates :", 1
        )[0]
        self.assertNotIn("decide", structural_section)
        for family in (
            "Shape",
            "Decode",
            "Control",
            "Dependencies",
            "Stack",
        ):
            self.assertIn(
                f"generatedSummaryCertificateStructure{family}Checked",
                structural_section,
            )

    def test_structural_family_modules_depend_only_on_checked_data(
        self,
    ) -> None:
        dag = internal_direct_call_register_summary_module_dag(
            push_pop_summary(),
            bindings(),
            root_namespace="StageA.Generated.StructuralFamilyBoundary",
        )

        data_module = next(
            module
            for module in dag.artifact_modules
            if module.module == f"{dag.root_node_module}Data"
        )
        family_modules = [
            module
            for module in dag.artifact_modules
            if module.module != data_module.module
        ]
        self.assertEqual(len(family_modules), 6)
        for module in family_modules:
            self.assertIn(f"import {data_module.module}", module.source)
            self.assertNotIn(
                "def generatedSummaryCertificate : Certificate :=",
                module.source,
            )
        self.assertEqual(
            data_module.source.count(
                "def generatedSummaryCertificate : Certificate :="
            ),
            1,
        )

    def test_large_control_inventory_is_split_into_bound_cacheable_packs(
        self,
    ) -> None:
        regions = tuple(
            region(100 + index, 0x1000 + index, 1)
            for index in range(65)
        )
        certificate = LeanInternalDirectCallRegisterCertificate(
            summary_id=40,
            dependency_depth=0,
            caller=CALL,
            callsite=CALL,
            callee_entry=regions[0],
            continuation=OUTER_CONTINUATION,
            callee_regions=regions,
            edges=tuple(
                LeanCalleeEdge(
                    regions[index].region_id,
                    regions[index + 1].region_id,
                    "direct",
                )
                for index in range(len(regions) - 1)
            ),
            returns=(
                LeanReturnInventoryEntry(
                    regions[-1].region_id,
                    OUTER_CONTINUATION.region_id,
                ),
            ),
            requested_registers=("esi", "esp"),
            stack_witnesses=(
                LeanStackSaveRestoreWitness(
                    "esi",
                    regions[0].region_id,
                    (regions[-1].region_id,),
                    4,
                    4,
                    4,
                    4,
                    protected_write_region_ids=tuple(
                        region_.region_id for region_ in regions[1:-1]
                    ),
                ),
            ),
        )

        dag = internal_direct_call_register_summary_module_dag(
            LeanInternalDirectCallRegisterSummaryTree(certificate),
            bindings(),
            root_namespace="StageA.Generated.PackedControl",
        )

        data = next(
            module for module in dag.artifact_modules
            if module.module == f"{dag.root_node_module}Data"
        )
        self.assertEqual(
            data.source.count("def generatedSummaryRegionPart"),
            4,
        )
        self.assertIn(
            "calleeRegions := generatedSummaryRegionParts.flatten",
            data.source,
        )
        graph_closed = next(
            module for module in dag.artifact_modules
            if module.module == (
                f"{dag.root_node_module}StructureGraphClosed"
            )
        )
        original_packs = [
            module for module in dag.artifact_modules
            if "StructureControlOriginalPack" in module.module
        ]
        candidate_packs = [
            module for module in dag.artifact_modules
            if "StructureControlCandidatePack" in module.module
        ]
        graph_packs = [
            module for module in dag.artifact_modules
            if "StructureGraphClosurePack" in module.module
        ]
        self.assertEqual(len(original_packs), 3)
        self.assertEqual(len(candidate_packs), 3)
        self.assertEqual(len(graph_packs), 3)
        self.assertEqual(graph_closed.resource_class, "medium")
        self.assertEqual(graph_closed.estimated_memory_mb, 4096)
        self.assertIn(
            "generatedSummaryCertificate.graphClosed = true",
            graph_closed.source,
        )
        self.assertNotIn(
            "generatedSummaryCertificate.graphClosed = true := by\n"
            "  decide",
            graph_closed.source,
        )
        self.assertIn(
            "GraphClosureWitness.checked_of_parts",
            graph_closed.source,
        )
        self.assertTrue(all(
            module.resource_class == "medium"
            and module.estimated_memory_mb == 2048
            and ".graphClosureWitness.partChecked" in module.source
            and "\n  decide\n" in module.source
            for module in graph_packs
        ))
        self.assertTrue(all(
            module.resource_class == "medium"
            and module.estimated_memory_mb == 4096
            and "\n  decide\n" in module.source
            for module in (*original_packs, *candidate_packs)
        ))
        control = next(
            module for module in dag.artifact_modules
            if module.module == f"{dag.root_node_module}StructureControl"
        )
        self.assertNotIn("\n  decide\n", control.source)
        self.assertIn(
            "Certificate."
            "structureControlChecked_of_closed_graph_and_region_parts",
            control.source,
        )
        self.assertNotIn(
            "generatedSummaryGraphPartsChecked",
            control.source,
        )
        witness_packs = [
            module for module in dag.artifact_modules
            if "PreservationWitness0000Pack" in module.module
        ]
        stack_pointer_packs = [
            module for module in dag.artifact_modules
            if "PreservationStackPointerPack" in module.module
        ]
        self.assertEqual(len(witness_packs), 3)
        self.assertEqual(len(stack_pointer_packs), 3)
        self.assertTrue(all(
            "stackWitnessRegionPartSideChecked" in module.source
            for module in witness_packs
        ))
        self.assertTrue(all(
            "stackPointerRegionPartSideChecked" in module.source
            for module in stack_pointer_packs
        ))
        preservation = next(
            module for module in dag.artifact_modules
            if module.module == f"{dag.root_node_module}Preservation"
        )
        self.assertNotIn(
            "generatedSummaryCertificateStackWitness0000Checked :",
            preservation.source,
        )
        self.assertNotIn(
            "generatedSummaryCertificateRegisterESPPreservedChecked :",
            preservation.source,
        )

    def test_very_large_control_inventory_uses_dedicated_memory_lane(
        self,
    ) -> None:
        regions = tuple(
            region(1000 + index, 0x4000 + index, 1)
            for index in range(256)
        )
        certificate = LeanInternalDirectCallRegisterCertificate(
            summary_id=41,
            dependency_depth=0,
            caller=CALL,
            callsite=CALL,
            callee_entry=regions[0],
            continuation=OUTER_CONTINUATION,
            callee_regions=regions,
            edges=tuple(
                LeanCalleeEdge(
                    regions[index].region_id,
                    regions[index + 1].region_id,
                    "direct",
                )
                for index in range(len(regions) - 1)
            ),
            returns=(
                LeanReturnInventoryEntry(
                    regions[-1].region_id,
                    OUTER_CONTINUATION.region_id,
                ),
            ),
            requested_registers=("esi",),
        )

        dag = internal_direct_call_register_summary_module_dag(
            LeanInternalDirectCallRegisterSummaryTree(certificate),
            bindings(),
            root_namespace="StageA.Generated.HighMemoryPackedControl",
        )
        graph_closed = next(
            module for module in dag.artifact_modules
            if module.module == (
                f"{dag.root_node_module}StructureGraphClosed"
            )
        )
        inventory_packs = [
            module for module in dag.artifact_modules
            if (
                "StructureControlOriginalPack" in module.module
                or "StructureControlCandidatePack" in module.module
            )
        ]

        self.assertEqual(len(inventory_packs), 16)
        graph_packs = [
            module for module in dag.artifact_modules
            if "StructureGraphClosurePack" in module.module
        ]
        self.assertEqual(len(graph_packs), 8)
        self.assertEqual(graph_closed.resource_class, "medium")
        self.assertEqual(graph_closed.estimated_memory_mb, 4096)
        self.assertTrue(all(
            module.resource_class == "medium"
            and module.estimated_memory_mb == 2048
            for module in graph_packs
        ))
        self.assertTrue(all(
            module.resource_class == "high-memory"
            and module.estimated_memory_mb == 24576
            for module in inventory_packs
        ))

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

    def test_caller_frame_words_are_serialized_separately_from_registers(
        self,
    ) -> None:
        summary = push_pop_summary()
        certificate = replace(
            summary.certificate,
            requested_registers=(),
            caller_frame_words=(LeanCallerFrameWord(36, 36),),
        )

        source = internal_direct_call_register_summary_source(
            LeanInternalDirectCallRegisterSummaryTree(certificate),
            bindings(),
        )

        self.assertIn("requestedRegisters := []", source)
        self.assertIn(
            "callerFrameWords := "
            "[{ originalOffset := 36, candidateOffset := 36 }]",
            source,
        )

    def test_stack_witness_is_checked_once_and_composed_into_preservation(
        self,
    ) -> None:
        dag = internal_direct_call_register_summary_module_dag(
            push_pop_summary(),
            bindings(),
            root_namespace="StageA.Generated.CompactPreservation",
        )
        source = next(
            artifact.source
            for artifact in dag.artifact_modules
            if artifact.module == f"{dag.root_node_module}Preservation"
        )
        root_node_source = dag.node_modules[0].source

        self.assertEqual(source.count("StackWitness0000Checked :"), 1)
        self.assertIn(
            "def generatedInternalDirectCallRegisterSummaryStackWitness0000",
            dag.root_source,
        )
        self.assertIn(
            "generatedInternalDirectCallRegisterSummaryStackWitness0000Member",
            dag.root_source,
        )
        self.assertIn(
            "generatedInternalDirectCallRegisterSummaryStackWitness0000Checked",
            dag.root_source,
        )
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
        self.assertIn(
            f"import {dag.root_node_module}Preservation",
            root_node_source,
        )
        self.assertNotIn("StackWitness0000Checked :", root_node_source)
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
