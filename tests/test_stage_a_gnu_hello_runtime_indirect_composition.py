from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.gnu_hello_runtime_indirect_composition import (
    CONSTRUCTOR_FRONTIER_ID,
    DYNAMIC_FRONTIER_ID,
    DYNAMIC_HEAD_SLOT_RVA,
    GNUHelloRuntimeIndirectCompositionGenerationError,
    STACK_FRONTIER_ID,
    gnu_hello_runtime_indirect_composition_source,
    plan_gnu_hello_runtime_indirect_composition,
)
from spaghetti_extractor.relational.original_cutpoint_graph_ir import (
    OriginalCutpointEdge,
    OriginalCutpointGraphIR,
    OriginalCutpointRegion,
    canonical_original_cutpoint_graph_sha256,
)


_ORIGINAL_SHA256 = "1" * 64
_STATE_MACHINE_SHA256 = "2" * 64
_STACK_SITE_STABLE_ID = "stack-dynamic-8174534cc03bae3851d1"
_SEMANTIC_RVAS = {
    291: 0x202E,
    292: 0x2033,
    293: 0x2040,
    2594: 0xA20F,
    2595: 0xA220,
    2596: 0xA227,
    2786: 0xAB54,
    2787: 0xAB61,
    2791: 0xAB82,
    2792: 0xAB86,
}


def _graph(
    *,
    omit_constructor_loopback: bool = False,
    omit_dynamic_guard: bool = False,
    target_id_shift: int = 0,
) -> OriginalCutpointGraphIR:
    base_successors = {
        291: (292,),
        292: (293,),
        2594: (2595,),
        2595: (2596,),
        2596: (() if omit_constructor_loopback else (2595,)),
        2786: (() if omit_dynamic_guard else (2787,)),
        2791: (2792,),
    }

    def shifted(target_id: int) -> int:
        return target_id + target_id_shift

    successors = {
        shifted(source): tuple(shifted(target) for target in targets)
        for source, targets in base_successors.items()
    }
    regions = tuple(
        OriginalCutpointRegion(
            target_id=target_id,
            rva=(
                0x1000 + target_id * 0x10
                if target_id < target_id_shift
                else _SEMANTIC_RVAS.get(
                    target_id - target_id_shift,
                    0x100000 + (target_id - target_id_shift) * 0x10,
                )
            ),
            size=1,
            alias_rvas=(
                (0xA213,)
                if target_id == shifted(2595)
                else ()
            ),
            successor_target_ids=successors.get(target_id, ()),
            root=target_id == shifted(0),
            synthetic_terminal_padding=False,
            semantic_contract_sha256=f"{target_id + 1:064x}",
            instruction_bytes_sha256=f"{target_id + 2:064x}",
        )
        for target_id in range(2793 + target_id_shift)
    )
    pairs = [
        (291, 292),
        (292, 293),
        (2594, 2595),
        (2595, 2596),
        (2791, 2792),
    ]
    if not omit_constructor_loopback:
        pairs.append((2596, 2595))
    if not omit_dynamic_guard:
        pairs.append((2786, 2787))
    edges = tuple(
        OriginalCutpointEdge(
            edge_index=index,
            source_target_id=shifted(source),
            target_target_id=shifted(target),
            kind="direct",
            machine_contract_id=None,
            transition_role="immediate",
            execution_successor=True,
        )
        for index, (source, target) in enumerate(pairs)
    )
    return OriginalCutpointGraphIR(
        original_pe_sha256=_ORIGINAL_SHA256,
        state_machine_sha256=_STATE_MACHINE_SHA256,
        regions=regions,
        edges=edges,
        root_target_ids=(shifted(0),),
        reachable_target_ids=tuple(
            range(target_id_shift, 2793 + target_id_shift)
        ),
    )


def _artifacts(
    root: Path,
    *,
    route_stable_id: str = STACK_FRONTIER_ID,
    constructor_stable_id: str = CONSTRUCTOR_FRONTIER_ID,
    dynamic_stable_id: str = DYNAMIC_FRONTIER_ID,
    omit_constructor_loopback: bool = False,
    omit_dynamic_guard: bool = False,
    target_id_shift: int = 0,
) -> dict[str, Path]:
    graph = _graph(
        omit_constructor_loopback=omit_constructor_loopback,
        omit_dynamic_guard=omit_dynamic_guard,
        target_id_shift=target_id_shift,
    )

    def shifted(target_id: int) -> int:
        return target_id + target_id_shift

    graph_path = root / "original-cutpoint-graph-ir.json"
    graph_path.write_text(json.dumps(graph.to_json()), encoding="utf-8")
    identity = {
        "original_pe_sha256": _ORIGINAL_SHA256,
        "state_machine_sha256": _STATE_MACHINE_SHA256,
    }
    closure_path = root / "original-stack-dynamic-control-closure.json"
    closure_path.write_text(json.dumps({
        "format": "stage-a-original-stack-dynamic-control-closure-v1",
        "inputs": identity,
        "counts": {"ignored": 0},
        "status": "incomplete",
        "sites": [
            {
                "closure_mode": "finite_stack_target",
                "source_target_id": shifted(292),
                "stable_id": _STACK_SITE_STABLE_ID,
                "allowed_target_ids": [shifted(5621)],
            },
            {
                "closure_mode": "empty_indexed_source",
                "source_target_id": shifted(2595),
                "stable_id": constructor_stable_id,
                "allowed_target_ids": [],
            },
            {
                "closure_mode": "uninhabited_dynamic_source",
                "source_target_id": shifted(2792),
                "stable_id": dynamic_stable_id,
                "allowed_target_ids": [],
            },
        ],
    }), encoding="utf-8")
    graph_content = canonical_original_cutpoint_graph_sha256(graph)
    runtime_path = root / "runtime-value-carry-ir.json"
    runtime_path.write_text(json.dumps({
        "format": "stage-a-runtime-value-carry-ir-v1",
        "inputs": {
            **identity,
            "cutpoint_graph_content_sha256": graph_content,
        },
        "proof_ready": False,
        "routes": [{
            "stable_id": route_stable_id,
            "origin": {
                "kind": "static_code_target",
                "target_id": shifted(5621),
                "offset": 0,
            },
            "target_fact": {
                "target_id": shifted(292),
                "location_id": 0,
            },
            "facts": [
                {"target_id": shifted(292), "location_id": 0},
                {"target_id": shifted(293), "location_id": 0},
            ],
            "transfers": [
                {
                    "edge_index": 0,
                    "kind": "decoded_preserve",
                    "authority_origin": None,
                    "source_target_id": shifted(291),
                    "target_target_id": shifted(292),
                },
                {
                    "edge_index": 1,
                    "kind": "call_frame_word_preserve",
                    "authority_origin": (
                        "checked_finite_origin_call_caller_frame_word_summary"
                    ),
                    "authority_lean_term": {
                        "module": (
                            "StageA.GeneratedRelationalInternalDirectCall"
                            "MixedOriginalIntegration0000203cEdgeafdcaedd"
                        ),
                        "namespace": (
                            "StageA.Generated.GeneratedRelationalInternal"
                            "DirectCallMixedOriginalIntegration"
                            "0000203cEdgeafdcaedd"
                        ),
                        "symbol": (
                            "generatedCheckedFiniteOriginCall"
                            "CallerFrameWordControlContract"
                        ),
                    },
                    "source_target_id": shifted(292),
                    "target_target_id": shifted(293),
                },
            ],
        }],
    }), encoding="utf-8")
    rooted_path = root / "nullable-code-pointer-rooted-unreachability.json"
    rooted_path.write_text(json.dumps({
        "format": "stage-a-relational-nullable-code-pointer-rooted-scc-v3",
        "inputs": {
            **identity,
            "cutpoint_graph_content_sha256": graph_content,
        },
        "counts": {"ignored": 1},
        "status": "runtime-premise-required",
        "entries": [{
            "source_target_id": shifted(2595),
            "stable_id": constructor_stable_id,
            "module": (
                "StageA."
                "GeneratedRelationalNullableCodePointerRootedUnreachability1"
            ),
            "authority_term": (
                "StageA.Generated.RelationalNullableCodePointer"
                "RootedUnreachability.Site1."
                "generatedNullableCodePointerRootedUnreachability1Authority"
            ),
            "empty_indexed_authority_term": (
                "StageA.GeneratedRelational."
                "OriginalStackDynamicControlClosure."
                "generatedOriginalStackDynamicClosure1"
                "EmptyIndexedAuthority"
            ),
            "incoming_edges": [
                {
                    "source_target_id": shifted(2594),
                    "target_target_id": shifted(2595),
                },
                {
                    "source_target_id": shifted(2596),
                    "target_target_id": shifted(2595),
                },
                {
                    "source_target_id": shifted(2595),
                    "target_target_id": shifted(2596),
                },
            ],
        }],
    }), encoding="utf-8")
    artifacts = {
        "cutpoint_graph": graph_path,
        "stack_dynamic_closure": closure_path,
        "runtime_value_carry": runtime_path,
        "rooted_unreachability": rooted_path,
    }
    return artifacts


class StageAGNUHelloRuntimeIndirectCompositionTests(unittest.TestCase):
    def test_exact_artifacts_emit_checked_target_292_route_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = plan_gnu_hello_runtime_indirect_composition(
                **_artifacts(Path(temporary))
            )
        self.assertEqual(plan.stack_route_index, 0)
        self.assertEqual(plan.stack_site_index, 0)
        self.assertEqual(plan.constructor_site_index, 1)
        self.assertEqual(plan.dynamic_site_index, 2)
        self.assertEqual(plan.stack_source_target_id, 292)
        self.assertEqual(plan.stack_successor_target_id, 293)
        self.assertEqual(plan.constructor_source_target_id, 2595)
        self.assertEqual(plan.dynamic_source_target_id, 2792)
        self.assertEqual(plan.dynamic_guard_source_target_id, 2786)
        self.assertEqual(plan.dynamic_guard_nonzero_target_id, 2787)
        self.assertEqual(
            plan.constructor_incoming,
            ((2594, 2595), (2596, 2595)),
        )
        self.assertEqual(plan.dynamic_incoming, ((2791, 2792),))

        self.assertEqual(
            plan.stack_transfer_authority_names,
            (
                "StageA.GeneratedRelational.RuntimeValueCarry."
                "generatedRuntimeValueCarryRoute0Transfer0Authority",
                "StageA.GeneratedRelational.RuntimeValueCarry."
                "generatedRuntimeValueCarryRoute0Transfer1Authority",
            ),
        )
        self.assertEqual(plan.stack_target_transfer_index, 1)
        source = gnu_hello_runtime_indirect_composition_source(plan)
        for fragment in (
            f'frontierId := "{CONSTRUCTOR_FRONTIER_ID}"',
            f'frontierId := "{DYNAMIC_FRONTIER_ID}"',
            f'"{STACK_FRONTIER_ID}"',
            "sourceTargetId := 292",
            "sourceTargetId := 2595",
            "sourceTargetId := 2792",
            "generatedStableFrontierIdsExact",
            "generatedConstructorRootedEvidenceExact",
            "generatedConstructorRootedExecutionAuthority",
            "generatedConstructorRootedSourceExcluded",
            "generatedConstructorSelectedSourceUninhabited",
            "generatedConstructorSelectedComposition",
            "RootedScannerOperationalReachable",
            "structure CheckedGuardedZeroSelectedSourceProjection",
            "CompleteWriteFootprintTrace generatedContext certificate",
            "CheckedGuardedZeroSelectedSourceProjection.sourceUninhabited",
            f"def generatedDynamicHeadRva : Nat := {DYNAMIC_HEAD_SLOT_RVA}",
            "generatedDynamicHeadInitialZeroChecked",
            f"sourceTargetId := {plan.dynamic_guard_source_target_id}",
            f"nonzeroTargetId := {plan.dynamic_guard_nonzero_target_id}",
            "generatedDynamicGuardEdgeChecked",
            "generatedDynamicSelectedSourceUninhabited",
            "generatedDynamicSelectedComposition",
            "noncomputable def generatedStackSeed",
            "checkedStackCarryRouteSeedValue_of_relocatedOrigin",
            "generatedStackTransfer0Authority",
            "generatedStackTransferAuthorities",
            ".decoded generatedStackTransfer0Authority",
            "generatedStackTransferInventoryChecked",
            "generatedStackTransferInventory",
            "generatedStackTransfer0SelectedAuthorityExact",
            "generatedStackTransfer1SelectedAuthorityExact",
            "generatedStackTransfer0SelectedExecution",
            "generatedStackTransfer1SelectedExecution",
            "CheckedRouteTransferExecution generatedContext",
            ".finiteFrame generatedStackTransfer1Authority",
            "generatedTarget292StackWindow",
            "rangeId := 0",
            "bytesAbove := 36",
            "generatedTarget292StackRangeChecked",
            "generatedTarget292StackRangeWitness",
            "generatedTarget292CallContract",
            "generatedTarget292SelectedExecution",
            "CheckedSelectedRouteTransferExecution.ofFiniteFrame",
            "theorem generatedRootExclusionChecked",
            "structure CheckedArtifactBundle",
            "def generatedCheckedArtifactBundle",
            "stableFrontierIdsExact : StableFrontierIdsExact",
            "constructorRootedEvidenceExact : ConstructorRootedEvidenceExact",
            "constructorRootedSourceExcluded :",
        ):
            self.assertIn(fragment, source)
        self.assertEqual(
            source.count("def generatedStackTransfer0SelectedExecution"),
            1,
        )
        self.assertEqual(
            source.count("def generatedStackTransfer1SelectedExecution"),
            1,
        )
        for forbidden in (
            "blocker_count",
            "frontier_count",
            "report_status",
            "proof_ready",
            'status":',
            "RemainingPremises",
            "runtime-indirect-operational-evidence",
            "TermBackedClosure",
            "CheckedInvariantOperationalCut",
            "CheckedOperationalBundle",
            "generatedAggregate",
            "generatedRuntimeIndirectStackComposition",
            "generatedRuntimeIndirectConstructorComposition",
            "generatedRuntimeIndirectDynamicComposition",
            "generatedCombinedRootHolds",
            "native_decide",
        ):
            self.assertNotIn(forbidden, source)

    def test_unrelated_earlier_regions_shift_ids_without_breaking_planning(
        self,
    ) -> None:
        target_id_shift = 7
        shifted_graph = _graph(target_id_shift=target_id_shift)
        for original_target_id, rva in _SEMANTIC_RVAS.items():
            self.assertEqual(
                shifted_graph.regions[
                    original_target_id + target_id_shift
                ].rva,
                rva,
            )
        with tempfile.TemporaryDirectory() as temporary:
            plan = plan_gnu_hello_runtime_indirect_composition(
                **_artifacts(
                    Path(temporary),
                    target_id_shift=target_id_shift,
                )
            )
        self.assertEqual(plan.stack_source_target_id, 292 + target_id_shift)
        self.assertEqual(
            plan.stack_successor_target_id,
            293 + target_id_shift,
        )
        self.assertEqual(
            plan.constructor_source_target_id,
            2595 + target_id_shift,
        )
        self.assertEqual(
            plan.dynamic_source_target_id,
            2792 + target_id_shift,
        )
        self.assertEqual(
            plan.constructor_incoming,
            (
                (2594 + target_id_shift, 2595 + target_id_shift),
                (2596 + target_id_shift, 2595 + target_id_shift),
            ),
        )
        self.assertEqual(
            plan.dynamic_incoming,
            ((2791 + target_id_shift, 2792 + target_id_shift),),
        )

        source = gnu_hello_runtime_indirect_composition_source(plan)
        for fragment in (
            f"sourceTargetId := {292 + target_id_shift}",
            f"sourceTargetId := {2595 + target_id_shift}",
            f"sourceTargetId := {2792 + target_id_shift}",
            f"sourceTargetId := {2786 + target_id_shift}",
            f"nonzeroTargetId := {2787 + target_id_shift}",
            (
                f"sourceTargetId := {2594 + target_id_shift}, "
                f"targetTargetId := {2595 + target_id_shift}"
            ),
        ):
            self.assertIn(fragment, source)

    def test_current_static_artifacts_report_exact_operational_gaps(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = plan_gnu_hello_runtime_indirect_composition(
                **_artifacts(Path(temporary))
            )
        self.assertEqual(
            [gap.source_target_id for gap in plan.evidence_gaps],
            [2595, 2792],
        )
        self.assertEqual(
            [gap.extractor_field for gap in plan.evidence_gaps],
            [
                "mixed_component.rooted_scanner_selected_projection",
                "reachable_static_slot.selected_zero_guard_projection",
            ],
        )
        self.assertEqual(
            [gap.checker_type for gap in plan.evidence_gaps],
            [
                "CheckedRootedScannerSelectedSourceProjection",
                "CheckedGuardedZeroSelectedSourceProjection",
            ],
        )
        self.assertEqual(
            [evidence.source_target_id for evidence in plan.checked_evidence],
            [292, 2595, 2792],
        )
        self.assertEqual(
            [evidence.evidence_kind for evidence in plan.checked_evidence],
            [
                "selected-stack-route-and-frame-window",
                "rooted-scanner-scc-execution-exclusion",
                "launch-zero-and-decoded-nonzero-guard",
            ],
        )
        source = gnu_hello_runtime_indirect_composition_source(plan)
        self.assertIn("generatedCheckedArtifactBundle", source)
        self.assertNotIn("CheckedOperationalBundle", source)
        self.assertNotIn("(evidence :", source)

    def test_stable_id_drift_fails_closed(self) -> None:
        for mutation in ("route", "constructor", "dynamic"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                arguments = {
                    "route": {"route_stable_id": "wrong.route"},
                    "constructor": {
                        "constructor_stable_id": "wrong-constructor"
                    },
                    "dynamic": {"dynamic_stable_id": "wrong-dynamic"},
                }[mutation]
                paths = _artifacts(Path(temporary), **arguments)
                with self.assertRaisesRegex(
                    GNUHelloRuntimeIndirectCompositionGenerationError,
                    "wrong stable ID",
                ):
                    plan_gnu_hello_runtime_indirect_composition(**paths)

    def test_rooted_companion_names_must_derive_from_checked_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = _artifacts(Path(temporary))
            rooted = json.loads(
                paths["rooted_unreachability"].read_text(encoding="utf-8")
            )
            rooted["entries"][0]["authority_term"] = (
                "StageA.Generated.RootedScannerUnchecked"
            )
            paths["rooted_unreachability"].write_text(
                json.dumps(rooted),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GNUHelloRuntimeIndirectCompositionGenerationError,
                "checked companion naming contract",
            ):
                plan_gnu_hello_runtime_indirect_composition(**paths)

    def test_target_292_route_execution_inventory_fails_closed(self) -> None:
        for mutation, message in (
            ("missing", "no unique stack-source-to-successor transfer"),
            ("wrong-contract", "wrong contract symbol"),
            ("duplicate", "no unique stack-source-to-successor transfer"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                paths = _artifacts(Path(temporary))
                runtime = json.loads(
                    paths["runtime_value_carry"].read_text(encoding="utf-8")
                )
                transfers = runtime["routes"][0]["transfers"]
                if mutation == "missing":
                    transfers.pop()
                elif mutation == "wrong-contract":
                    transfers[1]["authority_lean_term"]["symbol"] = (
                        "generatedUncheckedCallerFrameContract"
                    )
                else:
                    transfers.append(dict(transfers[1]))
                paths["runtime_value_carry"].write_text(
                    json.dumps(runtime),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    GNUHelloRuntimeIndirectCompositionGenerationError,
                    message,
                ):
                    plan_gnu_hello_runtime_indirect_composition(**paths)

    def test_diagnostic_counts_and_statuses_have_no_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = _artifacts(Path(temporary))
            before = plan_gnu_hello_runtime_indirect_composition(**paths)
            for name in ("stack_dynamic_closure", "rooted_unreachability"):
                payload = json.loads(paths[name].read_text(encoding="utf-8"))
                payload["counts"] = {"claimed_closed": 999999}
                payload["status"] = "pass"
                paths[name].write_text(json.dumps(payload), encoding="utf-8")
            after = plan_gnu_hello_runtime_indirect_composition(**paths)
        self.assertEqual(before, after)

    def test_missing_exact_incoming_edge_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = _artifacts(
                Path(temporary),
                omit_constructor_loopback=True,
            )
            with self.assertRaisesRegex(
                GNUHelloRuntimeIndirectCompositionGenerationError,
                "constructor incoming inventory does not match its RVAs",
            ):
                plan_gnu_hello_runtime_indirect_composition(**paths)

    def test_route_transfer_must_be_an_exact_graph_edge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = _artifacts(Path(temporary))
            runtime = json.loads(
                paths["runtime_value_carry"].read_text(encoding="utf-8")
            )
            runtime["routes"][0]["transfers"][0]["edge_index"] = 999
            paths["runtime_value_carry"].write_text(
                json.dumps(runtime),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GNUHelloRuntimeIndirectCompositionGenerationError,
                "not an exact cutpoint-graph edge",
            ):
                plan_gnu_hello_runtime_indirect_composition(**paths)

    def test_missing_dynamic_guard_edge_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = _artifacts(
                Path(temporary),
                omit_dynamic_guard=True,
            )
            with self.assertRaisesRegex(
                GNUHelloRuntimeIndirectCompositionGenerationError,
                "dynamic guarded predecessor edge is absent",
            ):
                plan_gnu_hello_runtime_indirect_composition(**paths)

    def test_identity_mismatch_fails_before_source_emission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = _artifacts(Path(temporary))
            closure = json.loads(
                paths["stack_dynamic_closure"].read_text(encoding="utf-8")
            )
            closure["inputs"]["original_pe_sha256"] = "f" * 64
            paths["stack_dynamic_closure"].write_text(
                json.dumps(closure),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                GNUHelloRuntimeIndirectCompositionGenerationError,
                "disagrees on original_pe_sha256",
            ):
                plan_gnu_hello_runtime_indirect_composition(**paths)


if __name__ == "__main__":
    unittest.main()
