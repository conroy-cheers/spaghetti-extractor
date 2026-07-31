from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.gnu_hello_runtime_indirect_composition import (
    CONSTRUCTOR_FRONTIER_ID,
    DYNAMIC_FRONTIER_ID,
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
_STACK_SITE_STABLE_ID = "stack-dynamic-ad0bad06992a9b2c16c0"


def _graph(*, omit_constructor_loopback: bool = False) -> OriginalCutpointGraphIR:
    successors = {
        291: (292,),
        292: (293,),
        2594: (2595,),
        2595: (2596,),
        2596: (() if omit_constructor_loopback else (2595,)),
        2791: (2792,),
    }
    regions = tuple(
        OriginalCutpointRegion(
            target_id=target_id,
            rva=0x1000 + target_id * 0x10,
            size=1,
            alias_rvas=(),
            successor_target_ids=successors.get(target_id, ()),
            root=target_id == 0,
            synthetic_terminal_padding=False,
            semantic_contract_sha256=f"{target_id + 1:064x}",
            instruction_bytes_sha256=f"{target_id + 2:064x}",
        )
        for target_id in range(2793)
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
    edges = tuple(
        OriginalCutpointEdge(
            edge_index=index,
            source_target_id=source,
            target_target_id=target,
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
        root_target_ids=(0,),
        reachable_target_ids=tuple(range(2793)),
    )


def _artifacts(
    root: Path,
    *,
    route_stable_id: str = STACK_FRONTIER_ID,
    constructor_stable_id: str = CONSTRUCTOR_FRONTIER_ID,
    dynamic_stable_id: str = DYNAMIC_FRONTIER_ID,
    omit_constructor_loopback: bool = False,
) -> dict[str, Path]:
    graph = _graph(omit_constructor_loopback=omit_constructor_loopback)
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
                "source_target_id": 292,
                "stable_id": _STACK_SITE_STABLE_ID,
                "allowed_target_ids": [5621],
            },
            {
                "closure_mode": "empty_indexed_source",
                "source_target_id": 2595,
                "stable_id": constructor_stable_id,
                "allowed_target_ids": [],
            },
            {
                "closure_mode": "uninhabited_dynamic_source",
                "source_target_id": 2792,
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
                "target_id": 5621,
                "offset": 0,
            },
            "target_fact": {"target_id": 292, "location_id": 0},
            "facts": [
                {"target_id": 292, "location_id": 0},
                {"target_id": 293, "location_id": 0},
            ],
            "transfers": [
                {
                    "edge_index": 0,
                    "kind": "decoded_preserve",
                    "authority_origin": None,
                    "source_target_id": 291,
                    "target_target_id": 292,
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
                    "source_target_id": 292,
                    "target_target_id": 293,
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
            "source_target_id": 2595,
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
                {"source_target_id": 2594, "target_target_id": 2595},
                {"source_target_id": 2596, "target_target_id": 2595},
                {"source_target_id": 2595, "target_target_id": 2596},
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
            "RootedScannerOperationalReachable",
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
                "mixed_component.rooted_scanner_phase_replay",
                "reachable_static_slot.write_preservation",
            ],
        )
        self.assertEqual(
            [gap.checker_type for gap in plan.evidence_gaps],
            [
                (
                    "CheckedMixedKernelSelectedInvariantClosure "
                    "(rooted scanner phase closure)"
                ),
                (
                    "OriginalWorldExecutionInvariant "
                    "(BSS dtor-head zero and preservation)"
                ),
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
            ("missing", "no unique target-292-to-293 transfer"),
            ("wrong-contract", "wrong contract symbol"),
            ("duplicate", "no unique target-292-to-293 transfer"),
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
                "incoming inventory is not exact GNU hello data",
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
