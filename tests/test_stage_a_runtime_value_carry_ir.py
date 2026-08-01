from __future__ import annotations

import dataclasses
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.original_cutpoint_graph_ir import (
    OriginalCutpointEdge,
    OriginalCutpointGraphIR,
    OriginalCutpointRegion,
    canonical_original_cutpoint_graph_sha256,
)
from spaghetti_extractor.relational.runtime_value_carry_ir import (
    RuntimeValueCarryIR,
    RuntimeValueCarryIRError,
    RuntimeValueCarryRoute,
    RuntimeValueFact,
    RuntimeValueLocation,
    RuntimeValueLeanTerm,
    RuntimeValueOrigin,
    RuntimeValueTransfer,
    validate_runtime_value_carry_ir,
)
from spaghetti_extractor.relational.lean.runtime_value_carry import (
    SEMANTICS_MODULE,
    write_runtime_value_carry_lean,
)


class StageARuntimeValueCarryIRTests(unittest.TestCase):
    _TERM = RuntimeValueLeanTerm(
        "StageA.GeneratedSeed",
        "StageA.Generated.Seed",
        "checkedSeed",
    )

    def _graph(self) -> OriginalCutpointGraphIR:
        regions = tuple(
            OriginalCutpointRegion(
                target_id=index,
                rva=0x1000 + index * 0x10,
                size=0x10,
                alias_rvas=(),
                successor_target_ids=(
                    (index + 1,) if index < 4 else ()
                ),
                root=index == 0,
                synthetic_terminal_padding=False,
                semantic_contract_sha256=f"{index + 1:x}" * 64,
                instruction_bytes_sha256=f"{index + 10:x}" * 64,
            )
            for index in range(6)
        )
        edges = tuple(
            OriginalCutpointEdge(
                edge_index=10 + index,
                source_target_id=index,
                target_target_id=index + 1,
                kind=(
                    "call_return"
                    if index in (0, 3)
                    else "direct"
                ),
                machine_contract_id=None,
                transition_role="continuation",
                execution_successor=True,
            )
            for index in range(4)
        )
        return OriginalCutpointGraphIR(
            original_pe_sha256="0" * 64,
            state_machine_sha256="9" * 64,
            regions=regions,
            edges=edges,
            root_target_ids=(0,),
            reachable_target_ids=tuple(range(6)),
        )

    def _finite_call_contract(self) -> dict:
        term = self._TERM.to_json()
        return {
            "contract_id": 7,
            "source_target_id": 0,
            "continuation_target_id": 1,
            "edge_index": 10,
            "source_rva": 0x1000,
            "callsite_rva": 0x1008,
            "continuation_rva": 0x1010,
            "callee_target_id": 5,
            "callee_rva": 0x1050,
            "origin": "checked_finite_origin_call_summary",
            "finite_target_ids": [5],
            "preserved_registers": [],
            "callee_preserved_registers": ["ebx"],
            "target_carried_registers": ["ebx"],
            "preserved_caller_frame_word_offsets": [],
            "remaining_semantic_premises": [],
            "authorizing_lean_term": term,
            "kernel_check": {
                "status": "checked",
                "module": term["module"],
                "term": term,
                "source_sha256": "a" * 64,
                "olean_sha256": "b" * 64,
            },
        }

    def _authority(self, *extra: dict) -> dict:
        return {
            "format": (
                "stage-a-mixed-original-direct-call-authority-bindings-v2"
            ),
            "contracts": [self._finite_call_contract(), *extra],
            "report_authority": False,
            "authority_source": "named Lean terms only",
        }

    def _value(self) -> RuntimeValueCarryIR:
        graph = self._graph()
        locations = (
            RuntimeValueLocation(0, "register", "ebx", 0),
            RuntimeValueLocation(1, "frame_word", "esp", 32),
        )
        route = RuntimeValueCarryRoute(
            stable_id="gnu.callback.slot",
            origin=RuntimeValueOrigin("static_code_target", 5),
            locations=locations,
            facts=(
                RuntimeValueFact(1, 0),
                RuntimeValueFact(2, 0),
                RuntimeValueFact(3, 1),
                RuntimeValueFact(4, 1),
            ),
            transfers=(
                RuntimeValueTransfer(
                    0, 10, 0, 1, "finite_origin_call_result",
                    None, 0, "checked_dependency", 7,
                    graph.regions[0].semantic_contract_sha256,
                    graph.regions[0].instruction_bytes_sha256,
                    "checked_finite_origin_call_summary",
                    5,
                    self._TERM,
                    "a" * 64,
                    "b" * 64,
                ),
                RuntimeValueTransfer(
                    1, 11, 1, 2, "decoded_preserve",
                    0, 0, "checked_dependency", None,
                    graph.regions[1].semantic_contract_sha256,
                    graph.regions[1].instruction_bytes_sha256,
                ),
                RuntimeValueTransfer(
                    2, 12, 2, 3, "decoded_register_to_frame",
                    0, 1, "checked_dependency", None,
                    graph.regions[2].semantic_contract_sha256,
                    graph.regions[2].instruction_bytes_sha256,
                ),
                RuntimeValueTransfer(
                    3, 13, 3, 4, "call_frame_word_preserve",
                    1, 1, "required", None,
                    graph.regions[3].semantic_contract_sha256,
                    graph.regions[3].instruction_bytes_sha256,
                ),
            ),
            target_fact=RuntimeValueFact(4, 1),
        )
        return RuntimeValueCarryIR(
            original_pe_sha256=graph.original_pe_sha256,
            state_machine_sha256=graph.state_machine_sha256,
            cutpoint_graph_content_sha256=(
                canonical_original_cutpoint_graph_sha256(graph)
            ),
            cutpoint_graph_artifact_sha256="6" * 64,
            direct_call_authority_sha256="7" * 64,
            stack_dynamic_authority_sha256="8" * 64,
            routes=(route,),
        )

    def test_predecessor_closed_route_keeps_missing_frame_proof_explicit(
        self,
    ) -> None:
        value = validate_runtime_value_carry_ir(
            self._value(),
            graph=self._graph(),
            direct_call_authority=self._authority(),
        )

        self.assertFalse(value.proof_ready)
        self.assertEqual(
            value.routes[0].transfers[-1].authority_status,
            "required",
        )

    def test_missing_incoming_edge_fails_closed(self) -> None:
        value = self._value()
        route = dataclasses.replace(
            value.routes[0],
            transfers=value.routes[0].transfers[:-1],
        )
        with self.assertRaisesRegex(
            RuntimeValueCarryIRError,
            "does not exactly cover incoming graph edges.*missing 13",
        ):
            validate_runtime_value_carry_ir(
                dataclasses.replace(value, routes=(route,)),
                graph=self._graph(),
                direct_call_authority=self._authority(),
            )

    def test_stale_source_semantics_fail_closed(self) -> None:
        value = self._value()
        transfers = list(value.routes[0].transfers)
        transfers[1] = dataclasses.replace(
            transfers[1],
            source_semantic_contract_sha256="f" * 64,
        )
        route = dataclasses.replace(
            value.routes[0],
            transfers=tuple(transfers),
        )
        with self.assertRaisesRegex(
            RuntimeValueCarryIRError,
            "stale source semantics",
        ):
            validate_runtime_value_carry_ir(
                dataclasses.replace(value, routes=(route,)),
                graph=self._graph(),
                direct_call_authority=self._authority(),
            )

    def test_checked_frame_word_requires_exact_offset_authority(self) -> None:
        term = self._TERM.to_json()
        frame_contract = {
            "contract_id": 8,
            "source_target_id": 3,
            "continuation_target_id": 4,
            "edge_index": 13,
            "source_rva": 0x1030,
            "callsite_rva": 0x1038,
            "continuation_rva": 0x1040,
            "callee_target_id": 5,
            "callee_rva": 0x1050,
            "origin": "checked_direct_call_caller_frame_word_summary",
            "finite_target_ids": [],
            "preserved_registers": [],
            "callee_preserved_registers": [],
            "target_carried_registers": [],
            "preserved_caller_frame_word_offsets": [],
            "remaining_semantic_premises": [],
            "authorizing_lean_term": term,
            "kernel_check": {
                "status": "checked",
                "module": term["module"],
                "term": term,
                "source_sha256": "a" * 64,
                "olean_sha256": "b" * 64,
            },
        }
        value = self._value()
        transfers = list(value.routes[0].transfers)
        transfers[-1] = dataclasses.replace(
            transfers[-1],
            authority_status="checked_dependency",
            authority_contract_id=8,
            authority_origin=frame_contract["origin"],
            authority_callee_target_id=5,
            authority_lean_term=self._TERM,
            authority_kernel_source_sha256="a" * 64,
            authority_kernel_olean_sha256="b" * 64,
        )
        route = dataclasses.replace(
            value.routes[0],
            transfers=tuple(transfers),
        )
        with self.assertRaisesRegex(
            RuntimeValueCarryIRError,
            "does not preserve the caller-frame word",
        ):
            validate_runtime_value_carry_ir(
                dataclasses.replace(value, routes=(route,)),
                graph=self._graph(),
                direct_call_authority=self._authority(frame_contract),
            )

    def test_closed_frame_word_authority_makes_route_proof_ready(self) -> None:
        term = self._TERM.to_json()
        frame_contract = {
            "contract_id": 8,
            "source_target_id": 3,
            "continuation_target_id": 4,
            "edge_index": 13,
            "source_rva": 0x1030,
            "callsite_rva": 0x1038,
            "continuation_rva": 0x1040,
            "callee_target_id": 5,
            "callee_rva": 0x1050,
            "origin": "checked_direct_call_caller_frame_word_summary",
            "finite_target_ids": [],
            "preserved_registers": [],
            "callee_preserved_registers": [],
            "target_carried_registers": [],
            "preserved_caller_frame_word_offsets": [32],
            "remaining_semantic_premises": [],
            "caller_frame_word_authorizing_lean_term": term,
            "authorizing_lean_term": term,
            "kernel_check": {
                "status": "checked",
                "module": term["module"],
                "term": term,
                "source_sha256": "a" * 64,
                "olean_sha256": "b" * 64,
            },
        }
        value = self._value()
        transfers = list(value.routes[0].transfers)
        transfers[-1] = dataclasses.replace(
            transfers[-1],
            authority_status="checked_dependency",
            authority_contract_id=8,
            authority_origin=frame_contract["origin"],
            authority_callee_target_id=5,
            authority_lean_term=self._TERM,
            authority_kernel_source_sha256="a" * 64,
            authority_kernel_olean_sha256="b" * 64,
        )
        route = dataclasses.replace(
            value.routes[0],
            transfers=tuple(transfers),
        )
        checked = validate_runtime_value_carry_ir(
            dataclasses.replace(value, routes=(route,)),
            graph=self._graph(),
            direct_call_authority=self._authority(frame_contract),
        )

        self.assertTrue(checked.proof_ready)

    def test_finite_origin_frame_word_authority_is_exactly_bound(self) -> None:
        term = self._TERM.to_json()
        frame_contract = {
            "contract_id": 8,
            "source_target_id": 3,
            "continuation_target_id": 4,
            "edge_index": 13,
            "source_rva": 0x1030,
            "callsite_rva": 0x1038,
            "continuation_rva": 0x1040,
            "callee_target_id": 5,
            "callee_rva": 0x1050,
            "origin": (
                "checked_finite_origin_call_caller_frame_word_summary"
            ),
            "finite_target_ids": [5],
            "preserved_registers": [],
            "callee_preserved_registers": [],
            "target_carried_registers": [],
            "preserved_caller_frame_word_offsets": [32],
            "remaining_semantic_premises": [],
            "caller_frame_word_authorizing_lean_term": term,
            "authorizing_lean_term": term,
            "kernel_check": {
                "status": "checked",
                "module": term["module"],
                "term": term,
                "source_sha256": "a" * 64,
                "olean_sha256": "b" * 64,
            },
        }
        value = self._value()
        transfers = list(value.routes[0].transfers)
        transfers[-1] = dataclasses.replace(
            transfers[-1],
            authority_status="checked_dependency",
            authority_contract_id=8,
            authority_origin=frame_contract["origin"],
            authority_callee_target_id=5,
            authority_lean_term=self._TERM,
            authority_kernel_source_sha256="a" * 64,
            authority_kernel_olean_sha256="b" * 64,
        )
        route = dataclasses.replace(
            value.routes[0],
            transfers=tuple(transfers),
        )

        checked = validate_runtime_value_carry_ir(
            dataclasses.replace(value, routes=(route,)),
            graph=self._graph(),
            direct_call_authority=self._authority(frame_contract),
        )

        self.assertTrue(checked.proof_ready)

        stale_contract = dict(frame_contract)
        stale_contract["callee_target_id"] = 4
        with self.assertRaisesRegex(
            RuntimeValueCarryIRError,
            "exact edge/source/continuation/callee",
        ):
            validate_runtime_value_carry_ir(
                dataclasses.replace(value, routes=(route,)),
                graph=self._graph(),
                direct_call_authority=self._authority(stale_contract),
            )

        stale_transfers = list(route.transfers)
        stale_transfers[-1] = dataclasses.replace(
            stale_transfers[-1],
            authority_lean_term=RuntimeValueLeanTerm(
                self._TERM.module,
                self._TERM.namespace,
                "wrongCheckedSeed",
            ),
        )
        with self.assertRaisesRegex(
            RuntimeValueCarryIRError,
            "exact authority reference",
        ):
            validate_runtime_value_carry_ir(
                dataclasses.replace(
                    value,
                    routes=(
                        dataclasses.replace(
                            route,
                            transfers=tuple(stale_transfers),
                        ),
                    ),
                ),
                graph=self._graph(),
                direct_call_authority=self._authority(frame_contract),
            )

        stale_contract_id = list(route.transfers)
        stale_contract_id[-1] = dataclasses.replace(
            stale_contract_id[-1],
            authority_contract_id=9,
        )
        with self.assertRaisesRegex(
            RuntimeValueCarryIRError,
            "exact authority reference",
        ):
            validate_runtime_value_carry_ir(
                dataclasses.replace(
                    value,
                    routes=(
                        dataclasses.replace(
                            route,
                            transfers=tuple(stale_contract_id),
                        ),
                    ),
                ),
                graph=self._graph(),
                direct_call_authority=self._authority(frame_contract),
            )

        uncompiled_contract = dict(frame_contract)
        uncompiled_contract["kernel_check"] = {
            **frame_contract["kernel_check"],
            "status": "pending",
        }
        with self.assertRaisesRegex(
            RuntimeValueCarryIRError,
            "was not kernel-compiled",
        ):
            validate_runtime_value_carry_ir(
                dataclasses.replace(value, routes=(route,)),
                graph=self._graph(),
                direct_call_authority=self._authority(uncompiled_contract),
            )

    def test_generated_finite_origin_semantics_closes_only_after_kernel_check(
        self,
    ) -> None:
        term = self._TERM.to_json()
        frame_contract = {
            "contract_id": 8,
            "source_target_id": 3,
            "continuation_target_id": 4,
            "edge_index": 13,
            "source_rva": 0x1030,
            "callsite_rva": 0x1038,
            "continuation_rva": 0x1040,
            "callee_target_id": 5,
            "callee_rva": 0x1050,
            "origin": (
                "checked_finite_origin_call_caller_frame_word_summary"
            ),
            "finite_target_ids": [5],
            "preserved_registers": [],
            "callee_preserved_registers": [],
            "target_carried_registers": [],
            "preserved_caller_frame_word_offsets": [32],
            "remaining_semantic_premises": [],
            "caller_frame_word_authorizing_lean_term": term,
            "authorizing_lean_term": term,
            "kernel_check": {
                "status": "checked",
                "module": term["module"],
                "term": term,
                "source_sha256": "a" * 64,
                "olean_sha256": "b" * 64,
            },
        }
        value = self._value()
        transfers = list(value.routes[0].transfers)
        transfers[-1] = dataclasses.replace(
            transfers[-1],
            authority_status="checked_dependency",
            authority_contract_id=8,
            authority_origin=frame_contract["origin"],
            authority_callee_target_id=5,
            authority_lean_term=self._TERM,
            authority_kernel_source_sha256="a" * 64,
            authority_kernel_olean_sha256="b" * 64,
        )
        route = dataclasses.replace(
            value.routes[0],
            transfers=tuple(transfers),
        )
        checked = validate_runtime_value_carry_ir(
            dataclasses.replace(value, routes=(route,)),
            graph=self._graph(),
            direct_call_authority=self._authority(frame_contract),
        )

        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            write_runtime_value_carry_lean(
                out, checked, graph=self._graph()
            )
            pending = json.loads(
                (out / "runtime-value-carry-lean.json").read_text(
                    encoding="utf-8"
                )
            )
            semantics = out / "StageA" / f"{SEMANTICS_MODULE}.lean"
            source = semantics.read_text(encoding="utf-8")
            binding_source = (
                out
                / "StageA"
                / "GeneratedRelationalRuntimeValueCarryBinding.lean"
            ).read_text(encoding="utf-8")
            structure_source = (
                out
                / "StageA"
                / "GeneratedRelationalRuntimeValueCarryStructure.lean"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "CheckedFiniteOriginCallCallerFrameWordRouteTransfer",
                source,
            )
            self.assertIn("CheckedRouteExecutionInvariant", source)
            self.assertIn("ExecutionInvariant", source)
            self.assertIn("OriginalValueFlowInventory", source)
            self.assertIn("generatedOriginalValueFlowFact0000", source)
            self.assertIn("generatedOriginalValueFlowFact0001", source)
            self.assertIn("targetIds := [1, 2]", source)
            self.assertIn("targetIds := [3, 4]", source)
            self.assertIn("location := .register .ebx", source)
            self.assertIn("location := .frameWord .esp (.add 32)", source)
            self.assertIn(
                "StageA.Relational.ValueOriginAtom.staticCodeTarget",
                source,
            )
            for forbidden in ("axiom ", "admit", "sorry"):
                self.assertNotIn(forbidden, source)
            self.assertIn("ExactIncomingChecked", binding_source)
            self.assertIn("CheckedRoute", binding_source)
            self.assertIn("decodedIncoming := true", structure_source)
            self.assertIn(
                "ExecutionInvariant",
                pending["routes"][0]["aggregate_invariant_constructor"],
            )
            self.assertIn(self._TERM.qualified, source)
            self.assertEqual(
                pending["routes"][0]["semantic_authority_status"],
                "kernel_compile_required",
            )
            self.assertFalse(pending["semantic_authority_complete"])
            declarations = pending[
                "original_combined_value_flow_declarations"
            ]
            self.assertEqual(
                declarations["inventory"]["symbol"],
                "generatedOriginalValueFlowInventory",
            )
            self.assertEqual(
                [row["id"] for row in declarations["facts"]], [0, 1]
            )
            self.assertEqual(
                [row["fact_stable_id"] for row in declarations["facts"]],
                [
                    "gnu.callback.slot:location:0",
                    "gnu.callback.slot:location:1",
                ],
            )
            self.assertEqual(
                [row["target_ids"] for row in declarations["facts"]],
                [[1, 2], [3, 4]],
            )

            source_sha256 = hashlib.sha256(
                semantics.read_bytes()
            ).hexdigest()
            write_runtime_value_carry_lean(
                out,
                checked,
                graph=self._graph(),
                kernel_checks={
                    f"StageA.{SEMANTICS_MODULE}": {
                        "status": "checked",
                        "source_sha256": "d" * 64,
                        "olean_sha256": "c" * 64,
                    }
                },
            )
            stale = json.loads(
                (out / "runtime-value-carry-lean.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                stale["routes"][0]["semantic_authority_status"],
                "kernel_compile_required",
            )
            write_runtime_value_carry_lean(
                out,
                checked,
                graph=self._graph(),
                kernel_checks={
                    f"StageA.{SEMANTICS_MODULE}": {
                        "status": "checked",
                        "source_sha256": source_sha256,
                        "olean_sha256": "c" * 64,
                    }
                },
            )
            closed = json.loads(
                (out / "runtime-value-carry-lean.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                closed["routes"][0]["semantic_authority"][0]["status"],
                "closed",
            )
            self.assertEqual(
                len(closed["routes"][0]["semantic_authority"]),
                len(checked.routes[0].transfers),
            )
            self.assertEqual(
                closed["routes"][0]["semantic_authority_status"],
                "closed",
            )
            self.assertTrue(closed["semantic_authority_complete"])

    def test_unclosed_named_dependency_fails_closed(self) -> None:
        authority = self._authority()
        authority["contracts"][0]["remaining_semantic_premises"] = [
            "StateRel"
        ]
        with self.assertRaisesRegex(
            RuntimeValueCarryIRError,
            "no closed named Lean authority",
        ):
            validate_runtime_value_carry_ir(
                self._value(),
                graph=self._graph(),
                direct_call_authority=authority,
            )


if __name__ == "__main__":
    unittest.main()
