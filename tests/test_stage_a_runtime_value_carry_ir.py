from __future__ import annotations

import dataclasses
import unittest

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
    RuntimeValueOrigin,
    RuntimeValueTransfer,
    validate_runtime_value_carry_ir,
)


class StageARuntimeValueCarryIRTests(unittest.TestCase):
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
        return {
            "contract_id": 7,
            "source_target_id": 0,
            "continuation_target_id": 1,
            "origin": "checked_finite_origin_call_summary",
            "finite_target_ids": [5],
            "preserved_registers": [],
            "callee_preserved_registers": ["ebx"],
            "target_carried_registers": ["ebx"],
            "preserved_caller_frame_word_offsets": [],
            "remaining_semantic_premises": [],
            "authorizing_lean_term": {
                "module": "StageA.GeneratedSeed",
                "namespace": "StageA",
                "symbol": "checkedSeed",
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
        frame_contract = {
            "contract_id": 8,
            "source_target_id": 3,
            "continuation_target_id": 4,
            "origin": "checked_direct_call_caller_frame_word_summary",
            "finite_target_ids": [],
            "preserved_registers": [],
            "callee_preserved_registers": [],
            "target_carried_registers": [],
            "preserved_caller_frame_word_offsets": [],
            "remaining_semantic_premises": [],
            "authorizing_lean_term": {
                "module": "StageA.GeneratedFrame",
                "namespace": "StageA",
                "symbol": "checkedFrame",
            },
        }
        value = self._value()
        transfers = list(value.routes[0].transfers)
        transfers[-1] = dataclasses.replace(
            transfers[-1],
            authority_status="checked_dependency",
            authority_contract_id=8,
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
        frame_contract = {
            "contract_id": 8,
            "source_target_id": 3,
            "continuation_target_id": 4,
            "origin": "checked_direct_call_caller_frame_word_summary",
            "finite_target_ids": [],
            "preserved_registers": [],
            "callee_preserved_registers": [],
            "target_carried_registers": [],
            "preserved_caller_frame_word_offsets": [32],
            "remaining_semantic_premises": [],
            "caller_frame_word_authorizing_lean_term": {
                "module": "StageA.GeneratedFrame",
                "namespace": "StageA",
                "symbol": "checkedFrame",
            },
            "authorizing_lean_term": {
                "module": "StageA.GeneratedFrame",
                "namespace": "StageA",
                "symbol": "checkedFrame",
            },
        }
        value = self._value()
        transfers = list(value.routes[0].transfers)
        transfers[-1] = dataclasses.replace(
            transfers[-1],
            authority_status="checked_dependency",
            authority_contract_id=8,
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
