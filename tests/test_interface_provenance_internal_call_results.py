from __future__ import annotations

import unittest

from tests import test_interface_provenance as fixtures

from spaghetti_extractor.call_site_effects import (
    CALL_SITE_EFFECT_FORMAT,
    parse_call_site_effects,
)
from spaghetti_extractor.interface_provenance import (
    recover_external_interface_targets,
)
from spaghetti_extractor.provenance_domain import ValueOrigin, origins_json


CALLEE_RVA = 0x1800
CALLEE_ADDRESS = fixtures.IMAGE_BASE + CALLEE_RVA


class InternalCallResultConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.InterfaceProvenanceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.interface_value = frozenset({ValueOrigin(
            "interface_object",
            (self.fixture.profile.sha256, "IThing"),
        )})

    def test_direct_exact_internal_call_applies_all_result_families(self) -> None:
        result = self._run_case("direct")

        self._assert_result_parity(result, dependency_unit="callee")

    def test_exact_origin_indirect_call_applies_all_result_families(self) -> None:
        result = self._run_case("exact_origin")

        self._assert_result_parity(result, dependency_unit="callee")

    def test_recovered_indirect_call_applies_all_result_families(self) -> None:
        result = self._run_case("recovered")

        self._assert_result_parity(
            result,
            dependency_unit="callee",
            target_recovery_dependency="exit:invoke",
        )

    def test_typed_origins_preserve_summary_and_call_dependencies(self) -> None:
        summary_dependency = "internal-summary:typed-result"
        typed_interface = ValueOrigin(
            "interface_object",
            (self.fixture.profile.sha256, "IThing"),
            (summary_dependency,),
        )
        result = self._run_case(
            "direct",
            register_relations={
                "eax": [{
                    "kind": "typed_origins",
                    "origins": origins_json(frozenset({typed_interface})),
                }],
            },
        )

        resolution = self._resolution(result, "exit:register-dispatch")
        call_dependency = self._call_dependency("callee")
        self.assertEqual(resolution["status"], "recovered", result)
        self.assertEqual(
            resolution["analysis_dependencies"],
            sorted([call_dependency, summary_dependency]),
        )
        effect = self._effect(result, "invoke")
        register_output = next(
            output
            for output in effect["result_frame"]["outputs"]
            if output["location"] == {
                "kind": "register_location",
                "key": ["eax"],
            }
        )
        self.assertEqual(
            register_output["origins"][0]["authority_dependencies"],
            [summary_dependency],
        )
        self.assertEqual(effect["dependencies"], [call_dependency])

    def test_malformed_or_over_budget_typed_origins_fail_closed(self) -> None:
        interface_json = next(iter(self.interface_value)).as_json()
        cases = {
            "malformed": [{
                "kind": "typed_origins",
                "origins": [{
                    **interface_json,
                    "authority_dependencies": ["z", "a"],
                }],
            }],
            "over_budget": [{
                "kind": "typed_origins",
                "origins": origins_json(frozenset({
                    next(iter(self.interface_value)),
                    ValueOrigin("exact", (0,)),
                })),
            }],
        }
        for name, relation in cases.items():
            with self.subTest(name=name):
                result = self._run_case(
                    "direct",
                    register_relations={"eax": relation},
                    finite_value_budget=1,
                    preserved_registers=frozenset({
                        "eax", "ebp", "ebx", "edi", "esi",
                    }),
                )

                self.assertEqual(
                    self._resolution(result, "exit:register-dispatch")["status"],
                    "incomplete",
                    result,
                )
                self.assertEqual(
                    self._resolution(result, "exit:memory-dispatch")["status"],
                    "recovered",
                    result,
                )
                effect = self._effect(result, "invoke")
                self.assertEqual(effect["status"], "incomplete")
                self.assertEqual(
                    effect["result_frame"],
                    {"status": "incomplete", "outputs": []},
                )
                self.assertIn("result_frame_unknown", effect["failure_codes"])

    def test_call_site_effect_emits_known_memory_write_span(self) -> None:
        result = self.fixture._run(
            [fixtures.factory_unit()],
            [],
            roots=["factory"],
            indirect_exits=[],
            allow_global_slot_promotion=False,
        )

        effect = self._effect(result, "factory")
        self.assertEqual(effect["status"], "complete")
        self.assertEqual(effect["memory_frame"], {
            "status": "complete",
            "preserved": False,
            "writes": [{
                "base": {"kind": "exact", "key": [fixtures.SLOT]},
                "size": 4,
            }],
        })
        self.assertEqual(effect["stack_frame"], {
            "status": "complete",
            "stack_cleanup_bytes": 8,
        })

    def _run_case(
        self,
        mode: str,
        *,
        register_relations: dict[str, list[dict[str, object]]] | None = None,
        finite_value_budget: int = 4,
        preserved_registers: frozenset[str] = frozenset({
            "ebp", "ebx", "edi", "esi",
        }),
    ) -> dict[str, object]:
        call = self._call(mode)
        units = [
            fixtures.unit("seed", 0x1000, writes=[
                {"register": "eax", "value": fixtures.load(fixtures.const(fixtures.SLOT))},
                {"register": "ecx", "value": fixtures.load(fixtures.const(fixtures.SLOT))},
            ]),
            fixtures.unit("invoke", 0x1100, events=[call], ordered=[call]),
            fixtures.unit("callee", CALLEE_RVA),
            fixtures.unit("register-vtable", 0x1200, writes=[{
                "register": "ecx",
                "value": fixtures.load(fixtures.reg("eax")),
            }]),
            fixtures.indirect_call("register-dispatch", 0x1210),
            fixtures.unit("memory-object", 0x1300, writes=[{
                "register": "eax",
                "value": fixtures.load(fixtures.const(fixtures.CHILD_SLOT)),
            }]),
            fixtures.unit("memory-vtable", 0x1310, writes=[{
                "register": "ecx",
                "value": fixtures.load(fixtures.reg("eax")),
            }]),
            fixtures.indirect_call("memory-dispatch", 0x1320),
        ]
        direct_edges = [
            fixtures.edge("seed", "invoke"),
            fixtures.edge("invoke", "register-vtable"),
            fixtures.edge("register-vtable", "register-dispatch"),
            fixtures.edge("invoke", "memory-object"),
            fixtures.edge("memory-object", "memory-vtable"),
            fixtures.edge("memory-vtable", "memory-dispatch"),
        ]
        recovered_edges: list[dict[str, object]] = []
        internal_edges: list[dict[str, object]] = []
        if mode == "direct":
            internal_edges.append({
                "source_unit_id": "invoke",
                "source_event_index": 0,
                "target_unit_id": "callee",
            })
        else:
            recovered_edges.append({
                "id": "exit:invoke",
                "kind": "indirect_call",
                "status": "recovered",
                "source_unit_id": "invoke",
                "source_event_index": 0,
                "target_rvas": [CALLEE_RVA],
                "target_unit_ids": ["callee"],
                "external_targets": [],
            })
        return recover_external_interface_targets(
            units=units,
            roots=["seed"],
            direct_edges=direct_edges,
            internal_call_edges=internal_edges,
            recovered_indirect_edges=recovered_edges,
            indirect_exits=[
                {
                    "id": "exit:register-dispatch",
                    "source_unit_id": "register-dispatch",
                    "source_rva": 0x1210,
                    "source_event_index": 0,
                    "kind": "indirect_call",
                    "target_expression": fixtures.load(fixtures.reg("ecx")),
                },
                {
                    "id": "exit:memory-dispatch",
                    "source_unit_id": "memory-dispatch",
                    "source_rva": 0x1320,
                    "source_event_index": 0,
                    "kind": "indirect_call",
                    "target_expression": fixtures.load(fixtures.reg("ecx")),
                },
            ],
            profiles=[self.fixture.profile],
            import_abis={},
            internal_call_preserved_registers={
                CALLEE_ADDRESS: preserved_registers,
            },
            internal_call_stack_cleanup={CALLEE_ADDRESS: 0},
            internal_call_result_relations={
                CALLEE_ADDRESS: register_relations or {
                    "eax": [{
                        "kind": "input_register",
                        "register": "ecx",
                    }],
                },
            },
            internal_call_memory_preservation={CALLEE_ADDRESS: True},
            internal_call_memory_result_relations={
                CALLEE_ADDRESS: {
                    ValueOrigin("exact", (fixtures.CHILD_SLOT,)): (
                        self.interface_value
                    ),
                },
            },
            image_base=fixtures.IMAGE_BASE,
            finite_value_budget=finite_value_budget,
            initial_known_slots={fixtures.SLOT: self.interface_value},
            allow_global_slot_promotion=False,
        )

    def _call(self, mode: str) -> dict[str, object]:
        if mode == "direct":
            event: dict[str, object] = {
                "kind": "internal_call",
                "target_rva": CALLEE_RVA,
                "return_rva": 0x1101,
            }
        else:
            event = {
                "kind": "indirect_call",
                "return_rva": 0x1101,
                "target": (
                    fixtures.const(CALLEE_ADDRESS)
                    if mode == "exact_origin"
                    else fixtures.reg("edi")
                ),
            }
        event["register_inputs"] = {
            name: fixtures.reg(name) for name in fixtures.REGISTERS
        }
        return event

    def _assert_result_parity(
        self,
        result: dict[str, object],
        *,
        dependency_unit: str,
        target_recovery_dependency: str | None = None,
    ) -> None:
        dependency = self._call_dependency(dependency_unit)
        resolution_dependencies = sorted([
            dependency,
            *(
                [target_recovery_dependency]
                if target_recovery_dependency is not None
                else []
            ),
        ])
        for exit_id in ("exit:register-dispatch", "exit:memory-dispatch"):
            resolution = self._resolution(result, exit_id)
            self.assertEqual(resolution["status"], "recovered", result)
            self.assertEqual(
                resolution["analysis_dependencies"], resolution_dependencies
            )

        effect = self._effect(result, "invoke")
        self.assertEqual(effect["format"], CALL_SITE_EFFECT_FORMAT)
        self.assertEqual(effect["status"], "complete")
        self.assertEqual(effect["stack_frame"], {
            "status": "complete",
            "stack_cleanup_bytes": 0,
        })
        self.assertEqual(effect["memory_frame"], {
            "status": "complete",
            "preserved": True,
            "writes": [],
        })
        self.assertEqual(effect["dependencies"], resolution_dependencies)
        self.assertEqual(len(effect["result_frame"]["outputs"]), 2)
        self.assertFalse(result["proof_authority"])
        parsed = parse_call_site_effects(
            result["call_site_effects"], finite_value_budget=4
        )
        self.assertEqual(len(parsed), len(result["call_site_effects"]))
        sites = [
            (item["unit_id"], item["event_index"])
            for item in result["call_site_effects"]
        ]
        self.assertEqual(sites, sorted(sites))

    def _call_dependency(self, target: str) -> str:
        return f'call-frame:["invoke",0,"{target}"]'

    def _effect(
        self, result: dict[str, object], unit_id: str
    ) -> dict[str, object]:
        return next(
            item
            for item in result["call_site_effects"]
            if item["unit_id"] == unit_id
        )

    def _resolution(
        self, result: dict[str, object], exit_id: str
    ) -> dict[str, object]:
        return next(
            item for item in result["resolutions"] if item["id"] == exit_id
        )


if __name__ == "__main__":
    unittest.main()
