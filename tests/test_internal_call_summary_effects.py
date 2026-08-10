from __future__ import annotations

import unittest

from spaghetti_extractor.call_site_effects import (
    CallOutput,
    CallSiteEffect,
    CallSiteId,
    CallWriteSpan,
)
from spaghetti_extractor.internal_call_summaries import (
    derive_internal_call_preservation_summaries,
)
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.provenance_domain import ValueOrigin


REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")


def reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def add(left: object, right: object) -> dict[str, object]:
    return {"op": "add32", "args": [left, right]}


def sub(left: object, right: object) -> dict[str, object]:
    return {"op": "sub32", "args": [left, right]}


def load(address: object) -> dict[str, object]:
    return {"op": "load", "address": address, "width": 4}


def unit(
    identifier: str,
    rva: int,
    *,
    outcome: str,
    events: list[dict[str, object]] | None = None,
    writes: list[dict[str, object]] | None = None,
    memory: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    register_writes = list(writes or [])
    if outcome == "return":
        register_writes.append({
            "register": "esp",
            "value": add(reg("esp"), const(4)),
        })
    return {
        "id": identifier,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "instructions": (
            [{"mnemonic": "ret", "operands": []}]
            if outcome == "return"
            else []
        ),
        "semantics": {
            "outcome": {"kind": outcome},
            "register_writes": register_writes,
            "memory_events": memory or [],
            "external_events": events or [],
        },
    }


def external_call(name: str) -> dict[str, object]:
    return {
        "kind": "external_call",
        "dll": "fixture.dll",
        "symbol": name,
        "register_inputs": {register: reg(register) for register in REGISTERS},
    }


def internal_call(target_rva: int) -> dict[str, object]:
    return {
        "kind": "internal_call",
        "target_rva": target_rva,
        "register_inputs": {register: reg(register) for register in REGISTERS},
    }


def edge(source: str, target: str) -> dict[str, object]:
    return {
        "kind": "direct_control",
        "source_unit_id": source,
        "resolved_unit_id": target,
        "status": "resolved",
    }


def effect(unit_id: str, resource: str) -> dict[str, object]:
    abi = resolve_machine_call_abi("pe32-cdecl-v1")
    assert abi is not None
    dependency = f"checked-external-site:{unit_id}:0"
    return CallSiteEffect(
        site=CallSiteId(unit_id, 0),
        transfer_kind="external_call",
        status="complete",
        register_frame_status="complete",
        preserved_registers=frozenset(abi.preserved_registers),
        stack_frame_status="complete",
        stack_cleanup_bytes=0,
        result_status="complete",
        outputs=(CallOutput(
            ValueOrigin("register_location", ("eax",)),
            frozenset({ValueOrigin("resource", (resource,), (dependency,))}),
        ),),
        memory_frame_status="complete",
        memory_preserved=True,
        memory_writes=(),
        abi=abi,
        argument_words=0,
        dependencies=(dependency,),
    ).as_json()


def memory_effect(
    unit_id: str,
    resource: str,
    *,
    address: int = 0x430000,
) -> dict[str, object]:
    abi = resolve_machine_call_abi("pe32-cdecl-v1")
    assert abi is not None
    dependency = f"checked-external-site:{unit_id}:0"
    location = ValueOrigin("exact", (address,))
    return CallSiteEffect(
        site=CallSiteId(unit_id, 0),
        transfer_kind="external_call",
        status="complete",
        register_frame_status="complete",
        preserved_registers=frozenset(abi.preserved_registers),
        stack_frame_status="complete",
        stack_cleanup_bytes=0,
        result_status="complete",
        outputs=(CallOutput(
            location,
            frozenset({ValueOrigin("resource", (resource,), (dependency,))}),
        ),),
        memory_frame_status="complete",
        memory_preserved=False,
        memory_writes=(CallWriteSpan(location, 4),),
        abi=abi,
        argument_words=0,
        dependencies=(dependency,),
    ).as_json()


class InternalCallSummaryEffectTests(unittest.TestCase):
    def test_partial_call_families_compose_without_closing_behavior(self) -> None:
        abi = resolve_machine_call_abi("pe32-cdecl-v1")
        assert abi is not None
        dependency = "call-frame-hypothesis:fixture"
        partial = CallSiteEffect(
            site=CallSiteId("callee", 0),
            transfer_kind="external_call",
            status="incomplete",
            register_frame_status="complete",
            preserved_registers=frozenset(abi.preserved_registers),
            stack_frame_status="complete",
            stack_cleanup_bytes=0,
            result_status="incomplete",
            outputs=(),
            memory_frame_status="incomplete",
            memory_preserved=False,
            memory_writes=(),
            abi=abi,
            argument_words=0,
            dependencies=(dependency,),
            failure_codes=("result_frame_unresolved",),
        ).as_json()
        result = derive_internal_call_preservation_summaries(
            units=[
                unit(
                    "caller",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit("caller-return", 0x1001, outcome="return"),
                unit(
                    "callee",
                    0x2000,
                    outcome="fallthrough",
                    events=[external_call("Unknown")],
                ),
                unit("callee-return", 0x2001, outcome="return"),
            ],
            roots=["caller"],
            direct_edges=[
                edge("caller", "caller-return"),
                edge("callee", "callee-return"),
            ],
            internal_call_edges=[{
                "source_unit_id": "caller",
                "source_event_index": 0,
                "target_unit_id": "callee",
                "status": "resolved",
            }],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            call_site_effects=[partial],
        )

        summaries = {
            row["target_unit_id"]: row for row in result["summaries"]
        }
        for identity in ("callee", "caller"):
            summary = summaries[identity]
            self.assertEqual(
                summary["register_preservation"]["status"], "complete"
            )
            self.assertIn("esi", summary["preserved_registers"])
            self.assertEqual(summary["return_behavior"]["status"], "incomplete")
            self.assertEqual(
                summary["return_instruction_cleanup"]["cleanup_bytes"], 0
            )
        self.assertIn(dependency, summaries["callee"]["target_dependencies"])

    def test_input_stack_word_written_to_global_composes_at_call_site(self) -> None:
        slot = 0x434960
        result = derive_internal_call_preservation_summaries(
            units=[
                unit(
                    "factory",
                    0x1000,
                    outcome="fallthrough",
                    events=[external_call("Create")],
                ),
                unit(
                    "push-result",
                    0x1001,
                    outcome="fallthrough",
                    writes=[{
                        "register": "esp",
                        "value": sub(reg("esp"), const(4)),
                    }],
                    memory=[{
                        "kind": "write",
                        "width": 4,
                        "address": sub(reg("esp"), const(4)),
                        "value": reg("eax"),
                    }],
                ),
                unit(
                    "call-store",
                    0x1002,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit("root-return", 0x1003, outcome="return"),
                unit(
                    "store-argument",
                    0x2000,
                    outcome="return",
                    memory=[{
                        "kind": "write",
                        "width": 4,
                        "address": const(slot),
                        "value": load(add(reg("esp"), const(4))),
                    }],
                ),
            ],
            roots=["factory"],
            direct_edges=[
                edge("factory", "push-result"),
                edge("push-result", "call-store"),
                edge("call-store", "root-return"),
            ],
            internal_call_edges=[{
                "source_unit_id": "call-store",
                "source_event_index": 0,
                "target_unit_id": "store-argument",
                "status": "resolved",
            }],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            call_site_effects=[effect("factory", "surface")],
        )

        summaries = {
            row["target_unit_id"]: row for row in result["summaries"]
        }
        callee_value = summaries["store-argument"]["result_memory_origins"][
            "locations"
        ][0]["value"]
        self.assertEqual(callee_value, {"kind": "input_stack_word", "offset": 4})
        root_value = summaries["factory"]["result_memory_origins"][
            "locations"
        ][0]["value"]
        self.assertEqual(root_value["kind"], "typed_origins")
        self.assertEqual(root_value["origins"][0]["key"], ["surface"])

    def test_known_stack_overwrite_kills_input_stack_relation(self) -> None:
        slot = 0x434960
        result = derive_internal_call_preservation_summaries(
            units=[
                unit(
                    "overwrite",
                    0x2000,
                    outcome="fallthrough",
                    memory=[{
                        "kind": "write",
                        "width": 4,
                        "address": add(reg("esp"), const(4)),
                        "value": const(0),
                    }],
                ),
                unit(
                    "store",
                    0x2001,
                    outcome="return",
                    memory=[{
                        "kind": "write",
                        "width": 4,
                        "address": const(slot),
                        "value": load(add(reg("esp"), const(4))),
                    }],
                ),
            ],
            roots=["overwrite"],
            direct_edges=[edge("overwrite", "store")],
            internal_call_edges=[],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
        )

        value = result["summaries"][0]["result_memory_origins"]["locations"][0][
            "value"
        ]
        self.assertEqual(value, {"kind": "exact", "value": 0})

    def test_typed_external_result_survives_wrapper_summary(self) -> None:
        result = derive_internal_call_preservation_summaries(
            units=[
                unit("wrapper", 0x1000, outcome="fallthrough", events=[external_call("Make")]),
                unit("return", 0x1001, outcome="return"),
            ],
            roots=["wrapper"],
            direct_edges=[edge("wrapper", "return")],
            internal_call_edges=[],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            call_site_effects=[effect("wrapper", "fixture-resource")],
        )

        summary = result["summaries"][0]
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(
            summary["result_register_origins"]["registers"]["eax"],
            {
                "kind": "typed_origins",
                "origins": [{
                    "kind": "resource",
                    "key": ["fixture-resource"],
                    "authority_dependencies": [
                        "checked-external-site:wrapper:0"
                    ],
                }],
            },
        )

    def test_join_retains_bounded_typed_alternatives(self) -> None:
        result = derive_internal_call_preservation_summaries(
            units=[
                unit("root", 0x1000, outcome="fallthrough"),
                unit("left", 0x1010, outcome="fallthrough", events=[external_call("Left")]),
                unit("right", 0x1020, outcome="fallthrough", events=[external_call("Right")]),
                unit("return", 0x1030, outcome="return"),
            ],
            roots=["root"],
            direct_edges=[
                edge("root", "left"),
                edge("root", "right"),
                edge("left", "return"),
                edge("right", "return"),
            ],
            internal_call_edges=[],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            call_site_effects=[effect("left", "left"), effect("right", "right")],
            max_value_alternatives=2,
        )

        origins = result["summaries"][0]["result_register_origins"]["registers"]["eax"]
        self.assertEqual(origins["kind"], "typed_origins")
        self.assertEqual(
            {tuple(origin["key"]) for origin in origins["origins"]},
            {("left",), ("right",)},
        )

    def test_memory_result_composes_through_internal_wrapper(self) -> None:
        slot = 0x430000
        result = derive_internal_call_preservation_summaries(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[internal_call(0x2000)],
                ),
                unit(
                    "load-result",
                    0x1001,
                    outcome="fallthrough",
                    writes=[{"register": "eax", "value": load(const(slot))}],
                ),
                unit("root-return", 0x1002, outcome="return"),
                unit(
                    "factory",
                    0x2000,
                    outcome="fallthrough",
                    events=[external_call("Create")],
                ),
                unit("factory-return", 0x2001, outcome="return"),
            ],
            roots=["root"],
            direct_edges=[
                edge("root", "load-result"),
                edge("load-result", "root-return"),
                edge("factory", "factory-return"),
            ],
            internal_call_edges=[{
                "source_unit_id": "root",
                "source_event_index": 0,
                "target_unit_id": "factory",
                "status": "resolved",
            }],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            call_site_effects=[memory_effect("factory", "surface")],
        )

        summaries = {
            row["target_unit_id"]: row for row in result["summaries"]
        }
        factory_memory = summaries["factory"]["result_memory_origins"]
        self.assertEqual(factory_memory["status"], "complete")
        self.assertEqual(factory_memory["locations"][0]["location"], {
            "kind": "exact",
            "key": [slot],
        })
        self.assertEqual(
            summaries["root"]["result_register_origins"]["registers"]["eax"]
            ["kind"],
            "typed_origins",
        )

    def test_unknown_write_kills_prior_memory_result(self) -> None:
        slot = 0x430000
        result = derive_internal_call_preservation_summaries(
            units=[
                unit(
                    "root",
                    0x1000,
                    outcome="fallthrough",
                    events=[external_call("Create")],
                ),
                unit(
                    "unknown-write",
                    0x1001,
                    outcome="fallthrough",
                    memory=[{
                        "kind": "write",
                        "width": 4,
                        "address": reg("ecx"),
                        "value": const(0),
                    }],
                ),
                unit("return", 0x1002, outcome="return"),
            ],
            roots=["root"],
            direct_edges=[
                edge("root", "unknown-write"),
                edge("unknown-write", "return"),
            ],
            internal_call_edges=[],
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis={},
            call_site_effects=[memory_effect("root", "surface", address=slot)],
        )

        summary = result["summaries"][0]
        self.assertEqual(summary["result_memory_origins"], {
            "status": "complete",
            "locations": [],
        })

    def test_exact_write_preserves_only_disjoint_typed_result(self) -> None:
        slot = 0x430000
        for name, write_address, expected_kind in (
            ("disjoint", slot + 8, "typed_origins"),
            ("overlap", slot, "exact"),
        ):
            with self.subTest(name=name):
                result = derive_internal_call_preservation_summaries(
                    units=[
                        unit(
                            "root",
                            0x1000,
                            outcome="fallthrough",
                            events=[external_call("Create")],
                        ),
                        unit(
                            "write",
                            0x1001,
                            outcome="fallthrough",
                            memory=[{
                                "kind": "write",
                                "width": 4,
                                "address": const(write_address),
                                "value": const(0),
                            }],
                        ),
                        unit("return", 0x1002, outcome="return"),
                    ],
                    roots=["root"],
                    direct_edges=[
                        edge("root", "write"),
                        edge("write", "return"),
                    ],
                    internal_call_edges=[],
                    recovered_indirect_targets=[],
                    indirect_exits=[],
                    import_abis={},
                    call_site_effects=[
                        memory_effect("root", "surface", address=slot)
                    ],
                )

                locations = result["summaries"][0]["result_memory_origins"][
                    "locations"
                ]
                slot_result = next(
                    row
                    for row in locations
                    if row["location"] == {"kind": "exact", "key": [slot]}
                )
                self.assertEqual(slot_result["value"]["kind"], expected_kind)

    def test_call_effect_must_bind_exact_machine_event(self) -> None:
        with self.assertRaisesRegex(ValueError, "exact machine-IR call"):
            derive_internal_call_preservation_summaries(
                units=[unit("root", 0x1000, outcome="return")],
                roots=["root"],
                direct_edges=[],
                internal_call_edges=[],
                recovered_indirect_targets=[],
                indirect_exits=[],
                import_abis={},
                call_site_effects=[effect("root", "bad")],
            )


if __name__ == "__main__":
    unittest.main()
