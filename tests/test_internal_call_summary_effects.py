from __future__ import annotations

import unittest

from spaghetti_extractor.call_site_effects import (
    CallOutput,
    CallSiteEffect,
    CallSiteId,
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


def unit(
    identifier: str,
    rva: int,
    *,
    outcome: str,
    events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    writes: list[dict[str, object]] = []
    if outcome == "return":
        writes.append({"register": "esp", "value": add(reg("esp"), const(4))})
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
            "register_writes": writes,
            "memory_events": [],
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


class InternalCallSummaryEffectTests(unittest.TestCase):
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
