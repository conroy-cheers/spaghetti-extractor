from __future__ import annotations

import json
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

from spaghetti_extractor.external_interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    ExternalInterfaceProfile,
    load_external_interface_profile,
    same_library_callback_call_through_effect_json,
)
from spaghetti_extractor.control_analysis_v2 import exact_control_inventory_v2
from spaghetti_extractor.import_abi import SelectedImportABI
from spaghetti_extractor.interface_provenance import (
    INTERFACE_PROVENANCE_FORMAT,
    recover_external_interface_targets,
)
from spaghetti_extractor.provenance_domain import ValueOrigin
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.machine_import_profiles import MachineImportIdentity


IMAGE_BASE = 0x400000
SLOT = 0x430000
CHILD_SLOT = 0x430004
REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")


def reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def add(left: object, right: object) -> dict[str, object]:
    return {"op": "add32", "args": [left, right]}


def sub(left: object, right: object) -> dict[str, object]:
    return {"op": "sub32", "args": [left, right]}


def mul(left: object, right: object) -> dict[str, object]:
    return {"op": "mul32", "args": [left, right]}


def bit_and(left: object, right: object) -> dict[str, object]:
    return {"op": "and32", "args": [left, right]}


def load(address: object) -> dict[str, object]:
    return {"op": "load", "width": 4, "address": address}


def unit(
    identifier: str,
    rva: int,
    *,
    writes: list[dict[str, object]] | None = None,
    memory: list[dict[str, object]] | None = None,
    events: list[dict[str, object]] | None = None,
    ordered: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": identifier,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "instructions": [],
        "semantics": {
            "outcome": {"kind": "fallthrough", "target_rva": rva + 1},
            "register_writes": writes or [],
            "memory_events": memory or [],
            "external_events": events or [],
            "ordered_events": ordered or [],
        },
    }


def factory_unit(identifier: str = "factory", rva: int = 0x1100) -> dict[str, object]:
    esp4 = sub(reg("esp"), const(4))
    esp8 = sub(esp4, const(4))
    call = {
        "kind": "external_call",
        "dll": "example.dll",
        "symbol": "CreateThing",
        "ordinal": None,
        "return_rva": rva + 1,
        "register_inputs": {name: reg(name) for name in REGISTERS},
    }
    call["register_inputs"]["esp"] = esp8
    writes = [
        {"kind": "write", "width": 4, "address": esp4, "value": const(SLOT)},
        {"kind": "write", "width": 4, "address": esp8, "value": const(0)},
    ]
    return unit(
        identifier,
        rva,
        memory=writes,
        events=[call],
        ordered=[*writes, call],
    )


def indirect_call(identifier: str = "call", rva: int = 0x1400) -> dict[str, object]:
    target = load(reg("ecx"))
    event = {
        "kind": "indirect_call",
        "return_rva": rva + 1,
        "target": target,
        "register_inputs": {name: reg(name) for name in REGISTERS},
    }
    return unit(identifier, rva, events=[event], ordered=[event])


def create_child_call(
    identifier: str = "create",
    rva: int = 0x1380,
) -> dict[str, object]:
    pushed_this = sub(reg("esp"), const(4))
    target = load(add(reg("ecx"), const(4)))
    write = {
        "kind": "write",
        "width": 4,
        "address": pushed_this,
        "value": reg("eax"),
        "instruction_rva": rva,
    }
    event = {
        "kind": "indirect_call",
        "return_rva": rva + 1,
        "target": target,
        "register_inputs": {name: reg(name) for name in REGISTERS},
    }
    event["register_inputs"]["esp"] = pushed_this
    return unit(
        identifier,
        rva,
        memory=[write],
        events=[event],
        ordered=[write, event],
    )


def ordinary_indirect_call(
    identifier: str = "ordinary",
    rva: int = 0x1350,
) -> dict[str, object]:
    esp4 = sub(reg("esp"), const(4))
    esp8 = sub(esp4, const(4))
    writes = [
        {"kind": "write", "width": 4, "address": esp4, "value": const(1)},
        {"kind": "write", "width": 4, "address": esp8, "value": const(2)},
    ]
    event = {
        "kind": "indirect_call",
        "return_rva": rva + 1,
        "target": reg("edi"),
        "register_inputs": {name: reg(name) for name in REGISTERS},
    }
    event["register_inputs"]["esp"] = esp8
    return unit(
        identifier,
        rva,
        memory=writes,
        events=[event],
        ordered=[*writes, event],
    )


def edge(source: str, target: str) -> dict[str, object]:
    return {"source_unit_id": source, "target_unit_id": target}


class InterfaceProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        path = Path(self.temporary.name) / "profile.json"
        path.write_text(json.dumps({
            "format": EXTERNAL_INTERFACE_PROFILE_FORMAT,
            "id": "fixture",
            "model": "x86-pe32",
            "status": "complete",
            "provenance": {"kind": "fixture"},
            "factories": [{
                "id": "factory",
                "import": {"dll": "example.dll", "symbol": "CreateThing"},
                "declaration": "CreateThing",
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 2,
                "out_interfaces": [{
                    "argument_index": 1,
                    "interface_id": "IThing",
                    "write_width": 4,
                }],
                "caller_memory_frame": {
                    "status": "complete",
                    "model": "pe32-declared-pointer-arguments-v1",
                    "arguments": [{
                        "argument_index": 1,
                        "role": "caller_memory",
                        "access": "read_write",
                        "extent": "fixed_word",
                        "retention": "during_call",
                    }],
                    "assumptions": [
                        "caller memory is accessed only through declared pointer arguments",
                        "non-callback pointer arguments are retained only during the call",
                        "opaque interface resources are disjoint from caller image and stack memory",
                    ],
                },
            }],
            "interfaces": [{
                "id": "IThing",
                "vtable": "IThingVtbl",
                "methods": [
                    {
                        "name": "Release",
                        "slot": 0,
                        "offset": 0,
                        "abi_template": "pe32-stdcall-v1",
                        "argument_words": 1,
                        "out_interfaces": [],
                        "caller_memory_frame": {
                            "status": "complete",
                            "model": "pe32-declared-pointer-arguments-v1",
                            "arguments": [{
                                "argument_index": 0,
                                "role": "interface_resource",
                                "access": "read_write",
                                "extent": "opaque_resource",
                                "retention": "during_call",
                            }],
                            "assumptions": [
                                "caller memory is accessed only through declared pointer arguments",
                                "non-callback pointer arguments are retained only during the call",
                                "opaque interface resources are disjoint from caller image and stack memory",
                            ],
                        },
                    },
                    {
                        "name": "CreateChild",
                        "slot": 1,
                        "offset": 4,
                        "abi_template": "pe32-stdcall-v1",
                        "argument_words": 2,
                        "out_interfaces": [{
                            "argument_index": 1,
                            "interface_id": "IThing",
                            "write_width": 4,
                        }],
                        "caller_memory_frame": {
                            "status": "complete",
                            "model": "pe32-declared-pointer-arguments-v1",
                            "arguments": [
                                {
                                    "argument_index": 0,
                                    "role": "interface_resource",
                                    "access": "read_write",
                                    "extent": "opaque_resource",
                                    "retention": "during_call",
                                },
                                {
                                    "argument_index": 1,
                                    "role": "caller_memory",
                                    "access": "read_write",
                                    "extent": "fixed_word",
                                    "retention": "during_call",
                                },
                            ],
                            "assumptions": [
                                "caller memory is accessed only through declared pointer arguments",
                                "non-callback pointer arguments are retained only during the call",
                                "opaque interface resources are disjoint from caller image and stack memory",
                            ],
                        },
                    },
                ],
            }],
        }), encoding="utf-8")
        self.profile: ExternalInterfaceProfile = load_external_interface_profile(path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_factory_object_vtable_and_method_resolve(self) -> None:
        units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{"register": "eax", "value": load(const(SLOT))}]),
            unit("vtable", 0x1300, writes=[{"register": "ecx", "value": load(reg("eax"))}]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [edge("factory", "object"), edge("object", "vtable"), edge("vtable", "call")],
            roots=["factory"],
        )

        self.assertEqual(result["format"], INTERFACE_PROVENANCE_FORMAT)
        self.assertGreater(
            result["counts"]["transfer_requests"],
            result["counts"]["transfer_evaluations"],
        )
        self.assertEqual(
            result["counts"]["transfer_cache_hits"],
            result["counts"]["transfer_requests"]
            - result["counts"]["transfer_evaluations"],
        )
        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered")
        protocol = resolution["external_targets"][0]["external_protocol"]
        self.assertEqual((protocol["interface_id"], protocol["method"]), ("IThing", "Release"))
        self.assertEqual(result["counts"]["static_interface_slots"], 1)

    def test_receiver_only_method_preserves_factory_interface_slot(self) -> None:
        units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{
                "register": "eax", "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            indirect_call("release", 0x1400),
            unit("object-again", 0x1500, writes=[{
                "register": "eax", "value": load(const(SLOT)),
            }]),
            unit("vtable-again", 0x1600, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "object"),
                edge("object", "vtable"),
                edge("vtable", "release"),
                edge("release", "object-again"),
                edge("object-again", "vtable-again"),
                edge("vtable-again", "call"),
            ],
            roots=["factory"],
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered", result)
        self.assertEqual(result["counts"]["static_interface_slots"], 1)

    def test_factory_object_survives_equal_symbolic_indexed_location(self) -> None:
        factory = factory_unit()
        indexed_slot = add(const(SLOT), mul(reg("ebx"), const(4)))
        factory["semantics"]["memory_events"][0]["value"] = indexed_slot
        factory["semantics"]["ordered_events"][0]["value"] = indexed_slot
        units = [
            factory,
            unit("object", 0x1200, writes=[{
                "register": "eax",
                "value": load(indexed_slot),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "object"),
                edge("object", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["factory"],
        )

        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered", resolution)
        protocol = resolution["external_targets"][0]["external_protocol"]
        self.assertEqual(
            (protocol["interface_id"], protocol["method"]),
            ("IThing", "Release"),
        )
        self.assertEqual(result["counts"]["static_interface_slots"], 0)

    def test_factory_type_recovery_requires_only_out_pointer_origin(self) -> None:
        factory = factory_unit()
        ordered = factory["semantics"]["ordered_events"]
        ordered[1]["value"] = reg("ebx")
        factory["semantics"]["memory_events"][1]["value"] = reg("ebx")
        units = [
            factory,
            unit("object", 0x1200, writes=[{
                "register": "eax", "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [edge("factory", "object"), edge("object", "vtable"), edge("vtable", "call")],
            roots=["factory"],
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")
        self.assertEqual(result["counts"]["static_interface_slots"], 1)
        self.assertNotIn(
            "interface_factory_arguments_incomplete",
            {issue["code"] for issue in result["issues"]},
        )

    def test_factory_effect_crosses_internal_call_via_stable_slot_fact(self) -> None:
        root_call = {
            "kind": "internal_call",
            "target_rva": 0x1100,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        units = [
            unit("root", 0x1000, events=[root_call], ordered=[root_call]),
            factory_unit(),
            unit("object", 0x1200, writes=[{"register": "eax", "value": load(const(SLOT))}]),
            unit("vtable", 0x1300, writes=[{"register": "ecx", "value": load(reg("eax"))}]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [edge("root", "object"), edge("object", "vtable"), edge("vtable", "call")],
            roots=["root"],
            internal_edges=[{
                "source_unit_id": "root",
                "source_event_index": 0,
                "target_unit_id": "factory",
            }],
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")
        self.assertGreaterEqual(result["fixed_point"]["rounds"], 2)

    def test_checked_memory_result_crosses_internal_call_without_slot_promotion(
        self,
    ) -> None:
        root_call = {
            "kind": "internal_call",
            "target_rva": 0x1100,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        units = [
            unit("root", 0x1000, events=[root_call], ordered=[root_call]),
            factory_unit(),
            unit(
                "object",
                0x1200,
                writes=[{"register": "eax", "value": load(const(SLOT))}],
            ),
            unit(
                "vtable",
                0x1300,
                writes=[{"register": "ecx", "value": load(reg("eax"))}],
            ),
            indirect_call(),
        ]
        interface_value = frozenset({
            ValueOrigin(
                "interface_object",
                (self.profile.sha256, "IThing"),
            )
        })

        result = self._run(
            units,
            [
                edge("root", "object"),
                edge("object", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["root"],
            internal_edges=[{
                "source_unit_id": "root",
                "source_event_index": 0,
                "target_unit_id": "factory",
            }],
            internal_call_memory_result_relations={
                IMAGE_BASE + 0x1100: {
                    ValueOrigin("exact", (SLOT,)): interface_value,
                }
            },
            allow_global_slot_promotion=False,
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered", result)
        self.assertEqual(
            result["resolutions"][0]["analysis_dependencies"],
            ['call-frame:["root",0,"factory"]'],
        )

    def test_internal_summary_instantiates_input_relative_interface_result(self) -> None:
        call = {
            "kind": "internal_call",
            "target_rva": 0x1180,
            "return_rva": 0x1201,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        units = [
            factory_unit(),
            unit(
                "object",
                0x1200,
                writes=[{"register": "ecx", "value": load(const(SLOT))}],
            ),
            unit("wrapper-call", 0x1201, events=[call], ordered=[call]),
            unit("wrapper", 0x1180),
            unit(
                "vtable",
                0x1300,
                writes=[{"register": "ecx", "value": load(reg("eax"))}],
            ),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "object"),
                edge("object", "wrapper-call"),
                edge("wrapper-call", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["factory"],
            internal_edges=[{
                "source_unit_id": "wrapper-call",
                "source_event_index": 0,
                "target_unit_id": "wrapper",
            }],
            internal_call_result_relations={
                IMAGE_BASE + 0x1180: {
                    "eax": [{"kind": "input_register", "register": "ecx"}],
                },
            },
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered", result)

    def test_unframed_internal_call_invalidates_mutable_slot_fact(self) -> None:
        write_slot = {
            "kind": "write",
            "width": 4,
            "address": const(SLOT),
            "value": const(IMAGE_BASE + 0x2000),
        }
        call = {
            "kind": "internal_call",
            "target_rva": 0x1800,
            "return_rva": 0x1101,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        units = [
            unit("write", 0x1000, memory=[write_slot], ordered=[write_slot]),
            unit("invoke", 0x1100, events=[call], ordered=[call]),
            unit(
                "load",
                0x1200,
                writes=[{"register": "eax", "value": load(const(SLOT))}],
            ),
            unit(
                "dispatch",
                0x1300,
                events=[{
                    "kind": "indirect_call",
                    "return_rva": 0x1301,
                    "target": reg("eax"),
                    "register_inputs": {name: reg(name) for name in REGISTERS},
                }],
                ordered=[{
                    "kind": "indirect_call",
                    "return_rva": 0x1301,
                    "target": reg("eax"),
                    "register_inputs": {name: reg(name) for name in REGISTERS},
                }],
            ),
            unit("callee", 0x1800),
            unit("target", 0x2000),
        ]
        direct = [
            edge("write", "invoke"),
            edge("invoke", "load"),
            edge("load", "dispatch"),
        ]
        internal = [{
            "source_unit_id": "invoke",
            "source_event_index": 0,
            "target_unit_id": "callee",
        }]
        indirect_exits = [{
            "id": "exit:dispatch",
            "source_unit_id": "dispatch",
            "source_rva": 0x1300,
            "source_event_index": 0,
            "kind": "indirect_call",
            "target_expression": reg("eax"),
        }]
        common = {
            "roots": ["write"],
            "internal_edges": internal,
            "indirect_exits": indirect_exits,
            "internal_call_preserved_registers": {
                IMAGE_BASE + 0x1800: frozenset({"ebp", "ebx", "edi", "esi"})
            },
            "allow_global_slot_promotion": False,
        }

        unsafe = self._run(units, direct, **common)
        framed = self._run(
            units,
            direct,
            internal_call_memory_preservation={IMAGE_BASE + 0x1800: True},
            **common,
        )

        self.assertEqual(unsafe["resolutions"][0]["status"], "incomplete")
        self.assertEqual(framed["resolutions"][0]["status"], "recovered")
        self.assertEqual(
            framed["resolutions"][0]["target_unit_ids"], ["target"]
        )
        self.assertEqual(
            framed["resolutions"][0]["analysis_dependencies"],
            ['call-frame:["invoke",0,"callee"]'],
        )

    def test_checked_slot_seed_reuses_the_prior_fixed_point(self) -> None:
        units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{
                "register": "eax", "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        direct = [
            edge("factory", "object"),
            edge("object", "vtable"),
            edge("vtable", "call"),
        ]
        seed: dict[object, object] = {}
        cold = self._run(
            units,
            direct,
            roots=["factory"],
            recovered_known_slots=seed,
        )
        warm = self._run(
            units,
            direct,
            roots=["factory"],
            initial_known_slots=seed,
        )

        self.assertGreaterEqual(cold["fixed_point"]["rounds"], 2)
        self.assertEqual(warm["fixed_point"]["rounds"], 1)
        self.assertEqual(
            warm["fixed_point"]["initial_known_slots"], len(seed)
        )
        self.assertEqual(warm["resolutions"], cold["resolutions"])
        self.assertEqual(
            warm["static_interface_slots"], cold["static_interface_slots"]
        )

    def test_global_slot_authority_seed_does_not_cross_unknown_call_effect(self) -> None:
        dependency = "hybrid-authority-v2:global_slot_invariant:" + "a" * 64
        call = {
            "kind": "internal_call",
            "target_rva": 0x1180,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        units = [
            unit("caller", 0x1100, events=[call], ordered=[call]),
            unit("helper", 0x1180),
            unit("dispatch", 0x1200),
            unit("target", 0x1800),
        ]
        exit_row = {
            "id": "exit:dispatch",
            "source_unit_id": "dispatch",
            "source_rva": 0x1200,
            "source_event_index": 0,
            "kind": "indirect_call",
            "target_expression": load(const(SLOT)),
        }
        seed = {
            SLOT: frozenset({
                ValueOrigin("exact", (IMAGE_BASE + 0x1800,), (dependency,))
            })
        }

        result = self._run(
            units,
            [edge("caller", "dispatch")],
            roots=["caller"],
            internal_edges=[{
                "source_unit_id": "caller",
                "source_event_index": 0,
                "target_unit_id": "helper",
            }],
            indirect_exits=[exit_row],
            initial_known_slots=seed,
            allow_global_slot_promotion=False,
        )

        self.assertEqual(result["resolutions"][0]["status"], "incomplete")
        self.assertEqual(
            result["resolutions"][0]["failure"]["code"],
            "static_slot_target_origin_missing",
        )

    def test_dynamic_allocator_result_carries_interface_field_provenance(self) -> None:
        allocator = {
            "kind": "internal_call",
            "target_rva": 0x1180,
            "return_rva": 0x1101,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        allocate = unit("allocate", 0x1100, events=[allocator], ordered=[allocator])
        esp4 = sub(reg("esp"), const(4))
        esp8 = sub(esp4, const(4))
        factory_call = {
            "kind": "external_call",
            "dll": "example.dll",
            "symbol": "CreateThing",
            "return_rva": 0x1201,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        factory_call["register_inputs"]["esp"] = esp8
        factory_call["register_inputs"]["esi"] = reg("eax")
        factory_writes = [
            {"kind": "write", "width": 4, "address": esp4, "value": reg("eax")},
            {"kind": "write", "width": 4, "address": esp8, "value": const(0)},
        ]
        factory = unit(
            "factory-dynamic",
            0x1200,
            memory=factory_writes,
            events=[factory_call],
            ordered=[*factory_writes, factory_call],
        )
        units = [
            allocate,
            unit("allocator-body", 0x1180),
            unit("store-pointer", 0x1190, memory=[{
                "kind": "write",
                "width": 4,
                "address": const(SLOT),
                "value": reg("eax"),
            }]),
            factory,
            unit("object-pointer", 0x1290, writes=[{
                "register": "eax", "value": load(const(SLOT)),
            }]),
            unit("object", 0x1300, writes=[{
                "register": "eax", "value": load(reg("eax")),
            }]),
            unit("vtable", 0x1310, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            indirect_call(rva=0x1320),
        ]
        result = self._run(
            units,
            [
                edge("allocate", "store-pointer"),
                edge("store-pointer", "factory-dynamic"),
                edge("object-pointer", "object"),
                edge("object", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["allocate", "object-pointer"],
            internal_edges=[{
                "source_unit_id": "allocate",
                "source_event_index": 0,
                "target_unit_id": "allocator-body",
            }],
            internal_call_result_relations={
                IMAGE_BASE + 0x1180: {
                    "eax": [{
                        "kind": "external_result",
                        "producer_unit_id": "heap-allocator",
                        "event_index": 0,
                        "import": {"dll": "kernel32.dll", "symbol": "HeapAlloc"},
                        "relation": "dynamic_range_base",
                        "nullable": False,
                    }],
                },
            },
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")
        self.assertGreaterEqual(result["fixed_point"]["rounds"], 2)
        self.assertEqual(result["counts"]["static_value_slots"], 1)
        self.assertEqual(result["counts"]["dynamic_value_slots"], 1)
        self.assertEqual(
            result["dynamic_interface_slots"][0]["origins"][0]["kind"],
            "interface_object",
        )

    def test_internal_call_frame_carries_typed_argument_into_callee(self) -> None:
        helper_slot = SLOT + 8
        pushed_object = sub(reg("esp"), const(4))
        pushed_kind = sub(pushed_object, const(4))
        call = {
            "kind": "internal_call",
            "target_rva": 0x1180,
            "return_rva": 0x1171,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        call["register_inputs"]["esp"] = pushed_kind
        prepare_writes = [
            {
                "kind": "write",
                "width": 4,
                "address": pushed_object,
                "value": load(const(SLOT)),
            },
            {
                "kind": "write",
                "width": 4,
                "address": pushed_kind,
                "value": const(0),
            },
        ]
        prepare = unit(
            "prepare-helper",
            0x1170,
            memory=prepare_writes,
            events=[call],
            ordered=[*prepare_writes, call],
        )
        helper_entry = unit(
            "helper-entry",
            0x1180,
            writes=[{
                "register": "esi",
                "value": load(add(reg("esp"), const(8))),
            }],
        )
        helper_store = unit(
            "helper-store",
            0x1181,
            memory=[{
                "kind": "write",
                "width": 4,
                "address": const(helper_slot),
                "value": reg("esi"),
            }],
        )
        units = [
            factory_unit(),
            prepare,
            helper_entry,
            helper_store,
            unit("object", 0x1200, writes=[{
                "register": "eax", "value": load(const(helper_slot)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "prepare-helper"),
                edge("helper-entry", "helper-store"),
                edge("prepare-helper", "object"),
                edge("object", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["factory"],
            internal_edges=[{
                "source_unit_id": "prepare-helper",
                "source_event_index": 0,
                "target_unit_id": "helper-entry",
            }],
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")
        slot = next(
            row for row in result["static_interface_slots"]
            if row["address"] == helper_slot
        )
        self.assertEqual(slot["origins"][0]["kind"], "interface_object")

    def test_plain_ret_cleanup_survives_nested_internal_summary_gap(self) -> None:
        call = {
            "kind": "internal_call",
            "target_rva": 0x1180,
            "return_rva": 0x1171,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        caller = unit("caller", 0x1170, events=[call], ordered=[call])
        helper = unit("helper", 0x1180)
        helper["semantics"]["outcome"] = {
            "kind": "return",
            "value": load(reg("esp")),
        }
        helper["instructions"] = [{
            "mnemonic": "ret",
            "operands": [],
        }]
        units = [
            factory_unit(),
            caller,
            helper,
            unit("object", 0x1200, writes=[{
                "register": "eax", "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "caller"),
                edge("caller", "object"),
                edge("object", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["factory"],
            internal_edges=[{
                "source_unit_id": "caller",
                "source_event_index": 0,
                "target_unit_id": "helper",
            }],
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")
        evidence = next(
            row for row in result["internal_call_cleanup_inference"]
            if row["target_unit_id"] == "helper"
        )
        self.assertEqual(evidence["status"], "complete")
        self.assertEqual(evidence["cleanup_bytes"], 0)

    def test_conflicting_return_immediates_do_not_infer_cleanup(self) -> None:
        call = {
            "kind": "internal_call",
            "target_rva": 0x1180,
            "return_rva": 0x1171,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        caller = unit("caller", 0x1170, events=[call], ordered=[call])
        helper = unit("helper", 0x1180)
        left = unit("return-left", 0x1181)
        left["semantics"]["outcome"] = {
            "kind": "return",
            "value": load(reg("esp")),
        }
        left["instructions"] = [{"mnemonic": "ret", "operands": []}]
        right = unit("return-right", 0x1182)
        right["semantics"]["outcome"] = {
            "kind": "return",
            "value": load(reg("esp")),
        }
        right["instructions"] = [{
            "mnemonic": "ret",
            "operands": [{"kind": "immediate", "value": 4}],
        }]
        result = self._run(
            [caller, helper, left, right, indirect_call()],
            [
                edge("caller", "call"),
                edge("helper", "return-left"),
                edge("helper", "return-right"),
            ],
            roots=["caller"],
            internal_edges=[{
                "source_unit_id": "caller",
                "source_event_index": 0,
                "target_unit_id": "helper",
            }],
        )

        evidence = next(
            row for row in result["internal_call_cleanup_inference"]
            if row["target_unit_id"] == "helper"
        )
        self.assertEqual(evidence["status"], "incomplete")
        self.assertEqual(
            evidence["failure"]["code"],
            "internal_call_return_cleanup_ambiguous",
        )

    def test_dominating_profile_write_reestablishes_static_slot_fact(self) -> None:
        units = [
            factory_unit("initial-factory", 0x1100),
            unit(
                "unknown-write",
                0x1150,
                memory=[{
                    "kind": "write",
                    "width": 4,
                    "address": const(SLOT),
                    "value": reg("edx"),
                }],
            ),
            factory_unit("overwriting-factory", 0x1160),
            unit("object", 0x1200, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("initial-factory", "unknown-write"),
                edge("unknown-write", "overwriting-factory"),
                edge("overwriting-factory", "object"),
                edge("object", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["initial-factory"],
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")
        self.assertEqual(result["counts"]["static_interface_slots"], 0)
        self.assertEqual(result["counts"]["tainted_static_slots"], 1)
        self.assertEqual(
            result["rejected_tainted_slots"],
            [{"kind": "static", "address": SLOT}],
        )

    def test_unknown_exact_write_poisons_only_downstream_loads(self) -> None:
        units = [
            factory_unit(),
            unit("before-object", 0x1120, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("before-vtable", 0x1130, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            indirect_call("before-call", 0x1140),
            unit(
                "unknown-write",
                0x1150,
                memory=[{
                    "kind": "write",
                    "width": 4,
                    "address": const(SLOT),
                    "value": reg("edx"),
                }],
            ),
            unit("object", 0x1200, writes=[{"register": "eax", "value": load(const(SLOT))}]),
            unit("vtable", 0x1300, writes=[{"register": "ecx", "value": load(reg("eax"))}]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "before-object"),
                edge("before-object", "before-vtable"),
                edge("before-vtable", "before-call"),
                edge("before-call", "unknown-write"),
                edge("unknown-write", "object"),
                edge("object", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["factory"],
            indirect_exits=[
                {
                    "id": "exit:before-call",
                    "source_unit_id": "before-call",
                    "source_rva": 0x1140,
                    "source_event_index": 0,
                    "kind": "indirect_call",
                    "target_expression": load(reg("ecx")),
                },
                {
                    "id": "exit:call",
                    "source_unit_id": "call",
                    "source_rva": 0x1400,
                    "source_event_index": 0,
                    "kind": "indirect_call",
                    "target_expression": load(reg("ecx")),
                },
            ],
        )

        resolutions = {row["id"]: row for row in result["resolutions"]}
        self.assertEqual(resolutions["exit:before-call"]["status"], "recovered")
        self.assertEqual(resolutions["exit:call"]["status"], "incomplete")
        self.assertEqual(result["counts"]["static_interface_slots"], 0)
        self.assertEqual(result["counts"]["tainted_static_slots"], 1)
        self.assertEqual(
            result["rejected_tainted_slots"],
            [{"kind": "static", "address": SLOT}],
        )

    def test_symbolic_write_may_alias_and_invalidates_static_slot(self) -> None:
        units = [
            factory_unit(),
            unit(
                "symbolic-write",
                0x1150,
                memory=[{
                    "kind": "write",
                    "width": 4,
                    "address": add(const(SLOT), mul(reg("ebx"), const(4))),
                    "value": const(0),
                }],
            ),
            unit("object", 0x1200, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "symbolic-write"),
                edge("symbolic-write", "object"),
                edge("object", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["factory"],
        )

        self.assertEqual(result["resolutions"][0]["status"], "incomplete")
        self.assertEqual(
            result["rejected_tainted_slots"],
            [{"kind": "static", "address": SLOT}],
        )

    def test_finite_nullable_static_slot_join_survives_nonnull_guard(self) -> None:
        null_write = {
            "kind": "write",
            "width": 4,
            "address": const(SLOT),
            "value": const(0),
        }
        units = [
            unit("root", 0x1000),
            factory_unit(),
            unit("null", 0x1150, memory=[null_write]),
            unit("object", 0x1200, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        nonnull = {
            "op": "ne32",
            "args": [reg("eax"), const(0)],
        }
        result = self._run(
            units,
            [
                edge("root", "factory"),
                edge("root", "null"),
                edge("factory", "object"),
                edge("null", "object"),
                {
                    "source_unit_id": "object",
                    "target_unit_id": "vtable",
                    "guard": nonnull,
                },
                edge("vtable", "call"),
            ],
            roots=["root"],
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")
        self.assertEqual(
            {
                origin["kind"]
                for origin in result["static_interface_slots"][0]["origins"]
            },
            {"exact", "interface_object"},
        )

    def test_unprofiled_method_slot_is_incomplete(self) -> None:
        call = indirect_call()
        call["semantics"]["external_events"][0]["target"] = load(add(reg("ecx"), const(8)))
        units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{"register": "eax", "value": load(const(SLOT))}]),
            unit("vtable", 0x1300, writes=[{"register": "ecx", "value": load(reg("eax"))}]),
            call,
        ]
        result = self._run(
            units,
            [edge("factory", "object"), edge("object", "vtable"), edge("vtable", "call")],
            roots=["factory"],
        )

        self.assertEqual(result["resolutions"][0]["status"], "incomplete")

    def test_method_arguments_cross_direct_unit_boundaries(self) -> None:
        prepare_write = {
            "kind": "write",
            "width": 4,
            "address": sub(reg("esp"), const(4)),
            "value": const(CHILD_SLOT),
            "instruction_rva": 0x1370,
        }
        units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            unit(
                "prepare",
                0x1370,
                writes=[{
                    "register": "esp",
                    "value": sub(reg("esp"), const(4)),
                }],
                memory=[prepare_write],
                ordered=[prepare_write],
            ),
            create_child_call(),
            unit("child", 0x1390, writes=[{
                "register": "eax",
                "value": load(const(CHILD_SLOT)),
            }]),
            unit("child-vtable", 0x13A0, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "object"),
                edge("object", "vtable"),
                edge("vtable", "prepare"),
                edge("prepare", "create"),
                edge("create", "child"),
                edge("child", "child-vtable"),
                edge("child-vtable", "call"),
            ],
            roots=["factory"],
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")
        recovery = next(
            row
            for row in result["call_argument_recoveries"]
            if row.get("method") == "CreateChild"
        )
        self.assertEqual(recovery["status"], "complete")
        witnesses = {
            witness["unit_id"]
            for argument in recovery["arguments"]
            for witness in argument["writes"]
        }
        self.assertEqual(witnesses, {"prepare", "create"})

    def test_recovered_method_replays_out_interface_effects(self) -> None:
        prepare_write = {
            "kind": "write",
            "width": 4,
            "address": sub(reg("esp"), const(4)),
            "value": const(CHILD_SLOT),
            "instruction_rva": 0x1370,
        }

        def graph(create: dict[str, object]) -> tuple[
            list[dict[str, object]], list[dict[str, object]]
        ]:
            units = [
                factory_unit(),
                unit("object", 0x1200, writes=[{
                    "register": "eax",
                    "value": load(const(SLOT)),
                }]),
                unit("vtable", 0x1300, writes=[{
                    "register": "ecx",
                    "value": load(reg("eax")),
                }]),
                unit(
                    "prepare",
                    0x1370,
                    writes=[{
                        "register": "esp",
                        "value": sub(reg("esp"), const(4)),
                    }],
                    memory=[prepare_write],
                    ordered=[prepare_write],
                ),
                create,
                unit("child", 0x1390, writes=[{
                    "register": "eax",
                    "value": load(const(CHILD_SLOT)),
                }]),
                unit("child-vtable", 0x13A0, writes=[{
                    "register": "ecx",
                    "value": load(reg("eax")),
                }]),
                indirect_call(),
            ]
            direct = [
                edge("factory", "object"),
                edge("object", "vtable"),
                edge("vtable", "prepare"),
                edge("prepare", "create"),
                edge("create", "child"),
                edge("child", "child-vtable"),
                edge("child-vtable", "call"),
            ]
            return units, direct

        exits = [
            {
                "id": "exit:create",
                "source_unit_id": "create",
                "source_rva": 0x1380,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": load(add(reg("ecx"), const(4))),
            },
            {
                "id": "exit:call",
                "source_unit_id": "call",
                "source_rva": 0x1400,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": load(reg("ecx")),
            },
        ]
        warm_units, direct = graph(create_child_call())
        warm = self._run(
            warm_units,
            direct,
            roots=["factory"],
            indirect_exits=exits,
            allow_global_slot_promotion=False,
        )
        create_target = next(
            row for row in warm["resolutions"] if row["id"] == "exit:create"
        )["external_targets"][0]

        recovered_create = create_child_call()
        unresolved_target = reg("edx")
        recovered_create["semantics"]["external_events"][0]["target"] = (
            unresolved_target
        )
        recovered_create["semantics"]["ordered_events"][-1]["target"] = (
            unresolved_target
        )
        cold_units, direct = graph(recovered_create)
        cold = self._run(
            cold_units,
            direct,
            roots=["factory"],
            recovered_indirect_edges=[{
                "id": "exit:create",
                "kind": "indirect_call",
                "status": "recovered",
                "source_unit_id": "create",
                "source_event_index": 0,
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [create_target],
            }],
            indirect_exits=exits,
            allow_global_slot_promotion=False,
        )

        child_call = next(
            row for row in cold["resolutions"] if row["id"] == "exit:call"
        )
        self.assertEqual(child_call["status"], "recovered", cold)
        recovered_contract = next(
            row
            for row in cold["call_argument_recoveries"]
            if row.get("method") == "CreateChild"
        )
        self.assertEqual(
            recovered_contract["target_source"],
            "recovered_indirect_exit",
        )

    def test_recovered_method_preserves_disjoint_interface_slot(self) -> None:
        warm_units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            indirect_call("release", 0x1350),
        ]
        warm = self._run(
            warm_units,
            [
                edge("factory", "object"),
                edge("object", "vtable"),
                edge("vtable", "release"),
            ],
            roots=["factory"],
            indirect_exits=[{
                "id": "exit:release",
                "source_unit_id": "release",
                "source_rva": 0x1350,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": load(reg("ecx")),
            }],
            allow_global_slot_promotion=False,
        )
        release_target = warm["resolutions"][0]["external_targets"][0]

        release = indirect_call("release", 0x1350)
        release["semantics"]["external_events"][0]["target"] = reg("edx")
        release["semantics"]["ordered_events"][0]["target"] = reg("edx")
        units = [
            factory_unit(),
            release,
            unit("object-again", 0x1500, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("vtable-again", 0x1600, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "release"),
                edge("release", "object-again"),
                edge("object-again", "vtable-again"),
                edge("vtable-again", "call"),
            ],
            roots=["factory"],
            recovered_indirect_edges=[{
                "id": "exit:release",
                "kind": "indirect_call",
                "status": "recovered",
                "source_unit_id": "release",
                "source_event_index": 0,
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [release_target],
            }],
            allow_global_slot_promotion=False,
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered", result)

    def test_conflicting_predecessor_arguments_remain_finite(self) -> None:
        def prepare(identifier: str, address: int) -> dict[str, object]:
            write = {
                "kind": "write",
                "width": 4,
                "address": sub(reg("esp"), const(4)),
                "value": const(address),
            }
            return unit(
                identifier,
                0x1370,
                writes=[{
                    "register": "esp",
                    "value": sub(reg("esp"), const(4)),
                }],
                memory=[write],
                ordered=[write],
            )

        units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            prepare("left", CHILD_SLOT),
            prepare("right", CHILD_SLOT + 4),
            create_child_call(),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "object"),
                edge("object", "vtable"),
                edge("vtable", "left"),
                edge("vtable", "right"),
                edge("left", "create"),
                edge("right", "create"),
                edge("create", "call"),
            ],
            roots=["factory"],
        )

        recovery = next(
            row
            for row in result["call_argument_recoveries"]
            if row.get("method") == "CreateChild"
        )
        self.assertEqual(recovery["status"], "complete")
        self.assertEqual(len(recovery["arguments"][1]["origins"]), 2)
        self.assertIn(
            "interface_out_pointer_unresolved",
            {issue["code"] for issue in result["issues"]},
        )

    def test_unknown_esp_mutation_blocks_predecessor_arguments(self) -> None:
        units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            unit("unknown-esp", 0x1370, writes=[{
                "register": "esp",
                "value": reg("edx"),
            }]),
            create_child_call(),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "object"),
                edge("object", "vtable"),
                edge("vtable", "unknown-esp"),
                edge("unknown-esp", "create"),
                edge("create", "call"),
            ],
            roots=["factory"],
        )

        recovery = next(
            row
            for row in result["call_argument_recoveries"]
            if row.get("method") == "CreateChild"
        )
        self.assertEqual(recovery["status"], "incomplete")
        self.assertEqual(recovery["failure"]["code"], "call_esp_origin_unresolved")

    def test_checked_stack_entry_restores_predecessor_out_pointer(self) -> None:
        prepare_write = {
            "kind": "write",
            "width": 4,
            "address": sub(reg("esp"), const(4)),
            "value": const(CHILD_SLOT),
        }
        prepare = unit(
            "prepare",
            0x1378,
            writes=[{
                "register": "esp",
                "value": sub(reg("esp"), const(4)),
            }],
            memory=[prepare_write],
            ordered=[prepare_write],
        )
        units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            unit("unknown-esp", 0x1370, writes=[{
                "register": "esp",
                "value": reg("edx"),
            }]),
            prepare,
            create_child_call(),
            indirect_call(),
        ]
        direct = [
            edge("factory", "object"),
            edge("object", "vtable"),
            edge("vtable", "unknown-esp"),
            edge("unknown-esp", "prepare"),
            edge("prepare", "create"),
            edge("create", "call"),
        ]

        incomplete = self._run(units, direct, roots=["factory"])
        complete = self._run(
            units,
            direct,
            roots=["factory"],
            checked_stack_entry_offsets={
                "prepare": [0],
                "create": [-4],
            },
        )

        incomplete_recovery = next(
            row
            for row in incomplete["call_argument_recoveries"]
            if row.get("method") == "CreateChild"
        )
        complete_recovery = next(
            row
            for row in complete["call_argument_recoveries"]
            if row.get("method") == "CreateChild"
        )
        self.assertEqual(incomplete_recovery["status"], "incomplete")
        self.assertEqual(complete_recovery["status"], "complete")
        self.assertEqual(
            complete_recovery["arguments"][1]["origins"],
            [{"kind": "exact", "key": [CHILD_SLOT]}],
        )

    def test_recovered_import_preserves_interface_and_stack_origins(self) -> None:
        show_window = MachineImportIdentity(
            "user32.dll", "symbol", "ShowWindow"
        )
        selected = self._selected_abi(show_window, argument_words=2)
        units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("save", 0x1210, writes=[{
                "register": "esi",
                "value": reg("eax"),
            }]),
            ordinary_indirect_call(),
            unit("restore", 0x1360, writes=[{
                "register": "eax",
                "value": reg("esi"),
            }]),
            unit("vtable", 0x1370, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            unit(
                "prepare",
                0x1380,
                writes=[{
                    "register": "esp",
                    "value": sub(reg("esp"), const(4)),
                }],
                memory=[{
                    "kind": "write",
                    "width": 4,
                    "address": sub(reg("esp"), const(4)),
                    "value": const(CHILD_SLOT),
                }],
            ),
            create_child_call(rva=0x1390),
            unit("child", 0x13A0, writes=[{
                "register": "eax",
                "value": load(const(CHILD_SLOT)),
            }]),
            unit("child-vtable", 0x13B0, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            indirect_call(),
        ]
        direct = [
            edge("factory", "object"),
            edge("object", "save"),
            edge("save", "ordinary"),
            edge("ordinary", "restore"),
            edge("restore", "vtable"),
            edge("vtable", "prepare"),
            edge("prepare", "create"),
            edge("create", "child"),
            edge("child", "child-vtable"),
            edge("child-vtable", "call"),
        ]
        result = self._run(
            units,
            direct,
            roots=["factory"],
            recovered_indirect_edges=[{
                "id": "exit:ordinary",
                "kind": "indirect_call",
                "status": "recovered",
                "source_unit_id": "ordinary",
                "source_event_index": 0,
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [selected.as_json()],
            }],
            extra_import_abis={show_window: selected},
        )

        recovery = next(
            row
            for row in result["call_argument_recoveries"]
            if row.get("method") == "CreateChild"
        )
        self.assertEqual(recovery["status"], "complete")
        self.assertEqual(result["resolutions"][0]["status"], "recovered")

    def test_hash_bound_direct_site_contract_qualifies_cached_import_target(self) -> None:
        iat = 0x450000
        identity = MachineImportIdentity("user32.dll", "symbol", "ShowWindow")
        abi = resolve_machine_call_abi("pe32-stdcall-v1")
        assert abi is not None
        observed_event = {
            "kind": "external_call",
            "dll": identity.dll,
            "symbol": identity.value,
            "ordinal": None,
            "return_rva": 0x1601,
            "register_inputs": {name: reg(name) for name in REGISTERS},
            "abi_contract": {
                "template": abi.template,
                "argument_words": 2,
                "profile_binding": {
                    "profile_id": "native-callthrough",
                    "profile_sha256": "a" * 64,
                    "entry_key": "machine_import_signatures",
                    "entry_index": 7,
                },
            },
        }
        target = reg("esi")
        call_event = {
            "kind": "indirect_call",
            "return_rva": 0x1401,
            "target": target,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        result = self._run(
            [
                unit("load-import", 0x1300, writes=[{
                    "register": "esi", "value": load(const(iat)),
                }]),
                unit("call", 0x1400, events=[call_event], ordered=[call_event]),
                unit(
                    "observed-direct-site",
                    0x1600,
                    events=[observed_event],
                    ordered=[observed_event],
                ),
            ],
            [edge("load-import", "call")],
            roots=["load-import"],
            imports=[{
                "dll": identity.dll,
                "symbol": identity.value,
                "ordinal": None,
                "thunk_rva": iat - IMAGE_BASE,
            }],
            indirect_exits=[{
                "id": "exit:call",
                "source_unit_id": "call",
                "source_rva": 0x1400,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": target,
            }],
        )

        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered", resolution)
        self.assertEqual(
            resolution["external_targets"][0]["profile_binding"],
            observed_event["abi_contract"]["profile_binding"],
        )

    def test_conflicting_hash_bound_site_contracts_fail_closed(self) -> None:
        identity = MachineImportIdentity("user32.dll", "symbol", "ShowWindow")
        abi = resolve_machine_call_abi("pe32-stdcall-v1")
        assert abi is not None

        def observed(identifier: str, words: int, index: int) -> dict[str, object]:
            event = {
                "kind": "external_call",
                "dll": identity.dll,
                "symbol": identity.value,
                "ordinal": None,
                "return_rva": 0x1601 + index,
                "register_inputs": {name: reg(name) for name in REGISTERS},
                "abi_contract": {
                    "template": abi.template,
                    "argument_words": words,
                    "profile_binding": {
                        "profile_id": "native-callthrough",
                        "profile_sha256": "a" * 64,
                        "entry_key": "machine_import_signatures",
                        "entry_index": index,
                    },
                },
            }
            return unit(identifier, 0x1600 + index, events=[event], ordered=[event])

        with self.assertRaisesRegex(ValueError, "conflicting hash-bound import ABI"):
            self._run(
                [observed("left", 1, 0), observed("right", 2, 1), indirect_call()],
                [],
                roots=["left"],
            )

    def test_conflicting_recovered_call_cleanup_fails_closed(self) -> None:
        show_window = MachineImportIdentity(
            "user32.dll", "symbol", "ShowWindow"
        )
        cdecl_call = MachineImportIdentity(
            "example.dll", "symbol", "CdeclCall"
        )
        stdcall = self._selected_abi(show_window, argument_words=2)
        cdecl = self._selected_abi(
            cdecl_call,
            argument_words=2,
            abi_template="pe32-cdecl-v1",
        )
        units = [
            factory_unit(),
            ordinary_indirect_call(),
            unit("object", 0x1360, writes=[{
                "register": "eax",
                "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1370, writes=[{
                "register": "ecx",
                "value": load(reg("eax")),
            }]),
            create_child_call(rva=0x1390),
            indirect_call(),
        ]
        result = self._run(
            units,
            [
                edge("factory", "ordinary"),
                edge("ordinary", "object"),
                edge("object", "vtable"),
                edge("vtable", "create"),
                edge("create", "call"),
            ],
            roots=["factory"],
            recovered_indirect_edges=[{
                "id": "exit:ordinary",
                "kind": "indirect_call",
                "status": "recovered",
                "source_unit_id": "ordinary",
                "source_event_index": 0,
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [stdcall.as_json(), cdecl.as_json()],
            }],
            extra_import_abis={show_window: stdcall, cdecl_call: cdecl},
        )

        recovery = next(
            row
            for row in result["call_argument_recoveries"]
            if row.get("method") == "CreateChild"
        )
        self.assertEqual(recovery["status"], "incomplete")
        self.assertEqual(recovery["failure"]["code"], "call_esp_origin_unresolved")

    def test_structured_callback_target_is_recovered_from_stack_pointee(self) -> None:
        identity = MachineImportIdentity(
            "user32.dll", "symbol", "RegisterClassA"
        )
        selected = self._selected_abi(identity, argument_words=1)
        call_esp = sub(reg("esp"), const(4))
        writes = [
            {
                "kind": "write",
                "width": 4,
                "address": add(reg("esp"), const(4)),
                "value": const(IMAGE_BASE + 0x1800),
                "instruction_rva": 0x1500,
            },
            {
                "kind": "write",
                "width": 4,
                "address": call_esp,
                "value": reg("esp"),
                "instruction_rva": 0x1501,
            },
        ]
        event = {
            "kind": "external_call",
            "return_rva": 0x1503,
            "dll": "user32.dll",
            "symbol": "RegisterClassA",
            "ordinal": None,
            "register_inputs": {name: reg(name) for name in REGISTERS},
            "abi_contract": {
                "template": "pe32-stdcall-v1",
                "argument_words": 1,
                "argument_base_offset": 0,
                "contract_id": "register-class-a",
                "world_effect": "callbackRegistration",
                "callback_source": {
                    "kind": "argument_pointee",
                    "argument": 0,
                    "offset": 4,
                },
                "callback_lifetime": (
                    "until_class_unregistered_or_process_exit"
                ),
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 4,
                    "stack_cleanup_bytes": 16,
                    "nullable": False,
                },
            },
        }
        event["register_inputs"]["esp"] = call_esp
        registration = unit(
            "registration",
            0x1500,
            memory=writes,
            events=[event],
            ordered=[*writes, {**event, "instruction_rva": 0x1502}],
        )
        result = self._run(
            [registration, unit("callback", 0x1800), indirect_call()],
            [edge("registration", "call")],
            roots=["registration"],
            extra_import_abis={identity: selected},
        )

        evidence = result["callback_registrations"][0]
        self.assertEqual(evidence["status"], "complete", evidence)
        self.assertEqual(evidence["instruction_rva"], 0x1502)
        self.assertEqual(evidence["target_rvas"], [0x1800])
        self.assertEqual(evidence["target_unit_ids"], ["callback"])
        self.assertEqual(evidence["source_locations"][0]["offset"], 4)
        self.assertEqual(
            evidence["source_locations"][0]["writes"][0]["unit_id"],
            "registration",
        )

        event_contract = event["abi_contract"]
        assert isinstance(event_contract, dict)
        event_contract["world_effect"] = "nativeCallthrough"
        event_contract["callback_effect"] = "explicit"
        native_result = self._run(
            [registration, unit("callback", 0x1800), indirect_call()],
            [edge("registration", "call")],
            roots=["registration"],
            extra_import_abis={identity: selected},
        )
        native_evidence = native_result["callback_registrations"][0]
        self.assertEqual(native_evidence["status"], "complete", native_evidence)
        self.assertEqual(native_evidence["target_unit_ids"], ["callback"])

    def test_interface_callback_method_requires_finite_argument_target(self) -> None:
        abi = resolve_machine_call_abi("pe32-stdcall-v1")
        assert abi is not None
        path = Path(self.temporary.name) / "callback-profile.json"
        path.write_text(json.dumps({
            "format": EXTERNAL_INTERFACE_PROFILE_FORMAT,
            "id": "callback-fixture",
            "model": "x86-pe32",
            "status": "complete",
            "provenance": {"kind": "fixture"},
            "factories": [{
                "id": "factory",
                "import": {"dll": "example.dll", "symbol": "CreateThing"},
                "declaration": "CreateThing",
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 2,
                "out_interfaces": [{
                    "argument_index": 1,
                    "interface_id": "IThing",
                    "write_width": 4,
                }],
            }],
            "interfaces": [{
                "id": "IThing",
                "vtable": "IThingVtbl",
                "methods": [{
                    "name": "Enumerate",
                    "slot": 0,
                    "offset": 0,
                    "abi_template": "pe32-stdcall-v1",
                    "machine_abi": abi.as_json(),
                    **same_library_callback_call_through_effect_json(
                        source={"kind": "argument_word", "argument": 1},
                        abi={
                            "kind": "generic_callback",
                            "argument_words": 2,
                            "stack_cleanup_bytes": 8,
                            "nullable": False,
                        },
                        lifetime="during_call",
                        status="complete",
                    ),
                    "argument_words": 2,
                    "out_interfaces": [],
                }],
            }],
        }), encoding="utf-8")
        self.profile = load_external_interface_profile(path)

        callback_address = IMAGE_BASE + 0x1800
        callback_slot = sub(reg("esp"), const(4))
        call_esp = sub(callback_slot, const(4))
        writes = [
            {
                "kind": "write",
                "width": 4,
                "address": callback_slot,
                "value": const(callback_address),
            },
            {
                "kind": "write",
                "width": 4,
                "address": call_esp,
                "value": const(SLOT),
            },
        ]
        call_event = {
            "kind": "indirect_call",
            "return_rva": 0x1401,
            "target": load(reg("ecx")),
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        call_event["register_inputs"]["esp"] = call_esp
        callback_call = unit(
            "call",
            0x1400,
            memory=writes,
            events=[call_event],
            ordered=[*writes, {**call_event, "instruction_rva": 0x1400}],
        )
        units = [
            factory_unit(),
            unit("object", 0x1200, writes=[{
                "register": "eax", "value": load(const(SLOT)),
            }]),
            unit("vtable", 0x1300, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            callback_call,
            unit("callback", 0x1800),
        ]
        result = self._run(
            units,
            [
                edge("factory", "object"),
                edge("object", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["factory"],
        )

        evidence = result["callback_registrations"][0]
        self.assertEqual(evidence["status"], "complete", evidence)
        self.assertEqual(evidence["target_rvas"], [0x1800])
        self.assertEqual(evidence["target_unit_ids"], ["callback"])

        writes[0]["value"] = reg("edx")
        unresolved = self._run(
            units,
            [
                edge("factory", "object"),
                edge("object", "vtable"),
                edge("vtable", "call"),
            ],
            roots=["factory"],
        )
        evidence = unresolved["callback_registrations"][0]
        self.assertEqual(evidence["status"], "incomplete")
        self.assertEqual(
            evidence["failure"]["code"], "callback_argument_origin_unresolved"
        )

    def test_converged_stack_access_is_exported_as_an_untrusted_proposal(self) -> None:
        root = unit("root", 0x1000, memory=[{
            "kind": "write",
            "width": 4,
            "address": add(reg("esp"), const(12)),
            "value": const(1),
        }])

        result = self._run(
            [root],
            [],
            roots=["root"],
            indirect_exits=[{
                "id": "unused-exit",
                "source_unit_id": "missing",
                "source_rva": 0,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": reg("eax"),
            }],
            allow_global_slot_promotion=False,
        )

        proposal = result["memory_access_proposals"][0]
        self.assertEqual(proposal["status"], "complete")
        self.assertEqual(proposal["unit_id"], "root")
        self.assertEqual(proposal["event_index"], 0)
        self.assertEqual(
            proposal["address_origins"],
            [{"kind": "stack_location", "key": [12]}],
        )
        self.assertFalse(result["proof_authority"])

    def test_nested_native_callback_activation_is_proved_fail_closed(self) -> None:
        identity = MachineImportIdentity("winmm.dll", "symbol", "midiStreamOpen")
        selected = self._selected_abi(identity, argument_words=2)

        def recover(flags: dict[str, object]) -> dict[str, object]:
            call_esp = sub(reg("esp"), const(8))
            writes = [
                {
                    "kind": "write",
                    "width": 4,
                    "address": call_esp,
                    "value": const(IMAGE_BASE + 0x1800),
                    "instruction_rva": 0x1500,
                },
                {
                    "kind": "write",
                    "width": 4,
                    "address": add(call_esp, const(4)),
                    "value": flags,
                    "instruction_rva": 0x1501,
                },
            ]
            event = {
                "kind": "external_call",
                "return_rva": 0x1503,
                "dll": "winmm.dll",
                "symbol": "midiStreamOpen",
                "ordinal": None,
                "register_inputs": {name: reg(name) for name in REGISTERS},
                "abi_contract": {
                    "template": "pe32-stdcall-v1",
                    "argument_words": 2,
                    "argument_base_offset": 0,
                    "contract_id": "nested-native-callback-fixture",
                    "world_effect": "callbackRegistration",
                    "callback_source": {"kind": "argument_word", "argument": 0},
                    "callback_lifetime": "until_resource_closed",
                    "callback_abi": {
                        "kind": "generic_callback",
                        "argument_words": 4,
                        "stack_cleanup_bytes": 16,
                        "nullable": False,
                    },
                    "callback_behavior": {
                        "kind": "nested_native_callback_v1",
                        "provider_relation": "same_pinned_native_provider_v1",
                        "delivery": "during_call_or_until_lifetime_end",
                        "activation": {
                            "kind": "masked_argument_equals",
                            "argument": 1,
                            "mask": 0x70000,
                            "value": 0x30000,
                        },
                        "message_argument": 1,
                        "message_values": [1],
                        "resource_argument": 0,
                        "instance_binding": {
                            "callback_argument": 2,
                            "registration_argument": 0,
                        },
                        "payload_arguments": [3],
                    },
                },
            }
            event["register_inputs"]["esp"] = call_esp
            registration = unit(
                "registration",
                0x1500,
                memory=writes,
                events=[event],
                ordered=[*writes, {**event, "instruction_rva": 0x1502}],
            )
            result = self._run(
                [registration, unit("callback", 0x1800), indirect_call()],
                [edge("registration", "call")],
                roots=["registration"],
                extra_import_abis={identity: selected},
            )
            return result["callback_registrations"][0]

        complete = recover(const(0x30000))
        self.assertEqual(complete["status"], "complete", complete)
        self.assertEqual(complete["callback_activation"]["exact_value"], 0x30000)
        self.assertEqual(complete["callback_activation"]["masked_value"], 0x30000)

        mismatch = recover(const(0x10000))
        self.assertEqual(mismatch["status"], "incomplete", mismatch)
        self.assertEqual(
            mismatch["failure"]["code"],
            "callback_activation_guard_mismatch",
        )

        unknown = recover(reg("eax"))
        self.assertEqual(unknown["status"], "incomplete", unknown)
        self.assertEqual(
            unknown["failure"]["code"],
            "callback_activation_origin_not_exact",
        )

    def test_callback_recovery_ignores_unrelated_opaque_argument(self) -> None:
        identity = MachineImportIdentity("winmm.dll", "symbol", "midiStreamOpen")
        selected = self._selected_abi(identity, argument_words=3)
        call_esp = sub(reg("esp"), const(12))
        writes = [
            {
                "kind": "write",
                "width": 4,
                "address": call_esp,
                "value": reg("eax"),
                "instruction_rva": 0x1510,
            },
            {
                "kind": "write",
                "width": 4,
                "address": add(call_esp, const(4)),
                "value": const(IMAGE_BASE + 0x1800),
                "instruction_rva": 0x1511,
            },
            {
                "kind": "write",
                "width": 4,
                "address": add(call_esp, const(8)),
                "value": const(0x30000),
                "instruction_rva": 0x1512,
            },
        ]
        event = {
            "kind": "external_call",
            "return_rva": 0x1514,
            "dll": identity.dll,
            "symbol": identity.value,
            "register_inputs": {name: reg(name) for name in REGISTERS},
            "abi_contract": {
                "template": "pe32-stdcall-v1",
                "argument_words": 3,
                "argument_base_offset": 0,
                "contract_id": "partial-callback-arguments",
                "world_effect": "callbackRegistration",
                "callback_source": {"kind": "argument_word", "argument": 1},
                "callback_lifetime": "until_resource_closed",
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 4,
                    "stack_cleanup_bytes": 16,
                    "nullable": False,
                },
                "callback_behavior": {
                    "kind": "nested_native_callback_v1",
                    "provider_relation": "same_pinned_native_provider_v1",
                    "delivery": "during_call_or_until_lifetime_end",
                    "activation": {
                        "kind": "masked_argument_equals",
                        "argument": 2,
                        "mask": 0x70000,
                        "value": 0x30000,
                    },
                    "message_argument": 1,
                    "message_values": [1],
                    "resource_argument": 0,
                    "instance_binding": {
                        "callback_argument": 2,
                        "registration_argument": 1,
                    },
                    "payload_arguments": [3],
                },
            },
        }
        event["register_inputs"]["esp"] = call_esp
        registration = unit(
            "registration",
            0x1510,
            memory=writes,
            events=[event],
            ordered=[*writes, {**event, "instruction_rva": 0x1513}],
        )
        result = self._run(
            [registration, unit("callback", 0x1800), indirect_call()],
            [edge("registration", "call")],
            roots=["registration"],
            extra_import_abis={identity: selected},
        )

        evidence = result["callback_registrations"][0]
        recovery = next(
            row
            for row in result["call_argument_recoveries"]
            if row.get("purpose") == "callback_registration_arguments"
        )
        self.assertEqual(evidence["status"], "complete", evidence)
        self.assertEqual(recovery["status"], "complete")
        self.assertEqual(recovery["required_argument_indices"], [1, 2])
        self.assertEqual(recovery["unresolved_argument_indices"], [])
        self.assertEqual(
            recovery["recovery_mode"], "rooted_inter_unit_stack"
        )

    def test_previous_callback_result_remains_callable_through_static_slot(self) -> None:
        identity = MachineImportIdentity(
            "kernel32.dll", "symbol", "SetUnhandledExceptionFilter"
        )
        selected = self._selected_abi(identity, argument_words=1)
        call_esp = sub(reg("esp"), const(4))
        argument_write = {
            "kind": "write",
            "width": 4,
            "address": call_esp,
            "value": const(IMAGE_BASE + 0x1800),
            "instruction_rva": 0x1500,
        }
        event = {
            "kind": "external_call",
            "return_rva": 0x1502,
            "dll": "kernel32.dll",
            "symbol": "SetUnhandledExceptionFilter",
            "ordinal": None,
            "register_inputs": {name: reg(name) for name in REGISTERS},
            "abi_contract": {
                "template": "pe32-stdcall-v1",
                "argument_words": 1,
                "argument_base_offset": 0,
                "contract_id": "set-unhandled-exception-filter",
                "profile_binding": {"id": "fixture", "sha256": "1" * 64},
                "world_effect": "callbackRegistration",
                "world_effect_argument": 0,
                "callback_lifetime": "until_replaced_or_process_exit",
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 1,
                    "stack_cleanup_bytes": 4,
                    "nullable": True,
                },
                "callback_result": {
                    "register": "eax",
                    "origin": "previous_registered_callback",
                    "nullable": True,
                },
            },
        }
        event["register_inputs"]["esp"] = call_esp
        registration = unit(
            "registration",
            0x1500,
            memory=[argument_write],
            events=[event],
            ordered=[argument_write, {**event, "instruction_rva": 0x1501}],
        )
        store = unit(
            "store-callback",
            0x1510,
            memory=[{
                "kind": "write",
                "width": 4,
                "address": const(SLOT),
                "value": reg("eax"),
            }],
        )
        target = load(const(SLOT))
        callback_call = unit(
            "call",
            0x1400,
            events=[{
                "kind": "indirect_call",
                "return_rva": 0x1401,
                "target": target,
                "register_inputs": {name: reg(name) for name in REGISTERS},
            }],
        )
        result = self._run(
            [registration, store, callback_call, unit("handler", 0x1800)],
            [edge("registration", "store-callback"), edge("store-callback", "call")],
            roots=["registration"],
            extra_import_abis={identity: selected},
        )

        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered", resolution)
        protocol = resolution["external_targets"][0]["external_protocol"]
        self.assertEqual(protocol["kind"], "pe32-previous-callback")
        self.assertEqual(protocol["callback_abi"]["stack_cleanup_bytes"], 4)

    def test_immutable_indexed_code_pointer_resolves_to_internal_target(self) -> None:
        table = IMAGE_BASE + 0x5000
        target_address = IMAGE_BASE + 0x2000
        seed = unit(
            "seed",
            0x1000,
            writes=[{"register": "eax", "value": const(1)}],
        )
        load_target = unit(
            "load-target",
            0x1001,
            writes=[{
                "register": "edi",
                "value": load(add(const(table), mul(reg("eax"), const(4)))),
            }],
        )
        target = load(add(const(table), mul(reg("eax"), const(4))))
        call = unit(
            "call",
            0x1002,
            events=[{
                "kind": "indirect_call",
                "return_rva": 0x1003,
                "target": reg("edi"),
                "register_inputs": {name: reg(name) for name in REGISTERS},
            }],
        )

        def immutable_reader(address: int, size: int) -> bytes | None:
            if (address, size) == (table + 4, 4):
                return target_address.to_bytes(4, "little")
            return None

        result = self._run(
            [seed, load_target, call, unit("target", 0x2000)],
            [edge("seed", "load-target"), edge("load-target", "call")],
            roots=["seed"],
            indirect_exits=[{
                "id": "exit:call",
                "source_unit_id": "call",
                "source_rva": 0x1002,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": target,
            }],
            static_data_reader=immutable_reader,
        )

        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered", resolution)
        self.assertEqual(resolution["target_rvas"], [0x2000])
        self.assertEqual(resolution["target_unit_ids"], ["target"])
        self.assertEqual(resolution["origin_kinds"], ["internal"])

    def test_exact_nonnull_guard_filters_nullable_static_callback_table(self) -> None:
        table = IMAGE_BASE + 0x5000
        target_address = IMAGE_BASE + 0x2000
        root = unit("root", 0x1000)
        null_seed = unit(
            "null-seed",
            0x1001,
            writes=[{"register": "esi", "value": const(table)}],
        )
        target_seed = unit(
            "target-seed",
            0x1002,
            writes=[{"register": "esi", "value": const(table + 4)}],
        )
        loaded = load(reg("esi"))
        select = unit(
            "select",
            0x1003,
            writes=[{"register": "eax", "value": loaded}],
        )
        select["semantics"]["outcome"] = {
            "kind": "branch",
            "true_target_rva": 0x1004,
            "false_target_rva": 0x1005,
        }
        select["semantics"]["edge_conditions"] = [
            {
                "target_rva": 0x1004,
                "condition": {
                    "op": "not",
                    "args": [{
                        "op": "eq",
                        "args": [
                            {"op": "and32", "args": [loaded, loaded]},
                            const(0),
                        ],
                    }],
                },
            },
            {
                "target_rva": 0x1005,
                "condition": {
                    "op": "eq",
                    "args": [
                        {"op": "and32", "args": [loaded, loaded]},
                        const(0),
                    ],
                },
            },
        ]
        call = unit(
            "call",
            0x1004,
            events=[{
                "kind": "indirect_call",
                "return_rva": 0x1005,
                "target": reg("eax"),
                "register_inputs": {name: reg(name) for name in REGISTERS},
            }],
        )
        skip = unit("skip", 0x1005)
        target = unit("target", 0x2000)
        units = [root, null_seed, target_seed, select, call, skip, target]
        for source, targets in {
            "root": [0x1001, 0x1002],
            "null-seed": [0x1003],
            "target-seed": [0x1003],
            "select": [0x1004, 0x1005],
        }.items():
            next(row for row in units if row["id"] == source)["control"] = {
                "direct_targets": targets,
                "has_indirect_target": False,
                "kind": "branch" if len(targets) == 2 else "fallthrough",
            }
        for row in (call, skip, target):
            row["control"] = {
                "direct_targets": [],
                "has_indirect_target": row is call,
                "kind": "indirect_call" if row is call else "return",
            }

        def immutable_reader(address: int, size: int) -> bytes | None:
            if size != 4:
                return None
            if address == table:
                return (0).to_bytes(4, "little")
            if address == table + 4:
                return target_address.to_bytes(4, "little")
            return None

        result = self._run(
            units,
            exact_control_inventory_v2(units)["direct_edges"],
            roots=["root"],
            indirect_exits=[{
                "id": "exit:callback",
                "source_unit_id": "call",
                "source_rva": 0x1004,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": reg("eax"),
            }],
            static_data_reader=immutable_reader,
        )

        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered", resolution)
        self.assertEqual(resolution["target_unit_ids"], ["target"])
        self.assertEqual(resolution["target_rvas"], [0x2000])

    def test_indexed_code_pointer_without_immutable_evidence_stays_incomplete(self) -> None:
        table = IMAGE_BASE + 0x5000
        seed = unit(
            "seed",
            0x1000,
            writes=[{"register": "eax", "value": const(1)}],
        )
        load_target = unit(
            "load-target",
            0x1001,
            writes=[{
                "register": "edi",
                "value": load(add(const(table), mul(reg("eax"), const(4)))),
            }],
        )
        call = unit(
            "call",
            0x1002,
            events=[{
                "kind": "indirect_call",
                "return_rva": 0x1003,
                "target": reg("edi"),
                "register_inputs": {name: reg(name) for name in REGISTERS},
            }],
        )
        result = self._run(
            [seed, load_target, call, unit("target", 0x2000)],
            [edge("seed", "load-target"), edge("load-target", "call")],
            roots=["seed"],
            indirect_exits=[{
                "id": "exit:call",
                "source_unit_id": "call",
                "source_rva": 0x1002,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": reg("edi"),
            }],
        )

        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "incomplete")
        self.assertEqual(
            resolution["failure"]["code"],
            "register_target_origin_missing",
        )

    def test_bounded_mask_recovers_every_immutable_jump_table_target(self) -> None:
        table = IMAGE_BASE + 0x5000
        target_addresses = [IMAGE_BASE + 0x2000 + index for index in range(4)]
        target = load(add(
            const(table),
            mul(bit_and(reg("eax"), const(3)), const(4)),
        ))
        jump = unit("jump", 0x1000)
        jump["semantics"]["outcome"] = {
            "kind": "indirect_jump",
            "target": target,
        }
        targets = [
            unit(f"target-{index}", 0x2000 + index)
            for index in range(4)
        ]

        def immutable_reader(address: int, size: int) -> bytes | None:
            if size != 4 or not table <= address < table + 16:
                return None
            index = (address - table) // 4
            return target_addresses[index].to_bytes(4, "little")

        result = self._run(
            [jump, *targets],
            [],
            roots=["jump"],
            indirect_exits=[{
                "id": "exit:jump",
                "source_unit_id": "jump",
                "source_rva": 0x1000,
                "source_event_index": None,
                "kind": "indirect_jump",
                "target_expression": target,
            }],
            static_data_reader=immutable_reader,
        )

        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered", resolution)
        self.assertEqual(
            resolution["target_unit_ids"],
            [f"target-{index}" for index in range(4)],
        )

    def test_unresolved_dispatch_reports_missing_symbolic_memory_fact(self) -> None:
        target = load(add(reg("eax"), const(28)))
        call = unit(
            "call",
            0x1400,
            events=[{
                "kind": "indirect_call",
                "return_rva": 0x1401,
                "target": target,
                "register_inputs": {name: reg(name) for name in REGISTERS},
            }],
        )

        result = self._run(
            [call],
            [],
            roots=["call"],
            indirect_exits=[{
                "id": "exit:call",
                "source_unit_id": "call",
                "source_rva": 0x1400,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": target,
            }],
        )

        failure = result["resolutions"][0]["failure"]
        self.assertEqual(failure["code"], "operation_view_origin_missing")
        frontier = failure["analysis_frontier"]
        self.assertEqual(frontier["code"], "load_value_origin_missing")
        self.assertEqual(frontier["path"], "target")
        self.assertEqual(
            [cause["code"] for cause in frontier["causes"]],
            ["symbolic_memory_fact_missing"],
        )

    def test_nested_dispatch_reports_deepest_missing_receiver_load(self) -> None:
        target = load(add(const(48), load(load(reg("edx")))))
        call = unit(
            "call",
            0x1400,
            events=[{
                "kind": "indirect_call",
                "return_rva": 0x1401,
                "target": target,
                "register_inputs": {name: reg(name) for name in REGISTERS},
            }],
        )

        result = self._run(
            [call],
            [],
            roots=["call"],
            indirect_exits=[{
                "id": "exit:call",
                "source_unit_id": "call",
                "source_rva": 0x1400,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": target,
            }],
        )

        frontier = result["resolutions"][0]["failure"]["analysis_frontier"]
        self.assertEqual(frontier["code"], "load_address_origin_missing")
        operand = frontier["cause"]
        self.assertEqual(operand["code"], "operand_origin_missing")
        receiver = operand["cause"]
        self.assertEqual(receiver["code"], "load_address_origin_missing")
        self.assertEqual(
            receiver["cause"]["causes"][0]["code"],
            "symbolic_memory_fact_missing",
        )

    def test_unknown_call_preservation_is_bootstrap_only(self) -> None:
        target_address = IMAGE_BASE + 0x2000
        seed = unit(
            "seed",
            0x1000,
            writes=[{"register": "esi", "value": const(target_address)}],
        )
        call_event = {
            "kind": "internal_call",
            "target_rva": 0x3000,
            "return_rva": 0x1002,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        call_internal = unit("internal-call", 0x1001, events=[call_event])
        call_target = unit(
            "call",
            0x1002,
            events=[{
                "kind": "indirect_call",
                "return_rva": 0x1003,
                "target": reg("esi"),
                "register_inputs": {name: reg(name) for name in REGISTERS},
            }],
        )
        units = [
            seed,
            call_internal,
            call_target,
            unit("target", 0x2000),
            unit("callee", 0x3000),
        ]
        direct = [edge("seed", "internal-call"), edge("internal-call", "call")]
        internal_edges = [{
            "source_unit_id": "internal-call",
            "source_event_index": 0,
            "target_unit_id": "callee",
            "status": "resolved",
        }]
        indirect_exits = [{
            "id": "exit:call",
            "source_unit_id": "call",
            "source_rva": 0x1002,
            "source_event_index": 0,
            "kind": "indirect_call",
            "target_expression": reg("esi"),
        }]

        bootstrap = self._run(
            units,
            direct,
            roots=["seed"],
            internal_edges=internal_edges,
            indirect_exits=indirect_exits,
            bootstrap_unknown_call_preserved_registers=frozenset({"esi"}),
        )
        strict_without_contract = self._run(
            units,
            direct,
            roots=["seed"],
            internal_edges=internal_edges,
            indirect_exits=indirect_exits,
        )
        strict_with_contract = self._run(
            units,
            direct,
            roots=["seed"],
            internal_edges=internal_edges,
            indirect_exits=indirect_exits,
            internal_call_preserved_registers={
                IMAGE_BASE + 0x3000: frozenset({"esi"})
            },
        )

        self.assertEqual(bootstrap["resolutions"][0]["status"], "recovered")
        self.assertIn(
            "bootstrap_call_preservation_used",
            {issue["code"] for issue in bootstrap["issues"]},
        )
        self.assertEqual(
            strict_without_contract["resolutions"][0]["status"], "incomplete"
        )
        self.assertEqual(
            strict_with_contract["resolutions"][0]["status"], "recovered"
        )
        self.assertNotIn(
            "bootstrap_call_preservation_used",
            {issue["code"] for issue in strict_with_contract["issues"]},
        )

    def _run(
        self,
        units: list[dict[str, object]],
        direct: list[dict[str, object]],
        *,
        roots: list[str],
        internal_edges: list[dict[str, object]] | None = None,
        recovered_indirect_edges: list[dict[str, object]] | None = None,
        extra_import_abis: dict[
            MachineImportIdentity, SelectedImportABI
        ] | None = None,
        stack_slot_budget: int = 256,
        imports: list[dict[str, object]] | None = None,
        indirect_exits: list[dict[str, object]] | None = None,
        static_data_reader: Callable[[int, int], bytes | None] | None = None,
        bootstrap_unknown_call_preserved_registers: frozenset[str] | None = None,
        internal_call_preserved_registers: dict[int, frozenset[str]] | None = None,
        internal_call_result_relations: dict[
            int, dict[str, list[dict[str, object]]]
        ] | None = None,
        internal_call_memory_preservation: dict[int, bool] | None = None,
        internal_call_memory_result_relations: dict[
            int, dict[ValueOrigin, frozenset[ValueOrigin] | None]
        ] | None = None,
        initial_known_slots: dict[object, object] | None = None,
        recovered_known_slots: dict[object, object] | None = None,
        checked_stack_entry_offsets: dict[str, list[int]] | None = None,
        allow_global_slot_promotion: bool = True,
    ) -> dict[str, object]:
        identity = MachineImportIdentity("example.dll", "symbol", "CreateThing")
        abi = resolve_machine_call_abi("pe32-stdcall-v1")
        assert abi is not None
        selected = SelectedImportABI(
            identity=identity,
            abi=abi,
            profile_id="fixture",
            profile_sha256="0" * 64,
            entry_key="machine_import_signatures",
            entry_index=0,
        )
        import_abis = {identity: selected}
        import_abis.update(extra_import_abis or {})
        return recover_external_interface_targets(
            units=units,
            roots=roots,
            direct_edges=direct,
            internal_call_edges=internal_edges or [],
            recovered_indirect_edges=recovered_indirect_edges or [],
            indirect_exits=indirect_exits or [{
                "id": "exit:call",
                "source_unit_id": "call",
                "source_rva": 0x1400,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": load(reg("ecx")),
            }],
            profiles=[self.profile],
            imports=imports or [],
            import_abis=import_abis,
            internal_call_preserved_registers=(
                internal_call_preserved_registers or {}
            ),
            internal_call_result_relations=(
                internal_call_result_relations or {}
            ),
            internal_call_memory_preservation=(
                internal_call_memory_preservation or {}
            ),
            internal_call_memory_result_relations=(
                internal_call_memory_result_relations or {}
            ),
            image_base=IMAGE_BASE,
            stack_slot_budget=stack_slot_budget,
            static_data_reader=static_data_reader,
            bootstrap_unknown_call_preserved_registers=(
                bootstrap_unknown_call_preserved_registers
            ),
            initial_known_slots=initial_known_slots,
            recovered_known_slots=recovered_known_slots,
            checked_stack_entry_offsets=checked_stack_entry_offsets,
            allow_global_slot_promotion=allow_global_slot_promotion,
        )

    @staticmethod
    def _selected_abi(
        identity: MachineImportIdentity,
        *,
        argument_words: int | None,
        abi_template: str = "pe32-stdcall-v1",
    ) -> SelectedImportABI:
        abi = resolve_machine_call_abi(abi_template)
        assert abi is not None
        return SelectedImportABI(
            identity=identity,
            abi=abi,
            profile_id="fixture",
            profile_sha256="1" * 64,
            entry_key="machine_import_signatures",
            entry_index=1,
            argument_words=argument_words,
        )


if __name__ == "__main__":
    unittest.main()
