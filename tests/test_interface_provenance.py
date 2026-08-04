from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external_interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    ExternalInterfaceProfile,
    load_external_interface_profile,
)
from spaghetti_extractor.import_abi import SelectedImportABI
from spaghetti_extractor.interface_provenance import (
    INTERFACE_PROVENANCE_FORMAT,
    recover_external_interface_targets,
)
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
        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered")
        protocol = resolution["external_targets"][0]["external_protocol"]
        self.assertEqual((protocol["interface_id"], protocol["method"]), ("IThing", "Release"))
        self.assertEqual(result["counts"]["static_interface_slots"], 1)

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

    def test_unknown_exact_write_taints_factory_slot(self) -> None:
        units = [
            factory_unit(),
            unit(
                "taint",
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
            [edge("factory", "taint"), edge("taint", "object"), edge("object", "vtable"), edge("vtable", "call")],
            roots=["factory"],
        )

        self.assertEqual(result["resolutions"][0]["status"], "incomplete")
        self.assertEqual(result["counts"]["static_interface_slots"], 0)

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

    def _run(
        self,
        units: list[dict[str, object]],
        direct: list[dict[str, object]],
        *,
        roots: list[str],
        internal_edges: list[dict[str, object]] | None = None,
        stack_slot_budget: int = 256,
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
        return recover_external_interface_targets(
            units=units,
            roots=roots,
            direct_edges=direct,
            internal_call_edges=internal_edges or [],
            recovered_indirect_edges=[],
            indirect_exits=[{
                "id": "exit:call",
                "source_unit_id": "call",
                "source_rva": 0x1400,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": load(reg("ecx")),
            }],
            profiles=[self.profile],
            import_abis={identity: selected},
            internal_call_preserved_registers={},
            image_base=IMAGE_BASE,
            stack_slot_budget=stack_slot_budget,
        )


if __name__ == "__main__":
    unittest.main()
