from __future__ import annotations

from hashlib import sha256
import unittest

from spaghetti_extractor.external_operation_profiles import (
    EXTERNAL_OPERATION_CONTRACT_FORMAT,
    EXTERNAL_OPERATION_PROFILE_FORMAT,
    parse_external_operation_profile,
)
from spaghetti_extractor.interface_provenance import (
    recover_external_interface_targets,
)


REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")


def reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def load(address: object) -> dict[str, object]:
    return {"op": "load", "width": 4, "address": address}


def add(left: object, right: object) -> dict[str, object]:
    return {"op": "add32", "args": [left, right]}


def sub(left: object, right: object) -> dict[str, object]:
    return {"op": "sub32", "args": [left, right]}


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
            "ordered_events": ordered if ordered is not None else events or [],
        },
    }


def operation_profile(
    *,
    guarded: bool = False,
    table_access: str = "object_table",
    contract_status: str = "complete",
):
    contract = {
        "format": EXTERNAL_OPERATION_CONTRACT_FORMAT,
        "id": "opaque",
        "status": contract_status,
        "memory_footprints": [],
        "world_effects": [],
    }
    if contract_status == "incomplete":
        contract["blockers"] = ["external_memory_effects_not_authored"]
    operation = lambda identifier, outputs=None: {
        "id": identifier,
        "abi_template": "pe32-stdcall-v1",
        "argument_words": 0,
        "environment_contract_id": "opaque",
        "output_rules": outputs or [],
    }
    return parse_external_operation_profile({
        "format": EXTERNAL_OPERATION_PROFILE_FORMAT,
        "id": "operation-fixture",
        "model": "x86-pe32",
        "status": "complete",
        "provenance": {"kind": "fixture"},
        "table_views": [{
            "id": "IRoot",
            "table": "IRootTable",
            "access": table_access,
        }],
        "operations": [
            operation("create", [{
                "kind": "return_register",
                "register": "eax",
                **(
                    {"success_guard": {"kind": "nonzero", "register": "eax"}}
                    if guarded
                    else {}
                ),
                "view": {"kind": "fixed", "view_id": "IRoot"},
            }]),
            operation("release"),
        ],
        "selectors": [
            {
                "kind": "direct_import",
                "operation_id": "create",
                "import": {"dll": "example.dll", "symbol": "CreateRoot"},
            },
            {
                "kind": "table_slot",
                "operation_id": "release",
                "view_id": "IRoot",
                "slot": 0,
            },
        ],
        "environment_contracts": [contract],
    })


class OperationProvenanceTests(unittest.TestCase):
    def test_incomplete_environment_contract_guides_but_cannot_authorize(self) -> None:
        call = {
            "kind": "external_call",
            "dll": "example.dll",
            "symbol": "CreateRoot",
            "ordinal": None,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        result = recover_external_interface_targets(
            units=[unit("create", 0x1000, events=[call])],
            roots=["create"],
            direct_edges=[],
            internal_call_edges=[],
            recovered_indirect_edges=[],
            indirect_exits=[],
            profiles=[],
            operation_profiles=[operation_profile(contract_status="incomplete")],
            import_abis={},
            internal_call_preserved_registers={},
            image_base=0x400000,
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIn(
            "operation_environment_contract_incomplete",
            {issue["code"] for issue in result["issues"]},
        )
        recovery = result["call_argument_recoveries"][0]
        self.assertEqual(recovery["status"], "complete")
        self.assertEqual(
            recovery["environment_contract"]["status"], "incomplete"
        )

    def test_returned_resource_view_resolves_table_slot(self) -> None:
        call = {
            "kind": "external_call",
            "dll": "example.dll",
            "symbol": "CreateRoot",
            "ordinal": None,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        target = load(reg("ecx"))
        indirect = {
            "kind": "indirect_call",
            "target": target,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        units = [
            unit("create", 0x1000, events=[call]),
            unit("table", 0x1010, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            unit("invoke", 0x1020, events=[indirect]),
        ]
        result = recover_external_interface_targets(
            units=units,
            roots=["create"],
            direct_edges=[
                {"source_unit_id": "create", "target_unit_id": "table"},
                {"source_unit_id": "table", "target_unit_id": "invoke"},
            ],
            internal_call_edges=[],
            recovered_indirect_edges=[],
            indirect_exits=[{
                "id": "invoke-exit",
                "source_unit_id": "invoke",
                "source_rva": 0x1020,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": target,
            }],
            profiles=[],
            operation_profiles=[operation_profile()],
            import_abis={},
            internal_call_preserved_registers={},
            image_base=0x400000,
        )

        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered")
        protocol = resolution["external_targets"][0]["external_protocol"]
        self.assertEqual(protocol["kind"], "pe32-operation")
        self.assertEqual(protocol["operation_id"], "release")
        self.assertFalse(result["proof_authority"])

    def test_missing_receiver_reports_operation_view_blocker(self) -> None:
        target = load(add(reg("ecx"), const(4)))
        event = {
            "kind": "indirect_call",
            "target": target,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        result = recover_external_interface_targets(
            units=[unit("invoke", 0x2000, events=[event])],
            roots=["invoke"],
            direct_edges=[],
            internal_call_edges=[],
            recovered_indirect_edges=[],
            indirect_exits=[{
                "id": "missing-view",
                "source_unit_id": "invoke",
                "source_rva": 0x2000,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": target,
            }],
            profiles=[],
            operation_profiles=[operation_profile()],
            import_abis={},
            internal_call_preserved_registers={},
            image_base=0x400000,
        )

        self.assertEqual(
            result["resolutions"][0]["failure"]["code"],
            "operation_view_origin_missing",
        )

    def test_success_guard_activates_guarded_return_view(self) -> None:
        call = {
            "kind": "external_call",
            "dll": "example.dll",
            "symbol": "CreateRoot",
            "ordinal": None,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        target = load(reg("ecx"))
        invoke = {
            "kind": "indirect_call",
            "target": target,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        units = [
            unit("create", 0x3000, events=[call]),
            unit("table", 0x3010, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            unit("invoke", 0x3020, events=[invoke]),
        ]

        def run(with_guard: bool):
            return recover_external_interface_targets(
                units=units,
                roots=["create"],
                direct_edges=[
                    {
                        "source_unit_id": "create",
                        "target_unit_id": "table",
                        "guard": (
                            {"op": "ne32", "args": [reg("eax"), const(0)]}
                            if with_guard
                            else None
                        ),
                    },
                    {"source_unit_id": "table", "target_unit_id": "invoke"},
                ],
                internal_call_edges=[],
                recovered_indirect_edges=[],
                indirect_exits=[{
                    "id": "guarded-invoke",
                    "source_unit_id": "invoke",
                    "source_rva": 0x3020,
                    "source_event_index": 0,
                    "kind": "indirect_call",
                    "target_expression": target,
                }],
                profiles=[],
                operation_profiles=[operation_profile(guarded=True)],
                import_abis={},
                internal_call_preserved_registers={},
                image_base=0x400000,
            )

        self.assertEqual(run(False)["resolutions"][0]["status"], "incomplete")
        self.assertEqual(run(True)["resolutions"][0]["status"], "recovered")

    def test_direct_c_operation_table_uses_the_same_provenance_engine(self) -> None:
        call = {
            "kind": "external_call",
            "dll": "example.dll",
            "symbol": "CreateRoot",
            "ordinal": None,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        target = load(reg("ecx"))
        invoke = {
            "kind": "indirect_call",
            "target": target,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        units = [
            unit("create", 0x4000, events=[call]),
            unit("copy-table", 0x4010, writes=[{
                "register": "ecx", "value": reg("eax"),
            }]),
            unit("invoke", 0x4020, events=[invoke]),
        ]
        result = recover_external_interface_targets(
            units=units,
            roots=["create"],
            direct_edges=[
                {"source_unit_id": "create", "target_unit_id": "copy-table"},
                {"source_unit_id": "copy-table", "target_unit_id": "invoke"},
            ],
            internal_call_edges=[],
            recovered_indirect_edges=[],
            indirect_exits=[{
                "id": "direct-table-invoke",
                "source_unit_id": "invoke",
                "source_rva": 0x4020,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": target,
            }],
            profiles=[],
            operation_profiles=[operation_profile(table_access="direct_table")],
            import_abis={},
            internal_call_preserved_registers={},
            image_base=0x400000,
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")
        self.assertEqual(
            result["resolutions"][0]["closure"],
            "checked_external_operation_inventory",
        )
        self.assertEqual(result["counts"]["recovered_operation_exits"], 1)
        self.assertEqual(result["counts"]["recovered_method_exits"], 0)

    def test_guarded_out_argument_uses_immutable_discriminator_bytes(self) -> None:
        iid_address = 0x450000
        output_slot = 0x460000
        iid = bytes.fromhex("00112233445566778899aabbccddeeff")
        payload = operation_profile().as_json()
        payload["operations"][0] = {
            "id": "create",
            "abi_template": "pe32-stdcall-v1",
            "argument_words": 2,
            "environment_contract_id": "create-output",
            "output_rules": [{
                "kind": "out_argument",
                "argument_index": 1,
                "write_width": 4,
                "success_guard": {
                    "kind": "equals",
                    "register": "eax",
                    "value": 0,
                },
                "view": {
                    "kind": "discriminator",
                    "argument_index": 0,
                    "read_bytes": len(iid),
                    "cases": [{
                        "bytes_sha256": sha256(iid).hexdigest(),
                        "view_id": "IRoot",
                    }],
                },
            }],
        }
        payload["environment_contracts"].append({
            "format": EXTERNAL_OPERATION_CONTRACT_FORMAT,
            "id": "create-output",
            "status": "complete",
            "memory_footprints": [{
                "access": "write",
                "base_argument": 1,
                "offset": 0,
                "size": {"kind": "fixed", "bytes": 4},
                "nullable": False,
            }],
            "world_effects": [],
        })
        profile = parse_external_operation_profile(payload)

        esp4 = sub(reg("esp"), const(4))
        esp8 = sub(esp4, const(4))
        writes = [
            {"kind": "write", "width": 4, "address": esp4,
             "value": const(output_slot)},
            {"kind": "write", "width": 4, "address": esp8,
             "value": const(iid_address)},
        ]
        call = {
            "kind": "external_call",
            "dll": "example.dll",
            "symbol": "CreateRoot",
            "ordinal": None,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        call["register_inputs"]["esp"] = esp8
        target = load(reg("ecx"))
        invoke = {
            "kind": "indirect_call",
            "target": target,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        units = [
            unit(
                "create",
                0x5000,
                memory=writes,
                events=[call],
                ordered=[*writes, call],
            ),
            unit("object", 0x5010, writes=[{
                "register": "eax", "value": load(const(output_slot)),
            }]),
            unit("table", 0x5020, writes=[{
                "register": "ecx", "value": load(reg("eax")),
            }]),
            unit("invoke", 0x5030, events=[invoke]),
        ]
        result = recover_external_interface_targets(
            units=units,
            roots=["create"],
            direct_edges=[
                {
                    "source_unit_id": "create",
                    "target_unit_id": "object",
                    "guard": {"op": "eq32", "args": [reg("eax"), const(0)]},
                },
                {"source_unit_id": "object", "target_unit_id": "table"},
                {"source_unit_id": "table", "target_unit_id": "invoke"},
            ],
            internal_call_edges=[],
            recovered_indirect_edges=[],
            indirect_exits=[{
                "id": "iid-selected-invoke",
                "source_unit_id": "invoke",
                "source_rva": 0x5030,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": target,
            }],
            profiles=[],
            operation_profiles=[profile],
            import_abis={},
            internal_call_preserved_registers={},
            image_base=0x400000,
            static_data_reader=lambda address, size: (
                iid if (address, size) == (iid_address, len(iid)) else None
            ),
        )

        self.assertEqual(result["resolutions"][0]["status"], "recovered")
        refinement = next(
            row for row in result["call_argument_recoveries"]
            if row.get("operation_id") == "create"
        )
        self.assertEqual(refinement["status"], "complete")
        self.assertEqual(
            {issue["code"] for issue in result["issues"]},
            set(),
        )

    def test_guarded_resolver_result_becomes_an_operation_target(self) -> None:
        payload = operation_profile().as_json()
        payload["operations"].extend([
            {
                "id": "resolve",
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 0,
                "environment_contract_id": "opaque",
                "output_rules": [{
                    "kind": "return_operation",
                    "register": "eax",
                    "result_id": "selected-entry",
                    "success_guard": {"kind": "nonzero", "register": "eax"},
                }],
            },
            {
                "id": "resolved-call",
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 0,
                "environment_contract_id": "opaque",
                "output_rules": [],
            },
        ])
        payload["selectors"].extend([
            {
                "kind": "direct_import",
                "operation_id": "resolve",
                "import": {"dll": "example.dll", "symbol": "Resolve"},
            },
            {
                "kind": "resolver_result",
                "operation_id": "resolved-call",
                "resolver_operation_id": "resolve",
                "result_id": "selected-entry",
            },
        ])
        profile = parse_external_operation_profile(payload)
        call = {
            "kind": "external_call",
            "dll": "example.dll",
            "symbol": "Resolve",
            "ordinal": None,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        invoke = {
            "kind": "indirect_call",
            "target": reg("eax"),
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        result = recover_external_interface_targets(
            units=[
                unit("resolve", 0x6000, events=[call]),
                unit("invoke", 0x6010, events=[invoke]),
            ],
            roots=["resolve"],
            direct_edges=[{
                "source_unit_id": "resolve",
                "target_unit_id": "invoke",
                "guard": {"op": "ne32", "args": [reg("eax"), const(0)]},
            }],
            internal_call_edges=[],
            recovered_indirect_edges=[],
            indirect_exits=[{
                "id": "resolved-invoke",
                "source_unit_id": "invoke",
                "source_rva": 0x6010,
                "source_event_index": 0,
                "kind": "indirect_call",
                "target_expression": reg("eax"),
            }],
            profiles=[],
            operation_profiles=[profile],
            import_abis={},
            internal_call_preserved_registers={},
            image_base=0x400000,
        )

        resolution = result["resolutions"][0]
        self.assertEqual(resolution["status"], "recovered")
        self.assertEqual(
            resolution["external_targets"][0]["external_protocol"][
                "operation_id"
            ],
            "resolved-call",
        )

    def test_callback_registration_emits_canonical_nested_frame_evidence(self) -> None:
        payload = operation_profile().as_json()
        payload["operations"].extend([
            {
                "id": "register-callback",
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 1,
                "environment_contract_id": "callback-registration",
                "output_rules": [],
            },
            {
                "id": "callback-invocation",
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 0,
                "environment_contract_id": "opaque",
                "output_rules": [],
            },
        ])
        payload["selectors"].extend([
            {
                "kind": "direct_import",
                "operation_id": "register-callback",
                "import": {"dll": "example.dll", "symbol": "RegisterCallback"},
            },
            {
                "kind": "callback",
                "operation_id": "callback-invocation",
                "callback_id": "completion",
            },
        ])
        payload["environment_contracts"].append({
            "format": EXTERNAL_OPERATION_CONTRACT_FORMAT,
            "id": "callback-registration",
            "status": "complete",
            "memory_footprints": [],
            "world_effects": [{
                "kind": "callbackRegistration",
                "argument_index": 0,
                "callback_id": "completion",
            }],
        })
        profile = parse_external_operation_profile(payload)

        callback_rva = 0x7100
        esp4 = sub(reg("esp"), const(4))
        write = {
            "kind": "write",
            "width": 4,
            "address": esp4,
            "value": const(0x400000 + callback_rva),
        }
        call = {
            "kind": "external_call",
            "dll": "example.dll",
            "symbol": "RegisterCallback",
            "ordinal": None,
            "register_inputs": {name: reg(name) for name in REGISTERS},
        }
        call["register_inputs"]["esp"] = esp4
        result = recover_external_interface_targets(
            units=[
                unit(
                    "register",
                    0x7000,
                    memory=[write],
                    events=[call],
                    ordered=[write, call],
                ),
                unit("callback-body", callback_rva),
            ],
            roots=["register"],
            direct_edges=[],
            internal_call_edges=[],
            recovered_indirect_edges=[],
            indirect_exits=[],
            profiles=[],
            operation_profiles=[profile],
            import_abis={},
            internal_call_preserved_registers={},
            image_base=0x400000,
        )

        refinement = next(
            row for row in result["call_argument_recoveries"]
            if row.get("operation_id") == "register-callback"
        )
        callback = refinement["world_effects"][0]
        self.assertEqual(callback["status"], "complete")
        self.assertEqual(callback["callback_id"], "completion")
        self.assertEqual(callback["target_rvas"], [callback_rva])
        self.assertEqual(callback["target_unit_ids"], ["callback-body"])


if __name__ == "__main__":
    unittest.main()
