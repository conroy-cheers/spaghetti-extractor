from __future__ import annotations

from ._support import *

class RootedReachabilityTests(unittest.TestCase):
    def test_unreachable_is_reported_only_after_complete_closure(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root", "child", "isolated"],
            roots=["root"],
            direct_edges=[
                {"source_unit_id": "root", "target_unit_id": "child"}
            ],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["reachable_units"], ["child", "root"])
        self.assertEqual(result["potential_units"], [])
        self.assertEqual(result["unreachable_units"], ["isolated"])

    def test_unresolved_edge_from_unreachable_unit_does_not_block_closure(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root", "isolated"],
            roots=["root"],
            direct_edges=[
                {"source_unit_id": "isolated", "target_unit_id": "missing"}
            ],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["reachable_units"], ["root"])
        self.assertEqual(result["potential_units"], [])
        self.assertEqual(result["unreachable_units"], ["isolated"])
        self.assertEqual(result["frontiers"], [])
        self.assertEqual(result["issues"], [])

    def test_unresolved_edge_from_unknown_unit_remains_incomplete(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            direct_edges=[
                {"source_unit_id": "missing", "target_unit_id": "root"}
            ],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["reachable_units"], ["root"])
        self.assertEqual(result["frontiers"], [])
        self.assertEqual(
            result["issues"],
            [
                {
                    "code": "unresolved_direct_edge",
                    "source_unit_id": "missing",
                }
            ],
        )

    def test_unresolved_frontiers_retain_distinct_target_locations(self) -> None:
        result = derive_rooted_reachable_units(
            units=[{"id": "root", "rva": 0x1000}],
            roots=["root"],
            internal_call_edges=[
                {
                    "kind": "internal_call",
                    "source_unit_id": "root",
                    "source_rva": 0x1004,
                    "source_event_index": 0,
                    "target_rva": 0x2000,
                },
                {
                    "kind": "internal_call",
                    "source_unit_id": "root",
                    "source_rva": 0x1004,
                    "source_event_index": 1,
                    "target_rva": 0x3000,
                },
            ],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(len(result["frontiers"]), 2)
        self.assertEqual(
            [
                {
                    key: frontier[key]
                    for key in (
                        "source_rva",
                        "source_event_index",
                        "target_rva",
                    )
                }
                for frontier in result["frontiers"]
            ],
            [
                {
                    "source_rva": 0x1004,
                    "source_event_index": 0,
                    "target_rva": 0x2000,
                },
                {
                    "source_rva": 0x1004,
                    "source_event_index": 1,
                    "target_rva": 0x3000,
                },
            ],
        )

    def test_calls_and_finite_indirect_targets_extend_reachability(self) -> None:
        units = [
            {"id": "root", "rva": 0x1000},
            {"id": "dispatch", "rva": 0x1010},
            {"id": "continuation", "rva": 0x1020},
            {"id": "callee", "rva": 0x1100},
            {"id": "case", "rva": 0x1200},
            {"id": "unreachable", "rva": 0x1300},
        ]
        result = derive_rooted_reachable_units(
            units=units,
            roots=(unit_id for unit_id in ["root"]),
            direct_edges=[
                {"source_unit_id": "root", "target_unit_id": "dispatch"},
                {
                    "source_unit_id": "dispatch",
                    "target_unit_id": "continuation",
                },
            ],
            internal_call_edges=[
                {"source_unit_id": "dispatch", "target_rva": 0x1100}
            ],
            recovered_indirect_targets=[
                {
                    "id": "exit:table",
                    "source_unit_id": "callee",
                    "kind": "indirect_jump",
                    "status": "recovered",
                    "target_rvas": [0x1200],
                }
            ],
            indirect_exits=[
                {
                    "id": "exit:table",
                    "source_unit_id": "callee",
                    "kind": "indirect_jump",
                },
                {
                    "id": "exit:unknown",
                    "source_unit_id": "case",
                    "kind": "indirect_call",
                    "target_expression": {"op": "input_reg", "reg": "edx"},
                },
                {
                    "id": "exit:unreachable",
                    "source_unit_id": "unreachable",
                    "kind": "indirect_jump",
                },
            ],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(
            result["reachable_units"],
            ["callee", "case", "continuation", "dispatch", "root"],
        )
        self.assertEqual(result["potential_units"], ["unreachable"])
        self.assertEqual(result["unreachable_units"], [])
        self.assertEqual(
            {
                (edge["kind"], edge["source_unit_id"], edge["target_unit_id"])
                for edge in result["edges"]
            },
            {
                ("direct", "root", "dispatch"),
                ("direct", "dispatch", "continuation"),
                ("internal_call", "dispatch", "callee"),
                ("recovered_indirect", "callee", "case"),
            },
        )
        self.assertEqual(
            [frontier["id"] for frontier in result["frontiers"]],
            ["exit:unknown"],
        )
        self.assertEqual(result["frontiers"][0]["reason"], "unresolved_indirect_exit")


    def test_partially_resolved_indirect_inventory_adds_no_edges(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root", "known"],
            roots=["root"],
            recovered_indirect_targets=[
                {
                    "id": "exit:partial",
                    "source_unit_id": "root",
                    "status": "recovered",
                    "target_unit_ids": ["known", "missing"],
                }
            ],
            indirect_exits=[
                {
                    "id": "exit:partial",
                    "source_unit_id": "root",
                    "kind": "indirect_jump",
                }
            ],
        )

        self.assertEqual(result["reachable_units"], ["root"])
        self.assertEqual(result["potential_units"], ["known"])
        self.assertEqual(result["unreachable_units"], [])
        self.assertEqual(result["edges"], [])
        self.assertEqual(len(result["frontiers"]), 1)
        self.assertEqual(result["frontiers"][0]["id"], "exit:partial")

    def test_partial_rva_binding_cannot_be_hidden_by_known_unit_ids(self) -> None:
        result = derive_rooted_reachable_units(
            units=[
                {"id": "root", "rva": 0x1000},
                {"id": "known", "rva": 0x1100},
            ],
            roots=["root"],
            recovered_indirect_targets=[
                {
                    "id": "exit:partial-rvas",
                    "source_unit_id": "root",
                    "status": "recovered",
                    "target_rvas": [0x1100, 0x1200],
                    "target_unit_ids": ["known"],
                }
            ],
            indirect_exits=[
                {
                    "id": "exit:partial-rvas",
                    "source_unit_id": "root",
                    "kind": "indirect_jump",
                }
            ],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["reachable_units"], ["root"])
        self.assertEqual(result["edges"], [])
        self.assertEqual(
            [frontier["id"] for frontier in result["frontiers"]],
            ["exit:partial-rvas"],
        )

    def test_finite_external_target_closes_exit_without_internal_edge(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root", "continuation", "unreachable"],
            roots=["root"],
            direct_edges=[{
                "source_unit_id": "root",
                "target_unit_id": "continuation",
            }],
            recovered_indirect_targets=[{
                "id": "exit:external",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "import": {
                        "dll": "user32.dll",
                        "symbol": "ShowWindow",
                    },
                }],
            }],
            indirect_exits=[{
                "id": "exit:external",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["frontiers"], [])
        self.assertEqual(result["reachable_units"], ["continuation", "root"])
        self.assertEqual(result["unreachable_units"], ["unreachable"])
        self.assertEqual(
            result["edges"],
            [{
                "kind": "direct",
                "source_unit_id": "root",
                "target_unit_id": "continuation",
            }],
        )

    def test_profile_bound_interface_method_closes_external_exit(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root", "continuation"],
            roots=["root"],
            direct_edges=[{
                "source_unit_id": "root",
                "target_unit_id": "continuation",
            }],
            recovered_indirect_targets=[{
                "id": "exit:method",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "external_protocol": {
                        "kind": "pe32-interface-method",
                        "profile_id": "fixture",
                        "profile_sha256": "a" * 64,
                        "interface_id": "IThing",
                        "method": "Release",
                        "slot": 2,
                        "offset": 8,
                    },
                    "abi": {
                        "template": "pe32-stdcall-v1",
                        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                        "clobbered_registers": ["eax", "ecx", "edx"],
                        "callee_cleanup": True,
                    },
                    "argument_words": 1,
                    "out_interfaces": [],
                }],
            }],
            indirect_exits=[{
                "id": "exit:method",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["frontiers"], [])

    def test_profile_bound_resolved_export_closes_external_exit(self) -> None:
        target = {"dll": "user32.dll", "symbol": "MessageBoxA"}
        abi = {
            "template": "pe32-stdcall-v1",
            "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            "clobbered_registers": ["eax", "ecx", "edx"],
            "callee_cleanup": True,
        }
        contract = {
            "id": "user32.dll!MessageBoxA",
            "import": target,
            "abi_template": "pe32-stdcall-v1",
            "arity": {"kind": "fixed", "words": 4},
            "disposition": "returns",
            "effect_model": {
                "kind": "exact_native_dll_callthrough_v1",
                "prerequisites": {
                    "same_pinned_dll_implementation": True,
                    "exact_machine_arguments": True,
                    "candidate_address_space_used_directly": True,
                },
            },
            "memory_effect": "nativeCallthrough",
            "memory_footprints": [],
            "world_effect": "nativeCallthrough",
            "callback_effect": "none",
            "result_register_relations": [
                {"register": "eax", "relation": "exact"}
            ],
        }
        result = derive_rooted_reachable_units(
            units=["root", "continuation"],
            roots=["root"],
            direct_edges=[{
                "source_unit_id": "root",
                "target_unit_id": "continuation",
            }],
            recovered_indirect_targets=[{
                "id": "exit:resolved-export",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "external_protocol": {
                        "kind": "pe32-resolved-export",
                        "profile_id": "fixture",
                        "profile_sha256": "c" * 64,
                        "target_id": 1,
                        "resolver_import": {
                            "dll": "kernel32.dll",
                            "symbol": "GetProcAddress",
                        },
                        "loader_import": {
                            "dll": "kernel32.dll",
                            "symbol": "LoadLibraryA",
                        },
                        "module": "user32.dll",
                        "name": "MessageBoxA",
                        "target": target,
                        "transfer_kind": "call",
                        "machine_contract": contract,
                    },
                    "abi": abi,
                    "argument_words": 4,
                    "out_interfaces": [],
                }],
            }],
            indirect_exits=[{
                "id": "exit:resolved-export",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["frontiers"], [])

    def test_malformed_interface_method_target_remains_frontier(self) -> None:
        result = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            recovered_indirect_targets=[{
                "id": "exit:method",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "external_protocol": {
                        "kind": "pe32-interface-method",
                        "profile_id": "fixture",
                        "profile_sha256": "a" * 64,
                        "interface_id": "IThing",
                        "method": "Release",
                        "slot": 2,
                        "offset": 12,
                    },
                    "abi": {"template": "pe32-stdcall-v1"},
                    "argument_words": 1,
                }],
            }],
            indirect_exits=[{
                "id": "exit:method",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(len(result["frontiers"]), 1)

    def test_profile_bound_operation_closes_external_exit(self) -> None:
        target = {
            "external_protocol": {
                "kind": "pe32-operation",
                "profile_id": "fixture",
                "profile_sha256": "b" * 64,
                "operation_id": "surface.blt",
                "transfer_kind": "call",
                "selectors": [{
                    "kind": "table_slot",
                    "operation_id": "surface.blt",
                    "view_id": "ISurface",
                    "slot": 7,
                }],
                "environment_contract_id": "surface.blt.environment",
            },
            "abi": {
                "template": "pe32-stdcall-v1",
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "callee_cleanup": True,
            },
            "argument_words": 6,
            "output_rules": [],
            "environment_contract": {
                "format": "stage-a-external-operation-contract-v1",
                "id": "surface.blt.environment",
                "status": "complete",
                "memory_footprints": [],
                "world_effects": [],
            },
        }
        result = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            recovered_indirect_targets=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [target],
            }],
            indirect_exits=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["frontiers"], [])

    def test_malformed_operation_abi_remains_frontier(self) -> None:
        target = {
            "external_protocol": {
                "kind": "pe32-operation",
                "profile_id": "fixture",
                "profile_sha256": "b" * 64,
                "operation_id": "surface.blt",
                "transfer_kind": "call",
                "selectors": [{
                    "kind": "table_slot",
                    "operation_id": "surface.blt",
                    "view_id": "ISurface",
                    "slot": 7,
                }],
                "environment_contract_id": "surface.blt.environment",
            },
            "abi": {
                "template": "pe32-stdcall-v1",
                "preserved_registers": [],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "callee_cleanup": True,
            },
            "argument_words": 6,
            "output_rules": [],
            "environment_contract": {
                "format": "stage-a-external-operation-contract-v1",
                "id": "surface.blt.environment",
                "status": "complete",
                "memory_footprints": [],
                "world_effects": [],
            },
        }
        result = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            recovered_indirect_targets=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [target],
            }],
            indirect_exits=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "incomplete")

    def test_malformed_operation_environment_contract_remains_frontier(self) -> None:
        target = {
            "external_protocol": {
                "kind": "pe32-operation",
                "profile_id": "fixture",
                "profile_sha256": "b" * 64,
                "operation_id": "surface.lock",
                "transfer_kind": "call",
                "selectors": [{
                    "kind": "table_slot",
                    "operation_id": "surface.lock",
                    "view_id": "ISurface",
                    "slot": 25,
                }],
                "environment_contract_id": "surface.lock.environment",
            },
            "abi": {
                "template": "pe32-stdcall-v1",
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "callee_cleanup": True,
            },
            "argument_words": 2,
            "output_rules": [],
            "environment_contract": {
                "format": "stage-a-external-operation-contract-v1",
                "id": "surface.lock.environment",
                "status": "complete",
                "memory_footprints": [{
                    "access": "write",
                    "base_argument": 2,
                    "offset": 0,
                    "size": {"kind": "fixed", "bytes": 4},
                    "nullable": False,
                }],
                "world_effects": [],
            },
        }
        result = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            recovered_indirect_targets=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [target],
            }],
            indirect_exits=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(len(result["frontiers"]), 1)

        target["environment_contract"] = {
            "format": "stage-a-external-operation-contract-v1",
            "id": "surface.lock.environment",
            "status": "incomplete",
            "blockers": ["external_memory_footprint_not_authored"],
            "memory_footprints": [],
            "world_effects": [],
        }
        incomplete_contract = derive_rooted_reachable_units(
            units=["root"],
            roots=["root"],
            recovered_indirect_targets=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [target],
            }],
            indirect_exits=[{
                "id": "exit:operation",
                "source_unit_id": "root",
                "kind": "indirect_call",
            }],
        )
        self.assertEqual(incomplete_contract["status"], "incomplete")
        self.assertEqual(len(incomplete_contract["frontiers"]), 1)
