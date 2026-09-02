from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.semantic_link.frontiers_v2 import (
    classify_semantic_frontiers_v2,
    derive_callback_capability_obligations_v2,
    derive_internal_dispatch_obligations_v2,
)


def _transfer(
    rva: int, *, call_kind: str | None = None, target_rva: int = 0,
    dll: str | None = None, symbol: str | None = None,
    indirect_terminator: bool = False,
) -> dict[str, object]:
    calls: list[dict[str, object]] = []
    if call_kind is not None:
        calls.append({
            "id": 0,
            "kind": call_kind,
            "instruction_rva": rva + 2,
            "target_rva": target_rva,
            "target_node": 7 if call_kind == "indirect_call" else None,
            "dll": dll,
            "symbol": symbol,
            "ordinal": None,
            "argument_nodes": [],
            "register_nodes": [],
            "flag_nodes": [],
            "stack_inputs": [],
            "return_rva": rva + 6,
            "event_index": 0,
        })
    return {
        "identity": f"semantic-transfer:fixture-{rva:08x}",
        "source": {"rva_start": rva},
        "calls": calls,
        "terminator": (
            {"op": "outcome_indirect", "operands": [9], "parameters": {}}
            if indirect_terminator else
            {"op": "outcome_return", "operands": [], "parameters": {}}
        ),
    }


class SemanticFrontierV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.transfers = [
            _transfer(0x1000, call_kind="internal_call", target_rva=0x2000),
            _transfer(0x2000),
            _transfer(
                0x3000, call_kind="external_call", dll="kernel32.dll",
                symbol="WriteFile",
            ),
            _transfer(0x4000, call_kind="indirect_call"),
            _transfer(0x5000, indirect_terminator=True),
        ]
        self.contracts = [{
            "dll": "kernel32.dll",
            "identity": {
                "dll": "kernel32.dll", "symbol": "WriteFile",
                "ordinal": None,
            },
            "import_kind": "ordinary",
            "cell_index": 0,
            "iat_rva": 0x9000,
            "boundary": {"physical_call_frame_v3": {
                "id": "physical-call-frame-v3:write-file",
            }},
            "root_ids": ["module:process_entry"],
        }]

    def classify(self, blockers: list[dict[str, object]]) -> dict[str, object]:
        return classify_semantic_frontiers_v2(
            fixed_point_blockers=blockers,
            linked_blockers=blockers,
            transfers=self.transfers,
            entry_targets=[0x1000, 0x2000, 0x3000, 0x4000],
            external_contracts=self.contracts,
            transfer_plan_sha256="a" * 64,
            resolved_environment_sha256="b" * 64,
        )

    def test_exact_known_frontiers_become_typed_runtime_obligations(self) -> None:
        result = self.classify([{
            "code": "unresolved_callee_effect_instantiation",
            "source_rva": 0x1000,
            "instruction_rva": 0x1002,
            "call_index": 0,
            "callee_function_rva": 0x2000,
        }, {
            "code": "unresolved_external_memory_write_footprint",
            "source_rva": 0x3000,
            "instruction_rva": 0x3002,
            "call_index": 0,
            "external_targets": [{
                "dll": "kernel32.dll", "identity": "WriteFile",
            }],
        }, {
            "code": "unresolved_reachable_indirect_target",
            "source_rva": 0x4000,
            "site": "call:00004002:0",
            "provenance": [{"kind": "unknown_scalar"}],
        }])

        self.assertEqual(result["semantic_holes"], [])
        self.assertEqual(
            {row["class"] for row in result["residual_obligations"]},
            {
                "object_reference_resolution",
                "external_write_validation",
                "indirect_external_callthrough",
            },
        )
        self.assertEqual(
            {row["class"] for row in result["analysis_frontiers"]},
            {
                "callee_summary_binding",
                "write_boundary_provenance",
                "code_target_provenance",
            },
        )
        indirect = next(
            row for row in result["residual_obligations"]
            if row["class"] == "indirect_external_callthrough"
        )
        callable_domain = next(
            row for row in result["admitted_domains"]
            if row["kind"] == "checked_indirect_callable_targets_v3"
        )
        self.assertEqual(
            callable_domain["guest_transfer_entry_rvas"],
            [0x1000, 0x2000, 0x3000, 0x4000],
        )
        self.assertEqual(
            indirect["admitted_domain"]["domain_sha256"],
            callable_domain["domain_sha256"],
        )

    def test_unknown_code_remains_a_semantic_hole(self) -> None:
        result = self.classify([{
            "code": "new_unreviewed_analysis_failure",
            "source_rva": 0x1000,
        }])

        self.assertEqual(result["residual_obligations"], [])
        self.assertEqual(result["analysis_frontiers"], [])
        self.assertEqual(
            [row["code"] for row in result["semantic_holes"]],
            ["new_unreviewed_analysis_failure"],
        )

    def test_exact_indirect_terminator_uses_the_shared_callable_domain(self) -> None:
        result = classify_semantic_frontiers_v2(
            fixed_point_blockers=[{
                "code": "unresolved_reachable_indirect_target",
                "source_rva": 0x5000,
                "site": "terminator",
                "provenance": [{"kind": "conflict"}],
            }],
            linked_blockers=[{
                "code": "unresolved_reachable_indirect_target",
                "source_rva": 0x5000,
                "site": "terminator",
                "provenance": [{"kind": "conflict"}],
            }],
            transfers=self.transfers,
            entry_targets=[0x1000, 0x2000, 0x3000, 0x4000, 0x5000],
            external_contracts=self.contracts,
            transfer_plan_sha256="a" * 64,
            resolved_environment_sha256="b" * 64,
        )

        self.assertEqual(result["semantic_holes"], [])
        self.assertEqual(
            result["residual_obligations"][0]["class"],
            "internal_code_dispatch",
        )
        callable_domain = result["admitted_domains"][0]
        self.assertEqual(
            callable_domain["kind"], "checked_indirect_callable_targets_v3"
        )
        self.assertEqual(len(callable_domain["external_loader_targets"]), 1)
        self.assertEqual(
            result["residual_obligations"][0]["admitted_domain"][
                "domain_sha256"
            ],
            callable_domain["domain_sha256"],
        )

    def test_known_code_with_wrong_transfer_shape_remains_a_hole(self) -> None:
        blocker = {
            "code": "unresolved_external_memory_write_footprint",
            "source_rva": 0x3000,
            "instruction_rva": 0x3002,
            "call_index": 0,
            "external_targets": [{
                "dll": "kernel32.dll", "identity": "WriteFile",
            }],
        }
        transfers = copy.deepcopy(self.transfers)
        transfers[2]["calls"][0]["kind"] = "internal_call"
        result = classify_semantic_frontiers_v2(
            fixed_point_blockers=[blocker],
            linked_blockers=[blocker],
            transfers=transfers,
            entry_targets=[0x1000, 0x2000, 0x3000, 0x4000],
            external_contracts=self.contracts,
            transfer_plan_sha256="a" * 64,
            resolved_environment_sha256="b" * 64,
        )

        self.assertEqual(len(result["semantic_holes"]), 1)
        self.assertEqual(result["residual_obligations"], [])

    def test_non_fixed_linker_blocker_cannot_be_discharged_by_code(self) -> None:
        fixed = [{
            "code": "unresolved_callee_effect_instantiation",
            "source_rva": 0x1000,
            "instruction_rva": 0x1002,
            "call_index": 0,
            "callee_function_rva": 0x2000,
        }]
        linked = [*fixed, {
            **fixed[0],
            "detail": "independent linker failure",
        }]
        result = classify_semantic_frontiers_v2(
            fixed_point_blockers=fixed,
            linked_blockers=linked,
            transfers=self.transfers,
            entry_targets=[0x1000, 0x2000, 0x3000, 0x4000],
            external_contracts=self.contracts,
            transfer_plan_sha256="a" * 64,
            resolved_environment_sha256="b" * 64,
        )

        self.assertEqual(len(result["semantic_holes"]), 1)
        self.assertEqual(len(result["residual_obligations"]), 1)

    def test_identities_are_content_addressed(self) -> None:
        blocker = {
            "code": "unresolved_reachable_indirect_target",
            "source_rva": 0x4000,
            "site": "call:00004002:0",
            "provenance": [{"kind": "unknown_scalar"}],
        }
        first = self.classify([blocker])
        second = self.classify([copy.deepcopy(blocker)])
        self.assertEqual(first, second)

    def test_may_inventory_includes_sites_not_visited_by_must_analysis(self) -> None:
        result = derive_internal_dispatch_obligations_v2(
            transfers=self.transfers,
            entry_targets=[0x1000, 0x2000, 0x3000, 0x4000, 0x5000],
            active_transfer_ids=[
                "semantic-transfer:fixture-00004000",
                "semantic-transfer:fixture-00005000",
            ],
            transfer_plan_sha256="a" * 64,
            machine_import_contracts=self.contracts,
            resolved_environment_sha256="b" * 64,
        )

        self.assertEqual(len(result["residual_obligations"]), 2)
        self.assertEqual(len(result["admitted_domains"]), 1)
        self.assertEqual(len(result["effects"]), 2)
        self.assertEqual(
            {
                tuple(row["subjects"])
                for row in result["residual_obligations"]
            },
            {
                ("semantic-transfer:fixture-00004000:call:0",),
                ("semantic-transfer:fixture-00005000:terminator",),
            },
        )
        call_obligation = next(
            row for row in result["residual_obligations"]
            if row["subjects"] == [
                "semantic-transfer:fixture-00004000:call:0"
            ]
        )
        self.assertEqual(
            call_obligation["class"], "indirect_external_callthrough"
        )
        callable_domain = next(
            row for row in result["admitted_domains"]
            if row["kind"] == "checked_indirect_callable_targets_v3"
        )
        self.assertEqual(len(callable_domain["external_loader_targets"]), 1)
        self.assertEqual(
            callable_domain["selection"]["ambiguity"], "reject"
        )
        terminator_obligation = next(
            row for row in result["residual_obligations"]
            if row["subjects"] == [
                "semantic-transfer:fixture-00005000:terminator"
            ]
        )
        self.assertEqual(
            terminator_obligation["admitted_domain"],
            call_obligation["admitted_domain"],
        )

    def test_callable_domain_includes_content_bound_interface_methods(
        self,
    ) -> None:
        profile_sha256 = "d" * 64
        method = {
            "external_protocol": {
                "kind": "pe32-interface-method",
                "profile_id": "fixture-interface-profile",
                "profile_sha256": profile_sha256,
                "profile_binding": {
                    "profile_id": "fixture-interface-profile",
                    "profile_sha256": profile_sha256,
                    "receiver_resource": {
                        "argument_index": 0,
                        "view_id": "IFixture",
                        "required_state": "live",
                        "dispatch_slot": 1,
                        "lifecycle_effect": "preserve",
                    },
                },
                "interface_id": "IFixture",
                "method": "Mutate",
                "slot": 1,
                "offset": 4,
            },
            "profile_binding": {
                "profile_id": "fixture-interface-profile",
                "profile_sha256": profile_sha256,
                "receiver_resource": {
                    "argument_index": 0,
                    "view_id": "IFixture",
                    "required_state": "live",
                    "dispatch_slot": 1,
                    "lifecycle_effect": "preserve",
                },
            },
            "abi": {
                "template": "pe32-stdcall-v1",
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "callee_cleanup": True,
            },
            "argument_words": 2,
            "out_interfaces": [],
            "receiver_resource": {
                "argument_index": 0,
                "view_id": "IFixture",
                "required_state": "live",
                "dispatch_slot": 1,
                "lifecycle_effect": "preserve",
            },
            "effect_model": {"kind": "same-library-call-through-v1"},
            "memory_effect": "sameNativeTargetCallThrough",
            "memory_footprints": [],
            "world_effect": "sameNativeTargetCallThrough",
            "callback_effect": "none",
        }
        result = derive_internal_dispatch_obligations_v2(
            transfers=self.transfers,
            entry_targets=[0x1000, 0x2000, 0x3000, 0x4000, 0x5000],
            active_transfer_ids=["semantic-transfer:fixture-00004000"],
            transfer_plan_sha256="a" * 64,
            machine_import_contracts=self.contracts,
            interface_method_catalogs=[{
                "interface_id": "IFixture",
                "profile_id": "fixture-interface-profile",
                "profile_sha256": profile_sha256,
                "vtable": "IFixtureVtbl",
                "methods": [method],
            }],
            resolved_environment_sha256="b" * 64,
        )

        domain = result["admitted_domains"][0]
        self.assertEqual(domain["external_interface_targets"][0]["method"], method)
        self.assertEqual(
            domain["selection"]["interface"],
            "live_factory_interface_vtable_method_capability",
        )
        stale = copy.deepcopy(method)
        stale["external_protocol"]["offset"] = 8
        with self.assertRaisesRegex(ValueError, "stale or duplicated"):
            derive_internal_dispatch_obligations_v2(
                transfers=self.transfers,
                entry_targets=[0x1000, 0x2000, 0x3000, 0x4000, 0x5000],
                active_transfer_ids=["semantic-transfer:fixture-00004000"],
                transfer_plan_sha256="a" * 64,
                machine_import_contracts=self.contracts,
                interface_method_catalogs=[{
                    "interface_id": "IFixture",
                    "profile_id": "fixture-interface-profile",
                    "profile_sha256": profile_sha256,
                    "vtable": "IFixtureVtbl",
                    "methods": [stale],
                }],
                resolved_environment_sha256="b" * 64,
            )

    def test_callback_inventory_is_total_without_must_target_precision(
        self,
    ) -> None:
        callback = _transfer(
            0x6000, call_kind="external_call", dll="kernel32.dll",
            symbol="SetUnhandledExceptionFilter",
        )
        callback["calls"][0]["stack_inputs"] = [[0, 4, 11]]
        protocol = {
            "format": "spaghetti-extractor-callback-protocol-v1",
            "id": "fixture-unhandled-filter",
            "action": "replace",
            "source": {
                "kind": "argument_word", "argument": 0,
                "sentinels": [{"kind": "null", "word": 0}],
            },
            "signature": {
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 1,
                "stack_cleanup_bytes": 4,
                "result": {"kind": "word", "register": "eax"},
            },
            "lifetime": {"kind": "until_process_exit"},
            "delivery": {"thread": "external", "timing": "deferred"},
            "instance": {"kind": "singleton"},
            "previous_result": None,
            "provider_behavior": None,
            "cardinality": {
                "minimum": 0, "maximum": None,
                "scope": "registration_generation",
            },
        }
        contract = {
            "identity": {
                "dll": "kernel32.dll", "symbol":
                "SetUnhandledExceptionFilter", "ordinal": None,
            },
            "contract": {"payload": {
                "callback_effect": "explicit",
                "callback_protocol": protocol,
            }},
            "boundary": {"callback_protocol": protocol},
        }

        result = derive_callback_capability_obligations_v2(
            transfers=[*self.transfers, callback],
            entry_targets=[
                0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000,
            ],
            active_transfer_ids=[
                "semantic-transfer:fixture-00006000",
            ],
            machine_import_contracts=[contract],
            transfer_plan_sha256="a" * 64,
            resolved_environment_sha256="b" * 64,
        )

        self.assertEqual(result["semantic_holes"], [])
        self.assertEqual(len(result["residual_obligations"]), 1)
        self.assertEqual(
            result["residual_obligations"][0]["class"],
            "callback_capability_publication",
        )
        self.assertEqual(len(result["effects"]), 1)
        self.assertEqual(
            result["effects"][0]["callback_source"][
                "direct_expression_node"
            ],
            11,
        )
        self.assertEqual(
            result["admitted_domains"][0]["targets"],
            [0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000],
        )

        protocol["lifetime"] = {
            "kind": "until_resource_event_or_process_exit",
            "end_event": "user32.dll!UnregisterClassA",
        }
        resource_result = derive_callback_capability_obligations_v2(
            transfers=[*self.transfers, callback],
            entry_targets=[
                0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000,
            ],
            active_transfer_ids=["semantic-transfer:fixture-00006000"],
            machine_import_contracts=[contract],
            transfer_plan_sha256="a" * 64,
            resolved_environment_sha256="b" * 64,
        )
        self.assertEqual(resource_result["semantic_holes"], [])
        self.assertEqual(
            resource_result["effects"][0]["lifetime"],
            "until_resource_event_or_process_exit:"
            "user32.dll!UnregisterClassA",
        )

        del protocol["lifetime"]["end_event"]
        missing_event = derive_callback_capability_obligations_v2(
            transfers=[*self.transfers, callback],
            entry_targets=[
                0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000,
            ],
            active_transfer_ids=["semantic-transfer:fixture-00006000"],
            machine_import_contracts=[contract],
            transfer_plan_sha256="a" * 64,
            resolved_environment_sha256="b" * 64,
        )
        self.assertEqual(missing_event["effects"], [])
        self.assertEqual(
            [row["code"] for row in missing_event["semantic_holes"]],
            ["callback_capability_protocol_incomplete"],
        )

    def test_malformed_explicit_callback_contract_is_a_semantic_hole(
        self,
    ) -> None:
        callback = _transfer(
            0x6000, call_kind="external_call", dll="kernel32.dll",
            symbol="SetUnhandledExceptionFilter",
        )
        malformed = {
            "identity": {
                "dll": "kernel32.dll",
                "symbol": "SetUnhandledExceptionFilter",
                "ordinal": None,
            },
            "contract": {"payload": {
                "callback_effect": "explicit",
                "callback_protocol": {"id": "missing-physical-contract"},
            }},
            "boundary": {
                "callback_protocol": {"id": "missing-physical-contract"},
            },
        }

        result = derive_callback_capability_obligations_v2(
            transfers=[*self.transfers, callback],
            entry_targets=[
                0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000,
            ],
            active_transfer_ids=[
                "semantic-transfer:fixture-00006000",
            ],
            machine_import_contracts=[malformed],
            transfer_plan_sha256="a" * 64,
            resolved_environment_sha256="b" * 64,
        )

        self.assertEqual(result["residual_obligations"], [])
        self.assertEqual(result["effects"], [])
        self.assertEqual(
            [row["code"] for row in result["semantic_holes"]],
            ["callback_capability_protocol_incomplete"],
        )


if __name__ == "__main__":
    unittest.main()
