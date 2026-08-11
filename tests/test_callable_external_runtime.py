from __future__ import annotations

import json
import hashlib
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.callable_external_runtime import (
    CALLABLE_EXTERNAL_RUNTIME_FORMAT,
    CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT,
    CallableExternalRuntimeError,
    build_callable_external_runtime_contract,
    build_callable_external_runtime_contract_v2,
    load_callable_external_runtime_contract,
)
from spaghetti_extractor.external_capabilities import load_callable_external_profile
from spaghetti_extractor.external_site_proposals_v2 import (
    build_external_site_proposals_v2,
)
_DIGEST = "1" * 64


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()


def _v2_inputs(temporary: Path) -> tuple[list[dict], dict, dict, object]:
    profile_path = temporary / "callable-profile.json"
    profile_path.write_text(json.dumps({
        "format": "stage-a-callable-external-profile-v2",
        "id": "test-kernel32-callable-v1",
        "model": "x86-pe32",
        "resolvers": [{
            "id": 0,
            "import": {"dll": "kernel32.dll", "symbol": "GetProcAddress"},
            "result_register": "eax",
            "module_argument_index": 0,
            "identity_argument_indices": [1],
            "nullable": True,
        }],
        "targets": [{
            "id": 7,
            "resolver_id": 0,
            "module": {
                "loader_import": {
                    "dll": "kernel32.dll",
                    "symbol": "GetModuleHandleA",
                },
                "loader_name_argument_index": 0,
                "bytes": list(b"KERNEL32"),
            },
            "identity_arguments": [{
                "kind": "canonical_static_string",
                "index": 1,
                "bytes": list(b"TestFeature"),
            }],
            "target": {"dll": "kernel32.dll", "symbol": "TestFeature"},
            "machine_contract": {
                "id": "kernel32.dll!TestFeature",
                "import": {"dll": "kernel32.dll", "symbol": "TestFeature"},
                "abi_template": "pe32-stdcall-v1",
                "arity": {"kind": "fixed", "words": 1},
                "disposition": "returns",
                "result_register_relations": [
                    {"register": "eax", "relation": "exact"}
                ],
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
            },
            "transfers": ["call"],
        }],
    }), encoding="utf-8")
    profile = load_callable_external_profile(profile_path)
    protocol = {
        "kind": "pe32-resolved-export",
        "profile_id": profile.profile_id,
        "profile_sha256": profile.sha256,
        "target_id": 7,
        "resolver_import": {
            "dll": "kernel32.dll",
            "symbol": "GetProcAddress",
        },
        "loader_import": {
            "dll": "kernel32.dll",
            "symbol": "GetModuleHandleA",
        },
        "module": "KERNEL32",
        "name": "TestFeature",
        "target": {"dll": "kernel32.dll", "symbol": "TestFeature"},
        "transfer_kind": "call",
        "machine_contract": {
            "id": "kernel32.dll!TestFeature",
        },
    }
    external_target = {
        "external_protocol": protocol,
        "abi": {
            "template": "pe32-stdcall-v1",
            "callee_cleanup": True,
            "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            "clobbered_registers": ["eax", "ecx", "edx"],
        },
        "argument_words": 1,
        "out_interfaces": [],
    }
    resolver_unit = "semantic-transfer:resolver"
    call_unit = "semantic-transfer:call"
    rows = [
        {
            "id": resolver_unit,
            "source": {"original": {"rva_start": 0x1100}},
            "semantics": {"external_events": [{
                "kind": "external_call",
                "dll": "kernel32.dll",
                "symbol": "GetProcAddress",
                "instruction_rva": 0x1104,
            }]},
        },
        {
            "id": call_unit,
            "source": {"original": {"rva_start": 0x1200}},
            "semantics": {"external_events": [{
                "kind": "indirect_call",
                "instruction_rva": 0x1202,
                "return_rva": 0x1204,
                "target": {"op": "reg", "name": "eax", "width": 32},
            }]},
        },
    ]
    interprocedural = {
        "format": "stage-a-interprocedural-analysis-v2",
        "status": "incomplete",
        "fixed_point": {"proposal_only": True},
        "recovered_targets": [{
            "id": "indirect-exit:test",
            "source_unit_id": call_unit,
            "source_event_index": 0,
            "status": "recovered",
            "external_targets": [external_target],
            "target_unit_ids": [],
        }],
        "operation_provenance": {
            "call_argument_recoveries": [{
                "status": "complete",
                "unit_id": resolver_unit,
                "event_index": 0,
                "callable_resolver": {
                    "profile_sha256": profile.sha256,
                    "resolver_id": 0,
                },
                "resolved_target": {
                    "dll": "kernel32.dll",
                    "symbol": "TestFeature",
                    "target_id": 7,
                },
            }],
        },
    }
    checked_contract = {
        "format": "stage-b-checked-external-site-contract-v1",
        "identity": {
            "kind": "resolved_export",
            "dll": "kernel32.dll",
            "symbol": "TestFeature",
            "ordinal": None,
            "protocol": "pe32-resolved-export",
            "profile_id": profile.profile_id,
            "profile_sha256": profile.sha256,
            "operation": None,
        },
        "transfer_kind": "call",
        "disposition": "returns_here",
        "profile_disposition": "returns",
        "abi_template": "pe32-stdcall-v1",
        "arity": {"kind": "fixed", "words": 1},
        "argument_base_offset": 4,
        "arguments": [{"op": "const", "value": 0, "width": 32}],
        "stack_arguments": [{
            "index": 0,
            "offset": 4,
            "width": 4,
            "value": {"op": "const", "value": 0, "width": 32},
        }],
        "contract_id": "kernel32.dll!TestFeature",
        "profile_binding": {
            "profile_id": profile.profile_id,
            "profile_sha256": profile.sha256,
        },
        "result_register_relations": [
            {"register": "eax", "relation": "exact"}
        ],
        "memory_effect": "nativeCallthrough",
        "memory_footprints": [],
        "world_effect": "nativeCallthrough",
        "callback_effect": "none",
        "callback_adapter": None,
        "out_pointer_relations": [],
        "out_interface_relations": [],
    }
    proposals = build_external_site_proposals_v2(
        checked_sites=[{
            "unit_id": call_unit,
            "event_index": 0,
            "target_alternative_index": 0,
            "target_alternative_sha256": _canonical_sha256(external_target),
            "contract": checked_contract,
        }],
        pe_sha256="2" * 64,
        machine_ir_sha256="3" * 64,
    )
    return rows, interprocedural, proposals, profile


def _inputs() -> tuple[dict, dict, dict, dict]:
    proposal = {
        "format": "stage-a-callable-external-proposal-v1",
        "status": "ready",
        "inputs": {
            "original_sha256": "2" * 64,
            "state_machine_sha256": "3" * 64,
            "machine_import_report_sha256": "4" * 64,
        },
        "sites": [{
            "boundary_id": 7,
            "instruction_rva": 0x1100,
            "source_rva": 0x10F0,
        }],
        "blockers": [],
    }
    capability = {
        "format": "stage-a-callable-external-capability-v3",
        "resolver_contracts": [{
            "id": 0,
            "machine_contract_id": 7,
            "result_register": "eax",
            "result_relation": "opaque_callable_capability",
            "argument_sources": [
                {"kind": "stack_word", "offset": 0},
                {"kind": "stack_word", "offset": 4},
            ],
            "identity_argument_indices": [1],
            "nullable": True,
        }],
        "capabilities": [{
            "id": 0,
            "resource_id": 0,
            "resolver_contract_id": 0,
            "resolver_site_id": 7,
            "identity_arguments": [{
                "kind": "canonical_static_string",
                "argument_index": 1,
                "target_id": 2,
                "offset": 0,
                "bytes": [102, 111, 111],
            }],
        }],
        "resolved_abi_contracts": [{
            "id": 0,
            "capability_id": 0,
            "transfer": "jump",
            "argument_sources": [],
            "stack_result_delta": 4,
            "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            "clobbered_registers": ["eax", "ecx", "edx"],
            "memory_effect": "none",
            "memory_footprints": [],
            "world_effect": "none",
        }],
    }
    execution = {
        "format": "stage-a-callable-external-execution-v1",
        "sites": [{
            "kind": "resolver",
            "id": 7,
            "source_target_id": 9,
            "machine_contract_id": 7,
            "argument_sources": [
                {"kind": "stack_word", "offset": 0},
                {"kind": "stack_word", "offset": 4},
            ],
            "resolver_contract_id": 0,
            "capability_id": 0,
        }],
    }
    authority = {
        "format": "stage-a-relocated-writable-static-pointer-slot-authorities-v2",
        "artifact_role": {
            "acceptance_authority": False,
            "lean_checker_must_reparse_and_redecode": True,
            "proposal_only": True,
        },
        "inputs": {
            "original_sha256": "2" * 64,
            "state_machine_sha256": "3" * 64,
        },
        "blockers": [],
        "sites": [{
            "source_rva": 0x2100,
            "instruction_rva": 0x2110,
            "slot_rva": 0x3000,
            "transfer_kind": "jump",
            "value_relation": "finite_origins",
            "external_routes": [{
                "resolver_contract_id": 0,
                "capability_id": 0,
                "abi_contract_id": 0,
                "resource_id": 0,
            }],
        }],
    }
    return proposal, capability, execution, authority


class CallableExternalRuntimeTests(unittest.TestCase):
    def test_projects_v2_resolved_export_for_diagnostic_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            rows, interprocedural, proposals, profile = _v2_inputs(
                Path(temporary_name)
            )
            contract = build_callable_external_runtime_contract_v2(
                machine_ir_rows=rows,
                interprocedural=interprocedural,
                external_site_proposals=proposals,
                callable_profiles=(profile,),
                original_sha256="2" * 64,
                machine_ir_sha256="3" * 64,
                interprocedural_sha256="4" * 64,
                external_site_proposals_sha256="5" * 64,
                profile_authority_sha256="6" * 64,
            )
            self.assertEqual(contract.format, CALLABLE_EXTERNAL_RUNTIME_V2_FORMAT)
            self.assertEqual(contract.authority_class, "diagnostic-proposal-v2")
            self.assertEqual(contract.resolvers[0].instruction_rva, 0x1104)
            self.assertEqual(contract.routes[0].instruction_rva, 0x1202)
            self.assertEqual(
                contract.routes[0].checked_external_contract.contract_id,
                "kernel32.dll!TestFeature",
            )
            path = Path(temporary_name) / "runtime-contract.json"
            path.write_text(json.dumps(contract.payload()), encoding="utf-8")
            self.assertEqual(load_callable_external_runtime_contract(path), contract)

    def test_v2_proposal_cannot_claim_static_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            rows, interprocedural, proposals, profile = _v2_inputs(
                Path(temporary_name)
            )
            with self.assertRaisesRegex(
                CallableExternalRuntimeError, "cold-replayed authority"
            ):
                build_callable_external_runtime_contract_v2(
                    machine_ir_rows=rows,
                    interprocedural=interprocedural,
                    external_site_proposals=proposals,
                    callable_profiles=(profile,),
                    original_sha256="2" * 64,
                    machine_ir_sha256="3" * 64,
                    interprocedural_sha256="4" * 64,
                    external_site_proposals_sha256="5" * 64,
                    profile_authority_sha256="6" * 64,
                    authority_class="static-authority-v2",
                )

    def test_projects_and_reloads_one_strict_call_route(self) -> None:
        proposal, capability, execution, authority = _inputs()
        capability["resolved_abi_contracts"][0]["transfer"] = "call"
        authority["sites"][0]["transfer_kind"] = "call"
        contract = build_callable_external_runtime_contract(
            proposal=proposal,
            capability=capability,
            execution=execution,
            writable_slot_authority=authority,
            proposal_sha256=_DIGEST,
            capability_sha256="5" * 64,
            execution_sha256="6" * 64,
            authority_sha256="7" * 64,
        )
        self.assertEqual(contract.routes[0].transfer, "call")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.json"
            path.write_text(json.dumps(contract.payload()), encoding="utf-8")
            self.assertEqual(load_callable_external_runtime_contract(path), contract)

    def test_projects_and_reloads_one_strict_runtime_route(self) -> None:
        proposal, capability, execution, authority = _inputs()
        contract = build_callable_external_runtime_contract(
            proposal=proposal,
            capability=capability,
            execution=execution,
            writable_slot_authority=authority,
            proposal_sha256=_DIGEST,
            capability_sha256="5" * 64,
            execution_sha256="6" * 64,
            authority_sha256="7" * 64,
        )
        payload = contract.payload()
        self.assertEqual(payload["format"], CALLABLE_EXTERNAL_RUNTIME_FORMAT)
        self.assertEqual(payload["counts"], {"resolver_sites": 1, "routes": 1})
        self.assertEqual(payload["resolver_sites"][0]["instruction_rva"], 0x1100)
        self.assertEqual(payload["routes"][0]["source_rva"], 0x2100)
        self.assertEqual(payload["routes"][0]["target_origin"], "writable_static_slot")
        self.assertIsNone(payload["routes"][0]["value_register"])
        self.assertFalse(payload["trust"]["acceptance_authority"])

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.json"
            path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
            loaded = load_callable_external_runtime_contract(path)
        self.assertEqual(loaded, contract)

    def test_projects_checked_resolver_register_tail_route(self) -> None:
        proposal, capability, execution, authority = _inputs()
        authority["sites"][0]["write_origin_evidence"] = [{
            "source_rva": 0x20F0,
            "instruction_rva": 0x20F0,
            "tail_instruction_rva": 0x20FA,
            "value_register": "eax",
            "external_routes": [{
                "resolver_contract_id": 0,
                "capability_id": 0,
                "abi_contract_id": 0,
                "resource_id": 0,
            }],
        }]

        contract = build_callable_external_runtime_contract(
            proposal=proposal,
            capability=capability,
            execution=execution,
            writable_slot_authority=authority,
            proposal_sha256=_DIGEST,
            capability_sha256="5" * 64,
            execution_sha256="6" * 64,
            authority_sha256="7" * 64,
        )

        self.assertEqual(len(contract.routes), 2)
        register_route = next(
            route
            for route in contract.routes
            if route.target_origin == "resolver_result_register"
        )
        self.assertEqual(register_route.source_rva, 0x20F0)
        self.assertEqual(register_route.instruction_rva, 0x20FA)
        self.assertEqual(register_route.value_register, "eax")

    def test_rejects_register_tail_route_without_exact_tail_instruction(self) -> None:
        proposal, capability, execution, authority = _inputs()
        authority["sites"][0]["write_origin_evidence"] = [{
            "source_rva": 0x20F0,
            "instruction_rva": 0x20F0,
            "tail_instruction_rva": None,
            "value_register": "eax",
            "external_routes": [{
                "resolver_contract_id": 0,
                "capability_id": 0,
                "abi_contract_id": 0,
                "resource_id": 0,
            }],
        }]

        with self.assertRaisesRegex(
            CallableExternalRuntimeError, "tail instruction RVA"
        ):
            build_callable_external_runtime_contract(
                proposal=proposal,
                capability=capability,
                execution=execution,
                writable_slot_authority=authority,
                proposal_sha256=_DIGEST,
                capability_sha256="5" * 64,
                execution_sha256="6" * 64,
                authority_sha256="7" * 64,
            )

    def test_rejects_unchecked_route_capability(self) -> None:
        proposal, capability, execution, authority = _inputs()
        authority["sites"][0]["external_routes"][0]["capability_id"] = 19
        with self.assertRaisesRegex(
            CallableExternalRuntimeError, "checked call/jump capability"
        ):
            build_callable_external_runtime_contract(
                proposal=proposal,
                capability=capability,
                execution=execution,
                writable_slot_authority=authority,
                proposal_sha256=_DIGEST,
                capability_sha256="5" * 64,
                execution_sha256="6" * 64,
                authority_sha256="7" * 64,
            )

    def test_rejects_corrupted_contract_identity(self) -> None:
        proposal, capability, execution, authority = _inputs()
        contract = build_callable_external_runtime_contract(
            proposal=proposal,
            capability=capability,
            execution=execution,
            writable_slot_authority=authority,
            proposal_sha256=_DIGEST,
            capability_sha256="5" * 64,
            execution_sha256="6" * 64,
            authority_sha256="7" * 64,
        )
        payload = contract.payload()
        payload["routes"][0]["source_rva"] += 1
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                CallableExternalRuntimeError, "identity is stale"
            ):
                load_callable_external_runtime_contract(path)


if __name__ == "__main__":
    unittest.main()
