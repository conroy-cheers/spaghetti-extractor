from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.callable_external_runtime import (
    CALLABLE_EXTERNAL_RUNTIME_FORMAT,
    CallableExternalRuntimeError,
    build_callable_external_runtime_contract,
    load_callable_external_runtime_contract,
)
_DIGEST = "1" * 64


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
