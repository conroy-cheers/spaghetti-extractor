from __future__ import annotations

import re
import unittest
from copy import deepcopy
from typing import Any

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.callable_external_capability import (
    CALLABLE_EXTERNAL_CAPABILITY_FORMAT,
    parse_callable_external_capability_artifact,
    relational_callable_external_capability_source,
)


def _artifact() -> dict[str, Any]:
    return {
        "format": CALLABLE_EXTERNAL_CAPABILITY_FORMAT,
        "resolver_contracts": [
            {
                "id": 3,
                "machine_contract_id": 17,
                "result_register": "eax",
                "result_relation": "opaque_callable_capability",
                "argument_sources": [
                    {"kind": "stack_word", "offset": 0},
                    {"kind": "stack_word", "offset": 4},
                ],
                "identity_argument_indices": [0, 1],
                "nullable": True,
            }
        ],
        "capabilities": [
            {
                "id": 41,
                "resource_id": 41,
                "resolver_contract_id": 3,
                "resolver_site_id": 8,
                "identity_arguments": [
                    {"kind": "exact_word", "index": 0, "value": 7},
                    {
                        "kind": "canonical_static_string",
                        "argument_index": 1,
                        "target_id": 5,
                        "offset": 2,
                        "bytes": [114, 117, 110],
                    },
                ],
            }
        ],
        "resolved_abi_contracts": [
            {
                "id": 50,
                "capability_id": 41,
                "transfer": "call",
                "argument_sources": [
                    {"kind": "register", "register": "ecx"},
                    {"kind": "stack_word", "offset": 4},
                ],
                "stack_result_delta": 0,
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "memory_effect": "none",
                "memory_footprints": [],
                "world_effect": "none",
            },
            {
                "id": 51,
                "capability_id": 41,
                "transfer": "jump",
                "argument_sources": [{"kind": "register", "register": "ecx"}],
                "stack_result_delta": 0,
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "memory_effect": "read_only",
                "memory_footprints": [
                    {
                        "access": "read",
                        "base_argument": 0,
                        "offset": 0,
                        "bytes": 8,
                        "nullable": False,
                    }
                ],
                "world_effect": "none",
            },
        ],
    }


class StageACallableExternalCapabilityTests(unittest.TestCase):
    def test_accepts_static_contracts_without_a_submitted_trace(self) -> None:
        artifact = parse_callable_external_capability_artifact(_artifact())

        capability = artifact.capabilities[0]
        self.assertEqual(capability.exact_identities[0].value, 7)
        self.assertEqual(capability.string_identities[0].bytes, (114, 117, 110))
        self.assertEqual(
            artifact.resolved_abi_contracts[0].argument_sources[0].register,
            "ecx",
        )
        self.assertTrue(artifact.resolver_contracts[0].nullable)

    def test_generated_module_has_no_trace_or_environment_authority(self) -> None:
        source = relational_callable_external_capability_source(_artifact())

        self.assertIn("immutableStringIdentityArguments", source)
        self.assertIn("nullable := true", source)
        self.assertIn("argumentSources := [.register .ecx, .stackWord 4]", source)
        self.assertIn("memoryEffect := .readOnly", source)
        self.assertIn("resolvedExternalABIRoutesUniqueChecked", source)
        self.assertNotIn("CallableCapabilityResourceProposal", source)
        self.assertNotIn("originalValue", source)
        self.assertNotIn("candidateValue", source)
        for forbidden in (
            "originalCallableExternalTrace",
            "candidateCallableExternalTrace",
            "EventOrderChecked",
            "EnvironmentRefinesAt :=",
            "native_decide",
        ):
            self.assertNotIn(forbidden, source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_submitted_trace_fields_are_rejected(self) -> None:
        payload = deepcopy(_artifact())
        payload["original_events"] = []

        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            parse_callable_external_capability_artifact(payload)

    def test_ordinary_related_word_result_is_not_callable(self) -> None:
        payload = deepcopy(_artifact())
        payload["resolver_contracts"][0]["result_relation"] = "related_word"

        with self.assertRaisesRegex(StageAInputError, "relatedWord is not callable"):
            parse_callable_external_capability_artifact(payload)

    def test_unknown_resolver_contract_fails_closed(self) -> None:
        payload = deepcopy(_artifact())
        payload["capabilities"][0]["resolver_contract_id"] = 999

        with self.assertRaisesRegex(StageAInputError, "unknown resolver contract"):
            parse_callable_external_capability_artifact(payload)

    def test_submitted_runtime_capability_values_fail_closed(self) -> None:
        payload = deepcopy(_artifact())
        payload["capabilities"][0]["original_value"] = 0x70000010

        with self.assertRaisesRegex(StageAInputError, "unexpected fields"):
            parse_callable_external_capability_artifact(payload)

    def test_wrong_resource_id_fails_closed(self) -> None:
        payload = deepcopy(_artifact())
        payload["capabilities"][0]["resource_id"] = 42

        with self.assertRaisesRegex(StageAInputError, "must equal the capability id"):
            parse_callable_external_capability_artifact(payload)

    def test_identity_inventory_must_be_exact_and_canonical(self) -> None:
        payload = deepcopy(_artifact())
        payload["capabilities"][0]["identity_arguments"].pop()

        with self.assertRaisesRegex(StageAInputError, "exactly cover"):
            parse_callable_external_capability_artifact(payload)

        payload = deepcopy(_artifact())
        payload["capabilities"][0]["identity_arguments"][1]["bytes"] = [65, 0, 66]
        with self.assertRaisesRegex(StageAInputError, "embedded terminators"):
            parse_callable_external_capability_artifact(payload)

    def test_resolver_arguments_must_match_stack_contract_surface(self) -> None:
        payload = deepcopy(_artifact())
        payload["resolver_contracts"][0]["argument_sources"][0] = {
            "kind": "register",
            "register": "ecx",
        }

        with self.assertRaisesRegex(StageAInputError, "exact stack_word"):
            parse_callable_external_capability_artifact(payload)

    def test_unconstrained_resolved_effects_fail_closed(self) -> None:
        payload = deepcopy(_artifact())
        payload["resolved_abi_contracts"][0]["memory_effect"] = "relational_state"
        with self.assertRaisesRegex(StageAInputError, "memory_effect is unsupported"):
            parse_callable_external_capability_artifact(payload)

        payload = deepcopy(_artifact())
        payload["resolved_abi_contracts"][0]["world_effect"] = "opaque_resources"
        with self.assertRaisesRegex(StageAInputError, "world_effect must be none"):
            parse_callable_external_capability_artifact(payload)


if __name__ == "__main__":
    unittest.main()
