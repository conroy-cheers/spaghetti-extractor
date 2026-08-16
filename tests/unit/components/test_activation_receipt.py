from __future__ import annotations

import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.activation_receipt import (
    ACTIVATION_FACET_IDS,
    ActivationFacetV1,
    ActivationReceiptV1,
)


def _facets() -> dict[str, ActivationFacetV1]:
    result: dict[str, ActivationFacetV1] = {}
    for index, facet_id in enumerate(ACTIVATION_FACET_IDS, start=1):
        digest = f"{index:x}" * 64
        result[facet_id] = ActivationFacetV1.create(
            identity=facet_id,
            status="satisfied" if facet_id in {"source_profile", "semantic_refinement"} else "checked",
            receipt_sha256=digest,
        )
    return result


class ActivationReceiptTests(unittest.TestCase):
    def test_authorizes_only_with_all_exact_satisfied_facets(self) -> None:
        facets = _facets()

        receipt = ActivationReceiptV1.create(facets=facets)

        self.assertEqual(receipt.status, "checked")
        self.assertTrue(receipt.activation_authorized)
        self.assertEqual(receipt.component_id, "component")
        self.assertEqual(
            tuple(item.identity for item in receipt.facets), ACTIVATION_FACET_IDS
        )
        self.assertEqual(receipt.next_actions, ())
        self.assertEqual(ActivationReceiptV1.parse(receipt.to_payload()), receipt)

    def test_stale_hash_fails_closed_and_ranks_refresh_action(self) -> None:
        facets = _facets()
        facets["machine_binding"] = ActivationFacetV1.create(
            identity="machine_binding",
            status="checked",
            receipt_sha256="a" * 64,
            expected_receipt_sha256="b" * 64,
        )

        receipt = ActivationReceiptV1.create(facets=facets)

        self.assertEqual(receipt.status, "violated")
        self.assertFalse(receipt.activation_authorized)
        self.assertEqual(receipt.next_actions[0].rank, 1)
        self.assertEqual(receipt.next_actions[0].facet_id, "machine_binding")
        self.assertEqual(receipt.next_actions[0].code, "refresh_stale_receipt")

    def test_component_identity_is_distinct_from_portable_c_namespace(self) -> None:
        receipt = ActivationReceiptV1.create(
            component_id="directdraw-init", facets=_facets()
        )

        self.assertEqual(receipt.component_id, "directdraw-init")
        self.assertEqual(ActivationReceiptV1.parse(receipt.to_payload()), receipt)

    def test_exact_receipts_bind_component_id_separately_from_interface_id(self) -> None:
        interface = {
            "format": "spaghetti-extractor-component-interface-ir-v2",
            "id": "dxball_directdraw_init",
            "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
            "state": [],
            "operations": [
                {
                    "id": "run",
                    "kind": "operation",
                    "parameters": [],
                    "results": [],
                    "effect_ids": [],
                    "allowed_service_ids": [],
                    "pre_states": ["ready"],
                    "post_states": ["ready"],
                }
            ],
            "effects": [],
            "services": [],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        }
        interface_sha256 = canonical_sha256_v3(interface)
        implementation_sha256 = "a" * 64
        source_plan_sha256 = "e" * 64
        payloads = {
            "source_compile": {
                "format": "fixture-source-compile",
                "status": "checked",
                "component_id": "directdraw-init",
                "interface_id": "dxball_directdraw_init",
                "bindings": {
                    "interface_sha256": interface_sha256,
                    "implementation_sha256": implementation_sha256,
                    "inductive_source_plan_sha256s": [source_plan_sha256],
                },
            },
            "source_profile": {
                "format": "fixture-source-profile",
                "status": "satisfied",
                "component_id": "directdraw-init",
                "bindings": {
                    "implementation_sha256": implementation_sha256,
                },
            },
            "machine_binding": {
                "format": "fixture-machine-binding",
                "status": "checked",
                "bindings": {"interface_sha256": interface_sha256},
            },
            "semantic_refinement": {
                "format": "fixture-semantic-refinement",
                "status": "satisfied",
                "component_id": "directdraw-init",
                "bindings": {
                    "interface_sha256": interface_sha256,
                    "implementation_sha256": implementation_sha256,
                    "semantic_contract_sha256": "c" * 64,
                    "source_profile_sha256": "d" * 64,
                    "source_plan_sha256": source_plan_sha256,
                    "relation_sha256": "f" * 64,
                    "machine_receipt_sha256": "9" * 64,
                },
            },
            "service_graph": {
                "format": "fixture-service-graph",
                "status": "checked",
                "interfaces": [
                    {"id": "dxball_directdraw_init", "sha256": interface_sha256}
                ],
            },
            "ownership": {
                "format": "fixture-ownership",
                "status": "checked",
                "lift_unit_id": "directdraw-init",
                "bindings": {"contract_sha256": "b" * 64},
            },
        }
        source_profile_core = payloads["source_profile"]
        source_profile_core["receipt_sha256"] = canonical_sha256_v3(
            source_profile_core
        )
        payloads["semantic_refinement"]["bindings"][
            "source_profile_sha256"
        ] = source_profile_core["receipt_sha256"]
        for facet_id, payload in payloads.items():
            digest_field = (
                "graph_sha256"
                if facet_id == "service_graph"
                else "activation_plan_sha256"
                if facet_id == "ownership"
                else "receipt_sha256"
            )
            if digest_field not in payload:
                payload[digest_field] = canonical_sha256_v3(payload)

        receipt = ActivationReceiptV1.from_receipts(
            interface=interface,
            source_profile=payloads["source_profile"],
            source_compile=payloads["source_compile"],
            machine_binding=payloads["machine_binding"],
            semantic_refinement=payloads["semantic_refinement"],
            service_graph=payloads["service_graph"],
            ownership=payloads["ownership"],
            component_id="directdraw-init",
        )

        self.assertEqual(receipt.component_id, "directdraw-init")
        self.assertEqual(receipt.status, "checked")
        self.assertTrue(receipt.activation_authorized)

    def test_stale_embedded_receipt_hash_fails_closed(self) -> None:
        interface_sha256 = canonical_sha256_v3(
            {
                "format": "spaghetti-extractor-component-interface-ir-v2",
                "id": "component",
                "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
                "state": [],
                "operations": [
                    {
                        "id": "run",
                        "kind": "operation",
                        "parameters": [],
                        "results": [],
                        "effect_ids": [],
                        "allowed_service_ids": [],
                        "pre_states": ["ready"],
                        "post_states": ["ready"],
                    }
                ],
                "effects": [],
                "services": [],
                "protocol": {"states": ["ready"], "initial_state": "ready"},
            }
        )
        implementation_sha256 = "a" * 64
        receipt_payloads = {
            facet_id: {
                "format": f"fixture-{facet_id}",
                "status": "satisfied" if facet_id in {"source_profile", "semantic_refinement"} else "checked",
            }
            for facet_id in ACTIVATION_FACET_IDS
            if facet_id != "interface"
        }
        receipt_payloads["source_compile"].update(
            {
                "component_id": "component",
                "interface_id": "component",
                "bindings": {
                    "interface_sha256": interface_sha256,
                    "implementation_sha256": implementation_sha256,
                },
            }
        )
        receipt_payloads["source_profile"].update(
            {
                "component_id": "component",
                "bindings": {
                    "implementation_sha256": implementation_sha256,
                },
            }
        )
        receipt_payloads["machine_binding"]["bindings"] = {
            "interface_sha256": interface_sha256
        }
        receipt_payloads["semantic_refinement"].update({
            "component_id": "component",
            "bindings": {
                "interface_sha256": interface_sha256,
                "implementation_sha256": implementation_sha256,
                "semantic_contract_sha256": "c" * 64,
                "source_profile_sha256": "d" * 64,
            },
        })
        receipt_payloads["service_graph"]["interfaces"] = [
            {"id": "component", "sha256": interface_sha256}
        ]
        receipt_payloads["ownership"].update(
            {
                "lift_unit_id": "component",
                "bindings": {"contract_sha256": "b" * 64},
            }
        )
        for facet_id, payload in receipt_payloads.items():
            digest_field = (
                "graph_sha256"
                if facet_id == "service_graph"
                else "activation_plan_sha256"
                if facet_id == "ownership"
                else "receipt_sha256"
            )
            payload[digest_field] = canonical_sha256_v3(payload)
        receipt_payloads["machine_binding"]["receipt_sha256"] = "f" * 64
        interface = {
            "format": "spaghetti-extractor-component-interface-ir-v2",
            "id": "component",
            "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
            "state": [],
            "operations": [
                {
                    "id": "run",
                    "kind": "operation",
                    "parameters": [],
                    "results": [],
                    "effect_ids": [],
                    "allowed_service_ids": [],
                    "pre_states": ["ready"],
                    "post_states": ["ready"],
                }
            ],
            "effects": [],
            "services": [],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        }

        receipt = ActivationReceiptV1.from_receipts(
            interface=interface,
            source_profile=receipt_payloads["source_profile"],
            source_compile=receipt_payloads["source_compile"],
            machine_binding=receipt_payloads["machine_binding"],
            semantic_refinement=receipt_payloads["semantic_refinement"],
            service_graph=receipt_payloads["service_graph"],
            ownership=receipt_payloads["ownership"],
        )

        self.assertEqual(receipt.status, "violated")
        self.assertEqual(receipt.next_actions[0].facet_id, "machine_binding")

    def test_missing_facet_is_incomplete_and_has_deterministic_next_action(self) -> None:
        facets = _facets()
        facets.pop("service_graph")

        receipt = ActivationReceiptV1.create(facets=facets)

        self.assertEqual(receipt.status, "incomplete")
        self.assertFalse(receipt.activation_authorized)
        self.assertEqual(
            [(item.rank, item.facet_id) for item in receipt.next_actions],
            [(1, "service_graph")],
        )


if __name__ == "__main__":
    unittest.main()
