from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.components.interface_ir import PortableComponentInterfaceV2
from spaghetti_extractor.components.service_graph import (
    ServiceGraphConfigurationV1,
    ServiceGraphV1,
    build_service_graph,
)


def _interface(
    component_id: str,
    operation_id: str,
    *,
    service_id: str | None = None,
    operation_kind: str = "operation",
) -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-component-interface-ir-v2",
        "id": component_id,
        "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
        "state": [],
        "operations": [
            {
                "id": operation_id,
                "kind": operation_kind,
                "parameters": [{"id": "argument", "type_id": "u32"}],
                "results": [{"id": "result", "type_id": "u32"}],
                "effect_ids": ["observed"],
                "allowed_service_ids": [] if service_id is None else [service_id],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            }
        ],
        "effects": [
            {
                "id": "observed",
                "kind": "observable",
                "target_id": None,
                "operation": "emit",
            }
        ],
        "services": (
            []
            if service_id is None
            else [
                {
                    "id": service_id,
                    "parameter_type_ids": ["u32"],
                    "result_type_id": "u32",
                    "effect_ids": ["observed"],
                }
            ]
        ),
        "protocol": {
            "states": ["ready"],
            "initial_state": "ready",
        },
    }


def _aggregate_interface(
    component_id: str,
    operation_id: str,
    *,
    type_prefix: str,
    service_id: str | None = None,
) -> dict[str, object]:
    def type_id(name: str) -> str:
        return f"{type_prefix}_{name}"

    return {
        "format": "spaghetti-extractor-component-interface-ir-v3",
        "id": component_id,
        "types": [
            {"id": type_id("word"), "kind": "scalar", "c_type": "uint32_t"},
            {"id": type_id("status"), "kind": "enum", "c_type": "int32_t"},
            {
                "id": type_id("payload"),
                "kind": "bytes",
                "access": "read",
                "extent_parameter_id": "extent",
                "nul_terminated": False,
            },
            {
                "id": type_id("handle"),
                "kind": "resource",
                "resource_kind": "stream_handle",
                "ownership": "borrowed",
            },
            {
                "id": type_id("completion"),
                "kind": "callback",
                "ownership": "borrowed",
                "nullable": False,
                "parameter_type_ids": [type_id("status"), type_id("handle")],
                "result_type_id": type_id("word"),
            },
            {
                "id": type_id("request"),
                "kind": "record",
                "access": "read",
                "fields": [
                    {"id": "sequence", "type_id": type_id("word")},
                    {"id": "status", "type_id": type_id("status")},
                    {"id": "payload", "type_id": type_id("payload")},
                    {"id": "handle", "type_id": type_id("handle")},
                    {"id": "completion", "type_id": type_id("completion")},
                ],
            },
        ],
        "state": [],
        "operations": [
            {
                "id": operation_id,
                "kind": "operation",
                "parameters": [
                    {"id": "request", "type_id": type_id("request")},
                    {"id": "extent", "type_id": type_id("word")},
                ],
                "results": [
                    {"id": "response", "type_id": type_id("request")},
                ],
                "effect_ids": ["observed"],
                "allowed_service_ids": [] if service_id is None else [service_id],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            }
        ],
        "effects": [
            {
                "id": "observed",
                "kind": "observable",
                "target_id": None,
                "operation": "emit",
            }
        ],
        "services": (
            []
            if service_id is None
            else [
                {
                    "id": service_id,
                    "parameter_type_ids": [type_id("request"), type_id("word")],
                    "result_type_id": type_id("request"),
                    "effect_ids": ["observed"],
                }
            ]
        ),
        "protocol": {
            "states": ["ready"],
            "initial_state": "ready",
        },
    }


def _logical_type(payload: dict[str, object], type_id: str) -> dict[str, object]:
    types = payload["types"]
    assert isinstance(types, list)
    for logical_type in types:
        assert isinstance(logical_type, dict)
        if logical_type.get("id") == type_id:
            return logical_type
    raise AssertionError(f"unknown test logical type {type_id!r}")


def _configuration(*bindings: dict[str, object]) -> ServiceGraphConfigurationV1:
    return ServiceGraphConfigurationV1.create(
        identity="development", bindings=list(bindings)
    )


def _component_binding(
    consumer: str,
    service: str,
    provider: str,
    operation: str,
    *,
    mediation: str = "direct",
) -> dict[str, object]:
    return {
        "component_id": consumer,
        "service_id": service,
        "provider": {
            "kind": "component_operation",
            "component_id": provider,
            "operation_id": operation,
        },
        "mediation": mediation,
    }


def _aggregate_component_graph(
    provider_payload: dict[str, object],
) -> ServiceGraphV1:
    consumer = PortableComponentInterfaceV2.parse(
        _aggregate_interface(
            "consumer",
            "run",
            type_prefix="consumer",
            service_id="calculate",
        )
    )
    provider = PortableComponentInterfaceV2.parse(provider_payload)
    return build_service_graph(
        interfaces={"consumer": consumer, "provider": provider},
        configuration=_configuration(
            _component_binding("consumer", "calculate", "provider", "calculate")
        ),
    )


class ServiceGraphTests(unittest.TestCase):
    def test_accepts_structurally_compatible_checked_views(self) -> None:
        def interface(component_id: str, *, service: bool) -> dict[str, object]:
            prefix = "consumer" if service else "provider"
            types = [
                {"id": f"{prefix}_u8", "kind": "scalar", "c_type": "uint8_t"},
                {"id": f"{prefix}_u32", "kind": "scalar", "c_type": "uint32_t"},
                {
                    "id": f"{prefix}_span",
                    "kind": "view",
                    "element_type_id": f"{prefix}_u8",
                    "access": "read",
                    "extent": {"kind": "parameter", "parameter_id": "count"},
                    "ownership": "borrowed",
                },
            ]
            return {
                "format": "spaghetti-extractor-component-interface-ir-v4",
                "id": component_id,
                "types": types,
                "state": [],
                "operations": [{
                    "id": "run" if service else "compare",
                    "kind": "operation",
                    "parameters": [
                        {"id": "span", "type_id": f"{prefix}_span"},
                        {"id": "count", "type_id": f"{prefix}_u32"},
                    ],
                    "results": [],
                    "effect_ids": [],
                    "allowed_service_ids": ["compare"] if service else [],
                    "pre_states": ["ready"],
                    "post_states": ["ready"],
                }],
                "effects": [],
                "services": ([{
                    "id": "compare",
                    "parameter_type_ids": [
                        f"{prefix}_span", f"{prefix}_u32"
                    ],
                    "result_type_id": None,
                    "effect_ids": [],
                }] if service else []),
                "protocol": {"states": ["ready"], "initial_state": "ready"},
            }

        graph = build_service_graph(
            interfaces={
                "consumer": PortableComponentInterfaceV2.parse(
                    interface("consumer", service=True)
                ),
                "provider": PortableComponentInterfaceV2.parse(
                    interface("provider", service=False)
                ),
            },
            configuration=_configuration(
                _component_binding("consumer", "compare", "provider", "compare")
            ),
        )
        self.assertEqual(graph.status, "checked")

    def test_accepts_compatible_component_provider_and_orders_provider_first(self) -> None:
        consumer = PortableComponentInterfaceV2.parse(
            _interface("consumer", "run", service_id="calculate")
        )
        provider = PortableComponentInterfaceV2.parse(
            _interface("provider", "calculate")
        )

        graph = build_service_graph(
            interfaces={"consumer": consumer, "provider": provider},
            configuration=_configuration(
                _component_binding(
                    "consumer", "calculate", "provider", "calculate"
                )
            ),
        )

        self.assertEqual(graph.status, "checked")
        self.assertTrue(graph.activation_authorized)
        self.assertEqual(graph.activation_order, (("provider",), ("consumer",)))
        self.assertEqual(ServiceGraphV1.parse(graph.to_payload()), graph)

    def test_accepts_external_provider_only_with_exact_signature_and_effects(self) -> None:
        consumer = PortableComponentInterfaceV2.parse(
            _interface("consumer", "run", service_id="calculate")
        )
        binding = {
            "component_id": "consumer",
            "service_id": "calculate",
            "provider": {
                "kind": "external_site",
                "site_id": "external-site-v3:" + "a" * 64,
                "parameter_type_ids": ["u32"],
                "result_type_id": "u32",
                "effect_ids": ["observed"],
            },
            "mediation": "direct",
        }

        graph = build_service_graph(
            interfaces={"consumer": consumer},
            configuration=_configuration(binding),
        )

        self.assertEqual(graph.status, "checked")

    def test_missing_provider_is_incomplete_but_not_authorizing(self) -> None:
        consumer = PortableComponentInterfaceV2.parse(
            _interface("consumer", "run", service_id="calculate")
        )

        graph = build_service_graph(
            interfaces={"consumer": consumer},
            configuration=_configuration(),
        )

        self.assertEqual(graph.status, "incomplete")
        self.assertFalse(graph.activation_authorized)
        self.assertEqual(graph.issues[0].code, "unresolved_required_service")

    def test_incompatible_provider_is_violated(self) -> None:
        consumer = PortableComponentInterfaceV2.parse(
            _interface("consumer", "run", service_id="calculate")
        )
        provider_payload = copy.deepcopy(_interface("provider", "calculate"))
        provider_payload["types"][0]["c_type"] = "int32_t"  # type: ignore[index]
        provider = PortableComponentInterfaceV2.parse(provider_payload)

        graph = build_service_graph(
            interfaces={"consumer": consumer, "provider": provider},
            configuration=_configuration(
                _component_binding(
                    "consumer", "calculate", "provider", "calculate"
                )
            ),
        )

        self.assertEqual(graph.status, "violated")
        self.assertFalse(graph.activation_authorized)
        self.assertIn(
            "component_service_parameter_mismatch",
            {issue.code for issue in graph.issues},
        )

    def test_accepts_recursively_compatible_aggregate_types_with_distinct_ids(
        self,
    ) -> None:
        graph = _aggregate_component_graph(
            _aggregate_interface(
                "provider", "calculate", type_prefix="provider"
            )
        )

        self.assertEqual(graph.status, "checked")
        self.assertTrue(graph.activation_authorized)

    def test_rejects_nested_representation_and_record_field_mismatches(self) -> None:
        cases = (
            ("scalar", "provider_word", "c_type", "uint64_t"),
            ("enum", "provider_status", "c_type", "uint32_t"),
            ("record access", "provider_request", "access", "write"),
        )
        for label, type_id, field, value in cases:
            with self.subTest(label=label):
                provider = _aggregate_interface(
                    "provider", "calculate", type_prefix="provider"
                )
                _logical_type(provider, type_id)[field] = value

                graph = _aggregate_component_graph(provider)

                self.assertEqual(graph.status, "violated")
                self.assertIn(
                    "component_service_parameter_mismatch",
                    {issue.code for issue in graph.issues},
                )

        provider = _aggregate_interface(
            "provider", "calculate", type_prefix="provider"
        )
        fields = _logical_type(provider, "provider_request")["fields"]
        assert isinstance(fields, list)
        assert isinstance(fields[0], dict)
        fields[0]["id"] = "different_sequence"

        graph = _aggregate_component_graph(provider)

        self.assertEqual(graph.status, "violated")

    def test_rejects_nested_bytes_access_and_bounds_metadata_mismatches(self) -> None:
        provider = _aggregate_interface(
            "provider", "calculate", type_prefix="provider"
        )
        _logical_type(provider, "provider_payload")["access"] = "write"

        graph = _aggregate_component_graph(provider)

        self.assertEqual(graph.status, "violated")

        provider = _aggregate_interface(
            "provider", "calculate", type_prefix="provider"
        )
        payload_type = _logical_type(provider, "provider_payload")
        payload_type["extent_parameter_id"] = None
        payload_type["nul_terminated"] = True

        graph = _aggregate_component_graph(provider)

        self.assertEqual(graph.status, "violated")

        provider = _aggregate_interface(
            "provider", "calculate", type_prefix="provider"
        )
        _logical_type(provider, "provider_payload")["extent_parameter_id"] = (
            "provider_extent"
        )
        operations = provider["operations"]
        assert isinstance(operations, list)
        assert isinstance(operations[0], dict)
        parameters = operations[0]["parameters"]
        assert isinstance(parameters, list)
        assert isinstance(parameters[1], dict)
        parameters[1]["id"] = "provider_extent"

        graph = _aggregate_component_graph(provider)

        self.assertEqual(graph.status, "violated")

    def test_rejects_nested_resource_kind_and_ownership_mismatches(self) -> None:
        provider = _aggregate_interface(
            "provider", "calculate", type_prefix="provider"
        )
        _logical_type(provider, "provider_handle")["resource_kind"] = "file_handle"

        graph = _aggregate_component_graph(provider)

        self.assertEqual(graph.status, "violated")
        self.assertIn(
            "component_service_parameter_mismatch",
            {issue.code for issue in graph.issues},
        )

        provider = _aggregate_interface(
            "provider", "calculate", type_prefix="provider"
        )
        _logical_type(provider, "provider_handle")["ownership"] = "retained"

        graph = _aggregate_component_graph(provider)

        self.assertEqual(graph.status, "violated")
        self.assertIn(
            "resource_ownership_mismatch",
            {issue.code for issue in graph.issues},
        )

    def test_rejects_nested_callback_capability_and_signature_mismatches(self) -> None:
        cases = (
            ("ownership", "ownership", "retained"),
            ("nullability", "nullable", True),
            ("parameters", "parameter_type_ids", ["provider_word"]),
            ("result", "result_type_id", None),
        )
        for label, field, value in cases:
            with self.subTest(label=label):
                provider = _aggregate_interface(
                    "provider", "calculate", type_prefix="provider"
                )
                _logical_type(provider, "provider_completion")[field] = value

                graph = _aggregate_component_graph(provider)

                self.assertEqual(graph.status, "violated")
                self.assertIn(
                    "component_service_parameter_mismatch",
                    {issue.code for issue in graph.issues},
                )

    def test_external_aggregate_types_are_wiring_not_refinement_authority(self) -> None:
        consumer = PortableComponentInterfaceV2.parse(
            _aggregate_interface(
                "consumer",
                "run",
                type_prefix="consumer",
                service_id="calculate",
            )
        )
        providers = (
            {
                "kind": "external_site",
                "site_id": "external-site-v3:" + "a" * 64,
                "parameter_type_ids": ["consumer_request", "consumer_word"],
                "result_type_id": "consumer_request",
                "effect_ids": ["observed"],
            },
            {
                "kind": "machine_events",
                "event_ids": ["unit:event"],
                "parameter_type_ids": ["consumer_request", "consumer_word"],
                "result_type_id": "consumer_request",
                "effect_ids": ["observed"],
            },
        )
        for provider in providers:
            with self.subTest(kind=provider["kind"]):
                graph = build_service_graph(
                    interfaces={"consumer": consumer},
                    configuration=_configuration(
                        {
                            "component_id": "consumer",
                            "service_id": "calculate",
                            "provider": provider,
                            "mediation": "direct",
                        }
                    ),
                )

                self.assertEqual(graph.status, "checked")
                self.assertTrue(graph.activation_authorized)
                self.assertEqual(graph.issues, ())

    def test_rejects_cycle_with_a_direct_edge(self) -> None:
        left = PortableComponentInterfaceV2.parse(
            _interface("left", "invoke", service_id="call_right")
        )
        right = PortableComponentInterfaceV2.parse(
            _interface("right", "invoke", service_id="call_left")
        )

        graph = build_service_graph(
            interfaces={"left": left, "right": right},
            configuration=_configuration(
                _component_binding("left", "call_right", "right", "invoke"),
                _component_binding("right", "call_left", "left", "invoke"),
            ),
        )

        self.assertEqual(graph.status, "violated")
        self.assertIn(
            "forbidden_service_dependency_cycle",
            {issue.code for issue in graph.issues},
        )

    def test_accepts_cycle_when_every_edge_is_explicitly_callback_mediated(self) -> None:
        left = PortableComponentInterfaceV2.parse(
            _interface(
                "left", "invoke", service_id="call_right", operation_kind="callback"
            )
        )
        right = PortableComponentInterfaceV2.parse(
            _interface(
                "right", "invoke", service_id="call_left", operation_kind="callback"
            )
        )

        graph = build_service_graph(
            interfaces={"left": left, "right": right},
            configuration=_configuration(
                _component_binding(
                    "left",
                    "call_right",
                    "right",
                    "invoke",
                    mediation="callback",
                ),
                _component_binding(
                    "right",
                    "call_left",
                    "left",
                    "invoke",
                    mediation="callback",
                ),
            ),
        )

        self.assertEqual(graph.status, "checked")
        self.assertTrue(graph.activation_authorized)
        self.assertEqual(graph.mediated_cycles, (("left", "right"),))
        self.assertEqual(graph.activation_order, (("left", "right"),))


if __name__ == "__main__":
    unittest.main()
