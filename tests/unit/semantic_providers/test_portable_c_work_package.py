from __future__ import annotations

import unittest

from spaghetti_extractor.components.work_package_v6 import ComponentWorkPackageV6
from spaghetti_extractor.semantic_link.module_v2 import LinkedSemanticModuleV2
from spaghetti_extractor.semantic_providers.portable_c_work_package import (
    PortableCWorkPackageError,
    _checked_callback_projection_capabilities_v2,
)


_DOMAIN_SHA256 = "a" * 64


class PortableCWorkPackageCallbackTests(unittest.TestCase):
    def _callback_inputs(
        self,
        *,
        targets: list[int] | None = None,
    ) -> tuple[ComponentWorkPackageV6, LinkedSemanticModuleV2, dict[str, object]]:
        authority_id = "projection-key"
        unit_id = "semantic-transfer:callback-site"
        protocol_id = "checked-callback"
        package = ComponentWorkPackageV6(
            payload={
                "operations": [
                    {
                        "machine_projection": {
                            "operation": {
                                "parameters": [
                                    {
                                        "id": "handler",
                                        "projection": {
                                            "kind": "callback_handle",
                                            "authority_id": authority_id,
                                            "protocol_id": protocol_id,
                                            "source": {
                                                "kind": "constant",
                                                "width": 32,
                                                "value": 0x401234,
                                            },
                                        },
                                    }
                                ],
                            },
                            "service_bindings": [
                                {
                                    "mediation": "callback",
                                    "provider": {
                                        "kind": "external_call",
                                        "events": [
                                            {
                                                "unit_id": unit_id,
                                                "event_index": 0,
                                            }
                                        ],
                                        "identity": {
                                            "dll": "provider.dll",
                                            "symbol": "Register",
                                            "ordinal": None,
                                        },
                                    },
                                }
                            ],
                        },
                    }
                ],
            }
        )
        linked = LinkedSemanticModuleV2(
            payload={
                "admitted_domains": [
                    {
                        "domain_sha256": _DOMAIN_SHA256,
                        "kind": "checked_callback_transfer_entry_rvas",
                        "protocol_id": protocol_id,
                        "targets": [0x1234] if targets is None else targets,
                    }
                ],
                "active_symbols": [
                    {
                        "symbol_id": "original:function:callback",
                        "kind": "function",
                        "original_rva": 0x1234,
                    }
                ],
                "effects": {
                    "callbacks": [
                        {
                            "source_transfer_id": unit_id,
                            "call_id": 0,
                            "callback_protocol_id": protocol_id,
                            "external_identity": {
                                "dll": "provider.dll",
                                "symbol": "Register",
                                "ordinal": None,
                            },
                            "admitted_domain": {
                                "kind": "catalog_reference",
                                "domain_sha256": _DOMAIN_SHA256,
                            },
                            "lifetime": "process",
                        }
                    ]
                },
            }
        )
        interface = {"loader": {"preferred_base": 0x400000}}
        return package, linked, interface

    def test_callback_projection_is_derived_from_v2_domain(self) -> None:
        package, linked, interface = self._callback_inputs()
        self.assertEqual(
            _checked_callback_projection_capabilities_v2(
                operations=package.payload["operations"],
                linked=linked,
                module_interface=interface,
            ),
            {
                "projection-key": {
                    "capability_id": "projection-key",
                    "protocol_id": "checked-callback",
                    "target_rva": 0x1234,
                    "target_word": 0x401234,
                    "lifetime": "process",
                },
            },
        )

    def test_callback_projection_outside_v2_domain_fails_closed(self) -> None:
        package, linked, interface = self._callback_inputs(targets=[0x5678])
        with self.assertRaisesRegex(
            PortableCWorkPackageError,
            "outside its checked V2 domain",
        ):
            _checked_callback_projection_capabilities_v2(
                operations=package.payload["operations"],
                linked=linked,
                module_interface=interface,
            )


if __name__ == "__main__":
    unittest.main()
