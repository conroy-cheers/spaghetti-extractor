from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.interface_ir import (
    PortableComponentInterfaceV2,
    PortableComponentInterfaceV3,
)
from spaghetti_extractor.libraries.v4_behavior_pack import (
    build_reusable_library_behavior_pack_v2,
    load_reusable_library_behavior_pack,
    load_reusable_library_behavior_pack_v1,
    load_reusable_library_behavior_pack_v2,
)
from spaghetti_extractor.libraries.v4_behavior_manifest import (
    read_library_behavior_pack_declaration,
)
from spaghetti_extractor.libraries.v4_behavior_records import (
    LIBRARY_BEHAVIOR_CONTRACT_CODEC_V2,
    LibraryBehaviorContractV2,
)

from .test_v4_behavior_pack import _build_fixture, _interface_payload


def _behavior_interface() -> PortableComponentInterfaceV3:
    return PortableComponentInterfaceV3.parse(
        {
            "format": "spaghetti-extractor-component-interface-ir-v3",
            "id": "generic_store",
            "types": [
                {"id": "u32", "kind": "scalar", "c_type": "uint32_t"},
                {
                    "id": "buffer",
                    "kind": "bytes",
                    "access": "read_write",
                    "extent_parameter_id": "length",
                    "nul_terminated": False,
                },
                {
                    "id": "handle",
                    "kind": "resource",
                    "resource_kind": "generic_handle",
                    "ownership": "borrowed",
                },
                {
                    "id": "notify",
                    "kind": "callback",
                    "ownership": "borrowed",
                    "nullable": False,
                    "parameter_type_ids": ["u32"],
                    "result_type_id": None,
                },
            ],
            "state": [{"id": "calls", "type_id": "u32", "initial": 0}],
            "operations": [
                {
                    "id": "apply",
                    "kind": "operation",
                    "parameters": [
                        {"id": "buffer", "type_id": "buffer"},
                        {"id": "length", "type_id": "u32"},
                        {"id": "handle", "type_id": "handle"},
                        {"id": "notify", "type_id": "notify"},
                    ],
                    "results": [],
                    "effect_ids": [
                        "buffer_written",
                        "calls_updated",
                        "handle_used",
                    ],
                    "allowed_service_ids": ["emit"],
                    "pre_states": ["ready"],
                    "post_states": ["ready"],
                }
            ],
            "effects": [
                {
                    "id": "buffer_written",
                    "kind": "memory",
                    "target_id": "buffer",
                    "operation": "write",
                },
                {
                    "id": "calls_updated",
                    "kind": "observable",
                    "target_id": "calls",
                    "operation": "write",
                },
                {
                    "id": "handle_used",
                    "kind": "resource",
                    "target_id": "handle",
                    "operation": "retain",
                },
                {
                    "id": "notify_called",
                    "kind": "callback",
                    "target_id": "notify",
                    "operation": "invoke",
                },
            ],
            "services": [
                {
                    "id": "emit",
                    "parameter_type_ids": ["notify", "u32"],
                    "result_type_id": None,
                    "effect_ids": ["notify_called"],
                }
            ],
            "protocol": {"states": ["ready"], "initial_state": "ready"},
        }
    )


class LibraryBehaviorContractV2Tests(unittest.TestCase):
    def test_contract_canonicalizes_state_and_visible_effects(self) -> None:
        interface = _behavior_interface()
        contract = LibraryBehaviorContractV2.create(interface)
        operation = contract.operations[0]

        self.assertEqual([row.field_id for row in contract.state_fields], ["calls"])
        self.assertEqual(contract.resource_type_ids, ("handle",))
        self.assertEqual(contract.callback_type_ids, ("notify",))
        self.assertEqual(operation.state_effect_ids, ("calls_updated",))
        self.assertEqual(operation.memory_effect_ids, ("buffer_written",))
        self.assertEqual(operation.resource_effect_ids, ("handle_used",))
        self.assertEqual(operation.callback_effect_ids, ("notify_called",))
        self.assertEqual(operation.service_ids, ("emit",))
        self.assertEqual(
            operation.externally_visible_effect_ids,
            ("calls_updated", "handle_used", "notify_called"),
        )
        self.assertEqual(
            LibraryBehaviorContractV2.from_payload(
                contract.to_payload(), "behavior fixture"
            ),
            contract,
        )

    def test_orphan_effect_fails_closed(self) -> None:
        payload = _behavior_interface().to_payload()
        payload["effects"].append(
            {
                "id": "unreachable_write",
                "kind": "memory",
                "target_id": "buffer",
                "operation": "write",
            }
        )
        interface = PortableComponentInterfaceV2.parse(payload)

        with self.assertRaisesRegex(ValueError, "not visible from an operation"):
            LibraryBehaviorContractV2.create(interface)


class ReusableLibraryBehaviorPackV2Tests(unittest.TestCase):
    def _build_v2(self, root: Path):
        fixture = _build_fixture(root)
        inputs = root / "inputs"
        contract = LibraryBehaviorContractV2.create(fixture["interface"])
        contract_path = inputs / "behavior-contract.json"
        LIBRARY_BEHAVIOR_CONTRACT_CODEC_V2.write(contract_path, contract)
        pack = build_reusable_library_behavior_pack_v2(
            implementation=inputs / "implementation.json",
            source_package=inputs / "source-package",
            interface=inputs / "portable-interface.json",
            behavior_contract=contract_path,
            source_profile=inputs / "source-profile.json",
            compile_receipt=inputs / "compile-receipt.json",
            qualification_receipt=inputs / "qualification-receipt.json",
            out_dir=root / "behavior-pack-v2",
        )
        return fixture, contract, pack

    def test_v2_pack_binds_typed_behavior_and_keeps_v1_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture, contract, built = self._build_v2(root)
            loaded = load_reusable_library_behavior_pack_v2(
                root / "behavior-pack-v2" / "behavior-pack.json"
            )

            self.assertTrue(loaded.authority_ready)
            self.assertEqual(loaded.behavior, contract)
            self.assertEqual(loaded.manifest["state_field_ids"], ["total"])
            self.assertEqual(
                loaded.manifest["externally_visible_effect_ids"],
                ["total_updated"],
            )
            self.assertEqual(loaded.pack_sha256, built.pack_sha256)
            self.assertEqual(
                load_reusable_library_behavior_pack(
                    root / "behavior-pack-v2"
                ).pack_sha256,
                built.pack_sha256,
            )
            self.assertEqual(
                read_library_behavior_pack_declaration(
                    root / "behavior-pack-v2"
                ).pack_sha256,
                built.pack_sha256,
            )
            self.assertEqual(
                load_reusable_library_behavior_pack_v1(fixture["root"]).interface,
                fixture["interface"],
            )

    def test_v2_pack_rejects_a_contract_for_another_interface(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _build_fixture(root)
            inputs = root / "inputs"
            other_payload = _interface_payload()
            other_payload["state"] = []
            other_payload["effects"] = []
            for operation in other_payload["operations"]:
                operation["effect_ids"] = []
            other = LibraryBehaviorContractV2.create(
                PortableComponentInterfaceV2.parse(other_payload)
            )
            contract_path = root / "other-behavior-contract.json"
            LIBRARY_BEHAVIOR_CONTRACT_CODEC_V2.write(contract_path, other)

            with self.assertRaisesRegex(
                ValueError, "does not exactly represent the portable interface"
            ):
                build_reusable_library_behavior_pack_v2(
                    implementation=inputs / "implementation.json",
                    source_package=inputs / "source-package",
                    interface=inputs / "portable-interface.json",
                    behavior_contract=contract_path,
                    source_profile=inputs / "source-profile.json",
                    compile_receipt=inputs / "compile-receipt.json",
                    qualification_receipt=inputs / "qualification-receipt.json",
                    out_dir=root / "bad-pack-v2",
                )


if __name__ == "__main__":
    unittest.main()
