from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external_interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    ExternalInterfaceProfileError,
    load_external_interface_profile,
)
from spaghetti_extractor.machine_import_profiles import MachineImportIdentity


def profile() -> dict[str, object]:
    return {
        "format": EXTERNAL_INTERFACE_PROFILE_FORMAT,
        "id": "fixture",
        "model": "x86-pe32",
        "status": "complete",
        "provenance": {"kind": "fixture"},
        "factories": [{
            "id": "factory",
            "import": {"dll": "example.dll", "symbol": "CreateThing"},
            "declaration": "CreateThing",
            "abi_template": "pe32-stdcall-v1",
            "argument_words": 2,
            "out_interfaces": [{
                "argument_index": 1,
                "interface_id": "IThing",
                "write_width": 4,
            }],
        }],
        "interfaces": [{
            "id": "IThing",
            "vtable": "IThingVtbl",
            "methods": [{
                "name": "Release",
                "slot": 0,
                "offset": 0,
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 1,
                "out_interfaces": [],
            }],
        }],
    }


class ExternalInterfaceProfileTests(unittest.TestCase):
    def test_loads_exact_factory_and_method_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(profile()), encoding="utf-8")

            loaded = load_external_interface_profile(path)

        identity = MachineImportIdentity("example.dll", "symbol", "CreateThing")
        self.assertEqual(loaded.factories_by_identity()[identity].argument_words, 2)
        method = loaded.interfaces_by_id()["IThing"].method_at_offset(0)
        self.assertIsNotNone(method)
        assert method is not None
        self.assertEqual(method.name, "Release")
        self.assertEqual(method.receiver_resource.as_json(), {
            "argument_index": 0,
            "view_id": "IThing",
            "required_state": "live",
            "dispatch_slot": 0,
            "lifecycle_effect": "may_release",
        })
        target = method.target_json(
            profile_id=loaded.profile_id,
            profile_sha256=loaded.sha256,
        )
        self.assertEqual(
            target["external_protocol"]["interface_id"],
            "IThing",
        )
        self.assertEqual(
            target["profile_binding"]["receiver_resource"],
            method.receiver_resource.as_json(),
        )

    def test_explicit_receiver_lifecycle_can_strengthen_release(self) -> None:
        payload = profile()
        payload["interfaces"][0]["methods"][0]["receiver_resource"] = {
            "argument_index": 0,
            "view_id": "IThing",
            "required_state": "live",
            "dispatch_slot": 0,
            "lifecycle_effect": "release",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = load_external_interface_profile(path)

        method = loaded.interfaces_by_id()["IThing"].methods[0]
        self.assertEqual(method.receiver_resource.lifecycle_effect, "release")

    def test_rejects_receiver_contract_that_differs_from_dispatch(self) -> None:
        for field, value in (
            ("argument_index", 1),
            ("view_id", "IOther"),
            ("required_state", "unknown"),
            ("dispatch_slot", 1),
            ("lifecycle_effect", "destroy"),
        ):
            malformed = profile()
            malformed["interfaces"][0]["methods"][0]["receiver_resource"] = {
                "argument_index": 0,
                "view_id": "IThing",
                "required_state": "live",
                "dispatch_slot": 0,
                "lifecycle_effect": "may_release",
                field: value,
            }
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory() as temporary:
                    path = Path(temporary) / "profile.json"
                    path.write_text(json.dumps(malformed), encoding="utf-8")
                    with self.assertRaisesRegex(
                        ExternalInterfaceProfileError, "receiver-resource"
                    ):
                        load_external_interface_profile(path)

    def test_rejects_noncontiguous_method_slots(self) -> None:
        malformed = profile()
        malformed["interfaces"][0]["methods"][0]["slot"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(malformed), encoding="utf-8")
            with self.assertRaises(ExternalInterfaceProfileError):
                load_external_interface_profile(path)

    def test_rejects_incomplete_profile(self) -> None:
        malformed = profile()
        malformed["status"] = "incomplete"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(malformed), encoding="utf-8")
            with self.assertRaises(ExternalInterfaceProfileError):
                load_external_interface_profile(path)

    def test_rejects_unknown_output_interface(self) -> None:
        malformed = profile()
        malformed["factories"][0]["out_interfaces"][0]["interface_id"] = "IUnknown"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(malformed), encoding="utf-8")
            with self.assertRaises(ExternalInterfaceProfileError):
                load_external_interface_profile(path)


if __name__ == "__main__":
    unittest.main()
