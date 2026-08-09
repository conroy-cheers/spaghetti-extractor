from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from spaghetti_extractor.external_interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
    ExternalInterfaceProfileError,
    InterfaceCallerMemoryFrame,
    InterfaceMemoryArgument,
    load_external_interface_profile,
    same_library_call_through_effect_json,
)
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.machine_import_profiles import (
    MachineImportProfileError,
    load_machine_import_profile_set,
)


def profile() -> dict[str, Any]:
    abi = resolve_machine_call_abi("pe32-stdcall-v1")
    assert abi is not None
    contract = {
        "abi_template": abi.template,
        "machine_abi": abi.as_json(),
        **same_library_call_through_effect_json(),
    }
    factory_memory_frame = InterfaceCallerMemoryFrame((
        InterfaceMemoryArgument(
            argument_index=0,
            role="caller_memory",
            access="read_write",
            extent="fixed_word",
            retention="during_call",
        ),
    )).as_json()
    method_memory_frame = InterfaceCallerMemoryFrame((
        InterfaceMemoryArgument(
            argument_index=0,
            role="interface_resource",
            access="read_write",
            extent="opaque_resource",
            retention="during_call",
        ),
    )).as_json()
    return {
        "format": EXTERNAL_INTERFACE_PROFILE_FORMAT,
        "id": "fixture",
        "model": "x86-pe32",
        "status": "complete",
        "effect_model": SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
        "provenance": {
            "kind": "pinned_clang_ast_from_reviewed_sdk_headers",
        },
        "factories": [{
            "id": "factory",
            "import": {"dll": "example.dll", "symbol": "CreateThing"},
            "declaration": "CreateThing",
            **contract,
            "caller_memory_frame": factory_memory_frame,
            "argument_words": 1,
            "out_interfaces": [{
                "argument_index": 0,
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
                **contract,
                "caller_memory_frame": method_memory_frame,
                "argument_words": 1,
                "out_interfaces": [],
            }],
        }],
    }


def load(payload: dict[str, Any]) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "profile.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        load_external_interface_profile(path)


class ExternalInterfaceCallThroughTests(unittest.TestCase):
    def test_factory_signature_round_trips_through_machine_import_loader(self) -> None:
        payload = profile()
        factory = payload["factories"][0]
        payload["machine_import_signatures"] = [{
            "id": 0,
            "import": factory["import"],
            "abi_template": factory["abi_template"],
            "machine_abi": factory["machine_abi"],
            "argument_words": factory["argument_words"],
            "result_register_relations": [
                {"register": "eax", "relation": "exact"}
            ],
            **same_library_call_through_effect_json(),
            "caller_memory_frame": factory["caller_memory_frame"],
            "out_interface_relations": [],
        }]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "profile.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            selected = load_machine_import_profile_set([path])
            self.assertEqual(len(selected.contracts), 1)

            malformed = copy.deepcopy(payload)
            malformed["machine_import_signatures"][0]["effect_model"][
                "target_relation"
            ] = "unreviewed-target"
            path.write_text(json.dumps(malformed), encoding="utf-8")
            with self.assertRaises(MachineImportProfileError):
                load_machine_import_profile_set([path])

    def test_sdk_profile_requires_effect_model_opt_in(self) -> None:
        malformed = profile()
        del malformed["effect_model"]

        with self.assertRaisesRegex(
            ExternalInterfaceProfileError, "no reviewed.*call-through effect model"
        ):
            load(malformed)

    def test_rejects_machine_abi_or_effect_field_removal(self) -> None:
        missing_fields = (
            ("factories", "machine_abi"),
            ("methods", "callback_effect"),
        )
        for container, field in missing_fields:
            with self.subTest(container=container, field=field):
                malformed = copy.deepcopy(profile())
                entry = (
                    malformed["factories"][0]
                    if container == "factories"
                    else malformed["interfaces"][0]["methods"][0]
                )
                del entry[field]

                with self.assertRaises(ExternalInterfaceProfileError):
                    load(malformed)

    def test_rejects_invented_pointed_to_footprints(self) -> None:
        malformed = copy.deepcopy(profile())
        malformed["interfaces"][0]["methods"][0]["memory_footprints"] = [{
            "access": "write",
            "base_argument": 0,
            "offset": 0,
            "size": {"kind": "fixed", "bytes": 4},
            "nullable": False,
        }]

        with self.assertRaisesRegex(
            ExternalInterfaceProfileError, "invalid.*call-through effect contract"
        ):
            load(malformed)


if __name__ == "__main__":
    unittest.main()
