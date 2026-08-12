from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external_interface_profiles import (
    EXTERNAL_INTERFACE_PROFILE_FORMAT,
    InterfaceCallerMemoryFrame,
    InterfaceMemoryArgument,
    SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
    same_library_call_through_effect_json,
)
from spaghetti_extractor.external_profile_authority_v2 import (
    EXTERNAL_PROFILE_AUTHORITY_V2_FORMAT,
    ExternalProfileAuthorityV2Error,
    build_external_profile_authority_v2,
    parse_external_profile_authority_v2,
)
from spaghetti_extractor.machine_abi import resolve_machine_call_abi


def _write(path: Path, payload: dict) -> Path:
    path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    return path


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")).hexdigest()


def _import_entry() -> dict:
    return {
        "id": "fixture.dll!Exact",
        "import": {"dll": "fixture.dll", "symbol": "Exact"},
        "abi_template": "pe32-stdcall-v1",
        "arity": {"kind": "fixed", "words": 0},
        "disposition": "returns",
        "result_register_relations": [],
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": "none",
        "callback_effect": "none",
        "out_pointer_relations": [],
        "out_interface_relations": [],
    }


def _import_profile(path: Path) -> Path:
    return _write(path, {
        "format": "stage-a-static-machine-import-profile-v1",
        "id": "fixture-profile",
        "machine_import_signatures": [_import_entry()],
    })


def _site(*, profile_sha256: str) -> dict:
    return {
        "format": "stage-b-checked-external-site-contract-v1",
        "identity": {
            "kind": "import",
            "dll": "fixture.dll",
            "symbol": "Exact",
            "ordinal": None,
            "protocol": None,
            "profile_id": None,
            "profile_sha256": None,
            "operation": None,
        },
        "transfer_kind": "call",
        "disposition": "returns_here",
        "profile_disposition": "returns",
        "abi_template": "pe32-stdcall-v1",
        "arity": {"kind": "fixed", "words": 0},
        "argument_base_offset": 0,
        "arguments": [],
        "stack_arguments": [],
        "contract_id": "fixture.dll!Exact",
        "profile_binding": {
            "profile_id": "fixture-profile",
            "profile_sha256": profile_sha256,
            "entry_key": "machine_import_signatures",
            "entry_index": 0,
        },
        "result_register_relations": [],
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": "none",
        "callback_effect": "none",
        "callback_adapter": None,
        "out_pointer_relations": [],
        "out_interface_relations": [],
    }


def _interface_profile(path: Path) -> Path:
    abi = resolve_machine_call_abi("pe32-stdcall-v1")
    assert abi is not None
    callthrough = {
        "abi_template": abi.template,
        "machine_abi": abi.as_json(),
        **same_library_call_through_effect_json(),
    }
    return _write(path, {
        "format": EXTERNAL_INTERFACE_PROFILE_FORMAT,
        "id": "interface-profile",
        "model": "x86-pe32",
        "status": "complete",
        "effect_model": SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
        "provenance": {"kind": "pinned_clang_ast_from_reviewed_sdk_headers"},
        "factories": [],
        "interfaces": [{
            "id": "IThing",
            "vtable": "IThingVtbl",
            "methods": [{
                "name": "Release",
                "slot": 0,
                "offset": 0,
                **callthrough,
                "argument_words": 1,
                "caller_memory_frame": InterfaceCallerMemoryFrame((
                    InterfaceMemoryArgument(
                        argument_index=0,
                        role="interface_resource",
                        access="read_write",
                        extent="opaque_resource",
                        retention="during_call",
                    ),
                )).as_json(),
                "out_interfaces": [],
            }],
        }],
    })


def _interface_site(*, profile_sha256: str) -> dict:
    effects = same_library_call_through_effect_json()
    argument = {"op": "input", "name": "this", "width": 32}
    receiver_resource = {
        "argument_index": 0,
        "view_id": "IThing",
        "required_state": "live",
        "dispatch_slot": 0,
        "lifecycle_effect": "may_release",
    }
    return {
        "format": "stage-b-checked-external-site-contract-v1",
        "identity": {
            "kind": "interface",
            "dll": None,
            "symbol": None,
            "ordinal": None,
            "protocol": "pe32-interface-method",
            "profile_id": "interface-profile",
            "profile_sha256": profile_sha256,
            "operation": "IThing::Release",
        },
        "transfer_kind": "call",
        "disposition": "returns_here",
        "profile_disposition": "returns",
        "abi_template": "pe32-stdcall-v1",
        "arity": {"kind": "fixed", "words": 1},
        "argument_base_offset": 0,
        "arguments": [argument],
        "stack_arguments": [{
            "index": 0,
            "offset": 0,
            "width": 4,
            "value": argument,
        }],
        "contract_id": "IThing::Release",
        "profile_binding": {
            "profile_id": "interface-profile",
            "profile_sha256": profile_sha256,
            "receiver_resource": receiver_resource,
        },
        "result_register_relations": [],
        "memory_effect": effects["memory_effect"],
        "memory_footprints": effects["memory_footprints"],
        "world_effect": effects["world_effect"],
        "callback_effect": "none",
        "callback_adapter": None,
        "out_pointer_relations": [],
        "out_interface_relations": [],
    }


class ExternalProfileAuthorityV2Tests(unittest.TestCase):
    def test_serialized_authority_rebuilds_from_embedded_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _import_profile(Path(temporary) / "profile.json")
            authority = build_external_profile_authority_v2([profile])

            parsed = parse_external_profile_authority_v2(authority.payload())

            self.assertEqual(parsed.payload(), authority.payload())

    def test_self_consistent_edited_index_fails_independent_byte_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _import_profile(Path(temporary) / "profile.json")
            payload = copy.deepcopy(
                build_external_profile_authority_v2([profile]).payload()
            )
            entry = payload["entries"][0]
            entry["contract"]["world_effect"] = "invented"
            entry_body = {
                key: value for key, value in entry.items() if key != "entry_id"
            }
            entry["entry_id"] = _canonical_sha256(entry_body)
            authority_body = {
                key: value for key, value in payload.items()
                if key != "authority_id"
            }
            payload["authority_id"] = _canonical_sha256(authority_body)

            with self.assertRaisesRegex(
                ExternalProfileAuthorityV2Error,
                "do not replay from their embedded exact bytes",
            ):
                parse_external_profile_authority_v2(payload)

    def test_exact_direct_import_replays_from_actual_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _import_profile(Path(temporary) / "profile.json")
            authority = build_external_profile_authority_v2([profile])
            digest = hashlib.sha256(profile.read_bytes()).hexdigest()

            replay = authority.replay_lookup(_site(profile_sha256=digest))

            self.assertEqual(replay.status, "complete", replay.message)
            self.assertEqual(authority.payload()["format"], EXTERNAL_PROFILE_AUTHORITY_V2_FORMAT)
            self.assertEqual(authority.artifacts[0].artifact_sha256, digest)
            self.assertEqual(authority.entries[0].family, "machine_import")

    def test_self_consistent_fake_profile_hash_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _import_profile(Path(temporary) / "profile.json")
            authority = build_external_profile_authority_v2([profile])

            replay = authority.replay_lookup(_site(profile_sha256="a" * 64))

            self.assertEqual(replay.status, "violated")
            self.assertEqual(replay.reason_code, "external_profile_hash_mismatch")

    def test_exact_interface_method_replays(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _interface_profile(Path(temporary) / "interface.json")
            authority = build_external_profile_authority_v2([profile])
            digest = hashlib.sha256(profile.read_bytes()).hexdigest()

            replay = authority.replay_lookup(
                _interface_site(profile_sha256=digest)
            )

            self.assertEqual(replay.status, "complete", replay.message)
            assert replay.entry is not None
            self.assertEqual(replay.entry.family, "interface_method")
            self.assertEqual(
                replay.entry.contract["receiver_resource"],
                replay.entry.profile_binding["receiver_resource"],
            )

    def test_receiver_resource_mismatch_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _interface_profile(Path(temporary) / "interface.json")
            authority = build_external_profile_authority_v2([profile])
            site = _interface_site(
                profile_sha256=hashlib.sha256(profile.read_bytes()).hexdigest()
            )
            site["profile_binding"]["receiver_resource"][
                "lifecycle_effect"
            ] = "preserve"

            replay = authority.replay_lookup(site)

            self.assertEqual(replay.status, "violated")
            self.assertEqual(
                replay.reason_code, "external_profile_contract_mismatch"
            )
            self.assertIn("profile_binding", replay.message or "")

    def test_edited_receiver_index_fails_exact_byte_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _interface_profile(Path(temporary) / "interface.json")
            payload = copy.deepcopy(
                build_external_profile_authority_v2([profile]).payload()
            )
            entry = next(
                item for item in payload["entries"]
                if item["family"] == "interface_method"
            )
            entry["contract"]["receiver_resource"][
                "lifecycle_effect"
            ] = "preserve"
            entry["contract"]["profile_binding"]["receiver_resource"][
                "lifecycle_effect"
            ] = "preserve"
            entry_body = {
                key: value for key, value in entry.items() if key != "entry_id"
            }
            entry["entry_id"] = _canonical_sha256(entry_body)
            authority_body = {
                key: value for key, value in payload.items()
                if key != "authority_id"
            }
            payload["authority_id"] = _canonical_sha256(authority_body)

            with self.assertRaisesRegex(
                ExternalProfileAuthorityV2Error,
                "do not replay from their embedded exact bytes",
            ):
                parse_external_profile_authority_v2(payload)

    def test_profile_contract_mismatch_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _interface_profile(Path(temporary) / "interface.json")
            authority = build_external_profile_authority_v2([profile])
            site = _interface_site(
                profile_sha256=hashlib.sha256(profile.read_bytes()).hexdigest()
            )
            site["world_effect"] = "invented"

            replay = authority.replay_lookup(site)

            self.assertEqual(replay.status, "violated")
            self.assertEqual(replay.reason_code, "external_profile_contract_mismatch")
            self.assertIn("world_effect", replay.message or "")

    def test_missing_abi_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _import_profile(Path(temporary) / "profile.json")
            authority = build_external_profile_authority_v2([profile])
            site = _site(
                profile_sha256=hashlib.sha256(profile.read_bytes()).hexdigest()
            )
            site["abi_template"] = None

            replay = authority.replay_lookup(site)

            self.assertEqual(replay.status, "incomplete")
            self.assertEqual(replay.reason_code, "external_site_abi_missing")

    def test_effect_tamper_cannot_be_hidden_by_rehashing_site(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _import_profile(Path(temporary) / "profile.json")
            authority = build_external_profile_authority_v2([profile])
            site = _site(
                profile_sha256=hashlib.sha256(profile.read_bytes()).hexdigest()
            )
            altered = copy.deepcopy(site)
            altered["memory_effect"] = "nativeCallthrough"

            replay = authority.replay_lookup(altered)

            self.assertEqual(replay.status, "violated")

    def test_callable_resolvers_and_targets_are_indexed_separately(self) -> None:
        profile = (
            Path(__file__).resolve().parents[1]
            / "profiles/pe32-kernel32-callable-resolvers-v1.json"
        )
        authority = build_external_profile_authority_v2([profile])
        digest = hashlib.sha256(profile.read_bytes()).hexdigest()
        target = next(
            entry for entry in authority.entries
            if entry.family == "callable_target"
            and entry.contract["contract_id"] == "user32.dll!GetActiveWindow"
        )
        site = {
            "format": "stage-b-checked-external-site-contract-v1",
            "identity": {
                "kind": "resolved_export",
                "dll": "user32.dll",
                "symbol": "GetActiveWindow",
                "ordinal": None,
                "protocol": "pe32-resolved-export",
                "profile_id": "pe32-kernel32-callable-resolvers-v1",
                "profile_sha256": digest,
                "operation": None,
            },
            "transfer_kind": "call",
            "disposition": "returns_here",
            "profile_disposition": "returns",
            "abi_template": "pe32-stdcall-v1",
            "arity": {"kind": "fixed", "words": 0},
            "argument_base_offset": 0,
            "arguments": [],
            "stack_arguments": [],
            "contract_id": "user32.dll!GetActiveWindow",
            "profile_binding": {
                "profile_id": "pe32-kernel32-callable-resolvers-v1",
                "profile_sha256": digest,
            },
            "result_register_relations": [
                {"register": "eax", "relation": "related_word"}
            ],
            "memory_effect": "nativeCallthrough",
            "memory_footprints": [],
            "world_effect": "nativeCallthrough",
            "callback_effect": "none",
            "callback_adapter": None,
            "out_pointer_relations": [],
            "out_interface_relations": [],
        }

        replay = authority.replay_lookup(site)

        self.assertEqual(replay.status, "complete", replay.message)
        self.assertEqual(replay.entry, target)
        resolver = next(
            entry for entry in authority.entries
            if entry.family == "callable_resolver"
        )
        self.assertFalse(resolver.complete)
        self.assertIn("ABI", resolver.failure_reason or "")

    def test_external_operations_and_callbacks_are_exact_index_families(self) -> None:
        from tests.test_external_operation_profiles import profile as operation_profile

        with tempfile.TemporaryDirectory() as temporary:
            profile = _write(
                Path(temporary) / "operations.json",
                operation_profile(),
            )
            authority = build_external_profile_authority_v2([profile])

        families = {entry.family for entry in authority.entries}
        self.assertIn("external_operation", families)
        self.assertIn("callback", families)
        self.assertTrue(all(
            entry.artifact_sha256 == authority.artifacts[0].artifact_sha256
            for entry in authority.entries
        ))
        release = next(
            entry for entry in authority.entries
            if entry.family == "external_operation"
            and entry.contract["contract_id"] == "release"
        )
        self.assertEqual(release.contract["receiver_resource"], {
            "argument_index": 0,
            "view_id": "IRoot",
            "required_state": "live",
            "dispatch_slot": 0,
            "lifecycle_effect": "may_release",
        })
        self.assertEqual(
            release.profile_binding["receiver_resource"],
            release.contract["receiver_resource"],
        )


if __name__ == "__main__":
    unittest.main()
