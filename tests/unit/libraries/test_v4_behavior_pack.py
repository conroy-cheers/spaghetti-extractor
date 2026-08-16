from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Callable

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.compile_receipt import (
    COMPONENT_COMPILE_RECEIPT_V1,
)
from spaghetti_extractor.components.formats import (
    COMPONENT_REFINEMENT_RECEIPT_V1_FORMAT,
)
from spaghetti_extractor.components.interface_ir import PortableComponentInterfaceV2
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.source_profile import (
    check_component_source_profile,
)
from spaghetti_extractor.libraries.v4_adoption_records import (
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
    LibraryOperationSourceMappingV1,
    ReusableLibraryImplementationV1,
)
from spaghetti_extractor.libraries.v4_behavior_manifest import (
    LibraryBehaviorManifestError,
    read_library_behavior_pack_declaration_v1,
)
from spaghetti_extractor.libraries.v4_behavior_pack import (
    LibraryBehaviorPackError,
    build_reusable_library_behavior_pack_v1,
    load_reusable_library_behavior_pack_v1,
)
from spaghetti_extractor.libraries.v4_identity_records import (
    LibraryIslandIssueV4,
)
from spaghetti_extractor.libraries.v4_record_support import canonical_sha256
from spaghetti_extractor.util import sha256_file, write_json


def _digest(character: str) -> str:
    return character * 64


def _interface_payload() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-component-interface-ir-v2",
        "id": "library_counter",
        "types": [{"id": "u32", "kind": "scalar", "c_type": "uint32_t"}],
        "state": [{"id": "total", "type_id": "u32", "initial": 0}],
        "operations": [
            {
                "id": "accumulate",
                "kind": "operation",
                "parameters": [{"id": "amount", "type_id": "u32"}],
                "results": [{"id": "total", "type_id": "u32"}],
                "effect_ids": ["total_updated"],
                "allowed_service_ids": [],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            },
            {
                "id": "reset",
                "kind": "operation",
                "parameters": [],
                "results": [],
                "effect_ids": ["total_updated"],
                "allowed_service_ids": [],
                "pre_states": ["ready"],
                "post_states": ["ready"],
            },
        ],
        "effects": [
            {
                "id": "total_updated",
                "kind": "observable",
                "target_id": "total",
                "operation": "write",
            }
        ],
        "services": [],
        "protocol": {"states": ["ready"], "initial_state": "ready"},
    }


def _write_self_hashed(
    path: Path,
    payload: dict[str, object],
    *,
    field: str = "receipt_sha256",
) -> dict[str, object]:
    core = dict(payload)
    core.pop(field, None)
    result = {**core, field: canonical_sha256_v3(core)}
    write_json(path, result)
    return result


def _rewrite_self_hashed(
    path: Path, mutate: Callable[[dict[str, object]], None]
) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.pop("receipt_sha256")
    mutate(payload)
    _write_self_hashed(path, payload)


def _rebind_behavior_manifest_artifact(root: Path, artifact_id: str) -> None:
    path = root / "behavior-pack.json"
    manifest = json.loads(path.read_text(encoding="utf-8"))
    relative = manifest["artifacts"][artifact_id]["path"]
    manifest["artifacts"][artifact_id]["sha256"] = sha256_file(root / relative)
    manifest.pop("pack_sha256")
    manifest["pack_sha256"] = canonical_sha256(manifest)
    write_json(path, manifest)


def _build_fixture(root: Path, *, stateless: bool = False) -> dict[str, object]:
    inputs = root / "inputs"
    inputs.mkdir()

    interface_payload = _interface_payload()
    if stateless:
        interface_payload["state"] = []
        interface_payload["effects"] = []
        for operation in interface_payload["operations"]:
            operation["effect_ids"] = []
    interface = PortableComponentInterfaceV2.parse(interface_payload)
    interface_path = inputs / "portable-interface.json"
    write_json(interface_path, interface_payload)

    source_file = inputs / "library-counter.c"
    stateful_source = (
        "uint32_t library_counter_accumulate(\n"
        "    spx_library_counter_context_v2 *context, uint32_t amount) {\n"
        "  context->state.total += amount;\n"
        "  return context->state.total;\n"
        "}\n\n"
        "void library_counter_reset(spx_library_counter_context_v2 *context) {\n"
        "  context->state.total = UINT32_C(0);\n"
        "}\n"
    )
    stateless_source = (
        "uint32_t library_counter_accumulate(uint32_t amount) {\n"
        "  return amount;\n"
        "}\n\n"
        "void library_counter_reset(void) {\n"
        "}\n"
    )
    source_file.write_text(
        '#include "portable-component-implementation.h"\n\n'
        + (stateless_source if stateless else stateful_source),
        encoding="ascii",
    )
    source_path = inputs / "source-package"
    source = build_component_source_package(
        lift_unit_id="library_counter",
        files={"library-counter.c": source_file},
        shared_inputs={},
        operation_symbols={
            "accumulate": "library_counter_accumulate",
            "reset": "library_counter_reset",
        },
        out_dir=source_path,
    )

    source_profile = check_component_source_profile(package=source_path)
    source_profile_path = inputs / "source-profile.json"
    write_json(source_profile_path, source_profile)

    compile_output = inputs / "compile-output"
    compile_output.mkdir()
    host_shared = compile_output / "component.so"
    pe32_object = compile_output / "component-pe32.o"
    host_shared.write_bytes(b"ELF fixture host shared object")
    pe32_object.write_bytes(b"COFF fixture PE32 object")
    compile_receipt_path = inputs / "compile-receipt.json"
    compile_receipt = _write_self_hashed(
        compile_receipt_path,
        {
            "format": COMPONENT_COMPILE_RECEIPT_V1,
            "status": "checked",
            "component_id": source["lift_unit_id"],
            "interface_id": interface.identity,
            "bindings": {
                "interface_sha256": interface.sha256,
                "implementation_sha256": source["implementation_sha256"],
                "inductive_source_plan_sha256s": [],
            },
            "operation_symbols": source["operation_symbols"],
            "toolchains": {
                "host_compiler": "/nix/store/fixture-host-cc/bin/cc",
                "pe32_compiler": "/nix/store/fixture-pe32-cc/bin/i686-w64-mingw32-cc",
            },
            "artifacts": {
                "host_shared": {
                    "path": host_shared.name,
                    "sha256": sha256_file(host_shared),
                },
                "pe32_object": {
                    "path": pe32_object.name,
                    "sha256": sha256_file(pe32_object),
                },
            },
            "policy": {
                "portable_interface_v2": True,
                "host_and_pe32_abi_checked": True,
                "framework_managed_state": True,
                "component_mutable_globals_forbidden": True,
                "inductive_public_wrappers_framework_generated": True,
            },
        },
    )

    qualification_path = inputs / "qualification-receipt.json"
    qualification = _write_self_hashed(
        qualification_path,
        {
            "format": COMPONENT_REFINEMENT_RECEIPT_V1_FORMAT,
            "status": "satisfied",
            "activation_authorized": True,
            "component_id": source["lift_unit_id"],
            "bindings": {
                "semantic_contract_sha256": _digest("a"),
                "interface_sha256": interface.sha256,
                "implementation_sha256": source["implementation_sha256"],
                "source_profile_sha256": source_profile["receipt_sha256"],
            },
            "checker": {
                "id": "cbmc",
                "version": "6.4.1",
                "sha256": _digest("b"),
                "architecture": "i386-win32",
                "timeout_seconds": 120,
            },
            "checks": [
                {
                    "operation_id": operation_id,
                    "status": "satisfied",
                    "code": "refinement_satisfied",
                    "properties": 4,
                    "property_ids": [f"{operation_id}.assertion.1"],
                    "model": {
                        "kind": "finite-machine-paths-v1",
                        "path_count": 1,
                        "max_service_events": 0,
                        "service_ids": [],
                        "state_ids": [] if stateless else ["total"],
                    },
                }
                for operation_id in ("accumulate", "reset")
            ],
            "issues": [],
            "policy": {
                "original_binary_executed": False,
                "operator_behavior_examples_used": False,
                "cbmc_is_pinned_trusted_checker": True,
                "finite_unwinding_cannot_authorize_loops": True,
                "unsupported_semantics_fail_closed": True,
            },
        },
    )

    mappings = tuple(
        LibraryOperationSourceMappingV1.create(
            operation_id=operation_id,
            source_id=str(source["lift_unit_id"]),
            source_symbol=source_symbol,
            source_sha256=str(source["implementation_sha256"]),
        )
        for operation_id, source_symbol in source["operation_symbols"].items()
    )
    implementation = ReusableLibraryImplementationV1.create(
        family_id="fixture-runtime",
        recipe_id="recipe.library-counter.portable-v1",
        compatible_release_ids=("fixture-runtime-1.0",),
        operation_source_mappings=mappings,
        interface_contract_ids=(interface.identity,),
        effect_contract_ids=tuple(effect.identity for effect in interface.effects),
        compile_profile_id=str(source_profile["profile_id"]),
        qualification_checker_id=str(qualification["checker"]["id"]),
        qualification_receipt_sha256=str(qualification["receipt_sha256"]),
    )
    implementation_path = inputs / "implementation.json"
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.write(
        implementation_path, implementation
    )

    pack_path = root / "behavior-pack"
    built = build_reusable_library_behavior_pack_v1(
        implementation=implementation_path,
        source_package=source_path,
        interface=interface_path,
        source_profile=source_profile_path,
        compile_receipt=compile_receipt_path,
        qualification_receipt=qualification_path,
        out_dir=pack_path,
    )
    return {
        "root": pack_path,
        "built": built,
        "implementation": implementation,
        "source": source,
        "interface": interface,
        "source_profile": source_profile,
        "compile_receipt": compile_receipt,
        "qualification": qualification,
    }


class ReusableLibraryBehaviorPackV1Tests(unittest.TestCase):
    def test_build_and_strict_load_bind_real_component_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]
            loaded = load_reusable_library_behavior_pack_v1(
                root / "behavior-pack.json"
            )

            self.assertEqual(loaded.pack_sha256, fixture["built"].pack_sha256)
            self.assertEqual(loaded.implementation, fixture["implementation"])
            self.assertEqual(loaded.source, fixture["source"])
            self.assertEqual(loaded.interface, fixture["interface"])
            self.assertEqual(loaded.source_profile, fixture["source_profile"])
            self.assertEqual(loaded.compile_receipt, fixture["compile_receipt"])
            self.assertEqual(
                loaded.qualification_receipt, fixture["qualification"]
            )
            self.assertEqual(
                set(loaded.manifest["artifacts"]),
                {
                    "implementation",
                    "source_manifest",
                    "interface",
                    "source_profile",
                    "compile_receipt",
                    "qualification_receipt",
                },
            )

    def test_source_byte_corruption_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]
            source = root / "source-package/sources/library-counter.c"
            source.write_text(
                source.read_text(encoding="ascii").replace("+=", "-="),
                encoding="ascii",
            )

            with self.assertRaisesRegex(ValueError, "source hash is stale"):
                load_reusable_library_behavior_pack_v1(root)

    def test_valid_interface_corruption_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]
            path = root / "portable-interface.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["id"] = "library_counter_changed"
            write_json(path, payload)

            with self.assertRaisesRegex(
                LibraryBehaviorPackError, "source package and portable interface"
            ):
                load_reusable_library_behavior_pack_v1(root)

    def test_rehashed_compile_receipt_corruption_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]

            def corrupt(payload: dict[str, object]) -> None:
                payload["bindings"]["interface_sha256"] = _digest("f")

            _rewrite_self_hashed(root / "compile-receipt.json", corrupt)
            with self.assertRaisesRegex(
                LibraryBehaviorPackError, "compile receipt is incomplete or stale"
            ):
                load_reusable_library_behavior_pack_v1(root)

    def test_rehashed_qualification_receipt_corruption_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]

            def corrupt(payload: dict[str, object]) -> None:
                payload["policy"]["original_binary_executed"] = True

            _rewrite_self_hashed(root / "qualification-receipt.json", corrupt)
            with self.assertRaisesRegex(
                LibraryBehaviorPackError,
                "static qualification receipt is incomplete or stale",
            ):
                load_reusable_library_behavior_pack_v1(root)

    def test_rehashed_operation_inventory_corruption_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]
            path = root / "source-package/source-package.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload.pop("implementation_sha256")
            del payload["operation_symbols"]["reset"]
            payload["implementation_sha256"] = canonical_sha256_v3(payload)
            write_json(path, payload)

            with self.assertRaisesRegex(
                LibraryBehaviorPackError, "operation inventories differ"
            ):
                load_reusable_library_behavior_pack_v1(root)

    def test_incomplete_implementation_status_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]
            complete = fixture["implementation"]
            issue = LibraryIslandIssueV4.create(
                family="implementation",
                status="incomplete",
                code="qualification_under_review",
                message="qualification has not been accepted",
                location="qualification",
            )
            incomplete = ReusableLibraryImplementationV1.create(
                family_id=complete.family_id,
                recipe_id=complete.recipe_id,
                compatible_release_ids=complete.compatible_release_ids,
                operation_source_mappings=complete.operation_source_mappings,
                interface_contract_ids=complete.interface_contract_ids,
                effect_contract_ids=complete.effect_contract_ids,
                compile_profile_id=complete.compile_profile_id,
                qualification_checker_id=complete.qualification_checker_id,
                qualification_receipt_sha256=(
                    complete.qualification_receipt_sha256
                ),
                issues=(issue,),
            )
            REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.write(
                root / "implementation.json", incomplete
            )

            with self.assertRaisesRegex(
                LibraryBehaviorPackError, "implementation is not complete"
            ):
                load_reusable_library_behavior_pack_v1(root)

    def test_non_authorizing_receipt_statuses_are_rejected(self) -> None:
        cases = (
            ("source-profile.json", "incomplete", "source profile"),
            ("compile-receipt.json", "incomplete", "compile receipt"),
            (
                "qualification-receipt.json",
                "incomplete",
                "static qualification receipt",
            ),
        )
        for relative, status, message in cases:
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                fixture = _build_fixture(Path(temporary))
                root = fixture["root"]

                def corrupt(payload: dict[str, object]) -> None:
                    payload["status"] = status
                    if relative == "qualification-receipt.json":
                        payload["activation_authorized"] = False

                _rewrite_self_hashed(root / relative, corrupt)
                with self.assertRaisesRegex(LibraryBehaviorPackError, message):
                    load_reusable_library_behavior_pack_v1(root)


class LibraryBehaviorManifestV1Tests(unittest.TestCase):
    def test_reads_a_complete_pack_from_directory_or_manifest_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]
            from_directory = read_library_behavior_pack_declaration_v1(root)
            from_path = read_library_behavior_pack_declaration_v1(
                root / "behavior-pack.json"
            )

            self.assertEqual(from_directory, from_path)
            self.assertEqual(
                from_directory.implementation, fixture["implementation"]
            )
            self.assertEqual(
                from_directory.pack_sha256, fixture["built"].pack_sha256
            )

    def test_every_inventoried_artifact_is_content_checked(self) -> None:
        artifacts = {
            "implementation": "implementation.json",
            "source_manifest": "source-package/source-package.json",
            "interface": "portable-interface.json",
            "source_profile": "source-profile.json",
            "compile_receipt": "compile-receipt.json",
            "qualification_receipt": "qualification-receipt.json",
        }
        for artifact_id, relative in artifacts.items():
            with self.subTest(artifact_id=artifact_id), tempfile.TemporaryDirectory() as temporary:
                fixture = _build_fixture(Path(temporary))
                root = fixture["root"]
                path = root / relative
                path.write_bytes(path.read_bytes() + b"\n")

                with self.assertRaisesRegex(
                    LibraryBehaviorManifestError,
                    f"artifact {artifact_id!r} has a stale hash",
                ):
                    read_library_behavior_pack_declaration_v1(root)

    def test_status_corruption_fails_after_outer_manifest_is_rebound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]
            path = root / "implementation.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["status"] = "incomplete"
            write_json(path, payload)
            _rebind_behavior_manifest_artifact(root, "implementation")

            with self.assertRaisesRegex(ValueError, "status must equal"):
                read_library_behavior_pack_declaration_v1(root)

    def test_manifest_hash_and_artifact_paths_are_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]
            path = root / "behavior-pack.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["pack_sha256"] = _digest("0")
            write_json(path, manifest)
            with self.assertRaisesRegex(
                LibraryBehaviorManifestError, "manifest hash is stale"
            ):
                read_library_behavior_pack_declaration_v1(root)

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _build_fixture(Path(temporary))
            root = fixture["root"]
            path = root / "behavior-pack.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest.pop("pack_sha256")
            manifest["artifacts"]["interface"]["path"] = "interface.json"
            manifest["pack_sha256"] = canonical_sha256(manifest)
            write_json(path, manifest)
            with self.assertRaisesRegex(
                LibraryBehaviorManifestError, "interface.*stale path"
            ):
                read_library_behavior_pack_declaration_v1(root)


if __name__ == "__main__":
    unittest.main()
