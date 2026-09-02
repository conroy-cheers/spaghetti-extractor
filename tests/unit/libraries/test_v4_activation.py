from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.artifacts.formats import (
    LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
)
from spaghetti_extractor.external.resolved import bind_launch_policy_v1
from spaghetti_extractor.libraries.abi_catalog import (
    LIBRARY_ABI_CATALOG_CODEC_V3,
    build_catalog_search_index,
)
from spaghetti_extractor.libraries.v4_activation import check_library_island_v1
from spaghetti_extractor.semantic_link.module_v2 import LinkedSemanticModuleV2
from spaghetti_extractor.libraries.v4_adoption_records import (
    LibraryAdoptionIntentV1,
    LibraryOperationSourceMappingV1,
    ReusableLibraryImplementationV1,
)
from spaghetti_extractor.libraries.v4_identity_records import (
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4,
    LibraryFunctionMatchV4,
    LibraryIslandHypothesisV4,
    LibraryReleaseHypothesesV4,
)
from spaghetti_extractor.libraries.v4_record_support import (
    canonical_sha256,
)
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.transfer.plan import write_executable_transfer_plan

from .library_fixture_support import (
    abi_profile,
    catalog,
    function_signature,
    machine_unit,
    write_machine,
)


@dataclass(frozen=True)
class _Fixture:
    root: Path
    release_root: Path
    island: LibraryIslandHypothesisV4
    implementation: ReusableLibraryImplementationV1
    intent: LibraryAdoptionIntentV1
    catalog_index: object
    linked_semantic_module: LinkedSemanticModuleV2


def _implementation(*, recipe_id: str, operation_id: str) -> ReusableLibraryImplementationV1:
    mapping = LibraryOperationSourceMappingV1.create(
        operation_id=operation_id,
        source_id=f"source:{recipe_id}",
        source_symbol=f"portable_{recipe_id.replace('-', '_')}",
        source_sha256="d" * 64,
    )
    return ReusableLibraryImplementationV1.create(
        family_id="fixture-family",
        recipe_id=recipe_id,
        compatible_release_ids=("1.0",),
        operation_source_mappings=(mapping,),
        interface_contract_ids=("interface:x86-cdecl",),
        effect_contract_ids=("effects:no-crossing",),
        compile_profile_id="compile:mingw32-c11",
        qualification_checker_id="checker:fixture-v1",
        qualification_receipt_sha256="e" * 64,
    )


def _write_release_set(root: Path, release: LibraryReleaseHypothesesV4) -> Path:
    output = root / "release-hypotheses"
    output.mkdir()
    filename = "release.json"
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.write(output / filename, release)
    manifest_core = {
        "format": LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
        "target_id": release.target_id,
        "target_binary_sha256": release.target_binary_sha256,
        "target_signature_graph_sha256": release.target_signature_graph_sha256,
        "catalog_search_index_sha256": release.catalog_search_index_sha256,
        "releases": [
            {
                "family_id": release.family_id,
                "release_id": release.release_id,
                "path": filename,
                "hypotheses_sha256": release.hypotheses_sha256,
                "status": release.status,
            }
        ],
    }
    write_json(
        output / "manifest.json",
        {**manifest_core, "manifest_sha256": canonical_sha256(manifest_core)},
    )
    return output


def _resolved_environment(root: Path, pe_sha256: str) -> Path:
    launch = {
        "assumptions": {
            name: {"contract": f"fixture-{name}"}
            for name in (
                "argv", "environment", "fs", "iat", "initial_stack",
                "relocations",
            )
        },
        "feature_inventory": {
            "direct_syscalls": [], "executable_writes": [], "threads": [],
            "unknown_async_callbacks": [], "unmodelled_seh": [],
        },
        "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
        "schema_version": 1,
    }
    payload = {
        "format": "spaghetti-extractor-resolved-external-environment-v1",
        "status": "complete",
        "bindings": {
            "module_interface_sha256": "1" * 64,
            "module_pe_sha256": pe_sha256,
            "environment_intent_sha256": "3" * 64,
            "runtime_profile_pack_sha256s": [],
            "interface_profile_pack_sha256s": [],
        },
        "target": {"abi": "pe32-i686-mingw32", "data_layout": "pe32-ilp32-v1"},
        "launch_policy": bind_launch_policy_v1(
            launch, source_sha256="4" * 64, filename="fixture-launch.json"
        ),
        "canonical_boundaries": [], "interface_method_catalogs": [],
        "machine_import_contracts": [], "original_semantic_imports": [],
        "generated_runtime_support_imports": [],
        "loader_service_contracts": [], "static_authority_bindings": [],
        "checked_exception_protocols": [], "blockers": [],
        "authority": "checked_static_environment",
    }
    payload["resolved_environment_sha256"] = canonical_sha256_v3(payload)
    output = root / "resolved-environment.json"
    write_json(output, payload)
    return output


def _fixture(
    root: Path,
    *,
    catalog_abi: str | None = "x86-cdecl",
    external_event: bool = False,
    indirect_exit: bool = False,
) -> _Fixture:
    operation_id = "catalog-operation"
    events = (
        (
            {
                "family": "external",
                "kind": "external_call",
                "instruction_rva": 0x1000,
                "target_rva": 0,
                "return_rva": 0x1004,
                "dll": "KERNEL32.dll",
                "symbol": "WriteFile",
                "ordinal": None,
                "abi_profile_id": "x86-cdecl",
                "register_inputs": {
                    name: {"op": "reg", "name": name, "width": 32}
                    for name in (
                        "eax", "ebx", "ecx", "edx",
                        "esi", "edi", "ebp", "esp",
                    )
                },
                "flag_inputs": {
                    name: {"op": "flag", "name": name}
                    for name in ("cf", "zf", "sf", "of", "pf", "df")
                },
                "arguments": [],
                "stack_inputs": [],
            },
        )
        if external_event
        else ()
    )
    unit = machine_unit(
        "library-unit",
        0x1000,
        "a" * 64,
        abi_profile(),
        external_events=events,
        control_kind="indirect_call" if indirect_exit else "return",
        extra=(
            {
                "control": {
                    "kind": "indirect_call",
                    "direct_targets": [],
                    "has_indirect_target": True,
                }
            }
            if indirect_exit
            else None
        ),
    )
    if events:
        unit["semantics"]["ordered_events"] = list(events)
    if indirect_exit:
        unit["semantics"]["outcome"] = {
            "kind": "indirect_jump",
            "target": {"op": "reg", "name": "eax", "width": 32},
        }
    machine = write_machine(root, [unit])
    transfer_root = root / "transfer"
    write_executable_transfer_plan(
        machine_ir=machine / "machine-ir.jsonl",
        machine_ir_manifest=machine / "machine-ir-manifest.json",
        out=transfer_root,
    )
    function = function_signature(
        function_id=operation_id,
        release="1.0",
        exact_hash=None,
        abi_profile_id=catalog_abi,
    )
    catalog_path = root / "catalog.json"
    LIBRARY_ABI_CATALOG_CODEC_V3.write(catalog_path, catalog((function,)))
    catalog_index = build_catalog_search_index(
        catalog_path, root / "catalog-search-index.json"
    )
    implementation = _implementation(
        recipe_id="portable-fixture", operation_id=operation_id
    )
    match = LibraryFunctionMatchV4.create(
        target_function_id="target-region",
        target_span_start=0x1000,
        target_span_end=0x1008,
        target_unit_ids=("library-unit",),
        catalog_function_id=operation_id,
        evidence=("unit_merkle",),
        score=70,
    )
    island = LibraryIslandHypothesisV4.create(
        target_id="fixture-target",
        family_id="fixture-family",
        release_id="1.0",
        target_unit_ids=("library-unit",),
        member_ids=("runtime.obj",),
        catalog_function_ids=(operation_id,),
        operation_ids=(operation_id,),
        matches=(match,),
        implementation_ids=(implementation.implementation_id,),
    )
    release = LibraryReleaseHypothesesV4.create(
        target_id="fixture-target",
        family_id="fixture-family",
        release_id="1.0",
        target_binary_sha256=sha256_file(root / "fixture.exe"),
        target_signature_graph_sha256="b" * 64,
        catalog_search_index_sha256=catalog_index.index_sha256,
        catalog_release_sha256="c" * 64,
        islands=(island,),
    )
    release_root = _write_release_set(root, release)
    intent = LibraryAdoptionIntentV1.create(
        target_id="fixture-target",
        island_id=island.island_id,
        hypotheses_sha256=release.hypotheses_sha256,
        implementation_id=implementation.implementation_id,
        mode="adopt",
    )
    resolved_environment = _resolved_environment(
        root, sha256_file(root / "fixture.exe")
    )
    return _Fixture(
        root=root,
        release_root=release_root,
        island=island,
        implementation=implementation,
        intent=intent,
        catalog_index=catalog_index,
        linked_semantic_module=LinkedSemanticModuleV2(
            payload={
                "format": "spaghetti-extractor-linked-semantic-module-v2",
            },
            package_root=root,
            package_members={
                "transfer_plan": transfer_root / "executable-transfer-plan.json",
                "resolved_external_environment": resolved_environment,
            },
        ),
    )


def _check(
    fixture: _Fixture,
    *,
    intent: LibraryAdoptionIntentV1 | None = None,
    implementation: ReusableLibraryImplementationV1 | None = None,
    name: str,
):
    return check_library_island_v1(
        target_id="fixture-target",
        linked_semantic_module=fixture.linked_semantic_module,
        release_hypotheses=fixture.release_root,
        island_id=fixture.island.island_id,
        adoption_intent=intent or fixture.intent,
        implementation=implementation or fixture.implementation,
        catalog_search_index=fixture.catalog_index,
        out=fixture.root / f"{name}.json",
    )


class V4LibraryActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_island_waits_for_semantic_module_physical_abi_authority(self) -> None:
        fixture = _fixture(self.root)

        receipt = _check(fixture, name="abi-unresolved")

        self.assertEqual(receipt.status, "incomplete")
        self.assertEqual(receipt.identity_status, "complete")
        self.assertEqual(receipt.boundary_status, "incomplete")
        self.assertEqual(receipt.implementation_status, "complete")
        self.assertEqual(receipt.checked_boundary_edge_ids, ())
        self.assertIn(
            "target_operation_physical_abi_unresolved",
            {issue.code for issue in receipt.issues},
        )

    def test_stale_intent_and_wrong_implementation_are_violated(self) -> None:
        fixture = _fixture(self.root)
        stale = LibraryAdoptionIntentV1.create(
            target_id="fixture-target",
            island_id=fixture.island.island_id,
            hypotheses_sha256="0" * 64,
            implementation_id=fixture.implementation.implementation_id,
            mode="adopt",
        )
        stale_receipt = _check(fixture, intent=stale, name="stale")
        self.assertEqual(stale_receipt.status, "violated")
        self.assertIn(
            "adoption_hypotheses_stale",
            {issue.code for issue in stale_receipt.issues},
        )

        wrong = _implementation(
            recipe_id="different-portable-fixture",
            operation_id="catalog-operation",
        )
        wrong_receipt = _check(fixture, implementation=wrong, name="wrong")
        self.assertEqual(wrong_receipt.status, "violated")
        self.assertIn(
            "adoption_implementation_mismatch",
            {issue.code for issue in wrong_receipt.issues},
        )

    def test_missing_catalog_abi_fails_closed(self) -> None:
        fixture = _fixture(self.root, catalog_abi=None)

        receipt = _check(fixture, name="missing-abi")

        self.assertEqual(receipt.status, "incomplete")
        self.assertIn(
            "target_operation_physical_abi_unresolved",
            {issue.code for issue in receipt.issues},
        )

    def test_missing_resolved_external_contract_fails_closed(self) -> None:
        fixture = _fixture(self.root, external_event=True)

        receipt = _check(fixture, name="missing-external")

        self.assertEqual(receipt.status, "incomplete")
        self.assertIn(
            "resolved_external_contract_missing", {issue.code for issue in receipt.issues}
        )

    def test_missing_finite_indirect_route_fails_closed(self) -> None:
        fixture = _fixture(self.root, indirect_exit=True)

        receipt = _check(fixture, name="missing-indirect")

        self.assertEqual(receipt.status, "incomplete")
        self.assertIn(
            "finite_control_route_missing",
            {issue.code for issue in receipt.issues},
        )


if __name__ == "__main__":
    unittest.main()
