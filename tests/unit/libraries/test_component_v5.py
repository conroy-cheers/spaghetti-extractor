from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from spaghetti_extractor.artifacts.formats import (
    LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
)
from spaghetti_extractor.libraries.abi_catalog import (
    LIBRARY_ABI_CATALOG_CODEC_V3,
    build_catalog_search_index,
)
from spaghetti_extractor.libraries.behavior_pack_v3 import (
    load_reusable_library_behavior_pack_v3,
)
from spaghetti_extractor.libraries.component_v5 import (
    build_checked_library_provider_binding_v1,
)
from spaghetti_extractor.libraries.v4_adoption_records import CheckedLibraryIslandV1
from spaghetti_extractor.semantic_link.module_v2 import LinkedSemanticModuleV2
from spaghetti_extractor.libraries.v4_identity_records import (
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4,
    LibraryFunctionMatchV4,
    LibraryIslandHypothesisV4,
    LibraryReleaseHypothesesV4,
)
from spaghetti_extractor.libraries.v4_record_support import canonical_sha256
from spaghetti_extractor.util import sha256_file, write_json
from spaghetti_extractor.transfer.plan import write_executable_transfer_plan

from .library_fixture_support import (
    abi_profile,
    catalog,
    function_signature,
    machine_unit,
    write_machine,
)
from .test_behavior_pack_v3 import build_behavior_pack_v3_fixture

TESTKIT = {
    "resources": (
        "targets/gnu-hello/intent/interfaces-v5/ascii-to-lower.json",
    )
}


def _write_release_set(root: Path, release: LibraryReleaseHypothesesV4) -> Path:
    destination = root / "release-hypotheses"
    destination.mkdir()
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.write(
        destination / "release.json", release
    )
    core = {
        "format": LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
        "target_id": release.target_id,
        "target_binary_sha256": release.target_binary_sha256,
        "target_signature_graph_sha256": release.target_signature_graph_sha256,
        "catalog_search_index_sha256": release.catalog_search_index_sha256,
        "releases": [
            {
                "family_id": release.family_id,
                "release_id": release.release_id,
                "path": "release.json",
                "hypotheses_sha256": release.hypotheses_sha256,
                "status": release.status,
            }
        ],
    }
    write_json(
        destination / "manifest.json",
        {**core, "manifest_sha256": canonical_sha256(core)},
    )
    return destination


class CheckedLibraryProviderBindingTests(unittest.TestCase):
    def _fixture(self, root: Path, *, variadic: bool = False) -> dict[str, object]:
        behavior = build_behavior_pack_v3_fixture(root / "behavior")
        pack = load_reusable_library_behavior_pack_v3(behavior["pack"])
        profile = abi_profile(
            "fixture-x86-cdecl",
            variadic="format" if variadic else "none",
        )
        machine_root = root / "machine"
        machine_root.mkdir()
        machine = write_machine(
            machine_root,
            [machine_unit("unit:convert", 0x1000, "a" * 64, profile)],
        )
        function = replace(
            function_signature(
                function_id="catalog:convert",
                release="fixture-runtime-1.0",
                exact_hash=None,
                abi_profile_id=profile.profile_id,
            ),
            family_id="fixture-runtime",
            operation_id="convert",
        )
        catalog_path = root / "catalog.json"
        LIBRARY_ABI_CATALOG_CODEC_V3.write(
            catalog_path, catalog((function,), profiles=(profile,))
        )
        catalog_index = build_catalog_search_index(
            catalog_path, root / "catalog-search-index.json"
        )
        match = LibraryFunctionMatchV4.create(
            target_function_id="target:convert",
            target_span_start=0x1000,
            target_span_end=0x1008,
            target_unit_ids=("unit:convert",),
            catalog_function_id="catalog:convert",
            evidence=("unit_merkle",),
            score=70,
        )
        island = LibraryIslandHypothesisV4.create(
            target_id="fixture-target",
            family_id=pack.implementation.family_id,
            release_id="fixture-runtime-1.0",
            target_unit_ids=("unit:convert",),
            member_ids=("runtime.obj",),
            catalog_function_ids=("catalog:convert",),
            operation_ids=("convert",),
            matches=(match,),
            implementation_ids=(pack.implementation.implementation_id,),
        )
        release = LibraryReleaseHypothesesV4.create(
            target_id="fixture-target",
            family_id=pack.implementation.family_id,
            release_id="fixture-runtime-1.0",
            target_binary_sha256=sha256_file(machine_root / "fixture.exe"),
            target_signature_graph_sha256="b" * 64,
            catalog_search_index_sha256=catalog_index.index_sha256,
            catalog_release_sha256="c" * 64,
            islands=(island,),
        )
        checked = CheckedLibraryIslandV1.create(
            target_id="fixture-target",
            target_binary_sha256=release.target_binary_sha256,
            machine_ir_sha256=sha256_file(machine / "machine-ir.jsonl"),
            island_id=island.island_id,
            hypotheses_sha256=release.hypotheses_sha256,
            implementation_id=pack.implementation.implementation_id,
            implementation_sha256=pack.implementation.implementation_sha256,
            checker_id="checked-library-island-v1",
            checked_unit_ids=island.target_unit_ids,
            checked_operation_ids=island.operation_ids,
        )
        structural = root / "structural-units.json"
        write_json(structural, {"unit_ids": ["unit:convert"]})
        transfer_root = root / "transfer"
        write_executable_transfer_plan(
            machine_ir=machine / "machine-ir.jsonl",
            machine_ir_manifest=machine / "machine-ir-manifest.json",
            out=transfer_root,
        )
        transfer = transfer_root / "executable-transfer-plan.json"
        return {
            "original": machine_root / "fixture.exe",
            "machine": machine,
            "structural": structural,
            "linked": LinkedSemanticModuleV2(
                payload={
                    "format": "spaghetti-extractor-linked-semantic-module-v2",
                },
                package_root=root,
                package_members={"transfer_plan": transfer},
            ),
            "release": _write_release_set(root, release),
            "checked": checked,
            "pack": behavior["pack"],
            "catalog": catalog_index,
        }

    def test_checked_island_derives_direct_provider_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._fixture(root)
            output = root / "component"
            binding = build_checked_library_provider_binding_v1(
                linked_semantic_module=fixture["linked"],
                release_hypotheses=fixture["release"],
                checked_island=fixture["checked"],
                behavior_pack=fixture["pack"],
                catalog_search_index=fixture["catalog"],
                out_dir=output,
            )
            interface_exists = (
                output / "interface/portable-component-interface-v5.json"
            ).is_file()
            contract_exists = (output / "component-contract-v4.json").exists()
            machine_binding_exists = (
                output / "component-machine-binding-v5.json"
            ).exists()

        self.assertEqual(binding["status"], "complete")
        self.assertEqual(binding["operations"][0]["unit_ids"], ["unit:convert"])
        projection = binding["operations"][0]["machine_projection"]
        self.assertEqual(
            projection["operation"]["parameters"][0]["projection"],
            {"kind": "stack", "offset": 4, "width": 32, "at": "entry"},
        )
        self.assertTrue(interface_exists)
        self.assertFalse(contract_exists)
        self.assertFalse(machine_binding_exists)

    def test_unsupported_variadic_abi_remains_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._fixture(root, variadic=True)
            binding = build_checked_library_provider_binding_v1(
                linked_semantic_module=fixture["linked"],
                release_hypotheses=fixture["release"],
                checked_island=fixture["checked"],
                behavior_pack=fixture["pack"],
                catalog_search_index=fixture["catalog"],
                out_dir=root / "component",
            )

        self.assertEqual(binding["status"], "incomplete")
        self.assertIn(
            "library_operation_abi_requires_explicit_mapping",
            {row["code"] for row in binding["blockers"]},
        )


if __name__ == "__main__":
    unittest.main()
