from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import ArtifactSetWriterV3
from spaghetti_extractor.artifacts.formats import (
    CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
    LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
)
from spaghetti_extractor.authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
)
from spaghetti_extractor.libraries.abi_catalog import (
    LIBRARY_ABI_CATALOG_CODEC_V3,
    build_catalog_search_index,
)
from spaghetti_extractor.libraries.v4_activation import check_library_island_v1
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
    machine: Path
    release_root: Path
    release: LibraryReleaseHypothesesV4
    island: LibraryIslandHypothesisV4
    implementation: ReusableLibraryImplementationV1
    intent: LibraryAdoptionIntentV1
    catalog_index: object
    external_sites: Path
    target_certificates: Path


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


def _empty_authority(root: Path, name: str, kind: str) -> Path:
    output = root / name
    ArtifactSetWriterV3(artifact_kind=kind, bindings=()).write(output, ())
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
                "kind": "external_call",
                "dll": "KERNEL32.dll",
                "symbol": "WriteFile",
                "abi_profile_id": "x86-cdecl",
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
    machine = write_machine(root, [unit])
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
    return _Fixture(
        root=root,
        machine=machine,
        release_root=release_root,
        release=release,
        island=island,
        implementation=implementation,
        intent=intent,
        catalog_index=catalog_index,
        external_sites=_empty_authority(
            root,
            "canonical-external-sites",
            CANONICAL_EXTERNAL_SITES_ARTIFACT_KIND_V3,
        ),
        target_certificates=_empty_authority(
            root,
            "target-certificates",
            INDIRECT_TARGET_CERTIFICATES_ARTIFACT_KIND_V3,
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
        machine_ir=fixture.machine,
        release_hypotheses=fixture.release_root,
        island_id=fixture.island.island_id,
        adoption_intent=intent or fixture.intent,
        implementation=implementation or fixture.implementation,
        catalog_search_index=fixture.catalog_index,
        canonical_external_sites=fixture.external_sites,
        target_certificates=fixture.target_certificates,
        out=fixture.root / f"{name}.json",
    )


class V4LibraryActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_small_no_crossing_island_with_qualified_implementation_completes(self) -> None:
        fixture = _fixture(self.root)

        receipt = _check(fixture, name="complete")

        self.assertEqual(receipt.status, "complete")
        self.assertEqual(receipt.identity_status, "complete")
        self.assertEqual(receipt.boundary_status, "complete")
        self.assertEqual(receipt.implementation_status, "complete")
        self.assertEqual(receipt.checked_boundary_edge_ids, ())

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
            "catalog_operation_abi_missing", {issue.code for issue in receipt.issues}
        )

    def test_missing_canonical_external_authority_fails_closed(self) -> None:
        fixture = _fixture(self.root, external_event=True)

        receipt = _check(fixture, name="missing-external")

        self.assertEqual(receipt.status, "incomplete")
        self.assertIn(
            "canonical_external_site_missing", {issue.code for issue in receipt.issues}
        )

    def test_missing_canonical_indirect_authority_fails_closed(self) -> None:
        fixture = _fixture(self.root, indirect_exit=True)

        receipt = _check(fixture, name="missing-indirect")

        self.assertEqual(receipt.status, "incomplete")
        self.assertIn(
            "indirect_target_certificate_missing",
            {issue.code for issue in receipt.issues},
        )


if __name__ == "__main__":
    unittest.main()
