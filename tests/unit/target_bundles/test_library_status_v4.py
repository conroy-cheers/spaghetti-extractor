from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.formats import (
    LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
)
from spaghetti_extractor.libraries.v4_adoption_records import (
    CHECKED_LIBRARY_ISLAND_CODEC_V1,
    CheckedLibraryIslandV1,
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
from spaghetti_extractor.libraries.v4_record_support import canonical_sha256
from spaghetti_extractor.target_bundles.library_status_v4 import (
    build_library_status_v4,
)
from spaghetti_extractor.util import write_json


def _fixture(root: Path):
    implementation = ReusableLibraryImplementationV1.create(
        family_id="fixture-runtime",
        recipe_id="recipe.increment-v1",
        compatible_release_ids=("1.0",),
        operation_source_mappings=(
            LibraryOperationSourceMappingV1.create(
                operation_id="increment",
                source_id="portable.increment",
                source_symbol="portable_increment",
                source_sha256="6" * 64,
            ),
        ),
        interface_contract_ids=("portable.increment",),
        effect_contract_ids=(),
        compile_profile_id="mingw32-c11",
        qualification_checker_id="static-refinement-v1",
        qualification_receipt_sha256="7" * 64,
    )
    match = LibraryFunctionMatchV4.create(
        target_function_id="target.increment",
        target_span_start=0x1000,
        target_span_end=0x1008,
        target_unit_ids=("unit:increment",),
        catalog_function_id="catalog.increment",
        evidence=("abi_envelope", "exact_bytes"),
        score=950,
    )
    island = LibraryIslandHypothesisV4.create(
        target_id="fixture",
        family_id="fixture-runtime",
        release_id="1.0",
        target_unit_ids=match.target_unit_ids,
        member_ids=("increment.obj",),
        catalog_function_ids=(match.catalog_function_id,),
        operation_ids=("increment",),
        matches=(match,),
        boundary_edge_ids=(),
        implementation_ids=(implementation.implementation_id,),
    )
    release = LibraryReleaseHypothesesV4.create(
        target_id="fixture",
        family_id="fixture-runtime",
        release_id="1.0",
        target_binary_sha256="1" * 64,
        target_signature_graph_sha256="2" * 64,
        catalog_search_index_sha256="3" * 64,
        catalog_release_sha256="4" * 64,
        islands=(island,),
    )
    release_root = root / "releases"
    release_root.mkdir()
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.write(
        release_root / "release.json", release
    )
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
                "path": "release.json",
                "hypotheses_sha256": release.hypotheses_sha256,
                "status": release.status,
            }
        ],
    }
    write_json(
        release_root / "manifest.json",
        {**manifest_core, "manifest_sha256": canonical_sha256(manifest_core)},
    )
    intent = LibraryAdoptionIntentV1.create(
        target_id="fixture",
        island_id=island.island_id,
        hypotheses_sha256=release.hypotheses_sha256,
        implementation_id=implementation.implementation_id,
        mode="adopt",
    )
    receipt = CheckedLibraryIslandV1.create(
        target_id="fixture",
        target_binary_sha256=release.target_binary_sha256,
        machine_ir_sha256="5" * 64,
        island_id=island.island_id,
        hypotheses_sha256=release.hypotheses_sha256,
        implementation_id=implementation.implementation_id,
        implementation_sha256=implementation.implementation_sha256,
        checker_id="checked-library-island-v1",
        checked_unit_ids=island.target_unit_ids,
        checked_operation_ids=island.operation_ids,
        checked_boundary_edge_ids=island.boundary_edge_ids,
    )
    return implementation, island, release_root, intent, receipt


def _component(
    root: Path,
    *,
    implementation: ReusableLibraryImplementationV1,
    island: LibraryIslandHypothesisV4,
    receipt: CheckedLibraryIslandV1,
    receipt_sha256: str | None = None,
) -> Path:
    output = root / "component"
    output.mkdir()
    core = {
        "format": "spaghetti-extractor-generated-library-component-v1",
        "status": "complete",
        "component_id": "portable.increment",
        "target_id": "fixture",
        "island_id": island.island_id,
        "implementation_id": implementation.implementation_id,
        "unit_ids": list(island.target_unit_ids),
        "operation_ids": list(island.operation_ids),
        "bindings": {
            "target_binary_sha256": "1" * 64,
            "machine_ir_sha256": receipt.machine_ir_sha256,
            "checked_island_receipt_sha256": (
                receipt.receipt_sha256
                if receipt_sha256 is None
                else receipt_sha256
            ),
        },
        "issues": [],
        "policy": {},
    }
    write_json(
        output / "library-component.json",
        {**core, "package_sha256": canonical_sha256(core)},
    )
    return output


class LibraryStatusV4Tests(unittest.TestCase):
    def test_unselected_hypotheses_do_not_block_adoption_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            implementation, _island, releases, _intent, _receipt = _fixture(root)
            result = build_library_status_v4(
                target_id="fixture",
                release_hypotheses=releases,
                implementations=(implementation,),
                out=root / "status.json",
            )
        self.assertEqual(result["adoption_status"], "ready")
        self.assertEqual(result["recognition_status"], "complete")
        self.assertEqual(result["counts"]["adoption_intents"], 0)

    def test_adoption_without_checked_artifacts_is_actionably_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            implementation, _island, releases, intent, _receipt = _fixture(root)
            result = build_library_status_v4(
                target_id="fixture",
                release_hypotheses=releases,
                adoption_intents=(intent,),
                implementations=(implementation,),
                out=root / "status.json",
            )
        self.assertEqual(result["adoption_status"], "incomplete")
        self.assertEqual(
            {issue["code"] for issue in result["selections"][0]["issues"]},
            {
                "checked_island_receipt_missing",
                "generated_library_component_missing",
            },
        )

    def test_exact_checked_component_makes_adoption_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            implementation, island, releases, intent, receipt = _fixture(root)
            component = _component(
                root,
                implementation=implementation,
                island=island,
                receipt=receipt,
            )
            result = build_library_status_v4(
                target_id="fixture",
                release_hypotheses=releases,
                adoption_intents=(intent,),
                checked_islands=(receipt,),
                generated_components=(component,),
                implementations=(implementation,),
                out=root / "status.json",
            )
        self.assertEqual(result["adoption_status"], "ready")
        self.assertEqual(result["counts"]["ready_adoptions"], 1)

    def test_stale_generated_component_is_violated_at_the_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            implementation, island, releases, intent, receipt = _fixture(root)
            component = _component(
                root,
                implementation=implementation,
                island=island,
                receipt=receipt,
                receipt_sha256="8" * 64,
            )
            result = build_library_status_v4(
                target_id="fixture",
                release_hypotheses=releases,
                adoption_intents=(intent,),
                checked_islands=(receipt,),
                generated_components=(component,),
                implementations=(implementation,),
                out=root / "status.json",
            )
        self.assertEqual(result["adoption_status"], "violated")
        self.assertEqual(
            result["selections"][0]["issues"][0]["code"],
            "generated_library_component_stale",
        )


if __name__ == "__main__":
    unittest.main()
