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
from spaghetti_extractor.semantic_link.module_v2 import LinkedSemanticModuleV2
from spaghetti_extractor.semantic_providers.qualification_v2 import (
    build_semantic_provider_qualification_v2,
)
from spaghetti_extractor.semantic_providers.slices_v2 import (
    SemanticSliceV2,
    build_semantic_slice_v2,
)
from spaghetti_extractor.util import json_dumps, sha256_text, write_json


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


def _provider(
    root: Path,
    *,
    implementation: ReusableLibraryImplementationV1,
    island: LibraryIslandHypothesisV4,
    receipt: CheckedLibraryIslandV1,
    receipt_sha256: str | None = None,
) -> Path:
    output = root / "provider"
    output.mkdir()
    definition_id = f"semantic-definition-v2:{'8' * 64}"
    module = LinkedSemanticModuleV2(payload={
        "linked_semantic_module_sha256": "9" * 64,
        "status": "complete",
        "semantic_holes": [],
        "definitions": [{
            "definition_id": definition_id,
            "symbol_id": f"original:function:{island.target_unit_ids[0]}",
            "definition_kind": "transfer_v2",
            "definition_sha256": "a" * 64,
            "dependency_contract_sha256s": [],
        }],
        "definition_requirements": [{
            "definition_id": definition_id,
            "symbol_id": f"original:function:{island.target_unit_ids[0]}",
            "allowed_provider_kinds": ["qualified_portable_c"],
            "dependency_contract_sha256s": [],
        }],
        "residual_obligations": [],
    })
    semantic_slice = SemanticSliceV2.parse(build_semantic_slice_v2(
        linked_semantic_module=module, definition_ids=[definition_id]
    ))
    facets = [{
        "name": name,
        "status": "checked",
        "receipt_sha256": "b" * 64,
    } for name in (
        "compile", "contextual_refinement", "induction", "lifecycle",
        "native_objects", "object_binding", "ownership", "relations",
        "services", "source",
    )]
    provenance_sha256 = (
        sha256_text(json_dumps(receipt.to_payload()) + "\n")
        if receipt_sha256 is None else receipt_sha256
    )
    payload = build_semantic_provider_qualification_v2(
        semantic_slice=semantic_slice,
        provider_id="fixture.library.increment.portable-c",
        provider_kind="qualified_portable_c",
        provider_artifact_sha256="c" * 64,
        facets=facets,
        definition_materializations=[{
            "definition_id": definition_id,
            "native_symbol": "portable_increment",
            "source_sha256s": ["d" * 64],
            "object_sha256s": ["e" * 64],
        }],
        tool_sha256s=["f" * 64],
        dependencies=[
            "provider-provenance:checked-library-island:"
            + provenance_sha256
        ],
    )
    write_json(
        output / "semantic-provider-qualification.json", payload,
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
                "library_semantic_provider_missing",
            },
        )

    def test_exact_checked_provider_makes_adoption_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            implementation, island, releases, intent, receipt = _fixture(root)
            provider = _provider(
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
                provider_qualifications=(provider,),
                implementations=(implementation,),
                out=root / "status.json",
            )
        self.assertEqual(result["adoption_status"], "ready")
        self.assertEqual(result["counts"]["ready_adoptions"], 1)

    def test_stale_semantic_provider_is_violated_at_the_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            implementation, island, releases, intent, receipt = _fixture(root)
            provider = _provider(
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
                provider_qualifications=(provider,),
                implementations=(implementation,),
                out=root / "status.json",
            )
        self.assertEqual(result["adoption_status"], "violated")
        self.assertEqual(
            result["selections"][0]["issues"][0]["code"],
            "library_semantic_provider_stale",
        )


if __name__ == "__main__":
    unittest.main()
