from __future__ import annotations

from pathlib import Path

from spaghetti_extractor.abi.catalog import (
    PhysicalAbiCatalogV1,
    build_physical_abi_catalog,
)
from spaghetti_extractor.abi.declarations import (
    PhysicalAbiDeclarationSetV1,
    PhysicalAbiDeclarationV1,
)
from spaghetti_extractor.abi.model import PhysicalAbiProfileV1
from spaghetti_extractor.artifacts.formats import (
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
    LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
)
from spaghetti_extractor.libraries.catalog import (
    bind_library_artifact_inputs,
    index_library_artifacts,
)
from spaghetti_extractor.libraries.v4_identity_records import (
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4,
    LibraryFunctionMatchV4,
    LibraryIslandHypothesisV4,
    LibraryReleaseHypothesesV4,
)
from spaghetti_extractor.libraries.v4_record_support import canonical_sha256
from spaghetti_extractor.util import write_json
from tests.unit.libraries._support import archive, coff_object


_FUNCTION = bytes.fromhex("5589e5b801000000c3")


def write_library_index(
    root: Path,
    *,
    snapshot_id: str = "runtime-snapshot-v1",
    symbol: str = "_run@4",
) -> Path:
    artifacts = root / "artifacts"
    artifacts.mkdir()
    (artifacts / "runtime.a").write_bytes(
        archive("runtime.obj", coff_object(_FUNCTION, symbol=symbol))
    )
    inputs = bind_library_artifact_inputs(
        {
            "format": LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
            "catalog_id": "fixture-runtime",
            "snapshot": {
                "id": snapshot_id,
                "target": {
                    "architecture": "i686",
                    "object_format": "coff",
                    "abi": "mingw32",
                },
            },
            "artifacts": [
                {
                    "id": "runtime",
                    "path": "runtime.a",
                    "retention_model": "archive_member",
                    "library_identity": {
                        "family_id": "fixture-runtime",
                        "component_id": "runtime",
                        "release_id": "1",
                        "abi_id": "mingw32",
                    },
                }
            ],
        }
    )
    destination = root / "artifact-index.json"
    index_library_artifacts(
        inputs=inputs,
        artifact_root=artifacts,
        out=destination,
    )
    return destination


def write_declaration_set(
    root: Path,
    *,
    profile: PhysicalAbiProfileV1,
    snapshot_id: str = "runtime-snapshot-v1",
    symbol: str = "_run@4",
    filename: str = "declarations.json",
) -> tuple[Path, PhysicalAbiDeclarationV1]:
    declaration = PhysicalAbiDeclarationV1.create(
        symbols=(symbol,),
        source_kind="header_ast",
        source_sha256="e" * 64,
        producer="fixture-header-parser-v1",
        profile=profile,
        dependency_ids=("fixture-toolchain-v1",),
    )
    declaration_set = PhysicalAbiDeclarationSetV1.create(
        snapshot_id=snapshot_id,
        declarations=(declaration,),
    )
    destination = root / filename
    declaration_set.write(destination)
    return destination, declaration


def write_declared_catalog(
    root: Path,
    *,
    profile: PhysicalAbiProfileV1,
    snapshot_id: str = "runtime-snapshot-v1",
    symbol: str = "_run@4",
) -> tuple[Path, PhysicalAbiCatalogV1, PhysicalAbiDeclarationV1]:
    index_path = write_library_index(
        root,
        snapshot_id=snapshot_id,
        symbol=symbol,
    )
    declarations_path, declaration = write_declaration_set(
        root,
        profile=profile,
        snapshot_id=snapshot_id,
        symbol=symbol,
    )
    catalog_path = root / "physical-abi-catalog.json"
    catalog = build_physical_abi_catalog(
        artifact_index=index_path,
        out=catalog_path,
        decoration_model="pe32-coff-gnu-v1",
        declarations=declarations_path,
    )
    return catalog_path, catalog, declaration


def write_release_set(
    root: Path,
    *,
    target_function_id: str,
    target_unit_ids: tuple[str, ...],
    catalog_function_id: str,
) -> Path:
    match = LibraryFunctionMatchV4.create(
        target_function_id=target_function_id,
        target_span_start=0x401000,
        target_span_end=0x401040,
        target_unit_ids=target_unit_ids,
        catalog_function_id=catalog_function_id,
        evidence=("exact_bytes",),
        score=1000,
    )
    island = LibraryIslandHypothesisV4.create(
        target_id="fixture.exe",
        family_id="fixture-runtime",
        release_id="1",
        target_unit_ids=target_unit_ids,
        member_ids=("archive-member:runtime.obj",),
        catalog_function_ids=(catalog_function_id,),
        operation_ids=("operation.run",),
        matches=(match,),
    )
    release = LibraryReleaseHypothesesV4.create(
        target_id="fixture.exe",
        family_id="fixture-runtime",
        release_id="1",
        target_binary_sha256="a" * 64,
        target_signature_graph_sha256="b" * 64,
        catalog_search_index_sha256="c" * 64,
        catalog_release_sha256="d" * 64,
        islands=(island,),
    )
    destination = root / "release-hypotheses"
    destination.mkdir()
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.write(
        destination / "release.json",
        release,
    )
    core = {
        "format": LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
        "target_id": release.target_id,
        "target_binary_sha256": release.target_binary_sha256,
        "target_signature_graph_sha256": (
            release.target_signature_graph_sha256
        ),
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


__all__ = [
    "write_declaration_set",
    "write_declared_catalog",
    "write_library_index",
    "write_release_set",
]
