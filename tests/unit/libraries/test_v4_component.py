from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import dataclass, replace
from pathlib import Path

from spaghetti_extractor.artifacts.formats import (
    LIBRARY_RELEASE_HYPOTHESES_SET_V4_FORMAT,
)
from spaghetti_extractor.libraries.abi_catalog import (
    LIBRARY_ABI_CATALOG_CODEC_V3,
    build_catalog_search_index,
)
from spaghetti_extractor.libraries.v4_adoption_records import (
    CHECKED_LIBRARY_ISLAND_CODEC_V1,
    CheckedLibraryIslandV1,
)
from spaghetti_extractor.libraries.v4_component import (
    build_checked_library_component_v1,
)
from spaghetti_extractor.libraries.v4_identity_records import (
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4,
    LibraryFunctionMatchV4,
    LibraryIslandHypothesisV4,
    LibraryReleaseHypothesesV4,
)
from spaghetti_extractor.libraries.v4_record_support import (
    LibraryV4RecordError,
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
from .test_v4_behavior_pack import _build_fixture


@dataclass(frozen=True)
class _ComponentFixture:
    root: Path
    machine: Path
    release_hypotheses: Path
    catalog_index: object
    checked_island: CheckedLibraryIslandV1
    behavior_pack: Path


def _write_release_set(
    root: Path, release: LibraryReleaseHypothesesV4
) -> Path:
    destination = root / "release-hypotheses"
    destination.mkdir()
    LIBRARY_RELEASE_HYPOTHESES_CODEC_V4.write(
        destination / "release.json", release
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


def _component_fixture(
    root: Path,
    *,
    variadic_accumulate: bool = False,
    stateful: bool = False,
) -> _ComponentFixture:
    behavior_root = root / "behavior"
    behavior_root.mkdir()
    behavior = _build_fixture(behavior_root, stateless=not stateful)
    implementation = behavior["implementation"]

    machine_root = root / "machine"
    machine_root.mkdir()
    accumulate_profile = abi_profile(
        "x86-cdecl-accumulate",
        variadic="format" if variadic_accumulate else "none",
    )
    reset_profile = replace(
        abi_profile("x86-cdecl-reset"),
        arguments=(),
        returns=(),
        boundary_effects=(),
    )
    units = [
        machine_unit(
            "unit:accumulate",
            0x1000,
            "a" * 64,
            accumulate_profile,
        ),
        machine_unit(
            "unit:reset",
            0x1010,
            "b" * 64,
            reset_profile,
        ),
    ]
    machine = write_machine(machine_root, units)

    functions = (
        replace(
            function_signature(
                function_id="catalog:accumulate",
                release="fixture-runtime-1.0",
                exact_hash=None,
                abi_profile_id=accumulate_profile.profile_id,
            ),
            operation_id="accumulate",
        ),
        replace(
            function_signature(
                function_id="catalog:reset",
                release="fixture-runtime-1.0",
                exact_hash=None,
                abi_profile_id=reset_profile.profile_id,
            ),
            operation_id="reset",
        ),
    )
    catalog_path = root / "catalog.json"
    LIBRARY_ABI_CATALOG_CODEC_V3.write(
        catalog_path,
        catalog(functions, profiles=(accumulate_profile, reset_profile)),
    )
    catalog_index = build_catalog_search_index(
        catalog_path, root / "catalog-search-index.json"
    )

    matches = (
        LibraryFunctionMatchV4.create(
            target_function_id="target:accumulate",
            target_span_start=0x1000,
            target_span_end=0x1008,
            target_unit_ids=("unit:accumulate",),
            catalog_function_id="catalog:accumulate",
            evidence=("unit_merkle",),
            score=70,
        ),
        LibraryFunctionMatchV4.create(
            target_function_id="target:reset",
            target_span_start=0x1010,
            target_span_end=0x1018,
            target_unit_ids=("unit:reset",),
            catalog_function_id="catalog:reset",
            evidence=("unit_merkle",),
            score=70,
        ),
    )
    island = LibraryIslandHypothesisV4.create(
        target_id="fixture-target",
        family_id=implementation.family_id,
        release_id="fixture-runtime-1.0",
        target_unit_ids=("unit:accumulate", "unit:reset"),
        member_ids=("runtime.obj",),
        catalog_function_ids=("catalog:accumulate", "catalog:reset"),
        operation_ids=("accumulate", "reset"),
        matches=matches,
        implementation_ids=(implementation.implementation_id,),
    )
    release = LibraryReleaseHypothesesV4.create(
        target_id="fixture-target",
        family_id=implementation.family_id,
        release_id="fixture-runtime-1.0",
        target_binary_sha256=sha256_file(machine_root / "fixture.exe"),
        target_signature_graph_sha256="c" * 64,
        catalog_search_index_sha256=catalog_index.index_sha256,
        catalog_release_sha256="d" * 64,
        islands=(island,),
    )
    release_hypotheses = _write_release_set(root, release)
    machine_sha256 = sha256_file(machine / "machine-ir.jsonl")
    checked_island = CheckedLibraryIslandV1.create(
        target_id="fixture-target",
        target_binary_sha256=release.target_binary_sha256,
        machine_ir_sha256=machine_sha256,
        island_id=island.island_id,
        hypotheses_sha256=release.hypotheses_sha256,
        implementation_id=implementation.implementation_id,
        implementation_sha256=implementation.implementation_sha256,
        checker_id="checked-library-island-v1",
        checked_unit_ids=island.target_unit_ids,
        checked_operation_ids=island.operation_ids,
    )

    return _ComponentFixture(
        root=root,
        machine=machine,
        release_hypotheses=release_hypotheses,
        catalog_index=catalog_index,
        checked_island=checked_island,
        behavior_pack=behavior["root"],
    )


def _build(
    fixture: _ComponentFixture,
    *,
    checked_island: CheckedLibraryIslandV1 | Path | None = None,
    behavior_pack: Path | None = None,
    name: str,
) -> dict[str, object]:
    return build_checked_library_component_v1(
        machine_ir=fixture.machine,
        release_hypotheses=fixture.release_hypotheses,
        checked_island=checked_island or fixture.checked_island,
        behavior_pack=behavior_pack or fixture.behavior_pack,
        catalog_search_index=fixture.catalog_index,
        canonical_external_sites=None,
        out_dir=fixture.root / name,
    )


class CheckedLibraryComponentV1Tests(unittest.TestCase):
    def test_stateless_scalar_pack_generates_canonical_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _component_fixture(Path(temporary))
            package = _build(fixture, name="complete")

            output = fixture.root / "complete"
            binding = json.loads(
                (output / "machine-binding.json").read_text(encoding="utf-8")
            )
            receipt = json.loads(
                (output / "machine-binding-receipt.json").read_text(
                    encoding="utf-8"
                )
            )
            semantics = json.loads(
                (output / "semantic-contract.json").read_text(encoding="utf-8")
            )

        self.assertEqual(package["status"], "complete")
        self.assertEqual(receipt["status"], "checked")
        self.assertEqual(semantics["status"], "satisfied")
        self.assertEqual(
            package["bindings"]["checked_island_receipt_sha256"],
            fixture.checked_island.receipt_sha256,
        )
        operations = {row["operation_id"]: row for row in binding["operations"]}
        self.assertEqual(
            operations["accumulate"]["parameters"],
            [
                {
                    "id": "amount",
                    "projection": {
                        "kind": "stack",
                        "offset": 4,
                        "width": 32,
                        "at": "entry",
                    },
                }
            ],
        )
        self.assertEqual(
            operations["accumulate"]["results"][0]["projection"],
            {"kind": "register", "register": "eax", "width": 32, "at": "exit"},
        )
        self.assertEqual(operations["reset"]["parameters"], [])
        self.assertEqual(operations["reset"]["results"], [])

    def test_real_stateful_effectful_pack_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _component_fixture(Path(temporary), stateful=True)
            package = _build(fixture, name="stateful")

        self.assertEqual(package["status"], "incomplete")
        self.assertEqual(
            {row["code"] for row in package["issues"]},
            {
                "effectful_library_component_generation_unsupported",
                "stateful_library_component_generation_unsupported",
            },
        )
        self.assertIsNone(package["bindings"]["machine_binding_receipt_sha256"])
        self.assertIsNone(package["bindings"]["semantic_contract_sha256"])

    def test_variadic_abi_requires_explicit_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _component_fixture(
                Path(temporary), variadic_accumulate=True
            )
            package = _build(fixture, name="variadic")

        self.assertEqual(package["status"], "incomplete")
        self.assertEqual(
            {row["code"] for row in package["issues"]},
            {"operation_abi_profile_requires_explicit_mapping"},
        )

    def test_stale_machine_binding_is_reported_as_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _component_fixture(Path(temporary))
            current = fixture.checked_island
            stale = CheckedLibraryIslandV1.create(
                target_id=current.target_id,
                target_binary_sha256=current.target_binary_sha256,
                machine_ir_sha256="0" * 64,
                island_id=current.island_id,
                hypotheses_sha256=current.hypotheses_sha256,
                implementation_id=current.implementation_id,
                implementation_sha256=current.implementation_sha256,
                checker_id=current.checker_id,
                checked_unit_ids=current.checked_unit_ids,
                checked_operation_ids=current.checked_operation_ids,
            )
            package = _build(
                fixture,
                checked_island=stale,
                name="stale-machine",
            )

        self.assertEqual(package["status"], "incomplete")
        self.assertIn(
            "checked_island_machine_ir_stale",
            {row["code"] for row in package["issues"]},
        )

    def test_corrupt_checked_island_is_rejected_before_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _component_fixture(Path(temporary))
            receipt_path = fixture.root / "corrupt-checked-island.json"
            CHECKED_LIBRARY_ISLAND_CODEC_V1.write(
                receipt_path, fixture.checked_island
            )
            payload = json.loads(receipt_path.read_text(encoding="utf-8"))
            payload["implementation_sha256"] = "f" * 64
            write_json(receipt_path, payload)

            with self.assertRaises(LibraryV4RecordError) as raised:
                _build(
                    fixture,
                    checked_island=receipt_path,
                    name="corrupt",
                )

        self.assertIn(
            raised.exception.code,
            {"stale_checked_island_id", "stale_checked_island_hash"},
        )


if __name__ == "__main__":
    unittest.main()
