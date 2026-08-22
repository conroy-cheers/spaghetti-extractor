from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.abi.catalog import PhysicalAbiCatalogV1
from spaghetti_extractor.abi.model import AbiFactV1, PhysicalAbiCertificateV1
from spaghetti_extractor.artifacts.io import ArtifactSetReaderV3
from spaghetti_extractor.authority.catalog_call_contracts import (
    CATALOG_CALL_CONTRACTS_ARTIFACT_KIND_V3,
    CATALOG_CALL_CONTRACT_CODEC_V1,
    CatalogCallContractV1,
    build_checked_catalog_call_contracts_v1,
    catalog_call_contract_machine_contradictions_v1,
)
from spaghetti_extractor.libraries.span_matching import StaticSpanMatch
from tests.unit.abi._support import physical_profile


def _catalog(path: Path) -> PhysicalAbiCatalogV1:
    certificate = PhysicalAbiCertificateV1.create(
        status="complete",
        subject_kind="library_member",
        subject_id="catalog-body",
        profile=physical_profile(),
        facts=(),
    )
    result = PhysicalAbiCatalogV1.create(
        status="complete",
        catalog_id="catalog-v1",
        source_index_sha256="1" * 64,
        decoration_model="pe32-coff-gnu-v1",
        declaration_set_sha256="2" * 64,
        evidence=(),
        facts=(),
        certificates=(certificate,),
        function_subjects=({"function_id": "catalog-body"},),
        issues=(),
    )
    result.write(path)
    return result


def _partial_catalog(path: Path) -> PhysicalAbiCatalogV1:
    facts = (
        AbiFactV1.create(
            subject_id="catalog-body",
            field="preserved_state",
            status="exact",
            values=(["ebp", "ebx", "edi", "esi"],),
        ),
        AbiFactV1.create(
            subject_id="catalog-body",
            field="stack_cleanup",
            status="exact",
            values=({"kind": "caller", "bytes": 0},),
        ),
        AbiFactV1.create(
            subject_id="catalog-body",
            field="arguments",
            status="unknown",
        ),
    )
    certificate = PhysicalAbiCertificateV1.create(
        status="incomplete",
        subject_kind="library_member",
        subject_id="catalog-body",
        profile=None,
        facts=facts,
    )
    result = PhysicalAbiCatalogV1.create(
        status="incomplete",
        catalog_id="catalog-v1",
        source_index_sha256="1" * 64,
        decoration_model="pe32-coff-gnu-v1",
        declaration_set_sha256="2" * 64,
        evidence=(),
        facts=(),
        certificates=(certificate,),
        function_subjects=({"function_id": "catalog-body"},),
        issues=(),
    )
    result.write(path)
    return result


class CatalogCallContractTests(unittest.TestCase):
    def test_exact_ret_immediate_vetoes_contradictory_cleanup(self) -> None:
        contract = CatalogCallContractV1.create(
            binary_sha256="a" * 64,
            match_id="match:entry",
            target_region_id="region:entry",
            target_entry_unit_id="unit:entry",
            target_unit_ids=("unit:entry",),
            catalog_id="catalog:test",
            catalog_sha256="b" * 64,
            catalog_function_id="catalog:function",
            certificate_id="certificate:function",
            exact_facts=(
                AbiFactV1.create(
                    subject_id="catalog:function",
                    field="stack_cleanup",
                    status="exact",
                    values=({"kind": "caller", "bytes": 0},),
                ),
            ),
        )

        self.assertEqual(
            catalog_call_contract_machine_contradictions_v1(
                contract,
                {
                    "unit:entry": SimpleNamespace(
                        returns=True, return_cleanup_bytes=0
                    )
                },
            ),
            (),
        )
        self.assertEqual(
            catalog_call_contract_machine_contradictions_v1(
                contract,
                {
                    "unit:entry": SimpleNamespace(
                        returns=True, return_cleanup_bytes=8
                    )
                },
            ),
            ("stack_cleanup",),
        )

    def test_exact_span_transfers_one_pinned_physical_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "fixture.exe"
            binary.write_bytes(b"exact-pe-fixture")
            binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
            catalog = _catalog(root / "physical.json")
            graph = SimpleNamespace(
                binary_sha256=binary_sha256,
                unit_spans=(SimpleNamespace(rva_start=0x1000, unit_id="unit:entry"),),
                functions=(
                    SimpleNamespace(
                        rva_start=0x1000,
                        rva_end=0x1010,
                        unit_ids=("unit:entry",),
                        function_id="target:function",
                    ),
                ),
            )
            match = StaticSpanMatch(
                "match:exact",
                0x1000,
                0x1010,
                ("unit:entry",),
                "catalog-body",
                ("relocation_masked_static_span",),
            )
            with (
                patch(
                    "spaghetti_extractor.authority.catalog_call_contracts."
                    "TARGET_SIGNATURE_GRAPH_CODEC_V3",
                    SimpleNamespace(read=lambda _path: graph),
                ),
                patch(
                    "spaghetti_extractor.authority.catalog_call_contracts."
                    "CATALOG_SEARCH_INDEX_CODEC_V3",
                    SimpleNamespace(read=lambda _path: SimpleNamespace()),
                ),
                patch(
                    "spaghetti_extractor.authority.catalog_call_contracts."
                    "discover_static_span_matches",
                    return_value=(match,),
                ),
            ):
                contracts = build_checked_catalog_call_contracts_v1(
                    binary=binary,
                    binary_identity="fixture.exe",
                    target_signature_graph=root / "graph.json",
                    catalog_search_index=root / "search.json",
                    physical_abi_catalogs=(root / "physical.json",),
                    out=root / "artifact",
                )

            self.assertEqual(len(contracts), 1)
            self.assertEqual(contracts[0].target_entry_unit_id, "unit:entry")
            self.assertEqual(contracts[0].catalog_sha256, catalog.catalog_sha256)
            reader = ArtifactSetReaderV3(root / "artifact")
            self.assertEqual(
                reader.manifest.artifact_kind,
                CATALOG_CALL_CONTRACTS_ARTIFACT_KIND_V3,
            )
            record = next(reader.iter_records())
            self.assertEqual(
                CATALOG_CALL_CONTRACT_CODEC_V1.read(record).value,
                contracts[0],
            )

    def test_ambiguous_exact_profiles_do_not_authorize_an_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "fixture.exe"
            binary.write_bytes(b"exact-pe-fixture")
            binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
            _catalog(root / "physical.json")
            graph = SimpleNamespace(
                binary_sha256=binary_sha256,
                unit_spans=(SimpleNamespace(rva_start=0x1000, unit_id="unit:entry"),),
                functions=(),
            )
            matches = (
                StaticSpanMatch("match:a", 0x1000, 0x1010, ("unit:entry",), "catalog-body", ("relocation_masked_static_span",)),
                StaticSpanMatch("match:b", 0x1000, 0x1020, ("unit:entry",), "catalog-body", ("relocation_masked_static_span",)),
            )
            with (
                patch("spaghetti_extractor.authority.catalog_call_contracts.TARGET_SIGNATURE_GRAPH_CODEC_V3", SimpleNamespace(read=lambda _path: graph)),
                patch("spaghetti_extractor.authority.catalog_call_contracts.CATALOG_SEARCH_INDEX_CODEC_V3", SimpleNamespace(read=lambda _path: SimpleNamespace())),
                patch("spaghetti_extractor.authority.catalog_call_contracts.discover_static_span_matches", return_value=matches),
            ):
                contracts = build_checked_catalog_call_contracts_v1(
                    binary=binary,
                    binary_identity="fixture.exe",
                    target_signature_graph=root / "graph.json",
                    catalog_search_index=root / "search.json",
                    physical_abi_catalogs=(root / "physical.json",),
                    out=root / "artifact",
                )
            self.assertEqual(contracts, ())

    def test_partial_certificate_exports_only_its_exact_call_frame_facts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "fixture.exe"
            binary.write_bytes(b"exact-pe-fixture")
            binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
            _partial_catalog(root / "physical.json")
            graph = SimpleNamespace(
                binary_sha256=binary_sha256,
                unit_spans=(
                    SimpleNamespace(rva_start=0x1000, unit_id="unit:entry"),
                ),
                functions=(),
            )
            match = StaticSpanMatch(
                "match:exact",
                0x1000,
                0x1010,
                ("unit:entry",),
                "catalog-body",
                ("relocation_masked_static_span",),
            )
            with (
                patch(
                    "spaghetti_extractor.authority.catalog_call_contracts."
                    "TARGET_SIGNATURE_GRAPH_CODEC_V3",
                    SimpleNamespace(read=lambda _path: graph),
                ),
                patch(
                    "spaghetti_extractor.authority.catalog_call_contracts."
                    "CATALOG_SEARCH_INDEX_CODEC_V3",
                    SimpleNamespace(read=lambda _path: SimpleNamespace()),
                ),
                patch(
                    "spaghetti_extractor.authority.catalog_call_contracts."
                    "discover_static_span_matches",
                    return_value=(match,),
                ),
            ):
                contracts = build_checked_catalog_call_contracts_v1(
                    binary=binary,
                    binary_identity="fixture.exe",
                    target_signature_graph=root / "graph.json",
                    catalog_search_index=root / "search.json",
                    physical_abi_catalogs=(root / "physical.json",),
                    out=root / "artifact",
                )

            self.assertEqual(len(contracts), 1)
            contract = contracts[0]
            self.assertIsNone(contract.profile)
            self.assertEqual(
                contract.preserved_registers,
                ("ebp", "ebx", "edi", "esi"),
            )
            self.assertEqual(contract.stack_cleanup.kind, "caller")
            self.assertEqual(
                tuple(row.field for row in contract.exact_facts),
                ("preserved_state", "stack_cleanup"),
            )

    def test_byte_identical_catalog_aliases_may_share_one_exact_abi(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "fixture.exe"
            binary.write_bytes(b"exact-pe-fixture")
            binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
            certificates = tuple(
                PhysicalAbiCertificateV1.create(
                    status="complete",
                    subject_kind="library_member",
                    subject_id=function_id,
                    profile=physical_profile(),
                    facts=(),
                )
                for function_id in ("catalog:alias-a", "catalog:alias-b")
            )
            catalog = PhysicalAbiCatalogV1.create(
                status="complete",
                catalog_id="catalog-v1",
                source_index_sha256="1" * 64,
                decoration_model="pe32-coff-gnu-v1",
                declaration_set_sha256="2" * 64,
                evidence=(),
                facts=(),
                certificates=certificates,
                function_subjects=tuple(
                    {"function_id": function_id}
                    for function_id in ("catalog:alias-a", "catalog:alias-b")
                ),
                issues=(),
            )
            catalog.write(root / "physical.json")
            graph = SimpleNamespace(
                binary_sha256=binary_sha256,
                unit_spans=(
                    SimpleNamespace(rva_start=0x1000, unit_id="unit:entry"),
                ),
                functions=(),
            )
            matches = tuple(
                StaticSpanMatch(
                    f"match:{index}",
                    0x1000,
                    0x1010,
                    ("unit:entry",),
                    function_id,
                    ("relocation_masked_static_span",),
                )
                for index, function_id in enumerate(
                    ("catalog:alias-a", "catalog:alias-b")
                )
            )
            with (
                patch(
                    "spaghetti_extractor.authority.catalog_call_contracts."
                    "TARGET_SIGNATURE_GRAPH_CODEC_V3",
                    SimpleNamespace(read=lambda _path: graph),
                ),
                patch(
                    "spaghetti_extractor.authority.catalog_call_contracts."
                    "CATALOG_SEARCH_INDEX_CODEC_V3",
                    SimpleNamespace(read=lambda _path: SimpleNamespace()),
                ),
                patch(
                    "spaghetti_extractor.authority.catalog_call_contracts."
                    "discover_static_span_matches",
                    return_value=matches,
                ),
            ):
                contracts = build_checked_catalog_call_contracts_v1(
                    binary=binary,
                    binary_identity="fixture.exe",
                    target_signature_graph=root / "graph.json",
                    catalog_search_index=root / "search.json",
                    physical_abi_catalogs=(root / "physical.json",),
                    out=root / "artifact",
                )

            self.assertEqual(len(contracts), 1)
            self.assertEqual(
                contracts[0].catalog_function_id,
                "catalog:alias-a",
            )


if __name__ == "__main__":
    unittest.main()
