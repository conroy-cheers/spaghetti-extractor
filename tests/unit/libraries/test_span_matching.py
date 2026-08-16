from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.libraries.abi_catalog import (
    LIBRARY_ABI_CATALOG_CODEC_V3,
    build_catalog_search_index,
)
from spaghetti_extractor.libraries.signature_graph import build_target_signature_graph
from spaghetti_extractor.libraries.span_matching import discover_static_span_matches
from tests.pe_fixtures import pe32_import_image

from .library_fixture_support import (
    abi_profile,
    catalog,
    function_signature,
    machine_unit,
    procedure_candidates,
    write_machine,
)


class StaticSpanMatchingTests(unittest.TestCase):
    def test_relocation_masked_body_is_recovered_without_symbol_partition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target_code = bytes.fromhex("55894433221183c001905dc3")
            pe = pe32_import_image(target_code, symbol="WriteFile")
            machine = write_machine(
                root,
                [
                    {
                        **machine_unit("body", 0x1000, "a" * 64, abi_profile()),
                        "source": {
                            "original": {
                                "rva_start": 0x1000,
                                "rva_end": 0x1000 + len(target_code),
                            },
                            "instruction_bytes_sha256": "a" * 64,
                        },
                    }
                ],
                binary_bytes=pe,
            )
            graph = build_target_signature_graph(
                machine,
                root / "target-signatures.json",
                procedure_candidates=procedure_candidates(
                    machine, (("procedure:body", ("body",)),)
                ),
                original_pe=root / "fixture.exe",
            )
            signature = replace(
                function_signature(
                    function_id="catalog-body",
                    release="1.0",
                    exact_hash=None,
                ),
                normalized_bytes_sha256="0" * 64,
                masked_bytes_hex="55890000000083c001905dc3",
                relocation_holes=((2, 4, "6", "_global"),),
                fixed_bytes=8,
                match_strength="strong",
                object_size=len(target_code),
            )
            catalog_path = root / "catalog.json"
            LIBRARY_ABI_CATALOG_CODEC_V3.write(
                catalog_path, catalog((signature,))
            )
            index = build_catalog_search_index(
                catalog_path, root / "search-index.json"
            )

            matches = discover_static_span_matches(
                target_graph=graph,
                search_index=index,
                target_pe=root / "fixture.exe",
            )

            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].target_rva_start, 0x1000)
            self.assertEqual(matches[0].target_unit_ids, ("body",))
            self.assertEqual(matches[0].catalog_function_id, "catalog-body")

    def test_target_pe_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pe = pe32_import_image(b"\x90" * 8, symbol="WriteFile")
            machine = write_machine(
                root,
                [machine_unit("body", 0x1000, "a" * 64, abi_profile())],
                binary_bytes=pe,
            )
            graph = build_target_signature_graph(
                machine,
                root / "target-signatures.json",
                procedure_candidates=procedure_candidates(
                    machine, (("procedure:body", ("body",)),)
                ),
            )
            catalog_path = root / "catalog.json"
            LIBRARY_ABI_CATALOG_CODEC_V3.write(
                catalog_path,
                catalog(
                    (
                        function_signature(
                            function_id="catalog-body",
                            release="1.0",
                            exact_hash=None,
                        ),
                    )
                ),
            )
            index = build_catalog_search_index(
                catalog_path, root / "search-index.json"
            )
            (root / "fixture.exe").write_bytes(pe + b"changed")

            with self.assertRaisesRegex(ValueError, "does not match"):
                discover_static_span_matches(
                    target_graph=graph,
                    search_index=index,
                    target_pe=root / "fixture.exe",
                )


if __name__ == "__main__":
    unittest.main()
