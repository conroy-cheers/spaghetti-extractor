from __future__ import annotations

import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.artifacts.formats import (
    LIBRARY_ARTIFACT_INPUTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
)
from spaghetti_extractor.libraries.catalog import (
    bind_library_artifact_inputs,
    index_library_artifacts,
)

from ._support import archive, coff_object, omf_record


_FUNCTION = bytes.fromhex("5589e5b801000000c3")


class LibraryCatalogParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_indexes_archive_and_omf_without_executing_artifacts(self) -> None:
        (self.artifacts / "runtime.a").write_bytes(
            archive("runtime.obj", coff_object(_FUNCTION, symbol="_runtime"))
        )
        (self.artifacts / "vintage.obj").write_bytes(
            omf_record(0x80, b"\x07VINTAGE")
            + omf_record(0x90, b"\x00\x01\x06legacy\x00\x00\x00")
            + omf_record(
                0xA0,
                b"\x01\x00\x00\x55\x89\xe5\x31\xc0\x40\x5d\xc3",
            )
        )
        inputs = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                "catalog_id": "fixture-libraries",
                "artifacts": [
                    {
                        "id": "runtime",
                        "path": "runtime.a",
                        "visibility": "public",
                        "redistributable": True,
                    },
                    {
                        "id": "vintage",
                        "path": "vintage.obj",
                        "visibility": "private",
                        "redistributable": False,
                    },
                ],
            }
        )
        index = index_library_artifacts(
            inputs=inputs,
            artifact_root=self.artifacts,
            out=self.root / "index.json",
        )

        self.assertEqual(index["status"], "indexed")
        self.assertFalse(index["executes_original_binary"])
        self.assertEqual(index["counts"]["function_fingerprints"], 2)
        archive_index = index["artifacts"][0]["index"]
        self.assertEqual(archive_index["kind"], "archive")
        function = archive_index["members"][0]["index"][
            "function_fingerprints"
        ][0]
        self.assertEqual(function["name"], "_runtime")
        self.assertEqual(function["bytes_sha256"], sha256(_FUNCTION).hexdigest())
        omf = index["artifacts"][1]["index"]
        self.assertEqual(omf["kind"], "omf_object")
        self.assertEqual(omf["module_name"], "VINTAGE")
        self.assertTrue(omf["records"][0]["checksum_valid"])
        self.assertEqual(omf["function_fingerprints"][0]["name"], "legacy")
        self.assertTrue(omf["function_fingerprints"][0]["matchable"])

    def test_v2_index_preserves_snapshot_member_and_library_identity(self) -> None:
        (self.artifacts / "runtime.a").write_bytes(
            archive("runtime.obj", coff_object(_FUNCTION, symbol="_runtime"))
        )
        inputs = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
                "catalog_id": "runtime-catalog",
                "snapshot": {
                    "id": "runtime-build-1",
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
        index = index_library_artifacts(
            inputs=inputs,
            artifact_root=self.artifacts,
            out=self.root / "v2-index.json",
        )

        self.assertEqual(
            index["format"], "spaghetti-extractor-library-artifact-index-v2"
        )
        member = index["artifacts"][0]["index"]["members"][0]
        self.assertTrue(member["member_id"].startswith("member:"))
        fingerprint = member["index"]["function_fingerprints"][0]
        self.assertTrue(fingerprint["fingerprint_id"].startswith("fingerprint:"))
        self.assertEqual(
            index["artifacts"][0]["library_identity"]["family_id"],
            "fixture-runtime",
        )

    def test_coff_fingerprint_separates_return_alignment(self) -> None:
        aligned = bytes.fromhex("8b442404c3909090")
        (self.artifacts / "aligned.a").write_bytes(
            archive("aligned.obj", coff_object(aligned, symbol="_aligned"))
        )
        inputs = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                "catalog_id": "aligned-library",
                "artifacts": [{"id": "aligned", "path": "aligned.a"}],
            }
        )
        index = index_library_artifacts(
            inputs=inputs,
            artifact_root=self.artifacts,
            out=self.root / "aligned-index.json",
        )

        fingerprint = index["artifacts"][0]["index"]["members"][0]["index"][
            "function_fingerprints"
        ][0]
        self.assertEqual(fingerprint["size"], 5)
        self.assertEqual(fingerprint["object_size"], 8)
        self.assertEqual(fingerprint["trailing_alignment"], "909090")
        self.assertEqual(fingerprint["match_strength"], "weak")

    def test_coff_fingerprint_separates_tail_jump_alignment(self) -> None:
        aligned = bytes.fromhex("31c0e9000000009090")
        (self.artifacts / "tail.a").write_bytes(
            archive("tail.obj", coff_object(aligned, symbol="_tail"))
        )
        inputs = bind_library_artifact_inputs(
            {
                "format": LIBRARY_ARTIFACT_INPUTS_FORMAT,
                "catalog_id": "tail-library",
                "artifacts": [{"id": "tail", "path": "tail.a"}],
            }
        )
        index = index_library_artifacts(
            inputs=inputs,
            artifact_root=self.artifacts,
            out=self.root / "tail-index.json",
        )

        fingerprint = index["artifacts"][0]["index"]["members"][0]["index"][
            "function_fingerprints"
        ][0]
        self.assertEqual(fingerprint["size"], 7)
        self.assertEqual(fingerprint["trailing_alignment"], "9090")


if __name__ == "__main__":
    unittest.main()
