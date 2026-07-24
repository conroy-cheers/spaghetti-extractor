from __future__ import annotations

import json
import math
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.artifact_byte_packs import (
    ARTIFACT_BYTE_PACK_FORMAT,
    ArtifactBytePackGenerationError,
    ExternalArtifactBytesBinding,
    generate_artifact_byte_pack_bundle,
)


class StageARelationalArtifactBytePackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_generates_deterministic_independent_shards_and_compact_aggregate(
        self,
    ) -> None:
        artifact = self.root / "opaque.bin"
        artifact.write_bytes(bytes(index % 251 for index in range(4097)))
        first = self.root / "first"
        second = self.root / "second"

        inventory = generate_artifact_byte_pack_bundle(
            artifact_path=artifact,
            out_dir=first,
            module_prefix="OpaqueFixture",
            namespace="StageA.GeneratedRelational.OpaqueFixture",
            pack_size=1024,
            chunk_size=256,
        )
        repeated = generate_artifact_byte_pack_bundle(
            artifact_path=artifact,
            out_dir=second,
            module_prefix="OpaqueFixture",
            namespace="StageA.GeneratedRelational.OpaqueFixture",
            pack_size=1024,
            chunk_size=256,
        )

        self.assertEqual(inventory.payload(), repeated.payload())
        self.assertEqual(inventory.payload()["format"], ARTIFACT_BYTE_PACK_FORMAT)
        self.assertEqual(len(inventory.packs), math.ceil(4097 / 1024))
        self.assertEqual(len(inventory.modules), len(inventory.packs) + 1)
        self.assertEqual(
            json.loads((first / "artifact-byte-packs.json").read_text()),
            inventory.payload(),
        )
        aggregate = (
            first / f"StageA/{inventory.aggregate_module}.lean"
        ).read_text()
        self.assertLess(len(aggregate.encode()), 4_000)
        self.assertNotRegex(aggregate, r"\[\s*0,\s*1,\s*2")
        for pack in inventory.packs:
            payload = (first / f"StageA/{pack.module}.lean").read_text()
            self.assertIn("ExactArtifactBytes", payload)
            self.assertIn("bytes :=", payload)
            self.assertNotIn("sha256", payload.lower())
            self.assertLess(len(payload.encode()), 20_000)

        self.assertEqual(
            inventory.binding,
            ExternalArtifactBytesBinding(
                module=f"StageA.{inventory.aggregate_module}",
                namespace=inventory.namespace,
                bytes_symbol=inventory.aggregate_bytes_name,
            ),
        )

    def test_empty_artifact_has_a_compact_identity(self) -> None:
        artifact = self.root / "empty.bin"
        artifact.write_bytes(b"")
        inventory = generate_artifact_byte_pack_bundle(
            artifact_path=artifact,
            out_dir=self.root / "empty",
            module_prefix="EmptyFixture",
        )
        aggregate = (
            self.root
            / "empty"
            / "StageA"
            / f"{inventory.aggregate_module}.lean"
        ).read_text()

        self.assertEqual(inventory.packs, ())
        self.assertIn("ExactArtifactBytes.empty", aggregate)

    def test_one_byte_change_invalidates_only_its_payload_source(self) -> None:
        artifact = self.root / "mutable.bin"
        artifact.write_bytes(bytes(range(32)))
        first = generate_artifact_byte_pack_bundle(
            artifact_path=artifact,
            out_dir=self.root / "before",
            module_prefix="IncrementalFixture",
            pack_size=8,
            chunk_size=4,
        )
        changed = bytearray(artifact.read_bytes())
        changed[10] ^= 0xFF
        artifact.write_bytes(changed)
        second = generate_artifact_byte_pack_bundle(
            artifact_path=artifact,
            out_dir=self.root / "after",
            module_prefix="IncrementalFixture",
            pack_size=8,
            chunk_size=4,
        )

        before = {row["name"]: row["source_sha256"] for row in first.modules}
        after = {row["name"]: row["source_sha256"] for row in second.modules}
        changed_modules = {name for name in before if before[name] != after[name]}
        self.assertEqual(changed_modules, {first.packs[1].module})
        self.assertEqual(
            before[first.aggregate_module], after[second.aggregate_module]
        )

    def test_rejects_invalid_sizes_paths_and_lean_names(self) -> None:
        artifact = self.root / "artifact.bin"
        artifact.write_bytes(b"artifact")
        for kwargs, message in (
            ({"pack_size": 0}, "pack and chunk sizes"),
            ({"pack_size": 4, "chunk_size": 8}, "pack and chunk sizes"),
            ({"module_prefix": "Bad-Name"}, "module prefix"),
            ({"namespace": "StageA.Bad; axiom escape : False"}, "namespace"),
            ({"aggregate_bytes_name": "bad.name"}, "bytes name"),
            ({"inventory_filename": "../escape.json"}, "inventory filename"),
            ({"inventory_filename": "inventory.txt"}, "inventory filename"),
        ):
            options = {
                "artifact_path": artifact,
                "out_dir": self.root / "rejected",
                "module_prefix": "Fixture",
                **kwargs,
            }
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(
                ArtifactBytePackGenerationError, message
            ):
                generate_artifact_byte_pack_bundle(**options)

        with self.assertRaisesRegex(
            ArtifactBytePackGenerationError, "qualified StageA"
        ):
            ExternalArtifactBytesBinding("Other.Data", "Other.Data", "bytes")

    def test_sources_have_no_unchecked_escape_hatches(self) -> None:
        paths = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/RelationalArtifactBytePacks.lean",
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/relational/lean/artifact_byte_packs.py",
        )
        for path in paths:
            source = path.read_text(encoding="utf-8")
            for marker in ("native_decide", "sorry", "axiom", "unsafe"):
                self.assertIsNone(re.search(rf"\b{marker}\b", source), (path, marker))


if __name__ == "__main__":
    unittest.main()
