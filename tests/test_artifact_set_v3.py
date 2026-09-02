from __future__ import annotations

import gzip
import os
import random
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spaghetti_extractor.artifacts import artifact_set
from spaghetti_extractor.artifacts.artifact_set import (
    IDENTITY_BUCKETS,
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    ArtifactV3Error,
    InternedExpressionV3,
    RecordDependencyV3,
    canonical_json_bytes_v3,
    identity_bucket_v3,
    parse_canonical_json_lines_v3,
)
from spaghetti_extractor.artifacts.io import (
    ArtifactBundleReaderV3,
    ArtifactSetReaderV3,
    open_artifact_reader_v3,
    write_artifact_bundle_v3,
)


BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", "a" * 64)
UPSTREAM = ArtifactDependencyV3(
    "units", "machine-ir", "artifact-set-v3:upstream", "b" * 64
)


def _record(index: int) -> ArtifactRecordV3:
    expression = InternedExpressionV3.create(
        {"op": "add", "left": {"reg": "eax"}, "right": 4}
    )
    return ArtifactRecordV3.create(
        f"unit:{index:05d}",
        {
            "index": index,
            "target": expression.reference(),
            "status": "complete",
        },
        dependencies=(RecordDependencyV3("units", f"unit:{index:05d}"),),
        expressions=(expression,),
    )


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _gzip_text(path: Path) -> str:
    with gzip.open(path, "rt", encoding="ascii") as source:
        return source.read()


class ArtifactSetV3Tests(unittest.TestCase):
    def test_native_canonical_encoding_matches_python_reference(self) -> None:
        if not artifact_set.native_acceleration_available_v3():
            self.skipTest("native extension is unavailable outside the Nix environment")
        values = (
            None,
            True,
            -123456789012345678901234567890,
            "ascii\ncaf\u00e9\U0001f642",
            {"z": [1, False], "a": {"control": "\u0001"}},
        )
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(
                    canonical_json_bytes_v3(value),
                    artifact_set._python_canonical_json_bytes_v3(value),
                )

    def test_native_batch_parser_matches_python_reference(self) -> None:
        values = (
            {"a": 1, "b": [True, None, "caf\u00e9"]},
            {"integer": 123456789012345678901234567890},
            ["\U0001f642", {"control": "\u0001"}],
        )
        encoded = b"".join(canonical_json_bytes_v3(value) + b"\n" for value in values)
        observed = parse_canonical_json_lines_v3(
            encoded, location="native fixture", maximum_line_bytes=4096
        )
        with (
            mock.patch.object(artifact_set, "_native_artifacts_v3", None),
            mock.patch.dict(os.environ, {"SPAGHETTI_REQUIRE_NATIVE": "0"}),
        ):
            reference = parse_canonical_json_lines_v3(
                encoded, location="python fixture", maximum_line_bytes=4096
            )
        self.assertEqual(observed, reference)

    def test_batch_parser_rejects_noncanonical_and_invalid_lines(self) -> None:
        cases = (
            (b'{"b":1,"a":2}\n', "noncanonical_json"),
            (b'{"a":1,"a":2}\n', "noncanonical_json"),
            (b'{"a":1.0}\n', "noncanonical_json"),
            (b"{}\r\n", "noncanonical_json"),
            (b'{"a":}\n', "invalid_json"),
        )
        for encoded, code in cases:
            with self.subTest(encoded=encoded):
                with self.assertRaises(ArtifactV3Error) as raised:
                    parse_canonical_json_lines_v3(
                        encoded,
                        location="malformed fixture",
                        maximum_line_bytes=4096,
                    )
                self.assertEqual(raised.exception.code, code)

    def test_required_native_acceleration_fails_closed(self) -> None:
        with (
            mock.patch.object(artifact_set, "_native_artifacts_v3", None),
            mock.patch.dict(os.environ, {"SPAGHETTI_REQUIRE_NATIVE": "1"}),
        ):
            with self.assertRaises(ArtifactV3Error) as raised:
                canonical_json_bytes_v3({"required": True})
        self.assertEqual(raised.exception.code, "native_acceleration_missing")

    def test_bundle_is_a_zero_copy_exact_record_selection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            ArtifactSetWriterV3(
                artifact_kind="facts", bindings=(BINDING,), dependencies=(UPSTREAM,)
            ).write(first, (_record(1), _record(2)))
            ArtifactSetWriterV3(
                artifact_kind="facts", bindings=(BINDING,), dependencies=(UPSTREAM,)
            ).write(second, (_record(3), _record(4)))
            bundle = root / "bundle"
            manifest = write_artifact_bundle_v3(
                bundle,
                (first, second),
                ("unit:00002", "unit:00003"),
                expected_kind="facts",
            )

            reader = open_artifact_reader_v3(bundle)
            self.assertIsInstance(reader, ArtifactBundleReaderV3)
            self.assertEqual(
                sorted(record.record_id for record in reader.iter_records()),
                ["unit:00002", "unit:00003"],
            )
            self.assertEqual(reader.manifest.artifact_id, manifest.artifact_id)
            self.assertEqual(
                reader.dependency_binding("facts").artifact_id,
                manifest.artifact_id,
            )
            self.assertTrue((bundle / "members" / "0000").is_symlink())

    def test_bundle_inventory_corruption_fails_before_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            ArtifactSetWriterV3(
                artifact_kind="facts", bindings=(BINDING,), dependencies=(UPSTREAM,)
            ).write(source, (_record(1),))
            bundle = root / "bundle"
            write_artifact_bundle_v3(
                bundle, (source,), ("unit:00001",), expected_kind="facts"
            )
            inventory = bundle / "record-ids.json.gz"
            inventory.write_bytes(inventory.read_bytes() + b"corrupt")
            with self.assertRaisesRegex(ArtifactV3Error, "corrupt_bundle_inventory"):
                ArtifactBundleReaderV3(bundle)

    def test_round_trip_is_canonical_and_deterministic(self) -> None:
        records = [_record(index) for index in range(180)]
        shuffled = list(records)
        random.Random(42).shuffle(shuffled)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            writer = ArtifactSetWriterV3(
                artifact_kind="transition-summary",
                bindings=(BINDING,),
                dependencies=(UPSTREAM,),
                max_pack_bytes=4096,
            )
            first_manifest = writer.write(first, iter(records))
            second_manifest = writer.write(second, iter(shuffled))

            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual(_tree_bytes(first), _tree_bytes(second))
            self.assertEqual(
                [row.record_id for row in ArtifactSetReaderV3(first).iter_records()],
                [row.record_id for row in ArtifactSetReaderV3(second).iter_records()],
            )
            self.assertTrue(
                all(pack.size_bytes <= 4096 for pack in first_manifest.packs)
            )
            self.assertEqual(first_manifest.record_count, len(records))

    def test_recursive_value_and_expression_interning_round_trip(self) -> None:
        shared = {
            "pre_state": {
                "registers": {name: 0 for name in ("eax", "ebx", "ecx", "edx")},
                "bytes": [0] * 256,
            }
        }
        expression = InternedExpressionV3.create(
            {"op": "load", "address": {"op": "add", "left": "eax", "right": 8}}
        )
        records = [
            ArtifactRecordV3.create(
                f"unit:{index:04d}",
                {"unit": index, "exact": shared, "result": expression.reference()},
                expressions=(expression,),
            )
            for index in range(96)
        ]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifact"
            manifest = ArtifactSetWriterV3(
                artifact_kind="transition-summary", bindings=(BINDING,)
            ).write(output, iter(records))
            observed = {
                row.record_id: row.value.to_value()
                for row in ArtifactSetReaderV3(output).iter_records()
            }
            self.assertEqual(
                observed,
                {row.record_id: row.value.to_value() for row in records},
            )
            pack_text = "".join(
                _gzip_text(output / pack.path) for pack in manifest.packs
            )
            self.assertIn('"entry":"value_node"', pack_text)
            self.assertIn('"entry":"expression"', pack_text)

    def test_duplicate_heavy_transition_shape_compresses_below_twenty_percent(
        self,
    ) -> None:
        # The repeated exact state is representative of the structure that made
        # the current 9,041-summary DX-Ball v2 artifact 310 MiB.  Unique unit
        # identity remains outside the shared subtree.
        shared_exact_state = {
            "format": "exact-machine-state-v2",
            "instruction_inventory": [
                {"bytes": "90" * 2048, "decoder": "checked", "width": 32},
                {"bytes": "00" * 2048, "memory": "flat", "width": 32},
            ],
            "registers": {
                name: {"kind": "input", "name": name}
                for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp")
            },
        }
        count = 768
        values = [
            {
                "format": "transition-summary-v2",
                "unit": f"unit:{index:05d}",
                "status": "complete",
                "exact_record": shared_exact_state,
            }
            for index in range(count)
        ]
        uninterned_size = sum(
            len(canonical_json_bytes_v3(value)) + 1 for value in values
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifact"
            manifest = ArtifactSetWriterV3(
                artifact_kind="transition-summary", bindings=(BINDING,)
            ).write(
                output,
                (
                    ArtifactRecordV3.create(f"unit:{index:05d}", value)
                    for index, value in enumerate(values)
                ),
            )
            packed_size = len(manifest.to_bytes()) + sum(
                pack.size_bytes for pack in manifest.packs
            )
            self.assertLess(packed_size / uninterned_size, 0.20)

    def test_corrupt_pack_is_rejected_before_records_are_returned(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifact"
            manifest = ArtifactSetWriterV3(
                artifact_kind="facts", bindings=(BINDING,), dependencies=(UPSTREAM,)
            ).write(output, (_record(1),))
            pack = output / manifest.packs[0].path
            pack.write_bytes(pack.read_bytes() + b"corrupt")
            with self.assertRaisesRegex(ArtifactV3Error, "corrupt_pack"):
                list(ArtifactSetReaderV3(output).iter_records())

    def test_cached_pack_rejects_mutation_after_first_checked_read(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifact"
            manifest = ArtifactSetWriterV3(
                artifact_kind="facts",
                bindings=(BINDING,),
                dependencies=(UPSTREAM,),
            ).write(output, (_record(1),))
            reader = ArtifactSetReaderV3(output)
            self.assertEqual(reader.get_record("unit:00001"), _record(1))

            pack = output / manifest.packs[0].path
            pack.write_bytes(pack.read_bytes() + b"corrupt")
            with self.assertRaises(ArtifactV3Error) as raised:
                reader.get_record("unit:00001")
            self.assertEqual(raised.exception.code, "artifact_changed_during_read")
            self.assertIn("immutable", raised.exception.remediation)

    def test_oversized_single_record_has_actionable_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ArtifactV3Error) as raised:
                ArtifactSetWriterV3(
                    artifact_kind="facts",
                    bindings=(BINDING,),
                    max_pack_bytes=512,
                ).write(
                    Path(temporary) / "artifact",
                    (ArtifactRecordV3.create("large", {"payload": "x" * 5000}),),
                )
            self.assertEqual(raised.exception.code, "oversized_record")
            self.assertIn("split the semantic record", raised.exception.remediation)

    def test_undeclared_record_dependency_is_rejected_with_remediation(self) -> None:
        record = ArtifactRecordV3.create(
            "unit:1",
            {"status": "complete"},
            dependencies=(RecordDependencyV3("missing", "upstream:1"),),
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ArtifactV3Error) as raised:
                ArtifactSetWriterV3(artifact_kind="facts", bindings=(BINDING,)).write(
                    Path(temporary) / "artifact", (record,)
                )
            self.assertEqual(raised.exception.code, "undeclared_dependency")
            self.assertIn("add those inputs", raised.exception.remediation)

    def test_reader_streams_packs_without_path_read_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "artifact"
            ArtifactSetWriterV3(
                artifact_kind="facts", bindings=(BINDING,), dependencies=(UPSTREAM,)
            ).write(output, (_record(index) for index in range(120)))
            reader = ArtifactSetReaderV3(output)
            with mock.patch.object(
                Path,
                "read_bytes",
                side_effect=AssertionError("pack read_bytes is forbidden"),
            ):
                observed = [row.record_id for row in reader.iter_records()]
            self.assertEqual(len(observed), 120)

    def test_identity_assignment_is_stable_and_exactly_64_way(self) -> None:
        first = [identity_bucket_v3(f"unit:{index}") for index in range(4096)]
        second = [identity_bucket_v3(f"unit:{index}") for index in range(4096)]
        self.assertEqual(first, second)
        self.assertEqual(set(first), set(range(IDENTITY_BUCKETS)))


if __name__ == "__main__":
    unittest.main()
