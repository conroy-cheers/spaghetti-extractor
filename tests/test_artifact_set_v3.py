from __future__ import annotations

import gzip
import random
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from spaghetti_extractor.artifact_set_v3 import (
    IDENTITY_BUCKETS,
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    ArtifactV3Error,
    DependencyNodePlanV3,
    DependencySchedulingManifestV3,
    InternedExpressionV3,
    RecordDependencyV3,
    StructuralSchedulingManifestV3,
    StructuralUnitPlanV3,
    canonical_json_bytes_v3,
    identity_bucket_v3,
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
            self.assertTrue(all(
                pack.size_bytes <= 4096 for pack in first_manifest.packs
            ))
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
                _gzip_text(output / pack.path)
                for pack in manifest.packs
            )
            self.assertIn('"entry":"value_node"', pack_text)
            self.assertIn('"entry":"expression"', pack_text)

    def test_duplicate_heavy_transition_shape_compresses_below_twenty_percent(self) -> None:
        # The repeated exact state is representative of the structure that made
        # the current 9,041-summary DX-Ball v2 artifact 310 MiB.  Unique unit
        # identity remains outside the shared subtree.
        shared_exact_state = {
            "format": "exact-machine-state-v2",
            "instruction_inventory": [
                {"bytes": "90" * 2048, "decoder": "checked", "width": 32},
                {"bytes": "00" * 2048, "memory": "flat", "width": 32},
            ],
            "registers": {name: {"kind": "input", "name": name} for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp"
            )},
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
        uninterned_size = sum(len(canonical_json_bytes_v3(value)) + 1 for value in values)
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
                ArtifactSetWriterV3(
                    artifact_kind="facts", bindings=(BINDING,)
                ).write(Path(temporary) / "artifact", (record,))
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

    def test_structural_plan_rejects_independent_inventory_omission(self) -> None:
        plan = StructuralSchedulingManifestV3.create(
            "c" * 64,
            (
                StructuralUnitPlanV3.create("unit:a", 0x1000, 0x1010),
                StructuralUnitPlanV3.create(
                    "unit:b", 0x1010, 0x1020, dependencies=("unit:a",)
                ),
            ),
        )
        parsed = StructuralSchedulingManifestV3.parse_bytes(plan.to_bytes())
        parsed.validate({
            "unit:a": (0x1000, 0x1010, ()),
            "unit:b": (0x1010, 0x1020, ("unit:a",)),
        })
        with self.assertRaisesRegex(ArtifactV3Error, "planner_omission"):
            parsed.validate({
                "unit:a": (0x1000, 0x1010, ()),
                "unit:b": (0x1010, 0x1020, ("unit:a",)),
                "unit:c": (0x1020, 0x1030, ()),
            })

    def test_dependency_plan_checks_exact_sccs_and_record_inventory(self) -> None:
        records = {
            "node:a": (RecordDependencyV3("units", "unit:a"),),
            "node:b": (RecordDependencyV3("units", "unit:b"),),
            "node:c": (RecordDependencyV3("units", "unit:c"),),
        }
        edges = {
            "node:a": ("node:b",),
            "node:b": ("node:a",),
            "node:c": ("node:b",),
        }
        plan = DependencySchedulingManifestV3.create(
            "d" * 64,
            (
                DependencyNodePlanV3.create(
                    node, dependencies=edges[node], records=records[node]
                )
                for node in edges
            ),
        )
        parsed = DependencySchedulingManifestV3.parse_bytes(plan.to_bytes())
        parsed.validate(edges, expected_records=records)
        self.assertEqual(sorted(len(row.members) for row in parsed.sccs), [1, 2])
        with self.assertRaisesRegex(ArtifactV3Error, "planner_omission"):
            parsed.validate({"node:a": ("node:b",), "node:b": ("node:a",)})


if __name__ == "__main__":
    unittest.main()
