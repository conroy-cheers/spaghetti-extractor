from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    DependencyNodePlanV3,
    DependencySchedulingManifestV3,
    RecordDependencyV3,
)
from spaghetti_extractor.phase_framework_v3 import (
    PhaseFrameworkV3Error,
    RecordCodecV3,
    map_sccs,
    map_units,
    reduce,
)


BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", "a" * 64)


def _input(root: Path, name: str, count: int = 4) -> Path:
    output = root / name
    ArtifactSetWriterV3(
        artifact_kind="machine-ir", bindings=(BINDING,)
    ).write(
        output,
        (
            ArtifactRecordV3.create(
                f"unit:{index}", {"value": index, "kind": name}
            )
            for index in range(count)
        ),
    )
    return output


class PhaseFrameworkV3Tests(unittest.TestCase):
    def test_map_units_is_one_to_one_and_auto_binds_accesses(self) -> None:
        def transform(context, source):
            side = context.record("side", source.record_id)
            return ArtifactRecordV3.create(
                source.record_id,
                {
                    "sum": source.value.to_value()["value"]
                    + side.value.to_value()["value"]
                },
            )

        phase = map_units(
            name="sum-units",
            version="1",
            source_input="units",
            required_inputs=("side", "units"),
            output_artifact_kind="summed-unit",
            transform=transform,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = phase.run(
                output_directory=root / "output",
                inputs={"units": _input(root, "units"), "side": _input(root, "side")},
                bindings=(BINDING,),
            )
            records = list(ArtifactSetReaderV3(result.output_directory).iter_records())
            self.assertEqual(len(records), 4)
            for record in records:
                self.assertEqual(
                    {dependency.input_name for dependency in record.dependencies},
                    {"side", "units"},
                )
            self.assertEqual(
                {row.name for row in result.manifest.dependencies},
                {"side", "units"},
            )

    def test_map_units_rejects_undeclared_reads_with_exact_remediation(self) -> None:
        phase = map_units(
            name="bad-read",
            version="1",
            source_input="units",
            required_inputs=("units",),
            output_artifact_kind="facts",
            transform=lambda context, source: (
                context.record("secret", source.record_id), source
            )[1],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(PhaseFrameworkV3Error) as raised:
                phase.run(
                    output_directory=root / "output",
                    inputs={"units": _input(root, "units")},
                    bindings=(BINDING,),
                )
            self.assertEqual(raised.exception.code, "undeclared_input_access")
            self.assertIn("required_inputs", raised.exception.remediation)

    def test_map_units_rejects_cardinality_change(self) -> None:
        phase = map_units(
            name="bad-cardinality",
            version="1",
            source_input="units",
            required_inputs=("units",),
            output_artifact_kind="facts",
            transform=lambda _context, source: ArtifactRecordV3.create(
                source.record_id + ":other", source.value.to_value()
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                PhaseFrameworkV3Error, "map_units_cardinality_violation"
            ):
                phase.run(
                    output_directory=root / "output",
                    inputs={"units": _input(root, "units")},
                    bindings=(BINDING,),
                )

    def test_typed_codec_keeps_domain_types_out_of_storage_layer(self) -> None:
        codec = RecordCodecV3[int](
            decode=lambda value: int(value["value"]),
            encode=lambda value: {"doubled": value},
        )

        def transform(_context, source):
            typed = codec.read(source)
            return codec.write(source.record_id, typed.value * 2)

        phase = map_units(
            name="typed-double",
            version="1",
            source_input="units",
            required_inputs=("units",),
            output_artifact_kind="typed-result",
            transform=transform,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = phase.run(
                output_directory=root / "output",
                inputs={"units": _input(root, "units", 2)},
                bindings=(BINDING,),
            )
            values = [
                row.value.to_value()
                for row in ArtifactSetReaderV3(result.output_directory).iter_records()
            ]
            self.assertEqual(
                sorted(values, key=lambda row: row["doubled"]),
                [{"doubled": 0}, {"doubled": 2}],
            )

    def test_map_sccs_auto_binds_planned_records(self) -> None:
        def transform(context, work_item):
            values = [record.value.to_value()["value"] for record in work_item.records(context)]
            return ArtifactRecordV3.create(
                work_item.record_id,
                {"members": list(work_item.scc.members), "sum": sum(values)},
            )

        phase = map_sccs(
            name="summarize-scc",
            version="1",
            required_inputs=("units",),
            output_artifact_kind="scc-summary",
            transform=transform,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            units = _input(root, "units", 3)
            schedule = DependencySchedulingManifestV3.create(
                "c" * 64,
                (
                    DependencyNodePlanV3.create(
                        "node:0",
                        dependencies=("node:1",),
                        records=(RecordDependencyV3("units", "unit:0"),),
                    ),
                    DependencyNodePlanV3.create(
                        "node:1",
                        dependencies=("node:0",),
                        records=(RecordDependencyV3("units", "unit:1"),),
                    ),
                    DependencyNodePlanV3.create(
                        "node:2",
                        records=(RecordDependencyV3("units", "unit:2"),),
                    ),
                ),
            )
            result = phase.run(
                output_directory=root / "output",
                inputs={"units": units},
                bindings=(BINDING,),
                schedule=schedule,
            )
            records = list(ArtifactSetReaderV3(result.output_directory).iter_records())
            self.assertEqual(len(records), 2)
            self.assertEqual(
                sorted(len(row.dependencies) for row in records), [1, 2]
            )

    def test_reduce_requires_and_runs_independent_completeness_hook(self) -> None:
        checks: list[int] = []

        def completeness(reader, _context):
            values = list(reader.iter_records())
            checks.append(len(values))
            reader.validate_completeness(("total",))

        phase = reduce(
            name="total",
            version="1",
            required_inputs=("units",),
            output_artifact_kind="total",
            transform=lambda context: ArtifactRecordV3.create(
                "total",
                {"total": sum(row.value.to_value()["value"] for row in context.records("units"))},
            ),
            completeness=completeness,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = phase.run(
                output_directory=root / "output",
                inputs={"units": _input(root, "units", 5)},
                bindings=(BINDING,),
            )
            self.assertEqual(checks, [1])
            record = next(ArtifactSetReaderV3(result.output_directory).iter_records())
            self.assertEqual(record.value.to_value(), {"total": 10})
            self.assertEqual(len(record.dependencies), 5)

    def test_reduce_without_completeness_is_rejected_at_definition_time(self) -> None:
        with self.assertRaisesRegex(
            TypeError, "missing 1 required keyword-only argument: 'completeness'"
        ):
            reduce(  # type: ignore[call-arg]
                name="unsafe",
                version="1",
                required_inputs=("units",),
                output_artifact_kind="unsafe",
                transform=lambda _context: ArtifactRecordV3.create("one", {}),
            )


if __name__ == "__main__":
    unittest.main()
