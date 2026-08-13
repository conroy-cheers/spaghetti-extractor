from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    ArtifactV3Error,
    DependencyNodePlanV3,
    DependencySchedulingManifestV3,
    RecordDependencyV3,
    write_artifact_bundle_v3,
)
from spaghetti_extractor.phase_framework_v3 import (
    PhaseDefinitionV3,
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
    def test_phase_consumes_bundle_through_the_standard_input_api(self) -> None:
        phase = map_units(
            name="bundle-input",
            version="1",
            source_input="units",
            input_artifact_kinds={"units": "machine-ir"},
            output_artifact_kind="facts",
            transform=lambda _context, source: ArtifactRecordV3.create(
                source.record_id, source.value.to_value()
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = _input(root, "first", 2)
            second = root / "second"
            ArtifactSetWriterV3(
                artifact_kind="machine-ir", bindings=(BINDING,)
            ).write(
                second,
                (
                    ArtifactRecordV3.create(
                        "unit:2", {"value": 2, "kind": "second"}
                    ),
                    ArtifactRecordV3.create(
                        "unit:3", {"value": 3, "kind": "second"}
                    ),
                ),
            )
            bundle = root / "bundle"
            bundle_manifest = write_artifact_bundle_v3(
                bundle,
                (first, second),
                ("unit:1", "unit:2"),
                expected_kind="machine-ir",
            )
            result = phase.run(
                output_directory=root / "output",
                inputs={"units": bundle},
                bindings=(BINDING,),
            )
            self.assertEqual(
                sorted(
                    row.record_id
                    for row in ArtifactSetReaderV3(result.output_directory).iter_records()
                ),
                ["unit:1", "unit:2"],
            )
            self.assertEqual(
                result.manifest.dependencies[0].artifact_id,
                bundle_manifest.artifact_id,
            )

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
            input_artifact_kinds={"side": "machine-ir", "units": "machine-ir"},
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
            input_artifact_kinds={"units": "machine-ir"},
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
            input_artifact_kinds={"units": "machine-ir"},
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

    def test_planned_record_inventory_replaces_redundant_source_prepass(self) -> None:
        phase = map_units(
            name="planned-units",
            version="1",
            source_input="units",
            input_artifact_kinds={"units": "machine-ir"},
            output_artifact_kind="facts",
            transform=lambda _context, source: ArtifactRecordV3.create(
                source.record_id, source.value.to_value()
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = phase.run(
                output_directory=root / "output",
                inputs={"units": _input(root, "units", 3)},
                bindings=(BINDING,),
                selected_record_ids=("unit:0", "unit:1", "unit:2"),
            )
            self.assertEqual(result.manifest.record_count, 3)

            with self.assertRaises(ArtifactV3Error) as raised:
                phase.run(
                    output_directory=root / "missing",
                    inputs={"units": root / "units"},
                    bindings=(BINDING,),
                    selected_record_ids=("unit:0", "unit:1"),
                )
            self.assertEqual(raised.exception.code, "planner_omission")

    def test_phase_rejects_wrong_input_artifact_kind_before_transform(self) -> None:
        phase = map_units(
            name="typed-input",
            version="1",
            source_input="units",
            input_artifact_kinds={"units": "exact-units-v3"},
            output_artifact_kind="facts",
            transform=lambda _context, source: source,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(
                PhaseFrameworkV3Error, "phase_input_kind_mismatch"
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
            input_artifact_kinds={"units": "machine-ir"},
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

    def test_typed_input_is_decoded_once_but_bound_to_every_work_item(self) -> None:
        decode_count = 0

        def decode(value):
            nonlocal decode_count
            decode_count += 1
            return int(value["value"])

        codec = RecordCodecV3[int](decode=decode, encode=lambda value: value)

        def transform(context, source):
            shared = context.typed_record("shared", "unit:0", codec)
            return ArtifactRecordV3.create(
                source.record_id, {"shared": shared.value}
            )

        phase = map_units(
            name="typed-input-cache",
            version="1",
            source_input="units",
            input_artifact_kinds={
                "shared": "machine-ir",
                "units": "machine-ir",
            },
            output_artifact_kind="facts",
            transform=transform,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = phase.run(
                output_directory=root / "output",
                inputs={
                    "shared": _input(root, "shared", 1),
                    "units": _input(root, "units", 4),
                },
                bindings=(BINDING,),
            )
            records = tuple(
                ArtifactSetReaderV3(result.output_directory).iter_records()
            )
            self.assertEqual(decode_count, 1)
            self.assertEqual(len(records), 4)
            for record in records:
                self.assertIn(
                    RecordDependencyV3("shared", "unit:0"),
                    record.dependencies,
                )

    def test_typed_record_accepts_the_selected_map_source(self) -> None:
        codec = RecordCodecV3[int](
            decode=lambda value: int(value["value"]),
            encode=lambda value: {"value": value},
        )

        def transform(context, source):
            typed = context.typed_record("units", source, codec)
            return ArtifactRecordV3.create(
                source.record_id, {"value": typed.value + 1}
            )

        phase = map_units(
            name="typed-selected-source",
            version="1",
            source_input="units",
            input_artifact_kinds={"units": "machine-ir"},
            output_artifact_kind="facts",
            transform=transform,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = phase.run(
                output_directory=root / "output",
                inputs={"units": _input(root, "units", 2)},
                bindings=(BINDING,),
            )
            self.assertEqual(
                sorted(
                    row.value.to_value()["value"]
                    for row in ArtifactSetReaderV3(
                        result.output_directory
                    ).iter_records()
                ),
                [1, 2],
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
            input_artifact_kinds={"units": "machine-ir"},
            output_artifact_kind="scc-summary",
            transform=transform,
            schedule_record_inputs=("units",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            units = _input(root, "units", 3)
            schedule = DependencySchedulingManifestV3.create(
                "c" * 64,
                (
                    DependencyNodePlanV3.create(
                        "unit:0",
                        dependencies=("unit:1",),
                    ),
                    DependencyNodePlanV3.create(
                        "unit:1",
                        dependencies=("unit:0",),
                    ),
                    DependencyNodePlanV3.create("unit:2"),
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

    def test_map_sccs_rejects_phase_records_in_structural_schedule(self) -> None:
        phase = map_sccs(
            name="checked-scc-source",
            version="1",
            input_artifact_kinds={
                "evidence": "machine-ir",
                "units": "machine-ir",
            },
            output_artifact_kind="scc-summary",
            transform=lambda _context, item: ArtifactRecordV3.create(
                item.record_id, {"members": list(item.scc.members)}
            ),
            schedule_record_inputs=("units",),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schedule = DependencySchedulingManifestV3.create(
                "c" * 64,
                (
                    DependencyNodePlanV3.create(
                        "unit:0",
                        records=(
                            RecordDependencyV3("evidence", "unit:0"),
                        ),
                    ),
                ),
            )
            with self.assertRaisesRegex(
                PhaseFrameworkV3Error, "phase_records_in_structural_schedule"
            ):
                phase.run(
                    output_directory=root / "output",
                    inputs={
                        "evidence": _input(root, "evidence", 1),
                        "units": _input(root, "units", 1),
                    },
                    bindings=(BINDING,),
                    schedule=schedule,
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
            input_artifact_kinds={"units": "machine-ir"},
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

    def test_producer_validation_checks_storage_without_replaying_transform(self) -> None:
        checks: list[str] = []

        def completeness(_reader, _context):
            checks.append("replayed")

        phase = reduce(
            name="producer-validated-total",
            version="1",
            input_artifact_kinds={"units": "machine-ir"},
            output_artifact_kind="total",
            transform=lambda _context: ArtifactRecordV3.create(
                "total", {"checked": True}
            ),
            completeness=completeness,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = phase.run(
                output_directory=root / "output",
                inputs={"units": _input(root, "units", 1)},
                bindings=(BINDING,),
                validation_mode="producer",
            )
            self.assertEqual(checks, [])
            self.assertEqual(
                next(
                    ArtifactSetReaderV3(result.output_directory).iter_records()
                ).value.to_value(),
                {"checked": True},
            )

    def test_reduce_attaches_the_complete_access_set_to_every_output(self) -> None:
        def transform(context):
            values = tuple(context.records("units"))
            return tuple(
                ArtifactRecordV3.create(
                    f"summary:{index}", {"records": len(values)}
                )
                for index in range(2)
            )

        def completeness(reader, _context):
            reader.validate_completeness(("summary:0", "summary:1"))

        phase = reduce(
            name="multi-summary",
            version="1",
            input_artifact_kinds={"units": "machine-ir"},
            output_artifact_kind="summaries",
            transform=transform,
            completeness=completeness,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = phase.run(
                output_directory=root / "output",
                inputs={"units": _input(root, "units", 3)},
                bindings=(BINDING,),
            )
            records = tuple(
                ArtifactSetReaderV3(result.output_directory).iter_records()
            )
            self.assertEqual(len(records), 2)
            self.assertEqual(
                {tuple(record.dependencies) for record in records},
                {tuple(records[0].dependencies)},
            )
            self.assertEqual(len(records[0].dependencies), 3)

    def test_artifact_scoped_reduce_uses_manifest_authority_without_record_bloat(self) -> None:
        def transform(context):
            count = sum(1 for _record in context.records("units"))
            return ArtifactRecordV3.create("summary", {"count": count})

        def completeness(reader, context):
            submitted = next(reader.iter_records()).value.to_value()
            expected = sum(1 for _record in context.records("units"))
            self.assertEqual(submitted, {"count": expected})

        phase = reduce(
            name="artifact-scoped-summary",
            version="1",
            input_artifact_kinds={"units": "machine-ir"},
            output_artifact_kind="summary",
            transform=transform,
            completeness=completeness,
            dependency_scope="artifact",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = phase.run(
                output_directory=root / "output",
                inputs={"units": _input(root, "units", 4)},
                bindings=(BINDING,),
            )
            record = next(
                ArtifactSetReaderV3(result.output_directory).iter_records()
            )
            self.assertEqual(record.dependencies, ())
            self.assertEqual(len(result.manifest.dependencies), 1)

    def test_artifact_scope_is_rejected_for_mapped_outputs(self) -> None:
        with self.assertRaises(PhaseFrameworkV3Error) as raised:
            PhaseDefinitionV3(
                name="unsafe-artifact-scope",
                version="1",
                form="map_units",
                output_artifact_kind="facts",
                required_inputs=("units",),
                input_artifact_kinds=(("units", "machine-ir"),),
                transform=lambda _context, source: source,
                source_input="units",
                dependency_scope="artifact",
            )
        self.assertEqual(raised.exception.code, "unsafe_artifact_dependency_scope")

    def test_reduce_without_completeness_is_rejected_at_definition_time(self) -> None:
        with self.assertRaisesRegex(
            TypeError, "missing 1 required keyword-only argument: 'completeness'"
        ):
            reduce(  # type: ignore[call-arg]
                name="unsafe",
                version="1",
                input_artifact_kinds={"units": "machine-ir"},
                output_artifact_kind="unsafe",
                transform=lambda _context: ArtifactRecordV3.create("one", {}),
            )


if __name__ == "__main__":
    unittest.main()
