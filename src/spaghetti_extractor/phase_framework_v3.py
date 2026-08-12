"""Ergonomic typed phase forms over content-addressed v3 artifact sets.

Phase authors provide a pure record transformation.  This module owns input
declaration, access tracking, dependency binding, canonical output packing,
and common completeness rules.  A transform cannot obtain an undeclared path,
and every record it reads is attached to its output automatically.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Generic, Literal, TypeAlias, TypeVar

from .artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactDependencyV3,
    ArtifactRecordV3,
    ArtifactSetManifestV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    ArtifactV3Error,
    DependencySccPlanV3,
    DependencySchedulingManifestV3,
    InternedExpressionV3,
    RecordDependencyV3,
    canonical_sha256_v3,
)


PhaseFormV3: TypeAlias = Literal["map_units", "map_sccs", "reduce"]
T = TypeVar("T")


class PhaseFrameworkV3Error(ArtifactV3Error):
    """A phase declaration or transformation violated the v3 contract."""


def _phase_fail(
    code: str,
    message: str,
    remediation: str,
    *,
    location: str | None = None,
) -> None:
    raise PhaseFrameworkV3Error(
        code, message, remediation=remediation, location=location
    )


def _canonical_names(values: Iterable[str], context: str) -> tuple[str, ...]:
    result = tuple(values)
    if (
        not result
        or result != tuple(sorted(set(result)))
        or any(not isinstance(value, str) or not value for value in result)
    ):
        _phase_fail(
            "invalid_phase_inputs",
            f"{context} must be a nonempty sorted unique name inventory",
            "declare required inputs once in sorted order",
        )
    return result


@dataclass(frozen=True)
class TypedRecordV3(Generic[T]):
    """A typed semantic value retaining its exact artifact envelope."""

    record_id: str
    value: T
    source: ArtifactRecordV3


@dataclass(frozen=True)
class RecordCodecV3(Generic[T]):
    """Optional domain codec layered above generic canonical JSON storage."""

    decode: Callable[[Any], T]
    encode: Callable[[T], Any]

    def read(self, record: ArtifactRecordV3) -> TypedRecordV3[T]:
        try:
            value = self.decode(record.value.to_value())
        except Exception as exc:
            _phase_fail(
                "record_schema_mismatch",
                f"record {record.record_id!r} failed its typed decoder: {exc}",
                "repair the upstream schema or use the codec matching that artifact kind",
            )
        return TypedRecordV3(record.record_id, value, record)

    def write(
        self,
        record_id: str,
        value: T,
        *,
        dependencies: Iterable[RecordDependencyV3] = (),
        expressions: Iterable[InternedExpressionV3] = (),
    ) -> ArtifactRecordV3:
        try:
            payload = self.encode(value)
        except Exception as exc:
            _phase_fail(
                "record_encoding_failed",
                f"record {record_id!r} failed its typed encoder: {exc}",
                "repair the output codec or return a value admitted by its schema",
            )
        return ArtifactRecordV3.create(
            record_id,
            payload,
            dependencies=dependencies,
            expressions=expressions,
        )


class PhaseContextV3:
    """Read-only declared inputs with automatic record-access tracking."""

    def __init__(self, readers: Mapping[str, ArtifactSetReaderV3]) -> None:
        self._readers = MappingProxyType(dict(readers))
        self._accesses: set[RecordDependencyV3] = set()

    @property
    def input_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._readers))

    def manifest(self, input_name: str) -> ArtifactSetManifestV3:
        return self._reader(input_name).manifest

    def records(self, input_name: str) -> Iterator[ArtifactRecordV3]:
        reader = self._reader(input_name)
        for record in reader.iter_records():
            self._accesses.add(RecordDependencyV3(input_name, record.record_id))
            yield record

    def typed_records(
        self, input_name: str, codec: RecordCodecV3[T]
    ) -> Iterator[TypedRecordV3[T]]:
        for record in self.records(input_name):
            yield codec.read(record)

    def record(self, input_name: str, record_id: str) -> ArtifactRecordV3:
        record = self._reader(input_name).get_record(record_id)
        self._accesses.add(RecordDependencyV3(input_name, record.record_id))
        return record

    def typed_record(
        self, input_name: str, record_id: str, codec: RecordCodecV3[T]
    ) -> TypedRecordV3[T]:
        return codec.read(self.record(input_name, record_id))

    @staticmethod
    def expression(value: Any) -> InternedExpressionV3:
        return InternedExpressionV3.create(value)

    def _reader(self, input_name: str) -> ArtifactSetReaderV3:
        try:
            return self._readers[input_name]
        except KeyError:
            _phase_fail(
                "undeclared_input_access",
                f"phase attempted to read undeclared input {input_name!r}",
                f"add {input_name!r} to required_inputs and pass it through the phase runner",
            )

    def _begin_work_item(self) -> None:
        self._accesses.clear()

    def _take_accesses(self) -> tuple[RecordDependencyV3, ...]:
        result = tuple(sorted(self._accesses))
        self._accesses.clear()
        return result


@dataclass(frozen=True)
class SccWorkItemV3:
    scc: DependencySccPlanV3
    node_records: tuple[RecordDependencyV3, ...]

    @property
    def record_id(self) -> str:
        return self.scc.scc_id

    def records(self, context: PhaseContextV3) -> tuple[ArtifactRecordV3, ...]:
        return tuple(
            context.record(reference.input_name, reference.record_id)
            for reference in self.node_records
        )


@dataclass(frozen=True)
class PhaseRunResultV3:
    manifest: ArtifactSetManifestV3
    output_directory: Path
    input_artifacts: tuple[ArtifactDependencyV3, ...]


CompletenessHookV3 = Callable[
    [ArtifactSetReaderV3, PhaseContextV3], None
]
ScheduleHookV3 = Callable[
    [DependencySchedulingManifestV3, PhaseContextV3], None
]
UnitTransformV3 = Callable[[PhaseContextV3, ArtifactRecordV3], ArtifactRecordV3]
SccTransformV3 = Callable[[PhaseContextV3, SccWorkItemV3], ArtifactRecordV3]
ReduceTransformV3 = Callable[
    [PhaseContextV3], ArtifactRecordV3 | Iterable[ArtifactRecordV3]
]


@dataclass(frozen=True)
class PhaseDefinitionV3:
    name: str
    version: str
    form: PhaseFormV3
    output_artifact_kind: str
    required_inputs: tuple[str, ...]
    transform: UnitTransformV3 | SccTransformV3 | ReduceTransformV3
    source_input: str | None = None
    completeness: CompletenessHookV3 | None = None
    schedule_validator: ScheduleHookV3 | None = None

    def __post_init__(self) -> None:
        if self.form not in {"map_units", "map_sccs", "reduce"}:
            _phase_fail(
                "invalid_phase_form",
                f"phase {self.name!r} has unsupported form {self.form!r}",
                "construct it with map_units, map_sccs, or reduce",
            )
        _canonical_names(self.required_inputs, "required_inputs")
        if self.form == "map_units" and self.source_input not in self.required_inputs:
            _phase_fail(
                "missing_source_input",
                f"map_units phase {self.name!r} has no declared source input",
                "pass source_input=<declared input> to map_units",
            )
        if self.form != "map_units" and self.source_input is not None:
            _phase_fail(
                "unexpected_source_input",
                f"{self.form} phase {self.name!r} declares a unit source",
                "remove source_input or use map_units",
            )
        if self.form == "reduce" and self.completeness is None:
            _phase_fail(
                "missing_completeness_hook",
                f"reduce phase {self.name!r} has no output completeness checker",
                "pass completeness=<independent expected-output validator> to reduce",
            )

    @property
    def definition_sha256(self) -> str:
        return canonical_sha256_v3({
            "name": self.name,
            "version": self.version,
            "form": self.form,
            "output_artifact_kind": self.output_artifact_kind,
            "required_inputs": list(self.required_inputs),
            "source_input": self.source_input,
            "has_completeness_hook": self.completeness is not None,
            "has_schedule_validator": self.schedule_validator is not None,
        })

    def run(
        self,
        *,
        output_directory: Path | str,
        inputs: Mapping[str, Path | str],
        bindings: Iterable[ArtifactBindingV3],
        status: str = "complete",
        schedule: DependencySchedulingManifestV3 | Path | str | None = None,
        selected_scc_ids: Iterable[str] | None = None,
        max_pack_bytes: int | None = None,
    ) -> PhaseRunResultV3:
        provided = set(inputs)
        expected = set(self.required_inputs)
        if provided != expected:
            _phase_fail(
                "phase_input_mismatch",
                f"phase {self.name!r} inputs differ: missing={sorted(expected-provided)!r}, unexpected={sorted(provided-expected)!r}",
                "pass exactly the named required_inputs; use a new phase declaration when semantics need another dependency",
            )
        readers = {name: ArtifactSetReaderV3(path) for name, path in inputs.items()}
        context = PhaseContextV3(readers)
        dependencies = tuple(
            readers[name].dependency_binding(name) for name in sorted(readers)
        )
        phase_binding = ArtifactBindingV3(
            name="phase",
            kind="phase-definition",
            identity=f"{self.name}@{self.version}",
            sha256=self.definition_sha256,
        )
        output_bindings = tuple(sorted({*bindings, phase_binding}))
        records: Iterable[ArtifactRecordV3]
        expected_output_ids: tuple[str, ...] | None = None
        if self.form == "map_units":
            assert self.source_input is not None
            expected_output_ids = tuple(
                record.record_id
                for record in readers[self.source_input].iter_records()
            )
            records = self._map_unit_records(
                context, readers[self.source_input]
            )
        elif self.form == "map_sccs":
            parsed_schedule = _load_dependency_schedule(schedule)
            _validate_schedule_inputs(parsed_schedule, context)
            if self.schedule_validator is not None:
                self.schedule_validator(parsed_schedule, context)
            selected = (
                {row.scc_id for row in parsed_schedule.sccs}
                if selected_scc_ids is None
                else set(selected_scc_ids)
            )
            unknown = selected - {row.scc_id for row in parsed_schedule.sccs}
            if unknown:
                _phase_fail(
                    "unknown_selected_scc",
                    f"phase selected absent SCCs {sorted(unknown)!r}",
                    "select IDs from the checked dependency scheduling manifest",
                )
            expected_output_ids = tuple(
                row.scc_id for row in parsed_schedule.sccs if row.scc_id in selected
            )
            records = self._map_scc_records(context, parsed_schedule, selected)
        else:
            if schedule is not None or selected_scc_ids is not None:
                _phase_fail(
                    "unexpected_schedule",
                    f"reduce phase {self.name!r} received SCC scheduling options",
                    "remove schedule arguments or define a map_sccs phase",
                )
            records = self._reduce_records(context)
        writer_options: dict[str, Any] = {}
        if max_pack_bytes is not None:
            writer_options["max_pack_bytes"] = max_pack_bytes
        writer = ArtifactSetWriterV3(
            artifact_kind=self.output_artifact_kind,
            bindings=output_bindings,
            dependencies=dependencies,
            status=status,
            **writer_options,
        )
        output_path = Path(output_directory)
        manifest = writer.write(output_path, records)
        reader = ArtifactSetReaderV3(output_path)
        if expected_output_ids is not None:
            reader.validate_completeness(expected_output_ids)
        if self.completeness is not None:
            self.completeness(reader, context)
        return PhaseRunResultV3(manifest, output_path, dependencies)

    def _map_unit_records(
        self,
        context: PhaseContextV3,
        source: ArtifactSetReaderV3,
    ) -> Iterator[ArtifactRecordV3]:
        transform = self.transform
        for input_record in source.iter_records():
            context._begin_work_item()
            source_name = self.source_input
            assert source_name is not None
            automatic = RecordDependencyV3(source_name, input_record.record_id)
            try:
                output = transform(context, input_record)  # type: ignore[call-arg]
            except ArtifactV3Error:
                raise
            except Exception as exc:
                _phase_fail(
                    "phase_transform_failed",
                    f"phase {self.name!r} failed for unit {input_record.record_id!r}: {exc}",
                    "repair the pure transform; rerun only this unit bucket",
                    location=input_record.record_id,
                )
            if not isinstance(output, ArtifactRecordV3):
                _phase_fail(
                    "untyped_phase_output",
                    f"phase {self.name!r} returned {type(output).__name__}",
                    "return ArtifactRecordV3.create(...) or a typed codec's write(...) result",
                    location=input_record.record_id,
                )
            if output.record_id != input_record.record_id:
                _phase_fail(
                    "map_units_cardinality_violation",
                    f"unit {input_record.record_id!r} produced {output.record_id!r}",
                    "preserve the unit ID; use reduce for intentional changes in output cardinality",
                    location=input_record.record_id,
                )
            yield _with_dependencies(
                output, {*context._take_accesses(), automatic}
            )

    def _map_scc_records(
        self,
        context: PhaseContextV3,
        schedule: DependencySchedulingManifestV3,
        selected: set[str],
    ) -> Iterator[ArtifactRecordV3]:
        nodes = {row.node_id: row for row in schedule.nodes}
        transform = self.transform
        for scc in schedule.sccs:
            if scc.scc_id not in selected:
                continue
            references = tuple(sorted({reference for member in scc.members for reference in nodes[member].records}))
            item = SccWorkItemV3(scc, references)
            context._begin_work_item()
            try:
                output = transform(context, item)  # type: ignore[call-arg]
            except ArtifactV3Error:
                raise
            except Exception as exc:
                _phase_fail(
                    "phase_transform_failed",
                    f"phase {self.name!r} failed for SCC {scc.scc_id!r}: {exc}",
                    "repair the pure transform; rerun only this SCC dependency closure",
                    location=scc.scc_id,
                )
            if not isinstance(output, ArtifactRecordV3) or output.record_id != scc.scc_id:
                _phase_fail(
                    "map_sccs_cardinality_violation",
                    f"SCC {scc.scc_id!r} did not produce one same-ID ArtifactRecordV3",
                    "return exactly one record whose ID is work_item.record_id",
                    location=scc.scc_id,
                )
            yield _with_dependencies(
                output, {*context._take_accesses(), *references}
            )

    def _reduce_records(
        self, context: PhaseContextV3
    ) -> Iterator[ArtifactRecordV3]:
        context._begin_work_item()
        try:
            result = self.transform(context)  # type: ignore[call-arg]
            iterator = iter((result,)) if isinstance(result, ArtifactRecordV3) else iter(result)
            for output in iterator:
                if not isinstance(output, ArtifactRecordV3):
                    _phase_fail(
                        "untyped_phase_output",
                        f"reduce phase {self.name!r} emitted {type(output).__name__}",
                        "yield ArtifactRecordV3 values from the pure reduction",
                    )
                yield _with_dependencies(output, context._take_accesses())
        except ArtifactV3Error:
            raise
        except Exception as exc:
            _phase_fail(
                "phase_transform_failed",
                f"reduce phase {self.name!r} failed: {exc}",
                "repair the pure reduction and rerun its CA derivation",
            )


def _with_dependencies(
    record: ArtifactRecordV3,
    dependencies: Iterable[RecordDependencyV3],
) -> ArtifactRecordV3:
    return replace(
        record,
        dependencies=tuple(sorted({*record.dependencies, *dependencies})),
    )


def _load_dependency_schedule(
    value: DependencySchedulingManifestV3 | Path | str | None,
) -> DependencySchedulingManifestV3:
    if isinstance(value, DependencySchedulingManifestV3):
        return value
    if value is None:
        _phase_fail(
            "missing_dependency_schedule",
            "map_sccs phase has no checked dependency schedule",
            "pass the dependency-schedule-v3 manifest generated for these exact inputs",
        )
    path = Path(value)
    try:
        return DependencySchedulingManifestV3.parse_bytes(
            path.read_bytes(), location=str(path)
        )
    except OSError as exc:
        _phase_fail(
            "missing_dependency_schedule",
            f"cannot read dependency schedule {path}: {exc}",
            "build or pass the dependency planning derivation",
        )


def _validate_schedule_inputs(
    schedule: DependencySchedulingManifestV3, context: PhaseContextV3
) -> None:
    for node in schedule.nodes:
        for reference in node.records:
            if reference.input_name not in context.input_names:
                _phase_fail(
                    "undeclared_schedule_input",
                    f"schedule node {node.node_id!r} refers to undeclared input {reference.input_name!r}",
                    "declare that phase input or regenerate the dependency schedule without it",
                )
            context.record(reference.input_name, reference.record_id)
    context._take_accesses()


def map_units(
    *,
    name: str,
    version: str,
    source_input: str,
    required_inputs: Sequence[str],
    output_artifact_kind: str,
    transform: UnitTransformV3,
    completeness: CompletenessHookV3 | None = None,
) -> PhaseDefinitionV3:
    """Define the common one-input-record to one-output-record phase."""

    return PhaseDefinitionV3(
        name=name,
        version=version,
        form="map_units",
        output_artifact_kind=output_artifact_kind,
        required_inputs=_canonical_names(required_inputs, "required_inputs"),
        source_input=source_input,
        transform=transform,
        completeness=completeness,
    )


def map_sccs(
    *,
    name: str,
    version: str,
    required_inputs: Sequence[str],
    output_artifact_kind: str,
    transform: SccTransformV3,
    completeness: CompletenessHookV3 | None = None,
    schedule_validator: ScheduleHookV3 | None = None,
) -> PhaseDefinitionV3:
    """Define one independently cached output record per dependency SCC."""

    return PhaseDefinitionV3(
        name=name,
        version=version,
        form="map_sccs",
        output_artifact_kind=output_artifact_kind,
        required_inputs=_canonical_names(required_inputs, "required_inputs"),
        transform=transform,
        completeness=completeness,
        schedule_validator=schedule_validator,
    )


def reduce(
    *,
    name: str,
    version: str,
    required_inputs: Sequence[str],
    output_artifact_kind: str,
    transform: ReduceTransformV3,
    completeness: CompletenessHookV3,
) -> PhaseDefinitionV3:
    """Define a global reduction with a mandatory independent closure check."""

    return PhaseDefinitionV3(
        name=name,
        version=version,
        form="reduce",
        output_artifact_kind=output_artifact_kind,
        required_inputs=_canonical_names(required_inputs, "required_inputs"),
        transform=transform,
        completeness=completeness,
    )


def run_phase_reference_v3(
    reference: str,
    *,
    output_directory: Path | str,
    inputs: Mapping[str, Path | str],
    bindings: Sequence[Mapping[str, Any]],
    status: str = "complete",
    schedule: Path | str | None = None,
    selected_scc_ids: Sequence[str] | None = None,
    max_pack_bytes: int | None = None,
) -> PhaseRunResultV3:
    """Nix-facing entry point for ``module:attribute`` phase definitions."""

    module_name, separator, attribute_name = reference.partition(":")
    if not separator or not module_name or not attribute_name:
        _phase_fail(
            "invalid_phase_reference",
            f"phase reference {reference!r} is not module:attribute",
            "export a PhaseDefinitionV3 and pass its Python module and attribute",
        )
    try:
        phase = getattr(importlib.import_module(module_name), attribute_name)
    except (ImportError, AttributeError) as exc:
        _phase_fail(
            "missing_phase_definition",
            f"cannot load {reference!r}: {exc}",
            "include the phase module in the checked Python source closure and export the named definition",
        )
    if not isinstance(phase, PhaseDefinitionV3):
        _phase_fail(
            "invalid_phase_definition",
            f"{reference!r} does not export PhaseDefinitionV3",
            "construct it with map_units, map_sccs, or reduce",
        )
    parsed_bindings = tuple(ArtifactBindingV3.parse(row) for row in bindings)
    return phase.run(
        output_directory=output_directory,
        inputs=inputs,
        bindings=parsed_bindings,
        status=status,
        schedule=schedule,
        selected_scc_ids=selected_scc_ids,
        max_pack_bytes=max_pack_bytes,
    )


__all__ = [
    "CompletenessHookV3",
    "PhaseContextV3",
    "PhaseDefinitionV3",
    "PhaseFrameworkV3Error",
    "PhaseRunResultV3",
    "RecordCodecV3",
    "SccWorkItemV3",
    "TypedRecordV3",
    "map_sccs",
    "map_units",
    "reduce",
    "run_phase_reference_v3",
]
