from __future__ import annotations

from spaghetti_extractor.artifact_set_v3 import ArtifactRecordV3
from spaghetti_extractor.phase_framework_v3 import map_sccs, map_units, reduce


def _transition(_context, record):
    return ArtifactRecordV3.create(
        record.record_id,
        {"value": record.value.to_value()["value"] * 10},
    )


transition = map_units(
    name="fixture-transition",
    version="1",
    source_input="units",
    input_artifact_kinds={"units": "units"},
    output_artifact_kind="transitions",
    transform=_transition,
)


def _summarize(context, work_item):
    records = work_item.records(context)
    return ArtifactRecordV3.create(
        work_item.record_id,
        {
            "members": list(work_item.scc.members),
            "total": sum(record.value.to_value()["value"] for record in records),
        },
    )


summarize = map_sccs(
    name="fixture-summarize",
    version="1",
    input_artifact_kinds={"transitions": "transitions"},
    output_artifact_kind="scc-summary",
    transform=_summarize,
    schedule_record_inputs=("transitions",),
)


def _validate_composition(reader, _context):
    reader.validate_completeness(("composition",))


def _compose(context):
    if tuple(context.records("evidence")):
        raise ValueError("fixture evidence must remain empty")
    return ArtifactRecordV3.create(
        "composition",
        {
            "total": sum(
                record.value.to_value()["total"]
                for record in context.records("summaries")
            )
        },
    )


composition = reduce(
    name="fixture-composition",
    version="1",
    input_artifact_kinds={
        "evidence": "optional-evidence",
        "summaries": "scc-summary",
    },
    output_artifact_kind="composition",
    transform=_compose,
    completeness=_validate_composition,
)
