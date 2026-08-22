from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import (
    ArtifactSetWriterV3,
    ArtifactV3Error,
)
from spaghetti_extractor.artifacts.io import ArtifactSetReaderV3
from spaghetti_extractor.artifacts.phases import PhaseContextV3
from spaghetti_extractor.authority.exact_units import (
    EXACT_UNIT_CODEC_V3,
    ExactUnitV3,
)
from spaghetti_extractor.authority.incoming_call_frames import (
    INCOMING_CALL_FRAME_CODEC_V3,
    INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
    INCOMING_CALL_FRAMES_PHASE_V3,
    check_incoming_call_frames_completeness_v3,
)
from spaghetti_extractor.authority.semantic_index import SEMANTIC_INDEX_PHASE_V3
from spaghetti_extractor.authority.transition_summaries import (
    TRANSITION_SUMMARIES_PHASE_V3,
)
from tests.unit.authority_inputs import test_external_site_evidence as fixture


def _leaf(unit_id: str, rva: int) -> dict[str, object]:
    unit = fixture._unit(fixture._event())
    unit["id"] = unit_id
    source = unit["source"]
    assert isinstance(source, dict)
    source["original"] = {"rva_start": rva, "rva_end": rva + 8}
    semantics = unit["semantics"]
    assert isinstance(semantics, dict)
    semantics["external_events"] = []
    semantics["ordered_events"] = []
    counts = semantics["counts"]
    assert isinstance(counts, dict)
    counts["external_events"] = 0
    counts["ordered_events"] = 0
    return unit


def _caller(
    unit_id: str, rva: int, target_rva: int, *, status: str = "qualified"
) -> dict[str, object]:
    event: dict[str, object] = {
        "kind": "internal_call",
        "target_rva": target_rva,
        "return_rva": rva + 8,
        "register_inputs": {"esp": fixture._register("esp")},
        "stack_inputs": [],
        "flag_inputs": {},
        "effect_model": "uninterpreted_internal_call_response_v1",
    }
    unit = fixture._unit(event)
    unit["id"] = unit_id
    unit["status"] = status
    source = unit["source"]
    assert isinstance(source, dict)
    source["original"] = {"rva_start": rva, "rva_end": rva + 8}
    return unit


def _inputs(root: Path, *, caller_status: str = "qualified") -> tuple[Path, Path]:
    units = (
        _caller("caller:unit", 0x1000, 0x2000, status=caller_status),
        _leaf("target:unit", 0x2000),
        _leaf("uncalled:unit", 0x3000),
    )
    exact_records = tuple(
        EXACT_UNIT_CODEC_V3.write(exact.record_id, exact)
        for exact in (
            ExactUnitV3.create(unit, pe_sha256=fixture.PE_SHA256)
            for unit in units
        )
    )
    exact = root / "exact"
    ArtifactSetWriterV3(
        artifact_kind="exact-units-v3",
        bindings=(fixture.BINDING,),
        status="complete",
    ).write(exact, exact_records)
    semantic = SEMANTIC_INDEX_PHASE_V3.run(
        output_directory=root / "semantic",
        inputs={"exact_units": exact},
        bindings=(fixture.BINDING,),
    ).output_directory
    transitions = TRANSITION_SUMMARIES_PHASE_V3.run(
        output_directory=root / "transitions",
        inputs={"exact_units": exact},
        bindings=(fixture.BINDING,),
    ).output_directory
    return semantic, transitions


def _run_index(root: Path, semantic: Path, transitions: Path) -> Path:
    return INCOMING_CALL_FRAMES_PHASE_V3.run(
        output_directory=root / "incoming",
        inputs={
            "semantic_index": semantic,
            "transition_summaries": transitions,
        },
        bindings=(fixture.BINDING,),
    ).output_directory


class IncomingCallFramesV3Tests(unittest.TestCase):
    def test_indexes_cross_unit_direct_call_and_empty_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            semantic, transitions = _inputs(root)
            output = _run_index(root, semantic, transitions)
            reader = ArtifactSetReaderV3(output)

            target_source = reader.get_record("target:unit")
            target = INCOMING_CALL_FRAME_CODEC_V3.read(target_source).value
            self.assertEqual(len(target.frames), 1)
            self.assertEqual(target.frames[0].source_unit_id, "caller:unit")
            self.assertEqual(target.frames[0].source_status, "complete")
            self.assertEqual(
                target.frames[0].event.to_value()["target_rva"], 0x2000
            )
            self.assertEqual(
                {(row.input_name, row.record_id) for row in target_source.dependencies},
                {
                    ("semantic_index", "caller:unit"),
                    ("semantic_index", "target:unit"),
                    ("transition_summaries", "caller:unit"),
                },
            )
            self.assertEqual(
                INCOMING_CALL_FRAME_CODEC_V3.read(
                    reader.get_record("uncalled:unit")
                ).value.frames,
                (),
            )

    def test_incomplete_caller_cannot_export_complete_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            semantic, transitions = _inputs(root, caller_status="incomplete")
            output = _run_index(root, semantic, transitions)
            target = INCOMING_CALL_FRAME_CODEC_V3.read(
                ArtifactSetReaderV3(output).get_record("target:unit")
            ).value
            self.assertEqual(target.frames[0].source_status, "incomplete")

    def test_missing_transition_inventory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            semantic, transitions = _inputs(root)
            transition_reader = ArtifactSetReaderV3(transitions)
            incomplete = root / "incomplete-transitions"
            ArtifactSetWriterV3(
                artifact_kind=transition_reader.manifest.artifact_kind,
                bindings=transition_reader.manifest.bindings,
                dependencies=transition_reader.manifest.dependencies,
                status="complete",
            ).write(
                incomplete,
                tuple(
                    row
                    for row in transition_reader.iter_records()
                    if row.record_id != "caller:unit"
                ),
            )
            with self.assertRaises(ArtifactV3Error) as raised:
                _run_index(root, semantic, incomplete)
            self.assertEqual(raised.exception.code, "incomplete_record_set")

    def test_completeness_rejects_tampered_frame_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            semantic, transitions = _inputs(root)
            output = _run_index(root, semantic, transitions)
            reader = ArtifactSetReaderV3(output)
            tampered_records = []
            for source in reader.iter_records():
                value = INCOMING_CALL_FRAME_CODEC_V3.read(source).value
                if value.record_id == "target:unit":
                    value = replace(value, frames=())
                tampered_records.append(
                    INCOMING_CALL_FRAME_CODEC_V3.write(
                        value.record_id,
                        value,
                        dependencies=source.dependencies,
                    )
                )
            tampered = root / "tampered"
            ArtifactSetWriterV3(
                artifact_kind=INCOMING_CALL_FRAMES_ARTIFACT_KIND_V3,
                bindings=(fixture.BINDING,),
                dependencies=reader.manifest.dependencies,
                status="complete",
            ).write(tampered, tuple(tampered_records))

            with self.assertRaises(ArtifactV3Error) as raised:
                check_incoming_call_frames_completeness_v3(
                    ArtifactSetReaderV3(tampered),
                    PhaseContextV3(
                        {
                            "semantic_index": ArtifactSetReaderV3(semantic),
                            "transition_summaries": ArtifactSetReaderV3(
                                transitions
                            ),
                        }
                    ),
                )
            self.assertEqual(
                raised.exception.code, "incoming_call_frame_index_contradiction"
            )


if __name__ == "__main__":
    unittest.main()
