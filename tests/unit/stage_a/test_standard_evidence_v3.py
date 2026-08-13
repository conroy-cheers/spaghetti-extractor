from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.analysis_v3.inductive_records import (
    INDUCTIVE_INPUT_CODEC_V3,
    InductiveConfigV3,
    InductiveCutpointV3,
)
from spaghetti_extractor.analysis_v3.root_closure import (
    LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3,
    LAUNCH_ROOT_EVIDENCE_CODEC_V3,
    LaunchRootEvidenceV3,
    launch_root_id_v3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    CanonicalValueV3,
)
from spaghetti_extractor.stage_a_standard_evidence_v3 import (
    StandardEvidenceV3Error,
    emit_standard_evidence_v3,
)


BINARY = ArtifactBindingV3("binary", "pe32", "fixture.exe", "a" * 64)


def _launch_roots(path: Path) -> Path:
    unit_id = "semantic-transfer:fixture-entry"
    root = LaunchRootEvidenceV3(
        record_id=launch_root_id_v3("pe_entrypoint", "entrypoint", unit_id),
        root_kind="pe_entrypoint",
        identity="entrypoint",
        unit_id=unit_id,
        unit_sha256="b" * 64,
        entry_state=CanonicalValueV3.of({"profile": "fixture-launch-v1"}),
        callback_id=None,
        status="complete",
        primary_blocker=None,
    )
    ArtifactSetWriterV3(
        artifact_kind=LAUNCH_ROOT_EVIDENCE_ARTIFACT_KIND_V3,
        bindings=(BINARY,),
    ).write(path, (LAUNCH_ROOT_EVIDENCE_CODEC_V3.write(root.record_id, root),))
    return path


def _manifest(path: Path, *, duplicate: bool = False) -> Path:
    recovered = {
        "id": "indirect-exit:finite-table",
        "source_unit_id": "semantic-transfer:source",
        "source_rva": 0x1200,
        "source_event_index": 2,
        "kind": "indirect_jump",
        "status": "recovered",
        "closure": "checked_finite_target_inventory",
        "target_unit_ids": ["semantic-transfer:b", "semantic-transfer:a"],
        "failure": None,
    }
    incomplete = {
        "id": "indirect-exit:unknown-register",
        "source_unit_id": "semantic-transfer:other",
        "source_rva": 0x1300,
        "source_event_index": 1,
        "kind": "indirect_call",
        "status": "incomplete",
        "closure": "unresolved",
        "target_unit_ids": [],
        "failure": {"code": "unsupported_target_expression"},
    }
    rows = [recovered, incomplete]
    if duplicate:
        rows.append(dict(recovered))
    path.write_text(
        json.dumps({"control": {"recovered_indirect_targets": rows}}),
        encoding="utf-8",
    )
    return path


class StandardEvidenceV3Tests(unittest.TestCase):
    def test_emits_conservative_hints_and_true_root_invariant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = emit_standard_evidence_v3(
                machine_ir_manifest=_manifest(root / "machine-ir-manifest.json"),
                launch_roots_path=_launch_roots(root / "launch-roots"),
                output_directory=root / "out",
            )

            hints = {
                row.record_id: row.value.to_value()
                for row in ArtifactSetReaderV3(root / "out" / "target-hints").iter_records()
            }
            self.assertEqual(
                hints["indirect-exit:finite-table"]["target_unit_ids"],
                ["semantic-transfer:a", "semantic-transfer:b"],
            )
            self.assertEqual(
                hints["indirect-exit:finite-table"]["status"], "recovered"
            )
            self.assertEqual(
                hints["indirect-exit:unknown-register"]["status"], "incomplete"
            )
            self.assertEqual(
                hints["indirect-exit:unknown-register"]["target_unit_ids"], []
            )

            inductive = tuple(
                INDUCTIVE_INPUT_CODEC_V3.read(row).value
                for row in ArtifactSetReaderV3(
                    root / "out" / "inductive-inputs"
                ).iter_records()
            )
            config = next(row for row in inductive if isinstance(row, InductiveConfigV3))
            cutpoint = next(
                row for row in inductive if isinstance(row, InductiveCutpointV3)
            )
            self.assertEqual(
                config.root_unit_ids, ("semantic-transfer:fixture-entry",)
            )
            self.assertEqual(config.root_entry_facts[0].facts, ())
            self.assertEqual(cutpoint.invariant.facts, ())
            self.assertEqual(metadata["binary_binding"], BINARY.to_payload())

    def test_duplicate_indirect_exit_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(
                StandardEvidenceV3Error, "repeats an indirect-exit ID"
            ):
                emit_standard_evidence_v3(
                    machine_ir_manifest=_manifest(
                        root / "machine-ir-manifest.json", duplicate=True
                    ),
                    launch_roots_path=_launch_roots(root / "launch-roots"),
                    output_directory=root / "out",
                )


if __name__ == "__main__":
    unittest.main()
