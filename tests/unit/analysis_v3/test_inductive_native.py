from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.analysis_v3._schema import AnalysisV3Error
from spaghetti_extractor.analysis_v3.exact_units import EXACT_UNITS_PHASE_V3
from spaghetti_extractor.analysis_v3.inductive import (
    INDUCTIVE_AUTHORITY_CODEC_V3,
    INDUCTIVE_AUTHORITY_PHASE_V3,
    INDUCTIVE_INPUT_CODEC_V3,
    CutpointInvariantV3,
    EntryFactsV3,
    InductiveAuthorityBodyV3,
    InductiveConfigV3,
    InductiveCutpointV3,
    InvariantBudgetsV3,
    InvariantFactV3,
)
from spaghetti_extractor.analysis_v3.memory_records import (
    MEMORY_VERSION_CODEC_V3,
    MemoryVersionRecordV3,
)
from spaghetti_extractor.analysis_v3.semantic_index import SEMANTIC_INDEX_PHASE_V3
from spaghetti_extractor.analysis_v3.structural_targets import (
    STRUCTURAL_TARGETS_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.target_certificates import (
    INDIRECT_TARGET_CERTIFICATES_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.transition_records import (
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionBinaryBindingV3,
)
from spaghetti_extractor.analysis_v3.transition_summaries import (
    TRANSITION_SUMMARIES_PHASE_V3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    ArtifactV3Error,
    DependencyNodePlanV3,
    DependencySchedulingManifestV3,
)


PE_SHA256 = "a" * 64
PROFILE_SHA256 = "b" * 64
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _unit(unit_id: str, rva: int, target: int, value: int) -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 4},
            "instruction_bytes_sha256": f"{rva:064x}",
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [
            {
                "mnemonic": "fixture",
                "rva_start": rva,
                "rva_end": rva + 4,
                "size": 4,
            }
        ],
        "semantics": {
            "pre_state": {
                "registers": {"eax": _reg("eax")},
                "flags": {},
                "memory": {
                    "op": "memory",
                    "name": "mem0",
                    "address_width": 32,
                    "value_width": 8,
                },
            },
            "register_writes": [{"register": "eax", "value": _const(value)}],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {"kind": "direct_jump", "target_rva": target},
            "stack_delta": None,
            "counts": {
                "register_writes": 1,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": 0,
                "faults": 0,
                "ordered_events": 0,
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": "direct_jump",
            "direct_targets": [target],
            "has_indirect_target": False,
        },
    }


def _write_artifact(
    path: Path, kind: str, records: tuple[ArtifactRecordV3, ...]
) -> Path:
    ArtifactSetWriterV3(artifact_kind=kind, bindings=(BINDING,)).write(path, records)
    return path


class NativeInductiveAuthorityTests(unittest.TestCase):
    def _inputs(
        self,
        root: Path,
        *,
        include_root_entry: bool = True,
        memory_summary_ids: tuple[str, ...] | None = None,
    ) -> tuple[dict[str, Path], DependencySchedulingManifestV3]:
        machine_ir = _write_artifact(
            root / "machine-ir",
            "machine-ir-v3-input",
            (
                ArtifactRecordV3.create("loop:a", _unit("loop:a", 0x1000, 0x1010, 1)),
                ArtifactRecordV3.create("loop:b", _unit("loop:b", 0x1010, 0x1000, 2)),
            ),
        )
        exact = EXACT_UNITS_PHASE_V3.run(
            output_directory=root / "exact",
            inputs={"machine_ir": machine_ir},
            bindings=(BINDING,),
        ).output_directory
        semantic = SEMANTIC_INDEX_PHASE_V3.run(
            output_directory=root / "semantic",
            inputs={"exact_units": exact},
            bindings=(BINDING,),
        ).output_directory
        transitions = TRANSITION_SUMMARIES_PHASE_V3.run(
            output_directory=root / "transitions",
            inputs={"exact_units": exact},
            bindings=(BINDING,),
        ).output_directory
        hints = _write_artifact(root / "hints", "target-hints-v3", ())
        targets = STRUCTURAL_TARGETS_PHASE_V3.run(
            output_directory=root / "targets",
            inputs={"semantic_index": semantic, "target_hints": hints},
            bindings=(BINDING,),
        ).output_directory
        schedule = DependencySchedulingManifestV3.create(
            "c" * 64,
            (
                DependencyNodePlanV3.create("loop:a", dependencies=("loop:b",)),
                DependencyNodePlanV3.create("loop:b", dependencies=("loop:a",)),
            ),
        )
        self.assertEqual(len(schedule.sccs), 1)
        scc_id = schedule.sccs[0].scc_id
        transition_values = tuple(
            TRANSITION_SUMMARY_CODEC_V3.read(row).value
            for row in ArtifactSetReaderV3(transitions).iter_records()
        )
        expected_summary_ids = tuple(
            sorted(row.summary_id for row in transition_values)
        )
        memory_value = MemoryVersionRecordV3.create(
            record_id=scc_id,
            status="complete",
            binary=TransitionBinaryBindingV3(PE_SHA256, "d" * 64),
            transition_summary_ids=(
                expected_summary_ids
                if memory_summary_ids is None
                else memory_summary_ids
            ),
            alias_policy="fail_closed",
            alias_components=(),
            versions=(),
            merges=(),
            access_versions=(),
            unknown_write_kills=(),
            issues=(),
        )
        memory = _write_artifact(
            root / "memory",
            "memory-versions-v3",
            (MEMORY_VERSION_CODEC_V3.write(scc_id, memory_value),),
        )

        invariant = InvariantFactV3.finite("register:eax", (1, 2))
        entry = EntryFactsV3(
            "launch:loop",
            "root",
            "loop:a",
            None,
            (InvariantFactV3.exact("register:eax", 1),),
        )
        config = InductiveConfigV3(
            record_id="inductive-config",
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(entry,) if include_root_entry else (),
            required_exports=(),
            dependency_discharges=(),
            budgets=InvariantBudgetsV3(),
        )
        cutpoints = (
            InductiveCutpointV3(
                "loop:a", CutpointInvariantV3("loop:a", (invariant,))
            ),
            InductiveCutpointV3(
                "loop:b", CutpointInvariantV3("loop:b", (invariant,))
            ),
        )
        inductive_inputs = _write_artifact(
            root / "inductive-inputs",
            "inductive-inputs-v3",
            (
                INDUCTIVE_INPUT_CODEC_V3.write(config.record_id, config),
                *(
                    INDUCTIVE_INPUT_CODEC_V3.write(row.record_id, row)
                    for row in cutpoints
                ),
            ),
        )
        target_evidence = _write_artifact(
            root / "target-evidence",
            "indirect-target-evaluation-evidence-v3",
            (),
        )
        target_certificates = INDIRECT_TARGET_CERTIFICATES_PHASE_V3.run(
            output_directory=root / "target-certificates",
            inputs={
                "inductive_inputs": inductive_inputs,
                "memory_versions": memory,
                "semantic_index": semantic,
                "semantic_index_global": semantic,
                "structural_targets": targets,
                "target_evidence": target_evidence,
                "transition_summaries": transitions,
            },
            bindings=(BINDING,),
        ).output_directory
        return (
            {
                "inductive_inputs": inductive_inputs,
                "memory_versions": memory,
                "semantic_index": semantic,
                "target_certificates": target_certificates,
                "transition_summaries": transitions,
            },
            schedule,
        )

    def test_native_checker_closes_a_finite_register_loop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, schedule = self._inputs(root)
            output = INDUCTIVE_AUTHORITY_PHASE_V3.run(
                output_directory=root / "authority",
                inputs=inputs,
                bindings=(BINDING,),
                schedule=schedule,
                validation_mode="replay",
            ).output_directory
            source = next(ArtifactSetReaderV3(output).iter_records())
            authority = INDUCTIVE_AUTHORITY_CODEC_V3.read(source).value
            self.assertEqual(authority.status, "complete")
            self.assertTrue(authority.authorizing)
            body = InductiveAuthorityBodyV3.parse(authority.body.to_value())
            self.assertEqual(body.structural_unit_count, 2)
            self.assertEqual(body.reachable_unit_count, 2)
            self.assertEqual(len(body.certificate_reports), 1)
            self.assertEqual(
                len(body.certificate_reports[0].preservation_witnesses), 2
            )
            self.assertEqual(
                {row.input_name for row in source.dependencies},
                {
                    "inductive_inputs",
                    "memory_versions",
                    "semantic_index",
                    "target_certificates",
                    "transition_summaries",
                },
            )

    def test_missing_root_entry_is_incomplete_at_the_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, schedule = self._inputs(root, include_root_entry=False)
            output = INDUCTIVE_AUTHORITY_PHASE_V3.run(
                output_directory=root / "authority",
                inputs=inputs,
                bindings=(BINDING,),
                schedule=schedule,
            ).output_directory
            authority = INDUCTIVE_AUTHORITY_CODEC_V3.read(
                next(ArtifactSetReaderV3(output).iter_records())
            ).value
            body = InductiveAuthorityBodyV3.parse(authority.body.to_value())
            self.assertEqual(authority.status, "incomplete")
            self.assertFalse(authority.authorizing)
            self.assertIn("root_entry_facts_missing", {row.code for row in body.issues})

    def test_stale_memory_transition_inventory_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, schedule = self._inputs(
                root, memory_summary_ids=("transition-summary:stale",)
            )
            output = INDUCTIVE_AUTHORITY_PHASE_V3.run(
                output_directory=root / "authority",
                inputs=inputs,
                bindings=(BINDING,),
                schedule=schedule,
            ).output_directory
            authority = INDUCTIVE_AUTHORITY_CODEC_V3.read(
                next(ArtifactSetReaderV3(output).iter_records())
            ).value
            body = InductiveAuthorityBodyV3.parse(authority.body.to_value())
            self.assertEqual(authority.status, "violated")
            self.assertIn(
                "memory_transition_inventory_contradiction",
                {row.code for row in body.issues},
            )

    def test_omitted_scheduled_transition_record_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, schedule = self._inputs(root)
            transition_reader = ArtifactSetReaderV3(inputs["transition_summaries"])
            retained = tuple(
                replace(row, dependencies=())
                for row in transition_reader.iter_records()
                if row.record_id == "loop:a"
            )
            inputs["transition_summaries"] = _write_artifact(
                root / "transitions-omitted",
                "transition-summaries-v3",
                retained,
            )
            with self.assertRaises(ArtifactV3Error) as caught:
                INDUCTIVE_AUTHORITY_PHASE_V3.run(
                    output_directory=root / "authority",
                    inputs=inputs,
                    bindings=(BINDING,),
                    schedule=schedule,
                )
            self.assertEqual(caught.exception.code, "missing_record")

    def test_corrupt_authority_body_id_fails_closed(self) -> None:
        issue = {
            "code": "inductive_config_missing",
            "status": "incomplete",
            "subject_id": "scc",
        }
        body = {
            "id": "inductive-authority-v3:" + "0" * 64,
            "format": "spaghetti-extractor-inductive-authority-check-v3",
            "status": "incomplete",
            "authorizing": False,
            "profile_sha256": None,
            "binary_pe_sha256": None,
            "memory_version_graph_id": None,
            "transition_summary_ids": [],
            "root_unit_ids": [],
            "certificate_reports": [],
            "checked_exports": [],
            "dependency_discharges": [],
            "issues": [issue],
            "counts": {
                "certificates": 0,
                "complete_certificates": 0,
                "structural_units": 1,
                "reachable_units": 0,
            },
        }
        with self.assertRaises(AnalysisV3Error) as caught:
            InductiveAuthorityBodyV3.parse(body)
        self.assertEqual(caught.exception.code, "stale_record_id")


if __name__ == "__main__":
    unittest.main()
