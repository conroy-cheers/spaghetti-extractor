from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.analysis_v3.exact_units import (
    EXACT_UNIT_CODEC_V3,
    EXACT_UNITS_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.inductive import (
    INDUCTIVE_AUTHORITY_CODEC_V3,
    INDUCTIVE_AUTHORITY_PHASE_V3,
    INDUCTIVE_INPUT_CODEC_V3,
    CutpointInvariantV3,
    EntryFactsV3,
    InductiveConfigV3,
    InductiveCutpointV3,
    InvariantBudgetsV3,
    InvariantFactV3,
)
from spaghetti_extractor.analysis_v3.memory_versions import (
    MEMORY_VERSION_CODEC_V3,
    MEMORY_VERSIONS_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.semantic_index import SEMANTIC_INDEX_PHASE_V3
from spaghetti_extractor.analysis_v3.structural_targets import (
    STRUCTURAL_TARGET_UNIT_CODEC_V3,
    STRUCTURAL_TARGETS_PHASE_V3,
)
from spaghetti_extractor.analysis_v3.transition_summaries import (
    TRANSITION_SUMMARIES_PHASE_V3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
    DependencyNodePlanV3,
    DependencySchedulingManifestV3,
)
PE_SHA256 = "a" * 64
PROFILE_SHA256 = "b" * 64
SLOT = 0x402000
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _unit(unit_id: str, rva: int, target: int, value: int) -> dict[str, object]:
    memory_event = {
        "kind": "write",
        "width": 4,
        "instruction_rva": rva + 1,
        "address": _const(SLOT),
        "value": _const(value),
    }
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 8},
            "instruction_bytes_sha256": f"{rva:064x}",
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [
            {
                "mnemonic": "fixture",
                "rva_start": rva,
                "rva_end": rva + 8,
                "size": 8,
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
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [memory_event],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {"kind": "direct_jump", "target_rva": target},
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 1,
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


class AnalysisV3PhaseChainTests(unittest.TestCase):
    def test_complete_authority_chain_is_recordized_and_exactly_dependent(self) -> None:
        units = (
            _unit("loop:a", 0x1000, 0x1010, 1),
            _unit("loop:b", 0x1010, 0x1000, 2),
        )
        fact = InvariantFactV3.finite(f"memory-range:{SLOT}:{SLOT + 4}", (1, 2))
        root = EntryFactsV3(
            "launch:loop",
            "root",
            "loop:a",
            None,
            (InvariantFactV3.exact(f"memory-range:{SLOT}:{SLOT + 4}", 1),),
        )

        with tempfile.TemporaryDirectory() as temporary:
            root_path = Path(temporary)
            machine_ir = _write_artifact(
                root_path / "machine-ir",
                "machine-ir-v3-input",
                tuple(ArtifactRecordV3.create(str(row["id"]), row) for row in units),
            )
            exact = EXACT_UNITS_PHASE_V3.run(
                output_directory=root_path / "exact",
                inputs={"machine_ir": machine_ir},
                bindings=(BINDING,),
            ).output_directory
            semantic_index = SEMANTIC_INDEX_PHASE_V3.run(
                output_directory=root_path / "semantic-index",
                inputs={"exact_units": exact},
                bindings=(BINDING,),
            ).output_directory
            transitions = TRANSITION_SUMMARIES_PHASE_V3.run(
                output_directory=root_path / "transitions",
                inputs={"exact_units": exact},
                bindings=(BINDING,),
            ).output_directory
            schedule = DependencySchedulingManifestV3.create(
                "c" * 64,
                (
                    DependencyNodePlanV3.create(
                        "loop:a",
                        dependencies=("loop:b",),
                    ),
                    DependencyNodePlanV3.create(
                        "loop:b",
                        dependencies=("loop:a",),
                    ),
                ),
            )
            memory_schedule = DependencySchedulingManifestV3.create(
                "d" * 64,
                (
                    DependencyNodePlanV3.create(
                        "loop:a",
                        dependencies=("loop:b",),
                    ),
                    DependencyNodePlanV3.create(
                        "loop:b",
                        dependencies=("loop:a",),
                    ),
                ),
            )
            with patch(
                "spaghetti_extractor.analysis_v3.transition_summaries._derive_summary",
                side_effect=AssertionError(
                    "memory composition must not regenerate checked transitions"
                ),
            ):
                memory = MEMORY_VERSIONS_PHASE_V3.run(
                    output_directory=root_path / "memory",
                    inputs={
                        "semantic_index": semantic_index,
                        "transition_summaries": transitions,
                    },
                    bindings=(BINDING,),
                    schedule=memory_schedule,
                ).output_directory
            hints = _write_artifact(root_path / "hints", "target-hints-v3", ())
            targets = STRUCTURAL_TARGETS_PHASE_V3.run(
                output_directory=root_path / "targets",
                inputs={
                    "semantic_index": semantic_index,
                    "target_hints": hints,
                },
                bindings=(BINDING,),
            ).output_directory

            config = InductiveConfigV3(
                record_id="inductive-config",
                profile_sha256=PROFILE_SHA256,
                root_unit_ids=("loop:a",),
                root_entry_facts=(root,),
                required_exports=(),
                dependency_discharges=(),
                budgets=InvariantBudgetsV3(),
            )
            cutpoints = (
                InductiveCutpointV3(
                    "loop:a", CutpointInvariantV3("loop:a", (fact,))
                ),
                InductiveCutpointV3(
                    "loop:b", CutpointInvariantV3("loop:b", (fact,))
                ),
            )
            inductive_inputs = _write_artifact(
                root_path / "inductive-inputs",
                "inductive-inputs-v3",
                (
                    INDUCTIVE_INPUT_CODEC_V3.write(config.record_id, config),
                    *(INDUCTIVE_INPUT_CODEC_V3.write(row.record_id, row) for row in cutpoints),
                ),
            )
            shared = {
                "inductive_inputs": inductive_inputs,
                "memory_versions": memory,
                "semantic_index": semantic_index,
                "structural_targets": targets,
                "transition_summaries": transitions,
            }
            authority = INDUCTIVE_AUTHORITY_PHASE_V3.run(
                output_directory=root_path / "authority",
                inputs=shared,
                bindings=(BINDING,),
                schedule=schedule,
            ).output_directory

            exact_rows = list(ArtifactSetReaderV3(exact).iter_records())
            self.assertEqual(len(exact_rows), 2)
            for row in exact_rows:
                self.assertEqual(
                    [(item.input_name, item.record_id) for item in row.dependencies],
                    [("machine_ir", row.record_id)],
                )
                self.assertEqual(EXACT_UNIT_CODEC_V3.read(row).record_id, row.record_id)

            transition_rows = list(ArtifactSetReaderV3(transitions).iter_records())
            for row in transition_rows:
                self.assertEqual(
                    [(item.input_name, item.record_id) for item in row.dependencies],
                    [("exact_units", row.record_id)],
                )
                payload = row.value.to_value()
                self.assertNotIn("detail", payload)
                self.assertNotIn(
                    "unit", payload["memory_accesses"][0]["binding"]
                )

            memory_rows = list(ArtifactSetReaderV3(memory).iter_records())
            self.assertEqual(len(memory_rows), 1)
            self.assertEqual(
                {MEMORY_VERSION_CODEC_V3.read(row).value.record_kind for row in memory_rows},
                {"scc_graph"},
            )
            self.assertNotIn("body", memory_rows[0].value.to_value())

            target_rows = list(ArtifactSetReaderV3(targets).iter_records())
            self.assertEqual(len(target_rows), 2)
            self.assertTrue(
                all(
                    not STRUCTURAL_TARGET_UNIT_CODEC_V3.read(row).value.proposals
                    for row in target_rows
                )
            )
            authority_rows = list(ArtifactSetReaderV3(authority).iter_records())
            typed_authority = [
                INDUCTIVE_AUTHORITY_CODEC_V3.read(row).value
                for row in authority_rows
            ]
            self.assertEqual(len(typed_authority), 1)
            scc_authority = typed_authority[0]
            self.assertEqual(scc_authority.record_kind, "scc_authority")
            self.assertEqual(scc_authority.status, "complete")
            self.assertTrue(scc_authority.authorizing)
            self.assertEqual(
                {dependency.input_name for dependency in authority_rows[0].dependencies},
                {
                    "inductive_inputs",
                    "memory_versions",
                    "semantic_index",
                    "structural_targets",
                    "transition_summaries",
                },
            )

            empty_inductive_inputs = _write_artifact(
                root_path / "empty-inductive-inputs",
                "inductive-inputs-v3",
                (),
            )
            incomplete_authority = INDUCTIVE_AUTHORITY_PHASE_V3.run(
                output_directory=root_path / "incomplete-authority",
                inputs={
                    **shared,
                    "inductive_inputs": empty_inductive_inputs,
                },
                bindings=(BINDING,),
                schedule=schedule,
            ).output_directory
            incomplete_record = next(
                ArtifactSetReaderV3(incomplete_authority).iter_records()
            )
            incomplete = INDUCTIVE_AUTHORITY_CODEC_V3.read(
                incomplete_record
            ).value
            self.assertEqual(incomplete.status, "incomplete")
            self.assertFalse(incomplete.authorizing)
            self.assertEqual(
                incomplete.body.to_value()["issues"],
                [
                    {
                        "code": "inductive_config_missing",
                        "status": "incomplete",
                        "subject_id": incomplete.record_id,
                    }
                ],
            )

    def test_structural_target_records_remain_non_authorizing(self) -> None:
        unit = _unit("dispatch", 0x1000, 0x1000, 1)
        unit["control"] = {
            "kind": "indirect_jump",
            "direct_targets": [],
            "has_indirect_target": True,
        }
        unit["semantics"]["outcome"] = {
            "kind": "indirect_jump",
            "target": _reg("eax"),
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir = _write_artifact(
                root / "machine-ir",
                "machine-ir-v3-input",
                (ArtifactRecordV3.create("dispatch", unit),),
            )
            exact = EXACT_UNITS_PHASE_V3.run(
                output_directory=root / "exact",
                inputs={"machine_ir": machine_ir},
                bindings=(BINDING,),
            ).output_directory
            semantic_index = SEMANTIC_INDEX_PHASE_V3.run(
                output_directory=root / "semantic-index",
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
                inputs={
                    "semantic_index": semantic_index,
                    "target_hints": hints,
                },
                bindings=(BINDING,),
            ).output_directory

            record = next(ArtifactSetReaderV3(targets).iter_records())
            proposal_set = STRUCTURAL_TARGET_UNIT_CODEC_V3.read(record).value
            self.assertEqual(len(proposal_set.proposals), 1)
            proposal = proposal_set.proposals[0]
            self.assertEqual(proposal.status, "incomplete")
            self.assertFalse(proposal.authorizing)
            self.assertEqual(proposal.issue_codes, ("structural_target_proposal_missing",))


if __name__ == "__main__":
    unittest.main()
