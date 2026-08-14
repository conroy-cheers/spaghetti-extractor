from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.authority.exact_units import EXACT_UNITS_PHASE_V3
from spaghetti_extractor.authority.memory_versions import (
    MEMORY_VERSION_CODEC_V3,
    MEMORY_VERSIONS_PHASE_V3,
)
from spaghetti_extractor.authority.semantic_index import SEMANTIC_INDEX_PHASE_V3
from spaghetti_extractor.authority.transition_summaries import (
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
from spaghetti_extractor.phase_framework_v3 import PhaseFrameworkV3Error


PE_SHA256 = "a" * 64
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _unit() -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "unit:unknown-write",
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1004},
            "instruction_bytes_sha256": "1" * 64,
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [
            {
                "mnemonic": "mov",
                "rva_start": 0x1000,
                "rva_end": 0x1004,
                "size": 4,
            }
        ],
        "semantics": {
            "pre_state": {"registers": {}, "flags": {}, "memory": {}},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [
                {
                    "kind": "write",
                    "width": 4,
                    "instruction_rva": 0x1000,
                    "address": {"op": "reg", "name": "eax", "width": 32},
                    "value": {"op": "const", "value": 1, "width": 32},
                }
            ],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {"kind": "return"},
            "stack_delta": {
                "status": "derived",
                "net_bytes": 4,
                "expression": {
                    "op": "add32",
                    "args": [
                        {"op": "reg", "name": "esp", "width": 32},
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            },
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
            "kind": "return",
            "direct_targets": [],
            "has_indirect_target": False,
        },
    }


class NativeMemoryVersionTests(unittest.TestCase):
    def test_unknown_write_is_checked_and_round_trips_without_v2_reader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine"
            ArtifactSetWriterV3(
                artifact_kind="machine-ir-v3-input", bindings=(BINDING,)
            ).write(
                machine,
                (ArtifactRecordV3.create("unit:unknown-write", _unit()),),
            )
            exact = EXACT_UNITS_PHASE_V3.run(
                output_directory=root / "exact",
                inputs={"machine_ir": machine},
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
            schedule = DependencySchedulingManifestV3.create(
                "b" * 64,
                (DependencyNodePlanV3.create("unit:unknown-write"),),
            )
            memory = MEMORY_VERSIONS_PHASE_V3.run(
                output_directory=root / "memory",
                inputs={
                    "semantic_index": semantic,
                    "transition_summaries": transitions,
                },
                bindings=(BINDING,),
                schedule=schedule,
            ).output_directory

            record = next(ArtifactSetReaderV3(memory).iter_records())
            checked = MEMORY_VERSION_CODEC_V3.read(record).value
            self.assertEqual(checked.status, "incomplete")
            self.assertEqual(len(checked.unknown_write_kills), 1)
            self.assertEqual(
                checked.unknown_write_kills[0].affected_scope, "all_components"
            )
            self.assertEqual(
                MEMORY_VERSION_CODEC_V3.read(
                    MEMORY_VERSION_CODEC_V3.write(record.record_id, checked)
                ).value,
                checked,
            )

            corrupt = copy.deepcopy(record.value.to_value())
            corrupt["unknown_write_kills"][0]["reason"] = "corrupt"
            with self.assertRaisesRegex(PhaseFrameworkV3Error, "stale_record_id"):
                MEMORY_VERSION_CODEC_V3.read(
                    ArtifactRecordV3.create(record.record_id, corrupt)
                )


if __name__ == "__main__":
    unittest.main()
