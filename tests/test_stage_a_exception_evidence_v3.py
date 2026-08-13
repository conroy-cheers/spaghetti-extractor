from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.analysis_v3.exceptional_transitions import (
    EXCEPTIONAL_TRANSITION_CODEC_V3,
    EXCEPTIONAL_TRANSITIONS_PHASE_V3,
    EXCEPTION_EVIDENCE_CODEC_V3,
)
from spaghetti_extractor.analysis_v3.exact_units import ExactUnitV3
from spaghetti_extractor.analysis_v3.semantic_index import (
    SEMANTIC_INDEX_ARTIFACT_KIND_V3,
    SEMANTIC_INDEX_CODEC_V3,
    derive_semantic_index_v3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactSetReaderV3,
    ArtifactSetWriterV3,
)
from spaghetti_extractor.stage_a_exception_evidence_v3 import (
    emit_exception_evidence_v3,
)


PE_SHA256 = "1" * 64
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _unit(
    unit_id: str,
    rva: int,
    *,
    fault_kind: str = "divide_error",
    condition: dict[str, object],
) -> dict[str, object]:
    fault = {
        "condition": condition,
        "instruction_rva": rva,
        "kind": fault_kind,
    }
    return {
        "control": {
            "direct_targets": [],
            "has_indirect_target": False,
            "kind": "return",
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "format": "stage-a-machine-ir-v2",
        "id": unit_id,
        "instructions": [
            {
                "instruction_sha256": f"{rva:064x}",
                "mnemonic": "fixture",
                "rva_end": rva + 1,
                "rva_start": rva,
                "size": 1,
            }
        ],
        "record_kind": "unit",
        "semantics": {
            "edge_conditions": [],
            "external_events": [],
            "faults": [fault],
            "flag_writes": [],
            "memory_events": [],
            "ordered_events": [{"family": "fault", **fault}],
            "outcome": {"kind": "return"},
            "pre_state": {"flags": {}, "registers": {}},
            "register_writes": [],
            "stack_delta": None,
        },
        "source": {
            "instruction_bytes_sha256": f"{rva:064x}",
            "original": {
                "rva_end": rva + 1,
                "rva_start": rva,
                "size": 1,
            },
        },
        "status": "qualified",
    }


def _launch_profile(*, unmodelled_seh: list[str] | None = None) -> dict[str, object]:
    return {
        "assumptions": {
            name: {"contract": f"fixture-{name}-v1"}
            for name in (
                "argv",
                "environment",
                "fs",
                "iat",
                "initial_stack",
                "relocations",
            )
        },
        "feature_inventory": {
            "direct_syscalls": [],
            "executable_writes": [],
            "threads": [],
            "unknown_async_callbacks": [],
            "unmodelled_seh": [] if unmodelled_seh is None else unmodelled_seh,
        },
        "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
        "schema_version": 1,
    }


class ExceptionEvidenceProviderV3Tests(unittest.TestCase):
    def _inputs(
        self,
        root: Path,
        units: list[dict[str, object]],
        *,
        profile: dict[str, object] | None = None,
    ) -> tuple[Path, Path, Path]:
        machine_ir = root / "machine-ir.jsonl"
        machine_ir.write_text(
            "".join(json.dumps(unit, sort_keys=True) + "\n" for unit in units),
            encoding="utf-8",
        )
        semantic_records = []
        for unit in units:
            exact = ExactUnitV3.create(unit, pe_sha256=PE_SHA256)
            semantic = derive_semantic_index_v3(exact)
            semantic_records.append(
                SEMANTIC_INDEX_CODEC_V3.write(semantic.record_id, semantic)
            )
        semantic_index = root / "semantic-index"
        ArtifactSetWriterV3(
            artifact_kind=SEMANTIC_INDEX_ARTIFACT_KIND_V3,
            bindings=(BINDING,),
        ).write(semantic_index, semantic_records)
        launch_profile = root / "launch-profile.json"
        launch_profile.write_text(
            json.dumps(profile or _launch_profile(), sort_keys=True),
            encoding="utf-8",
        )
        return machine_ir, semantic_index, launch_profile

    def test_static_false_and_profile_terminal_faults_close_generically(self) -> None:
        dynamic_condition = {
            "args": [
                {
                    "args": [
                        {"name": "edx", "op": "reg", "width": 32},
                        {"name": "eax", "op": "reg", "width": 32},
                        {"name": "ecx", "op": "reg", "width": 32},
                    ],
                    "op": "udiv_valid32",
                }
            ],
            "op": "not",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, semantic_index, launch_profile = self._inputs(
                root,
                [
                    _unit(
                        "unit:infeasible",
                        0x1000,
                        condition={"op": "false"},
                    ),
                    _unit(
                        "unit:terminal",
                        0x2000,
                        condition=dynamic_condition,
                    ),
                ],
            )
            metadata = emit_exception_evidence_v3(
                machine_ir=machine_ir,
                semantic_index=semantic_index,
                launch_profile=launch_profile,
                output_directory=root / "evidence-provider",
            )
            self.assertEqual(metadata["status"], "complete")
            self.assertEqual(metadata["counts"]["infeasible"], 1)
            self.assertEqual(metadata["counts"]["terminating"], 1)
            evidence_path = root / "evidence-provider" / "artifact"
            evidence = {
                row.record_id: EXCEPTION_EVIDENCE_CODEC_V3.read(row).value
                for row in ArtifactSetReaderV3(evidence_path).iter_records()
            }
            self.assertEqual(
                {row.disposition for row in evidence.values()},
                {"infeasible", "terminates"},
            )
            checked_path = EXCEPTIONAL_TRANSITIONS_PHASE_V3.run(
                output_directory=root / "checked",
                inputs={
                    "exception_evidence": evidence_path,
                    "semantic_index": semantic_index,
                },
                bindings=(BINDING,),
            ).output_directory
            checked = [
                EXCEPTIONAL_TRANSITION_CODEC_V3.read(row).value
                for row in ArtifactSetReaderV3(checked_path).iter_records()
            ]
            self.assertTrue(all(row.status == "complete" for row in checked))
            self.assertTrue(all(row.authorizing for row in checked))

    def test_unsupported_fault_and_modelled_seh_remain_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir, semantic_index, launch_profile = self._inputs(
                root,
                [
                    _unit(
                        "unit:unsupported",
                        0x3000,
                        fault_kind="page_fault",
                        condition={
                            "args": [
                                {"name": "ebx", "op": "reg", "width": 32},
                                _const(2),
                            ],
                            "op": "eq",
                        },
                    ),
                    _unit(
                        "unit:seh",
                        0x4000,
                        condition={
                            "args": [
                                {"name": "eax", "op": "reg", "width": 32},
                                _const(0),
                            ],
                            "op": "eq",
                        },
                    ),
                ],
                profile=_launch_profile(unmodelled_seh=["fixture-handler"]),
            )
            metadata = emit_exception_evidence_v3(
                machine_ir=machine_ir,
                semantic_index=semantic_index,
                launch_profile=launch_profile,
                output_directory=root / "evidence-provider",
            )
            self.assertEqual(metadata["status"], "incomplete")
            self.assertEqual(metadata["counts"]["incomplete"], 2)
            self.assertEqual(
                {row["code"] for row in metadata["records"]},
                {
                    "exception_fault_kind_unsupported",
                    "exception_terminal_profile_unsupported_features",
                },
            )


if __name__ == "__main__":
    unittest.main()
