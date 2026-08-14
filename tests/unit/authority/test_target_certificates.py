from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.authority.exact_units import EXACT_UNITS_PHASE_V3
from spaghetti_extractor.authority.inductive import (
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
from spaghetti_extractor.authority.memory_records import MEMORY_VERSION_CODEC_V3
from spaghetti_extractor.authority.memory_versions import MEMORY_VERSIONS_PHASE_V3
from spaghetti_extractor.authority.semantic_index import (
    SEMANTIC_INDEX_CODEC_V3,
    SEMANTIC_INDEX_PHASE_V3,
)
from spaghetti_extractor.authority.structural_targets import (
    STRUCTURAL_TARGETS_PHASE_V3,
)
from spaghetti_extractor.authority.target_certificate_checker import (
    INDIRECT_TARGET_CERTIFICATES_PHASE_V3,
    _memory_blockers,
)
from spaghetti_extractor.authority.target_certificate_records import (
    INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3,
    TARGET_EVALUATION_EVIDENCE_CODEC_V3,
    TargetEvaluationEvidenceV3,
)
from spaghetti_extractor.authority.memory_records import (
    ConcreteByteRangeV3,
    MemoryAliasComponentV3,
    MemoryGraphIssueV3,
    MemoryVersionRecordV3,
    UnknownWriteKillV3,
)
from spaghetti_extractor.authority.transition_records import (
    TRANSITION_SUMMARY_CODEC_V3,
    TransitionEventBindingV3,
)
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


PE_SHA256 = "a" * 64
PROFILE_SHA256 = "b" * 64
BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", PE_SHA256)


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _unit(unit_id: str, rva: int, *, indirect: bool, target_rva: int) -> dict[str, object]:
    outcome: dict[str, object]
    control: dict[str, object]
    if indirect:
        outcome = {"kind": "indirect_jump", "target": _reg("eax")}
        control = {
            "kind": "indirect_jump",
            "direct_targets": [],
            "has_indirect_target": True,
        }
    else:
        outcome = {"kind": "direct_jump", "target_rva": target_rva}
        control = {
            "kind": "direct_jump",
            "direct_targets": [target_rva],
            "has_indirect_target": False,
        }
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
            {"mnemonic": "fixture", "rva_start": rva, "rva_end": rva + 4, "size": 4}
        ],
        "semantics": {
            "pre_state": {"registers": {"eax": _reg("eax")}, "flags": {}},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": outcome,
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": 0,
                "faults": 0,
                "ordered_events": 0,
                "edge_conditions": 0,
            },
        },
        "control": control,
    }


def _write(path: Path, kind: str, records: tuple[ArtifactRecordV3, ...]) -> Path:
    ArtifactSetWriterV3(artifact_kind=kind, bindings=(BINDING,)).write(path, records)
    return path


class IndirectTargetCertificatesV3Tests(unittest.TestCase):
    def _chain(
        self,
        root: Path,
        *,
        include_evidence: bool,
        evidence_target: str | None = "target",
        proposal_target: str | None = None,
        proposal_status: str = "recovered",
        external_targets: tuple[dict[str, object], ...] = (),
    ) -> tuple[dict[str, Path], DependencySchedulingManifestV3, str]:
        machine_ir = _write(
            root / "machine-ir",
            "machine-ir-v3-input",
            (
                ArtifactRecordV3.create(
                    "dispatch", _unit("dispatch", 0x1000, indirect=True, target_rva=0)
                ),
                ArtifactRecordV3.create(
                    "target", _unit("target", 0x2000, indirect=False, target_rva=0x1000)
                ),
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
        source = SEMANTIC_INDEX_CODEC_V3.read(
            ArtifactSetReaderV3(semantic).get_record("dispatch")
        ).value
        occurrence = source.indirect_exits[0]
        hints = _write(
            root / "hints",
            "target-hints-v3",
            (
                ArtifactRecordV3.create(
                    occurrence.exit_id,
                    {
                        "id": occurrence.exit_id,
                        "source_unit_id": "dispatch",
                        "source_rva": 0x1000,
                        "source_event_index": None,
                        "kind": "indirect_jump",
                        "status": proposal_status,
                        "target_unit_ids": (
                            []
                            if (proposal_target if proposal_target is not None else evidence_target) is None
                            else [proposal_target if proposal_target is not None else evidence_target]
                        ),
                        "external_targets": list(external_targets),
                        "failure": (
                            None
                            if proposal_status == "recovered"
                            else {"code": "fixture_incomplete"}
                        ),
                    },
                ),
            ),
        )
        targets = STRUCTURAL_TARGETS_PHASE_V3.run(
            output_directory=root / "targets",
            inputs={"semantic_index": semantic, "target_hints": hints},
            bindings=(BINDING,),
        ).output_directory
        schedule = DependencySchedulingManifestV3.create(
            "c" * 64,
            (
                DependencyNodePlanV3.create("dispatch", dependencies=("target",)),
                DependencyNodePlanV3.create("target", dependencies=("dispatch",)),
            ),
        )
        memory = MEMORY_VERSIONS_PHASE_V3.run(
            output_directory=root / "memory",
            inputs={"semantic_index": semantic, "transition_summaries": transitions},
            bindings=(BINDING,),
            schedule=schedule,
        ).output_directory
        memory_record = next(ArtifactSetReaderV3(memory).iter_records())
        memory_value = MEMORY_VERSION_CODEC_V3.read(memory_record).value
        fact = InvariantFactV3.finite("register:eax", (0x2000,))
        config = InductiveConfigV3(
            record_id="inductive-config",
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("dispatch",),
            root_entry_facts=(
                EntryFactsV3(
                    "launch:dispatch",
                    "root",
                    "dispatch",
                    None,
                    (InvariantFactV3.exact("register:eax", 0x2000),),
                ),
            ),
            required_exports=(),
            dependency_discharges=(),
            budgets=InvariantBudgetsV3(),
        )
        cutpoints = (
            InductiveCutpointV3(
                "dispatch", CutpointInvariantV3("dispatch", (fact,))
            ),
            InductiveCutpointV3(
                "target", CutpointInvariantV3("target", (fact,))
            ),
        )
        inductive_inputs = _write(
            root / "inductive-inputs",
            "inductive-inputs-v3",
            (
                INDUCTIVE_INPUT_CODEC_V3.write(config.record_id, config),
                *(INDUCTIVE_INPUT_CODEC_V3.write(row.record_id, row) for row in cutpoints),
            ),
        )
        evidence_records: tuple[ArtifactRecordV3, ...] = ()
        if include_evidence:
            evidence = TargetEvaluationEvidenceV3.create(
                record_id=occurrence.exit_id,
                source_unit_id="dispatch",
                source_rva=0x1000,
                source_event_index=None,
                transfer_kind="indirect_jump",
                target_expression=occurrence.target_expression.to_value(),
                evaluation_method="inductive_finite_values",
                memory_record_id=memory_value.record_id,
                inductive_fact_id=fact.fact_id,
                target_unit_ids=(
                    () if evidence_target is None else (evidence_target,)
                ),
                external_targets=external_targets,
            )
            evidence_records = (
                TARGET_EVALUATION_EVIDENCE_CODEC_V3.write(evidence.record_id, evidence),
            )
        evidence_path = _write(
            root / "target-evidence",
            "indirect-target-evaluation-evidence-v3",
            evidence_records,
        )
        certificates = INDIRECT_TARGET_CERTIFICATES_PHASE_V3.run(
            output_directory=root / "certificates",
            inputs={
                "inductive_inputs": inductive_inputs,
                "memory_versions": memory,
                "semantic_index": semantic,
                "semantic_index_global": semantic,
                "structural_targets": targets,
                "target_evidence": evidence_path,
                "transition_summaries": transitions,
            },
            bindings=(BINDING,),
        ).output_directory
        return (
            {
                "inductive_inputs": inductive_inputs,
                "memory_versions": memory,
                "semantic_index": semantic,
                "target_certificates": certificates,
                "transition_summaries": transitions,
            },
            schedule,
            occurrence.exit_id,
        )

    def test_recovered_proposal_without_evaluation_evidence_cannot_authorize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs, _schedule, exit_id = self._chain(
                Path(temporary), include_evidence=False
            )
            unit = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(
                ArtifactSetReaderV3(inputs["target_certificates"]).get_record("dispatch")
            ).value
            certificate = unit.certificates[0]
            self.assertEqual(certificate.exit_id, exit_id)
            self.assertEqual(certificate.status, "incomplete")
            self.assertFalse(certificate.authorizing)
            self.assertEqual(
                certificate.primary_blocker.code,
                "target_evaluation_evidence_missing",
            )
            self.assertEqual(certificate.target_unit_ids, ())

    def test_checked_finite_certificate_closes_inductive_target_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, schedule, _exit_id = self._chain(root, include_evidence=True)
            unit = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(
                ArtifactSetReaderV3(inputs["target_certificates"]).get_record("dispatch")
            ).value
            certificate = unit.certificates[0]
            self.assertEqual(certificate.status, "complete")
            self.assertTrue(certificate.authorizing)
            self.assertEqual(certificate.target_unit_ids, ("target",))
            self.assertEqual(
                {row.input_name for row in certificate.dependencies},
                {
                    "inductive_inputs",
                    "memory_versions",
                    "semantic_index",
                    "semantic_index_global",
                    "structural_targets",
                    "target_evidence",
                    "transition_summaries",
                },
            )

            authority = INDUCTIVE_AUTHORITY_PHASE_V3.run(
                output_directory=root / "authority",
                inputs=inputs,
                bindings=(BINDING,),
                schedule=schedule,
            ).output_directory
            checked = INDUCTIVE_AUTHORITY_CODEC_V3.read(
                next(ArtifactSetReaderV3(authority).iter_records())
            ).value
            self.assertEqual(checked.status, "complete")
            self.assertTrue(checked.authorizing)
            issues = checked.body.to_value()["issues"]
            self.assertNotIn(
                "indirect_target_evaluation_certificate_missing",
                {row["code"] for row in issues},
            )

    def test_checked_evidence_overrides_only_an_incomplete_structural_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs, _schedule, _exit_id = self._chain(
                Path(temporary),
                include_evidence=True,
                proposal_status="incomplete",
            )
            certificate = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(
                ArtifactSetReaderV3(inputs["target_certificates"]).get_record(
                    "dispatch"
                )
            ).value.certificates[0]
            self.assertEqual(certificate.status, "complete")
            self.assertTrue(certificate.authorizing)

    def test_unknown_target_membership_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs, _schedule, _exit_id = self._chain(
                Path(temporary),
                include_evidence=True,
                evidence_target="missing-target",
            )
            unit = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(
                ArtifactSetReaderV3(inputs["target_certificates"]).get_record("dispatch")
            ).value
            certificate = unit.certificates[0]
            self.assertEqual(certificate.status, "violated")
            self.assertFalse(certificate.authorizing)
            self.assertEqual(
                certificate.primary_blocker.code,
                "indirect_target_unit_unknown",
            )

    def test_proposal_and_evaluation_inventory_contradiction_is_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs, _schedule, _exit_id = self._chain(
                Path(temporary),
                include_evidence=True,
                evidence_target="target",
                proposal_target="dispatch",
            )
            certificate = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(
                ArtifactSetReaderV3(inputs["target_certificates"]).get_record("dispatch")
            ).value.certificates[0]
            self.assertEqual(certificate.status, "violated")
            self.assertEqual(
                certificate.primary_blocker.code,
                "target_evaluation_inventory_contradiction",
            )

    def test_ambiguous_external_machine_value_is_incomplete(self) -> None:
        alternatives = (
            {"machine_target_value": 0x2000, "import": {"dll": "a", "symbol": "one"}},
            {"machine_target_value": 0x2000, "import": {"dll": "b", "symbol": "two"}},
        )
        with tempfile.TemporaryDirectory() as temporary:
            inputs, _schedule, _exit_id = self._chain(
                Path(temporary),
                include_evidence=True,
                evidence_target=None,
                external_targets=alternatives,
            )
            certificate = INDIRECT_TARGET_CERTIFICATE_UNIT_CODEC_V3.read(
                ArtifactSetReaderV3(inputs["target_certificates"]).get_record("dispatch")
            ).value.certificates[0]
            self.assertEqual(certificate.status, "incomplete")
            self.assertEqual(
                certificate.primary_blocker.code,
                "indirect_target_value_mapping_ambiguous",
            )

    def test_unknown_write_kill_taints_memory_backed_target_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs, _schedule, _exit_id = self._chain(
                Path(temporary), include_evidence=True
            )
            semantic = SEMANTIC_INDEX_CODEC_V3.read(
                ArtifactSetReaderV3(inputs["semantic_index"]).get_record("dispatch")
            ).value
            summary = TRANSITION_SUMMARY_CODEC_V3.read(
                ArtifactSetReaderV3(inputs["transition_summaries"]).get_record(
                    "dispatch"
                )
            ).value
            original_memory = MEMORY_VERSION_CODEC_V3.read(
                next(ArtifactSetReaderV3(inputs["memory_versions"]).iter_records())
            ).value
            memory_range = ConcreteByteRangeV3.create(0x4000, 0x4004)
            component = MemoryAliasComponentV3.create(
                ranges=(memory_range,),
                access_ids=(),
                address_class="concrete",
                contains_unknown_address=False,
            )
            binding = TransitionEventBindingV3(
                unit=summary.unit,
                event_index=0,
                event_kind="write",
                instruction_rva=summary.rva_start,
                event_sha256="f" * 64,
            )
            kill = UnknownWriteKillV3.create(
                access_id="unknown-write",
                binding=binding,
                affected_scope="all_components",
                reason="fixture unknown alias",
            )
            tainted = MemoryVersionRecordV3.create(
                record_id=original_memory.record_id,
                status="complete",
                binary=original_memory.binary,
                transition_summary_ids=original_memory.transition_summary_ids,
                alias_policy="fail_closed",
                alias_components=(component,),
                versions=(),
                merges=(),
                access_versions=(),
                unknown_write_kills=(kill,),
                issues=(),
            )
            blockers = _memory_blockers(
                tainted,
                semantic=semantic,
                summary=summary,
                memory_range=(0x4000, 0x4004),
            )
            self.assertIn(
                "target_memory_evidence_tainted",
                {row.code for row in blockers},
            )

    def test_unrelated_unknown_read_does_not_poison_a_concrete_target_slot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs, _schedule, _exit_id = self._chain(
                Path(temporary), include_evidence=True
            )
            semantic = SEMANTIC_INDEX_CODEC_V3.read(
                ArtifactSetReaderV3(inputs["semantic_index"]).get_record("dispatch")
            ).value
            summary = TRANSITION_SUMMARY_CODEC_V3.read(
                ArtifactSetReaderV3(inputs["transition_summaries"]).get_record(
                    "dispatch"
                )
            ).value
            original = MEMORY_VERSION_CODEC_V3.read(
                next(ArtifactSetReaderV3(inputs["memory_versions"]).iter_records())
            ).value
            target_component = MemoryAliasComponentV3.create(
                ranges=(ConcreteByteRangeV3.create(0x4000, 0x4004),),
                access_ids=("target-read",),
                address_class="concrete",
                contains_unknown_address=False,
            )
            unrelated_component = MemoryAliasComponentV3.create(
                ranges=(ConcreteByteRangeV3.create(0x5000, 0x5004),),
                access_ids=("unrelated-read",),
                address_class="concrete",
                contains_unknown_address=False,
            )
            issue = MemoryGraphIssueV3.create(
                status="incomplete",
                code="unknown_read_alias",
                subject_id="unrelated-read",
                detail={"address_class": "unknown"},
            )
            memory = MemoryVersionRecordV3.create(
                record_id=original.record_id,
                status="incomplete",
                binary=original.binary,
                transition_summary_ids=original.transition_summary_ids,
                alias_policy="fail_closed",
                alias_components=(target_component, unrelated_component),
                versions=(),
                merges=(),
                access_versions=(),
                unknown_write_kills=(),
                issues=(issue,),
            )
            blockers = _memory_blockers(
                memory,
                semantic=semantic,
                summary=summary,
                memory_range=(0x4000, 0x4004),
            )
            self.assertEqual(blockers, [])


if __name__ == "__main__":
    unittest.main()
